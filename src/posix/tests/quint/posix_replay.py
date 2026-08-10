#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
#
# SPDX-License-Identifier: LGPL-2.1-only

"""Replay a Quint-generated ITF trace against chimera's POSIX client.

Each state of the trace carries a `lastOp` label naming the syscall the
model issued and the result the implementation must produce (see posix.qnt).
This harness spawns posix_driver (an in-process memfs mount behind the
chimera_posix_* API, speaking line-delimited JSON), replays every step, and
compares the driver's actual result against the model's expectation.  Any
mismatch not covered by the known-deviation registry (posix_deviations.py)
is reported as a divergence with full context and fails the run.

Model-to-real mapping maintained here (DESIGN-POSIX.md "Step and trace
contract"):
  - model pid      -> per-operation credential/umask switch in the driver
  - model (pid,fd) -> real chimera fd, learned from open/dup replies
  - model sid      -> driver directory-stream id
  - model Ino      -> real (st_dev, st_ino), learned from stat replies
  - model block i  -> BLOCK_SIZE bytes at offset i * BLOCK_SIZE; block
                      symbol 0 is a hole (zero bytes), symbol s > 0 is
                      BLOCK_SIZE repetitions of byte 0x40 + s
  - timestamps     -> abstract instants checked for monotonic consistency,
                      never predicted; explicit utimensat values map to
                      fixed wall-clock times (XTIME) checked exactly
"""

import argparse
import base64
import json
import os
import signal
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import posix_deviations  # noqa: E402

MOUNT = "/test"
BADFD = 999999

# Explicit utimensat instants: model reserved value -> (sec, nsec).  Kept in
# the past so a later "mark to now" still satisfies the >= monotonic check.
XTIME = {-1: (1000000, 0), -2: (2000000, 0)}

FTYPE_MAP = {"FReg": "reg", "FDir": "dir", "FLnk": "lnk", "FFifo": "fifo",
             "FSock": "sock", "FBlk": "blk", "FChr": "chr"}

ACC_FLAGS = {"AccR": os.O_RDONLY, "AccW": os.O_WRONLY, "AccRW": os.O_RDWR}

WHENCE_MAP = {"WSet": "set", "WCur": "cur", "WEnd": "end",
              "WData": "data", "WHole": "hole"}

LOCK_CMD = {"CSetlk": "setlk", "CSetlkw": "setlkw", "CGetlk": "getlk"}
LOCK_TYPE = {"LkRd": "rd", "LkWr": "wr", "LkUn": "un"}
LOCKF_CMD = {"LfLock": "lock", "LfTlock": "tlock", "LfUlock": "ulock",
             "LfTst": "test"}

# The capability/policy profile of chimera's POSIX client over memfs,
# established empirically by the probe below (run with --probe) and pinned
# here as a regression check; posix_run.qnt's posixMemfs instance pins trace
# generation to the same profile.  A trace whose LInit profile disagrees is
# skipped (exit 77); --check-profile re-measures and diffs against this.
# None = not measurable / any value accepted (withRoot is harness-chosen;
# errLockAgain is unobservable while memfs lacks lock support, see PD1).
# Probed 2026-08-10 against memfs (block_size 4096):
PROFILE = {
    "copyRange": True,
    "cloneRange": True,
    "seekHole": True,
    "withRoot": None,
    "gidFromParent": False,
    "sgidInherit": False,
    "writeClearsSets": True,
    "pwriteAppends": False,
    "renameCtime": True,
    "strictAtime": False,
    "stickyWriteArm": False,
    "errNotempty": True,
    "errStickyAcces": True,
    "errUnlinkDirIsdir": True,
    "errLockAgain": None,
}


class TraceFormatError(Exception):
    pass


class Divergence(Exception):
    def __init__(self, step, op, mismatches):
        self.step = step
        self.op = op
        self.mismatches = mismatches
        super().__init__(f"step {step}: " + "; ".join(mismatches))


def itf_decode(v):
    """Decode one ITF-encoded Quint value into plain Python data."""
    if isinstance(v, dict):
        special = [k for k in v if k.startswith("#")]
        if special == ["#bigint"]:
            return int(v["#bigint"])
        if special == ["#map"]:
            return {itf_decode(k): itf_decode(val) for k, val in v["#map"]}
        if special == ["#set"]:
            return [itf_decode(x) for x in v["#set"]]
        if special == ["#tup"]:
            return tuple(itf_decode(x) for x in v["#tup"])
        if special:
            raise TraceFormatError(f"unrecognized ITF encoding {special}")
        if set(v.keys()) == {"tag", "value"}:
            return {"tag": v["tag"], "value": itf_decode(v["value"])}
        return {k: itf_decode(val) for k, val in v.items()}
    if isinstance(v, list):
        return [itf_decode(x) for x in v]
    if isinstance(v, (str, bool, int)):
        return v
    raise TraceFormatError(f"unrecognized ITF value {v!r}")


def load_trace(path):
    with open(path) as f:
        raw = json.load(f)
    if "states" not in raw or "vars" not in raw:
        raise TraceFormatError(f"{path}: not an ITF trace")
    states = []
    for st in raw["states"]:
        # Instance mains namespace the state variables
        # (posixMemfs::posix::fs); keep the base name.
        states.append({k.rsplit("::", 1)[-1]: itf_decode(v)
                       for k, v in st.items()
                       if k != "#meta" and not k.startswith("mbt::")})
    for st in states:
        if "lastOp" not in st or "fs" not in st:
            raise TraceFormatError(f"{path}: state missing lastOp/fs")
    return states


class Driver:
    """posix_driver process wrapper: one JSON request line per call."""

    def __init__(self, driver_path):
        self.stderr_file = tempfile.NamedTemporaryFile(
            prefix="posix_mbt_", suffix=".stderr", delete=False)
        self.proc = subprocess.Popen(
            [driver_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.stderr_file, text=True)
        ready = self.proc.stdout.readline()
        try:
            ready_obj = json.loads(ready)
        except json.JSONDecodeError:
            raise RuntimeError(
                f"driver failed to start: {ready!r}\n{self.stderr_tail()}")
        if not ready_obj.get("ready"):
            raise RuntimeError(f"driver not ready: {ready_obj}")
        self.block_size = ready_obj["blocksize"]

    def request(self, **req):
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError(
                f"driver died on request {req}\n{self.stderr_tail()}")
        return json.loads(line)

    def stderr_tail(self, lines=50):
        try:
            with open(self.stderr_file.name, errors="replace") as f:
                return "".join(f.readlines()[-lines:])
        except OSError:
            return "<no driver stderr>"

    def close(self):
        try:
            if self.proc.poll() is None:
                self.proc.stdin.write(json.dumps({"op": "shutdown"}) + "\n")
                self.proc.stdin.flush()
                self.proc.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired, BrokenPipeError):
            self.proc.kill()
            self.proc.wait()
        finally:
            self.stderr_file.close()
            os.unlink(self.stderr_file.name)


def real_path(pth):
    comps = pth["comps"]
    if pth["abs"]:
        p = MOUNT + "".join("/" + c for c in comps)
        if pth["slash"] and comps:
            p += "/"
        return p
    p = "/".join(comps)
    if pth["slash"] and comps:
        p += "/"
    return p


def real_target(tgt):
    if tgt["abs"]:
        return MOUNT + "".join("/" + c for c in tgt["comps"])
    return "/".join(tgt["comps"])


def creds_for(with_root):
    return {
        0: {"uid": 0 if with_root else 100, "gid": 10, "gids": [10, 30]},
        1: {"uid": 200, "gid": 20, "gids": [20, 30]},
    }


class Replayer:
    def __init__(self, driver, caps, verbose=False):
        self.drv = driver
        self.bs = driver.block_size
        self.caps = caps
        self.verbose = verbose
        self.fdmap = {}       # (pid, model fd) -> real fd
        self.sidmap = {}      # model sid -> driver sid
        self.inomap = {}      # model ino -> (dev, real ino)
        self.timemap = {}     # (model ino, field) -> (abstract, (sec, ns))
        self.history = []
        self.deviations_hit = {}
        self._cur_tag = None
        self._cur_req = None
        self._cur_fs = None

        for pid, cred in creds_for(caps["withRoot"]).items():
            self.drv.request(op="setcred", pid=pid, **cred)

    # -- helpers ----------------------------------------------------------

    def block_bytes(self, sym):
        if sym == 0:
            return b"\0" * self.bs
        return bytes([0x40 + sym]) * self.bs

    def expand(self, syms):
        return b"".join(self.block_bytes(s) for s in syms)

    def rfd(self, pid, mfd):
        return self.fdmap.get((pid, mfd), BADFD)

    def rsid(self, msid):
        return self.sidmap.get(msid, -1)

    def check_status(self, expected, actual, mism):
        """True if the errno matches (proceed with success-path checks)."""
        if actual == expected:
            return True
        dev = posix_deviations.reconcile(self._cur_tag, self._cur_req,
                                         expected, actual, self._cur_fs)
        if dev is not None:
            self.deviations_hit[dev.id] = self.deviations_hit.get(dev.id,
                                                                  0) + 1
            return False
        mism.append(f"errno: expected {expected}, got {actual}")
        return False

    def check_time(self, mino, field, abstract, wire, mism):
        if field == "atime" and not self.caps["strictAtime"]:
            return
        wire = tuple(wire)
        if abstract < 0:
            want = XTIME.get(abstract)
            if want is None:
                mism.append(f"{field}: unmapped explicit instant {abstract}")
            elif wire != want:
                mism.append(f"{field}: explicit instant {abstract}: "
                            f"expected {want}, got {wire}")
            self.timemap[(mino, field)] = (abstract, wire)
            return
        key = (mino, field)
        prev = self.timemap.get(key)
        if prev is None or prev[0] < 0:
            self.timemap[key] = (abstract, wire)
        elif abstract == prev[0]:
            if wire != prev[1]:
                mism.append(f"{field}: model instant unchanged ({abstract}) "
                            f"but wire value moved {prev[1]} -> {wire}")
        elif abstract > prev[0]:
            if wire < prev[1]:
                mism.append(f"{field}: model instant advanced "
                            f"{prev[0]} -> {abstract} but wire value went "
                            f"backwards {prev[1]} -> {wire}")
            self.timemap[key] = (abstract, wire)
        else:
            mism.append(f"{field}: model instant went backwards "
                        f"{prev[0]} -> {abstract} (harness bug?)")

    def check_statres(self, rv, res, post_fs, mism):
        """Compare a driver stat reply against the model's SStatR payload."""
        want_ftype = FTYPE_MAP[rv["ftype"]["tag"]]
        if res.get("ftype") != want_ftype:
            mism.append(f"ftype: expected {want_ftype}, got "
                        f"{res.get('ftype')}")
        if rv["ftype"]["tag"] == "FLnk":
            # PD16: memfs creates symlinks with mode 0755; POSIX/Linux use
            # 0777 (and never consult it).  Skip the mode check for links.
            pass
        elif res.get("mode") != rv["mode"]:
            mism.append(f"mode: expected {rv['mode']:#o}, "
                        f"got {res.get('mode', 0):#o}")
        if res.get("uid") != rv["uid"]:
            mism.append(f"uid: expected {rv['uid']}, got {res.get('uid')}")
        if res.get("gid") != rv["gid"]:
            mism.append(f"gid: expected {rv['gid']}, got {res.get('gid')}")
        if res.get("nlink") != rv["nlink"]:
            mism.append(f"nlink: expected {rv['nlink']}, "
                        f"got {res.get('nlink')}")
        if rv["ftype"]["tag"] == "FReg":
            want = rv["sizeB"] * self.bs
            if res.get("size") != want:
                mism.append(f"size: expected {want}, got {res.get('size')}")
        elif rv["ftype"]["tag"] == "FLnk":
            node = post_fs["inodes"].get(rv["ino"])
            if node is not None:
                want = len(real_target(node["target"]))
                if res.get("size") != want:
                    mism.append(f"symlink size: expected {want}, "
                                f"got {res.get('size')}")
        mino = rv["ino"]
        ident = (res.get("dev"), res.get("ino"))
        known = self.inomap.get(mino)
        if known is None:
            for other, oident in self.inomap.items():
                if oident == ident and other != mino \
                        and other in post_fs["inodes"]:
                    mism.append(f"st_ino {ident} of model ino {mino} "
                                f"collides with live model ino {other}")
            self.inomap[mino] = ident
        elif known != ident:
            mism.append(f"identity: model ino {mino} previously "
                        f"{known}, now {ident}")
        self.check_time(mino, "atime", rv["atime"], res["atime"], mism)
        self.check_time(mino, "mtime", rv["mtime"], res["mtime"], mism)
        self.check_time(mino, "ctime", rv["ctime"], res["ctime"], mism)

    # -- per-request handlers ---------------------------------------------

    def op_open(self, pid, rv, res_v, post_fs, mism):
        fl = rv["fl"]
        flags = ACC_FLAGS[fl["acc"]["tag"]]
        if fl["creat"]:
            flags |= os.O_CREAT
        if fl["excl"]:
            flags |= os.O_EXCL
        if fl["trunc"]:
            flags |= os.O_TRUNC
        if fl["appendF"]:
            flags |= os.O_APPEND
        if fl["directory"]:
            flags |= os.O_DIRECTORY
        if fl["nofollow"]:
            flags |= os.O_NOFOLLOW
        if rv["dfd"] == -1:
            r = self.drv.request(op="open", pid=pid,
                                 path=real_path(rv["pth"]), flags=flags,
                                 mode=fl["mode"])
        else:
            r = self.drv.request(op="openat", pid=pid,
                                 dirfd=self.rfd(pid, rv["dfd"]),
                                 path=real_path(rv["pth"]), flags=flags,
                                 mode=fl["mode"])
        if self.check_status(res_v["e"], r["err"], mism) \
                and res_v["e"] == 0:
            self.fdmap[(pid, res_v["fd"])] = r["ret"]
        return r

    def op_close(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="close", pid=pid, fd=self.rfd(pid, rv["fd"]))
        if self.check_status(res_v["e"], r["err"], mism) \
                and res_v["e"] == 0:
            self.fdmap.pop((pid, rv["fd"]), None)
        return r

    def op_dup(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="dup", pid=pid, fd=self.rfd(pid, rv["fd"]))
        if self.check_status(res_v["e"], r["err"], mism) \
                and res_v["e"] == 0:
            self.fdmap[(pid, res_v["fd"])] = r["ret"]
        return r

    def op_dup2(self, pid, rv, res_v, post_fs, mism):
        target = self.fdmap.get((pid, rv["nfd"]))
        if rv["fd"] == rv["nfd"] or target is not None:
            # A live target (or self-dup): real dup2 exercises the implicit
            # close of the old description.
            r = self.drv.request(op="dup2", pid=pid,
                                 fd=self.rfd(pid, rv["fd"]),
                                 nfd=self.rfd(pid, rv["nfd"]))
        else:
            # The model's nfd names a free slot; chimera fd numbers are its
            # own, so plain dup() is observationally identical here.
            r = self.drv.request(op="dup", pid=pid,
                                 fd=self.rfd(pid, rv["fd"]))
        if self.check_status(res_v["e"], r["err"], mism) \
                and res_v["e"] == 0:
            self.fdmap[(pid, rv["nfd"])] = r["ret"]
        return r

    def op_lseek(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="lseek", pid=pid,
                             fd=self.rfd(pid, rv["fd"]),
                             off=rv["off"] * self.bs,
                             whence=WHENCE_MAP[rv["wh"]["tag"]])
        if self.check_status(res_v["e"], r["err"], mism) \
                and res_v["e"] == 0:
            want = res_v["off"] * self.bs
            if r["ret"] != want:
                mism.append(f"lseek: expected offset {want}, got {r['ret']}")
        return r

    def op_read(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="read", pid=pid, fd=self.rfd(pid, rv["fd"]),
                             len=rv["len"] * self.bs)
        self._check_read(r, res_v, mism)
        return r

    def op_pread(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="pread", pid=pid, fd=self.rfd(pid, rv["fd"]),
                             off=rv["off"] * self.bs,
                             len=rv["len"] * self.bs)
        self._check_read(r, res_v, mism)
        return r

    def _check_read(self, r, res_v, mism):
        if self.check_status(res_v["e"], r["err"], mism) \
                and res_v["e"] == 0:
            expect = self.expand(res_v["syms"])
            if r["ret"] != len(expect):
                mism.append(f"read count: expected {len(expect)}, "
                            f"got {r['ret']}")
            data = base64.b64decode(r.get("data", ""))
            if data != expect:
                mism.append("read data mismatch: expected blocks "
                            f"{res_v['syms']}, got {len(data)} bytes"
                            + diff_bytes(expect, data, self.bs))

    def op_write(self, pid, rv, res_v, post_fs, mism):
        data = self.block_bytes(rv["pat"]) * rv["len"]
        r = self.drv.request(op="write", pid=pid, fd=self.rfd(pid, rv["fd"]),
                             data=base64.b64encode(data).decode())
        self._check_write(r, res_v, rv["len"], mism)
        return r

    def op_pwrite(self, pid, rv, res_v, post_fs, mism):
        data = self.block_bytes(rv["pat"]) * rv["len"]
        r = self.drv.request(op="pwrite", pid=pid,
                             fd=self.rfd(pid, rv["fd"]),
                             off=rv["off"] * self.bs,
                             data=base64.b64encode(data).decode())
        self._check_write(r, res_v, rv["len"], mism)
        return r

    def _check_write(self, r, res_v, blocks, mism):
        if self.check_status(res_v["e"], r["err"], mism) \
                and res_v["e"] == 0:
            if r["ret"] != blocks * self.bs:
                mism.append(f"write count: expected {blocks * self.bs}, "
                            f"got {r['ret']}")

    def op_truncate(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="truncate", pid=pid,
                             path=real_path(rv["pth"]),
                             len=rv["len"] * self.bs)
        self.check_status(res_v["e"], r["err"], mism)
        return r

    def op_ftruncate(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="ftruncate", pid=pid,
                             fd=self.rfd(pid, rv["fd"]),
                             len=rv["len"] * self.bs)
        self.check_status(res_v["e"], r["err"], mism)
        return r

    def op_stat(self, pid, rv, res_v, post_fs, mism):
        if rv["dfd"] == -1:
            r = self.drv.request(op="stat", pid=pid,
                                 path=real_path(rv["pth"]),
                                 follow=rv["follow"])
        else:
            r = self.drv.request(op="fstatat", pid=pid,
                                 dirfd=self.rfd(pid, rv["dfd"]),
                                 path=real_path(rv["pth"]),
                                 follow=rv["follow"])
        if self.check_status(res_v["e"], r["err"], mism) \
                and res_v["e"] == 0:
            self.check_statres(res_v, r, post_fs, mism)
        return r

    def op_fstat(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="fstat", pid=pid, fd=self.rfd(pid, rv["fd"]))
        if self.check_status(res_v["e"], r["err"], mism) \
                and res_v["e"] == 0:
            self.check_statres(res_v, r, post_fs, mism)
        return r

    def op_chmod(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="chmod", pid=pid, path=real_path(rv["pth"]),
                             mode=rv["mode"])
        self.check_status(res_v["e"], r["err"], mism)
        return r

    def op_fchmod(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="fchmod", pid=pid,
                             fd=self.rfd(pid, rv["fd"]), mode=rv["mode"])
        self.check_status(res_v["e"], r["err"], mism)
        return r

    def op_chown(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="chown", pid=pid, path=real_path(rv["pth"]),
                             uid=rv["u"], gid=rv["g"], follow=rv["follow"])
        self.check_status(res_v["e"], r["err"], mism)
        return r

    def op_fchown(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="fchown", pid=pid,
                             fd=self.rfd(pid, rv["fd"]),
                             uid=rv["u"], gid=rv["g"])
        self.check_status(res_v["e"], r["err"], mism)
        return r

    def _ts_args(self, prefix, ts):
        tag = ts["tag"]
        if tag == "TsNow":
            return {prefix + "type": "now"}
        if tag == "TsOmit":
            return {prefix + "type": "omit"}
        sec, nsec = XTIME[ts["value"]]
        return {prefix + "type": "val", prefix + "sec": sec,
                prefix + "nsec": nsec}

    def op_utimens(self, pid, rv, res_v, post_fs, mism):
        args = {}
        args.update(self._ts_args("a", rv["ta"]))
        args.update(self._ts_args("m", rv["tm"]))
        r = self.drv.request(op="utimens", pid=pid,
                             path=real_path(rv["pth"]), **args)
        self.check_status(res_v["e"], r["err"], mism)
        return r

    def op_futimens(self, pid, rv, res_v, post_fs, mism):
        args = {}
        args.update(self._ts_args("a", rv["ta"]))
        args.update(self._ts_args("m", rv["tm"]))
        r = self.drv.request(op="futimens", pid=pid,
                             fd=self.rfd(pid, rv["fd"]), **args)
        self.check_status(res_v["e"], r["err"], mism)
        return r

    def op_access(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="access", pid=pid,
                             path=real_path(rv["pth"]),
                             r=rv["r"], w=rv["w"], x=rv["x"], eff=rv["eff"])
        self.check_status(res_v["e"], r["err"], mism)
        return r

    def op_umask(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="umask", pid=pid, mask=rv["mask"])
        # The driver's per-pid table mirrors the model's umask state; a
        # disagreement means a harness bug, not a chimera one.
        if r["ret"] != res_v["old"]:
            mism.append(f"umask bookkeeping: expected old {res_v['old']}, "
                        f"driver had {r['ret']} (harness bug)")
        return r

    def op_mkdir(self, pid, rv, res_v, post_fs, mism):
        if rv["dfd"] == -1:
            r = self.drv.request(op="mkdir", pid=pid,
                                 path=real_path(rv["pth"]), mode=rv["mode"])
        else:
            r = self.drv.request(op="mkdirat", pid=pid,
                                 dirfd=self.rfd(pid, rv["dfd"]),
                                 path=real_path(rv["pth"]), mode=rv["mode"])
        self.check_status(res_v["e"], r["err"], mism)
        return r

    def op_mknod(self, pid, rv, res_v, post_fs, mism):
        ft = "fifo" if rv["ft"]["tag"] == "FFifo" else "reg"
        r = self.drv.request(op="mknod", pid=pid, path=real_path(rv["pth"]),
                             mode=rv["mode"], ftype=ft)
        self.check_status(res_v["e"], r["err"], mism)
        return r

    def op_symlink(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="symlink", pid=pid,
                             target=real_target(rv["tgt"]),
                             path=real_path(rv["pth"]))
        self.check_status(res_v["e"], r["err"], mism)
        return r

    def op_link(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="link", pid=pid,
                             old=real_path(rv["pthOld"]),
                             new=real_path(rv["pthNew"]),
                             follow=rv["followOld"])
        self.check_status(res_v["e"], r["err"], mism)
        return r

    def op_unlink(self, pid, rv, res_v, post_fs, mism):
        if rv["dfd"] == -1:
            r = self.drv.request(op="unlink", pid=pid,
                                 path=real_path(rv["pth"]))
        else:
            r = self.drv.request(op="unlinkat", pid=pid,
                                 dirfd=self.rfd(pid, rv["dfd"]),
                                 path=real_path(rv["pth"]), rmdir=False)
        self.check_status(res_v["e"], r["err"], mism)
        return r

    def op_rmdir(self, pid, rv, res_v, post_fs, mism):
        if rv["dfd"] == -1:
            r = self.drv.request(op="rmdir", pid=pid,
                                 path=real_path(rv["pth"]))
        else:
            r = self.drv.request(op="unlinkat", pid=pid,
                                 dirfd=self.rfd(pid, rv["dfd"]),
                                 path=real_path(rv["pth"]), rmdir=True)
        self.check_status(res_v["e"], r["err"], mism)
        return r

    def op_rename(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="rename", pid=pid,
                             old=real_path(rv["pthOld"]),
                             new=real_path(rv["pthNew"]))
        self.check_status(res_v["e"], r["err"], mism)
        return r

    def op_readlink(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="readlink", pid=pid,
                             path=real_path(rv["pth"]))
        if self.check_status(res_v["e"], r["err"], mism) \
                and res_v["e"] == 0:
            want = real_target(res_v["tgt"])
            if r.get("target") != want:
                mism.append(f"readlink: expected {want!r}, "
                            f"got {r.get('target')!r}")
        return r

    def op_opendir(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="opendir", pid=pid,
                             path=real_path(rv["pth"]))
        if self.check_status(res_v["e"], r["err"], mism) \
                and res_v["e"] == 0:
            self.sidmap[res_v["sid"]] = r["ret"]
        return r

    def op_readdir(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="readdir", pid=pid,
                             sid=self.rsid(rv["sid"]))
        if self.check_status(res_v["e"], r["err"], mism) \
                and res_v["e"] == 0:
            names = r.get("names", [])
            if len(names) != len(set(names)):
                mism.append(f"readdir: duplicate entries in {sorted(names)}")
            got = set(names) - {".", ".."}
            want = set(res_v["names"])
            if got != want:
                mism.append(f"readdir: expected {sorted(want)}, "
                            f"got {sorted(got)}")
        return r

    def op_rewinddir(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="rewinddir", pid=pid,
                             sid=self.rsid(rv["sid"]))
        self.check_status(res_v["e"], r["err"], mism)
        return r

    def op_closedir(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="closedir", pid=pid,
                             sid=self.rsid(rv["sid"]))
        if self.check_status(res_v["e"], r["err"], mism) \
                and res_v["e"] == 0:
            self.sidmap.pop(rv["sid"], None)
        return r

    def op_fcntl_dupfd(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="fcntl_dupfd", pid=pid,
                             fd=self.rfd(pid, rv["fd"]),
                             atleast=rv["atLeast"])
        ok = self.check_status(res_v["e"], r["err"], mism)
        if res_v["e"] == 0:
            if ok:
                self.fdmap[(pid, res_v["fd"])] = r["ret"]
            elif r["err"] == 22:
                # PD2: F_DUPFD is unimplemented (EINVAL).  Emulate with
                # dup() -- identical semantics except the (never checked)
                # descriptor number -- so the model's new descriptor exists
                # on the real side and the trace keeps replaying in sync.
                r2 = self.drv.request(op="dup", pid=pid,
                                      fd=self.rfd(pid, rv["fd"]))
                if r2["err"] == 0:
                    self.fdmap[(pid, res_v["fd"])] = r2["ret"]
        return r

    def op_fcntl_getfl(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="fcntl_getfl", pid=pid,
                             fd=self.rfd(pid, rv["fd"]))
        if self.check_status(res_v["e"], r["err"], mism) \
                and res_v["e"] == 0:
            want_acc = ACC_FLAGS[res_v["acc"]["tag"]]
            if (r["ret"] & os.O_ACCMODE) != want_acc:
                mism.append(f"F_GETFL access mode: expected {want_acc}, "
                            f"got {r['ret'] & os.O_ACCMODE}")
            if bool(r["ret"] & os.O_APPEND) != res_v["appendF"]:
                mism.append(f"F_GETFL O_APPEND: expected {res_v['appendF']},"
                            f" flags {r['ret']:#x}")
        return r

    def op_fcntl_setfl(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="fcntl_setfl", pid=pid,
                             fd=self.rfd(pid, rv["fd"]),
                             flags=os.O_APPEND if rv["appendF"] else 0)
        self.check_status(res_v["e"], r["err"], mism)
        return r

    def op_fcntl_lock(self, pid, rv, res_v, post_fs, mism):
        cmd = LOCK_CMD[rv["cmd"]["tag"]]
        r = self.drv.request(op="fcntl_lock", pid=pid,
                             fd=self.rfd(pid, rv["fd"]), cmd=cmd,
                             type=LOCK_TYPE[rv["lk"]["tag"]],
                             start=rv["lo"] * self.bs,
                             len=(rv["hi"] - rv["lo"]) * self.bs)
        if self.check_status(res_v["e"], r["err"], mism) \
                and res_v["e"] == 0 and cmd == "getlk":
            conflict = r.get("l_type", "un") != "un"
            if conflict != res_v["conflict"]:
                mism.append(f"F_GETLK: expected conflict="
                            f"{res_v['conflict']}, got l_type "
                            f"{r.get('l_type')}")
        return r

    def op_lockf(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="lockf", pid=pid,
                             fd=self.rfd(pid, rv["fd"]),
                             cmd=LOCKF_CMD[rv["cmd"]["tag"]],
                             len=rv["len"] * self.bs)
        self.check_status(res_v["e"], r["err"], mism)
        return r

    def op_fsync(self, pid, rv, res_v, post_fs, mism):
        op = "fdatasync" if rv["dataOnly"] else "fsync"
        r = self.drv.request(op=op, pid=pid, fd=self.rfd(pid, rv["fd"]))
        self.check_status(res_v["e"], r["err"], mism)
        return r

    def op_copy_range(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="copy_range", pid=pid,
                             fd_in=self.rfd(pid, rv["fdIn"]),
                             off_in=rv["offIn"] * self.bs,
                             fd_out=self.rfd(pid, rv["fdOut"]),
                             off_out=rv["offOut"] * self.bs,
                             len=rv["len"] * self.bs)
        if self.check_status(res_v["e"], r["err"], mism) \
                and res_v["e"] == 0:
            want = res_v["n"] * self.bs
            if r["ret"] != want:
                mism.append(f"copy_file_range: expected {want}, "
                            f"got {r['ret']}")
        return r

    def op_clone_range(self, pid, rv, res_v, post_fs, mism):
        r = self.drv.request(op="clone_range", pid=pid,
                             dst_fd=self.rfd(pid, rv["fdDst"]),
                             dst_off=rv["offDst"] * self.bs,
                             src_fd=self.rfd(pid, rv["fdSrc"]),
                             src_off=rv["offSrc"] * self.bs,
                             len=rv["len"] * self.bs)
        self.check_status(res_v["e"], r["err"], mism)
        return r

    HANDLERS = {
        "ROpen": op_open,
        "RClose": op_close,
        "RDup": op_dup,
        "RDup2": op_dup2,
        "RLseek": op_lseek,
        "RRead": op_read,
        "RWrite": op_write,
        "RPread": op_pread,
        "RPwrite": op_pwrite,
        "RTruncate": op_truncate,
        "RFtruncate": op_ftruncate,
        "RStat": op_stat,
        "RFstat": op_fstat,
        "RChmod": op_chmod,
        "RFchmod": op_fchmod,
        "RChown": op_chown,
        "RFchown": op_fchown,
        "RUtimens": op_utimens,
        "RFutimens": op_futimens,
        "RAccess": op_access,
        "RUmask": op_umask,
        "RMkdir": op_mkdir,
        "RMknod": op_mknod,
        "RSymlink": op_symlink,
        "RLink": op_link,
        "RUnlink": op_unlink,
        "RRmdir": op_rmdir,
        "RRename": op_rename,
        "RReadlink": op_readlink,
        "ROpendir": op_opendir,
        "RReaddir": op_readdir,
        "RRewinddir": op_rewinddir,
        "RClosedir": op_closedir,
        "RFcntlDupfd": op_fcntl_dupfd,
        "RFcntlGetfl": op_fcntl_getfl,
        "RFcntlSetfl": op_fcntl_setfl,
        "RFcntlLock": op_fcntl_lock,
        "RLockf": op_lockf,
        "RFsync": op_fsync,
        "RCopyRange": op_copy_range,
        "RCloneRange": op_clone_range,
    }

    def cleanup(self):
        """Best-effort close of everything still open, so driver shutdown
        does not trip chimera's shutdown-with-open-descriptors hang (PD9)."""
        try:
            for sid in list(self.sidmap.values()):
                self.drv.request(op="closedir", pid=0, sid=sid)
            for real in list(self.fdmap.values()):
                self.drv.request(op="close", pid=0, fd=real)
        except (RuntimeError, OSError, json.JSONDecodeError):
            pass

    def replay(self, states):
        for idx, state in enumerate(states[1:], start=1):
            label = state["lastOp"]
            if label["tag"] != "LCall":
                raise TraceFormatError(
                    f"step {idx}: unexpected label {label['tag']}")
            pid = label["value"]["pid"]
            req = label["value"]["req"]
            res = label["value"]["res"]
            tag = req["tag"]
            handler = self.HANDLERS.get(tag)
            if handler is None:
                raise TraceFormatError(f"step {idx}: no handler for {tag}")
            signal.alarm(60)
            mism = []
            self._cur_tag = tag
            self._cur_req = req["value"]
            self._cur_fs = state["fs"]
            r = handler(self, pid, req["value"], res["value"],
                        state["fs"], mism)
            self.history.append((idx, pid, tag, req["value"],
                                 res["value"], r))
            if self.verbose:
                print(f"  [{idx:4d}] pid{pid} {tag} {req['value']} "
                      f"-> {r}")
            if mism:
                raise Divergence(idx, (tag, req["value"], res["value"]),
                                 mism)
        signal.alarm(0)


def diff_bytes(expect, actual, block_size):
    n = min(len(expect), len(actual))
    for i in range(0, n, block_size):
        if expect[i:i + block_size] != actual[i:i + block_size]:
            return (f"; first differing block {i // block_size}: "
                    f"expected byte {expect[i]:#x}, "
                    f"got byte {actual[i] if i < len(actual) else -1:#x}")
    return "; lengths differ only"


# ---------------------------------------------------------------------------
# Live-profile probe: measures the capability/policy profile of the backend
# behind posix_driver, for pinning PROFILE and posix_run.qnt's posixMemfs.
# ---------------------------------------------------------------------------

def probe(driver_path):
    drv = Driver(driver_path)
    bs = drv.block_size
    out = {}
    root = {"uid": 0, "gid": 10, "gids": [10, 30]}
    user1 = {"uid": 100, "gid": 10, "gids": [10, 30]}
    user2 = {"uid": 200, "gid": 20, "gids": [20, 30]}
    drv.request(op="setcred", pid=0, **root)
    drv.request(op="setcred", pid=1, **user2)
    drv.request(op="setcred", pid=2, **user1)
    blk = base64.b64encode(b"A" * bs).decode()

    def mk(path, pid=0, mode=0o777):
        drv.request(op="mkdir", pid=pid, path=path, mode=mode)

    def touch(path, pid=0, mode=0o666, data=None):
        r = drv.request(op="open", pid=pid, path=path,
                        flags=os.O_CREAT | os.O_WRONLY, mode=mode)
        if data:
            drv.request(op="write", pid=pid, fd=r["ret"], data=data)
        drv.request(op="close", pid=pid, fd=r["ret"])

    # copy_file_range / clone_file_range / SEEK_HOLE
    touch("/test/p_src", data=blk)
    touch("/test/p_dst")
    fin = drv.request(op="open", pid=0, path="/test/p_src",
                      flags=os.O_RDONLY, mode=0)["ret"]
    fout = drv.request(op="open", pid=0, path="/test/p_dst",
                       flags=os.O_WRONLY, mode=0)["ret"]
    r = drv.request(op="copy_range", pid=0, fd_in=fin, off_in=0,
                    fd_out=fout, off_out=0, len=bs)
    out["copyRange"] = r["ret"] >= 0
    r = drv.request(op="clone_range", pid=0, dst_fd=fout, dst_off=0,
                    src_fd=fin, src_off=0, len=bs)
    out["cloneRange"] = r["ret"] >= 0
    drv.request(op="ftruncate", pid=0, fd=fout, len=0)
    drv.request(op="pwrite", pid=0, fd=fout, off=0, data=blk)
    drv.request(op="ftruncate", pid=0, fd=fout, len=3 * bs)
    r = drv.request(op="lseek", pid=0, fd=fout, off=0, whence="hole")
    out["seekHole"] = r["ret"] == bs
    out["seekHoleRaw"] = r["ret"]
    drv.request(op="close", pid=0, fd=fin)
    drv.request(op="close", pid=0, fd=fout)

    # gidFromParent: dir gid 77, creator (root, egid 10) makes a file
    mk("/test/p_gid")
    drv.request(op="chown", pid=0, path="/test/p_gid", uid=0, gid=77,
                follow=True)
    touch("/test/p_gid/f")
    r = drv.request(op="stat", pid=0, path="/test/p_gid/f", follow=True)
    out["gidFromParent"] = r.get("gid") == 77
    out["gidFromParentRaw"] = r.get("gid")

    # sgidInherit: subdir of a setgid dir
    mk("/test/p_sgid")
    drv.request(op="chmod", pid=0, path="/test/p_sgid", mode=0o2777)
    mk("/test/p_sgid/sub", mode=0o755)
    r = drv.request(op="stat", pid=0, path="/test/p_sgid/sub", follow=True)
    out["sgidInherit"] = bool(r.get("mode", 0) & 0o2000)

    # writeClearsSets: unprivileged owner writes a setuid file
    touch("/test/p_setid", pid=1, mode=0o700)
    drv.request(op="chmod", pid=1, path="/test/p_setid", mode=0o4755)
    fd = drv.request(op="open", pid=1, path="/test/p_setid",
                     flags=os.O_WRONLY, mode=0)["ret"]
    drv.request(op="write", pid=1, fd=fd, data=blk)
    drv.request(op="close", pid=1, fd=fd)
    r = drv.request(op="stat", pid=1, path="/test/p_setid", follow=True)
    out["writeClearsSets"] = not (r.get("mode", 0) & 0o4000)

    # pwriteAppends: pwrite at 0 through an O_APPEND descriptor
    touch("/test/p_app", data=blk)
    fd = drv.request(op="open", pid=0, path="/test/p_app",
                     flags=os.O_WRONLY | os.O_APPEND, mode=0)["ret"]
    drv.request(op="pwrite", pid=0, fd=fd, off=0,
                data=base64.b64encode(b"B" * bs).decode())
    drv.request(op="close", pid=0, fd=fd)
    r = drv.request(op="stat", pid=0, path="/test/p_app", follow=True)
    out["pwriteAppends"] = r.get("size") == 2 * bs

    # renameCtime
    touch("/test/p_ren")
    r1 = drv.request(op="stat", pid=0, path="/test/p_ren", follow=True)
    import time
    time.sleep(0.02)
    drv.request(op="rename", pid=0, old="/test/p_ren", new="/test/p_ren2")
    r2 = drv.request(op="stat", pid=0, path="/test/p_ren2", follow=True)
    out["renameCtime"] = tuple(r2["ctime"]) > tuple(r1["ctime"])

    # strictAtime: read marks atime
    touch("/test/p_at", data=blk)
    r1 = drv.request(op="stat", pid=0, path="/test/p_at", follow=True)
    time.sleep(0.02)
    fd = drv.request(op="open", pid=0, path="/test/p_at",
                     flags=os.O_RDONLY, mode=0)["ret"]
    drv.request(op="read", pid=0, fd=fd, len=bs)
    drv.request(op="close", pid=0, fd=fd)
    r2 = drv.request(op="stat", pid=0, path="/test/p_at", follow=True)
    out["strictAtime"] = tuple(r2["atime"]) > tuple(r1["atime"])

    # sticky arm + errno: sticky dir owned by root; victim owned by uid 100
    mk("/test/p_sticky")
    drv.request(op="chmod", pid=0, path="/test/p_sticky", mode=0o1777)
    touch("/test/p_sticky/w", mode=0o666)
    drv.request(op="chown", pid=0, path="/test/p_sticky/w", uid=100,
                gid=10, follow=True)
    r = drv.request(op="unlink", pid=1, path="/test/p_sticky/w")
    out["stickyWriteArm"] = r["ret"] == 0
    touch("/test/p_sticky/s", mode=0o600)
    drv.request(op="chown", pid=0, path="/test/p_sticky/s", uid=100,
                gid=10, follow=True)
    r = drv.request(op="unlink", pid=1, path="/test/p_sticky/s")
    out["stickyDenyErrno"] = r["err"]
    out["errStickyAcces"] = r["err"] == 13 if r["ret"] < 0 else None

    # errNotempty / errUnlinkDirIsdir
    mk("/test/p_ne")
    mk("/test/p_ne/x")
    r = drv.request(op="rmdir", pid=0, path="/test/p_ne")
    out["errNotempty"] = r["err"] == 39
    out["rmdirNonemptyErrno"] = r["err"]
    r = drv.request(op="unlink", pid=0, path="/test/p_ne")
    out["errUnlinkDirIsdir"] = r["err"] == 21
    out["unlinkDirErrno"] = r["err"]

    # record locks (expected EOPNOTSUPP on memfs, see PD1)
    fd = drv.request(op="open", pid=0, path="/test/p_src",
                     flags=os.O_RDWR, mode=0)["ret"]
    r = drv.request(op="fcntl_lock", pid=0, fd=fd, cmd="setlk", type="wr",
                    start=0, len=bs)
    out["lockErrno"] = r["err"]
    out["errLockAgain"] = None
    drv.request(op="close", pid=0, fd=fd)

    drv.close()
    return out


def report_divergence(trace_path, div, replayer, driver):
    print(f"\n=== DIVERGENCE in {trace_path} ===", file=sys.stderr)
    print(f"step {div.step}: {div.op[0]} req: {div.op[1]}", file=sys.stderr)
    print(f"  model expectation: {div.op[2]}", file=sys.stderr)
    for m in div.mismatches:
        print(f"  MISMATCH: {m}", file=sys.stderr)
    print("\nlast operations before failure:", file=sys.stderr)
    for idx, pid, tag, req, res, r in replayer.history[-10:]:
        print(f"  [{idx:4d}] pid{pid} {tag} {req} expect {res} -> {r}",
              file=sys.stderr)
    print("\n(pid, model fd) -> real fd map:", file=sys.stderr)
    for k, v in sorted(replayer.fdmap.items()):
        print(f"  {k}: {v}", file=sys.stderr)
    print(f"\ndriver stderr tail:\n{driver.stderr_tail()}", file=sys.stderr)


def run_trace(trace_path, args):
    states = load_trace(trace_path)
    if args.dry_run:
        print(f"{trace_path}: {len(states) - 1} steps, format OK")
        return True

    init = states[0]["lastOp"]
    if init["tag"] != "LInit":
        raise TraceFormatError(f"{trace_path}: first label is not LInit")
    caps = init["value"]["caps"]

    for key, want in PROFILE.items():
        if want is not None and caps.get(key) != want:
            print(f"{trace_path}: SKIP: trace profile {key}="
                  f"{caps.get(key)} does not match live profile {want}")
            sys.exit(77)

    driver = Driver(args.driver)
    try:
        replayer = Replayer(driver, caps, verbose=args.verbose)
        try:
            replayer.replay(states)
        except Divergence as div:
            report_divergence(trace_path, div, replayer, driver)
            replayer.cleanup()
            return False
        replayer.cleanup()

        dev_summary = ""
        if replayer.deviations_hit:
            parts = ", ".join(
                f"{k}x{v}"
                for k, v in sorted(replayer.deviations_hit.items()))
            dev_summary = f"; known deviations: {parts}"
        print(f"{trace_path}: {len(states) - 1} steps replayed"
              f"{dev_summary}")
        return True
    finally:
        driver.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--trace", action="append", default=[],
                    help="ITF trace file (repeatable; fresh driver per "
                         "trace)")
    ap.add_argument("--driver", help="path to the posix_quint_driver binary")
    ap.add_argument("--dry-run", action="store_true",
                    help="parse and validate traces without a driver")
    ap.add_argument("--probe", action="store_true",
                    help="measure the live capability/policy profile")
    ap.add_argument("--check-profile", action="store_true",
                    help="measure the live profile and diff against the "
                         "pinned PROFILE")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    def on_alarm(sig, frame):
        print("FATAL: driver request timed out (possible deadlock)",
              file=sys.stderr)
        sys.exit(1)

    signal.signal(signal.SIGALRM, on_alarm)

    if args.probe or args.check_profile:
        if not args.driver:
            ap.error("--driver is required for probing")
        measured = probe(args.driver)
        print(json.dumps(measured, indent=2))
        if args.check_profile:
            bad = [k for k, v in PROFILE.items()
                   if v is not None and measured.get(k) != v]
            if bad:
                print(f"PROFILE drift on: {bad}", file=sys.stderr)
                sys.exit(1)
        return

    if not args.trace:
        ap.error("--trace is required unless --probe")
    if not args.dry_run and not args.driver:
        ap.error("--driver is required unless --dry-run")

    failures = 0
    for trace in args.trace:
        if not run_trace(trace, args):
            failures += 1
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
