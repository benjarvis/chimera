#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
#
# SPDX-License-Identifier: LGPL-2.1-only

"""Replay a Quint-generated ITF trace against a live chimera NFS3 daemon.

Each state of the trace carries a `lastOp` record naming the RPC the model
issued and the reply the server must produce (see nfs3.qnt).  This harness
spawns a chimera daemon backed by memfs, obtains the export root file
handle via MOUNTv3, then replays every step through the standalone client
in nfs3_client.py, comparing the server's actual reply against the model's
expectation.  Any mismatch is reported as a divergence with full context
and fails the run.

Model-to-wire mapping maintained here:
  - model Fid        -> real nfs_fh3, learned from LOOKUP/CREATE/MKDIR
                        replies (byte-compared once known)
  - model block i    -> BLOCK_SIZE bytes at offset i * BLOCK_SIZE; block
                        symbol 0 is a hole (zero bytes), symbol s > 0 is
                        BLOCK_SIZE repetitions of byte 0x40 + s
  - fileid           -> not predicted; checked for consistency (a fid must
                        always report the same fileid; live fids distinct)
"""

import argparse
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nfs3_client  # noqa: E402
import deviations  # noqa: E402
from nfs3_client import (  # noqa: E402
    NFS3_OK, NF3REG, NF3DIR, NF3LNK, NF3SOCK, NF3FIFO,
    UNCHECKED, GUARDED, EXCLUSIVE)

FTYPE_WIRE = {"TReg": NF3REG, "TDir": NF3DIR, "TLnk": NF3LNK,
              "TFifo": NF3FIFO, "TSock": NF3SOCK}
CREATE_WIRE = {"Unchecked": UNCHECKED, "Guarded": GUARDED,
               "Exclusive": EXCLUSIVE}

# Expected constant replies, established empirically against the daemon
# (probe of 2026-08-08) and pinned here as regression checks.
# chimera: nfs3_proc_fsinfo.c (hardcoded transfer sizes/properties),
# nfs3_proc_pathconf.c (fully synthetic), memfs FSSTAT totals.
FSINFO_EXPECT = {"rtmax": 1048576, "rtpref": 1048576, "rtmult": 4096,
                 "wtmax": 1048576, "wtpref": 1048576, "wtmult": 4096,
                 "dtpref": 65536, "maxfilesize": 0xffffffffffffffff,
                 "time_delta": (0, 1), "properties": 0x1b}
PATHCONF_EXPECT = {"linkmax": 0xffffffff, "name_max": 255, "no_trunc": True,
                   "chown_restricted": True, "case_insensitive": False,
                   "case_preserving": True}
FSSTAT_EXPECT = {"tbytes": 107374182400, "fbytes": 107374182400,
                 "abytes": 107374182400, "tfiles": 1048576,
                 "ffiles": 1048576, "afiles": 1048576, "invarsec": 0}


class TraceFormatError(Exception):
    pass


class Divergence(Exception):
    def __init__(self, step, op, mismatches):
        self.step = step
        self.op = op
        self.mismatches = mismatches
        super().__init__(f"step {step}: " + "; ".join(mismatches))


def itf_decode(v):
    """Decode one ITF-encoded Quint value into plain Python data.

    Unknown encodings raise TraceFormatError so a Quint format change is a
    loud failure, never a silently skipped check.
    """
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
        states.append({k: itf_decode(v) for k, v in st.items()
                       if k != "#meta" and not k.startswith("mbt::")})
    for st in states:
        if "lastOp" not in st or "fs" not in st:
            raise TraceFormatError(f"{path}: state missing lastOp/fs")
    return states


class ChimeraServer:
    """Daemon lifecycle, following the s3_test.py / pynfs wrapper pattern."""

    READY_TIMEOUT = 30

    def __init__(self, chimera_path, nfs_port=2049, mount_port=20048):
        self.chimera_path = chimera_path
        self.nfs_port = nfs_port
        self.mount_port = mount_port
        self.process = None
        self.temp_dir = None
        self.log_path = None

    def start(self):
        self.temp_dir = tempfile.mkdtemp(prefix="nfs3_mbt_")
        config = {
            "server": {
                "threads": 4,
                "nfs_port": self.nfs_port,
                "external_portmap": False,
            },
            "mounts": {"share": {"module": "memfs", "path": "/"}},
            "exports": {"/share": {"path": "/share"}},
        }
        config_path = os.path.join(self.temp_dir, "config.json")
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

        self.log_path = os.path.join(self.temp_dir, "chimera.log")
        log = open(self.log_path, "wb")
        self.process = subprocess.Popen(
            [self.chimera_path, "-c", config_path],
            stdout=log, stderr=subprocess.STDOUT)
        log.close()

        deadline = time.time() + self.READY_TIMEOUT
        while True:
            if self.process.poll() is not None:
                raise RuntimeError(
                    f"chimera daemon exited during startup:\n{self.log_tail()}")
            try:
                with socket.create_connection(("127.0.0.1", self.mount_port),
                                              timeout=1):
                    pass
                with socket.create_connection(("127.0.0.1", self.nfs_port),
                                              timeout=1):
                    return
            except OSError:
                if time.time() >= deadline:
                    raise RuntimeError(
                        f"chimera not accepting connections after "
                        f"{self.READY_TIMEOUT}s:\n{self.log_tail()}")
                time.sleep(0.1)

    def log_tail(self, lines=100):
        try:
            with open(self.log_path, errors="replace") as f:
                return "".join(f.readlines()[-lines:])
        except OSError:
            return "<no daemon log>"

    def alive(self):
        return self.process is not None and self.process.poll() is None

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()


class Replayer:
    def __init__(self, client, root_fh, block_size, verbose=False):
        self.client = client
        self.block_size = block_size
        self.verbose = verbose
        self.fh = {0: root_fh}
        self.fileid = {}
        self.write_verf = None
        self.attr_checks = 0
        self.attr_skips = 0
        self.history = []
        # Known-deviation bookkeeping and the current step's context, which
        # check_status consults to reconcile a divergence (see deviations.py).
        self.deviations_hit = {}
        self._cur_tag = None
        self._cur_op = None
        self._cur_fs = None

    # -- helpers ----------------------------------------------------------

    def block_bytes(self, sym):
        if sym == 0:
            return b"\0" * self.block_size
        return bytes([0x40 + sym]) * self.block_size

    def expand(self, syms):
        return b"".join(self.block_bytes(s) for s in syms)

    def real_fh(self, fid, mism):
        fh = self.fh.get(fid)
        if fh is None:
            mism.append(f"model fid {fid} has no learned file handle "
                        f"(harness bug or earlier divergence)")
            raise Divergence(0, ("<no rpc sent>", {"fid": fid}), mism)
        return fh

    def learn_fh(self, fid, fh, mism):
        if fh is None:
            mism.append(f"server returned no file handle for fid {fid} "
                        f"(handle_follows=0)")
            return
        known = self.fh.get(fid)
        if known is None:
            self.fh[fid] = fh
        elif known != fh:
            mism.append(f"fid {fid}: file handle changed: "
                        f"was {known.hex()}, now {fh.hex()}")

    def check_attrs(self, fid, attrs, post_fs, mism, what="obj_attrs"):
        """Compare a returned fattr3 against the model's post-state node."""
        if attrs is None:
            self.attr_skips += 1
            return
        self.attr_checks += 1
        node = post_fs.get(fid)
        if node is None:
            mism.append(f"{what}: fid {fid} not in model post-state")
            return
        ftype = node["ftype"]["tag"]
        if attrs["type"] != FTYPE_WIRE[ftype]:
            mism.append(f"{what}: type: expected {FTYPE_WIRE[ftype]} "
                        f"({ftype}), got {attrs['type']}")
        if attrs["mode"] & 0o7777 != node["mode"]:
            mism.append(f"{what}: mode: expected {node['mode']:#o}, "
                        f"got {attrs['mode'] & 0o7777:#o}")
        if ftype != "TDir" and attrs["nlink"] != node["nlink"]:
            mism.append(f"{what}: nlink: expected {node['nlink']}, "
                        f"got {attrs['nlink']}")
        if ftype == "TReg":
            expect_size = len(node["data"]) * self.block_size
            if attrs["size"] != expect_size:
                mism.append(f"{what}: size: expected {expect_size}, "
                            f"got {attrs['size']}")
        elif ftype == "TLnk":
            if attrs["size"] != len(node["target"]):
                mism.append(f"{what}: symlink size: expected "
                            f"{len(node['target'])}, got {attrs['size']}")
        known = self.fileid.get(fid)
        if known is None:
            for other, other_id in self.fileid.items():
                if other_id == attrs["fileid"] and other in post_fs:
                    mism.append(f"{what}: fileid {attrs['fileid']} of fid "
                                f"{fid} collides with live fid {other}")
            self.fileid[fid] = attrs["fileid"]
        elif known != attrs["fileid"]:
            mism.append(f"{what}: fileid: fid {fid} previously reported "
                        f"{known}, now {attrs['fileid']}")

    def check_status(self, expected, actual, mism):
        """True if the reply status matches (proceed with OK-path checks).

        On a mismatch, consult the known-deviation registry: a registered,
        reconcilable deviation is recorded and treated as an expected xfail
        (returns False so the caller skips OK-path field checks, since the
        actual reply is the diverging one); an unregistered mismatch is a
        hard failure.
        """
        if actual == expected:
            return True
        dev = deviations.reconcile(self._cur_tag, self._cur_op,
                                   expected, actual, self._cur_fs)
        if dev is not None:
            self.deviations_hit[dev.id] = self.deviations_hit.get(dev.id, 0) + 1
            return False
        mism.append(f"status: expected {expected}, got {actual}")
        return False

    # -- per-procedure handlers -------------------------------------------

    def op_lookup(self, op, post_fs, mism):
        res = self.client.lookup(self.real_fh(op["dir"], mism), op["name"])
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            self.learn_fh(op["child"], res["obj_fh"], mism)
            self.check_attrs(op["child"], res["obj_attrs"], post_fs, mism)
        return res

    def op_getattr(self, op, post_fs, mism):
        res = self.client.getattr(self.real_fh(op["obj"], mism))
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            # OGetattr embeds the expected attrs, but they equal the
            # post-state node; one comparison path serves every reply.
            self.check_attrs(op["obj"], res["attrs"], post_fs, mism,
                             what="attrs")
        return res

    def op_create(self, op, post_fs, mism):
        cmode = CREATE_WIRE[op["cmode"]["tag"]]
        if cmode == EXCLUSIVE:
            res = self.client.create(self.real_fh(op["dir"], mism), op["name"],
                                     createmode=EXCLUSIVE,
                                     verf=struct.pack(">Q", op["verf"]))
        else:
            res = self.client.create(self.real_fh(op["dir"], mism), op["name"],
                                     createmode=cmode, mode=op["mode"])
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            self.learn_fh(op["obj"], res["obj_fh"], mism)
            self.check_attrs(op["obj"], res["obj_attrs"], post_fs, mism)
        return res

    def op_setattr(self, op, post_fs, mism):
        fh = self.real_fh(op["obj"], mism)
        guard = None
        if op["guard"] == 1:
            # A matching guard needs the object's live ctime; fetch it with
            # an auxiliary GETATTR (not part of the modeled sequence).
            pre = self.client.getattr(fh)
            if pre["status"] != NFS3_OK:
                mism.append(f"pre-guard GETATTR failed: {pre['status']}")
                return pre
            guard = tuple(pre["attrs"]["ctime"])
        elif op["guard"] == 2:
            guard = (1, 1)
        res = self.client.setattr(
            fh,
            mode=None if op["mode"] < 0 else op["mode"],
            size=None if op["sizeBlocks"] < 0
                 else op["sizeBlocks"] * self.block_size,
            guard_ctime=guard)
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            self.check_attrs(op["obj"], res["wcc"]["after"], post_fs, mism,
                             what="wcc.after")
        return res

    def op_access(self, op, post_fs, mism):
        res = self.client.access(self.real_fh(op["obj"], mism), op["mask"])
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            if res["access"] != op["access"]:
                mism.append(f"access: expected {op['access']:#x}, "
                            f"got {res['access']:#x}")
            self.check_attrs(op["obj"], res["attrs"], post_fs, mism)
        return res

    def op_symlink(self, op, post_fs, mism):
        # Request mode 0777; the model expects the server to ignore it and
        # store 0755 (see symlinkNode in nfs3.qnt).
        res = self.client.symlink(self.real_fh(op["dir"], mism), op["name"],
                                  op["target"], mode=0o777)
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            self.learn_fh(op["obj"], res["obj_fh"], mism)
            self.check_attrs(op["obj"], res["obj_attrs"], post_fs, mism)
        return res

    def op_readlink(self, op, post_fs, mism):
        res = self.client.readlink(self.real_fh(op["obj"], mism))
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            if res["target"] != op["target"]:
                mism.append(f"readlink: expected {op['target']!r}, "
                            f"got {res['target']!r}")
            self.check_attrs(op["obj"], res["attrs"], post_fs, mism)
        return res

    def op_mknod(self, op, post_fs, mism):
        res = self.client.mknod(self.real_fh(op["dir"], mism), op["name"],
                                FTYPE_WIRE[op["ftype"]["tag"]],
                                mode=op["mode"])
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            self.learn_fh(op["obj"], res["obj_fh"], mism)
            self.check_attrs(op["obj"], res["obj_attrs"], post_fs, mism)
        return res

    def op_rename(self, op, post_fs, mism):
        res = self.client.rename(self.real_fh(op["fromDir"], mism),
                                 op["fromName"],
                                 self.real_fh(op["toDir"], mism),
                                 op["toName"])
        self.check_status(op["status"], res["status"], mism)
        return res

    def op_link(self, op, post_fs, mism):
        res = self.client.link(self.real_fh(op["obj"], mism),
                               self.real_fh(op["dir"], mism), op["name"])
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            self.check_attrs(op["obj"], res["attrs"], post_fs, mism,
                             what="file_attributes")
        return res

    def op_readdir(self, op, post_fs, mism):
        fh = self.real_fh(op["dir"], mism)
        if op["plus"]:
            res = self.client.readdirplus(fh)
        else:
            res = self.client.readdir(fh)
        if not self.check_status(op["status"], res["status"], mism) \
                or op["status"] != NFS3_OK:
            return res
        names = [e["name"] for e in res["entries"]]
        if len(names) != len(set(names)):
            mism.append(f"readdir: duplicate entries in {sorted(names)}")
        # chimera emits "." and ".." (probed 2026-08-08).
        expect = set(op["names"]) | {".", ".."}
        if set(names) != expect:
            mism.append(f"readdir: expected entries {sorted(expect)}, "
                        f"got {sorted(names)}")
        if not res["eof"]:
            mism.append("readdir: eof not set on single-shot full listing")
        ents = post_fs[op["dir"]]["ents"]
        for e in res["entries"]:
            if e["name"] == ".":
                fid = op["dir"]
            elif e["name"] == ".." or e["name"] not in ents:
                continue
            else:
                fid = ents[e["name"]]
            known = self.fileid.get(fid)
            if known is None:
                self.fileid[fid] = e["fileid"]
            elif known != e["fileid"]:
                mism.append(f"readdir: entry {e['name']!r}: fileid of fid "
                            f"{fid} previously {known}, now {e['fileid']}")
            if op["plus"] and e["name"] not in (".", ".."):
                self.learn_fh(fid, e.get("fh"), mism)
                self.check_attrs(fid, e.get("attrs"), post_fs, mism,
                                 what=f"readdirplus[{e['name']}]")
        return res

    def op_commit(self, op, post_fs, mism):
        res = self.client.commit(self.real_fh(op["file"], mism))
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            if self.write_verf is None:
                self.write_verf = res["verf"]
            elif res["verf"] != self.write_verf:
                mism.append(f"commit verifier differs from write verifier: "
                            f"{self.write_verf.hex()} -> {res['verf'].hex()}")
        return res

    def _check_consts(self, res, expect, mism):
        for k, v in expect.items():
            got = tuple(res[k]) if isinstance(res[k], tuple) else res[k]
            if got != v:
                mism.append(f"{k}: expected {v}, got {res[k]}")

    def op_fsstat(self, op, post_fs, mism):
        res = self.client.fsstat(self.fh[0])
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            self._check_consts(res, FSSTAT_EXPECT, mism)
        return res

    def op_fsinfo(self, op, post_fs, mism):
        res = self.client.fsinfo(self.fh[0])
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            self._check_consts(res, FSINFO_EXPECT, mism)
        return res

    def op_pathconf(self, op, post_fs, mism):
        res = self.client.pathconf(self.real_fh(op["obj"], mism))
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            self._check_consts(res, PATHCONF_EXPECT, mism)
        return res

    def op_stalegetattr(self, op, post_fs, mism):
        res = self.client.getattr(self.real_fh(op["obj"], mism))
        self.check_status(op["status"], res["status"], mism)
        return res

    def op_mkdir(self, op, post_fs, mism):
        res = self.client.mkdir(self.real_fh(op["dir"], mism), op["name"],
                                mode=op["mode"])
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            self.learn_fh(op["obj"], res["obj_fh"], mism)
            self.check_attrs(op["obj"], res["obj_attrs"], post_fs, mism)
        return res

    def op_write(self, op, post_fs, mism):
        data = self.block_bytes(op["pat"]) * op["count"]
        res = self.client.write(self.real_fh(op["file"], mism),
                                op["offset"] * self.block_size,
                                data, stable=op["stable"])
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            if res["count"] != len(data):
                mism.append(f"count: expected {len(data)}, got {res['count']}")
            if res["committed"] < op["stable"]:
                mism.append(f"committed {res['committed']} weaker than "
                            f"requested stability {op['stable']}")
            if self.write_verf is None:
                self.write_verf = res["verf"]
            elif res["verf"] != self.write_verf:
                mism.append(f"write verifier changed mid-run: "
                            f"{self.write_verf.hex()} -> {res['verf'].hex()}")
            self.check_attrs(op["file"], res["wcc"]["after"], post_fs, mism,
                             what="wcc.after")
        return res

    def op_read(self, op, post_fs, mism):
        res = self.client.read(self.real_fh(op["file"], mism),
                               op["offset"] * self.block_size,
                               op["count"] * self.block_size)
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            expect = self.expand(op["blocks"])
            if res["count"] != len(expect):
                mism.append(f"count: expected {len(expect)}, "
                            f"got {res['count']}")
            if bool(res["eof"]) != op["eof"]:
                mism.append(f"eof: expected {op['eof']}, got {res['eof']}")
            if res["data"] != expect:
                mism.append(
                    f"data mismatch: expected {len(expect)} bytes "
                    f"(blocks {op['blocks']}), got {len(res['data'])} bytes"
                    + diff_bytes(expect, res["data"], self.block_size))
            self.check_attrs(op["file"], res["attrs"], post_fs, mism,
                             what="file_attributes")
        return res

    def op_remove(self, op, post_fs, mism):
        res = self.client.remove(self.real_fh(op["dir"], mism), op["name"])
        self.check_status(op["status"], res["status"], mism)
        return res

    def op_rmdir(self, op, post_fs, mism):
        res = self.client.rmdir(self.real_fh(op["dir"], mism), op["name"])
        self.check_status(op["status"], res["status"], mism)
        return res

    HANDLERS = {
        "OLookup": op_lookup,
        "OGetattr": op_getattr,
        "OStaleGetattr": op_stalegetattr,
        "OSetattr": op_setattr,
        "OAccess": op_access,
        "OCreate": op_create,
        "OMkdir": op_mkdir,
        "OSymlink": op_symlink,
        "OReadlink": op_readlink,
        "OMknod": op_mknod,
        "OWrite": op_write,
        "ORead": op_read,
        "ORemove": op_remove,
        "ORmdir": op_rmdir,
        "ORename": op_rename,
        "OLink": op_link,
        "OReaddir": op_readdir,
        "OCommit": op_commit,
        "OFsstat": op_fsstat,
        "OFsinfo": op_fsinfo,
        "OPathconf": op_pathconf,
    }

    def replay(self, states):
        for idx, state in enumerate(states[1:], start=1):
            tag = state["lastOp"]["tag"]
            op = state["lastOp"]["value"]
            handler = self.HANDLERS.get(tag)
            if handler is None:
                raise TraceFormatError(f"step {idx}: no handler for {tag}")
            mism = []
            self._cur_tag, self._cur_op, self._cur_fs = tag, op, state["fs"]
            try:
                res = handler(self, op, state["fs"], mism)
            except Divergence as div:
                # Re-anchor pre-RPC failures (e.g. unknown fid) to this step.
                raise Divergence(idx, (tag, op), div.mismatches) from None
            self.history.append((idx, tag, op, res))
            if self.verbose:
                print(f"  [{idx:4d}] {tag} {op} -> {res.get('status')}")
            if mism:
                raise Divergence(idx, (tag, op), mism)

    def attr_skip_rate(self):
        total = self.attr_checks + self.attr_skips
        return self.attr_skips / total if total else 0.0


def diff_bytes(expect, actual, block_size):
    """Locate the first differing block for the divergence report."""
    n = min(len(expect), len(actual))
    for i in range(0, n, block_size):
        if expect[i:i + block_size] != actual[i:i + block_size]:
            return (f"; first differing block {i // block_size}: "
                    f"expected byte {expect[i]:#x}, "
                    f"got byte {actual[i]:#x}")
    return "; lengths differ only"


def report_divergence(trace_path, div, replayer, server):
    print(f"\n=== DIVERGENCE in {trace_path} ===", file=sys.stderr)
    print(f"step {div.step}: {div.op[0]} args/expectation: {div.op[1]}",
          file=sys.stderr)
    for m in div.mismatches:
        print(f"  MISMATCH: {m}", file=sys.stderr)
    print("\nlast operations before failure:", file=sys.stderr)
    for idx, tag, op, res in replayer.history[-10:]:
        print(f"  [{idx:4d}] {tag} {op} -> {res}", file=sys.stderr)
    print(f"\nfid -> file handle map:", file=sys.stderr)
    for fid, fh in sorted(replayer.fh.items()):
        print(f"  {fid}: {fh.hex()}", file=sys.stderr)
    print(f"\ndaemon log tail:\n{server.log_tail()}", file=sys.stderr)


def run_trace(trace_path, args):
    states = load_trace(trace_path)
    if args.dry_run:
        print(f"{trace_path}: {len(states) - 1} steps, format OK")
        return True

    server = ChimeraServer(args.chimera, nfs_port=args.nfs_port,
                           mount_port=args.mount_port)
    try:
        server.start()
        mnt = nfs3_client.Mount3Client("127.0.0.1", port=args.mount_port)
        root_fh = mnt.mnt("/share")
        mnt.close()
        client = nfs3_client.Nfs3Client("127.0.0.1", port=args.nfs_port)
        client.null()

        replayer = Replayer(client, root_fh, args.block_size,
                            verbose=args.verbose)
        try:
            replayer.replay(states)
        except Divergence as div:
            report_divergence(trace_path, div, replayer, server)
            return False

        rate = replayer.attr_skip_rate()
        if rate > args.max_attr_skip_rate:
            print(f"{trace_path}: attribute skip rate {rate:.0%} exceeds "
                  f"{args.max_attr_skip_rate:.0%} "
                  f"({replayer.attr_skips} of "
                  f"{replayer.attr_checks + replayer.attr_skips} replies "
                  f"had attributes_follow=0)", file=sys.stderr)
            return False

        client.close()
        dev_summary = ""
        if replayer.deviations_hit:
            parts = ", ".join(f"{k}×{v}"
                              for k, v in sorted(replayer.deviations_hit.items()))
            dev_summary = f"; known deviations: {parts}"
        print(f"{trace_path}: {len(states) - 1} steps replayed, "
              f"{replayer.attr_checks} attribute checks "
              f"({replayer.attr_skips} skipped){dev_summary}")
        return True
    finally:
        server.stop()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--trace", action="append", required=True,
                    help="ITF trace file (repeatable; fresh daemon per trace)")
    ap.add_argument("--chimera", help="path to the chimera daemon binary")
    ap.add_argument("--block-size", type=int, default=8192)
    ap.add_argument("--nfs-port", type=int, default=2049)
    ap.add_argument("--mount-port", type=int, default=20048)
    ap.add_argument("--max-attr-skip-rate", type=float, default=0.1)
    ap.add_argument("--dry-run", action="store_true",
                    help="parse and validate traces without a server")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if not args.dry_run and not args.chimera:
        ap.error("--chimera is required unless --dry-run")

    failures = 0
    for trace in args.trace:
        if not run_trace(trace, args):
            failures += 1
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
