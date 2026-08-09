#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
#
# SPDX-License-Identifier: LGPL-2.1-only

"""Regression guard for the NFS3-layer fixes found via model-based testing,
plus assertions that the remaining documented deviation still reproduces.

For each item in DEVIATIONS.md this checks the *current expected* behavior:

  * F1/F2 (LINK / RENAME self-alias deadlocks) -- must return the correct
    error promptly rather than hanging.
  * F3/F4 (symlink LOOKUP/READDIR; exclusive-create same-verifier retry) --
    were deviations D1-D3, now fixed in the NFS3 layer, so this asserts the
    RFC-correct replies.  If one regresses, the assertion fails here.
  * D4 (rmdir-nondir-unlinks) -- still an open deviation; asserted to still
    reproduce.  When it is fixed, this assertion fails, which is the signal to
    update deviations.py / DEVIATIONS.md (the model already expects NOTDIR).
"""

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from replay import ChimeraServer  # noqa: E402
import nfs3_client as nc  # noqa: E402

NFS3_OK = 0
NFS3ERR_NOENT = 2
NFS3ERR_EXIST = 17
NFS3ERR_NOTDIR = 20
NFS3ERR_ISDIR = 21
NFS3ERR_NOTEMPTY = 66
NFS3ERR_SERVERFAULT = 10006


class ProbeFail(Exception):
    pass


def expect(label, got, want):
    if got != want:
        raise ProbeFail(f"{label}: got status {got}, expected {want}")
    print(f"  ok  {label}: status {got}")


def main():
    chimera = sys.argv[sys.argv.index("--chimera") + 1] \
        if "--chimera" in sys.argv else None
    srv = ChimeraServer(chimera)
    srv.start()
    failures = []
    try:
        root = nc.Mount3Client("127.0.0.1").mnt("/share")
        c = nc.Nfs3Client("127.0.0.1")
        c.rpc.sock.settimeout(8)   # a deadlock regression shows up as a timeout

        c.symlink(root, "sl", "target", mode=0o777)
        sl = c.lookup(root, "sl")["obj_fh"]

        checks = []

        def check(label, fn, want):
            try:
                expect(label, fn(), want)
            except ProbeFail as e:
                print(f"  FAIL {e}")
                failures.append(str(e))
            except Exception as e:  # e.g. socket timeout on a deadlock regression
                msg = f"{label}: {type(e).__name__} ({e})"
                print(f"  FAIL {msg}")
                failures.append(msg)

        print("F3 symlink LOOKUP/READDIR -> NOTDIR (fixed; was D1/D2):")
        check("LOOKUP via symlink handle", lambda: c.lookup(sl, "x")["status"],
              NFS3ERR_NOTDIR)
        check("READDIR via symlink handle", lambda: c.readdir(sl)["status"],
              NFS3ERR_NOTDIR)
        check("READDIRPLUS via symlink handle",
              lambda: c.readdirplus(sl)["status"], NFS3ERR_NOTDIR)

        print("F4 exclusive-create same-verifier retry is idempotent "
              "(fixed; was D3):")
        v = struct.pack(">Q", 0xABCD1234)
        check("EXCLUSIVE create fresh",
              lambda: c.create(root, "ex", nc.EXCLUSIVE, verf=v)["status"], NFS3_OK)
        check("EXCLUSIVE retry SAME verifier -> idempotent OK",
              lambda: c.create(root, "ex", nc.EXCLUSIVE, verf=v)["status"], NFS3_OK)
        check("EXCLUSIVE retry DIFFERENT verifier -> EXIST",
              lambda: c.create(root, "ex", nc.EXCLUSIVE,
                               verf=struct.pack(">Q", 0xBEEF))["status"],
              NFS3ERR_EXIST)

        print("F5 RMDIR/REMOVE type enforcement (fixed; was D4):")
        c.create(root, "reg", mode=0o644)
        check("RMDIR of a regular file -> NOTDIR",
              lambda: c.rmdir(root, "reg")["status"], NFS3ERR_NOTDIR)
        check("  file survives the rejected RMDIR",
              lambda: c.lookup(root, "reg")["status"], NFS3_OK)
        c.mkdir(root, "adir", mode=0o755)
        check("REMOVE of a directory -> ISDIR",
              lambda: c.remove(root, "adir")["status"], NFS3ERR_ISDIR)
        check("  directory survives the rejected REMOVE",
              lambda: c.lookup(root, "adir")["status"], NFS3_OK)

        print("F1 LINK self-alias deadlock (fixed; must not hang):")
        c.mkdir(root, "d1", mode=0o755)
        d1 = c.lookup(root, "d1")["obj_fh"]
        check("LINK directory onto its own handle",
              lambda: c.link(d1, d1, "x")["status"], NFS3ERR_ISDIR)

        print("F2 RENAME parent-alias deadlock (fixed; must not hang):")
        c.mkdir(root, "pd", mode=0o755)
        pd = c.lookup(root, "pd")["obj_fh"]
        c.mknod(pd, "f", nc.NF3FIFO, mode=0o644)
        check("RENAME child onto a name resolving to its parent",
              lambda: c.rename(pd, "f", root, "pd")["status"], NFS3ERR_ISDIR)
    finally:
        srv.stop()

    if failures:
        print(f"\n{len(failures)} deviation assertion(s) no longer hold:")
        for f in failures:
            print(f"  - {f}")
        print("\nIf chimera was fixed, update deviations.py + DEVIATIONS.md; "
              "if a deadlock reappeared, that is a regression.")
        sys.exit(1)
    print("\nAll documented deviations reproduce; both deadlock fixes hold.")


if __name__ == "__main__":
    main()
