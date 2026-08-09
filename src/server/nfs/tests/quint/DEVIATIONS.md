<!--
SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
SPDX-License-Identifier: LGPL-2.1-only
-->

# NFS3 model-based testing: findings & known deviations

The Quint model in `nfs3.qnt` encodes the **RFC 1813-correct** reply for every
operation. Where chimera's live behavior differs, the difference is recorded
here rather than baked into the model, so the RFC target stays visible and the
suite keeps working. Two mechanisms back this file:

- **`deviations.py`** — a machine-readable registry the replay harness uses to
  reconcile a divergence at run time. A registered *status-only* deviation is
  reported as a known deviation (xfail) and does not fail the run; an
  unregistered divergence is a hard failure.
- **dedicated tests** — for deviations that *mutate state* differently than the
  RFC (which would desync a stateful replay), the triggering case is excluded
  from random generation and pinned by an explicit test instead.

When chimera is fixed for any item below, delete its `deviations.py` entry (and
adjust the dedicated test): the model already asserts the RFC behavior, so the
suite will simply stay green through the RFC path.

## Bugs found and fixed in this effort

These were surfaced by replaying generated traces and fixed in `memfs.c`; the
model's RFC-correct expectations now hold, so the traces that hit them serve as
regression coverage.

### F1 — LINK of a directory onto its own handle self-deadlocks the daemon
- **Severity:** availability (DoS). A single `LINK` RPC where the object handle
  equals the target-directory handle wedged the serving thread while it held an
  inode lock, cascading to a full daemon hang for all clients.
- **Root cause:** `memfs_link_at` locks the parent directory, then locks the
  link target via `memfs_inode_get_fh`; when both handles name the same inode
  that is a second lock on the same non-recursive mutex, taken before the
  `S_ISDIR` rejection could run.
- **Fix:** detect target-handle == directory-handle up front and return
  `EISDIR` (the intended result) without the second lock (`memfs.c`,
  `memfs_link_at`).

### F2 — RENAME onto a name that resolves to a locked parent self-deadlocks
- **Severity:** availability (DoS). `RENAME(fromDir, X → toDir, Y)` where `Y`
  already resolves to `fromDir` (or `toDir`) — e.g. renaming `D/f` onto
  `root/d` when `root/d` *is* `D` — hung the daemon.
- **Root cause:** `memfs_rename_at` holds both parent-directory locks, then
  locks the existing destination inode via `memfs_inode_get_inum`; when that
  destination aliases an already-held parent it re-locks the same mutex. The
  function already guarded the same-inode-hardlink and ancestor-cycle cases,
  but not this one.
- **Fix:** reuse the already-held parent pointer when the destination entry
  aliases it (such a target is always a non-empty directory, so the rename is
  correctly rejected with `EISDIR`/`ENOTEMPTY` without re-locking).

### F3 — LOOKUP/READDIR on a symlink handle returned `SERVERFAULT` *(was D1/D2)*
- **RFC:** §3.3.3 (LOOKUP), §3.3.16/§3.3.17 (READDIR/READDIRPLUS). A
  non-directory object must yield `NFS3ERR_NOTDIR`; the server returned
  `NFS3ERR_SERVERFAULT` for a **symlink** handle (file/fifo/sock were already
  correct).
- **Root cause:** the memfs lookup/readdir paths report `CHIMERA_VFS_ESYMLINK`;
  `nfs3_status.h` had no case for it, so it hit `default → NFS3ERR_SERVERFAULT`.
- **Fix:** map `CHIMERA_VFS_ESYMLINK → NFS3ERR_NOTDIR` in `nfs3_status.h`
  (`chimera_vfs_error_to_nfsstat3`). This is the shared NFS3 error map, so it
  fixes the deviation for **every** backend, not just memfs. NFSv4 is
  untouched: `nfs4_status.h` keeps its own `ESYMLINK → NFS4ERR_SYMLINK`
  mapping, which v4 LOOKUP relies on.

### F4 — Exclusive CREATE same-verifier retry returned `EXIST` *(was D3)*
- **RFC:** §3.3.8. A retransmitted EXCLUSIVE create presenting the **same
  verifier** must succeed idempotently (return the existing object); the server
  returned `NFS3ERR_EXIST`, defeating the retransmit-safety the verifier exists
  to provide. (A *different* verifier correctly returned `EXIST`.)
- **Root cause:** the create stashes the 8-byte verifier into the atime/mtime
  seconds, but `nfs3_proc_create.c` copied only the low 4 bytes into each
  64-bit `tv_sec` field of an **unzeroed** attr buffer, leaving garbage in the
  high 32 bits. That garbage was stored on the inode and then compared against
  the clean 32-bit verifier on the readback path, so the match failed
  non-deterministically (it happened to work only when that memory was zero).
- **Fix:** assign the two 32-bit verifier halves through `uint32_t` temporaries
  so `tv_sec` is zero-extended, matching the readback comparison
  (`chimera_nfs3_create_open_at_parent_complete`). Proc-layer only; no backend
  change.

### F5 — RMDIR/REMOVE did not enforce the target type *(was D4)*
- **RFC / POSIX:** §3.3.13 RMDIR of a non-directory is `NFS3ERR_NOTDIR`;
  `unlink(2)` of a directory is `EISDIR`. The single VFS remove op could not
  express which was meant, so **both** were wrong: `RMDIR` of a file unlinked
  it (`NFS3_OK`), and `REMOVE`/`unlink` of a directory removed it. The same gap
  broke chimera's POSIX layer, where `unlink`, `rmdir` and `unlinkat`
  (`AT_REMOVEDIR` was discarded) all funnelled into one untyped remove.
- **Root cause:** the VFS `remove_at` op carried no expected-type information,
  so every backend removed whatever the name resolved to (the linux backend
  even tried `unlink` then `rmdir`).
- **Fix:** added `CHIMERA_VFS_REMOVE_ISDIR` / `CHIMERA_VFS_REMOVE_ISNOTDIR`
  flags to `remove_at` (`vfs.h`). Enforcing backends (memfs, cairn, diskfs)
  reject a mismatch (`ENOTDIR`/`EISDIR`); passthrough backends (linux,
  io_uring) use the flag to choose `unlinkat`'s `AT_REMOVEDIR`; with neither
  flag the legacy remove-anything behavior is preserved. Callers now pass the
  intent: NFS3 `RMDIR`→ISDIR / `REMOVE`→ISNOTDIR, the NFS-client backend sends
  `RMDIR` vs `REMOVE` accordingly, and the POSIX layer maps `rmdir`→ISDIR,
  `unlink`→ISNOTDIR, `unlinkat`→`AT_REMOVEDIR ? ISDIR : ISNOTDIR`. The model
  now type-checks both directions symmetrically.

## Known deviations (documented, not reconciled in traces)

_None: every deviation found by this effort has been fixed. New state-mutating
deviations would be listed here (excluded from generation, pinned by a
dedicated test); new status-only ones go in `deviations.py`._

## Annotations (chimera choices within RFC discretion — not deviations)

Recorded as `chimera:` comments in `nfs3.qnt`; the model matches chimera and no
divergence is expected.

- **ACCESS as root** grants every requested bit (including `EXECUTE` on a file
  with no execute bits). RFC 1813 §3.3.4 leaves ACCESS semantics to the server.
- **SYMLINK mode** is fixed at `0755`; the `sattr3` mode in the request is not
  applied.
- **UNCHECKED CREATE over an existing name** returns the existing object of any
  type (including a directory or symlink), attributes untouched — permitted by
  the UNCHECKED contract (no type check mandated).
- **Exclusive-create verifier lifetime:** the verifier is stashed in the file's
  atime/mtime, so it survives reads/GETATTR/ACCESS/COMMIT/LINK and a mode-only
  SETATTR, but a WRITE or a size-changing SETATTR updates mtime and clears it —
  after which a same-verifier CREATE is (correctly) `EXIST`, not an idempotent
  retransmit. The model encodes this (`xverf` cleared on write/truncate).
- **Stale file handles:** immediately after removal, GETATTR on a freed handle
  returns `NFS3ERR_NOENT` (RFC would use `NFS3ERR_STALE`); a syntactically
  bogus handle does return `STALE`. Not asserted in long traces because memfs
  recycles an inode's inum+gen, so a freed handle can later resolve to a new
  object — modeling that needs allocation-aware state (deferred).
