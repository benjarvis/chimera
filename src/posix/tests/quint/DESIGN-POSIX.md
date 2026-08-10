<!--
SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors

SPDX-License-Identifier: LGPL-2.1-only
-->

# POSIX file-API model-based testing design

A Quint specification of the POSIX.1-2024 (Issue 8) file API, built to
generate compliance tests for chimera's POSIX client
(`src/posix/posix.h`, the `chimera_posix_*` surface).  The model is
spec-first: behavior comes from the standard's text (verified rule
inventories in `posix-notes/`), not from chimera's implementation —
the point is to confirm compliance, not to codify current behavior.
It is the sibling of the NFS3/NFS4 suites under
`src/server/nfs/tests/quint/` and reuses their architecture: an
RFC/spec-first model whose transition labels carry request + expected
result, replayed against the live implementation by a harness that
compares.

## Modules

| File | Contents |
|------|----------|
| `posix_fs.qnt` | Generic filesystem under the API: inodes (uid/gid, 12 mode bits, nlink, three timestamps), sparse block maps, dirent maps with parent pointers, symlink targets as structured paths, orphan pinning and reaping, structural invariants |
| `posix_state.qnt` | Process-visible kernel state: descriptor tables → shared open file descriptions (offset, access mode, O_APPEND), per-(process, file) record locks as per-byte maps, directory streams, per-process creds and umask |
| `posix_ops.qnt` | Errno constants, `FeatureMode`/`Caps` gating, pathname resolution (XBD 4.16: symlink expansion, ELOOP, trailing slash, dot/dot-dot, per-component search checks), the file-access-permission algorithm, ~40 syscall handlers, `dispatch` |
| `posix.qnt` | Universes, `Label`/`lastOp` trace contract, nondet capability draw at `init`, generator actions, step flavors, invariants (`inv`) |
| `posix_run.qnt` | Instances: `posixDefault`, `posixStrict`, `posixLinuxish` |
| `posixTest.qnt` | Self-tests: `posixTestStd` (25 runs) and `posixTestRoot` (2 runs), all-pinned profiles |
| `posix-notes/` | Verified POSIX.1-2024 rule inventories (~430 rules) |

Verify with:

    quint test posixTest.qnt --main=posixTestStd
    quint test posixTest.qnt --main=posixTestRoot
    quint run posix_run.qnt --main=posixDefault --invariant=inv

## Relationship to the NFSv4 filesystem model

`posix_fs.qnt` is a deliberate fork of `nfs4_fs.qnt` with congruent
shapes (integer inodes, block-symbol content, dirent maps, parent
pointers, orphan pinning) so a future common-module extraction is
mechanical.  They differ where the protocols differ: POSIX adds
uid/gid/mode enforcement inputs, atime/mtime/ctime as abstract
instants, and structured symlink targets (the POSIX layer resolves
paths; NFS4 servers receive one component at a time); NFS4 keeps
xattrs, the change attribute, ALLOCATE's allocated-zero block state and
the exclusive-create verifier.  Neither claims to exhaust the real
chimera VFS, which is a richer NFS/SMB hybrid (NFSv4 ACLs, share
modes); each models exactly what its protocol can observe, which is
why the fs layer contains mechanism only and every policy decision
(permissions, sticky bit, setid clearing) lives in the protocol layer.

## Step and trace contract

One model step is one syscall by one process.  `lastOp` is:

- `LInit({caps})` — the drawn capability/policy profile.  The harness
  probes the live implementation once (copy_file_range support, clone
  support, SEEK_HOLE, availability of a root credential, and the
  behavior knobs below), then reconciles: a trace whose profile does
  not match reality is *skipped* when the operator mode was
  `FeatIfAdvertised` and *fails the suite* when it was
  `FeatMandatory` — so a backend that silently stops supporting a
  required feature turns the suite red instead of vacuously green.
- `LCall({pid, req, res})` — the request, the process issuing it, and
  the model's expected result.  Every result variant carries the errno
  in `e`; payloads are meaningful only on success.

Harness conventions:

- **Processes.** Model pids map to distinct OS processes (or distinct
  client instances with distinct creds via `chimera_posix_set_cred`);
  record-lock ownership and the close-drops-locks rule are per-pid.
- **Identity.** Model `Ino` values are abstract.  The harness learns
  the `st_ino`/`st_dev` of each created object from stat results and
  maintains the bijection; `SStatR.ino` equality is how hard-link
  identity (`link`, `rename` no-op) is checked.
- **Data.** Block symbol *s* at block index *i* expands to a full
  block of identical bytes; symbol 0 is all-zeroes (holes read as 0).
- **Timestamps.** Positive abstract instants are never predicted:
  if the model instant is unchanged between two observations the wire
  value must be unchanged; if it advanced the wire value must be `>=`
  its previous value (coarse clocks make `>` uncheckable).  Negative
  instants come from `utimensat` explicit values; the harness maps
  each reserved value to a fixed wall-clock time and checks exact
  equality.  `P_STRICT_ATIME=FeatOff` relaxes only the atime checks
  (relatime-like backends).
- **Paths.** `dfd == -1` means the plain absolute-path call; a real
  fd means the `*at` variant anchored at that descriptor.
- **readdir.** `RReaddir` is one atomic full sweep: the harness loops
  `readdir()` to EOF with no interleaved mutations and compares the
  *set* of names ("." and ".." stripped).  This sidesteps POSIX's
  unspecified window for concurrently modified streams; `rewinddir`
  re-primes the harness cursor.
- **F_GETLK.** POSIX lets the implementation report *any* blocking
  lock.  The model reports the lowest-pid conflicting owner; the
  harness checks only that the reported owner/range conflicts per the
  model, not the exact pick.
- **Blocking calls.** Generators emit `F_SETLKW`/`lockf(F_LOCK)` only
  when the model shows no conflict, so replay never blocks.

## Feature and policy gating

`FeatOff` pins false/unsupported, `FeatMandatory` pins
true/supported, `FeatIfAdvertised` (default) explores both and the
harness reconciles per trace.

| Const | Meaning (when true) |
|-------|---------------------|
| `F_COPY_RANGE` | copy_file_range supported (else EOPNOTSUPP) |
| `F_CLONE_RANGE` | clone_file_range supported (else EOPNOTSUPP) |
| `F_SEEK_HOLE` | lseek SEEK_HOLE/SEEK_DATA supported (else EINVAL) |
| `F_ROOT` | process 0 runs with euid 0 |
| `P_GID_FROM_PARENT` | new objects take the parent dir's gid (else egid) — POSIX allows either |
| `P_SGID_INHERIT` | new subdirs inherit S_ISGID (implementation-defined) |
| `P_WRITE_CLEARS_SETIDS` | write/truncate by unprivileged callers clears setuid/setgid ("may" in the spec) |
| `P_PWRITE_APPENDS` | pwrite honors O_APPEND (Linux divergence; POSIX says the offset wins) |
| `P_RENAME_CTIME` | rename marks the moved object's ctime (Issue 8 blesses both) |
| `P_STRICT_ATIME` | harness enforces atime marking exactly |
| `P_STICKY_WRITE_ARM` | sticky check exempts write-permitted callers (Issue 8 optional arm) |
| `P_ERR_NOTEMPTY` | non-empty dir errors are ENOTEMPTY (else EEXIST) |
| `P_ERR_STICKY_ACCES` | sticky violations are EACCES (else EPERM) |
| `P_ERR_UNLINKDIR_ISDIR` | unlink(directory) is EISDIR (else EPERM) |
| `P_ERR_LOCK_AGAIN` | lock conflicts are EAGAIN (else EACCES) |

Binary errno acceptance sets are pinned in `Caps` (not in a
harness-side acceptance registry) so every trace stays exact and
deterministic to replay.  Chimera-behavior deviations discovered
during replay follow the NFS3 suite's policy: status-only deviations
go to the deviations registry with a citation; state-mutating
divergences get excluded from generation plus a dedicated regression
test.

## Modeled surface

open/openat (O_RDONLY/O_WRONLY/O_RDWR, O_CREAT, O_EXCL, O_TRUNC,
O_APPEND, O_DIRECTORY, O_NOFOLLOW), close, dup, dup2, fcntl (F_DUPFD,
F_GETFL, F_SETFL/O_APPEND, F_SETLK, F_SETLKW, F_GETLK), lockf, lseek
(SET/CUR/END/DATA/HOLE), read/pread, write/pwrite (readv/writev
collapse to these), truncate/ftruncate, fsync/fdatasync, stat/lstat/
fstat/fstatat, chmod/fchmod/fchmodat, chown/lchown/fchown/fchownat,
utimensat/futimens, access/faccessat (AT_EACCESS), umask, mkdir(at),
mknod (regular/FIFO), symlink(at), link(at ± AT_SYMLINK_FOLLOW),
unlink(at), rmdir, rename(at), readlink(at), opendir/readdir/
rewinddir/closedir, copy_file_range, clone_file_range.

Out of scope, deliberately:

- the stdio `FILE*` layer (`chimera_posix_fopen`...) — client-side
  buffering over the fd layer, not filesystem semantics; unit tests
  cover it.  Phase 2 could add the fopen mode-string → oflag map.
- NFSv4 ACLs (`setacl`/`getacl`) — chimera extension, not POSIX; the
  model's permission checks use mode bits only.
- mount/umount/statfs/statvfs/pathconf — environment setup and
  implementation-defined values.
- telldir/seekdir cookies, dirfd/fdopendir plumbing.
- EXDEV/EROFS (single writable mount), ENAMETOOLONG/EMFILE/ENOSPC
  (resource limits), EINTR/partial I/O, O_SEARCH/O_EXEC, OFD locks,
  fork inheritance, mmap, mknod device nodes (created as typed nodes
  only, never opened).

## Generator discipline

- Paths are built from the model tree (parent-pointer walks), so deep
  valid paths appear organically; `genStatRaw` synthesizes arbitrary
  1–2 component paths (dot and dot-dot included) for negative
  resolution coverage.
- Symlink webs stay shallow: targets name existing entries (one hop)
  or the link itself (guaranteed ELOOP).  The model's expansion
  budget is SYMLOOP_MAX = 8; keeping acyclic chains far below it
  means a model ELOOP is always a genuine cycle, which any real
  implementation also rejects — deeper-but-acyclic chains would risk
  model-ELOOP vs server-success mismatches.
- FIFOs/specials are created but never opened (opening would block or
  need device support).
- Two processes with disjoint uids plus one shared supplementary
  group exercise all three permission classes both ways.
- `MAX_OBJECTS` bounds the tree so traces stay small.

## What the self-tests caught (model bugs fixed here)

- Creating entries through a dirfd whose directory had been rmdir'd
  (orphaned-but-open) corrupted the orphan invariant; POSIX requires
  ENOENT for resolution relative to a removed directory — `atStart`
  now enforces it.  Found by the mixed random walk.
- The "sticky" test mode was written as 1535 (= S_ISGID|0777);
  S_ISVTX|0777 is 1023.  The sticky tests initially passed for the
  wrong reason.
- A sum-type constructor named `LfTest` collided with `quint test`'s
  default /Test/ run matcher (same trap as the NFS4 suite's
  `lockTest` action) — renamed `LfTst`.

## Verification status (2026-08-09)

All six modules typecheck.  `posixTestStd` 25/25 and `posixTestRoot`
2/2 runs pass (including 4 random walks under `inv`; the mixed walk
soaked at 800 samples).  All three `posix_run.qnt` instances simulate
clean under `inv`.  A 12-trace `posixDefault` batch drew 12 distinct
capability profiles and covered 12 errnos; EAGAIN/ENOTEMPTY/EBUSY
appear in the deterministic runs but are rare in uniform walks —
flavor tuning for the trace corpus is phase-2 coverage work.

## Replay harness (added 2026-08-10)

- `posix_driver.c` — a thin executor over the `chimera_posix_*` API
  with an in-process memfs mount at `/test` (block_size pinned to the
  harness block size, 4096).  Line-delimited JSON on stdin/stdout; the
  JSON stream rides a private dup of stdout while fd 1 is pointed at
  stderr, because chimera's logger writes to stdout by default.  Model
  pids are realized as per-operation `chimera_posix_set_cred`/umask
  switches (both thread-local).
- `posix_replay.py` — ITF decode (instance-namespaced vars), the
  model→real maps ((pid,fd)→fd, sid→stream, Ino→(st_dev,st_ino)),
  timestamp consistency tracking, data expansion, and the LInit
  profile gate: a trace whose caps disagree with the pinned `PROFILE`
  exits 77 (ctest SKIP).  `--probe` measures the live profile;
  `--check-profile` diffs it against the pin.
- `posix_deviations.py` / `DEVIATIONS-POSIX.md` — the registry of
  chimera deviations found (status-only entries reconcile during
  replay; state-mutating ones are documented and fail traces).
- `posix_run.qnt posixMemfs` — the generation instance pinned to the
  probed memfs profile so no trace skips on reconcile; `F_ROOT` stays
  explorable because the harness chooses credentials.
- CMake: batched trace generation (fixed seeds), one ctest per trace,
  model self-tests bounded to `--max-samples=100`.

Harness conveniences that deliberately trade coverage for determinism:
`RReaddir` sweeps rewind first (the model's atomic-full-sweep
contract), model dot-dot at ROOT maps onto chimera's clamped dot-dot at
the mount root, `F_DUPFD` is emulated with `dup()` when chimera's
EINVAL deviation (PD2) fires, and every mapped descriptor is closed
before shutdown to dodge the shutdown-with-open-fds hang (PD9).

## Phase 2

Still deferred: telldir/seekdir, dirfd/fdopendir, fchmodat
AT_SYMLINK_NOFOLLOW, multi-mount EXDEV/EROFS, OFD locks, stdio
mode-string mapping, walk-flavor tuning for lock conflict density, a
coverage.py-style behavior-bucket gate over the trace corpus, and a
cross-check of the model against pjdfstest's expectations (chimera
already carries pjd-style tests).
