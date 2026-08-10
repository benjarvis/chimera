<!--
SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors

SPDX-License-Identifier: LGPL-2.1-only
-->

# Chimera POSIX-client deviations from POSIX.1-2024

> 2026-08-10: the straightforward subset was fixed in the
> `memfs-posix-fixes` commit series (see the Fixed section at the
> bottom); the registry entries for fixed deviations no longer fire and
> the remaining open items are the design-heavy ones (PD1 locks, PD3
> dirfd plumbing, PD6 linkat follow, PD11 per-op re-authorization,
> PD12 truncate/unlink open-cache aliasing, PD13/PD14 type-aware open
> gates, PD15's mutation paths, PD16/PD17 acceptance choices, PD20
> O_CREAT permission skip).

Found by the POSIX model-based test suite (this directory) against the
`chimera_posix_*` client API backed by memfs.  The model always encodes the
standard's behavior; each divergence is registered in `posix_deviations.py`
(status-only, reconciled during replay) or documented here (state-mutating,
surfaces as a hard trace failure until fixed).  Policy follows the NFS3
suite: fix-in-chimera is preferred; the model is never bent to match a bug.

Implementation-defined choices that are *not* deviations (POSIX allows
them) are pinned in the probed profile (`posix_replay.py PROFILE`,
`posix_run.qnt posixMemfs`): gid from creator's egid, no S_ISGID
inheritance, unprivileged writes clear setuid/setgid, pwrite ignores
O_APPEND, rename marks ctime, atime not marked on read (relatime-like),
no sticky write-permission arm, ENOTEMPTY, sticky errors EACCES,
unlink(dir) EISDIR.

## Open deviations

### PD1: record locks advertised but unimplemented on memfs (status-only)

memfs sets `CHIMERA_VFS_CAP_FS_LOCK` in `vfs_memfs.capabilities`, but
`memfs_dispatch` has no `CHIMERA_VFS_OP_LOCK` case: every
`fcntl(F_SETLK/F_SETLKW/F_GETLK)` and `lockf()` fails EOPNOTSUPP after
logging `memfs_dispatch: unknown operation 27`.  POSIX makes record locks
mandatory.  Fix: implement byte-range locks in memfs, or drop the
capability bit so the VFS layer serves a deliberate ENOTSUP.

### PD2/PD2b: fcntl F_DUPFD / F_GETFL / F_SETFL unimplemented (status-only)

`chimera_posix_fcntl` (src/posix/posix_fcntl.c) implements only the three
lock commands; everything else — including the mandatory F_DUPFD, F_GETFL,
F_SETFL — returns EINVAL.

### PD3: fstatat/faccessat reject real directory descriptors (status-only)

`posix_fstatat.c` and `posix_faccessat.c` hard-fail ENOSYS for any dirfd
other than AT_FDCWD ("For now, only support AT_FDCWD"), while openat,
mkdirat and unlinkat already resolve through the descriptor's open handle.
fstatat additionally ignores AT_SYMLINK_NOFOLLOW and faccessat ignores
AT_EACCESS (the latter is unobservable in the model universe, where
real ids always equal effective ids).

### PD4: O_APPEND ignored by write() (state-mutating)

The append flag is captured into `fd_entry.oflags` at open and never
consulted again: `chimera_posix_write` writes at the current stored offset
instead of seeking to EOF atomically with the write.  POSIX write():
"If the O_APPEND flag of the file status flags is set, the file offset
shall be set to the end of the file prior to each write."

### PD5: dup()/dup2() do not share the open file description (state-mutating)

POSIX requires dup/dup2/F_DUPFD to return a descriptor that *shares* the
open file description — one file offset, one set of status flags.  Chimera
keeps the offset per `fd_entry`: `dup()` hands out a fresh entry with
offset 0, and `dup2()` resets the target's offset to 0
(`posix_dup2.c: new_entry->offset = 0`).  A classic NAS-client compliance
trap (it also breaks the `lseek(dup(fd)) affects fd` idiom).

### PD6: linkat() ignores AT_SYMLINK_FOLLOW (state-mutating)

`posix_linkat.c` discards `flags` and only supports AT_FDCWD, so
`linkat(..., AT_SYMLINK_FOLLOW)` hard-links the symlink itself instead of
its target.

### PD7: read()/write() do not enforce the descriptor access mode
(state-mutating)

A descriptor opened O_RDONLY accepts `write()` (data lands in the file)
and one opened O_WRONLY accepts `read()`.  POSIX requires EBADF for both.
The open flags are stored (`fd_entry.oflags`) but the I/O paths never
check O_ACCMODE, and the VFS/memfs layers happily serve I/O through any
open handle.  (`ftruncate` on O_RDONLY does fail — with EINVAL — because
the model expects EINVAL there, this one matches.)

Observed immediately by the first smoke trace: `open(O_RDONLY|O_APPEND)`
followed by `write()` returned success and wrote 8 KiB; the model expected
EBADF.

### PD8: read() on a directory descriptor returns fabricated bytes

`read()` on a directory fd returns zero-filled bytes (4096 returned for a
4096 request) instead of failing.  POSIX leaves read-on-directory
implementation-defined but the honest choices are EISDIR (Linux) or real
data; serving zeroes misleads.  The model canonicalizes EISDIR.

### PD9: chimera_posix_shutdown hangs when descriptors are still open

With any fd left open, `chimera_posix_shutdown` → `chimera_vfs_destroy`
blocks forever in the close-thread handshake
(`pthread_cond_wait(&vfs->close_thread.cond, ...)`, src/vfs/vfs.c:849) —
the close thread never signals completion while unreleased open handles
remain.  A robust client should either close remaining descriptors or
bound the wait.  The replay harness works around it by closing every
mapped descriptor before shutdown.

### PD10: open()/dup() do not allocate the lowest available descriptor

POSIX open(): "The file descriptor returned ... shall be the lowest file
descriptor not currently open for that process."  Chimera allocates from a
LIFO free list seeded from the top of the table — the first three opens
return 1023, 1022, 1021.  Also makes F_DUPFD's "lowest ≥ arg" contract
unimplementable as-is.  (The replay harness never checks descriptor
numbers, so this does not fail traces; noted from observation.)

### PD12: mknod + truncate-by-path + open + unlink loses the open file
(state-mutating, data loss)

Minimal reproduction (as uid 0):

    mknod("/test/b", 0700)          — creates the file (no open involved)
    truncate("/test/b", 0)          — path setattr; internally does a real
                                      chimera_vfs_open(INFERRED) + release
    fd = open("/test/b", O_RDWR)    — user open
    unlink("/test/b")               — succeeds
    pread(fd, ...)                  — fails ENOENT; fstat(fd) also gone

Dropping the truncate, or creating the file via open(O_CREAT) instead of
mknod, or running as uid 100, makes the sequence behave (I/O keeps working
on the orphan, POSIX-correctly).  The path-truncate's internal open
(client_setattr.h: chimera_vfs_open + setattr + chimera_vfs_release)
appears to leave the VFS open-cache entry for the file in a state where
the later unlink reclaims the inode despite the user's still-open handle.
POSIX unlink: "the link count ... reduced; when it becomes 0 and no
process has the file open, the file's contents shall be freed" — with the
file open, I/O must keep working until last close.

### PD13: FIFO opens succeed with no FIFO semantics (status-only)

`open(fifo, O_WRONLY)` returns a usable descriptor immediately; POSIX
requires blocking until a reader appears (or ENXIO with O_NONBLOCK).
memfs treats the FIFO inode as a plain file.  The model canonicalizes
ENXIO as the honest NAS-backend answer.

### PD14: directories open for writing (status-only)

`open(dir, O_RDWR)` and `open(dir, O_WRONLY)` succeed; POSIX requires
EISDIR.  Combined with PD7/PD8 this yields writable directory
descriptors that accept reads of fabricated bytes.

### PD15: trailing slashes on non-directories ignored (status-only)

`stat("f/")` on a regular file succeeds and `mkdir("f/")` over an
existing non-directory reports EEXIST — XBD 4.16 requires ENOTDIR for
both.  A trailing slash also fails to force following a final symlink:
`lstat("lnk/")` returns the link itself where XBD 4.16 requires the
slash to resolve the link (ELOOP for a self-loop).  Genuine ELOOP
detection when actually following is correct.  (Dot-dot handling at the
mount root, by contrast, matches the model: chimera clamps `/test/..`
to the mount root like a chroot.)

### PD20: open(O_CREAT) on an existing file skips the permission check

`open(path, O_CREAT|O_WRONLY)` on an existing file the caller cannot
write succeeds; the identical open without O_CREAT correctly fails
EACCES.  POSIX applies the access-mode check to the existing file
regardless of O_CREAT.  Security-relevant in combination with PD7/PD11
oddities: the descriptor is handed out, and writes through it are then
policed only by the per-op re-check.

### PD21: truncate()/ftruncate() do not clear setuid/setgid

An unprivileged owner's `write()`/`pwrite()` clears S_ISUID (probed,
pinned as `writeClearsSets` in the profile), but `truncate()` and
`ftruncate()` by the same unprivileged owner leave 04755 intact.  The
clearing policy must be uniform across the mutation paths ("write or
truncate" share the clause in the standard); the inconsistency makes
the profile knob unsatisfiable and shows up as stat mode mismatches.

### PD22: SEEK_DATA/SEEK_HOLE out-of-range errno is EINVAL, not ENXIO

`lseek(fd, off, SEEK_DATA)` with off at/past EOF (or negative) returns
EINVAL from the client's pre-dispatch validation; POSIX (and Linux)
specify ENXIO.  memfs itself returns ENXIO correctly for the in-range
cases (probed).

### PD23: dup()/dup2() lose the open flags as well as the offset

Extension of PD5: the duplicated fd_entry's `oflags` is zeroed, so a
dup of an O_RDWR descriptor reads as O_RDONLY to the paths that do
consult flags — `ftruncate(dup(fd))` fails EINVAL on a perfectly
writable description.

### PD17: error-priority differences on doubly-invalid calls (status-only)

Where two failure conditions hold at once, chimera reports the
permission error and the model reports the structural one (POSIX leaves
priority unspecified; listed for visibility, reconciled during replay):

  - `unlink(directory)` in an unwritable parent → EACCES (model EISDIR;
    note POSIX *requires* EPERM/EISDIR for directory victims);
  - `mkdir(existing)` in an unwritable parent → EACCES (model EEXIST);
  - `link(directory-source, target-in-unwritable-parent)` → EACCES
    (model EPERM, which POSIX requires for directory sources).

### PD18: access()/faccessat() check the wrong identity entirely

The faccessat callback evaluates r/w/x against `getuid()`/`getgid()` of
the *host process* — not the chimera credential installed with
`chimera_posix_set_cred` — ignores supplementary groups, and ignores
AT_EACCESS.  Any process running the client as root gets "allowed" for
everything (execute still needs one x bit).  Root cause:
src/posix/posix_faccessat.c computes mode bits client-side from a stat
result using host ids.

### PD19: clone_file_range accepts source ranges beyond EOF (status-only)

`clone_file_range(dst, 0, src, off-past-EOF, len)` returns success;
the Linux contract (and the model) require EINVAL when the source range
does not lie within the source file.

### PD16: memfs creates symlinks with mode 0755

The model (following Linux and the pjd expectations) creates symlinks
with mode 0777; memfs reports 0755.  Harmless (symlink modes are never
consulted) but visible in every lstat; the harness skips the mode check
for symlinks, citing this entry.

### PD11: file permissions re-checked on every I/O; chmod revokes open
descriptors (state-mutating)

POSIX ties I/O rights to the open file description: "read() ... shall
fail [EBADF] if the file descriptor is not valid" and access permission
is checked *at open*; a later chmod() "shall not affect" I/O through
descriptors that are already open.  Chimera re-runs the file-mode access
check with the request credential on every read/write:

  - `open(O_CREAT|O_RDWR, 0222)` succeeds, `write()` succeeds, but
    `pread()` through that same descriptor fails EACCES (owner class has
    no read bit);
  - `open(O_CREAT|O_WRONLY, 0444)` succeeds but every write fails EACCES;
  - after `chmod(path, 0)`, both directions fail EACCES through a
    descriptor opened while the mode was 0644.

Server-style per-request authorization (correct for NFS) leaking through
the POSIX client, which never re-authorizes against the open-time rights.

## Fixed

Fixed 2026-08-10 by the `memfs-posix-fixes` series (branch pushed to
benjarvis/chimera):

- **PD2/PD10** — fcntl F_DUPFD/F_GETFL/F_SETFL implemented; the fd
  allocator hands out the lowest free descriptor (open/dup/F_DUPFD).
- **PD4** — write()/writev() honor O_APPEND (EOF resolved through the
  open handle before each append write).
- **PD5 (partial)/PD23** — dup/dup2 propagate the file offset and
  status flags to the duplicate; full description sharing (one offset
  object) remains open.
- **PD7** — read/write/pread/pwrite/readv/writev/read_into and
  copy/clone_file_range enforce the descriptor access mode (EBADF),
  including the O_APPEND-destination rule for copy_file_range.
- **PD8** — memfs fails read() of a directory with EISDIR (the model's
  opPread gained the same canonicalization opRead already had).
- **PD9** — chimera_posix_shutdown closes leaked descriptors instead of
  hanging in the VFS close-thread handshake.
- **PD15 (partial)** — stat()/lstat() enforce the trailing-slash
  directory requirement, and lstat routes trailing-slash paths through
  the following stat (ELOOP on self-loops).  Mutation paths still
  accept trailing slashes.
- **PD18** — faccessat evaluates the XBD 4.5 algorithm against the
  chimera request credential (supplementary groups included), not the
  host process uid/gid.
- **PD19** — memfs clone_range rejects source ranges beyond EOF.
- **PD21** — memfs truncation applies the kill-priv setuid/setgid
  clearing like the write path.
- **PD22** — negative SEEK_DATA/SEEK_HOLE offsets report ENXIO.
