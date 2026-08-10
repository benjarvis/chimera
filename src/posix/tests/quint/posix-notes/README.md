<!--
SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors

SPDX-License-Identifier: LGPL-2.1-only
-->

# POSIX.1-2024 rule inventories

Supporting research for the POSIX file-API Quint model (see
`../DESIGN-POSIX.md`).  Each file is a numbered rule inventory extracted
from and verified against fetched POSIX.1-2024 (Issue 8) text at
pubs.opengroup.org/onlinepubs/9799919799/, with requirement levels
(MUST / unspecified / implementation-defined / acceptance-set), exact
errno names, verbatim citations, per-rule modeling advice, and flagged
Linux divergences.  Rules the standard leaves open became the `Caps`
policy knobs and FeatureMode constants in the model.

| File | Scope |
|------|-------|
| `posix-open-resolution.md` | Pathname resolution (XBD 4.16), symlinks, ELOOP, trailing slash, open/openat flag semantics and errno matrix, close, timestamp marks |
| `posix-io.md` | read/write/pread/pwrite/lseek (incl. Issue 8 SEEK_HOLE/SEEK_DATA), truncate/ftruncate, fsync, holes and zero-fill, O_APPEND, atomicity notes |
| `posix-namespace.md` | mkdir/mknod/rmdir/unlink/rename/link/symlink/readlink and *at variants, the full rename matrix, sticky-bit rules, acceptance sets |
| `posix-metadata.md` | stat family, chmod/chown families, utimensat tiers, access, umask, the op-by-op file-times-update table |
| `posix-fd-locks.md` | Descriptor vs open file description, dup/dup2 sharing, fcntl record locks, F_GETLK, the close-drops-locks rule, lockf |
| `posix-dirs.md` | opendir/readdir/rewinddir/seekdir/telldir/closedir/scandir, the unspecified-window rule, deterministic sweep testing strategy |
| `posix-perms.md` | The file access permission algorithm (exclusive class selection), appropriate privileges, sticky bit, setid clearing, EACCES vs EPERM |
