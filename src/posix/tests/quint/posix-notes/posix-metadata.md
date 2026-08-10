<!--
SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors

SPDX-License-Identifier: LGPL-2.1-only
-->

# POSIX metadata rules — stat/chmod/chown/utimensat/access/umask + file-times model

Source: POSIX.1-2024 (IEEE Std 1003.1-2024, Issue 8),
https://pubs.opengroup.org/onlinepubs/9799919799/ — verified against the live
Issue 8 HTML (XBD `basedefs/V1_chap04.html` sections 4.5, 4.7, 4.12;
`basedefs/sys_stat.h.html`; and the `functions/*.html` pages for stat, chmod,
chown, futimens (utimensat), access, umask, open, mkdir, mknod, symlink, link,
unlink, rename, truncate, ftruncate, read, readv, write, readdir, readlink).
All quotes below were checked verbatim against the fetched page text on
2026-08-09. No Issue 7 fallback was needed. Rules that could not be verified
against fetched text are marked UNVERIFIED.

Notation:

- Requirement levels: **MUST** (shall), **MUST-NOT**, **may** (optional),
  **impl-defined**, **unspecified**, **acceptance-set{a|b}** (spec allows
  either; a conforming test must accept both).
- A / M / C = last data access / last data modification / last file status
  change timestamps (st_atim / st_mtim / st_ctim).
- "mark" = "mark for update" in the XBD 4.12 sense (see R1–R5).
- Citations are `page — "short quoted phrase"`.

---

## 1. The file-times model (XBD 4.12 "File Times Update")

**R1. Three timestamps per file.** Every file has exactly three associated
timestamps: A, M, C. MUST.
Cite: XBD 4.12 — "Each file has three distinct associated timestamps: the time
of last data access, the time of last data modification, and the time the file
status last changed."
Model: state per file: `atime`, `mtime`, `ctime` plus three boolean "marked"
flags (the tri-state: clean / marked / updated-now).

**R2. Tri-state marking model.** Functions do not necessarily update timestamps
immediately; each op *marks* the relevant timestamps for update, and the
implementation realizes marks immediately or later. MUST (that the mark
semantics are followed); the *timing* of realization is impl choice within R3.
Cite: XBD 4.12 — "An implementation may update timestamps that are marked for
update immediately, or it may update such timestamps periodically. At the point
in time when an update occurs, any marked timestamps shall be set to the
current time and the update marks shall be cleared."
Model: nondeterministic `flush` action that sets each marked timestamp to
`now` and clears marks; ops only set mark bits.

**R3. Forced realization points.** All pending marks MUST be realized (a) when
the file ceases to be open by any process, and (b) before any successful
stat-family or time-setting call on the file.
Cite: XBD 4.12 — "All timestamps that are marked for update shall be updated
when the file ceases to be open by any process or before a fstat(), fstatat(),
fsync(), futimens(), lstat(), stat(), utimensat(), or utimes() is successfully
performed on the file. Other times at which updates are done are unspecified."
Reinforced on the stat page: stat — "The stat() function shall update any
time-related fields (as described in XBD 4.12 File Times Update), before
writing into the stat structure."
Model: every stat/fstat/fstatat/lstat/fsync/utimensat/futimens transition must
begin with a forced flush of that file's marks; last-close also flushes.
Linux-divergence: `noatime`/`relatime` mount options deliberately suppress or
defer atime updates past a stat; strict-POSIX mode of the model should not
assume Linux default behavior for atime freshness (Linux default `relatime`
updates atime only if atime <= mtime/ctime or older than 24h).

**R4. Marks/updates suppressed on read-only file systems.** MUST-NOT mark or
update on a read-only file system.
Cite: XBD 4.12 — "Marks for update, and updates themselves, shall not be done
for files on read-only file systems".
Model: if modeling EROFS at all, gate all marking on `!readonly`.

**R5. Value clamping and resolution.** Timestamp resolution is impl-defined but
no coarser than 1 second; any value stored is clamped to the greatest
filesystem-supported value not greater than the requested value. MUST.
Cite: XBD 4.12 — "The resolution of timestamps of files in a file system is
implementation-defined, but shall be no coarser than one-second resolution.
... the implementation shall immediately set the timestamp to the greatest
value supported by the file system that is not greater than V."
Model: use an abstract monotonically-increasing logical clock; do not model
sub-second truncation unless testing a specific FS.

**R6. Ops that touch data/status must document their marks.** Every standard
function that reads/writes data "(even if the data does not change)" or
changes file status "(even if the file status does not change)" specifies
which timestamps it marks; marking at other times must be documented, except
pathname-resolution effects. Cite: XBD 4.12 — "Each function or utility in
POSIX.1-2024 that reads or writes data (even if the data does not change) or
performs an operation to change file status (even if the file status does not
change) indicates which of the appropriate timestamps shall be marked for
update. ... any changes caused by pathname resolution need not be documented."
Model: the op table in section 2 is the closed set of marking rules; pathname
resolution (e.g., search of directories, following symlinks) may freely mark
atimes — the model should ignore directory atime noise from resolution.

---

## 2. Op-by-op timestamp marking table (backbone)

All rows verified verbatim against the named Issue 8 function page. "parent" =
directory that contains the (new/removed) entry. "need-not" = spec says the
mark is optional in that case (acceptance-set{marked|not-marked}).

| Op | File A | File M | File C | Parent M | Parent C | Condition / notes |
|---|---|---|---|---|---|---|
| read/pread, nbyte>0 | mark | – | – | – | – | only when nbyte>0 (R7) |
| readv | mark | – | – | – | – | own page, unconditional wording (R7) |
| write/pwrite/writev, nbyte>0 | – | mark | mark | – | – | may clear setid bits (R8) |
| open O_CREAT (file created) | mark | mark | mark | mark | mark | new file: A,M,C; parent: M,C (R9) |
| open O_TRUNC (file existed) | – | mark | mark | – | – | unconditional on success (R10) |
| mkdir (new dir) | mark | mark | mark | mark | mark | (R11) |
| mknod / mkfifo (new file) | mark | mark | mark | mark | mark | (R12) |
| symlink (the new symlink) | mark | mark | mark | mark | mark | times of the *symlink itself* (R13) |
| link | – | – | mark (source file) | mark (new-entry dir) | mark (new-entry dir) | (R14) |
| unlink | – | – | mark iff nlink>0 remains | mark | mark | (R15) |
| rename | – | – | impl-varies (see R16) | mark (BOTH parents) | mark (BOTH parents) | (R16) |
| truncate | – | mark | mark | – | – | unconditional; may clear setid (R17) |
| ftruncate (regular file) | – | mark | mark | – | – | unconditional; may clear setid (R17) |
| chmod/fchmodat | – | – | mark | – | – | (R31) |
| chown/fchownat/lchown | – | – | mark (need-not if both -1) | – | – | (R38) |
| utimensat/futimens | set per times[0] | set per times[1] | mark (need-not if both OMIT) | – | – | (R45) |
| readdir | mark (of the dir) | – | – | – | – | "each time the directory is actually read" (R18) |
| readlink/readlinkat | mark (of the symlink) | – | – | – | – | (R19) |
| stat/fstat/lstat/fstatat | – | – | – | – | – | marks nothing; forces flush first (R3) |
| access/faccessat | – | – | – | – | – | no marking specified (R6 "other functions": unspecified) |

**R7. read family marks A only when nbyte > 0.** MUST.
Cite: read — "Upon successful completion, where nbyte is greater than 0,
read() shall mark for update the last data access timestamp of the file, and
shall return the number of bytes read." Rationale on the same page: "Note that
a read() of zero bytes does not modify the last data access timestamp. A
read() that requests more than zero bytes, but returns zero, is required to
modify the last data access timestamp."
pread: read page — "pread() function shall be equivalent to read(), except
that it shall read from a given position in the file without changing the file
offset" (inherits marking). readv has its own normative sentence: readv —
"Upon successful completion, readv() shall mark for update the last data
access timestamp of the file."
Model: `read(n)` with n>0 marks A even at EOF (0 bytes returned); `read(0)`
marks nothing.

**R8. write family marks M+C when nbyte > 0; may clear setid bits.** MUST for
the marks; may for the bit clearing.
Cite: write — "Upon successful completion, where nbyte is greater than 0,
write() shall mark for update the last data modification and last file status
change timestamps of the file, and if the file is a regular file, the S_ISUID
and S_ISGID bits of the file mode may be cleared."
Note the spec does NOT condition the clearing on privilege here (unlike chown).
Model: acceptance-set{setid-cleared | setid-kept} after successful write to a
regular file; always mark M and C for nbyte>0.
Linux-divergence: Linux clears S_ISUID always and S_ISGID only when S_IXGRP is
set (setgid-without-group-exec is the historic mandatory-locking encoding), and
skips clearing for privileged (CAP_FSETID) writers.

**R9. open O_CREAT creating a file marks new file A,M,C and parent M,C.** MUST.
Cite: open — "If O_CREAT is set and the file did not previously exist, upon
successful completion, open() shall mark for update the last data access, last
data modification, and last file status change timestamps of the file and the
last data modification and last file status change timestamps of the parent
directory."
Model: creation ops all share the pattern {new: A,M,C; parent: M,C}.

**R10. open O_TRUNC on an existing file marks M,C — unconditionally on
success.** MUST. The spec does not condition on the previous size.
Cite: open — "If O_TRUNC is set and the file did previously exist, upon
successful completion, open() shall mark for update the last data modification
and last file status change timestamps of the file." Semantics of O_TRUNC:
open — "If the file exists and is a regular file, and the file is successfully
opened O_RDWR or O_WRONLY, its length shall be truncated to 0, and the mode
and owner shall be unchanged. ... The result of using O_TRUNC without either
O_RDWR or O_WRONLY is undefined."
Model: O_TRUNC on an already-empty file still marks M,C. O_TRUNC+O_RDONLY is
undefined — exclude from generated traces.

**R11. mkdir marks new dir A,M,C and parent M,C.** MUST.
Cite: mkdir — "Upon successful completion, mkdir() shall mark for update the
last data access, last data modification, and last file status change
timestamps of the directory. Also, the last data modification and last file
status change timestamps of the directory that contains the new entry shall be
marked for update."

**R12. mknod marks new file A,M,C and parent M,C.** MUST.
Cite: mknod — "Upon successful completion, mknod() shall mark for update the
last data access, last data modification, and last file status change
timestamps of the file. Also, the last data modification and last file status
change timestamps of the directory that contains the new entry shall be marked
for update." mkfifo carries the same sentence on its own page (UNVERIFIED —
mkfifo page not fetched; pattern asserted from mknod, which normatively covers
FIFO creation: mknod — "Only a process with appropriate privileges may invoke
mknod() for file types other than FIFO-special.")

**R13. symlink marks the SYMLINK's A,M,C and parent M,C.** MUST — the times
belong to the symlink object itself, not the target.
Cite: symlink — "Upon successful completion, symlink() shall mark for update
the last data access, last data modification, and last file status change
timestamps of the symbolic link. Also, the last data modification and last
file status change timestamps of the directory that contains the new entry
shall be marked for update."
Model: symlinks are first-class nodes with their own three timestamps.

**R14. link marks C of the source file, and M,C of the directory gaining the
entry.** MUST. Only the *new entry's* parent is marked; nothing on the old
parent (it didn't change).
Cite: link — "Upon successful completion, link() shall mark for update the
last file status change timestamp of the file. Also, the last data
modification and last file status change timestamps of the directory that
contains the new entry shall be marked for update. If link() fails, no link
shall be created and the link count of the file shall remain unchanged."
Also: link — "If path1 names a directory, link() shall fail unless the process
has appropriate privileges and the implementation supports using link() on
directories" (EPERM). And Issue 8: link — "If path1 names a symbolic link, it
is implementation-defined whether link() follows the symbolic link, or creates
a new hard link to the symbolic link itself." (linkat AT_SYMLINK_FOLLOW makes
it follow: "a new hard link for the target of the symbolic link is created.")
Model: link(src, dst): src.ctime marked, dst_parent.{M,C} marked, src.nlink++.
plain link() on a symlink source is impl-defined — model linkat with explicit
flag instead.

**R15. unlink marks parent M,C; the victim's C is marked iff its link count
remains nonzero.** MUST.
Cite: unlink — "Upon successful completion, unlink() shall mark for update the
last data modification and last file status change timestamps of the parent
directory. Also, if the file's link count is not 0, the last file status
change timestamp of the file shall be marked for update."
Open-file survival: unlink — "If one or more processes have such a reference
to the file when the last link is removed, the link shall be removed before
unlink() returns, but the removal of the file contents shall be postponed
until there are no such references to the file."
Directories: unlink — "The path argument shall not name a directory unless the
process has appropriate privileges and the implementation supports using
unlink() on directories." (EPERM; use unlinkat AT_REMOVEDIR / rmdir.)
Model: if nlink goes 2 -> 1, victim ctime marked; if 1 -> 0 the inode may be
gone (no observable ctime unless still open — an open fd can fstat it, and the
mark rule "is not 0" means the last unlink does NOT require a C mark).

**R16. rename marks M,C of BOTH parent directories; the renamed file's own C
is acceptance-set.** Parents: MUST. File ctime: not specified normatively;
Issue 8 APPLICATION USAGE explicitly blesses both behaviors.
Cite: rename — "Upon successful completion, rename() shall mark for update the
last data modification and last file status change timestamps of the parent
directory of each file." And (informative) rename APPLICATION USAGE — "Some
implementations mark for update the last file status change timestamp of
renamed files and some do not. Applications which make use of the last file
status change timestamp may behave differently with respect to renamed files
unless they are designed to allow for either behavior."
Same-entry no-op: rename — "If the old argument and the new argument resolve
to either the same existing directory entry or different directory entries for
the same existing file, rename() shall return successfully and perform no
other action." (So in that case: NO timestamps marked at all.)
Failure atomicity: rename — "If the rename() function fails for any reason
other than [EIO], any file named by new shall be unaffected."
Model: parents' M,C marked (same dir counts once); file ctime =
acceptance-set{marked|unchanged}. Same-file rename is a total no-op that still
returns success. Linux-divergence: Linux does update the renamed file's ctime.

**R17. truncate/ftruncate mark M,C unconditionally on success (regular
files); setid bits may be cleared.** MUST for marks — the sentence has no
"if the size changed" condition; truncating to the current size still marks.
Cite: ftruncate — "Upon successful completion, if fildes refers to a regular
file, ftruncate() shall mark for update the last data modification and last
file status change timestamps of the file and the S_ISUID and S_ISGID bits of
the file mode may be cleared. If the ftruncate() function is unsuccessful, the
file is unaffected."
truncate — "Upon successful completion, truncate() shall mark for update the
last data modification and last file status change timestamps of the file,
and the S_ISUID and S_ISGID bits of the file mode may be cleared."
Extension is required: ftruncate — "If the file previously was smaller than
this size, ftruncate() shall increase the size of the file. If the file size
is increased, the extended area shall appear as if it were zero-filled."
truncate needs write permission: truncate — "The application shall ensure that
the process has write permission for the file" ([EACCES] "...write permission
is denied on the file"). ftruncate needs a writable fd: ftruncate — "[EBADF]
or [EINVAL] The fildes argument is not a file descriptor open for writing."
Other errnos: truncate: EACCES, EFBIG|EINVAL, EFBIG, EINTR, EINVAL (length<0),
EIO, EISDIR, ELOOP, ENAMETOOLONG, ENOENT, ENOTDIR, EROFS. ftruncate: EBADF|
EINVAL, EFBIG|EINVAL, EFBIG, EINTR, EINVAL, EIO.
Model: truncate(len == size) still marks M,C. EBADF-vs-EINVAL for non-writable
fd is acceptance-set{EBADF|EINVAL}.

**R18. readdir marks the directory's A each time the directory is actually
read.** MUST — note the buffering subtlety: the mark attaches to physical
reads, not to each readdir() return.
Cite: readdir — "The readdir() function may buffer several directory entries
per actual read operation; readdir() shall mark for update the last data
access timestamp of the directory each time the directory is actually read."
Model: model a whole-directory enumeration as one action that marks dir A at
least once; do not assert one mark per returned entry.

**R19. readlink marks the symlink's A.** MUST.
Cite: readlink — "Upon successful completion, readlink() shall mark for update
the last data access timestamp of the symbolic link."
Truncation: readlink — "If the buf argument is not large enough to contain the
link content, the first bufsize bytes shall be placed in buf." Return: "the
count of bytes placed in the buffer." [EINVAL] "The path argument names a file
that is not a symbolic link."
Model: readlink marks symlink A even though it "reads through" no data file.

---

## 3. stat / fstat / lstat / fstatat

**R20. Required-meaningful fields.** For all ordinary file types (i.e.,
everything except the SHM/TYM special objects): st_mode, st_ino, st_dev,
st_uid, st_gid, st_atim, st_ctim, st_mtim MUST be meaningful, and st_nlink
MUST equal the number of hard links. MUST.
Cite: stat — "For all other file types defined in this volume of POSIX.1-2024,
the structure members st_mode, st_ino, st_dev, st_uid, st_gid, st_atim,
st_ctim, and st_mtim shall have meaningful values and the value of the member
st_nlink shall be set to the number of hard links to the file."
Model: check exactly these fields; st_nlink is a hard invariant
(nlink == number of directory entries referencing the inode, +? see Traps for
directory link counts).

**R21. lstat on a symlink: type meaningful, permission bits unspecified,
st_size = strlen(target).** MUST for size; unspecified for mode bits.
Cite: stat — "For symbolic links, the st_mode member shall contain meaningful
information when used with the file type macros. The file mode bits in st_mode
are unspecified. The structure members st_ino, st_dev, st_uid, st_gid,
st_atim, st_ctim, and st_mtim shall have meaningful values and the value of
the st_nlink member shall be set to the number of hard links to the symbolic
link. The value of the st_size member shall be set to the length of the
pathname contained in the symbolic link not including any terminating null
byte."
Model: assert `lstat(sl).st_size == len(target_string)`; never assert symlink
permission bits. Linux note: Linux reports symlink mode 0777.

**R22. st_size per type.** Regular file: byte count (MUST). Symlink: target
length (MUST, R21). Directory and other types: unspecified.
Cite: <sys/stat.h> — "off_t st_size For regular files, the file size in
bytes. For symbolic links, the length in bytes of the pathname contained in
the symbolic link. ... For other file types, the use of this field is
unspecified."
Model: only assert st_size for regular files and symlinks; treat directory
st_size as opaque.

**R23. st_blksize / st_blocks are XSI and abstract.** impl-defined content.
Cite: <sys/stat.h> — "[XSI] blksize_t st_blksize A file system-specific
preferred I/O block size for this object. ... blkcnt_t st_blocks Number of
blocks allocated for this object."
Model: out of scope; at most assert st_blocks >= 0.

**R24. File identity.** (st_dev, st_ino) uniquely identifies a file; hard
links share it. MUST.
Cite: <sys/stat.h> — "A file identity is uniquely determined by the
combination of st_dev and st_ino. At any given time in a system, distinct
files shall have distinct file identities; hard links to the same file shall
have the same file identity."
Model: use inode ids; assert stat(a).ino == stat(b).ino after link(a,b).

**R25. stat needs no permission on the file itself — only search on the path
prefix.** MUST.
Cite: stat — "Read, write, or execute permission of the named file is not
required." EACCES is only: stat — "[EACCES] Search permission is denied for a
component of the path prefix."
Model: a mode-000 file is stat-able if the path is searchable.

**R26. fstatat dispatch and AT_SYMLINK_NOFOLLOW.** MUST.
Cite: stat — "The fstatat() function shall be equivalent to the stat() or
lstat() function, depending on the value of flag ... AT_SYMLINK_NOFOLLOW If
path names a symbolic link, the status of the symbolic link is returned." and
"If fstatat() is passed the special value AT_FDCWD in the fd parameter, the
current working directory shall be used and the behavior shall be identical to
a call to stat() or lstat() respectively."
Model: model one `getattr(node, follow: bool)` primitive.

**R27. stat family errno matrix.** MUST-fail conditions:
- EACCES — search denied on a path-prefix component (R25).
- EBADF — fstatat: "The path argument does not specify an absolute path and
  the fd argument is neither AT_FDCWD nor a valid file descriptor open for
  reading or searching."
- EIO — "An error occurred while reading from the file system."
- ELOOP — "A loop exists in symbolic links encountered during resolution of
  the path argument."
- ENAMETOOLONG — component longer than {NAME_MAX}.
- ENOENT — "A component of path does not name an existing file or path is an
  empty string."
- ENOTDIR — prefix component "neither a directory nor a symbolic link to a
  directory" (plus the trailing-slash-on-non-directory case).
- EOVERFLOW — file size/blocks/serial "cannot be represented correctly"
  (out of scope for an abstract model).
- EINVAL — fstatat: invalid flag.
Model: implement ENOENT/ENOTDIR/EACCES/ELOOP from shared path-walk logic;
EOVERFLOW excluded.

---

## 4. chmod / fchmod / fchmodat

**R28. Only owner-or-privileged may chmod.** MUST; else EPERM.
Cite: chmod — "If the effective user ID of the process does not match the
owner of the file and the process does not have appropriate privileges, the
chmod() function shall fail." Errors: chmod — "[EPERM] The effective user ID
does not match the owner of the file and the process does not have appropriate
privileges."
Note: write permission is irrelevant; group membership is irrelevant. Only
euid==st_uid or privilege.
Model: guard: euid == file.uid || privileged, else EPERM.

**R29. The 12 mode bits.** chmod sets the 9 permission bits plus S_ISUID,
S_ISGID, S_ISVTX; file-type bits in the argument are ignored.
Cite: chmod — "The chmod() function shall change S_ISUID, S_ISGID, [XSI]
S_ISVTX, and the file permission bits of the file named by the pathname
pointed to by the path argument to the corresponding bits in the mode
argument. If any bits that can be set in the st_mode value returned by lstat()
or stat() but cannot be changed using chmod(), such as the bits that are used
to encode the file type, are set in the mode argument, these read-only
st_mode bits shall be ignored." Restrictions: chmod — "Additional
implementation-defined restrictions may cause the S_ISUID and S_ISGID bits in
mode to be ignored, [XSI] and may cause the S_ISVTX bit in mode to be ignored
for non-directory files."
Model: mode is a 12-bit vector; allow an impl-defined predicate that drops
setuid/setgid/sticky requests (acceptance-set on those three bits' final
value only where the impl documents restrictions; on typical targets expect
them honored).

**R30. S_ISGID silently cleared for non-member unprivileged caller (regular
files).** MUST — the call still succeeds; the bit just doesn't stick.
Cite: chmod — "If the calling process does not have appropriate privileges,
and if the group ID of the file does not match the effective group ID or one
of the supplementary group IDs and if the file is a regular file, bit S_ISGID
(set-group-ID on execution) in the file's mode shall be cleared upon
successful return from chmod()."
Model: post-state: requested_mode & ~S_ISGID when (!privileged && file.gid not
in {egid} ∪ supplementary && regular). Success, not EPERM.

**R31. chmod marks C.** MUST — unconditional on success (even if the mode is
unchanged; cf. R6 "even if the file status does not change").
Cite: chmod — "Upon successful completion, chmod() shall mark for update the
last file status change timestamp of the file."
Model: chmod(file, same_mode) still marks C.

**R32. fchmodat AT_SYMLINK_NOFOLLOW may fail EOPNOTSUPP.** may-fail.
Cite: chmod — "AT_SYMLINK_NOFOLLOW If path names a symbolic link, then the
mode of the symbolic link is changed." and (may fail) "[EOPNOTSUPP] The
AT_SYMLINK_NOFOLLOW bit is set in the flag argument, path names a symbolic
link, and the system does not support changing the mode of a symbolic link."
(Note: the errno named on the Issue 8 page is EOPNOTSUPP, not ENOTSUP; on most
systems they are the same value.)
Model: acceptance-set{success-changing-symlink-mode | EOPNOTSUPP}.
Linux-divergence: historically glibc fchmodat(AT_SYMLINK_NOFOLLOW) returned
ENOTSUP; kernel 6.6 added fchmodat2 but symlink mode remains unchangeable on
Linux (EOPNOTSUPP path is the Linux reality).

**R33. chmod errno matrix.** MUST-fail: EACCES (search on prefix), ELOOP,
ENAMETOOLONG, ENOENT, ENOTDIR, EPERM (R28), EROFS ("The named file resides on
a read-only file system."). fchmodat also: EACCES (fd not O_SEARCH and dir
unsearchable), EBADF. may-fail: EINTR, EINVAL (mode or flag invalid),
EOPNOTSUPP (R32).
Model: same path-walk errors as stat; the file-specific check is only R28.

---

## 5. chown / fchown / lchown / fchownat

**R34. Base rule: owner-or-privileged may change ownership.** MUST.
Cite: chown — "Only processes with an effective user ID equal to the user ID
of the file or with appropriate privileges may change the ownership of a
file."

**R35. _POSIX_CHOWN_RESTRICTED: no giving files away; owner may chgrp to own
groups only.** MUST where the option is in effect (it is on all mainstream
systems).
Cite: chown — "Changing the user ID is restricted to processes with
appropriate privileges." and "Changing the group ID is permitted to a process
with an effective user ID equal to the user ID of the file, but without
appropriate privileges, if and only if owner is equal to the file's user ID or
(uid_t)-1 and group is equal either to the calling process' effective group ID
or to one of its supplementary group IDs."
EPERM: chown — "[EPERM] The effective user ID does not match the owner of the
file, or the calling process does not have appropriate privileges and
_POSIX_CHOWN_RESTRICTED indicates that such privilege is required."
Model (unprivileged): allow iff euid==file.uid && (owner in {file.uid, -1})
&& (group in {egid} ∪ supplementary ∪ {-1}); else EPERM. Privileged: anything.
Note: owner == file.uid (a "change" to the same uid) is explicitly allowed by
the "owner is equal to the file's user ID or (uid_t)-1" wording.

**R36. -1 means "don't change".** MUST.
Cite: chown — "If owner or group is specified as (uid_t)-1 or (gid_t)-1,
respectively, the corresponding ID of the file shall not be changed."
Model: treat -1 as Option::None per field.

**R37. setid-bit clearing on chown.** Three cases, all conditioned on at least
one of S_IXUSR/S_IXGRP/S_IXOTH being set:
- Regular file, unprivileged caller: MUST clear S_ISUID and S_ISGID.
  Cite: chown — "If the specified file is a regular file, one or more of the
  S_IXUSR, S_IXGRP, or S_IXOTH bits of the file mode are set, and the process
  does not have appropriate privileges, the set-user-ID (S_ISUID) and
  set-group-ID (S_ISGID) bits of the file mode shall be cleared upon
  successful return from chown()."
- Regular file, privileged caller: impl-defined.
  Cite: chown — "...and the process has appropriate privileges, it is
  implementation-defined whether the set-user-ID and set-group-ID bits are
  altered."
- Non-regular file (incl. directories): may clear.
  Cite: chown — "If the chown() function is successfully invoked on a file
  that is not a regular file and one or more of the S_IXUSR, S_IXGRP, or
  S_IXOTH bits of the file mode are set, the set-user-ID and set-group-ID
  bits may be cleared."
Note the precondition: with NO exec bits set anywhere, no clearing is
specified at all.
Model: unprivileged chown of exec-bearing regular file: post mode &=
~(S_ISUID|S_ISGID). Privileged / non-regular: acceptance-set{cleared|kept}.
Linux-divergence: Linux clears setuid/setgid on regular-file chown even for
root (unless the fs lacks support), never on directories, and clears S_ISGID
only when S_IXGRP is set.

**R38. chown marks C — even on a no-op ID change, except both-(-1).** MUST,
with a need-not carve-out only for (-1,-1).
Cite: chown — "Upon successful completion, chown() shall mark for update the
last file status change timestamp of the file, except that if owner is
(uid_t)-1 and group is (gid_t)-1, the file status change timestamp need not be
marked for update."
So chown(f, current_uid, current_gid) MUST mark C; chown(f, -1, -1) is
acceptance-set{marked|not-marked}.
Model: mark C unless (owner==-1 && group==-1), in which case accept both.

**R39. chown/fchownat errno matrix.** MUST-fail: EACCES (search on prefix),
ELOOP, ENAMETOOLONG, ENOENT, ENOTDIR, EPERM (R35), EROFS. fchownat also:
EACCES (fd not O_SEARCH), EBADF, ENOTDIR (fd not a directory), EINVAL (bad
flag, may). may-fail: EIO, EINTR, EINVAL — "The owner or group ID supplied is
not a value supported by the implementation.", ELOOP/ENAMETOOLONG extended
forms.
Cite: chown ERRORS section (quotes above and: "[EINVAL] The owner or group ID
supplied is not a value supported by the implementation.").
Model: EINVAL for out-of-range ids is may-fail — do not require it.

**R40. lchown / fchownat AT_SYMLINK_NOFOLLOW operate on the symlink itself.**
MUST.
Cite: chown — "AT_SYMLINK_NOFOLLOW If path names a symbolic link, ownership
of the symbolic link is changed." (and lchown is defined on the same page as
the symlink-targeting variant).
Model: symlinks have uid/gid state; chown-follow resolves, lchown doesn't.

---

## 6. utimensat / futimens

**R41. times[2] layout.** times[0] = access, times[1] = modification. MUST.
Cite: futimens — "The first array member represents the date and time of last
access, and the second member represents the date and time of last
modification."

**R42. NULL times = both set to now.** MUST.
Cite: futimens — "If the times argument is a null pointer, both the access and
modification timestamps shall be set to the greatest value supported by the
file system that is not greater than the current time."

**R43. UTIME_NOW / UTIME_OMIT per-slot semantics; tv_sec ignored for
specials.** MUST.
Cite: futimens — "If the tv_nsec field of a timespec structure has the special
value UTIME_NOW, the file's relevant timestamp shall be set to the greatest
value supported by the file system that is not greater than the current time.
If the tv_nsec field has the special value UTIME_OMIT, the file's relevant
timestamp shall not be changed. In either case, the tv_sec field shall be
ignored."
Model: per-slot enum {Set(t), Now, Omit}; explicit sets are clamped per R5.

**R44. Permission matrix.** Two tiers, distinguished by errno:
- NULL or both-UTIME_NOW: owner OR write access OR privilege. Else EACCES.
  Cite: futimens — "Only a process with the effective user ID equal to the
  user ID of the file, or with write access to the file, or with appropriate
  privileges may use futimens() or utimensat() with a null pointer as the
  times argument or with both tv_nsec fields set to the special value
  UTIME_NOW." Errno: "[EACCES] The times argument is a null pointer, or both
  tv_nsec values are UTIME_NOW, and the effective user ID of the process does
  not match the owner of the file and write access is denied."
- Any explicit time (not both-NOW, not both-OMIT): owner OR privilege ONLY —
  write access does not help. Else EPERM.
  Cite: futimens — "Only a process with the effective user ID equal to the
  user ID of the file or with appropriate privileges may use futimens() or
  utimensat() with a non-null times argument that does not have both tv_nsec
  fields set to UTIME_NOW and does not have both tv_nsec fields set to
  UTIME_OMIT." Errno: "[EPERM] The times argument is not a null pointer, does
  not have both tv_nsec fields set to UTIME_NOW, does not have both tv_nsec
  fields set to UTIME_OMIT, the calling process' effective user ID does not
  match the owner of the file, and the calling process does not have
  appropriate privileges."
Note: a mixed (Now, Omit) pair counts as the "explicit" tier (it is not
both-NOW), so it requires ownership even though it only sets to now.
Model: tier = both_now_or_null ? {owner|write|priv → else EACCES}
: {owner|priv → else EPERM}.

**R45. ctime marking: always on success, except both-OMIT need-not.** MUST
with carve-out.
Cite: futimens — "Upon successful completion, futimens() and utimensat() shall
mark the last file status change timestamp for update, with the exception that
if both tv_nsec fields are set to UTIME_OMIT, the file status change timestamp
need not be marked for update."
Model: C marked unless both-OMIT (then acceptance-set{marked|not}).

**R46. Both-OMIT: no ownership/permission check, but path errors still
detected; success is still success.** MUST for skipping the ownership check;
per-errno "may fail" for fd/path validity in the futimens/utimensat ERRORS
preamble.
Cite: futimens — "If both tv_nsec fields are set to UTIME_OMIT, no ownership
or permissions check shall be performed for the file, but other error
conditions may still be detected (including [EACCES] errors related to the
path prefix)." ERRORS preamble: "the futimens() and utimensat() functions
shall fail in the case that the times argument does not have both tv_nsec
fields set to UTIME_OMIT, and ... may fail in the case that the times argument
has both tv_nsec fields set to UTIME_OMIT".
Model: both-OMIT by a non-owner without any access: success (timestamps
untouched); path-prefix EACCES/ENOENT etc. are acceptance-set{error|success}
in the both-OMIT case (listed errors are downgraded to may-fail).

**R47. EINVAL conditions.** MUST-fail:
Cite: futimens — "[EINVAL] Either of the times argument structures specified a
tv_nsec value that was neither UTIME_NOW nor UTIME_OMIT, and was a value less
than zero or greater than or equal to 1000 million." Also EINVAL: "A new file
timestamp would be a value whose tv_sec component is not a value supported by
the file system." and utimensat: "The value of the flag argument is not
valid."
Model: validate tv_nsec ∈ [0, 10^9) ∪ {NOW, OMIT} before permission checks?
Order of checks is unspecified — accept either error when both apply.

**R48. AT_SYMLINK_NOFOLLOW sets the symlink's own times.** MUST.
Cite: futimens — "AT_SYMLINK_NOFOLLOW If path names a symbolic link, then the
access and modification times of the symbolic link are changed."

**R49. Remaining errno matrix.** EACCES (tier-1 perm; utimensat search on
prefix; fd not O_SEARCH), EBADF (futimens bad fd; utimensat bad dirfd), EINVAL
(R47), ELOOP, ENAMETOOLONG, ENOENT, ENOTDIR, EPERM (tier-2 perm), EROFS ("The
file system containing the file is read-only."). Failure guarantee: futimens —
"If -1 is returned, the file times shall not be affected."
Model: failed calls leave all three timestamps untouched.

---

## 7. access / faccessat

**R50. access checks with REAL uid/gid — including path search.** MUST.
Cite: access — "The checks for accessibility (including directory permissions
checked during pathname resolution) shall be performed using the real user ID
in place of the effective user ID and the real group ID in place of the
effective group ID."
Model: the ONLY op in this suite keyed to ruid/rgid; everything else uses
euid/egid. Needs separate real/effective identity in the caller state.

**R51. AT_EACCESS switches to effective ids.** MUST.
Cite: access — "AT_EACCESS ... The checks for accessibility (including
directory permissions checked during pathname resolution) shall be performed
using the effective user ID and group ID instead of the real user ID and group
ID as required in a call to access()." And faccessat with flag 0 "shall be
equivalent to the access() function" (modulo relative-path base).

**R52. amode: F_OK or OR of R_OK/W_OK/X_OK; F_OK is existence only.** MUST.
Cite: access — "The value of amode is either the bitwise-inclusive OR of the
access permissions to be checked (R_OK, W_OK, X_OK) or the existence test
(F_OK)."
F_OK checks no permission bits on the file itself — only that the path
resolves (search permission on the prefix is still needed, and its denial is
EACCES). This is by omission: no file-permission check is specified for F_OK.
Model: F_OK = path-resolution success; file may be mode 000.

**R53. Permission checks defer to XBD 4.7; each requested bit checked
individually.** MUST.
Cite: access — "If any access permissions are checked, each shall be checked
individually, as described in XBD 4.7 File Access Permissions". XBD 4.7 class
rule: "Access shall be granted if an alternate access control mechanism is not
enabled and the requested access permission bit is set for the class (file
owner class, file group class, or file other class) to which the process
belongs ... otherwise, access shall be denied."
Model: owner class if uid matches st_uid, else group class if gid/supplementary
matches st_gid, else other class; the FIRST matching class decides (owner
class denies even if 'other' would allow).

**R54. Privileged caller: R/W/search always granted; X requires at least one
x bit — but access() may report success anyway.** Two layers:
- XBD 4.7 (real behavior): "If a process has appropriate privileges: If read,
  write, or directory search permission is requested, access shall be granted.
  If execute permission is requested, access shall be granted if execute
  permission is granted to at least one user by the file permission bits or by
  an alternate access control mechanism; otherwise, access shall be denied."
  MUST.
- access() page carve-out (Issue 8): access — "except that where that
  description refers to execute permission for a process with appropriate
  privileges, an implementation may indicate success for X_OK even if execute
  permission is not granted to any user." may.
Model: privileged X_OK on a file with no x bits:
acceptance-set{success|EACCES}. Privileged R_OK/W_OK: always success. Also
note: X on a *directory* (search) for privileged is always granted.

**R55. access errno matrix.** MUST-fail: EACCES — "Permission bits of the file
mode do not permit the requested access, or search permission is denied on a
component of the path prefix."; ELOOP; ENAMETOOLONG; ENOENT; ENOTDIR; EROFS —
"Write access is requested for a file on a read-only file system.";
ETXTBSY — "Write access is requested for a pure procedure (shared text) file
that is being executed." (XSI shall-fail; Linux-divergence: Linux access()
does not fail W_OK with ETXTBSY). faccessat also: EACCES (fd not O_SEARCH),
EBADF, ENOTDIR. may-fail: EINVAL — "The value of the amode argument is
invalid.", faccessat EINVAL (flag), ELOOP/ENAMETOOLONG extended.
Model: EROFS for W_OK is a real must-fail; ETXTBSY needs an executing-binary
notion — mark out of scope.

**R56. access marks no timestamps.** By omission (R6's "other functions"
clause): no timestamp marking is specified for access.
Model: access/faccessat are pure reads of the permission state.

---

## 8. umask

**R57. Process-wide creation mask; returns previous value.** MUST.
Cite: umask — "The umask() function shall set the file mode creation mask of
the process to cmask and return the previous value of the mask." "No errors
are defined."
Model: one mask per process (thread-shared); umask never fails.

**R58. Only the 9 permission bits participate; S_ISVTX ignored (XSI); other
bits impl-defined.** MUST/impl-defined split.
Cite: umask — "Only the file permission bits of cmask (see <sys/stat.h>)
shall be used; [XSI] the S_ISVTX bit shall be ignored, and the meaning of the
other bits is implementation-defined." Return: "The file permission bits in
the value returned by umask() shall be the previous value of the file mode
creation mask. [XSI] The S_ISVTX bit in the returned value shall be clear."
So the mask can never remove S_ISUID/S_ISGID/S_ISVTX from a creation mode.
Model: mask state = 9 bits; ignore anything else passed in.

**R59. Where the mask applies.** The umask page enumerates the affected
creators: open/openat/creat, mkdir/mkdirat, mkfifo/mkfifoat, [XSI]
mknod/mknodat, [MSG] mq_open, sem_open. symlink is NOT in the list, and the
symlink page makes its mode unspecified (R64). MUST for the listed ops.
Cite: umask — "The file mode creation mask of the process is used to turn off
permission bits in the mode argument supplied during calls to the following
functions: open(), openat(), creat(), mkdir(), mkdirat(), mkfifo(), and
mkfifoat() [XSI] mknod(), mknodat() ... Permission bit positions that are set
in cmask are cleared in the mode of the created file."
Per-op wording, open — "a bitwise AND is performed on the file-mode bits and
the corresponding bits in the complement of the process' file mode creation
mask"; mkdir — "The file permission bits of the mode argument shall be
modified by the file creation mask of the process."; mknod — "The mknod()
function shall clear each bit whose corresponding bit in the file mode
creation mask of the process is set."
Model: created_perm = requested & 0777 & ~mask (setuid/setgid/sticky handling
per R60). umask does NOT apply to symlink creation.
Linux-divergence: when the parent directory carries a POSIX default ACL, Linux
ignores the umask for that creation — strict-POSIX model should not include
ACLs.

**R60. Non-permission bits in a creation mode.** open: "When bits other than
the file permission bits are set, the effect is unspecified." mkdir: "When
bits in mode other than the file permission bits [XSI] and S_ISVTX are set,
the meaning of these additional bits is implementation-defined." (i.e. mkdir
with XSI honors S_ISVTX on directories.)
Model: generate creation modes with only the 9 bits (+S_ISVTX for mkdir under
XSI); anything else is untestable portably.

---

## 9. Ownership & group of newly created objects

**R61. Owner of a new object = effective UID.** MUST, uniformly.
Cite: open — "the user ID of the file shall be set to the effective user ID of
the process"; mkdir — "The directory's user ID shall be set to the process'
effective user ID."; mknod — "The user ID of the file shall be initialized to
the effective user ID of the process."; symlink — "The symbolic link's user ID
shall be set to the process' effective user ID."
Model: new.uid = euid, always.

**R62. Group of a new object: acceptance-set{parent.gid | egid}.** MUST be one
of the two; which one is impl/config dependent.
Cite: open — "the group ID of the file shall be set to the group ID of the
file's parent directory or to the effective group ID of the process"; mkdir —
"The directory's group ID shall be set to the group ID of the parent directory
or to the effective group ID of the process."; mknod — "The group ID of the
file shall be initialized to either the effective group ID of the process or
the group ID of the parent directory."; symlink has the same pattern plus:
symlink — "Implementations shall provide a way to initialize the symbolic
link's group ID to the group ID of the parent directory. Implementations may,
but need not, provide an implementation-defined way to initialize the symbolic
link's group ID to the effective group ID of the calling process." (open and
mkdir carry the same two "Implementations shall provide a way ... may, but
need not ..." sentences.)
Model: assert new.gid ∈ {parent.gid, egid}. Do not hard-code either.

**R63. S_ISGID-directory group inheritance: NOT specified by POSIX.** The
Issue 8 mkdir/open pages contain no S_ISGID-inheritance rule (verified: no
occurrence of S_ISGID in the mkdir page text); the standard only offers the
R62 acceptance set. Whether the parent's S_ISGID bit forces parent-gid
inheritance, and whether a new subdirectory inherits the S_ISGID bit itself,
are outside the standard (the "shall provide a way" is typically satisfied by
exactly this mechanism, or by mount options).
Linux-divergence: on Linux, if the parent directory has S_ISGID set, the new
object gets parent.gid and a new directory also inherits S_ISGID; without it
(and without `grpid` mount option) the new object gets egid. Linux also clears
S_ISGID on non-directory creation when the creator is not a member of the
parent's group (since 5.19, for security).
Model: keep R62's acceptance set as the portable invariant; optionally model
the Linux S_ISGID rule as a FeatureMode.

**R64. Symlink permission bits are unspecified; contents always readable.**
unspecified.
Cite: symlink — "The values of the file mode bits for the created symbolic
link are unspecified. All interfaces specified by POSIX.1-2024 shall behave as
if the contents of symbolic links can always be read, except that the value of
the file mode bits returned in the st_mode field of the stat structure is
unspecified."
Model: never permission-check readlink against symlink mode bits; readlink
succeeds regardless of symlink mode (path-prefix search still required).

**R65. O_TRUNC preserves mode and owner.** MUST.
Cite: open — "its length shall be truncated to 0, and the mode and owner shall
be unchanged."
Model: truncation never resets ownership/mode (setid clearing on write/
truncate is separate, R8/R17).

---

## 10. Supporting: directory protection (sticky bit) — feeds unlink/rename

**R66. S_ISVTX on a writable directory restricts remove/rename.** MUST
(XSI-shaded errno choice).
Cite: XBD 4.5 — "If a directory is writable and the mode bit S_ISVTX is set on
the directory, a process may remove or rename files within that directory only
if one or more of the following is true: The effective user ID of the process
is the same as that of the owner ID of the file. The effective user ID of the
process is the same as that of the owner ID of the directory. The process has
appropriate privileges. Optionally, the file is writable by the process.
Whether or not files that are writable by the process can be removed or
renamed is implementation-defined."
Errno: unlink — "[EPERM] or [EACCES] The S_ISVTX flag is set on the directory
containing the file referred to by the path argument and the process does not
satisfy the criteria specified in XBD 4.5 Directory Protection." rename has
the same dual-errno wording for both the old file's directory and an existing
new file's directory. Non-directory S_ISVTX: XBD 4.5 — "If the S_ISVTX bit is
set on a non-directory file, the behavior is unspecified."
Model: sticky check = euid==file.uid || euid==dir.uid || privileged ||
(impl-defined: file writable). Errno acceptance-set{EPERM|EACCES}.
Linux-divergence: Linux returns EACCES for sticky violations and does not
grant the "file is writable" exception; Linux also ignores S_ISVTX on
regular files (no effect) which is within "unspecified".

---

## Testing notes

- **Timestamp assertions must go through a stat-family call**, which forces
  realization (R3). Pattern: `t0 = stat(); op(); t1 = stat();` and assert
  relations between t0/t1 fields. Never assert absolute times; assert
  monotone non-decrease and "changed vs unchanged" per the table, with
  acceptance for need-not cases (rename file-C, chown(-1,-1), both-OMIT).
- **1-second clamp (R5):** two ops within the same clock tick may yield equal
  timestamps. Assert `>=` for "marked" and `==` only for "not marked" when the
  clock is known to have advanced (insert a clock-advancing op or use an FS
  with ns resolution — still only assert >=).
- **The model's cheapest abstraction:** skip the mark/flush nondeterminism and
  update timestamps eagerly at op time, since every observation point (stat)
  forces realization anyway. The tri-state only becomes observable via mmap or
  crash semantics — out of scope. Keep the "need-not" cases as
  nondeterministic branches instead.
- **Identity split:** access (R50) is the only real-id consumer. If the test
  harness cannot vary ruid vs euid (e.g., NFS server context where only one
  identity exists per request), fold R50/R51 together and note the collapse.
- **Order of error checks is unspecified.** When a call has both a path error
  and a permission/EINVAL error available, accept any of the applicable
  errnos rather than a fixed priority.
- **Good adversarial cases from this inventory:**
  - chmod by non-member owner setting S_ISGID on a regular file → success with
    bit silently absent (R30).
  - utimensat explicit-times by a writer who is not owner → EPERM even though
    write access exists (R44).
  - utimensat both-OMIT by a stranger with no access to the file → success
    (R46).
  - truncate to the same length → M,C still change (R17).
  - open(O_TRUNC) on empty file → M,C change (R10).
  - unlink one of two hard links → survivor's C changes, nlink drops (R15).
  - read requesting >0 bytes at EOF (returns 0) → A still marked (R7).
  - chown(f, f.uid, g) where g ∈ supplementary → allowed unprivileged (R35);
    exec-bit-bearing file loses setuid/setgid (R37).
  - rename over an existing target: target's parent M,C marked; if old and
    new are links to the same file → total no-op with success (R16).
- **NFS/Chimera mapping caveat:** POSIX "appropriate privileges" maps to the
  server's root-squash policy; model privilege as a per-caller boolean, and
  make the privileged branches (R28/R35/R54) FeatureMode-gated since squashed
  root behaves unprivileged.

## Traps

- **EACCES vs EPERM is semantic, not stylistic:** EACCES = a permission-bit
  check failed (path search, file access, tier-1 utimensat); EPERM = an
  ownership/privilege rule failed (chmod non-owner, chown restriction, tier-2
  utimensat, sticky-bit under one reading). Sticky-bit violations are the one
  deliberate acceptance-set{EPERM|EACCES} (R66).
- **chmod does not need write access, and write access never enables chmod/
  chown/explicit-utimensat.** Only ownership or privilege do. Conversely,
  tier-1 utimensat (NULL/both-NOW) is the one metadata write that a mere
  writer can perform (R44).
- **rename's file-ctime is a portability trap** (R16): Linux marks it, the
  standard doesn't require it, and Issue 8 APPLICATION USAGE documents the
  split. A model asserting "unchanged" will fail on Linux; asserting "changed"
  fails elsewhere. Must be acceptance-set.
- **"need not be marked" ≠ "shall not be marked"**: chown(-1,-1) (R38) and
  both-OMIT utimensat (R45) may still bump ctime on a conforming system.
- **read(fd, buf, 0) vs read at EOF** (R7): the atime rule keys on the
  *requested* nbyte, not bytes returned.
- **readdir atime keys on physical reads** (R18): a fully-buffered directory
  stream may mark A once for many readdir() returns; never assert per-entry
  marks.
- **S_ISGID clearing on chmod (R30) applies only to regular files** — a
  non-member owner CAN set S_ISGID on a directory (that's how BSD-style
  group inheritance is configured). Don't over-apply the clearing rule.
- **chown setid clearing needs an exec bit present** (R37); chown on a
  mode-644 setuid file (setuid without any x bit) has no specified clearing.
  Also privileged chown clearing is impl-defined — Linux clears anyway.
- **umask can't mask setuid/setgid/sticky** (R58) and doesn't apply to
  symlink() at all (R59/R64).
- **Symlink st_size excludes the NUL** (R21) and symlink mode bits are
  garbage — never derive permissions from lstat().st_mode.
- **Directory st_size is unspecified** (R22) — never assert it (memfs-style
  0, ext4-style 4096, and NFS-server synthesized values are all conforming).
- **st_nlink for directories:** POSIX only says "number of hard links" (R20);
  whether `.`/`..` count as hard links making dirs 2+N is convention, not
  spec. Do not assert the classic 2+N rule as MUST (btrfs reports 1).
- **fchmodat AT_SYMLINK_NOFOLLOW is allowed to fail wholesale** (R32) — model
  it as a may-succeed feature, and note the page spells the errno EOPNOTSUPP.
- **fstatat/faccessat/fchownat EBADF wording** requires the fd be "open for
  reading or searching" for relative paths — an O_WRONLY dirfd is a valid
  EBADF trigger in the spec text, though rarely enforced.
  Linux-divergence: Linux accepts O_PATH/any-mode directory fds.
- **access with privileged X_OK** (R54): two-layer rule — real execution
  (XBD 4.7) needs at least one x bit even for root, but access() is allowed
  to lie and report success. acceptance-set{0|EACCES} for root X_OK on 000
  files.
- **EROFS interacts with the times model** (R4): on a read-only fs, even
  atime marks vanish; also access(W_OK) must fail EROFS (R55) even when the
  permission bits would grant write.
- **Failed calls must not partially apply:** futimens — "If -1 is returned,
  the file times shall not be affected."; chmod — "If -1 is returned, no
  change to the file mode occurs."; link — "If link() fails, no link shall be
  created"; ftruncate — "If the ftruncate() function is unsuccessful, the
  file is unaffected." Model every metadata op as atomic succeed-or-noop.
