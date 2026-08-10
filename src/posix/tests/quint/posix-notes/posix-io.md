<!--
SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors

SPDX-License-Identifier: LGPL-2.1-only
-->

# POSIX.1-2024 (Issue 8) — File I/O Rule Inventory

Scope: read, write, pread, pwrite, readv/writev, lseek, truncate, ftruncate,
fsync, fdatasync. For a formal Quint model of a single-client POSIX-over-NFS
harness.

Sources (all fetched and quoted verbatim from Issue 8,
https://pubs.opengroup.org/onlinepubs/9799919799/):

- `functions/read.html` (covers pread), `functions/write.html` (covers pwrite)
- `functions/lseek.html`, `functions/truncate.html`, `functions/ftruncate.html`
- `functions/fsync.html`, `functions/fdatasync.html`
- `functions/readv.html`, `functions/writev.html`
- `functions/V2_chap02.html` XSH 2.9.7 (raw HTML downloaded; section extracted
  directly — note Issue 8 retitled it "Thread Interactions with File
  Operations", not "... with Regular File Operations" as in Issue 7)
- `functions/fcntl.html` (advisory-lock language)

No Issue 7 fallback was needed. Requirement levels: **MUST** (shall),
**may-fail** (error detection optional), **unspecified**, **impl-defined**,
**acceptance-set{...}** (spec explicitly allows alternatives). Rules not backed
by fetched text are marked UNVERIFIED.

---

## 1. read()

**R1. nbyte == 0 is a no-op (with optional error detection).**
Behavior: returns 0, no side effects; implementation MAY instead detect and
return the documented errors. Requirement: acceptance-set{return 0 with no
effects, any documented error}. Errno: any from the ERRORS list.
Citation: read(): "Before any action described below is taken, and if nbyte is
zero, the read() function may detect and return errors as described below. In
the absence of errors, or if error detection is not performed, the read()
function shall return zero and have no other results."
Model: `read(fd, 0)` returns 0, state unchanged (incl. no atime mark, see R7);
accept a documented errno (e.g. EBADF on a write-only fd) as conformant.

**R2. Reads start at the file offset; offset advances by bytes read.**
Requirement: MUST. Citation: read(): "On files that support seeking (for
example, a regular file), the read() shall start at a position in the file
given by the file offset associated with fildes. The file offset shall be
incremented by the number of bytes actually read."
Model: `offset' = offset + retval`.

**R3. EOF: no transfer past end-of-file; at/after EOF returns 0.**
Requirement: MUST. Citation: read(): "No data transfer shall occur past the
current end-of-file. If the starting position is at or after the end-of-file,
0 shall be returned."
Model: `retval = min(nbyte, max(0, size - offset))`; retval 0 at EOF is
success, not an error.

**R4. Short reads on regular files.**
Behavior: the returned count may be less than nbyte only for enumerated
causes. Requirement: the spec says "may be less than nbyte if ..." — the
enumeration (bytes left < nbyte, signal, pipe/FIFO/special with fewer bytes
available) is the only stated license; a mid-file short read on a regular file
with no signals has no stated justification, but the wording is "may be less
... if", not "only if", so treat strictly-full reads as the expected behavior
and other short reads as acceptance-set{full, short} with a deviation flag.
Citation: read(): "This number shall never be greater than nbyte. The value
returned may be less than nbyte if the number of bytes left in the file is
less than nbyte, if the read() request was interrupted by a signal, or if the
file is a pipe or FIFO or special file and has fewer than nbyte bytes
immediately available for reading."
Model: assert `retval == min(nbyte, size - offset)` for regular files in a
signal-free harness; log (don't hard-fail) other short reads.

**R5. Holes / never-written bytes read as zeros.**
Requirement: MUST. Citation: read(): "The read() function reads data
previously written to a file. If any portion of a regular file prior to the
end-of-file has not been written, read() shall return bytes with value 0. For
example, lseek() allows the file offset to be set beyond the end of existing
data in the file. If data is later written at this point, subsequent reads in
the gap between the previous end of data and the newly written data shall
return bytes with value 0 until data is written into the gap."
Model: file content is a map offset→byte with default 0 up to `size`.

**R6. Read-after-write coherence (see also R21).**
A successful read of a byte position previously written must return the
written data. Requirement: MUST (write() DESCRIPTION, normative). Citation:
write(): "After a write() to a regular file has successfully returned: Any
successful read() from each byte position in the file that was modified by
that write shall return the data specified by the write() for that position
until such byte positions are again modified."
Model: reads are exact lookups against the modeled byte map — no staleness
allowed for a single client.

**R7. atime marking.**
Behavior: successful read with nbyte > 0 marks atime for update — including a
read at EOF that returns 0. nbyte == 0 does not. Requirement: MUST.
Citation: read(): "Upon successful completion, where nbyte is greater than 0,
read() shall mark for update the last data access timestamp of the file";
RATIONALE (informative but explicit): "Note that a read() of zero bytes does
not modify the last data access timestamp. A read() that requests more than
zero bytes, but returns zero, is required to modify the last data access
timestamp."
Model: mark atime on success iff nbyte > 0, even when retval == 0.
Note "mark for update" ≠ immediate update; the actual timestamp write may be
deferred until the file ceases to be open or a stat-family call (XBD file
times update semantics) — compare atime with >= against a pre-read snapshot,
and beware NFS relatime/noatime mounts (Linux-divergence: relatime is the
Linux default and suppresses many atime updates — UNVERIFIED here, but do not
hard-assert atime change).

**R8. EBADF when fd is not open for reading.**
Requirement: MUST ("These functions shall fail if"). Errno: EBADF.
Citation: read(): "[EBADF] The fildes argument is not a valid file descriptor
open for reading."
Model: read on O_WRONLY fd → EBADF, state unchanged.

**R9. read() on a directory fd: acceptance-set{success, EISDIR}, XSI-shaded.**
The EISDIR entry is conditional on the implementation disallowing it, i.e.
implementations are permitted to let read() succeed on a directory.
Requirement: acceptance-set{EISDIR, success with unspecified content}.
Citation: read() ERRORS (under "shall fail", [XSI] shaded): "[EISDIR] The
fildes argument refers to a directory and the implementation does not allow
the directory to be read using read() or pread(). The readdir() function
should be used instead."
Linux-divergence: Linux read() on a directory returns EISDIR (allowed by the
acceptance set, so not a conformance issue — just don't require EISDIR of
other implementations).
Model: accept {EISDIR, success}; if success, make no assertion on the bytes.

**R10. Misc read() errors — background/out of scope.**
EOVERFLOW (starting position ≥ offset maximum of the OFD) — out of scope for
a small-file model. EAGAIN on regular files is now a "shall fail" case in
Issue 8 when O_NONBLOCK is set and the thread would be delayed: "[EAGAIN] The
file is neither a pipe, nor a FIFO, nor a socket, the O_NONBLOCK flag is set
for the file descriptor, and the thread would be delayed in the read
operation." May-fail set includes EIO/ENOBUFS/ENOMEM/ENXIO.
Also: "The behavior of multiple concurrent reads on the same pipe, FIFO, or
terminal device is unspecified." (regular files are NOT in that list).
Model: don't set O_NONBLOCK in the harness; treat EAGAIN/EIO as
environment-failure, not modeled transitions.

---

## 2. write()

**R11. Writes go at the file offset; offset advances before return.**
Requirement: MUST. Citation: write(): "On a regular file or other file
capable of seeking, the actual writing of data shall proceed from the
position in the file indicated by the file offset associated with fildes.
Before successful return from write(), the file offset shall be incremented
by the number of bytes actually written."
Model: `offset' = offset + retval`.

**R12. Extension of the file.**
Requirement: MUST. Citation: write(): "On a regular file, if the position of
the last byte written is greater than or equal to the length of the file, the
length of the file shall be set to this position plus one."
Model: `size' = max(size, offset + retval)`.

**R13. Writing past EOF after lseek: the gap reads as zeros.**
Requirement: MUST. The zero-fill language lives on the lseek() and read()
pages, not write() (verified: write() page has no gap-fill sentence).
Citation: lseek(): "The lseek() function shall allow the file offset to be
set beyond the end of the existing data in the file. If data is later written
at this point, subsequent reads of data in the gap shall return bytes with
the value 0 until data is actually written into the gap." (read() page quote
in R5 is the matching read-side statement.)
Model: seek-past-EOF + write creates a hole [old_size, write_offset) that
reads as zeros; size jumps to write_offset + nbyte.

**R14. O_APPEND: atomic seek-to-EOF-then-write on the shared offset.**
Requirement: MUST. Citation: write(): "If the O_APPEND flag of the file
status flags is set, the file offset shall be set to the end of the file
prior to each write and no intervening file modification operation shall
occur between changing the file offset and the write operation."
Note this mutates the open file description's offset: after the write the
shared offset = old EOF + bytes written, regardless of where it was before,
and any prior lseek() position is ignored/overwritten for the write.
Model: for O_APPEND fds: `write_pos = size; offset' = size + retval;
size' = size + retval`. The no-intervening-modification clause is a
multi-writer atomicity guarantee — background for a single-threaded harness.

**R15. Return value / partial writes.**
Requirement: MUST. Citation: write() RETURN VALUE: "Upon successful
completion, these functions shall return the number of bytes actually written
to the file associated with fildes. This number shall never be greater than
nbyte." DESCRIPTION: "If a write() requests that more bytes be written than
there is room for (for example, the file size limit of the process or the
physical end of a medium), only as many bytes as there is room for shall be
written."
Model: with ample space, expect `retval == nbyte` for regular files
(signal-free harness); a short write with free space and no limits has no
stated justification — treat like R4 (log as deviation).

**R16. nbyte == 0 on a regular file.**
Requirement: acceptance-set{return 0 with no effects, documented error};
non-regular file: unspecified. Citation: write(): "Before any action
described below is taken, and if nbyte is zero and the file is a regular
file, the write() function may detect and return errors as described below.
In the absence of errors, or if error detection is not performed, the write()
function shall return zero and have no other results. If nbyte is zero and
the file is not a regular file, the results are unspecified."
Model: `write(fd, 0)` on regular file → 0, no state change (no timestamp
marks — R17 requires nbyte > 0); accept documented errno.

**R17. mtime + ctime marking.**
Requirement: MUST (when nbyte > 0 and successful). Citation: write(): "Upon
successful completion, where nbyte is greater than 0, write() shall mark for
update the last data modification and last file status change timestamps of
the file."
Model: mark mtime and ctime on successful non-zero write; same "mark for
update" deferral caveat as R7 — assert with >=, and assert no change for
nbyte == 0.

**R18. EBADF when fd is not open for writing.**
Requirement: MUST. Citation: write(): "[EBADF] The fildes argument is not a
valid file descriptor open for writing."
Model: write on O_RDONLY fd → EBADF, state unchanged.

**R19. EFBIG / ENOSPC — out of scope.**
Citation (one of three EFBIG entries): "[EFBIG] An attempt was made to write
a file that exceeds the implementation-defined maximum file size and there
was no room for any bytes to be written." ENOSPC: "There was no free space
remaining on the device containing the file."
Model: keep files tiny; treat ENOSPC/EFBIG as environment failures that abort
the trace rather than modeled transitions.

**R20. Overwrite semantics.**
Requirement: MUST. Citation: write(): "Any subsequent successful write() to
the same byte position in the file shall overwrite that file data."
Model: byte-map assignment (last write wins).

**R21. Serialization of writes vs. reads (write() page view).**
Citation (RATIONALE, informative): "Writes can be serialized with respect to
other reads and writes. If a read() of file data can be proven to occur
after a write() of the data, it must reflect that write()." The normative
counterpart is R6 plus XSH 2.9.7 (R52).
Model: single-threaded harness ⇒ trivially satisfied; keep as documentation.

---

## 3. pread() / pwrite()

**R22. pread reads at the given offset and does not move the file offset.**
Requirement: MUST. Citation: read(): "The pread() function shall be
equivalent to read(), except that it shall read from a given position in the
file without changing the file offset."
Model: same result function as read() with `pos = offset_arg`; fd offset
invariant across the call.

**R23. pwrite writes at the given offset, ignoring O_APPEND.**
Requirement: MUST. Citation: write(): "The pwrite() function shall be
equivalent to write(), except that it writes into a given position and does
not change the file offset (regardless of whether O_APPEND is set)."
Linux-divergence: on Linux, pwrite() on an fd opened with O_APPEND appends to
the end of the file regardless of the offset argument (documented in the
pwrite(2) man page BUGS section — the man-page citation is from memory,
UNVERIFIED this session; the POSIX text above is verified and unambiguous).
Model: model the POSIX behavior; gate an "appendish pwrite" acceptance branch
behind a Linux-compat FeatureMode flag if testing a Linux-backed VFS with
O_APPEND fds, or simply never combine O_APPEND with pwrite in generated
traces.

**R24. Negative offset → EINVAL; fd offset unchanged on that error.**
Requirement: MUST ("shall fail"). Errno: EINVAL. Citation: read()/write()
(identical wording): "[EINVAL] The file is a regular file or block special
file, and the offset argument is negative. The file offset shall remain
unchanged."
Model: guard offsets ≥ 0, or model the EINVAL branch with no state change.

**R25. pread/pwrite on non-seekable files → ESPIPE.**
Requirement: MUST. Citation: write() DESCRIPTION: "An attempt to perform a
pwrite() on a file that is incapable of seeking shall result in an error";
ERRORS (both pages): "[ESPIPE] The file is incapable of seeking."
Model: out of scope if the model has no pipes; note the errno name is ESPIPE
(not EINVAL).

---

## 4. lseek()

**R26. Whence semantics.**
Requirement: MUST. Citation: lseek(): "If whence is SEEK_SET, the file offset
shall be set to offset bytes."; "If whence is SEEK_CUR, the file offset shall
be set to its current location plus offset."; "If whence is SEEK_END, the
file offset shall be set to the size of the file plus offset."
Model: exactly these three formulas; SEEK_END uses current `size` (so it
observes truncate/extension by other fds on the same file).

**R27. SEEK_HOLE / SEEK_DATA (new in Issue 8).**
Requirement: MUST if implemented per the definitions; ENXIO cases specified.
Citation: lseek(): "If whence is SEEK_HOLE, the file offset shall be set to
the smallest location of a byte within a hole and not less than offset ...";
"A hole is a contiguous region of bytes within a file, all having the value
of zero. Not all bytes with the value zero need belong to a hole; however,
all seekable files shall have a virtual hole starting at the current size of
the file, whether or not the file is sparse."; "[ENXIO] The whence argument
is SEEK_HOLE or SEEK_DATA, and offset is greater than or equal to the file
size; or the whence argument is SEEK_DATA and the offset falls beyond the
last byte not within a hole."
Model: optional phase-2. The virtual-hole-at-EOF rule gives a cheap always-
valid oracle: SEEK_HOLE(0) on a fully-written file may return `size`; since
"not all bytes with the value zero need belong to a hole", only weak
assertions are portable (result in [offset, size], points at a zero byte or
EOF).

**R28. Seeking past EOF is allowed and does not extend the file.**
Requirement: MUST. Citation: lseek(): quote in R13, plus: "The lseek()
function shall not, by itself, extend the size of a file."
Model: offset may exceed size; size invariant under lseek.

**R29. Return value.**
Requirement: MUST. Citation: lseek(): "Upon successful completion, the
resulting offset, as measured in bytes from the beginning of the file, shall
be returned." On error "the file offset shall remain unchanged."
Model: retval equals the new absolute offset; failed lseek leaves offset
untouched.

**R30. Negative resulting offset / bad whence → EINVAL.**
Requirement: MUST ("shall fail"). Errno: EINVAL. Citation: lseek():
"[EINVAL] The whence argument is not a proper value, or the resulting file
offset would be negative for a regular file, block special file, or
directory."
Model: SEEK_CUR/SEEK_SET/SEEK_END producing a negative offset → EINVAL,
state unchanged.

**R31. ESPIPE on pipe/FIFO/socket.**
Requirement: MUST. Citation: lseek(): "[ESPIPE] The fildes argument is
associated with a pipe, FIFO, or socket."
Model: out of scope without pipes; note sockets included.

**R32. EBADF requires only an open fd — no access-mode requirement.**
Requirement: MUST. Citation: lseek(): "[EBADF] The fildes argument is not an
open file descriptor." (contrast R8/R18 — lseek works on read-only and
write-only fds alike).
Model: lseek legal on any open fd regardless of O_RDONLY/O_WRONLY.

**R33. Non-seekable devices impl-defined; directories are seekable objects.**
Citation: lseek(): "The behavior of lseek() on devices which are incapable of
seeking is implementation-defined." Directories: no explicit description, but
the EINVAL wording "for a regular file, block special file, or directory"
implies directory fds are contemplated; the meaning of a directory offset is
otherwise unspecified here.
Model: allow lseek on directory fds but assert nothing beyond
no-crash/negative-EINVAL.

**R34. lseek marks no timestamps.**
Requirement: verified absence — the lseek() page contains no timestamp
language at all.
Model: lseek is timestamp-neutral; assert atime/mtime/ctime unchanged.

**R35. EOVERFLOW — out of scope.**
Citation: lseek(): "[EOVERFLOW] The resulting file offset would be a value
which cannot be represented correctly in an object of type off_t."
Model: keep offsets small.

---

## 5. truncate() / ftruncate()

**R36. Shrink discards data.**
Requirement: MUST. Citation: truncate(): "The truncate() function shall cause
the regular file named by path to have a size which shall be equal to length
bytes. If the file previously was larger than length, the extra data is
discarded." ftruncate(): "If the size of the file previously exceeded length,
the extra data shall no longer be available to reads on the file."
Model: `size' = length`; byte map restricted to [0, length).

**R37. Extension is REQUIRED for both, and extended area reads as zeros.**
Requirement: MUST for both functions in Issue 8 — no implementation option.
Citation: truncate(): "If the file was previously shorter than length, its
size is increased, and the extended area appears as if it were zero-filled."
ftruncate(): "If the file previously was smaller than this size, ftruncate()
shall increase the size of the file. If the file size is increased, the
extended area shall appear as if it were zero-filled."
Historic note: pre-standard BSD truncate/ftruncate did not extend files
(UNVERIFIED, historical memory); Issue 8 text leaves no such latitude, and
the wording is materially identical for both functions.
Model: `size' = length` unconditionally; new range is a hole of zeros.

**R38. ftruncate applies to regular files; other types unspecified.**
Citation: ftruncate(): "If fildes refers to a regular file, the ftruncate()
function shall cause the size of the file to be truncated to length." ...
"If fildes refers to a shared memory object, ftruncate() shall set the size
of the shared memory object to length." ... "If fildes is a file descriptor
open for writing and refers to a file that is neither a regular file nor a
shared memory object, the result is unspecified." EINVAL is also on offer:
"[EINVAL] The length argument is less than 0 or the fildes argument refers
to a file on which this operation is not possible (for example, a pipe, FIFO
or socket)."
Model: only issue ftruncate on regular-file fds.

**R39. ftruncate on fd not open for writing: acceptance-set{EBADF, EINVAL}.**
Requirement: MUST fail; errno is an explicit either/or. Citation:
ftruncate() ERRORS: "[EBADF] or [EINVAL] The fildes argument is not a file
descriptor open for writing."
Linux-divergence: Linux returns EINVAL for a valid fd opened O_RDONLY and
EBADF for an invalid fd (memory, UNVERIFIED — but both fall inside the
acceptance set).
Model: accept either errno; assert no state change.

**R40. truncate permission: write permission via path → EACCES.**
Requirement: MUST. Citation: truncate(): "The application shall ensure that
the process has write permission for the file."; ERRORS: "[EACCES] A
component of the path prefix denies search permission, or write permission is
denied on the file." (No fd involved — truncate never returns EBADF.)
Model: mode check on the file itself for truncate(); fd-mode check (R39) for
ftruncate() — note ftruncate ignores file permission bits once the fd is
open for writing.

**R41. Negative length → EINVAL; directories: EISDIR (truncate).**
Requirement: MUST. Citation: truncate(): "[EINVAL] The length argument is
less than 0 or the path argument refers to a file, other than a directory,
on which this operation is not possible (for example, a FIFO or socket)."
and "[EISDIR] The named file is a directory." ftruncate(): "[EINVAL] The
length argument is less than 0 ..." (ftruncate has no EISDIR entry; a
directory fd open for writing is essentially unobtainable, and a
non-writable fd hits R39).
Model: truncate(dir) → EISDIR; truncate/ftruncate(len < 0) → EINVAL; no
state change on error.

**R42. Neither function moves any file offset.**
Requirement: MUST. Citation: truncate(): "The truncate() function shall not
modify the file offset for any open file descriptions associated with the
file." ftruncate(): "The value of the seek pointer shall not be modified by
a call to ftruncate()."
Model: offsets of all open fds invariant — so shrink can leave offsets past
EOF (subsequent read → 0, subsequent write re-extends with a hole; R3/R13).

**R43. Timestamps: marked UNCONDITIONALLY on success — even if size didn't
change.**
Requirement: MUST; verified that neither page carries an "if the file size is
changed" qualifier on the timestamp sentence. Citation: truncate(): "Upon
successful completion, truncate() shall mark for update the last data
modification and last file status change timestamps of the file, and the
S_ISUID and S_ISGID bits of the file mode may be cleared." ftruncate():
"Upon successful completion, if fildes refers to a regular file, ftruncate()
shall mark for update the last data modification and last file status change
timestamps of the file and the S_ISUID and S_ISGID bits of the file mode may
be cleared." (Only condition: regular file.)
Model: truncate-to-same-size still marks mtime+ctime. Good probe: many
implementations skip the update when the size is unchanged — that would be a
genuine conformance deviation worth a FeatureMode toggle.

**R44. EFBIG — out of scope; acceptance-set{EFBIG, EINVAL} for length > max.**
Citation: both pages: "[EFBIG] or [EINVAL] The length argument is greater
than the maximum file size."
Model: keep lengths small; note the either/or if ever probed.

---

## 6. readv() / writev()

**R45. Equivalence to read()/write() over concatenated buffers, in order.**
Requirement: MUST. Citation: readv(): "The readv() function shall be
equivalent to read(), except as described below. The readv() function shall
place the input data into the iovcnt buffers specified by the members of the
iov array: iov[0], iov[1], ..., iov[iovcnt-1]." and "The readv() function
shall always fill an area completely before proceeding to the next."
writev(): "The writev() function shall be equivalent to write(), except as
described below. The writev() function shall gather output data from the
iovcnt buffers specified by the members of the iov array" and "The writev()
function shall always write a complete area before proceeding to the next."
readv also carries its own atime sentence: "Upon successful completion,
readv() shall mark for update the last data access timestamp of the file."
Model: abstract both to single-buffer read/write of the concatenation —
justified by these equivalence sentences; no separate model actions needed.

**R46. iovcnt validity: split may-fail / shall-fail EINVAL.**
Requirement: iovcnt out of range: may-fail ("valid if greater than 0 and less
than or equal to {IOV_MAX}"; error listed under may-fail). Sum overflow:
MUST fail. Citation: writev(): "The iovcnt argument was less than or equal
to 0, or greater than {IOV_MAX}." (may fail) and "The sum of the iov_len
values in the iov array would overflow an ssize_t." (shall fail). Errors
otherwise: "Refer to write()."
Model: generate only valid iovcnt; if probing, acceptance-set{EINVAL,
success-as-if-valid?} — strictly, out-of-range iovcnt with no error raised is
undefined-ish (argument "is valid if" — behavior outside validity is not
defined), so just avoid it.

**R47. Error return leaves the offset unchanged.**
Citation: writev() RETURN VALUE: "Upon successful completion, writev() shall
return the number of bytes actually written. Otherwise, it shall return a
value of -1, the file-pointer shall remain unchanged, and errno shall be set
to indicate an error."
Model: matches the general failed-call-is-stateless convention.

---

## 7. fsync() / fdatasync()

**R48. fsync: transfer to storage; blocking; nature impl-defined.**
Requirement: MUST issue+wait, but what "transfer" means is impl-defined
unless SIO. Citation: fsync(): "The fsync() function shall request that all
data for the open file descriptor named by fildes is to be transferred to
the storage device associated with the file described by fildes. The nature
of the transfer is implementation-defined. The fsync() function shall not
return until the system has completed that action or until an error is
detected." SIO-shaded: "If _POSIX_SYNCHRONIZED_IO is defined, the fsync()
function shall force all currently queued I/O operations associated with the
file indicated by file descriptor fildes to the synchronized I/O completion
state. All I/O operations shall be completed as defined for synchronized I/O
file integrity completion." RATIONALE: "It is explicitly intended that a
null implementation is permitted."
Model: in a no-crash model, fsync is a pure no-op on visible state
(content, size, offsets, timestamps all invariant); only errno behavior is
observable.

**R49. fdatasync: data integrity (not file integrity) completion.**
Requirement: MUST (function is SIO/optional per its shading). Citation:
fdatasync(): "The fdatasync() function shall force all currently queued I/O
operations associated with the file indicated by file descriptor fildes to
the synchronized I/O completion state." and "all I/O operations shall be
completed as defined for synchronized I/O data integrity completion."
RETURN VALUE: "If successful, the fdatasync() function shall return the
value 0; otherwise, the function shall return the value -1 and set errno to
indicate the error."
Model: identical no-op to fsync in a no-crash model; the data-vs-file
integrity distinction (metadata like timestamps need not be flushed) is
invisible without crash injection.

**R50. Errors.**
Requirement: MUST fail on these. Citation: fsync(): "[EBADF] The fildes
argument is not a valid descriptor." — note: no "open for writing" clause;
fsync on a read-only fd is not an EBADF case. "[EINVAL] The fildes argument
does not refer to a file on which this operation is possible." "[EIO] An I/O
error occurred while reading from or writing to the file system." Also
"If the fsync() function fails, outstanding I/O operations are not
guaranteed to have been completed." fdatasync(): "[EBADF] The fildes
argument is not a valid file descriptor." "[EINVAL] This implementation does
not support synchronized I/O for this file."
Model: fsync/fdatasync on any open regular-file fd (either access mode) →
success; closed fd → EBADF; treat EINVAL as an environment capability flag,
EIO as trace-aborting.

**R51. No timestamp effects.**
Requirement: verified absence — neither page mentions timestamps.
Model: assert atime/mtime/ctime unchanged across fsync/fdatasync.

---

## 8. XSH 2.9.7 — atomicity/serialization (background)

**R52. Issue 8 "Thread Interactions with File Operations" (retitled from
Issue 7's "... with Regular File Operations"; scope broadened to "files in
the file hierarchy").** Two normative lists, both with the same all-or-none
rule. Path-based list: "All of the following functions shall be atomic with
respect to each other in the effects specified in POSIX.1-2024 when they
operate on files in the file hierarchy: chmod(), chown(), creat(),
fchmod(), fchmodat(), fchown(), fchownat(), fstat(), fstatat(), ftruncate(),
futimens(), lchown(), link(), linkat(), lstat(), open(), openat(),
readlink(), readlinkat(), rename(), renameat(), stat(), symlink(),
symlinkat(), truncate(), unlink(), unlinkat(), utimensat(), utimes()".
Fd-based list: "Except where specified otherwise, all of the following
functions shall be atomic with respect to each other in the effects
specified in POSIX.1-2024 when they operate on file descriptors that are
open, or being opened, to files in the file hierarchy: close(), dup2(),
dup3(), fcntl(), fstat(), fstatat(), ftruncate(), futimens(), lseek(),
open(), openat(), pread(), read(), readv(), pwrite(), write(), writev()".
The rule (verbatim, appears after each list): "If two threads each call one
of these functions, each call shall either see all of the specified effects
of the other call, or none of them."
So per POSIX 2024, two concurrent write()s to a regular file serialize:
each sees all-or-none of the other (no byte interleaving of the specified
effects), and a read concurrent with a write sees all-or-none of it.
Stated in terms of "two threads"; the section does not spell out
cross-process applicability in the quoted text (commonly read as applying
whenever the operations act on the same file — UNVERIFIED beyond the quote).
Model: background only — a single-threaded harness never exercises it; keep
as documentation for why no interleaving states are modeled.

---

## 9. Record locks vs. plain read/write

**R53. fcntl record locks are advisory: they do not gate read()/write().**
Requirement: by construction — the read() and write() ERRORS sections
(fetched in full) contain no record-lock-related errno at all; only
cooperating lockers are affected. Citation: fcntl() RATIONALE: "For advisory
file record locking to be effective, all processes that have access to a
file must cooperate and use the advisory mechanism before doing I/O on the
file. Enforcement-mode record locking is important when it cannot be assumed
that all processes are cooperating." Lock conflict is reported only to
fcntl callers, as acceptance-set{EACCES, EAGAIN}: "[EACCES] or [EAGAIN] The
cmd argument is F_SETLK, the type of lock (l_type) is a shared (F_RDLCK) or
exclusive (F_WRLCK) lock, and the requested lock cannot be set because it is
blocked by an existing lock on the file." Lock lifetime: "All process-owned
locks associated with a file for a given process shall be removed when any
file descriptor for that file is closed by that process (even if via a
different open file description) or the process holding that file descriptor
terminates."
Linux-divergence: Linux historically offered opt-in mandatory locking
(mount -o mand + setgid/no-group-exec mode), removed around kernel 5.15
(memory, UNVERIFIED); irrelevant on default mounts.
Model: locks held by other processes have zero effect on modeled
read/write/truncate transitions — no lock state needed in the I/O model.

---

## Testing notes

- Oracle for a regular file: state = (byteMap default-0, size, per-OFD
  offset, per-OFD status flags {O_APPEND, access mode}). Every rule above is
  a pure function of that state; timestamps are three "marked" booleans
  compared with >= against snapshots (R7, R17, R43 deferral caveat).
- Highest-value probes for an NFS-backed VFS: (a) hole creation via
  lseek-past-EOF-then-write and via truncate-extend, then byte-exact readback
  of the zero gap (R5, R13, R37); (b) truncate-to-same-size must still mark
  mtime+ctime (R43) — a known implementation shortcut; (c) O_APPEND write
  after an explicit lseek to 0 must land at EOF and reset the shared offset
  (R14); (d) read at exactly EOF returns 0 yet still marks atime (R3 + R7
  RATIONALE quote); (e) shrink below an fd's offset, then read (→0) and
  write (→ re-extend with hole) without any intervening lseek (R42).
- Error-path assertions should always include "state unchanged": POSIX
  explicitly pins this for lseek (R29), pread/pwrite EINVAL (R24), and
  writev (R47); for the rest it's the sensible reading but not always
  spelled per-call.
- nbyte == 0 calls: assert retval 0 AND no timestamp marks (R1, R7, R16,
  R17) — cheap and frequently wrong in servers that mark times before
  checking the count.
- Acceptance sets to encode, not single errnos: ftruncate-not-writable
  {EBADF, EINVAL} (R39); length-too-big {EFBIG, EINVAL} (R44); F_SETLK
  conflict {EACCES, EAGAIN} (R53); read-directory {EISDIR, success} (R9).
- Do not assert atime deltas on Linux NFS/relatime mounts without checking
  mount options (R7 note).

## Traps

- "Mark for update" is not "update now": XBD file-times semantics let the
  timestamp materialize later; comparing for strict inequality immediately
  after the call can produce false failures on coarse clocks — use snapshot
  ordering plus a stat to force materialization.
- The zero-fill-gap language is NOT on the write() page — it is on lseek()
  and read(); if you diff spec pages, don't conclude gaps are unspecified.
- pwrite + O_APPEND: POSIX 2024 is explicit ("regardless of whether
  O_APPEND is set") but Linux appends — the single biggest known divergence
  in this topic; never generate that combination unless testing for it
  deliberately (R23).
- ftruncate has no EISDIR and truncate has no EBADF: the two functions'
  error namespaces differ although the operation is "the same" (R39–R41).
- lseek EBADF only needs an open fd — a write-only fd may lseek and a
  read-only fd may lseek past EOF; only the subsequent I/O fails (R32 vs
  R8/R18).
- read() at EOF returning 0 is success and STILL marks atime; a model that
  keys timestamp marking on "bytes transferred > 0" instead of "nbyte > 0"
  is wrong (R7).
- Short read/write clauses are "may be less ... if" enumerations, not
  guarantees of fullness; hard-failing on a short op is technically stricter
  than the letter of the spec — log-and-continue is the defensible harness
  policy (R4, R15).
- XSH 2.9.7 changed between issues: Issue 7 title "Thread Interactions with
  Regular File Operations" / scope "regular files or symbolic links";
  Issue 8 title "Thread Interactions with File Operations" / scope "files in
  the file hierarchy", with the function set split into path-based and
  fd-based lists — cite the Issue 8 form (R52).
- fsync's guarantee floor is a "null implementation" (RATIONALE): a
  no-crash model must treat fsync/fdatasync success as carrying zero
  observable state meaning (R48).
- truncate()/ftruncate() may clear S_ISUID/S_ISGID ("may be cleared") — if
  the model ever tracks mode bits, that's an acceptance set, not a MUST
  (R43).
