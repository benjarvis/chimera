<!--
SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors

SPDX-License-Identifier: LGPL-2.1-only
-->

# POSIX rule inventory: file descriptors, open file descriptions, dup/dup2, fcntl locks, lockf

Source of truth: **POSIX.1-2024 (Issue 8), IEEE Std 1003.1-2024**, The Open Group Base
Specifications Issue 8, verified against the live HTML at
`https://pubs.opengroup.org/onlinepubs/9799919799/` on 2026-08-09 (pages fetched raw and
quoted verbatim; no fallback to Issue 7 was needed). Pages used:

- XBD Definitions: `basedefs/V1_chap03.html` (cited as "XBD 3.nnn")
- XSH General Information: `functions/V2_chap02.html` (cited as "XSH 2.n")
- `functions/open.html`, `functions/dup.html`, `functions/close.html`,
  `functions/fcntl.html`, `functions/lockf.html` (cited as "open()", "dup()", ...)

Issue 8 notes that matter for this inventory:
- Issue 8 renamed classic fcntl record locks to **"process-owned file locks"** and added
  **"OFD-owned file locks"** (`F_OFD_GETLK`/`F_OFD_SETLK`/`F_OFD_SETLKW`, Austin Group
  defects 768/1671). Older Issue 7 wording "all outstanding record locks owned by the
  process" no longer appears; the equivalent Issue 8 text is quoted at R40.
- Issue 8 added `FD_CLOFORK`, `F_DUPFD_CLOFORK`, `dup3()`, and `posix_close()`.

Requirement-level vocabulary used below:
- **MUST** — "shall" text.
- **acceptance-set{A,B}** — spec permits either; a conforming test must accept both.
- **unspecified / implementation-defined / MAY** — as in XBD.
- **UNVERIFIED** — could not be confirmed from fetched spec text.

---

## A. The two-level model: fd -> open file description -> file

**R1.** A file descriptor is a per-process integer naming an open file.
- Requirement: MUST (definition).
- Citation: XBD 3.141 File Descriptor — "A per-process unique, non-negative integer used
  to identify an open file for the purpose of file access. ... The value of a
  newly-created file descriptor is from zero to {OPEN_MAX}-1."
- Model: fd table is a per-process partial map `int -> descriptionId`, domain bounded by
  OPEN_MAX.

**R2.** The open file description is a separate object; many fds may refer to one
description; each fd refers to exactly one.
- Requirement: MUST (definition).
- Citation: XBD 3.241 Open File Description — "A record of how a process or group of
  processes is accessing a file. Each file descriptor refers to exactly one open file
  description, but an open file description can be referred to by more than one file
  descriptor. The file offset, file status, and file access modes are attributes of an
  open file description."
- Model: three-level state: `fdTable: (proc, int) -> ofdId`, `ofd: ofdId -> {offset,
  statusFlags, accessMode, fileId}`, `file: fileId -> {...}`.

**R3.** The file offset lives in the open file description, not in the fd, and exists for
regular files, block special files, and directories.
- Requirement: MUST (definition).
- Citation: XBD 3.148 File Offset — "The byte position in the file where the next I/O
  operation begins. Each open file description associated with a regular file, block
  special file, or directory has a file offset. ... There is no file offset specified for
  a pipe or FIFO."
- Model: `offset` is a field of the description record only.

**R4.** Every successful open() creates a NEW open file description, never shared with any
existing fd; independent open() calls on the same file therefore have independent offsets
and status flags.
- Requirement: MUST.
- Citation: open() DESCRIPTION — "It shall create an open file description that refers to
  a file and a file descriptor that refers to that open file description. ... The open
  file description is new, and therefore the file descriptor shall not share it with any
  other process in the system." Also "The file offset used to mark the current position
  within the file shall be set to the beginning of the file." and "The file status flags
  and file access modes of the open file description shall be set according to the value
  of oflag."
- Model: `open` allocates fresh ofdId with offset=0; two opens of one file never alias.

**R5.** The ONLY per-fd state is the file descriptor flags: FD_CLOEXEC and (Issue 8)
FD_CLOFORK. They do not propagate to other fds on the same description.
- Requirement: MUST.
- Citation: fcntl() F_GETFD — "File descriptor flags are associated with a single file
  descriptor and do not affect other file descriptors that refer to the same file."
- Model: `fdFlags: (proc, int) -> {cloexec, clofork}` beside the ofdId mapping; nothing
  else is per-fd.

**R6.** File status flags and access modes are per-description: shared by dup'd fds,
independent between separate opens.
- Requirement: MUST.
- Citation: fcntl() F_GETFL — "File status flags and file access modes are associated
  with the file description and do not affect other file descriptors that refer to the
  same file with different open file descriptions."
- Model: F_SETFL through one dup'd fd is observable via F_GETFL on the other.

**R7.** dup family fds SHARE the open file description (and its locks); an lseek/read/
write through one fd moves the offset seen by the other.
- Requirement: MUST.
- Citation: fcntl() F_DUPFD — "The new file descriptor shall refer to the same open file
  description as the original file descriptor, and shall share any locks." dup() —
  "The dup2() function shall cause the file descriptor fildes2 to refer to the same open
  file description as the file descriptor fildes and to share any locks". Offset sharing
  follows from XBD 3.241 ("The file offset ... [is an] attribute[] of an open file
  description") — the spec states offset visibility by putting the offset in the shared
  object, not by a separate sentence.
- Citation (handles): XSH 2.5.1 — "An open file description may be accessed through a
  file descriptor ... or through a stream ... an open file description may have several
  handles."
- Model: dup copies only the fd-table entry (ofdId); offset/status-flag mutations act on
  the shared ofd record.

**R8.** File descriptor allocation (open, dup, F_DUPFD base rule): the lowest numbered
available fd is allocated, atomically.
- Requirement: MUST.
- Citation: XSH 2.6 File Descriptor Allocation — "All functions that open one or more
  file descriptors shall, unless specified otherwise, atomically allocate the lowest
  numbered available (that is, not already open in the calling process) file descriptor
  at the time of each allocation."
- Model: `newFd = min(k : k not in dom(fdTable[proc]))`; this is a strong, testable
  determinism guarantee.

---

## B. dup()

**R9.** dup(fildes) is exactly fcntl(fildes, F_DUPFD, 0).
- Requirement: MUST.
- Citation: dup() — "The call dup(fildes) shall be equivalent to: fcntl(fildes,
  F_DUPFD, 0);"
- Model: define one primitive `dupfd(fd, minfd)`; dup = dupfd(fd, 0).

**R10.** dup returns the lowest available fd (>= 0), per R8/R9.
- Requirement: MUST.
- Citation: fcntl() F_DUPFD — "shall be allocated as described in 2.6 File Descriptor
  Allocation, except that it shall be the lowest numbered available file descriptor
  greater than or equal to the third argument, arg".
- Model: deterministic result value; assert exact fd number in tests.

**R11.** The new fd from dup/F_DUPFD has FD_CLOEXEC and FD_CLOFORK cleared.
- Requirement: MUST.
- Citation: fcntl() F_DUPFD — "The FD_CLOEXEC and FD_CLOFORK flags associated with the
  new file descriptor shall be cleared."
- Model: fdFlags(newFd) = {false,false} regardless of source fd's flags.

**R12.** dup() errors: EBADF for invalid source fd; EMFILE when the fd table is full.
- Requirement: MUST (as "shall fail if" conditions); the EMFILE condition is abstract —
  "available to the process" is bounded by {OPEN_MAX}, whose value is
  implementation-defined (and may change at runtime, XBD 3.141).
- Errnos: EBADF, EMFILE.
- Citation: dup() ERRORS — "[EBADF] The fildes argument is not a valid open file
  descriptor. [EMFILE] All file descriptors available to the process are currently
  open."
- Model: parameterize OPEN_MAX small (e.g. 6-8) so EMFILE is reachable in the model;
  treat the real limit as symbolic in tests.

---

## C. dup2()

**R13.** dup2(fildes, fildes2) makes fildes2 refer to the same description as fildes,
sharing locks, and returns fildes2.
- Requirement: MUST.
- Citation: dup() — "The dup2() function shall cause the file descriptor fildes2 to
  refer to the same open file description as the file descriptor fildes and to share any
  locks, and shall return fildes2."
- Model: fdTable[fildes2] := fdTable[fildes]; return fildes2.

**R14.** If fildes2 is already open, dup2 closes it first. The spec does not restate
close()'s side effects inline, but close()'s RATIONALE explicitly classifies dup2 as an
implicit close, and the lock-drop rule (R40) triggers on ANY close of ANY fd for the
file by the process — so dup2's implicit close DOES drop the process's process-owned
locks on the file that old fildes2 referred to.
- Requirement: MUST (by composition of quoted texts; the composition itself is an
  inference, flagged here, but there is no carve-out text exempting dup2).
- Citation: dup() — "If fildes2 is already a valid open file descriptor, it shall be
  closed first, unless fildes is equal to fildes2". close() RATIONALE — "the implicit
  closes of file descriptors, such as by exec, process termination, or dup2()". fcntl()
  — see R40 quote ("when any file descriptor for that file is closed by that process").
- Model: implement dup2 as close(fildes2) [with lock-drop] then bind; also decrement the
  old description's refcount (R43).

**R15.** dup2(fd, fd) with a valid fd returns fd WITHOUT closing it (locks survive,
FD_CLOEXEC/FD_CLOFORK unchanged).
- Requirement: MUST.
- Citation: dup() — "unless fildes is equal to fildes2 in which case dup2() shall
  return fildes2 without closing it." and "If fildes is equal to fildes2, the
  FD_CLOEXEC and FD_CLOFORK flags associated with fildes2 shall not be changed."
- Model: guard `fildes == fildes2` -> pure no-op returning fildes2 (fildes must still be
  valid, else R17).

**R16.** On success with fildes != fildes2, the new fildes2 has FD_CLOEXEC and FD_CLOFORK
cleared.
- Requirement: MUST.
- Citation: dup() — "Upon successful completion, if fildes is not equal to fildes2, the
  FD_CLOEXEC and FD_CLOFORK flags associated with fildes2 shall be cleared."
- Model: same as R11 for the target slot.

**R17.** dup2 EBADF: invalid fildes, or fildes2 out of range [0, OPEN_MAX). An invalid
fildes never closes fildes2. Whether fildes2 currently refers to an open file is
IRRELEVANT to validity.
- Requirement: MUST.
- Errno: EBADF.
- Citation: dup() — "If fildes is not a valid file descriptor, dup2() shall return -1
  and shall not close fildes2. If fildes2 is less than 0 or greater than or equal to
  {OPEN_MAX}, dup2() shall return -1 with errno set to [EBADF]." RATIONALE — "the only
  kind of invalidity that is relevant for fildes2 is whether it is out of range; that
  is, it does not matter whether fildes2 refers to an open file when the dup2() call is
  made."
- Model: validate fildes first, then fildes2 range; closed-but-in-range fildes2 is fine.

**R18.** If the implicit close of fildes2 fails, dup2 returns -1 and fildes2 keeps its
OLD description (may fail with EIO).
- Requirement: MUST for the no-change outcome; EIO is "may fail".
- Errnos: EIO (may).
- Citation: dup() — "If the close operation fails to close fildes2, dup2() shall
  return -1 without changing the open file description to which fildes2 refers." ERRORS —
  "may fail if: [EIO] An I/O error occurred while attempting to close fildes2."
- Model: only worth modeling if you model close failures at all; otherwise omit.

**R19.** dup2 remaining errors: EINTR is in the "shall fail" list (signal interruption).
dup2 has NO EMFILE case (target slot is named, not allocated).
- Requirement: MUST (as listed conditions).
- Errnos: EBADF, EINTR (shall); EIO (may).
- Citation: dup() ERRORS — "The dup2() and dup3() functions shall fail if: [EBADF] ...
  [EINTR] The function was interrupted by a signal."
- Model: omit EINTR unless modeling signals; assert dup2 never yields EMFILE.

**R20.** dup3() is dup2 plus: equal fds are an error (EINVAL), and O_CLOEXEC/O_CLOFORK in
flag atomically set the fd flags on fildes2.
- Requirement: MUST; invalid flag is "may fail" EINVAL.
- Errnos: EINVAL (equal fds — shall; bad flag — may), plus R17/R19 set.
- Citation: dup() — "it shall be an error if fildes is equal to fildes2, and the state of
  FD_CLOEXEC and FD_CLOFORK on the fildes2 file descriptor shall be determined solely by
  the flag argument"; ERRORS — "[EINVAL] The fildes and fildes2 arguments are equal."
- Model: optional; include only if the model tracks cloexec/clofork.

---

## D. fcntl F_DUPFD / F_GETFL / F_SETFL

**R21.** F_DUPFD returns the lowest available fd >= arg, sharing description and locks
(quotes at R7/R10). arg out of [0, OPEN_MAX) is EINVAL (contrast dup2's EBADF, R17); no
free fd >= arg is EMFILE.
- Requirement: MUST.
- Errnos: EBADF (bad fildes), EINVAL, EMFILE.
- Citation: fcntl() ERRORS — "[EINVAL] ... the cmd argument is F_DUPFD, F_DUPFD_CLOEXEC,
  or F_DUPFD_CLOFORK and arg is negative or is greater than or equal to {OPEN_MAX}";
  "[EMFILE] The argument cmd is F_DUPFD ... and all file descriptors available to the
  process are currently open, or no file descriptors greater than or equal to arg are
  available."
- Model: the EINVAL-vs-EBADF asymmetry between F_DUPFD and dup2 is a cheap high-value
  test.

**R22.** F_GETFL returns file status flags + access mode of the DESCRIPTION; access mode
extracted with O_ACCMODE. Extra nonstandard flags may appear in the result.
- Requirement: MUST; extra flags permitted ("may include").
- Citation: fcntl() F_GETFL — "Get the file status flags and file access modes ... for
  the file description associated with fildes. The file access modes can be extracted
  from the return value using the mask O_ACCMODE ... The flags returned may include
  non-standard file status flags which the application did not set".
- Model: compare `result & (O_APPEND|O_NONBLOCK|O_ACCMODE)` only; never full equality.

**R23.** F_SETFL sets file status flags on the description. Access-mode bits and
file-creation-flag bits in arg are IGNORED (access mode is read-only for the life of the
description). Changing bits other than file status flags is unspecified; O_NONBLOCK may
be ignored if unsupported by the file.
- Requirement: MUST (ignore rule); unspecified (other bits); unspecified (O_NONBLOCK on
  non-supporting fildes).
- Citation: fcntl() F_SETFL — "Set the file status flags ... Bits corresponding to the
  file access mode and the file creation flags ... that are set in arg shall be ignored.
  If any bits in arg other than those mentioned here are changed by the application, the
  result is unspecified. If fildes does not support non-blocking operations, it is
  unspecified whether the O_NONBLOCK flag will be ignored."
- Model: model status flags as {O_APPEND, O_NONBLOCK} on the ofd; F_SETFL replaces that
  set from arg; access mode immutable after open. (POSIX status flags also include
  O_SYNC/O_DSYNC/O_RSYNC — out of scope for an offset/lock model.)
- Linux-divergence: on Linux, F_SETFL additionally ignores O_DSYNC/O_SYNC changes
  (cannot be changed after open); POSIX would treat flipping them as a status-flag set.

**R24.** F_SETFL through one dup'd fd is visible via F_GETFL through the other (corollary
of R6/R7).
- Requirement: MUST.
- Citation: fcntl() F_GETFL quote at R6.
- Model: turning O_APPEND on via dup'd fd changes write behavior on both fds — good
  NAS-stressing scenario.

---

## E. fcntl record locks (process-owned; the classic F_GETLK/F_SETLK/F_SETLKW)

**R25.** Record locking is ADVISORY and shall be supported for regular files (may be for
others). Advisory means it constrains only other lock requests, not read()/write().
- Requirement: MUST (regular files); MAY (other files). No mandatory locking exists in
  POSIX.
- Citation: fcntl() — "The following values for cmd are available for advisory record
  locking. Record locking shall be supported for regular files, and may be supported for
  other files." RATIONALE — "Mandatory locks were omitted for several reasons".
- Model: locks are a separate relation; read/write transitions never consult it.

**R26.** struct flock fields: l_type (F_RDLCK/F_WRLCK/F_UNLCK), l_whence
(SEEK_SET/SEEK_CUR/SEEK_END), l_start, l_len, l_pid. On input l_pid is ignored for
F_GETLK/F_SETLK/F_SETLKW.
- Requirement: MUST.
- Citation: fcntl() — "The structure flock describes the type (l_type), starting offset
  (l_whence), relative offset (l_start), size (l_len), and process ID (l_pid) ... The
  value of l_whence is SEEK_SET, SEEK_CUR, or SEEK_END, to indicate that the relative
  offset l_start bytes shall be measured from the start of the file, current position,
  or end of the file, respectively. ... On input, the l_pid field shall be ignored for
  F_GETLK, F_SETLK and F_SETLKW".
- Model: normalize (whence,start,len) to an absolute byte interval at operation time.

**R27.** Positive l_len locks [l_start, l_start+l_len-1] (absolute, after whence
resolution).
- Requirement: MUST.
- Citation: fcntl() — "If l_len is positive, the area affected shall start at l_start
  and end at l_start+l_len-1."
- Model: closed interval [S, S+L-1].

**R28.** Negative l_len locks [l_start+l_len, l_start-1] — the bytes BEFORE l_start.
- Requirement: MUST (negative l_len must be accepted where off_t is signed — always in
  practice).
- Citation: fcntl() — "The value of l_len may be negative (where the definition of off_t
  permits negative values of l_len). ... If l_len is negative, the area affected shall
  start at l_start+l_len and end at l_start-1."
- Model: canonicalize to [S+L, S-1] before all other logic.

**R29.** A lock range must not extend before byte 0; a request that would is invalid. The
errno is EINVAL via the generic "data pointed to by arg is not valid" bucket (the spec
has no dedicated negative-start errno sentence).
- Requirement: MUST (the "shall not extend" text); errno mapping EINVAL is the only
  fitting listed error (inference flagged).
- Errno: EINVAL.
- Citation: fcntl() — "Locks may start and extend beyond the current end of a file, but
  shall not extend before the beginning of the file." ERRORS — "[EINVAL] ... the cmd
  argument is F_GETLK, F_SETLK, F_SETLKW ... and the data pointed to by arg is not
  valid, or fildes refers to a file that does not support locking."
- Model: reject any canonical interval with start < 0 with EINVAL.

**R30.** l_len == 0 means from l_start to the largest possible offset (present AND future
EOF); l_start=0/SEEK_SET/l_len=0 locks the whole file.
- Requirement: MUST.
- Citation: fcntl() — "A lock shall be set to extend to the largest possible value of
  the file offset for that file by setting l_len to 0. If such a lock also has l_start
  set to 0 and l_whence is set to SEEK_SET, the whole file shall be locked."
- Model: represent as half-open [S, INF); INF must compare beyond any file size.

**R31.** Locks may start and extend beyond current EOF (no allocation needed).
- Requirement: MUST.
- Citation: fcntl() — "Locks may start and extend beyond the current end of a file"
  (also lockf(): "An area need not be allocated to the file to be locked because locks
  may exist past the end-of-file.").
- Model: lock intervals are independent of file size; do NOT clamp to EOF.

**R32.** SEEK_CUR/SEEK_END are resolved at call time; fcntl locking never MODIFIES the
file offset. For a blocking F_SETLKW the byte range is fixed BEFORE blocking; later
offset or file-size changes do not move it.
- Requirement: MUST.
- Citation: fcntl() — "If the command is F_SETLKW or F_OFD_SETLKW and the thread needs
  to wait for a blocking lock to be released, then the range of bytes to be locked shall
  be determined before the fcntl() function blocks. If the file size or file descriptor
  seek offset change while fcntl() is blocked, this shall not affect the range of bytes
  locked." (No text anywhere gives fcntl locking an offset side-effect.)
- Model: snapshot offset/size into the absolute interval in the request action; blocked
  requests carry the resolved interval, not the flock struct.

**R33.** The lock OWNER for F_SETLK/F_SETLKW/F_GETLK is the PROCESS ("process-owned file
lock"); conflicts are evaluated against locks of OTHER processes (and, in Issue 8,
against OFD-owned locks of ANY description including fildes' own).
- Requirement: MUST.
- Citation: fcntl() — "Set or clear a process-owned file lock ..." (F_SETLK); "An
  F_SETLK or an F_SETLKW request (respectively) shall fail or block when another process
  has existing process-owned locks, or any open file description (including the one
  associated with fildes) has existing OFD-owned locks, on bytes in the specified region
  and any of those locks conflicts with the requested lock."
- Model: lock record = (fileId, ownerPid, type, interval). Which fd or description
  created it is irrelevant for process-owned lock identity.

**R34.** A process's new lock REPLACES its own existing lock(s) byte-for-byte over the
requested region — same-owner locks never conflict; this yields merge, downgrade,
upgrade, and split behavior.
- Requirement: MUST.
- Citation: fcntl() — "Before a successful return from an F_SETLK or an F_SETLKW request
  when the calling process has previously existing process-owned locks on bytes in the
  region specified by the request, the previous shared or exclusive lock for each byte
  in the specified region shall be replaced by the new shared or exclusive lock."
- Model: model per-byte (or normalized interval-set) ownership: apply = remove owner's
  coverage over the interval, then insert the new type over the interval. Splitting
  (RATIONALE: "Changing of lock types can result in a previously locked region being
  split into smaller regions.") falls out automatically.

**R35.** Conflict matrix: each byte holds either one or more SHARED locks or exactly one
EXCLUSIVE lock. Shared blocks other processes' exclusive; exclusive blocks other
processes' shared and exclusive; shared+shared coexist.
- Requirement: MUST.
- Citation: fcntl() — "Each byte in the file can be locked either with one or more
  shared locks (F_RDLCK) or with one exclusive lock (F_WRLCK)."; "When a shared lock is
  set on a segment of a file, other processes can set shared process-owned locks ... A
  shared process-owned lock shall prevent any other process from setting an exclusive
  process-owned lock ... An exclusive process-owned lock shall prevent any other process
  from setting a shared or exclusive process-owned lock ... on any portion of the
  protected area."
- Model: conflict(a,b) = overlap(a.interval, b.interval) && a.owner != b.owner &&
  (a.type == WR || b.type == WR).

**R36.** Permission gating by fd access mode: F_RDLCK requires the fd open for reading;
F_WRLCK requires the fd open for writing; violation is EBADF.
- Requirement: MUST.
- Errno: EBADF.
- Citation: fcntl() — "A request for a shared lock shall fail if the file descriptor is
  not open for reading. ... A request for an exclusive lock shall fail if the file
  descriptor is not open for writing." ERRORS — "[EBADF] ... the argument cmd is
  F_SETLK, F_SETLKW, F_OFD_SETLK, or F_OFD_SETLKW, the type of lock, l_type, is a shared
  lock (F_RDLCK), and fildes is not a valid file descriptor open for reading, or the
  type of lock, l_type, is an exclusive lock (F_WRLCK), and fildes is not a valid file
  descriptor open for writing."
- Model: check ofd.accessMode: F_RDLCK needs O_RDONLY|O_RDWR; F_WRLCK needs
  O_WRONLY|O_RDWR. Note F_UNLCK has NO access-mode requirement in the spec.

**R37.** F_SETLK is non-blocking: on conflict it fails immediately with EACCES OR EAGAIN
— an acceptance set; a portable test must accept either.
- Requirement: acceptance-set{EACCES, EAGAIN}.
- Citation: fcntl() F_SETLK — "If a shared or exclusive lock cannot be set, fcntl()
  shall return immediately with a return value of -1." ERRORS — "The fcntl() function
  shall fail if: [EACCES] or [EAGAIN] The cmd argument is F_SETLK, the type of lock
  (l_type) is a shared (F_RDLCK) or exclusive (F_WRLCK) lock, and the requested lock
  cannot be set because it is blocked by an existing lock on the file." The spec's own
  EXAMPLES section checks `errno == EACCES || errno == EAGAIN`.
- Model: nondeterministic errno choice, or a single abstract WOULD_BLOCK result mapped to
  {EACCES,EAGAIN} at the test adapter.
- Linux-divergence: Linux returns EAGAIN (EACCES only on some other unices); do not bake
  EAGAIN into the model as the sole answer.
- Note: F_OFD_SETLK conflict is EAGAIN only (no EACCES alternative) — separate ERRORS
  entry: "[EAGAIN] The cmd argument is F_OFD_SETLK ...".

**R38.** F_SETLKW blocks until grantable; a caught signal interrupts it with EINTR and the
lock is NOT taken. Deadlock DETECTION is optional; IF the system detects one it shall
fail with EDEADLK (EDEADLK is under "may fail").
- Requirement: MUST (block, EINTR semantics); implementation-optional detection —
  EDEADLK listed under "The fcntl() function may fail if".
- Errnos: EINTR (shall, on interrupt); EDEADLK (may).
- Citation: fcntl() F_SETLKW — "if a shared or exclusive lock is blocked by other locks,
  the thread shall wait until the request can be satisfied. ... Upon return from the
  signal handler, fcntl() shall return -1 with errno set to [EINTR], and the lock
  operation shall not be done." Deadlock — "If the system detects that sleeping until a
  locked region is unlocked would cause a deadlock, fcntl() shall fail with an [EDEADLK]
  error." RATIONALE — "Since implementation of full deadlock detection is not always
  feasible, the [EDEADLK] error was made optional."
- Model: model F_SETLKW as a pending-request queue; accept either EDEADLK or permanent
  blocking on a cycle (acceptance-set{EDEADLK, blocks-forever}). Fairness/ordering of
  wakeups among multiple blocked requesters is NOT specified — do not assert FIFO grant.

**R39.** F_GETLK reports ANY lock that would block the described lock — not required to
be the first/lowest one. If none would block, only l_type is changed, to F_UNLCK. When a
blocking lock is reported: l_whence=SEEK_SET, l_start/l_len describe the blocking lock,
l_pid is the holder's pid (or (pid_t)-1 for an OFD-owned blocking lock). F_GETLK does not
create or remove locks.
- Requirement: MUST (the reporting contract); WHICH blocking lock is reported is
  effectively unspecified ("any").
- Citation: fcntl() F_GETLK — "Get any lock which blocks the process-owned file lock
  description pointed to by the third argument ... If no lock is found that would
  prevent this lock from being created, then the structure shall be left unchanged
  except for the lock type in l_type which shall be set to F_UNLCK." Returned values —
  "l_whence: SEEK_SET. l_start: Start of the blocking lock. l_len: Length of the
  blocking lock. l_pid: Process ID of the process that holds the blocking lock if the
  blocking lock is a process-owned file lock, or (pid_t)-1 if the blocking lock is an
  OFD-owned file lock."
- Model: F_GETLK result = nondeterministic choice from the set of conflicting locks
  (test as membership check), else F_UNLCK. Caller's own process-owned locks are never
  "blocking" (they would be replaced per R34).
- Linux-divergence: Linux F_GETLK across NFS/OFD interplay historically reports l_pid=-1
  for OFD locks (matches Issue 8) but older kernels/filesystems reported bogus pids for
  remote locks.

**R40.** THE CLOSE TRAP: ALL process-owned locks a process holds on a file are dropped
when the process closes ANY fd for that file — even an fd from a completely different
open file description that never took the lock.
- Requirement: MUST.
- Citation: fcntl() — "All process-owned locks associated with a file for a given
  process shall be removed when any file descriptor for that file is closed by that
  process (even if via a different open file description) or the process holding that
  file descriptor terminates." close() — "All process-owned file locks that the calling
  process owns on the file associated with the file descriptor shall be unlocked."
  fcntl() RATIONALE — "closing any file descriptor for a given file (whether or not it
  is the same open file description that created the lock) causes the locks on that file
  to be relinquished for that process. Equivalently, any close for any file/process pair
  relinquishes the locks owned on that file for that process."
- Model: close(proc, fd): let f = file(ofd(fd)); remove ALL lock records with
  (owner=proc, file=f); then release the fd; then free the ofd if last ref (R43).
  This applies to IMPLICIT closes too: dup2's close-first (R14), exec with FD_CLOEXEC,
  process termination.

**R41.** Locks are NOT inherited across fork() by the child; they ARE retained across
exec (same process). dup within a process does not create new locks or a new owner —
"share any locks" (R7/R13) — so both dup'd fds see the same lock state, and closing
EITHER one drops all the process's locks on the file (R40).
- Requirement: MUST (no fork inheritance); exec retention is RATIONALE-stated
  ("may be inherited through one of the exec functions") — the normative basis is that
  the process (owner) is unchanged, and exec does not close non-FD_CLOEXEC fds.
- Citation: fcntl() — "Process-owned locks shall not be inherited by a child process."
  RATIONALE — "while an open file description may be shared through fork(), locks are
  not inherited through fork(). Yet locks may be inherited through one of the exec
  functions."
- Model: fork() copies the fd table (same ofdIds) but copies NO lock records; owner of
  every lock stays the original pid. Note the asymmetry: descriptions are shared with
  the child, locks are not.

**R42.** OFD-owned locks (Issue 8, F_OFD_*): owner is the open file description; removed
only when ALL fds for that description are closed; shared across processes holding the
description; conflict with process-owned locks both ways; replacement semantics apply
per-description. l_pid must be 0 on input.
- Requirement: MUST (where implemented; the F_OFD_* commands are mandatory in Issue 8).
- Citation: fcntl() — "All OFD-owned locks associated with a given open file description
  shall be removed when all file descriptors associated with that open file description
  have been closed ... OFD-owned locks shall be shared across all file descriptors that
  are associated with the owning open file description, regardless of which process
  holds the file descriptor." Conflict — R33 quote ("any open file description
  (including the one associated with fildes) has existing OFD-owned locks").
- Model: phase-2 candidate; if included, lock owner becomes a sum type Pid | OfdId, and
  note the striking corner: a process's own OFD lock on the SAME description can block
  its own process-owned F_SETLK ("including the one associated with fildes").

**R43.** The open file description is freed when its last fd is closed (refcounting is
observable through OFD-lock lifetime and offset sharing).
- Requirement: MUST.
- Citation: close() — "When all file descriptors associated with an open file
  description have been closed, the open file description shall be freed."
- Model: ofd refcount = number of fd-table entries (across all processes) pointing at
  it; free at zero.

**R44.** Unlock (F_UNLCK) removes the requesting process's locks over exactly the
requested segment; unlocking the middle of a lock leaves two locks (split). Special
case: a non-zero-l_len unlock whose last byte is the maximum off_t value, against an
existing l_len==0 lock covering that byte, is treated as an l_len==0 unlock.
- Requirement: MUST.
- Citation: fcntl() — "Otherwise, an unlock (F_UNLCK) request shall attempt to unlock
  only the requested segment." Special case — "An unlock (F_UNLCK) request in which
  l_len is non-zero and the offset of the last byte of the requested segment is the
  maximum value for an object of type off_t, when the process ... has an existing lock
  in which l_len is 0 and which includes the last byte of the requested segment, shall
  be treated as a request to unlock from the start of the requested segment with an
  l_len equal to 0." Splitting is normative via per-byte replacement (R34) and stated
  explicitly for lockf (R53); fcntl RATIONALE: "Changing of lock types can result in a
  previously locked region being split into smaller regions."
- Model: per-byte semantics make split/merge emergent; encode the max-off_t special case
  only if the model has finite off_t.

**R45.** Unlocking bytes that are not locked is NOT an error (F_SETLK/F_UNLCK on an
unlocked range succeeds).
- Requirement: MUST (no error is enumerated for it; "remove either type of lock" with no
  precondition; per-byte replacement of nothing is a no-op).
- Citation: fcntl() F_SETLK — "as well as remove either type of lock (F_UNLCK)". No
  ERRORS entry covers "range was not locked".
- Model: F_UNLCK is idempotent; always succeeds given valid args/fd.

**R46.** Lock-count resource limit: ENOLCK if the lock or unlock would exceed a
system-imposed limit on locked regions (unlock can fail too, because splitting creates
regions).
- Requirement: MUST (as a "shall fail if" condition when the limit exists; the limit
  itself is system-imposed/abstract).
- Errno: ENOLCK.
- Citation: fcntl() ERRORS — "[ENOLCK] The argument cmd is F_SETLK, F_SETLKW,
  F_OFD_SETLK, or F_OFD_SETLKW and satisfying the lock or unlock request would result in
  the number of locked regions in the system exceeding a system-imposed limit."
- Model: omit, or model as an always-possible nondeterministic failure you filter out in
  test verdicts.

**R47.** EINVAL / EOVERFLOW for lock commands: invalid cmd; invalid arg data; file type
that does not support locking; or requested segment's smallest/largest byte offset not
representable in off_t.
- Requirement: MUST.
- Errnos: EINVAL, EOVERFLOW.
- Citation: fcntl() ERRORS — "[EINVAL] The cmd argument is invalid; ... or the cmd
  argument is F_GETLK, F_SETLK, F_SETLKW ... and the data pointed to by arg is not
  valid, or fildes refers to a file that does not support locking."; "[EOVERFLOW] The
  cmd argument is F_GETLK, F_SETLK, F_SETLKW ... and the smallest or, if l_len is
  non-zero, the largest offset of any byte in the requested segment cannot be
  represented correctly in an object of type off_t."
- Model: with finite modeled off_t, EOVERFLOW guards S+L-1 overflow; EINVAL guards bad
  l_type/l_whence and negative resulting start (R29).

---

## F. lockf() (XSI)

**R48.** lockf() places advisory-mode PROCESS-OWNED file locks; commands are F_ULOCK
(unlock), F_LOCK (blocking exclusive lock), F_TLOCK (non-blocking exclusive lock),
F_TEST (probe for other processes' locks).
- Requirement: MUST (lockf is [XSI] shaded — mandatory only with the XSI option).
- Citation: lockf() — "The lockf() function shall lock sections of a file with
  advisory-mode process-owned file locks."; table — "F_ULOCK: Unlock locked sections.
  F_LOCK: Lock a section for exclusive use. F_TLOCK: Test and lock a section for
  exclusive use. F_TEST: Test a section for locks by other processes."
- Model: lockf produces the same kind of lock record as fcntl F_WRLCK in the abstract
  model, EXCEPT see R56 (interaction unspecified).

**R49.** lockf locks are EXCLUSIVE only — there is no shared/read lock via lockf.
- Requirement: MUST (the only lock-establishing commands are "for exclusive use").
- Citation: lockf() — "F_LOCK: Lock a section for exclusive use. F_TLOCK: Test and lock
  a section for exclusive use." (No shared variant exists in the interface.)
- Model: lockf lock type is always WR.

**R50.** lockf lock establishment requires the fd open for WRITING (O_WRONLY or O_RDWR);
otherwise EBADF for F_LOCK/F_TLOCK.
- Requirement: MUST.
- Errno: EBADF.
- Citation: lockf() — "To establish a lock with this function, the file descriptor shall
  be opened with write-only permission (O_WRONLY) or with read/write permission
  (O_RDWR)." ERRORS — "[EBADF] The fildes argument is not a valid open file descriptor;
  or function is F_LOCK or F_TLOCK and fildes is not a valid file descriptor open for
  writing."
- Model: matches fcntl F_WRLCK gating (R36). Spec imposes no access-mode gate on
  F_ULOCK/F_TEST.

**R51.** The section is anchored at the CURRENT FILE OFFSET: positive size locks
[offset, offset+size-1]; NEGATIVE size locks the preceding bytes [offset+size,
offset-1]; size==0 locks [offset, infinity) (present or any future EOF). size + current
offset < 0 is EINVAL.
- Requirement: MUST.
- Errnos: EINVAL (negative resulting start), EOVERFLOW (unrepresentable first/last
  byte).
- Citation: lockf() — "The section to be locked or unlocked starts at the current offset
  in the file and extends forward for a positive size or backward for a negative size
  (the preceding bytes up to but not including the current offset). If size is 0, the
  section from the current offset through the largest possible file offset shall be
  locked (that is, from the current offset through the present or any future
  end-of-file)." ERRORS — "[EINVAL] ... size plus the current file offset is less than
  0."; "[EOVERFLOW] The offset of the first, or if size is not 0 then the last, byte in
  the requested section cannot be represented correctly in an object of type off_t."
- Model: lockf READS ofd.offset (unlike fcntl, which reads it only for SEEK_CUR); it
  never modifies the offset. This couples the lock model to the shared-offset model:
  lseek through a dup'd fd changes what a subsequent lockf on the other fd locks.

**R52.** Same-process overlapping/adjacent lockf sections COMBINE into a single section.
- Requirement: MUST.
- Citation: lockf() — "The sections locked with F_LOCK or F_TLOCK may, in whole or in
  part, contain or be contained by a previously locked section for the same process.
  When this occurs, or if adjacent locked sections would occur, the sections shall be
  combined into a single locked section."
- Model: with per-byte semantics coalescing is unobservable except through lock-count
  limits; note fcntl has NO normative coalescing sentence — only lockf does.

**R53.** F_ULOCK may release wholly or partially; partial release leaves the remainder
locked; releasing the CENTER splits one section into TWO. Splitting can hit the lock
limit and fail.
- Requirement: MUST.
- Citation: lockf() — "When all of a locked section is not released ... the remaining
  portions of that section shall remain locked by the process. Releasing the center
  portion of a locked section shall cause the remaining locked beginning and end
  portions to become two separate locked sections. If the request would cause the number
  of locks in the system to exceed a system-imposed limit, the request shall fail."
  (Same max-off_t l_len==0 special case as fcntl: "An F_ULOCK request in which size is
  non-zero and the offset of the last byte of the requested section is the maximum value
  for an object of type off_t ... shall be treated as a request to unlock from the start
  of the requested section with a size equal to 0.")
- Model: identical unlock semantics to fcntl F_UNLCK over [offset, offset+size).

**R54.** F_LOCK blocks until available; F_TLOCK fails immediately if another process
holds a conflicting lock; F_TEST reports whether another process holds a lock on the
section. F_TLOCK/F_TEST conflict errno is EACCES OR EAGAIN (acceptance set).
- Requirement: MUST; acceptance-set{EACCES, EAGAIN} for the conflict errno.
- Citation: lockf() — "F_LOCK shall block the calling thread until the section is
  available. F_TLOCK shall cause the function to fail if the section is already locked
  by another process."; "F_TEST shall detect if a lock by another process is present on
  the specified section." ERRORS — "[EACCES] or [EAGAIN] The function argument is
  F_TLOCK or F_TEST and the section is already locked by another process."
- Model: F_TEST is a pure predicate (no state change); success means no OTHER process
  holds a conflicting lock (own locks never conflict).
- Linux-divergence: glibc lockf returns EAGAIN for F_TLOCK conflicts and EACCES for
  F_TEST conflicts (maps to fcntl F_SETLK/F_GETLK); accept both everywhere.

**R55.** lockf deadlock and interruption: if the system DETECTS a deadlock for F_LOCK it
shall fail EDEADLK ("shall fail" list, but conditioned on detection — same effective
optionality as fcntl); any signal interrupts blocking (EINTR). On any failure, existing
locks are unchanged.
- Requirement: MUST-if-detected (EDEADLK); MUST (EINTR interruptibility; failure leaves
  locks unchanged).
- Errnos: EDEADLK, EINTR; may-fail: EDEADLK-or-ENOLCK on lock-limit, EAGAIN if file is
  mmap'd, EOPNOTSUPP-or-EINVAL for unsupported file types.
- Citation: lockf() — "If the system detects that deadlock would occur, lockf() shall
  fail with an [EDEADLK] error."; "Blocking on a section shall be interrupted by any
  signal."; RETURN VALUE — "Otherwise, it shall return -1, set errno to indicate an
  error, and existing locks shall not be changed." ERRORS (may fail) — "[EAGAIN] The
  function argument is F_LOCK or F_TLOCK and the file is mapped with mmap().";
  "[EDEADLK] or [ENOLCK] ... the request would cause the number of locks to exceed a
  system-imposed limit."; "[EOPNOTSUPP] or [EINVAL] The implementation does not support
  the locking of files of the type indicated by the fildes argument."
- Model: reuse the fcntl blocking machinery; treat deadlock as
  acceptance-set{EDEADLK, blocks-forever}.

**R56.** The interaction between fcntl() locks and lockf() locks is UNSPECIFIED.
- Requirement: unspecified (both pages, [XSI] shaded on fcntl page).
- Citation: fcntl() — "The interaction between fcntl() and lockf() locks is
  unspecified." lockf() — identical sentence.
- Model: do NOT assert cross-API conflict/replacement outcomes in portable tests.
- Linux-divergence: on Linux/glibc, lockf() is implemented directly on fcntl record
  locks, so the two fully interact (one lock space). A NAS-backed POSIX layer may
  legitimately keep them separate — but if it mimics Linux it must share one lock table.

**R57.** lockf release-on-close and process exit mirror fcntl: first close by the locking
process of ANY fd for the file releases the process's locks; process termination removes
all its locks. Nothing on the lockf page states fork inheritance; the fcntl rule R41
governs (process-owned locks are not inherited).
- Requirement: MUST.
- Citation: lockf() — "Process-owned file locks shall be released on first close by the
  locking process of any file descriptor for the file."; "All the locks for a process
  are removed when the process terminates."
- Model: identical lock-drop hook as R40 — one shared mechanism.

---

## G. EBADF matrix (consolidated)

**R58.** EBADF cases, each MUST, quoted above at the cited rules:

| Call | EBADF condition | Rule |
|---|---|---|
| dup(fd) | fd not a valid open fd | R12 |
| dup2(fd, fd2) | fd not valid open fd; OR fd2 < 0 or fd2 >= OPEN_MAX (fd2 being closed-but-in-range is FINE) | R17 |
| fcntl(fd, ANY) | fd not a valid open fd | fcntl() ERRORS "[EBADF] The fildes argument is not a valid open file descriptor" |
| fcntl(fd, F_SETLK/F_SETLKW, RDLCK) | fd not open for reading | R36 |
| fcntl(fd, F_SETLK/F_SETLKW, WRLCK) | fd not open for writing | R36 |
| close(fd) | fd not an open fd (close() ERRORS: "The fildes argument is not a open file descriptor." [sic]) | R40/close() |
| lockf(fd, any) | fd not a valid open fd | R50 |
| lockf(fd, F_LOCK/F_TLOCK) | fd not open for writing | R50 |

Notes: F_DUPFD's bad-arg-range is EINVAL, not EBADF (R21) — the deliberate asymmetry vs
dup2. F_GETLK and F_UNLCK have NO access-mode EBADF text (only the WRLCK/RDLCK SETLK
cases); a probe with l_type=F_WRLCK via F_GETLK on a read-only fd is not enumerated as
EBADF. lockf F_TEST/F_ULOCK likewise carry no open-for-writing requirement.

---

## Testing notes

- **State to model**: `procs`, `fdTable: (pid, fdnum) -> ofdId (+ per-fd cloexec)`,
  `ofds: ofdId -> {fileId, offset, accessMode, statusFlags, refcount}`,
  `locks: set of {fileId, owner: pid, type: RD|WR, lo, hi(∞)}`, plus a pending-request
  set for F_SETLKW/F_LOCK. Keep OPEN_MAX tiny (6-8) and off_t tiny (e.g. 0..15 with a
  MAX sentinel) so EMFILE/EINVAL/EOVERFLOW and the max-off_t unlock special case (R44)
  are all reachable.
- **Acceptance sets in verdicts**: {EACCES,EAGAIN} for F_SETLK/F_TLOCK/F_TEST conflicts
  (R37, R54); {EDEADLK, blocks} for deadlock (R38, R55); {any conflicting lock} for the
  F_GETLK report (R39). Never assert a single errno for these.
- **Determinism to exploit**: lowest-fd allocation (R8/R10/R21) makes fd numbers fully
  predictable — assert exact values; it doubles as a probe that close/dup2 really freed
  slots.
- **High-yield sequences**:
  1. open, dup, lseek via fd A, write via fd B, check offset via A (R7).
  2. open twice independently, verify offsets do NOT couple (R4).
  3. lock via fd A, close dup'd fd B, verify lock GONE via second process (R40).
  4. lock via ofd1, open second description ofd2 same file, close ofd2's fd, verify
     lock GONE (R40 "even if via a different open file description").
  5. dup2 onto an fd that references the locked file's other description — locks gone
     (R14).
  6. same-process overlap: WR lock [0,9], RD lock [5,14] -> bytes 0-4 WR, 5-14 RD
     (byte-wise replacement, R34); then F_UNLCK [6,8] -> split (R44).
  7. F_SETLKW blocked, then mutate offset/file size, then release the blocker — granted
     range must be the ORIGINAL one (R32, needs SEEK_CUR/SEEK_END whence).
  8. fork: child sees the fds and shared offset but holds NO locks; child F_SETLK
     conflicts against parent's lock (R41).
  9. lockf negative size and fcntl negative l_len around offset 0 -> EINVAL (R29, R51).
  10. lock entirely past EOF succeeds; conflict there is real (R31).
- **Do not test**: cross-API fcntl-vs-lockf interaction (R56, unspecified); F_SETFL of
  bits outside status flags (unspecified); which of several blocking locks F_GETLK
  reports (assert membership only); wakeup ORDER of multiple blocked F_SETLKW callers
  (unspecified — no fairness text).

## Traps

- **THE close-drops-locks trap (R40)**: any close of any fd for the file by the owning
  process nukes ALL of that process's process-owned locks on that file — including
  closes of fds from other descriptions, dup2's implicit close (R14), and FD_CLOEXEC
  closes at exec. Classic real-world bug: a library helper does
  open("/same/file")/read/close and silently destroys the application's locks.
  NAS-backed implementations get this wrong in BOTH directions: (a) dropping locks only
  when the LOCKING description closes (too weak — must be per (process,file)); (b)
  keeping locks alive because the server-side open handle is still cached/open even
  though the client process closed an fd (too strong). NFS NLM/NFSv4 lock-owner models
  (per lock-owner, per open-owner) do not map 1:1 to POSIX per-(process,file) — this is
  exactly where an NFS-backed POSIX layer diverges. Model the drop as an atomic part of
  every close-like transition.
- **The dup-shared-offset trap (R7)**: dup/dup2/F_DUPFD share ONE offset. A NAS/gateway
  layer that materializes a fresh server-side open (fresh offset/state) per fd breaks
  this: lseek on one fd must move the other, F_SETFL O_APPEND on one must affect the
  other, and lockf on one fd locks relative to the offset the OTHER fd just moved
  (R51). Conversely two independent open() calls must NOT share (R4).
- **dup2 is a close (R14)**: its implicit close has full close semantics for lock
  purposes; also remember dup2(fd,fd) closes NOTHING (R15), and fildes2 validity is
  range-only (R17).
- **Owner is the process, not the fd (R33)**: same-process "conflicts" are silent
  byte-wise replacement (R34) — upgrade/downgrade always succeeds locally (modulo
  ENOLCK); implementations that key locks by fd or by description wrongly self-conflict
  or wrongly fail to replace. (OFD-owned locks, keyed by description, are the separate
  Issue 8 facility — R42 — and CAN self-conflict with process-owned locks even on the
  same fd.)
- **errno acceptance sets**: EACCES-or-EAGAIN (R37/R54); Linux says EAGAIN for F_SETLK
  and F_TLOCK but EACCES for lockf F_TEST — a model hardcoding one value fails on a
  conforming platform.
- **EINVAL vs EBADF asymmetry (R21 vs R17)**: F_DUPFD bad range -> EINVAL; dup2 bad
  fildes2 range -> EBADF.
- **F_SETLKW range freezing (R32)**: SEEK_CUR/SEEK_END resolve before blocking; lazy
  re-resolution at grant time is a bug.
- **l_len == 0 is infinite (R30)**, and locks past EOF are legal (R31): clamping ranges
  to file size (a common NAS shortcut) is wrong; the max-off_t unlock special case (R44)
  exists precisely because [start, ∞) can't otherwise be expressed with non-zero l_len.
- **F_GETLK is advisory-by-the-time-you-read-it and reports "any" blocker (R39)** with
  l_pid=-1 when the blocker is OFD-owned — asserting the first/lowest lock or a real pid
  is over-specification.
- **Advisory means invisible to I/O (R25)**: read/write must NOT consult locks. Linux
  removed mandatory locking entirely in kernel 5.15 (Linux-divergence: old
  -o mand mounts no longer exist); POSIX never had it.
- **UNVERIFIED items**: none — every rule above is backed by fetched Issue 8 text; the
  two flagged inferences are the dup2-close/lock-drop composition (R14) and the
  negative-start -> EINVAL errno mapping (R29), where the behavior is normative but the
  spec expresses it across sentences rather than in one quotable line.
