<!--
SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors

SPDX-License-Identifier: LGPL-2.1-only
-->

# POSIX.1-2024 (Issue 8) — Directory Streams Rule Inventory

Source: The Open Group Base Specifications Issue 8 / IEEE Std 1003.1-2024,
fetched 2026-08-09 from https://pubs.opengroup.org/onlinepubs/9799919799/
(pages: functions/opendir.html [covers fdopendir], functions/readdir.html,
functions/rewinddir.html, functions/seekdir.html, functions/telldir.html,
functions/closedir.html, functions/dirfd.html, functions/alphasort.html
[covers scandir], basedefs/V1_chap03.html [XBD definitions]).
Issue 8 was reachable; no Issue 7 fallback was needed. All quotes below were
extracted from the live Issue 8 pages this session; quotes are verbatim as
extracted (minor whitespace/italics markup normalized).

Requirement levels: MUST (POSIX "shall"), MAY-FAIL (POSIX "may fail"
errno), unspecified, undefined, implementation-defined,
acceptance-set{...} (model should accept any listed alternative),
UNVERIFIED (could not confirm against spec text this session).

Convention: "the window" = the interval since the most recent opendir() or
rewinddir() on the stream, per readdir's added/removed-file sentence (R13).

---

## 1. opendir() / fdopendir()

### R1 — opendir creates a stream positioned at the first entry
- Behavior: `opendir(dirname)` opens a directory stream for the named
  directory; the stream starts at the first entry (no implicit skipping).
- Level: MUST.
- Errno: none (success path).
- Cite: opendir.html: "The opendir() function shall open a directory stream
  corresponding to the directory named by the dirname argument. The
  directory stream shall be positioned at the first entry."
- Model: fresh stream state = snapshot cursor at position 0; first readdir
  yields the first entry of the sweep.

### R2 — Permissions: search on prefix components, read on the directory itself
- Behavior: opening requires search (x) permission on every path-prefix
  component and read (r) permission on the target directory. Both failures
  map to the same errno, EACCES.
- Level: MUST (shall fail).
- Errno: EACCES.
- Cite: opendir.html ERRORS: "[EACCES] Search permission is denied for the
  component of the path prefix of dirname or read permission is denied for
  dirname."
- Model: two distinct preconditions (prefix-search, dir-read) with a single
  observable errno EACCES; do not require distinguishing which failed.

### R3 — opendir shall-fail errno matrix
- Behavior: mandatory failures:
  - EACCES — see R2.
  - ELOOP — "A loop exists in symbolic links encountered during resolution
    of the dirname argument."
  - ENAMETOOLONG — "The length of a component of a pathname is longer than
    {NAME_MAX}."
  - ENOENT — "A component of dirname does not name an existing directory or
    dirname is an empty string."
  - ENOTDIR — "A component of dirname names an existing file that is
    neither a directory nor a symbolic link to a directory."
- Level: MUST (shall fail).
- Errno: EACCES, ELOOP, ENAMETOOLONG, ENOENT, ENOTDIR.
- Cite: opendir.html ERRORS, "The opendir() function shall fail if:".
- Model: these are deterministic given path-resolution state; assert exact
  errno when the model can compute the condition.

### R4 — opendir may-fail errno matrix
- Behavior: optional failures: ELOOP (SYMLOOP_MAX exceeded: "More than
  {SYMLOOP_MAX} symbolic links were encountered."), EMFILE ("All file
  descriptors available to the process are currently open."), ENAMETOOLONG
  ({PATH_MAX} form), ENFILE ("Too many files are currently open in the
  system."). Note: no ENOMEM is listed for opendir in Issue 8.
- Level: MAY-FAIL.
- Errno: ELOOP, EMFILE, ENAMETOOLONG, ENFILE.
- Cite: opendir.html ERRORS, "The opendir() function may fail if:".
- Model: treat as environment-induced; success is acceptance-set
  {DIR*, EMFILE, ENFILE} only if the model tracks fd budgets, else assume
  success.

### R5 — opendir's internal descriptor: O_DIRECTORY|O_CLOEXEC, counts toward OPEN_MAX
- Behavior: if the implementation backs the DIR with an fd, that fd is
  allocated "as if the O_DIRECTORY and O_CLOEXEC flags were passed to
  open()" (Issue 8 change: Austin Group Defect 368 added the FD_CLOEXEC
  requirement) and "shall be subject to the limit of {OPEN_MAX} file
  descriptors available to the process."
- Level: MUST (conditional on fd-backed implementation; fd-backing itself
  is an implementation choice — XBD 3.105: "An open directory stream may be
  implemented using a file descriptor.").
- Errno: EMFILE/ENFILE indirectly (R4).
- Cite: opendir.html DESCRIPTION; basedefs V1_chap03.html 3.105.
- Model: each open stream consumes one fd slot; streams are not inherited
  across exec (CLOEXEC).

### R6 — fdopendir: equivalent to opendir; fd must be open FOR READING (not O_SEARCH)
- Behavior: "The fdopendir() function shall be equivalent to the opendir()
  function except that the directory is specified by a file descriptor
  rather than by a name." The Issue 8 page contains no O_SEARCH language at
  all; the mandatory EBADF condition is "The fd argument is not a valid
  file descriptor open for reading." So the fd must have read access mode
  (O_RDONLY or O_RDWR); an O_SEARCH-only descriptor is not "open for
  reading" and falls under the EBADF shall-fail.
- Level: MUST.
- Errno: EBADF.
- Cite: opendir.html DESCRIPTION + ERRORS ("The fdopendir() function shall
  fail if: [EBADF] The fd argument is not a valid file descriptor open for
  reading.").
- Model: precondition for fdopendir success = valid fd, access mode
  includes read, fd refers to a directory. Linux-divergence: Linux has no
  native O_SEARCH; glibc historically does not define it (musl maps it to
  O_PATH), and glibc fdopendir rejects O_PATH descriptors — exact glibc
  errno UNVERIFIED.

### R7 — fdopendir transfers fd ownership to the stream
- Behavior: "Upon successful return from fdopendir(), the file descriptor
  is under the control of the system, and if any attempt is made to close
  the file descriptor, or to modify the state of the associated
  description, other than by means of closedir(), readdir(), readdir_r(),
  rewinddir(), or seekdir(), the behavior is undefined. Upon calling
  closedir() the file descriptor shall be closed."
- Level: MUST (ownership/close); undefined (any other mutation of the fd or
  its open file description, e.g. close(fd), lseek(fd), dup2 onto it).
- Errno: none.
- Cite: opendir.html DESCRIPTION.
- Model: on fdopendir success, mark the fd as owned-by-stream; the model
  must not generate close()/lseek() on it; closedir closes it exactly once.
  Also note (Defect 411, CHANGE HISTORY): FD_CLOEXEC is NOT cleared by
  fdopendir — caller's flag survives.

### R8 — fdopendir shall-fail matrix
- Behavior: EBADF (see R6) and ENOTDIR — "The descriptor fd is not
  associated with a directory." Both under "shall fail". No path-resolution
  errnos (no path is resolved).
- Level: MUST (shall fail).
- Errno: EBADF, ENOTDIR.
- Cite: opendir.html ERRORS.
- Model: deterministic on fd-table state; no EACCES exists for fdopendir
  (permission was checked when the fd was opened).

---

## 2. readdir()

### R9 — readdir returns the entry at the current position and advances
- Behavior: "The readdir() function shall return a pointer to a structure
  representing the directory entry at the current position in the directory
  stream specified by the argument dirp, and position the directory stream
  at the next entry."
- Level: MUST.
- Errno: none (success).
- Cite: readdir.html DESCRIPTION.
- Model: cursor semantics: emit stream[pos], pos += 1.

### R10 — d_name and d_ino are the POSIX-required dirent fields; d_ino must match
- Behavior: POSIX requires d_name and (on XSI/for non-symlink cases in
  general) d_ino in struct dirent. "The value of the structure's d_ino
  member shall be set to the file serial number of the file named by the
  d_name member." No d_type, d_off, d_reclen are required by POSIX.
- Level: MUST (d_ino correctness when present).
- Errno: EOVERFLOW if a value cannot be represented (R16).
- Cite: readdir.html DESCRIPTION.
- Model: observable per entry = (name, ino); ino must equal the model's
  serial number for that name at return time. Linux-divergence: d_type is
  ubiquitous on Linux but is a non-POSIX extension and may be DT_UNKNOWN —
  do not model it as required.

### R11 — No empty names
- Behavior: "The readdir() function shall not return directory entries
  containing empty names."
- Level: MUST.
- Errno: none.
- Cite: readdir.html DESCRIPTION.
- Model: invariant on every returned entry: len(d_name) >= 1.

### R12 — Dot and dot-dot: existence is the implementation's choice; if they exist, exactly one of each
- Behavior: "If entries for dot or dot-dot exist, one entry shall be
  returned for dot and one entry shall be returned for dot-dot; otherwise,
  they shall not be returned." (Issue 8 phrases this conditionally on
  existence rather than with "may"; whether a filesystem has dot/dot-dot
  entries is the implementation's property.) XBD 3.110/3.111 define dot =
  "." and dot-dot = "..".
- Level: acceptance-set{dot and dot-dot each present exactly once; both
  absent} — but consistent with whether the entries exist on that
  filesystem; MUST-once if present.
- Errno: none.
- Cite: readdir.html DESCRIPTION; basedefs 3.110, 3.111.
- Model: a per-filesystem boolean HasDotEntries; if true, every full sweep
  contains "." once and ".." once; if false, never. Do not allow flapping
  between sweeps of the same directory.

### R13 — The unspecified window: files added/removed after opendir/rewinddir
- Behavior: "If a file is removed from or added to the directory after the
  most recent call to opendir() or rewinddir(), whether a subsequent call
  to readdir() returns an entry for that file is unspecified."
- Level: unspecified (only for the touched entries; see R14 for the rest).
- Errno: none.
- Cite: readdir.html DESCRIPTION.
- Model: keep per-stream sets Added and Removed since the window started;
  entries in Added ∪ Removed are acceptance-set{returned, not-returned} for
  the remainder of the window.

### R14 — Entries neither added nor removed: returned (exactly once) — by definition, not by an explicit readdir sentence
- Behavior: Issue 8's readdir page contains NO explicit "shall be returned
  exactly once" sentence; the unspecified carve-out (R13) is scoped only to
  files added/removed in the window. The strongest guarantee is the XBD
  definition: 3.105 Directory Stream — "A sequence of all the directory
  entries in a particular directory." A sequence of ALL entries, combined
  with R9's advance-by-one cursor, yields: every entry that exists for the
  whole window appears in the sweep, and appears once.
- Level: MUST (by inference from XBD 3.105 + R9 + R13's limited scope; the
  "exactly once" reading is an inference, flagged as such — treat
  duplicates of a stable entry as a failure).
- Errno: none.
- Cite: basedefs V1_chap03.html 3.105; readdir.html DESCRIPTION (scope of
  the unspecified sentence).
- Model: for an unmodified window, multiset(sweep) minus dot entries ==
  set(model directory contents) with multiplicity 1. This is the core MBT
  check.

### R15 — End of stream: NULL with errno unchanged
- Behavior: "It shall return a null pointer upon reaching the end of the
  directory stream." / "When the end of the directory is encountered, a
  null pointer shall be returned and errno is not changed."
- Level: MUST.
- Errno: none (explicitly unchanged).
- Cite: readdir.html DESCRIPTION + RETURN VALUE.
- Model: EOF is NULL + errno==saved; per APPLICATION USAGE, tests should
  "set errno to 0 before calling readdir()" to distinguish EOF from error.

### R16 — readdir errno matrix
- Behavior: errors return NULL with errno set. Shall fail: EOVERFLOW ("One
  of the values in the structure to be returned cannot be represented
  correctly."), ENOMEM ("Insufficient memory is available."). May fail:
  EBADF ("The dirp argument does not refer to an open directory stream."),
  ENOENT ("The current position of the directory stream is invalid.").
- Level: MUST (shall-fail set); MAY-FAIL (EBADF, ENOENT).
- Errno: EOVERFLOW, ENOMEM; EBADF, ENOENT.
- Cite: readdir.html ERRORS.
- Model: ENOENT's "current position ... invalid" is the seekdir-stale-loc
  hook (R28/R50). EOVERFLOW only matters with 32-bit ino_t builds — skip.

### R17 — atime: marked for update each time the directory is ACTUALLY read
- Behavior: "readdir() shall mark for update the last data access timestamp
  of the directory each time the directory is actually read." Marking is
  tied to actual reads of the directory, not to each readdir() call —
  buffered implementations may satisfy many readdir() calls from one actual
  read. opendir() itself carries no atime requirement on this page.
- Level: MUST (on actual read); which calls constitute an actual read is
  implementation-dependent.
- Errno: none.
- Cite: readdir.html DESCRIPTION.
- Model: model atime as "updated at least once between opendir and the
  first successful readdir's completion, and possibly again later"; do not
  assert per-call atime bumps. Linux-divergence: relatime defers visible
  atime updates (up to 24h), so atime checks are unreliable on default
  mounts.

### R18 — Return storage: volatile per-stream, isolated across streams
- Behavior: the returned pointer/structure "might be invalidated or the
  structure or the storage areas might be overwritten by a subsequent call
  to readdir() on the same directory stream" but "They shall not be
  affected by a call to readdir() on a different directory stream."
- Level: unspecified (same-stream reuse); MUST (cross-stream isolation).
- Errno: none.
- Cite: readdir.html DESCRIPTION.
- Model: the test driver must copy (name, ino) out before the next readdir
  on that stream; interleaving two streams is safe and is a good MBT
  scenario (two cursors over one directory must each satisfy R14
  independently).

### R19 — Thread-safety; readdir_r obsolescent in Issue 8
- Behavior: "The readdir() function need not be thread-safe if concurrent
  calls are made for the same directory stream." (i.e., it IS required to
  be thread-safe otherwise; CHANGE HISTORY: Defects 696/1664 "making
  readdir_r() obsolescent, requiring readdir() to be thread-safe except
  when concurrent calls are made for the same directory stream"). FUTURE
  DIRECTIONS: "The readdir_r() function may be removed in a future
  version." readdir_r is still in the Issue 8 SYNOPSIS, marked OB.
- Level: MUST (thread-safety across distinct streams); undefined/racy
  (same-stream concurrency).
- Errno: none.
- Cite: readdir.html DESCRIPTION, FUTURE DIRECTIONS, CHANGE HISTORY.
- Model: never generate concurrent readdir on one stream; concurrent
  streams are fair game. Ignore readdir_r entirely.

### R20 — No ordering of entries is specified
- Behavior: the readdir page specifies no order in which entries are
  returned (no sentence on ordering exists).
- Level: unspecified.
- Errno: none.
- Cite: readdir.html (absence; verified no ordering text on the page).
- Model: compare sweeps as sets/multisets, never as sequences.
  Linux-divergence: ext4/xfs return hash/btree order, not creation or
  alphabetical order; NFS returns server cookie order. Any order-dependent
  oracle is wrong.

### R21 — Directory removed (rmdir) while the stream is open: POSIX is silent
- Behavior: neither readdir.html nor closedir.html addresses reading a
  stream whose directory has been removed. No quote exists; this is a spec
  gap, not an explicit "unspecified". (The general R13 window covers the
  ENTRIES that were removed, but not the enclosing directory's removal.)
- Level: UNVERIFIED / spec gap — treat as acceptance-set{NULL(EOF),
  remaining buffered entries then NULL, error}.
- Errno: none defined for this case.
- Cite: readdir.html, closedir.html (absence of any rmdir-of-target text).
- Model: Linux-divergence: Linux getdents on a removed directory returns 0
  (EOF), and glibc first drains its buffer (~32 KiB) — so already-buffered
  entries still come back. Best to avoid generating this case, or accept
  any prefix of the pre-rmdir sweep followed by EOF.

---

## 3. rewinddir()

### R22 — Reset to beginning AND refresh to current directory state
- Behavior: "The rewinddir() function shall reset the position of the
  directory stream to which dirp refers to the beginning of the directory.
  It shall also cause the directory stream to refer to the current state of
  the corresponding directory, as a call to opendir() would have done."
- Level: MUST.
- Errno: none.
- Cite: rewinddir.html DESCRIPTION.
- Model: rewinddir == re-snapshot: pos := 0, window restarts (Added/Removed
  sets cleared), stream contents := current model directory. Entries
  created before the rewinddir MUST appear in the post-rewind sweep (they
  are no longer in any window).

### R23 — rewinddir returns nothing and defines no errors
- Behavior: "The rewinddir() function shall not return a value." /
  ERRORS: "No errors are defined."
- Level: MUST.
- Errno: none.
- Cite: rewinddir.html RETURN VALUE, ERRORS.
- Model: rewinddir is infallible in the model; calling it on an invalid
  stream is out-of-model (undefined).

### R24 — rewinddir interacts with the window rule
- Behavior: R13's window is anchored at "the most recent call to opendir()
  or rewinddir()" — rewinddir closes the old uncertainty window and opens a
  new one. Mutations older than the last rewinddir are committed: their
  effects are part of the "current state" the stream must now reflect.
- Level: MUST (composition of R13 + R22).
- Errno: none.
- Cite: readdir.html DESCRIPTION + rewinddir.html DESCRIPTION.
- Model: rewinddir is the tool that turns a nondeterministic acceptance-set
  sweep back into a deterministic exact-set sweep. Use it liberally in
  generated traces to re-establish determinism after mutations.

---

## 4. seekdir() / telldir()

### R25 — seekdir restores a previously-told position
- Behavior: "The seekdir() function shall set the position of the next
  readdir() operation on the directory stream specified by dirp to the
  position specified by loc. The value of loc should have been returned
  from an earlier call to telldir() using the same directory stream. The
  new position reverts to the one associated with the directory stream when
  telldir() was performed."
- Level: MUST (when loc is valid per R26).
- Errno: none ("No errors are defined.").
- Cite: seekdir.html DESCRIPTION, ERRORS.
- Model: position token semantics: seekdir(tell_k) makes the next readdir
  resume where the stream stood at telldir call k.

### R26 — loc validity: same stream only; rewinddir invalidates
- Behavior: "If the value of loc was not obtained from an earlier call to
  telldir(), or if a call to rewinddir() occurred between the call to
  telldir() and the call to seekdir(), the results of subsequent calls to
  readdir() are unspecified." Cross-stream use is covered by "using the
  same directory stream" (R25) — a loc from another stream (or from a
  stream since closed and reopened) was "not obtained from an earlier call
  to telldir()" on THIS stream, hence unspecified.
- Level: unspecified (fabricated loc, cross-stream loc, post-rewinddir
  loc).
- Errno: none directly; readdir may then fail ENOENT "The current position
  of the directory stream is invalid." (R16).
- Cite: seekdir.html DESCRIPTION; readdir.html ERRORS.
- Model: only generate seekdir with a loc telldir'd from the same live
  stream with no intervening rewinddir. Everything else is out-of-model.

### R27 — telldir returns the current location; seekdir/telldir round-trip
- Behavior: "The telldir() function shall obtain the current location
  associated with the directory stream specified by dirp." and "If the most
  recent operation on the directory stream was a seekdir(), the directory
  position returned from the telldir() shall be the same as that supplied
  as a loc argument for seekdir()."
- Level: MUST.
- Errno: none ("No errors are defined."). APPLICATION USAGE and RATIONALE
  on the Issue 8 telldir page are "None."
- Cite: telldir.html DESCRIPTION, RETURN VALUE, ERRORS.
- Model: telldir immediately after seekdir(loc) must return loc. Otherwise
  loc values are opaque cookies — never interpret, compare, or do
  arithmetic on them.

### R28 — Seeking to a loc taken before a directory modification
- Behavior: POSIX does not carve this case out in seekdir (the loc WAS
  obtained from telldir on the same stream), but the R13 window still
  governs which entries a subsequent readdir returns, and readdir's
  MAY-FAIL ENOENT ("The current position of the directory stream is
  invalid.") explicitly licenses failure after such a seek.
- Level: acceptance-set{resume with R13 window semantics; readdir fails
  ENOENT} .
- Errno: ENOENT (may fail, on the subsequent readdir).
- Cite: seekdir.html DESCRIPTION; readdir.html ERRORS.
- Model: defer seekdir/telldir from the first model iteration; when added,
  only exercise them on unmodified windows, where resume-exactly is the
  sole acceptable outcome. Linux-divergence: on Linux the cookie is a
  getdents d_off (filesystem hash / NFS server cookie); seeking to a stale
  cookie after modification can skip or duplicate entries — consistent with
  "unspecified".

### R29 — loc after closedir: dead token
- Behavior: no text gives a telldir value validity beyond the life of its
  stream; after closedir the stream no longer exists, and a new stream on
  the same directory is a different stream, so using the old loc falls
  under R26's "not obtained from an earlier call to telldir()" (on that
  stream) → unspecified.
- Level: unspecified (by composition; no direct quote — flagged
  inference).
- Errno: none defined.
- Cite: seekdir.html DESCRIPTION (same-stream language); telldir.html.
- Model: loc tokens are keyed by (stream id); closedir kills all its
  tokens.

---

## 5. closedir()

### R30 — closedir closes the stream; dirp becomes unusable
- Behavior: "The closedir() function shall close the directory stream
  referred to by the argument dirp. Upon return, the value of dirp may no
  longer point to an accessible object of the type DIR."
- Level: MUST (close); undefined (any later use of dirp).
- Errno: see R32.
- Cite: closedir.html DESCRIPTION.
- Model: stream leaves the state space; never generate operations on a
  closed stream (EBADF is only MAY-fail — see R32 — so use-after-close has
  no reliable observable and must simply not be generated).

### R31 — closedir closes the associated fd, whatever its origin
- Behavior: "If there is a file descriptor associated with the stream
  (whether opened by opendir() or dirfd(), or passed to fdopendir() when
  creating the stream), that file descriptor shall be closed by
  closedir()." Matches fdopendir's "Upon calling closedir() the file
  descriptor shall be closed."
- Level: MUST.
- Errno: none.
- Cite: closedir.html DESCRIPTION; opendir.html DESCRIPTION.
- Model: closedir releases exactly one fd slot when the stream is
  fd-backed; the number obtained via dirfd() and the number passed to
  fdopendir() are the same slot — closed once, by closedir, never by the
  caller.

### R32 — closedir errno set: only MAY-fail EBADF and EINTR
- Behavior: "Upon successful completion, closedir() shall return 0;
  otherwise, -1 shall be returned and errno set to indicate the error."
  ERRORS defines only may-fail conditions: "[EBADF] The dirp argument does
  not refer to an open directory stream." and "[EINTR] The closedir()
  function was interrupted by a signal." There are NO shall-fail errors.
- Level: MAY-FAIL only.
- Errno: EBADF, EINTR.
- Cite: closedir.html RETURN VALUE, ERRORS.
- Model: closedir on a valid stream: expect 0 (treat EINTR as
  out-of-model, no signals generated). closedir on garbage: acceptance-set
  {-1/EBADF, undefined} — do not generate.

### R33 — The dirfd() descriptor is dead after closedir
- Behavior: direct consequence of R31: the descriptor previously returned
  by dirfd() is closed by closedir(); continued use yields EBADF like any
  closed fd (per general fd semantics, not restated on these pages).
- Level: MUST (closure); the post-close EBADF is standard fd behavior.
- Errno: EBADF (from whatever function is later applied to the stale fd).
- Cite: closedir.html DESCRIPTION ("whether opened by opendir() or
  dirfd()...shall be closed by closedir()").
- Model: any *at anchor derived from dirfd(stream) has lifetime bounded by
  that stream; invalidate it at closedir.

---

## 6. dirfd()

### R34 — dirfd returns the stream's associated fd
- Behavior: "If the directory stream referenced by dirp has an associated
  file descriptor, dirfd() shall return that file descriptor."
- Level: MUST.
- Errno: none.
- Cite: dirfd.html DESCRIPTION.
- Model: dirfd is a pure observer for fd-backed streams; repeated calls
  return the same fd.

### R35 — Issue 8 new: dirfd opens an fd on demand for non-fd-backed streams
- Behavior: "Otherwise, dirfd() shall open a new file description referring
  to the directory associated with the directory stream as if by calling:
  open(DirectoryName, O_RDONLY | O_DIRECTORY | O_CLOEXEC)." (Issue 7
  instead allowed may-fail ENOTSUP here.)
- Level: MUST.
- Errno: EMFILE, ENFILE for the on-demand open (R38).
- Cite: dirfd.html DESCRIPTION.
- Model: can be ignored on fd-backed targets (Linux DIRs are always
  fd-backed — the on-demand branch is dead code there; glibc dirfd cannot
  fail).

### R36 — The dirfd descriptor is under system control; mutations undefined
- Behavior: "Upon successful return from dirfd(), the file descriptor is
  under the control of the system, and if any attempt is made to close the
  file descriptor, or to modify the state of the associated description,
  other than by means of closedir(), readdir(), readdir_r(), rewinddir(),
  or seekdir(), the behavior is undefined. Upon calling closedir() the file
  descriptor shall be closed."
- Level: undefined (close(fd), lseek(fd), or anything mutating the open
  file description, e.g. its offset or status flags).
- Errno: none.
- Cite: dirfd.html DESCRIPTION.
- Model: forbid generating close/lseek/fcntl(F_SETFL)/dup2-onto for this
  fd. Reads of state (fstat) and uses that don't touch the description are
  fine — see R37.

### R37 — Legitimate uses: fchdir, fstat, and as a *at dirfd anchor
- Behavior: APPLICATION USAGE: "The dirfd() function is intended to be a
  mechanism by which an application may obtain a file descriptor to use for
  the fchdir() function." The fd refers to the directory with O_RDONLY
  semantics (R35's as-if open), so it satisfies the *at functions'
  directory-fd requirements; fchdir/fstat/openat-style use does not "modify
  the state of the associated description" and stays outside R36's
  undefined zone.
- Level: MUST (fchdir usability is the stated intent); *at-anchor
  suitability is a sound composition with XSH *at requirements, flagged as
  composition rather than a direct quote.
- Errno: per the called function.
- Cite: dirfd.html APPLICATION USAGE, DESCRIPTION.
- Model: for *at modeling, dirfd(stream) is a valid dirfd anchor whose
  target tracks the directory (not the path) — it stays valid across
  renames of the directory, dies at closedir (R33).

### R38 — dirfd errno matrix
- Behavior: shall fail: "[EMFILE] A new file descriptor is required and all
  file descriptors available to the process are currently open" and
  "[ENFILE] A new file descriptor is required and the maximum allowable
  number of files is currently open in the system" (both only reachable in
  the on-demand-open branch, R35). May fail: "[EINVAL] The dirp argument
  does not refer to a valid directory stream."
- Level: MUST (EMFILE/ENFILE when a new fd is required); MAY-FAIL
  (EINVAL).
- Errno: EMFILE, ENFILE, EINVAL.
- Cite: dirfd.html ERRORS.
- Model: on fd-backed implementations dirfd never fails for valid streams;
  EINVAL-on-garbage is not reliably observable — don't generate.

---

## 7. scandir() / alphasort()

### R39 — scandir = filtered sweep + malloc'd copies + qsort
- Behavior: "The scandir() function shall scan the directory dir, calling
  the function referenced by sel on each directory entry. Entries for which
  the function referenced by sel returns non-zero shall be stored in
  strings allocated as if by a call to malloc(), and sorted as if by a call
  to qsort() with the comparison function compar."
- Level: MUST.
- Errno: see R42.
- Cite: alphasort.html DESCRIPTION.
- Model: model scandir as: opendir + full readdir sweep (all R9–R21 rules
  apply, including the R13 window if the directory is mutated during the
  call) + filter + sort + closedir. Caller frees namelist entries.

### R40 — NULL sel selects everything
- Behavior: "If sel is a null pointer, all entries shall be selected."
- Level: MUST.
- Errno: none.
- Cite: alphasort.html DESCRIPTION.
- Model: scandir(dir, &nl, NULL, alphasort) is the canonical "give me the
  whole directory sorted" sweep — the best single-call oracle probe.

### R41 — scandir return value
- Behavior: "Upon successful completion, the scandir() function shall
  return the number of entries in the array and a pointer to the array
  through the parameter namelist. Otherwise, the scandir() function shall
  return -1."
- Level: MUST.
- Errno: per R42 on -1.
- Cite: alphasort.html RETURN VALUE.
- Model: count must equal the accepted entry multiset size; with NULL sel
  on an unmodified directory: |contents| (+2 if HasDotEntries, R12).

### R42 — scandir errno matrix (mirrors opendir + readdir + fd budget)
- Behavior: shall fail: EACCES ("Search permission is denied for the
  component of the path prefix of dir or read permission is denied for
  dir."), ELOOP, ENAMETOOLONG ({NAME_MAX} form), ENOENT ("A component of
  dir does not name an existing directory or dir is an empty string."),
  ENOMEM ("Insufficient storage space is available."), ENOTDIR ("A
  component of dir names an existing file that is neither a directory nor a
  symbolic link to a directory."), EOVERFLOW ("One of the values to be
  returned or passed to a callback function cannot be represented
  correctly."). May fail: ELOOP ({SYMLOOP_MAX}), EMFILE, ENAMETOOLONG
  ({PATH_MAX}), ENFILE.
- Level: MUST (shall-fail list); MAY-FAIL (may-fail list).
- Errno: EACCES, ELOOP, ENAMETOOLONG, ENOENT, ENOMEM, ENOTDIR, EOVERFLOW;
  EMFILE, ENFILE.
- Cite: alphasort.html ERRORS.
- Model: path-condition errnos are byte-identical to opendir's (R2/R3) —
  reuse the same guard predicates; ENOMEM/EOVERFLOW additions come from the
  readdir/malloc phases.

### R43 — alphasort compares by strcoll on d_name
- Behavior: "Sorting happens as if by calling the strcoll() function on the
  d_name element of the dirent structures passed as the two parameters."
  RETURN VALUE: ordering is "as appropriate to the current locale". No
  strcoll-fails-then-strcmp fallback text appears on the Issue 8 page.
- Level: MUST.
- Errno: none.
- Cite: alphasort.html DESCRIPTION, RETURN VALUE.
- Model: run the harness under LC_ALL=C/POSIX so alphasort order ==
  bytewise strcmp order and the oracle is a plain sort.

### R44 — alphasort "stability": none guaranteed for collation-equal names
- Behavior: sorting is "as if by a call to qsort()", and POSIX qsort leaves
  the relative order of members that compare equal unspecified. Distinct
  d_names are unique within a directory, but strcoll in a non-C locale can
  collate distinct names equal — their relative order is then unspecified.
- Level: unspecified (order among collation-equal names).
- Errno: none.
- Cite: alphasort.html DESCRIPTION ("as if by a call to qsort()").
- Model: in the C locale distinct names never compare equal, so the sorted
  output is fully deterministic — another reason to pin LC_ALL=C.

---

## 8. Interaction rules for MBT

### R45 — unlink of an entry mid-stream
- Behavior: the entry enters the R13 window; each remaining readdir on that
  stream may or may not return it. Strictly, R13 only says "whether ... is
  unspecified" per call — the sane acceptance is {absent, present once};
  a duplicate would additionally require the entry to be returned twice,
  which nothing licenses for the portion outside the window, but within the
  window a skip/dup via buffering is hard to rule out from the text alone.
- Level: acceptance-set{entry absent from remainder of sweep; entry present
  once}. Duplicates: pathological, flag but classify separately.
- Errno: none.
- Cite: readdir.html DESCRIPTION (R13 sentence).
- Model: Linux-divergence: glibc buffers getdents results (~32 KiB), so an
  entry already fetched into the buffer is returned even though it was
  unlinked; entries in unfetched chunks vanish. Both are inside the
  acceptance set.

### R46 — create (or link) of an entry mid-stream
- Behavior: symmetric to R45: the new entry may or may not appear in the
  remainder of the current sweep. It MUST appear in any sweep whose window
  starts after the creation (post-rewinddir or new stream, R22/R24).
- Level: acceptance-set{absent, present once} in the current window; MUST
  appear after the window resets.
- Errno: none.
- Cite: readdir.html DESCRIPTION; rewinddir.html DESCRIPTION.
- Model: after any mutation, follow with rewinddir before the checking
  sweep to regain a deterministic oracle.

### R47 — rename of an entry mid-stream: both names are in the window
- Behavior: rename(old, new) within the directory removes entry old and
  adds entry new — both fall under R13. A sweep overlapping the rename may
  show, for the {old, new} pair, any subset: neither, only old, only new,
  or both. (Rename INTO or OUT OF the directory contributes just one name
  to this window.)
- Level: acceptance-set{∅, {old}, {new}, {old,new}} for the affected names;
  all untouched entries still obey R14.
- Errno: none.
- Cite: readdir.html DESCRIPTION (R13 applied to the remove+add pair).
- Model: this is the classic MBT nondeterminism case; encode it as a
  per-name 2x2 acceptance and keep the rest of the sweep exact.

### R48 — Full sweep of an unmodified directory: exact set, each entry once
- Behavior: strongest available guarantee (see R14): the stream is "A
  sequence of all the directory entries in a particular directory" (XBD
  3.105), readdir walks it one entry per call (R9), never returns empty
  names (R11), returns dot/dot-dot exactly once each iff they exist (R12),
  and ends with NULL/errno-unchanged (R15). No ordering (R20). No sentence
  on the readdir page states "exactly once" explicitly — the exact-set
  oracle rests on 3.105.
- Level: MUST (with the R14 inference flag).
- Errno: none.
- Cite: basedefs 3.105; readdir.html DESCRIPTION/RETURN VALUE.
- Model: THE primary deterministic check: sweep-to-NULL on a quiescent
  directory, compare as multiset against model state, require multiplicity
  1, ignore order.

### R49 — rewinddir commits all prior mutations into the visible state
- Behavior: after rewinddir, the stream reflects "the current state of the
  corresponding directory, as a call to opendir() would have done" — every
  entry that exists at rewind time MUST be in the new sweep; every entry
  removed before rewind time MUST NOT be (unless re-touched inside the new
  window).
- Level: MUST.
- Errno: none.
- Cite: rewinddir.html DESCRIPTION.
- Model: checks that a stale snapshot is actually discarded — a server that
  keeps serving the old snapshot after rewinddir is nonconformant. Good
  targeted test for cookie-cached NFS/readdir implementations.

### R50 — Stale seekdir position after mutation
- Behavior: seekdir to a loc telldir'd earlier, with mutations in between:
  next readdir is governed by R13 for touched entries, and may fail ENOENT
  ("The current position of the directory stream is invalid.").
- Level: acceptance-set{resume + R13 semantics; NULL/ENOENT}.
- Errno: ENOENT (may fail).
- Cite: readdir.html ERRORS; seekdir.html DESCRIPTION.
- Model: defer (phase 2); when enabled, only assert on unmodified windows.

### R51 — scandir during concurrent mutation
- Behavior: scandir's internal sweep is a single window (R39); mutations
  concurrent with the call put the touched names into acceptance sets
  exactly as R45–R47. There is no atomicity guarantee — scandir is not a
  snapshot.
- Level: acceptance-set (per touched name), MUST for untouched names.
- Errno: R42.
- Cite: alphasort.html DESCRIPTION ("shall scan the directory ... calling
  ... on each directory entry").
- Model: in single-threaded MBT traces scandir is always quiescent —
  treat it as an atomic full sweep + sort; only distinguish it from the
  loop form if the harness injects concurrency.

---

## Testing notes

1. Deterministic oracle = quiescent sweep. Only assert exact
   set-equality (R48) on streams whose window (opendir/rewinddir → now)
   contains no directory mutations. Sequence: mutate → rewinddir (or fresh
   opendir) → sweep-to-NULL → compare multiset(names) and each d_ino
   against the model. Require multiplicity exactly 1 per name.
2. Mutation-window checks are acceptance sets. When a trace mutates
   mid-sweep, partition names into Touched (added/removed/renamed since
   window start) and Stable. Assert: Stable names appear exactly once
   (R14); Touched names appear 0 or 1 times, per R45–R47's per-name
   acceptance sets; a Touched name appearing twice or a Stable name
   missing/duplicated is a real failure worth flagging (dup-in-window at
   lower severity, see R45).
3. errno discipline: set errno=0 before each readdir; NULL+errno==0 is
   EOF, NULL+errno!=0 is error (readdir APPLICATION USAGE, R15/R16).
4. Locale pinning: run with LC_ALL=C so alphasort/scandir output order is
   the model's bytewise sort (R43/R44) — makes scandir a fully
   deterministic combined probe: count == |model dir| (+2 with dot
   entries), sorted names == sorted(model names).
5. Dot entries: learn HasDotEntries once per filesystem-under-test with a
   probe sweep of a known-empty directory, then require consistency (R12).
   Never hardcode presence: an object store or synthetic FS may omit them.
6. fd accounting: every open stream holds one fd (R5); closedir releases
   exactly one, including the fdopendir-donated and dirfd-obtained ones
   (R31/R33). An fd-leak check across a trace: count open fds before ==
   after when all streams are closed.
7. Two-stream isolation: interleave two streams on one directory; each
   must independently satisfy R48; entries copied from stream A must not be
   clobbered by readdir on stream B (R18).
8. Do not generate: operations on closed streams/fds (only MAY-fail
   errnos — no reliable observable, R30/R32/R33), concurrent readdir on one
   stream (R19), close/lseek on stream-owned fds (R7/R36), fabricated or
   cross-stream seekdir locs (R26), readdir on an rmdir'd directory unless
   the acceptance set of R21 is implemented.

## Traps

- "readdir returns entries in order" — false; no ordering exists (R20).
  Alphabetical results on tiny tmpfs dirs are a coincidence; ext4 hash
  order breaks it. Always compare as sets.
- "Each entry exactly once" is NOT a quoted readdir sentence — it derives
  from XBD 3.105's "sequence of all the directory entries". Cite 3.105, not
  readdir.html, when someone asks where the guarantee lives (R14).
- The dot/dot-dot rule is conditional existence, not "may be returned":
  if the entries exist, returning them is mandatory (exactly once each);
  if not, returning them is forbidden (R12). An implementation that
  sometimes shows "." and sometimes doesn't in the same directory is
  broken.
- fdopendir wants a READABLE fd. Issue 8's page never mentions O_SEARCH;
  EBADF is specified for an fd not "open for reading" (R6). Passing an
  O_PATH fd on Linux fails (glibc detail UNVERIFIED).
- EACCES is overloaded: prefix-search denial and target-read denial are
  the same errno for opendir/scandir (R2/R42); the model cannot distinguish
  them observationally.
- closedir's EBADF is only MAY-fail (R32) — a use-after-close test that
  "expects EBADF" is testing glibc, not POSIX.
- atime-per-readdir is a myth: the mark is per actual directory read
  (R17), and Linux relatime hides most updates anyway.
- telldir cookies are opaque: not offsets, not indexes, not monotonic; on
  NFS they are server cookies. Only the same-stream round-trip is defined
  (R25–R27).
- rewinddir/seekdir/telldir/closedir(valid) define NO errors — error
  injection there produces undefined behavior, not testable errnos
  (R23/R25/R27/R32).
- scandir's ENOMEM/EOVERFLOW have no opendir-loop analogue in the same
  shape — a model equating scandir errors 1:1 with opendir's misses the
  readdir/malloc-phase errnos (R42).
- The buffered-unlink illusion (Linux): an unlinked entry can still be
  returned because glibc had already fetched it via getdents — this is
  conformant (inside the R13 window), not a bug in the system under test.
