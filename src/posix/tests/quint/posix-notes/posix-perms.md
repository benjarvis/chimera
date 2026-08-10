<!--
SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors

SPDX-License-Identifier: LGPL-2.1-only
-->

# POSIX.1-2024 (Issue 8) — Permission and Privilege Model: Rule Inventory

Source of truth: POSIX.1-2024 / SUSv5 (Issue 8) at
https://pubs.opengroup.org/onlinepubs/9799919799/ — verified live 2026-08-09.
All quotes below were fetched from the Issue 8 HTML pages (not Issue 7, not memory).

Key section numbers in Issue 8 XBD Chapter 4 (verified against the chapter's
table of headings):
- XBD 4.5  Directory Protection        (sticky bit / S_ISVTX on directories)
- XBD 4.6  Extended Security Controls
- XBD 4.7  File Access Permissions     (the standard access algorithm)
- XBD 4.16 Pathname Resolution

Conventions used in this document:
- Requirement level: MUST (spec "shall"), MAY, implementation-defined,
  unspecified, acceptance-set{...} (spec allows any listed alternative).
- "Model:" lines give one-line advice for the Quint model.
- pjdfstest-derived observations are labeled explicitly and are NOT spec text.
- "Linux-divergence:" marks behavior Linux exhibits that the spec does not
  require (or contradicts).

---

## A. Credentials and file classes

### R1. Process credential tuple
- Behavior: The credentials relevant to file permission checking are:
  effective user ID, effective group ID, supplementary group IDs, real user
  ID, real group ID, and the file mode creation mask (umask). Definitions
  (XBD 3.x, Issue 8):
  - 3.117 Effective User ID: "An attribute of a process that is used in
    determining various permissions, including file access permissions."
  - 3.116 Effective Group ID: same wording as above for group.
  - 3.300 Real User ID: "The attribute of a process that, at the time of
    process creation, identifies the user who created the process."
- Requirement level: MUST (these are the defined inputs to XBD 4.7).
- errno: n/a.
- Citation: XBD 3.116, 3.117, 3.300; XBD 4.7.
- Model: creds = {euid, egid, sgroups: Set[gid], ruid, rgid, umask}. Only
  euid/egid/sgroups feed the access check (except access(), see R36); umask
  feeds creation modes (R41).

### R2. File owner class (definition)
- Behavior: XBD 3.150 File Owner Class: "A process is in the file owner
  class of a file if the effective user ID of the process matches the user
  ID of the file."
- Requirement level: MUST.
- Citation: XBD 3.150.
- Model: `class(file, creds) = Owner  iff creds.euid == file.uid`.

### R3. File group class (definition; owner class excluded first)
- Behavior: XBD 3.142 File Group Class: "A process is in the file group
  class of a file if the process is not in the file owner class and if the
  effective group ID or one of the supplementary group IDs of the process
  matches the group ID associated with the file."
- Requirement level: MUST. Note the leading "is not in the file owner
  class" — this is what makes class selection exclusive (see R5).
- Citation: XBD 3.142.
- Model: `Group iff euid != file.uid and (egid == file.gid or file.gid in sgroups)`.

### R4. File other class (definition)
- Behavior: XBD 3.149 File Other Class: "A process is in the file other
  class of a file if the process is not in the file owner class or file
  group class."
- Requirement level: MUST.
- Citation: XBD 3.149.
- Model: `Other` = the residual case. Exactly one class always holds.

### R5. Class selection is EXCLUSIVE
- Behavior: A process belongs to exactly one class, and only that class's
  permission bits are consulted. XBD 4.7 (non-privileged branch): "Access
  shall be granted if an alternate file access control mechanism is not
  enabled and the requested access permission bit is set for the class
  (file owner class, file group class, or file other class) to which the
  process belongs ... otherwise, access shall be denied." Because the class
  definitions (R2-R4) are mutually exclusive, an owner whose owner bits deny
  access is denied even if group or other bits would grant it; a group
  member whose group bits deny is denied even if other bits grant.
- Requirement level: MUST.
- errno: EACCES on denial (per the general 2.3 definition, R28).
- Citation: XBD 4.7 + XBD 3.142/3.149/3.150.
- Model: pick the class first, then test exactly that class's rwx bit.
  Never fall through to a more permissive class. This is the single most
  important correctness property of the checker.

### R6. Appropriate privileges (definition; modeling assumption)
- Behavior: XBD 3.21 Appropriate Privileges: "An implementation-defined
  means of associating privileges with a process with regard to the
  function calls, function call options, and the commands that need
  special privileges." POSIX deliberately does NOT say "uid 0".
- Requirement level: implementation-defined.
- Citation: XBD 3.21.
- Model: MODELING ASSUMPTION (flagged): treat `euid == 0` as possessing
  appropriate privileges, behind a boolean predicate `hasPriv(creds)` so
  the mapping can be changed (root-squash, capabilities). Cite 3.21 in the
  model comment; do not hard-code `euid == 0` at call sites.

---

## B. The file access permission algorithm (XBD 4.7)

### R7. Algorithm framing and additional mechanisms
- Behavior: XBD 4.7: "Whenever a process requests file access permission
  for read, write, or execute/search, if no additional mechanism denies
  access, access shall be determined as follows:" — i.e. an "additional
  file access control mechanism" (XBD 3.4: "An implementation-defined
  mechanism that is layered upon the access control mechanisms defined
  here, but which do not grant permissions beyond those defined herein.")
  may only further RESTRICT access; an "alternate file access control
  mechanism" (XBD 3.12: "An implementation-defined mechanism that is
  independent of the access control mechanisms defined herein, and which
  if enabled on a file may either restrict or extend the permissions of a
  given user.") replaces the bit test when enabled.
- Requirement level: MUST (the algorithm); the mechanisms themselves are
  implementation-defined.
- Citation: XBD 4.7; XBD 3.4; XBD 3.12.
- Model: model neither mechanism (no ACLs in phase 1). Record as an
  explicit model-scope note: "additional/alternate mechanisms absent."

### R8. Privileged processes: read, write, search always granted
- Behavior: XBD 4.7: "If a process has appropriate privileges: If read,
  write, or directory search permission is requested, access shall be
  granted."
- Requirement level: MUST.
- Citation: XBD 4.7.
- Model: `hasPriv => allow` for R, W, and directory search — regardless of
  any permission bits, including mode 000.

### R9. Privileged processes: execute needs at least one x bit
- Behavior: XBD 4.7: "If execute permission is requested, access shall be
  granted if execute permission is granted to at least one user by the
  file permission bits or by an alternate access control mechanism;
  otherwise, access shall be denied." So even a privileged process is
  denied execute on a mode-644 regular file.
- Requirement level: MUST.
- errno: EACCES.
- Citation: XBD 4.7.
- Note: directory SEARCH by a privileged process falls under R8 ("read,
  write, or directory search permission ... shall be granted"), so the
  ≥1-x-bit requirement applies only to EXECUTE of files, not to directory
  traversal.
- Model: for a NAS model with no execution, this matters only if you model
  an execute-style access probe (e.g. NFS ACCESS ACCESS4_EXECUTE); then:
  `hasPriv and requesting X => allow iff (file.mode & 0111) != 0`.

### R10. Non-privileged processes: the class bit decides
- Behavior: XBD 4.7: "The file permission bits of a file contain read,
  write, and execute/search permissions for the file owner class, file
  group class, and file other class. Access shall be granted if an
  alternate file access control mechanism is not enabled and the requested
  access permission bit is set for the class (file owner class, file group
  class, or file other class) to which the process belongs, or if an
  alternate file access control mechanism is enabled and it allows the
  requested access; otherwise, access shall be denied."
- Requirement level: MUST.
- errno: EACCES on denial (see R28).
- Citation: XBD 4.7.
- Model: `allow(file, creds, perm) = hasPriv ? (R8/R9) : bitSet(file.mode, class(file,creds), perm)`.

---

## C. Directory permission semantics (search vs read vs write)

### R11. Pathname resolution needs search (x) on every path-prefix component
- Behavior: Every affected function's mandatory [EACCES] entry begins with
  the same formula; e.g. open(): "Search permission is denied on a
  component of the path prefix ..."; chmod(): "Search permission is denied
  on a component of the path prefix."; unlink(): "Search permission is
  denied for a component of the path prefix ...". XBD 4.16 (Pathname
  Resolution) itself describes the mechanics but was verified NOT to
  contain an explicit search-permission sentence — the requirement is
  carried by the per-function [EACCES] entries and by XBD 4.7's
  "execute/search" wording.
- Requirement level: MUST (shall-fail [EACCES] entries).
- errno: EACCES.
- Citation: XSH open(), chmod(), unlink(), etc. ERRORS; XBD 4.7; XBD 4.16
  (absence of its own permission sentence — verified).
- Model: resolving `a/b/c` checks search(x) on every directory component of
  the prefix (`a`, then `a/b`). The final parent directory is itself a
  prefix component, so operations on an entry always need x on the parent
  in addition to whatever else (see R13, R14).

### R12. Reading a directory's contents needs read (r), not just search
- Behavior: opendir() mandatory [EACCES]: "Search permission is denied for
  the component of the path prefix of dirname or read permission is denied
  for dirname." Listing (opendir/readdir) therefore needs r on the
  directory; looking up a known name inside it needs only x.
- Requirement level: MUST.
- errno: EACCES.
- Citation: XSH fdopendir/opendir ERRORS.
- Model: READDIR requires r on the directory; LOOKUP of a named component
  requires x. A mode-311 directory is traversable and entries are
  creatable but not listable; mode-644 directory is listable but no entry
  inside is reachable (lookups fail EACCES on search).

### R13. Creating an entry needs write (w) on the parent (plus search to reach it)
- Behavior — exact per-function shall-fail [EACCES] wording:
  - open()/O_CREAT: "... or the file does not exist and write permission is
    denied for the parent directory of the file to be created ...".
  - mkdir(): "Search permission is denied on a component of the path
    prefix, or write permission is denied on the parent directory of the
    directory to be created."
  - symlink(): "Write permission is denied in the directory where the
    symbolic link is being created, or search permission is denied for a
    component of the path prefix of path2."
  - link(): "A component of either path prefix denies search permission,
    or the requested link requires writing in a directory that denies
    write permission, or the calling process does not have permission to
    access the existing file and this is required by the implementation."
    (Note the last clause: an access check on the SOURCE file of link() is
    implementation-optional — "The implementation may require that the
    calling process has permission to access the existing file.")
- Requirement level: MUST (w on parent); implementation-defined (link()
  source-file access requirement).
- errno: EACCES.
- Citation: XSH open, mkdir, symlink, link ERRORS/DESCRIPTION.
- Model: create(parent, name) requires search-reachability of parent AND
  w on parent. No permission on the created object is checked (it does not
  exist yet — see R40). Keep the link() source-access check OFF (POSIX
  baseline) or behind a knob.

### R14. Removing an entry needs write (w) on the parent (plus search)
- Behavior — exact shall-fail [EACCES] wording:
  - unlink(): "Search permission is denied for a component of the path
    prefix, or write permission is denied on the directory containing the
    directory entry to be removed."
  - rmdir(): "Search permission is denied on a component of the path
    prefix, or write permission is denied on the parent directory of the
    directory to be removed."
  Permissions on the FILE being unlinked are irrelevant (mode 000 files
  are removable if the parent grants w+x) — subject only to the sticky-bit
  rule (R18) whose optional 4th bullet can re-introduce a file-writability
  test.
- Requirement level: MUST.
- errno: EACCES.
- Citation: XSH unlink, rmdir ERRORS.
- Model: remove(parent, name) checks w on parent + reachability; never the
  victim's own mode (except sticky, R18).

### R15. rename() needs write on both parents; write on old itself only "may be required" when old is a directory
- Behavior: rename() DESCRIPTION: "Write access permission is required for
  the directory containing old and the directory containing new." And:
  "If the old argument points to the pathname of a directory, write access
  permission may be required for the directory named by old" (historically
  because its dot-dot entry must be rewritten on cross-directory moves).
  Mandatory [EACCES]: "A component of either path prefix denies search
  permission; or one of the directories containing old or new denies write
  permissions; or, write permission is required and is denied for a
  directory pointed to by the old or new arguments."
- Requirement level: MUST (w on both parents); "may be required" = the
  write-on-old-directory check is an implementation option the spec
  acknowledges (acceptance-set{check, don't check}).
- errno: EACCES.
- Citation: XSH rename DESCRIPTION and ERRORS.
- Linux-divergence: Linux requires write permission on the moved directory
  only for cross-directory renames (dot-dot rewrite); same-directory
  renames of directories don't need it. Model both parents' w as MUST and
  put the write-on-old-dir check behind a knob.
- Model: rename checks: search+w on oldparent, search+w on newparent,
  sticky rule at BOTH ends (R19), optional w on old-if-directory knob.

### R16. O_TRUNC and truncate()/ftruncate() need write on the file
- Behavior: open() [EACCES] includes "... or O_TRUNC is specified and
  write permission is denied." truncate() DESCRIPTION: "The application
  shall ensure that the process has write permission for the file."
  truncate() [EACCES]: "A component of the path prefix denies search
  permission, or write permission is denied on the file." ftruncate() has
  no EACCES: it requires an fd "open for writing" ([EBADF] / [EINVAL]
  territory), i.e. the permission check happened at open() time.
- Requirement level: MUST.
- errno: EACCES (path-based); EBADF/EINVAL (fd not open for writing).
- Citation: XSH open, truncate, ftruncate.
- Model: path-truncate = access check W on file; fd-truncate = check the
  open's access mode, not current file mode.

### R17. Open file descriptions carry rights; file mode is checked only at open
- Behavior: write() [EBADF]: "The fildes argument is not a valid file
  descriptor open for writing." Once a fd is open, subsequent chmod of the
  file does not revoke it; the mode is consulted at open() ("the file
  exists and the permissions specified by oflag are denied" — open()
  [EACCES]).
- Requirement level: MUST.
- errno: EBADF (wrong open mode), EACCES (at open time).
- Citation: XSH write ERRORS; open ERRORS.
- Model: per-handle access mode {R, W, RW} fixed at open; later mode/owner
  changes never invalidate existing handles. (NFS maps this imperfectly —
  a stateless server re-checks; NFSv4 has the "owner override" special
  case. Keep the POSIX property as the model's VFS-layer truth.)

---

## D. Sticky bit S_ISVTX on directories (XBD 4.5 Directory Protection)

### R18. The restricted-deletion rule (full text)
- Behavior: XBD 4.5, complete verbatim text:
  "If a directory is writable and the mode bit S_ISVTX is set on the
  directory, a process may remove or rename files within that directory
  only if one or more of the following is true:
  - The effective user ID of the process is the same as that of the owner
    ID of the file.
  - The effective user ID of the process is the same as that of the owner
    ID of the directory.
  - The process has appropriate privileges.
  - Optionally, the file is writable by the process. Whether or not files
    that are writable by the process can be removed or renamed is
    implementation-defined.
  If the S_ISVTX bit is set on a non-directory file, the behavior is
  unspecified."
  So: YES, there IS a write-permission-on-the-file alternative in the
  Issue 8 text, but it is an OPTIONAL, implementation-defined fourth arm —
  not part of the portable guarantee.
- Requirement level: MUST for the three-arm rule; implementation-defined
  for the 4th (file-writable) arm; unspecified for S_ISVTX on non-dirs.
- errno: see R19.
- Citation: XBD 4.5 (entire section quoted above).
- Linux-divergence: Linux does NOT implement the 4th arm (file
  writability does not help in a sticky directory).
- Model: default policy = 3-arm rule (euid==file.uid or euid==dir.uid or
  hasPriv); expose `stickyFileWritableArm: bool` knob defaulting to false
  (Linux/NFS-realistic).

### R19. Sticky violation errno is an acceptance set {EACCES, EPERM}
- Behavior: the sticky-violation error is a single mandatory ("shall
  fail") entry headed "[EPERM] or [EACCES]" on each page:
  - unlink(): "The S_ISVTX flag is set on the directory containing the
    file referred to by the path argument and the process does not satisfy
    the criteria specified in XBD 4.5 Directory Protection."
  - rmdir(): "The S_ISVTX flag is set on the directory containing the file
    referred to by the path argument and the process does not satisfy the
    criteria specified in XBD 4.5 Directory Protection."
  - rename(): "The S_ISVTX flag is set on the directory containing the
    file referred to by old and the process does not satisfy the criteria
    specified in XBD 4.5 Directory Protection with respect to old; or new
    refers to an existing file, the S_ISVTX flag is set on the directory
    containing this file, and the process does not satisfy the criteria
    specified in XBD 4.5 Directory Protection with respect to this file."
    (Note rename applies the sticky test at BOTH the source entry and, if
    the destination exists, the destination entry.)
- Requirement level: MUST fail; errno acceptance-set{EACCES, EPERM}.
- Citation: XSH unlink, rmdir, rename ERRORS ("shall fail" lists).
- pjdfstest-derived: unlink/11.t desc: "unlink returns EACCES or EPERM if
  the directory containing the file is marked sticky, and neither the
  containing directory nor the file to be removed are owned by the
  effective user ID" — succeeds when user owns dir, or owns file, or both;
  fails matching regex "EACCES|EPERM" otherwise. rename/09.t mirrors this
  for the source entry ("neither the containing directory nor 'from' are
  owned by the effective user ID"), also accepting either errno.
- Linux-divergence: Linux returns EPERM for sticky violations (well within
  the acceptance set).
- Model: on sticky denial, the model's errno oracle must accept
  {EACCES, EPERM}; do not pin one unless a policy knob narrows it.

### R20. Sticky bit constrains only remove/rename, never create or link-into
- Behavior: XBD 4.5 covers "remove or rename files within that directory"
  only. No POSIX text restricts creating entries, hardlinking into, or
  opening files in a sticky directory ("No mention of the sticky bit or
  S_ISVTX appears" on the link() page — verified). Creating in /tmp-style
  1777 directories is governed only by w+x on the directory (R13).
- Requirement level: MUST (absence of restriction).
- Citation: XBD 4.5; XSH link (verified absence).
- Linux-divergence: Linux's optional hardening sysctls
  (fs.protected_hardlinks, protected_symlinks, protected_regular,
  protected_fifos) add EACCES/EPERM failures for opens/links in sticky
  world-writable directories. These are extensions, NOT POSIX; keep out of
  the model or behind a clearly-labeled knob.
- Model: sticky check appears only in unlink/rmdir/rename(src and dst).

### R21. S_ISVTX on non-directories: unspecified; chmod may ignore
- Behavior: XBD 4.5: "If the S_ISVTX bit is set on a non-directory file,
  the behavior is unspecified." chmod(): "Additional implementation-defined
  restrictions may cause the S_ISUID and S_ISGID bits in mode to be
  ignored, and may cause the S_ISVTX bit in mode to be ignored for
  non-directory files."
- Requirement level: unspecified / implementation-defined.
- errno: none mandated.
- pjdfstest-derived: chmod/11.t: "chmod returns EFTYPE if the effective
  user ID is not the super-user, the mode includes the sticky bit
  (S_ISVTX), and path does not refer to a directory" — FreeBSD returns
  EFTYPE; Darwin/Linux/SunOS permit non-root users to set S_ISVTX on
  non-directories and the change takes effect. (EFTYPE is not a POSIX
  errno.)
- Model: allow setting S_ISVTX on any file type, give it semantics only on
  directories (Linux-realistic); note the unspecified zone in comments.

---

## E. S_ISUID / S_ISGID on regular files: when they are CLEARED

### R22. chown()/fchownat(): clearing is REQUIRED (with an execute-bit precondition)
- Behavior: chown() DESCRIPTION, three consecutive verbatim sentences:
  (a) "If the specified file is a regular file, one or more of the
  S_IXUSR, S_IXGRP, or S_IXOTH bits of the file mode are set, and the
  process does not have appropriate privileges, the set-user-ID (S_ISUID)
  and set-group-ID (S_ISGID) bits of the file mode shall be cleared upon
  successful return from chown()."
  (b) "If the specified file is a regular file, one or more of the
  S_IXUSR, S_IXGRP, or S_IXOTH bits of the file mode are set, and the
  process has appropriate privileges, it is implementation-defined whether
  the set-user-ID and set-group-ID bits are altered."
  (c) "If the chown() function is successfully invoked on a file that is
  not a regular file and one or more of the S_IXUSR, S_IXGRP, or S_IXOTH
  bits of the file mode are set, the set-user-ID and set-group-ID bits may
  be cleared."
  Note all three sentences are conditioned on AT LEAST ONE EXECUTE BIT
  being set. For a regular file with no x bits at all, the spec mandates
  nothing (clearing not required; whether it may still happen is not
  addressed — treat as unspecified).
- Requirement level: MUST clear (unprivileged, regular, ≥1 x bit);
  implementation-defined (privileged, regular, ≥1 x bit); MAY clear
  (non-regular, ≥1 x bit); unspecified (no x bits).
- errno: n/a (side effect of success).
- Citation: XSH chown DESCRIPTION.
- Linux-divergence: Linux clears S_ISUID on chown regardless of x bits,
  and clears S_ISGID only when S_IXGRP is set (S_ISGID without S_IXGRP is
  the mandatory-locking marker and is preserved). Both behaviors fit
  inside the spec's mandatory case but exceed/refine it at the edges.
- Model: on chown success by unprivileged caller of a regular file with
  any x bit: clear both bits (MUST). Everything else behind a knob;
  Linux-mode knob implements the S_IXGRP refinement.

### R23. write()/pwrite(): clearing is only MAY — no privilege condition stated
- Behavior: write() DESCRIPTION (only mention on the page, verified by
  full-page search): "Upon successful completion, where nbyte is greater
  than 0, write() shall mark for update the last data modification and
  last file status change timestamps of the file, and if the file is a
  regular file, the S_ISUID and S_ISGID bits of the file mode may be
  cleared." The spec does NOT require clearing, and does NOT condition the
  permission ("may") on the writer being unprivileged.
- Requirement level: MAY (acceptance-set{clear, keep}).
- Citation: XSH write DESCRIPTION.
- Linux-divergence: Linux DOES clear on write by processes without
  CAP_FSETID (S_ISUID always; S_ISGID only if S_IXGRP set). NFS servers
  commonly replicate this. POSIX permits but does not require it.
- Model: `clearSetidOnWrite: bool` knob; both settings are spec-conformant,
  so the model's errno/state oracle must accept either unless the knob is
  pinned to the SUT's behavior.

### R24. truncate()/ftruncate(): clearing is only MAY
- Behavior: both pages: "the S_ISUID and S_ISGID bits of the file mode may
  be cleared." (Verified on truncate() and ftruncate() pages; same
  timestamps sentence pattern as write().)
- Requirement level: MAY (acceptance-set{clear, keep}).
- Citation: XSH truncate, ftruncate DESCRIPTION.
- Model: reuse the R23 knob (same policy for size-changing writes).

### R25. chmod(): requested S_ISGID is force-CLEARED on group mismatch
- Behavior: chmod() DESCRIPTION, verbatim: "If the calling process does
  not have appropriate privileges, and if the group ID of the file does
  not match the effective group ID or one of the supplementary group IDs
  and if the file is a regular file, bit S_ISGID (set-group-ID on
  execution) in the file's mode shall be cleared upon successful return
  from chmod()." I.e. an unprivileged owner chmod'ing g+s on a file whose
  group they are not in gets a SUCCESSFUL chmod with S_ISGID silently
  stripped — not an error.
- Requirement level: MUST.
- errno: none — the call succeeds.
- Citation: XSH chmod DESCRIPTION.
- Model: apply requested mode, then strip S_ISGID when (!hasPriv &&
  file.gid != egid && file.gid not in sgroups && regular file). Assert
  chmod returns success in this case.

### R26. chmod(): implementations may ignore S_ISUID/S_ISGID in mode
- Behavior: chmod(): "Additional implementation-defined restrictions may
  cause the S_ISUID and S_ISGID bits in mode to be ignored." (Same
  sentence covers S_ISVTX on non-directories, R21.)
- Requirement level: implementation-defined.
- Citation: XSH chmod DESCRIPTION.
- Model: default: honor the bits (subject to R25); note divergence space.

### R27. Creation via open(O_CREAT)/mkdir: mode comes from mode & ~umask; no setid clearing text
- Behavior: open() O_CREAT: "the access permission bits (see <sys/stat.h>)
  of the file mode shall be set to the value of the argument following the
  oflag argument ... modified as follows: a bitwise AND is performed on
  the file-mode bits and the corresponding bits in the complement of the
  process' file mode creation mask." And: "When bits other than the file
  permission bits are set, the effect is unspecified." mkdir(): "The file
  permission bits of the mode argument shall be modified by the file
  creation mask of the process." The open() page contains no text about
  S_ISUID/S_ISGID being cleared at creation (verified absence).
- Requirement level: MUST (perm bits & ~umask); unspecified (non-permission
  bits in mode, i.e. passing S_ISUID/S_ISGID/S_ISVTX in open's mode).
- Citation: XSH open DESCRIPTION (O_CREAT), mkdir DESCRIPTION.
- Model: newMode = reqMode & 0777 & ~umask (treat setid/sticky bits in the
  creation mode as dropped — one legal resolution of "unspecified"; note
  Linux honors mode bits 07777 on mkdir/open minus umask).
- Linux-divergence: Linux applies umask to the full 07777 and keeps
  requested setid/sticky bits on creat/mkdir (except setgid stripping
  under some fs configs, e.g. vfat, or the setgid-dir interaction R39).

---

## F. EACCES vs EPERM across the API

### R28. General errno definitions (the dividing line)
- Behavior: XSH 2.3 Error Numbers, verbatim:
  [EACCES]: "Permission denied. An attempt was made to access a file in a
  way forbidden by its file access permissions."
  [EPERM]: "Operation not permitted. An attempt was made to perform an
  operation limited to processes with appropriate privileges or to the
  owner of a file or other resource."
- Requirement level: MUST (as glossed by each function page).
- Citation: XSH 2.3.
- Model: rule of thumb encoded per-op, not globally: mode-bit/search
  denials → EACCES; ownership/privilege gate failures → EPERM; sticky →
  either (R19).

### R29. chmod(): ownership gate → EPERM
- Behavior: DESCRIPTION: "If the effective user ID of the process does not
  match the owner of the file and the process does not have appropriate
  privileges, the chmod() function shall fail." Mandatory [EPERM]: "The
  effective user ID does not match the owner of the file and the process
  does not have appropriate privileges." [EACCES] on chmod is only for
  path-prefix search denial.
- Requirement level: MUST; errno: EPERM (gate), EACCES (prefix search).
- Citation: XSH chmod DESCRIPTION/ERRORS.
- Model: chmod errno = EPERM iff reached the file but not owner/priv.
  Note: no write permission on the file is needed — a non-writing owner
  can chmod; a writing non-owner cannot.

### R30. chown(): ownership/privilege gate → EPERM (_POSIX_CHOWN_RESTRICTED)
- Behavior: mandatory [EPERM]: "The effective user ID does not match the
  owner of the file, or the calling process does not have appropriate
  privileges and _POSIX_CHOWN_RESTRICTED indicates that such privilege is
  required." DESCRIPTION: where _POSIX_CHOWN_RESTRICTED is in effect
  (it is mandatory on-file in Issue 8 for regular use): "Changing the user
  ID is restricted to processes with appropriate privileges." "Changing
  the group ID is permitted to a process with an effective user ID equal
  to the user ID of the file ... if and only if owner is equal to the
  file's user ID or (uid_t)-1 and group is equal either to the calling
  process' effective group ID or to one of its supplementary group IDs."
  So an unprivileged owner may only "give away" the GROUP, and only to a
  group in their own credential set; never the uid.
- Requirement level: MUST; errno: EPERM (gate), EACCES (prefix search
  only).
- Citation: XSH chown DESCRIPTION/ERRORS.
- Model: chown(uid change) requires hasPriv → else EPERM. chown(gid
  change) requires (euid==file.uid && newgid in {egid} ∪ sgroups) or
  hasPriv → else EPERM. Remember the R22 setid-clearing side effect on
  success.

### R31. futimens()/utimensat(): the classic EACCES/EPERM split
- Behavior — DESCRIPTION, verbatim:
  Current time: "Only a process with the effective user ID equal to the
  user ID of the file, or with write access to the file, or with
  appropriate privileges may use futimens() or utimensat() with a null
  pointer as the times argument or with both tv_nsec fields set to the
  special value UTIME_NOW."
  Explicit times: "Only a process with the effective user ID equal to the
  user ID of the file or with appropriate privileges may use futimens()
  or utimensat() with a non-null times argument that does not have both
  tv_nsec fields set to UTIME_NOW and does not have both tv_nsec fields
  set to UTIME_OMIT."
  Both omitted: "If both tv_nsec fields are set to UTIME_OMIT, no
  ownership or permissions check shall be performed for the file, but
  other error conditions may still be detected (including [EACCES] errors
  related to the path prefix)."
  ERRORS, verbatim:
  [EACCES]: "The times argument is a null pointer, or both tv_nsec values
  are UTIME_NOW, and the effective user ID of the process does not match
  the owner of the file and write access is denied."
  [EPERM]: "The times argument is not a null pointer, does not have both
  tv_nsec fields set to UTIME_NOW, does not have both tv_nsec fields set
  to UTIME_OMIT, the calling process' effective user ID does not match
  the owner of the file, and the calling process does not have
  appropriate privileges."
- Requirement level: MUST; errno: EACCES (set-to-now denied), EPERM
  (explicit-times denied). Mixed cases (one NOW + one OMIT, or one
  explicit) count as "explicit" for the gate since the both-NOW/both-OMIT
  conditions fail → EPERM path.
- Citation: XSH futimens/utimensat DESCRIPTION/ERRORS.
- Model: three-way gate exactly as quoted. This is the cleanest spec
  example of EACCES-vs-EPERM discrimination — good test oracle. (NFS
  SETATTR atime/mtime SET_TO_CLIENT_TIME vs SET_TO_SERVER_TIME maps to
  explicit vs now.)

### R32. unlink() of a directory → EPERM
- Behavior: unlink() [EPERM]: "The file named by path is a directory, and
  either the calling process does not have appropriate privileges or the
  implementation prohibits using unlink() on directories."
- Requirement level: MUST fail unless privileged AND implementation
  allows; errno: EPERM.
- Citation: XSH unlink ERRORS.
- Linux-divergence: Linux always refuses unlink of directories but returns
  EISDIR, not EPERM. Acceptance-set for a portable oracle:
  {EPERM, EISDIR} (EISDIR justified by Linux; POSIX page says EPERM).
  Mark: Linux-divergence.
- Model: refuse dir-unlink with EPERM (POSIX) — accept EISDIR when
  validating against Linux-backed VFS.

### R33. link() to a directory → EPERM
- Behavior: link() [EPERM]: "The file named by path1 is a directory and
  either the calling process does not have appropriate privileges or the
  implementation prohibits using link() on directories."
- Requirement level: MUST (as above); errno: EPERM.
- Citation: XSH link ERRORS.
- Model: refuse hard links to directories, EPERM.

### R34. Search/mode-bit denials → EACCES everywhere
- Behavior: every function page's [EACCES] entries quoted throughout §C
  use EACCES exclusively for search-permission and permission-bit
  denials; no page uses EPERM for a pure mode-bit denial.
- Requirement level: MUST.
- Citation: XSH open/mkdir/unlink/rmdir/rename/link/symlink/chmod/chown
  ERRORS (all quoted above).
- Model: the access-check primitive returns EACCES; EPERM only ever comes
  from ownership/privilege gates (R29-R33) and optionally sticky (R19).

---

## G. access()/faccessat(): the real-ID exception

### R35. access() checks with REAL uid/gid
- Behavior: DESCRIPTION, verbatim: "The checks for accessibility
  (including directory permissions checked during pathname resolution)
  shall be performed using the real user ID in place of the effective
  user ID and the real group ID in place of the effective group ID."
  Note only euid/egid are substituted; the supplementary group IDs are
  not mentioned and thus still participate as-is in the file-group-class
  test (R3 with rgid substituted for egid).
- Requirement level: MUST.
- errno: EACCES — "Permission bits of the file mode do not permit the
  requested access, or search permission is denied on a component of the
  path prefix."
- Citation: XSH access DESCRIPTION/ERRORS.
- Model: access(F_OK|R_OK|W_OK|X_OK) = run R7-R10 with
  {ruid, rgid, sgroups}. All other operations use effective IDs.

### R36. faccessat(AT_EACCESS) switches back to effective IDs
- Behavior: verbatim: "The checks for accessibility (including directory
  permissions checked during pathname resolution) shall be performed
  using the effective user ID and group ID instead of the real user ID
  and group ID as required in a call to access()."
- Requirement level: MUST.
- Citation: XSH access (faccessat AT_EACCESS flag).
- Model: AT_EACCESS ⇒ identical to the ordinary internal check.

### R37. access(X_OK) privileged loophole
- Behavior: verbatim: "If any access permissions are checked, each shall
  be checked individually, as described in XBD 4.7 File Access
  Permissions, except that where that description refers to execute
  permission for a process with appropriate privileges, an implementation
  may indicate success for X_OK even if execute permission is not granted
  to any user." RATIONALE adds: "New implementations are discouraged from
  returning X_OK unless at least one execution permission bit is set."
- Requirement level: implementation-defined (acceptance-set{X_OK ok,
  X_OK EACCES} for privileged caller + no x bits).
- Citation: XSH access DESCRIPTION, RATIONALE.
- Model: if X-probes are modeled at all, accept both outcomes for the
  privileged/no-x-bit cell.

---

## H. Ownership and mode of created files

### R38. Owner of a new file = effective user ID (MUST)
- Behavior: open() O_CREAT, verbatim: "The user ID of the file shall be
  set to the effective user ID of the process; the group ID of the file
  shall be set to the group ID of the file's parent directory or to the
  effective group ID of the process". mkdir(): "The directory's user ID
  shall be set to the process' effective user ID." symlink(): "The
  symbolic link's user ID shall be set to the process' effective user ID."
- Requirement level: MUST (owner); group: see R39.
- Citation: XSH open, mkdir, symlink DESCRIPTION.
- Model: created.uid = euid, unconditionally (root-squash mapping happens
  before, in the creds, not here).

### R39. Group of a new file: acceptance-set{parent dir's gid, egid}; S_ISGID-dir inheritance is NOT POSIX text
- Behavior: open()/mkdir(), verbatim: "the group ID of the file shall be
  set to the group ID of the file's parent directory or to the effective
  group ID of the process". Plus: "Implementations shall provide a way to
  initialize the file's group ID to the group ID of the parent directory.
  Implementations may, but need not, provide an implementation-defined
  way to initialize the file's group ID to the effective group ID of the
  calling process." (mkdir has the identical pair for directories.)
  IMPORTANT: the Issue 8 mkdir and open pages contain NO text tying this
  choice to the parent's S_ISGID bit, and no text about a new
  subdirectory inheriting S_ISGID (verified by explicit search of the
  mkdir page including RATIONALE: "there is no mention of S_ISGID or
  set-group-ID directories"). The familiar rule "S_ISGID on parent ⇒ new
  file gets parent's gid and new subdir also gets S_ISGID" is the
  System V/Linux mechanism for providing the required "way", not spec
  text.
- Requirement level: acceptance-set{parent.gid, egid} (MUST be one of the
  two); the selection mechanism is implementation-defined.
- Citation: XSH open, mkdir DESCRIPTION; verified absence of S_ISGID
  wording on mkdir page.
- Linux-divergence (mechanism, spec-conformant): without S_ISGID on the
  parent, gid = egid (well, fsgid); with S_ISGID on the parent, gid =
  parent.gid, and a new DIRECTORY additionally inherits S_ISGID. Linux
  may also strip S_ISGID from a newly created file whose gid the creator
  is not a member of (vfs "sgid stripping", kernel ≥ 5.19 behavior for
  some paths). BSDs: always parent.gid regardless of S_ISGID.
- Model: `groupPolicy ∈ {BSDParentGid, SysVSetgidDir}` knob. In
  SysVSetgidDir mode: file.gid = parent.hasSetgid ? parent.gid : egid;
  new dirs also copy the S_ISGID bit itself when parent has it
  (Linux-derived rule — label as such, it is NOT quotable POSIX).

### R40. Mode-000 creation: the creation-time check is on the DIRECTORY; the returned fd works
- Behavior: open() [EACCES], verbatim: "Search permission is denied on a
  component of the path prefix, or the file exists and the permissions
  specified by oflag are denied, or the file does not exist and write
  permission is denied for the parent directory of the file to be
  created, or O_TRUNC is specified and write permission is denied." Note
  the exclusive branches: only "the file exists" triggers a check of the
  file's own bits; when it "does not exist" the only check is w on the
  parent. And for the returned descriptor, O_CREAT text, verbatim: "The
  argument following the oflag argument does not affect whether the file
  is open for reading, writing, or for both." Therefore
  open("new", O_CREAT|O_RDWR, 0000) MUST succeed (given w+x on parent)
  and the fd MUST be readable and writable, even though a second
  open("new", O_RDONLY) then fails EACCES — including for the owner.
- Requirement level: MUST.
- errno: EACCES only per the quoted branches.
- Citation: XSH open DESCRIPTION (O_CREAT), ERRORS.
- pjdfstest-derived: the suite's open/chmod tests exercise the same
  owner-locked-out pattern (owner with mode 000 gets EACCES on re-open
  but chmod still works per R29 — chmod needs ownership, not w).
- Model: creation path checks parent only; handle rights derive from
  oflag; the new file's mode constrains only FUTURE opens. This is a
  prime trap for naive models that run the access check against the new
  file's mode.

### R41. umask masks only the file permission bits
- Behavior: umask(), verbatim: "The umask() function shall set the file
  mode creation mask of the process to cmask and return the previous
  value of the mask. Only the file permission bits of cmask ... shall be
  used" and "Permission bit positions that are set in cmask are cleared
  in the mode of the created file."
- Requirement level: MUST.
- Citation: XSH umask DESCRIPTION.
- Model: umask ∈ [0,0777]; applied at open(O_CREAT)/mkdir/mkfifo/symlink
  creation sites (NFS: the client applies umask before sending the mode —
  keep umask in creds but note the NAS wrinkle).

### R42. Symbolic links: mode unspecified and never consulted; ownership set as usual
- Behavior: symlink(), verbatim: "The values of the file mode bits for
  the created symbolic link are unspecified." And: "All interfaces
  specified by POSIX.1-2024 shall behave as if the contents of symbolic
  links can always be read, except that the value of the file mode bits
  returned in the st_mode field of the stat structure is unspecified."
  Ownership: "The symbolic link's user ID shall be set to the process'
  effective user ID. The symbolic link's group ID shall be set to the
  group ID of the parent directory or to the effective group ID of the
  process."
- Requirement level: MUST (readable-contents behavior, ownership);
  unspecified (mode value).
- Citation: XSH symlink DESCRIPTION.
- Model: symlink nodes need uid/gid (for sticky-dir deletion tests, R18 —
  the "owner ID of the file" of a symlink matters!) but no meaningful
  mode; READLINK never permission-fails on the link itself.
- Linux-divergence: Linux reports symlink mode 0777 always; chmod on a
  symlink target follows the link (lchmod absent), fchmodat(...,
  AT_SYMLINK_NOFOLLOW) returns EOPNOTSUPP.

---

## I. NAS / root-squash caveat (commentary, not spec)

### R43. Privilege is a policy knob in NFS-backed filesystems
- Commentary (NOT spec text): NFS servers commonly "root-squash": a
  client-side euid 0 is mapped to an anonymous uid (traditionally
  65534) before any of the above rules run, so "appropriate privileges"
  effectively never holds for remote root; conversely `no_root_squash`
  restores it. Some servers also squash all uids (`all_squash`). Since
  POSIX already declares appropriate privileges implementation-defined
  (R6, XBD 3.21), the clean composition is: (1) a credential-mapping
  policy function creds' = squash(creds) applied at the protocol
  boundary, then (2) the pure POSIX checker of §A/§B with
  hasPriv(creds') = (creds'.euid == 0) as the base-model assumption.
- Requirement level: out of scope for POSIX; NFS-side behavior is
  server-policy.
- Model: keep `squash: Creds -> Creds` and `hasPriv: Creds -> bool` as
  separate, swappable policy knobs; never test `euid == 0` inline in
  operation rules.

---

## Testing notes

1. Exclusive-class matrix. For each perm P in {r,w,x} generate the 8
   modes where P is set/unset independently for owner/group/other, and
   drive with three cred sets (owner-only, group-only-via-egid,
   group-only-via-supplementary, other). Assert the class bit alone
   decides (R5). The killer cases: mode 0077 owner denied everything
   while everyone else allowed; mode 0707 group-member denied while
   owner and other allowed; supplementary-group membership must select
   the group class exactly like egid (R3).
2. Sticky matrix (R18/R19): dimensions = {euid==file.uid} x
   {euid==dir.uid} x {hasPriv} x {file writable by caller} x
   op ∈ {unlink, rmdir, rename-src, rename-dst-overwrite}. Expected:
   allow iff any of the first three holds; the file-writable-only cell is
   implementation-defined (knob); every deny cell accepts
   {EACCES, EPERM}. Remember rename tests sticky at BOTH ends and
   pjdfstest additionally shows same-directory renames succeed when the
   caller owns the file (source-arm satisfied).
3. utimensat oracle (R31): 3 time-arg shapes (both-NOW/null, explicit,
   both-OMIT) x 3 cred relations (owner, non-owner-with-w,
   non-owner-no-w) → 9 cells with distinct EACCES/EPERM/succeed
   outcomes; both-OMIT succeeds even for non-owner-no-w (only path
   search can fail).
4. Setid-clearing suite (R22-R25): chown by owner (gid-only change) on
   a 4755 file must land 0755 (or 0755+impl for privileged); chmod g+s
   by owner not in file's group must succeed with S_ISGID stripped
   (R25 — assert SUCCESS, not error); write/truncate clearing must be an
   acceptance-set check unless the knob is pinned. Include the no-x-bits
   chown case: spec requires nothing — treat any outcome for the setid
   bits as conformant, but flag Linux's asymmetric S_ISUID/S_ISGID rule.
5. Mode-000 paradoxes (R40): (a) create 000 + keep writing via original
   fd; (b) owner re-open fails EACCES; (c) owner chmod 600 succeeds
   (EPERM gate needs ownership only, R29); (d) unlink of a 000 file in a
   non-sticky dir succeeds given parent w+x (R14); (e) root opens the
   000 file fine (R8) but even root cannot X it (R9).
6. Directory r-vs-x split (R11/R12): mode 0311 dir — create/lookup/unlink
   inside OK, opendir fails EACCES; mode 0644 dir — opendir OK, but stat
   of any entry fails EACCES (no search); ensure the model distinguishes
   "read directory" from "traverse directory" as separate permission
   probes.
7. Creation ownership (R38/R39): every create asserts uid==euid; group
   asserted against the active groupPolicy knob; in SysVSetgidDir mode
   also assert subdirectory S_ISGID propagation (labeled Linux-derived).
8. Errno acceptance sets to encode once, centrally: sticky
   {EACCES,EPERM}; unlink(dir) {EPERM} POSIX / {EISDIR} Linux; privileged
   access(X_OK) with no x bits {ok, EACCES}.

## Traps

- T1 (exclusive class): the #1 implementation bug family. "Owner bits OR
  group bits OR other bits" is wrong; so is "try owner, fall back to
  group on deny". The spec picks ONE class (R2-R5) and stops.
- T2 (supplementary groups select the class too): a file gid present only
  in sgroups still puts you in the group class — and therefore LOCKS you
  OUT of other-bits even if other is more permissive (R3+R5).
- T3 (privileged execute): appropriate privileges do not grant execute on
  a file with no x bits anywhere (R9); but they DO grant directory search
  unconditionally (R8). Models that reuse one "x check" helper for both
  execute and search get the privileged row wrong.
- T4 (sticky has four arms in Issue 8): the optional "file is writable by
  the process" arm (R18) is real spec text but implementation-defined —
  a conformance oracle must not hard-require either behavior; Linux says
  no, some historic systems said yes.
- T5 (sticky errno): never pin EACCES or EPERM for sticky denials; the
  page headers literally read "[EPERM] or [EACCES]" in the shall-fail
  list (R19). pjdfstest agrees ("EACCES|EPERM").
- T6 (rename double sticky): sticky is evaluated at the source entry AND
  at an existing destination entry (R19's rename quote); a model that
  only guards the source misses the overwrite-in-sticky-dir denial.
- T7 (chmod is not a write): w on the file neither helps chmod (EPERM
  gate is ownership, R29) nor is needed by the owner; conversely
  utimensat-to-now is the one metadata op where w on the file substitutes
  for ownership (R31).
- T8 (mode-000 owner paradox): owner ≠ access. The owner can chmod,
  chown-group, utimensat-explicit, and be denied read/write/open — all
  simultaneously (R29/R30/R31 vs R5/R40).
- T9 (creation check is parental): open(O_CREAT) on a nonexistent file
  never consults the new file's mode — the [EACCES] branches are
  mutually exclusive on file existence (R40). Also the mode argument
  "does not affect whether the file is open for reading, writing, or for
  both" — the fd's rights come from oflag alone.
- T10 (chown clears setid only with an x bit): all three chown clearing
  sentences require ≥1 of S_IXUSR/S_IXGRP/S_IXOTH set (R22). A 4644 file
  (setuid, no x) chown'd by its owner is NOT required by POSIX to lose
  S_ISUID. Linux clears anyway — divergence to knob.
- T11 (write-clearing is optional in POSIX): asserting "write must clear
  setuid" is a Linux-ism; the spec says "may be cleared" (R23, R24).
  Conversely asserting "must NOT clear" is wrong too — acceptance set.
- T12 (S_ISGID silent strip on chmod): chmod g+s by an owner outside the
  file's group SUCCEEDS with the bit stripped (R25) — models that expect
  EPERM here are wrong; models that keep the bit are wrong too.
- T13 (setgid-dir inheritance isn't quotable POSIX): group inheritance
  from the parent is a POSIX acceptance-set member (R39), but keying it
  off the parent's S_ISGID bit — and propagating S_ISGID to subdirs — is
  Linux/System V mechanism, verified absent from the Issue 8 mkdir page.
  Label those transitions Linux-derived in the model.
- T14 (unlink of directory): POSIX page says EPERM; Linux returns EISDIR.
  Keep an acceptance set or a per-SUT pin (R32).
- T15 (link and sticky/source-perms): no sticky check on link() into a
  sticky dir (R20), and the source-file access check on link() is
  implementation-optional (R13/link quote); Linux's protected_hardlinks
  adds non-POSIX failures — keep off by default.
- T16 (access() real-ID): access() is the only real-ID consumer; its
  supplementary groups still apply, and faccessat(AT_EACCESS) flips back
  to effective (R35/R36). In a NAS model with no setuid execution,
  ruid==euid usually, making this dead code — assert that explicitly
  rather than modeling it wrong.
- T17 (S_ISVTX on non-directories): unspecified per XBD 4.5; FreeBSD
  even rejects setting it (EFTYPE, non-POSIX errno) while Linux permits
  it (pjdfstest chmod/11.t). Keep it storable-but-inert.
