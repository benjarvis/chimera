<!--
SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors

SPDX-License-Identifier: LGPL-2.1-only
-->

# POSIX.1-2024 (Issue 8) rule inventory: pathname resolution, open()/openat(), close()

Sources fetched and verified 2026-08-09 from https://pubs.opengroup.org/onlinepubs/9799919799/ :

- `functions/open.html` ("open" page, Issue 8) — open()/openat() description, flags, ERRORS.
- `functions/close.html` ("close" page, Issue 8) — close()/posix_close().
- `basedefs/V1_chap04.html` ("XBD 4") — 4.4 Directory Operations, 4.5 Directory Protection,
  4.7 File Access Permissions, 4.12 File Times Update, 4.16 Pathname Resolution.
- `basedefs/V1_chap03.html` ("XBD 3") — definitions 3.104, 3.110/3.111, 3.142/3.149/3.150,
  3.184, 3.254/3.255/3.256, 3.364.
- `functions/V2_chap02.html` ("XSH 2") — 2.6 File Descriptor Allocation.
- Issue 7 (2018 ed.) `open.html` and `close.html` fetched from
  https://pubs.opengroup.org/onlinepubs/9699919799/ for wording-diff purposes only (noted where used).

All quotes below are verbatim from the fetched Issue 8 pages unless labeled "Issue 7".
Requirement levels: **MUST** = "shall"; **MUST-fail** = listed under "shall fail if";
**MAY-fail** = listed under "may fail if"; **unspecified** / **undefined** /
**implementation-defined** as the spec says; **acceptance-set{...}** = spec allows any listed
alternative, a conforming implementation may pick either.

---

## A. Pathname resolution (XBD 4.16 + definitions)

**R1. Component-by-component walk.** Each filename in a pathname is looked up in the directory
named by its predecessor; resolution fails if that cannot be done.
Level: MUST. Cite: XBD 4.16 — "Each filename in the pathname is located in the directory
specified by its predecessor ... Pathname resolution shall fail if this cannot be accomplished."
Model: resolution is a fold over the component list carrying a "current directory" inode; each
step can fail with a specific errno.

**R2. Absolute vs relative start.** A pathname beginning with `/` starts at the process root
directory; otherwise at the CWD "or for certain interfaces the directory identified by a file
descriptor passed to the interface" (the *at functions).
Level: MUST. Cite: XBD 4.16 — "If the pathname begins with a <slash>, the predecessor of the
first filename ... shall be taken to be the root directory of the process."
Model: resolver takes a start-directory parameter (root | cwd | dirfd).

**R3. Resolution-for-creation stops at the parent.** When the entry is to be created
immediately after resolution (open with O_CREAT and file absent), only the path prefix is
resolved; the final component is then created by the operation.
Level: MUST. Cite: XBD 4.16 — "When a process resolves a pathname of a directory entry that is
to be created immediately after the pathname is resolved, pathname resolution terminates when
all components of the path prefix of the last component have been resolved."
Model: two resolver entry points: resolve-existing(path) and resolve-parent(path) returning
(parent-dir, last-name).

**R4. Search permission on every prefix directory.** Lack of search (execute) permission on any
component of the path prefix is an EACCES failure. (XBD 4.16 itself does not state the
permission check; it is imposed per-function.)
Level: MUST-fail, errno EACCES. Cite: open page ERRORS — "[EACCES] Search permission is denied
on a component of the path prefix". Access evaluation per XBD 4.7 — "Access shall be granted
if an alternate access control mechanism is not enabled and the requested access permission bit
is set for the class ... to which the process belongs".
Model: at each walk step check x-bit for the caller's class on the directory before lookup.
Class selection per R5.

**R5. Permission class selection.** Owner class = euid matches file uid (XBD 3.150). Group
class = not owner class, and egid or a supplementary gid matches file gid (XBD 3.142; "Other
members of the class may be implementation-defined"). Other class = neither (XBD 3.149). A
process with appropriate privileges is granted read/write/search unconditionally; execute
requires at least one x bit somewhere.
Level: MUST (class precedence); implementation-defined (extra group-class members). Cite: XBD
4.7 — "If a process has appropriate privileges: If read, write, or directory search permission
is requested, access shall be granted. If execute permission is requested, access shall be
granted if execute permission is granted to at least one user by the file permission bits".
Model: pure function access(cred, inode, want) with strict owner>group>other class fall-through
(owner class bits are used even if they deny while group bits would allow — precedence is by
class membership, not by "any bit that allows").

**R6. Intermediate component is a non-directory.** If a prefix component names an existing file
that is neither a directory nor a symlink to a directory, fail ENOTDIR.
Level: MUST-fail, errno ENOTDIR. Cite: open page ERRORS — "[ENOTDIR] A component of the path
prefix names an existing file that is neither a directory nor a symbolic link to a directory".
Model: walk step: if current is not a directory → ENOTDIR (checked before lookup of the next
name).

**R7. Intermediate component missing.** If a prefix component does not exist, fail ENOENT
(this applies even with O_CREAT — O_CREAT only creates the final component).
Level: MUST-fail, errno ENOENT. Cite: open page ERRORS — "[ENOENT] ... O_CREAT is set and a
component of the path prefix of path does not name an existing file".
Model: lookup miss on a non-final component → ENOENT always.

**R8. Empty pathname.** A null (empty) pathname never resolves; open must fail ENOENT.
Level: MUST-fail, errno ENOENT. Cite: XBD 4.16 — "A null pathname shall not be successfully
resolved." open page ERRORS — "[ENOENT] ... path points to an empty string."
Model: guard at entry: path == "" → ENOENT.

**R9. Multiple slashes collapse; leading `//` is special.** "Multiple successive <slash>
characters are considered to be the same as one <slash>, except it is implementation-defined
whether the case of exactly two leading <slash> characters is treated specially" (XBD 3.254);
"more than two leading <slash> characters shall be treated as a single <slash>" (XBD 4.16).
Level: MUST (collapse); implementation-defined (exactly-two-leading-slash).
Model: normalize `a//b` → `a/b`; treat leading `//` as `/` (declare the implementation choice);
`///...` → `/`.

**R10. Dot.** The filename `.` refers to the directory specified by its predecessor.
Level: MUST. Cite: XBD 4.16 — "The special filename dot shall refer to the directory specified
by its predecessor."
Model: no-op walk step, but the predecessor must be a directory (so `file/.` is ENOTDIR by R6)
and search permission on it is still required for the subsequent component.

**R11. Dot-dot; dot-dot at root.** `..` refers to the parent of its predecessor directory. "As
a special case, in the root directory, dot-dot may refer to the root directory itself."
Level: MUST (parent link); acceptance-set{root/.. = root, root/.. = something
implementation-specific} at the root ("may").
Cite: XBD 4.16 — "The special filename dot-dot shall refer to the parent directory of its
predecessor directory."
Model: model parent pointers per directory; pin root/.. == root (the universal choice; note it
is only "may" in the spec). Linux-divergence: none — Linux pins `/..` = `/`.

**R12. Trailing slash requires a directory.** A pathname with ≥1 non-slash character and
trailing slash(es) resolves only if the last component (symlinks followed) resolves "to an
existing directory or a directory entry that is to be created for a directory immediately
after the pathname is resolved". open() never creates directories, so for open a trailing
slash requires an existing directory.
Level: MUST. Cite: XBD 4.16 — "shall not be resolved successfully unless the last pathname
component before the trailing <slash> characters resolves (with symbolic links followed—see
below) to an existing directory".
Errno mapping for open: see R49 (ENOTDIR on existing non-directory), R50 (O_CREAT trailing
slash acceptance-set).
Model: track a boolean had_trailing_slash; after final lookup require is_dir.

**R13. Symlink in a non-final component: always followed.** Symlink expansion is only ever
suppressed when the component "is the last pathname component", the pathname "has no trailing
<slash>", AND "the function is required to act on the symbolic link itself, or certain
arguments direct that the function act on the symbolic link itself". In all other cases the
link contents are prefixed to the remaining pathname.
Level: MUST. Cite: XBD 4.16 — "If all of the following are true, then pathname resolution is
complete: This is the last pathname component ... The pathname has no trailing <slash> ...
the function [acts] on the symbolic link itself. In all other cases, the system shall prefix
the remaining pathname, if any, with the contents of the symbolic link".
Model: non-final symlink → splice contents + remainder, re-resolve; relative contents resolve
from "the directory containing the symbolic link".

**R14. Symlink in the final component of open(): followed by default.** Plain open() is not a
function that acts on the link itself, so a final-component symlink is followed. The only
open() arguments that direct acting on the link itself are O_NOFOLLOW (R33) and O_CREAT|O_EXCL
(R28).
Level: MUST. Cite: open page RATIONALE — "In general, the open() function follows the symbolic
link if path names a symbolic link." (normative basis: XBD 4.16 three-condition rule, R13).
Model: resolve final symlink unless oflag has O_NOFOLLOW, or (O_CREAT|O_EXCL) both set.

**R15. Trailing slash defeats act-on-link.** Because condition 2 of R13 requires "no trailing
<slash>", `open("link/", O_NOFOLLOW)` on a symlink-to-directory follows the link and opens the
directory (no ELOOP).
Level: MUST (derived from R13's conjunction). Cite: XBD 4.16 (same quote as R13).
Model: apply had_trailing_slash before the O_NOFOLLOW check. Linux-divergence: none — Linux
also follows here.

**R16. Empty symlink contents.** If the contents of an encountered symlink are the empty
string: acceptance-set{fail with ENOENT, use the pathname of the directory containing the
symlink in place of the contents}.
Level: acceptance-set, errno ENOENT (first alternative). Cite: XBD 4.16 — "if the contents of
the symbolic link is the empty string, then either pathname resolution shall fail with
functions reporting an [ENOENT] error ... or the pathname of the directory containing the
symbolic link shall be used in place of the contents of the symbolic link."
Model: accept both outcomes; prefer ENOENT as the canonical branch. Linux-divergence: Linux
cannot *create* empty symlinks (symlink("", p) → ENOENT) but a NAS backend can surface one
(e.g. created over NFS by another OS); Linux resolution of an empty-target symlink yields
ENOENT.

**R17. Absolute symlink contents; all-slash contents.** Prefixing is by string substitution;
if the contents consist solely of slashes, "all leading <slash> characters of the remaining
pathname shall be omitted from the resulting combined pathname, leaving only the leading
<slash> characters from the symbolic link contents".
Level: MUST. Cite: XBD 4.16 (quoted).
Model: symlink to "/" + remainder "a/b" → "/a/b"; symlink contents starting with "/" restart at
root.

**R18. Symlink loop: ELOOP mandatory; SYMLOOP_MAX exceeded: may-fail.** A detected loop shall
fail ELOOP. Merely exceeding the implementation's follow limit "may" fail; the limit "shall
not be smaller than {SYMLOOP_MAX}".
Level: MUST-fail (true loop) / MAY-fail (limit), errno ELOOP. Cite: XBD 4.16 — "If the system
detects a loop in the pathname resolution process, pathname resolution shall fail with
functions reporting an [ELOOP] error ... The same may happen if during the resolution process
more symbolic links were followed than the implementation allows. This implementation-defined
limit shall not be smaller than {SYMLOOP_MAX}." Mirrored in open ERRORS: shall-fail "[ELOOP] A
loop exists in symbolic links encountered during resolution of the path argument"; may-fail
"[ELOOP] More than {SYMLOOP_MAX} symbolic links were encountered".
Model: count follows; > bound → ELOOP. A bounded counter subsumes true-cycle detection (any
cycle exceeds the bound), which is the standard implementation technique and conforming.
Linux-divergence: Linux caps at 40 total follows (no cycle detection per se) — conforming.

**R19. Component length.** Any component longer than {NAME_MAX} "the implementation shall
consider this an error" → ENAMETOOLONG (shall-fail in open ERRORS). Whole-path > {PATH_MAX}
(including post-symlink-splice intermediate results) is only MAY-fail ENAMETOOLONG.
Level: MUST-fail (component > NAME_MAX); MAY-fail (path > PATH_MAX), errno ENAMETOOLONG.
Cite: XBD 4.16 — "If any pathname component is longer than {NAME_MAX}, the implementation
shall consider this an error." open ERRORS may-fail — "The length of a pathname exceeds
{PATH_MAX}, or pathname resolution of a symbolic link produced an intermediate result with a
length that exceeds {PATH_MAX}."
Model: abstractable — keep model names short; optionally one abstract "name too long" token.

**R20. Determinism.** Resolution of a given pathname yields the same result for every
interface absent concurrent changes.
Level: MUST. Cite: XBD 4.16 — "Pathname resolution for a given pathname shall yield the same
results when used by any interface in POSIX.1-2024 as long as there are no changes to any
files evaluated during pathname resolution".
Model: a single shared resolver function used by all modeled syscalls.

**R21. Directory-operation atomicity.** Operations that read/search/modify a directory are
atomic and serializable — open(O_CREAT) either fully creates+opens or has no effect.
Level: MUST. Cite: XBD 4.4 — "each operation shall either have its entire effect and succeed,
or shall not affect the file system and shall fail. Furthermore, these operations shall be
serializable". Reinforced by open RETURN VALUE — "If -1 is returned, no files shall be created
or modified."
Model: each syscall is one atomic transition; error transitions leave state unchanged.

---

## B. open()/openat() semantics and flags

**R22. Basic effect.** open creates a NEW open file description (never shared), returns the
lowest available fd, offset 0.
Level: MUST. Cite: open page — "The open file description is new, and therefore the file
descriptor shall not share it with any other process"; "The file offset ... shall be set to
the beginning of the file"; XSH 2.6 — "shall, unless specified otherwise, atomically allocate
the lowest numbered available (that is, not already open in the calling process) file
descriptor".
Model: state has FdTable: fd → ofd; OfdTable: ofd → {file, flags, offset}. Allocate min free fd.

**R23. Exactly one access mode.** "Applications shall specify exactly one of the first five
values (file access modes)": O_EXEC, O_RDONLY, O_RDWR, O_SEARCH, O_WRONLY. Violation is not
given defined behavior (application requirement); note O_RDONLY is historically 0 so
O_RDONLY|O_WRONLY cannot be detected.
Level: MUST (application shall); undefined for the implementation if violated.
Cite: open page — "Applications shall specify exactly one of the first five values (file
access modes) below in the value of oflag".
Model: make access mode an enum, not bits; do not model illegal combinations.

**R24. O_EXEC on a directory / O_SEARCH on a non-directory.** If O_EXEC != O_SEARCH on the
implementation: O_EXEC on a directory shall fail (EISDIR), O_SEARCH on a non-directory shall
fail (ENOTDIR). If they share a value, no such failure is required.
Level: MUST-fail (when values distinct), errno EISDIR / ENOTDIR. Cite: open page — "O_EXEC
Open for execute only (non-directory files). If path names a directory and O_EXEC is not the
same value as O_SEARCH, open() shall fail."; ERRORS "[EISDIR] The named file is a directory
and oflag ... includes O_EXEC when O_EXEC is not the same value as O_SEARCH"; "[ENOTDIR] ...
the path argument names a non-directory file and O_SEARCH was specified when O_SEARCH is not
the same value as O_EXEC."
Model: model O_EXEC/O_SEARCH as distinct enum values with the type checks above.
Linux-divergence: Linux/glibc do not provide O_EXEC/O_SEARCH as distinct flags (musl maps
O_SEARCH/O_EXEC to O_PATH); a NAS model targeting Linux clients may mark these modes optional.

**R25. O_RDWR on a FIFO.** An implementation may reject it: "If path names a FIFO, and the
implementation does not support opening a FIFO for simultaneous read and write, then open()
shall fail" — errno EINVAL ("[EINVAL] The path argument names a FIFO, O_RDWR was specified,
and the implementation considers this an error").
Level: acceptance-set{succeed, EINVAL}. Cite: open page (quoted).
Model: out of scope if FIFOs unmodeled; else a model parameter. Linux-divergence: Linux allows
O_RDWR on FIFOs (succeeds, opens both ends).

**R26. O_CREAT — creation semantics.** If the file exists, O_CREAT has no effect (except with
O_EXCL). If absent (and O_DIRECTORY clear): create a regular file with uid = euid; gid = parent
dir's gid OR process egid (see R27); permission bits = mode & ~umask.
Level: MUST. Cite: open page — "If the file exists, this flag has no effect except as noted
under O_EXCL below. Otherwise, if O_DIRECTORY is not set the file shall be created as a
regular file; the user ID of the file shall be set to the effective user ID of the process;
the group ID of the file shall be set to the group ID of the file's parent directory or to the
effective group ID of the process; and the access permission bits ... shall be set to the
value of the argument following the oflag argument taken as type mode_t modified as follows: a
bitwise AND is performed on the file-mode bits and the corresponding bits in the complement of
the process' file mode creation mask."
Also: "When bits other than the file permission bits are set, the effect is unspecified" (i.e.
setuid/setgid/sticky in mode → unspecified) and "The argument following the oflag argument
does not affect whether the file is open for reading, writing, or for both."
Model: create(inode{type:reg, uid:euid, gid:see R27, mode: m & ~umask, size:0}); ignore/forbid
non-permission bits in mode.

**R27. New-file group ID: acceptance-set.** gid is either the parent directory's gid or the
process egid. "Implementations shall provide a way to initialize the file's group ID to the
group ID of the parent directory. Implementations may, but need not, provide an
implementation-defined way to initialize the file's group ID to the effective group ID of the
calling process."
Level: acceptance-set{parent-dir gid, process egid}; the parent-dir option must exist in the
implementation. Cite: open page (quoted above; also RATIONALE: "Conforming applications should
not assume which group ID will be used.").
Model: accept either value in postcondition checks; or parameterize (BSD-style always-parent
vs SysV egid-unless-setgid-dir). Linux-divergence: Linux uses egid by default, parent gid when
the parent directory is setgid (or with grpid mount option) — both allowed by POSIX.

**R28. O_CREAT|O_EXCL.** Fails EEXIST if the file exists; existence-check + create is atomic
w.r.t. other O_CREAT|O_EXCL opens of the same name; if path names a symlink, fail EEXIST
"regardless of the contents of the symbolic link" (dangling included).
Level: MUST-fail, errno EEXIST. Cite: open page — "If O_CREAT and O_EXCL are set, open() shall
fail if the file exists. The check for the existence of the file and the creation of the file
if it does not exist shall be atomic ... If O_EXCL and O_CREAT are set, and path names a
symbolic link, open() shall fail and set errno to [EEXIST], regardless of the contents of the
symbolic link." ERRORS: "[EEXIST] O_CREAT and O_EXCL are set, and the named file exists."
Model: with O_CREAT|O_EXCL do a no-follow final lookup: any hit (incl. symlink) → EEXIST;
miss → create. Single atomic transition.

**R29. O_EXCL without O_CREAT.** "If O_EXCL is set and O_CREAT is not set, the result is
undefined."
Level: undefined. Cite: open page (quoted).
Model: exclude from the model's input alphabet. Linux-divergence: Linux ignores lone O_EXCL
for regular files (and uses it for block-device exclusivity) — do not test this combination.

**R30. O_TRUNC.** "If the file exists and is a regular file, and the file is successfully
opened O_RDWR or O_WRONLY, its length shall be truncated to 0, and the mode and owner shall be
unchanged. It shall have no effect on FIFO special files or terminal device files. Its effect
on other file types is implementation-defined. The result of using O_TRUNC without either
O_RDWR or O_WRONLY is undefined."
Level: MUST (regular file, write mode); no-effect (FIFO/tty); implementation-defined (other
types, e.g. directories opened O_RDONLY|O_TRUNC — but see R48 for dir+write); undefined
(O_TRUNC with O_RDONLY/O_SEARCH/O_EXEC).
Cite: open page (quoted verbatim above).
Model: if reg && (RDWR|WRONLY): size := 0, keep mode/owner, mark mtime+ctime (R80). Exclude
O_TRUNC|O_RDONLY from the input alphabet (undefined). Linux-divergence: Linux honors
O_RDONLY|O_TRUNC by truncating (with write access required) — but since POSIX says undefined,
a NAS server may do anything; don't test.

**R31. O_APPEND.** "If set, the file offset shall be set to the end of the file prior to each
write."
Level: MUST. Cite: open page (quoted).
Model: store append bit in the OFD; write() transition uses size as offset. (Open itself still
sets offset 0 — R22.)

**R32. O_DIRECTORY.** "If path resolves to a non-directory file, fail and set errno to
[ENOTDIR]."
Level: MUST-fail, errno ENOTDIR. Cite: open page (quoted); ERRORS "[ENOTDIR] ... O_DIRECTORY
was specified and the path argument names a non-directory file."
Note: "If O_CREAT and O_DIRECTORY are set and the requested access mode is neither O_WRONLY
nor O_RDWR, the result is unspecified." (open page). And O_CREAT's create-as-regular-file
clause applies only "if O_DIRECTORY is not set" — the spec never lets open() create a
directory; the O_CREAT|O_DIRECTORY missing-file case has no defined creating behavior.
Level for O_CREAT|O_DIRECTORY (+O_RDONLY): unspecified.
Model: post-resolution type check → ENOTDIR. Exclude O_CREAT|O_DIRECTORY from the alphabet.
Linux-divergence: Linux's O_CREAT|O_DIRECTORY behavior has historically been inconsistent
across kernel versions (documented in open(2) BUGS); avoid.

**R33. O_NOFOLLOW.** "If path names a symbolic link, fail and set errno to [ELOOP]." POSIX
specifies **ELOOP** for this case, verbatim: ERRORS — "[ELOOP] A loop exists in symbolic links
encountered during resolution of the path argument, **or O_NOFOLLOW was specified and the path
argument names a symbolic link**."
Level: MUST-fail, errno ELOOP. Cite: open page (both quotes).
Applies only to the final component with no trailing slash (R13/R15); prefix symlinks are
still followed.
Model: no-follow final lookup; symlink hit → ELOOP. Linux-divergence: none for errno (Linux
also ELOOP; contrast FreeBSD EMLINK). Linux O_PATH|O_NOFOLLOW opens the link itself — O_PATH
is not POSIX.

**R34. O_NONBLOCK on FIFOs.** With O_RDONLY: return without delay. With O_WRONLY: "shall
return an error if no process currently has the file open for reading" → ENXIO (mandatory:
"[ENXIO] O_NONBLOCK is set, the named file is a FIFO, O_WRONLY is set, and no process has the
file open for reading"). Without O_NONBLOCK: reader blocks until a writer opens, writer blocks
until a reader opens.
Level: MUST / MUST-fail, errno ENXIO. Cite: open page (quoted).
For non-FIFO, non-device files: "the O_NONBLOCK flag shall not cause an error, but it is
unspecified whether the file status flags will include the O_NONBLOCK flag."
Model: if FIFOs modeled: track per-file reader/writer open counts; O_NONBLOCK|O_WRONLY with
readers==0 → ENXIO; blocking opens as intermediate "waiting" states. For regular files:
O_NONBLOCK is a harmless no-op (unspecified whether flag is retained).

**R35. O_TTY_INIT, O_NOCTTY, O_CLOEXEC, O_CLOFORK, O_SYNC/O_DSYNC/O_RSYNC.** Terminal-init
and fd-flag behavior; sync flags affect I/O completion integrity only.
Level: out of scope for a NAS filesystem model (no terminals; fd flags don't touch FS state;
sync flags don't change visible FS state transitions).
Cite: open page O_TTY_INIT/O_CLOEXEC/O_CLOFORK/O_DSYNC/O_SYNC/O_RSYNC paragraphs.
Model: exclude from alphabet; optionally carry O_CLOEXEC as inert OFD metadata.

**R36. openat() equivalence.** "The openat() function shall be equivalent to the open()
function except in the case where path specifies a relative path. In this case the file to be
opened is determined relative to the directory associated with the file descriptor fd instead
of the current working directory." Hence an absolute path ignores dirfd entirely (per-function
errors R56-R58 are all conditioned on "not ... an absolute path").
Level: MUST. Cite: open page (quoted).
Model: one open transition parameterized by start-dir = (path absolute ? root : dirfd-dir).

**R37. AT_FDCWD.** "If openat() is passed the special value AT_FDCWD in the fd parameter, the
current working directory shall be used and the behavior shall be identical to a call to
open()."
Level: MUST. Cite: open page (quoted).
Model: AT_FDCWD → start-dir = cwd; skip R56-R58 dirfd checks.

---

## C. errno matrix for open()/openat() ("shall fail if" unless noted)

**R38. EACCES — four distinct causes.** "Search permission is denied on a component of the
path prefix, or the file exists and the permissions specified by oflag are denied, or the file
does not exist and write permission is denied for the parent directory of the file to be
created, or O_TRUNC is specified and write permission is denied."
Level: MUST-fail, errno EACCES. Cite: open page ERRORS (quoted verbatim).
Breakdown for the model:
  (a) prefix-dir search denied (per component, R4);
  (b) existing file: mode-vs-oflag — O_RDONLY needs r, O_WRONLY needs w, O_RDWR needs r+w,
      O_SEARCH needs x/search on the dir, O_EXEC needs x on the file;
  (c) O_CREAT and file absent: parent dir lacks w (note: parent needs w; POSIX does not
      require x to be checked again beyond the prefix walk — the parent IS the last prefix
      component, so its x was already required);
  (d) O_TRUNC and write permission denied on the file.
Also RATIONALE (informative): "POSIX.1-2024 permits [EACCES] to be returned for conditions
other than those explicitly listed." — treat EACCES as an always-allowed alternative where an
implementation enforces extra checks.
Model: evaluate in walk order: (a) during prefix; then existence split → (b)/(c); then (d).

**R39. EEXIST.** "O_CREAT and O_EXCL are set, and the named file exists." (Symlink case: R28,
even dangling.)
Level: MUST-fail, errno EEXIST. Cite: open page ERRORS.
Model: only reachable with O_CREAT|O_EXCL.

**R40. EISDIR — three causes.** "The named file is a directory and oflag includes O_WRONLY or
O_RDWR, or includes O_CREAT without O_DIRECTORY, or includes O_EXEC when O_EXEC is not the
same value as O_SEARCH."
Level: MUST-fail, errno EISDIR. Cite: open page ERRORS (quoted).
Note the middle clause is new in Issue 8 wording: open("dir", O_RDONLY|O_CREAT) → EISDIR.
Model: post-resolution: is_dir && (W|RDWR || O_CREAT&&!O_DIRECTORY || O_EXEC) → EISDIR.
Linux-divergence: none — Linux returns EISDIR for O_CREAT on an existing directory.

**R41. ENOENT — three causes.** "O_CREAT is not set and a component of path does not name an
existing file, or O_CREAT is set and a component of the path prefix of path does not name an
existing file, or path points to an empty string."
Level: MUST-fail, errno ENOENT. Cite: open page ERRORS (quoted verbatim).
Model: (i) final-component miss without O_CREAT; (ii) any prefix miss regardless of O_CREAT;
(iii) empty path. Also the dangling-final-symlink case: following a symlink whose target does
not exist re-enters resolution and ends in a component miss → ENOENT via (i) (or creation via
O_CREAT at the target name — see Traps T6).

**R42. ENOENT-or-ENOTDIR acceptance-set — O_CREAT with trailing slash.** "[ENOENT] or
[ENOTDIR] O_CREAT is set, and the path argument contains at least one non-<slash> character
and ends with one or more trailing <slash> characters. If path without the trailing <slash>
characters would name an existing file, an [ENOENT] error shall not occur."
Level: MUST-fail, acceptance-set{ENOENT, ENOTDIR}, narrowed to {ENOTDIR} when the trimmed
path names an existing file. Cite: open page ERRORS (quoted verbatim).
Note: with O_CREAT and trailing slash the call always fails — open cannot create a directory
(R12); if the entry exists and IS a directory, the failure is EISDIR via R40's O_CREAT clause.
Model: O_CREAT && trailing_slash: target exists(non-dir) → ENOTDIR; exists(dir) → EISDIR;
absent → {ENOENT|ENOTDIR} (accept either). Linux-divergence: Linux returns EISDIR for
`open("x/", O_CREAT)` when x absent — this is outside the POSIX acceptance set
{ENOENT,ENOTDIR}; flag as a deviation to tolerate if mirroring Linux.

**R43. ENOTDIR — four causes.** "A component of the path prefix names an existing file that
is neither a directory nor a symbolic link to a directory; or O_CREAT and O_EXCL are not
specified, the path argument contains at least one non-<slash> character and ends with one or
more trailing <slash> characters, and the last pathname component names an existing file that
is neither a directory nor a symbolic link to a directory; or O_DIRECTORY was specified and
the path argument names a non-directory file; or the path argument names a non-directory file
and O_SEARCH was specified when O_SEARCH is not the same value as O_EXEC."
Level: MUST-fail, errno ENOTDIR. Cite: open page ERRORS (quoted verbatim).
Model: causes: (i) prefix non-dir (R6); (ii) trailing slash on existing non-dir (no
O_CREAT|O_EXCL); (iii) O_DIRECTORY on non-dir (R32); (iv) O_SEARCH on non-dir (R24).

**R44. ELOOP.** Shall-fail: resolution loop, or O_NOFOLLOW on final symlink (R33). May-fail:
> SYMLOOP_MAX follows (R18).
Level: MUST-fail / MAY-fail, errno ELOOP. Cite: open page ERRORS (quotes in R18/R33).
Model: single bounded-follow counter + O_NOFOLLOW check.

**R45. EINVAL.** Shall-fail: FIFO+O_RDWR where implementation rejects (R25); or "synchronized
I/O flags were specified and the implementation does not support synchronized I/O for the
file". May-fail: "The value of the oflag argument is not valid."
Level: conditional MUST-fail / MAY-fail, errno EINVAL. Cite: open page ERRORS.
Model: abstract away (no SIO modeling; keep oflag alphabet valid-only).

**R46. ENXIO.** (a) FIFO write-only nonblocking with no reader (R34) — MUST-fail. (b) "The
named file is a character special or block special file, and the device associated with this
special file does not exist" — MUST-fail.
Level: MUST-fail, errno ENXIO. Cite: open page ERRORS.
Model: (a) only if FIFOs modeled; (b) out of scope for NAS (device nodes stored but their
devices are client-side; note NFS/SMB servers typically never open device nodes server-side).

**R47. EROFS.** "The named file resides on a read-only file system and either O_WRONLY,
O_RDWR, O_CREAT (if the file does not exist), or O_TRUNC is set in the oflag argument."
Level: MUST-fail, errno EROFS. Cite: open page ERRORS (quoted).
Note the parenthetical: O_CREAT on an EXISTING file on a read-only FS with O_RDONLY does NOT
give EROFS.
Model: boolean ro_fs; check after resolution: (W|RDWR) || O_TRUNC || (O_CREAT && !exists) →
EROFS. Order vs EACCES/ENOENT is unspecified — accept either error when multiple apply (see
Traps T10).

**R48. EILSEQ (new in Issue 8).** "O_CREAT was specified, the file did not exist, and the last
pathname component of path is not a portable filename and cannot be created in the target
directory."
Level: MUST-fail (when the FS cannot create the name), errno EILSEQ. Cite: open page ERRORS
(quoted). RATIONALE encourages rejecting names containing newline bytes.
Model: relevant for NAS (character-set-restricted backends, e.g. SMB name rules): a
per-directory/per-fs predicate can_create(name); false → EILSEQ.

**R49. Resource/limit errors — abstract away.** EMFILE ("All file descriptors available to
the process are currently open"), ENFILE ("maximum allowable number of files ... open in the
system"), ENOSPC ("The directory or file system that would contain the new file cannot be
expanded, the file does not exist, and O_CREAT is specified"), EINTR ("A signal was caught"),
EOVERFLOW (off_t overflow), ENAMETOOLONG (R19).
Level: MUST-fail conditions but environment-dependent. Cite: open page ERRORS.
Model: abstract away (model has unbounded tables and no signals), or expose a single
nondeterministic "resource failure" transition that leaves state unchanged (R21) if you want
robustness testing. May-fail EOPNOTSUPP (socket path) and ETXTBSY (shared-text file being
executed, write open) likewise out of scope.

---

## D. openat() specifics (per-function "shall fail if" clauses)

**R50. dirfd search-permission check depends on access mode (O_SEARCH exemption).** "If the
access mode of the open file description associated with the file descriptor is not O_SEARCH,
the function shall check whether directory searches are permitted using the current
permissions of the directory underlying the file descriptor. If the access mode is O_SEARCH,
the function shall not perform the check." Corresponding error: "[EACCES] The access mode of
the open file description associated with fd is not O_SEARCH and the permissions of the
directory underlying fd do not permit directory searches."
Level: MUST / MUST-fail, errno EACCES. Cite: open page DESCRIPTION + ERRORS (quoted verbatim).
Wording history: the Issue 7 2018 edition already carries this exact "access mode ... is not
O_SEARCH" text (applied via POSIX.1-2008 TC2, XSH/TC2-2008/0236); the original 2008 text keyed
on how the fd "was opened". Issue 8 keeps the TC2 formulation: the check uses the OFD's access
mode and the directory's CURRENT permissions at openat() time, not permissions at dirfd-open
time.
Model: OFD stores access mode; openat with relative path: if mode != O_SEARCH, require x on
dirfd's directory with current perms → else EACCES. Linux-divergence: Linux has no O_SEARCH;
it checks search permission during the walk with current permissions (and O_PATH fds are
usable as dirfd).

**R51. dirfd must be a valid fd open for reading or searching.** "[EBADF] The path argument
does not specify an absolute path and the fd argument is neither AT_FDCWD nor a valid file
descriptor open for reading or searching."
Level: MUST-fail, errno EBADF. Cite: open page ERRORS (quoted verbatim).
Note: a dirfd opened O_WRONLY (were that possible for a directory — it is not, R40) or O_EXEC
is not "open for reading or searching" → EBADF. Practically: dirfd must be O_RDONLY or
O_SEARCH.
Model: openat(fd,...) with relative path: fd unmapped → EBADF; mapped but access mode not in
{O_RDONLY, O_RDWR?, O_SEARCH} → EBADF. (Spec says "reading or searching"; O_RDWR on a
directory is impossible per R40, so the practical set is {O_RDONLY, O_SEARCH}.)
Linux-divergence: Linux accepts any fd type-wise and fails ENOTDIR for non-dirs; it does not
enforce an access-mode precondition (even O_PATH fds work).

**R52. dirfd not a directory.** "[ENOTDIR] The path argument is not an absolute path and fd is
a file descriptor associated with a non-directory file."
Level: MUST-fail, errno ENOTDIR. Cite: open page ERRORS (quoted).
Model: relative path && fd maps to non-dir → ENOTDIR (checked after EBADF validity).

**R53. Absolute path ignores dirfd.** All three openat-specific clauses (R50-R52) are
conditioned on the path being relative; with an absolute path "the behavior shall be identical
to a call to open()" (R36) — even a closed/garbage dirfd is not an error.
Level: MUST (derived: no error clause applies). Cite: open page DESCRIPTION + ERRORS
conditions ("does not specify an absolute path", "is not an absolute path").
Model: absolute path branch skips all dirfd checks. Linux-divergence: none.

---

## E. close()

**R54. Deallocation.** "The close() function shall deallocate the file descriptor indicated by
fildes. To deallocate means to make the file descriptor available for return by subsequent
calls to open() or other functions that allocate file descriptors."
Level: MUST. Cite: close page DESCRIPTION.
Model: remove fd from FdTable; freed number becomes the lowest-free candidate again (R22).

**R55. Process-owned lock drop — on the FILE, via ANY fd.** "All process-owned file locks that
the calling process owns on the file associated with the file descriptor shall be unlocked."
Note it says "on the file", not "on the open file description": closing ANY descriptor that
refers to the file releases ALL of the process's process-owned (fcntl F_SETLK-style) locks on
that file, including locks acquired through other fds.
Level: MUST. Cite: close page DESCRIPTION (quoted verbatim).
Wording history: Issue 7 said "All outstanding record locks owned by the process on the file
associated with the file descriptor shall be removed (that is, unlocked)." Issue 8 (Austin
Group Defect 768) renames these "process-owned file locks" to distinguish them from new
OFD-owned locks, which are NOT dropped by close of an unrelated fd (they belong to the OFD and
die with it).
Model: Locks: (file, owner=pid, range, type). close(fd): remove all lock records with
owner==pid on file(fd). If modeling OFD locks: owner==ofd records removed only at OFD free
(R56). Linux-divergence: none — Linux F_SETLK matches; F_OFD_SETLK matches OFD semantics.

**R56. OFD freeing.** "When all file descriptors associated with an open file description have
been closed, the open file description shall be freed."
Level: MUST. Cite: close page DESCRIPTION.
Model: refcount OFDs (dup/fork share them); free at zero; OFD-owned locks die here.

**R57. Last-close removal of unlinked files.** "If the link count of the file is 0, when all
file descriptors associated with the file are closed, the space occupied by the file shall be
freed and the file shall no longer be accessible." (XBD 3.184: last close = "When a process
closes a file, resulting in the file not being an open file within any process." XBD 3.188:
link count = "The number of directory entries that refer to a particular file.")
Level: MUST. Cite: close page DESCRIPTION (quoted verbatim).
So: unlink of an open file leaves the file accessible through existing fds; actual removal
happens at the system-wide last close. (Exception in spec text: mmap'd/shared-memory
references keep contents until unreferenced — out of scope.)
Model: inode has nlink and open-fd count (across all modeled processes); delete inode when
nlink==0 && open_count==0. This is THE silly-rename driver for NFS models: NFSv3 servers
cannot express "open" state, hence client-side .nfsXXXX renames — a NAS model should keep the
POSIX rule at the VFS layer and let protocol layers deviate.

**R58. close errors.** Shall-fail: "[EBADF] The fildes argument is not a open file
descriptor"; "[EINPROGRESS] The function was interrupted by a signal and fildes was closed but
the close operation is continuing asynchronously." May-fail: EINTR (only if
POSIX_CLOSE_RESTART nonzero — "in which case fildes is still open"), EIO. "For all other error
situations (except for [EBADF] where fildes was invalid), fildes shall be closed."
Level: MUST-fail EBADF; EINTR/EINPROGRESS/EIO out of scope for the model (signal/I/O
environment). close never returns EAGAIN/EWOULDBLOCK ("shall not return").
Cite: close page ERRORS + DESCRIPTION.
Model: fd unmapped → EBADF, state unchanged; otherwise close always succeeds and always
removes the fd (even the EIO case closes the fd — a model can treat close as infallible after
the EBADF guard).

**R59. FIFO drain on last close.** "When all file descriptors associated with a pipe or FIFO
special file are closed, any data remaining in the pipe or FIFO shall be discarded."
Level: MUST. Cite: close page DESCRIPTION. Model: only if FIFOs modeled.

---

## F. Timestamp effects of open (XBD 4.12 + open page)

**R60. O_CREAT creating a new file.** "If O_CREAT is set and the file did not previously
exist, upon successful completion, open() shall mark for update the last data access, last
data modification, and last file status change timestamps of the file and the last data
modification and last file status change timestamps of the parent directory."
Level: MUST. Cite: open page (quoted verbatim).
Model: on create: file.{atime,mtime,ctime} := now-mark; parent.{mtime,ctime} := now-mark.

**R61. O_TRUNC on an existing file.** "If O_TRUNC is set and the file did previously exist,
upon successful completion, open() shall mark for update the last data modification and last
file status change timestamps of the file."
Level: MUST. Cite: open page (quoted verbatim).
Note the literal text does not repeat O_TRUNC's regular-file/write-mode conditions and has no
"only if size changed" condition (unlike ftruncate): truncating an already-empty file on a
successful O_WRONLY|O_TRUNC open still marks mtime+ctime by the letter of this clause.
Model: successful open with O_TRUNC on pre-existing (regular, write-mode) file: mark
file.{mtime,ctime} even when size was already 0. Linux-divergence: none (Linux updates
mtime/ctime on O_TRUNC open unconditionally).

**R62. Plain open marks nothing.** No clause marks any timestamp for a plain open (no
creation, no truncation). atime is marked by read(), not by open().
Level: MUST (absence of requirement + XBD 4.12: functions indicate "which of the appropriate
timestamps shall be marked for update"; unlisted updates must be documented).
Cite: open page (only the two clauses above); XBD 4.12 — "If an implementation ... marks for
update one of these timestamps in a place or time not specified by POSIX.1-2024, this shall be
documented, except that any changes caused by pathname resolution need not be documented."
Model: open(existing, no O_TRUNC) leaves all timestamps unmarked.

**R63. Mark-for-update is deferred but must materialize.** "An implementation may update
timestamps that are marked for update immediately, or it may update such timestamps
periodically ... All timestamps that are marked for update shall be updated when the file
ceases to be open by any process or before a fstat(), fstatat(), fsync(), futimens(), lstat(),
stat(), utimensat(), or utimes() is successfully performed on the file." No marks on read-only
filesystems.
Level: MUST (materialize-before-stat); unspecified (other update points). Cite: XBD 4.12
(quoted).
Model: either update eagerly (simplest, conforming) or model a "pending mark" set flushed
before stat-like observations — eager update is observationally equivalent for a
model-based tester that only observes via stat.

---

## Testing notes (what a model-based tester should exercise)

1. **Resolution walk product space**: for each of {prefix component missing, prefix component
   is regular file, prefix component is symlink→dir, symlink→file, symlink→missing,
   dangling symlink chain, symlink cycle, empty-target symlink}, × {with/without O_CREAT,
   O_NOFOLLOW}: assert the errno of R6/R7/R16/R18/R41 and that failed opens change nothing
   (R21).
2. **Final-component symlink matrix**: plain open (follows, R14); O_NOFOLLOW → ELOOP (R33);
   O_CREAT|O_EXCL on live and dangling symlink → EEXIST (R28); O_CREAT (no O_EXCL) on
   dangling symlink → creates the TARGET (R41/T6); trailing slash + O_NOFOLLOW on
   symlink→dir → succeeds (R15).
3. **Trailing slash matrix**: `f/` for f ∈ {regular, dir, symlink→reg, symlink→dir, missing},
   × {plain, O_CREAT, O_CREAT|O_EXCL, O_DIRECTORY}: expected {ENOTDIR, ok, ENOTDIR, ok,
   ENOENT} for plain; O_CREAT cases per R42 acceptance-set; record which branch the SUT picks.
4. **Permission planes**: search-denied at each prefix depth (EACCES per component); file
   perms vs each access mode (r/w/rw); create in non-writable dir; O_TRUNC on non-writable
   file; owner-class-denies-but-group-allows (must still deny — class precedence R5);
   appropriate-privileges override.
5. **O_CREAT attribute postconditions**: uid==euid; gid ∈ {parent gid, egid} (record which);
   mode == arg & ~umask for several umasks; setuid bit in mode arg → don't assert (unspecified
   R26); size==0; timestamps R60 on file AND parent; O_CREAT on existing file leaves
   attributes and timestamps untouched.
6. **O_EXCL atomicity**: concurrent O_CREAT|O_EXCL races on one name — exactly one winner,
   loser gets EEXIST, both observe consistent directory state (R21/R28).
7. **O_TRUNC**: existing sizes {0, small, large} → size 0, mode/owner unchanged, mtime+ctime
   marked (R61 including the size-0 case); O_TRUNC absent → size unchanged; O_TRUNC|O_RDONLY
   excluded (undefined R30).
8. **EISDIR triple**: dir with O_WRONLY, O_RDWR, O_RDONLY|O_CREAT (R40).
9. **openat**: AT_FDCWD ≡ open; relative path via dirfd; absolute path with closed/bogus/
   non-dir dirfd (must succeed, R53); dirfd = regular-file fd (ENOTDIR R52); dirfd closed
   (EBADF R51); dir permissions changed after dirfd opened — current perms govern (R50);
   O_SEARCH dirfd bypasses the search check (R50) where O_SEARCH exists.
10. **close/last-close**: unlink-while-open keeps fd usable (read/write/fstat) until
    system-wide last close, then inode gone (R57); two fds to one file + one process lock →
    closing EITHER fd drops the lock (R55); dup'd fds: OFD (offset/flags) freed only at last
    close of the OFD (R56); close(fd) then reuse: freed number is the next allocated (R22/R54);
    close(bad fd) → EBADF and no state change.
11. **Deferred timestamps**: if the SUT defers, verify stat forces materialization (R63) —
    over NFS, weak-cache-consistency and attribute caching will fight this; test against the
    server's view.

## Traps (commonly gotten wrong; spec-vs-Linux divergences)

**T1. O_NOFOLLOW errno is ELOOP in POSIX** — not ENOTDIR, not EMLINK. Linux agrees; FreeBSD
returns EMLINK (divergence to tolerate only if BSD backends matter). And O_NOFOLLOW guards
ONLY the final component — prefix symlinks are followed regardless (R13/R33).

**T2. Trailing slash defeats O_NOFOLLOW and act-on-link** (R15): `open("link/",O_NOFOLLOW)` on
symlink→dir opens the directory. All three XBD conditions must hold for act-on-link.

**T3. New-file gid is an acceptance set** (R27): parent-dir gid and egid are BOTH conforming.
Linux picks egid unless the parent is setgid. An NFS server backed by a different OS may pick
parent gid always (BSD). Don't hard-code either.

**T4. EACCES class precedence** (R5): if euid owns the file, ONLY the owner bits count — mode
0077 denies the owner read even though "others" have rwx. People model "any matching bit
grants" and get this wrong.

**T5. O_CREAT does not create prefix directories** (R7/R41): missing intermediate → ENOENT
even with O_CREAT; only the final component is created.

**T6. O_CREAT through a dangling symlink creates the target** (R14/R28): without O_EXCL, the
final symlink is followed; if its target name is absent, the file is created AT THE TARGET
path. Only O_CREAT|O_EXCL refuses (EEXIST) — "regardless of the contents of the symbolic
link". Security-motivated per RATIONALE.

**T7. open("dir", O_RDONLY|O_CREAT) is EISDIR in Issue 8** (R40) — many suites expect success
because O_CREAT "has no effect" on existing files; Issue 8's EISDIR list explicitly includes
"O_CREAT without O_DIRECTORY". Linux already behaved this way.

**T8. O_CREAT trailing-slash on a missing name**: POSIX acceptance set is {ENOENT, ENOTDIR}
(R42); Linux returns EISDIR here — outside the POSIX set. A NAS server copying Linux deviates
from POSIX; a model should encode POSIX's set and register the Linux value as a known
deviation. Linux-divergence: confirmed behavioral difference class.

**T9. EROFS is not blanket** (R47): O_RDONLY (even with O_CREAT when the file exists) on a
read-only FS succeeds. Also XBD 4.12: no timestamp marks at all on read-only filesystems —
atime does not "pend" either.

**T10. Error precedence is unspecified.** When several shall-fail conditions hold (e.g.
search-denied prefix + missing file, or EROFS + EACCES), POSIX does not order them; a model
should accept any of the applicable errnos (acceptance-set over the enabled error rules)
rather than fixing Linux's walk order.

**T11. close drops locks on the FILE, not the fd** (R55): lock with fd1, close fd2 (same file,
same process) → lock gone. Unchanged in spirit since Issue 7; Issue 8 scopes it to
"process-owned" locks — OFD-owned locks survive unrelated closes. Any NAS lock model must key
process-owned locks by (process, file), not by fd or OFD.

**T12. close is not "undo"**: failed close (except EBADF) still closes the fd (R58); and
close never returns EAGAIN. Retrying close on error is a use-after-free of the fd number.

**T13. Unlinked-but-open files** (R57): removal happens at the LAST close system-wide, not
per-process. Over NFSv3 this is unimplementable server-side (stateless) — clients silly-rename;
NFSv4 has OPEN state enabling correct server behavior. Keep the POSIX rule in the VFS model;
treat protocol behavior as a refinement obligation, not a model change.

**T14. Empty symlink target is an acceptance set** (R16), not plain ENOENT — the "directory
containing the symbolic link" alternative is conforming. Linux can't create such links locally
but a NAS backend can hold them.

**T15. openat dirfd checks are Issue-8/TC2 "current permissions"** (R50): dropping x from the
directory after opening dirfd makes later openat calls fail EACCES (unless dirfd is O_SEARCH).
Testers caching "dirfd was fine at open time" get this wrong. Also EBADF (not ENOTDIR/EACCES)
is the errno for a dirfd not open for reading or searching (R51) — Linux does not enforce
this precondition at all (Linux-divergence).

**T16. Plain open bumps no timestamps** (R62) — not even atime. atime moves on read(). NFS
servers often bump atime on OPEN or READ differently (relatime etc. are mount-level
non-conformances); assert only the POSIX marks.

**T17. O_TRUNC timestamp fires even at size 0** (R61) — unlike ftruncate, the open() O_TRUNC
clause is unconditioned on a size change.

**T18. `//` prefix** (R9): exactly two leading slashes are implementation-defined (UNC-style
namespaces); three or more collapse to `/`. A model can normalize `//` = `/` but should
declare it as the chosen implementation behavior.
