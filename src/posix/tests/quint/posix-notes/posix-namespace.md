<!--
SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors

SPDX-License-Identifier: LGPL-2.1-only
-->

# POSIX.1-2024 (Issue 8) — Namespace Operations Rule Inventory

Source: The Open Group Base Specifications Issue 8, IEEE Std 1003.1-2024,
https://pubs.opengroup.org/onlinepubs/9799919799/ (functions/<name>.html, basedefs/V1_chap04.html).
All quotes below were verified against the live Issue 8 pages on 2026-08-09. No Issue 7 fallback was needed.

Requirement-level vocabulary used below:
- **MUST** — "shall" language in the normative text.
- **acceptance-set{A,B}** — the spec explicitly permits either errno; a conforming test must accept both.
- **may-fail** — errno listed under "These functions may fail"; a conforming implementation may return success or a different error in that situation.
- **implementation-defined / unspecified** — as marked in the spec.
- **Model:** — one-line advice for the Quint model.
- **Linux-divergence:** — behavior where Linux is known to differ from or narrow the POSIX text (from implementation knowledge, not the spec; verify empirically before encoding).

Scope notes for the model: single filesystem (EXDEV unreachable), no resource limits (EMLINK/ENOSPC/ENAMETOOLONG/EILSEQ out of scope unless noted), no I/O errors (EIO out of scope).

---

## 0. Cross-cutting XBD rules (apply to several functions)

**R1. Sticky-bit directory protection (XBD 4.5).**
Behavior: In a writable directory with S_ISVTX set, removal/rename of entries is restricted.
Level: MUST (with one implementation-defined arm).
Citation: XBD 4.5 Directory Protection: "If a directory is writable and the mode bit S_ISVTX is set on the directory, a process may remove or rename files within that directory only if one or more of the following is true: The effective user ID of the process is the same as that of the owner ID of the file. The effective user ID of the process is the same as that of the owner ID of the directory. The process has appropriate privileges. Optionally, the file is writable by the process. Whether or not files that are writable by the process can be removed or renamed is implementation-defined."
Errnos: at the function level, acceptance-set{EPERM, EACCES} (see per-function rules).
Model: `stickyOk(dir, entry, cred) = cred.euid == entry.uid or cred.euid == dir.uid or privileged(cred)`; treat the "file is writable" arm as an implementation-defined FeatureMode toggle (off = strict).

**R2. S_ISVTX on a non-directory.**
Behavior: Sticky bit on non-directory files has no defined meaning.
Level: unspecified.
Citation: XBD 4.5: "If the S_ISVTX bit is set on a non-directory file, the behavior is unspecified."
Model: Allow storing the bit on any inode; only evaluate it on directories.

**R3. Trailing slash requires a directory (XBD 4.16 Pathname Resolution).**
Behavior: `name/` resolves only if `name` is (or is being created as) a directory.
Level: MUST.
Citation: XBD 4.16: "A pathname that contains at least one non-<slash> character and that ends with one or more trailing <slash> characters shall not be resolved successfully unless the last pathname component before the trailing <slash> characters resolves (with symbolic links followed) to an existing directory or a directory entry that is to be created for a directory immediately after the pathname is resolved."
Errnos: ENOTDIR (existing non-dir), ENOENT or ENOTDIR per function (nonexistent; see per-function rules).
Model: Model a boolean `trailingSlash` on each path argument; reject non-directory outcomes.

**R4. Symbolic link with empty contents.**
Behavior: Resolving through a symlink whose contents are the empty string either fails or substitutes the containing directory.
Level: acceptance-set{fail with ENOENT, substitute containing directory}.
Citation: XBD 4.16: "if the contents of the symbolic link is the empty string, then either pathname resolution shall fail with functions reporting an [ENOENT] error ... or the pathname of the directory containing the symbolic link shall be used in place of the contents of the symbolic link."
Model: If empty-target symlinks are representable, accept either outcome on traversal; simpler: prevent creating them (see R70) and make this state unreachable.

**R5. Dot and dot-dot as names.**
Behavior: dot refers to the directory itself; dot-dot to its parent. Physical dot/dot-dot entries are not required to exist in every directory.
Level: MUST (meaning); existence of literal entries not mandated.
Citation: XBD 4.16: "The special filename dot shall refer to the directory specified by its predecessor. The special filename dot-dot shall refer to the parent directory of its predecessor directory."
Model: Do not store dot/dot-dot as entries; derive them. Treat nlink of a directory as derived: `2 + number_of_subdirectories` if nlink is exposed at all.

---

## 1. mkdir / mkdirat

**R6. Creation and mode.**
Behavior: Creates a new directory; permission bits and S_ISVTX come from `mode`, filtered by umask.
Level: MUST.
Citation: mkdir page: "The mkdir() function shall create a new directory with name path. The file permission bits and S_ISVTX bit of the new directory shall be initialized from mode." and "The file permission bits of the mode argument shall be modified by the file creation mask of the process."
Model: `newmode = (mode & 0o1777) & ~umask` (S_ISVTX passes through mode; umask applies only to the 0777 permission bits per the quoted sentence — apply umask to permission bits only).

**R7. Other mode bits (S_ISUID/S_ISGID in mode) are implementation-defined.**
Behavior: Bits in `mode` other than the permission bits and S_ISVTX have implementation-defined meaning.
Level: implementation-defined.
Citation: mkdir page: "When bits in mode other than the file permission bits and S_ISVTX are set, the meaning of these additional bits is implementation-defined."
Model: Mask them off (ignore) in the model; do not assert on their effect.

**R8. Ownership of the new directory — uid.**
Behavior: uid = effective uid of the process.
Level: MUST.
Citation: mkdir page: "The directory's user ID shall be set to the process' effective user ID."
Model: `newdir.uid = cred.euid`.

**R9. Ownership of the new directory — gid (acceptance set).**
Behavior: gid is EITHER the parent directory's gid OR the process effective gid; implementations must at least offer parent-gid inheritance as a possibility.
Level: acceptance-set{parent.gid, egid}.
Citation: mkdir page: "The directory's group ID shall be set to the group ID of the parent directory or to the effective group ID of the process." and "Implementations shall provide a way to initialize the directory's group ID to the group ID of the parent directory."
Model: Accept either gid in postconditions, or fix one via a FeatureMode (`GroupFromParent` vs `GroupFromEgid`).
Linux-divergence: Linux picks egid normally, but parent.gid when the parent has S_ISGID set (BSD semantics with -o grpid mounts always inherit). Both outcomes are inside the POSIX acceptance set.

**R10. S_ISGID bit inheritance from parent is NOT specified by POSIX.**
Behavior: The mkdir page never mentions S_ISGID/set-group-ID inheritance from the parent directory; POSIX is silent (verified: "No mention of S_ISGID or set-group-ID appears in DESCRIPTION, RATIONALE, or APPLICATION USAGE").
Level: unspecified (POSIX silence) / implementation behavior.
Citation: mkdir page (absence verified); only R7's implementation-defined clause covers S_ISGID **in the mode argument**.
Model: If modeling SGID-directory semantics (new dirs under an SGID dir get SGID + parent gid), gate it behind a Linux/BSD FeatureMode, not a POSIX rule.
Linux-divergence: Linux propagates S_ISGID from parent to new subdirectories and sets gid = parent.gid under an S_ISGID parent.

**R11. New directory is empty.**
Behavior: The created directory contains no entries (other than the conceptual dot/dot-dot).
Level: MUST.
Citation: mkdir page: "The newly created directory shall be an empty directory."
Model: `newdir.entries = Map()`.

**R12. Timestamps.**
Behavior: New directory's atime, mtime, ctime all marked for update; parent's mtime and ctime marked for update.
Level: MUST.
Citation: mkdir page: "Upon successful completion, mkdir() shall mark for update the last data access, last data modification, and last file status change timestamps of the directory. Also, the last data modification and last file status change timestamps of the directory that contains the new entry shall be marked for update."
Model: `touch(newdir, {a,m,c}); touch(parent, {m,c})`.

**R13. EEXIST — existing name, including any symlink (dangling or not).**
Behavior: If the final component exists, EEXIST; a symlink at the target — even a dangling one — is EEXIST, not ENOENT.
Level: MUST.
Citation: mkdir ERRORS: "[EEXIST] The named file exists." plus DESCRIPTION: "If path names a symbolic link, mkdir() shall fail and set errno to [EEXIST]."
Model: Lookup of final component must be NOFOLLOW for mkdir: any entry (file/dir/symlink) at the name → EEXIST.

**R14. ENOENT — missing prefix component or empty path.**
Level: MUST.
Citation: mkdir ERRORS: "[ENOENT] A component of the path prefix of path does not name an existing file or path is an empty string."
Model: Standard walk failure; empty path → ENOENT.

**R15. ENOTDIR — non-directory in prefix.**
Level: MUST.
Citation: mkdir ERRORS: "[ENOTDIR] A component of the path prefix names an existing file that is neither a directory nor a symbolic link to a directory."
Model: Prefix walk hits non-dir → ENOTDIR.

**R16. EACCES — search on prefix or write on parent.**
Level: MUST.
Citation: mkdir ERRORS: "[EACCES] Search permission is denied on a component of the path prefix, or write permission is denied on the parent directory of the directory to be created."
Model: Need x on every prefix dir, w+x on the parent.

**R17. ELOOP / EROFS / EMLINK.**
Level: MUST (base ELOOP; the SYMLOOP_MAX variant is may-fail).
Citation: mkdir ERRORS: "[ELOOP] A loop exists in symbolic links encountered during resolution of the path argument."; "[EROFS] The parent directory resides on a read-only file system."; "[EMLINK] The link count of the parent directory would exceed {LINK_MAX}."
Model: ELOOP reachable if the model has symlink cycles; EROFS/EMLINK out of scope (no RO fs, no LINK_MAX) — note EMLINK's text confirms the parent's link count grows on mkdir.

**R18. nlink accounting.**
Behavior: POSIX never states "parent link count += 1" directly, but R17's EMLINK text ("The link count of the parent directory would exceed {LINK_MAX}") presupposes it; per R5, literal dot/dot-dot entries are not mandated.
Level: implied (implementation convention on POSIX-style filesystems).
Model: If exposing st_nlink: `dir.nlink = 2 + subdirCount(dir)`; mkdir bumps parent's derived count via subdirCount.

**R19. mkdirat.**
Behavior: Same as mkdir with fd-relative resolution.
Level: MUST.
Citation: mkdirat text: "In this case the newly created directory is created relative to the directory associated with the file descriptor fd instead of the current working directory."
Model: NFS/NAS model resolves from a handle anyway; mkdirat adds no new namespace semantics (EBADF/ENOTDIR-on-fd are transport-level, out of scope).

---

## 2. rmdir

**R20. Empty-directory requirement.**
Behavior: Only empty directories may be removed; "empty" means nothing beyond the conceptual dot and dot-dot.
Level: MUST.
Citation: rmdir page: "The directory shall be removed only if it is an empty directory."
Model: `dir.entries == Map()` is the emptiness predicate (dot/dot-dot are not stored per R5).

**R21. Non-empty directory errno (acceptance set) — also extra hard links.**
Behavior: Non-empty target → EEXIST or ENOTEMPTY. Notably the same clause also fires when the directory has extra hard links.
Level: acceptance-set{EEXIST, ENOTEMPTY}, MUST fail.
Citation: rmdir ERRORS: "[EEXIST] or [ENOTEMPTY] The path argument names a directory that is not an empty directory, or there are hard links to the directory other than dot or a single entry in dot-dot."
Model: Accept both errnos in test acceptance; if the model forbids hard links to directories (recommended), the second clause is unreachable.
Linux-divergence: Linux returns ENOTEMPTY.

**R22. rmdir of a path ending in dot.**
Behavior: Fails.
Level: MUST, errno EINVAL.
Citation: rmdir page: "If the path argument refers to a path whose final component is either dot or dot-dot, rmdir() shall fail." and ERRORS: "[EINVAL] The path argument contains a last component that is dot."
Model: Final component "." → EINVAL.

**R23. rmdir of a path ending in dot-dot.**
Behavior: Fails ("shall fail" per R22's quote), but the ERRORS section pins EINVAL only for dot; no errno is explicitly assigned for dot-dot.
Level: MUST fail; errno effectively acceptance-set{EINVAL, ENOTEMPTY, EEXIST, EBUSY} in practice (spec is not explicit).
Citation: rmdir page: "If the path argument refers to a path whose final component is either dot or dot-dot, rmdir() shall fail." (dot-dot errno unassigned in ERRORS).
Model: Reject `..` as final component with a loose errno acceptance set.
Linux-divergence: Linux returns ENOTEMPTY for rmdir("x/..").

**R24. EACCES — search on prefix or write on parent.**
Level: MUST.
Citation: rmdir ERRORS: "[EACCES] Search permission is denied on a component of the path prefix, or write permission is denied on the parent directory."
Model: x on prefix dirs, w+x on parent.

**R25. Sticky-bit parent.**
Behavior: S_ISVTX on the parent + caller fails XBD 4.5 criteria → error.
Level: MUST fail; acceptance-set{EPERM, EACCES}. (XSI-shaded.)
Citation: rmdir ERRORS: "[EPERM] or [EACCES] The S_ISVTX flag is set on the directory containing the file referred to by the path argument and the process does not satisfy the criteria specified in XBD 4.5 Directory Protection."
Model: Apply R1 predicate before removal; accept either errno.

**R26. EBUSY — directory in use (implementation option).**
Behavior: A directory "in use" MAY be an error; additionally, removing the root or any process's cwd is explicitly unspecified-vs-EBUSY.
Level: EBUSY is listed as a "shall fail" condition but is self-gated by "the implementation considers this an error" phrasing on the cwd/root case; treat as implementation-option.
Citation: rmdir ERRORS: "[EBUSY] The directory to be removed is currently in use by the system or some process." and DESCRIPTION: "If the directory is the root directory or the current working directory of any process, it is unspecified whether the function succeeds, or whether it shall fail and set errno to [EBUSY]."
Model: Out of scope for a NAS namespace model (no cwd concept server-side); do not encode EBUSY as reachable.

**R27. Removal while the directory is open (dir stream / open handle).**
Behavior: The name is removed immediately; the directory object persists (invisible, un-writable) until last reference drops; its dot/dot-dot are conceptually removed and no new entries may be created.
Level: MUST.
Citation: rmdir page: "If one or more processes have the directory open when the last link is removed, the dot and dot-dot entries, if present, shall be removed before rmdir() returns and no new entries may be created in the directory, but the directory shall not be removed until all references to the directory are closed."
Model: Two-phase delete: unlinked-but-referenced directories exist as orphans with `deleted=true`; any create inside them must fail (ENOENT is the conventional errno — POSIX does not name one here).

**R28. ENOENT / ENOTDIR causes.**
Level: MUST.
Citation: rmdir ERRORS: "[ENOENT] A component of path does not name an existing file, or the path argument names a nonexistent directory or points to an empty string." and "[ENOTDIR] A component of path names an existing file that is neither a directory nor a symbolic link to a directory."
Note: rmdir's ENOTDIR text covers "a component of path" — including the FINAL component: rmdir of a regular file → ENOTDIR.
Model: rmdir(non-dir final) → ENOTDIR; missing final → ENOENT.

**R29. EROFS / ELOOP.**
Level: MUST (base ELOOP; SYMLOOP_MAX variant may-fail).
Citation: rmdir ERRORS: "[EROFS] The directory entry to be removed resides on a read-only file system."; "[ELOOP] A loop exists in symbolic links encountered during resolution of the path argument."
Model: EROFS out of scope; ELOOP reachable via symlink cycles.

**R30. Timestamps.**
Behavior: Parent's mtime + ctime marked.
Level: MUST.
Citation: rmdir page: "Upon successful completion, rmdir() shall mark for update the last data modification and last file status change timestamps of the parent directory."
Model: `touch(parent, {m,c})`. POSIX does not require touching the removed directory's own timestamps.

**R31. nlink effects.**
Behavior: Parent loses the child's dot-dot back-link (derived); the removed directory's link count drops to 0 (or to "no links" while open per R27).
Level: implied (see R5/R18).
Model: Derived nlink handles this automatically; if storing nlink, decrement parent by 1.

---

## 3. unlink / unlinkat

**R32. Basic semantics: remove entry, decrement link count.**
Level: MUST.
Citation: unlink page: "The unlink() function shall remove the directory entry named by path and shall decrement the link count of the file referenced by the directory entry."
Model: Remove name from parent map; `file.nlink -= 1`.

**R33. Deferred removal while the file is open (or mapped).**
Behavior: Link disappears immediately; file contents survive until no open fd/mmap reference remains.
Level: MUST.
Citation: unlink page: "When the file's link count becomes 0 and no process has a reference to the file via an open file descriptor or a memory mapping ..., the space occupied by the file shall be freed and the file shall no longer be accessible. If one or more processes have such a reference to the file when the last link is removed, the link shall be removed before unlink() returns, but the removal of the file contents shall be postponed until there are no such references to the file."
Model: Orphan set: inode survives with nlink==0 while `openRefs > 0`; reads/writes through open handles still work. (This is the NFS "silly rename" driver.)

**R34. unlink of a directory.**
Behavior: Not permitted unless the process has appropriate privileges AND the implementation supports it; errno is EPERM. EISDIR is NOT in the unlink ERRORS list.
Level: MUST fail (absent privilege+support), errno EPERM per POSIX.
Citation: unlink page: "The path argument shall not name a directory unless the process has appropriate privileges and the implementation supports using unlink() on directories." ERRORS: "[EPERM] The file named by path is a directory, and either the calling process does not have appropriate privileges or the implementation prohibits using unlink() on directories." APPLICATION USAGE: "Applications should use rmdir() to remove a directory."
Model: unlink(dir) → EPERM. Test acceptance should be {EPERM, EISDIR} if the harness may run against Linux.
Linux-divergence: Linux returns EISDIR for unlink() on a directory (unconditionally; even root cannot unlink directories).

**R35. unlinkat AT_REMOVEDIR.**
Behavior: With AT_REMOVEDIR, unlinkat behaves as rmdir.
Level: MUST.
Citation: unlinkat page: "AT_REMOVEDIR: Remove the directory entry specified by fd and path as a directory, not a normal file." Plus unlinkat-specific ERRORS: "[EEXIST] or [ENOTEMPTY] The flag parameter has the AT_REMOVEDIR bit set and the path argument names a directory that is not an empty directory, or there are hard links to the directory other than dot or a single entry in dot-dot." and "[ENOTDIR] The flag parameter has the AT_REMOVEDIR bit set and path does not name a directory." and "[EPERM] The file named by path is a directory, the flag parameter does not have the AT_REMOVEDIR bit set, and ..."
Model: `unlinkat(flags & AT_REMOVEDIR)` delegates to the rmdir action; invalid flags → EINVAL (may-fail: "[EINVAL] The value of the flag argument is not valid.").

**R36. Sticky-bit parent.**
Level: MUST fail; acceptance-set{EPERM, EACCES}. (XSI-shaded.)
Citation: unlink ERRORS: "[EPERM] or [EACCES] The S_ISVTX flag is set on the directory containing the file referred to by the path argument and the process does not satisfy the criteria specified in XBD 4.5 Directory Protection."
Model: Same predicate as R25 (R1).

**R37. EACCES — search on prefix or write on parent.**
Level: MUST.
Citation: unlink ERRORS: "[EACCES] Search permission is denied for a component of the path prefix, or write permission is denied on the directory containing the directory entry to be removed."
Model: x on prefix, w+x on parent. No permission on the file itself is required (outside sticky rule).

**R38. EBUSY (implementation-gated).**
Level: listed "shall fail" but self-gated: only if "the implementation considers this an error".
Citation: unlink ERRORS: "[EBUSY] The file named by the path argument cannot be unlinked because it is being used by the system or another process and the implementation considers this an error."
Model: Do not make EBUSY reachable (open files are handled by R33, not EBUSY).

**R39. ENOENT / ENOTDIR / trailing slash.**
Level: MUST.
Citation: unlink ERRORS: "[ENOENT] A component of path does not name an existing file or path is an empty string." and "[ENOTDIR] A component of the path prefix names an existing file that is neither a directory nor a symbolic link to a directory, or the path argument contains at least one non-<slash> character and ends with one or more trailing <slash> characters and the last pathname component names an existing file that is neither a directory nor a symbolic link to a directory."
Model: `unlink("file/")` → ENOTDIR. `unlink("dir/")` → falls to R34 (EPERM). Missing target → ENOENT.

**R40. ELOOP / EROFS / ETXTBSY.**
Level: ELOOP MUST (SYMLOOP_MAX variant may-fail); EROFS MUST; ETXTBSY may-fail.
Citation: unlink ERRORS: "[EROFS] The directory entry to be unlinked is part of a read-only file system."; may fail: "[ETXTBSY] The entry to be unlinked is the last directory entry to a pure procedure (shared text) file that is being executed."
Model: EROFS/ETXTBSY out of scope; ELOOP reachable.

**R41. Timestamps.**
Behavior: Parent mtime+ctime marked; if the file survives (nlink still > 0 after decrement), the FILE's ctime is marked.
Level: MUST.
Citation: unlink page: "Upon successful completion, unlink() shall mark for update the last data modification and last file status change timestamps of the parent directory. Also, if the file's link count is not 0, the last file status change timestamp of the file shall be marked for update."
Model: `touch(parent,{m,c}); if file.nlink > 0 after decrement: touch(file,{c})`. Note the condition is on the post-decrement count — unlinking the LAST link does not require a ctime mark (the inode is going away).

**R42. Symlink target of unlink.**
Behavior: unlink removes the symlink itself (final component not followed — implied by the whole design; EEXIST/ENOTDIR wording and the symlink page's "contents can always be read" text; rename page states it explicitly for rename, unlink page has no follow language).
Level: MUST (no-follow of final component).
Citation: unlink page has no sentence following the final symlink; removal operates on "the directory entry named by path".
Model: unlink(symlink) removes the link object, never the target.

---

## 4. rename / renameat

**R43. Same-file no-op.**
Behavior: If old and new resolve to the same directory entry OR to different entries of the same file (hard links), rename succeeds and does NOTHING (neither entry is removed).
Level: MUST.
Citation: rename page: "If the old argument and the new argument resolve to either the same existing directory entry or different directory entries for the same existing file, rename() shall return successfully and perform no other action."
Model: Compare resolved inode identity of old and new before anything else; if equal → success, state unchanged, and (per R58) even timestamps arguably unchanged ("perform no other action").
Linux-divergence: none — Linux implements this (hard-link case: both links remain).

**R44. Atomic replacement of an existing new.**
Behavior: If new exists, it is removed and old renamed in one step; some entry named `new` is visible to other threads at every instant, referring to either the old or the new file.
Level: MUST.
Citation: rename page: "a directory entry named new shall remain visible to other threads throughout the renaming operation and refer either to the file referred to by new or old before the operation began." (stated for the file case and for the directory case: "If the directory entry named by new exists, it shall be removed and old renamed to new.")
Model: Single atomic transition: remove old entry + (re)bind new name to old's inode in one step. No intermediate state where `new` is absent.

**R45. Old is a file, new is a directory → EISDIR.**
Level: MUST.
Citation: rename ERRORS: "[EISDIR] The new argument points to a directory and the old argument points to a file that is not a directory." DESCRIPTION: "If the old argument names a file that is not a directory and the new argument names a directory, ... rename() shall fail."
Model: type(old) != DIR && type(new) == DIR → EISDIR.

**R46. Old is a directory, new is a file → ENOTDIR.**
Level: MUST.
Citation: rename ERRORS: "[ENOTDIR] ... the old argument names a directory and the new argument names a non-directory file ..."
Model: type(old) == DIR && new exists && type(new) != DIR → ENOTDIR.

**R47. Directory over existing empty directory → allowed, target removed.**
Level: MUST.
Citation: rename page: "If the directory entry named by new exists, it shall be removed and old renamed to new." (directory case paragraph).
Model: Empty dir target is atomically replaced; the replaced directory's inode is freed (or orphaned if open, per R27 analogy).

**R48. Directory over non-empty directory → fail.**
Level: MUST fail; acceptance-set{EEXIST, ENOTEMPTY}.
Citation: rename ERRORS: "[EEXIST] or [ENOTEMPTY] The new argument names a directory that is not empty." DESCRIPTION: "... or new names a directory that is not empty, rename() shall fail."
Model: Accept both errnos.
Linux-divergence: Linux returns ENOTEMPTY (some filesystems historically EEXIST; NFS servers vary).

**R49. Old is an ancestor of new → EINVAL; dot / dot-dot final components → EINVAL.**
Level: MUST.
Citation: rename ERRORS: "[EINVAL] The old pathname names an ancestor directory of the new pathname, or either pathname argument contains a final component that is dot or dot-dot."
Model: Walk up from new's parent to root; if old's inode is on that chain → EINVAL. Reject "." or ".." as the final component of either argument → EINVAL. (Issue 8 pins EINVAL for dot/dot-dot here — unlike rmdir, there is no EBUSY alternative in the ERRORS list. Older SUS texts mentioned EBUSY-ish latitude; Issue 8's list gives EINVAL only. Test acceptance {EINVAL} with an optional widen-to-EBUSY toggle if targeting old systems.)

**R50. Symlinks: old renamed as-link, new removed as-link.**
Behavior: Final components are NOT followed; a symlink old is itself renamed, a symlink new is itself replaced.
Level: MUST.
Citation: rename page: "If the old argument points to a pathname of a symbolic link, the symbolic link shall be renamed. If the new argument points to a pathname of a symbolic link, the symbolic link shall be removed."
Model: NOFOLLOW resolution on both final components. Consequence: same-file check (R43) compares link objects, not targets.

**R51. Permissions: write on both parents; write on the renamed directory itself MAY be required.**
Level: MUST (parents); implementation-option (the moved directory itself).
Citation: rename page: "Write access permission is required for the directory containing old and the directory containing new. If the old argument points to the pathname of a directory, write access permission may be required for the directory named by old, and, if it exists, the directory named by new."
Errno: EACCES — "[EACCES] A component of either path prefix denies search permission; or one of the directories containing old or new denies write permissions; or, write permission is required and is denied for a directory pointed to by the old or new arguments."
Model: Require w+x on both parents; add FeatureMode `RenameDirNeedsWrite` for the may-require arm.
Linux-divergence: Linux requires write permission on the moved DIRECTORY itself only when it changes parent (the ".." update); same-parent renames don't check it.

**R52. Sticky bit on BOTH source and target parents.**
Behavior: Sticky check applies to removing old from its parent AND to replacing an existing new in its parent.
Level: MUST fail; acceptance-set{EPERM, EACCES}. (XSI-shaded.)
Citation: rename ERRORS: "[EPERM] or [EACCES] The S_ISVTX flag is set on the directory containing the file referred to by old and the process does not satisfy the criteria specified in XBD 4.5 Directory Protection with respect to old; or new refers to an existing file, the S_ISVTX flag is set on the directory containing this file, and the process does not satisfy the criteria specified in XBD 4.5 Directory Protection with respect to this file."
Model: Apply R1 twice: (oldParent, oldEntry) and, if new exists, (newParent, newEntry).

**R53. Trailing slash on new (and old).**
Behavior: `new/` fails unless new resolves to an existing directory; symmetric clauses for old.
Level: MUST.
Citation: rename page: "If the new argument does not resolve to an existing directory entry for a file of type directory and the new argument contains at least one non-<slash> character and ends with one or more trailing <slash> characters after all symbolic links have been processed, rename() shall fail." ERRORS [ENOTDIR] includes: "the old argument contains at least one non-<slash> character and ends with one or more trailing <slash> characters and the last pathname component names an existing file that is neither a directory nor a symbolic link to a directory; or the old argument names an existing non-directory file and the new argument names a nonexistent file, contains at least one non-<slash> character, and ends with one or more trailing <slash> characters; or the new argument names an existing non-directory file, contains at least one non-<slash> character, and ends with one or more trailing <slash> characters."
Model: trailingSlash on either arg + non-directory (or would-be non-directory) outcome → ENOTDIR.

**R54. ENOENT causes.**
Level: MUST.
Citation: rename ERRORS: "[ENOENT] The old argument does not name an existing file, a component of the path prefix of new does not exist, or either old or new points to an empty string."
Model: old missing → ENOENT; new's PARENT missing → ENOENT; new's final component missing is fine (that's the create case).

**R55. EBUSY (implementation-gated).**
Level: self-gated ("the implementation considers this an error").
Citation: rename ERRORS: "[EBUSY] The directory named by old or new is currently in use by the system or another process, and the implementation considers this an error."
Model: Not reachable in the model.

**R56. EXDEV / EMLINK / ENOSPC / ETXTBSY / EILSEQ / EROFS.**
Level: MUST (EXDEV, EROFS, EMLINK, ENOSPC, EILSEQ); ETXTBSY may-fail.
Citation: rename ERRORS: "[EXDEV] The file named by old and the directory in which the directory entry named by new is to be created or replaced are on different file systems and the implementation does not support hard links between file systems."; "[EMLINK] The file named by old is a directory, and the link count of the parent directory of new would exceed {LINK_MAX}."
Model: All out of scope (single fs, no limits). EMLINK's wording again confirms directory renames move a link onto the new parent (dot-dot accounting, R59).

**R57. Deferred content removal of a replaced open file.**
Behavior: If new named a file that was open, the name is replaced immediately but the displaced file's contents persist until closed (same as unlink R33).
Level: MUST.
Citation: rename page: "If one or more processes have the file open when the last link is removed, the link shall be removed before rename() returns, but the removal of the file contents shall be postponed until all references to the file are closed."
Model: Replaced target with open refs joins the orphan set.

**R58. Timestamps.**
Behavior: Both parents' mtime+ctime marked. The renamed file's own ctime: POSIX Issue 8 does NOT require it; explicitly notes divergence.
Level: MUST (parents); unspecified (renamed file's ctime).
Citation: rename page: "Upon successful completion, rename() shall mark for update the last data modification and last file status change timestamps of the parent directory of each file." APPLICATION USAGE: "Some implementations mark for update the last file status change timestamp of renamed files and some do not."
Model: `touch(oldParent,{m,c}); touch(newParent,{m,c})` (same dir touched once). Renamed inode's ctime: allow-both in acceptance (Linux DOES update ctime of the renamed inode).
Linux-divergence: Linux marks the renamed file's ctime.

**R59. nlink accounting for directory renames across parents.**
Behavior: Old parent loses the child's dot-dot back-link; new parent gains it. Implied by R56's EMLINK text; not stated as an accounting rule.
Level: implied.
Model: With derived nlink (R5/R18) this is automatic; with stored nlink: `oldParent.nlink -= 1; newParent.nlink += 1` when a directory changes parent.

**R60. renameat.**
Behavior: fd-relative resolution for both paths; adds EBADF/EACCES(O_SEARCH)/ENOTDIR-on-fd errors only.
Level: MUST.
Citation: renameat ERRORS: "[EBADF] The old argument does not specify an absolute path and the oldfd argument is neither AT_FDCWD nor a valid file descriptor open for reading or searching, ..."
Model: No new namespace semantics; out of scope beyond handle-based resolution already native to NFS.

---

## 5. link / linkat

**R61. Basic behavior; atomic; link count increment.**
Level: MUST.
Citation: link page: "The link() function shall create a new hard link (directory entry) for the existing file, path1." and "The link() function shall atomically create a new hard link for the existing file and the link count of the file shall be incremented by one."
Model: Bind new name in path2's parent to path1's inode; `inode.nlink += 1`; single atomic transition.

**R62. link() on a symlink source: implementation-defined follow.**
Behavior: Whether link() follows a symlink path1 or hard-links the symlink itself is implementation-defined.
Level: implementation-defined.
Citation: link page: "If path1 names a symbolic link, it is implementation-defined whether link() follows the symbolic link, or creates a new hard link to the symbolic link itself."
Model: FeatureMode `LinkFollowsSymlink` (bool); pick per target platform.
Linux-divergence: Linux link(2) does NOT follow — it hard-links the symlink itself (equivalent to linkat with flag 0).

**R63. linkat AT_SYMLINK_FOLLOW semantics (both directions pinned).**
Level: MUST.
Citation: linkat page: flag set — "If path1 names a symbolic link, a new hard link for the target of the symbolic link is created."; flag clear — "If the AT_SYMLINK_FOLLOW flag is clear in the flag argument and the path1 argument names a symbolic link, a new hard link is created for the symbolic link path1 and not its target."
Model: Model linkat with an explicit boolean; NFS LINK maps to the no-follow case (NFS never follows symlinks server-side).

**R64. Hard link to a directory.**
Behavior: Fails unless privileged AND implementation supports it; EPERM.
Level: MUST fail (absent privilege+support), errno EPERM.
Citation: link page: "If path1 names a directory, link() shall fail unless the process has appropriate privileges and the implementation supports using link() on directories." ERRORS: "[EPERM] The file named by path1 is a directory and either the calling process does not have appropriate privileges or the implementation prohibits using link() on directories."
Model: link(dir, …) → EPERM always (model does not support dir hard links — this also keeps the tree acyclic and rmdir emptiness simple).
Linux-divergence: Linux flatly forbids (EPERM even for root) — inside the POSIX allowance.

**R65. EEXIST — path2 exists, including as a (possibly dangling) symlink.**
Level: MUST.
Citation: link ERRORS: "[EEXIST] The path2 argument resolves to an existing directory entry or refers to a symbolic link."
Model: NOFOLLOW check on path2's final component: any entry (incl. dangling symlink) → EEXIST.

**R66. No ownership requirement on path1; access requirement is implementation-optional.**
Behavior: The caller need not own or have write permission to path1; an implementation MAY require "permission to access" the existing file.
Level: implementation-option.
Citation: link page: "The implementation may require that the calling process has permission to access the existing file." ERRORS [EACCES]: "A component of either path prefix denies search permission, or the requested link requires writing in a directory that denies write permission, or the calling process does not have permission to access the existing file and this is required by the implementation."
Model: Base model: require only x on both prefixes + w+x on path2's parent. FeatureMode for the extra source-access check.
Linux-divergence: Linux's `fs.protected_hardlinks=1` (default on modern distros) refuses links to files the caller cannot access/own in some setuid/unowned cases → EPERM (not EACCES); this is the sysctl exercising (and exceeding) the POSIX latitude.

**R67. ENOENT / ENOTDIR matrix (incl. trailing-slash refinement).**
Level: MUST; one cell is acceptance-set{ENOENT, ENOTDIR}.
Citation: link ERRORS: "[ENOENT] A component of either path prefix does not exist; the file named by path1 does not exist; or path1 or path2 points to an empty string."; "[ENOENT] or [ENOTDIR] The path1 argument names an existing non-directory file, and the path2 argument contains at least one non-<slash> character and ends with one or more trailing <slash> characters. If path2 without the trailing <slash> characters would name an existing file, an [ENOENT] error shall not occur."; "[ENOTDIR] A component of either path prefix names an existing file that is neither a directory nor a symbolic link to a directory, or the path1 argument contains at least one non-<slash> character and ends with one or more trailing <slash> characters and the last pathname component names an existing file that is neither a directory nor a symbolic link to a directory, ..."
Model: `link(file, "x/")`: if x exists → ENOTDIR; if x doesn't exist → acceptance-set{ENOENT, ENOTDIR}.

**R68. EMLINK / EXDEV / EROFS / ELOOP / EILSEQ.**
Level: MUST (base forms).
Citation: link ERRORS: "[EMLINK] The number of hard links to the file named by path1 would exceed {LINK_MAX}."; "[EXDEV] The file named by path1 and the directory in which the directory entry named by path2 is to be created are on different file systems and the implementation does not support hard links between file systems."; "[EROFS] The requested link requires writing in a directory on a read-only file system."
Model: All out of scope (single fs, no limits); ELOOP reachable via cycles.

**R69. Timestamps.**
Behavior: The FILE's ctime marked; path2's parent mtime+ctime marked. Nothing on path1's parent.
Level: MUST.
Citation: link page: "Upon successful completion, link() shall mark for update the last file status change timestamp of the file. Also, the last data modification and last file status change timestamps of the directory that contains the new entry shall be marked for update."
Model: `touch(inode,{c}); touch(path2Parent,{m,c})`.

---

## 6. symlink / symlinkat

**R70. Target string not validated; dangling allowed.**
Behavior: path1 is stored verbatim; it need not name anything.
Level: MUST.
Citation: symlink page: "The symlink() function shall create a symbolic link called path2 that contains the string pointed to by path1 (path2 is the name of the symbolic link created, path1 is the string contained in the symbolic link)." and "The string pointed to by path1 shall be treated only as a string and shall not be validated as a pathname."
Model: Store target as an opaque string; no existence/type checks. Dangling and self-referential targets are legal states.

**R71. Empty target string.**
Behavior: The symlink page assigns NO error to an empty path1 (ENOENT text covers path2 only: "[ENOENT] A component of the path prefix of path2 does not name an existing file or path2 is an empty string." — verified path1 is not mentioned anywhere on the page). Per R70, an empty string "shall not be validated", so creation should SUCCEED per strict POSIX; the trouble is deferred to resolution time (R4).
Level: MUST succeed per the letter of Issue 8 (creation); resolution behavior acceptance-set per R4.
Citation: symlink page (absence of path1-empty error, verified) + R70's "shall not be validated as a pathname" + XBD 4.16 empty-contents rule.
Model: Decide via FeatureMode: `AllowEmptySymlinkTarget` (POSIX letter) vs reject-ENOENT (Linux).
Linux-divergence: Linux symlink("", p) fails with ENOENT.

**R72. Symlink's own permission bits are meaningless.**
Behavior: Mode bits of a symlink are unspecified; link contents are always readable regardless.
Level: unspecified (mode value); MUST (always-readable behavior).
Citation: symlink page: "The values of the file mode bits for the created symbolic link are unspecified." and "All interfaces specified by POSIX.1-2024 shall behave as if the contents of symbolic links can always be read, except that the value of the file mode bits returned in the st_mode field of the stat structure is unspecified."
Model: Store no mode on symlink inodes (or a constant 0777); never permission-check reading/traversing THROUGH a symlink on the link's own bits.

**R73. Ownership of the new symlink.**
Level: MUST (uid); acceptance-set{parent.gid, egid} (gid), with mandatory parent-inheritance availability.
Citation: symlink page: "The symbolic link's user ID shall be set to the process' effective user ID. The symbolic link's group ID shall be set to the group ID of the parent directory or to the effective group ID of the process. Implementations shall provide a way to initialize the symbolic link's group ID to the group ID of the parent directory."
Model: Same gid FeatureMode as mkdir (R9).

**R74. EEXIST.**
Level: MUST.
Citation: symlink ERRORS: "[EEXIST] The path2 argument names an existing file."
Model: NOFOLLOW final-component check; any existing entry → EEXIST.

**R75. EACCES.**
Level: MUST.
Citation: symlink ERRORS: "[EACCES] Write permission is denied in the directory where the symbolic link is being created, or search permission is denied for a component of the path prefix of path2."
Model: x on prefix, w+x on parent. No check on anything related to path1.

**R76. ENOENT / ENOTDIR / trailing slash on path2.**
Level: MUST; trailing-slash cell is acceptance-set{ENOENT, ENOTDIR}.
Citation: symlink ERRORS: "[ENOENT] A component of the path prefix of path2 does not name an existing file or path2 is an empty string."; "[ENOENT] or [ENOTDIR] The path2 argument contains at least one non-<slash> character and ends with one or more trailing <slash> characters."; "[ENOTDIR] A component of the path prefix of path2 names an existing file that is neither a directory nor a symbolic link to a directory."
Model: `symlink(t, "x/")` → acceptance-set{ENOENT, ENOTDIR} (a symlink can never be a directory, so trailing slash always fails).

**R77. ENAMETOOLONG covers long path1 (SYMLINK_MAX).**
Level: MUST.
Citation: symlink ERRORS: "[ENAMETOOLONG] The length of a component of the pathname specified by the path2 argument is longer than {NAME_MAX} or the length of the path1 argument is longer than {SYMLINK_MAX}."
Model: Out of scope (no limits) unless you bound target length; note the only path1-related error in the list.

**R78. Timestamps.**
Level: MUST.
Citation: symlink page: "Upon successful completion, symlink() shall mark for update the last data access, last data modification, and last file status change timestamps of the symbolic link. Also, the last data modification and last file status change timestamps of the directory that contains the new entry shall be marked for update."
Model: `touch(link,{a,m,c}); touch(parent,{m,c})`.

**R79. EROFS / ELOOP / EILSEQ / ENOSPC.**
Level: MUST (base forms); ELOOP applies to path2 resolution only.
Citation: symlink ERRORS: "[EROFS] The new symbolic link would reside on a read-only file system."; "[ELOOP] A loop exists in symbolic links encountered during resolution of the path2 argument."
Model: EROFS/ENOSPC/EILSEQ out of scope; ELOOP reachable via path2 prefix cycles.

---

## 7. readlink / readlinkat

**R80. Returns contents; count returned.**
Level: MUST.
Citation: readlink page: "The readlink() function shall place the contents of the symbolic link referred to by path in the buffer buf which has size bufsize." and "Upon successful completion, these functions shall return the count of bytes placed in the buffer."
Model: Return (bytes, count) of min(len(target), bufsize).

**R81. Silent truncation; no NUL terminator.**
Level: MUST (truncation); should-not-assume (NUL).
Citation: readlink page: "If the buf argument is not large enough to contain the link content, the first bufsize bytes shall be placed in buf." and "If the number of bytes in the symbolic link is less than bufsize, the contents of the remainder of buf are unspecified." APPLICATION USAGE: "Conforming applications should not assume that the returned contents of the symbolic link are null-terminated."
Model: Truncation is SUCCESS (return == bufsize signals possible truncation); never an error. No NUL in the model's returned bytes.

**R82. EINVAL — not a symlink.**
Level: MUST.
Citation: readlink ERRORS: "[EINVAL] The path argument names a file that is not a symbolic link."
Model: readlink(file|dir|fifo) → EINVAL. (Final component NOFOLLOW by definition.)

**R83. Permission: search on prefix only; NO read-permission check on the link itself.**
Behavior: EACCES arises only from prefix search; there is no requirement of read permission on the symlink (consistent with R72's "contents can always be read").
Level: MUST (no link-read check per R72's shall-behave-as-if text; EACCES limited to prefix).
Citation: readlink ERRORS: "[EACCES] Search permission is denied for a component of the path prefix of path." (verified: no other permission language on the page).
Model: Only prefix x checks; the link's own bits never gate readlink.

**R84. ENOENT / ENOTDIR / ELOOP.**
Level: MUST (base forms).
Citation: readlink ERRORS (paraphrase verified): ENOENT — path component missing or empty string; ENOTDIR — prefix component not a directory nor symlink-to-directory; ELOOP — loop during resolution of the PREFIX.
Model: Standard walk errors; note ELOOP applies to the prefix, not the final link (the final link is not followed).

**R85. atime of the symlink is marked.**
Level: MUST ("shall").
Citation: readlink page: "Upon successful completion, readlink() shall mark for update the last data access timestamp of the symbolic link."
Model: `touch(link,{a})` on success.
Linux-divergence: visible atime updates depend on mount options (relatime/noatime); "mark for update" semantics still permit deferral, so this is mostly compatible — but a noatime mount never updates, which strictly violates the shall.

**R86. readlinkat.**
Behavior: fd-relative; adds EBADF/EACCES(O_SEARCH)/ENOTDIR-on-fd only.
Level: MUST.
Citation: readlinkat ERRORS (verified list).
Model: No new namespace semantics.

---

## 8. mknod / mknodat

**R87. Portable use is FIFO only; everything else unspecified at the portability level.**
Behavior: The only portable use is S_IFIFO with dev==0. S_IFREG, S_IFCHR, S_IFBLK, S_IFDIR are listed but marked non-portable.
Level: unspecified (non-FIFO portability); the type table itself is normative XSI.
Citation: mknod page: "The only portable use of mknod() is to create a FIFO-special file. If mode is not S_IFIFO or dev is not 0, the behavior of mknod() is unspecified." File types listed: S_IFIFO "FIFO-special", S_IFCHR "Character-special (non-portable)", S_IFDIR "Directory (non-portable)", S_IFBLK "Block-special (non-portable)", S_IFREG "Regular (non-portable)".
Model: Support S_IFIFO (as a typed inode, no I/O semantics) and optionally S_IFREG behind a FeatureMode; reject S_IFCHR/S_IFBLK/S_IFDIR (NAS scope: no device nodes).

**R88. Privilege requirement for non-FIFO types.**
Level: MUST (EPERM without appropriate privileges).
Citation: mknod page: "Only a process with appropriate privileges may invoke mknod() for file types other than FIFO-special." ERRORS: "[EPERM] The invoking process does not have appropriate privileges and the file type is not FIFO-special."
Model: `type != FIFO && !privileged → EPERM`.
Linux-divergence: Linux allows unprivileged mknod of S_IFREG and S_IFSOCK (only S_IFCHR/S_IFBLK need CAP_MKNOD) — more permissive than the POSIX letter.

**R89. Mode/umask and ownership.**
Level: MUST (umask, uid); acceptance-set{parent.gid, egid} (gid).
Citation: mknod page: "The owner, group, and other permission bits of mode shall be modified by the file mode creation mask of the process." "The user ID of the file shall be initialized to the effective user ID of the process." "The group ID of the file shall be initialized to either the effective group ID of the process or the group ID of the parent directory."
Model: Same creation attributes as mkdir (R6/R8/R9); reuse the gid FeatureMode.

**R90. Errno matrix.**
Level: MUST (base forms); ELOOP/ENAMETOOLONG extended forms may-fail.
Citation: mknod ERRORS (all verified verbatim): "[EACCES] A component of the path prefix denies search permission, or write permission is denied on the parent directory."; "[EEXIST] The named file exists."; "[EINVAL] An invalid argument exists."; "[ENOENT] A component of the path prefix of path does not name an existing file or path is an empty string."; "[ENOTDIR] A component of the path prefix names an existing file that is neither a directory nor a symbolic link to a directory."; "[EPERM] (see R88)"; "[EROFS] The directory in which the file is to be created is located on a read-only file system."
Model: Same shape as mkdir's matrix minus the symlink-EEXIST special sentence (still treat existing symlink at target as EEXIST via "The named file exists" + NOFOLLOW create semantics).

**R91. Timestamps.**
Level: MUST.
Citation: mknod page: "Upon successful completion, mknod() shall mark for update the last data access, last data modification, and last file status change timestamps of the file. Also, the last data modification and last file status change timestamps of the directory that contains the new entry shall be marked for update."
Model: Identical to mkdir's R12 shape.

**R92. mkfifo preferred; XSI marking.**
Level: advisory.
Citation: mknod APPLICATION USAGE: "The mkfifo() function is preferred over this function for making FIFO special files." Signature is XSI-shaded.
Model: Model a single `createNode(type)` action; mkfifo == mknod(S_IFIFO) with no privilege check.

---

## Testing notes

1. **Acceptance sets are first-class.** Encode errno checks as sets, not scalars: {EEXIST, ENOTEMPTY} (rmdir non-empty R21, rename dir-over-nonempty R48, unlinkat AT_REMOVEDIR R35), {EPERM, EACCES} (all four sticky rules R25/R36/R52), {ENOENT, ENOTDIR} (trailing-slash-on-nonexistent cells R67/R76), {EPERM, EISDIR} (unlink-of-dir R34, widened for Linux), gid ∈ {parent.gid, egid} (R9/R73/R89).
2. **Errno priority is unspecified.** When multiple error conditions hold simultaneously (e.g., sticky violation AND non-empty target on rename), POSIX does not order them; the test oracle must accept any listed errno whose condition holds.
3. **Timestamp oracle: "mark for update" is deferred.** Assert ordering/inequality after a sync point, not exact values; on NFS, assert via post-op attributes. The renamed inode's ctime (R58) must be allow-both.
4. **Same-file rename (R43) needs a hard-link generator state**: create link a→inode, link b→inode, rename(a,b) → success AND both a and b still exist AND nlink unchanged. This is the classic trap where naive implementations unlink b.
5. **Orphan/deferred-removal states (R27/R33/R57)** need an "open handle" dimension in the model even for a pure namespace suite: unlink-while-open, rmdir-while-open, rename-over-open-target. On NFS this surfaces as silly-rename client-side; the server model should keep nlink==0 inodes alive while referenced.
6. **NOFOLLOW cells:** mkdir target (R13), link path2 (R65), symlink path2 (R74), mknod target, rename old and new (R50), unlink target (R42), readlink target (R82) — the FINAL component is never followed by any creating/removing op. Only prefix components follow symlinks. A dangling symlink at the target is EEXIST for creators, and operable (rename/unlink/readlink) for the rest.
7. **Ancestor check for rename (R49)** should be tested with depth ≥ 3 and with the equal case (rename dir into itself: old == new-prefix) plus rename(parent, parent/child/x).
8. **Sticky-bit matrix (R1):** vary (dirOwner, entryOwner, caller) over 3 principals × privileged flag; expected outcome flips on `caller == entryOwner || caller == dirOwner || privileged`. Keep the "entry writable by caller" arm behind a FeatureMode and test both settings.
9. **Trailing slash** deserves its own small matrix per function: {existing dir, existing file, existing symlink-to-dir, existing symlink-to-file, nonexistent} × {creator ops, removal ops, rename old/new}.
10. **Empty-string paths** → ENOENT for every function's path argument (verified in every ERRORS section); this is a cheap always-on test cell.

## Traps

- **Linux-divergence: unlink(dir) returns EISDIR on Linux, but POSIX specifies EPERM and does not list EISDIR at all** (R34). NFS servers proxying local fs behavior will emit whatever the backend gives; accept {EPERM, EISDIR}.
- **Linux-divergence: link() to a symlink.** POSIX makes plain link() follow-vs-not implementation-defined (R62); Linux never follows. Do not encode "follows" as the default.
- **Linux-divergence: symlink with empty target fails ENOENT on Linux**, while Issue 8's letter says path1 "shall not be validated" and lists no error for it (R71). Pick via FeatureMode; if you allow creation, resolution must implement the R4 acceptance set.
- **Linux-divergence: mknod(S_IFREG) works unprivileged on Linux**, but the POSIX letter requires appropriate privileges for anything non-FIFO (R88), and calls non-FIFO use unspecified anyway (R87).
- **Linux-divergence: rename updates the renamed inode's ctime; POSIX explicitly leaves it open** (R58). Don't assert ctime-unchanged on rename.
- **Linux-divergence: renaming a directory to a NEW parent requires write permission on the directory itself on Linux** — the POSIX "may be required" arm (R51). Same-parent renames skip the check; a naive model with an unconditional check will false-positive.
- **mkdir on a dangling symlink is EEXIST, not ENOENT** (R13) — the DESCRIPTION sentence, not the ERRORS table, carries this; easy to miss.
- **link path2 EEXIST explicitly includes "refers to a symbolic link"** (R65) — dangling symlink at path2 is EEXIST, never ENOENT.
- **rmdir("x/..") has no pinned errno** (R23): "shall fail" with EINVAL reserved for dot only. Linux says ENOTEMPTY. Keep the acceptance set loose.
- **rename dot/dot-dot final component is EINVAL in Issue 8** (R49) — same clause as the ancestor rule; there is no EBUSY alternative in the Issue 8 ERRORS list for this, unlike some historical texts.
- **rmdir ENOTDIR covers the final component too** ("A component of path" — R28), so rmdir(regular-file) is ENOTDIR, not EINVAL/EPERM.
- **The sticky-bit "file writable by caller" escape hatch is implementation-defined** (R1, fourth bullet) — a model with the strict three-condition rule will disagree with any implementation that honors the optional arm.
- **unlink's file-ctime mark is conditional on POST-decrement nlink != 0** (R41): unlinking the last link requires no ctime mark; a model that always touches ctime will overconstrain.
- **EBUSY in rmdir/unlink/rename is self-gated** by "the implementation considers this an error" (R26/R38/R55) — never make it a required transition; never make it forbidden either if testing against kernels that use it (e.g., mountpoint targets).
- **"Empty" for rmdir is entry-count zero, but the same errno clause also fires on extra hard links to the directory** (R21) — irrelevant if the model forbids directory hard links (recommended: R64 EPERM unconditionally).
- **Atomicity of rename-replace (R44) is a THREAD-visibility property** ("shall remain visible to other threads") — in a concurrent model, no interleaving may observe `new` unbound; a naive remove-then-insert transition pair violates it.
