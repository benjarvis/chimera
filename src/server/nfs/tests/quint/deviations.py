# SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
#
# SPDX-License-Identifier: LGPL-2.1-only

"""Registry of known chimera deviations from RFC 1813.

The Quint model (nfs3.qnt) always encodes the RFC-correct reply.  Where
chimera is known to diverge, the divergence is recorded here rather than
baked into the model, so that:

  * the RFC target stays visible -- when chimera is fixed, the model's
    expectation already matches and the test goes green with no edit;
  * every non-conformance is one enumerable line item with an RFC citation,
    root cause, and candidate fix (see also DEVIATIONS.md);
  * the replay harness can tell a *known* deviation (report as xfail, do not
    fail the run) from an unexpected one (hard failure).

Only *status-only* deviations belong here: ones where the server's state
after the diverging reply still matches the model's, so replay can continue
in sync.  State-mutating deviations (where chimera changes the filesystem
differently than the RFC) would desync the model; those are excluded from
random trace generation and pinned by dedicated tests instead -- they are
listed with reconcilable=False for documentation but never matched during
replay.
"""

from dataclasses import dataclass, field
from typing import Callable, Optional

# nfsstat3 numbers referenced below.
NFS3_OK = 0
NFS3ERR_NOTDIR = 20
NFS3ERR_EXIST = 17
NFS3ERR_NOTSUPP = 10004
NFS3ERR_SERVERFAULT = 10006


@dataclass(frozen=True)
class Deviation:
    id: str
    rfc: str                 # RFC 1813 section
    summary: str
    root_cause: str          # source location
    candidate_fix: str
    # Trace reconciliation (status-only deviations):
    op: Optional[str] = None            # lastOp tag this applies to
    expected_status: Optional[int] = None
    actual_status: Optional[int] = None
    # Extra guard on (op_value, post_fs) -> bool; default always-true.
    context: Callable = field(default=lambda op, fs: True)
    reconcilable: bool = True           # False => documentation-only


KNOWN_DEVIATIONS = [
    # All deviations found by this effort have been fixed in the NFS3/VFS
    # layers -- see the "fixed" section of DEVIATIONS.md:
    #   D1/D2 lookup/readdir-on-symlink -> SERVERFAULT (nfs3_status.h)
    #   D3    exclusive-create same-verifier retry -> EXIST (nfs3_proc_create.c)
    #   D4    rmdir-of-non-directory (and unlink-of-directory) not type-checked
    #         (VFS remove_at type flags + backend enforcement)
    # The model is RFC-correct for all of them, so the suite now passes them
    # through the RFC path with no reconciliation.  New deviations get added
    # back here (status-only, reconcilable=True) or as documentation-only
    # entries (reconcilable=False) with a dedicated test.
]


def reconcile(tag, op, expected_status, actual_status, post_fs):
    """Return the matching reconcilable Deviation, or None.

    Called only when actual_status != expected_status.
    """
    for dev in KNOWN_DEVIATIONS:
        if not dev.reconcilable:
            continue
        if dev.op != tag:
            continue
        if dev.expected_status != expected_status:
            continue
        if dev.actual_status != actual_status:
            continue
        if dev.context(op, post_fs):
            return dev
    return None
