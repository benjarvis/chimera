// SPDX-FileCopyrightText: 2025-2026 Chimera-NAS Project Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

/*
 * NFSv4.1 callback (backchannel) channel: the server sends CB_COMPOUND CALLs to
 * the client over the connection the client established (RFC 8881 §2.10.3.1).
 */

struct chimera_server_nfs_thread;
struct nfs4_session;

#include <stdint.h>

/* Recall the whole-file layout the client holds for fh (CB_LAYOUTRECALL).
 * No-op if the client holds no layout for it.  Must be called on the
 * connection's own thread. */
void
chimera_nfs4_cb_recall_layout(
    struct chimera_server_nfs_thread *thread,
    struct nfs4_session              *session,
    const uint8_t                    *fh,
    uint32_t                          fhlen);
