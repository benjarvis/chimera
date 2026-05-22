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
struct nfs_client;

#include <stdint.h>

/*
 * Two-stage layout recall.  If the client holds a layout for fh, send
 * CB_LAYOUTRECALL and defer the conflicting operation: resume(resume_arg) is
 * invoked once the client returns the layout (LAYOUTRETURN) or confirms it no
 * longer holds it (NOMATCHING / transport failure).  If no layout is held,
 * resume() runs immediately.  Must be called on the connection's own thread.
 */
void
chimera_nfs4_cb_recall_and_wait(
    struct chimera_server_nfs_thread *thread,
    struct nfs4_session              *session,
    const uint8_t                    *fh,
    uint32_t                          fhlen,
    void (                           *resume )(void *arg),
    void                             *resume_arg);

/* Resume operations waiting on the recall of the layout for (client, fh).
 * Called when the client returns the layout (LAYOUTRETURN). */
void
chimera_nfs4_layout_recall_resolve(
    struct nfs_client *client,
    const uint8_t     *fh,
    uint16_t           fhlen);
