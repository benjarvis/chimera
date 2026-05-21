// SPDX-FileCopyrightText: 2025-2026 Chimera-NAS Project Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdlib.h>
#include <string.h>

#include "evpl/evpl_rpc2.h"
#include "nfs4_procs.h"
#include "nfs4_session.h"
#include "nfs4_state.h"
#include "nfs4_stateid.h"
#include "nfs_internal.h"
#include "nfs4_cb.h"

#define LAYOUT4_FLEX_FILES 0x4   /* RFC 8435; not in the generated XDR */

struct nfs4_cb_ctx {
    struct chimera_server_nfs_thread *thread;
    struct nfs4_session              *session;
};

/* The credential the server uses on the backchannel.  The Linux client accepts
 * AUTH_NONE only for CB_NULL; a real CB_COMPOUND must carry AUTH_SYS or it is
 * rejected with AUTH_ERROR (bad credential). */
static const struct evpl_rpc2_cred nfs4_cb_cred = {
    .flavor  = EVPL_RPC2_AUTH_SYS,
    .authsys = {
        .uid             = 0,
        .gid             = 0,
        .num_gids        = 0,
        .gids            = NULL,
        .machinename     = "chimera",
        .machinename_len = 7,
    },
};

static void
nfs4_cb_compound_reply(
    struct evpl                 *evpl,
    const struct evpl_rpc2_verf *verf,
    struct CB_COMPOUND4res      *reply,
    int                          status,
    void                        *private_data)
{
    struct nfs4_cb_ctx *ctx = private_data;

    if (status != 0 || !reply) {
        chimera_nfs_error("CB_COMPOUND transport failed: rpc status=%d", status);
    } else {
        chimera_nfs_info("CB_COMPOUND reply: cb_status=%d nops=%u",
                         reply->status, reply->num_resarray);
        /* RFC 8881 §20.9.3: on a successful CB_SEQUENCE the slot's sequenceid
         * advances for the next callback. */
        if (reply->status == NFS4_OK) {
            ctx->session->nfs4_session_cb_seqid++;
        }
    }

    free(ctx);
} /* nfs4_cb_compound_reply */

void
chimera_nfs4_cb_recall_layout(
    struct chimera_server_nfs_thread *thread,
    struct nfs4_session              *session,
    const uint8_t                    *fh,
    uint32_t                          fhlen)
{
    struct nfs_client       *client = session->client_unified;
    struct nfs_layout_state *layout;
    struct CB_COMPOUND4args  args;
    struct nfs_cb_argop4     argop[2];
    struct nfs4_cb_ctx      *ctx;
    struct stateid4          recall_stateid;

    if (!session->nfs4_session_cb_conn || !client) {
        return;
    }

    /* Nothing held -> nothing to recall. */
    layout = nfs_layout_state_find(client, fh, fhlen);
    if (!layout) {
        return;
    }

    /* Recall carries the file's current layout stateid (not bumped). */
    nfs4_stateid_encode(&recall_stateid, layout->seqid, NFS4_STATEID_TYPE_LAYOUT,
                        layout->shard, layout->slot_idx, layout->generation,
                        (uint32_t) client->client_id);

    memset(&args, 0, sizeof(args));
    memset(argop, 0, sizeof(argop));

    args.minorversion = 1;
    args.num_argarray = 2;
    args.argarray     = argop;

    /* op 0: CB_SEQUENCE (slot 0). */
    argop[0].argop = OP_CB_SEQUENCE;
    memcpy(argop[0].opcbsequence.csa_sessionid, session->nfs4_session_id,
           NFS4_SESSIONID_SIZE);
    argop[0].opcbsequence.csa_sequenceid     = session->nfs4_session_cb_seqid;
    argop[0].opcbsequence.csa_slotid         = 0;
    argop[0].opcbsequence.csa_highest_slotid = 0;
    argop[0].opcbsequence.csa_cachethis      = 0;

    /* op 1: CB_LAYOUTRECALL of the whole file. */
    argop[1].argop                                                = OP_CB_LAYOUTRECALL;
    argop[1].opcblayoutrecall.clora_type                          = LAYOUT4_FLEX_FILES;
    argop[1].opcblayoutrecall.clora_iomode                        = LAYOUTIOMODE4_ANY;
    argop[1].opcblayoutrecall.clora_changed                       = 0;
    argop[1].opcblayoutrecall.clora_recall.lor_recalltype         = LAYOUTRECALL4_FILE;
    argop[1].opcblayoutrecall.clora_recall.lor_layout.lor_fh.len  = fhlen;
    argop[1].opcblayoutrecall.clora_recall.lor_layout.lor_fh.data = (void *) fh;
    argop[1].opcblayoutrecall.clora_recall.lor_layout.lor_offset  = 0;
    argop[1].opcblayoutrecall.clora_recall.lor_layout.lor_length  = UINT64_MAX;
    argop[1].opcblayoutrecall.clora_recall.lor_layout.lor_stateid = recall_stateid;

    ctx          = calloc(1, sizeof(*ctx));
    ctx->thread  = thread;
    ctx->session = session;

    chimera_nfs_info("CB: sending CB_COMPOUND{CB_SEQUENCE, CB_LAYOUTRECALL} "
                     "fhlen=%u seqid=%u", fhlen, session->nfs4_session_cb_seqid);

    thread->shared->nfs_v4_cb.send_call_CB_COMPOUND(
        &session->nfs4_session_cb_prog, thread->evpl,
        session->nfs4_session_cb_conn, &nfs4_cb_cred,
        &args, 0, 0, 0, nfs4_cb_compound_reply, ctx);
} /* chimera_nfs4_cb_recall_layout */
