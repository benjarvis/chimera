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

/* Per-recall context, carried through the CB_COMPOUND reply so we can resolve
 * the deferred operations once the client acts on the recall. */
struct nfs4_cb_recall_ctx {
    struct chimera_server_nfs_thread *thread;
    struct nfs4_session              *session;
    struct nfs_client                *client;
    uint8_t                           fh[NFS4_FHSIZE];
    uint16_t                          fhlen;
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

/*
 * Drain and resume every operation waiting on the recall of the layout for
 * (client, fh): the client has either returned it (LAYOUTRETURN) or told us it
 * no longer holds it.  Idempotent -- a second call finds the list empty.
 */
void
chimera_nfs4_layout_recall_resolve(
    struct nfs_client *client,
    const uint8_t     *fh,
    uint16_t           fhlen)
{
    struct nfs_layout_state   *layout;
    struct nfs4_recall_waiter *waiters, *w, *next;

    pthread_mutex_lock(&client->lock);
    HASH_FIND(hh, client->layouts_by_fh, fh, fhlen, layout);
    if (layout) {
        waiters                = layout->recall_waiters;
        layout->recall_waiters = NULL;
        layout->recall_active  = 0;
    } else {
        waiters = NULL;
    }
    pthread_mutex_unlock(&client->lock);

    if (waiters) {
        chimera_nfs_info("CB: recall resolved, resuming deferred operation(s)");
    }

    for (w = waiters; w; w = next) {
        next = w->next;
        w->resume(w->arg);
        free(w);
    }
} /* chimera_nfs4_layout_recall_resolve */

static void
nfs4_cb_recall_reply(
    struct evpl                 *evpl,
    const struct evpl_rpc2_verf *verf,
    struct CB_COMPOUND4res      *reply,
    int                          status,
    void                        *private_data)
{
    struct nfs4_cb_recall_ctx *ctx       = private_data;
    int                        returning = 0;

    if (status == 0 && reply) {
        /* CB_SEQUENCE (op 0) ran, so the backchannel slot seqid is consumed
         * even if the recall op itself failed. */
        ctx->session->nfs4_session_cb_seqid++;

        /* COMPOUND status reflects the last op: NFS4_OK means the client
         * accepted the recall and will return the layout via LAYOUTRETURN;
         * anything else (typically NFS4ERR_NOMATCHING_LAYOUT) means it does
         * not hold the layout and no return is coming. */
        returning = (reply->status == NFS4_OK);
        chimera_nfs_info("CB_LAYOUTRECALL reply: cb_status=%d (%s)",
                         reply->status,
                         returning ? "client returning" : "no return expected");
    } else {
        chimera_nfs_error("CB_LAYOUTRECALL transport failed: rpc status=%d", status);
    }

    if (!returning) {
        /* No LAYOUTRETURN will arrive: resume the deferred ops now and drop the
         * now-stale layout state. */
        struct nfs_layout_state *layout;

        chimera_nfs4_layout_recall_resolve(ctx->client, ctx->fh, ctx->fhlen);

        layout = nfs_layout_state_find(ctx->client, ctx->fh, ctx->fhlen);
        if (layout) {
            nfs_layout_state_destroy(layout,
                                     &ctx->thread->shared->nfs4_state_table,
                                     ctx->thread->vfs_thread);
        }
    }

    free(ctx);
} /* nfs4_cb_recall_reply */

/* Build and send CB_COMPOUND{CB_SEQUENCE, CB_LAYOUTRECALL} for the whole-file
 * layout the client holds for fh, carrying the file's current layout stateid. */
static void
nfs4_cb_send_recall(
    struct chimera_server_nfs_thread *thread,
    struct nfs4_session              *session,
    struct nfs_layout_state          *layout,
    const uint8_t                    *fh,
    uint16_t                          fhlen)
{
    struct nfs_client         *client = session->client_unified;
    struct CB_COMPOUND4args    args;
    struct nfs_cb_argop4       argop[2];
    struct nfs4_cb_recall_ctx *ctx;
    struct stateid4            recall_stateid;

    nfs4_stateid_encode(&recall_stateid, layout->seqid, NFS4_STATEID_TYPE_LAYOUT,
                        layout->shard, layout->slot_idx, layout->generation,
                        (uint32_t) client->client_id);

    memset(&args, 0, sizeof(args));
    memset(argop, 0, sizeof(argop));

    args.minorversion = 1;
    args.num_argarray = 2;
    args.argarray     = argop;

    argop[0].argop = OP_CB_SEQUENCE;
    memcpy(argop[0].opcbsequence.csa_sessionid, session->nfs4_session_id,
           NFS4_SESSIONID_SIZE);
    argop[0].opcbsequence.csa_sequenceid     = session->nfs4_session_cb_seqid;
    argop[0].opcbsequence.csa_slotid         = 0;
    argop[0].opcbsequence.csa_highest_slotid = 0;
    argop[0].opcbsequence.csa_cachethis      = 0;

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
    ctx->client  = client;
    memcpy(ctx->fh, fh, fhlen);
    ctx->fhlen = fhlen;

    chimera_nfs_info("CB: sending CB_LAYOUTRECALL fhlen=%u seqid=%u",
                     fhlen, session->nfs4_session_cb_seqid);

    thread->shared->nfs_v4_cb.send_call_CB_COMPOUND(
        &session->nfs4_session_cb_prog, thread->evpl,
        session->nfs4_session_cb_conn, &nfs4_cb_cred,
        &args, 0, 0, 0, nfs4_cb_recall_reply, ctx);
} /* nfs4_cb_send_recall */

void
chimera_nfs4_cb_recall_and_wait(
    struct chimera_server_nfs_thread *thread,
    struct nfs4_session              *session,
    const uint8_t                    *fh,
    uint32_t                          fhlen,
    void (                           *resume )(void *arg),
    void                             *resume_arg)
{
    struct nfs_client         *client = session ? session->client_unified : NULL;
    struct nfs_layout_state   *layout;
    struct nfs4_recall_waiter *waiter;
    int                        send_recall = 0;

    /* No session/backchannel -> cannot recall; just proceed. */
    if (!client || !session->nfs4_session_cb_conn) {
        resume(resume_arg);
        return;
    }

    pthread_mutex_lock(&client->lock);

    HASH_FIND(hh, client->layouts_by_fh, fh, fhlen, layout);
    if (!layout) {
        /* Nothing held -> no conflict, proceed immediately. */
        pthread_mutex_unlock(&client->lock);
        resume(resume_arg);
        return;
    }

    waiter                 = calloc(1, sizeof(*waiter));
    waiter->resume         = resume;
    waiter->arg            = resume_arg;
    waiter->next           = layout->recall_waiters;
    layout->recall_waiters = waiter;

    if (!layout->recall_active) {
        layout->recall_active = 1;
        send_recall           = 1;
    }

    pthread_mutex_unlock(&client->lock);

    /* Only the first conflicting op kicks off the recall; later ones just queue
     * behind it and are released by the same resolution. */
    if (send_recall) {
        nfs4_cb_send_recall(thread, session, layout, fh, fhlen);
    }
} /* chimera_nfs4_cb_recall_and_wait */
