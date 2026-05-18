// SPDX-FileCopyrightText: 2025-2026 Chimera-NAS Project Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <stdatomic.h>
#include <stdbool.h>
#include <uthash.h>

#include "nfs3_xdr.h"
#include "nfs4_xdr.h"
#include "nfs_internal.h"
#include "vfs/vfs.h"

struct evpl_rpc2_conn;
struct nfs_request;

#define NFS4_SESSION_MAX_STATE        1024

#define NFS4_STATE_TYPE_OPEN          0
#define NFS4_STATE_TYPE_LOCK          1

/* RPC slot table caps (NFS4.1 SEQUENCE replay cache).  These are *server*
 * ceilings on what a client can negotiate at CREATE_SESSION; the negotiated
 * value is min(client_request, server_cap). */
#define NFS4_MAX_REPLY_CACHE_SLOTS    64u
#define NFS4_MAX_CACHED_RESPONSE_SIZE (64u * 1024u)
#define NFS4_MAX_REPLY_CACHE_BYTES    (4u * 1024u * 1024u)

enum nfs4_slot_state {
    NFS4_SLOT_UNUSED      = 0,
    NFS4_SLOT_IN_PROGRESS = 1,
    NFS4_SLOT_CACHED      = 2, /* completed; cachethis=true; bytes held */
    NFS4_SLOT_COMPLETED   = 3, /* completed; cachethis=false; no bytes */
};

/* Set on req->replay_action by the SEQUENCE handler so the compound
 * dispatcher knows whether to execute the compound normally or to
 * short-circuit and replay a cached reply. */
#define NFS4_REPLAY_ACTION_NONE       0
#define NFS4_REPLAY_ACTION_NEW        1
#define NFS4_REPLAY_ACTION_FROM_CACHE 2

struct nfs4_replay_slot {
    uint32_t seqid;          /* last completed seqid (in CACHED/COMPLETED) */
    uint32_t inflight_seqid; /* seqid being processed when IN_PROGRESS */
    uint8_t  state;          /* enum nfs4_slot_state */
    uint8_t  cachethis;      /* sa_cachethis from current inflight */
    uint32_t cached_len;     /* bytes in cached_buf (CACHED only) */
    void    *cached_buf;     /* RPC reply (header+body); malloc'd */
};

/* Magic stored in nfs4_session.magic so that a connection's private_data
 * (which may hold either an nlm_client* or an nfs4_session*) can be safely
 * type-checked in the disconnect handler.  Must match the layout of
 * nlm_client (uint32_t magic at offset 0). */
#define NFS4_SESSION_MAGIC 0x4E465353U     /* "NFSS" */

struct nfs4_state {
    struct stateid4                 nfs4_state_id;
    uint16_t                        nfs4_state_type;
    uint16_t                        nfs4_state_active;
    uint32_t                        nfs4_state_refcnt;
    struct chimera_vfs_open_handle *nfs4_state_handle;
    uint32_t                        nfs4_state_parent_slot; /* open slot index for LOCK states */
};

struct nfs4_client {
    uint64_t              nfs4_client_id;
    uint32_t              nfs4_client_owner_len;
    uint32_t              nfs4_client_refcnt;
    uint32_t              nfs4_client_proto;
    uint64_t              nfs4_client_verifier;
    struct UT_hash_handle nfs4_client_hh_by_owner;
    struct UT_hash_handle nfs4_client_hh_by_id;
    uint8_t               nfs4_client_owner[NFS4_OPAQUE_LIMIT];
    char                  nfs4_client_domain[NFS4_OPAQUE_LIMIT];
    char                  nfs4_client_name[NFS4_OPAQUE_LIMIT];
};

struct nfs4_session {
    /* magic MUST be the first member -- see NFS4_SESSION_MAGIC comment. */
    uint32_t                 magic;
    _Atomic uint32_t         refcount;
    _Atomic bool             destroyed;
    uint8_t                  nfs4_session_id[NFS4_SESSIONID_SIZE];
    uint64_t                 nfs4_session_clientid;
    pthread_mutex_t          nfs4_session_lock;
    uint32_t                 num_free_slots;
    struct nfs4_state        nfs4_session_state[NFS4_SESSION_MAX_STATE];
    uint16_t                 free_slot[NFS4_SESSION_MAX_STATE];
    uint32_t                 nfs4_session_implicit;
    struct nfs4_client      *nfs4_session_client;
    struct channel_attrs4    nfs4_session_fore_attrs;
    struct channel_attrs4    nfs4_session_back_attrs;
    uint32_t                 nfs4_session_fore_attrs_rdma_ird;
    uint32_t                 nfs4_session_back_attrs_rdma_ird;
    /* Replay cache (NFS4.1 SEQUENCE slot table).  Distinct from the
     * nfs4_session_state[] table above which holds OPEN/LOCK stateid
     * bookkeeping. */
    uint32_t                 replay_max_slots;
    uint32_t                 replay_maxresp_cached;
    size_t                   replay_bytes_in_use;
    struct nfs4_replay_slot *replay_slots;
    struct UT_hash_handle    nfs4_session_hh;
};

struct nfs4_client_table {
    struct nfs4_client  *nfs4_ct_clients_by_owner;
    struct nfs4_client  *nfs4_ct_clients_by_id;
    struct nfs4_session *nfs4_ct_sessions;
    uint64_t             nfs4_ct_next_client_id;
    pthread_mutex_t      nfs4_ct_lock;
};

void
nfs4_client_table_init(
    struct nfs4_client_table *table);

void
nfs4_client_table_free(
    struct nfs4_client_table *table);

void
nfs4_client_table_release_handles(
    struct nfs4_client_table  *table,
    struct chimera_vfs_thread *vfs_thread);

uint64_t
nfs4_client_register(
    struct nfs4_client_table *table,
    const void               *owner,
    int                       owner_len,
    uint64_t                  verifier,
    uint32_t                  proto,
    const char               *nii_domain,
    const char               *nii_name);

void
nfs4_client_unregister(
    struct nfs4_client_table *table,
    uint64_t                  client_id);

struct nfs4_session *
nfs4_create_session(
    struct nfs4_client_table    *table,
    uint64_t                     client_id,
    uint32_t                     implicit,
    uint32_t                     replay_max_slots,
    uint32_t                     replay_maxresp_cached,
    const struct channel_attrs4 *fore_attrs,
    const struct channel_attrs4 *back_attrs);

/* SEQUENCE replay slot state machine.  See plan in
 * /root/.claude/plans/lets-plan-out-the-steady-steele.md for the full
 * state diagram.  Returns NFS4_OK on success (NEW request or REPLAY hit),
 * otherwise an NFS4ERR_* code (BADSLOT / SEQ_MISORDERED / RETRY_UNCACHED_REP).
 * On NFS4_OK with *out_is_replay=true the caller must short-circuit the
 * compound and replay slot->cached_buf.
 *
 * On NFS4_OK the slot pointer and slot id are stashed on req for the
 * compound dispatcher to consume at finalize time.  cachethis is recorded
 * for the in-flight request and consulted only at finalize. */
nfsstat4 nfs4_replay_slot_acquire(
    struct nfs4_session *session,
    uint32_t             slotid,
    uint32_t             seqid,
    bool                 cachethis,
    struct nfs_request  *req,
    bool                *out_is_replay);

/* Called by the compound dispatcher just before sending the reply.  In
 * Phase 1 this advances IN_PROGRESS -> COMPLETED.  Phase 2 will optionally
 * capture the encoded reply bytes and transition to CACHED. */
void nfs4_replay_slot_finalize(
    struct nfs_request *req);

struct nfs4_session *
nfs4_session_lookup(
    struct nfs4_client_table *table,
    const void               *sessionid);

void
nfs4_destroy_session(
    struct nfs4_client_table *table,
    const void               *session_id);

struct nfs4_session *
nfs4_session_find_by_clientid(
    struct nfs4_client_table *table,
    uint64_t                  client_id);

/*
 * Reference counting for nfs4_session.
 *
 * A session is referenced by:
 *   - the client table (1 ref, dropped by nfs4_destroy_session or
 *     nfs4_client_table_free)
 *   - every evpl_rpc2_conn whose private_data points to it (1 ref each,
 *     installed by nfs4_session_bind_conn, dropped by
 *     nfs4_session_unbind_conn from the disconnect notify)
 *
 * nfs4_session_lookup() and nfs4_session_find_by_clientid() both return
 * a session with +1 ref.  Callers must release that ref with
 * nfs4_session_put() (either directly, or by binding it to a conn and then
 * putting the lookup ref).
 *
 * nfs4_session_bind_conn() takes its own +1 ref; it does NOT consume the
 * caller's ref.
 */
void nfs4_session_get(
    struct nfs4_session *session);
void nfs4_session_put(
    struct nfs4_session *session);
void nfs4_session_bind_conn(
    struct evpl_rpc2_conn *conn,
    struct nfs4_session   *session);
void nfs4_session_unbind_conn(
    struct evpl_rpc2_conn *conn);

static inline bool
nfs4_session_is_live(struct nfs4_session *session)
{
    return session &&
           session->magic == NFS4_SESSION_MAGIC &&
           !atomic_load_explicit(&session->destroyed, memory_order_acquire);
} // nfs4_session_is_live

static inline struct nfs4_state *
nfs4_session_alloc_slot(struct nfs4_session *session)
{
    uint32_t           slot;
    struct nfs4_state *state;

    pthread_mutex_lock(&session->nfs4_session_lock);

    chimera_nfs_abort_if(session->num_free_slots == 0, "no free session slots");

    slot  = session->free_slot[--session->num_free_slots];
    state = &session->nfs4_session_state[slot];

    state->nfs4_state_id.seqid = 1;

    *(uint32_t *) state->nfs4_state_id.other       = slot;
    *(uint64_t *) (state->nfs4_state_id.other + 4) = session->nfs4_session_clientid;

    state->nfs4_state_type        = NFS4_STATE_TYPE_OPEN;
    state->nfs4_state_active      = 1;
    state->nfs4_state_refcnt      = 0;
    state->nfs4_state_handle      = NULL;
    state->nfs4_state_parent_slot = NFS4_SESSION_MAX_STATE;

    pthread_mutex_unlock(&session->nfs4_session_lock);

    return state;
} /* nfs4_session_alloc_slot */

static inline int
nfs4_session_free_slot(
    struct nfs4_session             *session,
    struct nfs4_state               *state,
    struct chimera_vfs_open_handle **out_handle)
{
    uint32_t slot = *(uint32_t *) state->nfs4_state_id.other;

    *out_handle = NULL;

    pthread_mutex_lock(&session->nfs4_session_lock);

    if (!state->nfs4_state_active) {
        pthread_mutex_unlock(&session->nfs4_session_lock);
        return -1;
    }

    state->nfs4_state_active = 0;

    if (state->nfs4_state_refcnt == 0) {
        if (state->nfs4_state_type != NFS4_STATE_TYPE_LOCK) {
            *out_handle = state->nfs4_state_handle;
        }
        state->nfs4_state_handle                      = NULL;
        session->free_slot[session->num_free_slots++] = slot;
        pthread_mutex_unlock(&session->nfs4_session_lock);
        return 0;
    }

    /* refcnt > 0: deferred cleanup by last release_state */
    pthread_mutex_unlock(&session->nfs4_session_lock);
    return 1;
} /* nfs4_session_free_slot */

static inline void
nfs4_session_free_lock_states(
    struct nfs4_session *session,
    uint32_t             open_slot)
{
    struct chimera_vfs_open_handle *unused;
    uint32_t                        i;

    for (i = 0; i < NFS4_SESSION_MAX_STATE; i++) {
        struct nfs4_state *s = &session->nfs4_session_state[i];

        if (s->nfs4_state_type        == NFS4_STATE_TYPE_LOCK &&
            s->nfs4_state_active      == 1 &&
            s->nfs4_state_parent_slot == open_slot) {
            s->nfs4_state_handle = NULL;
            nfs4_session_free_slot(session, s, &unused);
        }
    }
} /* nfs4_session_free_lock_states */

static inline struct nfs4_state *
nfs4_session_get_state(
    struct nfs4_session   *session,
    const struct stateid4 *stateid)
{
    uint32_t slot = *(uint32_t *) stateid->other;

    return &session->nfs4_session_state[slot];
} /* nfs4_session_get_state */

static inline nfsstat4
nfs4_session_acquire_state(
    struct nfs4_session             *session,
    const struct stateid4           *stateid,
    struct nfs4_state              **out_state,
    struct chimera_vfs_open_handle **out_handle)
{
    uint32_t           slot     = *(uint32_t *) stateid->other;
    uint64_t           clientid = *(uint64_t *) (stateid->other + 4);
    struct nfs4_state *state;

    *out_state  = NULL;
    *out_handle = NULL;

    if (slot >= NFS4_SESSION_MAX_STATE) {
        return NFS4ERR_BAD_STATEID;
    }

    if (clientid != session->nfs4_session_clientid) {
        return NFS4ERR_BAD_STATEID;
    }

    state = &session->nfs4_session_state[slot];

    pthread_mutex_lock(&session->nfs4_session_lock);

    if (!state->nfs4_state_active || !state->nfs4_state_handle) {
        pthread_mutex_unlock(&session->nfs4_session_lock);
        return NFS4ERR_BAD_STATEID;
    }

    state->nfs4_state_refcnt++;
    *out_state  = state;
    *out_handle = state->nfs4_state_handle;

    pthread_mutex_unlock(&session->nfs4_session_lock);
    return NFS4_OK;
} /* nfs4_session_acquire_state */

static inline struct chimera_vfs_open_handle *
nfs4_session_release_state(
    struct nfs4_session *session,
    struct nfs4_state   *state)
{
    struct chimera_vfs_open_handle *handle = NULL;

    pthread_mutex_lock(&session->nfs4_session_lock);

    state->nfs4_state_refcnt--;

    if (state->nfs4_state_refcnt == 0 && !state->nfs4_state_active) {
        /* CLOSE already ran; we are the last user - do deferred cleanup */
        if (state->nfs4_state_type != NFS4_STATE_TYPE_LOCK) {
            handle = state->nfs4_state_handle;
        }
        state->nfs4_state_handle = NULL;
        uint32_t slot = *(uint32_t *) state->nfs4_state_id.other;
        session->free_slot[session->num_free_slots++] = slot;
    }

    pthread_mutex_unlock(&session->nfs4_session_lock);
    return handle;
} /* nfs4_session_release_state */

static inline nfsstat4
nfs4_session_validate_stateid(
    struct nfs4_session   *session,
    const struct stateid4 *stateid)
{
    uint32_t           slot     = *(uint32_t *) stateid->other;
    uint64_t           clientid = *(uint64_t *) (stateid->other + 4);
    struct nfs4_state *state;
    nfsstat4           status;

    if (slot >= NFS4_SESSION_MAX_STATE) {
        return NFS4ERR_BAD_STATEID;
    }

    if (clientid != session->nfs4_session_clientid) {
        return NFS4ERR_BAD_STATEID;
    }

    state = &session->nfs4_session_state[slot];

    pthread_mutex_lock(&session->nfs4_session_lock);

    if (!state->nfs4_state_active) {
        status = NFS4ERR_BAD_STATEID;
    } else {
        status = NFS4_OK;
    }

    pthread_mutex_unlock(&session->nfs4_session_lock);

    return status;
} /* nfs4_session_validate_stateid */

/*
 * Resolve the session for the current request.
 *
 * If `session` is non-NULL it is already borrowed via the conn's bind
 * (compound entry transitively holds a ref through evpl_rpc2_conn private_data)
 * and is returned as-is.
 *
 * Otherwise look up the session by the clientid embedded in `stateid`.  If
 * found, bind it to `conn` (taking a ref on the conn's behalf) and drop the
 * lookup's ref; the returned pointer is then borrowed via that conn ref.
 *
 * Returns NULL if no session exists for this client.
 */
static inline struct nfs4_session *
nfs4_resolve_session(
    struct nfs4_session      *session,
    struct evpl_rpc2_conn    *conn,
    struct nfs4_client_table *table,
    const struct stateid4    *stateid)
{
    uint64_t             client_id;
    struct nfs4_session *found;

    if (session) {
        return session;
    }

    client_id = *(uint64_t *) (stateid->other + 4);
    found     = nfs4_session_find_by_clientid(table, client_id);

    if (found) {
        nfs4_session_bind_conn(conn, found);
        nfs4_session_put(found);
    }

    return found;
} /* nfs4_resolve_session */
