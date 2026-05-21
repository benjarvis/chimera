// SPDX-FileCopyrightText: 2025-2026 Chimera-NAS Project Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * NFSv4.1 pNFS (file layout) metadata-server operations.
 *
 * v1 hands out whole-file NFSv4.1 file layouts steering each file to a single
 * data server.  The opaque bodies of device_addr4 (GETDEVICEINFO) and
 * layout_content4 (LAYOUTGET) are hand-encoded here rather than via the
 * generated marshallers: the bodies are small and fixed-shape for v1, and the
 * generated representation of the doubly-nested multipath_list4<> typedef is
 * not something we want to depend on.
 */

#include <string.h>

#include "nfs4_procs.h"
#include "nfs4_state.h"
#include "nfs4_status.h"
#include "nfs_internal.h"
#include "vfs/vfs_pnfs.h"
#include "vfs/vfs_procs.h"
#include "vfs/vfs_release.h"

#define NFS4_PNFS_STRIPE_UNIT 1048576U   /* 1 MiB; multiple of 64 (NFL util) */

/* --- minimal XDR append helpers (network byte order) --------------------- */

static inline void
pnfs_put_u32(
    void   **p,
    uint32_t value)
{
    *(uint32_t *) *p = chimera_nfs_hton32(value);
    *p              += sizeof(uint32_t);
} /* pnfs_put_u32 */

static inline void
pnfs_put_u64(
    void   **p,
    uint64_t value)
{
    *(uint64_t *) *p = chimera_nfs_hton64(value);
    *p              += sizeof(uint64_t);
} /* pnfs_put_u64 */

/* XDR opaque<>/string<>: 4-byte length, bytes, then zero padding to 4. */
static inline void
pnfs_put_opaque(
    void      **p,
    const void *data,
    uint32_t    len)
{
    uint32_t pad = (4 - (len & 3)) & 3;

    pnfs_put_u32(p, len);
    memcpy(*p, data, len);
    if (pad) {
        memset(*p + len, 0, pad);
    }
    *p += len + pad;
} /* pnfs_put_opaque */

/*
 * Encode an nfsv4_1_file_layout_ds_addr4 into buf for use as the
 * device_addr4.da_addr_body opaque.  v1: a single stripe mapped to a single
 * multipath list containing one netaddr (the chosen DS).  Returns the number
 * of bytes written.
 */
static uint32_t
chimera_nfs4_encode_ds_addr(
    uint8_t                     *buf,
    const struct chimera_vfs_ds *ds)
{
    void *p = buf;

    /* nflda_stripe_indices<> = { 0 } : stripe 0 -> multipath list index 0 */
    pnfs_put_u32(&p, 1);
    pnfs_put_u32(&p, 0);

    /* nflda_multipath_ds_list<> : one multipath_list4 ... */
    pnfs_put_u32(&p, 1);
    /* ... which is itself a netaddr4<> with one entry */
    pnfs_put_u32(&p, 1);
    pnfs_put_opaque(&p, ds->netid, strlen(ds->netid));
    pnfs_put_opaque(&p, ds->uaddr, strlen(ds->uaddr));

    return (uint8_t *) p - buf;
} /* chimera_nfs4_encode_ds_addr */

void
chimera_nfs4_getdeviceinfo(
    struct chimera_server_nfs_thread *thread,
    struct nfs_request               *req,
    struct nfs_argop4                *argop,
    struct nfs_resop4                *resop)
{
    struct GETDEVICEINFO4args   *args = &argop->opgetdeviceinfo;
    struct GETDEVICEINFO4res    *res  = &resop->opgetdeviceinfo;
    struct chimera_vfs          *vfs  = thread->shared->vfs;
    const struct chimera_vfs_ds *ds;
    uint8_t                      body[256];
    uint32_t                     body_len;
    int                          rc;

    if (!chimera_vfs_pnfs_enabled(vfs)) {
        res->gdir_status = NFS4ERR_NOTSUPP;
        chimera_nfs4_compound_complete(req, res->gdir_status);
        return;
    }

    if (args->gdia_layout_type != LAYOUT4_NFSV4_1_FILES) {
        res->gdir_status = NFS4ERR_UNKNOWN_LAYOUTTYPE;
        chimera_nfs4_compound_complete(req, res->gdir_status);
        return;
    }

    ds = chimera_vfs_pnfs_find_device(vfs, args->gdia_device_id);
    if (!ds) {
        res->gdir_status = NFS4ERR_INVAL;
        chimera_nfs4_compound_complete(req, res->gdir_status);
        return;
    }

    body_len = chimera_nfs4_encode_ds_addr(body, ds);

    /* gdia_maxcount bounds the bytes the client will accept for the
     * da_addr_body (RFC 8881 §18.40.3); signal TOOSMALL with the required
     * size if it cannot fit. */
    if (args->gdia_maxcount < body_len) {
        res->gdir_status   = NFS4ERR_TOOSMALL;
        res->gdir_mincount = body_len;
        chimera_nfs4_compound_complete(req, res->gdir_status);
        return;
    }

    res->gdir_resok4.gdir_device_addr.da_layout_type = LAYOUT4_NFSV4_1_FILES;

    rc = xdr_dbuf_opaque_copy(&res->gdir_resok4.gdir_device_addr.da_addr_body,
                              body,
                              body_len,
                              req->encoding->dbuf);
    if (rc) {
        res->gdir_status = NFS4ERR_RESOURCE;
        chimera_nfs4_compound_complete(req, res->gdir_status);
        return;
    }

    /* No device-id change notifications supported. */
    res->gdir_resok4.num_gdir_notification = 0;
    res->gdir_resok4.gdir_notification     = NULL;

    res->gdir_status = NFS4_OK;
    chimera_nfs4_compound_complete(req, NFS4_OK);
} /* chimera_nfs4_getdeviceinfo */

/*
 * Encode an nfsv4_1_file_layout4 into buf for the layout_content4.loc_body
 * opaque.  v1: one device, one data-server file handle, whole file.
 */
static uint32_t
chimera_nfs4_encode_file_layout(
    uint8_t                                 *buf,
    const struct chimera_vfs_layout_segment *seg)
{
    void *p = buf;

    memcpy(p, seg->deviceid, NFS4_DEVICEID4_SIZE);    /* nfl_deviceid (fixed) */
    p += NFS4_DEVICEID4_SIZE;

    /* nfl_util: stripe unit size with COMMIT_THRU_MDS so the client routes
     * COMMIT/LAYOUTCOMMIT to the MDS (simplest correct path for v1). */
    pnfs_put_u32(&p, NFS4_PNFS_STRIPE_UNIT | NFL4_UFLG_COMMIT_THRU_MDS);
    pnfs_put_u32(&p, 0);                              /* nfl_first_stripe_index */
    pnfs_put_u64(&p, 0);                              /* nfl_pattern_offset     */
    pnfs_put_u32(&p, 1);                              /* nfl_fh_list count      */
    pnfs_put_opaque(&p, seg->ds_fh, seg->ds_fh_len);  /* the DS file handle     */

    return (uint8_t *) p - buf;
} /* chimera_nfs4_encode_file_layout */

static void
chimera_nfs4_layoutget_complete(
    enum chimera_vfs_error             error_code,
    uint32_t                           num_segments,
    struct chimera_vfs_layout_segment *segments,
    void                              *private_data)
{
    struct nfs_request                *req   = private_data;
    struct LAYOUTGET4args             *args  = &req->args_compound->argarray[req->index].oplayoutget;
    struct LAYOUTGET4res              *res   = &req->res_compound.resarray[req->index].oplayoutget;
    struct nfs_state_table            *table = &req->thread->shared->nfs4_state_table;
    struct nfs_client                 *client;
    struct nfs_layout_state           *layout;
    struct chimera_vfs_layout_segment *seg;
    struct layout4                    *lo;
    uint8_t                           *body;
    uint32_t                           body_len, client_short_id;

    if (req->handle) {
        chimera_vfs_release(req->thread->vfs_thread, req->handle);
        req->handle = NULL;
    }

    if (error_code != CHIMERA_VFS_OK || num_segments == 0) {
        /* No layout for this file (e.g. not a pNFS-backed file) -> tell the
         * client to fall back; LAYOUTUNAVAILABLE is the spec-correct hint. */
        res->logr_status = (error_code == CHIMERA_VFS_ENOTSUP || num_segments == 0)
            ? NFS4ERR_LAYOUTUNAVAILABLE
            : chimera_nfs4_errno_to_nfsstat4(error_code);
        chimera_nfs4_compound_complete(req, res->logr_status);
        return;
    }

    seg    = &segments[0];
    client = req->session ? req->session->client_unified : NULL;

    if (!client) {
        /* pNFS requires a 4.1 session; without a unified client we have
         * nowhere to anchor the layout stateid. */
        res->logr_status = NFS4ERR_LAYOUTUNAVAILABLE;
        chimera_nfs4_compound_complete(req, res->logr_status);
        return;
    }

    client_short_id = (uint32_t) client->client_id;

    /* RFC 8881 §12.5.3: the server owns the layout stateid seqid.  Reuse the
     * per-{client,file} record if one exists (a refresh), else mint a new one
     * at seqid 1.  v1 is lenient about validating the incoming loga_stateid. */
    layout = nfs_layout_state_find(client, req->fh, req->fhlen);
    if (layout) {
        nfs_layout_state_bump(layout, client_short_id,
                              &res->logr_resok4.logr_stateid);
    } else {
        nfs_layout_state_create(client, req->fh, req->fhlen,
                                args->loga_iomode, client_short_id, table,
                                &res->logr_resok4.logr_stateid);
    }

    body = xdr_dbuf_alloc_space(256, req->encoding->dbuf);
    chimera_nfs_abort_if(body == NULL, "Failed to allocate space");
    body_len = chimera_nfs4_encode_file_layout(body, seg);

    lo = xdr_dbuf_alloc_space(sizeof(*lo), req->encoding->dbuf);
    chimera_nfs_abort_if(lo == NULL, "Failed to allocate space");

    lo->lo_offset           = 0;
    lo->lo_length           = UINT64_MAX;      /* whole file / to EOF */
    lo->lo_iomode           = args->loga_iomode;
    lo->lo_content.loc_type = LAYOUT4_NFSV4_1_FILES;

    int rc = xdr_dbuf_opaque_copy(&lo->lo_content.loc_body, body, body_len,
                                  req->encoding->dbuf);
    chimera_nfs_abort_if(rc, "Failed to copy layout body");

    res->logr_resok4.logr_return_on_close = 0;
    res->logr_resok4.num_logr_layout      = 1;
    res->logr_resok4.logr_layout          = lo;

    res->logr_status = NFS4_OK;
    chimera_nfs4_compound_complete(req, NFS4_OK);
} /* chimera_nfs4_layoutget_complete */

static void
chimera_nfs4_layoutget_open_callback(
    enum chimera_vfs_error          error_code,
    struct chimera_vfs_open_handle *handle,
    void                           *private_data)
{
    struct nfs_request    *req  = private_data;
    struct LAYOUTGET4args *args = &req->args_compound->argarray[req->index].oplayoutget;
    struct LAYOUTGET4res  *res  = &req->res_compound.resarray[req->index].oplayoutget;

    if (error_code != CHIMERA_VFS_OK) {
        res->logr_status = chimera_nfs4_errno_to_nfsstat4(error_code);
        chimera_nfs4_compound_complete(req, res->logr_status);
        return;
    }

    req->handle = handle;

    chimera_vfs_get_layout(req->thread->vfs_thread, &req->cred, handle,
                           args->loga_offset, args->loga_length,
                           args->loga_iomode,
                           CHIMERA_VFS_LAYOUT_TYPE_NFSV4_FILES,
                           chimera_nfs4_layoutget_complete, req);
} /* chimera_nfs4_layoutget_open_callback */

void
chimera_nfs4_layoutget(
    struct chimera_server_nfs_thread *thread,
    struct nfs_request               *req,
    struct nfs_argop4                *argop,
    struct nfs_resop4                *resop)
{
    struct LAYOUTGET4args *args = &argop->oplayoutget;
    struct LAYOUTGET4res  *res  = &resop->oplayoutget;

    req->handle = NULL;

    if (!chimera_vfs_pnfs_enabled(thread->shared->vfs)) {
        res->logr_status = NFS4ERR_NOTSUPP;
        chimera_nfs4_compound_complete(req, res->logr_status);
        return;
    }

    if (args->loga_layout_type != LAYOUT4_NFSV4_1_FILES) {
        res->logr_status = NFS4ERR_UNKNOWN_LAYOUTTYPE;
        chimera_nfs4_compound_complete(req, res->logr_status);
        return;
    }

    if (req->fhlen == 0) {
        res->logr_status = NFS4ERR_NOFILEHANDLE;
        chimera_nfs4_compound_complete(req, res->logr_status);
        return;
    }

    /* Open the current FH to obtain a handle for the VFS layout query. */
    chimera_vfs_open_fh(thread->vfs_thread, &req->cred,
                        req->fh, req->fhlen,
                        CHIMERA_VFS_OPEN_INFERRED | CHIMERA_VFS_OPEN_READ_ONLY,
                        chimera_nfs4_layoutget_open_callback, req);
} /* chimera_nfs4_layoutget */

void
chimera_nfs4_layoutreturn(
    struct chimera_server_nfs_thread *thread,
    struct nfs_request               *req,
    struct nfs_argop4                *argop,
    struct nfs_resop4                *resop)
{
    struct LAYOUTRETURN4args *args = &argop->oplayoutreturn;
    struct LAYOUTRETURN4res  *res  = &resop->oplayoutreturn;
    struct nfs_client        *client;

    if (!chimera_vfs_pnfs_enabled(thread->shared->vfs)) {
        res->lorr_status = NFS4ERR_NOTSUPP;
        chimera_nfs4_compound_complete(req, res->lorr_status);
        return;
    }

    if (args->lora_layout_type != LAYOUT4_NFSV4_1_FILES) {
        res->lorr_status = NFS4ERR_UNKNOWN_LAYOUTTYPE;
        chimera_nfs4_compound_complete(req, res->lorr_status);
        return;
    }

    client = req->session ? req->session->client_unified : NULL;

    /* v1 tracks a single whole-file layout per file, so a FILE return drops
     * the record entirely.  FSID/ALL returns are accepted as no-ops. */
    if (client &&
        args->lora_layoutreturn.lr_returntype == LAYOUTRETURN4_FILE) {
        struct nfs_layout_state *layout =
            nfs_layout_state_find(client, req->fh, req->fhlen);

        if (layout) {
            nfs_layout_state_destroy(layout,
                                     &thread->shared->nfs4_state_table,
                                     thread->vfs_thread);
        }
    }

    /* The whole layout is gone, so no layout stateid is returned
     * (RFC 8881 §18.44.3). */
    res->lorr_stateid.lrs_present = 0;
    res->lorr_status              = NFS4_OK;
    chimera_nfs4_compound_complete(req, NFS4_OK);
} /* chimera_nfs4_layoutreturn */

void
chimera_nfs4_getdevicelist(
    struct chimera_server_nfs_thread *thread,
    struct nfs_request               *req,
    struct nfs_argop4                *argop,
    struct nfs_resop4                *resop)
{
    struct GETDEVICELIST4res *res = &resop->opgetdevicelist;

    (void) thread;
    (void) argop;

    /* GETDEVICELIST is deprecated (RFC 8434); clients discover devices via
     * the deviceid returned in LAYOUTGET + GETDEVICEINFO. */
    res->gdlr_status = NFS4ERR_NOTSUPP;
    chimera_nfs4_compound_complete(req, res->gdlr_status);
} /* chimera_nfs4_getdevicelist */

static void
chimera_nfs4_layoutcommit_setattr_complete(
    enum chimera_vfs_error    error_code,
    struct chimera_vfs_attrs *pre_attr,
    struct chimera_vfs_attrs *set_attr,
    struct chimera_vfs_attrs *post_attr,
    void                     *private_data)
{
    struct nfs_request      *req = private_data;
    struct LAYOUTCOMMIT4res *res = &req->res_compound.resarray[req->index].oplayoutcommit;

    (void) pre_attr;
    (void) set_attr;

    if (req->handle) {
        chimera_vfs_release(req->thread->vfs_thread, req->handle);
        req->handle = NULL;
    }

    if (error_code != CHIMERA_VFS_OK) {
        res->locr_status = chimera_nfs4_errno_to_nfsstat4(error_code);
        chimera_nfs4_compound_complete(req, res->locr_status);
        return;
    }

    res->locr_resok4.locr_newsize.ns_sizechanged = 1;
    res->locr_resok4.locr_newsize.ns_size        =
        (post_attr && (post_attr->va_set_mask & CHIMERA_VFS_ATTR_SIZE))
        ? post_attr->va_size : 0;

    res->locr_status = NFS4_OK;
    chimera_nfs4_compound_complete(req, NFS4_OK);
} /* chimera_nfs4_layoutcommit_setattr_complete */

static void
chimera_nfs4_layoutcommit_open_callback(
    enum chimera_vfs_error          error_code,
    struct chimera_vfs_open_handle *handle,
    void                           *private_data)
{
    struct nfs_request       *req  = private_data;
    struct LAYOUTCOMMIT4args *args = &req->args_compound->argarray[req->index].oplayoutcommit;
    struct LAYOUTCOMMIT4res  *res  = &req->res_compound.resarray[req->index].oplayoutcommit;
    struct chimera_vfs_attrs *set_attr;

    if (error_code != CHIMERA_VFS_OK) {
        res->locr_status = chimera_nfs4_errno_to_nfsstat4(error_code);
        chimera_nfs4_compound_complete(req, res->locr_status);
        return;
    }

    req->handle = handle;

    /* No new high-water byte reported: nothing to sync to the MDS. */
    if (!args->loca_last_write_offset.no_newoffset) {
        chimera_vfs_release(req->thread->vfs_thread, req->handle);
        req->handle                                  = NULL;
        res->locr_resok4.locr_newsize.ns_sizechanged = 0;
        res->locr_status                             = NFS4_OK;
        chimera_nfs4_compound_complete(req, NFS4_OK);
        return;
    }

    /* Compound-lifetime storage so it outlives this async setattr. */
    set_attr = xdr_dbuf_alloc_space(sizeof(*set_attr), req->encoding->dbuf);
    chimera_nfs_abort_if(set_attr == NULL, "Failed to allocate space");

    set_attr->va_req_mask = 0;
    set_attr->va_set_mask = CHIMERA_VFS_ATTR_SIZE;
    set_attr->va_size     = args->loca_last_write_offset.no_offset + 1;

    if (args->loca_time_modify.nt_timechanged) {
        set_attr->va_set_mask     |= CHIMERA_VFS_ATTR_MTIME;
        set_attr->va_mtime.tv_sec  = args->loca_time_modify.nt_time.seconds;
        set_attr->va_mtime.tv_nsec = args->loca_time_modify.nt_time.nseconds;
    }

    chimera_vfs_setattr(req->thread->vfs_thread, &req->cred, handle,
                        set_attr, 0, CHIMERA_VFS_ATTR_SIZE,
                        chimera_nfs4_layoutcommit_setattr_complete, req);
} /* chimera_nfs4_layoutcommit_open_callback */

void
chimera_nfs4_layoutcommit(
    struct chimera_server_nfs_thread *thread,
    struct nfs_request               *req,
    struct nfs_argop4                *argop,
    struct nfs_resop4                *resop)
{
    struct LAYOUTCOMMIT4res *res = &resop->oplayoutcommit;

    req->handle = NULL;

    if (!chimera_vfs_pnfs_enabled(thread->shared->vfs)) {
        res->locr_status = NFS4ERR_NOTSUPP;
        chimera_nfs4_compound_complete(req, res->locr_status);
        return;
    }

    if (req->fhlen == 0) {
        res->locr_status = NFS4ERR_NOFILEHANDLE;
        chimera_nfs4_compound_complete(req, res->locr_status);
        return;
    }

    /* Open the MDS file to apply the client-reported size/mtime.  Data lives
     * on the DS; with COMMIT_THRU_MDS the client reports the new high-water
     * mark here so MDS metadata catches up. */
    chimera_vfs_open_fh(thread->vfs_thread, &req->cred,
                        req->fh, req->fhlen,
                        CHIMERA_VFS_OPEN_INFERRED,
                        chimera_nfs4_layoutcommit_open_callback, req);
} /* chimera_nfs4_layoutcommit */
