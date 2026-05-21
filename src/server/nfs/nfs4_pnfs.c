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
#include "nfs_internal.h"
#include "vfs/vfs_pnfs.h"

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
