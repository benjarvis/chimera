// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <arpa/inet.h>
#include "nfs4_procs.h"
#include "nfs4_status.h"
#include "vfs/vfs_procs.h"
#include "vfs/vfs_release.h"

static int
chimera_nfs4_listxattrs_callback(
    const char *key,
    int         key_len,
    uint64_t    cookie,
    void       *arg)
{
    struct nfs_request                *req    = arg;
    struct LISTXATTRS4args            *args   = &req->args_compound->argarray[req->index].oplistxattrs;
    struct nfs_nfs4_listxattrs_cursor *cursor = &req->listxattrs4_cursor;
    uint32_t                           entry_size;
    char                              *buffer;
    uint32_t                          *length_ptr;

    /* Calculate XDR overhead: 4 bytes for string length + RNDUP(key_len) for data */
    entry_size = 4 + ((key_len + 3) & ~3);

    /* Check if adding this entry would exceed maxcount */
    if (cursor->count + entry_size > args->lxa_maxcount) {
        /* Buffer full - stop iteration */
        return -1;
    }

    /* Allocate or reallocate buffer to hold the new entry */
    if (cursor->names) {
        xdr_dbuf_alloc_space(buffer, cursor->count + entry_size, req->msg->dbuf);
        memcpy(buffer, cursor->names, cursor->count);
        cursor->names = buffer;
    } else {
        xdr_dbuf_alloc_space(cursor->names, entry_size, req->msg->dbuf);
    }

    /* Append this key: 4-byte length + key data (padded to 4-byte boundary) */
    length_ptr = (uint32_t *)(cursor->names + cursor->count);
    *length_ptr = htonl(key_len);
    memcpy(cursor->names + cursor->count + 4, key, key_len);

    /* Zero out padding bytes */
    if (key_len & 3) {
        memset(cursor->names + cursor->count + 4 + key_len, 0, 4 - (key_len & 3));
    }

    cursor->count += entry_size;
    cursor->num_names++;

    return 0;
} /* chimera_nfs4_listxattrs_callback */

static void
chimera_nfs4_listxattrs_complete(
    enum chimera_vfs_error          error_code,
    struct chimera_vfs_open_handle *handle,
    uint64_t                        cookie,
    uint32_t                        eof,
    struct chimera_vfs_attrs       *attr,
    void                           *private_data)
{
    struct nfs_request                *req    = private_data;
    struct LISTXATTRS4res             *res    = &req->res_compound.resarray[req->index].oplistxattrs;
    struct nfs_nfs4_listxattrs_cursor *cursor = &req->listxattrs4_cursor;

    if (error_code == CHIMERA_VFS_OK) {
        res->lxr_status           = NFS4_OK;
        res->lxr_value.lxr_names.data = cursor->names;
        res->lxr_value.lxr_names.len  = cursor->count;
        res->lxr_value.lxr_cookie = cookie;
        res->lxr_value.lxr_eof    = eof;
    } else {
        res->lxr_status = chimera_nfs4_errno_to_nfsstat4(error_code);
    }

    chimera_vfs_release(req->thread->vfs_thread, req->handle);
    chimera_nfs4_compound_complete(req, NFS4_OK);
} /* chimera_nfs4_listxattrs_complete */

static void
chimera_nfs4_listxattrs_open_callback(
    enum chimera_vfs_error          error_code,
    struct chimera_vfs_open_handle *handle,
    void                           *private_data)
{
    struct nfs_request                *req    = private_data;
    struct LISTXATTRS4args            *args   = &req->args_compound->argarray[req->index].oplistxattrs;
    struct nfs_nfs4_listxattrs_cursor *cursor;

    if (error_code != CHIMERA_VFS_OK) {
        chimera_nfs4_compound_complete(req, chimera_nfs4_errno_to_nfsstat4(error_code));
        return;
    }

    req->handle = handle;

    /* Initialize cursor structure */
    cursor = &req->listxattrs4_cursor;
    cursor->count     = 0;
    cursor->maxcount  = args->lxa_maxcount;
    cursor->num_names = 0;
    cursor->names     = NULL;

    /* Validate maxcount - must be at least 8 bytes (4 for one length + 4 for minimal key) */
    if (args->lxa_maxcount < 8) {
        chimera_vfs_release(req->thread->vfs_thread, handle);
        chimera_nfs4_compound_complete(req, NFS4ERR_TOOSMALL);
        return;
    }

    chimera_vfs_listxattr(req->thread->vfs_thread,
                          handle,
                          0,
                          args->lxa_cookie,
                          chimera_nfs4_listxattrs_callback,
                          chimera_nfs4_listxattrs_complete,
                          req);
} /* chimera_nfs4_listxattrs_open_callback */

void
chimera_nfs4_listxattrs(
    struct chimera_server_nfs_thread *thread,
    struct nfs_request               *req,
    struct nfs_argop4                *argop,
    struct nfs_resop4                *resop)
{
    chimera_vfs_open(thread->vfs_thread,
                     req->fh,
                     req->fhlen,
                     CHIMERA_VFS_OPEN_INFERRED | CHIMERA_VFS_OPEN_PATH,
                     chimera_nfs4_listxattrs_open_callback,
                     req);
} /* chimera_nfs4_listxattrs */
