// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "nfs4_procs.h"
#include "nfs4_status.h"
#include "vfs/vfs_procs.h"
#include "vfs/vfs_release.h"

static void
chimera_nfs4_getxattr_complete(
    enum chimera_vfs_error    error_code,
    uint32_t                  value_length,
    struct evpl_iovec        *value_iov,
    int                       value_niov,
    struct chimera_vfs_attrs *attr,
    void                     *private_data)
{
    struct nfs_request  *req = private_data;
    struct GETXATTR4res *res = &req->res_compound.resarray[req->index].opgetxattr;

    if (error_code == CHIMERA_VFS_OK) {
        res->gxr_status       = NFS4_OK;
        res->gxr_value.length = value_length;
        res->gxr_value.iov    = value_iov;
        res->gxr_value.niov   = value_niov;
    } else {
        res->gxr_status = chimera_nfs4_errno_to_nfsstat4(error_code);
    }

    chimera_vfs_release(req->thread->vfs_thread, req->handle);
    chimera_nfs4_compound_complete(req, NFS4_OK);
} /* chimera_nfs4_getxattr_complete */

static void
chimera_nfs4_getxattr_open_callback(
    enum chimera_vfs_error          error_code,
    struct chimera_vfs_open_handle *handle,
    void                           *private_data)
{
    struct nfs_request   *req  = private_data;
    struct GETXATTR4args *args = &req->args_compound->argarray[req->index].opgetxattr;
    struct evpl_rpc2_msg *msg  = req->msg;
    struct evpl_iovec    *iov;

    if (error_code != CHIMERA_VFS_OK) {
        chimera_nfs4_compound_complete(req, chimera_nfs4_errno_to_nfsstat4(error_code));
        return;
    }

    req->handle = handle;

    /* Allocate iovec array for zero-copy xattr value */
    xdr_dbuf_alloc_space(iov, sizeof(*iov) * 64, msg->dbuf);

    chimera_vfs_getxattr(req->thread->vfs_thread,
                         handle,
                         args->gxa_name.data,
                         args->gxa_name.len,
                         iov,
                         64,
                         0,
                         chimera_nfs4_getxattr_complete,
                         req);
} /* chimera_nfs4_getxattr_open_callback */

void
chimera_nfs4_getxattr(
    struct chimera_server_nfs_thread *thread,
    struct nfs_request               *req,
    struct nfs_argop4                *argop,
    struct nfs_resop4                *resop)
{
    chimera_vfs_open(thread->vfs_thread,
                     req->fh,
                     req->fhlen,
                     CHIMERA_VFS_OPEN_INFERRED | CHIMERA_VFS_OPEN_PATH,
                     chimera_nfs4_getxattr_open_callback,
                     req);
} /* chimera_nfs4_getxattr */
