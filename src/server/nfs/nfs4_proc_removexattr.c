// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "nfs4_procs.h"
#include "nfs4_status.h"
#include "nfs4_attr.h"
#include "vfs/vfs_procs.h"
#include "vfs/vfs_release.h"

static void
chimera_nfs4_removexattr_complete(
    enum chimera_vfs_error    error_code,
    struct chimera_vfs_attrs *pre_attr,
    struct chimera_vfs_attrs *post_attr,
    void                     *private_data)
{
    struct nfs_request     *req = private_data;
    struct REMOVEXATTR4res *res = &req->res_compound.resarray[req->index].opremovexattr;

    if (error_code == CHIMERA_VFS_OK) {
        res->rxr_status = NFS4_OK;
        chimera_nfs4_set_changeinfo(&res->rxr_info, pre_attr, post_attr);
    } else {
        res->rxr_status = chimera_nfs4_errno_to_nfsstat4(error_code);
    }

    chimera_vfs_release(req->thread->vfs_thread, req->handle);
    chimera_nfs4_compound_complete(req, NFS4_OK);
} /* chimera_nfs4_removexattr_complete */

static void
chimera_nfs4_removexattr_open_callback(
    enum chimera_vfs_error          error_code,
    struct chimera_vfs_open_handle *handle,
    void                           *private_data)
{
    struct nfs_request      *req  = private_data;
    struct REMOVEXATTR4args *args = &req->args_compound->argarray[req->index].opremovexattr;

    if (error_code != CHIMERA_VFS_OK) {
        chimera_nfs4_compound_complete(req, chimera_nfs4_errno_to_nfsstat4(error_code));
        return;
    }

    req->handle = handle;

    /* Request mtime attributes for building change_info4 */
    chimera_vfs_removexattr(req->thread->vfs_thread,
                            handle,
                            args->rxa_name.data,
                            args->rxa_name.len,
                            CHIMERA_VFS_ATTR_MTIME,
                            CHIMERA_VFS_ATTR_MTIME,
                            chimera_nfs4_removexattr_complete,
                            req);
} /* chimera_nfs4_removexattr_open_callback */

void
chimera_nfs4_removexattr(
    struct chimera_server_nfs_thread *thread,
    struct nfs_request               *req,
    struct nfs_argop4                *argop,
    struct nfs_resop4                *resop)
{
    chimera_vfs_open(thread->vfs_thread,
                     req->fh,
                     req->fhlen,
                     CHIMERA_VFS_OPEN_INFERRED | CHIMERA_VFS_OPEN_PATH,
                     chimera_nfs4_removexattr_open_callback,
                     req);
} /* chimera_nfs4_removexattr */
