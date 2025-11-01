// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "nfs4_procs.h"
#include "nfs4_status.h"
#include "nfs4_attr.h"
#include "vfs/vfs_procs.h"
#include "vfs/vfs_release.h"

static void
chimera_nfs4_setxattr_complete(
    enum chimera_vfs_error    error_code,
    struct chimera_vfs_attrs *pre_attr,
    struct chimera_vfs_attrs *post_attr,
    void                     *private_data)
{
    struct nfs_request  *req = private_data;
    struct SETXATTR4res *res = &req->res_compound.resarray[req->index].opsetxattr;

    if (error_code == CHIMERA_VFS_OK) {
        res->sxr_status = NFS4_OK;
        chimera_nfs4_set_changeinfo(&res->sxr_info, pre_attr, post_attr);
    } else {
        res->sxr_status = chimera_nfs4_errno_to_nfsstat4(error_code);
    }

    chimera_vfs_release(req->thread->vfs_thread, req->handle);
    chimera_nfs4_compound_complete(req, NFS4_OK);
} /* chimera_nfs4_setxattr_complete */

static void
chimera_nfs4_setxattr_open_callback(
    enum chimera_vfs_error          error_code,
    struct chimera_vfs_open_handle *handle,
    void                           *private_data)
{
    struct nfs_request   *req  = private_data;
    struct SETXATTR4args *args = &req->args_compound->argarray[req->index].opsetxattr;
    uint32_t              flags;

    if (error_code != CHIMERA_VFS_OK) {
        chimera_nfs4_compound_complete(req, chimera_nfs4_errno_to_nfsstat4(error_code));
        return;
    }

    req->handle = handle;

    /* Map NFS4 flags to VFS flags */
    switch (args->sxa_option) {
        case SETXATTR4_EITHER:
            flags = CHIMERA_VFS_SETXATTR_EITHER;
            break;
        case SETXATTR4_CREATE:
            flags = CHIMERA_VFS_SETXATTR_CREATE;
            break;
        case SETXATTR4_REPLACE:
            flags = CHIMERA_VFS_SETXATTR_REPLACE;
            break;
        default:
            chimera_vfs_release(req->thread->vfs_thread, handle);
            chimera_nfs4_compound_complete(req, NFS4ERR_INVAL);
            return;
    }

    /* Request mtime attributes for building change_info4 */
    chimera_vfs_setxattr(req->thread->vfs_thread,
                         handle,
                         args->sxa_key.data,
                         args->sxa_key.len,
                         args->sxa_value.iov,
                         args->sxa_value.niov,
                         args->sxa_value.length,
                         flags,
                         CHIMERA_VFS_ATTR_MTIME,
                         CHIMERA_VFS_ATTR_MTIME,
                         chimera_nfs4_setxattr_complete,
                         req);
} /* chimera_nfs4_setxattr_open_callback */

void
chimera_nfs4_setxattr(
    struct chimera_server_nfs_thread *thread,
    struct nfs_request               *req,
    struct nfs_argop4                *argop,
    struct nfs_resop4                *resop)
{
    chimera_vfs_open(thread->vfs_thread,
                     req->fh,
                     req->fhlen,
                     CHIMERA_VFS_OPEN_INFERRED | CHIMERA_VFS_OPEN_PATH,
                     chimera_nfs4_setxattr_open_callback,
                     req);
} /* chimera_nfs4_setxattr */
