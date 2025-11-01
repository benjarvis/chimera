// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "vfs/vfs_procs.h"
#include "vfs_internal.h"
#include "vfs_open_cache.h"
#include "vfs_attr_cache.h"
#include "common/macros.h"

static void
chimera_vfs_getxattr_complete(struct chimera_vfs_request *request)
{
    chimera_vfs_getxattr_callback_t callback = request->proto_callback;

    if (request->status == CHIMERA_VFS_OK) {
        chimera_vfs_attr_cache_insert(request->thread->vfs->vfs_attr_cache,
                                      request->getxattr.handle->fh_hash,
                                      request->getxattr.handle->fh,
                                      request->getxattr.handle->fh_len,
                                      &request->getxattr.r_attr);
    }

    chimera_vfs_complete(request);

    callback(request->status,
             request->getxattr.r_value_length,
             request->getxattr.value_iov,
             request->getxattr.value_niov,
             &request->getxattr.r_attr,
             request->proto_private_data);

    chimera_vfs_request_free(request->thread, request);
} /* chimera_vfs_getxattr_complete */

SYMBOL_EXPORT void
chimera_vfs_getxattr(
    struct chimera_vfs_thread      *thread,
    struct chimera_vfs_open_handle *handle,
    const char                     *key,
    int                             key_len,
    struct evpl_iovec              *value_iov,
    int                             value_niov,
    uint64_t                        attr_mask,
    chimera_vfs_getxattr_callback_t callback,
    void                           *private_data)
{
    struct chimera_vfs_request *request;

    if (!(handle->vfs_module->capabilities & CHIMERA_VFS_CAP_XATTR)) {
        callback(CHIMERA_VFS_ENOTSUP, 0, NULL, 0, NULL, private_data);
        return;
    }

    request = chimera_vfs_request_alloc_by_handle(thread, handle);

    request->opcode                      = CHIMERA_VFS_OP_GETXATTR;
    request->complete                    = chimera_vfs_getxattr_complete;
    request->getxattr.handle             = handle;
    request->getxattr.key                = key;
    request->getxattr.key_len            = key_len;
    request->getxattr.value_iov          = value_iov;
    request->getxattr.value_niov         = value_niov;
    request->getxattr.r_attr.va_req_mask = attr_mask | CHIMERA_VFS_ATTR_MASK_CACHEABLE;
    request->getxattr.r_attr.va_set_mask = 0;
    request->proto_callback              = callback;
    request->proto_private_data          = private_data;

    chimera_vfs_dispatch(request);

} /* chimera_vfs_getxattr */
