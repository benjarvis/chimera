// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "vfs_procs.h"
#include "vfs_internal.h"
#include "vfs_attr_cache.h"
#include "common/macros.h"

static void
chimera_vfs_removexattr_complete(struct chimera_vfs_request *request)
{
    struct chimera_vfs_thread          *thread   = request->thread;
    chimera_vfs_removexattr_callback_t  callback = request->proto_callback;

    if (request->status == CHIMERA_VFS_OK) {
        chimera_vfs_attr_cache_insert(thread->vfs->vfs_attr_cache,
                                      request->fh_hash,
                                      request->fh,
                                      request->fh_len,
                                      &request->removexattr.r_post_attr);
    }

    chimera_vfs_complete(request);

    callback(request->status,
             &request->removexattr.r_pre_attr,
             &request->removexattr.r_post_attr,
             request->proto_private_data);

    chimera_vfs_request_free(thread, request);
} /* chimera_vfs_removexattr_complete */

SYMBOL_EXPORT void
chimera_vfs_removexattr(
    struct chimera_vfs_thread      *thread,
    struct chimera_vfs_open_handle *handle,
    const char                     *key,
    int                             key_len,
    uint64_t                        pre_attr_mask,
    uint64_t                        post_attr_mask,
    chimera_vfs_removexattr_callback_t callback,
    void                           *private_data)
{
    struct chimera_vfs_request *request;

    if (!(handle->vfs_module->capabilities & CHIMERA_VFS_CAP_XATTR)) {
        callback(CHIMERA_VFS_ENOTSUP, NULL, NULL, private_data);
        return;
    }

    request = chimera_vfs_request_alloc_by_handle(thread, handle);

    request->opcode                              = CHIMERA_VFS_OP_REMOVEXATTR;
    request->complete                            = chimera_vfs_removexattr_complete;
    request->removexattr.handle                  = handle;
    request->removexattr.key                     = key;
    request->removexattr.key_len                 = key_len;
    request->removexattr.r_pre_attr.va_req_mask  = pre_attr_mask;
    request->removexattr.r_pre_attr.va_set_mask  = 0;
    request->removexattr.r_post_attr.va_req_mask = post_attr_mask | CHIMERA_VFS_ATTR_MASK_CACHEABLE;
    request->removexattr.r_post_attr.va_set_mask = 0;
    request->proto_callback                      = callback;
    request->proto_private_data                  = private_data;

    chimera_vfs_dispatch(request);
} /* chimera_vfs_removexattr */
