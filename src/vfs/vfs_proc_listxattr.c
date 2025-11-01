// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <string.h>
#include "vfs/vfs_procs.h"
#include "vfs_internal.h"
#include "vfs_attr_cache.h"
#include "common/macros.h"
#include "common/misc.h"

static int
chimera_vfs_listxattr_bounce_result_callback(
    const char *key,
    int         key_len,
    uint64_t    cookie,
    void       *arg)
{
    struct chimera_vfs_request         *request = arg;
    struct chimera_vfs_listxattr_entry *entry;
    int                                 entry_size;
    char                               *entry_data;

    entry_size = (sizeof(*entry) + key_len + 7) & ~7;

    /* Check if we have enough space in the bounce buffer */
    if (request->listxattr.bounce_offset + entry_size > request->listxattr.bounce_iov.length) {
        return -1;
    }

    /* Pack the entry into the bounce buffer */
    entry_data = (char *) request->listxattr.bounce_iov.data + request->listxattr.bounce_offset;
    entry      = (struct chimera_vfs_listxattr_entry *) entry_data;

    entry->cookie  = cookie;
    entry->key_len = key_len;
    memcpy(entry_data + sizeof(*entry), key, key_len);

    request->listxattr.bounce_offset += entry_size;

    return 0;
} /* chimera_vfs_listxattr_bounce_result_callback */

static void
chimera_vfs_listxattr_complete(struct chimera_vfs_request *request)
{
    chimera_vfs_listxattr_complete_t complete = request->proto_callback;

    if (request->status == CHIMERA_VFS_OK) {
        chimera_vfs_attr_cache_insert(request->thread->vfs->vfs_attr_cache,
                                      request->listxattr.handle->fh_hash,
                                      request->listxattr.handle->fh,
                                      request->listxattr.handle->fh_len,
                                      &request->listxattr.r_attr);
    }

    chimera_vfs_complete(request);

    complete(request->status,
             request->listxattr.handle,
             request->listxattr.r_cookie,
             request->listxattr.r_eof,
             &request->listxattr.r_attr,
             request->proto_private_data);

    chimera_vfs_request_free(request->thread, request);
} /* chimera_vfs_listxattr_complete */

static void
chimera_vfs_listxattr_bounce_complete(struct chimera_vfs_request *request)
{
    struct chimera_vfs_listxattr_entry *entry;
    char                               *data_ptr;
    char                               *data_end;
    int                                 rc = 0;

    request->proto_private_data = request->listxattr.orig_private_data;

    data_ptr = request->listxattr.bounce_iov.data;
    data_end = data_ptr + request->listxattr.bounce_offset;

    while (data_ptr < data_end && rc == 0) {
        entry = (struct chimera_vfs_listxattr_entry *) data_ptr;

        rc = request->listxattr.orig_callback(
            data_ptr + sizeof(*entry),
            entry->key_len,
            entry->cookie,
            request->proto_private_data);

        if (rc != 0) {
            /* Application aborted the scan */
            request->listxattr.r_eof    = 0;
            request->listxattr.r_cookie = entry->cookie;
            break;
        }

        data_ptr += (sizeof(*entry) + entry->key_len + 7) & ~7;
    }

    evpl_iovec_release(&request->listxattr.bounce_iov);

    chimera_vfs_listxattr_complete(request);
} /* chimera_vfs_listxattr_bounce_complete */

SYMBOL_EXPORT void
chimera_vfs_listxattr(
    struct chimera_vfs_thread        *thread,
    struct chimera_vfs_open_handle   *handle,
    uint64_t                          attr_mask,
    uint64_t                          cookie,
    chimera_vfs_listxattr_callback_t  callback,
    chimera_vfs_listxattr_complete_t  complete,
    void                             *private_data)
{
    struct chimera_vfs_request *request;
    struct chimera_vfs_module  *module;

    if (!(handle->vfs_module->capabilities & CHIMERA_VFS_CAP_XATTR)) {
        complete(CHIMERA_VFS_ENOTSUP, handle, 0, 1, NULL, private_data);
        return;
    }

    request = chimera_vfs_request_alloc_by_handle(thread, handle);
    module  = request->module;

    request->opcode                       = CHIMERA_VFS_OP_LISTXATTR;
    request->listxattr.handle             = handle;
    request->listxattr.cookie             = cookie;
    request->listxattr.attr_mask          = attr_mask;
    request->listxattr.callback           = callback;
    request->listxattr.r_attr.va_req_mask = attr_mask | CHIMERA_VFS_ATTR_MASK_CACHEABLE;
    request->listxattr.r_attr.va_set_mask = 0;
    request->proto_callback               = complete;
    request->proto_private_data           = private_data;

    request->listxattr.bounce_offset  = 0;
    request->listxattr.orig_callback = NULL;

    /* If this module is blocking then we need to bounce the results into the original thread
     * before making the caller provided result callback
     */

    if (module->capabilities & CHIMERA_VFS_CAP_BLOCKING) {

        evpl_iovec_alloc(thread->evpl, 64 * 1024, 8, 1, &request->listxattr.bounce_iov);

        request->listxattr.orig_callback     = callback;
        request->listxattr.orig_private_data = private_data;

        request->listxattr.callback   = chimera_vfs_listxattr_bounce_result_callback;
        request->proto_private_data = request;

        request->complete = chimera_vfs_listxattr_bounce_complete;

    } else {
        request->complete = chimera_vfs_listxattr_complete;
    }

    chimera_vfs_dispatch(request);

} /* chimera_vfs_listxattr */
