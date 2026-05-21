// SPDX-FileCopyrightText: 2025-2026 Chimera-NAS Project Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <stdint.h>
#include <stdatomic.h>

/*
 * Shared pNFS device table.
 *
 * This is the single authoritative mapping of pNFS data-server (DS) "devices"
 * for the server.  It is owned by the VFS layer (reachable via
 * struct chimera_vfs) so that both consumers can reach it without duplicating
 * state:
 *
 *   - the VFS/backend layer (e.g. memfs) uses it to steer a newly created file
 *     to a DS and to construct the deterministic DS file handle it embeds in a
 *     layout, and
 *   - the NFS protocol layer uses it to answer GETDEVICEINFO/GETDEVICELIST with
 *     the DS network address.
 *
 * v1 only models whole-file NFSv4.1 file layouts (one DS per file), but the
 * table is deliberately keyed on an opaque 16-byte deviceid so a future
 * extent/block filesystem can reference many devices per file.
 */

#define CHIMERA_PNFS_MAX_DS       8
#define CHIMERA_VFS_DEVICEID_SIZE 16    /* == NFS4_DEVICEID4_SIZE */
#define CHIMERA_VFS_MOUNTID_SIZE  16    /* == CHIMERA_VFS_MOUNT_ID_SIZE */

struct chimera_vfs;

struct chimera_vfs_ds {
    uint8_t deviceid[CHIMERA_VFS_DEVICEID_SIZE];  /* stable id advertised to clients */
    uint8_t mount_id[CHIMERA_VFS_MOUNTID_SIZE];   /* DS export's FH mount_id prefix  */
    char    netid[8];                             /* RFC5665 netid, e.g. "tcp"       */
    char    uaddr[64];                            /* RFC5665 universal address       */
};

struct chimera_vfs_pnfs {
    int                   enabled;
    int                   num_ds;
    _Atomic uint32_t      steer_rr;               /* round-robin steering counter */
    struct chimera_vfs_ds ds[CHIMERA_PNFS_MAX_DS];
};

struct chimera_vfs_pnfs * chimera_vfs_pnfs_create(
    void);

void chimera_vfs_pnfs_destroy(
    struct chimera_vfs_pnfs *pnfs);

void chimera_vfs_pnfs_set_enabled(
    struct chimera_vfs *vfs,
    int                 enabled);

int chimera_vfs_pnfs_enabled(
    const struct chimera_vfs *vfs);

/*
 * Register a data server.  The deviceid is assigned deterministically from the
 * registration order so it is stable for the lifetime of the server instance.
 * Returns the device index (>= 0) or -1 if the table is full.
 */
int chimera_vfs_pnfs_add_device(
    struct chimera_vfs *vfs,
    const uint8_t      *mount_id,
    const char         *netid,
    const char         *uaddr);

int chimera_vfs_pnfs_num_devices(
    const struct chimera_vfs *vfs);

const struct chimera_vfs_ds * chimera_vfs_pnfs_get_device(
    const struct chimera_vfs *vfs,
    int                       idx);

const struct chimera_vfs_ds * chimera_vfs_pnfs_find_device(
    const struct chimera_vfs *vfs,
    const uint8_t            *deviceid);

/*
 * Choose a data server for a newly created file.  Returns a pointer to the
 * chosen device, or NULL if pNFS is disabled or no devices are configured.
 */
const struct chimera_vfs_ds * chimera_vfs_pnfs_steer(
    struct chimera_vfs *vfs);
