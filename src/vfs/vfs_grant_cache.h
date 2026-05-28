// SPDX-FileCopyrightText: 2025-2026 Chimera-NAS Project Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <string.h>
#include <urcu.h>
#include <urcu/urcu-memb.h>
#include <utlist.h>

#include "vfs/vfs.h"
#include "vfs_clock.h"
#include "prometheus-c.h"

/*
 * Access-grant cache: a shared, lock-free-read cache of authorization decisions
 * for engine-authoritative backends (memfs/cairn/diskfs), keyed by the object
 * file handle and the caller's credential identity.
 *
 * Why this exists: those backends have no kernel to enforce DAC, so the VFS
 * engine evaluates the ACL itself (see chimera_vfs_access_check).  Evaluating it
 * per I/O is far too expensive, so the result -- the caller's effective access
 * mask -- is cached here and reused across many reads/writes.  This decouples
 * grant caching from the open-handle lifecycle: an inferred NFSv3 read can keep
 * using a lock-free synthetic handle and still amortise its ACL check, instead
 * of being forced through the (mutex-sharded) open cache just to find somewhere
 * to stash the grant.
 *
 * Key/value: key is (fh, cred_hash); value is the full evaluated access mask
 * (chimera_vfs_access_check(..., CHIMERA_ACE_MASK_ALL)), so a single entry
 * answers read, write, delete, etc. for that caller on that object -- including
 * denials (a clear bit is a cached "no").
 *
 * Concurrency: lookups are lock-free RCU reads.  Inserts and per-file
 * invalidations take a per-shard entry_lock and publish with rcu_assign_pointer;
 * evicted/replaced entries are returned to a per-shard free list via call_rcu.
 * The slot index is derived from fh_hash ALONE (not the cred), so every cached
 * grant for one file lands in the same slot -- letting invalidate_fh() drop all
 * of a file's per-caller grants by walking a single slot.  Different creds for
 * the same file occupy distinct entries within that slot (set-associative).
 *
 * Coherence: each entry carries a TTL (ticks) so a stale grant cannot authorise
 * access indefinitely, and setattr/setacl actively invalidate the file's grants
 * the moment its mode/owner/ACL changes.  This is strictly tighter than the
 * prior handle-cached grant, which was never invalidated and lived as long as
 * the cached open handle.  A grant computed just before a concurrent chmod can
 * still be used for one in-flight op -- the same bounded TOCTOU window inherent
 * to any cached access decision, and acceptable under NFS attribute-cache
 * semantics.
 */

struct chimera_vfs_grant_cache_entry {
    uint64_t        fh_hash;
    uint64_t        cred_hash;
    uint64_t        score;
    uint64_t        expiration;                       /* stopwatch ticks */
    struct rcu_head rcu;
    union {
        struct chimera_vfs_grant_cache_entry *next;  /* when on the free list */
        struct chimera_vfs_grant_cache_shard *shard; /* when in use */
    };
    uint32_t        granted_access;
    uint16_t        fh_len;
    uint8_t         fh[CHIMERA_VFS_FH_SIZE];
};

struct chimera_vfs_grant_cache_shard {
    struct chimera_vfs_grant_cache_entry **entries;
    struct chimera_vfs_grant_cache_entry  *free_entries;
    pthread_mutex_t                        entry_lock;
    pthread_mutex_t                        free_lock;
    struct prometheus_counter_instance    *insert;
    struct prometheus_counter_instance    *hit;
    struct prometheus_counter_instance    *miss;
    struct prometheus_counter_instance    *invalidate;
};

struct chimera_vfs_grant_cache {
    uint8_t                               num_slots_bits;
    uint8_t                               num_shards_bits;
    uint8_t                               num_entries_bits;
    uint64_t                              num_slots;
    uint32_t                              num_shards;
    uint32_t                              num_entries;
    uint64_t                              num_slots_mask;
    uint32_t                              num_shards_mask;
    uint32_t                              num_entries_mask;
    uint64_t                              ttl;        /* seconds */
    struct chimera_vfs_grant_cache_shard *shards;
    struct prometheus_metrics            *metrics;
    struct prometheus_counter            *grant_cache;
    struct prometheus_counter_series     *insert_series;
    struct prometheus_counter_series     *hit_series;
    struct prometheus_counter_series     *miss_series;
    struct prometheus_counter_series     *invalidate_series;
};

static inline struct chimera_vfs_grant_cache *
chimera_vfs_grant_cache_create(
    uint8_t                    num_shards_bits,
    uint8_t                    num_slots_bits,
    uint8_t                    entries_per_slot_bits,
    uint64_t                   ttl,
    struct prometheus_metrics *metrics)
{
    struct chimera_vfs_grant_cache       *cache;
    struct chimera_vfs_grant_cache_shard *shard;
    struct chimera_vfs_grant_cache_entry *entry;
    int                                   i, j;

    cache = calloc(1, sizeof(struct chimera_vfs_grant_cache));

    cache->num_shards_bits  = num_shards_bits;
    cache->num_slots_bits   = num_slots_bits;
    cache->num_entries_bits = entries_per_slot_bits;
    cache->ttl              = ttl;

    cache->num_shards  = 1 << num_shards_bits;
    cache->num_slots   = 1 << num_slots_bits;
    cache->num_entries = 1 << entries_per_slot_bits;

    cache->num_slots_mask   = cache->num_slots - 1;
    cache->num_shards_mask  = cache->num_shards - 1;
    cache->num_entries_mask = cache->num_entries - 1;

    cache->shards = calloc(cache->num_shards, sizeof(struct chimera_vfs_grant_cache_shard));

    if (metrics) {
        cache->metrics     = metrics;
        cache->grant_cache = prometheus_metrics_create_counter(metrics, "chimera_grant_cache",
                                                               "Operations on the chimera VFS access-grant cache");

        cache->insert_series = prometheus_counter_create_series(cache->grant_cache,
                                                                (const char *[]) { "op" },
                                                                (const char *[]) { "insert" }, 1);
        cache->hit_series = prometheus_counter_create_series(cache->grant_cache,
                                                             (const char *[]) { "op" },
                                                             (const char *[]) { "hit" }, 1);
        cache->miss_series = prometheus_counter_create_series(cache->grant_cache,
                                                              (const char *[]) { "op" },
                                                              (const char *[]) { "miss" }, 1);
        cache->invalidate_series = prometheus_counter_create_series(cache->grant_cache,
                                                                    (const char *[]) { "op" },
                                                                    (const char *[]) { "invalidate" }, 1);
    }

    for (i = 0; i < cache->num_shards; i++) {

        shard          = &cache->shards[i];
        shard->entries = calloc(cache->num_slots * cache->num_entries,
                                sizeof(struct chimera_vfs_grant_cache_entry *));

        for (j = 0; j < cache->num_slots * cache->num_entries; j++) {
            entry = calloc(1, sizeof(struct chimera_vfs_grant_cache_entry));
            LL_PREPEND(shard->free_entries, entry);
        }

        pthread_mutex_init(&shard->entry_lock, NULL);
        pthread_mutex_init(&shard->free_lock, NULL);

        if (metrics) {
            shard->insert     = prometheus_counter_series_create_instance(cache->insert_series);
            shard->hit        = prometheus_counter_series_create_instance(cache->hit_series);
            shard->miss       = prometheus_counter_series_create_instance(cache->miss_series);
            shard->invalidate = prometheus_counter_series_create_instance(cache->invalidate_series);
        }
    }

    return cache;
} /* chimera_vfs_grant_cache_create */

static inline void
chimera_vfs_grant_cache_destroy(struct chimera_vfs_grant_cache *cache)
{
    struct chimera_vfs_grant_cache_shard *shard;
    struct chimera_vfs_grant_cache_entry *entry;
    int                                   i, j;

    rcu_barrier();

    for (i = 0; i < cache->num_shards; i++) {
        shard = &cache->shards[i];

        if (cache->metrics) {
            prometheus_counter_series_destroy_instance(cache->insert_series, shard->insert);
            prometheus_counter_series_destroy_instance(cache->hit_series, shard->hit);
            prometheus_counter_series_destroy_instance(cache->miss_series, shard->miss);
            prometheus_counter_series_destroy_instance(cache->invalidate_series, shard->invalidate);
        }

        for (j = 0; j < cache->num_slots * cache->num_entries; j++) {
            if (shard->entries[j]) {
                entry = shard->entries[j];
                free(entry);
            }
        }

        free(shard->entries);

        while (shard->free_entries) {
            entry               = shard->free_entries;
            shard->free_entries = entry->next;
            free(entry);
        }

        pthread_mutex_destroy(&shard->entry_lock);
        pthread_mutex_destroy(&shard->free_lock);
    }

    if (cache->metrics) {
        prometheus_counter_destroy_series(cache->grant_cache, cache->insert_series);
        prometheus_counter_destroy_series(cache->grant_cache, cache->hit_series);
        prometheus_counter_destroy_series(cache->grant_cache, cache->miss_series);
        prometheus_counter_destroy_series(cache->grant_cache, cache->invalidate_series);
        prometheus_counter_destroy(cache->metrics, cache->grant_cache);
    }

    free(cache->shards);
    free(cache);
} /* chimera_vfs_grant_cache_destroy */

/*
 * Look up the cached access mask for (fh, cred_hash).  Returns 0 and sets
 * *r_granted on a live hit; returns -1 on miss or expiry.  Lock-free RCU read.
 */
static inline int
chimera_vfs_grant_cache_lookup(
    struct chimera_vfs_grant_cache *cache,
    uint64_t                        fh_hash,
    const void                     *fh,
    int                             fh_len,
    uint64_t                        cred_hash,
    uint32_t                       *r_granted)
{
    struct chimera_vfs_grant_cache_entry  *entry;
    struct chimera_vfs_grant_cache_shard  *shard;
    struct chimera_vfs_grant_cache_entry **slot, **slot_end;
    int                                    rc;
    uint64_t                               now = chimera_vfs_now_ticks();

    shard = &cache->shards[fh_hash & cache->num_shards_mask];

    slot = &shard->entries[(fh_hash & cache->num_slots_mask) << cache->num_entries_bits];

    slot_end = slot + cache->num_entries;

    rc = -1;

    urcu_memb_read_lock();

    while (slot < slot_end) {
        entry = rcu_dereference(*slot);

        if (entry &&
            entry->fh_hash == fh_hash &&
            entry->cred_hash == cred_hash &&
            entry->expiration >= now &&
            entry->fh_len == fh_len &&
            memcmp(entry->fh, fh, fh_len) == 0) {

            *r_granted = entry->granted_access;
            entry->score++;
            rc = 0;
            break;
        }

        slot++;
    }

    urcu_memb_read_unlock();

    if (rc == 0) {
        prometheus_counter_increment(shard->hit);
    } else {
        prometheus_counter_increment(shard->miss);
    }

    return rc;
} /* chimera_vfs_grant_cache_lookup */

static inline void
chimera_vfs_grant_cache_free_entry_rcu(struct rcu_head *head)
{
    struct chimera_vfs_grant_cache_entry *entry = caa_container_of(head, struct chimera_vfs_grant_cache_entry, rcu);
    struct chimera_vfs_grant_cache_shard *shard = entry->shard;

    pthread_mutex_lock(&shard->free_lock);
    LL_PREPEND(shard->free_entries, entry);
    pthread_mutex_unlock(&shard->free_lock);
} /* chimera_vfs_grant_cache_free_entry_rcu */

/*
 * Insert (or replace) the grant for (fh, cred_hash).  An existing entry for the
 * same (fh, cred) is replaced; otherwise the lowest-score / empty entry in the
 * slot is evicted.
 */
static inline void
chimera_vfs_grant_cache_insert(
    struct chimera_vfs_grant_cache *cache,
    uint64_t                        fh_hash,
    const void                     *fh,
    int                             fh_len,
    uint64_t                        cred_hash,
    uint32_t                        granted)
{
    struct chimera_vfs_grant_cache_entry  *entry, *old_entry, *best_entry;
    struct chimera_vfs_grant_cache_shard  *shard;
    struct chimera_vfs_grant_cache_entry **slot, **slot_end, **slot_best;

    shard = &cache->shards[fh_hash & cache->num_shards_mask];

    slot = &shard->entries[(fh_hash & cache->num_slots_mask) << cache->num_entries_bits];

    slot_end  = slot + cache->num_entries;
    slot_best = slot;

    pthread_mutex_lock(&shard->free_lock);

    entry = shard->free_entries;

    if (entry) {
        LL_DELETE(shard->free_entries, entry);
    }

    pthread_mutex_unlock(&shard->free_lock);

    if (!entry) {
        entry = calloc(1, sizeof(struct chimera_vfs_grant_cache_entry));
    }

    entry->fh_hash        = fh_hash;
    entry->cred_hash      = cred_hash;
    entry->shard          = shard;
    entry->score          = 0;
    entry->granted_access = granted;
    entry->fh_len         = fh_len;
    memcpy(entry->fh, fh, fh_len);

    entry->expiration = chimera_vfs_now_ticks() +
        chimera_vfs_ns_to_ticks((uint64_t) cache->ttl * 1000000000ULL);

    urcu_memb_read_lock();

    pthread_mutex_lock(&shard->entry_lock);

    best_entry = *slot_best;

    while (slot < slot_end) {
        old_entry = *slot;

        if (old_entry && old_entry->fh_hash == fh_hash &&
            old_entry->cred_hash == cred_hash &&
            old_entry->fh_len == fh_len &&
            memcmp(old_entry->fh, fh, fh_len) == 0) {
            best_entry = old_entry;
            slot_best  = slot;
            break;
        }

        if ((best_entry && !old_entry) || (best_entry && old_entry && best_entry->score > old_entry->score)) {
            best_entry = old_entry;
            slot_best  = slot;
        }

        slot++;
    }

    rcu_assign_pointer(*slot_best, entry);

    prometheus_counter_increment(shard->insert);

    pthread_mutex_unlock(&shard->entry_lock);

    urcu_memb_read_unlock();

    if (best_entry) {
        call_rcu(&best_entry->rcu, chimera_vfs_grant_cache_free_entry_rcu);
    }
} /* chimera_vfs_grant_cache_insert */

/*
 * Drop every cached grant for a file (all credentials).  Called when the file's
 * mode/owner/ACL changes so a subsequent I/O recomputes against fresh attrs.
 * All of a file's grants share one slot (slot index is fh_hash-only), so this
 * walks a single slot.
 */
static inline void
chimera_vfs_grant_cache_invalidate_fh(
    struct chimera_vfs_grant_cache *cache,
    uint64_t                        fh_hash,
    const void                     *fh,
    int                             fh_len)
{
    struct chimera_vfs_grant_cache_entry  *old_entry;
    struct chimera_vfs_grant_cache_shard  *shard;
    struct chimera_vfs_grant_cache_entry **slot, **slot_end;

    shard = &cache->shards[fh_hash & cache->num_shards_mask];

    slot = &shard->entries[(fh_hash & cache->num_slots_mask) << cache->num_entries_bits];

    slot_end = slot + cache->num_entries;

    urcu_memb_read_lock();

    pthread_mutex_lock(&shard->entry_lock);

    while (slot < slot_end) {
        old_entry = *slot;

        if (old_entry && old_entry->fh_hash == fh_hash &&
            old_entry->fh_len == fh_len &&
            memcmp(old_entry->fh, fh, fh_len) == 0) {
            rcu_assign_pointer(*slot, NULL);
            prometheus_counter_increment(shard->invalidate);
            call_rcu(&old_entry->rcu, chimera_vfs_grant_cache_free_entry_rcu);
        }

        slot++;
    }

    pthread_mutex_unlock(&shard->entry_lock);

    urcu_memb_read_unlock();
} /* chimera_vfs_grant_cache_invalidate_fh */
