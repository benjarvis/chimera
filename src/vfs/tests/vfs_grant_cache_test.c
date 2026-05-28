// SPDX-FileCopyrightText: 2025-2026 Chimera-NAS Project Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NDEBUG
#include <assert.h>
#include <unistd.h>
#include <urcu.h>
#include <urcu/urcu-memb.h>

#include "vfs/vfs_grant_cache.h"
#include "vfs/vfs_clock.h"
#include "prometheus-c.h"

#define TEST_PASS(name) fprintf(stderr, "  PASS: %s\n", name)

/* Distinct file handles with their (synthetic) hashes.  The cache only requires
 * that the same (fh, fh_hash) pair is used for insert/lookup/invalidate of a
 * given object, not that fh_hash == hash(fh), so fixed values keep the test
 * independent of the hash implementation. */
static const uint8_t FH1[16] = { 0x01, 0x11, 0x21 };
static const uint8_t FH2[16] = { 0x02, 0x12, 0x22 };
#define FH1_HASH 0x1111111111111111ULL
#define FH2_HASH 0x2222222222222222ULL

#define CREDA    0xAAAAAAAAAAAAAAAAULL
#define CREDB    0xBBBBBBBBBBBBBBBBULL
#define CREDC    0xCCCCCCCCCCCCCCCCULL
#define CREDD    0xDDDDDDDDDDDDDDDDULL
#define CREDE    0xEEEEEEEEEEEEEEEEULL

/* A grant lookup returns 0 on hit (and sets *r); -1 on miss. */
static int
look(
    struct chimera_vfs_grant_cache *c,
    uint64_t                        fh_hash,
    const void                     *fh,
    uint64_t                        cred_hash,
    uint32_t                       *r)
{
    return chimera_vfs_grant_cache_lookup(c, fh_hash, fh, sizeof(FH1), cred_hash, r);
} /* look */

static struct chimera_vfs_grant_cache *
make_cache(
    struct prometheus_metrics **r_metrics,
    uint8_t                     shards_bits,
    uint8_t                     slots_bits,
    uint8_t                     entries_bits,
    uint64_t                    ttl)
{
    struct prometheus_metrics *metrics = prometheus_metrics_create(NULL, NULL, 0);

    assert(metrics != NULL);
    *r_metrics = metrics;
    return chimera_vfs_grant_cache_create(shards_bits, slots_bits, entries_bits, ttl, metrics);
} /* make_cache */

static void
free_cache(
    struct chimera_vfs_grant_cache *cache,
    struct prometheus_metrics      *metrics)
{
    chimera_vfs_grant_cache_destroy(cache);
    prometheus_metrics_destroy(metrics);
} /* free_cache */

static void
test_empty_miss(void)
{
    struct chimera_vfs_grant_cache *cache;
    struct prometheus_metrics      *metrics;
    uint32_t                        g;

    cache = make_cache(&metrics, 2, 4, 2, 600);
    assert(look(cache, FH1_HASH, FH1, CREDA, &g) == -1);
    free_cache(cache, metrics);

    TEST_PASS("empty cache misses");
} /* test_empty_miss */

static void
test_insert_and_keying(void)
{
    struct chimera_vfs_grant_cache *cache;
    struct prometheus_metrics      *metrics;
    uint32_t                        g;

    cache = make_cache(&metrics, 2, 4, 2, 600);

    /* Same file, two different credentials, distinct masks. */
    chimera_vfs_grant_cache_insert(cache, FH1_HASH, FH1, sizeof(FH1), CREDA, 0x01);
    chimera_vfs_grant_cache_insert(cache, FH1_HASH, FH1, sizeof(FH1), CREDB, 0x02);
    /* Different file, reused credential. */
    chimera_vfs_grant_cache_insert(cache, FH2_HASH, FH2, sizeof(FH2), CREDA, 0x04);

    g = 0;
    assert(look(cache, FH1_HASH, FH1, CREDA, &g) == 0 && g == 0x01);
    g = 0;
    assert(look(cache, FH1_HASH, FH1, CREDB, &g) == 0 && g == 0x02);
    g = 0;
    assert(look(cache, FH2_HASH, FH2, CREDA, &g) == 0 && g == 0x04);

    /* Unknown credential on a known file, and an unknown file: both miss. */
    assert(look(cache, FH1_HASH, FH1, CREDC, &g) == -1);
    assert(look(cache, FH2_HASH, FH2, CREDB, &g) == -1);

    /* Re-insert replaces the grant for the same (fh, cred). */
    chimera_vfs_grant_cache_insert(cache, FH1_HASH, FH1, sizeof(FH1), CREDA, 0x08);
    g = 0;
    assert(look(cache, FH1_HASH, FH1, CREDA, &g) == 0 && g == 0x08);

    free_cache(cache, metrics);

    TEST_PASS("insert + per-(fh,cred) keying + replace");
} /* test_insert_and_keying */

static void
test_invalidate_fh(void)
{
    struct chimera_vfs_grant_cache *cache;
    struct prometheus_metrics      *metrics;
    uint32_t                        g;

    cache = make_cache(&metrics, 2, 4, 2, 600);

    chimera_vfs_grant_cache_insert(cache, FH1_HASH, FH1, sizeof(FH1), CREDA, 0x01);
    chimera_vfs_grant_cache_insert(cache, FH1_HASH, FH1, sizeof(FH1), CREDB, 0x02);
    chimera_vfs_grant_cache_insert(cache, FH2_HASH, FH2, sizeof(FH2), CREDA, 0x04);

    /* Invalidating FH1 drops every credential's grant for FH1 but leaves FH2. */
    chimera_vfs_grant_cache_invalidate_fh(cache, FH1_HASH, FH1, sizeof(FH1));

    assert(look(cache, FH1_HASH, FH1, CREDA, &g) == -1);
    assert(look(cache, FH1_HASH, FH1, CREDB, &g) == -1);
    g = 0;
    assert(look(cache, FH2_HASH, FH2, CREDA, &g) == 0 && g == 0x04);

    free_cache(cache, metrics);

    TEST_PASS("invalidate_fh drops all creds for one file only");
} /* test_invalidate_fh */

static void
test_ttl_expiry(void)
{
    struct chimera_vfs_grant_cache *cache;
    struct prometheus_metrics      *metrics;
    uint32_t                        g;

    /* ttl == 0: the entry expires the instant the clock advances past insert. */
    cache = make_cache(&metrics, 2, 4, 2, 0);

    chimera_vfs_grant_cache_insert(cache, FH1_HASH, FH1, sizeof(FH1), CREDA, 0x01);

    usleep(2000);

    assert(look(cache, FH1_HASH, FH1, CREDA, &g) == -1);

    free_cache(cache, metrics);

    TEST_PASS("TTL expiry turns a hit into a miss");
} /* test_ttl_expiry */

static void
test_eviction_keeps_hot(void)
{
    struct chimera_vfs_grant_cache *cache;
    struct prometheus_metrics      *metrics;
    uint32_t                        g;
    int                             present;

    /* One shard, one slot, 4-way: every (fh, cred) competes in a single slot. */
    cache = make_cache(&metrics, 0, 0, 2, 600);

    /* A is hot: raise its score with repeated hits. */
    chimera_vfs_grant_cache_insert(cache, FH1_HASH, FH1, sizeof(FH1), CREDA, 0x01);
    for (int i = 0; i < 5; i++) {
        assert(look(cache, FH1_HASH, FH1, CREDA, &g) == 0);
    }

    /* Fill the remaining 3 ways, then overflow by one. */
    chimera_vfs_grant_cache_insert(cache, FH1_HASH, FH1, sizeof(FH1), CREDB, 0x02);
    chimera_vfs_grant_cache_insert(cache, FH1_HASH, FH1, sizeof(FH1), CREDC, 0x02);
    chimera_vfs_grant_cache_insert(cache, FH1_HASH, FH1, sizeof(FH1), CREDD, 0x02);
    chimera_vfs_grant_cache_insert(cache, FH1_HASH, FH1, sizeof(FH1), CREDE, 0x02);

    /* The hot entry and the newest entry survive; the slot still holds exactly
     * its 4-way capacity (one cold entry was evicted). */
    assert(look(cache, FH1_HASH, FH1, CREDA, &g) == 0);
    assert(look(cache, FH1_HASH, FH1, CREDE, &g) == 0);

    present  = (look(cache, FH1_HASH, FH1, CREDA, &g) == 0);
    present += (look(cache, FH1_HASH, FH1, CREDB, &g) == 0);
    present += (look(cache, FH1_HASH, FH1, CREDC, &g) == 0);
    present += (look(cache, FH1_HASH, FH1, CREDD, &g) == 0);
    present += (look(cache, FH1_HASH, FH1, CREDE, &g) == 0);
    assert(present == 4);

    free_cache(cache, metrics);

    TEST_PASS("eviction drops a cold entry, keeps the hot + newest");
} /* test_eviction_keeps_hot */

int
main(
    int    argc,
    char **argv)
{
    urcu_memb_register_thread();
    chimera_vfs_clock_init();

    test_empty_miss();
    test_insert_and_keying();
    test_invalidate_fh();
    test_ttl_expiry();
    test_eviction_keeps_hot();

    chimera_vfs_clock_shutdown();
    urcu_memb_unregister_thread();

    fprintf(stderr, "All grant cache tests passed\n");
    return 0;
} /* main */
