/****************************************************************************
 *  APCL Integration Test Suite
 *
 *  Author: Nouhaila HANBALI
 *  Date:   2026-03-18
 *
 *  Tests the full APCL pipeline end-to-end:
 *
 *    T01 – Happy-path single spend (must succeed)
 *    T02 – Basic double-spend (must be blocked)
 *    T03 – Concurrent double-spend / race condition (must be blocked)
 *    T04 – Re-spend after aggregation via stale sequence (must be blocked)
 *    T05 – Lock expiry: stale lock is reclaimed, new TX can proceed
 *    T06 – Multi-input transaction (must succeed end-to-end)
 *    T07 – Multi-input double-spend (partial overlap of inputs)
 *    T08 – Inflation attack through APCL (must still be blocked by LACT+)
 *    T09 – Sequential chain: spend output of previous TX
 *    T10 – Store integrity after several APCL-managed TXs
 *
 *  Each test prints PASS or FAIL and the suite returns 0 iff all pass.
 *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>   /* usleep */
#include "apcl.h"
#include "openssl/rand.h"

/* ── colour / formatting ────────────────────────────────────── */
#define GREEN  "\x1b[32m"
#define RED    "\x1b[31m"
#define YELLOW "\x1b[33m"
#define CYAN   "\x1b[36m"
#define BOLD   "\x1b[1m"
#define RESET  "\x1b[0m"

static int g_pass = 0;
static int g_fail = 0;

#define ASSERT(cond, msg)                                               \
    do {                                                                \
        if (cond) {                                                     \
            printf("    " GREEN "[PASS]" RESET " %s\n", msg);          \
            g_pass++;                                                   \
        } else {                                                        \
            printf("    " RED "[FAIL]" RESET " %s\n", msg);            \
            g_fail++;                                                   \
        }                                                               \
    } while (0)

static void section(const char *title)
{
    printf("\n" BOLD CYAN "━━━ %s ━━━" RESET "\n", title);
}

/* ─────────────────────────────────────────────────────────────
 * Shared helpers
 * ───────────────────────────────────────────────────────────── */

/** Mint amount coins into store and register coin in APCL table.
 *  Returns 1 on success, 0 on failure. */
static int do_mint(store_t *store, apcl_lock_table_t *table,
                   ctx_t *tx, uint8_t mask[LACTX_m - D][r_BYTES],
                   uint64_t amount)
{
    lactx_tx_init(tx, 2, 1);
    lactx_mint_tx_create(store, tx, mask, amount);
    if (lactx_tx_verify(store, tx) != 1) return 0;
    lactx_tx_aggregate(store, tx);
    return apcl_mint_register(table, tx) == 0 ? 1 : 0;
}

/**
 * Full APCL pipeline for a single TX:
 *   prepare → verify → acquire lock → [aggregate if commit=1]
 * Returns 1 if all steps up to and including lock succeed, 0 otherwise.
 */
static int apcl_pipeline(store_t *store, apcl_lock_table_t *table,
                           ctx_t *tx, apcl_tx_meta_t *meta, int commit)
{
    if (apcl_prepare_tx_meta(table, tx, meta) != 0) return 0;
    if (apcl_verify(store, tx, table, meta) != 1)   return 0;
    if (apcl_acquire_lock(table, tx, meta) != 1)    return 0;
    if (commit) {
        if (apcl_aggregate(store, tx, table, meta) != 1) return 0;
    }
    return 1;
}

/* Build a 1-in / N-out spend transaction (does NOT call tx_init – caller does) */
static int build_spend(store_t *store,
                       ctx_t *tx,
                       coin_t *input_coin,
                       uint8_t in_mask[LACTX_m - D][r_BYTES],
                       uint64_t v_in,
                       unsigned n_out,
                       uint8_t out_masks[][LACTX_m - D][r_BYTES],
                       uint64_t *v_out)
{
    lactx_coin_copy(&tx->in[0], input_coin);
    return lactx_header_create(&store->ctx, &tx->header,
                               n_out, tx->out, out_masks, v_out,
                               1, tx->in, &in_mask, &v_in);
}

/* ─────────────────────────────────────────────────────────────
 * T01 – Happy-path single spend
 * ───────────────────────────────────────────────────────────── */
static void t01_happy_path(void)
{
    section("T01: Happy-path single spend");

    uint8_t seed[SEED_BYTES]; RAND_bytes(seed, SEED_BYTES);
    store_t store = lactx_get_store(seed, "apcl_t01.db");
    apcl_lock_table_t table; apcl_lock_table_init(&table, 256);

    /* Mint */
    ctx_t tx_mint; uint8_t mint_mask[LACTX_m - D][r_BYTES];
    int minted = do_mint(&store, &table, &tx_mint, mint_mask, 1000);
    ASSERT(minted, "mint succeeded and coin registered");

    /* Spend */
    ctx_t tx_spend; lactx_tx_init(&tx_spend, 2, 1);
    uint8_t out_masks[2][LACTX_m - D][r_BYTES];
    uint64_t v_in = 1000, v_out[2] = {600, 400};
    lactx_key_copy(out_masks[0], mint_mask); /* reuse slot, doesn't matter */
    int built = build_spend(&store, &tx_spend, &tx_mint.out[0],
                            mint_mask, v_in, 2, out_masks, v_out);
    ASSERT(built == 1, "spend header created");

    apcl_tx_meta_t meta;
    int ok = apcl_pipeline(&store, &table, &tx_spend, &meta, 1 /*commit*/);
    ASSERT(ok, "single spend: verify + lock + aggregate all succeed");

    /* Store must be valid */
    ASSERT(lactx_store_verify(&store) == 1, "store integrity preserved");

    lactx_tx_free(&tx_mint); lactx_tx_free(&tx_spend);
    apcl_lock_table_free(&table);
    lactx_drop_store(&store); remove("apcl_t01.db");
}

/* ─────────────────────────────────────────────────────────────
 * T02 – Basic double-spend
 * ───────────────────────────────────────────────────────────── */
static void t02_basic_double_spend(void)
{
    section("T02: Basic double-spend (same coin, sequential)");

    uint8_t seed[SEED_BYTES]; RAND_bytes(seed, SEED_BYTES);
    store_t store = lactx_get_store(seed, "apcl_t02.db");
    apcl_lock_table_t table; apcl_lock_table_init(&table, 256);

    ctx_t tx_mint; uint8_t mint_mask[LACTX_m - D][r_BYTES];
    do_mint(&store, &table, &tx_mint, mint_mask, 500);

    /* TX A – legitimate */
    ctx_t tx_a; lactx_tx_init(&tx_a, 1, 1);
    uint8_t out_a[LACTX_m - D][r_BYTES];
    uint64_t va_in = 500, va_out = 500;
    build_spend(&store, &tx_a, &tx_mint.out[0], mint_mask, va_in, 1, &out_a, &va_out);

    apcl_tx_meta_t meta_a;
    int ok_a = apcl_pipeline(&store, &table, &tx_a, &meta_a, 1 /*commit*/);
    ASSERT(ok_a, "TX_A (first spend) succeeds");

    /* TX B – attempt to re-spend same coin */
    ctx_t tx_b; lactx_tx_init(&tx_b, 1, 1);
    uint8_t out_b[LACTX_m - D][r_BYTES];
    uint64_t vb_in = 500, vb_out = 500;
    build_spend(&store, &tx_b, &tx_mint.out[0], mint_mask, vb_in, 1, &out_b, &vb_out);

    apcl_tx_meta_t meta_b;
    int ok_b = apcl_pipeline(&store, &table, &tx_b, &meta_b, 0 /*no commit*/);
    ASSERT(!ok_b, "TX_B (double-spend) rejected by APCL");

    lactx_tx_free(&tx_mint); lactx_tx_free(&tx_a); lactx_tx_free(&tx_b);
    apcl_lock_table_free(&table);
    lactx_drop_store(&store); remove("apcl_t02.db");
}

/* ─────────────────────────────────────────────────────────────
 * T03 – Concurrent double-spend (race)
 * ───────────────────────────────────────────────────────────── */
static void t03_concurrent_race(void)
{
    section("T03: Concurrent double-spend / race condition");

    uint8_t seed[SEED_BYTES]; RAND_bytes(seed, SEED_BYTES);
    store_t store = lactx_get_store(seed, "apcl_t03.db");
    apcl_lock_table_t table; apcl_lock_table_init(&table, 256);

    ctx_t tx_mint; uint8_t mint_mask[LACTX_m - D][r_BYTES];
    do_mint(&store, &table, &tx_mint, mint_mask, 800);

    /* Both TXs pass raw LACT+ verify first (simulating concurrent arrival) */
    ctx_t tx_a, tx_b;
    lactx_tx_init(&tx_a, 1, 1); lactx_tx_init(&tx_b, 1, 1);

    uint8_t out_a[LACTX_m - D][r_BYTES], out_b[LACTX_m - D][r_BYTES];
    uint64_t va = 800, vb = 800;
    build_spend(&store, &tx_a, &tx_mint.out[0], mint_mask, va, 1, &out_a, &va);
    build_spend(&store, &tx_b, &tx_mint.out[0], mint_mask, vb, 1, &out_b, &vb);

    int lact_a = lactx_tx_verify(&store, &tx_a);
    int lact_b = lactx_tx_verify(&store, &tx_b);
    ASSERT(lact_a && lact_b,
           "both TXs pass raw LACT+ verify (vulnerability window exists without APCL)");

    /* APCL: prepare both (seq snapshot taken here) */
    apcl_tx_meta_t meta_a, meta_b;
    apcl_prepare_tx_meta(&table, &tx_a, &meta_a);
    apcl_prepare_tx_meta(&table, &tx_b, &meta_b);

    /* Race: TX_A wins lock */
    int lock_a = apcl_acquire_lock(&table, &tx_a, &meta_a);
    /* TX_B loses */
    int lock_b = apcl_acquire_lock(&table, &tx_b, &meta_b);

    ASSERT(lock_a,  "TX_A wins the lock race");
    ASSERT(!lock_b, "TX_B loses the lock race (concurrent double-spend blocked)");

    /* Consensus filter */
    ctx_t *ptx[2]          = { &tx_a, &tx_b };
    apcl_tx_meta_t *pm[2]  = { &meta_a, &meta_b };
    ctx_t *vtx[2]; apcl_tx_meta_t *vm[2];
    int n_valid = apcl_consensus_filter(&table, ptx, pm, 2, vtx, vm);
    ASSERT(n_valid == 1, "consensus filter admits only 1 of 2 conflicting TXs");

    /* Finalize winner */
    if (lock_a) apcl_aggregate(&store, &tx_a, &table, &meta_a);

    ASSERT(lactx_store_verify(&store) == 1, "store remains consistent after race");

    lactx_tx_free(&tx_mint); lactx_tx_free(&tx_a); lactx_tx_free(&tx_b);
    apcl_lock_table_free(&table);
    lactx_drop_store(&store); remove("apcl_t03.db");
}

/* ─────────────────────────────────────────────────────────────
 * T04 – Re-spend via stale sequence number
 * ───────────────────────────────────────────────────────────── */
static void t04_stale_sequence(void)
{
    section("T04: Re-spend via stale sequence number");

    uint8_t seed[SEED_BYTES]; RAND_bytes(seed, SEED_BYTES);
    store_t store = lactx_get_store(seed, "apcl_t04.db");
    apcl_lock_table_t table; apcl_lock_table_init(&table, 256);

    ctx_t tx_mint; uint8_t mint_mask[LACTX_m - D][r_BYTES];
    do_mint(&store, &table, &tx_mint, mint_mask, 200);

    /* First legitimate spend */
    ctx_t tx1; lactx_tx_init(&tx1, 1, 1);
    uint8_t out1[LACTX_m - D][r_BYTES];
    uint64_t v1 = 200;
    build_spend(&store, &tx1, &tx_mint.out[0], mint_mask, v1, 1, &out1, &v1);

    apcl_tx_meta_t meta1;
    apcl_prepare_tx_meta(&table, &tx1, &meta1);
    /* Save the stale meta BEFORE aggregation increments the sequence */
    apcl_tx_meta_t stale_meta = meta1;

    int ok1 = apcl_verify(&store, &tx1, &table, &meta1);
    ok1 = ok1 && apcl_acquire_lock(&table, &tx1, &meta1);
    ok1 = ok1 && apcl_aggregate(&store, &tx1, &table, &meta1);
    ASSERT(ok1, "first spend succeeds (seq 0 → seq 1 after aggregation)");

    /* Sequence of the coin is now 1. Stale meta has claimed_seq=0. */
    ctx_t tx2; lactx_tx_init(&tx2, 1, 1);
    uint8_t out2[LACTX_m - D][r_BYTES];
    uint64_t v2 = 200;
    /* We try to re-create a header for the same spent coin */
    build_spend(&store, &tx2, &tx_mint.out[0], mint_mask, v2, 1, &out2, &v2);

    /* Use the stale meta (seq=0) – apcl_verify must reject it */
    int ok2 = apcl_verify(&store, &tx2, &table, &stale_meta);
    ASSERT(!ok2, "re-spend with stale sequence rejected by apcl_verify");

    lactx_tx_free(&tx_mint); lactx_tx_free(&tx1); lactx_tx_free(&tx2);
    apcl_lock_table_free(&table);
    lactx_drop_store(&store); remove("apcl_t04.db");
}

/* ─────────────────────────────────────────────────────────────
 * T05 – Stale lock expiry allows a new TX to proceed
 * ───────────────────────────────────────────────────────────── */
static void t05_lock_expiry(void)
{
    section("T05: Stale lock expiry — new TX can proceed after timeout");

    uint8_t seed[SEED_BYTES]; RAND_bytes(seed, SEED_BYTES);
    store_t store = lactx_get_store(seed, "apcl_t05.db");
    apcl_lock_table_t table; apcl_lock_table_init(&table, 256);

    ctx_t tx_mint; uint8_t mint_mask[LACTX_m - D][r_BYTES];
    do_mint(&store, &table, &tx_mint, mint_mask, 400);

    /* TX_A acquires lock but never aggregates (crashes / times out) */
    ctx_t tx_a; lactx_tx_init(&tx_a, 1, 1);
    uint8_t out_a[LACTX_m - D][r_BYTES];
    uint64_t va = 400;
    build_spend(&store, &tx_a, &tx_mint.out[0], mint_mask, va, 1, &out_a, &va);

    apcl_tx_meta_t meta_a;
    apcl_prepare_tx_meta(&table, &tx_a, &meta_a);
    int locked = apcl_acquire_lock(&table, &tx_a, &meta_a);
    ASSERT(locked, "TX_A acquires lock");

    /* Manually backdate the lock timestamp to simulate expiry */
    {
        /* Access table internals to force expiry */
        pthread_mutex_lock(&table.mutex);
        for (size_t i = 0; i < table.count; i++) {
            if (table.entries[i].status == APCL_LOCKED) {
                /* Backdate by 10 seconds */
                table.entries[i].timestamp_ms -= (APCL_LOCK_TIMEOUT_MS + 10000);
            }
        }
        pthread_mutex_unlock(&table.mutex);
    }

    /* Sweep expired locks */
    apcl_expire_stale_locks(&table);

    /* TX_B (honest retry) should now be able to acquire the lock */
    ctx_t tx_b; lactx_tx_init(&tx_b, 1, 1);
    uint8_t out_b[LACTX_m - D][r_BYTES];
    uint64_t vb = 400;
    build_spend(&store, &tx_b, &tx_mint.out[0], mint_mask, vb, 1, &out_b, &vb);

    apcl_tx_meta_t meta_b;
    int ok_b = apcl_pipeline(&store, &table, &tx_b, &meta_b, 1 /*commit*/);
    ASSERT(ok_b, "TX_B succeeds after stale lock is expired and reclaimed");

    ASSERT(lactx_store_verify(&store) == 1, "store valid after lock expiry recovery");

    lactx_tx_free(&tx_mint); lactx_tx_free(&tx_a); lactx_tx_free(&tx_b);
    apcl_lock_table_free(&table);
    lactx_drop_store(&store); remove("apcl_t05.db");
}

/* ─────────────────────────────────────────────────────────────
 * T06 – Multi-input transaction (happy path)
 * ───────────────────────────────────────────────────────────── */
static void t06_multi_input_happy(void)
{
    section("T06: Multi-input transaction (happy path)");

    uint8_t seed[SEED_BYTES]; RAND_bytes(seed, SEED_BYTES);
    store_t store = lactx_get_store(seed, "apcl_t06.db");
    apcl_lock_table_t table; apcl_lock_table_init(&table, 256);

    /* Mint two coins */
    ctx_t m1, m2;
    uint8_t mask1[LACTX_m - D][r_BYTES], mask2[LACTX_m - D][r_BYTES];
    do_mint(&store, &table, &m1, mask1, 300);
    do_mint(&store, &table, &m2, mask2, 200);

    /* Spend both in one TX: 300+200 → 500 */
    ctx_t tx; lactx_tx_init(&tx, 1, 2);
    lactx_coin_copy(&tx.in[0], &m1.out[0]);
    lactx_coin_copy(&tx.in[1], &m2.out[0]);

    uint8_t in_masks[2][LACTX_m - D][r_BYTES];
    lactx_key_copy(in_masks[0], mask1);
    lactx_key_copy(in_masks[1], mask2);
    uint8_t out_masks[1][LACTX_m - D][r_BYTES];
    uint64_t v_in[2] = {300, 200}, v_out[1] = {500};

    int built = lactx_header_create(&store.ctx, &tx.header,
                                    1, tx.out, out_masks, v_out,
                                    2, tx.in, in_masks, v_in);
    ASSERT(built == 1, "multi-input header created");

    apcl_tx_meta_t meta;
    int ok = apcl_pipeline(&store, &table, &tx, &meta, 1 /*commit*/);
    ASSERT(ok, "multi-input APCL pipeline succeeds");
    ASSERT(lactx_store_verify(&store) == 1, "store valid after multi-input spend");

    lactx_tx_free(&m1); lactx_tx_free(&m2); lactx_tx_free(&tx);
    apcl_lock_table_free(&table);
    lactx_drop_store(&store); remove("apcl_t06.db");
}

/* ─────────────────────────────────────────────────────────────
 * T07 – Multi-input double-spend (partial input overlap)
 * ───────────────────────────────────────────────────────────── */
static void t07_multi_input_double_spend(void)
{
    section("T07: Multi-input double-spend (partial input overlap)");

    uint8_t seed[SEED_BYTES]; RAND_bytes(seed, SEED_BYTES);
    store_t store = lactx_get_store(seed, "apcl_t07.db");
    apcl_lock_table_t table; apcl_lock_table_init(&table, 256);

    ctx_t m1, m2;
    uint8_t mask1[LACTX_m - D][r_BYTES], mask2[LACTX_m - D][r_BYTES];
    do_mint(&store, &table, &m1, mask1, 300);
    do_mint(&store, &table, &m2, mask2, 200);

    /* TX_A uses coin1 only */
    ctx_t tx_a; lactx_tx_init(&tx_a, 1, 1);
    uint8_t oa[LACTX_m - D][r_BYTES];
    uint64_t vao = 300;
    build_spend(&store, &tx_a, &m1.out[0], mask1, 300, 1, &oa, &vao);

    /* TX_B uses BOTH coin1 and coin2 (overlaps with TX_A on coin1) */
    ctx_t tx_b; lactx_tx_init(&tx_b, 1, 2);
    lactx_coin_copy(&tx_b.in[0], &m1.out[0]);
    lactx_coin_copy(&tx_b.in[1], &m2.out[0]);
    uint8_t in_masks_b[2][LACTX_m - D][r_BYTES];
    lactx_key_copy(in_masks_b[0], mask1);
    lactx_key_copy(in_masks_b[1], mask2);
    uint8_t ob[1][LACTX_m - D][r_BYTES];
    uint64_t vb_in[2] = {300,200}, vb_out[1] = {500};
    lactx_header_create(&store.ctx, &tx_b.header,
                        1, tx_b.out, ob, vb_out,
                        2, tx_b.in, in_masks_b, vb_in);

    apcl_tx_meta_t meta_a, meta_b;
    /* TX_A locks coin1 first */
    apcl_prepare_tx_meta(&table, &tx_a, &meta_a);
    int ok_a = apcl_verify(&store, &tx_a, &table, &meta_a)
             && apcl_acquire_lock(&table, &tx_a, &meta_a);
    ASSERT(ok_a, "TX_A locks coin1");

    /* TX_B tries to lock coin1+coin2 — must fail because coin1 taken */
    apcl_prepare_tx_meta(&table, &tx_b, &meta_b);
    int ok_b = apcl_verify(&store, &tx_b, &table, &meta_b)
             && apcl_acquire_lock(&table, &tx_b, &meta_b);
    ASSERT(!ok_b, "TX_B (overlapping inputs) blocked by APCL");

    if (ok_a) apcl_aggregate(&store, &tx_a, &table, &meta_a);

    lactx_tx_free(&m1); lactx_tx_free(&m2);
    lactx_tx_free(&tx_a); lactx_tx_free(&tx_b);
    apcl_lock_table_free(&table);
    lactx_drop_store(&store); remove("apcl_t07.db");
}

/* ─────────────────────────────────────────────────────────────
 * T08 – Inflation attack still blocked by underlying LACT+
 * ───────────────────────────────────────────────────────────── */
static void t08_inflation_still_blocked(void)
{
    section("T08: Inflation attack — still blocked by LACT+ inside APCL");

    uint8_t seed[SEED_BYTES]; RAND_bytes(seed, SEED_BYTES);
    store_t store = lactx_get_store(seed, "apcl_t08.db");
    apcl_lock_table_t table; apcl_lock_table_init(&table, 256);

    ctx_t tx_mint; uint8_t mint_mask[LACTX_m - D][r_BYTES];
    do_mint(&store, &table, &tx_mint, mint_mask, 100);

    /* Attempt 100 → 80+80 (inflation: outputs > input) */
    ctx_t tx_inf; lactx_tx_init(&tx_inf, 2, 1);
    uint8_t out_inf[2][LACTX_m - D][r_BYTES];
    uint64_t vi = 100, vo[2] = {80, 80};

    /* lactx_header_create checks balance — should return 0 */
    int built = lactx_header_create(&store.ctx, &tx_inf.header,
                                    2, tx_inf.out, out_inf, vo,
                                    1, tx_inf.in, &mint_mask, &vi);
    /* If header creation somehow succeeded, APCL verify catches it via
     * the underlying lactx_tx_verify which checks balance proofs. */
    int ok_inf = 0;
    if (built) {
        lactx_coin_copy(&tx_inf.in[0], &tx_mint.out[0]);
        apcl_tx_meta_t meta_inf;
        apcl_prepare_tx_meta(&table, &tx_inf, &meta_inf);
        ok_inf = apcl_verify(&store, &tx_inf, &table, &meta_inf);
    }
    ASSERT(!ok_inf, "inflation attempt blocked (by LACT+ balance check inside APCL)");

    lactx_tx_free(&tx_mint); lactx_tx_free(&tx_inf);
    apcl_lock_table_free(&table);
    lactx_drop_store(&store); remove("apcl_t08.db");
}

/* ─────────────────────────────────────────────────────────────
 * T09 – Sequential chain: spend the output of a previous TX
 * ───────────────────────────────────────────────────────────── */
static void t09_sequential_chain(void)
{
    section("T09: Sequential chain — spend output of previous TX");

    uint8_t seed[SEED_BYTES]; RAND_bytes(seed, SEED_BYTES);
    store_t store = lactx_get_store(seed, "apcl_t09.db");
    apcl_lock_table_t table; apcl_lock_table_init(&table, 256);

    ctx_t tx_mint; uint8_t mint_mask[LACTX_m - D][r_BYTES];
    do_mint(&store, &table, &tx_mint, mint_mask, 600);

    /* TX1: 600 → 400 + 200 */
    ctx_t tx1; lactx_tx_init(&tx1, 2, 1);
    uint8_t out1[2][LACTX_m - D][r_BYTES];
    uint64_t v1_in = 600, v1_out[2] = {400, 200};
    build_spend(&store, &tx1, &tx_mint.out[0], mint_mask, v1_in, 2, out1, v1_out);

    apcl_tx_meta_t meta1;
    int ok1 = apcl_pipeline(&store, &table, &tx1, &meta1, 1);
    ASSERT(ok1, "TX1 (600 → 400+200) succeeds");

    /* TX2: spend the 400-coin output of TX1 → 400 */
    ctx_t tx2; lactx_tx_init(&tx2, 1, 1);
    uint8_t out2[LACTX_m - D][r_BYTES];
    uint64_t v2_in = 400, v2_out = 400;
    build_spend(&store, &tx2, &tx1.out[0], out1[0], v2_in, 1, &out2, &v2_out);

    apcl_tx_meta_t meta2;
    int ok2 = apcl_pipeline(&store, &table, &tx2, &meta2, 1);
    ASSERT(ok2, "TX2 (400 from TX1 output) succeeds");

    ASSERT(lactx_store_verify(&store) == 1, "store valid after 2-hop chain");

    lactx_tx_free(&tx_mint); lactx_tx_free(&tx1); lactx_tx_free(&tx2);
    apcl_lock_table_free(&table);
    lactx_drop_store(&store); remove("apcl_t09.db");
}

/* ─────────────────────────────────────────────────────────────
 * T10 – Store integrity after many APCL-managed TXs
 * ───────────────────────────────────────────────────────────── */
static void t10_store_integrity(void)
{
    section("T10: Store integrity after many APCL-managed transactions");

    uint8_t seed[SEED_BYTES]; RAND_bytes(seed, SEED_BYTES);
    store_t store = lactx_get_store(seed, "apcl_t10.db");
    apcl_lock_table_t table; apcl_lock_table_init(&table, 512);

    /* Mint 5 coins */
#define N_MINTS 5
    ctx_t mints[N_MINTS];
    uint8_t masks[N_MINTS][LACTX_m - D][r_BYTES];
    uint64_t amounts[N_MINTS] = {100, 200, 150, 300, 50};

    for (int i = 0; i < N_MINTS; i++) {
        int ok = do_mint(&store, &table, &mints[i], masks[i], amounts[i]);
        ASSERT(ok, "mint succeeded");
    }

    /* Spend each coin individually */
    int all_ok = 1;
    for (int i = 0; i < N_MINTS; i++) {
        ctx_t tx; lactx_tx_init(&tx, 1, 1);
        uint8_t out_m[LACTX_m - D][r_BYTES];
        uint64_t v = amounts[i];
        build_spend(&store, &tx, &mints[i].out[0], masks[i], v, 1, &out_m, &v);

        apcl_tx_meta_t meta;
        int ok = apcl_pipeline(&store, &table, &tx, &meta, 1);
        if (!ok) { all_ok = 0; }
        lactx_tx_free(&tx);
    }
    ASSERT(all_ok, "all 5 spends succeeded without conflict");

    ASSERT(lactx_store_verify(&store) == 1,
           "store integrity valid after 5 mints + 5 spends");

    for (int i = 0; i < N_MINTS; i++) lactx_tx_free(&mints[i]);
    apcl_lock_table_free(&table);
    lactx_drop_store(&store); remove("apcl_t10.db");
}

/* ─────────────────────────────────────────────────────────────
 * MAIN
 * ───────────────────────────────────────────────────────────── */
int main(void)
{
    printf("\n" BOLD
           "╔══════════════════════════════════════════════════════════╗\n"
           "║        APCL INTEGRATION TEST SUITE                      ║\n"
           "║  Activity-Proof Consensus Locking — Full Validation      ║\n"
           "╚══════════════════════════════════════════════════════════╝\n"
           RESET "\n");

    t01_happy_path();
    t02_basic_double_spend();
    t03_concurrent_race();
    t04_stale_sequence();
    t05_lock_expiry();
    t06_multi_input_happy();
    t07_multi_input_double_spend();
    t08_inflation_still_blocked();
    t09_sequential_chain();
    t10_store_integrity();

    printf("\n" BOLD "━━━ RESULTS ━━━" RESET "\n");
    printf("  " GREEN "PASSED: %d" RESET "\n", g_pass);
    printf("  " RED   "FAILED: %d" RESET "\n", g_fail);

    if (g_fail == 0) {
        printf("\n" GREEN BOLD
               "  ✓  All tests passed — APCL is functioning correctly.\n"
               RESET "\n");
    } else {
        printf("\n" RED BOLD
               "  ✗  %d test(s) failed — review APCL implementation.\n"
               RESET "\n", g_fail);
    }

    return g_fail == 0 ? 0 : 1;
}
