/****************************************************************************
 *  APCL Double-Spending Attack Test
 *
 *  Author: Nouhaila HANBALI
 *  Date:   2026-03-18
 *
 *  This test suite mirrors the original attack_double_spend.c but runs
 *  every scenario through the APCL layer.  It verifies that:
 *
 *  1. Basic double-spend → BLOCKED by APCL lock acquisition
 *  2. Concurrent double-spend → BLOCKED before consensus
 *  3. Database-level re-spend → BLOCKED by sequence check
 *
 *  All three tests should show "[SAFE]" with APCL enabled.
 *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "apcl.h"
#include "openssl/rand.h"

/* ── colour helpers ─────────────────────────────────────────── */
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define CYAN    "\x1b[36m"
#define MAGENTA "\x1b[35m"
#define RESET   "\x1b[0m"

static void print_header(const char *title)
{
    printf("\n╔════════════════════════════════════════════════════════╗\n");
    printf("║  %-52s  ║\n", title);
    printf("╚════════════════════════════════════════════════════════╝\n");
}

static void print_test(const char *desc)
{
    printf("\n" CYAN "→ TEST: %s" RESET "\n", desc);
}

static void print_safe(const char *msg)
{
    printf(GREEN "  [✓ APCL SAFE]: %s" RESET "\n", msg);
}

static void print_critical(const char *msg)
{
    printf(RED "  [!!! CRITICAL]: %s" RESET "\n", msg);
}

static void print_info(const char *msg)
{
    printf("  [i] %s\n", msg);
}

/* ─────────────────────────────────────────────────────────────
 * HELPERS
 * ───────────────────────────────────────────────────────────── */

/** Mint a coin into the store AND register it in the APCL lock table. */
static int apcl_mint_coin(store_t           *store,
                           apcl_lock_table_t *table,
                           ctx_t             *tx,
                           uint8_t            mask[LACTX_m - D][r_BYTES],
                           uint64_t           amount)
{
    lactx_tx_init(tx, 2, 1);
    lactx_mint_tx_create(store, tx, mask, amount);

    if (lactx_tx_verify(store, tx) != 1) {
        fprintf(stderr, "  [APCL helper] mint verify failed\n");
        return 0;
    }
    lactx_tx_aggregate(store, tx);

    /* Register the newly created coin in APCL */
    if (apcl_mint_register(table, tx) != 0) {
        fprintf(stderr, "  [APCL helper] failed to register minted coin\n");
        return 0;
    }
    return 1;
}

/* ─────────────────────────────────────────────────────────────
 * TEST 1: Basic Double-Spending
 * ───────────────────────────────────────────────────────────── */
static void test_basic_double_spend_apcl(void)
{
    print_test("Basic Double-Spending with APCL");
    print_info("Attempt to spend the same coin in two different transactions");

    /* Setup */
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);

    store_t store = lactx_get_store(seed, "apcl_basic.db");

    apcl_lock_table_t table;
    if (apcl_lock_table_init(&table, 256) != 0) {
        fprintf(stderr, "  lock table init failed\n");
        lactx_drop_store(&store);
        return;
    }

    /* Mint */
    printf("  [1] Minting 1000 coins...\n");
    ctx_t tx_mint;
    uint8_t mint_mask[LACTX_m - D][r_BYTES];
    if (!apcl_mint_coin(&store, &table, &tx_mint, mint_mask, 1000)) {
        goto cleanup_basic;
    }
    printf("      Minted coin registered in APCL table\n");

    /* Tx A : 1000 → 600 + 400 */
    printf("\n  [2] Building Tx_A (spend 1000 → 600+400)...\n");
    ctx_t tx_a;
    lactx_tx_init(&tx_a, 2, 1);

    uint8_t in_mask_a[LACTX_m - D][r_BYTES];
    uint8_t out_mask_a[2][LACTX_m - D][r_BYTES];
    uint64_t v_in_a  = 1000;
    uint64_t v_out_a[2] = {600, 400};

    lactx_key_copy(in_mask_a, mint_mask);
    lactx_coin_copy(&tx_a.in[0], &tx_mint.out[0]);
    lactx_header_create(&store.ctx, &tx_a.header,
                        2, tx_a.out, out_mask_a, v_out_a,
                        1, tx_a.in,  &in_mask_a, &v_in_a);

    /* Tx B : 1000 → 500 + 500  (same input coin!) */
    printf("  [3] Building Tx_B (spend SAME coin 1000 → 500+500)...\n");
    ctx_t tx_b;
    lactx_tx_init(&tx_b, 2, 1);

    uint8_t in_mask_b[LACTX_m - D][r_BYTES];
    uint8_t out_mask_b[2][LACTX_m - D][r_BYTES];
    uint64_t v_in_b  = 1000;
    uint64_t v_out_b[2] = {500, 500};

    lactx_key_copy(in_mask_b, mint_mask);
    lactx_coin_copy(&tx_b.in[0], &tx_mint.out[0]);  /* SAME input */
    lactx_header_create(&store.ctx, &tx_b.header,
                        2, tx_b.out, out_mask_b, v_out_b,
                        1, tx_b.in,  &in_mask_b, &v_in_b);

    /* APCL flow for Tx_A */
    apcl_tx_meta_t meta_a, meta_b;
    printf("\n  [4] APCL verify + lock Tx_A...\n");
    int ok_a = apcl_prepare_tx_meta(&table, &tx_a, &meta_a);
    ok_a = ok_a == 0 ? apcl_verify(&store, &tx_a, &table, &meta_a) : 0;
    if (ok_a) {
        ok_a = apcl_acquire_lock(&table, &tx_a, &meta_a);
    }
    printf("      Tx_A result: %s\n", ok_a ? GREEN "LOCKED (valid)" RESET
                                            : RED "REJECTED" RESET);

    /* APCL flow for Tx_B */
    printf("\n  [5] APCL verify + lock Tx_B (conflict expected)...\n");
    int ok_b = apcl_prepare_tx_meta(&table, &tx_b, &meta_b);
    ok_b = ok_b == 0 ? apcl_verify(&store, &tx_b, &table, &meta_b) : 0;
    if (ok_b) {
        ok_b = apcl_acquire_lock(&table, &tx_b, &meta_b);
    }
    printf("      Tx_B result: %s\n", ok_b ? RED "LOCKED (double-spend!)" RESET
                                            : GREEN "REJECTED (correct)" RESET);

    printf("\n" YELLOW "═══════════════════════════════════════════════════════" RESET "\n");
    if (ok_a && !ok_b) {
        print_safe("Double-spending BLOCKED — Tx_B was rejected at lock-acquisition");
    } else if (ok_a && ok_b) {
        print_critical("APCL FAILED — both transactions were locked simultaneously!");
    } else {
        printf("  [?] Unexpected outcome (A=%d, B=%d)\n", ok_a, ok_b);
    }

    /* Cleanup */
    if (ok_a) {
        apcl_tx_meta_t dummy = meta_a;
        apcl_aggregate(&store, &tx_a, &table, &dummy);
    }

    lactx_tx_free(&tx_mint);
    lactx_tx_free(&tx_a);
    lactx_tx_free(&tx_b);

cleanup_basic:
    apcl_lock_table_free(&table);
    lactx_drop_store(&store);
    remove("apcl_basic.db");
}

/* ─────────────────────────────────────────────────────────────
 * TEST 2: Concurrent Double-Spending (race condition simulation)
 * ───────────────────────────────────────────────────────────── */
static void test_concurrent_double_spend_apcl(void)
{
    print_test("Concurrent Double-Spending with APCL");
    print_info("Both Tx_A and Tx_B pass LACT+ cryptographic verify BEFORE");
    print_info("any aggregation — APCL must block at lock acquisition step");

    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);

    store_t store = lactx_get_store(seed, "apcl_concurrent.db");

    apcl_lock_table_t table;
    apcl_lock_table_init(&table, 256);

    /* Mint */
    ctx_t tx_mint;
    uint8_t mint_mask[LACTX_m - D][r_BYTES];
    printf("  [1] Minting 500 coins...\n");
    if (!apcl_mint_coin(&store, &table, &tx_mint, mint_mask, 500)) {
        goto cleanup_concurrent;
    }

    /* Build two conflicting TXs */
    ctx_t tx_a, tx_b;
    lactx_tx_init(&tx_a, 1, 1);
    lactx_tx_init(&tx_b, 1, 1);

    uint8_t in_a[LACTX_m - D][r_BYTES], out_a[LACTX_m - D][r_BYTES];
    uint8_t in_b[LACTX_m - D][r_BYTES], out_b[LACTX_m - D][r_BYTES];
    uint64_t v_in_a = 500, v_out_a = 500;
    uint64_t v_in_b = 500, v_out_b = 500;

    lactx_key_copy(in_a, mint_mask);
    lactx_coin_copy(&tx_a.in[0], &tx_mint.out[0]);
    lactx_header_create(&store.ctx, &tx_a.header,
                        1, tx_a.out, &out_a, &v_out_a,
                        1, tx_a.in,  &in_a,  &v_in_a);

    lactx_key_copy(in_b, mint_mask);
    lactx_coin_copy(&tx_b.in[0], &tx_mint.out[0]);   /* SAME input */
    lactx_header_create(&store.ctx, &tx_b.header,
                        1, tx_b.out, &out_b, &v_out_b,
                        1, tx_b.in,  &in_b,  &v_in_b);

    /* Simulate concurrent verification: both pass LACT+ checks first */
    printf("  [2] Simulating concurrent LACT+ verification (pre-APCL)...\n");
    int lact_a = lactx_tx_verify(&store, &tx_a);
    int lact_b = lactx_tx_verify(&store, &tx_b);
    printf("      Tx_A LACT+ verify: %s\n", lact_a ? "VALID" : "INVALID");
    printf("      Tx_B LACT+ verify: %s\n", lact_b ? "VALID" : "INVALID");

    if (lact_a && lact_b) {
        print_info("Both TXs pass LACT+ crypto checks — vulnerability window open");
        print_info("APCL lock acquisition now enforces exclusivity...");
    }

    /* APCL metadata */
    apcl_tx_meta_t meta_a, meta_b;
    apcl_prepare_tx_meta(&table, &tx_a, &meta_a);
    apcl_prepare_tx_meta(&table, &tx_b, &meta_b);

    /* Race: Tx_A acquires lock first */
    printf("\n  [3] Tx_A attempts APCL lock acquisition...\n");
    int lock_a = apcl_acquire_lock(&table, &tx_a, &meta_a);
    printf("      Tx_A lock: %s\n",
           lock_a ? GREEN "ACQUIRED" RESET : RED "FAILED" RESET);

    /* Tx_B tries to acquire the same lock — must fail */
    printf("  [4] Tx_B attempts APCL lock acquisition (conflict)...\n");
    int lock_b = apcl_acquire_lock(&table, &tx_b, &meta_b);
    printf("      Tx_B lock: %s\n",
           lock_b ? RED "ACQUIRED (double-spend!)" RESET
                  : GREEN "BLOCKED (correct)" RESET);

    /* Consensus filter */
    printf("\n  [5] Running APCL consensus filter...\n");
    ctx_t *pending_txs[2]      = { &tx_a, &tx_b };
    apcl_tx_meta_t *metas[2]   = { &meta_a, &meta_b };
    ctx_t *valid_txs[2];
    apcl_tx_meta_t *valid_metas[2];

    int n_valid = apcl_consensus_filter(&table,
                                         pending_txs, metas, 2,
                                         valid_txs, valid_metas);
    printf("      Transactions eligible for consensus: %d / 2\n", n_valid);

    printf("\n" YELLOW "═══════════════════════════════════════════════════════" RESET "\n");
    if (lock_a && !lock_b && n_valid == 1) {
        print_safe("Concurrent double-spending BLOCKED — only Tx_A enters consensus");
    } else {
        print_critical("APCL failed to prevent concurrent double-spend!");
    }

    /* Finalize Tx_A */
    if (lock_a)
        apcl_aggregate(&store, &tx_a, &table, &meta_a);

    /* Verify store integrity */
    int store_ok = lactx_store_verify(&store);
    printf("  Store integrity after APCL: %s\n",
           store_ok ? GREEN "VALID" RESET : RED "CORRUPTED" RESET);

    lactx_tx_free(&tx_mint);
    lactx_tx_free(&tx_a);
    lactx_tx_free(&tx_b);

cleanup_concurrent:
    apcl_lock_table_free(&table);
    lactx_drop_store(&store);
    remove("apcl_concurrent.db");
}

/* ─────────────────────────────────────────────────────────────
 * TEST 3: Re-spend after aggregation (sequence check)
 * ───────────────────────────────────────────────────────────── */
static void test_database_double_spend_apcl(void)
{
    print_test("Re-Spend After Aggregation with APCL (Sequence Check)");
    print_info("After a coin is spent and aggregated, its sequence increments.");
    print_info("A second TX with the old sequence must be rejected.");

    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);

    store_t store = lactx_get_store(seed, "apcl_database.db");

    apcl_lock_table_t table;
    apcl_lock_table_init(&table, 256);

    /* Mint */
    ctx_t tx_mint;
    uint8_t mint_mask[LACTX_m - D][r_BYTES];
    printf("  [1] Minting 300 coins...\n");
    if (!apcl_mint_coin(&store, &table, &tx_mint, mint_mask, 300)) {
        goto cleanup_db;
    }

    /* First spend: legitimate */
    ctx_t tx_spend;
    lactx_tx_init(&tx_spend, 1, 1);

    uint8_t in_m[LACTX_m - D][r_BYTES], out_m[LACTX_m - D][r_BYTES];
    uint64_t v_in = 300, v_out = 300;
    lactx_key_copy(in_m, mint_mask);
    lactx_coin_copy(&tx_spend.in[0], &tx_mint.out[0]);
    lactx_header_create(&store.ctx, &tx_spend.header,
                        1, tx_spend.out, &out_m, &v_out,
                        1, tx_spend.in,  &in_m,  &v_in);

    printf("  [2] Spending coin (first time)...\n");
    apcl_tx_meta_t meta_spend;
    apcl_prepare_tx_meta(&table, &tx_spend, &meta_spend);
    int v1 = apcl_verify(&store, &tx_spend, &table, &meta_spend);
    int l1 = v1 ? apcl_acquire_lock(&table, &tx_spend, &meta_spend) : 0;
    printf("      Verify: %s  Lock: %s\n",
           v1 ? "VALID" : "INVALID",
           l1 ? "ACQUIRED" : "FAILED");

    /* Aggregate (sequence increments here) */
    if (l1) apcl_aggregate(&store, &tx_spend, &table, &meta_spend);
    printf("      Coin aggregated – sequence incremented\n");

    /* Re-spend attempt using old meta (stale sequence) */
    printf("\n  [3] Attempting re-spend with STALE sequence...\n");
    ctx_t tx_double;
    lactx_tx_init(&tx_double, 1, 1);

    uint8_t in_m2[LACTX_m - D][r_BYTES], out_m2[LACTX_m - D][r_BYTES];
    uint64_t v_in2 = 300, v_out2 = 300;
    lactx_key_copy(in_m2, mint_mask);
    lactx_coin_copy(&tx_double.in[0], &tx_mint.out[0]);  /* spent coin */
    lactx_header_create(&store.ctx, &tx_double.header,
                        1, tx_double.out, &out_m2, &v_out2,
                        1, tx_double.in,  &in_m2,  &v_in2);

    /* Re-use old meta → stale sequence */
    apcl_tx_meta_t meta_double = meta_spend; /* claimed_seq = 0, but current = 1 */
    int v2 = apcl_verify(&store, &tx_double, &table, &meta_double);
    printf("      Re-spend verify: %s\n",
           v2 ? RED "VALID (double-spend!)" RESET
              : GREEN "REJECTED by sequence check (correct)" RESET);

    printf("\n" YELLOW "═══════════════════════════════════════════════════════" RESET "\n");
    if (!v2)
        print_safe("Re-spend blocked by APCL sequence check");
    else
        print_critical("APCL sequence check failed — re-spend accepted!");

    lactx_tx_free(&tx_mint);
    lactx_tx_free(&tx_spend);
    lactx_tx_free(&tx_double);

cleanup_db:
    apcl_lock_table_free(&table);
    lactx_drop_store(&store);
    remove("apcl_database.db");
}

/* ─────────────────────────────────────────────────────────────
 * MAIN
 * ───────────────────────────────────────────────────────────── */
int main(void)
{
    print_header("APCL DOUBLE-SPENDING PREVENTION TESTS");

    printf("\n" MAGENTA
           "Activity-Proof Consensus Locking (APCL) protection layer.\n"
           "Each scenario that was exploitable in vanilla LACT+ is now\n"
           "tested against the APCL-hardened pipeline.\n"
           RESET "\n");

    test_basic_double_spend_apcl();
    test_concurrent_double_spend_apcl();
    test_database_double_spend_apcl();

    print_header("SUMMARY");
    printf("\n");
    printf("APCL protection guarantees:\n");
    printf("  ✓ Only the first TX to acquire the lock proceeds to consensus\n");
    printf("  ✓ Concurrent TXs on same input are rejected at lock step\n");
    printf("  ✓ Re-spend after aggregation fails due to sequence mismatch\n");
    printf("  ✓ All LACT+ cryptographic properties preserved\n");
    printf("\n");
    printf("If all tests show [✓ APCL SAFE] → APCL is working correctly.\n\n");

    return 0;
}
