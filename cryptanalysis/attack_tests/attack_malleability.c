//
// LACT+ Cryptanalysis: Header Malleability Attack Test
// Tests if "Origami activity proofs" prevent creating different in/outputs for same header
// THIS IS LACT+'S KEY INNOVATION!
//
// Location: ~/Documents/LACTv2/cryptanalysis/attack_tests/attack_malleability.c
//

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "lactx_store.h"
#include "openssl/rand.h"

#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define CYAN    "\x1b[36m"
#define MAGENTA "\x1b[35m"
#define BLUE    "\x1b[34m"
#define RESET   "\x1b[0m"

void print_header(const char* title) {
    printf("\n╔════════════════════════════════════════════════════════╗\n");
    printf("║  %-52s  ║\n", title);
    printf("╚════════════════════════════════════════════════════════╝\n");
}

void print_test(const char* description) {
    printf("\n" CYAN "→ TEST: %s" RESET "\n", description);
}

void print_critical(const char* message) {
    printf(RED "  [!!!] CRITICAL: %s" RESET "\n", message);
}

void print_safe(const char* message) {
    printf(GREEN "  [✓] SAFE: %s" RESET "\n", message);
}

void print_info(const char* message) {
    printf(BLUE "  [i] %s" RESET "\n", message);
}

//============================================================================
// TEST 1: Same Header, Different Outputs
//============================================================================
void test_same_header_different_outputs() {
    print_test("Same Header, Different Outputs: LACT+'s core security claim");
    
    print_info("LACT+ claims that 'Origami activity proofs' make it infeasible");
    print_info("to create two different input/output sets for the same header.");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask;
    ctx_t tx_mint, tx1, tx2;
    
    printf("\n  [1] Setup: Minting 1000 coins...\n");
    store = lactx_get_store(seed, "test_malleability.db");
    
    lactx_tx_init(&tx_mint, 2, 1);
    lactx_mint_tx_create(&store, &tx_mint, mask, 1000);
    lactx_tx_aggregate(&store, &tx_mint);
    
    printf("\n  [2] Creating TX1: 1000 → 600 + 400...\n");
    lactx_tx_init(&tx1, 2, 1);
    
    key in_mask1, out_mask1[2];
    uint64_t v_in1 = 1000;
    uint64_t v_out1[2] = {600, 400};
    
    lactx_key_copy(in_mask1, mask);
    lactx_coin_copy(&tx1.in[0], &tx_mint.out[0]);
    
    lactx_header_create(&store.ctx, &tx1.header,
                       2, tx1.out, out_mask1, v_out1,
                       1, tx1.in, &in_mask1, &v_in1);
    
    printf("      TX1 header created\n");
    printf("      Outputs: 600 + 400\n");
    
    printf("\n  [3] Attempting to create TX2 with SAME header but different outputs...\n");
    printf("      Trying outputs: 500 + 500 (different split)\n");
    
    lactx_tx_init(&tx2, 2, 1);
    
    // Try to use the SAME header but with different output amounts
    key in_mask2, out_mask2[2];
    uint64_t v_in2 = 1000;
    uint64_t v_out2[2] = {500, 500};  // DIFFERENT outputs!
    
    lactx_key_copy(in_mask2, mask);
    lactx_coin_copy(&tx2.in[0], &tx_mint.out[0]);
    
    // Copy the header from TX1
    memcpy(&tx2.header, &tx1.header, sizeof(header_t));
    
    printf("\n  [4] Verifying TX1 (original)...\n");
    int v1 = lactx_tx_verify(&store, &tx1);
    printf("      TX1 valid: %s\n", v1 ? "YES" : "NO");
    
    printf("\n  [5] Verifying TX2 (same header, different outputs)...\n");
    int v2 = lactx_tx_verify(&store, &tx2);
    printf("      TX2 valid: %s\n", v2 ? "YES" : "NO");
    
    printf("\n" YELLOW "═══════════════════════════════════════════════════════" RESET "\n");
    
    if (v1 && v2) {
        print_critical("MALLEABILITY VULNERABILITY FOUND!");
        print_critical("Same header accepted with different outputs!");
        printf("      This breaks LACT+'s key security claim!\n");
        printf("      Activity proofs are NOT working!\n");
    } else if (v1 && !v2) {
        print_safe("Malleability prevented");
        printf("      Activity proof correctly binds header to outputs\n");
    } else {
        printf("      " YELLOW "Unexpected result - investigate further" RESET "\n");
    }
    
    lactx_tx_free(&tx_mint);
    lactx_tx_free(&tx1);
    lactx_tx_free(&tx2);
    lactx_drop_store(&store);
    remove("test_malleability.db");
}

//============================================================================
// TEST 2: Same Header, Different Inputs
//============================================================================
void test_same_header_different_inputs() {
    print_test("Same Header, Different Inputs: Testing input binding");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask1, mask2;
    ctx_t tx_mint1, tx_mint2, tx1, tx2;
    
    printf("  [1] Setup: Minting two coins (500 each)...\n");
    store = lactx_get_store(seed, "test_input_binding.db");
    
    lactx_tx_init(&tx_mint1, 2, 1);
    lactx_mint_tx_create(&store, &tx_mint1, mask1, 500);
    lactx_tx_aggregate(&store, &tx_mint1);
    
    lactx_tx_init(&tx_mint2, 2, 1);
    lactx_mint_tx_create(&store, &tx_mint2, mask2, 500);
    lactx_tx_aggregate(&store, &tx_mint2);
    
    printf("\n  [2] Creating TX1 using coin 1...\n");
    lactx_tx_init(&tx1, 1, 1);
    
    key in_mask1, out_mask1;
    uint64_t v_in1 = 500;
    uint64_t v_out1 = 500;
    
    lactx_key_copy(in_mask1, mask1);
    lactx_coin_copy(&tx1.in[0], &tx_mint1.out[0]);
    
    lactx_header_create(&store.ctx, &tx1.header,
                       1, tx1.out, &out_mask1, &v_out1,
                       1, tx1.in, &in_mask1, &v_in1);
    
    printf("\n  [3] Attempting TX2 with same header but using coin 2...\n");
    lactx_tx_init(&tx2, 1, 1);
    
    key in_mask2, out_mask2;
    uint64_t v_in2 = 500;
    uint64_t v_out2 = 500;
    
    lactx_key_copy(in_mask2, mask2);
    lactx_coin_copy(&tx2.in[0], &tx_mint2.out[0]);  // DIFFERENT input!
    
    // Copy header from TX1
    memcpy(&tx2.header, &tx1.header, sizeof(header_t));
    
    int v1 = lactx_tx_verify(&store, &tx1);
    int v2 = lactx_tx_verify(&store, &tx2);
    
    printf("      TX1 (coin 1): %s\n", v1 ? "VALID" : "INVALID");
    printf("      TX2 (coin 2, same header): %s\n", v2 ? "VALID" : "INVALID");
    
    if (v1 && v2) {
        print_critical("Input binding broken!");
        printf("      Same header works with different input coins!\n");
    } else {
        print_safe("Input binding works correctly");
    }
    
    lactx_tx_free(&tx_mint1);
    lactx_tx_free(&tx_mint2);
    lactx_tx_free(&tx1);
    lactx_tx_free(&tx2);
    lactx_drop_store(&store);
    remove("test_input_binding.db");
}

//============================================================================
// TEST 3: Header Replay Attack
//============================================================================
void test_header_replay() {
    print_test("Header Replay: Can valid header be reused later?");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask;
    ctx_t tx_mint, tx_spend, tx_replay;
    
    printf("  [1] Setup and creating first transaction...\n");
    store = lactx_get_store(seed, "test_replay.db");
    
    lactx_tx_init(&tx_mint, 2, 1);
    lactx_mint_tx_create(&store, &tx_mint, mask, 300);
    lactx_tx_aggregate(&store, &tx_mint);
    
    lactx_tx_init(&tx_spend, 1, 1);
    
    key in_mask, out_mask;
    uint64_t v_in = 300;
    uint64_t v_out = 300;
    
    lactx_key_copy(in_mask, mask);
    lactx_coin_copy(&tx_spend.in[0], &tx_mint.out[0]);
    
    lactx_header_create(&store.ctx, &tx_spend.header,
                       1, tx_spend.out, &out_mask, &v_out,
                       1, tx_spend.in, &in_mask, &v_in);
    
    printf("      First transaction created and aggregated\n");
    lactx_tx_aggregate(&store, &tx_spend);
    
    printf("\n  [2] Attempting to replay the same header...\n");
    lactx_tx_init(&tx_replay, 1, 1);
    
    // Copy everything including header
    lactx_key_copy(in_mask, mask);
    lactx_coin_copy(&tx_replay.in[0], &tx_spend.out[0]);
    memcpy(&tx_replay.header, &tx_spend.header, sizeof(header_t));
    
    int verify_result = lactx_tx_verify(&store, &tx_replay);
    
    printf("      Replay verification: %s\n", verify_result ? "VALID" : "INVALID");
    
    if (verify_result) {
        print_critical("Header replay possible!");
        printf("      Old headers can be reused!\n");
    } else {
        print_safe("Replay prevented");
    }
    
    lactx_tx_free(&tx_mint);
    lactx_tx_free(&tx_spend);
    lactx_tx_free(&tx_replay);
    lactx_drop_store(&store);
    remove("test_replay.db");
}

//============================================================================
// TEST 4: Activity Proof Collision
//============================================================================
void test_activity_proof_collision() {
    print_test("Activity Proof Collision: Can two different txs have same proof?");
    
    print_info("If two different transactions can generate the same activity proof,");
    print_info("then the proof doesn't uniquely identify the transaction.");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask;
    ctx_t tx_mint, tx1, tx2;
    
    printf("\n  [1] Setup: Minting coin...\n");
    store = lactx_get_store(seed, "test_collision.db");
    
    lactx_tx_init(&tx_mint, 2, 1);
    lactx_mint_tx_create(&store, &tx_mint, mask, 1000);
    lactx_tx_aggregate(&store, &tx_mint);
    
    printf("\n  [2] Creating two transactions with similar structure...\n");
    
    // TX1: 1000 → 500 + 500
    lactx_tx_init(&tx1, 2, 1);
    key in_mask1, out_mask1[2];
    uint64_t v_in1 = 1000;
    uint64_t v_out1[2] = {500, 500};
    
    lactx_key_copy(in_mask1, mask);
    lactx_coin_copy(&tx1.in[0], &tx_mint.out[0]);
    lactx_header_create(&store.ctx, &tx1.header,
                       2, tx1.out, out_mask1, v_out1,
                       1, tx1.in, &in_mask1, &v_in1);
    
    // TX2: 1000 → 500 + 500 (same amounts, different randomness)
    lactx_tx_init(&tx2, 2, 1);
    key in_mask2, out_mask2[2];
    uint64_t v_in2 = 1000;
    uint64_t v_out2[2] = {500, 500};
    
    lactx_key_copy(in_mask2, mask);
    lactx_coin_copy(&tx2.in[0], &tx_mint.out[0]);
    lactx_header_create(&store.ctx, &tx2.header,
                       2, tx2.out, out_mask2, v_out2,
                       1, tx2.in, &in_mask2, &v_in2);
    
    printf("      TX1: 1000 → 500 + 500\n");
    printf("      TX2: 1000 → 500 + 500 (different coins)\n");
    
    printf("\n  [3] Comparing headers...\n");
    
    int headers_identical = (memcmp(&tx1.header, &tx2.header, sizeof(header_t)) == 0);
    
    if (headers_identical) {
        print_critical("COLLISION FOUND!");
        printf("      Two different transactions have identical headers!\n");
        printf("      Activity proofs are NOT unique!\n");
    } else {
        print_safe("Headers are different (as expected)");
        printf("      Activity proofs appear to be unique\n");
    }
    
    lactx_tx_free(&tx_mint);
    lactx_tx_free(&tx1);
    lactx_tx_free(&tx2);
    lactx_drop_store(&store);
    remove("test_collision.db");
}

//============================================================================
// TEST 5: Aggregation Malleability
//============================================================================
void test_aggregation_malleability() {
    print_test("Aggregation Malleability: Does aggregation preserve binding?");
    
    print_info("After aggregation (removing spent coins), can headers be reinterpreted?");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask;
    ctx_t tx_mint, tx_spend;
    
    printf("\n  [1] Creating and aggregating a transaction...\n");
    store = lactx_get_store(seed, "test_agg_mal.db");
    
    lactx_tx_init(&tx_mint, 2, 1);
    lactx_mint_tx_create(&store, &tx_mint, mask, 400);
    lactx_tx_aggregate(&store, &tx_mint);
    
    lactx_tx_init(&tx_spend, 2, 1);
    
    key in_mask, out_mask[2];
    uint64_t v_in = 400;
    uint64_t v_out[2] = {200, 200};
    
    lactx_key_copy(in_mask, mask);
    lactx_coin_copy(&tx_spend.in[0], &tx_mint.out[0]);
    
    lactx_header_create(&store.ctx, &tx_spend.header,
                       2, tx_spend.out, out_mask, v_out,
                       1, tx_spend.in, &in_mask, &v_in);
    
    lactx_tx_aggregate(&store, &tx_spend);
    printf("      Transaction aggregated (input removed)\n");
    
    printf("\n  [2] Verifying aggregated store...\n");
    int store_valid = lactx_store_verify(&store);
    
    if (store_valid) {
        print_safe("Aggregated store is valid");
        printf("      Activity proof maintains integrity after aggregation\n");
    } else {
        print_critical("Aggregated store is INVALID!");
        printf("      Aggregation broke something!\n");
    }
    
    lactx_tx_free(&tx_mint);
    lactx_tx_free(&tx_spend);
    lactx_drop_store(&store);
    remove("test_agg_mal.db");
}

//============================================================================
// MAIN
//============================================================================
int main() {
    print_header("LACT+ HEADER MALLEABILITY ATTACK TESTS");
    
    printf("\n" MAGENTA "═══════════════════════════════════════════════════════" RESET "\n");
    printf(MAGENTA "  THIS IS THE MOST IMPORTANT TEST SUITE!" RESET "\n");
    printf(MAGENTA "═══════════════════════════════════════════════════════" RESET "\n\n");
    
    printf("LACT+'s main innovation: " BLUE "Origami Activity Proofs" RESET "\n");
    printf("Claim: Makes creating two different in/outputs for same header INFEASIBLE\n");
    printf("\n");
    printf("Why this matters:\n");
    printf("  • Enables trustless verification of aggregated blockchain\n");
    printf("  • Prevents malleability attacks\n");
    printf("  • Allows safe removal of spent coins\n");
    printf("\n");
    printf("If this is broken → LACT+'s main contribution fails!\n");
    
    test_same_header_different_outputs();
    test_same_header_different_inputs();
    test_header_replay();
    test_activity_proof_collision();
    test_aggregation_malleability();
    
    print_header("SUMMARY");
    printf("\n");
    printf(BLUE "Origami Activity Proofs must ensure:" RESET "\n");
    printf("  ✓ Headers uniquely identify input/output sets\n");
    printf("  ✓ Cannot reuse headers with different coins\n");
    printf("  ✓ Cannot replay old headers\n");
    printf("  ✓ Binding survives aggregation\n");
    printf("\n");
    printf("If ANY test shows malleability:\n");
    printf("  → " RED "CRITICAL FAILURE of LACT+'s core innovation!" RESET "\n");
    printf("  → Trustless aggregation becomes impossible\n");
    printf("  → Falls back to requiring trusted full nodes\n");
    printf("\n");
    
    return 0;
}