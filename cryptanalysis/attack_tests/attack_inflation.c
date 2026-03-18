//
// LACT+ Cryptanalysis: Inflation Attack Test
// Tests if money can be created from nothing (outputs > inputs)
//
// Location: ~/Documents/LACTv2/cryptanalysis/attack_tests/attack_inflation.c
//

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "lactx_store.h"
#include "openssl/rand.h"

// ANSI color codes
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN    "\x1b[36m"
#define RESET   "\x1b[0m"

void print_header(const char* title) {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════╗\n");
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

//============================================================================
// TEST 1: Basic Inflation - Outputs > Inputs
//============================================================================
void test_basic_inflation() {
    print_test("Basic Inflation: Creating more output than input");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask;
    ctx_t tx_mint, tx_inflate;
    
    printf("  [1] Setup: Minting 100 coins...\n");
    store = lactx_get_store(seed, "test_inflation.db");
    
    lactx_tx_init(&tx_mint, 2, 1);
    lactx_mint_tx_create(&store, &tx_mint, mask, 100);
    lactx_tx_verify(&store, &tx_mint);
    lactx_tx_aggregate(&store, &tx_mint);
    printf("      Minted 100 coins successfully\n");
    
    printf("\n  [2] Attempting to create MORE output than input...\n");
    printf("      Input:  100 coins\n");
    printf("      Output: 80 + 80 = 160 coins (60 extra!)\n");
    
    lactx_tx_init(&tx_inflate, 2, 1);
    
    key in_mask, out_mask[2];
    uint64_t v_in = 100;
    uint64_t v_out[2] = {80, 80};  // Total: 160 > 100!
    
    lactx_key_copy(in_mask, mask);
    lactx_coin_copy(&tx_inflate.in[0], &tx_mint.out[0]);
    
    printf("\n  [3] Creating header (sum check happens here)...\n");
    int create_result = lactx_header_create(&store.ctx, &tx_inflate.header,
                                            2, tx_inflate.out, out_mask, v_out,
                                            1, tx_inflate.in, &in_mask, &v_in);
    
    if (create_result == 1) {
        printf("      Header creation: SUCCESS\n");
        printf("      " YELLOW "⚠️  Header was created despite imbalance!" RESET "\n");
        
        printf("\n  [4] Verifying transaction...\n");
        int verify_result = lactx_tx_verify(&store, &tx_inflate);
        
        if (verify_result == 1) {
            print_critical("Transaction VERIFIED despite outputs > inputs!");
            print_critical("Inflation attack is POSSIBLE!");
            printf("      Created 60 extra coins out of thin air!\n");
        } else {
            print_safe("Verification caught the imbalance");
        }
    } else {
        print_safe("Header creation prevented inflation at creation stage");
    }
    
    // Cleanup
    lactx_tx_free(&tx_mint);
    lactx_tx_free(&tx_inflate);
    lactx_drop_store(&store);
    remove("test_inflation.db");
}

//============================================================================
// TEST 2: Extreme Inflation
//============================================================================
void test_extreme_inflation() {
    print_test("Extreme Inflation: Massive output imbalance");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask;
    ctx_t tx_mint, tx_inflate;
    
    printf("  [1] Setup: Minting 10 coins...\n");
    store = lactx_get_store(seed, "test_extreme.db");
    
    lactx_tx_init(&tx_mint, 2, 1);
    lactx_mint_tx_create(&store, &tx_mint, mask, 10);
    lactx_tx_aggregate(&store, &tx_mint);
    
    printf("\n  [2] Attempting EXTREME inflation...\n");
    printf("      Input:  10 coins\n");
    printf("      Output: 1,000,000 coins\n");
    
    lactx_tx_init(&tx_inflate, 1, 1);
    
    key in_mask, out_mask;
    uint64_t v_in = 10;
    uint64_t v_out = 1000000;  // 100,000x inflation!
    
    lactx_key_copy(in_mask, mask);
    lactx_coin_copy(&tx_inflate.in[0], &tx_mint.out[0]);
    
    int create_result = lactx_header_create(&store.ctx, &tx_inflate.header,
                                            1, tx_inflate.out, &out_mask, &v_out,
                                            1, tx_inflate.in, &in_mask, &v_in);
    
    if (create_result == 1) {
        int verify_result = lactx_tx_verify(&store, &tx_inflate);
        
        if (verify_result == 1) {
            print_critical("EXTREME inflation possible!");
            printf("      Turned 10 coins into 1,000,000!\n");
        } else {
            print_safe("Verification stopped extreme inflation");
        }
    } else {
        print_safe("Creation prevented extreme inflation");
    }
    
    // Cleanup
    lactx_tx_free(&tx_mint);
    lactx_tx_free(&tx_inflate);
    lactx_drop_store(&store);
    remove("test_extreme.db");
}

//============================================================================
// TEST 3: Subtle Inflation (Off-by-One)
//============================================================================
void test_subtle_inflation() {
    print_test("Subtle Inflation: Off-by-one error");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask;
    ctx_t tx_mint, tx_inflate;
    
    printf("  [1] Setup: Minting 1000 coins...\n");
    store = lactx_get_store(seed, "test_subtle.db");
    
    lactx_tx_init(&tx_mint, 2, 1);
    lactx_mint_tx_create(&store, &tx_mint, mask, 1000);
    lactx_tx_aggregate(&store, &tx_mint);
    
    printf("\n  [2] Attempting subtle inflation (off-by-one)...\n");
    printf("      Input:  1000 coins\n");
    printf("      Output: 501 + 500 = 1001 coins (+1 extra)\n");
    
    lactx_tx_init(&tx_inflate, 2, 1);
    
    key in_mask, out_mask[2];
    uint64_t v_in = 1000;
    uint64_t v_out[2] = {501, 500};  // Total: 1001
    
    lactx_key_copy(in_mask, mask);
    lactx_coin_copy(&tx_inflate.in[0], &tx_mint.out[0]);
    
    int create_result = lactx_header_create(&store.ctx, &tx_inflate.header,
                                            2, tx_inflate.out, out_mask, v_out,
                                            1, tx_inflate.in, &in_mask, &v_in);
    
    if (create_result == 1) {
        int verify_result = lactx_tx_verify(&store, &tx_inflate);
        
        if (verify_result == 1) {
            print_critical("Subtle inflation possible (off-by-one)!");
            printf("      Even 1 extra coin is a vulnerability!\n");
        } else {
            print_safe("Verification caught off-by-one inflation");
        }
    } else {
        print_safe("Creation prevented off-by-one inflation");
    }
    
    // Cleanup
    lactx_tx_free(&tx_mint);
    lactx_tx_free(&tx_inflate);
    lactx_drop_store(&store);
    remove("test_subtle.db");
}

//============================================================================
// TEST 4: Integer Overflow Inflation
//============================================================================
void test_overflow_inflation() {
    print_test("Overflow Inflation: Using integer overflow to create coins");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask;
    ctx_t tx_mint, tx_inflate;
    
    printf("  [1] Setup: Minting large coin...\n");
    store = lactx_get_store(seed, "test_overflow.db");
    
    uint64_t large_amount = UINT64_MAX - 1000;  // Near max value
    
    lactx_tx_init(&tx_mint, 2, 1);
    lactx_mint_tx_create(&store, &tx_mint, mask, large_amount);
    lactx_tx_aggregate(&store, &tx_mint);
    
    printf("      Minted: %lu coins (near UINT64_MAX)\n", large_amount);
    
    printf("\n  [2] Attempting overflow by adding more output...\n");
    
    lactx_tx_init(&tx_inflate, 2, 1);
    
    key in_mask, out_mask[2];
    uint64_t v_in = large_amount;
    uint64_t v_out[2] = {large_amount / 2 + 2000, large_amount / 2 + 2000};
    // Sum would overflow uint64_t
    
    lactx_key_copy(in_mask, mask);
    lactx_coin_copy(&tx_inflate.in[0], &tx_mint.out[0]);
    
    printf("      Input:  %lu\n", v_in);
    printf("      Output: %lu + %lu\n", v_out[0], v_out[1]);
    printf("      (Sum would overflow and wrap around)\n");
    
    int create_result = lactx_header_create(&store.ctx, &tx_inflate.header,
                                            2, tx_inflate.out, out_mask, v_out,
                                            1, tx_inflate.in, &in_mask, &v_in);
    
    if (create_result == 1) {
        int verify_result = lactx_tx_verify(&store, &tx_inflate);
        
        if (verify_result == 1) {
            print_critical("Integer overflow inflation POSSIBLE!");
            printf("      System doesn't handle overflow correctly!\n");
        } else {
            print_safe("Verification prevented overflow inflation");
        }
    } else {
        print_safe("Creation prevented overflow inflation");
    }
    
    // Cleanup
    lactx_tx_free(&tx_mint);
    lactx_tx_free(&tx_inflate);
    lactx_drop_store(&store);
    remove("test_overflow.db");
}

//============================================================================
// TEST 5: Multiple Inputs Inflation
//============================================================================
void test_multi_input_inflation() {
    print_test("Multiple Inputs Inflation: Outputs > sum of all inputs");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask1, mask2;
    ctx_t tx_mint1, tx_mint2, tx_inflate;
    
    printf("  [1] Setup: Minting two coins (300 + 200)...\n");
    store = lactx_get_store(seed, "test_multi.db");
    
    lactx_tx_init(&tx_mint1, 2, 1);
    lactx_mint_tx_create(&store, &tx_mint1, mask1, 300);
    lactx_tx_aggregate(&store, &tx_mint1);
    
    lactx_tx_init(&tx_mint2, 2, 1);
    lactx_mint_tx_create(&store, &tx_mint2, mask2, 200);
    lactx_tx_aggregate(&store, &tx_mint2);
    
    printf("      Total input: 300 + 200 = 500 coins\n");
    
    printf("\n  [2] Attempting to create 700 output from 500 input...\n");
    
    lactx_tx_init(&tx_inflate, 3, 2);
    
    key in_mask[2], out_mask[3];
    uint64_t v_in[2] = {300, 200};
    uint64_t v_out[3] = {300, 300, 100};  // Total: 700 > 500
    
    lactx_key_copy(in_mask[0], mask1);
    lactx_key_copy(in_mask[1], mask2);
    lactx_coin_copy(&tx_inflate.in[0], &tx_mint1.out[0]);
    lactx_coin_copy(&tx_inflate.in[1], &tx_mint2.out[0]);
    
    int create_result = lactx_header_create(&store.ctx, &tx_inflate.header,
                                            3, tx_inflate.out, out_mask, v_out,
                                            2, tx_inflate.in, in_mask, v_in);
    
    if (create_result == 1) {
        int verify_result = lactx_tx_verify(&store, &tx_inflate);
        
        if (verify_result == 1) {
            print_critical("Multi-input inflation POSSIBLE!");
            printf("      Created 200 extra coins from two inputs!\n");
        } else {
            print_safe("Verification caught multi-input inflation");
        }
    } else {
        print_safe("Creation prevented multi-input inflation");
    }
    
    // Cleanup
    lactx_tx_free(&tx_mint1);
    lactx_tx_free(&tx_mint2);
    lactx_tx_free(&tx_inflate);
    lactx_drop_store(&store);
    remove("test_multi.db");
}

//============================================================================
// MAIN
//============================================================================
int main() {
    print_header("LACT+ INFLATION ATTACK TESTS");
    
    printf("\n" MAGENTA "This test suite checks if LACT+ prevents inflation attacks." RESET "\n");
    printf(MAGENTA "Inflation = Creating more money than exists (outputs > inputs)." RESET "\n");
    
    test_basic_inflation();
    test_extreme_inflation();
    test_subtle_inflation();
    test_overflow_inflation();
    test_multi_input_inflation();
    
    print_header("SUMMARY");
    printf("\n");
    printf("Expected behavior (secure system):\n");
    printf("  ✓ Outputs must equal inputs\n");
    printf("  ✓ Any imbalance should be rejected\n");
    printf("  ✓ Overflow should be detected\n");
    printf("\n");
    printf("If any test shows inflation is possible:\n");
    printf("  → CRITICAL VULNERABILITY\n");
    printf("  → Economic security is broken\n");
    printf("\n");
    
    return 0;
}