//
// LACT+ Cryptanalysis: Negative Amount Attack Test
// Tests if negative amounts can bypass range proofs
//
// Location: ~/Documents/LACTv2/cryptanalysis/attack_tests/attack_negative.c
//

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "lactx_store.h"
#include "openssl/rand.h"

// ANSI colors
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define CYAN    "\x1b[36m"
#define MAGENTA "\x1b[35m"
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

//============================================================================
// TEST 1: Direct Negative Amount
//============================================================================
void test_direct_negative() {
    print_test("Direct Negative: Try to create coin with negative value");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask;
    ctx_t tx_mint, tx_negative;
    
    printf("  [1] Setup: Minting 500 coins...\n");
    store = lactx_get_store(seed, "test_negative.db");
    
    lactx_tx_init(&tx_mint, 2, 1);
    lactx_mint_tx_create(&store, &tx_mint, mask, 500);
    lactx_tx_aggregate(&store, &tx_mint);
    
    printf("\n  [2] Attempting to create output with -100 (as signed int)...\n");
    
    // Try to trick the system by using signed arithmetic
    int64_t negative_value = -100;
    uint64_t unsigned_trick = *((uint64_t*)&negative_value);
    
    printf("      Signed value:   %ld\n", negative_value);
    printf("      As unsigned:    %lu\n", unsigned_trick);
    printf("      (This is 2^64 - 100 due to two's complement)\n");
    
    lactx_tx_init(&tx_negative, 1, 1);
    
    key in_mask, out_mask;
    uint64_t v_in = 500;
    uint64_t v_out = unsigned_trick;  // Negative as unsigned
    
    lactx_key_copy(in_mask, mask);
    lactx_coin_copy(&tx_negative.in[0], &tx_mint.out[0]);
    
    int create_result = lactx_header_create(&store.ctx, &tx_negative.header,
                                            1, tx_negative.out, &out_mask, &v_out,
                                            1, tx_negative.in, &in_mask, &v_in);
    
    if (create_result == 1) {
        printf("      Header creation: SUCCESS\n");
        
        int verify_result = lactx_tx_verify(&store, &tx_negative);
        if (verify_result == 1) {
            print_critical("Negative amount bypassed range proof!");
        } else {
            print_safe("Range proof detected negative value");
        }
    } else {
        print_safe("Creation prevented negative value");
    }
    
    lactx_tx_free(&tx_mint);
    lactx_tx_free(&tx_negative);
    lactx_drop_store(&store);
    remove("test_negative.db");
}

//============================================================================
// TEST 2: Negative via Subtraction
//============================================================================
void test_negative_subtraction() {
    print_test("Negative via Subtraction: Input - large output = negative");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask;
    ctx_t tx_mint, tx_negative;
    
    printf("  [1] Setup: Minting 100 coins...\n");
    store = lactx_get_store(seed, "test_subtract.db");
    
    lactx_tx_init(&tx_mint, 2, 1);
    lactx_mint_tx_create(&store, &tx_mint, mask, 100);
    lactx_tx_aggregate(&store, &tx_mint);
    
    printf("\n  [2] Transaction: 100 input → 200 + (-100) outputs\n");
    printf("      If verification only checks sum, -100 might pass\n");
    
    lactx_tx_init(&tx_negative, 2, 1);
    
    key in_mask, out_mask[2];
    uint64_t v_in = 100;
    uint64_t v_out[2] = {200, UINT64_MAX - 99};  // Second is effectively -100
    
    lactx_key_copy(in_mask, mask);
    lactx_coin_copy(&tx_negative.in[0], &tx_mint.out[0]);
    
    printf("      Output 1: 200\n");
    printf("      Output 2: %lu (wraps to negative)\n", v_out[1]);
    
    int create_result = lactx_header_create(&store.ctx, &tx_negative.header,
                                            2, tx_negative.out, out_mask, v_out,
                                            1, tx_negative.in, &in_mask, &v_in);
    
    if (create_result == 1) {
        int verify_result = lactx_tx_verify(&store, &tx_negative);
        if (verify_result == 1) {
            print_critical("Negative via subtraction possible!");
        } else {
            print_safe("Range proofs prevented negative subtraction");
        }
    } else {
        print_safe("Creation prevented negative subtraction");
    }
    
    lactx_tx_free(&tx_mint);
    lactx_tx_free(&tx_negative);
    lactx_drop_store(&store);
    remove("test_subtract.db");
}

//============================================================================
// TEST 3: Zero and Near-Zero Values
//============================================================================
void test_zero_values() {
    print_test("Zero Values: Testing boundary at 0");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask;
    ctx_t tx_mint, tx_zero;
    
    printf("  [1] Setup: Minting 100 coins...\n");
    store = lactx_get_store(seed, "test_zero.db");
    
    lactx_tx_init(&tx_mint, 2, 1);
    lactx_mint_tx_create(&store, &tx_mint, mask, 100);
    lactx_tx_aggregate(&store, &tx_mint);
    
    printf("\n  [2] Testing zero-value output...\n");
    
    lactx_tx_init(&tx_zero, 2, 1);
    
    key in_mask, out_mask[2];
    uint64_t v_in = 100;
    uint64_t v_out[2] = {100, 0};  // One output is zero
    
    lactx_key_copy(in_mask, mask);
    lactx_coin_copy(&tx_zero.in[0], &tx_mint.out[0]);
    
    int create_result = lactx_header_create(&store.ctx, &tx_zero.header,
                                            2, tx_zero.out, out_mask, v_out,
                                            1, tx_zero.in, &in_mask, &v_in);
    
    if (create_result == 1) {
        int verify_result = lactx_tx_verify(&store, &tx_zero);
        if (verify_result == 1) {
            printf("      Zero-value outputs are ALLOWED\n");
            printf("      (This may or may not be intentional)\n");
        } else {
            printf("      Zero-value outputs are REJECTED\n");
        }
    }
    
    lactx_tx_free(&tx_mint);
    lactx_tx_free(&tx_zero);
    lactx_drop_store(&store);
    remove("test_zero.db");
}

//============================================================================
// TEST 4: UINT64_MAX Boundary
//============================================================================
void test_max_boundary() {
    print_test("Max Boundary: Testing UINT64_MAX and UINT64_MAX+1");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask;
    ctx_t tx_mint;
    
    printf("  [1] Attempting to mint coin with UINT64_MAX...\n");
    store = lactx_get_store(seed, "test_max.db");
    
    lactx_tx_init(&tx_mint, 2, 1);
    
    // Try to mint maximum possible value
    uint64_t max_value = UINT64_MAX;
    printf("      Value: %lu (UINT64_MAX)\n", max_value);
    
    lactx_mint_tx_create(&store, &tx_mint, mask, max_value);
    int mint_result = 0;
    if (mint_result == 0) {
        int verify_result = lactx_tx_verify(&store, &tx_mint);
        if (verify_result == 1) {
            printf("      MAX value accepted\n");
            printf("      Testing MAX + 1 (wraps to 0)...\n");
            
            // This should fail as it wraps
            ctx_t tx_wrap;
            lactx_tx_init(&tx_wrap, 2, 1);
            uint64_t wrap_value = max_value + 1;  // Wraps to 0
            
            lactx_mint_tx_create(&store, &tx_wrap, mask, wrap_value);
            int wrap_verify = lactx_tx_verify(&store, &tx_wrap);
            
            if (wrap_verify == 1) {
                print_critical("Overflow wrapping not detected!");
            } else {
                print_safe("Overflow wrapping detected");
            }
            
            lactx_tx_free(&tx_wrap);
        }
    } else {
        printf("      MAX value rejected (conservative approach)\n");
    }
    
    lactx_tx_free(&tx_mint);
    lactx_drop_store(&store);
    remove("test_max.db");
}

//============================================================================
// TEST 5: Type Confusion Attack
//============================================================================
void test_type_confusion() {
    print_test("Type Confusion: Mixing signed/unsigned types");
    
    printf("  [1] Testing if API accepts signed integers...\n");
    
    // This is more of a theoretical test
    // In C, we can cast signed to unsigned
    
    int64_t signed_values[] = {-1, -100, -1000, INT64_MIN};
    
    for (int i = 0; i < 4; i++) {
        int64_t signed_val = signed_values[i];
        uint64_t unsigned_val = (uint64_t)signed_val;
        
        printf("\n      Signed: %ld\n", signed_val);
        printf("      Cast to unsigned: %lu\n", unsigned_val);
        
        if (unsigned_val > (UINT64_MAX / 2)) {
            printf("      → Would be interpreted as large positive number\n");
            printf("      → Range proof should catch this\n");
        }
    }
    
    printf("\n  [2] If range proofs don't check upper bound properly,\n");
    printf("      these large values might pass verification.\n");
}

//============================================================================
// MAIN
//============================================================================
int main() {
    print_header("LACT+ NEGATIVE AMOUNT ATTACK TESTS");
    
    printf("\n" MAGENTA "This test suite checks if LACT+ range proofs prevent negative amounts." RESET "\n");
    printf(MAGENTA "Negative amounts could allow creating money or breaking balance." RESET "\n");
    
    test_direct_negative();
    test_negative_subtraction();
    test_zero_values();
    test_max_boundary();
    test_type_confusion();
    
    print_header("SUMMARY");
    printf("\n");
    printf("Expected behavior (secure system):\n");
    printf("  ✓ Range proofs must enforce 0 ≤ value < MAX\n");
    printf("  ✓ Negative values should be rejected\n");
    printf("  ✓ Type casting should not bypass checks\n");
    printf("\n");
    printf("If negative amounts pass verification:\n");
    printf("  → CRITICAL: Range proof is broken\n");
    printf("  → Inflation attacks become possible\n");
    printf("\n");
    
    return 0;
}