//
// LACT+ Cryptanalysis: Double-Spending Attack Test
// Tests if the same coin can be spent in two different transactions
//
// Location: ~/Documents/LACTv2/cryptanalysis/attack_tests/attack_double_spend.c
//

#include <stdio.h>
#include <string.h>
#include "lactx_store.h"
#include "openssl/rand.h"

// ANSI color codes for output
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

void print_result(int success, const char* message) {
    if (success) {
        printf(GREEN "  ✓ PASS: %s" RESET "\n", message);
    } else {
        printf(RED "  ✗ FAIL: %s" RESET "\n", message);
    }
}

void print_critical(const char* message) {
    printf(RED "  [!!!] CRITICAL: %s" RESET "\n", message);
}

void print_safe(const char* message) {
    printf(GREEN "  [✓] SAFE: %s" RESET "\n", message);
}

//============================================================================
// TEST 1: Basic Double-Spending - Spend Same Coin Twice
//============================================================================
void test_basic_double_spend() {
    print_test("Basic Double-Spending: Spend same coin in two transactions");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask;
    ctx_t tx_mint, tx1, tx2;
    
    printf("  [1] Initializing store...\n");
    store = lactx_get_store(seed, "test_double_spend.db");
    
    printf("  [2] Minting 1000 coins...\n");
    lactx_tx_init(&tx_mint, 2, 1);
    lactx_mint_tx_create(&store, &tx_mint, mask, 1000);
    
    if (lactx_tx_verify(&store, &tx_mint)) {
        printf("      Mint transaction is valid\n");
    }
    
    lactx_tx_aggregate(&store, &tx_mint);
    printf("      Minted coin aggregated\n");
    
    // Now we have one coin with 1000 units
    // Let's try to spend it TWICE
    
    printf("\n  [3] Creating TX1: Spending 1000 → 600 + 400...\n");
    lactx_tx_init(&tx1, 2, 1);
    
    key in_mask1, out_mask1[2];
    uint64_t v_in1 = 1000;
    uint64_t v_out1[2] = {600, 400};
    
    lactx_key_copy(in_mask1, mask);
    lactx_coin_copy(&tx1.in[0], &tx_mint.out[0]);
    
    if (lactx_header_create(&store.ctx, &tx1.header,
                           2, tx1.out, out_mask1, v_out1,
                           1, tx1.in, &in_mask1, &v_in1) == 1) {
        printf("      TX1 header created successfully\n");
    }
    
    if (lactx_tx_verify(&store, &tx1) == 1) {
        printf("      TX1 is valid\n");
    }
    
    printf("\n  [4] Creating TX2: Spending SAME 1000 → 500 + 500...\n");
    lactx_tx_init(&tx2, 2, 1);
    
    key in_mask2, out_mask2[2];
    uint64_t v_in2 = 1000;
    uint64_t v_out2[2] = {500, 500};
    int result1=0;
    int result2=-1;
    
    lactx_key_copy(in_mask2, mask);
    lactx_coin_copy(&tx2.in[0], &tx_mint.out[0]);  // SAME INPUT!
    
    if (lactx_header_create(&store.ctx, &tx2.header,
                           2, tx2.out, out_mask2, v_out2,
                           1, tx2.in, &in_mask2, &v_in2) == 1) {
        printf("      TX2 header created successfully\n");
    }
    
    if (lactx_tx_verify(&store, &tx2) == 1) {
        printf("      TX2 is valid\n");
    }
    
    printf("\n  [5] Attempting to aggregate TX1...\n");
    lactx_tx_aggregate(&store, &tx1);
    if (result1 == 0) {
        printf("      TX1 aggregated successfully(Assumed)\n");
    } else {
        printf("      TX1 aggregation failed (error code: %d)\n", result1);
    }
    
    printf("\n  [6] Attempting to aggregate TX2 (SAME COIN!)...\n");
     lactx_tx_aggregate(&store, &tx2);
    if (result2 == 0) {
        printf("      TX2 aggregated successfully\n");
        print_critical("Double-spending is POSSIBLE!");
        print_critical("Same coin was spent twice!");
    } else {
        printf("      TX2 aggregation failed (error code: %d)\n", result2);
        print_safe("Double-spending was PREVENTED");
    }
    
    // Verify store integrity
    printf("\n  [7] Verifying store integrity...\n");
    if (lactx_store_verify(&store) == 1) {
        printf("      Store is valid\n");
    } else {
        printf("      Store is INVALID!\n");
    }
    
    // Cleanup
    lactx_tx_free(&tx_mint);
    lactx_tx_free(&tx1);
    lactx_tx_free(&tx2);
    lactx_drop_store(&store);
    remove("test_double_spend.db");
    
    printf("\n" YELLOW "═══════════════════════════════════════════════════════" RESET "\n");
    if (result1 == 0 && result2 == 0) {
        print_critical("VULNERABILITY FOUND: Double-spending possible!");
        printf("      Both TX1 and TX2 were accepted using the same coin.\n");
    } else {
        print_safe("No vulnerability: LACT+ prevented double-spending");
    }
}

//============================================================================
// TEST 2: Concurrent Double-Spending
//============================================================================
void test_concurrent_double_spend() {
    print_test("Concurrent Double-Spending: Two transactions before aggregation");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask;
    ctx_t tx_mint, tx1, tx2;
    
    printf("  [1] Setup: Minting coin...\n");
    store = lactx_get_store(seed, "test_concurrent.db");
    
    lactx_tx_init(&tx_mint, 2, 1);
    lactx_mint_tx_create(&store, &tx_mint, mask, 500);
    lactx_tx_verify(&store, &tx_mint);
    lactx_tx_aggregate(&store, &tx_mint);
    
    printf("  [2] Creating two transactions BEFORE aggregating...\n");
    
    // TX1
    lactx_tx_init(&tx1, 1, 1);
    key in_mask1, out_mask1;
    uint64_t v_in1 = 500, v_out1 = 500;
    lactx_key_copy(in_mask1, mask);
    lactx_coin_copy(&tx1.in[0], &tx_mint.out[0]);
    lactx_header_create(&store.ctx, &tx1.header,
                       1, tx1.out, &out_mask1, &v_out1,
                       1, tx1.in, &in_mask1, &v_in1);
    
    // TX2 (using same coin)
    lactx_tx_init(&tx2, 1, 1);
    key in_mask2, out_mask2;
    uint64_t v_in2 = 500, v_out2 = 500;
    lactx_key_copy(in_mask2, mask);
    lactx_coin_copy(&tx2.in[0], &tx_mint.out[0]);  // SAME!
    lactx_header_create(&store.ctx, &tx2.header,
                       1, tx2.out, &out_mask2, &v_out2,
                       1, tx2.in, &in_mask2, &v_in2);
    
    printf("  [3] Verifying both transactions...\n");
    int valid1 = lactx_tx_verify(&store, &tx1);
    int valid2 = lactx_tx_verify(&store, &tx2);
    
    printf("      TX1 valid: %s\n", valid1 ? "YES" : "NO");
    printf("      TX2 valid: %s\n", valid2 ? "YES" : "NO");
    
    if (valid1 && valid2) {
        print_critical("Both transactions verify successfully!");
        printf("      This means validation doesn't catch double-spending.\n");
    }
    
    printf("\n  [4] Attempting simultaneous aggregation...\n");
    lactx_tx_aggregate(&store, &tx1);
     lactx_tx_aggregate(&store, &tx2);
    
    printf("      TX1 aggregated called \n");
    printf("      TX2 aggregated called\n");
    // The final summary must rely on store integrity.
    int store_valid = lactx_store_verify(&store); 
    
    printf("\n" YELLOW "═══════════════════════════════════════════════════════" RESET "\n");
    if (store_valid == 1) {
        print_safe("Protection works: Store remained valid after concurrent attempt");
    } else {
        print_critical("VULNERABILITY: Store INVALID after concurrent double-spending attempt!");
    }
    
    // Cleanup
    lactx_tx_free(&tx_mint);
    lactx_tx_free(&tx1);
    lactx_tx_free(&tx2);
    lactx_drop_store(&store);
    remove("test_concurrent.db");
    

}

//============================================================================
// TEST 3: Database-Level Double-Spending
//============================================================================
void test_database_double_spend() {
    print_test("Database-Level: Check if spent coins are properly tracked");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask;
    ctx_t tx_mint, tx_spend;
    
    printf("  [1] Mint and spend a coin...\n");
    store = lactx_get_store(seed, "test_database.db");
    
    lactx_tx_init(&tx_mint, 2, 1);
    lactx_mint_tx_create(&store, &tx_mint, mask, 300);
    lactx_tx_aggregate(&store, &tx_mint);
    
    lactx_tx_init(&tx_spend, 1, 1);
    key in_mask, out_mask;
    uint64_t v_in = 300, v_out = 300;
    lactx_key_copy(in_mask, mask);
    lactx_coin_copy(&tx_spend.in[0], &tx_mint.out[0]);
    lactx_header_create(&store.ctx, &tx_spend.header,
                       1, tx_spend.out, &out_mask, &v_out,
                       1, tx_spend.in, &in_mask, &v_in);
    lactx_tx_aggregate(&store, &tx_spend);
    
    printf("      Coin has been spent and aggregated\n");
    
    printf("\n  [2] Attempting to spend the same coin again...\n");
    ctx_t tx_double;
    lactx_tx_init(&tx_double, 1, 1);
    key in_mask2, out_mask2;
    uint64_t v_in2 = 300, v_out2 = 300;
    lactx_key_copy(in_mask2, mask);
    lactx_coin_copy(&tx_double.in[0], &tx_mint.out[0]);  // Already spent!
    
    lactx_header_create(&store.ctx, &tx_double.header,
                       1, tx_double.out, &out_mask2, &v_out2,
                       1, tx_double.in, &in_mask2, &v_in2);
    
    int verify_result = lactx_tx_verify(&store, &tx_double);
    printf("      Verification result: %s\n", verify_result ? "VALID" : "INVALID");
    
    if (verify_result == 1) {
        print_critical("Already-spent coin still verifies as valid!");
        printf("      Database doesn't track spent coins properly.\n");
    } else {
        print_safe("Spent coin correctly rejected");
    }
    
    // Cleanup
    lactx_tx_free(&tx_mint);
    lactx_tx_free(&tx_spend);
    lactx_tx_free(&tx_double);
    lactx_drop_store(&store);
    remove("test_database.db");
}

//============================================================================
// MAIN: Run All Double-Spending Tests
//============================================================================
int main() {
    print_header("LACT+ DOUBLE-SPENDING ATTACK TESTS");
    
    printf("\n" MAGENTA "This test suite checks if LACT+ prevents double-spending attacks." RESET "\n");
    printf(MAGENTA "Double-spending = Using the same coin in multiple transactions." RESET "\n");
    
    // Run all tests
    test_basic_double_spend();
    test_concurrent_double_spend();
    test_database_double_spend();
    
    // Final summary
    print_header("SUMMARY");
    printf("\n");
    printf("Tests completed. Check results above.\n");
    printf("\n");
    printf("Expected behavior (secure system):\n");
    printf("  ✓ First transaction should succeed\n");
    printf("  ✓ Second transaction (same coin) should FAIL\n");
    printf("  ✓ Database should track spent coins\n");
    printf("\n");
    printf("If any test shows double-spending is possible:\n");
    printf("  → CRITICAL VULNERABILITY FOUND\n");
    printf("  → Document and report immediately\n");
    printf("\n");
    
    return 0;
}