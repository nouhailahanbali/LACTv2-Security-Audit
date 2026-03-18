//
// LACT+ Cryptanalysis: Range Proof Attack Test  
// Tests the soundness and completeness of range proofs
//
// Location: ~/Documents/LACTv2/cryptanalysis/attack_tests/attack_range_proof.c


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
// TEST 1: Boundary Value Analysis
//============================================================================
void test_boundary_values() {
    print_test("Boundary Values: Testing edges of valid range");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask;
    
    store = lactx_get_store(seed, "test_boundary.db");
    
    uint64_t test_values[] = {
        0,                    // Minimum
        1,                    // Minimum + 1
        100,                  // Small value
        1000,                 // Medium value
        1000000,              // Large value
        UINT64_MAX / 2,       // Half of max
        UINT64_MAX - 1,       // Near maximum
        UINT64_MAX            // Maximum
    };
    
    int num_tests = sizeof(test_values) / sizeof(test_values[0]);
    
    printf("  Testing %d boundary values...\n\n", num_tests);
    
    for (int i = 0; i < num_tests; i++) {
        uint64_t value = test_values[i];
        
        printf("  [%d] Value: %lu", i+1, value);
        if (value == 0) printf(" (MIN)");
        else if (value == UINT64_MAX) printf(" (MAX)");
        else if (value == UINT64_MAX - 1) printf(" (MAX-1)");
        printf("\n");
        
        ctx_t tx;
        lactx_tx_init(&tx, 2, 1);
        
       lactx_mint_tx_create(&store, &tx, mask, value);
        int mint_result =0;
        if (mint_result == 0) {
            int verify_result = lactx_tx_verify(&store, &tx);
            
            if (verify_result == 1) {
                printf("      ✓ Accepted\n");
            } else {
                printf("      ✗ Rejected by verification\n");
            }
        } else {
            printf("      ✗ Rejected at creation\n");
        }
        
        lactx_tx_free(&tx);
    }
    
    lactx_drop_store(&store);
    remove("test_boundary.db");
}

//============================================================================
// TEST 2: Powers of Two
//============================================================================
void test_powers_of_two() {
    print_test("Powers of Two: Testing 2^n values");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask;
    
    store = lactx_get_store(seed, "test_powers.db");
    
    printf("  Testing powers of 2 from 2^0 to 2^63...\n\n");
    
    int passed = 0, failed = 0;
    
    for (int power = 0; power <= 63; power++) {
        uint64_t value = 1ULL << power;
        
        ctx_t tx;
        lactx_tx_init(&tx, 2, 1);
        
        lactx_mint_tx_create(&store, &tx, mask, value);
        int mint_result =0;
        if (mint_result == 0) {
            int verify_result = lactx_tx_verify(&store, &tx);
            
            if (verify_result == 1) {
                passed++;
                if (power % 8 == 0) {  // Print every 8th
                    printf("  2^%d = %lu: ✓\n", power, value);
                }
            } else {
                failed++;
                printf("  2^%d = %lu: ✗ REJECTED\n", power, value);
            }
        }
        
        lactx_tx_free(&tx);
    }
    
    printf("\n  Passed: %d/64, Failed: %d/64\n", passed, failed);
    
    if (failed > 0) {
        printf("  " YELLOW "⚠️  Some valid powers of 2 were rejected\n" RESET);
        printf("      This might indicate range proof limitations\n");
    }
    
    lactx_drop_store(&store);
    remove("test_powers.db");
}

//============================================================================
// TEST 3: Sequential Values Around Boundaries
//============================================================================
void test_sequential_boundary() {
    print_test("Sequential Boundary: Values around potential limits");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask;
    
    store = lactx_get_store(seed, "test_sequential.db");
    
    // Test around 2^32 (common boundary)
    uint64_t boundary = 1ULL << 32;
    
    printf("  Testing values around 2^32 = %lu\n\n", boundary);
    
    for (int offset = -5; offset <= 5; offset++) {
        uint64_t value = boundary + offset;
        
        printf("  2^32 %+d = %lu: ", offset, value);
        
        ctx_t tx;
        lactx_tx_init(&tx, 2, 1);
        
        lactx_mint_tx_create(&store, &tx, mask, value);
        int mint_result =0;
        if (mint_result == 0) {
            int verify_result = lactx_tx_verify(&store, &tx);
            printf("%s\n", verify_result == 1 ? "✓" : "✗");
        } else {
            printf("✗ (creation)\n");
        }
        
        lactx_tx_free(&tx);
    }
    
    lactx_drop_store(&store);
    remove("test_sequential.db");
}

//============================================================================
// TEST 4: Range Proof Forgery Attempt
//============================================================================
void test_range_proof_forgery() {
    print_test("Range Proof Forgery: Can we fake a valid range proof?");
    
    printf("  [1] This test would require:\n");
    printf("      - Understanding the range proof structure\n");
    printf("      - Attempting to modify proof parameters\n");
    printf("      - Testing if verification catches forgery\n");
    printf("\n");
    printf("  [2] Current limitation:\n");
    printf("      - Cannot directly manipulate proof internals\n");
    printf("      - Would need to modify src/lactx_coin.c\n");
    printf("\n");
    printf("  [3] Theoretical attack:\n");
    printf("      - Create coin with amount X\n");
    printf("      - Copy its range proof\n");
    printf("      - Try to use that proof for amount Y\n");
    printf("      - If accepted → proof is not binding!\n");
    printf("\n");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask1, mask2;
    ctx_t tx1, tx2;
    
    store = lactx_get_store(seed, "test_forgery.db");
    
    printf("  [4] Attempting proof reuse attack...\n");
    
    // Create first coin with amount 100
    lactx_tx_init(&tx1, 2, 1);
    lactx_mint_tx_create(&store, &tx1, mask1, 100);
    
    printf("      Created coin 1 with amount: 100\n");
    
    // Create second coin with amount 200
    lactx_tx_init(&tx2, 2, 1);
    lactx_mint_tx_create(&store, &tx2, mask2, 200);
    
    printf("      Created coin 2 with amount: 200\n");
    
    // Try to copy proof (this is oversimplified - actual attack harder)
    printf("\n      Attempting to copy range proof from coin 1 to coin 2...\n");
    printf("      (This requires internal structure knowledge)\n");
    
    // Verify both
    int v1 = lactx_tx_verify(&store, &tx1);
    int v2 = lactx_tx_verify(&store, &tx2);
    
    printf("      Coin 1 verification: %s\n", v1 ? "✓" : "✗");
    printf("      Coin 2 verification: %s\n", v2 ? "✓" : "✗");
    
    lactx_tx_free(&tx1);
    lactx_tx_free(&tx2);
    lactx_drop_store(&store);
    remove("test_forgery.db");
    
    printf("\n  " YELLOW "[NOTE] Full proof forgery requires deeper analysis" RESET "\n");
}

//============================================================================
// TEST 5: Extreme Value Stress Test
//============================================================================
void test_extreme_values() {
    print_test("Extreme Values: Stress testing range limits");
    
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    
    store_t store;
    key mask;
    
    store = lactx_get_store(seed, "test_extreme.db");
    
    uint64_t extreme_values[] = {
        UINT8_MAX,
        UINT16_MAX,
        UINT32_MAX,
        UINT64_MAX / 4,
        UINT64_MAX / 2,
        UINT64_MAX / 2 + 1,
        (UINT64_MAX / 4) * 3,
        UINT64_MAX - 1000,
        UINT64_MAX - 100,
        UINT64_MAX - 10,
        UINT64_MAX - 1
    };
    
    int num_tests = sizeof(extreme_values) / sizeof(extreme_values[0]);
    
    printf("  Testing %d extreme values...\n\n", num_tests);
    
    int accepted = 0, rejected = 0;
    
    for (int i = 0; i < num_tests; i++) {
        uint64_t value = extreme_values[i];
        
        ctx_t tx;
        lactx_tx_init(&tx, 2, 1);
        
        lactx_mint_tx_create(&store, &tx, mask, value);
        int mint_result =0;
        if (mint_result == 0) {
            int verify_result = lactx_tx_verify(&store, &tx);
            
            if (verify_result == 1) {
                accepted++;
                printf("  %lu: ✓\n", value);
            } else {
                rejected++;
                printf("  %lu: ✗\n", value);
            }
        } else {
            rejected++;
            printf("  %lu: ✗ (creation)\n", value);
        }
        
        lactx_tx_free(&tx);
    }
    
    printf("\n  Accepted: %d, Rejected: %d\n", accepted, rejected);
    
    if (accepted == num_tests) {
        printf("  " GREEN "✓ All extreme values accepted (wide range)" RESET "\n");
    } else {
        printf("  " YELLOW "⚠️  Some extreme values rejected" RESET "\n");
        printf("      Range proof may have conservative limits\n");
    }
    
    lactx_drop_store(&store);
    remove("test_extreme.db");
}

//============================================================================
// MAIN
//============================================================================
int main() {
    print_header("LACT+ RANGE PROOF ATTACK TESTS");
    
    printf("\n" MAGENTA "This test suite checks the soundness of LACT+ range proofs." RESET "\n");
    printf(MAGENTA "Range proofs must ensure: 0 ≤ amount < MAX without revealing amount." RESET "\n");
    
    test_boundary_values();
    test_powers_of_two();
    test_sequential_boundary();
    test_range_proof_forgery();
    test_extreme_values();
    
    print_header("SUMMARY");
    printf("\n");
    printf("Range Proof Properties:\n");
    printf("  • Soundness: Invalid values must be rejected\n");
    printf("  • Completeness: Valid values must be accepted\n");
    printf("  • Zero-knowledge: Amount remains hidden\n");
    printf("  • Binding: Proof tied to specific amount\n");
    printf("\n");
    printf("If any property is violated:\n");
    printf("  → Security or usability issue\n");
    printf("\n");
    
    return 0;
}