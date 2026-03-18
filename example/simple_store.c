//
// Created by jayamine on 12/11/21.
// Modified with performance metrics for cryptanalysis
//
#include <stdio.h>
#include "lactx_store.h"
#include "openssl/rand.h"
#include <time.h>
#include <sys/time.h>

// ========== PERFORMANCE MEASUREMENT FUNCTIONS ==========
// These go OUTSIDE main() function

// Get current time in milliseconds
double get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000.0) + (tv.tv_usec / 1000.0);
}

// Structure to store metrics for each transaction
typedef struct {
    double creation_ms;
    double verification_ms;
    double aggregation_ms;
    double total_ms;
    size_t total_size_bytes;
} perf_metrics_t;

// Print metrics for a transaction
void print_tx_metrics(const char* tx_name, perf_metrics_t* m, int num_inputs, int num_outputs) {
    printf("\n========== %s METRICS ==========\n", tx_name);
    printf("  Timing:\n");
    printf("    Creation:     %.3f ms\n", m->creation_ms);
    printf("    Verification: %.3f ms\n", m->verification_ms);
    printf("    Aggregation:  %.3f ms\n", m->aggregation_ms);
    printf("    Total:        %.3f ms\n", m->total_ms);
    printf("    TPS:          %.2f tx/sec\n", 1000.0 / m->total_ms);
    printf("  Size:\n");
    printf("    Total TX:     %zu bytes (%.2f KB)\n", m->total_size_bytes, m->total_size_bytes / 1024.0);
    printf("    Inputs:       %d coins\n", num_inputs);
    printf("    Outputs:      %d coins\n", num_outputs);
    printf("====================================\n");
}

// Print summary of all transactions
void print_summary(perf_metrics_t metrics[], int count) {
    double total_creation = 0, total_verification = 0, total_aggregation = 0;
    double total_time = 0;
    size_t total_size = 0;
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════╗\n");
    printf("║       LACT+ PERFORMANCE SUMMARY                    ║\n");
    printf("╚════════════════════════════════════════════════════╝\n");
    
    for (int i = 0; i < count; i++) {
        total_creation += metrics[i].creation_ms;
        total_verification += metrics[i].verification_ms;
        total_aggregation += metrics[i].aggregation_ms;
        total_time += metrics[i].total_ms;
        total_size += metrics[i].total_size_bytes;
    }
    
    double avg_creation = total_creation / count;
    double avg_verification = total_verification / count;
    double avg_aggregation = total_aggregation / count;
    double avg_total = total_time / count;
    double avg_size = total_size / (double)count;
    
    printf("\n[1] AVERAGE LATENCY (per transaction)\n");
    printf("    Creation:     %.3f ms\n", avg_creation);
    printf("    Verification: %.3f ms\n", avg_verification);
    printf("    Aggregation:  %.3f ms\n", avg_aggregation);
    printf("    Total:        %.3f ms\n", avg_total);
    
    printf("\n[2] THROUGHPUT (Transactions Per Second)\n");
    printf("    Creation only:     %.2f TPS\n", 1000.0 / avg_creation);
    printf("    Verification only: %.2f TPS\n", 1000.0 / avg_verification);
    printf("    Aggregation only:  %.2f TPS\n", 1000.0 / avg_aggregation);
    printf("    Overall:           %.2f TPS\n", 1000.0 / avg_total);
    
    printf("\n[3] SIZE ANALYSIS\n");
    printf("    Average TX size:  %.2f KB\n", avg_size / 1024.0);
    printf("    Total data:       %.2f KB\n", total_size / 1024.0);
    printf("    Header size:      %zu bytes\n", sizeof(header_t));
    printf("    Coin size:        %zu bytes\n", sizeof(coin_t));
    
    printf("\n[4] SIGNATURE SIZE (from header)\n");
    printf("    Header (contains sig): %zu bytes (%.2f KB)\n", 
           sizeof(header_t), sizeof(header_t) / 1024.0);
    
    printf("\n[5] COMPARISON\n");
    printf("    Bitcoin:  ~250 bytes, ~7 TPS\n");
    printf("    Ethereum: ~110 bytes, ~15 TPS\n");
    printf("    Monero:   ~13 KB, ~1700 TPS\n");
    printf("    LACT+:    ~%.2f KB, ~%.2f TPS\n", avg_size / 1024.0, 1000.0 / avg_total);
    
    printf("\n╔════════════════════════════════════════════════════╗\n");
    printf("║  Use these metrics for your cryptanalysis         ║\n");
    printf("╚════════════════════════════════════════════════════╝\n\n");
}

// ========== END PERFORMANCE FUNCTIONS ==========

int main() {
    uint8_t seed[SEED_BYTES];
    RAND_bytes(seed, SEED_BYTES);
    coin_t in_coins[2];
    store_t store;
    key in_mask[2];
    uint64_t v_in[2] = {500, 300};
    key out_mask[3];
    uint64_t v_out[3] = {400, 400, 0};
    int i;
    
    // Array to store metrics
    perf_metrics_t all_metrics[4];
    int metric_idx = 0;
    double t_start, t_end;
    
    printf("\n╔════════════════════════════════════════════════════╗\n");
    printf("║  LACT+ ENHANCED PERFORMANCE ANALYSIS               ║\n");
    printf("╚════════════════════════════════════════════════════╝\n");
    
    // Initiate the store
    store = lactx_get_store(seed, "test_ctx.db");
    printf("\nInitial Coinbase: %ld\n", store.coinbase);
    
    // ========== TX00: Minting 1000 coins ==========
    printf("\n--- Creating TX1 (Minting 1000 coins) ---\n");
    ctx_t tx00;
    lactx_tx_init(&tx00, 2, 1);
    
    t_start = get_time_ms();
    lactx_mint_tx_create(&store, &tx00, out_mask[0], 1000);
    t_end = get_time_ms();
    all_metrics[metric_idx].creation_ms = t_end - t_start;
    printf("TX1 is created to get 1000 coins from the coinbase.\n");
    
    t_start = get_time_ms();
    int valid = lactx_tx_verify(&store, &tx00);
    t_end = get_time_ms();
    all_metrics[metric_idx].verification_ms = t_end - t_start;
    if (valid)
        printf("TX1 is valid\n");
    
    t_start = get_time_ms();
    lactx_tx_aggregate(&store, &tx00);
    t_end = get_time_ms();
    all_metrics[metric_idx].aggregation_ms = t_end - t_start;
    printf("TX1 is aggregated\n");
    
    all_metrics[metric_idx].total_ms = all_metrics[metric_idx].creation_ms + 
                                       all_metrics[metric_idx].verification_ms + 
                                       all_metrics[metric_idx].aggregation_ms;
    all_metrics[metric_idx].total_size_bytes = sizeof(header_t) + 
                                               (tx00.header.in_len + tx00.header.out_len) * sizeof(coin_t);
    print_tx_metrics("TX1", &all_metrics[metric_idx], tx00.header.in_len, tx00.header.out_len);
    metric_idx++;
    
    // ========== TX01: Minting 500 coins ==========
    printf("\n--- Creating TX2 (Minting 500 coins) ---\n");
    ctx_t tx01;
    lactx_tx_init(&tx01, 2, 1);
    
    t_start = get_time_ms();
    lactx_mint_tx_create(&store, &tx01, out_mask[0], 500);
    t_end = get_time_ms();
    all_metrics[metric_idx].creation_ms = t_end - t_start;
    printf("TX2 is created to get 500 coins from the coinbase.\n");
    
    t_start = get_time_ms();
    valid = lactx_tx_verify(&store, &tx01);
    t_end = get_time_ms();
    all_metrics[metric_idx].verification_ms = t_end - t_start;
    if (valid == 1)
        printf("TX2 is valid\n");
    
    t_start = get_time_ms();
    lactx_tx_aggregate(&store, &tx01);
    t_end = get_time_ms();
    all_metrics[metric_idx].aggregation_ms = t_end - t_start;
    printf("TX2 is aggregated\n");
    printf("Coinbase: %ld\n", store.coinbase);
    
    all_metrics[metric_idx].total_ms = all_metrics[metric_idx].creation_ms + 
                                       all_metrics[metric_idx].verification_ms + 
                                       all_metrics[metric_idx].aggregation_ms;
    all_metrics[metric_idx].total_size_bytes = sizeof(header_t) + 
                                               (tx01.header.in_len + tx01.header.out_len) * sizeof(coin_t);
    print_tx_metrics("TX2", &all_metrics[metric_idx], tx01.header.in_len, tx01.header.out_len);
    metric_idx++;
    
    // ========== TX1: First transaction (1 input, 2 outputs) ==========
    printf("\n--- Creating TX3 (1 input -> 2 outputs) ---\n");
    ctx_t tx1;
    lactx_tx_init(&tx1, 2, 1);
    
    lactx_key_copy(in_mask[0], out_mask[0]);
    v_in[0] = 500;
    v_out[0] = 100;
    v_out[1] = 400;
    lactx_coin_copy(&tx1.in[0], &tx01.out[0]);
    
    t_start = get_time_ms();
    if(lactx_header_create(&store.ctx, &tx1.header,
                          2, tx1.out, out_mask, v_out,
                          1, tx1.in, in_mask, v_in) == 1) {
        printf("TX3 is created\n");
    }
    t_end = get_time_ms();
    all_metrics[metric_idx].creation_ms = t_end - t_start;
    
    for (i = 0; i < tx1.header.in_len; i++) 
        printf("\t\tin_coin[%d] : %ld\n", i, v_in[i]);
    for (i = 0; i < tx1.header.out_len; i++) 
        printf("\t\tout_coin[%d] : %ld\n", i, v_out[i]);
    
    t_start = get_time_ms();
    valid = lactx_tx_verify(&store, &tx1);
    t_end = get_time_ms();
    all_metrics[metric_idx].verification_ms = t_end - t_start;
    if (valid == 1)
        printf("TX3 is valid\n");
    
    t_start = get_time_ms();
    lactx_tx_aggregate(&store, &tx1);
    t_end = get_time_ms();
    all_metrics[metric_idx].aggregation_ms = t_end - t_start;
    printf("TX3 is aggregated\n");
    
    all_metrics[metric_idx].total_ms = all_metrics[metric_idx].creation_ms + 
                                       all_metrics[metric_idx].verification_ms + 
                                       all_metrics[metric_idx].aggregation_ms;
    all_metrics[metric_idx].total_size_bytes = sizeof(header_t) + 
                                               (tx1.header.in_len + tx1.header.out_len) * sizeof(coin_t);
    print_tx_metrics("TX3", &all_metrics[metric_idx], tx1.header.in_len, tx1.header.out_len);
    metric_idx++;
    
    // ========== TX2: Second transaction (2 inputs, 3 outputs) ==========
    printf("\n--- Creating TX4 (2 inputs -> 3 outputs) ---\n");
    ctx_t tx2;
    lactx_tx_init(&tx2, 3, 2);
    
    lactx_key_copy(in_mask[0], out_mask[0]);
    lactx_key_copy(in_mask[1], out_mask[1]);
    v_in[0] = 100;
    v_in[1] = 400;
    v_out[0] = 200;
    v_out[1] = 100;
    v_out[2] = 200;
    tx2.in[0] = tx1.out[0];
    tx2.in[1] = tx1.out[1];
    
    t_start = get_time_ms();
    if(lactx_header_create(&store.ctx, &tx2.header,
                          3, tx2.out, out_mask, v_out,
                          2, tx2.in, in_mask, v_in) == 1) {
        printf("TX4 is created\n");
    }
    t_end = get_time_ms();
    all_metrics[metric_idx].creation_ms = t_end - t_start;
    
    for (i = 0; i < tx2.header.in_len; i++) 
        printf("\t\tin_coin[%d] : %ld\n", i, v_in[i]);
    for (i = 0; i < tx2.header.out_len; i++) 
        printf("\t\tout_coin[%d] : %ld\n", i, v_out[i]);
    
    t_start = get_time_ms();
    valid = lactx_tx_verify(&store, &tx2);
    t_end = get_time_ms();
    all_metrics[metric_idx].verification_ms = t_end - t_start;
    if (valid == 1)
        printf("TX4 is valid\n");
    
    t_start = get_time_ms();
    lactx_tx_aggregate(&store, &tx2);
    t_end = get_time_ms();
    all_metrics[metric_idx].aggregation_ms = t_end - t_start;
    printf("TX4 is aggregated\n");
    
    all_metrics[metric_idx].total_ms = all_metrics[metric_idx].creation_ms + 
                                       all_metrics[metric_idx].verification_ms + 
                                       all_metrics[metric_idx].aggregation_ms;
    all_metrics[metric_idx].total_size_bytes = sizeof(header_t) + 
                                               (tx2.header.in_len + tx2.header.out_len) * sizeof(coin_t);
    print_tx_metrics("TX4", &all_metrics[metric_idx], tx2.header.in_len, tx2.header.out_len);
    metric_idx++;
    
    // ========== Store Verification ==========
    printf("\n--- Verifying Complete Store ---\n");
    t_start = get_time_ms();
    if(lactx_store_verify(&store) == 1)
        printf("LACTx store is valid\n");
    t_end = get_time_ms();
    printf("Store verification time: %.3f ms\n", t_end - t_start);
    
    // ========== Print Summary ==========
    print_summary(all_metrics, metric_idx);
    
    // Cleanup
    lactx_tx_free(&tx00);
    lactx_tx_free(&tx01);
    lactx_tx_free(&tx1);
    lactx_tx_free(&tx2);
    lactx_drop_store(&store);
    remove("test_ctx.db");
    
    return 0;
}
