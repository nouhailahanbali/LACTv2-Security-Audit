/****************************************************************************
 *  Activity-Proof Consensus Locking (APCL)
 *  Solution for Concurrent Double-Spending in LACT+
 *
 *  Author: Nouhaila HANBALI
 *  Date:   2026-03-18
 *
 *  This module implements APCL as described in:
 *  "Securing Lattice-Based Confidential Transactions Against
 *   Concurrent Double-Spending"
 *
 *  APCL augments LACT+ by inserting a consensus-aware locking phase
 *  between verification and aggregation. The key mechanisms are:
 *
 *    1. Sequence numbers bound to each UTXO coin (via coin.x2 identity)
 *    2. Extended activity proof Δ_APCL that encodes sequence info
 *    3. Atomic compare-and-swap lock acquisition on input coins
 *    4. Lock-aware consensus filtering (only locked TXs enter BFT)
 *    5. Sequence increment + lock finalization on aggregation
 *
 *  This prevents concurrent double-spending without altering any
 *  cryptographic assumption or privacy property of LACT+.
 *****************************************************************************/

#ifndef APCL_H
#define APCL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include "../include/lactx_store.h"

/* -------------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------- */

#define APCL_LOCK_ID_BYTES   ORIGAMI_HASH_BYTES   /* 49 bytes, same as Δ */
#define APCL_MAX_COINS       (MAX_ADDITIONS * 2)  /* max coins in a lock scope */
#define APCL_LOCK_TIMEOUT_MS 5000                 /* lock TTL in milliseconds */

/* -------------------------------------------------------------------------
 * Lock status enum
 * ---------------------------------------------------------------------- */
typedef enum {
    APCL_AVAILABLE  = 0,
    APCL_LOCKED     = 1,
    APCL_FINALIZED  = 2
} apcl_lock_status_t;

/* -------------------------------------------------------------------------
 * Per-coin lock record
 * ---------------------------------------------------------------------- */
typedef struct {
    uint8_t             coin_id[SEED_BYTES];           /* coin.x2 identity */
    apcl_lock_status_t  status;                        /* current lock state */
    uint8_t             lock_id[APCL_LOCK_ID_BYTES];  /* owning TX lock id  */
    uint64_t            timestamp_ms;                  /* acquisition time   */
    uint64_t            sequence;                      /* current seq number */
} apcl_coin_lock_t;

/* -------------------------------------------------------------------------
 * Global lock table
 * Wraps a flat array of coin locks protected by a single mutex.
 * In production this would be a distributed log; here we use a shared
 * in-process table to validate the algorithm.
 * ---------------------------------------------------------------------- */
typedef struct {
    apcl_coin_lock_t *entries;
    size_t            capacity;
    size_t            count;
    pthread_mutex_t   mutex;
} apcl_lock_table_t;

/* -------------------------------------------------------------------------
 * Per-transaction APCL metadata (added alongside the existing ctx_t)
 * ---------------------------------------------------------------------- */
typedef struct {
    uint8_t  lock_id[APCL_LOCK_ID_BYTES];  /* ComputeLockID result          */
    uint64_t claimed_seq[MAX_ADDITIONS];    /* sequence numbers per input    */
    int      n_inputs;                      /* number of inputs this TX has  */
    int      locks_acquired;               /* flag: set after Acquire_Lock   */
} apcl_tx_meta_t;

/* =========================================================================
 * Public API
 * ====================================================================== */

/**
 * apcl_lock_table_init  –  Initialise a global lock table.
 * @param table      pointer to an apcl_lock_table_t to initialise
 * @param capacity   maximum number of coin locks supported
 * @return 0 on success, -1 on allocation failure
 */
int apcl_lock_table_init(apcl_lock_table_t *table, size_t capacity);

/**
 * apcl_lock_table_free  –  Release resources held by a lock table.
 */
void apcl_lock_table_free(apcl_lock_table_t *table);

/**
 * apcl_coin_register  –  Register a new coin in the lock table (seq = 0).
 * Called when a coin is first created / added to the UTXO set.
 * @return 0 on success, -1 if table is full or coin already exists
 */
int apcl_coin_register(apcl_lock_table_t *table, const coin_t *coin);

/**
 * apcl_coin_deregister  –  Remove a coin from the lock table after spending.
 * @return 0 on success, -1 if not found
 */
int apcl_coin_deregister(apcl_lock_table_t *table, const coin_t *coin);

/**
 * apcl_get_sequence  –  Read the current sequence number for a coin.
 * @param[out] seq   filled with the sequence number on success
 * @return 0 on success, -1 if coin not found
 */
int apcl_get_sequence(apcl_lock_table_t *table,
                      const coin_t      *coin,
                      uint64_t          *seq);

/**
 * apcl_compute_lock_id  –  Derive the lock identifier for a transaction.
 * lock_id = SHA384(Δ_APCL || coin_id_0 || ... || coin_id_{n-1})
 * (truncated / padded to APCL_LOCK_ID_BYTES)
 *
 * @param[out] lock_id   output buffer of size APCL_LOCK_ID_BYTES
 * @param[in]  delta     activity proof bytes (ORIGAMI_HASH_BYTES)
 * @param[in]  inputs    input coins
 * @param[in]  n_inputs  number of inputs
 */
void apcl_compute_lock_id(uint8_t          lock_id[APCL_LOCK_ID_BYTES],
                           const uint8_t    delta[ORIGAMI_HASH_BYTES],
                           const coin_t    *inputs,
                           int              n_inputs);

/**
 * apcl_prepare_tx_meta  –  Snapshot current sequence numbers and compute
 * the lock_id for the given transaction.  Must be called right before
 * APCL_Verify so that the claimed sequences are fresh.
 *
 * @return 0 on success, -1 if any input coin is not found in the table
 */
int apcl_prepare_tx_meta(apcl_lock_table_t *table,
                          const ctx_t        *tx,
                          apcl_tx_meta_t     *meta);

/**
 * apcl_verify  –  Algorithm 3: APCL-Enhanced Verification.
 *
 * Performs the standard LACT+ cryptographic checks (delegated to
 * lactx_tx_verify) then additionally:
 *   - checks that each input coin is in the UTXO set
 *   - verifies claimed_seq == current_seq for each input
 *   - verifies no input coin is locked by a different TX
 *
 * @param store   LACT+ store (provides UTXO view and ctx)
 * @param tx      transaction to verify
 * @param table   global lock table
 * @param meta    pre-computed metadata (from apcl_prepare_tx_meta)
 * @return 1 if VALID, 0 if INVALID
 */
int apcl_verify(store_t            *store,
                ctx_t              *tx,
                apcl_lock_table_t  *table,
                apcl_tx_meta_t     *meta);

/**
 * apcl_acquire_lock  –  Algorithm 4: Consensus Lock Acquisition.
 *
 * Atomically transitions all input coins from AVAILABLE → LOCKED.
 * If any coin is already locked by another TX the whole operation is
 * rolled back (all-or-nothing).
 *
 * @return 1 on SUCCESS, 0 on FAILURE (conflict detected)
 */
int apcl_acquire_lock(apcl_lock_table_t *table,
                      const ctx_t        *tx,
                      apcl_tx_meta_t     *meta);

/**
 * apcl_consensus_filter  –  Algorithm 5: Lock-Aware Consensus.
 *
 * Given a list of pending transactions, returns only those whose input
 * coins are all still locked under the expected lock_id.
 * The caller then runs BFT consensus on the filtered set.
 *
 * @param table            global lock table
 * @param pending_txs      array of pending ctx_t pointers
 * @param pending_metas    array of corresponding apcl_tx_meta_t pointers
 * @param n_pending        number of pending transactions
 * @param[out] valid_txs   caller-allocated array; filled with valid pointers
 * @param[out] valid_metas corresponding metas for valid_txs
 * @return number of valid (consensus-eligible) transactions
 */
int apcl_consensus_filter(apcl_lock_table_t  *table,
                           ctx_t             **pending_txs,
                           apcl_tx_meta_t    **pending_metas,
                           int                 n_pending,
                           ctx_t             **valid_txs,
                           apcl_tx_meta_t    **valid_metas);

/**
 * apcl_aggregate  –  Algorithm 6: Lock-Aware Aggregation.
 *
 * Wraps lactx_tx_aggregate and additionally:
 *   - increments sequence numbers for consumed inputs
 *   - marks their locks as FINALIZED
 *   - registers new output coins in the lock table
 *
 * @return 1 on success, 0 if lock state is inconsistent (double-spend caught)
 */
int apcl_aggregate(store_t            *store,
                   ctx_t              *tx,
                   apcl_lock_table_t  *table,
                   apcl_tx_meta_t     *meta);

/**
 * apcl_release_lock  –  Release locks held by a transaction that was
 * rejected by consensus (allows another TX to attempt the coins).
 */
void apcl_release_lock(apcl_lock_table_t *table,
                       const ctx_t        *tx,
                       apcl_tx_meta_t     *meta);

/**
 * apcl_expire_stale_locks  –  Sweep the lock table and release any lock
 * whose timestamp has exceeded APCL_LOCK_TIMEOUT_MS.
 * Call periodically from a background thread or before each verify round.
 */
void apcl_expire_stale_locks(apcl_lock_table_t *table);

/**
 * apcl_mint_register  –  Convenience wrapper: register all output coins
 * produced by a minting transaction in the lock table.
 * Must be called after a successful mint + lactx_tx_aggregate so that
 * future spends of those coins can be locked.
 *
 * @return 0 on success, -1 on any error
 */
int apcl_mint_register(apcl_lock_table_t *table, const ctx_t *tx);

#ifdef __cplusplus
}
#endif

#endif /* APCL_H */
