/****************************************************************************
 *  Activity-Proof Consensus Locking (APCL) – Implementation
 *
 *  Author: Nouhaila HANBALI
 *  Date:   2026-03-18
 *
 *  See apcl.h for full API documentation.
 *****************************************************************************/

#include "apcl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>

/* =========================================================================
 * Internal helpers
 * ====================================================================== */

/** Return current time in milliseconds (monotonic). */
static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

/** Find the index of a coin_lock entry by coin identity (coin.x2).
 *  Caller must hold table->mutex.
 *  Returns index >= 0 on success, -1 if not found. */
static int find_entry_locked(const apcl_lock_table_t *table,
                              const uint8_t            coin_id[SEED_BYTES])
{
    for (size_t i = 0; i < table->count; i++) {
        if (memcmp(table->entries[i].coin_id, coin_id, SEED_BYTES) == 0)
            return (int)i;
    }
    return -1;
}

/* =========================================================================
 * Initialisation / teardown
 * ====================================================================== */

int apcl_lock_table_init(apcl_lock_table_t *table, size_t capacity)
{
    if (!table || capacity == 0) return -1;

    table->entries = (apcl_coin_lock_t *)calloc(capacity, sizeof(apcl_coin_lock_t));
    if (!table->entries) return -1;

    table->capacity = capacity;
    table->count    = 0;

    if (pthread_mutex_init(&table->mutex, NULL) != 0) {
        free(table->entries);
        table->entries = NULL;
        return -1;
    }
    return 0;
}

void apcl_lock_table_free(apcl_lock_table_t *table)
{
    if (!table) return;
    pthread_mutex_lock(&table->mutex);
    free(table->entries);
    table->entries  = NULL;
    table->capacity = 0;
    table->count    = 0;
    pthread_mutex_unlock(&table->mutex);
    pthread_mutex_destroy(&table->mutex);
}

/* =========================================================================
 * Coin registration
 * ====================================================================== */

int apcl_coin_register(apcl_lock_table_t *table, const coin_t *coin)
{
    if (!table || !coin) return -1;

    pthread_mutex_lock(&table->mutex);

    /* Minting coins use coin->s to identify themselves; normal coins use x2.
     * We always use x2 for normal coins; for minting coins we derive an id
     * from the s field packed into x2-sized bytes. */
    uint8_t cid[SEED_BYTES];
    if (coin->s != 0) {
        /* Pack s into first 8 bytes of cid, rest zero */
        memset(cid, 0, SEED_BYTES);
        memcpy(cid, &coin->s, sizeof(uint64_t));
    } else {
        memcpy(cid, coin->x2, SEED_BYTES);
    }

    /* Already registered? */
    if (find_entry_locked(table, cid) >= 0) {
        pthread_mutex_unlock(&table->mutex);
        return 0; /* idempotent */
    }

    if (table->count >= table->capacity) {
        pthread_mutex_unlock(&table->mutex);
        fprintf(stderr, "[APCL] lock table full (capacity=%zu)\n", table->capacity);
        return -1;
    }

    apcl_coin_lock_t *e = &table->entries[table->count++];
    memcpy(e->coin_id, cid, SEED_BYTES);
    e->status       = APCL_AVAILABLE;
    e->timestamp_ms = 0;
    e->sequence     = 0;
    memset(e->lock_id, 0, APCL_LOCK_ID_BYTES);

    pthread_mutex_unlock(&table->mutex);
    return 0;
}

int apcl_coin_deregister(apcl_lock_table_t *table, const coin_t *coin)
{
    if (!table || !coin) return -1;

    uint8_t cid[SEED_BYTES];
    if (coin->s != 0) {
        memset(cid, 0, SEED_BYTES);
        memcpy(cid, &coin->s, sizeof(uint64_t));
    } else {
        memcpy(cid, coin->x2, SEED_BYTES);
    }

    pthread_mutex_lock(&table->mutex);
    int idx = find_entry_locked(table, cid);
    if (idx < 0) {
        pthread_mutex_unlock(&table->mutex);
        return -1;
    }
    /* Swap with last entry to keep array compact */
    if ((size_t)idx != table->count - 1)
        table->entries[idx] = table->entries[table->count - 1];
    table->count--;
    pthread_mutex_unlock(&table->mutex);
    return 0;
}

int apcl_get_sequence(apcl_lock_table_t *table,
                      const coin_t      *coin,
                      uint64_t          *seq)
{
    if (!table || !coin || !seq) return -1;

    uint8_t cid[SEED_BYTES];
    if (coin->s != 0) {
        memset(cid, 0, SEED_BYTES);
        memcpy(cid, &coin->s, sizeof(uint64_t));
    } else {
        memcpy(cid, coin->x2, SEED_BYTES);
    }

    pthread_mutex_lock(&table->mutex);
    int idx = find_entry_locked(table, cid);
    if (idx < 0) {
        pthread_mutex_unlock(&table->mutex);
        return -1;
    }
    *seq = table->entries[idx].sequence;
    pthread_mutex_unlock(&table->mutex);
    return 0;
}

/* =========================================================================
 * Lock-ID derivation  (ComputeLockID)
 * ====================================================================== */

void apcl_compute_lock_id(uint8_t          lock_id[APCL_LOCK_ID_BYTES],
                           const uint8_t    delta[ORIGAMI_HASH_BYTES],
                           const coin_t    *inputs,
                           int              n_inputs)
{
    /* lock_id = SHA384(delta || x2_0 || x2_1 || ...) padded to LOCK_ID_BYTES */
    SHA512_CTX ctx;
    uint8_t digest[48]; /* SHA-384 output */

    SHA384_Init(&ctx);
    SHA384_Update(&ctx, delta, ORIGAMI_HASH_BYTES);
    for (int i = 0; i < n_inputs; i++) {
        if (inputs[i].s != 0) {
            uint8_t tmp[SEED_BYTES];
            memset(tmp, 0, SEED_BYTES);
            memcpy(tmp, &inputs[i].s, sizeof(uint64_t));
            SHA384_Update(&ctx, tmp, SEED_BYTES);
        } else {
            SHA384_Update(&ctx, inputs[i].x2, SEED_BYTES);
        }
    }
    SHA384_Final(digest, &ctx);

    /* Copy as many bytes as APCL_LOCK_ID_BYTES allows */
    size_t copy_len = (sizeof(digest) < APCL_LOCK_ID_BYTES)
                      ? sizeof(digest) : APCL_LOCK_ID_BYTES;
    memcpy(lock_id, digest, copy_len);
    if (copy_len < APCL_LOCK_ID_BYTES)
        memset(lock_id + copy_len, 0, APCL_LOCK_ID_BYTES - copy_len);
}

/* =========================================================================
 * Prepare TX metadata  (snapshot sequences + compute lock_id)
 * ====================================================================== */

int apcl_prepare_tx_meta(apcl_lock_table_t *table,
                          const ctx_t        *tx,
                          apcl_tx_meta_t     *meta)
{
    if (!table || !tx || !meta) return -1;

    int n = (int)tx->header.in_len;
    if (n <= 0 || n > MAX_ADDITIONS) return -1;

    meta->n_inputs        = n;
    meta->locks_acquired  = 0;

    /* Snapshot sequence numbers */
    for (int i = 0; i < n; i++) {
        if (apcl_get_sequence(table, &tx->in[i], &meta->claimed_seq[i]) != 0) {
            fprintf(stderr, "[APCL] prepare_tx_meta: coin %d not in lock table\n", i);
            return -1;
        }
    }

    /* Compute lock_id = ComputeLockID(Δ, inputs) */
    apcl_compute_lock_id(meta->lock_id,
                          tx->header.delta,
                          tx->in,
                          n);
    return 0;
}

/* =========================================================================
 * Algorithm 3 – APCL-Enhanced Verification
 * ====================================================================== */

int apcl_verify(store_t            *store,
                ctx_t              *tx,
                apcl_lock_table_t  *table,
                apcl_tx_meta_t     *meta)
{
    /* ------------------------------------------------------------------ */
    /* Step 1: Standard LACT+ cryptographic verification                  */
    /* ------------------------------------------------------------------ */
    if (lactx_tx_verify(store, tx) != 1) {
        fprintf(stderr, "[APCL] verify: standard LACT+ verification failed\n");
        return 0;
    }

    /* ------------------------------------------------------------------ */
    /* Step 2: Sequence number check  (new in APCL)                       */
    /* ------------------------------------------------------------------ */
    pthread_mutex_lock(&table->mutex);

    int n = (int)tx->header.in_len;
    for (int i = 0; i < n; i++) {
        uint8_t cid[SEED_BYTES];
        if (tx->in[i].s != 0) {
            memset(cid, 0, SEED_BYTES);
            memcpy(cid, &tx->in[i].s, sizeof(uint64_t));
        } else {
            memcpy(cid, tx->in[i].x2, SEED_BYTES);
        }

        int idx = find_entry_locked(table, cid);
        if (idx < 0) {
            fprintf(stderr, "[APCL] verify: input coin %d not registered\n", i);
            pthread_mutex_unlock(&table->mutex);
            return 0;
        }

        /* Verify sequence: claimed_seq must equal current sequence */
        if (meta->claimed_seq[i] != table->entries[idx].sequence) {
            fprintf(stderr,
                    "[APCL] verify: sequence mismatch on coin %d "
                    "(claimed=%lu, current=%lu)\n",
                    i,
                    (unsigned long)meta->claimed_seq[i],
                    (unsigned long)table->entries[idx].sequence);
            pthread_mutex_unlock(&table->mutex);
            return 0;
        }
    }

    /* ------------------------------------------------------------------ */
    /* Step 3: Lock availability check  (new in APCL)                     */
    /* ------------------------------------------------------------------ */
    for (int i = 0; i < n; i++) {
        uint8_t cid[SEED_BYTES];
        if (tx->in[i].s != 0) {
            memset(cid, 0, SEED_BYTES);
            memcpy(cid, &tx->in[i].s, sizeof(uint64_t));
        } else {
            memcpy(cid, tx->in[i].x2, SEED_BYTES);
        }

        int idx = find_entry_locked(table, cid);
        /* idx cannot be -1 here; we already checked above */
        apcl_coin_lock_t *e = &table->entries[idx];

        if (e->status == APCL_LOCKED) {
            /* Locked by a DIFFERENT transaction? */
            if (memcmp(e->lock_id, meta->lock_id, APCL_LOCK_ID_BYTES) != 0) {
                fprintf(stderr,
                        "[APCL] verify: coin %d is locked by another TX\n", i);
                pthread_mutex_unlock(&table->mutex);
                return 0;
            }
            /* Same transaction re-verifying – allowed */
        } else if (e->status == APCL_FINALIZED) {
            /* Coin already consumed */
            fprintf(stderr,
                    "[APCL] verify: coin %d is already finalized (spent)\n", i);
            pthread_mutex_unlock(&table->mutex);
            return 0;
        }
        /* APCL_AVAILABLE – ok */
    }

    pthread_mutex_unlock(&table->mutex);
    return 1; /* VALID */
}

/* =========================================================================
 * Algorithm 4 – Consensus Lock Acquisition
 * ====================================================================== */

int apcl_acquire_lock(apcl_lock_table_t *table,
                      const ctx_t        *tx,
                      apcl_tx_meta_t     *meta)
{
    if (!table || !tx || !meta) return 0;

    int n           = (int)tx->header.in_len;
    uint64_t ts_ms  = now_ms();

    pthread_mutex_lock(&table->mutex);

    /* Collect indices first to enable atomic all-or-nothing rollback */
    int indices[MAX_ADDITIONS];
    int acquired_count = 0;

    for (int i = 0; i < n; i++) {
        uint8_t cid[SEED_BYTES];
        if (tx->in[i].s != 0) {
            memset(cid, 0, SEED_BYTES);
            memcpy(cid, &tx->in[i].s, sizeof(uint64_t));
        } else {
            memcpy(cid, tx->in[i].x2, SEED_BYTES);
        }

        int idx = find_entry_locked(table, cid);
        if (idx < 0) {
            fprintf(stderr, "[APCL] acquire_lock: coin %d not in table\n", i);
            goto rollback;
        }
        indices[i] = idx;

        apcl_coin_lock_t *e = &table->entries[idx];

        /* AtomicCompareAndSwap: AVAILABLE → LOCKED  (or same lock_id) */
        if (e->status == APCL_AVAILABLE) {
            e->status       = APCL_LOCKED;
            e->timestamp_ms = ts_ms;
            memcpy(e->lock_id, meta->lock_id, APCL_LOCK_ID_BYTES);
            acquired_count++;
        } else if (e->status == APCL_LOCKED &&
                   memcmp(e->lock_id, meta->lock_id, APCL_LOCK_ID_BYTES) == 0) {
            /* Already locked by us – idempotent */
            acquired_count++;
        } else {
            /* Locked by another TX or finalized → conflict */
            fprintf(stderr,
                    "[APCL] acquire_lock: conflict on coin %d "
                    "(status=%d)\n", i, (int)e->status);
            goto rollback;
        }
    }

    pthread_mutex_unlock(&table->mutex);
    meta->locks_acquired = 1;
    return 1; /* SUCCESS */

rollback:
    /* Roll back any locks we already set in this attempt */
    for (int j = 0; j < acquired_count; j++) {
        apcl_coin_lock_t *e = &table->entries[indices[j]];
        if (e->status == APCL_LOCKED &&
            memcmp(e->lock_id, meta->lock_id, APCL_LOCK_ID_BYTES) == 0) {
            e->status = APCL_AVAILABLE;
            memset(e->lock_id, 0, APCL_LOCK_ID_BYTES);
            e->timestamp_ms = 0;
        }
    }
    pthread_mutex_unlock(&table->mutex);
    meta->locks_acquired = 0;
    return 0; /* FAILURE */
}

/* =========================================================================
 * Algorithm 5 – Lock-Aware Consensus Filter
 * ====================================================================== */

int apcl_consensus_filter(apcl_lock_table_t  *table,
                           ctx_t             **pending_txs,
                           apcl_tx_meta_t    **pending_metas,
                           int                 n_pending,
                           ctx_t             **valid_txs,
                           apcl_tx_meta_t    **valid_metas)
{
    if (!table || !pending_txs || !pending_metas || !valid_txs || !valid_metas)
        return 0;

    int valid_count = 0;

    pthread_mutex_lock(&table->mutex);

    for (int t = 0; t < n_pending; t++) {
        ctx_t          *tx   = pending_txs[t];
        apcl_tx_meta_t *meta = pending_metas[t];
        if (!tx || !meta) continue;

        int n       = (int)tx->header.in_len;
        int all_ok  = 1;

        for (int i = 0; i < n; i++) {
            uint8_t cid[SEED_BYTES];
            if (tx->in[i].s != 0) {
                memset(cid, 0, SEED_BYTES);
                memcpy(cid, &tx->in[i].s, sizeof(uint64_t));
            } else {
                memcpy(cid, tx->in[i].x2, SEED_BYTES);
            }

            int idx = find_entry_locked(table, cid);
            if (idx < 0) { all_ok = 0; break; }

            apcl_coin_lock_t *e = &table->entries[idx];
            if (e->status != APCL_LOCKED ||
                memcmp(e->lock_id, meta->lock_id, APCL_LOCK_ID_BYTES) != 0) {
                all_ok = 0;
                break;
            }
        }

        if (all_ok) {
            valid_txs[valid_count]   = tx;
            valid_metas[valid_count] = meta;
            valid_count++;
        } else {
            fprintf(stderr,
                    "[APCL] consensus_filter: TX %d excluded "
                    "(lock check failed)\n", t);
        }
    }

    pthread_mutex_unlock(&table->mutex);
    return valid_count;
}

/* =========================================================================
 * Algorithm 6 – Lock-Aware Aggregation
 * ====================================================================== */

int apcl_aggregate(store_t            *store,
                   ctx_t              *tx,
                   apcl_lock_table_t  *table,
                   apcl_tx_meta_t     *meta)
{
    if (!store || !tx || !table || !meta) return 0;

    /* Verify locks are still held before we commit */
    int n = (int)tx->header.in_len;

    pthread_mutex_lock(&table->mutex);

    for (int i = 0; i < n; i++) {
        uint8_t cid[SEED_BYTES];
        if (tx->in[i].s != 0) {
            memset(cid, 0, SEED_BYTES);
            memcpy(cid, &tx->in[i].s, sizeof(uint64_t));
        } else {
            memcpy(cid, tx->in[i].x2, SEED_BYTES);
        }

        int idx = find_entry_locked(table, cid);
        if (idx < 0) {
            fprintf(stderr, "[APCL] aggregate: coin %d not in table\n", i);
            pthread_mutex_unlock(&table->mutex);
            return 0;
        }

        apcl_coin_lock_t *e = &table->entries[idx];
        if (e->status != APCL_LOCKED ||
            memcmp(e->lock_id, meta->lock_id, APCL_LOCK_ID_BYTES) != 0) {
            fprintf(stderr,
                    "[APCL] aggregate: coin %d lock inconsistent "
                    "(double-spend caught at aggregation!)\n", i);
            pthread_mutex_unlock(&table->mutex);
            return 0;
        }
    }

    /* ------------------------------------------------------------------ */
    /* All locks verified: now commit                                      */
    /* 1. Increment sequence numbers and mark FINALIZED for input coins   */
    /* ------------------------------------------------------------------ */
    for (int i = 0; i < n; i++) {
        uint8_t cid[SEED_BYTES];
        if (tx->in[i].s != 0) {
            memset(cid, 0, SEED_BYTES);
            memcpy(cid, &tx->in[i].s, sizeof(uint64_t));
        } else {
            memcpy(cid, tx->in[i].x2, SEED_BYTES);
        }
        int idx = find_entry_locked(table, cid);
        apcl_coin_lock_t *e = &table->entries[idx];
        e->sequence++;          /* Increment sequence – invalidates stale TXs */
        e->status = APCL_FINALIZED;
    }

    pthread_mutex_unlock(&table->mutex);

    /* ------------------------------------------------------------------ */
    /* 2. Perform the actual LACT+ aggregation                            */
    /* ------------------------------------------------------------------ */
    lactx_tx_aggregate(store, tx);

    /* ------------------------------------------------------------------ */
    /* 3. Register new output coins in the lock table (sequence = 0)      */
    /* ------------------------------------------------------------------ */
    unsigned int out_len = tx->header.out_len;
    /* For minting TXs the second output is the change-back mint coin     */
    unsigned int reg_len = out_len;
    /* Minting TXs: only the first output is a normal spendable coin      */
    if (tx->header.v_in != 0 || tx->header.v_out != 0)
        reg_len = 1;

    pthread_mutex_lock(&table->mutex);
    for (unsigned int i = 0; i < reg_len; i++) {
        uint8_t cid[SEED_BYTES];
        memcpy(cid, tx->out[i].x2, SEED_BYTES);

        /* Only register if not already present */
        if (find_entry_locked(table, cid) < 0) {
            if (table->count < table->capacity) {
                apcl_coin_lock_t *e2 = &table->entries[table->count++];
                memcpy(e2->coin_id, cid, SEED_BYTES);
                e2->status       = APCL_AVAILABLE;
                e2->sequence     = 0;
                e2->timestamp_ms = 0;
                memset(e2->lock_id, 0, APCL_LOCK_ID_BYTES);
            } else {
                fprintf(stderr, "[APCL] aggregate: lock table full, "
                        "cannot register output coin %u\n", i);
            }
        }
    }
    pthread_mutex_unlock(&table->mutex);

    return 1; /* SUCCESS */
}

/* =========================================================================
 * Auxiliary functions
 * ====================================================================== */

void apcl_release_lock(apcl_lock_table_t *table,
                       const ctx_t        *tx,
                       apcl_tx_meta_t     *meta)
{
    if (!table || !tx || !meta || !meta->locks_acquired) return;

    int n = (int)tx->header.in_len;
    pthread_mutex_lock(&table->mutex);

    for (int i = 0; i < n; i++) {
        uint8_t cid[SEED_BYTES];
        if (tx->in[i].s != 0) {
            memset(cid, 0, SEED_BYTES);
            memcpy(cid, &tx->in[i].s, sizeof(uint64_t));
        } else {
            memcpy(cid, tx->in[i].x2, SEED_BYTES);
        }

        int idx = find_entry_locked(table, cid);
        if (idx < 0) continue;

        apcl_coin_lock_t *e = &table->entries[idx];
        if (e->status == APCL_LOCKED &&
            memcmp(e->lock_id, meta->lock_id, APCL_LOCK_ID_BYTES) == 0) {
            e->status = APCL_AVAILABLE;
            memset(e->lock_id, 0, APCL_LOCK_ID_BYTES);
            e->timestamp_ms = 0;
        }
    }

    pthread_mutex_unlock(&table->mutex);
    meta->locks_acquired = 0;
}

void apcl_expire_stale_locks(apcl_lock_table_t *table)
{
    if (!table) return;

    uint64_t now = now_ms();
    pthread_mutex_lock(&table->mutex);

    for (size_t i = 0; i < table->count; i++) {
        apcl_coin_lock_t *e = &table->entries[i];
        if (e->status == APCL_LOCKED &&
            e->timestamp_ms != 0 &&
            (now - e->timestamp_ms) > APCL_LOCK_TIMEOUT_MS) {
            fprintf(stderr,
                    "[APCL] expiring stale lock (age=%lu ms)\n",
                    (unsigned long)(now - e->timestamp_ms));
            e->status = APCL_AVAILABLE;
            memset(e->lock_id, 0, APCL_LOCK_ID_BYTES);
            e->timestamp_ms = 0;
        }
    }

    pthread_mutex_unlock(&table->mutex);
}

int apcl_mint_register(apcl_lock_table_t *table, const ctx_t *tx)
{
    if (!table || !tx) return -1;
    /* Register only the first output (the real new coin; second is mint change) */
    if (tx->header.out_len < 1) return -1;
    return apcl_coin_register(table, &tx->out[0]);
}
