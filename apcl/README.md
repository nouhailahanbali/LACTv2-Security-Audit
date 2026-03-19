# APCL – Activity-Proof Consensus Locking

**Author:** Nouhaila HANBALI  
**Date:** 2026-03-18  
**Paper:** *Work in Progress *

---

## What is APCL?

**Activity-Proof Consensus Locking (APCL)** is a lightweight protocol extension for LACT+ that closes the *Verification–Aggregation Gap* — the window during which two conflicting transactions spending the same coin can both pass cryptographic verification before either is aggregated.

### The Vulnerability (without APCL)

```
LACT+ pipeline (vulnerable):
  Validator 1:  [Verify Tx_A] → VALID  ──────────────────►  [Aggregate Tx_A] OK
  Validator 2:  [Verify Tx_B] → VALID  ──►  (conflict detected too late)  ► CORRUPT
```

`lactx_tx_verify` checks coin existence with a non-atomic local read.  
Two validators can each see the same coin as "unspent" and accept conflicting transactions.

### The Fix (with APCL)

```
APCL pipeline (secure):
  [Verify Tx_A] → [Acquire Lock Tx_A] → LOCKED  → Consensus → Aggregate
  [Verify Tx_B] → [Acquire Lock Tx_B] → BLOCKED  (coin already locked)
```

Four mechanisms close the gap:

| Mechanism | Where | Guarantee |
|---|---|---|
| **Sequence numbers** | Per UTXO coin | Re-spend with old state rejected immediately |
| **Extended activity proof Δ_APCL** | Per TX | TX bound to specific UTXO version |
| **Atomic compare-and-swap lock** | Lock table | Only one TX can claim a coin before consensus |
| **Consensus filter** | Pre-BFT | Only locked TXs enter Byzantine consensus |

No cryptographic assumption is altered. All LACT+ privacy, aggregation, and post-quantum properties are preserved.

---

## Repository Layout

```
apcl/
├── apcl.h                       ← Full public API (all types + all functions)
├── apcl.c                       ← Implementation (Algorithms 3-6 from paper)
├── attack_double_spend_apcl.c   ← 3-scenario targeted demo
├── apcl_integration_tests.c     ← 10-scenario full integration test suite
├── CMakeLists_apcl.cmake        ← CMake build rules
└── README.md                    ← This file
```

---

## How to Integrate

### Step 1 – Place the `apcl/` folder in the repository root

```
LACTv2/
├── apcl/           ← paste here
├── src/
├── include/
├── CMakeLists.txt
└── ...
```

### Step 2 – Add one line to the end of `CMakeLists.txt`

```cmake
# At the very end of CMakeLists.txt:
include(apcl/CMakeLists_apcl.cmake)
```

### Step 3 – Build

```bash
mkdir -p build && cd build
cmake ..
make apcl attack_double_spend_apcl apcl_integration_tests
```

---

## Running the Tests

### Targeted demo (3 scenarios)

```bash
./attack_double_spend_apcl
```

All three scenarios should show `[APCL SAFE]`:

```
→ TEST: Basic Double-Spending with APCL
  [✓ APCL SAFE]: Double-spending BLOCKED — Tx_B rejected at lock-acquisition

→ TEST: Concurrent Double-Spending with APCL
  [✓ APCL SAFE]: Concurrent double-spending BLOCKED — only Tx_A enters consensus

→ TEST: Re-Spend After Aggregation with APCL (Sequence Check)
  [✓ APCL SAFE]: Re-spend blocked by APCL sequence check
```

### Full integration suite (10 scenarios)

```bash
./apcl_integration_tests
```

| Test | Scenario | Expected |
|---|---|---|
| T01 | Happy-path single spend | PASS |
| T02 | Basic double-spend (sequential) | PASS (blocked) |
| T03 | Concurrent race condition | PASS (blocked) |
| T04 | Re-spend via stale sequence | PASS (blocked) |
| T05 | Stale lock expiry, new TX recovers | PASS |
| T06 | Multi-input happy path | PASS |
| T07 | Multi-input partial overlap double-spend | PASS (blocked) |
| T08 | Inflation attack still blocked by LACT+ | PASS |
| T09 | Sequential chain (spend TX output) | PASS |
| T10 | Store integrity after many APCL TXs | PASS |

### Via CTest

```bash
cd build && ctest --output-on-failure
```

---

## Comparing With the Original Attack

Run the unmodified attack to see the vulnerability:
```bash
./attack_double_spend
# → [!!!] CRITICAL: Double-spending is POSSIBLE!
```

Then run APCL-protected version:
```bash
./attack_double_spend_apcl
# → [✓ APCL SAFE]: Double-spending BLOCKED
```

---

## Algorithm Reference

| Function | Paper Algorithm | Description |
|---|---|---|
| `apcl_prepare_tx_meta` | Pre-step | Snapshot sequences + compute `lock_id` |
| `apcl_verify` | Algorithm 3 | LACT+ checks + sequence + lock availability |
| `apcl_acquire_lock` | Algorithm 4 | Atomic all-or-nothing CAS: AVAILABLE → LOCKED |
| `apcl_consensus_filter` | Algorithm 5 | Keep only TXs with valid locks for BFT |
| `apcl_aggregate` | Algorithm 6 | Increment sequences + FINALIZE + register outputs |

---

## Security Properties Preserved

| LACT+ Property | Status with APCL |
|---|---|
| Post-quantum security (Approx-SIS) | Unchanged |
| Activity proof integrity | Extended, not replaced |
| Range proof soundness | Unchanged |
| Balance constraints | Unchanged |
| Confidentiality / hiding | Unchanged (lock metadata is non-sensitive) |
| Transaction aggregation | Unchanged |
| Concurrent double-spend prevention | **New guarantee added by APCL** |

---

## Production Notes

The lock table is currently in-process (single node). For distributed deployment:

1. **Replicate the lock table** across validators (etcd, ZooKeeper, or a BFT atomic register).
2. **Tune `APCL_LOCK_TIMEOUT_MS`** to at least 2× expected consensus latency (default: 5000 ms).
3. **Call `apcl_expire_stale_locks`** periodically to reclaim locks from crashed validators.
