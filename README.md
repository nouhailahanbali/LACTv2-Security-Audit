# 🔐 LACTv2 Security Audit & APCL Mitigation Suite

**Authors:** Nouhaila HANBALI & Ahmed EL-YAHAOUI
📧 Email: [nouhailahanbali@gmail.com](mailto:nouhailahanbali@gmail.com)

---

## 📌 Research Status

**Vulnerability Identified & Mitigated**

This repository presents an **empirical security audit** of the **LACTv2 (Lattice-Based Aggregable Confidential Transactions)** protocol.

It includes:

* 📊 Benchmarking results (signature size & throughput)
* 🔍 Cryptanalysis demonstrating a **double-spending vulnerability**
* 🛡️ A mitigation layer: **APCL (Activity-Proof Consensus Locking)**

---

## ⚠️ 1. The Vulnerability: Verification–Aggregation Gap

A **critical race condition** was identified in the LACT+ reference implementation.

### 🧠 Root Cause

* `lactx_tx_verify` performs **non-atomic reads** of the UTXO set
* Two conflicting transactions can be validated simultaneously
* Both may be marked `VALID` before aggregation

### 🚨 Impact

* Double-spending becomes possible
* State corruption during aggregation

---

### 🧪 Reproducing the Attack (Vulnerable Version)

```bash
mkdir -p build && cd build
cmake ..
make attack_double_spend
./attack_double_spend
```

---

## 🛡️ 2. The Solution: APCL (Activity-Proof Consensus Locking)

APCL is a **lightweight synchronization layer** that eliminates the race condition.

### 🎯 Key Idea

Shift conflict detection from:

* ❌ Aggregation phase
  → ✅ Verification phase (with atomic locking)

---

### 🔧 Core Mechanisms

| Mechanism                        | Location        | Guarantee                             |
| -------------------------------- | --------------- | ------------------------------------- |
| **Sequence numbers**             | Per UTXO coin   | Prevents reuse of stale state         |
| **Activity proof (Δ_APCL)**      | Per transaction | Binds TX to UTXO version              |
| **Atomic compare-and-swap lock** | Lock table      | Ensures exclusive access to a coin    |
| **Consensus filter**             | Pre-BFT         | Only valid locked TXs enter consensus |

---

### 🔄 APCL Secure Pipeline

```
[Verify Tx_A] → [Acquire Lock Tx_A] → LOCKED  → Consensus → Aggregate
[Verify Tx_B] → [Acquire Lock Tx_B] → BLOCKED (coin already locked)
```

---

## 📁 3. Repository Layout

```
.
├── src/                        # Original LACT+ source code
├── include/                    # Header files for LACTv2 library
├── cryptanalysis/
│   └── attack_tests/           # Core research artifacts
│       ├── attack_double_spend.c   # Concurrent double-spending exploit
│       ├── attack_inflation.c      # Balance conservation tests
│       ├── attack_malleability.c   # Header immutability tests
│       └── attack_range_proof.c    # Range-proof soundness evaluation
├── apcl/                       # APCL Mitigation Layer (Algorithms 3–6)
│   ├── apcl.c                  # Core synchronization logic
│   ├── apcl.h                  # Function prototypes
│   ├── attack_double_spend_apcl.c  # Safety demonstration
│   └── apcl_integration_tests.c    # Full validation suite
├── bench/                      # Benchmarking (TPS, signature size)
└── example/                    # Mock UTXO store
```

---

## ⚙️ 4. Building & Testing

### 🔌 Integration

Ensure APCL is included in your build:

```cmake
include(apcl/CMakeLists_apcl.cmake)
```

---

### ▶️ Build

```bash
mkdir -p build && cd build
cmake ..
make apcl attack_double_spend_apcl apcl_integration_tests
```

---

### ▶️ Run

#### Run vulnerability demo (unprotected):

```bash
./attack_double_spend
```

#### Run APCL protection demo:

```bash
./attack_double_spend_apcl
```

#### Run full validation suite:

```bash
./apcl_integration_tests
```

---

## 📊 5. Security & Performance

* 🔐 **Post-quantum security:** Based on Approx-SIS hardness assumption
* 🕵️ **Privacy:** Lock metadata is non-sensitive
* ⚡ **Efficiency:** Preserves compact commitments (~5.7 KB)

---

## 📜 License & Attribution

This project builds upon the **LACT+ protocol**.
Refer to the `LICENSE` file for usage terms.

If you use this work, please cite:

* Original LACT+ authors
* This audit and APCL contribution

---

## ⭐ Summary

* ❌ Identified a **critical double-spending vulnerability**
* ✅ Proposed **APCL** as a robust mitigation
* 🔬 Provided reproducible attacks and validation suite

---
