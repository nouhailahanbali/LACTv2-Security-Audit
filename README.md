# LACTv2 Security Audit & APCL Mitigation Suite

Author: Nouhaila HANBALI & Ahmed EL-YAHAOUI 

Email: nouhailahanbali@gmail.com


# Research Status: [Vulnerability Identified & Mitigated]

This repository contains an empirical security audit of the LACTv2 (Lattice-Based Aggregable Confidential Transactions) protocol. It includes benchmarking results for signature sizes and throughput, targeted cryptanalysis demonstrating a concurrent double-spending vulnerability, and the proposed Activity-Proof Consensus Locking (APCL) synchronization layer to resolve it.

1. The Vulnerability: Verification-Aggregation Gap

Our audit identified a critical race condition in the LACT+ reference implementation. Because lactx_tx_verify performs non-atomic local reads of the UTXO set, two conflicting transactions can be validated simultaneously before either is aggregated. While the protocol correctly checks cryptographic validity, the lack of a pre-consensus lock allows these conflicting transactions to be marked as VALID simultaneously, leading to state corruption during the aggregation phase.

Reproducing the Attack (Vulnerable Version)

To see the vulnerability in action without APCL protection:

mkdir build && cd build
cmake ..
make attack_double_spend
./attack_double_spend


2. The Solution: APCL (Activity-Proof Consensus Locking)

APCL is a lightweight protocol extension that closes the gap by introducing atomic locking and sequence assignment. It shifts conflict detection from the Aggregation phase to the Verification phase.

# Key Mechanisms

Four mechanisms close the gap:

| Mechanism | Where | Guarantee |
|---|---|---|
| **Sequence numbers** | Per UTXO coin | Re-spend with old state rejected immediately |
| **Extended activity proof Δ_APCL** | Per TX | TX bound to specific UTXO version |
| **Atomic compare-and-swap lock** | Lock table | Only one TX can claim a coin before consensus |
| **Consensus filter** | Pre-BFT | Only locked TXs enter Byzantine consensus |

# APCL Pipeline (Secure)

[Verify Tx_A] → [Acquire Lock Tx_A] → LOCKED  → Consensus → Aggregate
[Verify Tx_B] → [Acquire Lock Tx_B] → BLOCKED (coin already locked)


3. Repository Layout
.
├── src/                        # Original LACT+ source code
├── include/                    # Header files for LACTv2 library
├── cryptanalysis/
│   └── attack_tests/           # Core research artifacts
│       ├── attack_double_spend.c   # Concurrent double-spending exploit
│       ├── attack_inflation.c      # Balance conservation tests
│       ├── attack_malleability.c   # Header immutability tests
│       └── attack_range_proof.c    # Range-proof soundness evaluation
├── apcl/                       # The APCL Mitigation Layer (Algs 3-6)
│   ├── apcl.c                  # Core synchronization logic
│   ├── apcl.h                  # APCL Function prototypes
│   ├── attack_double_spend_apcl.c  # 3-scenario safety demo
│   └── apcl_integration_tests.c    # 10-scenario full validation suite
├── bench/                      # Benchmarking (TPS, Signature Size)
└── example/                    # Mock UTXO store for testing

4. Building and Testing

# Integration

APCL is designed as a plug-in module. To include it in the build, ensure the following is in your CMakeLists.txt:

include(apcl/CMakeLists_apcl.cmake)


# Execution

Build and run the full suite:

mkdir -p build && cd build
cmake ..
make apcl attack_double_spend_apcl apcl_integration_tests


Run targeted safety demo:

./attack_double_spend_apcl


Run full 10-scenario integration suite:

./apcl_integration_tests


Test Coverage (apcl_integration_tests)

Test,Scenario,Expected
T01-T02,Single/Sequential Spend,PASS
T03-T04,Concurrent Race / Stale Seq,PASS (Blocked)
T05,Lock Recovery (Timeout),PASS
T07,Multi-input Overlap,PASS (Blocked)
T10,Store Integrity,PASS

5. Security & Performance

Post-quantum security: Based on the Approx-SIS hardness assumption.

Privacy: Lock metadata is non-sensitive; confidentiality is preserved.

Efficiency: APCL preserves storage efficiency gains (5.7 KB commitments).

# License & Attribution

This project is based on the LACT+ protocol. Please refer to the LICENSE file for terms. If you use this cryptanalysis or the APCL implementation in your research, please cite the original authors and this audit:

