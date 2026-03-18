# LACTv2: Security Audit and Double-Spending Analysis

This repository contains an empirical security audit of the LACTv2 protocol. It includes benchmarking results for signature sizes and throughput, alongside executable cryptanalysis demonstrating a concurrent double-spending vulnerability.

# Repository Structure

src/: Original protocol source code.

include/: Header files for the LACTv2 library.

cryptanalysis/attack_tests/: Core research artifacts.

    attack_double_spend.c: Implementation of the concurrent double-spending attack.

    attack_inflation.c: Tests for balance conservation integrity.

    attack_malleability.c: Tests for transaction header immutability.

    attack_range_proof.c: Evaluation of range-proof soundness.

bench/: Benchmarking scripts used to generate performance charts (TPS, Signature Size).

example/: Simple implementation of a UTXO store for testing.
 
 # How to build :
'mkdir build && cd build'
'cmake ..'
'make'
# Execute the Double-Spend Attack:
./attack_double_spend

# Findings Summary

Our research identifies a Verification-Aggregation Gap. While lactx_tx_verify correctly checks cryptographic validity, the lack of a pre-consensus lock allows conflicting transactions to be marked as VALID simultaneously, leading to state corruption during the aggregation phase.

# License & Attribution

This project is based on the LACT+ protocol. Please refer to the LICENSE file for terms. If you use this cryptanalysis in your research, please cite the original authors using CITATION.cff.

email: nouhailahanbali@gmail.com 