# Experiment Protocol — H1: Cascaded Evaluation Latency

- **Hypothesis**: H1 (Cascaded Latency Budget)
- **Protocol Status**: LOCKED (Pre-registration)
- **Date**: 2026-10-05

## Objective
Evaluate whether a three-tier evaluation cascade can achieve a P99 pre-execution decision latency <= 1.5ms across 10,000 execution requests, while maintaining zero timeout drops (> 50ms) and accurately identifying packed/anomalous binaries.

## Baseline Architecture
- Synchronous linear scan:
  - Read entire file from disk into buffer.
  - Compute full SHA-256 digest.
  - Execute multi-pattern string matcher across full binary body without caching.

## Treatment Architecture (Tiered Cascade)
- **Tier 1 (Fast-Path Reputation)**:
  - In-memory LRU reputation table (simulating RocksDB + moka cache).
  - Pre-computed hash lookup. Returns in <= 0.1 ms on hit.
- **Tier 2 (Heuristic Gate)**:
  - Zero-copy memory-mapped access.
  - Read PE headers + first 64KB.
  - Compute Shannon byte entropy $H = -\sum_{i=0}^{255} p_i \log_2(p_i)$.
  - If $H > 7.4$, flag as packed/suspicious binary. Returns in <= 0.8 ms.
- **Tier 3 (Deferred Deep Inspection)**:
  - Offload deep pattern matching to asynchronous worker pool (Rayon/Tokio model).
  - Driver returns synchronous pre-op decision immediately while deep scan proceeds out-of-band.

## Dataset & Workload Simulation
- 10,000 file execution requests:
  - 85% Known clean binaries (simulating system files with cache warm-up).
  - 10% Uncached benign executables (standard entropy $H \in [5.2, 6.8]$).
  - 5% Packed or malicious payloads (high entropy $H > 7.5$ or synthetic malware signatures).
- File sizes ranging from 32 KB to 15 MB.

## Predictions
1. **P99 Interception Latency**: Treatment <= 1.5 ms vs Baseline >= 10.0 ms.
2. **Mean Interception Latency**: Treatment <= 0.3 ms vs Baseline >= 6.0 ms.
3. **Kernel Fail-Open Timeouts (> 50ms)**: Exactly 0% for Treatment; > 2% for Baseline under concurrent bursts.
4. **Detection Retention**: 100% of high-entropy packed files ($H > 7.4$) flagged without requiring deep linear scan.
