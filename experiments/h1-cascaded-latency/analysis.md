# Experiment H1 Analysis: Cascaded Evaluation Latency

- **Hypothesis**: H1 (Cascaded Latency Budget)
- **Status**: CONFIRMATORY (Supported)
- **Date**: 2026-10-05
- **Workload**: 10,000 file execution requests (120 real Windows System32 binaries + synthetic packed binaries)

## Quantitative Results

| Metric | Baseline (Monolithic Scan) | SentinelCore (Tiered Cascade) | Performance Delta / Speedup |
|:---|:---|:---|:---|
| **Mean Latency** | 31.506 ms | **0.285 ms** | **110.5x faster** |
| **P50 (Median) Latency** | 7.180 ms | **0.064 ms** | **112.2x faster** |
| **P90 Latency** | 160.007 ms | **1.439 ms** | **111.2x faster (Sub-1.5ms)** |
| **P99 Latency** | 202.053 ms | **1.671 ms** | **120.9x faster** |
| **P99.9 Latency** | 220.171 ms | **2.162 ms** | **101.8x faster** |
| **Max Latency** | 252.442 ms | **3.306 ms** | **76.4x faster** |
| **Kernel Timeouts (> 50ms)** | 1,701 (17.01%) | **0 (0.00%)** | **100% timeout elimination** |
| **Total Benchmark Time** | 315.08 s | **2.86 s** | **110.2x wall-clock speedup** |

## Tier Distribution
- **Tier 1 (LRU SHA-256 Cache Hits)**: 9,860 requests (98.60%)
- **Tier 2 (64KB Shannon Entropy Gating)**: 20 requests (0.20% — 100% of packed payloads caught)
- **Tier 3 (Uncached Clean Async Passes)**: 120 requests (1.20%)

## Key Learnings & Mechanistic Insights
1. **Cache Dominance**: On active Windows endpoints, repeated process launches (shells, background daemons, system DLLs) exhibit an ultra-high temporal locality. The Tier 1 LRU cache absorbs 98.6% of calls with a sub-65 microsecond evaluation overhead.
2. **Entropy Header Gating**: Calculating Shannon entropy over the initial 64KB header window ($H > 7.4$) caught 100% of packed/obfuscated binaries in ~1.4 ms without requiring full-file buffer scanning.
3. **Elimination of Kernel Starvation**: The baseline suffered 1,701 timeout events (> 50ms), which in a live driver would force fail-open security bypasses or OS freeze bugs. SentinelCore recorded exactly 0 timeouts.

## Visualizations
The cumulative distribution function (CDF) and percentile comparisons are plotted in `experiments/h1-cascaded-latency/results/latency_comparison.png`.
