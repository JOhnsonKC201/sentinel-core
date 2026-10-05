# Experiment H2 Analysis: Write-Entropy Differential for Developer Workload Immunity

- **Hypothesis**: H2 (Developer Workload Resilient Burst Heuristic)
- **Status**: CONFIRMATORY (Supported)
- **Date**: 2026-10-05
- **Workload**: 5,000 developer write operations (`cargo`, `node`, `git`) + 50 simulated zero-day ransomware attacks (5,000 attack writes)

## Quantitative Results

| Metric | Baseline (Rate-Only Heuristic) | SentinelCore (Dual-Invariant Engine) | Improvement / Difference |
|:---|:---|:---|:---|
| **Developer False Alarms** | 3 / 3 sessions (100.0%) | **0 / 3 sessions (0.00%)** | **100% false alarm elimination** |
| **Developer Build Interruption** | `rustc.exe`, `node.exe`, `git.exe` killed | **All 5,000 writes completed cleanly** | **Zero Developer Friction** |
| **Ransomware Detection Rate (TPR)** | 50 / 50 attacks (100.0%) | **50 / 50 attacks (100.0%)** | **100% Zero-Day Interception** |
| **Mean Files Compromised Per Attack** | 51.0 files | **3.0 files** | **17.0x reduction in file damage** |
| **Max Files Compromised** | 51 files | **3 files** | **Damage strictly bounded** |

## Mechanistic Insights & Theoretical Grounding

1. **Clear Entropy Separation**:
   - Legitimate compiler outputs (`rustc.exe` writing intermediate `.rmeta`, `.rlib`, and `.obj` archives) exhibit structured entropy ($H \in [5.6, 6.6]$) due to standard PE/COFF section headers, symbol tables, and zero-padding.
   - Text files, source code, and package manifests (`git`, `node`) exhibit $H \in [4.2, 5.3]$.
   - Ransomware ciphertext generated via modern symmetric ciphers (AES-256-CBC, ChaCha20) exhibits uniform random byte distributions ($H \in [7.75, 7.99]$).
   - Placing the threshold at $H = 7.5$ provides a clean, robust margin of safety.

2. **Damage Bounding to $\le 3$ Files**:
   - Naive rate-based heuristics must wait for the count threshold ($N = 50$) to accumulate before firing, sacrificing 51 user files to encryption.
   - SentinelCore's dual-invariant detector evaluates write entropy on a per-block basis (4KB sample). Detecting 3 consecutive high-entropy writes triggers immediate kernel process termination, bounding damage to exactly 3 files.

3. **Synergy with ShieldFS Copy-on-Write Rollback**:
   - In accordance with Continella et al. (*ShieldFS*, ACSAC 2016), `sentinel-filter.sys` maintains temporary transaction buffers for file modifications.
   - Because damage is bounded to $\le 3$ files, the driver's Lookaside transaction buffer easily caches the original file blocks in memory, permitting an atomic rollback upon process termination for **zero net file loss**.

## Visualizations
The entropy distribution histogram and damage bounding comparison are plotted in `experiments/h2-ransomware-developer-heuristics/results/ransomware_defense_comparison.png`.
