# Experiment Protocol — H2: Write-Entropy Differential for Developer Workload Immunity

- **Hypothesis**: H2 (Developer Workload Resilient Burst Heuristic)
- **Protocol Status**: LOCKED (Pre-registration)
- **Date**: 2026-10-05

## Objective
Evaluate whether coupling sliding-window file modification velocity with write-entropy delta and parent process lineage enables instantaneous detection of zero-day ransomware bursts within $\le 3$ file modifications, while completely eliminating false positive detections on high-throughput developer workloads (`cargo build`, `npm install`, `git checkout`).

## Baseline Architecture (Naive Rate Threshold)
- Threshold: Any process executing $> 50$ file write operations within a rolling 1000ms window is flagged and terminated as ransomware.
- Lineage Agnostic: Does not inspect parent process lineage.
- Entropy Blind: Does not measure byte distribution entropy of written payload blocks.

## Treatment Architecture (SentinelCore Dual-Invariant Heuristic)
Based on Continella et al. (*ShieldFS*, ACSAC 2016) and Kharraz et al. (*DIMVA 2015*):
1. **Sliding-Window Event Tracker**: Tracks modifications in 1000ms rolling windows per process ID.
2. **Write-Block Shannon Entropy Delta**:
   $$\Delta H = H_{\text{write}} - H_{\text{read}}$$
   Ransomware encryption pushes ciphertext entropy to $H > 7.6$ (near uniform distribution), whereas compiler outputs, transpilers, and git extractions produce structured PE sections or ASCII/UTF-8 source files with $H < 6.8$.
3. **Lineage & Header Qualification**:
   - Processes whose parent lineage stems from authenticated developer tools (`cargo.exe`, `rustc.exe`, `git.exe`, `node.exe`) require dual-invalidation: both extreme rate ($> 200/\text{sec}$) AND ciphertext entropy ($H > 7.6$).
   - Valid PE section headers (`.text`, `.rdata`) exempt compiler binaries from immediate mitigation.
4. **Fast Mitigation Circuit**:
   - If velocity $> 100/\text{sec}$ AND $H > 7.6$: issue immediate process termination and isolate file handle within $\le 3$ file operations.

## Workload Datasets
1. **Developer Workload Stream (5,000 operations across 3 scenarios)**:
   - Scenario A: Multi-threaded compiler burst (`cargo build -j 16` generating object files, metadata, and binaries).
   - Scenario B: Package manager dependency extraction (`npm install` writing thousands of small JS/JSON modules).
   - Scenario C: Version control branch switch (`git checkout` writing hundreds of source files).
2. **Ransomware Attack Stream (5,000 operations across 3 simulated strains)**:
   - Strain 1: High-velocity bulk encryptor (WannaCry-style AES-CBC in-place overwrite).
   - Strain 2: Out-of-place encryptor with extension append (LockBit-style `.lock` renaming).
   - Strain 3: Low-and-slow intermittent encryptor (BlackCat-style targeted traversal).

## Predictions
1. **Developer False Positive Rate (FPR)**:
   - Baseline: $> 35\%$ false positive rate (severely disrupts developer builds).
   - SentinelCore Treatment: Exactly $0.00\%$ false positive rate ($< 0.01\%$).
2. **Ransomware Detection Rate (TPR)**:
   - Both Baseline and Treatment achieve $100\%$ detection of high-velocity ransomware.
3. **Mitigation Velocity (Damage Bounding)**:
   - Treatment terminates ransomware process within $\le 3$ file writes, saving $> 99.9\%$ of target files from corruption.
