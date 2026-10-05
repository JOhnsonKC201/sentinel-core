# Specification v3: Multi-Threaded Rust Scanning Core

- **Module**: `crates/sentinel-daemon/`
- **Status**: APPROVED
- **Author**: SentinelCore Engineering
- **Date**: 2026-10-05

## 1. Overview
The `sentinel-daemon` runs in Windows user space as a high-throughput, multi-threaded security service. It receives execution verification requests via the `\\SentinelFilterPort` communication port, evaluates binaries across a 3-tier cascade, and dispatches verdicts back to the kernel.

## 2. Threading & Concurrency Architecture
- **I/O Coordinator (Tokio Async Runtime)**:
  - Listens asynchronously on the Filter Communication Port using overlapped I/O (`FilterGetMessage`, `FilterReplyMessage`).
  - Dispatches tasks into a bounded crossbeam/mpsc work channel.
- **Evaluation Worker Pool (Rayon Threadpool)**:
  - Worker threads sized to `num_cpus - 1` to prevent CPU monopolization.
  - Zero dynamic heap allocation per request; memory-mapped file slices are evaluated in-place.

## 3. Storage & Cache Architecture
- **Embedded Hash Cache (RocksDB)**:
  - Write buffer size: `64 MB`.
  - Max background compaction jobs: `4`.
  - Key: 32-byte SHA-256 digest (`ring::digest::SHA256`).
  - Value: 1-byte verdict flag (`1=Allow`, `2=Block`, `3=Quarantine`).
- **In-Memory LRU Cache (`moka`)**:
  - Max capacity: 50,000 hot binary signatures.
  - Average lookup latency: `< 0.05 ms`.

## 4. Evaluation Cascade
1. **Tier 1 (Reputation Lookup)**:
   - Check `moka` memory cache -> then RocksDB.
   - If hit: return immediately (`VERDICT_ALLOW` or `VERDICT_BLOCK`).
2. **Tier 2 (Heuristic Gate & Entropy)**:
   - Map file using `memmap2::Mmap`.
   - Calculate Shannon byte entropy over header and code sections:
     $$H = -\sum_{i=0}^{255} p_i \log_2(p_i)$$
   - If $H > 7.4$: flag high heuristic risk (packed executable / custom cryptor).
3. **Tier 3 (YARA-X & Machine Learning)**:
   - Compiled YARA-X rules evaluated against memory-mapped buffer.
   - 2,381-dimensional EMBER tabular features extracted for LightGBM evaluation.
   - Malicious matches trigger atomic cache update and file quarantine.
