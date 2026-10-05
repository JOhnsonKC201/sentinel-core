# Specification v4: Behavioral Heuristics & ETW Telemetry Engine

- **Module**: `services/sentinel-telemetry/`
- **Status**: APPROVED
- **Author**: SentinelCore Engineering
- **Date**: 2026-10-05

## 1. Overview
The `sentinel-telemetry` service operates as a high-performance Go daemon that monitors post-execution process behavior, captures low-level operating system events via Event Tracing for Windows (ETW-TI), and intercepts zero-day crypto-ransomware through sliding-window behavioral heuristics.

## 2. Event Ingestion Pipeline
- **Event Tracing for Windows Threat Intelligence (ETW-TI)**:
  - Consumes kernel events from `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}` (`Microsoft-Windows-Threat-Intelligence`).
  - Intercepts:
    - `KERNEL_THREATINT_PROCESS_CREATE`: Parent/child process lineage and token privileges.
    - `KERNEL_THREATINT_ALLOCVM_REMOTE`: Cross-process memory allocations (Process Hollowing / Injection).
    - `KERNEL_THREATINT_SETTHREADCONTEXT`: Remote thread hijacking attempts.
- **Minifilter File Event Stream**:
  - Receives asynchronous notifications of `IRP_MJ_WRITE` and `IRP_MJ_SET_INFORMATION` from `sentinel-filter.sys`.

## 3. Sliding-Window Ransomware Interception
Based on the behavioral invariants established by Kharraz et al. (*DIMVA 2015*, *USENIX Security 2016*) and Continella et al. (*ShieldFS 2016*):
- **Process History State**:
  - Tracks `ModificationRate` (frequency of file writes within 1000ms rolling windows).
  - Tracks `EntropyDeltas` (transition from low-entropy structured document blocks to high-entropy encrypted ciphertext blocks).
- **Ransomware Burst Threshold**:
  - If a process produces `ModificationRate > 100` writes/second AND average write block entropy `H > 7.5`:
    - Action: Immediate kernel kill signal issued to driver.
    - Action: Quarantine vault atomic isolation of written payload.
    - Bounded Damage Guarantee: Ransomware activity neutralized within `<= 3` file writes.

## 4. Developer Workload Differentiation
To prevent false alarms on software engineering tasks (`cargo build`, `npm install`, `git checkout`):
- Lineage Whitelisting: Processes originating from authenticated development toolchains (`cargo.exe`, `rustc.exe`, `cl.exe`, `git.exe`, `node.exe`) are evaluated with relaxed rate limits (`Rate > 500/sec`) provided write-block entropy remains below `6.8`.
- Compiler Detection: Compiler PE generation produces valid Section Headers (`.text`, `.rdata`, `.reloc`) easily distinguished from uniform-random ciphertext bytes.
