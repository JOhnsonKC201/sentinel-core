# Research Log — SentinelCore Project

## 2026-10-05 — Bootstrap & Environment Initialization

### Context & Objective
Initiated autonomous research project to engineer, evaluate, and benchmark **SentinelCore**: a low-latency, kernel-filtered endpoint detection and antivirus architecture for Windows 11 development workstations.

### Key Decisions
1. **Toolchain Integration**: Selected `danielrosehill/Claude-Spec-Starter` for Spec-Driven Development (SDD) and date-prefixed ADRs, `am-will/swarms` for multi-agent parallel wave dispatching, and `krzemienski/enhanced-claude-code` for 5-minute state checkpointing.
2. **Subsystem Partitioning**:
   - Kernel Interceptor: C/C++ Windows File System Minifilter (Altitude `320500`, `IRP_MJ_CREATE`, `ObRegisterCallbacks` self-defense).
   - High-Throughput Core: Multi-threaded Rust daemon (`memmap2`, RocksDB, Shannon entropy, YARA-X).
   - Behavioral Telemetry: Go daemon tracking burst file modifications and ETW-TI events.
   - Operations: Tauri desktop console + AES-256-GCM authenticated quarantine vault.
3. **Core Hypotheses Formulated**:
   - **H1**: Three-tier evaluation cascade achieves <= 1.5ms P99 decision latency.
   - **H2**: Sliding-window write-entropy differential mitigates ransomware within <= 3 files while maintaining < 0.01% developer false-positive rate.
   - **H3**: Pre-allocated Lookaside Lists prevent non-paged pool exhaustion across 50,000 stress I/O operations.

### Literature Grounding
Mapped architecture against 22 peer-reviewed foundational papers across 5 pillars:
- Static Binary Analysis & ML: Saxe & Berlin (2015), EMBER (2018), MalConv (2018), Kolbitsch et al. (2009), Aho-Corasick (1975).
- Ransomware Interception & Resilient Filesystems: UNVEIL (2016), ShieldFS (2016), Gordian Knot (2015), Redemption (2017).
- EDR & Provenance Graphs: SLEUTH (2017), HOLMES (2019), UNICORN (2020), ProGraPher (2023), CAPTAIN (2025).
- Kernel Defense & Memory Integrity: Ether (2008), HookSafe (2009), CFI (2005), Cuckoo (2007).
- IoT & Edge Defense: Mirai (2017), Kitsune (2018), FIRMADYNE (2016), angr (2016).

### Next Steps
- Establish initial experiment protocol for Hypothesis H1 (Benchmark scanning latency: baseline vs tiered cascade).
- Implement benchmarking harness in `src/` and run Run 001.
