# Literature Survey — Foundational Research for SentinelCore

This document synthesizes the 22 core peer-reviewed academic papers that form the theoretical and empirical foundation of the SentinelCore endpoint security architecture.

---

## Pillar 1: Static Binary Analysis, Embeddings & Machine Learning Classifiers

### 1. Deep Neural Network Based Malware Detection Using Two Dimensional Binary Program Features
- **Authors & Venue**: Joshua Saxe & Konstantin Berlin — *IEEE CS Cloud / BigData* (2015)
- **Key Contribution**: Established the benchmark deep neural network pipeline using PE section headers, byte entropy histograms, and string hashes for sub-millisecond static binary classification.
- **Architectural Utility in Sentinel**: Informs the Tier 2 heuristic extractor in `sentinel-pe`, converting binary headers into sub-millisecond feature representations.

### 2. EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models
- **Authors & Venue**: Hyrum S. Anderson & Phil Roth — *arXiv:1804.04159* (2018)
- **Key Contribution**: Standardized 2,381-dimensional feature extraction covering parsed byte histograms, byte-entropy matrices, PE metadata flags, exports, and section characteristics trained via LightGBM.
- **Architectural Utility in Sentinel**: Primary static tabular ML scoring engine deployed alongside YARA-X, running sub-5ms CPU-only inference.

### 3. MalConv: Malware Detection by Eating a Whole EXE
- **Authors & Venue**: Edward Raff, Jon Barker, Jared Sylvester, Robert Brandon, Bryan Catanzaro, Charles K. Nicholas — *IEEE Access* (2018)
- **Key Contribution**: Raw-byte convolutional neural network architecture capable of processing entire raw executable binaries without requiring manual feature engineering, PE parsing, or disassembly.
- **Architectural Utility in Sentinel**: Handles packed, obfuscated, or corrupted PE binaries that cause traditional parsers to fail.

### 4. Effective and Efficient Malware Detection at the End Host
- **Authors & Venue**: Clemens Kolbitsch, Paolo Milani Comparetti, Christopher Kruegel, Engin Kirda, Xiaowen Zhou, Xiao-feng Wang — *USENIX Security* (2009)
- **Key Contribution**: Translates runtime executions into behavioral dependency graphs that evaluate system-call data dependencies without heavy dynamic taint analysis.
- **Architectural Utility in Sentinel**: Argument dependency tracking in `sentinel-daemon` across consecutive Windows API calls.

### 5. Efficient String Matching: An Aid to Bibliographic Search
- **Authors & Venue**: Alfred V. Aho & Margaret J. Corasick — *Communications of the ACM* (1975)
- **Key Contribution**: Deterministic finite automaton (DFA) string-matching algorithm searching arbitrary keyword sets simultaneously in $O(n + m)$ linear time.
- **Architectural Utility in Sentinel**: Algorithmic backbone for compiled YARA-X rule execution during memory-mapped file evaluations.

---

## Pillar 2: Ransomware Interception & Resilient Filesystems

### 6. UNVEIL: A Large-Scale, Automated Approach to Detecting Ransomware
- **Authors & Venue**: Amin Kharraz, William Robertson, Davide Balzarotti, Leyla Bilge, Engin Kirda — *USENIX Security* (2016)
- **Key Contribution**: Introduced dynamic environment synthesis to trap ransomware by tracking file-system interaction invariants and desktop visual dissimilarity changes.
- **Architectural Utility in Sentinel**: Blueprint for dynamic sandbox staging; automated decoy bait folders.

### 7. ShieldFS: A Self-Healing, Ransomware-Aware Filesystem
- **Authors & Venue**: Andrea Continella, Alessandro Guagnelli, Giovanni Zingaro, Giulio De Pasquale, Alessandro Barenghi, Stefano Zanero, Federico Maggi — *ACSAC / ACM TOPS* (2016/2018)
- **Key Contribution**: A Windows filesystem minifilter driver extension that inspects IRPs, tracks write-entropy deltas, and maintains shadow copy transaction buffers to roll back encrypted files upon threat classification.
- **Architectural Utility in Sentinel**: Direct model for `sentinel-filter.sys` copy-on-write buffer allocation on `IRP_MJ_WRITE`.

### 8. Cutting the Gordian Knot: A Look Under the Hood of Ransomware Analysis
- **Authors & Venue**: Amin Kharraz, William Robertson, Davide Balzarotti, Leyla Bilge, Engin Kirda — *DIMVA* (2015)
- **Key Contribution**: Systematic behavioral taxonomy tracking Master File Table (MFT) enumeration, file extension rewriting, and cryptographic API usage.
- **Architectural Utility in Sentinel**: Core heuristic ruleset for `sentinel-telemetry` (flagging MFT walks and ransom notes).

### 9. Redemption: Real-Time Protection Against Ransomware at End-Host
- **Authors & Venue**: Jisoo Kwon, Ziyun Zhu, Leyla Bilge, Engin Kirda — *RAID* (2017)
- **Key Contribution**: Transparent out-of-band kernel storage driver analyzing write-request entropy, access patterns, and file-inversion rates with negligible latency.
- **Architectural Utility in Sentinel**: Driver Lookaside List allocation scheme ensuring non-paged kernel pool protection.

---

## Pillar 3: EDR, Provenance Graphs & Behavioral Telemetry

### 10. SLEUTH: Real-Time Reconstruction of Attacks on Audit Logs
- **Authors & Venue**: Md Nahid Hossain et al. — *USENIX Security* (2017)
- **Key Contribution**: Real-time causal dependency tracking and tag propagation on streaming OS audit logs to reconstruct end-to-end APT attack graphs while filtering dependency explosion.
- **Architectural Utility in Sentinel**: Provenance tracking engine connecting parent processes, injected threads, dropped files, and outbound sockets.

### 11. HOLMES: Real-Time APT Detection through Correlation of Suspicious Information Flows
- **Authors & Venue**: Sadegh M. Milajerdi, Rigel Gjomemo, Birhanu Eshete, R. Sekar, V.N. Venkatakrishnan — *IEEE S&P* (2019)
- **Key Contribution**: Maps low-level audit logs to high-level MITRE ATT&CK tactics, techniques, and procedures (TTPs), dynamically correlating flows into High-level Scenario Graphs.
- **Architectural Utility in Sentinel**: MITRE ATT&CK alert generation pipeline preventing alert fatigue.

### 12. UNICORN: Runtime Provenance-Based Detector for Advanced Persistent Threats
- **Authors & Venue**: Xueyuan Han, Thomas Pasquier, Adam Bates, James Mickens, Margo Seltzer — *NDSS* (2020)
- **Key Contribution**: An unsupervised anomaly-based APT detector utilizing incremental graph sketching and evolutionary histograms to model long-term system execution from boot to shutdown.
- **Architectural Utility in Sentinel**: Long-term baseline modeling for stealthy persistence and delayed shellcode execution.

### 13. ProGraPher: An Anomaly Detection System based on Provenance Graph Embedding
- **Authors & Venue**: Fan Yang, Jiarong Xing, Zheng Leong Chua, et al. — *USENIX Security* (2023)
- **Key Contribution**: Combines graph embedding via Graph2Vec with sequence learning via TextRCNN over provenance snapshots to recognize normal execution patterns.
- **Architectural Utility in Sentinel**: Graph ML engine in background service to classify anomalous execution chains without manual rules.

### 14. CAPTAIN: Towards Lightweight, Adaptive Provenance-Based Intrusion Detection
- **Authors & Venue**: Lingzhi Wang et al. — *NDSS* (2025)
- **Key Contribution**: Differentiable tag propagation using gradient descent on false alarms from benign baseline logs to tune rule thresholds, cutting false alarms by > 90% under < 10% CPU.
- **Architectural Utility in Sentinel**: Runtime optimization loop tuning endpoint alerts against developer workloads (compilers, git, npm).

---

## Pillar 4: Kernel Interception, Memory Forensics & Evasion Defense

### 15. Ether: Malware Analysis via Hardware-Assisted Virtualization
- **Authors & Venue**: Artem Dinaburg, Paul Royal, Monir Sharif, Wenke Lee — *ACM CCS* (2008)
- **Key Contribution**: Pioneered hardware-assisted virtualization (Intel VT-x) to analyze malware out-of-guest, tracing memory modifications and API calls without executing code in untrusted guest environments.
- **Architectural Utility in Sentinel**: Model for isolated VM testing harness via WinDbg KDNET.

### 16. HookSafe: Protecting Large Numbers of Architecture Hooks with Low Overhead
- **Authors & Venue**: Zhi Wang, Xuxian Jiang, Weidong Cui, Peng Ning — *NDSS* (2009)
- **Key Contribution**: Relocates kernel hooks to dedicated write-protected shadow pages and routes control flow through a fine-grained indirection dispatcher.
- **Architectural Utility in Sentinel**: Driver self-defense securing `ObRegisterCallbacks` and filter dispatch pointers.

### 17. Control-Flow Integrity: Principles, Implementations, and Applications
- **Authors & Venue**: Martín Abadi, Mihai Budiu, Úlfar Erlingsson, Jay Ligatti — *ACM CCS / ACM TISSEC* (2005/2009)
- **Key Contribution**: Formalized Control-Flow Integrity (CFI) proving that software execution must be constrained to predetermined CFGs derived from static binary analysis.
- **Architectural Utility in Sentinel**: Enforced via MSVC `/guard:cf` and Rust CFI flags.

### 18. Toward Automated Dynamic Malware Analysis Using Cuckoo
- **Authors & Venue**: Carsten Willems, Thorsten Holz, Felix Freiling — *IEEE Security & Privacy* (2007)
- **Key Contribution**: Defined system architecture for instrumented dynamic binary execution, memory dumping, and structured API hook logging within isolated sandboxes.
- **Architectural Utility in Sentinel**: Automated VM-harness pipeline in CI/CD.

---

## Pillar 5: IoT, Firmware Analysis & Network Edge Defense

### 19. Understanding the Mirai Botnet
- **Authors & Venue**: Manos Antonakakis et al. — *USENIX Security* (2017)
- **Key Contribution**: Forensic analysis of the Mirai IoT botnet: rapid telnet/SSH scanning, credential harvesting, cross-compilation toolchains, and DDoS orchestration.
- **Architectural Utility in Sentinel**: Network behavioral fingerprinting rules for monitoring local network IoT devices.

### 20. Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection
- **Authors & Venue**: Yisroel Mirsky, Tomer Doitshman, Yuval Elovici, Asaf Shabtai — *NDSS* (2018)
- **Key Contribution**: Unsupervised online intrusion detection system using micro-autoencoders running on damped incremental statistics (1D incremental aggregators).
- **Architectural Utility in Sentinel**: Host network monitor flagging abnormal outbound traffic with negligible CPU/memory.

### 21. Towards Automated Dynamic Analysis for Linux-Based Embedded Firmware (FIRMADYNE)
- **Authors & Venue**: Daming D. Chen, Maverick Woo, David Brumley — *NDSS* (2016)
- **Key Contribution**: Automated extraction, QEMU full-system emulation, and dynamic software analysis of embedded Linux system images.
- **Architectural Utility in Sentinel**: Offline firmware vulnerability scanner for connected smart devices.

### 22. SOK: (State of) The Art of War: Offensive and Defensive Technology in Binary Analysis (angr)
- **Authors & Venue**: Yan Shoshitaishvili et al. — *IEEE S&P* (2016)
- **Key Contribution**: Unified framework for symbolic execution, control-flow graph recovery, and concolic constraint solving for cross-architecture binary reverse engineering.
- **Architectural Utility in Sentinel**: Automated unpacker identifying unreachable sandbox-evasion sleep loops.
