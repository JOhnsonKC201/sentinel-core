# SentinelCore Agent Policies & Invariants

## Non-Negotiable Safety & Quality Rules
- **Kernel Memory Safety**: Driver code must compile with `/WX` under MSVC WDK. Dynamic non-paged allocations in hot I/O paths are strictly prohibited; pre-allocated Lookaside Lists must be used.
- **Fail-Open Policy**: Any IPC timeout over 50ms MUST return `STATUS_SUCCESS` (`FLT_PREOP_SUCCESS_NO_CALLBACK`) to prevent operating system deadlocks.
- **Altitude Invariant**: File System Minifilter Driver must strictly register at Altitude `320500` (Microsoft Anti-Virus load order).
- **Zero-Copy IPC**: All shared memory structures must use `#pragma pack(push, 8)` / `#[repr(C, packed(8))]`.
- **Pre-Registration Rule**: In autoresearch, commit experiment protocols to Git BEFORE running code (`research(protocol): {hypothesis}`). Never combine protocol and results in one commit.
- **Developer Workload Rule**: Heuristics must never block processes whose lineage stems from approved development toolchains unless write-entropy > 7.5 and burst rate > 100 files/sec.
