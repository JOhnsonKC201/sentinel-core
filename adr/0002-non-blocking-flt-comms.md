# ADR 0002: Hard 50ms Kernel Fail-Open Timeout & Overlapped I/O

- **Status**: ACCEPTED
- **Date**: 2026-10-05
- **Deciders**: SentinelCore Architecture Team

## Context
If a kernel minifilter issues a synchronous blocking request to user space and the user-mode process locks, deadlocks, crashes, or is held in a debugger, every intercepted thread in the operating system hangs indefinitely. In `IRP_MJ_CREATE`, this results in immediate system lockup, explorer freeze, and OS watchdog bugchecks (`DPC_WATCHDOG_VIOLATION` or `CRITICAL_PROCESS_DIED`).

## Decision
1. All `FltSendMessage` calls in `sentinel-filter.sys` MUST specify a synchronous timeout of `-500,000` (50 milliseconds).
2. If `FltSendMessage` returns `STATUS_TIMEOUT`, the driver MUST fail-open immediately, returning `FLT_PREOP_SUCCESS_NO_CALLBACK` and logging a telemetry timeout flag.
3. The user daemon must process messages using Tokio overlapped asynchronous I/O and Rayon worker thread pools.

## Consequences
### Positive
- Guaranteed operating system survivability under all edge cases.
- Prevents user-mode latency spikes from cascading into kernel crashes.

### Negative
- A malicious zero-day executed during a sustained daemon denial-of-service could bypass pre-execution blocking. This is mitigated by post-execution behavioral ETW tracking and the ShieldFS copy-on-write rollback layer.
