# ADR 0001: 8-Byte Aligned Zero-Copy Binary Framing vs JSON/Protobuf

- **Status**: ACCEPTED
- **Date**: 2026-10-05
- **Deciders**: SentinelCore Architecture Team

## Context
Communication between the Windows Minifilter driver (`sentinel-filter.sys`) and the user-mode scanning daemon (`sentinel-daemon`) occurs via Microsoft Filter Manager communication ports (`FltSendMessage`). This call sits directly inside the synchronous `IRP_MJ_CREATE` execution path. Under peak system load, hundreds of executables, DLLs, and scripts are launched concurrently.

Serialized data exchange formats (e.g. JSON, XML, or standard Protocol Buffers) require memory allocations and parsing deserializers on both sides of the kernel boundary, adding ~0.3 - 0.8 ms of CPU overhead per request and risking memory fragmentation in kernel non-paged pools.

## Decision
We enforce a fixed-layout, 8-byte aligned C/Rust binary structure (`SCAN_REQUEST_PACKET` and `SCAN_RESPONSE_PACKET`) defined via `#pragma pack(push, 8)` and `#[repr(C, packed(8))]`.

## Consequences
### Positive
- Zero serialization/deserialization CPU latency: pointers can be cast directly over received port memory buffers.
- Zero dynamic non-paged pool memory allocations: memory layouts are fixed and pre-allocated from Lookaside Lists.
- Absolute cross-language binary compatibility between MSVC C/C++ and Rust.

### Negative
- Payload sizes are fixed at compile time (paths capped at 512 wide characters; longer paths require querying by File ID).
- Schema evolution requires incrementing a wire protocol version byte in the header.
