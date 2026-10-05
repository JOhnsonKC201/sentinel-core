# Specification v1: Zero-Copy Binary IPC Wire Protocol

- **Module**: `crates/sentinel-ipc` & `drivers/sentinel-filter/include/communication.h`
- **Status**: APPROVED
- **Author**: SentinelCore Engineering
- **Date**: 2026-10-05

## 1. Overview
This specification defines the zero-copy, 8-byte aligned binary wire framing used across the Windows kernel-to-user boundary via Microsoft Filter Manager communication ports (`FltCreateCommunicationPort` and `FltSendMessage`).

## 2. Memory Alignment & Packing Rules
To eliminate serialization and deserialization CPU cycles in the hot I/O execution path:
1. All structures MUST be packed with 8-byte boundaries using `#pragma pack(push, 8)` in C/C++ and `#[repr(C, packed(8))]` in Rust.
2. Variable-length structures are strictly prohibited across the kernel boundary; all payload fields must have fixed compile-time offsets.
3. String paths are formatted as UTF-16 wide-character arrays normalized to NT namespace (`\Device\HarddiskVolume...\...`).

## 3. Data Structures

### 3.1 Event Types
```c
typedef enum _SENTINEL_EVENT_TYPE {
    EVENT_FILE_EXECUTE      = 1, // IRP_MJ_CREATE with FILE_EXECUTE intent
    EVENT_FILE_CREATE       = 2, // New file creation
    EVENT_FILE_MODIFY       = 3, // File write/overwrite
    EVENT_PROCESS_TERMINATE = 4  // Process termination notification
} SENTINEL_EVENT_TYPE;
```

### 3.2 Verdict Actions
```c
typedef enum _VERDICT_ACTION {
    VERDICT_ALLOW      = 0x00000001, // Permit operation (STATUS_SUCCESS)
    VERDICT_BLOCK      = 0x00000002, // Deny operation (STATUS_ACCESS_DENIED)
    VERDICT_QUARANTINE = 0x00000003, // Isolate to AES-256 vault and block
    VERDICT_BYPASS     = 0x00000004  // System process whitelist bypass
} VERDICT_ACTION;
```

### 3.3 Scan Request Packet (Kernel -> User)
```c
typedef struct _SCAN_REQUEST_PACKET {
    ULONG64             MessageId;         // Monotonically increasing atomic sequence
    ULONG               ProcessId;         // Calling process ID
    ULONG               ThreadId;          // Calling thread ID
    SENTINEL_EVENT_TYPE EventType;         // Intercept event category
    ULONG               FilePathLength;    // Length in bytes of the valid NT path
    WCHAR               FilePath[512];     // Normalized NT path (max 512 wide chars)
    UCHAR               FileSha256[32];    // Pre-calculated hash (if cached in Lookaside)
    BOOLEAN             IsSystemProcess;   // True if caller is privileged kernel/system
} SCAN_REQUEST_PACKET, *PSCAN_REQUEST_PACKET;
```

### 3.4 Scan Response Packet (User -> Kernel)
```c
typedef struct _SCAN_RESPONSE_PACKET {
    ULONG64             MessageId;         // Matches request MessageId
    VERDICT_ACTION      Action;            // ALLOW, BLOCK, or QUARANTINE
    ULONG               TelemetryFlags;    // Bitmask: 0x01=CacheHit, 0x02=YaraHit, 0x04=EntropyHigh
    NTSTATUS            CustomBlockStatus; // NTSTATUS returned to I/O caller (default 0xC0000022)
} SCAN_RESPONSE_PACKET, *PSCAN_RESPONSE_PACKET;
```

## 4. Latency & Timeout Semantics
- **Interception Budget**: P99 pre-execution decision must be returned within `<= 1.5 ms`.
- **Fail-Open Deadline**: The kernel driver configures a synchronous `LARGE_INTEGER` timeout of `-500,000` (50 milliseconds).
- **Timeout Invariant**: If `FltSendMessage` returns `STATUS_TIMEOUT`, the filter pre-operation callback MUST return `FLT_PREOP_SUCCESS_NO_CALLBACK` immediately to prevent OS deadlocks or UI thread stalls.
