#ifndef _SENTINEL_COMMUNICATION_H_
#define _SENTINEL_COMMUNICATION_H_

#include <fltKernel.h>

#define SENTINEL_PORT_NAME L"\\SentinelFilterPort"
#define SENTINEL_ALTITUDE   L"320500"
#define SENTINEL_POOL_TAG   'tneS' // Sent

#pragma pack(push, 8)

typedef enum _SENTINEL_EVENT_TYPE {
    EVENT_FILE_EXECUTE      = 1,
    EVENT_FILE_CREATE       = 2,
    EVENT_FILE_MODIFY       = 3,
    EVENT_PROCESS_TERMINATE = 4
} SENTINEL_EVENT_TYPE;

typedef struct _SCAN_REQUEST_PACKET {
    ULONG64             MessageId;
    ULONG               ProcessId;
    ULONG               ThreadId;
    SENTINEL_EVENT_TYPE EventType;
    ULONG               FilePathLength;
    WCHAR               FilePath[512];        // Normalized NT path
    UCHAR               FileSha256[32];       // Pre-calculated hash (if cached)
    BOOLEAN             IsSystemProcess;
} SCAN_REQUEST_PACKET, *PSCAN_REQUEST_PACKET;

typedef enum _VERDICT_ACTION {
    VERDICT_ALLOW      = 0x00000001,
    VERDICT_BLOCK      = 0x00000002,
    VERDICT_QUARANTINE = 0x00000003,
    VERDICT_BYPASS     = 0x00000004
} VERDICT_ACTION;

typedef struct _SCAN_RESPONSE_PACKET {
    ULONG64             MessageId;
    VERDICT_ACTION      Action;
    ULONG               TelemetryFlags;
    NTSTATUS            CustomBlockStatus;    // Defaults to STATUS_ACCESS_DENIED
} SCAN_RESPONSE_PACKET, *PSCAN_RESPONSE_PACKET;

#pragma pack(pop)

#endif // _SENTINEL_COMMUNICATION_H_
