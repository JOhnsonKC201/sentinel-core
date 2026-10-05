#ifndef _SENTINEL_CALLBACKS_H_
#define _SENTINEL_CALLBACKS_H_

#include "communication.h"

FLT_PREOP_CALLBACK_STATUS
SentinelPreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

NTSTATUS
SentinelPortConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
);

VOID
SentinelPortDisconnectNotify(
    _In_opt_ PVOID ConnectionCookie
);

NTSTATUS
SentinelPortMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
);

NTSTATUS
SentinelFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

OB_PREOP_CALLBACK_STATUS
SentinelPreOpenProcessCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
);

#endif // _SENTINEL_CALLBACKS_H_
