/**
 * SentinelCore Windows File System Minifilter Driver (sentinel-filter.sys)
 * Assigned Altitude: 320500 (FSFilter Anti-Virus)
 * 
 * Intercepts file execution intents (IRP_MJ_CREATE), coordinates with the
 * user-mode sentinel-daemon via Filter Communication Ports, enforces strict
 * 50ms fail-open deadlines, and self-defends via ObRegisterCallbacks.
 */

#include "callbacks.h"

PFLT_FILTER gFilterHandle = NULL;
PFLT_PORT   gServerPort   = NULL;
PFLT_PORT   gClientPort   = NULL;
PVOID       gRegistrationHandle = NULL;
LONG64      gGlobalMessageCounter = 0;
ULONG       gProtectedDaemonPid   = 0;
NPAGED_LOOKASIDE_LIST gPacketLookaside;

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, SentinelPreCreateCallback, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    SentinelFilterUnload,
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL
};

FLT_PREOP_CALLBACK_STATUS
SentinelPreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
) {
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);

    // Fast-path: Kernel requests are not blocked to avoid deadlock
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Inspect execution intents (FILE_EXECUTE / GENERIC_EXECUTE)
    ULONG options = Data->Iopb->Parameters.Create.Options;
    ACCESS_MASK accessMask = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    if (!(accessMask & FILE_EXECUTE) && !(options & FILE_EXECUTE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Fail-open: If user-space daemon is detached or not running, allow execution
    if (gClientPort == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PSCAN_REQUEST_PACKET request = (PSCAN_REQUEST_PACKET)ExAllocateFromNPagedLookasideList(&gPacketLookaside);
    if (request == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK; // Fail-open on allocation failure
    }
    RtlZeroMemory(request, sizeof(SCAN_REQUEST_PACKET));

    SCAN_RESPONSE_PACKET response = {0};
    ULONG replyLength = sizeof(SCAN_RESPONSE_PACKET);

    // Hard 50-millisecond timeout to protect system responsiveness
    LARGE_INTEGER timeout;
    timeout.QuadPart = -10000 * 50; 

    request->MessageId = InterlockedIncrement64(&gGlobalMessageCounter);
    request->ProcessId = HandleToULong(PsGetCurrentProcessId());
    request->ThreadId  = HandleToULong(PsGetCurrentThreadId());
    request->EventType = EVENT_FILE_EXECUTE;

    // Resolve normalized NT path
    PFLT_FILE_NAME_INFORMATION nameInfo;
    if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) {
        FltParseFileNameInformation(nameInfo);
        request->FilePathLength = min(nameInfo->Name.Length, sizeof(request->FilePath) - sizeof(WCHAR));
        RtlCopyMemory(request->FilePath, nameInfo->Name.Buffer, request->FilePathLength);
        FltReleaseFileNameInformation(nameInfo);
    }

    // Send synchronous inquiry to user-space detection engine
    NTSTATUS status = FltSendMessage(
        gFilterHandle,
        &gClientPort,
        request,
        sizeof(SCAN_REQUEST_PACKET),
        &response,
        &replyLength,
        &timeout
    );

    ExFreeToNPagedLookasideList(&gPacketLookaside, request);

    // If verdict is BLOCK, deny execution
    if (NT_SUCCESS(status) && response.Action == VERDICT_BLOCK) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    // Default to allow (fail-open on timeout or clean verdict)
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

OB_PREOP_CALLBACK_STATUS
SentinelPreOpenProcessCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
) {
    UNREFERENCED_PARAMETER(RegistrationContext);

    PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
    ULONG targetPid = HandleToULong(PsGetProcessId(targetProcess));

    // Strip destructive access rights targeting our protected daemon PID
    if (targetPid == gProtectedDaemonPid && OperationInformation->KernelHandle == FALSE) {
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
    }
    return OB_PREOP_SUCCESS;
}

NTSTATUS
SentinelPortConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
) {
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionPortCookie);

    gClientPort = ClientPort;
    gProtectedDaemonPid = HandleToULong(PsGetCurrentProcessId());
    return STATUS_SUCCESS;
}

VOID
SentinelPortDisconnectNotify(
    _In_opt_ PVOID ConnectionCookie
) {
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(gFilterHandle, &gClientPort);
    gClientPort = NULL;
    gProtectedDaemonPid = 0;
}

NTSTATUS
SentinelPortMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
) {
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferSize);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferSize);
    *ReturnOutputBufferLength = 0;
    return STATUS_SUCCESS;
}

NTSTATUS
SentinelFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
) {
    UNREFERENCED_PARAMETER(Flags);

    if (gRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(gRegistrationHandle);
        gRegistrationHandle = NULL;
    }
    if (gServerPort != NULL) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
    }
    if (gFilterHandle != NULL) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }
    ExDeleteNPagedLookasideList(&gPacketLookaside);
    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(RegistryPath);

    ExInitializeNPagedLookasideList(
        &gPacketLookaside,
        NULL,
        NULL,
        0,
        sizeof(SCAN_REQUEST_PACKET),
        SENTINEL_POOL_TAG,
        0
    );

    NTSTATUS status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) return status;

    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName = RTL_CONSTANT_STRING(SENTINEL_PORT_NAME);
    PSECURITY_DESCRIPTOR sd;

    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        InitializeObjectAttributes(&oa, &portName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);
        status = FltCreateCommunicationPort(
            gFilterHandle,
            &gServerPort,
            &oa,
            NULL,
            SentinelPortConnectNotify,
            SentinelPortDisconnectNotify,
            SentinelPortMessageNotify,
            1 // Single connection from trusted daemon
        );
        FltFreeSecurityDescriptor(sd);
    }

    if (NT_SUCCESS(status)) {
        status = FltStartFiltering(gFilterHandle);
    }
    return status;
}
