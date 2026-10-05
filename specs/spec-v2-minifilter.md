# Specification v2: Windows File System Minifilter Driver

- **Module**: `drivers/sentinel-filter/`
- **Status**: APPROVED
- **Author**: SentinelCore Engineering
- **Date**: 2026-10-05

## 1. Overview
The `sentinel-filter.sys` driver intercepts file execution requests at the kernel level before user-space processes are granted code execution rights. It acts as the frontline interceptor and kernel enforcement arm of the SentinelCore system.

## 2. Altitude Registration & Filter Manager
- **Assigned Altitude**: `320500`
- **Altitude Group**: `320000 - 329999` (`FSFilter Anti-Virus`)
- **Ordering Guarantee**: Positioned above standard encryption, continuous backup, and virtualization filters, but below activity monitors, ensuring all user executions are intercepted prior to binary loading.

## 3. Intercepted Operations
The driver registers for:
1. `IRP_MJ_CREATE`:
   - Inspects `Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess` for `FILE_EXECUTE`.
   - Inspects `Data->Iopb->Parameters.Create.Options` for `FILE_NON_DIRECTORY_FILE` & `FILE_EXECUTE`.
   - Normalizes NT path via `FltGetFileNameInformation(..., FLT_FILE_NAME_NORMALIZED)`.
2. `IRP_MJ_SET_INFORMATION`:
   - Intercepts file renaming and disposition changes (catching ransomware extension append attacks like `.locked`, `.crypto`).
3. `IRP_MJ_WRITE`:
   - Monitors write burst frequency and entropy deltas across monitored volume boundaries.

## 4. Kernel Memory Safety & Lookaside Lists
To satisfy the Zero Non-Paged Pool Exhaustion invariant:
- Dynamic allocations via `ExAllocatePoolWithTag` inside `SentinelPreCreateCallback` are strictly forbidden.
- A pre-allocated NPAGED Lookaside List (`NPAGED_LOOKASIDE_LIST gPacketLookasideList`) is initialized during `DriverEntry` with pool tag `'tneS'` (`0x746E6553`).
- All `SCAN_REQUEST_PACKET` and `SCAN_RESPONSE_PACKET` instances are drawn from and returned to this Lookaside list.

## 5. Anti-Tamper Protection (`ObRegisterCallbacks`)
- Registers an object callback via `ObRegisterCallbacks` targeting `PsProcessType`.
- When an open process handle is requested:
  - If `TargetProcess == gProtectedDaemonPid` and `OperationInformation->KernelHandle == FALSE`:
    - Strips: `PROCESS_TERMINATE` (`0x0001`)
    - Strips: `PROCESS_VM_WRITE` (`0x0020`)
    - Strips: `PROCESS_VM_OPERATION` (`0x0008`)
    - Strips: `PROCESS_SUSPEND_RESUME` (`0x0800`)
- Guarantees immunity against unprivileged attackers and administrative `taskkill /F` or malicious process injectors.
