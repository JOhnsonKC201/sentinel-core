# ADR 0003: Process Handle Stripping via ObRegisterCallbacks

- **Status**: ACCEPTED
- **Date**: 2026-10-05
- **Deciders**: SentinelCore Architecture Team

## Context
Advanced malware, ransomware strains, and malicious actors frequently attempt to neutralize running antivirus engines before initiating destructive encryption or exfiltration. Standard user-mode services running as `NT AUTHORITY\SYSTEM` or local administrator can still be terminated via `TerminateProcess`, `taskkill /F`, process injection (`OpenProcess` + `WriteProcessMemory`), or thread suspension if an attacker obtains elevated rights.

## Decision
The kernel driver (`sentinel-filter.sys`) registers an Object Manager callback routine via `ObRegisterCallbacks` targeting `*PsProcessType`. Whenever a handle to `sentinel-daemon` is opened:
- If caller is unprivileged or administrative user-mode (`OperationInformation->KernelHandle == FALSE`):
  - Strip `PROCESS_TERMINATE` (`0x0001`)
  - Strip `PROCESS_VM_WRITE` (`0x0020`)
  - Strip `PROCESS_VM_OPERATION` (`0x0008`)
  - Strip `PROCESS_SUSPEND_RESUME` (`0x0800`)

## Consequences
### Positive
- Prevents termination or memory tampering of the security daemon, even from administrative Command Prompt or PowerShell sessions.
- Requires zero user-mode hooking or risky DLL injection into external processes.

### Negative
- Clean daemon shutdown or upgrade requires a kernel-authenticated communication token sent via the private Filter Communication Port.
