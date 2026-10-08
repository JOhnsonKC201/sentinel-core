"""
Process Monitor for SentinelCore
Monitors newly spawned processes on Windows, inspects executable binaries and command lines,
and terminates malicious executables before they establish persistence.
"""

import os
import time
import threading
from typing import Set, Callable, Optional
import psutil

from sentinel_scanner.engine import SentinelScanner, ScanVerdict
from sentinel_vault.vault import QuarantineVault

import collections

class ProcessMonitor:
    def __init__(
        self,
        scanner: SentinelScanner,
        vault: QuarantineVault,
        poll_interval: float = 0.3,
        on_process_blocked: Optional[Callable[[int, str, ScanVerdict, str], None]] = None
    ):
        self.scanner = scanner
        self.vault = vault
        self.poll_interval = poll_interval
        self.on_process_blocked = on_process_blocked
        self.is_running = False
        self.thread: Optional[threading.Thread] = None
        self.known_pids: Set[int] = set()
        self.inspected_count = 0
        self.blocked_count = 0
        self.recent_events = collections.deque(maxlen=100)

    def start(self):
        """Initializes known PIDs and starts background polling thread."""
        self.is_running = True
        try:
            self.known_pids = set(psutil.pids())
        except Exception:
            self.known_pids = set()

        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.is_running = False

    def _monitor_loop(self):
        while self.is_running:
            try:
                current_pids = set(psutil.pids())
                new_pids = current_pids - self.known_pids
                
                for pid in new_pids:
                    self._inspect_new_process(pid)

                self.known_pids = current_pids
            except Exception:
                pass
            time.sleep(self.poll_interval)

    def _inspect_new_process(self, pid: int):
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            self.inspected_count += 1
            exe_path = ""
            try:
                exe_path = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # 1. Inspect command line for fileless attacks, obfuscated powershell, shadowcopy deletion, LOLBins
            try:
                cmdline_list = proc.cmdline()
                cmdline_str = " ".join(cmdline_list)
                if cmdline_str:
                    cmd_verdict = self.scanner.scan_bytes(
                        cmdline_str.encode("utf-8", errors="ignore"),
                        filename=f"cmdline_{proc_name}"
                    )
                    if cmd_verdict.is_malicious():
                        try:
                            proc.kill()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                        
                        self.blocked_count += 1
                        vault_id = "mem-threat-terminated"
                        if exe_path and os.path.exists(exe_path) and not exe_path.lower().startswith(r"c:\windows"):
                            try:
                                vault_id = self.vault.isolate_file(exe_path, reason=cmd_verdict.reason)
                            except Exception:
                                pass
                        
                        event_record = {
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "type": "PROCESS_CMDLINE_BLOCKED",
                            "pid": pid,
                            "process": proc_name,
                            "reason": cmd_verdict.reason,
                            "details": cmdline_str[:120]
                        }
                        self.recent_events.append(event_record)

                        if self.on_process_blocked:
                            self.on_process_blocked(pid, proc_name, cmd_verdict, vault_id)
                        return
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # 2. Inspect executable file
            if exe_path and os.path.exists(exe_path):
                verdict = self.scanner.scan_file(exe_path)
                if verdict.is_malicious():
                    try:
                        proc.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                    self.blocked_count += 1
                    vault_id = self.vault.isolate_file(exe_path, reason=verdict.reason)
                    
                    event_record = {
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "type": "PROCESS_BINARY_BLOCKED",
                        "pid": pid,
                        "process": proc_name,
                        "reason": verdict.reason,
                        "details": exe_path
                    }
                    self.recent_events.append(event_record)

                    if self.on_process_blocked:
                        self.on_process_blocked(pid, proc_name, verdict, vault_id)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

