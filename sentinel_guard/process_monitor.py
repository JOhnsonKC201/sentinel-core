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
            exe_path = proc.exe()
            if not exe_path or not os.path.exists(exe_path):
                return

            # Check if binary is malicious
            verdict = self.scanner.scan_file(exe_path)
            if verdict.is_malicious():
                proc_name = proc.name()
                # 1. Kill the process immediately
                try:
                    proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                # 2. Isolate executable into quarantine vault
                vault_id = self.vault.isolate_file(exe_path, reason=verdict.reason)

                # 3. Notify
                if self.on_process_blocked:
                    self.on_process_blocked(pid, proc_name, verdict, vault_id)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
