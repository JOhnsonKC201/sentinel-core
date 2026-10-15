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
from sentinel_scanner.trust import is_protected_system_path
from sentinel_vault.vault import QuarantineVault

import collections
import logging

logger = logging.getLogger(__name__)

# Killing any of these logs the user out or bugchecks Windows.
SESSION_CRITICAL = frozenset({
    "winlogon.exe", "csrss.exe", "lsass.exe", "wininit.exe", "smss.exe",
    "services.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe", "system", "registry",
})

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
            self._poll_once()
            time.sleep(self.poll_interval)

    def _poll_once(self):
        try:
            current_pids = set(psutil.pids())
        except Exception as err:
            logger.warning("Process list unavailable: %s", err)
            return
        new_pids = current_pids - self.known_pids
        # Mark every PID seen before inspecting any of them. Otherwise one
        # failure skips this line and the same process is "new" again on the
        # next poll, forever.
        self.known_pids = current_pids
        for pid in new_pids:
            try:
                self._inspect_new_process(pid)
            except Exception as err:
                logger.warning("Inspecting PID %s failed: %s", pid, err)

    def _record(self, event_type: str, pid: int, proc_name: str, reason: str, details: str):
        self.recent_events.append({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "type": event_type,
            "pid": pid,
            "process": proc_name,
            "reason": reason,
            "details": details,
        })

    def _block(self, proc, pid: int, proc_name: str, exe_path: str, verdict: ScanVerdict,
               event_type: str, details: str, malicious_cmdline: bool = False):
        """Kill the process and quarantine its binary, within limits for Windows itself.

        A Windows binary flagged on its file contents is a false positive by
        construction (SearchProtocolHost.exe): report it, never act. A Windows
        binary run with a malicious command line is a LOLBin (vssadmin delete
        shadows): kill it, but leave the binary in place. Session-critical
        processes are never killed.
        """
        system_binary = bool(exe_path) and is_protected_system_path(exe_path)
        if proc_name.lower() in SESSION_CRITICAL or (system_binary and not malicious_cmdline):
            self._record("SYSTEM_BINARY_FLAGGED_NOT_BLOCKED", pid, proc_name, verdict.reason, exe_path or details)
            return
        try:
            proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        self.blocked_count += 1
        vault_id = "mem-threat-terminated"
        if exe_path and not system_binary and os.path.exists(exe_path):
            try:
                vault_id = self.vault.isolate_file(exe_path, reason=verdict.reason)
            except OSError as err:
                logger.warning("Could not quarantine %s: %s", exe_path, err)
        self._record(event_type, pid, proc_name, verdict.reason, details)
        if self.on_process_blocked:
            self.on_process_blocked(pid, proc_name, verdict, vault_id)

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

            # 1. Command line: fileless attacks, obfuscated PowerShell, shadow copy deletion, LOLBins
            try:
                cmdline_str = " ".join(proc.cmdline())
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cmdline_str = ""
            if cmdline_str:
                cmd_verdict = self.scanner.scan_bytes(
                    cmdline_str.encode("utf-8", errors="ignore"), filename=f"cmdline_{proc_name}")
                if cmd_verdict.is_malicious():
                    self._block(proc, pid, proc_name, exe_path, cmd_verdict,
                                "PROCESS_CMDLINE_BLOCKED", cmdline_str[:120], malicious_cmdline=True)
                    return

            # 2. Executable file
            if exe_path and os.path.exists(exe_path):
                verdict = self.scanner.scan_file(exe_path)
                if verdict.is_malicious():
                    self._block(proc, pid, proc_name, exe_path, verdict, "PROCESS_BINARY_BLOCKED", exe_path)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def audit_running_processes(self, limit: int = 150) -> list:
        """
        Audits all currently running processes on the host.
        Evaluates risk score based on LOLBin invocations, parent-child anomalies,
        and known threat heuristics.
        """
        SUSPICIOUS_PARENTS = {
            "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
            "acrobat.exe", "acrord32.exe", "chrome.exe", "msedge.exe", "firefox.exe"
        }
        SUSPICIOUS_CHILDREN = {
            "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "certutil.exe", "bitsadmin.exe", "vssadmin.exe", "whoami.exe", "rundll32.exe"
        }
        SUSPICIOUS_ARGS = [
            "-enc", "-encodedcommand", "downloadstring", "new-object net.webclient",
            "iex", "invoke-expression", "delete shadows", "bootstatuspolicy ignoreallfailures",
            "frombase64string", "mimikatz", "meterpreter"
        ]

        audited = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'ppid', 'create_time', 'memory_info']):
            try:
                info = proc.info
                pid = info['pid']
                if pid <= 4:
                    continue  # System Idle and System

                name = (info.get('name') or "").lower()
                exe = info.get('exe') or ""
                mem_mb = round(info['memory_info'].rss / (1024 * 1024), 1) if info.get('memory_info') else 0.0

                cmdline_str = ""
                try:
                    cmdline_list = proc.cmdline()
                    cmdline_str = " ".join(cmdline_list)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                parent_name = ""
                # Only resolve parent if child is a suspicious interpreter/LOLBin
                if name in SUSPICIOUS_CHILDREN:
                    try:
                        parent = proc.parent()
                        if parent:
                            parent_name = parent.name().lower()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                risk_score = 0
                indicators = []

                # Indicator 1: Suspicious parent-child execution
                if parent_name in SUSPICIOUS_PARENTS:
                    risk_score += 65
                    indicators.append(f"Abnormal parent spawn ({parent_name} -> {name})")

                # Indicator 2: High-risk command-line arguments
                cmd_lower = cmdline_str.lower()
                for arg in SUSPICIOUS_ARGS:
                    if arg in cmd_lower:
                        risk_score += 50
                        indicators.append(f"Suspicious argument: {arg}")
                        break

                # Indicator 3: System binary masquerading
                if name in ("svchost.exe", "lsass.exe", "services.exe", "csrss.exe"):
                    if exe and not exe.lower().startswith(r"c:\windows\system32"):
                        risk_score += 90
                        indicators.append(f"Masquerading system binary: {exe}")

                # Indicator 4: Script or LOLBin with remote network keywords
                if name in ("powershell.exe", "pwsh.exe", "certutil.exe", "bitsadmin.exe", "mshta.exe"):
                    if any(kw in cmd_lower for kw in ("http://", "https://", "ftp://")):
                        risk_score += 40
                        indicators.append("LOLBin downloading remote payload")

                risk_score = min(100, risk_score)
                threat_level = "CLEAN"
                if risk_score >= 60:
                    threat_level = "HIGH_RISK"
                elif risk_score >= 30:
                    threat_level = "SUSPICIOUS"

                audited.append({
                    "pid": pid,
                    "name": info.get('name') or f"PID {pid}",
                    "exe": exe,
                    "cmdline": cmdline_str[:160],
                    "parent": parent_name,
                    "memory_mb": mem_mb,
                    "risk_score": risk_score,
                    "threat_level": threat_level,
                    "indicators": indicators
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Sort highest risk first, then by memory
        audited.sort(key=lambda x: (x["risk_score"], x["memory_mb"]), reverse=True)
        return audited[:limit]

    def terminate_process(self, pid: int) -> bool:
        """Safely terminates a specified process by PID."""
        try:
            p = psutil.Process(pid)
            p.kill()
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False


