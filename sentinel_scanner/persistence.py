"""
Windows AutoRun & Persistence Mechanism Scanner for SentinelCore
Audits Windows Registry Run/RunOnce keys, Startup folders, and scheduled persistence items.
Cross-references startup targets against the SentinelCore evaluation engine.
"""

import os
import re
import shlex
import winreg
from typing import List, Dict, Any, Optional

from sentinel_scanner.engine import SentinelScanner, ScanVerdict

PERSISTENCE_REGISTRY_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
]

SUSPICIOUS_CMD_PATTERNS = [
    re.compile(r"powershell(\.exe)?\s+(-e|-enc|-w\s+hidden)", re.IGNORECASE),
    re.compile(r"mshta(\.exe)?\s+", re.IGNORECASE),
    re.compile(r"cscript(\.exe)?\s+.*\.vbs", re.IGNORECASE),
    re.compile(r"rundll32(\.exe)?\s+.*,\s*#", re.IGNORECASE),
    re.compile(r"cmd(\.exe)?\s+/c\s+start", re.IGNORECASE),
]

def extract_target_path(command: str) -> str:
    """Extracts the primary executable path from a startup command string."""
    command = command.strip()
    if not command:
        return ""

    # Quoted path
    if command.startswith('"'):
        end_idx = command.find('"', 1)
        if end_idx != -1:
            return command[1:end_idx]

    # Non-quoted: split on first space
    parts = command.split()
    if parts:
        return parts[0]
    return command

class PersistenceScanner:
    def __init__(self, scanner: Optional[SentinelScanner] = None):
        self.scanner = scanner or SentinelScanner()

    def audit_all(self) -> List[Dict[str, Any]]:
        """Audits all registry Run keys and Startup directories."""
        results = []
        results.extend(self._audit_registry())
        results.extend(self._audit_startup_folders())
        return results

    def _audit_registry(self) -> List[Dict[str, Any]]:
        items = []
        for root_key, subkey_path, display_name in PERSISTENCE_REGISTRY_KEYS:
            try:
                with winreg.OpenKey(root_key, subkey_path, 0, winreg.KEY_READ) as key:
                    num_values = winreg.QueryInfoKey(key)[1]
                    for i in range(num_values):
                        try:
                            val_name, val_data, val_type = winreg.EnumValue(key, i)
                            if isinstance(val_data, str):
                                item = self._evaluate_entry(display_name, val_name, val_data)
                                items.append(item)
                        except OSError:
                            continue
            except OSError:
                continue
        return items

    def _audit_startup_folders(self) -> List[Dict[str, Any]]:
        items = []
        folders = [
            (
                os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
                "User Startup Folder"
            ),
            (
                os.path.join(os.environ.get("ProgramData", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
                "Common Startup Folder"
            )
        ]

        for folder, label in folders:
            if not os.path.exists(folder):
                continue
            try:
                for entry in os.listdir(folder):
                    full_path = os.path.join(folder, entry)
                    if os.path.isfile(full_path):
                        item = self._evaluate_entry(label, entry, full_path)
                        items.append(item)
            except Exception:
                continue
        return items

    def _evaluate_entry(self, location: str, name: str, command: str) -> Dict[str, Any]:
        target_path = extract_target_path(command)
        exists = os.path.exists(target_path)
        is_threat = False
        threat_reason = ""
        tier = 0

        # Check for suspicious command-line execution arguments
        for pat in SUSPICIOUS_CMD_PATTERNS:
            if pat.search(command):
                is_threat = True
                threat_reason = "SuspiciousStartupArgument"
                tier = 3
                break

        # If file exists on disk, run through full static evaluation
        if exists and not is_threat:
            verdict = self.scanner.scan_file(target_path)
            if verdict.is_malicious():
                is_threat = True
                threat_reason = verdict.reason
                tier = verdict.tier

        return {
            "name": name,
            "location": location,
            "command": command,
            "target_path": target_path,
            "file_exists": exists,
            "is_threat": is_threat,
            "reason": threat_reason if is_threat else "Benign",
            "tier": tier
        }

    def remove_registry_entry(self, location: str, value_name: str) -> bool:
        """Removes an autorun value from registry if confirmed malicious."""
        root_map = {
            "HKCU\\Run": (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            "HKCU\\RunOnce": (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            "HKLM\\Run": (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            "HKLM\\RunOnce": (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        }

        if location not in root_map:
            return False

        root_key, subkey = root_map[location]
        try:
            with winreg.OpenKey(root_key, subkey, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, value_name)
                return True
        except OSError:
            return False
