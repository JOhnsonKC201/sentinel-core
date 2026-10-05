"""
Real-Time Filesystem Watcher for SentinelCore
Monitors user Downloads, Desktop, Documents, and Staging paths for suspicious file creations,
new executables, and high-frequency ransomware alterations using Win32 ReadDirectoryChangesW.
"""

import os
import time
import threading
from typing import List, Callable, Optional, Set
import win32file
import win32con

from sentinel_scanner.engine import SentinelScanner, ScanVerdict, VERDICT_ALLOW
from sentinel_vault.vault import QuarantineVault

MONITORED_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".pif",
    ".iso", ".vhd", ".locked", ".crypto"
}

class FilesystemWatcher:
    def __init__(
        self,
        scanner: SentinelScanner,
        vault: QuarantineVault,
        watch_dirs: Optional[List[str]] = None,
        on_alert: Optional[Callable[[str, ScanVerdict, str], None]] = None
    ):
        self.scanner = scanner
        self.vault = vault
        self.on_alert = on_alert
        self.is_running = False
        self.threads: List[threading.Thread] = []

        if watch_dirs is None:
            user_profile = os.environ.get("USERPROFILE", r"C:\Users\johns")
            watch_dirs = [
                os.path.join(user_profile, "Downloads"),
                os.path.join(user_profile, "Desktop"),
                os.path.join(user_profile, "Documents"),
                os.environ.get("TEMP", r"C:\Users\johns\AppData\Local\Temp")
            ]
        # Only watch directories that exist
        self.watch_dirs = [os.path.abspath(d) for d in watch_dirs if os.path.exists(d)]
        self._scanned_hashes: Set[str] = set()

    def start(self):
        """Starts real-time filesystem watchers in background threads."""
        self.is_running = True
        for directory in self.watch_dirs:
            t = threading.Thread(target=self._watch_directory, args=(directory,), daemon=True)
            t.start()
            self.threads.append(t)

    def stop(self):
        """Stops all watcher threads."""
        self.is_running = False

    def _watch_directory(self, path: str):
        """Win32 ReadDirectoryChangesW event loop for a directory."""
        try:
            hDir = win32file.CreateFile(
                path,
                win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_FLAG_BACKUP_SEMANTICS,
                None
            )
        except Exception:
            return

        flags = (
            win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
            win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
            win32con.FILE_NOTIFY_CHANGE_SIZE
        )

        buffer = bytearray(32768)
        while self.is_running:
            try:
                results = win32file.ReadDirectoryChangesW(
                    hDir,
                    buffer,
                    True,  # watch subtree
                    flags,
                    None,
                    None
                )
                for action, filename in results:
                    full_path = os.path.join(path, filename)
                    # Check action: 1=Added, 3=Modified, 4=Renamed Old, 5=Renamed New
                    if action in (1, 3, 5):
                        self._handle_file_event(full_path)
            except Exception:
                time.sleep(0.5)

    def _handle_file_event(self, file_path: str):
        """Evaluates a newly modified or created file."""
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            return

        _, ext = os.path.splitext(file_path.lower())
        if ext not in MONITORED_EXTENSIONS:
            return

        # Slight delay to ensure writer closed handle
        time.sleep(0.05)
        if not os.path.exists(file_path):
            return

        verdict = self.scanner.scan_file(file_path)
        if verdict.is_malicious():
            vault_id = self.vault.isolate_file(file_path, reason=verdict.reason)
            if self.on_alert:
                self.on_alert(file_path, verdict, vault_id)
