"""
Interactive Management Console & Dashboard for SentinelCore
Allows viewing real-time shield status, inspecting quarantine history,
triggering on-demand file/folder scans, and restoring false positives.
"""

import os
import sys
import time
from typing import List

from sentinel_scanner.engine import SentinelScanner, ScanVerdict
from sentinel_vault.vault import QuarantineVault

class SentinelConsole:
    def __init__(self, scanner: SentinelScanner, vault: QuarantineVault):
        self.scanner = scanner
        self.vault = vault

    def print_banner(self):
        print("""
========================================================================
   ____             _   _            _  ____                
  / ___|  ___ _ __ | |_(_)_ __   ___| |/ ___|___  _ __ ___ 
  \\___ \\ / _ \\ '_ \\| __| | '_ \\ / _ \\ | |   / _ \\| '__/ _ \\
   ___) |  __/ | | | |_| | | | |  __/ | |__| (_) | | |  __/
  |____/ \\___|_| |_|\\__|_|_| |_|\\___|_|\\____\\___/|_|  \\___|
        Personal Antivirus & Advanced Malware Prevention
========================================================================
        """)

    def print_status(self, is_guard_active: bool = True):
        quarantined = self.vault.list_quarantined()
        active_quarantine_count = sum(1 for item in quarantined if not item.get("is_restored"))

        print(f"[*] REAL-TIME SHIELD STATUS: {'[PROTECTED / ACTIVE]' if is_guard_active else '[STANDBY]'}")
        print(f"[*] REPUTATION CACHE SIZE:   {len(self.scanner.cache)} active signatures")
        print(f"[*] QUARANTINE VAULT:        {active_quarantine_count} neutralized threats isolated")
        print("="*72)

    def scan_directory(self, target_dir: str):
        """Runs an on-demand scan of a folder."""
        target_dir = os.path.abspath(target_dir)
        if not os.path.exists(target_dir):
            print(f"[!] Path does not exist: {target_dir}")
            return

        print(f"\n[*] Starting on-demand scan of: {target_dir}")
        scanned_count = 0
        threat_count = 0
        t0 = time.time()

        for root, _, files in os.walk(target_dir):
            for file in files:
                file_path = os.path.join(root, file)
                scanned_count += 1
                try:
                    verdict = self.scanner.scan_file(file_path)
                    if verdict.is_malicious():
                        threat_count += 1
                        print(f" [!] THREAT DETECTED: {file_path}")
                        print(f"     Reason: {verdict.reason} (Tier {verdict.tier})")
                        v_id = self.vault.isolate_file(file_path, reason=verdict.reason)
                        print(f"     Action: Isolated to Quarantine Vault (ID: {v_id[:8]}...)")
                except Exception as e:
                    pass

        elapsed = time.time() - t0
        print(f"\n[+] Scan Complete in {elapsed:.2f}s")
        print(f"    Total Files Scanned: {scanned_count}")
        print(f"    Threats Neutralized: {threat_count}")

    def show_quarantine(self):
        items = self.vault.list_quarantined()
        if not items:
            print("[*] Quarantine vault is currently empty.")
            return

        print("\n--- QUARANTINED THREATS ---")
        for item in items:
            status = "RESTORED" if item.get("is_restored") else "ISOLATED"
            print(f" - [{status}] ID: {item['vault_id']}")
            print(f"   Original Path: {item['original_path']}")
            print(f"   Reason:        {item['reason']}")
            print(f"   Time:          {item['quarantine_time']}")
            print()

    def restore_quarantine_item(self, vault_id: str):
        try:
            self.vault.restore_file(vault_id)
            print(f"[+] Successfully restored item {vault_id} to original path.")
        except Exception as e:
            print(f"[!] Restoration failed: {e}")
