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
        """, flush=True)

    def print_status(self, is_guard_active: bool = True):
        quarantined = self.vault.list_quarantined()
        active_quarantine_count = sum(1 for item in quarantined if not item.get("is_restored"))

        print(f"[*] REAL-TIME SHIELD STATUS: {'[PROTECTED / ACTIVE]' if is_guard_active else '[STANDBY]'}", flush=True)
        print(f"[*] REPUTATION CACHE SIZE:   {len(self.scanner.cache)} active signatures", flush=True)
        print(f"[*] QUARANTINE VAULT:        {active_quarantine_count} neutralized threats isolated", flush=True)
        print("="*72, flush=True)

    def scan_directory(self, target_dir: str):
        """Runs an on-demand scan of a folder with streaming progress."""
        target_dir = os.path.abspath(target_dir)
        if not os.path.exists(target_dir):
            print(f"[!] Path does not exist: {target_dir}", flush=True)
            return

        print(f"\n[*] Starting on-demand scan of: {target_dir}", flush=True)
        scanned_count = 0
        threat_count = 0
        t0 = time.time()

        for root, _, files in os.walk(target_dir):
            for file in files:
                file_path = os.path.join(root, file)
                scanned_count += 1

                if scanned_count % 50 == 0 or scanned_count == 1:
                    print(f"[*] Progress: {scanned_count} files scanned...", flush=True)

                try:
                    verdict = self.scanner.scan_file(file_path)
                    if verdict.is_malicious():
                        threat_count += 1
                        print(f"\n [!] >>> THREAT INTERCEPTED <<<", flush=True)
                        print(f"     File:   {file_path}", flush=True)
                        print(f"     Reason: {verdict.reason} (Tier {verdict.tier})", flush=True)
                        v_id = self.vault.isolate_file(file_path, reason=verdict.reason)
                        print(f"     Action: Neutralized & Encrypted into Vault (ID: {v_id[:8]}...)\n", flush=True)
                except Exception:
                    pass

        elapsed = time.time() - t0
        print(f"\n[+] Scan Complete in {elapsed:.2f}s", flush=True)
        print(f"    Total Files Scanned: {scanned_count}", flush=True)
        print(f"    Threats Neutralized: {threat_count}", flush=True)

    def show_quarantine(self):
        items = self.vault.list_quarantined()
        if not items:
            print("[*] Quarantine vault is currently empty.", flush=True)
            return

        print("\n--- QUARANTINED THREATS ---", flush=True)
        for item in items:
            status = "RESTORED" if item.get("is_restored") else "ISOLATED"
            print(f" - [{status}] ID: {item['vault_id']}", flush=True)
            print(f"   Original Path: {item['original_path']}", flush=True)
            print(f"   Reason:        {item['reason']}", flush=True)
            print(f"   Time:          {item['quarantine_time']}", flush=True)
            print(flush=True)

    def restore_quarantine_item(self, vault_id: str):
        try:
            self.vault.restore_file(vault_id)
            print(f"[+] Successfully restored item {vault_id} to original path.", flush=True)
        except Exception as e:
            print(f"[!] Restoration failed: {e}", flush=True)

    def delete_quarantine_item(self, vault_id: str):
        try:
            if self.vault.delete_quarantined(vault_id):
                print(f"[+] Permanently shredded and deleted threat {vault_id} from vault.", flush=True)
            else:
                print(f"[!] Item {vault_id} not found in quarantine.", flush=True)
        except Exception as e:
            print(f"[!] Deletion failed: {e}", flush=True)

    def purge_quarantine(self):
        try:
            purged = self.vault.purge_all()
            print(f"[+] Vault Purge Complete: {purged} threat archives permanently shredded.", flush=True)
        except Exception as e:
            print(f"[!] Purge failed: {e}", flush=True)

    def show_vault_stats(self):
        stats = self.vault.get_vault_stats()
        print("\n--- QUARANTINE VAULT METRICS ---", flush=True)
        print(f"[*] Total Quarantined: {stats['total_quarantined']}", flush=True)
        print(f"[*] Active Threats:    {stats['active_threats']}", flush=True)
        print(f"[*] Restored Items:    {stats['restored_count']}", flush=True)
        print(f"[*] Isolated Bytes:    {stats['active_bytes']:,} bytes", flush=True)
        print(f"[*] Storage Path:      {stats['vault_path']}\n", flush=True)

    def show_signatures(self):
        summary = self.scanner.get_signatures_summary()
        print("\n--- SENTINEL DETECTION SIGNATURES ---", flush=True)
        print(f"[*] Tier 1 Cache Entries: {summary['tier1_cache_entries']} / {summary['tier1_cache_capacity']}", flush=True)
        print(f"[*] Tier 2 Entropy Limit: {summary['tier2_entropy_threshold']} (UPX: {summary['tier2_upx_entropy_threshold']})", flush=True)
        print(f"[*] Tier 3 Threat Rules:  {summary['tier3_signatures_count']} loaded signatures", flush=True)
        for sig in summary["signatures"]:
            print(f"    - {sig}", flush=True)
        print()

    def show_recent_events(self, fs_watcher=None, proc_monitor=None):
        print("\n--- RECENT SECURITY EVENT LOG ---", flush=True)
        events = []
        if fs_watcher and hasattr(fs_watcher, "recent_events"):
            events.extend(list(fs_watcher.recent_events))
        if proc_monitor and hasattr(proc_monitor, "recent_events"):
            events.extend(list(proc_monitor.recent_events))

        if not events:
            print("[*] No security events logged yet.", flush=True)
            return

        events.sort(key=lambda x: x.get("timestamp", ""))
        for ev in events[-15:]:
            print(f"[{ev.get('timestamp')}] {ev.get('type')}: {ev.get('reason', '')} {ev.get('path', ev.get('process', ''))}", flush=True)
        print()

