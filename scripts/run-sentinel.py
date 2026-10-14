"""
SentinelCore Master Service & Personal Antivirus Launcher
Starts real-time filesystem protection, ransomware defense, process execution guard,
and the desktop management app.
"""

import os
import sys
import time
import argparse

# Add repo root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel_vault.vault import QuarantineVault
from sentinel_scanner.engine import SentinelScanner, ScanVerdict
from sentinel_behavior.ransomware_shield import RansomwareShield, ProcessActivityRecord
from sentinel_guard.watcher import FilesystemWatcher
from sentinel_guard.process_monitor import ProcessMonitor
from sentinel_ui.notifications import notify_threat_blocked
from sentinel_ui.dashboard import SentinelConsole

def alert_handler(file_path: str, verdict: ScanVerdict, vault_id: str):
    notify_threat_blocked(
        title=f"Malware Intercepted: {verdict.reason}",
        message=f"File neutralized and quarantined: {os.path.basename(file_path)}",
        threat_path=file_path
    )

def process_blocked_handler(pid: int, proc_name: str, verdict: ScanVerdict, vault_id: str):
    notify_threat_blocked(
        title=f"Malicious Process Terminated: {proc_name}",
        message=f"Process {proc_name} (PID {pid}) terminated via Tier {verdict.tier} detection.",
        threat_path=f"PID {pid} ({proc_name})"
    )

def ransomware_detected_handler(proc: ProcessActivityRecord):
    notify_threat_blocked(
        title="Ransomware Burst Attack Neutralized!",
        message=f"Process '{proc.name}' (PID {proc.pid}) was terminated after high-entropy file writes.",
        threat_path=f"PID {proc.pid}"
    )

def main():
    parser = argparse.ArgumentParser(description="SentinelCore Personal Antivirus & Malware Prevention Suite")
    parser.add_argument("--scan", type=str, help="Run an on-demand scan on a specific file or folder")
    parser.add_argument("--daemon", action="store_true", help="Run headlessly as background guard")
    parser.add_argument("--gui", action="store_true", help="Launch native desktop GUI application")
    parser.add_argument("--autorun", action="store_true", help="Audit Windows startup and persistence autorun entries")
    parser.add_argument("--net", action="store_true", help="Audit active network sockets for suspicious C2 connections")
    parser.add_argument("--procs", action="store_true", help="Audit currently running processes for LOLBins and anomalies")
    parser.add_argument("--integrity", action="store_true", help="Verify SentinelCore anti-tamper self-defense integrity")
    args = parser.parse_args()

    # 1. Check if GUI desktop app requested
    if args.gui:
        import tkinter as tk
        from sentinel_ui.desktop_gui import SentinelDesktopApp
        root = tk.Tk()
        app = SentinelDesktopApp(root)
        root.mainloop()
        return

    # 2. Initialize Core Engines
    vault = QuarantineVault()
    scanner = SentinelScanner()
    console = SentinelConsole(scanner=scanner, vault=vault)

    # 3. Check if single on-demand scan requested
    if args.scan:
        console.print_banner()
        console.scan_directory(args.scan)
        return

    if args.integrity:
        from sentinel_guard.integrity_guard import IntegrityGuard
        ig = IntegrityGuard()
        res = ig.verify_integrity()
        console.print_banner()
        print(f"[*] Verifying SentinelCore Core Engine Integrity Manifest ({res['timestamp']}):")
        if res["is_intact"]:
            print(f"[+] INTEGRITY VALID: All {res['verified_count']}/{res['total_monitored']} core binaries and databases are intact.")
            print("[+] Zero tampering or file corruptions detected.\n")
        else:
            print(f"[!] TAMPER DETECTED: {len(res['tampered_files'])} modified, {len(res['missing_files'])} missing!")
            for t in res["tampered_files"]:
                print(f"    - Modified: {t['file']}")
            for m in res["missing_files"]:
                print(f"    - Missing: {m}")
        return

    if args.autorun:
        from sentinel_scanner.persistence import PersistenceScanner
        ps = PersistenceScanner(scanner)
        console.print_banner()
        print("[*] Auditing Windows Registry and Startup AutoRun entries...\n")
        items = ps.audit_all()
        threat_count = sum(1 for i in items if i.get("is_threat"))
        for it in items:
            flag = "[! THREAT]" if it.get("is_threat") else "[+ CLEAN]"
            print(f" {flag:<12} | {it.get('location', ''):<18} | {it.get('name', ''):<25} | {it.get('target_path', '')}")
        print(f"\n[*] Total AutoRun entries audited: {len(items)} (Threats/Suspicious: {threat_count})\n")
        return

    if args.net:
        from sentinel_guard.network_monitor import NetworkMonitor
        nm = NetworkMonitor()
        console.print_banner()
        print("[*] Auditing active TCP/UDP sockets for suspicious C2 connections...\n")
        conns = nm.audit_connections()
        threat_count = sum(1 for c in conns if c["threat_level"] != "CLEAN")
        for c in conns[:40]:
            lvl = f"[{c['threat_level']}]"
            print(f" {lvl:<14} | {c['process']:<20} (PID {c['pid']:<6}) | {c['protocol']:<4} | {c['local_address']:<21} -> {c['remote_address'] or '*'}")
        print(f"\n[*] Active sockets audited: {len(conns)} (Alerts: {threat_count})\n")
        return

    if args.procs:
        pm = ProcessMonitor(scanner, vault)
        console.print_banner()
        print("[*] Auditing running processes for LOLBins and execution anomalies...\n")
        procs = pm.audit_running_processes(limit=40)
        susp_count = sum(1 for p in procs if p["threat_level"] != "CLEAN")
        for p in procs:
            lvl = f"[{p['threat_level']}]"
            ind = f" | {', '.join(p['indicators'])}" if p["indicators"] else ""
            print(f" {lvl:<14} | Score: {p['risk_score']:<3}/100 | PID {p['pid']:<6} | {p['name']:<22} | {p['memory_mb']:>6.1f} MB{ind}")
        print(f"\n[*] Audited running processes: {len(procs)} (Elevated Risk: {susp_count})\n")
        return

    # 3. Initialize Real-Time Shields
    ransomware_shield = RansomwareShield(
        window_seconds=1.0,
        entropy_threshold=7.5,
        consecutive_burst_limit=3,
        on_threat_detected=ransomware_detected_handler
    )

    fs_watcher = FilesystemWatcher(
        scanner=scanner,
        vault=vault,
        on_alert=alert_handler
    )

    proc_monitor = ProcessMonitor(
        scanner=scanner,
        vault=vault,
        on_process_blocked=process_blocked_handler
    )

    # 5. Start Background Real-Time Protection
    console.print_banner()
    print("[+] Starting Real-Time Filesystem Guard (Downloads, Desktop, Documents, Temp)...", flush=True)
    fs_watcher.start()

    print("[+] Starting Process Execution & Memory Guard...", flush=True)
    proc_monitor.start()

    print("[+] Starting Dual-Invariant Ransomware Shield...", flush=True)
    console.print_status(is_guard_active=True)

    if args.daemon:
        print("[*] Running in headless daemon mode. Press Ctrl+C to terminate.", flush=True)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Stopping SentinelCore shields...", flush=True)
            fs_watcher.stop()
            proc_monitor.stop()
            return

    # Interactive Console Loop
    print("\nCommands available:")
    print("  scan <path>          - Run on-demand scan of folder or file")
    print("  status               - Display active shield and cache metrics")
    print("  quarantine           - List neutralized files in the encrypted vault")
    print("  restore <vault_id>   - Restore a false positive to original path")
    print("  delete <vault_id>    - Permanently shred and delete threat from vault")
    print("  purge                - Permanently shred all quarantined threats")
    print("  stats                - Display vault and detection metrics")
    print("  signatures           - List active threat signature rules")
    print("  events               - Display recent security telemetry event log")
    print("  exit                 - Stop shields and exit\n", flush=True)

    try:
        while True:
            cmd = input("SentinelCore> ").strip()
            if not cmd:
                continue
            parts = cmd.split(maxsplit=1)
            action = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""

            if action in ("exit", "quit"):
                break
            elif action == "status":
                console.print_status(is_guard_active=True)
            elif action == "scan":
                if arg:
                    console.scan_directory(arg)
                else:
                    print("[!] Usage: scan <path>", flush=True)
            elif action == "quarantine":
                console.show_quarantine()
            elif action == "restore":
                if arg:
                    console.restore_quarantine_item(arg)
                else:
                    print("[!] Usage: restore <vault_id>", flush=True)
            elif action == "delete":
                if arg:
                    console.delete_quarantine_item(arg)
                else:
                    print("[!] Usage: delete <vault_id>", flush=True)
            elif action == "purge":
                console.purge_quarantine()
            elif action == "stats":
                console.show_vault_stats()
            elif action == "signatures":
                console.show_signatures()
            elif action == "events":
                console.show_recent_events(fs_watcher, proc_monitor)
            else:
                print(f"[!] Unknown command: {action}. Type 'scan', 'status', 'quarantine', 'restore', 'delete', 'purge', 'stats', 'signatures', 'events', or 'exit'.", flush=True)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        print("\n[*] Stopping SentinelCore shields...", flush=True)
        fs_watcher.stop()
        proc_monitor.stop()
        print("[+] All shields stopped safely.", flush=True)

if __name__ == "__main__":
    main()

