"""
SentinelCore Master Service & Personal Antivirus Launcher
Starts real-time filesystem protection, ransomware defense, process execution guard,
and the management dashboard.
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
from sentinel_ui.web_dashboard import SentinelWebServer

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
    parser.add_argument("--web", action="store_true", help="Launch interactive web management dashboard in browser")
    parser.add_argument("--port", type=int, default=8765, help="Port for web dashboard (default: 8765)")
    args = parser.parse_args()

    # 1. Initialize Core Engines
    vault = QuarantineVault()
    scanner = SentinelScanner()
    console = SentinelConsole(scanner=scanner, vault=vault)

    # 2. Check if single on-demand scan requested
    if args.scan:
        console.print_banner()
        console.scan_directory(args.scan)
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

    # 4. Initialize Web Dashboard Server
    web_server = SentinelWebServer(
        scanner=scanner,
        vault=vault,
        fs_watcher=fs_watcher,
        proc_monitor=proc_monitor,
        ransomware_shield=ransomware_shield,
        port=args.port
    )

    # 5. Start Background Real-Time Protection
    console.print_banner()
    print("[+] Starting Real-Time Filesystem Guard (Downloads, Desktop, Documents, Temp)...", flush=True)
    fs_watcher.start()

    print("[+] Starting Process Execution & Memory Guard...", flush=True)
    proc_monitor.start()

    print("[+] Starting Dual-Invariant Ransomware Shield...", flush=True)
    console.print_status(is_guard_active=True)

    # Start Web Dashboard
    web_server.start(open_browser=args.web)

    if args.daemon:
        print("[*] Running in headless daemon mode. Web UI active. Press Ctrl+C to terminate.", flush=True)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Stopping SentinelCore shields...", flush=True)
            fs_watcher.stop()
            proc_monitor.stop()
            web_server.stop()
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
    print("  web                  - Open Web Management Dashboard in default browser")
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
            elif action == "web":
                import webbrowser
                webbrowser.open(f"http://127.0.0.1:{args.port}")
                print(f"[+] Opened Web Dashboard in browser: http://127.0.0.1:{args.port}", flush=True)
            else:
                print(f"[!] Unknown command: {action}. Type 'scan', 'status', 'quarantine', 'restore', 'delete', 'purge', 'stats', 'signatures', 'events', 'web', or 'exit'.", flush=True)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        print("\n[*] Stopping SentinelCore shields...", flush=True)
        fs_watcher.stop()
        proc_monitor.stop()
        web_server.stop()
        print("[+] All shields stopped safely.", flush=True)

if __name__ == "__main__":
    main()

