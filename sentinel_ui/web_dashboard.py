"""
Embedded Web Management Dashboard & REST API for SentinelCore Antivirus
Serves a modern web UI on http://127.0.0.1:8765 using Python standard library http.server.
Provides real-time shield status, on-demand scanning, and quarantine management.
"""

import os
import sys
import json
import time
import threading
import webbrowser
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Optional, Dict, Any, List

from sentinel_scanner.engine import SentinelScanner, VERDICT_ALLOW, VERDICT_BLOCK, VERDICT_QUARANTINE
from sentinel_vault.vault import QuarantineVault
from sentinel_guard.watcher import FilesystemWatcher
from sentinel_guard.process_monitor import ProcessMonitor
from sentinel_behavior.ransomware_shield import RansomwareShield

class SentinelWebHandler(BaseHTTPRequestHandler):
    scanner: SentinelScanner
    vault: QuarantineVault
    fs_watcher: Optional[FilesystemWatcher] = None
    proc_monitor: Optional[ProcessMonitor] = None
    ransomware_shield: Optional[RansomwareShield] = None

    def log_message(self, format, *args):
        # Suppress noisy standard HTTP access logs
        return

    def _send_json(self, status_code: int, data: Any):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def _read_json_body(self) -> Dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            return {}
        body = self.rfile.read(content_length)
        return json.loads(body.decode("utf-8", errors="ignore"))

    def do_GET(self):
        url = self.path.split("?")[0]

        if url == "/" or url == "/index.html":
            static_dir = os.path.join(os.path.dirname(__file__), "static")
            index_path = os.path.join(static_dir, "index.html")
            if os.path.exists(index_path):
                with open(index_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_response(404)
                self.end_headers()
            return

        if url == "/api/status":
            quarantined = self.vault.list_quarantined()
            active_threats = sum(1 for item in quarantined if not item.get("is_restored"))

            recent_events = []
            if self.fs_watcher and hasattr(self.fs_watcher, "recent_events"):
                recent_events.extend(list(self.fs_watcher.recent_events))
            if self.proc_monitor and hasattr(self.proc_monitor, "recent_events"):
                recent_events.extend(list(self.proc_monitor.recent_events))

            sig_summary = self.scanner.get_signatures_summary()

            data = {
                "status": "PROTECTED",
                "reputation_cache_size": len(self.scanner.cache),
                "active_quarantined_threats": active_threats,
                "total_quarantined": len(quarantined),
                "signatures_count": sig_summary.get("tier3_signatures_count", 20),
                "fs_events_processed": getattr(self.fs_watcher, "events_processed", 0) if self.fs_watcher else 0,
                "fs_threats_blocked": getattr(self.fs_watcher, "threats_blocked", 0) if self.fs_watcher else 0,
                "procs_inspected": getattr(self.proc_monitor, "inspected_count", 0) if self.proc_monitor else 0,
                "procs_blocked": getattr(self.proc_monitor, "blocked_count", 0) if self.proc_monitor else 0,
                "recent_events": recent_events[-25:]
            }
            self._send_json(200, data)
            return

        if url == "/api/quarantine":
            items = self.vault.list_quarantined()
            self._send_json(200, items)
            return

        if url == "/api/signatures":
            summary = self.scanner.get_signatures_summary()
            self._send_json(200, summary)
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        url = self.path.split("?")[0]

        if url == "/api/scan":
            body = self._read_json_body()
            target_path = body.get("path", "").strip()
            if not target_path or not os.path.exists(target_path):
                self._send_json(400, {"error": "Invalid or non-existent path"})
                return

            results: List[Dict[str, Any]] = []
            scanned_count = 0
            threat_count = 0
            t0 = time.time()

            if os.path.isfile(target_path):
                files_to_scan = [target_path]
            else:
                files_to_scan = []
                for root, _, files in os.walk(target_path):
                    for f in files:
                        files_to_scan.append(os.path.join(root, f))
                        if len(files_to_scan) >= 1000:  # safety cap for on-demand batch
                            break
                    if len(files_to_scan) >= 1000:
                        break

            for fp in files_to_scan:
                scanned_count += 1
                try:
                    verdict = self.scanner.scan_file(fp)
                    if verdict.is_malicious():
                        threat_count += 1
                        vault_id = self.vault.isolate_file(fp, reason=verdict.reason)
                        results.append({
                            "file": fp,
                            "verdict": verdict.verdict,
                            "reason": verdict.reason,
                            "tier": verdict.tier,
                            "scan_time_ms": verdict.scan_time_ms,
                            "vault_id": vault_id
                        })
                    elif len(results) < 20 and not verdict.is_malicious() and scanned_count <= 10:
                        results.append({
                            "file": fp,
                            "verdict": verdict.verdict,
                            "reason": "Clean",
                            "tier": verdict.tier,
                            "scan_time_ms": verdict.scan_time_ms,
                            "vault_id": None
                        })
                except Exception:
                    pass

            elapsed = round(time.time() - t0, 3)
            self._send_json(200, {
                "elapsed_seconds": elapsed,
                "total_scanned": scanned_count,
                "threats_found": threat_count,
                "results": results
            })
            return

        if url == "/api/quarantine/restore":
            body = self._read_json_body()
            vault_id = body.get("vault_id")
            if not vault_id:
                self._send_json(400, {"error": "Missing vault_id"})
                return
            try:
                ok = self.vault.restore_file(vault_id)
                self._send_json(200, {"success": ok, "message": f"Successfully restored {vault_id}"})
            except Exception as e:
                self._send_json(500, {"error": str(e)})
            return

        if url == "/api/quarantine/delete":
            body = self._read_json_body()
            vault_id = body.get("vault_id")
            if not vault_id:
                self._send_json(400, {"error": "Missing vault_id"})
                return
            try:
                ok = self.vault.delete_quarantined(vault_id)
                self._send_json(200, {"success": ok, "message": f"Deleted {vault_id}"})
            except Exception as e:
                self._send_json(500, {"error": str(e)})
            return

        if url == "/api/quarantine/purge":
            try:
                purged = self.vault.purge_all()
                self._send_json(200, {"success": True, "purged_count": purged})
            except Exception as e:
                self._send_json(500, {"error": str(e)})
            return

        self.send_response(404)
        self.end_headers()

class SentinelWebServer:
    def __init__(
        self,
        scanner: SentinelScanner,
        vault: QuarantineVault,
        fs_watcher: Optional[FilesystemWatcher] = None,
        proc_monitor: Optional[ProcessMonitor] = None,
        ransomware_shield: Optional[RansomwareShield] = None,
        host: str = "127.0.0.1",
        port: int = 8765
    ):
        self.host = host
        self.port = port
        self.server: Optional[ThreadingHTTPServer] = None
        self.thread: Optional[threading.Thread] = None

        class BoundHandler(SentinelWebHandler):
            pass

        BoundHandler.scanner = scanner
        BoundHandler.vault = vault
        BoundHandler.fs_watcher = fs_watcher
        BoundHandler.proc_monitor = proc_monitor
        BoundHandler.ransomware_shield = ransomware_shield

        self.handler_class = BoundHandler

    def start(self, open_browser: bool = False):
        try:
            self.server = ThreadingHTTPServer((self.host, self.port), self.handler_class)
        except OSError:
            # Fallback to alternative port if 8765 is taken
            self.port += 1
            self.server = ThreadingHTTPServer((self.host, self.port), self.handler_class)

        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        url = f"http://{self.host}:{self.port}"
        print(f"[+] SentinelCore Web Dashboard live at: {url}", flush=True)

        if open_browser:
            webbrowser.open(url)

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
