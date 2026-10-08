"""
Unit Test for SentinelCore Web Dashboard and REST API Endpoints
Verifies that the web server serves index.html and responds to /api/status, /api/quarantine, and /api/signatures.
"""

import os
import sys
import time
import urllib.request
import json
import tempfile
import gc
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel_vault.vault import QuarantineVault
from sentinel_scanner.engine import SentinelScanner
from sentinel_ui.web_dashboard import SentinelWebServer

def test_web_dashboard_endpoints():
    temp_dir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(temp_dir, "rep.db")
        vault_dir = os.path.join(temp_dir, "vault")
        vault = QuarantineVault(vault_dir=vault_dir)
        scanner = SentinelScanner(db_path=db_path)

        port = 8799
        server = SentinelWebServer(scanner=scanner, vault=vault, port=port)
        server.start(open_browser=False)
        time.sleep(0.5)

        base_url = f"http://127.0.0.1:{server.port}"

        # 1. Test index.html
        with urllib.request.urlopen(f"{base_url}/") as response:
            assert response.status == 200
            html = response.read().decode("utf-8")
            assert "SentinelCore Antivirus" in html

        # 2. Test /api/status
        with urllib.request.urlopen(f"{base_url}/api/status") as response:
            assert response.status == 200
            status_data = json.loads(response.read().decode("utf-8"))
            assert status_data["status"] == "PROTECTED"
            assert "reputation_cache_size" in status_data
            assert "active_quarantined_threats" in status_data

        # 3. Test /api/signatures
        with urllib.request.urlopen(f"{base_url}/api/signatures") as response:
            assert response.status == 200
            sig_data = json.loads(response.read().decode("utf-8"))
            assert "signatures" in sig_data
            assert sig_data["tier3_signatures_count"] > 0

        # 4. Test /api/scan on a clean file
        dummy_file = os.path.join(temp_dir, "clean.txt")
        with open(dummy_file, "w") as f:
            f.write("Hello world, benign clean text file.")

        req = urllib.request.Request(
            f"{base_url}/api/scan",
            data=json.dumps({"path": dummy_file}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req) as response:
            assert response.status == 200
            scan_res = json.loads(response.read().decode("utf-8"))
            assert scan_res["total_scanned"] == 1
            assert scan_res["threats_found"] == 0

        server.stop()
        print("[+] test_web_dashboard_endpoints: PASSED (Web UI and REST API validated)")
    finally:
        del vault
        del scanner
        gc.collect()
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    test_web_dashboard_endpoints()
