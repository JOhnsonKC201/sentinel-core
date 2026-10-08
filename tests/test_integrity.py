"""
Automated Unit Tests for SentinelCore Anti-Tamper Integrity Guard
Verifies baseline hashing, tamper detection upon file alteration, and missing file detection.
"""

import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from sentinel_guard.integrity_guard import IntegrityGuard

def test_integrity_guard():
    temp_dir = tempfile.mkdtemp()
    try:
        # Create mock core target files in temp dir
        scanner_dir = os.path.join(temp_dir, "sentinel_scanner")
        os.makedirs(scanner_dir, exist_ok=True)
        file1 = os.path.join(scanner_dir, "engine.py")
        with open(file1, "wb") as f:
            f.write(b"def scan(): pass")

        guard_dir = os.path.join(temp_dir, "sentinel_guard")
        os.makedirs(guard_dir, exist_ok=True)
        file2 = os.path.join(guard_dir, "watcher.py")
        with open(file2, "wb") as f:
            f.write(b"def watch(): pass")

        manifest_file = os.path.join(temp_dir, "manifest.json")
        guard = IntegrityGuard(base_dir=temp_dir, manifest_path=manifest_file)
        guard.generate_and_save_baseline()

        # 1. Initial State: Should be completely intact
        res1 = guard.verify_integrity()
        assert res1["is_intact"] is True
        assert res1["status"] == "VALID"
        assert res1["verified_count"] == 2
        assert len(res1["tampered_files"]) == 0

        # 2. Tamper State: Alter file1 content
        with open(file1, "wb") as f:
            f.write(b"MALICIOUS_INJECTED_TAMPER_CODE")

        res2 = guard.verify_integrity()
        assert res2["is_intact"] is False
        assert res2["status"] == "TAMPER_DETECTED"
        assert len(res2["tampered_files"]) == 1
        assert res2["tampered_files"][0]["file"] == os.path.join("sentinel_scanner", "engine.py")

        # 3. Missing State: Delete file2
        os.remove(file2)
        res3 = guard.verify_integrity()
        assert res3["is_intact"] is False
        assert len(res3["missing_files"]) == 1

        print("[+] test_integrity_guard: PASSED (Integrity verification and tamper detection validated)")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    test_integrity_guard()
