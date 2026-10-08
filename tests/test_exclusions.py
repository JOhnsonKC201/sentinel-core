"""
Automated Unit Tests for SentinelCore Exclusion & Whitelist Manager
Verifies path exclusion, folder hierarchy exclusions, and SHA-256 hash whitelisting.
"""

import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from sentinel_scanner.exclusions import ExclusionManager
from sentinel_scanner.engine import SentinelScanner, VERDICT_ALLOW, VERDICT_QUARANTINE

def test_exclusions_manager():
    temp_dir = tempfile.mkdtemp()
    try:
        cfg = os.path.join(temp_dir, "test_exclusions.json")
        mgr = ExclusionManager(config_path=cfg)

        # 1. Path Exclusions
        safe_dir = os.path.join(temp_dir, "safe_folder")
        os.makedirs(safe_dir, exist_ok=True)
        safe_file = os.path.join(safe_dir, "tool.exe")
        with open(safe_file, "wb") as f:
            f.write(b"SAFE_CONTENT")

        assert not mgr.is_path_excluded(safe_file)

        mgr.add_path_exclusion(safe_dir)
        assert mgr.is_path_excluded(safe_file)
        assert mgr.is_path_excluded(safe_dir)

        # 2. Hash Exclusions
        dummy_hash = "a" * 64
        assert not mgr.is_hash_excluded(dummy_hash)

        mgr.add_hash_exclusion(dummy_hash)
        assert mgr.is_hash_excluded(dummy_hash)

        # 3. Persistence Reload Check
        mgr2 = ExclusionManager(config_path=cfg)
        assert mgr2.is_path_excluded(safe_file)
        assert mgr2.is_hash_excluded(dummy_hash)

        # 4. Scanner Integration Check
        scanner = SentinelScanner()
        scanner.exclusions = mgr

        # EICAR test string normally quarantined
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        import hashlib
        eicar_hash = hashlib.sha256(eicar).hexdigest()

        # Without hash whitelist -> Quarantined
        v1 = scanner.scan_bytes(eicar)
        assert v1.verdict == VERDICT_QUARANTINE

        # Whitelist EICAR hash
        mgr.add_hash_exclusion(eicar_hash)
        v2 = scanner.scan_bytes(eicar)
        assert v2.verdict == VERDICT_ALLOW
        assert "AllowlistedHash" in v2.reason

        print("[+] test_exclusions_manager: PASSED (Path and hash whitelisting verified)")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    test_exclusions_manager()
