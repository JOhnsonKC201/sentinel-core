"""
Automated Unit Tests for SentinelCore Static Scanner
Verifies Tier 1 Cache Hits, Tier 2 Shannon Entropy Gating, and Tier 3 Signature Detection.
"""

import os
import sys
import tempfile
import gc
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from sentinel_scanner.engine import SentinelScanner, VERDICT_ALLOW, VERDICT_BLOCK, VERDICT_QUARANTINE

def test_tier1_cache():
    temp_dir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(temp_dir, "test_rep.db")
        scanner = SentinelScanner(db_path=db_path)

        clean_binary = b"MZ" + b"\x00" * 58 + int(64).to_bytes(4, "little") + b"PE\x00\x00" + b"\x90" * 1000
        
        # First scan -> Tier 3 pass
        v1 = scanner.scan_bytes(clean_binary)
        assert v1.verdict == VERDICT_ALLOW
        assert v1.tier == 3

        # Second scan -> Tier 1 cache hit
        v2 = scanner.scan_bytes(clean_binary)
        assert v2.verdict == VERDICT_ALLOW
        assert v2.tier == 1
        assert v2.scan_time_ms < 0.5, f"Tier 1 too slow: {v2.scan_time_ms}ms"

        print(f"[+] test_tier1_cache: PASSED (Cache hit latency: {v2.scan_time_ms:.4f}ms)")
    finally:
        del scanner
        gc.collect()
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_tier2_entropy_gate():
    temp_dir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(temp_dir, "test_rep.db")
        scanner = SentinelScanner(db_path=db_path)

        # Packed binary: PE header + pure high-entropy random bytes
        packed_binary = b"MZ" + b"\x00" * 58 + int(64).to_bytes(4, "little") + b"PE\x00\x00" + os.urandom(65536)
        
        v = scanner.scan_bytes(packed_binary)
        assert v.verdict == VERDICT_QUARANTINE
        assert v.tier == 2
        assert "HighEntropyPacked" in v.reason
        assert v.entropy > 7.4

        print(f"[+] test_tier2_entropy_gate: PASSED (Flagged packed binary with H={v.entropy:.2f})")
    finally:
        del scanner
        gc.collect()
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_tier3_signatures():
    temp_dir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(temp_dir, "test_rep.db")
        scanner = SentinelScanner(db_path=db_path)

        # EICAR test string
        eicar_string = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        v_eicar = scanner.scan_bytes(eicar_string)
        assert v_eicar.verdict == VERDICT_QUARANTINE
        assert v_eicar.tier == 3
        assert "EICAR" in v_eicar.reason

        # ShadowCopy deletion pattern
        shadow_string = b"@echo off\r\nvssadmin.exe delete shadows /all /quiet\r\nexit"
        v_shadow = scanner.scan_bytes(shadow_string)
        assert v_shadow.verdict == VERDICT_QUARANTINE
        assert "ShadowCopyDelete" in v_shadow.reason

        # Mimikatz pattern
        mimi_string = b"sekurlsa::logonpasswords full dump"
        v_mimi = scanner.scan_bytes(mimi_string)
        assert v_mimi.verdict == VERDICT_QUARANTINE
        assert "Mimikatz" in v_mimi.reason

        print("[+] test_tier3_signatures: PASSED (EICAR, Ransomware shadow delete, and Mimikatz intercepted)")
    finally:
        del scanner
        gc.collect()
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    test_tier1_cache()
    test_tier2_entropy_gate()
    test_tier3_signatures()
