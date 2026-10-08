"""
Automated Unit Tests for SentinelCore Persistence & AutoRun Scanner
Verifies registry autorun auditing, startup folder parsing, and target path extraction.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from sentinel_scanner.persistence import PersistenceScanner, extract_target_path

def test_persistence_scanner():
    scanner = PersistenceScanner()

    # 1. Path extraction unit tests
    assert extract_target_path(r'"C:\Program Files\App\app.exe" --background') == r"C:\Program Files\App\app.exe"
    assert extract_target_path(r'C:\Windows\notepad.exe C:\test.txt') == r"C:\Windows\notepad.exe"
    assert extract_target_path("") == ""

    # 2. Audit Run
    items = scanner.audit_all()
    assert isinstance(items, list)
    
    # Check structure of audited items
    for item in items[:5]:
        assert "name" in item
        assert "location" in item
        assert "command" in item
        assert "file_exists" in item
        assert "is_threat" in item

    # 3. Suspicious startup command detection
    mock_malicious_cmd = r'powershell.exe -w hidden -enc JABhID0A...'
    eval_res = scanner._evaluate_entry("HKCU\\Run", "FakeUpdate", mock_malicious_cmd)
    assert eval_res["is_threat"] is True
    assert "SuspiciousStartupArgument" in eval_res["reason"]

    print(f"[+] test_persistence_scanner: PASSED (Audited {len(items)} system autorun entries successfully)")

if __name__ == "__main__":
    test_persistence_scanner()
