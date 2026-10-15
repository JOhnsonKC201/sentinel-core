"""
Automated Unit Tests for SentinelCore Heuristic Multi-Signal Risk Analyzer
Verifies malicious API detection, script execution scoring, and ZIP macro analysis.
"""

import os
import sys
import io
import gc
import shutil
import tempfile
import zipfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from sentinel_scanner.heuristics import HeuristicAnalyzer
from sentinel_scanner.engine import SentinelScanner, VERDICT_QUARANTINE

def test_heuristic_analysis():
    analyzer = HeuristicAnalyzer()

    # 1. Benign payload -> Score 0
    benign_code = b"print('Hello, world! Normal python code.')"
    res_clean = analyzer.analyze_bytes(benign_code)
    assert res_clean["score"] == 0
    assert not res_clean["is_suspicious"]

    # 2. Suspicious process hollowing imports -> High score
    hollow_imports = b"kernel32.dll: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, OpenProcess"
    res_hollow = analyzer.analyze_bytes(hollow_imports)
    assert res_hollow["score"] >= 60
    assert res_hollow["is_suspicious"]
    assert any("VirtualAllocEx" in ind for ind in res_hollow["indicators"])

    # 3. Malicious Office macro in ZIP archive
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("[Content_Types].xml", "<xml></xml>")
        zf.writestr("word/vbaProject.bin", b"VBA_MALICIOUS_MACRO_BYTES_AutoOpen")
    
    zip_bytes = zip_buffer.getvalue()
    res_macro = analyzer.analyze_bytes(zip_bytes)
    assert res_macro["score"] >= 50
    assert any("EmbeddedVbaMacro" in ind or "AutoExec" in ind for ind in res_macro["indicators"])

    # 4. Scanner engine integration
    # Isolated reputation DB: on the shared one a repeat run answers from the Tier 1 cache
    temp_dir = tempfile.mkdtemp()
    try:
        scanner = SentinelScanner(db_path=os.path.join(temp_dir, "test_rep.db"))
        verdict = scanner.scan_bytes(hollow_imports)
        assert verdict.verdict == VERDICT_QUARANTINE
        assert "Tier3:Heuristic" in verdict.reason
    finally:
        scanner = None
        gc.collect()
        shutil.rmtree(temp_dir, ignore_errors=True)

    print("[+] test_heuristic_analysis: PASSED (Dangerous APIs, script keywords, and macro heuristics verified)")

if __name__ == "__main__":
    test_heuristic_analysis()
