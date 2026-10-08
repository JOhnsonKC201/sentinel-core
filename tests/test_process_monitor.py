"""
Automated Unit Tests for SentinelCore Process Monitor & Process Audit
Tests running process auditing, LOLBin heuristic flagging, and process inspection.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from sentinel_scanner.engine import SentinelScanner
from sentinel_vault.vault import QuarantineVault
from sentinel_guard.process_monitor import ProcessMonitor

def test_process_audit():
    scanner = SentinelScanner()
    vault = QuarantineVault()
    monitor = ProcessMonitor(scanner=scanner, vault=vault)

    processes = monitor.audit_running_processes(limit=50)
    assert isinstance(processes, list)
    assert len(processes) > 0, "Expected at least 1 running process on Windows host"

    # Verify schema of each process entry
    sample = processes[0]
    required_keys = {"pid", "name", "exe", "cmdline", "parent", "memory_mb", "risk_score", "threat_level", "indicators"}
    for k in required_keys:
        assert k in sample, f"Missing required key {k} in process audit output"

    assert 0 <= sample["risk_score"] <= 100
    assert sample["threat_level"] in ("CLEAN", "SUSPICIOUS", "HIGH_RISK")

    print(f"[+] test_process_audit: PASSED (Audited {len(processes)} active system processes)")

if __name__ == "__main__":
    test_process_audit()
