"""
Unified Test Runner for SentinelCore Security Engine
Executes complete automated verification across all 7 operational security layers:
1. Cryptographic Quarantine Vault (AES-256-GCM)
2. 3-Tier Multi-Pattern Detection Engine & UPX Decompression
3. Advanced Heuristic Risk & Memory API Analyzer
4. Behavioral Ransomware Shield & Developer Workload Immunity
5. System Persistence & AutoRun Registry Auditor
6. Network Socket & C2 Channel Monitor
7. Live Process & LOLBin Anomaly Auditor
8. Anti-Tamper & Database Integrity Guard
9. Exclusion & Whitelist Rule Manager
10. Web Management Console & REST APIs
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tests.test_vault import test_quarantine_and_restore, test_vault_stats_and_purge
from tests.test_scanner import test_tier1_cache, test_tier2_entropy_gate, test_tier3_signatures, test_upx_and_advanced_signatures
from tests.test_heuristics import test_heuristic_analysis
from tests.test_exclusions import test_exclusions_manager
from tests.test_persistence import test_persistence_scanner
from tests.test_network import test_network_monitor
from tests.test_process_monitor import test_process_audit
from tests.test_integrity import test_integrity_guard
from tests.test_ransomware import test_developer_workload_immunity, test_ransomware_burst_mitigation
from tests.test_web_dashboard import test_web_dashboard_endpoints

def main():
    print("==========================================================")
    print("     Executing SentinelCore Automated Verification Suite  ")
    print("==========================================================\n")

    passed = 0
    total = 15

    # Layer 1: Quarantine Vault
    print("--- [Layer 1] Cryptographic Quarantine Vault Tests ---")
    try:
        test_quarantine_and_restore()
        passed += 1
    except Exception as e:
        print(f"[!] test_quarantine_and_restore FAILED: {e}")

    try:
        test_vault_stats_and_purge()
        passed += 1
    except Exception as e:
        print(f"[!] test_vault_stats_and_purge FAILED: {e}")

    # Layer 2: 3-Tier Static Scanner
    print("\n--- [Layer 2] 3-Tier Scanning Engine Tests ---")
    try:
        test_tier1_cache()
        passed += 1
    except Exception as e:
        print(f"[!] test_tier1_cache FAILED: {e}")

    try:
        test_tier2_entropy_gate()
        passed += 1
    except Exception as e:
        print(f"[!] test_tier2_entropy_gate FAILED: {e}")

    try:
        test_tier3_signatures()
        passed += 1
    except Exception as e:
        print(f"[!] test_tier3_signatures FAILED: {e}")

    try:
        test_upx_and_advanced_signatures()
        passed += 1
    except Exception as e:
        print(f"[!] test_upx_and_advanced_signatures FAILED: {e}")

    # Layer 3: Heuristics & Exclusions
    print("\n--- [Layer 3] Heuristics & Whitelist Engine Tests ---")
    try:
        test_heuristic_analysis()
        passed += 1
    except Exception as e:
        print(f"[!] test_heuristic_analysis FAILED: {e}")

    try:
        test_exclusions_manager()
        passed += 1
    except Exception as e:
        print(f"[!] test_exclusions_manager FAILED: {e}")

    # Layer 4: Persistence & Network Monitoring
    print("\n--- [Layer 4] Persistence & Network Auditing Tests ---")
    try:
        test_persistence_scanner()
        passed += 1
    except Exception as e:
        print(f"[!] test_persistence_scanner FAILED: {e}")

    try:
        test_network_monitor()
        passed += 1
    except Exception as e:
        print(f"[!] test_network_monitor FAILED: {e}")

    # Layer 5: Process Guard & Anti-Tamper
    print("\n--- [Layer 5] Process Audit & Anti-Tamper Verification Tests ---")
    try:
        test_process_audit()
        passed += 1
    except Exception as e:
        print(f"[!] test_process_audit FAILED: {e}")

    try:
        test_integrity_guard()
        passed += 1
    except Exception as e:
        print(f"[!] test_integrity_guard FAILED: {e}")

    # Layer 6: Behavioral Ransomware Shield
    print("\n--- [Layer 6] Behavioral Ransomware Shield Tests ---")
    try:
        test_developer_workload_immunity()
        passed += 1
    except Exception as e:
        print(f"[!] test_developer_workload_immunity FAILED: {e}")

    try:
        test_ransomware_burst_mitigation()
        passed += 1
    except Exception as e:
        print(f"[!] test_ransomware_burst_mitigation FAILED: {e}")

    # Layer 7: Web Management API
    print("\n--- [Layer 7] Web Management Console & API Tests ---")
    try:
        test_web_dashboard_endpoints()
        passed += 1
    except Exception as e:
        print(f"[!] test_web_dashboard_endpoints FAILED: {e}")

    print("\n" + "="*58)
    print(f"VERIFICATION SUMMARY: {passed}/{total} Test Suites Passed ({passed/total*100:.1f}%)")
    print("="*58)

    if passed == total:
        print("[+] ALL SYSTEM INVARIANTS VALIDATED WITH ZERO FAILURES.")
        return 0
    else:
        print(f"[!] {total - passed} tests failed.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
