"""
Unified Test Runner for SentinelCore Security Engine
Executes unit tests for Quarantine Vault, Static Scanner, and Ransomware Shield.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tests.test_vault import test_quarantine_and_restore
from tests.test_scanner import test_tier1_cache, test_tier2_entropy_gate, test_tier3_signatures
from tests.test_ransomware import test_developer_workload_immunity, test_ransomware_burst_mitigation

def main():
    print("==========================================================")
    print("     Executing SentinelCore Automated Verification Suite  ")
    print("==========================================================\n")

    passed = 0
    total = 6

    # Suite 1: Cryptographic Vault
    print("--- [Suite 1/3] Cryptographic Quarantine Vault Tests ---")
    try:
        test_quarantine_and_restore()
        passed += 1
    except Exception as e:
        print(f"[!] test_quarantine_and_restore FAILED: {e}")

    # Suite 2: 3-Tier Static Scanner
    print("\n--- [Suite 2/3] 3-Tier Scanning Engine Tests ---")
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

    # Suite 3: Behavioral Ransomware Shield
    print("\n--- [Suite 3/3] Behavioral Ransomware Shield Tests ---")
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
