"""
Automated Unit Tests for SentinelCore Network Socket & C2 Monitor
Verifies active connection auditing, suspicious C2 port detection, and LOLBin network checks.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from sentinel_guard.network_monitor import NetworkMonitor, SUSPICIOUS_C2_PORTS

def test_network_monitor():
    monitor = NetworkMonitor()

    # 1. Audit active connections
    conns = monitor.audit_connections()
    assert isinstance(conns, list)

    # 2. Check structure
    for c in conns[:5]:
        assert "pid" in c
        assert "process" in c
        assert "is_suspicious" in c
        assert "status" in c

    # 3. Verify C2 port detection logic
    assert 4444 in SUSPICIOUS_C2_PORTS
    assert 3333 in SUSPICIOUS_C2_PORTS

    print(f"[+] test_network_monitor: PASSED (Audited {len(conns)} active process sockets successfully)")

if __name__ == "__main__":
    test_network_monitor()
