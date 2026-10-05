"""
Automated Unit Tests for SentinelCore Behavioral Ransomware Shield
Verifies Developer Workload Immunity and 3-File Damage Bounding.
"""

import os
import sys
import random

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from sentinel_behavior.ransomware_shield import RansomwareShield, ProcessActivityRecord

def test_developer_workload_immunity():
    mitigated_processes = []
    def alert_cb(proc: ProcessActivityRecord):
        mitigated_processes.append(proc.pid)

    shield = RansomwareShield(
        window_seconds=1.0,
        entropy_threshold=7.50,
        consecutive_burst_limit=3,
        on_threat_detected=alert_cb
    )

    # Simulate developer build: rustc.exe with parent cargo.exe
    dev_pid = 9991
    proc = ProcessActivityRecord(dev_pid, "rustc.exe", "cargo.exe")
    shield.processes[dev_pid] = proc

    # 150 fast writes of structured compiler binary data (H ~ 5.8)
    for i in range(150):
        # Structured bytecode
        data = bytes([random.randint(0, 120) for _ in range(4096)])
        is_mitigated = shield.inspect_file_write(dev_pid, f"target/debug/lib_{i}.rlib", data)
        assert not is_mitigated, f"Developer process was erroneously mitigated at write #{i}!"

    assert dev_pid not in mitigated_processes, "Developer process was flagged as threat!"
    assert proc.is_mitigated is False
    assert len(proc.compromised_files) == 150
    print("[+] test_developer_workload_immunity: PASSED (150 rapid writes permitted without false alarm)")

def test_ransomware_burst_mitigation():
    mitigated_processes = []
    def alert_cb(proc: ProcessActivityRecord):
        mitigated_processes.append(proc.pid)

    shield = RansomwareShield(
        window_seconds=1.0,
        entropy_threshold=7.50,
        consecutive_burst_limit=3,
        on_threat_detected=alert_cb
    )

    # Simulate zero-day ransomware: encryptor.exe spawned from cmd.exe
    ransom_pid = 9992
    proc = ProcessActivityRecord(ransom_pid, "encryptor.exe", "cmd.exe")
    shield.processes[ransom_pid] = proc

    # Write high-entropy ciphertext blocks (AES-256 simulation)
    writes_attempted = 0
    for i in range(10):
        writes_attempted += 1
        ciphertext = os.urandom(4096)
        is_mitigated = shield.inspect_file_write(ransom_pid, f"C:/Users/Victim/Doc_{i}.locked", ciphertext)
        if is_mitigated:
            break

    assert writes_attempted == 3, f"Expected mitigation at write #3, but took {writes_attempted} writes!"
    assert ransom_pid in mitigated_processes, "Offending process was not reported to alert callback!"
    assert proc.is_mitigated is True
    print(f"[+] test_ransomware_burst_mitigation: PASSED (Ransomware neutralized at write #{writes_attempted})")

if __name__ == "__main__":
    test_developer_workload_immunity()
    test_ransomware_burst_mitigation()
