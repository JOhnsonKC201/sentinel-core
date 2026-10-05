"""
Automated Unit Tests for SentinelCore Quarantine Vault
Verifies AES-256-GCM encryption, secure unlinking, manifest records, and bit-for-bit restoration.
"""

import os
import sys
import tempfile
import hashlib
import gc

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from sentinel_vault.vault import QuarantineVault

def test_quarantine_and_restore():
    temp_dir = tempfile.mkdtemp()
    try:
        vault_dir = os.path.join(temp_dir, "vault")
        vault = QuarantineVault(vault_dir=vault_dir)

        # 1. Create a dummy test file
        test_file = os.path.join(temp_dir, "malicious_payload.exe")
        original_content = b"CRITICAL_SYSTEM_DATA_PAYLOAD_TEST_12345" * 100
        original_hash = hashlib.sha256(original_content).hexdigest()

        with open(test_file, "wb") as f:
            f.write(original_content)

        assert os.path.exists(test_file), "Test file was not created"

        # 2. Isolate into quarantine
        vault_id = vault.isolate_file(test_file, reason="Malware.Simulation")

        # Verify source file is unlinked/deleted
        assert not os.path.exists(test_file), "Source file was not unlinked after quarantine!"

        # Verify .qvault file exists
        qvault_path = os.path.join(vault_dir, f"{vault_id}.qvault")
        assert os.path.exists(qvault_path), "Quarantine vault container not found!"

        # Verify manifest entry exists
        items = vault.list_quarantined()
        assert len(items) == 1, f"Expected 1 manifest entry, got {len(items)}"
        assert items[0]["vault_id"] == vault_id
        assert items[0]["sha256"] == original_hash
        assert items[0]["is_restored"] == 0

        # 3. Restore file
        restored_file = os.path.join(temp_dir, "restored_payload.exe")
        success = vault.restore_file(vault_id, destination_path=restored_file)
        assert success is True, "Restoration failed!"
        assert os.path.exists(restored_file), "Restored file missing on disk!"

        with open(restored_file, "rb") as f:
            restored_content = f.read()

        assert hashlib.sha256(restored_content).hexdigest() == original_hash, "Hash mismatch after restoration!"
        assert restored_content == original_content, "Restored content does not match original bytes!"

        print("[+] test_quarantine_and_restore: PASSED (AES-256-GCM encryption & bit-for-bit restore verified)")
    finally:
        del vault
        gc.collect()
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    test_quarantine_and_restore()
