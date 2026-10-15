"""
Cryptographic Quarantine Vault for SentinelCore
Provides AES-256-GCM authenticated encryption for neutralizing malicious binaries
with SQLite manifest storage and atomic restoration capabilities.
"""

import os
import sqlite3
import uuid
import time
import hashlib
from typing import List, Dict, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_VAULT_DIR = r"C:\ProgramData\SentinelCore\Vault"

class QuarantineError(OSError):
    """The file could not be taken out of place, so nothing was quarantined."""


class QuarantineVault:
    def __init__(self, vault_dir: Optional[str] = None, key_file: Optional[str] = None):
        self.vault_dir = vault_dir or os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "SentinelCore", "Vault")
        os.makedirs(self.vault_dir, exist_ok=True)
        
        self.key_file = key_file or os.path.join(self.vault_dir, ".master.key")
        self.master_key = self._load_or_generate_key()
        self.cipher = AESGCM(self.master_key)
        
        self.db_path = os.path.join(self.vault_dir, "manifest.db")
        self._init_db()

    def _load_or_generate_key(self) -> bytes:
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f:
                return f.read()
        else:
            key = AESGCM.generate_key(bit_length=256)
            with open(self.key_file, "wb") as f:
                f.write(key)
            return key

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS quarantine_manifest (
                    vault_id TEXT PRIMARY KEY,
                    original_path TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    quarantine_time TEXT NOT NULL,
                    is_restored INTEGER DEFAULT 0
                )
            """)
            conn.commit()

    def isolate_file(self, source_path: str, reason: str = "threat_detected") -> str:
        """Encrypts the file with AES-256-GCM, stores metadata, and deletes the source payload."""
        source_path = os.path.abspath(source_path)
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"Source file not found: {source_path}")

        with open(source_path, "rb") as f:
            plaintext = f.read()

        file_size = len(plaintext)
        sha256_hash = hashlib.sha256(plaintext).hexdigest()
        vault_id = str(uuid.uuid4())
        
        # 12-byte random nonce
        nonce = os.urandom(12)
        ciphertext = self.cipher.encrypt(nonce, plaintext, None)

        target_vault_path = os.path.join(self.vault_dir, f"{vault_id}.qvault")
        with open(target_vault_path, "wb") as f:
            f.write(nonce)
            f.write(ciphertext)

        # Record in manifest
        now_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO quarantine_manifest (vault_id, original_path, file_size, sha256, reason, quarantine_time, is_restored)
                VALUES (?, ?, ?, ?, ?, ?, 0)
            """, (vault_id, source_path, file_size, sha256_hash, reason, now_str))
            conn.commit()

        # Unlink the original. If that is impossible (locked, protected,
        # no rights) the isolation did not happen: undo the copy so the vault
        # never fills with duplicates of a file that is still in place.
        try:
            self._remove_source(source_path)
        except OSError as err:
            self._discard(vault_id, target_vault_path)
            raise QuarantineError(f"Could not remove {source_path}: {err}") from err

        return vault_id

    @staticmethod
    def _remove_source(source_path: str):
        try:
            os.remove(source_path)
        except PermissionError:
            # A read-only attribute is the one case worth one retry
            import stat
            os.chmod(source_path, stat.S_IWRITE)
            os.remove(source_path)

    def _discard(self, vault_id: str, archive_path: str):
        try:
            os.remove(archive_path)
        except OSError:
            pass
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM quarantine_manifest WHERE vault_id = ?", (vault_id,))
            conn.commit()

    def restore_file(self, vault_id: str, destination_path: Optional[str] = None) -> bool:
        """Decrypts a quarantined file and restores it to disk."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT original_path, sha256, is_restored FROM quarantine_manifest WHERE vault_id = ?", (vault_id,))
            row = cursor.fetchone()

        if not row:
            raise ValueError(f"Vault ID not found in manifest: {vault_id}")

        orig_path, expected_hash, is_restored = row
        restore_path = destination_path or orig_path
        vault_file = os.path.join(self.vault_dir, f"{vault_id}.qvault")

        if not os.path.exists(vault_file):
            raise FileNotFoundError(f"Quarantine archive missing: {vault_file}")

        with open(vault_file, "rb") as f:
            nonce = f.read(12)
            ciphertext = f.read()

        plaintext = self.cipher.decrypt(nonce, ciphertext, None)

        # Verify integrity
        restored_hash = hashlib.sha256(plaintext).hexdigest()
        if restored_hash != expected_hash:
            raise ValueError("Integrity check failed during restoration! Hash mismatch.")

        # Ensure parent directory exists
        os.makedirs(os.path.dirname(restore_path), exist_ok=True)
        with open(restore_path, "wb") as f:
            f.write(plaintext)

        # Mark as restored
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE quarantine_manifest SET is_restored = 1 WHERE vault_id = ?", (vault_id,))
            conn.commit()

        # Remove archive file
        os.remove(vault_file)
        return True

    def list_quarantined(self) -> List[Dict]:
        """Returns all quarantined files."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM quarantine_manifest ORDER BY quarantine_time DESC")
            return [dict(row) for row in cursor.fetchall()]

    def delete_quarantined(self, vault_id: str) -> bool:
        """Permanently deletes the encrypted vault archive and removes it from the manifest."""
        vault_file = os.path.join(self.vault_dir, f"{vault_id}.qvault")
        if os.path.exists(vault_file):
            try:
                # Overwrite before unlinking for secure deletion
                file_size = os.path.getsize(vault_file)
                with open(vault_file, "wb") as f:
                    f.write(os.urandom(min(file_size, 4096)))
                os.remove(vault_file)
            except Exception:
                pass

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM quarantine_manifest WHERE vault_id = ?", (vault_id,))
            conn.commit()
        return True

    def purge_all(self) -> int:
        """Permanently deletes all quarantined archives."""
        items = self.list_quarantined()
        count = 0
        for item in items:
            if self.delete_quarantined(item["vault_id"]):
                count += 1
        return count

    def get_vault_stats(self) -> Dict:
        """Returns summary statistics for the quarantine vault."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*), SUM(file_size) FROM quarantine_manifest WHERE is_restored = 0")
            active_count, active_size = cursor.fetchone()
            cursor.execute("SELECT COUNT(*) FROM quarantine_manifest WHERE is_restored = 1")
            restored_count = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM quarantine_manifest")
            total_count = cursor.fetchone()[0]

        return {
            "total_quarantined": total_count or 0,
            "active_threats": active_count or 0,
            "restored_count": restored_count or 0,
            "active_bytes": active_size or 0,
            "vault_path": self.vault_dir
        }

