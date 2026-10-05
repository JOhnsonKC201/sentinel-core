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

        # Securely unlink original file
        try:
            os.remove(source_path)
        except Exception as e:
            # If standard removal fails, try clearing read-only attributes
            import stat
            os.chmod(source_path, stat.S_IWRITE)
            os.remove(source_path)

        return vault_id

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
