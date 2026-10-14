"""
Anti-Tamper & Integrity Guard for SentinelCore
Protects SentinelCore's core engines, definition rules, and vaults from
unauthorized modification, deletion, or tampering by local malware or attackers.
"""

import os
import sys
import json
import hashlib
import time
from typing import Dict, List, Any, Optional

CORE_TARGETS = [
    os.path.join("sentinel_scanner", "engine.py"),
    os.path.join("sentinel_scanner", "heuristics.py"),
    os.path.join("sentinel_scanner", "persistence.py"),
    os.path.join("sentinel_scanner", "exclusions.py"),
    os.path.join("sentinel_guard", "watcher.py"),
    os.path.join("sentinel_guard", "process_monitor.py"),
    os.path.join("sentinel_guard", "network_monitor.py"),
    os.path.join("sentinel_vault", "vault.py"),
    os.path.join("sentinel_behavior", "shield.py"),
    os.path.join("sentinel_ui", "desktop_gui.py"),
]

class IntegrityGuard:
    def __init__(self, base_dir: Optional[str] = None, manifest_path: Optional[str] = None):
        if base_dir is None:
            self.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        else:
            self.base_dir = os.path.abspath(base_dir)

        if manifest_path is None:
            data_dir = os.path.join(self.base_dir, "data")
            os.makedirs(data_dir, exist_ok=True)
            self.manifest_path = os.path.join(data_dir, "integrity_manifest.json")
        else:
            self.manifest_path = manifest_path

        self.baseline_hashes: Dict[str, str] = {}
        self._load_or_generate_baseline()

    def _compute_file_sha256(self, filepath: str) -> Optional[str]:
        if not os.path.isfile(filepath):
            return None
        h = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def _load_or_generate_baseline(self):
        if os.path.isfile(self.manifest_path):
            try:
                with open(self.manifest_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.baseline_hashes = data.get("hashes", {})
                    return
            except Exception:
                pass
        
        # If no manifest exists, generate baseline
        self.generate_and_save_baseline()

    def generate_and_save_baseline(self) -> Dict[str, str]:
        hashes = {}
        for rel_path in CORE_TARGETS:
            full_path = os.path.join(self.base_dir, rel_path)
            if os.path.isfile(full_path):
                file_hash = self._compute_file_sha256(full_path)
                if file_hash:
                    hashes[rel_path] = file_hash

        self.baseline_hashes = hashes
        payload = {
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "file_count": len(hashes),
            "hashes": hashes
        }
        try:
            os.makedirs(os.path.dirname(self.manifest_path), exist_ok=True)
            with open(self.manifest_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except Exception:
            pass

        return hashes

    def verify_integrity(self) -> Dict[str, Any]:
        """
        Verifies current files against the baseline integrity manifest.
        Returns detailed report indicating any tampered, modified, or missing components.
        """
        tampered = []
        missing = []
        verified_count = 0

        for rel_path, expected_hash in self.baseline_hashes.items():
            full_path = os.path.join(self.base_dir, rel_path)
            if not os.path.exists(full_path):
                missing.append(rel_path)
                continue

            current_hash = self._compute_file_sha256(full_path)
            if current_hash is None or current_hash != expected_hash:
                tampered.append({
                    "file": rel_path,
                    "expected_hash": expected_hash,
                    "actual_hash": current_hash or "CORRUPTED"
                })
            else:
                verified_count += 1

        is_intact = (len(tampered) == 0 and len(missing) == 0)

        return {
            "is_intact": is_intact,
            "status": "VALID" if is_intact else "TAMPER_DETECTED",
            "verified_count": verified_count,
            "total_monitored": len(self.baseline_hashes),
            "tampered_files": tampered,
            "missing_files": missing,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
