"""
Exclusion & Allowlist Manager for SentinelCore
Permits configuring trusted directory paths, specific file paths, and known SHA-256 hashes
to eliminate false positives while preserving system security.
"""

import os
import json
from typing import Set, List, Dict, Any

DEFAULT_EXCLUSIONS_PATH = os.path.join(
    os.environ.get("ProgramData", "C:\\ProgramData"),
    "SentinelCore",
    "exclusions.json"
)

class ExclusionManager:
    def __init__(self, config_path: str = DEFAULT_EXCLUSIONS_PATH):
        self.config_path = config_path
        self.excluded_paths: Set[str] = set()
        self.excluded_hashes: Set[str] = set()
        self.excluded_process_names: Set[str] = {
            "explorer.exe", "svchost.exe", "taskhostw.exe", "searchindexer.exe"
        }
        self.load()

    def load(self):
        """Loads exclusions from persistent JSON config."""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.excluded_paths = set(os.path.abspath(p).lower() for p in data.get("paths", []))
                    self.excluded_hashes = set(h.lower() for h in data.get("hashes", []))
                    self.excluded_process_names.update(p.lower() for p in data.get("process_names", []))
            except Exception:
                pass

    def save(self):
        """Saves current exclusions to disk."""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump({
                    "paths": sorted(list(self.excluded_paths)),
                    "hashes": sorted(list(self.excluded_hashes)),
                    "process_names": sorted(list(self.excluded_process_names))
                }, f, indent=2)
        except Exception:
            pass

    def add_path_exclusion(self, path: str) -> bool:
        norm = os.path.abspath(path).lower()
        self.excluded_paths.add(norm)
        self.save()
        return True

    def remove_path_exclusion(self, path: str) -> bool:
        norm = os.path.abspath(path).lower()
        if norm in self.excluded_paths:
            self.excluded_paths.remove(norm)
            self.save()
            return True
        return False

    def add_hash_exclusion(self, sha256_hash: str) -> bool:
        h = sha256_hash.strip().lower()
        if len(h) == 64:
            self.excluded_hashes.add(h)
            self.save()
            return True
        return False

    def remove_hash_exclusion(self, sha256_hash: str) -> bool:
        h = sha256_hash.strip().lower()
        if h in self.excluded_hashes:
            self.excluded_hashes.remove(h)
            self.save()
            return True
        return False

    def is_path_excluded(self, file_path: str) -> bool:
        """Checks if a file path is explicitly excluded or inside an excluded folder."""
        if not file_path:
            return False
        norm = os.path.abspath(file_path).lower()
        for exc in self.excluded_paths:
            if norm == exc or norm.startswith(exc + os.sep) or norm.startswith(exc + "/"):
                return True
        return False

    def is_hash_excluded(self, sha256_hash: str) -> bool:
        if not sha256_hash:
            return False
        return sha256_hash.lower() in self.excluded_hashes

    def is_process_excluded(self, proc_name: str) -> bool:
        if not proc_name:
            return False
        return proc_name.lower() in self.excluded_process_names

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_paths": len(self.excluded_paths),
            "paths": sorted(list(self.excluded_paths)),
            "total_hashes": len(self.excluded_hashes),
            "hashes": sorted(list(self.excluded_hashes)),
            "process_names": sorted(list(self.excluded_process_names))
        }
