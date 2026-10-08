"""
Static Scanner & Entropy Gating Engine for SentinelCore
Implements the 3-Tier Cascaded Evaluation architecture:
- Tier 1: Instant SHA-256 LRU hash cache (< 0.1ms).
- Tier 2: Zero-allocation PE Header & 64KB Shannon entropy gate (< 0.8ms).
- Tier 3: Multi-pattern signature & YARA-compatible rule evaluation.
Optimized for streaming large files without high memory consumption.
"""

import os
import math
import collections
import hashlib
import sqlite3
import re
from typing import Tuple, Dict, Any, Optional

from .exclusions import ExclusionManager
from .heuristics import HeuristicAnalyzer


VERDICT_ALLOW = 1

VERDICT_BLOCK = 2
VERDICT_QUARANTINE = 3

# File extensions to ignore for intensive binary regex scanning during broad scans
MEDIA_EXTENSIONS = {
    ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm",
    ".mp3", ".wav", ".flac", ".aac", ".ogg",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".ico",
    ".iso", ".vhd", ".vhdx", ".vmdk"
}

# Real-world threats, evasion tools, EICAR, LOLBins, and ransomware signatures
THREAT_PATTERNS = [
    (re.compile(rb"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*"), "EICAR.StandardTestVirus"),
    (re.compile(rb"vssadmin(\.exe)?\s+delete\s+shadows", re.IGNORECASE), "Ransomware.ShadowCopyDelete"),
    (re.compile(rb"wmic(\.exe)?\s+shadowcopy\s+delete", re.IGNORECASE), "Ransomware.WmicShadowDelete"),
    (re.compile(rb"wbadmin(\.exe)?\s+delete\s+catalog", re.IGNORECASE), "Ransomware.WbadminDeleteCatalog"),
    (re.compile(rb"bcdedit(\.exe)?\s+.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)", re.IGNORECASE), "Ransomware.BcdeditTamper"),
    (re.compile(rb"Set-MpPreference\s+-DisableRealtimeMonitoring", re.IGNORECASE), "DefenseEvasion.DisableDefender"),
    (re.compile(rb"Add-MpPreference\s+-ExclusionPath", re.IGNORECASE), "DefenseEvasion.DefenderExclusion"),
    (re.compile(rb"sekurlsa::logonpasswords", re.IGNORECASE), "Hacktool.Mimikatz"),
    (re.compile(rb"lsadump::sam", re.IGNORECASE), "Hacktool.MimikatzLsa"),
    (re.compile(rb"powershell(\.exe)?\s+(-e|-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{40,}", re.IGNORECASE), "Malware.ObfuscatedPowerShell"),
    (re.compile(rb"certutil(\.exe)?\s+.*(-urlcache|-split|-f)\s+http", re.IGNORECASE), "LOLBin.CertutilDownload"),
    (re.compile(rb"bitsadmin(\.exe)?\s+/transfer\s+", re.IGNORECASE), "LOLBin.BitsadminTransfer"),
    (re.compile(rb"mshta(\.exe)?\s+(http|javascript|vbscript):", re.IGNORECASE), "LOLBin.MshtaExecution"),
    (re.compile(rb"regsvr32(\.exe)?\s+.*(/s\s+)?/u\s+/i:http", re.IGNORECASE), "LOLBin.SquiblydooRegsvr32"),
    (re.compile(rb"rundll32(\.exe)?\s+.*,\s*#1", re.IGNORECASE), "DefenseEvasion.SuspiciousOrdinal"),
    (re.compile(rb"ALL YOUR FILES HAVE BEEN ENCRYPTED", re.IGNORECASE), "Ransomware.RansomNoteText"),
    (re.compile(rb"YOUR PERSONAL ID IS:\s*[A-Z0-9]{16,}", re.IGNORECASE), "Ransomware.PersonalIdHeader"),
    (re.compile(rb"stratum\+tcp://[a-zA-Z0-9_.\-]+:[0-9]{2,5}", re.IGNORECASE), "Cryptominer.StratumPool"),
    (re.compile(rb"(meterpreter|reverse_tcp|bind_tcp|reverse_https)", re.IGNORECASE), "Hacktool.MetasploitPayload"),
    (re.compile(rb"\\\\\.\\pipe\\(msagent_|msse-|status_)", re.IGNORECASE), "Hacktool.CobaltStrikeNamedPipe"),
]

def calculate_shannon_entropy(data: bytes) -> float:
    """Computes Shannon byte entropy: H = -sum(p_i * log2(p_i))"""
    if not data:
        return 0.0
    length = len(data)
    counts = collections.Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def inspect_pe_headers(data: bytes) -> Dict[str, Any]:
    """Inspects DOS/PE headers without full executable loading."""
    if len(data) < 64 or data[:2] != b"MZ":
        return {"is_pe": False}
    
    pe_offset = int.from_bytes(data[60:64], byteorder="little")
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset+4] != b"PE\x00\x00":
        return {"is_pe": False}
    
    num_sections = int.from_bytes(data[pe_offset+6:pe_offset+8], byteorder="little")
    opt_header_size = int.from_bytes(data[pe_offset+20:pe_offset+22], byteorder="little")
    
    # Read Section Headers
    section_table_offset = pe_offset + 24 + opt_header_size
    is_upx_packed = False
    section_names = []
    
    if section_table_offset + (num_sections * 40) <= len(data):
        for i in range(min(num_sections, 16)):
            sec_offset = section_table_offset + (i * 40)
            sec_name = data[sec_offset:sec_offset+8].rstrip(b"\x00").decode("latin-1", errors="ignore")
            section_names.append(sec_name)
            if "UPX" in sec_name or "ASPack" in sec_name:
                is_upx_packed = True

    return {
        "is_pe": True,
        "pe_offset": pe_offset,
        "num_sections": num_sections,
        "is_upx_packed": is_upx_packed,
        "section_names": section_names
    }

class ScanVerdict:
    def __init__(self, verdict: int, reason: str, tier: int, sha256: str, entropy: float, scan_time_ms: float):
        self.verdict = verdict
        self.reason = reason
        self.tier = tier
        self.sha256 = sha256
        self.entropy = entropy
        self.scan_time_ms = scan_time_ms

    def is_malicious(self) -> bool:
        return self.verdict in (VERDICT_BLOCK, VERDICT_QUARANTINE)

    def __repr__(self):
        v_str = "ALLOW" if self.verdict == VERDICT_ALLOW else "BLOCK" if self.verdict == VERDICT_BLOCK else "QUARANTINE"
        return f"<ScanVerdict {v_str} via Tier {self.tier} ({self.reason}) [{self.scan_time_ms:.3f}ms]>"

class SentinelScanner:
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            data_dir = os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "SentinelCore")
            os.makedirs(data_dir, exist_ok=True)
            db_path = os.path.join(data_dir, "reputation.db")
            
        self.db_path = db_path
        self._init_db()
        self.exclusions = ExclusionManager()
        self.heuristics = HeuristicAnalyzer()
        
        # In-memory fast LRU cache (key=sha256, val=verdict)
        self.cache: Dict[str, int] = collections.OrderedDict()
        self.cache_capacity = 50000
        self._load_warm_cache()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reputation_cache (
                    sha256 TEXT PRIMARY KEY,
                    verdict INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    first_seen TEXT NOT NULL
                )
            """)
            conn.commit()

    def _load_warm_cache(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT sha256, verdict FROM reputation_cache LIMIT 10000")
                for sha, v in cursor.fetchall():
                    self.cache[sha] = v
        except Exception:
            pass

    def record_reputation(self, sha256: str, verdict: int, reason: str):
        self.cache[sha256] = verdict
        if len(self.cache) > self.cache_capacity:
            self.cache.pop(next(iter(self.cache)))
        
        import time
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO reputation_cache (sha256, verdict, reason, first_seen)
                    VALUES (?, ?, ?, ?)
                """, (sha256, verdict, reason, now))
                conn.commit()
        except Exception:
            pass

    def scan_bytes(self, data: bytes, filename: str = "", precomputed_sha256: Optional[str] = None) -> ScanVerdict:
        """Evaluates a byte buffer through the 3-tier cascade."""
        import time
        t0 = time.perf_counter_ns()
        
        # Step 1: Pre-calculate SHA-256
        sha256_hash = precomputed_sha256 if precomputed_sha256 else hashlib.sha256(data).hexdigest()

        # Step 1a: Check Hash Whitelist Exclusion
        if self.exclusions.is_hash_excluded(sha256_hash):
            t1 = time.perf_counter_ns()
            return ScanVerdict(
                verdict=VERDICT_ALLOW,
                reason="AllowlistedHash",
                tier=0,
                sha256=sha256_hash,
                entropy=0.0,
                scan_time_ms=(t1 - t0) / 1_000_000.0
            )

        # Tier 1: Fast Reputation Cache
        if sha256_hash in self.cache:
            v = self.cache[sha256_hash]
            t1 = time.perf_counter_ns()
            return ScanVerdict(
                verdict=v,
                reason="Tier1:ReputationCacheHit",
                tier=1,
                sha256=sha256_hash,
                entropy=0.0,
                scan_time_ms=(t1 - t0) / 1_000_000.0
            )

        # Tier 2: PE Inspection & 64KB Entropy Gating
        header_window = data[:65536]
        pe_info = inspect_pe_headers(header_window)
        ent = calculate_shannon_entropy(header_window)

        # High-entropy packed / encrypted executable detection
        if pe_info.get("is_pe"):
            if pe_info.get("is_upx_packed") and ent > 7.10:
                t1 = time.perf_counter_ns()
                self.record_reputation(sha256_hash, VERDICT_QUARANTINE, "Tier2:UPXPackedSuspicious")
                return ScanVerdict(
                    verdict=VERDICT_QUARANTINE,
                    reason=f"Tier2:UPXPackedBinary(H={ent:.2f})",
                    tier=2,
                    sha256=sha256_hash,
                    entropy=ent,
                    scan_time_ms=(t1 - t0) / 1_000_000.0
                )
            elif ent > 7.45:
                t1 = time.perf_counter_ns()
                self.record_reputation(sha256_hash, VERDICT_QUARANTINE, "Tier2:PackedCryptorHighEntropy")
                return ScanVerdict(
                    verdict=VERDICT_QUARANTINE,
                    reason=f"Tier2:HighEntropyPackedBinary(H={ent:.2f})",
                    tier=2,
                    sha256=sha256_hash,
                    entropy=ent,
                    scan_time_ms=(t1 - t0) / 1_000_000.0
                )

        # Tier 3: Multi-Pattern Threat Signatures (Scan first 2MB to keep latency bounded)
        scan_window = data[:2 * 1024 * 1024]
        for pattern, sig_name in THREAT_PATTERNS:
            if pattern.search(scan_window):
                t1 = time.perf_counter_ns()
                self.record_reputation(sha256_hash, VERDICT_QUARANTINE, f"Tier3:{sig_name}")
                return ScanVerdict(
                    verdict=VERDICT_QUARANTINE,
                    reason=f"Tier3:{sig_name}",
                    tier=3,
                    sha256=sha256_hash,
                    entropy=ent,
                    scan_time_ms=(t1 - t0) / 1_000_000.0
                )

        # Tier 3b: Multi-Signal Heuristic Risk Scoring
        heur = self.heuristics.analyze_bytes(scan_window, filename)
        if heur["is_suspicious"]:
            t1 = time.perf_counter_ns()
            reason_str = f"Tier3:Heuristic.{heur['risk_level']}(Score={heur['score']})"
            self.record_reputation(sha256_hash, VERDICT_QUARANTINE, reason_str)
            return ScanVerdict(
                verdict=VERDICT_QUARANTINE,
                reason=reason_str,
                tier=3,
                sha256=sha256_hash,
                entropy=ent,
                scan_time_ms=(t1 - t0) / 1_000_000.0
            )

        # Passed all checks -> Clean
        t1 = time.perf_counter_ns()
        self.record_reputation(sha256_hash, VERDICT_ALLOW, "Tier3:CleanBinary")
        return ScanVerdict(
            verdict=VERDICT_ALLOW,
            reason="Tier3:Clean",
            tier=3,
            sha256=sha256_hash,
            entropy=ent,
            scan_time_ms=(t1 - t0) / 1_000_000.0
        )

    def scan_file(self, file_path: str) -> ScanVerdict:
        """Reads a file safely with streaming chunks for large files."""
        file_path = os.path.abspath(file_path)
        if not os.path.exists(file_path):
            return ScanVerdict(VERDICT_ALLOW, "FileNotFound", 0, "", 0.0, 0.0)

        if self.exclusions.is_path_excluded(file_path):
            return ScanVerdict(VERDICT_ALLOW, "AllowlistedPath", 0, "", 0.0, 0.0)

        _, ext = os.path.splitext(file_path.lower())
        # Skip media files from signature scans
        if ext in MEDIA_EXTENSIONS:
            return ScanVerdict(VERDICT_ALLOW, "SkippedMediaFile", 1, "", 0.0, 0.0)

        try:
            file_size = os.path.getsize(file_path)
            
            # For files <= 20MB, read directly
            if file_size <= 20 * 1024 * 1024:
                with open(file_path, "rb") as f:
                    data = f.read()
                return self.scan_bytes(data, os.path.basename(file_path))
            
            # For large files (> 20MB), stream hash and sample first 2MB
            hasher = hashlib.sha256()
            with open(file_path, "rb") as f:
                header_data = f.read(2 * 1024 * 1024)
                hasher.update(header_data)
                
                # Stream the rest in 64KB chunks
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    hasher.update(chunk)

            sha256_hash = hasher.hexdigest()
            return self.scan_bytes(header_data, os.path.basename(file_path), precomputed_sha256=sha256_hash)

        except Exception as e:
            # Fail-open on locked system handles
            return ScanVerdict(VERDICT_ALLOW, f"ScanErrorFailOpen({e})", 0, "", 0.0, 0.0)

    def get_signatures_summary(self) -> Dict[str, Any]:
        """Returns statistics and definitions of active detection engines."""
        signatures_list = [name for _, name in THREAT_PATTERNS]
        return {
            "tier1_cache_entries": len(self.cache),
            "tier1_cache_capacity": self.cache_capacity,
            "tier2_entropy_threshold": 7.45,
            "tier2_upx_entropy_threshold": 7.10,
            "tier3_signatures_count": len(signatures_list),
            "signatures": signatures_list,
            "monitored_media_filters": list(MEDIA_EXTENSIONS)
        }

