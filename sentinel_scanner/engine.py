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
import time
import logging
import threading
import collections
import contextlib
import hashlib
import sqlite3
import re
from typing import BinaryIO, Callable, Tuple, Dict, Any, Optional

from . import heuristics, trust
from .exclusions import ExclusionManager
from .heuristics import HeuristicAnalyzer, rules_fingerprint

logger = logging.getLogger(__name__)


VERDICT_ALLOW = 1

VERDICT_BLOCK = 2
VERDICT_QUARANTINE = 3

ENTROPY_GATE_PACKED = 7.45
ENTROPY_GATE_UPX = 7.10

ENTROPY_WINDOW = 64 * 1024
HEURISTIC_WINDOW = 2 * 1024 * 1024
IN_MEMORY_SCAN_LIMIT = 20 * 1024 * 1024
STREAM_CHUNK_SIZE = 4 * 1024 * 1024
# Bytes carried over between streamed chunks. A Windows command line tops out at
# 32,767 characters, so 64KB covers any match that could actually be executed;
# a longer match straddling a chunk boundary is not seen.
STREAM_OVERLAP = 64 * 1024
MEDIA_MAGIC_PEEK = 16

CACHE_CAPACITY = 50000
WARM_CACHE_ROWS = 10000

# File extensions to ignore for intensive binary regex scanning during broad scans
MEDIA_EXTENSIONS = {
    ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm",
    ".mp3", ".wav", ".flac", ".aac", ".ogg",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".ico",
    ".iso", ".vhd", ".vhdx", ".vmdk"
}

# Real-world threats, evasion tools, EICAR, LOLBins, and ransomware signatures.
# Gaps between tokens are bounded ({0,256}, same line): an open-ended `.*` costs
# quadratic time on a buffer that repeats the leading keyword.
THREAT_PATTERNS = [
    (re.compile(rb"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*"), "EICAR.StandardTestVirus"),
    (re.compile(rb"vssadmin(\.exe)?\s+delete\s+shadows", re.IGNORECASE), "Ransomware.ShadowCopyDelete"),
    (re.compile(rb"wmic(\.exe)?\s+shadowcopy\s+delete", re.IGNORECASE), "Ransomware.WmicShadowDelete"),
    (re.compile(rb"wbadmin(\.exe)?\s+delete\s+catalog", re.IGNORECASE), "Ransomware.WbadminDeleteCatalog"),
    (re.compile(rb"bcdedit(\.exe)?\s+[^\n]{0,256}(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)", re.IGNORECASE), "Ransomware.BcdeditTamper"),
    (re.compile(rb"Set-MpPreference\s+-DisableRealtimeMonitoring", re.IGNORECASE), "DefenseEvasion.DisableDefender"),
    (re.compile(rb"Add-MpPreference\s+-ExclusionPath", re.IGNORECASE), "DefenseEvasion.DefenderExclusion"),
    (re.compile(rb"sekurlsa::logonpasswords", re.IGNORECASE), "Hacktool.Mimikatz"),
    (re.compile(rb"lsadump::sam", re.IGNORECASE), "Hacktool.MimikatzLsa"),
    (re.compile(rb"powershell(\.exe)?\s+(-e|-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{40,}", re.IGNORECASE), "Malware.ObfuscatedPowerShell"),
    (re.compile(rb"certutil(\.exe)?\s+[^\n]{0,256}(-urlcache|-split|-f)\s+http", re.IGNORECASE), "LOLBin.CertutilDownload"),
    (re.compile(rb"bitsadmin(\.exe)?\s+/transfer\s+", re.IGNORECASE), "LOLBin.BitsadminTransfer"),
    (re.compile(rb"mshta(\.exe)?\s+(http|javascript|vbscript):", re.IGNORECASE), "LOLBin.MshtaExecution"),
    (re.compile(rb"regsvr32(\.exe)?\s+[^\n]{0,256}(/s\s+)?/u\s+/i:http", re.IGNORECASE), "LOLBin.SquiblydooRegsvr32"),
    (re.compile(rb"rundll32(\.exe)?\s+[^\n]{0,256},\s*#1", re.IGNORECASE), "DefenseEvasion.SuspiciousOrdinal"),
    (re.compile(rb"ALL YOUR FILES HAVE BEEN ENCRYPTED", re.IGNORECASE), "Ransomware.RansomNoteText"),
    (re.compile(rb"YOUR PERSONAL ID IS:\s*[A-Z0-9]{16,}", re.IGNORECASE), "Ransomware.PersonalIdHeader"),
    (re.compile(rb"stratum\+tcp://[a-zA-Z0-9_.\-]+:[0-9]{2,5}", re.IGNORECASE), "Cryptominer.StratumPool"),
    (re.compile(rb"(meterpreter|reverse_tcp|bind_tcp|reverse_https)", re.IGNORECASE), "Hacktool.MetasploitPayload"),
    (re.compile(rb"\\\\\.\\pipe\\(msagent_|msse-|status_)", re.IGNORECASE), "Hacktool.CobaltStrikeNamedPipe"),
]

# Lowercase literals that every match of a signature must contain. A substring
# test is far cheaper than the regex, so the regex only runs on buffers holding
# at least one anchor. A signature without an entry always runs its regex.
SIGNATURE_ANCHORS: Dict[str, Tuple[bytes, ...]] = {
    "EICAR.StandardTestVirus": (b"eicar-standard-antivirus-test-file",),
    "Ransomware.ShadowCopyDelete": (b"vssadmin",),
    "Ransomware.WmicShadowDelete": (b"shadowcopy",),
    "Ransomware.WbadminDeleteCatalog": (b"wbadmin",),
    "Ransomware.BcdeditTamper": (b"bcdedit",),
    "DefenseEvasion.DisableDefender": (b"set-mppreference",),
    "DefenseEvasion.DefenderExclusion": (b"add-mppreference",),
    "Hacktool.Mimikatz": (b"sekurlsa::logonpasswords",),
    "Hacktool.MimikatzLsa": (b"lsadump::sam",),
    "Malware.ObfuscatedPowerShell": (b"powershell",),
    "LOLBin.CertutilDownload": (b"certutil",),
    "LOLBin.BitsadminTransfer": (b"bitsadmin",),
    "LOLBin.MshtaExecution": (b"mshta",),
    "LOLBin.SquiblydooRegsvr32": (b"regsvr32",),
    "DefenseEvasion.SuspiciousOrdinal": (b"rundll32",),
    "Ransomware.RansomNoteText": (b"all your files have been encrypted",),
    "Ransomware.PersonalIdHeader": (b"your personal id is:",),
    "Cryptominer.StratumPool": (b"stratum+tcp://",),
    "Hacktool.MetasploitPayload": (b"meterpreter", b"reverse_tcp", b"bind_tcp", b"reverse_https"),
    "Hacktool.CobaltStrikeNamedPipe": (b"\\\\.\\pipe\\",),
}

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

def find_signature(data: bytes) -> Optional[str]:
    """Returns the name of the first threat signature matching the buffer, if any."""
    lowered = data.lower()
    for pattern, sig_name in THREAT_PATTERNS:
        anchors = SIGNATURE_ANCHORS.get(sig_name)
        if anchors and not any(anchor in lowered for anchor in anchors):
            continue
        if pattern.search(data):
            return sig_name
    return None

def signature_fingerprint() -> str:
    """Digest of everything that decides a verdict. A cached verdict is only
    trustworthy for the rule set and the code that produced it."""
    hasher = hashlib.sha256()
    for pattern, sig_name in THREAT_PATTERNS:
        hasher.update(repr((sig_name, pattern.pattern, pattern.flags, SIGNATURE_ANCHORS.get(sig_name))).encode("utf-8"))
    hasher.update(rules_fingerprint())

    # Thresholds, window sizes and scoring live in code rather than in a rule
    # table, so the detection modules themselves are part of the fingerprint.
    for module_path in (__file__, heuristics.__file__):
        try:
            with open(module_path, "rb") as f:
                hasher.update(f.read())
        except OSError as e:
            logger.warning("Detection module %s not readable for fingerprinting: %s", module_path, e)
    return hasher.hexdigest()[:16]

def is_trusted_media(extension: str, header: bytes) -> bool:
    """Decides whether a file may skip scanning on the strength of its media extension.

    `extension` is lowercase with the leading dot and is already known to be in
    MEDIA_EXTENSIONS. `header` holds the first MEDIA_MAGIC_PEEK bytes of the file.
    """
    # TODO(human): the extension is attacker-controlled, so trusting it alone lets
    # `payload.exe` renamed to `payload.png` skip the scanner entirely.
    return True

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

def _elapsed_ms(t0: int) -> float:
    return (time.perf_counter_ns() - t0) / 1_000_000.0

class SentinelScanner:
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            data_dir = os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "SentinelCore")
            os.makedirs(data_dir, exist_ok=True)
            db_path = os.path.join(data_dir, "reputation.db")

        self.db_path = db_path
        self.sig_version = signature_fingerprint()
        self._init_db()
        self.exclusions = ExclusionManager()
        self.heuristics = HeuristicAnalyzer()

        # In-memory fast LRU cache (key=sha256, val=verdict). Watcher, process
        # monitor and UI threads share one scanner, and a cache hit reorders it.
        self._cache_lock = threading.Lock()
        self.cache: "collections.OrderedDict[str, int]" = collections.OrderedDict()
        self.cache_capacity = CACHE_CAPACITY
        self._load_warm_cache()

    def _init_db(self):
        with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reputation_cache (
                    sha256 TEXT PRIMARY KEY,
                    verdict INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    sig_version TEXT NOT NULL DEFAULT ''
                )
            """)
            if not self._has_sig_version(conn):
                try:
                    conn.execute("ALTER TABLE reputation_cache ADD COLUMN sig_version TEXT NOT NULL DEFAULT ''")
                except sqlite3.OperationalError:
                    # Another SentinelCore process may have migrated the same DB first
                    if not self._has_sig_version(conn):
                        raise
            conn.commit()

            # Housekeeping only: correctness comes from filtering on sig_version when reading.
            try:
                conn.execute("DELETE FROM reputation_cache WHERE sig_version != ?", (self.sig_version,))
                conn.commit()
            except sqlite3.Error as e:
                logger.warning("Could not purge stale reputation rows: %s", e)

    @staticmethod
    def _has_sig_version(conn: sqlite3.Connection) -> bool:
        return any(row[1] == "sig_version" for row in conn.execute("PRAGMA table_info(reputation_cache)"))

    def _load_warm_cache(self):
        try:
            with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
                rows = conn.execute(
                    "SELECT sha256, verdict FROM reputation_cache WHERE sig_version = ? LIMIT ?",
                    (self.sig_version, WARM_CACHE_ROWS)
                ).fetchall()
            for sha, v in rows:
                self.cache[sha] = v
        except sqlite3.Error as e:
            logger.warning("Reputation cache starts cold: %s", e)

    def record_reputation(self, sha256: str, verdict: int, reason: str):
        with self._cache_lock:
            self.cache[sha256] = verdict
            self.cache.move_to_end(sha256)
            while len(self.cache) > self.cache_capacity:
                self.cache.popitem(last=False)

        now = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO reputation_cache (sha256, verdict, reason, first_seen, sig_version)
                    VALUES (?, ?, ?, ?, ?)
                """, (sha256, verdict, reason, now, self.sig_version))
                conn.commit()
        except sqlite3.Error as e:
            logger.warning("Could not persist reputation for %s: %s", sha256, e)

    def _lookup_known(self, sha256_hash: str, t0: int) -> Optional[ScanVerdict]:
        """Answers from the hash allowlist or the Tier 1 reputation cache without scanning."""
        if self.exclusions.is_hash_excluded(sha256_hash):
            return ScanVerdict(VERDICT_ALLOW, "AllowlistedHash", 0, sha256_hash, 0.0, _elapsed_ms(t0))

        with self._cache_lock:
            cached = self.cache.get(sha256_hash)
            if cached is not None:
                self.cache.move_to_end(sha256_hash)
        if cached is None:
            return None
        return ScanVerdict(cached, "Tier1:ReputationCacheHit", 1, sha256_hash, 0.0, _elapsed_ms(t0))

    def _evaluate(self, sha256_hash: str, head: bytes, filename: str, t0: int,
                  match_signature: Callable[[], Optional[str]],
                  is_trusted: Optional[Callable[[], bool]] = None) -> ScanVerdict:
        """Runs Tier 2 and Tier 3 on unknown content and records the outcome.

        `head` is the start of the content; `match_signature` covers all of it.
        `is_trusted` is asked only when a guessing tier (entropy, heuristics)
        would flag the file; signature matches never consult it.
        """
        def conclude(verdict: int, reason: str, tier: int, entropy: float) -> ScanVerdict:
            self.record_reputation(sha256_hash, verdict, reason)
            return ScanVerdict(verdict, reason, tier, sha256_hash, entropy, _elapsed_ms(t0))

        trusted_answer: Dict[str, bool] = {}

        def trusted() -> bool:
            if "value" not in trusted_answer:
                trusted_answer["value"] = bool(is_trusted and is_trusted())
            return trusted_answer["value"]

        # Tier 2: PE Inspection & 64KB Entropy Gating
        header_window = head[:ENTROPY_WINDOW]
        pe_info = inspect_pe_headers(header_window)
        ent = calculate_shannon_entropy(header_window)

        # High-entropy packed / encrypted executable detection
        if pe_info.get("is_pe") and not trusted():
            if pe_info.get("is_upx_packed") and ent > ENTROPY_GATE_UPX:
                return conclude(VERDICT_QUARANTINE, f"Tier2:UPXPackedBinary(H={ent:.2f})", 2, ent)
            if ent > ENTROPY_GATE_PACKED:
                return conclude(VERDICT_QUARANTINE, f"Tier2:HighEntropyPackedBinary(H={ent:.2f})", 2, ent)

        # Tier 3: Multi-Pattern Threat Signatures
        sig_name = match_signature()
        if sig_name:
            return conclude(VERDICT_QUARANTINE, f"Tier3:{sig_name}", 3, ent)

        # Tier 3b: Multi-Signal Heuristic Risk Scoring (first 2MB to keep latency bounded)
        heur = self.heuristics.analyze_bytes(head[:HEURISTIC_WINDOW], filename)
        if heur["is_suspicious"] and not trusted():
            return conclude(VERDICT_QUARANTINE, f"Tier3:Heuristic.{heur['risk_level']}(Score={heur['score']})", 3, ent)

        # Passed all checks -> Clean
        return conclude(VERDICT_ALLOW, "Tier3:Clean(TrustedPublisher)" if trusted_answer.get("value") else "Tier3:Clean", 3, ent)

    def scan_bytes(self, data: bytes, filename: str = "") -> ScanVerdict:
        """Evaluates a byte buffer through the 3-tier cascade."""
        t0 = time.perf_counter_ns()
        sha256_hash = hashlib.sha256(data).hexdigest()

        known = self._lookup_known(sha256_hash, t0)
        if known is not None:
            return known
        return self._evaluate(sha256_hash, data, filename, t0, lambda: find_signature(data))

    def _scan_large_stream(self, stream: BinaryIO, filename: str,
                           is_trusted: Optional[Callable[[], bool]] = None) -> ScanVerdict:
        """Hashes and signature-matches an open file in one streaming pass.

        A single pass keeps the hash and the scanned bytes in agreement even if
        the file is rewritten while it is being read.
        """
        t0 = time.perf_counter_ns()
        hasher = hashlib.sha256()
        head = b""
        carry = b""
        sig_name: Optional[str] = None

        while True:
            chunk = stream.read(STREAM_CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
            if not head:
                head = chunk[:HEURISTIC_WINDOW]
            if sig_name is None:
                sig_name = find_signature(carry + chunk)
                carry = chunk[-STREAM_OVERLAP:]

        sha256_hash = hasher.hexdigest()
        known = self._lookup_known(sha256_hash, t0)
        if known is not None:
            return known
        return self._evaluate(sha256_hash, head, filename, t0, lambda: sig_name, is_trusted)

    def scan_file(self, file_path: str) -> ScanVerdict:
        """Reads a file safely with streaming chunks for large files."""
        file_path = os.path.abspath(file_path)
        if not os.path.exists(file_path):
            return ScanVerdict(VERDICT_ALLOW, "FileNotFound", 0, "", 0.0, 0.0)

        if self.exclusions.is_path_excluded(file_path):
            return ScanVerdict(VERDICT_ALLOW, "AllowlistedPath", 0, "", 0.0, 0.0)

        _, ext = os.path.splitext(file_path.lower())

        def is_trusted() -> bool:
            # Looked up through the module so tests can substitute it.
            return trust.is_protected_system_path(file_path) or trust.has_valid_signature(file_path)

        try:
            # One handle for the media peek and the scan, so both see the same file
            with open(file_path, "rb") as f:
                # Skip media files from signature scans
                if ext in MEDIA_EXTENSIONS:
                    if is_trusted_media(ext, f.read(MEDIA_MAGIC_PEEK)):
                        return ScanVerdict(VERDICT_ALLOW, "SkippedMediaFile", 1, "", 0.0, 0.0)
                    f.seek(0)

                if os.fstat(f.fileno()).st_size > IN_MEMORY_SCAN_LIMIT:
                    return self._scan_large_stream(f, os.path.basename(file_path), is_trusted)
                data = f.read()
            t0 = time.perf_counter_ns()
            sha256_hash = hashlib.sha256(data).hexdigest()
            known = self._lookup_known(sha256_hash, t0)
            if known is not None:
                return known
            return self._evaluate(sha256_hash, data, os.path.basename(file_path), t0,
                                  lambda: find_signature(data), is_trusted)

        except Exception as e:
            # Fail-open on locked system handles
            return ScanVerdict(VERDICT_ALLOW, f"ScanErrorFailOpen({e})", 0, "", 0.0, 0.0)

    def get_signatures_summary(self) -> Dict[str, Any]:
        """Returns statistics and definitions of active detection engines."""
        signatures_list = [name for _, name in THREAT_PATTERNS]
        return {
            "tier1_cache_entries": len(self.cache),
            "tier1_cache_capacity": self.cache_capacity,
            "tier2_entropy_threshold": ENTROPY_GATE_PACKED,
            "tier2_upx_entropy_threshold": ENTROPY_GATE_UPX,
            "tier3_signatures_count": len(signatures_list),
            "signatures": signatures_list,
            "signature_version": self.sig_version,
            "monitored_media_filters": list(MEDIA_EXTENSIONS)
        }
