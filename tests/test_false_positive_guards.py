"""
Regression tests for the 2026-10 incident: a heuristic false positive on
C:\\Windows\\System32\\SearchProtocolHost.exe was cached, the process guard
killed it on every launch, isolate_file kept an encrypted copy each time the
delete failed, and one exception stalled the poll loop so the same PID was
"new" again 0.3 s later. 134,674 vault copies, 104 GB, in nine days.
"""

import gc
import os
import shutil
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel_guard.process_monitor import ProcessMonitor
from sentinel_scanner import trust
from sentinel_scanner.engine import SentinelScanner, VERDICT_ALLOW, VERDICT_QUARANTINE
from sentinel_scanner.exclusions import ExclusionManager
from sentinel_vault.vault import QuarantineError, QuarantineVault

SYSTEM_ROOT = os.environ.get("SystemRoot", r"C:\Windows")


@pytest.fixture
def workdir():
    path = tempfile.mkdtemp(prefix="sentinel_fp_")
    yield path
    gc.collect()
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def vault(workdir):
    return QuarantineVault(vault_dir=os.path.join(workdir, "vault"))


@pytest.fixture
def scanner(workdir):
    s = SentinelScanner(db_path=os.path.join(workdir, "rep.db"))
    s.exclusions = ExclusionManager(config_path=os.path.join(workdir, "exclusions.json"))
    return s


def _packed_pe(path: str):
    """A minimal PE header followed by random bytes: entropy far above the Tier 2 gate."""
    header = bytearray(512)
    header[0:2] = b"MZ"
    header[60:64] = (128).to_bytes(4, "little")
    header[128:132] = b"PE\x00\x00"
    with open(path, "wb") as f:
        f.write(bytes(header) + os.urandom(256 * 1024))


# ---- (a) isolation is all or nothing ---------------------------------------

def test_isolation_rolls_back_when_the_original_cannot_be_removed(vault, workdir):
    target = os.path.join(workdir, "locked.exe")
    with open(target, "wb") as f:
        f.write(b"MZ locked payload")
    with open(target, "rb"):  # an open handle blocks deletion on Windows
        with pytest.raises(QuarantineError):
            vault.isolate_file(target, reason="test")
    assert os.path.exists(target)
    assert vault.list_quarantined() == []
    assert [f for f in os.listdir(vault.vault_dir) if f.endswith(".qvault")] == []


def test_isolation_still_works_for_a_removable_file(vault, workdir):
    target = os.path.join(workdir, "evil.exe")
    with open(target, "wb") as f:
        f.write(b"MZ removable payload")
    vault_id = vault.isolate_file(target, reason="test")
    assert not os.path.exists(target)
    assert [i["vault_id"] for i in vault.list_quarantined()] == [vault_id]


# ---- (b) one bad PID cannot stall the poll loop ------------------------------

def test_poll_marks_pids_seen_even_when_inspection_raises(scanner, vault, monkeypatch):
    monitor = ProcessMonitor(scanner, vault)
    monitor.known_pids = {1}
    inspected = []

    def explode(pid):
        inspected.append(pid)
        raise PermissionError("vault write failed")

    monkeypatch.setattr("sentinel_guard.process_monitor.psutil.pids", lambda: [1, 2, 3])
    monkeypatch.setattr(monitor, "_inspect_new_process", explode)
    monitor._poll_once()
    monitor._poll_once()
    assert sorted(inspected) == [2, 3]  # each new PID inspected exactly once
    assert monitor.known_pids == {1, 2, 3}


# ---- (c) never act on Windows system files ----------------------------------

@pytest.mark.parametrize("path", [
    os.path.join(SYSTEM_ROOT, "System32", "SearchProtocolHost.exe"),
    os.path.join(SYSTEM_ROOT, "System32", "winlogon.exe"),
    os.path.join(SYSTEM_ROOT.lower(), "SysWOW64", "x.dll"),
])
def test_windows_files_are_protected_system_paths(path):
    assert trust.is_protected_system_path(path)


@pytest.mark.parametrize("path", [
    os.path.join(os.path.expanduser("~"), "Downloads", "setup.exe"),
    SYSTEM_ROOT + "Evil\\x.exe",  # prefix trick: C:\WindowsEvil is not C:\Windows
    os.path.join(SYSTEM_ROOT, "..", "Users", "x.exe"),
])
def test_other_paths_are_not_protected(path):
    assert not trust.is_protected_system_path(path)


def test_process_guard_only_alerts_on_a_flagged_system_binary(scanner, vault, monkeypatch):
    monitor = ProcessMonitor(scanner, vault)
    system_exe = os.path.join(SYSTEM_ROOT, "System32", "SearchProtocolHost.exe")
    killed = []

    class FakeProc:
        def name(self): return "SearchProtocolHost.exe"
        def exe(self): return system_exe
        def cmdline(self): return []
        def kill(self): killed.append(True)

    class Flagged:
        verdict, reason, tier, scan_time_ms = VERDICT_QUARANTINE, "Tier3:Heuristic.HIGH(Score=50)", 3, 0.1
        def is_malicious(self): return True

    monkeypatch.setattr("sentinel_guard.process_monitor.psutil.Process", lambda pid: FakeProc())
    monkeypatch.setattr("sentinel_guard.process_monitor.os.path.exists", lambda p: True)
    monkeypatch.setattr(scanner, "scan_file", lambda p: Flagged())
    monitor._inspect_new_process(4242)

    assert killed == []
    assert vault.list_quarantined() == []
    assert monitor.blocked_count == 0
    assert monitor.recent_events[-1]["type"] == "SYSTEM_BINARY_FLAGGED_NOT_BLOCKED"


# ---- (d) signed programs skip the guessing tiers ----------------------------

def test_signed_python_interpreter_has_a_valid_signature():
    # python.org builds carry an embedded Authenticode signature.
    assert trust.has_valid_signature(sys._base_executable)


def test_unsigned_file_has_no_valid_signature(workdir):
    target = os.path.join(workdir, "plain.exe")
    _packed_pe(target)
    assert not trust.has_valid_signature(target)


def test_tampered_signed_file_is_not_trusted(workdir):
    target = os.path.join(workdir, "tampered.exe")
    shutil.copyfile(sys._base_executable, target)
    with open(target, "r+b") as f:
        f.seek(1024)
        byte = f.read(1)
        f.seek(1024)
        f.write(bytes([byte[0] ^ 0xFF]))
    assert not trust.has_valid_signature(target)


def test_packed_unsigned_binary_is_still_quarantined(scanner, workdir, monkeypatch):
    target = os.path.join(workdir, "packed.exe")
    _packed_pe(target)
    monkeypatch.setattr(trust, "has_valid_signature", lambda p: False)
    assert scanner.scan_file(target).verdict == VERDICT_QUARANTINE


def test_packed_but_validly_signed_binary_is_allowed(scanner, workdir, monkeypatch):
    target = os.path.join(workdir, "signed_installer.exe")
    _packed_pe(target)
    monkeypatch.setattr(trust, "has_valid_signature", lambda p: True)
    verdict = scanner.scan_file(target)
    assert verdict.verdict == VERDICT_ALLOW
    assert "Trusted" in verdict.reason


def test_signature_rules_still_fire_on_a_signed_file(scanner, workdir, monkeypatch):
    target = os.path.join(workdir, "signed_but_eicar.com")
    with open(target, "wb") as f:
        f.write(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    monkeypatch.setattr(trust, "has_valid_signature", lambda p: True)
    assert scanner.scan_file(target).verdict == VERDICT_QUARANTINE


def _run_guard(scanner, vault, monkeypatch, exe_name, cmdline, cmd_malicious):
    monitor = ProcessMonitor(scanner, vault)
    exe = os.path.join(SYSTEM_ROOT, "System32", exe_name)
    killed = []

    class FakeProc:
        def name(self): return exe_name
        def exe(self): return exe
        def cmdline(self): return cmdline
        def kill(self): killed.append(exe_name)

    class Verdict:
        verdict, reason, tier, scan_time_ms = VERDICT_QUARANTINE, "Tier3:Ransomware.ShadowCopyDelete", 3, 0.1
        def __init__(self, bad): self.bad = bad
        def is_malicious(self): return self.bad

    monkeypatch.setattr("sentinel_guard.process_monitor.psutil.Process", lambda pid: FakeProc())
    monkeypatch.setattr(scanner, "scan_bytes", lambda data, filename="": Verdict(cmd_malicious))
    monkeypatch.setattr(scanner, "scan_file", lambda p: Verdict(False))
    monitor._inspect_new_process(77)
    return monitor, killed


def test_malicious_command_line_still_kills_a_windows_lolbin(scanner, vault, monkeypatch):
    monitor, killed = _run_guard(scanner, vault, monkeypatch, "vssadmin.exe",
                                 ["vssadmin", "delete", "shadows", "/all"], cmd_malicious=True)
    assert killed == ["vssadmin.exe"]
    assert vault.list_quarantined() == []  # the Windows binary itself stays put
    assert monitor.recent_events[-1]["type"] == "PROCESS_CMDLINE_BLOCKED"


@pytest.mark.parametrize("critical", ["winlogon.exe", "csrss.exe", "lsass.exe", "wininit.exe", "smss.exe"])
def test_session_critical_processes_are_never_killed(scanner, vault, monkeypatch, critical):
    monitor, killed = _run_guard(scanner, vault, monkeypatch, critical, [critical, "-x"], cmd_malicious=True)
    assert killed == []
    assert monitor.recent_events[-1]["type"] == "SYSTEM_BINARY_FLAGGED_NOT_BLOCKED"


# ---- found by end-to-end QA of the packaged app -----------------------------

EICAR = b"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_file_shield_quarantines_a_dropped_threat(scanner, vault, workdir):
    # ReadDirectoryChangesW was given a buffer instead of a size, returned None,
    # and the TypeError was swallowed: the shield never handled a single event.
    import time
    from sentinel_guard.watcher import FilesystemWatcher

    watch = os.path.join(workdir, "Downloads")
    os.makedirs(watch)
    alerts = []
    shield = FilesystemWatcher(scanner=scanner, vault=vault, watch_dirs=[watch],
                               on_alert=lambda path, verdict, vault_id: alerts.append(path))
    shield.start()
    try:
        time.sleep(0.3)
        dropped = os.path.join(watch, "invoice.bat")
        with open(dropped, "wb") as f:
            f.write(EICAR)
        deadline = time.time() + 5
        while os.path.exists(dropped) and time.time() < deadline:
            time.sleep(0.1)
        assert not os.path.exists(dropped)
        assert alerts == [dropped]
        assert shield.threats_blocked == 1
    finally:
        shield.stop()


def test_malicious_command_line_never_quarantines_the_interpreter(scanner, vault, workdir, monkeypatch):
    # QA: the packaged app quarantined .venv\Scripts\python.exe because a
    # probe passed the EICAR string on python's command line.
    interpreter = os.path.join(workdir, "python.exe")
    with open(interpreter, "wb") as f:
        f.write(b"MZ user-installed interpreter")
    monitor = ProcessMonitor(scanner, vault)
    killed = []

    class FakeProc:
        def name(self): return "python.exe"
        def exe(self): return interpreter
        def cmdline(self): return ["python", "-c", EICAR.decode()]
        def kill(self): killed.append(True)

    monkeypatch.setattr("sentinel_guard.process_monitor.psutil.Process", lambda pid: FakeProc())
    monitor._inspect_new_process(99)
    assert killed == [True]
    assert os.path.exists(interpreter)
    assert vault.list_quarantined() == []
