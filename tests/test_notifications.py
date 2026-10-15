"""
Threat notifications carry attacker-controlled text (file names, process
names, signature reasons). None of it may ever become PowerShell code.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel_ui import notifications

HOSTILE_NAME = 'invoice$(Start-Process calc)`"; Remove-Item C:\\x; ".exe'


class FakePopen:
    calls = []

    def __init__(self, args, **kwargs):
        FakePopen.calls.append((args, kwargs))


def _notify(monkeypatch, tmp_path, **kwargs):
    FakePopen.calls = []
    monkeypatch.setenv("ProgramData", str(tmp_path))
    monkeypatch.setattr(notifications.subprocess, "Popen", FakePopen)
    notifications.notify_threat_blocked(**kwargs)
    assert len(FakePopen.calls) == 1
    return FakePopen.calls[0]


def test_hostile_text_never_appears_in_the_powershell_command(monkeypatch, tmp_path):
    args, _ = _notify(monkeypatch, tmp_path, title=f"Malware Intercepted: {HOSTILE_NAME}",
                      message=f"File neutralized: {HOSTILE_NAME}", threat_path=HOSTILE_NAME)
    script = " ".join(args)
    assert "Start-Process" not in script
    assert "invoice" not in script


def test_hostile_text_travels_through_the_environment_verbatim(monkeypatch, tmp_path):
    title = f"Malware Intercepted: {HOSTILE_NAME}"
    message = f"File neutralized: {HOSTILE_NAME}"
    _, kwargs = _notify(monkeypatch, tmp_path, title=title, message=message)
    env = kwargs["env"]
    assert env["SENTINEL_TOAST_TITLE"] == title
    assert env["SENTINEL_TOAST_MESSAGE"] == message


def test_toast_window_stays_hidden(monkeypatch, tmp_path):
    args, kwargs = _notify(monkeypatch, tmp_path, title="t", message="m")
    assert "-NonInteractive" in args
    assert kwargs.get("creationflags", 0) & notifications.CREATE_NO_WINDOW


def test_threat_is_appended_to_the_audit_log(monkeypatch, tmp_path):
    _notify(monkeypatch, tmp_path, title="Blocked", message="evil.exe", threat_path="C:\\evil.exe")
    with open(tmp_path / "SentinelCore" / "threats.log", encoding="utf-8") as f:
        line = f.read()
    assert "[THREAT_NEUTRALIZED] Blocked - evil.exe (C:\\evil.exe)" in line
