import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel_guard.protection import ShieldState
from sentinel_ui.status import ATTENTION, AT_RISK, PROTECTED, summarize

UNAVAILABLE = ShieldState("ransomware", "Ransomware behaviour shield", False, False, "needs driver")


def _shields(fs: bool, proc: bool):
    return [
        ShieldState("filesystem", "Real-time file shield", fs, True, ""),
        ShieldState("process", "Process execution guard", proc, True, ""),
        UNAVAILABLE,
    ]


def test_all_available_shields_running_is_protected():
    assert summarize(_shields(True, True)).level == PROTECTED


def test_unavailable_shield_does_not_lower_the_level():
    assert summarize(_shields(True, True)).level == PROTECTED


def test_one_shield_off_needs_attention_and_names_it():
    summary = summarize(_shields(True, False))
    assert summary.level == ATTENTION
    assert "process execution guard" in summary.detail


def test_everything_off_is_at_risk():
    assert summarize(_shields(False, False)).level == AT_RISK


def test_tampering_overrides_running_shields():
    assert summarize(_shields(True, True), integrity_ok=False).level == ATTENTION


def test_unknown_integrity_is_not_treated_as_tampering():
    assert summarize(_shields(True, True), integrity_ok=None).level == PROTECTED
