"""
Headline protection status for the SentinelCore desktop app.
Derived only from what the ProtectionService reports, never assumed.
"""

from dataclasses import dataclass
from typing import Iterable, Optional

from sentinel_guard.protection import ShieldState

PROTECTED = "PROTECTED"
ATTENTION = "ATTENTION"
AT_RISK = "AT_RISK"

LEVEL_COLORS = {
    PROTECTED: ("#10B981", "#064E3B"),
    ATTENTION: ("#F59E0B", "#451A03"),
    AT_RISK: ("#F43F5E", "#4C0519"),
}


@dataclass(frozen=True)
class StatusSummary:
    level: str
    pill: str
    headline: str
    detail: str


def summarize(shields: Iterable[ShieldState], integrity_ok: Optional[bool] = True) -> StatusSummary:
    """Quarantined files are already neutralised, so they do not lower the level.
    An unavailable shield (no driver) is shown in the list but not held against
    the headline: the user cannot turn it on."""
    available = [s for s in shields if s.available]
    off = [s for s in available if not s.running]

    if integrity_ok is False:
        return StatusSummary(
            ATTENTION, "Tamper detected", "SentinelCore files were modified",
            "Integrity check found changed or missing engine files. Reinstall SentinelCore.")
    if available and len(off) == len(available):
        return StatusSummary(
            AT_RISK, "Not protected", "Real-time protection is off",
            "No shield is running. Turn protection on to scan new files and processes.")
    if off:
        names = ", ".join(s.label.lower() for s in off)
        return StatusSummary(
            ATTENTION, "Partly protected", "Some protection is off",
            f"Not running: {names}.")
    return StatusSummary(
        PROTECTED, "Protected", "Real-time protection is on",
        "New files in your user folders and newly started processes are being scanned.")
