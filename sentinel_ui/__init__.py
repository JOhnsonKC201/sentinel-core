"""
SentinelCore Desktop UI & Notification Package
"""

from .notifications import notify_threat_blocked
from .dashboard import SentinelConsole
from .desktop_gui import SentinelDesktopApp

__all__ = ["notify_threat_blocked", "SentinelConsole", "SentinelDesktopApp"]


