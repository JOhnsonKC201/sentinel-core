"""
SentinelCore Desktop UI & Notification Package
"""

from .notifications import notify_threat_blocked
from .dashboard import SentinelConsole
from .web_dashboard import SentinelWebServer

__all__ = ["notify_threat_blocked", "SentinelConsole", "SentinelWebServer"]

