"""
Real-Time Protection Service for SentinelCore
Owns the background shields the desktop app runs: the filesystem watcher and
the process execution guard. Reports what is actually running, so the UI
never has to claim a shield is on.
"""

import collections
import threading
from dataclasses import dataclass
from typing import Any, Callable, Deque, Dict, List, Optional

FILESYSTEM = "filesystem"
PROCESS = "process"
RANSOMWARE = "ransomware"
SHIELD_NAMES = (FILESYSTEM, PROCESS, RANSOMWARE)
STARTABLE = (FILESYSTEM, PROCESS)
HISTORY_LIMIT = 200

SHIELD_LABELS = {
    FILESYSTEM: "Real-time file shield",
    PROCESS: "Process execution guard",
    RANSOMWARE: "Ransomware behaviour shield",
}

# Spotting a ransomware burst needs the PID behind every file write. Only the
# kernel minifilter can see that, and it is not built or signed yet.
RANSOMWARE_UNAVAILABLE = "Needs the kernel minifilter driver, which is not installed"


@dataclass(frozen=True)
class ShieldState:
    name: str
    label: str
    running: bool
    available: bool
    detail: str


def _default_watcher_factory(scanner, vault, **kwargs):
    from sentinel_guard.watcher import FilesystemWatcher
    return FilesystemWatcher(scanner=scanner, vault=vault, **kwargs)


def _default_monitor_factory(scanner, vault, **kwargs):
    from sentinel_guard.process_monitor import ProcessMonitor
    return ProcessMonitor(scanner=scanner, vault=vault, **kwargs)


class ProtectionService:
    def __init__(
        self,
        scanner: Any,
        vault: Any,
        on_file_threat: Optional[Callable[..., None]] = None,
        on_process_threat: Optional[Callable[..., None]] = None,
        watcher_factory: Callable[..., Any] = _default_watcher_factory,
        monitor_factory: Callable[..., Any] = _default_monitor_factory,
    ):
        self.scanner = scanner
        self.vault = vault
        self._factories = {
            FILESYSTEM: lambda: watcher_factory(scanner, vault, on_alert=on_file_threat),
            PROCESS: lambda: monitor_factory(scanner, vault, on_process_blocked=on_process_threat),
        }
        self._shields: Dict[str, Any] = {}
        self._errors: Dict[str, str] = {}
        self._lock = threading.Lock()
        # Totals and events from shields that were stopped, so a restart
        # does not wipe what the user already saw.
        self._retired_totals: Dict[str, int] = collections.Counter()
        self._history: Deque[Dict[str, Any]] = collections.deque(maxlen=HISTORY_LIMIT)

    # ---- control ---------------------------------------------------------

    def _targets(self, name: Optional[str]) -> tuple:
        if name is None:
            return STARTABLE
        if name not in SHIELD_NAMES:
            raise ValueError(f"Unknown shield: {name}")
        return (name,) if name in STARTABLE else ()

    def start(self, name: Optional[str] = None):
        with self._lock:
            for shield_name in self._targets(name):
                current = self._shields.get(shield_name)
                if current is not None and current.is_running:
                    continue
                # Always a fresh instance: a stopped watcher's threads stay
                # blocked in ReadDirectoryChangesW until the next file event.
                shield = self._factories[shield_name]()
                try:
                    shield.start()
                except Exception as err:
                    self._errors[shield_name] = f"Failed to start: {err}"
                    continue
                self._errors.pop(shield_name, None)
                self._shields[shield_name] = shield

    def stop(self, name: Optional[str] = None):
        with self._lock:
            for shield_name in self._targets(name):
                shield = self._shields.pop(shield_name, None)
                if shield is None:
                    continue
                shield.stop()
                self._retire(shield)

    def _retire(self, shield: Any):
        for key, value in self._live_counters(shield).items():
            self._retired_totals[key] += value
        self._history.extend(list(getattr(shield, "recent_events", [])))

    # ---- reporting -------------------------------------------------------

    def is_running(self, name: str) -> bool:
        shield = self._shields.get(name)
        return bool(shield is not None and shield.is_running)

    def states(self) -> List[ShieldState]:
        states = []
        for name in SHIELD_NAMES:
            if name == RANSOMWARE:
                states.append(ShieldState(name, SHIELD_LABELS[name], False, False, RANSOMWARE_UNAVAILABLE))
                continue
            running = self.is_running(name)
            detail = self._errors.get(name) or ("Running" if running else "Turned off")
            states.append(ShieldState(name, SHIELD_LABELS[name], running, True, detail))
        return states

    @staticmethod
    def _live_counters(shield: Any) -> Dict[str, int]:
        return {
            "files_inspected": getattr(shield, "events_processed", 0),
            "file_threats_blocked": getattr(shield, "threats_blocked", 0),
            "processes_inspected": getattr(shield, "inspected_count", 0),
            "processes_blocked": getattr(shield, "blocked_count", 0),
        }

    def counters(self) -> Dict[str, int]:
        totals = collections.Counter(self._retired_totals)
        for shield in list(self._shields.values()):
            totals.update(self._live_counters(shield))
        return {key: totals.get(key, 0) for key in (
            "files_inspected", "file_threats_blocked", "processes_inspected", "processes_blocked")}

    def recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        events = list(self._history)
        for shield in list(self._shields.values()):
            events.extend(list(getattr(shield, "recent_events", [])))
        events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        return events[:limit]
