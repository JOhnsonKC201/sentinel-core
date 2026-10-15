"""
ProtectionService owns the real-time shields for the desktop app. These tests
use fake shields so no watcher threads or process polling touch the machine.
"""

import collections
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel_guard.protection import ProtectionService, ShieldState


class FakeShield:
    instances = []

    def __init__(self, scanner, vault, **kwargs):
        self.callbacks = kwargs
        self.is_running = False
        self.recent_events = collections.deque(maxlen=100)
        self.events_processed = 0
        self.threats_blocked = 0
        self.inspected_count = 0
        self.blocked_count = 0
        FakeShield.instances.append(self)

    def start(self):
        self.is_running = True

    def stop(self):
        self.is_running = False


class BrokenShield(FakeShield):
    def start(self):
        raise OSError("ReadDirectoryChangesW unavailable")


@pytest.fixture
def service():
    FakeShield.instances = []
    return ProtectionService(scanner=object(), vault=object(),
                             watcher_factory=FakeShield, monitor_factory=FakeShield)


def _state(service, name) -> ShieldState:
    return {s.name: s for s in service.states()}[name]


def test_nothing_runs_until_started(service):
    assert not any(s.running for s in service.states())


def test_start_all_runs_every_available_shield(service):
    service.start()
    assert _state(service, "filesystem").running
    assert _state(service, "process").running


def test_ransomware_shield_is_reported_unavailable_not_on(service):
    service.start()
    ransomware = _state(service, "ransomware")
    assert ransomware.available is False
    assert ransomware.running is False
    assert "driver" in ransomware.detail.lower()


def test_stop_one_shield_leaves_the_other_running(service):
    service.start()
    service.stop("filesystem")
    assert not _state(service, "filesystem").running
    assert _state(service, "process").running


def test_restart_builds_a_fresh_watcher(service):
    # A stopped watcher's threads sit in ReadDirectoryChangesW until the next
    # event; reusing the object would revive them next to the new ones.
    service.start("filesystem")
    first = FakeShield.instances[-1]
    service.stop("filesystem")
    service.start("filesystem")
    assert FakeShield.instances[-1] is not first
    assert first.is_running is False


def test_starting_a_running_shield_is_a_no_op(service):
    service.start("process")
    count = len(FakeShield.instances)
    service.start("process")
    assert len(FakeShield.instances) == count


def test_unknown_shield_name_is_rejected(service):
    with pytest.raises(ValueError):
        service.start("firewall")


def test_a_shield_that_fails_to_start_reports_the_error(service):
    broken = ProtectionService(scanner=object(), vault=object(),
                               watcher_factory=BrokenShield, monitor_factory=FakeShield)
    broken.start()
    fs = _state(broken, "filesystem")
    assert fs.running is False
    assert "ReadDirectoryChangesW unavailable" in fs.detail
    assert _state(broken, "process").running


def test_threat_callbacks_are_wired_to_the_shields():
    seen = []
    FakeShield.instances = []
    svc = ProtectionService(scanner=object(), vault=object(),
                            watcher_factory=FakeShield, monitor_factory=FakeShield,
                            on_file_threat=lambda *a: seen.append(("file", a)),
                            on_process_threat=lambda *a: seen.append(("proc", a)))
    svc.start()
    watcher, monitor = FakeShield.instances
    watcher.callbacks["on_alert"]("C:\\x.exe", "verdict", "vault-1")
    monitor.callbacks["on_process_blocked"](42, "x.exe", "verdict", "vault-2")
    assert seen == [("file", ("C:\\x.exe", "verdict", "vault-1")),
                    ("proc", (42, "x.exe", "verdict", "vault-2"))]


def test_recent_events_merge_both_shields_newest_first(service):
    service.start()
    watcher, monitor = FakeShield.instances
    watcher.recent_events.append({"timestamp": "2026-10-14 10:00:01", "type": "A"})
    monitor.recent_events.append({"timestamp": "2026-10-14 10:00:03", "type": "B"})
    watcher.recent_events.append({"timestamp": "2026-10-14 10:00:02", "type": "C"})
    assert [e["type"] for e in service.recent_events(limit=2)] == ["B", "C"]


def test_counters_survive_a_restart(service):
    service.start("filesystem")
    FakeShield.instances[-1].events_processed = 7
    FakeShield.instances[-1].threats_blocked = 2
    service.stop("filesystem")
    service.start("filesystem")
    FakeShield.instances[-1].events_processed = 3
    counters = service.counters()
    assert counters["files_inspected"] == 10
    assert counters["file_threats_blocked"] == 2


def test_stop_all_stops_everything(service):
    service.start()
    service.stop()
    assert not any(s.running for s in service.states())
