import os
import sys
import uuid

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel_ui.single_instance import SingleInstance


def _names():
    tag = uuid.uuid4().hex
    return f"Local\\SentinelTestMutex{tag}", f"Local\\SentinelTestShow{tag}"


def test_first_instance_is_primary_second_is_not():
    mutex, event = _names()
    first = SingleInstance(mutex, event)
    second = SingleInstance(mutex, event)
    try:
        assert first.is_primary
        assert not second.is_primary
    finally:
        second.release()
        first.release()


def test_second_launch_wakes_the_primary_exactly_once():
    mutex, event = _names()
    first = SingleInstance(mutex, event)
    second = SingleInstance(mutex, event)
    try:
        assert not first.show_requested()
        second.ask_primary_to_show()
        assert first.show_requested()
        assert not first.show_requested()
    finally:
        second.release()
        first.release()


def test_releasing_the_primary_frees_the_slot():
    mutex, event = _names()
    first = SingleInstance(mutex, event)
    first.release()
    again = SingleInstance(mutex, event)
    try:
        assert again.is_primary
    finally:
        again.release()
