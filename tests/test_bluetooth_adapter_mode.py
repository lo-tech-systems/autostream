"""Tests for the adapter mode writes (platform/bluetooth_adapter_mode.py):
the order of the writes, the backstop timeouts, the attach set, and that a
missing adapter never raises."""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
for _p in (REPO_ROOT / "platform",):
    _s = str(_p)
    if _s not in sys.path:
        sys.path.insert(0, _s)

import bluetooth_adapter_mode as mode_mod  # noqa: E402


class Recorder:
    def __init__(self, fail_on=()):
        self.writes = []
        self.fail_on = set(fail_on)

    def __call__(self, name, value):
        self.writes.append((name, value))
        if name in self.fail_on or "*" in self.fail_on:
            raise RuntimeError("org.freedesktop.DBus.Error.UnknownObject")


def _mode(recorder):
    return mode_mod.AdapterMode(write=recorder, hostname=lambda: "test-appliance")


def test_attach_sets_the_resting_mode_in_order():
    rec = Recorder()
    assert _mode(rec).at_attach() is True
    assert rec.writes == [
        ("Alias", "test-appliance"), ("Discoverable", False),
        ("Pairable", False), ("Connectable", True),
    ]


def test_open_sets_timeouts_before_their_flags_with_the_backstop():
    rec = Recorder()
    assert _mode(rec).open_window(300) is True
    backstop = 300 + mode_mod.BACKSTOP_SLACK_S
    assert rec.writes == [
        ("PairableTimeout", backstop), ("Pairable", True),
        ("DiscoverableTimeout", backstop), ("Discoverable", True),
        ("Connectable", True),
    ]


def test_close_reasserts_connectable_last():
    rec = Recorder()
    assert _mode(rec).close_window() is True
    assert rec.writes == [("Discoverable", False), ("Pairable", False), ("Connectable", True)]


def test_a_missing_adapter_never_raises_and_every_write_is_still_tried():
    rec = Recorder(fail_on={"*"})
    mode = _mode(rec)
    assert mode.close_window() is False
    assert mode.at_attach() is False
    assert mode.open_window(300) is False
    assert len(rec.writes) == 3 + 4 + 5


def test_one_failed_write_does_not_stop_the_rest():
    rec = Recorder(fail_on={"Discoverable"})
    assert _mode(rec).close_window() is False
    assert [w[0] for w in rec.writes] == ["Discoverable", "Pairable", "Connectable"]


def test_a_failure_is_logged_once_per_sequence_at_debug(caplog):
    rec = Recorder(fail_on={"*"})
    with caplog.at_level("DEBUG", logger="bluetooth_adapter_mode"):
        _mode(rec).close_window()
    records = [r for r in caplog.records if r.name == "bluetooth_adapter_mode"]
    assert len(records) == 1
    assert records[0].levelname == "DEBUG"


def test_nothing_but_open_window_makes_the_adapter_discoverable():
    text = (REPO_ROOT / "platform" / "bluetooth_adapter_mode.py").read_text(encoding="utf-8")
    assert text.count('("Discoverable", True)') == 1
    open_body = text.split("def open_window", 1)[1].split("def close_window", 1)[0]
    assert '("Discoverable", True)' in open_body
