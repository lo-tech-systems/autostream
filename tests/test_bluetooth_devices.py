"""Tests for the pairing window's device list (platform/bluetooth_devices.py).

One parametrised case per lifecycle row, plus the list's queries: which
devices are removed when the window closes, the audio hold, the merged list
and its name fallback. Pure; no dbus.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
for _p in (REPO_ROOT / "platform",):
    _s = str(_p)
    if _s not in sys.path:
        sys.path.insert(0, _s)

import bluetooth_devices as dev  # noqa: E402

MAC = "AA:BB:CC:DD:EE:02"
OTHER = "AA:BB:CC:DD:EE:03"
PAIRED_MAC = "AA:BB:CC:DD:EE:01"


def _list(paired=PAIRED_MAC):
    return dev.DeviceList(paired_mac=lambda: paired)


def _none(d):
    pass


def _found(d):
    d.on_discovered(MAC, "Speaker Finder")


def _provisional(d):
    d.on_agent_accept(MAC, None)


def _confirming_incoming(d):
    d.on_agent_accept(MAC, None)
    d.on_tap(MAC)


def _confirming_scan(d):
    d.on_discovered(MAC, "Speaker Finder")
    d.on_tap(MAC)


def _paired(d):
    _confirming_incoming(d)
    d.on_adopted(MAC)


SETUPS = {
    "none": _none, "found": _found, "provisional": _provisional,
    "confirming_incoming": _confirming_incoming, "confirming_scan": _confirming_scan,
    "paired": _paired,
}

EVENTS = {
    "discovered": lambda d: d.on_discovered(MAC, "Speaker Finder"),
    "agent_accept": lambda d: d.on_agent_accept(MAC, 123456),
    "paired_signal": lambda d: d.on_paired(MAC),
    "tap": lambda d: d.on_tap(MAC),
    "adopt_ok": lambda d: d.on_adopted(MAC),
    "adopt_failed": lambda d: d.on_adopt_failed(MAC),
    "window_close": lambda d: d.on_window_close(),
    "other_adopted": lambda d: (d.on_agent_accept(OTHER, None), d.on_tap(OTHER),
                                d.on_adopted(OTHER)),
    "interfaces_removed": lambda d: d.on_gone(MAC),
    "forget": lambda d: d.on_forget(MAC),
}

ROWS = [
    ("none", "discovered", dev.FOUND),
    ("none", "agent_accept", dev.PROVISIONAL),
    ("none", "paired_signal", dev.PROVISIONAL),
    ("found", "agent_accept", dev.PROVISIONAL),
    ("found", "paired_signal", dev.PROVISIONAL),
    ("found", "tap", dev.CONFIRMING),
    ("provisional", "tap", dev.CONFIRMING),
    ("provisional", "paired_signal", dev.PROVISIONAL),
    ("provisional", "agent_accept", dev.PROVISIONAL),
    ("provisional", "window_close", dev.REJECTED),
    ("provisional", "other_adopted", dev.REJECTED),
    ("confirming_incoming", "adopt_ok", dev.PAIRED),
    ("confirming_incoming", "adopt_failed", dev.PROVISIONAL),
    ("confirming_scan", "adopt_failed", dev.FOUND),
    ("confirming_incoming", "window_close", dev.REJECTED),
    ("found", "window_close", None),
    ("found", "interfaces_removed", None),
    ("provisional", "interfaces_removed", None),
    ("confirming_scan", "interfaces_removed", None),
    ("paired", "forget", None),
    # Not in the table: ignored, state kept.
    ("none", "tap", None),
    ("none", "forget", None),
    ("found", "adopt_ok", dev.FOUND),
    ("paired", "window_close", dev.PAIRED),
]


@pytest.mark.parametrize("setup,event,expected", ROWS,
                         ids=[f"{r[0]}-{r[1]}" for r in ROWS])
def test_row(setup, event, expected):
    d = _list()
    SETUPS[setup](d)
    EVENTS[event](d)
    assert d.state(MAC) == expected


class TestQueries:
    def test_rejected_after_close_lists_exactly_the_provisional_devices(self):
        d = _list()
        d.on_discovered("AA:BB:CC:DD:EE:10", "Found")
        d.on_agent_accept("AA:BB:CC:DD:EE:11", None)
        d.on_paired("AA:BB:CC:DD:EE:12")
        assert d.on_window_close() == ("AA:BB:CC:DD:EE:11", "AA:BB:CC:DD:EE:12")
        assert d.state("AA:BB:CC:DD:EE:10") is None

    def test_audio_mac_is_only_ever_the_paired_mac(self):
        d = _list()
        assert d.audio_mac() == PAIRED_MAC
        d.on_agent_accept(MAC, None)
        assert d.audio_mac() == PAIRED_MAC
        d.on_tap(MAC)
        assert d.audio_mac() == PAIRED_MAC
        assert _list(paired=None).audio_mac() is None

    def test_names_fall_back_to_the_mac(self):
        d = _list()
        d.on_agent_accept(MAC, None)
        assert d.merged()[0]["name"] == MAC
        assert d.name(MAC) == MAC
        d.set_name(MAC, "Portable Radio")
        assert d.merged()[0]["name"] == "Portable Radio"
        assert d.name(MAC) == "Portable Radio"

    def test_merged_list_keeps_first_appearance_order_and_hides_rejected(self):
        d = _list()
        d.on_agent_accept(OTHER, 654321)
        d.on_discovered(MAC, "Second")
        d.on_discovered(OTHER, "First")
        assert [e["mac"] for e in d.merged()] == [OTHER, MAC]
        assert d.merged()[0]["passkey"] == 654321
        d.on_tap(MAC)
        d.on_adopted(MAC)
        assert [e["mac"] for e in d.merged()] == [MAC]

    def test_a_retried_comparison_shows_its_latest_code(self):
        d = _list()
        d.on_agent_accept(MAC, 111111)
        d.on_agent_accept(MAC, 222222)
        d.on_agent_accept(MAC, None)
        assert d.merged() == [{"mac": MAC, "name": MAC, "source": dev.SOURCE_INCOMING,
                               "state": dev.PROVISIONAL, "passkey": 222222}]

    def test_a_found_device_that_pairs_in_becomes_incoming(self):
        d = _list()
        d.on_discovered(MAC, "Found")
        d.on_paired(MAC)
        d.on_tap(MAC)
        d.on_adopt_failed(MAC)
        assert d.state(MAC) == dev.PROVISIONAL

    def test_provisional_macs(self):
        d = _list()
        d.on_agent_accept(MAC, None)
        d.on_discovered(OTHER, "Found")
        assert d.provisional_macs() == frozenset({MAC})

    def test_macs_are_case_insensitive(self):
        d = _list()
        d.on_agent_accept(MAC.lower(), None)
        assert d.state(MAC) == dev.PROVISIONAL

    def test_clear_empties_the_list(self):
        d = _list()
        d.on_agent_accept(MAC, None)
        d.clear()
        assert d.merged() == [] and d.state(MAC) is None
