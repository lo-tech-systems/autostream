"""Tests for the pairing window machine (platform/bluetooth_window.py).

One parametrised case per row of the machine's table: the machine is driven
into the row's state through real events, the row's event is applied, and
the next state, the actions and the reply are checked. Pure; no dbus.
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
import bluetooth_window as win  # noqa: E402

PAIRED = "AA:BB:CC:DD:EE:01"
NEW = "AA:BB:CC:DD:EE:02"
OTHER = "AA:BB:CC:DD:EE:03"
T0 = 1000.0

CLOSE_ACTIONS = lambda rejected=(): (  # noqa: E731
    (win.ACT_STOP_DISCOVERY,), (win.ACT_ADAPTER_CLOSE,), (win.ACT_REMOVE_DEVICES, tuple(rejected)),
)


class Holder:
    def __init__(self, mac=None):
        self.mac = mac

    def __call__(self):
        return self.mac


def _machine(paired=PAIRED):
    holder = Holder(paired)
    devices = dev.DeviceList(paired_mac=holder)
    return win.WindowMachine(devices=devices, paired_mac=holder), holder


def _idle():
    return _machine()[0]


def _open():
    m = _idle()
    m.handle(win.START, T0)
    return m


def _open_with_provisional():
    m = _open()
    m.handle(win.AGENT_REQUEST, T0, mac=NEW, passkey=None)
    return m


def _open_with_found():
    m = _open()
    m.handle(win.DISCOVERED, T0, mac=NEW, name="Found One")
    return m


def _adopting():
    m = _open_with_provisional()
    m.handle(win.TAP, T0, mac=NEW)
    return m


def _closing():
    m = _open()
    m.handle(win.STOP, T0)
    return m


SETUPS = {
    "idle": _idle, "open": _open, "open+prov": _open_with_provisional,
    "open+found": _open_with_found, "adopting": _adopting, "closing": _closing,
}

# (setup, event, kwargs, now, next state, actions, reply)
ROWS = [
    ("idle", win.START, {}, T0, win.OPEN,
     ((win.ACT_ADAPTER_OPEN, win.WINDOW_LIMIT_S), (win.ACT_START_DISCOVERY,)), None),
    ("idle", win.HEARTBEAT, {}, T0, win.IDLE, (), None),
    ("idle", win.TICK, {}, T0, win.IDLE, (), None),
    ("idle", win.TAP, {"mac": NEW}, T0, win.IDLE, (), win.REPLY_NO_WINDOW),
    ("idle", win.STOP, {}, T0, win.IDLE, (), win.REPLY_NO_WINDOW),
    ("idle", win.ATTACH, {}, T0, win.IDLE,
     ((win.ACT_ADAPTER_ATTACH,), (win.ACT_SWEEP_BONDS,)), None),
    ("open", win.START, {}, T0 + 5, win.OPEN, (), None),
    ("open", win.HEARTBEAT, {}, T0 + 5, win.OPEN, (), None),
    ("open", win.TICK, {}, T0 + win.WINDOW_LIMIT_S, win.CLOSING, CLOSE_ACTIONS(), None),
    ("open", win.TICK, {}, T0 + win.HEARTBEAT_TIMEOUT_S, win.CLOSING, CLOSE_ACTIONS(), None),
    ("open", win.TICK, {}, T0 + win.HEARTBEAT_TIMEOUT_S - 1, win.OPEN, (), None),
    ("open", win.AGENT_REQUEST, {"mac": NEW, "passkey": 123456}, T0, win.OPEN, (), None),
    ("open", win.PAIRED, {"mac": NEW}, T0, win.OPEN, (), None),
    ("open", win.PAIRED, {"mac": PAIRED}, T0, win.OPEN, (), None),
    ("open", win.DISCOVERED, {"mac": NEW, "name": "X"}, T0, win.OPEN, (), None),
    ("open+prov", win.DEVICE_REMOVED, {"mac": NEW}, T0, win.OPEN, (), None),
    ("open+prov", win.TAP, {"mac": NEW}, T0, win.ADOPTING,
     ((win.ACT_ADOPT, NEW, win.ENTRY_TRUST),), None),
    ("open+found", win.TAP, {"mac": NEW}, T0, win.ADOPTING,
     ((win.ACT_ADOPT, NEW, win.ENTRY_PAIR),), None),
    ("open", win.TAP, {"mac": OTHER}, T0, win.OPEN, (), win.REPLY_UNKNOWN_DEVICE),
    ("open+prov", win.STOP, {}, T0, win.CLOSING, CLOSE_ACTIONS([NEW]), None),
    ("open+prov", win.ADAPTER_LOST, {}, T0, win.CLOSING, CLOSE_ACTIONS([NEW]), None),
    ("open", win.FORGET, {}, T0, win.CLOSING, CLOSE_ACTIONS(), None),
    ("open", win.ATTACH, {}, T0, win.IDLE,
     ((win.ACT_ADAPTER_ATTACH,), (win.ACT_SWEEP_BONDS,)), None),
    ("adopting", win.HEARTBEAT, {}, T0 + 5, win.ADOPTING, (), None),
    ("adopting", win.START, {}, T0 + 5, win.ADOPTING, (), None),
    ("adopting", win.TICK, {}, T0 + win.WINDOW_LIMIT_S + 1, win.ADOPTING, (), None),
    ("adopting", win.AGENT_REQUEST, {"mac": NEW}, T0, win.ADOPTING, (), None),
    ("adopting", win.AGENT_REQUEST, {"mac": OTHER}, T0, win.ADOPTING, (), None),
    ("adopting", win.TAP, {"mac": NEW}, T0, win.ADOPTING, (), win.REPLY_ADOPTING),
    ("adopting", win.ADOPT_DONE, {"mac": NEW, "ok": True}, T0, win.CLOSING,
     ((win.ACT_SOURCE_ADOPT, NEW),) + CLOSE_ACTIONS(), None),
    ("adopting", win.ADOPT_DONE, {"mac": NEW, "ok": False, "error": "boom"}, T0, win.OPEN,
     (), None),
    ("adopting", win.ADOPT_DONE, {"mac": OTHER, "ok": True}, T0, win.ADOPTING, (), None),
    ("adopting", win.STOP, {}, T0, win.ADOPTING, (), None),
    ("adopting", win.ADAPTER_LOST, {}, T0, win.ADOPTING, (), None),
    ("adopting", win.FORGET, {}, T0, win.CLOSING, CLOSE_ACTIONS([NEW]), None),
    ("adopting", win.ATTACH, {}, T0, win.IDLE,
     ((win.ACT_ADAPTER_ATTACH,), (win.ACT_SWEEP_BONDS,)), None),
    ("closing", win.CLEANUP_DONE, {}, T0, win.IDLE, (), None),
    ("closing", win.START, {}, T0, win.CLOSING, (), win.REPLY_CLOSING),
    ("closing", win.TAP, {"mac": NEW}, T0, win.CLOSING, (), win.REPLY_NO_WINDOW),
    ("closing", win.STOP, {}, T0, win.CLOSING, (), None),
    ("closing", win.TICK, {}, T0 + 999, win.CLOSING, (), None),
    ("closing", win.HEARTBEAT, {}, T0, win.CLOSING, (), None),
    ("closing", win.AGENT_REQUEST, {"mac": NEW}, T0, win.CLOSING, (), None),
    ("closing", win.ATTACH, {}, T0, win.IDLE,
     ((win.ACT_ADAPTER_ATTACH,), (win.ACT_SWEEP_BONDS,)), None),
]


@pytest.mark.parametrize(
    "setup,event,kwargs,now,next_state,actions,reply", ROWS,
    ids=[f"{r[0]}-{r[1]}-{i}" for i, r in enumerate(ROWS)],
)
def test_row(setup, event, kwargs, now, next_state, actions, reply):
    m = SETUPS[setup]()
    outcome = m.handle(event, now, **kwargs)
    assert m.state == next_state
    assert outcome.actions == actions
    assert outcome.reply == reply


class TestLimitsAndHeartbeat:
    def test_heartbeat_refresh_keeps_the_window_open(self):
        m = _open()
        for step in range(1, 9):
            now = T0 + step * (win.HEARTBEAT_TIMEOUT_S - 5)
            m.handle(win.HEARTBEAT, now)
            m.handle(win.TICK, now)
            assert m.state == win.OPEN
        assert m.last_close is None

    def test_overall_limit_closes_despite_heartbeats(self):
        m = _open()
        now = T0
        while now < T0 + win.WINDOW_LIMIT_S:
            now += 2
            m.handle(win.HEARTBEAT, now)
            m.handle(win.TICK, now)
        assert m.state == win.CLOSING
        assert m.last_close == {"reason": win.REASON_LIMIT, "error": None}

    def test_missing_heartbeat_closes_with_its_reason(self):
        m = _open()
        m.handle(win.TICK, T0 + win.HEARTBEAT_TIMEOUT_S)
        assert m.last_close["reason"] == win.REASON_NO_HEARTBEAT

    def test_remaining_seconds_counts_down_and_is_none_when_idle(self):
        m = _idle()
        assert m.remaining_s(T0) is None
        m.handle(win.START, T0)
        assert m.remaining_s(T0) == win.WINDOW_LIMIT_S
        assert m.remaining_s(T0 + 30.5) == win.WINDOW_LIMIT_S - 30
        assert m.remaining_s(T0 + win.WINDOW_LIMIT_S + 9) == 0


class TestCloseAndClean:
    def test_close_reason_survives_cleanup_for_the_next_poll(self):
        m = _open()
        m.handle(win.STOP, T0)
        m.handle(win.CLEANUP_DONE, T0)
        snap = m.snapshot(T0)
        assert snap["state"] == win.IDLE
        assert snap["last_close"] == {"reason": win.REASON_CANCEL, "error": None}
        assert snap["devices"] == []

    def test_start_clears_the_previous_close(self):
        m = _open()
        m.handle(win.STOP, T0)
        m.handle(win.CLEANUP_DONE, T0)
        m.handle(win.START, T0 + 1)
        assert m.snapshot(T0 + 1)["last_close"] is None

    def test_adopt_success_rejects_every_other_provisional_device(self):
        m = _open_with_provisional()
        m.handle(win.AGENT_REQUEST, T0, mac=OTHER)
        m.handle(win.TAP, T0, mac=NEW)
        outcome = m.handle(win.ADOPT_DONE, T0, mac=NEW, ok=True)
        assert outcome.actions[-1] == (win.ACT_REMOVE_DEVICES, (OTHER,))
        assert m.last_close["reason"] == win.REASON_PAIRED

    def test_adopt_failure_returns_to_open_with_the_error_and_the_entry(self):
        m = _adopting()
        m.handle(win.ADOPT_DONE, T0, mac=NEW, ok=False, error="org.bluez.Error.Failed")
        snap = m.snapshot(T0)
        assert snap["state"] == win.OPEN
        assert snap["adopting"] is None
        assert snap["last_error"] == "org.bluez.Error.Failed"
        assert snap["devices"][0]["state"] == dev.PROVISIONAL

    def test_stop_during_a_tap_closes_when_the_op_fails(self):
        m = _adopting()
        m.handle(win.STOP, T0)
        outcome = m.handle(win.ADOPT_DONE, T0, mac=NEW, ok=False, error="boom")
        assert m.state == win.CLOSING
        assert m.last_close == {"reason": win.REASON_CANCEL, "error": "boom"}
        assert outcome.actions[-1] == (win.ACT_REMOVE_DEVICES, (NEW,))

    def test_stop_during_a_tap_still_adopts_when_the_op_succeeds(self):
        m = _adopting()
        m.handle(win.ADAPTER_LOST, T0)
        outcome = m.handle(win.ADOPT_DONE, T0, mac=NEW, ok=True)
        assert outcome.actions[0] == (win.ACT_SOURCE_ADOPT, NEW)
        assert m.last_close["reason"] == win.REASON_PAIRED

    def test_found_devices_have_nothing_to_remove(self):
        m = _open_with_found()
        outcome = m.handle(win.STOP, T0)
        assert outcome.actions[-1] == (win.ACT_REMOVE_DEVICES, ())


class TestPairedPaths:
    def test_unknown_bond_becomes_provisional(self):
        m = _open()
        m.handle(win.PAIRED, T0, mac=NEW)
        assert m.devices.state(NEW) == dev.PROVISIONAL

    def test_the_paired_device_re_pairing_is_not_provisional(self):
        m = _open()
        m.handle(win.PAIRED, T0, mac=PAIRED)
        assert m.devices.state(PAIRED) is None

    def test_the_tapped_device_bonding_is_not_provisional(self):
        m = _open_with_found()
        m.handle(win.TAP, T0, mac=NEW)
        m.handle(win.PAIRED, T0, mac=NEW)
        assert m.devices.state(NEW) == dev.CONFIRMING

    def test_the_paired_device_is_never_listed_as_found(self):
        m = _open()
        m.handle(win.DISCOVERED, T0, mac=PAIRED, name="Old")
        assert m.devices.merged() == []

    def test_a_bond_during_a_tap_is_still_swept(self):
        m = _adopting()
        m.handle(win.PAIRED, T0, mac=OTHER)
        outcome = m.handle(win.ADOPT_DONE, T0, mac=NEW, ok=True)
        assert outcome.actions[-1] == (win.ACT_REMOVE_DEVICES, (OTHER,))


class TestQueries:
    def test_is_open_only_in_open(self):
        assert _idle().is_open() is False
        assert _open().is_open() is True
        assert _adopting().is_open() is False
        assert _closing().is_open() is False

    def test_is_active_outside_idle(self):
        assert _idle().is_active() is False
        assert _adopting().is_active() is True
        assert _closing().is_active() is True

    def test_snapshot_shape(self):
        snap = _open_with_provisional().snapshot(T0)
        assert set(snap) == {"state", "remaining_s", "devices", "adopting",
                             "last_close", "last_error"}
        assert snap["devices"] == [{"mac": NEW, "name": NEW, "source": dev.SOURCE_INCOMING,
                                    "state": dev.PROVISIONAL, "passkey": None}]


def test_the_window_module_imports_nothing_from_dbus():
    text = (REPO_ROOT / "platform" / "bluetooth_window.py").read_text(encoding="utf-8")
    assert "dbus" not in text and "bluetooth_bluez" not in text
