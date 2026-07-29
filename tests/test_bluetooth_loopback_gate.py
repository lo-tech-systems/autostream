"""Tests for the coordinator's Bluetooth-loopback start gate
(core/autostream_core.py, _wait_for_bluetooth_loopback).

The shared snd-aloop cable takes its rate/format from whichever end opens
first, so the coordinator must not start a monitor input on the loopback's
capture side until the pump reports it holds the playback end. These tests
drive the wait helper directly with a monkeypatched BluetoothClient, so no
socket, daemon, or real clock ceiling is involved.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_core as core_mod  # noqa: E402

BT_CAPTURE = "hw:CARD=ASBT,DEV=1"


class _FakeBtClient:
    """Stands in for BluetoothClient: serves a scripted sequence of status
    replies (the last entry repeats once the script is exhausted)."""

    script: list = []
    calls = 0

    def __init__(self) -> None:
        pass

    def status(self):
        cls = type(self)
        cls.calls += 1
        if not cls.script:
            return None
        idx = min(cls.calls - 1, len(cls.script) - 1)
        return cls.script[idx]


def _gate(monkeypatch, script, installed=True, wait_seconds=0.2, poll_seconds=0.01):
    class Client(_FakeBtClient):
        pass

    Client.script = script
    Client.calls = 0
    monkeypatch.setattr(core_mod, "BluetoothClient", Client)
    monkeypatch.setattr(core_mod, "bluetooth_installed", lambda: installed)
    monkeypatch.setattr(core_mod, "BLUETOOTH_LOOPBACK_WAIT_SECONDS", wait_seconds)
    monkeypatch.setattr(core_mod, "BLUETOOTH_LOOPBACK_POLL_SECONDS", poll_seconds)
    return Client


class TestWaitForBluetoothLoopback:
    def test_non_loopback_device_returns_without_client(self, monkeypatch):
        client = _gate(monkeypatch, [{"loopback_held": False}])
        core_mod._wait_for_bluetooth_loopback("hw:CARD=CODEC,DEV=0")
        assert client.calls == 0

    def test_loopback_playback_side_is_not_gated(self, monkeypatch):
        client = _gate(monkeypatch, [{"loopback_held": False}])
        core_mod._wait_for_bluetooth_loopback("hw:CARD=ASBT,DEV=0")
        assert client.calls == 0

    def test_bluetooth_not_installed_returns_immediately(self, monkeypatch):
        client = _gate(monkeypatch, [{"loopback_held": False}], installed=False)
        core_mod._wait_for_bluetooth_loopback(BT_CAPTURE)
        assert client.calls == 0

    def test_returns_once_pump_holds_loopback(self, monkeypatch):
        client = _gate(
            monkeypatch,
            [{"loopback_held": False}, {"loopback_held": False}, {"loopback_held": True}],
        )
        core_mod._wait_for_bluetooth_loopback(BT_CAPTURE)
        assert client.calls == 3

    def test_status_without_field_returns_immediately(self, monkeypatch):
        # An older bluetooth service that predates the field: nothing to
        # wait on, and no point polling.
        client = _gate(monkeypatch, [{"pump_source_active": True}])
        core_mod._wait_for_bluetooth_loopback(BT_CAPTURE)
        assert client.calls == 1

    def test_unreachable_service_times_out_and_returns(self, monkeypatch):
        client = _gate(monkeypatch, [], wait_seconds=0.05)
        core_mod._wait_for_bluetooth_loopback(BT_CAPTURE)
        assert client.calls >= 1   # kept polling until the ceiling, then gave up

    def test_never_held_times_out_and_returns(self, monkeypatch):
        client = _gate(monkeypatch, [{"loopback_held": False}], wait_seconds=0.05)
        core_mod._wait_for_bluetooth_loopback(BT_CAPTURE)
        assert client.calls >= 2
