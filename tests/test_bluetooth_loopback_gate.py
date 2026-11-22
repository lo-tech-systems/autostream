"""Tests for the Bluetooth-loopback start gate
(core/autostream_startup.py, _wait_for_bluetooth_loopback).

The shared snd-aloop cable takes its rate/format from whichever end opens
first, so the coordinator must not start input 3 on the loopback's capture
side until the pump reports it holds the playback end. These tests
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

import autostream_startup as startup  # noqa: E402


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


def _gate(monkeypatch, script, wait_seconds=0.2, poll_seconds=0.01):
    class Client(_FakeBtClient):
        pass

    Client.script = script
    Client.calls = 0
    monkeypatch.setattr(startup, "BluetoothClient", Client)
    monkeypatch.setattr(startup, "BLUETOOTH_LOOPBACK_WAIT_SECONDS", wait_seconds)
    monkeypatch.setattr(startup, "BLUETOOTH_LOOPBACK_POLL_SECONDS", poll_seconds)
    return Client


class TestWaitForBluetoothLoopback:
    """The gate is asked only for input 3 (the startup pass decides that),
    so it always polls; it answers whether input 3 may start now."""

    def test_returns_once_pump_holds_loopback(self, monkeypatch):
        client = _gate(
            monkeypatch,
            [{"loopback_held": False}, {"loopback_held": False}, {"loopback_held": True}],
        )
        assert startup._wait_for_bluetooth_loopback() is True
        assert client.calls == 3

    def test_status_without_field_returns_immediately(self, monkeypatch):
        # A status surface without the field: nothing to wait on, and no
        # point polling.
        client = _gate(monkeypatch, [{"pump_source_active": True}])
        assert startup._wait_for_bluetooth_loopback() is True
        assert client.calls == 1

    def test_unreachable_service_times_out_and_refuses(self, monkeypatch):
        client = _gate(monkeypatch, [], wait_seconds=0.05)
        assert startup._wait_for_bluetooth_loopback() is False
        assert client.calls >= 1   # kept polling until the ceiling, then gave up

    def test_never_held_times_out_and_refuses(self, monkeypatch):
        client = _gate(monkeypatch, [{"loopback_held": False}], wait_seconds=0.05)
        assert startup._wait_for_bluetooth_loopback() is False
        assert client.calls >= 2

    def test_shutting_down_does_not_wait(self, monkeypatch):
        client = _gate(monkeypatch, [{"loopback_held": False}], wait_seconds=5.0)
        monkeypatch.setattr(startup.runtime.stop_flag, "wait", lambda timeout: True)
        assert startup._wait_for_bluetooth_loopback() is True
        assert client.calls == 1
