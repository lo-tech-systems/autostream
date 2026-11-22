"""Tests for the autostream_bluetooth daemon's composition
(platform/bluetooth_service.py).

Exercises BluetoothStateMachine against a fake BluetoothOps (no dbus/gi
required) with an injectable fake clock (window limits / reconnect backoff
tested without any real sleeping): D-Bus signals become the right machine
events, the window's actions reach the adapter and the ops, the heartbeat is
recorded by the poll, and the pairing record is persisted on adoption. The
machines' own rows are covered in test_bluetooth_window.py,
test_bluetooth_devices.py and test_bluetooth_pump.py. FakeOps resolves ops
synchronously by default, so outcomes here are straight-line calls.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
for _p in (REPO_ROOT / "platform",):
    _s = str(_p)
    if _s not in sys.path:
        sys.path.insert(0, _s)

import bluetooth_bluez as bluez_mod  # noqa: E402
import bluetooth_devices as dev_mod  # noqa: E402
import bluetooth_pump as pump_mod  # noqa: E402
import bluetooth_service as svc  # noqa: E402
import bluetooth_window as win  # noqa: E402

MAC_A = "AA:BB:CC:DD:EE:01"
MAC_B = "AA:BB:CC:DD:EE:02"
MAC_C = "AA:BB:CC:DD:EE:03"


class FakeClock:
    """Mutable monotonic-clock stand-in; advance() moves it forward."""

    def __init__(self, start: float = 1000.0) -> None:
        self._t = start

    def __call__(self) -> float:
        return self._t

    def advance(self, seconds: float) -> None:
        self._t += seconds


class FakeOps:
    """Records every call the state machine issues. The op launchers
    resolve synchronously by default, standing in for an op whose async
    D-Bus calls all landed straight away; ``resolve_adopt``/
    ``resolve_remove``/``resolve_reconnect`` set to False leave the op in
    flight (the callback is kept in ``pending_*`` for the test to fire)."""

    def __init__(self) -> None:
        self.adapter_present = True
        self.adapter_kind: str | None = "usb"
        self.calls: list[tuple] = []
        self.adapter_writes: list[tuple] = []
        self.fail_adopt: str | None = None
        self.resolve_adopt = True
        self.resolve_remove = True
        self.resolve_reconnect = True
        self.pending_adopt = None
        self.pending_remove = None
        self.connected_macs: set[str] = set()
        self.aliases: dict[str, str] = {}
        self.purge_error: Exception | None = None
        self.sweep_result = 0

    def set_adapter_property(self, name, value) -> None:
        if not self.adapter_present:
            raise RuntimeError("org.freedesktop.DBus.Error.UnknownObject")
        self.adapter_writes.append((name, value))

    def purge_cached_devices(self, keep_macs) -> int:
        self.calls.append(("purge_cached_devices", frozenset(keep_macs)))
        if self.purge_error is not None:
            raise self.purge_error
        return 0

    def sweep_bonds(self, keep_macs) -> int:
        self.calls.append(("sweep_bonds", frozenset(keep_macs)))
        return self.sweep_result

    def start_discovery(self) -> None:
        self.calls.append(("start_discovery",))

    def stop_discovery(self) -> None:
        self.calls.append(("stop_discovery",))

    def start_adopt(self, mac, entry, old_mac, on_result, is_stale) -> None:
        self.calls.append(("start_adopt", mac, entry, old_mac))
        if not self.resolve_adopt:
            self.pending_adopt = (mac, on_result, is_stale)
            return
        if is_stale():
            return
        on_result(mac, self.fail_adopt is None, self.fail_adopt)

    def start_remove_devices(self, macs, on_done) -> None:
        self.calls.append(("start_remove_devices", tuple(macs)))
        if not self.resolve_remove:
            self.pending_remove = on_done
            return
        on_done()

    def start_reconnect_probe(self, mac, on_result, is_stale) -> None:
        self.calls.append(("start_reconnect_probe", mac))
        if not self.resolve_reconnect or is_stale():
            return
        if mac in self.connected_macs:
            on_result(mac, True)

    def device_alias_async(self, mac, on_result, on_error) -> None:
        self.calls.append(("device_alias_async", mac))
        if mac in self.aliases:
            on_result(self.aliases[mac])
        else:
            on_error(RuntimeError("org.bluez.Error.DoesNotExist"))

    def disconnect(self, mac: str) -> None:
        self.calls.append(("disconnect", mac))

    def remove_device(self, mac: str) -> None:
        self.calls.append(("remove_device", mac))

    def is_connected(self, mac: str) -> bool:
        return mac in self.connected_macs

    def is_connected_async(self, mac, on_result, on_error) -> None:
        self.calls.append(("is_connected_async", mac))
        on_result(mac in self.connected_macs)


class FakePump:
    """Records what the audio source machine did to the pump, without any
    real ALSA device."""

    def __init__(self) -> None:
        self.active_source: str | None = None
        self.active_rate: int | None = None
        self.sets: list = []
        self.buffer_ms_set: list[int] = []
        self.stopped = False
        self.negotiated_rate: int | None = None
        self.locked_out = False

    def set_active_source(self, capture_device, rate=None) -> None:
        self.sets.append(capture_device)
        self.active_source = capture_device
        if rate:
            self.active_rate = rate
            self.negotiated_rate = rate

    def current_source(self):
        return self.active_source

    def has_active_source(self) -> bool:
        return self.active_source is not None

    def holds_loopback(self) -> bool:
        return True

    def playback_locked_out(self) -> bool:
        return self.locked_out

    def is_streaming(self) -> bool:
        return self.active_source is not None

    def get_negotiated_rate(self):
        return self.negotiated_rate

    def set_buffer_ms(self, buffer_ms: int) -> None:
        self.buffer_ms_set.append(buffer_ms)

    def stop(self) -> None:
        self.stopped = True


def _write_paired(tmp_path, mac, name="Paired One"):
    (tmp_path / "bluetooth.json").write_text(
        json.dumps({"paired_mac": mac, "name": name, "paired_at": 1.0}), encoding="utf-8")


def _make_machine(tmp_path, ops=None, clock=None, paired=None, pump=None):
    ops = ops or FakeOps()
    clock = clock or FakeClock()
    if paired:
        _write_paired(tmp_path, paired)
    machine = svc.BluetoothStateMachine(
        ops=ops, state_path=str(tmp_path / "bluetooth.json"), clock=clock,
        hostname=lambda: "test-appliance",
    )
    machine.attach_pump(pump or FakePump())
    return machine, ops, clock


def _open(machine, ops):
    assert machine.window_start() is None
    ops.calls.clear()
    ops.adapter_writes.clear()


AUDIO_DEVICE_B = {"mac": MAC_B, "name": "Speaker Finder", "rssi": -60,
                  "paired": False, "audio_capable": True}
CLOSED_WRITES = [("Discoverable", False), ("Pairable", False), ("Connectable", True)]


# ---------------------------------------------------------------------------
# The window, composed
# ---------------------------------------------------------------------------

class TestWindowStartAndClose:
    def test_start_opens_the_adapter_then_purges_and_discovers(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path, paired=MAC_A)
        assert machine.window_start() is None
        assert ops.adapter_writes == [
            ("PairableTimeout", win.WINDOW_LIMIT_S + 10), ("Pairable", True),
            ("DiscoverableTimeout", win.WINDOW_LIMIT_S + 10), ("Discoverable", True),
            ("Connectable", True),
        ]
        assert ops.calls == [("purge_cached_devices", frozenset({MAC_A})), ("start_discovery",)]
        assert machine.get_status()["window_state"] == win.OPEN

    def test_start_without_an_adapter_is_refused(self, tmp_path):
        ops = FakeOps()
        ops.adapter_present = False
        machine, ops, _ = _make_machine(tmp_path, ops=ops)
        assert machine.window_start() == "no_adapter"
        assert machine.window.state == win.IDLE

    def test_start_while_closing_replies_closing(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        ops.resolve_remove = False
        _open(machine, ops)
        machine.mark_provisional(MAC_B, None)
        machine.window_stop()
        assert machine.window.state == win.CLOSING
        assert machine.window_start() == win.REPLY_CLOSING
        ops.pending_remove()
        assert machine.window.state == win.IDLE
        assert machine.window_start() is None

    def test_stop_closes_and_returns_the_adapter_to_rest(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        _open(machine, ops)
        assert machine.window_stop() is None
        assert ops.adapter_writes == CLOSED_WRITES
        assert ("stop_discovery",) in ops.calls
        assert machine.window.state == win.IDLE
        assert machine.window_poll()["last_close"]["reason"] == win.REASON_CANCEL

    def test_stop_with_no_window_replies_no_window(self, tmp_path):
        machine, _, _ = _make_machine(tmp_path)
        assert machine.window_stop() == win.REPLY_NO_WINDOW

    def test_discovery_purge_failure_does_not_block_discovery(self, tmp_path):
        ops = FakeOps()
        ops.purge_error = RuntimeError("dbus timeout")
        machine, ops, _ = _make_machine(tmp_path, ops=ops)
        assert machine.window_start() is None
        assert ("start_discovery",) in ops.calls


class TestHeartbeat:
    def test_the_poll_is_the_heartbeat(self, tmp_path):
        machine, ops, clock = _make_machine(tmp_path)
        _open(machine, ops)
        for _ in range(10):
            clock.advance(win.HEARTBEAT_TIMEOUT_S - 5)
            machine.window_poll()
            machine.tick()
        assert machine.window.state == win.OPEN

    def test_no_poll_for_the_timeout_closes_the_window(self, tmp_path):
        machine, ops, clock = _make_machine(tmp_path)
        _open(machine, ops)
        clock.advance(win.HEARTBEAT_TIMEOUT_S)
        machine.tick()
        assert ops.adapter_writes == CLOSED_WRITES
        assert machine.window_poll()["last_close"]["reason"] == win.REASON_NO_HEARTBEAT

    def test_the_overall_limit_closes_despite_polls(self, tmp_path):
        machine, ops, clock = _make_machine(tmp_path)
        _open(machine, ops)
        for _ in range(win.WINDOW_LIMIT_S // 2):
            clock.advance(2)
            machine.window_poll()
            machine.tick()
        assert machine.window_poll()["last_close"]["reason"] == win.REASON_LIMIT

    def test_poll_reply_shape(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        _open(machine, ops)
        snap = machine.window_poll()
        assert set(snap) == {"state", "remaining_s", "devices", "adopting", "last_close",
                             "last_error"}
        assert snap["remaining_s"] == win.WINDOW_LIMIT_S

    def test_heartbeat_writes_nothing_to_disk(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        _open(machine, ops)
        machine.window_poll()
        assert not (tmp_path / "bluetooth.json").exists()


class TestIncomingAndScanned:
    def test_agent_accept_lists_the_device_and_asks_its_name(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        ops.aliases[MAC_B] = "Portable CD"
        _open(machine, ops)
        machine.mark_provisional(MAC_B, 123456)
        assert machine.window_poll()["devices"] == [{
            "mac": MAC_B, "name": "Portable CD", "source": dev_mod.SOURCE_INCOMING,
            "state": dev_mod.PROVISIONAL, "passkey": 123456,
        }]
        assert machine.provisional_macs() == frozenset({MAC_B})

    def test_a_name_lookup_failure_leaves_the_mac_as_the_name(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        _open(machine, ops)
        machine.mark_provisional(MAC_B, None)
        assert machine.window_poll()["devices"][0]["name"] == MAC_B

    def test_a_discovered_device_is_listed_only_while_open(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        machine.on_device_found(AUDIO_DEVICE_B)
        assert machine.window_poll()["devices"] == []
        _open(machine, ops)
        machine.on_device_found(AUDIO_DEVICE_B)
        assert machine.window_poll()["devices"][0]["state"] == dev_mod.FOUND

    def test_a_bond_without_the_agent_becomes_provisional(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        _open(machine, ops)
        machine.on_device_paired(MAC_B)
        assert machine.devices.state(MAC_B) == dev_mod.PROVISIONAL

    def test_a_removed_device_leaves_the_list(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        _open(machine, ops)
        machine.mark_provisional(MAC_B, None)
        machine.on_device_removed(MAC_B)
        assert machine.window_poll()["devices"] == []


class TestTapAndAdopt:
    def test_tapping_a_provisional_device_trusts_it_and_replaces_the_old(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path, paired=MAC_A)
        ops.aliases[MAC_B] = "Portable CD"
        _open(machine, ops)
        machine.mark_provisional(MAC_B, None)
        machine.mark_provisional(MAC_C, None)
        assert machine.tap(MAC_B) is None
        assert ("start_adopt", MAC_B, win.ENTRY_TRUST, MAC_A) in ops.calls
        assert machine.trusted_mac() == MAC_B
        persisted = svc.load_persisted_state(str(tmp_path / "bluetooth.json"))
        assert persisted["paired_mac"] == MAC_B
        assert persisted["name"] == "Portable CD"
        assert ("start_remove_devices", (MAC_C,)) in ops.calls
        assert machine.window.state == win.IDLE
        assert machine.window_poll()["last_close"]["reason"] == win.REASON_PAIRED

    def test_tapping_a_found_device_pairs_it_from_here(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        _open(machine, ops)
        machine.on_device_found(AUDIO_DEVICE_B)
        machine.tap(MAC_B)
        assert ("start_adopt", MAC_B, win.ENTRY_PAIR, None) in ops.calls
        persisted = svc.load_persisted_state(str(tmp_path / "bluetooth.json"))
        assert persisted["name"] == "Speaker Finder"

    def test_an_unknown_device_cannot_be_tapped(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        _open(machine, ops)
        assert machine.tap(MAC_B) == win.REPLY_UNKNOWN_DEVICE
        assert machine.tap("not-a-mac") == win.REPLY_UNKNOWN_DEVICE

    def test_a_second_tap_during_an_adoption_is_refused(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        ops.resolve_adopt = False
        _open(machine, ops)
        machine.mark_provisional(MAC_B, None)
        machine.mark_provisional(MAC_C, None)
        machine.tap(MAC_B)
        assert machine.tap(MAC_C) == win.REPLY_ADOPTING
        assert machine.adopting() == MAC_B
        assert machine.window_open() is False

    def test_a_failed_adoption_keeps_the_window_and_reports_the_error(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path, paired=MAC_A)
        ops.fail_adopt = "org.bluez.Error.AuthenticationFailed"
        _open(machine, ops)
        machine.mark_provisional(MAC_B, None)
        machine.tap(MAC_B)
        snap = machine.window_poll()
        assert snap["state"] == win.OPEN
        assert snap["last_error"] == "org.bluez.Error.AuthenticationFailed"
        assert machine.trusted_mac() == MAC_A

    def test_a_late_result_after_forget_is_ignored(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path, paired=MAC_A)
        ops.resolve_adopt = False
        _open(machine, ops)
        machine.mark_provisional(MAC_B, None)
        machine.tap(MAC_B)
        mac, on_result, is_stale = ops.pending_adopt
        machine.forget()
        assert is_stale() is True
        on_result(mac, True, None)
        assert machine.trusted_mac() is None
        assert not (tmp_path / "bluetooth.json").exists()

    def test_adoption_fires_the_pair_success_hook(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        seen = []
        machine.set_pair_success_callback(seen.append)
        _open(machine, ops)
        machine.mark_provisional(MAC_B, None)
        machine.tap(MAC_B)
        assert seen == [MAC_B]

    def test_an_adopt_op_that_cannot_start_fails_the_tap(self, tmp_path):
        class NoAdapterOps(FakeOps):
            def start_adopt(self, *args):
                raise RuntimeError("bluetooth adapter not available")

        machine, ops, _ = _make_machine(tmp_path, ops=NoAdapterOps())
        _open(machine, ops)
        machine.mark_provisional(MAC_B, None)
        machine.tap(MAC_B)
        assert machine.window_poll()["last_error"] == "bluetooth adapter not available"


class TestAttachAndAdapterLoss:
    def test_attach_rests_the_adapter_and_sweeps_all_but_the_paired_bond(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path, paired=MAC_A)
        machine.on_attach()
        assert ops.adapter_writes == [
            ("Alias", "test-appliance"), ("Discoverable", False),
            ("Pairable", False), ("Connectable", True),
        ]
        assert ("sweep_bonds", frozenset({MAC_A})) in ops.calls

    def test_attach_with_nothing_paired_sweeps_every_bond(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        machine.on_attach()
        assert ("sweep_bonds", frozenset()) in ops.calls

    def test_adapter_loss_closes_the_window_without_raising(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        _open(machine, ops)
        machine.mark_provisional(MAC_B, None)
        ops.adapter_present = False
        machine.on_adapter_lost()
        assert machine.window.state == win.IDLE
        assert machine.window_poll()["last_close"]["reason"] == win.REASON_ADAPTER_LOST
        assert not any(c[0] == "start_remove_devices" for c in ops.calls)
        assert machine.get_status()["adapter_present"] is False


class TestForget:
    def test_forget_clears_state_and_removes_device(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path, paired=MAC_A)
        machine.forget()
        assert machine.trusted_mac() is None
        assert ("remove_device", MAC_A) in ops.calls
        assert not (tmp_path / "bluetooth.json").exists()

    def test_forget_noop_when_nothing_paired(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        machine.forget()
        assert ops.calls == []

    def test_forget_closes_an_open_window_first(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path, paired=MAC_A)
        _open(machine, ops)
        machine.forget()
        assert ops.adapter_writes == CLOSED_WRITES
        assert machine.window_poll()["last_close"]["reason"] == win.REASON_FORGET

    def test_forget_invokes_link_change_callback(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path, paired=MAC_A)
        seen = []
        machine.set_link_change_callback(seen.append)
        machine.forget()
        assert seen == [svc.LINK_DISCONNECTED]

    def test_forget_logs_and_does_not_raise_when_remove_device_fails(self, tmp_path, caplog):
        class RaisingOps(FakeOps):
            def remove_device(self, mac):
                raise RuntimeError("dbus timeout")

        machine, ops, _ = _make_machine(tmp_path, ops=RaisingOps(), paired=MAC_A)
        with caplog.at_level("WARNING"):
            machine.forget()
        assert machine.trusted_mac() is None
        assert any("forget" in r.message and MAC_A in r.message for r in caplog.records)


class TestLinkStateAndStatus:
    def test_link_state_updates_for_paired_device(self, tmp_path):
        machine, _, _ = _make_machine(tmp_path, paired=MAC_A)
        machine.on_link_state_changed(MAC_A, True)
        assert machine.get_status()["link"] == svc.LINK_CONNECTED

    def test_link_state_ignores_other_devices(self, tmp_path):
        machine, _, _ = _make_machine(tmp_path, paired=MAC_A)
        machine.on_link_state_changed(MAC_B, True)
        assert machine.get_status()["link"] == svc.LINK_DISCONNECTED

    def test_status_contract_shape(self, tmp_path):
        machine, _, _ = _make_machine(tmp_path)
        status = machine.get_status()
        assert set(status) == {
            "adapter_present", "paired", "link", "streaming", "scanning",
            "buffer_ms", "adapter_kind", "window_state", "held",
        }
        assert status["paired"] is None
        assert status["scanning"] is False
        assert status["window_state"] == win.IDLE
        assert status["held"] is None
        assert status["buffer_ms"] == svc.DEFAULT_BUFFER_MS
        assert status["adapter_kind"] == "usb"

    def test_status_scanning_while_a_window_is_open(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        _open(machine, ops)
        assert machine.get_status()["scanning"] is True

    def test_status_adapter_kind_null_when_no_adapter(self, tmp_path):
        ops = FakeOps()
        ops.adapter_present = False
        machine, _, _ = _make_machine(tmp_path, ops=ops)
        assert machine.get_status()["adapter_kind"] is None


class TestReconnectSupervisor:
    def test_no_reconnect_attempt_without_paired_device(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        machine.reconnect_tick()
        assert ops.calls == []

    def test_no_reconnect_attempt_while_connected(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path, paired=MAC_A)
        machine.on_link_state_changed(MAC_A, True)
        machine.reconnect_tick()
        assert ops.calls == []

    def test_reconnect_bounded_to_interval(self, tmp_path):
        machine, ops, clock = _make_machine(tmp_path, paired=MAC_A)
        machine.reconnect_tick()
        assert ops.calls.count(("start_reconnect_probe", MAC_A)) == 1
        clock.advance(svc.RECONNECT_INTERVAL_SECONDS - 1)
        machine.reconnect_tick()
        assert ops.calls.count(("start_reconnect_probe", MAC_A)) == 1
        clock.advance(2)
        machine.reconnect_tick()
        assert ops.calls.count(("start_reconnect_probe", MAC_A)) == 2

    def test_reconnect_resets_after_reconnection(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path, paired=MAC_A)
        machine.reconnect_tick()
        machine.on_link_state_changed(MAC_A, True)
        machine.on_link_state_changed(MAC_A, False)
        ops.calls.clear()
        machine.reconnect_tick()
        assert ("start_reconnect_probe", MAC_A) in ops.calls

    def test_reconnect_waits_while_a_window_is_open(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path, paired=MAC_A)
        _open(machine, ops)
        machine.tick()
        assert ("start_reconnect_probe", MAC_A) not in ops.calls
        machine.window_stop()
        machine.tick()
        assert ("start_reconnect_probe", MAC_A) in ops.calls

    def test_probe_finding_the_link_up_reports_connected(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path, paired=MAC_A)
        ops.connected_macs.add(MAC_A)
        machine.reconnect_tick()
        assert machine.get_status()["link"] == svc.LINK_CONNECTED

    def test_reconnect_is_stale_once_link_up_or_device_changed(self, tmp_path):
        machine, _, _ = _make_machine(tmp_path, paired=MAC_A)
        assert machine._reconnect_is_stale(MAC_A) is False
        machine.on_link_state_changed(MAC_A, True)
        assert machine._reconnect_is_stale(MAC_A) is True
        machine.forget()
        assert machine._reconnect_is_stale(MAC_A) is True


class TestBufferConfiguration:
    def test_default_buffer_ms_when_nothing_persisted(self, tmp_path):
        machine, _, _ = _make_machine(tmp_path)
        assert machine.get_buffer_ms() == svc.DEFAULT_BUFFER_MS

    @pytest.mark.parametrize("value,ok", [
        (svc.MIN_BUFFER_MS, True), (svc.MAX_BUFFER_MS, True),
        (svc.MIN_BUFFER_MS - 1, False), (svc.MAX_BUFFER_MS + 1, False),
        (200.0, False), ("200", False), (True, False),
    ])
    def test_set_buffer_ms_validation(self, tmp_path, value, ok):
        machine, _, _ = _make_machine(tmp_path)
        assert machine.set_buffer_ms(value) is ok

    def test_set_buffer_ms_persists_and_fires_callback(self, tmp_path):
        machine, _, _ = _make_machine(tmp_path)
        seen = []
        machine.set_buffer_change_callback(seen.append)
        assert machine.set_buffer_ms(9999) is False
        assert machine.set_buffer_ms(350) is True
        assert seen == [350]
        machine2, _, _ = _make_machine(tmp_path)
        assert machine2.get_buffer_ms() == 350

    def test_old_and_corrupt_state_files_default(self, tmp_path):
        _write_paired(tmp_path, MAC_A)
        machine, _, _ = _make_machine(tmp_path)
        assert machine.get_buffer_ms() == svc.DEFAULT_BUFFER_MS
        assert machine.trusted_mac() == MAC_A
        (tmp_path / "bluetooth.json").write_text('{"buffer_ms": 99999}', encoding="utf-8")
        machine, _, _ = _make_machine(tmp_path)
        assert machine.get_buffer_ms() == svc.DEFAULT_BUFFER_MS

    def test_buffer_ms_survives_forget(self, tmp_path):
        machine, _, _ = _make_machine(tmp_path, paired=MAC_A)
        machine.set_buffer_ms(300)
        machine.forget()
        persisted = svc.load_persisted_state(str(tmp_path / "bluetooth.json"))
        assert persisted == {"buffer_ms": 300}


class TestPersistence:
    def test_corrupt_and_missing_state_files_tolerated(self, tmp_path):
        machine, _, _ = _make_machine(tmp_path)
        assert machine.trusted_mac() is None
        (tmp_path / "bluetooth.json").write_text("not json", encoding="utf-8")
        machine, _, _ = _make_machine(tmp_path)
        assert machine.trusted_mac() is None

    def test_a_new_instance_loads_the_adopted_device(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        _open(machine, ops)
        machine.mark_provisional(MAC_B, None)
        machine.tap(MAC_B)
        machine2, _, _ = _make_machine(tmp_path)
        assert machine2.get_status()["paired"] == {"mac": MAC_B, "name": ""}


# ---------------------------------------------------------------------------
# BluetoothOps dispatch shape (no real dbus)
# ---------------------------------------------------------------------------

class FakeBluezClient:
    def __init__(self) -> None:
        self.adapter_present = True
        self.adapter_kind: str | None = "usb"
        self.calls: list[tuple] = []
        self.is_connected_result = False

    def start_discovery(self):
        self.calls.append(("start_discovery",))

    def stop_discovery(self):
        self.calls.append(("stop_discovery",))

    def set_adapter_property(self, name, value):
        self.calls.append(("set_adapter_property", name, value))

    def disconnect_device(self, mac):
        self.calls.append(("disconnect_device", mac))

    def remove_device(self, mac):
        self.calls.append(("remove_device", mac))

    def remove_cached_devices(self, keep_macs):
        self.calls.append(("remove_cached_devices", frozenset(keep_macs)))
        return 3

    def remove_bonded_devices(self, keep_macs):
        self.calls.append(("remove_bonded_devices", frozenset(keep_macs)))
        return 1

    def is_connected(self, mac):
        return self.is_connected_result

    def pair_async(self, mac, on_success, on_error, timeout=None):
        self.calls.append(("pair_async", mac))
        on_success()

    def set_trusted_async(self, mac, trusted, on_success, on_error, timeout=None):
        self.calls.append(("set_trusted_async", mac, trusted))
        on_success()

    def connect_async(self, mac, on_success, on_error, timeout=None):
        self.calls.append(("connect_async", mac))
        on_success()

    def disconnect_async(self, mac, on_success, on_error, timeout=None):
        self.calls.append(("disconnect_async", mac))
        on_success()

    def remove_device_async(self, mac, on_success, on_error, timeout=None):
        self.calls.append(("remove_device_async", mac))
        on_success()

    def is_connected_async(self, mac, on_result, on_error, timeout=None):
        on_result(self.is_connected_result)

    def device_alias_async(self, mac, on_result, on_error, timeout=None):
        on_result("Alias")


class TestBluetoothOps:
    def test_start_adopt_pair_entry_runs_the_whole_chain(self):
        client = FakeBluezClient()
        results = []
        svc.BluetoothOps(client).start_adopt(
            MAC_B, win.ENTRY_PAIR, MAC_A, lambda *r: results.append(r), lambda: False)
        assert results == [(MAC_B, True, None)]
        assert [c[0] for c in client.calls] == [
            "pair_async", "set_trusted_async", "connect_async", "remove_device_async"]

    def test_start_adopt_trust_entry_only_trusts_and_replaces(self):
        client = FakeBluezClient()
        results = []
        svc.BluetoothOps(client).start_adopt(
            MAC_B, win.ENTRY_TRUST, MAC_A, lambda *r: results.append(r), lambda: False)
        assert results == [(MAC_B, True, None)]
        assert [c[0] for c in client.calls] == ["set_trusted_async", "remove_device_async"]

    def test_start_remove_devices_disconnects_then_removes(self):
        client = FakeBluezClient()
        done = []
        svc.BluetoothOps(client).start_remove_devices((MAC_B,), lambda: done.append(True))
        assert client.calls == [("disconnect_async", MAC_B), ("remove_device_async", MAC_B)]
        assert done == [True]

    def test_adapter_property_and_sweep_pass_through(self):
        client = FakeBluezClient()
        ops = svc.BluetoothOps(client)
        ops.set_adapter_property("Pairable", False)
        assert ops.sweep_bonds({MAC_A}) == 1
        assert ops.purge_cached_devices({MAC_A}) == 3
        assert client.calls == [
            ("set_adapter_property", "Pairable", False),
            ("remove_bonded_devices", frozenset({MAC_A})),
            ("remove_cached_devices", frozenset({MAC_A})),
        ]

    def test_unbound_ops_report_no_adapter_and_raise(self):
        ops = svc.BluetoothOps()
        assert ops.adapter_present is False
        assert ops.adapter_kind is None
        assert ops.is_connected(MAC_A) is False
        for call in (lambda: ops.start_discovery(),
                     lambda: ops.set_adapter_property("Pairable", False),
                     lambda: ops.sweep_bonds(set()),
                     lambda: ops.start_adopt(MAC_A, win.ENTRY_PAIR, None, None, None)):
            with pytest.raises(RuntimeError):
                call()
        seen = []
        ops.is_connected_async(MAC_A, seen.append, lambda e: None)
        assert seen == [False]

    def test_set_bluez_binds_a_client_later(self):
        ops = svc.BluetoothOps()
        client = FakeBluezClient()
        ops.set_bluez(client)
        assert ops.adapter_present is True
        ops.start_discovery()
        assert ("start_discovery",) in client.calls


# ---------------------------------------------------------------------------
# The service: wiring, transports, shutdown
# ---------------------------------------------------------------------------

def _make_service(tmp_path, paired=None, ops=None):
    machine, ops, clock = _make_machine(tmp_path, ops=ops, paired=paired)
    service = svc.BluetoothService(state_path=str(tmp_path / "bt.json"))
    service.state_machine = machine
    service.pump = machine.source._pump
    service._ops = ops
    return service, ops


TRANSPORT_B = "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_02/sep1/fd0"
TRANSPORT_A = "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_01/sep1/fd0"
TRANSPORT_A2 = "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_01/sep1/fd1"


class TestPropsChangedBecomeEvents:
    def test_paired_true_marks_an_unknown_device_provisional(self, tmp_path):
        service, ops = _make_service(tmp_path)
        _open(service.state_machine, ops)
        service._on_props_changed(MAC_B, {"Paired": True})
        assert service.state_machine.devices.state(MAC_B) == dev_mod.PROVISIONAL

    def test_alias_change_names_the_entry(self, tmp_path):
        service, ops = _make_service(tmp_path)
        _open(service.state_machine, ops)
        service.state_machine.mark_provisional(MAC_B, None)
        service._on_props_changed(MAC_B, {"Alias": "Portable CD"})
        assert service.state_machine.window_poll()["devices"][0]["name"] == "Portable CD"

    def test_connected_drives_the_link(self, tmp_path):
        service, _ = _make_service(tmp_path, paired=MAC_A)
        service._on_props_changed(MAC_A, {"Connected": True})
        assert service.state_machine.get_status()["link"] == svc.LINK_CONNECTED


class TestTransportsAndTheHold:
    def test_the_paired_device_plays(self, tmp_path):
        service, _ = _make_service(tmp_path, paired=MAC_A)
        service._on_transport(TRANSPORT_A, MAC_A, bluez_mod.TRANSPORT_ACTIVE, 44100, "SBC")
        assert service.pump.active_source == pump_mod.bluealsa_capture_device(MAC_A)
        assert service.state_machine.get_status()["streaming"] is True

    def test_a_provisional_device_is_held_until_the_tap(self, tmp_path):
        service, ops = _make_service(tmp_path)
        sm = service.state_machine
        _open(sm, ops)
        sm.mark_provisional(MAC_B, None)
        service._on_transport(TRANSPORT_B, MAC_B, bluez_mod.TRANSPORT_ACTIVE, 44100, "SBC")
        assert service.pump.active_source is None
        assert sm.get_status()["held"] == {"mac": MAC_B}
        sm.tap(MAC_B)
        assert service.pump.active_source == pump_mod.bluealsa_capture_device(MAC_B)
        assert service.pump.active_rate == 44100
        assert sm.get_status()["held"] is None

    def test_the_paired_device_keeps_playing_while_another_is_held(self, tmp_path):
        service, ops = _make_service(tmp_path, paired=MAC_A)
        sm = service.state_machine
        service._on_transport(TRANSPORT_A, MAC_A, bluez_mod.TRANSPORT_ACTIVE, 44100, "SBC")
        _open(sm, ops)
        sm.mark_provisional(MAC_B, None)
        service._on_transport(TRANSPORT_B, MAC_B, bluez_mod.TRANSPORT_ACTIVE, 48000, "SBC")
        assert service.pump.active_source == pump_mod.bluealsa_capture_device(MAC_A)
        assert service._get_status()["sample_rate"] == 44100

    def test_the_transport_coming_back_is_taken_again(self, tmp_path):
        service, _ = _make_service(tmp_path, paired=MAC_A)
        service._on_transport(TRANSPORT_A, MAC_A, bluez_mod.TRANSPORT_ACTIVE, 44100, "SBC")
        service._on_transport(TRANSPORT_A, MAC_A, bluez_mod.TRANSPORT_IDLE)
        assert service.pump.active_source is None
        service._on_transport(TRANSPORT_A, MAC_A, bluez_mod.TRANSPORT_ACTIVE)
        assert service.pump.active_source == pump_mod.bluealsa_capture_device(MAC_A)
        assert service.pump.active_rate == 44100

    def test_an_old_transport_removed_after_a_new_one_does_not_clear_it(self, tmp_path):
        service, _ = _make_service(tmp_path, paired=MAC_A)
        service._on_transport(TRANSPORT_A, MAC_A, bluez_mod.TRANSPORT_ACTIVE, 44100, "SBC")
        service._on_transport(TRANSPORT_A2, MAC_A, bluez_mod.TRANSPORT_ACTIVE, 44100, "SBC")
        service._on_transport(TRANSPORT_A, MAC_A, bluez_mod.TRANSPORT_REMOVED)
        assert service.pump.active_source == pump_mod.bluealsa_capture_device(MAC_A)
        service._on_transport(TRANSPORT_A2, MAC_A, bluez_mod.TRANSPORT_REMOVED)
        assert service.pump.active_source is None

    def test_codec_and_rate_only_while_a_transport_is_active(self, tmp_path):
        service, _ = _make_service(tmp_path, paired=MAC_A)
        assert "codec" not in service._get_status()
        service._on_transport(TRANSPORT_A, MAC_A, bluez_mod.TRANSPORT_ACTIVE, 44100, "SBC")
        status = service._get_status()
        assert (status["codec"], status["sample_rate"]) == ("SBC", 44100)
        service._on_transport(TRANSPORT_A, MAC_A, bluez_mod.TRANSPORT_REMOVED)
        status = service._get_status()
        assert "codec" not in status and "sample_rate" not in status

    def test_rate_falls_back_to_the_pump_when_the_transport_has_none(self, tmp_path):
        service, _ = _make_service(tmp_path, paired=MAC_A)
        service._on_transport(TRANSPORT_A, MAC_A, bluez_mod.TRANSPORT_ACTIVE, None, "SBC")
        service.pump.negotiated_rate = 48000
        assert service._get_status()["sample_rate"] == 48000

    def test_link_down_clears_the_source(self, tmp_path):
        service, _ = _make_service(tmp_path, paired=MAC_A)
        service.state_machine.on_link_state_changed(MAC_A, True)
        service._on_transport(TRANSPORT_A, MAC_A, bluez_mod.TRANSPORT_ACTIVE, 44100, "SBC")
        service.state_machine.on_link_state_changed(MAC_A, False)
        assert service.pump.active_source is None


class FakeBluezForSync:
    def __init__(self, devices=None, transports=None) -> None:
        self._snapshot = {"devices": devices or {}, "transports": transports or []}

    def find_existing_state(self) -> dict:
        return dict(self._snapshot)


class TestStartupSync:
    def test_startup_sync_arms_the_pump_and_marks_the_link(self, tmp_path):
        service, _ = _make_service(tmp_path, paired=MAC_A)
        service._sync_startup_state(FakeBluezForSync(
            devices={MAC_A: True},
            transports=[{"path": TRANSPORT_A, "mac": MAC_A, "rate": 44100, "codec": "SBC"}]))
        assert service.state_machine.get_status()["link"] == svc.LINK_CONNECTED
        assert service.pump.active_source == pump_mod.bluealsa_capture_device(MAC_A)
        assert service._get_status()["codec"] == "SBC"

    def test_startup_sync_holds_a_transport_that_is_not_the_paired_device(self, tmp_path):
        service, _ = _make_service(tmp_path, paired=MAC_A)
        service._sync_startup_state(FakeBluezForSync(
            transports=[{"path": TRANSPORT_B, "mac": MAC_B, "rate": 44100, "codec": "SBC"}]))
        assert service.pump.active_source is None
        assert service.state_machine.get_status()["held"] == {"mac": MAC_B}

    def test_startup_sync_tolerates_snapshot_failure(self, tmp_path):
        class BrokenBluez:
            def find_existing_state(self):
                raise RuntimeError("dbus timeout")

        service, _ = _make_service(tmp_path)
        service._sync_startup_state(BrokenBluez())
        assert service.pump.active_source is None


class TestPairSuccessHook:
    def test_hook_picks_up_a_link_that_came_up_before_adoption(self, tmp_path):
        service, ops = _make_service(tmp_path)
        sm = service.state_machine
        sm.set_pair_success_callback(service._on_pair_success)
        ops.connected_macs.add(MAC_B)
        _open(sm, ops)
        sm.mark_provisional(MAC_B, None)
        sm.tap(MAC_B)
        assert sm.get_status()["link"] == svc.LINK_CONNECTED


class TestGetStatusWrapsPumpState:
    def test_additive_keys_over_the_state_machine_status(self, tmp_path):
        service, _ = _make_service(tmp_path)
        base = set(service.state_machine.get_status())
        assert set(service._get_status()) == base | {
            "pump_source_active", "loopback_held", "loopback_locked_out",
            "adapter_blocked", "version",
        }

    def test_pump_flags_and_version(self, tmp_path):
        service, _ = _make_service(tmp_path)
        assert service._get_status()["pump_source_active"] is False
        service.pump.locked_out = True
        assert service._get_status()["loopback_locked_out"] is True
        assert service._get_status()["version"] == svc.BLUETOOTH_SERVICE_VERSION == "0.6.0"


class TestSigtermAndStop:
    def test_on_sigterm_invokes_stop_and_removes_itself(self):
        service = svc.BluetoothService()
        calls = []
        service.stop = lambda: calls.append(True)
        assert service._on_sigterm() is False
        assert calls == [True]

    def test_on_sigterm_swallows_exceptions_from_stop(self):
        service = svc.BluetoothService()

        def _boom():
            raise RuntimeError("boom")

        service.stop = _boom
        assert service._on_sigterm() is False

    def test_stop_is_idempotent_and_safe_before_start(self, tmp_path):
        service = svc.BluetoothService(state_path=str(tmp_path / "bt.json"))

        class _CountingServer:
            stops = 0

            def stop(self):
                self.stops += 1

        server = _CountingServer()
        service.control_server = server
        service.stop()
        service.stop()
        assert server.stops == 1

    def test_stop_closes_an_open_window_before_disconnecting(self, tmp_path):
        service, ops = _make_service(tmp_path, paired=MAC_A)
        service.state_machine.on_link_state_changed(MAC_A, True)
        _open(service.state_machine, ops)
        service.stop()
        assert ops.adapter_writes[:3] == CLOSED_WRITES
        assert ("disconnect", MAC_A) in ops.calls
        assert service.state_machine.source.state == pump_mod.SOURCE_OFF

    def test_stop_closes_the_adapter_even_during_a_tap(self, tmp_path):
        service, ops = _make_service(tmp_path)
        ops.resolve_adopt = False
        sm = service.state_machine
        _open(sm, ops)
        sm.mark_provisional(MAC_B, None)
        sm.tap(MAC_B)
        ops.adapter_writes.clear()
        service.stop()
        assert ops.adapter_writes == CLOSED_WRITES

    def test_stop_does_not_disconnect_when_link_not_connected(self, tmp_path):
        service, ops = _make_service(tmp_path, paired=MAC_A)
        service.stop()
        assert not any(c[0] == "disconnect" for c in ops.calls)

    def test_stop_swallows_disconnect_exception(self, tmp_path):
        class RaisingOps(FakeOps):
            def disconnect(self, mac):
                raise RuntimeError("dbus timeout")

        service, _ = _make_service(tmp_path, paired=MAC_A, ops=RaisingOps())
        service.state_machine.on_link_state_changed(MAC_A, True)
        service.stop()


# ---------------------------------------------------------------------------
# Adapter-absent degradation and re-attach
# ---------------------------------------------------------------------------

class _DummyAgent:
    def __init__(self, bus, path, policy) -> None:
        self.policy = policy


class _FakeAgentManager:
    def __init__(self) -> None:
        self.registrations = 0
        self.already = False

    def RegisterAgent(self, *args, **kwargs) -> None:
        self.registrations += 1
        if self.already:
            raise RuntimeError("org.bluez.Error.AlreadyExists")

    def RequestDefaultAgent(self, *args, **kwargs) -> None:
        pass


class _FakeDbusModule:
    def __init__(self) -> None:
        self.agent_manager = _FakeAgentManager()

    def SystemBus(self):
        return _FakeBus()

    def Interface(self, obj, iface):
        return self.agent_manager


class _FakeBus:
    def get_object(self, service, path):
        return object()


def _bare_service(tmp_path):
    service = svc.BluetoothService(state_path=str(tmp_path / "bt.json"))
    service._dbus = _FakeDbusModule()
    service._ops = svc.BluetoothOps()
    service.state_machine = svc.BluetoothStateMachine(
        ops=service._ops, state_path=str(tmp_path / "bt.json"), hostname=lambda: "test-appliance",
    )
    service.state_machine.attach_pump(FakePump())
    service.pump = service.state_machine.source._pump
    return service


def _client_class(attempts, *, fail_connect_first=False, fail_power_first=False):
    class Client:
        def __init__(self, call_timeout=10.0) -> None:
            self.adapter_present = False
            self.adapter_kind = None
            self.subscriptions = 0
            self.writes = []

        def connect(self) -> None:
            attempts["connect"] = attempts.get("connect", 0) + 1
            if fail_connect_first and attempts["connect"] == 1:
                raise svc.bluez_mod.BluezUnavailable("no adapter found")
            self.adapter_present = True
            self.adapter_kind = "usb"

        def power_on(self) -> None:
            attempts["power"] = attempts.get("power", 0) + 1
            if fail_power_first and attempts["power"] == 1:
                raise RuntimeError("rfkill: Operation not permitted")

        def set_adapter_property(self, name, value) -> None:
            self.writes.append((name, value))

        def remove_bonded_devices(self, keep_macs) -> int:
            return 0

        def subscribe(self, **kwargs) -> None:
            assert set(kwargs) == {"on_device_found", "on_props_changed", "on_transport",
                                   "on_device_removed", "on_adapter_lost"}
            self.subscriptions += 1

        def find_existing_state(self) -> dict:
            return {"devices": {}, "transports": []}

    return Client


class TestAdapterAbsentDegradation:
    def test_try_connect_bluez_fails_then_recovers(self, tmp_path, monkeypatch, caplog):
        attempts: dict = {}
        monkeypatch.setattr(svc.bluez_mod, "BluezClient", _client_class(attempts, fail_connect_first=True))
        monkeypatch.setattr(svc.agent_mod, "build_agent_class", lambda dbus: _DummyAgent)
        service = _bare_service(tmp_path)

        with caplog.at_level("WARNING", logger="root"):
            assert service._try_connect_bluez() is False
        assert service.state_machine.get_status()["adapter_present"] is False
        assert not any("recovered after" in r.getMessage() for r in caplog.records)

        caplog.clear()
        with caplog.at_level("WARNING", logger="root"):
            assert service._try_connect_bluez() is True
        assert service.state_machine.get_status()["adapter_present"] is True
        assert service._bluez.subscriptions == 1
        assert service._bluez.writes[:4] == [
            ("Alias", "test-appliance"), ("Discoverable", False),
            ("Pairable", False), ("Connectable", True),
        ]
        recovered = [r for r in caplog.records if "recovered after" in r.getMessage()]
        assert len(recovered) == 1

        before = attempts["connect"]
        assert service._try_connect_bluez() is True
        assert attempts["connect"] == before

    def test_the_agent_is_registered_as_display_yes_no_with_live_getters(self, tmp_path, monkeypatch):
        attempts: dict = {}
        monkeypatch.setattr(svc.bluez_mod, "BluezClient", _client_class(attempts))
        monkeypatch.setattr(svc.agent_mod, "build_agent_class", lambda dbus: _DummyAgent)
        service = _bare_service(tmp_path)
        assert service._try_connect_bluez() is True
        policy = service._agent.policy
        assert policy.decide(svc.agent_mod.KIND_AUTHORIZE, MAC_B) is False
        service._ops.set_bluez(type("C", (), {"adapter_present": True,
                                              "set_adapter_property": lambda *a: None,
                                              "remove_cached_devices": lambda *a: 0,
                                              "start_discovery": lambda *a: None})())
        service.state_machine.window_start()
        assert policy.decide(svc.agent_mod.KIND_AUTHORIZE, MAC_B) is True
        assert service.state_machine.devices.state(MAC_B) == dev_mod.PROVISIONAL

    def test_adapter_loss_then_reattach_reuses_the_client_and_agent(self, tmp_path, monkeypatch):
        attempts: dict = {}
        monkeypatch.setattr(svc.bluez_mod, "BluezClient", _client_class(attempts))
        monkeypatch.setattr(svc.agent_mod, "build_agent_class", lambda dbus: _DummyAgent)
        service = _bare_service(tmp_path)
        assert service._try_connect_bluez() is True
        client, agent = service._bluez, service._agent

        service._on_adapter_lost()
        assert service._bluez_ready is False
        assert service._last_adapter_retry is None

        service._dbus.agent_manager.already = True
        assert service._try_connect_bluez() is True
        assert service._bluez is client and service._agent is agent
        assert client.subscriptions == 1
        assert service._dbus.agent_manager.registrations == 2

    def test_maybe_retry_adapter_bounded_by_interval(self, tmp_path, monkeypatch):
        attempts = {"n": 0}

        class NeverConnectsClient:
            def __init__(self, call_timeout=10.0) -> None:
                self.adapter_present = False

            def connect(self) -> None:
                attempts["n"] += 1
                raise svc.bluez_mod.BluezUnavailable("no adapter found")

        monkeypatch.setattr(svc.bluez_mod, "BluezClient", NeverConnectsClient)
        service = _bare_service(tmp_path)
        service._maybe_retry_adapter()
        service._maybe_retry_adapter()
        assert attempts["n"] == 1
        service._last_adapter_retry -= svc.ADAPTER_RETRY_INTERVAL_SECONDS
        service._maybe_retry_adapter()
        assert attempts["n"] == 2

    def test_power_on_failure_degrades_with_adapter_blocked(self, tmp_path, monkeypatch, caplog):
        attempts: dict = {}
        monkeypatch.setattr(svc.bluez_mod, "BluezClient", _client_class(attempts, fail_power_first=True))
        monkeypatch.setattr(svc.agent_mod, "build_agent_class", lambda dbus: _DummyAgent)
        service = _bare_service(tmp_path)

        assert service._try_connect_bluez() is False
        assert service._get_status()["adapter_blocked"] is True
        with caplog.at_level("WARNING", logger="root"):
            assert service._try_connect_bluez() is True
        assert service._get_status()["adapter_blocked"] is False
        assert len([r for r in caplog.records if "recovered after" in r.getMessage()]) == 1

    def test_no_adapter_at_all_is_not_adapter_blocked(self, tmp_path, monkeypatch):
        class NoAdapterClient:
            def __init__(self, call_timeout=10.0) -> None:
                pass

            def connect(self) -> None:
                raise svc.bluez_mod.BluezUnavailable("no adapter found")

        monkeypatch.setattr(svc.bluez_mod, "BluezClient", NoAdapterClient)
        service = _bare_service(tmp_path)
        assert service._try_connect_bluez() is False
        assert service._get_status()["adapter_blocked"] is False


# ---------------------------------------------------------------------------
# Source-text pins
# ---------------------------------------------------------------------------

def test_nothing_but_the_adapter_mode_writes_discoverable():
    """The appliance becomes discoverable only through
    bluetooth_adapter_mode.open_window; no other daemon module names the
    property in a write."""
    offenders = []
    for path in sorted((REPO_ROOT / "platform").glob("bluetooth_*.py")):
        if path.name in ("bluetooth_adapter_mode.py",):
            continue
        text = path.read_text(encoding="utf-8")
        if re.search(r"""["']Discoverable["']\s*[,)]""", text):
            offenders.append(path.name)
    assert offenders == []


def test_the_service_has_no_scan_or_pairing_modes_left():
    text = (REPO_ROOT / "platform" / "bluetooth_service.py").read_text(encoding="utf-8")
    for gone in ("MODE_SCANNING", "MODE_PAIRING", "PAIR_STATE_", "start_pairing",
                 "get_scan_results", "SCAN_WINDOW_SECONDS"):
        assert gone not in text
