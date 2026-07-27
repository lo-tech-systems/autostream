"""Tests for the autostream_bluetooth daemon's state machine
(platform/bluetooth_service.py).

Exercises BluetoothStateMachine against a fake BluetoothOps (no dbus/gi
required) with an injectable fake clock (window expiry / reconnect backoff
tested without any real sleeping) and a synchronous run_async (pairing
outcomes are deterministic rather than racing a background thread).
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

import bluetooth_service as svc  # noqa: E402

MAC_A = "AA:BB:CC:DD:EE:01"
MAC_B = "AA:BB:CC:DD:EE:02"


class FakeClock:
    """Mutable monotonic-clock stand-in; advance() moves it forward."""

    def __init__(self, start: float = 1000.0) -> None:
        self._t = start

    def __call__(self) -> float:
        return self._t

    def advance(self, seconds: float) -> None:
        self._t += seconds


class FakeOps:
    """Records every call the state machine issues; pair_and_trust/connect
    can be made to raise via ``fail_pair``/``fail_connect`` to simulate a
    BlueZ-side failure."""

    def __init__(self) -> None:
        self.adapter_present = True
        self.adapter_kind: str | None = "usb"
        self.calls: list[tuple] = []
        self.fail_pair: Exception | None = None
        self.fail_connect: Exception | None = None
        self.pairable_state: bool | None = None
        self.connected_macs: set[str] = set()
        self.purge_keep_macs: set[str] | None = None
        self.purge_result: int = 0
        self.purge_error: Exception | None = None

    def purge_cached_devices(self, keep_macs: set) -> int:
        self.calls.append(("purge_cached_devices", frozenset(keep_macs)))
        self.purge_keep_macs = set(keep_macs)
        if self.purge_error is not None:
            raise self.purge_error
        return self.purge_result

    def start_discovery(self) -> None:
        self.calls.append(("start_discovery",))

    def stop_discovery(self) -> None:
        self.calls.append(("stop_discovery",))

    def set_pairable(self, pairable: bool) -> None:
        self.pairable_state = pairable
        self.calls.append(("set_pairable", pairable))

    def pair_and_trust(self, mac: str) -> None:
        self.calls.append(("pair_and_trust", mac))
        if self.fail_pair is not None:
            raise self.fail_pair

    def connect(self, mac: str) -> None:
        self.calls.append(("connect", mac))
        if self.fail_connect is not None:
            raise self.fail_connect

    def disconnect(self, mac: str) -> None:
        self.calls.append(("disconnect", mac))

    def remove_device(self, mac: str) -> None:
        self.calls.append(("remove_device", mac))

    def is_connected(self, mac: str) -> bool:
        self.calls.append(("is_connected", mac))
        return mac in self.connected_macs


def _sync_run_async(fn):
    fn()


def _make_machine(tmp_path, ops=None, clock=None):
    ops = ops or FakeOps()
    clock = clock or FakeClock()
    state_path = str(tmp_path / "bluetooth.json")
    machine = svc.BluetoothStateMachine(
        ops=ops, state_path=state_path, clock=clock, run_async=_sync_run_async,
    )
    return machine, ops, clock


AUDIO_DEVICE_A = {"mac": MAC_A, "name": "Turntable A", "rssi": -50,
                  "paired": False, "audio_capable": True}
AUDIO_DEVICE_B = {"mac": MAC_B, "name": "Turntable B", "rssi": -60,
                  "paired": False, "audio_capable": True}


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class TestScan:
    def test_start_scan_enters_scanning_mode(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        assert machine.start_scan() is True
        assert machine.mode == svc.MODE_SCANNING
        assert ("start_discovery",) in ops.calls

    def test_start_scan_rejected_while_pairing(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)
        assert machine.mode == svc.MODE_IDLE  # sync pairing already resolved
        # Force back into pairing mode to test the guard directly.
        with machine._lock:
            machine.mode = svc.MODE_PAIRING
        assert machine.start_scan() is False

    def test_stop_scan_returns_to_idle(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        machine.start_scan()
        machine.stop_scan()
        assert machine.mode == svc.MODE_IDLE
        assert ("stop_discovery",) in ops.calls

    def test_scan_window_auto_stops_after_60s(self, tmp_path):
        machine, ops, clock = _make_machine(tmp_path)
        machine.start_scan()
        clock.advance(svc.SCAN_WINDOW_SECONDS - 1)
        machine.tick()
        assert machine.mode == svc.MODE_SCANNING
        clock.advance(2)
        machine.tick()
        assert machine.mode == svc.MODE_IDLE
        assert ops.calls.count(("stop_discovery",)) == 1

    def test_device_found_ignored_when_not_scanning(self, tmp_path):
        machine, _, _ = _make_machine(tmp_path)
        machine.on_device_found(AUDIO_DEVICE_A)
        assert machine.get_scan_results() == []

    def test_device_found_recorded_while_scanning(self, tmp_path):
        machine, _, _ = _make_machine(tmp_path)
        machine.start_scan()
        machine.on_device_found(AUDIO_DEVICE_A)
        results = machine.get_scan_results()
        assert len(results) == 1
        assert results[0]["mac"] == MAC_A
        assert results[0]["name"] == "Turntable A"
        assert results[0]["rssi"] == -50
        assert results[0]["paired"] is False

    def test_scan_results_cleared_on_new_scan(self, tmp_path):
        machine, _, _ = _make_machine(tmp_path)
        machine.start_scan()
        machine.on_device_found(AUDIO_DEVICE_A)
        machine.stop_scan()
        machine.start_scan()
        assert machine.get_scan_results() == []

    def test_start_scan_purges_cached_devices_keeping_paired_mac(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)  # sync resolution -> MAC_A trusted
        ops.calls.clear()

        assert machine.start_scan() is True
        assert ops.purge_keep_macs == {MAC_A}
        purge_idx = ops.calls.index(("purge_cached_devices", frozenset({MAC_A})))
        discovery_idx = ops.calls.index(("start_discovery",))
        assert purge_idx < discovery_idx

    def test_start_scan_purge_failure_does_not_block_discovery(self, tmp_path):
        ops = FakeOps()
        ops.purge_error = RuntimeError("dbus timeout")
        machine, ops, _ = _make_machine(tmp_path, ops=ops)

        assert machine.start_scan() is True
        assert machine.mode == svc.MODE_SCANNING
        assert ("start_discovery",) in ops.calls

    def test_scan_results_flag_paired_device(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        machine.start_scan()
        machine.on_device_found(AUDIO_DEVICE_A)
        machine.stop_scan()
        machine.start_pairing(MAC_A)  # sync resolution -> paired
        machine.start_scan()
        machine.on_device_found(AUDIO_DEVICE_A)
        results = machine.get_scan_results()
        assert results[0]["paired"] is True


# ---------------------------------------------------------------------------
# Pairing
# ---------------------------------------------------------------------------

class TestPairing:
    def test_successful_pairing_persists_and_reports_done(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        machine.start_scan()
        machine.on_device_found(AUDIO_DEVICE_A)
        machine.stop_scan()

        assert machine.start_pairing(MAC_A) is True
        assert machine.get_pair_status() == {"state": svc.PAIR_STATE_DONE}
        assert machine.trusted_mac() == MAC_A
        assert machine.mode == svc.MODE_IDLE
        assert ("pair_and_trust", MAC_A) in ops.calls
        # Pairable toggled on then off around the attempt.
        assert ops.calls.count(("set_pairable", True)) == 1
        assert ops.calls[-1] == ("set_pairable", False)

        # Persisted to disk.
        persisted = svc.load_persisted_state(str(tmp_path / "bluetooth.json"))
        assert persisted["paired_mac"] == MAC_A
        assert persisted["name"] == "Turntable A"

    def test_failed_pairing_reports_failed_with_error(self, tmp_path):
        ops = FakeOps()
        ops.fail_pair = RuntimeError("boom")
        machine, ops, _ = _make_machine(tmp_path, ops=ops)
        machine.start_pairing(MAC_A)
        status = machine.get_pair_status()
        assert status["state"] == svc.PAIR_STATE_FAILED
        assert "boom" in status["error"]
        assert machine.trusted_mac() is None

    def test_invalid_mac_rejected(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        assert machine.start_pairing("not-a-mac") is False
        assert ops.calls == []

    def test_pairing_rejected_while_already_pairing(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        with machine._lock:
            machine.mode = svc.MODE_PAIRING
        assert machine.start_pairing(MAC_B) is False

    def test_single_paired_device_replacement_removes_old(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)
        assert machine.trusted_mac() == MAC_A

        ops.calls.clear()
        machine.start_pairing(MAC_B)
        assert ("remove_device", MAC_A) in ops.calls
        assert machine.trusted_mac() == MAC_B

    def test_pairing_window_times_out_after_30s(self, tmp_path):
        # A run_async that never resolves (simulating a still-in-flight
        # blocking D-Bus call) so tick()'s own timeout must fire the failure.
        machine, ops, clock = _make_machine(tmp_path, clock=FakeClock())
        machine._run_async = lambda fn: None  # never actually runs
        machine.start_pairing(MAC_A)
        assert machine.mode == svc.MODE_PAIRING

        clock.advance(svc.PAIRING_WINDOW_SECONDS - 1)
        machine.tick()
        assert machine.mode == svc.MODE_PAIRING

        clock.advance(2)
        machine.tick()
        assert machine.mode == svc.MODE_IDLE
        status = machine.get_pair_status()
        assert status["state"] == svc.PAIR_STATE_FAILED
        assert status["error"] == "timeout"

    def test_stale_pair_result_ignored(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        machine._run_async = lambda fn: None
        machine.start_pairing(MAC_A)
        # A result for a MAC that is no longer the in-flight target (e.g. a
        # slow callback racing a new pairing attempt) must not clobber state.
        machine.on_pair_result(MAC_B, True)
        assert machine.trusted_mac() is None
        assert machine.get_pair_status()["state"] == svc.PAIR_STATE_PAIRING

    def test_pairing_window_open_reflects_mode(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        assert machine.pairing_window_open() is False
        machine._run_async = lambda fn: None
        machine.start_pairing(MAC_A)
        assert machine.pairing_window_open() is True
        assert machine.pairing_target_mac() == MAC_A

    def test_replacement_pair_failure_leaves_old_device_paired(self, tmp_path):
        """pair_and_trust(new) must run before
        remove_device(old), so a failed replacement pairing never strands
        the previously-trusted device un-bonded in BlueZ while state still
        claims it is paired."""
        machine, ops, _ = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)
        assert machine.trusted_mac() == MAC_A

        ops.calls.clear()
        ops.fail_pair = RuntimeError("boom")
        assert machine.start_pairing(MAC_B) is True

        status = machine.get_pair_status()
        assert status["state"] == svc.PAIR_STATE_FAILED
        assert machine.trusted_mac() == MAC_A
        assert ("remove_device", MAC_A) not in ops.calls
        assert ("pair_and_trust", MAC_B) in ops.calls

        persisted = svc.load_persisted_state(str(tmp_path / "bluetooth.json"))
        assert persisted["paired_mac"] == MAC_A

    def test_successful_replacement_removes_old_device_after_pairing_new(self, tmp_path):
        """The happy path still removes the old device, but only after the
        new one is pair_and_trust()-ed (call ordering)."""
        machine, ops, _ = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)
        ops.calls.clear()

        machine.start_pairing(MAC_B)
        assert machine.trusted_mac() == MAC_B
        pair_idx = ops.calls.index(("pair_and_trust", MAC_B))
        remove_idx = ops.calls.index(("remove_device", MAC_A))
        assert pair_idx < remove_idx

    def test_pair_success_callback_fires_only_on_success(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        seen = []
        machine.set_pair_success_callback(lambda mac: seen.append(mac))

        ops.fail_pair = RuntimeError("boom")
        machine.start_pairing(MAC_A)
        assert seen == []

        ops.fail_pair = None
        machine.start_pairing(MAC_B)
        assert seen == [MAC_B]

    def test_start_pairing_stops_discovery_when_scanning(self, tmp_path):
        """Entering pairing while a scan is open must
        stop discovery first and clear the scan window bookkeeping, mirroring
        stop_scan()."""
        machine, ops, _ = _make_machine(tmp_path)
        machine.start_scan()
        assert machine.mode == svc.MODE_SCANNING
        ops.calls.clear()

        assert machine.start_pairing(MAC_A) is True
        assert ("stop_discovery",) in ops.calls
        assert machine._scan_started_at is None
        assert machine.mode == svc.MODE_IDLE  # sync resolution -> back to idle


# ---------------------------------------------------------------------------
# Forget
# ---------------------------------------------------------------------------

class TestForget:
    def test_forget_clears_state_and_removes_device(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)
        ops.calls.clear()

        machine.forget()
        assert machine.trusted_mac() is None
        assert ("remove_device", MAC_A) in ops.calls
        state_path = tmp_path / "bluetooth.json"
        assert not state_path.exists()

    def test_forget_noop_when_nothing_paired(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        machine.forget()
        assert ops.calls == []

    def test_forget_invokes_link_change_callback(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)
        seen = []
        machine.set_link_change_callback(lambda state: seen.append(state))
        machine.forget()
        assert seen == [svc.LINK_DISCONNECTED]

    def test_forget_mid_pairing_ignores_late_result_and_persists_nothing(self, tmp_path):
        """forget() must clear _pairing_target_mac so
        a pairing worker thread already in flight (e.g. a replacement pairing
        started before this forget()) cannot land its result late and
        re-persist state the user just asked to clear."""
        machine, ops, _ = _make_machine(tmp_path)
        machine._run_async = lambda fn: None  # never actually runs -> simulates in-flight worker
        machine.start_pairing(MAC_A)
        assert machine.pairing_target_mac() == MAC_A
        assert machine.mode == svc.MODE_PAIRING

        machine.forget()
        assert machine.pairing_target_mac() is None
        assert machine.mode == svc.MODE_IDLE
        assert ("set_pairable", False) in ops.calls  # abandoned window closed

        # The abandoned worker's callback finally arrives.
        machine.on_pair_result(MAC_A, True)
        assert machine.trusted_mac() is None
        assert machine.get_pair_status()["state"] == svc.PAIR_STATE_PAIRING  # untouched

        state_path = tmp_path / "bluetooth.json"
        assert not state_path.exists()

    def test_forget_noop_when_nothing_paired_or_pairing(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        machine.forget()
        assert ops.calls == []

    def test_forget_logs_and_does_not_raise_when_remove_device_fails(self, tmp_path, caplog):
        class RaisingOps(FakeOps):
            def remove_device(self, mac):
                super().remove_device(mac)
                raise RuntimeError("dbus timeout")

        ops = RaisingOps()
        machine, ops, _ = _make_machine(tmp_path, ops=ops)
        machine.start_pairing(MAC_A)

        with caplog.at_level("WARNING"):
            machine.forget()  # must not raise
        assert machine.trusted_mac() is None
        assert any("forget" in r.message and MAC_A in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Link state / streaming / status contract
# ---------------------------------------------------------------------------

class TestLinkStateAndStatus:
    def test_link_state_updates_for_paired_device(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)
        machine.on_link_state_changed(MAC_A, True)
        assert machine.get_status()["link"] == svc.LINK_CONNECTED

    def test_link_state_ignores_other_devices(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)
        machine.on_link_state_changed(MAC_B, True)
        assert machine.get_status()["link"] == svc.LINK_DISCONNECTED

    def test_streaming_flag_reflects_transport(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        assert machine.get_status()["streaming"] is False
        machine.on_transport_changed(True)
        assert machine.get_status()["streaming"] is True
        machine.on_transport_changed(False)
        assert machine.get_status()["streaming"] is False

    def test_status_contract_shape(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        status = machine.get_status()
        assert set(status.keys()) == {
            "adapter_present", "paired", "link", "streaming", "scanning",
            "buffer_ms", "adapter_kind",
        }
        assert status["adapter_present"] is True
        assert status["paired"] is None
        assert status["link"] == svc.LINK_DISCONNECTED
        assert status["scanning"] is False
        assert status["buffer_ms"] == svc.DEFAULT_BUFFER_MS
        assert status["adapter_kind"] == "usb"

    def test_status_paired_field_shape_after_pairing(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)
        status = machine.get_status()
        assert status["paired"] == {"mac": MAC_A, "name": ""}

    def test_status_adapter_kind_null_when_no_adapter(self, tmp_path):
        ops = FakeOps()
        ops.adapter_present = False
        ops.adapter_kind = None
        machine, ops, _ = _make_machine(tmp_path, ops=ops)
        assert machine.get_status()["adapter_kind"] is None

    def test_status_adapter_kind_passthrough_when_present(self, tmp_path):
        ops = FakeOps()
        ops.adapter_kind = "onboard"
        machine, ops, _ = _make_machine(tmp_path, ops=ops)
        assert machine.get_status()["adapter_kind"] == "onboard"


# ---------------------------------------------------------------------------
# Reconnect supervisor
# ---------------------------------------------------------------------------

class TestReconnectSupervisor:
    def test_no_reconnect_attempt_without_paired_device(self, tmp_path):
        machine, ops, clock = _make_machine(tmp_path)
        machine.reconnect_tick()
        assert ops.calls == []

    def test_no_reconnect_attempt_while_connected(self, tmp_path):
        machine, ops, clock = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)
        machine.on_link_state_changed(MAC_A, True)
        ops.calls.clear()
        machine.reconnect_tick()
        assert ops.calls == []

    def test_reconnect_attempted_immediately_when_disconnected(self, tmp_path):
        machine, ops, clock = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)
        # Pairing leaves link disconnected (no PropertiesChanged simulated).
        ops.calls.clear()
        machine.reconnect_tick()
        assert ("connect", MAC_A) in ops.calls

    def test_reconnect_bounded_to_30s_interval(self, tmp_path):
        machine, ops, clock = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)
        ops.calls.clear()

        machine.reconnect_tick()
        assert ops.calls.count(("connect", MAC_A)) == 1

        clock.advance(svc.RECONNECT_INTERVAL_SECONDS - 1)
        machine.reconnect_tick()
        assert ops.calls.count(("connect", MAC_A)) == 1  # still bounded

        clock.advance(2)
        machine.reconnect_tick()
        assert ops.calls.count(("connect", MAC_A)) == 2

    def test_reconnect_resets_after_reconnection(self, tmp_path):
        machine, ops, clock = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)
        ops.calls.clear()

        machine.reconnect_tick()
        machine.on_link_state_changed(MAC_A, True)
        machine.on_link_state_changed(MAC_A, False)
        ops.calls.clear()
        # Immediately due again since the reconnect timer was cleared on reconnect.
        machine.reconnect_tick()
        assert ("connect", MAC_A) in ops.calls

    def test_tick_drives_reconnect_supervisor(self, tmp_path):
        machine, ops, clock = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)
        ops.calls.clear()
        machine.tick()
        assert ("connect", MAC_A) in ops.calls

    def test_reconnect_tick_skips_connect_when_already_connected(self, tmp_path):
        """BlueZ can show Connected:yes for a device the state
        machine still believes "disconnected" (a PropertiesChanged the
        subscription raced/missed). The supervisor must self-heal from a
        cheap is_connected() read instead of hammering Connect() against an
        already-connected device every 30s."""
        machine, ops, clock = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)
        ops.calls.clear()
        ops.connected_macs.add(MAC_A)

        machine.reconnect_tick()
        assert ("connect", MAC_A) not in ops.calls
        assert ("is_connected", MAC_A) in ops.calls
        assert machine.get_status()["link"] == svc.LINK_CONNECTED

    def test_reconnect_tick_still_connects_when_not_connected(self, tmp_path):
        machine, ops, clock = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)
        ops.calls.clear()

        machine.reconnect_tick()
        assert ("connect", MAC_A) in ops.calls
        assert machine.get_status()["link"] == svc.LINK_DISCONNECTED


# ---------------------------------------------------------------------------
# Configurable audio buffer (plan SS1 "Audio buffer")
# ---------------------------------------------------------------------------

class TestBufferConfiguration:
    def test_default_buffer_ms_when_nothing_persisted(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        assert machine.get_buffer_ms() == svc.DEFAULT_BUFFER_MS

    def test_set_buffer_ms_accepts_boundaries(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        assert machine.set_buffer_ms(svc.MIN_BUFFER_MS) is True
        assert machine.get_buffer_ms() == svc.MIN_BUFFER_MS
        assert machine.set_buffer_ms(svc.MAX_BUFFER_MS) is True
        assert machine.get_buffer_ms() == svc.MAX_BUFFER_MS

    def test_set_buffer_ms_rejects_below_minimum(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        assert machine.set_buffer_ms(svc.MIN_BUFFER_MS - 1) is False
        assert machine.get_buffer_ms() == svc.DEFAULT_BUFFER_MS

    def test_set_buffer_ms_rejects_above_maximum(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        assert machine.set_buffer_ms(svc.MAX_BUFFER_MS + 1) is False
        assert machine.get_buffer_ms() == svc.DEFAULT_BUFFER_MS

    def test_set_buffer_ms_rejects_non_int(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        assert machine.set_buffer_ms(200.0) is False
        assert machine.set_buffer_ms("200") is False

    def test_set_buffer_ms_rejects_bool(self, tmp_path):
        """bool is a subclass of int in Python; must be rejected explicitly."""
        machine, ops, _ = _make_machine(tmp_path)
        assert machine.set_buffer_ms(True) is False

    def test_set_buffer_ms_persists_and_round_trips(self, tmp_path):
        machine1, ops1, _ = _make_machine(tmp_path)
        assert machine1.set_buffer_ms(350) is True

        machine2, ops2, _ = _make_machine(tmp_path)
        assert machine2.get_buffer_ms() == 350

    def test_old_state_file_without_buffer_ms_defaults(self, tmp_path):
        """Tolerate a persisted file predating this key (a file written by a
        version of the daemon before buffer_ms existed)."""
        path = tmp_path / "bluetooth.json"
        path.write_text(
            '{"paired_mac": "AA:BB:CC:DD:EE:01", "name": "Turntable", "paired_at": 1.0}',
            encoding="utf-8",
        )
        machine, ops, _ = _make_machine(tmp_path)
        assert machine.get_buffer_ms() == svc.DEFAULT_BUFFER_MS
        assert machine.trusted_mac() == MAC_A

    def test_corrupt_buffer_ms_in_file_tolerated(self, tmp_path):
        path = tmp_path / "bluetooth.json"
        path.write_text('{"buffer_ms": 99999}', encoding="utf-8")
        machine, ops, _ = _make_machine(tmp_path)
        assert machine.get_buffer_ms() == svc.DEFAULT_BUFFER_MS

    def test_set_buffer_ms_fires_callback_only_on_success(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        seen = []
        machine.set_buffer_change_callback(lambda ms: seen.append(ms))

        assert machine.set_buffer_ms(9999) is False
        assert seen == []

        assert machine.set_buffer_ms(300) is True
        assert seen == [300]

    def test_buffer_ms_survives_forget(self, tmp_path):
        """Forgetting the paired device must not drop a configured buffer."""
        machine, ops, _ = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)
        machine.set_buffer_ms(300)
        machine.forget()

        state_path = tmp_path / "bluetooth.json"
        assert state_path.exists()
        persisted = svc.load_persisted_state(str(state_path))
        assert persisted.get("buffer_ms") == 300
        assert "paired_mac" not in persisted


# ---------------------------------------------------------------------------
# Persistence round-trip across instances
# ---------------------------------------------------------------------------

class TestPersistenceRoundTrip:
    def test_new_instance_loads_prior_paired_device(self, tmp_path):
        machine1, ops1, _ = _make_machine(tmp_path)
        machine1.start_pairing(MAC_A)

        machine2, ops2, _ = _make_machine(tmp_path)
        assert machine2.trusted_mac() == MAC_A
        assert machine2.get_status()["paired"]["mac"] == MAC_A

    def test_corrupt_state_file_tolerated(self, tmp_path):
        path = tmp_path / "bluetooth.json"
        path.write_text("not json", encoding="utf-8")
        machine, ops, _ = _make_machine(tmp_path)
        assert machine.trusted_mac() is None

    def test_missing_state_file_tolerated(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        assert machine.trusted_mac() is None


# ---------------------------------------------------------------------------
# BluetoothOps dispatch shape (no real dbus; verifies BluetoothOps composes
# the expected BluezClient calls in the expected order for pair_and_trust)
# ---------------------------------------------------------------------------

class FakeBluezClient:
    def __init__(self) -> None:
        self.adapter_present = True
        self.adapter_kind: str | None = "usb"
        self.calls: list[tuple] = []

    def start_discovery(self):
        self.calls.append(("start_discovery",))

    def stop_discovery(self):
        self.calls.append(("stop_discovery",))

    def set_pairable(self, pairable):
        self.calls.append(("set_pairable", pairable))

    def pair(self, mac):
        self.calls.append(("pair", mac))

    def set_trusted(self, mac, trusted=True):
        self.calls.append(("set_trusted", mac, trusted))

    def connect_device(self, mac):
        self.calls.append(("connect_device", mac))

    def disconnect_device(self, mac):
        self.calls.append(("disconnect_device", mac))

    def remove_device(self, mac):
        self.calls.append(("remove_device", mac))

    def remove_cached_devices(self, keep_macs):
        self.calls.append(("remove_cached_devices", frozenset(keep_macs)))
        return self.remove_cached_devices_result

    remove_cached_devices_result = 0

    def is_connected(self, mac):
        self.calls.append(("is_connected", mac))
        return self.is_connected_result

    is_connected_result = False


class TestBluetoothOps:
    def test_pair_and_trust_calls_pair_then_trust_then_connect(self):
        client = FakeBluezClient()
        ops = svc.BluetoothOps(client)
        ops.pair_and_trust(MAC_A)
        assert client.calls == [
            ("pair", MAC_A),
            ("set_trusted", MAC_A, True),
            ("connect_device", MAC_A),
        ]

    def test_adapter_present_reflects_client(self):
        client = FakeBluezClient()
        client.adapter_present = False
        ops = svc.BluetoothOps(client)
        assert ops.adapter_present is False

    def test_adapter_present_false_and_calls_raise_when_bluez_unbound(self):
        """Adapter-absent degradation: a BluetoothOps constructed
        before BlueZ is reachable reports adapter_present False and refuses
        to make any bluez-driving call rather than crashing on None."""
        ops = svc.BluetoothOps()
        assert ops.adapter_present is False
        with pytest.raises(RuntimeError):
            ops.start_discovery()
        with pytest.raises(RuntimeError):
            ops.pair_and_trust(MAC_A)

    def test_set_bluez_binds_a_client_later(self):
        ops = svc.BluetoothOps()
        client = FakeBluezClient()
        client.adapter_present = True
        ops.set_bluez(client)
        assert ops.adapter_present is True
        ops.start_discovery()
        assert ("start_discovery",) in client.calls

    def test_is_connected_false_when_bluez_unbound(self):
        """Unlike the other ops methods, is_connected()
        tolerates an absent BlueZ client by returning False rather than
        raising — the reconnect supervisor and pair-success hook use it only
        to decide whether to skip other work."""
        ops = svc.BluetoothOps()
        assert ops.is_connected(MAC_A) is False

    def test_is_connected_dispatches_to_client(self):
        client = FakeBluezClient()
        client.is_connected_result = True
        ops = svc.BluetoothOps(client)
        assert ops.is_connected(MAC_A) is True
        assert ("is_connected", MAC_A) in client.calls

    def test_adapter_kind_passthrough_when_bound(self):
        client = FakeBluezClient()
        client.adapter_kind = "onboard"
        ops = svc.BluetoothOps(client)
        assert ops.adapter_kind == "onboard"

    def test_adapter_kind_none_when_bluez_unbound(self):
        ops = svc.BluetoothOps()
        assert ops.adapter_kind is None

    def test_purge_cached_devices_dispatches_to_client(self):
        client = FakeBluezClient()
        client.remove_cached_devices_result = 3
        ops = svc.BluetoothOps(client)
        assert ops.purge_cached_devices({MAC_A}) == 3
        assert ("remove_cached_devices", frozenset({MAC_A})) in client.calls

    def test_purge_cached_devices_raises_when_bluez_unbound(self):
        ops = svc.BluetoothOps()
        with pytest.raises(RuntimeError):
            ops.purge_cached_devices(set())


# ---------------------------------------------------------------------------
# SIGTERM handling
# ---------------------------------------------------------------------------

class TestMakeSigtermHandler:
    def test_handler_invokes_stop(self):
        calls = []
        handler = svc.make_sigterm_handler(lambda: calls.append(True))
        handler(15, None)
        assert calls == [True]

    def test_handler_swallows_exceptions_from_stop(self):
        def _boom():
            raise RuntimeError("boom")

        handler = svc.make_sigterm_handler(_boom)
        handler(15, None)  # must not raise


# ---------------------------------------------------------------------------
# Transport-during-pairing dead-arm, pair-success hook,
# reconnect-supervisor self-heal, and startup-sync self-heal.
# ---------------------------------------------------------------------------

class FakePump:
    """Records what BluetoothService's transport/pair-success wiring did to
    the pump, without any real ALSA device."""

    def __init__(self) -> None:
        self.active_source: str | None = None
        self.active_rate: int | None = None
        self.clears = 0
        self.buffer_ms_set: list[int] = []
        self.stopped = False

    def set_active_source(self, capture_device, rate=None) -> None:
        self.active_source = capture_device
        if capture_device is None:
            self.clears += 1
        if rate:
            self.active_rate = rate

    def has_active_source(self) -> bool:
        return self.active_source is not None

    def is_streaming(self) -> bool:
        return self.active_source is not None

    def set_buffer_ms(self, buffer_ms: int) -> None:
        self.buffer_ms_set.append(buffer_ms)

    def stop(self) -> None:
        self.stopped = True


class FakeBluezForSync:
    """Just enough of BluezClient for _sync_startup_state()'s own call
    surface (find_existing_state())."""

    def __init__(self, devices=None, transport_active=False, transport_rate=None) -> None:
        self._snapshot = {
            "devices": devices or {},
            "transport_active": transport_active,
            "transport_rate": transport_rate,
        }

    def find_existing_state(self) -> dict:
        return dict(self._snapshot)


def _make_service(tmp_path, machine=None, ops=None) -> tuple[svc.BluetoothService, "FakePump"]:
    ops = ops or FakeOps()
    machine = machine or _make_machine(tmp_path, ops=ops)[0]
    service = svc.BluetoothService(state_path=str(tmp_path / "bt.json"))
    service.state_machine = machine
    service.pump = FakePump()
    service._ops = ops
    return service, ops


class TestTransportDuringPairingDeadArmFix:
    def test_transport_during_pairing_uses_pairing_target_mac(self, tmp_path):
        """Primary fix: the transport can appear while pair_and_trust() is
        still in flight (trusted_mac() is None) — it must be attributed to
        the in-flight pairing target, not dropped."""
        machine, ops, _ = _make_machine(tmp_path)
        machine._run_async = lambda fn: None  # keep pairing in-flight
        machine.start_pairing(MAC_A)
        assert machine.trusted_mac() is None
        assert machine.pairing_target_mac() == MAC_A

        service, _ = _make_service(tmp_path, machine=machine, ops=ops)
        service._on_transport_changed(True, rate=44100)

        assert service.pump.active_source == svc.pump_mod.bluealsa_capture_device(MAC_A)
        assert service.pump.active_rate == 44100

    def test_transport_with_no_trusted_or_pairing_mac_stays_zero_fill(self, tmp_path):
        service, ops = _make_service(tmp_path)
        service._on_transport_changed(True, rate=44100)
        assert service.pump.active_source is None

    def test_pairing_completes_after_transport_appeared_arms_pump_via_hook(self, tmp_path):
        """Pair-success hook (belt-and-braces): if a transport was already
        active by the time pairing landed but the pump was never armed, the
        hook arms it."""
        machine, ops, _ = _make_machine(tmp_path)
        ops.connected_macs.add(MAC_A)
        service, _ = _make_service(tmp_path, machine=machine, ops=ops)
        machine.set_pair_success_callback(service._on_pair_success)

        service._last_transport_active = True
        service._last_transport_rate = 44100

        assert machine.start_pairing(MAC_A) is True
        assert service.pump.active_source == svc.pump_mod.bluealsa_capture_device(MAC_A)
        assert service.pump.active_rate == 44100
        assert machine.get_status()["link"] == svc.LINK_CONNECTED

    def test_pair_success_hook_does_not_rearm_already_armed_pump(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        service, _ = _make_service(tmp_path, machine=machine, ops=ops)
        machine.set_pair_success_callback(service._on_pair_success)

        service._last_transport_active = True
        service.pump.set_active_source("bluealsa:DEV=already,PROFILE=a2dp")

        machine.start_pairing(MAC_A)
        assert service.pump.active_source == "bluealsa:DEV=already,PROFILE=a2dp"

    def test_pair_success_hook_leaves_pump_untouched_without_prior_transport(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        service, _ = _make_service(tmp_path, machine=machine, ops=ops)
        machine.set_pair_success_callback(service._on_pair_success)

        machine.start_pairing(MAC_A)
        assert service.pump.active_source is None


class TestStartupSyncSelfHeal:
    def test_startup_sync_arms_pump_and_marks_link_connected(self, tmp_path):
        """Daemon-restart-with-existing-transport: BlueZ only signals on
        change, so a restart while a device is connected and streaming never
        gets a fresh signal for either fact -- startup sync must self-heal
        both from a GetManagedObjects snapshot."""
        machine, ops, _ = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)
        assert machine.get_status()["link"] == svc.LINK_DISCONNECTED  # fresh restart

        service, _ = _make_service(tmp_path, machine=machine, ops=ops)
        bluez = FakeBluezForSync(devices={MAC_A: True}, transport_active=True, transport_rate=44100)
        service._sync_startup_state(bluez)

        assert machine.get_status()["link"] == svc.LINK_CONNECTED
        assert service.pump.active_source == svc.pump_mod.bluealsa_capture_device(MAC_A)
        assert service.pump.active_rate == 44100

    def test_startup_sync_noop_when_nothing_paired_or_active(self, tmp_path):
        service, _ = _make_service(tmp_path)
        bluez = FakeBluezForSync()
        service._sync_startup_state(bluez)
        assert service.pump.active_source is None
        assert service.state_machine.get_status()["link"] == svc.LINK_DISCONNECTED

    def test_startup_sync_tolerates_snapshot_failure(self, tmp_path):
        class BrokenBluez:
            def find_existing_state(self):
                raise RuntimeError("dbus timeout")

        service, _ = _make_service(tmp_path)
        service._sync_startup_state(BrokenBluez())  # must not raise
        assert service.pump.active_source is None


class TestStopDisconnectsOnShutdown:
    """SIGTERM path: stop() must best-effort Disconnect() a connected device
    so a source is not left playing into a dead sink once the service goes
    away — bounded (the underlying D-Bus call carries its own timeout) and
    exception-safe (never blocks or raises out of stop())."""

    def test_stop_disconnects_connected_device(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)
        machine.on_link_state_changed(MAC_A, True)
        service, ops = _make_service(tmp_path, machine=machine, ops=ops)
        ops.calls.clear()

        service.stop()
        assert ("disconnect", MAC_A) in ops.calls

    def test_stop_does_not_disconnect_when_link_not_connected(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)  # paired but link never reported connected
        service, ops = _make_service(tmp_path, machine=machine, ops=ops)
        ops.calls.clear()

        service.stop()
        assert not any(c[0] == "disconnect" for c in ops.calls)

    def test_stop_noop_when_nothing_paired(self, tmp_path):
        service, ops = _make_service(tmp_path)
        ops.calls.clear()
        service.stop()
        assert not any(c[0] == "disconnect" for c in ops.calls)

    def test_stop_swallows_disconnect_exception(self, tmp_path):
        machine, ops, _ = _make_machine(tmp_path)
        machine.start_pairing(MAC_A)
        machine.on_link_state_changed(MAC_A, True)

        class RaisingOps(FakeOps):
            def disconnect(self, mac):
                raise RuntimeError("dbus timeout")

        raising_ops = RaisingOps()
        raising_ops.connected_macs.add(MAC_A)
        service, _ = _make_service(tmp_path, machine=machine, ops=raising_ops)

        service.stop()  # must not raise

    def test_stop_is_safe_before_state_machine_assigned(self, tmp_path):
        service = svc.BluetoothService(state_path=str(tmp_path / "bt.json"))
        service.stop()  # must not raise


class TestGetStatusWrapsPumpState:
    def test_pump_source_active_reflects_pump_streaming(self, tmp_path):
        service, _ = _make_service(tmp_path)
        assert service._get_status()["pump_source_active"] is False
        service.pump.set_active_source("bluealsa:DEV=x,PROFILE=a2dp")
        assert service._get_status()["pump_source_active"] is True

    def test_get_status_additive_over_state_machine_status(self, tmp_path):
        service, _ = _make_service(tmp_path)
        base_keys = set(service.state_machine.get_status().keys())
        wrapped = service._get_status()
        assert set(wrapped.keys()) == base_keys | {"pump_source_active", "adapter_blocked"}


# ---------------------------------------------------------------------------
# Adapter-absent degradation
# ---------------------------------------------------------------------------

class _DummyAgent:
    def __init__(self, bus, path, policy) -> None:
        self.bus = bus
        self.path = path
        self.policy = policy


class _FakeAgentManager:
    def __init__(self) -> None:
        self.registered = False

    def RegisterAgent(self, *args, **kwargs) -> None:
        self.registered = True

    def RequestDefaultAgent(self, *args, **kwargs) -> None:
        pass


class _FakeDbusModule:
    """Just enough of the ``dbus`` module surface for _try_connect_bluez()'s
    agent-wiring step to run without a real dbus/gi installation (absent in
    the WSL test runner, per this module's own docstring)."""

    def __init__(self) -> None:
        self.agent_manager = _FakeAgentManager()

    def SystemBus(self):
        return _FakeBus()

    def Interface(self, obj, iface):
        return self.agent_manager


class _FakeBus:
    def get_object(self, service, path):
        return object()


class TestAdapterAbsentDegradation:
    def test_try_connect_bluez_fails_then_recovers(self, tmp_path, monkeypatch):
        attempts = {"n": 0}

        class FlakyBluezClient:
            def __init__(self, call_timeout=10.0) -> None:
                self.adapter_present = False
                self.adapter_kind = None
                self.subscribed = False

            def connect(self) -> None:
                attempts["n"] += 1
                if attempts["n"] == 1:
                    raise svc.bluez_mod.BluezUnavailable("no adapter found")
                self.adapter_present = True
                self.adapter_kind = "usb"

            def power_on(self) -> None:
                pass

            def ensure_not_discoverable(self) -> None:
                pass

            def subscribe(self, *args, **kwargs) -> None:
                self.subscribed = True

            def find_existing_state(self) -> dict:
                return {"devices": {}, "transport_active": False, "transport_rate": None}

        monkeypatch.setattr(svc.bluez_mod, "BluezClient", FlakyBluezClient)
        monkeypatch.setattr(svc.agent_mod, "build_agent_class", lambda dbus: _DummyAgent)

        service = svc.BluetoothService(state_path=str(tmp_path / "bt.json"))
        service._dbus = _FakeDbusModule()
        service._ops = svc.BluetoothOps()
        service.state_machine = svc.BluetoothStateMachine(
            ops=service._ops, state_path=str(tmp_path / "bt.json"),
        )

        # First attempt: no adapter -> degrades instead of raising.
        assert service._try_connect_bluez() is False
        assert service.state_machine.get_status()["adapter_present"] is False
        assert service._bluez_ready is False

        # Second attempt (the tick-driven retry): adapter now present.
        assert service._try_connect_bluez() is True
        assert service.state_machine.get_status()["adapter_present"] is True
        assert service._bluez_ready is True
        assert service._bluez.subscribed is True

        # Idempotent once attached: a further call is a no-op success.
        attempts_before = attempts["n"]
        assert service._try_connect_bluez() is True
        assert attempts["n"] == attempts_before

    def test_maybe_retry_adapter_bounded_by_interval(self, tmp_path, monkeypatch):
        attempts = {"n": 0}

        class NeverConnectsClient:
            def __init__(self, call_timeout=10.0) -> None:
                self.adapter_present = False

            def connect(self) -> None:
                attempts["n"] += 1
                raise svc.bluez_mod.BluezUnavailable("no adapter found")

        monkeypatch.setattr(svc.bluez_mod, "BluezClient", NeverConnectsClient)

        service = svc.BluetoothService(state_path=str(tmp_path / "bt.json"))
        service._dbus = _FakeDbusModule()
        service._ops = svc.BluetoothOps()
        service.state_machine = svc.BluetoothStateMachine(
            ops=service._ops, state_path=str(tmp_path / "bt.json"),
        )

        service._maybe_retry_adapter()
        assert attempts["n"] == 1
        service._maybe_retry_adapter()  # too soon -> bounded, no new attempt
        assert attempts["n"] == 1

        service._last_adapter_retry -= svc.ADAPTER_RETRY_INTERVAL_SECONDS
        service._maybe_retry_adapter()
        assert attempts["n"] == 2

    def test_start_survives_adapter_power_on_failure_then_recovers(self, tmp_path, monkeypatch):
        """An adapter that exists but cannot be powered (e.g. an rfkill
        soft-block) must not crash the attach attempt: it must be treated
        like the adapter-absent case for retry purposes, with the degraded
        state visible via adapter_blocked, and must clear once a later
        retry succeeds."""
        attempts = {"n": 0}

        class RfkillBlockedThenOkClient:
            def __init__(self, call_timeout=10.0) -> None:
                self.adapter_present = False
                self.adapter_kind = None
                self.subscribed = False

            def connect(self) -> None:
                self.adapter_present = True
                self.adapter_kind = "usb"

            def power_on(self) -> None:
                attempts["n"] += 1
                if attempts["n"] == 1:
                    raise RuntimeError("rfkill: Operation not permitted")

            def ensure_not_discoverable(self) -> None:
                pass

            def subscribe(self, *args, **kwargs) -> None:
                self.subscribed = True

            def find_existing_state(self) -> dict:
                return {"devices": {}, "transport_active": False, "transport_rate": None}

        monkeypatch.setattr(svc.bluez_mod, "BluezClient", RfkillBlockedThenOkClient)
        monkeypatch.setattr(svc.agent_mod, "build_agent_class", lambda dbus: _DummyAgent)

        service = svc.BluetoothService(state_path=str(tmp_path / "bt.json"))
        service._dbus = _FakeDbusModule()
        service._ops = svc.BluetoothOps()
        service.state_machine = svc.BluetoothStateMachine(
            ops=service._ops, state_path=str(tmp_path / "bt.json"),
        )
        service.pump = FakePump()

        # First attach attempt: adapter found but power-on fails -> degrades
        # rather than raising, and adapter_blocked reflects the failure.
        assert service._try_connect_bluez() is False
        assert service._bluez_ready is False
        status = service._get_status()
        assert status["adapter_present"] is False
        assert status["adapter_blocked"] is True

        # Retry succeeds -> flag clears and adapter attaches normally.
        assert service._try_connect_bluez() is True
        assert service._bluez_ready is True
        status = service._get_status()
        assert status["adapter_present"] is True
        assert status["adapter_blocked"] is False

    def test_adapter_blocked_false_by_default(self, tmp_path):
        service, _ = _make_service(tmp_path)
        assert service._get_status()["adapter_blocked"] is False

    def test_adapter_absent_at_startup_leaves_adapter_blocked_false(self, tmp_path, monkeypatch):
        """Distinguish the two degraded states: no adapter at all must not
        report adapter_blocked True (that flag is reserved for "adapter
        present but could not be powered")."""
        class NoAdapterClient:
            def __init__(self, call_timeout=10.0) -> None:
                pass

            def connect(self) -> None:
                raise svc.bluez_mod.BluezUnavailable("no adapter found")

        monkeypatch.setattr(svc.bluez_mod, "BluezClient", NoAdapterClient)

        service = svc.BluetoothService(state_path=str(tmp_path / "bt.json"))
        service._dbus = _FakeDbusModule()
        service._ops = svc.BluetoothOps()
        service.state_machine = svc.BluetoothStateMachine(
            ops=service._ops, state_path=str(tmp_path / "bt.json"),
        )
        service.pump = FakePump()

        assert service._try_connect_bluez() is False
        assert service._get_status()["adapter_blocked"] is False
