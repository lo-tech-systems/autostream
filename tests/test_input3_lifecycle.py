"""tests/test_input3_lifecycle.py

Input 3's lifecycle on the coordinator side, one test per row of its table:

  Absent    Bluetooth not installed: never configured, whatever the flag says.
  Disabled  flag off or services off: no monitor, the daemon's input 3 never
            configured or started.
  Waiting   a reload in progress, waiting for the pump to hold the loopback.
  Running   input 3 started, with its monitor.

The coordinator has no module of its own for this: the enable flag lives in
the settings, the running state in the startup pass's monitor list, and the
gate in the startup pass. These tests drive those places.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_live_config as live_config
import autostream_services as services
import autostream_startup as startup
from autostream_bluetooth_client import BLUETOOTH_CAPTURE_DEVICE
from autostream_config import parse_config
from autostream_settings import SettingsStore

_FIFO = "/tmp/autostream.fifo"


def _cfg(audio3_enabled=True, **sections):
    data = {"audio1": {"enabled": False}, "audio3": {"enabled": audio3_enabled}}
    data.update(sections)
    return parse_config(data, high_perf=False)


def _client() -> MagicMock:
    client = MagicMock()
    for name in ("set_log_level", "configure_input", "start_input", "set_gain", "set_eq",
                 "set_allow_capture", "stop_input"):
        getattr(client, name).return_value = True
    return client


def _started(client) -> list:
    return [c.args[0] for c in client.start_input.call_args_list]


def _configured(client) -> list:
    return [c.args[0] for c in client.configure_input.call_args_list]


def _bt(installed=True, services_on=True, held=True):
    """Patch the Bluetooth facts and the pump's loopback status as seen by
    the startup pass."""
    status = {"ok": True, "loopback_held": held}
    bt_client = MagicMock()
    bt_client.return_value.status.return_value = status
    return (
        patch.object(startup, "bluetooth_installed", return_value=installed),
        patch.object(startup, "bluetooth_services_enabled", return_value=services_on),
        patch.object(startup, "BluetoothClient", bt_client),
    )


def _run_startup(cfg, **bt):
    client = _client()
    a, b, c = _bt(**bt)
    with a, b, c, patch.object(startup, "BLUETOOTH_LOOPBACK_WAIT_SECONDS", 0.05), \
            patch.object(startup, "BLUETOOTH_LOOPBACK_POLL_SECONDS", 0.01):
        monitors = startup.configure_startup_monitors(client, cfg, _FIFO)
    return client, monitors


class TestAbsent:
    @pytest.mark.parametrize("flag", [True, False])
    def test_never_configured_when_not_installed(self, flag):
        client, monitors = _run_startup(_cfg(audio3_enabled=flag), installed=False, services_on=False)
        assert 3 not in _configured(client)
        assert monitors == []

    def test_the_flag_is_left_alone_when_not_installed(self, tmp_path):
        store = _store(tmp_path, {"audio3": {"enabled": True}})
        try:
            with patch.object(startup, "bluetooth_installed", return_value=False), \
                    patch.object(startup, "bluetooth_services_enabled") as services_on:
                startup.reconcile_bluetooth_input_startup(store)
            services_on.assert_not_called()
            assert store.snapshot().audio3_enabled is True
        finally:
            store.close(save=False)


class TestDisabled:
    @pytest.mark.parametrize("flag,services_on", [(False, True), (True, False), (False, False)])
    def test_no_monitor_and_never_configured(self, flag, services_on):
        client, monitors = _run_startup(_cfg(audio3_enabled=flag), services_on=services_on)
        assert 3 not in _configured(client)
        assert 3 not in _started(client)
        assert monitors == []

    def test_every_input_is_stopped_first(self):
        client, _ = _run_startup(_cfg(audio3_enabled=False))
        assert [c.args[0] for c in client.stop_input.call_args_list] == [1, 2, 3]

    def test_enable_switches_the_services_then_reloads(self, tmp_path):
        store = _store(tmp_path, {"audio3": {"enabled": False}})
        state = SimpleNamespace(settings=store)
        try:
            with patch.object(live_config, "bt_services_enable", return_value=(True, "ok")) as en, \
                    patch.object(live_config, "_debounce_coordinator_reload") as reload:
                outcome = store.set("audio3.enabled", True, state=state)
            en.assert_called_once()
            reload.assert_called_once_with(state)
            assert outcome.live is True
        finally:
            store.close(save=False)

    def test_an_enable_that_fails_stays_disabled_with_a_live_error(self, tmp_path):
        store = _store(tmp_path, {"audio3": {"enabled": False}})
        try:
            with patch.object(live_config, "bt_services_enable", return_value=(False, "no")), \
                    patch.object(live_config, "_debounce_coordinator_reload") as reload:
                outcome = store.set("audio3.enabled", True, state=SimpleNamespace(settings=store))
            reload.assert_not_called()
            assert outcome.live is False and outcome.live_error
            assert store.snapshot().audio3_enabled is False
        finally:
            store.close(save=False)


class TestWaiting:
    def test_the_gate_held_starts_input_3_on_the_loopback(self):
        client, monitors = _run_startup(_cfg())
        assert _started(client) == [3]
        client.configure_input.assert_any_call(
            3, BLUETOOTH_CAPTURE_DEVICE,
            pytest.approx(monitors[0].silence_threshold_dbfs),
            monitors[0].silence_seconds,
            monitors[0].track_change_silence_seconds,
            monitors[0].minimum_playback_seconds,
            input_type="line", dynamic_rate_matching=True, start_after_ms=60,
        )
        assert [(m.input_index, m.input_device) for m in monitors] == [(3, BLUETOOTH_CAPTURE_DEVICE)]

    def test_the_gate_is_waited_on_before_the_start(self):
        order = []
        client = _client()
        client.start_input.side_effect = lambda i: order.append(("start", i)) or True
        bt_client = MagicMock()
        bt_client.return_value.status.side_effect = \
            lambda: order.append(("status",)) or {"loopback_held": True}
        with patch.object(startup, "bluetooth_installed", return_value=True), \
                patch.object(startup, "bluetooth_services_enabled", return_value=True), \
                patch.object(startup, "BluetoothClient", bt_client):
            startup.configure_startup_monitors(client, _cfg(), _FIFO)
        assert order == [("status",), ("start", 3)]

    def test_a_gate_timeout_skips_input_3_for_this_reload_only(self):
        cfg = _cfg(audio1={"enabled": True, "capture_device": "hw:0,0"})
        client, monitors = _run_startup(cfg, held=False)
        assert 3 not in _started(client)
        assert [m.input_index for m in monitors] == [1]

    def test_a_status_without_the_field_does_not_wait(self):
        client = _client()
        bt_client = MagicMock()
        bt_client.return_value.status.return_value = {"ok": True}
        with patch.object(startup, "bluetooth_installed", return_value=True), \
                patch.object(startup, "bluetooth_services_enabled", return_value=True), \
                patch.object(startup, "BluetoothClient", bt_client):
            monitors = startup.configure_startup_monitors(client, _cfg(), _FIFO)
        assert [m.input_index for m in monitors] == [3]

    def test_a_failure_on_input_3_skips_it_and_keeps_the_others(self):
        cfg = _cfg(audio1={"enabled": True, "capture_device": "hw:0,0"})
        client = _client()
        client.start_input.side_effect = lambda i: i != 3
        a, b, c = _bt()
        with a, b, c:
            monitors = startup.configure_startup_monitors(client, cfg, _FIFO)
        assert monitors is not None
        assert [m.input_index for m in monitors] == [1]


class TestRunning:
    def test_three_inputs_start_and_none_captures_until_chosen(self):
        cfg = _cfg(audio1={"enabled": True, "capture_device": "hw:0,0"},
                   audio2={"enabled": True, "capture_device": "hw:1,0"})
        client, monitors = _run_startup(cfg)
        assert _started(client) == [1, 2, 3]
        assert [m.input_index for m in monitors] == [1, 2, 3]
        assert all(m.allow_capture is False for m in monitors)

    def test_disable_switches_the_services_off_then_reloads(self, tmp_path):
        store = _store(tmp_path, {"audio3": {"enabled": True}})
        state = SimpleNamespace(settings=store)
        try:
            with patch.object(live_config, "bt_services_disable", return_value=(True, "ok")) as dis, \
                    patch.object(live_config, "_debounce_coordinator_reload") as reload:
                store.set("audio3.enabled", False, state=state)
            dis.assert_called_once()
            reload.assert_called_once_with(state)
        finally:
            store.close(save=False)

    @pytest.mark.parametrize("flag,reloads", [(True, 1), (False, 0)])
    def test_a_rate_change_reloads_only_while_input_3_is_enabled(self, tmp_path, flag, reloads):
        store = _store(tmp_path, {"audio3": {"enabled": flag}})
        try:
            with patch.object(services, "submit") as submit:
                services._rate_follow_check(store, {"sample_rate": 48000}, 44100)
            assert submit.call_count == reloads
        finally:
            store.close(save=False)

    @pytest.mark.parametrize("flag,reloads", [(True, 1), (False, 0)])
    def test_a_lockout_heal_reloads_only_while_input_3_is_enabled(self, tmp_path, flag, reloads):
        store = _store(tmp_path, {"audio3": {"enabled": flag}})
        try:
            with patch.object(services, "submit") as submit:
                services._lockout_heal_check(store, {"loopback_locked_out": True}, 1, None)
            assert submit.call_count == reloads
        finally:
            store.close(save=False)

    def test_a_monitor_reconnect_resyncs_input_3_with_the_others(self):
        client = _client()
        client.set_fifo.return_value = True
        client.get_status.return_value = None
        monitors = [_monitor(1), _monitor(3)]
        with patch.object(startup, "reconcile_fifo_with_backend") as fifo, \
                patch.object(startup.monitor_control, "_apply_output_eq_config", return_value=True), \
                patch.object(startup, "_push_repeat_policy"), \
                patch.object(startup.log_setup, "get_live_platform_log_level", return_value="info"):
            fifo.return_value = SimpleNamespace(ok=True, message="")
            ok = _resync(client, monitors)
        assert ok is True
        assert _configured(client) == [1, 3]
        assert _started(client) == [1, 3]


class TestStartReconcile:
    @pytest.mark.parametrize("stored,services_on,expected", [
        (True, False, False),
        (False, True, True),
        (None, True, True),
        (None, False, False),
    ])
    def test_systemd_wins(self, tmp_path, stored, services_on, expected):
        section = {} if stored is None else {"enabled": stored}
        store = _store(tmp_path, {"audio3": section})
        try:
            with patch.object(startup, "bluetooth_installed", return_value=True), \
                    patch.object(startup, "bluetooth_services_enabled", return_value=services_on), \
                    patch.object(store, "save_now", return_value=True):
                startup.reconcile_bluetooth_input_startup(store)
            assert store.raw_snapshot()["audio3"]["enabled"] is expected
        finally:
            store.close(save=False)

    @pytest.mark.parametrize("flag", [True, False])
    def test_an_agreeing_flag_is_not_written(self, tmp_path, flag):
        store = _store(tmp_path, {"audio3": {"enabled": flag}})
        try:
            before = store.generation
            with patch.object(startup, "bluetooth_installed", return_value=True), \
                    patch.object(startup, "bluetooth_services_enabled", return_value=flag):
                startup.reconcile_bluetooth_input_startup(store)
            assert store.generation == before
        finally:
            store.close(save=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _store(tmp_path, data: dict) -> SettingsStore:
    import json
    path = tmp_path / "autostream.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return SettingsStore(str(path), _save_interval_seconds=9999)


def _monitor(index: int):
    return SimpleNamespace(
        input_index=index, input_device=f"hw:{index},0", silence_threshold_dbfs=-60.0,
        silence_seconds=30, track_change_silence_seconds=1.25, minimum_playback_seconds=30,
        input_type="line", dynamic_rate_matching=True, start_after_ms=60, gain_db=0.0,
        eq_40hz_db=0.0, eq_100hz_db=0.0, eq_8khz_db=0.0, _allow_capture=False,
        _allow_capture_sent=None,
    )


def _resync(client, monitors) -> bool:
    import inspect
    params = inspect.signature(startup.resync_monitor_daemon).parameters
    values = {
        "client": client, "monitors": monitors, "fifo_path": _FIFO,
        "owntone_base_url": "http://127.0.0.1:3689", "output_eq": None,
        "repeat_enabled": False, "repeat_codec": "auto", "repeat_target_minutes": 33,
        "audio_path": None,
    }
    return startup.resync_monitor_daemon(**{k: values[k] for k in params if k in values})
