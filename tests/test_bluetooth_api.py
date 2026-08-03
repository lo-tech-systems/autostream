"""Tests for the Bluetooth web-route/JSON-handler surface:

  - autostream_webui_api.send_bluetooth_* handlers (status/scan/pair/forget/
    services/onboard/buffer)
  - route registration + auth-gate + commissioning-allowlist exclusion in
    autostream_webui.py
  - the cross-input capture_device exclusivity settings guard (generalised
    from the original Bluetooth-only guard)
  - the About page's conditional Bluetooth service row
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_bluetooth_client import BLUETOOTH_CAPTURE_DEVICE, BLUETOOTH_PLAYBACK_DEVICE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_handler() -> MagicMock:
    h = MagicMock()
    h.wfile = io.BytesIO()
    return h


def _response(handler: MagicMock) -> tuple[int, dict]:
    code = handler.send_response.call_args[0][0]
    body = json.loads(handler.wfile.getvalue())
    return code, body


def _write_config(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def _minimal_cfg(tmp_path: Path, **audio_overrides) -> Path:
    cfg = tmp_path / "autostream.json"
    data = {
        "general": {"log_level": "info"},
        "owntone": {"base_url": "http://localhost:3689"},
        "webui": {
            "dark_mode": False, "show_master_volume": True, "show_input_detail": False,
            "show_hostname_on_home": False, "control_other_appliances": True,
            "output_usage_poll_interval_seconds": 3,
        },
        "updates": {"auto_update": False, "update_channel": "stable"},
    }
    data.update(audio_overrides)
    _write_config(cfg, data)
    return cfg


def _make_state(tmp_path: Path, **audio_overrides):
    from autostream_settings import SettingsStore
    from autostream_webui_state import WebUIState
    cfg = _minimal_cfg(tmp_path, **audio_overrides)
    store = SettingsStore(str(cfg), _save_interval_seconds=9999)
    state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)
    return state, store


# ---------------------------------------------------------------------------
# send_bluetooth_status_json
# ---------------------------------------------------------------------------

class TestBluetoothStatusJson:
    def test_not_installed_returns_flags_false_daemon_none(self, tmp_path):
        from autostream_webui_api import send_bluetooth_status_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            with patch("autostream_webui_api.bluetooth_installed", return_value=False):
                send_bluetooth_status_json(handler, state)
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body == {
            "ok": True, "installed": False, "services_enabled": False,
            "onboard_enabled": False, "daemon": None,
            "ui": {
                "card_summary": "Disabled",
                "paired_text": "No device paired",
                "bt_input_text": "Not Connected",
            },
        }

    def test_installed_live_status_returned(self, tmp_path):
        from autostream_webui_api import send_bluetooth_status_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        live = {"ok": True, "adapter_present": True, "paired": None, "link": "disconnected",
                "streaming": False, "scanning": False, "buffer_ms": 200, "adapter_kind": "usb"}
        try:
            with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
                 patch("autostream_webui_api.bluetooth_services_enabled", return_value=True), \
                 patch("autostream_webui_api.bluetooth_onboard_enabled", return_value=False), \
                 patch("autostream_webui_api.BluetoothClient") as m_cls:
                m_cls.return_value.status.return_value = live
                send_bluetooth_status_json(handler, state)
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is True
        assert body["installed"] is True
        assert body["services_enabled"] is True
        assert body["onboard_enabled"] is False
        assert body["daemon"] == live
        assert body["ui"] == {
            "card_summary": "Enabled · Not paired",
            "paired_text": "No device paired",
            "bt_input_text": "Not Connected",
        }

    def test_ui_enabled_not_paired(self, tmp_path):
        from autostream_webui_api import send_bluetooth_status_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        live = {"ok": True, "adapter_present": True, "paired": None, "link": "disconnected",
                "streaming": False, "scanning": False}
        try:
            with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
                 patch("autostream_webui_api.bluetooth_services_enabled", return_value=True), \
                 patch("autostream_webui_api.bluetooth_onboard_enabled", return_value=False), \
                 patch("autostream_webui_api.BluetoothClient") as m_cls:
                m_cls.return_value.status.return_value = live
                send_bluetooth_status_json(handler, state)
        finally:
            store.close(save=False)
        _, body = _response(handler)
        assert body["ui"] == {
            "card_summary": "Enabled · Not paired",
            "paired_text": "No device paired",
            "bt_input_text": "Not Connected",
        }

    def test_ui_paired_and_connected(self, tmp_path):
        from autostream_webui_api import send_bluetooth_status_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        live = {"ok": True, "adapter_present": True,
                "paired": {"mac": "AA:BB:CC:DD:EE:FF", "name": "BT-Turntable"},
                "link": "connected", "streaming": True, "scanning": False}
        try:
            with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
                 patch("autostream_webui_api.bluetooth_services_enabled", return_value=True), \
                 patch("autostream_webui_api.bluetooth_onboard_enabled", return_value=False), \
                 patch("autostream_webui_api.BluetoothClient") as m_cls:
                m_cls.return_value.status.return_value = live
                send_bluetooth_status_json(handler, state)
        finally:
            store.close(save=False)
        _, body = _response(handler)
        assert body["ui"] == {
            "card_summary": "Enabled · BT-Turntable connected",
            "paired_text": "BT-Turntable · Connected",
            "bt_input_text": "BT-Turntable",
        }

    def test_ui_paired_but_disconnected(self, tmp_path):
        """The fifth state: paired device present but the link is down --
        must not be reported as 'connected'."""
        from autostream_webui_api import send_bluetooth_status_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        live = {"ok": True, "adapter_present": True,
                "paired": {"mac": "AA:BB:CC:DD:EE:FF", "name": "BT-Turntable"},
                "link": "disconnected", "streaming": False, "scanning": False}
        try:
            with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
                 patch("autostream_webui_api.bluetooth_services_enabled", return_value=True), \
                 patch("autostream_webui_api.bluetooth_onboard_enabled", return_value=False), \
                 patch("autostream_webui_api.BluetoothClient") as m_cls:
                m_cls.return_value.status.return_value = live
                send_bluetooth_status_json(handler, state)
        finally:
            store.close(save=False)
        _, body = _response(handler)
        assert body["ui"] == {
            "card_summary": "Enabled · BT-Turntable (not connected)",
            "paired_text": "BT-Turntable · Not Connected",
            "bt_input_text": "Not Connected",
        }

    def test_installed_live_fails_falls_back_to_cache(self, tmp_path):
        from autostream_webui_api import send_bluetooth_status_json
        state, store = _make_state(tmp_path)
        cached = {"ok": True, "adapter_present": True, "paired": None, "link": "disconnected",
                  "streaming": False, "scanning": False}
        state.set_bluetooth_status(cached)
        handler = _make_handler()
        try:
            with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
                 patch("autostream_webui_api.bluetooth_services_enabled", return_value=True), \
                 patch("autostream_webui_api.bluetooth_onboard_enabled", return_value=False), \
                 patch("autostream_webui_api.BluetoothClient") as m_cls:
                m_cls.return_value.status.return_value = None
                send_bluetooth_status_json(handler, state)
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["daemon"] == cached

    def test_installed_no_live_no_cache_daemon_is_none_but_ok_true(self, tmp_path):
        """The card must always get a 200 ok:true so it can render the
        'no adapter' / disabled state rather than treating a down daemon as
        a request failure."""
        from autostream_webui_api import send_bluetooth_status_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
                 patch("autostream_webui_api.bluetooth_services_enabled", return_value=False), \
                 patch("autostream_webui_api.bluetooth_onboard_enabled", return_value=False), \
                 patch("autostream_webui_api.BluetoothClient") as m_cls:
                m_cls.return_value.status.return_value = None
                send_bluetooth_status_json(handler, state)
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is True
        assert body["daemon"] is None
        assert body["services_enabled"] is False


# ---------------------------------------------------------------------------
# POST services / onboard / buffer
# ---------------------------------------------------------------------------

class TestBluetoothServicesPost:
    def test_enable_action(self):
        from autostream_webui_api import send_bluetooth_services_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.bt_services_enable", return_value=(True, "enabled")) as m_en, \
             patch("autostream_webui_api.bt_services_disable") as m_dis:
            send_bluetooth_services_post_json(handler, {"action": "enable"})
        code, body = _response(handler)
        assert code == 200
        assert body == {"ok": True, "message": "enabled"}
        m_en.assert_called_once()
        m_dis.assert_not_called()

    def test_disable_action(self):
        from autostream_webui_api import send_bluetooth_services_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.bt_services_disable", return_value=(True, "disabled")):
            send_bluetooth_services_post_json(handler, {"action": "disable"})
        code, body = _response(handler)
        assert code == 200
        assert body == {"ok": True, "message": "disabled"}

    def test_failure_reported_but_still_200(self):
        from autostream_webui_api import send_bluetooth_services_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.bt_services_enable", return_value=(False, "sudo failed")):
            send_bluetooth_services_post_json(handler, {"action": "enable"})
        code, body = _response(handler)
        assert code == 200
        assert body == {"ok": False, "message": "sudo failed"}

    @pytest.mark.parametrize("action", ["start", "stop", "", None, 1, "enable_all"])
    def test_invalid_action_rejected(self, action):
        from autostream_webui_api import send_bluetooth_services_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True):
            send_bluetooth_services_post_json(handler, {"action": action})
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False

    def test_extra_keys_rejected(self):
        from autostream_webui_api import send_bluetooth_services_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True):
            send_bluetooth_services_post_json(handler, {"action": "enable", "extra": 1})
        code, body = _response(handler)
        assert code == 400

    def test_not_installed_is_unavailable(self):
        from autostream_webui_api import send_bluetooth_services_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=False):
            send_bluetooth_services_post_json(handler, {"action": "enable"})
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"


class TestBluetoothOnboardPost:
    def test_enable_reports_reboot_required(self):
        from autostream_webui_api import send_bluetooth_onboard_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.bt_onboard_set", return_value=(True, "onboard on")) as m_set:
            send_bluetooth_onboard_post_json(handler, {"enabled": True})
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is True
        assert body["reboot_required"] is True
        m_set.assert_called_once_with(True)

    def test_disable_reports_reboot_required(self):
        from autostream_webui_api import send_bluetooth_onboard_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.bt_onboard_set", return_value=(True, "onboard off")):
            send_bluetooth_onboard_post_json(handler, {"enabled": False})
        _, body = _response(handler)
        assert body["reboot_required"] is True

    def test_failure_no_reboot_required_key(self):
        from autostream_webui_api import send_bluetooth_onboard_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.bt_onboard_set", return_value=(False, "sudo failed")):
            send_bluetooth_onboard_post_json(handler, {"enabled": True})
        _, body = _response(handler)
        assert body["ok"] is False
        assert "reboot_required" not in body

    @pytest.mark.parametrize("bad", ["true", 1, None, "yes"])
    def test_non_bool_enabled_rejected(self, bad):
        from autostream_webui_api import send_bluetooth_onboard_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True):
            send_bluetooth_onboard_post_json(handler, {"enabled": bad})
        code, _ = _response(handler)
        assert code == 400

    def test_extra_keys_rejected(self):
        from autostream_webui_api import send_bluetooth_onboard_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True):
            send_bluetooth_onboard_post_json(handler, {"enabled": True, "extra": 1})
        code, _ = _response(handler)
        assert code == 400

    def test_not_installed_is_unavailable(self):
        from autostream_webui_api import send_bluetooth_onboard_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=False):
            send_bluetooth_onboard_post_json(handler, {"enabled": True})
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"


class TestBluetoothBufferPost:
    def test_valid_value_accepted(self):
        from autostream_webui_api import send_bluetooth_buffer_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.BluetoothClient") as m_cls:
            m_cls.return_value.configure.return_value = {"ok": True}
            send_bluetooth_buffer_post_json(handler, {"buffer_ms": 250})
        code, body = _response(handler)
        assert code == 200
        assert body == {"ok": True, "buffer_ms": 250}
        m_cls.return_value.configure.assert_called_once_with(250)

    @pytest.mark.parametrize("bad", [99, 501, 0, -1, "200", 200.5, True, None])
    def test_out_of_range_or_wrong_type_rejected(self, bad):
        from autostream_webui_api import send_bluetooth_buffer_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.BluetoothClient") as m_cls:
            send_bluetooth_buffer_post_json(handler, {"buffer_ms": bad})
        code, body = _response(handler)
        assert code == 400
        m_cls.return_value.configure.assert_not_called()

    def test_boundary_values_accepted(self):
        from autostream_webui_api import send_bluetooth_buffer_post_json
        for val in (100, 500):
            handler = _make_handler()
            with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
                 patch("autostream_webui_api.BluetoothClient") as m_cls:
                m_cls.return_value.configure.return_value = {"ok": True}
                send_bluetooth_buffer_post_json(handler, {"buffer_ms": val})
            code, _ = _response(handler)
            assert code == 200

    def test_daemon_rejects_as_invalid(self):
        from autostream_webui_api import send_bluetooth_buffer_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.BluetoothClient") as m_cls:
            m_cls.return_value.configure.return_value = {"ok": False, "error": "invalid_buffer_ms"}
            send_bluetooth_buffer_post_json(handler, {"buffer_ms": 200})
        code, body = _response(handler)
        assert code == 400
        assert body["error"] == "invalid_buffer_ms"

    def test_daemon_down_is_503(self):
        from autostream_webui_api import send_bluetooth_buffer_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.BluetoothClient") as m_cls:
            m_cls.return_value.configure.return_value = None
            send_bluetooth_buffer_post_json(handler, {"buffer_ms": 200})
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"

    def test_not_installed_is_unavailable(self):
        from autostream_webui_api import send_bluetooth_buffer_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=False):
            send_bluetooth_buffer_post_json(handler, {"buffer_ms": 200})
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"

    def test_extra_keys_rejected(self):
        from autostream_webui_api import send_bluetooth_buffer_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True):
            send_bluetooth_buffer_post_json(handler, {"buffer_ms": 200, "extra": 1})
        code, _ = _response(handler)
        assert code == 400


# ---------------------------------------------------------------------------
# WebUIState.set/get_bluetooth_status — deep-copy isolation
# ---------------------------------------------------------------------------

class TestBluetoothStatusDeepCopy:
    """set/get_bluetooth_status must deep-copy: the status nests
    paired{mac, name}, and a shallow dict() copy leaves that nested dict
    shared with the caller, letting a caller's later mutation corrupt the
    cache (or vice versa)."""

    def test_mutating_input_after_set_does_not_affect_cache(self, tmp_path):
        from autostream_webui_state import WebUIState
        state = WebUIState(str(tmp_path / "cfg.json"), str(tmp_path / "state.json"))
        status = {"ok": True, "paired": {"mac": "AA:BB:CC:DD:EE:FF", "name": "Original"}, "link": "connected"}
        state.set_bluetooth_status(status)
        status["paired"]["name"] = "Mutated"
        status["link"] = "disconnected"
        cached = state.get_bluetooth_status()
        assert cached["paired"]["name"] == "Original"
        assert cached["link"] == "connected"

    def test_mutating_returned_value_does_not_affect_cache(self, tmp_path):
        from autostream_webui_state import WebUIState
        state = WebUIState(str(tmp_path / "cfg.json"), str(tmp_path / "state.json"))
        status = {"ok": True, "paired": {"mac": "AA:BB:CC:DD:EE:FF", "name": "Original"}, "link": "connected"}
        state.set_bluetooth_status(status)
        got = state.get_bluetooth_status()
        got["paired"]["name"] = "Mutated"
        got["link"] = "disconnected"
        cached_again = state.get_bluetooth_status()
        assert cached_again["paired"]["name"] == "Original"
        assert cached_again["link"] == "connected"

    def test_none_status_clears_cache(self, tmp_path):
        from autostream_webui_state import WebUIState
        state = WebUIState(str(tmp_path / "cfg.json"), str(tmp_path / "state.json"))
        state.set_bluetooth_status({"ok": True, "paired": None})
        state.set_bluetooth_status(None)
        assert state.get_bluetooth_status() is None


# ---------------------------------------------------------------------------
# GET-style handlers: scan_results / pair_status
# ---------------------------------------------------------------------------

class TestBluetoothScanResultsAndPairStatus:
    def test_scan_results_disabled_is_unavailable(self):
        from autostream_webui_api import send_bluetooth_scan_results_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=False):
            send_bluetooth_scan_results_json(handler)
        _, body = _response(handler)
        assert body["ok"] is False
        assert body["error"] == "bluetooth_unavailable"

    def test_scan_results_success(self):
        from autostream_webui_api import send_bluetooth_scan_results_json
        handler = _make_handler()
        payload = {"ok": True, "devices": [{"mac": "AA:BB:CC:DD:EE:FF", "name": "TT", "rssi": -55, "paired": False}]}
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.BluetoothClient") as m_cls:
            m_cls.return_value.scan_results.return_value = payload
            send_bluetooth_scan_results_json(handler)
        code, body = _response(handler)
        assert code == 200
        assert body == payload

    def test_scan_results_daemon_unreachable(self):
        from autostream_webui_api import send_bluetooth_scan_results_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.BluetoothClient") as m_cls:
            m_cls.return_value.scan_results.return_value = None
            send_bluetooth_scan_results_json(handler)
        _, body = _response(handler)
        assert body["ok"] is False
        assert body["error"] == "bluetooth_unavailable"

    def test_pair_status_success(self):
        """A non-"done" state (here "connecting") passes the daemon payload
        through untouched -- no auto-configure attempt, no extra field."""
        from autostream_webui_api import send_bluetooth_pair_status_json
        handler = _make_handler()
        payload = {"ok": True, "state": "connecting"}
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.BluetoothClient") as m_cls:
            m_cls.return_value.pair_status.return_value = payload
            send_bluetooth_pair_status_json(handler)
        code, body = _response(handler)
        assert code == 200
        assert body == payload

    def test_pair_status_disabled_is_unavailable(self):
        from autostream_webui_api import send_bluetooth_pair_status_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=False):
            send_bluetooth_pair_status_json(handler)
        _, body = _response(handler)
        assert body["ok"] is False
        assert body["error"] == "bluetooth_unavailable"


# ---------------------------------------------------------------------------
# POST scan — closed action set
# ---------------------------------------------------------------------------

class TestBluetoothScanPost:
    def test_start_action(self):
        from autostream_webui_api import send_bluetooth_scan_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.BluetoothClient") as m_cls:
            m_cls.return_value.scan_start.return_value = {"ok": True}
            send_bluetooth_scan_post_json(handler, {"action": "start"})
        code, body = _response(handler)
        assert code == 200
        assert body == {"ok": True, "action": "start"}
        m_cls.return_value.scan_start.assert_called_once()
        m_cls.return_value.scan_stop.assert_not_called()

    def test_stop_action(self):
        from autostream_webui_api import send_bluetooth_scan_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.BluetoothClient") as m_cls:
            m_cls.return_value.scan_stop.return_value = {"ok": True}
            send_bluetooth_scan_post_json(handler, {"action": "stop"})
        code, body = _response(handler)
        assert code == 200
        assert body["action"] == "stop"

    @pytest.mark.parametrize("action", ["pause", "PAIR", "", None, 1, "start_and_stop"])
    def test_invalid_action_rejected(self, action):
        from autostream_webui_api import send_bluetooth_scan_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True):
            send_bluetooth_scan_post_json(handler, {"action": action})
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False

    def test_extra_keys_rejected(self):
        from autostream_webui_api import send_bluetooth_scan_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True):
            send_bluetooth_scan_post_json(handler, {"action": "start", "extra": "nope"})
        code, body = _response(handler)
        assert code == 400

    def test_non_dict_body_rejected(self):
        from autostream_webui_api import send_bluetooth_scan_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True):
            send_bluetooth_scan_post_json(handler, "not a dict")
        code, body = _response(handler)
        assert code == 400

    def test_disabled_is_unavailable_before_action_check(self):
        from autostream_webui_api import send_bluetooth_scan_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=False):
            send_bluetooth_scan_post_json(handler, {"action": "start"})
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"

    def test_scan_in_progress_is_409(self):
        """Daemon replies {"ok": false, "error": "scan_in_progress"} when a
        scan is already active -- surfaced as a 409."""
        from autostream_webui_api import send_bluetooth_scan_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.BluetoothClient") as m_cls:
            m_cls.return_value.scan_start.return_value = {"ok": False, "error": "scan_in_progress"}
            send_bluetooth_scan_post_json(handler, {"action": "start"})
        code, body = _response(handler)
        assert code == 409
        assert body["ok"] is False
        assert body["error"] == "scan_in_progress"

    def test_other_non_ok_error_stays_503(self):
        """503 is tunneled through the NGINX-intercepted-status contract
        (transport 200 + error_status), same as the existing daemon-failure
        tests."""
        from autostream_webui_api import send_bluetooth_scan_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.BluetoothClient") as m_cls:
            m_cls.return_value.scan_start.return_value = {"ok": False, "error": "adapter_missing"}
            send_bluetooth_scan_post_json(handler, {"action": "start"})
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"
        assert body.get("error_status") == 503


# ---------------------------------------------------------------------------
# POST pair — server-side MAC validation
# ---------------------------------------------------------------------------

class TestBluetoothPairPost:
    def test_valid_mac_accepted(self):
        from autostream_webui_api import send_bluetooth_pair_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.BluetoothClient") as m_cls:
            m_cls.return_value.pair.return_value = {"ok": True}
            send_bluetooth_pair_post_json(handler, {"address": "AA:BB:CC:DD:EE:FF"})
        code, body = _response(handler)
        assert code == 200
        assert body == {"ok": True}
        m_cls.return_value.pair.assert_called_once_with("AA:BB:CC:DD:EE:FF")

    @pytest.mark.parametrize("bad_address", [
        "not-a-mac", "AA:BB:CC:DD:EE", "AA:BB:CC:DD:EE:FF:00",
        "GG:BB:CC:DD:EE:FF", "AA-BB-CC-DD-EE-FF", "", 123, None,
        "AA:BB:CC:DD:EE:FF; rm -rf /",
    ])
    def test_invalid_mac_rejected(self, bad_address):
        from autostream_webui_api import send_bluetooth_pair_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.BluetoothClient") as m_cls:
            send_bluetooth_pair_post_json(handler, {"address": bad_address})
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False
        m_cls.return_value.pair.assert_not_called()

    def test_extra_keys_rejected(self):
        from autostream_webui_api import send_bluetooth_pair_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True):
            send_bluetooth_pair_post_json(handler, {"address": "AA:BB:CC:DD:EE:FF", "extra": 1})
        code, body = _response(handler)
        assert code == 400

    def test_daemon_failure_is_unavailable(self):
        from autostream_webui_api import send_bluetooth_pair_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.BluetoothClient") as m_cls:
            m_cls.return_value.pair.return_value = None
            send_bluetooth_pair_post_json(handler, {"address": "AA:BB:CC:DD:EE:FF"})
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"

    def test_disabled_is_unavailable(self):
        from autostream_webui_api import send_bluetooth_pair_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=False):
            send_bluetooth_pair_post_json(handler, {"address": "AA:BB:CC:DD:EE:FF"})
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"

    def test_pair_in_progress_is_409(self):
        """Daemon replies {"ok": false, "error": "pair_in_progress"} when a
        pairing attempt is already active -- surfaced as a 409, mirroring
        send_network_setup_json's watcher-busy 409."""
        from autostream_webui_api import send_bluetooth_pair_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.BluetoothClient") as m_cls:
            m_cls.return_value.pair.return_value = {"ok": False, "error": "pair_in_progress"}
            send_bluetooth_pair_post_json(handler, {"address": "AA:BB:CC:DD:EE:FF"})
        code, body = _response(handler)
        assert code == 409
        assert body["ok"] is False
        assert body["error"] == "pair_in_progress"

    def test_other_non_ok_error_stays_503(self):
        """Any non-ok reply other than the pair_in_progress contract stays
        the generic 503 bluetooth_unavailable -- e.g. a daemon-side failure
        reason we don't have a dedicated mapping for.  503 is tunneled
        through the NGINX-intercepted-status contract (transport 200 +
        error_status), same as the existing daemon-failure tests."""
        from autostream_webui_api import send_bluetooth_pair_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.BluetoothClient") as m_cls:
            m_cls.return_value.pair.return_value = {"ok": False, "error": "adapter_missing"}
            send_bluetooth_pair_post_json(handler, {"address": "AA:BB:CC:DD:EE:FF"})
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"
        assert body.get("error_status") == 503


# ---------------------------------------------------------------------------
# GET pair_status — post-pair input auto-enable rules
# ---------------------------------------------------------------------------

class TestBluetoothPairStatusAutoConfigure:
    """The daemon's ``pair`` reply only means pairing *started*; real
    success is only known once polling ``pair_status`` observes
    ``state == "done"``. That's the correct hook point for the input
    auto-enable rules (see autostream_webui_api._bt_pair_auto_configure),
    not the POST handler -- so this class exercises
    ``send_bluetooth_pair_status_json`` with a stubbed daemon reply rather
    than the pair POST.
    """

    def _poll(self, handler, state, daemon_state="done"):
        from autostream_webui_api import send_bluetooth_pair_status_json
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.BluetoothClient") as m_cls:
            m_cls.return_value.pair_status.return_value = {"ok": True, "state": daemon_state}
            send_bluetooth_pair_status_json(handler, state=state)

    def test_input1_disabled_maps_and_enables_input1(self, tmp_path):
        """Rule a: input 1 disabled -> loopback assigned to input 1 and enabled."""
        state, store = _make_state(tmp_path, audio1={"enabled": False})
        handler = _make_handler()
        try:
            self._poll(handler, state)
            snap = store.snapshot()
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is True
        assert body["state"] == "done"
        assert body["input_auto_configure"] == {"action": "enabled", "input": "audio1"}
        assert snap.audio1.capture_device == BLUETOOTH_CAPTURE_DEVICE
        assert snap.audio1_enabled is True

    def test_input1_disabled_overwrites_stale_device_value(self, tmp_path):
        """Rule a explicitly overwrites any stale device value on record."""
        state, store = _make_state(
            tmp_path, audio1={"enabled": False, "capture_device": "hw:1,0"},
        )
        handler = _make_handler()
        try:
            self._poll(handler, state)
            snap = store.snapshot()
        finally:
            store.close(save=False)
        assert snap.audio1.capture_device == BLUETOOTH_CAPTURE_DEVICE
        assert snap.audio1_enabled is True

    def test_input1_on_real_device_input2_disabled_maps_input2(self, tmp_path):
        """Rule b: input 1 already on a real device, input 2 disabled ->
        loopback assigned to input 2 and enabled; input 1 left untouched."""
        state, store = _make_state(tmp_path, audio1={"capture_device": "hw:1,0"})
        handler = _make_handler()
        try:
            self._poll(handler, state)
            snap = store.snapshot()
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["input_auto_configure"] == {"action": "enabled", "input": "audio2"}
        assert snap.audio2.capture_device == BLUETOOTH_CAPTURE_DEVICE
        assert snap.audio2_enabled is True
        assert snap.audio1.capture_device == "hw:1,0"

    def test_input1_on_real_device_input2_enabled_but_no_device_maps_input2(self, tmp_path):
        """Rule b's 'unmapped' also covers input 2 enabled with no device
        recorded, not only input 2 disabled."""
        state, store = _make_state(
            tmp_path, audio1={"capture_device": "hw:1,0"}, audio2={"enabled": True},
        )
        handler = _make_handler()
        try:
            self._poll(handler, state)
            snap = store.snapshot()
        finally:
            store.close(save=False)
        assert snap.audio2.capture_device == BLUETOOTH_CAPTURE_DEVICE
        assert snap.audio2_enabled is True

    def test_already_on_loopback_is_a_no_op_with_no_notice(self, tmp_path):
        """Rule c: input 1 already on the loopback -> nothing changes, and
        no notice is surfaced."""
        state, store = _make_state(
            tmp_path, audio1={"capture_device": BLUETOOTH_CAPTURE_DEVICE},
        )
        handler = _make_handler()
        try:
            self._poll(handler, state)
            snap = store.snapshot()
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["input_auto_configure"] == {"action": "already_configured"}
        assert "notice" not in body["input_auto_configure"]
        assert snap.audio1.capture_device == BLUETOOTH_CAPTURE_DEVICE
        assert snap.audio2.capture_device == ""

    def test_both_inputs_on_real_devices_leaves_config_alone_with_notice(self, tmp_path):
        """Rule d: both inputs already occupied by real devices -> nothing
        changes, but a notice is surfaced for the caller to display."""
        state, store = _make_state(
            tmp_path,
            audio1={"capture_device": "hw:1,0"},
            audio2={"capture_device": "hw:2,0", "enabled": True},
        )
        handler = _make_handler()
        try:
            self._poll(handler, state)
            snap = store.snapshot()
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        auto = body["input_auto_configure"]
        assert auto["action"] == "notice"
        assert auto["notice"]
        assert snap.audio1.capture_device == "hw:1,0"
        assert snap.audio2.capture_device == "hw:2,0"

    def test_never_produces_both_inputs_on_loopback(self, tmp_path):
        """Guard against a weird pre-existing state: input 1 disabled (which
        rule a would naively map to the loopback) while input 2 already
        holds the loopback -- must bail rather than end up with both inputs
        on the loopback at once."""
        state, store = _make_state(
            tmp_path,
            audio1={"enabled": False},
            audio2={"capture_device": BLUETOOTH_CAPTURE_DEVICE, "enabled": True},
        )
        handler = _make_handler()
        try:
            self._poll(handler, state)
            snap = store.snapshot()
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["input_auto_configure"] == {"action": "already_configured"}
        # Input 1 must not have been touched -- still disabled, no device.
        assert snap.audio1_enabled is False
        assert snap.audio1.capture_device == ""
        assert snap.audio2.capture_device == BLUETOOTH_CAPTURE_DEVICE

    def test_never_auto_disables_anything(self, tmp_path):
        """Both inputs already enabled on real devices: polling must never
        flip an enabled flag to False."""
        state, store = _make_state(
            tmp_path,
            audio1={"capture_device": "hw:1,0"},
            audio2={"capture_device": "hw:2,0", "enabled": True},
        )
        handler = _make_handler()
        try:
            self._poll(handler, state)
            snap = store.snapshot()
        finally:
            store.close(save=False)
        assert snap.audio1_enabled is True
        assert snap.audio2_enabled is True

    def test_no_state_available_omits_auto_configure_field(self):
        """When no WebUIState can be resolved (e.g. the module-global
        singleton hasn't been set up), the response falls back to the
        plain daemon-passthrough shape rather than raising."""
        from autostream_webui_api import send_bluetooth_pair_status_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.BluetoothClient") as m_cls, \
             patch("autostream_webui_api._bt_pairing_resolve_state", return_value=None):
            m_cls.return_value.pair_status.return_value = {"ok": True, "state": "done"}
            send_bluetooth_pair_status_json(handler)
        code, body = _response(handler)
        assert code == 200
        assert body == {"ok": True, "state": "done"}

    def test_failed_state_never_triggers_auto_configure(self, tmp_path):
        """A "failed" pairing attempt must never apply the auto-enable
        rules or attach the field, even with a fully resolvable state."""
        state, store = _make_state(tmp_path, audio1={"enabled": False})
        handler = _make_handler()
        try:
            self._poll(handler, state, daemon_state="failed")
            snap = store.snapshot()
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body == {"ok": True, "state": "failed"}
        assert "input_auto_configure" not in body
        assert snap.audio1_enabled is False
        assert snap.audio1.capture_device == ""

    def test_in_progress_state_never_triggers_auto_configure(self, tmp_path):
        """Same guarantee for an in-progress attempt."""
        state, store = _make_state(tmp_path, audio1={"enabled": False})
        handler = _make_handler()
        try:
            self._poll(handler, state, daemon_state="in_progress")
            snap = store.snapshot()
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert "input_auto_configure" not in body
        assert snap.audio1_enabled is False

    def test_repeated_done_polls_stay_idempotent(self, tmp_path):
        """The UI keeps polling after observing "done" is possible in
        principle (e.g. a slow client tick); a second "done" poll must not
        double-apply or error -- the rules themselves short-circuit once
        the input is already on the loopback."""
        state, store = _make_state(tmp_path, audio1={"enabled": False})
        handler1 = _make_handler()
        handler2 = _make_handler()
        try:
            self._poll(handler1, state)
            self._poll(handler2, state)
            snap = store.snapshot()
        finally:
            store.close(save=False)
        _, body2 = _response(handler2)
        assert body2["input_auto_configure"] == {"action": "already_configured"}
        assert snap.audio1.capture_device == BLUETOOTH_CAPTURE_DEVICE
        assert snap.audio1_enabled is True

    def test_pair_post_no_longer_applies_auto_configure(self, tmp_path):
        """The pair POST reply only means pairing *started* -- it must
        never touch settings or carry the auto-configure field, regardless
        of what the settings snapshot looks like."""
        from autostream_webui_api import send_bluetooth_pair_post_json
        state, store = _make_state(tmp_path, audio1={"enabled": False})
        handler = _make_handler()
        try:
            with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
                 patch("autostream_webui_api.BluetoothClient") as m_cls:
                m_cls.return_value.pair.return_value = {"ok": True}
                send_bluetooth_pair_post_json(handler, {"address": "AA:BB:CC:DD:EE:FF"})
            snap = store.snapshot()
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body == {"ok": True}
        assert "input_auto_configure" not in body
        assert snap.audio1_enabled is False
        assert snap.audio1.capture_device == ""


# ---------------------------------------------------------------------------
# _bt_pairing_resolve_state — script-vs-module identity fix
# ---------------------------------------------------------------------------

class TestBtPairingResolveState:
    """The webui process runs its own module as script (``__main__``), not
    as an importable ``autostream_webui`` -- so resolving the process-wide
    state must never ``import autostream_webui`` (that would create a
    second, unpopulated module instance) and must look the already-loaded
    modules up in ``sys.modules`` instead.
    """

    def test_explicit_state_passed_through_untouched(self):
        from autostream_webui_api import _bt_pairing_resolve_state
        sentinel = object()
        assert _bt_pairing_resolve_state(sentinel) is sentinel

    def test_falls_back_to_main_module_state(self):
        from autostream_webui_api import _bt_pairing_resolve_state
        fake_main = type("FakeMain", (), {"STATE": "main-state"})()
        had_bt_module = "autostream_webui" in sys.modules
        saved_bt_module = sys.modules.pop("autostream_webui", None)
        saved_main = sys.modules.get("__main__")
        try:
            sys.modules["__main__"] = fake_main
            assert _bt_pairing_resolve_state(None) == "main-state"
            # Must not have imported (or otherwise populated) a distinct
            # "autostream_webui" module entry as a side effect.
            assert "autostream_webui" not in sys.modules
        finally:
            sys.modules["__main__"] = saved_main
            if had_bt_module:
                sys.modules["autostream_webui"] = saved_bt_module

    def test_prefers_autostream_webui_module_over_main(self):
        """When a real ``autostream_webui`` module entry does exist (e.g. a
        test imported it) and carries a non-None STATE, it wins over
        ``__main__`` -- covers the (non-production) case of running under
        an actual import rather than as the launched script."""
        from autostream_webui_api import _bt_pairing_resolve_state
        fake_bt_module = type("FakeBtModule", (), {"STATE": "bt-module-state"})()
        fake_main = type("FakeMain", (), {"STATE": "main-state"})()
        saved_bt_module = sys.modules.get("autostream_webui")
        saved_main = sys.modules.get("__main__")
        try:
            sys.modules["autostream_webui"] = fake_bt_module
            sys.modules["__main__"] = fake_main
            assert _bt_pairing_resolve_state(None) == "bt-module-state"
        finally:
            if saved_bt_module is not None:
                sys.modules["autostream_webui"] = saved_bt_module
            else:
                sys.modules.pop("autostream_webui", None)
            sys.modules["__main__"] = saved_main

    def test_no_resolvable_state_returns_none_and_warns(self, caplog):
        from autostream_webui_api import _bt_pairing_resolve_state
        saved_bt_module = sys.modules.pop("autostream_webui", None)
        saved_main = sys.modules.get("__main__")
        try:
            sys.modules["__main__"] = type("FakeMain", (), {})()
            with caplog.at_level("WARNING"):
                assert _bt_pairing_resolve_state(None) is None
            assert "state unavailable" in caplog.text.lower()
        finally:
            sys.modules["__main__"] = saved_main
            if saved_bt_module is not None:
                sys.modules["autostream_webui"] = saved_bt_module


# ---------------------------------------------------------------------------
# POST forget
# ---------------------------------------------------------------------------

class TestBluetoothForgetPost:
    def test_success(self):
        from autostream_webui_api import send_bluetooth_forget_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.BluetoothClient") as m_cls:
            m_cls.return_value.forget.return_value = {"ok": True}
            send_bluetooth_forget_post_json(handler)
        code, body = _response(handler)
        assert code == 200
        assert body == {"ok": True}

    def test_disabled_is_unavailable(self):
        from autostream_webui_api import send_bluetooth_forget_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=False):
            send_bluetooth_forget_post_json(handler)
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"

    def test_daemon_failure_is_unavailable(self):
        from autostream_webui_api import send_bluetooth_forget_post_json
        handler = _make_handler()
        with patch("autostream_webui_api.bluetooth_installed", return_value=True), \
             patch("autostream_webui_api.BluetoothClient") as m_cls:
            m_cls.return_value.forget.return_value = None
            send_bluetooth_forget_post_json(handler)
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"


# ---------------------------------------------------------------------------
# Route registration in autostream_webui.py
# ---------------------------------------------------------------------------

class TestRouteRegistration:
    def _webui(self):
        try:
            import autostream_webui as _webui
        except ImportError:
            pytest.skip("autostream_webui import chain unavailable")
        return _webui

    def test_get_routes_dispatch(self):
        import inspect
        webui = self._webui()
        src = inspect.getsource(webui.ConfigWebHandler.do_GET)
        assert "/api/bluetooth/status" in src
        assert "send_bluetooth_status_json" in src
        assert "/api/bluetooth/scan_results" in src
        assert "send_bluetooth_scan_results_json" in src
        assert "/api/bluetooth/pair_status" in src
        assert "send_bluetooth_pair_status_json" in src

    def test_pair_status_dispatch_passes_module_state(self):
        """The pair_status handler needs the module-global WebUIState to
        run the post-pair auto-configure step (see
        _bt_pairing_resolve_state's script-vs-module identity trap) -- the
        dispatch call site must pass it explicitly rather than relying on
        the handler's own fallback resolution."""
        import inspect
        webui = self._webui()
        src = inspect.getsource(webui.ConfigWebHandler.do_GET)
        idx = src.find('"/api/bluetooth/pair_status"')
        assert idx != -1
        window = src[idx: idx + 300]
        assert "send_bluetooth_pair_status_json(self, state=STATE)" in window

    def test_post_routes_dispatch(self):
        import inspect
        webui = self._webui()
        src = inspect.getsource(webui.ConfigWebHandler.do_POST)
        assert "/api/bluetooth/scan" in src
        assert "send_bluetooth_scan_post_json" in src
        assert "/api/bluetooth/pair" in src
        assert "send_bluetooth_pair_post_json" in src
        assert "/api/bluetooth/forget" in src
        assert "send_bluetooth_forget_post_json" in src
        assert "/api/bluetooth/services" in src
        assert "send_bluetooth_services_post_json" in src
        assert "/api/bluetooth/onboard" in src
        assert "send_bluetooth_onboard_post_json" in src
        assert "/api/bluetooth/buffer" in src
        assert "send_bluetooth_buffer_post_json" in src

    def test_get_routes_each_have_explicit_auth_gate(self):
        """Per-route convention: each new GET route calls
        require_authenticated_if_pin_enabled directly above its handler call."""
        import inspect
        webui = self._webui()
        src = inspect.getsource(webui.ConfigWebHandler.do_GET)
        for marker in (
            '"/api/bluetooth/status"', '"/api/bluetooth/scan_results"', '"/api/bluetooth/pair_status"',
        ):
            idx = src.find(marker)
            assert idx != -1
            window = src[idx: idx + 200]
            assert "require_authenticated_if_pin_enabled" in window

    def test_post_routes_each_have_explicit_auth_gate(self):
        import inspect
        webui = self._webui()
        src = inspect.getsource(webui.ConfigWebHandler.do_POST)
        for marker in (
            '"/api/bluetooth/scan"', '"/api/bluetooth/pair"', '"/api/bluetooth/forget"',
            '"/api/bluetooth/services"', '"/api/bluetooth/onboard"', '"/api/bluetooth/buffer"',
        ):
            idx = src.find(marker)
            assert idx != -1
            window = src[idx: idx + 200]
            assert "require_authenticated_if_pin_enabled" in window

    def test_not_in_get_commissioning_allowlist(self):
        import inspect
        webui = self._webui()
        src = inspect.getsource(webui.ConfigWebHandler.do_GET)
        # Isolate the commissioning-allowed block (between "allowed = (" and its close).
        start = src.find("allowed = (")
        end = src.find("if not allowed:", start)
        block = src[start:end]
        assert "/api/bluetooth" not in block

    def test_not_in_post_commissioning_allowlist(self):
        import inspect
        webui = self._webui()
        src = inspect.getsource(webui.ConfigWebHandler.do_POST)
        start = src.find("_post_commissioning_allowed = (")
        end = src.find("if not _post_commissioning_allowed:", start)
        block = src[start:end]
        assert "/api/bluetooth" not in block


# ---------------------------------------------------------------------------
# Settings guard — cross-input capture_device exclusivity (generalised from
# the original Bluetooth-only double-assignment guard)
# ---------------------------------------------------------------------------

class TestDoubleAssignmentGuard:
    def test_second_input_rejected_when_first_already_bluetooth(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(
            tmp_path, audio1={"capture_device": BLUETOOTH_CAPTURE_DEVICE},
        )
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "audio2.capture_device", "value": BLUETOOTH_CAPTURE_DEVICE},
            )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False
        assert "bluetooth" in body["error"].lower() or "assigned" in body["error"].lower()

    def test_first_input_rejected_when_second_already_bluetooth(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(
            tmp_path, audio2={"capture_device": BLUETOOTH_CAPTURE_DEVICE},
        )
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "audio1.capture_device", "value": BLUETOOTH_CAPTURE_DEVICE},
            )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False

    def test_assigning_bluetooth_to_first_input_when_free_succeeds(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "audio1.capture_device", "value": BLUETOOTH_CAPTURE_DEVICE},
            )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is True

    def test_different_device_from_bluetooth_still_succeeds(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(
            tmp_path, audio1={"capture_device": BLUETOOTH_CAPTURE_DEVICE},
        )
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "audio2.capture_device", "value": "hw:1,0"},
            )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is True

    def test_ordinary_duplicate_device_rejected(self, tmp_path):
        """The guard is not Bluetooth-specific -- any device already
        assigned to the other input is rejected, e.g. two USB devices."""
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(
            tmp_path, audio1={"capture_device": "hw:1,0"},
        )
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "audio2.capture_device", "value": "hw:1,0"},
            )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False
        assert "assigned" in body["error"].lower()

    def test_ordinary_device_free_to_assign_when_not_taken(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(
            tmp_path, audio1={"capture_device": "hw:1,0"},
        )
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "audio2.capture_device", "value": "hw:2,0"},
            )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is True

    def test_toctou_race_atomic_mutator_check_catches_stale_fast_path(self, tmp_path):
        """The snapshot-based check in send_settings_post_json (the
        "fast path") happens outside the settings store lock, so two
        concurrent POSTs could both read a stale snapshot showing no
        conflict and both proceed to settings.update().  The authoritative
        check must live inside the mutator (which runs atomically under
        SettingsStore._lock, against the real raw dict being committed) so
        the second of the two still gets rejected.

        Simulated deterministically here: patch settings.snapshot() to
        return a stale pre-race view (no conflict) for the fast-path check,
        while the store's real raw state already has audio1 committed to
        Bluetooth (as if a concurrent request had just landed it).  Only the
        mutator-level check -- not the fast path -- can catch this.
        """
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        stale_snapshot = store.snapshot()  # audio1 not yet Bluetooth

        # Simulate the concurrent request that already committed audio1.
        store.update(
            lambda raw: raw.setdefault("audio1", {}).update({"capture_device": BLUETOOTH_CAPTURE_DEVICE})
        )

        handler = _make_handler()
        with patch.object(store, "snapshot", return_value=stale_snapshot):
            send_settings_post_json(
                handler, state,
                {"field": "audio2.capture_device", "value": BLUETOOTH_CAPTURE_DEVICE},
            )
        code, body = _response(handler)
        final = store.snapshot()  # patch reverted -- real post-request state
        store.close(save=False)

        assert code == 400
        assert body["ok"] is False
        assert "assigned" in body["error"].lower() or "bluetooth" in body["error"].lower()
        # The rejected mutation must not have been committed.
        assert final.audio2.capture_device != BLUETOOTH_CAPTURE_DEVICE

    def test_reassigning_same_input_to_bluetooth_is_not_a_double_assignment(self, tmp_path):
        """Re-saving audio1 as Bluetooth while audio1 itself already holds it
        must not be rejected as a conflict with 'the other input'."""
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(
            tmp_path, audio1={"capture_device": BLUETOOTH_CAPTURE_DEVICE},
        )
        handler = _make_handler()
        try:
            send_settings_post_json(
                handler, state,
                {"field": "audio1.capture_device", "value": BLUETOOTH_CAPTURE_DEVICE},
            )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is True


# ---------------------------------------------------------------------------
# Settings validator — reject the loopback PLAYBACK side as a capture_device
# (field report B): it is an internal device the pump feeds, never a valid
# input, so a stale save or hand-crafted request must not be able to set it.
# ---------------------------------------------------------------------------

class TestCaptureDeviceRejectsLoopbackPlayback:
    def test_rejected_when_bluetooth_enabled(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            with patch("autostream_webui_api.bluetooth_installed", return_value=True):
                send_settings_post_json(
                    handler, state,
                    {"field": "audio1.capture_device", "value": BLUETOOTH_PLAYBACK_DEVICE},
                )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False
        assert "bluetooth" in body["error"].lower()
        assert "loopback" in body["error"].lower() or "internal" in body["error"].lower()

    def test_rejected_for_second_input_too_when_bluetooth_enabled(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            with patch("autostream_webui_api.bluetooth_installed", return_value=True):
                send_settings_post_json(
                    handler, state,
                    {"field": "audio2.capture_device", "value": BLUETOOTH_PLAYBACK_DEVICE},
                )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False

    def test_accepted_when_bluetooth_disabled(self, tmp_path):
        """Byte-identical validator behaviour when Bluetooth mode is off --
        the raw hw: string is just an (unusual but well-formed) capture
        device value with no special meaning."""
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            with patch("autostream_webui_api.bluetooth_installed", return_value=False):
                send_settings_post_json(
                    handler, state,
                    {"field": "audio1.capture_device", "value": BLUETOOTH_PLAYBACK_DEVICE},
                )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is True

    def test_capture_side_still_accepted_when_bluetooth_enabled(self, tmp_path):
        """The CAPTURE side (BLUETOOTH_CAPTURE_DEVICE) is the valid Bluetooth
        input entry -- must not be caught by the playback-side guard."""
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            with patch("autostream_webui_api.bluetooth_installed", return_value=True):
                send_settings_post_json(
                    handler, state,
                    {"field": "audio1.capture_device", "value": BLUETOOTH_CAPTURE_DEVICE},
                )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is True

    def test_ordinary_device_still_accepted_when_bluetooth_enabled(self, tmp_path):
        from autostream_webui_api import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            with patch("autostream_webui_api.bluetooth_installed", return_value=True):
                send_settings_post_json(
                    handler, state,
                    {"field": "audio1.capture_device", "value": "hw:1,0"},
                )
        finally:
            store.close(save=False)
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is True


# ---------------------------------------------------------------------------
# About page — conditional Bluetooth service row
# ---------------------------------------------------------------------------

class TestAboutPageBluetoothRow:
    def _render(self):
        import autostream_webui_page_about as _about
        handler = MagicMock()
        buf = io.BytesIO()
        handler.wfile = buf
        state = MagicMock()
        with patch("autostream_webui_page_about.get_app_version", return_value="1.2.3"), \
             patch("autostream_webui_page_about.build_top_banner_html", return_value=("", "")), \
             patch("autostream_webui_page_about._config_snapshot", return_value=None), \
             patch("autostream_webui_page_about.load_license_text", return_value=""), \
             patch("autostream_webui_page_about.render_license_md", return_value=""):
            _about.send_about_page(handler, state)
        return buf.getvalue().decode("utf-8")

    def test_row_absent_when_disabled(self):
        import autostream_webui_page_about as _about
        with patch("autostream_webui_page_about.bluetooth_installed", return_value=False):
            html = self._render()
        assert "autostream_bluetooth.service" not in html

    def test_row_present_when_enabled(self):
        import autostream_webui_page_about as _about
        with patch("autostream_webui_page_about.bluetooth_installed", return_value=True):
            html = self._render()
        assert "data-service-unit='autostream_bluetooth.service'" in html or \
               'data-service-unit="autostream_bluetooth.service"' in html
        assert "Bluetooth Service" in html

    def test_collect_service_states_includes_row_when_enabled(self):
        import autostream_webui_page_about as _about
        with patch("autostream_webui_page_about.bluetooth_installed", return_value=True), \
             patch("autostream_webui_page_about.subprocess.run",
                   return_value=MagicMock(stdout="", returncode=0)):
            services = _about._collect_service_states("owntone", {})
        units = [s["unit"] for s in services]
        assert "autostream_bluetooth.service" in units
        assert len(services) == 7

    def test_collect_service_states_excludes_row_when_disabled(self):
        import autostream_webui_page_about as _about
        with patch("autostream_webui_page_about.bluetooth_installed", return_value=False), \
             patch("autostream_webui_page_about.subprocess.run",
                   return_value=MagicMock(stdout="", returncode=0)):
            services = _about._collect_service_states("owntone", {})
        units = [s["unit"] for s in services]
        assert "autostream_bluetooth.service" not in units
        assert len(services) == 6
