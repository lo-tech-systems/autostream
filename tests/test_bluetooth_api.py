"""Tests for the Bluetooth web-route/JSON-handler surface:

  - autostream_webui_api.send_bluetooth_* handlers (status/pair_window/pair/forget/
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
from settings_fixtures import fixed_view
import webui.session_state as session_state
import webui.system.services as webui_services
import webui.browser.about as webui_about
import webui.system.bluetooth as webui_system_bluetooth


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
        },
        "updates": {"auto_update": False, "update_channel": "stable"},
    }
    data.update(audio_overrides)
    _write_config(cfg, data)
    return cfg


def _make_state(tmp_path: Path, **audio_overrides):
    from autostream_settings import SettingsStore
    from webui.session_state import WebUIState
    cfg = _minimal_cfg(tmp_path, **audio_overrides)
    store = SettingsStore(str(cfg), _save_interval_seconds=9999)
    state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)
    return state, store


# ---------------------------------------------------------------------------
# send_bluetooth_status_json
# ---------------------------------------------------------------------------

class TestBluetoothStatusJson:
    def test_not_installed_returns_flags_false_daemon_none(self, tmp_path):
        from webui.system.bluetooth import send_bluetooth_status_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            with patch("webui.system.bluetooth.bluetooth_installed", return_value=False):
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
                "capture_label": "Bluetooth (service unavailable)",
            },
        }

    def test_installed_live_status_returned(self, tmp_path):
        from webui.system.bluetooth import send_bluetooth_status_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        live = {"ok": True, "adapter_present": True, "paired": None, "link": "disconnected",
                "streaming": False, "scanning": False, "buffer_ms": 200, "adapter_kind": "usb"}
        try:
            with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
                 patch("webui.system.bluetooth.bluetooth_services_enabled", return_value=True), \
                 patch("webui.system.bluetooth.bluetooth_onboard_enabled", return_value=False), \
                 patch("webui.system.bluetooth.BluetoothClient") as m_cls:
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
            "capture_label": "Bluetooth (not paired)",
        }

    def test_ui_enabled_not_paired(self, tmp_path):
        from webui.system.bluetooth import send_bluetooth_status_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        live = {"ok": True, "adapter_present": True, "paired": None, "link": "disconnected",
                "streaming": False, "scanning": False}
        try:
            with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
                 patch("webui.system.bluetooth.bluetooth_services_enabled", return_value=True), \
                 patch("webui.system.bluetooth.bluetooth_onboard_enabled", return_value=False), \
                 patch("webui.system.bluetooth.BluetoothClient") as m_cls:
                m_cls.return_value.status.return_value = live
                send_bluetooth_status_json(handler, state)
        finally:
            store.close(save=False)
        _, body = _response(handler)
        assert body["ui"] == {
            "card_summary": "Enabled · Not paired",
            "paired_text": "No device paired",
            "bt_input_text": "Not Connected",
            "capture_label": "Bluetooth (not paired)",
        }

    def test_ui_paired_and_connected(self, tmp_path):
        from webui.system.bluetooth import send_bluetooth_status_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        live = {"ok": True, "adapter_present": True,
                "paired": {"mac": "AA:BB:CC:DD:EE:FF", "name": "BT-Turntable"},
                "link": "connected", "streaming": True, "scanning": False}
        try:
            with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
                 patch("webui.system.bluetooth.bluetooth_services_enabled", return_value=True), \
                 patch("webui.system.bluetooth.bluetooth_onboard_enabled", return_value=False), \
                 patch("webui.system.bluetooth.BluetoothClient") as m_cls:
                m_cls.return_value.status.return_value = live
                send_bluetooth_status_json(handler, state)
        finally:
            store.close(save=False)
        _, body = _response(handler)
        assert body["ui"] == {
            "card_summary": "Enabled · BT-Turntable connected",
            "paired_text": "BT-Turntable · Connected",
            "bt_input_text": "BT-Turntable",
            "capture_label": "Bluetooth: BT-Turntable",
        }

    def test_ui_paired_but_disconnected(self, tmp_path):
        """The fifth state: paired device present but the link is down --
        must not be reported as 'connected'."""
        from webui.system.bluetooth import send_bluetooth_status_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        live = {"ok": True, "adapter_present": True,
                "paired": {"mac": "AA:BB:CC:DD:EE:FF", "name": "BT-Turntable"},
                "link": "disconnected", "streaming": False, "scanning": False}
        try:
            with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
                 patch("webui.system.bluetooth.bluetooth_services_enabled", return_value=True), \
                 patch("webui.system.bluetooth.bluetooth_onboard_enabled", return_value=False), \
                 patch("webui.system.bluetooth.BluetoothClient") as m_cls:
                m_cls.return_value.status.return_value = live
                send_bluetooth_status_json(handler, state)
        finally:
            store.close(save=False)
        _, body = _response(handler)
        assert body["ui"] == {
            "card_summary": "Enabled · BT-Turntable (not connected)",
            "paired_text": "BT-Turntable · Not Connected",
            "bt_input_text": "Not Connected",
            "capture_label": "Bluetooth: BT-Turntable",
        }

    def test_installed_live_fails_falls_back_to_cache(self, tmp_path, fake_store):
        from webui.system.bluetooth import send_bluetooth_status_json
        state, store = _make_state(tmp_path)
        cached = {"ok": True, "adapter_present": True, "paired": None, "link": "disconnected",
                  "streaming": False, "scanning": False}
        fake_store.devices(bluetooth_status=cached)
        handler = _make_handler()
        try:
            with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
                 patch("webui.system.bluetooth.bluetooth_services_enabled", return_value=True), \
                 patch("webui.system.bluetooth.bluetooth_onboard_enabled", return_value=False), \
                 patch("webui.system.bluetooth.BluetoothClient") as m_cls:
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
        from webui.system.bluetooth import send_bluetooth_status_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
                 patch("webui.system.bluetooth.bluetooth_services_enabled", return_value=False), \
                 patch("webui.system.bluetooth.bluetooth_onboard_enabled", return_value=False), \
                 patch("webui.system.bluetooth.BluetoothClient") as m_cls:
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
        from webui.system.bluetooth import send_bluetooth_services_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
             patch("webui.system.bluetooth.bt_services_enable", return_value=(True, "enabled")) as m_en, \
             patch("webui.system.bluetooth.bt_services_disable") as m_dis:
            send_bluetooth_services_post_json(handler, {"action": "enable"})
        code, body = _response(handler)
        assert code == 200
        assert body == {"ok": True, "message": "enabled"}
        m_en.assert_called_once()
        m_dis.assert_not_called()

    def test_disable_action(self):
        from webui.system.bluetooth import send_bluetooth_services_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
             patch("webui.system.bluetooth.bt_services_disable", return_value=(True, "disabled")):
            send_bluetooth_services_post_json(handler, {"action": "disable"})
        code, body = _response(handler)
        assert code == 200
        assert body == {"ok": True, "message": "disabled"}

    def test_failure_reported_but_still_200(self):
        from webui.system.bluetooth import send_bluetooth_services_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
             patch("webui.system.bluetooth.bt_services_enable", return_value=(False, "sudo failed")):
            send_bluetooth_services_post_json(handler, {"action": "enable"})
        code, body = _response(handler)
        assert code == 200
        assert body == {"ok": False, "message": "sudo failed"}

    @pytest.mark.parametrize("action", ["start", "stop", "", None, 1, "enable_all"])
    def test_invalid_action_rejected(self, action):
        from webui.system.bluetooth import send_bluetooth_services_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True):
            send_bluetooth_services_post_json(handler, {"action": action})
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False

    def test_extra_keys_rejected(self):
        from webui.system.bluetooth import send_bluetooth_services_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True):
            send_bluetooth_services_post_json(handler, {"action": "enable", "extra": 1})
        code, body = _response(handler)
        assert code == 400

    def test_not_installed_is_unavailable(self):
        from webui.system.bluetooth import send_bluetooth_services_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=False):
            send_bluetooth_services_post_json(handler, {"action": "enable"})
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"


class TestBluetoothOnboardPost:
    def test_enable_reports_reboot_required(self):
        from webui.system.bluetooth import send_bluetooth_onboard_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
             patch("webui.system.bluetooth.bt_onboard_set", return_value=(True, "onboard on")) as m_set:
            send_bluetooth_onboard_post_json(handler, {"enabled": True})
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is True
        assert body["reboot_required"] is True
        m_set.assert_called_once_with(True)

    def test_disable_reports_reboot_required(self):
        from webui.system.bluetooth import send_bluetooth_onboard_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
             patch("webui.system.bluetooth.bt_onboard_set", return_value=(True, "onboard off")):
            send_bluetooth_onboard_post_json(handler, {"enabled": False})
        _, body = _response(handler)
        assert body["reboot_required"] is True

    def test_failure_no_reboot_required_key(self):
        from webui.system.bluetooth import send_bluetooth_onboard_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
             patch("webui.system.bluetooth.bt_onboard_set", return_value=(False, "sudo failed")):
            send_bluetooth_onboard_post_json(handler, {"enabled": True})
        _, body = _response(handler)
        assert body["ok"] is False
        assert "reboot_required" not in body

    @pytest.mark.parametrize("bad", ["true", 1, None, "yes"])
    def test_non_bool_enabled_rejected(self, bad):
        from webui.system.bluetooth import send_bluetooth_onboard_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True):
            send_bluetooth_onboard_post_json(handler, {"enabled": bad})
        code, _ = _response(handler)
        assert code == 400

    def test_extra_keys_rejected(self):
        from webui.system.bluetooth import send_bluetooth_onboard_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True):
            send_bluetooth_onboard_post_json(handler, {"enabled": True, "extra": 1})
        code, _ = _response(handler)
        assert code == 400

    def test_not_installed_is_unavailable(self):
        from webui.system.bluetooth import send_bluetooth_onboard_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=False):
            send_bluetooth_onboard_post_json(handler, {"enabled": True})
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"


class TestBluetoothBufferPost:
    def test_valid_value_accepted(self):
        from webui.system.bluetooth import send_bluetooth_buffer_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
             patch("webui.system.bluetooth.BluetoothClient") as m_cls:
            m_cls.return_value.configure.return_value = {"ok": True}
            send_bluetooth_buffer_post_json(handler, {"buffer_ms": 250})
        code, body = _response(handler)
        assert code == 200
        assert body == {"ok": True, "buffer_ms": 250}
        m_cls.return_value.configure.assert_called_once_with(250)

    @pytest.mark.parametrize("bad", [99, 501, 0, -1, "200", 200.5, True, None])
    def test_out_of_range_or_wrong_type_rejected(self, bad):
        from webui.system.bluetooth import send_bluetooth_buffer_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
             patch("webui.system.bluetooth.BluetoothClient") as m_cls:
            send_bluetooth_buffer_post_json(handler, {"buffer_ms": bad})
        code, body = _response(handler)
        assert code == 400
        m_cls.return_value.configure.assert_not_called()

    def test_boundary_values_accepted(self):
        from webui.system.bluetooth import send_bluetooth_buffer_post_json
        for val in (100, 500):
            handler = _make_handler()
            with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
                 patch("webui.system.bluetooth.BluetoothClient") as m_cls:
                m_cls.return_value.configure.return_value = {"ok": True}
                send_bluetooth_buffer_post_json(handler, {"buffer_ms": val})
            code, _ = _response(handler)
            assert code == 200

    def test_daemon_rejects_as_invalid(self):
        from webui.system.bluetooth import send_bluetooth_buffer_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
             patch("webui.system.bluetooth.BluetoothClient") as m_cls:
            m_cls.return_value.configure.return_value = {"ok": False, "error": "invalid_buffer_ms"}
            send_bluetooth_buffer_post_json(handler, {"buffer_ms": 200})
        code, body = _response(handler)
        assert code == 400
        assert body["error"] == "invalid_buffer_ms"

    def test_daemon_down_is_503(self):
        from webui.system.bluetooth import send_bluetooth_buffer_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
             patch("webui.system.bluetooth.BluetoothClient") as m_cls:
            m_cls.return_value.configure.return_value = None
            send_bluetooth_buffer_post_json(handler, {"buffer_ms": 200})
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"

    def test_not_installed_is_unavailable(self):
        from webui.system.bluetooth import send_bluetooth_buffer_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=False):
            send_bluetooth_buffer_post_json(handler, {"buffer_ms": 200})
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"

    def test_extra_keys_rejected(self):
        from webui.system.bluetooth import send_bluetooth_buffer_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True):
            send_bluetooth_buffer_post_json(handler, {"buffer_ms": 200, "extra": 1})
        code, _ = _response(handler)
        assert code == 400


# ---------------------------------------------------------------------------
# WebUIState.get_bluetooth_status -- copy isolation
# ---------------------------------------------------------------------------

class TestBluetoothStatusCopies:
    """get_bluetooth_status reads the devices part and returns a fresh mutable
    copy: the status nests paired{mac, name}, and a shallow copy would leave
    that nested dict shared between callers."""

    def test_the_status_is_what_the_part_holds(self, tmp_path, fake_store):
        from webui.session_state import WebUIState
        state = WebUIState(str(tmp_path / "cfg.json"), str(tmp_path / "state.json"), settings=fixed_view())
        status = {"ok": True, "paired": {"mac": "AA:BB:CC:DD:EE:FF", "name": "Original"}, "link": "connected"}
        fake_store.devices(bluetooth_status=status)
        assert state.get_bluetooth_status() == status

    def test_mutating_the_published_dict_does_not_affect_the_part(self, tmp_path, fake_store):
        from webui.session_state import WebUIState
        state = WebUIState(str(tmp_path / "cfg.json"), str(tmp_path / "state.json"), settings=fixed_view())
        status = {"ok": True, "paired": {"mac": "AA:BB:CC:DD:EE:FF", "name": "Original"}, "link": "connected"}
        fake_store.devices(bluetooth_status=status)
        status["paired"]["name"] = "Mutated"
        status["link"] = "disconnected"
        cached = state.get_bluetooth_status()
        assert cached["paired"]["name"] == "Original"
        assert cached["link"] == "connected"

    def test_mutating_returned_value_does_not_affect_the_next_read(self, tmp_path, fake_store):
        from webui.session_state import WebUIState
        state = WebUIState(str(tmp_path / "cfg.json"), str(tmp_path / "state.json"), settings=fixed_view())
        status = {"ok": True, "paired": {"mac": "AA:BB:CC:DD:EE:FF", "name": "Original"}, "link": "connected"}
        fake_store.devices(bluetooth_status=status)
        got = state.get_bluetooth_status()
        got["paired"]["name"] = "Mutated"
        got["link"] = "disconnected"
        again = state.get_bluetooth_status()
        assert again["paired"]["name"] == "Original"
        assert again["link"] == "connected"

    def test_a_part_without_a_status_gives_none(self, tmp_path, fake_store):
        from webui.session_state import WebUIState
        state = WebUIState(str(tmp_path / "cfg.json"), str(tmp_path / "state.json"), settings=fixed_view())
        fake_store.devices(bluetooth_status={"ok": True, "paired": None})
        fake_store.devices(bluetooth_status=None)
        assert state.get_bluetooth_status() is None


# ---------------------------------------------------------------------------
# The pairing window: GET (the poll and heartbeat) and POST start/stop
# ---------------------------------------------------------------------------

_OPEN_POLL = {"ok": True, "state": "open", "remaining_s": 270, "devices": [], "adopting": None,
              "last_close": None, "last_error": None}


class TestBluetoothPairWindowGet:
    def test_disabled_is_unavailable(self):
        from webui.system.bluetooth import send_bluetooth_pair_window_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=False):
            send_bluetooth_pair_window_json(handler)
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"
        assert body.get("error_status") == 503

    def test_poll_passes_the_window_through(self):
        from webui.system.bluetooth import send_bluetooth_pair_window_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
             patch("webui.system.bluetooth.BluetoothClient") as m_cls:
            m_cls.return_value.window_poll.return_value = dict(_OPEN_POLL)
            send_bluetooth_pair_window_json(handler)
        code, body = _response(handler)
        assert code == 200
        assert body == _OPEN_POLL
        m_cls.return_value.window_poll.assert_called_once_with()

    def test_daemon_unreachable_is_unavailable(self):
        from webui.system.bluetooth import send_bluetooth_pair_window_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
             patch("webui.system.bluetooth.BluetoothClient") as m_cls:
            m_cls.return_value.window_poll.return_value = None
            send_bluetooth_pair_window_json(handler)
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"
        assert body.get("error_status") == 503


class TestBluetoothPairWindowPost:
    def _post(self, payload, reply=None, installed=True, method="window_start"):
        from webui.system.bluetooth import send_bluetooth_pair_window_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=installed), \
             patch("webui.system.bluetooth.BluetoothClient") as m_cls:
            getattr(m_cls.return_value, method).return_value = reply
            send_bluetooth_pair_window_post_json(handler, payload)
        return handler, m_cls

    def test_start(self):
        handler, m_cls = self._post({"action": "start"}, {"ok": True})
        assert _response(handler) == (200, {"ok": True, "action": "start"})
        m_cls.return_value.window_start.assert_called_once()
        m_cls.return_value.window_stop.assert_not_called()

    def test_stop_succeeds_even_with_no_window(self):
        for reply in ({"ok": True}, {"ok": False, "error": "no_window"}):
            handler, _ = self._post({"action": "stop"}, reply, method="window_stop")
            assert _response(handler) == (200, {"ok": True, "action": "stop"})

    def test_start_while_closing_is_409(self):
        handler, _ = self._post({"action": "start"}, {"ok": False, "error": "window_closing"})
        code, body = _response(handler)
        assert code == 409 and body["error"] == "window_closing"

    @pytest.mark.parametrize("reply", [None, {"ok": False, "error": "no_adapter"}])
    def test_no_adapter_or_daemon_is_503(self, reply):
        handler, _ = self._post({"action": "start"}, reply)
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"
        assert body.get("error_status") == 503

    @pytest.mark.parametrize("payload", [
        {"action": "pause"}, {"action": None}, {"action": "start", "extra": 1}, "not a dict",
    ])
    def test_bad_requests_rejected(self, payload):
        handler, m_cls = self._post(payload, {"ok": True})
        assert _response(handler)[0] == 400
        m_cls.return_value.window_start.assert_not_called()

    def test_disabled_is_unavailable(self):
        handler, _ = self._post({"action": "start"}, installed=False)
        assert _response(handler)[1]["error"] == "bluetooth_unavailable"


# ---------------------------------------------------------------------------
# POST pair — server-side MAC validation
# ---------------------------------------------------------------------------

class TestBluetoothPairPost:
    def test_valid_mac_accepted(self):
        from webui.system.bluetooth import send_bluetooth_pair_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
             patch("webui.system.bluetooth.BluetoothClient") as m_cls:
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
        from webui.system.bluetooth import send_bluetooth_pair_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
             patch("webui.system.bluetooth.BluetoothClient") as m_cls:
            send_bluetooth_pair_post_json(handler, {"address": bad_address})
        code, body = _response(handler)
        assert code == 400
        assert body["ok"] is False
        m_cls.return_value.pair.assert_not_called()

    def test_extra_keys_rejected(self):
        from webui.system.bluetooth import send_bluetooth_pair_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True):
            send_bluetooth_pair_post_json(handler, {"address": "AA:BB:CC:DD:EE:FF", "extra": 1})
        code, body = _response(handler)
        assert code == 400

    def test_daemon_failure_is_unavailable(self):
        from webui.system.bluetooth import send_bluetooth_pair_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
             patch("webui.system.bluetooth.BluetoothClient") as m_cls:
            m_cls.return_value.pair.return_value = None
            send_bluetooth_pair_post_json(handler, {"address": "AA:BB:CC:DD:EE:FF"})
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"

    def test_disabled_is_unavailable(self):
        from webui.system.bluetooth import send_bluetooth_pair_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=False):
            send_bluetooth_pair_post_json(handler, {"address": "AA:BB:CC:DD:EE:FF"})
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"

    @pytest.mark.parametrize("error,status", [
        ("window_adopting", 409), ("no_window", 409), ("unknown_device", 404),
    ])
    def test_tap_refusals_map_to_their_statuses(self, error, status):
        from webui.system.bluetooth import send_bluetooth_pair_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
             patch("webui.system.bluetooth.BluetoothClient") as m_cls:
            m_cls.return_value.pair.return_value = {"ok": False, "error": error}
            send_bluetooth_pair_post_json(handler, {"address": "AA:BB:CC:DD:EE:FF"})
        code, body = _response(handler)
        assert body.get("error_status", code) == status
        assert body["ok"] is False
        assert body["error"] == error

    def test_other_non_ok_error_stays_503(self):
        """Any non-ok reply other than the tap refusals stays
        the generic 503 bluetooth_unavailable -- e.g. a daemon-side failure
        reason we don't have a dedicated mapping for.  503 is tunneled
        through the NGINX-intercepted-status contract (transport 200 +
        error_status), same as the existing daemon-failure tests."""
        from webui.system.bluetooth import send_bluetooth_pair_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
             patch("webui.system.bluetooth.BluetoothClient") as m_cls:
            m_cls.return_value.pair.return_value = {"ok": False, "error": "adapter_missing"}
            send_bluetooth_pair_post_json(handler, {"address": "AA:BB:CC:DD:EE:FF"})
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"
        assert body.get("error_status") == 503


# ---------------------------------------------------------------------------
# GET pair_window — post-pair input auto-enable rules
# ---------------------------------------------------------------------------

_POLL_REPLIES = {
    "done": {"ok": True, "state": "idle", "last_close": {"reason": "paired", "error": None}},
    "failed": {"ok": True, "state": "idle", "last_close": {"reason": "limit", "error": None}},
    "in_progress": {"ok": True, "state": "adopting", "last_close": None},
}


class TestBluetoothPairStatusAutoConfigure:
    """The daemon's ``pair`` reply only means the tap *started*; real
    success is only known once the window's poll shows it closed with
    ``last_close.reason == "paired"``. That's the hook point for the input
    auto-enable rules (see _bt_pair_auto_configure), not the POST handler --
    so this class exercises ``send_bluetooth_pair_window_json`` with a
    stubbed daemon reply rather than the pair POST.
    """

    def _poll(self, handler, state, daemon_state="done"):
        from webui.system.bluetooth import send_bluetooth_pair_window_json
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
             patch("webui.system.bluetooth.BluetoothClient") as m_cls:
            m_cls.return_value.window_poll.return_value = dict(_POLL_REPLIES[daemon_state])
            send_bluetooth_pair_window_json(handler, state=state)

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
        assert body["last_close"]["reason"] == "paired"
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
        """When the route passes no WebUIState, the response is the plain
        daemon-passthrough shape rather than raising."""
        from webui.system.bluetooth import send_bluetooth_pair_window_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
             patch("webui.system.bluetooth.BluetoothClient") as m_cls:
            m_cls.return_value.window_poll.return_value = dict(_POLL_REPLIES["done"])
            send_bluetooth_pair_window_json(handler)
        code, body = _response(handler)
        assert code == 200
        assert body == _POLL_REPLIES["done"]

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
        assert body == _POLL_REPLIES["failed"]
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
        from webui.system.bluetooth import send_bluetooth_pair_post_json
        state, store = _make_state(tmp_path, audio1={"enabled": False})
        handler = _make_handler()
        try:
            with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
                 patch("webui.system.bluetooth.BluetoothClient") as m_cls:
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
# POST forget
# ---------------------------------------------------------------------------

class TestBluetoothForgetPost:
    def test_success(self):
        from webui.system.bluetooth import send_bluetooth_forget_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
             patch("webui.system.bluetooth.BluetoothClient") as m_cls:
            m_cls.return_value.forget.return_value = {"ok": True}
            send_bluetooth_forget_post_json(handler)
        code, body = _response(handler)
        assert code == 200
        assert body == {"ok": True}

    def test_disabled_is_unavailable(self):
        from webui.system.bluetooth import send_bluetooth_forget_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=False):
            send_bluetooth_forget_post_json(handler)
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"

    def test_daemon_failure_is_unavailable(self):
        from webui.system.bluetooth import send_bluetooth_forget_post_json
        handler = _make_handler()
        with patch("webui.system.bluetooth.bluetooth_installed", return_value=True), \
             patch("webui.system.bluetooth.BluetoothClient") as m_cls:
            m_cls.return_value.forget.return_value = None
            send_bluetooth_forget_post_json(handler)
        _, body = _response(handler)
        assert body["error"] == "bluetooth_unavailable"


# ---------------------------------------------------------------------------
# Route registration in autostream_webui.py
# ---------------------------------------------------------------------------

class TestRouteRegistration:
    """Bluetooth GET and POST routes are dispatched through the route table
    (see webui/routes.py) -- do_GET/do_POST no
    longer contain inline elif arms for any of these paths, so this class
    asserts against ROUTES (registration + auth level + allow_unconfigured)
    rather than grepping handler source, and exercises dispatch() directly
    for the one behavioural claim (pair_window's STATE-passing) that source
    inspection used to stand in for.
    """

    def _webui(self):
        try:
            import webui.server as _webui
            import webui.routes as _routes
        except ImportError:
            pytest.skip("web server import chain unavailable")
        return _webui, _routes

    def _route(self, routes_mod, path, method):
        for r in routes_mod.ROUTES:
            if r.path == path and method in r.methods:
                return r
        return None

    def test_get_routes_registered(self):
        _webui, routes_mod = self._webui()
        expected = {
            "/api/bluetooth/status": "webui.system.bluetooth.send_bluetooth_status_json",
            "/api/bluetooth/pair_window": "webui.system.bluetooth.send_bluetooth_pair_window_json",
        }
        for path, handler_name in expected.items():
            r = self._route(routes_mod, path, "GET")
            assert r is not None, f"{path} is not registered as a GET route"
            assert r.handler == handler_name, (
                f"{path}: expected handler={handler_name!r}, got {r.handler!r}"
            )

    def test_pair_window_dispatch_passes_module_state(self):
        """The pair_window handler needs the process-wide WebUIState to run
        the post-pair auto-configure step -- dispatch() must pass it
        explicitly."""
        _webui, routes_mod = self._webui()
        h = MagicMock()
        h._commissioning_required.return_value = False
        state = MagicMock()
        with patch.object(session_state, "STATE", state), \
             patch.object(session_state, "AUTH") as mock_auth, \
             patch.object(webui_system_bluetooth, "send_bluetooth_pair_window_json") as stub:
            mock_auth.require_authenticated_if_pin_enabled.return_value = True
            assert routes_mod.dispatch(h, "GET", "/api/bluetooth/pair_window") is True
        stub.assert_called_once_with(h, state)

    def test_post_routes_registered(self):
        _webui, routes_mod = self._webui()
        expected = {
            "/api/bluetooth/pair_window": "webui.system.bluetooth._route_post_bluetooth_pair_window",
            "/api/bluetooth/pair": "webui.system.bluetooth._route_post_bluetooth_pair",
            "/api/bluetooth/forget": "webui.system.bluetooth._route_post_bluetooth_forget",
            "/api/bluetooth/services": "webui.system.bluetooth._route_post_bluetooth_services",
            "/api/bluetooth/onboard": "webui.system.bluetooth._route_post_bluetooth_onboard",
            "/api/bluetooth/buffer": "webui.system.bluetooth._route_post_bluetooth_buffer",
        }
        for path, handler_name in expected.items():
            r = self._route(routes_mod, path, "POST")
            assert r is not None, f"{path} is not registered as a POST route"
            assert r.handler == handler_name, (
                f"{path}: expected handler={handler_name!r}, got {r.handler!r}"
            )

    def test_get_routes_each_have_full_auth_gate(self):
        """Per-route convention: each of these GET routes requires PIN auth
        when a PIN is configured."""
        _webui, routes_mod = self._webui()
        for path in ("/api/bluetooth/status", "/api/bluetooth/pair_window"):
            r = self._route(routes_mod, path, "GET")
            assert r is not None, f"{path} is not registered as a GET route"
            assert r.auth is routes_mod.AuthRequirement.FULL, f"{path}: expected FULL auth"

    def test_post_routes_each_have_full_auth_gate(self):
        _webui, routes_mod = self._webui()
        for path in (
            "/api/bluetooth/pair_window", "/api/bluetooth/pair", "/api/bluetooth/forget",
            "/api/bluetooth/services", "/api/bluetooth/onboard", "/api/bluetooth/buffer",
        ):
            r = self._route(routes_mod, path, "POST")
            assert r is not None, f"{path} is not registered as a POST route"
            assert r.auth is routes_mod.AuthRequirement.FULL, f"{path}: expected FULL auth"

    def test_not_in_get_commissioning_allowlist(self):
        _webui, routes_mod = self._webui()
        for path in ("/api/bluetooth/status", "/api/bluetooth/pair_window"):
            r = self._route(routes_mod, path, "GET")
            assert r is not None, f"{path} is not registered as a GET route"
            assert r.allow_unconfigured is False, f"{path}: expected allow_unconfigured=False"

    def test_not_in_post_commissioning_allowlist(self):
        _webui, routes_mod = self._webui()
        for path in (
            "/api/bluetooth/pair_window", "/api/bluetooth/pair", "/api/bluetooth/forget",
            "/api/bluetooth/services", "/api/bluetooth/onboard", "/api/bluetooth/buffer",
        ):
            r = self._route(routes_mod, path, "POST")
            assert r is not None, f"{path} is not registered as a POST route"
            assert r.allow_unconfigured is False, f"{path}: expected allow_unconfigured=False"


# ---------------------------------------------------------------------------
# Settings guard — cross-input capture_device exclusivity (generalised from
# the original Bluetooth-only double-assignment guard)
# ---------------------------------------------------------------------------

class TestDoubleAssignmentGuard:
    def test_second_input_rejected_when_first_already_bluetooth(self, tmp_path):
        from webui.browser.api_settings import send_settings_post_json
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
        from webui.browser.api_settings import send_settings_post_json
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
        from webui.browser.api_settings import send_settings_post_json
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
        from webui.browser.api_settings import send_settings_post_json
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
        from webui.browser.api_settings import send_settings_post_json
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
        from webui.browser.api_settings import send_settings_post_json
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
        from webui.browser.api_settings import send_settings_post_json
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
        from webui.browser.api_settings import send_settings_post_json
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
        from webui.browser.api_settings import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            with patch("autostream_live_config.bluetooth_installed", return_value=True):
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
        from webui.browser.api_settings import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            with patch("autostream_live_config.bluetooth_installed", return_value=True):
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
        from webui.browser.api_settings import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            with patch("webui.system.bluetooth.bluetooth_installed", return_value=False):
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
        from webui.browser.api_settings import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            with patch("webui.system.bluetooth.bluetooth_installed", return_value=True):
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
        from webui.browser.api_settings import send_settings_post_json
        state, store = _make_state(tmp_path)
        handler = _make_handler()
        try:
            with patch("webui.system.bluetooth.bluetooth_installed", return_value=True):
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
        import webui.browser.about as _about
        handler = MagicMock()
        buf = io.BytesIO()
        handler.wfile = buf
        state = MagicMock()
        with patch("webui.system.updates.get_app_version", return_value="1.2.3"), \
             patch("webui.browser.about.build_top_banner_html", return_value=("", "")), \
             patch("webui.common._config_snapshot", return_value=None), \
             patch("webui.browser.about.load_license_text", return_value=""), \
             patch("webui.browser.about.render_license_md", return_value=""):
            webui_about.send_about_page(handler, state)
        return buf.getvalue().decode("utf-8")

    def test_row_absent_when_disabled(self):
        import webui.browser.about as _about
        with patch("webui.system.services.bluetooth_installed", return_value=False):
            html = self._render()
        assert "autostream_bluetooth.service" not in html

    def test_row_present_when_enabled(self):
        import webui.browser.about as _about
        with patch("webui.system.services.bluetooth_installed", return_value=True):
            html = self._render()
        assert "data-service-unit='autostream_bluetooth.service'" in html or \
               'data-service-unit="autostream_bluetooth.service"' in html
        assert "Bluetooth Service" in html

    def test_collect_service_states_includes_row_when_enabled(self):
        import webui.browser.about as _about
        with patch("webui.system.services.bluetooth_installed", return_value=True), \
             patch("webui.system.services.subprocess.run",
                   return_value=MagicMock(stdout="", returncode=0)):
            services = webui_services._collect_service_states("owntone", {})
        units = [s["unit"] for s in services]
        assert "autostream_bluetooth.service" in units
        assert len(services) == 7

    def test_collect_service_states_excludes_row_when_disabled(self):
        import webui.browser.about as _about
        with patch("webui.system.services.bluetooth_installed", return_value=False), \
             patch("webui.system.services.subprocess.run",
                   return_value=MagicMock(stdout="", returncode=0)):
            services = webui_services._collect_service_states("owntone", {})
        units = [s["unit"] for s in services]
        assert "autostream_bluetooth.service" not in units
        assert len(services) == 6


class TestTheScanRoutesAreGone:
    def test_no_scan_or_pair_status_routes_or_handlers(self):
        import webui.routes as routes_mod
        paths = {r.path for r in routes_mod.ROUTES}
        for gone in ("/api/bluetooth/scan", "/api/bluetooth/scan_results", "/api/bluetooth/pair_status"):
            assert gone not in paths
        for name in ("send_bluetooth_scan_results_json", "send_bluetooth_pair_status_json",
                     "send_bluetooth_scan_post_json"):
            assert not hasattr(webui_system_bluetooth, name)
