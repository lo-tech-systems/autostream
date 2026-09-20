"""Tests for the SD card health monitoring web-route/JSON-handler surface:

  - autostream_webui_api.send_sdcard_health_* handlers (get/enable/disable)

Modelled on tests/test_bluetooth_api.py's handler-driving helpers (this
feature is the same "toggle backed by a privileged autostream_admin verb"
shape as the onboard Bluetooth toggle, so its API tests fit that file's
pattern better than tests/test_wp4b_settings_api.py, which drives
SettingsStore-backed fields rather than admin-verb-backed actions).
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

from autostream_webui_api import (
    send_sdcard_health_disable_post_json,
    send_sdcard_health_enable_post_json,
    send_sdcard_health_get_json,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_handler():
    h = MagicMock()
    h.wfile = io.BytesIO()
    return h


def _response(handler):
    code = handler.send_response.call_args[0][0]
    body = json.loads(handler.wfile.getvalue())
    return code, body


_SAMPLE_STATE = {
    "tool_present": True,
    "timer_enabled": False,
    "method": "auto",
    "check": "none",
    "serial": "",
    "at": "",
    "reason": "",
    "card": {"manfid": 0x03, "oemid": None, "name": "TestCard", "serial": "abc", "likely_supported": True},
    "health_percent": None,
    "last_sampled_at": None,
}


# ---------------------------------------------------------------------------
# GET /api/sdcard-health
# ---------------------------------------------------------------------------

class TestSdcardHealthGetJson:
    def test_returns_state_as_is(self):
        handler = _make_handler()
        with patch("autostream_webui_api.sdcard_health_state", return_value=_SAMPLE_STATE):
            send_sdcard_health_get_json(handler)
        code, body = _response(handler)
        assert code == 200
        assert body == _SAMPLE_STATE


# ---------------------------------------------------------------------------
# POST /api/sdcard-health/enable
# ---------------------------------------------------------------------------

class TestSdcardHealthEnablePost:
    def test_enables_on_passing_check(self):
        handler = _make_handler()
        with patch("autostream_webui_api.sdcard_health_check", return_value=(True, 0, {"success": True})) as m_check, \
             patch("autostream_webui_api.sdcard_health_enable", return_value=(True, 0, {"output": "enabled"})) as m_enable, \
             patch("autostream_webui_api.sdcard_health_state", return_value=_SAMPLE_STATE):
            send_sdcard_health_enable_post_json(handler, {"method": "auto"})
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is True
        assert body["state"] == _SAMPLE_STATE
        m_check.assert_called_once_with("auto")
        m_enable.assert_called_once_with("auto")

    def test_unsupported_check_refuses_with_409_and_reason(self):
        handler = _make_handler()
        with patch("autostream_webui_api.sdcard_health_check", return_value=(False, 3, {"reason": "not supported"})), \
             patch("autostream_webui_api.sdcard_health_enable") as m_enable:
            send_sdcard_health_enable_post_json(handler, {"method": "sandisk"})
        code, body = _response(handler)
        assert code == 409
        assert body["error"] == "unsupported"
        assert body["reason"] == "not supported"
        m_enable.assert_not_called()

    def test_hung_check_refuses_with_409(self):
        handler = _make_handler()
        with patch("autostream_webui_api.sdcard_health_check", return_value=(False, 4, {})), \
             patch("autostream_webui_api.sdcard_health_enable") as m_enable:
            send_sdcard_health_enable_post_json(handler, {"method": "auto"})
        code, body = _response(handler)
        assert code == 409
        assert body["error"] == "hung"
        m_enable.assert_not_called()

    def test_tool_missing_reports_503(self):
        handler = _make_handler()
        with patch("autostream_webui_api.sdcard_health_check", return_value=(False, 2, {})), \
             patch("autostream_webui_api.sdcard_health_enable") as m_enable:
            send_sdcard_health_enable_post_json(handler, {"method": "auto"})
        code, body = _response(handler)
        # 503 is tunnelled through the NGINX offline-page boundary: transport
        # is 200 with the semantic code carried in error_status.
        assert code == 200
        assert body["ok"] is False
        assert body["error"] == "tool_missing"
        assert body["error_status"] == 503
        m_enable.assert_not_called()

    def test_other_check_failure_is_500(self):
        handler = _make_handler()
        with patch("autostream_webui_api.sdcard_health_check", return_value=(False, 1, {"output": "boom"})), \
             patch("autostream_webui_api.sdcard_health_enable") as m_enable:
            send_sdcard_health_enable_post_json(handler, {"method": "auto"})
        code, body = _response(handler)
        assert code == 500
        assert body["ok"] is False
        m_enable.assert_not_called()

    def test_enable_failure_after_passing_check_is_500(self):
        handler = _make_handler()
        with patch("autostream_webui_api.sdcard_health_check", return_value=(True, 0, {})), \
             patch("autostream_webui_api.sdcard_health_enable", return_value=(False, 1, {"output": "boom"})):
            send_sdcard_health_enable_post_json(handler, {"method": "auto"})
        code, body = _response(handler)
        assert code == 500
        assert body["ok"] is False

    @pytest.mark.parametrize("bad_method", ["bogus", "", 123, None, True])
    def test_invalid_method_rejected(self, bad_method):
        handler = _make_handler()
        with patch("autostream_webui_api.sdcard_health_check") as m_check:
            send_sdcard_health_enable_post_json(handler, {"method": bad_method})
        code, _ = _response(handler)
        assert code == 400
        m_check.assert_not_called()

    def test_extra_keys_rejected(self):
        handler = _make_handler()
        with patch("autostream_webui_api.sdcard_health_check") as m_check:
            send_sdcard_health_enable_post_json(handler, {"method": "auto", "extra": 1})
        code, _ = _response(handler)
        assert code == 400
        m_check.assert_not_called()

    def test_non_dict_body_rejected(self):
        handler = _make_handler()
        send_sdcard_health_enable_post_json(handler, ["not", "a", "dict"])
        code, _ = _response(handler)
        assert code == 400


# ---------------------------------------------------------------------------
# POST /api/sdcard-health/disable
# ---------------------------------------------------------------------------

class TestSdcardHealthDisablePost:
    def test_disables_successfully(self):
        handler = _make_handler()
        with patch("autostream_webui_api.sdcard_health_disable", return_value=(True, 0, {"output": "disabled"})) as m_disable, \
             patch("autostream_webui_api.sdcard_health_state", return_value=_SAMPLE_STATE):
            send_sdcard_health_disable_post_json(handler, {})
        code, body = _response(handler)
        assert code == 200
        assert body["ok"] is True
        assert body["state"] == _SAMPLE_STATE
        m_disable.assert_called_once_with()

    def test_admin_failure_is_500(self):
        handler = _make_handler()
        with patch("autostream_webui_api.sdcard_health_disable", return_value=(False, 1, {"output": "boom"})):
            send_sdcard_health_disable_post_json(handler, {})
        code, body = _response(handler)
        assert code == 500
        assert body["ok"] is False

    def test_extra_keys_rejected(self):
        handler = _make_handler()
        with patch("autostream_webui_api.sdcard_health_disable") as m_disable:
            send_sdcard_health_disable_post_json(handler, {"extra": 1})
        code, _ = _response(handler)
        assert code == 400
        m_disable.assert_not_called()

    def test_non_dict_body_rejected(self):
        handler = _make_handler()
        send_sdcard_health_disable_post_json(handler, None)
        code, _ = _response(handler)
        assert code == 400
