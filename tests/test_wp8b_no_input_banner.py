"""tests/test_wp8b_no_input_banner.py

WP8B acceptance tests: post-setup "no input configured" notice.

Tests cover:
  - no_input_configured_notice_html(): the shared helper's on/off conditions
  - Home (/equaliser) page: notice renders only when neither input is enabled
  - Setup page: notice renders only when neither input is enabled
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)


# ---------------------------------------------------------------------------
# Unit tests — no_input_configured_notice_html()
# ---------------------------------------------------------------------------

class TestNoInputConfiguredNoticeHtml:
    def _snap(self, audio1_enabled: bool, audio2_enabled: bool):
        return SimpleNamespace(audio1_enabled=audio1_enabled, audio2_enabled=audio2_enabled)

    def test_none_snapshot_yields_empty(self):
        from autostream_webui_common import no_input_configured_notice_html
        assert no_input_configured_notice_html(None) == ""

    def test_both_enabled_yields_empty(self):
        from autostream_webui_common import no_input_configured_notice_html
        assert no_input_configured_notice_html(self._snap(True, True)) == ""

    def test_only_audio1_enabled_yields_empty(self):
        from autostream_webui_common import no_input_configured_notice_html
        assert no_input_configured_notice_html(self._snap(True, False)) == ""

    def test_only_audio2_enabled_yields_empty(self):
        from autostream_webui_common import no_input_configured_notice_html
        assert no_input_configured_notice_html(self._snap(False, True)) == ""

    def test_neither_enabled_yields_notice(self):
        from autostream_webui_common import no_input_configured_notice_html
        html = no_input_configured_notice_html(self._snap(False, False))
        assert "No input device configured" in html
        assert "/setup" in html
        assert "Bluetooth" in html


# ---------------------------------------------------------------------------
# Home page (/equaliser) — notice shown only when no input enabled
# ---------------------------------------------------------------------------

def _minimal_cfg(tmp_path: Path, *, audio1_enabled: bool = True, audio2_enabled: bool = False) -> Path:
    cfg = tmp_path / "autostream.json"
    cfg.write_text(json.dumps({
        "general": {"log_level": "info", "silence_seconds": 30},
        "owntone": {
            "base_url": "http://localhost:3689",
            "output_name": "Test Speaker",
            "volume_percent": 50,
        },
        "audio1": {
            "capture_device": "hw:1,0" if audio1_enabled else "",
            "enabled": audio1_enabled,
        },
        "audio2": {
            "capture_device": "hw:2,0" if audio2_enabled else "",
            "enabled": audio2_enabled,
        },
        "webui": {
            "dark_mode": False,
            "show_master_volume": True,
            "show_input_detail": False,
            "show_hostname_on_home": False,
            "control_other_appliances": False,
            "output_usage_poll_interval_seconds": 3,
        },
        "updates": {"auto_update": False, "update_channel": "stable"},
    }), encoding="utf-8")
    return cfg


class TestHomePageBanner:
    def _render(self, tmp_path: Path, *, audio1_enabled: bool, audio2_enabled: bool) -> str:
        from autostream_webui_page_equaliser import send_equaliser_page
        from autostream_settings import SettingsStore
        from autostream_webui_state import WebUIState

        cfg = _minimal_cfg(tmp_path, audio1_enabled=audio1_enabled, audio2_enabled=audio2_enabled)
        store = SettingsStore(str(cfg), _save_interval_seconds=9999)
        state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)

        handler = MagicMock()
        handler.wfile = io.BytesIO()
        handler._csrf_token = "tok"

        with patch("autostream_webui_page_equaliser.build_top_banner_html", return_value=("", "")), \
             patch("autostream_webui_page_equaliser.get_appliance_id", return_value="local-id"), \
             patch("autostream_webui_page_equaliser.get_all_appliances", return_value=[]):
            send_equaliser_page(handler, state)

        store.close(save=False)
        return handler.wfile.getvalue().decode("utf-8", errors="replace")

    def test_banner_absent_when_input1_enabled(self, tmp_path):
        html = self._render(tmp_path, audio1_enabled=True, audio2_enabled=False)
        assert "No input device configured" not in html

    def test_banner_present_when_no_input_enabled(self, tmp_path):
        html = self._render(tmp_path, audio1_enabled=False, audio2_enabled=False)
        assert "No input device configured" in html

    def test_banner_absent_when_only_input2_enabled(self, tmp_path):
        html = self._render(tmp_path, audio1_enabled=False, audio2_enabled=True)
        assert "No input device configured" not in html


# ---------------------------------------------------------------------------
# Setup page — notice shown only when no input enabled
# ---------------------------------------------------------------------------

class TestSetupPageBanner:
    def _render(self, tmp_path: Path, *, audio1_enabled: bool, audio2_enabled: bool) -> str:
        from autostream_webui_page_setup import send_setup_page
        from autostream_settings import SettingsStore
        from autostream_webui_state import WebUIState
        from autostream_players import ListOutputsResult

        cfg = _minimal_cfg(tmp_path, audio1_enabled=audio1_enabled, audio2_enabled=audio2_enabled)
        store = SettingsStore(str(cfg), _save_interval_seconds=9999)
        state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)

        handler = MagicMock()
        handler.wfile = io.BytesIO()
        auth = MagicMock()
        auth.ensure_session.return_value = "test-csrf"
        auth.get_csrf_token.return_value = "test-csrf"
        auth.get_boot_pin_value.return_value = "1234"

        with patch.multiple(
            "autostream_webui_page_setup",
            get_system_hostname=MagicMock(return_value="autostream"),
            list_outputs=MagicMock(return_value=ListOutputsResult(ok=False, error="unreachable")),
            get_ap_ssid=MagicMock(return_value="autostream_AP"),
            get_app_version=MagicMock(return_value="1.0.0"),
            _get_dial_sightings=MagicMock(return_value=[]),
            parse_dial_entries=MagicMock(return_value=[]),
            suggested_silence_threshold_dbfs=MagicMock(return_value=-50.0),
            build_top_banner_html=MagicMock(return_value=("", "")),
            _set_flash_cookie=MagicMock(),
        ):
            with patch.object(state, "get_monitor_devices", return_value=[]):
                send_setup_page(handler, state, auth, flash_msg="")

        store.close(save=False)
        return handler.wfile.getvalue().decode("utf-8", errors="replace")

    def test_banner_absent_when_input1_enabled(self, tmp_path):
        html = self._render(tmp_path, audio1_enabled=True, audio2_enabled=False)
        assert "No input device configured" not in html

    def test_banner_present_when_no_input_enabled(self, tmp_path):
        html = self._render(tmp_path, audio1_enabled=False, audio2_enabled=False)
        assert "No input device configured" in html
