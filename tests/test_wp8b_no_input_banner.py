"""tests/test_wp8b_no_input_banner.py

Acceptance tests: no page carries a separate "no input configured" notice.

With no input enabled the appliance reports it as an info entry of the
warnings part, which Home shows in its strip. Tests cover:
  - Main page (/): no separate notice, whatever inputs are enabled
  - Setup page: notice is absent
  - Equaliser page (/equaliser): notice is absent
"""
from __future__ import annotations

import io
import json
import sys
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from _setup_card_test_helpers import setup_page_mocks

from fake_store import fake_levels, fake_playback, fake_track, fake_outputs_result

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)


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


# ---------------------------------------------------------------------------
# Main page (/) — no separate notice.
# ---------------------------------------------------------------------------

def _make_playback_snapshot():
    snap = MagicMock()
    snap.inputs = {}
    snap.stylus_banner_text = ""
    snap.belt_banner_text = ""
    snap.bearing_banner_text = ""
    snap.has_warning = False
    snap.to_public_dict.return_value = {}
    return snap


class TestMainPageBanner:
    def _render(self, tmp_path: Path, *, audio1_enabled: bool, audio2_enabled: bool) -> str:
        from webui.browser.home import send_airplay_page
        from autostream_settings import SettingsStore
        from webui.session_state import WebUIState
        from autostream_players import ListOutputsResult
        from track_id.models import disabled_snapshot

        cfg = _minimal_cfg(tmp_path, audio1_enabled=audio1_enabled, audio2_enabled=audio2_enabled)
        store = SettingsStore(str(cfg), _save_interval_seconds=9999)
        state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)

        handler = MagicMock()
        handler.wfile = io.BytesIO()
        handler._csrf_token = "tok"
        handler._pending_set_cookies = []

        auth = MagicMock()
        auth.get_csrf_token.return_value = "tok"

        buf_result = MagicMock(ok=True, value="2250")

        patches = [
            patch("webui.browser.home.build_top_banner_html", return_value=("", "")),
            patch("autostream_rpi.get_appliance_id", return_value="local-id"),
            patch("webui.browser.home.get_all_appliances", return_value=[]),
            patch("webui.browser.home.get_system_hostname", return_value="autostream"),
            fake_levels([]),
            fake_playback(_make_playback_snapshot()),
            fake_outputs_result(ListOutputsResult(ok=False, error="unreachable")),
            patch("webui.browser.home.get_setting", return_value=buf_result),
            fake_track(disabled_snapshot()),
        ]

        with ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            send_airplay_page(handler, state, auth)

        store.close(save=False)
        return handler.wfile.getvalue().decode("utf-8", errors="replace")

    @pytest.mark.parametrize("audio1,audio2", [(True, False), (False, False), (False, True)])
    def test_no_separate_notice_whatever_inputs_are_enabled(self, tmp_path, audio1, audio2):
        html = self._render(tmp_path, audio1_enabled=audio1, audio2_enabled=audio2)
        assert "No input device configured" not in html


# ---------------------------------------------------------------------------
# Equaliser page (/equaliser) — notice removed; it now lives only on the
# main page. /equaliser is a distinct route (not the '/' home page), so this
# instance was dropped rather than kept.
# ---------------------------------------------------------------------------

class TestEqualiserPageBannerAbsent:
    def _render(self, tmp_path: Path, *, audio1_enabled: bool, audio2_enabled: bool) -> str:
        from webui.browser.equaliser import send_equaliser_page
        from autostream_settings import SettingsStore
        from webui.session_state import WebUIState

        cfg = _minimal_cfg(tmp_path, audio1_enabled=audio1_enabled, audio2_enabled=audio2_enabled)
        store = SettingsStore(str(cfg), _save_interval_seconds=9999)
        state = WebUIState(str(cfg), str(tmp_path / "state.json"), settings=store)

        handler = MagicMock()
        handler.wfile = io.BytesIO()
        handler._csrf_token = "tok"

        with patch("webui.browser.equaliser.build_top_banner_html", return_value=("", "")), \
             patch("autostream_rpi.get_appliance_id", return_value="local-id"), \
             patch("webui.browser.equaliser.get_all_appliances", return_value=[]):
            send_equaliser_page(handler, state)

        store.close(save=False)
        return handler.wfile.getvalue().decode("utf-8", errors="replace")

    def test_banner_absent_when_no_input_enabled(self, tmp_path):
        html = self._render(tmp_path, audio1_enabled=False, audio2_enabled=False)
        assert "No input device configured" not in html

    def test_banner_absent_when_input1_enabled(self, tmp_path):
        html = self._render(tmp_path, audio1_enabled=True, audio2_enabled=False)
        assert "No input device configured" not in html


# ---------------------------------------------------------------------------
# Setup page — notice removed; it now lives only on the main page.
# ---------------------------------------------------------------------------

class TestSetupPageBannerAbsent:
    def _render(self, tmp_path: Path, *, audio1_enabled: bool, audio2_enabled: bool) -> str:
        from webui.browser.setup.page import send_setup_page
        from autostream_settings import SettingsStore
        from webui.session_state import WebUIState
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

        fake_outputs_result(ListOutputsResult(ok=False, error="unreachable"))
        with setup_page_mocks():
            with patch.object(state, "get_monitor_devices", return_value=[]):
                send_setup_page(handler, state, auth)

        store.close(save=False)
        return handler.wfile.getvalue().decode("utf-8", errors="replace")

    def test_banner_absent_when_input1_enabled(self, tmp_path):
        html = self._render(tmp_path, audio1_enabled=True, audio2_enabled=False)
        assert "No input device configured" not in html

    def test_banner_absent_when_no_input_enabled(self, tmp_path):
        html = self._render(tmp_path, audio1_enabled=False, audio2_enabled=False)
        assert "No input device configured" not in html
