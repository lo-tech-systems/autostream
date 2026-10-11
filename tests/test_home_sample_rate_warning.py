"""Home page "Sample Rate Mismatch" banner and the input card's rate text.

While an input delivers a different standard rate than it was opened at and
Dynamic Rate Matching is off, the Home page shows a fixed banner that links
to that input's card on the Setup page.  The status reply carries the banner
text as a flat key; the input the banner links to is worked out by the page
from the per-input levels.  The input card's rate line (shown only with the
"Display Input Detail" preference on) says Locked, Acquiring or Mismatch.
"""
from __future__ import annotations

import json
import re
import sys
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_appliance_models as models
from autostream_core import SAMPLE_RATE_MISMATCH_BANNER_TEXT
from autostream_webui_api import send_status_json
from autostream_webui_page_airplay import send_airplay_page

_BANNER = "Sample Rate Mismatch: Please enable Dynamic Rate Matching"
_BANNER_OPEN = "<a id='sample-rate-warning-banner' href='/setup#input"


def _monitors(*mismatching: int):
    """Two fake monitors; the numbered inputs report a 44.1 kHz mismatch."""
    return patch("autostream_core.all_monitors", [
        SimpleNamespace(input_index=n, rate_mismatch_hz=44100 if n in mismatching else 0)
        for n in (2, 1)
    ])


# ---------------------------------------------------------------------------
# Banner text
# ---------------------------------------------------------------------------

class TestBannerText:
    def test_the_text_is_the_agreed_string(self):
        assert SAMPLE_RATE_MISMATCH_BANNER_TEXT == _BANNER


# ---------------------------------------------------------------------------
# Status payload and home state
# ---------------------------------------------------------------------------

def _status_body(state=None) -> dict:
    sent: dict = {}
    h = MagicMock()
    h.send_response.side_effect = lambda code: sent.__setitem__("code", code)
    h.wfile.write.side_effect = lambda data: sent.__setitem__("body", json.loads(data))
    with patch("autostream_webui_api.get_playback_snapshot") as gp:
        gp.return_value.to_public_dict.return_value = {}
        gp.return_value.stylus_banner_text = ""
        gp.return_value.belt_banner_text = ""
        gp.return_value.bearing_banner_text = ""
        send_status_json(h, state)
    return sent["body"]


class TestStatusPayload:
    def test_status_carries_the_banner_text_for_a_mismatch(self):
        with _monitors(1):
            assert _status_body()["sample_rate_banner_text"] == _BANNER

    def test_status_banner_text_empty_without_a_mismatch(self):
        with _monitors():
            assert _status_body()["sample_rate_banner_text"] == ""

    def test_status_banner_text_empty_with_no_monitors(self):
        with patch("autostream_core.all_monitors", []):
            assert _status_body()["sample_rate_banner_text"] == ""

    def test_both_inputs_mismatched_give_the_one_string(self):
        with _monitors(1, 2):
            assert _status_body()["sample_rate_banner_text"] == _BANNER

    def test_status_takes_the_text_from_the_home_state_warnings(self):
        home = {"input_levels": [], "playback": {}, "track_identification": {},
                "warnings": {"sample_rate": _BANNER}}
        with patch("autostream_webui_api.build_home_state", return_value=home):
            assert _status_body(MagicMock())["sample_rate_banner_text"] == _BANNER

    def test_status_text_is_empty_when_the_home_state_has_no_entry(self):
        home = {"input_levels": [], "playback": {}, "track_identification": {},
                "warnings": {}}
        with patch("autostream_webui_api.build_home_state", return_value=home):
            assert _status_body(MagicMock())["sample_rate_banner_text"] == ""

    def test_status_keeps_the_other_banner_keys(self):
        with _monitors(1):
            body = _status_body()
        for key in ("playback_banner_text", "belt_banner_text", "bearing_banner_text",
                    "dial_update_banner_text"):
            assert key in body


def _home_state(tmp_path) -> dict:
    cfg = tmp_path / "autostream.json"
    cfg.write_text("{}", encoding="utf-8")
    playback = MagicMock()
    playback.to_public_dict.return_value = {}
    playback.stylus_banner_text = ""
    playback.belt_banner_text = ""
    playback.bearing_banner_text = ""
    with ExitStack() as stack:
        for p in (
            patch("autostream_appliance_models.locked_load_config", return_value={}),
            patch("autostream_appliance_models.parse_config", return_value=MagicMock()),
            patch("autostream_appliance_models.get_setting",
                  return_value=MagicMock(ok=True, value="2250")),
            patch("autostream_appliance_models.list_outputs",
                  return_value=MagicMock(ok=True, outputs=[])),
            patch("autostream_appliance_models.get_monitor_levels_dbfs", return_value=[]),
            patch("autostream_appliance_models.get_playback_snapshot", return_value=playback),
            patch("autostream_appliance_models.get_appliance_id", return_value="aabbccdd1122"),
            patch("autostream_appliance_models.get_system_hostname", return_value="host"),
            patch("autostream_appliance_models.get_app_version", return_value="2.0.0"),
        ):
            stack.enter_context(p)
        return models.build_home_state(str(cfg))


class TestHomeState:
    def test_warning_present_for_a_mismatch(self, tmp_path):
        with _monitors(2):
            assert _home_state(tmp_path)["warnings"]["sample_rate"] == _BANNER

    def test_warning_empty_without_a_mismatch(self, tmp_path):
        with _monitors():
            assert _home_state(tmp_path)["warnings"]["sample_rate"] == ""


# ---------------------------------------------------------------------------
# Home page HTML
# ---------------------------------------------------------------------------

def _render_home(levels=None, show_input_detail=False) -> str:
    handler = MagicMock()
    chunks: list = []
    handler.wfile.write = lambda d: chunks.append(d)
    handler._csrf_token = "t"
    handler._pending_set_cookies = []
    auth = MagicMock()
    auth.get_csrf_token.return_value = "t"
    state = MagicMock()
    state.config_path = "dummy.ini"

    parsed = MagicMock()
    parsed.owntone.base_url = "http://localhost:3689"
    parsed.owntone.output_name = "autostream"
    parsed.owntone.volume_percent = 20
    parsed.webui.show_master_volume = False
    parsed.webui.show_input_detail = show_input_detail
    parsed.webui.show_hostname_on_home = False
    parsed.webui.control_other_appliances = False
    parsed.webui.hidden_outputs = []
    parsed.webui.dark_mode = False
    parsed.track_identification = MagicMock(enabled=False)
    snap = MagicMock()
    snap.inputs = {}
    snap.stylus_banner_text = ""
    snap.belt_banner_text = ""
    snap.bearing_banner_text = ""
    snap.has_warning = False
    snap.to_public_dict.return_value = {}

    from track_id.models import disabled_snapshot
    with ExitStack() as stack:
        for p in (
            patch("autostream_webui_page_airplay._config_snapshot", return_value=parsed),
            patch("autostream_webui_page_airplay.get_appliance_id", return_value="0" * 20),
            patch("autostream_webui_page_airplay.get_all_appliances", return_value=[]),
            patch("autostream_webui_page_airplay.get_system_hostname", return_value="autostream"),
            patch("autostream_webui_page_airplay.get_monitor_levels_dbfs",
                  return_value=list(levels or [])),
            patch("autostream_webui_page_airplay.get_playback_snapshot", return_value=snap),
            patch("autostream_webui_page_airplay._dial_update_banner_text", return_value=""),
            patch("autostream_webui_page_airplay.list_outputs",
                  return_value=MagicMock(ok=False, outputs=[])),
            patch("autostream_webui_page_airplay.get_setting",
                  return_value=MagicMock(ok=True, value="2250")),
            patch("autostream_core.get_active_track_identification_snapshot",
                  return_value=disabled_snapshot()),
            patch("autostream_webui_page_airplay.build_top_banner_html", return_value=("", "")),
        ):
            stack.enter_context(p)
        send_airplay_page(handler, state, auth)
    return b"".join(chunks).decode("utf-8", errors="replace")


class TestHomePage:
    def test_banner_visible_with_the_fixed_text_and_links_to_input_1(self):
        with _monitors(1):
            page = _render_home()
        assert _BANNER_OPEN + "1' style='display:block;" in page
        assert f"{_BANNER}</a>" in page

    def test_banner_links_to_input_2_when_only_input_2_mismatches(self):
        with _monitors(2):
            page = _render_home()
        assert _BANNER_OPEN + "2' style='display:block;" in page

    def test_banner_links_to_the_lowest_input_when_both_mismatch(self):
        with _monitors(1, 2):
            page = _render_home()
        assert _BANNER_OPEN + "1' style='display:block;" in page
        assert page.count(f"{_BANNER}</a>") == 1

    def test_banner_hidden_without_a_mismatch(self):
        with _monitors():
            page = _render_home()
        assert _BANNER_OPEN + "1' style='display:none;" in page
        assert f"{_BANNER}</a>" not in page

    def test_banner_follows_the_dial_update_banner_in_the_row(self):
        with _monitors(1):
            page = _render_home()
        assert page.index("id='dial-update-warning-banner'") < page.index(
            "id='sample-rate-warning-banner'"
        )

    def test_poll_script_refreshes_the_banner_and_its_link(self):
        with _monitors():
            page = _render_home()
        assert "'dial_update', 'sample_rate'" in page
        assert "item.replace('_', '-') + '-warning-banner'" in page
        assert "item === 'sample_rate'" in page
        assert "'/setup#input' +" in page
        assert "rate_mismatch_hz" in page


# ---------------------------------------------------------------------------
# Setup page deep link
# ---------------------------------------------------------------------------

class TestDeepLink:
    def _src(self) -> str:
        return (REPO_ROOT / "core" / "autostream_webui_page_setup.py").read_text(encoding="utf-8")

    def test_setup_page_script_opens_the_input_panels_for_the_hash(self):
        src = self._src()
        assert "location.hash === '#input1'" in src
        assert "openPanel('input1')" in src
        assert "location.hash === '#input2'" in src
        assert "openPanel('input2')" in src

    def test_input_panel_targets_exist(self):
        src = self._src()
        assert '_register_card("input1"' in src
        assert '_register_card("input2"' in src


# ---------------------------------------------------------------------------
# Input card rate text
# ---------------------------------------------------------------------------

def _signal(page: str) -> str:
    match = re.search(r'<div class="now-playing-signal" id="np-signal">(.*?)</div>', page)
    assert match, "np-signal element missing"
    return match.group(1)


def _level(**rate) -> dict:
    level = {"index": 1, "label": "Input 1", "dbfs": -30.0, "detected_hz": 0.0,
             "is_above_threshold": True}
    level.update(rate)
    return level


class TestSignalText:
    def test_locked_shows_the_detected_rate(self):
        page = _render_home([_level(rate_lock="locked", detected_hz=44100.0,
                                    detected_khz="44.1 kHz")], show_input_detail=True)
        assert _signal(page) == "Locked · 44.1 kHz"

    def test_whole_rates_have_no_decimal(self):
        page = _render_home([_level(rate_lock="locked", detected_hz=48000.0,
                                    detected_khz="48 kHz")], show_input_detail=True)
        assert _signal(page) == "Locked · 48 kHz"

    def test_acquiring(self):
        page = _render_home([_level(rate_lock="acquiring")], show_input_detail=True)
        assert _signal(page) == "Acquiring"

    def test_a_stopped_input_shows_no_rate_line(self):
        page = _render_home([_level(rate_lock="")], show_input_detail=True)
        assert _signal(page) == ""

    def test_a_stopped_input_shows_no_rate_line_even_with_a_stale_rate(self):
        page = _render_home([_level(rate_lock="", detected_hz=44100.0,
                                    detected_khz="44.1 kHz")], show_input_detail=True)
        assert _signal(page) == ""

    def test_mismatch_shows_the_delivered_rate(self):
        page = _render_home([_level(rate_lock="mismatch", detected_hz=48000.0,
                                    detected_khz="48 kHz", rate_mismatch_hz=44100,
                                    rate_mismatch_khz="44.1 kHz")], show_input_detail=True)
        assert _signal(page) == "Mismatch · 44.1 kHz"

    def test_an_older_monitor_keeps_the_locked_line(self):
        page = _render_home([_level(detected_hz=48000.0, detected_khz="48 kHz")],
                            show_input_detail=True)
        assert _signal(page) == "Locked · 48 kHz"

    def test_an_older_monitor_with_no_rate_shows_nothing(self):
        page = _render_home([_level()], show_input_detail=True)
        assert _signal(page) == ""

    def test_nothing_without_input_detail(self):
        for rate in (
            {"rate_lock": "locked", "detected_khz": "48 kHz"},
            {"rate_lock": "acquiring"},
            {"rate_lock": ""},
            {"rate_lock": "mismatch", "rate_mismatch_hz": 44100,
             "rate_mismatch_khz": "44.1 kHz"},
        ):
            page = _render_home([_level(**rate)], show_input_detail=False)
            assert _signal(page) == ""

    def test_the_browser_script_follows_the_same_three_branches(self):
        page = _render_home([_level()], show_input_detail=True)
        assert "activeLevel.rate_mismatch_khz" in page
        assert "activeLevel.detected_khz" in page
        assert "activeLevel.rate_lock" in page
        assert "rateLock && detectedKhz" in page
