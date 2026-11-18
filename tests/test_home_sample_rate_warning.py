"""Home page "Sample Rate Mismatch" banner and the input card's rate text.

While an input delivers a different standard rate than it was opened at and
Dynamic Rate Matching is off, the Home page shows a fixed banner that links
to that input's card on the Setup page.  The status reply carries the banner
text as a flat key; the input the banner links to is worked out by the page
from the per-input levels.  The input card's rate line (shown only with the
"Display Input Detail" preference on) says Locked, Acquiring or Mismatch.
"""
from __future__ import annotations

import contextlib
import json
import re
import sys
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, patch

import _source_text

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from fake_store import FakeStore, fake_levels, fake_outputs, fake_playback, fake_playback_mock, fake_track
import webui.browser.home_model as models
from autostream_state import store
from autostream_input_status import SAMPLE_RATE_MISMATCH_BANNER_TEXT
from webui.browser.home_api import send_status_json
from webui.browser.home import send_airplay_page
import webui.browser.home_model as webui_home_model

_BANNER = "Sample Rate Mismatch: Please enable Dynamic Rate Matching"
_BANNER_OPEN = "<a id='sample-rate-warning-banner' href='/setup#input"


def _monitors(*mismatching: int):
    """Two inputs; the numbered ones report a 44.1 kHz mismatch, as the inputs
    part holds it (the banner names the lowest-numbered such input)."""
    fake = FakeStore()
    lowest = min(mismatching, default=0)
    fake.inputs(
        [fake.input_entry(n, rate_mismatch_hz=44100 if n in mismatching else 0)
         for n in (2, 1)],
        mismatch=lowest, banner=_BANNER if lowest else "")
    return contextlib.nullcontext()


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
    with fake_playback_mock() as gp:
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
        with patch("autostream_runtime.all_monitors", []):
            assert _status_body()["sample_rate_banner_text"] == ""

    def test_both_inputs_mismatched_give_the_one_string(self):
        with _monitors(1, 2):
            assert _status_body()["sample_rate_banner_text"] == _BANNER

    def test_status_with_a_state_takes_the_text_from_the_snapshot(self):
        with _monitors(1):
            assert _status_body(MagicMock())["sample_rate_banner_text"] == _BANNER

    def test_status_with_a_state_has_no_text_without_a_mismatch(self):
        with _monitors():
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
            patch("autostream_start_buffer_cache.current_ms", return_value=2250),
            fake_outputs([]),
            fake_playback(playback),
            patch("autostream_rpi.get_appliance_id", return_value="aabbccdd1122"),
            patch("webui.browser.home_model.get_system_hostname", return_value="host"),
            patch("webui.system.updates.get_app_version", return_value="2.0.0"),
        ):
            stack.enter_context(p)
        return webui_home_model.build_home_state(store().snapshot(), MagicMock())


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


# ---------------------------------------------------------------------------
# Setup page deep link
# ---------------------------------------------------------------------------

class TestDeepLink:
    def _src(self) -> str:
        return _source_text.page_source("setup")

    def test_setup_page_script_opens_the_input_panels_for_the_hash(self):
        src = self._src()
        assert "location.hash === '#input1'" in src
        assert "openPanel('input1')" in src
        assert "location.hash === '#input2'" in src
        assert "openPanel('input2')" in src

    def test_input_panel_targets_exist(self):
        src = self._src()
        assert 'register_card("input1"' in src
        assert 'register_card("input2"' in src


# ---------------------------------------------------------------------------
# Input card rate text
# ---------------------------------------------------------------------------


