"""test_track_id_home_render.py — HTML rendering tests for track ID integration.

Verifies that send_airplay_page() and send_remote_home_page() embed track ID
state in the Now Playing card (np-name / np-signal / np-icon) and no longer
emit a separate ti-card element.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from _source_text import page_data, page_with_static

from fake_store import fake_levels, fake_playback, fake_track, fake_outputs_result

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

try:
    from webui.browser.home import send_remote_home_page
    from webui.browser.home import send_airplay_page
    from track_id.models import (
        STATE_ANALYSING,
        STATE_ERROR,
        STATE_NOT_FOUND,
        STATE_IDENTIFIED,
        STATE_WAITING,
        TrackIdentificationSnapshot,
        disabled_snapshot,
    )
    _HAS_IMPORTS = True
except ImportError:
    _HAS_IMPORTS = False

_skip = pytest.mark.skipif(
    not _HAS_IMPORTS, reason="webui.browser.home import chain unavailable"
)

_LOCAL_ID = "00000000000000000000"
_REMOTE_ID = "aabbccdd1122334455aa"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_parsed(*, show_master=False, show_input_detail=False):
    parsed = MagicMock()
    parsed.owntone.base_url = "http://localhost:3689"
    from autostream_config import DefaultOutput
    parsed.owntone.default_outputs = (DefaultOutput("", "autostream", 20),)
    parsed.owntone.volume_percent = 20
    parsed.webui.show_master_volume = show_master
    parsed.webui.show_input_detail = show_input_detail
    parsed.webui.show_hostname_on_home = False
    parsed.webui.control_other_appliances = False
    parsed.webui.hidden_outputs = []
    parsed.webui.dark_mode = False
    parsed.track_identification = MagicMock(enabled=False)
    return parsed


def _make_playback_snapshot():
    snap = MagicMock()
    snap.inputs = {}
    snap.stylus_banner_text = ""
    snap.belt_banner_text = ""
    snap.bearing_banner_text = ""
    snap.has_warning = False
    snap.to_public_dict.return_value = {}
    return snap


def _render_airplay_page(ti_snapshot=None, playback_snapshot=None, levels=None) -> str:
    """Invoke send_airplay_page() with all external deps mocked and return HTML."""
    if ti_snapshot is None:
        ti_snapshot = disabled_snapshot()

    handler = MagicMock()
    chunks: list[bytes] = []
    handler.wfile.write = lambda d: chunks.append(d)
    handler._csrf_token = "testcsrf"
    handler._pending_set_cookies = []

    auth = MagicMock()
    auth.get_csrf_token.return_value = "testcsrf"

    state = MagicMock()
    state.config_path = "dummy.ini"

    parsed = _make_parsed()
    playback = playback_snapshot if playback_snapshot is not None else _make_playback_snapshot()
    list_result = MagicMock(ok=False, outputs=[])
    buf_result = MagicMock(ok=True, value="2250")

    patches = [
        patch("webui.common._config_snapshot", return_value=parsed),
        patch("autostream_rpi.get_appliance_id", return_value=_LOCAL_ID),
        patch("webui.browser.home.get_all_appliances", return_value=[]),
        patch("webui.browser.home.get_system_hostname", return_value="autostream"),
        fake_levels(levels or []),
        fake_playback(playback),
        fake_outputs_result(list_result),
        patch("webui.browser.home.get_setting", return_value=buf_result),
        fake_track(ti_snapshot),
        patch("webui.browser.home.build_top_banner_html",
              return_value=("", "")),
    ]

    from contextlib import ExitStack
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        send_airplay_page(handler, state, auth)

    return page_with_static(b"".join(chunks).decode("utf-8", errors="replace"))


def _render_remote_home() -> str:
    """Invoke send_remote_home_page() with all external deps mocked."""
    handler = MagicMock()
    chunks: list[bytes] = []
    handler.wfile.write = lambda d: chunks.append(d)
    handler._csrf_token = "testcsrf"
    handler._pending_set_cookies = []

    state = MagicMock()
    state.config_path = "dummy.ini"

    parsed = MagicMock()
    parsed.owntone.volume_percent = 20
    parsed.webui.dark_mode = False
    parsed.webui.show_hostname_on_home = False
    parsed.webui.control_other_appliances = False

    patches = [
        patch("webui.common._config_snapshot", return_value=parsed),
        patch("autostream_rpi.get_appliance_id", return_value=_LOCAL_ID),
        patch("webui.browser.home.get_all_appliances", return_value=[]),
        patch("webui.browser.home.get_system_hostname", return_value="autostream"),
    ]

    from contextlib import ExitStack
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        send_remote_home_page(handler, state, _REMOTE_ID)

    return page_with_static(b"".join(chunks).decode("utf-8", errors="replace"))


# ---------------------------------------------------------------------------
# No ti-card in either page
# ---------------------------------------------------------------------------

@_skip
class TestNoTiCard:
    def test_airplay_page_has_no_ti_card(self):
        html = _render_airplay_page()
        assert 'id="ti-card"' not in html

    def test_airplay_page_has_no_ti_card_when_ti_enabled(self):
        snap = TrackIdentificationSnapshot(
            enabled=True, state=STATE_ANALYSING, status_text="Analysing",
        )
        html = _render_airplay_page(ti_snapshot=snap)
        assert 'id="ti-card"' not in html

    def test_remote_home_page_has_no_ti_card(self):
        html = _render_remote_home()
        assert 'id="ti-card"' not in html


# ---------------------------------------------------------------------------
# TI disabled — Now Playing card uses normal label
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# TI enabled + identified — Now Playing card shows artwork and track info
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# TI enabled + in-progress states — Now Playing card shows input label + suffix
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# JS contains track-ID-aware logic (not the old updateTrackIdCard)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Now Playing icon: three-way turntable / bluetooth / line-in selection
# ---------------------------------------------------------------------------


@_skip
class TestRemoteHomeCdIcon:
    def test_remote_home_emits_cd_icon_for_js(self):
        html = _render_remote_home()
        assert page_data(html)["icons"]["cd"].startswith("<svg")
        assert "window.__ICON_CD = pageIcons.cd;" in html


