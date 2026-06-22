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

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

try:
    from autostream_webui_page_airplay import send_airplay_page, send_remote_home_page
    from track_id.models import (
        STATE_ANALYSING,
        STATE_ERROR,
        STATE_NOT_FOUND,
        STATE_IDENTIFIED,
        TrackIdentificationSnapshot,
        disabled_snapshot,
    )
    _HAS_IMPORTS = True
except ImportError:
    _HAS_IMPORTS = False

_skip = pytest.mark.skipif(
    not _HAS_IMPORTS, reason="autostream_webui_page_airplay import chain unavailable"
)

_LOCAL_ID = "00000000000000000000"
_REMOTE_ID = "aabbccdd1122334455aa"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_parsed(*, show_master=False, show_input_detail=False):
    parsed = MagicMock()
    parsed.owntone.base_url = "http://localhost:3689"
    parsed.owntone.output_name = "autostream"
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


def _render_airplay_page(ti_snapshot=None) -> str:
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
    playback = _make_playback_snapshot()
    list_result = MagicMock(ok=False, outputs=[])
    buf_result = MagicMock(ok=True, value="2250")

    patches = [
        patch("autostream_webui_page_airplay.locked_load_config", return_value={}),
        patch("autostream_webui_page_airplay.parse_config", return_value=parsed),
        patch("autostream_webui_page_airplay.get_appliance_id", return_value=_LOCAL_ID),
        patch("autostream_webui_page_airplay.get_all_appliances", return_value=[]),
        patch("autostream_webui_page_airplay.get_system_hostname", return_value="autostream"),
        patch("autostream_webui_page_airplay.get_monitor_levels_dbfs", return_value=[]),
        patch("autostream_webui_page_airplay.get_playback_snapshot", return_value=playback),
        patch("autostream_webui_page_airplay.list_outputs", return_value=list_result),
        patch("autostream_webui_page_airplay.get_setting", return_value=buf_result),
        patch("autostream_core.get_active_track_identification_snapshot",
              return_value=ti_snapshot),
        patch("autostream_webui_page_airplay.build_top_banner_html",
              return_value=("", "")),
    ]

    from contextlib import ExitStack
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        send_airplay_page(handler, state, auth)

    return b"".join(chunks).decode("utf-8", errors="replace")


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

    patches = [
        patch("autostream_webui_page_airplay.locked_load_config", return_value={}),
        patch("autostream_webui_page_airplay.parse_config", return_value=parsed),
        patch("autostream_webui_page_airplay.get_appliance_id", return_value=_LOCAL_ID),
        patch("autostream_webui_page_airplay.get_all_appliances", return_value=[]),
        patch("autostream_webui_page_airplay.get_system_hostname", return_value="autostream"),
    ]

    from contextlib import ExitStack
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        send_remote_home_page(handler, state, _REMOTE_ID)

    return b"".join(chunks).decode("utf-8", errors="replace")


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

@_skip
class TestTiDisabledRender:
    def test_np_name_shows_input_label(self):
        html = _render_airplay_page(ti_snapshot=disabled_snapshot())
        # No input playing → np-ready, body hidden, but elements still in DOM.
        assert 'id="np-name"' in html

    def test_icon_uses_svg_key(self):
        html = _render_airplay_page(ti_snapshot=disabled_snapshot())
        assert 'data-np-icon-key="svg:false"' in html

    def test_no_np_icon_art_class_on_icon_element(self):
        html = _render_airplay_page(ti_snapshot=disabled_snapshot())
        # The CSS contains "np-icon-art" as a class name, but the icon element
        # must not carry that class when TI is disabled.
        assert 'class="now-playing-icon np-icon-art"' not in html


# ---------------------------------------------------------------------------
# TI enabled + identified — Now Playing card shows artwork and track info
# ---------------------------------------------------------------------------

@_skip
class TestTiIdentifiedRender:
    def _snap(self, *, title="Blue in Green", artist="Miles Davis",
               artwork_url="https://example.com/art.jpg"):
        return TrackIdentificationSnapshot(
            enabled=True,
            state=STATE_IDENTIFIED,
            status_text="Track identified",
            title=title,
            artist=artist,
            album="Kind of Blue",
            artwork_url=artwork_url,
        )

    def test_np_name_shows_track_title(self):
        html = _render_airplay_page(ti_snapshot=self._snap())
        assert "Blue in Green" in html

    def test_np_signal_shows_artist(self):
        html = _render_airplay_page(ti_snapshot=self._snap())
        assert "Miles Davis" in html

    def test_np_icon_shows_art_img(self):
        html = _render_airplay_page(ti_snapshot=self._snap())
        assert '<img src="https://example.com/art.jpg"' in html

    def test_np_icon_key_is_art(self):
        html = _render_airplay_page(ti_snapshot=self._snap())
        assert 'data-np-icon-key="art:https://example.com/art.jpg"' in html

    def test_np_icon_art_class_applied(self):
        html = _render_airplay_page(ti_snapshot=self._snap())
        assert 'np-icon-art' in html

    def test_album_not_shown(self):
        html = _render_airplay_page(ti_snapshot=self._snap())
        assert "Kind of Blue" not in html

    def test_empty_artwork_url_falls_back_to_svg(self):
        html = _render_airplay_page(ti_snapshot=self._snap(artwork_url=""))
        assert 'data-np-icon-key="art:"' in html
        # Icon element must not carry the art class when there is no artwork.
        assert 'class="now-playing-icon np-icon-art"' not in html

    def test_artwork_url_encoded_safely_in_attribute(self):
        url = "https://example.com/art?foo=bar&baz=qux"
        html = _render_airplay_page(ti_snapshot=self._snap(artwork_url=url))
        # src attribute must have & HTML-escaped (once).
        assert 'src="https://example.com/art?foo=bar&amp;baz=qux"' in html
        # data-np-icon-key must also encode & once (decoded by browser back to raw URL).
        assert 'data-np-icon-key="art:https://example.com/art?foo=bar&amp;baz=qux"' in html

    def test_title_html_escaped(self):
        html = _render_airplay_page(ti_snapshot=self._snap(title='<em>Blue</em>'))
        # The np-name div must contain the escaped title, not raw tags.
        assert '<em>Blue</em>' not in html
        assert '&lt;em&gt;Blue&lt;/em&gt;' in html

    def test_artist_html_escaped(self):
        html = _render_airplay_page(ti_snapshot=self._snap(artist='<em>Davis</em>'))
        assert '<em>Davis</em>' not in html
        assert '&lt;em&gt;Davis&lt;/em&gt;' in html


# ---------------------------------------------------------------------------
# TI enabled + in-progress states — Now Playing card shows input label + suffix
# ---------------------------------------------------------------------------

@_skip
class TestTiInProgressRender:
    def _snap(self, state, status_text=""):
        return TrackIdentificationSnapshot(
            enabled=True, state=state, status_text=status_text,
        )

    def test_analysing_shows_identifying_text(self):
        html = _render_airplay_page(ti_snapshot=self._snap(STATE_ANALYSING))
        assert "Identifying Track" in html

    def test_not_found_shows_unknown_track(self):
        html = _render_airplay_page(ti_snapshot=self._snap(STATE_NOT_FOUND))
        assert "Unknown track" in html

    def test_error_shows_unavailable_text(self):
        html = _render_airplay_page(ti_snapshot=self._snap(STATE_ERROR))
        assert "Track ID function not available" in html

    def test_in_progress_uses_svg_key(self):
        html = _render_airplay_page(ti_snapshot=self._snap(STATE_ANALYSING))
        assert 'data-np-icon-key="svg:false"' in html

    def test_in_progress_no_art_class_on_icon_element(self):
        html = _render_airplay_page(ti_snapshot=self._snap(STATE_ANALYSING))
        assert 'class="now-playing-icon np-icon-art"' not in html


# ---------------------------------------------------------------------------
# JS contains track-ID-aware logic (not the old updateTrackIdCard)
# ---------------------------------------------------------------------------

@_skip
class TestJsContent:
    def test_no_update_track_id_card_function(self):
        html = _render_airplay_page()
        assert "updateTrackIdCard" not in html

    def test_has_np_icon_key_logic(self):
        html = _render_airplay_page()
        assert "data-np-icon-key" in html

    def test_has_ti_state_check(self):
        html = _render_airplay_page()
        assert "tiState" in html

    def test_np_art_css_present(self):
        html = _render_airplay_page()
        assert "np-icon-art" in html

    def test_remote_no_update_track_id_card_function(self):
        html = _render_remote_home()
        assert "updateTrackIdCard" not in html

    def test_remote_has_np_icon_key_logic(self):
        html = _render_remote_home()
        assert "data-np-icon-key" in html

    def test_remote_np_art_css_present(self):
        html = _render_remote_home()
        assert "np-icon-art" in html
