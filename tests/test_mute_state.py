"""Tests for the per-speaker mute: how the output authority holds it, the
output-change rules, the end of a session, and the WebUI's now-playing
header/level slot (the volume slider is the WebUI's only unmute path).

Covers:
1.  The authority's mute model: a mute remembers each speaker's level, a
    muted selection reads as muted, a speaker joining it comes on silent, a
    user level change ends one speaker's mute, a deselect forgets it.
2.  submit_output_change(): enable-while-muted stays silent and remembers
    the requested level; a non-user volume-only write on a muted output
    remembers instead of writing; an explicit user volume write on a muted
    output ends its mute and writes normally; disable forgets the mute.
3.  The end of a session clears every mute.
4.  The WebUI now-playing header text (not a separate control) is the only
    mute indication; the old mute button/icon and the browser POST /api/mute
    route are both gone.
5.  The now-playing level slot markup: VU meter only, no mute button, in
    both the local and remote-shell renders.
6.  The now-playing header gains " (Muted)" while playing and muted, never
    on "Ready", and never when unmuted.
"""
from __future__ import annotations

import io
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from _source_text import page_with_static, static_text

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_player_service as player_service
from fake_store import (
    FakeStore, fake_levels, fake_outputs, fake_playback,
    fake_track,
)
from autostream_players import ActionResult, OutputInfo
from autostream_state import Origin, store
from autostream_state.outputs import get_authority
import webui.browser.home_model as webui_home_model
import webui.routes as webui_routes


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _output(id_: str, volume: int, selected: bool = True):
    return OutputInfo(id=id_, name=id_, selected=selected, volume_percent=volume)


def _update_result(ok=True):
    return ActionResult(
        ok=ok, error="" if ok else "connection refused", error_code="" if ok else "request_failed")


def _parsed_config(volume_percent=20):
    parsed = SimpleNamespace()
    parsed.owntone = SimpleNamespace(base_url="http://localhost:3689", volume_percent=volume_percent)
    return parsed


def _handler():
    h = MagicMock()
    h.wfile = io.BytesIO()
    return h


def _disabled_track_id_snapshot():
    from track_id.models import disabled_snapshot
    return disabled_snapshot()


@pytest.fixture
def writes(monkeypatch):
    """The player service: every volume write is recorded as (id, kwargs) in
    order, and answered from `results` (default: ok)."""
    rec = SimpleNamespace(calls=[], results=[])

    def update_output(base_url, out_id, **kwargs):
        rec.calls.append((out_id, kwargs))
        return rec.results.pop(0) if rec.results else _update_result(True)

    monkeypatch.setattr(player_service, "update_output", update_output)
    rec.levels = lambda: [(i, kw.get("volume_percent")) for i, kw in rec.calls]
    return rec


def _arrange(*outputs):
    FakeStore().outputs(list(outputs))


def _muted(writes, *outputs):
    """Adopt *outputs* and mute the selected ones, remembering their levels."""
    _arrange(*outputs)
    get_authority().mute_all(Origin.USER)
    writes.calls.clear()


def snap():
    return store().snapshot().outputs


# ---------------------------------------------------------------------------
# 1. The authority's mute model
# ---------------------------------------------------------------------------

class TestMuteModel:
    def test_starts_unmuted(self, writes):
        _arrange(_output("o1", 40))
        assert snap().muted_all is False and snap().unit("o1").muted is False

    def test_a_mute_remembers_the_level_and_reports_it_as_the_volume(self, writes):
        _muted(writes, _output("o1", 40))
        assert snap().muted_all is True
        assert snap().unit("o1").volume == 40
        assert snap().unit("o1").muted is True

    def test_a_second_mute_never_overwrites_the_remembered_level(self, writes):
        _muted(writes, _output("o1", 40))
        get_authority().mute_all(Origin.USER)
        assert snap().unit("o1").volume == 40
        assert writes.calls == []

    def test_a_speaker_switched_on_while_muted_comes_on_silent_and_remembers_its_level(self, writes):
        _muted(writes, _output("o1", 40), _output("o2", 0, selected=False))
        get_authority().select("o2", Origin.USER, volume=55)
        assert writes.levels() == [("o2", 0)]
        assert snap().unit("o2").muted is True and snap().unit("o2").volume == 55

    def test_a_user_level_change_ends_the_mute_of_that_speaker_only(self, writes):
        _muted(writes, _output("o1", 40), _output("o2", 60))
        get_authority().set_volume("o1", 25, Origin.USER)
        assert writes.levels() == [("o1", 25)]
        assert snap().unit("o1").muted is False and snap().unit("o2").muted is True
        assert snap().muted_all is False

    def test_a_level_change_by_anyone_else_only_moves_what_a_restore_brings_back(self, writes):
        _muted(writes, _output("o1", 40))
        get_authority().set_volume("o1", 25, Origin.SYSTEM)
        assert writes.calls == []
        assert snap().unit("o1").volume == 25 and snap().unit("o1").muted is True

    def test_switching_a_speaker_off_forgets_its_mute(self, writes):
        _muted(writes, _output("o1", 40), _output("o2", 60))
        get_authority().deselect("o1", Origin.USER)
        assert snap().unit("o1").muted is False
        assert snap().unit("o2").muted is True

    def test_a_mute_with_nothing_selected_is_still_held_until_the_session_ends(self, writes):
        _muted(writes, _output("o1", 40))
        get_authority().deselect("o1", Origin.USER)
        assert snap().muted_all is True
        get_authority().deselect_all(Origin.SESSION)
        assert snap().muted_all is False

    def test_the_end_of_a_session_clears_every_mute(self, writes):
        _muted(writes, _output("o1", 40), _output("o2", 60))
        get_authority().deselect_all(Origin.SESSION)
        assert all(u.muted is False for u in snap().units)
        assert snap().muted_all is False

    def test_the_next_sessions_default_speaker_starts_unmuted_at_the_configured_volume(self, writes):
        import autostream_output_intents  # noqa: F401 -- binds the rows
        from autostream_intents import Intent, submit
        _muted(writes, _output("Kitchen", 40))
        with patch.object(player_service, "stop_and_disable_all", return_value=ActionResult(ok=True)):
            get_authority().set_default_members([("", "Kitchen", 30)], 30)
            get_authority().deselect_all(Origin.SESSION)
            reply = submit(Intent(
                "outputs.select_default", {"key": "name:Kitchen", "volume": 30}, Origin.SESSION, "coordinator"))
        assert reply.ok is True
        assert writes.levels() == [("Kitchen", 30)]
        assert snap().unit("Kitchen").muted is False and snap().unit("Kitchen").volume == 30

    def test_a_volume_set_on_the_speaker_itself_ends_that_speakers_mute(self, writes):
        _muted(writes, _output("o1", 40), _output("o2", 60))
        FakeStore().outputs([_output("o1", 15), _output("o2", 0)])
        get_authority().device_volume_seen("o1")
        assert snap().unit("o1").muted is False and snap().unit("o1").volume == 15
        assert snap().unit("o2").muted is True
        assert writes.calls == []


# ---------------------------------------------------------------------------
# 2. Output changes and the mute
# ---------------------------------------------------------------------------

class TestOutputChangeMuteHooks:
    @staticmethod
    def _arrange_one(selected: bool, volume: int = 30):
        FakeStore().outputs([FakeStore.output_row("o1", "Speaker", selected=selected, volume_percent=volume)])

    def test_enable_while_muted_comes_on_silent_and_remembers_the_level(self, writes):
        import webui.browser.home_model as models
        FakeStore().outputs([
            FakeStore.output_row("o2", "Other", selected=True, volume_percent=30),
            FakeStore.output_row("o1", "Speaker", selected=False, volume_percent=0),
        ])
        get_authority().mute_all(Origin.USER)
        writes.calls.clear()
        result = webui_home_model.submit_output_change(
            {"id": "o1", "selected": True, "volume": 55},
            requester="coordinator", pin_requester=None, origin=Origin.SYSTEM,
        )
        assert result == {"ok": True, "id": "o1"}
        assert [kw.get("volume_percent") for _i, kw in writes.calls] == [0]
        assert snap().unit("o1").volume == 55 and snap().unit("o1").muted is True

    def test_a_system_level_write_while_muted_is_remembered_and_not_sent(self, writes):
        import webui.browser.home_model as models
        self._arrange_one(selected=True, volume=40)
        get_authority().mute_all(Origin.USER)
        writes.calls.clear()
        result = webui_home_model.submit_output_change(
            {"id": "o1", "selected": True, "volume": 12},
            requester="coordinator", pin_requester=None, origin=Origin.SYSTEM,
        )
        assert result == {"ok": True, "id": "o1"}
        assert writes.calls == []
        assert snap().unit("o1").volume == 12 and snap().muted_all is True

    def test_a_user_level_write_while_muted_ends_the_mute_and_writes(self, writes):
        """The WebUI has no unmute control: an explicit user volume set on a
        muted speaker is its unmute; the write is made for real."""
        import webui.browser.home_model as models
        self._arrange_one(selected=True, volume=40)
        get_authority().mute_all(Origin.USER)
        writes.calls.clear()
        result = webui_home_model.submit_output_change(
            {"id": "o1", "selected": True, "volume": 65}, requester="webui", pin_requester=None,
        )
        assert result == {"ok": True, "id": "o1"}
        assert [kw.get("volume_percent") for _i, kw in writes.calls] == [65]
        assert snap().muted_all is False

    def test_a_level_write_while_unmuted_is_unchanged(self, writes):
        import webui.browser.home_model as models
        self._arrange_one(selected=True)
        result = webui_home_model.submit_output_change(
            {"id": "o1", "selected": True, "volume": 12},
            requester="coordinator", pin_requester=None, origin=Origin.SYSTEM,
        )
        assert result == {"ok": True, "id": "o1"}
        assert len(writes.calls) == 1

    def test_disable_forgets_the_mute(self, writes):
        import webui.browser.home_model as models
        self._arrange_one(selected=True, volume=40)
        get_authority().mute_all(Origin.USER)
        result = webui_home_model.submit_output_change(
            {"id": "o1", "selected": False}, requester="webui", pin_requester=None,
        )
        assert result == {"ok": True, "id": "o1"}
        assert snap().unit("o1").muted is False


# ---------------------------------------------------------------------------
# 3. The end of a session
# ---------------------------------------------------------------------------

class TestSessionEndClearsMute:
    def test_the_end_of_a_session_clears_every_mute(self, writes):
        auth = get_authority()
        _arrange(_output("o1", 40))
        auth.mute_all(Origin.USER)
        assert snap().muted_all is True
        with patch.object(player_service, "stop_and_disable_all", return_value=ActionResult(ok=True)):
            auth.deselect_all(Origin.SESSION)
        assert snap().muted_all is False


# ---------------------------------------------------------------------------
# 4. The WebUI mute button/route are gone; the header text is the only
# mute indication and the volume slider is the only unmute path.
# ---------------------------------------------------------------------------

class TestWebUIMuteControlRemoved:
    def test_browser_mute_route_is_gone(self):
        matches = [r for r in webui_routes.ROUTES if r.path == "/api/mute"]
        assert matches == []

    def test_mute_icon_markup_and_slash_path(self):
        """ICON_SPEAKER_MUTED itself is kept (matches the dial's own glyph)
        even though the WebUI no longer renders it anywhere."""
        from webui.assets import ICON_SPEAKER_MUTED
        assert "<svg" in ICON_SPEAKER_MUTED
        assert "currentColor" in ICON_SPEAKER_MUTED
        # The slash is centred on the speaker body, matching the dial's own
        # shifted glyph (see dial_display_draw._draw_speaker_glyph).
        assert 'd="M1 5l14 14"' in ICON_SPEAKER_MUTED

    def test_page_js_no_longer_contains_mute_indicator_functions(self):
        import webui.assets as assets
        src = inspect_source(assets)
        assert "updateMuteIndicator" not in src
        assert "unmuteMaster" not in src

    def test_page_airplay_js_no_longer_calls_mute_indicator_functions(self):
        import webui.browser.home as page_airplay
        src = inspect_source(page_airplay)
        assert "updateMuteIndicator" not in src
        assert "unmuteMaster" not in src

    def test_page_js_header_shows_muted_suffix(self):
        assert "(Muted)" in static_text("shared/state_view.js")


def inspect_source(module) -> str:
    import inspect
    return inspect.getsource(module)


# ---------------------------------------------------------------------------
# 5. WebUI now-playing level slot: the VU meter and the mute indicator share
# one fixed-width slot (see _VU_STEREO_CSS's .np-level rule) so muting never
# shifts the name/signal text beside it.
# ---------------------------------------------------------------------------

def _hold_mute() -> None:
    """One speaker on and muted, as the page finds it when it is rendered."""
    FakeStore().outputs([FakeStore.output_row("o1", "Speaker", selected=True, volume_percent=30)])
    with patch.object(player_service, "update_output", return_value=ActionResult(ok=True)):
        get_authority().mute_all(Origin.USER)


def _render_airplay_page_html(show_input_detail: bool = True, playing: bool = False) -> str:
    """Invoke send_airplay_page() with every external dependency mocked and
    return the rendered HTML — trimmed down from test_track_id_home_render.py's
    own helper, this module's own copy so it stands on its own."""
    from webui.browser.home import send_airplay_page

    handler = MagicMock()
    chunks: list[bytes] = []
    handler.wfile.write = lambda d: chunks.append(d)
    handler._csrf_token = "testcsrf"
    handler._pending_set_cookies = []

    auth = MagicMock()
    auth.get_csrf_token.return_value = "testcsrf"

    state = MagicMock()
    state.config_path = "dummy.ini"

    parsed = MagicMock()
    parsed.owntone.base_url = "http://localhost:3689"
    from autostream_config import DefaultOutput
    parsed.owntone.default_outputs = (DefaultOutput("", "autostream", 20),)
    parsed.owntone.volume_percent = 20
    parsed.webui.show_master_volume = False
    parsed.webui.show_input_detail = show_input_detail
    parsed.webui.show_hostname_on_home = False
    parsed.webui.control_other_appliances = False
    parsed.webui.hidden_outputs = []
    parsed.webui.dark_mode = False
    parsed.track_identification = MagicMock(enabled=False)

    playback = MagicMock()
    playback.inputs = {}
    playback.stylus_banner_text = ""
    playback.belt_banner_text = ""
    playback.bearing_banner_text = ""
    playback.has_warning = False
    playback.to_public_dict.return_value = {}

    buf_result = MagicMock(ok=True, value="2250")
    input_levels = (
        [{"label": "Input 1", "is_above_threshold": True, "detected_hz": 0.0}]
        if playing else []
    )

    from contextlib import ExitStack
    patches = [
        patch("webui.common._config_snapshot", return_value=parsed),
        patch("autostream_appliance_identity.get_appliance_id", return_value="0" * 20),
        patch("webui.browser.home.get_system_hostname", return_value="autostream"),
        fake_levels(input_levels),
        fake_playback(playback),
        fake_outputs([], connected=False),
        patch("webui.browser.home.get_setting", return_value=buf_result),
        fake_track(_disabled_ti_snapshot()),
        patch("webui.browser.home.build_top_banner_html", return_value=("", "")),
    ]
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        send_airplay_page(handler, state, auth)
    return page_with_static(b"".join(chunks).decode("utf-8", errors="replace"))


def _render_airplay_page_html_playing() -> str:
    return _render_airplay_page_html(show_input_detail=True, playing=True)


def _disabled_ti_snapshot():
    from track_id.models import disabled_snapshot
    return disabled_snapshot()


class TestNowPlayingLevelSlotMarkup:
    def test_airplay_page_has_np_level_with_meter_and_no_mute_button(self):
        html = _render_airplay_page_html(show_input_detail=True)
        assert 'id="np-level"' in html
        assert 'id="np-vu"' in html
        assert 'id="np_mute_btn"' not in html
        assert 'np-mute-btn' not in html

    def test_airplay_page_omits_the_meter_without_input_detail_and_has_no_button(self):
        html = _render_airplay_page_html(show_input_detail=False)
        assert 'id="np-level"' in html
        assert 'id="np-vu"' not in html
        assert 'id="np_mute_btn"' not in html

# ---------------------------------------------------------------------------
# 6. The now-playing header text is the mute indication.
# ---------------------------------------------------------------------------

class TestNowPlayingHeaderMutedSuffix:


    def test_ready_header_never_gets_the_muted_suffix(self):
        """Not playing: mute is real but there is no active session to
        annotate, so "Ready" is shown plain, exactly as when unmuted."""
        _hold_mute()
        html = _render_airplay_page_html(show_input_detail=True)
        assert '>Ready<' in html
        assert '(Muted)<' not in html
