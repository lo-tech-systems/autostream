"""tests/test_repeat_ui_session.py

Acceptance tests: home-page UI for the unified session model.

Contract (coordinator-side): /api/status
gains a top-level "session": {"active": bool, "source": null|"input1"|
"input2"|"replay"}. The authoritative playing/active flag for the home page
is d.session.active, with a fallback to the pre-existing level-threshold
logic when the "session" block is entirely absent (talking to an older
backend that has not shipped this contract yet).

These tests assert against the JS SOURCE emitted by send_airplay_page (the
same "render + grep the markup" style as test_repeat_ui_wiring.py) since
there is no browser/DOM harness in this test suite; mocked status dicts are
therefore not fed through a real fetch, but the exact source lines that
implement the gating/optimistic-state logic are pinned so a regression in the
logic itself is caught.

Covers:
  1. Master-volume-card enable + now-playing/track-ID visibility rebased on
     d.session.active, with legacy (no session block) fallback.
  2. "Repeat Play" heading swap while d.session.source === 'replay'.
  3. Repeat button never shows "Replay Last" while d.session.active.
  4. Optimistic click state (immediate class/title, hold-until-agree-or-5s).
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock
from contextlib import ExitStack
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

_LOCAL_ID = "00000000000000000000"


def _make_parsed(*, repeat_enabled: bool = True, repeat_codec: str = "auto"):
    parsed = MagicMock()
    parsed.owntone.base_url = "http://localhost:3689"
    parsed.owntone.output_name = "autostream"
    parsed.owntone.volume_percent = 20
    parsed.webui.show_master_volume = True
    parsed.webui.show_input_detail = False
    parsed.webui.show_hostname_on_home = False
    parsed.webui.control_other_appliances = False
    parsed.webui.hidden_outputs = []
    parsed.webui.dark_mode = False
    parsed.track_identification = MagicMock(enabled=False)
    parsed.repeat.enabled = repeat_enabled
    parsed.repeat.codec = repeat_codec
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


def _render_airplay_page(*, repeat_enabled: bool = True) -> str:
    from autostream_webui_page_airplay import send_airplay_page
    from track_id.models import disabled_snapshot

    handler = MagicMock()
    chunks: list = []
    handler.wfile.write = lambda d: chunks.append(d)
    handler._csrf_token = "testcsrf"
    handler._pending_set_cookies = []

    auth = MagicMock()
    auth.get_csrf_token.return_value = "testcsrf"

    state = MagicMock()
    state.config_path = "dummy.ini"

    parsed = _make_parsed(repeat_enabled=repeat_enabled)
    playback = _make_playback_snapshot()
    list_result = MagicMock(ok=False, outputs=[])
    buf_result = MagicMock(ok=True, value="2250")

    patches = [
        patch("autostream_webui_page_airplay._config_snapshot", return_value=parsed),
        patch("autostream_webui_page_airplay.get_appliance_id", return_value=_LOCAL_ID),
        patch("autostream_webui_page_airplay.get_all_appliances", return_value=[]),
        patch("autostream_webui_page_airplay.get_system_hostname", return_value="autostream"),
        patch("autostream_webui_page_airplay.get_monitor_levels_dbfs", return_value=[]),
        patch("autostream_webui_page_airplay.get_playback_snapshot", return_value=playback),
        patch("autostream_webui_page_airplay.list_outputs", return_value=list_result),
        patch("autostream_webui_page_airplay.get_setting", return_value=buf_result),
        patch("autostream_core.get_active_track_identification_snapshot",
              return_value=disabled_snapshot()),
        patch("autostream_webui_page_airplay.build_top_banner_html", return_value=("", "")),
    ]

    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        send_airplay_page(handler, state, auth)

    return b"".join(chunks).decode("utf-8", errors="replace")


@pytest.fixture(scope="module")
def home_html() -> str:
    return _render_airplay_page(repeat_enabled=True)


# ---------------------------------------------------------------------------
# Symptom 1: master-volume/track-ID gating rebased on session.active
# ---------------------------------------------------------------------------

class TestSessionActiveGatesNowPlayingCard:
    def test_session_active_read_from_status_with_boolean_type_guard(self, home_html):
        assert (
            "var sessionActive = (session && typeof session.active === 'boolean') "
            "? !!session.active : null;" in home_html
        )

    def test_effective_active_prefers_session_over_legacy_is_playing(self, home_html):
        assert "var active = (sessionActive !== null) ? sessionActive : isPlaying;" in home_html

    def test_np_ready_and_hdr_gated_on_active_not_is_playing(self, home_html):
        # The card's dim/disabled visual state (which also visually covers
        # the nested master-volume-wrap) and the now-playing-body visibility
        # (which contains the track-ID name/signal spans) both key off
        # `active`, not the raw level-threshold `isPlaying`.
        assert "card.classList.toggle('np-ready', !active);" in home_html
        assert "card.classList.toggle('np-ready', !isPlaying);" not in home_html

    def test_legacy_fallback_when_session_block_absent(self, home_html):
        # When the backend sends no "session" key at all (old coordinator),
        # sessionActive resolves to null and `active` falls back to the
        # pre-existing isPlaying (level-threshold) computation -- current
        # behaviour is preserved unchanged for old-backend tolerance.
        assert "var session = (data && data.session) || null;" in home_html


# ---------------------------------------------------------------------------
# Symptom 5: "Repeat Play" heading while session.source === 'replay'
# ---------------------------------------------------------------------------

class TestReplayHeading:
    def test_heading_source_gate_present(self, home_html):
        # The local page leaves window.__REMOTE_HOSTNAME unset, so hdrSuffix
        # resolves to '' and the local heading renders with no hostname
        # suffix.
        assert (
            "hdrEl.textContent = (active ? (sessionSource === 'replay' ? "
            "'Repeat Play' : 'Now Playing') : 'Ready') + hdrSuffix;" in home_html
        )
        assert (
            "var hdrSuffix = window.__REMOTE_HOSTNAME ? (' · ' + window.__REMOTE_HOSTNAME) : '';"
            in home_html
        )

    def test_session_source_read_as_string_with_type_guard(self, home_html):
        assert (
            "var sessionSource = (session && typeof session.source === 'string') "
            "? session.source : null;" in home_html
        )


# ---------------------------------------------------------------------------
# Symptom 3: button never shows "Replay Last" while session.active
# ---------------------------------------------------------------------------

class TestReplayLastNeverWhileSessionActive:
    def test_show_replay_last_gated_on_session_active_with_legacy_fallback(self, home_html):
        assert (
            "var showReplayLast = (sessionActive === null)\n"
            "      ? (!on && hasBuffer)\n"
            "      : (!sessionActive && !on && hasBuffer && !armed && !replaying);"
            in home_html
        )

    def test_button_text_driven_by_show_replay_last_flag(self, home_html):
        assert "btn.textContent = showReplayLast ? '↻ Replay Last' : '↻ Repeat Play';" in home_html


# ---------------------------------------------------------------------------
# Symptom 4: optimistic click state, held until polled truth agrees or 5s
# ---------------------------------------------------------------------------

class TestOptimisticClickState:
    def test_optimistic_state_variable_declared(self, home_html):
        assert "var __repeatOptimistic = null;" in home_html

    def test_click_sets_optimistic_override_before_post_resolves(self, home_html):
        assert "__repeatOptimistic = { active: newArmed, ts: Date.now() };" in home_html
        # Class + transient title applied synchronously, before fetch() below.
        click_src = home_html.split("function onRepeatButtonClick()", 1)[1]
        opt_idx = click_src.index("__repeatOptimistic = { active: newArmed")
        fetch_idx = click_src.index("fetch(window.__REPEAT_URL || '/api/repeat'")
        assert opt_idx < fetch_idx
        assert "btn.classList.toggle('active', newArmed);" in click_src[opt_idx:fetch_idx]
        assert "btn.title = newArmed ? 'Starting…' : 'Stopping…';" in click_src[opt_idx:fetch_idx]

    def test_hold_until_agree_or_five_second_timeout(self, home_html):
        assert "var agrees = (__repeatOptimistic.active === polledOn);" in home_html
        assert "var expired = (Date.now() - __repeatOptimistic.ts) >= 5000;" in home_html
        assert "if (agrees || expired) {" in home_html

    def test_optimistic_override_wins_over_polled_state_while_held(self, home_html):
        assert "on = __repeatOptimistic.active;" in home_html

    def test_post_failure_reverts_optimistic_override(self, home_html):
        # Both the explicit {ok:false} branch and the network-error catch()
        # clear the override AND restore the pre-click class.
        assert "if (!d || !d.ok) {\n        __repeatOptimistic = null;\n        btn.classList.toggle('active', wasActive);\n      }" in home_html
        assert "}).catch(function(){\n      __repeatOptimistic = null;\n      btn.classList.toggle('active', wasActive);\n    });" in home_html

    def test_no_new_timers_beyond_existing_poll(self, home_html):
        # The optimistic mechanism must not introduce its own setTimeout/
        # setInterval; it only participates in the existing 1.5 s
        # refreshStatus()/updateRepeatButton() poll cycle already wired at
        # DOMContentLoaded.
        opt_block = home_html.split("var __repeatOptimistic = null;", 1)[1]
        opt_block = opt_block.split("function getOutputIdKey", 1)[0]
        assert "setTimeout" not in opt_block
        assert "setInterval" not in opt_block


# ---------------------------------------------------------------------------
# Track-ID display during replay
#
# Two independent gates must not hide the (already-correct, daemon-side)
# track-identification match during replay:
#   1. Server: get_active_track_identification_snapshot() only checked
#      m.is_capturing, which is False for the replay-origin input for the
#      whole duration of playback.
#   2. Client: the track-ID render block picked an arbitrary levels[0] input
#      (pretty copy) or never ran at all (minified remote-home copy) instead
#      of the actual replay-origin input.
# ---------------------------------------------------------------------------

import autostream_core as _core_mod
from autostream_core import AudioMonitor as _AudioMonitor
from track_id.models import disabled_snapshot as _disabled_snapshot
from track_id.models import waiting_snapshot as _waiting_snapshot
from track_id.models import TrackIdentificationSnapshot as _TISnapshot
from track_id.models import STATE_IDENTIFIED as _STATE_IDENTIFIED


def _mk_monitor(**overrides) -> _AudioMonitor:
    """Minimal AudioMonitor construction, patched free of FIFO/publisher I/O.

    Mirrors the _make_monitor helper used by test_audio_monitor_coordination.py
    and test_track_id_core.py -- duplicated here (rather than imported) since
    those modules don't expose it as a shared fixture and this file owns its
    own self-contained track-ID-during-replay test block.
    """
    defaults = dict(
        input_index=1,
        input_device="hw:1,0",
        silence_threshold_dbfs=-50.0,
        silence_seconds=5,
        fifo_path="/tmp/test_wpr9.fifo",
        owntone_base_url="",
        owntone_output_name="",
        owntone_volume_percent=50,
    )
    defaults.update(overrides)
    with patch("autostream_core.PersistentNowPlayingCache") as mock_cache_cls, \
         patch("autostream_core.get_shared_metadata_publisher") as mock_get_pub:
        mock_cache_cls.return_value.get_manual_hint.return_value = None
        mock_get_pub.side_effect = lambda path: MagicMock()
        mon = _AudioMonitor(**defaults)
    return mon


class TestGetActiveTrackIdentificationSnapshotDuringReplay:
    """Server-side fix 1 (autostream_core.get_active_track_identification_snapshot)."""

    def test_returns_origin_monitor_snapshot_when_replay_origin_and_not_capturing(self):
        origin_snap = _TISnapshot(
            enabled=True, state=_STATE_IDENTIFIED, status_text="Identified",
            input_index=1, title="Origin Track", artist="Origin Artist",
        )
        mon = _mk_monitor(input_index=1)
        mon.is_capturing = False
        mon._replay_origin = True
        mon._ti_snapshot = origin_snap
        _core_mod._track_id_service = MagicMock()

        result = _core_mod.get_active_track_identification_snapshot()
        assert result is origin_snap

    def test_capturing_monitor_takes_priority_over_a_replaying_one(self):
        # Mutual exclusion is a daemon invariant for the SAME recording, but
        # this function must still prefer an actually-capturing monitor over
        # a concurrently-replaying one on a different input if it ever
        # happens (belt-and-braces, matches the daemon's own priority).
        replay_snap = _TISnapshot(
            enabled=True, state=_STATE_IDENTIFIED, status_text="Identified",
            input_index=2, title="Replay Track",
        )
        capturing_snap = _TISnapshot(
            enabled=True, state=_STATE_IDENTIFIED, status_text="Identified",
            input_index=1, title="Live Track",
        )
        replaying_mon = _mk_monitor(input_index=2, fifo_path="/tmp/test_wpr9_b.fifo")
        replaying_mon.is_capturing = False
        replaying_mon._replay_origin = True
        replaying_mon._ti_snapshot = replay_snap

        capturing_mon = _mk_monitor(input_index=1, fifo_path="/tmp/test_wpr9_c.fifo")
        capturing_mon.is_capturing = True
        capturing_mon._replay_origin = False
        capturing_mon._ti_snapshot = capturing_snap
        _core_mod._track_id_service = MagicMock()

        result = _core_mod.get_active_track_identification_snapshot()
        assert result is capturing_snap

    def test_waiting_snapshot_when_service_enabled_but_nothing_actively_sourcing(self):
        mon = _mk_monitor(input_index=1)
        mon.is_capturing = False
        mon._replay_origin = False
        _core_mod._track_id_service = MagicMock()

        result = _core_mod.get_active_track_identification_snapshot()
        assert result.state == _waiting_snapshot().state
        assert result.enabled == _waiting_snapshot().enabled

    def test_disabled_snapshot_when_service_not_configured_and_nothing_active(self):
        mon = _mk_monitor(input_index=1)
        mon.is_capturing = False
        mon._replay_origin = False
        _core_mod._track_id_service = None

        result = _core_mod.get_active_track_identification_snapshot()
        assert result == _disabled_snapshot()

    def test_no_monitors_falls_back_to_disabled_snapshot(self):
        _core_mod._track_id_service = None
        assert _core_mod.all_monitors == []
        result = _core_mod.get_active_track_identification_snapshot()
        assert result == _disabled_snapshot()


# ---------------------------------------------------------------------------
# Client-side fix 2: track-ID render reachable during replay without a live
# activeLevel. The now-playing/session logic (formerly duplicated as
# updateNowPlayingCard on the local page and an inline copy inside the
# remote page's renderHomeState) now lives in a single shared function,
# renderNowPlayingCard (core/autostream_webui_assets.py::HOME_CARDS_SCRIPT),
# embedded byte-for-byte on both pages -- so these assertions are checked
# once against home_html and, separately, that the remote page's own
# renderHomeState delegates to it rather than re-implementing it.
# ---------------------------------------------------------------------------

class TestClientRendersTrackIdDuringReplay:
    def test_replay_origin_resolved_before_arbitrary_levels_zero_fallback(self, home_html):
        # The origin-input resolution block must appear, and appear textually
        # before the pre-existing "pick levels[0]" fallback so it takes
        # priority when both could apply.
        src = home_html.split("function renderNowPlayingCard(data)", 1)[1]
        origin_idx = src.index("sessionSource === 'replay'")
        fallback_idx = src.index(
            "if (!activeLevel && levels.length > 0) { activeLevel = levels[0]; activeIdx = 0; }"
        )
        assert origin_idx < fallback_idx

    def test_origin_input_read_from_repeat_recording_block(self, home_html):
        # Matches the naming convention already used by updateRepeatButton's
        # own "var recording = repeat.recording || {}": these exact
        # substrings are also on the wording-regression test's
        # internal-field-token allowlist (test_repeat_ui_wiring.py), so
        # introducing a differently-named intermediate variable here would
        # trip that guard.
        assert "var repeat = (data && data.repeat) || {};" in home_html
        assert "var recording = repeat.recording || {};" in home_html
        assert (
            "var originInput = Number.isFinite(Number(recording.origin_input))\n"
            "        ? Number(recording.origin_input) : null;" in home_html
        )

    def test_vu_ingest_skipped_for_replay_origin_fallback(self, home_html):
        # A replay-origin fallback level is not a genuine live level -- its
        # vu_history must not be fed into the VU meter queue.
        assert "if (!usingReplayOrigin) vuIngestHistory(activeIdx, activeLevel.vu_history);" in home_html
        # And the legacy unconditional call must be gone from this copy.
        assert "\n          vuIngestHistory(activeIdx, activeLevel.vu_history);\n        }}" not in home_html


def _render_remote_home_page() -> str:
    """Render send_remote_home_page's markup."""
    from autostream_webui_page_airplay import send_remote_home_page

    handler = MagicMock()
    chunks: list = []
    handler.wfile.write = lambda d: chunks.append(d)
    handler._csrf_token = "testcsrf"
    handler._pending_set_cookies = []

    state = MagicMock()
    state.config_path = "dummy.ini"
    parsed = _make_parsed(repeat_enabled=True)

    patches = [
        patch("autostream_webui_page_airplay._config_snapshot", return_value=parsed),
        patch("autostream_webui_page_airplay.get_appliance_id", return_value=_LOCAL_ID),
        patch("autostream_webui_page_airplay._build_appliances_for_selector", return_value=[]),
        patch("autostream_webui_page_airplay.build_appliance_selector_html", return_value=""),
    ]
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        send_remote_home_page(handler, state, "some-remote-appliance-id")

    return b"".join(chunks).decode("utf-8", errors="replace")


@pytest.fixture(scope="module")
def remote_home_html() -> str:
    return _render_remote_home_page()


class TestRemoteHomeDelegatesToSharedNowPlayingRenderer:
    def test_remote_render_home_state_calls_shared_renderer(self, remote_home_html):
        # renderHomeState (remote-only output/warnings orchestration) must
        # delegate the now-playing/session/track-ID logic to the shared
        # renderNowPlayingCard rather than re-implementing it inline.
        assert "function renderHomeState(data){\n  renderNowPlayingCard(data);" in remote_home_html

    def test_remote_page_embeds_shared_now_playing_renderer(self, remote_home_html):
        assert "function renderNowPlayingCard(data)" in remote_home_html

    def test_shared_script_is_byte_identical_on_both_pages(self, home_html, remote_home_html):
        # Regression guard for the refactor itself: both pages must embed
        # the exact same HOME_CARDS_SCRIPT text, not independently
        # hand-maintained copies that can drift apart again.
        from autostream_webui_assets import HOME_CARDS_SCRIPT

        assert HOME_CARDS_SCRIPT in home_html
        assert HOME_CARDS_SCRIPT in remote_home_html

    def test_info_modal_shared_across_both_pages(self, home_html, remote_home_html):
        # Regression guard for the info-modal extraction: both pages must
        # embed exactly one copy of the modal markup and the function that
        # drives it, sourced from the same shared constants.
        from autostream_webui_assets import COMMON_MODAL_CSS, INFO_MODAL_SCRIPT

        assert home_html.count('id="infoModal"') == 1
        assert remote_home_html.count('id="infoModal"') == 1
        assert "function showInfoModal" in home_html
        assert "function showInfoModal" in remote_home_html
        assert INFO_MODAL_SCRIPT in home_html
        assert INFO_MODAL_SCRIPT in remote_home_html
        assert ".modal-bd-scroll" in COMMON_MODAL_CSS


# ---------------------------------------------------------------------------
# Remote shell: repeat pill replaces the "<- Home" button; logo is the new
# home-navigation affordance; __REPEAT_URL is parameterized per page.
# ---------------------------------------------------------------------------

class TestRemoteShellTopControls:
    def test_no_return_home_button(self, remote_home_html):
        assert "← Home" not in remote_home_html
        assert "Return to this appliance" not in remote_home_html

    def test_repeat_pill_present_and_hidden_by_default(self, remote_home_html):
        assert 'id="repeat-btn"' in remote_home_html
        btn_tag = remote_home_html.split('id="repeat-btn"', 1)[1].split(">", 1)[0]
        assert "hidden" in btn_tag

    def test_repeat_pill_wired_to_click_handler(self, remote_home_html):
        assert "onRepeatButtonClick()" in remote_home_html

    def test_remote_render_home_state_calls_update_repeat_button(self, remote_home_html):
        assert "updateRepeatButton(data);" in remote_home_html


class TestRepeatUrlParameterization:
    def test_local_page_sets_repeat_url_to_api_repeat(self, home_html):
        assert "window.__REPEAT_URL='/api/repeat';" in home_html

    def test_remote_page_sets_repeat_url_to_gateway_path(self, remote_home_html):
        assert "window.__REPEAT_URL='/api/appliances/some-remote-appliance-id/repeat';" in remote_home_html


class TestLogoIsHomeLink:
    def test_banner_logo_html_wraps_images_in_home_link(self):
        from autostream_webui_assets import BANNER_LOGO_HTML

        assert '<a href="/"' in BANNER_LOGO_HTML
        # Both theme badges must be inside the link, not siblings of it.
        link_and_after = BANNER_LOGO_HTML.split('<a href="/"', 1)[1]
        assert "autostream-badge.png" in link_and_after
        assert "autostream-badge-dark.png" in link_and_after

    def test_local_and_remote_pages_embed_home_link_logo(self, home_html, remote_home_html):
        assert '<a href="/"' in home_html
        assert '<a href="/"' in remote_home_html
