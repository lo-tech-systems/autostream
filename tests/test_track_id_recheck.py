"""The periodic re-check of an identified track keeps the track on show.

While the re-check attempt runs in the background, every reader of the track
identification snapshot (Home status, the dial status reply, the dial change
digest, the receiver's now-playing metadata) still sees the identified track.
A track change, a new session or a seek still clears it at once and shows the
analysing state.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT / "core"), str(REPO_ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import autostream_core as core
from autostream_artwork import ArtworkImage
from autostream_core import NowPlayingMetadata
from autostream_dial_push import track_digest
from autostream_webui_api import _dial_track_id_dict
from track_id.models import (
    STATE_ANALYSING,
    STATE_ERROR,
    STATE_IDENTIFIED,
    STATE_NOT_FOUND,
    STATE_WAITING,
    TrackArtwork,
    TrackIdentificationResult,
)

from test_track_id_core import _active_monitor, _make_client, _make_service


ART_URL = "https://art.example/kind-of-blue.jpg"
OTHER_ART_URL = "https://art.example/coltrane.jpg"
COVER = ArtworkImage(data=b"cover-one", mime="image/jpeg", ident="0123456789abcdef")
OTHER_COVER = ArtworkImage(data=b"cover-two", mime="image/jpeg", ident="fedcba9876543210")

TRACK = TrackIdentificationResult(
    matched=True, title="Blue in Green", artist="Miles Davis",
    album="Kind of Blue", artwork=TrackArtwork(url=ART_URL),
    provider="test_provider", confidence=0.9,
)
OTHER_TRACK = TrackIdentificationResult(
    matched=True, title="Giant Steps", artist="John Coltrane",
    album="Giant Steps", artwork=TrackArtwork(url=OTHER_ART_URL),
    provider="test_provider", confidence=0.9,
)
NO_MATCH = TrackIdentificationResult(matched=False, provider="test_provider")


@pytest.fixture(autouse=True)
def _clean_globals(monkeypatch):
    monkeypatch.setattr(core, "_track_id_service", None)
    yield
    # Whether or not a test left the admission gate held, leave it free.
    core._track_id_request_gate.acquire(blocking=False)
    core._track_id_request_gate.release()


class _Rig:
    """An identified, capturing monitor with its re-check ready to dispatch.

    The task pool is replaced so a dispatched worker waits in `pending` until
    the test runs it; that is the window in which a re-check is in flight.
    """

    def __init__(self, monkeypatch, svc, mon):
        self.svc = svc
        self.mon = mon
        self.client = _make_client()
        self.pending: list = []
        monkeypatch.setattr(core, "all_monitors", [mon])
        monkeypatch.setattr(core, "get_session_state", lambda: {})
        monkeypatch.setattr(
            core._task_pool, "submit",
            lambda key, fn, *args, **kwargs: self.pending.append((fn, args)) or True,
        )

    def dispatch(self) -> None:
        self.mon._ti_next_attempt = 1.0  # due now
        self.mon.maybe_trigger_track_identification(self.client, 1000.0)

    def finish(self) -> None:
        fn, args = self.pending.pop(0)
        fn(*args)

    def snapshot(self):
        return core.get_active_track_identification_snapshot()


def _artwork_cache(images: dict) -> MagicMock:
    cache = MagicMock()
    cache.get.side_effect = lambda url: images.get(url)
    return cache


@pytest.fixture
def rig(monkeypatch):
    """A monitor that has identified TRACK and is due its periodic re-check."""
    svc = _make_service()
    svc.identify.return_value = TRACK
    core._track_id_service = svc
    mon = _active_monitor()
    mon._apply_track_id_service(svc)
    mon._artwork_cache = _artwork_cache({ART_URL: COVER, OTHER_ART_URL: OTHER_COVER})
    r = _Rig(monkeypatch, svc, mon)
    r.dispatch()  # the first identification
    assert mon._ti_snapshot.state == STATE_ANALYSING
    r.finish()
    assert mon._ti_snapshot.state == STATE_IDENTIFIED
    assert mon._current_nowplaying == NowPlayingMetadata(
        title="Blue in Green", artist="Miles Davis", album="Kind of Blue", artwork=COVER,
    )
    mon._nowplaying_publisher.reset_mock()
    return r


def _shown(snap) -> tuple:
    return (snap.state, snap.title, snap.artist, snap.album, snap.artwork_url)


IDENTIFIED_TRACK = (
    STATE_IDENTIFIED, "Blue in Green", "Miles Davis", "Kind of Blue", ART_URL,
)


class TestRecheckKeepsTheTrackOnShow:

    def test_published_track_is_unchanged_while_the_recheck_is_in_flight(self, rig):
        rig.dispatch()
        assert rig.mon._ti_inflight is True
        assert len(rig.pending) == 1
        assert _shown(rig.snapshot()) == IDENTIFIED_TRACK

    def test_a_second_attempt_is_not_started_while_the_recheck_is_in_flight(self, rig):
        rig.dispatch()
        rig.dispatch()
        assert len(rig.pending) == 1

    def test_the_same_track_back_changes_nothing_shown(self, rig):
        rig.dispatch()
        before = _shown(rig.snapshot())
        rig.finish()
        assert _shown(rig.snapshot()) == before == IDENTIFIED_TRACK
        assert rig.mon._ti_inflight is False

    def test_the_same_track_back_does_not_repush_metadata_or_artwork(self, rig):
        rig.dispatch()
        rig.finish()
        rig.mon._nowplaying_publisher.publish_refresh.assert_not_called()
        rig.mon._nowplaying_publisher.publish_start.assert_not_called()

    def test_a_different_track_replaces_the_old_one_directly(self, rig):
        rig.dispatch()
        rig.svc.identify.return_value = OTHER_TRACK
        seen = [_shown(rig.snapshot())]
        rig.finish()
        seen.append(_shown(rig.snapshot()))
        assert seen == [
            IDENTIFIED_TRACK,
            (STATE_IDENTIFIED, "Giant Steps", "John Coltrane", "Giant Steps", OTHER_ART_URL),
        ]

    def test_a_different_track_is_pushed_to_the_receiver_with_its_own_cover(self, rig):
        rig.dispatch()
        rig.svc.identify.return_value = OTHER_TRACK
        rig.finish()
        pub = rig.mon._nowplaying_publisher
        pub.publish_refresh.assert_called_once_with(NowPlayingMetadata(
            title="Giant Steps", artist="John Coltrane", album="Giant Steps",
            artwork=OTHER_COVER,
        ))

    def test_a_recheck_that_finds_nothing_follows_the_not_found_rule(self, rig):
        rig.dispatch()
        assert _shown(rig.snapshot()) == IDENTIFIED_TRACK
        rig.svc.identify.return_value = NO_MATCH
        rig.finish()
        snap = rig.snapshot()
        assert snap.state == STATE_NOT_FOUND
        assert snap.title == ""
        assert rig.mon._ti_next_attempt_reason == "no_match"

    def test_a_failed_recheck_follows_the_error_rule(self, rig):
        rig.dispatch()
        assert _shown(rig.snapshot()) == IDENTIFIED_TRACK
        rig.svc.identify.side_effect = RuntimeError("provider down")
        rig.finish()
        snap = rig.snapshot()
        assert snap.state == STATE_ERROR
        assert snap.title == ""

    def test_a_failed_recheck_leaves_the_receiver_on_the_last_track(self, rig):
        rig.dispatch()
        rig.svc.identify.return_value = NO_MATCH
        rig.finish()
        rig.mon._nowplaying_publisher.publish_refresh.assert_not_called()
        assert rig.mon._current_nowplaying.title == "Blue in Green"


class TestTrackChangeStillClearsAtOnce:

    def test_a_track_change_clears_the_held_track_at_once(self, rig):
        rig.mon._on_possible_track_change(1)
        snap = rig.snapshot()
        assert snap.state == STATE_WAITING
        assert (snap.title, snap.artist, snap.album, snap.artwork_url) == ("", "", "", "")

    def test_the_attempt_after_a_track_change_shows_analysing_not_the_old_track(self, rig):
        rig.mon._on_possible_track_change(1)
        rig.dispatch()
        snap = rig.snapshot()
        assert snap.state == STATE_ANALYSING
        assert snap.title == ""

    def test_a_track_change_during_a_recheck_is_not_overwritten_by_the_stale_result(self, rig):
        rig.dispatch()
        assert _shown(rig.snapshot()) == IDENTIFIED_TRACK
        rig.mon._on_possible_track_change(1)
        assert rig.snapshot().state == STATE_WAITING
        rig.mon._nowplaying_publisher.reset_mock()
        rig.svc.identify.return_value = OTHER_TRACK  # the old attempt's late answer
        rig.finish()
        assert rig.snapshot().state == STATE_WAITING
        assert rig.snapshot().title == ""
        rig.mon._nowplaying_publisher.publish_refresh.assert_not_called()
        # The attempt that follows the change then shows analysing.
        rig.dispatch()
        assert rig.snapshot().state == STATE_ANALYSING

    def test_a_new_session_clears_the_held_track(self, rig):
        rig.mon._arm_track_identification_for_session()
        assert rig.snapshot().state == STATE_WAITING
        rig.dispatch()
        assert rig.snapshot().state == STATE_ANALYSING

    def test_a_replay_seek_clears_the_held_track(self, rig):
        rig.mon.on_replay_seek_accepted(in_session=False)
        assert rig.snapshot().state == STATE_WAITING
        rig.dispatch()
        assert rig.snapshot().state == STATE_ANALYSING

    def test_a_track_change_still_resets_the_receiver_to_the_placeholder(self, rig):
        rig.mon._on_possible_track_change(1)
        pub = rig.mon._nowplaying_publisher
        pub.publish_refresh.assert_called_once()
        assert pub.publish_refresh.call_args.args[0].title != "Blue in Green"


class TestReadersDuringARecheck:

    def test_the_dial_status_reply_keeps_the_track(self, rig):
        rig.dispatch()
        reply = _dial_track_id_dict()
        assert reply["state"] == STATE_IDENTIFIED
        assert (reply["title"], reply["artist"], reply["album"], reply["artwork_url"]) == (
            "Blue in Green", "Miles Davis", "Kind of Blue", ART_URL,
        )

    def test_the_status_api_snapshot_keeps_the_track(self, rig):
        rig.dispatch()
        public = rig.snapshot().to_public_dict()
        assert public["state"] == STATE_IDENTIFIED
        assert public["title"] == "Blue in Green"
        assert public["artwork_url"] == ART_URL

    def test_the_home_page_keeps_the_title_and_cover(self, rig):
        from test_track_id_home_render import _render_airplay_page
        rig.dispatch()
        html = _render_airplay_page(ti_snapshot=rig.snapshot())
        assert "Blue in Green" in html
        assert ART_URL in html

    def test_the_dial_change_digest_is_unchanged_so_no_dial_is_hinted(self, rig):
        before = track_digest(rig.snapshot())
        rig.dispatch()
        during = track_digest(rig.snapshot())
        rig.finish()
        assert before is not None
        assert during == before == track_digest(rig.snapshot())

    def test_the_dial_digest_still_says_nothing_for_the_analysing_state(self, rig):
        rig.mon._on_possible_track_change(1)
        rig.dispatch()
        assert rig.snapshot().state == STATE_ANALYSING
        assert track_digest(rig.snapshot()) is None

    def test_the_receiver_is_sent_no_placeholder_for_a_periodic_recheck(self, rig):
        rig.dispatch()
        rig.finish()
        pub = rig.mon._nowplaying_publisher
        pub.publish_refresh.assert_not_called()
        pub.publish_start.assert_not_called()
        assert rig.mon._current_nowplaying.artwork == COVER
