"""tests/test_dial_choose_focus.py -- which appliance the dial follows.

A table of cases for dial_core_focus.choose_focus, taken from the rule the
dial has always applied: the focus the person picked, else the bound
appliance, else the playing appliance whose track is identified (with
artwork first), else the one that started playing first.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
for _p in (_ROOT / "dial", _ROOT / "core"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import dial_core_focus as cf  # noqa: E402
from dial_core_state import (  # noqa: E402
    AUTH_AUTHORIZED, AUTH_UNAUTHORIZED, AUTH_UNKNOWN, ApplianceState, FocusState,
)
from dial_repeat_store import RepeatRecord  # noqa: E402


def entry(name, *, playing=False, since=0.0, auth=AUTH_AUTHORIZED, repeat=None, status=True):
    aid = (name.lower().encode().hex() + "0" * 20)[:20]
    return ApplianceState(
        appliance_id=aid, service_name=f"autostream on {name}", name=name, ip="192.0.2.1", port=80,
        playing=playing, playing_since=since if playing else 0.0, auth=auth, dial_status=status,
        dial_outputs=True, dial_eq=True, repeat_capable=True, dial_proto_version=4,
        dial_eq_version=2, dial_outputs_version=2, status_error=None, master_volume=40, muted=False,
        repeat=repeat,
    )


def ident(url="https://example.test/a.jpg", **kw):
    return {"state": "identified", "title": "T", "artist": "A", "album": "B", "artwork_url": url, **kw}


def focus(**kw):
    base = dict(manual_id=None, bound_id=None, pending=None, reporting_id=None,
                source_service_name=None, accepted_replay=None, idle_focus=False)
    base.update(kw)
    return FocusState(**base)


def choose(roster, fo=None, tracks=None, now=100.0, prev=()):
    by_name = {e.name: e.appliance_id for e in roster}
    t = {by_name[n]: v for n, v in (tracks or {}).items()}
    return cf.choose_focus(roster, fo or focus(), now, tracks=t, prev_playing_ids=prev)


def name_of(roster, aid):
    return next((e.name for e in roster if e.appliance_id == aid), None)


# ---- the automatic pick ---------------------------------------------------------


class TestAutomatic:
    def test_nothing_playing_shows_nothing(self):
        r = [entry("A"), entry("B")]
        c = choose(r)
        assert (c.reporting_id, c.visible, c.idle_focus, c.source_service_name) == (None, (), None, None)

    def test_one_playing(self):
        r = [entry("A"), entry("B", playing=True, since=5)]
        c = choose(r)
        assert name_of(r, c.reporting_id) == "B"
        assert c.bound_id == c.reporting_id

    def test_oldest_playing_when_nothing_is_identified(self):
        r = [entry("Newer", playing=True, since=20), entry("Older", playing=True, since=10)]
        assert name_of(r, choose(r).reporting_id) == "Older"

    def test_identified_with_artwork_beats_an_older_appliance(self):
        r = [entry("Older", playing=True, since=10), entry("Newer", playing=True, since=20)]
        c = choose(r, tracks={"Newer": ident()})
        assert name_of(r, c.reporting_id) == "Newer"
        assert c.selection.url == "https://example.test/a.jpg"
        assert (c.selection.title, c.selection.artist, c.selection.album) == ("T", "A", "B")
        assert c.source_service_name == "autostream on Newer"

    def test_identified_without_artwork_is_the_fallback(self):
        r = [entry("Older", playing=True, since=10), entry("Newer", playing=True, since=20)]
        c = choose(r, tracks={"Newer": ident(url="")})
        assert name_of(r, c.reporting_id) == "Newer"
        assert c.selection.url is None and c.selection.title == "T"

    def test_artwork_beats_a_fallback_that_came_first(self):
        r = [entry("A", playing=True, since=10), entry("B", playing=True, since=20)]
        c = choose(r, tracks={"A": ident(url=""), "B": ident()})
        assert name_of(r, c.reporting_id) == "B"

    def test_not_identified_states_do_not_count(self):
        r = [entry("A", playing=True, since=10), entry("B", playing=True, since=20)]
        c = choose(r, tracks={"B": {"state": "analysing", "title": "x"}})
        assert name_of(r, c.reporting_id) == "A"

    def test_a_restart_with_two_already_playing_breaks_the_tie_by_name(self):
        r = [entry("Zed", playing=True, since=50), entry("Amp", playing=True, since=50)]
        assert name_of(r, choose(r).reporting_id) == "Amp"

    def test_a_refused_appliance_is_never_shown(self):
        r = [entry("Refused", playing=True, since=1, auth=AUTH_UNAUTHORIZED),
             entry("Ok", playing=True, since=2)]
        c = choose(r, tracks={"Refused": ident()})
        assert name_of(r, c.reporting_id) == "Ok"
        assert [e.name for e in c.visible] == ["Ok"]

    def test_unknown_access_counts_as_controllable(self):
        r = [entry("Unknown", playing=True, since=1, auth=AUTH_UNKNOWN)]
        assert name_of(r, choose(r).reporting_id) == "Unknown"

    def test_an_appliance_without_the_protocol_is_skipped_by_the_walk(self):
        r = [entry("Old", playing=True, since=1, status=False), entry("New", playing=True, since=2)]
        c = choose(r, tracks={"Old": ident(), "New": ident(url="")})
        assert c.selection.service == "autostream on New"

    def test_playing_since_order_is_by_time_name_then_address(self):
        r = [entry("B", playing=True, since=3), entry("A", playing=True, since=3), entry("C", playing=True, since=1)]
        assert [e.name for e in cf.playing_order(r)] == ["C", "A", "B"]


# ---- the focus the person picked --------------------------------------------------


class TestManualFocus:
    def test_a_focus_on_a_playing_appliance_is_pinned_over_an_identified_one(self):
        r = [entry("A", playing=True, since=10), entry("B", playing=True, since=20)]
        c = choose(r, focus(manual_id=r[0].appliance_id), tracks={"B": ident()})
        assert name_of(r, c.reporting_id) == "A"
        assert c.manual_id == r[0].appliance_id and c.idle_focus is None

    def test_a_focus_on_an_idle_appliance_is_kept_while_another_plays(self):
        r = [entry("Idle"), entry("Busy", playing=True, since=10)]
        c = choose(r, focus(manual_id=r[0].appliance_id), tracks={"Busy": ident()})
        assert name_of(r, c.reporting_id) == "Idle"
        assert c.idle_focus is r[0]
        assert c.manual_id == r[0].appliance_id
        assert c.selection.url is None
        assert c.source_service_name == "autostream on Idle"

    def test_a_focus_on_an_idle_appliance_with_nothing_else_playing(self):
        r = [entry("Idle")]
        c = choose(r, focus(manual_id=r[0].appliance_id))
        assert c.reporting_id == r[0].appliance_id and c.idle_focus is r[0]
        assert c.bound_id == r[0].appliance_id

    def test_a_focus_is_cleared_when_its_appliance_has_just_stopped(self):
        r = [entry("A"), entry("B", playing=True, since=10)]
        c = choose(r, focus(manual_id=r[0].appliance_id), prev=[r[0].appliance_id, r[1].appliance_id])
        assert c.manual_id is None and c.clear_reason == "appliance stopped playing"
        assert name_of(r, c.reporting_id) == "B"

    def test_a_focus_is_cleared_when_its_appliance_has_gone(self):
        r = [entry("A", playing=True, since=1)]
        c = choose(r, focus(manual_id="f" * 20))
        assert c.manual_id is None and c.clear_reason == "appliance gone or unauthorized"

    def test_a_focus_is_cleared_when_its_appliance_refuses_this_dial(self):
        r = [entry("A", auth=AUTH_UNAUTHORIZED)]
        c = choose(r, focus(manual_id=r[0].appliance_id))
        assert c.manual_id is None and c.reporting_id is None

    def test_a_bound_appliance_is_not_taken_over_by_a_newly_identified_one(self):
        r = [entry("A", playing=True, since=10), entry("B", playing=True, since=20)]
        c = choose(r, focus(bound_id=r[0].appliance_id), tracks={"B": ident()})
        assert name_of(r, c.reporting_id) == "A"

    def test_a_binding_is_released_when_its_appliance_stops(self):
        r = [entry("A"), entry("B", playing=True, since=20)]
        c = choose(r, focus(bound_id=r[0].appliance_id))
        assert name_of(r, c.reporting_id) == "B"
        assert c.bound_id == c.reporting_id


# ---- the pending focus and the accepted-replay bridge ---------------------------------


class TestPending:
    def test_a_pending_focus_that_is_not_rostered_yet_is_kept_and_named(self):
        pend = ("f" * 20, "autostream on Far", 200.0)
        c = choose([entry("A")], focus(manual_id="f" * 20, pending=pend), now=100.0)
        assert c.manual_id == "f" * 20 and c.pending == pend
        assert c.reporting_id == "f" * 20 and c.reporting is None

    def test_an_expired_pending_focus_is_cleared(self):
        pend = ("f" * 20, "autostream on Far", 90.0)
        c = choose([entry("A")], focus(manual_id="f" * 20, pending=pend), now=100.0)
        assert c.manual_id is None and c.pending is None

    def test_a_pending_focus_ends_once_the_appliance_is_playing(self):
        r = [entry("A", playing=True, since=1)]
        pend = (r[0].appliance_id, r[0].service_name, 200.0)
        c = choose(r, focus(manual_id=r[0].appliance_id, pending=pend))
        assert c.pending is None and c.manual_id == r[0].appliance_id

    def test_the_helpers_set_clear_and_drop_the_pending_focus(self):
        f = cf.with_pending(focus(), "x" * 20, "svc", 9.0)
        assert (f.manual_id, f.pending) == ("x" * 20, ("x" * 20, "svc", 9.0))
        assert cf.dropped_pending(f, "y" * 20) is None
        assert cf.dropped_pending(f, "x" * 20) == cf.cleared(f)
        assert cf.cleared(f).manual_id is None and cf.cleared(f).pending is None

    def test_the_grace_is_three_seconds(self):
        assert cf.FOCUS_PENDING_GRACE_S == 3.0


def replaying(accepted=True):
    return RepeatRecord(True, "replaying", False, 30.0, 5.0, 30.0, 0.0)


class TestAcceptedReplay:
    def test_an_accepted_replay_shows_as_playing_until_the_appliance_does(self):
        r = [entry("A", repeat=replaying())]
        aid = r[0].appliance_id
        c = choose(r, focus(manual_id=aid, accepted_replay=(aid, 120.0)))
        assert name_of(r, c.reporting_id) == "A"
        assert c.accepted_replay == (aid, 120.0) and len(c.visible) == 1 and c.visible[0].playing

    def test_the_window_ends_when_the_appliance_is_playing(self):
        r = [entry("A", playing=True, since=1, repeat=replaying())]
        aid = r[0].appliance_id
        c = choose(r, focus(manual_id=aid, accepted_replay=(aid, 120.0)))
        assert c.accepted_replay is None

    @pytest.mark.parametrize("fo, rec, now", [
        (lambda aid: focus(manual_id=None, accepted_replay=(aid, 120.0)), replaying(), 100.0),   # not following it
        (lambda aid: focus(manual_id=aid, accepted_replay=(aid, 120.0)), replaying(), 130.0),    # deadline
        (lambda aid: focus(manual_id=aid, accepted_replay=(aid, 120.0)),
         RepeatRecord(True, "hold", False, 30.0, 0.0, 30.0, 0.0), 100.0),                       # no replay running
        (lambda aid: focus(manual_id=aid, accepted_replay=(aid, 120.0)), None, 100.0),           # no record
    ])
    def test_the_window_closes(self, fo, rec, now):
        r = [entry("A", repeat=rec)]
        c = choose(r, fo(r[0].appliance_id), now=now)
        assert c.accepted_replay is None
        assert c.visible == ()

    def test_with_accepted_opens_only_for_the_followed_appliance(self):
        f = focus(manual_id="x" * 20)
        assert cf.with_accepted(f, "y" * 20, 9.0) is None
        assert cf.with_accepted(f, "x" * 20, 9.0).accepted_replay == ("x" * 20, 9.0)


# ---- applying a choice ---------------------------------------------------------------------


def test_apply_writes_every_decided_field():
    r = [entry("A", playing=True, since=1)]
    c = choose(r, tracks={"A": ident()})
    f = c.apply(focus(manual_id="gone"))
    assert (f.manual_id, f.bound_id, f.reporting_id) == (None, r[0].appliance_id, r[0].appliance_id)
    assert f.source_service_name == "autostream on A" and f.idle_focus is False
