"""Tests for dial_core_state.py: the snapshot dataclasses and the pure
decisions the poll tick makes over them. Nothing here touches the display,
a clock or the network; every time is passed in."""
from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
for _p in (str(REPO_ROOT / "dial"), str(REPO_ROOT / "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import dial_core_state as cs  # noqa: E402
from dial_auth import AUTH_AUTHORIZED, AUTH_UNAUTHORIZED, AUTH_UNKNOWN  # noqa: E402
from dial_mdns import PlayingTarget, RosterEntry  # noqa: E402
from dial_repeat_store import RepeatRecord  # noqa: E402


def _id(name: str) -> str:
    return (name.encode().hex() + "0" * 20)[:20]


def _target(name="Kitchen", auth=AUTH_UNKNOWN, dial_status=True, appliance_id=None,
            playing_since=100.0) -> PlayingTarget:
    return PlayingTarget(
        ip="192.0.2.10", port=80, name=name, dial_api=True, audio_status=True,
        dial_status=dial_status, service_name=name, playing_since=playing_since,
        appliance_id=_id(name) if appliance_id is None else appliance_id, auth=auth,
    )


def _entry(name="Kitchen", auth=AUTH_UNKNOWN, playing=False, repeat_capable=False,
           dial_outputs=False, dial_eq=False, appliance_id=None) -> RosterEntry:
    return RosterEntry(
        appliance_id=_id(name) if appliance_id is None else appliance_id,
        service_name=name, name=name, ip="192.0.2.10", port=80, playing=playing,
        repeat_capable=repeat_capable, dial_api=True, audio_status=True,
        dial_status=True, dial_outputs=dial_outputs, dial_eq=dial_eq, auth=auth,
    )


def _rec(state="hold", available=True, seconds=30.0) -> RepeatRecord:
    return RepeatRecord(
        available=available, state=state, armed=False, recording_seconds=seconds,
        position_seconds=0.0, duration_seconds=0.0, observed_at=0.0,
    )


def _track(artwork="https://provider.example/a.jpg", **kw) -> dict:
    base = {"state": "identified", "title": "T", "artist": "A", "album": "L"}
    if artwork is not None:
        base["artwork_url"] = artwork
    base.update(kw)
    return {"track_id": base}


# ---- dataclasses ---------------------------------------------------------


class TestDataclasses:
    def test_now_playing_defaults_and_appended_field(self):
        np_ = cs.NowPlaying("svc", "a", "t", 40)
        assert (np_.album, np_.playing, np_.artwork_url) == ("", True, "")
        assert cs.NowPlaying("svc", "a", "t", 40, "alb", False, "u").artwork_url == "u"

    def test_now_playing_equality_includes_artwork_url(self):
        assert cs.NowPlaying("s", "a", "t", 1) != cs.NowPlaying("s", "a", "t", 1, artwork_url="u")

    def test_output_row_defaults(self):
        row = cs.OutputRow("o", "Out", True, 50)
        assert (row.remote_in_use, row.remote_owner) == (False, None)
        assert row.is_default is False

    @pytest.mark.parametrize("cls", [
        cs.NowPlaying, cs.OutputRow, cs.SelectorRow, cs.PickerRow, cs.ApplianceState,
        cs.FocusState, cs.Artwork, cs.OutputsState, cs.EqBand, cs.EqState,
        cs.WarningState, cs.TransportRequest, cs.DialInfo, cs.CoreSnapshot,
        cs.FocusResolution, cs.Selection,
    ])
    def test_frozen(self, cls):
        assert cls.__dataclass_params__.frozen

    def test_dial_display_reexports_the_moved_types(self):
        import dial_display
        assert dial_display.OutputRow is cs.OutputRow
        assert dial_display.SelectorRow is cs.SelectorRow
        assert dial_display.PickerRow is cs.PickerRow

    def test_module_does_not_import_the_display(self):
        src = (REPO_ROOT / "dial" / "dial_core_state.py").read_text(encoding="utf-8")
        assert "dial_display" not in src
        assert "import threading" not in src and "import time" not in src


def _appliance(aid, **kw) -> cs.ApplianceState:
    base = dict(
        appliance_id=aid, service_name=aid, name=aid, ip="192.0.2.1", port=80,
        playing=False, playing_since=0.0, auth=AUTH_AUTHORIZED, dial_status=True,
        dial_outputs=False, dial_eq=False, repeat_capable=False, dial_proto_version=2,
        dial_eq_version=0, dial_outputs_version=0, status_error=None,
        master_volume=None, muted=None, repeat=None,
    )
    base.update(kw)
    return cs.ApplianceState(**base)


def _snapshot(appliances, manual=None, reporting=None) -> cs.CoreSnapshot:
    return cs.CoreSnapshot(
        seq=1, at=0.0, polling=True, appliances=tuple(appliances),
        focus=cs.FocusState(manual, None, None, reporting, None, None, False),
        now_playing=None, artwork=None, idle_affordance=False, outputs=None, eq=None,
        outputs_available=False, eq_available=False, warnings=(), due_warning_id=None,
        network=None, wifi_ever_connected=False, sd_health=None, update=None,
        transport=None, volume_readout=(None, None),
        dial=cs.DialInfo("d", "0", "u", "", 0, (), "current", "current"),
    )


class TestCoreSnapshotHelpers:
    def test_appliance_lookup(self):
        snap = _snapshot([_appliance("a"), _appliance("b")])
        assert snap.appliance("b").appliance_id == "b"
        assert snap.appliance("zz") is None
        assert snap.appliance(None) is None

    def test_reporting_and_focused_id(self):
        snap = _snapshot([_appliance("a"), _appliance("b")], manual=None, reporting="a")
        assert snap.reporting().appliance_id == "a"
        assert snap.focused_id() == "a"
        snap = _snapshot([_appliance("a"), _appliance("b")], manual="b", reporting="a")
        assert snap.focused_id() == "b"
        assert snap.reporting().appliance_id == "a"

    def test_nothing_focused(self):
        snap = _snapshot([_appliance("a")])
        assert snap.reporting() is None and snap.focused_id() is None

    def test_snapshot_is_immutable(self):
        snap = _snapshot([])
        with pytest.raises(dataclasses.FrozenInstanceError):
            snap.seq = 2  # type: ignore[misc]


# ---- visible_targets / started_refused ----------------------------------


class TestVisibleTargets:
    def test_drops_unauthorized_and_identity_less(self):
        keep = _target("Keep", auth=AUTH_AUTHORIZED)
        unknown = _target("Unknown", auth=AUTH_UNKNOWN)
        refused = _target("Refused", auth=AUTH_UNAUTHORIZED)
        anon = _target("Anon", appliance_id="")
        assert cs.visible_targets([keep, refused, anon, unknown]) == [keep, unknown]

    def test_empty(self):
        assert cs.visible_targets([]) == []


class TestStartedRefused:
    def test_only_new_refused(self):
        a = _target("A", auth=AUTH_UNAUTHORIZED)
        b = _target("B", auth=AUTH_UNAUTHORIZED)
        c = _target("C", auth=AUTH_AUTHORIZED)
        assert cs.started_refused([a, b, c], {b.appliance_id}) == [a.appliance_id]

    def test_none_when_all_known(self):
        a = _target("A", auth=AUTH_UNAUTHORIZED)
        assert cs.started_refused([a], {a.appliance_id}) == []

    def test_accepts_a_list_of_ids(self):
        a = _target("A", auth=AUTH_UNAUTHORIZED)
        assert cs.started_refused([a], [a.appliance_id]) == []


# ---- resolve_focus -------------------------------------------------------


def _auth_of(state):
    return lambda appliance_id: state


class TestResolveFocus:
    def test_no_focus(self):
        a = _target("A")
        res = cs.resolve_focus(None, None, [_entry("A", playing=True)], [a], set(), 0.0,
                               _auth_of(AUTH_UNKNOWN))
        assert res == cs.FocusResolution(None, None, None, None, None, None)

    def test_focus_on_playing_target(self):
        a = _target("A")
        e = _entry("A", playing=True)
        res = cs.resolve_focus(a.appliance_id, None, [e], [a], set(), 0.0, _auth_of(AUTH_UNKNOWN))
        assert res.manual_id == a.appliance_id
        assert res.focus_entry is e and res.focus_target is a
        assert res.idle_focus is None and res.clear_reason is None

    def test_idle_focus_kept_while_something_else_plays(self):
        b = _target("B")
        idle = _entry("Idle")
        res = cs.resolve_focus(idle.appliance_id, None, [idle, _entry("B", playing=True)], [b],
                               set(), 0.0, _auth_of(AUTH_UNKNOWN))
        assert res.focus_entry is idle and res.focus_target is None
        assert res.idle_focus is idle and res.clear_reason is None
        assert res.manual_id == idle.appliance_id

    def test_gone_from_roster_clears(self):
        res = cs.resolve_focus("x" * 20, None, [_entry("A")], [], set(), 0.0, _auth_of(AUTH_UNKNOWN))
        assert res.clear_reason == "appliance gone or unauthorized"
        assert res.manual_id is None and res.focus_entry is None and res.idle_focus is None

    def test_unauthorized_roster_entry_clears(self):
        e = _entry("A", auth=AUTH_UNAUTHORIZED)
        res = cs.resolve_focus(e.appliance_id, None, [e], [], set(), 0.0, _auth_of(AUTH_UNAUTHORIZED))
        assert res.clear_reason == "appliance gone or unauthorized"

    def test_stopped_focus_clears(self):
        e = _entry("A")
        res = cs.resolve_focus(e.appliance_id, None, [e], [], {e.appliance_id}, 0.0,
                               _auth_of(AUTH_UNKNOWN))
        assert res.clear_reason == "appliance stopped playing"
        assert res.manual_id is None and res.focus_entry is None and res.idle_focus is None

    def test_playing_focus_that_is_in_stopped_ids_is_not_cleared(self):
        # Present in the visible set this tick, so it did not stop.
        a = _target("A")
        e = _entry("A", playing=True)
        res = cs.resolve_focus(a.appliance_id, None, [e], [a], {a.appliance_id}, 0.0,
                               _auth_of(AUTH_UNKNOWN))
        assert res.clear_reason is None and res.focus_target is a

    def test_pending_grace_keeps_unrostered_focus(self):
        pending = ("p" * 20, "Pend", 10.0)
        res = cs.resolve_focus("p" * 20, pending, [], [], set(), 5.0, _auth_of(AUTH_UNKNOWN))
        assert res.clear_reason is None
        assert res.manual_id == "p" * 20 and res.pending == pending
        assert res.focus_entry is None and res.idle_focus is None

    def test_pending_grace_not_for_confirmed_unauthorized(self):
        pending = ("p" * 20, "Pend", 10.0)
        res = cs.resolve_focus("p" * 20, pending, [], [], set(), 5.0, _auth_of(AUTH_UNAUTHORIZED))
        assert res.clear_reason == "appliance gone or unauthorized"
        assert res.pending is None

    def test_pending_expired(self):
        pending = ("p" * 20, "Pend", 10.0)
        res = cs.resolve_focus("p" * 20, pending, [], [], set(), 10.0, _auth_of(AUTH_UNKNOWN))
        assert res.pending is None
        assert res.clear_reason == "appliance gone or unauthorized"

    def test_pending_for_a_different_focus_is_dropped(self):
        e = _entry("A")
        pending = ("p" * 20, "Pend", 100.0)
        res = cs.resolve_focus(e.appliance_id, pending, [e], [], set(), 1.0, _auth_of(AUTH_UNKNOWN))
        assert res.pending is None and res.clear_reason is None
        assert res.idle_focus is e

    def test_pending_converts_when_sighted_playing(self):
        a = _target("A")
        e = _entry("A", playing=True)
        pending = (a.appliance_id, "A", 100.0)
        res = cs.resolve_focus(a.appliance_id, pending, [e], [a], set(), 1.0, _auth_of(AUTH_UNKNOWN))
        assert res.pending is None and res.focus_target is a and res.clear_reason is None

    def test_pending_kept_while_rostered_but_idle(self):
        e = _entry("A")
        pending = (e.appliance_id, "A", 100.0)
        res = cs.resolve_focus(e.appliance_id, pending, [e], [], set(), 1.0, _auth_of(AUTH_UNKNOWN))
        assert res.pending == pending and res.idle_focus is e

    def test_auth_state_only_read_for_the_grace_check(self):
        calls = []

        def auth_state(aid):
            calls.append(aid)
            return AUTH_UNKNOWN

        e = _entry("A")
        cs.resolve_focus(e.appliance_id, None, [e], [], set(), 0.0, auth_state)
        assert calls == []


# ---- choose_pin / walk_order --------------------------------------------


class TestChoosePin:
    def test_focus_target_wins(self):
        a, b = _target("A"), _target("B")
        pin, bound = cs.choose_pin(a, b.appliance_id, [a, b])
        assert pin is a and bound == b.appliance_id

    def test_bound_target_pins_when_no_focus(self):
        a, b = _target("A"), _target("B")
        pin, bound = cs.choose_pin(None, b.appliance_id, [a, b])
        assert pin is b and bound == b.appliance_id

    def test_bound_target_gone_is_released(self):
        a = _target("A")
        pin, bound = cs.choose_pin(None, "gone" + "0" * 16, [a])
        assert pin is None and bound is None

    def test_nothing_bound(self):
        a = _target("A")
        assert cs.choose_pin(None, None, [a]) == (None, None)

    def test_no_lookup_when_caller_passes_no_binding(self):
        a = _target("A")
        assert cs.choose_pin(None, None, []) == (None, None)


class TestWalkOrder:
    def test_unpinned_is_unchanged(self):
        vis = [_target("A"), _target("B")]
        assert cs.walk_order(None, vis) is vis

    def test_pin_goes_first_rest_keep_order(self):
        a, b, c = _target("A"), _target("B"), _target("C")
        assert cs.walk_order(c, [a, b, c]) == [c, a, b]
        assert cs.walk_order(a, [a, b, c]) == [a, b, c]


# ---- the walk ------------------------------------------------------------


class TestWalkStep:
    def test_unpinned_artwork_stops_the_walk(self):
        t = _target("A")
        sel, fb = cs.walk_step(t, _track(), False, None)
        assert sel == cs.Selection("https://provider.example/a.jpg", "A", "A", "T", "L")
        assert fb is None

    def test_unpinned_status_error_skips(self):
        t = _target("A")
        assert cs.walk_step(t, None, False, None) == (None, None)

    def test_unpinned_not_identified_continues(self):
        t = _target("A")
        assert cs.walk_step(t, {"track_id": {"state": "searching"}}, False, None) == (None, None)
        assert cs.walk_step(t, {}, False, None) == (None, None)

    def test_unpinned_identified_without_art_sets_fallback_once(self):
        a, b = _target("A"), _target("B")
        sel, fb = cs.walk_step(a, _track(artwork=None), False, None)
        assert sel is None and fb[0] == "A"
        sel, fb2 = cs.walk_step(b, _track(artwork=None, title="Other"), False, fb)
        assert sel is None and fb2 is fb

    def test_pinned_with_artwork(self):
        t = _target("A")
        sel, _ = cs.walk_step(t, _track(), True, None)
        assert sel.url == "https://provider.example/a.jpg" and sel.service == "A"

    def test_pinned_identified_without_art_still_shows_text(self):
        t = _target("A")
        sel, _ = cs.walk_step(t, _track(artwork=None), True, None)
        assert sel == cs.Selection(None, "A", "A", "T", "L")

    def test_pinned_empty_artwork_url_is_none(self):
        t = _target("A")
        sel, _ = cs.walk_step(t, _track(artwork=""), True, None)
        assert sel.url is None and sel.title == "T"

    def test_pinned_not_identified_keeps_service_only(self):
        t = _target("A")
        sel, _ = cs.walk_step(t, {"track_id": {"state": "searching"}}, True, None)
        assert sel == cs.Selection(service="A")

    def test_pinned_with_status_error_keeps_selected_service(self):
        t = _target("A")
        sel, _ = cs.walk_step(t, None, True, None)
        assert sel == cs.Selection(service="A")

    def test_missing_text_fields_default_empty(self):
        t = _target("A")
        rec = {"track_id": {"state": "identified", "artwork_url": "u"}}
        sel, _ = cs.walk_step(t, rec, False, None)
        assert (sel.artist, sel.title, sel.album) == ("", "", "")


class TestWalkFallback:
    def test_none(self):
        assert cs.walk_fallback(None) == cs.Selection()

    def test_first_identified_without_art(self):
        fb = ("A", {"artist": "X", "title": "Y", "album": "Z"})
        assert cs.walk_fallback(fb) == cs.Selection(None, "A", "X", "Y", "Z")


class TestSelectFromRecords:
    def test_artwork_beats_earlier_text_only(self):
        a, b = _target("A"), _target("B")
        recs = {"A": _track(artwork=None), "B": _track(artwork="u2", title="B title")}
        sel = cs.select_from_records([a, b], recs, None)
        assert sel.service == "B" and sel.url == "u2" and sel.title == "B title"

    def test_text_only_fallback_when_no_artwork_anywhere(self):
        a, b = _target("A"), _target("B")
        recs = {"A": {"track_id": {"state": "searching"}}, "B": _track(artwork=None)}
        sel = cs.select_from_records([a, b], recs, None)
        assert sel == cs.Selection(None, "B", "A", "T", "L")

    def test_nothing_identified(self):
        a = _target("A")
        assert cs.select_from_records([a], {"A": {}}, None) == cs.Selection()

    def test_empty_walk(self):
        assert cs.select_from_records([], {}, None) == cs.Selection()

    def test_pinned_target_stops_the_walk(self):
        a, b = _target("A"), _target("B")
        recs = {"A": {}, "B": _track()}
        sel = cs.select_from_records(cs.walk_order(a, [a, b]), recs, a)
        assert sel == cs.Selection(service="A")

    def test_pinned_with_status_error_keeps_selected_service(self):
        a, b = _target("A"), _target("B")
        sel = cs.select_from_records([a, b], {"B": _track()}, a)
        assert sel == cs.Selection(service="A")

    def test_unpinned_status_error_skipped_to_next(self):
        a, b = _target("A"), _target("B")
        sel = cs.select_from_records([a, b], {"B": _track()}, None)
        assert sel.service == "B"

    def test_unauthorized_skipped(self):
        a = _target("A", auth=AUTH_UNAUTHORIZED)
        b = _target("B")
        sel = cs.select_from_records([a, b], {"A": _track(), "B": _track(artwork="ub")}, None)
        assert sel.service == "B" and sel.url == "ub"

    def test_unsupported_target_skipped_when_unpinned(self):
        a = _target("A", dial_status=False)
        b = _target("B")
        sel = cs.select_from_records([a, b], {"B": _track()}, None)
        assert sel.service == "B"

    def test_unsupported_pinned_target_selected_by_name(self):
        a = _target("A", dial_status=False)
        b = _target("B")
        sel = cs.select_from_records([a, b], {"B": _track()}, a)
        assert sel == cs.Selection(service="A")

    def test_matches_stepwise_walk(self):
        targets = [_target("A"), _target("B"), _target("C")]
        recs = {"A": _track(artwork=None, title="a"), "C": _track(artwork="uc")}
        fb = None
        out = None
        for t in targets:
            out, fb = cs.walk_step(t, recs.get(t.service_name), False, fb)
            if out is not None:
                break
        else:
            out = cs.walk_fallback(fb)
        assert out == cs.select_from_records(targets, recs, None)


# ---- reporting_for -------------------------------------------------------


class TestReportingFor:
    def test_idle_focus_wins(self):
        idle = _entry("Idle")
        assert cs.reporting_for(idle, [_target("A")], "A") is idle

    def test_selected_service_among_visible(self):
        a, b = _target("A"), _target("B")
        assert cs.reporting_for(None, [a, b], "B") is b

    def test_falls_back_to_first_visible(self):
        a, b = _target("A"), _target("B")
        assert cs.reporting_for(None, [a, b], None) is a
        assert cs.reporting_for(None, [a, b], "missing") is a

    def test_none_when_nothing_visible(self):
        assert cs.reporting_for(None, [], None) is None


# ---- with_accepted_replay ------------------------------------------------


class TestWithAcceptedReplay:
    AID = _id("Den")

    def _call(self, accepted=None, targets=None, roster=None, manual=None, rec=None, now=5.0):
        return cs.with_accepted_replay(
            accepted, [] if targets is None else targets,
            [_entry("Den", auth=AUTH_AUTHORIZED)] if roster is None else roster,
            manual, rec, now,
        )

    def test_no_window_is_identity(self):
        targets = [_target("A")]
        out, acc = self._call(None, targets)
        assert out is targets and acc is None

    def test_bridges_the_gap(self):
        accepted = (self.AID, 25.0)
        out, acc = self._call(accepted, manual=self.AID, rec=_rec("replaying"))
        assert acc is accepted
        assert len(out) == 1
        t = out[0]
        assert (t.appliance_id, t.service_name, t.playing_since) == (self.AID, "Den", 5.0)
        assert t.auth == AUTH_AUTHORIZED and t.dial_status

    def test_fading_out_still_bridges(self):
        accepted = (self.AID, 25.0)
        out, acc = self._call(accepted, manual=self.AID, rec=_rec("fading_out"))
        assert acc is accepted and len(out) == 1

    @pytest.mark.parametrize("label,kwargs", [
        ("deadline", dict(now=25.0)),
        ("focus moved", dict(manual="other")),
        ("record gone", dict(rec=None)),
        ("record unavailable", dict(rec=_rec("replaying", available=False))),
        ("replay not running", dict(rec=_rec("hold"))),
    ])
    def test_window_closes(self, label, kwargs):
        base = dict(accepted=(self.AID, 25.0), manual=self.AID, rec=_rec("replaying"))
        base.update(kwargs)
        targets = [_target("A")]
        out, acc = self._call(targets=targets, **base)
        assert out is targets and acc is None

    def test_window_closes_when_advertisement_seen(self):
        den = _target("Den")
        out, acc = self._call((self.AID, 25.0), targets=[den], manual=self.AID,
                              rec=_rec("replaying"))
        assert out == [den] and acc is None

    def test_unrostered_keeps_the_window_without_a_target(self):
        accepted = (self.AID, 25.0)
        targets = [_target("A")]
        out, acc = self._call(accepted, targets, roster=[], manual=self.AID, rec=_rec("replaying"))
        assert out is targets and acc is accepted

    def test_refused_roster_entry_not_bridged(self):
        accepted = (self.AID, 25.0)
        out, acc = self._call(accepted, roster=[_entry("Den", auth=AUTH_UNAUTHORIZED)],
                              manual=self.AID, rec=_rec("replaying"))
        assert out == [] and acc is accepted

    def test_input_list_not_mutated(self):
        targets = [_target("A")]
        self._call((self.AID, 25.0), targets, manual=self.AID, rec=_rec("replaying"))
        assert len(targets) == 1


# ---- rows ---------------------------------------------------------------


class TestSelectorRows:
    def test_filter_and_flags(self):
        auth = _entry("Auth", auth=AUTH_AUTHORIZED, playing=True)
        idle = _entry("Idle", auth=AUTH_AUTHORIZED)
        refused = _entry("Refused", auth=AUTH_UNAUTHORIZED, playing=True)
        unknown = _entry("Unknown", auth=AUTH_UNKNOWN)
        anon = _entry("Anon", auth=AUTH_AUTHORIZED, appliance_id="")
        rows = cs.selector_rows([auth, idle, refused, unknown, anon], None, auth.appliance_id)
        assert [r.label for r in rows] == ["Auth", "Idle", "Refused"]
        assert [r.current for r in rows] == [True, False, False]
        assert [r.playing for r in rows] == [True, False, False]
        assert [r.authorized for r in rows] == [True, True, False]

    def test_manual_focus_beats_reporting(self):
        a = _entry("A", auth=AUTH_AUTHORIZED)
        b = _entry("B", auth=AUTH_AUTHORIZED)
        rows = cs.selector_rows([a, b], b.appliance_id, a.appliance_id)
        assert [r.current for r in rows] == [False, True]

    def test_refused_row_is_never_current(self):
        a = _entry("A", auth=AUTH_UNAUTHORIZED)
        rows = cs.selector_rows([a], a.appliance_id, None)
        assert rows[0].current is False

    def test_returns_tuple_of_selector_rows(self):
        rows = cs.selector_rows([_entry("A", auth=AUTH_AUTHORIZED)], None, None)
        assert isinstance(rows, tuple) and isinstance(rows[0], cs.SelectorRow)
        assert cs.selector_rows([], None, None) == ()


class TestPickerRows:
    def test_only_held_authorized_capable(self):
        ok = _entry("Ok", auth=AUTH_AUTHORIZED, repeat_capable=True)
        notheld = _entry("NotHeld", auth=AUTH_AUTHORIZED, repeat_capable=True)
        incapable = _entry("Incapable", auth=AUTH_AUTHORIZED)
        refused = _entry("Refused", auth=AUTH_UNAUTHORIZED, repeat_capable=True)
        unknown = _entry("Unknown", auth=AUTH_UNKNOWN, repeat_capable=True)
        recs = {
            ok.appliance_id: _rec("hold", seconds=42.0),
            notheld.appliance_id: _rec("replaying"),
            incapable.appliance_id: _rec("hold"),
            refused.appliance_id: _rec("hold"),
            unknown.appliance_id: _rec("hold"),
        }
        seen = []

        def lookup(aid, now):
            seen.append(now)
            return recs.get(aid)

        rows = cs.picker_rows([ok, notheld, incapable, refused, unknown], lookup, 7.0)
        assert rows == (cs.PickerRow(ok.appliance_id, "Ok", ok.ip, ok.port, "Ok", 42.0),)
        assert set(seen) == {7.0}

    def test_no_record(self):
        e = _entry("A", auth=AUTH_AUTHORIZED, repeat_capable=True)
        assert cs.picker_rows([e], lambda a, n: None, 0.0) == ()


class TestIdleAffordance:
    def test_true_for_held_authorized_capable(self):
        e = _entry("A", auth=AUTH_AUTHORIZED, repeat_capable=True)
        assert cs.idle_affordance([e], {e.appliance_id}) is True

    @pytest.mark.parametrize("auth,capable,held", [
        (AUTH_UNKNOWN, True, True),
        (AUTH_UNAUTHORIZED, True, True),
        (AUTH_AUTHORIZED, False, True),
        (AUTH_AUTHORIZED, True, False),
    ])
    def test_false_otherwise(self, auth, capable, held):
        e = _entry("A", auth=auth, repeat_capable=capable)
        assert cs.idle_affordance([e], {e.appliance_id} if held else set()) is False

    def test_empty_roster(self):
        assert cs.idle_affordance([], {"x"}) is False


# ---- availability --------------------------------------------------------


class TestAvailability:
    def test_nothing_focused(self):
        e = _entry("A", dial_outputs=True, dial_eq=True)
        assert cs.availability([e], None, False, None) == (False, False, False)

    def test_focused_not_rostered(self):
        assert cs.availability([], "x", False, _rec()) == (True, False, False)

    def test_outputs_and_eq_from_the_entry(self):
        e = _entry("A", dial_outputs=True, dial_eq=True)
        assert cs.availability([e], e.appliance_id, False, None) == (True, True, True)

    def test_unauthorized_vetoes_outputs_and_eq(self):
        e = _entry("A", auth=AUTH_UNAUTHORIZED, dial_outputs=True, dial_eq=True)
        assert cs.availability([e], e.appliance_id, False, None) == (False, False, False)

    def test_unknown_auth_is_allowed(self):
        e = _entry("A", auth=AUTH_UNKNOWN, dial_outputs=True)
        assert cs.availability([e], e.appliance_id, False, None)[1] is True

    def test_compact_vetoes_eq_only(self):
        e = _entry("A", dial_outputs=True, dial_eq=True)
        assert cs.availability([e], e.appliance_id, True, None) == (False, True, False)

    def test_dots_from_an_available_repeat_record(self):
        e = _entry("A")
        assert cs.availability([e], e.appliance_id, False, _rec(available=True))[0] is True
        assert cs.availability([e], e.appliance_id, False, _rec(available=False))[0] is False

    def test_capability_flag_missing(self):
        e = _entry("A")
        assert cs.availability([e], e.appliance_id, False, None) == (False, False, False)

    def test_compact_callable_read_only_when_needed(self):
        calls = []

        def compact():
            calls.append(1)
            return False

        plain = _entry("A")
        assert cs.eq_available([plain], plain.appliance_id, compact) is False
        assert cs.eq_available([], None, compact) is False
        assert calls == []
        capable = _entry("B", dial_eq=True)
        assert cs.eq_available([capable], capable.appliance_id, compact) is True
        assert calls == [1]

    def test_dots_active_helper(self):
        assert cs.dots_active(None, False) is False
        assert cs.dots_active(None, True) is True
        assert cs.dots_active(_rec(available=True), False) is True
        assert cs.dots_active(_rec(available=False), False) is False


class TestApplianceStates:
    def test_webui_address_is_plain_http_on_the_roster_address(self):
        assert cs.webui_address("192.0.2.10", 80) == ("http", "192.0.2.10", 80)
        assert cs.webui_address("192.0.2.11", 8080) == ("http", "192.0.2.11", 8080)

    def test_one_state_per_roster_entry_in_roster_order(self):
        roster = [_entry("Kitchen", AUTH_AUTHORIZED, playing=True), _entry("Lounge")]
        states = cs.appliance_states(roster)
        assert [s.service_name for s in states] == ["Kitchen", "Lounge"]
        assert states[0].playing is True and states[1].playing is False
        assert states[0].auth == AUTH_AUTHORIZED
        assert (states[0].webui_scheme, states[0].webui_host, states[0].webui_port) == (
            "http", "192.0.2.10", 80,
        )

    def test_repeat_records_are_attached_by_id(self):
        roster = [_entry("Kitchen"), _entry("Lounge")]
        rec = RepeatRecord(True, "hold", False, 30.0, 0.0, 0.0, 1.0)
        states = cs.appliance_states(roster, {_id("Kitchen"): rec})
        assert states[0].repeat is rec and states[1].repeat is None

    def test_capability_versions_follow_the_flags(self):
        states = cs.appliance_states([_entry("Kitchen", dial_eq=True, dial_outputs=True), _entry("Lounge")])
        assert (states[0].dial_eq_version, states[0].dial_outputs_version) == (1, 1)
        assert (states[1].dial_eq_version, states[1].dial_outputs_version) == (0, 0)

    def test_state_appended_fields_have_defaults(self):
        snap_fields = {f.name for f in dataclasses.fields(cs.CoreSnapshot)}
        assert "dots_active" in snap_fields
        applied = {f.name: f for f in dataclasses.fields(cs.ApplianceState)}
        assert applied["webui_scheme"].default == "http"
        assert applied["webui_host"].default == ""
        assert applied["webui_port"].default == 0


# ---------------------------------------------------------------------------
# Appliance-supplied warnings: the validator over hostile replies
# ---------------------------------------------------------------------------

import json  # noqa: E402

TARGET = "a" * 20


def _reply(*warnings, appliance_id=TARGET, **extra):
    return {"appliance_id": appliance_id, "warnings": list(warnings), **extra}


def _warn(**kw):
    base = {"id": "stylus", "severity": "warning", "title": "Replace stylus",
            "message": "500 h played", "dismissal": "week"}
    base.update(kw)
    return base


def _validate(body, appliance_id=TARGET):
    return cs.validate_appliance_warnings(body, appliance_id)


class TestApplianceWarningValidator:
    def test_a_good_reply_comes_through_whole(self):
        (w,) = _validate(_reply(_warn()))
        assert w == cs.ApplianceWarning("stylus", "warning", "Replace stylus", "500 h played", "week")
        assert w.appliance_name == ""

    def test_raw_text_and_bytes_are_parsed(self):
        text = json.dumps(_reply(_warn()))
        assert len(_validate(text)) == 1
        assert len(_validate(text.encode())) == 1

    def test_an_oversized_body_is_refused_unparsed(self):
        body = json.dumps(_reply(_warn(message="x" * cs.APPLIANCE_WARNINGS_MAX_BODY_BYTES)))
        assert len(body) > cs.APPLIANCE_WARNINGS_MAX_BODY_BYTES
        assert _validate(body) == ()
        assert _validate(body.encode()) == ()

    def test_a_body_at_the_cap_is_still_read(self):
        good = json.dumps(_reply(_warn()))
        pad = " " * (cs.APPLIANCE_WARNINGS_MAX_BODY_BYTES - len(good))
        assert len(good + pad) == cs.APPLIANCE_WARNINGS_MAX_BODY_BYTES
        assert len(_validate(good + pad)) == 1

    def test_too_many_warnings_keeps_the_first_few(self):
        warnings = [_warn(id=f"w{i}", title=f"T{i}") for i in range(50)]
        out = _validate(_reply(*warnings))
        assert [w.id for w in out] == [f"w{i}" for i in range(cs.APPLIANCE_WARNINGS_MAX)]

    def test_a_list_padded_with_junk_is_scanned_only_so_far(self):
        junk = [None] * cs.APPLIANCE_WARNINGS_MAX_SCAN
        assert _validate(_reply(*junk, _warn())) == ()

    def test_long_strings_are_truncated_not_refused(self):
        (w,) = _validate(_reply(_warn(title="t" * 500, message="m" * 5000)))
        assert w.title == "t" * cs.APPLIANCE_WARNING_TITLE_MAX
        assert w.message == "m" * cs.APPLIANCE_WARNING_MESSAGE_MAX

    def test_control_characters_are_stripped(self):
        (w,) = _validate(_reply(_warn(title="Re\x00pl\x1bace\x7f stylus", message="a\x07b\x9fc")))
        assert w.title == "Replace stylus" and w.message == "abc"

    def test_white_space_controls_and_separators_become_one_space(self):
        (w,) = _validate(_reply(_warn(title="Replace\r\n\tstylus", message="one two three")))
        assert w.title == "Replace stylus"
        assert w.message == "one two three"

    @pytest.mark.parametrize("ch", [
        "‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨",
        "⁩", "‎", "‏", "؜", "​", "﻿",
    ])
    def test_bidi_and_format_characters_are_stripped(self, ch):
        (w,) = _validate(_reply(_warn(title=f"ab{ch}cd", message=f"{ch}x{ch}")))
        assert w.title == "abcd" and w.message == "x"

    def test_private_use_surrogate_and_unassigned_are_stripped(self):
        (w,) = _validate(_reply(_warn(title="ab\ud800c\U000e0080d")))
        assert w.title == "abcd"

    def test_text_is_normalised_to_nfc(self):
        (w,) = _validate(_reply(_warn(title="Café", message="Å")))
        assert w.title == "Café" and w.message == "Å"

    def test_a_stripped_character_between_a_base_and_a_mark_still_gives_nfc(self):
        (w,) = _validate(_reply(_warn(title="e​́x")))
        assert w.title == "éx"

    def test_a_title_empty_after_cleaning_drops_the_warning(self):
        assert _validate(_reply(_warn(title="‮\x00  "))) == ()
        assert _validate(_reply(_warn(title=None))) == ()
        assert _validate(_reply(_warn(title=7))) == ()
        assert _validate(_reply({"id": "x"})) == ()

    def test_a_missing_or_wrong_typed_message_is_empty(self):
        (a,) = _validate(_reply(_warn(message=None)))
        (b,) = _validate(_reply(_warn(message={"x": 1})))
        assert a.message == "" and b.message == ""

    @pytest.mark.parametrize("value", ["fatal", "", None, 3, ["critical"], {"a": 1}])
    def test_an_unknown_severity_takes_the_default(self, value):
        (w,) = _validate(_reply(_warn(severity=value)))
        assert w.severity == cs.APPLIANCE_WARNING_DEFAULT_SEVERITY == cs.SEVERITY_INFO

    @pytest.mark.parametrize("value", ["info", "warning", "critical", " Critical ", "WARNING"])
    def test_the_known_severities_are_kept(self, value):
        (w,) = _validate(_reply(_warn(severity=value)))
        assert w.severity == value.strip().lower()

    @pytest.mark.parametrize("value", ["forever", "", None, 9, "Week;rm"])
    def test_an_unknown_dismissal_hint_takes_the_default(self, value):
        (w,) = _validate(_reply(_warn(dismissal=value)))
        assert w.dismissal == cs.APPLIANCE_WARNING_DEFAULT_DISMISSAL == cs.DISMISS_DAY

    @pytest.mark.parametrize("value", ["day", "week", "none"])
    def test_the_known_dismissal_hints_are_kept(self, value):
        (w,) = _validate(_reply(_warn(dismissal=value)))
        assert w.dismissal == value

    @pytest.mark.parametrize("bad", [
        "", "Stylus", "has space", "a/b", "a:b", "../x", "a" * 33, "café", "x\n", "x\x00",
        "١", None, 5, ["a"], {"a": 1}, "a.b", "A",
    ])
    def test_an_invalid_id_drops_that_warning_only(self, bad):
        out = _validate(_reply(_warn(id=bad), _warn(id="ok", title="Fine")))
        assert [w.id for w in out] == ["ok"]

    @pytest.mark.parametrize("good", ["a", "a" * 32, "stylus-1", "a_b", "0", "-", "_"])
    def test_a_valid_id_is_kept(self, good):
        (w,) = _validate(_reply(_warn(id=good)))
        assert w.id == good

    def test_a_repeated_id_keeps_the_first(self):
        out = _validate(_reply(_warn(title="First"), _warn(title="Second")))
        assert [w.title for w in out] == ["First"]

    def test_a_body_for_another_appliance_is_refused(self):
        assert _validate(_reply(_warn(), appliance_id="b" * 20)) == ()
        assert _validate({"warnings": [_warn()]}) == ()
        assert _validate(_reply(_warn(), appliance_id=None)) == ()
        assert _validate(_reply(_warn(), appliance_id=123)) == ()
        assert _validate(_reply(_warn(), appliance_id=TARGET.upper())) == ()

    @pytest.mark.parametrize("target", ["", None, 5, ["x"]])
    def test_a_missing_target_id_refuses_everything(self, target):
        assert cs.validate_appliance_warnings(_reply(_warn(), appliance_id=target), target) == ()

    @pytest.mark.parametrize("body", [
        None, 0, 1.5, True, [], ["x"], "", "not json", "null", "[]", "[1,2]", '"str"', "{",
        b"\xff\xfe\x00", b"", {}, {"appliance_id": TARGET},
        {"appliance_id": TARGET, "warnings": None},
        {"appliance_id": TARGET, "warnings": "x"}, {"appliance_id": TARGET, "warnings": {"a": 1}},
        {"appliance_id": TARGET, "warnings": 5},
    ])
    def test_garbage_shapes_give_nothing(self, body):
        assert _validate(body) == ()

    def test_entries_that_are_not_objects_are_skipped(self):
        out = _validate(_reply(None, 5, "x", ["id"], [], _warn()))
        assert [w.id for w in out] == ["stylus"]

    def test_deeply_nested_json_is_refused_not_raised(self):
        body = "[" * 3000 + "]" * 3000
        assert _validate(body) == ()
        assert _validate('{"appliance_id": "%s", "warnings": %s}' % (TARGET, body)) == ()

    def test_extra_keys_are_ignored(self):
        (w,) = _validate(_reply(_warn(priority=999, interrupting=True, wake=True, url="http://x"),
                                priority=1, wake=True))
        assert not hasattr(w, "priority") and not hasattr(w, "interrupting")

    def test_hostile_text_is_data_never_interpreted(self):
        (w,) = _validate(_reply(_warn(title="{percent} %s ${x}", message="<b>x</b>; rm -rf /")))
        assert w.title == "{percent} %s ${x}"
        assert w.message == "<b>x</b>; rm -rf /"

    def test_it_never_raises_on_odd_objects(self):
        class Boom(dict):
            def get(self, *a):
                raise RuntimeError("no")
        assert _validate(Boom()) == ()

    def test_attribution_replaces_whatever_the_appliance_claimed(self):
        out = _validate(_reply(_warn(appliance_name="Spoofed", id="a", title="t"), _warn(id="b")))
        named = cs.attribute_appliance_warnings(out, "Kitchen")
        assert [w.appliance_name for w in named] == ["Kitchen", "Kitchen"]
        assert all(w.appliance_name == "" for w in out)


class TestApplianceWarningsSlot:
    def test_an_appliance_supplies_no_warnings_by_default(self):
        (state,) = cs.appliance_states([_entry()])
        assert state.supplies_warnings is False
        assert state.warnings == ()

    def test_the_capability_flag_reads_the_entry(self):
        entry = _entry()
        object.__setattr__(entry, "dial_warnings", True)
        (state,) = cs.appliance_states([entry])
        assert state.supplies_warnings is True

    def test_warnings_are_slotted_by_appliance_id(self):
        a, b = _entry("Kitchen"), _entry("Lounge")
        w = cs.ApplianceWarning("x", "info", "T", "", "day", "Lounge")
        first, second = cs.appliance_states([a, b], None, {b.appliance_id: (w,)})
        assert first.warnings == () and second.warnings == (w,)

    def test_new_fields_are_appended(self):
        names = [f.name for f in dataclasses.fields(cs.ApplianceState)]
        assert names[-2:] == ["supplies_warnings", "warnings"]
