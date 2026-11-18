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

import dial_appliance_warnings as aw  # noqa: E402
import dial_core_focus as cf  # noqa: E402
import dial_core_state as cs  # noqa: E402
from dial_core_state import AUTH_AUTHORIZED, AUTH_UNAUTHORIZED, AUTH_UNKNOWN  # noqa: E402
from dial_mdns import PlayingTarget  # noqa: E402
from dial_test_support import RosterEntry  # noqa: E402
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

    def test_frozen(self):
        classes = (
            cs.NowPlaying, cs.OutputRow, cs.SelectorRow, cs.PickerRow, cs.ApplianceState,
            cs.FocusState, cs.Artwork, cs.OutputsState, cs.EqBand, cs.EqState,
            cs.WarningState, cs.TransportRequest, cs.DialInfo, cs.CoreSnapshot,
            cf.FocusResolution, cf.Selection,
        )
        not_frozen = [cls.__name__ for cls in classes if not cls.__dataclass_params__.frozen]
        assert not not_frozen, f"not frozen: {not_frozen}"

    @pytest.mark.parametrize(
        "name", ["dial_core_state.py", "dial_core_focus.py", "dial_appliance_warnings.py",
                 "dial_core_effects.py", "dial_core_model.py"])
    def test_a_pure_core_module_imports_no_display_thread_clock_or_volume_worker(self, name):
        src = (REPO_ROOT / "dial" / name).read_text(encoding="utf-8")
        assert "dial_display" not in src
        assert "import threading" not in src and "import time" not in src
        assert "from dial_volume" not in src and "import dial_volume" not in src


def _appliance(aid, **kw) -> cs.ApplianceState:
    base = dict(
        appliance_id=aid, service_name=aid, name=aid, ip="192.0.2.1", port=80,
        playing=False, playing_since=0.0, auth=AUTH_AUTHORIZED, dial_status=True,
        dial_outputs=False, dial_eq=False, repeat_capable=False, dial_proto_version=2,
        dial_outputs_version=0, status_error=None,
        master_volume=None, muted=None, repeat=None,
    )
    base.update(kw)
    return cs.ApplianceState(**base)


def _snapshot(appliances, manual=None, reporting=None) -> cs.CoreSnapshot:
    return cs.CoreSnapshot(
        seq=1, at=0.0, polling=True, appliances=tuple(appliances),
        focus=cs.FocusState(manual, None, None, reporting, None, None, False),
        now_playing=None, artwork=None, idle_affordance=False, outputs=None, eq=None,
        outputs_available=False, eq_available=False, warnings=(), due_status_id=None,
        network=None, wifi_ever_connected=False, sd_health=None, update=None,
        transport=None,
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


# ---- visible_targets ----------------------------------------------------


class TestVisibleTargets:
    def test_drops_unauthorized_and_identity_less(self):
        keep = _target("Keep", auth=AUTH_AUTHORIZED)
        unknown = _target("Unknown", auth=AUTH_UNKNOWN)
        refused = _target("Refused", auth=AUTH_UNAUTHORIZED)
        anon = _target("Anon", appliance_id="")
        assert cf.visible_targets([keep, refused, anon, unknown]) == [keep, unknown]

    def test_empty(self):
        assert cf.visible_targets([]) == []


# ---- resolve_focus -------------------------------------------------------


def _auth_of(state):
    return lambda appliance_id: state


class TestResolveFocus:
    def test_no_focus(self):
        a = _target("A")
        res = cf.resolve_focus(None, None, [_entry("A", playing=True)], [a], set(), 0.0,
                               _auth_of(AUTH_UNKNOWN))
        assert res == cf.FocusResolution(None, None, None, None, None, None)

    def test_focus_on_playing_target(self):
        a = _target("A")
        e = _entry("A", playing=True)
        res = cf.resolve_focus(a.appliance_id, None, [e], [a], set(), 0.0, _auth_of(AUTH_UNKNOWN))
        assert res.manual_id == a.appliance_id
        assert res.focus_entry is e and res.focus_target is a
        assert res.idle_focus is None and res.clear_reason is None

    def test_idle_focus_kept_while_something_else_plays(self):
        b = _target("B")
        idle = _entry("Idle")
        res = cf.resolve_focus(idle.appliance_id, None, [idle, _entry("B", playing=True)], [b],
                               set(), 0.0, _auth_of(AUTH_UNKNOWN))
        assert res.focus_entry is idle and res.focus_target is None
        assert res.idle_focus is idle and res.clear_reason is None
        assert res.manual_id == idle.appliance_id

    def test_gone_from_roster_clears(self):
        res = cf.resolve_focus("x" * 20, None, [_entry("A")], [], set(), 0.0, _auth_of(AUTH_UNKNOWN))
        assert res.clear_reason == "appliance gone or unauthorized"
        assert res.manual_id is None and res.focus_entry is None and res.idle_focus is None

    def test_unauthorized_roster_entry_clears(self):
        e = _entry("A", auth=AUTH_UNAUTHORIZED)
        res = cf.resolve_focus(e.appliance_id, None, [e], [], set(), 0.0, _auth_of(AUTH_UNAUTHORIZED))
        assert res.clear_reason == "appliance gone or unauthorized"

    def test_stopped_focus_clears(self):
        e = _entry("A")
        res = cf.resolve_focus(e.appliance_id, None, [e], [], {e.appliance_id}, 0.0,
                               _auth_of(AUTH_UNKNOWN))
        assert res.clear_reason == "appliance stopped playing"
        assert res.manual_id is None and res.focus_entry is None and res.idle_focus is None

    def test_playing_focus_that_is_in_stopped_ids_is_not_cleared(self):
        # Present in the visible set this tick, so it did not stop.
        a = _target("A")
        e = _entry("A", playing=True)
        res = cf.resolve_focus(a.appliance_id, None, [e], [a], {a.appliance_id}, 0.0,
                               _auth_of(AUTH_UNKNOWN))
        assert res.clear_reason is None and res.focus_target is a

    def test_pending_grace_keeps_unrostered_focus(self):
        pending = ("p" * 20, "Pend", 10.0)
        res = cf.resolve_focus("p" * 20, pending, [], [], set(), 5.0, _auth_of(AUTH_UNKNOWN))
        assert res.clear_reason is None
        assert res.manual_id == "p" * 20 and res.pending == pending
        assert res.focus_entry is None and res.idle_focus is None

    def test_pending_grace_not_for_confirmed_unauthorized(self):
        pending = ("p" * 20, "Pend", 10.0)
        res = cf.resolve_focus("p" * 20, pending, [], [], set(), 5.0, _auth_of(AUTH_UNAUTHORIZED))
        assert res.clear_reason == "appliance gone or unauthorized"
        assert res.pending is None

    def test_pending_expired(self):
        pending = ("p" * 20, "Pend", 10.0)
        res = cf.resolve_focus("p" * 20, pending, [], [], set(), 10.0, _auth_of(AUTH_UNKNOWN))
        assert res.pending is None
        assert res.clear_reason == "appliance gone or unauthorized"

    def test_pending_for_a_different_focus_is_dropped(self):
        e = _entry("A")
        pending = ("p" * 20, "Pend", 100.0)
        res = cf.resolve_focus(e.appliance_id, pending, [e], [], set(), 1.0, _auth_of(AUTH_UNKNOWN))
        assert res.pending is None and res.clear_reason is None
        assert res.idle_focus is e

    def test_pending_converts_when_sighted_playing(self):
        a = _target("A")
        e = _entry("A", playing=True)
        pending = (a.appliance_id, "A", 100.0)
        res = cf.resolve_focus(a.appliance_id, pending, [e], [a], set(), 1.0, _auth_of(AUTH_UNKNOWN))
        assert res.pending is None and res.focus_target is a and res.clear_reason is None

    def test_pending_kept_while_rostered_but_idle(self):
        e = _entry("A")
        pending = (e.appliance_id, "A", 100.0)
        res = cf.resolve_focus(e.appliance_id, pending, [e], [], set(), 1.0, _auth_of(AUTH_UNKNOWN))
        assert res.pending == pending and res.idle_focus is e

    def test_auth_state_only_read_for_the_grace_check(self):
        calls = []

        def auth_state(aid):
            calls.append(aid)
            return AUTH_UNKNOWN

        e = _entry("A")
        cf.resolve_focus(e.appliance_id, None, [e], [], set(), 0.0, auth_state)
        assert calls == []


# ---- choose_pin / walk_order --------------------------------------------


class TestChoosePin:
    def test_focus_target_wins(self):
        a, b = _target("A"), _target("B")
        pin, bound = cf.choose_pin(a, b.appliance_id, [a, b])
        assert pin is a and bound == b.appliance_id

    def test_bound_target_pins_when_no_focus(self):
        a, b = _target("A"), _target("B")
        pin, bound = cf.choose_pin(None, b.appliance_id, [a, b])
        assert pin is b and bound == b.appliance_id

    def test_bound_target_gone_is_released(self):
        a = _target("A")
        pin, bound = cf.choose_pin(None, "gone" + "0" * 16, [a])
        assert pin is None and bound is None

    def test_nothing_bound(self):
        a = _target("A")
        assert cf.choose_pin(None, None, [a]) == (None, None)

    def test_no_lookup_when_caller_passes_no_binding(self):
        a = _target("A")
        assert cf.choose_pin(None, None, []) == (None, None)


class TestWalkOrder:
    def test_unpinned_is_unchanged(self):
        vis = [_target("A"), _target("B")]
        assert cf.walk_order(None, vis) is vis

    def test_pin_goes_first_rest_keep_order(self):
        a, b, c = _target("A"), _target("B"), _target("C")
        assert cf.walk_order(c, [a, b, c]) == [c, a, b]
        assert cf.walk_order(a, [a, b, c]) == [a, b, c]


# ---- the walk ------------------------------------------------------------


class TestWalkStep:
    def test_unpinned_artwork_stops_the_walk(self):
        t = _target("A")
        sel, fb = cf.walk_step(t, _track(), False, None)
        assert sel == cf.Selection("https://provider.example/a.jpg", "A", "A", "T", "L")
        assert fb is None

    def test_unpinned_status_error_skips(self):
        t = _target("A")
        assert cf.walk_step(t, None, False, None) == (None, None)

    def test_unpinned_not_identified_continues(self):
        t = _target("A")
        assert cf.walk_step(t, {"track_id": {"state": "searching"}}, False, None) == (None, None)
        assert cf.walk_step(t, {}, False, None) == (None, None)

    def test_unpinned_identified_without_art_sets_fallback_once(self):
        a, b = _target("A"), _target("B")
        sel, fb = cf.walk_step(a, _track(artwork=None), False, None)
        assert sel is None and fb[0] == "A"
        sel, fb2 = cf.walk_step(b, _track(artwork=None, title="Other"), False, fb)
        assert sel is None and fb2 is fb

    def test_pinned_with_artwork(self):
        t = _target("A")
        sel, _ = cf.walk_step(t, _track(), True, None)
        assert sel.url == "https://provider.example/a.jpg" and sel.service == "A"

    def test_pinned_identified_without_art_still_shows_text(self):
        t = _target("A")
        sel, _ = cf.walk_step(t, _track(artwork=None), True, None)
        assert sel == cf.Selection(None, "A", "A", "T", "L")

    def test_pinned_empty_artwork_url_is_none(self):
        t = _target("A")
        sel, _ = cf.walk_step(t, _track(artwork=""), True, None)
        assert sel.url is None and sel.title == "T"

    def test_pinned_not_identified_keeps_service_only(self):
        t = _target("A")
        sel, _ = cf.walk_step(t, {"track_id": {"state": "searching"}}, True, None)
        assert sel == cf.Selection(service="A")

    def test_pinned_with_status_error_keeps_selected_service(self):
        t = _target("A")
        sel, _ = cf.walk_step(t, None, True, None)
        assert sel == cf.Selection(service="A")

    def test_missing_text_fields_default_empty(self):
        t = _target("A")
        rec = {"track_id": {"state": "identified", "artwork_url": "u"}}
        sel, _ = cf.walk_step(t, rec, False, None)
        assert (sel.artist, sel.title, sel.album) == ("", "", "")


class TestWalkFallback:
    def test_none(self):
        assert cf.walk_fallback(None) == cf.Selection()

    def test_first_identified_without_art(self):
        fb = ("A", {"artist": "X", "title": "Y", "album": "Z"})
        assert cf.walk_fallback(fb) == cf.Selection(None, "A", "X", "Y", "Z")


class TestSelectFromRecords:
    def test_artwork_beats_earlier_text_only(self):
        a, b = _target("A"), _target("B")
        recs = {"A": _track(artwork=None), "B": _track(artwork="u2", title="B title")}
        sel = cf.select_from_records([a, b], recs, None)
        assert sel.service == "B" and sel.url == "u2" and sel.title == "B title"

    def test_text_only_fallback_when_no_artwork_anywhere(self):
        a, b = _target("A"), _target("B")
        recs = {"A": {"track_id": {"state": "searching"}}, "B": _track(artwork=None)}
        sel = cf.select_from_records([a, b], recs, None)
        assert sel == cf.Selection(None, "B", "A", "T", "L")

    def test_nothing_identified(self):
        a = _target("A")
        assert cf.select_from_records([a], {"A": {}}, None) == cf.Selection()

    def test_empty_walk(self):
        assert cf.select_from_records([], {}, None) == cf.Selection()

    def test_pinned_target_stops_the_walk(self):
        a, b = _target("A"), _target("B")
        recs = {"A": {}, "B": _track()}
        sel = cf.select_from_records(cf.walk_order(a, [a, b]), recs, a)
        assert sel == cf.Selection(service="A")

    def test_pinned_with_status_error_keeps_selected_service(self):
        a, b = _target("A"), _target("B")
        sel = cf.select_from_records([a, b], {"B": _track()}, a)
        assert sel == cf.Selection(service="A")

    def test_unpinned_status_error_skipped_to_next(self):
        a, b = _target("A"), _target("B")
        sel = cf.select_from_records([a, b], {"B": _track()}, None)
        assert sel.service == "B"

    def test_unauthorized_skipped(self):
        a = _target("A", auth=AUTH_UNAUTHORIZED)
        b = _target("B")
        sel = cf.select_from_records([a, b], {"A": _track(), "B": _track(artwork="ub")}, None)
        assert sel.service == "B" and sel.url == "ub"

    def test_unsupported_target_skipped_when_unpinned(self):
        a = _target("A", dial_status=False)
        b = _target("B")
        sel = cf.select_from_records([a, b], {"B": _track()}, None)
        assert sel.service == "B"

    def test_unsupported_pinned_target_selected_by_name(self):
        a = _target("A", dial_status=False)
        b = _target("B")
        sel = cf.select_from_records([a, b], {"B": _track()}, a)
        assert sel == cf.Selection(service="A")

    def test_matches_stepwise_walk(self):
        targets = [_target("A"), _target("B"), _target("C")]
        recs = {"A": _track(artwork=None, title="a"), "C": _track(artwork="uc")}
        fb = None
        out = None
        for t in targets:
            out, fb = cf.walk_step(t, recs.get(t.service_name), False, fb)
            if out is not None:
                break
        else:
            out = cf.walk_fallback(fb)
        assert out == cf.select_from_records(targets, recs, None)


# ---- reporting_for -------------------------------------------------------


class TestReportingFor:
    def test_idle_focus_wins(self):
        idle = _entry("Idle")
        assert cf.reporting_for(idle, [_target("A")], "A") is idle

    def test_selected_service_among_visible(self):
        a, b = _target("A"), _target("B")
        assert cf.reporting_for(None, [a, b], "B") is b

    def test_falls_back_to_first_visible(self):
        a, b = _target("A"), _target("B")
        assert cf.reporting_for(None, [a, b], None) is a
        assert cf.reporting_for(None, [a, b], "missing") is a

    def test_none_when_nothing_visible(self):
        assert cf.reporting_for(None, [], None) is None


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


# ---------------------------------------------------------------------------
# Appliance-supplied warnings: the validator over hostile replies
# ---------------------------------------------------------------------------

TARGET = "a" * 20


def _reply(*warnings, appliance_id=TARGET, **extra):
    return {"appliance_id": appliance_id, "warnings": list(warnings), **extra}


def _warn(**kw):
    base = {"id": "stylus", "severity": "warning", "title": "Replace stylus",
            "message": "500 h played"}
    base.update(kw)
    return base


def _validate(body):
    return aw.appliance_warning_entries(body["warnings"], aw.APPLIANCE_WARNINGS_MAX)


class TestApplianceWarningValidator:
    def test_a_good_reply_comes_through_whole(self):
        (w,) = _validate(_reply(_warn()))
        assert w == aw.ApplianceWarning("stylus", "warning", "Replace stylus", "500 h played")
        assert w.appliance_name == ""

    def test_too_many_warnings_keeps_the_first_few(self):
        warnings = [_warn(id=f"w{i}", title=f"T{i}") for i in range(50)]
        out = _validate(_reply(*warnings))
        assert [w.id for w in out] == [f"w{i}" for i in range(aw.APPLIANCE_WARNINGS_MAX)]

    def test_a_list_padded_with_junk_is_scanned_only_so_far(self):
        junk = [None] * (4 * aw.APPLIANCE_WARNINGS_MAX)
        assert _validate(_reply(*junk, _warn())) == ()

    def test_long_strings_are_truncated_not_refused(self):
        (w,) = _validate(_reply(_warn(title="t" * 500, message="m" * 5000)))
        assert w.title == "t" * aw.APPLIANCE_WARNING_TITLE_MAX
        assert w.message == "m" * aw.APPLIANCE_WARNING_MESSAGE_MAX

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
        assert w.severity == aw.APPLIANCE_WARNING_DEFAULT_SEVERITY == aw.SEVERITY_INFO

    @pytest.mark.parametrize("value", ["info", "warning", "critical", " Critical ", "WARNING"])
    def test_the_known_severities_are_kept(self, value):
        (w,) = _validate(_reply(_warn(severity=value)))
        assert w.severity == value.strip().lower()

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

    def test_entries_that_are_not_objects_are_skipped(self):
        out = _validate(_reply(None, 5, "x", ["id"], [], _warn()))
        assert [w.id for w in out] == ["stylus"]

    def test_extra_keys_are_ignored(self):
        (w,) = _validate(_reply(_warn(priority=999, interrupting=True, wake=True, url="http://x"),
                                priority=1, wake=True))
        assert not hasattr(w, "priority") and not hasattr(w, "interrupting")

    def test_hostile_text_is_data_never_interpreted(self):
        (w,) = _validate(_reply(_warn(title="{percent} %s ${x}", message="<b>x</b>; rm -rf /")))
        assert w.title == "{percent} %s ${x}"
        assert w.message == "<b>x</b>; rm -rf /"

    def test_attribution_replaces_whatever_the_appliance_claimed(self):
        out = _validate(_reply(_warn(appliance_name="Spoofed", id="a", title="t"), _warn(id="b")))
        named = aw.attribute_appliance_warnings(out, "Kitchen")
        assert [w.appliance_name for w in named] == ["Kitchen", "Kitchen"]
        assert all(w.appliance_name == "" for w in out)
        names = [f.name for f in dataclasses.fields(cs.ApplianceState)]
        assert names[-1] == "warnings"


def _request(kind, state, error=None, changed_at=100.0):
    return cs.TransportRequest(
        "a" * 20, kind, changed_at, state, changed_at, error, "o2", 0)


class TestAwaitingPin:
    def test_a_pending_pin_is_awaited_and_a_pending_set_is_not(self):
        assert cs.awaiting_pin(_request("output_pin", "pending"), 101.0) is True
        assert cs.awaiting_pin(_request("output_set", "pending"), 101.0) is False

    def test_a_set_rejected_asking_for_a_pin_is_awaited_within_the_window(self):
        for error in ("pin_required", "pin_invalid"):
            request = _request("output_set", "rejected", error)
            assert cs.awaiting_pin(request, 100.0) is True
            assert cs.awaiting_pin(request, 100.0 + cs.PIN_WINDOW_S - 0.01) is True
            assert cs.awaiting_pin(request, 100.0 + cs.PIN_WINDOW_S) is False

    def test_a_rejected_pin_attempt_is_awaited_whatever_the_reason(self):
        for error in ("rate_limited", "unreachable", "backend_error", "output_in_use"):
            request = _request("output_pin", "rejected", error)
            assert cs.awaiting_pin(request, 150.0) is True
            assert cs.awaiting_pin(request, 100.0 + cs.PIN_WINDOW_S) is False

    def test_a_rejected_set_for_another_reason_is_not_awaited(self):
        assert cs.awaiting_pin(_request("output_set", "rejected", "output_in_use"), 101.0) is False
        assert cs.awaiting_pin(_request("output_set", "rejected", "rate_limited"), 101.0) is False
        assert cs.awaiting_pin(_request("output_set", "rejected", None), 101.0) is False

    def test_an_accepted_request_is_not_awaited(self):
        assert cs.awaiting_pin(_request("output_pin", "accepted"), 101.0) is False

    def test_other_request_kinds_and_no_request_are_not_awaited(self):
        assert cs.awaiting_pin(_request("seek", "rejected", "pin_required"), 101.0) is False
        assert cs.awaiting_pin(_request("seek", "pending"), 101.0) is False
        assert cs.awaiting_pin(None, 101.0) is False

    def test_the_window_ends_a_window_after_the_request_changed_on_the_outputs_lane_only(self):
        assert cs.pin_window_end(_request("output_set", "rejected", "pin_required")) == 100.0 + cs.PIN_WINDOW_S
        assert cs.pin_window_end(_request("output_pin", "pending", changed_at=130.0)) == 130.0 + cs.PIN_WINDOW_S
        assert cs.pin_window_end(_request("seek", "rejected", "pin_required")) is None
        assert cs.pin_window_end(None) is None

    def test_a_pin_is_wanted_by_kind_state_and_error_whatever_the_time(self):
        table = [
            (_request("output_pin", "pending"), True),
            (_request("output_set", "pending"), False),
            (_request("output_set", "rejected", "pin_required"), True),
            (_request("output_set", "rejected", "pin_invalid"), True),
            (_request("output_set", "rejected", "output_in_use"), False),
            (_request("output_pin", "rejected", "rate_limited"), True),
            (_request("output_pin", "accepted"), False),
            (_request("seek", "rejected", "pin_required"), False),
            (None, False),
        ]
        for request, wanted in table:
            assert cs.pin_wanted(request) is wanted, request

    def test_a_pending_pin_is_awaited_past_the_window(self):
        assert cs.awaiting_pin(_request("output_pin", "pending"), 100.0 + cs.PIN_WINDOW_S + 50) is True

    def test_the_pin_rule_is_four_to_eight_ascii_digits(self):
        for good in ("1234", "12345678", "0000"):
            assert cs.PIN_RE.match(good)
        for bad in ("123", "123456789", "12a4", "1234\n", " 1234", "１２３４", ""):
            assert not cs.PIN_RE.match(bad)


class TestAwaitingTitle:
    @pytest.mark.parametrize("playing,title,expected", [
        (True, "", True), (True, "Tunnel of Love", False), (False, "", False), (False, "x", False),
    ])
    def test_only_a_playing_appliance_with_no_title_is_awaiting_one(self, playing, title, expected):
        now_playing = cs.NowPlaying("Lounge", "Dire Straits", title, 42, playing=playing)
        assert cs.awaiting_title(now_playing) is expected

    def test_nothing_held_is_not_awaiting_a_title(self):
        assert cs.awaiting_title(None) is False

    def test_the_word_for_it_is_playing(self):
        assert cs.PLAYING_TEXT == "Playing"


class TestTitleFallback:
    def test_the_input_label_wins_while_a_title_is_awaited(self):
        now_playing = cs.NowPlaying("Lounge", "", "", 42, input_label="CD")
        assert cs.title_fallback(now_playing) == "CD"

    def test_the_fixed_word_without_a_label(self):
        assert cs.title_fallback(cs.NowPlaying("Lounge", "", "", 42)) == "Playing"

    def test_empty_for_a_titled_track_even_with_a_label(self):
        now_playing = cs.NowPlaying("Lounge", "", "Tunnel of Love", 42, input_label="CD")
        assert cs.title_fallback(now_playing) == ""

    def test_empty_when_not_playing(self):
        now_playing = cs.NowPlaying("Lounge", "", "", 42, playing=False, input_label="CD")
        assert cs.title_fallback(now_playing) == ""

    def test_empty_for_nothing_held(self):
        assert cs.title_fallback(None) == ""


def test_six_band():
    assert [cs.six_band(v) for v in (0, 1, 2, 3)] == [False, False, True, True]


def test_pin_capable_outputs():
    assert [cs.pin_capable_outputs(v) for v in (0, 1, 2, 3)] == [False, False, True, True]


def _failure(**fields):
    base = {"seq": 3, "boot": "b1", "unit_id": "1001", "name": "Speaker A",
            "reason": "refused", "mine": True, "age_s": 4}
    base.update(fields)
    return base


class TestParseStartFailure:
    def test_a_good_object(self):
        assert cs.parse_start_failure(_failure()) == cs.StartFailureReport(
            "b1", 3, "1001", "Speaker A", "refused", True, 4)

    @pytest.mark.parametrize("raw", [
        None, "x", [], {},
        _failure(seq=0), _failure(seq=True), _failure(seq="3"), _failure(seq=None),
        _failure(age_s=-1), _failure(age_s=True), _failure(age_s=1.5), _failure(age_s=None),
        _failure(reason="x" * 33), _failure(reason="Refused"), _failure(reason=""), _failure(reason=3),
        _failure(boot="has space"), _failure(boot=""), _failure(boot=None), _failure(boot="b" * 65),
        _failure(unit_id="a/b"), _failure(unit_id=7),
        _failure(mine="yes"), _failure(name=None), _failure(name=5),
    ])
    def test_a_malformed_object_is_none(self, raw):
        assert cs.parse_start_failure(raw) is None

    def test_mine_absent_reads_false(self):
        raw = _failure()
        del raw["mine"]
        assert cs.parse_start_failure(raw).mine is False

    def test_a_long_name_is_cleaned_and_capped(self):
        report = cs.parse_start_failure(_failure(name="  A‮B\u0007" + "x" * 200))
        assert len(report.name) <= cs.START_FAILURE_NAME_MAX
        assert "‮" not in report.name and "\u0007" not in report.name


def _report(**fields):
    return cs.parse_start_failure(_failure(**fields))


def _set_request(state, output_id="1001", appliance_id="a" * 20, kind="output_set"):
    return cs.TransportRequest(appliance_id, kind, 100.0, state, 100.0, None, output_id, 0)


def _action(report, seen=None, request=None):
    return cs.start_failure_action(report, seen, appliance_id="a" * 20, request=request)


class TestStartFailureAction:
    def test_no_report_is_seen(self):
        assert _action(None) == cs.FAILURE_SEEN

    def test_the_same_boot_at_or_above_the_seq_is_seen(self):
        assert _action(_report(), ("b1", 3)) == cs.FAILURE_SEEN
        assert _action(_report(), ("b1", 7)) == cs.FAILURE_SEEN

    def test_a_new_boot_is_not_seen_whatever_the_seq(self):
        assert _action(_report(seq=1), ("b0", 7)) == cs.FAILURE_NOTICE

    def test_a_higher_seq_is_not_seen(self):
        assert _action(_report(seq=4), ("b1", 3)) == cs.FAILURE_NOTICE

    def test_another_clients_failure_is_marked(self):
        assert _action(_report(mine=False)) == cs.FAILURE_MARK
        assert _action(_report(mine=False, reason="pin_required"),
                       request=_set_request("accepted")) == cs.FAILURE_MARK

    def test_a_pin_request_after_an_accepted_reply_reopens(self):
        assert _action(_report(reason="pin_required"),
                       request=_set_request("accepted")) == cs.FAILURE_PIN

    def test_a_pin_request_has_no_age_rule(self):
        assert _action(_report(reason="pin_required", age_s=500),
                       request=_set_request("accepted")) == cs.FAILURE_PIN

    def test_a_pin_request_while_the_reply_is_pending_defers(self):
        assert _action(_report(reason="pin_required"),
                       request=_set_request("pending")) == cs.FAILURE_DEFER

    def test_a_pin_request_the_reply_already_asked_is_marked(self):
        assert _action(_report(reason="pin_required"),
                       request=_set_request("rejected")) == cs.FAILURE_MARK

    @pytest.mark.parametrize("request_", [
        None,
        _set_request("accepted", output_id="1002"),
        _set_request("accepted", appliance_id="b" * 20),
        _set_request("accepted", kind="output_pin"),
        _set_request("accepted", kind="seek"),
    ])
    def test_a_pin_request_for_another_request_is_marked(self, request_):
        assert _action(_report(reason="pin_required"), request=request_) == cs.FAILURE_MARK

    def test_a_wrong_pin_is_marked(self):
        assert _action(_report(reason="pin_invalid"),
                       request=_set_request("accepted")) == cs.FAILURE_MARK

    def test_an_old_failure_is_marked(self):
        assert _action(_report(age_s=cs.START_FAILURE_MAX_AGE_S)) == cs.FAILURE_NOTICE
        assert _action(_report(age_s=cs.START_FAILURE_MAX_AGE_S + 1)) == cs.FAILURE_MARK

    def test_a_fresh_failure_of_the_dials_own_raises_the_notice(self):
        assert _action(_report()) == cs.FAILURE_NOTICE
        assert _action(_report(reason="mystery")) == cs.FAILURE_NOTICE


def test_reopen_for_pin_keeps_the_identity_and_moves_the_window():
    request = cs.TransportRequest("a" * 20, "output_set", 100.0, "accepted", 101.0, None, "1001", 0,
                                  (True, 40))
    reopened = cs.reopen_for_pin(request, 150.0)
    assert (reopened.state, reopened.error, reopened.changed_at, reopened.shown) == (
        "rejected", "pin_required", 150.0, None)
    assert (reopened.requested_at, reopened.output_id, reopened.appliance_id, reopened.kind) == (
        100.0, "1001", "a" * 20, "output_set")
    assert cs.awaiting_pin(reopened, 150.0 + cs.PIN_WINDOW_S - 1)
    assert not cs.awaiting_pin(reopened, 150.0 + cs.PIN_WINDOW_S)
