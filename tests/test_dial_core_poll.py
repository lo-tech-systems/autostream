"""Tests for dial_core_poll.py: the poll tick's I/O steps, driven with
injected fetchers and clocks. No display, no network."""
from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
for _p in (str(REPO_ROOT / "dial"), str(REPO_ROOT / "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import dial_core_poll as cp  # noqa: E402
from dial_core_state import artwork_key  # noqa: E402
import dial_repeat_store as drs  # noqa: E402
from dial_auth import (  # noqa: E402
    AUTH_AUTHORIZED, AUTH_UNAUTHORIZED, AUTH_UNKNOWN, OUTCOME_AUTHORIZED, auth_map,
)
from dial_mdns import PlayingTarget, RosterEntry  # noqa: E402


def _id(name: str) -> str:
    return (name.encode().hex() + "0" * 20)[:20]


def _target(name="Kitchen", auth=AUTH_UNKNOWN, dial_status=True, proto=2,
            playing_since=100.0) -> PlayingTarget:
    return PlayingTarget(
        ip="192.0.2.10", port=80, name=name, dial_api=True, audio_status=True,
        dial_status=dial_status, service_name=name, playing_since=playing_since,
        appliance_id=_id(name), auth=auth, dial_proto_version=proto,
    )


def _entry(name="Idle", playing=False, dial_status=True, repeat_capable=False,
           dial_outputs=False, dial_eq=False, proto=2) -> RosterEntry:
    return RosterEntry(
        appliance_id=_id(name), service_name=name, name=name, ip="192.0.2.11", port=80,
        playing=playing, repeat_capable=repeat_capable, dial_api=True, audio_status=True,
        dial_status=dial_status, dial_outputs=dial_outputs, dial_eq=dial_eq,
        dial_proto_version=proto,
    )


def _ok(appliance_id=None, **extra) -> dict:
    return {"status_error": None, "appliance_id": appliance_id, "master_volume": 40,
            "muted": False, **extra}


def _refusal(appliance_id=None, **extra) -> dict:
    return {"status_error": "unauthorized", "appliance_id": appliance_id, **extra}


def _track(title="T", artwork="https://provider.example/a.jpg") -> dict:
    return {"state": "identified", "title": title, "artist": "A", "album": "L",
            "artwork_url": artwork}


class _Fetcher:
    """Stub for fetch_target_status: replies by service name, records calls."""

    def __init__(self, replies: dict):
        self.replies = replies
        self.calls: list[str] = []
        self.asked: list[tuple] = []

    def __call__(self, target, dial_id, timeout_seconds=None):
        self.calls.append(target.service_name)
        self.asked.append((target.service_name, dial_id, timeout_seconds))
        return self.replies[target.service_name]


class _Clock:
    def __init__(self, t=10.0, step=0.0):
        self.t = t
        self.step = step

    def __call__(self):
        value = self.t
        self.t += self.step
        return value


@pytest.fixture(autouse=True)
def _clean_repeat_store():
    drs.repeat_store.prune(set())
    yield
    drs.repeat_store.prune(set())


# ---- capabilities -------------------------------------------------------------


class TestCapabilities:
    def test_playing_target_flags(self):
        caps = cp.appliance_capabilities(_target(proto=2))
        assert caps == cp.Capabilities(
            status=True, outputs=False, eq=False, repeat=False,
            typed_refusals=True, reports_mute=True,
        )

    def test_roster_entry_flags(self):
        caps = cp.appliance_capabilities(
            _entry(repeat_capable=True, dial_outputs=True, dial_eq=True, proto=0))
        assert caps.repeat and caps.outputs and caps.eq
        assert not caps.typed_refusals and not caps.reports_mute

    def test_the_txt_path_carries_the_versions_the_flags_imply(self):
        caps = cp.appliance_capabilities(
            _entry(repeat_capable=True, dial_outputs=True, dial_eq=True, proto=2))
        assert (caps.warnings, caps.eq_version, caps.outputs_version) == (False, 1, 1)
        bare = cp.appliance_capabilities(_target(proto=2))
        assert (bare.warnings, bare.eq_version, bare.outputs_version) == (False, 0, 0)

    def test_status_flag_off(self):
        assert cp.appliance_capabilities(_target(dial_status=False)).status is False

    def test_version_decides_typed_refusals_and_mute(self):
        assert not cp.appliance_capabilities(_target(proto=0)).typed_refusals
        assert cp.appliance_capabilities(_target(proto=2)).reports_mute

    def test_object_without_the_optional_flags_reads_conservatively(self):
        class Bare:
            dial_status = True
        caps = cp.appliance_capabilities(Bare())
        assert (caps.outputs, caps.eq, caps.repeat) == (False, False, False)
        assert caps.typed_refusals and caps.reports_mute


# ---- applying a reply to the stores ---------------------------------------------


class TestApplyStatusToAuth:
    def test_good_reply_authorises(self):
        t = _target("Hall")
        assert cp.apply_status_to_auth(t, _ok(t.appliance_id)) is True
        assert auth_map.state(t.appliance_id) == AUTH_AUTHORIZED

    def test_refusal_without_body_id_uses_the_resolved_id(self):
        t = _target("Hall", proto=0)
        assert cp.apply_status_to_auth(t, _refusal(None, untyped_refusal=True)) is True
        assert auth_map.state(t.appliance_id) == AUTH_UNAUTHORIZED

    def test_plain_refusal_without_body_id_is_uncorrelated(self):
        t = _target("Hall")
        assert cp.apply_status_to_auth(t, _refusal(None)) is False
        assert auth_map.state(t.appliance_id) == AUTH_UNKNOWN

    def test_earlier_dialect_success_without_id_still_authorises(self):
        t = _target("Hall", proto=0)
        assert cp.apply_status_to_auth(t, _ok(None)) is True
        assert auth_map.state(t.appliance_id) == AUTH_AUTHORIZED

    def test_typed_dialect_success_without_id_does_not(self):
        t = _target("Hall", proto=2)
        assert cp.apply_status_to_auth(t, _ok(None)) is False

    def test_transient_error_moves_nothing(self):
        t = _target("Hall")
        cp.apply_status_to_auth(t, {"status_error": "timeout", "appliance_id": t.appliance_id})
        assert auth_map.state(t.appliance_id) == AUTH_UNKNOWN

    def test_a_typed_refusal_naming_the_appliance_marks_it(self):
        t = _target("Hall")
        assert cp.apply_status_to_auth(t, _refusal(t.appliance_id)) is True
        assert auth_map.state(t.appliance_id) == AUTH_UNAUTHORIZED

    def test_a_good_reply_naming_another_appliance_moves_nothing(self):
        t = _target("Hall")
        cp.apply_status_to_auth(t, _ok(_id("Other")))
        assert auth_map.state(t.appliance_id) == AUTH_UNKNOWN

    def test_first_refusal_warns_once(self, caplog):
        t = _target("Hall")
        with caplog.at_level(logging.WARNING):
            for _ in range(3):
                cp.apply_status_to_auth(t, _refusal(t.appliance_id))
        warned = [r for r in caplog.records if "refused this dial" in r.getMessage()]
        assert len(warned) == 1 and "Hall" in warned[0].getMessage()

    def test_refusal_after_authorisation_warns_again(self, caplog):
        t = _target("Hall")
        with caplog.at_level(logging.WARNING):
            cp.apply_status_to_auth(t, _refusal(t.appliance_id))
            cp.apply_status_to_auth(t, _ok(t.appliance_id))
            cp.apply_status_to_auth(t, _refusal(t.appliance_id))
        assert len([r for r in caplog.records if "refused this dial" in r.getMessage()]) == 2


class TestApplyStatusToRepeat:
    def _obj(self):
        return {"available": True, "state": "hold", "armed": False, "held": True,
                "recording_seconds": 30.0,
                "replay": {"active": False, "position_seconds": 0.0, "duration_seconds": 30.0}}

    def test_good_reply_updates_the_store(self):
        aid = _id("A")
        cp.apply_status_to_repeat(aid, _ok(aid, repeat=self._obj()), 5.0)
        rec = drs.repeat_store.get(aid, 5.0)
        assert rec is not None and rec.state == "hold" and rec.recording_seconds == 30.0

    def test_confirmed_refusal_clears_it(self):
        aid = _id("A")
        cp.apply_status_to_repeat(aid, _ok(aid, repeat=self._obj()), 5.0)
        cp.apply_status_to_repeat(aid, _refusal(aid), 6.0)
        assert drs.repeat_store.get(aid, 6.0) is None

    def test_transient_error_leaves_it(self):
        aid = _id("A")
        cp.apply_status_to_repeat(aid, _ok(aid, repeat=self._obj()), 5.0)
        cp.apply_status_to_repeat(aid, {"status_error": "timeout"}, 6.0)
        assert drs.repeat_store.get(aid, 6.0) is not None

    def test_identity_less_is_a_noop(self):
        cp.apply_status_to_repeat("", _ok(None, repeat=self._obj()), 5.0)
        assert drs.repeat_store.get("", 5.0) is None


class TestProbeAuth:
    def test_fetches_with_the_status_timeout_and_applies(self):
        t = _target("Hall")
        seen = {}

        def fetch(target, dial_id, timeout_seconds=None):
            seen.update(target=target, dial_id=dial_id, timeout=timeout_seconds)
            return _ok(t.appliance_id)

        result = cp.probe_auth(t, "dial-1", fetch=fetch)
        assert result["status_error"] is None
        assert seen == {"target": t, "dial_id": "dial-1", "timeout": cp.DIAL_STATUS_TIMEOUT_SECONDS}
        assert auth_map.state(t.appliance_id) == AUTH_AUTHORIZED


# ---- first checks -------------------------------------------------------------------


class TestFirstChecks:
    def test_asks_the_first_unchecked_and_stops_when_it_accepts(self):
        a, b = _target("A"), _target("B")
        fetch = _Fetcher({"A": _ok(a.appliance_id), "B": _ok(b.appliance_id)})
        checks = cp.first_checks([a, b], set(), "d", fetch=fetch, now_fn=_Clock(7.0))
        assert fetch.calls == ["A"]
        assert list(checks) == ["A"]
        assert checks["A"][0] == 7.0 and checks["A"][1]["status_error"] is None

    def test_a_refusal_moves_on_to_the_next(self):
        a, b = _target("A"), _target("B")
        fetch = _Fetcher({"A": _refusal(a.appliance_id), "B": _ok(b.appliance_id)})
        checks = cp.first_checks([a, b], set(), "d", fetch=fetch)
        assert fetch.calls == ["A", "B"]
        assert auth_map.state(a.appliance_id) == AUTH_UNAUTHORIZED
        assert set(checks) == {"A", "B"}

    def test_stops_at_one_already_playing_last_tick(self):
        a = _target("A")
        fetch = _Fetcher({})
        assert cp.first_checks([a], {a.appliance_id}, "d", fetch=fetch) == {}
        assert fetch.calls == []

    def test_stops_at_one_with_known_auth(self):
        a = _target("A", auth=AUTH_AUTHORIZED)
        fetch = _Fetcher({})
        assert cp.first_checks([a], set(), "d", fetch=fetch) == {}
        assert fetch.calls == []

    def test_stops_at_one_without_a_status_endpoint(self):
        a = _target("A", dial_status=False)
        fetch = _Fetcher({})
        assert cp.first_checks([a], set(), "d", fetch=fetch) == {}

    def test_feeds_the_repeat_store(self):
        a = _target("A")
        reply = _ok(a.appliance_id, repeat={
            "available": True, "state": "hold", "armed": False, "held": True,
            "recording_seconds": 12.0,
            "replay": {"active": False, "position_seconds": 0.0, "duration_seconds": 12.0}})
        cp.first_checks([a], set(), "d", fetch=_Fetcher({"A": reply}), now_fn=_Clock(3.0))
        assert drs.repeat_store.get(a.appliance_id, 3.0).recording_seconds == 12.0


# ---- the walk ---------------------------------------------------------------------------


class TestWalk:
    def test_stops_at_the_first_identified_track(self):
        a, b = _target("A", playing_since=1.0), _target("B", playing_since=2.0)
        fetch = _Fetcher({
            "A": _ok(a.appliance_id, track_id=_track("One")),
            "B": _ok(b.appliance_id, track_id=_track("Two")),
        })
        w = cp.walk([a, b], {}, "d", None, fetch=fetch, now_fn=_Clock(4.0))
        assert fetch.calls == ["A"]
        assert w.selection.service == "A" and w.selection.title == "One"
        assert w.visited == {"A"} and set(w.records) == {"A"}
        assert w.status_sent_at == {"A": 4.0}
        assert w.released is False

    def test_unidentified_falls_through_to_the_next(self):
        a, b = _target("A"), _target("B")
        fetch = _Fetcher({
            "A": _ok(a.appliance_id, track_id=None),
            "B": _ok(b.appliance_id, track_id=_track("Two")),
        })
        w = cp.walk([a, b], {}, "d", None, fetch=fetch)
        assert fetch.calls == ["A", "B"]
        assert w.selection.service == "B"

    def test_nothing_identified_selects_no_artwork(self):
        a = _target("A")
        fetch = _Fetcher({"A": _ok(a.appliance_id, track_id=None)})
        w = cp.walk([a], {}, "d", None, fetch=fetch)
        assert w.selection.url is None and w.selection.service is None
        assert set(w.records) == {"A"}

    def test_first_check_reply_is_used_instead_of_asking(self):
        a = _target("A")
        fetch = _Fetcher({})
        reply = _ok(a.appliance_id, track_id=_track("One"))
        w = cp.walk([a], {"A": (2.5, reply)}, "d", None, fetch=fetch)
        assert fetch.calls == []
        assert w.status_sent_at == {"A": 2.5}
        assert w.selection.service == "A"

    def test_each_ask_carries_the_dial_id_and_the_status_timeout(self):
        a, b = _target("A"), _target("B")
        fetch = _Fetcher({"A": _ok(a.appliance_id, track_id=None), "B": _ok(b.appliance_id, track_id=None)})
        cp.walk([a, b], {}, "dial-uuid", None, fetch=fetch)
        assert fetch.asked == [
            ("A", "dial-uuid", cp.DIAL_STATUS_TIMEOUT_SECONDS),
            ("B", "dial-uuid", cp.DIAL_STATUS_TIMEOUT_SECONDS),
        ]

    def test_a_failed_fetch_is_skipped_without_marking_and_the_walk_goes_on(self):
        a, b = _target("A"), _target("B")
        fetch = _Fetcher({
            "A": {"status_error": "timeout", "appliance_id": a.appliance_id},
            "B": _ok(b.appliance_id, track_id=_track("Two")),
        })
        w = cp.walk([a, b], {}, "d", None, fetch=fetch)
        assert fetch.calls == ["A", "B"]
        assert w.selection.service == "B"
        assert w.errors == {"A": "timeout"} and set(w.records) == {"B"}
        assert w.visited == {"A", "B"}
        assert auth_map.state(a.appliance_id) == AUTH_UNKNOWN

    def test_skips_unauthorised_and_unsupported_rows(self):
        bad = _target("Bad", auth=AUTH_UNAUTHORIZED)
        old = _target("Old", dial_status=False)
        good = _target("Good")
        fetch = _Fetcher({"Good": _ok(good.appliance_id, track_id=_track("G"))})
        w = cp.walk([bad, old, good], {}, "d", None, fetch=fetch)
        assert fetch.calls == ["Good"]
        assert w.visited == {"Good"}

    def test_pinned_target_without_status_is_selected_without_asking(self):
        pin = _target("Pin", dial_status=False)
        other = _target("Other")
        fetch = _Fetcher({})
        w = cp.walk([pin, other], {}, "d", pin, fetch=fetch)
        assert fetch.calls == []
        assert w.selection.service == "Pin"

    def test_pinned_target_stays_selected_without_artwork(self):
        pin = _target("Pin")
        other = _target("Other")
        fetch = _Fetcher({"Pin": _ok(pin.appliance_id, track_id=None)})
        w = cp.walk([pin, other], {}, "d", pin, fetch=fetch)
        assert fetch.calls == ["Pin"]
        assert w.selection.service == "Pin"

    def test_revoked_pin_calls_back_and_walks_on(self):
        pin = _target("Pin")
        other = _target("Other")
        fetch = _Fetcher({
            "Pin": _refusal(pin.appliance_id),
            "Other": _ok(other.appliance_id, track_id=_track("O")),
        })
        revoked = []
        w = cp.walk([pin, other], {}, "d", pin, fetch=fetch, on_revoke=lambda: revoked.append(1))
        assert revoked == [1] and w.released is True
        assert fetch.calls == ["Pin", "Other"]
        assert w.selection.service == "Other"
        assert w.visited == {"Pin", "Other"}
        assert "Pin" not in w.records
        assert auth_map.state(pin.appliance_id) == AUTH_UNAUTHORIZED

    def test_refusal_of_an_unpinned_row_does_not_call_back(self):
        a, b = _target("A"), _target("B")
        fetch = _Fetcher({
            "A": _refusal(a.appliance_id),
            "B": _ok(b.appliance_id, track_id=_track("B")),
        })
        revoked = []
        w = cp.walk([a, b], {}, "d", None, fetch=fetch, on_revoke=lambda: revoked.append(1))
        assert revoked == [] and w.released is False
        assert w.selection.service == "B"

    def test_feeds_auth_and_repeat_for_each_asked_target(self):
        a = _target("A")
        fetch = _Fetcher({"A": _ok(a.appliance_id, track_id=None)})
        cp.walk([a], {}, "d", None, fetch=fetch)
        assert auth_map.state(a.appliance_id) == AUTH_AUTHORIZED

    def test_empty_walk_has_an_empty_selection(self):
        w = cp.walk([], {}, "d", None, fetch=_Fetcher({}))
        assert w.selection.service is None
        assert w.records == {} and w.visited == set()


# ---- observations -------------------------------------------------------------------------


class TestObserveTick:
    def _calls(self, records, reporting, sent, visible, volume):
        mute, vol, forget = [], [], []
        cp.observe_tick(
            records, reporting, sent, visible, volume,
            observe_mute=lambda name, muted, **kw: mute.append((name, muted, kw)),
            observe_volume=lambda name, v: vol.append((name, v)),
            forget=lambda names: forget.append(set(names)),
        )
        return mute, vol, forget

    def test_every_walked_target_is_observed_reporting_last(self):
        a, b = _target("A"), _target("B")
        records = {"A": {"muted": True}, "B": {"muted": False}}
        mute, vol, forget = self._calls(records, "B", {"A": 1.0, "B": 2.0}, [a, b], 55)
        assert [m[0] for m in mute] == ["A", "B"]
        assert mute[0][2] == {"requested_at": 1.0, "status_reports_mute": True}
        assert mute[1][1] is False and mute[1][2]["requested_at"] == 2.0
        assert vol == [("B", 55)]
        assert forget == [{"A", "B"}]

    def test_unwalked_services_count_as_sent_at_zero(self):
        a = _target("A")
        mute, _, _ = self._calls({}, "A", {}, [a], None)
        assert mute == [("A", None, {"requested_at": 0.0, "status_reports_mute": True})]

    def test_earlier_dialect_target_does_not_report_mute(self):
        a = _target("A", proto=0)
        mute, _, _ = self._calls({"A": {"muted": None}}, "A", {"A": 1.0}, [a], 10)
        assert mute[-1][2]["status_reports_mute"] is False

    def test_non_int_volume_clears_the_reporting_volume(self):
        a = _target("A")
        _, vol, _ = self._calls({"A": {}}, "A", {}, [a], None)
        assert vol == [("A", None)]
        _, vol, _ = self._calls({"A": {}}, "A", {}, [a], True)
        assert vol == [("A", None)]

    def test_no_reporting_name_observes_no_volume(self):
        a = _target("A")
        _, vol, _ = self._calls({}, None, {}, [a], None)
        assert vol == []


# ---- reconcile ---------------------------------------------------------------------------------


class TestReconcile:
    def test_only_unvisited_status_rows_are_enriched(self):
        walked = _entry("Walked", playing=True)
        idle = _entry("Idle")
        nostatus = _entry("Old", dial_status=False)
        seen = []

        def enrich(pending, dial_id):
            seen.append([t.service_name for t in pending])
            return [{"name": t.service_name, "status_error": None,
                     "appliance_id": t.appliance_id} for t in pending]

        cp.reconcile([walked, idle, nostatus], {"Walked"}, "d", enrich=enrich, now_fn=_Clock(5.0))
        assert seen == [["Idle"]]
        assert auth_map.state(idle.appliance_id) == AUTH_AUTHORIZED

    def test_not_due_rows_are_skipped(self):
        idle = _entry("Idle")
        auth_map.apply(idle.appliance_id, cp.OUTCOME_UNAUTHORIZED, idle.appliance_id, 5.0)
        called = []
        cp.reconcile([idle], set(), "d", enrich=lambda p, d: called.append(p) or [],
                     now_fn=_Clock(6.0))
        assert called == []

    def test_no_pending_rows_makes_no_fetch(self):
        called = []
        cp.reconcile([], set(), "d", enrich=lambda p, d: called.append(p) or [])
        assert called == []

    def test_repeat_stamped_after_the_fetch_returns(self):
        idle = _entry("Idle", repeat_capable=True)
        clock = _Clock(5.0)
        obj = {"available": True, "state": "replaying", "armed": True, "held": True,
               "recording_seconds": 30.0,
               "replay": {"active": True, "position_seconds": 1.0, "duration_seconds": 30.0}}

        def enrich(pending, dial_id):
            clock.t = 9.0       # the fan-out takes four seconds
            return [{"name": "Idle", "status_error": None,
                     "appliance_id": idle.appliance_id, "repeat": obj}]

        cp.reconcile([idle], set(), "d", enrich=enrich, now_fn=clock)
        assert drs.repeat_store.get(idle.appliance_id, 9.0).observed_at == 9.0

    def test_prunes_the_store_to_the_roster(self):
        gone = _id("Gone")
        drs.repeat_store.update(gone, drs.parse_repeat_object(
            {"available": True, "state": "hold", "armed": False, "held": True,
             "recording_seconds": 3.0,
             "replay": {"active": False, "position_seconds": 0.0, "duration_seconds": 3.0}}, 1.0))
        cp.reconcile([], set(), "d", enrich=lambda p, d: [], now_fn=_Clock(2.0))
        assert drs.repeat_store.get(gone, 2.0) is None


# ---- push probes -----------------------------------------------------------------------------------


class TestDrainPushProbes:
    def _probe(self, fetch):
        return lambda target: cp.probe_auth(target, "d", fetch=fetch)

    def test_promoted_ids_are_returned(self):
        t = _target("A")
        fetch = _Fetcher({"A": _ok(t.appliance_id)})
        promoted = cp.drain_push_probes(
            {t.appliance_id}, {t.appliance_id: t}, {}, "d", self._probe(fetch))
        assert promoted == {t.appliance_id}

    def test_already_authorised_is_not_promoted(self):
        t = _target("A")
        auth_map.apply(t.appliance_id, OUTCOME_AUTHORIZED, t.appliance_id, 1.0)
        fetch = _Fetcher({"A": _ok(t.appliance_id)})
        promoted = cp.drain_push_probes(
            {t.appliance_id}, {t.appliance_id: t}, {}, "d", self._probe(fetch))
        assert promoted == set() and fetch.calls == ["A"]

    def test_a_refusal_is_not_a_promotion(self):
        t = _target("A")
        fetch = _Fetcher({"A": _refusal(t.appliance_id)})
        assert cp.drain_push_probes(
            {t.appliance_id}, {t.appliance_id: t}, {}, "d", self._probe(fetch)) == set()

    def test_falls_back_to_the_roster_for_an_idle_appliance(self):
        r = _entry("Idle")
        fetch = _Fetcher({"Idle": _ok(r.appliance_id)})
        promoted = cp.drain_push_probes(
            {r.appliance_id}, {}, {r.appliance_id: r}, "d", self._probe(fetch))
        assert promoted == {r.appliance_id}

    def test_unrostered_and_statusless_ids_are_skipped(self):
        r = _entry("Old", dial_status=False)
        fetch = _Fetcher({})
        promoted = cp.drain_push_probes(
            {r.appliance_id, "f" * 20}, {}, {r.appliance_id: r}, "d", self._probe(fetch))
        assert promoted == set() and fetch.calls == []


# ---- artwork bytes ---------------------------------------------------------------------------------------


class _Limiter:
    def __init__(self):
        self.entries = []

    def log(self, level, key, msg, *args):
        self.entries.append((level, key, msg % args))


class TestFetchArtworkBytes:
    URL = "https://provider.example/a.jpg"

    def test_success_returns_the_bytes_with_a_stable_key(self):
        seen = []

        def fetch(url, timeout):
            seen.append((url, timeout))
            return b"jpeg", ""

        art = cp.fetch_artwork_bytes(self.URL, _Limiter(), fetch=fetch, now_fn=_Clock(12.0))
        assert seen == [(self.URL, cp.ARTWORK_FETCH_TIMEOUT_SECONDS)]
        assert art.url == self.URL and art.data == b"jpeg" and art.fetched_at == 12.0
        assert len(art.key) == 16 and self.URL not in art.key
        again = cp.fetch_artwork_bytes(self.URL, _Limiter(), fetch=fetch)
        assert again.key == art.key == artwork_key(self.URL)
        assert artwork_key("https://provider.example/b.jpg") != art.key

    def test_failure_reports_logs_and_returns_none(self):
        errors, limiter = [], _Limiter()
        art = cp.fetch_artwork_bytes(
            self.URL, limiter, fetch=lambda u, t: (None, "timeout"), on_error=errors.append)
        assert art is None
        assert errors == ["artwork_fetch_failed"]
        (level, key, text), = limiter.entries
        assert level == logging.WARNING and "timeout" in text
        assert self.URL not in text and self.URL not in key

    def test_failure_without_a_callback(self):
        assert cp.fetch_artwork_bytes(
            self.URL, _Limiter(), fetch=lambda u, t: (None, "bad")) is None

    def test_url_log_key_is_short_and_non_reversible(self):
        key = cp.url_log_key(self.URL)
        assert len(key) == 12 and "provider" not in key


# ---------------------------------------------------------------------------
# Outputs and EQ replies
# ---------------------------------------------------------------------------

from dial_core_state import EqBand, OutputRow  # noqa: E402


def _out(id="1", name="Bedroom", selected=True, volume=40, **extra):
    return {"id": id, "name": name, "selected": selected, "volume": volume, **extra}


class TestParseOutputsBody:
    def test_well_formed_rows_become_output_rows(self):
        rows = cp.parse_outputs_body(200, {"ok": True, "outputs": [_out(), _out("2", "Study", False, 0)]})
        assert rows == (OutputRow("1", "Bedroom", True, 40), OutputRow("2", "Study", False, 0))

    def test_an_empty_list_is_a_valid_result(self):
        assert cp.parse_outputs_body(200, {"ok": True, "outputs": []}) == ()

    def test_an_output_in_use_elsewhere_is_kept_and_marked(self):
        rows = cp.parse_outputs_body(200, {"ok": True, "outputs": [
            _out("1", remote_in_use=False),
            _out("2", remote_in_use=True, remote_owner="Hall"),
            _out("3", remote_in_use=True),
        ]})
        assert [(r.id, r.remote_in_use, r.remote_owner) for r in rows] == [
            ("1", False, None), ("2", True, "Hall"), ("3", True, None),
        ]

    def test_is_default_is_read_and_absent_reads_false(self):
        rows = cp.parse_outputs_body(200, {"ok": True, "outputs": [
            _out("1", is_default=True), _out("2"),
        ]})
        assert rows[0].is_default is True and rows[1].is_default is False

    def test_a_non_bool_is_default_does_not_fail_the_reply(self):
        rows = cp.parse_outputs_body(200, {"ok": True, "outputs": [_out("1", is_default="yes")]})
        assert rows is not None and rows[0].is_default is True

    def test_an_owner_is_only_carried_for_a_row_in_use(self):
        rows = cp.parse_outputs_body(200, {"ok": True, "outputs": [
            _out("1", remote_in_use=False, remote_owner="Hall"),
        ]})
        assert rows[0].remote_owner is None

    def test_a_malformed_row_in_use_is_skipped_not_fatal(self):
        rows = cp.parse_outputs_body(200, {"ok": True, "outputs": [
            _out("1"), {"id": "2", "remote_in_use": True},
        ]})
        assert rows == (OutputRow("1", "Bedroom", True, 40),)

    @pytest.mark.parametrize("body", [
        {"ok": True, "outputs": [{"id": "1"}]},
        {"ok": True, "outputs": ["bad"]},
        {"ok": True, "outputs": [_out(id="")]},
        {"ok": True, "outputs": [_out(selected="yes")]},
        {"ok": True, "outputs": [_out(volume=True)]},
        {"ok": True, "outputs": [_out(volume="4")]},
        {"ok": True, "outputs": "nope"},
        {"ok": False, "error": "backend_unavailable"},
        None,
    ])
    def test_anything_malformed_is_transient(self, body):
        assert cp.parse_outputs_body(200, body) is None

    def test_a_row_with_no_id_key_is_transient(self):
        assert cp.parse_outputs_body(200, {"ok": True, "outputs": [
            {"name": "A", "selected": True, "volume": 10, "remote_in_use": False},
        ]}) is None

    def test_a_failed_request_is_transient(self):
        assert cp.parse_outputs_body(412, {"ok": True, "outputs": []}) is None
        assert cp.parse_outputs_body(None, None) is None

    def test_levels_are_clamped(self):
        rows = cp.parse_outputs_body(200, {"ok": True, "outputs": [_out(volume=250), _out("2", volume=-5)]})
        assert [r.volume for r in rows] == [100, 0]


class TestParseEqBody:
    def test_bass_and_treble_become_the_two_bands_of_the_first_capability(self):
        assert cp.parse_eq_body(200, {"ok": True, "bass_db": 3, "treble_db": -2}) == (
            EqBand("bass", None, 3, -6, 6), EqBand("treble", None, -2, -6, 6),
        )

    @pytest.mark.parametrize("status, body", [
        (500, None),
        (200, None),
        (200, {"ok": False}),
        (200, {"ok": True, "bass_db": "2", "treble_db": 1}),
        (200, {"ok": True, "bass_db": 2}),
        (200, {"ok": True, "bass_db": True, "treble_db": 1}),
        (412, {"ok": True, "bass_db": 1, "treble_db": 1}),
    ])
    def test_anything_malformed_or_failed_is_dropped(self, status, body):
        assert cp.parse_eq_body(status, body) is None


def _peq(band_id="peq3", frequency_hz=300, gain_db=1.0, min_db=-12, max_db=12, **extra):
    band = {"id": band_id, "frequency_hz": frequency_hz, "type": "peak",
            "gain_db": gain_db, "min_db": min_db, "max_db": max_db}
    band.update(extra)
    return band


def _six_band_body(bands=None, bass=2, treble=-1):
    return {"ok": True, "bass_db": bass, "treble_db": treble, "bands": bands if bands is not None else [
        _peq("peq1", 40, 2.0), _peq("peq2", 100, 2.0), _peq("peq3", 300, 0.0),
        _peq("peq4", 1000, 0.0), _peq("peq5", 4000, -0.5), _peq("peq6", 10000, -1.0),
    ]}


class TestParseEqBodySixBand:
    def test_six_bands_then_the_two_derived_controls(self):
        bands = cp.parse_eq_body(200, _six_band_body(), 2)
        assert [b.id for b in bands] == ["peq1", "peq2", "peq3", "peq4", "peq5", "peq6", "bass", "treble"]
        assert bands[0] == EqBand("peq1", 40, 2, -12, 12)
        assert bands[4] == EqBand("peq5", 4000, 0, -12, 12)
        assert bands[6:] == (EqBand("bass", None, 2, -6, 6), EqBand("treble", None, -1, -6, 6))

    def test_gains_round_to_whole_dB(self):
        gains = [(1.4, 1), (1.5, 2), (-0.5, 0), (-1.5, -1), (3, 3)]
        bands = cp.parse_eq_body(
            200, _six_band_body([_peq(f"peq{i}", gain_db=g) for i, (g, _) in enumerate(gains)]), 2)
        assert [b.gain_db for b in bands[:5]] == [want for _, want in gains]

    def test_gains_clamp_to_the_stated_range(self):
        bands = cp.parse_eq_body(200, _six_band_body([
            _peq("peq1", gain_db=40), _peq("peq2", gain_db=-40, min_db=-6, max_db=6),
        ]), 2)
        assert (bands[0].gain_db, bands[1].gain_db) == (12, -6)
        assert (bands[1].min_db, bands[1].max_db) == (-6, 6)

    def test_a_repeated_id_is_dropped(self):
        bands = cp.parse_eq_body(200, _six_band_body([_peq("peq1", gain_db=1), _peq("peq1", gain_db=5)]), 2)
        assert [(b.id, b.gain_db) for b in bands[:-2]] == [("peq1", 1)]

    def test_an_empty_list_leaves_only_the_derived_controls(self):
        bands = cp.parse_eq_body(200, _six_band_body([]), 2)
        assert [b.id for b in bands] == ["bass", "treble"]

    @pytest.mark.parametrize("bands", [
        None, "x", {}, 5,
        ["peq1"],
        [_peq("bass")], [_peq("treble")],
        [_peq("PEQ1")], [_peq("a-b")], [_peq("x" * 17)], [_peq("")], [_peq(None)],
        [_peq(frequency_hz=0)], [_peq(frequency_hz=-5)], [_peq(frequency_hz=True)],
        [_peq(frequency_hz=100.5)], [_peq(frequency_hz="100")],
        [_peq(gain_db="1")], [_peq(gain_db=None)], [_peq(gain_db=True)],
        [_peq(gain_db=float("nan"))], [_peq(gain_db=float("inf"))],
        [_peq(min_db=None)], [_peq(max_db="12")], [_peq(min_db=6, max_db=-6)],
        [_peq(f"p{i}") for i in range(17)],
    ])
    def test_a_malformed_list_is_transient(self, bands):
        body = _six_band_body()
        body["bands"] = bands
        assert cp.parse_eq_body(200, body, 2) is None

    def test_sixteen_bands_are_accepted(self):
        bands = cp.parse_eq_body(200, _six_band_body([_peq(f"p{i}") for i in range(16)]), 2)
        assert len(bands) == 18

    def test_a_reply_without_bands_is_transient_at_version_two(self):
        body = _six_band_body()
        del body["bands"]
        assert cp.parse_eq_body(200, body, 2) is None

    def test_version_two_still_needs_the_derived_controls(self):
        body = _six_band_body()
        body["bass_db"] = "2"
        assert cp.parse_eq_body(200, body, 2) is None

    def test_capability_one_ignores_the_bands(self):
        assert cp.parse_eq_body(200, _six_band_body(), 1) == (
            EqBand("bass", None, 2, -6, 6), EqBand("treble", None, -1, -6, 6),
        )
        assert cp.parse_eq_body(200, _six_band_body(["junk"])) == cp.parse_eq_body(200, _six_band_body(), 1)

    def test_a_failed_request_is_transient_at_version_two(self):
        assert cp.parse_eq_body(500, _six_band_body(), 2) is None
        assert cp.parse_eq_body(200, None, 2) is None


# ---------------------------------------------------------------------------
# Pairing flag on the rows and the set-reply readers
# ---------------------------------------------------------------------------


class TestPairingFlag:
    def test_rows_read_needs_auth_key_and_default_it(self):
        rows = cp.parse_outputs_body(200, {"ok": True, "outputs": [
            _out("1", needs_auth_key=True), _out("2"), _out("3", needs_auth_key=None),
            _out("4", needs_auth_key="yes"), _out("5", needs_auth_key=1),
            _out("6", needs_auth_key=False),
        ]})
        assert [r.needs_auth_key for r in rows] == [True, False, False, False, False, False]

    def test_the_other_pairing_fields_are_not_read(self):
        rows = cp.parse_outputs_body(200, {"ok": True, "outputs": [
            _out("1", pin_pending=True, pin_claim="webui"),
        ]})
        assert rows == (OutputRow("1", "Bedroom", True, 40),)


class TestReplyErrorId:
    @pytest.mark.parametrize("status, body, expected", [
        (200, {"ok": True}, None),
        (200, {"ok": True, "id": "2"}, None),
        (200, {"ok": False, "pin_required": True, "error": "Output requires PIN"}, "pin_required"),
        (200, {"ok": False, "pin_invalid": True, "error": "Wrong PIN"}, "pin_invalid"),
        (200, {"ok": False, "pin_required": True, "pin_invalid": True}, "pin_invalid"),
        (200, {"ok": False, "error": "output_in_use", "owner": "Den"}, "output_in_use"),
        (200, {"ok": False, "error": "encoder_capacity"}, "encoder_capacity"),
        (200, {"ok": False, "error": "rate_limited", "retry_after_s": 42}, "rate_limited"),
        (200, {"ok": False, "error": "invalid_pin"}, "invalid_pin"),
        (412, {"ok": False, "error": "dial_not_authorized"}, "dial_not_authorized"),
        (400, {"ok": False, "error": "invalid_request_body"}, "invalid_request_body"),
        (200, {"ok": False, "error": "Backend returned HTTP 500"}, "backend_error"),
        (200, {"ok": False, "error": "x" * 40}, "backend_error"),
        (200, {"ok": False, "error": "x" * 32}, "x" * 32),
        (200, {"ok": False, "error": "bad\n"}, "backend_error"),
        (200, {"ok": False, "error": 7}, "backend_error"),
        (200, {"ok": False, "error": None}, "backend_error"),
        (200, {"ok": False}, "backend_error"),
        (200, {"ok": "yes"}, "backend_error"),
        (200, {"ok": 1}, "backend_error"),
        (200, {"pin_required": "true"}, "backend_error"),
        (500, {"ok": True}, "backend_error"),
        (200, "junk", "backend_error"),
        (200, None, "backend_error"),
        (200, [], "backend_error"),
        (None, None, "unreachable"),
        (None, {"ok": True}, "unreachable"),
    ])
    def test_the_id_a_view_keys_on(self, status, body, expected):
        assert cp.reply_error_id(status, body) == expected


class TestReplyRetryAfter:
    @pytest.mark.parametrize("body, expected", [
        ({"retry_after_s": 42}, 42),
        ({"retry_after_s": 0}, 0),
        ({"retry_after_s": 7.9}, 0),
        ({"retry_after_s": True}, 0),
        ({"retry_after_s": False}, 0),
        ({"retry_after_s": -3}, 0),
        ({"retry_after_s": 10 ** 9}, 3600),
        ({"retry_after_s": 3600}, 3600),
        ({"retry_after_s": "5"}, 0),
        ({"retry_after_s": None}, 0),
        ({"retry_after_s": [5]}, 0),
        ({}, 0),
        (None, 0),
        ("junk", 0),
    ])
    def test_whole_seconds_or_zero(self, body, expected):
        assert cp.reply_retry_after(body) == expected
