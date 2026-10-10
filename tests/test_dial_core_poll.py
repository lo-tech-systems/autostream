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

    def __call__(self, target, dial_id, timeout_seconds=None):
        self.calls.append(target.service_name)
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
        assert again.key == art.key

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
