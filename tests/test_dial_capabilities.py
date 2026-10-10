"""Tests for dial_capabilities.py (the registry, the reply validator and the
capabilities switch point), dial_appliance_fetch.py (the worker) and the core
steps that tie them together: the fetch schedule and the result fold."""
from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
for _p in (str(REPO_ROOT / "dial"), str(REPO_ROOT / "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import dial_appliance_fetch as daf
import dial_capabilities as dc
from dial_core import DialCore
from dial_core_state import ActionResult
from dial_mdns import PlayingTarget, RosterEntry

AID = "a" * 20
BID = "b" * 20


@pytest.fixture(autouse=True)
def _clean_registry():
    dc.registry.clear()
    yield
    dc.registry.clear()


def _body(appliance_id=AID, capabilities=None, **extra):
    body = {
        "ok": True, "appliance_id": appliance_id, "version": "0.8.0", "dial_proto": 3,
        "capabilities": capabilities if capabilities is not None else {
            "dial_status": 1, "dial_outputs": 1, "dial_eq": 2, "repeat": 1,
            "audio_status": 1, "dial_warnings": 1,
        },
    }
    body.update(extra)
    return body


def _entry(appliance_id=AID, proto=3, version="0.8.0", **flags):
    return RosterEntry(
        appliance_id=appliance_id, service_name="Kitchen", name="Kitchen", ip="192.0.2.10",
        port=80, playing=False, repeat_capable=flags.pop("repeat_capable", False),
        dial_proto_version=proto, version=version, **flags,
    )


# ---- registry -----------------------------------------------------------------


class TestRegistry:
    def test_nothing_held_is_due(self):
        assert dc.due(AID, "0.8.0", 100.0)

    def test_record_then_learned_and_not_due_for_that_version(self):
        dc.record(AID, "0.8.0", {"dial_eq": 2}, 100.0)
        held = dc.learned(AID)
        assert held.version == "0.8.0" and held.capabilities == {"dial_eq": 2}
        assert held.fetched_at == 100.0
        assert not dc.due(AID, "0.8.0", 10_000.0)

    def test_a_different_version_is_due_again(self):
        dc.record(AID, "0.8.0", {"dial_eq": 2}, 100.0)
        assert dc.due(AID, "0.8.1", 101.0)

    def test_record_copies_the_mapping(self):
        caps = {"dial_eq": 2}
        dc.record(AID, "v", caps, 0.0)
        caps["dial_eq"] = 9
        assert dc.learned(AID).capabilities == {"dial_eq": 2}

    def test_failure_backs_off_60_doubling_to_600(self):
        now = 1000.0
        waits = []
        for _ in range(6):
            dc.note_failure(AID, now)
            assert not dc.due(AID, "v", now)
            wait = 1.0
            while not dc.due(AID, "v", now + wait):
                wait += 1.0
            waits.append(wait)
        assert waits == [60.0, 120.0, 240.0, 480.0, 600.0, 600.0]

    def test_a_success_clears_the_backoff(self):
        dc.note_failure(AID, 0.0)
        dc.record(AID, "v", {}, 1.0)
        assert dc.due(AID, "w", 2.0)

    def test_forget(self):
        dc.record(AID, "v", {}, 0.0)
        dc.note_failure(BID, 0.0)
        dc.forget(AID)
        dc.forget(BID)
        assert dc.learned(AID) is None and dc.due(BID, "v", 1.0)

    def test_prune_keeps_only_the_known_ids(self):
        dc.record(AID, "v", {}, 0.0)
        dc.record(BID, "v", {}, 0.0)
        dc.note_failure("c" * 20, 0.0)
        dc.prune({AID})
        assert dc.learned(AID) is not None and dc.learned(BID) is None
        assert dc.due("c" * 20, "v", 1.0)


# ---- the reply validator --------------------------------------------------------


class TestParseCapabilitiesBody:
    def test_a_good_reply(self):
        assert dc.parse_capabilities_body(200, _body(), AID) == {
            "dial_status": 1, "dial_outputs": 1, "dial_eq": 2, "repeat": 1,
            "audio_status": 1, "dial_warnings": 1,
        }

    def test_bytes_and_text_are_parsed(self):
        raw = json.dumps(_body())
        assert dc.parse_capabilities_body(200, raw, AID)["dial_eq"] == 2
        assert dc.parse_capabilities_body(200, raw.encode(), AID)["dial_eq"] == 2

    @pytest.mark.parametrize("status", [None, 404, 403, 500, 204])
    def test_a_status_other_than_200_is_refused(self, status):
        assert dc.parse_capabilities_body(status, _body(), AID) is None

    def test_oversized_is_refused(self):
        raw = json.dumps(_body(capabilities={"dial_eq": 1}, pad="x" * 5000))
        assert dc.parse_capabilities_body(200, raw, AID) is None

    @pytest.mark.parametrize("body", [None, [], "[]", "not json", b"\xff\xfe", 5])
    def test_not_an_object_is_refused(self, body):
        assert dc.parse_capabilities_body(200, body, AID) is None

    def test_not_ok_is_refused(self):
        assert dc.parse_capabilities_body(200, _body(ok=False), AID) is None
        assert dc.parse_capabilities_body(200, _body(ok="yes"), AID) is None

    def test_the_wrong_appliance_is_refused(self):
        assert dc.parse_capabilities_body(200, _body(appliance_id=BID), AID) is None
        assert dc.parse_capabilities_body(200, _body(appliance_id=None), AID) is None

    def test_no_id_to_check_against_is_refused(self):
        assert dc.parse_capabilities_body(200, _body(), "") is None

    @pytest.mark.parametrize("caps", [None, [], "x", 3])
    def test_capabilities_that_are_not_an_object_are_refused(self, caps):
        body = _body()
        body["capabilities"] = caps
        assert dc.parse_capabilities_body(200, body, AID) is None

    def test_bad_values_and_names_are_dropped(self):
        caps = {
            "good": 1, "zero": 0, "bool": True, "float": 1.5, "neg": -1, "str": "1",
            "nested": {"a": 1}, "list": [1], "Upper": 1, "has-dash": 1, "": 1,
            "x" * 33: 1, "digit1": 1,
        }
        assert dc.parse_capabilities_body(200, _body(capabilities=caps), AID) == {
            "good": 1, "zero": 0,
        }

    def test_at_most_32_entries_are_read(self):
        letters = "abcdefghijklmnopqrstuvwxyz"
        caps = {f"k{letters[i % 26]}{letters[i // 26]}": 1 for i in range(40)}
        assert len(caps) == 40
        out = dc.parse_capabilities_body(200, _body(capabilities=caps), AID)
        assert len(out) == 32

    def test_never_raises(self):
        class Boom(dict):
            def get(self, *a):
                raise RuntimeError

        assert dc.parse_capabilities_body(200, Boom(), AID) is None


# ---- the switch point -----------------------------------------------------------


class TestSwitchPoint:
    def test_txt_path_equals_the_flags_for_every_entry_type(self):
        entry = _entry(proto=0, version="", dial_outputs=True, dial_eq=True, repeat_capable=True)
        caps = dc.appliance_capabilities(entry)
        assert (caps.status, caps.outputs, caps.eq, caps.repeat) == (True, True, True, True)
        assert (caps.eq_version, caps.outputs_version, caps.warnings) == (1, 1, False)
        assert not caps.typed_refusals and not caps.reports_mute

        playing = PlayingTarget(
            ip="192.0.2.1", port=80, name="x", dial_status=True, dial_eq=True,
            dial_eq_version=2, appliance_id=AID, dial_proto_version=2,
        )
        caps = dc.appliance_capabilities(playing)
        assert caps.eq and caps.eq_version == 2 and not caps.outputs and not caps.repeat
        assert caps.typed_refusals and caps.reports_mute

    def test_a_bare_object_reads_conservatively(self):
        class Bare:
            dial_status = True

        caps = dc.appliance_capabilities(Bare())
        assert caps == dc.Capabilities(
            status=True, outputs=False, eq=False, repeat=False,
            typed_refusals=True, reports_mute=True,
        )

    def test_the_txt_warnings_flag_is_read_below_v3(self):
        entry = _entry(proto=2)
        object.__setattr__(entry, "dial_warnings", True)
        assert dc.appliance_capabilities(entry).warnings is True

    def test_json_overrides_for_v3_with_a_matching_version(self):
        dc.record(AID, "0.8.0", {"dial_status": 1, "dial_outputs": 1, "dial_eq": 2,
                                 "repeat": 1, "dial_warnings": 1}, 0.0)
        caps = dc.appliance_capabilities(_entry(proto=3, dial_eq=True, dial_outputs=True))
        assert caps.eq_version == 2 and caps.warnings and caps.outputs_version == 1
        assert caps.repeat and caps.status

    def test_json_can_remove_what_the_flags_advertise(self):
        dc.record(AID, "0.8.0", {"dial_status": 1}, 0.0)
        caps = dc.appliance_capabilities(_entry(proto=3, dial_eq=True, repeat_capable=True))
        assert not caps.eq and not caps.repeat and caps.status

    def test_a_different_advertised_version_ignores_the_held_reply(self):
        dc.record(AID, "0.7.0", {"dial_status": 1, "dial_eq": 2}, 0.0)
        caps = dc.appliance_capabilities(_entry(proto=3, version="0.8.0", dial_eq=True))
        assert caps.eq_version == 1

    def test_a_target_with_no_version_matches_on_id(self):
        dc.record(AID, "0.8.0", {"dial_status": 1, "dial_eq": 2}, 0.0)
        playing = PlayingTarget(
            ip="192.0.2.1", port=80, name="x", dial_status=True, appliance_id=AID,
            dial_proto_version=3,
        )
        assert dc.appliance_capabilities(playing).eq_version == 2

    @pytest.mark.parametrize("proto", [0, 2])
    def test_older_generations_never_read_the_registry(self, proto):
        dc.record(AID, "0.8.0", {"dial_status": 1, "dial_eq": 2, "dial_warnings": 1}, 0.0)
        caps = dc.appliance_capabilities(_entry(proto=proto, dial_eq=True))
        assert caps.eq_version == 1 and not caps.warnings and not caps.outputs

    def test_v3_before_the_reply_lands_reads_the_flags(self):
        caps = dc.appliance_capabilities(_entry(proto=3, dial_outputs=True, dial_eq=True))
        assert caps.outputs and caps.eq_version == 1 and not caps.warnings
        assert caps.typed_refusals and caps.reports_mute

    def test_the_fallback_matrix(self):
        flags = dict(dial_outputs=True, dial_eq=True, repeat_capable=True)
        dc.record(AID, "0.8.0", {"dial_status": 1, "dial_outputs": 1, "dial_eq": 2,
                                 "repeat": 1, "dial_warnings": 1}, 0.0)
        rows = [
            dc.appliance_capabilities(_entry(proto=0, version="0.6.0", **flags)),
            dc.appliance_capabilities(_entry(proto=2, **flags)),
            dc.appliance_capabilities(_entry(proto=3, **flags)),
        ]
        assert [(c.eq_version, c.warnings, c.typed_refusals) for c in rows] == [
            (1, False, False), (1, False, True), (2, True, True),
        ]


# ---- the worker -------------------------------------------------------------------


class _FakeConn:
    last = None

    def __init__(self, host, port=None, timeout=None, *, data=b"{}", status=200):
        self.host, self.port, self.timeout = host, port, timeout
        self._data, self._status = data, status
        self.request_args = None
        self.closed = False
        _FakeConn.last = self

    def request(self, method, url, body=None, headers=None):
        self.request_args = (method, url, body, headers)

    def getresponse(self):
        resp = MagicMock()
        resp.status = self._status
        resp.read = MagicMock(side_effect=lambda n=None: self._data if n is None else self._data[:n])
        return resp

    def close(self):
        self.closed = True


def _conn_class(data, status=200):
    def make(host, port=None, timeout=None):
        return _FakeConn(host, port, timeout, data=data, status=status)
    return make


def _drain():
    try:
        while True:
            daf._queue.get_nowait()
    except Exception:
        pass
    with daf._pending_lock:
        daf._pending.clear()


@pytest.fixture
def _clean_worker():
    _drain()
    daf._cfg = MagicMock(uuid="dial-uuid")
    yield
    _drain()
    daf._cfg = None
    daf._on_result = None


@pytest.mark.usefixtures("_clean_worker")
class TestFetchWorker:
    def _target(self, version="0.8.0"):
        return daf._FetchTarget(AID, "10.0.0.5", 8080, version)

    def test_the_capabilities_request_is_a_bare_get(self):
        raw = json.dumps(_body()).encode()
        with patch("dial_appliance_fetch.http.client.HTTPConnection", _conn_class(raw)):
            status, body = daf._send_one("capabilities", self._target())
        conn = _FakeConn.last
        assert (status, body) == (200, _body())
        assert conn.request_args == ("GET", "/api/dial/capabilities", None, None)
        assert (conn.host, conn.port, conn.timeout) == ("10.0.0.5", 8080, daf.FETCH_TIMEOUT_S)
        assert conn.closed

    def test_the_warnings_request_is_a_post_carrying_the_dials_id(self):
        raw = json.dumps({"ok": True, "appliance_id": AID, "warnings": []}).encode()
        with patch("dial_appliance_fetch.http.client.HTTPConnection", _conn_class(raw)):
            status, body = daf._send_one("warnings", self._target())
        method, path, payload, headers = _FakeConn.last.request_args
        assert (status, body["warnings"]) == (200, [])
        assert (method, path) == ("POST", "/api/dial/warnings")
        assert json.loads(payload) == {"dial_id": "dial-uuid"}
        assert headers == {"Content-Type": "application/json"}

    def test_a_refusal_body_is_reported_with_its_status(self):
        raw = json.dumps({"ok": False, "error": "dial_not_authorized", "appliance_id": AID}).encode()
        with patch("dial_appliance_fetch.http.client.HTTPConnection", _conn_class(raw, 412)):
            status, body = daf._send_one("warnings", self._target())
        assert (status, body["error"]) == (412, "dial_not_authorized")

    def test_a_connection_failure_is_none_none(self):
        def boom(*a, **kw):
            raise OSError("refused")

        with patch("dial_appliance_fetch.http.client.HTTPConnection", boom):
            assert daf._send_one("capabilities", self._target()) == (None, None)

    def test_a_non_json_body_reports_the_status_and_none(self):
        with patch("dial_appliance_fetch.http.client.HTTPConnection", _conn_class(b"<html>", 404)):
            assert daf._send_one("capabilities", self._target()) == (404, None)

    def test_a_non_object_body_is_none(self):
        with patch("dial_appliance_fetch.http.client.HTTPConnection", _conn_class(b"[1]")):
            assert daf._send_one("capabilities", self._target()) == (200, None)

    def test_enqueue_coalesces_per_kind_and_appliance(self):
        assert daf.enqueue("capabilities", self._target())
        assert not daf.enqueue("capabilities", self._target("0.9"))
        assert daf.enqueue("capabilities", daf._FetchTarget(BID, "10.0.0.6", 80))
        assert daf._queue.qsize() == 2

    def test_an_unknown_kind_is_refused(self):
        assert not daf.enqueue("nonsense", self._target())
        assert daf._queue.qsize() == 0

    def test_the_worker_reports_each_read_with_its_version(self):
        done = threading.Event()
        got = []

        def on_result(*args):
            got.append(args)
            done.set()

        raw = json.dumps(_body()).encode()
        daf._on_result = on_result
        with patch("dial_appliance_fetch.http.client.HTTPConnection", _conn_class(raw)):
            threading.Thread(target=daf._worker, daemon=True).start()
            daf.enqueue("capabilities", self._target("0.8.0"))
            assert done.wait(5)
        assert got == [("capabilities", AID, "0.8.0", 200, _body())]
        # picked up: the same read may be queued again
        assert daf.enqueue("capabilities", self._target())

    def test_a_raising_callback_does_not_kill_the_worker(self):
        calls = []
        done = threading.Event()

        def on_result(*args):
            calls.append(args)
            if len(calls) == 1:
                raise RuntimeError("boom")
            done.set()

        daf._on_result = on_result
        with patch("dial_appliance_fetch.http.client.HTTPConnection", _conn_class(b"{}")):
            threading.Thread(target=daf._worker, daemon=True).start()
            daf.enqueue("capabilities", self._target())
            deadline = time.monotonic() + 5
            while not calls and time.monotonic() < deadline:
                time.sleep(0.01)
            daf.enqueue("capabilities", self._target())
            assert done.wait(5)


# ---- the core's schedule and fold ---------------------------------------------------


class _Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def _core(*entries, clock=None):
    core = DialCore("dial-1", lambda: [], lambda: [], clock=clock or _Clock())
    core.set_roster(list(entries))
    return core


@pytest.fixture
def _fetches():
    with patch("dial_core._enqueue_appliance_fetch") as enq:
        yield enq


class TestCoreSchedule:
    def test_a_v3_appliance_is_asked_for_its_capabilities(self, _fetches):
        core = _core(_entry(proto=3))
        core._refresh_capabilities(1000.0)
        assert _fetches.call_count == 1
        kind, target = _fetches.call_args.args
        assert kind == "capabilities"
        assert (target.appliance_id, target.ip, target.port, target.version) == (
            AID, "192.0.2.10", 80, "0.8.0")

    @pytest.mark.parametrize("proto", [0, 2])
    def test_older_generations_are_never_fetched(self, _fetches, proto):
        core = _core(_entry(proto=proto))
        core._refresh_capabilities(1000.0)
        assert not _fetches.called

    def test_an_entry_without_an_id_is_never_fetched(self, _fetches):
        core = _core(_entry(appliance_id="", proto=3))
        core._refresh_capabilities(1000.0)
        assert not _fetches.called

    def test_nothing_more_is_asked_once_the_reply_is_held(self, _fetches):
        core = _core(_entry(proto=3))
        assert core.on_capabilities_result(AID, "0.8.0", 200, _body())
        core._refresh_capabilities(2000.0)
        assert not _fetches.called

    def test_an_upgrade_makes_it_due_again(self, _fetches):
        core = _core(_entry(proto=3))
        core.on_capabilities_result(AID, "0.8.0", 200, _body())
        core.set_roster([_entry(proto=3, version="0.9.0")])
        core._refresh_capabilities(2000.0)
        assert _fetches.call_args.args[1].version == "0.9.0"

    def test_a_failure_backs_off(self, _fetches):
        clock = _Clock(1000.0)
        core = _core(_entry(proto=3), clock=clock)
        core.on_capabilities_result(AID, "0.8.0", None, None)
        core._refresh_capabilities(1030.0)
        assert not _fetches.called
        core._refresh_capabilities(1061.0)
        assert _fetches.called

    def test_housekeeping_runs_the_step(self, _fetches):
        core = _core(_entry(proto=3))
        core._housekeeping(1000.0)
        assert _fetches.called


class TestCoreFold:
    def test_a_reply_publishes_warnings_and_eq_version(self):
        core = _core(_entry(proto=3, dial_eq=True))
        before = core.snapshot()
        assert not before.appliances[0].supplies_warnings
        assert before.appliances[0].dial_eq_version == 1
        assert core.on_capabilities_result(AID, "0.8.0", 200, _body())
        after = core.snapshot().appliances[0]
        assert after.supplies_warnings and after.dial_eq_version == 2
        assert after.dial_outputs_version == 1 and after.dial_outputs
        assert core.snapshot().seq > before.seq

    def test_a_bad_reply_changes_nothing(self):
        core = _core(_entry(proto=3))
        seq = core.snapshot().seq
        assert not core.on_capabilities_result(AID, "0.8.0", 200, _body(appliance_id=BID))
        assert not core.on_capabilities_result(AID, "0.8.0", 404, None)
        assert core.snapshot().seq == seq
        assert dc.learned(AID) is None

    def test_a_reply_for_an_appliance_off_the_roster_is_ignored(self):
        core = _core(_entry(proto=3))
        assert not core.on_capabilities_result(BID, "0.8.0", 200, _body(appliance_id=BID))
        assert dc.learned(BID) is None

    def test_an_identical_reply_publishes_nothing(self):
        core = _core(_entry(proto=3))
        core.on_capabilities_result(AID, "0.8.0", 200, _body())
        seq = core.snapshot().seq
        assert not core.on_capabilities_result(AID, "0.8.0", 200, _body())
        assert core.snapshot().seq == seq

    def test_a_held_eq_state_moves_to_the_new_capability_version(self):
        core = _core(_entry(proto=3, dial_eq=True))
        core.set_focus(AID)
        core.watch_eq(AID, "spi", True, fetch=False)
        assert core.snapshot().eq.capability_version == 1
        core.on_capabilities_result(AID, "0.8.0", 200, _body())
        assert core.snapshot().eq.capability_version == 2

    def test_a_refusal_reads_the_switch_point(self):
        core = _core(_entry(proto=3, dial_eq=True))
        core.on_capabilities_result(AID, "0.8.0", 200, _body(capabilities={"dial_status": 1}))
        assert core.set_eq(AID, {"bass": 1}) == ActionResult(False, "no_capability")

    def test_a_v2_appliance_is_unaffected_by_a_stray_record(self):
        dc.record(AID, "0.8.0", {"dial_status": 1, "dial_eq": 2, "dial_warnings": 1}, 0.0)
        core = _core(_entry(proto=2, dial_eq=True))
        state = core.snapshot().appliances[0]
        assert state.dial_eq_version == 1 and not state.supplies_warnings


class TestResultRouting:
    def test_each_kind_reaches_its_core_method(self):
        from dial_main import _on_appliance_fetch_result
        core = MagicMock()
        route = _on_appliance_fetch_result(core)
        route("capabilities", AID, "0.8.0", 200, {"a": 1})
        route("warnings", AID, "", 412, {"b": 2})
        route("other", AID, "", 200, {})
        core.on_capabilities_result.assert_called_once_with(AID, "0.8.0", 200, {"a": 1})
        core.on_warnings_result.assert_called_once_with(AID, 412, {"b": 2})
