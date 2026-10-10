"""Tests for telling dials that state changed: the fan-out job and the hint.

Covers:
1.  Fan-out recipients: the authorised, sighted dials at protocol generation
    3 or above, less the exclusion, each posted once with the appliance id
    added to the job's body.
2.  No retry, no sleep: a failed send is made once.
3.  The per-dial backoff: a failed dial is skipped inside the window, tried
    last after it, cleared by a success, and forgotten after a minute.
4.  The queue carries records: enqueue_fanout never touches the network,
    and the worker routes a named-dial job and a fan-out job differently.
5.  The coalescer: the first change goes at once, later ones inside the
    window go together when it ends, the exclusion is an intersection and
    the emit callback runs outside the lock. Time and the timer are injected.
6.  notify_state_changed: input checks, no raise, no I/O on the caller's
    thread, and what the emit function hands the push worker.
7.  The digests and the change watch the coordinator loop uses.
8.  The protocol document describes the route.
"""
from __future__ import annotations

import http.client
import socket
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_dial_push as dp
import autostream_webui_dials as wd
from autostream_dials import DialSighting

APPLIANCE_ID = "aaaaaaaaaaaaaaaaaaaa"
PATH = "/state-changed"


def _sighting(uuid, proto="v3"):
    return DialSighting(uuid=uuid, name=uuid, version="1.0.0", ip=f"ip-{uuid}",
                        port=7842, pin_recovery=False, dial_proto=proto)


class _Rig:
    """Canned dials file, sightings, clock and sender for _fanout."""

    def __init__(self, entries, sightings=None, appliance_id=APPLIANCE_ID):
        self.entries = entries
        self.sightings = (sightings if sightings is not None
                          else {u: _sighting(u) for u in entries})
        self.appliance_id = appliance_id
        self.now = 1000.0
        self.failing = set()
        self.posts = []

    def _post(self, ip, port, path, body, timeout):
        self.posts.append((ip, port, path, dict(body), timeout))
        return ip.removeprefix("ip-") not in self.failing

    def fanout(self, *, exclude=frozenset(), min_generation=3, body=None):
        job = wd._PushJob(PATH, None, body or {"changed": ["mute"]},
                          min_generation=min_generation, exclude=frozenset(exclude))
        self.posts.clear()
        with (
            patch.object(wd, "parse_dial_entries",
                         return_value=[SimpleNamespace(uuid=u) for u in self.entries]),
            patch.object(wd, "get_dial_sighting", side_effect=self.sightings.get),
            patch.object(wd, "get_appliance_id", return_value=self.appliance_id),
            patch.object(wd, "_post_push_body", side_effect=self._post),
            patch.object(wd.time, "monotonic", side_effect=lambda: self.now),
            patch.object(wd.time, "sleep", side_effect=AssertionError("fan-out slept")),
        ):
            wd._fanout(job)
        return [p[0].removeprefix("ip-") for p in self.posts]


class TestFanout:
    def setup_method(self):
        wd._fanout_failed_at.clear()

    def teardown_method(self):
        wd._fanout_failed_at.clear()

    def test_recipients_are_eligible_dials_less_the_exclusion(self):
        rig = _Rig(["a", "b", "c", "old", "gone"],
                   {"a": _sighting("a"), "b": _sighting("b"), "c": _sighting("c"),
                    "old": _sighting("old", "v2")})
        assert rig.fanout(exclude={"b"}) == ["a", "c"]

    def test_each_is_posted_once_with_the_id_added_and_the_push_timeout(self):
        rig = _Rig(["a", "b"])
        rig.fanout(body={"changed": ["mute", "volume"]})
        assert rig.posts == [
            ("ip-a", 7842, PATH,
             {"appliance_id": APPLIANCE_ID, "changed": ["mute", "volume"]}, wd._PUSH_TIMEOUT_S),
            ("ip-b", 7842, PATH,
             {"appliance_id": APPLIANCE_ID, "changed": ["mute", "volume"]}, wd._PUSH_TIMEOUT_S),
        ]

    def test_the_job_body_is_not_modified(self):
        rig = _Rig(["a"])
        body = {"changed": ["mute"]}
        rig.fanout(body=body)
        assert body == {"changed": ["mute"]}

    def test_no_retry_on_failure(self):
        rig = _Rig(["a", "b"])
        rig.failing = {"a", "b"}
        assert rig.fanout() == ["a", "b"]

    def test_a_failed_dial_is_skipped_2s_later(self):
        rig = _Rig(["a", "b"])
        rig.failing = {"a"}
        rig.fanout()
        rig.now += 2.0
        assert rig.fanout() == ["b"]

    def test_a_failed_dial_is_tried_last_6s_later(self):
        rig = _Rig(["a", "b", "c"])
        rig.failing = {"a"}
        rig.fanout()
        rig.now += 6.0
        assert rig.fanout() == ["b", "c", "a"]

    def test_a_success_clears_the_mark(self):
        rig = _Rig(["a", "b"])
        rig.failing = {"a"}
        rig.fanout()
        rig.now += 6.0
        rig.failing = set()
        assert rig.fanout() == ["b", "a"]
        assert "a" not in wd._fanout_failed_at
        assert rig.fanout() == ["a", "b"]

    def test_a_dial_that_fails_again_keeps_its_mark(self):
        rig = _Rig(["a", "b"])
        rig.failing = {"a"}
        rig.fanout()
        rig.now += 6.0
        rig.fanout()
        assert wd._fanout_failed_at["a"] == rig.now
        rig.now += 2.0
        assert rig.fanout() == ["b"]

    def test_marks_older_than_a_minute_are_pruned(self):
        rig = _Rig(["a"])
        wd._fanout_failed_at.update({"a": rig.now - 61.0, "gone": rig.now - 30.0})
        rig.fanout()
        assert "gone" in wd._fanout_failed_at
        wd._fanout_failed_at["gone"] = rig.now - 61.0
        rig.fanout()
        assert "gone" not in wd._fanout_failed_at

    def test_nothing_is_sent_without_an_identity(self):
        rig = _Rig(["a"], appliance_id=None)
        assert rig.fanout() == []

    def test_a_dial_that_vanishes_before_its_turn_is_skipped(self):
        rig = _Rig(["a", "b"])
        looked_up = []
        real = rig.sightings

        def get(uuid):
            if uuid == "a":
                looked_up.append(uuid)
                # Seen when the recipients are resolved, gone by the send.
                return real.get(uuid) if len(looked_up) == 1 else None
            return real.get(uuid)

        rig.sightings = SimpleNamespace(get=get)
        assert rig.fanout() == ["b"]
        assert len(looked_up) == 2

    def test_a_failed_dial_is_sent_to_again_exactly_at_the_backoff(self):
        rig = _Rig(["a"])
        rig.failing = {"a"}
        rig.fanout()
        rig.now += wd.STATE_FANOUT_BACKOFF_S - 0.001
        assert rig.fanout() == []
        rig.now += 0.001
        assert rig.fanout() == ["a"]

    def test_recipients_are_resolved_afresh_for_each_fan_out(self):
        rig = _Rig(["a"])
        assert rig.fanout() == ["a"]
        rig.entries = ["a", "new"]
        rig.sightings["new"] = _sighting("new")
        assert rig.fanout() == ["a", "new"]

    def test_a_failed_send_is_logged_with_the_dial(self, caplog):
        rig = _Rig(["a", "b"])
        rig.failing = {"b"}
        with caplog.at_level("DEBUG"):
            rig.fanout()
        lines = [r.getMessage() for r in caplog.records if "did not take" in r.getMessage()]
        assert lines == [
            f"dial push: b did not take {PATH}, skipping it for 5 s"]


class TestJobs:
    def test_enqueue_fanout_queues_one_record_and_never_touches_the_network(self):
        queue_ = wd.queue.SimpleQueue()
        with (
            patch.object(wd, "_push_queue", queue_),
            patch.object(wd, "_push_worker_thread", SimpleNamespace(is_alive=lambda: True)),
            patch.object(wd.http.client, "HTTPConnection") as conn,
            patch.object(wd, "parse_dial_entries", side_effect=AssertionError("read the file")),
        ):
            wd.enqueue_fanout(PATH, {"changed": ["mute"]}, min_generation=3,
                              exclude={"d1"})
        conn.assert_not_called()
        assert queue_.qsize() == 1
        job = queue_.get_nowait()
        assert job == wd._PushJob(PATH, None, {"changed": ["mute"]},
                                  min_generation=3, exclude=frozenset({"d1"}))

    def test_enqueue_push_queues_a_record_for_one_dial(self):
        queue_ = wd.queue.SimpleQueue()
        with (
            patch.object(wd, "_push_queue", queue_),
            patch.object(wd, "_push_worker_thread", SimpleNamespace(is_alive=lambda: True)),
        ):
            wd.enqueue_push("/auth-changed", "d1", APPLIANCE_ID)
        assert queue_.get_nowait() == wd._PushJob(
            "/auth-changed", "d1", {"appliance_id": APPLIANCE_ID})

    def test_run_job_routes_a_named_dial_to_push_once(self):
        job = wd._PushJob("/auth-changed", "d1", {"appliance_id": APPLIANCE_ID})
        with (
            patch.object(wd, "_push_once") as once,
            patch.object(wd, "_fanout") as fanout,
        ):
            wd._run_job(job)
        once.assert_called_once_with("/auth-changed", "d1", APPLIANCE_ID)
        fanout.assert_not_called()

    def test_run_job_routes_a_fan_out_job_to_fanout(self):
        job = wd._PushJob(PATH, None, {"changed": ["mute"]}, min_generation=3)
        with (
            patch.object(wd, "_push_once") as once,
            patch.object(wd, "_fanout") as fanout,
        ):
            wd._run_job(job)
        fanout.assert_called_once_with(job)
        once.assert_not_called()

    def test_post_push_keeps_its_signature_and_body(self):
        with patch.object(wd, "_post_push_body", return_value=True) as post:
            assert wd._post_push("ip", 7842, "/p", APPLIANCE_ID, 1.0) is True
        post.assert_called_once_with("ip", 7842, "/p", {"appliance_id": APPLIANCE_ID}, 1.0)


class _Time:
    """A clock the test moves by hand, and a timer it fires by hand."""

    def __init__(self):
        self.now = 100.0
        self.scheduled = []
        self.scheduled_at = 0.0

    def clock(self):
        return self.now

    def schedule(self, delay, fn):
        self.scheduled_at = self.now
        self.scheduled.append((delay, fn))

    def fire(self):
        _delay, fn = self.scheduled.pop(0)
        fn()


def _coalescer(min_interval_s=0.3):
    t = _Time()
    emitted = []
    c = dp.StateChangeCoalescer(
        lambda kinds, names: emitted.append((kinds, names)),
        clock=t.clock, schedule=t.schedule, min_interval_s=min_interval_s,
    )
    return c, t, emitted


class TestCoalescer:
    def test_the_first_change_is_emitted_at_once_with_its_exclusion(self):
        c, t, emitted = _coalescer()
        c.notify(("mute",), "d1")
        assert emitted == [(frozenset({"mute"}), frozenset({"d1"}))]
        assert t.scheduled == []

    def test_a_second_change_inside_the_window_waits_for_its_end(self):
        c, t, emitted = _coalescer()
        c.notify(("mute",))
        t.now += 0.1
        c.notify(("volume",))
        assert len(emitted) == 1
        assert len(t.scheduled) == 1
        assert abs(t.scheduled[0][0] - 0.2) < 1e-9

    def test_a_third_change_schedules_nothing_more(self):
        c, t, emitted = _coalescer()
        c.notify(("mute",))
        t.now += 0.1
        c.notify(("volume",))
        t.now += 0.1
        c.notify(("outputs",))
        assert len(t.scheduled) == 1
        assert len(emitted) == 1

    def test_the_flush_emits_the_merged_kinds_once(self):
        c, t, emitted = _coalescer()
        c.notify(("mute",))
        t.now += 0.1
        c.notify(("volume",))
        t.now += 0.1
        c.notify(("outputs", "volume"))
        t.now += 0.1
        t.fire()
        assert emitted[1] == (frozenset({"volume", "outputs"}), frozenset())
        assert len(emitted) == 2
        c.flush()
        assert len(emitted) == 2

    def test_a_change_after_the_window_is_emitted_at_once(self):
        c, t, emitted = _coalescer()
        c.notify(("mute",))
        t.now += 0.5
        c.notify(("volume",))
        assert [e[0] for e in emitted] == [frozenset({"mute"}), frozenset({"volume"})]
        assert t.scheduled == []

    def test_a_flush_restarts_the_window(self):
        c, t, emitted = _coalescer()
        c.notify(("mute",))
        t.now += 0.1
        c.notify(("volume",))
        t.now += 0.2
        t.fire()
        t.now += 0.1
        c.notify(("eq",))
        assert len(emitted) == 2
        assert len(t.scheduled) == 1
        assert abs(t.scheduled[0][0] - 0.2) < 1e-9

    def test_a_continuous_stream_is_emitted_about_three_times_a_second(self):
        c, t, emitted = _coalescer()
        end = t.now + 2.0
        while t.now < end:
            c.notify(("volume",))
            t.now += 0.05
            while t.scheduled and t.now >= t.scheduled_at + t.scheduled[0][0]:
                t.fire()
        assert 5 <= len(emitted) <= 8

    def test_exclusion_is_the_intersection_of_what_was_merged(self):
        for first, second, expected in (
            ("A", "A", {"A"}),
            ("A", "B", set()),
            ("A", None, set()),
            (None, "A", set()),
        ):
            c, t, emitted = _coalescer()
            c.notify(("outputs",))
            t.now += 0.1
            c.notify(("mute",), first)
            c.notify(("volume",), second)
            t.now += 0.2
            t.fire()
            assert emitted[-1][1] == frozenset(expected), (first, second)

    def test_a_flush_with_nothing_pending_emits_nothing(self):
        c, _t, emitted = _coalescer()
        c.flush()
        assert emitted == []

    def test_emit_runs_outside_the_lock(self):
        t = _Time()
        seen = []
        holder = {}

        def emit(kinds, names):
            seen.append(kinds)
            if len(seen) == 1:
                holder["c"].notify(("volume",))

        c = dp.StateChangeCoalescer(emit, clock=t.clock, schedule=t.schedule)
        holder["c"] = c
        done = threading.Event()

        def run():
            c.notify(("mute",))
            done.set()

        th = threading.Thread(target=run, daemon=True)
        th.start()
        assert done.wait(2.0), "emit re-entered notify and deadlocked"
        assert seen == [frozenset({"mute"})]
        assert len(t.scheduled) == 1

    def test_a_failing_schedule_lets_the_next_change_schedule_again(self):
        t = _Time()
        calls = []

        def schedule(delay, fn):
            calls.append(delay)
            if len(calls) == 1:
                raise RuntimeError("cannot start a thread")
            t.schedule(delay, fn)

        c = dp.StateChangeCoalescer(lambda k, n: None, clock=t.clock, schedule=schedule)
        c.notify(("mute",))
        t.now += 0.1
        try:
            c.notify(("volume",))
        except RuntimeError:
            pass
        c.notify(("eq",))
        assert len(calls) == 2


class TestNotify:
    def setup_method(self):
        self._original = dp._coalescer

    def teardown_method(self):
        dp._coalescer = self._original

    def test_a_change_reaches_the_coalescer_with_the_exclusion(self):
        calls = []
        dp._coalescer = SimpleNamespace(notify=lambda *a: calls.append(a))
        dp.notify_state_changed("mute", "volume", except_dial="d1")
        assert calls == [(("mute", "volume"), "d1")]

    def test_an_unknown_kind_or_none_is_dropped_not_raised(self):
        calls = []
        dp._coalescer = SimpleNamespace(notify=lambda *a: calls.append(a))
        dp.notify_state_changed()
        dp.notify_state_changed("nonsense")
        dp.notify_state_changed("mute", "nonsense")
        assert calls == []

    def test_an_empty_or_non_string_except_dial_reads_as_none(self):
        calls = []
        dp._coalescer = SimpleNamespace(notify=lambda *a: calls.append(a))
        dp.notify_state_changed("mute", except_dial="")
        dp.notify_state_changed("mute", except_dial=7)
        dp.notify_state_changed("mute", except_dial=None)
        assert [c[1] for c in calls] == [None, None, None]

    def test_a_raising_coalescer_never_raises_out(self):
        def boom(*_a):
            raise RuntimeError("boom")

        dp._coalescer = SimpleNamespace(notify=boom)
        dp.notify_state_changed("mute")

    def test_the_emit_function_queues_one_fan_out(self):
        with patch.object(wd, "enqueue_fanout") as fanout:
            dp._emit_hint(frozenset({"volume", "mute"}), frozenset({"d1"}))
        fanout.assert_called_once_with(
            "/state-changed", {"changed": ["mute", "volume"]},
            min_generation=3, exclude=frozenset({"d1"}),
        )

    def test_a_failing_emit_function_is_contained(self):
        with patch.object(wd, "enqueue_fanout", side_effect=RuntimeError("boom")):
            dp._emit_hint(frozenset({"mute"}), frozenset())

    def test_the_caller_does_no_network_or_file_work(self):
        jobs = []

        def refuse(*_a, **_k):
            raise AssertionError("I/O on the caller's thread")

        dp._coalescer = dp.StateChangeCoalescer(dp._emit_hint)
        with (
            patch.object(wd, "_enqueue", side_effect=jobs.append),
            patch.object(socket, "socket", refuse),
            patch.object(socket, "create_connection", refuse),
            patch.object(http.client.HTTPConnection, "request", refuse),
            patch("autostream_dials.parse_dial_entries", refuse),
            patch.object(wd, "parse_dial_entries", refuse),
        ):
            dp.notify_state_changed("mute", except_dial="d1")
        assert len(jobs) == 1
        assert jobs[0].uuid is None
        assert jobs[0].body == {"changed": ["mute"]}
        assert jobs[0].exclude == frozenset({"d1"})
        assert jobs[0].min_generation == 3

    def test_an_unhashable_kind_is_dropped_not_raised(self):
        calls = []
        dp._coalescer = SimpleNamespace(notify=lambda *a: calls.append(a))
        dp.notify_state_changed(["mute"])
        assert calls == []

    def test_the_default_timer_is_a_daemon_that_is_started(self):
        with patch.object(dp.threading, "Timer") as timer:
            dp._timer(0.2, print)
        timer.assert_called_once_with(0.2, print)
        assert timer.return_value.daemon is True
        timer.return_value.start.assert_called_once_with()

    def test_input_is_an_accepted_kind(self):
        assert "input" in dp.CHANGE_KINDS


def _snap(**over):
    fields = dict(enabled=True, state="identified", title="T", artist="A",
                  album="B", artwork_url="http://x/1", updated_at=1.0,
                  last_attempt_at=2.0)
    fields.update(over)
    return SimpleNamespace(**fields)


def _identified(title):
    return _snap(title=title, artwork_url=f"http://x/{title}")


def _analysing():
    return _snap(state="analysing", title="", artist="", album="", artwork_url="")


def _not_found():
    return _snap(state="not_found", title="", artist="", album="", artwork_url="")


def _waiting():
    return _snap(state="waiting", title="", artist="", album="", artwork_url="")


def _track_watch(snaps):
    """A track watch that reads the given snapshots in turn."""
    feed = iter(snaps)
    return dp.ChangeWatch("track", lambda: dp.track_digest(next(feed)))


class TestDigests:
    def _block(self, **over):
        rs = {
            "enabled": True, "armed": True,
            "recording": {"active": True, "seconds": 3.0},
            "replay": {"active": False, "fading_out": False, "position_seconds": 0.0},
        }
        rs.update(over)
        return rs

    def test_repeat_digest_moves_on_what_a_dial_shows(self):
        base = dp.repeat_digest(self._block())
        for changed in (
            self._block(armed=False),
            self._block(enabled=False),
            self._block(recording={"active": False, "seconds": 3.0}),
            self._block(recording={"active": True, "seconds": 0}),
            self._block(replay={"active": True, "fading_out": False}),
            self._block(replay={"active": False, "fading_out": True}),
        ):
            assert dp.repeat_digest(changed) != base

    def test_repeat_digest_ignores_positions_and_growing_seconds(self):
        a = dp.repeat_digest(self._block())
        b = dp.repeat_digest(self._block(recording={"active": True, "seconds": 4.0}))
        c = dp.repeat_digest(self._block(
            replay={"active": False, "fading_out": False, "position_seconds": 9.5}))
        assert a == b == c

    def test_repeat_digest_of_a_non_dict_is_empty(self):
        assert dp.repeat_digest(None) == ()
        assert dp.repeat_digest("x") == ()

    def test_repeat_digest_tolerates_missing_blocks(self):
        assert dp.repeat_digest({}) == (False, False, False, False, False, False)

    def _snap(self, **over):
        return _snap(**over)

    def test_track_digest_moves_on_title_or_artwork(self):
        base = dp.track_digest(self._snap())
        assert dp.track_digest(self._snap(title="U")) != base
        assert dp.track_digest(self._snap(artwork_url="http://x/2")) != base
        assert dp.track_digest(self._snap(state="waiting")) != base

    def test_track_digest_ignores_timestamps(self):
        base = dp.track_digest(self._snap())
        assert dp.track_digest(self._snap(updated_at=9.0, last_attempt_at=8.0)) == base

    def test_track_digest_of_an_analysing_snapshot_is_no_reading(self):
        assert dp.track_digest(self._snap(state="analysing", title="")) is None

    def test_track_digest_of_nothing_is_not_identified(self):
        assert dp.track_digest(None) == (False, False, "", "", "", "")

    def test_track_digest_does_not_tell_unidentified_states_apart(self):
        assert (dp.track_digest(self._snap(state="not_found", title="", artwork_url=""))
                == dp.track_digest(self._snap(state="waiting", title="", artwork_url="")))

    def test_artwork_that_is_not_http_is_left_out(self):
        assert dp.track_digest(self._snap(artwork_url="file:///x.png"))[-1] == ""
        assert dp.track_digest(self._snap(artwork_url=None))[-1] == ""
        assert dp.track_digest(self._snap(artwork_url="https://x/1"))[-1] == "https://x/1"

    def test_artwork_on_an_unidentified_snapshot_is_left_out(self):
        digest = dp.track_digest(self._snap(state="not_found", artwork_url="http://x/1"))
        assert digest[-1] == ""
        assert digest[2:5] == ("", "", "")

    def test_repeat_digest_is_never_none(self):
        for value in (None, {}, [], "x", 3, self._block()):
            assert dp.repeat_digest(value) is not None


class TestChangeWatch:
    def test_the_first_reading_is_silent(self):
        with patch.object(dp, "notify_state_changed") as notify:
            watch = dp.ChangeWatch("repeat", lambda: (1,))
            assert watch.step() is False
        notify.assert_not_called()

    def test_a_change_notifies_once_with_its_kind(self):
        values = iter([(1,), (2,), (2,)])
        with patch.object(dp, "notify_state_changed") as notify:
            watch = dp.ChangeWatch("track", lambda: next(values))
            assert watch.step() is False
            assert watch.step() is True
            assert watch.step() is False
        notify.assert_called_once_with("track")

    def test_a_raising_digest_is_silent_and_keeps_the_last_value(self):
        script = [(1,), RuntimeError("boom"), (1,), (2,)]

        def digest():
            item = script.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

        with patch.object(dp, "notify_state_changed") as notify:
            watch = dp.ChangeWatch("repeat", digest)
            assert watch.step() is False
            assert watch.step() is False
            assert watch.step() is False
            notify.assert_not_called()
            assert watch.step() is True
        notify.assert_called_once_with("repeat")

    def test_a_recheck_of_the_same_track_notifies_nothing(self):
        watch = _track_watch([_identified("A"), _analysing(), _identified("A")])
        with patch.object(dp, "notify_state_changed") as notify:
            for _ in range(3):
                watch.step()
        notify.assert_not_called()

    def test_retrying_an_unidentified_track_notifies_nothing(self):
        watch = _track_watch([_not_found(), _analysing(), _not_found(),
                              _analysing(), _not_found()])
        with patch.object(dp, "notify_state_changed") as notify:
            for _ in range(5):
                watch.step()
        notify.assert_not_called()

    def test_a_title_change_across_a_recheck_notifies_once(self):
        watch = _track_watch([_identified("A"), _analysing(), _identified("B")])
        with patch.object(dp, "notify_state_changed") as notify:
            for _ in range(3):
                watch.step()
        notify.assert_called_once_with("track")

    def test_a_track_change_through_waiting_notifies_twice(self):
        watch = _track_watch([_identified("A"), _waiting(), _analysing(),
                              _identified("B")])
        with patch.object(dp, "notify_state_changed") as notify:
            for _ in range(4):
                watch.step()
        assert notify.call_count == 2

    def test_a_first_reading_in_flight_leaves_the_watch_unprimed(self):
        watch = _track_watch([_analysing(), _identified("A"), _identified("B")])
        with patch.object(dp, "notify_state_changed") as notify:
            assert watch.step() is False
            assert watch.step() is False
            notify.assert_not_called()
            assert watch.step() is True
        notify.assert_called_once_with("track")

    def test_a_session_event_notifies_session_and_steps_every_watch(self):
        stepped = []
        watches = [SimpleNamespace(step=(lambda i=i: stepped.append(i))) for i in range(2)]
        with patch.object(dp, "notify_state_changed") as notify:
            dp.hint_dials_after_cycle("session_started", watches)
        notify.assert_called_once_with("session")
        assert stepped == [0, 1]

    def test_no_session_event_notifies_nothing_but_still_steps(self):
        stepped = []
        watch = SimpleNamespace(step=lambda: stepped.append(1))
        with patch.object(dp, "notify_state_changed") as notify:
            dp.hint_dials_after_cycle(None, (watch,))
        notify.assert_not_called()
        assert stepped == [1]


class TestDoc:
    def _text(self):
        return (REPO_ROOT / "docs" / "dial" / "DIAL_PROTOCOL.md").read_text(encoding="utf-8")

    def test_the_route_and_every_sent_token_are_documented(self):
        text = self._text()
        assert "### `POST /state-changed`" in text
        for kind in dp.CHANGE_KINDS - {"input"}:
            assert f"| `{kind}` |" in text, kind

    def test_the_capability_table_has_a_row_for_the_route(self):
        assert "| (none) | the dial's `POST /state-changed` |" in self._text()


class TestCallSites:
    """Each call site hints with the literal kinds, after its change, and
    never when nothing changed."""

    def test_an_output_mutation_that_succeeds_hints_outputs_once(self):
        import autostream_appliance_models as models
        with patch("autostream_appliance_models._apply_output_mutation",
                   return_value={"ok": True, "id": "o"}) as inner, \
             patch("autostream_appliance_models.notify_state_changed") as notify:
            result = models.apply_output_mutation(
                "http://x", "o", {"id": "o", "selected": True},
                offset_ms=5, mode="m", output_name="n",
                initiated_by="user", requester="r")
        assert result == {"ok": True, "id": "o"}
        notify.assert_called_once_with("outputs")
        inner.assert_called_once_with(
            "http://x", "o", {"id": "o", "selected": True},
            offset_ms=5, mode="m", output_name="n",
            initiated_by="user", requester="r")

    def test_an_output_mutation_that_fails_does_not_hint(self):
        import autostream_appliance_models as models
        failed = {"ok": False, "id": "o", "error": "x"}
        with patch("autostream_appliance_models._apply_output_mutation",
                   return_value=failed), \
             patch("autostream_appliance_models.notify_state_changed") as notify:
            result = models.apply_output_mutation(
                "http://x", "o", {"id": "o", "selected": True}, initiated_by="system")
        assert result is failed
        notify.assert_not_called()

    def test_an_output_mutation_that_raises_does_not_hint(self):
        import autostream_appliance_models as models
        with patch("autostream_appliance_models.notify_state_changed") as notify:
            try:
                models.apply_output_mutation("http://x", "o", {}, initiated_by="bogus")
            except ValueError:
                pass
            else:
                raise AssertionError("expected ValueError")
        notify.assert_not_called()

    def _mute(self, body, status=200):
        import autostream_webui_api as api
        calls = []
        with patch("autostream_webui_api.dial_authorization", return_value="authorized"), \
             patch("autostream_webui_api.apply_mute_action", return_value=(status, body)), \
             patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, b: calls.append(("send_json", c))), \
             patch("autostream_webui_api.notify_state_changed",
                   side_effect=lambda *k, **kw: calls.append(("notify", k, kw))):
            api.send_dial_mute_post_json(
                object(), object(), {"dial_id": "dial-1", "action": "mute"})
        return calls

    def test_a_mute_hints_after_the_reply_leaving_out_the_asking_dial(self):
        assert self._mute({"ok": True, "muted": True}) == [
            ("send_json", 200), ("notify", ("mute",), {"except_dial": "dial-1"})]

    def test_a_mute_that_did_not_work_does_not_hint(self):
        assert self._mute({"ok": False, "error": "backend_unavailable"}) == [
            ("send_json", 200)]

    def _volume(self, delta, *, muted=False, outputs=None, update_ok=None,
                restore=None):
        import autostream_webui_api as api
        from autostream_players import ActionResult, ListOutputsResult, OutputInfo
        calls = []
        outs = outputs if outputs is not None else [
            OutputInfo(id="a", name="a", selected=True, volume_percent=40),
            OutputInfo(id="b", name="b", selected=True, volume_percent=20)]
        updates = iter(update_ok if update_ok is not None else [True] * len(outs))
        parsed = SimpleNamespace(owntone=SimpleNamespace(
            base_url="http://x", volume_percent=20))

        def notify(*kinds, **kw):
            calls.append(("notify", kinds, kw, api._volume_lock.locked()))

        with patch("autostream_webui_api.dial_authorization", return_value="authorized"), \
             patch("autostream_webui_api._config_snapshot", return_value=parsed), \
             patch("autostream_webui_api.list_outputs",
                   return_value=ListOutputsResult(ok=True, outputs=tuple(outs))), \
             patch("autostream_webui_api.update_output",
                   side_effect=lambda *a, **kw: ActionResult(ok=next(updates))), \
             patch("autostream_webui_api.mute_state.is_muted", return_value=muted), \
             patch("autostream_webui_api._restore_locked",
                   return_value=restore or (200, {"ok": True}, outs)), \
             patch("autostream_webui_api.send_json",
                   side_effect=lambda h, c, b: calls.append(("send_json", c, dict(b)))), \
             patch("autostream_webui_api.notify_state_changed", side_effect=notify):
            api.send_dial_volume_post_json(
                object(), object(), {"dial_id": "dial-1", "delta": delta})
        return calls

    def test_a_volume_step_hints_after_the_reply_outside_the_lock(self):
        calls = self._volume(5)
        assert [c[0] for c in calls] == ["send_json", "notify"]
        assert calls[1] == ("notify", ("volume",), {"except_dial": "dial-1"}, False)

    def test_a_partly_failed_volume_step_still_hints(self):
        calls = self._volume(5, update_ok=[True, False])
        assert calls[0][2].get("partial") is True
        assert calls[1] == ("notify", ("volume",), {"except_dial": "dial-1"}, False)

    def test_a_volume_step_where_every_output_failed_does_not_hint(self):
        calls = self._volume(5, update_ok=[False, False])
        assert [c[0] for c in calls] == ["send_json"]
        assert calls[0][2] == {"ok": False, "error": "all_outputs_failed"}

    def test_volume_up_while_muted_hints_mute_and_volume_outside_the_lock(self):
        calls = self._volume(5, muted=True)
        assert [c[0] for c in calls] == ["send_json", "notify"]
        assert calls[1] == (
            "notify", ("mute", "volume"), {"except_dial": "dial-1"}, False)

    def test_a_restore_that_failed_does_not_hint(self):
        calls = self._volume(
            5, muted=True, restore=(200, {"ok": False, "error": "x"}, []))
        assert [c[0] for c in calls] == ["send_json"]

    def test_volume_down_while_muted_changes_nothing_and_does_not_hint(self):
        calls = self._volume(-5, muted=True)
        assert [c[0] for c in calls] == ["send_json"]
        assert calls[0][2]["muted"] is True

    def test_a_volume_step_with_no_active_outputs_does_not_hint(self):
        from autostream_players import OutputInfo
        calls = self._volume(
            5, outputs=[OutputInfo(id="a", name="a", selected=False, volume_percent=0)])
        assert [c[0] for c in calls] == ["send_json"]


class TestRepeatAndLoopCallSites:
    """The repeat acknowledgement hints after the cache and session state are
    written and outside the cache lock; the coordinator's watches read the
    cached repeat state and the identified track."""

    @staticmethod
    def _block():
        return {
            "enabled": True, "armed": True,
            "recording": {"active": False, "seconds": 342.0, "origin_input": 1},
            "replay": {"active": False, "fading_out": False,
                       "position_seconds": 0.0, "duration_seconds": 0.0},
        }

    @staticmethod
    def _ack(state="replaying", ok=True):
        return {"type": "ack", "command": "repeat_seek", "ok": ok,
                "state": state, "armed": True, "position_seconds": 5.0}

    def _apply(self, ack, cached=True):
        import autostream_core as core
        seen = []

        def notify(*kinds, **kw):
            free = core._repeat_status_lock.acquire(blocking=False)
            if free:
                core._repeat_status_lock.release()
            seen.append((kinds, kw, free,
                         core.get_repeat_status()["replay"]["active"],
                         core.get_session_state()["active"]))

        core._set_repeat_status(self._block() if cached else None)
        core._set_session_state(False, None)
        try:
            with patch("autostream_core._rearm_replay_identification"), \
                 patch("autostream_core._announce_replay_playing"), \
                 patch("autostream_core.notify_state_changed", side_effect=notify) as n:
                result = core.apply_repeat_ack(ack)
        finally:
            core._set_repeat_status(None)
            core._set_session_state(False, None)
        return result, n, seen

    def test_a_repeat_ack_hints_repeat_after_the_state_is_written(self):
        ack = self._ack()
        result, notify, seen = self._apply(ack)
        assert result is ack
        notify.assert_called_once_with("repeat")
        kinds, kw, lock_free, replay_active, session_active = seen[0]
        assert kinds == ("repeat",) and kw == {}
        assert lock_free is True
        assert replay_active is True
        assert session_active is True

    def test_a_failed_ack_does_not_hint(self):
        _, notify, _ = self._apply(self._ack(ok=False))
        notify.assert_not_called()

    def test_an_ack_with_no_cached_status_does_not_hint(self):
        _, notify, _ = self._apply(self._ack(), cached=False)
        notify.assert_not_called()

    def test_an_unknown_state_or_command_or_no_ack_does_not_hint(self):
        for ack in (self._ack(state="bogus"),
                    dict(self._ack(), command="repeat_dance"), None):
            _, notify, _ = self._apply(ack)
            notify.assert_not_called()

    def test_the_loop_hints_once_after_the_announcement_sync(self):
        import inspect
        import autostream_core as core
        src = inspect.getsource(core.run_autostream)
        assert src.count("hint_dials_after_cycle(") == 1
        hook = src.index("hint_dials_after_cycle(session_event, dial_hint_watches)")
        assert src.index(
            "_sync_playing_announcement(session_source is not None, version)") < hook
        assert hook < src.index("_teardown_identification_after_replay_end(")
        assert ('ChangeWatch("repeat", lambda: repeat_digest(get_repeat_status()))'
                in src)
        assert ('ChangeWatch("track", lambda: track_digest('
                'get_active_track_identification_snapshot()))' in src)
        assert (src.index("dial_hint_watches = (")
                < src.index("\n    while not stop_flag.is_set():"))

    def test_the_loops_digests_read_the_cached_state(self):
        import autostream_core as core
        rs = {"v": self._block()}
        snap = {"v": _snap()}
        with patch("autostream_core.get_repeat_status", side_effect=lambda: rs["v"]), \
             patch("autostream_core.get_active_track_identification_snapshot",
                   side_effect=lambda: snap["v"]), \
             patch.object(dp, "notify_state_changed") as notify:
            watches = (
                dp.ChangeWatch("repeat", lambda: dp.repeat_digest(core.get_repeat_status())),
                dp.ChangeWatch("track", lambda: dp.track_digest(
                    core.get_active_track_identification_snapshot())),
            )
            for w in watches:
                assert w.step() is False
            rs["v"] = dict(self._block(), armed=False)
            assert watches[0].step() is True
            assert watches[1].step() is False
            snap["v"] = _snap(title="Other")
            assert watches[1].step() is True
        assert [c.args for c in notify.call_args_list] == [("repeat",), ("track",)]
