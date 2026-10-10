"""Tests for the push worker's fan-out job: one push to every eligible dial.

Covers:
1.  Recipients: the authorised, sighted dials at protocol generation 3 or
    above, less the exclusion, each posted once with the appliance id added
    to the job's body.
2.  No retry, no sleep: a failed send is made once.
3.  The per-dial backoff: a failed dial is skipped inside the window, tried
    last after it, cleared by a success, and forgotten after a minute.
4.  The queue carries records: enqueue_fanout never touches the network,
    and the worker routes a named-dial job and a fan-out job differently.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

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
