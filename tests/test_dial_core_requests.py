"""tests/test_dial_core_requests.py -- dial_core_requests: intents, replies, settling, the lane."""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
for _p in (_ROOT / "dial", _ROOT / "core"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import dial_core_requests as rq  # noqa: E402
from autostream_peer_client import PeerReply, PeerSnapshot  # noqa: E402
from dial_core_state import TransportRequest  # noqa: E402

AID = "a" * 20


def pending(kind="output_set", output_id="u1", shown=(True, 40), at=5.0):
    return TransportRequest(AID, kind, at, "pending", at, None, output_id, 0, shown)


def ok(version=7, boot="b1", result=None):
    return PeerReply(True, None, version, boot, result or {}, None)


def refused(error, retry=None):
    return PeerReply(False, error, None, None, {}, retry)


def snap(version=7, boot="b1", parts=None):
    return PeerSnapshot(peer_id=AID, boot=boot, version=version, part_versions={}, parts=parts or {},
                        reachable=True, access="playback", access_reason=None, protocol=4,
                        protocol_ok=True, configured=True, heard_at=1.0, seq=1)


# ---- intents --------------------------------------------------------------------


class TestIntents:
    def test_output_set(self):
        i = rq.output_set("u1", selected=True, volume=35)
        assert (i.kind, i.name, dict(i.args), i.extra_body) == (
            "output_set", "outputs.set", {"id": "u1", "selected": True, "volume": 35}, None)

    def test_output_set_without_a_level_sends_none(self):
        assert dict(rq.output_set("u1", selected=False).args) == {"id": "u1", "selected": False}

    def test_pin_capable_only_with_pin_entry(self):
        assert rq.output_set("u1", selected=True, pin_entry=True).extra_body == {"pin_capable": True}
        assert rq.output_set("u1", selected=True, pin_entry=False).extra_body is None

    def test_a_pin_submission_is_always_pin_capable(self):
        i = rq.output_pin("u1", "1234")
        assert (i.kind, i.name, dict(i.args), i.extra_body) == (
            "output_pin", "output.pin.submit", {"id": "u1", "pin": "1234"}, {"pin_capable": True})

    def test_band_ids_write_their_own_fields(self):
        i = rq.eq_set({"peq3": 2, "peq6": -20})
        assert (i.kind, i.name) == ("eq_set", "output.eq.set")
        assert i.args == {"fields": [["peq3_db", 2.0], ["peq6_db", -12.0]]}

    def test_bass_writes_the_two_lowest_bands(self):
        assert rq.eq_set({"bass": 9}).args == {"fields": [["peq1_db", 6.0], ["peq2_db", 6.0]]}

    def test_treble_writes_the_top_band_in_full_and_the_next_by_half(self):
        assert rq.eq_set({"treble": -4}).args == {"fields": [["peq6_db", -4.0], ["peq5_db", -2.0]]}

    def test_an_unknown_control_is_refused(self):
        with pytest.raises(ValueError):
            rq.eq_set({"mid": 1})

    def test_reset(self):
        i = rq.eq_reset()
        assert (i.kind, i.name, dict(i.args)) == ("eq_reset", "output.eq.reset", {})

    def test_replay_rows(self):
        assert (rq.replay_seek().kind, rq.replay_seek().name, dict(rq.replay_seek().args)) == (
            "seek", "repeat.seek", {"position": 0})
        assert (rq.replay_stop().kind, rq.replay_stop().name, dict(rq.replay_stop().args)) == (
            "stop", "repeat.transport", {"action": "stop"})
        assert (rq.repeat_arm(True).kind, rq.repeat_arm(True).name, dict(rq.repeat_arm(False).args)) == (
            "arm", "repeat.arm", {"armed": False})


# ---- folding a reply --------------------------------------------------------------


class TestFoldReply:
    def test_ok_is_accepted_and_keeps_the_shown_value(self):
        r = rq.fold_reply(pending(), ok(), 9.0)
        assert (r.state, r.changed_at, r.error, r.shown) == ("accepted", 9.0, None, (True, 40))

    def test_a_refusal_is_rejected_with_the_peers_name_and_drops_the_shown_value(self):
        r = rq.fold_reply(pending(), refused("output_in_use"), 9.0)
        assert (r.state, r.error, r.shown) == ("rejected", "output_in_use", None)

    @pytest.mark.parametrize("error", ["unreachable", "timeout", "bad_reply", "backoff", "protocol_mismatch"])
    def test_a_transport_outcome_is_rejected_with_its_name(self, error):
        r = rq.fold_reply(pending(), refused(error), 9.0)
        assert (r.state, r.error) == ("rejected", error)

    def test_a_pin_error_keeps_the_name_the_screens_map(self):
        assert rq.fold_reply(pending(), refused("pin_required"), 9.0).error == "pin_required"

    def test_a_refusal_without_a_name_reads_as_a_bad_reply(self):
        assert rq.fold_reply(pending(), PeerReply(False, None, None, None, {}, None), 9.0).error == "bad_reply"

    def test_rate_limited_carries_the_wait(self):
        r = rq.fold_reply(pending("seek", None, None), refused("rate_limited", 0.4), 9.0)
        assert (r.error, r.retry_after_s) == ("rate_limited", 1)

    def test_the_wait_is_capped_and_never_negative(self):
        assert rq.retry_after(refused("rate_limited", 99999)) == rq.RETRY_AFTER_MAX_S
        assert rq.retry_after(refused("rate_limited", -3)) == 0
        assert rq.retry_after(refused("rate_limited", None)) == 0

    def test_other_errors_carry_no_wait(self):
        assert rq.fold_reply(pending(), refused("output_in_use", 5.0), 9.0).retry_after_s == 0


# ---- settling ----------------------------------------------------------------------


def unit(availability="ok", uid="u1"):
    return {"id": uid, "name": "N", "availability": availability}


class TestSettling:
    def waiting(self, **kw):
        base = dict(appliance_id=AID, token=5.0, boot="b1", version=7)
        base.update(kw)
        return rq.Waiting(**base)

    def test_nothing_to_wait_for_without_a_shown_value_or_a_version(self):
        assert rq.wait_for(pending(shown=None), ok(), snap()) is None
        assert rq.wait_for(pending(), PeerReply(True, None, None, None, {}, None), snap()) is None

    def test_wait_for_records_the_reply_and_the_unit(self):
        w = rq.wait_for(pending(), ok(version=9, boot="bx"), snap(parts={"outputs": {"start_failure": {"seq": 4}}}))
        assert (w.appliance_id, w.token, w.boot, w.version, w.unit_id, w.failure_seq) == (
            AID, 5.0, "bx", 9, "u1", 4)

    def test_a_request_that_is_not_for_a_unit_waits_on_no_unit(self):
        assert rq.wait_for(pending("seek", None, (True, None)), ok(), snap()).unit_id is None

    def test_held_until_the_snapshot_reaches_the_reply_version(self):
        w = self.waiting(unit_id=None)
        assert not rq.settled(w, snap(version=6))
        assert rq.settled(w, snap(version=7))
        assert rq.settled(w, snap(version=8))

    def test_the_event_before_the_reply_settles_at_once(self):
        w = rq.wait_for(pending(), ok(version=7), snap(version=8, parts={"outputs": {"units": [unit()]}}))
        assert rq.settled(w, snap(version=8, parts={"outputs": {"units": [unit()]}}))

    def test_a_new_boot_settles(self):
        assert rq.settled(self.waiting(version=99), snap(version=1, boot="b2"))

    def test_an_unread_snapshot_never_settles(self):
        assert not rq.settled(self.waiting(), None)

    def test_a_missing_boot_does_not_count_as_a_new_one(self):
        assert not rq.settled(self.waiting(version=9), snap(version=3, boot=None))

    def test_a_starting_speaker_holds_the_value_past_the_version(self):
        w = self.waiting(unit_id="u1")
        starting = snap(version=8, parts={"outputs": {"units": [unit("starting")]}})
        assert not rq.settled(w, starting)
        assert rq.settled(w, snap(version=9, parts={"outputs": {"units": [unit("ok")]}}))

    def test_a_start_failure_for_the_unit_ends_the_wait(self):
        w = self.waiting(unit_id="u1", failure_seq=2)
        failed = snap(version=9, parts={"outputs": {
            "units": [unit("starting")], "start_failure": {"seq": 3, "unit_id": "u1"}}})
        assert rq.settled(w, failed)

    def test_an_old_start_failure_does_not_end_the_wait(self):
        w = self.waiting(unit_id="u1", failure_seq=3)
        old = snap(version=9, parts={"outputs": {
            "units": [unit("starting")], "start_failure": {"seq": 3, "unit_id": "u1"}}})
        assert not rq.settled(w, old)

    def test_a_failure_for_another_unit_does_not_end_the_wait(self):
        w = self.waiting(unit_id="u1", failure_seq=0)
        other = snap(version=9, parts={"outputs": {
            "units": [unit("starting")], "start_failure": {"seq": 1, "unit_id": "u2"}}})
        assert not rq.settled(w, other)

    def test_a_unit_that_has_gone_settles(self):
        assert rq.settled(self.waiting(unit_id="u1"), snap(version=8, parts={"outputs": {"units": []}}))


# ---- the lane ------------------------------------------------------------------------


class FakeClient:
    def __init__(self, reply=None, gate=None):
        self.calls = []
        self.reply = reply or ok()
        self.gate = gate

    def submit(self, name, args, *, extra_body=None, read_s=None, backoff=True):
        self.calls.append(("submit", name, dict(args), extra_body, read_s, backoff))
        if self.gate is not None:
            self.gate.wait(5)
        return self.reply

    def fetch(self, parts, *, merge=True):
        self.calls.append(("fetch", list(parts), merge))
        return {"repeat": {"block": {}}}


class Collector:
    def __init__(self):
        self.done = []
        self.event = threading.Event()

    def __call__(self, item, result):
        self.done.append((item, result))
        self.event.set()

    def wait(self, n=1, timeout=5.0):
        end = time.monotonic() + timeout
        while len(self.done) < n and time.monotonic() < end:
            time.sleep(0.005)
        assert len(self.done) >= n


@pytest.fixture
def lane_parts():
    created = []

    def make(clients, on_done):
        lane = rq.RequestLane(clients.get, on_done)
        created.append(lane)
        lane.start()
        return lane
    yield make
    for lane in created:
        lane.stop()


class TestLane:
    def test_a_request_is_sent_with_its_arguments_and_extra_body(self, lane_parts):
        client, got = FakeClient(), Collector()
        lane = lane_parts({AID: client}, got)
        i = rq.output_set("u1", selected=True, volume=20, pin_entry=True)
        lane.enqueue(rq.LaneItem(AID, i.kind, i.name, i.args, i.extra_body, token=5.0))
        got.wait()
        assert client.calls == [("submit", "outputs.set", {"id": "u1", "selected": True, "volume": 20},
                                 {"pin_capable": True}, None, True)]
        item, reply = got.done[0]
        assert item.token == 5.0 and reply.ok

    def test_items_are_sent_in_order_one_at_a_time(self, lane_parts):
        client, got = FakeClient(), Collector()
        lane = lane_parts({AID: client}, got)
        for n in range(3):
            lane.enqueue(rq.LaneItem(AID, "arm", "repeat.arm", {"armed": bool(n % 2)}, None, float(n)))
        got.wait(3)
        assert [c[2]["armed"] for c in client.calls] == [False, True, False]
        assert [item.token for item, _ in got.done] == [0.0, 1.0, 2.0]

    def test_a_refusal_reaches_the_handler(self, lane_parts):
        got = Collector()
        lane = lane_parts({AID: FakeClient(refused("rate_limited", 1.0))}, got)
        lane.enqueue(rq.LaneItem(AID, "seek", "repeat.seek", {"position": 0}, None, 1.0))
        got.wait()
        assert got.done[0][1].error == "rate_limited" and got.done[0][1].retry_after_s == 1.0

    def test_an_appliance_with_no_client_is_unreachable(self, lane_parts):
        got = Collector()
        lane = lane_parts({}, got)
        lane.enqueue(rq.LaneItem(AID, "stop", "repeat.transport", {"action": "stop"}, None, 1.0))
        got.wait()
        assert (got.done[0][1].ok, got.done[0][1].error) == (False, "unreachable")

    def test_a_fetch_reads_the_parts_with_merge(self, lane_parts):
        client, got = FakeClient(), Collector()
        lane = lane_parts({AID: client}, got)
        lane.enqueue(rq.LaneItem(AID, "fetch", parts=("repeat",)))
        got.wait()
        assert client.calls == [("fetch", ["repeat"], True)]
        assert got.done[0][1] == {"repeat": {"block": {}}}

    def test_a_fetch_for_an_appliance_with_no_client_gives_none(self, lane_parts):
        got = Collector()
        lane = lane_parts({}, got)
        lane.enqueue(rq.LaneItem(AID, "fetch", parts=("repeat",)))
        got.wait()
        assert got.done[0][1] is None

    def test_a_raising_handler_does_not_end_the_thread(self, lane_parts):
        client, seen = FakeClient(), []

        def handler(item, result):
            seen.append(item.token)
            raise RuntimeError("boom")
        lane = lane_parts({AID: client}, handler)
        for n in (1.0, 2.0):
            lane.enqueue(rq.LaneItem(AID, "arm", "repeat.arm", {"armed": True}, None, n))
        end = time.monotonic() + 5
        while len(seen) < 2 and time.monotonic() < end:
            time.sleep(0.005)
        assert seen == [1.0, 2.0]

    def test_a_raising_send_does_not_end_the_thread(self, lane_parts):
        class Bad(FakeClient):
            def submit(self, *a, **k):
                raise RuntimeError("boom")
        got = Collector()
        good = FakeClient()
        lane = lane_parts({AID: Bad(), "b" * 20: good}, got)
        lane.enqueue(rq.LaneItem(AID, "arm", "repeat.arm", {"armed": True}, None, 1.0))
        lane.enqueue(rq.LaneItem("b" * 20, "arm", "repeat.arm", {"armed": True}, None, 2.0))
        got.wait()
        assert got.done[0][0].token == 2.0

    def test_a_slow_item_holds_the_ones_behind_it(self, lane_parts):
        gate = threading.Event()
        slow, fast, got = FakeClient(gate=gate), FakeClient(), Collector()
        lane = lane_parts({AID: slow, "b" * 20: fast}, got)
        lane.enqueue(rq.LaneItem(AID, "arm", "repeat.arm", {"armed": True}, None, 1.0))
        lane.enqueue(rq.LaneItem("b" * 20, "arm", "repeat.arm", {"armed": True}, None, 2.0))
        time.sleep(0.1)
        assert fast.calls == [] and got.done == []
        gate.set()
        got.wait(2)
        assert [i.token for i, _ in got.done] == [1.0, 2.0]

    def test_stop_ends_the_thread(self):
        lane = rq.RequestLane({}.get, lambda item, result: None)
        lane.start()
        thread = lane._thread
        lane.stop()
        assert not thread.is_alive()


# ---- the core on the lane ------------------------------------------------------------

from dial_pool_support import Rig, aid, peer, replay_block, unit as pool_unit  # noqa: E402
from dial_pool_support import ok as reply_ok, refused as reply_refused  # noqa: E402

K = aid("Kitchen")


@pytest.fixture
def rig():
    r = Rig()
    yield r
    r.close()


def kitchen(rig, **kw):
    """Kitchen playing, focused, with one speaker and six bands."""
    base = dict(playing=True, units=[pool_unit(volume=40)], bands=[0, 0, 0, 0, 0, 0], version=1)
    base.update(kw)
    client = rig.add("Kitchen", peer("Kitchen", **base))
    rig.fold()
    return client


def sent(rig, client, n=1):
    assert rig.wait(lambda: len(client.sent()) >= n), client.calls
    return client.sent()


class TestCoreIntents:
    def test_a_speaker_switch(self, rig):
        client = kitchen(rig)
        assert rig.core.set_output(K, "u1", selected=True).accepted
        assert sent(rig, client)[0][1:] == ("outputs.set", {"id": "u1", "selected": True}, None)

    def test_a_speaker_level(self, rig):
        client = kitchen(rig)
        rig.core.set_output(K, "u1", selected=True, volume=30)
        assert sent(rig, client)[0][1:3] == ("outputs.set", {"id": "u1", "selected": True, "volume": 30})

    def test_pin_capable_only_with_pin_entry(self, rig):
        client = kitchen(rig)
        rig.core.set_output(K, "u1", selected=True, pin_entry=True)
        assert sent(rig, client)[0][3] == {"pin_capable": True}

    def test_a_pin_submission(self, rig):
        client = kitchen(rig)
        rig.core.set_output(K, "u1", pin="1234")
        assert sent(rig, client)[0][1:] == ("output.pin.submit", {"id": "u1", "pin": "1234"}, {"pin_capable": True})
        assert rig.core.snapshot().outputs_request.kind == "output_pin"

    def test_an_eq_band_and_a_step(self, rig):
        client = kitchen(rig)
        rig.core.set_eq(K, {"peq3": 2})
        rig.core.step_eq(K, "peq1", -1)
        calls = sent(rig, client, 2)
        assert calls[0][1:3] == ("output.eq.set", {"fields": [["peq3_db", 2.0]]})
        assert calls[1][1:3] == ("output.eq.set", {"fields": [["peq1_db", -1.0]]})

    def test_an_eq_reset_is_one_intent(self, rig):
        client = kitchen(rig)
        rig.core.reset_eq(K)
        assert sent(rig, client)[0][1:3] == ("output.eq.reset", {})
        pairs, _ = rig.core.eq_override()
        assert pairs and all(gain == 0 for _, gain in pairs)

    @pytest.mark.parametrize("method, expected", [
        ("start_replay", ("repeat.seek", {"position": 0})),
        ("restart_replay", ("repeat.seek", {"position": 0})),
        ("stop_replay", ("repeat.transport", {"action": "stop"})),
    ])
    def test_the_replay_rows(self, rig, method, expected):
        client = kitchen(rig, repeat=replay_block("replaying"))
        assert getattr(rig.core, method)(K).accepted
        assert sent(rig, client)[0][1:3] == expected

    def test_arming(self, rig):
        client = kitchen(rig, repeat=replay_block("recording"))
        assert rig.core.set_repeat_armed(K, True).accepted
        assert sent(rig, client)[0][1:3] == ("repeat.arm", {"armed": True})

    def test_a_replay_start_holds_the_focus_for_three_seconds(self, rig):
        kitchen(rig, repeat=replay_block("hold"))
        rig.core.start_replay(K)
        assert rig.core.snapshot().focus.pending[2] == rig.t + 3.0


class TestLocalRefusals:
    def test_an_unknown_appliance(self, rig):
        client = kitchen(rig)
        assert rig.core.set_output("f" * 20, "u1", selected=True).reason == "unknown_appliance"
        assert client.sent() == []

    def test_an_appliance_that_refused_this_dial(self, rig):
        client = rig.add("Kitchen", peer("Kitchen", access="none", access_reason="dial_not_authorized",
                                         units=[pool_unit()]))
        rig.fold()
        assert rig.core.set_output(K, "u1", selected=True).reason == "unauthorized"
        assert client.sent() == []

    def test_a_speaker_in_use_elsewhere(self, rig):
        client = kitchen(rig, units=[pool_unit(in_use_by="Hall", in_use_id="x")])
        assert rig.core.set_output(K, "u1", selected=True).reason == "wrong_state"
        assert client.sent() == []

    def test_a_pin_of_the_wrong_shape(self, rig):
        client = kitchen(rig)
        assert rig.core.set_output(K, "u1", pin="12").reason == "wrong_state"
        assert client.sent() == []

    def test_a_protocol_mismatch_has_no_capability(self, rig):
        client = rig.add("Kitchen", peer("Kitchen", protocol_ok=False, protocol=5))
        rig.fold()
        assert rig.core.set_eq(K, {"bass": 1}).reason == "no_capability"
        assert client.sent() == []

    def test_a_replay_with_no_record(self, rig):
        client = kitchen(rig)
        assert rig.core.stop_replay(K).reason == "no_record"
        assert client.sent() == []


class TestCoreSettling:
    def test_the_shown_value_is_kept_until_the_version_is_reached(self, rig):
        client = kitchen(rig, version=1)
        client.reply = reply_ok(version=5)
        rig.core.set_output(K, "u1", selected=True, volume=30)
        assert rig.wait(lambda: rig.core.snapshot().outputs_request.state == "accepted")
        assert rig.core.snapshot().outputs_request.shown == (True, 30)
        rig.set("Kitchen", peer("Kitchen", playing=True, units=[pool_unit(selected=True, volume=30)], version=5, seq=2))
        rig.fold()
        assert rig.core.snapshot().outputs_request.shown is None

    def test_an_event_before_the_reply_settles_at_once(self, rig):
        client = kitchen(rig, version=1)
        client.reply = reply_ok(version=5)
        client.gate = threading.Event()
        rig.core.set_output(K, "u1", selected=True)
        rig.set("Kitchen", peer("Kitchen", playing=True, units=[pool_unit(selected=True)], version=6, seq=2))
        rig.fold()
        client.gate.set()
        assert rig.wait(lambda: rig.core.snapshot().outputs_request.state == "accepted")
        assert rig.core.snapshot().outputs_request.shown is None

    def test_a_speaker_still_starting_holds_the_value_past_the_version(self, rig):
        client = kitchen(rig, version=1)
        client.reply = reply_ok(version=5)
        rig.core.set_output(K, "u1", selected=True)
        assert rig.wait(lambda: rig.core.snapshot().outputs_request.state == "accepted")
        rig.set("Kitchen", peer("Kitchen", playing=True, units=[pool_unit(availability="starting")], version=5, seq=2))
        rig.fold()
        assert rig.core.snapshot().outputs_request.shown is not None
        rig.set("Kitchen", peer("Kitchen", playing=True, units=[pool_unit(selected=True)], version=6, seq=3))
        rig.fold()
        assert rig.core.snapshot().outputs_request.shown is None

    def test_a_new_boot_settles(self, rig):
        client = kitchen(rig, version=1)
        client.reply = reply_ok(version=50)
        rig.core.set_output(K, "u1", selected=True)
        assert rig.wait(lambda: rig.core.snapshot().outputs_request.state == "accepted")
        rig.set("Kitchen", peer("Kitchen", playing=True, units=[pool_unit()], version=1, boot="b2", seq=2))
        rig.fold()
        assert rig.core.snapshot().outputs_request.shown is None

    @pytest.mark.parametrize("error", ["unreachable", "timeout", "bad_reply", "backoff", "protocol_mismatch"])
    def test_a_transport_outcome_is_rejected_with_its_name(self, rig, error):
        client = kitchen(rig)
        client.reply = reply_refused(error)
        rig.core.set_output(K, "u1", selected=True)
        assert rig.wait(lambda: rig.core.snapshot().outputs_request.state == "rejected")
        request = rig.core.snapshot().outputs_request
        assert (request.error, request.shown) == (error, None)

    def test_a_double_replay_tap_is_rate_limited(self, rig):
        client = kitchen(rig, repeat=replay_block("replaying"))
        client.reply = reply_refused("rate_limited", 0.6)
        rig.core.restart_replay(K)
        assert rig.wait(lambda: rig.core.snapshot().transport.state == "rejected")
        transport = rig.core.snapshot().transport
        assert (transport.error, transport.retry_after_s) == ("rate_limited", 1)


class TestSubmitIntent:
    def test_the_request_is_recorded_and_the_reply_returned(self, rig):
        client = kitchen(rig)
        client.reply = reply_ok(version=9)
        reply = rig.core.submit_intent(K, "outputs.set", {"id": "u1", "selected": True, "volume": 20})
        assert reply.ok and reply.version == 9
        request = rig.core.snapshot().outputs_request
        assert (request.kind, request.state, request.shown) == ("output_set", "accepted", (True, 20))
        assert client.sent()[0][1:] == ("outputs.set", {"id": "u1", "selected": True, "volume": 20}, None)

    def test_pin_capable_follows_pin_entry_and_a_pin_always_has_it(self, rig):
        client = kitchen(rig)
        rig.core.submit_intent(K, "outputs.set", {"id": "u1", "selected": True}, pin_entry=True)
        rig.core.submit_intent(K, "output.pin.submit", {"id": "u1", "pin": "4321"})
        assert [c[3] for c in client.sent()] == [{"pin_capable": True}, {"pin_capable": True}]

    def test_a_repeat_intent_is_recorded_on_the_transport(self, rig):
        kitchen(rig, repeat=replay_block("replaying"))
        rig.core.submit_intent(K, "repeat.transport", {"action": "stop"})
        assert rig.core.snapshot().transport.kind == "stop"

    @pytest.mark.parametrize("setup, name, args, expected", [
        ("ok", "volume.step", {}, "unknown_intent"),
        ("ok", "outputs.set", {"id": "nope", "selected": True}, "wrong_state"),
        ("ok", "output.pin.submit", {"id": "u1", "pin": "x"}, "wrong_state"),
        ("ok", "repeat.seek", {"position": 0}, "no_record"),
        ("refused", "outputs.set", {"id": "u1", "selected": True}, "dial_not_authorized"),
        ("mismatch", "output.eq.reset", {}, "protocol_mismatch"),
        ("gone", "outputs.set", {"id": "u1", "selected": True}, "unknown_appliance"),
    ])
    def test_a_local_refusal_sends_nothing(self, rig, setup, name, args, expected):
        if setup == "refused":
            client = rig.add("Kitchen", peer("Kitchen", access="none", access_reason="dial_not_authorized",
                                             units=[pool_unit()]))
        elif setup == "mismatch":
            client = rig.add("Kitchen", peer("Kitchen", protocol_ok=False, protocol=3))
        else:
            client = kitchen(rig)
        rig.fold()
        target = "f" * 20 if setup == "gone" else K
        reply = rig.core.submit_intent(target, name, args)
        assert (reply.ok, reply.error, reply.version, reply.boot, dict(reply.result), reply.retry_after_s) == (
            False, expected, None, None, {}, None)
        assert client.sent() == []

    def test_an_appliance_that_is_not_focused_is_refused(self, rig):
        kitchen(rig)
        client = rig.add("Lounge", peer("Lounge", units=[pool_unit()]))
        rig.fold()
        assert rig.core.submit_intent(aid("Lounge"), "output.eq.reset", {}).error == "wrong_state"
        assert client.sent() == []

    def test_it_sends_on_the_callers_thread_while_the_lane_is_blocked(self, rig):
        client = kitchen(rig)
        lounge = rig.add("Lounge", peer("Lounge"))
        lounge.gate = threading.Event()
        rig.fold()
        # A slow item holds the lane.
        rig.core._lane.enqueue(rq.LaneItem(aid("Lounge"), "arm", "repeat.arm", {"armed": True}, None, 1.0))
        assert rig.wait(lambda: lounge.sent())
        reply = rig.core.submit_intent(K, "output.pin.submit", {"id": "u1", "pin": "1234"})
        assert reply.ok
        assert client.threads == [threading.current_thread()]
        lounge.gate.set()

    def test_the_request_is_recorded_before_it_is_sent(self, rig):
        client = kitchen(rig)
        seen = []
        real = client.submit

        def submit(name, args, **kw):
            seen.append(rig.core.snapshot().outputs_request)
            return real(name, args, **kw)
        client.submit = submit
        rig.core.submit_intent(K, "outputs.set", {"id": "u1", "selected": True})
        assert seen[0] is not None and seen[0].state == "pending" and seen[0].kind == "output_set"
