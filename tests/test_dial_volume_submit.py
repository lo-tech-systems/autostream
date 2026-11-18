"""dial_volume sends a volume step and a mute through the target's client:
`submit` with the short read and without the write backoff, no `default_level`
in the arguments, the mute action as "mute" or "restore", a fan-out thread per
target, mute-all decided from each client's held `muted_all`, and the readout
following the stream's master volume."""
from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
for _p in (str(REPO_ROOT / "dial"), str(REPO_ROOT / "core"), str(REPO_ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import dial_volume as dv
from dial_mdns import PlayingTarget
from dial_pool_support import Rig, aid, ok, peer, refused


class SubmitClient:
    """A PeerClient stand-in that records every submit with its keywords and
    models the write backoff: a transport failure on a call that asked for
    the backoff refuses the calls after it."""

    def __init__(self, snap=None, reply=None) -> None:
        self.snap = snap
        self.reply = reply if reply is not None else ok(result={"ok": True, "volume": 50, "muted": False})
        self.calls: list = []
        self.in_backoff = False

    def snapshot(self):
        return self.snap

    def submit(self, name, args, *, extra_body=None, read_s=None, backoff=True):
        self.calls.append((name, dict(args), read_s, backoff))
        if backoff and self.in_backoff:
            return refused("backoff", 5.0)
        if not self.reply.ok and self.reply.error in ("timeout", "unreachable") and backoff:
            self.in_backoff = True
        return self.reply


def target(name: str, ip: str = "192.0.2.10") -> PlayingTarget:
    return PlayingTarget(ip=ip, port=80, name=name, dial_api=True,
                         service_name=f"autostream on {name}", appliance_id=aid(name))


@pytest.fixture(autouse=True)
def clean():
    def reset():
        dv._fail_counts.clear()
        dv.observe_master_volume(None, None)
        dv.observe_mute_state(None, None)
        dv._on_readout_changed = None
        dv._on_mute_changed = None
        dv._client_for = None
    reset()
    yield
    reset()


def wire(**clients):
    by_id = {aid(name): client for name, client in clients.items()}
    dv._client_for = by_id.get
    return by_id


class TestStep:
    def test_a_step_is_one_submit_with_the_short_read_and_no_backoff(self):
        client = SubmitClient()
        wire(Kitchen=client)
        dv._send_one(target("Kitchen"), 4, [])
        assert client.calls == [("volume.step", {"delta": 4}, 0.4, False)]

    def test_no_default_level_is_sent(self):
        client = SubmitClient()
        wire(Kitchen=client)
        dv._send_one(target("Kitchen"), -2, [])
        assert "default_level" not in client.calls[0][1]

    @pytest.mark.parametrize("muted, action", [(True, "mute"), (False, "restore")])
    def test_a_mute_is_the_mute_set_action(self, muted, action):
        client = SubmitClient(reply=ok(result={"ok": True, "muted": muted}))
        wire(Kitchen=client)
        dv._send_one_mute(target("Kitchen"), muted)
        assert client.calls == [("mute.set", {"action": action}, 0.4, False)]

    def test_a_target_with_no_client_is_not_sent_to(self, caplog):
        wire()
        with caplog.at_level(logging.DEBUG):
            dv._send_one(target("Ghost"), 1, [])
            dv._send_one_mute(target("Ghost"), True)
        assert dv.shown_volume("autostream on Ghost") is None

    def test_a_fan_out_over_three_targets_sends_one_step_each(self):
        clients = {n: SubmitClient() for n in ("Kitchen", "Lounge", "Study")}
        wire(**clients)
        targets = [target(n, ip=f"192.0.2.{i}") for i, n in enumerate(clients, 10)]
        dv._fan_out(targets, 3)
        assert all(c.calls == [("volume.step", {"delta": 3}, 0.4, False)] for c in clients.values())

    def test_a_mute_fan_out_sends_the_same_action_to_every_target(self):
        clients = {n: SubmitClient(reply=ok(result={"ok": True, "muted": True})) for n in ("Kitchen", "Lounge")}
        wire(**clients)
        dv._fan_out_mute([target(n, ip=f"192.0.2.{i}") for i, n in enumerate(clients, 10)], True)
        assert all(c.calls == [("mute.set", {"action": "mute"}, 0.4, False)] for c in clients.values())


class TestReply:
    def test_a_reply_at_the_top_sets_the_clamp(self):
        wire(Kitchen=SubmitClient(reply=ok(result={"ok": True, "volume": 100, "muted": False})))
        clamped: list = []
        dv._send_one(target("Kitchen"), 5, clamped)
        assert clamped == [True]

    def test_a_reply_at_the_bottom_sets_the_clamp(self):
        wire(Kitchen=SubmitClient(reply=ok(result={"ok": True, "volume": 0, "muted": True})))
        clamped: list = []
        dv._send_one(target("Kitchen"), -5, clamped)
        assert clamped == [True]

    def test_a_reply_inside_the_range_does_not(self):
        wire(Kitchen=SubmitClient(reply=ok(result={"ok": True, "volume": 60, "muted": False})))
        clamped: list = []
        dv._send_one(target("Kitchen"), 5, clamped)
        assert clamped == []

    def test_the_reply_sets_the_readout_and_the_mute_flag(self):
        wire(Kitchen=SubmitClient(reply=ok(result={"ok": True, "volume": 42, "muted": True})))
        seen: list = []
        dv._on_readout_changed = lambda: seen.append(1)
        dv._send_one(target("Kitchen"), 2, [])
        assert dv.shown_volume("autostream on Kitchen") == 42
        assert dv.shown_muted("autostream on Kitchen") is True
        assert seen == [1]

    def test_a_refusal_changes_nothing(self):
        wire(Kitchen=SubmitClient(reply=refused("all_outputs_failed")))
        clamped: list = []
        dv._send_one(target("Kitchen"), 2, clamped)
        assert clamped == [] and dv.shown_volume("autostream on Kitchen") is None
        assert dv._fail_counts == {"192.0.2.10": 1}

    @pytest.mark.parametrize("error", ["dial_not_authorized", "unconfigured", "protocol_mismatch"])
    def test_an_access_refusal_is_quiet_and_not_a_failure(self, error, caplog):
        wire(Kitchen=SubmitClient(reply=refused(error)))
        with caplog.at_level(logging.DEBUG):
            dv._send_one(target("Kitchen"), 2, [])
            dv._send_one_mute(target("Kitchen"), True)
        assert dv._fail_counts == {}
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]

    def test_success_clears_the_failure_count(self):
        dv._fail_counts["192.0.2.10"] = 3
        wire(Kitchen=SubmitClient())
        dv._send_one(target("Kitchen"), 1, [])
        assert dv._fail_counts == {}


class TestTimeouts:
    def test_a_burst_of_timed_out_steps_leaves_other_requests_unrefused(self):
        client = SubmitClient(reply=refused("timeout"))
        wire(Kitchen=client)
        for _ in range(5):
            dv._send_one(target("Kitchen"), 1, [])
        assert not client.in_backoff
        client.reply = ok()
        other = client.submit("output.eq.set", {"fields": []})
        assert other.ok and other.error is None


class TestMuteAll:
    def _held(self, **kwargs):
        clients = {
            n: SubmitClient(snap=peer(n, muted_all=muted, reachable=reachable),
                            reply=ok(result={"ok": True, "muted": True}))
            for n, (muted, reachable) in kwargs.items()
        }
        wire(**clients)
        return clients, [target(n, ip=f"192.0.2.{i}") for i, n in enumerate(clients, 10)]

    def test_one_unmuted_appliance_makes_the_action_mute(self):
        clients, targets = self._held(Kitchen=(True, True), Lounge=(False, True))
        dv._dispatch_mute_all(targets)
        assert {c.calls[0][1]["action"] for c in clients.values()} == {"mute"}

    def test_every_appliance_muted_makes_the_action_restore(self):
        clients, targets = self._held(Kitchen=(True, True), Lounge=(True, True))
        dv._dispatch_mute_all(targets)
        assert {c.calls[0][1]["action"] for c in clients.values()} == {"restore"}

    def test_an_unreachable_appliance_counts_as_unmuted(self):
        clients, targets = self._held(Kitchen=(True, True), Lounge=(True, False))
        dv._dispatch_mute_all(targets)
        assert {c.calls[0][1]["action"] for c in clients.values()} == {"mute"}

    def test_an_appliance_with_no_snapshot_counts_as_unmuted(self):
        clients, targets = self._held(Kitchen=(True, True))
        wire(Kitchen=clients["Kitchen"], Lounge=SubmitClient(snap=None))
        targets.append(target("Lounge", ip="192.0.2.11"))
        dv._dispatch_mute_all(targets)
        assert clients["Kitchen"].calls[0][1]["action"] == "mute"

    def test_the_decision_sends_only_the_mute_requests(self):
        clients, targets = self._held(Kitchen=(True, True), Lounge=(True, True))
        dv._dispatch_mute_all(targets)
        assert all(len(c.calls) == 1 and c.calls[0][0] == "mute.set" for c in clients.values())

    def test_the_echo_lands_for_every_target_before_the_sends(self):
        clients, targets = self._held(Kitchen=(False, True), Lounge=(False, True))
        seen: dict = {}
        orig = SubmitClient.submit

        def spy(self, *a, **k):
            for t in targets:
                seen.setdefault(t.service_name, dv.shown_muted(t.service_name))
            return orig(self, *a, **k)

        SubmitClient.submit = spy
        try:
            dv._dispatch_mute_all(targets)
        finally:
            SubmitClient.submit = orig
        assert seen == {"autostream on Kitchen": True, "autostream on Lounge": True}

    def test_no_targets_sends_nothing(self):
        clients, _ = self._held(Kitchen=(True, True))
        dv._dispatch_mute_all([])
        assert clients["Kitchen"].calls == []


class TestReadoutFromTheStream:
    @pytest.fixture
    def rig(self):
        r = Rig()
        r.io.observe_volume = dv.observe_master_volume
        r.io.observe_volume_tracked = dv.observe_master_volume_if_tracked
        yield r
        r.close()

    def test_the_readout_follows_master_volume(self, rig):
        rig.add("Kitchen", peer("Kitchen", playing=True, master_volume=30, seq=1))
        rig.fold()
        assert dv.shown_volume("autostream on Kitchen") == 30
        rig.set("Kitchen", peer("Kitchen", playing=True, master_volume=44, seq=2))
        rig.fold()
        assert dv.shown_volume("autostream on Kitchen") == 44

    def test_a_fold_that_changes_nothing_leaves_the_pending_steps(self, rig):
        rig.add("Kitchen", peer("Kitchen", playing=True, master_volume=30, seq=1))
        rig.fold()
        dv.enqueue_delta(5)
        while not dv._queue.empty():
            dv._queue.get_nowait()
        rig.set("Kitchen", peer("Kitchen", playing=True, master_volume=30, seq=2, heard_at=2.0))
        rig.fold()
        assert dv.shown_volume("autostream on Kitchen") == 35

    def test_a_move_of_the_volume_replaces_the_pending_steps(self, rig):
        rig.add("Kitchen", peer("Kitchen", playing=True, master_volume=30, seq=1))
        rig.fold()
        dv.enqueue_delta(5)
        while not dv._queue.empty():
            dv._queue.get_nowait()
        rig.set("Kitchen", peer("Kitchen", playing=True, master_volume=33, seq=2))
        rig.fold()
        assert dv.shown_volume("autostream on Kitchen") == 33

    def test_a_new_reporting_appliance_re_keys_the_readout(self, rig):
        rig.add("Kitchen", peer("Kitchen", playing=True, master_volume=30, seq=1))
        rig.fold()
        rig.set("Kitchen", peer("Kitchen", playing=False, master_volume=30, seq=2))
        rig.add("Lounge", peer("Lounge", playing=True, master_volume=55, seq=1))
        rig.fold()
        assert dv.shown_volume("autostream on Lounge") == 55

    def test_nothing_playing_clears_the_readout(self, rig):
        rig.add("Kitchen", peer("Kitchen", playing=True, master_volume=30, seq=1))
        rig.fold()
        rig.set("Kitchen", peer("Kitchen", playing=False, master_volume=30, seq=2))
        rig.fold()
        assert dv.shown_volume("autostream on Kitchen") is None
