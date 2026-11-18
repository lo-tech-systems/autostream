"""Tests for autostream_peer_client: PeerClient, PeerPool and roster_view, against
the fake peer server."""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from types import MappingProxyType

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import autostream_peer_client as pc  # noqa: E402
from autostream_peer_registry import Sighting  # noqa: E402
from autostream_protocol import PROTOCOL  # noqa: E402
from fake_peer_server import BOOT, FakePeer  # noqa: E402

PEER = "b2c3d4e5f6a1b2c3d4e5"
LOCAL = "a1b2c3d4e5f6a1b2c3d4"
IP = "127.0.0.1"


def wait_for(predicate, timeout: float = 3.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


@pytest.fixture
def rig(monkeypatch):
    monkeypatch.setattr(pc, "BACKOFF_STEPS", (0.05, 0.1))
    peers, clients = [], []

    class Rig:
        def peer(self, **kw):
            p = FakePeer(**kw).start()
            peers.append(p)
            return p

        def client(self, peer=None, *, start=True, **kw):
            c = pc.PeerClient(PEER, client_id=f"peer:{LOCAL}", **kw)
            clients.append(c)
            if peer is not None:
                c.set_sighting(IP, peer.port, PROTOCOL)
            if start:
                c.start()
            return c

    yield Rig()
    for c in clients:
        c.stop()
    for p in peers:
        p.stop()
    for c in clients:
        if c._thread is not None:
            c._thread.join(2.0)


def ready(c):
    return wait_for(lambda: c.snapshot().reachable and c.snapshot().boot is not None)


def state_gets(peer):
    return [p for m, p in peer.requests if p.startswith("/api/v1/state")]


class TestFollowing:
    def test_hello_full_read_then_stream_with_since(self, rig):
        peer = rig.peer()
        c = rig.client(peer)
        assert ready(c) and wait_for(lambda: peer.connects)
        assert state_gets(peer)[:2] == ["/api/v1/state?parts=", "/api/v1/state"]
        got = peer.connects[0]
        assert got["since"] == f"{BOOT}-{peer.version}"
        assert got["query"]["client"] == f"peer:{LOCAL}"
        assert got["query"]["protocol"] == str(PROTOCOL)
        snap = c.snapshot()
        assert snap.boot == BOOT and snap.version == peer.version
        assert snap.protocol == PROTOCOL and snap.protocol_ok and snap.configured is True
        assert snap.heard_at > 0

    def test_a_quiet_peer_gives_every_part_within_three_seconds(self, rig):
        peer = rig.peer(parts={"outputs": {"units": []}, "settings": {"generation": 1}})
        c = rig.client(peer)
        assert wait_for(lambda: set(c.snapshot().parts) == set(peer.parts), 3.0)
        assert c.snapshot().part_versions["outputs"] == peer.part_versions["outputs"]

    def test_change_events_merge_whole_parts(self, rig):
        peer = rig.peer(parts={"outputs": {"units": [1]}})
        c = rig.client(peer)
        assert ready(c) and wait_for(lambda: peer.open_streams() == 1)
        peer.push({"session": {"active": True}})
        assert wait_for(lambda: c.snapshot().parts["session"] == {"active": True})
        snap = c.snapshot()
        assert snap.version == peer.version
        assert snap.part_versions["session"] == peer.version
        assert snap.part_versions["outputs"] == 10          # untouched
        assert snap.parts["outputs"] == {"units": [1]}

    def test_appliance_part_change_updates_configured(self, rig):
        peer = rig.peer()
        c = rig.client(peer)
        assert ready(c) and wait_for(lambda: peer.open_streams() == 1)
        peer.push({"appliance": {"configured": False}})
        assert wait_for(lambda: c.snapshot().configured is False)

    def test_an_event_at_or_below_the_held_version_is_ignored(self, rig):
        peer = rig.peer()
        c = rig.client(peer)
        assert ready(c) and wait_for(lambda: peer.open_streams() == 1)
        old = peer._change_bytes({"session": {"active": True}}, False).replace(
            b"-%d\n" % peer.version, b"-5\n").replace(b'"version": %d' % peer.version, b'"version": 5')
        peer.write(old)
        time.sleep(0.2)
        assert c.snapshot().parts["session"] == {"active": False}

    def test_access_events(self, rig):
        peer = rig.peer()
        c = rig.client(peer)
        assert wait_for(lambda: c.snapshot().access == "playback")
        peer.send_access("none", "control_disabled")
        assert wait_for(lambda: c.snapshot().access == "none")
        assert c.snapshot().access_reason == "control_disabled"

    def test_resume_after_a_lifetime_end_with_no_miss_and_no_fetch(self, rig):
        peer = rig.peer()
        peer.lifetime_s = 0.3
        c = rig.client(peer)
        assert ready(c)
        reachable = []
        c.subscribe(lambda cl: reachable.append(cl.snapshot().reachable))
        assert wait_for(lambda: len(peer.connects) >= 3)
        assert len(state_gets(peer)) == 2           # the hello and the one full read
        assert all(x["since"] == f"{BOOT}-{peer.version}" for x in peer.connects)
        assert False not in reachable

    def test_a_boot_change_gives_a_full_read(self, rig):
        peer = rig.peer()
        c = rig.client(peer)
        assert ready(c) and wait_for(lambda: peer.open_streams() == 1)
        peer.parts["session"] = {"active": True}
        peer.new_boot()
        assert wait_for(lambda: c.snapshot().boot == "fedcba9876543210")
        snap = c.snapshot()
        assert snap.version == 3 and snap.parts["session"] == {"active": True}
        assert snap.reachable

    def test_a_stall_marks_unreachable_and_keeps_the_parts(self, rig, monkeypatch):
        monkeypatch.setattr(pc, "STREAM_READ_S", 0.3)
        peer = rig.peer()
        peer.stall_events = True
        c = rig.client(peer)
        seen = []
        c.subscribe(lambda cl: seen.append(cl.snapshot()))
        assert wait_for(lambda: any(not s.reachable and s.boot for s in seen), 4.0)
        down = next(s for s in seen if not s.reachable and s.boot)
        assert "appliance" in down.parts

    def test_backoff_steps(self):
        assert [pc.backoff_delay(n) for n in range(1, 9)] == [1, 2, 4, 8, 15, 30, 30, 30]

    def test_an_unreachable_peer_retries_and_stays_down(self, rig):
        c = rig.client(None)
        c.set_sighting(IP, 1, PROTOCOL)
        c.start()
        assert wait_for(lambda: c.snapshot().heard_at == 0.0)
        time.sleep(0.3)
        assert not c.snapshot().reachable

    def test_too_many_refusals_keep_reachable(self, rig):
        peer = rig.peer()
        peer.refusal = (503, {"ok": False, "error": "too_many_from_address"})
        c = rig.client(peer)
        assert wait_for(lambda: len(peer.connects) >= 3)
        assert c.snapshot().reachable

    def test_an_unknown_refusal_is_a_miss(self, rig):
        peer = rig.peer()
        peer.refusal = (404, {"ok": False, "error": "not_found"})
        c = rig.client(peer)
        seen = []
        c.subscribe(lambda cl: seen.append(cl.snapshot().reachable))
        assert wait_for(lambda: False in seen)


class TestProtocol:
    def test_txt_mismatch_opens_nothing_and_a_new_sighting_wakes_it(self, rig, monkeypatch):
        monkeypatch.setattr(pc, "PROTOCOL_RECHECK_S", 0.1)
        peer = rig.peer()
        c = rig.client(start=False)
        c.set_sighting(IP, peer.port, PROTOCOL + 1)
        c.start()
        assert wait_for(lambda: not c.snapshot().protocol_ok)
        time.sleep(0.35)
        assert peer.requests == []
        c.set_sighting(IP, peer.port, PROTOCOL)
        assert ready(c) and c.snapshot().protocol_ok

    def test_hello_mismatch_opens_no_stream_and_looks_again(self, rig, monkeypatch):
        monkeypatch.setattr(pc, "PROTOCOL_RECHECK_S", 0.1)
        peer = rig.peer(protocol=99)
        c = rig.client(peer)
        assert wait_for(lambda: len(state_gets(peer)) >= 3)
        assert peer.connects == [] and "/api/v1/state" not in state_gets(peer)
        snap = c.snapshot()
        assert not snap.protocol_ok and snap.protocol == 99
        peer.protocol = PROTOCOL
        assert wait_for(lambda: c.snapshot().protocol_ok and c.snapshot().reachable, 3.0)

    def test_stream_protocol_mismatch_body(self, rig, monkeypatch):
        monkeypatch.setattr(pc, "PROTOCOL_RECHECK_S", 5.0)
        peer = rig.peer()
        peer.refusal = (200, {"ok": False, "error": "protocol_mismatch"})
        c = rig.client(peer)
        assert wait_for(lambda: not c.snapshot().protocol_ok)

    def test_submit_is_refused_locally_on_mismatch(self, rig, monkeypatch):
        monkeypatch.setattr(pc, "PROTOCOL_RECHECK_S", 5.0)
        peer = rig.peer(protocol=99)
        c = rig.client(peer)
        assert wait_for(lambda: not c.snapshot().protocol_ok)
        assert c.submit("volume.set", {}).error == "protocol_mismatch"
        assert peer.posts == []


class TestAddressAndStop:
    def test_an_address_change_moves_the_stream_without_a_miss(self, rig):
        a, b = rig.peer(), rig.peer()
        c = rig.client(a)
        # The first event has been read, so the move finds a stream that has been heard.
        assert ready(c) and wait_for(lambda: a.open_streams() == 1
                                     and c.snapshot().access == pc.ACCESS_PLAYBACK)
        seen = []
        c.subscribe(lambda cl: seen.append(cl.snapshot().reachable))
        c.set_sighting(IP, b.port, PROTOCOL)
        assert wait_for(lambda: b.open_streams() == 1)
        assert b.connects[0]["since"] == f"{BOOT}-{a.version}"
        assert state_gets(b) == []
        # The old stream is no longer read: an event on it is never merged, and
        # the next one on the new stream is.
        a.push({"session": {"active": True}})
        b.push({"session": {"active": False, "from": "b"}})
        assert wait_for(lambda: c.snapshot().parts["session"] == {"active": False, "from": "b"})
        assert False not in seen and c.snapshot().reachable

    def test_same_sighting_again_changes_nothing(self, rig):
        peer = rig.peer()
        c = rig.client(peer)
        assert ready(c) and wait_for(lambda: peer.open_streams() == 1)
        c.set_sighting(IP, peer.port, PROTOCOL)
        time.sleep(0.2)
        assert len(peer.connects) == 1

    def _stops_fast(self, c):
        t0 = time.monotonic()
        c.stop()
        c._thread.join(2.0)
        assert not c._thread.is_alive()
        assert time.monotonic() - t0 < 0.5

    def test_stop_from_backoff(self, rig, monkeypatch):
        monkeypatch.setattr(pc, "BACKOFF_STEPS", (30.0,))
        c = rig.client(None)
        c.set_sighting(IP, 1, PROTOCOL)
        c.start()
        time.sleep(0.3)
        self._stops_fast(c)

    def test_stop_from_hello(self, rig):
        peer = rig.peer()
        peer.stall_state = True
        c = rig.client(peer)
        assert wait_for(lambda: peer.requests)
        self._stops_fast(c)

    def test_stop_from_the_stream(self, rig):
        peer = rig.peer()
        c = rig.client(peer)
        assert ready(c) and wait_for(lambda: peer.open_streams() == 1)
        self._stops_fast(c)

    def test_stop_from_a_callback_returns_and_the_thread_ends(self, rig):
        peer = rig.peer()
        c = rig.client(peer)
        c.subscribe(lambda cl: cl.stop())
        assert wait_for(lambda: c._stop.is_set())
        c._thread.join(2.0)
        assert not c._thread.is_alive()


class TestSnapshot:
    def test_read_only_views(self, rig):
        peer = rig.peer()
        c = rig.client(peer)
        assert ready(c)
        snap = c.snapshot()
        assert isinstance(snap.parts, MappingProxyType)
        with pytest.raises(TypeError):
            snap.parts["x"] = 1
        with pytest.raises(TypeError):
            snap.part_versions["x"] = 1

    def test_wait_for_change(self, rig):
        peer = rig.peer()
        c = rig.client(peer)
        assert ready(c) and wait_for(lambda: peer.open_streams() == 1)
        seq = c.snapshot().seq
        assert c.wait_for_change(seq, 0.1) is None
        threading.Timer(0.1, peer.push, args=({"session": {"active": True}},)).start()
        got = c.wait_for_change(seq, 2.0)
        assert got is not None and got.seq != seq

    def test_a_heartbeat_moves_heard_at_only(self, rig):
        peer = rig.peer()
        c = rig.client(peer)
        assert ready(c) and wait_for(lambda: peer.open_streams() == 1)
        time.sleep(0.05)
        before = c.snapshot()
        peer.heartbeat()
        assert wait_for(lambda: c.snapshot().heard_at > before.heard_at)
        assert c.snapshot().seq == before.seq

    def test_unsubscribe(self, rig):
        peer = rig.peer()
        c = rig.client(peer, start=False)
        calls = []
        handle = c.subscribe(lambda cl: calls.append(1))
        c.unsubscribe(handle)
        c.start()
        assert ready(c)
        assert calls == []


def dead_client(rig, **kw):
    c = rig.client(None, start=False, **kw)
    c.set_sighting(IP, 1, PROTOCOL)
    return c


class TestSubmit:
    def test_body_shape_and_extra_body_precedence(self, rig):
        peer = rig.peer()
        c = rig.client(peer, extra_body={"pin_capable": False, "keep": 1})
        reply = c.submit("volume.set", {"level": 5}, extra_body={"pin_capable": True,
                                                                "client": "x", "args": 9})
        assert reply.ok and reply.boot == BOOT and reply.version == peer.version
        name, body = peer.posts[0]
        assert name == "volume.set"
        assert body == {"pin_capable": True, "keep": 1, "client": f"peer:{LOCAL}",
                        "protocol": PROTOCOL, "args": {"level": 5}}

    def test_local_refusal_on_no_access(self, rig):
        peer = rig.peer()
        peer.access = {"role": "none", "reason": "control_disabled"}
        c = rig.client(peer)
        assert wait_for(lambda: c.snapshot().access == "none")
        reply = c.submit("mute.set", {})
        assert not reply.ok and reply.error == "control_disabled"
        assert peer.posts == []

    def test_peer_refusal_passes_through_with_retry_after(self, rig):
        peer = rig.peer()
        peer.intent_reply = lambda n, b: (200, {"ok": False, "error": "rate_limited",
                                                "retry_after_s": 2.5, "result": {"x": 1}})
        c = rig.client(peer)
        reply = c.submit("volume.step", {})
        assert (reply.ok, reply.error, reply.retry_after_s, dict(reply.result)) == (
            False, "rate_limited", 2.5, {"x": 1})
        assert c.submit("volume.step", {}).error == "rate_limited"     # not in backoff

    def test_http_error_status_with_a_body_is_a_reply(self, rig):
        peer = rig.peer()
        peer.intent_reply = lambda n, b: (400, {"ok": False, "error": "invalid_client"})
        c = rig.client(peer)
        assert c.submit("volume.step", {}).error == "invalid_client"

    def test_transport_failure_advances_the_write_backoff(self, rig):
        c = dead_client(rig)
        first = c.submit("volume.step", {})
        assert first.error == "unreachable"
        second = c.submit("volume.step", {})
        assert second.error == "backoff" and 0 < second.retry_after_s <= 0.05

    def test_per_call_read_timeout(self, rig):
        peer = rig.peer()
        peer.intent_delay_s = 0.6
        c = rig.client(peer)
        t0 = time.monotonic()
        assert c.submit("volume.step", {}, read_s=0.1).error == "timeout"
        assert time.monotonic() - t0 < 0.5

    def test_backoff_false_is_not_refused_and_does_not_advance(self, rig, monkeypatch):
        monkeypatch.setattr(pc, "BACKOFF_STEPS", (0.2, 0.4, 5.0, 6.0))
        peer = rig.peer()
        peer.intent_delay_s = 0.4
        c = rig.client(peer)
        assert c.submit("a", {}, read_s=0.05).error == "timeout"        # failure 1: 0.2 s
        assert c.submit("a", {}).error == "backoff"
        time.sleep(0.25)
        assert c.submit("b", {}, read_s=0.05, backoff=False).error == "timeout"
        assert c.submit("b", {}, read_s=0.05, backoff=False).error == "timeout"
        second = c.submit("c", {}, read_s=0.05)                          # failure 2: 0.4 s
        assert second.error == "timeout"
        left = c.submit("c", {}).retry_after_s
        assert left is not None and left <= 0.4

    def test_a_call_made_while_in_backoff_is_sent_when_backoff_false(self, rig, monkeypatch):
        monkeypatch.setattr(pc, "BACKOFF_STEPS", (5.0,))
        peer = rig.peer()
        c = rig.client(None, start=False)
        c.set_sighting(IP, 1, PROTOCOL)
        assert c.submit("a", {}).error == "unreachable"
        assert c.submit("a", {}).error == "backoff"
        c.set_sighting(IP, peer.port, PROTOCOL)
        reply = c.submit("a", {}, backoff=False)
        assert reply.ok and len(peer.posts) == 1
        assert c.submit("a", {}).ok            # the reply cleared the backoff

    def test_concurrent_with_the_stream(self, rig):
        peer = rig.peer()
        peer.intent_delay_s = 0.5
        c = rig.client(peer)
        assert ready(c) and wait_for(lambda: peer.open_streams() == 1)
        out = []
        t = threading.Thread(target=lambda: out.append(c.submit("volume.step", {})))
        t.start()
        assert wait_for(lambda: peer.posts)
        peer.push({"session": {"active": True}})
        assert wait_for(lambda: c.snapshot().parts["session"] == {"active": True}, 0.4)
        t.join(2.0)
        assert out and out[0].ok

    def test_never_raises(self, rig):
        peer = rig.peer()
        c = rig.client(peer)
        reply = c.submit("volume.step", {"x": object()})
        assert not reply.ok and reply.error == "bad_reply"
        assert pc.PeerClient(PEER, client_id=f"peer:{LOCAL}").submit("a", {}).error == "unreachable"


class TestFetch:
    def test_a_400_passes_through(self, rig):
        peer = rig.peer()
        c = rig.client(peer)
        status, body = c.fetch(["nope"])
        assert status == 400 and body["error"] == "unknown_part"

    def test_none_only_on_transport_failure(self, rig):
        assert dead_client(rig).fetch(["appliance"]) is None
        peer = rig.peer()
        status, body = rig.client(peer, start=False).fetch(["appliance"])
        assert status == 200 and body["parts"] == {"appliance": {"configured": True}}

    def test_merge_replaces_parts_wakes_and_signals_without_moving_versions(self, rig):
        peer = rig.peer(parts={"repeat": {"pos": 1}})
        c = rig.client(peer)
        assert ready(c) and wait_for(lambda: peer.open_streams() == 1)
        before = c.snapshot()
        calls = []
        c.subscribe(lambda cl: calls.append(1))
        peer.parts["repeat"] = {"pos": 2}                 # a fast field: no version moves
        woke = []
        t = threading.Thread(target=lambda: woke.append(c.wait_for_change(before.seq, 2.0)))
        t.start()
        status, _ = c.fetch(["repeat"], merge=True)
        t.join(2.0)
        after = c.snapshot()
        assert status == 200 and after.parts["repeat"] == {"pos": 2}
        assert after.seq > before.seq and woke[0] is not None and calls
        assert (after.version, dict(after.part_versions)) == (before.version, dict(before.part_versions))

    def test_default_leaves_the_snapshot_alone(self, rig):
        peer = rig.peer(parts={"repeat": {"pos": 1}})
        c = rig.client(peer)
        assert ready(c)
        before = c.snapshot()
        peer.parts["repeat"] = {"pos": 2}
        c.fetch(["repeat"])
        assert c.snapshot().parts["repeat"] == {"pos": 1}
        assert c.snapshot().seq == before.seq

    def test_a_reply_from_another_boot_is_returned_but_not_merged(self, rig):
        peer = rig.peer(parts={"repeat": {"pos": 1}})
        c = rig.client(peer)
        assert ready(c) and wait_for(lambda: peer.open_streams() == 1)
        before = c.snapshot()
        peer.parts["repeat"] = {"pos": 2}
        peer.new_boot(drop=False)
        status, body = c.fetch(["repeat"], merge=True)
        assert status == 200 and body["parts"]["repeat"] == {"pos": 2}
        assert c.snapshot().parts["repeat"] == {"pos": 1} and c.snapshot().seq == before.seq


# -- the pool and the roster --------------------------------------------------------

class FakeRegistry:
    def __init__(self):
        self.subs = {}
        self.current = {}

    def subscribe(self, fn):
        self.subs[len(self.subs) + 1] = fn
        return len(self.subs)

    def unsubscribe(self, handle):
        self.subs.pop(handle, None)

    def sightings(self):
        return dict(self.current)

    def fire(self, kind, peer_id, sighting):
        for fn in list(self.subs.values()):
            fn(kind, peer_id, sighting)


def sighting(port, host="Peer", peer_id=PEER, **kw):
    fields = dict(id=peer_id, hostname=host, ip=IP, port=port, version="0.8.0",
                  control=True, proto=PROTOCOL, service_name="s")
    fields.update(kw)
    return Sighting(**fields)


class TestPool:
    def test_add_change_remove(self, rig):
        a, b = rig.peer(), rig.peer()
        reg = FakeRegistry()
        reg.current[PEER] = sighting(a.port)
        made = []

        def make(peer_id):
            c = pc.PeerClient(peer_id, client_id="dial:" + "0" * 20)
            made.append(c)
            return c
        pool = pc.PeerPool(reg, make)
        signals = []
        pool.subscribe(lambda: signals.append(1))
        pool.start()
        try:
            client = pool.get(PEER)
            assert client is made[0] and ready(client)
            assert wait_for(lambda: a.connects and signals)
            reg.fire("change", PEER, sighting(b.port))
            assert wait_for(lambda: b.connects)
            other = "c3d4e5f6a1b2c3d4e5f6"
            reg.fire("add", other, sighting(a.port, peer_id=other))
            assert set(pool.clients()) == {PEER, other}
            reg.fire("remove", PEER, None)
            assert pool.get(PEER) is None and set(pool.clients()) == {other}
            assert wait_for(lambda: client._stop.is_set())
        finally:
            pool.stop()
        assert pool.clients() == {}
        assert reg.subs == {}

    def test_an_add_for_a_known_id_only_moves_it(self, rig):
        a = rig.peer()
        reg = FakeRegistry()
        pool = pc.PeerPool(reg, lambda i: pc.PeerClient(i, client_id="dial:" + "0" * 20))
        pool.start()
        try:
            reg.fire("add", PEER, sighting(a.port))
            first = pool.get(PEER)
            reg.fire("add", PEER, sighting(a.port + 1))
            assert pool.get(PEER) is first
        finally:
            pool.stop()


class TestRosterView:
    def snap(self, **kw):
        fields = dict(peer_id=PEER, boot=BOOT, version=1, part_versions={}, parts={},
                      reachable=True, access="playback", access_reason=None, protocol=PROTOCOL,
                      protocol_ok=True, configured=True, heard_at=1.0, seq=1)
        fields.update(kw)
        return pc.PeerSnapshot(**fields)

    def test_order_playing_and_unknown(self):
        sightings = {
            "i1": sighting(1, host="beta", peer_id="i1"),
            "i2": sighting(1, host="Alpha", peer_id="i2", control=False),
            "i3": sighting(1, host="gamma", peer_id="i3"),
        }
        snaps = {"i1": self.snap(parts={"session": {"active": True}}),
                 "i2": self.snap(reachable=False, protocol_ok=False, access="none", configured=False)}
        view = pc.roster_view(sightings, snaps)
        assert [e.hostname for e in view] == ["Alpha", "beta", "gamma"]
        alpha, beta, gamma = view
        assert (alpha.control, alpha.reachable, alpha.protocol_ok, alpha.access,
                alpha.configured, alpha.playing) == (False, False, False, "none", False, False)
        assert beta.playing is True and beta.reachable
        assert (gamma.reachable, gamma.access, gamma.configured, gamma.playing) == (
            False, "unknown", None, False)
        assert gamma.protocol_ok is True
