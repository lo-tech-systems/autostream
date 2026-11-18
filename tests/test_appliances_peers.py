"""Tests for autostream_appliances: the peers part, which speakers other
appliances are playing, and resolving an appliance id. The appliances are
FakePeer servers behind a fake registry."""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import autostream_appliances as appliances  # noqa: E402
import autostream_output_intents  # noqa: E402,F401 -- binds the output rows
import autostream_peer_client as pc  # noqa: E402
import autostream_pin_pairing as pairing  # noqa: E402
import autostream_runtime as runtime  # noqa: E402
import autostream_state as state  # noqa: E402
from autostream_intents import Intent, submit  # noqa: E402
from autostream_peer_registry import Sighting  # noqa: E402
from autostream_players import ActionResult  # noqa: E402
from autostream_protocol import PROTOCOL  # noqa: E402
from autostream_state import Origin  # noqa: E402
from autostream_state.outputs import get_authority  # noqa: E402
from fake_peer_server import FakePeer  # noqa: E402
from fake_store import FakeStore  # noqa: E402
from output_fakes import row  # noqa: E402
import webui.browser.home_model as home_model  # noqa: E402

LOCAL = "a1b2c3d4e5f6a1b2c3d4"
IP = "127.0.0.1"


def peer_id(n: int) -> str:
    return f"{n:x}" * 20


def wait_for(predicate, timeout: float = 10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def playing_parts(*speakers, active=True, availability="ok"):
    units = [{"id": str(i), "name": name, "selected": True, "availability": availability,
              "reported": {"id": str(i)}} for i, name in enumerate(speakers, 1)]
    return {"session": {"active": active}, "outputs": {"units": units},
            "appliance": {"configured": True}}


class FakeRegistry:
    def __init__(self, local_id=None, **_kw):
        self.subs = {}
        self.current = {}
        self.conflicting = frozenset()
        self.started = False
        self.grace = None

    def start(self, shutdown_event=None):
        self.started = True

    def stop(self):
        self.started = False

    def subscribe(self, fn):
        self.subs[len(self.subs) + 1] = fn
        return len(self.subs)

    def unsubscribe(self, handle):
        self.subs.pop(handle, None)

    def sightings(self):
        return dict(self.current)

    def conflicts(self):
        return self.conflicting

    def set_grace_period(self, seconds):
        self.grace = seconds

    def add(self, peer_id, host, port, **kw):
        fields = dict(id=peer_id, hostname=host, ip=IP, port=port, version="0.8.0",
                      control=True, proto=PROTOCOL, service_name=host)
        fields.update(kw)
        self.current[peer_id] = Sighting(**fields)
        for fn in list(self.subs.values()):
            fn("add", peer_id, self.current[peer_id])


@pytest.fixture
def rig(monkeypatch):
    monkeypatch.setattr(pc, "BACKOFF_STEPS", (0.05, 0.1))
    monkeypatch.setattr("autostream_rpi.get_appliance_id", lambda: LOCAL)
    made = []

    def factory(**kw):
        reg = FakeRegistry(**kw)
        made.append(reg)
        return reg

    monkeypatch.setattr(appliances, "PeerRegistry", factory)
    peers = []

    class Rig:
        registry = None

        def start(self):
            appliances.start(runtime.Lifecycle(threading.Event()), None)
            self.registry = made[-1]

        def peer(self, n, host, parts=None, **sighting):
            p = FakePeer(parts=parts if parts is not None else playing_parts(active=False)).start()
            peers.append(p)
            self.registry.add(peer_id(n), host, p.port, **sighting)
            return p

        def part(self):
            return state.store().snapshot().peers.entries

        def usage(self):
            return dict(appliances._usage)

        def requests(self):
            return sum(len(p.requests) for p in peers)

    yield Rig()
    appliances.stop()
    for p in peers:
        p.stop()
    appliances._usage.clear()
    get_authority().set_remote_usage({})


@pytest.fixture
def player(monkeypatch):
    import autostream_player_service as ps
    rec = SimpleNamespace(calls=[])

    def update_output(base_url, out_id, **kwargs):
        rec.calls.append((out_id, kwargs))
        return ActionResult(ok=True)

    monkeypatch.setattr(ps, "update_output", update_output)
    return rec


class TestPeersPart:
    def test_two_peers_are_listed_by_hostname_with_control_off_included(self, rig):
        rig.start()
        rig.peer(2, "Zulu")
        rig.peer(3, "alpha", control=False)
        assert wait_for(lambda: [e.hostname for e in rig.part()] == ["alpha", "Zulu"]
                        and all(e.reachable for e in rig.part()))
        alpha, zulu = rig.part()
        assert alpha.control is False and zulu.control is True
        assert zulu.id == peer_id(2) and zulu.configured is True and zulu.playing is False

    def test_a_conflicting_id_is_not_listed(self, rig):
        rig.start()
        rig.registry.conflicting = frozenset({peer_id(4)})
        rig.peer(2, "Good")
        assert wait_for(lambda: [e.hostname for e in rig.part()] == ["Good"])
        assert appliances.resolve(peer_id(4)).kind == "conflict"

    def test_an_unconfigured_peer_is_listed_not_set_up_and_resolves_unconfigured(self, rig):
        rig.start()
        rig.peer(2, "Fresh", parts={"appliance": {"configured": False}, "session": {"active": False}})
        assert wait_for(lambda: rig.part() and rig.part()[0].configured is False)
        assert appliances.resolve(peer_id(2)).kind == "unconfigured"

    def test_a_peer_that_goes_away_leaves_the_part(self, rig):
        rig.start()
        rig.peer(2, "Gone")
        assert wait_for(lambda: len(rig.part()) == 1)
        del rig.registry.current[peer_id(2)]
        for fn in list(rig.registry.subs.values()):
            fn("remove", peer_id(2), None)
        assert wait_for(lambda: rig.part() == ())

    def test_several_changes_before_the_worker_runs_give_one_pass(self, rig, monkeypatch):
        calls = []
        release = threading.Event()
        real = appliances._pass

        def counted():
            calls.append(1)
            if len(calls) == 1:
                release.wait(3)
            real()

        monkeypatch.setattr(appliances, "_pass", counted)
        rig.start()
        assert wait_for(lambda: len(calls) == 1)
        for _ in range(5):
            appliances._wake.set()
        release.set()
        assert wait_for(lambda: len(calls) == 2)
        time.sleep(0.2)
        assert len(calls) == 2


class TestOccupancy:
    def test_a_playing_peers_selected_reported_speaker_is_in_use(self, rig):
        rig.start()
        rig.peer(2, "Hall", parts=playing_parts("Kitchen"))
        assert wait_for(lambda: rig.usage() == {"kitchen": (peer_id(2), "Hall")})
        assert rig.part()[0].playing is True

    def test_nothing_is_in_use_while_the_peer_has_no_session(self, rig):
        rig.start()
        p = rig.peer(2, "Hall", parts=playing_parts("Kitchen", active=False))
        assert wait_for(lambda: rig.part() and rig.part()[0].reachable)
        assert rig.usage() == {}
        p.push(playing_parts("Kitchen"))
        assert wait_for(lambda: "kitchen" in rig.usage())
        p.push({"session": {"active": False}})
        assert wait_for(lambda: rig.usage() == {})

    def test_a_speaker_waiting_for_a_pin_or_not_reported_is_not_in_use(self, rig):
        rig.start()
        parts = playing_parts("Kitchen", availability="password")
        parts["outputs"]["units"].append({"id": "9", "name": "Lounge", "selected": True,
                                          "availability": "ok", "reported": None})
        parts["outputs"]["units"].append({"id": "8", "name": "Study", "selected": False,
                                          "availability": "ok", "reported": {"id": "8"}})
        rig.peer(2, "Hall", parts=parts)
        assert wait_for(lambda: rig.part() and rig.part()[0].playing)
        assert rig.usage() == {}

    def test_names_match_without_regard_to_case_and_the_first_hostname_wins(self, rig):
        rig.start()
        rig.peer(2, "Zulu", parts=playing_parts("KITCHEN"))
        rig.peer(3, "Alpha", parts=playing_parts("kitchen"))
        assert wait_for(lambda: rig.usage() == {"kitchen": (peer_id(3), "Alpha")})

    def test_it_clears_when_the_peer_goes_away(self, rig):
        rig.start()
        p = rig.peer(2, "Hall", parts=playing_parts("Kitchen"))
        assert wait_for(lambda: "kitchen" in rig.usage())
        p.stop()
        assert wait_for(lambda: rig.usage() == {})

    def test_a_stalled_stream_holds_the_speaker_until_the_client_misses(self, rig, monkeypatch):
        monkeypatch.setattr(pc, "STREAM_READ_S", 0.8)
        rig.start()
        p = rig.peer(2, "Hall", parts=playing_parts("Kitchen"))
        assert wait_for(lambda: "kitchen" in rig.usage())
        p.stall_events = True
        p.close_streams()
        time.sleep(0.3)
        assert "kitchen" in rig.usage()
        assert wait_for(lambda: rig.usage() == {})

    def test_a_peer_whose_stream_just_ends_keeps_its_speakers(self, rig):
        rig.start()
        p = rig.peer(2, "Hall", parts=playing_parts("Kitchen"))
        assert wait_for(lambda: "kitchen" in rig.usage())
        p.close_streams()
        time.sleep(0.3)
        assert "kitchen" in rig.usage()

    def test_the_part_carries_the_owner_and_never_for_a_speaker_selected_here(self, rig):
        FakeStore().outputs([row("1", "Kitchen"), row("2", "Lounge", selected=True)])
        rig.start()
        rig.peer(2, "Hall", parts=playing_parts("Kitchen", "Lounge"))
        assert wait_for(lambda: state.store().snapshot().outputs.unit("1").in_use_by == "Hall")
        kitchen, lounge = state.store().snapshot().outputs.unit("1"), state.store().snapshot().outputs.unit("2")
        assert (kitchen.in_use_id, kitchen.in_use_by) == (peer_id(2), "Hall")
        assert (lounge.in_use_id, lounge.in_use_by) == ("", "")

    def test_the_appearance_is_logged_at_debug_only(self, rig, caplog):
        with caplog.at_level("DEBUG"):
            rig.start()
            rig.peer(2, "Hall", parts=playing_parts("Kitchen"))
            assert wait_for(lambda: "kitchen" in rig.usage())
        lines = [r for r in caplog.records if "now in use by" in r.getMessage()]
        assert lines and all(r.levelname == "DEBUG" for r in lines)


class TestIntentChecks:
    def occupied(self, rig, *speakers):
        rig.start()
        rig.peer(2, "Hall", parts=playing_parts(*speakers))
        assert wait_for(lambda: state.store().snapshot().outputs.unit("1") is not None
                        and state.store().snapshot().outputs.unit("1").in_use_by == "Hall")

    def test_outputs_set_refuses_a_speaker_the_part_shows_in_use_and_makes_no_request(self, rig, player):
        FakeStore().outputs([row("1", "Kitchen")])
        self.occupied(rig, "Kitchen")
        before = rig.requests()
        r = home_model.submit_output_change({"id": "1", "selected": True},
                                            requester="webui", pin_requester=pairing.REQUESTER_WEBUI)
        assert r == {"ok": False, "id": "1", "error": "output_in_use", "owner": "Hall"}
        assert player.calls == [] and rig.requests() == before

    def test_select_default_refuses_the_member_in_use_and_starts_the_rest(self, rig, player):
        FakeStore().outputs([row("1", "Kitchen"), row("2", "Hall")])
        get_authority().set_default_members([("", "Kitchen", 40), ("", "Hall", 40)], 40)
        self.occupied(rig, "Kitchen")

        def pick(name):
            return submit(Intent("outputs.select_default", {"key": "name:" + name, "volume": 40},
                                 Origin.SESSION, "coordinator"))

        refused = pick("Kitchen")
        assert (refused.ok, refused.error, refused.result) == (False, "in_use", {"owner": "Hall"})
        assert pick("Hall").ok is True
        assert [c[0] for c in player.calls] == ["2"]


class TestResolve:
    def test_each_kind(self, rig, monkeypatch):
        assert appliances.resolve("nope").kind == "invalid"
        assert appliances.resolve(LOCAL).kind == "bound"
        assert appliances.resolve(peer_id(5)).kind == "unknown"      # not started
        rig.start()
        assert appliances.resolve(peer_id(5)).kind == "unknown"
        rig.peer(2, "Hall")
        rig.peer(3, "Quiet", control=False)
        assert wait_for(lambda: len(rig.part()) == 2 and all(e.reachable for e in rig.part()))
        res = appliances.resolve(peer_id(2))
        assert res.kind == "remote" and res.client is not None and res.sighting.hostname == "Hall"
        off = appliances.resolve(peer_id(3))
        assert off.kind == "control_off" and off.client is None and off.sighting.hostname == "Quiet"


class TestStart:
    def test_nothing_starts_without_an_appliance_id(self, monkeypatch):
        monkeypatch.setattr("autostream_rpi.get_appliance_id", lambda: None)
        made = []
        monkeypatch.setattr(appliances, "PeerRegistry", lambda **kw: made.append(kw))
        appliances.start(runtime.Lifecycle(threading.Event()), None)
        assert made == [] and appliances._thread is None

    def test_a_grace_period_set_before_start_is_applied_and_one_after_is_passed_on(self, rig):
        appliances.set_grace_period(300)
        rig.start()
        assert rig.registry.grace == 300 and rig.registry.started
        appliances.set_grace_period(60)
        assert rig.registry.grace == 60

    def test_start_is_idempotent_and_stop_ends_the_worker(self, rig):
        rig.start()
        first = appliances._thread
        appliances.start(runtime.Lifecycle(threading.Event()), None)
        assert appliances._thread is first
        appliances.stop()
        assert not first.is_alive() and appliances._thread is None
        appliances.stop()
