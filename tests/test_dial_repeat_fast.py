"""tests/test_dial_repeat_fast.py -- the replay position, which the change
stream does not carry: read again every few seconds while an appliance
replays, whatever screen is shown or none, and once after an accepted seek or
stop."""
from __future__ import annotations

import pytest

from dial_pool_support import Rig, aid, peer, replay_block, unit
from dial_pool_support import ok as reply_ok, refused as reply_refused

from dial_core import REPEAT_FETCH_S

K = aid("Kitchen")


def attach_screen(core, kind, stack):
    """Attach a screen to *core*: none, the small screen's view, or the HD
    page's change hub."""
    if kind == "spi":
        pytest.importorskip("PIL.Image", reason="Pillow not installed")
        from dial_config import DialDisplayConfig
        from dial_display import DialDisplay
        from dial_test_support import TEST_LOGO_PATH, FakeBackend
        display = DialDisplay(
            config=DialDisplayConfig(fitted=True), dial_id="dial-uuid",
            logo_path=TEST_LOGO_PATH, backend_factory=FakeBackend, core=core,
        )
        stack.append(display.stop)
        display.start()
    elif kind == "hd":
        from dial_hd_events import ChangeHub
        hub = ChangeHub(core)
        stack.append(hub.stop)
        hub.start()


@pytest.fixture
def rig():
    r = Rig()
    stack = []
    r.stack = stack
    yield r
    for stop in reversed(stack):
        stop()
    r.close()


def fetches(client):
    return [c for c in client.fetches() if c[1] == ["repeat"]]


@pytest.mark.parametrize("screen", ["none", "spi", "hd"])
def test_a_replaying_appliance_is_read_every_few_seconds(rig, screen):
    attach_screen(rig.core, screen, rig.stack)
    client = rig.add("Kitchen", peer("Kitchen", playing=True, source="replay", repeat=replay_block("replaying")))
    rig.fold()
    rig.core._fetch_replay_positions(rig.t)
    assert fetches(client) == []
    rig.core._fetch_replay_positions(rig.t + REPEAT_FETCH_S)
    assert rig.wait(lambda: len(fetches(client)) == 1)
    rig.core._fetch_replay_positions(rig.t + REPEAT_FETCH_S + 1)
    rig.core._fetch_replay_positions(rig.t + 2 * REPEAT_FETCH_S)
    assert rig.wait(lambda: len(fetches(client)) == 2)
    assert fetches(client)[0] == ("fetch", ["repeat"], True)


def test_the_fetch_interval_is_five_seconds():
    assert REPEAT_FETCH_S == 5.0


def test_nothing_is_read_while_idle(rig):
    client = rig.add("Kitchen", peer("Kitchen", repeat=replay_block("hold")))
    rig.fold()
    for step in range(4):
        rig.core._fetch_replay_positions(rig.t + step * REPEAT_FETCH_S)
    rig.wait(lambda: False, timeout=0.1)
    assert fetches(client) == []


def test_the_reads_stop_when_the_replay_does(rig):
    client = rig.add("Kitchen", peer("Kitchen", playing=True, source="replay", repeat=replay_block("replaying")))
    rig.fold()
    rig.core._fetch_replay_positions(rig.t)
    rig.set("Kitchen", peer("Kitchen", repeat=replay_block("hold"), seq=2))
    rig.fold()
    rig.core._fetch_replay_positions(rig.t + REPEAT_FETCH_S)
    rig.wait(lambda: False, timeout=0.1)
    assert fetches(client) == []


@pytest.mark.parametrize("method", ["restart_replay", "stop_replay"])
def test_one_read_after_an_accepted_seek_or_stop(rig, method):
    client = rig.add("Kitchen", peer("Kitchen", playing=True, source="replay",
                                     repeat=replay_block("replaying"), units=[unit()]))
    rig.fold()
    client.reply = reply_ok()
    getattr(rig.core, method)(K)
    assert rig.wait(lambda: len(fetches(client)) == 1)
    rig.wait(lambda: False, timeout=0.1)
    assert len(fetches(client)) == 1


def test_one_read_after_an_accepted_intent_from_the_page(rig):
    client = rig.add("Kitchen", peer("Kitchen", playing=True, source="replay", repeat=replay_block("replaying")))
    rig.fold()
    rig.core.submit_intent(K, "repeat.seek", {"position": 0})
    assert rig.wait(lambda: len(fetches(client)) == 1)


def test_no_read_after_a_refused_seek(rig):
    client = rig.add("Kitchen", peer("Kitchen", playing=True, source="replay", repeat=replay_block("replaying")))
    rig.fold()
    client.reply = reply_refused("rate_limited", 1.0)
    rig.core.restart_replay(K)
    assert rig.wait(lambda: rig.core.snapshot().transport.state == "rejected")
    rig.wait(lambda: False, timeout=0.1)
    assert fetches(client) == []


def test_no_read_after_arming(rig):
    client = rig.add("Kitchen", peer("Kitchen", repeat=replay_block("recording")))
    rig.fold()
    rig.core.set_repeat_armed(K, False)
    assert rig.wait(lambda: rig.core.snapshot().transport.state == "accepted")
    rig.wait(lambda: False, timeout=0.1)
    assert fetches(client) == []


def test_an_unreachable_appliance_has_no_repeat_record(rig):
    rig.add("Kitchen", peer("Kitchen", repeat=replay_block("replaying"), reachable=False))
    assert rig.fold().appliance(K).repeat is None
