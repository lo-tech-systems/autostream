"""Tests for the mute flag and the volume level the dial shows for the
appliance it reports from: the real core and the real volume worker's stores
together, with only the appliances' clients stood in for.

Covers: the state following the appliance the dial reports from after a fold
(its level and its mute flag, whatever the readout last named), a mute toggle
reaching the state at once under either scope without waiting for a fold, the
worker telling the core when it has written the mute store, and a view being
left unpainted by it.
"""
from __future__ import annotations

import dataclasses
import os
import queue
import sys
import time
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))

import pytest

import dial_volume as dv
from autostream_peer_registry import Sighting
from dial_core import DialCore
from dial_core_state import ActionResult
from dial_hd_events import ChangeHub
from dial_mdns import PlayingTarget
from dial_pool_support import ok, peer, refused

DIAL_ID = "dial-1"


def _target(name, ip, playing_since) -> PlayingTarget:
    return PlayingTarget(
        ip=ip, port=80, name=name, dial_api=True, audio_status=True, dial_status=True,
        service_name=name, playing_since=playing_since,
        appliance_id=(name.encode().hex() + "0" * 20)[:20], auth="unknown",
    )


LOUNGE = _target("Lounge", "192.0.2.11", 100.0)
KITCHEN = _target("Kitchen", "192.0.2.12", 200.0)


def _status(volume, muted) -> dict:
    return {
        "playing": True, "master_volume": volume, "selected_output_count": 1,
        "track_id": None, "status_error": None, "appliance_id": None, "muted": muted,
    }


class Appliances:
    """The appliances as the clients see them: each one's volume and mute
    flag, held and answering mute and volume requests. Also the pool and the
    registry the core reads them from."""

    def __init__(self, *targets, playing=None) -> None:
        self.all_targets = list(targets)
        self.targets = list(targets if playing is None else playing)   # the ones playing now
        self.volume = {t.service_name: 40 for t in targets}
        self.muted = {t.service_name: False for t in targets}
        self.by_ip = {t.ip: t.service_name for t in targets}
        self.refuse_mute = False

    def sightings(self) -> dict:
        return {t.appliance_id: Sighting(id=t.appliance_id, hostname=t.name, ip=t.ip, port=t.port,
                                         version="0.8.0", control=True, proto=4,
                                         service_name=t.service_name)
                for t in self.all_targets}

    def clients(self) -> dict:
        return {t.appliance_id: self.client_for(t.appliance_id) for t in self.all_targets}

    def get(self, appliance_id):
        return self.client_for(appliance_id)

    def subscribe(self, fn) -> int:
        return 1

    def client_for(self, appliance_id):
        """The client the volume worker sends through for one appliance."""
        name = next((t.service_name for t in self.all_targets if t.appliance_id == appliance_id), None)
        return _Client(self, name) if name is not None else None


class _Client:
    """One appliance's client: its held mute flag, and the volume and mute
    intents answered from the appliance's state."""

    def __init__(self, appliances: "Appliances", name: str) -> None:
        self.appliances = appliances
        self.name = name

    def snapshot(self):
        a = self.appliances
        target = next(t for t in a.all_targets if t.service_name == self.name)
        snap = peer(self.name, playing=any(t.service_name == self.name for t in a.targets),
                    master_volume=a.volume[self.name], muted_all=a.muted[self.name],
                    heard_at=time.monotonic())
        return dataclasses.replace(snap, peer_id=target.appliance_id)

    def submit(self, intent, args, *, extra_body=None, read_s=None, backoff=True):
        a = self.appliances
        if intent == "mute.set":
            if a.refuse_mute:
                return refused("no_active_outputs")
            a.muted[self.name] = args["action"] == "mute"
            return ok(result={"ok": True, "muted": a.muted[self.name]})
        a.volume[self.name] = max(0, min(100, a.volume[self.name] + args["delta"]))
        return ok(result={"ok": True, "volume": a.volume[self.name], "muted": a.muted[self.name]})


def _drain_queue() -> None:
    while True:
        try:
            dv._queue.get_nowait()
        except queue.Empty:
            return


@pytest.fixture(autouse=True)
def _clean_stores():
    """The worker's stores and its queue are process-wide."""
    def reset():
        dv.observe_mute_state(None, None)
        dv.observe_master_volume(None, None)
        _drain_queue()
    reset()
    yield
    reset()


class Rig:
    """A core reading *appliances* through their clients and the worker's
    callbacks wired to it as the service wires them."""

    def __init__(self, appliances: Appliances, mute_scope="current") -> None:
        self.appliances = appliances
        self.scope = mute_scope
        self.core = DialCore(DIAL_ID)
        self.core.attach_pool(appliances, appliances)
        self.core.set_mute_scope(lambda: self.scope)
        self.hub = ChangeHub(self.core)
        self.steps = 0
        self.core.subscribe(self._count)

    def _count(self) -> None:
        self.steps += 1

    def poll(self) -> None:
        self.core.fold_once()

    def volume(self) -> dict:
        """The level and the shown mute flag of the appliance reported from."""
        snapshot = self.core.snapshot()
        playing = snapshot.now_playing
        service = playing.service_name if playing is not None else None
        level = dv.shown_volume(service) if service else None
        return {"appliance_id": snapshot.focus.reporting_id, "level": level,
                "muted": dv.shown_muted(service) if service else None}

    def mute_targets(self) -> list:
        if self.scope == "all":
            return list(self.appliances.targets)
        name = self.core.snapshot().now_playing.service_name
        return [t for t in self.appliances.targets if t.service_name == name]

    def run_worker(self) -> None:
        """Send what is queued, as the worker thread would."""
        with patch.object(dv, "_on_mute_changed", self.core.mute_changed, create=True), \
                patch.object(dv, "_on_readout_changed", self.core.readout_changed), \
                patch.object(dv, "_client_for", self.appliances.client_for):
            while True:
                try:
                    first = dv._queue.get_nowait()
                except queue.Empty:
                    return
                for event in dv._coalesce(first):
                    if event[0] == "mute_all":
                        dv._dispatch_mute_all(self.mute_targets())
                    elif event[0] == "mute":
                        dv._fan_out_mute(self.mute_targets(), event[1])
                    else:
                        dv._fan_out(self.mute_targets(), event[1])


# ---------------------------------------------------------------------------
# The state follows the appliance the dial reports from
# ---------------------------------------------------------------------------

class TestStateFollowsTheReportingAppliance:
    def test_a_poll_brings_the_level_and_the_mute_flag_into_the_state(self):
        rig = Rig(Appliances(LOUNGE))
        rig.appliances.volume["Lounge"] = 31
        rig.poll()
        assert rig.volume() == {"appliance_id": LOUNGE.appliance_id, "level": 31, "muted": False}
        # Changed somewhere else (its own web page, another dial): the next
        # poll's reading is what the state says, with no volume reply needed.
        rig.appliances.volume["Lounge"] = 55
        rig.appliances.muted["Lounge"] = True
        rig.poll()
        assert rig.volume() == {"appliance_id": LOUNGE.appliance_id, "level": 55, "muted": True}

    def test_a_readout_left_naming_another_appliance_does_not_stick(self):
        """The readout was last published for one appliance; the dial now
        follows another. Its level and mute flag are the followed one's."""
        appliances = Appliances(LOUNGE, KITCHEN, playing=[KITCHEN])
        appliances.volume.update(Lounge=31, Kitchen=15)
        rig = Rig(appliances)
        rig.poll()
        rig.core.volume_step(1)
        rig.run_worker()
        assert dv.shown_volume("Kitchen") == 16

        appliances.muted["Lounge"] = True
        appliances.targets[:] = [LOUNGE]
        rig.poll()
        assert dv.shown_volume("Lounge") == 31
        assert rig.volume() == {"appliance_id": LOUNGE.appliance_id, "level": 31, "muted": True}

    def test_nothing_playing_clears_the_readout(self):
        rig = Rig(Appliances(LOUNGE))
        rig.poll()
        assert rig.volume()["level"] == 40
        rig.appliances.targets.clear()
        rig.poll()
        assert rig.volume() == {"appliance_id": None, "level": None, "muted": None}


# ---------------------------------------------------------------------------
# A mute toggle reaches the state without waiting for a poll
# ---------------------------------------------------------------------------

class TestMuteToggleReachesTheState:
    @pytest.mark.parametrize("scope", ["current", "all"])
    def test_muting_then_unmuting_shows_in_the_state_each_time(self, scope):
        rig = Rig(Appliances(LOUNGE), mute_scope=scope)
        rig.poll()
        assert rig.volume()["muted"] is False

        assert rig.core.mute_toggle(LOUNGE.appliance_id) == ActionResult(True)
        rig.run_worker()
        assert rig.appliances.muted["Lounge"] is True
        assert rig.volume()["muted"] is True
        # Later polls agree with it.
        rig.poll()
        rig.poll()
        assert rig.volume()["muted"] is True

        assert rig.core.mute_toggle(LOUNGE.appliance_id) == ActionResult(True)
        rig.run_worker()
        assert rig.appliances.muted["Lounge"] is False
        assert rig.volume()["muted"] is False
        rig.poll()
        assert rig.volume()["muted"] is False

    @pytest.mark.parametrize("scope", ["current", "all"])
    def test_a_toggle_is_shown_whatever_the_readout_last_named(self, scope):
        """The readout was last published for an appliance that has since
        stopped; mute is then pressed on the one now followed."""
        appliances = Appliances(LOUNGE, KITCHEN, playing=[KITCHEN])
        rig = Rig(appliances, mute_scope=scope)
        rig.poll()
        rig.core.volume_step(1)
        rig.run_worker()
        appliances.targets[:] = [LOUNGE]
        rig.poll()

        rig.core.mute_toggle(LOUNGE.appliance_id)
        rig.run_worker()
        assert appliances.muted["Lounge"] is True
        assert rig.volume() == {"appliance_id": LOUNGE.appliance_id, "level": 40, "muted": True}
        rig.poll()
        assert rig.volume()["muted"] is True

    def test_a_fleet_toggle_publishes_when_the_worker_has_decided(self):
        """Under the broadcast scope nothing is known at the press: the
        change is published from the worker, once for its echo and once for
        each appliance's answer."""
        rig = Rig(Appliances(LOUNGE, KITCHEN), mute_scope="all")
        rig.poll()
        seq = rig.core.snapshot().seq
        rig.core.mute_toggle()
        assert rig.core.snapshot().seq == seq
        rig.run_worker()
        assert rig.core.snapshot().seq == seq + 3
        assert rig.volume()["muted"] is True

    def test_a_single_toggle_publishes_its_echo_at_the_press(self):
        rig = Rig(Appliances(LOUNGE), mute_scope="current")
        rig.poll()
        seq = rig.core.snapshot().seq
        rig.core.mute_toggle()
        assert rig.core.snapshot().seq == seq + 1
        assert rig.volume()["muted"] is True
        rig.run_worker()
        assert rig.core.snapshot().seq == seq + 2
        assert rig.volume()["muted"] is True

    def test_the_hub_steps_for_a_fleet_toggle(self):
        rig = Rig(Appliances(LOUNGE), mute_scope="all")
        rig.poll()
        rig.hub.start()
        try:
            seen = rig.hub.wait_for_change(0, 2.0)
            rig.core.mute_toggle()
            rig.run_worker()
            assert rig.hub.wait_for_change(seen, 2.0) is not None
            assert rig.volume()["muted"] is True
        finally:
            rig.hub.stop()

    def test_a_refused_mute_is_put_right_by_the_next_poll(self):
        rig = Rig(Appliances(LOUNGE), mute_scope="all")
        rig.poll()
        rig.appliances.refuse_mute = True
        rig.core.mute_toggle()
        with patch("dial_volume.logging"):
            rig.run_worker()
        assert rig.appliances.muted["Lounge"] is False
        rig.poll()
        assert rig.volume()["muted"] is False

    def test_a_mute_change_queues_no_repaint_for_a_view(self):
        rig = Rig(Appliances(LOUNGE), mute_scope="current")
        rig.poll()
        rig.core.take_effects()
        rig.core.mute_toggle()
        rig.run_worker()
        assert rig.core.take_effects() == []


# ---------------------------------------------------------------------------
# The worker says when it has written the mute store
# ---------------------------------------------------------------------------

class TestWorkerReportsMuteChanges:
    def _run(self, call, appliances, callback):
        with patch.object(dv, "_on_mute_changed", callback), \
                patch.object(dv, "_client_for", appliances.client_for):
            call()

    def test_a_fleet_toggle_reports_its_echo_before_any_answer(self):
        appliances = Appliances(LOUNGE)
        seen = []
        self._run(
            lambda: dv._dispatch_mute_all([LOUNGE]), appliances,
            lambda: seen.append((dv.shown_muted("Lounge"), appliances.muted["Lounge"])),
        )
        assert seen == [(True, False), (True, True)]

    def test_an_answered_mute_reports_after_the_store_is_written(self):
        appliances = Appliances(LOUNGE)
        seen = []
        self._run(
            lambda: dv._send_one_mute(LOUNGE, True), appliances,
            lambda: seen.append((dv.shown_muted("Lounge"), "Lounge" in dv._mute_inflight)),
        )
        assert seen == [(True, False)]

    def test_a_failed_mute_still_reports(self):
        seen = []

        class Down:
            def submit(self, *args, **kwargs):
                return refused("unreachable")

        with patch.object(dv, "_on_mute_changed", lambda: seen.append(1)), \
                patch.object(dv, "_client_for", lambda appliance_id: Down()), patch("dial_volume.logging"):
            dv._send_one_mute(LOUNGE, True)
        assert seen == [1]

    def test_a_listener_that_raises_does_not_stop_the_send(self):
        appliances = Appliances(LOUNGE)

        def boom():
            raise RuntimeError("listener")

        self._run(lambda: dv._dispatch_mute_all([LOUNGE]), appliances, boom)
        assert appliances.muted["Lounge"] is True
        assert dv.shown_muted("Lounge") is True

    def test_no_listener_is_fine(self):
        appliances = Appliances(LOUNGE)
        self._run(lambda: dv._dispatch_mute_all([LOUNGE]), appliances, None)
        assert dv.shown_muted("Lounge") is True

    def test_the_worker_is_started_with_the_listener(self):
        started = []
        with patch("dial_volume.threading.Thread") as thread, \
                patch.object(dv, "_on_mute_changed", None), patch.object(dv, "_on_readout_changed", None), \
                patch.object(dv, "_targets_fn", None), \
                patch.object(dv, "_led_ref", None), patch.object(dv, "_mute_targets_fn", None):
            dv.start_volume_worker(
                lambda: [], None, on_mute_changed=lambda: started.append(1))
            dv._notify_mute_changed()
            assert thread.called
        assert started == [1]
