"""Tests for the mute flag and the volume level the HD page is sent: the real
core, the real volume worker's stores and the real state builder together,
with only the network stood in for.

Covers: the state following the appliance the dial reports from after a poll
(its level and its mute flag, whatever the readout last named), a mute toggle
reaching the state at once under either scope without waiting for a poll, the
worker telling the core when it has written the mute store, and a view being
left unpainted by it.
"""
from __future__ import annotations

import json
import os
import queue
import sys
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))

import pytest

import dial_auth
import dial_hd_server as hds
import dial_repeat_store as drs
import dial_volume as dv
from dial_core import DialCore, PollIO
from dial_core_state import ActionResult
from dial_hd_events import ChangeHub
from dial_mdns import PlayingTarget

DIAL_ID = "dial-1"


def _target(name, ip, playing_since) -> PlayingTarget:
    return PlayingTarget(
        ip=ip, port=80, name=name, dial_api=True, audio_status=True, dial_status=True,
        service_name=name, playing_since=playing_since,
        appliance_id=(name.encode().hex() + "0" * 20)[:20], auth="unknown", dial_proto_version=3,
    )


LOUNGE = _target("Lounge", "192.0.2.11", 100.0)
KITCHEN = _target("Kitchen", "192.0.2.12", 200.0)


def _status(volume, muted) -> dict:
    return {
        "playing": True, "master_volume": volume, "selected_output_count": 1,
        "track_id": None, "status_error": None, "appliance_id": None, "muted": muted,
    }


class _Reply:
    """A urlopen() result carrying a JSON body."""

    def __init__(self, body: dict) -> None:
        self._raw = json.dumps(body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def read(self, *args) -> bytes:
        return self._raw


class Appliances:
    """The appliances as the network stand-ins see them: each one's volume
    and mute flag, answering status, mute and volume requests."""

    def __init__(self, *targets, playing=None) -> None:
        self.targets = list(targets if playing is None else playing)   # the ones playing now
        self.volume = {t.service_name: 40 for t in targets}
        self.muted = {t.service_name: False for t in targets}
        self.by_ip = {t.ip: t.service_name for t in targets}
        self.refuse_mute = False

    def fetch_status(self, target, *args, **kwargs) -> dict:
        name = target.service_name
        return _status(self.volume[name], self.muted[name])

    def urlopen(self, request, timeout=None):
        name = self.by_ip[request.full_url.split("/")[2].split(":")[0]]
        body = json.loads(request.data)
        if request.full_url.endswith("/api/dial/mute"):
            if self.refuse_mute:
                return _Reply({"ok": False, "error": "no_active_outputs"})
            self.muted[name] = body["action"] == "mute"
            return _Reply({"ok": True, "muted": self.muted[name]})
        self.volume[name] = max(0, min(100, self.volume[name] + body["delta"]))
        return _Reply({"ok": True, "volume": self.volume[name], "muted": self.muted[name]})


def _drain_queue() -> None:
    while True:
        try:
            dv._queue.get_nowait()
        except queue.Empty:
            return


@pytest.fixture(autouse=True)
def _clean_stores():
    """The worker's stores, its queue and the auth and repeat stores are
    process-wide."""
    def reset():
        dv.observe_mute_state(None, None)
        dv.observe_master_volume(None, None)
        _drain_queue()
        dial_auth.auth_map.reset()
        drs.repeat_store.prune(set())
    reset()
    yield
    reset()


class Rig:
    """A polling core over *appliances*, the worker's callbacks wired to it
    as the service wires them, and the HD server's state builder."""

    def __init__(self, appliances: Appliances, mute_scope="current") -> None:
        self.appliances = appliances
        self.scope = mute_scope
        self.core = DialCore(DIAL_ID, lambda: list(appliances.targets), lambda: [])
        self.core.set_io(PollIO(fetch_status=appliances.fetch_status, enrich=lambda *a, **k: None))
        self.core.set_mute_scope(lambda: self.scope)
        self.hub = ChangeHub(self.core)
        self.server = hds.HdServer(SimpleNamespace(), self.core, hub=self.hub, port=0)
        self.hub.set_builder(self.server.build_state_bytes)
        self.steps = 0
        self.core.subscribe(self._count)
        self.core.set_polling(True)

    def _count(self) -> None:
        self.steps += 1

    def poll(self) -> None:
        self.core.poll_once()

    def volume(self) -> dict:
        return json.loads(self.server.build_state_bytes(1))["volume"]

    def mute_targets(self) -> list:
        if self.scope == "all":
            return list(self.appliances.targets)
        name = self.core.snapshot().now_playing.service_name
        return [t for t in self.appliances.targets if t.service_name == name]

    def run_worker(self) -> None:
        """Send what is queued, as the worker thread would."""
        with patch.object(dv, "_on_mute_changed", self.core.mute_changed, create=True), \
                patch.object(dv, "_on_readout_changed", self.core.readout_changed), \
                patch.object(dv, "fetch_target_status", self.appliances.fetch_status), \
                patch("dial_volume.urllib.request.urlopen", self.appliances.urlopen):
            while True:
                try:
                    first = dv._queue.get_nowait()
                except queue.Empty:
                    return
                for event in dv._coalesce(first):
                    if event[0] == "mute_all":
                        dv._dispatch_mute_all(self.mute_targets(), DIAL_ID)
                    elif event[0] == "mute":
                        dv._fan_out_mute(self.mute_targets(), DIAL_ID, event[1])
                    else:
                        dv._fan_out(self.mute_targets(), DIAL_ID, event[1])


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
        assert rig.core.snapshot().volume_readout == ("Kitchen", 16)

        appliances.muted["Lounge"] = True
        appliances.targets[:] = [LOUNGE]
        rig.poll()
        assert rig.core.snapshot().volume_readout == ("Lounge", 31)
        assert rig.volume() == {"appliance_id": LOUNGE.appliance_id, "level": 31, "muted": True}

    def test_nothing_playing_clears_the_readout(self):
        rig = Rig(Appliances(LOUNGE))
        rig.poll()
        assert rig.volume()["level"] == 40
        rig.appliances.targets.clear()
        rig.poll()
        assert rig.core.snapshot().volume_readout == (None, None)
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
            assert json.loads(rig.hub.state()[1])["volume"]["muted"] is True
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
                patch.object(dv, "fetch_target_status", appliances.fetch_status), \
                patch("dial_volume.urllib.request.urlopen", appliances.urlopen):
            call()

    def test_a_fleet_toggle_reports_its_echo_before_any_answer(self):
        appliances = Appliances(LOUNGE)
        seen = []
        self._run(
            lambda: dv._dispatch_mute_all([LOUNGE], DIAL_ID), appliances,
            lambda: seen.append((dv.shown_muted("Lounge"), appliances.muted["Lounge"])),
        )
        assert seen == [(True, False), (True, True)]

    def test_an_answered_mute_reports_after_the_store_is_written(self):
        appliances = Appliances(LOUNGE)
        seen = []
        self._run(
            lambda: dv._send_one_mute(LOUNGE, DIAL_ID, True), appliances,
            lambda: seen.append((dv.shown_muted("Lounge"), "Lounge" in dv._mute_inflight)),
        )
        assert seen == [(True, False)]

    def test_a_failed_mute_still_reports(self):
        appliances = Appliances(LOUNGE)
        seen = []

        def fail(*args, **kwargs):
            raise OSError("no route")

        with patch.object(dv, "_on_mute_changed", lambda: seen.append(1)), \
                patch("dial_volume.urllib.request.urlopen", fail), patch("dial_volume.logging"):
            dv._send_one_mute(LOUNGE, DIAL_ID, True)
        assert seen == [1]

    def test_a_listener_that_raises_does_not_stop_the_send(self):
        appliances = Appliances(LOUNGE)

        def boom():
            raise RuntimeError("listener")

        self._run(lambda: dv._dispatch_mute_all([LOUNGE], DIAL_ID), appliances, boom)
        assert appliances.muted["Lounge"] is True
        assert dv.shown_muted("Lounge") is True

    def test_no_listener_is_fine(self):
        appliances = Appliances(LOUNGE)
        self._run(lambda: dv._dispatch_mute_all([LOUNGE], DIAL_ID), appliances, None)
        assert dv.shown_muted("Lounge") is True

    def test_the_worker_is_started_with_the_listener(self):
        started = []
        with patch("dial_volume.threading.Thread") as thread, \
                patch.object(dv, "_on_mute_changed", None), patch.object(dv, "_on_readout_changed", None), \
                patch.object(dv, "_cfg", None), patch.object(dv, "_targets_fn", None), \
                patch.object(dv, "_led_ref", None), patch.object(dv, "_mute_targets_fn", None):
            dv.start_volume_worker(
                SimpleNamespace(uuid=DIAL_ID), lambda: [], None, on_mute_changed=lambda: started.append(1))
            dv._notify_mute_changed()
            assert thread.called
        assert started == [1]
