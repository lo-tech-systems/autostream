"""Tests for a change the appliance pushes reaching the HD page's state: the
real core, the real volume stores and the real state builder together, with
only the network stood in for.

Covers: a mute made behind the dial's back showing in the state after the
tick a hint brings, a hint for an appliance the dial does not know leaving the
state alone, and the core thread alone (no manual poll) carrying a hint to
the state.
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))
from test_dial_hd_mute import (  # noqa: F401 (the fixture is autouse)
    LOUNGE, Appliances, Rig, _clean_stores,
)


class TestAPushedChangeReachesTheState:
    def test_a_mute_made_elsewhere_shows_after_the_tick_the_hint_brings(self):
        rig = Rig(Appliances(LOUNGE))
        rig.poll()
        assert rig.volume()["muted"] is False

        rig.appliances.muted["Lounge"] = True
        steps = rig.steps
        rig.core.notify_state_changed(LOUNGE.appliance_id, ("mute",))
        rig.core._drain_state_pushes()
        rig.poll()

        assert rig.volume() == {"appliance_id": LOUNGE.appliance_id, "level": 40, "muted": True}
        assert rig.steps > steps

    def test_a_hint_for_an_appliance_the_dial_does_not_know_changes_nothing(self):
        rig = Rig(Appliances(LOUNGE))
        rig.poll()
        before = rig.volume()
        rig.core.notify_state_changed("f" * 20, ("volume", "eq"))
        rig.core._drain_state_pushes()
        rig.poll()
        assert rig.volume() == before

    def test_the_core_thread_alone_carries_a_hint_to_the_state(self):
        rig = Rig(Appliances(LOUNGE))
        rig.core.set_poll_interval(60)
        rig.core.start()
        try:
            deadline = time.monotonic() + 3.0
            while rig.core.snapshot().ticks < 1 and time.monotonic() < deadline:
                time.sleep(0.005)
            assert rig.volume()["muted"] is False

            rig.appliances.muted["Lounge"] = True
            rig.core.notify_state_changed(LOUNGE.appliance_id, ("mute",))
            deadline = time.monotonic() + 3.0
            while rig.volume()["muted"] is not True and time.monotonic() < deadline:
                time.sleep(0.005)
        finally:
            rig.core.stop()
        assert rig.volume()["muted"] is True
