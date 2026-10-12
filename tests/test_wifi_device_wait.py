"""The Wi-Fi watcher's fast reconnect after the adapter was not available.

When a package upgrade restarts the Wi-Fi authentication service, NetworkManager
keeps the device but reports it ``unavailable`` for a few seconds, and a
``connection up`` in that window fails with "No suitable device found". The
watcher then used to wait out its whole reconnect back-off. These tests drive
whole passes and the sleeps between them on a fake clock and a scripted radio
state, and compare the escalation state with and without the feature.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from dataclasses import asdict
from unittest.mock import MagicMock, patch

import pytest

from _wifi_fixtures import _Clock, _run_monitor_once, watcher  # noqa: F401

T0 = 100000.0
FAST_FIELDS = {"device_wait_until", "device_wait_episode"}


class _Scenario:
    """A fake clock, a scripted radio, and the calls the watcher makes."""

    def __init__(self, watcher, *, ready_at=None, radio=True, online=True, boot_age=3600.0):
        self.w = watcher
        self.clock = _Clock(T0)
        self.ready_at = ready_at          # None: the device never becomes available
        self.connects: list[float] = []
        self.radio_checks: list[float] = []
        self.reboots: list[float] = []
        self.sleeps: list[float] = []
        self.escalations = 0
        self.use_radio = radio
        watcher.STATE.boot_time = T0 - boot_age
        watcher.STATE.last_active_path_seen = T0 - boot_age
        watcher.STATE.been_online_this_boot = online

    def _radio(self) -> str:
        self.radio_checks.append(self.clock.t)
        if self.ready_at is not None and self.clock.t >= self.ready_at:
            return "ready"
        return "unavailable"

    def _sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.clock.advance(seconds)

    def pass_(self) -> None:
        """One full monitor pass at the current time, offline with Wi-Fi configured."""
        w = self.w
        dead = MagicMock(return_value=False)
        with patch.object(w.LOOP_CTX, "wifi_radio_state", self._radio if self.use_radio else None), \
             patch.object(w.LOOP_CTX, "request_network_down_reboot",
                          side_effect=lambda now, reason: self.reboots.append(self.clock.t)):
            before = len(self.connects)
            connect = _run_monitor_once(w, now=self.clock.t, wifi_cfg=True, dead_recovery=dead)
        if connect.call_count:
            self.connects.extend([self.clock.t] * connect.call_count)
        assert len(self.connects) >= before
        self.escalations += dead.call_count

    def sleep(self) -> None:
        """The sleep between two passes, as the real loop does it."""
        w = self.w

        def _connect():
            self.connects.append(self.clock.t)

        with patch("time.monotonic", self.clock), patch("time.sleep", self._sleep), \
             patch.object(w.LOOP_CTX, "wifi_radio_state", self._radio if self.use_radio else None), \
             patch.object(w.LOOP_CTX, "connect_to_configured_wifi", side_effect=_connect):
            w._sleep_monitor_interval()

    def run(self, seconds: float) -> None:
        end = self.clock.t + seconds
        while self.clock.t < end:
            self.pass_()
            self.sleep()

    def state(self) -> dict:
        s = asdict(self.w.STATE)
        for k in FAST_FIELDS:
            s.pop(k)
        s.pop("boot_time"), s.pop("last_active_path_seen")
        return s


def test_a_device_that_comes_back_within_the_fast_phase_is_reconnected_at_the_next_check(watcher):
    """The link drops, the first attempt finds the device unavailable, and the
    device becomes available five seconds later."""
    sc = _Scenario(watcher, ready_at=T0 + 5)
    sc.pass_()
    assert sc.connects == [T0]                      # the prompt attempt on entry
    assert watcher.STATE.device_wait_until == T0 + watcher.wifi_policy.DEVICE_WAIT_MAX
    sc.sleep()
    assert sc.connects == [T0, T0 + 6]              # retried at the first check after it came back
    assert watcher.STATE.device_wait_until is None  # the fast phase is over
    assert sum(sc.sleeps) == watcher.NETWORK_MONITOR_INTERVAL   # the pass cadence is unchanged
    assert sc.sleeps == [3, 3, 9]                   # two short waits, then the rest of the interval


def test_the_fast_reconnect_leaves_the_back_off_and_the_escalation_unchanged(watcher):
    fast = _Scenario(watcher, ready_at=T0 + 5)
    fast.run(60)
    fast_state, fast_reboots, fast_esc = fast.state(), fast.reboots, fast.escalations
    fast_conn = (watcher.STATE.conn_down_start, watcher.STATE.last_reconnect_attempt)
    assert watcher.RECOVERY_STATE == watcher.wifi_recovery.RecoveryState()

    # The same drop with the feature switched off: identical state, apart from
    # the one extra reconnect and the fast-phase bookkeeping.
    watcher.STATE.__init__(mode=watcher.wifi_policy.Mode.BOOT)
    off = _Scenario(watcher, ready_at=T0 + 5, radio=False)
    off.run(60)
    assert fast_state == off.state()
    assert fast_conn == (watcher.STATE.conn_down_start, watcher.STATE.last_reconnect_attempt)
    assert (fast_reboots, fast_esc) == (off.reboots, off.escalations)
    assert len(fast.connects) == len(off.connects) + 1


def test_a_real_connection_failure_with_the_device_available_keeps_the_ordinary_back_off(watcher):
    sc = _Scenario(watcher, ready_at=T0 - 1)        # the device is available throughout
    sc.pass_()
    assert sc.connects == [T0]
    assert watcher.STATE.device_wait_until is None  # no fast phase
    sc.sleep()
    assert sc.sleeps == [watcher.NETWORK_MONITOR_INTERVAL]
    assert sc.connects == [T0]
    # No further attempt until the gateway has been down for GW_DOWN_RECONNECT_AFTER.
    after = watcher.GW_DOWN_RECONNECT_AFTER
    sc.clock.t = T0 + after - 1
    sc.pass_()
    assert sc.connects == [T0]
    sc.clock.t = T0 + after + 1
    sc.pass_()
    assert sc.connects == [T0, T0 + after + 1]
    # ... and then at most one per RECONNECT_ATTEMPT_INTERVAL.
    sc.clock.t = T0 + after + 1 + watcher.RECONNECT_ATTEMPT_INTERVAL - 1
    sc.pass_()
    assert len(sc.connects) == 2
    sc.clock.t += 2
    sc.pass_()
    assert len(sc.connects) == 3


def test_the_fast_phase_ends_at_its_bound_and_the_ordinary_schedule_resumes(watcher):
    sc = _Scenario(watcher, ready_at=None)          # the device never becomes available
    sc.pass_()
    assert watcher.STATE.device_wait_until == T0 + watcher.wifi_policy.DEVICE_WAIT_MAX
    while sc.clock.t < T0 + 120:
        sc.sleep()
        sc.pass_()
    assert watcher.STATE.device_wait_until is None
    # Only the entry attempt: the polling never reconnected, as the device was never ready.
    assert sc.connects == [T0]
    # The checks were bounded by the phase: one every few seconds for at most a minute.
    polls = [t for t in sc.radio_checks if T0 < t <= T0 + 120]
    in_phase = [t for t in polls if t <= T0 + watcher.wifi_policy.DEVICE_WAIT_MAX]
    assert len(in_phase) <= watcher.wifi_policy.DEVICE_WAIT_MAX // watcher.wifi_policy.DEVICE_WAIT_POLL_INTERVAL + 3
    assert [t for t in polls if t > T0 + watcher.wifi_policy.DEVICE_WAIT_MAX + 15] == []
    # After the bound the ordinary single sleep per pass is back.
    sc.sleeps.clear()
    sc.sleep()
    assert sc.sleeps == [watcher.NETWORK_MONITOR_INTERVAL]


def test_each_offline_episode_gets_one_fast_phase(watcher):
    sc = _Scenario(watcher, ready_at=None)
    sc.run(watcher.GW_DOWN_RECONNECT_AFTER + 60)
    # The scheduled attempt at the back-off also found the device unavailable, but
    # the episode had its fast phase already, so none was started again.
    assert watcher.STATE.device_wait_until is None
    assert watcher.STATE.device_wait_episode == T0


def test_nothing_changes_while_the_device_has_not_been_online_this_boot(watcher):
    """The boot window: the same passes with and without the feature are identical."""
    on = _Scenario(watcher, ready_at=T0 + 5, online=False, boot_age=30.0)
    on.run(120)
    on_state, on_connects, on_checks = on.state(), on.connects, on.radio_checks
    assert watcher.STATE.device_wait_until is None and watcher.STATE.device_wait_episode is None
    watcher.STATE.__init__(mode=watcher.wifi_policy.Mode.BOOT)
    off = _Scenario(watcher, ready_at=T0 + 5, online=False, boot_age=30.0, radio=False)
    off.run(120)
    assert on_state == off.state()
    assert on_connects == off.connects
    assert on.sleeps == off.sleeps
    # The radio state is read around each attempt but never starts polling.
    assert set(on_checks) <= {t for t in on_connects}


def test_no_fast_phase_while_a_hotspot_is_up(watcher):
    sc = _Scenario(watcher, ready_at=None)
    watcher.STATE.setup_mode = True
    with patch.object(watcher.LOOP_CTX, "wifi_radio_state", sc._radio):
        watcher.wifi_loop._reconnect_noting_device_state(
            watcher.LOOP_CTX, T0, T0)
    assert watcher.STATE.device_wait_until is None


def test_a_device_that_never_becomes_available_reaches_the_ladder_as_before(watcher):
    """Repeated device-unavailable results do not bring any escalation forward,
    and the gateway-down reboot still happens at its threshold."""
    horizon = watcher.GW_DOWN_REBOOT_AFTER + 120
    on = _Scenario(watcher, ready_at=None)
    on.run(horizon)
    on_result = (on.reboots, on.connects, on.escalations, on.state())
    watcher.STATE.__init__(mode=watcher.wifi_policy.Mode.BOOT)
    off = _Scenario(watcher, ready_at=None, radio=False)
    off.run(horizon)
    assert on_result == (off.reboots, off.connects, off.escalations, off.state())
    assert on.reboots, "the reboot ladder must still be reached"
    assert on.reboots[0] >= T0 + watcher.GW_DOWN_REBOOT_AFTER


def test_the_fast_phase_stops_when_the_connection_comes_back_by_itself(watcher):
    sc = _Scenario(watcher, ready_at=None)
    sc.pass_()
    assert watcher.STATE.device_wait_until is not None
    watcher.STATE.conn_down_start = None            # a healthy pass cleared the episode
    sc.sleep()
    assert watcher.STATE.device_wait_until is None
    assert sc.connects == [T0]


def test_the_fast_phase_leaves_an_activation_in_flight_alone(watcher):
    sc = _Scenario(watcher, ready_at=T0 + 1)
    sc.pass_()
    watcher.STATE.transitioning = True
    sc.sleep()
    assert sc.connects == [T0]                      # no competing reconnect
    watcher.STATE.transitioning = False


def test_an_unreadable_device_state_never_breaks_the_loop(watcher):
    def boom():
        raise OSError("nmcli went away")
    watcher.STATE.been_online_this_boot = True
    with patch.object(watcher.LOOP_CTX, "wifi_radio_state", boom), \
         patch.object(watcher.LOOP_CTX, "connect_to_configured_wifi") as connect:
        watcher.wifi_loop._reconnect_noting_device_state(watcher.LOOP_CTX, T0, T0)
    connect.assert_called_once()
    assert watcher.STATE.device_wait_until is None


# ---- the device-state fact itself ----

@pytest.mark.parametrize("states,expected", [
    ([], "unknown"),
    (["unavailable"], "unavailable"),
    (["unavailable", "unavailable"], "unavailable"),
    (["disconnected"], "ready"),
    (["unavailable", "disconnected"], "ready"),
    (["connected"], "ready"),
    (["connecting (prepare)"], "ready"),
    (["unmanaged"], "unknown"),
    (["unavailable", "unmanaged"], "unknown"),
])
def test_the_radio_fact_comes_from_networkmanagers_device_state(watcher, states, expected):
    assert watcher.wifi_net.classify_wifi_radio(states) == expected


def test_the_radio_fact_reads_the_wifi_devices_only(watcher):
    out = MagicMock(returncode=0, stdout="lo:loopback:unmanaged:\neth0:ethernet:connected:Wired\n"
                                          "wlan0:wifi:unavailable:\n", stderr="")
    with patch.object(watcher.wifi_net, "run_cmd", return_value=out):
        assert watcher.wifi_net.wifi_radio_state() == "unavailable"
    failed = MagicMock(returncode=1, stdout="", stderr="boom")
    with patch.object(watcher.wifi_net, "run_cmd", return_value=failed):
        assert watcher.wifi_net.wifi_radio_state() == "unknown"
