"""Purity / invariant tests for the pure connectivity policy module.

These moved out of test_p1_wifi_watcher.py in Phase B-WP4: they exercise
wifi_policy directly, with no watcher / Flask / sysutils load, proving the
decision core is genuinely standalone and effect-free (constraint 10).  State
and facts are supplied as plain SimpleNamespace stand-ins; the per-adapter
recovery facts are duck-typed (next_recovery_action reads only .healthy,
.link_down, .quarantined, .noip_suppressed, .managed).
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_PLATFORM = str(Path(__file__).parent.parent / "platform")
if _PLATFORM not in sys.path:
    sys.path.insert(0, _PLATFORM)

import wifi_policy  # noqa: E402


def _state(*, setup_mode=False, conn_reboot_retry_after=0.0,
           connectivity_ok=False, boot_time=None):
    return SimpleNamespace(
        setup_mode=setup_mode,
        conn_reboot_retry_after=conn_reboot_retry_after,
        connectivity_ok=connectivity_ok,
        boot_time=boot_time,
    )


def _facts(*, wired_ok=False, taken_at=100.0):
    return SimpleNamespace(wired_ok=wired_ok, taken_at=taken_at)


class TestNextMode:
    M = wifi_policy.Mode

    def test_setup_mode_is_hotspot(self):
        # Hotspot wins even with a reboot accepted or a usable path.
        st = _state(setup_mode=True, conn_reboot_retry_after=float("inf"))
        assert wifi_policy.next_mode(st, _facts(wired_ok=True)) is self.M.HOTSPOT

    def test_reboot_pending(self):
        assert wifi_policy.next_mode(_state(conn_reboot_retry_after=float("inf")),
                                     _facts()) is self.M.REBOOT_PENDING

    def test_online_via_wired(self):
        assert wifi_policy.next_mode(_state(), _facts(wired_ok=True)) is self.M.ONLINE

    def test_online_via_connectivity_ok(self):
        assert wifi_policy.next_mode(_state(connectivity_ok=True), _facts()) is self.M.ONLINE

    def test_boot_window_when_offline(self):
        st = _state(boot_time=100.0)
        f = _facts(taken_at=100.0 + wifi_policy.BOOT_AP_GRACE - 1)
        assert wifi_policy.next_mode(st, f) is self.M.BOOT

    def test_offline_reconnecting_after_boot_grace(self):
        st = _state(boot_time=100.0)
        f = _facts(taken_at=100.0 + wifi_policy.BOOT_AP_GRACE + 1)
        assert wifi_policy.next_mode(st, f) is self.M.OFFLINE_RECONNECTING

    def test_always_returns_valid_mode_and_is_pure(self):
        for setup, reboot, conn, boot in [
            (True, 0.0, False, None), (False, float("inf"), False, None),
            (False, 0.0, True, None), (False, 0.0, False, 0.0), (False, 0.0, False, None),
        ]:
            st = _state(setup_mode=setup, conn_reboot_retry_after=reboot,
                        connectivity_ok=conn, boot_time=boot)
            before = dict(st.__dict__)
            assert wifi_policy.next_mode(st, _facts()) in set(self.M)
            assert st.__dict__ == before  # no state mutation

    def test_no_w_seam(self):
        assert "w" not in inspect.signature(wifi_policy.next_mode).parameters


class TestPurposeTable:
    P = wifi_policy.HotspotPurpose
    T = wifi_policy.PURPOSE_TABLE

    def test_five_rows_matching_spec(self):
        assert set(self.T) == set(self.P)
        assert self.T[self.P.FIRST_RUN].deadline_s is None
        assert self.T[self.P.FIRST_RUN].eth_suppressible is True
        assert self.T[self.P.FIRST_RUN].probes_return is False
        assert self.T[self.P.FIRST_RUN].rollback is False
        for p in (self.P.BOOT_RECOVERY, self.P.USB_LOSS_RECOVERY):
            assert self.T[p].deadline_s == wifi_policy.AP_MAX_DURATION
            assert self.T[p].eth_suppressible is True
            assert self.T[p].probes_return is True
            assert self.T[p].rollback is False
            assert self.T[p].probe_grace_s == 0.0
        assert self.T[self.P.EXPLICIT_RECONFIGURE].eth_suppressible is False
        assert self.T[self.P.EXPLICIT_RECONFIGURE].rollback is True
        assert self.T[self.P.EXPLICIT_RECONFIGURE].probe_grace_s == wifi_policy.HOTSPOT_PROBE_GRACE
        assert self.T[self.P.MANUAL].eth_suppressible is False
        assert self.T[self.P.MANUAL].probe_grace_s == wifi_policy.HOTSPOT_PROBE_GRACE

    def test_entries_are_frozen(self):
        policy = self.T[self.P.MANUAL]
        with pytest.raises(Exception):
            policy.deadline_s = 1.0


class TestNextRecoveryAction:
    K = wifi_policy.RecoveryKind
    P = wifi_policy.HotspotPurpose

    def _arf(self, ifname, *, is_usb=False, is_builtin=False, healthy=False,
             link_down=False, quarantined=False, noip_suppressed=False, managed=True):
        return SimpleNamespace(
            ifname=ifname, is_usb=is_usb, is_builtin=is_builtin, managed=managed,
            healthy=healthy, link_down=link_down, quarantined=quarantined,
            noip_suppressed=noip_suppressed,
        )

    def _rf(self, records, *, onboard="", usb=(), preferred_usb="", hotspot="",
            active="", saved=True, wired_ok=False, now=1000.0):
        return wifi_policy.RecoveryFacts(
            adapters_by_ifname={r.ifname: r for r in records},
            onboard_ifname=onboard, usb_ifnames=tuple(usb),
            preferred_usb_ifname=preferred_usb, hotspot_ifname=hotspot,
            active_ifname=active, saved_configured=saved, wired_ok=wired_ok, taken_at=now,
        )

    def _act(self, facts):
        return wifi_policy.next_recovery_action(_state(), facts)

    def test_wired_ok_holds(self):
        assert self._act(self._rf([], wired_ok=True)).kind is self.K.HOLD

    def test_unconfigured_enters_first_run(self):
        a = self._act(self._rf([], saved=False))
        assert a.kind is self.K.ENTER_HOTSPOT and a.purpose is self.P.FIRST_RUN

    def test_unconfigured_in_hotspot_holds(self):
        assert self._act(self._rf([], saved=False, hotspot="wlan0")).kind is self.K.HOLD

    def test_active_healthy_holds(self):
        usb = self._arf("wlan1", is_usb=True, healthy=True)
        f = self._rf([usb], usb=("wlan1",), preferred_usb="wlan1", active="wlan1")
        assert self._act(f).kind is self.K.HOLD

    def test_field_log_wedged_usb_activates_onboard(self):
        onboard = self._arf("wlan0", is_builtin=True, healthy=False)
        usb = self._arf("wlan1", is_usb=True, link_down=True, noip_suppressed=True)
        f = self._rf([onboard, usb], onboard="wlan0", usb=("wlan1",),
                     preferred_usb="", hotspot="wlan0", active="wlan1")
        a = self._act(f)
        assert a.kind is self.K.ACTIVATE_ONBOARD and a.ifname == "wlan0" and a.drop_hotspot is True

    def test_boot_entry_tries_onboard_before_hotspot(self):
        onboard = self._arf("wlan0", is_builtin=True)
        usb = self._arf("wlan1", is_usb=True, link_down=True)
        f = self._rf([onboard, usb], onboard="wlan0", usb=("wlan1",),
                     preferred_usb="wlan1", active="wlan1")
        a = self._act(f)
        assert a.kind is self.K.ACTIVATE_ONBOARD and a.drop_hotspot is False

    def test_usable_usb_preferred_over_onboard(self):
        onboard = self._arf("wlan0", is_builtin=True)
        usb = self._arf("wlan1", is_usb=True, link_down=False)
        f = self._rf([onboard, usb], onboard="wlan0", usb=("wlan1",),
                     preferred_usb="wlan1", active="")
        a = self._act(f)
        assert a.kind is self.K.ACTIVATE_USB and a.ifname == "wlan1"

    def test_usb_active_no_ip_holds(self):
        usb = self._arf("wlan1", is_usb=True, link_down=False, healthy=False)
        f = self._rf([usb], usb=("wlan1",), preferred_usb="wlan1", active="wlan1")
        assert self._act(f).kind is self.K.HOLD

    def test_onboard_failed_active_no_usb_enters_hotspot(self):
        onboard = self._arf("wlan0", is_builtin=True, healthy=False)
        a = self._act(self._rf([onboard], onboard="wlan0", active="wlan0"))
        assert a.kind is self.K.ENTER_HOTSPOT and a.purpose is self.P.BOOT_RECOVERY

    def test_single_wedged_usb_no_onboard_defers_to_reset_ladder(self):
        usb = self._arf("wlan1", is_usb=True, link_down=True)
        f = self._rf([usb], usb=("wlan1",), preferred_usb="wlan1", active="wlan1")
        assert self._act(f).kind is self.K.HOLD

    def test_no_w_seam(self):
        assert "w" not in inspect.signature(wifi_policy.next_recovery_action).parameters
