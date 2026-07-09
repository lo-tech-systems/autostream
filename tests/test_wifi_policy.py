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


# ---------------------------------------------------------------------------
# USB BSSID ownership: table maintenance + selection/roam policy
# ---------------------------------------------------------------------------

def _row(bssid, ssid, signal, in_use=False):
    return {"bssid": bssid, "ssid": ssid, "signal": signal, "in_use": in_use}


class TestUpdateBssidTable:
    def test_upserts_matching_ssid_rows_only(self):
        table = {}
        rows = [_row("AA", "Home", 70), _row("BB", "Other", 90)]
        wifi_policy.update_bssid_table(table, rows, "Home", now=100.0)
        assert set(table.keys()) == {"AA"}
        assert table["AA"]["signal"] == 70
        assert table["AA"]["last_seen"] == 100.0
        assert table["AA"]["fail_count"] == 0
        assert table["AA"]["quarantined_until"] is None

    def test_returns_in_use_row(self):
        table = {}
        rows = [_row("AA", "Home", 70), _row("BB", "Home", 90, in_use=True)]
        result = wifi_policy.update_bssid_table(table, rows, "Home", now=100.0)
        assert result == ("BB", 90)

    def test_returns_empty_when_no_in_use_row(self):
        table = {}
        rows = [_row("AA", "Home", 70)]
        result = wifi_policy.update_bssid_table(table, rows, "Home", now=100.0)
        assert result == ("", 0)

    def test_upsert_preserves_fail_count_and_quarantine(self):
        table = {"AA": {"ssid": "Home", "signal": 40, "last_seen": 50.0,
                        "fail_count": 2, "quarantined_until": 999.0}}
        rows = [_row("AA", "Home", 60)]
        wifi_policy.update_bssid_table(table, rows, "Home", now=100.0)
        assert table["AA"]["signal"] == 60
        assert table["AA"]["fail_count"] == 2
        assert table["AA"]["quarantined_until"] == 999.0

    def test_evicts_stale_entries(self):
        table = {"OLD": {"ssid": "Home", "signal": 50, "last_seen": 0.0,
                         "fail_count": 0, "quarantined_until": None}}
        rows = [_row("AA", "Home", 70)]
        now = wifi_policy.BSSID_EVICT_SECS + 1
        wifi_policy.update_bssid_table(table, rows, "Home", now=now)
        assert "OLD" not in table
        assert "AA" in table

    def test_ssid_change_clears_table(self):
        table = {"AA": {"ssid": "Home", "signal": 70, "last_seen": 100.0,
                        "fail_count": 0, "quarantined_until": None}}
        wifi_policy.clear_bssid_table(table)
        assert table == {}


class TestRecordBssidOutcome:
    def _table(self):
        return {
            "AA": {"ssid": "Home", "signal": 70, "last_seen": 100.0,
                  "fail_count": 0, "quarantined_until": None},
            "BB": {"ssid": "Home", "signal": 60, "last_seen": 100.0,
                  "fail_count": wifi_policy.BSSID_QUARANTINE_FAILS, "quarantined_until": None},
            "CC": {"ssid": "Other", "signal": 80, "last_seen": 100.0,
                  "fail_count": wifi_policy.BSSID_QUARANTINE_FAILS, "quarantined_until": None},
        }

    def test_failure_increments_count(self):
        table = self._table()
        wifi_policy.record_bssid_failure(table, "AA")
        assert table["AA"]["fail_count"] == 1

    def test_failure_on_unknown_bssid_is_noop(self):
        table = self._table()
        wifi_policy.record_bssid_failure(table, "ZZ")  # must not raise
        assert "ZZ" not in table

    def test_success_zeroes_own_count(self):
        table = self._table()
        table["AA"]["fail_count"] = 5
        wifi_policy.record_bssid_success(table, "AA", now=200.0)
        assert table["AA"]["fail_count"] == 0

    def test_success_quarantines_other_failed_same_ssid_entries(self):
        table = self._table()
        wifi_policy.record_bssid_success(table, "AA", now=200.0)
        assert table["BB"]["quarantined_until"] == 200.0 + wifi_policy.BSSID_QUARANTINE_SECS

    def test_success_does_not_quarantine_other_ssid_entries(self):
        table = self._table()
        wifi_policy.record_bssid_success(table, "AA", now=200.0)
        assert table["CC"]["quarantined_until"] is None

    def test_no_success_no_quarantine(self):
        table = self._table()
        wifi_policy.record_bssid_failure(table, "AA")
        assert table["BB"]["quarantined_until"] is None


class TestSelectBssid:
    def test_orders_by_fail_count_then_signal(self):
        table = {
            "AA": {"ssid": "Home", "signal": 60, "last_seen": 100.0,
                  "fail_count": 1, "quarantined_until": None},
            "BB": {"ssid": "Home", "signal": 90, "last_seen": 100.0,
                  "fail_count": 0, "quarantined_until": None},
            "CC": {"ssid": "Home", "signal": 50, "last_seen": 100.0,
                  "fail_count": 0, "quarantined_until": None},
        }
        assert wifi_policy.select_bssid(table, now=100.0) == "BB"

    def test_excludes_stale_entries(self):
        table = {
            "AA": {"ssid": "Home", "signal": 90, "last_seen": 0.0,
                  "fail_count": 0, "quarantined_until": None},
        }
        now = wifi_policy.BSSID_FRESH_SECS + 1
        assert wifi_policy.select_bssid(table, now=now) == ""

    def test_excludes_quarantined_entries(self):
        table = {
            "AA": {"ssid": "Home", "signal": 90, "last_seen": 100.0,
                  "fail_count": 0, "quarantined_until": 200.0},
            "BB": {"ssid": "Home", "signal": 50, "last_seen": 100.0,
                  "fail_count": 0, "quarantined_until": None},
        }
        assert wifi_policy.select_bssid(table, now=100.0) == "BB"

    def test_quarantine_expired_is_selectable(self):
        table = {
            "AA": {"ssid": "Home", "signal": 90, "last_seen": 100.0,
                  "fail_count": 0, "quarantined_until": 50.0},
        }
        assert wifi_policy.select_bssid(table, now=100.0) == "AA"

    def test_excludes_given_bssid(self):
        table = {
            "AA": {"ssid": "Home", "signal": 90, "last_seen": 100.0,
                  "fail_count": 0, "quarantined_until": None},
            "BB": {"ssid": "Home", "signal": 50, "last_seen": 100.0,
                  "fail_count": 0, "quarantined_until": None},
        }
        assert wifi_policy.select_bssid(table, now=100.0, exclude="AA") == "BB"

    def test_empty_table_returns_empty(self):
        assert wifi_policy.select_bssid({}, now=100.0) == ""


class TestNextRoamTarget:
    def _table(self, current_signal=50, candidate_signal=90):
        return {
            "CUR": {"ssid": "Home", "signal": current_signal, "last_seen": 100.0,
                   "fail_count": 0, "quarantined_until": None},
            "CAND": {"ssid": "Home", "signal": candidate_signal, "last_seen": 100.0,
                    "fail_count": 0, "quarantined_until": None},
        }

    def test_playing_true_holds(self):
        table = self._table()
        assert wifi_policy.next_roam_target(table, "CUR", 100.0, True, None) == ""

    def test_playing_none_defers(self):
        table = self._table()
        assert wifi_policy.next_roam_target(table, "CUR", 100.0, None, None) == ""

    def test_holdoff_not_elapsed_holds(self):
        table = self._table()
        last = 100.0 - (wifi_policy.ROAM_HOLDOFF_SECS - 1)
        assert wifi_policy.next_roam_target(table, "CUR", 100.0, False, last) == ""

    def test_holdoff_elapsed_allows_roam(self):
        table = self._table(current_signal=50, candidate_signal=70)  # clears ROAM_MARGIN
        last = 100.0 - (wifi_policy.ROAM_HOLDOFF_SECS + 1)
        assert wifi_policy.next_roam_target(table, "CUR", 100.0, False, last) == "CAND"

    def test_no_last_roam_allows_roam(self):
        table = self._table(current_signal=50, candidate_signal=70)
        assert wifi_policy.next_roam_target(table, "CUR", 100.0, False, None) == "CAND"

    def test_margin_arm_roams(self):
        table = self._table(current_signal=60, candidate_signal=60 + wifi_policy.ROAM_MARGIN)
        assert wifi_policy.next_roam_target(table, "CUR", 100.0, False, None) == "CAND"

    def test_margin_arm_insufficient_holds(self):
        table = self._table(current_signal=60, candidate_signal=60 + wifi_policy.ROAM_MARGIN - 1)
        assert wifi_policy.next_roam_target(table, "CUR", 100.0, False, None) == ""

    def test_low_signal_arm_roams_with_relaxed_margin(self):
        table = self._table(current_signal=wifi_policy.ROAM_LOW_SIGNAL,
                            candidate_signal=wifi_policy.ROAM_LOW_SIGNAL + wifi_policy.ROAM_LOW_MARGIN)
        assert wifi_policy.next_roam_target(table, "CUR", 100.0, False, None) == "CAND"

    def test_low_signal_arm_insufficient_holds(self):
        table = self._table(current_signal=wifi_policy.ROAM_LOW_SIGNAL,
                            candidate_signal=wifi_policy.ROAM_LOW_SIGNAL + wifi_policy.ROAM_LOW_MARGIN - 1)
        assert wifi_policy.next_roam_target(table, "CUR", 100.0, False, None) == ""

    def test_current_above_low_floor_needs_full_margin(self):
        # current above ROAM_LOW_SIGNAL: the relaxed low-margin arm must not apply.
        table = self._table(current_signal=wifi_policy.ROAM_LOW_SIGNAL + 1,
                            candidate_signal=wifi_policy.ROAM_LOW_SIGNAL + 1 + wifi_policy.ROAM_LOW_MARGIN)
        assert wifi_policy.next_roam_target(table, "CUR", 100.0, False, None) == ""

    def test_quarantined_candidate_excluded(self):
        table = self._table(current_signal=50, candidate_signal=90)
        table["CAND"]["quarantined_until"] = 200.0
        assert wifi_policy.next_roam_target(table, "CUR", 100.0, False, None) == ""

    def test_stale_candidate_excluded(self):
        table = self._table(current_signal=50, candidate_signal=90)
        table["CAND"]["last_seen"] = 0.0
        now = wifi_policy.BSSID_FRESH_SECS + 1
        assert wifi_policy.next_roam_target(table, "CUR", now, False, None) == ""

    def test_no_candidate_holds(self):
        table = {"CUR": {"ssid": "Home", "signal": 50, "last_seen": 100.0,
                         "fail_count": 0, "quarantined_until": None}}
        assert wifi_policy.next_roam_target(table, "CUR", 100.0, False, None) == ""

    def test_below_floor_rejected_despite_margin(self):
        # The field incident verbatim: 30 -> 47 clears ROAM_LOW_MARGIN but the
        # candidate is well below BSSID_ROAM_MIN_SIGNAL.
        table = self._table(current_signal=30, candidate_signal=47)
        assert wifi_policy.next_roam_target(table, "CUR", 100.0, False, None) == ""

    def test_below_floor_rejected_on_full_margin_arm(self):
        table = self._table(current_signal=30, candidate_signal=wifi_policy.BSSID_ROAM_MIN_SIGNAL - 1)
        assert wifi_policy.next_roam_target(table, "CUR", 100.0, False, None) == ""

    def test_at_floor_with_margin_accepted(self):
        table = self._table(current_signal=30, candidate_signal=wifi_policy.BSSID_ROAM_MIN_SIGNAL)
        assert wifi_policy.next_roam_target(table, "CUR", 100.0, False, None) == "CAND"

    def test_above_floor_with_low_signal_margin_accepted(self):
        # current satisfies the low-signal arm (<= ROAM_LOW_SIGNAL) and the
        # candidate clears both the relaxed margin and the absolute floor.
        current = wifi_policy.ROAM_LOW_SIGNAL - 1
        candidate = current + wifi_policy.ROAM_LOW_MARGIN
        assert candidate == wifi_policy.BSSID_ROAM_MIN_SIGNAL
        table = self._table(current_signal=current, candidate_signal=candidate)
        assert wifi_policy.next_roam_target(table, "CUR", 100.0, False, None) == "CAND"

    def test_custom_min_signal_overrides_default_floor(self):
        table = self._table(current_signal=30, candidate_signal=47)
        assert wifi_policy.next_roam_target(
            table, "CUR", 100.0, False, None, min_signal=40) == "CAND"


class TestUpdateRoamStreak:
    def test_empty_candidate_resets(self):
        streak = {"ifname": "wlan1", "bssid": "AA:BB", "count": 2, "last_seen": 100.0}
        assert wifi_policy.update_roam_streak(streak, "wlan1", "", 200.0) == {}

    def test_same_candidate_increments_and_refreshes(self):
        streak = {"ifname": "wlan1", "bssid": "AA:BB", "count": 1, "last_seen": 100.0}
        result = wifi_policy.update_roam_streak(streak, "wlan1", "AA:BB", 200.0)
        assert result == {"ifname": "wlan1", "bssid": "AA:BB", "count": 2, "last_seen": 200.0}

    def test_different_candidate_resets_to_one(self):
        streak = {"ifname": "wlan1", "bssid": "AA:BB", "count": 3, "last_seen": 100.0}
        result = wifi_policy.update_roam_streak(streak, "wlan1", "CC:DD", 200.0)
        assert result == {"ifname": "wlan1", "bssid": "CC:DD", "count": 1, "last_seen": 200.0}

    def test_different_interface_resets_to_one(self):
        streak = {"ifname": "wlan1", "bssid": "AA:BB", "count": 3, "last_seen": 100.0}
        result = wifi_policy.update_roam_streak(streak, "wlan2", "AA:BB", 200.0)
        assert result == {"ifname": "wlan2", "bssid": "AA:BB", "count": 1, "last_seen": 200.0}

    def test_empty_streak_starts_at_one(self):
        result = wifi_policy.update_roam_streak({}, "wlan1", "AA:BB", 100.0)
        assert result == {"ifname": "wlan1", "bssid": "AA:BB", "count": 1, "last_seen": 100.0}

    def test_does_not_mutate_input_streak(self):
        streak = {"ifname": "wlan1", "bssid": "AA:BB", "count": 1, "last_seen": 100.0}
        wifi_policy.update_roam_streak(streak, "wlan1", "AA:BB", 200.0)
        assert streak == {"ifname": "wlan1", "bssid": "AA:BB", "count": 1, "last_seen": 100.0}


class TestBssidTablesAccessors:
    def test_bssid_table_for_interface_creates_empty_table(self):
        tables = {}
        table = wifi_policy.bssid_table_for_interface(tables, "wlan1")
        assert table == {}
        assert tables == {"wlan1": {}}

    def test_bssid_table_for_interface_returns_same_table_on_repeat_calls(self):
        tables = {}
        table1 = wifi_policy.bssid_table_for_interface(tables, "wlan1")
        table1["AA:BB"] = {"ssid": "Home"}
        table2 = wifi_policy.bssid_table_for_interface(tables, "wlan1")
        assert table2 == {"AA:BB": {"ssid": "Home"}}

    def test_bssid_table_for_interface_keeps_interfaces_separate(self):
        tables = {}
        wifi_policy.bssid_table_for_interface(tables, "wlan0")["X"] = 1
        wifi_policy.bssid_table_for_interface(tables, "wlan1")["Y"] = 2
        assert tables == {"wlan0": {"X": 1}, "wlan1": {"Y": 2}}

    def test_clear_bssid_tables_drops_all_interfaces(self):
        tables = {"wlan0": {"X": 1}, "wlan1": {"Y": 2}}
        wifi_policy.clear_bssid_tables(tables)
        assert tables == {}
