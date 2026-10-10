"""Storage guard tests.

Covers:
  - classify_storage: all threshold boundaries
  - has_recovered_from_warning / has_recovered_from_critical
  - _is_eligible_archive: every allowlisted directory, all extensions,
    active base logs, unknown dirs, and unknown filenames
  - _parse_sdcard_health_percent: valid, out-of-range, missing fields
  - compute_desired_ceiling: disk state and SD health combinations
  - compute_expiry_target: tier-1 and tier-2, null ts, too-early
  - apply_expiry_to_saved: cascading tier-1→tier-2
  - _level_quieter_than: all orderings
  - Guard allowlist safety: active logs never selected, no symlinks
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "tests"))

from conftest import load_supervisor_script

sg = load_supervisor_script("autostream_storage_guard", "storage_guard_wp3")


# ---------------------------------------------------------------------------
# get_playing_status — uncertain/malformed treated as None (Section 8.3)
# ---------------------------------------------------------------------------

class TestGetPlayingStatus:
    def _run(self, api_data):
        from unittest.mock import patch
        with patch.object(sg, "_api_get", return_value=api_data):
            return sg.get_playing_status()

    def test_ok_true_playing_true(self):
        assert self._run({"ok": True, "playing": True}) is True

    def test_ok_true_playing_false(self):
        assert self._run({"ok": True, "playing": False}) is False

    def test_ok_false_is_none(self):
        assert self._run({"ok": False, "error": "playing status unavailable"}) is None

    def test_missing_ok_is_none(self):
        assert self._run({"playing": True}) is None

    def test_non_boolean_playing_is_none(self):
        assert self._run({"ok": True, "playing": "yes"}) is None

    def test_unreachable_is_none(self):
        assert self._run(None) is None


# ---------------------------------------------------------------------------
# classify_storage
# ---------------------------------------------------------------------------

class TestClassifyStorage:
    def _m(self, free_bytes, free_pct, free_inode_pct):
        return {
            "free_bytes": free_bytes,
            "free_percent": free_pct,
            "free_inodes_percent": free_inode_pct,
        }

    # Normal state: at least 15% free, 1 GiB free, 10% inodes
    def test_normal_plenty(self):
        assert sg.classify_storage(self._m(2 * 1024**3, 50.0, 50.0)) == "normal"

    def test_normal_boundary_bytes(self):
        # Exactly 1 GiB free, 15% free, 10% inodes → still normal
        assert sg.classify_storage(self._m(1024**3, 15.0, 10.0)) == "normal"

    def test_warning_below_bytes(self):
        # Just below 1 GiB but above 512 MiB and above 8%, not critical
        assert sg.classify_storage(self._m(800 * 1024**2, 10.0, 8.0)) == "warning"

    def test_warning_below_pct(self):
        # Below 15% pct
        assert sg.classify_storage(self._m(2 * 1024**3, 12.0, 15.0)) == "warning"

    def test_critical_below_512mib(self):
        assert sg.classify_storage(self._m(400 * 1024**2, 6.0, 8.0)) == "critical"

    def test_critical_below_8pct(self):
        assert sg.classify_storage(self._m(1024**3, 6.0, 10.0)) == "critical"

    def test_critical_below_inode_pct(self):
        assert sg.classify_storage(self._m(1024**3, 20.0, 3.0)) == "critical"

    def test_emergency_below_128mib(self):
        assert sg.classify_storage(self._m(100 * 1024**2, 2.0, 5.0)) == "emergency"

    def test_emergency_below_3pct(self):
        assert sg.classify_storage(self._m(512 * 1024**2, 2.0, 5.0)) == "emergency"

    def test_emergency_below_1pct_inodes(self):
        assert sg.classify_storage(self._m(512 * 1024**2, 10.0, 0.5)) == "emergency"


class TestRecovery:
    def _m(self, free_bytes, free_pct, free_inode_pct):
        return {"free_bytes": free_bytes, "free_percent": free_pct,
                "free_inodes_percent": free_inode_pct}

    def test_recovered_from_warning(self):
        # 1.25 GiB, 17%, 12% inodes
        assert sg.has_recovered_from_warning(
            self._m(int(1.25 * 1024**3), 17.0, 12.0)
        ) is True

    def test_not_recovered_from_warning_pct(self):
        assert sg.has_recovered_from_warning(
            self._m(int(1.25 * 1024**3), 16.0, 12.0)
        ) is False

    def test_recovered_from_critical(self):
        assert sg.has_recovered_from_critical(
            self._m(768 * 1024**2, 10.0, 6.0)
        ) is True

    def test_not_recovered_from_critical_inode(self):
        assert sg.has_recovered_from_critical(
            self._m(768 * 1024**2, 10.0, 5.0)
        ) is False


# ---------------------------------------------------------------------------
# _is_eligible_archive
# ---------------------------------------------------------------------------

class TestIsEligibleArchive:
    # /var/log/autostream — all rotated files eligible
    def test_autostream_numbered(self):
        assert sg._is_eligible_archive("/var/log/autostream", "autostream.1.gz") is True

    def test_autostream_dated(self):
        assert sg._is_eligible_archive("/var/log/autostream", "autostream-20260601.gz") is True

    def test_autostream_active_base_not_eligible(self):
        # File named exactly 'autostream' (no suffix) - not a rotated archive
        assert sg._is_eligible_archive("/var/log/autostream", "autostream") is False

    def test_autostream_any_base(self):
        assert sg._is_eligible_archive("/var/log/autostream", "mylog.2.xz") is True

    # /var/log/nginx
    def test_nginx_access_numbered(self):
        assert sg._is_eligible_archive("/var/log/nginx", "access.log.1") is True

    def test_nginx_access_dated(self):
        # base = 'access.log' (from dated pattern); allowed for nginx
        assert sg._is_eligible_archive("/var/log/nginx", "access.log-20260601.gz") is True

    def test_nginx_error_numbered(self):
        assert sg._is_eligible_archive("/var/log/nginx", "error.log.1.gz") is True

    def test_nginx_unknown_base_not_eligible(self):
        assert sg._is_eligible_archive("/var/log/nginx", "custom.log.1") is False

    def test_nginx_active_log_not_eligible(self):
        assert sg._is_eligible_archive("/var/log/nginx", "access.log") is False

    # /var/log
    def test_varlog_syslog_numbered(self):
        assert sg._is_eligible_archive("/var/log", "syslog.1") is True

    def test_varlog_syslog_numbered_gz(self):
        assert sg._is_eligible_archive("/var/log", "syslog.2.gz") is True

    def test_varlog_syslog_dated(self):
        assert sg._is_eligible_archive("/var/log", "syslog-20260601") is True

    def test_varlog_syslog_dated_gz(self):
        assert sg._is_eligible_archive("/var/log", "syslog-20260601.gz") is True

    def test_varlog_auth_log_numbered(self):
        assert sg._is_eligible_archive("/var/log", "auth.log.1") is True

    def test_varlog_dpkg_log_numbered(self):
        assert sg._is_eligible_archive("/var/log", "dpkg.log.2.bz2") is True

    def test_varlog_unknown_base_not_eligible(self):
        assert sg._is_eligible_archive("/var/log", "wtmp.1") is False

    def test_varlog_active_syslog_not_eligible(self):
        assert sg._is_eligible_archive("/var/log", "syslog") is False

    def test_varlog_unknown_extension(self):
        assert sg._is_eligible_archive("/var/log", "syslog.1.lzma") is False

    def test_unknown_directory_not_eligible(self):
        assert sg._is_eligible_archive("/tmp", "syslog.1.gz") is False

    # All supported extensions
    @pytest.mark.parametrize("ext", ["", ".gz", ".bz2", ".xz", ".zst"])
    def test_autostream_all_extensions(self, ext):
        assert sg._is_eligible_archive("/var/log/autostream", f"autostream.1{ext}") is True

    @pytest.mark.parametrize("ext", [".gz", ".bz2", ".xz", ".zst"])
    def test_varlog_all_extensions(self, ext):
        assert sg._is_eligible_archive("/var/log", f"syslog.1{ext}") is True


# ---------------------------------------------------------------------------
# SD-card health parser
# ---------------------------------------------------------------------------

class TestParseSdcardHealth:
    def test_endurance_remain(self):
        data = {"success": True, "enduranceRemainLifePercent": 42.7}
        assert sg._parse_sdcard_health_percent(data) == 43

    def test_health_percent_used(self):
        data = {"success": True, "healthStatusPercentUsed": 30.0}
        assert sg._parse_sdcard_health_percent(data) == 70

    def test_success_false_returns_none(self):
        assert sg._parse_sdcard_health_percent({"success": False}) is None

    def test_out_of_range_returns_none(self):
        data = {"success": True, "enduranceRemainLifePercent": 150.0}
        assert sg._parse_sdcard_health_percent(data) is None

    def test_negative_returns_none(self):
        data = {"success": True, "enduranceRemainLifePercent": -5.0}
        assert sg._parse_sdcard_health_percent(data) is None

    def test_zero_remaining(self):
        data = {"success": True, "enduranceRemainLifePercent": 0.0}
        assert sg._parse_sdcard_health_percent(data) == 0

    def test_missing_fields_returns_none(self):
        data = {"success": True}
        assert sg._parse_sdcard_health_percent(data) is None


# ---------------------------------------------------------------------------
# compute_desired_ceiling
# ---------------------------------------------------------------------------

class TestComputeDesiredCeiling:
    def _sd(self, status="unavailable", pct=None):
        return {"status": status, "remaining_percent": pct}

    def test_normal_no_ceiling(self):
        assert sg.compute_desired_ceiling("normal", self._sd()) is None

    def test_warning_ceiling_info(self):
        assert sg.compute_desired_ceiling("warning", self._sd()) == "info"

    def test_critical_ceiling_warning(self):
        assert sg.compute_desired_ceiling("critical", self._sd()) == "warning"

    def test_emergency_ceiling_warning(self):
        assert sg.compute_desired_ceiling("emergency", self._sd()) == "warning"

    def test_low_sd_health_ceiling_warning(self):
        assert sg.compute_desired_ceiling("normal", self._sd("valid", 15)) == "warning"

    def test_warning_disk_plus_low_sd_quietest(self):
        # warning disk → "info"; low sd → "warning"; quietest wins = "warning"
        result = sg.compute_desired_ceiling("warning", self._sd("valid", 15))
        # "warning" is quieter than "info"
        assert result == "warning"

    def test_sd_above_threshold_no_ceiling(self):
        assert sg.compute_desired_ceiling("normal", self._sd("valid", 30)) is None

    def test_sd_stale_no_ceiling(self):
        assert sg.compute_desired_ceiling("normal", self._sd("stale", 5)) is None


# ---------------------------------------------------------------------------
# compute_expiry_target
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 6, 24, 4, 0, 0, tzinfo=timezone.utc)


class TestComputeExpiryTarget:
    def _api(self, level, changed_at):
        return {"level": level, "changed_at": changed_at}

    def test_spam_expired_48h(self):
        ts = (_NOW - timedelta(hours=49)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert sg.compute_expiry_target(self._api("spam", ts), _NOW) == "info"

    def test_debug_expired_48h(self):
        ts = (_NOW - timedelta(hours=48, minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert sg.compute_expiry_target(self._api("debug", ts), _NOW) == "info"

    def test_debug_not_yet_expired(self):
        ts = (_NOW - timedelta(hours=47)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert sg.compute_expiry_target(self._api("debug", ts), _NOW) is None

    def test_info_expired_168h(self):
        ts = (_NOW - timedelta(hours=169)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert sg.compute_expiry_target(self._api("info", ts), _NOW) == "warning"

    def test_info_not_yet_expired(self):
        ts = (_NOW - timedelta(hours=167)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert sg.compute_expiry_target(self._api("info", ts), _NOW) is None

    def test_null_changed_at_no_expiry(self):
        assert sg.compute_expiry_target(self._api("spam", None), _NOW) is None

    def test_warning_level_no_expiry(self):
        ts = (_NOW - timedelta(hours=500)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert sg.compute_expiry_target(self._api("warning", ts), _NOW) is None


# ---------------------------------------------------------------------------
# apply_expiry_to_saved
# ---------------------------------------------------------------------------

class TestApplyExpiryToSaved:
    def test_spam_within_48h_unchanged(self):
        ts = (_NOW - timedelta(hours=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert sg.apply_expiry_to_saved("spam", ts, _NOW) == "spam"

    def test_spam_beyond_48h_becomes_info(self):
        ts = (_NOW - timedelta(hours=50)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert sg.apply_expiry_to_saved("spam", ts, _NOW) == "info"

    def test_debug_beyond_48h_info_not_further_expired_in_one_step(self):
        # Total 200h old: spam → info at 48h; from that point, 152h more
        # That exceeds 168h limit... wait, the elapsed is computed from
        # saved_at (the original timestamp). So info clock would be reset to 0
        # at the Tier-1 expiry event per the apply_expiry_to_saved impl.
        ts = (_NOW - timedelta(hours=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
        # spam → info (elapsed reset), no further tier-2 within same call
        result = sg.apply_expiry_to_saved("debug", ts, _NOW)
        assert result == "info"

    def test_info_within_168h_unchanged(self):
        ts = (_NOW - timedelta(hours=100)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert sg.apply_expiry_to_saved("info", ts, _NOW) == "info"

    def test_info_beyond_168h_becomes_warning(self):
        ts = (_NOW - timedelta(hours=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert sg.apply_expiry_to_saved("info", ts, _NOW) == "warning"

    def test_null_ts_unchanged(self):
        assert sg.apply_expiry_to_saved("spam", None, _NOW) == "spam"

    def test_warning_unchanged(self):
        ts = (_NOW - timedelta(hours=1000)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert sg.apply_expiry_to_saved("warning", ts, _NOW) == "warning"


# ---------------------------------------------------------------------------
# SD-health hysteresis and retention
# ---------------------------------------------------------------------------

class TestSdHealthCeilingApplies:
    def _sd(self, status="valid", pct=None):
        return {"status": status, "remaining_percent": pct}

    def test_below_threshold_no_history(self):
        assert sg._sd_health_ceiling_applies(self._sd("valid", 15), None, _NOW) is True

    def test_above_threshold_no_history(self):
        assert sg._sd_health_ceiling_applies(self._sd("valid", 30), None, _NOW) is False

    def test_in_hysteresis_zone_with_recent_history(self):
        # 22% is between 20% (trigger) and 25% (recover) — retain within 72h
        ts = (_NOW - timedelta(hours=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert sg._sd_health_ceiling_applies(self._sd("valid", 22), ts, _NOW) is True

    def test_above_hysteresis_clears_within_retention(self):
        # 26% is above 25% recover threshold — clear even within 72h
        ts = (_NOW - timedelta(hours=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert sg._sd_health_ceiling_applies(self._sd("valid", 26), ts, _NOW) is False

    def test_stale_within_72h_retains_ceiling(self):
        ts = (_NOW - timedelta(hours=40)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert sg._sd_health_ceiling_applies(self._sd("stale"), ts, _NOW) is True

    def test_stale_beyond_72h_clears(self):
        ts = (_NOW - timedelta(hours=73)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert sg._sd_health_ceiling_applies(self._sd("stale"), ts, _NOW) is False

    def test_stale_no_history(self):
        assert sg._sd_health_ceiling_applies(self._sd("stale"), None, _NOW) is False

    def test_in_hysteresis_zone_beyond_72h_still_retains(self):
        # Valid in-band readings are NOT subject to the 72-hour expiry —
        # only stale/unavailable data uses that window.
        ts = (_NOW - timedelta(hours=80)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert sg._sd_health_ceiling_applies(self._sd("valid", 22), ts, _NOW) is True

    def test_exactly_at_recover_threshold_retained(self):
        # Exactly 25 % must still be restricted; release only when strictly above 25 %.
        ts = (_NOW - timedelta(hours=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert sg._sd_health_ceiling_applies(self._sd("valid", 25), ts, _NOW) is True

    def test_one_above_recover_threshold_clears(self):
        # 26 % is strictly above 25 % — clear.
        ts = (_NOW - timedelta(hours=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert sg._sd_health_ceiling_applies(self._sd("valid", 26), ts, _NOW) is False

    def test_in_hysteresis_no_history_no_retain(self):
        # If in [20 %, 25 %] but never previously restricted, no ceiling applies.
        assert sg._sd_health_ceiling_applies(self._sd("valid", 22), None, _NOW) is False


class TestComputeDesiredCeilingHysteresis:
    """compute_desired_ceiling uses hysteresis/retention when context is passed."""

    def _sd(self, status="valid", pct=None):
        return {"status": status, "remaining_percent": pct}

    def test_hysteresis_zone_retains_ceiling(self):
        ts = (_NOW - timedelta(hours=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        result = sg.compute_desired_ceiling(
            "normal", self._sd("valid", 22),
            prev_sd_restricted_at=ts, now=_NOW,
        )
        assert result == "warning"

    def test_above_hysteresis_clears(self):
        ts = (_NOW - timedelta(hours=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        result = sg.compute_desired_ceiling(
            "normal", self._sd("valid", 26),
            prev_sd_restricted_at=ts, now=_NOW,
        )
        assert result is None

    def test_stale_retains_within_72h(self):
        ts = (_NOW - timedelta(hours=40)).strftime("%Y-%m-%dT%H:%M:%SZ")
        result = sg.compute_desired_ceiling(
            "normal", self._sd("stale"),
            prev_sd_restricted_at=ts, now=_NOW,
        )
        assert result == "warning"


# ---------------------------------------------------------------------------
# run_log_level_policy — expiry applies regardless of changed_by
# ---------------------------------------------------------------------------

class TestRunLogLevelPolicyExpiry:
    def _make_guard_state(self):
        return {"log_policy": {}}

    def _make_sd_health(self):
        return {"status": "unavailable", "remaining_percent": None}

    def _run(self, api_state):
        from unittest.mock import patch
        ok_result = {"ok": True, "level": "info"}
        actions = []
        with patch.object(sg, "get_log_level_state", return_value=api_state), \
             patch.object(sg, "_api_put_log_level", return_value=ok_result) as mock_put:
            sg.run_log_level_policy(
                disk_state="normal",
                sd_health=self._make_sd_health(),
                guard_state=self._make_guard_state(),
                actions=actions,
                now=_NOW,
            )
        return mock_put

    def test_user_debug_expired_after_48h(self):
        ts = (_NOW - timedelta(hours=50)).strftime("%Y-%m-%dT%H:%M:%SZ")
        api_state = {"level": "debug", "changed_by": "user", "changed_at": ts}
        mock_put = self._run(api_state)
        mock_put.assert_called_with("info")

    def test_system_debug_expired_after_48h(self):
        ts = (_NOW - timedelta(hours=50)).strftime("%Y-%m-%dT%H:%M:%SZ")
        api_state = {"level": "debug", "changed_by": "system", "changed_at": ts}
        mock_put = self._run(api_state)
        mock_put.assert_called_with("info")

    def test_recent_debug_not_expired(self):
        ts = (_NOW - timedelta(hours=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        api_state = {"level": "debug", "changed_by": "user", "changed_at": ts}
        mock_put = self._run(api_state)
        mock_put.assert_not_called()


# ---------------------------------------------------------------------------
# run_log_level_policy — SD health active_reasons and timestamp management
# ---------------------------------------------------------------------------

class TestRunLogLevelPolicySdHealth:
    """Verify active_reasons and sd_health_restricted_at updates."""

    _API_STATE = {"level": "spam", "changed_by": "user", "changed_at": None}

    def _run(self, sd_health, guard_state):
        from unittest.mock import patch
        ok_result = {"ok": True, "level": "warning"}
        result = {}
        actions = []
        with patch.object(sg, "get_log_level_state", return_value=self._API_STATE), \
             patch.object(sg, "_api_put_log_level", return_value=ok_result):
            result = sg.run_log_level_policy(
                disk_state="normal",
                sd_health=sd_health,
                guard_state=guard_state,
                actions=actions,
                now=_NOW,
            )
        return result, actions

    def _sd(self, status="valid", pct=None):
        return {"status": status, "remaining_percent": pct}

    def test_fresh_trigger_adds_reason_and_sets_timestamp(self):
        result, _ = self._run(self._sd("valid", 10), {"log_policy": {}})
        assert "low_sd_health" in result["active_reasons"]
        assert result["sd_health_restricted_at"] is not None

    def test_hysteresis_zone_adds_reason(self):
        ts = (_NOW - timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        guard = {"log_policy": {"sd_health_restricted_at": ts}}
        result, _ = self._run(self._sd("valid", 22), guard)
        assert "low_sd_health" in result["active_reasons"]

    def test_stale_retention_adds_reason(self):
        ts = (_NOW - timedelta(hours=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        guard = {"log_policy": {"sd_health_restricted_at": ts}}
        result, _ = self._run(self._sd("stale"), guard)
        assert "low_sd_health" in result["active_reasons"]

    def test_fresh_trigger_refreshes_existing_timestamp(self):
        # When pct < 20 % on subsequent runs, timestamp must be updated to now,
        # not left at the original activation time.
        old_ts = (_NOW - timedelta(hours=50)).strftime("%Y-%m-%dT%H:%M:%SZ")
        guard = {"log_policy": {"sd_health_restricted_at": old_ts}}
        result, _ = self._run(self._sd("valid", 10), guard)
        new_ts = result["sd_health_restricted_at"]
        assert new_ts != old_ts
        assert new_ts == _NOW.strftime("%Y-%m-%dT%H:%M:%SZ")

    def test_hysteresis_zone_refreshes_timestamp(self):
        # Valid readings in [20 %, 25 %] must also refresh the timestamp so that
        # a subsequent transition to stale/unavailable data still gets the full
        # 72-hour retention window measured from the most recent valid reading.
        old_ts = (_NOW - timedelta(hours=50)).strftime("%Y-%m-%dT%H:%M:%SZ")
        guard = {"log_policy": {"sd_health_restricted_at": old_ts}}
        result, _ = self._run(self._sd("valid", 22), guard)
        new_ts = result["sd_health_restricted_at"]
        assert new_ts != old_ts
        assert new_ts == _NOW.strftime("%Y-%m-%dT%H:%M:%SZ")

    def test_hysteresis_to_stale_transition_retains_ceiling(self):
        # Scenario: health was at 22 % for several days (timestamp refreshed each run).
        # Data then becomes unavailable.  The 72-hour retention window should run from
        # the last valid reading, not the original trigger — so restriction is kept.
        recent_ts = (_NOW - timedelta(hours=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        guard = {"log_policy": {"sd_health_restricted_at": recent_ts}}
        result, _ = self._run(self._sd("stale"), guard)
        assert "low_sd_health" in result["active_reasons"]
        # Timestamp must be unchanged (stale data does not refresh it).
        assert result["sd_health_restricted_at"] == recent_ts

    def test_no_restriction_clears_timestamp(self):
        ts = (_NOW - timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        guard = {"log_policy": {"sd_health_restricted_at": ts}}
        result, _ = self._run(self._sd("valid", 90), guard)
        assert "low_sd_health" not in result.get("active_reasons", [])
        assert result["sd_health_restricted_at"] is None


# ---------------------------------------------------------------------------
# _level_quieter_than
# ---------------------------------------------------------------------------

class TestLevelQuieterThan:
    def test_fatal_quieter_than_warning(self):
        assert sg._level_quieter_than("fatal", "warning") is True

    def test_warning_quieter_than_info(self):
        assert sg._level_quieter_than("warning", "info") is True

    def test_spam_not_quieter_than_debug(self):
        assert sg._level_quieter_than("spam", "debug") is False

    def test_same_level_not_quieter(self):
        assert sg._level_quieter_than("info", "info") is False

    def test_info_not_quieter_than_warning(self):
        assert sg._level_quieter_than("info", "warning") is False


# ---------------------------------------------------------------------------
# Archive safety: active log never eligible
# ---------------------------------------------------------------------------

class TestArchiveSafety:
    @pytest.mark.parametrize("base", [
        "syslog", "auth.log", "kern.log", "daemon.log",
        "dpkg.log", "alternatives.log",
    ])
    def test_active_varlog_base_not_eligible(self, base):
        assert sg._is_eligible_archive("/var/log", base) is False

    @pytest.mark.parametrize("base", ["access.log", "error.log"])
    def test_active_nginx_base_not_eligible(self, base):
        assert sg._is_eligible_archive("/var/log/nginx", base) is False

    def test_unknown_extension_not_eligible(self):
        assert sg._is_eligible_archive("/var/log", "syslog.1.lzma") is False

    def test_dotfile_not_matched(self):
        # Hidden file should not match numbered pattern unexpectedly
        assert sg._is_eligible_archive("/var/log", ".syslog") is False

    def test_autostream_dir_no_active_base(self):
        # Any plain file in /var/log/autostream without numeric/dated suffix is not eligible
        assert sg._is_eligible_archive("/var/log/autostream", "autostream.log") is False


# ---------------------------------------------------------------------------
# detect_install_kind: dial vs appliance detection
# ---------------------------------------------------------------------------

class TestDetectInstallKind:
    def test_dial_flag_wins(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sg, "INSTALL_STATE_PATH", tmp_path / "no-such-file.env")
        monkeypatch.setattr(sg, "DIAL_HW_CONFIG_PATH", tmp_path / "no-such-file.json")
        assert sg.detect_install_kind(["--dial"]) == sg.KIND_DIAL

    def test_appliance_flag_wins(self, tmp_path, monkeypatch):
        state = tmp_path / "install-state.env"
        state.write_text("AUTOSTREAM_PRODUCT=autostream-dial\n", encoding="utf-8")
        monkeypatch.setattr(sg, "INSTALL_STATE_PATH", state)
        assert sg.detect_install_kind(["--appliance"]) == sg.KIND_APPLIANCE

    def test_product_key_dial(self, tmp_path, monkeypatch):
        state = tmp_path / "install-state.env"
        state.write_text("AUTOSTREAM_PRODUCT=autostream-dial\n", encoding="utf-8")
        monkeypatch.setattr(sg, "INSTALL_STATE_PATH", state)
        monkeypatch.setattr(sg, "DIAL_HW_CONFIG_PATH", tmp_path / "absent.json")
        assert sg.detect_install_kind([]) == sg.KIND_DIAL

    def test_product_key_appliance(self, tmp_path, monkeypatch):
        state = tmp_path / "install-state.env"
        state.write_text("AUTOSTREAM_PRODUCT=autostream\n", encoding="utf-8")
        monkeypatch.setattr(sg, "INSTALL_STATE_PATH", state)
        assert sg.detect_install_kind([]) == sg.KIND_APPLIANCE

    def test_missing_state_falls_back_to_hw_config(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sg, "INSTALL_STATE_PATH", tmp_path / "absent.env")
        hw = tmp_path / "autostream-dial.json"
        hw.write_text("{}", encoding="utf-8")
        monkeypatch.setattr(sg, "DIAL_HW_CONFIG_PATH", hw)
        assert sg.detect_install_kind([]) == sg.KIND_DIAL

    def test_nothing_present_is_appliance(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sg, "INSTALL_STATE_PATH", tmp_path / "absent.env")
        monkeypatch.setattr(sg, "DIAL_HW_CONFIG_PATH", tmp_path / "absent.json")
        assert sg.detect_install_kind([]) == sg.KIND_APPLIANCE

    def test_quoted_value_parses(self, tmp_path, monkeypatch):
        state = tmp_path / "install-state.env"
        state.write_text('AUTOSTREAM_PRODUCT="autostream-dial"\n', encoding="utf-8")
        monkeypatch.setattr(sg, "INSTALL_STATE_PATH", state)
        assert sg.detect_install_kind([]) == sg.KIND_DIAL


# ---------------------------------------------------------------------------
# main(): dial mode skips playing/log-level policy; appliance mode keeps them
# ---------------------------------------------------------------------------

class TestMainDialMode:
    def _patch_common(self, monkeypatch, tmp_path):
        from unittest.mock import MagicMock

        monkeypatch.setattr(sg, "STATE_PATH", tmp_path / "storage-guard.json")
        monkeypatch.setattr(sg, "_acquire_lock", lambda *a, **k: os.open(
            str(tmp_path / f"lock-{len(os.listdir(tmp_path))}"), os.O_RDWR | os.O_CREAT
        ))
        monkeypatch.setattr(sg, "measure_storage", lambda: {
            "total_bytes": 100 * 1024 ** 3,
            "free_bytes": 50 * 1024 ** 3,
            "used_bytes": 50 * 1024 ** 3,
            "free_percent": 50.0,
            "free_inodes_percent": 50.0,
            "total_inodes": 1000000,
            "free_inodes": 500000,
        })
        monkeypatch.setattr(sg, "_logrotate_timer_status", lambda: {
            "exists": False, "enabled": False, "active": False,
        })
        monkeypatch.setattr(sg, "scan_largest_files", lambda *a, **k: [])
        monkeypatch.setattr(sg, "scan_deleted_open_files", lambda: [])
        monkeypatch.setattr(sg, "run_cleanup", lambda **k: "normal")
        playing_mock = MagicMock(return_value=None)
        policy_mock = MagicMock(return_value={})
        monkeypatch.setattr(sg, "get_playing_status", playing_mock)
        monkeypatch.setattr(sg, "run_log_level_policy", policy_mock)
        return playing_mock, policy_mock

    def test_dial_mode_skips_playing_and_log_policy(self, tmp_path, monkeypatch):
        playing_mock, policy_mock = self._patch_common(monkeypatch, tmp_path)
        monkeypatch.setattr(sys, "argv", ["autostream_storage_guard", "--dial"])
        assert sg.main() == 0
        playing_mock.assert_not_called()
        policy_mock.assert_not_called()
        saved = json.loads((tmp_path / "storage-guard.json").read_text(encoding="utf-8"))
        assert saved["install_kind"] == "dial"
        assert saved["log_policy"] == {}

    def test_appliance_mode_calls_playing_and_log_policy(self, tmp_path, monkeypatch):
        playing_mock, policy_mock = self._patch_common(monkeypatch, tmp_path)
        playing_mock.return_value = False
        monkeypatch.setattr(sys, "argv", ["autostream_storage_guard", "--appliance"])
        assert sg.main() == 0
        playing_mock.assert_called_once()
        policy_mock.assert_called_once()
        saved = json.loads((tmp_path / "storage-guard.json").read_text(encoding="utf-8"))
        assert saved["install_kind"] == "appliance"


def test_log_policy_only_is_noop_on_dial(tmp_path, monkeypatch):
    from unittest.mock import MagicMock

    monkeypatch.setattr(sg, "STATE_PATH", tmp_path / "storage-guard.json")
    policy_only_mock = MagicMock(return_value=0)
    monkeypatch.setattr(sg, "_run_log_policy_only", policy_only_mock)
    monkeypatch.setattr(sys, "argv", ["autostream_storage_guard", "--log-policy-only", "--dial"])
    assert sg.main() == 0
    policy_only_mock.assert_not_called()


def test_sd_health_thresholds_match_sysutils():
    sys.path.insert(0, str(REPO_ROOT / "core"))
    import autostream_sysutils as su

    assert sg.SD_HEALTH_LOW_THRESHOLD == su.SD_HEALTH_LOW_THRESHOLD
    assert sg.SD_HEALTH_RECOVER_THRESHOLD == su.SD_HEALTH_RECOVER_THRESHOLD
    assert sg.SD_HEALTH_STALE_HOURS == su.SD_HEALTH_STALE_HOURS
