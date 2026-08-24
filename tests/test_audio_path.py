"""Audio Path quality-selection tests.

Covers the Python/webui half:
  - autostream_config.normalize_audio_path() clamp/demote matrix
  - autostream_config.parse_config() audio_path wiring (high_perf plumbing)
  - autostream_player_service: --src / resample_quality composition,
    sync_monitor_args_for_audio_path() restart-skip-when-unchanged, and
    push_resample_quality() capability/tolerance behaviour
  - autostream_core: startup fill-missing / demote-only / never-promote /
    second-boot-no-write write-back
  - autostream_webui_api: server-side "max" rejection on small hardware and
    the live change-flow wiring
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_config as cfgmod
import autostream_player_service as svc
import autostream_players as ap


# ---------------------------------------------------------------------------
# autostream_config.normalize_audio_path()
# ---------------------------------------------------------------------------

class TestNormalizeAudioPath:
    @pytest.mark.parametrize("value", ["max", "balanced", "fast"])
    def test_valid_values_pass_through_on_high_perf(self, value):
        assert cfgmod.normalize_audio_path(value, high_perf=True) == value

    def test_max_demotes_to_balanced_on_low_perf(self):
        assert cfgmod.normalize_audio_path("max", high_perf=False) == "balanced"

    @pytest.mark.parametrize("high_perf", [True, False])
    def test_balanced_and_fast_unaffected_by_hardware(self, high_perf):
        assert cfgmod.normalize_audio_path("balanced", high_perf=high_perf) == "balanced"
        assert cfgmod.normalize_audio_path("fast", high_perf=high_perf) == "fast"

    @pytest.mark.parametrize("value", ["bogus", "", None, "MAX_QUALITY", 123])
    @pytest.mark.parametrize("high_perf", [True, False])
    def test_invalid_values_clamp_to_balanced(self, value, high_perf):
        assert cfgmod.normalize_audio_path(value, high_perf=high_perf) == "balanced"

    def test_case_insensitive(self):
        assert cfgmod.normalize_audio_path("MAX", high_perf=True) == "max"
        assert cfgmod.normalize_audio_path("Balanced", high_perf=False) == "balanced"


class TestParseConfigAudioPath:
    def test_absent_key_defaults_balanced_regardless_of_hardware(self):
        result_low = cfgmod.parse_config({}, high_perf=False)
        result_high = cfgmod.parse_config({}, high_perf=True)
        # absent -> "balanced" is the *raw default*; parse_config does not
        # fill in the hardware default itself (that is autostream_core's
        # startup write-back job) -- it only normalizes what's present.
        assert result_low.general.audio_path == "balanced"
        assert result_high.general.audio_path == "balanced"

    def test_present_max_demoted_when_high_perf_false(self):
        data = {"general": {"audio_path": "max"}}
        result = cfgmod.parse_config(data, high_perf=False)
        assert result.general.audio_path == "balanced"

    def test_present_max_kept_when_high_perf_true(self):
        data = {"general": {"audio_path": "max"}}
        result = cfgmod.parse_config(data, high_perf=True)
        assert result.general.audio_path == "max"

    def test_high_perf_none_computed_lazily(self):
        data = {"general": {"audio_path": "max"}}
        with patch("autostream_rpi.is_high_performance_pi", return_value=False):
            result = cfgmod.parse_config(data)
        assert result.general.audio_path == "balanced"

        with patch("autostream_rpi.is_high_performance_pi", return_value=True):
            result = cfgmod.parse_config(data)
        assert result.general.audio_path == "max"


# ---------------------------------------------------------------------------
# autostream_player_service: args composition
# ---------------------------------------------------------------------------

class TestMonitorArgsForFormat:
    @pytest.mark.parametrize("audio_path,tier", [
        ("max", "best"),
        ("balanced", "medium"),
        ("fast", "fast"),
        ("bogus", "medium"),
        ("", "medium"),
    ])
    def test_src_tier_mapping_native(self, audio_path, tier):
        assert svc._monitor_args_for_format("native", audio_path) == f"--src {tier}"

    @pytest.mark.parametrize("audio_path,tier", [
        ("max", "best"),
        ("balanced", "medium"),
        ("fast", "fast"),
    ])
    def test_src_tier_mapping_compatible(self, audio_path, tier):
        assert (
            svc._monitor_args_for_format("compatible", audio_path)
            == f"--compatible --src {tier}"
        )

    def test_default_audio_path_is_balanced(self):
        assert svc._monitor_args_for_format("native") == "--src medium"


class TestResampleQualityForAudioPath:
    @pytest.mark.parametrize("audio_path,expected", [
        ("max", "high"),
        ("balanced", "high"),
        ("fast", "standard"),
        ("bogus", "high"),
    ])
    def test_mapping(self, audio_path, expected):
        assert svc._resample_quality_for_audio_path(audio_path) == expected


# ---------------------------------------------------------------------------
# sync_monitor_args_for_audio_path()
# ---------------------------------------------------------------------------

class TestSyncMonitorArgsForAudioPath:
    def setup_method(self):
        svc._DETECTION_CACHE.clear()

    def _resolved(self, desired_format, *, confident=True):
        backend = MagicMock()
        backend.required_monitor_format.return_value = desired_format
        return svc.ResolvedBackend(
            backend_id="owntone-mini", backend=backend, detection_confident=confident,
        )

    def test_empty_base_url_is_noop(self):
        assert svc.sync_monitor_args_for_audio_path("", "balanced") is False

    def test_unconfident_backend_is_noop(self):
        with patch.object(svc, "resolve_backend", return_value=self._resolved("native", confident=False)), \
             patch.object(svc, "_write_monitor_args_env_file") as write_mock:
            result = svc.sync_monitor_args_for_audio_path("http://localhost:3689", "max")
        assert result is False
        write_mock.assert_not_called()

    def test_writes_and_restarts_when_args_changed(self, tmp_path):
        target = tmp_path / "monitor_args.env"
        target.write_text("AUTOSTREAM_MONITOR_ARGS=--src medium\n", encoding="utf-8")
        with patch.object(svc, "MONITOR_ARGS_ENV_PATH", str(target)), \
             patch.object(svc, "resolve_backend", return_value=self._resolved("native")), \
             patch.object(svc, "_restart_monitor_async") as restart_mock:
            result = svc.sync_monitor_args_for_audio_path("http://localhost:3689", "max")
        assert result is True
        assert target.read_text(encoding="utf-8") == "AUTOSTREAM_MONITOR_ARGS=--src best\n"
        restart_mock.assert_called_once()

    def test_skips_restart_when_args_unchanged(self, tmp_path):
        target = tmp_path / "monitor_args.env"
        target.write_text("AUTOSTREAM_MONITOR_ARGS=--src medium\n", encoding="utf-8")
        with patch.object(svc, "MONITOR_ARGS_ENV_PATH", str(target)), \
             patch.object(svc, "resolve_backend", return_value=self._resolved("native")), \
             patch.object(svc, "_restart_monitor_async") as restart_mock, \
             patch.object(svc, "_write_monitor_args_env_file") as write_mock:
            result = svc.sync_monitor_args_for_audio_path("http://localhost:3689", "balanced")
        assert result is False
        write_mock.assert_not_called()
        restart_mock.assert_not_called()

    def test_compatible_format_composes_flag_too(self, tmp_path):
        target = tmp_path / "monitor_args.env"
        target.write_text("AUTOSTREAM_MONITOR_ARGS=--compatible --src medium\n", encoding="utf-8")
        with patch.object(svc, "MONITOR_ARGS_ENV_PATH", str(target)), \
             patch.object(svc, "resolve_backend", return_value=self._resolved("compatible")), \
             patch.object(svc, "_restart_monitor_async"):
            result = svc.sync_monitor_args_for_audio_path("http://localhost:3689", "fast")
        assert result is True
        assert target.read_text(encoding="utf-8") == "AUTOSTREAM_MONITOR_ARGS=--compatible --src fast\n"

    def test_unknown_desired_format_is_noop(self):
        backend = MagicMock()
        backend.required_monitor_format.return_value = None
        resolved = svc.ResolvedBackend(backend_id="owntone", backend=backend, detection_confident=True)
        with patch.object(svc, "resolve_backend", return_value=resolved), \
             patch.object(svc, "_write_monitor_args_env_file") as write_mock:
            result = svc.sync_monitor_args_for_audio_path("http://localhost:3689", "max")
        assert result is False
        write_mock.assert_not_called()


# ---------------------------------------------------------------------------
# push_resample_quality()
# ---------------------------------------------------------------------------

class TestPushResampleQuality:
    def _save_result(self, *, ok=True, unsupported=False, error_code=""):
        r = MagicMock()
        r.ok = ok
        r.unsupported = unsupported
        r.error = "" if ok else (error_code or "save failed")
        r.error_code = "" if ok else (error_code or "save_failed")
        r.message = r.error or r.error_code
        return r

    def test_pushes_high_for_max_and_balanced(self):
        with patch.object(svc, "save_setting", return_value=self._save_result(ok=True)) as save_mock:
            svc.push_resample_quality("http://localhost:3689", "max")
            svc.push_resample_quality("http://localhost:3689", "balanced")
        calls = [c.args for c in save_mock.call_args_list]
        assert calls[0] == ("http://localhost:3689", ap.SETTING_RESAMPLE_QUALITY, "high")
        assert calls[1] == ("http://localhost:3689", ap.SETTING_RESAMPLE_QUALITY, "high")

    def test_pushes_standard_for_fast(self):
        with patch.object(svc, "save_setting", return_value=self._save_result(ok=True)) as save_mock:
            svc.push_resample_quality("http://localhost:3689", "fast")
        assert save_mock.call_args.args == (
            "http://localhost:3689", ap.SETTING_RESAMPLE_QUALITY, "standard",
        )

    def test_stock_owntone_unsupported_is_tolerated_no_op(self, caplog):
        with patch.object(svc, "save_setting", return_value=self._save_result(ok=False, unsupported=True)):
            result = svc.push_resample_quality("http://localhost:3689", "max")
        assert result.unsupported is True

    def test_old_mini_rejection_is_tolerated_not_raised(self):
        with patch.object(svc, "save_setting", return_value=self._save_result(ok=False, unsupported=True, error_code="unsupported")):
            result = svc.push_resample_quality("http://localhost:3689", "max")
        assert result.ok is False
        assert result.unsupported is True

    def test_transient_failure_does_not_raise(self):
        with patch.object(svc, "save_setting", return_value=self._save_result(ok=False, error_code="request_failed")):
            result = svc.push_resample_quality("http://localhost:3689", "max")
        assert result.ok is False
        assert result.unsupported is False


# ---------------------------------------------------------------------------
# autostream_core: startup audio_path write-back
# ---------------------------------------------------------------------------

def _make_settings_store(tmp_path, initial: dict):
    from autostream_settings import SettingsStore

    config_path = str(tmp_path / "config.json")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(initial, f)
    writer = MagicMock()
    store = SettingsStore(config_path, _save_interval_seconds=9999, _writer=writer)
    return store, writer


class TestReconcileAudioPathStartup:
    def test_fill_missing_writes_hardware_default_high_perf(self, tmp_path, caplog):
        import autostream_core as core
        store, writer = _make_settings_store(tmp_path, {})
        try:
            with patch("autostream_core.is_high_performance_pi", return_value=True), \
                 caplog.at_level("INFO"):
                core._reconcile_audio_path_startup(store)
            assert store.raw_snapshot()["general"]["audio_path"] == "max"
            assert writer.call_count == 1
            assert any("hardware default" in r.message for r in caplog.records)
        finally:
            store.close(save=False)

    def test_fill_missing_writes_hardware_default_low_perf(self, tmp_path):
        import autostream_core as core
        store, writer = _make_settings_store(tmp_path, {})
        try:
            with patch("autostream_core.is_high_performance_pi", return_value=False):
                core._reconcile_audio_path_startup(store)
            assert store.raw_snapshot()["general"]["audio_path"] == "balanced"
            assert writer.call_count == 1
        finally:
            store.close(save=False)

    def test_demote_only_writes_once_and_warns(self, tmp_path, caplog):
        import autostream_core as core
        store, writer = _make_settings_store(tmp_path, {"general": {"audio_path": "max"}})
        try:
            with patch("autostream_core.is_high_performance_pi", return_value=False), \
                 caplog.at_level("WARNING"):
                core._reconcile_audio_path_startup(store)
            assert store.raw_snapshot()["general"]["audio_path"] == "balanced"
            assert writer.call_count == 1
            assert any("demoted" in r.message for r in caplog.records)
        finally:
            store.close(save=False)

    def test_present_balanced_on_high_perf_never_modified(self, tmp_path):
        import autostream_core as core
        store, writer = _make_settings_store(tmp_path, {"general": {"audio_path": "balanced"}})
        try:
            with patch("autostream_core.is_high_performance_pi", return_value=True):
                core._reconcile_audio_path_startup(store)
            assert store.raw_snapshot()["general"]["audio_path"] == "balanced"
            assert writer.call_count == 0
        finally:
            store.close(save=False)

    def test_present_max_on_high_perf_never_modified(self, tmp_path):
        import autostream_core as core
        store, writer = _make_settings_store(tmp_path, {"general": {"audio_path": "max"}})
        try:
            with patch("autostream_core.is_high_performance_pi", return_value=True):
                core._reconcile_audio_path_startup(store)
            assert store.raw_snapshot()["general"]["audio_path"] == "max"
            assert writer.call_count == 0
        finally:
            store.close(save=False)

    def test_second_boot_after_demotion_writes_nothing(self, tmp_path):
        import autostream_core as core
        store, writer = _make_settings_store(tmp_path, {"general": {"audio_path": "max"}})
        try:
            with patch("autostream_core.is_high_performance_pi", return_value=False):
                core._reconcile_audio_path_startup(store)
                assert writer.call_count == 1
                # Second pass (e.g. a retry lap of the startup loop, or a
                # subsequent boot re-reading the now-demoted persisted value).
                core._reconcile_audio_path_startup(store)
                assert writer.call_count == 1
        finally:
            store.close(save=False)

    def test_second_boot_after_fill_missing_writes_nothing(self, tmp_path):
        import autostream_core as core
        store, writer = _make_settings_store(tmp_path, {})
        try:
            with patch("autostream_core.is_high_performance_pi", return_value=True):
                core._reconcile_audio_path_startup(store)
                assert writer.call_count == 1
                core._reconcile_audio_path_startup(store)
                assert writer.call_count == 1
        finally:
            store.close(save=False)


# ---------------------------------------------------------------------------
# autostream_core: _fresh_audio_path() -- fresh settings-store read for the
# reconnect resync (never a disk read, never a cached snapshot fallback)
# ---------------------------------------------------------------------------

class TestFreshAudioPath:
    def test_returns_current_store_snapshot_value(self, tmp_path):
        import autostream_core as core
        store, _writer = _make_settings_store(tmp_path, {"general": {"audio_path": "fast"}})
        try:
            assert core._fresh_audio_path(store) == "fast"
        finally:
            store.close(save=False)

    def test_reflects_in_memory_update_without_a_disk_flush(self, tmp_path):
        """A store mutation is visible to _fresh_audio_path() immediately,
        before the background save cycle (here disabled via a very long
        interval) has written anything to disk."""
        import autostream_core as core
        store, writer = _make_settings_store(tmp_path, {"general": {"audio_path": "balanced"}})
        try:
            store.update(
                lambda r: r.setdefault("general", {}).update({"audio_path": "fast"})
            )
            assert writer.call_count == 0
            assert core._fresh_audio_path(store) == "fast"
        finally:
            store.close(save=False)

    def test_settings_none_returns_none(self):
        import autostream_core as core
        assert core._fresh_audio_path(None) is None

    def test_snapshot_raising_returns_none_not_raise(self):
        import autostream_core as core
        store = MagicMock()
        store.snapshot.side_effect = RuntimeError("store unavailable")
        assert core._fresh_audio_path(store) is None


# ---------------------------------------------------------------------------
# autostream_core: _resync_monitor_daemon() audio_path freshness + skip-on-
# unknown semantics
# ---------------------------------------------------------------------------

class TestResyncAudioPathFreshness:
    def _mock_client(self):
        c = MagicMock()
        c.set_fifo.return_value = True
        c.set_log_level.return_value = True
        c.set_repeat_enabled.return_value = True
        return c

    def test_none_audio_path_skips_backend_sync_but_still_reconciles_format(self, caplog):
        """With audio_path unresolved (None), reconcile_monitor_format() is
        still called (format enforcement is snapshot-free and must not be
        skipped) but _sync_audio_path_backend() is not -- pushing a derived
        resample_quality/tier from an unknown source value would be a
        guess."""
        import autostream_core as core

        client = self._mock_client()
        status_dict = {"output_format": "native"}
        client.get_status.return_value = status_dict
        with patch("autostream_core.reconcile_fifo_with_backend") as rf, \
             patch("autostream_core.reconcile_monitor_format") as monfmt, \
             patch("autostream_core.reconcile_pipe_format_with_backend") as fmt, \
             patch("autostream_core._sync_audio_path_backend") as sync_backend, \
             patch("autostream_core.apply_input_gain", return_value=True), \
             patch("autostream_core.apply_input_eq", return_value=True), \
             patch("autostream_core._apply_output_eq_config", return_value=True), \
             caplog.at_level("WARNING"):
            rf.return_value = MagicMock(ok=True, message="")
            monfmt.return_value = MagicMock(ok=True, error="", error_code="")
            fmt.return_value = MagicMock(ok=True, error="", error_code="")
            ok = core._resync_monitor_daemon(
                client, [], "/tmp/test.fifo", "http://localhost:3689",
                MagicMock(), audio_path=None,
            )
        assert ok is True
        monfmt.assert_called_once_with(
            "http://localhost:3689", status_dict, timeout=3.0, audio_path=None,
        )
        sync_backend.assert_not_called()
        assert any(
            r.levelname == "WARNING" and "audio_path" in r.message
            for r in caplog.records
        )

    def test_race_replay_fresh_store_read_leaves_matching_env_untouched(self, tmp_path):
        """Replays the reconnect race: a stale cfg-shaped snapshot holds
        "balanced" but is never consulted -- the resync is wired to
        audio_path derived from a fresh store read (here "fast", matching
        what is already persisted in the env file), so the tier owner's own
        idempotence check finds a match and neither rewrites the env file
        nor requests a restart."""
        import autostream_core as core

        store, _writer = _make_settings_store(tmp_path, {"general": {"audio_path": "fast"}})
        stale_cfg_audio_path = "balanced"  # what a pre-change loop snapshot would hold; unused
        assert stale_cfg_audio_path != store.snapshot().general.audio_path

        env_path = tmp_path / "monitor_args.env"
        env_path.write_text("AUTOSTREAM_MONITOR_ARGS=--src fast\n", encoding="utf-8")

        client = self._mock_client()
        client.get_status.return_value = {"output_format": "native"}
        backend = MagicMock()
        backend.required_monitor_format.return_value = "native"
        resolved = svc.ResolvedBackend(
            backend_id="owntone-mini", backend=backend, detection_confident=True,
        )

        try:
            with patch.object(svc, "MONITOR_ARGS_ENV_PATH", str(env_path)), \
                 patch.object(svc, "resolve_backend", return_value=resolved), \
                 patch.object(svc, "_restart_monitor_async") as restart_mock, \
                 patch("autostream_core.reconcile_fifo_with_backend") as rf, \
                 patch("autostream_core.reconcile_monitor_format") as monfmt, \
                 patch("autostream_core.reconcile_pipe_format_with_backend") as fmt, \
                 patch("autostream_core.push_resample_quality"), \
                 patch("autostream_core.apply_input_gain", return_value=True), \
                 patch("autostream_core.apply_input_eq", return_value=True), \
                 patch("autostream_core._apply_output_eq_config", return_value=True):
                rf.return_value = MagicMock(ok=True, message="")
                monfmt.return_value = MagicMock(ok=True, error="", error_code="")
                fmt.return_value = MagicMock(ok=True, error="", error_code="")
                ok = core._resync_monitor_daemon(
                    client, [], "/tmp/test.fifo", "http://localhost:3689",
                    MagicMock(), audio_path=core._fresh_audio_path(store),
                )
            assert ok is True
            assert env_path.read_text(encoding="utf-8") == "AUTOSTREAM_MONITOR_ARGS=--src fast\n"
            restart_mock.assert_not_called()
        finally:
            store.close(save=False)

    def test_store_updated_disk_stale_env_matches_store_stays_unchanged(self, tmp_path):
        """The decisive freshness case. The settings store has already been
        updated to "fast" but the on-disk json is still the pre-change
        "balanced" (background dirty-save has not run yet -- the writer
        below is never invoked). The env file already carries the fast
        tier. The resync must take audio_path from the store, not from
        disk: a disk-read implementation would return "balanced" here (the
        read succeeds; the bytes are merely stale) and clobber the env
        file, reproducing the exact failure this fixes."""
        import autostream_core as core

        store, writer = _make_settings_store(tmp_path, {"general": {"audio_path": "balanced"}})
        store.update(
            lambda r: r.setdefault("general", {}).update({"audio_path": "fast"})
        )
        assert writer.call_count == 0  # disk genuinely never touched by this update

        env_path = tmp_path / "monitor_args.env"
        env_path.write_text("AUTOSTREAM_MONITOR_ARGS=--src fast\n", encoding="utf-8")

        client = self._mock_client()
        client.get_status.return_value = {"output_format": "native"}
        backend = MagicMock()
        backend.required_monitor_format.return_value = "native"
        resolved = svc.ResolvedBackend(
            backend_id="owntone-mini", backend=backend, detection_confident=True,
        )

        try:
            with patch.object(svc, "MONITOR_ARGS_ENV_PATH", str(env_path)), \
                 patch.object(svc, "resolve_backend", return_value=resolved), \
                 patch.object(svc, "_restart_monitor_async") as restart_mock, \
                 patch("autostream_core.reconcile_fifo_with_backend") as rf, \
                 patch("autostream_core.reconcile_monitor_format") as monfmt, \
                 patch("autostream_core.reconcile_pipe_format_with_backend") as fmt, \
                 patch("autostream_core.push_resample_quality"), \
                 patch("autostream_core.apply_input_gain", return_value=True), \
                 patch("autostream_core.apply_input_eq", return_value=True), \
                 patch("autostream_core._apply_output_eq_config", return_value=True):
                rf.return_value = MagicMock(ok=True, message="")
                monfmt.return_value = MagicMock(ok=True, error="", error_code="")
                fmt.return_value = MagicMock(ok=True, error="", error_code="")
                ok = core._resync_monitor_daemon(
                    client, [], "/tmp/test.fifo", "http://localhost:3689",
                    MagicMock(), audio_path=core._fresh_audio_path(store),
                )
            assert ok is True
            assert env_path.read_text(encoding="utf-8") == "AUTOSTREAM_MONITOR_ARGS=--src fast\n"
            restart_mock.assert_not_called()
        finally:
            store.close(save=False)

    def test_skip_then_converge(self, tmp_path, caplog):
        """Store unavailable on one pass: env untouched, skip logged at
        WARNING. A later pass with the store available behaves normally
        (tier owner rewrites/no-ops correctly against fresh data)."""
        import autostream_core as core

        env_path = tmp_path / "monitor_args.env"
        env_path.write_text("AUTOSTREAM_MONITOR_ARGS=--src fast\n", encoding="utf-8")

        client = self._mock_client()
        client.get_status.return_value = {"output_format": "native"}
        backend = MagicMock()
        backend.required_monitor_format.return_value = "native"
        resolved = svc.ResolvedBackend(
            backend_id="owntone-mini", backend=backend, detection_confident=True,
        )

        with patch.object(svc, "MONITOR_ARGS_ENV_PATH", str(env_path)), \
             patch.object(svc, "resolve_backend", return_value=resolved), \
             patch.object(svc, "_restart_monitor_async") as restart_mock, \
             patch("autostream_core.reconcile_fifo_with_backend") as rf, \
             patch("autostream_core.reconcile_monitor_format") as monfmt, \
             patch("autostream_core.reconcile_pipe_format_with_backend") as fmt, \
             patch("autostream_core.push_resample_quality"), \
             patch("autostream_core.apply_input_gain", return_value=True), \
             patch("autostream_core.apply_input_eq", return_value=True), \
             patch("autostream_core._apply_output_eq_config", return_value=True), \
             caplog.at_level("WARNING"):
            rf.return_value = MagicMock(ok=True, message="")
            monfmt.return_value = MagicMock(ok=True, error="", error_code="")
            fmt.return_value = MagicMock(ok=True, error="", error_code="")

            # Pass 1: store unavailable.
            ok = core._resync_monitor_daemon(
                client, [], "/tmp/test.fifo", "http://localhost:3689",
                MagicMock(), audio_path=core._fresh_audio_path(None),
            )
            assert ok is True
            assert env_path.read_text(encoding="utf-8") == "AUTOSTREAM_MONITOR_ARGS=--src fast\n"
            restart_mock.assert_not_called()
            assert any(
                r.levelname == "WARNING" and "audio_path" in r.message
                for r in caplog.records
            )

            # Pass 2: store available, same value already persisted -> the
            # tier owner's idempotence check still finds a match.
            store, _writer = _make_settings_store(tmp_path, {"general": {"audio_path": "fast"}})
            try:
                ok = core._resync_monitor_daemon(
                    client, [], "/tmp/test.fifo", "http://localhost:3689",
                    MagicMock(), audio_path=core._fresh_audio_path(store),
                )
            finally:
                store.close(save=False)
            assert ok is True
            assert env_path.read_text(encoding="utf-8") == "AUTOSTREAM_MONITOR_ARGS=--src fast\n"
            restart_mock.assert_not_called()


# ---------------------------------------------------------------------------
# autostream_webui_api: server-side validation + live change flow
# ---------------------------------------------------------------------------

class TestValidateAudioPath:
    def test_accepts_balanced_and_fast_regardless_of_hardware(self):
        import autostream_webui_api as api
        with patch("autostream_webui_api.is_high_performance_pi", return_value=False):
            assert api._validate_audio_path("balanced") == "balanced"
            assert api._validate_audio_path("fast") == "fast"

    def test_accepts_max_on_high_perf_hardware(self):
        import autostream_webui_api as api
        with patch("autostream_webui_api.is_high_performance_pi", return_value=True):
            assert api._validate_audio_path("max") == "max"

    def test_rejects_max_on_small_hardware(self):
        import autostream_webui_api as api
        with patch("autostream_webui_api.is_high_performance_pi", return_value=False):
            with pytest.raises(ValueError):
                api._validate_audio_path("max")

    def test_rejects_unknown_value(self):
        import autostream_webui_api as api
        with pytest.raises(ValueError):
            api._validate_audio_path("ultra")

    def test_rejects_non_string(self):
        import autostream_webui_api as api
        with pytest.raises(ValueError):
            api._validate_audio_path(123)


class TestLiveAudioPath:
    def _make_state(self, tmp_path, initial=None):
        from autostream_settings import SettingsStore
        config_path = str(tmp_path / "config.json")
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(initial or {"owntone": {"base_url": "http://localhost:3689"}}, f)
        store = SettingsStore(config_path, _save_interval_seconds=9999, _writer=MagicMock())
        state = MagicMock()
        state.settings = store
        return state, store

    def test_pushes_resample_quality_and_syncs_args(self, tmp_path):
        import autostream_webui_api as api
        state, store = self._make_state(tmp_path)
        try:
            with patch("autostream_webui_api.push_resample_quality") as push_mock, \
                 patch("autostream_webui_api.sync_monitor_args_for_audio_path") as sync_mock:
                result = api._live_audio_path(state, "fast")
            assert result is True
            push_mock.assert_called_once_with("http://localhost:3689", "fast", timeout=3.0)
            sync_mock.assert_called_once_with("http://localhost:3689", "fast", timeout=3.0)
        finally:
            store.close(save=False)

    def test_tolerant_of_push_failure(self, tmp_path):
        """Both callees are individually tolerant (never raise); the live_fn
        must still report success once the setting itself is safely
        persisted (which happens before live_fn runs)."""
        import autostream_webui_api as api
        state, store = self._make_state(tmp_path)
        try:
            with patch("autostream_webui_api.push_resample_quality", return_value=MagicMock()), \
                 patch("autostream_webui_api.sync_monitor_args_for_audio_path", return_value=False):
                result = api._live_audio_path(state, "max")
            assert result is True
        finally:
            store.close(save=False)

    def test_field_registered_with_correct_validator_and_live_fn(self):
        import autostream_webui_api as api
        assert "general.audio_path" in api._SETTINGS_FIELDS
        section, key, validator, live_fn = api._SETTINGS_FIELDS["general.audio_path"]
        assert section == "general"
        assert key == "audio_path"
        assert validator is api._validate_audio_path
        assert live_fn is api._live_audio_path
