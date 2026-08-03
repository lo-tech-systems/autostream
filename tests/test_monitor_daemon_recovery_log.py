"""tests/test_monitor_daemon_recovery_log.py

Coverage for the "first success after failure" recovery-WARNING wired
around the coordinator poll loop's autostream_monitor daemon connection
(run_autostream(), the get_status()-failure branch and the reconnect
branch immediately above it). Both branches share one _RecoveryLog
instance -- the daemon connection is a single observable resource from an
operator's point of view, regardless of which call raised.

Driving run_autostream() itself (rather than extracting the loop body)
mirrors the existing harness style in test_wp2_settings_ownership.py's
TestRunAutostreamStartupFormatReconcile: everything not under test is
mocked out, monitors is kept empty so the per-monitor sections of the poll
loop are no-ops, and stop_flag.is_set() is call-counted to let a fixed
number of get_status() calls happen before the loop exits cleanly (no
exception needed to terminate it).
"""
from __future__ import annotations

import contextlib
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_core as core


def _minimal_cfg(tmp_path: Path) -> Path:
    cfg = tmp_path / "autostream.json"
    cfg.write_text(json.dumps({
        "general": {"log_level": "info", "log_file": "/tmp/autostream.log"},
        "owntone": {"base_url": "http://localhost:3689"},
        "webui": {"dark_mode": False, "advertise_appliance": True},
    }), encoding="utf-8")
    return cfg


def _run_autostream_with_get_status_sequence(tmp_path, get_status_results, is_set_threshold):
    """Drive run_autostream() through one startup pass and len(get_status_results) - 1
    poll-loop iterations (the first get_status_results entry is the
    startup-phase format probe; the rest feed successive poll iterations).

    client.is_connected() is kept True throughout so the reconnect branch
    (which shares the same recovery-log instance as the get_status()
    branch, via the same fail()/ok() pattern) is never entered -- exercising
    the get_status() call site alone is sufficient to prove the wiring.

    is_set_threshold: stop_flag.is_set() call-count after which it starts
    returning True (calibrated per test to let the sequence above play out
    then exit the poll loop cleanly).
    """
    cfg = _minimal_cfg(tmp_path)
    from autostream_settings import SettingsStore
    store = SettingsStore(str(cfg), _save_interval_seconds=9999)

    call_count = [0]

    def _is_set():
        call_count[0] += 1
        return call_count[0] > is_set_threshold

    mock_client = MagicMock()
    mock_client.is_connected.return_value = True
    mock_client.connect.return_value = True
    mock_client.set_fifo.return_value = True
    mock_client.get_status.side_effect = get_status_results

    mock_session_tracker_cls = MagicMock()
    mock_session_tracker_cls.return_value.update.return_value = (None, None, None, None)

    with contextlib.ExitStack() as stack:
        sf = stack.enter_context(patch.object(core, "stop_flag"))
        # reload_flag is a module-level Event that other tests may leave set;
        # a set flag would make the poll loop break into a config reload on
        # its first iteration instead of consuming the scripted get_status
        # sequence. Replace it so this harness is order-independent.
        rf = stack.enter_context(patch.object(core, "reload_flag"))
        rf.is_set.return_value = False
        stack.enter_context(patch.object(core, "unconfigured", return_value=False))
        stack.enter_context(patch.object(core, "MonitorClient", return_value=mock_client))
        stack.enter_context(patch.object(core, "_install_signal_handlers"))
        stack.enter_context(patch.object(core, "get_install_state", return_value={}))
        stack.enter_context(patch.object(core, "_ensure_playback_tracker"))
        stack.enter_context(patch.object(core, "_start_output_usage_poller"))
        stack.enter_context(patch("autostream_log_policy.apply_startup_log_level"))
        stack.enter_context(patch.object(core, "setup_logging"))
        stack.enter_context(patch.object(core, "_reconcile_audio_path_startup"))
        stack.enter_context(patch.object(
            core, "reconcile_fifo_with_backend",
            return_value=MagicMock(ok=True, message="")))
        stack.enter_context(patch.object(
            core, "reconcile_monitor_format",
            return_value=MagicMock(ok=True, error="", error_code="")))
        stack.enter_context(patch.object(
            core, "reconcile_pipe_format_with_backend",
            return_value=MagicMock(ok=True, error="", error_code="")))
        stack.enter_context(patch.object(
            core, "ensure_pipe_source_ready",
            return_value=MagicMock(ok=True, message="")))
        stack.enter_context(patch.object(core, "_sync_audio_path_backend"))
        stack.enter_context(patch.object(core, "_configure_startup_monitors", return_value=[]))
        stack.enter_context(patch.object(core, "_build_track_id_service", return_value=None))
        stack.enter_context(patch.object(core, "_start_playing_reconciliation"))
        stack.enter_context(patch.object(core, "_SessionTracker", mock_session_tracker_cls))
        stack.enter_context(patch.object(core, "_dispatch_session_event"))
        stack.enter_context(patch.object(core, "_sync_playing_announcement"))
        stack.enter_context(patch.object(core, "_playback_tracker", None))
        stack.enter_context(patch.object(core, "_cleanup_discovery"))
        stack.enter_context(patch.object(core.time, "sleep"))

        sf.is_set.side_effect = _is_set
        core.run_autostream(str(cfg), settings=store)

    store.close(save=False)


class TestMonitorDaemonRecoveryLog:
    def test_get_status_recovery_logs_one_warning(self, tmp_path, caplog):
        with caplog.at_level("WARNING", logger="root"):
            _run_autostream_with_get_status_sequence(
                tmp_path,
                get_status_results=[
                    {"output_rate": 44100, "output_bits": 16},  # startup format probe
                    None,                                        # iteration 1: fails
                    {"inputs": [], "monitor_build": "x", "log_level": "info"},  # iteration 2: recovers
                ],
                is_set_threshold=5,
            )

        recovered = [r for r in caplog.records if "recovered after" in r.getMessage()]
        assert len(recovered) == 1
        assert "autostream_monitor connection" in recovered[0].getMessage()
        assert "recovered after 1 failure(s)" in recovered[0].getMessage()

    def test_get_status_still_failing_logs_no_recovery(self, tmp_path, caplog):
        """A run that never gets a successful get_status() must not emit a
        recovery WARNING -- only the underlying failure warnings."""
        with caplog.at_level("WARNING", logger="root"):
            _run_autostream_with_get_status_sequence(
                tmp_path,
                get_status_results=[
                    {"output_rate": 44100, "output_bits": 16},
                    None,
                    None,
                ],
                is_set_threshold=4,
            )

        recovered = [r for r in caplog.records if "recovered after" in r.getMessage()]
        assert recovered == []
