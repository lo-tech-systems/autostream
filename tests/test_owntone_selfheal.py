"""tests/test_owntone_selfheal.py

Self-healing tests for two OwnTone failure modes.

  1. OwnTone-restart reconcile (_OwntoneReconcileTracker /
     _reconcile_owntone_outputs_if_wiped): a still-active session that finds
     OwnTone reporting zero selected outputs for several consecutive checks
     re-arms the existing _maybe_retry_owntone retry machinery, UNLESS a
     recent user-initiated output action (note_user_output_action()) makes
     the zero state look intentional.

  2. OwnTone-hang watchdog (_OwntoneHangWatchdog /
     _maybe_run_owntone_hang_watchdog): a stalled FIFO write
     (status["fifo"]["stalled_seconds"]) during an active session, with
     OwnTone still reachable, requests a rate-limited supervised restart via
     run_admin_cmd(["restart-owntone"]); an absent "fifo" block (old daemon
     binary) disarms it silently.

  3. Composition: stall -> watchdog fires once (rate-limited thereafter) ->
     OwnTone comes back with zero outputs -> reconcile re-enables. The
     user-deselect edge does not spuriously trigger reconcile.

The C++ daemon side (the "fifo" status block) is mocked throughout -- these
tests exercise the Python contract against synthetic status/outputs
sequences, not a real daemon or OwnTone backend.
"""
from __future__ import annotations

import os
import sys
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

import autostream_core as core
from autostream_core import (
    AudioMonitor,
    _maybe_run_owntone_hang_watchdog,
    _OwntoneHangWatchdog,
    _OwntoneReconcileTracker,
    _reconcile_owntone_outputs_if_wiped,
    get_owntone_selfheal_state,
    note_user_output_action,
)


BASE_URL = "http://localhost:3689"


def _make_monitor(**overrides) -> AudioMonitor:
    defaults = dict(
        input_index=1,
        input_device="hw:0,0",
        silence_threshold_dbfs=-50.0,
        silence_seconds=5,
        fifo_path="/tmp/test.fifo",
        owntone_base_url=BASE_URL,
        owntone_output_name="Test Speaker",
        owntone_volume_percent=50,
    )
    defaults.update(overrides)
    with patch("autostream_core.PersistentNowPlayingCache") as mock_cache_cls, \
         patch("autostream_core.get_shared_metadata_publisher") as mock_get_pub:
        mock_cache_cls.return_value.get_manual_hint.return_value = None
        mock_get_pub.side_effect = lambda path: MagicMock()
        mon = AudioMonitor(**defaults)
    return mon


def _outputs(*selected_flags) -> list:
    return [SimpleNamespace(id=str(i), selected=bool(sel), name=f"out{i}")
            for i, sel in enumerate(selected_flags)]


@pytest.fixture(autouse=True)
def _reset_selfheal_state_and_user_action():
    """Isolate module-level caches between tests (same discipline as other
    coordinator-state tests in this suite, e.g. _set_repeat_status)."""
    note_user_output_action(0.0)
    core._set_owntone_selfheal_state(
        reconcile_fired_count=0,
        reconcile_last_fired_at=0.0,
        watchdog_armed=False,
        watchdog_restart_count=0,
        watchdog_last_restart_at=0.0,
    )
    yield
    note_user_output_action(0.0)


# ── _OwntoneReconcileTracker: pure update() diff behaviour ──────────────────

class TestOwntoneReconcileTrackerPure:
    def test_no_session_never_counts(self):
        tracker = _OwntoneReconcileTracker()
        for _ in range(10):
            assert tracker.update(
                session_active=False, selected_count=0, now=100.0,
                last_user_action_at=0.0,
            ) is False

    def test_unreachable_outputs_api_never_counts(self):
        tracker = _OwntoneReconcileTracker()
        for _ in range(10):
            assert tracker.update(
                session_active=True, selected_count=None, now=100.0,
                last_user_action_at=0.0,
            ) is False

    def test_nonzero_selected_never_fires(self):
        tracker = _OwntoneReconcileTracker()
        for _ in range(10):
            assert tracker.update(
                session_active=True, selected_count=1, now=100.0,
                last_user_action_at=0.0,
            ) is False

    def test_fires_after_threshold_consecutive_zero_polls(self):
        tracker = _OwntoneReconcileTracker()
        now = 1000.0
        results = [
            tracker.update(
                session_active=True, selected_count=0, now=now + i,
                last_user_action_at=0.0,
            )
            for i in range(tracker.ZERO_POLL_THRESHOLD)
        ]
        assert results[:-1] == [False] * (tracker.ZERO_POLL_THRESHOLD - 1)
        assert results[-1] is True

    def test_below_threshold_does_not_fire(self):
        tracker = _OwntoneReconcileTracker()
        now = 1000.0
        for i in range(tracker.ZERO_POLL_THRESHOLD - 1):
            assert tracker.update(
                session_active=True, selected_count=0, now=now + i,
                last_user_action_at=0.0,
            ) is False

    def test_latched_until_nonzero_seen_again(self):
        """Once fired, does not fire again on further zero polls until a
        nonzero observation re-arms it (avoids re-firing every cycle once
        the retry machinery has already been re-armed)."""
        tracker = _OwntoneReconcileTracker()
        now = 1000.0
        for i in range(tracker.ZERO_POLL_THRESHOLD):
            fired = tracker.update(
                session_active=True, selected_count=0, now=now + i,
                last_user_action_at=0.0,
            )
        assert fired is True
        # More zero polls: must not fire again.
        for i in range(10):
            assert tracker.update(
                session_active=True, selected_count=0, now=now + 100 + i,
                last_user_action_at=0.0,
            ) is False

    def test_rearms_after_nonzero_then_fires_again_on_new_zero_streak(self):
        tracker = _OwntoneReconcileTracker()
        now = 1000.0
        for i in range(tracker.ZERO_POLL_THRESHOLD):
            tracker.update(
                session_active=True, selected_count=0, now=now + i,
                last_user_action_at=0.0,
            )
        # Outputs come back.
        assert tracker.update(
            session_active=True, selected_count=1, now=now + 50,
            last_user_action_at=0.0,
        ) is False
        # Goes to zero again -> should be able to fire once more.
        results = [
            tracker.update(
                session_active=True, selected_count=0, now=now + 60 + i,
                last_user_action_at=0.0,
            )
            for i in range(tracker.ZERO_POLL_THRESHOLD)
        ]
        assert results[-1] is True

    def test_recent_user_action_suppresses_fire(self):
        """User-deselect edge: a recent note_user_output_action() timestamp
        suppresses what would otherwise be a fire."""
        tracker = _OwntoneReconcileTracker()
        now = 1000.0
        last_fired = None
        for i in range(tracker.ZERO_POLL_THRESHOLD + 5):
            last_fired = tracker.update(
                session_active=True, selected_count=0, now=now + i,
                last_user_action_at=now - 1.0,  # 1s ago: well within grace
            )
        assert last_fired is False

    def test_fires_once_user_action_ages_past_grace_window(self):
        tracker = _OwntoneReconcileTracker()
        now = 1000.0
        user_action_at = now - 1.0
        for i in range(tracker.ZERO_POLL_THRESHOLD):
            assert tracker.update(
                session_active=True, selected_count=0, now=now + i,
                last_user_action_at=user_action_at,
            ) is False
        # Time passes well beyond the grace window; streak continues.
        later = now + tracker.USER_ACTION_GRACE_SECONDS + 10
        assert tracker.update(
            session_active=True, selected_count=0, now=later,
            last_user_action_at=user_action_at,
        ) is True

    def test_reset_clears_streak(self):
        tracker = _OwntoneReconcileTracker()
        now = 1000.0
        tracker.update(session_active=True, selected_count=0, now=now, last_user_action_at=0.0)
        tracker.reset()
        for i in range(tracker.ZERO_POLL_THRESHOLD - 1):
            assert tracker.update(
                session_active=True, selected_count=0, now=now + 1 + i,
                last_user_action_at=0.0,
            ) is False


# ── _reconcile_owntone_outputs_if_wiped: poll-loop wiring ───────────────────

class TestReconcileWiring:
    def test_fires_and_resets_monitor_retry_state(self):
        mon = _make_monitor()
        mon._owntone_enabled_ok = True
        mon._owntone_last_attempt = 12345.0
        tracker = _OwntoneReconcileTracker()
        note_user_output_action(0.0)

        with patch.object(mon, "_get_owntone_outputs", return_value=_outputs(False, False)):
            fired_any = False
            now = 1000.0
            for i in range(tracker.ZERO_POLL_THRESHOLD + 1):
                before = mon._owntone_enabled_ok
                _reconcile_owntone_outputs_if_wiped(tracker, mon, True, now + i)
                if mon._owntone_enabled_ok is False and before is True:
                    fired_any = True

        assert fired_any is True
        assert mon._owntone_enabled_ok is False
        assert mon._owntone_last_attempt == 0.0
        state = get_owntone_selfheal_state()
        assert state["reconcile_fired_count"] == 1

    def test_no_session_does_not_touch_monitor_state(self):
        mon = _make_monitor()
        mon._owntone_enabled_ok = True
        tracker = _OwntoneReconcileTracker()
        with patch.object(mon, "_get_owntone_outputs", return_value=_outputs(False)):
            for i in range(10):
                _reconcile_owntone_outputs_if_wiped(tracker, None, False, 1000.0 + i)
        assert mon._owntone_enabled_ok is True

    def test_nonzero_selected_outputs_never_fires(self):
        mon = _make_monitor()
        mon._owntone_enabled_ok = True
        tracker = _OwntoneReconcileTracker()
        with patch.object(mon, "_get_owntone_outputs", return_value=_outputs(True, False)):
            for i in range(10):
                _reconcile_owntone_outputs_if_wiped(tracker, mon, True, 1000.0 + i)
        assert mon._owntone_enabled_ok is True

    def test_user_deselect_edge_does_not_spuriously_fire(self):
        """A user manually deselecting every output mid-session must not
        trigger reconcile within the grace window."""
        mon = _make_monitor()
        mon._owntone_enabled_ok = True
        tracker = _OwntoneReconcileTracker()
        note_user_output_action()  # simulate the user's POST /api/output just landing

        with patch.object(mon, "_get_owntone_outputs", return_value=_outputs(False, False)):
            now = time.time()
            for i in range(tracker.ZERO_POLL_THRESHOLD + 5):
                _reconcile_owntone_outputs_if_wiped(tracker, mon, True, now + i)

        assert mon._owntone_enabled_ok is True
        state = get_owntone_selfheal_state()
        assert state["reconcile_fired_count"] == 0


# ── _OwntoneHangWatchdog: pure decision logic ───────────────────────────────

class TestOwntoneHangWatchdogPure:
    def test_no_session_never_fires(self):
        wd = _OwntoneHangWatchdog()
        assert wd.maybe_fire(
            session_active=False, fifo_status={"stalled_seconds": 999.0},
            now=100.0, owntone_reachable_fn=lambda: True,
        ) is False

    def test_absent_fifo_block_disarmed_silently(self):
        wd = _OwntoneHangWatchdog()
        assert wd.maybe_fire(
            session_active=True, fifo_status=None,
            now=100.0, owntone_reachable_fn=lambda: True,
        ) is False
        assert wd.restart_count == 0

    def test_non_dict_fifo_block_disarmed(self):
        wd = _OwntoneHangWatchdog()
        assert wd.maybe_fire(
            session_active=True, fifo_status="not-a-dict",
            now=100.0, owntone_reachable_fn=lambda: True,
        ) is False

    def test_below_threshold_does_not_fire(self):
        wd = _OwntoneHangWatchdog()
        assert wd.maybe_fire(
            session_active=True,
            fifo_status={"stalled_seconds": wd.STALL_THRESHOLD_SECONDS - 1},
            now=100.0, owntone_reachable_fn=lambda: True,
        ) is False

    def test_above_threshold_and_reachable_fires(self):
        wd = _OwntoneHangWatchdog()
        assert wd.maybe_fire(
            session_active=True,
            fifo_status={"stalled_seconds": wd.STALL_THRESHOLD_SECONDS + 1},
            now=100.0, owntone_reachable_fn=lambda: True,
        ) is True
        assert wd.restart_count == 1

    def test_unreachable_owntone_does_not_fire(self):
        """OwnTone-down is handled by existing machinery, not this watchdog."""
        wd = _OwntoneHangWatchdog()
        assert wd.maybe_fire(
            session_active=True,
            fifo_status={"stalled_seconds": wd.STALL_THRESHOLD_SECONDS + 1},
            now=100.0, owntone_reachable_fn=lambda: False,
        ) is False
        assert wd.restart_count == 0

    def test_rate_limited_after_first_fire(self):
        wd = _OwntoneHangWatchdog()
        stalled = {"stalled_seconds": wd.STALL_THRESHOLD_SECONDS + 1}
        assert wd.maybe_fire(
            session_active=True, fifo_status=stalled, now=100.0,
            owntone_reachable_fn=lambda: True,
        ) is True
        # Still stalled a minute later: rate-limited.
        assert wd.maybe_fire(
            session_active=True, fifo_status=stalled, now=160.0,
            owntone_reachable_fn=lambda: True,
        ) is False
        # Past the 10-minute rate limit: can fire again.
        assert wd.maybe_fire(
            session_active=True, fifo_status=stalled,
            now=100.0 + wd.RESTART_RATE_LIMIT_SECONDS + 1,
            owntone_reachable_fn=lambda: True,
        ) is True
        assert wd.restart_count == 2

    def test_reachability_probe_only_called_when_stall_exceeds_threshold(self):
        """Cost discipline: the (non-zero-cost) reachability probe must not
        be evaluated on every poll, only once the stall threshold is
        already exceeded."""
        wd = _OwntoneHangWatchdog()
        probe = MagicMock(return_value=True)
        wd.maybe_fire(
            session_active=True,
            fifo_status={"stalled_seconds": 1.0},
            now=100.0, owntone_reachable_fn=probe,
        )
        probe.assert_not_called()


class TestMaybeRunOwntoneHangWatchdogWiring:
    def test_fires_restart_command_via_run_admin_cmd(self):
        wd = _OwntoneHangWatchdog()
        status = {"fifo": {"stalled_seconds": wd.STALL_THRESHOLD_SECONDS + 5}}
        fake_result = MagicMock(returncode=0, stderr="")
        with patch("autostream_core.list_outputs") as mock_list, \
             patch("autostream_core.run_admin_cmd", return_value=fake_result) as mock_admin, \
             patch("autostream_core.threading.Thread") as mock_thread_cls:
            mock_list.return_value = SimpleNamespace(ok=True)
            # Run the worker function synchronously instead of on a thread,
            # so the assertion below can observe run_admin_cmd's call.
            def _run_now(target=None, name=None, daemon=None):
                target()
                return MagicMock()
            mock_thread_cls.side_effect = _run_now

            _maybe_run_owntone_hang_watchdog(wd, status, True, BASE_URL, 1000.0)

        mock_admin.assert_called_once_with(["restart-owntone"], timeout=20.0)
        state = get_owntone_selfheal_state()
        assert state["watchdog_restart_count"] == 1
        assert state["watchdog_armed"] is True

    def test_absent_fifo_block_no_restart_and_reports_disarmed(self):
        wd = _OwntoneHangWatchdog()
        with patch("autostream_core.run_admin_cmd") as mock_admin:
            _maybe_run_owntone_hang_watchdog(wd, {}, True, BASE_URL, 1000.0)
        mock_admin.assert_not_called()
        state = get_owntone_selfheal_state()
        assert state["watchdog_armed"] is False

    def test_no_session_no_restart(self):
        wd = _OwntoneHangWatchdog()
        status = {"fifo": {"stalled_seconds": wd.STALL_THRESHOLD_SECONDS + 5}}
        with patch("autostream_core.run_admin_cmd") as mock_admin:
            _maybe_run_owntone_hang_watchdog(wd, status, False, BASE_URL, 1000.0)
        mock_admin.assert_not_called()


# ── Composition: stall -> watchdog -> owntone back with zero outputs -> reconcile ──

class TestSelfHealComposition:
    def test_full_incident_sequence(self):
        """Synthetic status sequence modelling a full self-heal incident end-to-end:

        1. Session active, FIFO stalled beyond threshold, OwnTone reachable
           -> watchdog fires exactly once (and is rate-limited thereafter).
        2. OwnTone "comes back" (simulated: fifo stall clears) but reports
           zero selected outputs for several consecutive checks -> reconcile
           re-arms the monitor's retry machinery.
        3. Rate limiting: a second stall shortly after does NOT fire the
           watchdog again.
        """
        mon = _make_monitor()
        mon._owntone_enabled_ok = True
        watchdog = _OwntoneHangWatchdog()
        reconcile = _OwntoneReconcileTracker()
        note_user_output_action(0.0)

        base = 1000.0
        restart_calls = []

        def _fake_run_admin_cmd(args, timeout=None):
            restart_calls.append(args)
            return MagicMock(returncode=0, stderr="")

        # Phase 1: stalled FIFO, OwnTone reachable.
        stalled_status = {"fifo": {"stalled_seconds": watchdog.STALL_THRESHOLD_SECONDS + 5}}
        with patch("autostream_core.list_outputs", return_value=SimpleNamespace(ok=True)), \
             patch("autostream_core.run_admin_cmd", side_effect=_fake_run_admin_cmd), \
             patch("autostream_core.threading.Thread") as mock_thread_cls:
            def _run_now(target=None, name=None, daemon=None):
                target()
                return MagicMock()
            mock_thread_cls.side_effect = _run_now

            _maybe_run_owntone_hang_watchdog(watchdog, stalled_status, True, BASE_URL, base)
            # Immediately stalled again: rate-limited, must not fire twice.
            _maybe_run_owntone_hang_watchdog(watchdog, stalled_status, True, BASE_URL, base + 1)

        assert len(restart_calls) == 1
        assert restart_calls[0] == ["restart-owntone"]

        # Phase 2: OwnTone is back but reports zero selected outputs for a
        # few consecutive checks (the post-restart wipe).
        with patch.object(mon, "_get_owntone_outputs", return_value=_outputs(False, False)):
            for i in range(reconcile.ZERO_POLL_THRESHOLD):
                _reconcile_owntone_outputs_if_wiped(reconcile, mon, True, base + 10 + i)

        assert mon._owntone_enabled_ok is False
        assert mon._owntone_last_attempt == 0.0

        state = get_owntone_selfheal_state()
        assert state["watchdog_restart_count"] == 1
        assert state["reconcile_fired_count"] == 1

    def test_user_deselect_edge_does_not_trigger_reconcile_in_composition(self):
        mon = _make_monitor()
        mon._owntone_enabled_ok = True
        reconcile = _OwntoneReconcileTracker()

        now = time.time()
        note_user_output_action(now)  # user just deselected everything

        with patch.object(mon, "_get_owntone_outputs", return_value=_outputs(False, False)):
            for i in range(reconcile.ZERO_POLL_THRESHOLD + 3):
                _reconcile_owntone_outputs_if_wiped(reconcile, mon, True, now + i)

        assert mon._owntone_enabled_ok is True
        assert get_owntone_selfheal_state()["reconcile_fired_count"] == 0


# ── /api/status passthrough ─────────────────────────────────────────────────

class TestStatusPassthrough:
    def test_owntone_selfheal_block_present_in_status_json(self):
        from autostream_webui_api import send_status_json

        core._set_owntone_selfheal_state(
            reconcile_fired_count=2, reconcile_last_fired_at=42.0,
            watchdog_armed=True, watchdog_restart_count=1,
            watchdog_last_restart_at=99.0,
        )
        handler = MagicMock()
        handler.wfile = MagicMock()
        sent = {}

        def _wfile_write(data):
            import json
            sent["body"] = json.loads(data)

        handler.wfile.write.side_effect = _wfile_write

        with patch("autostream_webui_api.get_monitor_levels_dbfs", return_value=[]):
            send_status_json(handler)

        assert sent["body"]["owntone_selfheal"] == {
            "reconcile_fired_count": 2,
            "reconcile_last_fired_at": 42.0,
            "watchdog_armed": True,
            "watchdog_restart_count": 1,
            "watchdog_last_restart_at": 99.0,
        }
