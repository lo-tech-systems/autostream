"""dial_volume tests that need no client: the failure log's rate limit, the
fan-out helpers' shape, queue coalescing, the mute observation store and its
echo, the worker's per-event target resolution, target selection and the
optimistic readout. The sends themselves are in test_dial_volume_submit.py.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

import dial_core_focus as cf
import dial_volume as dv
from dial_mdns import PlayingTarget


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _target(ip: str = "192.168.1.10", port: int = 80, service_name: str = "") -> PlayingTarget:
    return PlayingTarget(ip=ip, port=port, name="test", dial_api=True, service_name=service_name)


def _clear_state():
    dv._fail_counts.clear()
    # Reset the readout and the mute observation store, so a test never
    # inherits state left behind by an earlier test.
    dv.observe_master_volume(None, None)
    dv.observe_mute_state(None, None)
    dv._on_readout_changed = None
    dv._mute_targets_fn = None
    dv._client_for = None


def _seed_mute_observation(service_name: str, muted: bool) -> None:
    """Seed the mute observation store as if an earlier response had already
    reported *muted* for *service_name*: the dial keeps no belief of its own,
    only what it was last told."""
    dv.observe_mute_state(service_name, muted)


# ---------------------------------------------------------------------------
# _log_volume_failure: rate limiting
# ---------------------------------------------------------------------------

class TestLogVolumeFailureRateLimit:
    def setup_method(self):
        _clear_state()

    def test_first_failure_logs_warning(self, caplog):
        import logging
        with caplog.at_level(logging.DEBUG):
            dv._log_volume_failure("1.1.1.1", "test error %s", "detail")
        warnings = [r for r in caplog.records
                    if r.levelno >= logging.WARNING and "1.1.1.1" in r.getMessage()]
        assert warnings, "First failure must log at WARNING"

    def test_second_failure_logs_debug(self, caplog):
        import logging
        dv._log_volume_failure("2.2.2.2", "err")  # 1st → WARNING
        caplog.clear()
        with caplog.at_level(logging.DEBUG):
            dv._log_volume_failure("2.2.2.2", "err")  # 2nd → DEBUG
        warnings = [r for r in caplog.records
                    if r.levelno >= logging.WARNING and "2.2.2.2" in r.getMessage()]
        debugs   = [r for r in caplog.records
                    if r.levelno == logging.DEBUG and "2.2.2.2" in r.getMessage()]
        assert not warnings, "2nd failure must not log at WARNING"
        assert debugs, "2nd failure must log at DEBUG"

    def test_warning_again_after_a_minute(self, caplog):
        import logging
        ip = "3.3.3.3"
        clock = [1000.0]
        with patch("autostream_logging.time.monotonic", lambda: clock[0]):
            dv._log_volume_failure(ip, "err")
            for _ in range(9):
                dv._log_volume_failure(ip, "err")
            caplog.clear()
            with caplog.at_level(logging.DEBUG):
                dv._log_volume_failure(ip, "err")          # 11th, same minute
                clock[0] += 61.0
                dv._log_volume_failure(ip, "err")          # a minute on
        levels = [r.levelno for r in caplog.records if ip in r.getMessage()]
        assert levels == [logging.DEBUG, logging.WARNING]

    def test_mute_failures_have_their_own_timer(self, caplog):
        import logging
        ip = "4.4.4.4"
        dv._log_volume_failure(ip, "err")
        caplog.clear()
        with caplog.at_level(logging.DEBUG):
            dv._log_mute_failure(ip, "err")
        assert [r.levelno for r in caplog.records if ip in r.getMessage()] == [logging.WARNING]

    def test_targets_have_their_own_timers(self, caplog):
        import logging
        dv._log_volume_failure("5.5.5.5", "err")
        caplog.clear()
        with caplog.at_level(logging.DEBUG):
            dv._log_volume_failure("6.6.6.6", "err")
        assert [r.levelno for r in caplog.records if "6.6.6.6" in r.getMessage()] == [logging.WARNING]


# ---------------------------------------------------------------------------
# _fan_out: concurrent dispatch
# ---------------------------------------------------------------------------

class TestFanOut:
    def setup_method(self):
        _clear_state()

    def test_sends_to_all_targets(self):
        targets = [_target("1.0.0.1"), _target("1.0.0.2"), _target("1.0.0.3")]
        sent_to = []

        def fake_send_one(target, delta, clamped):
            sent_to.append(target.ip)

        with patch.object(dv, "_send_one", side_effect=fake_send_one):
            dv._fan_out(targets, 2)

        assert sorted(sent_to) == ["1.0.0.1", "1.0.0.2", "1.0.0.3"]

    def test_returns_true_when_any_clamped(self):
        targets = [_target("1.0.0.1"), _target("1.0.0.2")]

        def fake_send_one(target, delta, clamped):
            if target.ip == "1.0.0.1":
                clamped.append(True)

        with patch.object(dv, "_send_one", side_effect=fake_send_one):
            result = dv._fan_out(targets, 5)

        assert result is True

    def test_returns_false_when_no_target_clamped(self):
        targets = [_target()]

        def fake_send_one(target, delta, clamped):
            pass

        with patch.object(dv, "_send_one", side_effect=fake_send_one):
            result = dv._fan_out(targets, 2)

        assert result is False


# ---------------------------------------------------------------------------
# Queue coalescing: one summed delta per burst, LED flash on clamp
# ---------------------------------------------------------------------------

class TestQueueCoalescing:
    def setup_method(self):
        _clear_state()

    def test_burst_coalesced_to_one_fan_out_call(self):
        """Multiple enqueue_delta calls before the worker runs should produce
        one _fan_out call with the summed delta."""
        fan_out_calls = []

        def fake_fan_out(targets, delta):
            fan_out_calls.append(delta)
            return False

        target = _target()
        done = threading.Event()

        def fake_targets():
            return [target]

        dv._targets_fn = fake_targets
        dv._led_ref    = None

        import queue as _q
        # Pre-load three deltas into a fresh queue
        fresh_queue: _q.SimpleQueue = _q.SimpleQueue()
        fresh_queue.put(2)
        fresh_queue.put(3)
        fresh_queue.put(1)

        with patch.object(dv, "_fan_out", side_effect=fake_fan_out), \
             patch.object(dv, "_queue", fresh_queue):
            # Simulate one worker iteration
            delta = dv._queue.get()
            while True:
                try:
                    delta += dv._queue.get_nowait()
                except _q.Empty:
                    break
            dv._fan_out(fake_targets(), delta)

        assert fan_out_calls == [6], f"Expected [6], got {fan_out_calls}"

    def test_led_flashed_when_clamped(self):
        """LED.flash_clamped() must be called when fan_out returns True."""
        mock_led = MagicMock()
        dv._led_ref = mock_led
        dv._targets_fn = lambda: [_target()]

        import queue as _q
        fresh_queue: _q.SimpleQueue = _q.SimpleQueue()
        fresh_queue.put(5)

        with patch.object(dv, "_fan_out", return_value=True), \
             patch.object(dv, "_queue", fresh_queue):
            delta = dv._queue.get()
            while True:
                try:
                    delta += dv._queue.get_nowait()
                except _q.Empty:
                    break
            targets = dv._targets_fn()
            clamped = dv._fan_out(targets, delta)
            if clamped and dv._led_ref:
                dv._led_ref.flash_clamped()


# ---------------------------------------------------------------------------
# enqueue_mute_all(): plain queue put, no lock, no I/O, no store echo -- the
# action is decided at dispatch, not here.
# ---------------------------------------------------------------------------

class TestEnqueueMuteAll:
    def setup_method(self):
        _clear_state()
        while True:
            try:
                dv._queue.get_nowait()
            except Exception:
                break

    def test_enqueues_one_mute_all_event(self):
        dv.enqueue_mute_all()
        assert dv._queue.get_nowait() == ("mute_all", 1)

    def test_performs_no_network_io(self):
        def boom(*a, **kw):
            raise AssertionError("enqueue_mute_all() must never touch a client")

        dv._client_for = boom
        dv.enqueue_mute_all()  # must not raise

    def test_writes_nothing_to_the_observation_store(self):
        """Unlike enqueue_mute(), there is no same-frame echo -- the fleet
        action is not known yet at enqueue time."""
        dv.observe_mute_state("svc", False)
        dv.enqueue_mute_all()
        assert dv.shown_muted("svc") is False


# ---------------------------------------------------------------------------
# enqueue_mute(): flips the caller-supplied reported state, no network I/O,
# no DialDisplay lock, no belief of its own kept anywhere in this module.
# ---------------------------------------------------------------------------

class TestEnqueueMuteAbsoluteAction:
    def setup_method(self):
        _clear_state()
        # Drain any leftover queue items from a previous test.
        while True:
            try:
                dv._queue.get_nowait()
            except Exception:
                break

    def test_reported_unmuted_flips_to_mute(self):
        new_state = dv.enqueue_mute(False)
        assert new_state is True
        assert dv._queue.get_nowait() == ("mute", True)

    def test_reported_muted_flips_to_restore(self):
        new_state = dv.enqueue_mute(True)
        assert new_state is False
        assert dv._queue.get_nowait() == ("mute", False)

    def test_enqueue_mute_performs_no_network_io(self):
        def boom(*a, **kw):
            raise AssertionError("enqueue_mute() must never touch a client")

        dv._client_for = boom
        dv.enqueue_mute(False)  # must not raise

    def test_enqueue_mute_echoes_into_the_observation_store(self):
        """The dial persists nothing, but a press must still repaint the
        glyph on the same frame -- the echo lives in the mute observation
        store (dial_volume._readout_muted), not any belief."""
        dv.observe_mute_state("svc", False)
        dv.enqueue_mute(False)
        assert dv.shown_muted("svc") is True

    def test_enqueue_mute_does_not_touch_which_service_the_store_reports_for(self):
        """The echo updates only the value, never the tracked service -- it
        applies to whichever service the store already associates with the
        reporting appliance."""
        dv.observe_mute_state("svc", False)
        dv.enqueue_mute(False)
        assert dv.shown_muted("other-svc") is False

    def test_enqueue_mute_leaves_other_services_entries_untouched(self):
        """The store is per-service: echoing the reporting appliance's flip
        must never disturb an unrelated service's own entry (e.g. one a
        recent poll or a scope-"all" fan-out already recorded)."""
        dv.observe_mute_state("svc-other", True)
        dv.observe_mute_state("svc", False)  # the most recently observed -- becomes the echo target
        dv.enqueue_mute(False)
        assert dv.shown_muted("svc") is True
        assert dv.shown_muted("svc-other") is True  # untouched


# ---------------------------------------------------------------------------
# _worker(): dispatches a mute batch item through _fan_out_mute with the
# belief carried in the queue event (mirrors TestQueueCoalescing's style of
# simulating a single worker iteration rather than driving the real
# infinite-loop thread).
# ---------------------------------------------------------------------------

class TestWorkerMuteDispatch:
    def setup_method(self):
        _clear_state()

    def test_mute_batch_item_dispatches_via_fan_out_mute(self):
        fan_out_mute_calls = []

        def fake_fan_out_mute(targets, muted):
            fan_out_mute_calls.append(muted)

        target = _target()
        dv._targets_fn = lambda: [target]

        with patch.object(dv, "_fan_out_mute", side_effect=fake_fan_out_mute):
            batch = dv._coalesce(("mute", True))
            targets = dv._targets_fn()
            for event in batch:
                if event[0] == "delta":
                    dv._fan_out(targets, event[1])
                else:
                    dv._fan_out_mute(targets, event[1])

        assert fan_out_mute_calls == [True]

    def test_mute_all_batch_item_dispatches_via_dispatch_mute_all(self):
        """The real _worker() routes a "mute_all" event to
        _dispatch_mute_all(), not _fan_out_mute() directly -- the action
        isn't known until dispatch decides it."""
        dispatch_calls = []

        def fake_dispatch_mute_all(targets):
            dispatch_calls.append(targets)

        target = _target()
        dv._targets_fn = lambda: [target]
        dv._mute_targets_fn = None

        with patch.object(dv, "_dispatch_mute_all", side_effect=fake_dispatch_mute_all):
            batch = dv._coalesce(("mute_all", 1))
            for event in batch:
                resolver = dv._mute_targets_fn or dv._targets_fn
                targets = resolver()
                if event[0] == "mute_all":
                    dv._dispatch_mute_all(targets)

        assert dispatch_calls == [[target]]


# ---------------------------------------------------------------------------
# select_volume_target(): pure single-target selection — no I/O, no lock,
# no module state. The focus rule's reporting_for and dial_main's volume-target
# resolver both call this so they can never disagree about who the
# reporting-from target is.
# ---------------------------------------------------------------------------

class TestSelectVolumeTarget:
    def test_preferred_present_is_returned_even_when_not_first(self):
        older = _target(ip="7.0.0.1", service_name="older")
        newer = _target(ip="7.0.0.2", service_name="newer")
        assert cf.select_volume_target([older, newer], "newer") is newer

    def test_preferred_absent_falls_back_to_first(self):
        older = _target(ip="7.0.0.1", service_name="older")
        newer = _target(ip="7.0.0.2", service_name="newer")
        assert cf.select_volume_target([older, newer], "vanished") is older

    def test_none_preferred_falls_back_to_first(self):
        older = _target(ip="7.0.0.1", service_name="older")
        newer = _target(ip="7.0.0.2", service_name="newer")
        assert cf.select_volume_target([older, newer], None) is older

    def test_empty_list_with_preferred_returns_none(self):
        assert cf.select_volume_target([], "anything") is None

    def test_empty_list_with_no_preferred_returns_none(self):
        assert cf.select_volume_target([], None) is None


# ---------------------------------------------------------------------------
# _worker(): per-event target resolution — a delta event resolves via
# _targets_fn(), a mute event resolves via _mute_targets_fn() (falling back
# to _targets_fn() when unset). Mirrors TestWorkerMuteDispatch's style of
# simulating a single worker iteration (see that class's docstring) rather
# than driving the real infinite-loop thread, now extended to also resolve
# per event rather than once per batch — see dial_volume._worker().
# ---------------------------------------------------------------------------

class TestWorkerTargetResolution:
    def setup_method(self):
        _clear_state()

    def _dispatch(self, batch):
        """Reproduce _worker()'s per-event resolution branch for *batch*
        without the blocking queue.get() loop, recording which resolver's
        result reached which fan-out call."""
        fan_out_calls = []
        fan_out_mute_calls = []
        mute_all_calls = []
        for event in batch:
            if event[0] == "delta":
                targets = dv._targets_fn()
                if not targets:
                    continue
                fan_out_calls.append((targets, event[1]))
            elif event[0] == "mute_all":
                resolver = dv._mute_targets_fn or dv._targets_fn
                targets = resolver()
                if not targets:
                    continue
                mute_all_calls.append(targets)
            else:
                resolver = dv._mute_targets_fn or dv._targets_fn
                targets = resolver()
                if not targets:
                    continue
                fan_out_mute_calls.append((targets, event[1]))
        return fan_out_calls, fan_out_mute_calls, mute_all_calls

    def test_delta_event_uses_targets_fn(self):
        vol_target = _target(ip="8.0.0.1", service_name="volume-target")
        mute_target = _target(ip="8.0.0.2", service_name="mute-target")
        dv._targets_fn = lambda: [vol_target]
        dv._mute_targets_fn = lambda: [mute_target]

        fan_out_calls, fan_out_mute_calls, mute_all_calls = self._dispatch([("delta", 5)])

        assert fan_out_calls == [([vol_target], 5)]
        assert fan_out_mute_calls == []
        assert mute_all_calls == []

    def test_mute_event_uses_mute_targets_fn_when_set(self):
        vol_target = _target(ip="8.0.0.1", service_name="volume-target")
        mute_target = _target(ip="8.0.0.2", service_name="mute-target")
        dv._targets_fn = lambda: [vol_target]
        dv._mute_targets_fn = lambda: [mute_target]

        fan_out_calls, fan_out_mute_calls, mute_all_calls = self._dispatch([("mute", True)])

        assert fan_out_calls == []
        assert fan_out_mute_calls == [([mute_target], True)]
        assert mute_all_calls == []

    def test_mute_event_falls_back_to_targets_fn_when_mute_targets_fn_unset(self):
        vol_target = _target(ip="8.0.0.1", service_name="volume-target")
        dv._targets_fn = lambda: [vol_target]
        dv._mute_targets_fn = None

        _, fan_out_mute_calls, _mute_all = self._dispatch([("mute", True)])

        assert fan_out_mute_calls == [([vol_target], True)]

    def test_mute_all_event_uses_mute_targets_fn(self):
        vol_target = _target(ip="8.0.0.1", service_name="volume-target")
        mute_target = _target(ip="8.0.0.2", service_name="mute-target")
        dv._targets_fn = lambda: [vol_target]
        dv._mute_targets_fn = lambda: [mute_target]

        fan_out_calls, fan_out_mute_calls, mute_all_calls = self._dispatch([("mute_all", 1)])

        assert fan_out_calls == []
        assert fan_out_mute_calls == []
        assert mute_all_calls == [[mute_target]]

    def test_empty_targets_fn_result_skips_only_the_delta_event(self):
        mute_target = _target(ip="8.0.0.2", service_name="mute-target")
        dv._targets_fn = lambda: []
        dv._mute_targets_fn = lambda: [mute_target]

        fan_out_calls, fan_out_mute_calls, _mute_all = self._dispatch([("delta", 5), ("mute", True)])

        assert fan_out_calls == []
        assert fan_out_mute_calls == [([mute_target], True)]

    def test_empty_mute_targets_fn_result_skips_only_the_mute_event(self):
        vol_target = _target(ip="8.0.0.1", service_name="volume-target")
        dv._targets_fn = lambda: [vol_target]
        dv._mute_targets_fn = lambda: []

        fan_out_calls, fan_out_mute_calls, _mute_all = self._dispatch([("delta", 5), ("mute", True)])

        assert fan_out_calls == [([vol_target], 5)]
        assert fan_out_mute_calls == []


# ---------------------------------------------------------------------------
# Optimistic volume readout: observe_master_volume()/shown_volume()/
# enqueue_delta()'s pending-offset nudge.
# ---------------------------------------------------------------------------

class TestVolumeReadout:
    def setup_method(self):
        dv.observe_master_volume(None, None)
        # Drain any leftover queue items so enqueue_delta() below doesn't
        # leave the shared module queue non-empty for a later test.
        while True:
            try:
                dv._queue.get_nowait()
            except Exception:
                break

    def test_shown_volume_none_before_any_observation(self):
        assert dv.shown_volume("a") is None

    def test_shown_volume_none_for_none_service_name(self):
        dv.observe_master_volume("a", 50)
        assert dv.shown_volume(None) is None

    def test_enqueued_delta_after_observation_shows_optimistic_total(self):
        dv.observe_master_volume("a", 50)
        dv.enqueue_delta(2)
        assert dv.shown_volume("a") == 52

    def test_pending_clamps_at_100(self):
        dv.observe_master_volume("a", 95)
        dv.enqueue_delta(50)
        assert dv.shown_volume("a") == 100

    def test_pending_clamps_at_0(self):
        dv.observe_master_volume("a", 5)
        dv.enqueue_delta(-50)
        assert dv.shown_volume("a") == 0

    def test_new_observation_resets_pending(self):
        dv.observe_master_volume("a", 50)
        dv.enqueue_delta(10)
        assert dv.shown_volume("a") == 60
        dv.observe_master_volume("a", 40)  # supersedes the +10 pending above
        assert dv.shown_volume("a") == 40

    def test_shown_volume_for_a_different_target_is_none(self):
        """A stale number from another appliance must never be shown."""
        dv.observe_master_volume("a", 50)
        assert dv.shown_volume("b") is None

    def test_observation_of_none_volume_shows_none(self):
        """volume=None means the target has no selected outputs."""
        dv.observe_master_volume("a", 50)
        dv.observe_master_volume("a", None)
        assert dv.shown_volume("a") is None

    def test_observation_of_none_service_clears_the_readout_entirely(self):
        dv.observe_master_volume("a", 50)
        dv.observe_master_volume(None, None)
        assert dv.shown_volume("a") is None


