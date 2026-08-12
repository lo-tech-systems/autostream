"""Tests for track-identification scheduling in AudioMonitor.

Covers: disabled/waiting/analysing/identified/not_found/error state machine,
outcome-driven scheduling (match→refresh+jitter, no_match→retry_seconds,
error→30s, rate_limit→120s, upstream_rejection→300s), process-wide admission
gate, worker token generation guard, capture-stop reset, now-playing
publication, and protected-deadline preservation.
"""
from __future__ import annotations

import sys
import time
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_core as core
from autostream_core import AudioMonitor, MonitorClient
from track_id.models import (
    STATE_DISABLED,
    STATE_WAITING,
    STATE_ANALYSING,
    STATE_IDENTIFIED,
    STATE_NOT_FOUND,
    STATE_ERROR,
    TrackIdentificationResult,
    TrackIDRateLimitedError,
    TrackIDUpstreamRejectionError,
    disabled_snapshot,
    waiting_snapshot,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_monitor(**overrides) -> AudioMonitor:
    defaults = dict(
        input_index=1,
        input_device="hw:1,0",
        silence_threshold_dbfs=-50.0,
        silence_seconds=5,
        fifo_path="/tmp/test_ti.fifo",
        owntone_base_url="",
        owntone_output_name="",
        owntone_volume_percent=50,
    )
    defaults.update(overrides)
    with patch("autostream_core.PersistentNowPlayingCache") as mock_cache_cls, \
         patch("autostream_core.get_shared_metadata_publisher") as mock_get_pub:
        mock_cache_cls.return_value.get_manual_hint.return_value = None
        # Fresh MagicMock per call: see test_audio_monitor_coordination.py's
        # _make_monitor for why this doesn't just use a shared return_value.
        mock_get_pub.side_effect = lambda path: MagicMock()
        mon = AudioMonitor(**defaults)
    return mon


def _active_monitor(**overrides) -> AudioMonitor:
    """Monitor with is_capturing=True, is_silent=False."""
    mon = _make_monitor(**overrides)
    mon.is_capturing = True
    mon.is_silent = False
    return mon


_DEFAULT_RATE = 16000
_DEFAULT_PCM = b"\x00" * (_DEFAULT_RATE * 2 * 15)


def _make_service(
    matched: bool = True,
    analysis_lead_in: int = 5,
    snapshot: int = 15,
    retry: int = 30,
    refresh: int = 60,
    provider_id: str = "test_provider",
    raise_exc=None,
) -> MagicMock:
    svc = MagicMock()
    svc.provider_id = provider_id
    svc.analysis_lead_in_seconds = analysis_lead_in
    svc.snapshot_seconds = snapshot
    svc.retry_seconds = retry
    svc.refresh_seconds = refresh
    if raise_exc is not None:
        svc.identify.side_effect = raise_exc
    else:
        svc.identify.return_value = TrackIdentificationResult(
            matched=matched,
            title="Test Title" if matched else "",
            artist="Test Artist" if matched else "",
            album="Test Album" if matched else "",
            provider=provider_id,
            confidence=0.9 if matched else None,
        )
    return svc


def _make_client(
    pcm: bytes = _DEFAULT_PCM,
    rate: int = _DEFAULT_RATE,
) -> MagicMock:
    c = MagicMock(spec=MonitorClient)
    c.get_id_snapshot.return_value = (pcm, rate)
    return c


def _run_worker_sync(
    mon: AudioMonitor,
    pcm: bytes = None,
    rate: int = _DEFAULT_RATE,
    token: object = None,
    dispatch_gen: int = None,
) -> object:
    """Acquire the gate, install the token, call _ti_worker synchronously, return token."""
    if pcm is None:
        pcm = _DEFAULT_PCM
    if token is None:
        token = object()
    if dispatch_gen is None:
        dispatch_gen = mon._ti_generation
    core._track_id_request_gate.acquire()
    mon._ti_inflight = True
    mon._ti_inflight_token = token
    mon._ti_worker(bytes(pcm), rate, token, dispatch_gen)
    return token


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_track_id_service():
    old = core._track_id_service
    core._track_id_service = None
    yield
    core._track_id_service = old


# ---------------------------------------------------------------------------
# Initial snapshot state
# ---------------------------------------------------------------------------

class TestInitialState:

    def test_initial_snapshot_is_disabled_without_service(self):
        core._track_id_service = None
        mon = _make_monitor()
        assert mon._ti_snapshot.state == STATE_DISABLED
        assert mon._ti_snapshot.enabled is False

    def test_apply_service_sets_waiting(self):
        mon = _make_monitor()
        svc = _make_service()
        mon._apply_track_id_service(svc)
        assert mon._ti_snapshot.state == STATE_WAITING
        assert mon._ti_snapshot.enabled is True

    def test_apply_none_service_sets_disabled(self):
        mon = _make_monitor()
        mon._apply_track_id_service(None)
        assert mon._ti_snapshot.state == STATE_DISABLED

    def test_apply_service_defers_first_attempt_by_lead_in_plus_snapshot(self):
        """First attempt = analysis_lead_in_seconds + snapshot_seconds when capturing."""
        mon = _active_monitor()
        svc = _make_service(analysis_lead_in=5, snapshot=15)
        before = time.time()
        mon._apply_track_id_service(svc)
        assert mon._ti_next_attempt >= before + 19  # 5+15 minus small epsilon

    def test_apply_service_not_capturing_leaves_next_attempt_zero(self):
        """When not capturing, _apply_track_id_service defers until capture starts."""
        mon = _make_monitor()  # is_capturing=False
        svc = _make_service(analysis_lead_in=5, snapshot=15)
        mon._apply_track_id_service(svc)
        assert mon._ti_next_attempt == 0.0

    def test_apply_none_service_does_not_set_future_next_attempt(self):
        mon = _make_monitor()
        mon._apply_track_id_service(None)
        assert mon._ti_next_attempt == 0.0

    def test_capture_start_defers_first_attempt_by_lead_in_plus_snapshot(self):
        """On capture start, first attempt = analysis_lead_in + snapshot into the future."""
        svc = _make_service(analysis_lead_in=5, snapshot=15)
        mon = _active_monitor()
        core._track_id_service = svc
        before = time.time()
        mon._on_capture_started()
        assert mon._ti_next_attempt >= before + 19

    def test_capture_start_without_service_does_not_set_future_next_attempt(self):
        core._track_id_service = None
        mon = _active_monitor()
        mon._on_capture_started()
        assert mon._ti_next_attempt == 0.0

    def test_capture_start_sets_waiting_snapshot_when_service_present(self):
        svc = _make_service()
        mon = _active_monitor()
        core._track_id_service = svc
        mon._on_capture_started()
        assert mon._ti_snapshot.state == STATE_WAITING

    def test_capture_start_sets_disabled_snapshot_when_no_service(self):
        core._track_id_service = None
        mon = _active_monitor()
        mon._on_capture_started()
        assert mon._ti_snapshot.state == STATE_DISABLED

    def test_capture_start_clears_inflight_token(self):
        svc = _make_service()
        mon = _active_monitor()
        core._track_id_service = svc
        mon._ti_inflight = True
        mon._ti_inflight_token = object()
        mon._on_capture_started()
        assert mon._ti_inflight is False
        assert mon._ti_inflight_token is None


# ---------------------------------------------------------------------------
# Disabled config never calls get_id_snapshot
# ---------------------------------------------------------------------------

class TestDisabledConfig:

    def test_disabled_service_never_calls_get_id_snapshot(self):
        core._track_id_service = None
        mon = _active_monitor()
        client = _make_client()
        mon.maybe_trigger_track_identification(client, time.time())
        client.get_id_snapshot.assert_not_called()


# ---------------------------------------------------------------------------
# Waiting state when enabled but no audio / not capturing
# ---------------------------------------------------------------------------

class TestWaitingState:

    def test_no_trigger_when_silent(self):
        svc = _make_service()
        mon = _active_monitor()
        mon.is_silent = True
        client = _make_client()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon.maybe_trigger_track_identification(client, time.time())
        client.get_id_snapshot.assert_not_called()

    def test_no_trigger_when_not_capturing(self):
        svc = _make_service()
        mon = _make_monitor()
        mon.is_capturing = False
        mon.is_silent = False
        client = _make_client()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon.maybe_trigger_track_identification(client, time.time())
        client.get_id_snapshot.assert_not_called()


# ---------------------------------------------------------------------------
# Dispatch scheduling
# ---------------------------------------------------------------------------

class TestDispatchScheduling:

    def test_trigger_after_deadline_elapsed(self):
        svc = _make_service()
        mon = _active_monitor()
        client = _make_client()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon._ti_next_attempt = 1.0  # past deadline → trigger immediately

        mon.maybe_trigger_track_identification(client, time.time())
        client.get_id_snapshot.assert_called_once()

    def test_no_trigger_before_deadline_elapsed(self):
        svc = _make_service()
        mon = _active_monitor()
        client = _make_client()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon._ti_next_attempt = time.time() + 1000.0  # far in the future

        mon.maybe_trigger_track_identification(client, time.time())
        client.get_id_snapshot.assert_not_called()

    def test_dispatch_sets_analysing_snapshot(self):
        svc = _make_service()
        mon = _active_monitor()
        client = _make_client()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)

        # Prevent actual thread from running — just check the synchronous part.
        dispatched_threads = []

        def fake_start(self_thread):
            dispatched_threads.append(self_thread)

        mon._ti_next_attempt = 1.0  # past deadline → trigger immediately
        with patch.object(threading.Thread, "start", fake_start):
            mon.maybe_trigger_track_identification(client, time.time())

        assert mon._ti_snapshot.state == STATE_ANALYSING
        assert len(dispatched_threads) == 1

        # Clean up — release gate that maybe_trigger acquired but thread never released.
        core._track_id_request_gate.release()

    def test_skips_worker_when_pcm_too_short(self):
        from track_id.service import MIN_PCM_DURATION_SECONDS
        svc = _make_service()
        mon = _active_monitor()
        short_pcm = b"\x00" * int(_DEFAULT_RATE * 2 * (MIN_PCM_DURATION_SECONDS - 1))
        client = MagicMock()
        client.get_id_snapshot.return_value = (short_pcm, _DEFAULT_RATE)
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon._ti_next_attempt = 0.0

        mon.maybe_trigger_track_identification(client, time.time())
        assert mon._ti_inflight is False

    def test_generation_change_during_snapshot_aborts_dispatch(self):
        """If the generation advances while get_id_snapshot() runs, dispatch is aborted."""
        svc = _make_service()
        mon = _active_monitor()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon._ti_next_attempt = 1.0  # past deadline

        def snapshot_and_bump(*_args, **_kw):
            mon._ti_generation += 1
            return (_DEFAULT_PCM, _DEFAULT_RATE)

        client = MagicMock()
        client.get_id_snapshot.side_effect = snapshot_and_bump

        mon.maybe_trigger_track_identification(client, time.time())

        assert not core._track_id_request_gate.locked()
        assert mon._ti_inflight is False

    def test_generation_change_during_snapshot_no_audio_aborts_without_scheduling(self):
        """Generation race with None snapshot must not schedule a retry on the old service."""
        svc = _make_service()
        mon = _active_monitor()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon._ti_next_attempt = 1.0

        def snapshot_and_bump(*_args, **_kw):
            mon._ti_generation += 1
            return None  # empty result — as if capture stopped mid-call

        client = MagicMock()
        client.get_id_snapshot.side_effect = snapshot_and_bump

        before_deadline = mon._ti_next_attempt
        mon.maybe_trigger_track_identification(client, time.time())

        assert not core._track_id_request_gate.locked()
        assert mon._ti_inflight is False
        # Deadline must not have been overwritten with a stale retry from the old service.
        assert mon._ti_next_attempt == before_deadline

    def test_generation_change_during_snapshot_short_audio_aborts_without_scheduling(self):
        """Generation race with short snapshot must not schedule a retry on the old service."""
        from track_id.service import MIN_PCM_DURATION_SECONDS
        svc = _make_service()
        mon = _active_monitor()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon._ti_next_attempt = 1.0

        short_pcm = b"\x00" * int(_DEFAULT_RATE * 2 * (MIN_PCM_DURATION_SECONDS - 1))

        def snapshot_and_bump(*_args, **_kw):
            mon._ti_generation += 1
            return (short_pcm, _DEFAULT_RATE)

        client = MagicMock()
        client.get_id_snapshot.side_effect = snapshot_and_bump

        before_deadline = mon._ti_next_attempt
        mon.maybe_trigger_track_identification(client, time.time())

        assert not core._track_id_request_gate.locked()
        assert mon._ti_inflight is False
        assert mon._ti_next_attempt == before_deadline

    def test_service_change_during_snapshot_aborts_dispatch(self):
        """If the service changes while get_id_snapshot() runs, dispatch is aborted."""
        svc = _make_service()
        mon = _active_monitor()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon._ti_next_attempt = 1.0

        def snapshot_and_swap(*_args, **_kw):
            core._track_id_service = _make_service()
            return (_DEFAULT_PCM, _DEFAULT_RATE)

        client = MagicMock()
        client.get_id_snapshot.side_effect = snapshot_and_swap

        mon.maybe_trigger_track_identification(client, time.time())

        assert not core._track_id_request_gate.locked()
        assert mon._ti_inflight is False

    def test_service_change_during_snapshot_no_audio_aborts_without_scheduling(self):
        """Service race with None snapshot must not schedule a retry on the replaced service."""
        svc = _make_service()
        mon = _active_monitor()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon._ti_next_attempt = 1.0

        def snapshot_and_swap(*_args, **_kw):
            core._track_id_service = _make_service()
            return None

        client = MagicMock()
        client.get_id_snapshot.side_effect = snapshot_and_swap

        before_deadline = mon._ti_next_attempt
        mon.maybe_trigger_track_identification(client, time.time())

        assert not core._track_id_request_gate.locked()
        assert mon._ti_inflight is False
        assert mon._ti_next_attempt == before_deadline

    def test_thread_start_failure_releases_gate(self):
        """If Thread.start() raises, the gate is released and inflight is cleared."""
        svc = _make_service()
        mon = _active_monitor()
        client = _make_client()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon._ti_next_attempt = 1.0

        with patch.object(threading.Thread, "start", side_effect=RuntimeError("OS thread limit")):
            mon.maybe_trigger_track_identification(client, time.time())

        # Gate must be released and inflight cleared despite the exception.
        assert not core._track_id_request_gate.locked()
        assert mon._ti_inflight is False
        assert mon._ti_inflight_token is None

    def test_apply_service_blocks_while_ti_state_lock_held(self):
        """_apply_track_id_service must block while _ti_state_lock is held by dispatch."""
        mon = _make_monitor()
        apply_completed = threading.Event()

        def run_apply():
            mon._apply_track_id_service(None)
            apply_completed.set()

        mon._ti_state_lock.acquire()
        t = threading.Thread(target=run_apply, daemon=True)
        t.start()

        # Give the thread time to start and attempt the lock.
        t.join(timeout=0.1)
        assert not apply_completed.is_set(), (
            "_apply_track_id_service must not proceed while _ti_state_lock is held"
        )

        mon._ti_state_lock.release()
        apply_completed.wait(timeout=2.0)
        assert apply_completed.is_set()

    def test_apply_service_after_dispatch_publishes_disabled_not_analysing(self):
        """If identification is disabled after dispatch sets STATE_ANALYSING, the
        final snapshot must be STATE_DISABLED — the UI must not be stuck in analysing."""
        from track_id.models import STATE_ANALYSING, STATE_DISABLED
        svc = _make_service()
        mon = _active_monitor()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon._ti_next_attempt = 1.0

        # Suppress the actual thread so maybe_trigger completes synchronously.
        with patch.object(threading.Thread, "start"):
            mon.maybe_trigger_track_identification(_make_client(), time.time())

        # Release the gate the dispatch acquired (no real worker to release it).
        if core._track_id_request_gate.locked():
            core._track_id_request_gate.release()

        assert mon._ti_snapshot.state == STATE_ANALYSING  # dispatch set this

        # Web handler disables identification after dispatch completed.
        core._track_id_service = None
        mon._apply_track_id_service(None)

        assert mon._ti_snapshot.state != STATE_ANALYSING, (
            "UI must not be stuck in analysing after identification is disabled"
        )


# ---------------------------------------------------------------------------
# In-flight guard
# ---------------------------------------------------------------------------

class TestInflightGuard:

    def test_inflight_prevents_duplicate_worker(self):
        svc = _make_service()
        mon = _active_monitor()
        client = _make_client()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon._ti_inflight = True
        mon._ti_next_attempt = 0.0

        mon.maybe_trigger_track_identification(client, time.time())
        client.get_id_snapshot.assert_not_called()

    def test_admission_gate_prevents_concurrent_workers(self):
        """If the gate is held by another input, retry delay is set to now+1."""
        svc = _make_service()
        mon = _active_monitor()
        client = _make_client()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon._ti_next_attempt = 1.0  # past deadline → trigger immediately

        # Hold the gate to simulate another input running.
        core._track_id_request_gate.acquire()
        try:
            before = time.time()
            mon.maybe_trigger_track_identification(client, before)
            client.get_id_snapshot.assert_not_called()
            assert mon._ti_next_attempt >= before
            assert mon._ti_next_attempt < before + 5.0
        finally:
            core._track_id_request_gate.release()


# ---------------------------------------------------------------------------
# Worker: identified result
# ---------------------------------------------------------------------------

class TestWorkerIdentified:

    def test_worker_success_sets_identified(self):
        svc = _make_service(matched=True)
        mon = _active_monitor()
        core._track_id_service = svc
        _run_worker_sync(mon)
        assert mon._ti_snapshot.state == STATE_IDENTIFIED
        assert mon._ti_snapshot.title == "Test Title"
        assert mon._ti_snapshot.artist == "Test Artist"
        assert mon._ti_inflight is False
        assert mon._ti_inflight_token is None

    def test_identified_publishes_nowplaying(self):
        """A match landing mid-session must go through publish_refresh(), not
        publish_start(): the worker fires well after the session's pbeg
        already went out, so it must not emit a second one."""
        svc = _make_service(matched=True)
        mon = _active_monitor()
        core._track_id_service = svc
        _run_worker_sync(mon)
        mon._nowplaying_publisher.publish_refresh.assert_called()
        mon._nowplaying_publisher.publish_start.assert_not_called()

    def test_identified_does_not_publish_when_nowplaying_unchanged(self):
        from autostream_core import NowPlayingMetadata
        svc = _make_service(matched=True)
        mon = _active_monitor()
        core._track_id_service = svc
        mon._current_nowplaying = NowPlayingMetadata(
            title="Test Title", artist="Test Artist", album="Test Album"
        )
        mon._nowplaying_publisher.publish_refresh.reset_mock()
        _run_worker_sync(mon)
        mon._nowplaying_publisher.publish_refresh.assert_not_called()

    def test_identified_sets_last_identified_at(self):
        svc = _make_service(matched=True)
        mon = _active_monitor()
        core._track_id_service = svc
        assert mon._ti_last_identified_at == 0.0
        before = time.time()
        _run_worker_sync(mon)
        assert mon._ti_last_identified_at >= before

    def test_identified_schedules_refresh(self):
        """On match, next attempt = refresh_seconds ± jitter (clamped ≥ 1 s)."""
        from autostream_config import TRACK_ID_REFRESH_JITTER_SECONDS
        svc = _make_service(matched=True, refresh=60)
        mon = _active_monitor()
        core._track_id_service = svc
        before = time.time()
        _run_worker_sync(mon)
        # Must be in [refresh - jitter, refresh + jitter] from now (clamped ≥ 1).
        lo = before + (60 - TRACK_ID_REFRESH_JITTER_SECONDS) - 1
        hi = before + (60 + TRACK_ID_REFRESH_JITTER_SECONDS) + 1
        assert lo <= mon._ti_next_attempt <= hi
        assert mon._ti_next_attempt_reason == "match"


# ---------------------------------------------------------------------------
# Worker: not-found result
# ---------------------------------------------------------------------------

class TestWorkerNotFound:

    def test_worker_no_match_sets_not_found(self):
        svc = _make_service(matched=False)
        mon = _active_monitor()
        core._track_id_service = svc
        _run_worker_sync(mon)
        assert mon._ti_snapshot.state == STATE_NOT_FOUND
        assert mon._ti_inflight is False

    def test_not_found_schedules_retry(self):
        svc = _make_service(matched=False, retry=30)
        mon = _active_monitor()
        core._track_id_service = svc
        before = time.time()
        _run_worker_sync(mon)
        assert mon._ti_next_attempt >= before + 29
        assert mon._ti_next_attempt_reason == "no_match"

    def test_not_found_does_not_publish_nowplaying(self):
        svc = _make_service(matched=False)
        mon = _active_monitor()
        core._track_id_service = svc
        mon._nowplaying_publisher.publish_refresh.reset_mock()
        _run_worker_sync(mon)
        mon._nowplaying_publisher.publish_refresh.assert_not_called()

    def test_configuration_error_sets_error_state(self):
        svc = MagicMock()
        svc.provider_id = "test_provider"
        svc.analysis_lead_in_seconds = 5
        svc.snapshot_seconds = 15
        svc.retry_seconds = 30
        svc.refresh_seconds = 60
        svc.identify.return_value = TrackIdentificationResult(
            matched=False,
            provider="test_provider",
            source_detail="no_api_key",
            is_configuration_error=True,
        )
        mon = _active_monitor()
        core._track_id_service = svc
        _run_worker_sync(mon)
        assert mon._ti_snapshot.state == STATE_ERROR
        assert mon._ti_inflight is False

    def test_configuration_error_schedules_retry(self):
        svc = MagicMock()
        svc.provider_id = "test_provider"
        svc.analysis_lead_in_seconds = 5
        svc.snapshot_seconds = 15
        svc.retry_seconds = 30
        svc.refresh_seconds = 60
        svc.identify.return_value = TrackIdentificationResult(
            matched=False,
            provider="test_provider",
            is_configuration_error=True,
        )
        mon = _active_monitor()
        core._track_id_service = svc
        before = time.time()
        _run_worker_sync(mon)
        assert mon._ti_next_attempt >= before + 29
        assert mon._ti_next_attempt_reason == "error"


# ---------------------------------------------------------------------------
# Worker: exception → error state and scheduling
# ---------------------------------------------------------------------------

class TestWorkerError:

    def test_worker_exception_sets_error_state(self):
        svc = _make_service(raise_exc=RuntimeError("connection refused"))
        mon = _active_monitor()
        core._track_id_service = svc
        _run_worker_sync(mon)
        assert mon._ti_snapshot.state == STATE_ERROR
        assert mon._ti_inflight is False

    def test_worker_exception_schedules_error_retry(self):
        from autostream_config import TRACK_ID_ERROR_RETRY_SECONDS
        svc = _make_service(raise_exc=RuntimeError("boom"))
        mon = _active_monitor()
        core._track_id_service = svc
        before = time.time()
        _run_worker_sync(mon)
        assert mon._ti_next_attempt >= before + TRACK_ID_ERROR_RETRY_SECONDS - 1
        assert mon._ti_next_attempt_reason == "error"

    def test_worker_exception_does_not_expose_message(self, caplog):
        import logging
        svc = _make_service(raise_exc=RuntimeError("SECRETKEY=abc123"))
        mon = _active_monitor()
        core._track_id_service = svc
        with caplog.at_level(logging.DEBUG):
            _run_worker_sync(mon)
        assert "SECRETKEY" not in caplog.text
        assert "abc123" not in caplog.text

    def test_error_retry_constant_is_30(self):
        from autostream_config import TRACK_ID_ERROR_RETRY_SECONDS
        assert TRACK_ID_ERROR_RETRY_SECONDS == 30


# ---------------------------------------------------------------------------
# Rate-limit back-off
# ---------------------------------------------------------------------------

class TestRateLimitBackoff:

    def test_rate_limited_error_sets_backoff(self):
        from autostream_config import TRACK_ID_RATE_LIMIT_BACKOFF_SECONDS
        svc = _make_service(raise_exc=TrackIDRateLimitedError("rate_limited"))
        mon = _active_monitor()
        core._track_id_service = svc
        before = time.time()
        _run_worker_sync(mon)
        assert mon._ti_next_attempt >= before + TRACK_ID_RATE_LIMIT_BACKOFF_SECONDS - 1
        assert mon._ti_next_attempt_reason == "rate_limit"

    def test_rate_limited_error_sets_error_snapshot(self):
        svc = _make_service(raise_exc=TrackIDRateLimitedError("rate_limited"))
        mon = _active_monitor()
        core._track_id_service = svc
        _run_worker_sync(mon)
        assert mon._ti_snapshot.state == STATE_ERROR

    def test_rate_limit_backoff_constant_is_120(self):
        from autostream_config import TRACK_ID_RATE_LIMIT_BACKOFF_SECONDS
        assert TRACK_ID_RATE_LIMIT_BACKOFF_SECONDS == 120

    def test_generic_exception_uses_error_retry_not_rate_limit(self):
        from autostream_config import (
            TRACK_ID_ERROR_RETRY_SECONDS,
            TRACK_ID_RATE_LIMIT_BACKOFF_SECONDS,
        )
        svc = _make_service(raise_exc=RuntimeError("boom"))
        mon = _active_monitor()
        core._track_id_service = svc
        before = time.time()
        _run_worker_sync(mon)
        assert mon._ti_next_attempt < before + TRACK_ID_RATE_LIMIT_BACKOFF_SECONDS

    def test_rate_limit_logs_backoff(self, caplog):
        import logging
        svc = _make_service(raise_exc=TrackIDRateLimitedError("rate_limited"))
        mon = _active_monitor()
        core._track_id_service = svc
        with caplog.at_level(logging.WARNING):
            _run_worker_sync(mon)
        assert any("rate limited" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Upstream rejection back-off (HTTP 403/406)
# ---------------------------------------------------------------------------

class TestUpstreamRejectionBackoff:

    def test_upstream_rejection_403_sets_backoff(self):
        from autostream_config import TRACK_ID_UPSTREAM_REJECTION_BACKOFF_SECONDS
        svc = _make_service(raise_exc=TrackIDUpstreamRejectionError(403))
        mon = _active_monitor()
        core._track_id_service = svc
        before = time.time()
        _run_worker_sync(mon)
        assert mon._ti_next_attempt >= before + TRACK_ID_UPSTREAM_REJECTION_BACKOFF_SECONDS - 1
        assert mon._ti_next_attempt_reason == "upstream_rejection"

    def test_upstream_rejection_406_sets_backoff(self):
        from autostream_config import TRACK_ID_UPSTREAM_REJECTION_BACKOFF_SECONDS
        svc = _make_service(raise_exc=TrackIDUpstreamRejectionError(406))
        mon = _active_monitor()
        core._track_id_service = svc
        before = time.time()
        _run_worker_sync(mon)
        assert mon._ti_next_attempt >= before + TRACK_ID_UPSTREAM_REJECTION_BACKOFF_SECONDS - 1

    def test_upstream_rejection_sets_error_snapshot(self):
        svc = _make_service(raise_exc=TrackIDUpstreamRejectionError(403))
        mon = _active_monitor()
        core._track_id_service = svc
        _run_worker_sync(mon)
        assert mon._ti_snapshot.state == STATE_ERROR

    def test_upstream_rejection_backoff_constant_is_300(self):
        from autostream_config import TRACK_ID_UPSTREAM_REJECTION_BACKOFF_SECONDS
        assert TRACK_ID_UPSTREAM_REJECTION_BACKOFF_SECONDS == 300

    def test_upstream_rejection_logs_http_status(self, caplog):
        import logging
        svc = _make_service(raise_exc=TrackIDUpstreamRejectionError(403))
        mon = _active_monitor()
        core._track_id_service = svc
        with caplog.at_level(logging.WARNING):
            _run_worker_sync(mon)
        assert any("403" in r.message and "upstream" in r.message for r in caplog.records)

    def test_upstream_rejection_handled_before_rate_limit(self):
        """UpstreamRejectionError must not fall through to the rate-limit branch."""
        from autostream_config import (
            TRACK_ID_RATE_LIMIT_BACKOFF_SECONDS,
            TRACK_ID_UPSTREAM_REJECTION_BACKOFF_SECONDS,
        )
        svc = _make_service(raise_exc=TrackIDUpstreamRejectionError(403))
        mon = _active_monitor()
        core._track_id_service = svc
        before = time.time()
        _run_worker_sync(mon)
        assert mon._ti_next_attempt >= before + TRACK_ID_UPSTREAM_REJECTION_BACKOFF_SECONDS - 1
        assert mon._ti_next_attempt_reason == "upstream_rejection"


# ---------------------------------------------------------------------------
# Protected deadlines
# ---------------------------------------------------------------------------

class TestProtectedDeadlines:

    def test_rate_limit_deadline_not_overwritten_by_shorter_delay(self):
        """_schedule_track_id_attempt must not shrink a rate_limit deadline."""
        mon = _make_monitor()
        future = time.time() + 200.0
        mon._ti_next_attempt = future
        mon._ti_next_attempt_reason = "rate_limit"

        mon._schedule_track_id_attempt(time.time() + 10.0, "no_match")

        assert mon._ti_next_attempt == future  # preserved
        assert mon._ti_next_attempt_reason == "rate_limit"

    def test_upstream_rejection_deadline_not_overwritten_by_shorter_delay(self):
        mon = _make_monitor()
        future = time.time() + 350.0
        mon._ti_next_attempt = future
        mon._ti_next_attempt_reason = "upstream_rejection"

        mon._schedule_track_id_attempt(time.time() + 5.0, "match")

        assert mon._ti_next_attempt == future
        assert mon._ti_next_attempt_reason == "upstream_rejection"

    def test_rate_limit_deadline_can_be_extended(self):
        """A longer deadline can replace a shorter rate_limit deadline."""
        mon = _make_monitor()
        soon = time.time() + 50.0
        mon._ti_next_attempt = soon
        mon._ti_next_attempt_reason = "rate_limit"

        later = time.time() + 300.0
        mon._schedule_track_id_attempt(later, "upstream_rejection")

        assert mon._ti_next_attempt >= later - 1  # new (later) deadline accepted
        assert mon._ti_next_attempt_reason == "upstream_rejection"

    def test_non_protected_reason_is_always_overwritten(self):
        mon = _make_monitor()
        future = time.time() + 100.0
        mon._ti_next_attempt = future
        mon._ti_next_attempt_reason = "match"  # not protected

        mon._schedule_track_id_attempt(time.time() + 5.0, "no_match")

        assert mon._ti_next_attempt_reason == "no_match"


# ---------------------------------------------------------------------------
# Worker token guard
# ---------------------------------------------------------------------------

class TestWorkerTokenGuard:

    def test_stale_token_does_not_update_snapshot(self):
        """Worker called with a stale token must not overwrite the snapshot."""
        svc = _make_service(matched=True)
        mon = _active_monitor()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)

        current_snapshot = mon._ti_snapshot
        stale_token = object()
        fresh_token = object()

        # Install fresh_token as current; call worker with stale_token.
        core._track_id_request_gate.acquire()
        mon._ti_inflight = True
        mon._ti_inflight_token = fresh_token  # current token ≠ stale_token
        mon._ti_worker(bytes(_DEFAULT_PCM), _DEFAULT_RATE, stale_token, mon._ti_generation)

        # Snapshot must not have changed to IDENTIFIED.
        assert mon._ti_snapshot is current_snapshot

    def test_stale_token_does_not_clear_inflight(self):
        """Stale token must not clear _ti_inflight for the live generation."""
        svc = _make_service(matched=True)
        mon = _active_monitor()
        core._track_id_service = svc
        fresh_token = object()
        stale_token = object()

        core._track_id_request_gate.acquire()
        mon._ti_inflight = True
        mon._ti_inflight_token = fresh_token
        mon._ti_worker(bytes(_DEFAULT_PCM), _DEFAULT_RATE, stale_token, mon._ti_generation)

        assert mon._ti_inflight is True  # must not have been cleared
        assert mon._ti_inflight_token is fresh_token

    def test_matching_token_clears_inflight(self):
        """When the token matches, _ti_inflight and _ti_inflight_token are cleared."""
        svc = _make_service(matched=True)
        mon = _active_monitor()
        core._track_id_service = svc
        _run_worker_sync(mon)
        assert mon._ti_inflight is False
        assert mon._ti_inflight_token is None

    def test_gate_always_released_even_with_stale_token(self):
        """Gate must be released whether or not the token matches."""
        svc = _make_service(matched=True)
        mon = _active_monitor()
        core._track_id_service = svc
        stale_token = object()
        fresh_token = object()

        core._track_id_request_gate.acquire()
        mon._ti_inflight = True
        mon._ti_inflight_token = fresh_token
        mon._ti_worker(bytes(_DEFAULT_PCM), _DEFAULT_RATE, stale_token, mon._ti_generation)

        # Gate should have been released; try acquiring it immediately.
        acquired = core._track_id_request_gate.acquire(blocking=False)
        assert acquired, "Gate was not released after stale-token worker returned"
        core._track_id_request_gate.release()

    def test_gate_released_on_exception_with_stale_token(self):
        """Gate is released even when the exception path encounters a stale token."""
        svc = _make_service(raise_exc=RuntimeError("boom"))
        mon = _active_monitor()
        core._track_id_service = svc
        stale_token = object()
        fresh_token = object()

        core._track_id_request_gate.acquire()
        mon._ti_inflight = True
        mon._ti_inflight_token = fresh_token
        mon._ti_worker(bytes(_DEFAULT_PCM), _DEFAULT_RATE, stale_token, mon._ti_generation)

        acquired = core._track_id_request_gate.acquire(blocking=False)
        assert acquired, "Gate was not released after stale-token exception path"
        core._track_id_request_gate.release()


# ---------------------------------------------------------------------------
# Generation guard — stale workers do not overwrite fresh state
# ---------------------------------------------------------------------------

class TestGenerationGuard:

    def test_apply_service_increments_generation(self):
        mon = _make_monitor()
        gen_before = mon._ti_generation
        mon._apply_track_id_service(_make_service())
        assert mon._ti_generation == gen_before + 1

    def test_apply_service_live_rebuilds_service(self, tmp_path):
        """apply_track_id_config_live reads the saved config and rebuilds."""
        import json
        from autostream_core import apply_track_id_config_live
        cfg = {
            "general": {"silence_seconds": 30},
            "owntone": {"base_url": "http://localhost:3689"},
            "audio1": {
                "capture_device": "hw:0,0",
                "silence_threshold": -66,
                "turntable": False,
            },
            "track_identification": {"enabled": False},
        }
        p = tmp_path / "autostream.json"
        p.write_text(json.dumps(cfg))
        old_svc = core._track_id_service
        try:
            apply_track_id_config_live(str(p))
            assert core._track_id_service is None
        finally:
            core._track_id_service = old_svc


# ---------------------------------------------------------------------------
# Capture stop resets to waiting
# ---------------------------------------------------------------------------

class TestCaptureStopReset:

    def test_stop_resets_to_waiting_when_service_active(self):
        svc = _make_service()
        mon = _active_monitor()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        from track_id.models import TrackIdentificationSnapshot
        mon._ti_snapshot = TrackIdentificationSnapshot(
            enabled=True,
            state=STATE_IDENTIFIED,
            status_text="Identified",
            title="Old Track",
            artist="Old Artist",
            updated_at=time.time(),
        )
        client = MagicMock(spec=MonitorClient)
        with patch.object(core, "any_monitor_capturing", return_value=False), \
             patch.object(core, "_stop_and_disable_owntone"):
            mon._on_capture_stopped(client)
        assert mon._ti_snapshot.state == STATE_WAITING

    def test_stop_resets_to_disabled_when_no_service(self):
        core._track_id_service = None
        mon = _active_monitor()
        client = MagicMock(spec=MonitorClient)
        with patch.object(core, "any_monitor_capturing", return_value=False), \
             patch.object(core, "_stop_and_disable_owntone"):
            mon._on_capture_stopped(client)
        assert mon._ti_snapshot.state == STATE_DISABLED

    def test_capture_stop_clears_next_attempt(self):
        """_on_capture_stopped must clear any pending next-attempt deadline."""
        svc = _make_service()
        mon = _active_monitor()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon._ti_next_attempt = time.time() + 100.0
        mon._ti_next_attempt_reason = "match"
        client = MagicMock(spec=MonitorClient)
        with patch.object(core, "any_monitor_capturing", return_value=False), \
             patch.object(core, "_stop_and_disable_owntone"):
            mon._on_capture_stopped(client)
        assert mon._ti_next_attempt == 0.0
        assert mon._ti_next_attempt_reason == ""

    def test_capture_stop_increments_generation(self):
        """_on_capture_stopped must bump the generation to invalidate running workers."""
        svc = _make_service()
        mon = _active_monitor()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        gen_before = mon._ti_generation
        client = MagicMock(spec=MonitorClient)
        with patch.object(core, "any_monitor_capturing", return_value=False), \
             patch.object(core, "_stop_and_disable_owntone"):
            mon._on_capture_stopped(client)
        assert mon._ti_generation == gen_before + 1

    def test_capture_stop_stale_worker_does_not_overwrite_snapshot(self):
        """A worker completing after capture stops must not overwrite the waiting snapshot.

        Concurrency: the worker captures my_gen at dispatch time; _on_capture_stopped
        bumps the generation while the worker is blocked in svc.identify.  The worker
        then sees the mismatch and skips all state updates.
        """
        svc = _make_service(matched=True)
        mon = _active_monitor()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)

        # Pause the worker inside svc.identify so we can call stop while it runs.
        proceed = threading.Event()
        result_value = svc.identify.return_value
        def slow_identify(*a, **kw):
            proceed.wait()
            return result_value
        svc.identify.side_effect = slow_identify

        stale_token = object()
        old_gen = mon._ti_generation
        core._track_id_request_gate.acquire()
        mon._ti_inflight = True
        mon._ti_inflight_token = stale_token

        worker = threading.Thread(
            target=mon._ti_worker,
            args=(bytes(_DEFAULT_PCM), _DEFAULT_RATE, stale_token, old_gen),
            daemon=True,
        )
        worker.start()

        # Call stop while worker is blocked: bumps generation.
        client = MagicMock(spec=MonitorClient)
        with patch.object(core, "any_monitor_capturing", return_value=False), \
             patch.object(core, "_stop_and_disable_owntone"):
            mon._on_capture_stopped(client)

        waiting_snap = mon._ti_snapshot
        assert waiting_snap.state == STATE_WAITING

        # Let the worker finish: it sees generation mismatch and must not overwrite.
        proceed.set()
        worker.join(timeout=2.0)
        assert not worker.is_alive()
        assert mon._ti_snapshot is waiting_snap


# ---------------------------------------------------------------------------
# get_track_identification_snapshot
# ---------------------------------------------------------------------------

class TestGetSnapshot:

    def test_returns_snapshot_for_known_index(self):
        mon = _make_monitor(input_index=7)
        from autostream_core import get_track_identification_snapshot
        snap = get_track_identification_snapshot(7)
        assert snap is not None

    def test_returns_disabled_for_unknown_index(self):
        from autostream_core import get_track_identification_snapshot
        snap = get_track_identification_snapshot(9999)
        assert snap.state == STATE_DISABLED


# ---------------------------------------------------------------------------
# get_id_snapshot clamp: snapshot_seconds is used not lead-in
# ---------------------------------------------------------------------------

class TestMonitorSnapshotClamp:

    def _run_trigger(self, analysis_lead_in: int = 5, snapshot: int = 15) -> int:
        pcm = b"\x00" * int(_DEFAULT_RATE * 2 * snapshot)
        client = MagicMock(spec=MonitorClient)
        client.get_id_snapshot.return_value = (pcm, _DEFAULT_RATE)
        svc = _make_service(analysis_lead_in=analysis_lead_in, snapshot=snapshot)
        mon = _active_monitor()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon._ti_next_attempt = 1.0  # past deadline → trigger immediately
        mon.maybe_trigger_track_identification(client, time.time())
        args, kwargs = client.get_id_snapshot.call_args
        return kwargs.get("max_seconds", args[1] if len(args) > 1 else None)

    def test_snapshot_seconds_used_not_lead_in_seconds(self):
        assert self._run_trigger(analysis_lead_in=45, snapshot=15) == 15

    def test_snapshot_seconds_passed_for_large_lead_in(self):
        assert self._run_trigger(analysis_lead_in=30, snapshot=15) == 15

    def test_snapshot_pcm_exceeds_min_duration_guard(self):
        from track_id.service import MIN_PCM_DURATION_SECONDS
        pcm = b"\x00" * int(_DEFAULT_RATE * 2 * 15)
        duration_s = len(pcm) / (_DEFAULT_RATE * 2)
        assert duration_s >= MIN_PCM_DURATION_SECONDS


# ---------------------------------------------------------------------------
# Short-snapshot debug log
# ---------------------------------------------------------------------------

class TestShortSnapshotLog:

    def test_short_snapshot_logs_correct_message(self, caplog):
        import logging
        from track_id.service import MIN_PCM_DURATION_SECONDS
        svc = _make_service()
        mon = _active_monitor()
        short_pcm = b"\x00" * int(_DEFAULT_RATE * 2 * (MIN_PCM_DURATION_SECONDS - 1))
        client = MagicMock()
        client.get_id_snapshot.return_value = (short_pcm, _DEFAULT_RATE)
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon._ti_next_attempt = 1.0  # past deadline → trigger immediately

        with caplog.at_level(logging.DEBUG):
            mon.maybe_trigger_track_identification(client, time.time())

        messages = [r.message for r in caplog.records]
        assert any("snapshot too short" in m for m in messages), \
            f"Expected 'snapshot too short' in log, got: {messages}"
        assert mon._ti_inflight is False

    def test_snapshot_bytes_logged_on_valid_pcm(self, caplog):
        import logging
        svc = _make_service()
        mon = _active_monitor()
        pcm = b"\x00" * int(_DEFAULT_RATE * 2 * 15)
        client = MagicMock()
        client.get_id_snapshot.return_value = (pcm, _DEFAULT_RATE)
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon._ti_next_attempt = 1.0  # past deadline → trigger immediately

        with caplog.at_level(logging.DEBUG):
            mon.maybe_trigger_track_identification(client, time.time())

        messages = " ".join(r.message for r in caplog.records)
        assert "snapshot returned" in messages
        assert str(len(pcm)) in messages


# ---------------------------------------------------------------------------
# apply_track_id_config_live with enabled config
# ---------------------------------------------------------------------------

class TestApplyTrackIdConfigLiveEnabled:

    def test_apply_service_live_rebuilds_service_enabled(self, tmp_path):
        import json
        from autostream_core import apply_track_id_config_live
        cfg = {
            "general": {"silence_seconds": 30},
            "owntone": {"base_url": "http://localhost:3689"},
            "audio1": {
                "capture_device": "hw:0,0",
                "silence_threshold": -66,
                "turntable": False,
            },
            "track_identification": {
                "enabled": True,
                "provider": "vibra_shazam",
                "analysis_lead_in_seconds": 5,
            },
        }
        p = tmp_path / "autostream.json"
        p.write_text(json.dumps(cfg))
        old_svc = core._track_id_service
        try:
            apply_track_id_config_live(str(p))
            assert core._track_id_service is not None
            assert core._track_id_service.analysis_lead_in_seconds == 5
        finally:
            core._track_id_service = old_svc

    def test_apply_service_live_pushes_to_monitors(self, tmp_path):
        import json
        from autostream_core import apply_track_id_config_live
        cfg = {
            "general": {"silence_seconds": 30},
            "owntone": {"base_url": "http://localhost:3689"},
            "audio1": {
                "capture_device": "hw:0,0",
                "silence_threshold": -66,
                "turntable": False,
            },
            "track_identification": {"enabled": False},
        }
        p = tmp_path / "autostream.json"
        p.write_text(json.dumps(cfg))
        mon = _make_monitor()
        old_svc = core._track_id_service
        try:
            apply_track_id_config_live(str(p))
            assert mon._ti_snapshot.state == STATE_DISABLED
        finally:
            core._track_id_service = old_svc


# ---------------------------------------------------------------------------
# T5: Track-change events connected to scheduling
# ---------------------------------------------------------------------------

def _make_capturing_monitor_with_service(svc=None, **overrides) -> AudioMonitor:
    """Return an active monitor already baselining a track_change_seq of 0."""
    if svc is None:
        svc = _make_service()
    mon = _active_monitor(**overrides)
    core._track_id_service = svc
    mon._apply_track_id_service(svc)
    mon.track_change_seq = 0
    mon._track_change_seq_baseline = 0
    return mon


class TestTrackChangeScheduling:

    def test_seq_advance_schedules_lead_in_plus_snapshot(self):
        """A track-change event schedules analysis_lead_in + snapshot from now."""
        svc = _make_service(analysis_lead_in=5, snapshot=15)
        mon = _make_capturing_monitor_with_service(svc)
        before = time.time()
        mon._on_possible_track_change(1)
        assert mon._ti_next_attempt >= before + 19
        assert mon._ti_next_attempt_reason == "track_change"

    def test_seq_advance_sets_waiting_snapshot(self):
        svc = _make_service()
        mon = _make_capturing_monitor_with_service(svc)
        from track_id.models import TrackIdentificationSnapshot
        mon._ti_snapshot = TrackIdentificationSnapshot(
            enabled=True, state=STATE_IDENTIFIED,
            status_text="", updated_at=time.time(),
        )
        mon._on_possible_track_change(1)
        assert mon._ti_snapshot.state == STATE_WAITING

    def test_seq_advance_increments_generation(self):
        svc = _make_service()
        mon = _make_capturing_monitor_with_service(svc)
        gen_before = mon._ti_generation
        mon._on_possible_track_change(1)
        assert mon._ti_generation == gen_before + 1

    def test_seq_advance_updates_baseline(self):
        svc = _make_service()
        mon = _make_capturing_monitor_with_service(svc)
        mon._on_possible_track_change(7)
        assert mon._track_change_seq_baseline == 7

    def test_seq_advance_without_service_updates_baseline_only(self):
        """Without a service, baseline is updated but no scheduling occurs."""
        mon = _make_capturing_monitor_with_service()
        core._track_id_service = None
        before_attempt = mon._ti_next_attempt
        mon._on_possible_track_change(3)
        assert mon._track_change_seq_baseline == 3
        # Scheduling unchanged (no service to schedule with).
        assert mon._ti_next_attempt == before_attempt

    def test_seq_advance_does_not_apply_jitter(self):
        """Track-change delay must equal analysis_lead_in + snapshot exactly (no jitter)."""
        svc = _make_service(analysis_lead_in=10, snapshot=15)
        mon = _make_capturing_monitor_with_service(svc)
        before = time.time()
        mon._on_possible_track_change(1)
        # Delay is 10+15=25, floor is now+1 from _schedule_track_id_attempt.
        # Allow tight epsilon (only scheduling floor can push it slightly higher).
        assert mon._ti_next_attempt <= before + 26
        assert mon._ti_next_attempt >= before + 24

    def test_multiple_seq_increments_schedule_one_attempt(self):
        """Multiple advances in one poll produce a single rescheduling."""
        svc = _make_service(analysis_lead_in=5, snapshot=15)
        mon = _make_capturing_monitor_with_service(svc)
        gen_before = mon._ti_generation

        # Simulate skipping from 0 → 3 (three events between polls).
        mon.track_change_seq = 3
        mon._track_change_seq_baseline = 0

        # _ingest_status already capturing path: seq differs → one call.
        status = {
            "capturing": True, "silent": False,
            "level_dbfs": -30.0, "poll_peak_dbfs": -30.0,
            "detected_hz": 0.0, "track_change_seq": 3,
        }
        mon._ingest_status(status)
        assert mon._ti_next_attempt_reason == "track_change"
        assert mon._track_change_seq_baseline == 3
        assert mon._ti_generation == gen_before + 1  # only one increment

    def test_capture_start_seq_is_baselined_not_treated_as_event(self):
        """On capture start, the current seq is baselined without triggering a change event."""
        svc = _make_service()
        mon = _make_monitor()
        mon.is_capturing = False
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        gen_before = mon._ti_generation

        # Simulate capture starting with seq already at 5.
        status = {
            "capturing": True, "silent": False,
            "level_dbfs": -30.0, "poll_peak_dbfs": -30.0,
            "detected_hz": 0.0, "track_change_seq": 5,
        }
        mon._ingest_status(status)
        assert mon._track_change_seq_baseline == 5
        assert mon._ti_generation == gen_before  # no change event fired

    def test_track_change_preserves_rate_limit_deadline(self):
        """Track-change event must not shorten an active rate-limit deadline."""
        svc = _make_service(analysis_lead_in=5, snapshot=15)
        mon = _make_capturing_monitor_with_service(svc)

        # Set a rate-limit deadline far in the future.
        rate_limit_deadline = time.time() + 200.0
        mon._ti_next_attempt = rate_limit_deadline
        mon._ti_next_attempt_reason = "rate_limit"

        mon._on_possible_track_change(1)

        assert mon._ti_next_attempt == rate_limit_deadline  # preserved
        assert mon._ti_next_attempt_reason == "rate_limit"

    def test_track_change_preserves_upstream_rejection_deadline(self):
        """Track-change event must not shorten an upstream_rejection deadline."""
        svc = _make_service(analysis_lead_in=5, snapshot=15)
        mon = _make_capturing_monitor_with_service(svc)

        rejection_deadline = time.time() + 350.0
        mon._ti_next_attempt = rejection_deadline
        mon._ti_next_attempt_reason = "upstream_rejection"

        mon._on_possible_track_change(1)

        assert mon._ti_next_attempt == rejection_deadline
        assert mon._ti_next_attempt_reason == "upstream_rejection"

    def test_track_change_overrides_match_refresh_deadline(self):
        """Track-change event (25s) can shorten a match-refresh deadline (300s)."""
        svc = _make_service(analysis_lead_in=5, snapshot=15, refresh=300)
        mon = _make_capturing_monitor_with_service(svc)

        match_deadline = time.time() + 300.0
        mon._ti_next_attempt = match_deadline
        mon._ti_next_attempt_reason = "match"

        before = time.time()
        mon._on_possible_track_change(1)

        # New deadline should be ~25s from now, not 300s.
        assert mon._ti_next_attempt < before + 30
        assert mon._ti_next_attempt_reason == "track_change"

    def test_stale_worker_does_not_publish_after_track_change(self):
        """Worker started before a track-change event must not update state.

        dispatch_gen is captured at dispatch time; _on_possible_track_change bumps
        the generation so the stale worker sees a mismatch and skips state updates.
        """
        svc = _make_service(matched=True)
        mon = _active_monitor()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)

        # Pre-change: stale worker has acquired gate and installed its token.
        stale_token = object()
        old_gen = mon._ti_generation  # generation at dispatch time
        core._track_id_request_gate.acquire()
        mon._ti_inflight = True
        mon._ti_inflight_token = stale_token

        # Track-change event fires: generation bumps, snapshot set to waiting.
        mon._on_possible_track_change(1)
        waiting_snap = mon._ti_snapshot
        assert waiting_snap.state == STATE_WAITING

        # Gate is still held from the first acquire (simulating the running worker).
        # Call _ti_worker with old_gen; it sees generation mismatch and skips updates.
        mon._ti_worker(bytes(_DEFAULT_PCM), _DEFAULT_RATE, stale_token, old_gen)

        # Snapshot must still be the waiting snapshot from _on_possible_track_change.
        assert mon._ti_snapshot is waiting_snap

    def test_track_change_does_not_clear_inflight_when_worker_running(self):
        """A track-change event must not clear _ti_inflight; the old worker owns it."""
        svc = _make_service(analysis_lead_in=5, snapshot=15)
        mon = _make_capturing_monitor_with_service(svc)
        mon._ti_inflight = True
        mon._ti_inflight_token = object()

        mon._on_possible_track_change(1)

        assert mon._ti_inflight is True

    def test_stale_worker_clears_inflight_enabling_next_dispatch(self):
        """After a track-change, the stale worker's finally clears _ti_inflight
        so the next coordinator poll can dispatch the replacement worker."""
        svc = _make_service(matched=True)
        mon = _active_monitor()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)

        # Simulate the stale worker: it holds the gate and its token.
        stale_token = object()
        old_gen = mon._ti_generation  # generation at dispatch time
        core._track_id_request_gate.acquire()
        mon._ti_inflight = True
        mon._ti_inflight_token = stale_token

        # Track change fires: generation bumps, deadline updated, inflight left.
        mon._on_possible_track_change(1)
        assert mon._ti_inflight is True  # still set; stale worker not done yet

        # Stale worker finishes: sees generation mismatch, skips state, clears inflight.
        mon._ti_worker(bytes(_DEFAULT_PCM), _DEFAULT_RATE, stale_token, old_gen)

        assert mon._ti_inflight is False   # cleared by stale worker's finally
        assert mon._ti_inflight_token is None
        assert not core._track_id_request_gate.locked()  # gate released

    def test_ingest_status_fires_track_change_on_seq_advance(self):
        """_ingest_status with advancing seq triggers _on_possible_track_change."""
        svc = _make_service(analysis_lead_in=5, snapshot=15)
        mon = _active_monitor()
        mon.is_capturing = True
        mon.track_change_seq = 0
        mon._track_change_seq_baseline = 0
        core._track_id_service = svc
        mon._apply_track_id_service(svc)

        before = time.time()
        status = {
            "capturing": True, "silent": False,
            "level_dbfs": -30.0, "poll_peak_dbfs": -30.0,
            "detected_hz": 0.0, "track_change_seq": 2,
        }
        transition = mon._ingest_status(status)
        assert transition == ""  # not a start/stop
        assert mon._track_change_seq_baseline == 2
        assert mon._ti_next_attempt >= before + 19
        assert mon._ti_next_attempt_reason == "track_change"

    def test_ingest_status_no_event_when_seq_unchanged(self):
        """_ingest_status does not schedule a track-change when seq is stable."""
        svc = _make_service()
        mon = _active_monitor()
        mon.is_capturing = True
        mon.track_change_seq = 3
        mon._track_change_seq_baseline = 3
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon._ti_next_attempt = time.time() + 1000.0  # some future deadline
        mon._ti_next_attempt_reason = "match"

        status = {
            "capturing": True, "silent": False,
            "level_dbfs": -30.0, "poll_peak_dbfs": -30.0,
            "detected_hz": 0.0, "track_change_seq": 3,  # same
        }
        mon._ingest_status(status)
        assert mon._ti_next_attempt_reason == "match"  # unchanged


# ---------------------------------------------------------------------------
# T5b: Detecting-interstitial -- a track-change event publishes the input
# label + placeholder logo immediately, rather than holding the previous
# track's title/artwork until re-identification completes.
# ---------------------------------------------------------------------------

class TestTrackChangeInterstitial:

    def test_track_change_publishes_default_metadata_with_placeholder(self):
        """A gap event publishes once: input-label title, placeholder artwork."""
        from autostream_artwork import ArtworkImage
        placeholder = ArtworkImage(data=b"placeholder-bytes", mime="image/png", ident="placeholder1234")
        svc = _make_service()
        mon = _make_capturing_monitor_with_service(svc)
        expected_default = mon._default_nowplaying_metadata()

        with patch("autostream_core._load_placeholder_artwork", return_value=placeholder):
            mon._on_possible_track_change(1)

        mon._nowplaying_publisher.publish_refresh.assert_called_once()
        published = mon._nowplaying_publisher.publish_refresh.call_args[0][0]
        assert published.title == expected_default.title
        assert published.artist == expected_default.artist
        assert published.artwork == placeholder
        assert mon._current_nowplaying == published

    def test_track_change_publishes_with_none_artwork_when_placeholder_missing(self):
        """If the bundled placeholder can't be loaded, publish artwork=None
        and let the publisher's own HOLD-UNTIL-NEW fallback take over."""
        svc = _make_service()
        mon = _make_capturing_monitor_with_service(svc)

        with patch("autostream_core._load_placeholder_artwork", return_value=None):
            mon._on_possible_track_change(1)

        mon._nowplaying_publisher.publish_refresh.assert_called_once()
        published = mon._nowplaying_publisher.publish_refresh.call_args[0][0]
        assert published.artwork is None

    def test_track_change_without_service_does_not_publish(self):
        """The svc-is-None early-out must still skip publishing entirely."""
        mon = _make_capturing_monitor_with_service()
        core._track_id_service = None
        mon._on_possible_track_change(3)
        mon._nowplaying_publisher.publish_refresh.assert_not_called()

    def test_same_track_reidentification_after_interstitial_republishes(self):
        """A completed identification of the SAME track, landing after the
        interstitial reset _current_nowplaying, must still publish (it now
        differs from the interstitial's input-label/placeholder metadata),
        restoring the receiver's display without any special-casing."""
        from autostream_artwork import ArtworkImage
        placeholder = ArtworkImage(data=b"placeholder-bytes", mime="image/png", ident="placeholder1234")
        svc = _make_service(matched=True)
        mon = _active_monitor()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)

        with patch("autostream_core._load_placeholder_artwork", return_value=placeholder):
            mon._on_possible_track_change(1)
        mon._nowplaying_publisher.publish_refresh.reset_mock()
        interstitial_meta = mon._current_nowplaying
        assert interstitial_meta.artwork == placeholder

        # Re-identification lands and matches the same track as before.
        _run_worker_sync(mon)

        mon._nowplaying_publisher.publish_refresh.assert_called_once()
        published = mon._nowplaying_publisher.publish_refresh.call_args[0][0]
        assert published.title == "Test Title"
        assert published.artist == "Test Artist"
        assert published != interstitial_meta
        assert mon._current_nowplaying == published

    def test_different_track_reidentification_after_interstitial_publishes_new(self):
        """A completed identification of a DIFFERENT track after the
        interstitial publishes that new track's metadata."""
        svc = _make_service(matched=True)
        mon = _active_monitor()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)

        mon._on_possible_track_change(1)
        mon._nowplaying_publisher.publish_refresh.reset_mock()

        _run_worker_sync(mon)

        mon._nowplaying_publisher.publish_refresh.assert_called_once()
        published = mon._nowplaying_publisher.publish_refresh.call_args[0][0]
        assert published.title == "Test Title"
        assert published.artist == "Test Artist"
        assert mon._current_nowplaying == published


# ---------------------------------------------------------------------------
# Track identification during replay
# ---------------------------------------------------------------------------
#
# The origin input isn't "capturing" while its recording replays, so track
# identification must key off an "actively-sourcing" gate (is_capturing OR
# replay_origin) rather than a raw is_capturing check, everywhere that would
# otherwise leave identification permanently dead for a replay-sourced
# session:
#   - maybe_trigger_track_identification() checks actively-sourcing, not
#     "is_capturing" alone
#   - _ingest_status()'s track_change_seq check runs "if was actively-sourcing
#     and is actively-sourcing"
#   - the identification cycle is armed from _dispatch_session_event() for a
#     replay-sourced session_started/source_changed, not only from
#     _on_capture_started
# These tests exercise that "actively-sourcing" gate.

class TestTrackIdentificationDuringReplay:

    def test_maybe_trigger_fires_during_replay_despite_not_capturing(self):
        """The core fix: replay_origin=True must let dispatch proceed even
        though is_capturing is False (previously a hard bail-out)."""
        svc = _make_service()
        mon = _make_monitor()
        mon.is_capturing = False
        mon.is_silent = True  # replay input is silent by definition
        client = _make_client()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon._ti_next_attempt = 1.0  # past deadline

        mon.maybe_trigger_track_identification(client, time.time(), replay_origin=True)
        client.get_id_snapshot.assert_called_once()

    def test_maybe_trigger_does_not_fire_when_not_actively_sourcing(self):
        """Neither capturing nor the replay origin: still gated (e.g. an
        idle input, or an input that was replaying but the recording has
        since stopped)."""
        svc = _make_service()
        mon = _make_monitor()
        mon.is_capturing = False
        mon.is_silent = True
        client = _make_client()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon._ti_next_attempt = 1.0

        mon.maybe_trigger_track_identification(client, time.time(), replay_origin=False)
        client.get_id_snapshot.assert_not_called()

    def test_silent_gate_still_applies_to_live_capture(self):
        """Regression guard: a genuinely silent LIVE capture (not replay)
        must remain gated -- only the replay case bypasses is_silent."""
        svc = _make_service()
        mon = _active_monitor()
        mon.is_silent = True
        client = _make_client()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon._ti_next_attempt = 1.0

        mon.maybe_trigger_track_identification(client, time.time(), replay_origin=False)
        client.get_id_snapshot.assert_not_called()

    def test_live_capture_behaviour_unchanged_when_not_replaying(self):
        """Sanity check: a normal live, non-silent capture with
        replay_origin=False (the default) triggers identification normally."""
        svc = _make_service()
        mon = _active_monitor()
        client = _make_client()
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        mon._ti_next_attempt = 1.0

        mon.maybe_trigger_track_identification(client, time.time())
        client.get_id_snapshot.assert_called_once()

    def test_ingest_status_seq_advance_during_replay_triggers_track_change(self):
        """track_change_seq advances are daemon-routed under origin_input
        during replay; _ingest_status must detect them even though
        is_capturing is False on both sides of the ingest, as long as
        replay_origin is True on both sides (steady-state replay)."""
        svc = _make_service(analysis_lead_in=5, snapshot=15)
        mon = _make_monitor()
        mon.is_capturing = False
        mon._replay_origin = True  # was actively-sourcing via replay last cycle
        mon.track_change_seq = 0
        mon._track_change_seq_baseline = 0
        core._track_id_service = svc
        mon._apply_track_id_service(svc)

        before = time.time()
        status = {
            "capturing": False, "silent": True,
            "level_dbfs": -90.0, "poll_peak_dbfs": -90.0,
            "detected_hz": 0.0, "track_change_seq": 2,
        }
        transition = mon._ingest_status(status, replay_origin=True)
        assert transition == ""  # no capturing transition
        assert mon._track_change_seq_baseline == 2
        assert mon._ti_next_attempt_reason == "track_change"
        assert mon._ti_next_attempt >= before + 19

    def test_ingest_status_replay_transition_cycle_does_not_baseline_or_fire(self):
        """On the very cycle replay-sourcing BEGINS (was_actively_sourcing
        False -> True), _ingest_status must not itself baseline the seq or
        fire a track-change: that transition is armed by
        _dispatch_session_event -> _arm_track_identification_for_replay()
        after this same poll cycle, mirroring _on_capture_started."""
        svc = _make_service()
        mon = _make_monitor()
        mon.is_capturing = False
        mon._replay_origin = False  # not actively-sourcing before this cycle
        mon.track_change_seq = 0
        mon._track_change_seq_baseline = 0
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        gen_before = mon._ti_generation

        status = {
            "capturing": False, "silent": True,
            "level_dbfs": -90.0, "poll_peak_dbfs": -90.0,
            "detected_hz": 0.0, "track_change_seq": 7,  # daemon already bumped it
        }
        mon._ingest_status(status, replay_origin=True)  # transition cycle
        # No track-change fired: baseline left at its old (now stale) value
        # and generation untouched -- _arm_track_identification_for_replay()
        # is responsible for re-baselining once the session tracker sees it.
        assert mon._ti_generation == gen_before
        assert mon._replay_origin is True  # field itself does update

    def test_arm_track_identification_for_replay_baselines_seq(self):
        svc = _make_service(analysis_lead_in=5, snapshot=15)
        mon = _make_monitor()
        mon.is_capturing = False
        mon.track_change_seq = 9
        mon._track_change_seq_baseline = 0
        core._track_id_service = svc
        mon._apply_track_id_service(svc)

        before = time.time()
        mon._arm_track_identification_for_replay()

        assert mon._track_change_seq_baseline == 9
        assert mon._ti_next_attempt_reason == "initial"
        assert mon._ti_next_attempt >= before + 19  # lead-in(5)+snapshot(15)

    def test_arm_track_identification_for_replay_resets_generation_and_inflight(self):
        svc = _make_service()
        mon = _make_monitor()
        mon.is_capturing = False
        core._track_id_service = svc
        mon._apply_track_id_service(svc)
        gen_before = mon._ti_generation
        mon._ti_inflight = True
        mon._ti_inflight_token = object()

        mon._arm_track_identification_for_replay()

        assert mon._ti_generation == gen_before + 1
        assert mon._ti_inflight is False
        assert mon._ti_inflight_token is None

    def test_arm_track_identification_for_replay_sets_waiting_snapshot(self):
        svc = _make_service()
        mon = _make_monitor()
        mon.is_capturing = False
        core._track_id_service = svc
        mon._apply_track_id_service(svc)

        mon._arm_track_identification_for_replay()
        assert mon._ti_snapshot.state == STATE_WAITING

    def test_arm_track_identification_for_replay_disabled_service_sets_disabled_snapshot(self):
        mon = _make_monitor()
        mon.is_capturing = False
        core._track_id_service = None

        mon._arm_track_identification_for_replay()
        assert mon._ti_snapshot.state == STATE_DISABLED

    def test_session_started_replay_source_arms_via_dispatch(self):
        """End-to-end through _dispatch_session_event(): a session_started
        event landing on the replay source arms the origin monitor's
        identification cycle."""
        from autostream_core import _dispatch_session_event
        svc = _make_service(analysis_lead_in=5, snapshot=15)
        origin_mon = _make_monitor(input_index=1)
        origin_mon.is_capturing = False  # replay, not live capture
        origin_mon.track_change_seq = 4
        origin_mon._track_change_seq_baseline = 0
        core._track_id_service = svc
        origin_mon._apply_track_id_service(svc)

        with patch.object(core, "_start_session_owntone"), \
             patch.object(origin_mon, "_nowplaying_publisher"):
            _dispatch_session_event(
                "session_started", None, origin_mon, "", new_source="replay",
            )

        assert origin_mon._track_change_seq_baseline == 4
        assert origin_mon._ti_next_attempt_reason == "initial"


# ---------------------------------------------------------------------------
# Setup page markup
# ---------------------------------------------------------------------------

class TestSetupPageMarkup:

    def test_factory_reset_card_has_closing_angle_bracket(self):
        import sys
        from pathlib import Path
        core_path = str(Path(__file__).parent.parent / "core")
        if core_path not in sys.path:
            sys.path.insert(0, core_path)
        import autostream_webui_page_setup as setup_mod
        import inspect
        source = inspect.getsource(setup_mod)
        assert "onclick=\"openPanel('factory-reset')\">" in source, \
            "Factory Reset card tag is missing closing '>'"
        assert "onclick=\"openPanel('factory-reset')\"\n" not in source, \
            "Factory Reset card tag has a bare newline where '>' should be"
