"""Tests for WP4 — track identification scheduling in AudioMonitor.

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
         patch("autostream_core.OwntoneMetadataPipePublisher") as mock_pub_cls:
        mock_cache_cls.return_value.get_manual_hint.return_value = None
        mock_pub_cls.return_value = MagicMock()
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
) -> object:
    """Acquire the gate, install the token, call _ti_worker synchronously, return token."""
    if pcm is None:
        pcm = _DEFAULT_PCM
    if token is None:
        token = object()
    core._track_id_request_gate.acquire()
    mon._ti_inflight = True
    mon._ti_inflight_token = token
    mon._ti_worker(bytes(pcm), rate, token)
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
        mon._on_capture_started(was_idle=False)
        assert mon._ti_next_attempt >= before + 19

    def test_capture_start_without_service_does_not_set_future_next_attempt(self):
        core._track_id_service = None
        mon = _active_monitor()
        mon._on_capture_started(was_idle=False)
        assert mon._ti_next_attempt == 0.0

    def test_capture_start_sets_waiting_snapshot_when_service_present(self):
        svc = _make_service()
        mon = _active_monitor()
        core._track_id_service = svc
        mon._on_capture_started(was_idle=False)
        assert mon._ti_snapshot.state == STATE_WAITING

    def test_capture_start_sets_disabled_snapshot_when_no_service(self):
        core._track_id_service = None
        mon = _active_monitor()
        mon._on_capture_started(was_idle=False)
        assert mon._ti_snapshot.state == STATE_DISABLED

    def test_capture_start_clears_inflight_token(self):
        svc = _make_service()
        mon = _active_monitor()
        core._track_id_service = svc
        mon._ti_inflight = True
        mon._ti_inflight_token = object()
        mon._on_capture_started(was_idle=False)
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
        svc = _make_service(matched=True)
        mon = _active_monitor()
        core._track_id_service = svc
        _run_worker_sync(mon)
        mon._nowplaying_publisher.publish_start.assert_called()

    def test_identified_does_not_publish_when_nowplaying_unchanged(self):
        from autostream_core import NowPlayingMetadata
        svc = _make_service(matched=True)
        mon = _active_monitor()
        core._track_id_service = svc
        mon._current_nowplaying = NowPlayingMetadata(
            title="Test Title", artist="Test Artist", album="Test Album"
        )
        mon._nowplaying_publisher.publish_start.reset_mock()
        _run_worker_sync(mon)
        mon._nowplaying_publisher.publish_start.assert_not_called()

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
        mon._nowplaying_publisher.publish_start.reset_mock()
        _run_worker_sync(mon)
        mon._nowplaying_publisher.publish_start.assert_not_called()

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
        mon._ti_worker(bytes(_DEFAULT_PCM), _DEFAULT_RATE, stale_token)

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
        mon._ti_worker(bytes(_DEFAULT_PCM), _DEFAULT_RATE, stale_token)

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
        mon._ti_worker(bytes(_DEFAULT_PCM), _DEFAULT_RATE, stale_token)

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
        mon._ti_worker(bytes(_DEFAULT_PCM), _DEFAULT_RATE, stale_token)

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
