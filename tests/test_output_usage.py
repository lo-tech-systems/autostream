"""Tests for core/autostream_output_usage.py.

Uses injected clock, target provider, and HTTP fetcher so tests do not
need real threads or sockets.
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_output_usage as ou


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_target(name="living-room", ip="192.168.1.2", port=8080, audio_status=True):
    t = MagicMock()
    t.name = name
    t.ip = ip
    t.port = port
    t.service_name = name
    t.audio_status = audio_status
    return t


def _reset_module():
    """Reset all module-level state between tests."""
    with ou._lock:
        ou._cache.clear()
        ou._poll_interval = 3
        ou._started = False
        ou._poll_thread = None
    ou._target_provider = None
    ou._http_fetcher = None
    ou._clock = None


@pytest.fixture(autouse=True)
def reset_state():
    _reset_module()
    yield
    _reset_module()


def _fake_clock():
    """Returns a mutable clock for injection."""
    state = [0.0]

    def clock():
        return state[0]

    def advance(seconds):
        state[0] += seconds

    return clock, advance


# ---------------------------------------------------------------------------
# _parse_playing_target
# ---------------------------------------------------------------------------

class TestParsePlayingTarget:
    def _parts(self, ip="1.2.3.4", port="8080", svc="living-room"):
        parts = [""] * 10
        parts[3] = svc
        parts[7] = ip
        parts[8] = port
        return parts

    def test_audio_status_v1_and_dial_api_v1_accepted(self):
        parts = self._parts()
        txt = {"dial_api": "v1", "audio_status": "v1"}
        result = ou._parse_playing_target(parts, txt)
        assert result is not None
        key, target = result
        assert key == "living-room"
        assert target.audio_status is True

    def test_missing_dial_api_rejected(self):
        parts = self._parts()
        txt = {"audio_status": "v1"}
        assert ou._parse_playing_target(parts, txt) is None

    def test_wrong_dial_api_version_rejected(self):
        parts = self._parts()
        txt = {"dial_api": "v2", "audio_status": "v1"}
        assert ou._parse_playing_target(parts, txt) is None

    def test_missing_audio_status_rejected(self):
        parts = self._parts()
        txt = {"dial_api": "v1"}
        assert ou._parse_playing_target(parts, txt) is None

    def test_wrong_audio_status_version_rejected(self):
        parts = self._parts()
        txt = {"dial_api": "v1", "audio_status": "v2"}
        assert ou._parse_playing_target(parts, txt) is None

    def test_bad_port_rejected(self):
        parts = self._parts(port="notanumber")
        txt = {"dial_api": "v1", "audio_status": "v1"}
        assert ou._parse_playing_target(parts, txt) is None


# ---------------------------------------------------------------------------
# Cache and usage service tests
# ---------------------------------------------------------------------------

class TestOutputUsageCache:
    def test_playing_true_with_outputs_creates_entry(self):
        clock, advance = _fake_clock()
        ou._clock = clock
        target = _make_target(name="lr")

        def fetcher(url, timeout):
            return {"playing": True, "outputs": ["Kitchen"]}

        ou._http_fetcher = fetcher
        ou._target_provider = lambda: [target]
        ou._poll_once(3)

        snap = ou.get_usage_snapshot()
        assert "kitchen" in snap
        assert snap["kitchen"].owner_name == "lr"

    def test_playing_false_creates_no_entry(self):
        clock, _ = _fake_clock()
        ou._clock = clock
        target = _make_target()

        ou._http_fetcher = lambda url, timeout: {"playing": False, "outputs": ["Kitchen"]}
        ou._target_provider = lambda: [target]
        ou._poll_once(3)

        assert ou.get_usage_snapshot() == {}

    def test_outputs_null_creates_no_entry(self):
        clock, _ = _fake_clock()
        ou._clock = clock
        target = _make_target()

        ou._http_fetcher = lambda url, timeout: {"playing": True, "outputs": None}
        ou._target_provider = lambda: [target]
        ou._poll_once(3)

        assert ou.get_usage_snapshot() == {}

    def test_outputs_empty_list_creates_no_entry(self):
        clock, _ = _fake_clock()
        ou._clock = clock
        target = _make_target()

        ou._http_fetcher = lambda url, timeout: {"playing": True, "outputs": []}
        ou._target_provider = lambda: [target]
        ou._poll_once(3)

        assert ou.get_usage_snapshot() == {}

    def test_malformed_json_fails_open(self):
        clock, _ = _fake_clock()
        ou._clock = clock
        target = _make_target()

        def bad_fetcher(url, timeout):
            raise ValueError("bad json")

        ou._http_fetcher = bad_fetcher
        ou._target_provider = lambda: [target]
        ou._poll_once(3)  # must not raise

        assert ou.get_usage_snapshot() == {}

    def test_connection_error_fails_open(self):
        clock, _ = _fake_clock()
        ou._clock = clock
        target = _make_target()

        def conn_err(url, timeout):
            raise ConnectionRefusedError("refused")

        ou._http_fetcher = conn_err
        ou._target_provider = lambda: [target]
        ou._poll_once(3)

        assert ou.get_usage_snapshot() == {}

    def test_timeout_error_fails_open(self):
        clock, _ = _fake_clock()
        ou._clock = clock
        target = _make_target()

        def timeout_err(url, timeout):
            raise TimeoutError("timeout")

        ou._http_fetcher = timeout_err
        ou._target_provider = lambda: [target]
        ou._poll_once(3)

        assert ou.get_usage_snapshot() == {}

    def test_entry_expires_after_ttl(self):
        clock, advance = _fake_clock()
        ou._clock = clock
        target = _make_target()

        ou._http_fetcher = lambda url, timeout: {"playing": True, "outputs": ["Kitchen"]}
        ou._target_provider = lambda: [target]
        ou._poll_once(3)

        assert "kitchen" in ou.get_usage_snapshot()

        # Advance past TTL (max(2*3+1, 5) = 7 seconds)
        advance(8.0)
        assert "kitchen" not in ou.get_usage_snapshot()

    def test_name_matching_case_insensitive(self):
        clock, _ = _fake_clock()
        ou._clock = clock
        target = _make_target()

        ou._http_fetcher = lambda url, timeout: {"playing": True, "outputs": ["KITCHEN"]}
        ou._target_provider = lambda: [target]
        ou._poll_once(3)

        assert ou.usage_for_output("kitchen") is not None
        assert ou.usage_for_output("Kitchen") is not None
        assert ou.usage_for_output("KITCHEN") is not None

    def test_usage_for_output_returns_none_for_unknown(self):
        assert ou.usage_for_output("NonExistent") is None

    def test_is_output_in_use_elsewhere_true(self):
        clock, _ = _fake_clock()
        ou._clock = clock
        target = _make_target()

        ou._http_fetcher = lambda url, timeout: {"playing": True, "outputs": ["Kitchen"]}
        ou._target_provider = lambda: [target]
        ou._poll_once(3)

        assert ou.is_output_in_use_elsewhere("Kitchen") is True
        assert ou.is_output_in_use_elsewhere("Living Room") is False


# ---------------------------------------------------------------------------
# State-transition logging
# ---------------------------------------------------------------------------

class TestTransitionLogging:
    def test_appearance_logged_at_info(self, caplog):
        clock, _ = _fake_clock()
        ou._clock = clock
        target = _make_target(name="lr")

        ou._http_fetcher = lambda url, timeout: {"playing": True, "outputs": ["Kitchen"]}
        ou._target_provider = lambda: [target]

        with caplog.at_level("INFO", logger="autostream_output_usage"):
            ou._poll_once(3)

        assert any("Kitchen now in use by lr" in r.message for r in caplog.records)

    def test_appearance_not_relogged_on_second_poll(self, caplog):
        clock, _ = _fake_clock()
        ou._clock = clock
        target = _make_target(name="lr")

        ou._http_fetcher = lambda url, timeout: {"playing": True, "outputs": ["Kitchen"]}
        ou._target_provider = lambda: [target]

        with caplog.at_level("INFO", logger="autostream_output_usage"):
            ou._poll_once(3)
            caplog.clear()
            ou._poll_once(3)

        # Second poll should NOT re-log the appearance
        assert not any("now in use" in r.message for r in caplog.records)

    def test_clear_logged_when_target_stops_reporting(self, caplog):
        clock, advance = _fake_clock()
        ou._clock = clock
        target = _make_target(name="lr")

        ou._http_fetcher = lambda url, timeout: {"playing": True, "outputs": ["Kitchen"]}
        ou._target_provider = lambda: [target]
        ou._poll_once(3)

        # Now target reports no outputs
        ou._http_fetcher = lambda url, timeout: {"playing": True, "outputs": ["Bedroom"]}

        with caplog.at_level("INFO", logger="autostream_output_usage"):
            ou._poll_once(3)

        assert any("Kitchen no longer in use" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Poll interval normalization
# ---------------------------------------------------------------------------

class TestPollIntervalNormalization:
    def test_default_is_3(self):
        assert ou._poll_interval == 3

    def test_configure_valid_value(self):
        ou.configure(10)
        assert ou._poll_interval == 10

    def test_configure_below_min_normalizes(self):
        ou.configure(0)
        assert ou._poll_interval == 3

    def test_configure_above_max_normalizes(self):
        ou.configure(100)
        assert ou._poll_interval == 3

    def test_configure_min_boundary(self):
        ou.configure(1)
        assert ou._poll_interval == 1

    def test_configure_max_boundary(self):
        ou.configure(30)
        assert ou._poll_interval == 30

    def test_configure_invalid_string_normalizes(self, caplog):
        with caplog.at_level("WARNING", logger="autostream_output_usage"):
            ou.configure("bad")  # type: ignore
        assert ou._poll_interval == 3


# ---------------------------------------------------------------------------
# Concurrent fetch cap
# ---------------------------------------------------------------------------

class TestConcurrentFetchCap:
    def test_concurrent_fetches_capped_at_4(self):
        clock, _ = _fake_clock()
        ou._clock = clock
        targets = [_make_target(name=f"t{i}", ip=f"10.0.0.{i}") for i in range(6)]
        concurrent = [0]
        peak = [0]
        gate = threading.Semaphore(0)
        done_ev = threading.Event()

        def slow_fetcher(url, timeout):
            concurrent[0] += 1
            if concurrent[0] > peak[0]:
                peak[0] = concurrent[0]
            gate.acquire()
            concurrent[0] -= 1
            return {"playing": True, "outputs": ["Kitchen"]}

        ou._http_fetcher = slow_fetcher
        ou._target_provider = lambda: list(targets)

        def run_poll():
            ou._poll_once(3)
            done_ev.set()

        # Run poll in a background thread
        t = threading.Thread(target=run_poll, daemon=True)
        t.start()

        # Let all threads hit the gate
        time.sleep(0.1)
        # Release them all
        for _ in range(6):
            gate.release()
        done_ev.wait(timeout=5.0)

        assert peak[0] <= 4, f"Peak concurrent fetches {peak[0]} exceeded cap of 4"

    def test_no_lock_held_during_http(self):
        """Verify cache lock is not held while performing HTTP work."""
        clock, _ = _fake_clock()
        ou._clock = clock
        target = _make_target()
        lock_held_during_fetch = [False]

        def checking_fetcher(url, timeout):
            # Try to acquire the lock; if it's free, HTTP is running outside it.
            acquired = ou._lock.acquire(blocking=False)
            lock_held_during_fetch[0] = not acquired
            if acquired:
                ou._lock.release()
            return {"playing": True, "outputs": ["Kitchen"]}

        ou._http_fetcher = checking_fetcher
        ou._target_provider = lambda: [target]
        ou._poll_once(3)

        assert not lock_held_during_fetch[0], "Cache lock must not be held during HTTP fetch"


# ---------------------------------------------------------------------------
# refresh_now
# ---------------------------------------------------------------------------

class TestRefreshNow:
    def test_refresh_now_updates_cache(self):
        clock, _ = _fake_clock()
        ou._clock = clock
        target = _make_target()

        ou._http_fetcher = lambda url, timeout: {"playing": True, "outputs": ["Kitchen"]}
        ou._target_provider = lambda: [target]
        ou.refresh_now("test", timeout=1.5)

        assert ou.is_output_in_use_elsewhere("Kitchen") is True

    def test_refresh_now_respects_timeout(self):
        clock, _ = _fake_clock()
        ou._clock = clock
        target = _make_target()
        call_timeouts = []

        def recording_fetcher(url, timeout):
            call_timeouts.append(timeout)
            return {"playing": True, "outputs": []}

        ou._http_fetcher = recording_fetcher
        ou._target_provider = lambda: [target]
        ou.refresh_now("test", timeout=0.5)

        assert call_timeouts, "fetcher should be called"
        for t in call_timeouts:
            assert t <= 0.5

    def test_refresh_now_with_no_targets_is_noop(self):
        ou._target_provider = lambda: []
        ou.refresh_now("test")  # must not raise


# ---------------------------------------------------------------------------
# annotate_outputs
# ---------------------------------------------------------------------------

class TestAnnotateOutputs:
    def test_annotates_unselected_matching_output(self):
        clock, _ = _fake_clock()
        ou._clock = clock
        target = _make_target(name="lr")

        ou._http_fetcher = lambda url, timeout: {"playing": True, "outputs": ["Kitchen"]}
        ou._target_provider = lambda: [target]
        ou._poll_once(3)

        outputs = [{"id": "1", "name": "Kitchen", "selected": False, "volume": 50}]
        result = ou.annotate_outputs(outputs)
        assert result[0]["remote_in_use"] is True
        assert result[0]["remote_owner"] == "lr"

    def test_does_not_mark_selected_output_in_use(self):
        clock, _ = _fake_clock()
        ou._clock = clock
        target = _make_target(name="lr")

        ou._http_fetcher = lambda url, timeout: {"playing": True, "outputs": ["Kitchen"]}
        ou._target_provider = lambda: [target]
        ou._poll_once(3)

        outputs = [{"id": "1", "name": "Kitchen", "selected": True, "volume": 50}]
        result = ou.annotate_outputs(outputs)
        assert result[0]["remote_in_use"] is False

    def test_unoccupied_output_has_false_fields(self):
        outputs = [{"id": "2", "name": "Living Room", "selected": False}]
        result = ou.annotate_outputs(outputs)
        assert result[0]["remote_in_use"] is False
        assert result[0]["remote_owner"] == ""
        assert result[0]["remote_owner_service"] == ""

    def test_does_not_mutate_input_dicts(self):
        outputs = [{"id": "1", "name": "Kitchen", "selected": False}]
        original = dict(outputs[0])
        ou.annotate_outputs(outputs)
        assert outputs[0] == original

    def test_annotate_does_not_call_refresh(self):
        refresh_called = []
        orig = ou.refresh_now

        ou.refresh_now = lambda *a, **kw: refresh_called.append(True)
        try:
            ou.annotate_outputs([{"id": "1", "name": "Kitchen", "selected": False}])
        finally:
            ou.refresh_now = orig

        assert not refresh_called, "annotate_outputs must not call refresh_now"


# ---------------------------------------------------------------------------
# Multiple owners for same output
# ---------------------------------------------------------------------------

class TestMultipleOwners:
    def test_last_writer_wins_for_same_output(self, caplog):
        clock, _ = _fake_clock()
        ou._clock = clock
        target_a = _make_target(name="lr", ip="10.0.0.1", port=8080)
        target_b = _make_target(name="br", ip="10.0.0.2", port=8080)

        call_count = [0]

        def fetcher(url, timeout):
            call_count[0] += 1
            return {"playing": True, "outputs": ["Kitchen"]}

        ou._http_fetcher = fetcher
        ou._target_provider = lambda: [target_a, target_b]

        with caplog.at_level("DEBUG", logger="autostream_output_usage"):
            ou._poll_once(3)

        # One of the owners wins; both make a claim
        usage = ou.usage_for_output("Kitchen")
        assert usage is not None
        assert usage.owner_name in ("lr", "br")


# ---------------------------------------------------------------------------
# outputs:null does not clear previous usage
# ---------------------------------------------------------------------------

class TestNullOutputsPreservesCache:
    def test_null_outputs_does_not_clear_existing_entry(self):
        clock, advance = _fake_clock()
        ou._clock = clock
        target = _make_target(name="lr")

        ou._http_fetcher = lambda url, timeout: {"playing": True, "outputs": ["Kitchen"]}
        ou._target_provider = lambda: [target]
        ou._poll_once(3)
        assert ou.is_output_in_use_elsewhere("Kitchen")

        # Second poll: null outputs (unknown state)
        ou._http_fetcher = lambda url, timeout: {"playing": True, "outputs": None}
        ou._poll_once(3)

        # Entry should still be there (not expired yet)
        assert ou.is_output_in_use_elsewhere("Kitchen")
