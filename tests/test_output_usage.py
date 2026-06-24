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
    t.hostname = ""
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
    ou._local_ip_provider = None
    ou._local_hostname_provider = None
    with ou._local_ips_cache_lock:
        ou._local_ips_cache = None
        ou._local_ips_cache_time = 0.0
    # Reset WP2 shutdown state.
    ou._poll_stop_event.clear()
    ou._browser_shutdown = None
    with ou._browser_lock:
        ou._browser = None


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
    def _parts(self, ip="1.2.3.4", port="8080", svc="living-room", hostname="living-room.local"):
        parts = [""] * 10
        parts[3] = svc
        parts[6] = hostname
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

    def test_hostname_stored_from_parts6(self):
        parts = self._parts(hostname="myappliance.local")
        txt = {"dial_api": "v1", "audio_status": "v1"}
        result = ou._parse_playing_target(parts, txt)
        assert result is not None
        _, target = result
        assert target.hostname == "myappliance.local"

    def test_missing_parts6_gives_empty_hostname(self):
        """Short parts list (no index 6) results in empty hostname, not an error."""
        parts = [""] * 9
        parts[3] = "svc"
        parts[7] = "1.2.3.4"
        parts[8] = "8080"
        # parts[6] is "" — avahi always sends it, but guard for robustness
        txt = {"dial_api": "v1", "audio_status": "v1"}
        result = ou._parse_playing_target(parts, txt)
        assert result is not None
        _, target = result
        assert target.hostname == ""

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
# Owner-name derivation
# ---------------------------------------------------------------------------

class TestOwnerName:
    def _make_avahi_target(self, svc: str, hostname: str, ip: str = "192.168.1.2"):
        """Return a _PlayingTarget as _parse_playing_target would produce it."""
        from autostream_output_usage import _PlayingTarget
        return _PlayingTarget(
            service_name=svc,
            ip=ip,
            port=8080,
            name=svc,
            audio_status=True,
            hostname=hostname,
        )

    def test_hostname_used_as_owner_name(self):
        """Hostname (parts[6]) is the authoritative owner label; service name is ignored."""
        clock, _ = _fake_clock()
        ou._clock = clock
        target = self._make_avahi_target(
            svc=r"autostream\032on\032SL-PG4",
            hostname="SL-PG4.local",
        )
        ou._target_provider = lambda: [target]
        ou._http_fetcher = lambda url, timeout: {"playing": True, "outputs": ["Kitchen"]}
        ou._poll_once(3)

        usage = ou.usage_for_output("Kitchen")
        assert usage is not None
        assert usage.owner_name == "SL-PG4"

    def test_service_name_unchanged_as_cache_key(self):
        """service_name on OutputUsage is the raw mDNS instance name, not the display label."""
        clock, _ = _fake_clock()
        ou._clock = clock
        raw_svc = r"autostream\032on\032SL-PG4"
        target = self._make_avahi_target(svc=raw_svc, hostname="SL-PG4.local")
        ou._target_provider = lambda: [target]
        ou._http_fetcher = lambda url, timeout: {"playing": True, "outputs": ["Kitchen"]}
        ou._poll_once(3)

        usage = ou.usage_for_output("Kitchen")
        assert usage is not None
        assert usage.service_name == raw_svc

    def test_annotate_outputs_emits_clean_remote_owner(self):
        """annotate_outputs passes the cleaned hostname through as remote_owner."""
        clock, _ = _fake_clock()
        ou._clock = clock
        target = self._make_avahi_target(
            svc=r"autostream\032on\032SL-PG4",
            hostname="SL-PG4.local",
        )
        ou._target_provider = lambda: [target]
        ou._http_fetcher = lambda url, timeout: {"playing": True, "outputs": ["Kitchen"]}
        ou._poll_once(3)

        annotated = ou.annotate_outputs([{"name": "Kitchen", "selected": False}])
        assert annotated[0]["remote_owner"] == "SL-PG4"

    def test_fallback_decodes_avahi_escape_and_strips_prefix(self):
        """Without a hostname, service name is decoded: \\032→space, 'autostream on ' stripped."""
        clock, _ = _fake_clock()
        ou._clock = clock
        target = self._make_avahi_target(
            svc=r"autostream\032on\032SL-PG4",
            hostname="",
        )
        ou._target_provider = lambda: [target]
        ou._http_fetcher = lambda url, timeout: {"playing": True, "outputs": ["Kitchen"]}
        ou._poll_once(3)

        usage = ou.usage_for_output("Kitchen")
        assert usage is not None
        assert usage.owner_name == "SL-PG4"

    def test_fallback_bare_service_name_returned_as_is(self):
        """A service name with no 'autostream on' prefix is returned decoded but otherwise intact."""
        clock, _ = _fake_clock()
        ou._clock = clock
        target = self._make_avahi_target(svc=r"My\032Appliance", hostname="")
        ou._target_provider = lambda: [target]
        ou._http_fetcher = lambda url, timeout: {"playing": True, "outputs": ["Kitchen"]}
        ou._poll_once(3)

        usage = ou.usage_for_output("Kitchen")
        assert usage is not None
        assert usage.owner_name == "My Appliance"

    def test_local_suffix_stripped_from_hostname(self):
        """Trailing .local is removed from the hostname label."""
        assert ou._derive_owner_name(
            self._make_avahi_target(svc="svc", hostname="myhost.local")
        ) == "myhost"

    def test_hostname_without_local_suffix_used_as_is(self):
        """A hostname that is already bare (no .local) is returned unchanged."""
        assert ou._derive_owner_name(
            self._make_avahi_target(svc="svc", hostname="myhost")
        ) == "myhost"


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

    def test_refresh_now_returns_before_slow_fetchers_finish(self):
        """refresh_now must return within ~timeout even when fetchers are slow."""
        import time as _time
        clock, _ = _fake_clock()
        ou._clock = clock
        target = _make_target()
        ou._target_provider = lambda: [target]

        def _slow_fetcher(url, timeout):
            _time.sleep(0.3)
            return {"playing": True, "outputs": ["Kitchen"]}

        ou._http_fetcher = _slow_fetcher
        start = _time.monotonic()
        ou.refresh_now("test", timeout=0.05)
        elapsed = _time.monotonic() - start
        # Must return well before the 0.3 s fetcher sleep completes.
        assert elapsed < 0.25, f"refresh_now took {elapsed:.3f}s, expected < 0.25s"

    def test_refresh_now_does_not_raise_on_timeout(self):
        """TimeoutError from as_completed must be swallowed, not propagated."""
        import time as _time
        clock, _ = _fake_clock()
        ou._clock = clock
        target = _make_target()
        ou._target_provider = lambda: [target]

        def _slow_fetcher(url, timeout):
            _time.sleep(0.3)
            return {"playing": True, "outputs": ["Kitchen"]}

        ou._http_fetcher = _slow_fetcher
        # Must not raise even with a very tight deadline.
        ou.refresh_now("test", timeout=0.01)


# ---------------------------------------------------------------------------
# Self-target filter
# ---------------------------------------------------------------------------

def _make_target_at(ip: str, name: str = "self", hostname: str = "") -> object:
    """Make a _PlayingTarget-like object at a given IP (and optional mDNS hostname)."""
    from autostream_output_usage import _PlayingTarget
    return _PlayingTarget(service_name=name, ip=ip, port=7070, name=name, audio_status=True, hostname=hostname)


class TestSelfTargetFilter:
    def test_target_with_local_ip_is_excluded_from_poll(self):
        """A target whose IP is in local_ips must not reach the fetcher."""
        ou._local_ip_provider = lambda: frozenset({"192.168.1.10"})
        self_target = _make_target_at("192.168.1.10", "self")
        ou._target_provider = lambda: [self_target]
        fetcher_calls = []
        ou._http_fetcher = lambda url, timeout: (fetcher_calls.append(url), {"playing": True, "outputs": ["Kitchen"]})[1]
        clock, _ = _fake_clock()
        ou._clock = clock
        ou._poll_once(3)
        assert fetcher_calls == [], "self-target must not be fetched"
        assert ou.usage_for_output("Kitchen") is None, "self-target must not populate cache"

    def test_remote_target_with_different_ip_is_not_filtered(self):
        """A target whose IP is not local must still be polled."""
        ou._local_ip_provider = lambda: frozenset({"192.168.1.10"})
        remote_target = _make_target_at("192.168.1.20", "remote")
        ou._target_provider = lambda: [remote_target]
        fetcher_calls = []
        ou._http_fetcher = lambda url, timeout: (fetcher_calls.append(url), {"playing": True, "outputs": ["Kitchen"]})[1]
        clock, _ = _fake_clock()
        ou._clock = clock
        ou._poll_once(3)
        assert fetcher_calls, "remote target must be fetched"
        assert ou.usage_for_output("Kitchen") is not None

    def test_mixed_targets_only_remote_polled(self):
        """When self and remote are both in the target list, only remote is polled."""
        ou._local_ip_provider = lambda: frozenset({"10.0.0.1"})
        self_target = _make_target_at("10.0.0.1", "self")
        remote_target = _make_target_at("10.0.0.2", "remote")
        ou._target_provider = lambda: [self_target, remote_target]
        polled_ips = []
        def fetcher(url, timeout):
            polled_ips.append(url)
            return {"playing": True, "outputs": ["Lounge"]}
        ou._http_fetcher = fetcher
        clock, _ = _fake_clock()
        ou._clock = clock
        ou._poll_once(3)
        assert len(polled_ips) == 1
        assert "10.0.0.1" not in polled_ips[0]
        assert "10.0.0.2" in polled_ips[0]

    def test_self_target_does_not_populate_cache_via_refresh_now(self):
        """refresh_now also filters self-targets."""
        ou._local_ip_provider = lambda: frozenset({"192.168.1.5"})
        self_target = _make_target_at("192.168.1.5")
        ou._target_provider = lambda: [self_target]
        ou._http_fetcher = lambda url, timeout: {"playing": True, "outputs": ["Kitchen"]}
        clock, _ = _fake_clock()
        ou._clock = clock
        ou.refresh_now("test", timeout=1.5)
        assert ou.usage_for_output("Kitchen") is None

    def test_loopback_always_filtered(self):
        """127.0.0.1 is always in the local set and is filtered even without injection."""
        loopback_target = _make_target_at("127.0.0.1", "lo-self")
        ou._target_provider = lambda: [loopback_target]
        fetcher_calls = []
        ou._http_fetcher = lambda url, timeout: (fetcher_calls.append(1), {"playing": True, "outputs": ["Kitchen"]})[1]
        clock, _ = _fake_clock()
        ou._clock = clock
        ou._poll_once(3)
        assert fetcher_calls == [], "loopback target must never be polled"

    def test_empty_local_ips_does_not_filter_any_target(self):
        """If local IP set is empty, no targets are filtered (fail-open)."""
        ou._local_ip_provider = lambda: frozenset()
        remote_target = _make_target_at("192.168.1.20", "remote")
        ou._target_provider = lambda: [remote_target]
        fetcher_calls = []
        ou._http_fetcher = lambda url, timeout: (fetcher_calls.append(1), {"playing": True, "outputs": ["Kitchen"]})[1]
        clock, _ = _fake_clock()
        ou._clock = clock
        ou._poll_once(3)
        assert fetcher_calls == [1], "remote target must not be filtered when local_ips is empty"


# ---------------------------------------------------------------------------
# Hostname-based self-target filter
# ---------------------------------------------------------------------------

class TestSelfHostnameFilter:
    def test_hostname_match_filters_even_with_unknown_ip(self):
        """A target with matching hostname is filtered even if local IP set is empty."""
        ou._local_hostname_provider = lambda: "myappliance"
        ou._local_ip_provider = lambda: frozenset()
        self_target = _make_target_at("192.168.1.10", "self", hostname="myappliance.local")
        ou._target_provider = lambda: [self_target]
        fetcher_calls = []
        ou._http_fetcher = lambda url, timeout: (fetcher_calls.append(url), {"playing": True, "outputs": ["Kitchen"]})[1]
        clock, _ = _fake_clock()
        ou._clock = clock
        ou._poll_once(3)
        assert fetcher_calls == [], "self-target matched by hostname must not be fetched"
        assert ou.usage_for_output("Kitchen") is None

    def test_hostname_filter_strips_local_suffix(self):
        """.local suffix on target hostname is stripped before comparison."""
        ou._local_hostname_provider = lambda: "myappliance"
        ou._local_ip_provider = lambda: frozenset()
        self_target = _make_target_at("192.168.1.10", "self", hostname="myappliance.local")
        remote_target = _make_target_at("192.168.1.20", "remote", hostname="otherappliance.local")
        ou._target_provider = lambda: [self_target, remote_target]
        fetcher_calls = []
        ou._http_fetcher = lambda url, timeout: (fetcher_calls.append(url), {"playing": True, "outputs": ["Kitchen"]})[1]
        clock, _ = _fake_clock()
        ou._clock = clock
        ou._poll_once(3)
        assert len(fetcher_calls) == 1, "only the remote target must be fetched"
        assert "192.168.1.20" in fetcher_calls[0]

    def test_hostname_filter_case_insensitive(self):
        """Hostname comparison is case-insensitive."""
        ou._local_hostname_provider = lambda: "MyAppliance"
        ou._local_ip_provider = lambda: frozenset()
        self_target = _make_target_at("192.168.1.10", "self", hostname="MYAPPLIANCE.local")
        ou._target_provider = lambda: [self_target]
        fetcher_calls = []
        ou._http_fetcher = lambda url, timeout: (fetcher_calls.append(url), {"playing": True, "outputs": ["Kitchen"]})[1]
        clock, _ = _fake_clock()
        ou._clock = clock
        ou._poll_once(3)
        assert fetcher_calls == [], "case difference must not prevent self-filter"

    def test_empty_target_hostname_falls_back_to_ip_filter(self):
        """A target with no hostname is still filtered by IP when IP matches."""
        ou._local_hostname_provider = lambda: "myappliance"
        ou._local_ip_provider = lambda: frozenset({"192.168.1.10"})
        self_target = _make_target_at("192.168.1.10", "self", hostname="")
        ou._target_provider = lambda: [self_target]
        fetcher_calls = []
        ou._http_fetcher = lambda url, timeout: (fetcher_calls.append(url), {"playing": True, "outputs": ["Kitchen"]})[1]
        clock, _ = _fake_clock()
        ou._clock = clock
        ou._poll_once(3)
        assert fetcher_calls == [], "target with no hostname must be filtered by IP fallback"

    def test_empty_local_hostname_disables_hostname_filter(self):
        """Unknown local hostname disables hostname filter; IP filter still applies."""
        ou._local_hostname_provider = lambda: ""
        ou._local_ip_provider = lambda: frozenset()
        target = _make_target_at("192.168.1.10", "remote", hostname="myappliance.local")
        ou._target_provider = lambda: [target]
        fetcher_calls = []
        ou._http_fetcher = lambda url, timeout: (fetcher_calls.append(url), {"playing": True, "outputs": ["Kitchen"]})[1]
        clock, _ = _fake_clock()
        ou._clock = clock
        ou._poll_once(3)
        assert fetcher_calls, "must not filter when local hostname is unknown (fail-open)"

    def test_hostname_filter_reflects_runtime_change(self):
        """Hostname comparison uses the live value each poll; no stale state after a rename."""
        clock, _ = _fake_clock()
        ou._clock = clock
        ou._local_ip_provider = lambda: frozenset()

        # First poll: provider says local hostname is "oldname".
        ou._local_hostname_provider = lambda: "oldname"
        target_old = _make_target_at("192.168.1.10", "self", hostname="oldname.local")
        ou._target_provider = lambda: [target_old]
        fetcher_calls_1 = []
        ou._http_fetcher = lambda url, timeout: (fetcher_calls_1.append(url), {"playing": True, "outputs": []})[1]
        ou._poll_once(3)
        assert fetcher_calls_1 == [], "old-name self-target must be filtered on first poll"

        # Simulate hostname change: provider now returns "newname" (as if sethostname ran).
        ou._local_hostname_provider = lambda: "newname"
        target_new = _make_target_at("192.168.1.10", "self", hostname="newname.local")
        ou._target_provider = lambda: [target_new]
        fetcher_calls_2 = []
        ou._http_fetcher = lambda url, timeout: (fetcher_calls_2.append(url), {"playing": True, "outputs": []})[1]
        ou._poll_once(3)
        assert fetcher_calls_2 == [], "new-name self-target must be filtered on second poll (no stale cache)"

    def test_ip_cache_ttl_expires_and_refreshes(self):
        """_resolve_local_ips refreshes the cache after _LOCAL_IPS_TTL seconds."""
        clock, advance = _fake_clock()
        ou._clock = clock
        # Seed the cache at t=0 with a known-stale value.
        with ou._local_ips_cache_lock:
            ou._local_ips_cache = frozenset({"10.0.0.99"})
            ou._local_ips_cache_time = clock()

        # Within TTL: stale value is returned without re-resolving.
        result = ou._resolve_local_ips()
        assert "10.0.0.99" in result

        # Advance past TTL.
        advance(ou._LOCAL_IPS_TTL + 1.0)

        # After TTL: re-resolve is triggered; cache timestamp advances.
        ou._resolve_local_ips()
        with ou._local_ips_cache_lock:
            updated_time = ou._local_ips_cache_time
        assert updated_time > ou._LOCAL_IPS_TTL, "cache timestamp must advance after TTL expiry"


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


# ---------------------------------------------------------------------------
# WP2: Shutdown awareness (plan section 5)
# ---------------------------------------------------------------------------

class TestShutdownAwareness:
    def test_poll_sleep_interrupted_by_poll_stop_event(self):
        """_interruptible_poll_sleep exits immediately when _poll_stop_event is set."""
        import time as _t
        ou._poll_stop_event.set()
        start = _t.monotonic()
        ou._interruptible_poll_sleep(10.0)
        assert _t.monotonic() - start < 0.5

    def test_poll_sleep_interrupted_by_browser_shutdown(self):
        """_interruptible_poll_sleep exits immediately when _browser_shutdown event is set."""
        import time as _t
        ev = threading.Event()
        ou._browser_shutdown = ev
        ev.set()
        start = _t.monotonic()
        ou._interruptible_poll_sleep(10.0)
        assert _t.monotonic() - start < 0.5

    def test_poll_sleep_runs_full_duration_without_shutdown(self):
        """_interruptible_poll_sleep respects the full deadline when not shut down."""
        import time as _t
        start = _t.monotonic()
        ou._interruptible_poll_sleep(0.15)
        assert _t.monotonic() - start >= 0.13

    def test_get_browser_returns_none_when_shutdown_already_set(self):
        """_get_browser() creates no browser and returns None when shutdown event is set."""
        ev = threading.Event()
        ev.set()
        ou._browser_shutdown = ev
        result = ou._get_browser()
        assert result is None
        with ou._browser_lock:
            assert ou._browser is None

    def test_get_browser_creates_no_browser_after_shutdown_set(self):
        """_get_browser() must not install a new browser after shutdown begins."""
        ev = threading.Event()
        ou._browser_shutdown = ev
        ev.set()
        # Call twice to ensure it stays None.
        ou._get_browser()
        ou._get_browser()
        with ou._browser_lock:
            assert ou._browser is None

    def test_stop_does_not_create_browser_when_none_exists(self):
        """stop() completes without instantiating a browser."""
        with ou._browser_lock:
            assert ou._browser is None
        ou.stop()
        with ou._browser_lock:
            assert ou._browser is None

    def test_stop_delegates_to_existing_browser(self):
        """stop() calls stop() on the underlying browser when one was already created."""
        from unittest.mock import MagicMock
        mock_br = MagicMock()
        with ou._browser_lock:
            ou._browser = mock_br
        ou.stop(timeout=0.5)
        mock_br.stop.assert_called_once()

    def test_stop_joins_poll_thread(self):
        """stop() waits for the poll thread to exit."""
        import time as _t
        thread_started = threading.Event()
        thread_done = threading.Event()

        def slow_poll_loop():
            thread_started.set()
            ou._poll_stop_event.wait(timeout=2.0)
            thread_done.set()

        t = threading.Thread(target=slow_poll_loop, daemon=True)
        t.start()
        thread_started.wait(timeout=1.0)
        with ou._lock:
            ou._poll_thread = t

        ou.stop(timeout=1.0)
        assert thread_done.is_set(), "poll thread must have exited after stop()"
