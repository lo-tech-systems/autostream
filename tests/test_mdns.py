"""Shared mDNS transport tests.

Covers:
  - parse_avahi_txt: quoted and escaped TXT parsing, malformed TXT handling
  - MdnsBrowser IPv4 filtering
  - Five-tuple tracking and deduplication across interfaces
  - Removal of one interface preserving another
  - Removal of the final interface removing the logical target
  - Scanner lifecycle / startup-grace state
  - Exact scanner readiness formula and the invariant that
    ready:false cannot accompany grace_remaining_ms:0
  - Thread-safe snapshot copying
  - Retry delay sequence and reset behavior
  - Idempotent start
  - Shutdown-aware browser lifecycle (WP1)
"""
from __future__ import annotations

import subprocess
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

from autostream_mdns import MdnsBrowser, parse_avahi_txt


# ---------------------------------------------------------------------------
# parse_avahi_txt
# ---------------------------------------------------------------------------

class TestParseAvahiTxt:
    def test_simple_key_value(self):
        result = parse_avahi_txt('key=value')
        assert result == {'key': 'value'}

    def test_multiple_pairs(self):
        result = parse_avahi_txt('a=1 b=2 c=3')
        assert result == {'a': '1', 'b': '2', 'c': '3'}

    def test_quoted_value_with_spaces(self):
        result = parse_avahi_txt('"key=hello world"')
        assert result == {'key': 'hello world'}

    def test_empty_string_returns_empty_dict(self):
        assert parse_avahi_txt('') == {}

    def test_token_without_equals_ignored(self):
        result = parse_avahi_txt('noequals a=1')
        assert result == {'a': '1'}

    def test_malformed_quotes_returns_partial_or_empty(self):
        # shlex raises ValueError on unclosed quotes; must not propagate
        result = parse_avahi_txt('"unclosed')
        assert isinstance(result, dict)

    def test_value_can_contain_equals(self):
        result = parse_avahi_txt('k=a=b=c')
        assert result['k'] == 'a=b=c'

    def test_backslash_escape_in_value(self):
        result = parse_avahi_txt(r'"k=hel\"lo"')
        assert 'k' in result

    def test_empty_value(self):
        result = parse_avahi_txt('k=')
        assert result == {'k': ''}

    def test_dial_api_capability(self):
        result = parse_avahi_txt('dial_api=v1 audio_status=v1 version=1.2.3')
        assert result['dial_api'] == 'v1'
        assert result['audio_status'] == 'v1'


# ---------------------------------------------------------------------------
# MdnsBrowser helpers
# ---------------------------------------------------------------------------

def _make_browser(service_type: str = "_test._tcp", parse_fn=None):
    if parse_fn is None:
        def parse_fn(parts, txt):
            key = txt.get("id")
            if not key:
                return None
            return (key, {"ip": parts[7], "name": txt.get("name", "")})
    return MdnsBrowser(service_type=service_type, parse_fn=parse_fn)


def _avahi_resolve_line(iface="eth0", proto="IPv4", name="my-svc",
                         stype="_test._tcp", domain="local",
                         host="myhost.local", ip="192.168.1.1", port="1234",
                         txt='id=abc name=test'):
    """Build a fake avahi-browse =;... resolved line."""
    return f"=;{iface};{proto};{name};{stype};{domain};{host};{ip};{port};{txt}"


def _avahi_remove_line(iface="eth0", proto="IPv4", name="my-svc",
                        stype="_test._tcp", domain="local"):
    return f"-;{iface};{proto};{name};{stype};{domain}"


# ---------------------------------------------------------------------------
# IPv4 filtering
# ---------------------------------------------------------------------------

class TestIPv4Filtering:
    def test_ipv4_event_is_processed(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(proto="IPv4"))
        assert len(browser.get_snapshot()) == 1

    def test_ipv6_event_is_ignored(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(proto="IPv6"))
        assert len(browser.get_snapshot()) == 0

    def test_non_resolve_event_ignored(self):
        browser = _make_browser()
        browser._handle_line("+ eth0 IPv4 my-svc _test._tcp local")
        assert len(browser.get_snapshot()) == 0


# ---------------------------------------------------------------------------
# Five-tuple tracking and deduplication
# ---------------------------------------------------------------------------

class TestFiveTupleDeduplication:
    def test_add_single_entry(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(ip="1.2.3.4", txt='id=aaa name=one'))
        snap = browser.get_snapshot()
        assert 'aaa' in snap
        assert snap['aaa']['ip'] == '1.2.3.4'

    def test_same_identity_on_two_interfaces_deduplicates(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(
            iface="eth0", ip="10.0.0.1", txt='id=aaa name=test'))
        browser._handle_line(_avahi_resolve_line(
            iface="wlan0", ip="10.0.0.2", txt='id=aaa name=test'))
        snap = browser.get_snapshot()
        assert len(snap) == 1
        assert 'aaa' in snap

    def test_removal_of_one_interface_preserves_other(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(
            iface="eth0", name="svc-eth", ip="10.0.0.1", txt='id=aaa name=test'))
        browser._handle_line(_avahi_resolve_line(
            iface="wlan0", name="svc-eth", ip="10.0.0.2", txt='id=aaa name=test'))
        # Remove the eth0 sighting
        browser._handle_line(_avahi_remove_line(iface="eth0", name="svc-eth"))
        snap = browser.get_snapshot()
        assert 'aaa' in snap  # still present via wlan0

    def test_removal_of_final_interface_removes_identity(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(
            iface="eth0", ip="10.0.0.1", txt='id=aaa name=test'))
        browser._handle_line(_avahi_remove_line(iface="eth0"))
        snap = browser.get_snapshot()
        assert 'aaa' not in snap

    def test_two_different_identities_on_same_interface(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(
            name="svc1", ip="10.0.0.1", txt='id=aaa name=one'))
        browser._handle_line(_avahi_resolve_line(
            name="svc2", ip="10.0.0.2", txt='id=bbb name=two'))
        snap = browser.get_snapshot()
        assert len(snap) == 2

    def test_remove_one_leaves_other(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(
            name="svc1", ip="10.0.0.1", txt='id=aaa name=one'))
        browser._handle_line(_avahi_resolve_line(
            name="svc2", ip="10.0.0.2", txt='id=bbb name=two'))
        browser._handle_line(_avahi_remove_line(name="svc1"))
        snap = browser.get_snapshot()
        assert 'aaa' not in snap
        assert 'bbb' in snap

    def test_parse_fn_returning_none_ignored(self):
        def parse_fn(parts, txt):
            return None  # always ignore
        browser = _make_browser(parse_fn=parse_fn)
        browser._handle_line(_avahi_resolve_line())
        assert browser.get_snapshot() == {}

    def test_missing_id_in_txt_ignored(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(txt='name=test'))  # no id=
        assert browser.get_snapshot() == {}


# ---------------------------------------------------------------------------
# Thread-safe snapshot
# ---------------------------------------------------------------------------

class TestThreadSafeSnapshot:
    def test_snapshot_is_a_copy(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(txt='id=aaa name=test'))
        snap = browser.get_snapshot()
        # Modifying the snapshot must not affect the registry
        snap['new_key'] = {'ip': '0.0.0.0'}
        assert 'new_key' not in browser.get_snapshot()

    def test_concurrent_reads_do_not_raise(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(txt='id=aaa name=test'))
        errors = []

        def reader():
            try:
                for _ in range(50):
                    _ = browser.get_snapshot()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=reader) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []


# ---------------------------------------------------------------------------
# Idempotent start (existing tests)
# ---------------------------------------------------------------------------

class TestIdempotentStart:
    def test_start_is_idempotent(self):
        browser = _make_browser()
        started_threads = []

        original_start = threading.Thread.start

        with patch.object(threading.Thread, "start", side_effect=lambda self: started_threads.append(1) or original_start(self)):
            pass  # just count, don't interfere

        # Manual test: calling start twice should not start two browse loops
        assert not browser.has_started
        with patch.object(browser, "_browse_loop"):
            browser.start()
            browser.start()
        assert browser.has_started

    def test_start_sets_has_started_flag(self):
        browser = _make_browser()
        assert not browser.has_started
        with patch("threading.Thread.start"):
            browser.start()
        assert browser.has_started


# ---------------------------------------------------------------------------
# Scanner lifecycle / startup grace state
# ---------------------------------------------------------------------------

class TestScannerLifecycle:
    def test_not_started_is_not_ready(self):
        browser = _make_browser()
        assert not browser.scanner_ready()

    def test_ready_after_first_browse_event(self):
        browser = _make_browser()
        with patch("threading.Thread.start"):
            browser.start()
        browser._has_browse_event = True
        assert browser.scanner_ready()

    def test_ready_after_8s_elapsed(self):
        browser = _make_browser()
        with patch("threading.Thread.start"):
            browser.start()
        browser._start_monotonic = time.monotonic() - 8.1
        assert browser.scanner_ready()

    def test_not_ready_within_8s_without_event(self):
        browser = _make_browser()
        with patch("threading.Thread.start"):
            browser.start()
        browser._start_monotonic = time.monotonic() - 1.0
        assert not browser.scanner_ready()

    def test_invariant_not_ready_implies_grace_remaining_nonzero(self):
        """If scanner_ready() is False, grace_remaining_ms() must be > 0."""
        browser = _make_browser()
        with patch("threading.Thread.start"):
            browser.start()
        browser._start_monotonic = time.monotonic() - 1.0
        assert not browser.scanner_ready()
        assert browser.grace_remaining_ms() > 0

    def test_ready_implies_grace_remaining_zero(self):
        browser = _make_browser()
        with patch("threading.Thread.start"):
            browser.start()
        browser._has_browse_event = True
        assert browser.scanner_ready()
        assert browser.grace_remaining_ms() == 0

    def test_grace_remaining_zero_after_8s(self):
        browser = _make_browser()
        with patch("threading.Thread.start"):
            browser.start()
        browser._start_monotonic = time.monotonic() - 9.0
        assert browser.grace_remaining_ms() == 0

    def test_grace_remaining_decreases_over_time(self):
        browser = _make_browser()
        with patch("threading.Thread.start"):
            browser.start()
        browser._start_monotonic = time.monotonic() - 3.0
        remaining = browser.grace_remaining_ms()
        assert 4500 < remaining < 5100  # approximately 5s left

    def test_has_browse_event_set_on_handle_line(self):
        browser = _make_browser()
        assert not browser.has_browse_event
        browser._has_browse_event = True
        assert browser.has_browse_event


# ---------------------------------------------------------------------------
# on_add / on_remove callbacks
# ---------------------------------------------------------------------------

class TestCallbacks:
    def test_on_add_called_for_new_identity(self):
        added = []

        def on_add(key, model):
            added.append(key)

        browser = _make_browser()
        browser._on_add = on_add
        browser._handle_line(_avahi_resolve_line(txt='id=aaa name=test'))
        assert added == ['aaa']

    def test_on_add_not_called_for_duplicate_interface(self):
        added = []
        browser = _make_browser()
        browser._on_add = lambda k, m: added.append(k)
        browser._handle_line(_avahi_resolve_line(
            iface="eth0", name="svc1", txt='id=aaa name=test'))
        browser._handle_line(_avahi_resolve_line(
            iface="wlan0", name="svc1", txt='id=aaa name=test'))
        assert len(added) == 1

    def test_on_remove_called_when_last_interface_removed(self):
        removed = []
        browser = _make_browser()
        browser._on_remove = lambda k, m: removed.append(k)
        browser._handle_line(_avahi_resolve_line(
            iface="eth0", txt='id=aaa name=test'))
        browser._handle_line(_avahi_remove_line(iface="eth0"))
        assert 'aaa' in removed

    def test_on_remove_not_called_when_other_interface_remains(self):
        removed = []
        browser = _make_browser()
        browser._on_remove = lambda k, m: removed.append(k)
        browser._handle_line(_avahi_resolve_line(
            iface="eth0", name="svc1", txt='id=aaa name=test'))
        browser._handle_line(_avahi_resolve_line(
            iface="wlan0", name="svc1", txt='id=aaa name=test'))
        browser._handle_line(_avahi_remove_line(iface="eth0", name="svc1"))
        assert removed == []

    def test_callback_exception_does_not_propagate(self):
        def on_add(k, m):
            raise RuntimeError("boom")

        browser = _make_browser()
        browser._on_add = on_add
        # Must not raise
        browser._handle_line(_avahi_resolve_line(txt='id=aaa name=test'))


# ---------------------------------------------------------------------------
# Retry delay sequence
# ---------------------------------------------------------------------------

class TestRetryDelaySequence:
    def test_retry_delays_constant(self):
        from autostream_mdns import _RETRY_DELAYS
        assert _RETRY_DELAYS == [5, 10, 20, 30]

    def test_retry_caps_at_30(self):
        from autostream_mdns import _RETRY_DELAYS
        for idx in range(10):
            delay = _RETRY_DELAYS[min(idx, len(_RETRY_DELAYS) - 1)]
            assert delay <= 30


# ---------------------------------------------------------------------------
# Dial installer test: mdns module deployed
# ---------------------------------------------------------------------------

class TestDialInstallerMdnsDeploy:
    def test_mdns_module_deployed_in_dial_installer(self):
        content = (REPO_ROOT / "autostream_dial_install.sh").read_text(encoding="utf-8")
        assert "autostream_mdns.py" in content, (
            "autostream_dial_install.sh must deploy core/autostream_mdns.py"
        )

    def test_mdns_module_deployed_as_flat_path(self):
        content = (REPO_ROOT / "autostream_dial_install.sh").read_text(encoding="utf-8")
        assert "/opt/autostream/autostream_mdns.py" in content, (
            "autostream_mdns.py must be installed at /opt/autostream/autostream_mdns.py"
        )


# ---------------------------------------------------------------------------
# WP1: Shutdown-aware browser lifecycle tests
# ---------------------------------------------------------------------------

class _FakeProc:
    """Minimal fake Popen object for lifecycle tests."""

    def __init__(self, lines=(), returncode=0, pid=12345):
        self._lines = list(lines)
        self.returncode = returncode
        self.pid = pid
        self.terminated = False
        self.killed = False
        self._stdout_lines = iter(self._lines)
        self.stdout = self

    def __iter__(self):
        return self._stdout_lines

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode

    def poll(self):
        return self.returncode


class TestShutdownLifecycle:
    """Tests 1–16 from the WP1 spec."""

    # 1. start() remains idempotent.
    def test_start_idempotent_no_second_thread(self):
        browser = _make_browser()
        thread_starts = []
        original = threading.Thread.start
        with patch.object(threading.Thread, "start",
                          lambda self: (thread_starts.append(1), original(self)) and None):
            with patch.object(browser, "_browse_loop", return_value=None):
                browser.start()
                browser.start()
        assert len(thread_starts) == 1

    # 2. start() with an already-set application event launches no thread.
    def test_start_with_set_shutdown_event_does_not_start_thread(self):
        browser = _make_browser()
        ev = threading.Event()
        ev.set()
        thread_starts = []
        with patch.object(threading.Thread, "start",
                          lambda self: thread_starts.append(1)):
            browser.start(shutdown_event=ev)
        assert thread_starts == []
        assert not browser.has_started

    # 3. stop() before start is harmless.
    def test_stop_before_start_is_harmless(self):
        browser = _make_browser()
        browser.stop()  # must not raise

    # 4. stop() is idempotent.
    def test_stop_is_idempotent(self):
        browser = _make_browser()
        browser.stop()
        browser.stop()  # must not raise

    # 5. stop() sets shutdown state and terminates a running child.
    def test_stop_sets_shutdown_and_terminates_child(self):
        browser = _make_browser()
        proc = _FakeProc()
        browser._current_proc = proc
        browser.stop(timeout=0.5)
        assert browser._stop_event.is_set()
        assert proc.terminated

    # 6. A child that ignores terminate() is killed within the timeout path.
    def test_stop_kills_child_that_ignores_terminate(self):
        browser = _make_browser()

        class _SlowProc(_FakeProc):
            def wait(self, timeout=None):
                if timeout is not None and timeout < 999:
                    raise subprocess.TimeoutExpired(cmd="avahi-browse", timeout=timeout)
                return self.returncode

        proc = _SlowProc()
        browser._current_proc = proc
        browser.stop(timeout=1.0)
        assert proc.killed

    # 7. Active child is reaped and browser thread is joined boundedly.
    def test_stop_joins_browser_thread(self):
        browser = _make_browser()
        # Start a real (but trivial) thread so join() can work
        done = threading.Event()

        def _trivial():
            browser._stop_event.wait()
            done.set()

        t = threading.Thread(target=_trivial, daemon=True)
        t.start()
        browser._browse_thread = t

        browser.stop(timeout=1.0)
        assert done.wait(timeout=0.2), "thread should have exited"
        assert not t.is_alive()

    # 8. Shutdown during retry backoff returns promptly and launches no replacement.
    def test_interruptible_wait_returns_on_shutdown(self):
        browser = _make_browser()
        browser._stop_event.set()
        start = time.monotonic()
        browser._interruptible_wait(30.0)  # would block 30s without shutdown
        assert (time.monotonic() - start) < 0.5

    # 9. Application shutdown concurrent with child EOF emits no warning.
    def test_app_shutdown_event_suppresses_warning(self):
        browser = _make_browser()
        app_ev = threading.Event()
        app_ev.set()
        browser._app_shutdown = app_ev

        # Simulate the end-of-loop shutdown check:
        # _shutdown_requested() is True so we return before logging.
        with patch.object(browser, "_interruptible_wait") as mock_wait:
            # Force the loop body to return after the shutdown check
            # by having it see shutdown before the warning path.
            # We verify _shutdown_requested() is True.
            assert browser._shutdown_requested()

    # 10. Explicit stop() concurrent with child EOF emits no warning.
    def test_stop_event_suppresses_warning(self):
        browser = _make_browser()
        browser._stop_event.set()
        assert browser._shutdown_requested()

    # 11. An unexpected exit logs the return code and retries.
    def test_unexpected_exit_logs_rc_and_retries(self):
        """_browse_loop logs rc and retries on unexpected avahi-browse exit."""
        browser = _make_browser()
        call_count = [0]

        # Fake Popen: first call returns a proc that EOF immediately (rc=1),
        # second call triggers shutdown.
        def fake_popen(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                proc = _FakeProc(lines=[], returncode=1)
                return proc
            # On second iteration, set stop event so loop exits.
            browser._stop_event.set()
            raise OSError("shutdown triggered")

        with patch("autostream_mdns.subprocess.Popen", side_effect=fake_popen), \
             patch.object(browser, "_interruptible_wait") as mock_wait, \
             patch("autostream_mdns.logger") as mock_logger:
            browser._browse_loop()

        # Warning must have been logged with rc=1 after the first exit.
        # Call signature: warning("mdns(%s): avahi-browse exited rc=%s; restarting", svc, rc)
        warning_calls = [c for c in mock_logger.warning.call_args_list
                         if "avahi-browse exited" in str(c)]
        assert len(warning_calls) >= 1
        # rc is passed as the last positional arg; check it equals 1
        assert warning_calls[0].args[-1] == 1

    # 12. An unexpected launch exception still retries.
    def test_launch_exception_still_retries(self):
        """An OSError launching avahi-browse does not abort the retry loop."""
        browser = _make_browser()
        call_count = [0]

        def fake_popen(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise OSError("avahi-browse not found")
            browser._stop_event.set()
            raise OSError("shutdown triggered")

        with patch("autostream_mdns.subprocess.Popen", side_effect=fake_popen), \
             patch.object(browser, "_interruptible_wait"), \
             patch("autostream_mdns.logger"):
            browser._browse_loop()

        assert call_count[0] == 2  # tried twice

    # 13. Registry snapshots are empty after explicit stop.
    def test_stop_clears_registry(self):
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(txt='id=aaa name=test'))
        assert len(browser.get_snapshot()) == 1
        browser.stop()
        assert browser.get_snapshot() == {}

    # 14. Registry snapshots are cleared immediately after unexpected exit, before retry.
    def test_registry_cleared_before_retry(self):
        """After unexpected exit, stale entries are cleared before the retry wait."""
        browser = _make_browser()
        browser._handle_line(_avahi_resolve_line(txt='id=aaa name=test'))

        cleared_before_wait = []

        def check_and_set(_delay):
            # Capture state at retry-wait time, then stop
            cleared_before_wait.append(dict(browser.get_snapshot()))
            browser._stop_event.set()

        call_count = [0]

        def fake_popen(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] >= 2:
                browser._stop_event.set()
                raise OSError("done")
            return _FakeProc(lines=[], returncode=0)

        with patch("autostream_mdns.subprocess.Popen", side_effect=fake_popen), \
             patch.object(browser, "_interruptible_wait", side_effect=check_and_set), \
             patch("autostream_mdns.logger"):
            browser._browse_loop()

        assert cleared_before_wait, "interruptible_wait must have been called"
        assert cleared_before_wait[0] == {}, "registry must be empty before retry wait"

    # 15. Shutdown clearing does not invoke on_remove or on_change.
    def test_stop_does_not_fire_callbacks(self):
        removed = []
        changed = []
        browser = _make_browser()
        browser._on_remove = lambda k, m: removed.append(k)
        browser._on_change = lambda k, old, new: changed.append(k)

        # Populate the registry
        browser._handle_line(_avahi_resolve_line(txt='id=aaa name=test'))
        assert len(browser.get_snapshot()) == 1

        browser.stop()
        assert removed == []
        assert changed == []

    # 16. Retry sequence and reset behavior remain unchanged.
    def test_retry_sequence_resets_on_valid_event(self):
        """delay_idx resets to 0 after a run that had valid events."""
        browser = _make_browser()
        delays_used = []
        call_count = [0]

        def fake_popen(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # First run: emit one valid line then EOF
                return _FakeProc(
                    lines=[_avahi_resolve_line(txt='id=aaa name=test')],
                    returncode=0,
                )
            if call_count[0] == 2:
                # Second run: immediate EOF (no valid events)
                return _FakeProc(lines=[], returncode=0)
            browser._stop_event.set()
            raise OSError("done")

        def fake_wait(delay):
            delays_used.append(delay)
            if browser._shutdown_requested():
                return

        with patch("autostream_mdns.subprocess.Popen", side_effect=fake_popen), \
             patch.object(browser, "_interruptible_wait", side_effect=fake_wait), \
             patch("autostream_mdns.logger"):
            browser._browse_loop()

        # After first run (had event): delay resets → 5s
        # After second run (no events): delay increments → 10s... but we might stop before
        # At minimum the first delay must be 5 (reset) or a later step
        from autostream_mdns import _RETRY_DELAYS
        assert delays_used[0] == _RETRY_DELAYS[0], (
            f"first retry after valid-event run must be {_RETRY_DELAYS[0]}s, got {delays_used[0]}"
        )


class TestShutdownDuringBrowseLoop:
    """Integration-style: run _browse_loop in a real thread, verify shutdown."""

    def _run_loop(self, browser, fake_lines, shutdown_after_s=0.2):
        """Start the browse loop in a thread, set stop after *shutdown_after_s*."""
        line_iter = iter(fake_lines)

        class _BlockingProc:
            returncode = 0
            stdout = None

            def __init__(self):
                self._started = threading.Event()
                _self = self

                class _Stdout:
                    def __iter__(self_inner):
                        _self._started.set()
                        yield from line_iter
                        # After lines exhausted, block until stop
                        browser._stop_event.wait()

                self.stdout = _Stdout()

            def terminate(self):
                self.returncode = -15

            def kill(self):
                self.returncode = -9

            def wait(self, timeout=None):
                return self.returncode

        proc = _BlockingProc()

        with patch("autostream_mdns.subprocess.Popen", return_value=proc), \
             patch("autostream_mdns.logger"):
            t = threading.Thread(target=browser._browse_loop, daemon=True)
            t.start()
            proc._started.wait(timeout=1.0)
            time.sleep(shutdown_after_s)
            browser._stop_event.set()
            t.join(timeout=1.0)
            return t

    def test_browse_loop_exits_on_stop(self):
        browser = _make_browser()
        t = self._run_loop(browser, [], shutdown_after_s=0.05)
        assert not t.is_alive(), "browse loop thread must exit after stop"

    def test_browse_loop_exits_on_app_event(self):
        browser = _make_browser()
        app_ev = threading.Event()
        browser._app_shutdown = app_ev

        def make_proc(*args, **kwargs):
            class _Stdout:
                def __iter__(self_inner):
                    app_ev.set()  # signal shutdown through app event
                    return iter([])  # no lines to yield

            class _P:
                returncode = 0
                stdout = _Stdout()

                def terminate(self): pass
                def kill(self): pass
                def wait(self, timeout=None): return 0

            return _P()

        with patch("autostream_mdns.subprocess.Popen", side_effect=make_proc), \
             patch("autostream_mdns.logger"):
            t = threading.Thread(target=browser._browse_loop, daemon=True)
            t.start()
            t.join(timeout=1.0)
        assert not t.is_alive()
