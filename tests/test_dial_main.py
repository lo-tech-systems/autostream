"""WP3 tests for dial/dial_main.py lifecycle and shutdown.

Covers:
- SIGTERM sets shutdown event without blocking (plan test 3)
- SIGINT sets shutdown event without blocking (plan test 4)
- Final cleanup stops the mDNS browser and both servers (plan test 5)
- Shutdown event ends the main loop without another 5-second iteration (plan test 6)
- Fatal non-shutdown exceptions propagate (plan test 7)
"""
from __future__ import annotations

import signal
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
_CORE = str(REPO_ROOT / "core")
for _p in (_DIAL, _CORE):
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cfg():
    cfg = MagicMock()
    cfg.uuid = "test-uuid"
    cfg.auto_update = False
    cfg.pin = None
    cfg.led_gpio = 17
    cfg.clk_gpio = 22
    cfg.dt_gpio = 27
    cfg.sw_gpio = None
    return cfg


def _run_main_patched(shutdown_event_setter=None, raise_in_loop=None):
    """Run dial_main.main() with all hardware and service dependencies patched.

    shutdown_event_setter: callable(shutdown_event) called in a background thread
        to trigger shutdown.
    raise_in_loop: if provided, raised instead of executing the loop body.
    """
    import dial_main as dm

    cfg = _make_cfg()

    loop_iterations = [0]

    def fake_wait(timeout):
        loop_iterations[0] += 1
        if raise_in_loop is not None and loop_iterations[0] == 1:
            raise raise_in_loop
        # Return True (shutdown) after the first iteration.
        return True

    mock_led = MagicMock()
    mock_http = MagicMock()
    mock_http._server = MagicMock()
    mock_control = MagicMock()

    # Capture the shutdown event that main() creates.
    captured_event = {}

    original_threading_event = threading.Event

    class _CapturingEvent(threading.Event):
        def __init__(self):
            super().__init__()
            captured_event["ev"] = self
            if shutdown_event_setter is not None:
                t = threading.Thread(
                    target=lambda: (time.sleep(0.05), shutdown_event_setter(self)),
                    daemon=True,
                )
                t.start()

        def wait(self, timeout=None):
            return super().wait(timeout=min(timeout, 0.1) if timeout else 0.1)

    with patch("dial_main.load_config", return_value=cfg), \
         patch("dial_main._reconcile_update_timer"), \
         patch("dial_main._announce_self"), \
         patch("dial_main.DialLED", return_value=mock_led), \
         patch("dial_main.DialHTTPServer", return_value=mock_http), \
         patch("dial_main.start_playing_browser"), \
         patch("dial_main.stop_playing_browser") as mock_stop_browser, \
         patch("dial_main.start_volume_worker"), \
         patch("dial_main.DialControlServer", return_value=mock_control), \
         patch("threading.Event", _CapturingEvent):
        dm.main()

    return captured_event.get("ev"), mock_stop_browser, mock_http, mock_control


# ---------------------------------------------------------------------------
# Signal handler tests
# ---------------------------------------------------------------------------

class TestSignalHandlers:
    def test_sigterm_sets_shutdown_event(self):
        """SIGTERM handler sets the shutdown event without blocking."""
        import dial_main as dm

        cfg = _make_cfg()
        captured = {}

        class _CapEvent(threading.Event):
            def __init__(self):
                super().__init__()
                captured["ev"] = self

            def wait(self, timeout=None):
                # Exit immediately on first wait after SIGTERM.
                return super().wait(timeout=0.01)

        with patch("dial_main.load_config", return_value=cfg), \
             patch("dial_main._reconcile_update_timer"), \
             patch("dial_main._announce_self"), \
             patch("dial_main.DialLED"), \
             patch("dial_main.DialHTTPServer") as mock_http_cls, \
             patch("dial_main.start_playing_browser"), \
             patch("dial_main.stop_playing_browser"), \
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.DialControlServer") as mock_ctrl_cls, \
             patch("threading.Event", _CapEvent):
            mock_http_cls.return_value._server = MagicMock()
            mock_ctrl_cls.return_value = MagicMock()
            # Fire SIGTERM to our own process in a background thread after setup.
            def _fire_signal():
                time.sleep(0.05)
                signal.raise_signal(signal.SIGTERM)
            threading.Thread(target=_fire_signal, daemon=True).start()
            dm.main()

        assert "ev" in captured
        assert captured["ev"].is_set(), "SIGTERM must set the shutdown event"

    def test_sigint_sets_shutdown_event(self):
        """SIGINT handler sets the shutdown event without blocking."""
        import dial_main as dm

        cfg = _make_cfg()
        captured = {}

        class _CapEvent(threading.Event):
            def __init__(self):
                super().__init__()
                captured["ev"] = self

            def wait(self, timeout=None):
                return super().wait(timeout=0.01)

        with patch("dial_main.load_config", return_value=cfg), \
             patch("dial_main._reconcile_update_timer"), \
             patch("dial_main._announce_self"), \
             patch("dial_main.DialLED"), \
             patch("dial_main.DialHTTPServer") as mock_http_cls, \
             patch("dial_main.start_playing_browser"), \
             patch("dial_main.stop_playing_browser"), \
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.DialControlServer") as mock_ctrl_cls, \
             patch("threading.Event", _CapEvent):
            mock_http_cls.return_value._server = MagicMock()
            mock_ctrl_cls.return_value = MagicMock()

            def _fire_signal():
                time.sleep(0.05)
                signal.raise_signal(signal.SIGINT)
            threading.Thread(target=_fire_signal, daemon=True).start()
            dm.main()

        assert "ev" in captured
        assert captured["ev"].is_set(), "SIGINT must set the shutdown event"


# ---------------------------------------------------------------------------
# Cleanup path tests
# ---------------------------------------------------------------------------

class TestDialFinalCleanup:
    def test_finally_calls_stop_browser_then_servers(self):
        """On normal exit the finally block stops the browser before the servers."""
        import dial_main as dm

        cfg = _make_cfg()
        order = []

        mock_http = MagicMock()
        mock_http._server = MagicMock()
        mock_http._server.shutdown.side_effect = lambda: order.append("http")
        mock_control = MagicMock()
        mock_control.stop.side_effect = lambda: order.append("control")

        class _QuickEvent(threading.Event):
            def wait(self, timeout=None):
                return True  # immediate shutdown

        def _mock_stop_browser():
            order.append("browser")

        with patch("dial_main.load_config", return_value=cfg), \
             patch("dial_main._reconcile_update_timer"), \
             patch("dial_main._announce_self"), \
             patch("dial_main.DialLED"), \
             patch("dial_main.DialHTTPServer", return_value=mock_http), \
             patch("dial_main.start_playing_browser"), \
             patch("dial_main.stop_playing_browser", side_effect=_mock_stop_browser), \
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.DialControlServer", return_value=mock_control), \
             patch("threading.Event", _QuickEvent):
            dm.main()

        assert "browser" in order, "stop_playing_browser must be called in finally"
        assert "control" in order, "control_server.stop() must be called in finally"
        assert "http" in order, "http_server.shutdown() must be called in finally"
        assert order.index("browser") < order.index("control"), (
            "browser must be stopped before control server"
        )

    def test_finally_runs_on_exception(self):
        """The finally block runs even when the loop body raises."""
        import dial_main as dm

        cfg = _make_cfg()
        browser_stopped = []

        mock_http = MagicMock()
        mock_http._server = MagicMock()
        mock_control = MagicMock()

        iteration = [0]

        class _ExplodingEvent(threading.Event):
            def wait(self, timeout=None):
                iteration[0] += 1
                if iteration[0] == 1:
                    raise RuntimeError("fatal test error")
                return True

        with patch("dial_main.load_config", return_value=cfg), \
             patch("dial_main._reconcile_update_timer"), \
             patch("dial_main._announce_self"), \
             patch("dial_main.DialLED"), \
             patch("dial_main.DialHTTPServer", return_value=mock_http), \
             patch("dial_main.start_playing_browser"), \
             patch("dial_main.stop_playing_browser",
                   side_effect=lambda: browser_stopped.append(True)), \
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.DialControlServer", return_value=mock_control), \
             patch("threading.Event", _ExplodingEvent):
            with pytest.raises(RuntimeError):
                dm.main()

        assert browser_stopped, "stop_playing_browser must run even after exception"

    def test_shutdown_exits_loop_without_extra_iteration(self):
        """When shutdown_event.wait(5) returns True, the loop body does not run."""
        import dial_main as dm

        cfg = _make_cfg()
        led_calls = []

        mock_led = MagicMock()
        mock_led.set_playing.side_effect = lambda: led_calls.append("playing")
        mock_led.set_idle.side_effect = lambda: led_calls.append("idle")

        mock_http = MagicMock()
        mock_http._server = MagicMock()
        mock_control = MagicMock()

        class _ImmediateShutdownEvent(threading.Event):
            def wait(self, timeout=None):
                return True  # shutdown signaled immediately

        with patch("dial_main.load_config", return_value=cfg), \
             patch("dial_main._reconcile_update_timer"), \
             patch("dial_main._announce_self"), \
             patch("dial_main.DialLED", return_value=mock_led), \
             patch("dial_main.DialHTTPServer", return_value=mock_http), \
             patch("dial_main.start_playing_browser"), \
             patch("dial_main.stop_playing_browser"), \
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.DialControlServer", return_value=mock_control), \
             patch("threading.Event", _ImmediateShutdownEvent):
            dm.main()

        assert led_calls == [], (
            "LED must not be set if shutdown fires before first loop iteration"
        )

    def test_fatal_exception_propagates(self):
        """A non-shutdown exception from control_server.start() propagates out."""
        import dial_main as dm

        cfg = _make_cfg()
        mock_http = MagicMock()
        mock_http._server = MagicMock()
        mock_control = MagicMock()
        mock_control.start.side_effect = OSError("socket bind failed")

        class _QuickEvent(threading.Event):
            def wait(self, timeout=None):
                return True

        with patch("dial_main.load_config", return_value=cfg), \
             patch("dial_main._reconcile_update_timer"), \
             patch("dial_main._announce_self"), \
             patch("dial_main.DialLED"), \
             patch("dial_main.DialHTTPServer", return_value=mock_http), \
             patch("dial_main.start_playing_browser"), \
             patch("dial_main.stop_playing_browser"), \
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.DialControlServer", return_value=mock_control), \
             patch("threading.Event", _QuickEvent):
            with pytest.raises(OSError, match="socket bind failed"):
                dm.main()
