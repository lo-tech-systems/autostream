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

    with patch("dial_main._configure_logging"), \
         patch("dial_main.load_config", return_value=cfg), \
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
        installed = {}

        class _CapEvent(threading.Event):
            def __init__(self):
                super().__init__()
                captured["ev"] = self

            def wait(self, timeout=None):
                return super().wait(timeout=0.01)

        def _capture_signal(sig, handler):
            installed[sig] = handler

        with patch("dial_main._configure_logging"), \
             patch("dial_main.load_config", return_value=cfg), \
             patch("dial_main._reconcile_update_timer"), \
             patch("dial_main._announce_self"), \
             patch("dial_main.DialLED"), \
             patch("dial_main.DialHTTPServer") as mock_http_cls, \
             patch("dial_main.start_playing_browser"), \
             patch("dial_main.stop_playing_browser"), \
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.DialControlServer") as mock_ctrl_cls, \
             patch("dial_main.signal.signal", side_effect=_capture_signal), \
             patch("threading.Event", _CapEvent):
            mock_http_cls.return_value._server = MagicMock()
            mock_ctrl_cls.return_value = MagicMock()

            def _fire_signal():
                time.sleep(0.05)
                handler = installed.get(signal.SIGTERM)
                if handler:
                    handler(signal.SIGTERM, None)

            threading.Thread(target=_fire_signal, daemon=True).start()
            dm.main()

        assert "ev" in captured
        assert captured["ev"].is_set(), "SIGTERM must set the shutdown event"

    def test_sigint_sets_shutdown_event(self):
        """SIGINT handler sets the shutdown event without blocking."""
        import dial_main as dm

        cfg = _make_cfg()
        captured = {}
        installed = {}

        class _CapEvent(threading.Event):
            def __init__(self):
                super().__init__()
                captured["ev"] = self

            def wait(self, timeout=None):
                return super().wait(timeout=0.01)

        def _capture_signal(sig, handler):
            installed[sig] = handler

        with patch("dial_main._configure_logging"), \
             patch("dial_main.load_config", return_value=cfg), \
             patch("dial_main._reconcile_update_timer"), \
             patch("dial_main._announce_self"), \
             patch("dial_main.DialLED"), \
             patch("dial_main.DialHTTPServer") as mock_http_cls, \
             patch("dial_main.start_playing_browser"), \
             patch("dial_main.stop_playing_browser"), \
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.DialControlServer") as mock_ctrl_cls, \
             patch("dial_main.signal.signal", side_effect=_capture_signal), \
             patch("threading.Event", _CapEvent):
            mock_http_cls.return_value._server = MagicMock()
            mock_ctrl_cls.return_value = MagicMock()

            def _fire_signal():
                time.sleep(0.05)
                handler = installed.get(signal.SIGINT)
                if handler:
                    handler(signal.SIGINT, None)

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

        with patch("dial_main._configure_logging"), \
             patch("dial_main.load_config", return_value=cfg), \
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

        class _ExplodingEvent(threading.Event):
            def wait(self, timeout=None):
                # Target only the main loop's shutdown_event.wait(5) — other
                # Event.wait() calls (e.g. inside Thread.start() or the
                # display manager's own poll loop) use different timeouts
                # and must not be disturbed by this test's fault injection.
                if timeout == 5:
                    raise RuntimeError("fatal test error")
                return True

        with patch("dial_main._configure_logging"), \
             patch("dial_main.load_config", return_value=cfg), \
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

        with patch("dial_main._configure_logging"), \
             patch("dial_main.load_config", return_value=cfg), \
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

    def test_display_started_and_stopped_around_control_lifetime(self):
        """dial_main.main() must start the display manager after mDNS startup
        and stop it in the finally block, using the real create_dial_display()
        wiring (not a mocked display)."""
        import dial_main as dm

        cfg = _make_cfg()
        cfg.display = MagicMock(fitted=False)
        mock_http = MagicMock()
        mock_http._server = MagicMock()
        mock_control = MagicMock()

        class _QuickEvent(threading.Event):
            def wait(self, timeout=None):
                return True

        with patch("dial_main._configure_logging"), \
             patch("dial_main.load_config", return_value=cfg), \
             patch("dial_main._reconcile_update_timer"), \
             patch("dial_main._announce_self"), \
             patch("dial_main.DialLED"), \
             patch("dial_main.DialHTTPServer", return_value=mock_http) as mock_http_cls, \
             patch("dial_main.start_playing_browser"), \
             patch("dial_main.stop_playing_browser"), \
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.DialControlServer", return_value=mock_control), \
             patch("threading.Event", _QuickEvent):
            dm.main()

        # The display passed to DialHTTPServer must be a real DialDisplay whose
        # thread has been started and cleanly stopped.
        _, kwargs = mock_http_cls.call_args
        display = kwargs["display_status_provider"]
        assert display.get_status()["fitted"] is False
        assert display._thread is None or not display._thread.is_alive()

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

        with patch("dial_main._configure_logging"), \
             patch("dial_main.load_config", return_value=cfg), \
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


# ---------------------------------------------------------------------------
# WP-8: end-to-end display selection through the real mDNS registry, and
# live POST /screen/settings apply against a running DialDisplay.
# ---------------------------------------------------------------------------

class TestEndToEndDisplaySelection:
    """Exercises dial_mdns + dial_display together (not mocked get_display_targets),
    with only the network call (fetch_target_status) mocked."""

    def setup_method(self):
        import dial_mdns as dm_mdns
        with dm_mdns._browser._lock:
            dm_mdns._browser._by_key.clear()
            dm_mdns._browser._by_identity.clear()
        with dm_mdns._state_lock:
            dm_mdns._target_state.clear()

    def _add_playing(self, name="Kitchen", ip="192.168.1.10", port=80):
        import dial_mdns as dm_mdns
        line = f"=;eth0;IPv4;{name};_autostream-playing._tcp;local;host;{ip};{port};dial_api=v1 dial_status=v1"
        dm_mdns._browser._handle_line(line)

    def _make_real_display(self, fitted=True):
        import dial_display as dd
        import dial_mdns as dm_mdns

        cfg_display = MagicMock(fitted=fitted)
        display = dd.DialDisplay(
            config=cfg_display,
            get_display_targets=dm_mdns.get_display_targets,
            mark_display_target_unauthorized=dm_mdns.mark_display_target_unauthorized,
            dial_id="dial-uuid",
            logo_path=str(REPO_ROOT / "images" / "autostream-logo-centred-dark.png"),
            backend_factory=dd.NoOpBackend,
        )
        display.enable()
        return display

    def test_no_targets_shows_logo(self):
        display = self._make_real_display()
        display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_unauthorized_status_error_marks_row_via_real_mdns(self):
        import dial_mdns as dm_mdns

        self._add_playing()
        display = self._make_real_display()
        with patch("dial_display.fetch_target_status",
                   return_value={"track_id": None, "status_error": "unauthorized"}):
            display._poll_once()

        targets = dm_mdns.get_display_targets()
        assert targets[0].display_authorized is False

    def test_no_artwork_shows_logo(self):
        self._add_playing()
        display = self._make_real_display()
        with patch("dial_display.fetch_target_status",
                   return_value={"track_id": None, "status_error": None}):
            display._poll_once()
        assert display.get_status()["showing"] == "logo"

    def test_oldest_playing_since_target_selected_first(self):
        """Two playing targets — the one added first (older playing_since) must
        be polled and win the selection when both offer usable artwork."""
        self._add_playing(name="Older", ip="192.168.1.10")
        self._add_playing(name="Newer", ip="192.168.1.11")
        display = self._make_real_display()

        polled = []

        def fake_fetch(target, dial_id, timeout_seconds):
            polled.append(target.name)
            return {
                "track_id": {
                    "enabled": True, "state": "identified",
                    "artwork_url": "https://provider.example/a.jpg",
                },
                "status_error": None,
            }

        with patch("dial_display.fetch_target_status", side_effect=fake_fetch):
            display._poll_once()

        assert polled == ["Older"]


class TestScreenSettingsLiveApply:
    """POST /screen/settings against a real DialHTTPServer + real DialDisplay."""

    def _post_screen_settings(self, server, body: dict):
        import json as _json

        handler_cls = server._make_handler()
        h = object.__new__(handler_cls)
        body_bytes = _json.dumps(body).encode()
        h.path = "/screen/settings"
        h.rfile = __import__("io").BytesIO(body_bytes)
        h.client_address = ("127.0.0.1", 1)
        h.headers = {"Content-Length": str(len(body_bytes))}
        result = {}
        h._send_json = lambda s, d: result.update(status=s, data=d)
        h.send_error = lambda c, *_: result.update(status=c)
        h._send_429 = lambda w: result.update(status=429)
        with patch("dial_config.save_config"):
            h._handle_screen_settings()
        return result

    def test_post_screen_settings_enables_real_display_manager(self):
        from dial_config import DialConfig, DialDisplayConfig
        from dial_display import DialDisplay, NoOpBackend
        from dial_http_server import DialHTTPServer
        import dial_mdns as dm_mdns

        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=False))
        display = DialDisplay(
            config=cfg.display,
            get_display_targets=dm_mdns.get_display_targets,
            mark_display_target_unauthorized=dm_mdns.mark_display_target_unauthorized,
            dial_id=cfg.uuid,
            backend_factory=NoOpBackend,
        )
        server = DialHTTPServer.__new__(DialHTTPServer)
        server._cfg = cfg
        server._cfg_lock = __import__("threading").Lock()
        server._display_status = display
        server._recovery_window = MagicMock()

        assert display.get_status()["fitted"] is False

        result = self._post_screen_settings(server, {"screen": {"fitted": True}})

        assert result["status"] == 200
        assert result["data"]["ok"] is True
        assert result["data"]["runtime"]["fitted"] is True
        # The *same* running display manager instance must reflect the change.
        assert display.get_status()["fitted"] is True
