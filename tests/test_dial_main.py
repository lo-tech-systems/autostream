"""Tests for dial/dial_main.py lifecycle and shutdown.

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
from contextlib import contextmanager
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
# Rotary encoder / button GPIO skip logic (screen-only dial support)
# ---------------------------------------------------------------------------

class TestOptionalGpioSetup:
    """Screen-only dials have no rotary encoder or button wired up.  main()
    must skip setup_rotary_encoder/setup_button entirely (no call, no
    warning) when the relevant GPIOs are null, logging one deliberate INFO
    line instead."""

    def _run(self, cfg, caplog):
        import dial_main as dm

        mock_http = MagicMock()
        mock_http._server = MagicMock()
        mock_control = MagicMock()
        mock_encoder_setup = MagicMock(return_value="encoder-handle")
        mock_button_setup = MagicMock(return_value="button-handle")

        fake_rpi = MagicMock()
        fake_rpi.setup_rotary_encoder = mock_encoder_setup
        fake_rpi.setup_button = mock_button_setup

        class _QuickEvent(threading.Event):
            def wait(self, timeout=None):
                return True

        import builtins
        real_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name == "autostream_rpi":
                return fake_rpi
            return real_import(name, *args, **kwargs)

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
             patch("threading.Event", _QuickEvent), \
             patch("builtins.__import__", side_effect=_fake_import), \
             caplog.at_level("INFO"):
            dm.main()

        return mock_encoder_setup, mock_button_setup

    def test_all_gpios_null_skips_both_and_logs_info(self, caplog):
        """A pure screen-only dial: neither setup is called, both INFO lines
        are logged, and the service still starts (dm.main() must not raise)."""
        cfg = _make_cfg()
        cfg.clk_gpio = None
        cfg.dt_gpio = None
        cfg.sw_gpio = None

        encoder_setup, button_setup = self._run(cfg, caplog)

        encoder_setup.assert_not_called()
        button_setup.assert_not_called()
        assert "rotary encoder not configured; skipping" in caplog.text
        assert "button not configured; skipping" in caplog.text

    def test_only_sw_set_sets_up_button_but_skips_encoder(self, caplog):
        cfg = _make_cfg()
        cfg.clk_gpio = None
        cfg.dt_gpio = None
        cfg.sw_gpio = 23

        encoder_setup, button_setup = self._run(cfg, caplog)

        encoder_setup.assert_not_called()
        button_setup.assert_called_once()
        assert button_setup.call_args.args[0] == 23
        assert "rotary encoder not configured; skipping" in caplog.text
        assert "button not configured; skipping" not in caplog.text

    def test_partial_encoder_pair_skips_setup(self, caplog):
        """clk set but dt null (or vice versa) must not attempt encoder
        setup — a partial pair is not a usable encoder."""
        cfg = _make_cfg()
        cfg.clk_gpio = 22
        cfg.dt_gpio = None
        cfg.sw_gpio = None

        encoder_setup, button_setup = self._run(cfg, caplog)

        encoder_setup.assert_not_called()
        button_setup.assert_not_called()
        assert "rotary encoder not configured; skipping" in caplog.text

    def test_fully_configured_sets_up_both(self, caplog):
        """Unchanged behaviour when everything is configured: both are set
        up and no 'not configured' INFO lines are emitted."""
        cfg = _make_cfg()
        cfg.clk_gpio = 22
        cfg.dt_gpio = 27
        cfg.sw_gpio = 23

        encoder_setup, button_setup = self._run(cfg, caplog)

        encoder_setup.assert_called_once()
        assert encoder_setup.call_args.args[0] == 22
        assert encoder_setup.call_args.args[1] == 27
        button_setup.assert_called_once()
        assert button_setup.call_args.args[0] == 23
        assert "rotary encoder not configured; skipping" not in caplog.text
        assert "button not configured; skipping" not in caplog.text


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

    def test_display_stack_import_failure_degrades_to_noop(self):
        """If dial_display (e.g. Pillow) is unavailable, main() must degrade to
        NoOpDisplayStatusProvider rather than fail the whole service — volume
        control must not depend on the display stack being importable."""
        import builtins
        import dial_main as dm
        from dial_http_server import NoOpDisplayStatusProvider

        cfg = _make_cfg()
        mock_http = MagicMock()
        mock_http._server = MagicMock()
        mock_control = MagicMock()

        class _QuickEvent(threading.Event):
            def wait(self, timeout=None):
                return True

        real_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name == "dial_display" or name.startswith("dial_display."):
                raise ImportError("simulated missing Pillow/display stack")
            return real_import(name, *args, **kwargs)

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
             patch("threading.Event", _QuickEvent), \
             patch("builtins.__import__", side_effect=_fake_import):
            dm.main()  # must not raise

        _, kwargs = mock_http_cls.call_args
        assert isinstance(kwargs["display_status_provider"], NoOpDisplayStatusProvider)

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
# End-to-end display selection through the real mDNS registry, and
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
        server._touch_source = None
        server._touch_runtime = ''

        assert display.get_status()["fitted"] is False

        result = self._post_screen_settings(server, {"screen": {"fitted": True}})

        assert result["status"] == 200
        assert result["data"]["ok"] is True
        assert result["data"]["runtime"]["fitted"] is True
        # The *same* running display manager instance must reflect the change.
        assert display.get_status()["fitted"] is True

    def test_post_screen_settings_toggles_rotate_on_real_display_manager(self):
        from dial_config import DialConfig, DialDisplayConfig
        from dial_display import DialDisplay, NoOpBackend
        from dial_http_server import DialHTTPServer
        import dial_mdns as dm_mdns

        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=True, rotate=False))
        display = DialDisplay(
            config=cfg.display,
            get_display_targets=dm_mdns.get_display_targets,
            mark_display_target_unauthorized=dm_mdns.mark_display_target_unauthorized,
            dial_id=cfg.uuid,
            backend_factory=NoOpBackend,
        )
        display.enable()
        server = DialHTTPServer.__new__(DialHTTPServer)
        server._cfg = cfg
        server._cfg_lock = __import__("threading").Lock()
        server._display_status = display
        server._recovery_window = MagicMock()
        server._touch_source = None
        server._touch_runtime = ''

        assert display.get_status()["rotate"] is False

        result = self._post_screen_settings(
            server, {"screen": {"fitted": True, "rotate": True}}
        )

        assert result["status"] == 200
        assert result["data"]["runtime"]["rotate"] is True
        # Applied synchronously against the real running manager, not merely
        # in the response payload.
        assert display.get_status()["rotate"] is True

    def test_post_screen_settings_applies_screen_type_and_bgr_on_real_display_manager(self):
        from dial_config import DialConfig, DialDisplayConfig
        from dial_display import DialDisplay, NoOpBackend
        from dial_http_server import DialHTTPServer
        import dial_mdns as dm_mdns

        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=True, bgr=False))
        display = DialDisplay(
            config=cfg.display,
            get_display_targets=dm_mdns.get_display_targets,
            mark_display_target_unauthorized=dm_mdns.mark_display_target_unauthorized,
            dial_id=cfg.uuid,
            backend_factory=NoOpBackend,
        )
        display.enable()
        server = DialHTTPServer.__new__(DialHTTPServer)
        server._cfg = cfg
        server._cfg_lock = __import__("threading").Lock()
        server._display_status = display
        server._recovery_window = MagicMock()
        server._touch_source = None
        server._touch_runtime = ''

        assert display.get_status()["bgr"] is False
        assert display.get_status()["screen_type"] == "st7735s_160x128"

        result = self._post_screen_settings(
            server,
            {"screen": {"fitted": True, "screen_type": "st7789_240x240", "bgr": True}},
        )

        assert result["status"] == 200
        assert result["data"]["runtime"]["screen_type"] == "st7789_240x240"
        assert result["data"]["runtime"]["bgr"] is True
        # Applied synchronously against the real running manager, not merely
        # in the response payload. NoOpBackend never fails to "open", so
        # this is an unconditional apply-then-persist success path.
        assert display.get_status()["screen_type"] == "st7789_240x240"
        assert display.get_status()["bgr"] is True


# ---------------------------------------------------------------------------
# Touch construction — built AFTER the display, only when fitted AND a real
# touch controller is selected; its own ImportError/Exception isolation so a
# missing gpiozero/driver library degrades to no-touch without affecting the
# display or volume control; .stop() hooked into the same finally teardown
# as the display and control server.
# ---------------------------------------------------------------------------

class TestTouchConstruction:
    def _run(self, cfg_display, build_mock=None, caplog=None):
        import dial_main as dm

        cfg = _make_cfg()
        cfg.display = cfg_display
        mock_http = MagicMock()
        mock_http._server = MagicMock()
        mock_control = MagicMock()
        if build_mock is None:
            build_mock = MagicMock(return_value=MagicMock())

        class _QuickEvent(threading.Event):
            def wait(self, timeout=None):
                return True

        patches = [
            patch("dial_main._configure_logging"),
            patch("dial_main.load_config", return_value=cfg),
            patch("dial_main._reconcile_update_timer"),
            patch("dial_main._announce_self"),
            patch("dial_main.DialLED"),
            patch("dial_main.DialHTTPServer", return_value=mock_http),
            patch("dial_main.start_playing_browser"),
            patch("dial_main.stop_playing_browser"),
            patch("dial_main.start_volume_worker"),
            patch("dial_main.DialControlServer", return_value=mock_control),
            patch("threading.Event", _QuickEvent),
            patch("dial_main._build_touch_source", build_mock),
        ]
        for p in patches:
            p.start()
        try:
            dm.main()
        finally:
            for p in reversed(patches):
                p.stop()
        self._last_http = mock_http
        return build_mock

    def test_touch_constructed_when_fitted_and_touch_type_set(self):
        from dial_config import DialDisplayConfig

        touch_instance = MagicMock()
        build_mock = MagicMock(return_value=touch_instance)

        self._run(DialDisplayConfig(fitted=True, touch_type="xpt2046"), build_mock)

        build_mock.assert_called_once()
        touch_instance.start.assert_called_once()
        touch_instance.stop.assert_called_once()

    def test_not_constructed_when_not_fitted(self):
        from dial_config import DialDisplayConfig

        build_mock = MagicMock()
        self._run(DialDisplayConfig(fitted=False, touch_type="xpt2046"), build_mock)
        build_mock.assert_not_called()

    def test_not_constructed_when_touch_type_none(self):
        from dial_config import DialDisplayConfig

        build_mock = MagicMock()
        self._run(DialDisplayConfig(fitted=True, touch_type="none"), build_mock)
        build_mock.assert_not_called()

    def test_construction_failure_degrades_to_no_touch_dial_still_starts(self, caplog):
        from dial_config import DialDisplayConfig

        build_mock = MagicMock(side_effect=RuntimeError("no SPI bus"))
        with caplog.at_level("WARNING"):
            self._run(DialDisplayConfig(fitted=True, touch_type="xpt2046"), build_mock)
        assert "touch stack unavailable" in caplog.text

    def test_start_failure_degrades_to_no_touch_and_stop_not_called(self, caplog):
        from dial_config import DialDisplayConfig

        touch_instance = MagicMock()
        touch_instance.start.side_effect = RuntimeError("gpiozero missing")
        build_mock = MagicMock(return_value=touch_instance)

        with caplog.at_level("WARNING"):
            self._run(DialDisplayConfig(fitted=True, touch_type="xpt2046"), build_mock)

        assert "touch stack unavailable" in caplog.text
        # The failed instance never made it into the module's touch_source
        # local, so nothing in the finally block tries to stop it again.
        touch_instance.stop.assert_not_called()

    # -- set_touch_runtime() reports what actually happened, distinct from
    #    what set_can_confirm_presence reports (that's presence, this is the
    #    controller identity for GET /screen/settings' runtime.touch_type) --

    def test_touch_runtime_reports_running_controller_key(self):
        from dial_config import DialDisplayConfig

        touch_instance = MagicMock()
        build_mock = MagicMock(return_value=touch_instance)

        self._run(DialDisplayConfig(fitted=True, touch_type="xpt2046"), build_mock)

        self._last_http.set_touch_runtime.assert_called_once_with("xpt2046")

    def test_touch_runtime_none_when_not_fitted(self):
        from dial_config import DialDisplayConfig

        build_mock = MagicMock()
        self._run(DialDisplayConfig(fitted=False, touch_type="xpt2046"), build_mock)

        self._last_http.set_touch_runtime.assert_called_once_with("none")

    def test_touch_runtime_none_when_touch_type_none(self):
        from dial_config import DialDisplayConfig

        build_mock = MagicMock()
        self._run(DialDisplayConfig(fitted=True, touch_type="none"), build_mock)

        self._last_http.set_touch_runtime.assert_called_once_with("none")

    def test_touch_runtime_failed_when_construction_raised(self, caplog):
        from dial_config import DialDisplayConfig

        build_mock = MagicMock(side_effect=RuntimeError("no SPI bus"))
        with caplog.at_level("WARNING"):
            self._run(DialDisplayConfig(fitted=True, touch_type="xpt2046"), build_mock)

        self._last_http.set_touch_runtime.assert_called_once_with("failed")

    def test_touch_runtime_failed_when_start_raised(self, caplog):
        from dial_config import DialDisplayConfig

        touch_instance = MagicMock()
        touch_instance.start.side_effect = RuntimeError("gpiozero missing")
        build_mock = MagicMock(return_value=touch_instance)

        with caplog.at_level("WARNING"):
            self._run(DialDisplayConfig(fitted=True, touch_type="xpt2046"), build_mock)

        self._last_http.set_touch_runtime.assert_called_once_with("failed")

    def test_encoder_and_button_path_unaffected_by_touch_failure(self, caplog):
        """A raising touch stack must not affect the (independent) rotary
        encoder / button setup path."""
        import dial_main as dm
        from dial_config import DialDisplayConfig

        cfg = _make_cfg()
        cfg.display = DialDisplayConfig(fitted=True, touch_type="xpt2046")
        cfg.clk_gpio = 22
        cfg.dt_gpio = 27
        cfg.sw_gpio = 23

        mock_http = MagicMock()
        mock_http._server = MagicMock()
        mock_control = MagicMock()
        mock_encoder_setup = MagicMock(return_value="encoder-handle")
        mock_button_setup = MagicMock(return_value="button-handle")

        fake_rpi = MagicMock()
        fake_rpi.setup_rotary_encoder = mock_encoder_setup
        fake_rpi.setup_button = mock_button_setup

        import builtins
        real_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name == "autostream_rpi":
                return fake_rpi
            return real_import(name, *args, **kwargs)

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
             patch("threading.Event", _QuickEvent), \
             patch("dial_main._build_touch_source", side_effect=RuntimeError("boom")), \
             patch("builtins.__import__", side_effect=_fake_import), \
             caplog.at_level("WARNING"):
            dm.main()  # must not raise

        mock_encoder_setup.assert_called_once()
        mock_button_setup.assert_called_once()
        assert "touch stack unavailable" in caplog.text

    def test_not_constructed_when_display_stack_unavailable(self):
        """Even if cfg says fitted + a real touch controller, touch must not
        start against the NoOpDisplayStatusProvider fallback — it has no
        set_overlay()/notify_touch_activity() for touch to call into."""
        import builtins
        import dial_main as dm
        from dial_config import DialDisplayConfig

        cfg = _make_cfg()
        cfg.display = DialDisplayConfig(fitted=True, touch_type="xpt2046")
        mock_http = MagicMock()
        mock_http._server = MagicMock()
        mock_control = MagicMock()
        build_mock = MagicMock()

        class _QuickEvent(threading.Event):
            def wait(self, timeout=None):
                return True

        real_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name == "dial_display" or name.startswith("dial_display."):
                raise ImportError("simulated missing Pillow/display stack")
            return real_import(name, *args, **kwargs)

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
             patch("threading.Event", _QuickEvent), \
             patch("dial_main._build_touch_source", build_mock), \
             patch("builtins.__import__", side_effect=_fake_import):
            dm.main()  # must not raise

        build_mock.assert_not_called()


class TestBuildTouchSourceWiring:
    """Direct tests of dial_main._build_touch_source()'s callback wiring,
    with the hardware-touching pieces (open_driver, TouchEventSource's
    background thread) faked out."""

    @contextmanager
    def _built(self, confirm_presence=None, is_muted_value=False):
        """Construct via dial_main._build_touch_source() with the mocks
        still active, yielding everything a test needs — the invoked
        callbacks reference module globals (enqueue_delta etc.) resolved at
        CALL time, not definition time, so the patches must still be in
        effect when a test actually invokes a captured callback."""
        import dial_main as dm
        from dial_config import DialDisplayConfig

        cfg = MagicMock()
        cfg.display = DialDisplayConfig(fitted=True, touch_type="xpt2046")
        cfg.step_percent = 3

        display = MagicMock()
        display.noncomposited_generation = MagicMock(return_value=0)

        captured = {}

        def fake_touch_event_source(driver, touch_filter, state_machine, **kwargs):
            captured["driver"] = driver
            captured["kwargs"] = kwargs
            instance = MagicMock()
            captured["instance"] = instance
            return instance

        with patch("dial_touch_drivers.open_driver") as mock_open, \
             patch("dial_touch.TouchEventSource", side_effect=fake_touch_event_source), \
             patch("dial_main.enqueue_delta") as mock_delta, \
             patch("dial_main.enqueue_mute", return_value=True) as mock_mute, \
             patch("dial_main.is_muted", return_value=is_muted_value):
            result = dm._build_touch_source(cfg, display, confirm_presence=confirm_presence)
            yield cfg, display, result, captured, mock_open, mock_delta, mock_mute

    def test_driver_opened_for_configured_controller(self):
        with self._built() as (cfg, display, result, captured, mock_open, *_):
            mock_open.assert_called_once_with("xpt2046")
            assert captured["driver"] is mock_open.return_value
            assert result is captured["instance"]

    def test_noncomposited_generation_getter_wired_to_display(self):
        with self._built() as (cfg, display, result, captured, *_):
            assert captured["kwargs"]["get_noncomposited_generation"] is display.noncomposited_generation

    def test_volume_up_enqueues_step_percent_and_notifies_activity(self):
        with self._built() as (cfg, display, result, captured, _open, mock_delta, mock_mute):
            captured["kwargs"]["on_volume_up"]()
            mock_delta.assert_called_once_with(3)
            display.notify_touch_activity.assert_called_once()

    def test_volume_down_enqueues_negative_step_percent(self):
        with self._built() as (cfg, display, result, captured, _open, mock_delta, mock_mute):
            captured["kwargs"]["on_volume_down"]()
            mock_delta.assert_called_once_with(-3)
            display.notify_touch_activity.assert_called_once()

    def test_mute_toggle_enqueues_mute(self):
        with self._built() as (cfg, display, result, captured, _open, mock_delta, mock_mute):
            captured["kwargs"]["on_mute_toggle"]()
            mock_mute.assert_called_once()
            display.notify_touch_activity.assert_called_once()

    def test_mute_toggle_repaints_glyph_from_returned_belief(self):
        """The press flips the belief and repaints the glyph on the same
        frame — set_overlay must be called with the new belief returned by
        enqueue_mute(), not the pre-press one from is_muted()."""
        from dial_touch_layout import TouchZone

        with self._built() as (cfg, display, result, captured, _open, mock_delta, mock_mute):
            captured["kwargs"]["on_mute_toggle"]()

            display.set_overlay.assert_called_once()
            state = display.set_overlay.call_args[0][0]
            assert state.visible is True
            assert state.pressed == TouchZone.MUTE
            assert state.muted is True  # enqueue_mute() was stubbed to return True

    def test_reveal_overlay_sets_overlay_visible_and_signals_overlay_live(self):
        with self._built() as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_reveal_overlay"]()

            display.set_overlay.assert_called_once()
            state = display.set_overlay.call_args[0][0]
            assert state.visible is True
            assert state.pressed is None
            display.notify_touch_activity.assert_called_once()
            result.overlay_live.assert_called_once()

    def test_reveal_overlay_reads_muted_from_belief(self):
        """A reveal must show the CURRENT belief on its very first frame,
        not the tri-state default — otherwise a mute set by the physical
        button (or an earlier touch session) would briefly draw wrong."""
        with self._built(is_muted_value=True) as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_reveal_overlay"]()

            state = display.set_overlay.call_args[0][0]
            assert state.muted is True

    def test_dismiss_overlay_sets_overlay_hidden(self):
        with self._built() as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_dismiss_overlay"]()

            state = display.set_overlay.call_args[0][0]
            assert state.visible is False

    def test_set_pressed_zone_sets_overlay_with_the_zone(self):
        from dial_touch_layout import TouchZone

        with self._built() as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_set_pressed_zone"](TouchZone.UP)

            state = display.set_overlay.call_args[0][0]
            assert state.visible is True
            assert state.pressed == TouchZone.UP
            display.notify_touch_activity.assert_called_once()

    def test_reveal_overlay_confirms_presence(self):
        """The very first touch-down — reveal-only, nothing armed yet — must
        still confirm presence (see reveal-then-arm in dial_touch.py: a
        first contact may never reach on_set_pressed_zone at all)."""
        confirm = MagicMock()
        with self._built(confirm_presence=confirm) as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_reveal_overlay"]()
        confirm.assert_called_once()

    def test_set_pressed_zone_confirms_presence(self):
        """A press that arms immediately (overlay already visible) must also
        confirm presence."""
        from dial_touch_layout import TouchZone

        confirm = MagicMock()
        with self._built(confirm_presence=confirm) as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_set_pressed_zone"](TouchZone.DOWN)
        confirm.assert_called_once()

    def test_confirm_presence_is_optional(self):
        """confirm_presence defaults to None — callers/tests that don't pass
        it must not have on_reveal_overlay/on_set_pressed_zone raise."""
        from dial_touch_layout import TouchZone

        with self._built() as (cfg, display, result, captured, *_):
            captured["kwargs"]["on_reveal_overlay"]()
            captured["kwargs"]["on_set_pressed_zone"](TouchZone.UP)


# ---------------------------------------------------------------------------
# Both mute press entry points (touch mute zone AND the physical button)
# must stay off DialDisplay._lock and off the network.
#
# Runs dial_main.main() end-to-end with a REAL DialDisplay (spied via
# dial_display.create_dial_display) and the REAL dial_volume.enqueue_mute(),
# not stand-ins for either — otherwise this would only prove a hand-rolled
# copy of the wiring is safe, not the actual callbacks dial_main builds.
# ---------------------------------------------------------------------------

class TestMutePressEntryPointsStayLockFreeAndNetworkFree:
    def _run(self):
        import dial_main as dm
        import dial_display as dd
        from dial_config import DialConfig, DialDisplayConfig

        cfg = DialConfig(
            uuid="lock-test-uuid",
            sw_gpio=23,
            clk_gpio=None,
            dt_gpio=None,
            led_gpio=None,
            pin="",
        )
        cfg.display = DialDisplayConfig(fitted=True, touch_type="xpt2046")

        captured: dict = {}

        real_create_dial_display = dd.create_dial_display

        def spy_create_dial_display(*args, **kwargs):
            instance = real_create_dial_display(*args, **kwargs)
            captured["display"] = instance
            return instance

        def fake_touch_event_source(driver, touch_filter, state_machine, **kwargs):
            captured["touch_kwargs"] = kwargs
            return MagicMock()

        def fake_setup_button(gpio, on_press, bounce_time=0.1):
            captured["on_press"] = on_press
            return MagicMock()

        fake_rpi = MagicMock()
        fake_rpi.setup_rotary_encoder = MagicMock(return_value=None)
        fake_rpi.setup_button = fake_setup_button

        import builtins
        real_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name == "autostream_rpi":
                return fake_rpi
            return real_import(name, *args, **kwargs)

        class _QuickEvent(threading.Event):
            def wait(self, timeout=None):
                return True

        mock_http = MagicMock()
        mock_http._server = MagicMock()

        with patch("dial_main._configure_logging"), \
             patch("dial_main.load_config", return_value=cfg), \
             patch("dial_main._reconcile_update_timer"), \
             patch("dial_main._announce_self"), \
             patch("dial_main.DialLED"), \
             patch("dial_main.DialHTTPServer", return_value=mock_http), \
             patch("dial_main.start_playing_browser"), \
             patch("dial_main.stop_playing_browser"), \
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.DialControlServer"), \
             patch("dial_touch_drivers.open_driver"), \
             patch("dial_touch.TouchEventSource", side_effect=fake_touch_event_source), \
             patch.object(dd, "create_dial_display", side_effect=spy_create_dial_display), \
             patch("threading.Event", _QuickEvent), \
             patch("builtins.__import__", side_effect=_fake_import):
            dm.main()

        return captured

    def test_neither_entry_point_blocks_on_display_lock_or_touches_the_network(self):
        captured = self._run()
        display = captured["display"]
        on_mute_toggle = captured["touch_kwargs"]["on_mute_toggle"]
        on_press = captured["on_press"]

        def _network_call_forbidden(*args, **kwargs):
            raise AssertionError("a mute press entry point performed network I/O")

        with patch("urllib.request.urlopen", side_effect=_network_call_forbidden):
            # Hold DialDisplay's own lock in THIS thread. If either entry
            # point tried to acquire it (directly, or via a display method
            # that isn't actually lock-free), the call below would block
            # for the full join timeout instead of returning immediately.
            held = display._lock.acquire(blocking=False)
            assert held, "test setup: could not acquire display._lock to hold it"
            try:
                for name, entry_point in (
                    ("touch mute zone", on_mute_toggle),
                    ("physical button", on_press),
                ):
                    done = threading.Event()

                    def run(entry_point=entry_point, done=done):
                        entry_point()
                        done.set()

                    t = threading.Thread(target=run, daemon=True)
                    t.start()
                    t.join(timeout=1.0)
                    assert done.is_set(), (
                        f"{name} entry point blocked while DialDisplay._lock "
                        "was held — it must never take that lock"
                    )
            finally:
                display._lock.release()


# ---------------------------------------------------------------------------
# Lost-PIN recovery: any deliberate physical input confirms presence, and
# can_confirm_presence reports what actually got constructed at runtime.
#
# These run dial_main.main() end-to-end against a REAL DialHTTPServer +
# RecoveryWindow (constructed without binding a socket) rather than a bare
# MagicMock, so a wiring mistake (e.g. forgetting to call confirm_volume(),
# or calling the wrong dial_server's method) cannot be masked by a mock that
# silently accepts any call/attribute access.
# ---------------------------------------------------------------------------

class TestPresenceConfirmationWiring:
    def _real_server(self):
        import dial_http_server as dhs
        from dial_config import DialConfig

        cfg = DialConfig(uuid="x", pin="1234")
        server = dhs.DialHTTPServer.__new__(dhs.DialHTTPServer)
        server._cfg = cfg
        server._cfg_lock = threading.Lock()
        server._recovery_window = dhs.RecoveryWindow(lambda add: None)
        server._can_confirm_presence = False
        server._display_status = dhs.NoOpDisplayStatusProvider()
        server._server = MagicMock()
        return server

    def _run(self, cfg, server, build_mock=None):
        import dial_main as dm

        control_kwargs = {}

        def _capture_control(**kwargs):
            control_kwargs.update(kwargs)
            return MagicMock()

        mock_encoder_setup = MagicMock(return_value="encoder-handle")
        mock_button_setup = MagicMock(return_value="button-handle")
        fake_rpi = MagicMock()
        fake_rpi.setup_rotary_encoder = mock_encoder_setup
        fake_rpi.setup_button = mock_button_setup

        class _QuickEvent(threading.Event):
            def wait(self, timeout=None):
                return True

        import builtins
        real_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name == "autostream_rpi":
                return fake_rpi
            return real_import(name, *args, **kwargs)

        patches = [
            patch("dial_main._configure_logging"),
            patch("dial_main.load_config", return_value=cfg),
            patch("dial_main._reconcile_update_timer"),
            patch("dial_main._announce_self"),
            patch("dial_main.DialLED"),
            patch("dial_main.DialHTTPServer", return_value=server),
            patch("dial_main.start_playing_browser"),
            patch("dial_main.stop_playing_browser"),
            patch("dial_main.start_volume_worker"),
            patch("dial_main.DialControlServer", side_effect=_capture_control),
            patch("threading.Event", _QuickEvent),
            # RecoveryWindow.open() is real here (cfg.pin is set) — mock out
            # only the timer thread it schedules, not its state transitions.
            patch("dial_http_server.threading.Timer"),
            patch("builtins.__import__", side_effect=_fake_import),
        ]
        if build_mock is not None:
            patches.append(patch("dial_main._build_touch_source", build_mock))
        for p in patches:
            p.start()
        try:
            dm.main()
        finally:
            for p in reversed(patches):
                p.stop()

        return control_kwargs, mock_encoder_setup, mock_button_setup

    # -- any deliberate input confirms presence --------------------------

    def test_encoder_down_confirms(self):
        cfg = _make_cfg()  # clk=22, dt=27 already set
        cfg.pin = "1234"
        server = self._real_server()

        _, encoder_setup, _ = self._run(cfg, server)

        encoder_setup.assert_called_once()
        nudge_down_cb = encoder_setup.call_args.args[3]
        assert server._recovery_window.snapshot()["volume_confirmed"] is False
        nudge_down_cb()
        assert server._recovery_window.snapshot()["volume_confirmed"] is True

    def test_nudge_delta_negative_confirms(self):
        cfg = _make_cfg()
        cfg.pin = "1234"
        server = self._real_server()

        control_kwargs, _, _ = self._run(cfg, server)

        assert server._recovery_window.snapshot()["volume_confirmed"] is False
        control_kwargs["nudge_delta"](-3)
        assert server._recovery_window.snapshot()["volume_confirmed"] is True

    def test_nudge_delta_zero_does_not_confirm(self):
        """Unchanged behaviour: a zero delta is not a deliberate input."""
        cfg = _make_cfg()
        cfg.pin = "1234"
        server = self._real_server()

        control_kwargs, _, _ = self._run(cfg, server)

        control_kwargs["nudge_delta"](0)
        assert server._recovery_window.snapshot()["volume_confirmed"] is False

    def test_button_press_confirms(self):
        cfg = _make_cfg()
        cfg.sw_gpio = 23
        cfg.pin = "1234"
        server = self._real_server()

        _, _, button_setup = self._run(cfg, server)

        button_setup.assert_called_once()
        on_press_cb = button_setup.call_args.args[1]
        assert server._recovery_window.snapshot()["volume_confirmed"] is False
        on_press_cb()
        assert server._recovery_window.snapshot()["volume_confirmed"] is True

    def test_touch_contact_confirms(self):
        """main() must wire confirm_presence=http_server.confirm_volume into
        _build_touch_source — invoking it must confirm the real recovery
        window, exactly like the encoder/button paths above."""
        from dial_config import DialDisplayConfig

        cfg = _make_cfg()
        cfg.clk_gpio = None
        cfg.dt_gpio = None
        cfg.sw_gpio = None
        cfg.display = DialDisplayConfig(fitted=True, touch_type="xpt2046")
        cfg.pin = "1234"
        server = self._real_server()

        captured = {}

        def build_mock(cfg_arg, display_arg, confirm_presence=None):
            captured["confirm_presence"] = confirm_presence
            return MagicMock()

        self._run(cfg, server, build_mock=build_mock)

        assert captured["confirm_presence"].__self__ is server
        assert captured["confirm_presence"].__func__ is server.confirm_volume.__func__
        assert server._recovery_window.snapshot()["volume_confirmed"] is False
        captured["confirm_presence"]()
        assert server._recovery_window.snapshot()["volume_confirmed"] is True

    # -- can_confirm_presence reflects what actually got constructed -----

    def test_can_confirm_presence_true_for_encoder_and_button(self):
        from dial_config import DialDisplayConfig

        cfg = _make_cfg()
        cfg.clk_gpio, cfg.dt_gpio, cfg.sw_gpio = 22, 27, 23
        cfg.display = DialDisplayConfig(fitted=False, touch_type="none")
        server = self._real_server()

        self._run(cfg, server)

        assert server._can_confirm_presence is True

    def test_can_confirm_presence_true_for_encoder_only(self):
        from dial_config import DialDisplayConfig

        cfg = _make_cfg()
        cfg.clk_gpio, cfg.dt_gpio, cfg.sw_gpio = 22, 27, None
        cfg.display = DialDisplayConfig(fitted=False, touch_type="none")
        server = self._real_server()

        self._run(cfg, server)

        assert server._can_confirm_presence is True

    def test_can_confirm_presence_true_for_button_only(self):
        from dial_config import DialDisplayConfig

        cfg = _make_cfg()
        cfg.clk_gpio, cfg.dt_gpio, cfg.sw_gpio = None, None, 23
        cfg.display = DialDisplayConfig(fitted=False, touch_type="none")
        server = self._real_server()

        self._run(cfg, server)

        assert server._can_confirm_presence is True

    def test_can_confirm_presence_true_for_touch_only(self):
        from dial_config import DialDisplayConfig

        cfg = _make_cfg()
        cfg.clk_gpio, cfg.dt_gpio, cfg.sw_gpio = None, None, None
        cfg.display = DialDisplayConfig(fitted=True, touch_type="xpt2046")
        server = self._real_server()
        build_mock = MagicMock(return_value=MagicMock())

        self._run(cfg, server, build_mock=build_mock)

        assert server._can_confirm_presence is True

    def test_can_confirm_presence_false_for_screen_only(self):
        """No encoder, no button, touch_type 'none': a lock with no key is
        worse than no lock, so this dial must report it cannot confirm."""
        from dial_config import DialDisplayConfig

        cfg = _make_cfg()
        cfg.clk_gpio, cfg.dt_gpio, cfg.sw_gpio = None, None, None
        cfg.display = DialDisplayConfig(fitted=True, touch_type="none")
        server = self._real_server()

        self._run(cfg, server)

        assert server._can_confirm_presence is False

    def test_can_confirm_presence_false_when_touch_construction_raised(self):
        """A dial with touch_type configured whose driver failed to load has
        no WORKING confirmable input, regardless of configuration."""
        from dial_config import DialDisplayConfig

        cfg = _make_cfg()
        cfg.clk_gpio, cfg.dt_gpio, cfg.sw_gpio = None, None, None
        cfg.display = DialDisplayConfig(fitted=True, touch_type="xpt2046")
        server = self._real_server()
        build_mock = MagicMock(side_effect=RuntimeError("no SPI bus"))

        self._run(cfg, server, build_mock=build_mock)

        assert server._can_confirm_presence is False
