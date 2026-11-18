"""Tests for dial/dial_main.py lifecycle and shutdown.

Covers:
- SIGTERM sets shutdown event without blocking (plan test 3)
- SIGINT sets shutdown event without blocking (plan test 4)
- Final cleanup stops the mDNS browser and both servers (plan test 5)
- Shutdown event ends the main loop without another 5-second iteration (plan test 6)
- Fatal non-shutdown exceptions propagate (plan test 7)
"""
from __future__ import annotations

import os
import signal
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
_CORE = str(REPO_ROOT / "core")
for _p in (_DIAL, _CORE):
    if _p not in sys.path:
        sys.path.insert(0, _p)


@pytest.fixture(autouse=True)
def _no_hd_listener():
    """main() builds the HD page's server and hub; none of these tests may
    bind its real port."""
    import dial_main
    with patch.object(dial_main, "HdServer"), patch.object(dial_main, "ChangeHub"):
        yield


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


def _run_main_patched(shutdown_event_setter=None, raise_in_loop=None, fitted=True,
                      playing_targets=None):
    """Run dial_main.main() with all hardware and service dependencies patched.

    shutdown_event_setter: callable(shutdown_event) called in a background thread
        to trigger shutdown.
    raise_in_loop: if provided, raised instead of executing the loop body.
    fitted: cfg.display.fitted.
    playing_targets: if provided, what dial_main.get_playing_targets returns.
    """
    import dial_main as dm

    cfg = _make_cfg()
    cfg.display.fitted = fitted

    loop_iterations = [0]

    def fake_wait(timeout):
        loop_iterations[0] += 1
        if raise_in_loop is not None and loop_iterations[0] == 1:
            raise raise_in_loop
        # Return True (shutdown) after the first iteration.
        return True

    mock_led = MagicMock()
    # Set once the idle loop's body has run (it ends by setting the LED), so a
    # setter can wait for that rather than guess how long startup takes.
    loop_body_ran = threading.Event()
    mock_led.set_playing.side_effect = lambda: loop_body_ran.set()
    mock_led.set_idle.side_effect = lambda: loop_body_ran.set()
    mock_http = MagicMock()
    mock_control = MagicMock()

    # Capture the shutdown event that main() creates.
    captured_event = {}

    import _thread

    # Only the FIRST Event() constructed is main()'s own shutdown_event —
    # every later one is internal to the display/http/control stack. Guard
    # on that so the setter thread (and the capture) only ever fires once;
    # spawning it via the low-level _thread module (not threading.Thread)
    # avoids infinite recursion, since threading.Event is patched globally
    # here and threading.Thread.__init__ itself constructs an Event().
    _captured_once = []

    class _CapturingEvent(threading.Event):
        def __init__(self):
            super().__init__()
            if _captured_once:
                return
            _captured_once.append(self)
            captured_event["ev"] = self
            self.loop_body_ran = loop_body_ran
            if shutdown_event_setter is not None:
                def _fire():
                    time.sleep(0.05)
                    shutdown_event_setter(self)
                _thread.start_new_thread(_fire, ())

        def wait(self, timeout=None):
            return super().wait(timeout=min(timeout, 0.1) if timeout else 0.1)

    with patch("dial_main._configure_logging"), \
         patch("dial_main.load_config", return_value=cfg), \
         patch("dial_main._reconcile_update_timer"), \
         patch("dial_main._announce_self"), \
         patch("dial_main.DialLED", return_value=mock_led), \
         patch("dial_main.DialHTTPServer", return_value=mock_http), \
         patch("dial_main.start_volume_worker"), \
         patch("dial_main._start_peer_pool", wraps=dm._start_peer_pool) as mock_start_peer_pool, \
         patch("dial_main.PeerRegistry"), \
         patch("dial_main.start_network_worker"), \
         patch("dial_main.DialControlServer", return_value=mock_control), \
         patch("threading.Event", _CapturingEvent), \
         patch("dial_main.get_playing_targets",
               **({"return_value": playing_targets}
                  if playing_targets is not None else {"wraps": dm.get_playing_targets})):
        dm.main()

    return (
        captured_event.get("ev"), mock_http, mock_control, mock_start_peer_pool,
    )


class TestPeerPoolStartup:
    """The peer pool starts unconditionally, like the volume worker: every
    dial holds every sighted appliance, whatever its screen, and the core
    reads them from it."""

    def test_started_regardless_of_fitted(self):
        _ev, _http, _ctrl, start_pool = _run_main_patched(
            fitted=False, shutdown_event_setter=lambda ev: ev.set(),
        )
        start_pool.assert_called_once()

    def test_the_core_is_attached_to_the_pool(self):
        _ev, _http, _ctrl, start_pool = _run_main_patched(
            fitted=True, shutdown_event_setter=lambda ev: ev.set(),
        )
        core = start_pool.call_args.args[1]
        assert core.pool is not None and core.snapshot().polling


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
        mock_control = MagicMock()
        mock_encoder_setup = MagicMock(return_value="encoder-handle")
        mock_button_setup = MagicMock(return_value="button-handle")

        fake_gpio = MagicMock()
        fake_gpio.setup_rotary_encoder = mock_encoder_setup
        fake_gpio.setup_button = mock_button_setup

        class _QuickEvent(threading.Event):
            def wait(self, timeout=None):
                return True

        import builtins
        real_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name == "autostream_dial_gpio":
                return fake_gpio
            return real_import(name, *args, **kwargs)

        with patch("dial_main._configure_logging"), \
             patch("dial_main.load_config", return_value=cfg), \
             patch("dial_main._reconcile_update_timer"), \
             patch("dial_main._announce_self"), \
             patch("dial_main.DialLED"), \
             patch("dial_main.DialHTTPServer", return_value=mock_http), \
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.PeerRegistry"), \
             patch("dial_main.start_network_worker"), \
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
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.PeerRegistry"), \
             patch("dial_main.start_network_worker"), \
             patch("dial_main.DialControlServer") as mock_ctrl_cls, \
             patch("dial_main.signal.signal", side_effect=_capture_signal), \
             patch("threading.Event", _CapEvent):
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
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.PeerRegistry"), \
             patch("dial_main.start_network_worker"), \
             patch("dial_main.DialControlServer") as mock_ctrl_cls, \
             patch("dial_main.signal.signal", side_effect=_capture_signal), \
             patch("threading.Event", _CapEvent):
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
    def test_finally_stops_the_registry_then_the_servers(self):
        """On normal exit the finally block stops the peer registry (the one
        mDNS browser) before the servers."""
        import dial_main as dm

        cfg = _make_cfg()
        order = []

        mock_http = MagicMock()
        mock_http.stop.side_effect = lambda: order.append("http")
        mock_control = MagicMock()
        mock_control.stop.side_effect = lambda: order.append("control")

        class _QuickEvent(threading.Event):
            def wait(self, timeout=None):
                return True  # immediate shutdown

        registry = MagicMock()
        registry.return_value.stop.side_effect = lambda: order.append("browser")

        with patch("dial_main._configure_logging"), \
             patch("dial_main.load_config", return_value=cfg), \
             patch("dial_main._reconcile_update_timer"), \
             patch("dial_main._announce_self"), \
             patch("dial_main.DialLED"), \
             patch("dial_main.DialHTTPServer", return_value=mock_http), \
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.PeerRegistry", registry), \
             patch("dial_main.start_network_worker"), \
             patch("dial_main.DialControlServer", return_value=mock_control), \
             patch("threading.Event", _QuickEvent):
            dm.main()

        assert "browser" in order, "the peer registry must be stopped in finally"
        assert "control" in order, "control_server.stop() must be called in finally"
        assert "http" in order, "http_server.stop() must be called in finally"
        assert order.index("browser") < order.index("control"), (
            "browser must be stopped before control server"
        )

    def test_finally_runs_on_exception(self):
        """The finally block runs even when the loop body raises."""
        import dial_main as dm

        cfg = _make_cfg()
        browser_stopped = []
        registry = MagicMock()
        registry.return_value.stop.side_effect = lambda: browser_stopped.append(True)

        mock_http = MagicMock()
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
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.PeerRegistry", registry), \
             patch("dial_main.start_network_worker"), \
             patch("dial_main.DialControlServer", return_value=mock_control), \
             patch("threading.Event", _ExplodingEvent):
            with pytest.raises(RuntimeError):
                dm.main()

        assert browser_stopped, "the peer registry must be stopped even after an exception"

    def test_shutdown_exits_loop_without_extra_iteration(self):
        """When shutdown_event.wait(5) returns True, the loop body does not run."""
        import dial_main as dm

        cfg = _make_cfg()
        led_calls = []

        mock_led = MagicMock()
        mock_led.set_playing.side_effect = lambda: led_calls.append("playing")
        mock_led.set_idle.side_effect = lambda: led_calls.append("idle")

        mock_http = MagicMock()
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
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.PeerRegistry"), \
             patch("dial_main.start_network_worker"), \
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
        cfg.display = MagicMock(fitted=False, screen_size_inches=None)
        mock_http = MagicMock()
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
             patch("dial_main.start_volume_worker") as mock_vol_worker, \
             patch("dial_main.PeerRegistry"), \
             patch("dial_main.start_network_worker"), \
             patch("dial_main.DialControlServer", return_value=mock_control), \
             patch("threading.Event", _QuickEvent):
            dm.main()

        # The display passed to DialHTTPServer must be a real DialDisplay whose
        # thread has been started and cleanly stopped.
        _, kwargs = mock_http_cls.call_args
        display = kwargs["display_status_provider"]
        assert display.get_status()["fitted"] is False
        assert display._core._thread is None or not display._core._thread.is_alive()

        # start_volume_worker must be wired with the single-targeting
        # resolvers and the core's readout_changed (the core the display
        # paints, which main() builds).
        _, vol_kwargs = mock_vol_worker.call_args
        assert callable(vol_kwargs["mute_targets_fn"])
        assert vol_kwargs["on_readout_changed"] == display.core.readout_changed
        assert vol_kwargs["on_mute_changed"] == display.core.mute_changed

    def test_display_stack_import_failure_degrades_to_noop(self):
        """If dial_display (e.g. Pillow) is unavailable, main() must degrade to
        NoOpDisplayStatusProvider rather than fail the whole service — volume
        control must not depend on the display stack being importable."""
        import builtins
        import dial_main as dm
        from dial_screen_settings import NoOpDisplayStatusProvider

        cfg = _make_cfg()
        mock_http = MagicMock()
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
             patch("dial_main.start_volume_worker") as mock_vol_worker, \
             patch("dial_main.PeerRegistry"), \
             patch("dial_main.start_network_worker"), \
             patch("dial_main.DialControlServer", return_value=mock_control), \
             patch("threading.Event", _QuickEvent), \
             patch("builtins.__import__", side_effect=_fake_import):
            dm.main()  # must not raise

        _, kwargs = mock_http_cls.call_args
        assert isinstance(kwargs["display_status_provider"], NoOpDisplayStatusProvider)

        # The readout callback belongs to the core, which exists without a
        # screen, so volume is fully wired up regardless.
        _, vol_kwargs = mock_vol_worker.call_args
        assert vol_kwargs["on_readout_changed"].__name__ == "readout_changed"
        assert vol_kwargs["on_mute_changed"].__name__ == "mute_changed"
        assert callable(vol_kwargs["mute_targets_fn"])

    def test_display_stack_import_failure_still_runs_the_core(self):
        """Without the display stack the dial has no screen, but its appliance
        model is built, holds the appliances, is started with the service and
        stopped with it."""
        import builtins
        import dial_main as dm

        cfg = _make_cfg()
        cfg.display.fitted = True
        cfg.display.poll_interval_s = 3
        mock_http = MagicMock()
        mock_control = MagicMock()
        started = []

        class _QuickEvent(threading.Event):
            def wait(self, timeout=None):
                return True

        real_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name == "dial_display" or name.startswith("dial_display."):
                raise ImportError("simulated missing Pillow/display stack")
            return real_import(name, *args, **kwargs)

        from dial_core import DialCore
        real_start = DialCore.start

        def _start(core):
            real_start(core)
            started.append(core)

        with patch("dial_main._configure_logging"),              patch("dial_main.load_config", return_value=cfg),              patch("dial_main._reconcile_update_timer"),              patch("dial_main._announce_self"),              patch("dial_main.DialLED"),              patch("dial_main.DialHTTPServer", return_value=mock_http) as mock_http_cls,              patch("dial_main.start_volume_worker"),              patch("dial_main.PeerRegistry"),              patch("dial_main.start_network_worker"),              patch("dial_main.DialControlServer", return_value=mock_control),              patch.object(DialCore, "start", _start),              patch("threading.Event", _QuickEvent),              patch("builtins.__import__", side_effect=_fake_import):
            dm.main()

        _, kwargs = mock_http_cls.call_args
        display = kwargs["display_status_provider"]
        assert isinstance(display, dm._HeadlessDisplay)
        assert started[0].snapshot().polling is True
        assert len(started) == 1 and not started[0]._thread.is_alive()
        # The appliances stay held whatever the fitted flag says.
        display.update_config(type("Cfg", (), {"fitted": False})())
        assert started[0].snapshot().polling is True

    def test_fatal_exception_propagates(self):
        """A non-shutdown exception from control_server.start() propagates out."""
        import dial_main as dm

        cfg = _make_cfg()
        mock_http = MagicMock()
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
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.PeerRegistry"), \
             patch("dial_main.start_network_worker"), \
             patch("dial_main.DialControlServer", return_value=mock_control), \
             patch("threading.Event", _QuickEvent):
            with pytest.raises(OSError, match="socket bind failed"):
                dm.main()


# ---------------------------------------------------------------------------
# Unclean-shutdown signal: running.txt lifecycle.
#
# Nothing acts on the signal yet; this only establishes and logs it.
# Each test patches dial_recovery.RUNNING_MARKER_PATH to a tmp_path
# file so nothing touches the real /var/lib/autostream location.
# ---------------------------------------------------------------------------

class TestRunningMarkerLifecycle:
    def _run(self, marker_path, caplog=None, touch_side_effect=None, unlink_side_effect=None):
        import dial_main as dm

        cfg = _make_cfg()
        mock_http = MagicMock()
        mock_control = MagicMock()

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
            patch("dial_main.start_volume_worker"),
            patch("dial_main.PeerRegistry"),
            patch("dial_main.start_network_worker"),
            patch("dial_main.DialControlServer", return_value=mock_control),
            patch("threading.Event", _QuickEvent),
            patch("dial_recovery.RUNNING_MARKER_PATH", marker_path),
        ]
        for p in patches:
            p.start()
        try:
            if touch_side_effect is not None:
                with patch.object(type(marker_path), "touch", side_effect=touch_side_effect):
                    dm.main()
            elif unlink_side_effect is not None:
                with patch.object(type(marker_path), "unlink", side_effect=unlink_side_effect):
                    dm.main()
            else:
                dm.main()
        finally:
            for p in reversed(patches):
                p.stop()

    def test_marker_created_at_start(self, tmp_path):
        marker = tmp_path / "running.txt"
        assert not marker.exists()

        class _NeverShutdown(threading.Event):
            """Only used to observe the marker exists mid-run — main() still
            exits via the standard QuickEvent behaviour in _run()."""

        # Simplest check: the marker exists by the time main() returns, since
        # a clean shutdown deletes it — so assert existence DURING the run by
        # checking inside a patched _reconcile_update_timer callback instead.
        seen = {}

        def _observe(*_a, **_kw):
            seen["exists_after_create"] = marker.exists()

        import dial_main as dm

        cfg = _make_cfg()
        mock_http = MagicMock()
        mock_control = MagicMock()

        class _QuickEvent(threading.Event):
            def wait(self, timeout=None):
                return True

        with patch("dial_main._configure_logging"), \
             patch("dial_main.load_config", return_value=cfg), \
             patch("dial_main._reconcile_update_timer", side_effect=_observe), \
             patch("dial_main._announce_self"), \
             patch("dial_main.DialLED"), \
             patch("dial_main.DialHTTPServer", return_value=mock_http), \
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.PeerRegistry"), \
             patch("dial_main.start_network_worker"), \
             patch("dial_main.DialControlServer", return_value=mock_control), \
             patch("threading.Event", _QuickEvent), \
             patch("dial_recovery.RUNNING_MARKER_PATH", marker):
            dm.main()

        assert seen["exists_after_create"] is True, (
            "running marker must exist by the time startup proceeds past "
            "_reconcile_update_timer(), i.e. it is created early in main()"
        )

    def test_marker_removed_on_clean_shutdown(self, tmp_path):
        marker = tmp_path / "running.txt"
        self._run(marker)
        assert not marker.exists(), (
            "running marker must be deleted by the finally block on clean shutdown"
        )

    def test_survival_detected_and_logged_at_warning(self, tmp_path, caplog):
        marker = tmp_path / "running.txt"
        marker.write_text("")  # simulate survival from an unclean previous run
        with caplog.at_level("WARNING"):
            self._run(marker, caplog)
        assert "running marker survived" in caplog.text
        assert any(r.levelname == "WARNING" for r in caplog.records
                    if "running marker survived" in r.message)

    def test_no_warning_on_first_boot_when_marker_absent(self, tmp_path, caplog):
        marker = tmp_path / "running.txt"
        assert not marker.exists()
        with caplog.at_level("WARNING"):
            self._run(marker, caplog)
        assert "running marker survived" not in caplog.text

    def test_write_failure_does_not_prevent_startup(self, tmp_path, caplog):
        """A read-only/broken state directory must not stop the dial from
        starting — creating the marker is best-effort."""
        marker = tmp_path / "running.txt"
        with caplog.at_level("WARNING"):
            self._run(marker, caplog, touch_side_effect=OSError("read-only file system"))
        # main() must not have raised (the context manager above would have
        # propagated it) and the failure must be logged.
        assert "could not create running marker" in caplog.text

    def test_delete_failure_does_not_prevent_shutdown(self, tmp_path, caplog):
        """A failure to delete the marker must not prevent the rest of the
        finally block (and thus main()) from completing."""
        marker = tmp_path / "running.txt"
        with caplog.at_level("WARNING"):
            self._run(marker, caplog, unlink_side_effect=OSError("read-only file system"))
        assert "could not remove running marker" in caplog.text


# ---------------------------------------------------------------------------
# PIN-recovery arm-request evaluation: the clock-sync-aware age check in
# isolation (no dial_main.main() involved, no real sleeping).
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# PIN-recovery arming decision wired through dial_main.main(): arm only when
# the running marker survived AND a request file is present, consuming the
# request only in that branch. Each test patches dial_recovery's
# RUNNING_MARKER_PATH, PIN_RESET_PATH and _TIMESYNC_MARKER_PATH to tmp_path files so nothing
# touches the real /var/lib/autostream or /run locations.
# ---------------------------------------------------------------------------

class TestRecoveryArmingDecision:
    def _run(
        self, tmp_path, *, running_marker_present, request_present,
        cfg_pin="1234", synced=True, request_mtime_offset=0.0, caplog=None,
    ):
        import dial_main as dm

        cfg = _make_cfg()
        cfg.pin = cfg_pin

        running_marker = tmp_path / "running.txt"
        if running_marker_present:
            running_marker.write_text("")

        request_path = tmp_path / "pin_reset.txt"
        if request_present:
            request_path.write_text("")
            if request_mtime_offset:
                t = time.time() + request_mtime_offset
                os.utime(request_path, (t, t))

        sync_marker = tmp_path / "synchronized"
        if synced:
            sync_marker.write_text("")

        mock_http = MagicMock()
        mock_control = MagicMock()

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
            patch("dial_main.start_volume_worker"),
            patch("dial_main.PeerRegistry"),
            patch("dial_main.start_network_worker"),
            patch("dial_main.DialControlServer", return_value=mock_control),
            patch("threading.Event", _QuickEvent),
            patch("dial_recovery.RUNNING_MARKER_PATH", running_marker),
            patch("dial_recovery.PIN_RESET_PATH", request_path),
            patch("dial_recovery._TIMESYNC_MARKER_PATH", sync_marker),
        ]
        for p in patches:
            p.start()
        try:
            if caplog is not None:
                with caplog.at_level("WARNING"):
                    dm.main()
            else:
                dm.main()
        finally:
            for p in reversed(patches):
                p.stop()

        return mock_http, request_path

    def test_both_present_arms(self, tmp_path):
        mock_http, _ = self._run(
            tmp_path, running_marker_present=True, request_present=True
        )
        mock_http.begin_recovery_window.assert_called_once()

    def test_running_marker_absent_does_not_arm(self, tmp_path):
        mock_http, _ = self._run(
            tmp_path, running_marker_present=False, request_present=True
        )
        mock_http.begin_recovery_window.assert_not_called()

    def test_request_absent_does_not_arm(self, tmp_path):
        mock_http, _ = self._run(
            tmp_path, running_marker_present=True, request_present=False
        )
        mock_http.begin_recovery_window.assert_not_called()

    def test_no_pin_configured_does_not_arm(self, tmp_path):
        mock_http, _ = self._run(
            tmp_path, running_marker_present=True, request_present=True,
            cfg_pin=None,
        )
        mock_http.begin_recovery_window.assert_not_called()

    def test_request_deleted_only_in_both_present_branch(self, tmp_path):
        _, request_path = self._run(
            tmp_path, running_marker_present=True, request_present=True
        )
        assert not request_path.exists()

    def test_request_survives_when_running_marker_absent(self, tmp_path):
        """An unrelated restart between arming and power-cycling (clean
        shutdown, so the running marker does NOT survive) must leave the
        request intact rather than silently disarming it."""
        _, request_path = self._run(
            tmp_path, running_marker_present=False, request_present=True
        )
        assert request_path.exists()

    def test_fresh_request_arms_when_synced(self, tmp_path):
        mock_http, request_path = self._run(
            tmp_path, running_marker_present=True, request_present=True,
        )
        mock_http.begin_recovery_window.assert_called_once()

    def test_stale_request_does_not_arm_when_synced(self, tmp_path):
        mock_http, request_path = self._run(
            tmp_path, running_marker_present=True, request_present=True,
            request_mtime_offset=-(30 * 60 + 60),
        )
        mock_http.begin_recovery_window.assert_not_called()
        # Still consumed: the both-present branch was entered even though
        # the age check failed.
        assert not request_path.exists()

    def test_unsynced_clock_honours_arm_and_logs_skip(self, tmp_path, caplog, monkeypatch):
        import dial_recovery

        # Shrink the poll timeout for this test only, so main() cannot block
        # on a real wait if this ever regresses to using real time.sleep.
        monkeypatch.setattr(dial_recovery, "_TIMESYNC_POLL_TIMEOUT_S", 0)

        mock_http, _ = self._run(
            tmp_path, running_marker_present=True, request_present=True,
            synced=False, caplog=caplog,
        )

        mock_http.begin_recovery_window.assert_called_once()
        assert "clock not yet synchronised" in caplog.text

    def test_no_wait_when_no_request_file(self, tmp_path):
        """A normal boot with no pending request must never even reach the
        age/sync check — nothing should delay startup."""
        with patch("dial_recovery._recovery_request_within_window") as mock_eval:
            self._run(
                tmp_path, running_marker_present=True, request_present=False
            )
        mock_eval.assert_not_called()


# ---------------------------------------------------------------------------
# Live POST /screen/settings apply against a running DialDisplay.
# ---------------------------------------------------------------------------

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
        from dial_core import DialCore
        from dial_display import DialDisplay
        from dial_display_backend import NoOpBackend
        from dial_http_server import DialHTTPServer
        from dial_screen_settings import ScreenSettingsService

        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=False))
        display = DialDisplay(
            config=cfg.display,
            core=DialCore(cfg.uuid),
            backend_factory=NoOpBackend,
        )
        server = DialHTTPServer.__new__(DialHTTPServer)
        server._cfg = cfg
        server._cfg_lock = __import__("threading").Lock()
        server._recovery_window = MagicMock()
        server._screen = ScreenSettingsService(
            config=server.config_snapshot, update_cfg=server.update_cfg,
            display_status=display,
        )

        assert display.get_status()["fitted"] is False

        result = self._post_screen_settings(server, {"screen": {"fitted": True}})

        assert result["status"] == 200
        assert result["data"]["ok"] is True
        assert result["data"]["runtime"]["fitted"] is True
        # The *same* running display manager instance must reflect the change.
        assert display.get_status()["fitted"] is True

    def test_post_screen_settings_toggles_rotate_on_real_display_manager(self):
        from dial_config import DialConfig, DialDisplayConfig
        from dial_core import DialCore
        from dial_display import DialDisplay
        from dial_display_backend import NoOpBackend
        from dial_http_server import DialHTTPServer
        from dial_screen_settings import ScreenSettingsService

        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=True, rotate=False))
        display = DialDisplay(
            config=cfg.display,
            core=DialCore(cfg.uuid),
            backend_factory=NoOpBackend,
        )
        display.enable()
        server = DialHTTPServer.__new__(DialHTTPServer)
        server._cfg = cfg
        server._cfg_lock = __import__("threading").Lock()
        server._recovery_window = MagicMock()
        server._screen = ScreenSettingsService(
            config=server.config_snapshot, update_cfg=server.update_cfg,
            display_status=display,
        )

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
        from dial_core import DialCore
        from dial_display import DialDisplay
        from dial_display_backend import NoOpBackend
        from dial_http_server import DialHTTPServer
        from dial_screen_settings import ScreenSettingsService

        cfg = DialConfig(uuid="x", display=DialDisplayConfig(fitted=True, bgr=False))
        display = DialDisplay(
            config=cfg.display,
            core=DialCore(cfg.uuid),
            backend_factory=NoOpBackend,
        )
        display.enable()
        server = DialHTTPServer.__new__(DialHTTPServer)
        server._cfg = cfg
        server._cfg_lock = __import__("threading").Lock()
        server._recovery_window = MagicMock()
        server._screen = ScreenSettingsService(
            config=server.config_snapshot, update_cfg=server.update_cfg,
            display_status=display,
        )

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
            patch("dial_main.start_volume_worker"),
            patch("dial_main.PeerRegistry"),
            patch("dial_main.start_network_worker"),
            patch("dial_main.DialControlServer", return_value=mock_control),
            patch("threading.Event", _QuickEvent),
            patch("dial_main.build_touch_source", build_mock),
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
        mock_control = MagicMock()
        mock_encoder_setup = MagicMock(return_value="encoder-handle")
        mock_button_setup = MagicMock(return_value="button-handle")

        fake_gpio = MagicMock()
        fake_gpio.setup_rotary_encoder = mock_encoder_setup
        fake_gpio.setup_button = mock_button_setup

        import builtins
        real_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name == "autostream_dial_gpio":
                return fake_gpio
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
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.PeerRegistry"), \
             patch("dial_main.start_network_worker"), \
             patch("dial_main.DialControlServer", return_value=mock_control), \
             patch("threading.Event", _QuickEvent), \
             patch("dial_main.build_touch_source", side_effect=RuntimeError("boom")), \
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
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.PeerRegistry"), \
             patch("dial_main.start_network_worker"), \
             patch("dial_main.DialControlServer", return_value=mock_control), \
             patch("threading.Event", _QuickEvent), \
             patch("dial_main.build_touch_source", build_mock), \
             patch("builtins.__import__", side_effect=_fake_import):
            dm.main()  # must not raise

        build_mock.assert_not_called()


# ---------------------------------------------------------------------------
# build_touch_source() building the filter/state machine at the configured
# layout size — layout_context_for(cfg.display) is the single source both
# are built from.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# _build_volume_targets_fn(): zero-arg resolver for the volume worker — the
# display's artwork source when it has one and it is still present in the
# target list, else the oldest playing target (select_volume_target's
# fallback). Must degrade gracefully for a NoOpDisplayStatusProvider (no
# current_source_service_name at all) or a raising accessor — display
# failure must never affect volume control.
# ---------------------------------------------------------------------------

class TestVolumeTargetsResolver:
    def _targets(self):
        from dial_mdns import PlayingTarget
        older = PlayingTarget(ip="1.0.0.1", port=80, name="Older", service_name="older", appliance_id="older", playing_since=10.0)
        newer = PlayingTarget(ip="1.0.0.2", port=80, name="Newer", service_name="newer", appliance_id="newer", playing_since=20.0)
        return [older, newer]

    def test_display_reports_a_present_service_name_even_if_not_oldest(self):
        import dial_main as dm

        targets = self._targets()
        display = MagicMock(spec=["current_source_service_name"])
        display.current_source_service_name = MagicMock(return_value="newer")
        resolve = dm._build_volume_targets_fn(display, get_targets=lambda: targets)

        assert resolve() == [targets[1]]

    def test_display_reports_a_name_no_longer_present_falls_back_to_oldest(self):
        import dial_main as dm

        targets = self._targets()
        display = MagicMock(spec=["current_source_service_name"])
        display.current_source_service_name = MagicMock(return_value="vanished")
        resolve = dm._build_volume_targets_fn(display, get_targets=lambda: targets)

        assert resolve() == [targets[0]]

    def test_display_reports_none_falls_back_to_oldest(self):
        import dial_main as dm

        targets = self._targets()
        display = MagicMock(spec=["current_source_service_name"])
        display.current_source_service_name = MagicMock(return_value=None)
        resolve = dm._build_volume_targets_fn(display, get_targets=lambda: targets)

        assert resolve() == [targets[0]]

    def test_noop_display_status_provider_has_no_accessor_falls_back_to_oldest(self):
        import dial_main as dm
        from dial_screen_settings import NoOpDisplayStatusProvider

        targets = self._targets()
        display = NoOpDisplayStatusProvider()
        assert not hasattr(display, "current_source_service_name")
        resolve = dm._build_volume_targets_fn(display, get_targets=lambda: targets)

        assert resolve() == [targets[0]]

    def test_raising_accessor_falls_back_to_oldest(self):
        import dial_main as dm

        targets = self._targets()
        display = MagicMock(spec=["current_source_service_name"])

        def boom():
            raise RuntimeError("display broke")

        display.current_source_service_name = boom
        resolve = dm._build_volume_targets_fn(display, get_targets=lambda: targets)

        assert resolve() == [targets[0]]

    def test_no_targets_returns_empty_list(self):
        import dial_main as dm

        display = MagicMock(spec=["current_source_service_name"])
        display.current_source_service_name = MagicMock(return_value="anything")
        resolve = dm._build_volume_targets_fn(display, get_targets=lambda: [])

        assert resolve() == []

    def test_unauthorized_target_is_excluded(self):
        import dial_main as dm
        from dial_mdns import PlayingTarget

        older = PlayingTarget(ip="1.0.0.1", port=80, name="Older", service_name="older", appliance_id="older",
                               playing_since=10.0, auth="unauthorized")
        newer = PlayingTarget(ip="1.0.0.2", port=80, name="Newer", service_name="newer", appliance_id="newer",
                               playing_since=20.0, auth="unknown")
        display = MagicMock(spec=["current_source_service_name"])
        display.current_source_service_name = MagicMock(return_value=None)
        resolve = dm._build_volume_targets_fn(display, get_targets=lambda: [older, newer])

        assert resolve() == [newer]

    def test_unknown_auth_target_remains_eligible(self):
        """An appliance not yet confirmed either way must stay controllable —
        only a confirmed 412 (unauthorized) removes a row."""
        import dial_main as dm
        from dial_mdns import PlayingTarget

        t = PlayingTarget(ip="1.0.0.1", port=80, name="X", service_name="x", appliance_id="x",
                           playing_since=1.0, auth="unknown")
        display = MagicMock(spec=["current_source_service_name"])
        display.current_source_service_name = MagicMock(return_value=None)
        resolve = dm._build_volume_targets_fn(display, get_targets=lambda: [t])

        assert resolve() == [t]

    def test_authorized_target_remains_eligible(self):
        import dial_main as dm
        from dial_mdns import PlayingTarget

        t = PlayingTarget(ip="1.0.0.1", port=80, name="X", service_name="x", appliance_id="x",
                           playing_since=1.0, auth="authorized")
        display = MagicMock(spec=["current_source_service_name"])
        display.current_source_service_name = MagicMock(return_value=None)
        resolve = dm._build_volume_targets_fn(display, get_targets=lambda: [t])

        assert resolve() == [t]

    def test_all_unauthorized_returns_empty(self):
        import dial_main as dm
        from dial_mdns import PlayingTarget

        t = PlayingTarget(ip="1.0.0.1", port=80, name="X", service_name="x", appliance_id="x",
                           playing_since=1.0, auth="unauthorized")
        display = MagicMock(spec=["current_source_service_name"])
        display.current_source_service_name = MagicMock(return_value=None)
        resolve = dm._build_volume_targets_fn(display, get_targets=lambda: [t])

        assert resolve() == []

    def test_focus_volume_target_wins_regardless_of_get_targets(self):
        import dial_main as dm

        targets = self._targets()
        focused = object()
        display = MagicMock(spec=["current_source_service_name", "focus_volume_target"])
        display.current_source_service_name = MagicMock(return_value="newer")
        display.focus_volume_target = MagicMock(return_value=focused)
        resolve = dm._build_volume_targets_fn(display, get_targets=lambda: targets)

        assert resolve() == [focused]

    def test_focus_volume_target_returning_none_falls_back_to_today(self):
        import dial_main as dm

        targets = self._targets()
        display = MagicMock(spec=["current_source_service_name", "focus_volume_target"])
        display.current_source_service_name = MagicMock(return_value="newer")
        display.focus_volume_target = MagicMock(return_value=None)
        resolve = dm._build_volume_targets_fn(display, get_targets=lambda: targets)

        assert resolve() == [targets[1]]

    def test_raising_focus_volume_target_falls_back_to_today(self):
        import dial_main as dm

        targets = self._targets()
        display = MagicMock(spec=["current_source_service_name", "focus_volume_target"])
        display.current_source_service_name = MagicMock(return_value=None)

        def boom():
            raise RuntimeError("focus accessor broke")

        display.focus_volume_target = boom
        resolve = dm._build_volume_targets_fn(display, get_targets=lambda: targets)

        assert resolve() == [targets[0]]

    def test_scope_fn_returning_all_returns_every_playing_target_ignoring_focus(self):
        """Broadcast scope "all": every playing target with auth !=
        unauthorized, in roster order, with any manual focus ignored -- a
        fleet-wide twist has no single appliance to pin to."""
        import dial_main as dm
        from dial_mdns import PlayingTarget

        targets = self._targets()
        blocked = PlayingTarget(ip="1.0.0.3", port=80, name="Blocked", service_name="blocked", appliance_id="blocked",
                                 playing_since=30.0, auth="unauthorized")
        focused = object()
        display = MagicMock(spec=["current_source_service_name", "focus_volume_target"])
        display.current_source_service_name = MagicMock(return_value="newer")
        display.focus_volume_target = MagicMock(return_value=focused)
        resolve = dm._build_volume_targets_fn(
            display, get_targets=lambda: targets, scope_fn=lambda: "all",
            get_all_targets=lambda: targets + [blocked],
        )

        assert resolve() == targets

    def test_scope_fn_returning_current_keeps_todays_single_target_behaviour(self):
        import dial_main as dm

        targets = self._targets()
        display = MagicMock(spec=["current_source_service_name"])
        display.current_source_service_name = MagicMock(return_value="newer")
        resolve = dm._build_volume_targets_fn(
            display, get_targets=lambda: targets, scope_fn=lambda: "current",
        )

        assert resolve() == [targets[1]]

    def test_scope_fn_none_keeps_todays_single_target_behaviour(self):
        """No scope_fn supplied at all (an older call site, or a test) must
        behave exactly as before this feature existed."""
        import dial_main as dm

        targets = self._targets()
        display = MagicMock(spec=["current_source_service_name"])
        display.current_source_service_name = MagicMock(return_value=None)
        resolve = dm._build_volume_targets_fn(display, get_targets=lambda: targets)

        assert resolve() == [targets[0]]

    def test_scope_fn_called_fresh_per_resolve(self):
        """The live-read discipline every resolver here follows: a
        /screen/settings save applies to the very next twist with no
        restart."""
        import dial_main as dm

        targets = self._targets()
        display = MagicMock(spec=["current_source_service_name"])
        display.current_source_service_name = MagicMock(return_value="newer")
        scope = {"value": "current"}
        resolve = dm._build_volume_targets_fn(
            display, get_targets=lambda: targets, scope_fn=lambda: scope["value"],
            get_all_targets=lambda: targets,
        )

        assert resolve() == [targets[1]]
        scope["value"] = "all"
        assert resolve() == targets


# ---------------------------------------------------------------------------
# Effective scope end to end: an http server over a live config, exercised
# through the SAME resolvers main() wires up, proves fitted=False forces
# broadcast to every target regardless of the stored scope.
# ---------------------------------------------------------------------------

class TestEffectiveScopeEndToEnd:
    def _server(self, *, fitted, volume_scope="current", mute_scope="current"):
        from dial_config import DialConfig, DialDisplayConfig
        from dial_http_server import DialHTTPServer

        cfg = DialConfig(uuid="x", display=DialDisplayConfig(
            fitted=fitted, volume_scope=volume_scope, mute_scope=mute_scope,
        ))
        server = DialHTTPServer.__new__(DialHTTPServer)
        server._cfg = cfg
        server._cfg_lock = threading.Lock()
        return server

    def test_unfitted_screen_forces_volume_resolver_to_every_target(self):
        import dial_main as dm
        from dial_mdns import PlayingTarget

        http_server = self._server(fitted=False)
        targets = [
            PlayingTarget(ip="1.0.0.1", port=80, name=n, service_name=n, appliance_id=n)
            for n in ("a", "b")
        ]
        display = MagicMock(spec=["current_source_service_name"])
        display.current_source_service_name = MagicMock(return_value="a")
        resolve = dm._build_volume_targets_fn(
            display, get_targets=lambda: targets,
            scope_fn=lambda: http_server.effective_volume_scope,
            get_all_targets=lambda: targets,
        )

        assert resolve() == targets

    def test_fitted_screen_with_current_scope_gives_the_single_target(self):
        import dial_main as dm
        from dial_mdns import PlayingTarget

        http_server = self._server(fitted=True, volume_scope="current")
        targets = [
            PlayingTarget(ip="1.0.0.1", port=80, name=n, service_name=n, appliance_id=n)
            for n in ("a", "b")
        ]
        display = MagicMock(spec=["current_source_service_name"])
        display.current_source_service_name = MagicMock(return_value="a")
        resolve = dm._build_volume_targets_fn(
            display, get_targets=lambda: targets,
            scope_fn=lambda: http_server.effective_volume_scope,
            get_all_targets=lambda: targets,
        )

        assert resolve() == [targets[0]]

    def test_unfitted_screen_forces_mute_resolver_to_every_target(self):
        import dial_main as dm
        from dial_mdns import PlayingTarget

        http_server = self._server(fitted=False)
        targets = [
            PlayingTarget(ip="1.0.0.1", port=80, name=n, service_name=n, appliance_id=n)
            for n in ("a", "b")
        ]
        volume_targets_fn = MagicMock(return_value=["single-target"])
        resolve = dm._build_mute_targets_fn(http_server, volume_targets_fn, get_all_targets=lambda: targets)

        assert resolve() == targets

    def test_fitted_screen_with_current_scope_gives_the_single_mute_target(self):
        import dial_main as dm
        from dial_mdns import PlayingTarget

        http_server = self._server(fitted=True, mute_scope="current")
        targets = [
            PlayingTarget(ip="1.0.0.1", port=80, name=n, service_name=n, appliance_id=n)
            for n in ("a", "b")
        ]
        volume_targets_fn = MagicMock(return_value=["single-target"])
        resolve = dm._build_mute_targets_fn(http_server, volume_targets_fn, get_all_targets=lambda: targets)

        assert resolve() == ["single-target"]


# ---------------------------------------------------------------------------
# _build_mute_targets_fn(): fleet-wide when the live effective mute scope is
# "all" (read live from http_server, not a captured cfg value), else the
# same single target volume uses.
# ---------------------------------------------------------------------------

class TestMuteTargetsResolver:
    def test_scope_current_returns_volume_resolvers_list(self):
        import dial_main as dm

        http_server = MagicMock()
        http_server.effective_mute_scope = "current"
        volume_targets_fn = MagicMock(return_value=["single-target"])
        all_targets_fn = MagicMock(return_value=["a", "b", "c"])

        resolve = dm._build_mute_targets_fn(http_server, volume_targets_fn, get_all_targets=all_targets_fn)

        assert resolve() == ["single-target"]
        all_targets_fn.assert_not_called()

    def test_scope_all_returns_every_playing_target(self):
        import dial_main as dm
        from dial_mdns import PlayingTarget

        http_server = MagicMock()
        http_server.effective_mute_scope = "all"
        volume_targets_fn = MagicMock(return_value=["single-target"])
        targets = [
            PlayingTarget(ip="1.0.0.1", port=80, name=n, service_name=n, appliance_id=n)
            for n in ("a", "b", "c")
        ]
        all_targets_fn = MagicMock(return_value=targets)

        resolve = dm._build_mute_targets_fn(http_server, volume_targets_fn, get_all_targets=all_targets_fn)

        assert resolve() == targets
        volume_targets_fn.assert_not_called()

    def test_setting_is_read_live_not_captured_at_build_time(self):
        """A /screen/settings change to the mute scope (or the screen being
        unfitted) must apply to the very next mute press without rebuilding
        the resolver — the resolver reads http_server.effective_mute_scope
        on every call."""
        import dial_main as dm
        from dial_mdns import PlayingTarget

        class _FakeServer:
            effective_mute_scope = "current"

        server = _FakeServer()
        volume_targets_fn = MagicMock(return_value=["single-target"])
        targets = [
            PlayingTarget(ip="1.0.0.1", port=80, name=n, service_name=n, appliance_id=n)
            for n in ("a", "b")
        ]
        all_targets_fn = MagicMock(return_value=targets)
        resolve = dm._build_mute_targets_fn(server, volume_targets_fn, get_all_targets=all_targets_fn)

        assert resolve() == ["single-target"]
        server.effective_mute_scope = "all"
        assert resolve() == targets

    def test_unauthorized_targets_excluded_from_mute_all(self):
        import dial_main as dm
        from dial_mdns import PlayingTarget

        http_server = MagicMock()
        http_server.effective_mute_scope = "all"
        volume_targets_fn = MagicMock(return_value=[])
        authorized = PlayingTarget(ip="1.0.0.1", port=80, name="A", service_name="a", appliance_id="a", auth="unknown")
        blocked = PlayingTarget(ip="1.0.0.2", port=80, name="B", service_name="b", appliance_id="b", auth="unauthorized")
        all_targets_fn = MagicMock(return_value=[authorized, blocked])

        resolve = dm._build_mute_targets_fn(http_server, volume_targets_fn, get_all_targets=all_targets_fn)

        assert resolve() == [authorized]

    def test_identityless_targets_excluded_from_every_resolution(self):
        import dial_main as dm
        from dial_mdns import PlayingTarget

        identified = PlayingTarget(ip="1.0.0.1", port=80, name="A", service_name="a",
                                   appliance_id="a", playing_since=20.0)
        anonymous = PlayingTarget(ip="1.0.0.2", port=80, name="B", service_name="b",
                                  appliance_id="", playing_since=10.0)
        both = [anonymous, identified]
        display = MagicMock(spec=["current_source_service_name"])
        display.current_source_service_name = MagicMock(return_value="b")

        single = dm._build_volume_targets_fn(display, get_targets=lambda: both)
        assert single() == [identified]
        fan_out = dm._build_volume_targets_fn(
            display, get_targets=lambda: both, scope_fn=lambda: "all", get_all_targets=lambda: both,
        )
        assert fan_out() == [identified]
        http_server = MagicMock()
        http_server.effective_mute_scope = "all"
        mute = dm._build_mute_targets_fn(http_server, single, get_all_targets=lambda: both)
        assert mute() == [identified]
        assert dm._build_volume_targets_fn(display, get_targets=lambda: [anonymous])() == []

    def test_single_target_mute_follows_the_focus_entry(self):
        """scope "current": single-target mute is exactly whatever the
        volume resolver returns, so a focus on an idle appliance (built
        through the real volume resolver) reaches mute unchanged."""
        import dial_main as dm

        http_server = MagicMock()
        http_server.effective_mute_scope = "current"
        focused = object()
        display = MagicMock(spec=["current_source_service_name", "focus_volume_target"])
        display.current_source_service_name = MagicMock(return_value=None)
        display.focus_volume_target = MagicMock(return_value=focused)
        volume_targets_fn = dm._build_volume_targets_fn(display, get_targets=lambda: [])

        resolve = dm._build_mute_targets_fn(http_server, volume_targets_fn)

        assert resolve() == [focused]


# ---------------------------------------------------------------------------
# The one thing a mute push does, shared by the touch MUTE zone and the
# physical button: DialCore.mute_toggle(), with the scope read live from the
# HTTP server through the injected callable.
# ---------------------------------------------------------------------------

def _core_with_mute_scope(scope, source="svc"):
    from dial_core import DialCore

    http_server = MagicMock()
    http_server.effective_mute_scope = scope
    core = DialCore("d" * 20)
    core.set_mute_scope(lambda: http_server.effective_mute_scope)
    core.current_source_service_name = MagicMock(return_value=source)
    return core


class TestMuteToggleDecision:
    def test_scope_current_enqueues_mute_with_the_flipped_reported_state(self):
        core = _core_with_mute_scope("current")

        with patch("dial_core.shown_muted", return_value=False) as mock_shown, \
             patch("dial_core.enqueue_mute") as mock_enqueue, \
             patch("dial_core.enqueue_mute_all") as mock_enqueue_all:
            core.mute_toggle()

        mock_shown.assert_called_once_with("svc")
        mock_enqueue.assert_called_once_with(False)
        mock_enqueue_all.assert_not_called()

    def test_scope_all_enqueues_one_fleet_toggle_and_writes_nothing_to_the_store(self):
        import dial_volume as dv

        core = _core_with_mute_scope("all")

        dv.observe_mute_state("svc", False)
        try:
            with patch("dial_core.enqueue_mute") as mock_enqueue:
                core.mute_toggle()
            mock_enqueue.assert_not_called()
            # The store is untouched -- the fleet action is decided later,
            # on the worker thread, not here.
            assert dv.shown_muted("svc") is False
            assert dv._queue.get_nowait() == ("mute_all", 1)
        finally:
            dv.observe_mute_state(None, None)

    def test_neither_scope_performs_network_io(self):
        for scope in ("current", "all"):
            core = _core_with_mute_scope(scope)

            def boom(*a, **kw):
                raise AssertionError("mute toggle performed network I/O")

            with patch("urllib.request.urlopen", side_effect=boom):
                core.mute_toggle()  # must not raise


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
    def _run(self, *, fitted=True, effective_mute_scope="current"):
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
        # touch_type stays "xpt2046" (and build_touch_source is exercised)
        # even for the fitted=False run below: main() only skips
        # constructing touch when fitted is False, so that run's assertions
        # exercise the physical button entry point alone, which is fine --
        # the button never depended on the screen either.
        cfg.display = DialDisplayConfig(fitted=fitted, touch_type="xpt2046")

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

        fake_gpio = MagicMock()
        fake_gpio.setup_rotary_encoder = MagicMock(return_value=None)
        fake_gpio.setup_button = fake_setup_button

        import builtins
        real_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name == "autostream_dial_gpio":
                return fake_gpio
            return real_import(name, *args, **kwargs)

        class _QuickEvent(threading.Event):
            def wait(self, timeout=None):
                return True

        mock_http = MagicMock()
        mock_http.effective_mute_scope = effective_mute_scope

        with patch("dial_main._configure_logging"), \
             patch("dial_main.load_config", return_value=cfg), \
             patch("dial_main._reconcile_update_timer"), \
             patch("dial_main._announce_self"), \
             patch("dial_main.DialLED"), \
             patch("dial_main.DialHTTPServer", return_value=mock_http), \
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.PeerRegistry"), \
             patch("dial_main.start_network_worker"), \
             patch("dial_main.DialControlServer"), \
             patch("dial_touch_drivers.open_driver"), \
             patch("dial_touch_source.TouchEventSource", side_effect=fake_touch_event_source), \
             patch.object(dd, "create_dial_display", side_effect=spy_create_dial_display), \
             patch("threading.Event", _QuickEvent), \
             patch("builtins.__import__", side_effect=_fake_import):
            dm.main()

        return captured

    @staticmethod
    def _assert_lock_free_and_network_free(display, entry_points):
        def _network_call_forbidden(*args, **kwargs):
            raise AssertionError("a mute press entry point performed network I/O")

        with patch("urllib.request.urlopen", side_effect=_network_call_forbidden):
            # Hold DialDisplay's own lock in THIS thread. If any entry point
            # tried to acquire it (directly, or via a display method that
            # isn't actually lock-free), the call below would block for the
            # full join timeout instead of returning immediately.
            held = display._lock.acquire(blocking=False)
            assert held, "test setup: could not acquire display._lock to hold it"
            try:
                for name, entry_point in entry_points:
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

    def test_neither_entry_point_blocks_on_display_lock_or_touches_the_network(self):
        captured = self._run()
        display = captured["display"]
        on_mute_toggle = captured["touch_kwargs"]["on_mute_toggle"]
        on_press = captured["on_press"]

        self._assert_lock_free_and_network_free(display, [
            ("touch mute zone", on_mute_toggle),
            ("physical button", on_press),
        ])

    def test_scope_all_entry_points_stay_lock_free_and_network_free(self):
        """Under broadcast scope "all" both entry points enqueue a fleet
        toggle (enqueue_mute_all()) instead of enqueue_mute() -- the fleet
        status sweep that decides the action happens later, on the volume
        worker thread, never here."""
        captured = self._run(effective_mute_scope="all")
        display = captured["display"]
        on_mute_toggle = captured["touch_kwargs"]["on_mute_toggle"]
        on_press = captured["on_press"]

        self._assert_lock_free_and_network_free(display, [
            ("touch mute zone (scope all)", on_mute_toggle),
            ("physical button (scope all)", on_press),
        ])

    def test_fitted_false_button_entry_point_stays_lock_free_and_network_free(self):
        """A screenless dial builds no touch stack at all, but the physical
        button entry point must stay just as lock-free and network-free."""
        captured = self._run(fitted=False)
        display = captured["display"]
        on_press = captured["on_press"]

        self._assert_lock_free_and_network_free(display, [
            ("physical button (fitted=False)", on_press),
        ])


# ---------------------------------------------------------------------------
# The info page's data provider: wired after the HTTP server exists, before
# display.start(), against a REAL DialDisplay (spied via create_dial_display)
# — proves the actual lambda dial_main builds, not a hand-rolled stand-in.
# ---------------------------------------------------------------------------

class TestInfoProviderWiring:
    def _run(self):
        import dial_main as dm
        import dial_display as dd
        from dial_config import DialConfig, DialDisplayConfig

        cfg = DialConfig(
            uuid="info-wiring-uuid", sw_gpio=None, clk_gpio=None, dt_gpio=None,
            led_gpio=None, pin="",
        )
        cfg.display = DialDisplayConfig(fitted=True, touch_type="xpt2046")

        captured: dict = {}
        real_create_dial_display = dd.create_dial_display

        def spy_create_dial_display(*args, **kwargs):
            instance = real_create_dial_display(*args, **kwargs)
            captured["display"] = instance
            return instance

        mock_http = MagicMock()
        mock_http.get_runtime_status.return_value = {"name": "Kitchen Dial"}
        captured["http"] = mock_http

        class _QuickEvent(threading.Event):
            def wait(self, timeout=None):
                return True

        with patch("dial_main._configure_logging"), \
             patch("dial_main.load_config", return_value=cfg), \
             patch("dial_main._reconcile_update_timer"), \
             patch("dial_main._announce_self"), \
             patch("dial_main.DialLED"), \
             patch("dial_main.DialHTTPServer", return_value=mock_http), \
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.PeerRegistry"), \
             patch("dial_main.start_network_worker") as mock_net_worker, \
             patch("dial_main.DialControlServer"), \
             patch.object(dd, "create_dial_display", side_effect=spy_create_dial_display), \
             patch("threading.Event", _QuickEvent):
            dm.main()

        captured["start_network_worker"] = mock_net_worker
        return captured

    def test_provider_wired_and_calls_gather_dial_info_with_live_name_and_version(self):
        import dial_main as dm

        captured = self._run()
        display = captured["display"]
        assert display._get_info_rows is not None

        with patch("dial_main.gather_dial_info", return_value=(("Dial name", "Kitchen Dial"),)) as mock_gather, \
             patch("dial_main.network_latest", return_value="sentinel-view"), \
             patch("dial_main.dial_sdhealth.info_value", return_value="87% Good"):
            rows = display._get_info_rows()
        mock_gather.assert_called_once_with(
            "Kitchen Dial", dm.VERSION, network="sentinel-view", sd_health="87% Good", uuid="info-wiring-uuid",
        )
        assert rows == (("Dial name", "Kitchen Dial"),)

    def test_provider_reads_the_live_runtime_name_not_a_stale_snapshot(self):
        """get_runtime_status() is called fresh on every provider
        invocation, not once at wiring time — a /configure rename must show
        up on the next info-page open without a restart."""
        captured = self._run()
        display = captured["display"]
        http = captured["http"]

        with patch("dial_main.gather_dial_info", return_value=()) as mock_gather:
            display._get_info_rows()
            http.get_runtime_status.return_value = {"name": "Renamed Dial"}
            display._get_info_rows()
        assert mock_gather.call_args_list[0].args[0] == "Kitchen Dial"
        assert mock_gather.call_args_list[1].args[0] == "Renamed Dial"

    def test_network_worker_started_with_sdhealth_tick(self):
        import dial_main as dm
        import dial_sdhealth

        captured = self._run()
        captured["start_network_worker"].assert_called_once()
        kwargs = captured["start_network_worker"].call_args.kwargs
        assert kwargs["on_tick"] is dial_sdhealth.tick

    def test_not_wired_for_a_noop_display(self):
        """set_info_provider is only ever called when the display stack
        actually has one — the NoOpDisplayStatusProvider fallback (a Pillow/
        display-stack import failure) has no screen at all."""
        import dial_main as dm
        from dial_screen_settings import NoOpDisplayStatusProvider

        noop = NoOpDisplayStatusProvider()
        assert not hasattr(noop, "set_info_provider")


# ---------------------------------------------------------------------------
# Boot splash wiring: main() paints "Starting..." through the real display
# manager before the HTTP server, the mDNS browsers and display.start().
# ---------------------------------------------------------------------------

class TestBootSplashWiring:
    def _run(self, fitted=True):
        import dial_main as dm
        import dial_display as dd
        from dial_config import DialConfig, DialDisplayConfig

        cfg = DialConfig(uuid="splash-uuid", sw_gpio=None, clk_gpio=None, dt_gpio=None, led_gpio=None, pin="")
        cfg.display = DialDisplayConfig(fitted=fitted)

        order: list = []
        real_create = dd.create_dial_display

        def spy_create(*args, **kwargs):
            inst = real_create(*args, **kwargs)
            # Shadow the bound methods on this one instance to record order
            # without opening a real backend.
            inst.show_starting = lambda: order.append("show_starting")
            inst.start = lambda: order.append("start")
            inst.stop = lambda: order.append("stop")
            return inst

        mock_http = MagicMock()
        mock_http.get_runtime_status.return_value = {"name": "Dial"}

        def http_ctor(*a, **k):
            order.append("http")
            return mock_http

        class _QuickEvent(threading.Event):
            def wait(self, timeout=None):
                return True

        with patch("dial_main._configure_logging"), \
             patch("dial_main.load_config", return_value=cfg), \
             patch("dial_main._reconcile_update_timer", side_effect=lambda *_: order.append("update_timer")), \
             patch("dial_main._announce_self", side_effect=lambda *_: order.append("announce")), \
             patch("dial_main.DialLED"), \
             patch("dial_main.DialHTTPServer", side_effect=http_ctor), \
             patch("dial_main.start_volume_worker"), \
             patch("dial_main.PeerRegistry", side_effect=lambda **_: order.append("mdns") or MagicMock()), \
             patch("dial_main.start_network_worker"), \
             patch("dial_main.DialControlServer"), \
             patch.object(dd, "create_dial_display", side_effect=spy_create), \
             patch("threading.Event", _QuickEvent):
            dm.main()
        return order

    def test_splash_is_painted_once_before_everything_else(self):
        order = self._run()
        assert order.count("show_starting") == 1
        assert order.index("show_starting") < order.index("update_timer")
        assert order.index("show_starting") < order.index("announce")
        assert order.index("show_starting") < order.index("http")
        assert order.index("show_starting") < order.index("mdns")
        assert order.index("show_starting") < order.index("start")

    def test_display_start_still_follows_mdns_startup(self):
        order = self._run()
        assert order.index("mdns") < order.index("start")

    def test_noop_display_has_no_show_starting_and_main_still_boots(self):
        from dial_screen_settings import NoOpDisplayStatusProvider
        assert not hasattr(NoOpDisplayStatusProvider(), "show_starting")
        # _run_main_patched(...) with the display import forced to fail is
        # already covered by the existing fallback test elsewhere in this
        # file; add a `show_starting` absence assertion there if that test
        # inspects the provider instance.


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
        import dial_recovery
        from dial_config import DialConfig
        from dial_screen_settings import NoOpDisplayStatusProvider, ScreenSettingsService

        cfg = DialConfig(uuid="x", pin="1234")
        server = dhs.DialHTTPServer.__new__(dhs.DialHTTPServer)
        server._cfg = cfg
        server._cfg_lock = threading.Lock()
        server._recovery_window = dial_recovery.RecoveryWindow(lambda add: None)
        server._can_confirm_presence = False
        server._screen = ScreenSettingsService(
            config=server.config_snapshot, update_cfg=server.update_cfg,
            display_status=NoOpDisplayStatusProvider(),
        )
        server._server = MagicMock()
        return server

    def _run(self, cfg, server, tmp_path, build_mock=None):
        import dial_main as dm

        # Recovery is now armed only when the running marker survived AND a
        # request file is present (see dial_main._recovery_request_within_
        # window) — these tests are about confirm-presence wiring into an
        # already-armed window, not about the arming decision itself, so
        # simulate an armed window directly: a survived marker, a fresh
        # request, and a synchronised clock.
        running_marker = tmp_path / "running.txt"
        running_marker.write_text("")
        pin_reset = tmp_path / "pin_reset.txt"
        pin_reset.write_text("")
        sync_marker = tmp_path / "synchronized"
        sync_marker.write_text("")

        control_kwargs = {}

        def _capture_control(**kwargs):
            control_kwargs.update(kwargs)
            return MagicMock()

        mock_encoder_setup = MagicMock(return_value="encoder-handle")
        mock_button_setup = MagicMock(return_value="button-handle")
        fake_gpio = MagicMock()
        fake_gpio.setup_rotary_encoder = mock_encoder_setup
        fake_gpio.setup_button = mock_button_setup

        class _QuickEvent(threading.Event):
            def wait(self, timeout=None):
                return True

        import builtins
        real_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name == "autostream_dial_gpio":
                return fake_gpio
            return real_import(name, *args, **kwargs)

        patches = [
            patch("dial_main._configure_logging"),
            patch("dial_main.load_config", return_value=cfg),
            patch("dial_main._reconcile_update_timer"),
            patch("dial_main._announce_self"),
            patch("dial_main.DialLED"),
            patch("dial_main.DialHTTPServer", return_value=server),
            patch("dial_main.start_volume_worker"),
            patch("dial_main.PeerRegistry"),
            patch("dial_main.start_network_worker"),
            patch("dial_main.DialControlServer", side_effect=_capture_control),
            patch("threading.Event", _QuickEvent),
            # RecoveryWindow.open() is real here (cfg.pin is set) — mock out
            # only the timer thread it schedules, not its state transitions.
            patch("dial_recovery.threading.Timer"),
            patch("builtins.__import__", side_effect=_fake_import),
            patch("dial_recovery.RUNNING_MARKER_PATH", running_marker),
            patch("dial_recovery.PIN_RESET_PATH", pin_reset),
            patch("dial_recovery._TIMESYNC_MARKER_PATH", sync_marker),
        ]
        if build_mock is not None:
            patches.append(patch("dial_main.build_touch_source", build_mock))
        for p in patches:
            p.start()
        try:
            dm.main()
        finally:
            for p in reversed(patches):
                p.stop()

        return control_kwargs, mock_encoder_setup, mock_button_setup

    # -- any deliberate input confirms presence --------------------------

    def test_encoder_down_confirms(self, tmp_path):
        cfg = _make_cfg()  # clk=22, dt=27 already set
        cfg.pin = "1234"
        server = self._real_server()

        _, encoder_setup, _ = self._run(cfg, server, tmp_path)

        encoder_setup.assert_called_once()
        nudge_down_cb = encoder_setup.call_args.args[3]
        assert server._recovery_window.snapshot()["volume_confirmed"] is False
        nudge_down_cb()
        assert server._recovery_window.snapshot()["volume_confirmed"] is True

    def test_nudge_delta_negative_confirms(self, tmp_path):
        cfg = _make_cfg()
        cfg.pin = "1234"
        server = self._real_server()

        control_kwargs, _, _ = self._run(cfg, server, tmp_path)

        assert server._recovery_window.snapshot()["volume_confirmed"] is False
        control_kwargs["nudge_delta"](-3)
        assert server._recovery_window.snapshot()["volume_confirmed"] is True

    def test_nudge_delta_zero_does_not_confirm(self, tmp_path):
        """Unchanged behaviour: a zero delta is not a deliberate input."""
        cfg = _make_cfg()
        cfg.pin = "1234"
        server = self._real_server()

        control_kwargs, _, _ = self._run(cfg, server, tmp_path)

        control_kwargs["nudge_delta"](0)
        assert server._recovery_window.snapshot()["volume_confirmed"] is False

    def test_button_press_confirms(self, tmp_path):
        cfg = _make_cfg()
        cfg.sw_gpio = 23
        cfg.pin = "1234"
        server = self._real_server()

        _, _, button_setup = self._run(cfg, server, tmp_path)

        button_setup.assert_called_once()
        on_press_cb = button_setup.call_args.args[1]
        assert server._recovery_window.snapshot()["volume_confirmed"] is False
        on_press_cb()
        assert server._recovery_window.snapshot()["volume_confirmed"] is True

    # -- encoder/button nudges pop the repeat screen back to main ---------

    def test_encoder_nudge_pops_repeat_screen(self, tmp_path):
        cfg = _make_cfg()  # clk=22, dt=27 already set
        cfg.pin = "1234"
        server = self._real_server()

        with patch("dial_display.DialDisplay.pop_secondary") as mock_pop:
            _, encoder_setup, _ = self._run(cfg, server, tmp_path)
            nudge_down_cb = encoder_setup.call_args.args[3]
            nudge_down_cb()
        mock_pop.assert_called_with("repeat")

    def test_button_press_pops_repeat_screen(self, tmp_path):
        cfg = _make_cfg()
        cfg.sw_gpio = 23
        cfg.pin = "1234"
        server = self._real_server()

        with patch("dial_display.DialDisplay.pop_secondary") as mock_pop:
            _, _, button_setup = self._run(cfg, server, tmp_path)
            on_press_cb = button_setup.call_args.args[1]
            on_press_cb()
        mock_pop.assert_called_with("repeat")

    def test_nudge_survives_a_raising_pop_secondary(self, tmp_path):
        """A raising/missing display.pop_secondary() must never block the
        nudge itself — display failure must never affect volume control."""
        cfg = _make_cfg()
        cfg.pin = "1234"
        server = self._real_server()

        with patch("dial_display.DialDisplay.pop_secondary", side_effect=RuntimeError("boom")):
            _, encoder_setup, _ = self._run(cfg, server, tmp_path)
            nudge_down_cb = encoder_setup.call_args.args[3]
            nudge_down_cb()  # must not raise
        assert server._recovery_window.snapshot()["volume_confirmed"] is True

    def test_touch_contact_confirms(self, tmp_path):
        """main() must wire confirm_presence=http_server.confirm_volume into
        build_touch_source — invoking it must confirm the real recovery
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

        def build_mock(cfg_arg, display_arg, confirm_presence=None, step_percent=None, core=None):
            captured["confirm_presence"] = confirm_presence
            return MagicMock()

        self._run(cfg, server, tmp_path, build_mock=build_mock)

        assert captured["confirm_presence"].__self__ is server
        assert captured["confirm_presence"].__func__ is server.confirm_volume.__func__
        assert server._recovery_window.snapshot()["volume_confirmed"] is False
        captured["confirm_presence"]()
        assert server._recovery_window.snapshot()["volume_confirmed"] is True

    # -- can_confirm_presence reflects what actually got constructed -----

    def test_can_confirm_presence_true_for_encoder_and_button(self, tmp_path):
        from dial_config import DialDisplayConfig

        cfg = _make_cfg()
        cfg.clk_gpio, cfg.dt_gpio, cfg.sw_gpio = 22, 27, 23
        cfg.display = DialDisplayConfig(fitted=False, touch_type="none")
        server = self._real_server()

        self._run(cfg, server, tmp_path)

        assert server._can_confirm_presence is True

    def test_can_confirm_presence_true_for_encoder_only(self, tmp_path):
        from dial_config import DialDisplayConfig

        cfg = _make_cfg()
        cfg.clk_gpio, cfg.dt_gpio, cfg.sw_gpio = 22, 27, None
        cfg.display = DialDisplayConfig(fitted=False, touch_type="none")
        server = self._real_server()

        self._run(cfg, server, tmp_path)

        assert server._can_confirm_presence is True

    def test_can_confirm_presence_true_for_button_only(self, tmp_path):
        from dial_config import DialDisplayConfig

        cfg = _make_cfg()
        cfg.clk_gpio, cfg.dt_gpio, cfg.sw_gpio = None, None, 23
        cfg.display = DialDisplayConfig(fitted=False, touch_type="none")
        server = self._real_server()

        self._run(cfg, server, tmp_path)

        assert server._can_confirm_presence is True

    def test_can_confirm_presence_true_for_touch_only(self, tmp_path):
        from dial_config import DialDisplayConfig

        cfg = _make_cfg()
        cfg.clk_gpio, cfg.dt_gpio, cfg.sw_gpio = None, None, None
        cfg.display = DialDisplayConfig(fitted=True, touch_type="xpt2046")
        server = self._real_server()
        build_mock = MagicMock(return_value=MagicMock())

        self._run(cfg, server, tmp_path, build_mock=build_mock)

        assert server._can_confirm_presence is True

    def test_can_confirm_presence_false_for_screen_only(self, tmp_path):
        """No encoder, no button, touch_type 'none': a lock with no key is
        worse than no lock, so this dial must report it cannot confirm."""
        from dial_config import DialDisplayConfig

        cfg = _make_cfg()
        cfg.clk_gpio, cfg.dt_gpio, cfg.sw_gpio = None, None, None
        cfg.display = DialDisplayConfig(fitted=True, touch_type="none")
        server = self._real_server()

        self._run(cfg, server, tmp_path)

        assert server._can_confirm_presence is False

    def test_can_confirm_presence_false_when_touch_construction_raised(self, tmp_path):
        """A dial with touch_type configured whose driver failed to load has
        no WORKING confirmable input, regardless of configuration."""
        from dial_config import DialDisplayConfig

        cfg = _make_cfg()
        cfg.clk_gpio, cfg.dt_gpio, cfg.sw_gpio = None, None, None
        cfg.display = DialDisplayConfig(fitted=True, touch_type="xpt2046")
        server = self._real_server()
        build_mock = MagicMock(side_effect=RuntimeError("no SPI bus"))

        self._run(cfg, server, tmp_path, build_mock=build_mock)

        assert server._can_confirm_presence is False


class TestConfigureLogging:
    """The dial's log file lives on the SD card, so the default level is
    WARNING rather than INFO; APP_LOG_LEVEL raises it back up."""

    def _run(self, env):
        import dial_main as dm

        with patch.dict(os.environ, env, clear=False), \
             patch("dial_main.os.makedirs"), \
             patch("dial_main.logging.basicConfig") as basic_config, \
             patch("dial_main.logging.FileHandler"), \
             patch("dial_main.logging.StreamHandler"):
            dm._configure_logging()
        return basic_config

    def test_default_is_warning(self):
        os.environ.pop("APP_LOG_LEVEL", None)
        basic_config = self._run({})
        assert basic_config.call_args.kwargs["level"] == 30  # logging.WARNING

    def test_app_log_level_debug_is_honoured(self):
        basic_config = self._run({"APP_LOG_LEVEL": "DEBUG"})
        assert basic_config.call_args.kwargs["level"] == 10  # logging.DEBUG

    def test_garbage_falls_back_to_warning(self):
        basic_config = self._run({"APP_LOG_LEVEL": "NOT_A_LEVEL"})
        assert basic_config.call_args.kwargs["level"] == 30  # logging.WARNING


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def test_configure_logging_limits_repeated_lines_on_both_handlers():
    import logging
    import autostream_logging
    import dial_main

    with patch("dial_main.os.makedirs"), \
         patch("dial_main.logging.FileHandler", side_effect=lambda path: logging.NullHandler()), \
         patch("dial_main.logging.basicConfig") as basic_config:
        dial_main._configure_logging()

    handlers = basic_config.call_args.kwargs["handlers"]
    assert len(handlers) == 2
    for handler in handlers:
        assert any(isinstance(f, autostream_logging.RateLimitFilter) for f in handler.filters)
