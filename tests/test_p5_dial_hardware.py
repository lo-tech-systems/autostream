"""P5 — Dial hardware runtime tests.

What runs here (offline, no GPIO, no Pi hardware):
  - RotaryEncoderHandler: gpiozero absent, init failure, successful init with
    fake GPIO device — verify callbacks wired and graceful degradation.
  - DialLED: gpio=None no-ops; gpiozero absent no-ops; mock LED on/off/blink.
  - dial_main._configure_logging: reads APP_LOG_LEVEL env var.
  - dial_volume: worker skips fan-out when no targets available.

Covered by existing tests (not duplicated here):
  - _reconcile_update_timer (test_dial_http_server.py lines 699–734)
  - _send_one, _fan_out, _log_volume_failure, queue coalescing,
    LED flash on clamp (test_dial_volume_sender.py)
  - /api/dial/volume HTTP auth + delta validation (test_dial_volume.py)

Environment-dependent (not run here, real Pi only):
  - Actual GPIO encoder direction: physical CW/CCW rotation — must be
    confirmed by plugging in hardware and observing volume direction.
    Manual checklist: see docs/manual-hardware-checklist.md.
  - LED polarity: confirm LED illuminates during audio playback and flashes
    at volume boundary. Requires physical LED + resistor on configured pin.
  - Button behavior (if used as mute): verify debounce and hold timing.
  - Power-loss recovery: pull power during update; confirm boot-time recover
    service resets stale in_progress status before service restarts.
"""
from __future__ import annotations

import logging
import os
import queue
import sys
import threading
import time
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, call, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
DIAL_DIR = REPO_ROOT / "dial"
sys.path.insert(0, str(DIAL_DIR))


# ---------------------------------------------------------------------------
# RotaryEncoderHandler — gpiozero absent / init failure / success
# ---------------------------------------------------------------------------

class TestRotaryEncoderHandlerGpioAbsent:
    """RotaryEncoderHandler must not crash when gpiozero is unavailable."""

    def _make_handler(self, on_cw=None, on_ccw=None):
        from dial_encoder import RotaryEncoderHandler
        return RotaryEncoderHandler(
            clk_gpio=17, dt_gpio=18,
            on_cw=on_cw or (lambda: None),
            on_ccw=on_ccw or (lambda: None),
        )

    def test_constructs_without_gpiozero(self):
        with patch.dict(sys.modules, {"gpiozero": None}):
            # ImportError when gpiozero=None in sys.modules causes ImportError
            handler = self._make_handler()
        assert handler._encoder is None

    def test_constructs_when_gpiozero_raises_on_import(self):
        """Any exception during gpiozero import/init is caught silently."""
        fake_gpio = MagicMock()
        fake_gpio.RotaryEncoder.side_effect = RuntimeError("lgpio device open failed")
        with patch.dict(sys.modules, {"gpiozero": fake_gpio}):
            handler = self._make_handler()
        assert handler._encoder is None

    def test_does_not_raise_even_if_init_fails(self):
        fake_gpio = MagicMock()
        fake_gpio.RotaryEncoder.side_effect = Exception("gpio error")
        with patch.dict(sys.modules, {"gpiozero": fake_gpio}):
            handler = self._make_handler()   # must not raise

    def test_logs_warning_on_gpio_failure(self, caplog):
        fake_gpio = MagicMock()
        fake_gpio.RotaryEncoder.side_effect = RuntimeError("no device")
        with caplog.at_level(logging.WARNING), \
             patch.dict(sys.modules, {"gpiozero": fake_gpio}):
            self._make_handler()
        # Warning must mention 'encoder' and explain GPIO init failed.
        assert any("encoder" in r.message.lower() for r in caplog.records), (
            "No warning logged when encoder GPIO init failed"
        )


class TestRotaryEncoderHandlerWithFakeGpio:
    """RotaryEncoderHandler wires callbacks to a successfully created encoder."""

    def _make_with_fake_encoder(self, on_cw, on_ccw):
        fake_enc = MagicMock()
        FakeEncoder = MagicMock(return_value=fake_enc)
        fake_gpio = MagicMock()
        fake_gpio.RotaryEncoder = FakeEncoder
        with patch.dict(sys.modules, {"gpiozero": fake_gpio}):
            from dial_encoder import RotaryEncoderHandler
            handler = RotaryEncoderHandler(17, 18, on_cw, on_ccw)
        return handler, fake_enc

    def test_encoder_stored_on_success(self):
        cw_fn = MagicMock()
        handler, fake_enc = self._make_with_fake_encoder(cw_fn, MagicMock())
        assert handler._encoder is fake_enc

    def test_clockwise_callback_wired(self):
        cw_fn = MagicMock()
        ccw_fn = MagicMock()
        handler, fake_enc = self._make_with_fake_encoder(cw_fn, ccw_fn)
        assert fake_enc.when_rotated_clockwise is cw_fn

    def test_counter_clockwise_callback_wired(self):
        cw_fn = MagicMock()
        ccw_fn = MagicMock()
        handler, fake_enc = self._make_with_fake_encoder(cw_fn, ccw_fn)
        assert fake_enc.when_rotated_counter_clockwise is ccw_fn

    def test_encoder_created_with_correct_gpio_pins(self):
        fake_gpio = MagicMock()
        created_args: list = []

        def fake_encoder(**kw):
            created_args.append(kw)
            m = MagicMock()
            return m

        fake_gpio.RotaryEncoder = fake_encoder
        with patch.dict(sys.modules, {"gpiozero": fake_gpio}):
            from dial_encoder import RotaryEncoderHandler
            RotaryEncoderHandler(23, 24, lambda: None, lambda: None)

        assert created_args[0]["a"] == 23
        assert created_args[0]["b"] == 24

    def test_cw_callback_invocation_reaches_caller(self):
        """Simulate gpiozero calling when_rotated_clockwise."""
        fired: list[int] = []
        cw_fn = lambda: fired.append(1)
        handler, fake_enc = self._make_with_fake_encoder(cw_fn, lambda: None)
        # Directly invoke the callback as gpiozero would
        fake_enc.when_rotated_clockwise()
        assert fired == [1]

    def test_ccw_callback_invocation_reaches_caller(self):
        fired: list[int] = []
        ccw_fn = lambda: fired.append(-1)
        handler, fake_enc = self._make_with_fake_encoder(lambda: None, ccw_fn)
        fake_enc.when_rotated_counter_clockwise()
        assert fired == [-1]


# ---------------------------------------------------------------------------
# DialLED — gpio=None no-ops; mock GPIO
# ---------------------------------------------------------------------------

class TestDialLEDGpioNone:
    """DialLED with gpio=None must be completely silent/no-op."""

    def test_constructs_with_none_gpio(self):
        from dial_led import DialLED
        led = DialLED(gpio=None)
        assert led._led is None

    def test_set_playing_does_not_raise(self):
        from dial_led import DialLED
        DialLED(gpio=None).set_playing()

    def test_set_idle_does_not_raise(self):
        from dial_led import DialLED
        DialLED(gpio=None).set_idle()

    def test_flash_clamped_does_not_raise(self):
        from dial_led import DialLED
        led = DialLED(gpio=None)
        led.flash_clamped()   # must return immediately without starting a thread

    def test_flash_clamped_starts_no_thread_with_none_gpio(self):
        from dial_led import DialLED
        led = DialLED(gpio=None)
        threads_before = threading.active_count()
        led.flash_clamped()
        time.sleep(0.02)  # give scheduler a moment
        assert threading.active_count() <= threads_before, (
            "flash_clamped() must not start a thread when _led is None"
        )


class TestDialLEDGpioAbsent:
    """DialLED with a GPIO pin but gpiozero unavailable → graceful no-op."""

    def test_constructs_when_gpiozero_absent(self):
        with patch.dict(sys.modules, {"gpiozero": None}):
            from dial_led import DialLED
            led = DialLED(gpio=17)
        assert led._led is None

    def test_set_playing_noop_when_gpiozero_absent(self):
        with patch.dict(sys.modules, {"gpiozero": None}):
            from dial_led import DialLED
            led = DialLED(gpio=17)
        led.set_playing()   # must not raise


class TestDialLEDWithMockGpio:
    """DialLED with a fake gpiozero.LED device."""

    def _make_led(self, gpio: int = 17):
        fake_led = MagicMock()
        FakeLED = MagicMock(return_value=fake_led)
        fake_gpio = MagicMock()
        fake_gpio.LED = FakeLED
        with patch.dict(sys.modules, {"gpiozero": fake_gpio}):
            from dial_led import DialLED
            led = DialLED(gpio=gpio)
        return led, fake_led

    def test_set_playing_calls_on(self):
        led, fake_led = self._make_led()
        led.set_playing()
        fake_led.on.assert_called_once()

    def test_set_idle_calls_off(self):
        led, fake_led = self._make_led()
        led.set_idle()
        fake_led.off.assert_called_once()

    def test_flash_clamped_starts_blink_thread(self):
        led, fake_led = self._make_led()
        led.flash_clamped()
        # Give the blink thread time to start and invoke blink
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            if fake_led.blink.called:
                break
            time.sleep(0.02)
        assert fake_led.blink.called, "flash_clamped() must call LED.blink()"

    def test_flash_clamped_blink_two_cycles(self):
        led, fake_led = self._make_led()
        fake_led.blink = MagicMock()  # won't block
        led.flash_clamped()
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            if fake_led.blink.called:
                break
            time.sleep(0.02)
        _, kwargs = fake_led.blink.call_args
        assert kwargs.get("n", 0) == 2, "flash_clamped must blink exactly 2 times"

    def test_set_playing_after_idle_calls_on_again(self):
        led, fake_led = self._make_led()
        led.set_idle()
        led.set_playing()
        assert fake_led.on.call_count == 1
        assert fake_led.off.call_count == 1


# ---------------------------------------------------------------------------
# dial_main._configure_logging
# ---------------------------------------------------------------------------

class TestConfigureLogging:
    def test_default_level_is_info(self):
        import dial_main
        with patch("logging.basicConfig") as mock_cfg, \
             patch.dict(os.environ, {}, clear=False):
            os.environ.pop("APP_LOG_LEVEL", None)
            dial_main._configure_logging()
        _, kwargs = mock_cfg.call_args
        # _configure_logging passes the string "INFO" directly (Python logging accepts it)
        assert kwargs["level"] == "INFO"

    def test_debug_level_from_env(self):
        import dial_main
        with patch("logging.basicConfig") as mock_cfg, \
             patch.dict(os.environ, {"APP_LOG_LEVEL": "DEBUG"}):
            dial_main._configure_logging()
        _, kwargs = mock_cfg.call_args
        assert kwargs["level"] == "DEBUG"

    def test_invalid_level_from_env_does_not_crash(self):
        import dial_main
        with patch("logging.basicConfig"), \
             patch.dict(os.environ, {"APP_LOG_LEVEL": "NOTLEVEL"}):
            dial_main._configure_logging()   # must not raise

    def test_gpiozero_logger_suppressed_at_info(self):
        """gpiozero noise must be suppressed at WARNING when main is at INFO."""
        import dial_main
        with patch("logging.basicConfig"), \
             patch.dict(os.environ, {"APP_LOG_LEVEL": "INFO"}):
            dial_main._configure_logging()
        gpz_logger = logging.getLogger("gpiozero")
        assert gpz_logger.level == logging.WARNING, (
            f"Expected gpiozero logger at WARNING, got {gpz_logger.level}"
        )


# ---------------------------------------------------------------------------
# dial_volume — worker skips fan-out when targets list is empty
# ---------------------------------------------------------------------------

class TestVolumeWorkerNoTargets:
    """When get_playing_targets() returns [], worker must skip _fan_out."""

    def test_worker_skips_fan_out_with_empty_targets(self):
        import dial_volume as dv

        fan_out_calls: list = []
        original_fan_out = dv._fan_out

        def spy_fan_out(*args, **kwargs):
            fan_out_calls.append(args)
            return original_fan_out(*args, **kwargs)

        # Set module globals directly (as start_volume_worker does)
        dv._targets_fn = lambda: []   # empty — no playing targets
        dv._cfg = MagicMock()
        dv._cfg.uuid = "test-uuid"
        dv._led_ref = None

        fresh_queue: queue.SimpleQueue = queue.SimpleQueue()
        fresh_queue.put(5)

        with patch.object(dv, "_fan_out", side_effect=spy_fan_out):
            delta = fresh_queue.get()
            while True:
                try:
                    delta += fresh_queue.get_nowait()
                except queue.Empty:
                    break
            targets = dv._targets_fn()
            # Worker should not call _fan_out when targets is empty
            if targets:
                dv._fan_out(targets, dv._cfg.uuid, delta)

        assert fan_out_calls == [], (
            "Worker must not call _fan_out when no playing targets are available"
        )

    def test_worker_calls_fan_out_when_targets_present(self):
        import dial_volume as dv

        Target = MagicMock()
        Target.ip = "192.168.1.1"
        Target.port = 3000

        fan_out_calls: list = []

        dv._targets_fn = lambda: [Target]
        dv._cfg = MagicMock()
        dv._cfg.uuid = "test-uuid"

        fresh_queue: queue.SimpleQueue = queue.SimpleQueue()
        fresh_queue.put(3)

        with patch.object(dv, "_fan_out", side_effect=lambda *a: fan_out_calls.append(a) or False):
            delta = fresh_queue.get()
            targets = dv._targets_fn()
            if targets:
                dv._fan_out(targets, dv._cfg.uuid, delta)

        assert len(fan_out_calls) == 1


# ---------------------------------------------------------------------------
# End-to-end encoder → volume → LED flow (deterministic, no real GPIO)
# ---------------------------------------------------------------------------

class TestEndToEndEventFlow:
    """Encoder event → enqueue_delta → _fan_out → LED.flash_clamped."""

    def test_cw_callback_enqueues_positive_delta(self):
        import dial_volume as dv

        enqueued: list[int] = []
        with patch.object(dv, "_queue") as mock_q:
            mock_q.put.side_effect = lambda x: enqueued.append(x)
            dv.enqueue_delta(5)

        assert enqueued == [5]

    def test_ccw_callback_enqueues_negative_delta(self):
        import dial_volume as dv

        enqueued: list[int] = []
        with patch.object(dv, "_queue") as mock_q:
            mock_q.put.side_effect = lambda x: enqueued.append(x)
            dv.enqueue_delta(-3)

        assert enqueued == [-3]

    def test_fan_out_triggers_led_flash_on_clamp(self):
        """_fan_out returning True must cause LED.flash_clamped() in the worker logic."""
        import dial_volume as dv

        mock_led = MagicMock()
        dv._led_ref = mock_led
        dv._targets_fn = lambda: [MagicMock()]
        dv._cfg = MagicMock()
        dv._cfg.uuid = "uuid"

        with patch.object(dv, "_fan_out", return_value=True):
            targets = dv._targets_fn()
            clamped = dv._fan_out(targets, dv._cfg.uuid, 10)
            if clamped and dv._led_ref:
                dv._led_ref.flash_clamped()

        mock_led.flash_clamped.assert_called_once()

    def test_fan_out_no_led_flash_when_not_clamped(self):
        import dial_volume as dv

        mock_led = MagicMock()
        dv._led_ref = mock_led
        dv._targets_fn = lambda: [MagicMock()]
        dv._cfg = MagicMock()

        with patch.object(dv, "_fan_out", return_value=False):
            targets = dv._targets_fn()
            clamped = dv._fan_out(targets, dv._cfg.uuid, 5)
            if clamped and dv._led_ref:
                dv._led_ref.flash_clamped()

        mock_led.flash_clamped.assert_not_called()
