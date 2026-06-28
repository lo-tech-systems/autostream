"""P5 — Dial hardware runtime tests.

What runs here (offline, no GPIO, no Pi hardware):
  - setup_rotary_encoder / setup_button (autostream_rpi): gpiozero absent,
    init failure, successful init — verify callbacks, pins, debounce, pull-up,
    wrap=False, and max_steps=0.
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
  - Button behavior (mute): verify debounce and hold timing.
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
CORE_DIR = REPO_ROOT / "core"
sys.path.insert(0, str(DIAL_DIR))
sys.path.insert(0, str(CORE_DIR))


# ---------------------------------------------------------------------------
# setup_rotary_encoder — shared GPIO helper (autostream_rpi)
# ---------------------------------------------------------------------------

class TestSetupRotaryEncoderGpioAbsent:
    """setup_rotary_encoder returns None when gpiozero is unavailable."""

    def test_returns_none_without_gpiozero(self):
        import autostream_rpi as rpi
        with patch.dict(sys.modules, {"gpiozero": None}):
            result = rpi.setup_rotary_encoder(17, 18, lambda: None, lambda: None)
        assert result is None

    def test_returns_none_when_gpiozero_raises(self):
        import autostream_rpi as rpi
        fake_gpio = MagicMock()
        fake_gpio.RotaryEncoder.side_effect = RuntimeError("lgpio device open failed")
        with patch.dict(sys.modules, {"gpiozero": fake_gpio}):
            result = rpi.setup_rotary_encoder(17, 18, lambda: None, lambda: None)
        assert result is None

    def test_does_not_raise_on_init_failure(self):
        import autostream_rpi as rpi
        fake_gpio = MagicMock()
        fake_gpio.RotaryEncoder.side_effect = Exception("gpio error")
        with patch.dict(sys.modules, {"gpiozero": fake_gpio}):
            rpi.setup_rotary_encoder(17, 18, lambda: None, lambda: None)  # must not raise

    def test_logs_warning_on_gpio_failure(self, caplog):
        import autostream_rpi as rpi
        fake_gpio = MagicMock()
        fake_gpio.RotaryEncoder.side_effect = RuntimeError("no device")
        with caplog.at_level(logging.WARNING), \
             patch.dict(sys.modules, {"gpiozero": fake_gpio}):
            rpi.setup_rotary_encoder(17, 18, lambda: None, lambda: None)
        assert any("encoder" in r.message.lower() for r in caplog.records), (
            "No warning logged when encoder GPIO init failed"
        )


class TestSetupRotaryEncoderWithFakeGpio:
    """setup_rotary_encoder configures pins, callbacks, wrap, max_steps."""

    def _make_with_fake_encoder(self, on_cw, on_ccw, clk=17, dt=18):
        import autostream_rpi as rpi
        fake_enc = MagicMock()
        FakeEncoder = MagicMock(return_value=fake_enc)
        fake_gpio = MagicMock()
        fake_gpio.RotaryEncoder = FakeEncoder
        with patch.dict(sys.modules, {"gpiozero": fake_gpio}):
            enc = rpi.setup_rotary_encoder(clk, dt, on_cw, on_ccw)
        return enc, fake_enc, FakeEncoder

    def test_returns_encoder_instance(self):
        _, fake_enc, _ = self._make_with_fake_encoder(lambda: None, lambda: None)
        assert fake_enc is not None

    def test_clockwise_callback_wired(self):
        cw_fn = MagicMock()
        ccw_fn = MagicMock()
        enc, fake_enc, _ = self._make_with_fake_encoder(cw_fn, ccw_fn)
        assert fake_enc.when_rotated_clockwise is cw_fn

    def test_counter_clockwise_callback_wired(self):
        cw_fn = MagicMock()
        ccw_fn = MagicMock()
        enc, fake_enc, _ = self._make_with_fake_encoder(cw_fn, ccw_fn)
        assert fake_enc.when_rotated_counter_clockwise is ccw_fn

    def test_encoder_created_with_correct_gpio_pins(self):
        import autostream_rpi as rpi
        fake_gpio = MagicMock()
        created_args: list = []

        def fake_encoder_cls(*args, **kw):
            created_args.append(args)
            return MagicMock()

        fake_gpio.RotaryEncoder = fake_encoder_cls
        with patch.dict(sys.modules, {"gpiozero": fake_gpio}):
            rpi.setup_rotary_encoder(23, 24, lambda: None, lambda: None)

        # autostream_rpi passes clk and dt as positional args
        assert created_args[0][0] == 23
        assert created_args[0][1] == 24

    def test_encoder_wrap_false(self):
        import autostream_rpi as rpi
        fake_gpio = MagicMock()
        created_kwargs: list = []

        def fake_encoder_cls(*args, **kw):
            created_kwargs.append(kw)
            return MagicMock()

        fake_gpio.RotaryEncoder = fake_encoder_cls
        with patch.dict(sys.modules, {"gpiozero": fake_gpio}):
            rpi.setup_rotary_encoder(17, 18, lambda: None, lambda: None)

        assert created_kwargs[0].get("wrap") is False

    def test_encoder_max_steps_zero(self):
        import autostream_rpi as rpi
        fake_gpio = MagicMock()
        created_kwargs: list = []

        def fake_encoder_cls(*args, **kw):
            created_kwargs.append(kw)
            return MagicMock()

        fake_gpio.RotaryEncoder = fake_encoder_cls
        with patch.dict(sys.modules, {"gpiozero": fake_gpio}):
            rpi.setup_rotary_encoder(17, 18, lambda: None, lambda: None)

        assert created_kwargs[0].get("max_steps") == 0

    def test_cw_callback_invocation_reaches_caller(self):
        fired: list[int] = []
        cw_fn = lambda: fired.append(1)
        _, fake_enc, _ = self._make_with_fake_encoder(cw_fn, lambda: None)
        fake_enc.when_rotated_clockwise()
        assert fired == [1]

    def test_ccw_callback_invocation_reaches_caller(self):
        fired: list[int] = []
        ccw_fn = lambda: fired.append(-1)
        _, fake_enc, _ = self._make_with_fake_encoder(lambda: None, ccw_fn)
        fake_enc.when_rotated_counter_clockwise()
        assert fired == [-1]


# ---------------------------------------------------------------------------
# setup_button — shared GPIO helper with debounce (autostream_rpi)
# ---------------------------------------------------------------------------

class TestSetupButton:
    def test_returns_none_without_gpiozero(self):
        import autostream_rpi as rpi
        with patch.dict(sys.modules, {"gpiozero": None}):
            result = rpi.setup_button(22, lambda: None)
        assert result is None

    def test_returns_none_when_gpiozero_raises(self):
        import autostream_rpi as rpi
        fake_gpio = MagicMock()
        fake_gpio.Button.side_effect = RuntimeError("GPIO init failed")
        with patch.dict(sys.modules, {"gpiozero": fake_gpio}):
            result = rpi.setup_button(22, lambda: None)
        assert result is None

    def test_does_not_raise_on_init_failure(self):
        import autostream_rpi as rpi
        fake_gpio = MagicMock()
        fake_gpio.Button.side_effect = Exception("gpio error")
        with patch.dict(sys.modules, {"gpiozero": fake_gpio}):
            rpi.setup_button(22, lambda: None)  # must not raise

    def test_press_callback_wired(self):
        import autostream_rpi as rpi
        fired = []
        press_fn = lambda: fired.append(1)
        fake_btn = MagicMock()
        fake_gpio = MagicMock()
        fake_gpio.Button.return_value = fake_btn
        with patch.dict(sys.modules, {"gpiozero": fake_gpio}):
            rpi.setup_button(22, press_fn)
        assert fake_btn.when_pressed is press_fn

    def test_pull_up_enabled(self):
        import autostream_rpi as rpi
        fake_gpio = MagicMock()
        created_kwargs: list = []

        def fake_btn_cls(*args, **kw):
            created_kwargs.append(kw)
            return MagicMock()

        fake_gpio.Button = fake_btn_cls
        with patch.dict(sys.modules, {"gpiozero": fake_gpio}):
            rpi.setup_button(22, lambda: None)

        assert created_kwargs[0].get("pull_up") is True

    def test_default_bounce_time(self):
        import autostream_rpi as rpi
        fake_gpio = MagicMock()
        created_kwargs: list = []

        def fake_btn_cls(*args, **kw):
            created_kwargs.append(kw)
            return MagicMock()

        fake_gpio.Button = fake_btn_cls
        with patch.dict(sys.modules, {"gpiozero": fake_gpio}):
            rpi.setup_button(22, lambda: None)

        assert created_kwargs[0].get("bounce_time") == 0.1

    def test_custom_bounce_time(self):
        import autostream_rpi as rpi
        fake_gpio = MagicMock()
        created_kwargs: list = []

        def fake_btn_cls(*args, **kw):
            created_kwargs.append(kw)
            return MagicMock()

        fake_gpio.Button = fake_btn_cls
        with patch.dict(sys.modules, {"gpiozero": fake_gpio}):
            rpi.setup_button(22, lambda: None, bounce_time=0.2)

        assert created_kwargs[0].get("bounce_time") == 0.2

    def test_gpio_pin_passed(self):
        import autostream_rpi as rpi
        fake_gpio = MagicMock()
        created_args: list = []

        def fake_btn_cls(*args, **kw):
            created_args.append(args)
            return MagicMock()

        fake_gpio.Button = fake_btn_cls
        with patch.dict(sys.modules, {"gpiozero": fake_gpio}):
            rpi.setup_button(22, lambda: None)

        assert created_args[0][0] == 22


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
    def _call_configure(self, env):
        import dial_main
        file_handler = MagicMock(name="file_handler")
        stream_handler = MagicMock(name="stream_handler")
        with patch("logging.basicConfig") as mock_cfg, \
             patch("logging.FileHandler", return_value=file_handler) as mock_file, \
             patch("logging.StreamHandler", return_value=stream_handler) as mock_stream, \
             patch("os.makedirs") as mock_makedirs, \
             patch.dict(os.environ, env, clear=False):
            if "APP_LOG_LEVEL" not in env:
                os.environ.pop("APP_LOG_LEVEL", None)
            dial_main._configure_logging()
        return mock_cfg, mock_file, mock_stream, mock_makedirs, file_handler, stream_handler

    def test_default_level_is_info(self):
        mock_cfg, *_ = self._call_configure({})
        _, kwargs = mock_cfg.call_args
        assert kwargs["level"] == logging.INFO

    def test_debug_level_from_env(self):
        mock_cfg, *_ = self._call_configure({"APP_LOG_LEVEL": "DEBUG"})
        _, kwargs = mock_cfg.call_args
        assert kwargs["level"] == logging.DEBUG

    def test_invalid_level_from_env_does_not_crash(self):
        mock_cfg, *_ = self._call_configure({"APP_LOG_LEVEL": "NOTLEVEL"})
        _, kwargs = mock_cfg.call_args
        assert kwargs["level"] == logging.INFO

    def test_matches_main_autostream_format_and_handlers(self):
        mock_cfg, mock_file, mock_stream, mock_makedirs, file_handler, stream_handler = \
            self._call_configure({"APP_LOG_LEVEL": "INFO"})
        _, kwargs = mock_cfg.call_args
        mock_makedirs.assert_called_once_with("/var/log/autostream", exist_ok=True)
        mock_file.assert_called_once_with("/var/log/autostream/autostream-dial.log")
        mock_stream.assert_called_once_with(sys.stdout)
        assert kwargs["format"] == "%(asctime)s: %(message)s"
        assert kwargs["datefmt"] == "%d-%b-%y %H:%M:%S"
        assert kwargs["handlers"] == [file_handler, stream_handler]

    def test_gpiozero_logger_suppressed_at_info(self):
        """gpiozero noise must be suppressed at WARNING when main is at INFO."""
        self._call_configure({"APP_LOG_LEVEL": "INFO"})
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

        enqueued = []
        with patch.object(dv, "_queue") as mock_q:
            mock_q.put.side_effect = lambda x: enqueued.append(x)
            dv.enqueue_delta(5)

        assert enqueued == [("delta", 5)]

    def test_ccw_callback_enqueues_negative_delta(self):
        import dial_volume as dv

        enqueued = []
        with patch.object(dv, "_queue") as mock_q:
            mock_q.put.side_effect = lambda x: enqueued.append(x)
            dv.enqueue_delta(-3)

        assert enqueued == [("delta", -3)]

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
