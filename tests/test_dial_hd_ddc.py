"""Tests for the HD dial's DDC/CI backlight: packet encoding and reply
validation, detection, the brightness and power sequences, the worker that
coalesces requests, and what happens when the bus misbehaves. The bus is a
fake display, so no i2c device is needed."""
from __future__ import annotations

import errno
import os
import sys
import threading
import time
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))

import dial_hd_ddc as ddc
from dial_hd_ddc import DdcBacklight, DdcError, DdcLink, DdcUnsupported, parse_get_reply
from dial_hd_panel import Backlight, HdPanel

BRIGHTNESS, POWER = ddc.VCP_BRIGHTNESS, ddc.VCP_POWER


# ---- a fake display ---------------------------------------------------------


def xor(seed, data):
    for byte in data:
        seed ^= byte
    return seed


def reply(code, current, maximum, result=0):
    body = bytes([0x6E, 0x88, 0x02, result, code, 0, maximum >> 8, maximum & 255,
                  current >> 8, current & 255])
    return body + bytes([xor(0x50, body)])


class Display:
    """A monitor on the other end of the bus: it checks what it is sent the way
    a real one would, keeps its features, and can be told to misbehave."""

    def __init__(self, brightness=31, maximum=100, power=True, busy_after_wake=0):
        self.values = {BRIGHTNESS: [brightness, maximum]}
        if power:
            self.values[POWER] = [1, 4]
        self.log = []                   # ("set", code, value) in order
        self.gets = []
        self.pending = b""
        self.busy = 0                   # commands still ignored (waking up)
        self.busy_after_wake = busy_after_wake
        self.error = None               # raised by the next write, if set
        self.corrupt = None             # replaces every get reply, if set
        self.opens = 0

    def open(self, *_a):
        self.opens += 1
        return self

    def write(self, data):
        if self.error is not None:
            raise self.error
        assert data[-1] == xor(0x6E, data[:-1]), "bad request checksum"
        assert data[0] == 0x51 and data[1] == 0x80 | (len(data) - 3)
        if data[2] == 0x03:
            code, value = data[3], (data[4] << 8) | data[5]
            if self.busy:
                self.busy -= 1
                return
            self.log.append(("set", code, value))
            if code == POWER:
                was_off = self.values[POWER][0] != 1
                self.values[POWER][0] = 1 if value == 1 else 2
                if value == 1 and was_off:
                    self.busy = self.busy_after_wake
            elif code in self.values:
                self.values[code][0] = value
            self.pending = b""
        else:
            code = data[3]
            self.gets.append(code)
            if self.busy:
                self.busy -= 1
                self.pending = bytes([0x6E, 0x80, 0xBE]) + bytes(8)
            elif code in self.values:
                self.pending = reply(code, *self.values[code])
            else:
                self.pending = reply(code, 0, 0, result=1)
        if self.corrupt is not None and data[2] == 0x01:
            self.pending = self.corrupt

    def read(self, size):
        data, self.pending = self.pending[:size], b""
        return data

    def close(self):
        pass

    def sets(self, code=None):
        return [v for (_k, c, v) in self.log if code is None or c == code]


class Pauses:
    """The sleep function: records the pauses, and can hold the worker."""

    def __init__(self):
        self.durations = []
        self.gate = None
        self.entered = threading.Event()

    def __call__(self, seconds):
        self.durations.append(seconds)
        if self.gate is not None:
            self.entered.set()
            self.gate.wait(5)


def make(display=None, power=True, maximum=100, **kw):
    display = display or Display(power=power, maximum=maximum)
    pauses = Pauses()
    link = DdcLink(display.open, pauses)
    backlight = DdcBacklight(link, maximum, power, sleep=pauses, **kw)
    return backlight, display, pauses


def wait_for(condition, timeout=3.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if condition():
            return True
        time.sleep(0.005)
    return condition()


def finish(backlight):
    """Stop the worker without the leave-it-on step, after it has drained."""
    with backlight._cond:
        backlight._stopping = True
        backlight._cond.notify()
    if backlight._thread is not None:
        backlight._thread.join(3)


# ---- packets -----------------------------------------------------------------


class TestPackets:
    def test_a_set_brightness_request(self):
        assert ddc.set_request(0x10, 50) == bytes([0x51, 0x84, 0x03, 0x10, 0x00, 0x32, 0x9A])

    def test_a_get_brightness_request(self):
        assert ddc.get_request(0x10) == bytes([0x51, 0x82, 0x01, 0x10, 0xAC])

    def test_a_value_above_255_uses_both_bytes(self):
        assert ddc.set_request(0x10, 0x1234)[4:6] == bytes([0x12, 0x34])

    def test_a_valid_reply_gives_current_and_maximum(self):
        data = bytes([0x6E, 0x88, 0x02, 0x00, 0x10, 0x00, 0x00, 0x64, 0x00, 0x1F, 0xDF])
        assert parse_get_reply(data, 0x10) == (31, 100)

    def test_the_builder_in_these_tests_agrees_with_the_known_reply(self):
        assert reply(0x10, 31, 100) == bytes(
            [0x6E, 0x88, 0x02, 0x00, 0x10, 0x00, 0x00, 0x64, 0x00, 0x1F, 0xDF])


def corrupted(**changes):
    good = bytearray(reply(0x10, 31, 100))
    for index, value in changes.items():
        good[int(index[1:])] = value
    return bytes(good)


def resum(data):
    data = bytearray(data)
    data[-1] = xor(0x50, data[:-1])
    return bytes(data)


class TestReplyValidation:
    @pytest.mark.parametrize("data,why", [
        (b"", "0 bytes"),
        (reply(0x10, 1, 2)[:6], "6 bytes"),
        (reply(0x10, 1, 2) + b"\x00", "12 bytes"),
        (bytes([0x6E, 0x80, 0xBE]) + bytes(8), "null reply"),
        (bytes(11), "reply from 0x00"),
        (bytes([0x6E, 0x80]) + bytes(9), "null reply"),
        (corrupted(b0=0x6F), "reply from"),
        (corrupted(b1=0x87), "length byte"),
        (corrupted(b10=0x00), "checksum"),
        (resum(corrupted(b2=0x03)), "opcode"),
        (resum(corrupted(b3=2)), "result code 2"),
        (resum(corrupted(b4=0x12)), "not 0x10"),
    ])
    def test_a_malformed_reply_is_an_error(self, data, why):
        with pytest.raises(DdcError, match=why):
            parse_get_reply(data, 0x10)

    def test_an_unsupported_feature_is_its_own_error(self):
        with pytest.raises(DdcUnsupported):
            parse_get_reply(reply(0x10, 0, 0, result=1), 0x10)

    def test_the_link_turns_a_bus_error_into_a_ddc_error_and_reopens(self):
        display = Display()
        link = DdcLink(display.open, lambda _s: None)
        assert link.get_vcp(BRIGHTNESS) == (31, 100)
        display.error = OSError(errno.EREMOTEIO, "nack")
        with pytest.raises(DdcError):
            link.get_vcp(BRIGHTNESS)
        display.error = None
        assert link.get_vcp(BRIGHTNESS) == (31, 100)
        assert display.opens == 2

    def test_a_failure_to_open_is_a_ddc_error(self):
        def refuse():
            raise PermissionError(errno.EACCES, "denied")
        with pytest.raises(DdcError):
            DdcLink(refuse, lambda _s: None).set_vcp(BRIGHTNESS, 1)

    def test_every_command_is_followed_by_the_protocol_pauses(self):
        pauses = Pauses()
        link = DdcLink(Display().open, pauses)
        link.get_vcp(BRIGHTNESS)
        link.set_vcp(BRIGHTNESS, 5)
        assert pauses.durations == [ddc.DDC_PAUSE_S] * 4
        assert ddc.DDC_PAUSE_S >= 0.05


# ---- detection ----------------------------------------------------------------


@pytest.fixture
def tree(tmp_path):
    """A /sys/class/drm and /dev with the given connectors and bus nodes."""
    drm, dev, adapters = tmp_path / "drm", tmp_path / "dev", tmp_path / "adapters"
    for directory in (drm, dev, adapters):
        directory.mkdir()

    def add(connector="card0-HDMI-A-1", status="connected", bus="i2c-2", node=True):
        (adapters / bus).mkdir(exist_ok=True)
        entry = drm / connector
        entry.mkdir()
        (entry / "status").write_text(status + "\n")
        os.symlink(adapters / bus, entry / "ddc")
        if node:
            (dev / bus).write_text("")
        return dev / bus

    return SimpleNamespace(drm=drm, dev=dev, add=add)


def detect(tree, displays, **kw):
    """DdcBacklight.detect with the buses mapped to fake displays."""
    return DdcBacklight.detect(
        tree.drm, tree.dev, open_bus=lambda path: displays[path.name].open(),
        sleep=kw.pop("sleep", lambda _s: None), **kw)


class TestDetection:
    def test_a_connected_panel_with_brightness_and_power(self, tree, caplog):
        tree.add()
        with caplog.at_level("INFO"):
            found = detect(tree, {"i2c-2": Display(maximum=100)})
        assert found.kind == "ddc" and found._max == 100 and found._power is True
        assert any("DDC backlight on" in r.getMessage() and "power control yes" in r.getMessage()
                   for r in caplog.records)

    def test_a_panel_without_power_control_is_still_a_backlight(self, tree):
        tree.add()
        found = detect(tree, {"i2c-2": Display(power=False)})
        assert found._power is False and found._max == 100

    def test_the_panels_own_maximum_is_used(self, tree):
        tree.add()
        assert detect(tree, {"i2c-2": Display(maximum=255)})._max == 255

    def test_a_panel_that_does_not_report_brightness_is_none(self, tree):
        tree.add()
        display = Display()
        del display.values[BRIGHTNESS]
        assert detect(tree, {"i2c-2": display}) is None

    def test_a_zero_maximum_is_none(self, tree):
        tree.add()
        assert detect(tree, {"i2c-2": Display(maximum=0)}) is None

    def test_a_first_null_reply_is_retried(self, tree):
        tree.add()
        display = Display()
        display.busy = 1
        assert detect(tree, {"i2c-2": display}) is not None

    def test_a_disconnected_connector_is_skipped(self, tree):
        tree.add(status="disconnected")
        assert detect(tree, {"i2c-2": Display()}) is None

    def test_only_hdmi_connectors_are_walked(self, tree):
        tree.add(connector="card0-DSI-1")
        assert detect(tree, {"i2c-2": Display()}) is None

    def test_a_missing_device_node_is_skipped(self, tree):
        tree.add(node=False)
        assert detect(tree, {"i2c-2": Display()}) is None

    def test_the_second_connector_is_tried_when_the_first_is_silent(self, tree):
        tree.add("card0-HDMI-A-1", bus="i2c-1")
        tree.add("card0-HDMI-A-2", bus="i2c-2")
        silent = Display()
        silent.error = OSError(errno.ENXIO, "no device")
        found = detect(tree, {"i2c-1": silent, "i2c-2": Display(maximum=80)})
        assert found._max == 80

    def test_no_drm_tree_is_none(self, tmp_path):
        assert DdcBacklight.detect(tmp_path / "none", tmp_path) is None

    @pytest.mark.parametrize("error", [
        OSError(errno.ENXIO, "x"), PermissionError(errno.EACCES, "x"),
        OSError(errno.EBUSY, "x"), OSError(errno.ENOENT, "x")])
    def test_a_bus_that_cannot_be_used_is_none_without_raising(self, tree, error):
        tree.add()

        def refuse(_path):
            raise error
        assert DdcBacklight.detect(tree.drm, tree.dev, open_bus=refuse, sleep=lambda _s: None) is None

    def test_an_unexpected_failure_is_none(self, tree):
        tree.add()

        def explode(_path):
            raise RuntimeError("boom")
        assert DdcBacklight.detect(tree.drm, tree.dev, open_bus=explode, sleep=lambda _s: None) is None

    def test_a_panel_that_never_answers_properly_is_given_up_on_quickly(self, tree):
        for n in range(6):
            tree.add(f"card0-HDMI-A-{n + 1}", bus=f"i2c-{n + 1}")
        now = [0.0]

        def sleep(seconds):
            now[0] += seconds

        displays = {}
        for n in range(6):
            display = Display()
            display.busy = 10 ** 6              # every reply is a null reply
            displays[f"i2c-{n + 1}"] = display
        assert detect(tree, displays, sleep=sleep, clock=lambda: now[0]) is None
        assert now[0] <= ddc.DETECT_BUDGET_S + 1.0

    def test_a_single_silent_panel_costs_well_under_a_second(self, tree):
        tree.add()
        now = [0.0]
        display = Display()
        display.busy = 10 ** 6
        detect(tree, {"i2c-2": display}, sleep=lambda s: now.__setitem__(0, now[0] + s))
        assert now[0] < 1.0


class TestDetectionOrder:
    def sysfs(self, tmp_path):
        directory = tmp_path / "backlight" / "panel0"
        directory.mkdir(parents=True)
        (directory / "brightness").write_text("0")
        (directory / "max_brightness").write_text("255")
        return tmp_path / "backlight"

    def test_a_writable_sysfs_backlight_wins(self, tree, tmp_path, monkeypatch):
        tree.add()
        monkeypatch.setattr(DdcBacklight, "detect", classmethod(lambda *a, **k: pytest.fail("probed ddc")))
        found = ddc.detect_backlight(self.sysfs(tmp_path), tree.drm, tree.dev)
        assert isinstance(found, Backlight) and found.kind == "sysfs"

    def test_ddc_is_next(self, tree, tmp_path, monkeypatch):
        tree.add()
        sentinel = object()
        monkeypatch.setattr(DdcBacklight, "detect", classmethod(lambda *a, **k: sentinel))
        assert ddc.detect_backlight(tmp_path / "no-backlight", tree.drm, tree.dev) is sentinel

    def test_otherwise_none(self, tmp_path):
        assert ddc.detect_backlight(tmp_path / "a", tmp_path / "b", tmp_path / "c") is None


# ---- brightness and power -----------------------------------------------------


class TestBrightnessAndPower:
    @pytest.mark.parametrize("percent,maximum,expected", [
        (100, 100, 100), (50, 100, 50), (5, 100, 5), (1, 100, 1), (80, 255, 204),
        (1, 10, 1), (100, 31, 31), (200, 100, 100)])
    def test_percent_is_a_share_of_the_panels_maximum(self, percent, maximum, expected):
        backlight, display, _ = make(maximum=maximum)
        display.values[POWER][0] = 1
        backlight._on = True
        backlight.set_percent(percent)
        finish(backlight)
        assert display.sets(BRIGHTNESS) == [expected]

    def test_a_powered_on_panel_gets_only_the_brightness(self):
        backlight, display, _ = make()
        backlight.set_percent(50)
        finish(backlight)
        assert display.log == [("set", BRIGHTNESS, 50)]

    def test_start_up_powers_the_panel_on_before_setting_the_brightness(self):
        backlight, display, pauses = make()
        display.values[POWER][0] = 2                 # left in standby by a dead dial
        backlight.set_percent(80)
        finish(backlight)
        assert display.log == [("set", POWER, 1), ("set", BRIGHTNESS, 80)]
        assert ddc.WAKE_SETTLE_S in pauses.durations

    def test_sleep_powers_the_panel_off(self):
        backlight, display, _ = make()
        backlight.set_percent(0)
        finish(backlight)
        assert display.log == [("set", POWER, ddc.POWER_OFF)]
        assert display.values[POWER][0] == 2

    def test_wake_powers_on_waits_then_verifies_the_brightness(self):
        backlight, display, pauses = make()
        backlight.set_percent(0)
        assert wait_for(lambda: len(display.log) == 1)
        backlight.set_percent(40)
        finish(backlight)
        assert display.log == [("set", POWER, 4), ("set", POWER, 1), ("set", BRIGHTNESS, 40)]
        assert display.gets[-1] == BRIGHTNESS           # the read-back

    def test_a_panel_still_waking_is_retried_until_it_takes_the_value(self):
        display = Display(busy_after_wake=3)
        backlight, display, _ = make(display)
        display.values[POWER][0] = 2
        backlight.set_percent(40)
        finish(backlight)
        assert display.values[BRIGHTNESS][0] == 40
        assert backlight._warned is False

    def test_a_panel_that_never_takes_it_gives_up_after_a_bounded_number_of_tries(self, caplog):
        display = Display(busy_after_wake=10 ** 6)
        backlight, display, pauses = make(display)
        display.values[POWER][0] = 2
        with caplog.at_level("WARNING"):
            backlight.set_percent(40)
            finish(backlight)
        sets = [e for e in display.log if e[1] == BRIGHTNESS]
        assert sets == [] and display.gets.count(BRIGHTNESS) <= ddc.WAKE_ATTEMPTS
        assert len(pauses.durations) < 40
        assert len([r for r in caplog.records if "DDC" in r.getMessage()]) == 1

    def test_without_power_control_sleep_sets_brightness_zero(self):
        backlight, display, _ = make(power=False)
        backlight.set_percent(0)
        assert wait_for(lambda: len(display.log) == 1)
        backlight.set_percent(60)
        finish(backlight)
        assert display.log == [("set", BRIGHTNESS, 0), ("set", BRIGHTNESS, 60)]

    def test_a_known_powered_panel_is_not_asked_again_on_every_change(self):
        backlight, display, _ = make()
        backlight.set_percent(50)
        assert wait_for(lambda: display.sets(BRIGHTNESS) == [50])
        backlight.set_percent(60)
        finish(backlight)
        assert display.gets == [POWER]


# ---- the worker -----------------------------------------------------------------


class TestWorker:
    def test_set_percent_returns_at_once_even_when_the_bus_is_slow(self):
        backlight, display, pauses = make()
        pauses.gate = threading.Event()
        started = time.monotonic()
        backlight.set_percent(30)
        assert pauses.entered.wait(3)
        for value in range(31, 60):
            backlight.set_percent(value)
        assert time.monotonic() - started < 1.0
        pauses.gate.set()
        finish(backlight)

    def test_many_posts_make_few_writes_and_the_last_value_wins(self):
        backlight, display, pauses = make()
        pauses.gate = threading.Event()
        backlight.set_percent(10)
        assert pauses.entered.wait(3)                   # the worker is mid-write
        for value in range(11, 91):
            backlight.set_percent(value)
        pauses.gate.set()
        finish(backlight)
        # The power read gets the first pause; whatever it had started with, only the
        # first and last wanted levels are ever written.
        assert display.sets(BRIGHTNESS)[-1] == 90
        assert len(display.sets(BRIGHTNESS)) <= 2

    def test_a_sleep_posted_after_a_brightness_is_not_lost(self):
        backlight, display, pauses = make()
        pauses.gate = threading.Event()
        backlight.set_percent(40)
        assert pauses.entered.wait(3)
        backlight.set_percent(70)
        backlight.set_percent(0)
        pauses.gate.set()
        finish(backlight)
        assert display.log[-1] == ("set", POWER, ddc.POWER_OFF)
        assert 70 not in display.sets(BRIGHTNESS)

    def test_a_brightness_posted_after_a_sleep_wins(self):
        backlight, display, pauses = make()
        pauses.gate = threading.Event()
        backlight.set_percent(40)
        assert pauses.entered.wait(3)
        backlight.set_percent(0)
        backlight.set_percent(70)
        pauses.gate.set()
        finish(backlight)
        assert display.sets(BRIGHTNESS)[-1] == 70
        assert ("set", POWER, ddc.POWER_OFF) not in display.log

    def test_a_newer_request_cuts_a_wake_retry_short(self):
        display = Display(busy_after_wake=10 ** 6)
        backlight, display, pauses = make(display)
        display.values[POWER][0] = 2
        pauses.gate = threading.Event()
        backlight.set_percent(40)
        assert pauses.entered.wait(3)
        backlight.set_percent(0)
        pauses.gate.set()
        finish(backlight)
        assert display.gets.count(BRIGHTNESS) <= 2

    def test_nothing_runs_until_the_first_request(self):
        backlight, display, _ = make()
        assert backlight._thread is None and display.log == []

    def test_a_percent_out_of_range_is_clamped(self):
        backlight, display, _ = make()
        backlight.set_percent(500)
        backlight.set_percent(-5)
        finish(backlight)
        assert display.log[-1] == ("set", POWER, ddc.POWER_OFF)

    def test_the_condition_is_not_held_while_talking_to_the_bus(self):
        backlight, display, pauses = make()
        held = []
        original = display.write
        display.write = lambda data: (held.append(backlight._cond._is_owned()), original(data))[1]
        backlight.set_percent(30)
        backlight.set_percent(0)
        finish(backlight)
        assert held and not any(held)


class TestClose:
    def test_close_stops_the_thread(self):
        backlight, display, _ = make()
        backlight.set_percent(30)
        thread = backlight._thread
        backlight.close()
        assert not thread.is_alive()

    def test_close_without_ever_being_used_is_harmless(self):
        make()[0].close()

    def test_close_leaves_a_sleeping_panel_on_at_its_last_level(self):
        backlight, display, _ = make()
        backlight.set_percent(65)
        backlight.set_percent(0)
        backlight.close()
        assert display.values[POWER][0] == 1
        assert display.values[BRIGHTNESS][0] == 65

    def test_close_leaves_an_awake_panel_alone(self):
        backlight, display, _ = make()
        backlight.set_percent(65)
        assert wait_for(lambda: display.sets(BRIGHTNESS) == [65])
        backlight.close()
        assert display.log == [("set", BRIGHTNESS, 65)]

    def test_requests_after_close_are_ignored(self):
        backlight, display, _ = make()
        backlight.set_percent(65)
        backlight.close()
        before = list(display.log)
        backlight.set_percent(0)
        time.sleep(0.05)
        assert display.log == before


# ---- failures -------------------------------------------------------------------


class TestFailures:
    @pytest.mark.parametrize("error", [
        OSError(errno.ENXIO, "x"), PermissionError(errno.EACCES, "x"),
        OSError(errno.EBUSY, "x"), OSError(errno.EREMOTEIO, "x")])
    def test_a_bus_error_never_raises_and_is_logged_once(self, error, caplog):
        backlight, display, _ = make()
        display.error = error
        with caplog.at_level("WARNING"):
            backlight.set_percent(50)
            backlight.set_percent(0)
            backlight.set_percent(60)
            finish(backlight)
        assert len([r for r in caplog.records if "DDC" in r.getMessage()]) == 1

    def test_the_next_request_recovers(self):
        backlight, display, _ = make()
        display.error = OSError(errno.EBUSY, "busy")
        backlight.set_percent(50)
        assert wait_for(lambda: backlight._warned)
        display.error = None
        backlight.set_percent(70)
        finish(backlight)
        assert display.values[BRIGHTNESS][0] == 70

    def test_a_malformed_reply_is_a_failure_not_an_exception(self, caplog):
        backlight, display, _ = make()
        display.corrupt = bytes(11)
        display.values[POWER][0] = 2
        with caplog.at_level("WARNING"):
            backlight.set_percent(50)
            finish(backlight)
        assert backlight._warned

    def test_the_power_state_is_forgotten_after_a_failure(self):
        backlight, display, _ = make()
        backlight.set_percent(50)
        assert wait_for(lambda: display.sets(BRIGHTNESS) == [50])
        display.error = OSError(errno.EREMOTEIO, "x")
        backlight.set_percent(0)
        assert wait_for(lambda: backlight._on is None)
        display.error = None
        backlight.set_percent(50)
        finish(backlight)
        assert display.values[BRIGHTNESS][0] == 50

    def test_a_non_ddc_exception_in_the_worker_does_not_kill_it(self):
        backlight, display, _ = make()
        original = display.write
        calls = []

        def flaky(data):
            calls.append(1)
            if len(calls) == 2:
                raise RuntimeError("boom")
            return original(data)
        display.write = flaky
        backlight.set_percent(50)
        assert wait_for(lambda: backlight._warned)
        backlight.set_percent(60)
        finish(backlight)
        assert display.values[BRIGHTNESS][0] == 60


# ---- through HdPanel --------------------------------------------------------------


class Hub:
    def publish(self, *_a):
        pass


class TestPanelDrivesDdc:
    def make(self, **kw):
        backlight, display, pauses = make(**kw)
        settings = SimpleNamespace(sleep_after_s=300, brightness=80, always_show_controls=False)
        panel = HdPanel(Hub(), settings=lambda: settings, backlight=backlight)
        return panel, backlight, display, settings

    def test_the_view_reports_the_kind(self):
        panel, *_ = self.make()
        assert panel.view()["backlight"] == "ddc" and panel.backlight_kind == "ddc"

    def test_start_applies_the_configured_brightness_and_powers_on(self):
        panel, backlight, display, _ = self.make()
        display.values[POWER][0] = 2
        panel.start()
        panel.stop()
        assert display.log == [("set", POWER, 1), ("set", BRIGHTNESS, 80)]

    def test_sleep_and_wake_drive_power_and_brightness(self):
        panel, backlight, display, _ = self.make()
        panel.start()
        assert wait_for(lambda: display.sets(BRIGHTNESS) == [80])
        panel.sleep_now()
        assert wait_for(lambda: display.values[POWER][0] == 2)
        panel.touch()
        assert wait_for(lambda: display.values[POWER][0] == 1 and display.sets(BRIGHTNESS)[-1] == 80)
        panel.stop()

    def test_a_changed_setting_is_shown_when_awake_and_held_back_when_asleep(self):
        panel, backlight, display, settings = self.make()
        settings.brightness = 30
        panel.apply_settings()
        assert wait_for(lambda: display.sets(BRIGHTNESS) == [30])
        panel.sleep_now()
        settings.brightness = 55
        panel.apply_settings()
        assert wait_for(lambda: display.values[POWER][0] == 2)
        panel.touch()
        assert wait_for(lambda: display.sets(BRIGHTNESS)[-1] == 55)
        panel.stop()

    def test_stop_leaves_the_panel_on(self):
        panel, backlight, display, _ = self.make()
        panel.start()
        panel.sleep_now()
        panel.stop()
        assert display.values[POWER][0] == 1
        assert not backlight._thread.is_alive()
