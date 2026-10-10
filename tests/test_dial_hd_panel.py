"""Tests for the HD dial's panel service: the idle clock, sleep and wake rules,
the sysfs backlight and what the service does and does not hold while it
calls out."""
from __future__ import annotations

import os
import stat
import sys
import threading
import time
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))

import dial_hd_panel as hdp
from dial_hd_panel import Backlight, HdPanel


class Hub:
    def __init__(self):
        self.publishes = 0
        self.panel = None
        self.lock_held_at_publish = []

    def publish(self, *_a):
        self.publishes += 1
        if self.panel is not None:
            self.lock_held_at_publish.append(self.panel._lock.locked())


class Clock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


def make_settings(**kwargs):
    values = {"sleep_after_s": 300, "brightness": 80}
    values.update(kwargs)
    return SimpleNamespace(**values)


class FakeBacklight:
    kind = "sysfs"

    def __init__(self, panel=None):
        self.writes = []
        self.panel = panel
        self.lock_held_at_write = []

    def set_percent(self, percent):
        self.writes.append(percent)
        if self.panel is not None:
            self.lock_held_at_write.append(self.panel._lock.locked())

    def close(self):
        self.closed = True


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def hub():
    return Hub()


@pytest.fixture
def settings():
    return make_settings()


@pytest.fixture
def panel(hub, settings, clock):
    panel = HdPanel(hub, settings=lambda: settings, clock=clock)
    hub.panel = panel
    return panel


def idle(panel, clock, seconds, **kwargs):
    clock.now += seconds
    panel.tick(clock.now, playing=kwargs.get("playing", False), interrupt=kwargs.get("interrupt", False),
               engaged=kwargs.get("engaged", False))


# ---- the idle clock --------------------------------------------------------


class TestIdleClock:
    def test_the_panel_starts_awake(self, panel):
        assert panel.view()["asleep"] is False

    @pytest.mark.parametrize("sleep_after", [60, 300, 900])
    def test_it_sleeps_once_idle_for_the_chosen_time(self, panel, clock, settings, hub, sleep_after):
        settings.sleep_after_s = sleep_after
        panel.tick(clock.now, playing=False, interrupt=False)
        idle(panel, clock, sleep_after - 1)
        assert panel.view()["asleep"] is False
        assert hub.publishes == 0
        idle(panel, clock, 1)
        assert panel.view()["asleep"] is True
        assert hub.publishes == 1

    def test_zero_never_sleeps(self, panel, clock, settings, hub):
        settings.sleep_after_s = 0
        for _ in range(5):
            idle(panel, clock, 100000)
        assert panel.view()["asleep"] is False
        assert hub.publishes == 0

    def test_playing_keeps_it_awake(self, panel, clock, hub):
        for _ in range(5):
            idle(panel, clock, 1000, playing=True)
        assert panel.view()["asleep"] is False

    def test_the_idle_clock_starts_when_playing_stops(self, panel, clock):
        idle(panel, clock, 1000, playing=True)
        idle(panel, clock, 0)                        # playing stops: the clock starts here
        idle(panel, clock, 299)
        assert panel.view()["asleep"] is False
        idle(panel, clock, 1)
        assert panel.view()["asleep"] is True

    def test_a_change_to_the_setting_applies_to_the_running_clock(self, panel, clock, settings):
        panel.tick(clock.now, playing=False, interrupt=False)
        idle(panel, clock, 100)
        settings.sleep_after_s = 60
        idle(panel, clock, 1)
        assert panel.view()["asleep"] is True

    def test_activity_restarts_the_clock(self, panel, clock):
        panel.tick(clock.now, playing=False, interrupt=False)
        idle(panel, clock, 290)
        panel.touch()
        idle(panel, clock, 290)
        assert panel.view()["asleep"] is False
        idle(panel, clock, 10)
        assert panel.view()["asleep"] is True

    def test_engaged_holds_it_awake_without_restarting_the_clock(self, panel, clock):
        panel.tick(clock.now, playing=False, interrupt=False)
        idle(panel, clock, 290, engaged=True)
        idle(panel, clock, 10, engaged=True)
        assert panel.view()["asleep"] is False
        idle(panel, clock, 1)                          # the clock was never restarted
        assert panel.view()["asleep"] is True

    def test_ticks_while_asleep_change_nothing(self, panel, clock, hub):
        panel.tick(clock.now, playing=False, interrupt=False)
        idle(panel, clock, 300)
        assert hub.publishes == 1
        idle(panel, clock, 5000)
        assert hub.publishes == 1


class TestWakeRules:
    def asleep(self, panel, clock):
        panel.tick(clock.now, playing=False, interrupt=False)
        idle(panel, clock, 300)
        assert panel.view()["asleep"] is True

    def test_engaged_does_not_wake_a_sleeping_panel(self, panel, clock, hub):
        self.asleep(panel, clock)
        idle(panel, clock, 1, engaged=True)
        idle(panel, clock, 1000, engaged=True)
        assert panel.view()["asleep"] is True
        assert hub.publishes == 1

    def test_the_clock_is_not_restarted_when_engaged_ends(self, panel, clock):
        panel.tick(clock.now, playing=False, interrupt=False)
        idle(panel, clock, 1000, engaged=True)
        assert panel.view()["asleep"] is False
        idle(panel, clock, 0)                          # engaged ends: idle for the whole time already
        assert panel.view()["asleep"] is True

    def test_playback_starting_wakes_it(self, panel, clock, hub):
        self.asleep(panel, clock)
        idle(panel, clock, 1, playing=True)
        assert panel.view()["asleep"] is False
        assert hub.publishes == 2

    def test_an_interrupting_warning_wakes_it(self, panel, clock, hub):
        self.asleep(panel, clock)
        idle(panel, clock, 1, interrupt=True)
        assert panel.view()["asleep"] is False
        assert hub.publishes == 2

    def test_a_warning_that_does_not_interrupt_never_wakes_it(self, panel, clock, hub):
        self.asleep(panel, clock)
        idle(panel, clock, 1, interrupt=False)
        assert panel.view()["asleep"] is True

    def test_an_interrupt_that_stays_due_does_not_hold_it_awake(self, panel, clock):
        self.asleep(panel, clock)
        idle(panel, clock, 1, interrupt=True)
        panel.sleep_now()
        idle(panel, clock, 1, interrupt=True)          # still due, not a new one
        assert panel.view()["asleep"] is True

    def test_playback_that_continues_does_not_wake_a_panel_put_to_sleep(self, panel, clock):
        idle(panel, clock, 1, playing=True)
        panel.sleep_now()
        idle(panel, clock, 1, playing=True)
        assert panel.view()["asleep"] is True

    def test_touch_wakes_and_publishes_once(self, panel, clock, hub):
        self.asleep(panel, clock)
        panel.touch()
        assert panel.view()["asleep"] is False
        assert hub.publishes == 2
        panel.touch()
        assert hub.publishes == 2                       # awake: nothing changed

    def test_wake_is_touch(self, panel, clock):
        self.asleep(panel, clock)
        panel.wake()
        assert panel.view()["asleep"] is False

    def test_sleep_now_sleeps_at_once_and_publishes_once(self, panel, hub):
        panel.sleep_now()
        assert panel.view()["asleep"] is True
        panel.sleep_now()
        assert hub.publishes == 1

    def test_after_waking_the_full_idle_time_applies_again(self, panel, clock):
        self.asleep(panel, clock)
        panel.touch()
        idle(panel, clock, 299)
        assert panel.view()["asleep"] is False
        idle(panel, clock, 1)
        assert panel.view()["asleep"] is True


class TestView:
    def test_it_reports_the_settings_and_the_backlight_kind(self, hub, clock):
        settings = make_settings(brightness=55, sleep_after_s=900)
        panel = HdPanel(hub, settings=lambda: settings, backlight=FakeBacklight(), clock=clock)
        assert panel.view() == {
            "asleep": False, "brightness": 55, "sleep_after_s": 900, "backlight": "sysfs",
            "kiosk": False,
        }

    def test_with_no_backlight_the_kind_is_none(self, panel):
        assert panel.view()["backlight"] == "none"
        assert panel.backlight_kind == "none"

    def test_the_view_feeds_the_state_body(self, panel):
        import hd_scenarios as hs
        from dial_hd_state import build_state
        body = build_state(
            hs.SCENARIOS["playing_artwork"].snapshot, panel=panel.view(),
            settings={"brightness": 1}, hub_seq=1, now=0.0,
        )
        assert body["panel"]["asleep"] is False
        assert body["panel"]["backlight"] == "none"


# ---- the backlight ---------------------------------------------------------


@pytest.fixture
def sysfs(tmp_path):
    def make(name="panel0", maximum="255", writable=True):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "brightness").write_text("0")
        if maximum is not None:
            (directory / "max_brightness").write_text(maximum)
        if not writable:
            (directory / "brightness").chmod(stat.S_IRUSR)
        return directory
    return make


def level(directory):
    return int((directory / "brightness").read_text())


class TestBacklight:
    def test_percent_scales_to_the_maximum(self, sysfs):
        directory = sysfs(maximum="255")
        backlight = Backlight(directory)
        backlight.set_percent(100)
        assert level(directory) == 255
        backlight.set_percent(50)
        assert level(directory) == 128
        backlight.set_percent(0)
        assert level(directory) == 0

    def test_any_awake_level_is_at_least_the_lowest_step(self, sysfs):
        directory = sysfs(maximum="10")
        Backlight(directory).set_percent(1)
        assert level(directory) == 1

    def test_out_of_range_is_clamped(self, sysfs):
        directory = sysfs(maximum="100")
        backlight = Backlight(directory)
        backlight.set_percent(500)
        assert level(directory) == 100
        backlight.set_percent(-5)
        assert level(directory) == 0

    def test_detect_finds_the_first_usable_one(self, sysfs, tmp_path):
        first = sysfs("a_panel", maximum="64")
        sysfs("b_panel")
        found = Backlight.detect(tmp_path)
        assert found is not None
        found.set_percent(100)
        assert level(first) == 64
        assert found.kind == "sysfs"

    @pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can write anything")
    def test_detect_is_none_without_write_permission(self, sysfs, tmp_path):
        sysfs(writable=False)
        assert Backlight.detect(tmp_path) is None

    @pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can write anything")
    def test_detect_skips_an_unwritable_one_for_a_writable_one(self, sysfs, tmp_path):
        sysfs("a_locked", writable=False)
        usable = sysfs("b_usable", maximum="9")
        found = Backlight.detect(tmp_path)
        found.set_percent(100)
        assert level(usable) == 9

    def test_detect_is_none_without_a_readable_maximum(self, sysfs, tmp_path):
        sysfs(maximum=None)
        assert Backlight.detect(tmp_path) is None

    @pytest.mark.parametrize("text", ["", "abc", "0", "-3"])
    def test_detect_is_none_with_an_unusable_maximum(self, sysfs, tmp_path, text):
        sysfs(maximum=text)
        assert Backlight.detect(tmp_path) is None

    def test_detect_is_none_for_no_root(self, tmp_path):
        assert Backlight.detect(tmp_path / "missing") is None
        assert Backlight.detect(tmp_path) is None

    def test_a_failed_write_never_raises_and_is_logged_once(self, sysfs, caplog):
        directory = sysfs()
        backlight = Backlight(directory)
        (directory / "brightness").unlink()
        (directory / "brightness").mkdir()              # writing a directory fails
        with caplog.at_level("WARNING"):
            backlight.set_percent(50)
            backlight.set_percent(60)
        assert len([r for r in caplog.records if "backlight write failed" in r.getMessage()]) == 1


class TestPanelDrivesTheBacklight:
    def make(self, hub, settings, clock):
        panel = HdPanel(hub, settings=lambda: settings, clock=clock)
        backlight = FakeBacklight(panel)
        panel._backlight = backlight
        hub.panel = panel
        return panel, backlight

    def test_start_sets_the_awake_level(self, hub, settings, clock):
        panel, backlight = self.make(hub, settings, clock)
        panel.start()
        assert backlight.writes == [80]

    def test_sleep_goes_dark_and_wake_returns_to_the_setting(self, hub, settings, clock):
        panel, backlight = self.make(hub, settings, clock)
        panel.sleep_now()
        panel.touch()
        assert backlight.writes == [0, 80]

    def test_idle_sleep_goes_dark(self, hub, settings, clock):
        panel, backlight = self.make(hub, settings, clock)
        panel.tick(clock.now, playing=False, interrupt=False)
        idle(panel, clock, 300)
        assert backlight.writes == [0]

    def test_a_changed_brightness_is_shown_at_once_when_awake(self, hub, settings, clock):
        panel, backlight = self.make(hub, settings, clock)
        settings.brightness = 30
        panel.apply_settings()
        assert backlight.writes == [30]
        assert hub.publishes == 1

    def test_a_changed_brightness_leaves_a_sleeping_panel_dark(self, hub, settings, clock):
        panel, backlight = self.make(hub, settings, clock)
        panel.sleep_now()
        settings.brightness = 30
        panel.apply_settings()
        assert backlight.writes == [0, 0]
        panel.touch()
        assert backlight.writes[-1] == 30

    def test_no_backlight_still_publishes(self, panel, hub):
        panel.sleep_now()
        panel.apply_settings()
        assert hub.publishes == 2

    def test_the_panel_lock_is_never_held_while_calling_out(self, hub, settings, clock):
        panel, backlight = self.make(hub, settings, clock)
        panel.start()
        panel.tick(clock.now, playing=False, interrupt=False)
        idle(panel, clock, 300)
        panel.touch()
        panel.sleep_now()
        panel.apply_settings()
        assert backlight.lock_held_at_write and not any(backlight.lock_held_at_write)
        assert hub.lock_held_at_publish and not any(hub.lock_held_at_publish)

    def test_concurrent_transitions_leave_the_hardware_at_the_final_state(self, hub, settings, clock):
        panel, backlight = self.make(hub, settings, clock)
        barrier = threading.Barrier(6)

        def flip(i):
            barrier.wait()
            for _ in range(50):
                (panel.sleep_now if i % 2 else panel.touch)()

        threads = [threading.Thread(target=flip, args=(i,)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        panel.apply_settings()
        expected = 0 if panel.view()["asleep"] else 80
        assert backlight.writes[-1] == expected


# ---- the background tick ---------------------------------------------------


class TestTickThread:
    def test_the_thread_feeds_the_tick_from_the_inputs(self, hub, settings, monkeypatch):
        monkeypatch.setattr(hdp, "TICK_S", 0.01)
        state = {"playing": False, "interrupt": False}
        panel = HdPanel(
            hub, settings=lambda: settings, inputs=lambda: (state["playing"], state["interrupt"], False),
        )
        settings.sleep_after_s = 60
        panel.start()
        try:
            panel.sleep_now()
            state["playing"] = True
            deadline = time.monotonic() + 3
            while panel.view()["asleep"] and time.monotonic() < deadline:
                time.sleep(0.01)
            assert panel.view()["asleep"] is False
        finally:
            panel.stop()

    def test_a_raising_input_does_not_end_the_thread(self, hub, settings, monkeypatch):
        monkeypatch.setattr(hdp, "TICK_S", 0.01)
        calls = []

        def inputs():
            calls.append(1)
            if len(calls) < 3:
                raise RuntimeError("core gone")
            return False, False

        panel = HdPanel(hub, settings=lambda: settings, inputs=inputs)
        panel.start()
        try:
            deadline = time.monotonic() + 3
            while len(calls) < 5 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert len(calls) >= 5
        finally:
            panel.stop()

    def test_stop_ends_the_thread_and_is_repeatable(self, hub, settings, monkeypatch):
        monkeypatch.setattr(hdp, "TICK_S", 0.01)
        panel = HdPanel(hub, settings=lambda: settings, inputs=lambda: (False, False))
        panel.start()
        thread = panel._thread
        panel.stop()
        assert not thread.is_alive()
        panel.stop()

    def test_without_inputs_no_thread_is_started(self, panel):
        panel.start()
        assert panel._thread is None
