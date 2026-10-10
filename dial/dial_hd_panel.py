"""dial_hd_panel.py: the HD dial's panel service (sleep, wake, brightness).

The panel is asleep or awake. Asleep, the page draws a black shield (the
state body reports it) and the first touch only wakes; where the display
exposes a sysfs backlight the service also drives it to zero, and awake back
to the configured brightness. The backlight is a sysfs one or, on an HDMI
panel that answers the monitor control channel, a DDC one (see
dial_hd_ddc.py); both have the same interface. With no backlight the
page-only shield is all there is.

The idle clock starts when nothing is playing and restarts on activity. After
the configured sleep-after time the panel sleeps. Someone in the middle of
something on the page (engaged) holds it awake without restarting the idle
clock. Playback starting, or an interrupting warning becoming due, wakes it;
an appliance warning that does not interrupt never does.

Locking: one small lock guards the panel's own fields and is never held while
calling out (the hub, the settings reader, the backlight). Backlight writes
are serialised by their own lock and always write the latest wanted level, so
two threads changing state cannot leave the hardware showing the older one.
A slow backlight (DDC) takes the level and applies it on a thread of its own,
so a caller never waits on the hardware.
The panel never calls into the core.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path
from typing import Callable

BACKLIGHT_ROOT = Path("/sys/class/backlight")
TICK_S = 1.0


def scaled_level(percent: int, maximum: int) -> int:
    """*percent* (clamped to 0..100) as a share of *maximum*: 0 is dark, any
    other value at least the lowest step."""
    percent = max(0, min(100, int(percent)))
    return 0 if percent == 0 else max(1, round(maximum * percent / 100))


class BacklightBase:
    """What every backlight kind shares: a *kind* name, a first-failure-only
    warning, and a close() for kinds that hold something."""

    kind = ""

    def __init__(self) -> None:
        self._warned = False

    def _warn_once(self, what: str, error: object) -> None:
        if not self._warned:
            self._warned = True
            logging.warning("HD panel: %s failed (%s)", what, error)

    def set_percent(self, percent: int) -> None:
        raise NotImplementedError

    def close(self) -> None:
        """Release anything held and leave the panel lit."""


class Backlight(BacklightBase):
    """A sysfs backlight: brightness is written as a share of max_brightness."""

    kind = "sysfs"

    def __init__(self, directory: Path) -> None:
        super().__init__()
        self._brightness = Path(directory) / "brightness"
        self._max = self._read_max(Path(directory) / "max_brightness")

    @staticmethod
    def _read_max(path: Path) -> int:
        try:
            value = int(path.read_text().strip())
        except (OSError, ValueError):
            return 0
        return value if value > 0 else 0

    @classmethod
    def detect(cls, root: "Path | str" = BACKLIGHT_ROOT) -> "Backlight | None":
        """The first backlight under *root* whose brightness file this
        process can write and whose maximum is readable, else None."""
        try:
            entries = sorted(Path(root).iterdir())
        except OSError:
            return None
        for entry in entries:
            brightness = entry / "brightness"
            try:
                if not (brightness.is_file() and os.access(brightness, os.W_OK)):
                    continue
            except OSError:
                continue
            backlight = cls(entry)
            if backlight._max > 0:
                return backlight
        return None

    def set_percent(self, percent: int) -> None:
        """Set the level: 0 is dark, any other value at least the lowest
        step. Never raises; the first failure is logged."""
        try:
            self._brightness.write_text(str(scaled_level(percent, self._max)))
        except OSError as e:
            self._warn_once("backlight write", e)


class HdPanel:
    """*hub* is published to on every transition. *settings* returns the
    current screen settings (sleep_after_s, brightness, always_show_controls).
    *kiosk* says the page is shown on this dial's own screen.
    *inputs*, when given, returns (playing, interrupting, engaged) and feeds the
    background tick started by start()."""

    def __init__(
        self, hub, *, settings: Callable[[], object], backlight: "BacklightBase | None" = None,
        inputs: "Callable[[], tuple[bool, bool, bool]] | None" = None, clock=time.monotonic,
        kiosk: bool = False,
    ) -> None:
        self._hub = hub
        self._settings = settings
        self._backlight = backlight
        self._inputs = inputs
        self._clock = clock
        self._kiosk = kiosk
        self._lock = threading.Lock()
        self._hw_lock = threading.Lock()
        self._asleep = False
        self._idle_since: "float | None" = clock()
        self._playing = False
        self._interrupting = False
        self._stop = threading.Event()
        self._thread: "threading.Thread | None" = None

    # ---- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        """Set the backlight to the awake level and begin ticking."""
        self._apply_backlight()
        if self._inputs is None or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True, name="hd-panel")
        self._thread.start()

    def stop(self) -> None:
        """Stop ticking and leave the panel lit."""
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None and thread.is_alive():
            thread.join(2.0)
        if self._backlight is not None:
            self._backlight.close()

    def _run(self) -> None:
        while not self._stop.wait(TICK_S):
            try:
                playing, interrupting, engaged = self._inputs()
                self.tick(self._clock(), playing=playing, interrupt=interrupting, engaged=engaged)
            except Exception:
                logging.debug("hd panel: tick failed", exc_info=True)

    # ---- reads -------------------------------------------------------------

    @property
    def backlight_kind(self) -> str:
        return self._backlight.kind if self._backlight is not None else "none"

    def view(self) -> dict:
        """The panel block's inputs: asleep, brightness, sleep_after_s,
        backlight kind, always_show_controls and whether this is the kiosk
        surface."""
        settings = self._settings()
        with self._lock:
            asleep = self._asleep
        return {
            "asleep": asleep,
            "brightness": settings.brightness,
            "sleep_after_s": settings.sleep_after_s,
            "backlight": self.backlight_kind,
            "always_show_controls": settings.always_show_controls,
            "kiosk": self._kiosk,
        }

    # ---- transitions -------------------------------------------------------

    def touch(self) -> None:
        """Activity: the idle clock restarts, and a sleeping panel wakes."""
        with self._lock:
            was_asleep = self._asleep
            self._asleep = False
            self._idle_since = self._clock() if not self._playing else None
        if was_asleep:
            self._changed()

    def wake(self) -> None:
        self.touch()

    def sleep_now(self) -> None:
        with self._lock:
            was_asleep = self._asleep
            self._asleep = True
        if not was_asleep:
            self._changed()

    def apply_settings(self) -> None:
        """The brightness setting changed: show it now if awake. Always
        publishes, so the page's pull-down follows the saved value."""
        self._apply_backlight()
        self._hub.publish()

    def tick(self, now: float, *, playing: bool, interrupt: bool, engaged: bool = False) -> None:
        """Fold what is playing and whether an interrupting warning is due,
        and sleep when the idle time has run out. *engaged* (someone mid-task on
        the page) only defers the sleep: it neither wakes nor restarts the clock."""
        sleep_after = self._settings().sleep_after_s
        changed = False
        with self._lock:
            started = playing and not self._playing
            interrupted = interrupt and not self._interrupting
            if self._playing and not playing:
                self._idle_since = now
            self._playing = playing
            self._interrupting = interrupt
            if playing:
                self._idle_since = None
            elif self._idle_since is None:
                self._idle_since = now
            if self._asleep and (started or interrupted):
                self._asleep = False
                changed = True
                if not playing:
                    self._idle_since = now
            elif (
                not self._asleep and not playing and not engaged and sleep_after > 0
                and self._idle_since is not None and now - self._idle_since >= sleep_after
            ):
                self._asleep = True
                changed = True
        if changed:
            self._changed()

    # ---- effects (never under the panel lock) ------------------------------

    def _changed(self) -> None:
        self._apply_backlight()
        self._hub.publish()

    def _apply_backlight(self) -> None:
        if self._backlight is None:
            return
        with self._hw_lock:
            with self._lock:
                asleep = self._asleep
            level = 0 if asleep else self._settings().brightness
            self._backlight.set_percent(level)
