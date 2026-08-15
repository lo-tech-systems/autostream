"""dial_touch_controllers.py — touch controller profile table.

Pure data, mirroring dial_display_profiles.py: NO hardware imports here,
ever — not at module level and not inside any function. dial_config.py
imports this module for enum validation, and dial_config is loaded
unconditionally at dial process start, before the display stack's ImportError
isolation gets a chance to run (see dial_display_profiles.py's module
docstring for the full argument — the same discipline applies here). A
hardware import at this level would let a missing/broken touch library crash
the whole dial service, including volume control.

Resolving a driver_tag to an actual driver class happens lazily inside
dial_touch_drivers.py's open(), exactly as dial_display_adafruit.py resolves
DisplayProfile.driver_tag — so this table stays free of hardware even though
dial_main.py selects a controller from it at startup.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TouchController:
    key: str
    label: str
    bus: str  # "spi" | "i2c"
    driver_tag: str | None
    # Nominal calibration constants for resistive panels. None (the default)
    # for capacitive controllers, which report already-scaled coordinates
    # and need no raw-ADC calibration here.
    raw_x_min: int | None = None
    raw_x_max: int | None = None
    raw_y_min: int | None = None
    raw_y_max: int | None = None
    z_threshold: int | None = None


class UnknownTouchControllerError(KeyError):
    """Raised by get_controller() for a key not present in TOUCH_CONTROLLERS."""


# Ordered table: key -> controller. "none" is the default and disables touch
# entirely — no driver_tag, no bus semantics, nothing constructed.
TOUCH_CONTROLLERS: dict[str, TouchController] = {
    "none": TouchController(
        key="none",
        label="None",
        bus="spi",
        driver_tag=None,
    ),
    # XPT2046 nominal 12-bit calibration constants. Unverified on hardware —
    # these are textbook/datasheet-typical raw ADC extremes for a 12-bit
    # resistive touch controller (0-4095 full range), inset slightly for the
    # usual panel-edge non-linearity. Real panels vary and should be
    # recalibrated once actual hardware is available.
    "xpt2046": TouchController(
        key="xpt2046",
        label="Resistive (XPT2046/HR2046)",
        bus="spi",
        driver_tag="xpt2046",
        raw_x_min=200,
        raw_x_max=3900,
        raw_y_min=200,
        raw_y_max=3900,
        # Calibrated against real hardware over ~3500 idle samples and a
        # run of progressively lighter touches:
        #   idle, nothing on the panel:      max z 176
        #   lightest deliberate touch:       median z 338 (min single 315)
        # So the usable window is 176..338, and this sits mid-window. Going
        # lower buys NO sensitivity — every genuine contact measured read
        # well above 300 — while walking into the idle noise band. An
        # earlier value of 20 was set from a much shorter idle sample that
        # happened to peak at 26, and was well below the real noise floor.
        z_threshold=250,
    ),
    "ft6206": TouchController(
        key="ft6206",
        label="Capacitive (FT6206/FT6236)",
        bus="i2c",
        driver_tag="ft6206",
    ),
}

DEFAULT_TOUCH_KEY = "none"


def get_controller(key: str) -> TouchController:
    """Look up a controller by key, raising UnknownTouchControllerError if
    absent. The caller decides how to surface the error."""
    try:
        return TOUCH_CONTROLLERS[key]
    except KeyError:
        raise UnknownTouchControllerError(key) from None


def list_controllers() -> list[dict]:
    """Return the published catalogue as [{"key", "text"}, ...] for the API."""
    return [{"key": c.key, "text": c.label} for c in TOUCH_CONTROLLERS.values()]
