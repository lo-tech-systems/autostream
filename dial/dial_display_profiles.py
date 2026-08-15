"""dial_display_profiles.py — display panel profile table.

Pure data: no hardware imports here, ever (no adafruit_rgb_display, board,
busio, digitalio — not even inside a function). dial_config.py imports this
module, and dial_config is imported unconditionally at dial process start,
before the display stack gets a chance to isolate a broken Adafruit install
behind open()'s try/except. A hardware import at this level would let a
missing/broken adafruit-circuitpython-rgb-display crash the whole dial
service — including volume control — which violates the degrade-to-noop
invariant documented in dial_display_adafruit.py and dial_display.py. Driver
classes are named here only as plain string tags; resolving a tag to an
actual driver class happens lazily inside the backend's open() (see
dial_display_adafruit.py).

Doctrine: DisplayBackend is OUTPUT-ONLY. A future touch panel is a sibling
event-source object with its own thread and its own lifecycle — never
methods bolted onto the display backend. The reserved Profile.touch field
below exists so a profile can eventually name a touch controller/bus, but
nothing in this codebase constructs or drives one yet.

Key naming convention: a profile key encodes the LOGICAL/compose dimensions
in landscape WIDTHxHEIGHT order — the dimensions the compose pipeline works
in and the driver is constructed with (see rotation_mechanism below for why
that is not always the panel's "natural" portrait orientation). The label
instead follows the datasheet/marketing convention, which is not always
landscape (e.g. ST7735S panels are commonly sold as "128x160" portrait).
Key and label are deliberately decoupled — both are opaque strings as far as
the web UI and the rest of the dial package are concerned.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DisplayProfile:
    key: str
    label: str
    driver_tag: str
    width: int
    height: int
    x_offset: int = 0
    y_offset: int = 0
    rotation: int = 0
    # How the driver reaches the panel's physical landscape scan order:
    #
    # "init_table" — the driver's own hardcoded init table sets a fixed
    # MADCTL value, so the *controller itself* scans landscape once
    # initialised, and rotation must stay 0 with the driver constructed
    # using landscape dimensions. ST7735S is the case in point: its init
    # sets MADCTL=0x60 (MV|MX), so after the axis exchange the CASET
    # "column" register addresses the physical 160-px axis (162 GRAM
    # addresses) and RASET the 128-px axis (132 addresses) — the driver must
    # therefore be constructed with width=160, height=128, rotation=0, and
    # each pre-rendered landscape frame is sent as-is in a single
    # full-screen write, every pixel (background included) overwritten on
    # every update. (Configuring the common-sense-looking portrait 128x160
    # + rotation=90 instead writes only 128 of the 160 physical columns —
    # leaving an unfilled stripe — and overflows the 132-address row
    # register, mangling the image.) Set rotation=180 in a profile if the
    # image is upside down for the chosen mounting — the driver still
    # rotates the frame in software for that value; dimensions stay
    # unchanged.
    #
    # "sw_per_frame" — the controller's native scan order is left alone and
    # the library's base Display.image() rotates each frame in software
    # before sending it, per the rotation value passed to the driver.
    rotation_mechanism: str = "init_table"
    # Optional MADCTL (0x36) byte written straight after construction, for
    # panels whose driver hardcodes a portrait init table. The frame path
    # packs RGB565 itself and writes one full-screen window through
    # _block(), bypassing the library's Display.image() — so the library's
    # software rotation never runs and the controller's own scan order is
    # the only thing that can put the panel in landscape. None leaves the
    # driver's init table untouched.
    madctl: int | None = None
    # How a resistive touch sheet's native axes map onto this panel as it is
    # actually scanned. A touch controller is wired to the sheet, not to the
    # display controller, so nothing about madctl or rotation reaches it —
    # a panel put into landscape by its scan order still reports portrait
    # touch axes, and the mapping has to be stated here per profile.
    # Applied to normalised coordinates: swap first, then invert.
    touch_swap_xy: bool = False
    touch_invert_x: bool = False
    touch_invert_y: bool = False
    baudrate: int = 16_000_000
    # RESERVED for a future touch panel: controller tag + bus type. Not
    # constructed or read anywhere yet — see the module docstring doctrine.
    touch: object = None


class UnknownDisplayProfileError(KeyError):
    """Raised by get_profile() for a key not present in DISPLAY_PROFILES."""


# Ordered table: key -> profile. The first entry is today's shipped panel and
# must reproduce its current behaviour exactly.
DISPLAY_PROFILES: dict[str, DisplayProfile] = {
    # Today's shipped panel. Visible area starts at GRAM 0,0 — no
    # green-tab-style offsets (confirmed on hardware: non-zero offsets shift
    # the image on this panel).
    "st7735s_160x128": DisplayProfile(
        key="st7735s_160x128",
        label="ST7735S (128x160)",
        driver_tag="st7735s",
        width=160,
        height=128,
        x_offset=0,
        y_offset=0,
        rotation=0,
        rotation_mechanism="init_table",
        baudrate=16_000_000,
    ),
    # Untested on hardware — nominal values for a 128x128 ST7735S variant.
    "st7735s_128x128": DisplayProfile(
        key="st7735s_128x128",
        label="ST7735S (128x128)",
        driver_tag="st7735s",
        width=128,
        height=128,
        x_offset=0,
        y_offset=0,
        rotation=0,
        rotation_mechanism="init_table",
        baudrate=16_000_000,
    ),
    # Untested on hardware — nominal values. Many 240x240 ST7789 boards are
    # built on 240x320 GRAM and need y_offset=80 to reach the visible area;
    # shipping 0 here until a real panel confirms the offset.
    "st7789_240x240": DisplayProfile(
        key="st7789_240x240",
        label="ST7789 (240x240)",
        driver_tag="st7789",
        width=240,
        height=240,
        x_offset=0,
        y_offset=0,
        rotation=0,
        rotation_mechanism="sw_per_frame",
        baudrate=32_000_000,
    ),
    # Untested on hardware — nominal values for a 240x320 ST7789 panel used
    # in its 320x240 landscape orientation.
    "st7789_320x240": DisplayProfile(
        key="st7789_320x240",
        label="ST7789 (240x320)",
        driver_tag="st7789",
        width=320,
        height=240,
        x_offset=0,
        y_offset=0,
        rotation=0,
        rotation_mechanism="sw_per_frame",
        baudrate=32_000_000,
    ),
    # The panel is natively portrait: the pinned library hardcodes
    # MADCTL=0x48 (MX|BGR, no row/column exchange) in its init table and
    # defaults to width=240, height=320. Declaring 320x240 against that
    # scan order addresses columns 0..319 on a controller whose column
    # register spans 0..239, which wraps every row and mangles the image.
    # madctl=0x28 sets MV (row/column exchange) and keeps BGR, so the
    # controller scans landscape and a full-screen 320x240 window is valid.
    # Use the rotate toggle if the chosen mounting wants the other way up.
    "ili9341_320x240": DisplayProfile(
        key="ili9341_320x240",
        label="ILI9341 (320x240)",
        driver_tag="ili9341",
        width=320,
        height=240,
        x_offset=0,
        y_offset=0,
        rotation=0,
        rotation_mechanism="init_table",
        madctl=0x28,
        # madctl=0x28 sets MV, so the display scans with rows and columns
        # exchanged while the touch sheet keeps its native axes — hence the
        # swap. The inversion signs cannot be derived from the datasheet
        # (they depend on which edge the sheet's tails leave the glass on
        # this board); these were established against real hardware, with
        # the panel's 180-degree rotate setting on. They describe the
        # UNROTATED panel — dial_main XORs the rotate setting in.
        touch_swap_xy=True,
        touch_invert_x=True,
        touch_invert_y=True,
        baudrate=32_000_000,
    ),
}

DEFAULT_PROFILE_KEY = "st7735s_160x128"


def get_profile(key: str) -> DisplayProfile:
    """Look up a profile by key, raising UnknownDisplayProfileError if absent.

    The caller decides how to surface the error (e.g. fall back to the
    default profile, or reject a config write) — this helper only performs
    the lookup.
    """
    try:
        return DISPLAY_PROFILES[key]
    except KeyError:
        raise UnknownDisplayProfileError(key) from None


def list_profiles() -> list[dict]:
    """Return the published catalogue as [{"key", "text"}, ...] for the API."""
    return [{"key": p.key, "text": p.label} for p in DISPLAY_PROFILES.values()]


def backend_name_for(profile: DisplayProfile) -> str:
    """Derive the backend's reported name from its driver tag.

    The default profile must still report "adafruit_st7735s" — the name the
    backend has always used.
    """
    return f"adafruit_{profile.driver_tag}"
