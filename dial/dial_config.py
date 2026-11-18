"""dial_config.py — Dial configuration loading and saving.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Two-file split:
  /etc/autostream/autostream-dial.json    — hardware + UUID, root:autostream 0640
  /var/lib/autostream/dial-settings.json — mutable settings, autostream 0600
"""
from __future__ import annotations

import json
import logging
import threading
from typing import Callable
from dataclasses import dataclass, field, replace
from dataclasses import fields as dataclass_fields
from pathlib import Path

import autostream_sysutils

# dial_display_profiles.py is pure data (no hardware imports) — see its module
# docstring for why that must never change. Importing it here is therefore
# safe even though dial_config is imported unconditionally at process start,
# before the display stack gets a chance to isolate a broken Adafruit install.
from dial_display_profiles import DEFAULT_PROFILE_KEY, DISPLAY_PROFILES, LAYOUT_SIZES, layout_sizes_for

# dial_touch_controllers.py is likewise pure data (no hardware imports) — see
# its module docstring for the same argument as dial_display_profiles above.
# Importing it here is safe and preserves the invariant that dial_config never
# pulls in hardware.
from dial_touch_controllers import DEFAULT_TOUCH_KEY, TOUCH_CONTROLLERS
from dial_values import is_int, read_env_file

HW_CONFIG_PATH     = Path('/etc/autostream/autostream-dial.json')
SETTINGS_PATH      = Path('/var/lib/autostream/dial-settings.json')
INSTALL_STATE_PATH = Path('/var/lib/autostream/install-state.env')

# Unclean-shutdown signal (see dial_recovery.py's running-marker lifecycle):
# created at every service start, deleted on clean shutdown. Its survival at
# the next startup is evidence the previous stop was NOT clean (power loss,
# or the process was killed).
#
# This MUST live on real disk, alongside SETTINGS_PATH above — NOT in /run
# or any other tmpfs. /run is cleared at every boot, so a marker there would
# always be absent at startup: power cycles would never be detected, and any
# feature armed off that signal would never arm. That would be a silent,
# total failure, not a partial degradation.
RUNNING_MARKER_PATH = Path('/var/lib/autostream/running.txt')

# PIN-recovery arm request (see dial_recovery.py's startup arming decision):
# written by the dial's unauthenticated arm endpoint when an admin requests
# recovery, deleted by the disarm endpoint or once consumed at the next
# startup. Its mtime is the request time, used to expire stale requests.
#
# Same placement rule as RUNNING_MARKER_PATH above and for the same reason:
# this MUST live on real disk, not /run. A tmpfs copy would vanish at every
# reboot, and a power cycle is exactly the event this file is meant to
# survive across — losing it there would silently defeat the feature.
PIN_RESET_PATH = Path('/var/lib/autostream/pin_reset.txt')


def _normalise_dial_channel(value: object) -> str:
    """Return 'dev' only when *value* normalises to 'dev'; otherwise 'stable'."""
    return "dev" if str(value or "").strip().lower() == "dev" else "stable"


# Which appliances a volume twist / a mute push address: the bound appliance
# ("current") or every playing appliance ("all"). See effective_scope() below
# for how the "current" choice is overridden while no screen is fitted.
SCOPE_CURRENT = "current"
SCOPE_ALL = "all"
SCOPES = (SCOPE_CURRENT, SCOPE_ALL)

# How often the dial's poll loop asks the appliances for their state, in
# whole seconds. Faster means a quicker reaction to a new track or a
# start/stop, at the cost of more traffic. The default matches
# dial_display.DISPLAY_POLL_INTERVAL_SECONDS.
POLL_INTERVAL_MIN_S = 2
POLL_INTERVAL_MAX_S = 6
POLL_INTERVAL_DEFAULT_S = 6

# Seconds of idleness before an HD panel sleeps (0 = never), and the panel
# brightness percentage while awake. Only an HD (kiosk) surface acts on them;
# they are stored and reported for every surface. panel_power_off says whether
# a sleeping HDMI panel is also powered down over its control channel. It is
# off by default because some panels are left with image retention after being
# powered down that way, so the default is to dim the backlight and leave the
# panel powered.
SLEEP_AFTER_CHOICES_S = (0, 60, 300, 900)
SLEEP_AFTER_DEFAULT_S = 300
BRIGHTNESS_MIN = 5
BRIGHTNESS_MAX = 100
BRIGHTNESS_DEFAULT = 80

# The loopback port the HD page is served on; the hardware config file may
# override it with hd_port.
HD_PORT_DEFAULT = 7843


@dataclass
class DialDisplayConfig:
    """Screen settings for the dial's display.

    `touch_type` is deliberately colocated here rather than split into its own
    config section: it is part of the screen assembly (the touch panel and the
    LCD share the same physical unit and the same webui "Screen" settings
    section), so it shares one save path and one validation path with the
    other screen fields. Do not "fix" this later by pulling it out.

    `always_show_controls` is colocated for the same reason: it only makes
    sense with a screen (there is nothing to hold visible without one), and
    it shares the screen save path — see validate_screen_settings() and the
    "Always show controls" design notes for the held-visible behaviour it
    drives in dial_display.py/dial_touch.py.

    `volume_scope`/`mute_scope` are colocated for the same reason again: the
    choice only exists because a screen may or may not be there (a dial with
    no screen, or one too small to select an appliance, cannot choose which
    appliance a twist/push addresses, so it must address every playing one),
    and it shares the screen save/validate path, which is also where
    `fitted` — the one input to the effective rule below — lives.
    """
    fitted: bool = False
    rotate: bool = False
    screen_type: str = DEFAULT_PROFILE_KEY
    bgr: bool = False
    touch_type: str = DEFAULT_TOUCH_KEY
    always_show_controls: bool = False
    # Screen diagonal in inches, or None to use the selected profile's own
    # built-in default (dial_display_profiles.DisplayProfile.
    # default_diagonal_inches). A user override, since the same controller
    # and resolution ship in several physical sizes. See
    # dial_display_profiles.effective_diagonal_inches().
    screen_size_inches: float | None = None
    # Logical render size, or None to render at the panel's own resolution
    # (today's behaviour). One of dial_display_profiles.LAYOUT_SIZES' keys;
    # the frame is composed at that size and resampled to the panel, and
    # touch is mapped the other way. See layout_context_for().
    layout_size: str | None = None
    # Which appliances a volume twist addresses while the screen is enabled:
    # the bound appliance ("current") or every playing appliance ("all").
    # See effective_scope() below for what happens while the screen is not
    # enabled.
    volume_scope: str = SCOPE_CURRENT
    # Same choice, for a mute push.
    mute_scope: str = SCOPE_CURRENT
    # Seconds between poll ticks, POLL_INTERVAL_MIN_S..POLL_INTERVAL_MAX_S.
    poll_interval_s: int = POLL_INTERVAL_DEFAULT_S
    # HD surface only: idle seconds before the panel sleeps (one of
    # SLEEP_AFTER_CHOICES_S, 0 = never) and the awake brightness percentage.
    sleep_after_s: int = SLEEP_AFTER_DEFAULT_S
    brightness: int = BRIGHTNESS_DEFAULT
    # HD surface only: power an HDMI panel down while asleep (see above).
    panel_power_off: bool = False


def effective_scope(display: "DialDisplayConfig", stored: str) -> str:
    """The scope a dial actually acts on: *stored* while a screen is fitted,
    else always SCOPE_ALL — a screenless dial (or one too small to select an
    appliance) cannot choose which appliance to address, so it addresses
    every playing one regardless of what was last saved. Pure; no locks, no
    I/O."""
    return stored if display.fitted else SCOPE_ALL


@dataclass
class DialConfig:
    clk_gpio:       int | None = 17
    dt_gpio:        int | None = 27
    sw_gpio:        int | None = 22
    led_gpio:       int | None = None
    port:           int        = 7842
    hd_port:        int        = HD_PORT_DEFAULT
    uuid:           str        = ''
    step_percent:   int        = 2
    name:           str        = ''
    pin:            str        = ''
    auto_update:    bool       = False
    update_channel: str        = 'stable'
    # Whether the user asked for SD card health monitoring. Intent only: the
    # scheduled timer is the truth, and the wrapper can switch it off on its
    # own after a hung probe. Reported alongside the live state so the card
    # can show "requested but off" without guessing.
    sd_health_monitoring: bool = False
    # Whether the HD page is also served on a LAN listener for development.
    # Off by default; only settable through the PIN-gated /configure.
    hd_dev_access: bool = False
    display:        DialDisplayConfig = field(default_factory=DialDisplayConfig)


class InvalidScreenSettings(ValueError):
    """Raised by validate_screen_settings() for a malformed screen settings object."""


def _same(value):
    return value


@dataclass(frozen=True)
class _ScreenField:
    """One screen setting: how the strict API check and the lenient file load
    both treat it."""
    name: str
    default: object
    # The strict rule: an error text for a value that breaks it, else None.
    # The second argument is the screen_type resolved before this field.
    check: Callable[[object, str], "str | None"]
    nullable: bool = False        # JSON null is accepted and means None
    required: bool = False        # the strict check refuses an object without it
    convert: Callable[[object], object] = _same   # applied to an accepted value
    coerce_on_load: bool = False  # the lenient load takes bool(value), no check
    carried: bool = False         # kept from the current config when a POST omits it


def _check_bool(name: str):
    def check(value, screen_type):
        if not isinstance(value, bool):
            return f"screen.{name} must be a boolean"
        return None
    return check


def _check_screen_type(value, screen_type):
    if not isinstance(value, str):
        return "screen.screen_type must be a string"
    if value not in DISPLAY_PROFILES:
        return f"unknown screen.screen_type: {value!r}"
    return None


def _check_touch_type(value, screen_type):
    if not isinstance(value, str):
        return "screen.touch_type must be a string"
    if value not in TOUCH_CONTROLLERS:
        return f"unknown screen.touch_type: {value!r}"
    return None


def _check_screen_size(value, screen_type):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not (0.5 <= value <= 20.0):
        return "screen.screen_size_inches must be a number between 0.5 and 20, or null"
    return None


def _check_layout_size(value, screen_type):
    if not isinstance(value, str) or value not in LAYOUT_SIZES:
        return f"screen.layout_size must be one of {sorted(LAYOUT_SIZES)} or null"
    if value not in layout_sizes_for(DISPLAY_PROFILES[screen_type]):
        return f"screen.layout_size {value!r} is not available for screen_type {screen_type!r}"
    return None


def _check_scope(name: str):
    def check(value, screen_type):
        if not isinstance(value, str) or value not in SCOPES:
            return f"screen.{name} must be one of {list(SCOPES)}"
        return None
    return check


def _check_poll_interval(value, screen_type):
    if not is_int(value) or not (POLL_INTERVAL_MIN_S <= value <= POLL_INTERVAL_MAX_S):
        return (
            f"screen.poll_interval_s must be a whole number of seconds from "
            f"{POLL_INTERVAL_MIN_S} to {POLL_INTERVAL_MAX_S}"
        )
    return None


def _check_sleep_after(value, screen_type):
    if not is_int(value) or value not in SLEEP_AFTER_CHOICES_S:
        return f"screen.sleep_after_s must be one of {list(SLEEP_AFTER_CHOICES_S)}"
    return None


def _check_brightness(value, screen_type):
    if not is_int(value) or not (BRIGHTNESS_MIN <= value <= BRIGHTNESS_MAX):
        return f"screen.brightness must be a whole number from {BRIGHTNESS_MIN} to {BRIGHTNESS_MAX}"
    return None


_DEFAULTS = DialDisplayConfig()


def _field(name: str, check, **flags) -> _ScreenField:
    return _ScreenField(name, getattr(_DEFAULTS, name), check, **flags)


# Every screen setting, in the order the strict check runs. The rules:
# - fitted is required; the booleans (rotate, bgr, always_show_controls) are
#   optional and must be JSON booleans when present, which keeps an older
#   web UI's whole-object POST (it never sends the newer ones) valid.
# - screen_type and touch_type are strings naming a known profile or
#   controller. An unknown one is a hard error rather than a silent fallback,
#   since silently coercing a wrong driver choice would hide the mistake this
#   check exists to catch.
# - screen_size_inches is a number from 0.5 to 20 or null (the profile's own
#   size).
# - layout_size is null (the panel's own resolution) or a key of LAYOUT_SIZES
#   that the selected screen_type offers.
# - volume_scope and mute_scope are one of SCOPES.
# - poll_interval_s, sleep_after_s and brightness are JSON integers in their
#   ranges; panel_power_off is a JSON boolean. These four are carried: a POST
#   that omits them keeps the configured values.
_SCREEN_FIELDS = (
    _field("fitted", _check_bool("fitted"), required=True, coerce_on_load=True),
    _field("rotate", _check_bool("rotate"), coerce_on_load=True),
    _field("bgr", _check_bool("bgr"), coerce_on_load=True),
    _field("screen_type", _check_screen_type),
    _field("touch_type", _check_touch_type),
    _field("always_show_controls", _check_bool("always_show_controls"), coerce_on_load=True),
    _field("screen_size_inches", _check_screen_size, nullable=True, convert=float),
    _field("layout_size", _check_layout_size, nullable=True),
    _field("volume_scope", _check_scope("volume_scope")),
    _field("mute_scope", _check_scope("mute_scope")),
    _field("poll_interval_s", _check_poll_interval, carried=True),
    _field("sleep_after_s", _check_sleep_after, carried=True),
    _field("brightness", _check_brightness, carried=True),
    _field("panel_power_off", _check_bool("panel_power_off"), carried=True),
)
_FIELD_BY_NAME = {f.name: f for f in _SCREEN_FIELDS}

# The settings a POST that omits them leaves as configured.
CARRIED_SCREEN_FIELDS = tuple(f.name for f in _SCREEN_FIELDS if f.carried)


def validate_screen_settings(obj: object) -> DialDisplayConfig:
    """Validate a complete API-supplied `screen` settings object.

    Strict: the object must be a dict holding only known fields, `fitted` must
    be present, and every field present must satisfy its rule in the table
    above (JSON types are exact: 0/1 or "true" is not a boolean). A field left
    out takes its default, so an older web UI's POST still validates.
    Raises InvalidScreenSettings on any violation.
    """
    if not isinstance(obj, dict):
        raise InvalidScreenSettings("screen must be an object")
    unknown = set(obj.keys()) - set(_FIELD_BY_NAME)
    if unknown:
        raise InvalidScreenSettings(f"unknown screen fields: {sorted(unknown)}")
    resolved: dict[str, object] = {}
    for f in _SCREEN_FIELDS:
        if f.required and f.name not in obj:
            raise InvalidScreenSettings(f"screen.{f.name} is required")
        value = obj.get(f.name, f.default)
        if value is None and f.nullable:
            resolved[f.name] = None
            continue
        error = f.check(value, resolved.get("screen_type", DEFAULT_PROFILE_KEY))
        if error is not None:
            raise InvalidScreenSettings(error)
        resolved[f.name] = f.convert(value)
    return DialDisplayConfig(**resolved)


def display_settings(display: DialDisplayConfig) -> dict:
    """The screen settings as a plain dict: what is saved and what the
    screen-settings replies report."""
    return {f.name: getattr(display, f.name) for f in dataclass_fields(display)}


def _resolve_persisted(name: str, value: object, *, screen_type: str) -> object:
    """Resolve a persisted value for screen setting *name*, falling back to
    its default with a warning log rather than raising.

    A corrupt or stale file (a profile renamed or removed across an upgrade,
    a screen_type swap that no longer offers a layout size) must not brick the
    dial at startup: only the strict API-facing validate_screen_settings() may
    reject a value outright. A missing or null value silently means the
    default, which is the ordinary "never overridden" state; the booleans that
    gate the screen are read as plain truthiness.
    """
    f = _FIELD_BY_NAME[name]
    if f.coerce_on_load:
        return bool(value)
    if value is None:
        return f.default
    error = f.check(value, screen_type)
    if error is None:
        return f.convert(value)
    logging.warning(
        "dial config: unusable persisted %s %r (%s), using %r", name, value, error, f.default,
    )
    return f.default


def _load_display(block: dict, base: DialDisplayConfig) -> DialDisplayConfig:
    """The display config in a hardware or settings file block, each missing
    setting taken from *base* and each unusable one from its default."""
    resolved: dict[str, object] = {}
    for f in _SCREEN_FIELDS:
        resolved[f.name] = _resolve_persisted(
            f.name, block.get(f.name, getattr(base, f.name)),
            screen_type=resolved.get("screen_type", base.screen_type),
        )
    return DialDisplayConfig(**resolved)


def _resolve_hd_port(value: object) -> int:
    """Resolve the hardware file's hd_port, falling back to HD_PORT_DEFAULT for
    anything that is not a usable unprivileged port. Missing (None) silently
    means the default."""
    if value is None:
        return HD_PORT_DEFAULT
    if is_int(value) and 1024 <= value <= 65535:
        return value
    logging.warning("dial config: unusable hd_port %r — falling back to %d", value, HD_PORT_DEFAULT)
    return HD_PORT_DEFAULT


def load_config() -> DialConfig:
    """Load hardware config then overlay mutable settings.

    UUID fallback order: dial.json → install-state.env → RuntimeError.
    Never silently generates a new UUID.
    """
    cfg = DialConfig()

    hw = json.loads(HW_CONFIG_PATH.read_text(encoding='utf-8'))
    cfg.clk_gpio  = hw.get('clk_gpio', cfg.clk_gpio)
    cfg.dt_gpio   = hw.get('dt_gpio',  cfg.dt_gpio)
    cfg.sw_gpio   = hw.get('sw_gpio', cfg.sw_gpio)
    cfg.led_gpio  = hw.get('led_gpio')
    cfg.port      = hw.get('port', cfg.port)
    cfg.hd_port   = _resolve_hd_port(hw.get('hd_port'))
    cfg.uuid      = hw.get('uuid', '')

    hw_display = hw.get('display')
    if isinstance(hw_display, dict):
        cfg.display = _load_display(hw_display, cfg.display)

    if SETTINGS_PATH.exists():
        s = json.loads(SETTINGS_PATH.read_text(encoding='utf-8'))
        cfg.step_percent   = s.get('step_percent',   cfg.step_percent)
        cfg.name           = s.get('name',           cfg.name)
        cfg.pin            = s.get('pin',            cfg.pin)
        cfg.auto_update    = s.get('auto_update',    cfg.auto_update)
        cfg.update_channel = _normalise_dial_channel(s.get('update_channel', cfg.update_channel))
        cfg.sd_health_monitoring = bool(s.get('sd_health_monitoring', False))
        cfg.hd_dev_access  = bool(s.get('hd_dev_access', False))
        # A persisted mute_all_playing (retired — see DialDisplayConfig's
        # mute_scope) is migrated onto mute_scope ONCE below, only when the
        # settings file has no display.mute_scope key yet; the legacy key
        # itself is never written again by save_config.
        legacy_mute_all_playing = bool(s.get('mute_all_playing', False))
        s_display = s.get('display')
        if isinstance(s_display, dict):
            display = _load_display(s_display, cfg.display)
            if 'mute_scope' not in s_display and legacy_mute_all_playing:
                display = replace(display, mute_scope=SCOPE_ALL)
            cfg.display = display
        elif legacy_mute_all_playing:
            # No display block at all in this settings file, but the legacy
            # top-level flag is present — migrate it onto the hw-overlay-
            # resolved display config the same way as the dict branch above.
            cfg.display = replace(cfg.display, mute_scope=SCOPE_ALL)

    if not cfg.uuid:
        state = read_env_file(INSTALL_STATE_PATH)
        cfg.uuid = state.get('DIAL_UUID', '')

    if not cfg.uuid:
        raise RuntimeError(
            "No UUID in dial.json or install-state.env — reinstall required."
        )

    return cfg


_save_lock = threading.Lock()


def save_config(cfg: DialConfig) -> None:
    """Write runtime-mutable fields to dial-settings.json atomically.

    Never writes hardware config or UUID.  The shared atomic writer gives each
    call a unique temp file and sets mode 0600 before any data is written.
    """
    data = {
        'step_percent':   cfg.step_percent,
        'name':           cfg.name,
        'pin':            cfg.pin,
        'auto_update':    cfg.auto_update,
        'update_channel': cfg.update_channel,
        'sd_health_monitoring': cfg.sd_health_monitoring,
        'hd_dev_access':  cfg.hd_dev_access,
        'display':        display_settings(cfg.display),
    }
    with _save_lock:
        autostream_sysutils.atomic_write_file(
            SETTINGS_PATH, lambda f: json.dump(data, f, indent=2), mode=0o600,
        )
