"""dial_config.py — Dial configuration loading and saving.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Two-file split:
  /etc/autostream/autostream-dial.json    — hardware + UUID, root:autostream 0640
  /var/lib/autostream/dial-settings.json — mutable settings, autostream 0600
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path

# dial_display_profiles.py is pure data (no hardware imports) — see its module
# docstring for why that must never change. Importing it here is therefore
# safe even though dial_config is imported unconditionally at process start,
# before the display stack gets a chance to isolate a broken Adafruit install.
from dial_display_profiles import DEFAULT_PROFILE_KEY, DISPLAY_PROFILES

# dial_touch_controllers.py is likewise pure data (no hardware imports) — see
# its module docstring for the same argument as dial_display_profiles above.
# Importing it here is safe and preserves the invariant that dial_config never
# pulls in hardware.
from dial_touch_controllers import DEFAULT_TOUCH_KEY, TOUCH_CONTROLLERS

HW_CONFIG_PATH     = Path('/etc/autostream/autostream-dial.json')
SETTINGS_PATH      = Path('/var/lib/autostream/dial-settings.json')
INSTALL_STATE_PATH = Path('/var/lib/autostream/install-state.env')

# Unclean-shutdown signal (see dial_main.py's running-marker lifecycle):
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

# PIN-recovery arm request (see dial_main.py's startup arming decision):
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


@dataclass
class DialConfig:
    clk_gpio:       int | None = 17
    dt_gpio:        int | None = 27
    sw_gpio:        int | None = 22
    led_gpio:       int | None = None
    port:           int        = 7842
    uuid:           str        = ''
    step_percent:   int        = 2
    name:           str        = ''
    pin:            str        = ''
    auto_update:    bool       = False
    update_channel: str        = 'stable'
    mute_all_playing: bool     = False
    display:        DialDisplayConfig = field(default_factory=DialDisplayConfig)


class InvalidScreenSettings(ValueError):
    """Raised by validate_screen_settings() for a malformed screen settings object."""


def validate_screen_settings(obj: object) -> DialDisplayConfig:
    """Validate a complete API-supplied `screen` settings object.

    Strict: `fitted` must be a JSON boolean (not 0/1/"true"), the object must be
    a dict containing only known fields, and `fitted` may not be missing or
    unrecognised fields present. `rotate` and `bgr` are optional (default to
    False) so older webuis that omit them still validate, but if present they
    must also be strict JSON booleans. `screen_type` is optional (defaults to
    DEFAULT_PROFILE_KEY); if present it must be a string naming a known
    profile — an unknown value is a hard InvalidScreenSettings error rather
    than a silent fallback, since silently coercing a wrong driver choice to
    the default would mask the very mistake this validation exists to catch.
    `touch_type` is optional (defaults to DEFAULT_TOUCH_KEY, i.e. "none") and
    follows the exact same rule: if present it must be a string naming a
    known controller in TOUCH_CONTROLLERS, otherwise InvalidScreenSettings.
    `always_show_controls` is optional (defaults to False), same rule as
    `rotate` and `bgr`: if present it must be a strict JSON boolean. This is
    what keeps an old appliance's whole-object POST (which never sends the
    field at all) from 400ing, and a new appliance never sends it to a dial
    whose GET response did not advertise it in the first place.
    `screen_size_inches` is optional (defaults to None, meaning "use the
    selected profile's own default"); if present it must be a JSON number
    (int or float, not bool) between 0.5 and 20 inches, or JSON null — a
    range wide enough for every SPI panel plausibly wired to this dial while
    still catching an obvious typo.
    Raises InvalidScreenSettings on any violation.
    """
    if not isinstance(obj, dict):
        raise InvalidScreenSettings("screen must be an object")
    unknown = set(obj.keys()) - {
        "fitted", "rotate", "screen_type", "bgr", "touch_type", "always_show_controls",
        "screen_size_inches",
    }
    if unknown:
        raise InvalidScreenSettings(f"unknown screen fields: {sorted(unknown)}")
    if "fitted" not in obj:
        raise InvalidScreenSettings("screen.fitted is required")
    fitted = obj["fitted"]
    if not isinstance(fitted, bool):
        raise InvalidScreenSettings("screen.fitted must be a boolean")
    rotate = obj.get("rotate", False)
    if not isinstance(rotate, bool):
        raise InvalidScreenSettings("screen.rotate must be a boolean")
    bgr = obj.get("bgr", False)
    if not isinstance(bgr, bool):
        raise InvalidScreenSettings("screen.bgr must be a boolean")
    screen_type = obj.get("screen_type", DEFAULT_PROFILE_KEY)
    if not isinstance(screen_type, str):
        raise InvalidScreenSettings("screen.screen_type must be a string")
    if screen_type not in DISPLAY_PROFILES:
        raise InvalidScreenSettings(f"unknown screen.screen_type: {screen_type!r}")
    touch_type = obj.get("touch_type", DEFAULT_TOUCH_KEY)
    if not isinstance(touch_type, str):
        raise InvalidScreenSettings("screen.touch_type must be a string")
    if touch_type not in TOUCH_CONTROLLERS:
        raise InvalidScreenSettings(f"unknown screen.touch_type: {touch_type!r}")
    always_show_controls = obj.get("always_show_controls", False)
    if not isinstance(always_show_controls, bool):
        raise InvalidScreenSettings("screen.always_show_controls must be a boolean")
    screen_size_inches = obj.get("screen_size_inches")
    if screen_size_inches is not None:
        if (
            isinstance(screen_size_inches, bool)
            or not isinstance(screen_size_inches, (int, float))
            or not (0.5 <= screen_size_inches <= 20.0)
        ):
            raise InvalidScreenSettings(
                "screen.screen_size_inches must be a number between 0.5 and 20, or null"
            )
        screen_size_inches = float(screen_size_inches)
    return DialDisplayConfig(
        fitted=fitted, rotate=rotate, screen_type=screen_type, bgr=bgr,
        touch_type=touch_type, always_show_controls=always_show_controls,
        screen_size_inches=screen_size_inches,
    )


def _resolve_persisted_screen_type(value: object) -> str:
    """Resolve a persisted screen_type value, falling back to the default
    profile with a warning log rather than raising.

    A corrupt or stale settings file (e.g. after a profile is renamed/removed
    across an upgrade) must not brick the dial at startup — only the strict
    API-facing validate_screen_settings() is allowed to reject an unknown
    profile outright.
    """
    if isinstance(value, str) and value in DISPLAY_PROFILES:
        return value
    if value is not None:
        logging.warning(
            "dial config: unknown persisted screen_type %r — falling back to %s",
            value, DEFAULT_PROFILE_KEY,
        )
    return DEFAULT_PROFILE_KEY


def _resolve_persisted_touch_type(value: object) -> str:
    """Resolve a persisted touch_type value, falling back to the default
    controller ("none") with a warning log rather than raising.

    Mirrors _resolve_persisted_screen_type: a corrupt or stale settings file
    must not brick the dial at startup — only the strict API-facing
    validate_screen_settings() is allowed to reject an unknown controller
    outright.
    """
    if isinstance(value, str) and value in TOUCH_CONTROLLERS:
        return value
    if value is not None:
        logging.warning(
            "dial config: unknown persisted touch_type %r — falling back to %s",
            value, DEFAULT_TOUCH_KEY,
        )
    return DEFAULT_TOUCH_KEY


def _resolve_persisted_screen_size(value: object) -> float | None:
    """Resolve a persisted screen_size_inches value, falling back to None
    (meaning "use the selected profile's own default") with a warning log
    for anything unusable, rather than raising.

    Mirrors _resolve_persisted_screen_type/_resolve_persisted_touch_type: a
    corrupt or stale settings file must not brick the dial at startup — only
    the strict API-facing validate_screen_settings() is allowed to reject an
    out-of-range value outright. Missing or JSON null both silently mean
    None — that is the ordinary "never overridden" state, not corruption.
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not (0.5 <= value <= 20.0):
        logging.warning(
            "dial config: unusable persisted screen_size_inches %r — falling back to the "
            "profile default", value,
        )
        return None
    return float(value)


def _read_env_file(path: Path) -> dict[str, str]:
    """Parse a KEY=VALUE env file without executing it."""
    data: dict[str, str] = {}
    try:
        for raw in path.read_text(encoding='utf-8').splitlines():
            line = raw.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            k, _, v = line.partition('=')
            k = k.strip()
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
                v = v[1:-1]
            data[k] = v
    except OSError:
        pass
    return data


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
    cfg.uuid      = hw.get('uuid', '')

    hw_display = hw.get('display')
    if isinstance(hw_display, dict):
        cfg.display = DialDisplayConfig(
            fitted=bool(hw_display.get('fitted', False)),
            rotate=bool(hw_display.get('rotate', False)),
            screen_type=_resolve_persisted_screen_type(hw_display.get('screen_type')),
            bgr=bool(hw_display.get('bgr', False)),
            touch_type=_resolve_persisted_touch_type(hw_display.get('touch_type')),
            always_show_controls=bool(hw_display.get('always_show_controls', False)),
            screen_size_inches=_resolve_persisted_screen_size(hw_display.get('screen_size_inches')),
        )

    if SETTINGS_PATH.exists():
        s = json.loads(SETTINGS_PATH.read_text(encoding='utf-8'))
        cfg.step_percent   = s.get('step_percent',   cfg.step_percent)
        cfg.name           = s.get('name',           cfg.name)
        cfg.pin            = s.get('pin',            cfg.pin)
        cfg.auto_update    = s.get('auto_update',    cfg.auto_update)
        cfg.update_channel = _normalise_dial_channel(s.get('update_channel', cfg.update_channel))
        cfg.mute_all_playing = bool(s.get('mute_all_playing', cfg.mute_all_playing))
        s_display = s.get('display')
        if isinstance(s_display, dict):
            cfg.display = DialDisplayConfig(
                fitted=bool(s_display.get('fitted', cfg.display.fitted)),
                rotate=bool(s_display.get('rotate', cfg.display.rotate)),
                screen_type=_resolve_persisted_screen_type(
                    s_display.get('screen_type', cfg.display.screen_type)
                ),
                bgr=bool(s_display.get('bgr', cfg.display.bgr)),
                touch_type=_resolve_persisted_touch_type(
                    s_display.get('touch_type', cfg.display.touch_type)
                ),
                always_show_controls=bool(
                    s_display.get('always_show_controls', cfg.display.always_show_controls)
                ),
                screen_size_inches=_resolve_persisted_screen_size(
                    s_display.get('screen_size_inches', cfg.display.screen_size_inches)
                ),
            )

    if not cfg.uuid:
        state = _read_env_file(INSTALL_STATE_PATH)
        cfg.uuid = state.get('DIAL_UUID', '')

    if not cfg.uuid:
        raise RuntimeError(
            "No UUID in dial.json or install-state.env — reinstall required."
        )

    return cfg


_save_lock = threading.Lock()


def save_config(cfg: DialConfig) -> None:
    """Write runtime-mutable fields to dial-settings.json atomically.

    Never writes hardware config or UUID.  Uses mkstemp so concurrent calls
    each get a unique temp file; chmod 0600 before any data is written.
    """
    data = {
        'step_percent':   cfg.step_percent,
        'name':           cfg.name,
        'pin':            cfg.pin,
        'auto_update':    cfg.auto_update,
        'update_channel': cfg.update_channel,
        'mute_all_playing': cfg.mute_all_playing,
        'display':        {
            'fitted':      cfg.display.fitted,
            'rotate':      cfg.display.rotate,
            'screen_type': cfg.display.screen_type,
            'bgr':         cfg.display.bgr,
            'touch_type':  cfg.display.touch_type,
            'always_show_controls': cfg.display.always_show_controls,
            'screen_size_inches': cfg.display.screen_size_inches,
        },
    }
    with _save_lock:
        fd, tmp_path = tempfile.mkstemp(dir=SETTINGS_PATH.parent, suffix='.tmp')
        try:
            os.chmod(tmp_path, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            Path(tmp_path).replace(SETTINGS_PATH)
        except:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
