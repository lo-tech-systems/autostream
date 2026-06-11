#!/usr/bin/env python3
"""
autostream_config.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Single source of truth for:
- loading the INI (ConfigParser)
- parsing / defaults / derived values

--

Configuration file example (INI):

[general]
log_file = /var/log/autostream/autostream.log
log_level = info               ; fatal, log, warning, info, debug, spam
fifo_path = /tmp/autostream-pipes/autostream
silence_seconds = 30           ; length of time of continuous silence before stopping

[audio1]
capture_device = hw:1,0        ; ALSA hw identifier reported by autostream_monitor
silence_threshold = -66        ; dBFS threshold (e.g. -66 ~= 16/32767)
turntable = no                 ; set to yes to enable stylus-life tracking
stylus_life_hours = 500        ; reminder threshold for stylus replacement
gain_db = 0                    ; input gain before EQ
eq_40hz_db = 0                 ; sub-bass bell at 40 Hz (Q=0.707)
eq_100hz_db = 0                ; bass shelf at 100 Hz
eq_8khz_db = 0                 ; treble shelf at 8 kHz

[audio2]
enabled = no                   ; set to yes to enable this channel
capture_device = hw:2,0        ; ALSA hw identifier reported by autostream_monitor
silence_threshold = -66        ; dBFS threshold (e.g. -66 ~= 16/32767)
turntable = no                 ; set to yes to enable stylus-life tracking
stylus_life_hours = 500        ; reminder threshold for stylus replacement
gain_db = 0                    ; input gain before EQ
eq_40hz_db = 0                 ; sub-bass bell at 40 Hz (Q=0.707)
eq_100hz_db = 0                ; bass shelf at 100 Hz
eq_8khz_db = 0                 ; treble shelf at 8 kHz

[owntone]
base_url = http://localhost:3689
output_name = Kitchen Speaker
volume_percent = 20

[webui]
                               ; hidden_outputs are not shown on the volume control screen
hidden_outputs =
    Computer
    Dining Room
--
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json as _json
import logging
import os
from pathlib import Path
import re
import stat
import threading
import configparser
from datetime import datetime
from typing import Iterable, Optional, Tuple

DEFAULT_LOG_LEVEL = "info"
VALID_LOG_LEVELS = ("fatal", "log", "warning", "info", "debug", "spam")
DEFAULT_AIRPLAY_MODE = "default"
VALID_AIRPLAY_MODES = ("default", "raop", "airplay2")
DEFAULT_STYLUS_LIFE_HOURS = 0  # 0 = tracking disabled ("Don't track usage")
VALID_STYLUS_LIFE_HOURS = (100, 250, 500, 750, 1000)

# Maintenance tracking (drive belt, main bearing oil) — hours and elapsed-time options.
# 0 is the sentinel meaning "Don't track" for all maintenance thresholds.
VALID_MAINTENANCE_LIFE_HOURS = (0, 1000, 2000, 3000)        # drive belt
VALID_BEARING_LIFE_HOURS = (0, 200, 500, 1000, 2000)        # main bearing oil
VALID_MAINTENANCE_LIFE_YEARS = (0, 1, 2, 3, 4, 5)


def normalize_stylus_life_hours(
    value: object,
    default: int = DEFAULT_STYLUS_LIFE_HOURS,
) -> int:
    """Return a valid stylus-life value in hours, or 0 for tracking disabled.

    0 is the sentinel meaning 'Don't track usage'.  Positive values from
    VALID_STYLUS_LIFE_HOURS mean tracking is enabled with that rated life.
    Any unrecognised value falls back to *default*.
    """
    try:
        hours = int(str(value).strip())
    except Exception:
        return int(default)
    if hours == 0:
        return 0
    return hours if hours > 0 else int(default)


def _normalize_choice(value: object, valid_set: tuple, default: int = 0) -> int:
    """Coerce *value* to a member of *valid_set*, or return 0 / *default*.

    0 is always accepted as the 'Don't track' sentinel.  Any unrecognised
    positive integer falls back to *default* rather than being accepted.
    """
    try:
        v = int(str(value).strip())
    except Exception:
        return int(default)
    if v == 0:
        return 0
    return v if v in valid_set else int(default)


def normalize_maintenance_life_hours(value: object, default: int = 0) -> int:
    """Return a valid belt hours threshold, or 0 (tracking disabled)."""
    return _normalize_choice(value, VALID_MAINTENANCE_LIFE_HOURS, default)


def normalize_bearing_life_hours(value: object, default: int = 0) -> int:
    """Return a valid bearing hours threshold, or 0 (tracking disabled)."""
    return _normalize_choice(value, VALID_BEARING_LIFE_HOURS, default)


def normalize_maintenance_life_years(value: object, default: int = 0) -> int:
    """Return a valid elapsed-time threshold in years, or 0 (disabled)."""
    return _normalize_choice(value, VALID_MAINTENANCE_LIFE_YEARS, default)


_PYTHON_LOG_LEVELS = {
    "fatal": logging.CRITICAL,
    "log": logging.ERROR,
    "warning": logging.WARNING,
    "info": logging.INFO,
    "debug": logging.DEBUG,
    "spam": logging.DEBUG,
}

_OWNTONE_LOG_LEVELS = {
    "fatal": 0,
    "log": 1,
    "warning": 2,
    "info": 3,
    "debug": 4,
    "spam": 5,
}

# Inverse of _OWNTONE_LOG_LEVELS: OwnTone integer severity → platform level name.
OWNTONE_INT_TO_LOG_LEVEL: dict[int, str] = {v: k for k, v in _OWNTONE_LOG_LEVELS.items()}


CONFIG_IO_LOCK = threading.Lock()


def get_log_level_options() -> tuple[str, ...]:
    """Return the supported platform log-level names."""
    return VALID_LOG_LEVELS


def normalize_log_level(value: object, default: str = DEFAULT_LOG_LEVEL) -> str:
    """Return a supported platform log-level name."""
    text = str(value or "").strip().lower()
    if text in VALID_LOG_LEVELS:
        return text
    fallback = str(default or "").strip().lower()
    return fallback if fallback in VALID_LOG_LEVELS else DEFAULT_LOG_LEVEL


def python_log_level_value(level_name: object) -> int:
    """Map a platform log-level name to Python's logging constants."""
    return _PYTHON_LOG_LEVELS[normalize_log_level(level_name)]


def owntone_log_level_value(level_name: object) -> int:
    """Map a platform log-level name to OwnTone's integer runtime severity."""
    return _OWNTONE_LOG_LEVELS[normalize_log_level(level_name)]


def normalize_airplay_mode(
    value: object,
    default: str = DEFAULT_AIRPLAY_MODE,
) -> str:
    """Return a supported per-speaker AirPlay mode."""
    text = str(value or "").strip().lower()
    if text in VALID_AIRPLAY_MODES:
        return text
    fallback = str(default or "").strip().lower()
    return fallback if fallback in VALID_AIRPLAY_MODES else DEFAULT_AIRPLAY_MODE


# -----------------------------
# Raw INI loading
# -----------------------------
def load_config(path: str) -> configparser.ConfigParser:
    """
    Load configuration from `path`.

    If the file does not exist yet, return an *empty* ConfigParser and let
    callers rely on .get(..., fallback=...) defaults.
    """
    cfg = configparser.ConfigParser()

    if not os.path.exists(path):
        return cfg

    read = cfg.read(path)
    if not read:
        raise FileNotFoundError(f"Config file not found or unreadable: {path}")

    return cfg


def read_pin_override(path: str) -> tuple[Optional[str], bool]:
    """Return (pin_override, present). Blank values are treated as absent."""
    with CONFIG_IO_LOCK:
        cfg = load_config(path)
        if not cfg.has_section("auth"):
            return None, False
        raw = cfg.get("auth", "pin_override", fallback="")
    pin = str(raw or "").strip()
    if not pin:
        return None, False
    return pin, True


def write_pin_override(path: str, pin: str) -> None:
    """Persist a PIN override to the main INI."""
    from autostream_sysutils import atomic_write_file
    with CONFIG_IO_LOCK:
        cfg = load_config(path)
        if not cfg.has_section("auth"):
            cfg.add_section("auth")
        cfg.set("auth", "pin_override", str(pin).strip())
        atomic_write_file(path, cfg.write, preserve_mode=False)


# -----------------------------
# Parsed / typed config
# -----------------------------
@dataclass(frozen=True)
class AudioInputConfig:
    capture_device: str
    silence_threshold_dbfs: float
    is_turntable: bool
    stylus_life_hours: int
    # Drive belt maintenance tracking
    belt_life_hours: int
    belt_life_years: int
    # Main bearing oil maintenance tracking
    bearing_life_hours: int
    bearing_life_years: int
    gain_db: float
    eq_40hz_db: float
    eq_100hz_db: float
    eq_8khz_db: float


@dataclass(frozen=True)
class OwntoneConfig:
    base_url: str
    output_name: str
    volume_percent: int
    output_offsets_ms: dict[str, int]
    output_airplay_modes: dict[str, str]
    known_outputs: dict[str, str]


@dataclass(frozen=True)
class GeneralConfig:
    log_file: str
    log_level: str
    silence_seconds: int
    fifo_path: str


@dataclass(frozen=True)
class WebUIConfig:
    """Web UI-only configuration.
    This must not affect core streaming logic.
    """
    # Names of Owntone outputs that should be hidden from the Web UI.
    # Matching is case-insensitive.
    hidden_outputs: tuple[str, ...]
    # Whether to show the master volume card on the home page. Default: True.
    show_master_volume: bool
    # Whether to show the input detail pill (label, sample rate, dBFS) on the
    # home page. Default: False.
    show_input_detail: bool
    # Whether to use the dark colour theme. Default: False.
    dark_mode: bool
    # Whether to show the system hostname in the home-page top controls.
    show_hostname_on_home: bool


@dataclass(frozen=True)
class OutputEqConfig:
    """Shared output-stage EQ and gain settings (INI section [output_eq])."""
    gain_db: float
    auto_trim_enabled: bool
    peq1_db: float
    peq2_db: float
    peq3_db: float
    peq4_db: float
    peq5_db: float
    peq6_db: float


@dataclass(frozen=True)
class UpdatesConfig:
    """Autonomous update settings (INI section [updates])."""
    auto_update: bool


@dataclass(frozen=True)
class AutostreamConfig:
    general: GeneralConfig
    audio1: AudioInputConfig
    audio2_enabled: bool
    audio2: AudioInputConfig
    owntone: OwntoneConfig
    webui: WebUIConfig
    output_eq: OutputEqConfig
    updates: UpdatesConfig


def _split_list(raw: str | None) -> tuple[str, ...]:
    """Parse a comma/newline-separated list from the INI.

    Supports either:
      hidden_outputs = A, B, C
    or
      hidden_outputs =
          A
          B
          C
    """
    if not raw:
        return ()
    items: list[str] = []
    for ln in str(raw).splitlines():
        for part in ln.split(","):
            s = part.strip()
            if s:
                items.append(s)
    # Deduplicate while preserving order (case-insensitive)
    seen: set[str] = set()
    out: list[str] = []
    for s in items:
        key = s.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return tuple(out)


def _parse_audio_input_config(
    cfg: configparser.ConfigParser,
    section: str,
) -> AudioInputConfig:
    """Parse a single [audioN] section into an AudioInputConfig."""
    return AudioInputConfig(
        capture_device=cfg.get(section, "capture_device", fallback="").strip(),
        silence_threshold_dbfs=cfg.getfloat(section, "silence_threshold", fallback=-66.0),
        is_turntable=cfg.getboolean(section, "turntable", fallback=False),
        stylus_life_hours=normalize_stylus_life_hours(
            cfg.get(section, "stylus_life_hours", fallback=str(DEFAULT_STYLUS_LIFE_HOURS)),
            default=DEFAULT_STYLUS_LIFE_HOURS,
        ),
        belt_life_hours=normalize_maintenance_life_hours(
            cfg.get(section, "belt_life_hours", fallback="0"),
        ),
        belt_life_years=normalize_maintenance_life_years(
            cfg.get(section, "belt_life_years", fallback="0"),
        ),
        bearing_life_hours=normalize_bearing_life_hours(
            cfg.get(section, "bearing_life_hours", fallback="0"),
        ),
        bearing_life_years=normalize_maintenance_life_years(
            cfg.get(section, "bearing_life_years", fallback="0"),
        ),
        gain_db=cfg.getfloat(section, "gain_db", fallback=0.0),
        eq_40hz_db=cfg.getfloat(section, "eq_40hz_db", fallback=0.0),
        eq_100hz_db=cfg.getfloat(section, "eq_100hz_db", fallback=0.0),
        eq_8khz_db=cfg.getfloat(
            section, "eq_8khz_db",
            fallback=cfg.getfloat(section, "eq_10khz_db", fallback=0.0),
        ),
    )


def parse_config(cfg: configparser.ConfigParser) -> AutostreamConfig:
    # General
    log_file = cfg.get(
        "general", "log_file",
        fallback="/var/log/autostream/autostream.log"
    )
    log_level = normalize_log_level(
        cfg.get("general", "log_level", fallback=DEFAULT_LOG_LEVEL),
        default=DEFAULT_LOG_LEVEL,
    )
    silence_seconds = cfg.getint("general", "silence_seconds", fallback=30)
    fifo_path = cfg.get("general", "fifo_path", fallback="/tmp/autostream-pipes/autostream.fifo")

    general = GeneralConfig(
        log_file=log_file,
        log_level=log_level,
        silence_seconds=silence_seconds,
        fifo_path=fifo_path,
    )

    # Audio #1
    audio1 = _parse_audio_input_config(cfg, "audio1")

    # Audio #2
    audio2_enabled = cfg.getboolean("audio2", "enabled", fallback=False)
    audio2 = _parse_audio_input_config(cfg, "audio2")

    # Owntone per-output offsets (keyed by output id as string)
    offsets: dict[str, int] = {}
    if cfg.has_section("owntone_offsets"):
        for k, v in cfg.items("owntone_offsets"):
            # ConfigParser lowercases keys by default; that's fine for numeric IDs.
            try:
                offsets[str(k).strip()] = int(str(v).strip())
            except Exception:
                offsets[str(k).strip()] = 0

    # Owntone per-output runtime protocol preferences for newer OwnTone builds.
    # Store the full preference, including explicit "default", so runtime
    # speaker activation can clear any previously forced protocol.
    airplay_modes: dict[str, str] = {}
    if cfg.has_section("owntone_airplay_modes"):
        for k, v in cfg.items("owntone_airplay_modes"):
            key = str(k).strip()
            if not key:
                continue
            airplay_modes[key] = normalize_airplay_mode(v)

    # Known outputs registry keyed by stable OwnTone output id. The value is
    # the last known display name so the UI can still render offline speakers.
    known_outputs: dict[str, str] = {}
    if cfg.has_section("owntone_known_outputs"):
        for k, v in cfg.items("owntone_known_outputs"):
            key = str(k).strip()
            if not key:
                continue
            name = str(v).strip()
            if name:
                known_outputs[key] = name

    # Owntone
    owntone = OwntoneConfig(
        base_url=cfg.get("owntone", "base_url", fallback="http://localhost:3689"),
        output_name=cfg.get("owntone", "output_name", fallback=""),
        volume_percent=cfg.getint("owntone", "volume_percent", fallback=20),
        output_offsets_ms=offsets,
        output_airplay_modes=airplay_modes,
        known_outputs=known_outputs,
    )

    # Web UI
    webui = WebUIConfig(
        hidden_outputs=_split_list(cfg.get("webui", "hidden_outputs", fallback="")),
        show_master_volume=cfg.getboolean("webui", "show_master_volume", fallback=True),
        show_input_detail=cfg.getboolean("webui", "show_input_detail", fallback=False),
        dark_mode=cfg.getboolean("webui", "dark_mode", fallback=False),
        show_hostname_on_home=cfg.getboolean("webui", "show_hostname_on_home", fallback=False),
    )

    output_eq = OutputEqConfig(
        gain_db=cfg.getfloat("output_eq", "gain_db", fallback=0.0),
        auto_trim_enabled=cfg.getboolean("output_eq", "auto_trim_enabled", fallback=False),
        peq1_db=cfg.getfloat("output_eq", "peq1_db", fallback=0.0),
        peq2_db=cfg.getfloat("output_eq", "peq2_db", fallback=0.0),
        peq3_db=cfg.getfloat("output_eq", "peq3_db", fallback=0.0),
        peq4_db=cfg.getfloat("output_eq", "peq4_db", fallback=0.0),
        peq5_db=cfg.getfloat("output_eq", "peq5_db", fallback=0.0),
        peq6_db=cfg.getfloat("output_eq", "peq6_db", fallback=0.0),
    )

    updates = UpdatesConfig(
        auto_update=cfg.getboolean("updates", "auto_update", fallback=False),
    )

    return AutostreamConfig(
        general=general,
        audio1=audio1,
        audio2_enabled=audio2_enabled,
        audio2=audio2,
        owntone=owntone,
        webui=webui,
        output_eq=output_eq,
        updates=updates,
    )


def load_and_parse(path: str) -> AutostreamConfig:
    return parse_config(load_config(path))


# Cache: path -> ((mtime, size), unconfigured_bool)
_unconfigured_lock = threading.Lock()
_unconfigured_cache: dict[str, tuple[tuple[float, int], bool]] = {}
_MONITOR_DEVICE_RE = re.compile(
    r"^hw:(?:\d+,\d+|CARD=[^,]+,DEV=\d+)$",
    re.IGNORECASE,
)


def mark_configured(path: str) -> None:
    """
    After successfully writing the INI, call this to force unconfigured(path) == False
    immediately (until the file changes again).
    """
    try:
        st = os.stat(path)
        sig = (float(st.st_mtime), int(st.st_size))
    except OSError:
        return

    with _unconfigured_lock:
        _unconfigured_cache[path] = (sig, False)


def _get_nonempty(cfg: configparser.ConfigParser, section: str, key: str) -> str:
    """Return a stripped value or '' if missing/blank."""
    try:
        return cfg.get(section, key, fallback="").strip()
    except (configparser.Error, ValueError):
        return ""


def is_valid_monitor_device_id(device: str) -> bool:
    """Return True if device is in an ALSA hw:* form accepted by autostream_monitor."""
    return bool(_MONITOR_DEVICE_RE.fullmatch((device or "").strip()))


def unconfigured(path: str) -> bool:
    """
    True if the system should be treated as unconfigured.

    Requires:
      - [general] fifo_path (non-empty)
      - [audio1] capture_device in an ALSA hw:* format
      - [owntone] output_name (non-empty)

    Cached by (mtime, size) so we only re-parse when the INI changes.
    """
    # Fast stat + basic sanity checks
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):
            return True
        if st.st_size == 0:
            return True
        sig = (float(st.st_mtime), int(st.st_size))
    except FileNotFoundError:
        return True
    except OSError:
        # unreadable, permission denied, sandboxed, etc.
        return True

    # Cache hit?
    with _unconfigured_lock:
        cached = _unconfigured_cache.get(path)
        if cached and cached[0] == sig:
            return cached[1]

    # Parse + validate required fields
    cfg = configparser.ConfigParser()
    read_ok = cfg.read(path)
    if not read_ok:
        is_unconfigured = True
    else:
        fifo_path = _get_nonempty(cfg, "general", "fifo_path")
        audio1_dev = _get_nonempty(cfg, "audio1", "capture_device")

        output_name = _get_nonempty(cfg, "owntone", "output_name")

        is_unconfigured = not (
            fifo_path
            and is_valid_monitor_device_id(audio1_dev)
            and output_name
        )

    # Update cache
    with _unconfigured_lock:
        _unconfigured_cache[path] = (sig, is_unconfigured)

    return is_unconfigured

