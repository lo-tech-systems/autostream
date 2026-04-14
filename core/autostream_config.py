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
eq_10khz_db = 0                ; treble shelf at 10 kHz

[audio2]
enabled = no                   ; set to yes to enable this channel
capture_device = hw:2,0        ; ALSA hw identifier reported by autostream_monitor
silence_threshold = -66        ; dBFS threshold (e.g. -66 ~= 16/32767)
turntable = no                 ; set to yes to enable stylus-life tracking
stylus_life_hours = 500        ; reminder threshold for stylus replacement
gain_db = 0                    ; input gain before EQ
eq_40hz_db = 0                 ; sub-bass bell at 40 Hz (Q=0.707)
eq_100hz_db = 0                ; bass shelf at 100 Hz
eq_10khz_db = 0                ; treble shelf at 10 kHz

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

from dataclasses import dataclass
import logging
import os
import re
import stat
import threading
import configparser
from typing import Iterable, Optional, Tuple

from autostream_playback import DEFAULT_STYLUS_LIFE_HOURS, normalize_stylus_life_hours


DEFAULT_LOG_LEVEL = "info"
VALID_LOG_LEVELS = ("fatal", "log", "warning", "info", "debug", "spam")
DEFAULT_AIRPLAY_MODE = "default"
VALID_AIRPLAY_MODES = ("default", "raop", "airplay2")

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
    with CONFIG_IO_LOCK:
        cfg = load_config(path)
        if not cfg.has_section("auth"):
            cfg.add_section("auth")
        cfg.set("auth", "pin_override", str(pin).strip())
        with open(path, "w", encoding="utf-8") as f:
            cfg.write(f)


def clear_pin_override(path: str) -> None:
    """Remove any persisted PIN override from the main INI."""
    with CONFIG_IO_LOCK:
        cfg = load_config(path)
        if not cfg.has_section("auth"):
            return
        if cfg.has_option("auth", "pin_override"):
            cfg.remove_option("auth", "pin_override")
        if not list(cfg.items("auth")):
            cfg.remove_section("auth")
        with open(path, "w", encoding="utf-8") as f:
            cfg.write(f)


# -----------------------------
# Parsed / typed config
# -----------------------------
@dataclass(frozen=True)
class AudioInputConfig:
    capture_device: str
    silence_threshold_dbfs: float
    is_turntable: bool
    stylus_life_hours: int
    gain_db: float
    eq_40hz_db: float
    eq_100hz_db: float
    eq_10khz_db: float


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


@dataclass(frozen=True)
class AutostreamConfig:
    general: GeneralConfig
    audio1: AudioInputConfig
    audio2_enabled: bool
    audio2: AudioInputConfig
    owntone: OwntoneConfig
    webui: WebUIConfig


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
    capture_device1 = cfg.get("audio1", "capture_device", fallback="").strip()
    silence_threshold1 = cfg.getfloat("audio1", "silence_threshold", fallback=-66.0)
    turntable1 = cfg.getboolean("audio1", "turntable", fallback=False)
    stylus_life_hours1 = normalize_stylus_life_hours(
        cfg.get("audio1", "stylus_life_hours", fallback=str(DEFAULT_STYLUS_LIFE_HOURS)),
        default=DEFAULT_STYLUS_LIFE_HOURS,
    )
    gain_db1 = cfg.getfloat("audio1", "gain_db", fallback=0.0)
    eq_40hz_db1 = cfg.getfloat("audio1", "eq_40hz_db", fallback=0.0)
    eq_100hz_db1 = cfg.getfloat("audio1", "eq_100hz_db", fallback=0.0)
    eq_10khz_db1 = cfg.getfloat("audio1", "eq_10khz_db", fallback=0.0)

    audio1 = AudioInputConfig(
        capture_device=capture_device1,
        silence_threshold_dbfs=silence_threshold1,
        is_turntable=turntable1,
        stylus_life_hours=stylus_life_hours1,
        gain_db=gain_db1,
        eq_40hz_db=eq_40hz_db1,
        eq_100hz_db=eq_100hz_db1,
        eq_10khz_db=eq_10khz_db1,
    )

    # Audio #2
    audio2_enabled = cfg.getboolean("audio2", "enabled", fallback=False)
    capture_device2 = cfg.get("audio2", "capture_device", fallback="").strip()
    silence_threshold2 = cfg.getfloat("audio2", "silence_threshold", fallback=-66.0)
    turntable2 = cfg.getboolean("audio2", "turntable", fallback=False)
    stylus_life_hours2 = normalize_stylus_life_hours(
        cfg.get("audio2", "stylus_life_hours", fallback=str(DEFAULT_STYLUS_LIFE_HOURS)),
        default=DEFAULT_STYLUS_LIFE_HOURS,
    )
    gain_db2 = cfg.getfloat("audio2", "gain_db", fallback=0.0)
    eq_40hz_db2 = cfg.getfloat("audio2", "eq_40hz_db", fallback=0.0)
    eq_100hz_db2 = cfg.getfloat("audio2", "eq_100hz_db", fallback=0.0)
    eq_10khz_db2 = cfg.getfloat("audio2", "eq_10khz_db", fallback=0.0)

    audio2 = AudioInputConfig(
        capture_device=capture_device2,
        silence_threshold_dbfs=silence_threshold2,
        is_turntable=turntable2,
        stylus_life_hours=stylus_life_hours2,
        gain_db=gain_db2,
        eq_40hz_db=eq_40hz_db2,
        eq_100hz_db=eq_100hz_db2,
        eq_10khz_db=eq_10khz_db2,
    )

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
    )

    return AutostreamConfig(
        general=general,
        audio1=audio1,
        audio2_enabled=audio2_enabled,
        audio2=audio2,
        owntone=owntone,
        webui=webui,
    )


def load_and_parse(path: str) -> AutostreamConfig:
    return parse_config(load_config(path))


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

def _is_minimally_valid_ini(path: str) -> bool:
    """
    Return True if INI can be parsed and contains at least one section.
    Keep this lightweight; you can strengthen it later (required keys, etc.).
    """
    p = configparser.ConfigParser()
    try:
        with open(path, "r", encoding="utf-8") as f:
            p.read_file(f)
    except Exception:
        return False
    return len(p.sections()) > 0


# Cache: path -> ((mtime, size), unconfigured_bool)
_unconfigured_lock = threading.Lock()
_unconfigured_cache: dict[str, tuple[tuple[float, int], bool]] = {}
_MONITOR_DEVICE_RE = re.compile(
    r"^hw:(?:\d+,\d+|CARD=[^,]+,DEV=\d+)$",
    re.IGNORECASE,
)


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
