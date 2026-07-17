#!/usr/bin/env python3
"""
autostream_config.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Single source of truth for:
- loading the JSON config file (/etc/autostream/autostream.json)
- loading and saving the runtime state file (/var/lib/autostream/autostream-state.json)
- parsing / defaults / derived values
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
import re
import stat
import threading
from typing import Optional

# Canonical path for the mutable runtime state file.
# Import this constant rather than hardcoding the path at call sites.
STATE_PATH = "/var/lib/autostream/autostream-state.json"

# Canonical path for the audio FIFO that the monitor writes and the playback
# backend reads. Import this constant rather than hardcoding the path at call
# sites. It lives under /run because everything below /tmp is subject to
# age-based cleanup: the FIFO would be deleted after a long idle period, and the
# backend would keep reading the deleted FIFO rather than the one we recreate.
# /run/autostream-pipes is created at boot by system/tmpfiles.d/autostream.conf.
FIFO_PATH = "/run/autostream-pipes/autostream.fifo"

DEFAULT_LOG_LEVEL = "info"
VALID_LOG_LEVELS = ("fatal", "log", "warning", "info", "debug", "spam")
DEFAULT_MDNS_GRACE_PERIOD_SECONDS = 120
MIN_MDNS_GRACE_PERIOD_SECONDS = 60
MAX_MDNS_GRACE_PERIOD_SECONDS = 900

DEFAULT_LOG_LEVEL_CHANGED_BY = "user"
VALID_LOG_LEVEL_CHANGED_BY = ("user", "system")

# Canonical UTC timestamp written by Autostream: YYYY-MM-DDTHH:MM:SSZ
_UTC_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

TRACK_ID_DEFAULT_PROVIDER = "vibra_shazam"
TRACK_ID_KNOWN_PROVIDERS = frozenset({"vibra_shazam"})

TRACK_ID_DEFAULT_ANALYSIS_LEAD_IN_SECONDS = 10
TRACK_ID_MIN_ANALYSIS_LEAD_IN_SECONDS = 0
TRACK_ID_MAX_ANALYSIS_LEAD_IN_SECONDS = 30

TRACK_ID_DEFAULT_SNAPSHOT_SECONDS = 15
TRACK_ID_MIN_SNAPSHOT_SECONDS = 5
TRACK_ID_MAX_SNAPSHOT_SECONDS = 20

TRACK_ID_DEFAULT_RETRY_SECONDS = 5
TRACK_ID_MIN_RETRY_SECONDS = 5
TRACK_ID_MAX_RETRY_SECONDS = 60

TRACK_ID_DEFAULT_REFRESH_SECONDS = 300
TRACK_ID_MIN_REFRESH_SECONDS = 60
TRACK_ID_MAX_REFRESH_SECONDS = 900

TRACK_ID_DEFAULT_TRACK_CHANGE_SILENCE_SECONDS = 1.25
TRACK_ID_MIN_TRACK_CHANGE_SILENCE_SECONDS = 0.5
TRACK_ID_MAX_TRACK_CHANGE_SILENCE_SECONDS = 5.0

# Internal policy constants — not user-configurable.
TRACK_ID_REFRESH_JITTER_SECONDS = 20
TRACK_ID_ERROR_RETRY_SECONDS = 30
TRACK_ID_RATE_LIMIT_BACKOFF_SECONDS = 120
TRACK_ID_UPSTREAM_REJECTION_BACKOFF_SECONDS = 300
DEFAULT_AIRPLAY_MODE = "default"
VALID_AIRPLAY_MODES = (
    "default",
    "raop",
    "airplay2",
    "airplay2_buffered",
    "airplay2_surround_stereo",
    "airplay2_surround_upmix",
)
DEFAULT_STYLUS_LIFE_HOURS = 0  # 0 = tracking disabled ("Don't track usage")
VALID_STYLUS_LIFE_HOURS = (100, 250, 500, 750, 1000)

# Maintenance tracking (drive belt, main bearing oil) — hours and elapsed-time options.
# 0 is the sentinel meaning "Don't track" for all maintenance thresholds.
VALID_MAINTENANCE_LIFE_HOURS = (0, 1000, 2000, 3000)        # drive belt
VALID_BEARING_LIFE_HOURS = (0, 200, 500, 1000, 2000)        # main bearing oil
VALID_MAINTENANCE_LIFE_YEARS = (0, 1, 2, 3, 4, 5)

# Silence-detection presets by input type. Turntable ADC noise floors sit
# well above line-level sources, so a turntable input needs a less sensitive
# (higher) threshold to avoid reading its own noise as continuous playback.
TURNTABLE_SILENCE_THRESHOLD_DBFS = -45.0
LINE_LEVEL_SILENCE_THRESHOLD_DBFS = -60.0


def normalize_stylus_life_hours(
    value: object,
    default: int = DEFAULT_STYLUS_LIFE_HOURS,
) -> int:
    """Return a stylus-life value in hours, or 0 if tracking is disabled.

    Zero disables tracking.  Any positive integer is accepted — values outside
    VALID_STYLUS_LIFE_HOURS (the set the UI offers) are preserved as-is so that
    a custom lifetime set via direct config editing is not discarded.  Negative
    values and non-numeric strings fall back to *default*.
    """
    try:
        hours = int(str(value).strip())
    except Exception:
        return int(default)
    if hours == 0:
        return 0
    return hours if hours > 0 else int(default)


def _normalize_choice(value: object, valid_set: tuple, default: int = 0) -> int:
    """Coerce *value* to a member of *valid_set*, or return 0 / *default*."""
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


def suggested_silence_threshold_dbfs(is_turntable: bool) -> float:
    """Return the recommended silence threshold preset for the input type."""
    return (
        TURNTABLE_SILENCE_THRESHOLD_DBFS
        if bool(is_turntable)
        else LINE_LEVEL_SILENCE_THRESHOLD_DBFS
    )


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


# Use RLock so handlers holding the lock can call save_config/save_state
# (which also acquire this lock) without deadlocking.
CONFIG_IO_LOCK = threading.RLock()


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


def normalize_mdns_grace_period_seconds(value: object) -> int:
    """Return mDNS final-removal grace in seconds, clamped to the UI range."""
    try:
        seconds = int(value)  # type: ignore[arg-type]
    except Exception:
        return DEFAULT_MDNS_GRACE_PERIOD_SECONDS
    return max(MIN_MDNS_GRACE_PERIOD_SECONDS, min(MAX_MDNS_GRACE_PERIOD_SECONDS, seconds))


def normalize_log_level_changed_by(value: object) -> str:
    """Return a valid changed_by value, defaulting to 'user' for invalid/missing input."""
    text = str(value or "").strip().lower()
    return text if text in VALID_LOG_LEVEL_CHANGED_BY else DEFAULT_LOG_LEVEL_CHANGED_BY


def normalize_log_level_changed_at(value: object) -> Optional[str]:
    """Return a canonical UTC timestamp string or None for invalid/missing input."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if _UTC_TS_RE.match(text):
        return text
    return None


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
# JSON file I/O
# -----------------------------

def load_config(path: str) -> dict:
    """Load configuration from *path*. Returns an empty dict if the file is absent."""
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError) as e:
        raise ValueError(f"Config file unreadable or malformed: {path}: {e}") from e


def save_config(path: str, data: dict) -> None:
    """Atomically write the config JSON. Acquires CONFIG_IO_LOCK internally."""
    from autostream_sysutils import atomic_write_file
    with CONFIG_IO_LOCK:
        atomic_write_file(path, lambda f: json.dump(data, f, indent=2), preserve_mode=False)


def load_state(path: str) -> dict:
    """Load runtime state JSON. Returns an empty dict only if the file is absent."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}


def save_state(path: str, data: dict) -> None:
    """Atomically write the state JSON. Acquires CONFIG_IO_LOCK internally."""
    from autostream_sysutils import atomic_write_file
    with CONFIG_IO_LOCK:
        atomic_write_file(path, lambda f: json.dump(data, f, indent=2), preserve_mode=False)


def read_pin_override(path: str) -> tuple[Optional[str], bool]:
    """Return (pin_override, present) from the state file at *path*. Blank values are absent."""
    with CONFIG_IO_LOCK:
        data = load_state(path)
    pin = str((data.get("auth") or {}).get("pin_override", "") or "").strip()
    if not pin:
        return None, False
    return pin, True


def write_pin_override(path: str, pin: str) -> None:
    """Persist a PIN override to the state file at *path*."""
    from autostream_sysutils import atomic_write_file
    with CONFIG_IO_LOCK:
        data = load_state(path)
        data.setdefault("auth", {})["pin_override"] = str(pin).strip()
        atomic_write_file(path, lambda f: json.dump(data, f, indent=2), preserve_mode=False)


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
    mdns_grace_period_seconds: int
    log_level_changed_by: str
    log_level_changed_at: Optional[str]


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
    # Whether to announce this appliance via _autostream._tcp for peer discovery.
    # Default: True (backwards-compatible; absence means advertise).
    advertise_appliance: bool
    # Whether to allow controlling other autostream appliances from this UI.
    # Requires show_hostname_on_home=True to take effect.
    # Default: True (backwards-compatible; absence means allow).
    control_other_appliances: bool
    # Poll interval for querying output usage from other playing appliances, seconds.
    output_usage_poll_interval_seconds: int


@dataclass(frozen=True)
class OutputEqConfig:
    """Shared output-stage EQ and gain settings (JSON section output_eq)."""
    gain_db: float
    auto_trim_enabled: bool
    peq1_db: float
    peq2_db: float
    peq3_db: float
    peq4_db: float
    peq5_db: float
    peq6_db: float


OUTPUT_USAGE_POLL_INTERVAL_DEFAULT = 3
OUTPUT_USAGE_POLL_INTERVAL_MIN = 1
OUTPUT_USAGE_POLL_INTERVAL_MAX = 30


def normalize_output_usage_poll_interval(value: object) -> int:
    """Return a valid poll interval in seconds, or the default on bad input."""
    try:
        v = int(value)  # type: ignore[arg-type]
    except Exception:
        return OUTPUT_USAGE_POLL_INTERVAL_DEFAULT
    if v < OUTPUT_USAGE_POLL_INTERVAL_MIN or v > OUTPUT_USAGE_POLL_INTERVAL_MAX:
        return OUTPUT_USAGE_POLL_INTERVAL_DEFAULT
    return v


def normalize_update_channel(value: object) -> str:
    """Return 'dev' only when *value* normalises to 'dev'; otherwise 'stable'.

    Identical semantics to the private normaliser in autostream_update_support
    but lives here so application code can use it without importing the
    root-only supervisor module.
    """
    return "dev" if str(value or "").strip().lower() == "dev" else "stable"


@dataclass(frozen=True)
class UpdatesConfig:
    """Autonomous update settings (JSON section updates)."""
    auto_update: bool
    update_channel: str


def _normalize_track_id_int(value: object, default: int, lo: int, hi: int) -> int:
    """Clamp a track-ID integer setting to [lo, hi]; use default for invalid input."""
    try:
        v = int(float(str(value)))  # type: ignore[arg-type]
    except Exception:
        return default
    return max(lo, min(hi, v))


def _normalize_track_id_float(value: object, default: float, lo: float, hi: float) -> float:
    """Clamp a track-ID float setting to [lo, hi]; use default for invalid/non-finite input."""
    import math
    try:
        v = float(str(value))  # type: ignore[arg-type]
    except Exception:
        return default
    if not math.isfinite(v):
        return default
    return max(lo, min(hi, v))


def normalize_track_id_analysis_lead_in_seconds(value: object) -> int:
    return _normalize_track_id_int(
        value,
        TRACK_ID_DEFAULT_ANALYSIS_LEAD_IN_SECONDS,
        TRACK_ID_MIN_ANALYSIS_LEAD_IN_SECONDS,
        TRACK_ID_MAX_ANALYSIS_LEAD_IN_SECONDS,
    )


def normalize_track_id_snapshot_seconds(value: object) -> int:
    return _normalize_track_id_int(
        value,
        TRACK_ID_DEFAULT_SNAPSHOT_SECONDS,
        TRACK_ID_MIN_SNAPSHOT_SECONDS,
        TRACK_ID_MAX_SNAPSHOT_SECONDS,
    )


def normalize_track_id_retry_seconds(value: object) -> int:
    return _normalize_track_id_int(
        value,
        TRACK_ID_DEFAULT_RETRY_SECONDS,
        TRACK_ID_MIN_RETRY_SECONDS,
        TRACK_ID_MAX_RETRY_SECONDS,
    )


def normalize_track_id_refresh_seconds(value: object) -> int:
    return _normalize_track_id_int(
        value,
        TRACK_ID_DEFAULT_REFRESH_SECONDS,
        TRACK_ID_MIN_REFRESH_SECONDS,
        TRACK_ID_MAX_REFRESH_SECONDS,
    )


def normalize_track_id_track_change_silence_seconds(value: object) -> float:
    return _normalize_track_id_float(
        value,
        TRACK_ID_DEFAULT_TRACK_CHANGE_SILENCE_SECONDS,
        TRACK_ID_MIN_TRACK_CHANGE_SILENCE_SECONDS,
        TRACK_ID_MAX_TRACK_CHANGE_SILENCE_SECONDS,
    )


@dataclass(frozen=True)
class TrackIdentificationConfig:
    """Track identification settings (JSON section track_identification)."""
    enabled: bool
    provider: str
    analysis_lead_in_seconds: int
    snapshot_seconds: int
    retry_seconds: int
    refresh_seconds: int
    track_change_silence_seconds: float
    # Nested provider configs keyed by provider id.  Only known provider IDs
    # (see TRACK_ID_KNOWN_PROVIDERS) are retained; others are silently discarded.
    providers: dict


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
    track_identification: TrackIdentificationConfig


def _parse_audio_input_config(section: dict) -> AudioInputConfig:
    """Parse a single audio section dict into an AudioInputConfig."""
    is_turntable = bool(section.get("turntable", False))
    raw_threshold = section.get("silence_threshold")
    return AudioInputConfig(
        capture_device=str(section.get("capture_device", "") or "").strip(),
        silence_threshold_dbfs=(
            float(raw_threshold) if raw_threshold is not None
            else suggested_silence_threshold_dbfs(is_turntable)
        ),
        is_turntable=is_turntable,
        stylus_life_hours=normalize_stylus_life_hours(
            section.get("stylus_life_hours", DEFAULT_STYLUS_LIFE_HOURS),
            default=DEFAULT_STYLUS_LIFE_HOURS,
        ),
        belt_life_hours=normalize_maintenance_life_hours(section.get("belt_life_hours", 0)),
        belt_life_years=normalize_maintenance_life_years(section.get("belt_life_years", 0)),
        bearing_life_hours=normalize_bearing_life_hours(section.get("bearing_life_hours", 0)),
        bearing_life_years=normalize_maintenance_life_years(section.get("bearing_life_years", 0)),
        gain_db=float(section.get("gain_db", 0.0) or 0.0),
        eq_40hz_db=float(section.get("eq_40hz_db", 0.0) or 0.0),
        eq_100hz_db=float(section.get("eq_100hz_db", 0.0) or 0.0),
        # Support legacy eq_10khz_db key from pre-migration INI configs.
        eq_8khz_db=float(section.get("eq_8khz_db", section.get("eq_10khz_db", 0.0)) or 0.0),
    )


def set_input_mode(raw: dict, index: int, is_turntable: bool) -> float:
    """Set an input's turntable flag and its derived silence threshold together.

    Returns the threshold that was written, so callers can compare it against
    the previously stored value without recomputing it.
    """
    section = raw.setdefault(f"audio{index}", {})
    section["turntable"] = bool(is_turntable)
    threshold = suggested_silence_threshold_dbfs(is_turntable)
    section["silence_threshold"] = threshold
    return threshold


def parse_config(data: dict, state: Optional[dict] = None) -> AutostreamConfig:
    """Parse a config dict (and optional state dict) into typed dataclasses.

    *data* is loaded from /etc/autostream/autostream.json.
    *state* is optionally loaded from /var/lib/autostream/autostream-state.json
    and provides known_outputs. Callers that do not need known_outputs may omit it.
    """
    if state is None:
        state = {}

    general_d = data.get("general") or {}
    general = GeneralConfig(
        log_file=str(general_d.get("log_file", "/var/log/autostream/autostream.log") or ""),
        log_level=normalize_log_level(general_d.get("log_level", DEFAULT_LOG_LEVEL)),
        silence_seconds=int(general_d.get("silence_seconds", 30) or 30),
        # Fixed appliance path: any value carried in the config is ignored, and
        # autostream_migrate.py rewrites it. See FIFO_PATH.
        fifo_path=FIFO_PATH,
        mdns_grace_period_seconds=normalize_mdns_grace_period_seconds(
            general_d.get("mdns_grace_period_seconds", DEFAULT_MDNS_GRACE_PERIOD_SECONDS)
        ),
        log_level_changed_by=normalize_log_level_changed_by(general_d.get("log_level_changed_by")),
        log_level_changed_at=normalize_log_level_changed_at(general_d.get("log_level_changed_at")),
    )

    audio1 = _parse_audio_input_config(data.get("audio1") or {})

    audio2_section = data.get("audio2") or {}
    audio2_enabled = bool(audio2_section.get("enabled", False))
    audio2 = _parse_audio_input_config(audio2_section)

    owntone_d = data.get("owntone") or {}

    offsets: dict[str, int] = {}
    offsets_raw = owntone_d.get("offsets") or {}
    if isinstance(offsets_raw, dict):
        for k, v in offsets_raw.items():
            try:
                offsets[str(k).strip()] = int(v)
            except Exception:
                offsets[str(k).strip()] = 0

    airplay_modes: dict[str, str] = {}
    modes_raw = owntone_d.get("airplay_modes") or {}
    if isinstance(modes_raw, dict):
        for k, v in modes_raw.items():
            key = str(k).strip()
            if key:
                airplay_modes[key] = normalize_airplay_mode(v)

    # known_outputs lives in the state file, not the config file.
    known_outputs: dict[str, str] = {}
    raw_known = (state.get("owntone") or {}).get("known_outputs") or {}
    if isinstance(raw_known, dict):
        for k, v in raw_known.items():
            key = str(k).strip()
            name = str(v).strip()
            if key and name:
                known_outputs[key] = name

    owntone = OwntoneConfig(
        base_url=str(owntone_d.get("base_url", "http://localhost:3689") or ""),
        output_name=str(owntone_d.get("output_name", "") or ""),
        volume_percent=int(owntone_d.get("volume_percent", 20) or 20),
        output_offsets_ms=offsets,
        output_airplay_modes=airplay_modes,
        known_outputs=known_outputs,
    )

    webui_d = data.get("webui") or {}
    hidden_raw = webui_d.get("hidden_outputs") or []
    if isinstance(hidden_raw, list):
        hidden_outputs = tuple(str(x).strip() for x in hidden_raw if str(x).strip())
    else:
        hidden_outputs = ()

    webui = WebUIConfig(
        hidden_outputs=hidden_outputs,
        show_master_volume=bool(webui_d.get("show_master_volume", True)),
        show_input_detail=bool(webui_d.get("show_input_detail", False)),
        dark_mode=bool(webui_d.get("dark_mode", False)),
        show_hostname_on_home=bool(webui_d.get("show_hostname_on_home", False)),
        advertise_appliance=bool(webui_d.get("advertise_appliance", True)),
        control_other_appliances=bool(webui_d.get("control_other_appliances", True)),
        output_usage_poll_interval_seconds=normalize_output_usage_poll_interval(
            webui_d.get("output_usage_poll_interval_seconds", OUTPUT_USAGE_POLL_INTERVAL_DEFAULT)
        ),
    )

    eq_d = data.get("output_eq") or {}
    output_eq = OutputEqConfig(
        gain_db=float(eq_d.get("gain_db", 0.0) or 0.0),
        auto_trim_enabled=bool(eq_d.get("auto_trim_enabled", False)),
        peq1_db=float(eq_d.get("peq1_db", 0.0) or 0.0),
        peq2_db=float(eq_d.get("peq2_db", 0.0) or 0.0),
        peq3_db=float(eq_d.get("peq3_db", 0.0) or 0.0),
        peq4_db=float(eq_d.get("peq4_db", 0.0) or 0.0),
        peq5_db=float(eq_d.get("peq5_db", 0.0) or 0.0),
        peq6_db=float(eq_d.get("peq6_db", 0.0) or 0.0),
    )

    updates_d = data.get("updates") or {}
    updates = UpdatesConfig(
        auto_update=bool(updates_d.get("auto_update", False)),
        update_channel=normalize_update_channel(updates_d.get("update_channel")),
    )

    track_id_d = data.get("track_identification") or {}
    raw_providers = track_id_d.get("providers")
    providers: dict = {}
    if isinstance(raw_providers, dict):
        for prov_id, prov_cfg in raw_providers.items():
            if str(prov_id) in TRACK_ID_KNOWN_PROVIDERS:
                providers[str(prov_id)] = dict(prov_cfg) if isinstance(prov_cfg, dict) else {}
    track_identification = TrackIdentificationConfig(
        enabled=bool(track_id_d.get("enabled", False)),
        provider=str(track_id_d.get("provider", TRACK_ID_DEFAULT_PROVIDER) or TRACK_ID_DEFAULT_PROVIDER),
        analysis_lead_in_seconds=normalize_track_id_analysis_lead_in_seconds(
            track_id_d.get("analysis_lead_in_seconds", TRACK_ID_DEFAULT_ANALYSIS_LEAD_IN_SECONDS)
        ),
        snapshot_seconds=normalize_track_id_snapshot_seconds(
            track_id_d.get("snapshot_seconds", TRACK_ID_DEFAULT_SNAPSHOT_SECONDS)
        ),
        retry_seconds=normalize_track_id_retry_seconds(
            track_id_d.get("retry_seconds", TRACK_ID_DEFAULT_RETRY_SECONDS)
        ),
        refresh_seconds=normalize_track_id_refresh_seconds(
            track_id_d.get("refresh_seconds", TRACK_ID_DEFAULT_REFRESH_SECONDS)
        ),
        track_change_silence_seconds=normalize_track_id_track_change_silence_seconds(
            track_id_d.get("track_change_silence_seconds", TRACK_ID_DEFAULT_TRACK_CHANGE_SILENCE_SECONDS)
        ),
        providers=providers,
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
        track_identification=track_identification,
    )


def load_and_parse(path: str, state_path: Optional[str] = None) -> AutostreamConfig:
    data = load_config(path)
    state = load_state(state_path) if state_path else {}
    return parse_config(data, state)


# Cache: path -> ((mtime, size), unconfigured_bool)
_unconfigured_lock = threading.Lock()
_unconfigured_cache: dict[str, tuple[tuple[float, int], bool]] = {}
_MONITOR_DEVICE_RE = re.compile(
    r"^hw:(?:\d+,\d+|CARD=[^,]+,DEV=\d+)$",
    re.IGNORECASE,
)


def mark_configured(path: str) -> None:
    """Force unconfigured(path) == False immediately after a successful config write."""
    try:
        st = os.stat(path)
        sig = (float(st.st_mtime), int(st.st_size))
    except OSError:
        return
    with _unconfigured_lock:
        _unconfigured_cache[path] = (sig, False)


def is_valid_monitor_device_id(device: str) -> bool:
    """Return True if device is in an ALSA hw:* form accepted by autostream_monitor."""
    return bool(_MONITOR_DEVICE_RE.fullmatch((device or "").strip()))


def unconfigured(path: str) -> bool:
    """
    True if the system should be treated as unconfigured.

    Requires:
      - general.fifo_path (non-empty)
      - audio1.capture_device in an ALSA hw:* format
      - owntone.output_name (non-empty)

    Cached by (mtime, size) so we only re-parse when the JSON changes.
    """
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
        return True

    with _unconfigured_lock:
        cached = _unconfigured_cache.get(path)
        if cached and cached[0] == sig:
            return cached[1]

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        fifo_path = str((data.get("general") or {}).get("fifo_path", "") or "").strip()
        audio1_dev = str((data.get("audio1") or {}).get("capture_device", "") or "").strip()
        output_name = str((data.get("owntone") or {}).get("output_name", "") or "").strip()
        is_unconfigured = not (
            fifo_path
            and is_valid_monitor_device_id(audio1_dev)
            and output_name
        )
    except Exception:
        is_unconfigured = True

    with _unconfigured_lock:
        _unconfigured_cache[path] = (sig, is_unconfigured)

    return is_unconfigured
