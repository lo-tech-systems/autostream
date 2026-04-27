#!/usr/bin/env python3
"""autostream_playback_stats.py

Playback-hours tracking for autostream inputs.

This module keeps runtime playback counters in a small JSON file, separate
from autostream.ini. User-editable settings such as "turntable" and
"stylus_life_hours" should remain in the INI and be supplied to the tracker
at runtime. Counters are driven by audible playback activity, not by the
full capture window, so trailing silence used to detect end-of-playback is
not counted.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone

from autostream_config import (
    DEFAULT_STYLUS_LIFE_HOURS,
    VALID_STYLUS_LIFE_HOURS,
    VALID_MAINTENANCE_LIFE_HOURS,
    VALID_BEARING_LIFE_HOURS,
    VALID_MAINTENANCE_LIFE_YEARS,
    normalize_stylus_life_hours,
    normalize_maintenance_life_hours,
    normalize_maintenance_life_years,
)
from autostream_sysutils import atomic_write_file


LOGGER = logging.getLogger(__name__)


PLAYBACK_SCHEMA_VERSION = 2
DEFAULT_FLUSH_INTERVAL_SECONDS = 300.0

DEFAULT_PLAYBACK_STATS_PATH = Path(
    os.environ.get(
        "AUTOSTREAM_PLAYBACK_STATS_PATH",
        "/opt/autostream/playback_stats.json",
    )
).expanduser()

TURNTABLE_SILENCE_THRESHOLD_DBFS = -45.0
LINE_LEVEL_SILENCE_THRESHOLD_DBFS = -60.0

STYLUS_WARNING_HOURS = 10.0
STYLUS_WARNING_SECONDS = int(STYLUS_WARNING_HOURS * 3600)

# Maintenance items (belt, bearing): warning thresholds before the due point.
MAINTENANCE_HOURS_WARNING_THRESHOLD = 50   # hours before hours-limit → "due soon"
MAINTENANCE_HOURS_WARNING_SECONDS = int(MAINTENANCE_HOURS_WARNING_THRESHOLD * 3600)
MAINTENANCE_TIME_WARNING_DAYS = 30         # days before time-limit → "due soon"

SAVE_ERROR_LOG_INTERVAL_SECONDS = 60.0


def get_default_playback_stats_path() -> Path:
    """Return the default JSON path used for persisted playback stats."""
    return DEFAULT_PLAYBACK_STATS_PATH


def get_stylus_life_options() -> tuple[int, ...]:
    """Return the supported stylus-life options for UI dropdowns."""
    return VALID_STYLUS_LIFE_HOURS


def get_maintenance_life_hours_options() -> tuple[int, ...]:
    """Return the supported belt hours-threshold options for UI dropdowns."""
    return VALID_MAINTENANCE_LIFE_HOURS


def get_bearing_life_hours_options() -> tuple[int, ...]:
    """Return the supported bearing hours-threshold options for UI dropdowns."""
    return VALID_BEARING_LIFE_HOURS


def get_maintenance_life_years_options() -> tuple[int, ...]:
    """Return the supported maintenance elapsed-time options for UI dropdowns."""
    return VALID_MAINTENANCE_LIFE_YEARS


def suggested_silence_threshold_dbfs(is_turntable: bool) -> float:
    """Return the recommended silence threshold preset for the input type."""
    return (
        TURNTABLE_SILENCE_THRESHOLD_DBFS
        if bool(is_turntable)
        else LINE_LEVEL_SILENCE_THRESHOLD_DBFS
    )


def input_label(input_index: int) -> str:
    """Return the standard user-facing label for an input slot."""
    return f"Input {int(input_index)}"


def hours_from_seconds(total_seconds: int) -> float:
    """Convert whole seconds to hours rounded to one decimal place."""
    return round(max(0, int(total_seconds)) / 3600.0, 1)


def format_hours(total_seconds: int) -> str:
    """Return a compact hours string suitable for UI display."""
    return f"{hours_from_seconds(total_seconds):.1f} h"


def _utc_now_iso(timestamp: float) -> str:
    return (
        datetime.fromtimestamp(float(timestamp), tz=timezone.utc)
        .replace(microsecond=0)
        .isoformat()
    )


def _coerce_non_negative_int(value: object, default: int = 0) -> int:
    try:
        out = int(value)
    except Exception:
        return int(default)
    return out if out >= 0 else int(default)


def _calc_item_hours(
    life_hours: int,
    used_seconds: int,
    warning_seconds: int,
) -> tuple:
    """Return (remaining_secs, overdue, warning) for a hours-tracked maintenance item.

    Returns (None, False, False) when life_hours is 0 (tracking disabled).
    """
    if life_hours <= 0:
        return None, False, False
    remaining = int(life_hours * 3600) - used_seconds
    overdue = remaining <= 0
    warning = not overdue and remaining < warning_seconds
    return remaining, overdue, warning


def _days_elapsed_since(iso_timestamp: Optional[str], now: float) -> Optional[int]:
    """Return whole days elapsed since *iso_timestamp*, or None if absent/unparseable."""
    if not iso_timestamp:
        return None
    try:
        dt = datetime.fromisoformat(str(iso_timestamp))
        now_dt = datetime.fromtimestamp(float(now), tz=timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0, (now_dt - dt).days)
    except Exception:
        return None


def _atomic_write_json(path: Path, payload: dict) -> None:
    """Write JSON atomically, preserving existing file permissions."""
    def _write(fh):
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")

    atomic_write_file(path, _write, preserve_mode=True)


def _read_json_object(path: Path) -> dict:
    """Return the decoded JSON object from path, or {} if unavailable."""
    try:
        with path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)
        return raw if isinstance(raw, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as exc:
        LOGGER.warning("Failed loading playback stats from %s: %s", path, exc)
        return {}


@dataclass(frozen=True)
class PlaybackInputConfig:
    """Runtime configuration supplied by autostream.ini."""

    enabled: bool = True
    is_turntable: bool = False
    stylus_life_hours: int = DEFAULT_STYLUS_LIFE_HOURS
    belt_life_hours: int = 0
    belt_life_years: int = 0
    bearing_life_hours: int = 0
    bearing_life_years: int = 0

    @classmethod
    def normalized(
        cls,
        *,
        enabled: bool = True,
        is_turntable: bool = False,
        stylus_life_hours: object = DEFAULT_STYLUS_LIFE_HOURS,
        belt_life_hours: object = 0,
        belt_life_years: object = 0,
        bearing_life_hours: object = 0,
        bearing_life_years: object = 0,
    ) -> "PlaybackInputConfig":
        return cls(
            enabled=bool(enabled),
            is_turntable=bool(is_turntable),
            stylus_life_hours=normalize_stylus_life_hours(stylus_life_hours),
            belt_life_hours=normalize_maintenance_life_hours(belt_life_hours),
            belt_life_years=normalize_maintenance_life_years(belt_life_years),
            bearing_life_hours=normalize_maintenance_life_hours(bearing_life_hours),
            bearing_life_years=normalize_maintenance_life_years(bearing_life_years),
        )


@dataclass
class PlaybackInputState:
    """Persisted counters for a single input slot."""

    total_playback_seconds: int = 0
    stylus_playback_seconds: int = 0
    last_stylus_reset_at: Optional[str] = None
    belt_playback_seconds: int = 0
    last_belt_service_at: Optional[str] = None
    bearing_playback_seconds: int = 0
    last_bearing_service_at: Optional[str] = None

    @classmethod
    def from_json_obj(cls, raw: object) -> "PlaybackInputState":
        if not isinstance(raw, dict):
            return cls()
        return cls(
            total_playback_seconds=_coerce_non_negative_int(
                raw.get("total_playback_seconds"), 0
            ),
            stylus_playback_seconds=_coerce_non_negative_int(
                raw.get("stylus_playback_seconds"), 0
            ),
            last_stylus_reset_at=(
                str(raw.get("last_stylus_reset_at")).strip()
                if raw.get("last_stylus_reset_at")
                else None
            ),
            belt_playback_seconds=_coerce_non_negative_int(
                raw.get("belt_playback_seconds"), 0
            ),
            last_belt_service_at=(
                str(raw.get("last_belt_service_at")).strip()
                if raw.get("last_belt_service_at")
                else None
            ),
            bearing_playback_seconds=_coerce_non_negative_int(
                raw.get("bearing_playback_seconds"), 0
            ),
            last_bearing_service_at=(
                str(raw.get("last_bearing_service_at")).strip()
                if raw.get("last_bearing_service_at")
                else None
            ),
        )

    def to_json_obj(self) -> dict:
        return {
            "total_playback_seconds": _coerce_non_negative_int(
                self.total_playback_seconds, 0
            ),
            "stylus_playback_seconds": _coerce_non_negative_int(
                self.stylus_playback_seconds, 0
            ),
            "last_stylus_reset_at": self.last_stylus_reset_at,
            "belt_playback_seconds": _coerce_non_negative_int(
                self.belt_playback_seconds, 0
            ),
            "last_belt_service_at": self.last_belt_service_at,
            "bearing_playback_seconds": _coerce_non_negative_int(
                self.bearing_playback_seconds, 0
            ),
            "last_bearing_service_at": self.last_bearing_service_at,
        }


@dataclass(frozen=True)
class InputPlaybackSnapshot:
    """Calculated playback view for one input, ready for UI consumption."""

    input_index: int
    label: str
    active: bool
    enabled: bool
    is_turntable: bool

    # Total lifetime hours
    total_playback_seconds: int
    total_playback_hours: float

    # Stylus wear
    stylus_playback_seconds: int
    stylus_playback_hours: float
    stylus_life_hours: int
    stylus_remaining_seconds: Optional[int]
    stylus_remaining_hours: Optional[float]
    stylus_warning: bool
    stylus_overdue: bool
    last_stylus_reset_at: Optional[str]

    # Drive belt — hours dimension
    belt_life_hours: int
    belt_playback_seconds: int
    belt_playback_hours: float
    belt_hours_remaining: Optional[int]   # seconds remaining; None when hours tracking off
    belt_hours_overdue: bool
    belt_hours_warning: bool

    # Drive belt — elapsed-time dimension
    belt_life_years: int
    belt_elapsed_days: Optional[int]      # None when no service date recorded
    belt_time_overdue: bool
    belt_time_warning: bool

    # Drive belt — combined
    belt_overdue: bool
    belt_warning: bool
    last_belt_service_at: Optional[str]

    # Main bearing oil — hours dimension
    bearing_life_hours: int
    bearing_playback_seconds: int
    bearing_playback_hours: float
    bearing_hours_remaining: Optional[int]
    bearing_hours_overdue: bool
    bearing_hours_warning: bool

    # Main bearing oil — elapsed-time dimension
    bearing_life_years: int
    bearing_elapsed_days: Optional[int]
    bearing_time_overdue: bool
    bearing_time_warning: bool

    # Main bearing oil — combined
    bearing_overdue: bool
    bearing_warning: bool
    last_bearing_service_at: Optional[str]

    def to_public_dict(self) -> dict:
        return {
            "input_index": int(self.input_index),
            "label": self.label,
            "active": bool(self.active),
            "enabled": bool(self.enabled),
            "is_turntable": bool(self.is_turntable),
            "total_playback_seconds": int(self.total_playback_seconds),
            "total_playback_hours": float(self.total_playback_hours),
            # Stylus
            "stylus_playback_seconds": int(self.stylus_playback_seconds),
            "stylus_playback_hours": float(self.stylus_playback_hours),
            "stylus_life_hours": int(self.stylus_life_hours),
            "stylus_remaining_seconds": (
                None if self.stylus_remaining_seconds is None
                else int(self.stylus_remaining_seconds)
            ),
            "stylus_remaining_hours": (
                None if self.stylus_remaining_hours is None
                else float(self.stylus_remaining_hours)
            ),
            "stylus_warning": bool(self.stylus_warning),
            "stylus_overdue": bool(self.stylus_overdue),
            "last_stylus_reset_at": self.last_stylus_reset_at,
            # Belt
            "belt_life_hours": int(self.belt_life_hours),
            "belt_playback_seconds": int(self.belt_playback_seconds),
            "belt_playback_hours": float(self.belt_playback_hours),
            "belt_hours_remaining": (
                None if self.belt_hours_remaining is None
                else int(self.belt_hours_remaining)
            ),
            "belt_hours_overdue": bool(self.belt_hours_overdue),
            "belt_hours_warning": bool(self.belt_hours_warning),
            "belt_life_years": int(self.belt_life_years),
            "belt_elapsed_days": (
                None if self.belt_elapsed_days is None
                else int(self.belt_elapsed_days)
            ),
            "belt_time_overdue": bool(self.belt_time_overdue),
            "belt_time_warning": bool(self.belt_time_warning),
            "belt_overdue": bool(self.belt_overdue),
            "belt_warning": bool(self.belt_warning),
            "last_belt_service_at": self.last_belt_service_at,
            # Bearing
            "bearing_life_hours": int(self.bearing_life_hours),
            "bearing_playback_seconds": int(self.bearing_playback_seconds),
            "bearing_playback_hours": float(self.bearing_playback_hours),
            "bearing_hours_remaining": (
                None if self.bearing_hours_remaining is None
                else int(self.bearing_hours_remaining)
            ),
            "bearing_hours_overdue": bool(self.bearing_hours_overdue),
            "bearing_hours_warning": bool(self.bearing_hours_warning),
            "bearing_life_years": int(self.bearing_life_years),
            "bearing_elapsed_days": (
                None if self.bearing_elapsed_days is None
                else int(self.bearing_elapsed_days)
            ),
            "bearing_time_overdue": bool(self.bearing_time_overdue),
            "bearing_time_warning": bool(self.bearing_time_warning),
            "bearing_overdue": bool(self.bearing_overdue),
            "bearing_warning": bool(self.bearing_warning),
            "last_bearing_service_at": self.last_bearing_service_at,
        }


@dataclass(frozen=True)
class PlaybackSnapshot:
    """Combined playback snapshot for all tracked inputs."""

    inputs: dict[int, InputPlaybackSnapshot]

    # Stylus
    stylus_warning_indices: tuple[int, ...]
    stylus_overdue_indices: tuple[int, ...]
    stylus_banner_text: Optional[str]

    # Drive belt
    belt_warning_indices: tuple[int, ...]
    belt_overdue_indices: tuple[int, ...]
    belt_banner_text: Optional[str]

    # Main bearing oil
    bearing_warning_indices: tuple[int, ...]
    bearing_overdue_indices: tuple[int, ...]
    bearing_banner_text: Optional[str]

    @property
    def has_warning(self) -> bool:
        return bool(
            self.stylus_warning_indices or self.stylus_overdue_indices
            or self.belt_warning_indices or self.belt_overdue_indices
            or self.bearing_warning_indices or self.bearing_overdue_indices
        )

    def to_public_dict(self) -> dict:
        return {
            "inputs": {
                str(idx): snap.to_public_dict()
                for idx, snap in sorted(self.inputs.items())
            },
            "stylus_warning_input_indices": list(self.stylus_warning_indices),
            "stylus_overdue_input_indices": list(self.stylus_overdue_indices),
            "stylus_banner_text": self.stylus_banner_text,
            "belt_warning_input_indices": list(self.belt_warning_indices),
            "belt_overdue_input_indices": list(self.belt_overdue_indices),
            "belt_banner_text": self.belt_banner_text,
            "bearing_warning_input_indices": list(self.bearing_warning_indices),
            "bearing_overdue_input_indices": list(self.bearing_overdue_indices),
            "bearing_banner_text": self.bearing_banner_text,
            "has_warning": self.has_warning,
        }


@dataclass(frozen=True)
class MaintenanceResetResult:
    """Result of a user-requested maintenance item reset."""

    applied: bool
    persisted: bool
    last_service_at: Optional[str] = None  # ISO timestamp actually written to state


def _build_banner(
    snapshots: dict[int, InputPlaybackSnapshot],
    *,
    overdue_filter: Callable,
    warning_filter: Callable,
    overdue_single: Callable,
    overdue_multi: str,
    warning_single: Callable,
    warning_multi: str,
    overdue_sort_key: Optional[Callable] = None,
    warning_sort_key: Optional[Callable] = None,
) -> Optional[str]:
    """Generic maintenance banner builder — returns a short string or None."""
    overdue = sorted(
        (s for s in snapshots.values() if overdue_filter(s)),
        key=overdue_sort_key or (lambda s: s.input_index),
    )
    if overdue:
        return overdue_single(overdue[0]) if len(overdue) == 1 else overdue_multi
    warning = sorted(
        (s for s in snapshots.values() if warning_filter(s)),
        key=warning_sort_key or (lambda s: s.input_index),
    )
    if not warning:
        return None
    return warning_single(warning[0]) if len(warning) == 1 else warning_multi


def build_stylus_warning_text(
    snapshots: dict[int, InputPlaybackSnapshot],
) -> Optional[str]:
    """Return a concise banner string, or None if no stylus warning is needed."""
    return _build_banner(
        snapshots,
        overdue_filter=lambda s: s.enabled and s.stylus_life_hours > 0 and s.stylus_overdue,
        warning_filter=lambda s: s.enabled and s.stylus_life_hours > 0 and s.stylus_warning,
        overdue_single=lambda s: f"{s.label} stylus needs changing now.",
        overdue_multi="Stylus replacement needed on multiple inputs.",
        warning_single=lambda s: (
            f"{s.label} stylus needs changing soon ({s.stylus_remaining_hours:.1f} h remaining)."
            if s.stylus_remaining_hours is not None
            else f"{s.label} stylus needs changing soon (replacement due soon)."
        ),
        warning_multi="Stylus replacement due soon on multiple inputs.",
        warning_sort_key=lambda s: (
            s.stylus_remaining_seconds if s.stylus_remaining_seconds is not None else 10**18,
            s.input_index,
        ),
    )


def build_belt_banner_text(
    snapshots: dict[int, InputPlaybackSnapshot],
) -> Optional[str]:
    """Return a concise banner string for drive belt, or None if no warning."""
    return _build_banner(
        snapshots,
        overdue_filter=lambda s: s.enabled and s.belt_overdue,
        warning_filter=lambda s: s.enabled and s.belt_warning,
        overdue_single=lambda s: f"{s.label} drive belt needs attention now.",
        overdue_multi="Drive belt service needed on multiple inputs.",
        warning_single=lambda s: f"{s.label} drive belt service is due soon.",
        warning_multi="Drive belt service due soon on multiple inputs.",
    )


def build_bearing_banner_text(
    snapshots: dict[int, InputPlaybackSnapshot],
) -> Optional[str]:
    """Return a concise banner string for main bearing oil, or None if no warning."""
    return _build_banner(
        snapshots,
        overdue_filter=lambda s: s.enabled and s.bearing_overdue,
        warning_filter=lambda s: s.enabled and s.bearing_warning,
        overdue_single=lambda s: f"{s.label} main bearing needs attention now.",
        overdue_multi="Main bearing service needed on multiple inputs.",
        warning_single=lambda s: f"{s.label} main bearing service is due soon.",
        warning_multi="Main bearing service due soon on multiple inputs.",
    )


class PlaybackTracker:
    """Thread-safe playback-hours tracker with periodic JSON persistence."""

    def __init__(
        self,
        stats_path: Optional[str | Path] = None,
        *,
        flush_interval_seconds: float = DEFAULT_FLUSH_INTERVAL_SECONDS,
        time_fn: Optional[Callable[[], float]] = None,
    ) -> None:
        self.stats_path = Path(stats_path or DEFAULT_PLAYBACK_STATS_PATH).expanduser()
        self.flush_interval_seconds = max(1.0, float(flush_interval_seconds))
        self._time_fn = time_fn or time.time
        self._lock = threading.RLock()
        self._configs: dict[int, PlaybackInputConfig] = {}
        self._states: dict[int, PlaybackInputState] = {}
        self._active_since: dict[int, float] = {}
        self._dirty = False
        self._last_persist_at = self._time_fn()
        self._last_save_error_log_at = 0.0
        self._load_locked()

    def replace_input_configs(
        self,
        configs: dict[int, PlaybackInputConfig],
    ) -> None:
        """Replace the full set of known input configs."""
        with self._lock:
            now = self._time_fn()
            self._accrue_all_active_locked(now)
            self._configs = {
                self._normalize_input_index(idx): PlaybackInputConfig.normalized(
                    enabled=cfg.enabled,
                    is_turntable=cfg.is_turntable,
                    stylus_life_hours=cfg.stylus_life_hours,
                    belt_life_hours=cfg.belt_life_hours,
                    belt_life_years=cfg.belt_life_years,
                    bearing_life_hours=cfg.bearing_life_hours,
                    bearing_life_years=cfg.bearing_life_years,
                )
                for idx, cfg in configs.items()
            }
            for idx, cfg in self._configs.items():
                if not cfg.enabled:
                    self._active_since.pop(idx, None)

    def update_input_config(
        self,
        input_index: int,
        *,
        enabled: bool,
        is_turntable: bool,
        stylus_life_hours: object,
        belt_life_hours: object = 0,
        belt_life_years: object = 0,
        bearing_life_hours: object = 0,
        bearing_life_years: object = 0,
    ) -> None:
        """Update config for a single input, splitting active time at the change."""
        idx = self._normalize_input_index(input_index)
        with self._lock:
            self._accrue_input_locked(idx, self._time_fn())
            cfg = PlaybackInputConfig.normalized(
                enabled=enabled,
                is_turntable=is_turntable,
                stylus_life_hours=stylus_life_hours,
                belt_life_hours=belt_life_hours,
                belt_life_years=belt_life_years,
                bearing_life_hours=bearing_life_hours,
                bearing_life_years=bearing_life_years,
            )
            self._configs[idx] = cfg
            if not cfg.enabled:
                self._active_since.pop(idx, None)

    def on_playback_started(self, input_index: int) -> None:
        """Mark an input as actively playing audible audio."""
        idx = self._normalize_input_index(input_index)
        with self._lock:
            cfg = self._configs.get(idx, PlaybackInputConfig())
            if not cfg.enabled:
                self._active_since.pop(idx, None)
                return
            self._ensure_input_state_locked(idx)
            self._active_since.setdefault(idx, self._time_fn())

    def on_playback_stopped(self, input_index: int) -> None:
        """Mark an input as no longer playing audible audio."""
        idx = self._normalize_input_index(input_index)
        with self._lock:
            self._accrue_input_locked(idx, self._time_fn())
            self._active_since.pop(idx, None)
            if self._dirty:
                self._save_best_effort_locked(force=True, context="playback stop")

    def sync_playback_state(self, input_index: int, active: bool) -> None:
        """Convenience wrapper for callers that already know the target state."""
        if active:
            self.on_playback_started(input_index)
        else:
            self.on_playback_stopped(input_index)

    def _reset_item_locked(
        self,
        idx: int,
        playback_attr: str,
        date_attr: str,
        item_name: str,
    ) -> MaintenanceResetResult:
        """Zero one maintenance counter and record today's date. Lock must be held."""
        now = self._time_fn()
        now_iso = _utc_now_iso(now)
        self._accrue_input_locked(idx, now)
        state = self._ensure_input_state_locked(idx)
        setattr(state, playback_attr, 0)
        setattr(state, date_attr, now_iso)
        if idx in self._active_since:
            self._active_since[idx] = now
        self._dirty = True
        try:
            self._save_locked(force=True)
        except Exception as exc:
            self._log_save_failure_locked(f"{item_name} reset", exc)
            return MaintenanceResetResult(applied=True, persisted=False, last_service_at=now_iso)
        return MaintenanceResetResult(applied=True, persisted=True, last_service_at=now_iso)

    def reset_stylus(self, input_index: int) -> MaintenanceResetResult:
        """Reset stylus usage for an input and persist immediately."""
        idx = self._normalize_input_index(input_index)
        with self._lock:
            return self._reset_item_locked(
                idx, "stylus_playback_seconds", "last_stylus_reset_at", "stylus"
            )

    def reset_belt(self, input_index: int) -> MaintenanceResetResult:
        """Reset belt usage counter and record service date for an input."""
        idx = self._normalize_input_index(input_index)
        with self._lock:
            return self._reset_item_locked(
                idx, "belt_playback_seconds", "last_belt_service_at", "belt"
            )

    def reset_bearing(self, input_index: int) -> MaintenanceResetResult:
        """Reset bearing oil usage counter and record service date for an input."""
        idx = self._normalize_input_index(input_index)
        with self._lock:
            return self._reset_item_locked(
                idx, "bearing_playback_seconds", "last_bearing_service_at", "bearing"
            )

    def maybe_flush(self) -> None:
        """Persist dirty counters if the flush interval has elapsed."""
        with self._lock:
            now = self._time_fn()
            self._accrue_all_active_locked(now)
            if self._dirty and (now - self._last_persist_at) >= self.flush_interval_seconds:
                self._save_best_effort_locked(force=True, context="periodic flush")

    def save(self) -> None:
        """Force an immediate checkpoint to disk."""
        with self._lock:
            self._accrue_all_active_locked(self._time_fn())
            self._save_best_effort_locked(force=True, context="save")

    def close(self) -> None:
        """Flush current counters before shutdown/reload."""
        self.save()

    def snapshot(self) -> PlaybackSnapshot:
        """Return the current in-memory view including active sessions."""
        with self._lock:
            now = self._time_fn()
            indices = sorted(set(self._states) | set(self._configs) | set(self._active_since))
            inputs: dict[int, InputPlaybackSnapshot] = {}

            for idx in indices:
                cfg = self._configs.get(idx, PlaybackInputConfig())
                state = self._states.get(idx, PlaybackInputState())
                active_since = None if not cfg.enabled else self._active_since.get(idx)

                total_seconds = int(state.total_playback_seconds)
                stylus_seconds = int(state.stylus_playback_seconds)
                belt_seconds = int(state.belt_playback_seconds)
                bearing_seconds = int(state.bearing_playback_seconds)
                active = active_since is not None

                if active_since is not None and now > active_since:
                    elapsed = int(now - active_since)
                    if elapsed > 0:
                        total_seconds += elapsed
                        if cfg.is_turntable and cfg.stylus_life_hours > 0:
                            stylus_seconds += elapsed
                        if cfg.is_turntable and cfg.belt_life_hours > 0:
                            belt_seconds += elapsed
                        if cfg.is_turntable and cfg.bearing_life_hours > 0:
                            bearing_seconds += elapsed

                # --- Stylus calculations ---
                _turntable = cfg.is_turntable
                stylus_remaining_seconds, stylus_overdue, stylus_warning = _calc_item_hours(
                    cfg.stylus_life_hours if _turntable else 0,
                    stylus_seconds,
                    STYLUS_WARNING_SECONDS,
                )
                stylus_remaining_hours = (
                    round(stylus_remaining_seconds / 3600.0, 1)
                    if stylus_remaining_seconds is not None else None
                )

                # --- Belt calculations ---
                belt_hours_remaining, belt_hours_overdue, belt_hours_warning = _calc_item_hours(
                    cfg.belt_life_hours if _turntable else 0,
                    belt_seconds,
                    MAINTENANCE_HOURS_WARNING_SECONDS,
                )

                belt_elapsed_days: Optional[int] = None
                belt_time_overdue = False
                belt_time_warning = False

                if _turntable and cfg.belt_life_years > 0:
                    belt_elapsed_days = _days_elapsed_since(state.last_belt_service_at, now)
                    if belt_elapsed_days is not None:
                        belt_threshold_days = cfg.belt_life_years * 365
                        belt_time_overdue = belt_elapsed_days >= belt_threshold_days
                        belt_time_warning = (
                            not belt_time_overdue
                            and belt_elapsed_days >= belt_threshold_days - MAINTENANCE_TIME_WARNING_DAYS
                        )

                belt_overdue = belt_hours_overdue or belt_time_overdue
                belt_warning = (belt_hours_warning or belt_time_warning) and not belt_overdue

                # --- Bearing calculations ---
                bearing_hours_remaining, bearing_hours_overdue, bearing_hours_warning = _calc_item_hours(
                    cfg.bearing_life_hours if _turntable else 0,
                    bearing_seconds,
                    MAINTENANCE_HOURS_WARNING_SECONDS,
                )

                bearing_elapsed_days: Optional[int] = None
                bearing_time_overdue = False
                bearing_time_warning = False

                if _turntable and cfg.bearing_life_years > 0:
                    bearing_elapsed_days = _days_elapsed_since(
                        state.last_bearing_service_at, now
                    )
                    if bearing_elapsed_days is not None:
                        bearing_threshold_days = cfg.bearing_life_years * 365
                        bearing_time_overdue = bearing_elapsed_days >= bearing_threshold_days
                        bearing_time_warning = (
                            not bearing_time_overdue
                            and bearing_elapsed_days >= bearing_threshold_days - MAINTENANCE_TIME_WARNING_DAYS
                        )

                bearing_overdue = bearing_hours_overdue or bearing_time_overdue
                bearing_warning = (
                    (bearing_hours_warning or bearing_time_warning) and not bearing_overdue
                )

                inputs[idx] = InputPlaybackSnapshot(
                    input_index=idx,
                    label=input_label(idx),
                    active=active,
                    enabled=cfg.enabled,
                    is_turntable=cfg.is_turntable,
                    total_playback_seconds=total_seconds,
                    total_playback_hours=hours_from_seconds(total_seconds),
                    # Stylus
                    stylus_playback_seconds=stylus_seconds,
                    stylus_playback_hours=hours_from_seconds(stylus_seconds),
                    stylus_life_hours=cfg.stylus_life_hours,
                    stylus_remaining_seconds=stylus_remaining_seconds,
                    stylus_remaining_hours=stylus_remaining_hours,
                    stylus_warning=stylus_warning,
                    stylus_overdue=stylus_overdue,
                    last_stylus_reset_at=state.last_stylus_reset_at,
                    # Belt
                    belt_life_hours=cfg.belt_life_hours,
                    belt_playback_seconds=belt_seconds,
                    belt_playback_hours=hours_from_seconds(belt_seconds),
                    belt_hours_remaining=belt_hours_remaining,
                    belt_hours_overdue=belt_hours_overdue,
                    belt_hours_warning=belt_hours_warning,
                    belt_life_years=cfg.belt_life_years,
                    belt_elapsed_days=belt_elapsed_days,
                    belt_time_overdue=belt_time_overdue,
                    belt_time_warning=belt_time_warning,
                    belt_overdue=belt_overdue,
                    belt_warning=belt_warning,
                    last_belt_service_at=state.last_belt_service_at,
                    # Bearing
                    bearing_life_hours=cfg.bearing_life_hours,
                    bearing_playback_seconds=bearing_seconds,
                    bearing_playback_hours=hours_from_seconds(bearing_seconds),
                    bearing_hours_remaining=bearing_hours_remaining,
                    bearing_hours_overdue=bearing_hours_overdue,
                    bearing_hours_warning=bearing_hours_warning,
                    bearing_life_years=cfg.bearing_life_years,
                    bearing_elapsed_days=bearing_elapsed_days,
                    bearing_time_overdue=bearing_time_overdue,
                    bearing_time_warning=bearing_time_warning,
                    bearing_overdue=bearing_overdue,
                    bearing_warning=bearing_warning,
                    last_bearing_service_at=state.last_bearing_service_at,
                )

            def _sorted_indices(condition):
                return tuple(
                    snap.input_index
                    for snap in sorted(inputs.values(), key=lambda s: s.input_index)
                    if condition(snap)
                )

            return PlaybackSnapshot(
                inputs=inputs,
                stylus_warning_indices=_sorted_indices(
                    lambda s: s.enabled and s.stylus_life_hours > 0
                    and s.stylus_warning and not s.stylus_overdue
                ),
                stylus_overdue_indices=_sorted_indices(
                    lambda s: s.enabled and s.stylus_life_hours > 0 and s.stylus_overdue
                ),
                stylus_banner_text=build_stylus_warning_text(inputs),
                belt_warning_indices=_sorted_indices(
                    lambda s: s.enabled and s.belt_warning and not s.belt_overdue
                ),
                belt_overdue_indices=_sorted_indices(
                    lambda s: s.enabled and s.belt_overdue
                ),
                belt_banner_text=build_belt_banner_text(inputs),
                bearing_warning_indices=_sorted_indices(
                    lambda s: s.enabled and s.bearing_warning and not s.bearing_overdue
                ),
                bearing_overdue_indices=_sorted_indices(
                    lambda s: s.enabled and s.bearing_overdue
                ),
                bearing_banner_text=build_bearing_banner_text(inputs),
            )

    def get_input_snapshot(self, input_index: int) -> InputPlaybackSnapshot:
        """Return the snapshot for a single input slot."""
        idx = self._normalize_input_index(input_index)
        snap = self.snapshot().inputs.get(idx)
        if snap is not None:
            return snap

        cfg = self._configs.get(idx, PlaybackInputConfig())
        return InputPlaybackSnapshot(
            input_index=idx,
            label=input_label(idx),
            active=False,
            enabled=cfg.enabled,
            is_turntable=cfg.is_turntable,
            total_playback_seconds=0,
            total_playback_hours=0.0,
            stylus_playback_seconds=0,
            stylus_playback_hours=0.0,
            stylus_life_hours=cfg.stylus_life_hours,
            stylus_remaining_seconds=(
                int(cfg.stylus_life_hours * 3600)
                if cfg.is_turntable and cfg.stylus_life_hours > 0
                else None
            ),
            stylus_remaining_hours=(
                float(cfg.stylus_life_hours)
                if cfg.is_turntable and cfg.stylus_life_hours > 0
                else None
            ),
            stylus_warning=False,
            stylus_overdue=False,
            last_stylus_reset_at=None,
            belt_life_hours=cfg.belt_life_hours,
            belt_playback_seconds=0,
            belt_playback_hours=0.0,
            belt_hours_remaining=(
                int(cfg.belt_life_hours * 3600)
                if cfg.is_turntable and cfg.belt_life_hours > 0
                else None
            ),
            belt_hours_overdue=False,
            belt_hours_warning=False,
            belt_life_years=cfg.belt_life_years,
            belt_elapsed_days=None,
            belt_time_overdue=False,
            belt_time_warning=False,
            belt_overdue=False,
            belt_warning=False,
            last_belt_service_at=None,
            bearing_life_hours=cfg.bearing_life_hours,
            bearing_playback_seconds=0,
            bearing_playback_hours=0.0,
            bearing_hours_remaining=(
                int(cfg.bearing_life_hours * 3600)
                if cfg.is_turntable and cfg.bearing_life_hours > 0
                else None
            ),
            bearing_hours_overdue=False,
            bearing_hours_warning=False,
            bearing_life_years=cfg.bearing_life_years,
            bearing_elapsed_days=None,
            bearing_time_overdue=False,
            bearing_time_warning=False,
            bearing_overdue=False,
            bearing_warning=False,
            last_bearing_service_at=None,
        )

    def public_snapshot_dict(self) -> dict:
        """Return a JSON-ready snapshot for future API/UI use."""
        return self.snapshot().to_public_dict()

    def _load_locked(self) -> None:
        raw = _read_json_object(self.stats_path)
        inputs_raw = raw.get("inputs")
        if not isinstance(inputs_raw, dict):
            self._states = {}
            self._dirty = False
            self._last_persist_at = self._time_fn()
            return

        loaded: dict[int, PlaybackInputState] = {}
        for raw_key, raw_value in inputs_raw.items():
            try:
                idx = self._normalize_input_index(raw_key)
            except ValueError:
                continue
            loaded[idx] = PlaybackInputState.from_json_obj(raw_value)

        self._states = loaded
        self._dirty = False
        self._last_persist_at = self._time_fn()

    def _save_locked(self, *, force: bool) -> None:
        if not force and not self._dirty:
            return

        payload = {
            "schema_version": PLAYBACK_SCHEMA_VERSION,
            "updated_at": _utc_now_iso(self._time_fn()),
            "inputs": {
                str(idx): state.to_json_obj()
                for idx, state in sorted(self._states.items())
            },
        }

        _atomic_write_json(self.stats_path, payload)
        self._dirty = False
        self._last_persist_at = self._time_fn()
        self._last_save_error_log_at = 0.0

    def _save_best_effort_locked(self, *, force: bool, context: str) -> None:
        try:
            self._save_locked(force=force)
        except Exception as exc:
            self._log_save_failure_locked(context, exc)

    def _log_save_failure_locked(self, context: str, exc: Exception) -> None:
        now = self._time_fn()
        if (
            self._last_save_error_log_at <= 0.0
            or (now - self._last_save_error_log_at) >= SAVE_ERROR_LOG_INTERVAL_SECONDS
        ):
            LOGGER.warning(
                "Failed to persist playback stats during %s to %s: %s",
                context,
                self.stats_path,
                exc,
            )
            self._last_save_error_log_at = now

    def _ensure_input_state_locked(self, input_index: int) -> PlaybackInputState:
        idx = self._normalize_input_index(input_index)
        state = self._states.get(idx)
        if state is None:
            state = PlaybackInputState()
            self._states[idx] = state
        return state

    def _accrue_all_active_locked(self, now: float) -> None:
        for idx in list(self._active_since):
            self._accrue_input_locked(idx, now)

    def _accrue_input_locked(self, input_index: int, now: float) -> None:
        idx = self._normalize_input_index(input_index)
        active_since = self._active_since.get(idx)
        if active_since is None or now <= active_since:
            return

        elapsed = int(now - active_since)
        if elapsed <= 0:
            return

        state = self._ensure_input_state_locked(idx)
        cfg = self._configs.get(idx, PlaybackInputConfig())

        state.total_playback_seconds += elapsed
        if cfg.is_turntable and cfg.stylus_life_hours > 0:
            state.stylus_playback_seconds += elapsed
        if cfg.is_turntable and cfg.belt_life_hours > 0:
            state.belt_playback_seconds += elapsed
        if cfg.is_turntable and cfg.bearing_life_hours > 0:
            state.bearing_playback_seconds += elapsed

        # Preserve any sub-second remainder so repeated accrual does not drift.
        self._active_since[idx] = active_since + elapsed
        self._dirty = True

    @staticmethod
    def _normalize_input_index(value: object) -> int:
        idx = int(str(value).strip())
        if idx <= 0:
            raise ValueError(f"Invalid input index: {value!r}")
        return idx
