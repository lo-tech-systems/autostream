#!/usr/bin/env python3
"""autostream_playback.py

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

from autostream_sysutils import atomic_write_file


LOGGER = logging.getLogger(__name__)


PLAYBACK_SCHEMA_VERSION = 1
DEFAULT_FLUSH_INTERVAL_SECONDS = 300.0

DEFAULT_PLAYBACK_STATS_PATH = Path(
    os.environ.get(
        "AUTOSTREAM_PLAYBACK_STATS_PATH",
        "/opt/autostream/playback_stats.json",
    )
).expanduser()

DEFAULT_STYLUS_LIFE_HOURS = 500
VALID_STYLUS_LIFE_HOURS = (100, 250, 500, 750, 1000)

TURNTABLE_SILENCE_THRESHOLD_DBFS = -45.0
LINE_LEVEL_SILENCE_THRESHOLD_DBFS = -60.0

STYLUS_WARNING_HOURS = 10.0
STYLUS_WARNING_SECONDS = int(STYLUS_WARNING_HOURS * 3600)
SAVE_ERROR_LOG_INTERVAL_SECONDS = 60.0


def get_default_playback_stats_path() -> Path:
    """Return the default JSON path used for persisted playback stats."""
    return DEFAULT_PLAYBACK_STATS_PATH


def get_stylus_life_options() -> tuple[int, ...]:
    """Return the supported stylus-life options for UI dropdowns."""
    return VALID_STYLUS_LIFE_HOURS


def suggested_silence_threshold_dbfs(is_turntable: bool) -> float:
    """Return the recommended silence threshold preset for the input type."""
    return (
        TURNTABLE_SILENCE_THRESHOLD_DBFS
        if bool(is_turntable)
        else LINE_LEVEL_SILENCE_THRESHOLD_DBFS
    )


def normalize_stylus_life_hours(
    value: object,
    default: int = DEFAULT_STYLUS_LIFE_HOURS,
) -> int:
    """Return a safe positive stylus-life value in hours."""
    try:
        hours = int(str(value).strip())
    except Exception:
        return int(default)
    return hours if hours > 0 else int(default)


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

    @classmethod
    def normalized(
        cls,
        *,
        enabled: bool = True,
        is_turntable: bool = False,
        stylus_life_hours: object = DEFAULT_STYLUS_LIFE_HOURS,
    ) -> "PlaybackInputConfig":
        return cls(
            enabled=bool(enabled),
            is_turntable=bool(is_turntable),
            stylus_life_hours=normalize_stylus_life_hours(stylus_life_hours),
        )


@dataclass
class PlaybackInputState:
    """Persisted counters for a single input slot."""

    total_playback_seconds: int = 0
    stylus_playback_seconds: int = 0
    last_stylus_reset_at: Optional[str] = None

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
        }


@dataclass(frozen=True)
class InputPlaybackSnapshot:
    """Calculated playback view for one input, ready for UI consumption."""

    input_index: int
    label: str
    active: bool
    enabled: bool
    is_turntable: bool
    total_playback_seconds: int
    total_playback_hours: float
    stylus_playback_seconds: int
    stylus_playback_hours: float
    stylus_life_hours: int
    stylus_remaining_seconds: Optional[int]
    stylus_remaining_hours: Optional[float]
    stylus_warning: bool
    stylus_overdue: bool
    last_stylus_reset_at: Optional[str]

    def to_public_dict(self) -> dict:
        return {
            "input_index": int(self.input_index),
            "label": self.label,
            "active": bool(self.active),
            "enabled": bool(self.enabled),
            "is_turntable": bool(self.is_turntable),
            "total_playback_seconds": int(self.total_playback_seconds),
            "total_playback_hours": float(self.total_playback_hours),
            "stylus_playback_seconds": int(self.stylus_playback_seconds),
            "stylus_playback_hours": float(self.stylus_playback_hours),
            "stylus_life_hours": int(self.stylus_life_hours),
            "stylus_remaining_seconds": (
                None
                if self.stylus_remaining_seconds is None
                else int(self.stylus_remaining_seconds)
            ),
            "stylus_remaining_hours": (
                None
                if self.stylus_remaining_hours is None
                else float(self.stylus_remaining_hours)
            ),
            "stylus_warning": bool(self.stylus_warning),
            "stylus_overdue": bool(self.stylus_overdue),
            "last_stylus_reset_at": self.last_stylus_reset_at,
        }


@dataclass(frozen=True)
class PlaybackSnapshot:
    """Combined playback snapshot for all tracked inputs."""

    inputs: dict[int, InputPlaybackSnapshot]
    warning_input_indices: tuple[int, ...]
    overdue_input_indices: tuple[int, ...]
    banner_text: Optional[str]

    @property
    def has_warning(self) -> bool:
        return bool(self.warning_input_indices or self.overdue_input_indices)

    def to_public_dict(self) -> dict:
        return {
            "inputs": {
                str(idx): snap.to_public_dict()
                for idx, snap in sorted(self.inputs.items())
            },
            "warning_input_indices": [int(i) for i in self.warning_input_indices],
            "overdue_input_indices": [int(i) for i in self.overdue_input_indices],
            "banner_text": self.banner_text,
            "has_warning": self.has_warning,
        }


@dataclass(frozen=True)
class StylusResetResult:
    """Result of a user-requested stylus reset."""

    applied: bool
    persisted: bool


def build_stylus_warning_text(
    snapshots: dict[int, InputPlaybackSnapshot],
) -> Optional[str]:
    """Return a concise banner string, or None if no warning is needed."""
    overdue = sorted(
        (
            snap
            for snap in snapshots.values()
            if snap.enabled and snap.stylus_overdue
        ),
        key=lambda snap: snap.input_index,
    )
    if overdue:
        if len(overdue) == 1:
            return f"{overdue[0].label} stylus needs changing now."
        return "Stylus replacement needed on multiple inputs."

    warning = sorted(
        (
            snap
            for snap in snapshots.values()
            if snap.enabled and snap.stylus_warning
        ),
        key=lambda snap: (
            snap.stylus_remaining_seconds
            if snap.stylus_remaining_seconds is not None
            else 10**18,
            snap.input_index,
        ),
    )
    if not warning:
        return None
    if len(warning) == 1:
        remaining = warning[0].stylus_remaining_hours
        remaining_txt = (
            f"{remaining:.1f} h remaining"
            if remaining is not None
            else "replacement due soon"
        )
        return f"{warning[0].label} stylus needs changing soon ({remaining_txt})."
    return "Stylus replacement due soon on multiple inputs."


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
    ) -> None:
        """Update config for a single input, splitting active time at the change."""
        idx = self._normalize_input_index(input_index)
        with self._lock:
            self._accrue_input_locked(idx, self._time_fn())
            cfg = PlaybackInputConfig.normalized(
                enabled=enabled,
                is_turntable=is_turntable,
                stylus_life_hours=stylus_life_hours,
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

    def reset_stylus(self, input_index: int) -> StylusResetResult:
        """Reset stylus usage for an input and persist immediately."""
        idx = self._normalize_input_index(input_index)
        with self._lock:
            now = self._time_fn()
            self._accrue_input_locked(idx, now)
            state = self._ensure_input_state_locked(idx)
            state.stylus_playback_seconds = 0
            state.last_stylus_reset_at = _utc_now_iso(now)
            if idx in self._active_since:
                self._active_since[idx] = now
            self._dirty = True
            try:
                self._save_locked(force=True)
            except Exception as exc:
                self._log_save_failure_locked("stylus reset", exc)
                return StylusResetResult(applied=True, persisted=False)
            return StylusResetResult(applied=True, persisted=True)

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
                active = active_since is not None

                if active_since is not None and now > active_since:
                    elapsed = int(now - active_since)
                    if elapsed > 0:
                        total_seconds += elapsed
                        if cfg.is_turntable:
                            stylus_seconds += elapsed

                stylus_remaining_seconds: Optional[int] = None
                stylus_remaining_hours: Optional[float] = None
                stylus_warning = False
                stylus_overdue = False

                if cfg.is_turntable:
                    stylus_remaining_seconds = (
                        int(cfg.stylus_life_hours * 3600) - stylus_seconds
                    )
                    stylus_remaining_hours = round(stylus_remaining_seconds / 3600.0, 1)
                    stylus_overdue = stylus_remaining_seconds <= 0
                    stylus_warning = stylus_remaining_seconds < STYLUS_WARNING_SECONDS

                inputs[idx] = InputPlaybackSnapshot(
                    input_index=idx,
                    label=input_label(idx),
                    active=active,
                    enabled=cfg.enabled,
                    is_turntable=cfg.is_turntable,
                    total_playback_seconds=total_seconds,
                    total_playback_hours=hours_from_seconds(total_seconds),
                    stylus_playback_seconds=stylus_seconds,
                    stylus_playback_hours=hours_from_seconds(stylus_seconds),
                    stylus_life_hours=cfg.stylus_life_hours,
                    stylus_remaining_seconds=stylus_remaining_seconds,
                    stylus_remaining_hours=stylus_remaining_hours,
                    stylus_warning=stylus_warning,
                    stylus_overdue=stylus_overdue,
                    last_stylus_reset_at=state.last_stylus_reset_at,
                )

            warning_indices = tuple(
                snap.input_index
                for snap in sorted(inputs.values(), key=lambda snap: snap.input_index)
                if snap.enabled and snap.stylus_warning and not snap.stylus_overdue
            )
            overdue_indices = tuple(
                snap.input_index
                for snap in sorted(inputs.values(), key=lambda snap: snap.input_index)
                if snap.enabled and snap.stylus_overdue
            )

            return PlaybackSnapshot(
                inputs=inputs,
                warning_input_indices=warning_indices,
                overdue_input_indices=overdue_indices,
                banner_text=build_stylus_warning_text(inputs),
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
                int(cfg.stylus_life_hours * 3600) if cfg.is_turntable else None
            ),
            stylus_remaining_hours=(
                float(cfg.stylus_life_hours) if cfg.is_turntable else None
            ),
            stylus_warning=False,
            stylus_overdue=False,
            last_stylus_reset_at=None,
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
        if cfg.is_turntable:
            state.stylus_playback_seconds += elapsed

        # Preserve any sub-second remainder so repeated accrual does not drift.
        self._active_since[idx] = active_since + elapsed
        self._dirty = True

    @staticmethod
    def _normalize_input_index(value: object) -> int:
        idx = int(str(value).strip())
        if idx <= 0:
            raise ValueError(f"Invalid input index: {value!r}")
        return idx
