"""autostream_live_config -- settings whose change takes effect while running.

A settings field with a live effect names a function that applies the new
value to the running appliance: the repeat policy, input gain and equaliser,
the OwnTone output and volume, the silence timeout and threshold, the input
type, Dynamic Rate Matching, the audio path, the capture devices, and track
identification. Each change is validated by the settings route, stored, and
then applied here without a restart where the field allows it.

The routes and the Setup form reach this module through intents: saving,
reloading and applying settings, the advertisement and automatic-update
switches, and the coordinator reload are rows bound at the bottom of the
file. The coordinator's own functions (publishing the inputs, the playback
tracker's input configuration, the track identification service) are reached
through one set of hooks that the coordinator binds at import.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, replace
from typing import Callable, Optional

import autostream_monitor_client as monitor_client
import autostream_monitor_control as monitor_control
import autostream_runtime as runtime
from autostream_bluetooth_client import (
    bluetooth_installed,
    classify_loopback_hw,
    is_loopback_playback,
)
from autostream_config import (
    AUDIO_PATH_CHOICES,
    CONFIG_IO_LOCK,
    REPEAT_CODEC_CHOICES,
    SILENCE_THRESHOLD_MAX_DBFS,
    SILENCE_THRESHOLD_MIN_DBFS,
    input_type_silence_threshold_dbfs,
    load_config,
    normalize_airplay_mode,
    normalize_input_type,
    normalize_repeat_codec,
    normalize_track_id_analysis_lead_in_seconds,
    normalize_track_id_refresh_seconds,
    normalize_track_id_track_change_silence_seconds,
    save_config,
    set_input_type,
)
from autostream_debounce import default_debouncer
from autostream_intents.table import Intent, Outcome, bind, submit
from autostream_player_service import push_resample_quality, sync_monitor_args_for_audio_path
from autostream_rpi import is_high_performance_pi
from autostream_settings import SettingsStore
from autostream_settings_schema import (
    CrossFieldValidationError,
    LiveClass,
    cross_validate_capture_device_unique,
    get_field_spec,
    register_field,
)
from autostream_state import Origin, store
from autostream_sysutils import run_admin_cmd

_OWNER = "autostream_live_config"


# ---------------------------------------------------------------------------
# Coordinator hooks
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CoordinatorHooks:
    """The coordinator functions this module calls. The coordinator owns them
    and binds them once, at import; this module never imports the coordinator."""

    publish_inputs: Callable[[], None]
    apply_track_id_config_live: Callable[[str], None]
    apply_track_id_config_live_from_parsed: Callable[[object], None]
    update_playback_input_config: Callable[..., object]


_coordinator: Optional[CoordinatorHooks] = None


def bind_coordinator(hooks: CoordinatorHooks) -> None:
    global _coordinator
    _coordinator = hooks


def _hooks() -> CoordinatorHooks:
    if _coordinator is None:
        raise RuntimeError("the coordinator has not bound its hooks")
    return _coordinator


def _store_of(state: object) -> Optional[SettingsStore]:
    settings = getattr(state, "settings", None)
    return settings if isinstance(settings, SettingsStore) else None


def _validate_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    raise ValueError("Value must be true or false")


def _validate_gain_db(value: object) -> float:
    import math
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Value must be a number")
    v = float(value)
    if not math.isfinite(v) or v < -10.0 or v > 10.0:
        raise ValueError("Value must be between -10 and 10")
    return v


def _live_gain_1(state: object, value: object) -> bool:
    return bool(monitor_control.set_live_input_gain(1, float(value)))


def _live_gain_2(state: object, value: object) -> bool:
    return bool(monitor_control.set_live_input_gain(2, float(value)))


def _live_eq_1(state: object, value: object) -> bool:
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if not isinstance(settings, _SettingsStore):
        return False
    snap = settings.snapshot()
    return bool(monitor_control.set_live_input_eq(
        1,
        eq_40hz_db=snap.audio1.eq_40hz_db,
        eq_100hz_db=snap.audio1.eq_100hz_db,
        eq_8khz_db=snap.audio1.eq_8khz_db,
    ))


def _live_eq_2(state: object, value: object) -> bool:
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if not isinstance(settings, _SettingsStore):
        return False
    snap = settings.snapshot()
    return bool(monitor_control.set_live_input_eq(
        2,
        eq_40hz_db=snap.audio2.eq_40hz_db,
        eq_100hz_db=snap.audio2.eq_100hz_db,
        eq_8khz_db=snap.audio2.eq_8khz_db,
    ))


def _validate_repeat_codec(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError(f"Value must be one of {', '.join(REPEAT_CODEC_CHOICES)}")
    v = value.strip().lower()
    if v not in REPEAT_CODEC_CHOICES:
        raise ValueError(f"Value must be one of {', '.join(REPEAT_CODEC_CHOICES)}")
    return normalize_repeat_codec(v)


# Browser-editable buffer-target choices: Vinyl / CD. Direct config-file
# edits still accept any value in [REPEAT_TARGET_MINUTES_MIN,
# REPEAT_TARGET_MINUTES_MAX] via normalize_repeat_target_minutes(); this
# validator only guards the Settings-page field.
_REPEAT_TARGET_MINUTES_CHOICES = (33, 80)


def _validate_repeat_target_minutes(value: object) -> int:
    if isinstance(value, bool):
        raise ValueError(
            f"Value must be one of {', '.join(str(c) for c in _REPEAT_TARGET_MINUTES_CHOICES)}"
        )
    try:
        v = int(float(str(value).strip()))
    except Exception:
        raise ValueError(
            f"Value must be one of {', '.join(str(c) for c in _REPEAT_TARGET_MINUTES_CHOICES)}"
        )
    if v not in _REPEAT_TARGET_MINUTES_CHOICES:
        raise ValueError(
            f"Value must be one of {', '.join(str(c) for c in _REPEAT_TARGET_MINUTES_CHOICES)}"
        )
    return v


def _live_repeat_enabled(state: object, value: object) -> bool:
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if not isinstance(settings, _SettingsStore):
        return False
    snap = settings.snapshot()
    return bool(monitor_control.set_live_repeat_enabled(bool(value), snap.repeat.codec, snap.repeat.target_minutes))


def _live_repeat_codec(state: object, value: object) -> bool:
    """Apply a codec-pin change while repeat is enabled.

    Same off/on toggle shape as _live_repeat_target_minutes() below (repeat
    arena redesign): a plain set_enabled(enabled, new_codec)
    call with the daemon already enabled used to just rewrite the pinned
    codec in place, with no re-plan of the (now fixed-per-arena) codec the
    daemon actually records at. Pulsing off then on drives the daemon's own
    config-change re-plan (RepeatController::set_enabled() -- an internal
    disable+enable when target_minutes or codec actually changes while
    staying enabled) so a codec pin takes effect immediately instead of only
    at the next unrelated enable/disable. See _live_repeat_target_minutes()'s
    own docstring for the staleness caveat, which applies identically here.
    """
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if not isinstance(settings, _SettingsStore):
        return False
    snap = settings.snapshot()
    if not snap.repeat.enabled:
        return True

    new_codec = str(value)
    status = store().snapshot().repeat.block or {}
    previous_codec = status.get("codec")
    if previous_codec == new_codec:
        return True

    off_ok = monitor_control.set_live_repeat_enabled(False, new_codec, snap.repeat.target_minutes)
    on_ok = monitor_control.set_live_repeat_enabled(True, new_codec, snap.repeat.target_minutes)
    return bool(off_ok) and bool(on_ok)


def _live_repeat_target_minutes(state: object, value: object) -> bool:
    """Apply a buffer-target change while repeat is enabled.

    By the time a live_fn runs, send_settings_post_json has already
    committed the new value to the settings store (settings.update() runs
    before live_fn is called) -- snap.repeat.target_minutes here is already
    the NEW value, not the one the daemon is currently running with. The
    daemon's own last-reported target (the repeat part) is used as the
    "previous value" instead: it reflects what is actually live, independent
    of settings-store write timing, so it is the only value that can
    correctly answer "did this change from what's running".

    If repeat is currently disabled, the new target just persists -- the
    enable path forwards the stored value, so there is nothing to push now.
    If enabled and the daemon-reported target differs from the new value,
    pulse the policy off then on so the daemon frees any held buffer
    (including an active replay) and re-arms at the new target. If the
    daemon-reported target already matches, no daemon traffic is sent.

    Known bounded staleness: the daemon status cache refreshes on the
    coordinator's poll cycle, so two target changes inside one poll
    interval can compare against a pre-pulse reading and skip a push,
    leaving the daemon on the earlier target until the next repeat policy
    push (enable/codec change or reconnect resync). The buffer note
    reflects the daemon's actual target, so the mismatch is visible and
    recoverable by re-selecting the target.
    """
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if not isinstance(settings, _SettingsStore):
        return False
    snap = settings.snapshot()
    if not snap.repeat.enabled:
        return True

    try:
        new_target = int(value)
    except Exception:
        return False

    status = store().snapshot().repeat.block or {}
    try:
        previous_target = int(status.get("target_minutes"))
    except (TypeError, ValueError):
        previous_target = None

    if previous_target == new_target:
        return True

    off_ok = monitor_control.set_live_repeat_enabled(False, snap.repeat.codec, new_target)
    on_ok = monitor_control.set_live_repeat_enabled(True, snap.repeat.codec, new_target)
    return bool(off_ok) and bool(on_ok)


register_field("repeat.enabled", "repeat", "enabled", _validate_bool, live=_live_repeat_enabled,
               live_class=LiveClass.LIVE)
register_field("repeat.codec", "repeat", "codec", _validate_repeat_codec, live=_live_repeat_codec,
               live_class=LiveClass.LIVE)
register_field("repeat.target_minutes", "repeat", "target_minutes", _validate_repeat_target_minutes,
               live=_live_repeat_target_minutes, live_class=LiveClass.LIVE)
register_field("audio1.gain_db", "audio1", "gain_db", _validate_gain_db, live=_live_gain_1, live_class=LiveClass.LIVE)
register_field("audio2.gain_db", "audio2", "gain_db", _validate_gain_db, live=_live_gain_2, live_class=LiveClass.LIVE)
register_field("audio1.eq_40hz_db", "audio1", "eq_40hz_db", _validate_gain_db, live=_live_eq_1, live_class=LiveClass.LIVE)
register_field("audio1.eq_100hz_db", "audio1", "eq_100hz_db", _validate_gain_db, live=_live_eq_1, live_class=LiveClass.LIVE)
register_field("audio1.eq_8khz_db", "audio1", "eq_8khz_db", _validate_gain_db, live=_live_eq_1, live_class=LiveClass.LIVE)
register_field("audio2.eq_40hz_db", "audio2", "eq_40hz_db", _validate_gain_db, live=_live_eq_2, live_class=LiveClass.LIVE)
register_field("audio2.eq_100hz_db", "audio2", "eq_100hz_db", _validate_gain_db, live=_live_eq_2, live_class=LiveClass.LIVE)
register_field("audio2.eq_8khz_db", "audio2", "eq_8khz_db", _validate_gain_db, live=_live_eq_2, live_class=LiveClass.LIVE)


# ---------------------------------------------------------------------------
# Live pushes to the running monitors
# ---------------------------------------------------------------------------

def _normalize_owntone_output_offsets(
    output_offsets_ms: Optional[dict[str, object]] = None,
) -> dict[str, int]:
    normalized: dict[str, int] = {}
    for raw_key, raw_val in (output_offsets_ms or {}).items():
        key = str(raw_key).strip()
        if not key:
            continue
        try:
            off = int(raw_val)
        except Exception:
            off = 0
        normalized[key] = max(-2000, min(2000, off))
    return normalized


def _normalize_owntone_output_airplay_modes(
    output_airplay_modes: Optional[dict[str, object]] = None,
) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for raw_key, raw_val in (output_airplay_modes or {}).items():
        key = str(raw_key).strip()
        if not key:
            continue
        normalized[key] = normalize_airplay_mode(raw_val)
    return normalized


def update_live_owntone_runtime(
    *,
    output_name: str,
    volume_percent: object,
    output_offsets_ms: Optional[dict[str, object]] = None,
    output_airplay_modes: Optional[dict[str, object]] = None,
) -> bool:
    try:
        live_output_name = str(output_name or "").strip()
        try:
            live_volume_percent = int(str(volume_percent).strip())
        except Exception:
            live_volume_percent = 20
        live_volume_percent = max(0, min(100, live_volume_percent))
        live_output_offsets_ms = _normalize_owntone_output_offsets(output_offsets_ms)
        live_output_airplay_modes = _normalize_owntone_output_airplay_modes(
            output_airplay_modes
        )

        with runtime._monitors_lock:
            for monitor in runtime.all_monitors:
                monitor.owntone_output_name = live_output_name
                monitor.owntone_volume_percent = live_volume_percent
                monitor.owntone_output_offsets_ms = dict(live_output_offsets_ms)
                monitor.owntone_output_airplay_modes = dict(live_output_airplay_modes)
        return True
    except Exception as e:
        logging.warning("Could not update live OwnTone runtime settings: %s", e)
        return False


def update_live_silence_seconds(
    silence_seconds: int,
    *,
    socket_path: Optional[str] = None,
) -> bool:
    """Apply a live silence timeout update to all configured running monitors.

    The monitor daemon supports live updates of silence_seconds via
    configure_input(), so this avoids a full coordinator reload for that single
    setting. Returns True on success, False if the live update could not be
    applied and the caller should fall back to a config reload.
    """
    try:
        live_silence_seconds = max(1, min(3600, int(silence_seconds)))
    except Exception:
        logging.warning(
            "Could not update live silence timeout: invalid value %r",
            silence_seconds,
        )
        return False

    with runtime._monitors_lock:
        snapshot = list(runtime.all_monitors)

    if not snapshot:
        return True

    try:
        with monitor_client._connected_monitor(socket_path) as client:
            if client is None:
                logging.warning(
                    "Could not connect to monitor daemon for live silence timeout update.",
                )
                return False

            for monitor in snapshot:
                if not client.configure_input(
                    monitor.input_index,
                    monitor.input_device,
                    monitor.silence_threshold_dbfs,
                    live_silence_seconds,
                    monitor.track_change_silence_seconds,
                    monitor.minimum_playback_seconds,
                    input_type=monitor.input_type,
                    dynamic_rate_matching=monitor.dynamic_rate_matching,
                ):
                    logging.warning(
                        "Live silence timeout update failed for input %d.",
                        monitor.input_index,
                    )
                    return False

            with runtime._monitors_lock:
                for monitor in runtime.all_monitors:
                    monitor.silence_seconds = live_silence_seconds
            return True
    except Exception as e:
        logging.warning("Could not update live silence timeout: %s", e)
        return False


# A live push to the daemon is tried a few times before it is reported as
# not applied. Each attempt opens its own connection, so a daemon that is
# busy or restarting gets a fresh socket; the gap keeps the whole thing
# well inside the request that asked for it.
LIVE_PUSH_ATTEMPTS = 3
LIVE_PUSH_RETRY_GAP_SECONDS = 0.15


def _push_input_config_with_retry(
    monitor: "AudioMonitor", *, socket_path: Optional[str] = None,
) -> bool:
    """Send one monitor's current configure_input() values to the daemon.

    Returns True on the first acknowledged push, False once every attempt
    has failed. The monitor's attributes are the source of truth, so a
    failed push is repaired by the next reconnect resync. Never raises.
    """
    for attempt in range(1, LIVE_PUSH_ATTEMPTS + 1):
        try:
            with monitor_client._connected_monitor(socket_path) as client:
                if client is not None and client.configure_input(
                    monitor.input_index,
                    monitor.input_device,
                    monitor.silence_threshold_dbfs,
                    monitor.silence_seconds,
                    monitor.track_change_silence_seconds,
                    monitor.minimum_playback_seconds,
                    input_type=monitor.input_type,
                    dynamic_rate_matching=monitor.dynamic_rate_matching,
                ):
                    return True
        except Exception as e:
            logging.warning(
                "Live input config push for input %d failed: %s",
                monitor.input_index, e,
            )
        if attempt < LIVE_PUSH_ATTEMPTS:
            time.sleep(LIVE_PUSH_RETRY_GAP_SECONDS)
    logging.warning(
        "Live input config push for input %d not applied after %d attempts; "
        "it is saved and will be sent when the daemon reconnects.",
        monitor.input_index, LIVE_PUSH_ATTEMPTS,
    )
    return False


def update_live_silence_threshold_dbfs(
    input_index: int,
    silence_threshold_dbfs: float,
    *,
    socket_path: Optional[str] = None,
) -> bool:
    """Apply a live silence-threshold change to one input's running monitor.

    The monitor's cached threshold is updated first, so the value survives
    a failed push and goes out with the next reconnect resync. Returns
    True when the input has no running monitor or the daemon acknowledged
    the push, False when every push attempt failed.
    """
    try:
        live_threshold_dbfs = float(silence_threshold_dbfs)
    except Exception:
        logging.warning(
            "Could not update live silence threshold: invalid value %r",
            silence_threshold_dbfs,
        )
        return False

    with runtime._monitors_lock:
        target = next(
            (m for m in runtime.all_monitors if m.input_index == input_index), None
        )
    if target is None:
        return True

    target.silence_threshold_dbfs = live_threshold_dbfs
    return _push_input_config_with_retry(target, socket_path=socket_path)


def update_live_input_type(
    input_index: int,
    input_type: str,
    silence_threshold_dbfs: float,
    *,
    socket_path: Optional[str] = None,
) -> bool:
    """Apply a live input-type change to one input's running monitor.

    The monitor's type, turntable flag and threshold are updated, the
    default now-playing title follows the type (and is re-sent if the
    current bundle is still a default), and the daemon is pushed the new
    configuration. Returns True when the input has no running monitor or
    the daemon acknowledged the push, False when every push attempt failed;
    the attributes are updated either way.
    """
    new_type = normalize_input_type(input_type)
    try:
        threshold = float(silence_threshold_dbfs)
    except Exception:
        logging.warning(
            "Could not update live input type: invalid threshold %r",
            silence_threshold_dbfs,
        )
        return False

    with runtime._monitors_lock:
        target = next(
            (m for m in runtime.all_monitors if m.input_index == input_index), None
        )
    if target is None:
        return True

    old_default = target._default_nowplaying_metadata()
    target.input_type = new_type
    target.is_turntable = new_type == "turntable"
    target.silence_threshold_dbfs = threshold

    # A bundle that is still the old default takes the new one; an
    # identified track is left alone and the next boundary uses the new
    # default anyway.
    cur = target._current_nowplaying
    if cur is not None and (cur.title, cur.artist, cur.album) == (
        old_default.title, old_default.artist, old_default.album
    ):
        target._current_nowplaying = replace(
            target._default_nowplaying_metadata(), artwork=cur.artwork
        )
    runtime.request_nowplaying_republish()
    _hooks().publish_inputs()

    return _push_input_config_with_retry(target, socket_path=socket_path)


def update_live_dynamic_rate_matching(
    input_index: int,
    enabled: bool,
    *,
    socket_path: Optional[str] = None,
) -> bool:
    """Apply a live Dynamic Rate Matching change to one input's running monitor.

    The monitor's attribute is updated first, so the value survives a failed
    push and goes out with the next reconnect resync. Returns True when the
    input has no running monitor or the daemon acknowledged the push, False
    when every push attempt failed.
    """
    with runtime._monitors_lock:
        target = next(
            (m for m in runtime.all_monitors if m.input_index == input_index), None
        )
    if target is None:
        return True

    target.dynamic_rate_matching = bool(enabled)
    # The Setup note follows the switch at once, whether or not the push
    # succeeds.
    _hooks().publish_inputs()
    return _push_input_config_with_retry(target, socket_path=socket_path)


# ---------------------------------------------------------------------------
# OwnTone, silence, audio path, capture and track identification
# ---------------------------------------------------------------------------

def _validate_volume_percent(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Value must be a number")
    v = int(value)
    if v < 0 or v > 100:
        raise ValueError("Value must be between 0 and 100")
    return v


def _validate_silence_seconds(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Value must be a number")
    v = int(value)
    if v < 5 or v > 300:
        raise ValueError("Value must be between 5 and 300")
    return v


def _validate_output_name(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Value must be a string")
    v = value.strip()
    if not v:
        raise ValueError("Value must be a non-empty string")
    return v


def _live_owntone_name(state: object, value: object) -> bool:
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if not isinstance(settings, _SettingsStore):
        return False
    snap = settings.snapshot()
    return bool(update_live_owntone_runtime(
        output_name=str(value),
        volume_percent=snap.owntone.volume_percent,
        output_offsets_ms=snap.owntone.output_offsets_ms,
        output_airplay_modes=snap.owntone.output_airplay_modes,
    ))


def _live_owntone_volume(state: object, value: object) -> bool:
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if not isinstance(settings, _SettingsStore):
        return False
    snap = settings.snapshot()
    return bool(update_live_owntone_runtime(
        output_name=snap.owntone.output_name,
        volume_percent=int(value),
        output_offsets_ms=snap.owntone.output_offsets_ms,
        output_airplay_modes=snap.owntone.output_airplay_modes,
    ))


def _live_silence(state: object, value: object) -> bool:
    return bool(update_live_silence_seconds(int(value)))


def _validate_audio_path(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError(f"Value must be one of {', '.join(AUDIO_PATH_CHOICES)}")
    v = value.strip().lower()
    if v not in AUDIO_PATH_CHOICES:
        raise ValueError(f"Value must be one of {', '.join(AUDIO_PATH_CHOICES)}")
    if v == "max" and not is_high_performance_pi():
        # Defends against a stale browser tab (the Best tier is filtered
        # out of the rendered options on this hardware, see settings_card_html
        # in autostream_webui_page_setup.py) or a hand-crafted request.
        raise ValueError("Best quality is only available on Pi 4/5-class hardware")
    return v


def _live_audio_path(state: object, value: object) -> bool:
    """Web UI change flow: persist happens before this runs (send_settings_
    post_json commits via settings.update() first, same as every other live
    function here); this pushes the two derived knobs.

    Both steps are individually tolerant of backend/transport failure (see
    push_resample_quality()/sync_monitor_args_for_audio_path()'s own
    docstrings -- stock OwnTone, an old owntone-mini, or a transient error
    are all logged and left for the next reconcile pass, never raised), so
    this always reports success once the setting itself is saved -- matching
    the tolerated-to-fail treatment already used for the daemon-side repeat
    policy push elsewhere in this codebase.
    """
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if not isinstance(settings, _SettingsStore):
        return False
    snap = settings.snapshot()
    base_url = snap.owntone.base_url
    audio_path = str(value)

    push_resample_quality(base_url, audio_path, timeout=3.0)
    sync_monitor_args_for_audio_path(base_url, audio_path, timeout=3.0)
    return True


# ---------------------------------------------------------------------------
# Validators, debounce helpers and live functions
# ---------------------------------------------------------------------------

def _validate_capture_device(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Value must be a string")
    v = value.strip()
    if not v:
        raise ValueError("Value must be a non-empty string")
    # Reject the ASBT loopback's PLAYBACK side: it is an internal device the
    # pump feeds, never a valid capture-device value -- a stale saved value
    # or a hand-crafted request could otherwise resurface it (see the Setup
    # page's synthetic "(not currently detected)" option, build_opts in
    # autostream_webui_page_setup.py). Only rejected when the Bluetooth-input
    # subsystem is installed, so appliances without it see byte-identical
    # validator behaviour.
    if bluetooth_installed() and is_loopback_playback(v):
        raise ValueError(
            "That is the internal Bluetooth loopback device; select the Bluetooth input entry instead"
        )
    return v


def _validate_track_id_lead_in(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Value must be a number")
    return normalize_track_id_analysis_lead_in_seconds(value)


def _validate_track_id_refresh(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Value must be a number")
    return normalize_track_id_refresh_seconds(value)


def _validate_track_id_silence(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Value must be a number")
    return normalize_track_id_track_change_silence_seconds(value)


# Debounce helpers.
#
# _debounce_coordinator_reload keeps its own ad hoc threading.Timer/lock/
# global trio rather than the shared primitive below: the reload flag it
# signals is already an idempotent threading.Event, so this timer may be
# deletable outright rather than migrated onto the shared debouncer. Do
# not touch it here.
#
# The coordinator reload timer calls save_now() before signalling so the
# coordinator always reads up-to-date settings from disk.

_coordinator_reload_lock = threading.Lock()
_coordinator_reload_timer: Optional[threading.Timer] = None


def _debounce_coordinator_reload(state: object, delay: float = 0.3) -> None:
    global _coordinator_reload_timer
    with _coordinator_reload_lock:
        if _coordinator_reload_timer is not None:
            _coordinator_reload_timer.cancel()

        def _do_reload():
            from autostream_settings import SettingsStore as _SettingsStore
            settings = getattr(state, "settings", None)
            if isinstance(settings, _SettingsStore):
                settings.save_now()
            submit(Intent("settings.reload", {"reason": "settings changed"},
                          Origin.SYSTEM, "webui"))

        _coordinator_reload_timer = threading.Timer(delay, _do_reload)
        _coordinator_reload_timer.daemon = True
        _coordinator_reload_timer.start()


# The one genuine debounce-of-a-live-push case among this module's two
# reload timers: built on the shared autostream_debounce.Debouncer (one
# implementation, greppable) instead of its own bespoke
# threading.Timer/lock/global trio. Same coalescing behaviour: a call
# arriving within `delay` of the previous one replaces it, and only the
# last-registered snapshot read actually runs.
def _debounce_track_id_rebuild(state: object, delay: float = 0.3) -> None:
    def _do_rebuild():
        from autostream_settings import SettingsStore as _SettingsStore
        settings = getattr(state, "settings", None)
        if isinstance(settings, _SettingsStore):
            try:
                snap = settings.snapshot()
                _hooks().apply_track_id_config_live_from_parsed(snap)
            except Exception:
                logging.exception("debounced track-ID rebuild failed")

    default_debouncer().trigger("track_id_rebuild", delay, _do_rebuild)


def _live_capture_1(state: object, value: object) -> bool:
    _debounce_coordinator_reload(state)
    return True


def _live_capture_2(state: object, value: object) -> bool:
    _debounce_coordinator_reload(state)
    return True


def _live_audio1_enabled(state: object, value: object) -> bool:
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if isinstance(settings, _SettingsStore):
        snap = settings.snapshot()
        _hooks().update_playback_input_config(
            1,
            enabled=bool(value),
            is_turntable=snap.audio1.is_turntable,
            input_type=snap.audio1.input_type,
            is_bluetooth=classify_loopback_hw(snap.audio1.capture_device) == "capture",
            stylus_life_hours=snap.audio1.stylus_life_hours,
            belt_life_hours=snap.audio1.belt_life_hours,
            belt_life_years=snap.audio1.belt_life_years,
            bearing_life_hours=snap.audio1.bearing_life_hours,
            bearing_life_years=snap.audio1.bearing_life_years,
        )
    _debounce_coordinator_reload(state)
    return True


def _live_audio2_enabled(state: object, value: object) -> bool:
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if isinstance(settings, _SettingsStore):
        snap = settings.snapshot()
        _hooks().update_playback_input_config(
            2,
            enabled=bool(value),
            is_turntable=snap.audio2.is_turntable,
            input_type=snap.audio2.input_type,
            is_bluetooth=classify_loopback_hw(snap.audio2.capture_device) == "capture",
            stylus_life_hours=snap.audio2.stylus_life_hours,
            belt_life_hours=snap.audio2.belt_life_hours,
            belt_life_years=snap.audio2.belt_life_years,
            bearing_life_hours=snap.audio2.bearing_life_hours,
            bearing_life_years=snap.audio2.bearing_life_years,
        )
    _debounce_coordinator_reload(state)
    return True


def _validate_input_type(value: object) -> str:
    if not isinstance(value, str) or normalize_input_type(value, default="") == "":
        raise ValueError("Value must be one of turntable, cd, line")
    return normalize_input_type(value)


def _validate_silence_threshold_dbfs(value: object) -> float:
    import math
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Value must be a number")
    v = float(value)
    if not math.isfinite(v) or v < SILENCE_THRESHOLD_MIN_DBFS or v > SILENCE_THRESHOLD_MAX_DBFS:
        raise ValueError(
            f"Value must be between {SILENCE_THRESHOLD_MIN_DBFS:.0f} and {SILENCE_THRESHOLD_MAX_DBFS:.0f}"
        )
    return float(round(v))


def _sync_playback_input_config(snap, input_index: int) -> None:
    """Hand one input's current settings to the playback tracker."""
    a = snap.audio1 if input_index == 1 else snap.audio2
    _hooks().update_playback_input_config(
        input_index,
        enabled=snap.audio1_enabled if input_index == 1 else snap.audio2_enabled,
        is_turntable=a.is_turntable,
        input_type=a.input_type,
        is_bluetooth=classify_loopback_hw(a.capture_device) == "capture",
        stylus_life_hours=a.stylus_life_hours,
        belt_life_hours=a.belt_life_hours,
        belt_life_years=a.belt_life_years,
        bearing_life_hours=a.bearing_life_hours,
        bearing_life_years=a.bearing_life_years,
    )


def _live_input_type(state: object, input_index: int, value: object) -> bool:
    # Runs after the store has committed the type, flag and preset, so the
    # snapshot already holds the threshold to push with the type.
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if isinstance(settings, _SettingsStore):
        snap = settings.snapshot()
        _sync_playback_input_config(snap, input_index)
        a = snap.audio1 if input_index == 1 else snap.audio2
        return update_live_input_type(input_index, a.input_type, a.silence_threshold_dbfs)
    return update_live_input_type(
        input_index, value, input_type_silence_threshold_dbfs(value))


def _live_input_type_1(state: object, value: object) -> bool:
    return _live_input_type(state, 1, value)


def _live_input_type_2(state: object, value: object) -> bool:
    return _live_input_type(state, 2, value)


def _live_silence_threshold_1(state: object, value: object) -> bool:
    return update_live_silence_threshold_dbfs(1, float(value))


def _live_silence_threshold_2(state: object, value: object) -> bool:
    return update_live_silence_threshold_dbfs(2, float(value))


def _live_dynamic_rate_matching_1(state: object, value: object) -> bool:
    return update_live_dynamic_rate_matching(1, bool(value))


def _live_dynamic_rate_matching_2(state: object, value: object) -> bool:
    return update_live_dynamic_rate_matching(2, bool(value))


def _live_track_id(state: object, value: object) -> bool:
    _debounce_track_id_rebuild(state)
    return True


def _mutate_input_type(raw: dict, section: str, key: str, value: object) -> None:
    """FieldSpec.mutate for audio{1,2}.input_type: set_input_type also keeps
    the turntable flag in step and moves the threshold to the new preset."""
    set_input_type(raw, int(section[-1]), value)


# Rows of the settings schema whose change has a live effect. The validators
# and live functions are the ones above; the schema table carries them for the
# settings routes and the Setup form.
register_field("owntone.output_name", "owntone", "output_name", _validate_output_name,
               live=_live_owntone_name, live_class=LiveClass.LIVE)
register_field("owntone.volume_percent", "owntone", "volume_percent", _validate_volume_percent,
               live=_live_owntone_volume, live_class=LiveClass.LIVE)
register_field("general.silence_seconds", "general", "silence_seconds", _validate_silence_seconds,
               live=_live_silence, live_class=LiveClass.LIVE)
register_field("general.audio_path", "general", "audio_path", _validate_audio_path,
               live=_live_audio_path, live_class=LiveClass.RELOAD)
register_field("audio1.capture_device", "audio1", "capture_device", _validate_capture_device,
               live=_live_capture_1, cross_validate=cross_validate_capture_device_unique,
               live_class=LiveClass.RELOAD)
register_field("audio2.capture_device", "audio2", "capture_device", _validate_capture_device,
               live=_live_capture_2, cross_validate=cross_validate_capture_device_unique,
               live_class=LiveClass.RELOAD)
register_field("audio1.enabled", "audio1", "enabled", _validate_bool,
               live=_live_audio1_enabled, live_class=LiveClass.RELOAD)
register_field("audio2.enabled", "audio2", "enabled", _validate_bool,
               live=_live_audio2_enabled, live_class=LiveClass.RELOAD)
# One store update writes the type, the turntable flag and the preset
# threshold; the live effect is the playback tracker and a daemon push, never a
# reload.
register_field("audio1.input_type", "audio1", "input_type", _validate_input_type,
               live=_live_input_type_1, mutate=_mutate_input_type, live_class=LiveClass.LIVE)
register_field("audio2.input_type", "audio2", "input_type", _validate_input_type,
               live=_live_input_type_2, mutate=_mutate_input_type, live_class=LiveClass.LIVE)
register_field("audio1.silence_threshold", "audio1", "silence_threshold",
               _validate_silence_threshold_dbfs, live=_live_silence_threshold_1,
               live_class=LiveClass.LIVE)
register_field("audio2.silence_threshold", "audio2", "silence_threshold",
               _validate_silence_threshold_dbfs, live=_live_silence_threshold_2,
               live_class=LiveClass.LIVE)
register_field("audio1.dynamic_rate_matching", "audio1", "dynamic_rate_matching", _validate_bool,
               live=_live_dynamic_rate_matching_1, live_class=LiveClass.LIVE)
register_field("audio2.dynamic_rate_matching", "audio2", "dynamic_rate_matching", _validate_bool,
               live=_live_dynamic_rate_matching_2, live_class=LiveClass.LIVE)
register_field("track_identification.enabled", "track_identification", "enabled", _validate_bool,
               live=_live_track_id, live_class=LiveClass.RELOAD)
register_field("track_identification.analysis_lead_in_seconds", "track_identification",
               "analysis_lead_in_seconds", _validate_track_id_lead_in, live=_live_track_id,
               form_coerce=normalize_track_id_analysis_lead_in_seconds, live_class=LiveClass.RELOAD)
register_field("track_identification.refresh_seconds", "track_identification",
               "refresh_seconds", _validate_track_id_refresh, live=_live_track_id,
               form_coerce=normalize_track_id_refresh_seconds, live_class=LiveClass.RELOAD)
register_field("track_identification.track_change_silence_seconds", "track_identification",
               "track_change_silence_seconds", _validate_track_id_silence, live=_live_track_id,
               form_coerce=normalize_track_id_track_change_silence_seconds,
               live_class=LiveClass.RELOAD)


# ---------------------------------------------------------------------------
# Settings intents
# ---------------------------------------------------------------------------

# Serialises the announcement reconcile, for the JSON route and the Setup form
# alike. Must not be held while CONFIG_IO_LOCK is held, and vice versa.
_advertise_lock = threading.Lock()

_NOT_SAVED_WARNING = "Preference applied but could not be saved — will revert on restart"


def _settings_apply(intent: Intent, wait: float) -> Outcome:
    """Commit already-validated values, one settings path each, and run each
    field's live effect. *context* is the request's state, whose store is
    written. The result's outcomes are the store's SetOutcome fields, in order."""
    state = intent.context
    settings = _store_of(state)
    if settings is None:
        return Outcome(ok=False, error="Settings store unavailable", result={"unavailable": True})
    outcomes = []
    try:
        for path, value in intent.args["changes"]:
            outcomes.append(settings._set_normalized(
                get_field_spec(path), value, state=state)._asdict())
    except CrossFieldValidationError as exc:
        return Outcome(ok=False, error=str(exc), result={"invalid": str(exc)})
    except Exception:
        logging.exception("settings.apply: store update failed")
        return Outcome(ok=False, error="Internal error", result={"internal": True})
    return Outcome(ok=True, result={"outcomes": outcomes})


def _settings_save(intent: Intent, wait: float) -> Outcome:
    settings = _store_of(intent.context)
    if settings is None:
        return Outcome(ok=False, error="Settings store not available")
    if settings.save_now():
        return Outcome(ok=True)
    return Outcome(ok=False, error="Settings could not be saved")


def _settings_reload(intent: Intent, wait: float) -> Outcome:
    runtime.request_config_reload()
    return Outcome(ok=True)


def _form_apply(intent: Intent, wait: float) -> Outcome:
    """Apply, in order, the live parts of a Setup form save. *context* is the
    configuration parsed before the form's changes; the steps carry the form's
    own values. A step that is not applied makes the outcome not ok, and the
    result lists each step's result."""
    cfg = intent.context
    results = []
    for name, params in intent.args["steps"]:
        if name == "owntone_runtime":
            results.append(bool(update_live_owntone_runtime(
                output_name=params["output_name"],
                volume_percent=params["volume_percent"],
                output_offsets_ms=cfg.owntone.output_offsets_ms,
                output_airplay_modes=cfg.owntone.output_airplay_modes,
            )))
        elif name == "playback_input":
            index = int(params["input"])
            audio = cfg.audio1 if index == 1 else cfg.audio2
            turntable = bool(params["is_turntable"])
            results.append(bool(_hooks().update_playback_input_config(
                index,
                enabled=bool(params["enabled"]),
                is_turntable=turntable,
                input_type="turntable" if turntable else "line",
                stylus_life_hours=audio.stylus_life_hours,
                belt_life_hours=audio.belt_life_hours,
                belt_life_years=audio.belt_life_years,
                bearing_life_hours=audio.bearing_life_hours,
                bearing_life_years=audio.bearing_life_years,
            )))
        elif name == "silence_seconds":
            results.append(bool(update_live_silence_seconds(params)))
        elif name == "track_id":
            _hooks().apply_track_id_config_live(params)
            results.append(True)
        else:
            return Outcome(ok=False, error="invalid_steps")
    return Outcome(ok=all(results), result={"results": results})


def _advertisement(intent: Intent, wait: float) -> Outcome:
    """Apply the peer advertisement preference, then store it only when the
    privileged call worked. With *rollback_to* the value is written to the
    configuration file instead of the store, and the previous preference is
    restored if that write fails (the Setup form's path)."""
    import autostream_appliances as appliances

    value = intent.args["value"]
    version = intent.args["version"]
    rollback_to = intent.args.get("rollback_to")
    with _advertise_lock:
        if not appliances.reconcile_appliance_announcement(version, value):
            logging.warning("settings.advertisement: admin call failed for advertise=%s", value)
            return Outcome(ok=False, error="apply_failed")
        if rollback_to is not None:
            config_path = getattr(intent.context, "config_path", None)
            try:
                with CONFIG_IO_LOCK:
                    fresh_cfg = load_config(config_path)
                    fresh_cfg.setdefault("webui", {})["advertise_appliance"] = value
                    save_config(config_path, fresh_cfg)
            except Exception:
                logging.warning(
                    "settings.advertisement: failed to persist advertise_appliance=%s; "
                    "rolling back service state", value)
                appliances.reconcile_appliance_announcement(version, rollback_to)
                return Outcome(ok=False, error="save_failed")
            return Outcome(ok=True)
        settings = _store_of(intent.context)
        if settings is not None:
            try:
                settings.update(
                    lambda raw: raw.setdefault("webui", {}).update({"advertise_appliance": value}))
            except Exception:
                logging.exception("settings.advertisement: store write failed")
                return Outcome(ok=True, result={"warning": _NOT_SAVED_WARNING})
    return Outcome(ok=True)


def _auto_update(intent: Intent, wait: float) -> Outcome:
    """Switch the automatic update timer, then store the preference only when
    the privileged call worked, so a failed call cannot commit a wrong value."""
    value = intent.args["value"]
    verb = "enable" if value else "disable"
    result = run_admin_cmd(["toggle-update-timer", verb], timeout=5.0)
    if result.returncode != 0:
        logging.warning(
            "settings.auto_update: toggle-update-timer %s failed (rc=%d): %s",
            verb, result.returncode, (result.stderr or "").strip(),
        )
        return Outcome(ok=False, error=f"Auto-update timer could not be {verb}d")
    settings = _store_of(intent.context)
    if settings is not None:
        try:
            settings.update(lambda raw: raw.setdefault("updates", {}).update({"auto_update": value}))
        except Exception:
            logging.exception("settings.auto_update: store write failed")
            return Outcome(ok=True, result={"warning": _NOT_SAVED_WARNING})
    return Outcome(ok=True)


bind("settings.apply", _settings_apply, owner=_OWNER)
bind("settings.save", _settings_save, owner=_OWNER)
bind("settings.reload", _settings_reload, owner=_OWNER)
bind("settings.form_apply", _form_apply, owner=_OWNER)
bind("settings.advertisement", _advertisement, owner=_OWNER)
bind("settings.auto_update", _auto_update, owner=_OWNER)
