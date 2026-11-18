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
file.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import math
import threading
import time
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Callable, Mapping, Optional

import autostream_identification as identification
import autostream_input_status as input_status
import autostream_monitor_client as monitor_client
import autostream_monitor_control as monitor_control
import autostream_playback_tracking as playback_tracking
import autostream_runtime as runtime
from autostream_bluetooth_client import (
    bluetooth_installed,
    classify_loopback_hw,
    is_loopback_playback,
)
from autostream_config import (
    OutputsConfig,
    AUDIO_PATH_CHOICES,
    BUFFERED_AIRPLAY_MODES,
    CONFIG_IO_LOCK,
    DEFAULT_AIRPLAY_MODE,
    FIFO_PATH,
    DEVICE_PAUSE_SCOPE_DEFAULT,
    DEVICE_PAUSE_SCOPES,
    PLAY_GUARD_SECONDS_DEFAULT,
    PLAY_GUARD_SECONDS_RANGE,
    REPEAT_CODEC_CHOICES,
    SILENCE_THRESHOLD_MAX_DBFS,
    SILENCE_THRESHOLD_MIN_DBFS,
    PAUSE_OFF_SECONDS_DEFAULT,
    PAUSE_OFF_SECONDS_RANGE,
    VALID_AIRPLAY_MODES,
    input_type_silence_threshold_dbfs,
    load_config,
    load_state,
    normalize_airplay_mode,
    normalize_input_type,
    normalize_repeat_codec,
    normalize_track_id_analysis_lead_in_seconds,
    normalize_track_id_refresh_seconds,
    normalize_track_id_track_change_silence_seconds,
    parse_config,
    save_state,
    set_input_type,
)
import autostream_start_buffer_cache as start_buffer_cache
from autostream_debounce import default_debouncer
from autostream_intents.table import Intent, Outcome, bind, submit
from autostream_player_service import (
    push_resample_quality,
    save_setting,
    sync_monitor_args_for_audio_path,
)
from autostream_players import (
    SETTING_BUFFERED_AUDIO_ENABLED,
    SETTING_DEVICE_REMOVAL_GRACE_PERIOD,
    SETTING_START_BUFFER_MS,
    SETTING_UNCOMPRESSED_ALAC,
    SETTING_USER_AGENT,
)
from autostream_rpi import is_high_performance_pi
from autostream_settings import SettingsStore, writable_store
from autostream_settings_schema import (
    CrossFieldValidationError,
    LiveClass,
    cross_validate_capture_device_unique,
    get_field_spec,
    register_field,
)
from autostream_state import Origin, store
from autostream_state.outputs import get_authority
from autostream_sysutils import run_admin_cmd

_OWNER = "autostream_live_config"


def _store_of(state: object) -> Optional[SettingsStore]:
    return writable_store(getattr(state, "settings", None))


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
    settings = writable_store(getattr(state, "settings", None))
    if settings is None:
        return False
    snap = settings.snapshot()
    return bool(monitor_control.set_live_input_eq(
        1,
        eq_40hz_db=snap.audio1.eq_40hz_db,
        eq_100hz_db=snap.audio1.eq_100hz_db,
        eq_8khz_db=snap.audio1.eq_8khz_db,
    ))


def _live_eq_2(state: object, value: object) -> bool:
    settings = writable_store(getattr(state, "settings", None))
    if settings is None:
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
    settings = writable_store(getattr(state, "settings", None))
    if settings is None:
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
    settings = writable_store(getattr(state, "settings", None))
    if settings is None:
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
    settings = writable_store(getattr(state, "settings", None))
    if settings is None:
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
    input_status.publish_inputs()

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
    input_status.publish_inputs()
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
    settings = writable_store(getattr(state, "settings", None))
    if settings is None:
        return False
    snap = settings.snapshot()
    return bool(update_live_owntone_runtime(
        output_name=str(value),
        volume_percent=snap.owntone.volume_percent,
        output_offsets_ms=snap.owntone.output_offsets_ms,
        output_airplay_modes=snap.owntone.output_airplay_modes,
    ))


def _live_owntone_volume(state: object, value: object) -> bool:
    settings = writable_store(getattr(state, "settings", None))
    if settings is None:
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
        # in webui/common.py) or a hand-crafted request.
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
    settings = writable_store(getattr(state, "settings", None))
    if settings is None:
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
    # webui/browser/setup/cards_inputs.py). Only rejected when the Bluetooth-input
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
            settings = writable_store(getattr(state, "settings", None))
            if settings is not None:
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
        settings = writable_store(getattr(state, "settings", None))
        if settings is not None:
            try:
                snap = settings.snapshot()
                identification.apply_track_id_config_live_from_parsed(snap)
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
    settings = writable_store(getattr(state, "settings", None))
    if settings is not None:
        snap = settings.snapshot()
        playback_tracking.update_playback_input_config(
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
    settings = writable_store(getattr(state, "settings", None))
    if settings is not None:
        snap = settings.snapshot()
        playback_tracking.update_playback_input_config(
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
    playback_tracking.update_playback_input_config(
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
    settings = writable_store(getattr(state, "settings", None))
    if settings is not None:
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
               live_class=LiveClass.RELOAD)
register_field("track_identification.refresh_seconds", "track_identification",
               "refresh_seconds", _validate_track_id_refresh, live=_live_track_id,
               live_class=LiveClass.RELOAD)
register_field("track_identification.track_change_silence_seconds", "track_identification",
               "track_change_silence_seconds", _validate_track_id_silence, live=_live_track_id,
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
    timeout = intent.args.get("timeout")
    saved = settings.save_now() if timeout is None else settings.save_now(timeout=timeout)
    if saved:
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
            results.append(bool(playback_tracking.update_playback_input_config(
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
            identification.apply_track_id_config_live(params)
            results.append(True)
        else:
            return Outcome(ok=False, error="invalid_steps")
    return Outcome(ok=all(results), result={"results": results})


def _advertisement(intent: Intent, wait: float) -> Outcome:
    """Apply the peer advertisement preference, then store it only when the
    privileged call worked."""
    import autostream_appliances as appliances

    value = intent.args["value"]
    version = intent.args["version"]
    with _advertise_lock:
        if not appliances.reconcile_appliance_announcement(version, value):
            logging.warning("settings.advertisement: admin call failed for advertise=%s", value)
            return Outcome(ok=False, error="apply_failed")
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


def _service_field_set(intent: Intent, wait: float) -> Outcome:
    """Write one service-life field: the raw value goes through the field's
    own normaliser, then is stored as a plain write (no live effect; the
    route pushes the playback tracker itself). *context* is the request's
    state, whose store is written. The result's value is what was stored."""
    settings = _store_of(intent.context)
    if settings is None:
        return Outcome(ok=False, error="Settings store unavailable", result={"unavailable": True})
    path = intent.args["path"]
    spec = get_field_spec(path) if path.startswith("service_") else None
    if spec is None or spec.normalise is None or spec.section is None or spec.key is None:
        return Outcome(ok=False, error="Unknown field", result={"unknown": True})
    try:
        normalised = spec.normalise(intent.args["value"])
    except Exception as exc:
        message = f"Invalid value: {exc}"
        return Outcome(ok=False, error=message, result={"invalid": message})
    section, key = spec.section, spec.key
    try:
        settings.update(lambda raw: raw.setdefault(section, {}).update({key: normalised}))
    except Exception as exc:
        logging.exception("settings.service_field.set: store write failed")
        return Outcome(ok=False, error=str(exc), result={"failed": True})
    return Outcome(ok=True, result={"value": normalised})


def _settings_discard(intent: Intent, wait: float) -> Outcome:
    """Stop the store without saving its unsaved changes (before a factory
    reset, which wipes the configuration anyway)."""
    settings = _store_of(intent.context)
    if settings is None:
        return Outcome(ok=False, error="Settings store unavailable")
    try:
        settings.close(save=False)
    except Exception:
        logging.warning("settings.discard: store close failed", exc_info=True)
        return Outcome(ok=False, error="Settings store could not be closed")
    return Outcome(ok=True)


def _first_boot_commit(intent: Intent, wait: float) -> Outcome:
    """Store one first-boot step. Step "output" records the chosen OwnTone
    output. Step "finish" records the Appliance page: input 1 (or, when it is
    skipped, only its disabled flag), the volume and the fixed FIFO path.
    *context* is the request's state, whose store is written."""
    settings = _store_of(intent.context)
    if settings is None:
        return Outcome(ok=False, error="Settings store unavailable", result={"unavailable": True})
    args = intent.args
    if args["step"] == "output":
        output_name = args.get("output_name")
        if not output_name:
            return Outcome(ok=False, error="invalid_args")

        def _mutator(raw: dict) -> None:
            raw.setdefault("owntone", {}).update({"output_name": output_name})
    else:
        skip_input1 = bool(args.get("skip_input1"))
        capture_device = args.get("capture_device")
        input_type = args.get("input_type")
        volume_percent = args.get("volume_percent")
        if volume_percent is None or (not skip_input1 and (not capture_device or not input_type)):
            return Outcome(ok=False, error="invalid_args")

        def _mutator(raw: dict) -> None:
            if skip_input1:
                # Leave capture_device/turntable untouched -- only the
                # enabled flag changes, so a device chosen in the dropdown
                # before tapping Skip is not silently persisted.
                raw.setdefault("audio1", {})["enabled"] = False
            else:
                raw.setdefault("audio1", {})["capture_device"] = capture_device
                raw.setdefault("audio1", {})["enabled"] = True
                set_input_type(raw, 1, input_type)
            raw.setdefault("owntone", {})["volume_percent"] = volume_percent
            # Fixed appliance path, not something first boot can choose
            raw.setdefault("general", {})["fifo_path"] = FIFO_PATH
    try:
        settings.update(_mutator)
    except Exception as exc:
        logging.exception("first_boot.commit: store update failed")
        return Outcome(ok=False, error=str(exc), result={"failed": True})
    return Outcome(ok=True)


bind("settings.apply", _settings_apply, owner=_OWNER)
bind("settings.save", _settings_save, owner=_OWNER)
bind("settings.reload", _settings_reload, owner=_OWNER)
bind("settings.form_apply", _form_apply, owner=_OWNER)
bind("settings.advertisement", _advertisement, owner=_OWNER)
bind("settings.auto_update", _auto_update, owner=_OWNER)
bind("settings.service_field.set", _service_field_set, owner=_OWNER)
bind("settings.discard", _settings_discard, owner=_OWNER)
bind("first_boot.commit", _first_boot_commit, owner=_OWNER)


# ---------------------------------------------------------------------------
# Backend settings
#
# The OwnTone-compatible backend's native settings, the per-output visibility,
# mode and offset, and the mDNS grace period. The routes parse and check the
# request, then submit one "backend.setting.set" intent; the handler below
# does the work and reports in its result whether the backend asks for a
# restart (the route starts it) and whether an offset reached the speaker.
# ---------------------------------------------------------------------------

def _config_snapshot(state):
    """A parsed configuration, preferring the in-memory settings store."""
    settings = _store_of(state)
    if settings is not None:
        return settings.snapshot()
    with CONFIG_IO_LOCK:
        return parse_config(load_config(state.config_path))


def _owntone_update_live_runtime(state: object) -> None:
    """Re-apply owntone runtime from the current store or config snapshot."""
    try:
        snap = _config_snapshot(state)
        submit(Intent(
            "settings.form_apply",
            {"steps": (("owntone_runtime", {
                "output_name": snap.owntone.output_name,
                "volume_percent": snap.owntone.volume_percent,
            }),)},
            Origin.USER, "webui", context=snap))
    except Exception:
        logging.exception("_owntone_update_live_runtime failed")


def _owntone_state_update_known_outputs(state: object, updates: dict[str, str]) -> None:
    """Race-safe merge of output name updates into the state file.

    Re-reads the state file inside CONFIG_IO_LOCK so that concurrent PIN
    or other state changes made while network calls were in flight are
    preserved.
    """
    if not updates:
        return
    with CONFIG_IO_LOCK:
        live = load_state(state.state_path)
        ko = live.setdefault("owntone", {}).setdefault("known_outputs", {})
        ko.update(updates)
        save_state(state.state_path, live)


# -----------------------------------------------------------------------------
# Per-output settings are keyed by a runtime-discovered output name/id, so
# they don't fit a flat dotted-path schema row -- SETTINGS_SCHEMA.get_field_spec()
# matches a concrete path such as "owntone.offsets.abc123" against a
# registered template row ("owntone.offsets.*") on an exact-path lookup
# miss (see autostream_settings_schema.py's get_field_spec()). Only the
# per-output offset's static -2000..2000 clamp lives on its row (below,
# apply_output_offset); the dynamic negative-offset tightening (start-buffer-
# size-dependent, queried live from the owntone backend) is not a static
# schema bound and correctly stays a pre-clamp step the handler still does
# before committing. The AirPlay-mode row is registered for schema
# completeness -- it is the second field with the same runtime-keyed shape --
# but send_owntone_output_mode_json's own validation is left
# untouched here, for two reasons that make folding it in a behaviour change
# rather than a consolidation:
#   1. Reject vs coerce. The handler's accepted-value set is exactly
#      VALID_AIRPLAY_MODES, but it *rejects* anything outside it with a 400
#      and an enumerated error message. This row's validate callable is
#      normalize_airplay_mode(), which silently coerces an unknown mode to
#      DEFAULT_AIRPLAY_MODE -- so routing the handler through the row would
#      turn a hard rejection into a silent fallback.
#   2. The buffered-mode availability gate (BUFFERED_AIRPLAY_MODES vs the
#      backend's live buffered-audio setting) depends on runtime state, not
#      a static enum bound, so it cannot live on the row at all.
# This row stays declarative-only for now.
def _validate_output_offset_ms(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("offset_ms must be a number")
    return max(-2000, min(2000, int(value)))


register_field(
    "owntone.offsets.*", "owntone", "offsets", _validate_output_offset_ms,
    bounds=(-2000, 2000), live_class=LiveClass.LIVE,
)


register_field(
    "owntone.airplay_modes.*", "owntone", "airplay_modes", normalize_airplay_mode,
    enum=frozenset(VALID_AIRPLAY_MODES), live_class=LiveClass.LIVE,
)


# Whether an Apple TV's HomePods play with the Apple TV. Stored only when the
# user changes it (absent: with); it takes effect at the next start of that
# output, and nothing about it is pushed here.
register_field(
    "owntone.include_tv.*", "owntone", "include_tv", _validate_bool,
    type=bool, default=True, live_class=LiveClass.PASSIVE,
)


def _validate_device_pause_scope(value: object) -> str:
    if not isinstance(value, str) or value not in DEVICE_PAUSE_SCOPES:
        raise ValueError("device_pause_scope must be one of " + ", ".join(DEVICE_PAUSE_SCOPES))
    return value


def _validate_pause_off_seconds(value: object) -> int:
    low, high = PAUSE_OFF_SECONDS_RANGE
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"pause_off_seconds must be a whole number from {low} to {high}")
    return value


def _validate_play_guard_seconds(value: object) -> float:
    low, high = PLAY_GUARD_SECONDS_RANGE
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or not low <= value <= high):
        raise ValueError(f"play_after_metadata_ignore_seconds must be a number from {low:g} to {high:g}")
    return float(value)


def _live_read_at_use(state: object, value: object) -> bool:
    """These settings are read when the Pause or Play arrives, so a stored
    value is already in force."""
    return True


register_field(
    "outputs.device_pause_scope", "outputs", "device_pause_scope", _validate_device_pause_scope,
    live=_live_read_at_use, type=str, enum=frozenset(DEVICE_PAUSE_SCOPES),
    default=DEVICE_PAUSE_SCOPE_DEFAULT, live_class=LiveClass.LIVE,
)
register_field(
    "outputs.pause_off_seconds", "outputs", "pause_off_seconds", _validate_pause_off_seconds,
    live=_live_read_at_use, type=int, bounds=PAUSE_OFF_SECONDS_RANGE,
    default=PAUSE_OFF_SECONDS_DEFAULT, live_class=LiveClass.LIVE,
)
register_field(
    "outputs.play_after_metadata_ignore_seconds", "outputs", "play_after_metadata_ignore_seconds",
    _validate_play_guard_seconds,
    live=_live_read_at_use, type=float, bounds=PLAY_GUARD_SECONDS_RANGE,
    default=PLAY_GUARD_SECONDS_DEFAULT, live_class=LiveClass.LIVE,
)


# The include-Apple-TV choices and the Pause settings, as the output
# authority and the policy read them: parsed again only when the settings
# store has committed since. _output_settings_lock is a leaf held for the
# compare and the swap; the store is read outside it.
@dataclass(frozen=True)
class OutputSettings:
    generation: int
    include_tv: Mapping[str, bool]
    policy: OutputsConfig


_UNBOUND_OUTPUT_SETTINGS = OutputSettings(-1, MappingProxyType({}), OutputsConfig())
_output_settings_lock = threading.Lock()
_output_settings_store: Optional[SettingsStore] = None
_output_settings: OutputSettings = _UNBOUND_OUTPUT_SETTINGS
_output_settings_touched = False


def bind_settings_store(settings: Optional[SettingsStore]) -> None:
    """Bootstrap: where output_settings() reads from. None unbinds."""
    global _output_settings_store, _output_settings, _output_settings_touched
    with _output_settings_lock:
        _output_settings_store = settings
        _output_settings = _UNBOUND_OUTPUT_SETTINGS
        _output_settings_touched = True


def output_settings() -> OutputSettings:
    """The include-Apple-TV choices and the policy settings, re-read only when
    the settings store's generation moved. Unbound: the defaults."""
    global _output_settings, _output_settings_touched
    with _output_settings_lock:
        store_ = _output_settings_store
        cached = _output_settings
    if store_ is None:
        return cached
    generation = store_.generation
    if cached.generation == generation:
        return cached
    parsed = store_.snapshot()
    fresh = OutputSettings(generation, MappingProxyType(dict(parsed.owntone.include_tv)), parsed.outputs)
    with _output_settings_lock:
        _output_settings = fresh
        _output_settings_touched = True
    return fresh


def output_policy_settings() -> OutputsConfig:
    return output_settings().policy


def include_tv_for(unit_id: str) -> bool:
    return output_settings().include_tv.get(unit_id, True)


def reset_output_settings_for_tests() -> None:
    """Unbind and forget. Returns at once when nothing touched the cache."""
    global _output_settings_store, _output_settings, _output_settings_touched
    if not _output_settings_touched:
        return
    with _output_settings_lock:
        _output_settings_store = None
        _output_settings = _UNBOUND_OUTPUT_SETTINGS
        _output_settings_touched = False


def apply_output_offset(state: object, output_id: str, raw_offset) -> dict:
    """Clamp, store, and (best-effort) live-push an output offset.

    Shared by send_owntone_output_offset_json (POST /api/owntone/output-offset)
    and the "Align outputs" apply endpoint so both paths clamp/store/push
    identically. Returns a dict shaped like the JSON body callers already
    send, minus the "ok" wrapper key that varies slightly by caller.
    """
    output_id = str(output_id or "").strip()
    if not output_id:
        return {"ok": False, "error": "output_id required"}
    # Static -2000..2000 clamp lives on the "owntone.offsets.*"
    # template schema row (registered above); same clamp, same error
    # message, only its declaration moved.
    offset_path = f"owntone.offsets.{output_id}"
    offset_spec = get_field_spec(offset_path)
    try:
        offset_ms = offset_spec.validate(raw_offset)
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    try:
        base_url = _config_snapshot(state).owntone.base_url
    except Exception:
        base_url = ""

    # Negative offsets delay this output's local playback relative to the
    # stream; push it back further than the start buffer can absorb and
    # playback underruns. Only tighten (never loosen) the -2000ms UI floor,
    # and only pay for the backend round trip when the request is actually
    # negative -- the common positive-offset case never needs it.
    if offset_ms < 0 and base_url:
        from autostream_players import SETTING_START_BUFFER_MS, SETTING_START_BUFFER_MS_DEFAULT
        from autostream_player_service import get_setting as _get_setting
        buf_result = _get_setting(base_url, SETTING_START_BUFFER_MS, timeout=1.5)
        start_buffer_ms = int(buf_result.value) if buf_result.ok else SETTING_START_BUFFER_MS_DEFAULT
        max_negative = -(start_buffer_ms - 250)
        if max_negative > -2000:
            offset_ms = max(max_negative, offset_ms)

    _store = writable_store(getattr(state, "settings", None))
    if _store is None:
        return {"ok": False, "error": "Settings store unavailable"}

    try:
        # offset_ms here may have been dynamically tightened (start-buffer-
        # size-dependent) beyond the static schema bound already applied
        # above -- _set_normalized commits it as-is.
        _store._set_normalized(offset_spec, offset_ms, path=offset_path)
    except Exception:
        logging.exception("apply_output_offset: store update failed")
        return {"ok": False, "error": "Internal error"}

    _owntone_update_live_runtime(state)

    applied_live = False
    if base_url:
        import autostream_player_service as _player_service
        try:
            caps = _player_service.get_capabilities(base_url, timeout=2)
            if caps.can_set_output_offset and _player_service.supports_live_offset(base_url, timeout=2):
                push_result = _player_service.update_output(base_url, output_id, offset_ms=offset_ms, timeout=2)
                applied_live = bool(push_result.ok)
        except Exception:
            # Store write already succeeded above; owntone being down or
            # unreachable here is not a failure the caller needs to see --
            # applied_live=False tells the UI the value is queued, not live.
            logging.info("apply_output_offset: live push failed", exc_info=True)

    return {
        "ok": True,
        "output_id": output_id,
        "offset_ms": offset_ms,
        "applied_live": applied_live,
    }


def _push_owntone_native_setting(
    state: object,
    setting_key: str,
    value: object,
    reject_unsupported: bool = False,
) -> tuple[bool, bool, str]:
    """Push a native setting to the configured OwnTone-compatible backend.
    Returns (ok, restart_required, error); starting the restart is the caller's.

    Unsupported settings are tolerated by default: best-effort pushes such as the
    mDNS grace period fire against whatever backend is configured (including none,
    in dial mode) and must not surface an error. Callers driving a user-visible,
    backend-gated control pass reject_unsupported=True to get a real failure.
    """
    try:
        parsed = _config_snapshot(state)
        base_url = parsed.owntone.base_url
    except Exception as exc:
        return False, False, f"Config unavailable: {exc}"

    result = save_setting(base_url, setting_key, value, timeout=5.0)
    if result.unsupported and reject_unsupported:
        return False, False, (
            result.message or "This backend does not support that setting"
        )
    if not result.ok and not result.unsupported:
        return False, False, result.message or "OwnTone API error"

    return True, bool(result.restart_required), ""


def apply_mdns_grace_period(state: object, seconds: int) -> tuple[bool, bool, str]:
    """Push configured mDNS grace to appliance discovery and OwnTone Mini.

    Synchronous: configures the in-process appliance browser and then contacts
    the OwnTone backend, returning its result. Used by the interactive settings
    handler, which reports success/restart back to the caller.
    """
    import autostream_appliances as appliances

    appliances.set_grace_period(seconds)
    return _push_owntone_native_setting(
        state, SETTING_DEVICE_REMOVAL_GRACE_PERIOD, seconds
    )


def _forward_mdns_grace_period_to_owntone(
    state: object,
    seconds: int,
) -> tuple[bool, bool, str]:
    """Best-effort consumer sync for the autostream-owned mDNS grace setting."""

    return _push_owntone_native_setting(
        state, SETTING_DEVICE_REMOVAL_GRACE_PERIOD, seconds
    )


def apply_mdns_grace_period_startup(
    state: object,
    on_restart: Optional[Callable[[object], None]] = None,
) -> None:
    """Apply the configured mDNS grace at startup without blocking boot.

    Configures the in-process appliance browser synchronously (cheap, always
    safe, and all a dial needs), then pushes the value to the OwnTone backend on
    a background daemon thread. Backgrounding keeps a slow or absent backend
    (e.g. dial mode with no OwnTone) from delaying startup, and isolates the
    network call from the startup thread. *on_restart*, when given, is called
    with the state if the backend then asks for a restart.
    """
    try:
        cfg = _config_snapshot(state)
        seconds = int(cfg.general.mdns_grace_period_seconds)
    except Exception:
        logging.debug("startup mdns grace: config unavailable", exc_info=True)
        return

    import autostream_appliances as appliances
    appliances.set_grace_period(seconds)

    def _push_to_owntone() -> None:
        try:
            ok, restart_needed, err = _push_owntone_native_setting(
                state, SETTING_DEVICE_REMOVAL_GRACE_PERIOD, seconds
            )
            if not ok:
                logging.debug("startup mdns grace owntone push failed: %s", err)
            elif restart_needed and on_restart is not None:
                on_restart(state)
        except Exception:
            logging.debug("startup mdns grace owntone push error", exc_info=True)

    threading.Thread(
        target=_push_to_owntone, daemon=True, name="mdns-grace-startup",
    ).start()


def _buffered_audio_is_enabled(state: object) -> bool:
    """Report whether the backend currently has buffered audio switched on.

    Backends that do not expose the setting cannot serve buffered modes either,
    so an unreadable or unsupported result counts as off.
    """
    from autostream_player_service import get_setting

    try:
        parsed = _config_snapshot(state)
        result = get_setting(
            parsed.owntone.base_url, SETTING_BUFFERED_AUDIO_ENABLED, timeout=3,
        )
    except Exception:
        logging.debug("buffered-audio probe failed", exc_info=True)
        return False
    return bool(result.ok and result.value)


def _reset_buffered_output_modes(state: object) -> list[str]:
    """Fall outputs saved as a buffered-transport mode back to the default mode.

    Called when buffered audio is switched off: those modes are no longer
    selectable, so leaving them persisted would silently reapply an unavailable
    mode if the setting were later turned back on, or when an undiscovered
    speaker reappears. Returns the output ids that were changed.
    """
    _store = writable_store(getattr(state, "settings", None))
    if _store is None:
        logging.warning("buffered-audio off: settings store unavailable, modes not reset")
        return []

    changed: list[str] = []

    def _mutator(raw: dict) -> None:
        changed.clear()  # keep the tally accurate if the store reapplies the mutator
        modes = raw.setdefault("owntone", {}).setdefault("airplay_modes", {})
        for output_id, mode in list(modes.items()):
            if str(mode or "").strip().lower() in BUFFERED_AIRPLAY_MODES:
                modes[output_id] = DEFAULT_AIRPLAY_MODE
                changed.append(str(output_id))

    try:
        _store.update(_mutator)
    except Exception:
        logging.exception("buffered-audio off: failed to reset output modes")
        return []

    if changed:
        _owntone_update_live_runtime(state)
    return changed


def _native_setting(state: object, key: str, value: object, *, reject_unsupported: bool = False) -> Outcome:
    ok, restart_needed, error = _push_owntone_native_setting(
        state, key, value, reject_unsupported=reject_unsupported)
    if not ok:
        return Outcome(ok=False, error=error or "OwnTone API error")
    return Outcome(ok=True, result={"restart_required": restart_needed})


def _set_buffered_audio(state: object, value: object) -> Outcome:
    ok, restart_needed, error = _push_owntone_native_setting(
        state, SETTING_BUFFERED_AUDIO_ENABLED, value, reject_unsupported=True)
    if not ok:
        return Outcome(ok=False, error=error or "OwnTone API error")
    reset_outputs: list[str] = []
    if not value:
        reset_outputs = _reset_buffered_output_modes(state)
    return Outcome(ok=True, result={"restart_required": restart_needed, "reset_outputs": reset_outputs})


def _set_start_buffer(state: object, value: object) -> Outcome:
    ok, restart_needed, error = _push_owntone_native_setting(state, SETTING_START_BUFFER_MS, value)
    if not ok:
        return Outcome(ok=False, error=error or "OwnTone API error")
    # The dial status path serves the buffer from this cache; refresh it now so
    # a change reaches the dial on its next poll.
    start_buffer_cache.note_saved(value)
    return Outcome(ok=True, result={"restart_required": restart_needed})


def _set_mdns_grace_period(state: object, seconds: int) -> Outcome:
    settings = _store_of(state)
    if settings is None:
        return Outcome(ok=False, error="Settings store unavailable")

    def _mutator(raw_config: dict) -> None:
        raw_config.setdefault("general", {})["mdns_grace_period_seconds"] = seconds

    try:
        settings.update(_mutator)
    except Exception:
        logging.exception("backend.setting.set: mDNS grace period store update failed")
        return Outcome(ok=False, error="Internal error")

    import autostream_appliances as appliances
    appliances.set_grace_period(seconds)

    ok, restart_needed, error = _forward_mdns_grace_period_to_owntone(state, seconds)
    result: dict = {"restart_required": restart_needed}
    if not ok:
        logging.debug("mDNS grace period OwnTone forward failed: %s", error)
        result["warning"] = error or "OwnTone sync failed"
    return Outcome(ok=True, result=result)


def _set_output_mode(state: object, mode: str, output_id: str) -> Outcome:
    # A page rendered while buffered audio was on keeps offering the buffered
    # modes until it is reloaded, so refuse them here rather than trusting the
    # form's option list to still be current.
    if mode in BUFFERED_AIRPLAY_MODES and not _buffered_audio_is_enabled(state):
        return Outcome(
            ok=False,
            error="Buffered audio is disabled — enable it before selecting this mode")
    settings = _store_of(state)
    if settings is None:
        return Outcome(ok=False, error="Settings store unavailable")

    def _mutator(raw: dict) -> None:
        raw.setdefault("owntone", {}).setdefault("airplay_modes", {})[output_id] = mode

    try:
        settings.update(_mutator)
    except Exception:
        logging.exception("backend.setting.set: output mode store update failed")
        return Outcome(ok=False, error="Internal error")

    _owntone_update_live_runtime(state)
    return Outcome(ok=True, result={"output_id": output_id, "mode": mode})


def _set_output_visibility(state: object, value: object, output_id: str) -> Outcome:
    output_name = value["output_name"]
    visible = value["visible"]
    settings = _store_of(state)
    if settings is None:
        return Outcome(ok=False, error="Settings store unavailable")

    def _mutator(raw: dict) -> None:
        hidden = list(raw.setdefault("webui", {}).get("hidden_outputs") or [])
        name_cf = output_name.casefold()
        if visible:
            hidden = [h for h in hidden if str(h).casefold() != name_cf]
        else:
            if not any(str(h).casefold() == name_cf for h in hidden):
                hidden.append(output_name)
        raw["webui"]["hidden_outputs"] = hidden

    try:
        settings.update(_mutator)
    except Exception:
        logging.exception("backend.setting.set: output visibility store update failed")
        return Outcome(ok=False, error="Internal error")

    if output_id:
        try:
            _owntone_state_update_known_outputs(state, {output_id: output_name})
        except Exception:
            logging.exception("backend.setting.set: known_outputs update failed")

    return Outcome(ok=True, result={"output_name": output_name, "visible": visible})


def _set_output_offset(state: object, raw_offset: object, output_id: str) -> Outcome:
    response = apply_output_offset(state, output_id, raw_offset)
    if not response.get("ok"):
        return Outcome(ok=False, error=response.get("error"))
    return Outcome(ok=True, result={
        "output_id": response["output_id"],
        "offset_ms": response["offset_ms"],
        "applied_live": response["applied_live"],
    })


def _set_output_include_tv(state: object, value: object, output_id: str) -> Outcome:
    """Store whether an Apple TV's HomePods play with the Apple TV, and restart
    the group when it is playing so the change takes effect now."""
    if not store().snapshot().outputs.include_tv_supported:
        return Outcome(ok=False, error="Not supported by the connected player")
    if not output_id:
        return Outcome(ok=False, error="output_id required")
    settings = _store_of(state)
    if settings is None:
        return Outcome(ok=False, error="Settings store unavailable")
    wanted = bool(value)
    changed = wanted != include_tv_for(output_id)
    if changed:
        path = f"owntone.include_tv.{output_id}"
        try:
            settings._set_normalized(get_field_spec(path), wanted, path=path)
        except Exception:
            logging.exception("backend.setting.set: include_tv store update failed")
            return Outcome(ok=False, error="Internal error")
    reselected = False
    if changed:
        unit = store().snapshot().outputs.unit(output_id)
        # A group that is not playing, or is waiting for its HomePods, takes
        # the new value at its next start.
        if unit is not None and unit.selected and unit.reported is not None and unit.reported.selected:
            reselected = get_authority().reselect(output_id, Origin.USER, requester="webui").refused is None
    return Outcome(ok=True, result={"output_id": output_id, "include_tv": wanted, "reselected": reselected})


_BACKEND_SETTINGS = {
    "uncompressed_audio": lambda state, value, output_id: _native_setting(
        state, SETTING_UNCOMPRESSED_ALAC, value),
    "buffered_audio": lambda state, value, output_id: _set_buffered_audio(state, value),
    "start_buffer_ms": lambda state, value, output_id: _set_start_buffer(state, value),
    "user_agent": lambda state, value, output_id: _native_setting(
        state, SETTING_USER_AGENT, value, reject_unsupported=True),
    "mdns_grace_period": lambda state, value, output_id: _set_mdns_grace_period(state, value),
    "output_mode": lambda state, value, output_id: _set_output_mode(state, value, output_id),
    "output_visibility": lambda state, value, output_id: _set_output_visibility(state, value, output_id),
    "output_offset": lambda state, value, output_id: _set_output_offset(state, value, output_id),
    "output_include_tv": lambda state, value, output_id: _set_output_include_tv(state, value, output_id),
}


def _backend_setting(intent: Intent, wait: float) -> Outcome:
    """Apply one backend setting. *context* is the request's state. The result
    says whether the backend asks for a restart ("restart_required") and carries
    what the setting's route replies with."""
    args = intent.args
    return _BACKEND_SETTINGS[args["setting"]](
        intent.context, args["value"], args.get("output_id") or "")


bind("backend.setting.set", _backend_setting, owner=_OWNER)
