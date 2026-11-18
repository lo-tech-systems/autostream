"""autostream_live_config -- settings whose change takes effect while running.

A settings field with a live effect names a function that applies the new
value to the running appliance. The repeat policy fields are registered here:
each change is validated, stored by the settings route, and then pushed to the
audio monitor daemon without a reload.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import autostream_monitor_control as monitor_control
from autostream_config import REPEAT_CODEC_CHOICES, normalize_repeat_codec
from autostream_settings_schema import LiveClass, register_field
from autostream_state import store


def _validate_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    raise ValueError("Value must be true or false")


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
