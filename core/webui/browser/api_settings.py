#!/usr/bin/env python3
"""webui/browser/api_settings.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Settings endpoints.

Contents:
  - send_settings_get_json           -- GET /api/settings
  - send_settings_post_json          -- POST /api/settings
  - send_hostname_post_json          -- POST /api/hostname
  - send_advertisement_post_json     -- POST /api/advertisement
  - send_auto_update_post_json       -- POST /api/auto-update
  - send_save_now_json               -- POST /api/settings/save
  - send_log_level_get_json          -- GET /api/log-level
  - send_log_level_put_json          -- PUT /api/log-level
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from autostream_config import (
    OUTPUT_USAGE_POLL_INTERVAL_MAX,
    OUTPUT_USAGE_POLL_INTERVAL_MIN,
    is_valid_monitor_device_id,
    normalize_update_channel,
)
from autostream_intents import Intent, submit
from autostream_settings import SettingsView
from autostream_state import Origin
from autostream_state.live import state_refresh
from autostream_sysutils import get_system_hostname, set_system_hostname
from urllib.parse import urlparse as _urlparse
from webui.session_state import WebUIState
from autostream_settings_schema import (
    LiveClass,
    cross_validate_hostname_visibility_cascade,
    get_field_spec,
    register_field,
)
from webui import common
from webui.system import updates
from webui import session_state
from webui.browser import first_boot


# ---------------------------------------------------------------------------
# Generic settings API
# ---------------------------------------------------------------------------

def _validate_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    raise ValueError("Value must be true or false")


def _validate_poll_interval(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Value must be a number")
    iv = int(value)
    if iv < OUTPUT_USAGE_POLL_INTERVAL_MIN or iv > OUTPUT_USAGE_POLL_INTERVAL_MAX:
        raise ValueError(
            f"Value must be between {OUTPUT_USAGE_POLL_INTERVAL_MIN}"
            f" and {OUTPUT_USAGE_POLL_INTERVAL_MAX}"
        )
    return iv


def _validate_update_channel(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Value must be 'stable' or 'dev'")
    if value.strip().lower() not in ("stable", "dev"):
        raise ValueError("Value must be 'stable' or 'dev'")
    return normalize_update_channel(value)


class _DuplicateCaptureDeviceError(Exception):
    """Raised by ``send_settings_post_json``'s mutator to signal, atomically
    under ``SettingsStore._lock``, that the capture device being assigned is
    already assigned to the other audio input.

    Applies to any device, not just the Bluetooth loopback: the same
    physical/ALSA device must never be attached to both inputs at once.
    Caught specifically by the caller so the request fails with a 400 error
    message rather than falling through to the generic "Internal error" 200
    response used for unexpected mutator failures.
    """


# Maps public dotted field name → (section, key, validator, live_fn_or_None).
#
# Each row below is registered into the shared SETTINGS_SCHEMA table
# (autostream_settings_schema.py) via the same call that builds this dict,
# rather than living only here -- the validator functions and live_fn
# callables themselves are unchanged (same bodies, same error strings),
# only their bookkeeping is single-sourced.
def _reg_settings_field(path, section, key, validate, live=None,
                         cross_validate=None, mutate=None, live_class=LiveClass.PASSIVE):
    register_field(path, section, key, validate, live=live,
                    cross_validate=cross_validate, mutate=mutate, live_class=live_class)
    return (section, key, validate, live)


_SETTINGS_FIELDS: dict = {
    # Personalisation (no live effect)
    "webui.dark_mode":                          _reg_settings_field("webui.dark_mode", "webui", "dark_mode", _validate_bool),
    "webui.show_master_volume":                 _reg_settings_field("webui.show_master_volume", "webui", "show_master_volume", _validate_bool),
    "webui.show_input_detail":                  _reg_settings_field("webui.show_input_detail", "webui", "show_input_detail", _validate_bool),
    "webui.show_hostname_on_home":              _reg_settings_field("webui.show_hostname_on_home", "webui", "show_hostname_on_home", _validate_bool, cross_validate=cross_validate_hostname_visibility_cascade),
    "webui.control_other_appliances":           _reg_settings_field("webui.control_other_appliances", "webui", "control_other_appliances", _validate_bool),
    "webui.output_usage_poll_interval_seconds": _reg_settings_field("webui.output_usage_poll_interval_seconds", "webui", "output_usage_poll_interval_seconds", _validate_poll_interval),
    "updates.update_channel":                   _reg_settings_field("updates.update_channel", "updates", "update_channel", _validate_update_channel),
}


class _LateFields(Mapping):
    """Fields whose validator and live function are registered by
    autostream_live_config, which the web layer does not import: each row is
    read from the schema when asked, so it is there once that module is."""

    _PATHS = (
        "audio1.gain_db", "audio2.gain_db",
        "audio1.eq_40hz_db", "audio1.eq_100hz_db", "audio1.eq_8khz_db",
        "audio2.eq_40hz_db", "audio2.eq_100hz_db", "audio2.eq_8khz_db",
        "repeat.enabled", "repeat.codec", "repeat.target_minutes",
        "owntone.default_outputs", "owntone.volume_percent",
        "general.silence_seconds", "general.audio_path",
        "audio1.capture_device", "audio2.capture_device",
        "audio1.enabled", "audio2.enabled",
        "audio1.input_type", "audio2.input_type",
        "audio1.silence_threshold", "audio2.silence_threshold",
        "audio1.dynamic_rate_matching", "audio2.dynamic_rate_matching",
        "track_identification.enabled",
        "track_identification.analysis_lead_in_seconds",
        "track_identification.refresh_seconds",
        "track_identification.track_change_silence_seconds",
        "outputs.device_pause_scope", "outputs.pause_off_seconds",
        "outputs.play_after_metadata_ignore_seconds",
    )

    def __getitem__(self, path):
        spec = get_field_spec(path) if path in self._PATHS else None
        if spec is None:
            raise KeyError(path)
        return (spec.section, spec.key, spec.validate, spec.live_fn)

    def __iter__(self):
        return (p for p in self._PATHS if get_field_spec(p) is not None)

    def __len__(self):
        return sum(1 for _ in self)


class _SettingsFieldTable(Mapping):
    """The fields declared here, then the late ones."""

    def __init__(self, own: dict, late: Mapping) -> None:
        self._own = own
        self._late = late

    def __getitem__(self, path):
        if path in self._own:
            return self._own[path]
        return self._late[path]

    def __iter__(self):
        yield from self._own
        yield from self._late

    def __len__(self):
        return len(self._own) + len(self._late)


_SETTINGS_FIELDS = _SettingsFieldTable(_SETTINGS_FIELDS, _LateFields())


def send_settings_get_json(handler, state) -> None:
    """GET /api/settings — return all browser-editable non-secret settings."""
    try:
        parsed = common._config_snapshot(state)
    except Exception as e:
        common.send_json(handler, 200, {"ok": False, "error": str(e)})
        return
    values = {
        "webui.dark_mode":                         parsed.webui.dark_mode,
        "webui.show_master_volume":                parsed.webui.show_master_volume,
        "webui.show_input_detail":                 parsed.webui.show_input_detail,
        "webui.show_hostname_on_home":             parsed.webui.show_hostname_on_home,
        "webui.control_other_appliances":          parsed.webui.control_other_appliances,
        "webui.output_usage_poll_interval_seconds": parsed.webui.output_usage_poll_interval_seconds,
        "updates.update_channel":                  parsed.updates.update_channel,
        "general.audio_path":                      parsed.general.audio_path,
        "repeat.enabled":                          parsed.repeat.enabled,
        "repeat.codec":                            parsed.repeat.codec,
        "repeat.target_minutes":                   parsed.repeat.target_minutes,
    }
    common.send_json(handler, 200, {"ok": True, "values": values})


def send_settings_post_json(handler, state, json_obj: dict) -> None:
    """POST /api/settings -- update one named setting via the SettingsStore.

    Request: {"field": "<dotted.name>", "value": <json_value>}

    Success (HTTP 200):  {"ok": true, "field": "...", "value": <normalised>}
    Validation failure (HTTP 400): {"ok": false, "field": "...", "error": "..."}
    """
    if not isinstance(json_obj, dict):
        common.send_json(handler, 400, {"ok": False, "error": "JSON object required"})
        return

    field = json_obj.get("field")
    if not isinstance(field, str) or not field.strip():
        common.send_json(handler, 400, {"ok": False, "field": "", "error": "field must be a non-empty string"})
        return
    field = field.strip()

    if "value" not in json_obj:
        common.send_json(handler, 400, {"ok": False, "field": field, "error": "value is required"})
        return

    if field not in _SETTINGS_FIELDS:
        common.send_json(handler, 400, {"ok": False, "field": field, "error": "Unknown field"})
        return

    section, key, validator, live_fn = _SETTINGS_FIELDS[field]
    raw_value = json_obj["value"]

    # audio1.capture_device may be cleared to an empty string only while
    # input 1 is disabled (audio1.enabled=false) -- the field validator
    # otherwise rejects empty values unconditionally, same as it always has.
    if field == "audio1.capture_device" and isinstance(raw_value, str) and not raw_value.strip():
        settings_probe = getattr(state, "settings", None)
        audio1_enabled = True
        if isinstance(settings_probe, SettingsView):
            try:
                audio1_enabled = bool(settings_probe.snapshot().audio1_enabled)
            except Exception:
                audio1_enabled = True
        if audio1_enabled:
            common.send_json(handler, 400, {"ok": False, "field": field, "error": "Value must be a non-empty string"})
            return
        normalized = ""
    else:
        try:
            normalized = validator(raw_value)
        except ValueError as e:
            common.send_json(handler, 400, {"ok": False, "field": field, "error": str(e)})
            return

    settings = getattr(state, "settings", None)
    if not isinstance(settings, SettingsView):
        common.send_json(handler, 200, {"ok": False, "field": field, "error": "Settings store unavailable"})
        return

    # Enabling input 1 requires a valid capture device already on record --
    # mirrors the completeness gates in autostream_config.unconfigured() and
    # autostream_commissioning.is_technically_complete().
    if field == "audio1.enabled" and normalized:
        try:
            current_device = str(settings.snapshot().audio1.capture_device or "").strip()
        except Exception:
            current_device = ""
        if not is_valid_monitor_device_id(current_device):
            common.send_json(handler, 400, {
                "ok": False,
                "field": field,
                "error": "Set a valid capture device before enabling input 1",
            })
            return

    # Cross-input exclusivity guard: the same capture device must never be
    # assigned to both inputs at once (generalised from the Bluetooth-only
    # guard -- applies to any device, not just the loopback). This is a
    # fast-path check against the live snapshot (not authoritative — see
    # the equivalent check inside _mutator below, which runs atomically
    # under the store lock and is what actually prevents two concurrent
    # requests both racing past this early check and both committing).
    if field in ("audio1.capture_device", "audio2.capture_device") and normalized:
        other_section = "audio2" if field == "audio1.capture_device" else "audio1"
        try:
            other_value = str(getattr(settings.snapshot(), other_section).capture_device or "").strip()
        except Exception:
            other_value = ""
        if other_value == normalized:
            common.send_json(handler, 400, {
                "ok": False,
                "field": field,
                "error": "That device is already assigned to the other input; choose a different device or reassign it first",
            })
            return

    # The mutation (including the input type's non-flat write and the
    # hostname-visibility cascade) and the live-push side effect are the schema
    # row's own `mutate`/`cross_validate`/`live_fn`, applied by the settings
    # intent, not logic hand-rolled at this call site. The authoritative
    # cross-input exclusivity check is `cross_validate_capture_device_unique`,
    # run from inside the store's commit against the raw copy about to be
    # committed -- same atomicity guarantee (under SettingsStore._lock) as any
    # single-field mutator.
    reply = submit(Intent(
        "settings.apply", {"changes": ((field, normalized),)}, Origin.USER, "webui",
        context=state))
    if not reply.ok:
        if "invalid" in reply.result:
            common.send_json(handler, 400, {"ok": False, "field": field, "error": reply.result["invalid"]})
        else:
            common.send_json(handler, 200, {"ok": False, "field": field, "error": "Internal error"})
        return
    outcome = reply.result["outcomes"][0]

    resp: dict = {"ok": True, "field": field, "value": normalized}
    if live_fn is not None:
        resp["live"] = outcome["live"]
        if not outcome["live"]:
            resp["live_error"] = outcome["live_error"]
    # outcome["reload_scheduled"] (SetOutcome.reload_scheduled) is
    # deliberately NOT added to the wire response here -- this endpoint's
    # response shape must stay byte-identical to what callers already
    # depend on. The field is available to any in-process caller of
    # settings.set()/_set_normalized() via the returned SetOutcome; wiring it
    # onto the wire is a separate, later decision.
    common.send_json(handler, 200, resp)


# -----------------------------------------------------------------------------
# Dedicated transaction endpoints for privileged/external operations
# -----------------------------------------------------------------------------

def send_hostname_post_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/settings/hostname -- change the system hostname.

    Calls set_system_hostname(); on success, returns a redirect URL so the
    browser can follow the appliance to its new mDNS address.
    """
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        common.send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    new_hn = str(payload.get("value") or "").strip()
    if not new_hn:
        common.send_json(handler, 400, {"ok": False, "error": "Hostname must not be empty"})
        return

    old_hn = get_system_hostname()
    if new_hn == old_hn:
        common.send_json(handler, 200, {"ok": True, "changed": False, "value": old_hn})
        return

    try:
        set_system_hostname(new_hn)
    except Exception as exc:
        logging.warning("send_hostname_post_json: hostname change failed: %s", exc)
        common.send_json(handler, 200, {"ok": False, "error": "Hostname could not be changed"})
        return

    state_refresh()
    host_header = str(handler.headers.get("Host", "") or "")
    port_num = _urlparse(f"http://{host_header}").port
    port = str(port_num) if port_num else None
    host_p = f"{new_hn}.local:{port}" if port else f"{new_hn}.local"
    redirect_url = f"http://{host_p}/setup"

    common.send_json(handler, 200, {"ok": True, "changed": True, "value": new_hn, "redirect_url": redirect_url})


def send_advertisement_post_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/settings/advertisement -- toggle peer advertisement.

    The advertisement intent applies the preference and persists it to the
    store only on success.
    """
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        common.send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    value = payload.get("value")
    if not isinstance(value, bool):
        common.send_json(handler, 400, {"ok": False, "error": "value must be a boolean"})
        return

    try:
        version = updates.get_app_version()
    except Exception:
        logging.exception("send_advertisement_post_json: unexpected failure")
        common.send_json(handler, 200, {"ok": False, "error": "Advertisement preference could not be applied"})
        return
    reply = submit(Intent(
        "settings.advertisement", {"value": value, "version": version}, Origin.USER, "webui",
        context=state))
    if not reply.ok:
        common.send_json(handler, 200, {"ok": False, "error": "Advertisement preference could not be applied"})
        return
    if "warning" in reply.result:
        common.send_json(handler, 200, {"ok": True, "value": value, "warning": reply.result["warning"]})
        return

    common.send_json(handler, 200, {"ok": True, "value": value})


def send_auto_update_post_json(handler, state: WebUIState, body: str) -> None:
    """POST /api/settings/auto-update -- toggle the automatic update timer.

    The auto-update intent calls the toggle-update-timer admin command and
    persists to the store only on success, so a failed privileged call cannot
    commit an incorrect value.
    """
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        common.send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    value = payload.get("value")
    if not isinstance(value, bool):
        common.send_json(handler, 400, {"ok": False, "error": "value must be a boolean"})
        return

    reply = submit(Intent(
        "settings.auto_update", {"value": value}, Origin.USER, "webui", context=state))
    if not reply.ok:
        common.send_json(handler, 200, {"ok": False, "error": reply.error})
        return
    if "warning" in reply.result:
        common.send_json(handler, 200, {"ok": True, "value": value, "warning": reply.result["warning"]})
        return

    common.send_json(handler, 200, {"ok": True, "value": value})


def send_save_now_json(handler, state: WebUIState) -> None:
    """POST /api/settings/save -- flush in-memory settings to disk synchronously.

    Called before durability-sensitive actions (reboot, update install) so
    that in-flight autosave changes are not lost when the process restarts.
    Returns an error if the store is unavailable or the save fails; the
    caller should treat a failure as a barrier and not proceed.
    """
    reply = submit(Intent("settings.save", {}, Origin.USER, "webui", context=state))
    if reply.ok:
        common.send_json(handler, 200, {"ok": True})
    else:
        common.send_json(handler, 200, {"ok": False, "error": reply.error})


# ---------------------------------------------------------------------------
# Log-level and playing-status APIs
# ---------------------------------------------------------------------------

# Fields the PUT /api/log-level body is allowed to contain.
_LOG_LEVEL_PUT_ALLOWED_FIELDS: frozenset[str] = frozenset({"level"})


def send_log_level_get_json(handler, state: WebUIState) -> None:
    """GET /api/log-level — return current log-level policy state."""
    from autostream_state.live import get_log_level_state
    result = get_log_level_state(
        state.config_path, settings=getattr(state, "settings", None)
    )
    common.send_json(handler, 200, result)


def send_log_level_put_json(
    handler,
    state: WebUIState,
    json_obj: dict,
    changed_by: str,
) -> None:
    """PUT /api/log-level -- validate, persist, and apply log level.

    `changed_by` must be "user" or "system"; the caller determines which
    based on the request classification (direct-local vs. browser-proxied).
    Unknown fields in the body produce HTTP 400.
    """
    # Reject any unknown or prohibited fields.
    unknown = set(json_obj.keys()) - _LOG_LEVEL_PUT_ALLOWED_FIELDS
    if unknown:
        common.send_browser_api_error(
            handler, 400, f"Unknown field(s): {', '.join(sorted(unknown))}"
        )
        return

    requested_level = json_obj.get("level")
    if requested_level is None:
        common.send_browser_api_error(handler, 400, "Missing required field: level")
        return

    # Persistence goes through the process's SettingsStore: the store owns the
    # config file and its next save would revert a direct disk write.
    reply = submit(Intent(
        "log.level.set", {"level": requested_level, "changed_by": changed_by},
        Origin.USER if changed_by == "user" else Origin.SYSTEM, "webui", context=state))
    result = reply.result.get("response", {})
    if not reply.ok:
        error = reply.error or "Unknown error"
        if "Unsupported" in error or "Invalid" in error:
            common.send_browser_api_error(handler, 400, error)
        else:
            common.send_browser_api_error(handler, 500, "Configuration could not be saved")
        return

    # Note: watcher forwarding is now performed inside set_log_level itself
    # (applied["wifi_watcher"]) so every caller stays in sync, not just this
    # HTTP handler. Do not call forward_log_level_to_watcher again here.
    common.send_json(handler, 200, result)


# -----------------------------------------------------------------------------
# Route-table adapters: the calling convention the dispatcher uses (handler,
# state[, body]) in front of the senders above.
# -----------------------------------------------------------------------------


def _route_post_settings(handler, state, body_str):
    # Legacy inline check (do_POST's former /api/settings arm): unlike the
    # generic requires_body gate (which only rejects an *empty* body), this
    # route requires the body to have parsed as a JSON object -- a
    # form-urlencoded body (json_obj stays None) is rejected too.
    json_obj = common._route_post_json_obj(handler)
    if not isinstance(json_obj, dict):
        handler.send_error(400, "JSON object required")
        return
    send_settings_post_json(handler, state, json_obj)


def _route_post_settings_save(handler, state, body_str):
    send_save_now_json(handler, state)


def _route_get_log_level(handler, state):
    if handler._is_direct_local():
        send_log_level_get_json(handler, state)
        return
    # Proxied caller: reproduce the commissioning gate. No auth gate --
    # "/api/log-level" is in AUTH.ALLOWLIST_PATHS, so requires_auth() is
    # always False for it.
    if handler._commissioning_required():
        first_boot._route_commissioning_redirect_get(handler, state)
        return
    handler._csrf_token = session_state.AUTH.ensure_session(handler)
    send_log_level_get_json(handler, state)


def _route_put_log_level(handler, state):
    # Reproduces do_PUT verbatim: its own bespoke body-read (Content-Type
    # must be application/json -> 415, distinct from every other route's
    # parse), no commissioning gate at all, and CSRF-only (no PIN) for a
    # proxied caller.
    body_bytes = handler._read_post_body_bytes()
    if body_bytes is None:
        return
    try:
        body_str = body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        handler.send_error(400, "Request body is not valid UTF-8")
        return

    ct = (handler.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
    if ct != "application/json":
        handler.send_error(415, "Content-Type must be application/json")
        return

    if not body_str:
        handler.send_error(400, "Missing request body")
        return

    try:
        json_obj = json.loads(body_str)
    except json.JSONDecodeError:
        handler.send_error(400, "Invalid JSON")
        return

    if not isinstance(json_obj, dict):
        handler.send_error(400, "JSON object required")
        return

    if handler._is_direct_local():
        send_log_level_put_json(handler, state, json_obj, "system")
        return

    csrf_token = handler._extract_csrf_token(None, json_obj)
    if not session_state.AUTH.validate_csrf(handler, csrf_token):
        common.send_browser_api_error(handler, 403, "CSRF validation failed")
        return

    send_log_level_put_json(handler, state, json_obj, "user")
