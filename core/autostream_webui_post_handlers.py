#!/usr/bin/env python3
"""autostream_webui_post_handlers.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

POST request handlers for the autostream Web UI.

Contents:
  - handle_output_update          -- POST /api/output
  - handle_setup_post             -- POST /setup
  - handle_live_input_eq_update   -- POST /api/input_eq
  - handle_live_input_gain_update -- POST /api/input_gain
  - handle_factory_reset_post     -- POST /api/factory-reset
"""

from __future__ import annotations

import json
import logging
import threading

from typing import Optional
from urllib.parse import parse_qs, quote

from autostream_config import (
    CONFIG_IO_LOCK,
    DEFAULT_AIRPLAY_MODE,
    load_config,
    mark_configured,
    parse_config,
    save_config,
    set_input_mode,
)
from autostream_core import (
    apply_track_id_config_live,
    request_config_reload,
    set_live_input_eq,
    set_live_input_gain,
    update_live_owntone_runtime,
    update_live_silence_seconds,
    update_playback_input_config,
)
from autostream_player_service import config_airplay_mode_to_backend
from autostream_sysutils import factory_reset_system, get_system_hostname, run_admin_cmd, set_system_hostname

from autostream_webui_common import (
    _set_flash_cookie,
    build_top_banner_html,
    locked_load_config,
    send_hostname_changed_page,
)
from autostream_webui_state import WebUIState
from autostream_webui_api import _ADVERTISE_LOCK, send_json, send_settings_post_json
from autostream_webui_page_setup import send_setup_page


def _fld(form: dict, n: str, d: str = "") -> str:
    """Return the first value for form field *n*, or *d* if absent/empty."""
    return (form.get(n, []) or [d])[0]


# -----------------------------------------------------------------------------
# Output toggle / volume handler
# -----------------------------------------------------------------------------

def handle_output_update(handler, state: WebUIState, body: str) -> None:
    try:
        payload = json.loads(body)
        out_id = str(payload.get("id") or "").strip()

        cfg = locked_load_config(state.config_path)
        parsed = parse_config(cfg)
        base_url = parsed.owntone.base_url.rstrip("/")

        op = (payload.get("op") or "").strip().lower()
        offset_ms_raw = parsed.owntone.output_offsets_ms.get(out_id) if out_id else None
        offset_ms = int(offset_ms_raw) if offset_ms_raw is not None else None
        mode_text = parsed.owntone.output_airplay_modes.get(out_id, DEFAULT_AIRPLAY_MODE) if out_id else DEFAULT_AIRPLAY_MODE
        mode = config_airplay_mode_to_backend(mode_text)

        from autostream_appliance_models import apply_output_mutation
        result = apply_output_mutation(base_url, out_id, payload, offset_ms=offset_ms, mode=mode)
        send_json(handler, 200, result)
    except Exception as e:
        logging.error("Update failed: %s", e)
        send_json(handler, 200, {"ok": False, "error": str(e)})


# -----------------------------------------------------------------------------
# Setup form POST
# -----------------------------------------------------------------------------

def handle_setup_post(handler, state: WebUIState, auth, body: str) -> None:
    form = parse_qs(body)
    def fld(n, d=""): return _fld(form, n, d)
    _track_id_changed = False
    try:
        with CONFIG_IO_LOCK:
            cfg = load_config(state.config_path)
            p = parse_config(cfg)

            # Snapshot daemon-relevant values before any changes so we can decide
            # whether a full coordinator reload is needed after saving.
            old_audio1_device    = p.audio1.capture_device
            old_audio1_threshold = p.audio1.silence_threshold_dbfs
            old_audio2_enabled   = p.audio2_enabled
            old_audio2_device    = p.audio2.capture_device
            old_audio2_threshold = p.audio2.silence_threshold_dbfs
            old_silence_seconds  = p.general.silence_seconds
            new_audio2_enabled   = "audio2_enabled" in form
            new_audio1_turntable = "audio_turntable" in form
            new_audio2_turntable = "audio2_turntable" in form

            # Hostname
            old_hn = get_system_hostname()
            nh = fld("system_hostname").strip()
            hostname_changed = bool(nh and nh != old_hn)
            if hostname_changed:
                set_system_hostname(nh)

            # Config updates
            a1 = cfg.setdefault("audio1", {})
            a1["capture_device"] = fld("audio_capture_device", p.audio1.capture_device)
            new_audio1_threshold = set_input_mode(cfg, 1, new_audio1_turntable)
            a1["gain_db"] = float(fld("audio1_gain_db", str(p.audio1.gain_db)))
            a1["eq_40hz_db"] = float(fld("audio1_eq_40hz_db", str(p.audio1.eq_40hz_db)))
            a1["eq_100hz_db"] = float(fld("audio1_eq_100hz_db", str(p.audio1.eq_100hz_db)))
            a1["eq_8khz_db"] = float(fld("audio1_eq_8khz_db", str(p.audio1.eq_8khz_db)))
            a1.pop("eq_10khz_db", None)

            a2 = cfg.setdefault("audio2", {})
            a2["enabled"] = bool(new_audio2_enabled)
            a2["capture_device"] = fld("audio2_capture_device", p.audio2.capture_device)
            new_audio2_threshold = set_input_mode(cfg, 2, new_audio2_turntable)
            a2["gain_db"] = float(fld("audio2_gain_db", str(p.audio2.gain_db)))
            a2["eq_40hz_db"] = float(fld("audio2_eq_40hz_db", str(p.audio2.eq_40hz_db)))
            a2["eq_100hz_db"] = float(fld("audio2_eq_100hz_db", str(p.audio2.eq_100hz_db)))
            a2["eq_8khz_db"] = float(fld("audio2_eq_8khz_db", str(p.audio2.eq_8khz_db)))
            a2.pop("eq_10khz_db", None)

            owntone = cfg.setdefault("owntone", {})
            owntone["output_name"] = fld("owntone_output_name", p.owntone.output_name)
            owntone["volume_percent"] = int(fld("owntone_volume_percent", str(p.owntone.volume_percent)))

            general = cfg.setdefault("general", {})
            general["silence_seconds"] = int(fld("silence_seconds", str(p.general.silence_seconds)))

            # Snapshot the current advertise preference for post-save comparison.
            old_advertise = p.webui.advertise_appliance
            new_advertise = old_advertise  # default: no change

            # Only persist show_master_volume / show_input_detail when the Customise
            # panel was rendered (sentinel field present). During initial setup the
            # panel is absent and the checkboxes are never submitted; leaving the
            # keys absent lets parse_config use its defaults (True / False).
            if "webui_show_master_volume_present" in form:
                webui = cfg.setdefault("webui", {})
                webui["show_master_volume"] = bool("webui_show_master_volume" in form)
                webui["show_input_detail"] = bool("webui_show_input_detail" in form)
                webui["dark_mode"] = bool("webui_dark_mode" in form)
                new_show_hostname = bool("webui_show_hostname_on_home" in form)
                webui["show_hostname_on_home"] = new_show_hostname
                # Enforce dependency: control_other_appliances requires show_hostname_on_home.
                if not new_show_hostname:
                    webui["control_other_appliances"] = False
                elif "webui_control_other_appliances_present" in form:
                    webui["control_other_appliances"] = bool("webui_control_other_appliances" in form)
                # advertise_appliance is intentionally NOT saved here — it requires
                # a successful privileged service operation before being persisted.
                # That field-level update happens after this block.

            if "webui_output_usage_poll_interval_present" in form:
                from autostream_config import normalize_output_usage_poll_interval
                webui = cfg.setdefault("webui", {})
                webui["output_usage_poll_interval_seconds"] = normalize_output_usage_poll_interval(
                    fld("webui_output_usage_poll_interval_seconds", "3")
                )

            # Capture the intended advertise value when the panel was rendered.
            if "webui_advertise_appliance_present" in form:
                new_advertise = bool("webui_advertise_appliance" in form)

            # Persist auto_update when the updates panel was rendered (initial setup omits it).
            old_auto_update = p.updates.auto_update
            new_auto_update = old_auto_update  # default: no change
            if "updates_auto_update_present" in form:
                new_auto_update = "updates_auto_update" in form
                cfg.setdefault("updates", {})["auto_update"] = bool(new_auto_update)

            # Persist update_channel when the updates panel was rendered.
            # Channel changes require no timer operation or service restart.
            if "updates_channel_present" in form:
                new_channel = "dev" if "updates_prerelease_channel" in form else "stable"
                cfg.setdefault("updates", {})["update_channel"] = new_channel

            # Persist defaults into the JSON the first time it is created (or if missing).
            if not str(general.get("log_file", "") or "").strip():
                general["log_file"] = p.general.log_file

            # Fixed appliance path, so correct it rather than only filling it in.
            general["fifo_path"] = p.general.fifo_path

            # Track identification settings — only saved when sentinel is present.
            _track_id_changed = False
            if "track_identification_present" in form:
                ti = cfg.setdefault("track_identification", {})
                old_ti_enabled = p.track_identification.enabled
                new_ti_enabled = "track_identification_enabled" in form
                ti["enabled"] = bool(new_ti_enabled)
                from autostream_config import (
                    TRACK_ID_DEFAULT_PROVIDER,
                    TRACK_ID_DEFAULT_RETRY_SECONDS,
                    TRACK_ID_DEFAULT_SNAPSHOT_SECONDS,
                    normalize_track_id_analysis_lead_in_seconds,
                    normalize_track_id_refresh_seconds,
                    normalize_track_id_track_change_silence_seconds,
                )
                ti.setdefault("provider", p.track_identification.provider or TRACK_ID_DEFAULT_PROVIDER)
                ti["analysis_lead_in_seconds"] = normalize_track_id_analysis_lead_in_seconds(
                    fld("ti_analysis_lead_in_seconds"))
                ti["refresh_seconds"] = normalize_track_id_refresh_seconds(
                    fld("ti_refresh_seconds"))
                ti["track_change_silence_seconds"] = normalize_track_id_track_change_silence_seconds(
                    fld("ti_track_change_silence_seconds"))
                ti.setdefault("snapshot_seconds", TRACK_ID_DEFAULT_SNAPSHOT_SECONDS)
                ti.setdefault("retry_seconds", TRACK_ID_DEFAULT_RETRY_SECONDS)
                ti.pop("interval_seconds", None)  # remove legacy field
                if new_ti_enabled != old_ti_enabled:
                    _track_id_changed = True

            save_config(state.config_path, cfg)
            mark_configured(state.config_path)

        # Sync the autostream update timer when auto_update changed.
        if new_auto_update != old_auto_update:
            verb = "enable" if new_auto_update else "disable"
            result = run_admin_cmd(["toggle-update-timer", verb], timeout=5.0)
            if result.returncode != 0:
                # Roll back: revert auto_update to the previous value.
                cfg.setdefault("updates", {})["auto_update"] = bool(old_auto_update)
                try:
                    with CONFIG_IO_LOCK:
                        save_config(state.config_path, cfg)
                except Exception:
                    logging.warning("toggle-update-timer rollback write failed")
                logging.warning(
                    "toggle-update-timer %s failed (rc=%d): %s",
                    verb, result.returncode, (result.stderr or "").strip(),
                )
                send_setup_page(handler, state, auth,
                                flash_msg="Auto-update toggle failed; timer could not be updated.",
                                flash_type="error")
                return

        # Race-safe advertisement preference field-level update.
        # Serialize with _ADVERTISE_LOCK; do not hold CONFIG_IO_LOCK during admin call.
        if "webui_advertise_appliance_present" in form and new_advertise != old_advertise:
            try:
                from autostream_appliances import reconcile_appliance_announcement
                from autostream_webui_common import get_app_version
                with _ADVERTISE_LOCK:
                    ok = reconcile_appliance_announcement(get_app_version(), new_advertise)
                    if not ok:
                        logging.warning(
                            "handle_setup_post: advertisement preference admin call failed; "
                            "not persisting advertise_appliance=%s",
                            new_advertise,
                        )
                        send_setup_page(
                            handler, state, auth,
                            flash_msg="Advertisement preference could not be applied; check logs.",
                            flash_type="error",
                        )
                        return
                    # Admin call succeeded: re-load fresh config and change only this field.
                    try:
                        with CONFIG_IO_LOCK:
                            fresh_cfg = load_config(state.config_path)
                            fresh_cfg.setdefault("webui", {})["advertise_appliance"] = new_advertise
                            save_config(state.config_path, fresh_cfg)
                    except Exception:
                        logging.warning(
                            "handle_setup_post: failed to persist advertise_appliance=%s; "
                            "rolling back service state",
                            new_advertise,
                        )
                        # Roll back: restore previous service state.
                        reconcile_appliance_announcement(get_app_version(), old_advertise)
                        send_setup_page(
                            handler, state, auth,
                            flash_msg="Advertisement preference could not be saved; check logs.",
                            flash_type="error",
                        )
                        return
            except Exception:
                logging.exception("handle_setup_post: advertisement preference update failed")
                # Do not abort the whole save; the other preferences were already saved.

        update_live_owntone_runtime(
            output_name=fld("owntone_output_name", p.owntone.output_name),
            volume_percent=fld(
                "owntone_volume_percent",
                str(p.owntone.volume_percent),
            ),
            output_offsets_ms=p.owntone.output_offsets_ms,
            output_airplay_modes=p.owntone.output_airplay_modes,
        )
        update_playback_input_config(
            1,
            enabled=True,
            is_turntable=new_audio1_turntable,
            stylus_life_hours=p.audio1.stylus_life_hours,
            belt_life_hours=p.audio1.belt_life_hours,
            belt_life_years=p.audio1.belt_life_years,
            bearing_life_hours=p.audio1.bearing_life_hours,
            bearing_life_years=p.audio1.bearing_life_years,
        )
        update_playback_input_config(
            2,
            enabled=new_audio2_enabled,
            is_turntable=new_audio2_turntable,
            stylus_life_hours=p.audio2.stylus_life_hours,
            belt_life_hours=p.audio2.belt_life_hours,
            belt_life_years=p.audio2.belt_life_years,
            bearing_life_hours=p.audio2.bearing_life_hours,
            bearing_life_years=p.audio2.bearing_life_years,
        )

        # One-shot success banner (cookie-based) to avoid sticky URLs in iOS A2HS/PWA.
        _set_flash_cookie(handler, "Settings saved", max_age=30)

        # Redirect back to / on save
        next_path = "/"

        if hostname_changed:
            send_hostname_changed_page(handler, nh, path=next_path, show_nav=False)
        else:
            handler.send_response(302)
            handler.send_header("Location", next_path)
            handler.send_header("Content-Length", "0")
            handler.end_headers()

        # Only restart the coordinator if a setting that requires daemon
        # reconfiguration actually changed.
        try:
            new_silence_seconds = int(fld("silence_seconds", str(old_silence_seconds)))
        except ValueError:
            new_silence_seconds = old_silence_seconds

        daemon_changed = (
            fld("audio_capture_device", old_audio1_device) != old_audio1_device
            or new_audio1_threshold != old_audio1_threshold
            or new_audio2_enabled != old_audio2_enabled
            or fld("audio2_capture_device", old_audio2_device) != old_audio2_device
            or new_audio2_threshold != old_audio2_threshold
        )
        silence_seconds_changed = new_silence_seconds != old_silence_seconds

        if silence_seconds_changed and not daemon_changed:
            if not update_live_silence_seconds(new_silence_seconds):
                daemon_changed = True

        if daemon_changed:
            request_config_reload()
        elif _track_id_changed:
            apply_track_id_config_live(state.config_path)
    except Exception:
        logging.exception("handle_setup_post: unexpected failure during save")
        send_setup_page(handler, state, auth, flash_msg="Save failed", flash_type="error")


# -----------------------------------------------------------------------------
# Live EQ / gain update handlers
# -----------------------------------------------------------------------------

def handle_live_input_eq_update(handler, state: WebUIState, body: str) -> None:
    """Apply live per-input EQ changes to autostream_monitor and persist to the store."""
    import math
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    try:
        raw_index = payload.get("input", 0)
        if isinstance(raw_index, bool):
            raise TypeError("bool")
        input_index = int(raw_index)
        eq_fields = ("eq_40hz_db", "eq_100hz_db", "eq_8khz_db")
        for f in eq_fields:
            if isinstance(payload.get(f), bool):
                raise TypeError("bool")
        eq_40hz_db = float(payload.get("eq_40hz_db", 0.0))
        eq_100hz_db = float(payload.get("eq_100hz_db", 0.0))
        eq_8khz_db = float(payload.get("eq_8khz_db", 0.0))
    except Exception:
        send_json(handler, 400, {"ok": False, "error": "Invalid EQ payload"})
        return

    if input_index not in (1, 2):
        send_json(handler, 400, {"ok": False, "error": "input must be 1 or 2"})
        return

    for val in (eq_40hz_db, eq_100hz_db, eq_8khz_db):
        if not math.isfinite(val) or val < -10.0 or val > 10.0:
            send_json(handler, 400, {"ok": False, "error": "EQ gain must be between -10 and 10 dB"})
            return

    # Persist all three bands atomically to the store (all bands or none).
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if isinstance(settings, _SettingsStore):
        section = f"audio{input_index}"
        try:
            def _mutate(raw: dict) -> None:
                s = raw.setdefault(section, {})
                s["eq_40hz_db"] = eq_40hz_db
                s["eq_100hz_db"] = eq_100hz_db
                s["eq_8khz_db"] = eq_8khz_db
            settings.update(_mutate)
        except Exception:
            logging.warning("handle_live_input_eq_update: store write failed", exc_info=True)

    ok = set_live_input_eq(
        input_index=input_index,
        eq_40hz_db=eq_40hz_db,
        eq_100hz_db=eq_100hz_db,
        eq_8khz_db=eq_8khz_db,
    )
    if not ok:
        send_json(handler, 200, {"ok": False, "error": "Could not update live EQ"})
        return

    send_json(handler, 200, {
        "ok": True,
        "input": input_index,
        "eq_40hz_db": eq_40hz_db,
        "eq_100hz_db": eq_100hz_db,
        "eq_8khz_db": eq_8khz_db,
    })


def handle_live_input_gain_update(handler, state: WebUIState, body: str) -> None:
    """Apply live per-input gain changes to autostream_monitor and persist to the store."""
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    try:
        raw_index = payload.get("input", 0)
        if isinstance(raw_index, bool):
            raise TypeError("bool")
        input_index = int(raw_index)
    except Exception:
        send_json(handler, 400, {"ok": False, "error": "Invalid gain payload"})
        return

    if input_index not in (1, 2):
        send_json(handler, 400, {"ok": False, "error": "input must be 1 or 2"})
        return

    field = f"audio{input_index}.gain_db"
    send_settings_post_json(handler, state, {"field": field, "value": payload.get("gain_db")})


# -----------------------------------------------------------------------------
# Factory reset handler
# -----------------------------------------------------------------------------

def handle_factory_reset_post(handler, state: WebUIState, auth) -> None:
    """POST /api/factory-reset — schedule factory reset via privileged helper.

    The privileged helper schedules the actual reset as a transient systemd
    unit (escaping the autostream.service cgroup) and returns immediately, so
    this handler completes before the reset sequence begins.

    The client should navigate to /offline/resetting immediately after
    issuing this request and must not wait for a meaningful response body,
    since the service will be stopped as part of the reset sequence.

    Dirty in-memory settings are discarded rather than flushed; factory reset
    wipes the config file anyway so saving first would be misleading.
    """
    from autostream_settings import SettingsStore as _SettingsStore
    settings = getattr(state, "settings", None)
    if isinstance(settings, _SettingsStore):
        try:
            settings.close(save=False)
        except Exception:
            logging.warning("handle_factory_reset_post: store close failed", exc_info=True)
    try:
        factory_reset_system()
        send_json(handler, 200, {"ok": True})
    except Exception as e:
        logging.error("handle_factory_reset_post: scheduling failed: %s", e)
        send_json(handler, 500, {"ok": False, "error": "Factory reset could not be scheduled", "detail": str(e)})
