#!/usr/bin/env python3
"""autostream_webui_post_handlers.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

POST request handlers for the autostream Web UI.

Contents:
  - handle_output_update          -- POST /api/output
  - handle_setup_post             -- POST /setup
  - handle_live_input_eq_update   -- POST /api/input_eq
  - handle_live_input_gain_update -- POST /api/input_gain
  - handle_owntone_setup_post     -- POST /owntone-setup
  - handle_factory_reset_post     -- POST /api/factory-reset
"""

from __future__ import annotations

import html
import json
import logging
import textwrap
import threading

from typing import Optional
from urllib.parse import parse_qs, quote, urlparse

from autostream_config import (
    CONFIG_IO_LOCK,
    DEFAULT_AIRPLAY_MODE,
    load_config,
    load_state,
    mark_configured,
    normalize_airplay_mode,
    parse_config,
    save_config,
    save_state,
    unconfigured,
)
from autostream_core import (
    request_config_reload,
    set_live_input_eq,
    set_live_input_gain,
    update_live_owntone_runtime,
    update_live_silence_seconds,
    update_playback_input_config,
)
from autostream_players import (
    SETTING_DEVICE_REMOVAL_GRACE_PERIOD,
    SETTING_DEVICE_REMOVAL_GRACE_PERIOD_DEFAULT_MINUTES,
    SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MAX_MINUTES,
    SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MIN_MINUTES,
    SETTING_START_BUFFER_MS,
    SETTING_START_BUFFER_MS_DEFAULT,
    SETTING_START_BUFFER_MS_MAX,
    SETTING_START_BUFFER_MS_MIN,
    SETTING_START_BUFFER_MS_STEP,
    SETTING_UNCOMPRESSED_ALAC,
)
from autostream_player_service import (
    config_airplay_mode_to_backend,
    save_setting,
)
from autostream_playback_stats import suggested_silence_threshold_dbfs
from autostream_sysutils import factory_reset_system, get_system_hostname, run_admin_cmd, set_system_hostname

# Dedicated lock for serializing advertisement preference changes.
# Must not be held while CONFIG_IO_LOCK is held, and vice versa.
_ADVERTISE_LOCK = threading.Lock()
from autostream_webui_assets import BANNER_HTML, STYLE_CSS, VIEWPORT_META
from autostream_webui_common import (
    _set_flash_cookie,
    build_top_banner_html,
    locked_load_config,
)
from autostream_webui_state import WebUIState
from autostream_webui_api import send_json
from autostream_webui_page_setup import send_setup_page
from autostream_webui_page_owntone import send_owntone_setup_page, start_owntone_restart_async


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
            new_audio1_threshold = suggested_silence_threshold_dbfs(new_audio1_turntable)
            new_audio2_threshold = suggested_silence_threshold_dbfs(new_audio2_turntable)

            # Hostname
            old_hn = get_system_hostname()
            nh = fld("system_hostname").strip()
            hostname_changed = bool(nh and nh != old_hn)
            if hostname_changed:
                set_system_hostname(nh)

            # Config updates
            a1 = cfg.setdefault("audio1", {})
            a1["capture_device"] = fld("audio_capture_device", p.audio1.capture_device)
            a1["silence_threshold"] = new_audio1_threshold
            a1["turntable"] = bool(new_audio1_turntable)
            a1["gain_db"] = float(fld("audio1_gain_db", str(p.audio1.gain_db)))
            a1["eq_40hz_db"] = float(fld("audio1_eq_40hz_db", str(p.audio1.eq_40hz_db)))
            a1["eq_100hz_db"] = float(fld("audio1_eq_100hz_db", str(p.audio1.eq_100hz_db)))
            a1["eq_8khz_db"] = float(fld("audio1_eq_8khz_db", str(p.audio1.eq_8khz_db)))
            a1.pop("eq_10khz_db", None)

            a2 = cfg.setdefault("audio2", {})
            a2["enabled"] = bool(new_audio2_enabled)
            a2["capture_device"] = fld("audio2_capture_device", p.audio2.capture_device)
            a2["silence_threshold"] = new_audio2_threshold
            a2["turntable"] = bool(new_audio2_turntable)
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

            if not str(general.get("fifo_path", "") or "").strip():
                general["fifo_path"] = p.general.fifo_path

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
            host_header = handler.headers.get("Host", "")
            port_num = urlparse(f"http://{host_header}").port
            port = str(port_num) if port_num else None
            host_p = f"{nh}.local:{port}" if port else f"{nh}.local"
            redirect_url = f"http://{host_p}{next_path}"

            # Render a redirect page
            lic_html, lic_spacer = build_top_banner_html(flash_msg=None)
            safe_url = html.escape(redirect_url)

            body_html = textwrap.dedent(f"""\
              <!DOCTYPE html><html><head><meta charset="utf-8">{VIEWPORT_META}
              <title>Hostname changed</title>
              <meta http-equiv="refresh" content="5;url={safe_url}">
              <style>{STYLE_CSS}</style></head>
              <body>{lic_html}{lic_spacer}<div class="container">{BANNER_HTML}
                <h1>Hostname changed</h1>
                <div class="card">
                  <p>Your device hostname is now <strong>{html.escape(nh)}.local</strong>.</p>
                  <p>Redirecting you to {safe_url}</p>
                  <p style="word-break:break-word;">
                    <a class="pill-btn" href="{safe_url}">Tap here to continue</a>
                  </p>
                </div>
              </div></body></html>
            """)
            body_bytes = body_html.encode("utf-8")

            try:
                handler.send_response(200)
                handler.send_header("Content-Type", "text/html; charset=utf-8")
                handler.send_header("Content-Length", str(len(body_bytes)))
                handler.end_headers()
                handler.wfile.write(body_bytes)
                try:
                    handler.wfile.flush()
                except Exception:
                    pass
            except Exception:
                pass
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
    except Exception:
        logging.exception("handle_setup_post: unexpected failure during save")
        send_setup_page(handler, state, auth, flash_msg="Save failed", flash_type="error")


# -----------------------------------------------------------------------------
# Live EQ / gain update handlers
# -----------------------------------------------------------------------------

def handle_live_input_eq_update(handler, state: WebUIState, body: str) -> None:
    """Apply live per-input EQ changes to autostream_monitor."""
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
        for field in eq_fields:
            if isinstance(payload.get(field), bool):
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
    """Apply live per-input gain changes to autostream_monitor."""
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
        if isinstance(payload.get("gain_db"), bool):
            raise TypeError("bool")
        gain_db = float(payload.get("gain_db", 0.0))
    except Exception:
        send_json(handler, 400, {"ok": False, "error": "Invalid gain payload"})
        return

    if input_index not in (1, 2):
        send_json(handler, 400, {"ok": False, "error": "input must be 1 or 2"})
        return

    if not math.isfinite(gain_db) or gain_db < -10.0 or gain_db > 10.0:
        send_json(handler, 400, {"ok": False, "error": "Gain must be between -10 and 10 dB"})
        return

    ok = set_live_input_gain(
        input_index=input_index,
        gain_db=gain_db,
    )
    if not ok:
        send_json(handler, 200, {"ok": False, "error": "Could not update live gain"})
        return

    send_json(handler, 200, {
        "ok": True,
        "input": input_index,
        "gain_db": gain_db,
    })


# -----------------------------------------------------------------------------
# Owntone setup POST
# -----------------------------------------------------------------------------

def handle_owntone_setup_post(handler, state: WebUIState, auth, body: str) -> None:
    form = parse_qs(body)
    def fld(n, d=""): return _fld(form, n, d)
    try:
        cfg = locked_load_config(state.config_path)
        state_data = load_state(state.state_path)

        speakers: list[tuple[str, str, bool, str, Optional[int]]] = []
        valid_airplay_modes = {DEFAULT_AIRPLAY_MODE, "raop", "airplay2"}
        i = 0
        while f"spk_{i}" in form:
            speaker_id = fld(f"spk_id_{i}", "").strip()
            name = fld(f"spk_{i}")
            show = (f"show_{i}" in form)
            mode = fld(f"mode_{i}", DEFAULT_AIRPLAY_MODE).strip().lower()
            if mode not in valid_airplay_modes:
                mode = DEFAULT_AIRPLAY_MODE
            offset_ms: Optional[int] = None
            if f"offset_{i}" in form:
                raw_off = fld(f"offset_{i}", "0")
                try:
                    offset_ms = int(str(raw_off).strip())
                except Exception:
                    offset_ms = 0
                offset_ms = max(-2000, min(2000, offset_ms))
            speakers.append((speaker_id, name, show, mode, offset_ms))

            i += 1

        speakers.sort(key=lambda t: t[1].casefold())

        hidden = [
            spk_name
            for (_spk_id, spk_name, show, _mode, _offset) in speakers
            if not show
        ]
        cfg.setdefault("webui", {})["hidden_outputs"] = hidden

        base_url = str((cfg.get("owntone") or {}).get("base_url") or "http://localhost:3689")

        existing_parsed = parse_config(cfg, state_data)
        offsets_by_id = dict(existing_parsed.owntone.output_offsets_ms)
        runtime_airplay_modes_by_id = dict(existing_parsed.owntone.output_airplay_modes)
        known_outputs = dict(existing_parsed.owntone.known_outputs)
        for out_id, spk, _show, mode, offset_ms in speakers:
            out_id = str(out_id or "").strip()
            if out_id and spk.strip():
                known_outputs[out_id] = spk.strip()
            if out_id:
                if offset_ms is not None:
                    offsets_by_id[out_id] = offset_ms
                runtime_airplay_modes_by_id[out_id] = normalize_airplay_mode(mode)

        # offsets and airplay_modes stay in the config file
        cfg.setdefault("owntone", {})["offsets"] = offsets_by_id
        cfg.setdefault("owntone", {})["airplay_modes"] = runtime_airplay_modes_by_id
        # known_outputs moves to the state file
        state_data.setdefault("owntone", {})["known_outputs"] = known_outputs

        restart_required = False
        want_uncompressed_audio = ("uncompressed_alac" in form)
        save_uncompressed_result = save_setting(
            base_url,
            SETTING_UNCOMPRESSED_ALAC,
            want_uncompressed_audio,
            timeout=3,
        )
        if not save_uncompressed_result.ok and not save_uncompressed_result.unsupported:
            raise RuntimeError("Could not update OwnTone uncompressed_alac via API")
        restart_required = restart_required or bool(save_uncompressed_result.restart_required)

        if "start_buffer_ms" in form:
            try:
                want_buffer = int(fld("start_buffer_ms", str(SETTING_START_BUFFER_MS_DEFAULT)).strip())
            except (ValueError, TypeError):
                want_buffer = SETTING_START_BUFFER_MS_DEFAULT
            want_buffer = max(
                SETTING_START_BUFFER_MS_MIN,
                min(
                    SETTING_START_BUFFER_MS_MAX,
                    round(want_buffer / SETTING_START_BUFFER_MS_STEP) * SETTING_START_BUFFER_MS_STEP,
                ),
            )
            save_buffer_result = save_setting(
                base_url,
                SETTING_START_BUFFER_MS,
                want_buffer,
                timeout=3,
            )
            if not save_buffer_result.ok and not save_buffer_result.unsupported:
                raise RuntimeError("Could not update OwnTone start_buffer_ms via API")
            restart_required = restart_required or bool(save_buffer_result.restart_required)

        if "device_removal_grace_period_minutes" in form:
            try:
                want_grace_minutes = int(fld("device_removal_grace_period_minutes", str(SETTING_DEVICE_REMOVAL_GRACE_PERIOD_DEFAULT_MINUTES)).strip())
            except (ValueError, TypeError):
                want_grace_minutes = SETTING_DEVICE_REMOVAL_GRACE_PERIOD_DEFAULT_MINUTES
            want_grace_minutes = max(
                SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MIN_MINUTES,
                min(SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MAX_MINUTES, want_grace_minutes),
            )
            save_grace_result = save_setting(
                base_url,
                SETTING_DEVICE_REMOVAL_GRACE_PERIOD,
                want_grace_minutes * 60,
                timeout=3,
            )
            if not save_grace_result.ok and not save_grace_result.unsupported:
                raise RuntimeError("Could not update OwnTone device_removal_grace_period via API")
            restart_required = restart_required or bool(save_grace_result.restart_required)

        # Write both files under a single lock. Re-load state inside the lock so
        # that a concurrent PIN change made while OwnTone API calls were in flight
        # is not overwritten with the stale snapshot loaded at the start of the handler.
        with CONFIG_IO_LOCK:
            save_config(state.config_path, cfg)
            live_state = load_state(state.state_path)
            live_state.setdefault("owntone", {})["known_outputs"] = known_outputs
            save_state(state.state_path, live_state)

        saved_parsed = parse_config(cfg, live_state)
        owntone_d = cfg.get("owntone") or {}
        update_live_owntone_runtime(
            output_name=str(owntone_d.get("output_name", "") or ""),
            volume_percent=owntone_d.get("volume_percent", 20),
            output_offsets_ms=saved_parsed.owntone.output_offsets_ms,
            output_airplay_modes=saved_parsed.owntone.output_airplay_modes,
        )

        if restart_required:
            start_owntone_restart_async(state)

        _set_flash_cookie(handler, "Settings saved", max_age=30)

        next_path = "/setup"
        loc = (
            "/owntone-restarting?next=" + quote(next_path, safe="/?=&")
            if restart_required
            else next_path
        )

        handler.send_response(303)
        handler.send_header("Location", loc)
        handler.send_header("Content-Length", "0")
        handler.end_headers()
    except Exception:
        logging.exception("handle_owntone_setup_post failed")
        send_owntone_setup_page(
            handler,
            state,
            auth,
            error="Save failed",
        )


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
    """
    try:
        factory_reset_system()
        send_json(handler, 200, {"ok": True})
    except Exception as e:
        logging.error("handle_factory_reset_post: scheduling failed: %s", e)
        send_json(handler, 500, {"ok": False, "error": "Factory reset could not be scheduled", "detail": str(e)})

