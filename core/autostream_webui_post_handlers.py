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
"""

from __future__ import annotations

import html
import json
import logging
import textwrap

import requests

from typing import Optional
from urllib.parse import parse_qs, quote

from autostream_config import (
    DEFAULT_AIRPLAY_MODE,
    DEFAULT_OWNTONE_PROTOCOL_API_STATE,
    mark_configured,
    normalize_airplay_mode,
    parse_config,
    unconfigured,
)
from autostream_core import (
    reset_input_stylus,
    set_live_input_eq,
    set_live_input_gain,
    update_live_owntone_runtime,
    update_playback_input_config,
)
from autostream_owntone import (
    _coerce_owntone_bool,
    _coerce_owntone_int,
    build_owntone_output_update_payload,
    owntone_fetch_outputs,
    owntone_get_output,
    owntone_get_setting,
    owntone_output_protocol_support,
    owntone_put_setting,
    read_airplay2_for_speaker,
    read_and_set_global_uncompressed_audio,
    resolve_owntone_output_airplay_mode,
    resolve_owntone_protocol_api_state,
    write_airplay2_for_speaker,
    write_and_set_global_uncompressed_audio,
    OWNTONE_CONF_PATH,
)
from autostream_playback import normalize_stylus_life_hours, suggested_silence_threshold_dbfs
from autostream_sysutils import get_system_hostname, set_system_hostname
from autostream_webui_assets import BANNER_HTML, STYLE_CSS, VIEWPORT_META
from autostream_webui_common import (
    CONFIG_IO_LOCK,
    _set_flash_cookie,
    build_top_banner_html,
    locked_load_config,
)
from autostream_webui_state import WebUIState
from autostream_webui_api import send_json
from autostream_webui_page_setup import send_setup_page
from autostream_webui_page_owntone import send_owntone_setup_page, start_owntone_restart_async


# -----------------------------------------------------------------------------
# Output toggle / volume handler
# -----------------------------------------------------------------------------

def handle_output_update(handler, state: WebUIState, body: str) -> None:
    try:
        payload = json.loads(body)
        out_id = payload.get("id")
        op = (payload.get("op") or "").strip().lower()
        selected = bool(payload.get("selected", False))
        volume = max(0, min(100, int(payload.get("volume", 50))))

        # PIN may arrive as string or number depending on client implementation.
        pin_raw = payload.get("pin") if isinstance(payload, dict) else None
        pin = (str(pin_raw).strip() if pin_raw is not None else "")

        cfg = locked_load_config(state.config_path)
        parsed = parse_config(cfg)
        base_url = parsed.owntone.base_url.rstrip("/")
        url = base_url + f"/api/outputs/{out_id}"

        # Two modes:
        #   (1) Normal output update: selected/volume plus autostream-managed
        #       runtime settings like offset/protocol (never send pin here)
        #   (2) PIN verification: pin ONLY (no selected/volume)
        if op == "pin":
            if not pin:
                send_json(handler, 200, {"ok": False, "error": "Missing PIN", "id": str(out_id)})
                return
            out_payload = {"pin": pin}

            logging.info("Owntone API call: PUT %s json={\"pin\":\"***\"}", url)
            resp = requests.put(url, json=out_payload, timeout=3)
            logging.info("Owntone API response: status=%s body=%s",
                         getattr(resp, "status_code", None),
                         (getattr(resp, "text", "") or "").strip())

            # Mode (2): PIN-only verification.
            # OwnTone returns 400 if the PIN was wrong/failed; client should re-prompt.
            if resp.status_code == 400:
                send_json(handler, 200, {
                    "ok": False,
                    "id": str(out_id),
                    "pin_invalid": True,
                    "status": int(resp.status_code),
                    "error": (resp.text or "").strip(),
                })
                return
            if not resp.ok:
                send_json(handler, 200, {
                    "ok": False,
                    "id": str(out_id),
                    "status": int(resp.status_code),
                    "error": (resp.text or "").strip(),
                })
                return
            send_json(handler, 200, {"ok": True, "id": str(out_id)})
            return

        if selected:
            outputs = owntone_fetch_outputs(base_url, timeout=3)
            out_obj = owntone_get_output(
                base_url,
                out_id,
                outputs=outputs,
                timeout=3,
            )
            mode = resolve_owntone_output_airplay_mode(
                out_id,
                output_airplay_modes=parsed.owntone.output_airplay_modes,
            )
            payload_result = build_owntone_output_update_payload(
                out_obj,
                selected=True,
                volume=volume,
                offset_ms=parsed.owntone.output_offsets_ms.get(str(out_id)),
                protocol_mode=mode,
            )
            out_payload = payload_result.payload
            if payload_result.protocol_coerced:
                logging.warning(
                    "OwnTone output %s does not support the configured runtime protocol; coercing to default.",
                    out_id,
                )
            if payload_result.protocol_requested and not payload_result.protocol_included:
                if payload_result.output_known:
                    logging.info(
                        "Skipping runtime protocol for OwnTone output %s because this build does not advertise protocol capability.",
                        out_id,
                    )
                else:
                    logging.warning(
                        "Skipping runtime protocol for OwnTone output %s because output metadata was unavailable.",
                        out_id,
                    )
            logging.info("Owntone API call: PUT %s json=%s", url, out_payload)
            resp = requests.put(url, json=out_payload, timeout=3)
            logging.info("Owntone API response: status=%s body=%s",
                         getattr(resp, "status_code", None),
                         (getattr(resp, "text", "") or "").strip())

            # OwnTone returns HTTP 400 when an output enable requires device PIN verification.
            if resp.status_code == 400:
                send_json(handler, 200, {
                    "ok": False,
                    "pin_required": True,
                    "id": str(out_id),
                    "output_name": str(payload.get("name") or ""),
                    "status": int(resp.status_code),
                    "error": (resp.text or "").strip(),
                })
                return

            if not resp.ok:
                send_json(handler, 200, {
                    "ok": False,
                    "id": str(out_id),
                    "status": int(resp.status_code),
                    "error": (resp.text or "").strip(),
                    "pin_invalid": False,
                })
                return

            send_json(handler, 200, {"ok": True, "id": str(out_id)})
            return

        # Disable path: preserve all other currently-selected outputs by using /api/outputs/set.
        outputs_url = base_url + "/api/outputs"
        set_url = base_url + "/api/outputs/set"
        list_resp = requests.get(outputs_url, timeout=3)
        if not list_resp.ok:
            send_json(handler, 200, {
                "ok": False,
                "id": str(out_id),
                "status": int(list_resp.status_code),
                "error": (list_resp.text or "").strip(),
            })
            return

        outputs = (list_resp.json() or {}).get("outputs", [])
        remaining = [str(o.get("id")) for o in outputs if o.get("selected") and str(o.get("id")) != str(out_id)]

        set_payload = {"outputs": remaining}
        logging.info("Owntone API call: PUT %s json=%s", set_url, set_payload)
        resp = requests.put(set_url, json=set_payload, timeout=3)
        logging.info("Owntone API response: status=%s body=%s",
                     getattr(resp, "status_code", None),
                     (getattr(resp, "text", "") or "").strip())
        if not resp.ok:
            send_json(handler, 200, {
                "ok": False,
                "id": str(out_id),
                "status": int(resp.status_code),
                "error": (resp.text or "").strip(),
                "pin_invalid": False,
            })
            return

        send_json(handler, 200, {"ok": True, "id": str(out_id)})
    except Exception as e:
        logging.error("Update failed: %s", e)
        send_json(handler, 200, {"ok": False, "error": str(e)})


# -----------------------------------------------------------------------------
# Setup form POST
# -----------------------------------------------------------------------------

def handle_setup_post(handler, state: WebUIState, auth, body: str) -> None:
    form = parse_qs(body)
    def fld(n, d=""): return (form.get(n, []) or [d])[0]
    try:
        cfg = locked_load_config(state.config_path)
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
        new_audio1_stylus_life = normalize_stylus_life_hours(
            fld("audio_stylus_life_hours", str(p.audio1.stylus_life_hours))
        )
        new_audio2_stylus_life = normalize_stylus_life_hours(
            fld("audio2_stylus_life_hours", str(p.audio2.stylus_life_hours))
        )
        reset_stylus_input_raw = fld("stylus_reset_input", "").strip()

        # Hostname
        old_hn = get_system_hostname()
        nh = fld("system_hostname").strip()
        hostname_changed = bool(nh and nh != old_hn)
        if hostname_changed:
            set_system_hostname(nh)

        # Config updates
        if not cfg.has_section("audio1"): cfg.add_section("audio1")
        cfg.set("audio1", "capture_device", fld("audio_capture_device", p.audio1.capture_device))
        cfg.set("audio1", "silence_threshold", str(new_audio1_threshold))
        cfg.set("audio1", "turntable", "yes" if new_audio1_turntable else "no")
        cfg.set("audio1", "stylus_life_hours", str(new_audio1_stylus_life))
        cfg.set("audio1", "gain_db", fld("audio1_gain_db", str(p.audio1.gain_db)))
        cfg.set("audio1", "eq_40hz_db", fld("audio1_eq_40hz_db", str(p.audio1.eq_40hz_db)))
        cfg.set("audio1", "eq_100hz_db", fld("audio1_eq_100hz_db", str(p.audio1.eq_100hz_db)))
        cfg.set("audio1", "eq_10khz_db", fld("audio1_eq_10khz_db", str(p.audio1.eq_10khz_db)))

        if not cfg.has_section("audio2"): cfg.add_section("audio2")
        cfg.set("audio2", "enabled", "yes" if new_audio2_enabled else "no")
        cfg.set("audio2", "capture_device", fld("audio2_capture_device", p.audio2.capture_device))
        cfg.set("audio2", "silence_threshold", str(new_audio2_threshold))
        cfg.set("audio2", "turntable", "yes" if new_audio2_turntable else "no")
        cfg.set("audio2", "stylus_life_hours", str(new_audio2_stylus_life))
        cfg.set("audio2", "gain_db", fld("audio2_gain_db", str(p.audio2.gain_db)))
        cfg.set("audio2", "eq_40hz_db", fld("audio2_eq_40hz_db", str(p.audio2.eq_40hz_db)))
        cfg.set("audio2", "eq_100hz_db", fld("audio2_eq_100hz_db", str(p.audio2.eq_100hz_db)))
        cfg.set("audio2", "eq_10khz_db", fld("audio2_eq_10khz_db", str(p.audio2.eq_10khz_db)))

        if not cfg.has_section("owntone"): cfg.add_section("owntone")
        cfg.set("owntone", "output_name", fld("owntone_output_name", p.owntone.output_name))
        cfg.set("owntone", "volume_percent", fld("owntone_volume_percent", str(p.owntone.volume_percent)))

        if not cfg.has_section("general"): cfg.add_section("general")
        cfg.set("general", "silence_seconds", fld("silence_seconds", str(p.general.silence_seconds)))

        # Persist defaults into the INI the first time it is created (or if missing)
        if not cfg.get("general", "log_file", fallback="").strip():
            cfg.set("general", "log_file", p.general.log_file)

        if not cfg.get("general", "fifo_path", fallback="").strip():
            cfg.set("general", "fifo_path", p.general.fifo_path)

        # Atomicity across concurrent requests/tabs:
        with CONFIG_IO_LOCK:
            with open(state.config_path, "w", encoding="utf-8") as f:
                cfg.write(f)
            mark_configured(state.config_path)

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
            stylus_life_hours=new_audio1_stylus_life,
        )
        update_playback_input_config(
            2,
            enabled=new_audio2_enabled,
            is_turntable=new_audio2_turntable,
            stylus_life_hours=new_audio2_stylus_life,
        )

        reset_stylus_result = None
        reset_stylus_input: Optional[int] = None
        if reset_stylus_input_raw:
            try:
                reset_stylus_input = int(reset_stylus_input_raw)
            except ValueError:
                reset_stylus_input = None
            if reset_stylus_input in (1, 2):
                reset_stylus_result = reset_input_stylus(reset_stylus_input)

        from autostream_webui_page_setup import _stylus_reset_flash_text
        flash_text = "Settings saved"
        if reset_stylus_input is not None and reset_stylus_result is not None:
            flash_text = _stylus_reset_flash_text(
                reset_stylus_input,
                reset_stylus_result,
                settings_saved=True,
            )

        # One-shot success banner (cookie-based) to avoid sticky URLs in iOS A2HS/PWA.
        _set_flash_cookie(handler, flash_text, max_age=30)

        # Redirect back to / on save
        next_path = "/"

        if hostname_changed:
            host_header = handler.headers.get("Host", "")
            port = host_header.rsplit(":", 1)[1] if ":" in host_header else None
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
            from autostream_core import update_live_silence_seconds
            if not update_live_silence_seconds(new_silence_seconds):
                daemon_changed = True

        if daemon_changed:
            from autostream_core import request_config_reload
            request_config_reload()
    except Exception as e:
        send_setup_page(handler, state, auth, flash_msg="Save failed", flash_type="error")


# -----------------------------------------------------------------------------
# Live EQ / gain update handlers
# -----------------------------------------------------------------------------

def handle_live_input_eq_update(handler, state: WebUIState, body: str) -> None:
    """Apply live per-input EQ changes to autostream_monitor."""
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    try:
        input_index = int(payload.get("input", 0))
        eq_40hz_db = float(payload.get("eq_40hz_db", 0.0))
        eq_100hz_db = float(payload.get("eq_100hz_db", 0.0))
        eq_10khz_db = float(payload.get("eq_10khz_db", 0.0))
    except Exception:
        send_json(handler, 400, {"ok": False, "error": "Invalid EQ payload"})
        return

    if input_index not in (1, 2):
        send_json(handler, 400, {"ok": False, "error": "input must be 1 or 2"})
        return

    for val in (eq_40hz_db, eq_100hz_db, eq_10khz_db):
        if val < -10.0 or val > 10.0:
            send_json(handler, 400, {"ok": False, "error": "EQ gain must be between -10 and 10 dB"})
            return

    ok = set_live_input_eq(
        input_index=input_index,
        eq_40hz_db=eq_40hz_db,
        eq_100hz_db=eq_100hz_db,
        eq_10khz_db=eq_10khz_db,
    )
    if not ok:
        send_json(handler, 200, {"ok": False, "error": "Could not update live EQ"})
        return

    send_json(handler, 200, {
        "ok": True,
        "input": input_index,
        "eq_40hz_db": eq_40hz_db,
        "eq_100hz_db": eq_100hz_db,
        "eq_10khz_db": eq_10khz_db,
    })


def handle_live_input_gain_update(handler, state: WebUIState, body: str) -> None:
    """Apply live per-input gain changes to autostream_monitor."""
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    try:
        input_index = int(payload.get("input", 0))
        gain_db = float(payload.get("gain_db", 0.0))
    except Exception:
        send_json(handler, 400, {"ok": False, "error": "Invalid gain payload"})
        return

    if input_index not in (1, 2):
        send_json(handler, 400, {"ok": False, "error": "input must be 1 or 2"})
        return

    if gain_db < -10.0 or gain_db > 10.0:
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

    def fld(n, d=""):
        return (form.get(n, []) or [d])[0]

    try:
        cfg = locked_load_config(state.config_path)

        # Tuple: (stable_output_id, display_name, show, mode, offset_ms_or_none)
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
        if not cfg.has_section("webui"):
            cfg.add_section("webui")
        if hidden:
            cfg.set("webui", "hidden_outputs", "\n    " + "\n    ".join(hidden))
        else:
            cfg.set("webui", "hidden_outputs", "")

        base_url = cfg.get("owntone", "base_url", fallback="http://localhost:3689")
        current_outputs = owntone_fetch_outputs(base_url, timeout=3)
        current_outputs_list = current_outputs or []
        outputs_by_id = {
            str(o.get("id")).strip(): o
            for o in current_outputs_list
            if o.get("id") is not None
        }
        persisted_protocol_api_state = cfg.get(
            "owntone",
            "protocol_api_state",
            fallback=DEFAULT_OWNTONE_PROTOCOL_API_STATE,
        )
        protocol_api_state = resolve_owntone_protocol_api_state(
            current_outputs,
            persisted_protocol_api_state,
        )
        if current_outputs is None:
            logging.warning(
                "OwnTone setup save: output metadata was unavailable; reusing last-known protocol compatibility state %r.",
                protocol_api_state,
            )
        elif not current_outputs_list:
            logging.info(
                "OwnTone setup save: no outputs are currently discovered; reusing last-known protocol compatibility state %r.",
                protocol_api_state,
            )

        existing_parsed = parse_config(cfg)
        # Preserve entries for currently undiscovered outputs so a temporary
        # disappearance does not erase the user's saved id-based preference.
        offsets_by_id = dict(existing_parsed.owntone.output_offsets_ms)
        runtime_airplay_modes_by_id = dict(existing_parsed.owntone.output_airplay_modes)
        existing_runtime_mode_ids = set(runtime_airplay_modes_by_id.keys())
        known_outputs = dict(existing_parsed.owntone.known_outputs)
        conf_airplay_writes: list[tuple[str, bool]] = []
        if protocol_api_state == "legacy":
            runtime_airplay_modes_by_id = {}
        for out_id, spk, _show, mode, offset_ms in speakers:
            out_id = str(out_id or "").strip()
            out_obj = outputs_by_id.get(out_id) if out_id else None
            if out_id and spk.strip():
                known_outputs[out_id] = spk.strip()
            if out_id:
                if offset_ms is not None:
                    offsets_by_id[out_id] = offset_ms

            normalized_mode = normalize_airplay_mode(mode)
            if protocol_api_state == "runtime":
                if not out_id:
                    logging.warning(
                        "OwnTone speaker %r has no stable output id yet; cannot save runtime protocol preference.",
                        spk,
                    )
                    continue
                protocol_support = owntone_output_protocol_support(out_obj)
                if protocol_support.supports_runtime_protocol:
                    if normalized_mode == "raop" and not protocol_support.supports_raop:
                        logging.warning(
                            "OwnTone speaker %r does not support AirPlay 1; coercing mode to default.",
                            spk,
                        )
                        normalized_mode = DEFAULT_AIRPLAY_MODE
                    elif normalized_mode == "airplay2" and not protocol_support.supports_airplay2:
                        logging.warning(
                            "OwnTone speaker %r does not support AirPlay 2; coercing mode to default.",
                            spk,
                        )
                        normalized_mode = DEFAULT_AIRPLAY_MODE
                    logging.info(
                        "OwnTone speaker %r will use runtime protocol preference %r on output id %s.",
                        spk,
                        normalized_mode,
                        out_id,
                    )
                elif out_obj is None:
                    if out_id not in existing_runtime_mode_ids:
                        logging.warning(
                            "OwnTone speaker %r is not currently discovered and has no previously confirmed runtime AirPlay mode; leaving its mode unchanged.",
                            spk,
                        )
                        continue
                    logging.info(
                        "OwnTone speaker %r is not currently discovered; saving runtime protocol preference %r on output id %s for later.",
                        spk,
                        normalized_mode,
                        out_id,
                        )
                else:
                    if out_id not in existing_runtime_mode_ids:
                        logging.warning(
                            "OwnTone speaker %r did not provide protocol capability metadata and has no previously confirmed runtime AirPlay mode; leaving its mode unchanged.",
                            spk,
                        )
                        continue
                    logging.warning(
                        "OwnTone speaker %r did not provide protocol capability metadata during this save; keeping runtime preference %r on output id %s pending.",
                        spk,
                        normalized_mode,
                        out_id,
                    )
                runtime_airplay_modes_by_id[out_id] = normalized_mode
                continue

            if protocol_api_state == "legacy":
                if not spk.strip():
                    logging.warning(
                        "OwnTone speaker %r has no usable display name; cannot apply legacy owntone.conf mode handling.",
                        out_id,
                    )
                    continue
                if out_id:
                    runtime_airplay_modes_by_id.pop(out_id, None)
                conf_airplay_writes.append((spk, normalized_mode == "airplay2"))
                logging.info(
                    "OwnTone speaker %r will use legacy owntone.conf AirPlay mode handling.",
                    spk,
                )
                continue

            if not out_id:
                logging.warning(
                    "OwnTone speaker %r has no stable output id and compatibility is still unknown; mode change will be ignored for now.",
                    spk,
                )
                continue
            if out_id not in existing_runtime_mode_ids:
                logging.warning(
                    "OwnTone speaker %r compatibility is still unknown and it has no previously confirmed runtime AirPlay mode; leaving its mode unchanged.",
                    spk,
                )
                continue
            runtime_airplay_modes_by_id[out_id] = normalized_mode
            logging.warning(
                "OwnTone speaker %r compatibility could not be confirmed; saving pending runtime protocol preference %r on output id %s only.",
                spk,
                normalized_mode,
                out_id,
            )

        if cfg.has_section("owntone_offsets"):
            cfg.remove_section("owntone_offsets")
        cfg.add_section("owntone_offsets")
        for oid, off in sorted(offsets_by_id.items(), key=lambda kv: kv[0]):
            try:
                cfg.set("owntone_offsets", str(oid), str(int(off)))
            except Exception:
                cfg.set("owntone_offsets", str(oid), "0")

        if cfg.has_section("owntone_airplay_modes"):
            cfg.remove_section("owntone_airplay_modes")
        cfg.add_section("owntone_airplay_modes")
        for oid, mode in sorted(runtime_airplay_modes_by_id.items(), key=lambda kv: kv[0]):
            cfg.set("owntone_airplay_modes", str(oid), mode)

        if cfg.has_section("owntone_airplay_modes_by_name"):
            cfg.remove_section("owntone_airplay_modes_by_name")

        if cfg.has_section("owntone_known_outputs"):
            cfg.remove_section("owntone_known_outputs")
        cfg.add_section("owntone_known_outputs")
        for oid, name in sorted(known_outputs.items(), key=lambda kv: kv[0]):
            cfg.set("owntone_known_outputs", str(oid), str(name))

        if not cfg.has_section("owntone"):
            cfg.add_section("owntone")
        cfg.set("owntone", "protocol_api_state", protocol_api_state)

        want_uncompressed_audio = ("uncompressed_alac" in form)
        api_set_uncompressed = owntone_put_setting(
            base_url, "airplay", "uncompressed_alac", want_uncompressed_audio
        )
        if api_set_uncompressed.available and not api_set_uncompressed.ok:
            raise RuntimeError("Could not update OwnTone uncompressed_alac via API")

        restart_required = False

        _START_BUFFER_MIN = 300
        _START_BUFFER_MAX = 3500
        _START_BUFFER_STEP = 50
        if "start_buffer_ms" in form:
            try:
                want_buffer = int(fld("start_buffer_ms", "2250").strip())
            except (ValueError, TypeError):
                want_buffer = 2250
            want_buffer = max(
                _START_BUFFER_MIN,
                min(
                    _START_BUFFER_MAX,
                    round(want_buffer / _START_BUFFER_STEP) * _START_BUFFER_STEP,
                ),
            )
            cur_buf_res = owntone_get_setting(base_url, "general", "start_buffer_ms")
            cur_buf = (
                _coerce_owntone_int(cur_buf_res.value)
                if (cur_buf_res.available and cur_buf_res.ok)
                else None
            )
            if cur_buf is None or want_buffer != cur_buf:
                api_set_buffer = owntone_put_setting(
                    base_url, "general", "start_buffer_ms", want_buffer
                )
                if api_set_buffer.available and not api_set_buffer.ok:
                    raise RuntimeError("Could not update OwnTone start_buffer_ms via API")
                if api_set_buffer.ok:
                    restart_required = True

        with CONFIG_IO_LOCK:
            with open(state.config_path, "w", encoding="utf-8") as f:
                cfg.write(f)

            for spk, ap2 in conf_airplay_writes:
                current_ap2 = read_airplay2_for_speaker(spk, OWNTONE_CONF_PATH)
                if current_ap2 is None or bool(current_ap2) != bool(ap2):
                    if not write_airplay2_for_speaker(spk, ap2, OWNTONE_CONF_PATH):
                        raise RuntimeError(
                            f"Could not update AirPlay mode for speaker {spk!r}"
                        )
                    restart_required = True

            if not api_set_uncompressed.available:
                current_uncompressed = bool(
                    read_and_set_global_uncompressed_audio(OWNTONE_CONF_PATH)
                )
                if current_uncompressed != bool(want_uncompressed_audio):
                    if not write_and_set_global_uncompressed_audio(
                        enabled=want_uncompressed_audio,
                        conf_path=OWNTONE_CONF_PATH,
                    ):
                        raise RuntimeError("Could not update OwnTone uncompressed_alac setting")
                    restart_required = True

        saved_parsed = parse_config(cfg)
        update_live_owntone_runtime(
            output_name=cfg.get("owntone", "output_name", fallback=""),
            volume_percent=cfg.get("owntone", "volume_percent", fallback="20"),
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
        send_owntone_setup_page(
            handler,
            state,
            auth,
            error="Save failed",
        )
