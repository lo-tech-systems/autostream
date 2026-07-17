#!/usr/bin/env python3
"""autostream_webui_page_first_boot.py

Copyright (c) 2026 Lo-tech Systems Limited. All rights reserved.

First-boot commissioning pages and workflow endpoints.

Contents:
  - send_first_boot_owntone_page    -- GET /first-boot/owntone
  - send_first_boot_appliance_page  -- GET /first-boot/appliance
  - handle_first_boot_continue_post -- POST /first-boot/owntone/continue
  - handle_first_boot_finish_post   -- POST /first-boot/appliance/finish
"""

from __future__ import annotations

import html
import json
import logging
from typing import Optional

from autostream_config import (
    DEFAULT_AIRPLAY_MODE,
    load_state,
    mark_configured,
    parse_config,
    set_input_mode,
)
from autostream_commissioning import (
    is_technically_complete,
    mark_commissioning_complete,
)
from autostream_player_service import list_outputs, output_supported_config_modes
from autostream_sysutils import get_system_hostname, set_system_hostname
from autostream_webui_api import send_json
from autostream_webui_assets import AUTOSAVE_JS, BANNER_HTML
from autostream_webui_common import (
    _config_snapshot,
    build_page_html,
    build_top_banner_html,
    send_hostname_changed_page,
)
from autostream_webui_state import WebUIState

_DEFAULT_FIFO_PATH = "/tmp/autostream-pipes/autostream.fifo"


# ---------------------------------------------------------------------------
# Shared page scaffolding
# ---------------------------------------------------------------------------

def _first_boot_page(title: str, body_html: str, body_suffix: str = "") -> str:
    lic_html, lic_spacer = build_top_banner_html()
    return build_page_html(
        title,
        body_html,
        lic_html=lic_html,
        lic_spacer=lic_spacer,
        body_suffix=body_suffix,
        show_nav=False,
        active_tab="setup",
    )


def _send_html(handler, content: str, status: int = 200) -> None:
    body = content.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


# ---------------------------------------------------------------------------
# GET /first-boot/owntone
# ---------------------------------------------------------------------------

def send_first_boot_owntone_page(
    handler,
    state: WebUIState,
    auth,
    error: Optional[str] = None,
) -> None:
    """Render the OwnTone first-boot step: discover and select the default output."""
    try:
        snap = _config_snapshot(state)
    except Exception:
        snap = None

    base_url = snap.owntone.base_url if snap else "http://localhost:3689"
    current_output = (snap.owntone.output_name or "") if snap else ""

    outputs_result = list_outputs(base_url, timeout=3)
    outputs = list(outputs_result.outputs) if outputs_result.ok else []

    csrf_token = getattr(handler, "_csrf_token", None) or auth.get_csrf_token(handler.headers) or ""

    output_options = ""
    for output in outputs:
        name = str(output.name or "").strip()
        if not name:
            continue
        sel = " selected" if name == current_output else ""
        output_options += f"<option value='{html.escape(name)}'{sel}>{html.escape(name)}</option>"
    if not output_options:
        output_options = "<option value=''>No outputs detected yet</option>"
    if current_output and not any(
        str(o.name or "").strip() == current_output for o in outputs
    ):
        output_options = (
            f"<option value='{html.escape(current_output)}' selected>"
            f"{html.escape(current_output)} (not currently visible)</option>"
        ) + output_options

    error_html = f"<p class='error'>{html.escape(error)}</p>" if error else ""

    body_html = f"""
{BANNER_HTML}
<h1>Initial Setup (1 of 2)</h1>
<h2 style="font-size:1rem;color:#666;font-weight:normal;margin-top:-0.5rem;">OwnTone Output Selection</h2>
{error_html}
<form method="POST" action="/first-boot/owntone/continue">
  <input type="hidden" name="csrf_token" value="{html.escape(csrf_token)}">
  <fieldset>
    <legend>Default Output</legend>
    <label>
      Output:
      <select name="output_name" id="fb_output_name">
        {output_options}
      </select>
    </label>
    <div style="margin-top:0.75rem;">
      <a href="/first-boot/owntone" class="pill-btn small"
         style="font-weight:500;border:1px solid #ccc;">&#8635; Refresh</a>
    </div>
  </fieldset>
  <p class="actions"><button type="submit">Continue</button></p>
</form>
"""
    _send_html(handler, _first_boot_page("First Boot — OwnTone", body_html))


# ---------------------------------------------------------------------------
# GET /first-boot/appliance
# ---------------------------------------------------------------------------

def send_first_boot_appliance_page(
    handler,
    state: WebUIState,
    auth,
    error: Optional[str] = None,
) -> None:
    """Render the Appliance first-boot step: ALSA device, volume, hostname, Finish."""
    try:
        snap = _config_snapshot(state)
    except Exception:
        snap = None

    monitor_devices = state.get_monitor_devices()
    current_dev1 = (snap.audio1.capture_device or "") if snap else ""
    current_turntable1 = bool(snap.audio1.is_turntable) if snap else False
    current_vol = int(snap.owntone.volume_percent) if snap else 20
    current_hn = get_system_hostname()

    def _build_device_opts(cur: str) -> str:
        opts = ""
        found = False
        for dev in monitor_devices:
            hw = str(dev.get("hw") or "").strip()
            if not hw:
                continue
            label = str(dev.get("label") or hw).strip()
            sel = " selected" if hw == cur else ""
            if sel:
                found = True
            opts += f"<option value='{html.escape(hw)}'{sel}>{html.escape(label)}</option>"
        if not found and cur:
            opts = f"<option value='{html.escape(cur)}' selected>{html.escape(cur)}</option>" + opts
        if not opts:
            opts = "<option value=''>No ALSA devices detected</option>"
        return opts

    csrf_token = getattr(handler, "_csrf_token", None) or auth.get_csrf_token(handler.headers) or ""
    error_html = f"<p class='error'>{html.escape(error)}</p>" if error else ""

    body_html = f"""
{BANNER_HTML}
<h1>Initial Setup (2 of 2)</h1>
<h2 style="font-size:1rem;color:#666;font-weight:normal;margin-top:-0.5rem;">Appliance Configuration</h2>
{error_html}
<form method="POST" action="/first-boot/appliance/finish">
  <input type="hidden" name="csrf_token" value="{html.escape(csrf_token)}">
  <fieldset>
    <legend>Input 1</legend>
    <label>
      Capture device:
      <select name="audio1_capture_device">
        {_build_device_opts(current_dev1)}
      </select>
    </label>
    <div style="display:flex;align-items:center;gap:0.75rem;margin-top:0.75rem;">
      <label class="output-toggle" style="margin:0;">
        <input type="checkbox" name="audio1_turntable" {'checked' if current_turntable1 else ''}>
        <span class="switch"></span>
      </label>
      <span>Turntable (phono pre-amp required)</span>
    </div>
  </fieldset>
  <fieldset>
    <legend>Volume</legend>
    <div class="slider-header">
      <span>Default Volume:</span>
      <span id="fb_vol_val">{current_vol}%</span>
    </div>
    <input type="range" name="volume_percent"
           min="0" max="100" step="1" value="{current_vol}"
           oninput="document.getElementById('fb_vol_val').textContent=this.value+'%';">
  </fieldset>
  <fieldset>
    <legend>Appliance</legend>
    <label>
      Hostname:
      <input type="text" name="hostname" value="{html.escape(current_hn)}"
             style="width:100%;box-sizing:border-box;">
    </label>
  </fieldset>
  <p class="actions"><button type="submit">Finish</button></p>
</form>
"""
    _send_html(handler, _first_boot_page("First Boot — Appliance", body_html))


# ---------------------------------------------------------------------------
# POST /first-boot/owntone/continue
# ---------------------------------------------------------------------------

def handle_first_boot_continue_post(handler, state: WebUIState, auth, body: str) -> None:
    """Validate OwnTone output selection and advance to the Appliance step."""
    from urllib.parse import parse_qs
    form = parse_qs(body or "", keep_blank_values=True)

    def fld(name: str, default: str = "") -> str:
        vals = form.get(name) or []
        return str(vals[0]).strip() if vals else default

    output_name = fld("output_name", "").strip()
    if not output_name:
        send_first_boot_owntone_page(handler, state, auth, error="Please select an output.")
        return

    from autostream_settings import SettingsStore as _SettingsStore
    _store = getattr(state, "settings", None)
    if not isinstance(_store, _SettingsStore):
        send_first_boot_owntone_page(
            handler, state, auth, error="Settings store unavailable."
        )
        return

    try:
        _store.update(lambda raw: raw.setdefault("owntone", {}).update({"output_name": output_name}))
    except Exception as exc:
        logging.exception("handle_first_boot_continue_post: store update failed")
        send_first_boot_owntone_page(
            handler, state, auth, error=f"Could not save output selection: {exc}"
        )
        return

    handler.send_response(303)
    handler.send_header("Location", "/first-boot/appliance")
    handler.send_header("Content-Length", "0")
    handler.end_headers()


# ---------------------------------------------------------------------------
# POST /first-boot/appliance/finish
# ---------------------------------------------------------------------------

_VALID_AIRPLAY_MODES = {DEFAULT_AIRPLAY_MODE, "raop", "airplay2"}


def handle_first_boot_finish_post(handler, state: WebUIState, auth, body: str) -> None:
    """Validate Appliance settings, save, mark configured, redirect to /."""
    from urllib.parse import parse_qs
    from autostream_config import is_valid_monitor_device_id, mark_configured as _mark_configured

    form = parse_qs(body or "", keep_blank_values=True)

    def fld(name: str, default: str = "") -> str:
        vals = form.get(name) or []
        return str(vals[0]).strip() if vals else default

    from autostream_settings import SettingsStore as _SettingsStore
    _store = getattr(state, "settings", None)
    if not isinstance(_store, _SettingsStore):
        send_first_boot_appliance_page(
            handler, state, auth, error="Settings store unavailable."
        )
        return

    # Validate required fields
    audio1_dev = fld("audio1_capture_device", "").strip()
    if not is_valid_monitor_device_id(audio1_dev):
        send_first_boot_appliance_page(
            handler, state, auth,
            error=f"Invalid ALSA device {audio1_dev!r}. Please select a valid hw:* device."
        )
        return

    audio1_turntable = "audio1_turntable" in form
    try:
        volume_percent = max(0, min(100, int(fld("volume_percent", "20"))))
    except (ValueError, TypeError):
        volume_percent = 20

    hostname_raw = fld("hostname", "").strip()
    old_hn = get_system_hostname()
    hostname_changed = bool(hostname_raw and hostname_raw != old_hn)

    # Commit all values to store (including FIFO default if not already set)
    try:
        def _mutator(raw: dict) -> None:
            raw.setdefault("audio1", {})["capture_device"] = audio1_dev
            set_input_mode(raw, 1, audio1_turntable)
            raw.setdefault("owntone", {})["volume_percent"] = volume_percent
            # Ensure FIFO path has a default
            if not str(raw.setdefault("general", {}).get("fifo_path", "") or "").strip():
                raw["general"]["fifo_path"] = _DEFAULT_FIFO_PATH
        _store.update(_mutator)
    except Exception as exc:
        logging.exception("handle_first_boot_finish_post: store update failed")
        send_first_boot_appliance_page(
            handler, state, auth, error=f"Could not save settings: {exc}"
        )
        return

    # Validate output_name was set in the previous step
    snap = _store.snapshot()
    if not str(snap.owntone.output_name or "").strip():
        send_first_boot_appliance_page(
            handler, state, auth, error="No OwnTone output selected. Please go back and select one."
        )
        return

    # Apply hostname change if requested
    if hostname_changed:
        try:
            set_system_hostname(hostname_raw)
        except Exception as exc:
            logging.warning("handle_first_boot_finish_post: hostname change failed: %s", exc)
            send_first_boot_appliance_page(
                handler, state, auth, error=f"Could not change hostname: {exc}"
            )
            return

    # Synchronous save — must succeed before marking configured
    if not _store.save_now():
        logging.error("handle_first_boot_finish_post: save_now failed or timed out")
        send_first_boot_appliance_page(
            handler, state, auth, error="Settings could not be saved. Please try again."
        )
        return

    # Verify on-disk config now passes technical completeness
    if not is_technically_complete(state.config_path):
        send_first_boot_appliance_page(
            handler, state, auth,
            error="Configuration is still incomplete after save. Please check all required fields."
        )
        return

    # Mark commissioning complete (race-safe)
    try:
        mark_commissioning_complete(state.state_path)
    except Exception as exc:
        logging.exception("handle_first_boot_finish_post: mark_commissioning_complete failed")
        send_first_boot_appliance_page(
            handler, state, auth, error=f"Could not update commissioning state: {exc}"
        )
        return

    # Update the in-process unconfigured cache
    _mark_configured(state.config_path)

    if hostname_changed:
        send_hostname_changed_page(handler, hostname_raw, path="/", show_nav=False)
        return

    # Redirect to home
    handler.send_response(303)
    handler.send_header("Location", "/")
    handler.send_header("Content-Length", "0")
    handler.end_headers()
