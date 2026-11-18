#!/usr/bin/env python3
"""autostream_webui_page_airplay.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Renderer for the main AirPlay control page (/).
"""

from __future__ import annotations

import html
import logging

from typing import Optional

from autostream_appliance_models import _dial_update_banner_text, build_output_list
from autostream_appliances import get_all_appliances
from autostream_state import active_track, format_khz, store
from autostream_state.live import get_setting
from autostream_players import SETTING_START_BUFFER_MS, SETTING_START_BUFFER_MS_DEFAULT
from autostream_config import input_type_label, normalize_input_type
import autostream_rpi as rpi
from autostream_sysutils import get_system_hostname, reboot_system
from webui.components import output_card_html, slider_html
from webui import static
from webui.assets import (
    A2HS_PROMPT_HTML,
    BANNER_LOGO_HTML,
    ICON_BLUETOOTH,
    ICON_CD,
    ICON_LINE_LEVEL,
    ICON_TURNTABLE,
    INFO_MODAL_HTML,
)
from webui.common import (
    build_appliance_selector_html,
    build_page_html,
    build_top_banner_html,
    no_input_configured_notice_html,
)
from webui.session_state import WebUIState
from webui import common


# Wall-clock tolerance, in seconds, for transient emptiness of the backend's
# reported outputs list (for example while a stereo pair is reforming, the
# device list can briefly shrink to zero before settling back). Both the
# local page poll and the remote/proxy home-state poll debounce an observed
# empty-outputs state against this tolerance before clearing the displayed
# output cards and showing the "no outputs" placeholder. Not exposed via any
# UI or settings surface.
OUTPUTS_EMPTY_TOLERANCE_SECONDS = 6.0


# Stylesheets both Home renderers link: the shared modal and selector styles and
# the Home page's own rules.
_HOME_PAGE_STYLE_FILES = ("page/modal.css", "page/appliance_selector.css", "page/home.css")


def _build_appliances_for_selector() -> list:
    """Return the bound-first appliance list suitable for the selector widget.

    Format matches the /api/appliances JSON response so the same JS update
    function works for both server-rendered initial state and polled updates.
    """
    local_id = rpi.get_appliance_id() or ""
    hostname = str(get_system_hostname() or "").strip()
    if hostname.lower().endswith(".local"):
        hostname = hostname[:-6]
    bound = {
        "id": local_id,
        "hostname": hostname.strip() or "autostream",
        "is_bound": True,
        "home_path": "/",
        "equaliser_path": "/equaliser",
    }
    peers = get_all_appliances()
    result = [bound]
    for s in peers:
        if s.id == local_id:
            continue
        result.append({
            "id": s.id,
            "hostname": s.hostname or "autostream",
            "is_bound": False,
            "home_path": f"/a/{s.id}/",
            "equaliser_path": f"/a/{s.id}/equaliser",
        })
    return result


def send_airplay_page(
    handler,
    state: WebUIState,
    auth,
    error: Optional[str] = None,
    flash_msg: Optional[str] = None,
    flash_type: str = "success",
) -> None:
    """Render the main AirPlay control page."""
    def _display_hostname_label() -> str:
        hostname = str(get_system_hostname() or "").strip()
        if hostname.lower().endswith(".local"):
            hostname = hostname[:-6]
        return hostname.strip() or "autostream"

    try:
        parsed = common._config_snapshot(state)
    except Exception:
        # If we're here something bad happened - user should have been redirected to the setup page
        # if the INI is missing. Hence, take the nuclear option and inform the user that something
        # went wrong - then reboot the system. This code serves only inline code in case the file
        # system is dead (which is likely). Reboot may therefore also fail.
        #
        # This page deliberately does not go through build_page_html()/the shared
        # extra_css channel: it must still render something
        # readable if the filesystem itself is failing, so it cannot depend on the
        # shared theme.css asset or any other autostream module state.
        body = (
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>System Error</title>"
            "<style>body{font-family:system-ui,sans-serif;margin:2rem;}</style>"
            "</head><body>"
            "<h1>System Error</h1>"
            "<p>Unfortunately, an unrecoverable error has occurred: "
            "autostream was unable to read the configuration file.</p>"
            "<p><strong>autostream will now try to reboot.</strong></p>"
            "<p>Please check back in a few minutes. If the system does not recover, "
            "please power-cycle autostream and try again. If the problem persists, "
            "please replace the SD card and reinstall autostream.</p>"
            "</body></html>"
        )

        # Best-effort response; never prevent reboot.
        try:
            common.send_html(handler, 500, body)
            try:
                handler.wfile.flush()
            except Exception:
                pass
        except Exception:
            pass

        # Best-effort log; never prevent reboot.
        try:
            logging.error(
                "Config load error, rebooting system",
                exc_info=True
            )
        except Exception:
            pass
        reboot_system(reason="UserRequestSystemError")
        return

    owntone_base_url = parsed.owntone.base_url
    default_output_name = parsed.owntone.output_name
    hidden_output_names = {str(n).strip().casefold() for n in (parsed.webui.hidden_outputs or ()) if str(n).strip()}
    show_master_volume = parsed.webui.show_master_volume
    show_input_detail = parsed.webui.show_input_detail
    show_hostname_on_home = parsed.webui.show_hostname_on_home
    control_other_appliances = parsed.webui.control_other_appliances
    effective_control = show_hostname_on_home and control_other_appliances

    snap = store().snapshot()
    input_levels = snap.inputs.levels()

    playback_snapshot = snap.playback
    stylus_banner_text = playback_snapshot.stylus_banner_text or ""
    belt_banner_text = playback_snapshot.belt_banner_text or ""
    bearing_banner_text = playback_snapshot.bearing_banner_text or ""
    dial_update_banner_text = _dial_update_banner_text()
    sample_rate_banner_text = snap.inputs.sample_rate_warning_text
    sample_rate_input_index = snap.inputs.sample_rate_mismatch_input or 1
    hostname_label = _display_hostname_label()

    # Determine the active input for the initial Now Playing card render.
    _np_active_idx = 0
    _np_active_level: dict = {}
    for _i, _lv in enumerate(input_levels):
        if _lv.get("is_above_threshold"):
            _np_active_idx = _i
            _np_active_level = _lv
            break
    else:
        if input_levels:
            _np_active_level = input_levels[0]

    _np_is_playing = any(lv.get("is_above_threshold") for lv in input_levels)
    # The level's own input number picks the snapshot; a level with none
    # (older appliance) falls back to its list position.
    _np_level_index = _np_active_level.get("index")
    _np_input_num = (
        _np_level_index
        if isinstance(_np_level_index, int) and not isinstance(_np_level_index, bool)
        else _np_active_idx + 1
    )
    _np_snap = playback_snapshot.inputs.get(_np_input_num)
    _np_is_turntable = bool(_np_snap.is_turntable) if _np_snap else False
    _np_is_bluetooth = bool(_np_snap.is_bluetooth) if _np_snap else False
    _np_input_type = (
        normalize_input_type(getattr(_np_snap, "input_type", ""), default="")
        if _np_snap else ""
    )
    # Precedence: turntable wins over bluetooth-ness, then the type picks the
    # icon -- a bluetooth turntable is still shown as a turntable.  The words
    # are the input's type label; a snapshot with no type falls back to words
    # derived from the flags.
    _np_icon_kind = (
        "turntable" if _np_is_turntable
        else "bluetooth" if _np_is_bluetooth
        else "cd" if _np_input_type == "cd"
        else "line"
    )
    _np_label = str(_np_active_level.get("label", f"Input {_np_input_num}"))
    _np_type_label = (
        input_type_label(_np_input_type) if _np_input_type
        else {
            "turntable": "Turntable",
            "bluetooth": "Bluetooth",
            "cd": "CD",
            "line": "Line Level",
        }[_np_icon_kind]
    )
    _np_rate_lock = str(_np_active_level.get("rate_lock", "locked"))
    _np_khz_text = str(_np_active_level.get("detected_khz", ""))
    _np_mismatch_khz = format_khz(float(_np_active_level.get("rate_mismatch_hz", 0) or 0))
    _np_signal_parts = []
    if show_input_detail:
        if _np_rate_lock == "mismatch" and _np_mismatch_khz:
            _np_signal_parts += ["Mismatch", _np_mismatch_khz]
        elif _np_rate_lock == "acquiring":
            _np_signal_parts.append("Acquiring")
        elif _np_rate_lock and _np_khz_text:
            _np_signal_parts += ["Locked", _np_khz_text]
    _np_signal = " \u00b7 ".join(_np_signal_parts)
    _np_icon_svg = {
        "turntable": ICON_TURNTABLE,
        "bluetooth": ICON_BLUETOOTH,
        "cd": ICON_CD,
        "line": ICON_LINE_LEVEL,
    }[_np_icon_kind]

    # Track identification initial state for server-rendered card.
    _ti_snap = active_track(snap)
    _ti_dict = _ti_snap.to_public_dict()
    _ti_enabled = bool(_ti_dict.get("enabled"))
    _ti_state = str(_ti_dict.get("state") or "")
    _ti_title = str(_ti_dict.get("title") or "")
    _ti_artist = str(_ti_dict.get("artist") or "")
    _ti_artwork_url_raw = str(_ti_dict.get("artwork_url") or "")
    _ti_artwork_url = html.escape(_ti_artwork_url_raw)  # safe for HTML src attribute

    # Compute the initial Now Playing icon and meta text for the server render.
    if _ti_enabled and _ti_state == "identified":
        if _ti_artwork_url:
            _np_icon_content = f'<img src="{_ti_artwork_url}" alt="">'
            # Use raw URL in the key so html.escape() in the template encodes it only once.
            _np_icon_key = f"art:{_ti_artwork_url_raw}"
            _np_icon_extra_cls = " np-icon-art"
        else:
            _np_icon_content = _np_icon_svg
            _np_icon_key = "art:"
            _np_icon_extra_cls = ""
        _np_display_name = html.escape(_ti_title or "Unknown")
        _np_display_signal = html.escape(_ti_artist)
    elif _ti_enabled:
        _input_prefix = (
            input_type_label(_np_input_type) if _np_input_type
            else {
                "turntable": "Vinyl",
                "bluetooth": "Bluetooth",
                "cd": "CD",
                "line": "Line In",
            }[_np_icon_kind]
        )
        if _ti_state == "error":
            _np_display_name = html.escape(f"{_input_prefix} – Track ID function not available")
        elif _ti_state == "not_found":
            _np_display_name = html.escape(f"{_input_prefix} – Unknown track")
        elif _ti_state in ("waiting_for_audio", "analysing"):
            # Use the API's own status_text ("Waiting for audio" /
            # "Analysing") instead of collapsing both into the
            # "Identifying Track…" catch-all.
            _ti_status_text = str(_ti_dict.get("status_text") or "Identifying Track…")
            _np_display_name = html.escape(f"{_input_prefix} – {_ti_status_text}")
        else:
            _np_display_name = html.escape(f"{_input_prefix} – Identifying Track…")
        _np_display_signal = ""
        _np_icon_content = _np_icon_svg
        _np_icon_key = f"svg:{_np_icon_kind}"
        _np_icon_extra_cls = ""
    else:
        _np_display_name = html.escape(f"{_np_label} · {_np_type_label}")
        _np_display_signal = html.escape(_np_signal)
        _np_icon_content = _np_icon_svg
        _np_icon_key = f"svg:{_np_icon_kind}"
        _np_icon_extra_cls = ""

    # Fetch the OwnTone start-buffer setting so the VU meter can be aligned to
    # the AirPlay playback delay.  Fall back to the default if OwnTone is
    # unreachable (e.g. still starting) or if the backend does not support it.
    try:
        _buf_result = get_setting(owntone_base_url, SETTING_START_BUFFER_MS, timeout=1)
        vu_delay_ms = int(_buf_result.value) if _buf_result.ok else SETTING_START_BUFFER_MS_DEFAULT
    except Exception:
        vu_delay_ms = SETTING_START_BUFFER_MS_DEFAULT

    outputs_part = store().snapshot().outputs
    if not outputs_part.connected:
        _placeholder_state = "unreachable"
    elif not outputs_part.reported_rows():
        _placeholder_state = "empty"
    else:
        _placeholder_state = "hidden"

    # Filter and sort outputs through the shared model helper, then annotate with occupancy.
    output_dicts = build_output_list(parsed, outputs_part.units) if outputs_part.connected else []
    try:
        from autostream_state.live import annotate_outputs as _annotate_outputs
        output_dicts = _annotate_outputs(output_dicts)
    except Exception:
        pass

    # Output-card markup: server-rendered HTML for the local Home page.
    #
    # DELIBERATE DUAL-RENDER EXCEPTION (remote-shell JS mirroring): the
    # remote/proxy Home page cannot
    # server-render this markup (it doesn't run this Python code -- it
    # renders client-side from polled JSON), so this block is intentionally
    # mirrored by the JS function `renderOutputList()`/`buildOutputCardElement()`
    # in `nginx/static/render_fragments.js` (served statically like
    # poll.js/theme.css, not inlined). Any change to the
    # output-card markup/classes/data-* attributes here must be reflected
    # there too, or the local and remote Home pages will visibly drift apart.
    outputs_html = ""
    for out in output_dicts:
        outputs_html += output_card_html(
            out_id=out["id"],
            name=out["name"],
            selected=out["selected"],
            volume=out["volume"],
            is_default=out["is_default"],
            remote_in_use=bool(out.get("remote_in_use")),
            remote_owner=str(out.get("remote_owner") or ""),
        )

    # Master volume: average of currently-selected outputs, or preset if none on.
    _selected_volumes = [out["volume"] for out in output_dicts if out["selected"]]
    if _selected_volumes:
        initial_master = round(sum(_selected_volumes) / len(_selected_volumes))
        master_inactive = False
    else:
        master_inactive = True

    lic_html, lic_spacer = build_top_banner_html(flash_msg=flash_msg, flash_type=flash_type)
    csrf_token = getattr(handler, "_csrf_token", None) or auth.get_csrf_token(handler.headers) or ""
    preset_volume = max(0, min(100, int(parsed.owntone.volume_percent or 20)))
    if master_inactive:
        initial_master = preset_volume
    _local_appliances = _build_appliances_for_selector()
    _local_id = str(rpi.get_appliance_id() or "")
    if show_hostname_on_home:
        _top_right_html = build_appliance_selector_html(
            _local_appliances, _local_id, "home",
            display_only=not effective_control,
        )
    else:
        _top_right_html = ""
    csrf_meta = (
        f"<meta name='csrf-token' content='{html.escape(csrf_token)}'>"
        f"<script>window.__CSRF='{html.escape(csrf_token)}';</script>"
    ) + static.script_tag("page/csrf_recovery.js")

    _island = static.page_data_island({
        "preset_volume": preset_volume,
        "show_input_detail": bool(show_input_detail),
        "vu_delay_ms": int(vu_delay_ms),
        "icons": {
            "turntable": ICON_TURNTABLE,
            "bluetooth": ICON_BLUETOOTH,
            "cd": ICON_CD,
            "line_level": ICON_LINE_LEVEL,
        },
        "local_id": _local_id,
        "selector_current_id": _local_id,
        "output_url": "/api/output",
        "repeat_url": "/api/repeat",
        "outputs_empty_tolerance_ms": int(OUTPUTS_EMPTY_TOLERANCE_SECONDS * 1000),
        "pin_prompt_fallback": "Enter PIN shown on your device",
        "control_other_appliances": bool(effective_control),
    })
    _head_extra = (
        csrf_meta
        + _island
        + "\n"
        + static.script_tag("poll.js") + "\n"
        + static.script_tag("render_fragments.js") + "\n"
        + static.script_tag("page/home_cards.js")
        + static.script_tag("page/appliance_selector.js")
        + static.script_tag("page/info_modal.js")
        + static.script_tag("page/start_failure.js")
        + static.script_tag("page/home.js")
    )
    _body_prefix = """
<div id="pinModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="pinModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="pinModalTitle">Enter PIN</div>
    <div class="bd modal-bd">
      <p>Enter the PIN shown on your Apple TV (or other AirPlay device) to enable playback.</p>
      <input id="pinModalInput" inputmode="numeric" autocomplete="one-time-code" placeholder="PIN" pattern="[0-9]*" maxlength="8" />
      <div id="pinModalNote" class="modal-note" hidden></div>
    </div>
    <div class="ft modal-ft">
      <button type="button" class="btn modal-btn modal-btn-secondary" id="pinModalCancel">Cancel</button>
      <button type="button" class="btn modal-btn modal-btn-primary" id="pinModalOk">OK</button>
    </div>
  </div>
</div>""" + INFO_MODAL_HTML

    # Repeat control -- small pill-style button rendered only when repeat.enabled,
    # styled like the appliance-selector button. Wired into
    # the existing 1.5 s refreshStatus() poll; click -> POST /api/repeat.
    # data-state attr: off / armed / repeating (used only for click-intent logic;
    # visual "active" treatment reuses the same accent-border/selected-surface
    # look as .output-card-on / .now-playing-card).
    _repeat_btn_html = (
        '<button type="button" class="pill-btn small repeat-btn" id="repeat-btn"'
        ' data-state="off" disabled'
        ' onclick="onRepeatButtonClick()">&#8635; Repeat Play</button>'
    ) if parsed.repeat.enabled else ""

    # Top controls row: repeat button + optional hostname/selector.
    _top_controls_html = (
        f"<div class='airplay-top-controls'>"
        f"{_repeat_btn_html}"
        + _top_right_html
        + f"</div>"
    )

    # Master volume wrapper embedded inside the Now Playing card.
    _np_vol_html = (
        f'<div class="np-volume-wrap{" master-volume-inactive" if master_inactive else ""}"'
        f' id="master-volume-card">'
        f'<div class="slider-header"><span>Master Volume</span></div>'
        + slider_html(
            id="master_vol_slider",
            value=initial_master,
            disabled=master_inactive,
            extra_attrs=(
                ' oninput="onMasterVolumeInput(this.value)"'
                ' onchange="onMasterVolumeChange(this.value)"'
                ' onmousedown="onMasterVolumeDragStart()"'
                ' ontouchstart="onMasterVolumeDragStart()"'
            ),
        )
        + f'</div>'
    ) if show_master_volume else ""

    # Now Playing card: header, input body (hidden when ready), master volume.
    # Active (playing): accent border + surface-selected. Ready: dim via .np-ready.
    _vu_bar_html = '<div class="vu-bar"></div>' * 7
    _vu_meter_html = (
        f'<div class="vu-meter" id="np-vu" aria-hidden="true">'
        f'<div class="vu-col" id="np-vu-l">{_vu_bar_html}</div>'
        f'<div class="vu-col" id="np-vu-r">{_vu_bar_html}</div>'
        f'</div>'
    ) if show_input_detail else ""
    # The level slot always renders the VU meter (when this appliance has
    # input detail to show); there is no separate mute indicator here any
    # more -- a mute is now shown in the header text instead, and the VU
    # meter itself simply stays visible whether the appliance is muted or
    # not (see home.css's .np-level rule for the slot's fixed width).
    _vu_html = f'<div class="np-level" id="np-level">{_vu_meter_html}</div>'
    _np_card_cls = "" if _np_is_playing else " np-ready"
    _np_hdr_text = "Now Playing" if _np_is_playing else "Ready"
    if _np_is_playing and snap.outputs.muted_all:
        # The WebUI has no dedicated unmute control any more: moving the
        # volume slider is the only way out of a mute, so the header text
        # is what tells the user the appliance is currently muted.
        _np_hdr_text += " (Muted)"
    _now_playing_card_html = (
        f'<div class="now-playing-card{_np_card_cls}" id="now-playing-card">'
        f'<div class="now-playing-hdr" id="np-hdr">{html.escape(_np_hdr_text)}</div>'
        f'<div class="now-playing-body">'
        f'<div class="now-playing-icon{_np_icon_extra_cls}" id="np-icon" data-np-icon-key="{html.escape(_np_icon_key)}">'
        f'{_np_icon_content}'
        f'</div>'
        f'<div class="now-playing-meta">'
        f'<div class="now-playing-name" id="np-name">{_np_display_name}</div>'
        f'<div class="now-playing-signal" id="np-signal">{_np_display_signal}</div>'
        f'</div>'
        f'{_vu_html}'
        f'</div>'
        f'{_np_vol_html}'
        f'</div>'
    )

    _warn_style_base = (
        "padding:0.85rem 0.9rem;border-radius:12px;"
        "border:1px solid var(--color-status-danger);"
        "background:var(--color-surface-raised);"
        "color:var(--color-text);font-size:0.99rem;"
        "text-align:center;text-decoration:none;"
    )
    _placeholder_text = {
        "unreachable": "Waiting for owntone",
        "empty": "Waiting for device discovery",
    }.get(_placeholder_state, "")
    _placeholder_html = (
        f"<p id='outputs-placeholder'{' hidden' if _placeholder_state == 'hidden' else ''}"
        f" style='text-align:center;color:var(--color-text-muted,#888);padding:1.5rem 0;margin:0;'>"
        f"{html.escape(_placeholder_text)}</p>"
    )
    _body_html = (
        # Full-width logo
        f"<div class='airplay-masthead'><div class='airplay-brand'>{BANNER_LOGO_HTML}</div></div>"
        # Repeat button + optional hostname pill
        + _top_controls_html
        # "No input configured" notice -- shown above the Now Playing card
        # (which holds the master volume control when enabled) so it reads
        # as a call-to-action ahead of playback/volume controls.
        + no_input_configured_notice_html(parsed)
        # Now Playing card (contains master volume when enabled)
        + _now_playing_card_html
        # Service warning banners
        + f"<a id='stylus-warning-banner' href='/service'"
        f" style='display:{'none' if not stylus_banner_text else 'block'};"
        f"margin:0.85rem 0 0.35rem;{_warn_style_base}'>"
        f"{html.escape(stylus_banner_text)}</a>"
        + f"<a id='belt-warning-banner' href='/service'"
        f" style='display:{'none' if not belt_banner_text else 'block'};"
        f"margin:0.35rem 0 0.35rem;{_warn_style_base}'>"
        f"{html.escape(belt_banner_text)}</a>"
        + f"<a id='bearing-warning-banner' href='/service'"
        f" style='display:{'none' if not bearing_banner_text else 'block'};"
        f"margin:0.35rem 0 0.35rem;{_warn_style_base}'>"
        f"{html.escape(bearing_banner_text)}</a>"
        + f"<a id='dial-update-warning-banner' href='/setup#dials'"
        f" style='display:{'none' if not dial_update_banner_text else 'block'};"
        f"margin:0.35rem 0 0.35rem;{_warn_style_base}'>"
        f"{html.escape(dial_update_banner_text)}</a>"
        + f"<a id='sample-rate-warning-banner' href='/setup#input{sample_rate_input_index}'"
        f" style='display:{'none' if not sample_rate_banner_text else 'block'};"
        f"margin:0.35rem 0 0.35rem;{_warn_style_base}'>"
        f"{html.escape(sample_rate_banner_text)}</a>"
        + (f"<p style='color:var(--color-status-danger);'>{html.escape(error)}</p>" if error else "")
        + _placeholder_html
        + A2HS_PROMPT_HTML
        + f"<div id='outputs-list'>{outputs_html}</div>"
    )
    html_body = build_page_html(
        "autostream",
        _body_html,
        style_files=_HOME_PAGE_STYLE_FILES,
        head_extra=_head_extra,
        body_prefix=_body_prefix,
        body_suffix=static.script_tag("page/a2hs.js") + static.script_tag("page/banner_dismiss.js"),
        lic_html=lic_html,
        lic_spacer=lic_spacer,
        active_tab="home",
        service_warn=playback_snapshot.has_warning,
        dark_mode=parsed.webui.dark_mode,
    )
    try:
        common.send_html(handler, 200, html_body)
    except Exception:
        logging.exception("Failed sending airplay page response.")


# ---------------------------------------------------------------------------
# Remote Home page — /a/<appliance_id>/
# ---------------------------------------------------------------------------

def send_remote_home_page(handler, state: WebUIState, appliance_id: str) -> None:
    """Render the remote Home shell for a remote appliance.

    Serves a client-side polling shell. JavaScript fetches
    /api/appliances/<id>/home every 3 seconds and updates the DOM.
    Output mutations go to /api/appliances/<id>/output via the gateway.
    After 3 consecutive transport failures the browser returns to /.
    Definitive resolution errors (not_found, etc.) return immediately to /.
    """
    try:
        parsed = common._config_snapshot(state)
    except Exception:
        try:
            handler.send_error(500, "Configuration unavailable")
        except Exception:
            pass
        return

    csrf_token = getattr(handler, "_csrf_token", None) or ""
    preset_volume = max(0, min(100, int(parsed.owntone.volume_percent or 20)))
    dark_mode = parsed.webui.dark_mode
    effective_control = parsed.webui.show_hostname_on_home and parsed.webui.control_other_appliances

    appliances = _build_appliances_for_selector()
    _local_id = str(rpi.get_appliance_id() or "")

    poll_url = f"/api/appliances/{appliance_id}/home"
    output_url = f"/api/appliances/{appliance_id}/output"
    repeat_url = f"/api/appliances/{appliance_id}/repeat"

    _selector_html = build_appliance_selector_html(appliances, appliance_id, "home")

    # Resolve remote hostname for page title and JS failure messages
    _remote_hostname = "autostream"
    for a in appliances:
        if a.get("id") == appliance_id:
            _remote_hostname = str(a.get("hostname") or "autostream")
            break
    if _remote_hostname.lower().endswith(".local"):
        _remote_hostname = _remote_hostname[:-6]

    _warn_style_base = (
        "padding:0.85rem 0.9rem;border-radius:12px;"
        "border:1px solid var(--color-status-danger);"
        "background:var(--color-surface-raised);"
        "color:var(--color-text);font-size:0.99rem;"
        "text-align:center;text-decoration:none;"
    )

    _island = static.page_data_island({
        "preset_volume": preset_volume,
        "show_input_detail": False,
        "vu_delay_ms": 2250,
        "icons": {
            "turntable": ICON_TURNTABLE,
            "bluetooth": ICON_BLUETOOTH,
            "cd": ICON_CD,
            "line_level": ICON_LINE_LEVEL,
        },
        "local_id": _local_id,
        "selector_current_id": appliance_id,
        "output_url": output_url,
        "repeat_url": repeat_url,
        "outputs_empty_tolerance_ms": int(OUTPUTS_EMPTY_TOLERANCE_SECONDS * 1000),
        "pin_prompt_fallback": "Enter PIN",
        "control_other_appliances": bool(effective_control),
        "remote_aid": appliance_id,
        "remote_hostname": _remote_hostname,
        "poll_url": poll_url,
    })

    _head_extra = (
        f"<meta name='csrf-token' content='{html.escape(csrf_token)}'>"
        f"<script>window.__CSRF='{html.escape(csrf_token)}';</script>"
        + static.script_tag("page/csrf_recovery.js")
        + _island
        + "\n"
        + static.script_tag("render_fragments.js") + "\n"
        + static.script_tag("page/home_cards.js")
        + static.script_tag("page/appliance_selector.js")
        + static.script_tag("page/info_modal.js")
        + static.script_tag("page/start_failure.js")
        + static.script_tag("page/remote_home.js")
    )

    _body_prefix = """
<div id="pinModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="pinModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="pinModalTitle">Enter PIN</div>
    <div class="bd modal-bd">
      <p>Enter the PIN shown on your Apple TV (or other AirPlay device) to enable playback.</p>
      <input id="pinModalInput" inputmode="numeric" autocomplete="one-time-code" placeholder="PIN" pattern="[0-9]*" maxlength="8" />
      <div id="pinModalNote" class="modal-note" hidden></div>
    </div>
    <div class="ft modal-ft">
      <button type="button" class="btn modal-btn modal-btn-secondary" id="pinModalCancel">Cancel</button>
      <button type="button" class="btn modal-btn modal-btn-primary" id="pinModalOk">OK</button>
    </div>
  </div>
</div>""" + INFO_MODAL_HTML

    _np_icon_svg = ICON_LINE_LEVEL

    # Repeat control -- same small pill-style button as the local page, but
    # hidden until the polled home feed's "repeat" block confirms the remote
    # appliance actually has the feature enabled (updateRepeatButton, shared
    # via home_cards.js, un-hides it from renderHomeState). An older
    # remote appliance that never reports a "repeat" block simply leaves the
    # pill hidden -- no error shown. Navigation back to the bound appliance
    # is via the logo (BANNER_LOGO_HTML links to "/"), so this slot no longer
    # needs a dedicated "Home" button.
    _repeat_btn_html = (
        '<button type="button" class="pill-btn small repeat-btn" id="repeat-btn"'
        ' data-state="off" disabled hidden'
        ' onclick="onRepeatButtonClick()">&#8635; Repeat Play</button>'
    )

    _top_controls_html = (
        f"<div class='airplay-top-controls'>"
        f"{_repeat_btn_html}"
        f"{_selector_html}"
        f"</div>"
    )

    _now_playing_card_html = (
        f'<div class="now-playing-card np-ready" id="now-playing-card">'
        f'<div class="now-playing-hdr" id="np-hdr">Ready · {html.escape(_remote_hostname)}</div>'
        f'<div class="now-playing-body">'
        f'<div class="now-playing-icon" id="np-icon" data-np-icon-key="svg:line">'
        f'{_np_icon_svg}'
        f'</div>'
        f'<div class="now-playing-meta">'
        f'<div class="now-playing-name" id="np-name">Connecting&hellip;</div>'
        f'<div class="now-playing-signal" id="np-signal"></div>'
        f'</div>'
        f'<div class="np-level" id="np-level"></div>'
        f'</div>'
        f'<div class="np-volume-wrap master-volume-inactive" id="master-volume-card" hidden>'
        f'<div class="slider-header"><span>Master Volume</span></div>'
        + slider_html(
            id="master_vol_slider",
            value=preset_volume,
            disabled=True,
            extra_attrs=(
                ' oninput="onMasterVolumeInput(this.value)"'
                ' onchange="onMasterVolumeChange(this.value)"'
                ' onmousedown="onMasterVolumeDragStart()"'
                ' ontouchstart="onMasterVolumeDragStart()"'
            ),
        )
        + f'</div>'
        f'</div>'
    )

    _body_html = (
        f"<div class='airplay-masthead'><div class='airplay-brand'>{BANNER_LOGO_HTML}</div></div>"
        + _top_controls_html
        + _now_playing_card_html
        + f"<a id='stylus-warning-banner' href='#'"
        f" style='display:none;margin:0.85rem 0 0.35rem;{_warn_style_base}'></a>"
        + f"<a id='belt-warning-banner' href='#'"
        f" style='display:none;margin:0.35rem 0 0.35rem;{_warn_style_base}'></a>"
        + f"<a id='bearing-warning-banner' href='#'"
        f" style='display:none;margin:0.35rem 0 0.35rem;{_warn_style_base}'></a>"
        + f"<p id='outputs-placeholder' style='text-align:center;"
        f"color:var(--color-text-muted,#888);padding:1.5rem 0;margin:0;'>"
        f"Connecting&hellip;</p>"
        + f"<div id='outputs-list'></div>"
    )

    html_body = build_page_html(
        f"autostream — {html.escape(_remote_hostname)}",
        _body_html,
        style_files=_HOME_PAGE_STYLE_FILES,
        head_extra=_head_extra,
        body_prefix=_body_prefix,
        body_suffix=static.script_tag("page/a2hs.js") + static.script_tag("page/banner_dismiss.js"),
        active_tab="home",
        dark_mode=dark_mode,
        remote_id=appliance_id,
    )
    try:
        common.send_html(handler, 200, html_body)
    except Exception:
        logging.exception("Failed sending remote home page response.")
