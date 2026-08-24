#!/usr/bin/env python3
"""autostream_webui_page_airplay.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Renderer for the main AirPlay control page (/).
"""

from __future__ import annotations

import html
import json
import logging

from typing import Optional

from autostream_appliance_models import build_output_list
from autostream_appliances import get_all_appliances
from autostream_core import (
    get_monitor_levels_dbfs,
    get_playback_snapshot,
)
from autostream_player_service import get_setting, list_outputs
from autostream_players import SETTING_START_BUFFER_MS, SETTING_START_BUFFER_MS_DEFAULT
from autostream_rpi import get_appliance_id
from autostream_sysutils import get_system_hostname, reboot_system
from autostream_webui_components import output_card_html, slider_html
from autostream_webui_assets import (
    A2HS_PROMPT_HTML,
    A2HS_SCRIPT,
    APPLIANCE_SELECTOR_CSS,
    BANNER_DISMISS_SCRIPT,
    BANNER_LOGO_HTML,
    COMMON_MODAL_CSS,
    HOME_CARDS_SCRIPT,
    ICON_BLUETOOTH,
    ICON_LINE_LEVEL,
    ICON_TURNTABLE,
    INFO_MODAL_HTML,
    INFO_MODAL_SCRIPT,
    PIN_MODAL_CSS,
)
from autostream_webui_common import (
    CSRF_RECOVERY_SCRIPT,
    _config_snapshot,
    build_appliance_selector_html,
    build_page_html,
    build_top_banner_html,
    get_app_version,
    no_input_configured_notice_html,
    send_html,
)
from autostream_webui_state import WebUIState


# Wall-clock tolerance, in seconds, for transient emptiness of the backend's
# reported outputs list (for example while a stereo pair is reforming, the
# device list can briefly shrink to zero before settling back). Both the
# local page poll and the remote/proxy home-state poll debounce an observed
# empty-outputs state against this tolerance before clearing the displayed
# output cards and showing the "no outputs" placeholder. Not exposed via any
# UI or settings surface.
OUTPUTS_EMPTY_TOLERANCE_SECONDS = 6.0


_NP_ART_CSS = (
    ".now-playing-icon.np-icon-art{width:72px;height:72px;border-radius:6px;overflow:hidden;}"
    ".now-playing-icon.np-icon-art img{width:100%;height:100%;object-fit:cover;display:block;}"
)

_VU_STEREO_CSS = (
    ".vu-meter{flex-direction:row;gap:3px;width:23px;}"
    ".vu-col{display:flex;flex-direction:column-reverse;gap:2px;"
    "width:10px;flex:0 0 10px;}"
)

# Shared extra_css for the two "Home page" renderers below (send_airplay_page,
# send_remote_home_page) — built once at import time rather than reconstructed
# identically inside each function on every request.
_HOME_PAGE_EXTRA_CSS = f"{COMMON_MODAL_CSS}\n{PIN_MODAL_CSS}\n{APPLIANCE_SELECTOR_CSS}\n{_VU_STEREO_CSS}\n{_NP_ART_CSS}"


_REMOTE_HOME_SCRIPT = """<script>
function renderHomeState(data){
  renderNowPlayingCard(data);
  updateRepeatButton(data);
  var prefs=(data&&data.preferences)||{};var showMaster=!!prefs.show_master_volume;var masterCard=document.getElementById('master-volume-card');if(masterCard)masterCard.hidden=!showMaster;
  if(Array.isArray(data.outputs)){
    var outputs=data.outputs;
    if(outputs.length===0){
      if(__outputsEmptySince==null)__outputsEmptySince=Date.now();
      if((Date.now()-__outputsEmptySince)>=window.__OUTPUTS_EMPTY_TOLERANCE_MS){var _ol=document.getElementById('outputs-list');if(_ol)while(_ol.firstChild)_ol.removeChild(_ol.firstChild);__lastOutputsShape='';setOutputsPlaceholder('empty');}
      // else: within tolerance -- leave existing cards and placeholder alone
    }else{
      __outputsEmptySince=null;
      var inShape=_outputsShape(outputs);if(inShape!==__lastOutputsShape){__lastOutputsShape=inShape;renderOutputList(outputs);}else{setOutputsPlaceholder('hidden');outputs.forEach(function(o){var id=String(o.id);if(window.__PENDING_OUTPUTS&&window.__PENDING_OUTPUTS.has(id))return;var cb=document.getElementById('output_enabled_'+id);var sl=document.getElementById('vol_slider_'+id);if(cb){cb.checked=!!o.selected;updateOutputStateVisual(id,!!o.selected);}if(sl&&sl!==document.activeElement){var v=normalizeVolume(o.volume);if(sl.value!==String(v)){sl.value=String(v);updateVolumeLabel(id,v);}}});reorderOutputCards();if(document.activeElement!==document.getElementById('master_vol_slider'))updateMasterVolumeCard();}
    }
  }
  // else: outputs unknown (field missing/null despite an ok reply) -- freeze
  // the empty-tolerance timer and leave the DOM untouched entirely.
  var warnings=(data&&data.warnings)||{};['stylus','belt','bearing'].forEach(function(item){var el=document.getElementById(item+'-warning-banner');if(!el)return;var txt=String(warnings[item]||'').trim();el.style.display=txt?'block':'none';el.textContent=txt;});
  if(showMaster)updateMasterVolumeCard();
}
var __lastOutputsShape='';
var __outputsEmptySince=null;
function _outputShapeKey(o){return String(o.id)+'|'+String(o.name||'')+'|'+String(!!o.is_default)+'|'+String(!!o.remote_in_use)+'|'+String(o.remote_owner||'');}
function _outputsShape(outputs){return outputs.map(_outputShapeKey).sort().join(',');}
var __remoteFailCount=0;var __remotePolling=true;var __remotePollTimer=null;
var __DEFINITIVE_ERRORS=['not_found','appliance_unconfigured','appliance_conflicted','appliance_identity_unavailable'];
var __TRANSPORT_ERRORS=['remote_timeout','remote_bad_response','appliance_offline'];
function __homeRedirectWithFlash(msg){window.location.href='/?msg='+encodeURIComponent('error:'+msg);}
function __homeHandleDefinitiveError(err){var h=window.__REMOTE_HOSTNAME||'autostream';var msgs={'not_found':'The selected appliance address is invalid. Returned to this appliance.','appliance_unconfigured':h+' is not ready for remote control. Returned to this appliance.','appliance_conflicted':h+' has a network identity conflict and cannot be selected safely. Returned to this appliance.','appliance_identity_unavailable':h+' cannot currently provide multi-appliance access. Returned to this appliance.'};__homeRedirectWithFlash(msgs[err]||(h+' is unavailable. Returned to this appliance.'));}
function scheduleRemotePoll(){if(__remotePollTimer)clearTimeout(__remotePollTimer);__remotePollTimer=setTimeout(pollHomeState,3000);}
async function pollHomeState(){if(!__remotePolling)return;var data=null;try{var r=await fetch(window.__POLL_URL,{cache:'no-store',signal:AbortSignal.timeout(5000)});data=await r.json();}catch(e){__remoteFailCount++;if(__remoteFailCount>=3){__homeRedirectWithFlash((window.__REMOTE_HOSTNAME||'autostream')+' is unavailable. Returned to this appliance.');return;}scheduleRemotePoll();return;}if(!data||!data.ok){var err=(data&&data.error)||'remote_timeout';if(__DEFINITIVE_ERRORS.indexOf(err)>=0){__homeHandleDefinitiveError(err);return;}if(__TRANSPORT_ERRORS.indexOf(err)>=0){__remoteFailCount++;if(__remoteFailCount>=3){__homeRedirectWithFlash((window.__REMOTE_HOSTNAME||'autostream')+' is unavailable. Returned to this appliance.');return;}}scheduleRemotePoll();return;}__remoteFailCount=0;renderHomeState(data);scheduleRemotePoll();}
window.addEventListener('DOMContentLoaded',function(){
  window.__PENDING_OUTPUTS=new Set();window.__MASTER_DRAG_SNAPSHOTS={};window.__MASTER_DRAG_BASE=0;window.__OUTPUTS_IN_FLIGHT=false;
  initApplianceSelector();refreshApplianceSelector();
  setInterval(function(){if(!document.hidden)refreshApplianceSelector();},15000);
  document.addEventListener('visibilitychange',function(){if(!document.hidden){__remotePolling=true;__remoteFailCount=0;pollHomeState();refreshApplianceSelector();}else{__remotePolling=false;if(__remotePollTimer){clearTimeout(__remotePollTimer);__remotePollTimer=null;}}});
  __remotePolling=true;__remoteFailCount=0;
  setInterval(vuRenderTick,VU_BIN_MS);
  pollHomeState();
});
</script>"""

_NAVIGATE_SCRIPT = (
    "<script>"
    "function navigateToRemoteAppliance(hostname){"
    "fetch('/api/appliances',{cache:'no-store'})"
    ".then(function(r){return r.json();})"
    ".then(function(data){"
    "if(!data||!data.ok||!Array.isArray(data.appliances))return;"
    "var appliance=data.appliances.find(function(a){"
    "return String(a.hostname||'').toLowerCase()===String(hostname||'').toLowerCase();"
    "});"
    "if(appliance){window.location.href='/a/'+String(appliance.id)+'/';}"
    "}).catch(function(){});"
    "}"
    "document.addEventListener('DOMContentLoaded',function(){"
    "var list=document.getElementById('outputs-list');"
    "if(!list)return;"
    "list.addEventListener('click',function(e){"
    "if(!window.__CONTROL_OTHER_APPLIANCES)return;"
    "var card=e.target.closest('.output-card[data-remote-in-use=\"1\"]');"
    "if(!card)return;"
    "if(e.target.closest('.output-toggle')||e.target.closest('.output-slider-wrap'))return;"
    "var owner=card.getAttribute('data-remote-owner');"
    "if(owner)navigateToRemoteAppliance(owner);"
    "});"
    "});"
    "</script>"
)


def _build_appliances_for_selector() -> list:
    """Return the bound-first appliance list suitable for the selector widget.

    Format matches the /api/appliances JSON response so the same JS update
    function works for both server-rendered initial state and polled updates.
    """
    local_id = get_appliance_id() or ""
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
        parsed = _config_snapshot(state)
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
            send_html(handler, 500, body)
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

    try:
        input_levels = get_monitor_levels_dbfs()
    except Exception:
        input_levels = []

    playback_snapshot = get_playback_snapshot()
    stylus_banner_text = playback_snapshot.stylus_banner_text or ""
    belt_banner_text = playback_snapshot.belt_banner_text or ""
    bearing_banner_text = playback_snapshot.bearing_banner_text or ""
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
    _np_snap = playback_snapshot.inputs.get(_np_active_idx + 1)
    _np_is_turntable = bool(_np_snap.is_turntable) if _np_snap else False
    _np_is_bluetooth = bool(_np_snap.is_bluetooth) if _np_snap else False
    # Precedence: turntable wins over bluetooth-ness (mirrors
    # _default_nowplaying_title in autostream_core.py) -- a bluetooth
    # turntable is still shown/labelled as a turntable.
    _np_icon_kind = (
        "turntable" if _np_is_turntable
        else "bluetooth" if _np_is_bluetooth
        else "line"
    )
    _np_label = str(_np_active_level.get("label", f"Input {_np_active_idx + 1}"))
    _np_type_label = {
        "turntable": "Turntable",
        "bluetooth": "Bluetooth",
        "line": "Line Level",
    }[_np_icon_kind]
    _np_hz = float(_np_active_level.get("detected_hz", 0.0))
    _np_signal_parts = []
    if show_input_detail and _np_hz > 0:
        _np_signal_parts.append("Locked")
        _np_signal_parts.append(f"{_np_hz / 1000:.0f} kHz")
    _np_signal = " \u00b7 ".join(_np_signal_parts)
    _np_icon_svg = {
        "turntable": ICON_TURNTABLE,
        "bluetooth": ICON_BLUETOOTH,
        "line": ICON_LINE_LEVEL,
    }[_np_icon_kind]

    # Track identification initial state for server-rendered card.
    try:
        from autostream_core import get_active_track_identification_snapshot as _gati
        _ti_snap = _gati()
    except Exception:
        from track_id.models import disabled_snapshot as _ds
        _ti_snap = _ds()
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
        _input_prefix = {
            "turntable": "Vinyl",
            "bluetooth": "Bluetooth",
            "line": "Line In",
        }[_np_icon_kind]
        if _ti_state == "error":
            _np_display_name = html.escape(f"{_input_prefix} – Track ID function not available")
        elif _ti_state == "not_found":
            _np_display_name = html.escape(f"{_input_prefix} – Unknown track")
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

    outputs_result = list_outputs(owntone_base_url, timeout=3)
    raw_outputs = list(outputs_result.outputs) if outputs_result.ok else []
    if not outputs_result.ok:
        _placeholder_state = "unreachable"
    elif not raw_outputs:
        _placeholder_state = "empty"
    else:
        _placeholder_state = "hidden"

    # Filter and sort outputs through the shared model helper, then annotate with occupancy.
    output_dicts = build_output_list(parsed, raw_outputs)
    try:
        from autostream_output_usage import annotate_outputs as _annotate_outputs
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
    # in `nginx/static/render_fragments.js` (source of truth:
    # RENDER_FRAGMENTS_JS, core/autostream_webui_assets.py -- served
    # statically like poll.js/theme.css, not inlined). Any change to the
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
    _local_id = str(get_appliance_id() or "")
    if show_hostname_on_home:
        _top_right_html = build_appliance_selector_html(
            _local_appliances, _local_id, "home",
            display_only=not effective_control,
        )
    else:
        _top_right_html = ""
    csrf_meta = (
        f"<meta name='csrf-token' content='{html.escape(csrf_token)}'>"
        f"<script>window.__CSRF='{html.escape(csrf_token)}';"
        f"window.__PRESET_VOLUME={preset_volume};"
        f"window.__SHOW_INPUT_DETAIL={'true' if show_input_detail else 'false'};"
        f"window.__VU_DELAY_MS={int(vu_delay_ms)};"
        f"window.__ICON_TURNTABLE={json.dumps(ICON_TURNTABLE)};"
        f"window.__ICON_BLUETOOTH={json.dumps(ICON_BLUETOOTH)};"
        f"window.__ICON_LINE_LEVEL={json.dumps(ICON_LINE_LEVEL)};"
        f"window.__LOCAL_ID='{html.escape(_local_id)}';"
        f"window.__SELECTOR_CURRENT_ID='{html.escape(_local_id)}';"
        f"window.__OUTPUT_URL='/api/output';"
        f"window.__REPEAT_URL='/api/repeat';"
        f"window.__OUTPUTS_EMPTY_TOLERANCE_MS={int(OUTPUTS_EMPTY_TOLERANCE_SECONDS * 1000)};"
        f"window.__PIN_PROMPT_FALLBACK='Enter PIN shown on your device';"
        f"window.__CONTROL_OTHER_APPLIANCES={json.dumps(effective_control)};"
        f"</script>"
    ) + CSRF_RECOVERY_SCRIPT

    _extra_css = _HOME_PAGE_EXTRA_CSS
    _poll_js_src = f'<script src="/static/poll.js?v={html.escape(get_app_version())}"></script>'
    _render_fragments_js_src = f'<script src="/static/render_fragments.js?v={html.escape(get_app_version())}"></script>'
    _head_extra = f"""{csrf_meta}
{_poll_js_src}
{_render_fragments_js_src}
""" + HOME_CARDS_SCRIPT + INFO_MODAL_SCRIPT + f"""
      <script>
        function getOutputIdKey(outputs) {{
          return JSON.stringify(outputs.map(function(o) {{
            return String(o.id) + '|' + String(!!o.remote_in_use) + '|' + String(o.remote_owner || '');
          }}).sort());
        }}
        function onStatusPollData(d) {{
          renderNowPlayingCard(d);
          updateRepeatButton(d);
          ['stylus', 'belt', 'bearing'].forEach(function(item) {{
            var el = document.getElementById(item + '-warning-banner');
            if (!el) return;
            var key = item === 'stylus' ? 'playback_banner_text' : item + '_banner_text';
            var txt = String((d && d[key]) || '').trim();
            el.style.display = txt ? 'block' : 'none';
            el.textContent = txt;
          }});
        }}
        function onOutputsPollData(j) {{
          var __list = document.getElementById('outputs-list');
          var __domIds = __list ? Array.from(__list.querySelectorAll('.output-card[data-output-id]')).map(function(c) {{
            return c.getAttribute('data-output-id') + '|' + (c.getAttribute('data-remote-in-use') === '1' ? 'true' : 'false') + '|' + (c.getAttribute('data-remote-owner') || '');
          }}) : [];
          var domKey = __domIds.length > 0 ? JSON.stringify(__domIds.sort()) : '';
          if (!j || !j.ok) {{
            if (domKey === '') {{ setOutputsPlaceholder('unreachable'); }}
            return;
          }}
          if (!Array.isArray(j.outputs)) {{
            // Outputs unknown (field missing despite an ok reply): leave the
            // DOM untouched and freeze the empty-tolerance timer rather than
            // treating this as a confirmed empty outputs list.
            return;
          }}
          var outputs = j.outputs;
          if (outputs.length === 0) {{
            if (window.__OUTPUTS_EMPTY_SINCE == null) {{ window.__OUTPUTS_EMPTY_SINCE = Date.now(); }}
            if (domKey !== '' && (Date.now() - window.__OUTPUTS_EMPTY_SINCE) < window.__OUTPUTS_EMPTY_TOLERANCE_MS) {{
              return;
            }}
          }} else {{
            window.__OUTPUTS_EMPTY_SINCE = null;
          }}
          var targetKey = outputs.length > 0 ? getOutputIdKey(outputs) : '';
          if (targetKey === domKey) {{
            if (targetKey === '') {{
              setOutputsPlaceholder('empty');
            }} else {{
              setOutputsPlaceholder('hidden');
              for (const o of outputs) {{
                const id = String(o.id);
                if (window.__PENDING_OUTPUTS && window.__PENDING_OUTPUTS.has(id)) continue;
                const cb = document.getElementById("output_enabled_" + id);
                const sl = document.getElementById("vol_slider_" + id);
                if (cb) cb.checked = !!o.selected;
                updateOutputStateVisual(id, !!o.selected);
                if (sl && !isActiveControl(sl)) {{
                  const v = normalizeVolume(o.volume);
                  const vstr = String(v);
                  if (sl.value !== vstr) sl.value = vstr;
                  updateVolumeLabel(id, v);
                }}
              }}
              reorderOutputCards();
              if (!isActiveControl(document.getElementById('master_vol_slider'))) updateMasterVolumeCard();
            }}
            return;
          }}
          var hasPending = window.__PENDING_OUTPUTS && window.__PENDING_OUTPUTS.size > 0;
          var masterActive = isActiveControl(document.getElementById('master_vol_slider'));
          var pinVisible = !!(document.getElementById('pinModal') && document.getElementById('pinModal').classList.contains('show'));
          var anySliderActive = !!(document.activeElement && document.activeElement.id && document.activeElement.id.startsWith('vol_slider_'));
          if (!hasPending && !masterActive && !pinVisible && !anySliderActive) {{
            renderOutputList(outputs);
            return;
          }}
          if (domKey !== '') {{ setOutputsPlaceholder('hidden'); }}
          for (const o of outputs) {{
            const id = String(o.id);
            if (window.__PENDING_OUTPUTS && window.__PENDING_OUTPUTS.has(id)) continue;
            const cb = document.getElementById("output_enabled_" + id);
            const sl = document.getElementById("vol_slider_" + id);
            if (cb) cb.checked = !!o.selected;
            updateOutputStateVisual(id, !!o.selected);
            if (sl && !isActiveControl(sl)) {{
              const v = normalizeVolume(o.volume);
              const vstr = String(v);
              if (sl.value !== vstr) sl.value = vstr;
              updateVolumeLabel(id, v);
            }}
          }}
          reorderOutputCards();
          if (!isActiveControl(document.getElementById('master_vol_slider'))) updateMasterVolumeCard();
        }}

        window.addEventListener('DOMContentLoaded',function(){{
          window.__PENDING_OUTPUTS = new Set();
          window.__MASTER_DRAG_SNAPSHOTS = {{}};
          window.__MASTER_DRAG_BASE = 0;
          document.querySelectorAll('[data-volume-label-for]').forEach(s=>{{
            var i=s.getAttribute('data-volume-label-for'), sl=document.getElementById('vol_slider_'+i);
            if(sl)updateVolumeLabel(i, sl.value);
            var cb=document.getElementById('output_enabled_'+i);
            if(cb) updateOutputStateVisual(String(i), !!cb.checked);
          }});
          reorderOutputCards();
          updateMasterVolumeCard();
          window.__OUTPUTS_EMPTY_SINCE = null;
          setInterval(vuRenderTick, VU_BIN_MS);
          initApplianceSelector();
          refreshApplianceSelector();
          setInterval(function(){{if(!document.hidden) refreshApplianceSelector();}},15000);
          document.addEventListener('visibilitychange',function(){{if(!document.hidden) refreshApplianceSelector();}});
          Poller({{ url: '/api/status', intervalMs: 1500, onData: onStatusPollData }});
          Poller({{ url: '/api/owntone/outputs_state', intervalMs: 1500, timeoutMs: 5000, onData: onOutputsPollData }});
        }});
      </script>""" + _NAVIGATE_SCRIPT
    _body_prefix = """
<div id="pinModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="pinModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="pinModalTitle">Enter PIN</div>
    <div class="bd modal-bd">
      <p>Enter the PIN shown on your Apple TV (or other AirPlay device) to enable playback.</p>
      <input id="pinModalInput" inputmode="numeric" autocomplete="one-time-code" placeholder="PIN" />
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
        ' onclick="onRepeatButtonClick()">\u21bb Repeat Play</button>'
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
    _vu_html = (
        f'<div class="vu-meter" id="np-vu" aria-hidden="true">'
        f'<div class="vu-col" id="np-vu-l">{_vu_bar_html}</div>'
        f'<div class="vu-col" id="np-vu-r">{_vu_bar_html}</div>'
        f'</div>'
    ) if show_input_detail else ""
    _np_card_cls = "" if _np_is_playing else " np-ready"
    _np_hdr_text = "Now Playing" if _np_is_playing else "Ready"
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
        + (f"<p style='color:var(--color-status-danger);'>{html.escape(error)}</p>" if error else "")
        + _placeholder_html
        + A2HS_PROMPT_HTML
        + f"<div id='outputs-list'>{outputs_html}</div>"
    )
    html_body = build_page_html(
        "autostream",
        _body_html,
        extra_css=_extra_css,
        head_extra=_head_extra,
        body_prefix=_body_prefix,
        body_suffix=A2HS_SCRIPT + BANNER_DISMISS_SCRIPT,
        lic_html=lic_html,
        lic_spacer=lic_spacer,
        active_tab="home",
        service_warn=playback_snapshot.has_warning,
        dark_mode=parsed.webui.dark_mode,
    )
    try:
        send_html(handler, 200, html_body)
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
        parsed = _config_snapshot(state)
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
    _local_id = str(get_appliance_id() or "")

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

    _extra_css = _HOME_PAGE_EXTRA_CSS

    _head_extra = (
        f"<meta name='csrf-token' content='{html.escape(csrf_token)}'>"
        f"<script>"
        f"window.__CSRF='{html.escape(csrf_token)}';"
        f"window.__PRESET_VOLUME={preset_volume};"
        f"window.__SHOW_INPUT_DETAIL=false;"
        f"window.__VU_DELAY_MS=2250;"
        f"window.__ICON_TURNTABLE={json.dumps(ICON_TURNTABLE)};"
        f"window.__ICON_BLUETOOTH={json.dumps(ICON_BLUETOOTH)};"
        f"window.__ICON_LINE_LEVEL={json.dumps(ICON_LINE_LEVEL)};"
        f"window.__LOCAL_ID='{html.escape(_local_id)}';"
        f"window.__REMOTE_AID='{html.escape(appliance_id)}';"
        f"window.__REMOTE_HOSTNAME='{html.escape(_remote_hostname)}';"
        f"window.__SELECTOR_CURRENT_ID='{html.escape(appliance_id)}';"
        f"window.__POLL_URL='{html.escape(poll_url)}';"
        f"window.__OUTPUT_URL='{html.escape(output_url)}';"
        f"window.__REPEAT_URL='{html.escape(repeat_url)}';"
        f"window.__OUTPUTS_EMPTY_TOLERANCE_MS={int(OUTPUTS_EMPTY_TOLERANCE_SECONDS * 1000)};"
        f"window.__CONTROL_OTHER_APPLIANCES={json.dumps(effective_control)};"
        f"</script>\n"
        + CSRF_RECOVERY_SCRIPT
        + f'<script src="/static/render_fragments.js?v={html.escape(get_app_version())}"></script>\n'
        + HOME_CARDS_SCRIPT
        + INFO_MODAL_SCRIPT
        + _REMOTE_HOME_SCRIPT
        + _NAVIGATE_SCRIPT
    )

    _body_prefix = """
<div id="pinModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="pinModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="pinModalTitle">Enter PIN</div>
    <div class="bd modal-bd">
      <p>Enter the PIN shown on your Apple TV (or other AirPlay device) to enable playback.</p>
      <input id="pinModalInput" inputmode="numeric" autocomplete="one-time-code" placeholder="PIN" />
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
    # via HOME_CARDS_SCRIPT, un-hides it from renderHomeState). An older
    # remote appliance that never reports a "repeat" block simply leaves the
    # pill hidden -- no error shown. Navigation back to the bound appliance
    # is via the logo (BANNER_LOGO_HTML links to "/"), so this slot no longer
    # needs a dedicated "Home" button.
    _repeat_btn_html = (
        '<button type="button" class="pill-btn small repeat-btn" id="repeat-btn"'
        ' data-state="off" disabled hidden'
        ' onclick="onRepeatButtonClick()">↻ Repeat Play</button>'
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
        f'<div class="now-playing-name" id="np-name">Connecting…</div>'
        f'<div class="now-playing-signal" id="np-signal"></div>'
        f'</div>'
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
        f"Connecting…</p>"
        + f"<div id='outputs-list'></div>"
    )

    html_body = build_page_html(
        f"autostream — {html.escape(_remote_hostname)}",
        _body_html,
        extra_css=_extra_css,
        head_extra=_head_extra,
        body_prefix=_body_prefix,
        body_suffix=A2HS_SCRIPT + BANNER_DISMISS_SCRIPT,
        active_tab="home",
        dark_mode=dark_mode,
        remote_id=appliance_id,
    )
    try:
        send_html(handler, 200, html_body)
    except Exception:
        logging.exception("Failed sending remote home page response.")
