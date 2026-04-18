#!/usr/bin/env python3
"""autostream_webui_page_airplay.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Renderer for the main AirPlay control page (/).
"""

from __future__ import annotations

import html
import logging
import textwrap

from typing import Optional

from autostream_config import parse_config
from autostream_core import (
    any_monitor_capturing,
    get_monitor_levels_dbfs,
    get_playback_snapshot,
)
from autostream_player_service import list_outputs
from autostream_sysutils import reboot_system
from autostream_webui_assets import (
    A2HS_PROMPT_HTML,
    A2HS_SCRIPT,
    BANNER_HTML,
    PIN_MODAL_CSS,
    STYLE_CSS,
    VIEWPORT_META,
)
from autostream_webui_common import build_top_banner_html, locked_load_config
from autostream_webui_state import WebUIState
from autostream_webui_api import _status_text_for_home


def send_airplay_page(
    handler,
    state: WebUIState,
    auth,
    error: Optional[str] = None,
    flash_msg: Optional[str] = None,
    flash_type: str = "success",
) -> None:
    """Render the main AirPlay control page."""
    try:
        cfg = locked_load_config(state.config_path)
        parsed = parse_config(cfg)
    except Exception:
        # If we're here something bad happened - user should have been redirected to the setup page
        # if the INI is missing. Hence, take the nuclear option and inform the user that something
        # went wrong - then reboot the system. This code serves only inline code in case the file
        # system is dead (which is likely). Reboot may therefore also fail.
        body = textwrap.dedent(f"""\
          <!DOCTYPE html><html><head><meta charset="utf-8"><title>Logs</title>
          <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
          <style>{STYLE_CSS}
          body {{ font-size: 14px !important; }}
          </style></head>
          <body>
            <h1>System Error</h1>
            <p>Unfortunately, an unrecoverable error has occurred:
            autostream was unable to read the configuration file.</p>
            <p><strong>autostream will now try to reboot.</strong></p>
            <p>Please check back in a few minutes. If the system does not recover,
            please power-cycle autostream and try again. If the problem persists,
            please replace the SD card and reinstall autostream.</p>
          </body>
        """)

        # Best-effort response; never prevent reboot.
        try:
            handler.send_response(500)
            handler.send_header("Content-Type", "text/html; charset=utf-8")
            body_bytes = body.encode("utf-8")
            handler.send_header("Content-Length", str(len(body_bytes)))
            handler.end_headers()
            handler.wfile.write(body_bytes)
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

    try:
        is_playing = any_monitor_capturing()
    except Exception:
        is_playing = False

    try:
        input_levels = get_monitor_levels_dbfs()
    except Exception:
        input_levels = []

    playback_snapshot = get_playback_snapshot()
    stylus_banner_text = playback_snapshot.banner_text or ""
    setup_button_style = (
        "flex:1;text-align:center;background:#c00000;color:#fff;border-color:#c00000;"
        if stylus_banner_text else
        "flex:1;text-align:center;"
    )
    status_text = _status_text_for_home(is_playing, input_levels)
    status_class = "playing" if is_playing else "waiting"

    input_levels_html = ""
    for lv in input_levels:
        label = html.escape(str(lv.get("label", "Input ")))
        dbfs = float(lv.get("dbfs", -90.0))
        detected_hz = float(lv.get("detected_hz", 0.0)) / 1000.0
        hz_txt = f" ({detected_hz:.3f} kHz)" if detected_hz > 0 else ""
        extra_cls = " input-level-pill-active" if lv.get("is_above_threshold") else ""
        input_levels_html += (
            f'<span class="pill status-pill input-level-pill{extra_cls}">'
            f'{label}{hz_txt}: {dbfs:.1f} dB</span>'
        )

    outputs_result = list_outputs(owntone_base_url, timeout=3)
    outputs = list(outputs_result.outputs) if outputs_result.ok else []
    if not outputs_result.ok:
        error = error or (
            outputs_result.error
            or outputs_result.detail
            or f"Could not reach Owntone at {owntone_base_url}"
        )

    # Keep the configured default output at the top; otherwise use a stable
    # alphabetical order regardless of whether an output is currently enabled.
    outputs = sorted(
        outputs,
        key=lambda output: (
            0 if (output.name == default_output_name) else 1,
            str(output.name or "").casefold(),
        ),
    )

    outputs_html = ""
    for out in outputs:
        out_id = str(out.id or "").strip()
        if not out_id:
            continue
        name = out.name or f"Output {out_id}"
        selected = bool(out.selected)
        if str(name).strip().casefold() in hidden_output_names and not selected and name != default_output_name:
            continue

        volume = max(0, min(100, int(out.volume_percent)))
        safe_name = html.escape(str(name))
        default_badge = '<span class="output-card-default">Default</span>' if name == default_output_name else ""
        state_text = "On" if selected else "Off"
        state_cls = "on" if selected else "off"
        card_state_cls = "output-card-on" if selected else "output-card-off"
        is_default = "1" if name == default_output_name else "0"
        outputs_html += f"""
          <div class="output-card {card_state_cls}" id="output_card_{out_id}" data-output-id="{out_id}" data-is-default="{is_default}">
            <div class="output-card-head">
              <div class="output-card-meta">
                <div class="output-card-name">{safe_name}</div>
                {default_badge}
                <span class="output-state-chip {state_cls}" id="output_state_{out_id}">{state_text}</span>
              </div>
              <label class="output-toggle" onclick="event.stopPropagation();">
                <input type="checkbox" id="output_enabled_{out_id}"{' checked' if selected else ''} onchange="onToggleOutput('{out_id}')">
                <span class="switch" aria-hidden="true"></span>
              </label>
            </div>
            <div class="output-slider-wrap" id="output_slider_wrap_{out_id}" onclick="event.stopPropagation();"{' hidden' if not selected else ''}>
              <div class="slider-header"><span>Volume:</span><span id="vol_label_{out_id}" data-volume-label-for="{out_id}"></span></div>
              <input type="range" id="vol_slider_{out_id}" min="0" max="100" step="1" value="{volume}" oninput="updateVolumeLabel('{out_id}', this.value)" onchange="onVolumeChange('{out_id}', this.value)">
            </div>
          </div>
        """

    lic_html, lic_spacer = build_top_banner_html(flash_msg=flash_msg, flash_type=flash_type)
    csrf_token = getattr(handler, "_csrf_token", None) or auth.get_csrf_token(handler.headers) or ""
    preset_volume = max(0, min(100, int(parsed.owntone.volume_percent or 20)))
    csrf_meta = f"<meta name='csrf-token' content='{html.escape(csrf_token)}'><script>window.__CSRF='{html.escape(csrf_token)}';window.__PRESET_VOLUME={preset_volume};</script>"

    html_body = textwrap.dedent(f"""\
      <!DOCTYPE html><html><head><meta charset="utf-8">{VIEWPORT_META}
      <title>autostream</title><style>{STYLE_CSS}\n{PIN_MODAL_CSS}</style>{csrf_meta}

      <script>
        function normalizeVolume(v){{
          const n = Number(v);
          if (!Number.isFinite(n)) return 0;
          return Math.max(0, Math.min(100, Math.round(n)));
        }}
        function formatVolume(v){{
          return String(normalizeVolume(v)) + '%';
        }}
        function updateVolumeLabel(id,v){{var s=document.getElementById('vol_label_'+id);if(s)s.textContent=formatVolume(v);}}
        function reorderOutputCards(){{
          const list = document.getElementById('outputs-list');
          if (!list) return;
          const cards = Array.from(list.querySelectorAll('.output-card'));
          cards.sort((a, b) => {{
            const da = a.getAttribute('data-is-default') === '1' ? 1 : 0;
            const db = b.getAttribute('data-is-default') === '1' ? 1 : 0;
            if (db !== da) return db - da;
            const la = a.querySelector('.output-card-name');
            const lb = b.querySelector('.output-card-name');
            const na = ((la && la.textContent) || '').trim().toLowerCase();
            const nb = ((lb && lb.textContent) || '').trim().toLowerCase();
            return na.localeCompare(nb);
          }});
          cards.forEach(card => list.appendChild(card));
        }}
        function updateOutputStateVisual(id, selected){{
          const chip = document.getElementById('output_state_' + id);
          const card = document.getElementById('output_card_' + id);
          const wrap = document.getElementById('output_slider_wrap_' + id);
          if (chip) {{
            chip.textContent = selected ? 'On' : 'Off';
            chip.classList.toggle('on', !!selected);
            chip.classList.toggle('off', !selected);
          }}
          if (card) {{
            card.classList.toggle('output-card-on', !!selected);
            card.classList.toggle('output-card-off', !selected);
          }}
          if (wrap) {{
            wrap.hidden = !selected;
          }}
        }}

        function showPinModal(outputName){{
          return new Promise((resolve) => {{
            const m = document.getElementById('pinModal');
            const title = document.getElementById('pinModalTitle');
            const input = document.getElementById('pinModalInput');
            const btnOk = document.getElementById('pinModalOk');
            const btnCancel = document.getElementById('pinModalCancel');
            if (!m || !input || !btnOk || !btnCancel) {{
              // Fallback to native prompt if our modal is missing for any reason.
              const v = window.prompt('Enter PIN shown on your device' + (outputName ? ' ('+outputName+')' : '') + ':', '');
              resolve(v && String(v).trim() ? String(v).trim() : null);
              return;
            }}
            title.textContent = outputName ? ('Enter PIN for ' + outputName) : 'Enter PIN';
            input.value = '';
            m.classList.add('show');
            // iOS: defer focus slightly so the keyboard reliably appears.
            setTimeout(() => {{ try {{ input.focus(); }} catch (e) {{}} }}, 60);

            const cleanup = (val) => {{
              m.classList.remove('show');
              btnOk.onclick = null;
              btnCancel.onclick = null;
              input.onkeydown = null;
              resolve(val);
            }};
            btnCancel.onclick = () => cleanup(null);
            btnOk.onclick = () => {{
              const v = (input.value || '').trim();
              cleanup(v ? v : null);
            }};
            input.onkeydown = (ev) => {{
              if (ev.key === 'Enter') {{ ev.preventDefault(); btnOk.click(); }}
              else if (ev.key === 'Escape') {{ ev.preventDefault(); btnCancel.click(); }}
            }};
          }});
        }}

        async function postOutputUpdate(id, selected, volume){{
          const r = await fetch('/api/output',{{
            method:'POST',
            credentials:'same-origin',
            signal: AbortSignal.timeout(5000),
            headers:{{
              'Content-Type':'application/json',
              'X-CSRF-Token':window.__CSRF||''
            }},
            body:JSON.stringify({{
              id:id,
              selected:!!selected,
              volume:parseInt(volume||0,10)||0,
              csrf_token: window.__CSRF||''
            }})
          }});
          if (handleHomeSessionRejected(r)) return {{ ok:false, _http:r.status, session_rejected:true }};
          // Server replies JSON for this endpoint (including failures)
          let j = null;
          try {{ j = await r.json(); }} catch (e) {{ j = {{ ok: r.ok }}; }}
          j._http = r.status;
          return j;
        }}

        function handleHomeSessionRejected(response){{
          const status = Number(response && response.status);
          if (status !== 401 && status !== 403) return false;
          if (window.__HOME_SESSION_REFRESHING) return true;
          window.__HOME_SESSION_REFRESHING = true;
          window.location.reload();
          return true;
        }}

        async function postPinOnly(id, pin) {{
          const r = await fetch('/api/output', {{
            method:'POST',
            credentials:'same-origin',
            signal: AbortSignal.timeout(5000),
            headers:{{
              'Content-Type':'application/json',
              'X-CSRF-Token':window.__CSRF||''
            }},
            body:JSON.stringify({{
              op:'pin',
              id:id,
              pin: String(pin||'').trim(),
              csrf_token: window.__CSRF||''
            }})
          }});
          if (handleHomeSessionRejected(r)) return {{ ok:false, _http:r.status, session_rejected:true }};
          let j = null;
          try {{ j = await r.json(); }} catch (e) {{ j = {{ ok: r.ok }}; }}
          j._http = r.status;
          return j;
        }}

        async function sendUpdate(id){{
          const c=document.getElementById('output_enabled_'+id), s=document.getElementById('vol_slider_'+id);
          const selected = c?c.checked:false;
          const volume = s?normalizeVolume(parseInt(s.value,10)):0;
          window.__PENDING_OUTPUTS.add(String(id));
          try {{
            let j = null;
            try {{
              j = await postOutputUpdate(id, selected, volume);
            }} catch (e) {{
              // Network error or 5 s abort -> let periodic refresh reconcile UI.
              return;
            }}

            // If OwnTone requires a PIN, prompt and do PIN-only verification.
            // On wrong PIN (still 400), re-prompt; on success, retry the original enable.
            if (selected && j && j.pin_required) {{
              // Temporarily revert the toggle until fully enabled.
              if (c) {{
                c.checked = false;
                updateOutputStateVisual(String(id), false);
              }}

              let nm = '';
              try {{
                const card = c ? c.closest('.output-card') : null;
                const label = card ? card.querySelector('.output-card-name') : null;
                nm = label ? (label.textContent || '').trim() : '';
              }} catch (e) {{}}

              while (true) {{
                const pin = await showPinModal(nm || 'this speaker');
                if (!pin) return; // user cancelled

                let jpin = null;
                try {{
                  jpin = await postPinOnly(id, pin);
                }} catch (e) {{
                  // treat as failure; keep disabled
                  if (c) {{
                    c.checked = false;
                    updateOutputStateVisual(String(id), false);
                  }}
                  return;
                }}

                if (jpin && jpin.ok) {{
                  // PIN accepted -> retry the original enable request (without pin)
                  try {{
                    const jen = await postOutputUpdate(id, true, volume);
                    if (jen && jen.ok) {{
                      if (c) {{
                        c.checked = true;
                        updateOutputStateVisual(String(id), true);
                      }}
                      return;
                    }}
                    // If it still asks for PIN, loop again.
                    if (jen && jen.pin_required) {{
                      if (c) {{
                        c.checked = false;
                        updateOutputStateVisual(String(id), false);
                      }}
                      continue;
                    }}
                  }} catch (e) {{
                    if (c) {{
                      c.checked = false;
                      updateOutputStateVisual(String(id), false);
                    }}
                  }}
                  return;
                }}

                // Wrong PIN -> re-prompt
                if (jpin && jpin.pin_invalid) {{
                  continue;
                }}

                // Other error -> stop
                return;
              }}
            }}
          }} finally {{
            window.__PENDING_OUTPUTS.delete(String(id));
          }}
        }}

        function onToggleOutput(id){{
          const cb = document.getElementById('output_enabled_' + id);
          if (cb) updateOutputStateVisual(String(id), !!cb.checked);
          if (cb && cb.checked) {{
            const sl = document.getElementById('vol_slider_' + id);
            if (sl) {{ sl.value = String(window.__PRESET_VOLUME || 20); updateVolumeLabel(id, sl.value); }}
          }}
          reorderOutputCards();
          sendUpdate(id);
        }}
        function onVolumeChange(id,v){{
          updateVolumeLabel(id,v);
          sendUpdate(id);
        }}
        function escapeHtml(s){{
          return String(s||'').replace(/[&<>"']/g, function(ch){{
            return {{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[ch] || ch;
          }});
        }}
        function renderInputLevels(levels){{
          var row = document.getElementById('input-level-row');
          var wrap = document.getElementById('home-input-level-wrap');
          if(!row) return;
          if(!Array.isArray(levels) || levels.length===0){{
            row.hidden = true;
            if (wrap) wrap.hidden = true;
            row.innerHTML = '';
            return;
          }}
          row.hidden = false;
          if (wrap) wrap.hidden = false;
          row.innerHTML = levels.map(function(lv){{
            var label = escapeHtml(String((lv && lv.label) || 'Input '));
            var db = Number(lv && lv.dbfs);
            var hz = Number(lv && lv.detected_hz);
            var txt = Number.isFinite(db) ? db.toFixed(1) + ' dB' : '-- dB';
            var hzTxt = '';
            if (Number.isFinite(hz) && hz > 0) hzTxt = ' (' + (hz / 1000).toFixed(3) + ' kHz)';
            var cls = (lv && lv.is_above_threshold) ? ' input-level-pill-active' : '';
            return '<span class="pill status-pill input-level-pill' + cls + '">' + label + hzTxt + ': ' + txt + '</span>';
          }}).join('');
        }}
        function refreshStatus(){{
          fetch('/api/status').then(r=>r.json()).then(d=>{{
            var p=document.getElementById('status-pill');if(!p)return;
            p.textContent=d.status_text; p.classList.remove('status-playing','status-waiting');
            p.classList.add('status-'+d.status_class);
            renderInputLevels(d.input_levels || []);
            var warn=document.getElementById('stylus-warning-banner');
            var setupBtn=document.getElementById('setup-pill-btn');
            if (warn) {{
              var txt = String((d && d.playback_banner_text) || '').trim();
              warn.hidden = !txt;
              warn.textContent = txt;
              if (setupBtn) {{
                if (txt) {{
                  setupBtn.style.background = '#c00000';
                  setupBtn.style.color = '#fff';
                  setupBtn.style.borderColor = '#c00000';
                }} else {{
                  setupBtn.style.background = '';
                  setupBtn.style.color = '';
                  setupBtn.style.borderColor = '';
                }}
              }}
            }}
          }});
        }}
        function isActiveControl(el) {{
          return el && document.activeElement === el;
        }}

        async function refreshOutputsState() {{
          let j = null;
          try {{
            const r = await fetch("/api/owntone/outputs_state", {{ cache: "no-store" }});
            j = await r.json();
          }} catch (e) {{
            return;
          }}
          if (!j || !j.ok || !Array.isArray(j.outputs)) return;

          for (const o of j.outputs) {{
            const id = String(o.id);

            // Skip outputs with a request in flight; sendUpdate's finally block
            // will remove the id once the request settles (or aborts after 5 s).
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
        }}

        window.addEventListener('DOMContentLoaded',function(){{
          window.__PENDING_OUTPUTS = new Set();
          document.querySelectorAll('[data-volume-label-for]').forEach(s=>{{
            var i=s.getAttribute('data-volume-label-for'), sl=document.getElementById('vol_slider_'+i);
            if(sl)updateVolumeLabel(i, sl.value);
            var cb=document.getElementById('output_enabled_'+i);
            if(cb) updateOutputStateVisual(String(i), !!cb.checked);
          }});
          reorderOutputCards();
          setInterval(() => {{ refreshStatus(); refreshOutputsState(); }}, 2000);
          refreshStatus();
          refreshOutputsState();
        }});
      </script></head>
      <body>{lic_html}{lic_spacer}
      <div id="pinModal" role="dialog" aria-modal="true" aria-labelledby="pinModalTitle">
        <div class="panel">
          <div class="hdr" id="pinModalTitle">Enter PIN</div>
          <div class="bd">
            <p>Enter the PIN shown on your Apple TV (or other AirPlay device) to enable playback.</p>
            <input id="pinModalInput" inputmode="numeric" autocomplete="one-time-code" placeholder="PIN" />
          </div>
          <div class="ft">
            <button type="button" class="btn cancel" id="pinModalCancel">Cancel</button>
            <button type="button" class="btn ok" id="pinModalOk">OK</button>
          </div>
        </div>
      </div>
      <div class="container">
      <div class="airplay-masthead">
        <div class="airplay-brand">{BANNER_HTML}</div>
      </div>
      <div class="airplay-top-controls">
        <div class="airplay-refresh-wrap">
          <button type="button"
                  class="pill-btn"
                  onclick="location.reload();"
                  title="Reload page to refresh speakers">
            ↻ Refresh
          </button>
        </div>
        <span id="status-pill"
              class="pill status-pill status-{status_class}">
          {html.escape(status_text)}
        </span>
      </div>
      <div id="stylus-warning-banner" {'hidden' if not stylus_banner_text else ''} style="margin:0.85rem 0 0.35rem;padding:0.8rem 1rem;border-radius:8px;background:#c00000;color:#fff;font-weight:700;text-align:center;">
        {html.escape(stylus_banner_text)}
      </div>
      {f"<p style='color:red;'>{html.escape(error)}</p>" if error else ""}
      {A2HS_PROMPT_HTML}
      <div id="outputs-list">{outputs_html}</div>
      <div class="home-input-level-wrap" id="home-input-level-wrap" {'hidden' if not input_levels_html else ''}>
        <div id="input-level-row" class="pill-row input-level-row">
          {input_levels_html}
        </div>
      </div>
      <br />
      <p class="actions" style="margin-top:1rem;display:flex;gap:0.75rem;">
        <a href="/about" class="pill-btn" style="flex:1;text-align:center;">About</a>
        <a href="/setup" id="setup-pill-btn" class="pill-btn" style="{setup_button_style}">Setup</a>
      </p>
      <p style="margin-top:0.25rem; text-align:center;">
        <small>Copyright &copy; Lo-tech Systems Limited.<br><strong>lo-tech.co.uk/autostream</strong></small>
      </p></div>{A2HS_SCRIPT}</body></html>
    """)
    body_bytes = html_body.encode("utf-8")
    try:
        handler.send_response(200)
        handler.send_header("Content-Type", "text/html; charset=utf-8")
        handler.send_header("Content-Length", str(len(body_bytes)))
        handler.end_headers()
        handler.wfile.write(body_bytes)
    except (BrokenPipeError, ConnectionResetError):
        logging.info("Client disconnected before airplay page response completed.")
    except Exception:
        logging.exception("Failed sending airplay page response.")
