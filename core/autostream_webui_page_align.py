#!/usr/bin/env python3
"""autostream_webui_page_align.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Page renderer and JSON endpoints for the "Align outputs" calibration
feature (see autostream_align.py for the orchestrator that actually runs
the tone-burst cycle).

Responsibilities:
  - GET  /align              -- explains the feature, Start/Abort controls,
                                 status polling, review table once a result
                                 has landed.
  - GET  /align/result       -- handoff from the (separately hosted) phone
                                 measurement page; parses params, stops the
                                 run, redirects back to /align to show the
                                 review table (kept server-side on the
                                 orchestrator, not in the URL).
  - POST /api/align/start    -- start a run
  - POST /api/align/abort    -- cancel a run in progress
  - GET  /api/align/status   -- poll target for the /align page
  - POST /api/align/apply    -- apply proposed offsets from a landed result
  - POST /api/align/discard  -- discard a landed result without applying
"""

from __future__ import annotations

import html
import json
import logging

from autostream_align import parse_result_entries
from autostream_webui_api import apply_output_offset, send_json
from autostream_webui_assets import COMMON_MODAL_CSS, INFO_MODAL_HTML, INFO_MODAL_SCRIPT
from autostream_webui_common import (
    CSRF_RECOVERY_SCRIPT,
    _config_snapshot,
    build_page_html,
    build_top_banner_html,
)
from autostream_webui_state import WebUIState

_log = logging.getLogger(__name__)

_OFFSET_CLAMP_MS = 2000


# -----------------------------------------------------------------------------
# /align -- explainer + controls + review table
# -----------------------------------------------------------------------------

def send_align_page(handler, state: WebUIState) -> None:
    parsed = None
    try:
        parsed = _config_snapshot(state)
    except Exception:
        parsed = None
    dark_mode = parsed.webui.dark_mode if parsed else False

    csrf_token = getattr(handler, "_csrf_token", None) or ""
    lic_html, lic_spacer = build_top_banner_html()

    review_html = _render_review_section(state)
    has_pending_result = bool(review_html)

    # While a measurement result is pending review, only the review/summary
    # flow renders -- the outputs-selection + calibration-volume + Start
    # section would let the user kick off a new run and lose the one
    # waiting to be applied/discarded.
    if has_pending_result:
        selection_html = ""
    else:
        outputs_html = _render_outputs_section(state)
        selection_html = (
            f"{outputs_html}"
            "<div class='align-controls' style='margin:1rem 0;'>"
            "<button type='button' class='pill-btn' id='alignStartBtn' onclick='alignStart()'>Start</button>"
            "<button type='button' class='pill-btn small' id='alignAbortBtn' onclick='alignAbort()' style='display:none;margin-left:0.5rem;'>Abort</button>"
            "</div>"
            "<div id='alignStatus' class='helptext' style='margin:1rem 0;text-align:left;'></div>"
            "<div id='alignLaunch' style='display:none;margin:1rem 0;'>"
            "<p>Open this link on your phone:</p>"
            "<a id='alignLaunchLink' class='pill-btn small' href='#' target='_blank' rel='noopener'>Open calibration page</a>"
            "</div>"
        )

    body_html = (
        "<div class='align-page'>"
        "<h1>Speaker Synchronisation</h1>"
        "<p class='helptext' style='text-align:left;margin-top:0;'>"
        "This plays a short test tone through each selected AirPlay output in "
        "turn. Open the link below on your phone, hold it near your speakers, "
        "and it will measure and hand back timing offsets to line them up."
        "</p>"
        "<button type='button' class='pill-btn small' style='width:100%;margin-top:0.5rem;' "
        "onclick='alignShowPrivacy()'>Privacy</button>"
        f"{selection_html}"
        f"<div id='alignReview'>{review_html}</div>"
        "</div>"
    )

    head_extra = (
        f"<script>window.__CSRF='{html.escape(csrf_token)}';</script>\n"
        + CSRF_RECOVERY_SCRIPT
        + INFO_MODAL_SCRIPT
        + _ALIGN_SCRIPT
    )

    html_body = build_page_html(
        "Speaker Synchronisation",
        body_html,
        extra_css=f"{COMMON_MODAL_CSS}\n{_ALIGN_EXTRA_CSS}",
        head_extra=head_extra,
        body_prefix=INFO_MODAL_HTML,
        lic_html=lic_html,
        lic_spacer=lic_spacer,
        active_tab="setup",
        dark_mode=dark_mode,
    )
    body_bytes = html_body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body_bytes)))
    handler.end_headers()
    handler.wfile.write(body_bytes)


def _render_outputs_section(state: WebUIState) -> str:
    """Server-rendered checkbox list of available outputs plus the
    calibration-volume slider. Fetches outputs the same way AlignRun.start
    does -- best-effort, never fails the page if the backend is down."""
    try:
        base_url = _config_snapshot(state).owntone.base_url
    except Exception:
        base_url = ""

    outputs = []
    if base_url:
        try:
            import autostream_player_service as player_service
            result = player_service.list_outputs(base_url, timeout=3)
            if result.ok:
                outputs = list(result.outputs)
        except Exception:
            _log.debug("align page: could not list outputs", exc_info=True)

    if not outputs:
        return (
            "<h2>Select the outputs to calibrate</h2>"
            "<p class='helptext' style='text-align:left;'>No outputs available.</p>"
        )

    rows = []
    for out in outputs:
        selected = bool(getattr(out, "selected", False))
        checked = " checked" if selected else ""
        card_state = "output-card-on" if selected else "output-card-off"
        rows.append(
            f"<div class='output-card {card_state}'>"
            "<div class='output-card-head'>"
            "<div class='output-card-meta'>"
            f"<div class='output-card-name'>{html.escape(out.name)}</div>"
            "</div>"
            "<label class='output-toggle'>"
            f"<input type='checkbox' class='align-output-checkbox' value='{html.escape(out.id)}'{checked}"
            " onchange=\"this.closest('.output-card').classList.toggle('output-card-on',this.checked);"
            "this.closest('.output-card').classList.toggle('output-card-off',!this.checked);\">"
            "<span class='switch'></span>"
            "</label>"
            "</div>"
            "</div>"
        )

    return (
        "<h2>Select the outputs to calibrate</h2>"
        f"<div id='alignOutputs'>{''.join(rows)}</div>"
        "<div class='output-slider-wrap' style='margin:1rem 0;'>"
        "<div class='slider-header'><span>Calibration volume</span>"
        "<span id='alignVolumeVal' class='slider-value'>50</span></div>"
        "<input type='range' id='alignVolume' min='1' max='100' value='50' "
        "oninput=\"document.getElementById('alignVolumeVal').textContent=this.value;\">"
        "</div>"
    )


def _render_review_section(state: WebUIState) -> str:
    run = getattr(state, "align_run", None)
    if run is None:
        return ""
    result = run.pending_result()
    if result is None:
        return ""

    from autostream_align import AlignArrival

    snapshots = {s.id: s for s in run.snapshots()}
    arrivals = {a.output_id: a for a in result.arrivals}
    if result.ref_output_id not in arrivals:
        # The phone page's data list need not repeat the reference output
        # itself -- its delta/spread relative to itself is zero by definition.
        arrivals[result.ref_output_id] = AlignArrival(
            output_id=result.ref_output_id, delta_ms=0, spread_ms=0
        )

    rows = []
    for oid, snap in snapshots.items():
        arrival = arrivals.get(oid)
        if arrival is None:
            continue
        proposed = max(-_OFFSET_CLAMP_MS, min(_OFFSET_CLAMP_MS, snap.stored_offset_ms - arrival.delta_ms))
        warn = arrival.spread_ms > 40
        rows.append(
            "<tr>"
            f"<td>{html.escape(snap.name)}</td>"
            f"<td>{arrival.delta_ms} ms</td>"
            f"<td{' class=\"align-warn\"' if warn else ''}>{arrival.spread_ms} ms"
            + (" &mdash; noisy measurement" if warn else "")
            + "</td>"
            f"<td>{snap.stored_offset_ms} ms</td>"
            f"<td>{proposed} ms</td>"
            f"<td><input type='hidden' class='align-offset-id' value='{html.escape(oid)}'>"
            f"<input type='hidden' class='align-offset-val' value='{proposed}'></td>"
            "</tr>"
        )

    return (
        "<div id='align-review-block'>"
        "<h2>Measurement result</h2>"
        "<table class='align-review-table'>"
        "<thead><tr><th>Output</th><th>Measured delta</th><th>Spread</th>"
        "<th>Current offset</th><th>Proposed offset</th><th></th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
        "<p class='helptext'>Nothing has been saved yet — Apply writes the"
        " proposed offsets to the outputs.</p>"
        "<div style='margin-top:1rem;'>"
        "<button type='button' class='pill-btn' onclick='alignApply()'>Apply</button>"
        "<button type='button' class='pill-btn small' onclick='alignDiscard()' style='margin-left:0.5rem;'>Discard</button>"
        "</div>"
        "<div class='helptext' id='align-apply-status'></div>"
        "</div>"
    )


# Scoped styling for elements unique to this page (the review/result table
# and its noisy-spread warning cell). Everything else on the page reuses
# sitewide idioms already defined in STYLE_CSS (build_page_html's shared
# stylesheet) -- .output-card / .output-toggle / .switch for the output
# list, .slider-header / input[type=range] for the calibration-volume
# slider, .pill-btn for buttons, .helptext for secondary copy -- so no
# fonts or colours are declared here outside the CSS custom properties the
# rest of the site already uses.
_ALIGN_EXTRA_CSS = """
.align-review-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 0.5rem;
  font-size: 0.92rem;
}

.align-review-table th,
.align-review-table td {
  text-align: left;
  padding: 0.5rem 0.6rem;
  border-bottom: 1px solid var(--color-border);
}

.align-review-table th {
  color: var(--color-text-secondary);
  font-weight: 600;
  font-size: 0.82rem;
  text-transform: uppercase;
  letter-spacing: 0.02em;
}

.align-review-table tbody tr:last-child td {
  border-bottom: none;
}

.align-warn {
  color: var(--color-status-warning);
  font-weight: 600;
}
"""


_ALIGN_SCRIPT = """
<script>
(function(){
function alignPoll(){
  fetch('/api/align/status',{cache:'no-store'}).then(function(r){return r.json();}).then(function(d){
    var startBtn=document.getElementById('alignStartBtn');
    var abortBtn=document.getElementById('alignAbortBtn');
    var statusEl=document.getElementById('alignStatus');
    var launchEl=document.getElementById('alignLaunch');
    var running=(d.state==='running'||d.state==='finishing');
    if(startBtn)startBtn.disabled=running;
    if(abortBtn)abortBtn.style.display=running?'':'none';
    if(statusEl){
      if(running){
        var out=d.current_output_name?(' — playing on '+d.current_output_name):'';
        statusEl.textContent='Calibrating'+out+' (cycle '+(d.cycle_count||0)+')';
      } else if(d.last_error){
        statusEl.textContent='Stopped: '+d.last_error;
      } else {
        statusEl.textContent='';
      }
    }
    if(launchEl){
      if(running&&d.launch_url){
        launchEl.style.display='';
        var link=document.getElementById('alignLaunchLink');
        if(link){link.href=d.launch_url;}
      } else {
        launchEl.style.display='none';
      }
    }
  }).catch(function(){});
}
window.alignStart=function(){
  var startBtn=document.getElementById('alignStartBtn');
  var statusEl=document.getElementById('alignStatus');
  var outputIds=[];
  document.querySelectorAll('.align-output-checkbox:checked').forEach(function(cb){outputIds.push(cb.value);});
  var volumeEl=document.getElementById('alignVolume');
  var volume=volumeEl?parseInt(volumeEl.value,10):50;
  var originalLabel=startBtn?startBtn.textContent:'Start';
  if(startBtn){startBtn.disabled=true;startBtn.textContent='Starting…';}
  if(statusEl)statusEl.textContent='';
  fetch('/api/align/start',{
    method:'POST',credentials:'same-origin',
    headers:{'Content-Type':'application/json','X-CSRF-Token':window.__CSRF||''},
    body:JSON.stringify({output_ids:outputIds,volume:volume})
  }).then(function(r){return r.json();}).then(function(d){
    if(!d.ok||!d.launch_url){
      if(startBtn){startBtn.disabled=false;startBtn.textContent=originalLabel;}
      if(statusEl)statusEl.textContent='Could not start: '+(d.error||'error');
      return;
    }
    window.location.href=d.launch_url;
  }).catch(function(){
    if(startBtn){startBtn.disabled=false;startBtn.textContent=originalLabel;}
    if(statusEl)statusEl.textContent='Could not start: network error';
  });
};
window.alignAbort=function(){
  fetch('/api/align/abort',{
    method:'POST',credentials:'same-origin',
    headers:{'Content-Type':'application/json','X-CSRF-Token':window.__CSRF||''},
    body:JSON.stringify({})
  }).then(function(){alignPoll();}).catch(function(){});
};
window.alignApply=function(){
  var offsets={};
  var summary=[];
  document.querySelectorAll('.align-review-table tbody tr').forEach(function(tr){
    var id=tr.querySelector('.align-offset-id');
    var val=tr.querySelector('.align-offset-val');
    if(id&&val){
      offsets[id.value]=parseInt(val.value,10)||0;
      summary.push({
        name:tr.cells[0]?tr.cells[0].textContent:id.value,
        current:tr.cells[3]?tr.cells[3].textContent:'',
        proposed:tr.cells[4]?tr.cells[4].textContent:''
      });
    }
  });
  fetch('/api/align/apply',{
    method:'POST',credentials:'same-origin',
    headers:{'Content-Type':'application/json','X-CSRF-Token':window.__CSRF||''},
    body:JSON.stringify({offsets:offsets})
  }).then(function(r){return r.json();}).then(function(d){
    if(!d||!d.ok){
      var st=document.getElementById('align-apply-status');
      if(st)st.textContent='Could not apply: '+((d&&d.error)||'error');
      return;
    }
    var rows=summary.map(function(s){
      return '<tr><td>'+s.name+'</td><td>'+s.current+'</td><td><strong>'+s.proposed+'</strong></td></tr>';
    }).join('');
    var block=document.getElementById('align-review-block');
    if(block){
      block.innerHTML='<h2>Offsets applied</h2>'
        +'<table class="align-review-table">'
        +'<thead><tr><th>Output</th><th>Previous</th><th>New</th></tr></thead>'
        +'<tbody>'+rows+'</tbody></table>'
        +'<p class="helptext">The new offsets are live on the outputs now.</p>'
        +'<div style="margin-top:1rem;">'
        +'<a class="pill-btn" href="/owntone-setup" style="width:100%;display:block;margin-top:0.5rem;">Open Output Settings</a>'
        +'<a class="pill-btn small" href="/align" style="width:100%;display:block;margin-top:0.5rem;">Run Alignment Again</a>'
        +'</div>';
    }
  }).catch(function(){
    var st=document.getElementById('align-apply-status');
    if(st)st.textContent='Could not apply: network error';
  });
};
window.alignShowPrivacy=function(){
  var msg='<p>The measurement page is served from lo-tech.co.uk because browsers '
    +'only allow microphone access on a secure (HTTPS) site.</p>'
    +'<p>All listening and analysis happens on your phone itself — no audio is '
    +'ever recorded or sent anywhere.</p>'
    +'<p>Nothing at all is sent to lo-tech.co.uk. Only the final timing numbers '
    +'are handed back to this device.</p>';
  var btnOk=document.getElementById('infoModalOk');
  if(btnOk)btnOk.textContent='Continue';
  showInfoModal('Privacy',msg,true);
};
window.alignDiscard=function(){
  fetch('/api/align/discard',{
    method:'POST',credentials:'same-origin',
    headers:{'Content-Type':'application/json','X-CSRF-Token':window.__CSRF||''},
    body:JSON.stringify({})
  }).then(function(){window.location.href='/align';}).catch(function(){});
};
document.addEventListener('DOMContentLoaded',function(){
  alignPoll();
  setInterval(alignPoll,2000);
});
}());
</script>
"""


# -----------------------------------------------------------------------------
# GET /align/result -- handoff from the phone measurement page
# -----------------------------------------------------------------------------

def send_align_result_get(handler, state: WebUIState, query: dict) -> None:
    """Parse the ?v=&ref=&data= handoff, stop the run, and render the review
    page (table of outputs with proposed offsets, Apply/Discard)."""
    from autostream_align import AlignResult

    run = getattr(state, "align_run", None)
    version = (query.get("v") or [""])[0]
    ref = (query.get("ref") or [""])[0].strip()
    data_raw = (query.get("data") or [""])[0]

    if run is not None and version == "1" and ref:
        arrivals = parse_result_entries(data_raw)
        run.finish(AlignResult(ref_output_id=ref, arrivals=tuple(arrivals)))
    elif run is not None:
        # Malformed handoff -- still stop the run so it doesn't run to
        # timeout, but don't fabricate a result to show.
        run.finish(None)

    send_align_page(handler, state)


# -----------------------------------------------------------------------------
# JSON endpoints
# -----------------------------------------------------------------------------

def send_align_start_json(handler, state: WebUIState, body: str) -> None:
    run = getattr(state, "align_run", None)
    if run is None:
        send_json(handler, 200, {"ok": False, "error": "Calibration is unavailable"})
        return

    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    output_ids = payload.get("output_ids")
    if (
        not isinstance(output_ids, list)
        or len(output_ids) < 2
        or not all(isinstance(oid, str) and oid.strip() for oid in output_ids)
    ):
        send_json(handler, 400, {"ok": False, "error": "output_ids must list at least two outputs"})
        return

    volume = payload.get("volume")
    if isinstance(volume, bool) or not isinstance(volume, int) or not (1 <= volume <= 100):
        send_json(handler, 400, {"ok": False, "error": "volume must be a whole number between 1 and 100"})
        return

    try:
        base_url = _config_snapshot(state).owntone.base_url
    except Exception:
        base_url = ""

    # The appliance is served over plain HTTP on the LAN (nginx reverse
    # proxy in front, no TLS termination here).
    host = handler.headers.get("Host") or "localhost"
    ret_url = f"http://{host}/align/result"

    ok, result = run.start(
        base_url=base_url, ret_url=ret_url, output_ids=output_ids, volume_percent=volume
    )
    if not ok:
        send_json(handler, 200, {"ok": False, "error": result})
        return
    send_json(handler, 200, {"ok": True, "launch_url": result})


def send_align_abort_json(handler, state: WebUIState) -> None:
    run = getattr(state, "align_run", None)
    if run is not None:
        run.abort()
    send_json(handler, 200, {"ok": True})


def send_align_status_json(handler, state: WebUIState) -> None:
    run = getattr(state, "align_run", None)
    if run is None:
        send_json(handler, 200, {
            "state": "idle", "current_output_id": None, "current_output_name": None,
            "cycle_count": 0, "seconds_remaining": None, "launch_url": "",
            "last_error": "", "has_pending_result": False,
        })
        return
    send_json(handler, 200, run.status())


def send_align_apply_json(handler, state: WebUIState, body: str) -> None:
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
        return

    offsets = payload.get("offsets")
    if not isinstance(offsets, dict) or not offsets:
        send_json(handler, 400, {"ok": False, "error": "offsets required"})
        return

    applied = {}
    for output_id, raw_offset in offsets.items():
        result = apply_output_offset(state, output_id, raw_offset)
        if result.get("ok"):
            applied[result["output_id"]] = result["offset_ms"]

    run = getattr(state, "align_run", None)
    if run is not None:
        run.discard_result()

    send_json(handler, 200, {"ok": True, "applied": applied})


def send_align_discard_json(handler, state: WebUIState) -> None:
    run = getattr(state, "align_run", None)
    if run is not None:
        run.discard_result()
    send_json(handler, 200, {"ok": True})
