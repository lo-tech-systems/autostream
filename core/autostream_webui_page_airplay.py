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
from autostream_config import parse_config
from autostream_core import (
    get_monitor_levels_dbfs,
    get_playback_snapshot,
)
from autostream_player_service import get_setting, list_outputs
from autostream_players import SETTING_START_BUFFER_MS, SETTING_START_BUFFER_MS_DEFAULT
from autostream_rpi import get_appliance_id
from autostream_sysutils import get_system_hostname, reboot_system
from autostream_webui_assets import (
    A2HS_PROMPT_HTML,
    A2HS_SCRIPT,
    APPLIANCE_SELECTOR_CSS,
    BANNER_DISMISS_SCRIPT,
    BANNER_LOGO_HTML,
    COMMON_MODAL_CSS,
    ICON_LINE_LEVEL,
    ICON_TURNTABLE,
    PIN_MODAL_CSS,
)
from autostream_webui_common import (
    build_appliance_selector_html,
    build_page_html,
    build_top_banner_html,
    locked_load_config,
)
from autostream_webui_state import WebUIState


_REMOTE_HOME_SCRIPT = """<script>
function normalizeVolume(v){var n=Number(v);if(!Number.isFinite(n))return 0;return Math.max(0,Math.min(100,Math.round(n)));}
function formatVolume(v){return String(normalizeVolume(v))+'%';}
function updateVolumeLabel(id,v){var s=document.getElementById('vol_label_'+id);if(s)s.textContent=formatVolume(v);}
function reorderOutputCards(){var list=document.getElementById('outputs-list');if(!list)return;var cards=Array.from(list.querySelectorAll('.output-card'));cards.sort(function(a,b){var da=a.getAttribute('data-is-default')==='1'?1:0,db=b.getAttribute('data-is-default')==='1'?1:0;if(db!==da)return db-da;var na=((a.querySelector('.output-card-name')&&a.querySelector('.output-card-name').textContent)||'').trim().toLowerCase();var nb=((b.querySelector('.output-card-name')&&b.querySelector('.output-card-name').textContent)||'').trim().toLowerCase();return na.localeCompare(nb);});cards.forEach(function(c){list.appendChild(c);});}
function updateOutputStateVisual(id,selected){var chip=document.getElementById('output_state_'+id);var card=document.getElementById('output_card_'+id);var wrap=document.getElementById('output_slider_wrap_'+id);if(chip){chip.textContent=selected?'On':'Off';chip.classList.toggle('on',!!selected);chip.classList.toggle('off',!selected);}if(card){card.classList.toggle('output-card-on',!!selected);card.classList.toggle('output-card-off',!selected);}if(wrap){wrap.hidden=!selected;}}
function computeMasterVolume(){var sum=0,count=0;document.querySelectorAll('.output-card').forEach(function(card){var id=card.getAttribute('data-output-id');if(!id)return;var cb=document.getElementById('output_enabled_'+id);var sl=document.getElementById('vol_slider_'+id);if(cb&&cb.checked&&sl){sum+=normalizeVolume(sl.value);count++;}});return count>0?Math.round(sum/count):null;}
function updateMasterVolumeCard(){var card=document.getElementById('master-volume-card');var sl=document.getElementById('master_vol_slider');if(!card||!sl)return;var v=computeMasterVolume();var inactive=(v===null);var val=inactive?(window.__PRESET_VOLUME||20):v;card.classList.toggle('master-volume-inactive',inactive);sl.disabled=inactive;if(String(sl.value)!==String(val))sl.value=String(val);}
function onMasterVolumeDragStart(){var sl=document.getElementById('master_vol_slider');if(!sl||sl.disabled)return;var snaps={};document.querySelectorAll('.output-card').forEach(function(card){var id=card.getAttribute('data-output-id');if(!id)return;var cb=document.getElementById('output_enabled_'+id);var vs=document.getElementById('vol_slider_'+id);if(cb&&cb.checked&&vs)snaps[id]=normalizeVolume(vs.value);});window.__MASTER_DRAG_SNAPSHOTS=snaps;window.__MASTER_DRAG_BASE=normalizeVolume(sl.value);}
function _applyMasterScale(newMaster){var snaps=window.__MASTER_DRAG_SNAPSHOTS||{};var base=typeof window.__MASTER_DRAG_BASE==='number'?window.__MASTER_DRAG_BASE:0;var nm=normalizeVolume(newMaster);Object.keys(snaps).forEach(function(id){var sl=document.getElementById('vol_slider_'+id);if(!sl)return;var nv=base>0?Math.round(snaps[id]*nm/base):nm;nv=Math.max(0,Math.min(100,nv));sl.value=String(nv);updateVolumeLabel(id,nv);});}
function onMasterVolumeInput(v){_applyMasterScale(v);}
function onMasterVolumeChange(v){_applyMasterScale(v);var snaps=window.__MASTER_DRAG_SNAPSHOTS||{};Object.keys(snaps).forEach(function(id){sendUpdate(id);});window.__MASTER_DRAG_SNAPSHOTS={};}
function showPinModal(outputName){return new Promise(function(resolve){var m=document.getElementById('pinModal');var input=document.getElementById('pinModalInput');var btnOk=document.getElementById('pinModalOk');var btnCancel=document.getElementById('pinModalCancel');if(!m||!input||!btnOk||!btnCancel){var v=window.prompt('Enter PIN'+(outputName?' ('+outputName+')':'')+':','');resolve(v&&String(v).trim()?String(v).trim():null);return;}if(outputName)document.getElementById('pinModalTitle').textContent='Enter PIN for '+outputName;input.value='';m.classList.add('show');setTimeout(function(){try{input.focus();}catch(e){}},60);var cleanup=function(val){m.classList.remove('show');btnOk.onclick=null;btnCancel.onclick=null;input.onkeydown=null;resolve(val);};btnCancel.onclick=function(){cleanup(null);};btnOk.onclick=function(){var v=(input.value||'').trim();cleanup(v?v:null);};input.onkeydown=function(ev){if(ev.key==='Enter'){ev.preventDefault();btnOk.click();}else if(ev.key==='Escape'){ev.preventDefault();btnCancel.click();}};});}
function handleHomeSessionRejected(response){var status=Number(response&&response.status);if(status!==401&&status!==403)return false;if(window.__HOME_SESSION_REFRESHING)return true;window.__HOME_SESSION_REFRESHING=true;window.location.reload();return true;}
async function postOutputUpdate(id,selected,volume){var r=await fetch(window.__OUTPUT_URL,{method:'POST',credentials:'same-origin',signal:AbortSignal.timeout(5000),headers:{'Content-Type':'application/json','X-CSRF-Token':window.__CSRF||''},body:JSON.stringify({id:id,selected:!!selected,volume:parseInt(volume||0,10)||0,csrf_token:window.__CSRF||''})});if(handleHomeSessionRejected(r))return{ok:false,_http:r.status,session_rejected:true};var j=null;try{j=await r.json();}catch(e){j={ok:r.ok};}j._http=r.status;return j;}
async function postPinOnly(id,pin){var r=await fetch(window.__OUTPUT_URL,{method:'POST',credentials:'same-origin',signal:AbortSignal.timeout(5000),headers:{'Content-Type':'application/json','X-CSRF-Token':window.__CSRF||''},body:JSON.stringify({op:'pin',id:id,pin:String(pin||'').trim(),csrf_token:window.__CSRF||''})});if(handleHomeSessionRejected(r))return{ok:false,_http:r.status,session_rejected:true};var j=null;try{j=await r.json();}catch(e){j={ok:r.ok};}j._http=r.status;return j;}
async function sendUpdate(id){var c=document.getElementById('output_enabled_'+id),s=document.getElementById('vol_slider_'+id);var selected=c?c.checked:false;var volume=s?normalizeVolume(parseInt(s.value,10)):0;window.__PENDING_OUTPUTS.add(String(id));try{var j=null;try{j=await postOutputUpdate(id,selected,volume);}catch(e){return;}if(selected&&j&&j.pin_required){if(c){c.checked=false;updateOutputStateVisual(String(id),false);}var nm='';try{var card=c?c.closest('.output-card'):null;var label=card?card.querySelector('.output-card-name'):null;nm=label?(label.textContent||'').trim():'';}catch(e){}while(true){var pin=await showPinModal(nm||'this speaker');if(!pin)return;var jpin=null;try{jpin=await postPinOnly(id,pin);}catch(e){if(c){c.checked=false;updateOutputStateVisual(String(id),false);}return;}if(jpin&&jpin.ok){try{var jen=await postOutputUpdate(id,true,volume);if(jen&&jen.ok){if(c){c.checked=true;updateOutputStateVisual(String(id),true);}return;}if(jen&&jen.pin_required){if(c){c.checked=false;updateOutputStateVisual(String(id),false);}continue;}}catch(e){if(c){c.checked=false;updateOutputStateVisual(String(id),false);}return;}return;}if(jpin&&jpin.pin_invalid)continue;return;}}}finally{window.__PENDING_OUTPUTS.delete(String(id));}}
function onToggleOutput(id){var cb=document.getElementById('output_enabled_'+id);if(cb)updateOutputStateVisual(String(id),!!cb.checked);if(cb&&cb.checked){var sl=document.getElementById('vol_slider_'+id);if(sl){sl.value=String(window.__PRESET_VOLUME||20);updateVolumeLabel(id,sl.value);}}reorderOutputCards();updateMasterVolumeCard();sendUpdate(id);}
function onVolumeChange(id,v){updateVolumeLabel(id,v);if(document.activeElement!==document.getElementById('master_vol_slider'))updateMasterVolumeCard();sendUpdate(id);}
var VU_THRESHOLDS=[-60,-48,-36,-24,-12,-6,-3];var VU_COLORS=['#2196F3','#2196F3','#2196F3','#2196F3','#f0ad4e','#fd7e14','#dc3545'];var VU_BIN_MS=100;var VU_DELAY_BINS=Math.max(1,Math.round((window.__VU_DELAY_MS||2250)/VU_BIN_MS));
var _vuQueue={};var _vuLastSeq={};var _vuActiveIdx=-1;
function updateVuBars(l,r){var lBars=document.querySelectorAll('#np-vu-l .vu-bar');var rBars=document.querySelectorAll('#np-vu-r .vu-bar');lBars.forEach(function(bar,i){var lit=Number.isFinite(Number(l))&&Number(l)>=VU_THRESHOLDS[i];bar.style.background=lit?VU_COLORS[i]:'';});rBars.forEach(function(bar,i){var lit=Number.isFinite(Number(r))&&Number(r)>=VU_THRESHOLDS[i];bar.style.background=lit?VU_COLORS[i]:'';});}
function vuIngestHistory(activeIdx,vu_history){if(activeIdx!==_vuActiveIdx){_vuQueue={};_vuLastSeq={};_vuActiveIdx=activeIdx;}if(!vu_history||!Array.isArray(vu_history.bins)||vu_history.bins.length===0)return;var bins=vu_history.bins;var latestSeq=vu_history.latest_seq||0;var cutoffSeq=latestSeq-VU_DELAY_BINS;if(cutoffSeq<0)return;if(!_vuQueue[activeIdx])_vuQueue[activeIdx]=[];if(!_vuLastSeq[activeIdx])_vuLastSeq[activeIdx]=0;var lastSeen=_vuLastSeq[activeIdx];if(latestSeq<lastSeen&&lastSeen>0){_vuQueue[activeIdx]=[];_vuLastSeq[activeIdx]=0;lastSeen=0;}var added=0;for(var i=0;i<bins.length;i++){var b=bins[i];if(b.seq>lastSeen&&b.seq<=cutoffSeq){_vuQueue[activeIdx].push(b);added++;}}if(added>0)_vuLastSeq[activeIdx]=cutoffSeq;var maxQ=VU_DELAY_BINS*2;var q=_vuQueue[activeIdx];if(q.length>maxQ)_vuQueue[activeIdx]=q.slice(q.length-maxQ);}
function vuRenderTick(){var q=_vuQueue[_vuActiveIdx];var bin=(q&&q.length>0)?q.shift():null;updateVuBars(bin?bin.l:-90,bin?bin.r:-90);}
function buildOutputCardElement(o){var id=String(o.id||'');var name=String(o.name||('Output '+id));var selected=!!o.selected;var volume=normalizeVolume(o.volume);var isDefault=!!o.is_default;var card=document.createElement('div');card.className='output-card '+(selected?'output-card-on':'output-card-off');card.id='output_card_'+id;card.setAttribute('data-output-id',id);card.setAttribute('data-is-default',isDefault?'1':'0');var head=document.createElement('div');head.className='output-card-head';var meta=document.createElement('div');meta.className='output-card-meta';var nameDiv=document.createElement('div');nameDiv.className='output-card-name';nameDiv.textContent=name;meta.appendChild(nameDiv);if(isDefault){var badge=document.createElement('span');badge.className='output-card-default';badge.textContent='Default';meta.appendChild(badge);}var chip=document.createElement('span');chip.className='output-state-chip '+(selected?'on':'off');chip.id='output_state_'+id;chip.textContent=selected?'On':'Off';meta.appendChild(chip);head.appendChild(meta);var toggle=document.createElement('label');toggle.className='output-toggle';toggle.addEventListener('click',function(e){e.stopPropagation();});var cb=document.createElement('input');cb.type='checkbox';cb.id='output_enabled_'+id;cb.checked=selected;cb.addEventListener('change',function(){onToggleOutput(id);});toggle.appendChild(cb);var sw=document.createElement('span');sw.className='switch';sw.setAttribute('aria-hidden','true');toggle.appendChild(sw);head.appendChild(toggle);card.appendChild(head);var wrap=document.createElement('div');wrap.className='output-slider-wrap';wrap.id='output_slider_wrap_'+id;wrap.addEventListener('click',function(e){e.stopPropagation();});if(!selected)wrap.hidden=true;var sliderHdr=document.createElement('div');sliderHdr.className='slider-header';var volText=document.createElement('span');volText.textContent='Volume:';sliderHdr.appendChild(volText);var volLbl=document.createElement('span');volLbl.id='vol_label_'+id;volLbl.setAttribute('data-volume-label-for',id);sliderHdr.appendChild(volLbl);wrap.appendChild(sliderHdr);var sl=document.createElement('input');sl.type='range';sl.id='vol_slider_'+id;sl.min=0;sl.max=100;sl.step=1;sl.value=volume;sl.addEventListener('input',function(){updateVolumeLabel(id,this.value);});sl.addEventListener('change',function(){onVolumeChange(id,this.value);});wrap.appendChild(sl);card.appendChild(wrap);return card;}
function setOutputsPlaceholder(state){var el=document.getElementById('outputs-placeholder');if(!el)return;if(state==='hidden'){el.hidden=true;el.textContent='';}else if(state==='unreachable'){el.hidden=false;el.textContent='Waiting for owntone';}else{el.hidden=false;el.textContent='Waiting for device discovery';}}
function renderOutputList(outputs){var list=document.getElementById('outputs-list');if(!list)return;while(list.firstChild)list.removeChild(list.firstChild);for(var i=0;i<outputs.length;i++){list.appendChild(buildOutputCardElement(outputs[i]));}list.querySelectorAll('[data-volume-label-for]').forEach(function(s){var id=s.getAttribute('data-volume-label-for');var sl=document.getElementById('vol_slider_'+id);if(sl)updateVolumeLabel(id,sl.value);var cb=document.getElementById('output_enabled_'+id);if(cb)updateOutputStateVisual(String(id),!!cb.checked);});reorderOutputCards();updateMasterVolumeCard();setOutputsPlaceholder(outputs.length>0?'hidden':'empty');}
function renderHomeState(data){
  var playback=(data&&data.playback)||{};var levels=(data&&data.input_levels)||[];var inputs=playback.inputs||{};
  var isPlaying=false,activeLevel=null,activeIdx=0;
  for(var i=0;i<levels.length;i++){if(levels[i]&&levels[i].is_above_threshold){isPlaying=true;activeLevel=levels[i];activeIdx=i;break;}}
  var card=document.getElementById('now-playing-card');var hdrEl=document.getElementById('np-hdr');
  if(card)card.classList.toggle('np-ready',!isPlaying);if(hdrEl)hdrEl.textContent=isPlaying?'Now Playing':'Ready';
  if(!isPlaying){_vuActiveIdx=-1;_vuQueue={};updateVuBars(-90,-90);}else{
    if(!activeLevel&&levels.length>0){activeLevel=levels[0];activeIdx=0;}
    if(activeLevel){var inputSnap=inputs[String(activeIdx+1)]||{};var isTurntable=!!inputSnap.is_turntable;var label=String(activeLevel.label||('Input '+(activeIdx+1)));var hz=Number(activeLevel.detected_hz||0);var nameEl=document.getElementById('np-name');var signalEl=document.getElementById('np-signal');var iconEl=document.getElementById('np-icon');if(nameEl)nameEl.textContent=label+' \\u00b7 '+(isTurntable?'Turntable':'Line Level');if(signalEl){var sp=[];if(window.__SHOW_INPUT_DETAIL&&Number.isFinite(hz)&&hz>0){sp.push('Locked');sp.push(Math.round(hz/1000)+' kHz');}signalEl.textContent=sp.join(' \\u00b7 ');}if(iconEl&&iconEl.dataset.iconType!==String(isTurntable)){iconEl.innerHTML=isTurntable?window.__ICON_TURNTABLE:window.__ICON_LINE_LEVEL;iconEl.dataset.iconType=String(isTurntable);}vuIngestHistory(activeIdx,activeLevel.vu_history);}
  }
  var prefs=(data&&data.preferences)||{};var showMaster=!!prefs.show_master_volume;var masterCard=document.getElementById('master-volume-card');if(masterCard)masterCard.hidden=!showMaster;
  var outputs=Array.isArray(data.outputs)?data.outputs:[];
  if(outputs.length===0){setOutputsPlaceholder('empty');}else{
    var list=document.getElementById('outputs-list');var domIds=list?Array.from(list.querySelectorAll('.output-card[data-output-id]')).map(function(c){return c.getAttribute('data-output-id');}):[];var inIds=outputs.map(function(o){return String(o.id);});if(JSON.stringify(inIds.slice().sort())!==JSON.stringify(domIds.slice().sort())){renderOutputList(outputs);}else{setOutputsPlaceholder('hidden');outputs.forEach(function(o){var id=String(o.id);if(window.__PENDING_OUTPUTS&&window.__PENDING_OUTPUTS.has(id))return;var cb=document.getElementById('output_enabled_'+id);var sl=document.getElementById('vol_slider_'+id);if(cb){cb.checked=!!o.selected;updateOutputStateVisual(id,!!o.selected);}if(sl&&sl!==document.activeElement){var v=normalizeVolume(o.volume);if(sl.value!==String(v)){sl.value=String(v);updateVolumeLabel(id,v);}}});reorderOutputCards();if(document.activeElement!==document.getElementById('master_vol_slider'))updateMasterVolumeCard();}
  }
  var warnings=(data&&data.warnings)||{};['stylus','belt','bearing'].forEach(function(item){var el=document.getElementById(item+'-warning-banner');if(!el)return;var txt=String(warnings[item]||'').trim();el.style.display=txt?'block':'none';el.textContent=txt;});
  if(showMaster)updateMasterVolumeCard();
}
var __remoteFailCount=0;var __remotePolling=true;var __remotePollTimer=null;
var __DEFINITIVE_ERRORS=['not_found','appliance_unconfigured','appliance_conflicted','appliance_identity_unavailable'];
var __TRANSPORT_ERRORS=['remote_timeout','remote_bad_response','appliance_offline'];
function __homeRedirectWithFlash(msg){window.location.href='/?msg='+encodeURIComponent('error:'+msg);}
function __homeHandleDefinitiveError(err){var h=window.__REMOTE_HOSTNAME||'autostream';var msgs={'not_found':'The selected appliance address is invalid. Returned to this appliance.','appliance_unconfigured':h+' is not ready for remote control. Returned to this appliance.','appliance_conflicted':h+' has a network identity conflict and cannot be selected safely. Returned to this appliance.','appliance_identity_unavailable':h+' cannot currently provide multi-appliance access. Returned to this appliance.'};__homeRedirectWithFlash(msgs[err]||(h+' is unavailable. Returned to this appliance.'));}
function scheduleRemotePoll(){if(__remotePollTimer)clearTimeout(__remotePollTimer);__remotePollTimer=setTimeout(pollHomeState,3000);}
async function pollHomeState(){if(!__remotePolling)return;var data=null;try{var r=await fetch(window.__POLL_URL,{cache:'no-store',signal:AbortSignal.timeout(5000)});data=await r.json();}catch(e){__remoteFailCount++;if(__remoteFailCount>=3){__homeRedirectWithFlash((window.__REMOTE_HOSTNAME||'autostream')+' is unavailable. Returned to this appliance.');return;}scheduleRemotePoll();return;}if(!data||!data.ok){var err=(data&&data.error)||'remote_timeout';if(__DEFINITIVE_ERRORS.indexOf(err)>=0){__homeHandleDefinitiveError(err);return;}if(__TRANSPORT_ERRORS.indexOf(err)>=0){__remoteFailCount++;if(__remoteFailCount>=3){__homeRedirectWithFlash((window.__REMOTE_HOSTNAME||'autostream')+' is unavailable. Returned to this appliance.');return;}}scheduleRemotePoll();return;}__remoteFailCount=0;renderHomeState(data);scheduleRemotePoll();}
function initApplianceSelector(){var btn=document.getElementById('appliance-selector-btn');var dd=document.getElementById('appliance-selector-dropdown');if(!btn||!dd)return;btn.addEventListener('click',function(e){e.stopPropagation();var open=!dd.hidden;dd.hidden=open;btn.setAttribute('aria-expanded',String(!open));if(!open)refreshApplianceSelector();});document.addEventListener('click',function(){if(!dd.hidden){dd.hidden=true;btn.setAttribute('aria-expanded','false');}});dd.addEventListener('keydown',function(e){var opts=Array.from(dd.querySelectorAll('.appliance-selector-option'));var idx=opts.indexOf(document.activeElement);if(e.key==='ArrowDown'){e.preventDefault();var n=opts[idx+1]||opts[0];if(n)n.focus();}else if(e.key==='ArrowUp'){e.preventDefault();var p=opts[idx-1]||opts[opts.length-1];if(p)p.focus();}else if(e.key==='Escape'){dd.hidden=true;btn.setAttribute('aria-expanded','false');btn.focus();}});}
function updateSelectorFromAppliances(appliances,currentId,currentPage){var dd=document.getElementById('appliance-selector-dropdown');var nameEl=document.getElementById('appliance-selector-current');if(!dd)return;dd.innerHTML='';var dividerAdded=false;appliances.forEach(function(a){var isBound=!!a.is_bound;if(!isBound&&!dividerAdded){dividerAdded=true;var divEl=document.createElement('div');divEl.className='appliance-selector-divider';divEl.setAttribute('role','separator');divEl.setAttribute('aria-hidden','true');dd.appendChild(divEl);}var href=currentPage==='equaliser'?(a.equaliser_path||'/a/'+a.id+'/equaliser'):(a.home_path||(isBound?'/':'/a/'+a.id+'/'));var opt=document.createElement('a');opt.href=href;opt.setAttribute('role','option');opt.setAttribute('aria-selected',a.id===currentId?'true':'false');opt.className='appliance-selector-option'+(a.id===currentId?' appliance-selector-option-active':'');if(isBound)opt.style.fontWeight='700';opt.textContent=String(a.hostname||'autostream');dd.appendChild(opt);});var cur=appliances.find(function(a){return a.id===currentId;});if(nameEl&&cur)nameEl.textContent=String(cur.hostname||'autostream');}
function refreshApplianceSelector(){fetch('/api/appliances',{cache:'no-store'}).then(function(r){return r.json();}).then(function(data){if(!data||!data.ok||!Array.isArray(data.appliances))return;var el=document.getElementById('appliance-selector');var currentId=el?(el.getAttribute('data-current-id')||window.__REMOTE_AID||''):(window.__REMOTE_AID||'');var currentPage=el?(el.getAttribute('data-current-page')||'home'):'home';updateSelectorFromAppliances(data.appliances,currentId,currentPage);}).catch(function(){});}
window.addEventListener('DOMContentLoaded',function(){
  window.__PENDING_OUTPUTS=new Set();window.__MASTER_DRAG_SNAPSHOTS={};window.__MASTER_DRAG_BASE=0;window.__OUTPUTS_IN_FLIGHT=false;
  initApplianceSelector();refreshApplianceSelector();
  setInterval(function(){if(!document.hidden)refreshApplianceSelector();},15000);
  document.addEventListener('visibilitychange',function(){if(!document.hidden){__remoteFailCount=0;pollHomeState();refreshApplianceSelector();}else{__remotePolling=false;if(__remotePollTimer){clearTimeout(__remotePollTimer);__remotePollTimer=null;}}});
  __remotePolling=true;__remoteFailCount=0;
  setInterval(vuRenderTick,VU_BIN_MS);
  pollHomeState();
});
</script>"""


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
        cfg = locked_load_config(state.config_path)
        parsed = parse_config(cfg)
    except Exception:
        # If we're here something bad happened - user should have been redirected to the setup page
        # if the INI is missing. Hence, take the nuclear option and inform the user that something
        # went wrong - then reboot the system. This code serves only inline code in case the file
        # system is dead (which is likely). Reboot may therefore also fail.
        body = (
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
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
    _np_label = str(_np_active_level.get("label", f"Input {_np_active_idx + 1}"))
    _np_type_label = "Turntable" if _np_is_turntable else "Line Level"
    _np_hz = float(_np_active_level.get("detected_hz", 0.0))
    _np_signal_parts = []
    if show_input_detail and _np_hz > 0:
        _np_signal_parts.append("Locked")
        _np_signal_parts.append(f"{_np_hz / 1000:.0f} kHz")
    _np_signal = " \u00b7 ".join(_np_signal_parts)
    _np_icon_svg = ICON_TURNTABLE if _np_is_turntable else ICON_LINE_LEVEL

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

    # Filter and sort outputs through the shared model helper.
    output_dicts = build_output_list(parsed, raw_outputs)

    outputs_html = ""
    for out in output_dicts:
        out_id = out["id"]
        name = out["name"]
        selected = out["selected"]
        volume = out["volume"]
        safe_name = html.escape(name)
        default_badge = '<span class="output-card-default">Default</span>' if out["is_default"] else ""
        state_text = "On" if selected else "Off"
        state_cls = "on" if selected else "off"
        card_state_cls = "output-card-on" if selected else "output-card-off"
        is_default = "1" if out["is_default"] else "0"
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
        f"window.__ICON_LINE_LEVEL={json.dumps(ICON_LINE_LEVEL)};"
        f"window.__LOCAL_ID='{html.escape(_local_id)}';"
        f"</script>"
    )

    _vu_stereo_css = (
        ".vu-meter{flex-direction:row;gap:3px;width:23px;}"
        ".vu-col{display:flex;flex-direction:column-reverse;gap:2px;"
        "width:10px;flex:0 0 10px;}"
    )
    _extra_css = f"{COMMON_MODAL_CSS}\n{PIN_MODAL_CSS}\n{APPLIANCE_SELECTOR_CSS}\n{_vu_stereo_css}"
    _head_extra = f"""{csrf_meta}

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

        function computeMasterVolume(){{
          var sum=0, count=0;
          document.querySelectorAll('.output-card').forEach(function(card){{
            var id=card.getAttribute('data-output-id');
            if(!id) return;
            var cb=document.getElementById('output_enabled_'+id);
            var sl=document.getElementById('vol_slider_'+id);
            if(cb && cb.checked && sl){{sum+=normalizeVolume(sl.value);count++;}}
          }});
          return count>0 ? Math.round(sum/count) : null;
        }}
        function updateMasterVolumeCard(){{
          var card=document.getElementById('master-volume-card');
          var sl=document.getElementById('master_vol_slider');
          if(!card||!sl) return;
          var v=computeMasterVolume();
          var inactive=(v===null);
          var val=inactive?(window.__PRESET_VOLUME||20):v;
          card.classList.toggle('master-volume-inactive',inactive);
          sl.disabled=inactive;
          if(String(sl.value)!==String(val)) sl.value=String(val);
        }}
        function onMasterVolumeDragStart(){{
          var sl=document.getElementById('master_vol_slider');
          if(!sl||sl.disabled) return;
          var snaps={{}};
          document.querySelectorAll('.output-card').forEach(function(card){{
            var id=card.getAttribute('data-output-id');
            if(!id) return;
            var cb=document.getElementById('output_enabled_'+id);
            var vs=document.getElementById('vol_slider_'+id);
            if(cb&&cb.checked&&vs) snaps[id]=normalizeVolume(vs.value);
          }});
          window.__MASTER_DRAG_SNAPSHOTS=snaps;
          window.__MASTER_DRAG_BASE=normalizeVolume(sl.value);
        }}
        function _applyMasterScale(newMaster){{
          var snaps=window.__MASTER_DRAG_SNAPSHOTS||{{}};
          var base=typeof window.__MASTER_DRAG_BASE==='number'?window.__MASTER_DRAG_BASE:0;
          var nm=normalizeVolume(newMaster);
          Object.keys(snaps).forEach(function(id){{
            var sl=document.getElementById('vol_slider_'+id);
            if(!sl) return;
            var nv=base>0?Math.round(snaps[id]*nm/base):nm;
            nv=Math.max(0,Math.min(100,nv));
            sl.value=String(nv);
            updateVolumeLabel(id,nv);
          }});
        }}
        function onMasterVolumeInput(v){{
          _applyMasterScale(v);
        }}
        function onMasterVolumeChange(v){{
          _applyMasterScale(v);
          var snaps=window.__MASTER_DRAG_SNAPSHOTS||{{}};
          Object.keys(snaps).forEach(function(id){{ sendUpdate(id); }});
          window.__MASTER_DRAG_SNAPSHOTS={{}};
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
          updateMasterVolumeCard();
          sendUpdate(id);
        }}
        function onVolumeChange(id,v){{
          updateVolumeLabel(id,v);
          if(!isActiveControl(document.getElementById('master_vol_slider'))) updateMasterVolumeCard();
          sendUpdate(id);
        }}
        var VU_THRESHOLDS = [-60, -48, -36, -24, -12, -6, -3];
        var VU_COLORS = ['#2196F3','#2196F3','#2196F3','#2196F3','#f0ad4e','#fd7e14','#dc3545'];
        var VU_BIN_MS = 100;
        var VU_DELAY_BINS = Math.max(1, Math.round((window.__VU_DELAY_MS || 2250) / VU_BIN_MS));

        // Per-input VU queue state.
        var _vuQueue = {{}};         // inputIdx → Array of pending bins
        var _vuLastSeq = {{}};       // inputIdx → last seq appended to queue
        var _vuActiveIdx = -1;      // currently displayed input index (-1 = none)

        function updateVuBars(left_dbfs, right_dbfs){{
          var lBars = document.querySelectorAll('#np-vu-l .vu-bar');
          var rBars = document.querySelectorAll('#np-vu-r .vu-bar');
          lBars.forEach(function(bar, i){{
            var lit = Number.isFinite(Number(left_dbfs)) && Number(left_dbfs) >= VU_THRESHOLDS[i];
            bar.style.background = lit ? VU_COLORS[i] : '';
          }});
          rBars.forEach(function(bar, i){{
            var lit = Number.isFinite(Number(right_dbfs)) && Number(right_dbfs) >= VU_THRESHOLDS[i];
            bar.style.background = lit ? VU_COLORS[i] : '';
          }});
        }}

        function vuIngestHistory(activeIdx, vu_history){{
          // If the active input changed, clear all queues immediately.
          if (activeIdx !== _vuActiveIdx) {{
            _vuQueue = {{}};
            _vuLastSeq = {{}};
            _vuActiveIdx = activeIdx;
          }}
          if (!vu_history || !Array.isArray(vu_history.bins) || vu_history.bins.length === 0)
            return;
          var bins = vu_history.bins;
          var latestSeq = vu_history.latest_seq || 0;
          // Only show bins that are VU_DELAY_BINS steps behind the latest
          // so the display lags the signal by approximately __VU_DELAY_MS.
          var cutoffSeq = latestSeq - VU_DELAY_BINS;
          if (cutoffSeq < 0) return;
          if (!_vuQueue[activeIdx]) _vuQueue[activeIdx] = [];
          if (!_vuLastSeq[activeIdx]) _vuLastSeq[activeIdx] = 0;
          var lastSeen = _vuLastSeq[activeIdx];
          // Detect seq reset (daemon restart): clear and resync.
          if (latestSeq < lastSeen && lastSeen > 0) {{
            _vuQueue[activeIdx] = [];
            _vuLastSeq[activeIdx] = 0;
            lastSeen = 0;
          }}
          var added = 0;
          for (var i = 0; i < bins.length; i++) {{
            var b = bins[i];
            if (b.seq > lastSeen && b.seq <= cutoffSeq) {{
              _vuQueue[activeIdx].push(b);
              added++;
            }}
          }}
          if (added > 0)
            _vuLastSeq[activeIdx] = cutoffSeq;
          // Bound queue to 2× the delay window to guard against extreme fetch jitter.
          var maxQ = VU_DELAY_BINS * 2;
          var q = _vuQueue[activeIdx];
          if (q.length > maxQ)
            _vuQueue[activeIdx] = q.slice(q.length - maxQ);
        }}

        function vuRenderTick(){{
          var q = _vuQueue[_vuActiveIdx];
          var bin = (q && q.length > 0) ? q.shift() : null;
          updateVuBars(bin ? bin.l : -90, bin ? bin.r : -90);
        }}

        function updateNowPlayingCard(data){{
          var levels = (data && data.input_levels) || [];
          var inputs = (data && data.playback && data.playback.inputs) || {{}};
          var isPlaying = false, activeLevel = null, activeIdx = 0;
          for (var i = 0; i < levels.length; i++) {{
            if (levels[i] && levels[i].is_above_threshold) {{
              isPlaying = true; activeLevel = levels[i]; activeIdx = i; break;
            }}
          }}
          var card = document.getElementById('now-playing-card');
          var hdrEl = document.getElementById('np-hdr');
          if (card) card.classList.toggle('np-ready', !isPlaying);
          if (hdrEl) hdrEl.textContent = isPlaying ? 'Now Playing' : 'Ready';
          if (!isPlaying) {{
            _vuActiveIdx = -1;
            _vuQueue = {{}};
            updateVuBars(-90, -90);
            return;
          }}
          if (!activeLevel && levels.length > 0) {{ activeLevel = levels[0]; activeIdx = 0; }}
          if (!activeLevel) return;
          var inputSnap = inputs[String(activeIdx + 1)] || {{}};
          var isTurntable = !!inputSnap.is_turntable;
          var label = String(activeLevel.label || ('Input ' + (activeIdx + 1)));
          var signalParts = [];
          if (window.__SHOW_INPUT_DETAIL) {{
            var hz = Number(activeLevel.detected_hz || 0);
            if (Number.isFinite(hz) && hz > 0) {{
              signalParts.push('Locked');
              signalParts.push(Math.round(hz / 1000) + ' kHz');
            }}
          }}
          var nameEl = document.getElementById('np-name');
          var signalEl = document.getElementById('np-signal');
          var iconEl = document.getElementById('np-icon');
          if (nameEl) nameEl.textContent = label + ' \u00b7 ' + (isTurntable ? 'Turntable' : 'Line Level');
          if (signalEl) signalEl.textContent = signalParts.join(' \u00b7 ');
          if (iconEl && iconEl.dataset.iconType !== String(isTurntable)) {{
            iconEl.innerHTML = isTurntable ? window.__ICON_TURNTABLE : window.__ICON_LINE_LEVEL;
            iconEl.dataset.iconType = String(isTurntable);
          }}
          vuIngestHistory(activeIdx, activeLevel.vu_history);
        }}
        function refreshStatus(){{
          fetch('/api/status', {{ cache: 'no-store' }}).then(r=>r.json()).then(d=>{{
            updateNowPlayingCard(d);
            ['stylus', 'belt', 'bearing'].forEach(function(item) {{
              var el = document.getElementById(item + '-warning-banner');
              if (!el) return;
              var key = item === 'stylus' ? 'playback_banner_text' : item + '_banner_text';
              var txt = String((d && d[key]) || '').trim();
              el.style.display = txt ? 'block' : 'none';
              el.textContent = txt;
            }});
          }});
        }}
        function isActiveControl(el) {{
          return el && document.activeElement === el;
        }}
        function buildOutputCardElement(o) {{
          var id = String(o.id || '');
          var name = String(o.name || ('Output ' + id));
          var selected = !!o.selected;
          var volume = normalizeVolume(o.volume);
          var isDefault = !!o.is_default;

          var card = document.createElement('div');
          card.className = 'output-card ' + (selected ? 'output-card-on' : 'output-card-off');
          card.id = 'output_card_' + id;
          card.setAttribute('data-output-id', id);
          card.setAttribute('data-is-default', isDefault ? '1' : '0');

          var head = document.createElement('div');
          head.className = 'output-card-head';

          var meta = document.createElement('div');
          meta.className = 'output-card-meta';
          var nameDiv = document.createElement('div');
          nameDiv.className = 'output-card-name';
          nameDiv.textContent = name;
          meta.appendChild(nameDiv);
          if (isDefault) {{
            var badge = document.createElement('span');
            badge.className = 'output-card-default';
            badge.textContent = 'Default';
            meta.appendChild(badge);
          }}
          var chip = document.createElement('span');
          chip.className = 'output-state-chip ' + (selected ? 'on' : 'off');
          chip.id = 'output_state_' + id;
          chip.textContent = selected ? 'On' : 'Off';
          meta.appendChild(chip);
          head.appendChild(meta);

          var toggle = document.createElement('label');
          toggle.className = 'output-toggle';
          toggle.addEventListener('click', function(e) {{ e.stopPropagation(); }});
          var cb = document.createElement('input');
          cb.type = 'checkbox';
          cb.id = 'output_enabled_' + id;
          cb.checked = selected;
          cb.addEventListener('change', function() {{ onToggleOutput(id); }});
          toggle.appendChild(cb);
          var sw = document.createElement('span');
          sw.className = 'switch';
          sw.setAttribute('aria-hidden', 'true');
          toggle.appendChild(sw);
          head.appendChild(toggle);
          card.appendChild(head);

          var wrap = document.createElement('div');
          wrap.className = 'output-slider-wrap';
          wrap.id = 'output_slider_wrap_' + id;
          wrap.addEventListener('click', function(e) {{ e.stopPropagation(); }});
          if (!selected) wrap.hidden = true;
          var sliderHdr = document.createElement('div');
          sliderHdr.className = 'slider-header';
          var volText = document.createElement('span');
          volText.textContent = 'Volume:';
          sliderHdr.appendChild(volText);
          var volLbl = document.createElement('span');
          volLbl.id = 'vol_label_' + id;
          volLbl.setAttribute('data-volume-label-for', id);
          sliderHdr.appendChild(volLbl);
          wrap.appendChild(sliderHdr);
          var sl = document.createElement('input');
          sl.type = 'range';
          sl.id = 'vol_slider_' + id;
          sl.min = 0; sl.max = 100; sl.step = 1; sl.value = volume;
          sl.addEventListener('input', function() {{ updateVolumeLabel(id, this.value); }});
          sl.addEventListener('change', function() {{ onVolumeChange(id, this.value); }});
          wrap.appendChild(sl);
          card.appendChild(wrap);

          return card;
        }}
        function getOutputIdKey(outputs) {{
          return JSON.stringify(outputs.map(function(o) {{ return String(o.id); }}).sort());
        }}
        function setOutputsPlaceholder(state) {{
          var el = document.getElementById('outputs-placeholder');
          if (!el) return;
          if (state === 'hidden') {{
            el.hidden = true;
            el.textContent = '';
          }} else if (state === 'unreachable') {{
            el.hidden = false;
            el.textContent = 'Waiting for owntone';
          }} else {{
            el.hidden = false;
            el.textContent = 'Waiting for device discovery';
          }}
        }}
        function renderOutputList(outputs) {{
          var list = document.getElementById('outputs-list');
          if (!list) return;
          while (list.firstChild) list.removeChild(list.firstChild);
          for (var i = 0; i < outputs.length; i++) {{ list.appendChild(buildOutputCardElement(outputs[i])); }}
          list.querySelectorAll('[data-volume-label-for]').forEach(function(s) {{
            var id = s.getAttribute('data-volume-label-for');
            var sl = document.getElementById('vol_slider_' + id);
            if (sl) updateVolumeLabel(id, sl.value);
            var cb = document.getElementById('output_enabled_' + id);
            if (cb) updateOutputStateVisual(String(id), !!cb.checked);
          }});
          reorderOutputCards();
          updateMasterVolumeCard();
          setOutputsPlaceholder(outputs.length > 0 ? 'hidden' : 'empty');
        }}

        async function refreshOutputsState() {{
          if (window.__OUTPUTS_IN_FLIGHT) return;
          window.__OUTPUTS_IN_FLIGHT = true;
          try {{
            let j = null;
            var __ctrl = new AbortController();
            var __ctrlTimer = setTimeout(function() {{ __ctrl.abort(); }}, 5000);
            try {{
              const r = await fetch("/api/owntone/outputs_state", {{ cache: "no-store", signal: __ctrl.signal }});
              j = await r.json();
            }} catch (e) {{
              return;
            }} finally {{
              clearTimeout(__ctrlTimer);
            }}
            var __list = document.getElementById('outputs-list');
            var __domIds = __list ? Array.from(__list.querySelectorAll('.output-card[data-output-id]')).map(function(c) {{ return c.getAttribute('data-output-id'); }}) : [];
            var domKey = __domIds.length > 0 ? JSON.stringify(__domIds.sort()) : '';
            if (!j || !j.ok) {{
              if (domKey === '') {{ setOutputsPlaceholder('unreachable'); }}
              return;
            }}
            var outputs = Array.isArray(j.outputs) ? j.outputs : [];
            var targetKey = outputs.length > 0 ? getOutputIdKey(outputs) : '';
            if (outputs.length === 0 && domKey !== '') {{
              window.__OUTPUTS_EMPTY_COUNT = (window.__OUTPUTS_EMPTY_COUNT || 0) + 1;
              if (window.__OUTPUTS_EMPTY_COUNT < 3) {{ return; }}
            }} else {{
              window.__OUTPUTS_EMPTY_COUNT = 0;
            }}
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
          }} finally {{
            window.__OUTPUTS_IN_FLIGHT = false;
          }}
        }}

        function initApplianceSelector(){{
          var btn=document.getElementById('appliance-selector-btn');
          var dd=document.getElementById('appliance-selector-dropdown');
          if(!btn||!dd) return;
          btn.addEventListener('click',function(e){{
            e.stopPropagation();
            var open=!dd.hidden;
            dd.hidden=open;
            btn.setAttribute('aria-expanded',String(!open));
            if(!open) refreshApplianceSelector();
          }});
          document.addEventListener('click',function(){{
            if(!dd.hidden){{dd.hidden=true;btn.setAttribute('aria-expanded','false');}}
          }});
          dd.addEventListener('keydown',function(e){{
            var opts=Array.from(dd.querySelectorAll('.appliance-selector-option'));
            var idx=opts.indexOf(document.activeElement);
            if(e.key==='ArrowDown'){{e.preventDefault();var n=opts[idx+1]||opts[0];if(n)n.focus();}}
            else if(e.key==='ArrowUp'){{e.preventDefault();var p=opts[idx-1]||opts[opts.length-1];if(p)p.focus();}}
            else if(e.key==='Escape'){{dd.hidden=true;btn.setAttribute('aria-expanded','false');btn.focus();}}
          }});
        }}
        function updateSelectorFromAppliances(appliances,currentId,currentPage){{
          var dd=document.getElementById('appliance-selector-dropdown');
          var nameEl=document.getElementById('appliance-selector-current');
          if(!dd) return;
          dd.innerHTML='';
          var dividerAdded=false;
          appliances.forEach(function(a){{
            var isBound=!!a.is_bound;
            if(!isBound&&!dividerAdded){{
              dividerAdded=true;
              var divEl=document.createElement('div');
              divEl.className='appliance-selector-divider';
              divEl.setAttribute('role','separator');
              divEl.setAttribute('aria-hidden','true');
              dd.appendChild(divEl);
            }}
            var href=currentPage==='equaliser'
              ?(a.equaliser_path||'/a/'+a.id+'/equaliser')
              :(a.home_path||(isBound?'/':'/a/'+a.id+'/'));
            var opt=document.createElement('a');
            opt.href=href;
            opt.setAttribute('role','option');
            opt.setAttribute('aria-selected',a.id===currentId?'true':'false');
            opt.className='appliance-selector-option'+(a.id===currentId?' appliance-selector-option-active':'');
            if(isBound) opt.style.fontWeight='700';
            opt.textContent=String(a.hostname||'autostream');
            dd.appendChild(opt);
          }});
          var cur=appliances.find(function(a){{return a.id===currentId;}});
          if(nameEl&&cur) nameEl.textContent=String(cur.hostname||'autostream');
        }}
        function refreshApplianceSelector(){{
          fetch('/api/appliances',{{cache:'no-store'}})
            .then(function(r){{return r.json();}})
            .then(function(data){{
              if(!data||!data.ok||!Array.isArray(data.appliances)) return;
              var el=document.getElementById('appliance-selector');
              var currentId=el?(el.getAttribute('data-current-id')||window.__LOCAL_ID||''):(window.__LOCAL_ID||'');
              var currentPage=el?(el.getAttribute('data-current-page')||'home'):'home';
              updateSelectorFromAppliances(data.appliances,currentId,currentPage);
            }})
            .catch(function(){{}});
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
          window.__OUTPUTS_IN_FLIGHT = false;
          setInterval(function(){{ refreshStatus(); refreshOutputsState(); }}, 1500);
          setInterval(vuRenderTick, VU_BIN_MS);
          initApplianceSelector();
          refreshApplianceSelector();
          setInterval(function(){{if(!document.hidden) refreshApplianceSelector();}},15000);
          document.addEventListener('visibilitychange',function(){{if(!document.hidden) refreshApplianceSelector();}});
          refreshStatus();
          refreshOutputsState();
        }});
      </script>"""
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
</div>"""

    # Top controls row: refresh button + optional hostname/selector.
    _top_controls_html = (
        f"<div class='airplay-top-controls'>"
        f"<button type='button' class='pill-btn small' onclick='location.reload();'"
        f" title='Reload page to refresh speakers'>\u21bb Refresh</button>"
        + _top_right_html
        + f"</div>"
    )

    # Master volume wrapper embedded inside the Now Playing card.
    master_disabled_attr = " disabled" if master_inactive else ""
    _np_vol_html = (
        f'<div class="np-volume-wrap{" master-volume-inactive" if master_inactive else ""}"'
        f' id="master-volume-card">'
        f'<div class="slider-header"><span>Master Volume</span></div>'
        f'<input type="range" id="master_vol_slider" min="0" max="100" step="1"'
        f' value="{initial_master}"{master_disabled_attr}'
        f' oninput="onMasterVolumeInput(this.value)"'
        f' onchange="onMasterVolumeChange(this.value)"'
        f' onmousedown="onMasterVolumeDragStart()"'
        f' ontouchstart="onMasterVolumeDragStart()">'
        f'</div>'
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
        f'<div class="now-playing-icon" id="np-icon" data-icon-type="{str(_np_is_turntable).lower()}">'
        f'{_np_icon_svg}'
        f'</div>'
        f'<div class="now-playing-meta">'
        f'<div class="now-playing-name" id="np-name">'
        f'{html.escape(_np_label)} \u00b7 {html.escape(_np_type_label)}'
        f'</div>'
        f'<div class="now-playing-signal" id="np-signal">{html.escape(_np_signal)}</div>'
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
        # Refresh button + optional hostname pill
        + _top_controls_html
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
        cfg = locked_load_config(state.config_path)
        parsed = parse_config(cfg)
    except Exception:
        try:
            handler.send_error(500, "Configuration unavailable")
        except Exception:
            pass
        return

    csrf_token = getattr(handler, "_csrf_token", None) or ""
    preset_volume = max(0, min(100, int(parsed.owntone.volume_percent or 20)))
    dark_mode = parsed.webui.dark_mode

    appliances = _build_appliances_for_selector()
    _local_id = str(get_appliance_id() or "")

    poll_url = f"/api/appliances/{appliance_id}/home"
    output_url = f"/api/appliances/{appliance_id}/output"

    _selector_html = build_appliance_selector_html(appliances, appliance_id, "home")

    # Resolve remote hostname for page title and JS failure messages
    _remote_hostname = "autostream"
    for a in appliances:
        if a.get("id") == appliance_id:
            _remote_hostname = str(a.get("hostname") or "autostream")
            break

    _warn_style_base = (
        "padding:0.85rem 0.9rem;border-radius:12px;"
        "border:1px solid var(--color-status-danger);"
        "background:var(--color-surface-raised);"
        "color:var(--color-text);font-size:0.99rem;"
        "text-align:center;text-decoration:none;"
    )

    _vu_stereo_css = (
        ".vu-meter{flex-direction:row;gap:3px;width:23px;}"
        ".vu-col{display:flex;flex-direction:column-reverse;gap:2px;"
        "width:10px;flex:0 0 10px;}"
    )
    _extra_css = f"{COMMON_MODAL_CSS}\n{PIN_MODAL_CSS}\n{APPLIANCE_SELECTOR_CSS}\n{_vu_stereo_css}"

    _head_extra = (
        f"<meta name='csrf-token' content='{html.escape(csrf_token)}'>"
        f"<script>"
        f"window.__CSRF='{html.escape(csrf_token)}';"
        f"window.__PRESET_VOLUME={preset_volume};"
        f"window.__SHOW_INPUT_DETAIL=false;"
        f"window.__VU_DELAY_MS=2250;"
        f"window.__ICON_TURNTABLE={json.dumps(ICON_TURNTABLE)};"
        f"window.__ICON_LINE_LEVEL={json.dumps(ICON_LINE_LEVEL)};"
        f"window.__LOCAL_ID='{html.escape(_local_id)}';"
        f"window.__REMOTE_AID='{html.escape(appliance_id)}';"
        f"window.__REMOTE_HOSTNAME='{html.escape(_remote_hostname)}';"
        f"window.__POLL_URL='{html.escape(poll_url)}';"
        f"window.__OUTPUT_URL='{html.escape(output_url)}';"
        f"</script>\n"
        + _REMOTE_HOME_SCRIPT
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
</div>"""

    _np_icon_svg = ICON_LINE_LEVEL

    _top_controls_html = (
        f"<div class='airplay-top-controls'>"
        f"<button type='button' class='pill-btn small' onclick='location.href=\"/\"'"
        f" title='Return to this appliance'>← Home</button>"
        f"{_selector_html}"
        f"</div>"
    )

    _now_playing_card_html = (
        f'<div class="now-playing-card np-ready" id="now-playing-card">'
        f'<div class="now-playing-hdr" id="np-hdr">Ready</div>'
        f'<div class="now-playing-body">'
        f'<div class="now-playing-icon" id="np-icon" data-icon-type="false">'
        f'{_np_icon_svg}'
        f'</div>'
        f'<div class="now-playing-meta">'
        f'<div class="now-playing-name" id="np-name">Connecting…</div>'
        f'<div class="now-playing-signal" id="np-signal"></div>'
        f'</div>'
        f'</div>'
        f'<div class="np-volume-wrap master-volume-inactive" id="master-volume-card" hidden>'
        f'<div class="slider-header"><span>Master Volume ({html.escape(_remote_hostname)})</span></div>'
        f'<input type="range" id="master_vol_slider" min="0" max="100" step="1"'
        f' value="{preset_volume}" disabled'
        f' oninput="onMasterVolumeInput(this.value)"'
        f' onchange="onMasterVolumeChange(this.value)"'
        f' onmousedown="onMasterVolumeDragStart()"'
        f' ontouchstart="onMasterVolumeDragStart()">'
        f'</div>'
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
    body_bytes = html_body.encode("utf-8")
    try:
        handler.send_response(200)
        handler.send_header("Content-Type", "text/html; charset=utf-8")
        handler.send_header("Content-Length", str(len(body_bytes)))
        handler.end_headers()
        handler.wfile.write(body_bytes)
    except (BrokenPipeError, ConnectionResetError):
        logging.info("Client disconnected before remote home page response completed.")
    except Exception:
        logging.exception("Failed sending remote home page response.")
