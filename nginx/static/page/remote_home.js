var pageData = (function () {
  try { return JSON.parse(document.getElementById('page-data').textContent); }
  catch (e) { return {}; }
})();
window.__REMOTE_AID = pageData.remote_aid;
window.__REMOTE_HOSTNAME = pageData.remote_hostname;
window.__POLL_URL = pageData.poll_url;

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
function navigateToRemoteAppliance(hostname){fetch('/api/appliances',{cache:'no-store'}).then(function(r){return r.json();}).then(function(data){if(!data||!data.ok||!Array.isArray(data.appliances))return;var appliance=data.appliances.find(function(a){return String(a.hostname||'').toLowerCase()===String(hostname||'').toLowerCase();});if(appliance){window.location.href='/a/'+String(appliance.id)+'/';}}).catch(function(){});}document.addEventListener('DOMContentLoaded',function(){var list=document.getElementById('outputs-list');if(!list)return;list.addEventListener('click',function(e){if(!window.__CONTROL_OTHER_APPLIANCES)return;var card=e.target.closest('.output-card[data-remote-in-use="1"]');if(!card)return;if(e.target.closest('.output-toggle')||e.target.closest('.output-slider-wrap'))return;var owner=card.getAttribute('data-remote-owner');if(owner)navigateToRemoteAppliance(owner);});});
