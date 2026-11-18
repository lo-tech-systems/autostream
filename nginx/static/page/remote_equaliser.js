var pageData = (function () {
  try { return JSON.parse(document.getElementById('page-data').textContent); }
  catch (e) { return {}; }
})();
window.__POLL_URL = pageData.poll_url;
window.__SAVE_URL = pageData.save_url;
window.__RESET_URL = pageData.reset_url;
window.__STATUS_URL = pageData.status_url;
window.__REMOTE_AID = pageData.remote_aid;
window.__REMOTE_HOSTNAME = pageData.remote_hostname;
window.__LOCAL_ID = pageData.local_id;
window.__SELECTOR_CURRENT_PAGE = pageData.selector_current_page;

var _EQ_BAND_KEYS=['peq1_db','peq2_db','peq3_db','peq4_db','peq5_db','peq6_db'];
var _EQ_INITIAL_RETRY_DELAYS_MS=[500,500,1000,1000,2000,3000];
var _EQ_NORMAL_POLL_MS=3000;
var _EQ_DEGRADED_POLL_MS=10000;
var _eqDegraded=false;
var _eqWriteSeq={};
var _eqPendingFields=new Set();
var _eqPollTimer=null;
var _eqPolling=true;
var __EQ_DEFINITIVE_ERRORS=['not_found','appliance_unconfigured','appliance_conflicted','appliance_identity_unavailable'];
var __EQ_TRANSPORT_ERRORS=['remote_timeout','remote_bad_response','appliance_offline'];
function _sleep(ms){return new Promise(function(resolve){setTimeout(resolve,ms);});}

function _fmtDb(v,decimals){var s=v.toFixed(decimals!==undefined?decimals:0);return(v>0?'+':'')+s+' dB';}

function _eqRedirectWithFlash(msg){window.location.href='/?msg='+encodeURIComponent('error:'+msg);}

function _eqHandleError(error){
  var hostname=window.__REMOTE_HOSTNAME||'autostream';
  if(__EQ_DEFINITIVE_ERRORS.indexOf(error)>=0){
    var msgs={
      'not_found':'The selected appliance address is invalid. Returned to this appliance.',
      'appliance_unconfigured':hostname+' is not ready for remote control. Returned to this appliance.',
      'appliance_conflicted':hostname+' has a network identity conflict and cannot be selected safely. Returned to this appliance.',
      'appliance_identity_unavailable':hostname+' cannot currently provide multi-appliance access. Returned to this appliance.'
    };
    _eqRedirectWithFlash(msgs[error]||(hostname+' is unavailable. Returned to this appliance.'));
    return true;
  }
  if(__EQ_TRANSPORT_ERRORS.indexOf(error)>=0){
    _eqDegraded=true;
    return false;
  }
  return false;
}

function _saveEqField(field,value){
  if(!_eqWriteSeq[field])_eqWriteSeq[field]=0;
  var seq=++_eqWriteSeq[field];
  _eqPendingFields.add(field);
  fetch(window.__SAVE_URL,{
    method:'POST',credentials:'same-origin',
    signal:AbortSignal.timeout(5000),
    headers:{'Content-Type':'application/json','X-CSRF-Token':window.__CSRF||''},
    body:JSON.stringify({field:field,value:value})
  }).then(function(r){return r.json();}).then(function(d){
    if(_eqWriteSeq[field]!==seq)return;
    _eqPendingFields.delete(field);
    if(!d||!d.ok){var err=(d&&d.error)||'remote_bad_response';_eqHandleError(err);}
    else{_eqDegraded=false;}
  }).catch(function(e){
    if(_eqWriteSeq[field]!==seq)return;
    _eqPendingFields.delete(field);
    _eqDegraded=true;
  });
}

function syncOutputGain(value){
  var v=parseFloat(value);
  var el=document.getElementById('output_gain_db_val');
  if(el)el.textContent=_fmtDb(v,1);
  _saveEqField('gain_db',v);
}

function syncOutputPeq(key,value){
  var v=parseInt(value,10);
  var el=document.getElementById(key+'_val');
  if(el)el.textContent=_fmtDb(v,0);
  _saveEqField(key,v);
  if(typeof _drawEqCurve==='function')_drawEqCurve();
}

function setOutputAutoTrim(enabled){
  _saveEqField('auto_trim_enabled',enabled?'true':'false');
  var el=document.getElementById('output_trim_status');
  if(!el)return;
  if(!enabled){el.style.display='none';el.textContent='';}
  else{el.style.display='';el.textContent='Calculating\u2026';_pollTrimStatus();}
}

function resetEq(){
  fetch(window.__RESET_URL,{
    method:'POST',credentials:'same-origin',
    signal:AbortSignal.timeout(5000),
    headers:{'Content-Type':'application/json','X-CSRF-Token':window.__CSRF||''},
    body:'{}'
  }).then(function(r){return r.json();}).then(function(d){
    if(!d||!d.ok){var err=(d&&d.error)||'remote_bad_response';_eqHandleError(err);return;}
    _eqDegraded=false;
    _EQ_BAND_KEYS.forEach(function(key){
      var sl=document.getElementById(key);if(sl)sl.value=0;
      var vl=document.getElementById(key+'_val');if(vl)vl.textContent='0 dB';
    });
    if(typeof _drawEqCurve==='function')_drawEqCurve();
  }).catch(function(){
    _eqDegraded=true;
  });
}

function _pollTrimStatus(){
  fetch(window.__STATUS_URL,{credentials:'same-origin',signal:AbortSignal.timeout(5000)})
    .then(function(r){return r.json();})
    .then(function(d){
      if(!d||!d.ok){
        var err=(d&&d.error)||'remote_bad_response';
        if(err!=='remote_backoff')_eqHandleError(err);
        return;
      }
      _eqDegraded=false;
      var el=document.getElementById('output_trim_status');if(!el)return;
      var cb=document.getElementById('output_auto_trim');
      if(!cb||!cb.checked){el.style.display='none';el.textContent='';return;}
      el.style.display='';
      var db=parseFloat(d.output_auto_trim_db);
      el.textContent='Auto-trim: '+(Number.isFinite(db)?db.toFixed(1)+' dB applied':'unavailable');
    })
    .catch(function(){
      _eqDegraded=true;
    });
}

async function _pollFullEqState(){
  if(!_eqPolling||document.hidden)return;
  try{
    var r=await fetch(window.__POLL_URL,{cache:'no-store',signal:AbortSignal.timeout(5000)});
    var data=await r.json();
    if(!data||!data.ok){
      var err=(data&&data.error)||'remote_bad_response';
      if(__EQ_DEFINITIVE_ERRORS.indexOf(err)>=0){_eqHandleError(err);return;}
      _eqDegraded=true;
    }else{
      _eqDegraded=false;
      renderEqFromState(data);
    }
  }catch(e){
    _eqDegraded=true;
  }
  _scheduleEqPoll();
}

function _scheduleEqPoll(){
  if(_eqPollTimer)clearTimeout(_eqPollTimer);
  _eqPollTimer=setTimeout(_pollFullEqState,_eqDegraded?_EQ_DEGRADED_POLL_MS:_EQ_NORMAL_POLL_MS);
}

function renderEqFromState(data){
  var bandContainer=document.getElementById('eq-bands-container');
  var gainSection=document.getElementById('eq-gain-section');
  var loading=document.getElementById('eq-loading-msg');
  var resetBtn=document.getElementById('eq-flat-btn');
  if(loading)loading.hidden=true;
  if(resetBtn)resetBtn.disabled=false;
  if(bandContainer&&!bandContainer.querySelector('input')&&typeof _EQ_BANDS!=='undefined'){
    bandContainer.innerHTML='';
    _EQ_BANDS.forEach(function(b){
      var key=b.key;var label=b.label||(b.freq_hz+' Hz');
      var val=data[key]!==undefined?parseFloat(data[key]):0;
      var sign=val>0?'+':'';
      var col=document.createElement('div');col.className='eq-band';
      col.innerHTML='<span class="eq-band-freq">'+label+'</span>'+
        '<input type="range" class="eq-band-slider" min="-12" max="12" step="1"'+
        ' id="'+key+'" value="'+val.toFixed(0)+'"'+
        ' oninput="syncOutputPeq(\''+key+'\',this.value)">'+
        '<span class="eq-band-val" id="'+key+'_val">'+sign+val.toFixed(0)+' dB</span>';
      bandContainer.appendChild(col);
    });
  }else if(bandContainer){
    _EQ_BAND_KEYS.forEach(function(key){
      if(_eqPendingFields.has(key))return;
      var sl=document.getElementById(key);
      if(!sl||sl===document.activeElement)return;
      var v=data[key]!==undefined?parseInt(data[key],10):0;
      if(String(sl.value)!==String(v)){
        sl.value=String(v);
        var lbl=document.getElementById(key+'_val');
        if(lbl)lbl.textContent=_fmtDb(v,0);
      }
    });
  }
  if(gainSection&&!gainSection.querySelector('input')){
    var gainDb=data.gain_db!==undefined?parseFloat(data.gain_db):0;
    var autoTrim=!!data.auto_trim_enabled;
    var gsign=gainDb>0?'+':'';
    gainSection.innerHTML=
      '<div class="eq-auto-trim-row">'+
      '<div class="eq-auto-trim-labels">'+
      '<div class="eq-auto-trim-title">Automatically trim gain</div>'+
      '<div class="eq-auto-trim-subtitle">Prevent clipping by adjusting output level automatically</div>'+
      '<div class="eq-auto-trim-subtitle" id="output_trim_status"'+(autoTrim?'':' style="display:none;"')+'>'+
      (autoTrim?'Calculating\u2026':'')+
      '</div></div>'+
      '<label class="output-toggle" style="flex-shrink:0;margin-top:2px;">'+
      '<input type="checkbox" id="output_auto_trim"'+(autoTrim?' checked':'')+
      ' onchange="setOutputAutoTrim(this.checked)"><span class="switch"></span></label>'+
      '</div>'+
      '<div class="eq-gain-row">'+
      '<span class="eq-gain-label">Output gain</span>'+
      '<span class="eq-gain-value" id="output_gain_db_val">'+gsign+gainDb.toFixed(1)+' dB</span>'+
      '</div>'+
      '<input type="range" min="-12" max="12" step="0.5" id="output_gain_db"'+
      ' value="'+gainDb.toFixed(1)+'" oninput="syncOutputGain(this.value)">'+
      '<div class="eq-gain-ticks"><span>-12 dB</span><span>0 dB</span><span>+12 dB</span></div>';
  }else if(gainSection){
    if(!_eqPendingFields.has('gain_db')){
      var gs=document.getElementById('output_gain_db');
      if(gs&&gs!==document.activeElement&&data.gain_db!==undefined){
        var gv=parseFloat(data.gain_db);
        var gvStr=gv.toFixed(1);
        if(gs.value!==gvStr){
          gs.value=gvStr;
          var gvEl=document.getElementById('output_gain_db_val');
          if(gvEl)gvEl.textContent=_fmtDb(gv,1);
        }
      }
    }
    if(!_eqPendingFields.has('auto_trim_enabled')){
      var cbTrim=document.getElementById('output_auto_trim');
      if(cbTrim&&data.auto_trim_enabled!==undefined){
        cbTrim.checked=!!data.auto_trim_enabled;
        if(!data.auto_trim_enabled){
          var trimSt=document.getElementById('output_trim_status');
          if(trimSt){trimSt.style.display='none';trimSt.textContent='';}
        }
      }
    }
  }
  if(data.output_auto_trim_db!==undefined){
    var trimEl=document.getElementById('output_trim_status');
    var cbAt=document.getElementById('output_auto_trim');
    if(trimEl&&cbAt&&cbAt.checked){
      trimEl.style.display='';
      var trimDb=parseFloat(data.output_auto_trim_db);
      trimEl.textContent='Auto-trim: '+(Number.isFinite(trimDb)?trimDb.toFixed(1)+' dB applied':'unavailable');
    }
  }
  if(typeof _drawEqCurve==='function')_drawEqCurve();
}

async function _loadInitialEqState(){
  var delays=_EQ_INITIAL_RETRY_DELAYS_MS;
  for(var attempt=0;attempt<=delays.length;attempt++){
    try{
      var r=await fetch(window.__POLL_URL,{cache:'no-store',signal:AbortSignal.timeout(5000)});
      var data=await r.json();
      if(data&&data.ok){
        _eqDegraded=false;
        renderEqFromState(data);
        var cb=document.getElementById('output_auto_trim');
        if(cb&&cb.checked)_pollTrimStatus();
        _scheduleEqPoll();
        return;
      }
      var err=(data&&data.error)||'remote_bad_response';
      if(__EQ_DEFINITIVE_ERRORS.indexOf(err)>=0){_eqHandleError(err);return;}
      if(attempt<delays.length){
        var waitMs=delays[attempt];
        if(data&&data.retry_after)waitMs=Math.max(waitMs,data.retry_after*1000);
        await _sleep(waitMs);
      }
    }catch(e){
      if(attempt<delays.length)await _sleep(delays[attempt]);
    }
  }
  _scheduleEqPoll();
}

function initApplianceSelector(){
  var btn=document.getElementById('appliance-selector-btn');
  var dd=document.getElementById('appliance-selector-dropdown');
  if(!btn||!dd)return;
  btn.addEventListener('click',function(e){
    e.stopPropagation();var open=!dd.hidden;dd.hidden=open;
    btn.setAttribute('aria-expanded',String(!open));
    if(!open)refreshApplianceSelector();
  });
  document.addEventListener('click',function(){
    if(!dd.hidden){dd.hidden=true;btn.setAttribute('aria-expanded','false');}
  });
  dd.addEventListener('keydown',function(e){
    var opts=Array.from(dd.querySelectorAll('.appliance-selector-option'));
    var idx=opts.indexOf(document.activeElement);
    if(e.key==='ArrowDown'){e.preventDefault();var n=opts[idx+1]||opts[0];if(n)n.focus();}
    else if(e.key==='ArrowUp'){e.preventDefault();var p=opts[idx-1]||opts[opts.length-1];if(p)p.focus();}
    else if(e.key==='Escape'){dd.hidden=true;btn.setAttribute('aria-expanded','false');btn.focus();}
  });
}
function updateSelectorFromAppliances(appliances,currentId,currentPage){
  var dd=document.getElementById('appliance-selector-dropdown');
  var nameEl=document.getElementById('appliance-selector-current');
  if(!dd)return;dd.innerHTML='';var dividerAdded=false;
  appliances.forEach(function(a){
    var isBound=!!a.is_bound;
    if(!isBound&&!dividerAdded){dividerAdded=true;var divEl=document.createElement('div');divEl.className='appliance-selector-divider';divEl.setAttribute('role','separator');divEl.setAttribute('aria-hidden','true');dd.appendChild(divEl);}
    var href=currentPage==='equaliser'?(a.equaliser_path||'/a/'+a.id+'/equaliser'):(a.home_path||(isBound?'/':'/a/'+a.id+'/'));
    var opt=document.createElement('a');opt.href=href;opt.setAttribute('role','option');
    opt.setAttribute('aria-selected',a.id===currentId?'true':'false');
    opt.className='appliance-selector-option'+(a.id===currentId?' appliance-selector-option-active':'');
    if(isBound)opt.style.fontWeight='700';opt.textContent=String(a.hostname||'autostream');dd.appendChild(opt);
  });
  var cur=appliances.find(function(a){return a.id===currentId;});
  if(nameEl&&cur)nameEl.textContent=String(cur.hostname||'autostream');
}
window.addEventListener('DOMContentLoaded',function(){
  initApplianceSelector();refreshApplianceSelector();
  setInterval(function(){if(!document.hidden)refreshApplianceSelector();},15000);
  document.addEventListener('visibilitychange',function(){
    if(!document.hidden){_eqPolling=true;_eqDegraded=false;_pollFullEqState();refreshApplianceSelector();}
    else{_eqPolling=false;if(_eqPollTimer){clearTimeout(_eqPollTimer);_eqPollTimer=null;}}
  });
  _loadInitialEqState();
});
