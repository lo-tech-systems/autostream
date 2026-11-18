var pageData = (function () {
  try { return JSON.parse(document.getElementById('page-data').textContent); }
  catch (e) { return {}; }
})();
window.__LOCAL_ID = pageData.local_id;
window.__SELECTOR_CURRENT_PAGE = pageData.selector_current_page;
window.__POLL_URL = pageData.poll_url;

var _csrfToken = document.getElementById('_csrfField').value;
var _EQ_BAND_KEYS = ['peq1_db','peq2_db','peq3_db','peq4_db','peq5_db','peq6_db'];
var _eqPollTimer = null;
var _eqWriteSeq = {};
var _eqPendingFields = new Set();

function _fmtDb(v, decimals) {
  var s = v.toFixed(decimals !== undefined ? decimals : 0);
  return (v > 0 ? '+' : '') + s + ' dB';
}

function _saveEqField(field, value) {
  if (!_eqWriteSeq[field]) _eqWriteSeq[field] = 0;
  var seq = ++_eqWriteSeq[field];
  _eqPendingFields.add(field);
  fetch('/api/output_eq/config', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': _csrfToken},
    body: JSON.stringify({field: field, value: value})
  }).then(function(r) { return r.json(); }).then(function(d) {
    if (_eqWriteSeq[field] !== seq) return;
    _eqPendingFields.delete(field);
    if (!d.ok) { console.warn('Output EQ save failed:', field, d.error); }
  }).catch(function(e) {
    if (_eqWriteSeq[field] !== seq) return;
    _eqPendingFields.delete(field);
    console.warn('Output EQ save error:', e);
  });
}

function syncOutputGain(value) {
  var v = parseFloat(value);
  document.getElementById('output_gain_db_val').textContent = _fmtDb(v, 1);
  _saveEqField('gain_db', v);
}

function syncOutputPeq(key, value) {
  var v = parseInt(value, 10);
  document.getElementById(key + '_val').textContent = _fmtDb(v, 0);
  _saveEqField(key, v);
  _drawEqCurve();
}

function setOutputAutoTrim(enabled) {
  _saveEqField('auto_trim_enabled', enabled ? 'true' : 'false');
  var el = document.getElementById('output_trim_status');
  if (!el) return;
  if (!enabled) {
    el.style.display = 'none';
    el.textContent = '';
  } else {
    el.style.display = '';
    el.textContent = 'Calculating\u2026';
  }
}

function resetEq() {
  fetch('/api/output_eq/reset', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': _csrfToken},
    body: '{}'
  }).then(function(r) { return r.json(); }).then(function(d) {
    if (!d.ok) { console.warn('EQ reset failed:', d.error); return; }
    _EQ_BAND_KEYS.forEach(function(key) {
      var slider = document.getElementById(key);
      if (slider) slider.value = 0;
      var val = document.getElementById(key + '_val');
      if (val) val.textContent = '0 dB';
    });
    _drawEqCurve();
  }).catch(function(e) { console.warn('EQ reset error:', e); });
}

function _scheduleEqPoll() {
  if (_eqPollTimer) clearTimeout(_eqPollTimer);
  _eqPollTimer = setTimeout(_pollFullEqState, 3000);
}

async function _pollFullEqState() {
  if (document.hidden) { _scheduleEqPoll(); return; }
  try {
    var r = await fetch(window.__POLL_URL, {cache: 'no-store', signal: AbortSignal.timeout(5000)});
    var data = await r.json();
    if (data && data.ok) { _updateEqFromPoll(data); }
  } catch(e) {}
  _scheduleEqPoll();
}

function _updateEqFromPoll(data) {
  _EQ_BAND_KEYS.forEach(function(key) {
    if (_eqPendingFields.has(key)) return;
    var sl = document.getElementById(key);
    if (!sl || sl === document.activeElement) return;
    var v = data[key] !== undefined ? parseInt(data[key], 10) : null;
    if (v !== null && String(sl.value) !== String(v)) {
      sl.value = String(v);
      var lbl = document.getElementById(key + '_val');
      if (lbl) lbl.textContent = _fmtDb(v, 0);
    }
  });
  if (!_eqPendingFields.has('gain_db')) {
    var gs = document.getElementById('output_gain_db');
    if (gs && gs !== document.activeElement && data.gain_db !== undefined) {
      var gv = parseFloat(data.gain_db);
      var gvStr = gv.toFixed(1);
      if (gs.value !== gvStr) {
        gs.value = gvStr;
        var gvEl = document.getElementById('output_gain_db_val');
        if (gvEl) gvEl.textContent = _fmtDb(gv, 1);
      }
    }
  }
  if (!_eqPendingFields.has('auto_trim_enabled')) {
    var cb = document.getElementById('output_auto_trim');
    if (cb && data.auto_trim_enabled !== undefined) {
      cb.checked = !!data.auto_trim_enabled;
      if (!data.auto_trim_enabled) {
        var trimSt = document.getElementById('output_trim_status');
        if (trimSt) { trimSt.style.display = 'none'; trimSt.textContent = ''; }
      }
    }
  }
  if (data.output_auto_trim_db !== undefined) {
    var trimEl = document.getElementById('output_trim_status');
    var cbAt = document.getElementById('output_auto_trim');
    if (trimEl && cbAt && cbAt.checked) {
      trimEl.style.display = '';
      var trimDb = parseFloat(data.output_auto_trim_db);
      trimEl.textContent = 'Auto-trim: ' + (Number.isFinite(trimDb) ? trimDb.toFixed(1) + ' dB applied' : 'unavailable');
    }
  }
  if (typeof _drawEqCurve === 'function') _drawEqCurve();
}

document.addEventListener('DOMContentLoaded', function() {
  _drawEqCurve();
  initApplianceSelector();
  refreshApplianceSelector();
  setInterval(function(){if(!document.hidden)refreshApplianceSelector();}, 15000);
  document.addEventListener('visibilitychange', function(){
    if (!document.hidden) { _pollFullEqState(); refreshApplianceSelector(); }
    else {
      if (_eqPollTimer) { clearTimeout(_eqPollTimer); _eqPollTimer = null; }
    }
  });
  _pollFullEqState();
});

function initApplianceSelector(){
  var btn=document.getElementById('appliance-selector-btn');
  var dd=document.getElementById('appliance-selector-dropdown');
  if(!btn||!dd) return;
  btn.addEventListener('click',function(e){
    e.stopPropagation();
    var open=!dd.hidden;
    dd.hidden=open;
    btn.setAttribute('aria-expanded',String(!open));
    if(!open) refreshApplianceSelector();
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
  if(!dd) return;
  dd.innerHTML='';
  var dividerAdded=false;
  appliances.forEach(function(a){
    var isBound=!!a.is_bound;
    if(!isBound&&!dividerAdded){
      dividerAdded=true;
      var divEl=document.createElement('div');
      divEl.className='appliance-selector-divider';
      divEl.setAttribute('role','separator');
      divEl.setAttribute('aria-hidden','true');
      dd.appendChild(divEl);
    }
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
  });
  var cur=appliances.find(function(a){return a.id===currentId;});
  if(nameEl&&cur) nameEl.textContent=String(cur.hostname||'autostream');
}

