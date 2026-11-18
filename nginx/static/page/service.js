var _csrfToken = document.getElementById('_csrfField').value;

// Per-field state for leading+trailing throttle auto-save.
// Each entry: {timer, ctrl, pending} where pending=null means no trailing call queued.
var _autoSaveState = {};

function openServiceDetail(item, idx) {
  document.querySelectorAll('.service-slide-detail .setup-detail-panel').forEach(function(p) {
    p.classList.remove('active');
  });
  var panel = document.getElementById('service-detail-' + item + '-' + idx);
  if (panel) panel.classList.add('active');
  document.getElementById('serviceSlideTrack').classList.add('panel-detail');
  window.scrollTo(0, 0);
}

function closeServiceDetail() {
  document.getElementById('serviceSlideTrack').classList.remove('panel-detail');
  window.scrollTo(0, 0);
}

function _showSaveError(fieldName) {
  var sel = document.querySelector('[name="' + fieldName + '"]');
  if (!sel) return;
  var err = document.createElement('span');
  err.textContent = ' Save failed';
  err.style.cssText = 'color:var(--color-status-danger);font-size:0.85rem;';
  sel.parentNode.appendChild(err);
  setTimeout(function() { if (err.parentNode) err.parentNode.removeChild(err); }, 4000);
}

function _fireSave(name, value) {
  var s = _autoSaveState[name];
  if (!s) return;
  if (s.ctrl) { s.ctrl.abort(); }
  var ctrl = new AbortController();
  s.ctrl = ctrl;
  fetch('/api/service/config', {
    method: 'POST',
    credentials: 'same-origin',
    signal: ctrl.signal,
    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': _csrfToken},
    body: JSON.stringify({field: name, value: value})
  }).then(function(r) { return r.json(); }).then(function(d) {
    if (s.ctrl === ctrl) s.ctrl = null;
    if (!d.ok) { _showSaveError(name); return; }
    if (d.display) { _applyDisplay(d.display, name); }
  }).catch(function(e) {
    if (e.name !== 'AbortError') { _showSaveError(name); }
  });
}

function _autoSaveField(name, value) {
  var s = _autoSaveState[name];
  if (!s) {
    // No suppress window active: fire immediately (leading edge) and open a 300 ms window.
    _autoSaveState[name] = {timer: null, ctrl: null, pending: null};
    s = _autoSaveState[name];
    _fireSave(name, value);
    s.timer = setTimeout(function() {
      var pending = s.pending;
      s.timer = null;
      s.pending = null;
      delete _autoSaveState[name];
      // Trailing call: if a further change arrived during the window, fire it now.
      if (pending !== null) { _autoSaveField(name, pending); }
    }, 300);
  } else {
    // Within suppress window: record latest value for the trailing call.
    s.pending = value;
  }
}

function _applyHoursDisplay(d, item, idx) {
  var liveDiv = document.getElementById(item + '-hours-live-' + idx);
  if (!d.hours_live) {
    if (liveDiv) liveDiv.style.display = 'none';
    return;
  }
  if (liveDiv) liveDiv.style.display = '';
  var el;
  el = document.getElementById(item + '-hours-bar-pct-' + idx);
  if (el) el.textContent = d.hours_bar_pct + '%';
  el = document.getElementById(item + '-hours-bar-fill-' + idx);
  if (el) { el.style.width = d.hours_bar_pct + '%'; el.setAttribute('data-status', d.hours_bar_status); }
  el = document.getElementById(item + '-hours-used-val-' + idx);
  if (el) el.textContent = d.hours_used;
  el = document.getElementById(item + '-hours-remaining-val-' + idx);
  if (el) { el.textContent = d.hours_remaining; el.style.color = d.hours_remaining_warn ? 'var(--color-status-danger)' : ''; }
}

function _applyTimeDisplay(d, item, idx) {
  var liveDiv = document.getElementById(item + '-time-live-' + idx);
  if (!d.time_live) {
    if (liveDiv) liveDiv.style.display = 'none';
    return;
  }
  if (liveDiv) liveDiv.style.display = '';
  var el;
  el = document.getElementById(item + '-time-bar-pct-' + idx);
  if (el) el.textContent = d.time_bar_pct + '%';
  el = document.getElementById(item + '-time-bar-fill-' + idx);
  if (el) { el.style.width = d.time_bar_pct + '%'; el.setAttribute('data-status', d.time_bar_status); }
  el = document.getElementById(item + '-time-age-val-' + idx);
  if (el) el.textContent = d.age;
  el = document.getElementById(item + '-time-remaining-val-' + idx);
  if (el) { el.textContent = d.remaining; el.style.color = d.remaining_warn ? 'var(--color-status-danger)' : ''; }
  el = document.getElementById(item + '-time-due-val-' + idx);
  if (el) el.textContent = d.due;
}

function _applyCardState(d, item, idx) {
  if (d.card_sub === undefined) return;
  var card = document.getElementById('svc-list-card-' + item + '-' + idx);
  if (!card) return;
  var warn = !!d.card_warn;
  card.style.borderColor = warn ? 'var(--color-status-danger)' : '';
  var t = card.querySelector('.setup-list-card-title');
  if (t) t.style.color = warn ? 'var(--color-status-danger)' : '';
  var c = card.querySelector('.setup-list-chevron');
  if (c) c.style.color = warn ? 'var(--color-status-danger)' : '';
  var s = card.querySelector('.setup-list-card-sub');
  if (s) s.textContent = d.card_sub;
}

function _applyDisplay(display, fieldName) {
  // fieldName: "service_{item}_life_{hours|years}_input{idx}"
  var m = fieldName.match(/^service_(\w+)_life_(?:hours|years)_input(\d+)$/);
  if (!m) return;
  var item = m[1], idx = parseInt(m[2], 10);
  if (display.hours_live !== undefined) { _applyHoursDisplay(display, item, idx); }
  if (display.time_live  !== undefined) { _applyTimeDisplay(display, item, idx); }
  _applyCardState(display, item, idx);
}

function _updateResetBtnState(item, idx) {
  var hSel = document.querySelector('[name="service_' + item + '_life_hours_input' + idx + '"]');
  var ySel = document.querySelector('[name="service_' + item + '_life_years_input' + idx + '"]');
  var btn = document.getElementById(item + '-reset-btn-' + idx);
  if (!btn) return;
  var hOff = !hSel || parseInt(hSel.value, 10) === 0;
  var yOff = !ySel || parseInt(ySel.value, 10) === 0;
  btn.disabled = hOff && yOff;
}

function _showServiceConfirm(msg) {
  return new Promise(function(resolve) {
    var m = document.getElementById('svcConfirmModal');
    var title = document.getElementById('svcConfirmTitle');
    var btnOk = document.getElementById('svcConfirmOk');
    var btnCancel = document.getElementById('svcConfirmCancel');
    if (!m || !btnOk || !btnCancel) { resolve(true); return; }
    if (title) title.textContent = msg;
    m.classList.add('show');
    var cleanup = function(val) {
      m.classList.remove('show');
      btnOk.onclick = null; btnCancel.onclick = null;
      resolve(val);
    };
    btnCancel.onclick = function() { cleanup(false); };
    btnOk.onclick    = function() { cleanup(true);  };
  });
}

function doServiceReset(item, idx) {
  var labels = {
    stylus:  'Mark stylus as changed?',
    belt:    'Mark drive belt as replaced?',
    bearing: 'Mark bearing as oiled?'
  };
  var msg = labels[item] || 'Confirm reset?';
  _showServiceConfirm(msg).then(function(confirmed) {
    if (!confirmed) return;
    var btn = document.getElementById(item + '-reset-btn-' + idx);
    if (btn) btn.disabled = true;
    fetch('/api/service/reset', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': _csrfToken},
      body: JSON.stringify({item: item, input: idx})
    }).then(function(r) { return r.json(); }).then(function(d) {
      if (!d.ok) { if (btn) btn.disabled = false; return; }
      var _disp = d.display || {card_sub: 'Tracking on', card_warn: false};
      if (d.display) {
        _applyHoursDisplay(_disp, item, idx);
        _applyTimeDisplay(_disp, item, idx);
        var dateKey = item === 'stylus' ? 'stylus-last-service-val-' : item + '-last-service-val-';
        var dateEl = document.getElementById(dateKey + idx);
        if (dateEl && _disp.last_service) { dateEl.textContent = _disp.last_service; }
      }
      _applyCardState(_disp, item, idx);
      if (d.warning) {
        var notice = document.createElement('span');
        notice.textContent = '\u26a0 Reset not persisted \u2014 may revert on restart';
        notice.style.cssText = 'color:var(--color-status-danger);font-size:0.85rem;display:block;margin-top:0.3rem;';
        if (btn && btn.parentNode) btn.parentNode.appendChild(notice);
        setTimeout(function() { if (notice.parentNode) notice.parentNode.removeChild(notice); }, 8000);
      }
      _updateResetBtnState(item, idx);
      if (btn) {
        btn.style.borderColor = ''; btn.style.background = ''; btn.style.color = '';
        btn.disabled = false;
      }
    }).catch(function() { if (btn) btn.disabled = false; });
  });
}
