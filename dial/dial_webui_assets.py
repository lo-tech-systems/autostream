"""dial_webui_assets.py — Setup page HTML/CSS/JS served by the dial HTTP server.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

This module contains the dial's configuration web UI as a Python string
constant.  It is served directly by the Python HTTP server on port 7842
(proxied through nginx on port 80).  No static-file nginx config is needed.
"""

SETUP_PAGE_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>autostream dial</title>
  <style>
    :root {
      --bg:       #0f0f13;
      --card:     #1a1a22;
      --border:   #2a2a38;
      --text:     #e0e0e8;
      --muted:    #888;
      --accent:   #4a9eff;
      --ok:       #28a745;
      --err:      #dc3545;
      --r:        8px;
    }
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,sans-serif;
         font-size:15px;min-height:100vh}
    .hdr{background:var(--card);border-bottom:1px solid var(--border);padding:1rem 1.25rem}
    .hdr-t{font-size:1.05rem;font-weight:600}
    .hdr-s{font-size:0.75rem;color:var(--muted);margin-top:0.15rem}
    .main{max-width:520px;margin:1.5rem auto;padding:0 1rem}
    .card{background:var(--card);border:1px solid var(--border);border-radius:var(--r);
          margin-bottom:1rem;overflow:hidden}
    .ct{padding:0.65rem 1rem;font-size:0.78rem;font-weight:600;letter-spacing:.06em;
        text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border)}
    .row{display:flex;align-items:center;gap:.75rem;padding:.7rem 1rem;
         border-bottom:1px solid var(--border)}
    .row:last-child{border-bottom:none}
    .lbl{flex:0 0 110px;font-size:.85rem;color:var(--muted)}
    .val{flex:1}
    input[type=text],input[type=number],input[type=password]{
      background:#0f0f18;border:1px solid var(--border);border-radius:4px;
      color:var(--text);padding:.38rem .6rem;font-size:.85rem;width:100%}
    input:focus{outline:none;border-color:var(--accent)}
    .btn{background:var(--accent);color:#fff;border:none;border-radius:4px;
         padding:.38rem .8rem;font-size:.8rem;font-weight:600;cursor:pointer;white-space:nowrap}
    .btn:hover{opacity:.88}
    .btn:disabled{opacity:.45;cursor:default}
    .btn.sec{background:var(--border);color:var(--text)}
    .btn.danger{background:var(--err)}
    .btns{display:flex;gap:.4rem;flex-wrap:wrap}
    .msg{font-size:.78rem;padding:.4rem 1rem;min-height:1.6rem;color:var(--muted)}
    .msg.ok{color:var(--ok)}.msg.err{color:var(--err)}
    label.tog{display:flex;align-items:center;gap:.5rem;cursor:pointer;font-size:.85rem}
    /* modal */
    .mo{display:none;position:fixed;inset:0;background:rgba(0,0,0,.72);z-index:99;
        align-items:center;justify-content:center}
    .mo.show{display:flex}
    .mp{background:var(--card);border:1px solid var(--border);border-radius:var(--r);
        padding:1.25rem;min-width:290px;max-width:380px;width:90%}
    .mp h3{font-size:.95rem;margin-bottom:.6rem}
    .mp p{font-size:.82rem;color:var(--muted);margin-bottom:.7rem}
    .mp input{margin-bottom:.45rem}
    .me{color:var(--err);font-size:.78rem;min-height:1.2em}
    .mf{display:flex;gap:.4rem;justify-content:flex-end;margin-top:.7rem}
  </style>
</head>
<body>
<div class="hdr">
  <div class="hdr-t">autostream dial</div>
  <div class="hdr-s" id="hdr-s">Loading…</div>
</div>
<div class="main">

  <div class="card">
    <div class="ct">Device</div>
    <div class="row">
      <div class="lbl">Name</div>
      <div class="val"><input type="text" id="c-name" maxlength="64" placeholder="My Dial"></div>
    </div>
    <div class="row">
      <div class="lbl">Step</div>
      <div class="val" style="display:flex;align-items:center;gap:.5rem">
        <input type="number" id="c-step" min="1" max="10" style="width:68px">
        <span style="font-size:.82rem;color:var(--muted)">% per click</span>
      </div>
    </div>
    <div class="row">
      <div class="lbl">Auto-update</div>
      <div class="val">
        <label class="tog">
          <input type="checkbox" id="c-auto">
          <span>Weekly updates</span>
        </label>
      </div>
    </div>
    <div class="row" style="justify-content:flex-end">
      <button class="btn sec" onclick="saveConfig()">Save</button>
    </div>
    <div class="msg" id="m-cfg"></div>
  </div>

  <div class="card">
    <div class="ct">PIN</div>
    <div class="row">
      <div class="lbl">Status</div>
      <div class="val" id="pin-st" style="font-size:.85rem">—</div>
    </div>
    <div class="row">
      <div class="btns">
        <button class="btn sec" id="b-pin-set"    onclick="openPin('set')">Set PIN</button>
        <button class="btn sec" id="b-pin-change" onclick="openPin('change')" style="display:none">Change PIN</button>
        <button class="btn sec danger" id="b-pin-rm" onclick="openPin('remove')" style="display:none">Remove PIN</button>
      </div>
    </div>
    <div class="msg" id="m-pin"></div>
  </div>

  <div class="card">
    <div class="ct">Firmware</div>
    <div class="row">
      <div class="lbl">Version</div>
      <div class="val" id="fw-ver" style="font-size:.85rem">—</div>
    </div>
    <div class="row">
      <div class="lbl">Update</div>
      <div class="val" style="display:flex;align-items:center;gap:.75rem;flex-wrap:wrap">
        <button class="btn" id="b-upd" onclick="triggerUpdate()">Check for update</button>
        <span id="upd-st" style="font-size:.8rem;color:var(--muted)"></span>
      </div>
    </div>
    <div class="msg" id="m-fw"></div>
  </div>

</div>

<!-- PIN modal -->
<div class="mo" id="pin-mo">
  <div class="mp">
    <h3 id="pm-title">Set PIN</h3>
    <p  id="pm-msg"></p>
    <input type="password" id="pm-cur" placeholder="Current PIN" autocomplete="current-password" style="display:none">
    <input type="password" id="pm-new" placeholder="New PIN (4–8 digits)" autocomplete="new-password">
    <div class="me" id="pm-err"></div>
    <div class="mf">
      <button class="btn sec" onclick="closePin()">Cancel</button>
      <button class="btn" id="pm-ok" onclick="applyPin()">Apply</button>
    </div>
  </div>
</div>

<script>
var _pinSet = false, _pinMode = 'set', _pend = null, _poll = null;

function msg(id, t, ok) {
  var e = document.getElementById(id);
  e.textContent = t;
  e.className = 'msg' + (ok === true ? ' ok' : ok === false ? ' err' : '');
}

async function loadCfg() {
  try {
    var r = await fetch('/configure'), d = await r.json();
    _pinSet = !!d.pin_set;
    document.getElementById('c-name').value  = d.name         || '';
    document.getElementById('c-step').value  = d.step_percent || 2;
    document.getElementById('c-auto').checked = !!d.auto_update;
    document.getElementById('fw-ver').textContent = d.version || 'unknown';
    document.getElementById('hdr-s').textContent =
      (d.name || 'unnamed') + ' · ' + (d.version || 'unknown');
    pinUI();
  } catch(e) {
    document.getElementById('hdr-s').textContent = 'Error loading config';
  }
}

function pinUI() {
  document.getElementById('pin-st').textContent     = _pinSet ? 'Set' : 'Not set';
  document.getElementById('b-pin-set').style.display    = _pinSet ? 'none' : '';
  document.getElementById('b-pin-change').style.display = _pinSet ? '' : 'none';
  document.getElementById('b-pin-rm').style.display     = _pinSet ? '' : 'none';
}

async function loadUpdSt() {
  try {
    var r = await fetch('/update/status'), d = await r.json();
    var el = document.getElementById('upd-st');
    if (d.state === 'running') {
      el.textContent = 'Updating…';
      el.style.color = 'var(--accent)';
      if (!_poll) _poll = setInterval(loadUpdSt, 3000);
    } else if (d.state === 'complete') {
      el.textContent = 'Complete — reload to see changes';
      el.style.color = 'var(--ok)';
      clearInterval(_poll); _poll = null;
    } else if (d.state === 'failed') {
      el.textContent = 'Update failed';
      el.style.color = 'var(--err)';
      clearInterval(_poll); _poll = null;
    } else {
      el.textContent = '';
    }
  } catch(e) {}
}

async function _post(path, body) {
  var r = await fetch(path, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  });
  return [r.status, await r.json()];
}

async function _doSave(body) {
  try {
    var [st, d] = await _post('/configure', body);
    if (d.ok) { msg('m-cfg', 'Saved', true); await loadCfg(); }
    else msg('m-cfg', d.error || 'Save failed', false);
  } catch(e) { msg('m-cfg', 'Network error', false); }
}

async function saveConfig() {
  var name = document.getElementById('c-name').value.trim();
  var step = parseInt(document.getElementById('c-step').value, 10);
  var au   = document.getElementById('c-auto').checked;
  if (!(step >= 1 && step <= 10)) { msg('m-cfg', 'Step must be 1–10', false); return; }
  var body = {name: name, step_percent: step, auto_update: au};
  if (_pinSet) { _pinMode = 'save'; _pend = body; openPin('save'); return; }
  await _doSave(body);
}

function openPin(mode) {
  _pinMode = mode;
  var c = document.getElementById('pm-cur'), n = document.getElementById('pm-new');
  var t = document.getElementById('pm-title'), m = document.getElementById('pm-msg');
  var ok = document.getElementById('pm-ok');
  document.getElementById('pm-err').textContent = '';
  c.value = ''; n.value = '';
  if (mode === 'set') {
    t.textContent = 'Set PIN'; m.textContent = 'Choose a 4–8 digit PIN.';
    c.style.display = 'none'; n.style.display = ''; n.placeholder = 'New PIN (4–8 digits)';
    ok.textContent = 'Set PIN';
  } else if (mode === 'change') {
    t.textContent = 'Change PIN'; m.textContent = 'Enter current PIN, then new PIN.';
    c.style.display = ''; n.style.display = ''; c.placeholder = 'Current PIN';
    n.placeholder = 'New PIN (4–8 digits)'; ok.textContent = 'Change';
  } else if (mode === 'remove') {
    t.textContent = 'Remove PIN'; m.textContent = 'Enter current PIN to remove it.';
    c.style.display = ''; n.style.display = 'none'; c.placeholder = 'Current PIN';
    ok.textContent = 'Remove';
  } else if (mode === 'save') {
    t.textContent = 'PIN Required'; m.textContent = 'Enter your PIN to save changes.';
    c.style.display = ''; n.style.display = 'none'; c.placeholder = 'PIN';
    ok.textContent = 'Save';
  }
  document.getElementById('pin-mo').classList.add('show');
  (c.style.display !== 'none' ? c : n).focus();
}

function closePin() {
  document.getElementById('pin-mo').classList.remove('show');
  _pend = null;
}

async function applyPin() {
  var cur = document.getElementById('pm-cur').value;
  var nw  = document.getElementById('pm-new').value;
  var err = document.getElementById('pm-err');
  err.textContent = '';
  var body;
  if (_pinMode === 'set') {
    if (!/^\d{4,8}$/.test(nw)) { err.textContent = 'PIN must be 4–8 digits'; return; }
    body = {new_pin: nw};
  } else if (_pinMode === 'change') {
    if (!cur) { err.textContent = 'Enter current PIN'; return; }
    if (!/^\d{4,8}$/.test(nw)) { err.textContent = 'New PIN must be 4–8 digits'; return; }
    body = {current_pin: cur, new_pin: nw};
  } else if (_pinMode === 'remove') {
    if (!cur) { err.textContent = 'Enter current PIN'; return; }
    body = {current_pin: cur, new_pin: ''};
  } else if (_pinMode === 'save') {
    closePin();
    if (_pend) { _pend.current_pin = cur; await _doSave(_pend); _pend = null; }
    return;
  }
  try {
    var [st, d] = await _post('/configure', body);
    if (d.ok) {
      closePin();
      msg('m-pin', _pinMode === 'remove' ? 'PIN removed' : 'PIN updated', true);
      await loadCfg();
    } else if (st === 403) {
      err.textContent = 'Incorrect PIN';
    } else if (st === 429) {
      err.textContent = 'Too many attempts — try again later';
    } else {
      err.textContent = d.error || 'Failed';
    }
  } catch(e) { err.textContent = 'Network error'; }
}

async function triggerUpdate() {
  var btn = document.getElementById('b-upd'), st = document.getElementById('upd-st');
  btn.disabled = true;
  st.textContent = 'Starting…'; st.style.color = 'var(--accent)';
  try {
    var [s, d] = await _post('/update', {});
    if (d.ok) {
      msg('m-fw', 'Update scheduled', true);
      _poll = setInterval(loadUpdSt, 3000);
    } else {
      st.textContent = d.error || 'Failed'; st.style.color = 'var(--err)';
      btn.disabled = false;
    }
  } catch(e) { st.textContent = 'Network error'; st.style.color = 'var(--err)'; btn.disabled = false; }
}

document.addEventListener('keydown', function(ev) {
  if (!document.getElementById('pin-mo').classList.contains('show')) return;
  if (ev.key === 'Enter') applyPin();
  if (ev.key === 'Escape') closePin();
});

loadCfg();
loadUpdSt();
</script>
</body>
</html>"""
