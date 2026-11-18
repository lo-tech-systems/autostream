var pageData = (function () {
  try { return JSON.parse(document.getElementById('page-data').textContent); }
  catch (e) { return {}; }
})();
var pageIcons = pageData.icons || {};
window.__PRESET_VOLUME = pageData.preset_volume;
window.__SHOW_INPUT_DETAIL = pageData.show_input_detail;
window.__VU_DELAY_MS = pageData.vu_delay_ms;
window.__ICON_TURNTABLE = pageIcons.turntable;
window.__ICON_BLUETOOTH = pageIcons.bluetooth;
window.__ICON_CD = pageIcons.cd;
window.__ICON_LINE_LEVEL = pageIcons.line_level;
window.__LOCAL_ID = pageData.local_id;
window.__SELECTOR_CURRENT_ID = pageData.selector_current_id;
window.__OUTPUT_URL = pageData.output_url;
window.__REPEAT_URL = pageData.repeat_url;
window.__OUTPUTS_EMPTY_TOLERANCE_MS = pageData.outputs_empty_tolerance_ms;
window.__PIN_PROMPT_FALLBACK = pageData.pin_prompt_fallback;
window.__CONTROL_OTHER_APPLIANCES = pageData.control_other_appliances;

  function normalizeVolume(v){
    const n = Number(v);
    if (!Number.isFinite(n)) return 0;
    return Math.max(0, Math.min(100, Math.round(n)));
  }
  function formatVolume(v){
    return String(normalizeVolume(v)) + '%';
  }
  function updateVolumeLabel(id,v){var s=document.getElementById('vol_label_'+id);if(s)s.textContent=formatVolume(v);}
  function isActiveControl(el) {
    return el && document.activeElement === el;
  }
  // The name on a card, without the state label that follows it.
  function outputCardNameText(el){
    var t = '';
    if (!el) return t;
    for (var n = el.firstChild; n; n = n.nextSibling) {
      if (n.nodeType === 3) t += n.data;
    }
    return t.trim();
  }
  function reorderOutputCards(){
    const list = document.getElementById('outputs-list');
    if (!list) return;
    const cards = Array.from(list.querySelectorAll('.output-card'));
    cards.sort((a, b) => {
      const da = a.getAttribute('data-is-default') === '1' ? 1 : 0;
      const db = b.getAttribute('data-is-default') === '1' ? 1 : 0;
      if (db !== da) return db - da;
      const la = a.querySelector('.output-card-name');
      const lb = b.querySelector('.output-card-name');
      const na = outputCardNameText(la).toLowerCase();
      const nb = outputCardNameText(lb).toLowerCase();
      return na.localeCompare(nb);
    });
    cards.forEach(card => list.appendChild(card));
  }
  // Shows a card's state. `row` is the row the list sent: with it the card also
  // takes its Connecting or offline look and its toggle's disabled state;
  // without it (a tap) those stay as they are, except that a speaker switched
  // off is no longer connecting.
  function updateOutputStateVisual(id, selected, row){
    const cb = document.getElementById('output_enabled_' + id);
    const chip = document.getElementById('output_state_' + id);
    const card = document.getElementById('output_card_' + id);
    const wrap = document.getElementById('output_slider_wrap_' + id);
    if (card && card.getAttribute('data-remote-in-use') === '1') return;
    if (!card && cb && cb.disabled) return;
    const label = document.getElementById('output_label_' + id);
    const sl = document.getElementById('vol_slider_' + id);
    let connecting = card ? card.classList.contains('output-card-connecting') : false;
    let offline = card ? card.classList.contains('output-card-offline') : false;
    if (row) {
      connecting = !!row.connecting;
      offline = !!row.offline;
      if (cb) cb.disabled = !!row.disabled;
    }
    if (!selected) connecting = false;
    if (card) {
      card.classList.toggle('output-card-connecting', connecting);
      card.classList.toggle('output-card-offline', offline);
    }
    if (label) {
      label.textContent = connecting ? ' (Connecting)' : (offline ? ' (offline)' : '');
      label.hidden = !(connecting || offline);
    }
    if (sl) sl.disabled = offline;
    if (chip) {
      chip.textContent = selected ? 'On' : 'Off';
      chip.classList.toggle('on', !!selected);
      chip.classList.toggle('off', !selected);
    }
    if (card) {
      card.classList.toggle('output-card-on', !!selected);
      card.classList.toggle('output-card-off', !selected);
    }
    if (wrap) {
      wrap.hidden = !selected;
    }
  }

  // Opens the PIN dialog and resolves with the digits entered, or null on
  // Cancel/Escape. `note` is a line of text under the input (empty hides it).
  // The input only accepts 4 to 8 digits and OK stays disabled until four
  // have been typed.
  function showPinModal(outputName, note){
    return new Promise((resolve) => {
      const m = document.getElementById('pinModal');
      const title = document.getElementById('pinModalTitle');
      const input = document.getElementById('pinModalInput');
      const btnOk = document.getElementById('pinModalOk');
      const btnCancel = document.getElementById('pinModalCancel');
      const noteEl = document.getElementById('pinModalNote');
      if (!m || !input || !btnOk || !btnCancel) {
        // Fallback to native prompt if our modal is missing for any reason.
        const fallbackLabel = window.__PIN_PROMPT_FALLBACK || 'Enter PIN';
        const v = window.prompt(fallbackLabel + (outputName ? ' ('+outputName+')' : '') + ':', '');
        const t = v ? String(v).trim() : '';
        resolve(/^[0-9]{4,8}$/.test(t) ? t : null);
        return;
      }
      title.textContent = outputName ? ('Enter PIN for ' + outputName) : 'Enter PIN';
      if (noteEl) {
        noteEl.textContent = note || '';
        noteEl.hidden = !note;
      }
      input.value = '';
      input.disabled = false;
      btnOk.disabled = true;
      m.classList.add('show');
      // iOS: defer focus slightly so the keyboard reliably appears.
      setTimeout(() => { try { input.focus(); } catch (e) {} }, 60);

      const cleanup = (val) => {
        m.classList.remove('show');
        btnOk.onclick = null;
        btnCancel.onclick = null;
        input.onkeydown = null;
        input.oninput = null;
        resolve(val);
      };
      input.oninput = () => {
        const digits = String(input.value || '').replace(/[^0-9]/g, '').slice(0, 8);
        if (input.value !== digits) input.value = digits;
        btnOk.disabled = digits.length < 4;
      };
      btnCancel.onclick = () => cleanup(null);
      btnOk.onclick = () => {
        const v = (input.value || '').trim();
        if (!/^[0-9]{4,8}$/.test(v)) return;
        cleanup(v);
      };
      input.onkeydown = (ev) => {
        if (ev.key === 'Enter') { ev.preventDefault(); if (!btnOk.disabled) btnOk.click(); }
        else if (ev.key === 'Escape') { ev.preventDefault(); btnCancel.click(); }
      };
    });
  }

  // Shown after the appliance limits PIN attempts: the dialog stays open
  // with the input and OK disabled and counts the seconds down. Resolves
  // true when the wait is over, false if the user cancels.
  function showPinWait(outputName, seconds){
    return new Promise((resolve) => {
      const m = document.getElementById('pinModal');
      const title = document.getElementById('pinModalTitle');
      const input = document.getElementById('pinModalInput');
      const btnOk = document.getElementById('pinModalOk');
      const btnCancel = document.getElementById('pinModalCancel');
      const noteEl = document.getElementById('pinModalNote');
      let left = Math.max(1, parseInt(seconds, 10) || 1);
      if (!m || !input || !btnOk || !btnCancel) {
        setTimeout(() => resolve(true), left * 1000);
        return;
      }
      const label = () => 'Wait ' + left + (left === 1 ? ' second' : ' seconds') + ' before retry';
      title.textContent = outputName ? ('Enter PIN for ' + outputName) : 'Enter PIN';
      if (noteEl) { noteEl.textContent = label(); noteEl.hidden = false; }
      input.value = '';
      input.disabled = true;
      btnOk.disabled = true;
      m.classList.add('show');

      let timer = null;
      const onKey = (ev) => {
        if (ev.key === 'Escape') { ev.preventDefault(); btnCancel.click(); }
      };
      const cleanup = (val) => {
        if (timer !== null) { clearInterval(timer); timer = null; }
        document.removeEventListener('keydown', onKey);
        m.classList.remove('show');
        btnOk.onclick = null;
        btnCancel.onclick = null;
        resolve(val);
      };
      btnOk.onclick = null;
      btnCancel.onclick = () => cleanup(false);
      document.addEventListener('keydown', onKey);
      timer = setInterval(() => {
        left -= 1;
        if (left <= 0) { cleanup(true); return; }
        if (noteEl) noteEl.textContent = label();
      }, 1000);
    });
  }

  function computeMasterVolume(){
    var sum=0, count=0;
    document.querySelectorAll('.output-card').forEach(function(card){
      var id=card.getAttribute('data-output-id');
      if(!id) return;
      var cb=document.getElementById('output_enabled_'+id);
      var sl=document.getElementById('vol_slider_'+id);
      if(cb && cb.checked && sl){sum+=normalizeVolume(sl.value);count++;}
    });
    return count>0 ? Math.round(sum/count) : null;
  }
  function updateMasterVolumeCard(){
    var card=document.getElementById('master-volume-card');
    var sl=document.getElementById('master_vol_slider');
    if(!card||!sl) return;
    var v=computeMasterVolume();
    var inactive=(v===null);
    var val=inactive?(window.__PRESET_VOLUME||20):v;
    card.classList.toggle('master-volume-inactive',inactive);
    sl.disabled=inactive;
    if(String(sl.value)!==String(val)) sl.value=String(val);
  }
  function onMasterVolumeDragStart(){
    var sl=document.getElementById('master_vol_slider');
    if(!sl||sl.disabled) return;
    var snaps={};
    document.querySelectorAll('.output-card').forEach(function(card){
      var id=card.getAttribute('data-output-id');
      if(!id) return;
      var cb=document.getElementById('output_enabled_'+id);
      var vs=document.getElementById('vol_slider_'+id);
      if(cb&&cb.checked&&vs) snaps[id]=normalizeVolume(vs.value);
    });
    window.__MASTER_DRAG_SNAPSHOTS=snaps;
    window.__MASTER_DRAG_BASE=normalizeVolume(sl.value);
  }
  function _applyMasterScale(newMaster){
    var snaps=window.__MASTER_DRAG_SNAPSHOTS||{};
    var base=typeof window.__MASTER_DRAG_BASE==='number'?window.__MASTER_DRAG_BASE:0;
    var nm=normalizeVolume(newMaster);
    Object.keys(snaps).forEach(function(id){
      var sl=document.getElementById('vol_slider_'+id);
      if(!sl) return;
      var nv=base>0?Math.round(snaps[id]*nm/base):nm;
      nv=Math.max(0,Math.min(100,nv));
      sl.value=String(nv);
      updateVolumeLabel(id,nv);
    });
  }
  function onMasterVolumeInput(v){
    _applyMasterScale(v);
  }
  function onMasterVolumeChange(v){
    _applyMasterScale(v);
    var snaps=window.__MASTER_DRAG_SNAPSHOTS||{};
    Object.keys(snaps).forEach(function(id){ sendUpdate(id); });
    window.__MASTER_DRAG_SNAPSHOTS={};
  }

  function handleHomeSessionRejected(response){
    const status = Number(response && response.status);
    if (status !== 401 && status !== 403) return false;
    if (window.__HOME_SESSION_REFRESHING) return true;
    window.__HOME_SESSION_REFRESHING = true;
    window.location.reload();
    return true;
  }

  async function postOutputUpdate(id, selected, volume){
    const r = await fetch(window.__OUTPUT_URL || '/api/output',{
      method:'POST',
      credentials:'same-origin',
      signal: AbortSignal.timeout(5000),
      headers:{
        'Content-Type':'application/json',
        'X-CSRF-Token':window.__CSRF||''
      },
      body:JSON.stringify({
        id:id,
        selected:!!selected,
        volume:parseInt(volume||0,10)||0,
        csrf_token: window.__CSRF||''
      })
    });
    if (handleHomeSessionRejected(r)) return { ok:false, _http:r.status, session_rejected:true };
    // Server replies JSON for this endpoint (including failures)
    let j = null;
    try { j = await r.json(); } catch (e) { j = { ok: r.ok }; }
    j._http = r.status;
    return j;
  }

  async function postPairAndEnable(id, pin, volume) {
    const r = await fetch(window.__OUTPUT_URL || '/api/output', {
      method:'POST',
      credentials:'same-origin',
      signal: AbortSignal.timeout(5000),
      headers:{
        'Content-Type':'application/json',
        'X-CSRF-Token':window.__CSRF||''
      },
      body:JSON.stringify({
        id:id,
        op:'pin',
        pin: String(pin||'').trim(),
        selected: true,
        volume: normalizeVolume(volume),
        csrf_token: window.__CSRF||''
      })
    });
    if (handleHomeSessionRejected(r)) return { ok:false, _http:r.status, session_rejected:true };
    let j = null;
    try { j = await r.json(); } catch (e) { j = { ok: r.ok }; }
    j._http = r.status;
    return j;
  }

  // Runs the PIN-entry/retry loop for one output. Each attempt is one
  // request that pairs the output and switches it on. `c` is the checkbox
  // element to keep in sync with the outcome, or null when there is no live
  // checkbox (e.g. a poll-driven prompt for a card not being toggled by the
  // user). Returns true once the output ends up enabled, false if the user
  // cancelled or the attempt failed. An appliance that only understands the
  // pin-only request replies ok without enabling; the next poll then shows
  // the output off and switching it on again needs no PIN.
  async function runPinFlow(id, nm, volume, c) {
    const setOn = () => {
      if (c) {
        c.checked = true;
        updateOutputStateVisual(String(id), true);
      }
    };
    const setOff = () => {
      if (c) {
        c.checked = false;
        updateOutputStateVisual(String(id), false);
      }
    };
    // Temporarily revert the toggle until fully enabled.
    setOff();

    let note = '';
    while (true) {
      const pin = await showPinModal(nm || 'this speaker', note);
      if (!pin) return false; // user cancelled

      let j = null;
      try {
        j = await postPairAndEnable(id, pin, volume);
      } catch (e) {
        // treat as failure; keep disabled
        setOff();
        return false;
      }

      if (j && j.ok) { setOn(); return true; }
      if (j && j.pin_invalid) {
        note = 'That PIN was not accepted. Try again.';
        continue;
      }
      if (j && j.error === 'rate_limited') {
        const wait = Math.max(1, parseInt(j.retry_after_s, 10) || 1);
        if (!(await showPinWait(nm || 'this speaker', wait))) return false;
        note = '';
        continue;
      }
      if (j && j.pin_required) { note = ''; continue; } // the device asked for a new code
      setOff();
      return false;
    }
  }

  // Poll-driven counterpart to the PIN prompt in sendUpdate(): the backend
  // flags an output with pin_pending while it is asking for a PIN, not
  // just right after the user toggles it on, so the outputs poll offers
  // the prompt itself. __PIN_DISMISSED tracks ids the user cancelled the
  // prompt for, so the poll does not immediately re-open it every cycle;
  // it is cleared per-id once that output stops asking for a PIN, so a
  // later re-request (e.g. the device forgot pairing again) prompts again.
  // A row claimed by a dial that can enter the PIN is left to it.
  async function maybePromptForPin(outputs) {
    if (!window.__PIN_DISMISSED) window.__PIN_DISMISSED = new Set();
    if (!window.__PENDING_OUTPUTS) window.__PENDING_OUTPUTS = new Set();
    for (const o of outputs) {
      if (!o.pin_pending) window.__PIN_DISMISSED.delete(String(o.id));
    }
    if (window.__PIN_PROMPT_ACTIVE) return;
    const pinModal = document.getElementById('pinModal');
    if (pinModal && pinModal.classList.contains('show')) return;

    const target = outputs.find(function(o) {
      const id = String(o.id);
      return !!o.pin_pending && !window.__PIN_DISMISSED.has(id) &&
        !window.__PENDING_OUTPUTS.has(id) &&
        !(o.pin_claim && o.pin_claim !== 'webui');
    });
    if (!target) return;

    const id = String(target.id);
    window.__PIN_PROMPT_ACTIVE = true;
    window.__PENDING_OUTPUTS.add(id);
    try {
      const sl = document.getElementById('vol_slider_' + id);
      const volume = sl ? normalizeVolume(parseInt(sl.value, 10)) : (window.__PRESET_VOLUME || 20);
      const cb = document.getElementById('output_enabled_' + id);
      const ok = await runPinFlow(id, target.name, volume, cb || null);
      if (!ok) window.__PIN_DISMISSED.add(id);
    } finally {
      window.__PIN_PROMPT_ACTIVE = false;
      window.__PENDING_OUTPUTS.delete(id);
    }
  }

  async function sendUpdate(id){
    const c=document.getElementById('output_enabled_'+id), s=document.getElementById('vol_slider_'+id);
    if (c && c.disabled) return;
    const selected = c?c.checked:false;
    const volume = s?normalizeVolume(parseInt(s.value,10)):0;
    window.__PENDING_OUTPUTS.add(String(id));
    try {
      let j = null;
      try {
        j = await postOutputUpdate(id, selected, volume);
      } catch (e) {
        // Network error or 5 s abort -> let periodic refresh reconcile UI.
        return;
      }

      if (selected && j && j.error === 'output_in_use') {
        if (c) { c.checked = false; updateOutputStateVisual(String(id), false); }
        return;
      }

      // Output card name, shared by the encoder-capacity and PIN branches below.
      let nm = '';
      try {
        const card = c ? c.closest('.output-card') : null;
        const label = card ? card.querySelector('.output-card-name') : null;
        nm = outputCardNameText(label);
      } catch (e) {}

      if (selected && j && j.error === 'encoder_capacity') {
        if (c) { c.checked = false; updateOutputStateVisual(String(id), false); }
        (window.__HANDLED_FAILURE = window.__HANDLED_FAILURE || {})[String(id)] = Date.now();
        showInfoModal('CPU limit reached',
          'Unable to enable ' + (nm || 'this output') + ': the appliance\'s CPU cannot encode another stream at the selected quality. Disable another output or choose a lighter audio mode.');
        return;
      }

      // If OwnTone requires a PIN, prompt; each attempt pairs and enables in
      // one request, and a wrong PIN re-prompts.
      if (selected && j && j.pin_required) {
        await runPinFlow(id, nm, volume, c);
      }
    } finally {
      window.__PENDING_OUTPUTS.delete(String(id));
    }
  }

  function onToggleOutput(id){
    const cb = document.getElementById('output_enabled_' + id);
    if (cb && cb.disabled) return;
    if (cb) updateOutputStateVisual(String(id), !!cb.checked);
    if (cb && cb.checked) {
      const sl = document.getElementById('vol_slider_' + id);
      if (sl) { sl.value = String(window.__PRESET_VOLUME || 20); updateVolumeLabel(id, sl.value); }
    }
    reorderOutputCards();
    updateMasterVolumeCard();
    sendUpdate(id);
  }
  function onVolumeChange(id,v){
    updateVolumeLabel(id,v);
    if(!isActiveControl(document.getElementById('master_vol_slider'))) updateMasterVolumeCard();
    sendUpdate(id);
  }
  var VU_THRESHOLDS = [-60, -48, -36, -24, -12, -6, -3];
  var VU_COLORS = ['#2196F3','#2196F3','#2196F3','#2196F3','#f0ad4e','#fd7e14','#dc3545'];
  var VU_BIN_MS = 100;
  var VU_DELAY_BINS = Math.max(1, Math.round((window.__VU_DELAY_MS || 2250) / VU_BIN_MS));

  // Per-input VU queue state.
  var _vuQueue = {};         // inputIdx -> Array of pending bins
  var _vuLastSeq = {};       // inputIdx -> last seq appended to queue
  var _vuActiveIdx = -1;      // currently displayed input index (-1 = none)

  function updateVuBars(left_dbfs, right_dbfs){
    var lBars = document.querySelectorAll('#np-vu-l .vu-bar');
    var rBars = document.querySelectorAll('#np-vu-r .vu-bar');
    lBars.forEach(function(bar, i){
      var lit = Number.isFinite(Number(left_dbfs)) && Number(left_dbfs) >= VU_THRESHOLDS[i];
      bar.style.background = lit ? VU_COLORS[i] : '';
    });
    rBars.forEach(function(bar, i){
      var lit = Number.isFinite(Number(right_dbfs)) && Number(right_dbfs) >= VU_THRESHOLDS[i];
      bar.style.background = lit ? VU_COLORS[i] : '';
    });
  }

  function vuIngestHistory(activeIdx, vu_history){
    // If the active input changed, clear all queues immediately.
    if (activeIdx !== _vuActiveIdx) {
      _vuQueue = {};
      _vuLastSeq = {};
      _vuActiveIdx = activeIdx;
    }
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
    if (latestSeq < lastSeen && lastSeen > 0) {
      _vuQueue[activeIdx] = [];
      _vuLastSeq[activeIdx] = 0;
      lastSeen = 0;
    }
    var added = 0;
    for (var i = 0; i < bins.length; i++) {
      var b = bins[i];
      if (b.seq > lastSeen && b.seq <= cutoffSeq) {
        _vuQueue[activeIdx].push(b);
        added++;
      }
    }
    if (added > 0)
      _vuLastSeq[activeIdx] = cutoffSeq;
    // Bound queue to 2x the delay window to guard against extreme fetch jitter.
    var maxQ = VU_DELAY_BINS * 2;
    var q = _vuQueue[activeIdx];
    if (q.length > maxQ)
      _vuQueue[activeIdx] = q.slice(q.length - maxQ);
  }

  function vuRenderTick(){
    var q = _vuQueue[_vuActiveIdx];
    var bin = (q && q.length > 0) ? q.shift() : null;
    updateVuBars(bin ? bin.l : -90, bin ? bin.r : -90);
  }

  function renderNowPlayingCard(data){
    var levels = (data && data.input_levels) || [];
    var inputs = (data && data.playback && data.playback.inputs) || {};
    var isPlaying = false, activeLevel = null, activeIdx = 0;
    for (var i = 0; i < levels.length; i++) {
      if (levels[i] && levels[i].is_above_threshold) {
        isPlaying = true; activeLevel = levels[i]; activeIdx = i; break;
      }
    }
    // Authoritative playing/active state: prefer d.session.active (the
    // coordinator's unified session flag -- true during buffered
    // AirPlay/AAC playback AND repeat replay, neither of which trips
    // the input-level threshold above); fall back to the legacy
    // level-based isPlaying when talking to an older backend with no
    // session block.
    var session = (data && data.session) || null;
    var sessionActive = (session && typeof session.active === 'boolean') ? !!session.active : null;
    var sessionSource = (session && typeof session.source === 'string') ? session.source : null;
    var active = (sessionActive !== null) ? sessionActive : isPlaying;
    var card = document.getElementById('now-playing-card');
    var hdrEl = document.getElementById('np-hdr');
    if (card) card.classList.toggle('np-ready', !active);
    // Remote-shell pages set window.__REMOTE_HOSTNAME so the header also
    // identifies which appliance is being viewed; the local page leaves it
    // unset so its own header carries no suffix.
    var hdrSuffix = window.__REMOTE_HOSTNAME ? (' \u00b7 ' + window.__REMOTE_HOSTNAME) : '';
    // The WebUI has no dedicated mute control any more (moving the volume
    // slider is the only way to unmute), so a mute is surfaced in the
    // header text instead -- only while a session is actually active;
    // "Ready" never carries the suffix.
    var mutedSuffix = (active && data && data.muted) ? ' (Muted)' : '';
    if (hdrEl) hdrEl.textContent = (active ? (sessionSource === 'replay' ? 'Repeat Play' : 'Now Playing') : 'Ready') + mutedSuffix + hdrSuffix;
    if (!active) {
      _vuActiveIdx = -1;
      _vuQueue = {};
      updateVuBars(-90, -90);
      return;
    }
    // During replay no input trips the live-level threshold (the
    // origin input is not "capturing"), so activeLevel is still null
    // here even though session.active is true and the origin monitor's
    // track-identification snapshot is live (server-side fix in
    // get_active_track_identification_snapshot). Resolve the origin
    // input from repeat.recording.origin_input -- present verbatim
    // whenever sessionSource === 'replay' -- so the icon/label reflect
    // the actual replaying input rather than an arbitrary levels[0]
    // guess. Not a genuine live level, so vuIngestHistory is skipped
    // for it below.
    var usingReplayOrigin = false;
    if (!activeLevel && sessionSource === 'replay') {
      var repeat = (data && data.repeat) || {};
      var recording = repeat.recording || {};
      var originInput = Number.isFinite(Number(recording.origin_input))
        ? Number(recording.origin_input) : null;
      if (originInput !== null) {
        var originIdx = originInput - 1;
        // Match the origin input's level by its input number; levels from
        // an older appliance carry none, so those match by position.
        var originLevel = null;
        for (var j = 0; j < levels.length; j++) {
          if (levels[j] && Number(levels[j].index) === originInput) { originLevel = levels[j]; break; }
        }
        activeLevel = originLevel || levels[originIdx] || {
          index: originInput, label: 'Input ' + originInput, dbfs: -90, detected_hz: 0, is_above_threshold: false,
          rate_lock: 'locked', detected_khz: '', rate_mismatch_khz: '',
        };
        activeIdx = originIdx;
        usingReplayOrigin = true;
      }
    }
    if (!activeLevel && levels.length > 0) { activeLevel = levels[0]; activeIdx = 0; }
    if (!activeLevel) return;
    // The level's own input number picks the snapshot; a level with none
    // (older appliance) falls back to its list position.
    var inputNum = (typeof activeLevel.index === 'number' && Number.isFinite(activeLevel.index))
      ? activeLevel.index : activeIdx + 1;
    var inputSnap = inputs[String(inputNum)] || {};
    var isTurntable = !!inputSnap.is_turntable;
    var isBluetooth = !!inputSnap.is_bluetooth;
    var inputType = String(inputSnap.input_type || '');
    var typeLabel = String(inputSnap.type_label || '');
    // Precedence: turntable wins over bluetooth-ness, then the type picks
    // the icon (mirrors the server's _np_icon_kind derivation). The words
    // are the input's type label; an appliance that sends no type gets
    // words derived from the flags instead.
    var iconKind = isTurntable ? 'turntable' : (isBluetooth ? 'bluetooth' : (inputType === 'cd' ? 'cd' : 'line'));
    var iconSvgByKind = {
      turntable: window.__ICON_TURNTABLE,
      bluetooth: window.__ICON_BLUETOOTH,
      cd: window.__ICON_CD,
      line: window.__ICON_LINE_LEVEL,
    };
    var iconLabelByKind = { turntable: 'Vinyl', bluetooth: 'Bluetooth', cd: 'CD', line: 'Line In' };
    var typeLabelByKind = { turntable: 'Turntable', bluetooth: 'Bluetooth', cd: 'CD', line: 'Line Level' };
    var inputPrefix = typeLabel || iconLabelByKind[iconKind];
    var inputTypeText = typeLabel || typeLabelByKind[iconKind];
    var label = String(activeLevel.label || ('Input ' + inputNum));
    var signalParts = [];
    if (window.__SHOW_INPUT_DETAIL) {
      var rateLock = activeLevel.rate_lock == null ? 'locked' : String(activeLevel.rate_lock);
      var mismatchKhz = String(activeLevel.rate_mismatch_khz || '');
      var detectedKhz = String(activeLevel.detected_khz || '');
      if (rateLock === 'mismatch' && mismatchKhz) {
        signalParts.push('Mismatch');
        signalParts.push(mismatchKhz);
      } else if (rateLock === 'acquiring') {
        signalParts.push('Acquiring');
      } else if (rateLock && detectedKhz) {
        signalParts.push('Locked');
        signalParts.push(detectedKhz);
      }
    }
    var nameEl = document.getElementById('np-name');
    var signalEl = document.getElementById('np-signal');
    var iconEl = document.getElementById('np-icon');
    var ti = (data && data.track_identification) || {};
    var tiEnabled = !!(ti && ti.enabled);
    var tiState = String((ti && ti.state) || '');
    var tiIdentified = tiEnabled && tiState === 'identified';
    var tiTitle = String((ti && ti.title) || '');
    var tiArtist = String((ti && ti.artist) || '');
    var tiArtUrl = String((ti && ti.artwork_url) || '');
    if (tiIdentified) {
      if (nameEl) nameEl.textContent = tiTitle || 'Unknown';
      if (signalEl) signalEl.textContent = tiArtist;
      if (iconEl) {
        var artKey = 'art:' + tiArtUrl;
        if (iconEl.getAttribute('data-np-icon-key') !== artKey) {
          iconEl.setAttribute('data-np-icon-key', artKey);
          if (tiArtUrl) {
            var artImg = new Image();
            artImg.onload = function() {
              if (iconEl.getAttribute('data-np-icon-key') === artKey) {
                iconEl.textContent = '';
                var img = document.createElement('img');
                img.src = tiArtUrl;
                img.alt = '';
                iconEl.appendChild(img);
                iconEl.classList.add('np-icon-art');
              }
            };
            artImg.src = tiArtUrl;
          } else {
            iconEl.innerHTML = iconSvgByKind[iconKind];
            iconEl.classList.remove('np-icon-art');
          }
        }
      }
    } else if (tiEnabled) {
      var suffix;
      if (tiState === 'error') { suffix = 'Track ID function not available'; }
      else if (tiState === 'not_found') { suffix = 'Unknown track'; }
      else if (tiState === 'waiting_for_audio' || tiState === 'analysing') {
        // Use the API's own status_text ("Waiting for audio" / "Analysing")
        // instead of collapsing both into the "Identifying Track..." catch-all,
        // so a stalled schedule is visibly different from one that is working.
        suffix = String((ti && ti.status_text) || 'Identifying Track\u2026');
      }
      else { suffix = 'Identifying Track\u2026'; }
      if (nameEl) nameEl.textContent = inputPrefix + ' \u2013 ' + suffix;
      if (signalEl) signalEl.textContent = '';
      var svgKey = 'svg:' + iconKind;
      if (iconEl && iconEl.getAttribute('data-np-icon-key') !== svgKey) {
        iconEl.setAttribute('data-np-icon-key', svgKey);
        iconEl.innerHTML = iconSvgByKind[iconKind];
        iconEl.classList.remove('np-icon-art');
      }
    } else {
      if (nameEl) nameEl.textContent = label + ' \u00b7 ' + inputTypeText;
      if (signalEl) signalEl.textContent = signalParts.join(' \u00b7 ');
      var svgKey2 = 'svg:' + iconKind;
      if (iconEl && iconEl.getAttribute('data-np-icon-key') !== svgKey2) {
        iconEl.setAttribute('data-np-icon-key', svgKey2);
        iconEl.innerHTML = iconSvgByKind[iconKind];
        iconEl.classList.remove('np-icon-art');
      }
    }
    if (!usingReplayOrigin) vuIngestHistory(activeIdx, activeLevel.vu_history);
  }

  function _fmtRepeatTime(s){
    s = Math.max(0, Math.round(Number(s) || 0));
    var m = Math.floor(s / 60), r = s % 60;
    return m + ':' + (r < 10 ? '0' : '') + r;
  }
  // __repeatOptimistic holds the click's immediate intent until the polled
  // truth agrees with it (or a fallback timeout elapses): { active, kind,
  // ts }. kind is 'start' or 'stop' -- 'stop' gets a longer fallback window
  // (REPEAT_STOP_OPTIMISTIC_TIMEOUT_MS) because it also has to cover the
  // fade-out phase, which the server now reports explicitly via
  // repeat.replay.fading_out (see updateRepeatButton's 'stopping' state
  // below) so the button doesn't just go dead for the fade (kFadeSeconds,
  // core/monitor/autostream_monitor.h -- currently 1.0 s).
  var __repeatOptimistic = null;
  var REPEAT_START_OPTIMISTIC_TIMEOUT_MS = 5000;
  var REPEAT_STOP_OPTIMISTIC_TIMEOUT_MS = 10000;

  // No master-volume writes are made anywhere in this stop/fade flow --
  // 'stopping' is purely a visual/feedback state (label, disabled button,
  // page quiesce class); it never touches output/appliance volume.
  function updateRepeatButton(d){
    var btn = document.getElementById('repeat-btn');
    if (!btn) return;
    var repeat = (d && d.repeat) || null;
    if (!repeat || !repeat.enabled) {
      btn.hidden = true;
      __repeatOptimistic = null;
      _setRepeatStopping(false);
      return;
    }
    btn.hidden = false;
    var recording = repeat.recording || {};
    var replay = repeat.replay || {};
    var armed = !!repeat.armed;
    var replaying = !!replay.active;
    var fadingOut = !!replay.fading_out;
    var hasBuffer = Number(recording.bytes || 0) > 0;
    var polledOn = replaying || armed;
    var session = (d && d.session) || null;
    var sessionActive = (session && typeof session.active === 'boolean') ? !!session.active : null;

    // Optimistic-click reconciliation: hold the click's immediate
    // visual state until the polled truth agrees with it, or the
    // fallback timeout elapses -- the stop/start fade (kFadeSeconds,
    // core/monitor/autostream_monitor.h) means
    // polled state lags the click, and without this the button would
    // flicker back mid-fade.
    var on = polledOn;
    var state = replaying ? 'repeating' : (armed ? 'armed' : 'off');
    var optimisticStopPending = false;
    if (__repeatOptimistic) {
      optimisticStopPending = (__repeatOptimistic.kind === 'stop' && __repeatOptimistic.active === false);
      var timeoutMs = (__repeatOptimistic.kind === 'stop')
        ? REPEAT_STOP_OPTIMISTIC_TIMEOUT_MS
        : REPEAT_START_OPTIMISTIC_TIMEOUT_MS;
      // The stop confirms complete once the server reports the replay
      // fully gone (not just no-longer-fading): active false AND
      // fading_out false. Until then, keep the optimistic 'stopping'
      // visual even if a single poll briefly reports active=false while
      // fading_out lags (defensive against ordering, though the daemon
      // sets both from the same _state read).
      var stopConfirmed = optimisticStopPending && !replaying && !fadingOut;
      var agrees = optimisticStopPending ? stopConfirmed : (__repeatOptimistic.active === polledOn);
      var expired = (Date.now() - __repeatOptimistic.ts) >= timeoutMs;
      if (agrees || expired) {
        __repeatOptimistic = null;
        optimisticStopPending = false;
      } else {
        on = __repeatOptimistic.active;
        state = on ? (replaying ? 'repeating' : 'armed') : 'off';
      }
    }

    // 'stopping' state: the single derivation point for fade-out
    // feedback. True while either the optimistic stop click hasn't been
    // confirmed yet (covers the click-to-poll-catch-up window, including
    // while the server still reports replay.active true), or the server
    // itself reports the fade in flight with no local optimistic state
    // at all (e.g. a second tab, or a page load that lands mid-fade).
    var stopping = optimisticStopPending || fadingOut;
    if (stopping) state = 'stopping';

    btn.setAttribute('data-state', state);
    btn.classList.toggle('active', on || stopping);
    btn.disabled = stopping || (!hasBuffer && !replaying && !on);

    // 'Replay Last' only makes sense when nothing is authoritatively
    // playing right now: with a session block, gate it on
    // !sessionActive too so it never flashes while a live source (e.g.
    // a CD) is already playing at start-up. Legacy backends with no
    // session block keep the pre-existing gating.
    var showReplayLast = (sessionActive === null)
      ? (!on && hasBuffer)
      : (!sessionActive && !on && hasBuffer && !armed && !replaying);
    btn.textContent = stopping ? 'Stopping\u2026' : (showReplayLast ? '\u21bb Replay Last' : '\u21bb Repeat Play');

    if (!__repeatOptimistic) {
      var title = '';
      if (replaying) {
        var pos = _fmtRepeatTime(replay.position_seconds), dur = _fmtRepeatTime(replay.duration_seconds);
        title = pos + ' / ' + dur;
        // truncated_head is the DEFINED wrap semantic (keeps the last N
        // minutes), not a pressure symptom -- the suffix describes what's
        // held, not what was lost.
        if (recording.truncated_head) title += ' \u00b7 most recent kept';
      } else if (armed) {
        title = recording.active ? 'Buffering\u2026' : 'Waiting for playback';
      }
      btn.title = title;
    }

    _setRepeatStopping(stopping);
  }

  // Single page-quiesce choke point: toggles body.repeat-stopping and
  // inert on the sibling controls (never on #repeat-btn itself, which is
  // the feedback element and must stay visible + interactive-looking,
  // though disabled). No per-control special-casing anywhere else.
  function _repeatStoppingInertTargets(){
    var ids = ['now-playing-card', 'outputs-list'];
    var targets = [];
    for (var i = 0; i < ids.length; i++) {
      var el = document.getElementById(ids[i]);
      if (el) targets.push(el);
    }
    // Any other direct child of .airplay-top-controls besides the repeat
    // button itself -- covers the appliance-selector widget, which lives
    // in that row as a sibling of #repeat-btn on both the local and
    // remote pages. Walking siblings (rather than inerting the shared
    // container) is what lets the button stay interactive-looking while
    // everything around it quiesces.
    var topControls = document.querySelector('.airplay-top-controls');
    if (topControls) {
      var kids = topControls.children;
      for (var j = 0; j < kids.length; j++) {
        var kid = kids[j];
        if (kid.id === 'repeat-btn') continue;
        if (targets.indexOf(kid) === -1) targets.push(kid);
      }
    }
    return targets;
  }
  var __repeatStoppingActive = false;
  function _setRepeatStopping(stopping){
    stopping = !!stopping;
    if (stopping === __repeatStoppingActive) return;
    __repeatStoppingActive = stopping;
    document.body.classList.toggle('repeat-stopping', stopping);
    var targets = _repeatStoppingInertTargets();
    for (var i = 0; i < targets.length; i++) {
      if (stopping) {
        targets[i].setAttribute('inert', '');
      } else {
        targets[i].removeAttribute('inert');
      }
    }
  }

  function onRepeatButtonClick(){
    var btn = document.getElementById('repeat-btn');
    if (!btn || btn.disabled) return;
    var wasActive = btn.classList.contains('active');
    var state = btn.getAttribute('data-state');
    // repeating -> stop replay; armed -> disarm; off -> arm (starts replay
    // immediately if idle with a buffer, or arms for stream-end if playing live).
    var newArmed = (state === 'repeating' || state === 'armed') ? false : true;
    // Two very different clicks both disarm, and only one of them stops
    // anything: 'repeating' interrupts a replay that now has to fade out,
    // while 'armed' merely cancels a pending action -- the true source is
    // still playing and nothing fades. Giving the 'armed' case the stop
    // treatment would flash "Stopping..." and quiesce the page for a
    // teardown that never happens, so it gets its own kind.
    var kind = newArmed ? 'start' : (state === 'repeating' ? 'stop' : 'disarm');
    // Apply the optimistic visual state immediately: don't wait for the
    // POST to resolve before flipping the class/label, so the click
    // feels instant even though the fade (kFadeSeconds, core/monitor/
    // autostream_monitor.h) means the polled truth
    // will lag behind for a while. Stop clicks disable the button too --
    // closes the double-click-during-fade hole where a second click
    // mid-fade could re-arm/re-stop against a session that's already
    // tearing down.
    __repeatOptimistic = { active: newArmed, kind: kind, ts: Date.now() };
    if (kind === 'stop') {
      // 'active' (the accent-outline styling) stays true through the stop
      // click -- the button remains the visible feedback element while
      // stopping, it just swaps its label/disabled state; only a confirmed
      // 'off' clears the outline.
      btn.classList.add('active');
      btn.setAttribute('data-state', 'stopping');
      btn.textContent = 'Stopping\u2026';
      btn.title = 'Stopping\u2026';
      btn.disabled = true;
    } else if (kind === 'disarm') {
      // Straight to the off look, button still live. The label is left
      // alone: it already reads '(reload) Repeat Play' while armed, and the next
      // poll settles it (e.g. to '(reload) Replay Last' if the source has since
      // gone idle with a buffer).
      btn.classList.remove('active');
      btn.setAttribute('data-state', 'off');
      btn.title = '';
      btn.disabled = false;
    } else {
      btn.classList.add('active');
      btn.setAttribute('data-state', 'armed');
      btn.textContent = '\u21bb Repeat Play';
      btn.title = 'Starting\u2026';
      btn.disabled = false;
    }
    // Only a genuine fade quiesces the page. A stale 'armed' reading (a
    // replay that started between the last poll and the click) still gets
    // the full stopping treatment from the server's own fading_out flag on
    // the next poll, so nothing is lost by being conservative here.
    _setRepeatStopping(kind === 'stop');
    fetch(window.__REPEAT_URL || '/api/repeat', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.__CSRF || '' },
      body: JSON.stringify({ armed: newArmed })
    }).then(function(r){ return r.json(); }).then(function(d){
      if (!d || !d.ok) {
        __repeatOptimistic = null;
        btn.classList.toggle('active', wasActive);
        btn.disabled = false;
        _setRepeatStopping(false);
      }
    }).catch(function(){
      __repeatOptimistic = null;
      btn.classList.toggle('active', wasActive);
      btn.disabled = false;
      _setRepeatStopping(false);
    });
  }

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
