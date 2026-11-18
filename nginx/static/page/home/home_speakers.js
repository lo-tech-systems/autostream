// The speaker cards: drawn from the outputs part, with the switch, the volume
// sliders, the master slider, the PIN dialog and the "Could not start" notice.
// A value sent and not yet seen come back is held in ctx.pending.
import { speakerRows, masterVolume, startFailure } from '../../shared/state_view.js';
import { START_FAILURE, REFUSAL, CHIP, AUTO_START_PILL } from '../../shared/texts.js';
import { submit } from './home_intents.js';

const EMPTY_TOLERANCE_MS = 6000;
const HANDLED_MS = 15000;
const SEEN_KEY = 'autostream.startFailureSeen';
const $ = (id) => document.getElementById(id);
const clamp = (v) => Math.max(0, Math.min(100, Math.round(Number(v)) || 0));
const shown = (id) => !!($(id) && $(id).classList.contains('show'));
const mk = (tag, cls) => { const e = document.createElement(tag); if (cls) e.className = cls; return e; };

let ctx;                       // { prefs, pending, redraw }
let seen = { boot: '', seq: 0, first: true };
let emptySince = null;
let drag = null;               // the master slider's drag: { base, snaps }
let promptActive = false;
const busy = new Set();        // speakers with a request in flight
const dismissed = new Set();   // speakers whose PIN prompt was cancelled
const handled = {};            // speaker id -> when its own switch showed the CPU-limit notice
const names = {};              // speaker id -> name, as last drawn

const hold = (key, value, version) => { if (value === undefined) return; ctx.pending.mark(key, value, version); setTimeout(ctx.redraw, 2100); };
const label = (id, v) => { const s = $('vol_label_' + id); if (s) s.textContent = clamp(v) + '%'; };

// The PIN dialog: resolves with the digits, or null on Cancel. With wait > 0 it
// counts the seconds down with the input disabled, then resolves true (false on Cancel).
function pinDialog(name, note, wait = 0) {
  return new Promise((resolve) => {
    const [m, input, ok, cancel, noteEl] = ['pinModal', 'pinModalInput', 'pinModalOk', 'pinModalCancel', 'pinModalNote'].map($);
    let left = wait;
    let timer = null;
    const text = () => 'Wait ' + left + (left === 1 ? ' second' : ' seconds') + ' before retry';
    $('pinModalTitle').textContent = 'Enter PIN for ' + name;
    noteEl.textContent = wait ? text() : note;
    noteEl.hidden = !(wait || note);
    input.value = '';
    input.disabled = !!wait;
    ok.disabled = true;
    m.classList.add('show');
    if (!wait) setTimeout(() => { try { input.focus(); } catch (e) { /* hidden again */ } }, 60);
    const onKey = (e) => { if (e.key === 'Escape') { e.preventDefault(); cancel.click(); } };
    const done = (v) => {
      clearInterval(timer);
      document.removeEventListener('keydown', onKey);
      m.classList.remove('show');
      ok.onclick = cancel.onclick = input.oninput = input.onkeydown = null;
      resolve(v);
    };
    document.addEventListener('keydown', onKey);
    cancel.onclick = () => done(wait ? false : null);
    ok.onclick = () => { const v = input.value.trim(); if (!wait && /^[0-9]{4,8}$/.test(v)) done(v); };
    input.oninput = () => {
      const d = input.value.replace(/[^0-9]/g, '').slice(0, 8);
      if (input.value !== d) input.value = d;
      ok.disabled = d.length < 4;
    };
    input.onkeydown = (e) => { if (e.key === 'Enter') { e.preventDefault(); if (!ok.disabled) ok.click(); } };
    if (wait) timer = setInterval(() => { if (--left <= 0) done(true); else noteEl.textContent = text(); }, 1000);
  });
}

// One PIN attempt is one request that pairs the speaker and switches it on.
async function pinFlow(id, name, volume) {
  hold('sel:' + id, false, null);
  let note = '';
  for (;;) {
    const pin = await pinDialog(name || 'this speaker', note);
    if (!pin) return false;
    let r;
    try { r = await submit('output.pin.submit', { id, pin, selected: true, volume, name }); } catch (e) { return false; }
    const res = r.result || {};
    if (r.ok) { hold('sel:' + id, true, r.version); return true; }
    note = '';
    if (res.pin_invalid) note = REFUSAL.pin_invalid;
    else if (r.error === 'rate_limited') {
      const s = Math.max(1, parseInt(r.retry_after_s ?? res.retry_after_s, 10) || 1);
      if (!(await pinDialog(name || 'this speaker', '', s))) return false;
    } else if (!res.pin_required) return false;
  }
}

// A speaker asking for a PIN that nobody else is entering gets the dialog.
function maybePrompt(rows) {
  for (const r of rows) if (!r.pinPending) dismissed.delete(r.id);
  if (promptActive || shown('pinModal')) return;
  const t = rows.find((r) => r.pinPending && !dismissed.has(r.id) && !busy.has(r.id) && (r.pinClaim === '' || r.pinClaim === 'webui'));
  if (!t) return;
  promptActive = true;
  busy.add(t.id);
  const sl = $('vol_slider_' + t.id);
  pinFlow(t.id, t.name, sl ? clamp(sl.value) : ctx.prefs.preset_volume)
    .then((ok) => { if (!ok) dismissed.add(t.id); })
    .finally(() => { promptActive = false; busy.delete(t.id); ctx.redraw(); });
}

async function send(id, selected, volume) {
  const { pending, prefs } = ctx;
  const name = names[id] || '';
  hold('sel:' + id, selected, null);
  hold('vol:' + id, volume, null);
  ctx.redraw();
  busy.add(id);
  try {
    const r = await submit('outputs.set', { id, selected, volume, name });
    const res = r.result || {};
    const err = r.error || res.error;
    if (r.ok) { hold('sel:' + id, selected, r.version); hold('vol:' + id, volume, r.version); return; }
    pending.drop('sel:' + id);
    pending.drop('vol:' + id);
    if (selected && err === 'encoder_capacity') {
      handled[id] = Date.now();
      const t = REFUSAL.encoder_capacity(name);
      window.showInfoModal(t.title, t.text).then(ctx.redraw);
    } else if (selected && res.pin_required) {
      if (!(await pinFlow(id, name, volume || (ctx.own ? prefs.preset_volume : undefined)))) dismissed.add(id);
    }
  } catch (e) {
    pending.drop('sel:' + id);
    pending.drop('vol:' + id);
  } finally {
    busy.delete(id);
    ctx.redraw();
  }
}

function build(id) {
  const card = mk('div', 'output-card');
  card.id = 'output_card_' + id;
  card.setAttribute('data-output-id', id);
  const head = mk('div', 'output-card-head');
  const meta = mk('div', 'output-card-meta');
  const name = mk('div', 'output-card-name');
  name.append(document.createTextNode(''), Object.assign(mk('span', 'output-card-state-label'), { id: 'output_label_' + id }));
  const badge = Object.assign(mk('span', 'output-card-default'), { textContent: AUTO_START_PILL });
  const chip = Object.assign(mk('span', 'output-state-chip'), { id: 'output_state_' + id });
  meta.append(name, badge, chip);
  const toggle = mk('label', 'output-toggle');
  toggle.addEventListener('click', (e) => e.stopPropagation());
  const cb = Object.assign(document.createElement('input'), { type: 'checkbox', id: 'output_enabled_' + id });
  cb.addEventListener('change', () => {
    const sl = $('vol_slider_' + id);
    // Another appliance starts a speaker at its own level: no volume is sent.
    const start = ctx.own ? ctx.prefs.preset_volume : undefined;
    if (cb.checked && sl && ctx.own) sl.value = String(start);
    send(id, cb.checked, cb.checked ? start : clamp(sl && sl.value));
  });
  const sw = mk('span', 'switch');
  sw.setAttribute('aria-hidden', 'true');
  toggle.append(cb, sw);
  head.append(meta, toggle);
  const wrap = Object.assign(mk('div', 'output-slider-wrap'), { id: 'output_slider_wrap_' + id });
  wrap.addEventListener('click', (e) => e.stopPropagation());
  const hdr = mk('div', 'slider-header');
  hdr.append(Object.assign(mk('span'), { textContent: 'Volume:' }), Object.assign(mk('span'), { id: 'vol_label_' + id }));
  const sl = Object.assign(document.createElement('input'), { type: 'range', id: 'vol_slider_' + id, min: 0, max: 100, step: 1 });
  sl.addEventListener('input', () => label(id, sl.value));
  sl.addEventListener('change', () => send(id, true, clamp(sl.value)));
  wrap.append(hdr, sl);
  card.append(head, wrap);
  return card;
}

function paint(card, r) {
  const { pending } = ctx;
  const id = r.id;
  names[id] = r.name;
  const on = pending.value('sel:' + id, r.on);
  const vol = pending.value('vol:' + id, r.volume);
  const connecting = r.connecting && on;
  const offline = r.offline;
  card.className = 'output-card ' + (r.inUseBy ? 'output-card-in-use' : on ? 'output-card-on' : 'output-card-off')
    + (connecting ? ' output-card-connecting' : '') + (offline ? ' output-card-offline' : '');
  card.setAttribute('data-auto-start', r.autoStart ? '1' : '0');
  card.setAttribute('data-remote-in-use', r.inUseBy ? '1' : '0');
  card.setAttribute('data-remote-owner', r.inUseBy);
  card.setAttribute('data-remote-owner-id', r.inUseId);
  const nm = card.querySelector('.output-card-name');
  nm.firstChild.data = r.name;
  const lab = $('output_label_' + id);
  lab.textContent = connecting ? CHIP.connecting : offline ? CHIP.offline : '';
  lab.hidden = !lab.textContent;
  card.querySelector('.output-card-default').style.display = r.autoStart ? '' : 'none';
  const chip = $('output_state_' + id);
  chip.className = 'output-state-chip ' + (r.inUseBy ? 'in-use' : on ? 'on' : 'off');
  chip.textContent = r.inUseBy ? CHIP.inUse(r.inUseBy) : on ? CHIP.on : CHIP.off;
  const cb = $('output_enabled_' + id);
  cb.checked = on;
  cb.disabled = r.disabled;
  $('output_slider_wrap_' + id).hidden = !on;
  const sl = $('vol_slider_' + id);
  sl.disabled = offline;
  if (document.activeElement !== sl && !drag) { sl.value = String(vol); label(id, vol); }
}

function drawMaster(p) {
  const sl = $('master_vol_slider');
  if (!sl || document.activeElement === sl || drag) return;
  const m = masterVolume(p);
  const card = $('master-volume-card');
  card.classList.toggle('master-volume-inactive', m === null);
  sl.disabled = m === null;
  sl.value = String(m === null ? ctx.prefs.preset_volume : ctx.pending.value('master', m));
}

// "Could not start <speaker>", once per (boot, seq) in this tab, never over another dialog.
function notice(view) {
  const res = startFailure(view, seen);
  const f = res.show;
  const adopt = () => {
    seen = res.seen;
    try { sessionStorage.setItem(SEEN_KEY, JSON.stringify({ boot: seen.boot, seq: seen.seq })); } catch (e) { /* kept in memory */ }
  };
  if (!f) { adopt(); return; }
  if (f.reason === 'encoder_capacity' && Date.now() - (handled[f.unit_id] || 0) < HANDLED_MS) { adopt(); return; }
  if (shown('infoModal') || shown('pinModal')) { seen = { ...seen, first: false }; return; }
  adopt();
  window.showInfoModal('Could not start ' + f.name, START_FAILURE[f.reason] || START_FAILURE.other).then(ctx.redraw);
}

export function drawSpeakers(view) {
  const p = view.parts;
  const list = $('outputs-list');
  if (!p.outputs || !list) return;
  const rows = speakerRows(p, { includeOffline: true });
  if (!rows.length && list.children.length) {
    emptySince = emptySince || Date.now();
    const left = EMPTY_TOLERANCE_MS - (Date.now() - emptySince);
    if (left > 0) { setTimeout(ctx.redraw, left + 50); return; }
  } else if (rows.length) emptySince = null;
  const cards = new Map(Array.from(list.children).map((c) => [c.getAttribute('data-output-id'), c]));
  rows.forEach((r, i) => {
    const card = cards.get(r.id) || build(r.id);
    cards.delete(r.id);
    if (list.children[i] !== card) list.insertBefore(card, list.children[i] || null);
    paint(card, r);
  });
  for (const c of cards.values()) c.remove();
  const ph = $('outputs-placeholder');
  const text = !p.outputs.connected ? 'Waiting for owntone' : p.outputs.units.some((u) => u.reported) ? '' : 'Waiting for device discovery';
  ph.textContent = text;
  ph.hidden = !text;
  drawMaster(p);
  maybePrompt(rows);
  notice(view);
}

// Scale the selected speakers' sliders with the master slider; on release one
// volume.set sends the level and the server scales the same way.
export function initSpeakers(context) {
  ctx = context;
  try { seen = { ...(JSON.parse(sessionStorage.getItem(SEEN_KEY)) || seen), first: true }; } catch (e) { /* no stored value */ }
  const master = $('master_vol_slider');
  const snap = () => {
    drag = { base: clamp(master.value), snaps: {} };
    document.querySelectorAll('.output-card').forEach((c) => {
      const id = c.getAttribute('data-output-id');
      if ($('output_enabled_' + id).checked) drag.snaps[id] = clamp($('vol_slider_' + id).value);
    });
  };
  const scale = () => {
    const nm = clamp(master.value);
    const out = {};
    for (const [id, v] of Object.entries(drag.snaps)) { out[id] = clamp(drag.base > 0 ? (v * nm) / drag.base : nm); $('vol_slider_' + id).value = String(out[id]); label(id, out[id]); }
    return out;
  };
  if (master) {
    master.addEventListener('mousedown', snap);
    master.addEventListener('touchstart', snap, { passive: true });
    master.addEventListener('input', () => { if (!drag) snap(); scale(); });
    master.addEventListener('change', async () => {
      if (!drag) snap();
      const out = scale();
      const level = clamp(master.value);
      drag = null;
      for (const [id, v] of Object.entries(out)) hold('vol:' + id, v, null);
      hold('master', level, null);
      let r = null;
      try { r = await submit('volume.set', { level }); } catch (e) { /* treated as a failure */ }
      for (const id of [...Object.keys(out), 'master']) {
        if (r && r.ok) hold(id === 'master' ? id : 'vol:' + id, id === 'master' ? level : out[id], r.version);
        else ctx.pending.drop(id === 'master' ? id : 'vol:' + id);
      }
      ctx.redraw();
    });
  }
  $('outputs-list').addEventListener('click', (e) => {
    const card = e.target.closest('.output-card[data-remote-in-use="1"]');
    const owner = card && card.getAttribute('data-remote-owner-id');
    if (!ctx.prefs.control_other_appliances || !owner || e.target.closest('.output-toggle, .output-slider-wrap')) return;
    window.location.href = '/a/' + owner + '/';
  });
}
