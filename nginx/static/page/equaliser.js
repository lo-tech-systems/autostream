// Equaliser: the sliders and the auto-trim switch follow the eq part of the
// appliance state, so a change made anywhere shows here at once; each change
// made here goes out as an intent.
import { StateStream } from '../shared/state_stream.js';
import { Pending } from '../shared/pending.js';
import { submit } from './home/home_intents.js';
import { initSelector } from './selector_menu.js';

const island = JSON.parse(document.getElementById('page-data').textContent);
window.__CSRF = document.getElementById('_csrfField').value;
const BANDS = ['peq1_db', 'peq2_db', 'peq3_db', 'peq4_db', 'peq5_db', 'peq6_db'];
const pending = new Pending();
const sent = {};
const $ = (id) => document.getElementById(id);
const idOf = (field) => (field === 'gain_db' ? 'output_gain_db' : field);
const fmt = (v, d = 0) => (v > 0 ? '+' : '') + v.toFixed(d) + ' dB';
const curve = () => { if (window._drawEqCurve) window._drawEqCurve(); };
let stream = null;
let stopTrim = null;

// Put the value of a field on its slider and label unless the person is holding it.
function show(field, value, decimals) {
  const el = $(idOf(field));
  const v = Number(pending.value(field, value));
  if (!el || el === document.activeElement || !Number.isFinite(v)) return;
  el.value = String(v);
  $(idOf(field) + '_val').textContent = fmt(v, decimals);
}

function draw(view, names, resync) {
  pending.settle(view.version, resync);
  const eq = view.parts.eq || {};
  if ((eq.output_bands || []).length) BANDS.forEach((k, i) => show(k, eq.output_bands[i], 0));
  if (eq.output_gain_db != null) show('gain_db', eq.output_gain_db, 1);
  const box = $('output_auto_trim');
  if (eq.auto_trim_enabled != null) box.checked = !!pending.value('auto_trim_enabled', eq.auto_trim_enabled);
  const trim = view.parts.monitor ? view.parts.monitor.output_trim_db : null;
  const el = $('output_trim_status');
  el.style.display = box.checked ? '' : 'none';
  el.textContent = !box.checked ? '' : Number.isFinite(trim) ? 'Auto-trim: ' + trim.toFixed(1) + ' dB applied' : 'Calculating\u2026';
  if (box.checked && !stopTrim) stopTrim = stream.pollParts(['monitor'], 3000);
  if (!box.checked && stopTrim) { stopTrim(); stopTrim = null; }
  curve();
}
const redraw = () => draw(stream.view);

// Send one field. The page keeps showing it until the state has caught up.
function save(field, value) {
  const n = (sent[field] = (sent[field] || 0) + 1);
  pending.mark(field, value, null);
  const failed = () => { if (sent[field] === n) { pending.drop(field); redraw(); } };
  submit('output.eq.set', { fields: [[field, String(value)]] }).then((r) => {
    if (!r.ok) failed(); else if (sent[field] === n) pending.mark(field, value, r.version);
  }).catch(failed);
}

function slider(field, decimals) {
  $(idOf(field)).addEventListener('input', (e) => {
    const v = Number(e.target.value);
    $(idOf(field) + '_val').textContent = fmt(v, decimals);
    save(field, v);
    curve();
  });
}
BANDS.forEach((k) => slider(k, 0));
slider('gain_db', 1);
$('output_auto_trim').addEventListener('change', (e) => { save('auto_trim_enabled', e.target.checked); redraw(); });
$('eq-flat-btn').addEventListener('click', () => submit('output.eq.reset').then((r) => {
  if (!r.ok) return;
  BANDS.forEach((k) => pending.mark(k, 0, r.version));
  redraw();
}));

initSelector({ page: 'equaliser', currentId: island.local_id });
stream = new StateStream({ base: '/api/v1', initial: island.state, onChange: draw });
draw(stream.view);
