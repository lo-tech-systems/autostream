// The Now Playing card and its level meter. What to show is worked out in
// state_view.js; this only draws it.
import { nowPlaying, activeInput, playing } from '../../shared/state_view.js';

const THRESHOLDS = [-60, -48, -36, -24, -12, -6, -3];
const COLORS = ['#2196F3', '#2196F3', '#2196F3', '#2196F3', '#f0ad4e', '#fd7e14', '#dc3545'];
const BIN_MS = 100;
const $ = (id) => document.getElementById(id);

let queue = [];
let lastSeq = 0;
let vuInput = -1;
let delayBins = 22;

function paintBars(l, r) {
  for (const [id, db] of [['np-vu-l', l], ['np-vu-r', r]]) {
    document.querySelectorAll('#' + id + ' .vu-bar').forEach((bar, i) => {
      bar.style.background = Number.isFinite(Number(db)) && Number(db) >= THRESHOLDS[i] ? COLORS[i] : '';
    });
  }
}

// Queue the level bins that are delayBins behind the newest, so the meter
// lags the signal by about the player's start buffer.
function ingest(input, hist) {
  if (input !== vuInput) { queue = []; lastSeq = 0; vuInput = input; }
  if (!hist || !Array.isArray(hist.bins) || !hist.bins.length) return;
  const latest = hist.latest_seq || 0;
  const cutoff = latest - delayBins;
  if (cutoff < 0) return;
  if (latest < lastSeq) { queue = []; lastSeq = 0; }
  const fresh = hist.bins.filter((b) => b.seq > lastSeq && b.seq <= cutoff);
  if (fresh.length) { queue.push(...fresh); lastSeq = cutoff; }
  if (queue.length > delayBins * 2) queue = queue.slice(-delayBins * 2);
}

function drawIcon(icon, np, icons) {
  const key = np.artUrl ? 'art:' + np.artUrl : 'svg:' + np.iconKind;
  if (icon.getAttribute('data-np-icon-key') === key) return;
  icon.setAttribute('data-np-icon-key', key);
  const svg = () => { icon.innerHTML = icons[np.iconKind === 'line' ? 'line_level' : np.iconKind] || ''; icon.classList.remove('np-icon-art'); };
  if (!np.artUrl) { svg(); return; }
  const img = new Image();
  img.onload = () => {
    if (icon.getAttribute('data-np-icon-key') !== key) return;
    icon.textContent = '';
    img.alt = '';
    icon.appendChild(img);
    icon.classList.add('np-icon-art');
  };
  img.src = np.artUrl;
}

export function initNowPlaying(prefs) {
  delayBins = Math.max(1, Math.round((prefs.vu_delay_ms || 2250) / BIN_MS));
  if (prefs.show_input_detail) setInterval(() => { const b = queue.shift(); paintBars(b ? b.l : -90, b ? b.r : -90); }, BIN_MS);
}

export function drawNowPlaying(p, prefs, icons) {
  const np = nowPlaying(p, prefs);
  const card = $('now-playing-card');
  if (!card) return;
  card.classList.toggle('np-ready', !playing(p));
  $('np-hdr').textContent = np.header;
  $('np-name').textContent = np.title;
  $('np-signal').textContent = np.subtitle;
  drawIcon($('np-icon'), np, icons);
  const n = activeInput(p);
  if (!playing(p)) { queue = []; vuInput = -1; return; }
  const e = ((p.inputs && p.inputs.entries) || []).find((x) => x.index === n);
  if (!(p.session.source === 'replay')) ingest(n, e && e.level && e.level.vu_history);
}
