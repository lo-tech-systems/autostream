// What a page shows, worked out from the state parts. Pure functions of
// view.parts (p below): no DOM, no clock, no storage.
import { INPUT_TYPE_LABELS, TYPE_WORD, PREFIX_WORD } from './texts.js';

const START_FAILURE_MAX_AGE_S = 30;
const RANK = { critical: 0, warning: 1, info: 2 };
const TRACK_WORDS = { error: 'Track ID function not available', not_found: 'Unknown track' };
const IDENTIFYING = 'Identifying Track\u2026';

const entries = (p) => (p.inputs && p.inputs.entries) || [];
const block = (p) => (p.repeat && p.repeat.block) || {};
const replay = (p) => block(p).replay || {};

export const playing = (p) => !!(p.session && p.session.active);

// Playing, or a replay that is running or fading out.
export const live = (p) => playing(p) || !!replay(p).active || !!replay(p).fading_out;

// The input number behind the session: the session's own source, else the
// first input above its threshold, else the first input; null with no inputs.
export function activeInput(p) {
  const src = (p.session && p.session.source) || '';
  let n = null;
  if (src === 'replay') {
    const origin = (block(p).recording || {}).origin_input;
    if (replay(p).active && Number.isInteger(origin)) n = origin;
  } else if (/^input\d+$/.test(src)) {
    n = Number(src.slice(5));
  }
  if (n === null) {
    const hot = entries(p).find((e) => e.level && e.level.is_above_threshold);
    const first = entries(p)[0];
    n = hot ? hot.index : first ? first.index : null;
  }
  return n;
}

function signal(lv) {
  const lock = lv.rate_lock == null ? 'locked' : String(lv.rate_lock);
  if (lock === 'mismatch' && lv.rate_mismatch_khz) return 'Mismatch \u00b7 ' + lv.rate_mismatch_khz;
  if (lock === 'acquiring') return 'Acquiring';
  return lock && lv.detected_khz ? 'Locked \u00b7 ' + lv.detected_khz : '';
}

// { header, iconKind, artUrl, title, subtitle, muted } for the Now Playing card.
export function nowPlaying(p, prefs = {}) {
  const active = playing(p);
  const found = activeInput(p);
  const n = found === null ? 1 : found;
  const e = entries(p).find((x) => x.index === found);
  const lv = (e && e.level) || {};
  const pb = ((p.playback && p.playback.inputs) || {})[String(n)] || {};
  const type = e && INPUT_TYPE_LABELS[e.input_type] ? e.input_type : '';
  const kind = pb.is_turntable ? 'turntable' : pb.is_bluetooth ? 'bluetooth' : type === 'cd' ? 'cd' : 'line';
  const t = ((p.track && p.track.entries) || {})[String(n)] || {};
  const muted = active && !!(p.outputs && p.outputs.muted_all);
  let title;
  let subtitle = '';
  let artUrl = '';
  if (t.enabled && t.state === 'identified') {
    title = t.title || 'Unknown';
    subtitle = t.artist || '';
    artUrl = /^https?:\/\//.test(t.artwork_url || '') ? t.artwork_url : '';
  } else if (t.enabled) {
    const word = t.state === 'waiting_for_audio' || t.state === 'analysing' ? t.status_text || IDENTIFYING : TRACK_WORDS[t.state] || IDENTIFYING;
    title = (type ? INPUT_TYPE_LABELS[type] : PREFIX_WORD[kind]) + ' \u2013 ' + word;
  } else {
    title = (lv.label || 'Input ' + n) + ' \u00b7 ' + (type ? INPUT_TYPE_LABELS[type] : TYPE_WORD[kind]);
    subtitle = prefs.show_input_detail ? signal(lv) : '';
  }
  const head = active ? (p.session.source === 'replay' ? 'Repeat Play' : 'Now Playing') : 'Ready';
  return { header: head + (muted ? ' (Muted)' : ''), iconKind: kind, artUrl, title, subtitle, muted };
}

// The speaker cards in order: Auto-Start first, then by name. A hidden speaker
// stays while it is on or in the Auto-Start set; an offline Auto-Start card
// shows only with opts.includeOffline.
export function speakerRows(p, opts = {}) {
  const inSession = playing(p);
  const rows = [];
  for (const u of (p.outputs && p.outputs.units) || []) {
    const on = !!u.selected && u.availability !== 'password';
    if (!u.id || !u.name || (u.offline && !(opts.includeOffline && u.auto_start)) || (u.hidden && !on && !u.auto_start)) continue;
    const by = u.in_use_by || '';
    rows.push({
      id: u.id,
      name: u.name,
      on,
      volume: Math.max(0, Math.min(100, Math.round(u.volume) || 0)),
      chip: by ? 'in-use' : on ? 'on' : 'off',
      autoStart: !!u.auto_start,
      inUseBy: by,
      connecting: !by && !!u.connecting,
      offline: !by && !u.connecting && !!u.offline,
      disabled: !!by || (!!u.offline && !inSession),
      pinPending: !!(u.reported && u.reported.pin_pending),
      pinClaim: u.pin_claim || '',
    });
  }
  const key = (r) => r.name.toLowerCase();
  return rows.sort((a, b) => (b.autoStart - a.autoStart) || key(a).localeCompare(key(b)));
}

export function masterVolume(p) {
  const m = p.outputs && p.outputs.master_volume;
  return m == null ? null : m;
}

// Decide whether to tell the person about the latest failed start. seen is
// { boot, seq, first } (first: this is the first reading since the page
// loaded, when a failure already over 30 s old is not news). Returns { show,
// seen }: the failure to show or null, and the new seen. A PIN reason is
// answered by the PIN dialog, so it is marked seen and not shown.
export function startFailure(view, seen) {
  const f = (view.parts.outputs || {}).start_failure || null;
  const cur = seen || { boot: '', seq: 0, first: true };
  const kept = { boot: cur.boot, seq: cur.seq, first: false };
  if (!f || (cur.boot === view.boot && f.seq <= cur.seq)) return { show: null, seen: kept };
  const stale = cur.first && view.time - f.at > START_FAILURE_MAX_AGE_S;
  const quiet = stale || f.reason === 'pin_invalid' || f.reason === 'pin_required';
  return { show: quiet ? null : f, seen: { boot: view.boot, seq: f.seq, first: false } };
}

const clock = (s) => {
  const t = Math.max(0, Math.round(Number(s) || 0));
  return Math.floor(t / 60) + ':' + (t % 60 < 10 ? '0' : '') + (t % 60);
};

// { shown, state, label, title, disabled } for the repeat button.
export function repeatControls(p) {
  const b = block(p);
  const rec = b.recording || {};
  const rp = b.replay || {};
  const hasBuffer = Number(rec.bytes || 0) > 0;
  const on = !!rp.active || !!b.armed;
  const stopping = !!rp.fading_out;
  let title = '';
  if (rp.active) title = clock(rp.position_seconds) + ' / ' + clock(rp.duration_seconds) + (rec.truncated_head ? ' \u00b7 most recent kept' : '');
  else if (b.armed) title = rec.active ? 'Buffering\u2026' : 'Waiting for playback';
  const again = !playing(p) && !on && hasBuffer;
  return {
    shown: !!b.enabled,
    state: stopping ? 'stopping' : rp.active ? 'repeating' : b.armed ? 'armed' : 'off',
    label: stopping ? 'Stopping\u2026' : again ? '\u21bb Replay Last' : '\u21bb Repeat Play',
    title,
    disabled: stopping || (!hasBuffer && !on),
  };
}

const kindWord = (k) => k.charAt(0).toUpperCase() + k.slice(1).replace(/_/g, ' ');

// banner: every critical entry. strip: the others, with same-kind entries for
// several inputs folded into one card, and a link only on the appliance's own
// page. more: how many cards lie beyond the first two. serviceSeverity: the
// worst severity of an entry that links to /service, or null.
export function warningsFor(p, { own = true } = {}) {
  const all = (p.warnings && p.warnings.entries) || [];
  const cards = [];
  const folds = new Map();
  for (const e of all.filter((x) => x.severity !== 'critical')) {
    const key = e.subject ? e.kind + '|' + e.severity : '';
    const prior = key && folds.get(key);
    if (prior) { prior.subjects.push(e.subject); continue; }
    const card = { severity: e.severity, kind: e.kind, title: e.title, message: e.message, link: own ? e.link || null : null, subjects: e.subject ? [e.subject] : [] };
    if (key) folds.set(key, card);
    cards.push(card);
  }
  const strip = cards.map((c) => {
    const folded = c.subjects.length > 1;
    return { severity: c.severity, title: folded ? kindWord(c.kind) : c.title, message: folded ? c.message + ' on ' + c.subjects.join(', ') : c.message, link: c.link };
  });
  let serviceSeverity = null;
  for (const e of all) {
    if (e.link === '/service' && (serviceSeverity === null || RANK[e.severity] < RANK[serviceSeverity])) serviceSeverity = e.severity;
  }
  const banner = all.filter((e) => e.severity === 'critical').map((e) => ({ severity: e.severity, title: e.title, message: e.message }));
  return { banner, strip, more: Math.max(0, strip.length - 2), serviceSeverity };
}
