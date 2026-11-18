// The Repeat Play button. The server's repeat state decides what it shows
// (repeatControls); a click shows its effect at once and holds it until the
// state copy has caught up.
import { repeatControls } from '../../shared/state_view.js';
import { submit } from './home_intents.js';

const STOPPING = 'Stopping\u2026';
let stopping = false;

// While a replay fades out, everything on the page but the button is dimmed
// and inert, so nothing is started against a session that is ending.
function quiesce(on) {
  if (on === stopping) return;
  stopping = on;
  document.body.classList.toggle('repeat-stopping', on);
  const targets = [document.getElementById('now-playing-card'), document.getElementById('outputs-list')];
  const top = document.querySelector('.airplay-top-controls');
  if (top) targets.push(...Array.from(top.children).filter((k) => k.id !== 'repeat-btn'));
  for (const t of targets) if (t) t.toggleAttribute('inert', on);
}

export function drawRepeat(view, pending) {
  const btn = document.getElementById('repeat-btn');
  if (!btn) return;
  const rc = repeatControls(view.parts);
  const held = pending.value('repeat', null);
  const state = held ? held.state : rc.state;
  btn.hidden = !rc.shown;
  btn.setAttribute('data-state', state);
  btn.classList.toggle('active', state !== 'off');
  btn.disabled = state === 'stopping' || (held ? false : rc.disabled);
  btn.textContent = state === 'stopping' ? STOPPING : rc.label;
  btn.title = held ? held.title : rc.title;
  quiesce(state === 'stopping');
}

// repeating -> stop; armed -> disarm; off -> arm (replays at once when idle
// with a buffer, otherwise at the end of the live stream).
export function initRepeat(pending, redraw) {
  const btn = document.getElementById('repeat-btn');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    if (btn.disabled) return;
    const s = btn.getAttribute('data-state');
    const arm = !(s === 'repeating' || s === 'armed');
    pending.mark('repeat', { state: arm ? 'armed' : s === 'repeating' ? 'stopping' : 'off', title: arm ? 'Starting\u2026' : '' }, null);
    redraw();
    let reply = null;
    try { reply = await submit('repeat.arm', { armed: arm }); } catch (e) { /* shown as a failure below */ }
    if (reply && reply.ok && ((reply.result || {}).ack || {}).ok) pending.mark('repeat', pending.value('repeat', null), reply.version);
    else pending.drop('repeat');
    redraw();
    setTimeout(redraw, 2100);
  });
}

