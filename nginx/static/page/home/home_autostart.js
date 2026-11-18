// The pin (in the Master Volume header, or above the speaker list): it saves the speakers playing now as the
// Auto-Start set, after a confirmation.
import { AUTO_START_CONFIRM, REFUSAL } from '../../shared/texts.js';
import { playing } from '../../shared/state_view.js';
import { submit } from './home_intents.js';

const $ = (id) => document.getElementById(id);

export function initAutostart() {
  const modal = $('autoStartModal');
  if (!modal) return;
  $('autoStartText').textContent = AUTO_START_CONFIRM;
  const close = () => modal.classList.remove('show');
  $('autostart-pin').addEventListener('click', () => modal.classList.add('show'));
  $('autoStartCancel').addEventListener('click', close);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && modal.classList.contains('show')) close(); });
  $('autoStartYes').addEventListener('click', async () => {
    close();
    let reply;
    try { reply = await submit('outputs.save_default', {}); } catch (e) { reply = { ok: false }; }
    if (!reply.ok) window.showInfoModal('Auto-Start', REFUSAL[reply.error] || REFUSAL.settings_unavailable);
  });
}

// Shown during a session; set when the speakers on are the saved set.
export function drawAutostart(p) {
  const pin = $('autostart-pin');
  if (!pin) return;
  const set = !!(p.outputs && p.outputs.default_matches);
  pin.hidden = !playing(p);
  pin.setAttribute('aria-pressed', String(set));
  pin.classList.toggle('is-set', set);
}
