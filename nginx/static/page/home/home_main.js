// Home: holds the appliance's state, keeps it current from the change stream
// and asks each module to draw it.
import { StateStream } from '../../shared/state_stream.js';
import { Pending } from '../../shared/pending.js';
import { live } from '../../shared/state_view.js';
import { initSelector } from '../selector_menu.js';
import { RELAY } from '../../shared/texts.js';
import { setBase } from './home_intents.js';
import { initSpeakers, drawSpeakers } from './home_speakers.js';
import { initAutostart, drawAutostart } from './home_autostart.js';
import { initNowPlaying, drawNowPlaying } from './home_now_playing.js';
import { initRepeat, drawRepeat } from './home_repeat.js';
import { initWarnings, drawWarnings } from './home_warnings.js';

const island = JSON.parse(document.getElementById('page-data').textContent);
const prefs = island.prefs;
const own = island.own !== false;
const base = island.base || '/api/v1';
const pending = new Pending();
let stream = null;
let stopVu = null;
const redraw = () => draw(stream.view);

function draw(view, names, resync) {
  pending.settle(view.version, resync);
  const p = view.parts;
  const vu = prefs.show_input_detail && live(p);
  if (vu && !stopVu) stopVu = stream.pollParts(['inputs'], 1000);
  if (!vu && stopVu) { stopVu(); stopVu = null; }
  for (const step of [() => drawSpeakers(view), () => drawAutostart(p), () => drawRepeat(view, pending),
    () => drawWarnings(p, redraw, own), () => drawNowPlaying(p, prefs, island.icons)]) {
    try { step(); } catch (e) { console.error(e); }
  }
}

setBase(base);
initSpeakers({ prefs, pending, redraw, own });
initAutostart();
initRepeat(pending, redraw);
initWarnings(redraw);
initNowPlaying(prefs);
initSelector({ page: 'home', currentId: island.local_id, self: island.selector[0] });
// Another appliance's page goes back to this one's when the relay says it cannot
// be had, or after three failures in a row to reach it.
let failures = 0;
const onRefused = (status, error) => {
  if (own) return;
  const ph = document.getElementById('outputs-placeholder');
  if (ph && RELAY[error]) { ph.textContent = RELAY[error]; ph.hidden = false; }
  failures = [403, 404, 409].includes(status) ? 3 : failures + 1;
  if (failures >= 3) window.location.href = '/';
};
stream = new StateStream({ base, initial: island.state, onChange: draw, onUp: () => { failures = 0; }, onRefused });
draw(stream.view);
