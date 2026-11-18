// Home: holds the appliance's state, keeps it current from the change stream
// and asks each module to draw it.
import { StateStream } from '../../shared/state_stream.js';
import { Pending } from '../../shared/pending.js';
import { live } from '../../shared/state_view.js';
import { initSelector } from '../selector_menu.js';
import { initSpeakers, drawSpeakers } from './home_speakers.js';
import { initAutostart, drawAutostart } from './home_autostart.js';
import { initNowPlaying, drawNowPlaying } from './home_now_playing.js';
import { initRepeat, drawRepeat } from './home_repeat.js';
import { initWarnings, drawWarnings } from './home_warnings.js';

const island = JSON.parse(document.getElementById('page-data').textContent);
const prefs = island.prefs;
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
    () => drawWarnings(p, redraw), () => drawNowPlaying(p, prefs, island.icons)]) {
    try { step(); } catch (e) { console.error(e); }
  }
}

initSpeakers({ prefs, pending, redraw });
initAutostart();
initRepeat(pending, redraw);
initWarnings(redraw);
initNowPlaying(prefs);
initSelector({ page: 'home', currentId: island.local_id });
stream = new StateStream({ base: '/api/v1', initial: island.state, onChange: draw });
draw(stream.view);
