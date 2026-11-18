// What the appliance wants a person to know: the red banner for critical
// entries, the strip of cards for the rest, and the Service tab's marker.
import { warningsFor } from '../../shared/state_view.js';
import { moreSuffix, moreCards } from '../../shared/texts.js';

const SEVERITIES = ['critical', 'warning', 'info'];
let bannerOpen = false;
let stripOpen = false;
let last = '';

const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
};

function drawBanner(list) {
  let b = document.getElementById('red-banner');
  if (!list.length) {
    if (b) { b.remove(); document.getElementById('red-banner-spacer').remove(); }
    bannerOpen = false;
    return;
  }
  if (!b) {
    b = el('div');
    b.id = 'red-banner';
    const s = el('div');
    s.id = 'red-banner-spacer';
    document.body.prepend(b, s);
  }
  const line = (e) => e.title + ': ' + e.message;
  const many = list.length > 1;
  b.textContent = '';
  if (many && bannerOpen) for (const e of list) b.appendChild(el('div', '', line(e)));
  else b.textContent = line(list[0]) + (many ? moreSuffix(list.length - 1) : '');
  b.classList.toggle('red-banner-tap', many);
  if (many) b.setAttribute('aria-expanded', String(bannerOpen)); else b.removeAttribute('aria-expanded');
}

function card(w) {
  const c = el(w.link ? 'a' : 'div', 'warning-card sev-' + w.severity + (w.link ? ' warning-card-link' : ''));
  if (w.link) c.href = w.link;
  const body = el('div', 'warning-card-body');
  body.append(el('div', 'warning-card-title', w.title), el('div', 'warning-card-msg', w.message));
  c.appendChild(body);
  if (w.link) c.appendChild(el('span', 'warning-card-chevron', '\u203a'));
  return c;
}

function drawStrip(w, redraw) {
  const strip = document.getElementById('warnings-strip');
  if (!strip) return;
  strip.textContent = '';
  strip.hidden = !w.strip.length;
  for (const c of stripOpen ? w.strip : w.strip.slice(0, 2)) strip.appendChild(card(c));
  if (w.more && !stripOpen) {
    const m = el('button', 'warning-more', moreCards(w.more));
    m.type = 'button';
    m.addEventListener('click', () => { stripOpen = true; redraw(); });
    strip.appendChild(m);
  }
}

export function initWarnings(redraw) {
  document.addEventListener('click', (e) => {
    if (e.target.closest('#red-banner') && document.querySelector('#red-banner.red-banner-tap')) { bannerOpen = !bannerOpen; redraw(); }
  });
}

export function drawWarnings(p, redraw) {
  const w = warningsFor(p, { own: true });
  const key = JSON.stringify([w, bannerOpen, stripOpen]);
  if (key !== last) { last = key; drawBanner(w.banner); drawStrip(w, redraw); }
  const tab = document.getElementById('service-nav-tab');
  if (tab) for (const s of SEVERITIES) tab.classList.toggle('nav-tab-warn-' + s, w.serviceSeverity === s);
}
