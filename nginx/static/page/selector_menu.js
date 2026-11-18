// The appliance selector: its dropdown, drawn again from this appliance's own
// peers part each time it opens. The page starts with the list drawn by the server.
import { SELECTOR_NOTE } from '../shared/texts.js';

const href = (a, page) => (page === 'equaliser' ? a.equaliser_path || '/a/' + a.id + '/equaliser' : a.home_path || (a.is_bound ? '/' : '/a/' + a.id + '/'));

// This appliance first, then the appliances it may control; one that cannot be
// used yet is listed with the reason.
const listFrom = (self, entries) => [self].concat(entries.filter((e) => e.control && e.id !== self.id).map((e) => ({
  id: e.id, hostname: e.hostname, is_bound: false, note: !e.protocol_ok ? SELECTOR_NOTE.update : e.configured === false ? SELECTOR_NOTE.setup : '',
})));

function fill(dd, nameEl, list, currentId, page) {
  dd.textContent = '';
  list.forEach((a, i) => {
    if (!a.is_bound && (i === 0 || list[i - 1].is_bound)) {
      const d = Object.assign(document.createElement('div'), { className: 'appliance-selector-divider' });
      d.setAttribute('role', 'separator');
      d.setAttribute('aria-hidden', 'true');
      dd.appendChild(d);
    }
    const name = String(a.hostname || 'autostream');
    const o = document.createElement(a.note ? 'span' : 'a');
    if (a.note) { o.textContent = name + ' (' + a.note + ')'; o.setAttribute('aria-disabled', 'true'); } else { o.href = href(a, page); o.textContent = name; }
    o.className = 'appliance-selector-option' + (a.note ? ' appliance-selector-option-note' : '') + (a.id === currentId ? ' appliance-selector-option-active' : '');
    o.setAttribute('role', 'option');
    o.setAttribute('aria-selected', String(a.id === currentId));
    if (a.is_bound) o.style.fontWeight = '700';
    dd.appendChild(o);
  });
  const cur = list.find((a) => a.id === currentId);
  if (nameEl && cur) nameEl.textContent = String(cur.hostname || 'autostream');
}

// Wire the selector already on the page: open and close, arrow keys, and the
// list read again when it opens. *self* is this appliance's own entry.
export function initSelector({ page = 'home', currentId = '', self = null } = {}) {
  const btn = document.getElementById('appliance-selector-btn');
  const dd = document.getElementById('appliance-selector-dropdown');
  if (!btn || !dd || !self) return;
  const id = document.getElementById('appliance-selector').getAttribute('data-current-id') || currentId;
  const nameEl = document.getElementById('appliance-selector-current');
  const close = () => { dd.hidden = true; btn.setAttribute('aria-expanded', 'false'); };
  const refresh = () => fetch('/api/v1/state?parts=peers', { cache: 'no-store' }).then((r) => r.json()).then((d) => {
    const peers = d && d.parts && d.parts.peers;
    if (peers && Array.isArray(peers.entries)) fill(dd, nameEl, listFrom(self, peers.entries), id, page);
  }).catch(() => {});
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    const wasOpen = !dd.hidden;
    dd.hidden = wasOpen;
    btn.setAttribute('aria-expanded', String(!wasOpen));
    if (!wasOpen) refresh();
  });
  document.addEventListener('click', () => { if (!dd.hidden) close(); });
  dd.addEventListener('keydown', (e) => {
    const opts = Array.from(dd.querySelectorAll('a.appliance-selector-option'));
    const i = opts.indexOf(document.activeElement);
    if (e.key === 'ArrowDown') { e.preventDefault(); (opts[i + 1] || opts[0] || btn).focus(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); (opts[i - 1] || opts[opts.length - 1] || btn).focus(); }
    else if (e.key === 'Escape') { close(); btn.focus(); }
  });
}
