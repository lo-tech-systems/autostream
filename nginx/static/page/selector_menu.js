// The appliance selector: its dropdown, and its list from /api/appliances.
const href = (a, page) => (page === 'equaliser' ? a.equaliser_path || '/a/' + a.id + '/equaliser' : a.home_path || (a.is_bound ? '/' : '/a/' + a.id + '/'));

function fill(dd, nameEl, list, currentId, page) {
  dd.textContent = '';
  list.forEach((a, i) => {
    if (!a.is_bound && (i === 0 || list[i - 1].is_bound)) {
      const d = Object.assign(document.createElement('div'), { className: 'appliance-selector-divider' });
      d.setAttribute('role', 'separator');
      d.setAttribute('aria-hidden', 'true');
      dd.appendChild(d);
    }
    const o = Object.assign(document.createElement('a'), { href: href(a, page), textContent: String(a.hostname || 'autostream') });
    o.className = 'appliance-selector-option' + (a.id === currentId ? ' appliance-selector-option-active' : '');
    o.setAttribute('role', 'option');
    o.setAttribute('aria-selected', String(a.id === currentId));
    if (a.is_bound) o.style.fontWeight = '700';
    dd.appendChild(o);
  });
  const cur = list.find((a) => a.id === currentId);
  if (nameEl && cur) nameEl.textContent = String(cur.hostname || 'autostream');
}

// Wire the selector already on the page: open and close, arrow keys, and the
// appliance list fetched when it opens and every 15 s while the page shows.
export function initSelector({ page = 'home', currentId = '' } = {}) {
  const btn = document.getElementById('appliance-selector-btn');
  const dd = document.getElementById('appliance-selector-dropdown');
  if (!btn || !dd) return;
  const id = document.getElementById('appliance-selector').getAttribute('data-current-id') || currentId;
  const nameEl = document.getElementById('appliance-selector-current');
  const close = () => { dd.hidden = true; btn.setAttribute('aria-expanded', 'false'); };
  const refresh = () => fetch('/api/appliances', { cache: 'no-store' }).then((r) => r.json()).then((d) => {
    if (d && d.ok && Array.isArray(d.appliances)) fill(dd, nameEl, d.appliances, id, page);
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
    const opts = Array.from(dd.querySelectorAll('.appliance-selector-option'));
    const i = opts.indexOf(document.activeElement);
    if (e.key === 'ArrowDown') { e.preventDefault(); (opts[i + 1] || opts[0] || btn).focus(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); (opts[i - 1] || opts[opts.length - 1] || btn).focus(); }
    else if (e.key === 'Escape') { close(); btn.focus(); }
  });
  refresh();
  setInterval(() => { if (!document.hidden) refresh(); }, 15000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
}
