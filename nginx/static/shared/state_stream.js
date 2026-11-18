// StateStream -- holds the appliance's state and keeps it current from the
// change stream at base + '/events', resumed across reconnects.
//
//   const s = new StateStream({ base: '/api/v1', initial, onChange, onAccess, onUp, onDown, onRefused });
//   s.view  // { boot, version, time, parts, partVersions }
//   onChange(view, names, resync): names are the parts that changed (null when
//   the copy was replaced whole); resync is true when it was replaced because
//   the stream could not say what moved.
//
// - Opens only while the document is visible, and resumes with ?since=.
// - A dropped stream that is not open again within graceMs is down; one the
//   browser gave up on is down at once and is opened again after about
//   retryMs, with jitter, so refused tabs do not retry together.
// - While the stream is down the state is fetched every 2 s. A new boot
//   replaces the copy whole and is never compared by version.
// - isUp() stays true while the page is hidden if the stream was up.
// - onRefused(status, error) is called when a state fetch is answered with
//   anything but a state (status 0 for a network failure).
const call = (fn, ...args) => { if (typeof fn === 'function') { try { fn(...args); } catch (e) { /* a handler's fault is its own */ } } };

export class StateStream {
  constructor({ base, initial, onChange, onAccess, onUp, onDown, onRefused, graceMs = 5000, retryMs = 30000 }) {
    Object.assign(this, { base, onChange, onAccess, onUp, onDown, onRefused, graceMs, retryMs });
    this._view = { boot: '', version: 0, time: 0, parts: {}, partVersions: {} };
    if (initial) this._adopt(initial);
    this._es = null; this._up = false; this._gone = false; this._seq = 0;
    this._grace = null; this._retry = null; this._fb = null;
    document.addEventListener('visibilitychange', () => {
      if (this._gone) return;
      if (document.hidden) { this._stop(); } else if (!this._es && !this._retry) { this._open(); }
    });
    window.addEventListener('pagehide', () => this._stop());
    if (window.EventSource) this._open(); else this._goDown();
  }

  get view() { return this._view; }

  isUp() { return this._up; }

  restart() { this._stop(); this._open(); }

  close() { this._gone = true; this._stop(); this._up = false; }

  // Fetch the named parts every ms while the page is visible and merge them
  // into the copy; the versions are left alone. Returns stop().
  pollParts(names, ms) {
    const tick = async () => {
      if (document.hidden || this._gone) return;
      try {
        const b = await this._fetchState('?parts=' + names.join(','));
        if (this._view.boot && b.boot !== this._view.boot) return;
        Object.assign(this._view.parts, b.parts);
        if (b.time) this._view.time = b.time;
        call(this.onChange, this._view, names, false);
      } catch (e) { /* the next tick tries again */ }
    };
    const t = setInterval(tick, ms);
    tick();
    return () => clearInterval(t);
  }

  _adopt(b) {
    this._view = { boot: b.boot, version: b.version, time: b.time || 0, parts: b.parts || {}, partVersions: b.part_versions || {} };
  }

  async _fetchState(query = '') {
    let r;
    try { r = await fetch(this.base + '/state' + query, { cache: 'no-store', credentials: 'same-origin' }); } catch (e) { call(this.onRefused, 0, 'unreachable'); throw e; }
    let b = null;
    let readable = true;
    try { b = await r.json(); } catch (e) { readable = false; }
    // A 404 or 503 behind the proxy arrives as a 200 that names its status.
    const status = r.ok ? (b && b.ok === false && b.error_status) || 200 : r.status;
    if (status !== 200) { call(this.onRefused, status, b && b.error); throw new Error('state ' + status); }
    if (!readable) throw new Error('state body');
    return b;
  }

  async _resync() {
    const n = ++this._seq;
    try {
      const b = await this._fetchState();
      if (n !== this._seq || this._gone) return;
      this._adopt(b);
      call(this.onChange, this._view, null, true);
    } catch (e) {
      if (!this._gone) setTimeout(() => this._resync(), 2000);
    }
  }

  _startFallback() {
    if (this._fb || this._gone || document.hidden) return;
    const tick = async () => {
      try {
        const b = await this._fetchState();
        if (this._up || this._gone) return;
        const same = b.boot === this._view.boot;
        if (same && b.version <= this._view.version) return;
        this._adopt(b);
        call(this.onChange, this._view, null, !same);
      } catch (e) { /* the next tick tries again */ }
    };
    this._fb = setInterval(tick, 2000);
    tick();
  }

  _stopFallback() { if (this._fb) { clearInterval(this._fb); this._fb = null; } }

  _goDown() {
    this._up = false;
    if (this._fb) return;
    this._startFallback();
    call(this.onDown);
  }

  _stop() {
    if (this._es) { const old = this._es; this._es = null; try { old.close(); } catch (e) { /* already closed */ } }
    for (const k of ['_grace', '_retry']) { clearTimeout(this[k]); this[k] = null; }
    this._stopFallback();
  }

  _open() {
    if (this._gone || this._es || !window.EventSource || document.hidden) return;
    const v = this._view;
    let src;
    try { src = new EventSource(this.base + '/events' + (v.boot ? '?since=' + encodeURIComponent(v.boot + '-' + v.version) : '')); } catch (e) { return; }
    this._es = src;
    src.addEventListener('open', () => {
      if (src !== this._es) return;
      clearTimeout(this._grace); this._grace = null;
      this._stopFallback();
      if (!this._up) { this._up = true; call(this.onUp); }
    });
    src.addEventListener('change', (ev) => {
      if (src !== this._es) return;
      let d;
      try { d = JSON.parse(ev.data); } catch (e) { return; }
      if (!d) return;
      if (d.resync) { this._resync(); return; }
      const names = Object.keys(d.data || {});
      Object.assign(this._view.parts, d.data);
      for (const n of names) this._view.partVersions[n] = d.version;
      this._view.boot = d.boot; this._view.version = d.version;
      call(this.onChange, this._view, names, false);
    });
    src.addEventListener('access', (ev) => {
      if (src !== this._es) return;
      try { call(this.onAccess, JSON.parse(ev.data)); } catch (e) { /* not JSON */ }
    });
    src.addEventListener('error', () => {
      if (src !== this._es) return;
      if (src.readyState === 2) {
        this._stop();
        this._goDown();
        this._retry = setTimeout(() => { this._retry = null; this._open(); }, this.retryMs * (0.8 + Math.random() * 0.4));
      } else if (!this._grace) {
        this._grace = setTimeout(() => { this._grace = null; this._goDown(); }, this.graceMs);
      }
    });
  }
}
