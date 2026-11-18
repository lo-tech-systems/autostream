// Values a page has sent and not yet seen come back, so a push that lands
// before the reply does not move a control the person is using.
const HOLD_MS = 2000;

export class Pending {
  constructor(now = Date.now) { this._now = now; this._held = new Map(); }

  // Hold value for key until the state copy reaches replyVersion (null while
  // the reply is not in yet), or for ms (2 s unless given).
  mark(key, value, replyVersion, ms = HOLD_MS) {
    this._held.set(key, { value, version: replyVersion, until: this._now() + ms });
  }

  // The held value for key, else live.
  value(key, live) {
    const h = this._held.get(key);
    return h && this._now() < h.until ? h.value : live;
  }

  // Let go of key at once, for a request that failed.
  drop(key) { this._held.delete(key); }

  // Drop what the copy has reached or the time has passed; all of it on a resync.
  settle(viewVersion, resync) {
    for (const [k, h] of this._held) {
      if (resync || this._now() >= h.until || (h.version != null && viewVersion >= h.version)) this._held.delete(k);
    }
  }
}
