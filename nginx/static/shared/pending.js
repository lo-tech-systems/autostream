// Values a page has sent and not yet seen come back, so a push that lands
// before the reply does not move a control the person is using.
const HOLD_MS = 2000;

export class Pending {
  constructor(now = Date.now) { this._now = now; this._held = new Map(); }

  // Hold value for key until the state copy reaches replyVersion (null while
  // the reply is not in yet), or for 2 s.
  mark(key, value, replyVersion) {
    this._held.set(key, { value, version: replyVersion, at: this._now() });
  }

  // The held value for key, else live.
  value(key, live) {
    const h = this._held.get(key);
    return h && this._now() - h.at < HOLD_MS ? h.value : live;
  }

  // Drop what the copy has reached or the time has passed; all of it on a resync.
  settle(viewVersion, resync) {
    for (const [k, h] of this._held) {
      if (resync || this._now() - h.at >= HOLD_MS || (h.version != null && viewVersion >= h.version)) this._held.delete(k);
    }
  }
}
