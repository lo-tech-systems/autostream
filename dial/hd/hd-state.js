// hd-state.js: what the HD page holds besides the dial's own state: the
// page's values (ui), the optimistic values, the pressed transport button,
// the replay clock, and the hook the page's entry sets so that what asks
// for a redraw does not have to import the file that draws.

import { CONFIG, POWER_IDLE_UI, REPLAY_ROWS } from "./hd-tables.js";

// Set by the page's entry once render exists; what asks for a redraw calls this.
export const hooks = { render: () => {} };

// ---- State, optimistic values ----------------------------------------

// What the page itself holds besides the dial's state.
export const ui = {
    state: null, stateAt: Date.now(), offline: false, vm: null,
    eqOpen: false, eqFor: null, sheetOpen: false, info: null, infoBusy: false,
    notice: null, viewing: null,
    activityAt: 0,
    focusShown: null, listScrolledAt: { appliances: 0, speakers: 0 }, autoScrollUntil: 0,
    replayClock: null, power: Object.assign({}, POWER_IDLE_UI), host: window.location.hostname,
    // The keypad's own buffer (the digits live nowhere else), the request
    // it was typed for, and the request the person turned away.
    pin: { forKey: null, digits: "", dismissedAt: null },
    pinShown: false
};
export const PIN_IDLE = { forKey: null, digits: "" };
export const pending = {};         // control key -> { value, deadline }
export const dragging = new Set();  // control keys under a finger

// The pressed transport button (play, back to the start or stop), held
// down from the press until a PRESS_RELEASES rule lets it go; only one
// at a time, though a Stop takes the place of a held play or restart.
// { state, id (the appliance), target (the button), from (the record's
// state at the press), token (the dial's identity for the request, once
// known), base (the timer position a Stop held), before (the dial's
// latest request at the press), serial (which press this is) }.
// "none": nothing is held. "sent": the request is out and its token is
// not known. "bound": the token is known. Each event leads from a state
// to the next in PRESS_NEXT; one it does not list changes nothing.
const PRESS_NEXT = {
    none: { start: "sent" },
    sent: { replace: "sent", token: "bound", lost: "none", release: "none" },
    bound: { replace: "sent", token: "bound", lost: "none", release: "none" }
};
const PRESS_REPLACES = (held, target) => target === "stop" && held !== "stop";

export const press = {
    state: "none", id: null, target: null, from: null, token: null, base: null, before: null, serial: 0,

    fire(event) {
        const next = PRESS_NEXT[this.state][event];
        if (!next) { return false; }
        this.state = next;
        return true;
    },

    current() {
        return this.state === "none" ? null : this;
    },

    // The press's serial, or 0 when one is already held. *position* is
    // where the timer stands, *before* the request the dial last showed.
    start(target, appliance, position, before) {
        const event = this.state === "none" ? "start" : PRESS_REPLACES(this.target, target) ? "replace" : "";
        if (!this.fire(event)) { return 0; }
        this.serial += 1;
        Object.assign(this, {
            id: appliance.id, target: target, from: appliance.repeat.state, token: null,
            base: target === "stop" ? position : null, before: before
        });
        return this.serial;
    },

    // The answer to press *serial*'s request: its reply, or false when it
    // was refused or lost. A reply with no token leaves the press to be
    // bound to the first new request the state shows.
    sent(serial, reply) {
        if (serial !== this.serial) { return; }
        if (!reply) {
            this.fire("lost");
        } else if (typeof reply.token === "number" && this.fire("token")) {
            this.token = reply.token;
        }
    },

    // Where a held Stop holds the timer for appliance *id*, or null.
    heldStop(id) {
        return this.state !== "none" && this.target === "stop" && this.id === id ? this.base : null;
    },

    // Looks at the state: binds a press that has no token to the
    // request it shows, and lets the press go when a rule says so.
    observe(ctx) {
        if (this.state === "none") { return; }
        if (this.token === null && ctx.t && ctx.t.requested_at !== this.before && this.fire("token")) {
            this.token = ctx.t.requested_at;
        }
        const own = !!ctx.t && this.token !== null && ctx.t.requested_at === this.token;
        if (PRESS_RELEASES.some((rule) => rule(Object.assign({ press: this, own: own }, ctx)))) {
            this.fire("release");
        }
    }
};
// A pressed transport button (see *press*) is held down from the press
// until the first of these lets it go. Each reads the state alone, so
// the button can never stay down: the request is the dial's own, and it
// always ends accepted or rejected, with the appliance's next report to
// follow. Each rule gets { press, focus, offline, r (the appliance's
// record, when it has a replay row), t (the dial's latest request of the
// press's kind), own (t is this press's request) }.
export const PRESS_RELEASES = [
    // the appliance is no longer the one being followed, or the dial is gone
    (c) => c.offline || !c.focus || c.focus.id !== c.press.id,
    // the appliance stopped what it was replaying, or has no record
    (c) => !c.r || (c.press.from === "replaying" && c.r.state !== "replaying"),
    // another request has taken the press's place
    (c) => c.press.token !== null && !c.own,
    (c) => c.own && c.t.state === "rejected",
    // the appliance accepted it and has reported since
    (c) => c.own && c.t.state === "accepted" && c.r.observed_at >= c.t.changed_at
];

export function setPending(key, value) {
    pending[key] = { value: value, deadline: Date.now() + CONFIG.pendingMs };
    setTimeout(hooks.render, CONFIG.pendingMs + 30);
}

// The value to show for a control: the optimistic one until the state
// agrees with it or its time is up, then the state's.
export function settle(key, actual) {
    const p = pending[key];
    if (!p) { return actual; }
    if (p.value === actual || Date.now() >= p.deadline) {
        delete pending[key];
        return actual;
    }
    return p.value;
}

export function rollBack(keys) {
    (keys || []).forEach((key) => { delete pending[key]; });
    hooks.render();
}

// ---- The replay clock --------------------------------------------------

// The page keeps its own clock for a running replay, { id, base, at,
// slew, running }: the position was *base* seconds at page time *at*,
// and for the next while it runs *slew* fast (or, negative, slow). The
// dial's position arrives a little early or late each time, so it only
// steers the clock: a small difference is worked off by running slightly
// fast or slow for a few seconds, which keeps the timer even and never
// takes it backwards, and only a large one (a restart, another replay)
// moves it at once.
export function clockRate(clock, now) {
    return (now - clock.at) / 1000 < CONFIG.replaySlewS ? 1 + clock.slew : 1;
}

export function clockPosition(clock, now) {
    if (!clock.running) { return clock.base; }
    const gone = (now - clock.at) / 1000;
    return clock.base + gone + clock.slew * Math.min(gone, CONFIG.replaySlewS);
}

export function nextReplayClock(old, state, now) {
    const focus = state.appliances.find((a) => a.id === state.focus.appliance_id);
    const r = focus ? focus.repeat : null;
    const row = r ? REPLAY_ROWS[r.state] : null;
    if (!row || row.time !== "position") { return null; }
    const held = old && old.id === focus.id ? old : null;
    const local = held ? clockPosition(held, now) : null;
    if (r.state !== "replaying") {
        // Not moving any more: it stops where the page had it, which
        // is where Stop held it when that was pressed.
        const pressed = press.heldStop(focus.id);
        const base = pressed !== null ? pressed : held ? local : r.position_s;
        return { id: focus.id, base: base, at: now, slew: 0, running: false };
    }
    const error = held && held.running ? r.position_s - local : Infinity;
    if (Math.abs(error) > CONFIG.replayResyncS) {
        return { id: focus.id, base: r.position_s, at: now, slew: 0, running: true };
    }
    const slew = Math.max(-CONFIG.replayMaxSlew, Math.min(CONFIG.replayMaxSlew, error / CONFIG.replaySlewS));
    return { id: focus.id, base: local, at: now, slew: slew, running: true };
}

