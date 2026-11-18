// hd-state.js: what the HD page holds besides the state's two parts: the
// page's values (ui), the optimistic values, the pressed transport button,
// the replay clock, and the hook the page's entry sets so that what asks
// for a redraw does not have to import the file that draws.

import { CONFIG, POWER_IDLE_UI, REPLAY_ROWS } from "./hd-tables.js";
import { Pending } from "/static/shared/pending.js";

// Set by the page's entry once render exists; what asks for a redraw calls this.
export const hooks = { render: () => {}, touched: () => {} };

// ---- State, optimistic values ----------------------------------------

// What the page itself holds besides the state: dial and focused are its two
// parts, time the core's clock reading that came with them at stateAt.
export const ui = {
    dial: null, focused: null, time: 0, stateAt: Date.now(), offline: false, vm: null,
    eqOpen: false, eqFor: null, sheetOpen: false, info: null, infoBusy: false,
    notice: null, viewing: null, autoStartAsked: false, activityAt: 0,
    startFailureAnswered: null,   // the key of the "could not start" card the person has answered
    // The idle clock for the open panels: its timer, the fingers now held
    // on a followed drag, and whether the last look at the state was asleep.
    panelTimer: 0, fingers: 0, wasAsleep: false,
    focusShown: null, listScrolledAt: { appliances: 0, speakers: 0 }, autoScrollUntil: 0,
    replayClock: null, power: Object.assign({}, POWER_IDLE_UI), host: window.location.hostname,
    // The keypad's own buffer (the digits live nowhere else), the request
    // it was typed for, and the request the person turned away.
    pin: { forKey: null, digits: "", dismissedAt: null },
    pinShown: false
};
export const PIN_IDLE = { forKey: null, digits: "" };
export const pending = new Pending();
export const dragging = new Set();  // control keys under a finger

// The pressed transport button, held down from the press until a
// PRESS_RELEASES rule lets it go; one at a time, though a Stop takes the
// place of a held play or restart. { state ("none", "sent", or "bound" once
// token, the first new request the dial's transport block shows, is known),
// id (the appliance), target (the button), from (the record's state at the
// press), base (the timer position a Stop held), before (the dial's latest
// request at the press), serial }. PRESS_NEXT gives each event's next state.
const PRESS_NEXT = {
    none: { start: "sent" },
    sent: { replace: "sent", token: "bound", lost: "none", release: "none" },
    bound: { replace: "sent", lost: "none", release: "none" }
};
const PRESS_REPLACES = (held, target) => target === "stop" && held !== "stop";

export const press = {
    state: "none", id: null, target: null, from: null, token: null, base: null, before: null, serial: 0,

    fire(event) {
        const next = PRESS_NEXT[this.state][event];
        if (next) { this.state = next; }
        return !!next;
    },

    current() { return this.state === "none" ? null : this; },

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

    // The answer to press *serial*'s request: false lets it go.
    sent(serial, reply) {
        if (serial === this.serial && !reply) { this.fire("lost"); }
    },

    // Where a held Stop holds the timer for appliance *id*, or null.
    heldStop(id) { return this.state !== "none" && this.target === "stop" && this.id === id ? this.base : null; },

    // Looks at the state: binds the press to the first new request it
    // shows, and lets the press go when a rule says so.
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
// A pressed transport button is held until the first of these lets it go.
// Each reads the state alone, and the dial's request always ends accepted or
// rejected, so it never stays down. Each gets { press, focus, offline, r (the
// appliance's record with a replay row), t (the dial's latest request of the
// press's kind), own (t is this press's) }.
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

// Shows *value* for control *key* until the focused appliance reaches
// *version* (null: until it is known) or *ms* runs out, then the state's.
export function hold(key, value, version, ms) {
    const wait = ms || CONFIG.pendingMs;
    pending.mark(key, value, version === undefined ? null : version, wait);
    setTimeout(hooks.render, wait + 30);
}

export function rollBack(keys) {
    (keys || []).forEach((key) => pending.drop(key)); hooks.render();
}

// A record's position on the core's clock *time*: a replay's is the reported
// one carried on from when it was reported, up to the recording's length.
export function reportedPosition(r, time) {
    const at = r.position_s + (r.state === "replaying" ? Math.max(0, time - r.observed_at) : 0);
    return Math.max(0, r.duration_s > 0 ? Math.min(at, r.duration_s) : at);
}

// ---- The replay clock --------------------------------------------------

// The page keeps its own clock for a running replay, { id, base, at, slew,
// running }: the position was *base* seconds at page time *at*, and for the
// next while it runs *slew* fast (or, negative, slow). The dial's position
// only steers it: a small difference is worked off over a few seconds, which
// keeps the timer even and never takes it backwards; a large one (a restart,
// another replay) moves it at once.
export function clockRate(clock, now) {
    return (now - clock.at) / 1000 < CONFIG.replaySlewS ? 1 + clock.slew : 1;
}

export function clockPosition(clock, now) {
    if (!clock.running) { return clock.base; }
    const gone = (now - clock.at) / 1000;
    return clock.base + gone + clock.slew * Math.min(gone, CONFIG.replaySlewS);
}

export function nextReplayClock(old, dial, time, now) {
    const focus = dial.appliances.find((a) => a.id === dial.focus.appliance_id);
    const r = focus ? focus.repeat : null;
    const row = r ? REPLAY_ROWS[r.state] : null;
    if (!row || row.time !== "position") { return null; }
    const held = old && old.id === focus.id ? old : null;
    const local = held ? clockPosition(held, now) : null;
    if (r.state !== "replaying") {
        // Not moving any more: it stops where the page had it, which
        // is where Stop held it when that was pressed.
        const pressed = press.heldStop(focus.id);
        const base = pressed !== null ? pressed : held ? local : reportedPosition(r, time);
        return { id: focus.id, base: base, at: now, slew: 0, running: false };
    }
    const position = reportedPosition(r, time);
    const error = held && held.running ? position - local : Infinity;
    if (Math.abs(error) > CONFIG.replayResyncS) {
        return { id: focus.id, base: position, at: now, slew: 0, running: true };
    }
    const slew = Math.max(-CONFIG.replayMaxSlew, Math.min(CONFIG.replayMaxSlew, error / CONFIG.replaySlewS));
    return { id: focus.id, base: local, at: now, slew: slew, running: true };
}
