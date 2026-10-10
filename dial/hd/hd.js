import {
    CONFIG,
    STATUS_RULES,
    REFUSALS,
    FALLBACK_REFUSAL,
    OFFLINE_REFUSAL,
    PIN_TEXT,
    PIN_LINE_RULES,
    PAIR_ELSEWHERE,
    PIN_KEY_OFF,
    PIN_KEY_OFF_DIGIT,
    EMPTY_STATE,
    LOGO_URL,
    ARTWORK_PREFIX,
    LOGO_BACKDROP_URL,
    ACTION_PREFIX,
    ENDPOINTS,
    INFO_URL,
    REPLAY_ROWS,
    REPLAY_BUTTONS,
    NO_TIME,
    POWER_CARDS,
    POWER_RULES,
    POWER_TAKEN_OVER,
    POWER_IDLE_UI,
    SLEEP_CHOICES,
    DIM_FLOOR,
    BRIGHTNESS_MAX,
    SEVERITY_ORDER,
    EQ_FILTERS,
    EQ_TWO_BAND,
    EQ_LABELS,
    EQ_GRAPH,
    formatLength,
    signed
} from "./hd-tables.js";
import { make, setText, makeIcon, setLevel, syncList, els } from "./hd-dom.js";

// ---- State, optimistic values ----------------------------------------

// What the page itself holds besides the dial's state.
const ui = {
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
const PIN_IDLE = { forKey: null, digits: "" };
const pending = {};         // control key -> { value, deadline }
const dragging = new Set();  // control keys under a finger

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

const press = {
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

function setPending(key, value) {
    pending[key] = { value: value, deadline: Date.now() + CONFIG.pendingMs };
    setTimeout(render, CONFIG.pendingMs + 30);
}

// The value to show for a control: the optimistic one until the state
// agrees with it or its time is up, then the state's.
function settle(key, actual) {
    const p = pending[key];
    if (!p) { return actual; }
    if (p.value === actual || Date.now() >= p.deadline) {
        delete pending[key];
        return actual;
    }
    return p.value;
}

function rollBack(keys) {
    (keys || []).forEach((key) => { delete pending[key]; });
    render();
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
function clockRate(clock, now) {
    return (now - clock.at) / 1000 < CONFIG.replaySlewS ? 1 + clock.slew : 1;
}

function clockPosition(clock, now) {
    if (!clock.running) { return clock.base; }
    const gone = (now - clock.at) / 1000;
    return clock.base + gone + clock.slew * Math.min(gone, CONFIG.replaySlewS);
}

function nextReplayClock(old, state, now) {
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

// ---- The equaliser's response maths ----------------------------------

// RBJ audio EQ cookbook biquad, normalised, as the appliance's monitor
// configures its filters.
function biquad(type, f0, q, gainDb, fs) {
    const A = Math.pow(10, gainDb / 40);
    const w0 = 2 * Math.PI * f0 / fs;
    const cos = Math.cos(w0);
    const alpha = Math.sin(w0) / (2 * q);
    const t = 2 * Math.sqrt(A) * alpha;
    let b0, b1, b2, a0, a1, a2;
    if (type === "peak") {
        b0 = 1 + alpha * A; b1 = -2 * cos; b2 = 1 - alpha * A;
        a0 = 1 + alpha / A; a1 = -2 * cos; a2 = 1 - alpha / A;
    } else if (type === "low_shelf") {
        b0 = A * ((A + 1) - (A - 1) * cos + t);
        b1 = 2 * A * ((A - 1) - (A + 1) * cos);
        b2 = A * ((A + 1) - (A - 1) * cos - t);
        a0 = (A + 1) + (A - 1) * cos + t;
        a1 = -2 * ((A - 1) + (A + 1) * cos);
        a2 = (A + 1) + (A - 1) * cos - t;
    } else if (type === "high_shelf") {
        b0 = A * ((A + 1) + (A - 1) * cos + t);
        b1 = -2 * A * ((A - 1) + (A + 1) * cos);
        b2 = A * ((A + 1) + (A - 1) * cos - t);
        a0 = (A + 1) - (A - 1) * cos + t;
        a1 = 2 * ((A - 1) - (A + 1) * cos);
        a2 = (A + 1) - (A - 1) * cos - t;
    } else {
        return { b0: 1, b1: 0, b2: 0, a1: 0, a2: 0 };
    }
    return { b0: b0 / a0, b1: b1 / a0, b2: b2 / a0, a1: a1 / a0, a2: a2 / a0 };
}

function magnitudeDb(c, f, fs) {
    const w = 2 * Math.PI * f / fs;
    const nr = c.b0 + c.b1 * Math.cos(w) + c.b2 * Math.cos(2 * w);
    const ni = -(c.b1 * Math.sin(w) + c.b2 * Math.sin(2 * w));
    const dr = 1 + c.a1 * Math.cos(w) + c.a2 * Math.cos(2 * w);
    const di = -(c.a1 * Math.sin(w) + c.a2 * Math.sin(2 * w));
    return 10 * Math.log10((nr * nr + ni * ni) / Math.max(dr * dr + di * di, 1e-30));
}

// The filters a set of sliders adds up to: [{ type, hz, q, gain }].
function responseFilters(bands) {
    const out = [];
    const add = (id, hz, gain) => {
        const shape = EQ_FILTERS[id];
        if (shape) { out.push({ type: shape.type, hz: hz || shape.hz, q: shape.q, gain: gain }); }
    };
    bands.forEach((band) => {
        const parts = EQ_TWO_BAND[band.id];
        if (parts) {
            parts.forEach(([id, share]) => add(id, 0, band.gain * share));
        } else {
            add(band.id, band.hz, band.gain);
        }
    });
    return out;
}

function eqLabel(band) {
    if (EQ_LABELS[band.id]) { return EQ_LABELS[band.id]; }
    if (!band.frequency_hz) { return band.id; }
    return band.frequency_hz >= 1000 ? band.frequency_hz / 1000 + "kHz" : band.frequency_hz + "Hz";
}

// ---- The view model: everything the DOM shows, from the state ---------

function applianceStatus(a) {
    const rule = STATUS_RULES.find((r) => r[0](a));
    return { label: rule[1], bad: rule[2] };
}

function replayBadge(a) {
    const r = a.repeat;
    if (!r || r.state !== "hold") { return ""; }
    return "Replay " + formatLength(r.duration_s || r.recording_s);
}

function nowPlayingText(s, focus) {
    const np = s.now_playing;
    if (!s.started) { return { title: "Starting...", sub: "" }; }
    const head = np ? np.title || np.title_fallback : "";
    if (head || (np && np.artist)) {
        const rest = head ? [np.artist, np.album] : [np.album];
        return { title: head || np.artist, sub: rest.filter(Boolean).join(" · ") };
    }
    return { title: "Nothing playing", sub: focus ? focus.name : "" };
}

function speakerNote(focus, outputs, rows) {
    if (!focus) { return ""; }
    if (outputs && outputs.appliance_id === focus.id && outputs.loaded) {
        return rows.length ? "" : "No speakers on this appliance.";
    }
    return focus.capabilities.outputs ? "Loading speakers..." : "This appliance has no speaker controls.";
}

// The appliance's warnings that have a card to show and are not snoozed.
function shownWarnings(a, cardsById) {
    return a.warnings.filter((w) => !w.snoozed && cardsById.has(w.key));
}

function warnBadge(a, cardsById) {
    const list = shownWarnings(a, cardsById);
    if (!list.length) { return null; }
    const worst = list.reduce((top, w) => (
        SEVERITY_ORDER.indexOf(w.severity) > SEVERITY_ORDER.indexOf(top) ? w.severity : top
    ), "info");
    return { count: list.length, severity: worst, key: list[0].key };
}

// What the timer reads for each kind of time in REPLAY_ROWS: [elapsed,
// total] in seconds, null for a time there is none of.
const REPLAY_TIMES = {
    none: () => [null, null],
    length: (r) => [0, r.duration_s || r.recording_s],
    position: (r, position) => [position, r.duration_s]
};

const timeText = (seconds) => (seconds === null ? NO_TIME : formatLength(seconds));

// A pressed transport button (see *press*) is held down from the press
// until the first of these lets it go. Each reads the state alone, so
// the button can never stay down: the request is the dial's own, and it
// always ends accepted or rejected, with the appliance's next report to
// follow. Each rule gets { press, focus, offline, r (the appliance's
// record, when it has a replay row), t (the dial's latest request of the
// press's kind), own (t is this press's request) }.
const PRESS_RELEASES = [
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

// The appliance's record and its replay row, or null when the focus has
// no replay row to show.
function replayOf(focus) {
    const r = focus && focus.capabilities.repeat ? focus.repeat : null;
    const row = r && r.available ? REPLAY_ROWS[r.state] : null;
    return row ? { r: r, row: row } : null;
}

// What PRESS_RELEASES reads, from the page's current state.
function pressContext() {
    const s = ui.state;
    const focus = s ? s.appliances.find((a) => a.id === s.focus.appliance_id) || null : null;
    const t = s && s.transport && s.transport.appliance_id === press.id
        && s.transport.kind === REPLAY_BUTTONS[press.target].kind ? s.transport : null;
    const replay = replayOf(focus);
    return { focus: focus, offline: ui.offline, r: replay ? replay.r : null, t: t };
}

// The replay row's controls for the focused appliance, from its record.
// The position counts whole seconds gone, so it is cut, not rounded,
// until the replay is at its end.
//
// A Stop that has been pressed holds the timer where it was and greys
// the controls until the appliance stops replaying, the request is
// refused or rejected, or another request takes its place; the timer
// then goes by the state again.
function deriveReplay(focus, usable, local) {
    const replay = replayOf(focus);
    if (!replay) { return { items: [], ticking: false, nextMs: 0 }; }
    const r = replay.r;
    const row = replay.row;
    const pressed = !!local.press;
    const stopping = pressed && local.press.target === "stop";
    const clock = local.replayClock && local.replayClock.id === focus.id ? local.replayClock : null;
    const length = r.duration_s > 0 ? r.duration_s : Infinity;
    const at = stopping ? local.press.base : clock ? clockPosition(clock, local.now) : r.position_s;
    const ended = at >= length;
    const position = ended ? length : Math.floor(at);
    const ticking = !!clock && clock.running && !ended && !stopping;
    const can = (id) => usable && !stopping && row.usable.indexOf(id) >= 0;
    const items = row.controls.map((id) => {
        if (id === "arm") { return { id: id, on: settle("arm", r.armed), enabled: can(id) }; }
        if (id === "counter") {
            const times = REPLAY_TIMES[row.time](r, position);
            return { id: id, text: timeText(times[0]) + " / " + timeText(times[1]), frozen: row.dim || stopping };
        }
        return { id: id, enabled: can(id), pushed: pressed && local.press.target === id };
    });
    return {
        items: items,
        ticking: ticking,
        // How long until the position reaches its next whole second.
        nextMs: ticking
            ? (Math.floor(at) + 1 - at) / clockRate(clock, local.now) * 1000 + CONFIG.replayTickLagMs : 0
    };
}

function deriveEq(s, focus, usable, local) {
    const block = s.eq;
    const ready = !!focus && !!block && block.appliance_id === focus.id && block.loaded;
    const bands = (ready ? block.bands : []).map((b) => ({
        id: b.id, frequency_hz: b.frequency_hz, hz: b.frequency_hz, label: eqLabel(b),
        min: b.min_db, max: b.max_db, gain: settle("eq:" + b.id, b.gain_db)
    }));
    const available = !!focus && focus.capabilities.eq > 0;
    return {
        available: available,
        open: available && local.eqOpen && focus.id === local.eqFor,
        name: focus ? focus.name : "",
        note: ready ? "" : "Loading equaliser...",
        bands: bands,
        filters: responseFilters(bands),
        enabled: usable && ready
    };
}

function cardFrom(card, owner) {
    return {
        key: card.id, source: card.source || "", title: card.title, message: card.message,
        severity: card.severity, progress: typeof card.progress === "number" ? card.progress : null,
        buttons: card.buttons.map((b, i) => ({ id: i + ":" + b.action, label: b.label, act: b.action })),
        closable: false, owner: owner, kind: "notice"
    };
}

// The dial's clock as this page estimates it: the reading the state came
// with plus the time on this page's clock since the state arrived. The
// page's own clock only ever measures that elapsed time.
function dialNow(s, local) {
    return s.now + (local.now - local.stateAt) / 1000;
}

// The keypad card (or, for an appliance that cannot take a PIN from a
// dial, the card saying where to enter it) while a speaker's PIN is
// wanted on the focused appliance and the person has not turned it away.
// A state without deadlines (an older dial) shows it while the dial says
// a PIN is awaited.
function derivePinCard(s, focus, local) {
    const r = s.outputs_request;
    if (!r || !focus || r.appliance_id !== focus.id || !r.awaiting_pin) { return null; }
    const timed = r.state === "rejected" && typeof r.awaiting_until === "number";
    if (timed && dialNow(s, local) >= r.awaiting_until) { return null; }
    if (local.pin.dismissedAt === r.requested_at) { return null; }
    // A dial that predates pin_accepted reports only versions; read them
    // until the state version next changes.
    const accepts = r.pin_accepted !== undefined ? r.pin_accepted : focus.capabilities.outputs >= 2;
    if (!accepts) {
        return {
            kind: "notice", key: "pair", source: focus.webui, title: PAIR_ELSEWHERE.title,
            message: PAIR_ELSEWHERE.message(focus.name), severity: "info", progress: null,
            closable: false, buttons: [{ id: "ok", label: "OK", act: "pin_cancel" }],
            requestedAt: r.requested_at, timed: timed
        };
    }
    const row = s.outputs && s.outputs.rows.find((x) => x.id === r.output_id);
    const name = row ? row.name : "this speaker";
    const key = r.requested_at + ":" + r.state + ":" + (r.error || "");
    const digits = local.pin.forKey === key ? local.pin.digits : "";
    const busy = r.state === "pending";
    const limited = r.state === "rejected" && r.error === "rate_limited";
    const waitLeft = limited && typeof r.retry_until === "number"
        ? Math.max(0, Math.ceil(r.retry_until - dialNow(s, local))) : 0;
    const line = PIN_LINE_RULES.find((rule) => rule[0](r, waitLeft));
    return {
        kind: "pin", key: "pin", source: "", severity: "info", progress: null, closable: false, timed: timed,
        title: "Enter PIN for " + name,
        message: busy ? PIN_TEXT.busy : PIN_TEXT.instruction(name),
        buttons: [{ id: "cancel", label: "Cancel", act: "pin_cancel" }],
        pin: {
            key: key, digits: digits, busy: busy, error: line[1](r, waitLeft), errorIsWait: line[2], waiting: waitLeft > 0,
            canSubmit: !busy && waitLeft === 0 && digits.length >= CONFIG.pinLength,
            requestedAt: r.requested_at, outputId: r.output_id
        }
    };
}

// The shut-down card to show, if any: its key in POWER_CARDS.
function derivePower(s, local) {
    const rule = POWER_RULES.find((r) => r[0](s.power, local.power));
    return rule ? rule[1] : null;
}

// The one modal card to show, if any: the shut-down card first (the person
// has just asked for it), then the PIN recovery confirmation,
// then a speaker's PIN, the not-authorised notice, an appliance warning
// opened from its badge, then the warning the dial says is due.
function deriveModal(s, focus, local) {
    const cardsById = new Map(s.warnings.cards.map((c) => [c.id, c]));
    const owners = new Map();
    s.appliances.forEach((a) => a.warnings.forEach((w) => owners.set(w.key, a.id)));
    const due = cardsById.get(s.warnings.due);

    const power = derivePower(s, local);
    if (power) {
        return Object.assign({ key: "power", source: "", severity: "warning", progress: null, kind: "notice" }, POWER_CARDS[power]);
    }
    if (s.recovery.active && !s.recovery.confirmed) {
        return {
            key: "presence", source: "", title: "Confirm you are at the dial",
            message: "The PIN is being recovered from the web UI. Confirm only if that is you.",
            severity: "warning", progress: null, closable: false,
            kind: "notice",
            buttons: [{ id: "presence", label: "Confirm", act: "presence" }]
        };
    }
    const pinCard = derivePinCard(s, focus, local);
    if (pinCard) { return pinCard; }
    const unauthorised = s.appliances.find((a) => a.id === local.notice && a.auth !== "authorized");
    if (unauthorised) {
        return {
            key: "notice", source: unauthorised.webui, title: "Not authorised",
            message: "Allow this dial in " + unauthorised.name + "'s web UI (Setup, Dials)",
            severity: "info", progress: null, closable: true,
            kind: "notice",
            buttons: [{ id: "ok", label: "OK", act: "close" }]
        };
    }
    // The due warning is shown when it belongs to the dial or to the
    // focused appliance; a card opened from a badge is the same card, and
    // then it is as much owed an answer.
    const owner = due ? owners.get(due.id) : null;
    const dueShown = !!due && !due.snoozed && (!owner || (!!focus && owner === focus.id));
    const viewed = cardsById.get(local.viewing);
    if (viewed && !viewed.snoozed) {
        const card = cardFrom(viewed, owners.get(viewed.id));
        card.closable = !(dueShown && due.id === viewed.id);
        return card;
    }
    return dueShown ? cardFrom(due, owner) : null;
}

// The dial's own screen is a loopback page, a laptop is not.
function isLoopbackHost(host) {
    return host === "127.0.0.1" || host === "localhost" || host === "[::1]";
}

function derive(s, local) {
    const offline = local.offline;
    const byId = new Map(s.appliances.map((a) => [a.id, a]));
    const cardsById = new Map(s.warnings.cards.map((c) => [c.id, c]));
    const focusId = s.focus.appliance_id;
    const focus = byId.get(focusId) || null;
    const shownFocus = settle("focus", focusId);
    const usable = !offline && !!focus && focus.auth === "authorized" && focus.reachable;

    const appliances = s.appliances.map((a) => {
        const status = applianceStatus(a);
        return {
            id: a.id, name: a.name, label: status.label, bad: status.bad,
            lit: !status.bad && (a.playing || a.replaying),
            badge: replayBadge(a), current: a.id === shownFocus,
            warn: warnBadge(a, cardsById)
        };
    });

    const outputs = s.outputs;
    const live = !!focus && !!outputs && outputs.appliance_id === focus.id && outputs.loaded;
    const speakers = (live ? outputs.rows : []).map((row) => {
        const on = settle("out:" + row.id + ":selected", !!row.selected);
        const chip = row.in_use
            ? { text: row.owner ? "In Use by " + row.owner : "In Use", tone: "in-use" }
            : { text: on ? "On" : "Off", tone: on ? "on" : "off" };
        return {
            id: row.id, name: row.name, on: on, chip: chip, inUse: !!row.in_use,
            isDefault: !!row.default,
            level: settle("out:" + row.id + ":volume", row.volume),
            enabled: usable && !row.in_use
        };
    });

    const volume = s.volume;
    const mine = !!focus && volume.appliance_id === focus.id;
    const known = mine && typeof volume.level === "number";
    const art = s.artwork && typeof s.artwork.url === "string" && s.artwork.url.indexOf(ARTWORK_PREFIX) === 0
        ? s.artwork.url : "";
    const backdrop = art && typeof s.artwork.backdrop_url === "string"
        && s.artwork.backdrop_url.indexOf(ARTWORK_PREFIX) === 0 ? s.artwork.backdrop_url : "";
    const text = nowPlayingText(s, focus);

    const panel = s.panel;
    const settings = {
        brightness: settle("brightness", panel.brightness),
        sleepAfter: settle("sleep_after_s", panel.sleep_after_s),
        // Any real backlight kind (sysfs or ddc) does the dimming itself.
        dim: panel.backlight === "none"
            ? DIM_FLOOR + (1 - DIM_FLOOR) * settle("brightness", panel.brightness) / BRIGHTNESS_MAX : null
    };

    const replay = deriveReplay(focus, usable, local);
    const eq = deriveEq(s, focus, usable, local);
    const modal = deriveModal(s, focus, local);

    return {
        offline: offline,
        asleep: !!panel.asleep,
        appliances: appliances,
        focusId: shownFocus,
        appliancesNote: s.started && !appliances.length ? "No appliances found." : "",
        speakersLabel: focus ? "Speakers on " + focus.name : "Speakers",
        speakers: speakers,
        speakersNote: speakerNote(focus, outputs, speakers),
        title: text.title, sub: text.sub, art: art, backdrop: backdrop,
        eqVisible: eq.available,
        volume: {
            enabled: usable && known,
            level: known ? settle("master", volume.level) : null,
            muted: mine && settle("mute", !!volume.muted)
        },
        replay: replay,
        eq: eq,
        settings: settings,
        hidePointer: !!panel.kiosk && isLoopbackHost(local.host),
        sheet: { open: local.sheetOpen, info: deriveInfo(local.info), canPower: !offline && !derivePower(s, local) },
        modal: modal,
        // Something on the page changes with the clock.
        live: replay.ticking || !!(modal && modal.timed)
    };
}

function deriveInfo(info) {
    const rows = info ? info.rows.map((row, i) => ({ id: i + ":" + row[0], label: row[0], value: row[1] })) : [];
    let note = "";
    if (!info) { note = "Loading..."; } else if (info.failed && !rows.length) { note = "Details are not available."; }
    return { rows: rows, note: note };
}

// ---- Painting -------------------------------------------------------

function createApplianceRow() {
    const node = make("button", "appliance");
    node.type = "button";
    const parts = {
        dot: node.appendChild(make("span", "dot")),
        name: node.appendChild(make("span", "name")),
        warn: node.appendChild(make("span", "warn-badge")),
        badge: node.appendChild(make("span", "badge")),
        state: node.appendChild(make("span", "state"))
    };
    parts.warn.setAttribute("role", "button");
    node.addEventListener("click", () => onAppliance(node.dataset.key));
    parts.warn.addEventListener("click", (event) => {
        event.stopPropagation();
        onWarnBadge(parts.warn.dataset.key);
    });
    node._update = (item) => {
        node.classList.toggle("lit", item.lit);
        node.classList.toggle("bad", item.bad);
        node.setAttribute("aria-current", item.current ? "true" : "false");
        setText(parts.name, item.name);
        setText(parts.badge, item.badge);
        setText(parts.state, item.label);
        parts.warn.hidden = !item.warn;
        if (item.warn) {
            parts.warn.dataset.key = item.warn.key;
            parts.warn.className = "warn-badge sev-" + item.warn.severity;
            parts.warn.setAttribute("aria-label", item.warn.count + " warning" + (item.warn.count > 1 ? "s" : ""));
            setText(parts.warn, String(item.warn.count));
        }
    };
    return node;
}

function createSpeakerCard() {
    const node = make("div", "output-card");
    const head = node.appendChild(make("div", "output-card-head"));
    const meta = head.appendChild(make("div", "output-card-meta"));
    const name = meta.appendChild(make("div", "output-card-name"));
    const badge = meta.appendChild(make("span", "output-card-default", "Default"));
    const chip = meta.appendChild(make("span", "output-state-chip"));
    const toggle = head.appendChild(make("label", "output-toggle"));
    const box = toggle.appendChild(make("input"));
    box.type = "checkbox";
    toggle.appendChild(make("span", "switch"));
    const levelRow = node.appendChild(make("div", "level-row"));
    const slider = levelRow.appendChild(make("input", "hslider"));
    slider.type = "range";
    slider.min = "0";
    slider.max = "100";
    const num = levelRow.appendChild(make("div", "level-num"));
    const key = () => "out:" + node.dataset.key + ":volume";

    box.addEventListener("change", () => onOutputToggle(node.dataset.key, box.checked));
    slider.addEventListener("input", () => onOutputLevel(node.dataset.key, Number(slider.value), false));
    slider.addEventListener("change", () => onOutputLevel(node.dataset.key, Number(slider.value), true));
    trackDrag(slider, key);

    node._update = (item) => {
        node.classList.toggle("output-card-on", item.on && !item.inUse);
        node.classList.toggle("output-card-off", !item.on || item.inUse);
        node.classList.toggle("output-card-in-use", item.inUse);
        setText(name, item.name);
        badge.hidden = !item.isDefault;
        setText(chip, item.chip.text);
        chip.className = "output-state-chip " + item.chip.tone;
        box.setAttribute("aria-label", item.name);
        box.disabled = !item.enabled;
        if (box.checked !== item.on) { box.checked = item.on; }
        levelRow.hidden = !item.on || item.inUse;
        slider.setAttribute("aria-label", item.name + " level");
        if (dragging.has(key())) {
            slider.disabled = !item.enabled;
        } else {
            setLevel(slider, item.level, item.enabled);
        }
        setText(num, String(item.level));
    };
    return node;
}

// Replay row controls, one builder per control id in REPLAY_ROWS.
function replayButton(id) {
    const node = make("button", "icon-btn replay-btn");
    node.type = "button";
    node.setAttribute("aria-label", REPLAY_BUTTONS[id].label);
    node.appendChild(makeIcon(REPLAY_BUTTONS[id].icon));
    node.addEventListener("click", () => onPress(id));
    node._update = (item) => {
        node.disabled = !item.enabled;
        node.setAttribute("aria-busy", item.pushed ? "true" : "false");
    };
    return node;
}

const REPLAY_BUILDERS = {
    arm: () => {
        const node = make("label", "output-toggle repeat-arm");
        node.appendChild(make("span", "repeat-arm-text", "Repeat Play"));
        const box = node.appendChild(make("input"));
        box.type = "checkbox";
        node.appendChild(make("span", "switch"));
        box.addEventListener("change", () => onArm(box.checked));
        node._update = (item) => {
            box.disabled = !item.enabled;
            if (box.checked !== item.on) { box.checked = item.on; }
        };
        return node;
    },
    counter: () => {
        const node = make("div", "replay-counter");
        node._update = (item) => {
            setText(node, item.text);
            node.classList.toggle("frozen", item.frozen);
        };
        return node;
    },
    play: () => replayButton("play"),
    restart: () => replayButton("restart"),
    stop: () => replayButton("stop")
};

function createReplayControl(item) {
    return REPLAY_BUILDERS[item.id]();
}

function createInfoRow() {
    const node = make("div", "info-row");
    const label = node.appendChild(make("dt"));
    const value = node.appendChild(make("dd"));
    node._update = (item) => {
        setText(label, item.label);
        setText(value, item.value);
    };
    return node;
}

function createSleepChoice(item) {
    const node = make("button", "");
    node.type = "button";
    node.addEventListener("click", () => onSleepAfter(item.seconds));
    node._update = (choice) => {
        setText(node, choice.label);
        node.setAttribute("aria-pressed", choice.on ? "true" : "false");
    };
    return node;
}

function createBand() {
    const node = make("div", "eq-band");
    const freq = node.appendChild(make("span", "eq-band-freq"));
    const slider = node.appendChild(make("div", "eq-band-box")).appendChild(make("input", "hd-band-slider"));
    slider.type = "range";
    slider.step = "1";
    const val = node.appendChild(make("span", "eq-band-val"));
    const key = () => "eq:" + node.dataset.key;
    slider.addEventListener("input", () => onEqGain(node.dataset.key, Number(slider.value), false));
    slider.addEventListener("change", () => onEqGain(node.dataset.key, Number(slider.value), true));
    trackDrag(slider, key);
    node._update = (item) => {
        setText(freq, item.label);
        slider.setAttribute("aria-label", item.label + " gain");
        slider.min = String(item.min);
        slider.max = String(item.max);
        slider.disabled = !item.enabled;
        if (!dragging.has(key()) && String(slider.value) !== String(item.gain)) { slider.value = item.gain; }
        const span = item.max - item.min || 1;
        const at = (v) => Math.max(0, Math.min(100, (v - item.min) / span * 100));
        slider.style.setProperty("--lo", Math.min(at(item.gain), at(0)) + "%");
        slider.style.setProperty("--hi", Math.max(at(item.gain), at(0)) + "%");
        setText(val, signed(item.gain) + " dB");
    };
    return node;
}

function createCardButton() {
    const node = make("button", "pill-btn card-btn");
    node.type = "button";
    node.addEventListener("click", () => {
        const modal = ui.vm && ui.vm.modal;
        const button = modal && modal.buttons.find((b) => b.id === node.dataset.key);
        if (button) { CARD_ACTIONS[button.act](modal); }
    });
    node._update = (item) => setText(node, item.label);
    return node;
}

function paintNote(node, text) {
    node.hidden = !text;
    setText(node, text);
}

function paintReplay(replay) {
    syncList(els.replay, replay.items, createReplayControl);
}

function paintSheet(vm) {
    const open = vm.sheet.open;
    els.sheet.classList.toggle("open", open);
    els.sheet.inert = !open;
    els.scrim.classList.toggle("show", open);
    els.handle.setAttribute("aria-expanded", open ? "true" : "false");

    const st = vm.settings;
    if (!dragging.has("brightness") && String(els.brightness.value) !== String(st.brightness)) {
        els.brightness.value = st.brightness;
    }
    const bright = els.brightness;
    bright.style.setProperty("--fill", (bright.value - bright.min) / (bright.max - bright.min) * 100 + "%");
    setText(els.brightnessNum, String(st.brightness));
    syncList(els.sleepAfter, SLEEP_CHOICES.map(([seconds, label]) => (
        { id: String(seconds), seconds: seconds, label: label, on: st.sleepAfter === seconds }
    )), createSleepChoice);
    els.power.disabled = !vm.sheet.canPower;
    syncList(els.info, vm.sheet.info.rows, createInfoRow);
    paintNote(els.infoNote, vm.sheet.info.note);
}

function paintEq(vm) {
    const eq = vm.eq;
    els.eqPage.classList.toggle("open", eq.open);
    els.eqPage.inert = !eq.open;
    setText(els.eqFor, eq.name);
    paintNote(els.eqNote, eq.note);
    els.eqReset.disabled = !eq.enabled;
    syncList(els.eqBands, eq.bands.map((b) => Object.assign({ enabled: eq.enabled }, b)), createBand);
    els.eqBands.classList.toggle("two", eq.bands.length === 2);
    if (!eq.open) {
        graph.key = "";
        return;
    }
    const key = JSON.stringify(eq.filters.map((f) => [f.type, f.hz, f.q, f.gain]))
        + ":" + els.eqGraph.clientWidth + "x" + els.eqGraph.clientHeight;
    if (key !== graph.key) {
        graph.key = key;
        scheduleGraph();
    }
}

function paintModal(card) {
    els.modal.hidden = !card;
    if (!card) { paintPin({ kind: "none" }); return; }
    els.card.className = "card sev-" + card.severity + " kind-" + card.kind;
    setText(els.cardTitle, card.title);
    setText(els.cardMessage, card.message);
    paintNote(els.cardSource, card.source);
    els.cardProgress.hidden = card.progress === null;
    els.cardBar.style.setProperty("--fill", (card.progress || 0) + "%");
    syncList(els.cardButtons, card.buttons, createCardButton);
    paintPin(card);
}

// The keypad: one box per digit (at least pinLength), the line under
// them, and each key's usable state.
function paintPin(card) {
    const isPin = card.kind === "pin";
    els.cardPinBoxes.hidden = !isPin;
    els.cardPinError.hidden = !isPin;
    els.cardPinPad.hidden = !isPin;
    if (!isPin) {
        // Nothing typed stays in the page once the keypad is not on show.
        Array.from(els.cardPinBoxes.children).forEach((box) => setText(box, ""));
        return;
    }
    const p = card.pin;
    const shown = Math.max(CONFIG.pinLength, Math.min(CONFIG.pinMax, p.digits.length));
    const open = !p.busy && !p.waiting && p.digits.length < shown;
    els.cardPinBoxes.classList.toggle("dense", shown > CONFIG.pinLength);
    els.cardPinBoxes.setAttribute("aria-label", p.digits.length < CONFIG.pinLength
        ? p.digits.length + " of " + CONFIG.pinLength + " digits entered"
        : p.digits.length + " digits entered");
    Array.from(els.cardPinBoxes.children).forEach((box, i) => {
        box.hidden = i >= shown;
        setText(box, p.digits.charAt(i));
        box.classList.toggle("next", open && i === p.digits.length);
    });
    setText(els.cardPinError, p.error);
    els.cardPinError.classList.toggle("wait", p.errorIsWait);
    Array.from(els.cardPinPad.children).forEach((key) => {
        const off = (PIN_KEY_OFF[key.dataset.key] || PIN_KEY_OFF_DIGIT)(p);
        key.disabled = off;
        if (key.dataset.key === "ok") { key.classList.toggle("off", off); }
    });
}

// The two scroll regions and the key each records its user scrolls under.
const LISTS = [["appliances", () => els.appliancesList], ["speakers", () => els.speakersList]];

// Mark a list with where it continues, from its own scroll metrics.
function markOverflow(list) {
    list.classList.toggle("more-above", list.scrollTop > 1);
    list.classList.toggle("more-below", list.scrollTop + list.clientHeight < list.scrollHeight - 1);
}

function markLists() { LISTS.forEach(([, get]) => markOverflow(get())); }

LISTS.forEach(([name, get]) => {
    get().addEventListener("scroll", () => {
        if (Date.now() >= ui.autoScrollUntil) { ui.listScrolledAt[name] = Date.now(); }
        markOverflow(get());
    }, { passive: true });
});
if (typeof ResizeObserver === "function") {
    const sizes = new ResizeObserver(markLists);
    LISTS.forEach(([, get]) => sizes.observe(get()));
}

// Bring the followed appliance's row into view when the focus moved on
// its own, unless the user has just been scrolling that list.
function followFocus(focusId) {
    if (focusId === ui.focusShown) { return; }
    ui.focusShown = focusId;
    if (!focusId || Date.now() - ui.listScrolledAt.appliances < CONFIG.userScrollHoldMs) { return; }
    const node = Array.from(els.appliances.children).find((n) => n.dataset.key === focusId);
    if (!node) { return; }
    ui.autoScrollUntil = Date.now() + CONFIG.autoScrollSettleMs;
    node.scrollIntoView({ block: "nearest" });
}

// The two pictures (artwork and its backdrop) change together: the ghosts
// take what is on screen, the fronts load the new sources hidden, and one
// class flip cross-fades them once both have loaded or fallen back.
const PICTURES = [
    { front: els.art, ghost: els.artPrev, fallback: LOGO_URL },
    { front: els.backdrop, ghost: els.backdropPrev, fallback: LOGO_BACKDROP_URL }
];
const pictureSwap = { generation: 0, pending: 0, timer: null, open: false, target: LOGO_URL + " " + LOGO_BACKDROP_URL };

function swapPictures(artUrl, backdropUrl, logo) {
    const target = artUrl + " " + backdropUrl;
    if (pictureSwap.target === target) { return; }
    pictureSwap.target = target;
    pictureSwap.generation += 1;
    clearTimeout(pictureSwap.timer);
    const urls = [artUrl, backdropUrl];
    // A change that arrives mid-load leaves the ghosts alone: they keep
    // the last picture that was shown.
    if (!pictureSwap.open) {
        PICTURES.forEach((p) => {
            p.ghost.setAttribute("src", p.front.getAttribute("src") || "");
            p.ghost.classList.toggle("logo", p.front.classList.contains("logo"));
            p.ghost.classList.add("showing");
            p.front.classList.add("loading");
        });
    }
    pictureSwap.open = true;
    pictureSwap.pending = PICTURES.length;
    PICTURES.forEach((p, i) => {
        if (i === 0) { p.front.classList.toggle("logo", logo); }
        p.front.setAttribute("src", urls[i]);
    });
    const generation = pictureSwap.generation;
    pictureSwap.timer = setTimeout(() => finishSwap(generation), CONFIG.pictureSettleMs);
}

function finishSwap(generation) {
    if (generation !== pictureSwap.generation || !pictureSwap.open) { return; }
    pictureSwap.open = false;
    pictureSwap.pending = 0;
    clearTimeout(pictureSwap.timer);
    void els.art.offsetWidth;   // commit the hidden state so the flip fades
    PICTURES.forEach((p) => {
        p.ghost.classList.remove("showing");
        p.front.classList.remove("loading");
    });
}

function pictureDone() {
    pictureSwap.pending = Math.max(0, pictureSwap.pending - 1);
    if (pictureSwap.pending === 0) { finishSwap(pictureSwap.generation); }
}

function paint(vm) {
    document.documentElement.classList.toggle("no-pointer", vm.hidePointer);
    els.app.classList.toggle("offline", vm.offline);
    els.app.classList.toggle("dimmed", vm.settings.dim !== null);
    if (vm.settings.dim !== null) { els.app.style.setProperty("--dim", String(vm.settings.dim)); }
    els.sleep.classList.toggle("on", vm.asleep);
    syncList(els.appliances, vm.appliances, createApplianceRow);
    paintNote(els.appliancesNote, vm.appliancesNote);
    setText(els.speakersLabel, vm.speakersLabel);
    syncList(els.speakers, vm.speakers, createSpeakerCard);
    paintNote(els.speakersNote, vm.speakersNote);
    followFocus(vm.focusId);
    markLists();

    setText(els.title, vm.title);
    setText(els.sub, vm.sub);
    swapPictures(vm.art || LOGO_URL, vm.backdrop || LOGO_BACKDROP_URL, !vm.art);
    els.eq.hidden = !vm.eqVisible;
    paintReplay(vm.replay);

    const v = vm.volume;
    els.volumeRow.classList.toggle("muted", v.muted);
    els.mute.setAttribute("aria-pressed", v.muted ? "true" : "false");
    els.mute.setAttribute("aria-label", v.muted ? "Unmute" : "Mute");
    els.mute.disabled = !v.enabled;
    if (dragging.has("master")) {
        els.master.disabled = !v.enabled;
    } else {
        setLevel(els.master, v.level === null ? 0 : v.level, v.enabled);
    }
    setText(els.masterNum, v.level === null ? "--" : String(v.level));

    paintSheet(vm);
    paintEq(vm);
    paintModal(vm.modal);
}

let replayTick = 0;

function render() {
    // A held button ends with its reason, before the page is drawn.
    press.observe(pressContext());
    const view = () => derive(ui.state || EMPTY_STATE, Object.assign({ now: Date.now(), press: press.current() }, ui));
    ui.vm = view();
    // The dial's state takes over from the shut-down request the page sent.
    if (ui.power.sent && ui.state && POWER_TAKEN_OVER(ui.state.power, ui.power)) {
        ui.power = Object.assign({}, ui.power, { sent: false });
        ui.vm = view();
    }
    // A page-only selection ends when nothing shows it any more.
    if (ui.eqOpen && !ui.vm.eq.open) { ui.eqOpen = false; }
    if (!ui.vm.modal) {
        ui.notice = null;
        ui.viewing = null;
    }
    // The digits go with the card; what was turned away stays turned away.
    const pinNow = !!ui.vm.modal && ui.vm.modal.kind === "pin";
    if (!pinNow && (ui.pin.digits || ui.pin.forKey)) {
        ui.pin = Object.assign({}, ui.pin, PIN_IDLE);
    }
    const request = ui.state && ui.state.outputs_request;
    if (ui.pinShown && !pinNow && request && request.state === "accepted") { toast(PIN_TEXT.paired); }
    ui.pinShown = pinNow;
    paint(ui.vm);
    // A running replay is drawn again as its position reaches each
    // whole second, so the timer steps evenly whenever states arrive.
    clearTimeout(replayTick);
    replayTick = ui.vm.replay.ticking ? setTimeout(render, ui.vm.replay.nextMs) : 0;
}

// ---- The equaliser's response graph ------------------------------------

const graph = { key: "", frame: 0 };

function scheduleGraph() {
    if (graph.frame) { return; }
    graph.frame = requestAnimationFrame(() => {
        graph.frame = 0;
        drawGraph();
    });
}

function drawGraph() {
    const canvas = els.eqGraph;
    const w = canvas.clientWidth;
    const h = canvas.clientHeight;
    if (!w || !h || !ui.vm) { return; }
    const G = EQ_GRAPH;
    const dpr = Math.min(window.devicePixelRatio || 1, G.maxDpr);
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    const g = canvas.getContext("2d");
    g.scale(dpr, dpr);
    const css = getComputedStyle(els.app);
    const color = (name) => css.getPropertyValue(name).trim();
    const pw = w - G.padLeft - G.padRight;
    const ph = h - G.padTop - G.padBottom;
    const fx = (f) => G.padLeft + pw * Math.log(f / G.fMin) / Math.log(G.fMax / G.fMin);
    const dy = (db) => G.padTop + ph * (G.range - Math.max(-G.range, Math.min(G.range, db))) / (2 * G.range);

    g.fillStyle = color("--color-eq-bg");
    g.fillRect(0, 0, w, h);
    g.font = "11px " + css.fontFamily;
    g.lineWidth = 1;
    G.gridDb.forEach((db) => {
        g.strokeStyle = color(db === 0 ? "--color-eq-grid-zero" : "--color-eq-grid");
        g.beginPath();
        g.moveTo(G.padLeft, dy(db));
        g.lineTo(w - G.padRight, dy(db));
        g.stroke();
        g.fillStyle = color("--color-text-dim");
        g.textAlign = "right";
        g.fillText(signed(db), G.padLeft - 6, dy(db) + 4);
    });
    let labelled = -Infinity;
    G.gridHz.forEach(([f, text]) => {
        g.strokeStyle = color("--color-eq-grid");
        g.beginPath();
        g.moveTo(fx(f), G.padTop);
        g.lineTo(fx(f), G.padTop + ph);
        g.stroke();
        // A label that would run into the one before it is left off.
        if (fx(f) - labelled < G.labelGap) { return; }
        labelled = fx(f);
        g.fillStyle = color("--color-text-dim");
        g.textAlign = f === G.fMin ? "left" : f === G.fMax ? "right" : "center";
        g.fillText(text, fx(f), h - 6);
    });

    const coeffs = ui.vm.eq.filters.map((f) => biquad(f.type, f.hz, f.q, f.gain, G.fs));
    const total = (f) => coeffs.reduce((sum, c) => sum + magnitudeDb(c, f, G.fs), 0);
    const points = [];
    for (let i = 0; i <= G.points; i++) {
        const f = G.fMin * Math.pow(G.fMax / G.fMin, i / G.points);
        points.push([fx(f), dy(total(f))]);
    }
    const accent = color("--color-accent");
    const fill = g.createLinearGradient(0, G.padTop, 0, G.padTop + ph);
    fill.addColorStop(0, "rgba(82,152,216,0.30)");
    fill.addColorStop(1, "rgba(82,152,216,0.02)");
    g.beginPath();
    g.moveTo(points[0][0], dy(0));
    points.forEach(([x, y]) => g.lineTo(x, y));
    g.lineTo(points[points.length - 1][0], dy(0));
    g.closePath();
    g.fillStyle = fill;
    g.fill();
    g.beginPath();
    points.forEach(([x, y], i) => (i ? g.lineTo(x, y) : g.moveTo(x, y)));
    g.strokeStyle = accent;
    g.lineWidth = 2.4;
    g.stroke();
    ui.vm.eq.bands.forEach((band) => {
        const f = band.hz || (EQ_TWO_BAND[band.id] ? EQ_FILTERS[EQ_TWO_BAND[band.id][0][0]].hz : 0);
        if (!f) { return; }
        g.beginPath();
        g.arc(fx(f), dy(total(f)), 4.5, 0, Math.PI * 2);
        g.fillStyle = "#fff";
        g.fill();
    });
}

if (typeof ResizeObserver === "function") {
    new ResizeObserver(() => {
        graph.key = "";
        if (ui.vm && ui.vm.eq.open) { scheduleGraph(); }
    }).observe(els.eqGraph);
}

// ---- Requests -------------------------------------------------------

let toastTimer = 0;

function toast(text, ms) {
    setText(els.toast, text);
    els.toast.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => els.toast.classList.remove("show"), ms || CONFIG.toastMs);
}

function get(path) {
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), CONFIG.requestTimeoutMs);
    return fetch(path, { credentials: "same-origin", cache: "no-store", signal: abort.signal })
        .then((response) => (response.ok ? response.text() : Promise.reject(new Error("http_" + response.status))))
        .finally(() => clearTimeout(timer));
}

// Every request that changes something goes through here. A refusal or a
// failure shows briefly (unless *quiet*) and puts the controls named in
// *keys* back to what the state says. The promise gives the reply (an
// object, so truthy) when it went through and false when it did not.
function post(action, body, keys, quiet) {
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), CONFIG.requestTimeoutMs);
    return fetch(ENDPOINTS[action] || ACTION_PREFIX + action, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Requested-With": "autostream-hd" },
        credentials: "same-origin",
        body: JSON.stringify(body),
        signal: abort.signal
    }).then((response) => response.json().catch(() => ({})).then((reply) => {
        if (!response.ok || reply.ok === false) {
            const reason = reply.error || "http_" + response.status;
            console.warn("action " + action + " refused: " + reason);
            if (!quiet) { toast(REFUSALS[reason] || FALLBACK_REFUSAL); }
            rollBack(keys);
            return false;
        }
        return reply;
    })).catch((error) => {
        console.warn("action " + action + " failed: " + error);
        if (!quiet) { toast(OFFLINE_REFUSAL); }
        rollBack(keys);
        return false;
    }).finally(() => clearTimeout(timer));
}

// While a slider is dragged: the first change goes out at once, later ones
// at most once per gap (the newest wins), and the final one always goes.
const lanes = {};

function sendDrag(key, action, body, final, keys) {
    const lane = lanes[key] || (lanes[key] = { timer: 0, queued: null, last: "" });
    const text = JSON.stringify(body);
    if (final) {
        clearTimeout(lane.timer);
        lane.timer = 0;
        lane.queued = null;
        if (text !== lane.last) { lane.last = text; post(action, body, keys); }
        return;
    }
    if (lane.timer) {
        lane.queued = [action, body, keys];
        return;
    }
    lane.last = text;
    post(action, body, keys);
    lane.timer = setTimeout(() => {
        const queued = lane.queued;
        lane.timer = 0;
        lane.queued = null;
        if (queued) { sendDrag(key, queued[0], queued[1], false, queued[2]); }
    }, CONFIG.sendGapMs);
}

// A slider under a finger: the state leaves it alone, and a new drag to
// the value the last one ended on is still sent.
function trackDrag(slider, key) {
    slider.addEventListener("pointerdown", (event) => {
        dragging.add(key());
        delete lanes[key()];
        followPointer(event, null, () => dragging.delete(key()));
    });
}

// Follows the pointer that began a drag from the document, so the drag
// survives the finger leaving the element it started on. Only that pointer
// counts (a second finger can neither steer nor end it), and a cancel ends
// it like a lift. move may be null; end gets the event that ended it.
function followPointer(start, move, end) {
    const id = start.pointerId;
    const onMove = (event) => {
        if (event.pointerId === id && move) { move(event); }
    };
    const onEnd = (event) => {
        if (event.pointerId !== id) { return; }
        document.removeEventListener("pointermove", onMove);
        document.removeEventListener("pointerup", onEnd);
        document.removeEventListener("pointercancel", onEnd);
        end(event);
    };
    document.addEventListener("pointermove", onMove);
    document.addEventListener("pointerup", onEnd);
    document.addEventListener("pointercancel", onEnd);
}

// ---- Actions from the page ------------------------------------------

const focusId = () => (ui.state ? ui.state.focus.appliance_id : null);
const canAct = () => !!ui.state && !ui.offline;

function onAppliance(id) {
    if (!canAct()) { return; }
    const a = ui.state.appliances.find((item) => item.id === id);
    if (!a) { return; }
    if (a.auth !== "authorized") {
        ui.notice = id;
        render();
        return;
    }
    if (id === focusId() && !pending.focus) { return; }
    setPending("focus", id);
    render();
    post("focus", { appliance_id: id }, ["focus"]);
}

function onWarnBadge(key) {
    ui.viewing = key;
    render();
}

function onOutputToggle(id, selected) {
    const key = "out:" + id + ":selected";
    setPending(key, selected);
    render();
    post("output", { appliance_id: focusId(), output_id: id, selected: selected }, [key]);
}

function onOutputLevel(id, level, final) {
    const key = "out:" + id + ":volume";
    setPending(key, level);
    render();
    sendDrag(key, "output", { appliance_id: focusId(), output_id: id, volume: level }, final, [key]);
}

function onMasterLevel(level, final) {
    setPending("master", level);
    render();
    sendDrag("master", "volume_set", { appliance_id: focusId(), level: level }, final, ["master"]);
}

function onMute() {
    if (!ui.vm || !ui.vm.volume.enabled) { return; }
    setPending("mute", !ui.vm.volume.muted);
    render();
    post("mute_toggle", { appliance_id: focusId() }, ["mute"]);
}

function onArm(armed) {
    setPending("arm", armed);
    render();
    post("repeat_arm", { appliance_id: focusId(), armed: armed }, ["arm"]);
}

// The transport buttons are held down from the press (see
// PRESS_RELEASES) and let go at once if the request does not go through.
function onPress(id) {
    const appliance = ui.state && ui.state.appliances.find((item) => item.id === focusId());
    if (!appliance || !appliance.repeat || !canAct()) { return; }
    const clock = ui.replayClock && ui.replayClock.id === appliance.id ? ui.replayClock : null;
    const position = clock ? clockPosition(clock, Date.now()) : appliance.repeat.position_s;
    const serial = press.start(id, appliance, position, ui.state.transport ? ui.state.transport.requested_at : null);
    if (!serial) { return; }
    render();
    post(REPLAY_BUTTONS[id].action, { appliance_id: appliance.id }).then((reply) => {
        press.sent(serial, reply);
        // A token alone is not news to draw: the state has yet to show
        // the request it names.
        if (!press.current()) { render(); }
    });
}

function onEqGain(id, gain, final) {
    const key = "eq:" + id;
    setPending(key, gain);
    render();
    sendDrag(key, "eq", { appliance_id: focusId(), gains: { [id]: gain } }, final, [key]);
}

function onEqReset() {
    if (!ui.vm) { return; }
    const keys = ui.vm.eq.bands.map((b) => "eq:" + b.id);
    keys.forEach((key) => {
        setPending(key, 0);
        delete lanes[key];
    });
    render();
    post("eq_reset", { appliance_id: focusId() }, keys);
}

function setEqOpen(open) {
    ui.eqOpen = open;
    ui.eqFor = open ? focusId() : null;
    render();
}

function onBrightness(value, final) {
    setPending("brightness", value);
    render();
    sendDrag("brightness", "settings", { brightness: value }, final, ["brightness"]);
}

function onSleepAfter(seconds) {
    setPending("sleep_after_s", seconds);
    render();
    post("settings", { sleep_after_s: seconds }, ["sleep_after_s"]);
}

function setSheet(open) {
    ui.sheetOpen = open;
    if (open) { loadInfo(); }
    render();
}

function loadInfo() {
    const fresh = ui.info && !ui.info.failed && Date.now() - ui.info.at < CONFIG.infoMaxAgeMs;
    if (ui.infoBusy || fresh) { return; }
    ui.infoBusy = true;
    get(INFO_URL)
        .then((text) => JSON.parse(text).rows)
        .then((rows) => {
            ui.info = { rows: rows.filter((r) => Array.isArray(r) && r.length === 2), at: Date.now(), failed: false };
        })
        .catch(() => {
            ui.info = { rows: ui.info ? ui.info.rows : [], at: Date.now(), failed: true };
        })
        .finally(() => {
            ui.infoBusy = false;
            render();
        });
}

// What each button on a modal card does.
const CARD_ACTIONS = {
    dismiss: (card) => {
        ui.viewing = null;
        post("warning_dismiss", { warning_id: card.key });
        render();
    },
    restart: () => post("dial_restart", {}),
    shutdown: () => {
        ui.power = Object.assign({}, ui.power, { asked: false, sent: true });
        setSheet(false);
        post("dial_shutdown", {}).then((went) => {
            if (!went) {
                ui.power = Object.assign({}, ui.power, { sent: false });
                render();
            }
        });
    },
    power_ack: () => {
        ui.power = Object.assign({}, ui.power, { dismissedAt: ui.state.power.changed_at });
        render();
    },
    presence: () => post("presence", {}),
    close: () => {
        ui.notice = null;
        ui.viewing = null;
        ui.power = Object.assign({}, ui.power, { asked: false });
        render();
    },
    pin_cancel: (card) => {
        const at = card.kind === "pin" ? card.pin.requestedAt : card.requestedAt;
        ui.pin = Object.assign({}, ui.pin, PIN_IDLE, { dismissedAt: at });
        render();
    }
};

els.master.addEventListener("input", () => onMasterLevel(Number(els.master.value), false));
els.master.addEventListener("change", () => onMasterLevel(Number(els.master.value), true));
trackDrag(els.master, () => "master");
els.mute.addEventListener("click", onMute);
// A picture that fails falls back to the logo once; a failing fallback
// counts as loaded, so a swap always ends.
PICTURES.forEach((p, i) => {
    p.front.addEventListener("load", pictureDone);
    p.front.addEventListener("error", () => {
        if (p.front.getAttribute("src") !== p.fallback) {
            if (i === 0) { p.front.classList.add("logo"); }
            p.front.setAttribute("src", p.fallback);
            return;
        }
        pictureDone();
    });
});

els.eq.addEventListener("click", () => setEqOpen(true));
els.eqClose.addEventListener("click", () => setEqOpen(false));
els.eqReset.addEventListener("click", onEqReset);

els.brightness.addEventListener("input", () => onBrightness(Number(els.brightness.value), false));
els.brightness.addEventListener("change", () => onBrightness(Number(els.brightness.value), true));
trackDrag(els.brightness, () => "brightness");
els.power.addEventListener("click", () => {
    ui.power = Object.assign({}, ui.power, { asked: true });
    render();
});
els.sleepNow.addEventListener("click", () => {
    setSheet(false);
    post("panel_sleep", {});
});
els.scrim.addEventListener("click", () => setSheet(false));
els.modal.addEventListener("click", (event) => {
    if (event.target === els.modal && ui.vm && ui.vm.modal && ui.vm.modal.closable) { CARD_ACTIONS.close(); }
});

// The keypad edits the buffer; OK sends it once and empties it.
const PIN_EDITS = {
    del: (digits) => digits.slice(0, -1)
};

function onPinKey(key) {
    const card = ui.vm && ui.vm.modal;
    if (!card || card.kind !== "pin" || card.pin.busy || card.pin.waiting) { return; }
    const p = card.pin;
    let digits = p.digits;
    if (key === "ok") {
        if (!p.canSubmit) { return; }
        post("output", { appliance_id: focusId(), output_id: p.outputId, selected: true, pin: digits });
        digits = "";
    } else if (PIN_EDITS[key]) {
        digits = PIN_EDITS[key](digits);
    } else if (/^[0-9]$/.test(key) && digits.length < CONFIG.pinMax) {
        digits += key;
    }
    ui.pin = Object.assign({}, ui.pin, { forKey: p.key, digits: digits });
    render();
}

els.cardPinPad.addEventListener("click", (event) => {
    const key = event.target.closest("button[data-key]");
    if (key && !key.disabled) { onPinKey(key.dataset.key); }
});

// The pull-down: a tap on the handle toggles it, a drag follows the finger
// and settles open or shut. Dragging the open sheet's own background
// (not a control) up closes it.
function bindSheetDrag(target, startOpen) {
    target.addEventListener("pointerdown", (event) => {
        if (ui.sheetOpen !== startOpen) { return; }
        if (startOpen && event.target.closest("input, button, label")) { return; }
        const height = els.sheet.offsetHeight;
        const y0 = event.clientY;
        let dy = 0;
        let moved = false;
        els.sheet.classList.add("dragging");
        const move = (e) => {
            dy = e.clientY - y0;
            if (Math.abs(dy) > CONFIG.tapMovePx) { moved = true; }
            const offset = startOpen ? Math.min(0, dy) : Math.max(-height, Math.min(0, dy - height));
            els.sheet.style.transform = "translateY(" + offset + "px)";
        };
        followPointer(event, move, () => {
            els.sheet.classList.remove("dragging");
            els.sheet.style.transform = "";
            if (!moved) {
                setSheet(!startOpen);
            } else {
                const keep = height / CONFIG.dragCloseFraction;
                setSheet(startOpen ? dy > -keep : dy > keep);
            }
        });
    });
}
bindSheetDrag(els.handle, false);
bindSheetDrag(els.sheet, true);
// A keyboard press on the handle is a click with no pointer.
els.handle.addEventListener("click", (event) => {
    if (event.detail === 0) { setSheet(!ui.sheetOpen); }
});

// A touch while the panel sleeps only wakes it. The panel can be awake
// again before the finger lifts, and the click that ends the touch is
// aimed at whatever is then under it, so the shield goes on taking
// touches until that click has landed on it (or, for a touch that ends
// without one, a moment after the finger lifts).
const releaseShield = () => els.sleep.classList.remove("held");
els.sleep.addEventListener("pointerdown", (event) => {
    event.preventDefault();
    event.stopPropagation();
    els.sleep.classList.add("held");
    followPointer(event, null, () => setTimeout(releaseShield, CONFIG.wakeGuardMs));
    post("panel_wake", {});
});
els.sleep.addEventListener("click", releaseShield);

// Every other touch counts as activity for the panel's idle clock
// (reported at most once in a while).
document.addEventListener("pointerdown", () => {
    if (ui.vm && ui.vm.asleep) { return; }
    const now = Date.now();
    if (now - ui.activityAt >= CONFIG.activityGapMs) {
        ui.activityAt = now;
        post("panel_activity", {}, [], true);
    }
}, true);

// ---- The event stream -----------------------------------------------

let source = null;
let lastHeard = Date.now();
let retryAt = 0;
let lastPoll = 0;
let checking = false;

function setOffline(value) {
    if (ui.offline === value) { return; }
    ui.offline = value;
    render();
}

function heard() {
    lastHeard = Date.now();
    setOffline(false);
}

function accept(text) {
    try {
        ui.state = JSON.parse(text);
    } catch (e) {
        return;
    }
    ui.stateAt = Date.now();
    ui.replayClock = nextReplayClock(ui.replayClock, ui.state, ui.stateAt);
    render();
}

function connect() {
    source = new EventSource("/api/v1/events");
    source.onopen = heard;
    source.addEventListener("state", (event) => {
        heard();
        accept(event.data);
    });
    source.onerror = () => {
        // The browser reconnects by itself (sending Last-Event-ID) unless it
        // gave up, as it does on a refusal; then try again after a pause.
        if (source.readyState === EventSource.CLOSED) { retryAt = Date.now() + CONFIG.streamRetryMs; }
    };
}

// Fetch the state directly: to recover faster than the browser's own
// schedule, and to check a stream that has been quiet for a long time.
function check() {
    if (checking) { return; }
    checking = true;
    lastPoll = Date.now();
    get("/api/v1/state")
        .then((text) => {
            const wasOffline = ui.offline;
            heard();
            if (wasOffline || !ui.state) { accept(text); }
        })
        .catch(() => setOffline(true))
        .finally(() => { checking = false; });
}

function tick() {
    const now = Date.now();
    if (source.readyState === EventSource.CLOSED && now >= retryAt) { connect(); }
    const quiet = now - lastHeard;
    if (ui.offline) {
        if (now - lastPoll >= CONFIG.pollMs) { check(); }
    } else if (source.readyState !== EventSource.OPEN && quiet > CONFIG.offlineAfterMs) {
        setOffline(true);
    } else if (quiet > CONFIG.quietCheckMs) {
        check();
    }
    if (ui.vm && ui.vm.live) { render(); }
}

// Leaving the page (a kiosk reload) closes the stream now, so the server
// is not left holding a client slot until its next write.
// Exposed so the host rule can be checked on its own.
window.hdIsLoopbackHost = isLoopbackHost;

window.addEventListener("pagehide", () => {
    if (source) { source.close(); }
});

setText(els.offline, "Reconnecting...");
render();
connect();
setInterval(tick, CONFIG.tickMs);
