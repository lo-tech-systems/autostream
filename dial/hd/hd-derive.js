// hd-derive.js: the HD page's view model: everything the DOM shows, worked out
// from the dial's state and the page's own facts (the optimistic values, the
// press, the open sheet, the PIN being typed). It builds the model and
// paints nothing; its one outside read is settle, for the optimistic values.

import {
    CONFIG,
    STATUS_RULES,
    PIN_TEXT,
    PIN_LINE_RULES,
    PAIR_ELSEWHERE,
    ARTWORK_PREFIX,
    REPLAY_ROWS,
    NO_TIME,
    POWER_CARDS,
    POWER_RULES,
    DIM_FLOOR,
    BRIGHTNESS_MAX,
    SEVERITY_ORDER,
    formatLength
} from "./hd-tables.js";
import { responseFilters, eqLabel } from "./hd-eq.js";
import { settle, clockRate, clockPosition } from "./hd-state.js";

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

// The appliance's record and its replay row, or null when the focus has
// no replay row to show.
export function replayOf(focus) {
    const r = focus && focus.capabilities.repeat ? focus.repeat : null;
    const row = r && r.available ? REPLAY_ROWS[r.state] : null;
    return row ? { r: r, row: row } : null;
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
export function isLoopbackHost(host) {
    return host === "127.0.0.1" || host === "localhost" || host === "[::1]";
}

export function derive(s, local) {
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
