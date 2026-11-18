// hd-derive.js: the HD page's view model: everything the DOM shows, from the
// state's two parts (the dial's own, and the focused appliance's as it reported
// them) and the page's own facts. It paints nothing; its one outside read is
// the held optimistic values.

import {
    CONFIG, STATUS_RULES, PIN_TEXT, PIN_LINE_RULES, ARTWORK_PREFIX, REPLAY_ROWS, NO_TIME, POWER_CARDS,
    POWER_RULES, AUTO_START_CARD, DIM_FLOOR, BRIGHTNESS_MAX, SEVERITY_ORDER, EQ_FILTERS, EQ_GRAPH, formatLength
} from "./hd-tables.js";
import { responseFilters, eqLabel } from "./hd-eq.js";
import { pending, clockRate, clockPosition, reportedPosition } from "./hd-state.js";
import { speakerRows, masterVolume, nowPlaying, playing, activeInput } from "/static/shared/state_view.js";
import { CHIP, INPUT_TYPE_LABELS, START_FAILURE, AUTO_START_PILL, AUTO_START_CONFIRM } from "/static/shared/texts.js";

const held = (key, live) => pending.value(key, live);

function applianceStatus(a) {
    const rule = STATUS_RULES.find((r) => r[0](a));
    return { label: rule[1], bad: rule[2] };
}

const replayBadge = (a) => (
    a.repeat && a.repeat.state === "hold" ? "Replay " + formatLength(a.repeat.duration_s || a.repeat.recording_s) : "");

function nowPlayingText(dial, p, focus) {
    if (!dial.started) { return { title: "Starting...", sub: "" }; }
    if (!p || !playing(p)) { return { title: "Nothing playing", sub: focus ? focus.name : "" }; }
    const np = nowPlaying(p, {});
    const n = activeInput(p);
    const t = ((p.track && p.track.entries) || {})[String(n === null ? 1 : n)] || {};
    const e = ((p.inputs && p.inputs.entries) || []).find((x) => x.index === n);
    if (!t.enabled) { return { title: n === null ? "Playing" : INPUT_TYPE_LABELS[e && e.input_type] || "Line", sub: "" }; }
    return { title: np.title, sub: t.state === "identified" ? [t.artist, t.album].filter(Boolean).join(" \u00b7 ") : np.subtitle };
}

// The speaker rows as the browser draws them. A PIN being entered for a
// speaker elsewhere leaves its switch alone here.
function deriveSpeakers(dial, p, usable) {
    const own = "dial:" + dial.dial.uuid;
    return (p ? speakerRows(p, { includeOffline: true }) : []).map((row) => {
        const on = held("out:" + row.id + ":selected", row.on);
        const inUse = row.chip === "in-use";
        const elsewhere = !!row.pinClaim && row.pinClaim !== own;
        const connecting = row.connecting && on;
        const tone = inUse ? "in-use" : connecting ? "connecting" : row.offline ? "offline" : on ? "on" : "off";
        return {
            id: row.id, on: on, inUse: inUse, autoStart: row.autoStart, pill: AUTO_START_PILL,
            name: row.name + (connecting ? CHIP.connecting : row.offline ? CHIP.offline : ""),
            chip: { text: inUse ? CHIP.inUse(row.inUseBy) : on ? CHIP.on : CHIP.off, tone: tone },
            level: held("out:" + row.id + ":volume", row.volume),
            enabled: usable && !row.disabled && !elsewhere
        };
    });
}

function speakerNote(focus, focused, rows) {
    if (!focus || rows.length) { return ""; }
    return focused && focused.reachable ? "No speakers on this appliance." : "Loading speakers...";
}

// The badge for the appliance's warnings that have a card and are not snoozed.
function warnBadge(a, cardsById) {
    const list = a.warnings.filter((w) => !w.snoozed && cardsById.has(w.key));
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

// The core's clock as this page estimates it: the reading the state came
// with plus the time on this page's clock since the state arrived.
const dialNow = (local) => local.time + (local.now - local.stateAt) / 1000;

// The appliance's record and its replay row, or null when the focus has
// no replay row to show.
export function replayOf(focus) {
    const r = focus ? focus.repeat : null;
    const row = r && r.available ? REPLAY_ROWS[r.state] : null;
    return row ? { r: r, row: row } : null;
}

// The replay row's controls for the focused appliance, from its record. The
// position counts whole seconds gone (cut, not rounded) until the end. A
// pressed Stop holds the timer and greys the controls until the press is let
// go; the timer then goes by the state again.
function deriveReplay(focus, usable, local) {
    const replay = replayOf(focus);
    if (!replay) { return { items: [], ticking: false, nextMs: 0 }; }
    const r = replay.r;
    const row = replay.row;
    const pressed = !!local.press;
    const stopping = pressed && local.press.target === "stop";
    const clock = local.replayClock && local.replayClock.id === focus.id ? local.replayClock : null;
    const length = r.duration_s > 0 ? r.duration_s : Infinity;
    const at = stopping ? local.press.base : clock ? clockPosition(clock, local.now) : reportedPosition(r, dialNow(local));
    const ended = at >= length;
    const position = ended ? length : Math.floor(at);
    const ticking = !!clock && clock.running && !ended && !stopping;
    const can = (id) => usable && !stopping && row.usable.indexOf(id) >= 0;
    const items = row.controls.map((id) => {
        if (id === "arm") { return { id: id, on: held("arm", r.armed), enabled: can(id) }; }
        if (id === "counter") {
            const times = REPLAY_TIMES[row.time](r, position);
            return { id: id, text: timeText(times[0]) + " / " + timeText(times[1]), frozen: row.dim || stopping };
        }
        return { id: id, enabled: can(id), pushed: pressed && local.press.target === id };
    });
    return {
        items: items, ticking: ticking,
        // How long until the position reaches its next whole second.
        nextMs: ticking
            ? (Math.floor(at) + 1 - at) / clockRate(clock, local.now) * 1000 + CONFIG.replayTickLagMs : 0
    };
}

// The six bands of the focused appliance's equaliser, when it reports six.
function deriveEq(p, focus, usable, local) {
    const gains = p && p.eq && Array.isArray(p.eq.output_bands) && p.eq.output_bands.length === 6 ? p.eq.output_bands : [];
    const bands = Object.keys(EQ_FILTERS).slice(0, gains.length).map((id, i) => {
        const hz = EQ_FILTERS[id].hz;
        return { id: id, hz: hz, label: eqLabel(hz), min: -EQ_GRAPH.range, max: EQ_GRAPH.range, gain: held("eq:" + id, gains[i]) };
    });
    const available = !!focus && bands.length > 0;
    return {
        available: available,
        open: available && local.eqOpen && focus.id === local.eqFor,
        name: focus ? focus.name : "",
        note: "",
        bands: bands,
        filters: responseFilters(bands),
        enabled: usable
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

// The keypad card while a speaker's PIN is wanted on the focused appliance
// and the person has not turned it away.
function derivePinCard(dial, p, focus, local) {
    const r = dial.outputs_request;
    if (!r || !focus || r.appliance_id !== focus.id || !r.awaiting_pin) { return null; }
    const timed = r.state === "rejected" && typeof r.awaiting_until === "number";
    if (timed && dialNow(local) >= r.awaiting_until) { return null; }
    if (local.pin.dismissedAt === r.requested_at) { return null; }
    const unit = p && p.outputs ? (p.outputs.units || []).find((u) => u.id === r.output_id) : null;
    const name = unit ? unit.name : "this speaker";
    const key = r.requested_at + ":" + r.state + ":" + (r.error || "");
    const digits = local.pin.forKey === key ? local.pin.digits : "";
    const busy = r.state === "pending";
    const limited = r.state === "rejected" && r.error === "rate_limited";
    const waitLeft = limited && typeof r.retry_until === "number"
        ? Math.max(0, Math.ceil(r.retry_until - dialNow(local))) : 0;
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

// The "could not start" card for the focused appliance, until it is answered.
function deriveStartFailure(dial, focus, local) {
    const f = dial.start_failure;
    if (!f || !focus || f.appliance_id !== focus.id || local.startFailureAnswered === f.key) { return null; }
    return {
        kind: "notice", key: "start_failure", source: "", severity: "warning", progress: null, closable: false,
        timed: false, title: "Could not start " + f.name, message: START_FAILURE[f.reason] || START_FAILURE.other,
        buttons: [{ id: "ok", label: "OK", act: "start_failure_ok" }], failureKey: f.key
    };
}

// The shut-down card to show, if any: its key in POWER_CARDS.
function derivePower(dial, local) {
    const rule = POWER_RULES.find((r) => r[0](dial.power, local.power));
    return rule ? rule[1] : null;
}

// The one modal card to show, if any: the shut-down card first (the person
// has just asked for it), then the Auto-Start question (asked for too),
// then the PIN recovery confirmation, a speaker's PIN, a speaker that could
// not start, the not-allowed notice, an appliance warning opened from its
// badge, then the warning the dial says is due.
function deriveModal(dial, p, focus, local) {
    const cardsById = new Map(dial.warnings.cards.map((c) => [c.id, c]));
    const owners = new Map();
    dial.appliances.forEach((a) => a.warnings.forEach((w) => owners.set(w.key, a.id)));
    const due = cardsById.get(dial.warnings.due);

    const power = derivePower(dial, local);
    if (power) {
        return Object.assign({ key: "power", source: "", severity: "warning", progress: null, kind: "notice" }, POWER_CARDS[power]);
    }
    if (local.autoStartAsked) { return Object.assign({ message: AUTO_START_CONFIRM }, AUTO_START_CARD); }
    if (dial.recovery.active && !dial.recovery.confirmed) {
        return {
            key: "presence", source: "", title: "Confirm you are at the dial", severity: "warning", progress: null,
            message: "The PIN is being recovered from the web UI. Confirm only if that is you.", closable: false,
            kind: "notice", buttons: [{ id: "presence", label: "Confirm", act: "presence" }]
        };
    }
    const pinCard = derivePinCard(dial, p, focus, local);
    if (pinCard) { return pinCard; }
    const failureCard = deriveStartFailure(dial, focus, local);
    if (failureCard) { return failureCard; }
    const refused = dial.appliances.find((a) => a.id === local.notice && a.auth !== "authorized");
    if (refused) {
        return {
            key: "notice", source: refused.webui, title: "Not allowed", severity: "info", progress: null,
            message: "Allow this dial in " + refused.name + "'s web UI (Setup, Dials)", closable: true,
            kind: "notice", buttons: [{ id: "ok", label: "OK", act: "close" }]
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

export function derive(dial, focused, local) {
    const cardsById = new Map(dial.warnings.cards.map((c) => [c.id, c]));
    const focusId = dial.focus.appliance_id;
    const focus = dial.appliances.find((a) => a.id === focusId) || null;
    const p = focused ? focused.parts : null;
    const shownFocus = held("focus", focusId);
    const usable = !local.offline && !!focused && focused.reachable && focused.access === "playback";

    const appliances = dial.appliances.map((a) => {
        const status = applianceStatus(a);
        return {
            id: a.id, name: a.name, label: status.label, bad: status.bad,
            lit: !status.bad && (a.playing || a.replaying), badge: replayBadge(a),
            current: a.id === shownFocus, warn: warnBadge(a, cardsById)
        };
    });

    const speakers = deriveSpeakers(dial, p, usable);
    // Master volume and mute act on the dial's volume target: usable only while it is focused.
    const mine = !!focused && focused.id === dial.focus.reporting_id;
    const level = mine ? masterVolume(p) : null;
    const known = typeof level === "number";
    const art = dial.artwork && typeof dial.artwork.url === "string" && dial.artwork.url.indexOf(ARTWORK_PREFIX) === 0
        ? dial.artwork.url : "";
    const backdrop = art && typeof dial.artwork.backdrop_url === "string"
        && dial.artwork.backdrop_url.indexOf(ARTWORK_PREFIX) === 0 ? dial.artwork.backdrop_url : "";
    const text = nowPlayingText(dial, p, focus);

    const panel = dial.panel;
    const settings = {
        brightness: held("brightness", panel.brightness),
        sleepAfter: held("sleep_after_s", panel.sleep_after_s),
        // Any real backlight kind (sysfs or ddc) does the dimming itself.
        dim: panel.backlight === "none"
            ? DIM_FLOOR + (1 - DIM_FLOOR) * held("brightness", panel.brightness) / BRIGHTNESS_MAX : null
    };

    const replay = deriveReplay(focus, usable, local);
    const eq = deriveEq(p, focus, usable, local);
    const modal = deriveModal(dial, p, focus, local);

    return {
        offline: local.offline,
        asleep: !!panel.asleep,
        appliances: appliances,
        focusId: shownFocus,
        appliancesNote: dial.started && !appliances.length ? "No appliances found." : "",
        speakersLabel: focus ? "Speakers on " + focus.name : "Speakers",
        speakers: speakers,
        speakersNote: speakerNote(focus, focused, speakers),
        autoStart: { shown: usable && !!p && playing(p), set: !!(p && p.outputs && p.outputs.default_matches) },
        title: text.title, sub: text.sub, art: art, backdrop: backdrop,
        eqVisible: eq.available,
        volume: {
            enabled: usable && known,
            level: known ? held("master", level) : null,
            muted: mine && !!held("mute", !!(p && p.outputs && p.outputs.muted_all))
        },
        replay: replay,
        eq: eq,
        settings: settings,
        hidePointer: !!panel.kiosk && isLoopbackHost(local.host),
        sheet: { open: local.sheetOpen, info: deriveInfo(local.info), canPower: !local.offline && !derivePower(dial, local) },
        modal: modal,
        // Something on the page changes with the clock.
        live: replay.ticking || !!(modal && modal.timed)
    };
}

function deriveInfo(info) {
    const rows = info ? info.rows.map((row, i) => ({ id: i + ":" + row[0], label: row[0], value: row[1] })) : [];
    return { rows: rows, note: !info ? "Loading..." : info.failed && !rows.length ? "Details are not available." : "" };
}
