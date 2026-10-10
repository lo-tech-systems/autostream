(function () {
    "use strict";

    // ---- Configuration and tables ---------------------------------------

    const CONFIG = {
        sendGapMs: 100,             // at most one request per control in this time while dragging
        pendingMs: 2000,            // how long an optimistic value stands in for the state
        requestTimeoutMs: 4000,
        offlineAfterMs: 10000,      // no stream and nothing heard for this long: offline
        quietCheckMs: 20000,        // an open but silent stream is checked with a state fetch
        pollMs: 5000,               // state fetch cadence while offline
        streamRetryMs: 30000,       // wait before reopening a stream the browser gave up on
        tickMs: 1000,
        toastMs: 3000,
        hideControlsMs: 6000,       // untouched this long, a playing screen shows the artwork alone
        activityGapMs: 5000,        // at most one panel activity report in this time
        infoMaxAgeMs: 10000,        // the dial details are fetched again after this
        tapMovePx: 6,               // a press that moves less than this is a tap
        dragCloseFraction: 3,       // a pull-down moved more than 1/this of its height stays moved
        userScrollHoldMs: 3000,     // after the user scrolls a list, the page leaves it alone this long
        autoScrollSettleMs: 400     // scroll events this soon after the page's own scroll are not the user's
    };

    // The first rule that matches gives an appliance row its label.
    const STATUS_RULES = [
        [(a) => a.auth !== "authorized", "Not authorised", true],
        [(a) => !a.reachable, "Not responding", true],
        [(a) => a.replaying, "Replaying", false],
        [(a) => a.playing, "Playing", false],
        [() => true, "Idle", false]
    ];

    const REFUSALS = {
        unknown_appliance: "That appliance is no longer there.",
        unauthorized: "This dial is not authorised on that appliance.",
        no_capability: "That appliance cannot do this.",
        wrong_state: "Not possible right now.",
        not_polling: "The dial is still starting.",
        not_focused: "Select that appliance first.",
        no_record: "There is nothing to do that with."
    };
    const FALLBACK_REFUSAL = "That did not work.";
    const OFFLINE_REFUSAL = "No connection to the dial.";

    const EMPTY_STATE = {
        started: false,
        focus: { appliance_id: null },
        appliances: [],
        now_playing: null,
        artwork: null,
        volume: { appliance_id: null, level: null, muted: null },
        outputs: null,
        eq: null,
        warnings: { due: null, cards: [] },
        panel: { asleep: false, brightness: 80, sleep_after_s: 300, backlight: "none", always_show_controls: false },
        recovery: { active: false, confirmed: false }
    };

    const LOGO_URL = "/static/logo.png";
    const ARTWORK_PREFIX = "/api/v1/artwork/";
    const ACTION_PREFIX = "/api/v1/actions/";

    // Everything that is not an action under the action prefix.
    const ENDPOINTS = {
        settings: "/api/v1/settings",
        panel_wake: "/api/v1/panel/wake",
        panel_sleep: "/api/v1/panel/sleep",
        panel_activity: "/api/v1/panel/activity"
    };
    const INFO_URL = "/api/v1/info";

    // The controls the replay row shows for each state of an appliance's
    // recording, left to right. An empty list hides the row.
    const REPLAY_CONTROLS = {
        idle: [], recording: ["arm"], pending: ["arm"], hold: ["start"],
        replaying: ["counter", "restart", "stop"], fading_out: ["counter", "restart", "stop"]
    };
    const REPLAY_BUTTONS = {
        start: { action: "replay_start", text: "Replay" },
        restart: { action: "replay_restart", text: "Restart" },
        stop: { action: "replay_stop", text: "Stop" }
    };

    // The pull-down's choices: [seconds, label]; 0 is never.
    const SLEEP_CHOICES = [[60, "1 min"], [300, "5 min"], [900, "15 min"], [0, "Never"]];
    // With no backlight to drive the screen is dimmed instead, down to this.
    const DIM_FLOOR = 0.35;
    const BRIGHTNESS_MAX = 100;

    const SEVERITY_ORDER = ["info", "warning", "critical"];

    // The equaliser's filters as the appliance applies them (a six band
    // appliance has these six; the sample rate is the appliance's monitor
    // rate, whose difference at 44.1 kHz is below a pixel).
    const EQ_FILTERS = {
        peq1: { type: "low_shelf", hz: 40, q: 0.5 },
        peq2: { type: "peak", hz: 100, q: 0.707 },
        peq3: { type: "peak", hz: 300, q: 0.707 },
        peq4: { type: "peak", hz: 1000, q: 0.707 },
        peq5: { type: "peak", hz: 4000, q: 0.707 },
        peq6: { type: "high_shelf", hz: 10000, q: 0.5 }
    };
    // How an appliance with only bass and treble applies each of them: the
    // bands it moves and the share of the slider's gain each one gets.
    const EQ_TWO_BAND = {
        bass: [["peq1", 1], ["peq2", 1]],
        treble: [["peq6", 1], ["peq5", 0.5]]
    };
    const EQ_LABELS = { bass: "Bass", treble: "Treble" };
    const EQ_GRAPH = {
        fs: 48000, fMin: 20, fMax: 20000, range: 12, points: 200, maxDpr: 2,
        padLeft: 34, padRight: 10, padTop: 10, padBottom: 22, labelGap: 38,
        gridDb: [-12, -6, 0, 6, 12],
        gridHz: [[20, "20"], [100, "100"], [1000, "1k"], [10000, "10k"], [20000, "20k"]]
    };

    // ---- Small DOM helpers ------------------------------------------------

    const $ = (id) => document.getElementById(id);

    function make(tag, className, text) {
        const node = document.createElement(tag);
        if (className) { node.className = className; }
        if (text !== undefined) { node.textContent = text; }
        return node;
    }

    function setText(node, text) {
        if (node.textContent !== text) { node.textContent = text; }
    }

    function setLevel(slider, value, enabled) {
        slider.disabled = !enabled;
        if (String(slider.value) !== String(value)) { slider.value = value; }
        slider.style.setProperty("--fill", value + "%");
    }

    // Make the children of *parent* match *items* (each with a unique id) in
    // order, keeping existing nodes so a control being dragged survives.
    // create(item) returns a node with an _update(item) method.
    function syncList(parent, items, create) {
        const old = new Map();
        Array.from(parent.children).forEach((child) => old.set(child.dataset.key, child));
        let prev = null;
        items.forEach((item) => {
            let node = old.get(item.id);
            if (node) {
                old.delete(item.id);
            } else {
                node = create(item);
                node.dataset.key = item.id;
            }
            node._update(item);
            const want = prev ? prev.nextElementSibling : parent.firstElementChild;
            if (want !== node) { parent.insertBefore(node, want); }
            prev = node;
        });
        old.forEach((node) => node.remove());
    }

    function formatLength(seconds) {
        const total = Math.max(0, Math.round(seconds || 0));
        const h = Math.floor(total / 3600);
        const m = Math.floor(total / 60) % 60;
        const s = total % 60;
        const pad = (n) => (n < 10 ? "0" : "") + n;
        return (h ? h + ":" + pad(m) : String(m)) + ":" + pad(s);
    }

    function signed(value) {
        return (value > 0 ? "+" : "") + value;
    }

    // ---- State, optimistic values ----------------------------------------

    // What the page itself holds besides the dial's state.
    const ui = {
        state: null, stateAt: Date.now(), offline: false, vm: null,
        eqOpen: false, eqFor: null, sheetOpen: false, info: null, infoBusy: false,
        notice: null, viewing: null,
        touchAt: Date.now(), forceHidden: false, covered: false, activityAt: 0,
        focusShown: null, listScrolledAt: { appliances: 0, speakers: 0 }, autoScrollUntil: 0
    };
    const pending = {};         // control key -> { value, deadline }
    const dragging = new Set();  // control keys under a finger

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
        if (np && (np.title || np.artist)) {
            const rest = np.title ? [np.artist, np.album] : [np.album];
            return { title: np.title || np.artist, sub: rest.filter(Boolean).join(" · ") };
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

    // The replay row's controls for the focused appliance, from its record.
    const REPLAY_ITEMS = {
        arm: (r, can) => ({ id: "arm", on: settle("arm", r.armed), enabled: can }),
        start: (r, can) => ({ id: "start", text: "Replay " + formatLength(r.duration_s || r.recording_s), enabled: can }),
        counter: (r, can, position) => ({
            id: "counter", text: formatLength(position) + " / " + formatLength(r.duration_s),
            frozen: r.state !== "replaying"
        }),
        restart: (r, can) => ({ id: "restart", text: REPLAY_BUTTONS.restart.text, enabled: can && r.state === "replaying" }),
        stop: (r, can) => ({ id: "stop", text: REPLAY_BUTTONS.stop.text, enabled: can && r.state === "replaying" })
    };

    function deriveReplay(focus, usable, local) {
        const r = focus && focus.capabilities.repeat ? focus.repeat : null;
        const controls = r && r.available ? REPLAY_CONTROLS[r.state] : null;
        if (!controls) { return { items: [], ticking: false }; }
        let position = r.position_s;
        if (r.state === "replaying") {
            position += (local.now - local.stateAt) / 1000;
            if (r.duration_s > 0) { position = Math.min(position, r.duration_s); }
        }
        return {
            items: controls.map((id) => REPLAY_ITEMS[id](r, usable, position)),
            ticking: r.state === "replaying"
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
            closable: false, owner: owner
        };
    }

    // The one modal card to show, if any: the PIN recovery confirmation first,
    // then the not-authorised notice, an appliance warning opened from its
    // badge, then the warning the dial says is due.
    function deriveModal(s, focus, local) {
        const cardsById = new Map(s.warnings.cards.map((c) => [c.id, c]));
        const owners = new Map();
        s.appliances.forEach((a) => a.warnings.forEach((w) => owners.set(w.key, a.id)));
        const due = cardsById.get(s.warnings.due);

        if (s.recovery.active && !s.recovery.confirmed) {
            return {
                key: "presence", source: "", title: "Confirm you are at the dial",
                message: "The PIN is being recovered from the web UI. Confirm only if that is you.",
                severity: "warning", progress: null, closable: false,
                buttons: [{ id: "presence", label: "Confirm", act: "presence" }]
            };
        }
        const unauthorised = s.appliances.find((a) => a.id === local.notice && a.auth !== "authorized");
        if (unauthorised) {
            return {
                key: "notice", source: unauthorised.webui, title: "Not authorised",
                message: "Allow this dial in " + unauthorised.name + "'s web UI (Setup, Dials)",
                severity: "info", progress: null, closable: true,
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
        const text = nowPlayingText(s, focus);

        const panel = s.panel;
        const settings = {
            brightness: settle("brightness", panel.brightness),
            sleepAfter: settle("sleep_after_s", panel.sleep_after_s),
            always: settle("always", !!panel.always_show_controls),
            dim: panel.backlight === "none"
                ? DIM_FLOOR + (1 - DIM_FLOOR) * settle("brightness", panel.brightness) / BRIGHTNESS_MAX : null
        };

        const replay = deriveReplay(focus, usable, local);
        const eq = deriveEq(s, focus, usable, local);
        const modal = deriveModal(s, focus, local);
        const playing = !!s.now_playing && !!s.now_playing.playing;
        const idle = local.now - local.touchAt > CONFIG.hideControlsMs;
        const hideable = !settings.always && playing && !modal && !eq.open && !local.sheetOpen;

        return {
            offline: offline,
            asleep: !!panel.asleep,
            appliances: appliances,
            focusId: shownFocus,
            appliancesNote: s.started && !appliances.length ? "No appliances found." : "",
            speakersLabel: focus ? "Speakers on " + focus.name : "Speakers",
            speakers: speakers,
            speakersNote: speakerNote(focus, outputs, speakers),
            title: text.title, sub: text.sub, art: art,
            eqVisible: eq.available,
            volume: {
                enabled: usable && known,
                level: known ? settle("master", volume.level) : null,
                muted: mine && settle("mute", !!volume.muted)
            },
            replay: replay,
            eq: eq,
            settings: settings,
            sheet: { open: local.sheetOpen, info: deriveInfo(local.info) },
            modal: modal,
            controlsHidden: hideable && (local.forceHidden || idle),
            // Something on the page changes with the clock.
            live: replay.ticking || (hideable && !local.forceHidden && !idle)
        };
    }

    function deriveInfo(info) {
        const rows = info ? info.rows.map((row, i) => ({ id: i + ":" + row[0], label: row[0], value: row[1] })) : [];
        let note = "";
        if (!info) { note = "Loading..."; } else if (info.failed && !rows.length) { note = "Details are not available."; }
        return { rows: rows, note: note };
    }

    // ---- Painting -------------------------------------------------------

    const els = {
        app: $("app"), appliances: $("appliances"), appliancesNote: $("appliances-note"),
        appliancesList: $("appliances-list"), speakersList: $("speakers-list"),
        speakers: $("speakers"), speakersNote: $("speakers-note"), speakersLabel: $("speakers-label"),
        right: $("right"), replay: $("replay-row"),
        art: $("art"), title: $("title"), sub: $("sub"), eq: $("eq-open"), mute: $("mute"),
        master: $("master"), masterNum: $("master-num"), volumeRow: $("volume-row"),
        offline: $("offline"), toast: $("toast"),
        handle: $("handle"), scrim: $("scrim"), sheet: $("sheet"),
        brightness: $("brightness"), brightnessNum: $("brightness-num"), sleepAfter: $("sleep-after"),
        always: $("always"), sleepNow: $("sleep-now"), info: $("info"), infoNote: $("info-note"),
        eqPage: $("eq"), eqClose: $("eq-close"), eqReset: $("eq-reset"), eqFor: $("eq-for"),
        eqBands: $("eq-bands"), eqGraph: $("eq-graph"), eqNote: $("eq-note"),
        modal: $("modal"), card: $("card"), cardTitle: $("card-title"), cardMessage: $("card-message"),
        cardSource: $("card-source"), cardProgress: $("card-progress"), cardBar: $("card-bar"),
        cardButtons: $("card-buttons"), sleep: $("sleep")
    };

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

    // Replay row controls, one builder per id in REPLAY_CONTROLS.
    function replayButton(id) {
        const node = make("button", "pill-btn replay-btn");
        node.type = "button";
        node.addEventListener("click", () => onReplayButton(id));
        node._update = (item) => {
            setText(node, item.text);
            node.disabled = !item.enabled;
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
        start: () => replayButton("start"),
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
        const slider = node.appendChild(make("input", "eq-band-slider"));
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
        if (els.always.checked !== st.always) { els.always.checked = st.always; }
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
        if (!card) { return; }
        els.card.className = "card sev-" + card.severity;
        setText(els.cardTitle, card.title);
        setText(els.cardMessage, card.message);
        paintNote(els.cardSource, card.source);
        els.cardProgress.hidden = card.progress === null;
        els.cardBar.style.setProperty("--fill", (card.progress || 0) + "%");
        syncList(els.cardButtons, card.buttons, createCardButton);
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

    function paint(vm) {
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
        const src = vm.art || LOGO_URL;
        if (els.art.getAttribute("src") !== src) { els.art.setAttribute("src", src); }
        els.art.classList.toggle("logo", !vm.art);
        els.eq.hidden = !vm.eqVisible;
        els.right.classList.toggle("controls-hidden", vm.controlsHidden);
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

    function render() {
        const view = () => derive(ui.state || EMPTY_STATE, Object.assign({ now: Date.now() }, ui));
        ui.vm = view();
        // Controls stay up while a page or card covers them, and for a full
        // while after it goes.
        const covered = !!ui.vm.modal || ui.vm.eq.open || ui.sheetOpen;
        if (ui.covered && !covered) {
            ui.touchAt = Date.now();
            ui.forceHidden = false;
            ui.vm = view();
        }
        ui.covered = covered;
        // A page-only selection ends when nothing shows it any more.
        if (ui.eqOpen && !ui.vm.eq.open) { ui.eqOpen = false; }
        if (!ui.vm.modal) {
            ui.notice = null;
            ui.viewing = null;
        }
        paint(ui.vm);
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
    // *keys* back to what the state says.
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
            }
        })).catch((error) => {
            console.warn("action " + action + " failed: " + error);
            if (!quiet) { toast(OFFLINE_REFUSAL); }
            rollBack(keys);
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
        slider.addEventListener("pointerdown", () => {
            dragging.add(key());
            delete lanes[key()];
        });
        ["pointerup", "pointercancel"].forEach((type) => {
            slider.addEventListener(type, () => dragging.delete(key()));
        });
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

    function onReplayButton(id) {
        post(REPLAY_BUTTONS[id].action, { appliance_id: focusId() });
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

    function onAlways(checked) {
        setPending("always", checked);
        render();
        post("settings", { always_show_controls: checked }, ["always"]);
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
        presence: () => post("presence", {}),
        close: () => {
            ui.notice = null;
            ui.viewing = null;
            render();
        }
    };

    els.master.addEventListener("input", () => onMasterLevel(Number(els.master.value), false));
    els.master.addEventListener("change", () => onMasterLevel(Number(els.master.value), true));
    trackDrag(els.master, () => "master");
    els.mute.addEventListener("click", onMute);
    els.art.addEventListener("error", () => {
        if (els.art.getAttribute("src") !== LOGO_URL) {
            els.art.setAttribute("src", LOGO_URL);
            els.art.classList.add("logo");
        }
    });

    els.eq.addEventListener("click", () => setEqOpen(true));
    els.eqClose.addEventListener("click", () => setEqOpen(false));
    els.eqReset.addEventListener("click", onEqReset);

    els.brightness.addEventListener("input", () => onBrightness(Number(els.brightness.value), false));
    els.brightness.addEventListener("change", () => onBrightness(Number(els.brightness.value), true));
    trackDrag(els.brightness, () => "brightness");
    els.always.addEventListener("change", () => onAlways(els.always.checked));
    els.sleepNow.addEventListener("click", () => {
        setSheet(false);
        post("panel_sleep", {});
    });
    els.scrim.addEventListener("click", () => setSheet(false));
    els.modal.addEventListener("click", (event) => {
        if (event.target === els.modal && ui.vm && ui.vm.modal && ui.vm.modal.closable) { CARD_ACTIONS.close(); }
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
            target.setPointerCapture(event.pointerId);
            const move = (e) => {
                dy = e.clientY - y0;
                if (Math.abs(dy) > CONFIG.tapMovePx) { moved = true; }
                const offset = startOpen ? Math.min(0, dy) : Math.max(-height, Math.min(0, dy - height));
                els.sheet.style.transform = "translateY(" + offset + "px)";
            };
            const up = () => {
                target.removeEventListener("pointermove", move);
                target.removeEventListener("pointerup", up);
                target.removeEventListener("pointercancel", up);
                els.sheet.classList.remove("dragging");
                els.sheet.style.transform = "";
                if (!moved) {
                    setSheet(!startOpen);
                } else {
                    const keep = height / CONFIG.dragCloseFraction;
                    setSheet(startOpen ? dy > -keep : dy > keep);
                }
            };
            target.addEventListener("pointermove", move);
            target.addEventListener("pointerup", up);
            target.addEventListener("pointercancel", up);
        });
    }
    bindSheetDrag(els.handle, false);
    bindSheetDrag(els.sheet, true);
    // A keyboard press on the handle is a click with no pointer.
    els.handle.addEventListener("click", (event) => {
        if (event.detail === 0) { setSheet(!ui.sheetOpen); }
    });

    // A touch while the panel sleeps only wakes it.
    els.sleep.addEventListener("pointerdown", (event) => {
        event.preventDefault();
        event.stopPropagation();
        post("panel_wake", {});
    });

    // Every other touch: it counts as activity for the panel's idle clock
    // (reported at most once in a while), and on the right column it brings
    // back controls that have faded, or with the artwork toggles them.
    document.addEventListener("pointerdown", (event) => {
        if (ui.vm && ui.vm.asleep) { return; }
        const now = Date.now();
        if (now - ui.activityAt >= CONFIG.activityGapMs) {
            ui.activityAt = now;
            post("panel_activity", {}, [], true);
        }
        if (els.right.contains(event.target)) {
            ui.touchAt = now;
            ui.forceHidden = !!event.target.closest(".art-frame") && !!ui.vm && !ui.vm.controlsHidden;
            render();
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
    window.addEventListener("pagehide", () => {
        if (source) { source.close(); }
    });

    setText(els.offline, "Reconnecting...");
    render();
    connect();
    setInterval(tick, CONFIG.tickMs);
}());
