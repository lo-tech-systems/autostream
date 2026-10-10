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
        noticeMs: 7000
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
        outputs: null
    };

    const LOGO_URL = "/static/logo.png";
    const ARTWORK_PREFIX = "/api/v1/artwork/";

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
        const m = Math.floor(total / 60);
        const s = total % 60;
        return m + ":" + (s < 10 ? "0" : "") + s;
    }

    // ---- State, optimistic values ----------------------------------------

    const ui = { state: null, offline: false, vm: null };
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

    function derive(s, offline) {
        const byId = new Map(s.appliances.map((a) => [a.id, a]));
        const focusId = s.focus.appliance_id;
        const focus = byId.get(focusId) || null;
        const shownFocus = settle("focus", focusId);
        const usable = !offline && !!focus && focus.auth === "authorized" && focus.reachable;

        const appliances = s.appliances.map((a) => {
            const status = applianceStatus(a);
            return {
                id: a.id, name: a.name, label: status.label, bad: status.bad,
                lit: !status.bad && (a.playing || a.replaying),
                badge: replayBadge(a), current: a.id === shownFocus
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

        return {
            offline: offline,
            appliances: appliances,
            appliancesNote: s.started && !appliances.length ? "No appliances found." : "",
            speakersLabel: focus ? "Speakers on " + focus.name : "Speakers",
            speakers: speakers,
            speakersNote: speakerNote(focus, outputs, speakers),
            title: text.title, sub: text.sub, art: art,
            eqVisible: !!focus && focus.capabilities.eq > 0,
            volume: {
                enabled: usable && known,
                level: known ? settle("master", volume.level) : null,
                muted: mine && settle("mute", !!volume.muted)
            }
        };
    }

    // ---- Painting -------------------------------------------------------

    const els = {
        app: $("app"), appliances: $("appliances"), appliancesNote: $("appliances-note"),
        speakers: $("speakers"), speakersNote: $("speakers-note"), speakersLabel: $("speakers-label"),
        art: $("art"), title: $("title"), sub: $("sub"), eq: $("eq-open"), mute: $("mute"),
        master: $("master"), masterNum: $("master-num"), volumeRow: $("volume-row"),
        offline: $("offline"), toast: $("toast")
    };

    function createApplianceRow() {
        const node = make("button", "appliance");
        node.type = "button";
        const parts = {
            dot: node.appendChild(make("span", "dot")),
            name: node.appendChild(make("span", "name")),
            badge: node.appendChild(make("span", "badge")),
            state: node.appendChild(make("span", "state"))
        };
        node.addEventListener("click", () => onAppliance(node.dataset.key));
        node._update = (item) => {
            node.classList.toggle("lit", item.lit);
            node.classList.toggle("bad", item.bad);
            node.setAttribute("aria-current", item.current ? "true" : "false");
            setText(parts.name, item.name);
            setText(parts.badge, item.badge);
            setText(parts.state, item.label);
        };
        return node;
    }

    function createSpeakerCard() {
        const node = make("div", "output-card");
        const head = node.appendChild(make("div", "output-card-head"));
        const meta = head.appendChild(make("div", "output-card-meta"));
        const name = meta.appendChild(make("div", "output-card-name"));
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
        slider.addEventListener("pointerdown", () => dragging.add(key()));
        ["pointerup", "pointercancel"].forEach((type) => {
            slider.addEventListener(type, () => dragging.delete(key()));
        });

        node._update = (item) => {
            node.classList.toggle("output-card-on", item.on && !item.inUse);
            node.classList.toggle("output-card-off", !item.on || item.inUse);
            node.classList.toggle("output-card-in-use", item.inUse);
            setText(name, item.name);
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

    function paintNote(node, text) {
        node.hidden = !text;
        setText(node, text);
    }

    function paint(vm) {
        els.app.classList.toggle("offline", vm.offline);
        syncList(els.appliances, vm.appliances, createApplianceRow);
        paintNote(els.appliancesNote, vm.appliancesNote);
        setText(els.speakersLabel, vm.speakersLabel);
        syncList(els.speakers, vm.speakers, createSpeakerCard);
        paintNote(els.speakersNote, vm.speakersNote);

        setText(els.title, vm.title);
        setText(els.sub, vm.sub);
        const src = vm.art || LOGO_URL;
        if (els.art.getAttribute("src") !== src) { els.art.setAttribute("src", src); }
        els.art.classList.toggle("logo", !vm.art);
        els.eq.hidden = !vm.eqVisible;

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
    }

    function render() {
        ui.vm = derive(ui.state || EMPTY_STATE, ui.offline);
        paint(ui.vm);
    }

    // ---- Requests -------------------------------------------------------

    let toastTimer = 0;

    function toast(text, ms) {
        setText(els.toast, text);
        els.toast.classList.add("show");
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => els.toast.classList.remove("show"), ms || CONFIG.toastMs);
    }

    // Every action goes through here. A refusal or a failure shows briefly and
    // puts the controls named in *keys* back to what the state says.
    function post(action, body, keys) {
        const abort = new AbortController();
        const timer = setTimeout(() => abort.abort(), CONFIG.requestTimeoutMs);
        return fetch("/api/v1/actions/" + action, {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-Requested-With": "autostream-hd" },
            credentials: "same-origin",
            body: JSON.stringify(body),
            signal: abort.signal
        }).then((response) => response.json().catch(() => ({})).then((reply) => {
            if (!response.ok || reply.ok === false) {
                const reason = reply.error || "http_" + response.status;
                console.warn("action " + action + " refused: " + reason);
                toast(REFUSALS[reason] || FALLBACK_REFUSAL);
                rollBack(keys);
            }
        })).catch((error) => {
            console.warn("action " + action + " failed: " + error);
            toast(OFFLINE_REFUSAL);
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

    // ---- Actions from the page ------------------------------------------

    const focusId = () => (ui.state ? ui.state.focus.appliance_id : null);
    const canAct = () => !!ui.state && !ui.offline;

    function onAppliance(id) {
        if (!canAct()) { return; }
        const a = ui.state.appliances.find((item) => item.id === id);
        if (!a) { return; }
        if (a.auth !== "authorized") {
            toast("Allow this dial in " + a.name + "'s web UI (Setup, Dials): " + a.webui, CONFIG.noticeMs);
            return;
        }
        if (id === focusId() && !pending.focus) { return; }
        setPending("focus", id);
        render();
        post("focus", { appliance_id: id }, ["focus"]);
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

    els.master.addEventListener("input", () => onMasterLevel(Number(els.master.value), false));
    els.master.addEventListener("change", () => onMasterLevel(Number(els.master.value), true));
    els.master.addEventListener("pointerdown", () => dragging.add("master"));
    ["pointerup", "pointercancel"].forEach((type) => {
        els.master.addEventListener(type, () => dragging.delete("master"));
    });
    els.mute.addEventListener("click", onMute);
    els.art.addEventListener("error", () => {
        if (els.art.getAttribute("src") !== LOGO_URL) {
            els.art.setAttribute("src", LOGO_URL);
            els.art.classList.add("logo");
        }
    });

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
        fetch("/api/v1/state", { credentials: "same-origin", cache: "no-store" })
            .then((response) => (response.ok ? response.text() : Promise.reject(new Error("http_" + response.status))))
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
    }

    setText(els.offline, "Reconnecting...");
    render();
    connect();
    setInterval(tick, CONFIG.tickMs);
}());
