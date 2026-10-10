import {
    CONFIG,
    PIN_TEXT,
    PIN_KEY_OFF,
    PIN_KEY_OFF_DIGIT,
    EMPTY_STATE,
    LOGO_URL,
    LOGO_BACKDROP_URL,
    REPLAY_BUTTONS,
    POWER_TAKEN_OVER,
    SLEEP_CHOICES,
    signed
} from "./hd-tables.js";
import { make, setText, makeIcon, setLevel, syncList, els } from "./hd-dom.js";
import { graph, scheduleGraph } from "./hd-eq.js";
import { toast, get, trackDrag } from "./hd-requests.js";
import {
    onAppliance,
    onWarnBadge,
    onOutputToggle,
    onOutputLevel,
    onPress,
    onArm,
    onSleepAfter,
    onEqGain,
    CARD_ACTIONS
} from "./hd-actions.js";
import { derive, replayOf, isLoopbackHost } from "./hd-derive.js";
import {
    ui,
    PIN_IDLE,
    dragging,
    press,
    nextReplayClock,
    hooks
} from "./hd-state.js";

// What asks for a redraw from the state module calls this.
hooks.render = render;

// What PRESS_RELEASES reads, from the page's current state.
function pressContext() {
    const s = ui.state;
    const focus = s ? s.appliances.find((a) => a.id === s.focus.appliance_id) || null : null;
    const t = s && s.transport && s.transport.appliance_id === press.id
        && s.transport.kind === REPLAY_BUTTONS[press.target].kind ? s.transport : null;
    const replay = replayOf(focus);
    return { focus: focus, offline: ui.offline, r: replay ? replay.r : null, t: t };
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
