import {
    CONFIG,
    REFUSALS,
    FALLBACK_REFUSAL,
    OFFLINE_REFUSAL,
    PIN_TEXT,
    PIN_KEY_OFF,
    PIN_KEY_OFF_DIGIT,
    EMPTY_STATE,
    LOGO_URL,
    LOGO_BACKDROP_URL,
    ACTION_PREFIX,
    ENDPOINTS,
    INFO_URL,
    REPLAY_BUTTONS,
    POWER_TAKEN_OVER,
    SLEEP_CHOICES,
    signed
} from "./hd-tables.js";
import { make, setText, makeIcon, setLevel, syncList, els } from "./hd-dom.js";
import { graph, scheduleGraph } from "./hd-eq.js";
import { derive, replayOf, isLoopbackHost } from "./hd-derive.js";
import {
    ui,
    PIN_IDLE,
    pending,
    dragging,
    press,
    setPending,
    rollBack,
    clockPosition,
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
