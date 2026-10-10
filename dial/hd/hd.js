import {
    CONFIG,
    PIN_TEXT,
    EMPTY_STATE,
    REPLAY_BUTTONS,
    POWER_TAKEN_OVER
} from "./hd-tables.js";
import { setText, els } from "./hd-dom.js";
import { toast, get } from "./hd-requests.js";
import { paint } from "./hd-paint.js";
import { derive, replayOf, isLoopbackHost } from "./hd-derive.js";
import { ui, PIN_IDLE, press, nextReplayClock, hooks } from "./hd-state.js";

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

// A held button is looked at when the state or the connection changes,
// and only then: a redraw for any other reason (the replay timer, a
// control's own change) has nothing new to say about the request, and
// must not let go of a button whose request the state has yet to show.
function observePress() {
    press.observe(pressContext());
}

let replayTick = 0;

function render() {
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

// ---- The event stream -----------------------------------------------

let source = null;
let lastHeard = Date.now();
let retryAt = 0;
let lastPoll = 0;
let checking = false;

function setOffline(value) {
    if (ui.offline === value) { return; }
    ui.offline = value;
    observePress();
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
    observePress();
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
