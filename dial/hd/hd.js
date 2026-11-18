import { CONFIG, PIN_TEXT, EMPTY_STATE, REPLAY_BUTTONS, POWER_TAKEN_OVER } from "./hd-tables.js";
import { setText, els } from "./hd-dom.js";
import { toast } from "./hd-requests.js";
import { paint } from "./hd-paint.js";
import { watchPanels } from "./hd-actions.js";
import { derive, replayOf, isLoopbackHost } from "./hd-derive.js";
import { ui, PIN_IDLE, pending, press, nextReplayClock, hooks } from "./hd-state.js";
import { StateStream } from "/static/shared/state_stream.js";

// What asks for a redraw from the state module calls this.
hooks.render = render;

// What PRESS_RELEASES reads, from the page's current state.
function pressContext() {
    const d = ui.dial;
    const focus = d ? d.appliances.find((a) => a.id === d.focus.appliance_id) || null : null;
    const t = d && d.transport && d.transport.appliance_id === press.id
        && d.transport.kind === REPLAY_BUTTONS[press.target].kind ? d.transport : null;
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
    const view = () => derive(ui.dial || EMPTY_STATE, ui.focused, Object.assign({ now: Date.now(), press: press.current() }, ui));
    ui.vm = view();
    // The dial's state takes over from the shut-down request the page sent.
    if (ui.power.sent && ui.dial && POWER_TAKEN_OVER(ui.dial.power, ui.power)) {
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
    const request = ui.dial && ui.dial.outputs_request;
    if (ui.pinShown && !pinNow && request && request.state === "accepted") { toast(PIN_TEXT.paired); }
    ui.pinShown = pinNow;
    paint(ui.vm);
    // A running replay is drawn again as its position reaches each
    // whole second, so the timer steps evenly whenever states arrive.
    clearTimeout(replayTick);
    replayTick = ui.vm.replay.ticking ? setTimeout(render, ui.vm.replay.nextMs) : 0;
    watchPanels();
}

function setOffline(value) {
    if (ui.offline === value) { return; }
    ui.offline = value;
    observePress();
    render();
}

// A new copy of the state. A value held for one appliance (or one run of
// it) never shows on another; otherwise what the appliance has reached
// lets its held values go.
function accept(view) {
    Object.assign(ui, { dial: view.parts.dial || null, focused: view.parts.focused || null, time: view.time, stateAt: Date.now() });
    const f = ui.focused;
    const key = f ? f.id + " " + f.boot : "";
    if (key !== ui.focusedKey) {
        ui.focusedKey = key;
        pending.settle(null, true);
    } else {
        pending.settle(f ? f.version : 0, false);
    }
    ui.replayClock = ui.dial ? nextReplayClock(ui.replayClock, ui.dial, ui.time, ui.stateAt) : null;
    observePress();
    render();
}

// Exposed so the host rule can be checked on its own.
window.hdIsLoopbackHost = isLoopbackHost;

setText(els.offline, "Reconnecting...");
render();
new StateStream({
    base: "/api/v1", initial: null, onChange: accept,
    onDown: () => setOffline(true), onUp: () => setOffline(false), graceMs: CONFIG.offlineAfterMs
});
// Something on the page changes with the clock (the replay timer, a timed card).
setInterval(() => { if (ui.vm && ui.vm.live) { render(); } }, 1000);
