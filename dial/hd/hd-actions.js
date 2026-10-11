// hd-actions.js: what a touch does on the HD page: the handlers, the card
// actions, the keypad, the pull-down drag, the sleep shield and the activity
// report, with the event bindings that reach them.

import { CONFIG, INFO_URL, REPLAY_BUTTONS } from "./hd-tables.js";
import { els } from "./hd-dom.js";
import { ui, PIN_IDLE, pending, press, setPending, clockPosition, hooks } from "./hd-state.js";
import { post, sendDrag, get, followPointer, forgetLane, trackDrag } from "./hd-requests.js";

// ---- Actions from the page ------------------------------------------

const focusId = () => (ui.state ? ui.state.focus.appliance_id : null);
const canAct = () => !!ui.state && !ui.offline;

export function onAppliance(id) {
    if (!canAct()) { return; }
    const a = ui.state.appliances.find((item) => item.id === id);
    if (!a) { return; }
    if (a.auth !== "authorized") {
        ui.notice = id;
        hooks.render();
        return;
    }
    if (id === focusId() && !pending.focus) { return; }
    setPending("focus", id);
    hooks.render();
    post("focus", { appliance_id: id }, ["focus"]);
}

export function onWarnBadge(key) {
    ui.viewing = key;
    hooks.render();
}

export function onOutputToggle(id, selected) {
    const key = "out:" + id + ":selected";
    setPending(key, selected);
    hooks.render();
    post("output", { appliance_id: focusId(), output_id: id, selected: selected }, [key]);
}

export function onOutputLevel(id, level, final) {
    const key = "out:" + id + ":volume";
    setPending(key, level);
    hooks.render();
    sendDrag(key, "output", { appliance_id: focusId(), output_id: id, volume: level }, final, [key]);
}

function onMasterLevel(level, final) {
    setPending("master", level);
    hooks.render();
    sendDrag("master", "volume_set", { appliance_id: focusId(), level: level }, final, ["master"]);
}

function onMute() {
    if (!ui.vm || !ui.vm.volume.enabled) { return; }
    setPending("mute", !ui.vm.volume.muted);
    hooks.render();
    post("mute_toggle", { appliance_id: focusId() }, ["mute"]);
}

export function onArm(armed) {
    setPending("arm", armed);
    hooks.render();
    post("repeat_arm", { appliance_id: focusId(), armed: armed }, ["arm"]);
}

// The transport buttons are held down from the press (see
// PRESS_RELEASES) and let go at once if the request does not go through.
export function onPress(id) {
    const appliance = ui.state && ui.state.appliances.find((item) => item.id === focusId());
    if (!appliance || !appliance.repeat || !canAct()) { return; }
    const clock = ui.replayClock && ui.replayClock.id === appliance.id ? ui.replayClock : null;
    const position = clock ? clockPosition(clock, Date.now()) : appliance.repeat.position_s;
    const serial = press.start(id, appliance, position, ui.state.transport ? ui.state.transport.requested_at : null);
    if (!serial) { return; }
    hooks.render();
    post(REPLAY_BUTTONS[id].action, { appliance_id: appliance.id }).then((reply) => {
        press.sent(serial, reply);
        // A token alone is not news to draw: the state has yet to show
        // the request it names.
        if (!press.current()) { hooks.render(); }
    });
}

export function onEqGain(id, gain, final) {
    const key = "eq:" + id;
    setPending(key, gain);
    hooks.render();
    sendDrag(key, "eq", { appliance_id: focusId(), gains: { [id]: gain } }, final, [key]);
}

function onEqReset() {
    if (!ui.vm) { return; }
    const keys = ui.vm.eq.bands.map((b) => "eq:" + b.id);
    keys.forEach((key) => {
        setPending(key, 0);
        forgetLane(key);
    });
    hooks.render();
    post("eq_reset", { appliance_id: focusId() }, keys);
}

function setEqOpen(open) {
    ui.eqOpen = open;
    ui.eqFor = open ? focusId() : null;
    hooks.render();
}

function onBrightness(value, final) {
    setPending("brightness", value);
    hooks.render();
    sendDrag("brightness", "settings", { brightness: value }, final, ["brightness"]);
}

export function onSleepAfter(seconds) {
    setPending("sleep_after_s", seconds);
    hooks.render();
    post("settings", { sleep_after_s: seconds }, ["sleep_after_s"]);
}

function setSheet(open) {
    ui.sheetOpen = open;
    if (open) { loadInfo(); }
    hooks.render();
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
            hooks.render();
        });
}

// What each button on a modal card does.
export const CARD_ACTIONS = {
    dismiss: (card) => {
        ui.viewing = null;
        post("warning_dismiss", { warning_id: card.key });
        hooks.render();
    },
    restart: () => post("dial_restart", {}),
    shutdown: () => {
        ui.power = Object.assign({}, ui.power, { asked: false, sent: true });
        setSheet(false);
        post("dial_shutdown", {}).then((went) => {
            if (!went) {
                ui.power = Object.assign({}, ui.power, { sent: false });
                hooks.render();
            }
        });
    },
    power_ack: () => {
        ui.power = Object.assign({}, ui.power, { dismissedAt: ui.state.power.changed_at });
        hooks.render();
    },
    presence: () => post("presence", {}),
    close: () => {
        ui.notice = null;
        ui.viewing = null;
        ui.power = Object.assign({}, ui.power, { asked: false });
        hooks.render();
    },
    pin_cancel: (card) => {
        const at = card.kind === "pin" ? card.pin.requestedAt : card.requestedAt;
        ui.pin = Object.assign({}, ui.pin, PIN_IDLE, { dismissedAt: at });
        hooks.render();
    }
};

els.master.addEventListener("input", () => onMasterLevel(Number(els.master.value), false));
els.master.addEventListener("change", () => onMasterLevel(Number(els.master.value), true));
trackDrag(els.master, () => "master");
els.mute.addEventListener("click", onMute);

els.eq.addEventListener("click", () => setEqOpen(true));
els.eqClose.addEventListener("click", () => setEqOpen(false));
els.eqReset.addEventListener("click", onEqReset);

els.brightness.addEventListener("input", () => onBrightness(Number(els.brightness.value), false));
els.brightness.addEventListener("change", () => onBrightness(Number(els.brightness.value), true));
trackDrag(els.brightness, () => "brightness");
els.power.addEventListener("click", () => {
    ui.power = Object.assign({}, ui.power, { asked: true });
    hooks.render();
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
    hooks.render();
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

// ---- The open panels' idle clock ---------------------------------------

// The pull-down and the equaliser close by themselves after
// CONFIG.panelIdleCloseMs with no touch. One timer, set only while a panel
// is open, and not while a finger is held or a card is up (the clock starts
// again when the card goes). Drawing again never restarts it.
const panelsOpen = () => ui.sheetOpen || ui.eqOpen;

function closePanels() {
    ui.panelTimer = 0;
    if (ui.sheetOpen) { setSheet(false); }
    if (ui.eqOpen) { setEqOpen(false); }
}

function armPanelClock(restart) {
    const wanted = panelsOpen() && !ui.fingers && !(ui.vm && ui.vm.modal);
    if (!wanted) {
        clearTimeout(ui.panelTimer);
        ui.panelTimer = 0;
    } else if (restart || !ui.panelTimer) {
        clearTimeout(ui.panelTimer);
        ui.panelTimer = setTimeout(closePanels, CONFIG.panelIdleCloseMs);
    }
}

// Called after every draw: sees to the timer for what is open now, and
// closes both panels when the screen has just gone to sleep.
export function watchPanels() {
    const asleep = !!(ui.vm && ui.vm.asleep);
    const fell = asleep && !ui.wasAsleep;
    ui.wasAsleep = asleep;
    if (fell) { closePanels(); }
    armPanelClock(false);
}

hooks.touched = () => armPanelClock(true);

// Any way of working a panel counts: a touch or mouse press, a drag, a
// key, a slider change, a click (a keyboard press on a button is one) and
// the wheel.
["pointerdown", "keydown", "input", "change", "click", "wheel"].forEach((type) => {
    document.addEventListener(type, hooks.touched, { capture: true, passive: true });
});
