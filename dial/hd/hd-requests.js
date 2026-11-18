// hd-requests.js: how the HD page talks to the dial: the toast, the request
// helpers (the dial's own actions and the appliance intents), the slider drag
// lanes and the pointer follower.

import {
    CONFIG, DIAL_REFUSALS, FALLBACK_REFUSAL, OFFLINE_REFUSAL, ACTION_PREFIX, INTENT_PREFIX, ENDPOINTS
} from "./hd-tables.js";
import { setText, els } from "./hd-dom.js";
import { ui, pending, dragging, hold, rollBack, hooks } from "./hd-state.js";
import { REFUSAL } from "/static/shared/texts.js";

let toastTimer = 0;

export function toast(text, ms) {
    setText(els.toast, text);
    els.toast.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => els.toast.classList.remove("show"), ms || CONFIG.toastMs);
}

// Every request goes out here, and is given up after requestTimeoutMs.
function call(url, init) {
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), CONFIG.requestTimeoutMs);
    return fetch(url, Object.assign({ credentials: "same-origin", cache: "no-store", signal: abort.signal }, init))
        .finally(() => clearTimeout(timer));
}

export const get = (path) => call(path).then((response) => (
    response.ok ? response.text() : Promise.reject(new Error("http_" + response.status))));

// A change: [ok, reply], ok false for a refusal; no answer at all rejects.
const send = (url, body) => call(url, {
    method: "POST", body: JSON.stringify(body),
    headers: { "Content-Type": "application/json", "X-Requested-With": "autostream-hd" }
}).then((response) => response.json().catch(() => ({})).then((reply) => (
    [response.ok && reply.ok !== false, Object.assign({ error: "http_" + response.status }, reply)])));

// What a refusal says: the dial's own words, else the appliance's, else the fallback.
export const refusalText = (reason) => DIAL_REFUSALS[reason]
    || (typeof REFUSAL[reason] === "function" ? REFUSAL[reason]().text : REFUSAL[reason]) || FALLBACK_REFUSAL;

// A request that did not go through: says so unless *quiet*, and lets go of *keys*.
function failed(name, text, why, keys, quiet) {
    console.warn("request " + name + " " + why);
    if (!quiet) { toast(text); }
    rollBack(keys);
    return false;
}

// A dial action. The promise gives the reply (truthy) when it went through, else false.
export function post(action, body, keys, quiet) {
    return send(ENDPOINTS[action] || ACTION_PREFIX + action, body).then(([ok, reply]) => (
        ok ? reply : failed(action, refusalText(reply.error), "refused: " + reply.error, keys, quiet)
    ), (error) => failed(action, OFFLINE_REFUSAL, "failed: " + error, keys, quiet));
}

// What the keypad card answers itself: a PIN wanted, a wrong one, a wait.
const keypadAnswers = (reply) => !!(reply.result && (reply.result.pin_required || reply.result.pin_invalid))
    || reply.error === "rate_limited";

// An appliance intent for the focused appliance. The values held under *keys*
// then stay until the appliance reaches the reply's version (another run of it
// lets go at once); a refusal lets them go and says why; no answer in time says
// nothing and leaves them to run out. The promise gives the reply, or false.
export function submit(name, args, keys) {
    const sentTo = ui.focused;
    return send(INTENT_PREFIX + name, { appliance_id: sentTo ? sentTo.id : "", args: args }).then(([ok, reply]) => {
        const now = ui.focused;
        if (!ok) { return reply.error !== "timeout" && failed(name, refusalText(reply.error), "refused: " + reply.error, keys, keypadAnswers(reply)); }
        const same = !!now && now.id === sentTo.id && now.boot === reply.boot;
        (keys || []).forEach((key) => {
            const value = pending.value(key);
            if (same && value !== undefined) { hold(key, value, reply.version, CONFIG.requestTimeoutMs); } else { pending.drop(key); }
        });
        if (now) { pending.settle(now.version, false); }
        hooks.render();
        return reply;
    }, (error) => (error.name === "AbortError" ? false : failed(name, OFFLINE_REFUSAL, "failed: " + error, keys, false)));
}

// While a slider is dragged: the first change goes out at once, later ones at
// most once per gap (the newest wins), and the final one always goes. A lane
// has one request [how (post or submit), name, body, keys] in flight, since
// two on the wire can reach the dial in either order.
export const lanes = {};

function flush(lane) {
    if (lane.busy || !lane.queued) { return; }
    const [how, name, body, keys] = lane.queued;
    Object.assign(lane, { queued: null, last: JSON.stringify(body), busy: true });
    how(name, body, keys).finally(() => {
        lane.busy = false;
        flush(lane);
    });
}

export function sendDrag(key, final, how, name, body, keys) {
    const lane = lanes[key] || (lanes[key] = { timer: 0, queued: null, last: "", busy: false });
    const queued = [how, name, body, keys];
    if (final) {
        clearTimeout(lane.timer);
        Object.assign(lane, { timer: 0, queued: JSON.stringify(body) === lane.last ? null : queued });
        flush(lane);
        return;
    }
    lane.queued = queued;
    if (lane.timer) { return; }
    flush(lane);
    lane.timer = setTimeout(() => {
        lane.timer = 0;
        if (lane.queued) { sendDrag(key, false, ...lane.queued); }
    }, CONFIG.sendGapMs);
}

// A slider under a finger: the state leaves it alone, and a new drag is sent whatever its value.
export function trackDrag(slider, key) {
    slider.addEventListener("pointerdown", (event) => {
        dragging.add(key());
        forgetLane(key());
        followPointer(event, null, () => dragging.delete(key()));
    });
}

// Forgets the value a lane last sent, so the next one goes out whatever it is.
export function forgetLane(key) {
    if (lanes[key]) { lanes[key].last = ""; }
}

// Follows the pointer that began a drag from the document, so the drag survives
// the finger leaving its element. Only that pointer counts, and a cancel ends it
// like a lift; move may be null. While it is held the panels' idle clock waits.
export function followPointer(start, move, end) {
    const id = start.pointerId;
    const on = { pointermove: (event) => { if (event.pointerId === id && move) { move(event); } } };
    on.pointerup = on.pointercancel = (event) => {
        if (event.pointerId !== id) { return; }
        Object.keys(on).forEach((type) => document.removeEventListener(type, on[type]));
        ui.fingers -= 1;
        end(event);
        hooks.touched();
    };
    ui.fingers += 1;
    hooks.touched();
    Object.keys(on).forEach((type) => document.addEventListener(type, on[type]));
}
