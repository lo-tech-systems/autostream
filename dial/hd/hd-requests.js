// hd-requests.js: how the HD page talks to the dial: the toast, the GET and
// POST helpers, the slider drag lanes and the pointer follower.

import { CONFIG, REFUSALS, FALLBACK_REFUSAL, OFFLINE_REFUSAL, ACTION_PREFIX, ENDPOINTS } from "./hd-tables.js";
import { setText, els } from "./hd-dom.js";
import { dragging, rollBack } from "./hd-state.js";

// ---- Requests -------------------------------------------------------

let toastTimer = 0;

export function toast(text, ms) {
    setText(els.toast, text);
    els.toast.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => els.toast.classList.remove("show"), ms || CONFIG.toastMs);
}

export function get(path) {
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
export function post(action, body, keys, quiet) {
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
// at most once per gap (the newest wins), and the final one always goes. A
// lane has one request in flight: a newer value waits for the answer, since
// two on the wire can reach the dial in either order.
export const lanes = {};

function newLane() {
    return { timer: 0, queued: null, last: "", busy: false };
}

function flush(lane) {
    if (lane.busy || !lane.queued) { return; }
    const [action, body, keys] = lane.queued;
    lane.queued = null;
    lane.last = JSON.stringify(body);
    lane.busy = true;
    post(action, body, keys).finally(() => {
        lane.busy = false;
        flush(lane);
    });
}

export function sendDrag(key, action, body, final, keys) {
    const lane = lanes[key] || (lanes[key] = newLane());
    const queued = [action, body, keys];
    if (final) {
        clearTimeout(lane.timer);
        lane.timer = 0;
        lane.queued = JSON.stringify(body) === lane.last ? null : queued;
        flush(lane);
        return;
    }
    lane.queued = queued;
    if (lane.timer) { return; }
    flush(lane);
    lane.timer = setTimeout(() => {
        lane.timer = 0;
        if (lane.queued) { sendDrag(key, ...lane.queued, false); }
    }, CONFIG.sendGapMs);
}

// A slider under a finger: the state leaves it alone, and a new drag to
// the value the last one ended on is still sent.
export function trackDrag(slider, key) {
    slider.addEventListener("pointerdown", (event) => {
        dragging.add(key());
        forgetLane(key());
        followPointer(event, null, () => dragging.delete(key()));
    });
}

// Forgets the value a lane last sent, so the next one goes out whatever it
// is; a request still in flight keeps the lane's place.
export function forgetLane(key) {
    if (lanes[key]) { lanes[key].last = ""; }
}

// Follows the pointer that began a drag from the document, so the drag
// survives the finger leaving the element it started on. Only that pointer
// counts (a second finger can neither steer nor end it), and a cancel ends
// it like a lift. move may be null; end gets the event that ended it.
export function followPointer(start, move, end) {
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
