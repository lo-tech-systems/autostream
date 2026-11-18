// hd-tables.js: the HD page's configuration, rule tables, text and URLs,
// and two pure formatters. Plain data and functions of their arguments: this
// file imports nothing and touches neither the DOM nor the clock.

// ---- Configuration and tables ---------------------------------------

export const CONFIG = {
    sendGapMs: 100,             // at most one request per control in this time while dragging
    pendingMs: 2000,            // how long a dial setting's optimistic value stands in for the state
    requestTimeoutMs: 8000,     // above the dial's own wait for an appliance's answer
    offlineAfterMs: 10000,      // a stream down this long: offline
    toastMs: 3000,
    activityGapMs: 5000,        // at most one panel activity report in this time
    panelIdleCloseMs: 60000,    // the pull-down and the equaliser close after this long with no touch
    infoMaxAgeMs: 10000,        // the dial details are fetched again after this
    tapMovePx: 6,               // a press that moves less than this is a tap
    wakeGuardMs: 400,           // the shield lets go this long after the waking finger lifts, if no click came
    dragCloseFraction: 3,       // a pull-down moved more than 1/this of its height stays moved
    userScrollHoldMs: 3000,     // after the user scrolls a list, the page leaves it alone this long
    autoScrollSettleMs: 400,    // scroll events this soon after the page's own scroll are not the user's
    pictureSettleMs: 2000,      // a picture that has not loaded by then is shown anyway
    replayResyncS: 2,           // the replay clock jumps to the dial's position only when this far out
    replaySlewS: 10,            // a smaller difference is worked off over this long
    replayMaxSlew: 0.05,        // by running the clock at most this much fast or slow
    replayTickLagMs: 15,        // how soon after a whole second the timer is drawn again
    pinLength: 4,               // digits needed before OK is offered, and boxes always shown
    pinMax: 8                   // the most digits the keypad takes
};

// The first rule that matches gives an appliance row its label.
export const STATUS_RULES = [
    [(a) => a.auth !== "authorized", "Not allowed", true],
    [(a) => a.update_needed, "Needs an update", true],
    [(a) => !a.reachable, "Not responding", true],
    [(a) => a.replaying, "Replaying", false],
    [(a) => a.playing, "Playing", false],
    [() => true, "Idle", false]
];

// What a refusal from the dial itself, or from its link to the appliance,
// says; an appliance's own refusals read from the shared texts.
export const DIAL_REFUSALS = {
    unknown_appliance: "That appliance is no longer there.",
    wrong_state: "Not possible right now.",
    no_record: "There is nothing to do that with.",
    local_only: "That can only be done on the dial's own screen.",
    unreachable: "The appliance did not answer.",
    timeout: "The appliance did not answer in time.",
    bad_reply: "The appliance's answer could not be read.",
    backoff: "The appliance is not answering. The dial keeps trying.",
    protocol_mismatch: "That appliance needs an update.",
    dial_not_authorized: "This dial is not allowed on that appliance."
};
export const FALLBACK_REFUSAL = "That did not work.";
export const OFFLINE_REFUSAL = "No connection to the dial.";

export const PIN_TEXT = {
    instruction: (name) => "Enter the PIN shown on the screen of " + name + ".", busy: "Pairing...",
    wrong: "That PIN was not accepted. Try again.", wait: (n) => "Wait " + n + " seconds before retry", paired: "Paired"
};
// What a rejected speaker request says on the keypad card; the card's own
// reasons for being (a PIN wanted, a wait with its own line) say nothing.
export const SET_FAILURES = {
    pin_invalid: PIN_TEXT.wrong,
    invalid_pin: PIN_TEXT.wrong,
    output_in_use: "That speaker is in use by another appliance.",
    encoder_capacity: "The appliance cannot encode another stream.",
    unreachable: "The appliance did not answer.",
    backend_error: "The appliance could not do that.",
    dial_not_authorized: DIAL_REFUSALS.dial_not_authorized
};
export const SILENT_PIN_OUTCOMES = new Set(["pin_required", "rate_limited"]);
// The first rule that matches gives the keypad card's line under the boxes:
// [applies, text, is a wait].
export const PIN_LINE_RULES = [
    [(r, waitLeft) => waitLeft > 0, (r, waitLeft) => PIN_TEXT.wait(waitLeft), true],
    [(r) => r.state !== "rejected" || SILENT_PIN_OUTCOMES.has(r.error), () => "", false],
    [() => true, (r) => SET_FAILURES[r.error] || FALLBACK_REFUSAL, false]
];
// Whether a keypad key is unusable, by key; a digit is the default.
export const PIN_KEY_OFF = {
    ok: (p) => !p.canSubmit,
    del: (p) => p.busy || p.waiting || !p.digits.length
};
export const PIN_KEY_OFF_DIGIT = (p) => p.busy || p.waiting || p.digits.length >= CONFIG.pinMax;

// The dial part before the first state arrives.
export const EMPTY_STATE = {
    started: false, dial: { uuid: "" }, focus: { appliance_id: null, reporting_id: null }, appliances: [],
    artwork: null, transport: null, outputs_request: null, start_failure: null,
    bell: { severity: null, entries: [] }, status: null,
    panel: {
        asleep: false, brightness: 80, brightness_max: 100, sleep_after_s: 300, sleep_choices: [0, 60, 300, 900],
        backlight: "none", kiosk: false
    },
    recovery: { active: false, confirmed: false }, power: { state: "idle", changed_at: 0 }
};

export const LOGO_URL = "/static/logo.png";
export const ARTWORK_PREFIX = "/api/v1/artwork/";
export const LOGO_BACKDROP_URL = "/api/v1/logo/backdrop";
export const ACTION_PREFIX = "/api/v1/actions/";
export const INTENT_PREFIX = "/api/v1/intents/";

// Everything that is not an action under the action prefix.
export const ENDPOINTS = {
    settings: "/api/v1/settings", panel_wake: "/api/v1/panel/wake",
    panel_sleep: "/api/v1/panel/sleep", panel_activity: "/api/v1/panel/activity"
};
export const INFO_URL = "/api/v1/info";

// The replay row for each state of an appliance's recording: its controls
// left to right, which can be used, what the timer reads (nothing, the
// recording's length from zero, or the replay's position) and whether it is
// dimmed. A state not listed has no row.
export const TRANSPORT_IDLE = ["play", "stop", "counter"];
export const TRANSPORT_REPLAY = ["restart", "stop", "counter"];
export const REPLAY_ROWS = {
    idle: { controls: TRANSPORT_IDLE, usable: [], time: "none", dim: true },
    recording: { controls: ["arm"], usable: ["arm"] },
    pending: { controls: ["arm"], usable: ["arm"] },
    hold: { controls: TRANSPORT_IDLE, usable: ["play"], time: "length", dim: false },
    replaying: { controls: TRANSPORT_REPLAY, usable: ["restart", "stop"], time: "position", dim: false },
    fading_out: { controls: TRANSPORT_REPLAY, usable: [], time: "position", dim: true }
};
// The transport buttons: the intent each sends, the kind of request the dial
// records for it, its spoken label and its icon as path data on a 24 unit
// square. Each is held down from the press until the appliance has answered.
const SEEK_START = { intent: "repeat.seek", args: { position: 0 }, kind: "seek" };
export const REPLAY_BUTTONS = {
    play: Object.assign({ label: "Play the recording", icon: "M8 5.5v13l11-6.5z" }, SEEK_START),
    restart: Object.assign({ label: "Back to the start", icon: "M4 6h2.2v12H4zM13 6v12l-6-6zM20 6v12l-6-6z" }, SEEK_START),
    stop: { intent: "repeat.transport", args: { action: "stop" }, kind: "stop", label: "Stop the replay", icon: "M6.5 6.5h11v11h-11z" }
};
export const NO_TIME = "-:--";
export const SVG_NS = "http://www.w3.org/2000/svg";

// The card the Auto-Start pin opens; its message is the shared sentence.
export const AUTO_START_CARD = {
    key: "auto_start", kind: "notice", title: "Auto-Start", source: "", severity: "info", progress: null, closable: true,
    buttons: [{ id: "cancel", label: "Cancel", act: "close" }, { id: "yes", label: "Yes", act: "auto_start_yes" }]
};

// The cards the Shut down button leads to, by stage: the question, the
// wait while the dial goes down, and the news that it did not.
export const POWER_CARDS = {
    confirm: {
        title: "Shut down?", closable: true,
        message: "The dial will switch off. Unplug it and plug it back in to start it again.",
        buttons: [{ id: "cancel", label: "Cancel", act: "close" }, { id: "shutdown", label: "Shut down", act: "shutdown" }]
    },
    going: { title: "Shutting down...", closable: false, buttons: [], message: "Wait for the screen to go dark before taking the power away." },
    failed: {
        title: "The dial did not shut down", closable: false,
        message: "Nothing was switched off. You can try again from the power button.",
        buttons: [{ id: "ok", label: "OK", act: "power_ack" }]
    }
};
// The card to show, first match wins: p is the dial's power block, u the page's
// own facts (asked: the question is open; sent: the request is out and the
// state has not yet taken it over; dismissedAt: the failure the person has seen).
export const POWER_RULES = [
    [(p, u) => p.state === "requested" || u.sent, "going"],
    [(p, u) => p.state === "failed" && u.dismissedAt !== p.changed_at, "failed"],
    [(p, u) => u.asked, "confirm"]
];
// Whether the dial's state has taken over from the request the page sent.
export const POWER_TAKEN_OVER = (p, u) =>
    p.state === "requested" || (p.state === "failed" && p.changed_at !== u.dismissedAt);
export const POWER_IDLE_UI = { asked: false, sent: false, dismissedAt: 0 };

// A pull-down choice's label: 0 seconds is never.
export const sleepLabel = (seconds) => (seconds === 0 ? "Never" : `${seconds / 60} min`);
// With no backlight to drive the screen is dimmed instead, down to DIM_FLOOR.
export const DIM_FLOOR = 0.35;
export const SEVERITY_ORDER = ["info", "warning", "critical"];

// The equaliser's filters as the appliance applies them, in the order of its
// six band values (the sample rate is the appliance's monitor rate, whose
// difference at 44.1 kHz is below a pixel).
export const EQ_FILTERS = {
    peq1: { type: "low_shelf", hz: 40, q: 0.5 }, peq2: { type: "peak", hz: 100, q: 0.707 },
    peq3: { type: "peak", hz: 300, q: 0.707 }, peq4: { type: "peak", hz: 1000, q: 0.707 },
    peq5: { type: "peak", hz: 4000, q: 0.707 }, peq6: { type: "high_shelf", hz: 10000, q: 0.5 }
};
export const EQ_GRAPH = {
    fs: 48000, fMin: 20, fMax: 20000, range: 12, points: 200, maxDpr: 2,
    padLeft: 34, padRight: 10, padTop: 10, padBottom: 22, labelGap: 38,
    gridDb: [-12, -6, 0, 6, 12],
    gridHz: [[20, "20"], [100, "100"], [1000, "1k"], [10000, "10k"], [20000, "20k"]]
};


export function formatLength(seconds) {
    const total = Math.max(0, Math.round(seconds || 0));
    const h = Math.floor(total / 3600);
    const m = Math.floor(total / 60) % 60;
    const s = total % 60;
    const pad = (n) => (n < 10 ? "0" : "") + n;
    return (h ? h + ":" + pad(m) : String(m)) + ":" + pad(s);
}

export const signed = (value) => (value > 0 ? "+" : "") + value;
