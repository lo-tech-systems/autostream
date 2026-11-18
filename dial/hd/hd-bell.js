// hd-bell.js: the warning bells. The dial's own bell sits in the APPLIANCES
// header and each appliance row has one of its own; a tap opens a card that
// pages through that bell's warnings. Nothing here opens a card by itself, and
// putting a card away asks nothing of the dial.

import { SEVERITY_ORDER } from "./hd-tables.js";
import { els, make, makeIcon, setText, BELL_ICON } from "./hd-dom.js";
import { ui, hooks } from "./hd-state.js";

// The label of each extra action an entry offers beside Close.
const ACTION_LABELS = { restart: "Restart" };

// The owner of the dial's own bell; an appliance's is its id.
const DIAL = "dial";

// What a bell shows: its count and worst severity, or null with no entries.
export function bellBadge(entries, owner) {
    if (!entries.length) { return null; }
    const worst = entries.reduce((top, e) => (
        SEVERITY_ORDER.indexOf(e.severity) > SEVERITY_ORDER.indexOf(top) ? e.severity : top
    ), "info");
    return { count: entries.length, severity: worst, owner: owner };
}

function entriesOf(dial, owner) {
    if (owner === DIAL) { return dial.bell.entries; }
    const a = dial.appliances.find((item) => item.id === owner);
    return a ? a.warnings : [];
}

export function openBell(owner) {
    ui.bell = { owner: owner, index: 0 };
    hooks.render();
}

// The next entry, the first after the last.
export function nextEntry() {
    const count = ui.dial && ui.bell ? entriesOf(ui.dial, ui.bell.owner).length : 0;
    if (count) { ui.bell = { owner: ui.bell.owner, index: (Math.min(ui.bell.index, count - 1) + 1) % count }; }
    hooks.render();
}

const button = (act, label, i) => ({ id: i + ":" + act, label: label, act: act });

// The card for the bell the person has opened, or null when there is none to
// show: an appliance whose warnings have gone, or no state yet. An empty dial
// bell shows that the dial is well.
export function bellCard(dial, bell) {
    if (!bell || !dial.started) { return null; }
    const entries = entriesOf(dial, bell.owner);
    const card = { key: "bell", progress: null, closable: true, kind: "notice" };
    if (!entries.length) {
        if (bell.owner !== DIAL) { return null; }
        return Object.assign(card, {
            title: "Dial is healthy", message: "No warnings on this dial.", severity: "info",
            source: dial.dial.name + " · version " + dial.dial.version, buttons: [button("close", "Close", 0)]
        });
    }
    const at = Math.min(bell.index, entries.length - 1);
    const e = entries[at];
    const acts = [["close", "Close"]].concat(e.actions.map((act) => [act, ACTION_LABELS[act] || act]),
        entries.length > 1 ? [["next", "Next"]] : []);
    return Object.assign(card, {
        title: e.title, message: e.message, severity: e.severity,
        source: e.source + (entries.length > 1 ? " · " + (at + 1) + " of " + entries.length : ""),
        buttons: acts.map((a, i) => button(a[0], a[1], i))
    });
}

// The dial bell's button: an outline with nothing to say, otherwise filled in
// the worst severity's colour with the count in it.
export function paintDialBell(badge) {
    const count = els.dialBell.lastChild;
    els.dialBell.className = "head-btn dial-bell" + (badge ? " filled sev-" + badge.severity : "");
    els.dialBell.setAttribute("aria-label", badge ? "Dial warnings: " + badge.count : "Dial warnings");
    setText(count, badge ? String(badge.count) : "");
}

els.dialBell.append(makeIcon(BELL_ICON), make("span", "warn-count"));
els.dialBell.addEventListener("click", () => openBell(DIAL));
