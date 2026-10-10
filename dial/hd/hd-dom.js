// hd-dom.js: element lookup, the small DOM helpers and the table of the
// page's elements. Reads the document; it holds no state of its own.

import { SVG_NS } from "./hd-tables.js";

// ---- Small DOM helpers ------------------------------------------------

export const $ = (id) => document.getElementById(id);

export function make(tag, className, text) {
    const node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined) { node.textContent = text; }
    return node;
}

export function setText(node, text) {
    if (node.textContent !== text) { node.textContent = text; }
}

// A filled icon drawn from path data on a 24 unit square.
export function makeIcon(pathData) {
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("width", "28");
    svg.setAttribute("height", "28");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("fill", "currentColor");
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", pathData);
    svg.appendChild(path);
    return svg;
}

export function setLevel(slider, value, enabled) {
    slider.disabled = !enabled;
    if (String(slider.value) !== String(value)) { slider.value = value; }
    slider.style.setProperty("--fill", value + "%");
}

// Make the children of *parent* match *items* (each with a unique id) in
// order, keeping existing nodes so a control being dragged survives.
// create(item) returns a node with an _update(item) method.
export function syncList(parent, items, create) {
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

export const els = {
    app: $("app"), appliances: $("appliances"), appliancesNote: $("appliances-note"),
    appliancesList: $("appliances-list"), speakersList: $("speakers-list"),
    speakers: $("speakers"), speakersNote: $("speakers-note"), speakersLabel: $("speakers-label"),
    replay: $("replay-row"),
    art: $("art"), artPrev: $("art-prev"), backdrop: $("backdrop"), backdropPrev: $("backdrop-prev"),
    artZone: $("art-zone"), title: $("title"), sub: $("sub"), eq: $("eq-open"), mute: $("mute"),
    master: $("master"), masterNum: $("master-num"), volumeRow: $("volume-row"),
    offline: $("offline"), toast: $("toast"),
    handle: $("handle"), scrim: $("scrim"), sheet: $("sheet"),
    brightness: $("brightness"), brightnessNum: $("brightness-num"), sleepAfter: $("sleep-after"),
    sleepNow: $("sleep-now"), power: $("power"), info: $("info"), infoNote: $("info-note"),
    eqPage: $("eq"), eqClose: $("eq-close"), eqReset: $("eq-reset"), eqFor: $("eq-for"),
    eqBands: $("eq-bands"), eqGraph: $("eq-graph"), eqNote: $("eq-note"),
    modal: $("modal"), card: $("card"), cardTitle: $("card-title"), cardMessage: $("card-message"),
    cardSource: $("card-source"), cardProgress: $("card-progress"), cardBar: $("card-bar"),
    cardButtons: $("card-buttons"), sleep: $("sleep"),
    cardPinBoxes: $("card-pin-boxes"), cardPinError: $("card-pin-error"), cardPinPad: $("card-pin-pad")
};
