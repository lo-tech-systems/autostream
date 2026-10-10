// hd-eq.js: the HD page's equaliser: the response maths (the biquad and its
// magnitude, which the graph alone calls), the filters a set of sliders adds
// up to, the band labels, and the canvas graph drawn from them.

import { EQ_FILTERS, EQ_TWO_BAND, EQ_LABELS, EQ_GRAPH, signed } from "./hd-tables.js";
import { els } from "./hd-dom.js";
import { ui } from "./hd-state.js";

// ---- The equaliser's response maths ----------------------------------

// RBJ audio EQ cookbook biquad, normalised, as the appliance's monitor
// configures its filters.
function biquad(type, f0, q, gainDb, fs) {
    const A = Math.pow(10, gainDb / 40);
    const w0 = 2 * Math.PI * f0 / fs;
    const cos = Math.cos(w0);
    const alpha = Math.sin(w0) / (2 * q);
    const t = 2 * Math.sqrt(A) * alpha;
    let b0, b1, b2, a0, a1, a2;
    if (type === "peak") {
        b0 = 1 + alpha * A; b1 = -2 * cos; b2 = 1 - alpha * A;
        a0 = 1 + alpha / A; a1 = -2 * cos; a2 = 1 - alpha / A;
    } else if (type === "low_shelf") {
        b0 = A * ((A + 1) - (A - 1) * cos + t);
        b1 = 2 * A * ((A - 1) - (A + 1) * cos);
        b2 = A * ((A + 1) - (A - 1) * cos - t);
        a0 = (A + 1) + (A - 1) * cos + t;
        a1 = -2 * ((A - 1) + (A + 1) * cos);
        a2 = (A + 1) + (A - 1) * cos - t;
    } else if (type === "high_shelf") {
        b0 = A * ((A + 1) + (A - 1) * cos + t);
        b1 = -2 * A * ((A - 1) + (A + 1) * cos);
        b2 = A * ((A + 1) + (A - 1) * cos - t);
        a0 = (A + 1) - (A - 1) * cos + t;
        a1 = 2 * ((A - 1) - (A + 1) * cos);
        a2 = (A + 1) - (A - 1) * cos - t;
    } else {
        return { b0: 1, b1: 0, b2: 0, a1: 0, a2: 0 };
    }
    return { b0: b0 / a0, b1: b1 / a0, b2: b2 / a0, a1: a1 / a0, a2: a2 / a0 };
}

function magnitudeDb(c, f, fs) {
    const w = 2 * Math.PI * f / fs;
    const nr = c.b0 + c.b1 * Math.cos(w) + c.b2 * Math.cos(2 * w);
    const ni = -(c.b1 * Math.sin(w) + c.b2 * Math.sin(2 * w));
    const dr = 1 + c.a1 * Math.cos(w) + c.a2 * Math.cos(2 * w);
    const di = -(c.a1 * Math.sin(w) + c.a2 * Math.sin(2 * w));
    return 10 * Math.log10((nr * nr + ni * ni) / Math.max(dr * dr + di * di, 1e-30));
}

// The filters a set of sliders adds up to: [{ type, hz, q, gain }].
export function responseFilters(bands) {
    const out = [];
    const add = (id, hz, gain) => {
        const shape = EQ_FILTERS[id];
        if (shape) { out.push({ type: shape.type, hz: hz || shape.hz, q: shape.q, gain: gain }); }
    };
    bands.forEach((band) => {
        const parts = EQ_TWO_BAND[band.id];
        if (parts) {
            parts.forEach(([id, share]) => add(id, 0, band.gain * share));
        } else {
            add(band.id, band.hz, band.gain);
        }
    });
    return out;
}

export function eqLabel(band) {
    if (EQ_LABELS[band.id]) { return EQ_LABELS[band.id]; }
    if (!band.frequency_hz) { return band.id; }
    return band.frequency_hz >= 1000 ? band.frequency_hz / 1000 + "kHz" : band.frequency_hz + "Hz";
}

// ---- The equaliser's response graph ------------------------------------

export const graph = { key: "", frame: 0 };

export function scheduleGraph() {
    if (graph.frame) { return; }
    graph.frame = requestAnimationFrame(() => {
        graph.frame = 0;
        drawGraph();
    });
}

function drawGraph() {
    const canvas = els.eqGraph;
    const w = canvas.clientWidth;
    const h = canvas.clientHeight;
    if (!w || !h || !ui.vm) { return; }
    const G = EQ_GRAPH;
    const dpr = Math.min(window.devicePixelRatio || 1, G.maxDpr);
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    const g = canvas.getContext("2d");
    g.scale(dpr, dpr);
    const css = getComputedStyle(els.app);
    const color = (name) => css.getPropertyValue(name).trim();
    const pw = w - G.padLeft - G.padRight;
    const ph = h - G.padTop - G.padBottom;
    const fx = (f) => G.padLeft + pw * Math.log(f / G.fMin) / Math.log(G.fMax / G.fMin);
    const dy = (db) => G.padTop + ph * (G.range - Math.max(-G.range, Math.min(G.range, db))) / (2 * G.range);

    g.fillStyle = color("--color-eq-bg");
    g.fillRect(0, 0, w, h);
    g.font = "11px " + css.fontFamily;
    g.lineWidth = 1;
    G.gridDb.forEach((db) => {
        g.strokeStyle = color(db === 0 ? "--color-eq-grid-zero" : "--color-eq-grid");
        g.beginPath();
        g.moveTo(G.padLeft, dy(db));
        g.lineTo(w - G.padRight, dy(db));
        g.stroke();
        g.fillStyle = color("--color-text-dim");
        g.textAlign = "right";
        g.fillText(signed(db), G.padLeft - 6, dy(db) + 4);
    });
    let labelled = -Infinity;
    G.gridHz.forEach(([f, text]) => {
        g.strokeStyle = color("--color-eq-grid");
        g.beginPath();
        g.moveTo(fx(f), G.padTop);
        g.lineTo(fx(f), G.padTop + ph);
        g.stroke();
        // A label that would run into the one before it is left off.
        if (fx(f) - labelled < G.labelGap) { return; }
        labelled = fx(f);
        g.fillStyle = color("--color-text-dim");
        g.textAlign = f === G.fMin ? "left" : f === G.fMax ? "right" : "center";
        g.fillText(text, fx(f), h - 6);
    });

    const coeffs = ui.vm.eq.filters.map((f) => biquad(f.type, f.hz, f.q, f.gain, G.fs));
    const total = (f) => coeffs.reduce((sum, c) => sum + magnitudeDb(c, f, G.fs), 0);
    const points = [];
    for (let i = 0; i <= G.points; i++) {
        const f = G.fMin * Math.pow(G.fMax / G.fMin, i / G.points);
        points.push([fx(f), dy(total(f))]);
    }
    const accent = color("--color-accent");
    const fill = g.createLinearGradient(0, G.padTop, 0, G.padTop + ph);
    fill.addColorStop(0, "rgba(82,152,216,0.30)");
    fill.addColorStop(1, "rgba(82,152,216,0.02)");
    g.beginPath();
    g.moveTo(points[0][0], dy(0));
    points.forEach(([x, y]) => g.lineTo(x, y));
    g.lineTo(points[points.length - 1][0], dy(0));
    g.closePath();
    g.fillStyle = fill;
    g.fill();
    g.beginPath();
    points.forEach(([x, y], i) => (i ? g.lineTo(x, y) : g.moveTo(x, y)));
    g.strokeStyle = accent;
    g.lineWidth = 2.4;
    g.stroke();
    ui.vm.eq.bands.forEach((band) => {
        const f = band.hz || (EQ_TWO_BAND[band.id] ? EQ_FILTERS[EQ_TWO_BAND[band.id][0][0]].hz : 0);
        if (!f) { return; }
        g.beginPath();
        g.arc(fx(f), dy(total(f)), 4.5, 0, Math.PI * 2);
        g.fillStyle = "#fff";
        g.fill();
    });
}

if (typeof ResizeObserver === "function") {
    new ResizeObserver(() => {
        graph.key = "";
        if (ui.vm && ui.vm.eq.open) { scheduleGraph(); }
    }).observe(els.eqGraph);
}
