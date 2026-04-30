"""autostream_webui.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Web assets (e.g. CSS) to support web front-end for autostrea
"""


STYLE_CSS = """
/* ── Colour palette ─────────────────────────────────────────────────────────
   All theme-sensitive colours are defined here as CSS custom properties.
   The [data-theme="dark"] block overrides them for dark mode; every rule
   below uses var(--color-*) so no hardcoded colours appear in components.
   Status colours (danger, success, warning) are overridden in dark mode via
   --color-status-danger/success/warning.
   ── */
:root {
  /* Background layers */
  --color-bg:                #f5f5f5;
  --color-surface:           #ffffff;
  --color-surface-raised:    #f8fafb;
  --color-surface-selected:  #f1f6fc;
  --color-surface-code:      #f3f4f6;
  --color-surface-pane:      #f4f5f6;
  --color-surface-muted:     #e9ecef;
  --color-surface-pressed:   #edf2f7;
  /* Text */
  --color-text:              #333333;
  --color-text-secondary:    #555555;
  --color-text-strong:       #121212;
  --color-text-pane:         #1a1a1a;
  --color-text-dim:          #6c757d;
  --color-text-muted:        #495057;
  /* Borders */
  --color-border:            #dddddd;
  --color-border-card:       #d9dee3;
  --color-border-code:       #d1d5db;
  --color-border-nav:        #e0e0e0;
  /* Status chips */
  --color-chip-on-bg:        #d1e7dd;
  --color-chip-on-text:      #0f5132;
  --color-chip-off-bg:       #e2e3e5;
  --color-chip-off-text:     #41464b;
  --color-chip-neutral-bg:   #eceff2;
  --color-chip-neutral-text: #495057;
  /* Controls and interactive */
  --color-control-off:       #adb5bd;
  --color-toggle-on:         #198754;
  --color-nav-inactive:      #8a8a8e;
  --color-accent:            #2b80d1;
  --color-btn-bg:            #6c757d;
  /* Status (theme-invariant) */
  --color-success:           #28a745;
  --color-danger:            #c00000;
  /* Status highlights: bars, banners, danger zones (overridden in dark mode) */
  --color-status-danger:     #dc3545;
  --color-status-success:    #28a745;
  --color-status-warning:    #f0ad4e;
  /* Equaliser curve display */
  --color-eq-bg:             #e4e8ec;
  --color-eq-grid:           rgba(0,0,0,0.12);
  --color-eq-grid-zero:      rgba(0,0,0,0.30);
  --color-eq-zero-line:      rgba(0,0,0,0.20);
  color-scheme: light;
}

[data-theme="dark"] {
  /* --color-surface matches --color-bg so the container blends seamlessly
     with the page body; the logo background (#0e2841) therefore matches too.
     Cards use --color-surface-raised to remain visually distinct. */
  --color-bg:                #0e2841;
  --color-surface:           #0e2841;
  --color-surface-raised:    #1a3a58;
  --color-surface-selected:  #1e4470;
  --color-surface-code:      #132f4c;
  --color-surface-pane:      #0c2035;
  --color-surface-muted:     #1a3250;
  --color-surface-pressed:   #204870;
  --color-text:              #dce8f2;
  --color-text-secondary:    #8eacc4;
  --color-text-strong:       #edf2f8;
  --color-text-pane:         #c8daea;
  --color-text-dim:          #7a9ab8;
  --color-text-muted:        #7a9ab8;
  --color-border:            #243e58;
  --color-border-card:       #243e58;
  --color-border-code:       #2e5072;
  --color-border-nav:        #1a3250;
  --color-chip-on-bg:        #1a4a30;
  --color-chip-on-text:      #5dce84;
  --color-chip-off-bg:       #283848;
  --color-chip-off-text:     #7a9ab8;
  --color-chip-neutral-bg:   #1e3c58;
  --color-chip-neutral-text: #7a9ab8;
  --color-control-off:       #3c5a72;
  --color-toggle-on:         #28a060;
  --color-nav-inactive:      #6a8aa0;
  --color-accent:            #5298d8;
  --color-btn-bg:            #3c5a72;
  /* Status highlights: deep rose/teal/amber replacements for dark mode */
  --color-status-danger:     #B23A48;
  --color-status-success:    #2F9E7E;
  --color-status-warning:    #E0A458;
  /* Equaliser curve display */
  --color-eq-bg:             #0d1c2b;
  --color-eq-grid:           rgba(100,150,200,0.22);
  --color-eq-grid-zero:      rgba(100,150,200,0.55);
  --color-eq-zero-line:      rgba(100,150,200,0.45);
  color-scheme: dark;
}

/* Logo: show light logo by default; swap to dark logo in dark theme.
   Three-part selectors (specificity 0,3,0) beat any two-part rule such as
   .airplay-brand .banner-logo (0,2,0), preventing it from overriding display:none. */
.banner-logo-wrap .banner-logo.banner-logo-dark { display: none; }
[data-theme="dark"] .banner-logo-wrap .banner-logo.banner-logo-light { display: none; }
[data-theme="dark"] .banner-logo-wrap .banner-logo.banner-logo-dark { display: block; }

.container {
  max-width: 1000px;
  margin: 1rem auto;
  background: var(--color-surface);
  padding: 1.25rem 1.5rem 1.5rem;
  box-shadow: 0 2px 6px rgba(0,0,0,0.05);
  border-radius: 8px;
}

.status-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.75rem;
  font-size: 0.95rem;
}

.status-label {
  font-weight: 600;
  color: var(--color-text-secondary);
}

.status-pill {
  padding: 0.15rem 0.7rem;
  border-radius: 999px;
  font-weight: 600;
  font-size: 0.85rem;
}

.status-pill.status-playing {
  background: var(--color-chip-on-bg);
  color: var(--color-chip-on-text);
}

.status-pill.status-waiting {
  background: var(--color-chip-off-bg);
  color: var(--color-chip-off-text);
}

.hostname-pill {
  background: var(--color-chip-neutral-bg);
  color: var(--color-chip-neutral-text);
}

h1 {
  font-size: 1.6rem;
  margin: 0 0 0.75rem 0;
}

p {
  margin: 0.35rem 0 0.85rem 0;
}

label {
  display: block;
  margin-top: 0.75rem;
  font-size: 1rem;
}

input[type=text],
input[type=password],
input[type=number],
input[type=url],
select {
  width: 100%;
  max-width: 100%;
  padding: 0.65rem 0.7rem;      /* bigger tap target */
  margin-top: 0.25rem;
  box-sizing: border-box;
  font-size: 1rem;
  background: var(--color-surface-code);
  color: var(--color-text);
  border: 1px solid var(--color-border-code);
  border-radius: 4px;
}

fieldset {
  margin-bottom: 1.5rem;
  padding: 1rem 0.9rem 1.2rem;
  border-radius: 6px;
  border: 1px solid var(--color-border);
}

legend {
  font-weight: 600;
  padding: 0 0.25rem;
  font-size: 1.05rem;
}

.key-reveal-wrap {
  margin-top: 0.5rem;
}

.key-reveal {
  margin: 0;
  padding: 0.5rem 0.75rem;
  border-radius: 10px;
  background: var(--color-surface-code);
  border: 1px solid var(--color-border-code);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas,
               "Liberation Mono", "Courier New", monospace; /* courier-ish */
  font-size: 0.95rem;
  line-height: 1.25rem;
  white-space: pre-wrap;
  word-break: break-all;
  min-height: 1.25rem; /* so it doesn't collapse when empty */
}

.helptext {
  display: block;
  text-align:center;
  font-size: 0.9rem;
  color: var(--color-text-secondary);
  margin-top: 0.25rem;
}

.slider-value {
  display: inline-block;
  min-width: 3.5rem;
  margin-left: 0.75rem;
  font-size: 0.95rem;
  text-align: right;
}

/* Make sliders much bigger */
input[type=range] {
  width: 100%;
  margin-top: 0.5rem;
  height: 30px;                 /* overall element height */
}

/* WebKit (Safari/Chrome) slider styling */
input[type=range]::-webkit-slider-runnable-track {
  height: 10px;
  border-radius: 999px;
}

input[type=range]::-webkit-slider-thumb {
  -webkit-appearance: none;
  appearance: none;
  width: 26px;
  height: 26px;
  border-radius: 50%;
  margin-top: -8px;             /* centers thumb on track */
}

/* Firefox slider styling */
input[type=range]::-moz-range-track {
  height: 10px;
  border-radius: 999px;
}

input[type=range]::-moz-range-thumb {
  width: 26px;
  height: 26px;
  border-radius: 50%;
}

button[type=submit] {
  padding: 0.8rem 1.6rem;       /* bigger button */
  font-size: 1.05rem;
  font-weight: 600;
  background: var(--color-btn-bg);
  color: #fff;
  border-radius: 999px;
  border: none;
  cursor: pointer;
  width: 100%;
}

/* Header row above the slider */
.slider-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.35rem;   /* space between label row and slider */
  font-size: 1rem;
  font-weight: 600;
}

/* Right-aligned value */
.slider-value {
  min-width: 3rem;
  text-align: right;
  font-size: 1rem;
  color: var(--color-text);
}

.output-card {
  margin-bottom: 0.62rem;
  padding: 0.52rem 0.72rem 0.5rem;
  border-radius: 12px;
  border: 1px solid var(--color-border-card);
  background: var(--color-surface-raised);
  transition: border-color 120ms ease, background 120ms ease, box-shadow 120ms ease;
}

.output-card-on {
  border-color: var(--color-accent);
  background: var(--color-surface-selected);
}

.output-card-off {
  border-color: var(--color-border-card);
  background: var(--color-surface-raised);
}

.output-card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.52rem;
}

.output-card-meta {
  display: grid;
  grid-template-columns: repeat(2, max-content);
  align-items: center;
  gap: 0.22rem 0.4rem;
  min-width: 0;
  flex: 1 1 auto;
}

.output-card-name {
  grid-column: 1 / -1;
  font-size: 0.99rem;
  font-weight: 700;
  color: var(--color-text-strong);
  line-height: 1.12;
  overflow-wrap: anywhere;
  word-break: break-word;
}

.output-card-default {
  display: inline-block;
  padding: 0.06rem 0.4rem;
  border-radius: 999px;
  background: var(--color-chip-neutral-bg);
  color: var(--color-chip-neutral-text);
  font-size: 0.68rem;
  font-weight: 700;
  white-space: nowrap;
}

.output-state-chip {
  display: inline-block;
  padding: 0.06rem 0.45rem;
  border-radius: 999px;
  font-size: 0.68rem;
  font-weight: 700;
  white-space: nowrap;
}

.output-state-chip.on {
  background: var(--color-chip-on-bg);
  color: var(--color-chip-on-text);
}

.output-state-chip.off {
  background: var(--color-chip-off-bg);
  color: var(--color-chip-off-text);
}

.output-toggle {
  margin: 0;
  display: inline-flex;
  align-items: center;
}

.output-toggle input {
  position: absolute;
  opacity: 0;
  width: 0;
  height: 0;
}

.output-toggle .switch {
  position: relative;
  width: 48px;
  height: 27px;
  border-radius: 999px;
  background: var(--color-control-off);
  transition: background 140ms ease;
}

.output-toggle .switch::after {
  content: "";
  position: absolute;
  top: 2.5px;
  left: 2.5px;
  width: 22px;
  height: 22px;
  border-radius: 50%;
  background: #fff;
  box-shadow: 0 1px 3px rgba(0,0,0,0.2);
  transition: transform 140ms ease;
}

.output-toggle input:checked + .switch {
  background: var(--color-toggle-on);
}

.output-toggle input:checked + .switch::after {
  transform: translateX(21px);
}

.output-slider-wrap {
  margin-top: 0.18rem;
}

.output-slider-wrap .slider-header {
  margin-bottom: 0.08rem;
  font-size: 0.9rem;
}

.output-slider-wrap input[type=range] {
  margin-top: 0.1rem;
  height: 20px;
}

/* Slider stands alone on its own row */
input[type=range] {
  display: block;
  width: 100%;
}

button[type=submit]:active {
  transform: translateY(1px);
}

/* Reusable pill button (matches existing UI buttons) */
.pill-btn {
  display: inline-block;
  padding: 0.6rem 1.2rem;
  font-size: 1rem;
  line-height: 1;
  font-weight: 600;
  background: var(--color-btn-bg);
  color: #fff;
  border-radius: 999px;
  border: none;
  cursor: pointer;
  box-shadow: 0 2px 6px rgba(0,0,0,0.05);
  text-decoration: none;
}

.pill-btn-disabled {
  display: inline-block;
  padding: 0.6rem 1.2rem;
  font-size: 1rem;
  font-weight: 600;
  background: var(--color-btn-bg);
  cursor: not-allowed;
  color: #fff;
  border-radius: 999px;
  border: none;
  box-shadow: 0 2px 6px rgba(0,0,0,0.05);
  text-decoration: none;
}
.pill-btn.small {
  padding: 0.5rem 1.0rem;   /* slightly smaller */
  font-size: 0.95rem;
  font-weight: 600;
}

.pill-btn:active {
  transform: translateY(1px);
}

.pill-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  box-shadow: none;
}

.pill-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5em;
  margin-bottom: 0.75em;
}

.banner-logo-wrap {
  width: 100%;
  text-align: center;
  margin-bottom: 1rem;
}

.banner-logo {
  width: 100%;
  max-width: 100%;
  height: auto;
  display: block;
  margin: 0;
}

.airplay-masthead {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 0.9rem;
  margin-bottom: 1rem;
}

.airplay-brand {
  flex: 1 1 auto;
  min-width: 0;
}

.airplay-brand .banner-logo-wrap {
  margin-bottom: 0;
  text-align: left;
}

.airplay-brand .banner-logo {
  width: 100%;
  max-width: 100%;
  height: auto;
  display: block;
  margin: 0;
}

.airplay-top-controls {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.6rem;
  margin-bottom: 0.75rem;
}

.airplay-top-controls .status-pill {
  flex: 0 0 auto;
}

/* ── Now Playing card ────────────────────────────────────────────────────── */
.now-playing-card {
  margin-bottom: 0.75rem;
  padding: 0.65rem 0.75rem 0.6rem;
  border-radius: 12px;
  border: 2px solid var(--color-accent);
  background: var(--color-surface-selected);
}
.now-playing-hdr {
  font-size: 0.72rem;
  font-weight: 600;
  color: var(--color-text-dim);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  margin-bottom: 0.45rem;
}
.now-playing-body {
  display: flex;
  align-items: center;
  gap: 0.7rem;
  margin-bottom: 0.45rem;
}
.now-playing-icon {
  flex: 0 0 auto;
  width: 38px;
  height: 38px;
  color: var(--color-text);
}
.now-playing-icon svg { width: 100%; height: 100%; }
.now-playing-meta {
  flex: 1 1 auto;
  min-width: 0;
}
.now-playing-name {
  font-size: 0.95rem;
  font-weight: 600;
  color: var(--color-text-strong);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.now-playing-signal {
  font-size: 0.78rem;
  color: var(--color-text-dim);
  margin-top: 0.1rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.now-playing-playing-to {
  font-size: 0.8rem;
  color: var(--color-text-secondary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.vu-meter {
  display: flex;
  flex-direction: column-reverse;
  gap: 2px;
  width: 10px;
  height: 48px;
  flex-shrink: 0;
}
.vu-bar {
  width: 100%;
  flex: 1;
  border-radius: 1px;
  background: var(--color-surface-muted);
  transition: background-color 0.12s ease-out;
}
.now-playing-card.np-ready {
  border-color: var(--color-border-card);
  border-width: 1px;
  background: var(--color-surface-raised);
  opacity: 0.45;
}
.now-playing-card.np-ready .now-playing-body {
  display: none;
}
.np-volume-wrap {
  margin-top: 0.5rem;
  padding-top: 0.45rem;
  border-top: 1px solid var(--color-border);
}
.np-volume-wrap .slider-header {
  font-size: 0.9rem;
  margin-bottom: 0.08rem;
}
.np-volume-wrap input[type=range] {
  margin-top: 0.1rem;
  height: 20px;
}
.np-volume-wrap.master-volume-inactive {
  opacity: 0.5;
}

/* iOS-style storage bar */
.storage-bar {
  width: 100%;
  height: 14px;
  background: var(--color-surface-muted);
  border-radius: 999px;
  overflow: hidden;
  box-shadow: inset 0 1px 2px rgba(0,0,0,0.08);
  margin: 0 0 0 0;
}

.storage-bar .used {
  height: 100%;
  width: 0%;
  background: var(--color-success);
  border-radius: 999px;
  transition: width 0.3s ease;
}

/* Status-driven bar colours — set via data-status="healthy|warning|critical" */
.storage-bar .used[data-status="healthy"]  { background: var(--color-status-success); }
.storage-bar .used[data-status="warning"]  { background: var(--color-status-warning); }
.storage-bar .used[data-status="critical"] { background: var(--color-status-danger);  }

.storage-meta {
  display: flex;
  justify-content: space-between;
  gap: 0.75rem;
  flex-wrap: wrap;
  font-size: 0.95rem;
}

.bar-label {
  display: flex;
  justify-content: space-between;
  gap: 0.75rem;
  flex-wrap: wrap;
  font-size: 0.95rem;
  margin-top: 0.25rem;
}

.licence-pane {
  background: var(--color-surface-pane);
  color: var(--color-text-pane);
  padding: 0.75rem;
  border-radius: 6px;
  font-size: 0.85rem;
  line-height: 1.4;
  max-height: 45vh;
  overflow: auto;
}


/* Update buttons row: left/right within the pane */
.update-row {
  margin-top: 0.5rem;
  display: flex;
  justify-content: space-between; /* left + right */
  align-items: center;
  gap: 0.75rem;
  flex-wrap: wrap;                /* wraps neatly on small screens */
}

.update-row .pill-btn {
  flex: 1 1 12rem;                /* good tap targets, equal-ish width */
}

code {
  background: #0f0f0f;
  padding: 0 0.25rem;
  border-radius: 3px;
}

/* ── Equaliser page ─────────────────────────────────────────────────────── */
.eq-page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1rem;
}

.eq-page-header h1 {
  margin: 0;
}

.eq-back-btn {
  font-size: 1.4rem;
  font-weight: 700;
  color: var(--color-text);
  text-decoration: none;
  line-height: 1;
  padding: 0.1rem 0.2rem;
}

.eq-section {
  margin-bottom: 1.25rem;
  padding: 1rem 0.9rem 1.1rem;
  border-radius: 8px;
  border: 1px solid var(--color-border);
  background: var(--color-surface-raised);
}

.eq-section-title {
  font-weight: 700;
  font-size: 1.05rem;
  margin-bottom: 0.85rem;
}

.eq-bands-wrap {
  display: flex;
  align-items: stretch;
  gap: 0.4rem;
}

.eq-scale {
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  font-size: 0.78rem;
  color: var(--color-text-secondary);
  padding-top: 1.4rem;     /* aligns top label with slider top (below freq label) */
  padding-bottom: 1.6rem;  /* aligns bottom label with slider bottom (above val label) */
  min-width: 2rem;
  text-align: right;
  padding-right: 0.3rem;
}

.eq-bands-row {
  position: relative;
  isolation: isolate;
  display: flex;
  flex: 1;
  justify-content: space-around;
  gap: 0.15rem;
}

/* Dotted 0 dB reference line across all band sliders.
   top = freq-label line-height (0.75rem × 1.2) + its margin-bottom (0.3rem)
       + half the slider height (75px). */
.eq-bands-row::after {
  content: '';
  position: absolute;
  left: 0;
  right: 0;
  top: calc(0.9rem + 0.3rem + 75px);
  border-top: 1px dashed var(--color-eq-zero-line);
  pointer-events: none;
  z-index: -1;
}

.eq-band {
  display: flex;
  flex-direction: column;
  align-items: center;
  flex: 1;
}

/* Vertical range slider for EQ bands */
.eq-band-slider {
  writing-mode: vertical-lr;
  direction: rtl;
  width: 30px !important;
  height: 150px !important;
  margin: 0 !important;
  padding: 0;
  cursor: pointer;
  display: block;
}

/* Re-centre WebKit thumb on vertical track */
.eq-band-slider::-webkit-slider-thumb {
  margin-top: -8px;
}

.eq-band-freq {
  font-size: 0.75rem;
  color: var(--color-text-secondary);
  text-align: center;
  margin-bottom: 0.3rem;
  white-space: nowrap;
}

.eq-band-val {
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--color-text);
  text-align: center;
  min-width: 2.8rem;
  margin-top: 0.1rem;
}

.eq-auto-trim-row {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 0.75rem;
}

.eq-auto-trim-labels {
  flex: 1 1 auto;
  min-width: 0;
}

.eq-auto-trim-title {
  font-weight: 600;
  font-size: 1rem;
}

.eq-auto-trim-subtitle {
  font-size: 0.88rem;
  color: var(--color-text-secondary);
  margin-top: 0.15rem;
}

.eq-gain-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: 1rem;
  margin-bottom: 0.35rem;
}

.eq-gain-label {
  font-weight: 600;
  font-size: 1rem;
}

.eq-gain-value {
  font-weight: 600;
  font-size: 1rem;
}

.eq-gain-ticks {
  display: flex;
  justify-content: space-between;
  font-size: 0.78rem;
  color: var(--color-text-secondary);
  margin-top: 0.2rem;
}

/* Equaliser frequency-response SVG curve */
.eq-curve-wrap {
  margin-bottom: 0.75rem;
  border-radius: 6px;
  overflow: hidden;
  line-height: 0;   /* removes inline-block gap beneath SVG */
}

.eq-curve-svg {
  width: 100%;
  height: auto;
  display: block;
}

/* SVG element classes — used by inline SVG inside the EQ card */
.eq-curve-bg   { fill: var(--color-eq-bg); }
.eq-grid       { stroke: var(--color-eq-grid);      stroke-width: 0.7; fill: none; }
.eq-grid-zero  { stroke: var(--color-eq-grid-zero); stroke-width: 0.9;
                 stroke-dasharray: 4 3;              fill: none; }
.eq-curve-path { stroke: var(--color-accent);       stroke-width: 1.8; fill: none; }
.eq-handle     { fill: var(--color-accent);
                 stroke: rgba(255,255,255,0.75);     stroke-width: 0.8; }

@media (min-width: 600px) {
  .container { margin: 2rem auto; }  /* keep the roomy desktop spacing */
  button[type=submit] { width: auto; }
}

@media (max-width: 520px) {
  .airplay-masthead {
    align-items: center;
  }
}

#a2hs-prompt {
  position: fixed;
  left: 0;
  right: 0;
  bottom: 0;
  z-index: 9999;
  background: rgba(0, 0, 0, 0.55);
  padding: 0.5rem;
}

#a2hs-inner {
  max-width: 480px;
  margin: 0 auto;
  background: var(--color-surface);
  border-radius: 1rem;
  padding: 0.9rem 1rem;
  box-shadow: 0 4px 16px rgba(0,0,0,0.2);
  font-size: 0.95rem;
}

#a2hs-inner strong {
  display: block;
  margin-bottom: 0.25rem;
}

body {
  margin: 0 !important;
  padding: 0 !important;   /* critical for iOS fixed banner */
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: var(--color-bg);
  font-size: 18px;
}

#red-banner {
  position: fixed !important;
  top: 0 !important;
  left: 0 !important;
  right: 0 !important;
  background: var(--color-status-danger);
  color: #ffffff;
  text-align: center;
  font-weight: 700;
  padding: 0.6rem 1rem !important;
  padding-top: calc(0.6rem + constant(safe-area-inset-top)) !important;
  padding-top: calc(0.6rem + env(safe-area-inset-top)) !important;
  z-index: 10000;
}
#red-banner-spacer {
  height: calc(3rem + constant(safe-area-inset-top));
  height: calc(3rem + env(safe-area-inset-top));
}
#green-banner {
  position: fixed !important;
  will-change: transform;
  transform: translateY(0);
  transition: transform 320ms ease;
  top: 0 !important;
  left: 0 !important;
  right: 0 !important;
  background: var(--color-status-success);
  color: #ffffff;
  text-align: center;
  font-weight: 700;
  padding: 0.6rem 1rem !important;
  padding-top: calc(0.6rem + constant(safe-area-inset-top)) !important;
  padding-top: calc(0.6rem + env(safe-area-inset-top)) !important;
  z-index: 10000;
}
#green-banner-spacer {
  height: calc(3rem + constant(safe-area-inset-top));
  height: calc(3rem + env(safe-area-inset-top));
  transition: height 320ms ease;
  overflow: hidden;
}
/* Fade-out support for flash (green) banner */
.flash-hidden {
  opacity: 0;
  pointer-events: none;
}
.flash-spacer-hidden {
  height: 0 !important;
}
.flash-rollup {
  /* JS sets --flash-rollup-y to the banner height (px) */
  transform: translateY(calc(-1 * var(--flash-rollup-y, 0px)));
}

/* ── Setup page: slide-panel navigation (post-config only) ── */
.setup-slide-viewport {
  overflow: hidden;
  width: 100%;
}
.setup-slide-track {
  display: flex;
  width: 300%;
  transition: transform 0.35s cubic-bezier(0.4, 0, 0.2, 1);
}
.setup-slide-track.panel-open {
  transform: translateX(-33.333%);
}
.setup-slide-track.preamp-open {
  transform: translateX(-66.667%);
}
.setup-slide-list,
.setup-slide-panels,
.setup-slide-preamp {
  width: 33.333%;
  flex-shrink: 0;
  min-width: 0;
}
.setup-list-card {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.85rem 0.9rem;
  margin-bottom: 0.62rem;
  border-radius: 12px;
  border: 1px solid var(--color-border-card);
  background: var(--color-surface-raised);
  cursor: pointer;
  user-select: none;
  -webkit-tap-highlight-color: transparent;
  transition: background 120ms ease;
  gap: 0.5rem;
}
.setup-list-card:active {
  background: var(--color-surface-pressed);
}
.setup-list-card-body {
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
  min-width: 0;
  flex: 1 1 auto;
}
.setup-list-card-title {
  font-weight: 700;
  font-size: 1rem;
  color: var(--color-text-strong);
  line-height: 1.2;
}
.setup-list-card-sub {
  font-size: 0.82rem;
  color: var(--color-text-dim);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.setup-list-chevron {
  font-size: 1.4rem;
  color: var(--color-control-off);
  flex-shrink: 0;
  line-height: 1;
}
.setup-detail-panel {
  display: none;
}
.setup-detail-panel.active {
  display: block;
}
.setup-preamp-panel {
  display: none;
}
.setup-preamp-panel.active {
  display: block;
}
.setup-detail-back {
  margin-bottom: 0.75rem;
}

/* ── Nav bar bottom clearance (only when nav bar is present) ── */
.setup-customise-row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.setup-customise-row > span:last-child {
  font-size: 0.94rem;
  line-height: 1.25;
}

body.has-bottom-nav .container {
  padding-bottom: 5rem;
}

/* ── Bottom navigation bar ── */
.bottom-nav {
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  background: var(--color-surface);
  border-top: 1px solid var(--color-border-nav);
  display: flex;
  z-index: 1000;
  padding-bottom: constant(safe-area-inset-bottom);
  padding-bottom: env(safe-area-inset-bottom);
}
.nav-tab {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 0.55rem 0 0.5rem;
  color: var(--color-nav-inactive);
  text-decoration: none;
  font-size: 0.7rem;
  font-weight: 500;
  gap: 0.18rem;
  -webkit-tap-highlight-color: transparent;
}
.nav-tab svg {
  width: 24px;
  height: 24px;
}
.nav-tab-active {
  color: var(--color-accent);
  box-shadow: inset 0 3px 0 var(--color-accent);
}
.nav-tab-warn {
  color: var(--color-danger);
}

/* ── Mobile: match body background to --color-surface so no gap shows
   above or below the content container.  Dark mode already has
   --color-bg == --color-surface; this brings light mode into line.
   Placed last so it overrides the base body { background } rule above. ── */
@media (max-width: 599px) {
  body {
    background: var(--color-surface);
  }
  .container {
    margin: 0;
    border-radius: 0;
    box-shadow: none;
  }
}
"""

BANNER_LOGO_HTML = """
  <div class="banner-logo-wrap">
    <img src="/autostream-badge.png" alt="AutoStream" class="banner-logo banner-logo-light">
    <img src="/autostream-badge-dark.png" alt="AutoStream" class="banner-logo banner-logo-dark">
  </div>
"""

BANNER_DISMISS_SCRIPT = """
<script>
document.addEventListener("DOMContentLoaded", () => {
  const banner = document.getElementById("green-banner");
  if (!banner) return;

  const spacer = document.getElementById("green-banner-spacer");

  window.setTimeout(() => {
    // Measure actual rendered height (includes iOS safe-area padding).
    const h = Math.ceil(banner.getBoundingClientRect().height);

    // Tell CSS how far to translate.
    banner.style.setProperty("--flash-rollup-y", h + "px");

    // Trigger animations
    banner.classList.add("flash-rollup");
    if (spacer) spacer.classList.add("flash-spacer-hidden");

    // After animation completes, remove from layout completely.
    window.setTimeout(() => {
      banner.style.display = "none";
      if (spacer) spacer.style.display = "none";
    }, 400);
  }, 5000);
});
</script>
"""

# Backward-compatible alias used by all pages except the home page.
BANNER_HTML = BANNER_LOGO_HTML + BANNER_DISMISS_SCRIPT


LICENSE_BANNER_CSS = ""

VIEWPORT_META = '<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">'

COMMON_MODAL_CSS = """
  .modal-overlay{position:fixed;inset:0;display:none;align-items:center;justify-content:center;background:rgba(0,0,0,.45);z-index:9999;padding:1.25rem;--modal-primary-bg:var(--color-btn-bg);--modal-primary-text:#fff;--modal-secondary-bg:var(--color-surface-muted);--modal-secondary-text:var(--color-text);}
  .modal-overlay.show{display:flex;}
  [data-theme="dark"] .modal-overlay{--modal-primary-bg:var(--color-btn-bg);--modal-primary-text:#fff;--modal-secondary-bg:var(--color-surface-muted);--modal-secondary-text:var(--color-text-strong);}
  .modal-panel{width:min(var(--modal-width,22rem),100%);background:var(--modal-bg,var(--color-surface));border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,.25);overflow:hidden;}
  .modal-hdr{padding:0.9rem 1rem;border-bottom:1px solid var(--color-border-nav);font-weight:700;color:var(--modal-title-color,var(--color-text-strong));}
  .modal-bd{padding:1rem;}
  .modal-bd p{margin:0 0 .75rem 0;}
  .modal-bd input{width:100%;font-size:1.2rem;padding:.65rem .75rem;border:1px solid var(--color-border-code);border-radius:12px;outline:none;}
  .modal-ft{display:flex;gap:.75rem;padding:0.9rem 1rem;border-top:1px solid var(--color-border-nav);}
  .modal-btn{flex:1;border:none;border-radius:999px;padding:.8rem .9rem;font-weight:700;font-size:1rem;cursor:pointer;box-shadow:0 2px 6px rgba(0,0,0,0.05);}
  .modal-btn:disabled{opacity:0.65;cursor:not-allowed;box-shadow:none;}
  .modal-btn-primary{background:var(--modal-primary-bg);color:var(--modal-primary-text);}
  .modal-btn-secondary{background:var(--modal-secondary-bg);color:var(--modal-secondary-text);}
  .modal-btn-danger{background:var(--color-status-danger);color:#fff;}
"""

PIN_MODAL_CSS = """
  #pinModal .modal-panel{--modal-width:22rem;}
"""


A2HS_PROMPT_HTML = """
  <div id="a2hs-prompt" style="display:none;">
    <div id="a2hs-inner">
      <strong>autostream works like an app!</strong>
      <p>
        For easier access, add autostream to your home screen. Hit '...' below, then choose <b>Share</b>,
        then scroll down and chose <b>Add to Home Screen</b>.
      </p>
      <button type="button" id="a2hs-close">Got it</button>
    </div>
  </div>
"""

A2HS_SCRIPT = """
<script>
(function () {
  function setupA2HS() {
    // Detect iOS
    var ua = window.navigator.userAgent || "";
    var isIOS = /iphone|ipad|ipod/i.test(ua);

    // Detect if already running as a Home Screen app / standalone
    var isInStandalone =
      (window.navigator.standalone === true) ||
      (window.matchMedia && window.matchMedia("(display-mode: standalone)").matches);

    // Debug log
    try {
      console.log("A2HS check:", {
        ua: ua,
        isIOS: isIOS,
        isInStandalone: isInStandalone
      });
    } catch (e) {}

    // If not iOS, or already installed as an "app", don't show
    if (!isIOS || isInStandalone) {
      return;
    }

    // --- Once-per-day logic ---
    var now = Date.now();
    var lastShown = 0;
    try {
      lastShown = parseInt(localStorage.getItem("a2hs-last-shown") || "0", 10);
    } catch (e) {}

    var ONE_DAY = 24 * 60 * 60 * 1000;

    if (lastShown && (now - lastShown) < ONE_DAY) {
      return; // Already shown within 24 hours
    }

    var prompt = document.getElementById("a2hs-prompt");
    var closeBtn = document.getElementById("a2hs-close");

    if (!prompt || !closeBtn) {
      return;
    }

    prompt.style.display = "block";

    try {
      localStorage.setItem("a2hs-last-shown", String(now));
    } catch (e) {}

    closeBtn.addEventListener("click", function () {
      prompt.style.display = "none";
    });
  }

  // Run after DOM is ready so #a2hs-prompt exists even if script is in <head>
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", setupA2HS);
  } else {
    setupA2HS();
  }
})();
</script>
"""

# ── Bottom nav icons (Feather-style inline SVG) ──────────────────────────────

NAV_ICON_HOME = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M3 9.5L12 3l9 6.5V20a1 1 0 01-1 1H4a1 1 0 01-1-1V9.5z"/>'
    '<path d="M9 21V12h6v9"/>'
    '</svg>'
)

NAV_ICON_SETUP = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<circle cx="12" cy="12" r="3"/>'
    '<path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0'
    'l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09'
    'A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06'
    'A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9'
    'a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68'
    'a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33'
    'l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21'
    'a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/>'
    '</svg>'
)

NAV_ICON_LOGS = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<line x1="8" y1="6" x2="21" y2="6"/>'
    '<line x1="8" y1="12" x2="21" y2="12"/>'
    '<line x1="8" y1="18" x2="21" y2="18"/>'
    '<line x1="3" y1="6" x2="3.01" y2="6"/>'
    '<line x1="3" y1="12" x2="3.01" y2="12"/>'
    '<line x1="3" y1="18" x2="3.01" y2="18"/>'
    '</svg>'
)

NAV_ICON_ABOUT = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<circle cx="12" cy="12" r="10"/>'
    '<line x1="12" y1="16" x2="12" y2="12"/>'
    '<line x1="12" y1="8" x2="12.01" y2="8"/>'
    '</svg>'
)

NAV_ICON_EQUALISER = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<line x1="4" y1="21" x2="4" y2="14"/>'
    '<line x1="4" y1="10" x2="4" y2="3"/>'
    '<line x1="12" y1="21" x2="12" y2="12"/>'
    '<line x1="12" y1="8" x2="12" y2="3"/>'
    '<line x1="20" y1="21" x2="20" y2="16"/>'
    '<line x1="20" y1="12" x2="20" y2="3"/>'
    '<line x1="1" y1="14" x2="7" y2="14"/>'
    '<line x1="9" y1="8" x2="15" y2="8"/>'
    '<line x1="17" y1="16" x2="23" y2="16"/>'
    '</svg>'
)

NAV_ICON_SERVICE = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77'
    'a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91'
    'a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>'
    '</svg>'
)

# ── Input type icons (Now Playing card) ──────────────────────────────────────

ICON_TURNTABLE = (
    '<svg viewBox="0 0 44 44" fill="none" xmlns="http://www.w3.org/2000/svg">'
    # Rounded-square frame
    '<rect x="2" y="2" width="40" height="40" rx="7"'
    ' stroke="var(--color-accent)" stroke-width="1.5"/>'
    # Record outer rim
    '<circle cx="19" cy="23" r="13"'
    ' stroke="var(--color-accent)" stroke-width="1.5"/>'
    # Record groove ring (subtle)
    '<circle cx="19" cy="23" r="8"'
    ' stroke="var(--color-accent)" stroke-width="1" opacity="0.5"/>'
    # Label area
    '<circle cx="19" cy="23" r="4.5"'
    ' stroke="var(--color-accent)" stroke-width="1.2"/>'
    # Centre spindle (filled dot)
    '<circle cx="19" cy="23" r="1.5" fill="var(--color-accent)"/>'
    # Tonearm pivot (filled dot, upper right)
    '<circle cx="37" cy="8" r="2.5" fill="var(--color-accent)"/>'
    # Tonearm body
    '<line x1="36" y1="10" x2="29" y2="17"'
    ' stroke="var(--color-accent)" stroke-width="2" stroke-linecap="round"/>'
    # Headshell
    '<line x1="29" y1="17" x2="26.5" y2="14.5"'
    ' stroke="var(--color-accent)" stroke-width="1.5" stroke-linecap="round"/>'
    '</svg>'
)

ICON_LINE_LEVEL = (
    '<svg viewBox="0 0 44 44" fill="none" xmlns="http://www.w3.org/2000/svg">'
    '<rect x="10" y="4" width="9" height="24" rx="4.5" fill="currentColor" opacity="0.85"/>'
    '<rect x="12.5" y="26" width="4" height="8" rx="2" fill="currentColor" opacity="0.75"/>'
    '<circle cx="14.5" cy="37" r="3" fill="currentColor"/>'
    '<rect x="25" y="4" width="9" height="24" rx="4.5" fill="#f47320" opacity="0.9"/>'
    '<rect x="27.5" y="26" width="4" height="8" rx="2" fill="#f47320" opacity="0.8"/>'
    '<circle cx="29.5" cy="37" r="3" fill="#f47320"/>'
    '</svg>'
)


# -----------------------------------------------------------------------------
# Service page CSS and JavaScript
# Exported for use by autostream_webui_page_service.
# -----------------------------------------------------------------------------

SERVICE_CSS = (
    ".service-slide-viewport { overflow: hidden; width: 100%; }\n"
    ".service-slide-track { display: flex; width: 200%;"
    " transition: transform 0.35s cubic-bezier(0.4, 0, 0.2, 1); }\n"
    ".service-slide-track.panel-detail { transform: translateX(-50%); }\n"
    ".service-slide-list, .service-slide-detail"
    " { width: 50%; flex-shrink: 0; min-width: 0; }\n"
    ".service-divider { border: none; border-top: 1px solid var(--color-border-nav); margin: 0.4rem 0; }\n"
    + COMMON_MODAL_CSS
)

# Plain string — no Python substitutions. CSRF token is read from the DOM.
#
# Display values (bar percentages, remaining text, dates, card subtitles) are
# computed server-side in autostream_webui_service_schema and returned in API
# responses as a `display` dict. The JS functions below are thin DOM applicators
# only — no business logic or threshold recalculation here.
#   _applyHoursDisplay(d, item, idx)  — applies hours display dict to DOM
#   _applyTimeDisplay(d, item, idx)   — applies time display dict to DOM
#   _applyCardState(d, item, idx)     — updates list-card subtitle and warn styling
#   _applyDisplay(display, fieldName) — parses field name, dispatches to all three
SERVICE_JS = """
var _csrfToken = document.getElementById('_csrfField').value;

// Per-field state for leading+trailing throttle auto-save.
// Each entry: {timer, ctrl, pending} where pending=null means no trailing call queued.
var _autoSaveState = {};

function openServiceDetail(item, idx) {
  document.querySelectorAll('.service-slide-detail .setup-detail-panel').forEach(function(p) {
    p.classList.remove('active');
  });
  var panel = document.getElementById('service-detail-' + item + '-' + idx);
  if (panel) panel.classList.add('active');
  document.getElementById('serviceSlideTrack').classList.add('panel-detail');
  window.scrollTo(0, 0);
}

function closeServiceDetail() {
  document.getElementById('serviceSlideTrack').classList.remove('panel-detail');
  window.scrollTo(0, 0);
}

function _showSaveError(fieldName) {
  var sel = document.querySelector('[name="' + fieldName + '"]');
  if (!sel) return;
  var err = document.createElement('span');
  err.textContent = ' Save failed';
  err.style.cssText = 'color:var(--color-status-danger);font-size:0.85rem;';
  sel.parentNode.appendChild(err);
  setTimeout(function() { if (err.parentNode) err.parentNode.removeChild(err); }, 4000);
}

function _fireSave(name, value) {
  var s = _autoSaveState[name];
  if (!s) return;
  if (s.ctrl) { s.ctrl.abort(); }
  var ctrl = new AbortController();
  s.ctrl = ctrl;
  fetch('/api/service/config', {
    method: 'POST',
    credentials: 'same-origin',
    signal: ctrl.signal,
    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': _csrfToken},
    body: JSON.stringify({field: name, value: value})
  }).then(function(r) { return r.json(); }).then(function(d) {
    if (s.ctrl === ctrl) s.ctrl = null;
    if (!d.ok) { _showSaveError(name); return; }
    if (d.display) { _applyDisplay(d.display, name); }
  }).catch(function(e) {
    if (e.name !== 'AbortError') { _showSaveError(name); }
  });
}

function _autoSaveField(name, value) {
  var s = _autoSaveState[name];
  if (!s) {
    // No suppress window active: fire immediately (leading edge) and open a 300 ms window.
    _autoSaveState[name] = {timer: null, ctrl: null, pending: null};
    s = _autoSaveState[name];
    _fireSave(name, value);
    s.timer = setTimeout(function() {
      var pending = s.pending;
      s.timer = null;
      s.pending = null;
      delete _autoSaveState[name];
      // Trailing call: if a further change arrived during the window, fire it now.
      if (pending !== null) { _autoSaveField(name, pending); }
    }, 300);
  } else {
    // Within suppress window: record latest value for the trailing call.
    s.pending = value;
  }
}

function _applyHoursDisplay(d, item, idx) {
  var liveDiv = document.getElementById(item + '-hours-live-' + idx);
  if (!d.hours_live) {
    if (liveDiv) liveDiv.style.display = 'none';
    return;
  }
  if (liveDiv) liveDiv.style.display = '';
  var el;
  el = document.getElementById(item + '-hours-bar-pct-' + idx);
  if (el) el.textContent = d.hours_bar_pct + '%';
  el = document.getElementById(item + '-hours-bar-fill-' + idx);
  if (el) { el.style.width = d.hours_bar_pct + '%'; el.setAttribute('data-status', d.hours_bar_status); }
  el = document.getElementById(item + '-hours-used-val-' + idx);
  if (el) el.textContent = d.hours_used;
  el = document.getElementById(item + '-hours-remaining-val-' + idx);
  if (el) { el.textContent = d.hours_remaining; el.style.color = d.hours_remaining_warn ? 'var(--color-status-danger)' : ''; }
}

function _applyTimeDisplay(d, item, idx) {
  var liveDiv = document.getElementById(item + '-time-live-' + idx);
  if (!d.time_live) {
    if (liveDiv) liveDiv.style.display = 'none';
    return;
  }
  if (liveDiv) liveDiv.style.display = '';
  var el;
  el = document.getElementById(item + '-time-bar-pct-' + idx);
  if (el) el.textContent = d.time_bar_pct + '%';
  el = document.getElementById(item + '-time-bar-fill-' + idx);
  if (el) { el.style.width = d.time_bar_pct + '%'; el.setAttribute('data-status', d.time_bar_status); }
  el = document.getElementById(item + '-time-age-val-' + idx);
  if (el) el.textContent = d.age;
  el = document.getElementById(item + '-time-remaining-val-' + idx);
  if (el) { el.textContent = d.remaining; el.style.color = d.remaining_warn ? 'var(--color-status-danger)' : ''; }
  el = document.getElementById(item + '-time-due-val-' + idx);
  if (el) el.textContent = d.due;
}

function _applyCardState(d, item, idx) {
  if (d.card_sub === undefined) return;
  var card = document.getElementById('svc-list-card-' + item + '-' + idx);
  if (!card) return;
  var warn = !!d.card_warn;
  card.style.borderColor = warn ? 'var(--color-status-danger)' : '';
  var t = card.querySelector('.setup-list-card-title');
  if (t) t.style.color = warn ? 'var(--color-status-danger)' : '';
  var c = card.querySelector('.setup-list-chevron');
  if (c) c.style.color = warn ? 'var(--color-status-danger)' : '';
  var s = card.querySelector('.setup-list-card-sub');
  if (s) s.textContent = d.card_sub;
}

function _applyDisplay(display, fieldName) {
  // fieldName: "service_{item}_life_{hours|years}_input{idx}"
  var m = fieldName.match(/^service_(\\w+)_life_(?:hours|years)_input(\\d+)$/);
  if (!m) return;
  var item = m[1], idx = parseInt(m[2], 10);
  if (display.hours_live !== undefined) { _applyHoursDisplay(display, item, idx); }
  if (display.time_live  !== undefined) { _applyTimeDisplay(display, item, idx); }
  _applyCardState(display, item, idx);
}

function _updateResetBtnState(item, idx) {
  var hSel = document.querySelector('[name="service_' + item + '_life_hours_input' + idx + '"]');
  var ySel = document.querySelector('[name="service_' + item + '_life_years_input' + idx + '"]');
  var btn = document.getElementById(item + '-reset-btn-' + idx);
  if (!btn) return;
  var hOff = !hSel || parseInt(hSel.value, 10) === 0;
  var yOff = !ySel || parseInt(ySel.value, 10) === 0;
  btn.disabled = hOff && yOff;
}

function _showServiceConfirm(msg) {
  return new Promise(function(resolve) {
    var m = document.getElementById('svcConfirmModal');
    var title = document.getElementById('svcConfirmTitle');
    var btnOk = document.getElementById('svcConfirmOk');
    var btnCancel = document.getElementById('svcConfirmCancel');
    if (!m || !btnOk || !btnCancel) { resolve(true); return; }
    if (title) title.textContent = msg;
    m.classList.add('show');
    var cleanup = function(val) {
      m.classList.remove('show');
      btnOk.onclick = null; btnCancel.onclick = null;
      resolve(val);
    };
    btnCancel.onclick = function() { cleanup(false); };
    btnOk.onclick    = function() { cleanup(true);  };
  });
}

function doServiceReset(item, idx) {
  var labels = {
    stylus:  'Mark stylus as changed?',
    belt:    'Mark drive belt as replaced?',
    bearing: 'Mark bearing as oiled?'
  };
  var msg = labels[item] || 'Confirm reset?';
  _showServiceConfirm(msg).then(function(confirmed) {
    if (!confirmed) return;
    var btn = document.getElementById(item + '-reset-btn-' + idx);
    if (btn) btn.disabled = true;
    fetch('/api/service/reset', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': _csrfToken},
      body: JSON.stringify({item: item, input: idx})
    }).then(function(r) { return r.json(); }).then(function(d) {
      if (!d.ok) { if (btn) btn.disabled = false; return; }
      var _disp = d.display || {card_sub: 'Tracking on', card_warn: false};
      if (d.display) {
        _applyHoursDisplay(_disp, item, idx);
        _applyTimeDisplay(_disp, item, idx);
        var dateKey = item === 'stylus' ? 'stylus-last-service-val-' : item + '-last-service-val-';
        var dateEl = document.getElementById(dateKey + idx);
        if (dateEl && _disp.last_service) { dateEl.textContent = _disp.last_service; }
      }
      _applyCardState(_disp, item, idx);
      if (d.warning) {
        var notice = document.createElement('span');
        notice.textContent = '\\u26a0 Reset not persisted \\u2014 may revert on restart';
        notice.style.cssText = 'color:var(--color-status-danger);font-size:0.85rem;display:block;margin-top:0.3rem;';
        if (btn && btn.parentNode) btn.parentNode.appendChild(notice);
        setTimeout(function() { if (notice.parentNode) notice.parentNode.removeChild(notice); }, 8000);
      }
      _updateResetBtnState(item, idx);
      if (btn) {
        btn.style.borderColor = ''; btn.style.background = ''; btn.style.color = '';
        btn.disabled = false;
      }
    }).catch(function() { if (btn) btn.disabled = false; });
  });
}
"""
