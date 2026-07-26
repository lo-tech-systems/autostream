"""autostream_webui_assets.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Web assets (e.g. CSS) to support the autostream web front-end.
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
  --color-eq-axis:           rgba(0,0,0,0.30);
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
  --color-eq-axis:           rgba(100,150,200,0.55);
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

.output-state-chip.in-use {
  background: var(--color-chip-off-bg);
  color: var(--color-chip-off-text);
  font-style: italic;
  border: 2px solid var(--color-status-success);
}

.output-card-in-use {
  border-color: var(--color-border-card);
  background: var(--color-surface-raised);
  opacity: 0.7;
  cursor: pointer;
  transition: opacity 140ms ease;
  pointer-events: auto;
}

.output-card-in-use:hover {
  opacity: 0.85;
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
  background: var(--color-accent);
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

/* Repeat button (home page top controls row) -- small pill-btn styled like
   the appliance-selector button; blue accent outline when armed/replaying,
   reusing the same active-card treatment as .output-card-on/.now-playing-card.
   Border is always reserved (transparent) so the active outline doesn't shift
   layout when toggled. */
.repeat-btn {
  border: 2px solid transparent;
}
.repeat-btn.active {
  border-color: var(--color-accent);
  background: var(--color-surface-selected);
  color: var(--color-text);
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

.eq-section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 1.9rem;
  margin-bottom: 0.65rem;
}

.eq-bands-wrap {
  display: flex;
  align-items: stretch;
  gap: 0.4rem;
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
.eq-curve-bg        { fill: var(--color-eq-bg); }
.eq-axis            { stroke: var(--color-eq-axis); fill: none; }
.eq-axis-x          { stroke-width: 0.8; }
.eq-axis-y          { stroke-width: 0.8; }
.eq-curve-fill      { fill: url(#eq-glow-grad); stroke: none; }
.eq-glow-stop-top   { stop-color: var(--color-accent); stop-opacity: 0.28; }
.eq-glow-stop-bottom{ stop-color: var(--color-accent); stop-opacity: 0; }
.eq-curve-path      { stroke: var(--color-accent);  stroke-width: 1.8; fill: none; }
.eq-handle          { fill: var(--color-accent);
                      stroke: rgba(255,255,255,0.75); stroke-width: 0.8; }

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
  display: flex;
  align-items: center;
  gap: 0.75rem;
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

body.has-bottom-nav {
  padding-bottom: calc(5.12rem + constant(safe-area-inset-bottom));
  padding-bottom: calc(5.12rem + env(safe-area-inset-bottom));
  box-sizing: border-box;
}

body.has-bottom-nav .container {
  padding-bottom: 5.12rem;
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
  padding: 0.6rem 0 0;
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

APPLIANCE_SELECTOR_CSS = """
  .appliance-selector{position:relative;display:inline-flex;align-items:center;}
  .appliance-selector-btn{display:inline-flex;align-items:center;gap:4px;padding:0.22rem 0.6rem;border-radius:999px;background:var(--color-surface-raised);border:1px solid var(--color-border);color:var(--color-text-secondary);font-size:0.82rem;font-weight:500;cursor:pointer;white-space:nowrap;max-width:160px;overflow:hidden;text-overflow:ellipsis;}
  .appliance-selector-btn:hover,.appliance-selector-btn:focus{background:var(--color-surface-pressed);outline:2px solid var(--color-accent);outline-offset:1px;}
  .appliance-selector-chevron{font-size:0.7rem;opacity:0.6;flex-shrink:0;pointer-events:none;}
  .appliance-selector-dropdown{position:absolute;right:0;top:calc(100% + 4px);min-width:190px;background:var(--color-surface);border:1px solid var(--color-border);border-radius:10px;box-shadow:0 4px 16px rgba(0,0,0,0.12);z-index:100;overflow:hidden;padding:4px 0;}
  .appliance-selector-option{display:block;padding:0.5rem 0.9rem;font-size:0.9rem;color:var(--color-text);text-decoration:none;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
  .appliance-selector-option:hover,.appliance-selector-option:focus{background:var(--color-surface-pressed);outline:none;}
  .appliance-selector-option-active{color:var(--color-accent);}
  .appliance-selector-divider{height:1px;background:var(--color-border);margin:4px 0;}
  .nav-tab-disabled{opacity:0.38;pointer-events:none;cursor:default;color:var(--color-nav-inactive);}
"""


# Card/now-playing rendering shared by the local Home page
# (send_airplay_page) and the remote-control Home shell
# (send_remote_home_page). Both pages embed this once and layer their own
# page-specific polling loop (local: /api/status + /api/owntone/outputs_state;
# remote: /api/appliances/<id>/home) on top of it.
#
# Parameterization points read from page-specific `window.*` globals set in
# each page's own inline <script> block before this one runs:
#   window.__OUTPUT_URL           -- output POST endpoint (defaults to
#                                     '/api/output' for the local page)
#   window.__PIN_PROMPT_FALLBACK  -- native window.prompt() label used only
#                                     if the PIN modal DOM is missing
#                                     (defaults to 'Enter PIN')
#   window.__REMOTE_HOSTNAME      -- when set, appended to the Now Playing
#                                     header as ' · <hostname>'; the local
#                                     page leaves this unset so its header
#                                     carries no suffix
#   window.__SELECTOR_CURRENT_ID  -- appliance id considered "current" by
#                                     the appliance-selector widget
HOME_CARDS_SCRIPT = """
<script>
  function normalizeVolume(v){
    const n = Number(v);
    if (!Number.isFinite(n)) return 0;
    return Math.max(0, Math.min(100, Math.round(n)));
  }
  function formatVolume(v){
    return String(normalizeVolume(v)) + '%';
  }
  function updateVolumeLabel(id,v){var s=document.getElementById('vol_label_'+id);if(s)s.textContent=formatVolume(v);}
  function isActiveControl(el) {
    return el && document.activeElement === el;
  }
  function reorderOutputCards(){
    const list = document.getElementById('outputs-list');
    if (!list) return;
    const cards = Array.from(list.querySelectorAll('.output-card'));
    cards.sort((a, b) => {
      const da = a.getAttribute('data-is-default') === '1' ? 1 : 0;
      const db = b.getAttribute('data-is-default') === '1' ? 1 : 0;
      if (db !== da) return db - da;
      const la = a.querySelector('.output-card-name');
      const lb = b.querySelector('.output-card-name');
      const na = ((la && la.textContent) || '').trim().toLowerCase();
      const nb = ((lb && lb.textContent) || '').trim().toLowerCase();
      return na.localeCompare(nb);
    });
    cards.forEach(card => list.appendChild(card));
  }
  function updateOutputStateVisual(id, selected){
    const cb = document.getElementById('output_enabled_' + id);
    if (cb && cb.disabled) return;
    const chip = document.getElementById('output_state_' + id);
    const card = document.getElementById('output_card_' + id);
    const wrap = document.getElementById('output_slider_wrap_' + id);
    if (chip) {
      chip.textContent = selected ? 'On' : 'Off';
      chip.classList.toggle('on', !!selected);
      chip.classList.toggle('off', !selected);
    }
    if (card) {
      card.classList.toggle('output-card-on', !!selected);
      card.classList.toggle('output-card-off', !selected);
    }
    if (wrap) {
      wrap.hidden = !selected;
    }
  }

  function showPinModal(outputName){
    return new Promise((resolve) => {
      const m = document.getElementById('pinModal');
      const title = document.getElementById('pinModalTitle');
      const input = document.getElementById('pinModalInput');
      const btnOk = document.getElementById('pinModalOk');
      const btnCancel = document.getElementById('pinModalCancel');
      if (!m || !input || !btnOk || !btnCancel) {
        // Fallback to native prompt if our modal is missing for any reason.
        const fallbackLabel = window.__PIN_PROMPT_FALLBACK || 'Enter PIN';
        const v = window.prompt(fallbackLabel + (outputName ? ' ('+outputName+')' : '') + ':', '');
        resolve(v && String(v).trim() ? String(v).trim() : null);
        return;
      }
      title.textContent = outputName ? ('Enter PIN for ' + outputName) : 'Enter PIN';
      input.value = '';
      m.classList.add('show');
      // iOS: defer focus slightly so the keyboard reliably appears.
      setTimeout(() => { try { input.focus(); } catch (e) {} }, 60);

      const cleanup = (val) => {
        m.classList.remove('show');
        btnOk.onclick = null;
        btnCancel.onclick = null;
        input.onkeydown = null;
        resolve(val);
      };
      btnCancel.onclick = () => cleanup(null);
      btnOk.onclick = () => {
        const v = (input.value || '').trim();
        cleanup(v ? v : null);
      };
      input.onkeydown = (ev) => {
        if (ev.key === 'Enter') { ev.preventDefault(); btnOk.click(); }
        else if (ev.key === 'Escape') { ev.preventDefault(); btnCancel.click(); }
      };
    });
  }

  function showInfoModal(title, message){
    return new Promise((resolve) => {
      const m = document.getElementById('infoModal');
      const titleEl = document.getElementById('infoModalTitle');
      const msgEl = document.getElementById('infoModalMessage');
      const btnOk = document.getElementById('infoModalOk');
      if (!m || !titleEl || !msgEl || !btnOk) {
        // Fallback to native alert if our modal is missing for any reason.
        window.alert(title + ': ' + message);
        resolve();
        return;
      }
      titleEl.textContent = title;
      msgEl.textContent = message;
      m.classList.add('show');

      const cleanup = () => {
        m.classList.remove('show');
        btnOk.onclick = null;
        document.removeEventListener('keydown', onKey);
        resolve();
      };
      const onKey = (ev) => {
        if (ev.key === 'Escape') { ev.preventDefault(); cleanup(); }
      };
      btnOk.onclick = () => cleanup();
      document.addEventListener('keydown', onKey);
    });
  }

  function computeMasterVolume(){
    var sum=0, count=0;
    document.querySelectorAll('.output-card').forEach(function(card){
      var id=card.getAttribute('data-output-id');
      if(!id) return;
      var cb=document.getElementById('output_enabled_'+id);
      var sl=document.getElementById('vol_slider_'+id);
      if(cb && cb.checked && sl){sum+=normalizeVolume(sl.value);count++;}
    });
    return count>0 ? Math.round(sum/count) : null;
  }
  function updateMasterVolumeCard(){
    var card=document.getElementById('master-volume-card');
    var sl=document.getElementById('master_vol_slider');
    if(!card||!sl) return;
    var v=computeMasterVolume();
    var inactive=(v===null);
    var val=inactive?(window.__PRESET_VOLUME||20):v;
    card.classList.toggle('master-volume-inactive',inactive);
    sl.disabled=inactive;
    if(String(sl.value)!==String(val)) sl.value=String(val);
  }
  function onMasterVolumeDragStart(){
    var sl=document.getElementById('master_vol_slider');
    if(!sl||sl.disabled) return;
    var snaps={};
    document.querySelectorAll('.output-card').forEach(function(card){
      var id=card.getAttribute('data-output-id');
      if(!id) return;
      var cb=document.getElementById('output_enabled_'+id);
      var vs=document.getElementById('vol_slider_'+id);
      if(cb&&cb.checked&&vs) snaps[id]=normalizeVolume(vs.value);
    });
    window.__MASTER_DRAG_SNAPSHOTS=snaps;
    window.__MASTER_DRAG_BASE=normalizeVolume(sl.value);
  }
  function _applyMasterScale(newMaster){
    var snaps=window.__MASTER_DRAG_SNAPSHOTS||{};
    var base=typeof window.__MASTER_DRAG_BASE==='number'?window.__MASTER_DRAG_BASE:0;
    var nm=normalizeVolume(newMaster);
    Object.keys(snaps).forEach(function(id){
      var sl=document.getElementById('vol_slider_'+id);
      if(!sl) return;
      var nv=base>0?Math.round(snaps[id]*nm/base):nm;
      nv=Math.max(0,Math.min(100,nv));
      sl.value=String(nv);
      updateVolumeLabel(id,nv);
    });
  }
  function onMasterVolumeInput(v){
    _applyMasterScale(v);
  }
  function onMasterVolumeChange(v){
    _applyMasterScale(v);
    var snaps=window.__MASTER_DRAG_SNAPSHOTS||{};
    Object.keys(snaps).forEach(function(id){ sendUpdate(id); });
    window.__MASTER_DRAG_SNAPSHOTS={};
  }

  function handleHomeSessionRejected(response){
    const status = Number(response && response.status);
    if (status !== 401 && status !== 403) return false;
    if (window.__HOME_SESSION_REFRESHING) return true;
    window.__HOME_SESSION_REFRESHING = true;
    window.location.reload();
    return true;
  }

  async function postOutputUpdate(id, selected, volume){
    const r = await fetch(window.__OUTPUT_URL || '/api/output',{
      method:'POST',
      credentials:'same-origin',
      signal: AbortSignal.timeout(5000),
      headers:{
        'Content-Type':'application/json',
        'X-CSRF-Token':window.__CSRF||''
      },
      body:JSON.stringify({
        id:id,
        selected:!!selected,
        volume:parseInt(volume||0,10)||0,
        csrf_token: window.__CSRF||''
      })
    });
    if (handleHomeSessionRejected(r)) return { ok:false, _http:r.status, session_rejected:true };
    // Server replies JSON for this endpoint (including failures)
    let j = null;
    try { j = await r.json(); } catch (e) { j = { ok: r.ok }; }
    j._http = r.status;
    return j;
  }

  async function postPinOnly(id, pin) {
    const r = await fetch(window.__OUTPUT_URL || '/api/output', {
      method:'POST',
      credentials:'same-origin',
      signal: AbortSignal.timeout(5000),
      headers:{
        'Content-Type':'application/json',
        'X-CSRF-Token':window.__CSRF||''
      },
      body:JSON.stringify({
        op:'pin',
        id:id,
        pin: String(pin||'').trim(),
        csrf_token: window.__CSRF||''
      })
    });
    if (handleHomeSessionRejected(r)) return { ok:false, _http:r.status, session_rejected:true };
    let j = null;
    try { j = await r.json(); } catch (e) { j = { ok: r.ok }; }
    j._http = r.status;
    return j;
  }

  async function sendUpdate(id){
    const c=document.getElementById('output_enabled_'+id), s=document.getElementById('vol_slider_'+id);
    if (c && c.disabled) return;
    const selected = c?c.checked:false;
    const volume = s?normalizeVolume(parseInt(s.value,10)):0;
    window.__PENDING_OUTPUTS.add(String(id));
    try {
      let j = null;
      try {
        j = await postOutputUpdate(id, selected, volume);
      } catch (e) {
        // Network error or 5 s abort -> let periodic refresh reconcile UI.
        return;
      }

      if (selected && j && j.error === 'output_in_use') {
        if (c) { c.checked = false; updateOutputStateVisual(String(id), false); }
        return;
      }

      // Output card name, shared by the encoder-capacity and PIN branches below.
      let nm = '';
      try {
        const card = c ? c.closest('.output-card') : null;
        const label = card ? card.querySelector('.output-card-name') : null;
        nm = label ? (label.textContent || '').trim() : '';
      } catch (e) {}

      if (selected && j && j.error === 'encoder_capacity') {
        if (c) { c.checked = false; updateOutputStateVisual(String(id), false); }
        showInfoModal('CPU limit reached',
          'Unable to enable ' + (nm || 'this output') + ': the appliance\\'s CPU cannot encode another stream at the selected quality. Disable another output or choose a lighter audio mode.');
        return;
      }

      // If OwnTone requires a PIN, prompt and do PIN-only verification.
      // On wrong PIN (still 400), re-prompt; on success, retry the original enable.
      if (selected && j && j.pin_required) {
        // Temporarily revert the toggle until fully enabled.
        if (c) {
          c.checked = false;
          updateOutputStateVisual(String(id), false);
        }

        while (true) {
          const pin = await showPinModal(nm || 'this speaker');
          if (!pin) return; // user cancelled

          let jpin = null;
          try {
            jpin = await postPinOnly(id, pin);
          } catch (e) {
            // treat as failure; keep disabled
            if (c) {
              c.checked = false;
              updateOutputStateVisual(String(id), false);
            }
            return;
          }

          if (jpin && jpin.ok) {
            // PIN accepted -> retry the original enable request (without pin)
            try {
              const jen = await postOutputUpdate(id, true, volume);
              if (jen && jen.ok) {
                if (c) {
                  c.checked = true;
                  updateOutputStateVisual(String(id), true);
                }
                return;
              }
              // If it still asks for PIN, loop again.
              if (jen && jen.pin_required) {
                if (c) {
                  c.checked = false;
                  updateOutputStateVisual(String(id), false);
                }
                continue;
              }
            } catch (e) {
              if (c) {
                c.checked = false;
                updateOutputStateVisual(String(id), false);
              }
            }
            return;
          }

          // Wrong PIN -> re-prompt
          if (jpin && jpin.pin_invalid) {
            continue;
          }

          // Other error -> stop
          return;
        }
      }
    } finally {
      window.__PENDING_OUTPUTS.delete(String(id));
    }
  }

  function onToggleOutput(id){
    const cb = document.getElementById('output_enabled_' + id);
    if (cb && cb.disabled) return;
    if (cb) updateOutputStateVisual(String(id), !!cb.checked);
    if (cb && cb.checked) {
      const sl = document.getElementById('vol_slider_' + id);
      if (sl) { sl.value = String(window.__PRESET_VOLUME || 20); updateVolumeLabel(id, sl.value); }
    }
    reorderOutputCards();
    updateMasterVolumeCard();
    sendUpdate(id);
  }
  function onVolumeChange(id,v){
    updateVolumeLabel(id,v);
    if(!isActiveControl(document.getElementById('master_vol_slider'))) updateMasterVolumeCard();
    sendUpdate(id);
  }
  var VU_THRESHOLDS = [-60, -48, -36, -24, -12, -6, -3];
  var VU_COLORS = ['#2196F3','#2196F3','#2196F3','#2196F3','#f0ad4e','#fd7e14','#dc3545'];
  var VU_BIN_MS = 100;
  var VU_DELAY_BINS = Math.max(1, Math.round((window.__VU_DELAY_MS || 2250) / VU_BIN_MS));

  // Per-input VU queue state.
  var _vuQueue = {};         // inputIdx -> Array of pending bins
  var _vuLastSeq = {};       // inputIdx -> last seq appended to queue
  var _vuActiveIdx = -1;      // currently displayed input index (-1 = none)

  function updateVuBars(left_dbfs, right_dbfs){
    var lBars = document.querySelectorAll('#np-vu-l .vu-bar');
    var rBars = document.querySelectorAll('#np-vu-r .vu-bar');
    lBars.forEach(function(bar, i){
      var lit = Number.isFinite(Number(left_dbfs)) && Number(left_dbfs) >= VU_THRESHOLDS[i];
      bar.style.background = lit ? VU_COLORS[i] : '';
    });
    rBars.forEach(function(bar, i){
      var lit = Number.isFinite(Number(right_dbfs)) && Number(right_dbfs) >= VU_THRESHOLDS[i];
      bar.style.background = lit ? VU_COLORS[i] : '';
    });
  }

  function vuIngestHistory(activeIdx, vu_history){
    // If the active input changed, clear all queues immediately.
    if (activeIdx !== _vuActiveIdx) {
      _vuQueue = {};
      _vuLastSeq = {};
      _vuActiveIdx = activeIdx;
    }
    if (!vu_history || !Array.isArray(vu_history.bins) || vu_history.bins.length === 0)
      return;
    var bins = vu_history.bins;
    var latestSeq = vu_history.latest_seq || 0;
    // Only show bins that are VU_DELAY_BINS steps behind the latest
    // so the display lags the signal by approximately __VU_DELAY_MS.
    var cutoffSeq = latestSeq - VU_DELAY_BINS;
    if (cutoffSeq < 0) return;
    if (!_vuQueue[activeIdx]) _vuQueue[activeIdx] = [];
    if (!_vuLastSeq[activeIdx]) _vuLastSeq[activeIdx] = 0;
    var lastSeen = _vuLastSeq[activeIdx];
    // Detect seq reset (daemon restart): clear and resync.
    if (latestSeq < lastSeen && lastSeen > 0) {
      _vuQueue[activeIdx] = [];
      _vuLastSeq[activeIdx] = 0;
      lastSeen = 0;
    }
    var added = 0;
    for (var i = 0; i < bins.length; i++) {
      var b = bins[i];
      if (b.seq > lastSeen && b.seq <= cutoffSeq) {
        _vuQueue[activeIdx].push(b);
        added++;
      }
    }
    if (added > 0)
      _vuLastSeq[activeIdx] = cutoffSeq;
    // Bound queue to 2x the delay window to guard against extreme fetch jitter.
    var maxQ = VU_DELAY_BINS * 2;
    var q = _vuQueue[activeIdx];
    if (q.length > maxQ)
      _vuQueue[activeIdx] = q.slice(q.length - maxQ);
  }

  function vuRenderTick(){
    var q = _vuQueue[_vuActiveIdx];
    var bin = (q && q.length > 0) ? q.shift() : null;
    updateVuBars(bin ? bin.l : -90, bin ? bin.r : -90);
  }

  function renderNowPlayingCard(data){
    var levels = (data && data.input_levels) || [];
    var inputs = (data && data.playback && data.playback.inputs) || {};
    var isPlaying = false, activeLevel = null, activeIdx = 0;
    for (var i = 0; i < levels.length; i++) {
      if (levels[i] && levels[i].is_above_threshold) {
        isPlaying = true; activeLevel = levels[i]; activeIdx = i; break;
      }
    }
    // Authoritative playing/active state: prefer d.session.active (the
    // coordinator's unified session flag -- true during buffered
    // AirPlay/AAC playback AND repeat replay, neither of which trips
    // the input-level threshold above); fall back to the legacy
    // level-based isPlaying when talking to an older backend with no
    // session block.
    var session = (data && data.session) || null;
    var sessionActive = (session && typeof session.active === 'boolean') ? !!session.active : null;
    var sessionSource = (session && typeof session.source === 'string') ? session.source : null;
    var active = (sessionActive !== null) ? sessionActive : isPlaying;
    var card = document.getElementById('now-playing-card');
    var hdrEl = document.getElementById('np-hdr');
    if (card) card.classList.toggle('np-ready', !active);
    // Remote-shell pages set window.__REMOTE_HOSTNAME so the header also
    // identifies which appliance is being viewed; the local page leaves it
    // unset so its own header carries no suffix.
    var hdrSuffix = window.__REMOTE_HOSTNAME ? (' · ' + window.__REMOTE_HOSTNAME) : '';
    if (hdrEl) hdrEl.textContent = (active ? (sessionSource === 'replay' ? 'REPEAT PLAYBACK' : 'Now Playing') : 'Ready') + hdrSuffix;
    if (!active) {
      _vuActiveIdx = -1;
      _vuQueue = {};
      updateVuBars(-90, -90);
      return;
    }
    // During replay no input trips the live-level threshold (the
    // origin input is not "capturing"), so activeLevel is still null
    // here even though session.active is true and the origin monitor's
    // track-identification snapshot is live (server-side fix in
    // get_active_track_identification_snapshot). Resolve the origin
    // input from repeat.recording.origin_input -- present verbatim
    // whenever sessionSource === 'replay' -- so the icon/label reflect
    // the actual replaying input rather than an arbitrary levels[0]
    // guess. Not a genuine live level, so vuIngestHistory is skipped
    // for it below.
    var usingReplayOrigin = false;
    if (!activeLevel && sessionSource === 'replay') {
      var repeat = (data && data.repeat) || {};
      var recording = repeat.recording || {};
      var originInput = Number.isFinite(Number(recording.origin_input))
        ? Number(recording.origin_input) : null;
      if (originInput !== null) {
        var originIdx = originInput - 1;
        activeLevel = levels[originIdx] || {
          label: 'Input ' + originInput, dbfs: -90, detected_hz: 0, is_above_threshold: false,
        };
        activeIdx = originIdx;
        usingReplayOrigin = true;
      }
    }
    if (!activeLevel && levels.length > 0) { activeLevel = levels[0]; activeIdx = 0; }
    if (!activeLevel) return;
    var inputSnap = inputs[String(activeIdx + 1)] || {};
    var isTurntable = !!inputSnap.is_turntable;
    var label = String(activeLevel.label || ('Input ' + (activeIdx + 1)));
    var signalParts = [];
    if (window.__SHOW_INPUT_DETAIL) {
      var hz = Number(activeLevel.detected_hz || 0);
      if (Number.isFinite(hz) && hz > 0) {
        signalParts.push('Locked');
        signalParts.push(Math.round(hz / 1000) + ' kHz');
      }
    }
    var nameEl = document.getElementById('np-name');
    var signalEl = document.getElementById('np-signal');
    var iconEl = document.getElementById('np-icon');
    var ti = (data && data.track_identification) || {};
    var tiEnabled = !!(ti && ti.enabled);
    var tiState = String((ti && ti.state) || '');
    var tiIdentified = tiEnabled && tiState === 'identified';
    var tiTitle = String((ti && ti.title) || '');
    var tiArtist = String((ti && ti.artist) || '');
    var tiArtUrl = String((ti && ti.artwork_url) || '');
    if (tiIdentified) {
      if (nameEl) nameEl.textContent = tiTitle || 'Unknown';
      if (signalEl) signalEl.textContent = tiArtist;
      if (iconEl) {
        var artKey = 'art:' + tiArtUrl;
        if (iconEl.getAttribute('data-np-icon-key') !== artKey) {
          iconEl.setAttribute('data-np-icon-key', artKey);
          if (tiArtUrl) {
            var artImg = new Image();
            artImg.onload = function() {
              if (iconEl.getAttribute('data-np-icon-key') === artKey) {
                iconEl.textContent = '';
                var img = document.createElement('img');
                img.src = tiArtUrl;
                img.alt = '';
                iconEl.appendChild(img);
                iconEl.classList.add('np-icon-art');
              }
            };
            artImg.src = tiArtUrl;
          } else {
            iconEl.innerHTML = isTurntable ? window.__ICON_TURNTABLE : window.__ICON_LINE_LEVEL;
            iconEl.classList.remove('np-icon-art');
          }
        }
      }
    } else if (tiEnabled) {
      var inputPrefix = isTurntable ? 'Vinyl' : 'Line In';
      var suffix;
      if (tiState === 'error') { suffix = 'Track ID function not available'; }
      else if (tiState === 'not_found') { suffix = 'Unknown track'; }
      else { suffix = 'Identifying Track…'; }
      if (nameEl) nameEl.textContent = inputPrefix + ' – ' + suffix;
      if (signalEl) signalEl.textContent = '';
      var svgKey = 'svg:' + String(isTurntable);
      if (iconEl && iconEl.getAttribute('data-np-icon-key') !== svgKey) {
        iconEl.setAttribute('data-np-icon-key', svgKey);
        iconEl.innerHTML = isTurntable ? window.__ICON_TURNTABLE : window.__ICON_LINE_LEVEL;
        iconEl.classList.remove('np-icon-art');
      }
    } else {
      if (nameEl) nameEl.textContent = label + ' · ' + (isTurntable ? 'Turntable' : 'Line Level');
      if (signalEl) signalEl.textContent = signalParts.join(' · ');
      var svgKey2 = 'svg:' + String(isTurntable);
      if (iconEl && iconEl.getAttribute('data-np-icon-key') !== svgKey2) {
        iconEl.setAttribute('data-np-icon-key', svgKey2);
        iconEl.innerHTML = isTurntable ? window.__ICON_TURNTABLE : window.__ICON_LINE_LEVEL;
        iconEl.classList.remove('np-icon-art');
      }
    }
    if (!usingReplayOrigin) vuIngestHistory(activeIdx, activeLevel.vu_history);
  }

  function buildOutputCardElement(o) {
    var id = String(o.id || '');
    var name = String(o.name || ('Output ' + id));
    var selected = !!o.selected;
    var volume = normalizeVolume(o.volume);
    var isDefault = !!o.is_default;
    var remoteInUse = !!o.remote_in_use;
    var remoteOwner = String(o.remote_owner || '');

    var card = document.createElement('div');
    card.className = 'output-card ' + (remoteInUse ? 'output-card-in-use' : (selected ? 'output-card-on' : 'output-card-off'));
    card.id = 'output_card_' + id;
    card.setAttribute('data-output-id', id);
    card.setAttribute('data-is-default', isDefault ? '1' : '0');
    card.setAttribute('data-remote-in-use', remoteInUse ? '1' : '0');
    card.setAttribute('data-remote-owner', remoteOwner);

    var head = document.createElement('div');
    head.className = 'output-card-head';

    var meta = document.createElement('div');
    meta.className = 'output-card-meta';
    var nameDiv = document.createElement('div');
    nameDiv.className = 'output-card-name';
    nameDiv.textContent = name;
    meta.appendChild(nameDiv);
    if (isDefault) {
      var badge = document.createElement('span');
      badge.className = 'output-card-default';
      badge.textContent = 'Default';
      meta.appendChild(badge);
    }
    var chip = document.createElement('span');
    chip.className = 'output-state-chip ' + (remoteInUse ? 'in-use' : (selected ? 'on' : 'off'));
    chip.id = 'output_state_' + id;
    chip.textContent = remoteInUse ? ('In Use by ' + (remoteOwner || 'another appliance')) : (selected ? 'On' : 'Off');
    meta.appendChild(chip);
    head.appendChild(meta);

    var toggle = document.createElement('label');
    toggle.className = 'output-toggle';
    toggle.addEventListener('click', function(e) { e.stopPropagation(); });
    var cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.id = 'output_enabled_' + id;
    cb.checked = selected;
    if (remoteInUse) cb.disabled = true;
    cb.addEventListener('change', function() { onToggleOutput(id); });
    toggle.appendChild(cb);
    var sw = document.createElement('span');
    sw.className = 'switch';
    sw.setAttribute('aria-hidden', 'true');
    toggle.appendChild(sw);
    head.appendChild(toggle);
    card.appendChild(head);

    var wrap = document.createElement('div');
    wrap.className = 'output-slider-wrap';
    wrap.id = 'output_slider_wrap_' + id;
    wrap.addEventListener('click', function(e) { e.stopPropagation(); });
    if (!selected) wrap.hidden = true;
    var sliderHdr = document.createElement('div');
    sliderHdr.className = 'slider-header';
    var volText = document.createElement('span');
    volText.textContent = 'Volume:';
    sliderHdr.appendChild(volText);
    var volLbl = document.createElement('span');
    volLbl.id = 'vol_label_' + id;
    volLbl.setAttribute('data-volume-label-for', id);
    sliderHdr.appendChild(volLbl);
    wrap.appendChild(sliderHdr);
    var sl = document.createElement('input');
    sl.type = 'range';
    sl.id = 'vol_slider_' + id;
    sl.min = 0; sl.max = 100; sl.step = 1; sl.value = volume;
    sl.addEventListener('input', function() { updateVolumeLabel(id, this.value); });
    sl.addEventListener('change', function() { onVolumeChange(id, this.value); });
    wrap.appendChild(sl);
    card.appendChild(wrap);

    return card;
  }

  function setOutputsPlaceholder(state) {
    var el = document.getElementById('outputs-placeholder');
    if (!el) return;
    if (state === 'hidden') {
      el.hidden = true;
      el.textContent = '';
    } else if (state === 'unreachable') {
      el.hidden = false;
      el.textContent = 'Waiting for owntone';
    } else {
      el.hidden = false;
      el.textContent = 'Waiting for device discovery';
    }
  }
  function renderOutputList(outputs) {
    var list = document.getElementById('outputs-list');
    if (!list) return;
    while (list.firstChild) list.removeChild(list.firstChild);
    for (var i = 0; i < outputs.length; i++) { list.appendChild(buildOutputCardElement(outputs[i])); }
    list.querySelectorAll('[data-volume-label-for]').forEach(function(s) {
      var id = s.getAttribute('data-volume-label-for');
      var sl = document.getElementById('vol_slider_' + id);
      if (sl) updateVolumeLabel(id, sl.value);
      var cb = document.getElementById('output_enabled_' + id);
      if (cb) updateOutputStateVisual(String(id), !!cb.checked);
    });
    reorderOutputCards();
    updateMasterVolumeCard();
    setOutputsPlaceholder(outputs.length > 0 ? 'hidden' : 'empty');
  }

  function initApplianceSelector(){
    var btn=document.getElementById('appliance-selector-btn');
    var dd=document.getElementById('appliance-selector-dropdown');
    if(!btn||!dd) return;
    btn.addEventListener('click',function(e){
      e.stopPropagation();
      var open=!dd.hidden;
      dd.hidden=open;
      btn.setAttribute('aria-expanded',String(!open));
      if(!open) refreshApplianceSelector();
    });
    document.addEventListener('click',function(){
      if(!dd.hidden){dd.hidden=true;btn.setAttribute('aria-expanded','false');}
    });
    dd.addEventListener('keydown',function(e){
      var opts=Array.from(dd.querySelectorAll('.appliance-selector-option'));
      var idx=opts.indexOf(document.activeElement);
      if(e.key==='ArrowDown'){e.preventDefault();var n=opts[idx+1]||opts[0];if(n)n.focus();}
      else if(e.key==='ArrowUp'){e.preventDefault();var p=opts[idx-1]||opts[opts.length-1];if(p)p.focus();}
      else if(e.key==='Escape'){dd.hidden=true;btn.setAttribute('aria-expanded','false');btn.focus();}
    });
  }
  function updateSelectorFromAppliances(appliances,currentId,currentPage){
    var dd=document.getElementById('appliance-selector-dropdown');
    var nameEl=document.getElementById('appliance-selector-current');
    if(!dd) return;
    dd.innerHTML='';
    var dividerAdded=false;
    appliances.forEach(function(a){
      var isBound=!!a.is_bound;
      if(!isBound&&!dividerAdded){
        dividerAdded=true;
        var divEl=document.createElement('div');
        divEl.className='appliance-selector-divider';
        divEl.setAttribute('role','separator');
        divEl.setAttribute('aria-hidden','true');
        dd.appendChild(divEl);
      }
      var href=currentPage==='equaliser'
        ?(a.equaliser_path||'/a/'+a.id+'/equaliser')
        :(a.home_path||(isBound?'/':'/a/'+a.id+'/'));
      var opt=document.createElement('a');
      opt.href=href;
      opt.setAttribute('role','option');
      opt.setAttribute('aria-selected',a.id===currentId?'true':'false');
      opt.className='appliance-selector-option'+(a.id===currentId?' appliance-selector-option-active':'');
      if(isBound) opt.style.fontWeight='700';
      opt.textContent=String(a.hostname||'autostream');
      dd.appendChild(opt);
    });
    var cur=appliances.find(function(a){return a.id===currentId;});
    if(nameEl&&cur) nameEl.textContent=String(cur.hostname||'autostream');
  }
  function refreshApplianceSelector(){
    fetch('/api/appliances',{cache:'no-store'})
      .then(function(r){return r.json();})
      .then(function(data){
        if(!data||!data.ok||!Array.isArray(data.appliances)) return;
        var el=document.getElementById('appliance-selector');
        var currentId=el?(el.getAttribute('data-current-id')||window.__SELECTOR_CURRENT_ID||''):(window.__SELECTOR_CURRENT_ID||'');
        var currentPage=el?(el.getAttribute('data-current-page')||'home'):'home';
        updateSelectorFromAppliances(data.appliances,currentId,currentPage);
      })
      .catch(function(){});
  }
</script>
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
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 206 206"'
    ' fill="none" stroke="var(--color-accent)" stroke-width="2.5"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    # Outer case
    '<rect x="2.5" y="4.5" width="201" height="200" rx="4"/>'
    # Record
    '<circle cx="87" cy="95" r="69"/>'
    '<circle cx="87" cy="95" r="26"/>'
    '<circle cx="87" cy="95" r="3"/>'
    # Record grooves
    '<path d="M31 81 C38 59,56 43,80 38"/>'
    '<path d="M43 87 C52 67,66 55,81 51"/>'
    # Tonearm pivot
    '<circle cx="177" cy="47" r="13"/>'
    '<circle cx="177" cy="47" r="5"/>'
    # Tonearm base block
    '<rect x="169" y="21" width="14" height="14"/>'
    # Tonearm
    '<path d="M177 60 L177 101"/>'
    '<path d="M177 101 C177 111,172 119,165 126"/>'
    '<path d="M165 126 L143 148"/>'
    '<path d="M188 59 L188 102"/>'
    '<path d="M188 102 C188 116,181 129,171 139"/>'
    '<path d="M171 139 L152 158"/>'
    # Cartridge / needle
    '<rect x="141" y="136" width="18" height="27" transform="rotate(45 141 136)"/>'
    '<path d="M156 156 L166 166"/>'
    # Buttons
    '<circle cx="156" cy="178" r="8"/>'
    '<rect x="176" y="170" width="11" height="18" rx="5.5"/>'
    '</svg>'
)

ICON_LINE_LEVEL = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 258"'
    ' fill="none" stroke="var(--color-accent)" stroke-width="7"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    # Top cable
    '<path d="M56 57 V14"/>'
    '<path d="M56 14 C56 9,60 5,64 5"/>'
    '<path d="M64 5 C69 5,72 9,72 14"/>'
    '<path d="M72 14 V57"/>'
    # Upper connector block
    '<path d="M31 57 H96"/>'
    '<path d="M96 57 C99 57,101 60,101 63"/>'
    '<path d="M101 63 V101"/>'
    '<path d="M31 101 V63"/>'
    '<path d="M31 63 C31 60,34 57,37 57"/>'
    # Main body
    '<path d="M21 101 H107"/>'
    '<path d="M107 101 V167"/>'
    '<path d="M107 167 L86 191"/>'
    '<path d="M86 191 H42"/>'
    '<path d="M42 191 L21 167"/>'
    '<path d="M21 167 V101"/>'
    # Strain relief / lower grip
    '<path d="M42 191 V245"/>'
    '<path d="M42 245 C42 250,46 254,51 254"/>'
    '<path d="M51 254 H77"/>'
    '<path d="M77 254 C82 254,86 250,86 245"/>'
    '<path d="M86 245 V191"/>'
    # Grip grooves
    '<path d="M42 209 H57"/>'
    '<path d="M71 209 H86"/>'
    '<path d="M42 226 H57"/>'
    '<path d="M71 226 H86"/>'
    '<path d="M42 243 H57"/>'
    '<path d="M71 243 H86"/>'
    # Front slots
    '<path d="M59 122 H69"/>'
    '<path d="M59 138 H69"/>'
    '<path d="M59 154 H69"/>'
    '</svg>'
)

# ── Dial locked-section padlock icons ─────────────────────────────────────────
# Feather-style 24×24, stroke="var(--color-accent)" so they adapt to dark mode.

ICON_PADLOCK_LOCKED = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="var(--color-accent)" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<rect x="3" y="11" width="18" height="11" rx="2"/>'
    '<path d="M7 11V7a5 5 0 0 1 10 0v4"/>'
    '</svg>'
)

ICON_PADLOCK_UNLOCKED = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="var(--color-accent)" stroke-width="2"'
    ' stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<rect x="3" y="11" width="18" height="11" rx="2"/>'
    '<path d="M7 11V7a5 5 0 0 1 9.9-1"/>'
    '</svg>'
)

DIAL_LOCKED_SECTION_CSS = """
.dial-locked-section {
  margin-top: 0.75rem;
  border: 1px solid var(--color-border-card);
  border-radius: 6px;
  padding: 0.5rem 0.6rem 0.6rem;
}
.dial-locked-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.dial-locked-label {
  font-size: 0.75rem;
  color: var(--color-text-dim);
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.dial-lock-btn {
  background: none;
  border: none;
  cursor: pointer;
  padding: 2px;
  line-height: 0;
  display: flex;
  align-items: center;
  border-radius: 4px;
}
.dial-lock-btn svg { width: 18px; height: 18px; }
.dial-lock-btn:focus-visible { outline: 2px solid var(--color-accent); outline-offset: 2px; }
.dial-locked-controls { transition: opacity 120ms ease; }
.dial-section-locked .dial-locked-controls {
  opacity: 0.45;
  pointer-events: none;
  user-select: none;
}
"""

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
    ".service-slide-detail .service-control-card {"
    " margin-bottom: 1.25rem;"
    " padding: 1rem 0.9rem 1.1rem;"
    " border-radius: 8px;"
    " border: 1px solid var(--color-border);"
    " background: var(--color-surface-raised);"
    " }\n"
    ".service-slide-detail .service-control-card-title {"
    " font-weight: 700;"
    " font-size: 1.05rem;"
    " margin-bottom: 0.85rem;"
    " color: var(--color-text);"
    " line-height: 1.25;"
    " }\n"
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

# ---------------------------------------------------------------------------
# Shared autosave controller for POST /api/settings (WP3+)
# ---------------------------------------------------------------------------
# Requires window.__CSRF to be set before this script runs (done by csrf_meta
# injected in head_extra on every page that uses it).
# Exports:
#   settingsSaveField(field, value)                  — send immediately (checkbox/select)
#   settingsSaveFieldDebounced(field, value, ms)      — debounced send (text/number/range)
#   flushPendingToServer() → Promise                  — drain before navigation
#   settingsTransact(url, payload, opts)              — privileged/external transaction
# ---------------------------------------------------------------------------
AUTOSAVE_JS = """
<script>
(function() {
  var _csrf = window.__CSRF || '';
  var _statusEl = null;
  var _pendingTimers = {};    // field → {timer, value}
  var _pendingRequests = {};  // field → {ctrl, promise}

  function _getStatus() {
    if (!_statusEl) _statusEl = document.getElementById('autosave-status');
    return _statusEl;
  }

  function _setStatus(text) {
    var el = _getStatus();
    if (el) el.textContent = text;
  }

  function _hasPending() {
    return Object.keys(_pendingTimers).length > 0 || Object.keys(_pendingRequests).length > 0;
  }

  function _send(field, value) {
    var prev = _pendingRequests[field];
    if (prev) { try { prev.ctrl.abort(); } catch(_) {} }
    var ctrl = new AbortController();
    _setStatus('Saving…');
    var p = fetch('/api/settings', {
      method: 'POST',
      credentials: 'same-origin',
      signal: ctrl.signal,
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': _csrf},
      body: JSON.stringify({field: field, value: value})
    }).then(function(r) { return r.json(); }).then(function(d) {
      if (_pendingRequests[field] && _pendingRequests[field].ctrl === ctrl) {
        delete _pendingRequests[field];
      }
      if (d.ok) {
        var statusMsg = (d.live === false) ? 'Saved (could not apply live)' : 'Saved';
        if (!_hasPending()) _setStatus(statusMsg);
        setTimeout(function() {
          var el = _getStatus();
          if (el && (el.textContent === 'Saved' || el.textContent === 'Saved (could not apply live)')) el.textContent = '';
        }, 2000);
      } else {
        _setStatus('Could not save — ' + (d.error || 'error'));
      }
    }).catch(function(e) {
      if (_pendingRequests[field] && _pendingRequests[field].ctrl === ctrl) {
        delete _pendingRequests[field];
      }
      if (e.name !== 'AbortError') _setStatus('Could not save');
    });
    _pendingRequests[field] = {ctrl: ctrl, promise: p};
    return p;
  }

  window.settingsSaveField = function(field, value) {
    _send(field, value);
  };

  window.settingsSaveFieldDebounced = function(field, value, ms) {
    var entry = _pendingTimers[field];
    if (entry) clearTimeout(entry.timer);
    _pendingTimers[field] = {
      timer: setTimeout(function() {
        delete _pendingTimers[field];
        _send(field, value);
      }, ms || 500),
      value: value
    };
  };

  window.flushPendingToServer = function() {
    var promises = [];
    Object.keys(_pendingTimers).forEach(function(field) {
      var entry = _pendingTimers[field];
      if (entry) {
        clearTimeout(entry.timer);
        var val = entry.value;
        delete _pendingTimers[field];
        promises.push(_send(field, val));
      }
    });
    Object.keys(_pendingRequests).forEach(function(field) {
      var entry = _pendingRequests[field];
      if (entry && entry.promise) promises.push(entry.promise);
    });
    return Promise.all(promises);
  };

  window.settingsTransact = function(url, payload, opts) {
    opts = opts || {};
    _setStatus('Applying…');
    fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': _csrf},
      body: JSON.stringify(payload)
    }).then(function(r) { return r.json(); }).then(function(d) {
      if (!d.ok) {
        _setStatus('Could not apply — ' + (d.error || 'error'));
        if (opts.onError) opts.onError(d);
        return;
      }
      _setStatus('Saved');
      setTimeout(function() {
        var el = _getStatus();
        if (el && el.textContent === 'Saved') el.textContent = '';
      }, 2000);
      if (d.redirect_url) { window.location.href = d.redirect_url; return; }
      if (opts.onSuccess) opts.onSuccess(d);
    }).catch(function(e) {
      _setStatus('Could not apply');
      if (opts.onError) opts.onError({error: String(e)});
    });
  };

  window.addEventListener('beforeunload', function(e) {
    if (_hasPending()) {
      e.preventDefault();
      e.returnValue = '';
    }
  });
})();
</script>
"""
