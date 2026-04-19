"""autostream_webui.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Web assets (e.g. CSS) to support web front-end for autostrea
"""


STYLE_CSS = """
.container {
  max-width: 1000px;
  margin: 1rem auto;
  background: #fff;
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
  color: #555;
}

.status-pill {
  padding: 0.15rem 0.7rem;
  border-radius: 999px;
  font-weight: 600;
  font-size: 0.85rem;
}

.status-pill.status-playing {
  background: #d1e7dd;
  color: #0f5132;
}

.status-pill.status-waiting {
  background: #e2e3e5;
  color: #41464b;
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
}

fieldset {
  margin-bottom: 1.5rem;
  padding: 1rem 0.9rem 1.2rem;
  border-radius: 6px;
  border: 1px solid #ddd;
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
  background: #f3f4f6;   /* light grey */
  border: 1px solid #d1d5db;
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
  color: #555;
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
  background: #6c757d;
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
  color: #333;
}

.output-card {
  margin-bottom: 0.62rem;
  padding: 0.52rem 0.72rem 0.5rem;
  border-radius: 12px;
  border: 1px solid #d9dee3;
  background: #f8fafb;
  transition: border-color 120ms ease, background 120ms ease, box-shadow 120ms ease;
}

.output-card-on {
  border-color: #2b80d1;
  background: #f1f6fc;
}

.output-card-off {
  border-color: #d9dee3;
  background: #f8fafb;
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
  color: #121212;
  line-height: 1.12;
  overflow-wrap: anywhere;
  word-break: break-word;
}

.output-card-default {
  display: inline-block;
  padding: 0.06rem 0.4rem;
  border-radius: 999px;
  background: #eceff2;
  color: #495057;
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
  background: #d1e7dd;
  color: #0f5132;
}

.output-state-chip.off {
  background: #e2e3e5;
  color: #41464b;
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
  background: #adb5bd;
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
  background: #198754;
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
  font-weight: 600;
  background: #6c757d;
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
  background: #6c757d;
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

.airplay-refresh-wrap .pill-btn {
  padding: 0.45rem 1.1rem;
  font-size: 0.85rem;
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

.input-level-row {
  justify-content: flex-start;
  flex-wrap: wrap;
  gap: 0.4rem;
  margin-top: -0.2rem;
}

.input-level-pill {
  background: #e9ecef;
  color: #495057;
  font-size: 0.82rem;
}

.home-input-level-wrap {
  display: flex;
  justify-content: center;
  margin-top: 1rem;
  margin-bottom: 1rem;
}

.home-input-level-wrap .input-level-row {
  justify-content: center;
  margin-top: 0;
}

.input-level-pill-active {
  background: #d1e7dd;
  color: #0f5132;
}

/* iOS-style storage bar */
.storage-bar {
  width: 100%;
  height: 14px;
  background: #e9ecef;           /* light grey (available) */
  border-radius: 999px;
  overflow: hidden;
  box-shadow: inset 0 1px 2px rgba(0,0,0,0.08);
  margin: 0 0 0 0;
}

.storage-bar .used {
  height: 100%;
  width: 0%;
  background: #28a745;           /* green default */
  border-radius: 999px;
  transition: width 0.3s ease;
}

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
  background: #f4f5f6;
  color: #1a1a1a;
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
  background: #0f0f0fd;
  padding: 0 0.25rem;
  border-radius: 3px;
}

@media (min-width: 600px) {
  .container { margin: 2rem auto; }  /* keep the roomy desktop spacing */
  button[type=submit] { width: auto; }
}

@media (max-width: 520px) {
  .airplay-masthead {
    align-items: center;
  }
  .airplay-refresh-wrap .pill-btn {
    padding: 0.5rem 1rem;
    font-size: 0.83rem;
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
  background: #fff;
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
  background: #f5f5f5;
  font-size: 18px;
}

#red-banner {
  position: fixed !important;
  top: 0 !important;
  left: 0 !important;
  right: 0 !important;
  background: #c00000;
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
  background: #28a745;
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
  border: 1px solid #d9dee3;
  background: #f8fafb;
  cursor: pointer;
  user-select: none;
  -webkit-tap-highlight-color: transparent;
  transition: background 120ms ease;
  gap: 0.5rem;
}
.setup-list-card:active {
  background: #edf2f7;
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
  color: #121212;
  line-height: 1.2;
}
.setup-list-card-sub {
  font-size: 0.82rem;
  color: #6c757d;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.setup-list-chevron {
  font-size: 1.4rem;
  color: #adb5bd;
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
"""

BANNER_HTML = """
  <div class="banner-logo-wrap">
    <img src="/autostream-badge.png" alt="AutoStream" class="banner-logo">
  </div>

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


LICENSE_BANNER_CSS = ""

VIEWPORT_META = '<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">'

PIN_MODAL_CSS = """
  #pinModal{position:fixed;inset:0;display:none;align-items:center;justify-content:center;background:rgba(0,0,0,.45);z-index:9999;padding:1.25rem;}
  #pinModal.show{display:flex;}
  #pinModal .panel{width:min(22rem,100%);background:#fff;border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,.25);overflow:hidden;}
  #pinModal .hdr{padding:0.9rem 1rem;border-bottom:1px solid #eee;font-weight:700;}
  #pinModal .bd{padding:1rem;}
  #pinModal .bd p{margin:0 0 .75rem 0;}
  #pinModal input{width:100%;font-size:1.2rem;padding:.65rem .75rem;border:1px solid #ccc;border-radius:12px;outline:none;}
  #pinModal .ft{display:flex;gap:.75rem;padding:0.9rem 1rem;border-top:1px solid #eee;}
  #pinModal .btn{flex:1;border:none;border-radius:999px;padding:.8rem .9rem;font-weight:700;font-size:1rem;background:#6c757d;color:#fff;box-shadow:0 2px 6px rgba(0,0,0,0.05);}
  #pinModal .btn.cancel{background:#6c757d;color:#fff;}
  #pinModal .btn.ok{background:#6c757d;color:#fff;}
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
