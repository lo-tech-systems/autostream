"""autostream_webui_assets.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Web assets (e.g. CSS) to support the autostream web front-end.
"""

# Shared client-side polling helper.
# Served by nginx as a static file (nginx/static/poll.js) rather than
# inlined -- this Python constant is the drift-guard source of truth,
# checked byte-identical against the static file by
# tests/test_poll_js_sync.py. Unlike the shared theme CSS (nginx/static/theme.css,
# which has no Python copy at all), poll.js still keeps this Python constant
# as its source of truth for the moment.
POLL_JS = """// Poller -- shared polling helper.
//
// One implementation of "visibility-aware interval + in-flight suppression +
// caller-supplied active-control suppression + remote-variant backoff +
// panel-scoped/bounded polling" for every setInterval-based poll loop, so
// each page does not need its own hand-rolled copy of the same pieces of
// logic.
//
// Usage:
//   var p = Poller({
//     url: '/api/status',       // string, or a function returning a string
//     intervalMs: 1500,
//     onData: function(json) { ... },
//     isSuppressed: function() { return false; },   // optional
//     fetchOptions: {},                              // optional, merged into fetch()
//     timeoutMs: 0,                                  // optional AbortController timeout
//     onError: function(res, body) { ... },           // optional: any fetch/non-ok response
//     variant: 'local',                               // 'local' (default) | 'remote'
//     activeOnly: false,                              // true: don't auto-start: caller calls p.start()/p.stop()
//     maxAttempts: 0,                                 // >0: stop permanently after N fired attempts
//     onMaxAttempts: function() { ... },              // optional, called once when maxAttempts is reached
//     classifyError: function(res, body) { ... },     // remote only: return 'definitive' or 'transient'
//     onDefinitiveError: function(res, body) { ... }, // remote only: called once, polling then stops
//   });
//
// Behaviour:
//   - One shared document-level visibilitychange listener pauses every live,
//     currently-running Poller's timer while the tab is hidden, and fires one
//     immediate poll plus resumes the timer on becoming visible again.
//   - Each Poller tracks its own in-flight flag; a tick that fires while the
//     previous request is still outstanding is a no-op (skipped, not queued).
//   - isSuppressed(), when supplied, is checked after the response parses:
//     the request still fires (so server state doesn't drift out of sync
//     with what will be re-rendered once suppression ends) but onData is not
//     called while it returns true.
//   - activeOnly: true means the Poller does NOT start on construction --
//     the caller drives its lifetime explicitly with p.start()/p.stop(),
//     matching a detail panel's own open/close lifecycle (e.g. a Setup
//     card). A stopped activeOnly poller is fully inert: no timer, not
//     resumed by visibilitychange.
//   - maxAttempts: > 0 stops the poller permanently (ignoring visibility)
//     once that many fetches have been fired, optionally invoking
//     onMaxAttempts() once. Matches "poll N times then give up" (bounded
//     probes -- Bluetooth pairing status, dial busy-state, lost-PIN
//     countdown, Repeat Playback's capacity probe).
//   - variant: 'remote' runs a short fixed initial-retry schedule on start
//     (0.5s, 1s, 2s, 4s) before settling into steady-state polling at
//     intervalMs, then tracks a rolling consecutive-failure count: at 3
//     consecutive failures it enters degraded mode (10s cadence) until one
//     poll succeeds, resetting failure count and cadence together in the
//     same tick. classifyError(), when supplied, distinguishes a
//     'definitive' failure (calls onDefinitiveError() once and stops
//     polling outright) from a 'transient' one (feeds the consecutive-
//     failure counter); with no classifyError, every failure is transient.
(function () {
  var __pollers = [];
  var REMOTE_INITIAL_RETRY_SCHEDULE_MS = [500, 1000, 2000, 4000];
  var REMOTE_DEGRADED_INTERVAL_MS = 10000;
  var REMOTE_DEGRADED_THRESHOLD = 3;

  function __currentIntervalMs(p) {
    if (p.variant === 'remote') {
      if (p.retryStep < REMOTE_INITIAL_RETRY_SCHEDULE_MS.length) {
        return REMOTE_INITIAL_RETRY_SCHEDULE_MS[p.retryStep];
      }
      if (p.degraded) return REMOTE_DEGRADED_INTERVAL_MS;
    }
    return p.intervalMs;
  }

  function __scheduleNext(p) {
    if (p.stopped) return;
    if (p.maxAttempts && p.attempts >= p.maxAttempts) {
      p.stopped = true;
      if (p.onMaxAttempts) p.onMaxAttempts();
      return;
    }
    if (p.timer) clearTimeout(p.timer);
    if (p.activeOnly ? !p.running : document.hidden) return;
    p.timer = setTimeout(function () { __fire(p); }, __currentIntervalMs(p));
  }

  function __onSuccess(p, json) {
    if (p.variant === 'remote') {
      if (p.retryStep < REMOTE_INITIAL_RETRY_SCHEDULE_MS.length) p.retryStep = REMOTE_INITIAL_RETRY_SCHEDULE_MS.length;
      p.failCount = 0;
      p.degraded = false;
    }
    if (!(p.isSuppressed && p.isSuppressed())) p.onData(json);
  }

  function __onFailure(p, res, body) {
    if (p.onError) p.onError(res, body);
    if (p.variant !== 'remote') return;
    var kind = p.classifyError ? p.classifyError(res, body) : 'transient';
    if (kind === 'definitive') {
      p.stopped = true;
      if (p.onDefinitiveError) p.onDefinitiveError(res, body);
      return;
    }
    p.failCount += 1;
    if (p.failCount >= REMOTE_DEGRADED_THRESHOLD) p.degraded = true;
  }

  function __fire(p) {
    p.timer = null;
    if (p.inFlight) { __scheduleNext(p); return; }
    p.inFlight = true;
    p.attempts += 1;
    var url = (typeof p.url === 'function') ? p.url() : p.url;
    var opts = Object.assign({ cache: 'no-store' }, p.fetchOptions || {});
    var ctrl = null;
    var timeoutTimer = null;
    if (p.timeoutMs) {
      ctrl = new AbortController();
      opts.signal = ctrl.signal;
      timeoutTimer = setTimeout(function () { ctrl.abort(); }, p.timeoutMs);
    }
    var res = null;
    fetch(url, opts)
      .then(function (r) { res = r; return r.json(); })
      .then(function (j) {
        if (timeoutTimer) clearTimeout(timeoutTimer);
        if (res && !res.ok) { __onFailure(p, res, j); return; }
        __onSuccess(p, j);
      })
      .catch(function () {
        if (timeoutTimer) clearTimeout(timeoutTimer);
        __onFailure(p, res, null);
      })
      .finally(function () {
        p.inFlight = false;
        __scheduleNext(p);
      });
  }

  function __resume(p) {
    if (p.activeOnly && !p.running) return;
    if (p.timer) return;
    __fire(p);
  }

  function __pause(p) {
    if (p.timer) {
      clearTimeout(p.timer);
      p.timer = null;
    }
  }

  document.addEventListener('visibilitychange', function () {
    __pollers.forEach(function (p) {
      if (p.stopped) return;
      if (p.activeOnly && !p.running) return;
      if (document.hidden) {
        __pause(p);
      } else {
        __resume(p);
      }
    });
  });

  window.Poller = function (opts) {
    var p = {
      url: opts.url,
      fetchOptions: opts.fetchOptions || null,
      timeoutMs: opts.timeoutMs || 0,
      intervalMs: opts.intervalMs,
      onData: opts.onData,
      isSuppressed: opts.isSuppressed || null,
      variant: opts.variant || 'local',
      activeOnly: !!opts.activeOnly,
      maxAttempts: opts.maxAttempts || 0,
      onMaxAttempts: opts.onMaxAttempts || null,
      classifyError: opts.classifyError || null,
      onDefinitiveError: opts.onDefinitiveError || null,
      inFlight: false,
      timer: null,
      running: false,
      stopped: false,
      attempts: 0,
      retryStep: 0,
      failCount: 0,
      degraded: false,
    };
    __pollers.push(p);
    // Fire once immediately on construction (matches the initial-call-plus-
    // periodic-timer shape every poll loop needs), then only keep the timer
    // running while the tab is visible -- unless activeOnly, which waits for
    // an explicit p.start() (e.g. a Setup card's detail-panel open).
    if (!p.activeOnly) {
      p.running = true;
      if (!document.hidden) __fire(p);
    }
    p.start = function () {
      if (p.stopped || p.running) return;
      p.running = true;
      if (!document.hidden) __fire(p);
    };
    p.stop = function () {
      p.running = false;
      __pause(p);
    };
    return p;
  };
})();
"""

# Client-side output-card fragment renderer. Served by nginx as a static
# file (nginx/static/render_fragments.js) rather than inlined -- this Python
# constant is the drift-guard source of truth, checked byte-identical
# against the static file by tests/test_render_fragments_js_sync.py,
# mirroring the poll.js/theme.css convention above.
#
# DELIBERATE DUAL-RENDER EXCEPTION: buildOutputCardElement()/
# renderOutputList() are the client-side mirror of the server-rendered
# output-card markup built by output_card_html()
# (core/autostream_webui_components.py) and assembled into the `outputs_html`
# loop in core/autostream_webui_page_airplay.py's send_airplay_page(). The
# remote/proxy Home page has no server-rendered HTML to reuse -- it
# reconstructs the same markup here from polled JSON instead. Any change to
# the output-card markup/classes/data-* attributes on the Python side must be
# mirrored here too (and vice versa), or the local and remote Home pages will
# visibly drift apart. setOutputsPlaceholder() travels with them since
# renderOutputList() is its only caller.
#
# Depends on several small helpers (normalizeVolume, updateVolumeLabel,
# updateOutputStateVisual, reorderOutputCards, updateMasterVolumeCard,
# onToggleOutput, onVolumeChange) that remain defined in HOME_CARDS_SCRIPT --
# safe because these are plain function *declarations*, resolved against the
# shared global scope only when actually called (well after every page
# <script> tag has run), not at parse time, so the relative order of the two
# <script> tags on the page doesn't matter.
RENDER_FRAGMENTS_JS = """function buildOutputCardElement(o) {
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
"""

BANNER_LOGO_HTML = """
  <div class="banner-logo-wrap">
    <a href="/" title="autostream Home" aria-label="autostream Home" class="banner-logo-link">
      <img src="/autostream-badge.png" alt="AutoStream" class="banner-logo banner-logo-light">
      <img src="/autostream-badge-dark.png" alt="AutoStream" class="banner-logo banner-logo-dark">
    </a>
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
  .modal-bd-scroll{max-height:min(60vh,30rem);overflow-y:auto;}
"""

PIN_MODAL_CSS = """
  #pinModal .modal-panel{--modal-width:22rem;}
"""

# Single-OK-button info modal, shared by every page that needs to surface a
# dismissable notice. Pair with INFO_MODAL_SCRIPT, which defines the
# showInfoModal(title, message, isHtml) function driving this markup.
INFO_MODAL_HTML = """
<div id="infoModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="infoModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="infoModalTitle">Notice</div>
    <div class="bd modal-bd modal-bd-scroll">
      <div id="infoModalMessage"></div>
    </div>
    <div class="ft modal-ft">
      <button type="button" class="btn modal-btn modal-btn-primary" id="infoModalOk">OK</button>
    </div>
  </div>
</div>"""

INFO_MODAL_SCRIPT = """
<script>
  function showInfoModal(title, message, isHtml){
    return new Promise((resolve) => {
      const m = document.getElementById('infoModal');
      const titleEl = document.getElementById('infoModalTitle');
      const msgEl = document.getElementById('infoModalMessage');
      const btnOk = document.getElementById('infoModalOk');
      if (!m || !titleEl || !msgEl || !btnOk) {
        // Fallback to native alert if our modal is missing for any reason.
        // HTML messages are not safe/meaningful in a plain alert, so only
        // the title is shown in that case.
        window.alert(isHtml ? title : (title + ': ' + message));
        resolve();
        return;
      }
      titleEl.textContent = title;
      if (isHtml) { msgEl.innerHTML = message; } else { msgEl.textContent = message; }
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
</script>
"""

# Buttonless modal shown by settingsTransact (see AUTOSAVE_JS below) while a
# restart-required setting's daemon restart is in flight. No footer/buttons —
# it dismisses itself once /api/owntone/ready reports the restart finished.
RESTART_MODAL_HTML = """
<div id="restartModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="restartModalTitle">
  <div class="panel modal-panel">
    <div class="hdr modal-hdr" id="restartModalTitle">Applying setting&hellip;</div>
    <div class="bd modal-bd">
      <p>OwnTone is restarting to apply the change. Playback will pause briefly.</p>
    </div>
  </div>
</div>"""

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
#   window.__REPEAT_URL           -- repeat arm/disarm POST endpoint
#                                     (defaults to '/api/repeat' for the
#                                     local page; the remote shell sets
#                                     '/api/appliances/<id>/repeat')
#   window.__PIN_PROMPT_FALLBACK  -- native window.prompt() label used only
#                                     if the PIN modal DOM is missing
#                                     (defaults to 'Enter PIN')
#   window.__REMOTE_HOSTNAME      -- when set, appended to the Now Playing
#                                     header as ' · <hostname>'; the local
#                                     page leaves this unset so its header
#                                     carries no suffix
#   window.__SELECTOR_CURRENT_ID  -- appliance id considered "current" by
#                                     the appliance-selector widget
#
# updateRepeatButton(d) must be called by each page's own poll cycle
# (local: onStatusPollData(); remote: renderHomeState()) with the polled
# status/home dict so the repeat pill (#repeat-btn, rendered by the page
# itself -- hidden by default on the remote shell) stays in sync.

# Shared appliance-selector refresh. Previously defined identically three
# times (here, and twice more in autostream_webui_page_equaliser.py for the
# local/remote Equaliser pages) -- now the one definition, spliced into each
# page's existing <script> block.
# Each page sets a different "current appliance" fallback global today
# (Home: window.__SELECTOR_CURRENT_ID; local Equaliser: window.__LOCAL_ID;
# remote Equaliser: window.__REMOTE_AID) -- all three are consulted here so
# this single definition preserves every page's prior fallback behaviour.
# window.__SELECTOR_CURRENT_PAGE (defaulting to 'home') likewise covers
# Equaliser's prior 'equaliser' default. updateSelectorFromAppliances(),
# which this calls, is still defined per-page (identically) alongside it.
REFRESH_APPLIANCE_SELECTOR_SCRIPT = """  function refreshApplianceSelector(){
    fetch('/api/appliances',{cache:'no-store'})
      .then(function(r){return r.json();})
      .then(function(data){
        if(!data||!data.ok||!Array.isArray(data.appliances)) return;
        var el=document.getElementById('appliance-selector');
        var fallbackId=window.__SELECTOR_CURRENT_ID||window.__LOCAL_ID||window.__REMOTE_AID||'';
        var fallbackPage=window.__SELECTOR_CURRENT_PAGE||'home';
        var currentId=el?(el.getAttribute('data-current-id')||fallbackId):fallbackId;
        var currentPage=el?(el.getAttribute('data-current-page')||fallbackPage):fallbackPage;
        updateSelectorFromAppliances(data.appliances,currentId,currentPage);
      })
      .catch(function(){});
  }
"""

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
    if (hdrEl) hdrEl.textContent = (active ? (sessionSource === 'replay' ? 'Repeat Play' : 'Now Playing') : 'Ready') + hdrSuffix;
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
    var isBluetooth = !!inputSnap.is_bluetooth;
    // Precedence: turntable wins over bluetooth-ness (mirrors the server's
    // _default_nowplaying_title / _np_icon_kind derivation).
    var iconKind = isTurntable ? 'turntable' : (isBluetooth ? 'bluetooth' : 'line');
    var iconSvgByKind = {
      turntable: window.__ICON_TURNTABLE,
      bluetooth: window.__ICON_BLUETOOTH,
      line: window.__ICON_LINE_LEVEL,
    };
    var iconLabelByKind = { turntable: 'Vinyl', bluetooth: 'Bluetooth', line: 'Line In' };
    var typeLabelByKind = { turntable: 'Turntable', bluetooth: 'Bluetooth', line: 'Line Level' };
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
            iconEl.innerHTML = iconSvgByKind[iconKind];
            iconEl.classList.remove('np-icon-art');
          }
        }
      }
    } else if (tiEnabled) {
      var inputPrefix = iconLabelByKind[iconKind];
      var suffix;
      if (tiState === 'error') { suffix = 'Track ID function not available'; }
      else if (tiState === 'not_found') { suffix = 'Unknown track'; }
      else { suffix = 'Identifying Track…'; }
      if (nameEl) nameEl.textContent = inputPrefix + ' – ' + suffix;
      if (signalEl) signalEl.textContent = '';
      var svgKey = 'svg:' + iconKind;
      if (iconEl && iconEl.getAttribute('data-np-icon-key') !== svgKey) {
        iconEl.setAttribute('data-np-icon-key', svgKey);
        iconEl.innerHTML = iconSvgByKind[iconKind];
        iconEl.classList.remove('np-icon-art');
      }
    } else {
      if (nameEl) nameEl.textContent = label + ' · ' + typeLabelByKind[iconKind];
      if (signalEl) signalEl.textContent = signalParts.join(' · ');
      var svgKey2 = 'svg:' + iconKind;
      if (iconEl && iconEl.getAttribute('data-np-icon-key') !== svgKey2) {
        iconEl.setAttribute('data-np-icon-key', svgKey2);
        iconEl.innerHTML = iconSvgByKind[iconKind];
        iconEl.classList.remove('np-icon-art');
      }
    }
    if (!usingReplayOrigin) vuIngestHistory(activeIdx, activeLevel.vu_history);
  }

  function _fmtRepeatTime(s){
    s = Math.max(0, Math.round(Number(s) || 0));
    var m = Math.floor(s / 60), r = s % 60;
    return m + ':' + (r < 10 ? '0' : '') + r;
  }
  // __repeatOptimistic holds the click's immediate intent until the polled
  // truth agrees with it (or a fallback timeout elapses): { active, kind,
  // ts }. kind is 'start' or 'stop' -- 'stop' gets a longer fallback window
  // (REPEAT_STOP_OPTIMISTIC_TIMEOUT_MS) because it also has to cover the
  // fade-out phase, which the server now reports explicitly via
  // repeat.replay.fading_out (see updateRepeatButton's 'stopping' state
  // below) so the button doesn't just go dead for the fade (kFadeSeconds,
  // core/monitor/autostream_monitor.h -- currently 1.0 s).
  var __repeatOptimistic = null;
  var REPEAT_START_OPTIMISTIC_TIMEOUT_MS = 5000;
  var REPEAT_STOP_OPTIMISTIC_TIMEOUT_MS = 10000;

  // No master-volume writes are made anywhere in this stop/fade flow --
  // 'stopping' is purely a visual/feedback state (label, disabled button,
  // page quiesce class); it never touches output/appliance volume.
  function updateRepeatButton(d){
    var btn = document.getElementById('repeat-btn');
    if (!btn) return;
    var repeat = (d && d.repeat) || null;
    if (!repeat || !repeat.enabled) {
      btn.hidden = true;
      __repeatOptimistic = null;
      _setRepeatStopping(false);
      return;
    }
    btn.hidden = false;
    var recording = repeat.recording || {};
    var replay = repeat.replay || {};
    var armed = !!repeat.armed;
    var replaying = !!replay.active;
    var fadingOut = !!replay.fading_out;
    var hasBuffer = Number(recording.bytes || 0) > 0;
    var polledOn = replaying || armed;
    var session = (d && d.session) || null;
    var sessionActive = (session && typeof session.active === 'boolean') ? !!session.active : null;

    // Optimistic-click reconciliation: hold the click's immediate
    // visual state until the polled truth agrees with it, or the
    // fallback timeout elapses -- the stop/start fade (kFadeSeconds,
    // core/monitor/autostream_monitor.h) means
    // polled state lags the click, and without this the button would
    // flicker back mid-fade.
    var on = polledOn;
    var state = replaying ? 'repeating' : (armed ? 'armed' : 'off');
    var optimisticStopPending = false;
    if (__repeatOptimistic) {
      optimisticStopPending = (__repeatOptimistic.kind === 'stop' && __repeatOptimistic.active === false);
      var timeoutMs = (__repeatOptimistic.kind === 'stop')
        ? REPEAT_STOP_OPTIMISTIC_TIMEOUT_MS
        : REPEAT_START_OPTIMISTIC_TIMEOUT_MS;
      // The stop confirms complete once the server reports the replay
      // fully gone (not just no-longer-fading): active false AND
      // fading_out false. Until then, keep the optimistic 'stopping'
      // visual even if a single poll briefly reports active=false while
      // fading_out lags (defensive against ordering, though the daemon
      // sets both from the same _state read).
      var stopConfirmed = optimisticStopPending && !replaying && !fadingOut;
      var agrees = optimisticStopPending ? stopConfirmed : (__repeatOptimistic.active === polledOn);
      var expired = (Date.now() - __repeatOptimistic.ts) >= timeoutMs;
      if (agrees || expired) {
        __repeatOptimistic = null;
        optimisticStopPending = false;
      } else {
        on = __repeatOptimistic.active;
        state = on ? (replaying ? 'repeating' : 'armed') : 'off';
      }
    }

    // 'stopping' state: the single derivation point for fade-out
    // feedback. True while either the optimistic stop click hasn't been
    // confirmed yet (covers the click-to-poll-catch-up window, including
    // while the server still reports replay.active true), or the server
    // itself reports the fade in flight with no local optimistic state
    // at all (e.g. a second tab, or a page load that lands mid-fade).
    var stopping = optimisticStopPending || fadingOut;
    if (stopping) state = 'stopping';

    btn.setAttribute('data-state', state);
    btn.classList.toggle('active', on || stopping);
    btn.disabled = stopping || (!hasBuffer && !replaying && !on);

    // 'Replay Last' only makes sense when nothing is authoritatively
    // playing right now: with a session block, gate it on
    // !sessionActive too so it never flashes while a live source (e.g.
    // a CD) is already playing at start-up. Legacy backends with no
    // session block keep the pre-existing gating.
    var showReplayLast = (sessionActive === null)
      ? (!on && hasBuffer)
      : (!sessionActive && !on && hasBuffer && !armed && !replaying);
    btn.textContent = stopping ? 'Stopping…' : (showReplayLast ? '↻ Replay Last' : '↻ Repeat Play');

    if (!__repeatOptimistic) {
      var title = '';
      if (replaying) {
        var pos = _fmtRepeatTime(replay.position_seconds), dur = _fmtRepeatTime(replay.duration_seconds);
        title = pos + ' / ' + dur;
        // truncated_head is the DEFINED wrap semantic (keeps the last N
        // minutes), not a pressure symptom -- the suffix describes what's
        // held, not what was lost.
        if (recording.truncated_head) title += ' · most recent kept';
      } else if (armed) {
        title = recording.active ? 'Buffering…' : 'Waiting for playback';
      }
      btn.title = title;
    }

    _setRepeatStopping(stopping);
  }

  // Single page-quiesce choke point: toggles body.repeat-stopping and
  // inert on the sibling controls (never on #repeat-btn itself, which is
  // the feedback element and must stay visible + interactive-looking,
  // though disabled). No per-control special-casing anywhere else.
  function _repeatStoppingInertTargets(){
    var ids = ['now-playing-card', 'outputs-list'];
    var targets = [];
    for (var i = 0; i < ids.length; i++) {
      var el = document.getElementById(ids[i]);
      if (el) targets.push(el);
    }
    // Any other direct child of .airplay-top-controls besides the repeat
    // button itself -- covers the appliance-selector widget, which lives
    // in that row as a sibling of #repeat-btn on both the local and
    // remote pages. Walking siblings (rather than inerting the shared
    // container) is what lets the button stay interactive-looking while
    // everything around it quiesces.
    var topControls = document.querySelector('.airplay-top-controls');
    if (topControls) {
      var kids = topControls.children;
      for (var j = 0; j < kids.length; j++) {
        var kid = kids[j];
        if (kid.id === 'repeat-btn') continue;
        if (targets.indexOf(kid) === -1) targets.push(kid);
      }
    }
    return targets;
  }
  var __repeatStoppingActive = false;
  function _setRepeatStopping(stopping){
    stopping = !!stopping;
    if (stopping === __repeatStoppingActive) return;
    __repeatStoppingActive = stopping;
    document.body.classList.toggle('repeat-stopping', stopping);
    var targets = _repeatStoppingInertTargets();
    for (var i = 0; i < targets.length; i++) {
      if (stopping) {
        targets[i].setAttribute('inert', '');
      } else {
        targets[i].removeAttribute('inert');
      }
    }
  }

  function onRepeatButtonClick(){
    var btn = document.getElementById('repeat-btn');
    if (!btn || btn.disabled) return;
    var wasActive = btn.classList.contains('active');
    var state = btn.getAttribute('data-state');
    // repeating -> stop replay; armed -> disarm; off -> arm (starts replay
    // immediately if idle with a buffer, or arms for stream-end if playing live).
    var newArmed = (state === 'repeating' || state === 'armed') ? false : true;
    // Two very different clicks both disarm, and only one of them stops
    // anything: 'repeating' interrupts a replay that now has to fade out,
    // while 'armed' merely cancels a pending action -- the true source is
    // still playing and nothing fades. Giving the 'armed' case the stop
    // treatment would flash "Stopping…" and quiesce the page for a
    // teardown that never happens, so it gets its own kind.
    var kind = newArmed ? 'start' : (state === 'repeating' ? 'stop' : 'disarm');
    // Apply the optimistic visual state immediately: don't wait for the
    // POST to resolve before flipping the class/label, so the click
    // feels instant even though the fade (kFadeSeconds, core/monitor/
    // autostream_monitor.h) means the polled truth
    // will lag behind for a while. Stop clicks disable the button too --
    // closes the double-click-during-fade hole where a second click
    // mid-fade could re-arm/re-stop against a session that's already
    // tearing down.
    __repeatOptimistic = { active: newArmed, kind: kind, ts: Date.now() };
    if (kind === 'stop') {
      // 'active' (the accent-outline styling) stays true through the stop
      // click -- the button remains the visible feedback element while
      // stopping, it just swaps its label/disabled state; only a confirmed
      // 'off' clears the outline.
      btn.classList.add('active');
      btn.setAttribute('data-state', 'stopping');
      btn.textContent = 'Stopping…';
      btn.title = 'Stopping…';
      btn.disabled = true;
    } else if (kind === 'disarm') {
      // Straight to the off look, button still live. The label is left
      // alone: it already reads '↻ Repeat Play' while armed, and the next
      // poll settles it (e.g. to '↻ Replay Last' if the source has since
      // gone idle with a buffer).
      btn.classList.remove('active');
      btn.setAttribute('data-state', 'off');
      btn.title = '';
      btn.disabled = false;
    } else {
      btn.classList.add('active');
      btn.setAttribute('data-state', 'armed');
      btn.textContent = '↻ Repeat Play';
      btn.title = 'Starting…';
      btn.disabled = false;
    }
    // Only a genuine fade quiesces the page. A stale 'armed' reading (a
    // replay that started between the last poll and the click) still gets
    // the full stopping treatment from the server's own fading_out flag on
    // the next poll, so nothing is lost by being conservative here.
    _setRepeatStopping(kind === 'stop');
    fetch(window.__REPEAT_URL || '/api/repeat', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.__CSRF || '' },
      body: JSON.stringify({ armed: newArmed })
    }).then(function(r){ return r.json(); }).then(function(d){
      if (!d || !d.ok) {
        __repeatOptimistic = null;
        btn.classList.toggle('active', wasActive);
        btn.disabled = false;
        _setRepeatStopping(false);
      }
    }).catch(function(){
      __repeatOptimistic = null;
      btn.classList.toggle('active', wasActive);
      btn.disabled = false;
      _setRepeatStopping(false);
    });
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
""" + REFRESH_APPLIANCE_SELECTOR_SCRIPT + """</script>
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

ICON_BLUETOOTH = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 258"'
    ' fill="none" stroke="var(--color-accent)" stroke-width="7"'
    ' stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M9 74 L119 184 L64 239 L64 19 L119 74 L9 184"/>'
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
# Shared autosave controller for POST /api/settings
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

  // Buttonless "Applying setting…" modal for restart-required autosaves. The
  // restart itself is coalesced 0.75s after the save response, so an
  // immediate ready-poll can see the daemon still up with no restart in
  // progress — dismissal therefore waits for either an observed in_progress
  // state or a minimum elapsed window before trusting "not in progress" as
  // "finished". A hard timeout gives up and reports failure via the status
  // line instead of polling forever.
  var _restartPollTimer = null;
  var _restartHardTimer = null;
  var _restartSawInProgress = false;
  var _restartStartedAt = 0;
  var _restartLastMessage = '';

  function _restartModalEl() {
    return document.getElementById('restartModal');
  }

  function _restartDismiss(statusMessage) {
    var m = _restartModalEl();
    if (m) m.classList.remove('show');
    if (_restartPollTimer) { clearTimeout(_restartPollTimer); _restartPollTimer = null; }
    if (_restartHardTimer) { clearTimeout(_restartHardTimer); _restartHardTimer = null; }
    if (statusMessage) _setStatus(statusMessage);
  }

  function _restartPoll() {
    fetch('/api/owntone/ready', {cache: 'no-store'}).then(function(r) { return r.json(); }).then(function(j) {
      var restart = j.restart || {};
      if (restart.message) _restartLastMessage = restart.message;
      if (restart.in_progress) _restartSawInProgress = true;
      var elapsed = Date.now() - _restartStartedAt;
      if (j.ok && !restart.in_progress && (_restartSawInProgress || elapsed >= 3000)) {
        // A restart that ran and failed leaves the daemon up but the change
        // unapplied — surface its message rather than dismissing silently.
        if (_restartSawInProgress && restart.ok === false) {
          _restartDismiss(_restartLastMessage || 'OwnTone restart failed');
        } else {
          _restartDismiss();
        }
        return;
      }
      _restartPollTimer = setTimeout(_restartPoll, 1000);
    }).catch(function() {
      _restartPollTimer = setTimeout(_restartPoll, 1000);
    });
  }

  function _restartBegin() {
    var m = _restartModalEl();
    if (!m) return;  // page has no restart modal — degrade to no-op
    m.classList.add('show');
    _restartSawInProgress = false;
    _restartStartedAt = Date.now();
    _restartLastMessage = '';
    if (_restartPollTimer) clearTimeout(_restartPollTimer);
    if (_restartHardTimer) clearTimeout(_restartHardTimer);
    _restartPollTimer = setTimeout(_restartPoll, 1000);
    _restartHardTimer = setTimeout(function() {
      _restartDismiss(_restartLastMessage || 'OwnTone restart timed out');
    }, 30000);
  }

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
      if (d.restart_required) { _restartBegin(); }
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
