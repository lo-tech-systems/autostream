// Poller -- shared polling helper.
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
