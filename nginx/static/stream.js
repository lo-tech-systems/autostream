// StateStream -- the appliance's change stream, resumed across reconnects.
//
// Usage:
//   var s = StateStream({
//     url: '/api/v1/events',
//     onChange: function(parts, resync) { ... },  // parts: array of part names
//     onUp: function() { ... },                   // the stream is open
//     onDown: function() { ... },                 // it is not, and will not be soon
//     graceMs: 5000,       // a dropped stream that is not open again within this is down
//     retryMs: 30000,      // wait before opening again a stream the browser gave up on
//   });
//   s.isUp(); s.restart(); s.close();
//
// Behaviour:
//   - Opens only while the document is visible. Hidden: closes the stream
//     (the server frees the slot within a second) and calls nothing.
//     Visible again: opens with ?since=<last id>, so the first event says
//     only what moved meanwhile.
//   - The browser's own reconnect (after the server ends a stream, or a
//     network blip) sends Last-Event-ID; the page is not told unless the
//     stream stays closed past graceMs.
//   - A stream the browser gives up on (a refusal, a redirect, a non-stream
//     reply) is down at once, and is opened again after retryMs with up to
//     20 percent jitter, so eight refused tabs do not retry together.
//   - No EventSource in the browser: down at once, never opened.
//   - isUp() stays true while the page is hidden and the stream was up when
//     it was closed; a page that is hidden has nothing to fetch and must not
//     fall back to polling for that reason.
(function () {
  window.StateStream = function (opts) {
    var url = opts.url;
    var graceMs = opts.graceMs || 5000;
    var retryMs = opts.retryMs || 30000;
    var es = null;
    var up = false;
    var lastId = '';
    var graceTimer = null;
    var retryTimer = null;
    var gone = false;

    function call(fn, a, b) {
      if (typeof fn !== 'function') return;
      try { fn(a, b); } catch (e) {}
    }
    function clearGrace() {
      if (graceTimer) { clearTimeout(graceTimer); graceTimer = null; }
    }
    function clearRetry() {
      if (retryTimer) { clearTimeout(retryTimer); retryTimer = null; }
    }
    function closeStream() {
      if (es) {
        var old = es;
        es = null;
        try { old.close(); } catch (e) {}
      }
    }
    function goDown() {
      if (!up) return;
      up = false;
      call(opts.onDown);
    }
    function scheduleRetry() {
      clearRetry();
      var wait = retryMs * (0.8 + Math.random() * 0.4);
      retryTimer = setTimeout(function () {
        retryTimer = null;
        if (!gone && !document.hidden) open();
      }, wait);
    }

    function open() {
      if (gone || es || !window.EventSource || document.hidden) return;
      var target = url + (lastId ? '?since=' + encodeURIComponent(lastId) : '');
      var src;
      try { src = new EventSource(target); } catch (e) { return; }
      es = src;
      src.addEventListener('open', function () {
        if (src !== es) return;
        clearGrace();
        if (!up) { up = true; call(opts.onUp); }
      });
      src.addEventListener('change', function (ev) {
        if (src !== es) return;
        if (ev.lastEventId) lastId = ev.lastEventId;
        var d = null;
        try { d = JSON.parse(ev.data); } catch (e) { return; }
        if (!d) return;
        call(opts.onChange, Array.isArray(d.parts) ? d.parts : [], !!d.resync);
      });
      src.addEventListener('error', function () {
        if (src !== es) return;
        if (src.readyState === 2) {
          closeStream();
          clearGrace();
          goDown();
          scheduleRetry();
        } else if (!graceTimer) {
          graceTimer = setTimeout(function () {
            graceTimer = null;
            goDown();
          }, graceMs);
        }
      });
    }

    function restart() {
      closeStream();
      clearGrace();
      clearRetry();
      open();
    }

    document.addEventListener('visibilitychange', function () {
      if (gone) return;
      if (document.hidden) {
        closeStream();
        clearGrace();
        clearRetry();
      } else if (!es && !retryTimer) {
        open();
      }
    });
    window.addEventListener('pagehide', function () {
      closeStream();
      clearGrace();
      clearRetry();
    });

    open();

    return {
      isUp: function () { return up; },
      restart: restart,
      close: function () {
        gone = true;
        closeStream();
        clearGrace();
        clearRetry();
        up = false;
      },
    };
  };
})();
