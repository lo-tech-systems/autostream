(function() {
  var _csrf = window.__CSRF || '';
  var _statusEl = null;
  var _pendingTimers = {};    // field -> {timer, value}
  var _pendingRequests = {};  // field -> {ctrl, promise}

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
    _setStatus('Saving\u2026');
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
        _setStatus('Could not save \u2014 ' + (d.error || 'error'));
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

  // Buttonless "Applying setting..." modal for restart-required autosaves. The
  // restart itself is coalesced 0.75s after the save response, so an
  // immediate ready-poll can see the daemon still up with no restart in
  // progress -- dismissal therefore waits for either an observed in_progress
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
        // unapplied -- surface its message rather than dismissing silently.
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
    if (!m) return;  // page has no restart modal -- degrade to no-op
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
    _setStatus('Applying\u2026');
    fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': _csrf},
      body: JSON.stringify(payload)
    }).then(function(r) { return r.json(); }).then(function(d) {
      if (!d.ok) {
        _setStatus('Could not apply \u2014 ' + (d.error || 'error'));
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
