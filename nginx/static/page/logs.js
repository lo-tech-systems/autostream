var pageData = (function () {
  try { return JSON.parse(document.getElementById('page-data').textContent); }
  catch (e) { return {}; }
})();
  var _csrfToken = pageData.csrf_token;
  function _fmtChangedAt(ts) {
    if (!ts) return 'Time unknown';
    try { return new Date(ts).toLocaleString(); } catch(e) { return ts; }
  }
  function _loadLevel() {
    fetch('/api/log-level', {credentials:'same-origin'})
      .then(function(r){return r.json();})
      .then(function(d){
        if (!d.ok) return;
        var sel = document.getElementById('log_level');
        if (sel) sel.value = d.level;
        var meta = document.getElementById('logLevelMeta');
        if (meta) {
          var who = d.changed_by === 'system' ? 'System' : 'User';
          meta.textContent = 'Last changed by ' + who + ' \u00b7 ' + _fmtChangedAt(d.changed_at);
        }
      })
      .catch(function(){});
  }
  document.getElementById('logLevelSaveBtn').addEventListener('click', function() {
    var sel = document.getElementById('log_level');
    if (!sel) return;
    var lvl = sel.value;
    var overlay = document.getElementById('applyingOverlay');
    var msg = document.getElementById('logLevelMsg');
    if (overlay) overlay.classList.add('visible');
    if (msg) msg.textContent = '';
    fetch('/api/log-level', {
      method: 'PUT',
      credentials: 'same-origin',
      headers: {'Content-Type':'application/json','X-CSRF-Token':_csrfToken},
      body: JSON.stringify({level: lvl})
    })
    .then(function(r){return r.json();})
    .then(function(d){
      if (overlay) overlay.classList.remove('visible');
      if (msg) {
        if (d.ok) {
          var ap = d.applied || {};
          var parts = [];
          if (ap.monitor === false) parts.push('monitor not updated');
          if (ap.owntone === false) parts.push('OwnTone not updated');
          if (ap.nginx === false) parts.push('NGINX not updated');
          msg.textContent = parts.length ? 'Saved (partial: ' + parts.join(', ') + ')' : 'Saved';
        } else {
          msg.textContent = 'Error: ' + (d.error || 'save failed');
        }
      }
      if (d.ok) _loadLevel();
    })
    .catch(function(e){
      if (overlay) overlay.classList.remove('visible');
      if (msg) msg.textContent = 'Save failed';
    });
  });
  window.addEventListener('load', function() {
    _loadLevel();
    var w = document.getElementById('logWrapper');
    var b = document.getElementById('logDlBtn');
    var ua = navigator.userAgent || '';
    var isIPhone = /iPhone/.test(ua);
    var isStandalone =
      (window.navigator && window.navigator.standalone === true) ||
      (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches);
    if (b && isIPhone && isStandalone) {
      b.style.display = 'none';
    }
    if (w && b && b.style.display !== 'none') {
      b.style.width = w.offsetWidth + 'px';
    }
  });
