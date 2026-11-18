var pageData = (function () {
  try { return JSON.parse(document.getElementById('page-data').textContent); }
  catch (e) { return {}; }
})();
const liveEnabled = pageData.live_enabled === true;
function onShowToggle(i, checked) {
  document.getElementById('spk_settings_' + i).style.display = checked ? 'block' : 'none';
}
var _owntoneTimers = {};
var OFFSET_MIN_MS = -2000;
var OFFSET_MAX_MS = 2000;
function _owntoneOffsetSync(i, offsetMs) {
  var val = document.getElementById('off_val_' + i);
  if (val) {
    val.dataset.offset = offsetMs;
    val.textContent = offsetMs;
  }
  var stepper = document.getElementById('off_stepper_' + i);
  if (stepper) {
    stepper.querySelectorAll('[data-step]').forEach(function(b) {
      var next = offsetMs + parseInt(b.dataset.step, 10);
      b.disabled = next < OFFSET_MIN_MS || next > OFFSET_MAX_MS;
    });
  }
}
function _owntoneOffsetDebounced(i, outputId, offsetMs) {
  clearTimeout(_owntoneTimers['offset_' + outputId]);
  _owntoneTimers['offset_' + outputId] = setTimeout(function() {
    settingsTransact('/api/owntone/output-offset', {output_id: outputId, offset_ms: offsetMs}, {
      onSuccess: function(d) { _owntoneOffsetSync(i, d.offset_ms); }
    });
  }, 300);
}
function _owntoneOffsetStep(i, outputId, stepMs) {
  var val = document.getElementById('off_val_' + i);
  var current = val ? parseInt(val.dataset.offset, 10) || 0 : 0;
  var next = Math.max(OFFSET_MIN_MS, Math.min(OFFSET_MAX_MS, current + stepMs));
  _owntoneOffsetSync(i, next);
  if (liveEnabled) _owntoneOffsetDebounced(i, outputId, next);
}
function _owntoneOffsetReset(i, outputId) {
  _owntoneOffsetSync(i, 0);
  if (liveEnabled) _owntoneOffsetDebounced(i, outputId, 0);
}
