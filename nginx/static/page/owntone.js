var pageData = (function () {
  try { return JSON.parse(document.getElementById('page-data').textContent); }
  catch (e) { return {}; }
})();
const liveEnabled = pageData.live_enabled === true;
function onShowToggle(i, checked) {
  document.getElementById('spk_settings_' + i).style.display = checked ? 'block' : 'none';
}
var _owntoneTimers = {};
function _owntoneOffsetSync(i, offsetMs) {
  var slider = document.getElementById('off_slider_' + i);
  var val = document.getElementById('off_val_' + i);
  if (slider) slider.value = offsetMs;
  if (val) val.textContent = offsetMs + ' ms';
}
function _owntoneOffsetDebounced(i, outputId, offsetMs) {
  clearTimeout(_owntoneTimers['offset_' + outputId]);
  _owntoneTimers['offset_' + outputId] = setTimeout(function() {
    settingsTransact('/api/owntone/output-offset', {output_id: outputId, offset_ms: offsetMs}, {
      onSuccess: function(d) { _owntoneOffsetSync(i, d.offset_ms); }
    });
  }, 300);
}
function _owntoneOffsetReset(i, outputId) {
  _owntoneOffsetSync(i, 0);
  if (liveEnabled) _owntoneOffsetDebounced(i, outputId, 0);
}
