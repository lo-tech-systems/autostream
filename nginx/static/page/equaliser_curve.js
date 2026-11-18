var pageData = (function () {
  try { return JSON.parse(document.getElementById('page-data').textContent); }
  catch (e) { return {}; }
})();
var _EQ_BANDS = pageData.eq_bands;

// EQ frequency-response curve
// Constants mirror the Python _CURVE_* values in this module.
var _EQ_FS        = pageData.eq_fs;
var _SVG_W        = pageData.curve.w;
var _SVG_H        = pageData.curve.h;
var _SVG_F_MIN    = pageData.curve.f_min;
var _SVG_F_MAX    = pageData.curve.f_max;
var _SVG_DB_RANGE = pageData.curve.db_range;
var _SVG_PAD_Y    = pageData.curve.pad_y;
var _SVG_N_PTS    = pageData.curve.n_pts;

function _freqToX(f) {
  return _SVG_W * Math.log(f / _SVG_F_MIN) / Math.log(_SVG_F_MAX / _SVG_F_MIN);
}

function _dbToY(db) {
  var c = Math.max(-_SVG_DB_RANGE, Math.min(_SVG_DB_RANGE, db));
  return _SVG_H / 2 - c * (_SVG_H / 2 - _SVG_PAD_Y) / _SVG_DB_RANGE;
}

// RBJ Audio EQ Cookbook biquad coefficients.
// Mirrors BiquadFilter::configure() in autostream_monitor_dsp.cpp exactly.
function _biquadCoeffs(type, f0, q, gainDb) {
  var A      = Math.pow(10.0, gainDb / 40.0);
  var w0     = 2.0 * Math.PI * f0 / _EQ_FS;
  var cos_w0 = Math.cos(w0);
  var sin_w0 = Math.sin(w0);
  var alpha  = sin_w0 / (2.0 * q);
  var b0, b1, b2, a0, a1, a2;
  if (type === 'peak') {
    b0 = 1.0 + alpha * A;  b1 = -2.0 * cos_w0;  b2 = 1.0 - alpha * A;
    a0 = 1.0 + alpha / A;  a1 = -2.0 * cos_w0;  a2 = 1.0 - alpha / A;
  } else if (type === 'low_shelf') {
    var t = 2.0 * Math.sqrt(A) * alpha;
    b0 =      A * ((A+1) - (A-1)*cos_w0 + t);
    b1 =  2*A   * ((A-1) - (A+1)*cos_w0    );
    b2 =      A * ((A+1) - (A-1)*cos_w0 - t);
    a0 =          ((A+1) + (A-1)*cos_w0 + t);
    a1 = -2.0   * ((A-1) + (A+1)*cos_w0    );
    a2 =          ((A+1) + (A-1)*cos_w0 - t);
  } else if (type === 'high_shelf') {
    var t = 2.0 * Math.sqrt(A) * alpha;
    b0 =      A * ((A+1) + (A-1)*cos_w0 + t);
    b1 = -2*A   * ((A-1) + (A+1)*cos_w0    );
    b2 =      A * ((A+1) + (A-1)*cos_w0 - t);
    a0 =          ((A+1) - (A-1)*cos_w0 + t);
    a1 =  2.0   * ((A-1) - (A+1)*cos_w0    );
    a2 =          ((A+1) - (A-1)*cos_w0 - t);
  } else {
    // Unity passthrough
    return {b0:1, b1:0, b2:0, a1:0, a2:0};
  }
  return {b0:b0/a0, b1:b1/a0, b2:b2/a0, a1:a1/a0, a2:a2/a0};
}

// Magnitude response in dB of a normalised biquad at frequency f Hz.
function _biquadMagDb(c, f) {
  var w   = 2.0 * Math.PI * f / _EQ_FS;
  var cw  = Math.cos(w),  c2w = Math.cos(2*w);
  var sw  = Math.sin(w),  s2w = Math.sin(2*w);
  var nr  = c.b0 + c.b1*cw  + c.b2*c2w;
  var ni  =      -(c.b1*sw  + c.b2*s2w);
  var dr  = 1.0  + c.a1*cw  + c.a2*c2w;
  var di  =      -(c.a1*sw  + c.a2*s2w);
  var m2  = (nr*nr + ni*ni) / Math.max(dr*dr + di*di, 1e-30);
  return 10.0 * Math.log(m2) / Math.LN10;
}

function _drawEqCurve() {
  var pathEl = document.getElementById('eq-curve-path');
  if (!pathEl || typeof _EQ_BANDS === 'undefined') return;

  // Build normalised biquad coefficients for every band from current slider values.
  var coeffs = _EQ_BANDS.map(function(b) {
    var sl = document.getElementById(b.key);
    return _biquadCoeffs(b.type, b.freq_hz, b.q, sl ? parseFloat(sl.value) : 0.0);
  });

  // Evaluate total dB at _SVG_N_PTS log-spaced frequencies and build SVG path.
  var d = '';
  for (var i = 0; i <= _SVG_N_PTS; i++) {
    var f  = _SVG_F_MIN * Math.pow(_SVG_F_MAX / _SVG_F_MIN, i / _SVG_N_PTS);
    var db = 0.0;
    for (var j = 0; j < coeffs.length; j++) { db += _biquadMagDb(coeffs[j], f); }
    var px = _freqToX(f), py = _dbToY(db);
    d += (i === 0 ? 'M' : 'L') + px.toFixed(2) + ' ' + py.toFixed(2);
  }
  pathEl.setAttribute('d', d);

  // Update glow fill - same path closed down to the bottom of the SVG.
  var fillEl = document.getElementById('eq-curve-fill');
  if (fillEl) {
    fillEl.setAttribute('d', d + ' L' + _SVG_W + ' ' + _SVG_H + ' L0 ' + _SVG_H + ' Z');
  }

  // Move each handle to the total curve magnitude at its band's centre frequency.
  _EQ_BANDS.forEach(function(b, i) {
    var handle = document.getElementById('eq-handle-' + b.key);
    if (!handle) return;
    var db = 0.0;
    for (var j = 0; j < coeffs.length; j++) { db += _biquadMagDb(coeffs[j], b.freq_hz); }
    handle.setAttribute('cy', _dbToY(db).toFixed(2));
  });
}
