// goertzel-processor.js
// AudioWorkletProcessor that runs a two-frequency Goertzel detector
// (nominally 1000 Hz and 1250 Hz) over ~100ms windows, and a faster
// envelope check on the 1000 Hz tone for burst-onset timing.
//
// Detection is relative to an adaptive per-frequency noise floor rather
// than a fixed magnitude threshold, since real-room background noise
// varies a lot between devices and environments. Each tracked frequency
// keeps a slow running average of its own "quiet" magnitude, and a burst
// is flagged once the live magnitude rises a configurable multiple above
// that floor (falling back to a small absolute floor while the average
// is still being seeded, and while the room is essentially silent).
//
// Messages posted to the main thread:
//   { type: 'level', sample, f1, f2, floor1, floor2, active1, active2, rmsDb }
//                                                     -- roughly every 100ms
//                                                     -- rmsDb: broadband RMS
//                                                        of the same window,
//                                                        in dBFS (-90..0)
//   { type: 'onset', sample }                         -- on each rising edge
//
// Messages accepted from the main thread:
//   { type: 'setThreshold', value }        -- onset sensitivity, expressed
//                                              as a magnitude multiple (K_HIGH)
//                                              over the tracked noise floor
//   { type: 'reset' }                      -- clears the adaptive noise-floor
//                                              state for all bins; sent on a
//                                              capture-profile switch, since
//                                              the new profile's gain scale
//                                              invalidates the old floor
//
// "sample" is the running audio-clock sample count since the worklet
// was created (i.e. derived from the sample rate, not Date.now()).

// The floor tracker is asymmetric: it falls quickly and rises very slowly,
// with no seed phase and no quiet-gating. A tone already sounding when the
// mic opens therefore cannot poison the floor for long (symmetric or
// quiet-gated trackers latch onto a continuous tone and then nothing can
// ever trigger), and a short burst barely lifts it.
const FLOOR_RISE_ALPHA = 0.005; // per analysis window, magnitude above floor
const FLOOR_FALL_ALPHA = 0.1;   // per analysis window, magnitude below floor
const FLOOR_MIN = 1e-5;         // floor never allowed to collapse below this
const ONSET_ABS_MIN = 1e-4;     // absolute floor under the SNR trigger, for near-silent rooms
const ABS_TRIGGER = 0.01;       // magnitude that always triggers (~-40dBFS narrowband),
                                // regardless of floor history
const K_LOW = 0.5;              // release level, as a fraction of the trigger level

class GoertzelProcessor extends AudioWorkletProcessor {
  constructor(options) {
    super();

    const opts = (options && options.processorOptions) || {};
    this.f1 = opts.f1 || 1000;
    this.f2 = opts.f2 || 1250;
    this.kHigh = typeof opts.kHigh === 'number' ? opts.kHigh : 8;

    // ~100ms analysis window for the level bars.
    this.windowSize = Math.max(256, Math.round(sampleRate * 0.1));
    this.windowBuf = new Float32Array(this.windowSize);
    this.windowFill = 0;

    // Shorter window for onset envelope tracking (~10ms), refreshed
    // every incoming render block so onset timing has decent resolution.
    this.envSize = Math.max(128, Math.round(sampleRate * 0.01));
    this.envBuf = new Float32Array(this.envSize);
    this.envFill = 0;

    this.sampleCount = 0;

    // Adaptive noise-floor state, one bin per tracked frequency/window
    // combination.
    this.levelBin1 = this.makeBin();
    this.levelBin2 = this.makeBin();
    this.envBin1 = this.makeBin();

    this.port.onmessage = (e) => {
      const msg = e.data;
      if (!msg) return;
      if (msg.type === 'setThreshold' && typeof msg.value === 'number') {
        this.kHigh = msg.value;
      } else if (msg.type === 'reset') {
        this.levelBin1 = this.makeBin();
        this.levelBin2 = this.makeBin();
        this.envBin1 = this.makeBin();
      }
    };
  }

  makeBin() {
    return { floor: FLOOR_MIN, active: false };
  }

  // Updates one adaptive-floor bin with a fresh magnitude reading and
  // returns { active, onset, floor }. `onset` is true only on the exact
  // window where the bin transitions from inactive to active. The trigger
  // is capped at ABS_TRIGGER so a strong tone always detects even while
  // the floor is still recovering from contamination.
  updateBin(bin, magnitude) {
    const trigger = Math.min(Math.max(ONSET_ABS_MIN, this.kHigh * bin.floor), ABS_TRIGGER);
    const release = trigger * K_LOW;

    let onset = false;
    if (!bin.active && magnitude > trigger) {
      bin.active = true;
      onset = true;
    } else if (bin.active && magnitude < release) {
      bin.active = false;
    }

    const alpha = magnitude > bin.floor ? FLOOR_RISE_ALPHA : FLOOR_FALL_ALPHA;
    bin.floor = Math.max(FLOOR_MIN, bin.floor + alpha * (magnitude - bin.floor));

    return { active: bin.active, onset: onset, floor: bin.floor };
  }

  goertzel(samples, freq) {
    const n = samples.length;
    const k = Math.round((n * freq) / sampleRate);
    const w = (2 * Math.PI * k) / n;
    const cosine = Math.cos(w);
    const coeff = 2 * cosine;
    let q0 = 0, q1 = 0, q2 = 0;
    for (let i = 0; i < n; i++) {
      q0 = coeff * q1 - q2 + samples[i];
      q2 = q1;
      q1 = q0;
    }
    const real = q1 - q2 * cosine;
    const imag = q2 * Math.sin(w);
    const magnitude = Math.sqrt(real * real + imag * imag);
    // Rough normalisation so a full-scale sine lands near 1.0.
    return magnitude / (n / 2);
  }

  // Broadband RMS of a sample window, in dBFS, clamped to -90..0. Used for
  // the always-on input level meter so gain differences between capture
  // profiles are visible even without a tone playing.
  rmsDb(buf) {
    let sum = 0;
    for (let i = 0; i < buf.length; i++) sum += buf[i] * buf[i];
    const rms = Math.sqrt(sum / buf.length);
    const db = 20 * Math.log10(Math.max(rms, 1e-9));
    return Math.max(-90, Math.min(0, db));
  }

  process(inputs) {
    const input = inputs[0];
    if (!input || input.length === 0 || !input[0] || input[0].length === 0) {
      return true;
    }
    const channel = input[0];
    const blockLen = channel.length;

    for (let i = 0; i < blockLen; i++) {
      const s = channel[i];

      // --- 100ms window for level bars ---
      this.windowBuf[this.windowFill++] = s;
      if (this.windowFill >= this.windowSize) {
        const f1level = this.goertzel(this.windowBuf, this.f1);
        const f2level = this.goertzel(this.windowBuf, this.f2);
        const rmsDbVal = this.rmsDb(this.windowBuf);
        const r1 = this.updateBin(this.levelBin1, f1level);
        const r2 = this.updateBin(this.levelBin2, f2level);
        this.port.postMessage({
          type: 'level',
          sample: this.sampleCount + i,
          f1: f1level,
          f2: f2level,
          floor1: r1.floor,
          floor2: r2.floor,
          active1: r1.active,
          active2: r2.active,
          rmsDb: rmsDbVal
        });
        this.windowFill = 0;
      }

      // --- ~10ms window for onset envelope on f1 ---
      this.envBuf[this.envFill++] = s;
      if (this.envFill >= this.envSize) {
        const envLevel = this.goertzel(this.envBuf, this.f1);
        this.envFill = 0;

        const r = this.updateBin(this.envBin1, envLevel);
        if (r.onset) {
          this.port.postMessage({
            type: 'onset',
            sample: this.sampleCount + i
          });
        }
      }
    }

    this.sampleCount += blockLen;
    return true;
  }
}

registerProcessor('goertzel-processor', GoertzelProcessor);
