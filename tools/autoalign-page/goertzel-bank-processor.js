// goertzel-bank-processor.js
// AudioWorkletProcessor that runs a Goertzel detector bank, one bin per
// distinct output frequency, over short (~10ms) analysis windows. Each
// window is used both to timestamp burst onsets (with hysteresis, on the
// audio-clock sample counter) and to report a live "loudest bin" level for
// on-screen feedback.
//
// Detection is relative to an adaptive per-frequency noise floor rather
// than a fixed magnitude threshold, since real-room background noise
// varies a lot between devices and environments. Each bin keeps a slow
// running average of its own "quiet" magnitude, and a burst is flagged
// once the live magnitude rises a configurable multiple above that floor
// (falling back to a small absolute floor while the average is still
// being seeded, and while the room is essentially silent).
//
// Messages posted to the main thread:
//   { type: 'onset', sample, freqIndex }   -- rising edge on freqs[freqIndex]
//   { type: 'level', sample, freqIndex, value, floor, active }
//                                           -- throttled loudest-bin level
//
// Messages accepted from the main thread:
//   { type: 'setThreshold', value }        -- onset sensitivity, expressed
//                                              as a magnitude multiple (K_HIGH)
//                                              over each bin's tracked floor
//
// "sample" is a running audio-clock sample count since the worklet was
// created (derived from sampleRate, not Date.now()), matching the timing
// idiom proven in tools/autoalign-spike/goertzel-processor.js.
//
// Onset attribution assumes at most one frequency is genuinely active at a
// time (the appliance solos one output, hence one frequency, at once). If a
// window shows more than one bin above its own trigger level simultaneously,
// it is treated as transition noise between bursts and no onset is emitted.
// This attribution rule, and all downstream clustering, is unchanged by the
// switch to adaptive floors -- only the per-bin active/onset decision below
// is different.

const FLOOR_ALPHA = 0.02;      // per ~10ms hop, while at/below the release level
const FLOOR_SEED_WINDOWS = 10; // hops averaged to seed each bin's initial floor
const FLOOR_MIN = 1e-5;        // floor never allowed to collapse below this
const ONSET_ABS_MIN = 1e-4;    // absolute floor under the SNR trigger, for near-silent rooms
const K_LOW = 0.5;             // release level, as a fraction of the trigger level

class GoertzelBankProcessor extends AudioWorkletProcessor {
  constructor(options) {
    super();

    const opts = (options && options.processorOptions) || {};
    this.freqs = (Array.isArray(opts.freqs) && opts.freqs.length) ? opts.freqs : [1000];
    this.kHigh = typeof opts.kHigh === 'number' ? opts.kHigh : 8;

    // ~10ms analysis/onset window, matching the spike's envelope window.
    this.envSize = Math.max(128, Math.round(sampleRate * 0.01));
    this.envBuf = new Float32Array(this.envSize);
    this.envFill = 0;

    this.sampleCount = 0;
    this.bins = this.freqs.map(() => ({ floor: null, seedSum: 0, seedCount: 0, active: false }));

    // Throttle 'level' messages so the port doesn't get ~100/s of traffic.
    this.hopCount = 0;
    this.levelHopStride = 4; // ~every 4th ~10ms hop, roughly 25-40ms

    this.port.onmessage = (e) => {
      const msg = e.data;
      if (msg && msg.type === 'setThreshold' && typeof msg.value === 'number') {
        this.kHigh = msg.value;
      }
    };
  }

  // Seeds (or reads) one bin's adaptive floor and returns the trigger and
  // release levels derived from it. While still seeding, both are Infinity
  // so the bin can never register as "above" until it has a real floor.
  // Does not decide active/onset -- the "exactly one frequency above"
  // attribution rule spans all bins at once, so that decision is made by
  // the caller in process() once every bin's trigger is known.
  triggerFor(bin, magnitude) {
    if (bin.floor === null) {
      bin.seedSum += magnitude;
      bin.seedCount++;
      if (bin.seedCount >= FLOOR_SEED_WINDOWS) {
        bin.floor = Math.max(FLOOR_MIN, bin.seedSum / bin.seedCount);
      } else {
        return { trigger: Infinity, release: Infinity };
      }
    }

    const trigger = Math.max(ONSET_ABS_MIN, this.kHigh * bin.floor);
    return { trigger: trigger, release: trigger * K_LOW };
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

  process(inputs) {
    const input = inputs[0];
    if (!input || input.length === 0 || !input[0] || input[0].length === 0) {
      return true;
    }
    const channel = input[0];
    const blockLen = channel.length;
    const freqs = this.freqs;
    const nFreqs = freqs.length;

    for (let i = 0; i < blockLen; i++) {
      this.envBuf[this.envFill++] = channel[i];

      if (this.envFill >= this.envSize) {
        this.envFill = 0;
        const sampleAt = this.sampleCount + i;

        const levels = new Array(nFreqs);
        let loudestIdx = 0;
        for (let fi = 0; fi < nFreqs; fi++) {
          levels[fi] = this.goertzel(this.envBuf, freqs[fi]);
          if (levels[fi] > levels[loudestIdx]) loudestIdx = fi;
        }

        const bins = this.bins;
        const triggers = new Array(nFreqs);

        let aboveCount = 0;
        let aboveIdx = -1;
        for (let fi = 0; fi < nFreqs; fi++) {
          const t = this.triggerFor(bins[fi], levels[fi]);
          triggers[fi] = t;
          if (levels[fi] > t.trigger) {
            aboveCount++;
            aboveIdx = fi;
          }
        }

        if (aboveCount === 1) {
          if (!bins[aboveIdx].active) {
            bins[aboveIdx].active = true;
            this.port.postMessage({ type: 'onset', sample: sampleAt, freqIndex: aboveIdx });
          }
          for (let fi = 0; fi < nFreqs; fi++) {
            if (fi !== aboveIdx && bins[fi].active && levels[fi] < triggers[fi].release) {
              bins[fi].active = false;
            }
          }
        } else if (aboveCount === 0) {
          for (let fi = 0; fi < nFreqs; fi++) {
            if (bins[fi].active && levels[fi] < triggers[fi].release) {
              bins[fi].active = false;
            }
          }
        }
        // aboveCount > 1: simultaneous bins above their trigger -- transition
        // noise between bursts. No onset emitted, states left untouched.

        // Adaptive floor: only quiet bins (own magnitude below their own
        // release level) get pulled toward the current magnitude, so a
        // burst (or its decay tail) never drags a floor upward.
        for (let fi = 0; fi < nFreqs; fi++) {
          if (bins[fi].floor !== null && levels[fi] < triggers[fi].release) {
            bins[fi].floor = Math.max(FLOOR_MIN, bins[fi].floor + FLOOR_ALPHA * (levels[fi] - bins[fi].floor));
          }
        }

        this.hopCount++;
        if (this.hopCount >= this.levelHopStride) {
          this.hopCount = 0;
          this.port.postMessage({
            type: 'level',
            sample: sampleAt,
            freqIndex: loudestIdx,
            value: levels[loudestIdx],
            floor: bins[loudestIdx].floor,
            active: bins[loudestIdx].active
          });
        }
      }
    }

    this.sampleCount += blockLen;
    return true;
  }
}

registerProcessor('goertzel-bank-processor', GoertzelBankProcessor);
