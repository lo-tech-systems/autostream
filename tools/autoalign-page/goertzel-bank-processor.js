// goertzel-bank-processor.js
// AudioWorkletProcessor that runs a Goertzel detector bank, one bin per
// distinct output frequency, over short (~10ms) analysis windows. Each
// window is used both to timestamp burst onsets (with hysteresis, on the
// audio-clock sample counter) and to report a live "loudest bin" level for
// on-screen feedback.
//
// Messages posted to the main thread:
//   { type: 'onset', sample, freqIndex }   -- rising edge on freqs[freqIndex]
//   { type: 'level', sample, freqIndex, value } -- throttled loudest-bin level
//
// Messages accepted from the main thread:
//   { type: 'setThreshold', value }        -- onset threshold (0..1)
//
// "sample" is a running audio-clock sample count since the worklet was
// created (derived from sampleRate, not Date.now()), matching the timing
// idiom proven in tools/autoalign-spike/goertzel-processor.js.
//
// Onset attribution assumes at most one frequency is genuinely active at a
// time (the appliance solos one output, hence one frequency, at once). If a
// window shows more than one bin above threshold simultaneously, it is
// treated as transition noise between bursts and no onset is emitted.

class GoertzelBankProcessor extends AudioWorkletProcessor {
  constructor(options) {
    super();

    const opts = (options && options.processorOptions) || {};
    this.freqs = (Array.isArray(opts.freqs) && opts.freqs.length) ? opts.freqs : [1000];
    this.threshold = typeof opts.threshold === 'number' ? opts.threshold : 0.15;

    // ~10ms analysis/onset window, matching the spike's envelope window.
    this.envSize = Math.max(128, Math.round(sampleRate * 0.01));
    this.envBuf = new Float32Array(this.envSize);
    this.envFill = 0;

    this.sampleCount = 0;
    this.onsetState = this.freqs.map(function () { return 'below'; });

    // Throttle 'level' messages so the port doesn't get ~100/s of traffic.
    this.hopCount = 0;
    this.levelHopStride = 4; // ~every 4th ~10ms hop, roughly 25-40ms

    this.port.onmessage = (e) => {
      const msg = e.data;
      if (msg && msg.type === 'setThreshold' && typeof msg.value === 'number') {
        this.threshold = msg.value;
      }
    };
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

        const onHi = this.threshold;
        const onLo = this.threshold * 0.6;

        let aboveCount = 0;
        let aboveIdx = -1;
        for (let fi = 0; fi < nFreqs; fi++) {
          if (levels[fi] >= onHi) {
            aboveCount++;
            aboveIdx = fi;
          }
        }

        if (aboveCount === 1) {
          if (this.onsetState[aboveIdx] === 'below') {
            this.onsetState[aboveIdx] = 'above';
            this.port.postMessage({ type: 'onset', sample: sampleAt, freqIndex: aboveIdx });
          }
          for (let fi = 0; fi < nFreqs; fi++) {
            if (fi !== aboveIdx && this.onsetState[fi] === 'above' && levels[fi] < onLo) {
              this.onsetState[fi] = 'below';
            }
          }
        } else if (aboveCount === 0) {
          for (let fi = 0; fi < nFreqs; fi++) {
            if (this.onsetState[fi] === 'above' && levels[fi] < onLo) {
              this.onsetState[fi] = 'below';
            }
          }
        }
        // aboveCount > 1: simultaneous bins above threshold -- transition
        // noise between bursts. No onset emitted, states left untouched.

        this.hopCount++;
        if (this.hopCount >= this.levelHopStride) {
          this.hopCount = 0;
          this.port.postMessage({
            type: 'level',
            sample: sampleAt,
            freqIndex: loudestIdx,
            value: levels[loudestIdx]
          });
        }
      }
    }

    this.sampleCount += blockLen;
    return true;
  }
}

registerProcessor('goertzel-bank-processor', GoertzelBankProcessor);
