// goertzel-processor.js
// AudioWorkletProcessor that runs a two-frequency Goertzel detector
// (nominally 1000 Hz and 1250 Hz) over ~100ms windows, and a faster
// envelope check on the 1000 Hz tone for burst-onset timing.
//
// Messages posted to the main thread:
//   { type: 'level', sample, f1, f2 }                 -- roughly every 100ms
//   { type: 'onset', sample }                         -- on each rising edge
//
// Messages accepted from the main thread:
//   { type: 'setThreshold', value }                   -- onset threshold (0..1)
//
// "sample" is the running audio-clock sample count since the worklet
// was created (i.e. derived from the sample rate, not Date.now()).

class GoertzelProcessor extends AudioWorkletProcessor {
  constructor(options) {
    super();

    const opts = (options && options.processorOptions) || {};
    this.f1 = opts.f1 || 1000;
    this.f2 = opts.f2 || 1250;
    this.threshold = typeof opts.threshold === 'number' ? opts.threshold : 0.15;

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
    this.onsetState = 'below'; // 'below' | 'above'

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

    for (let i = 0; i < blockLen; i++) {
      const s = channel[i];

      // --- 100ms window for level bars ---
      this.windowBuf[this.windowFill++] = s;
      if (this.windowFill >= this.windowSize) {
        const f1level = this.goertzel(this.windowBuf, this.f1);
        const f2level = this.goertzel(this.windowBuf, this.f2);
        this.port.postMessage({
          type: 'level',
          sample: this.sampleCount + i,
          f1: f1level,
          f2: f2level
        });
        this.windowFill = 0;
      }

      // --- ~10ms window for onset envelope on f1 ---
      this.envBuf[this.envFill++] = s;
      if (this.envFill >= this.envSize) {
        const envLevel = this.goertzel(this.envBuf, this.f1);
        this.envFill = 0;

        const onHi = this.threshold;
        const onLo = this.threshold * 0.6;

        if (this.onsetState === 'below' && envLevel >= onHi) {
          this.onsetState = 'above';
          this.port.postMessage({
            type: 'onset',
            sample: this.sampleCount + i
          });
        } else if (this.onsetState === 'above' && envLevel < onLo) {
          this.onsetState = 'below';
        }
      }
    }

    this.sampleCount += blockLen;
    return true;
  }
}

registerProcessor('goertzel-processor', GoertzelProcessor);
