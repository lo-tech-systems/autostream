# Audio Tuning

## Audio Tuning

This page explains how to use gain, equaliser, and auto-trim without causing clipping.

If your system sounds harsh, distorted, or unexpectedly loud after EQ changes, start here.

---

## What the controls do

- **Input gain** adjusts the level of one source before it reaches the shared output stage.
- **Input equaliser** adjusts the tone of one source.
- **Output equaliser** adjusts the final shared tone for all sources.
- **Output gain** adjusts the final shared level after the output EQ.
- **Auto-trim** watches the final post-EQ, post-gain signal and automatically cuts level when clipping is detected.

---

## Why clipping happens

Equaliser boosts increase level as well as tone.

For example, a bass boost or presence boost may sound good on most tracks, but a louder record or CD can then push the final output above 0 dBFS. When that happens, the result can sound hard, brittle, or obviously distorted.

Many CDs, especially heavily compressed releases from the early 2000s, are mastered extremely hot and leave little or no headroom in the original 16-bit digital signal. In those cases, even a small EQ boost can push the signal into clipping.

The fix is not usually "less EQ" on its own. The overall output gain often needs to be reduced first by setting it to a negative value, which creates headroom for the tone controls to work without hard clipping.

This is why EQ and gain should be treated together.

---

## Recommended workflow

When using EQ, the safest approach is:

1. Start with conservative settings.
2. Enable **Auto-trim** (on the Equaliser page)
3. Play a loud or "hot" track, especially one with strong bass or bright peaks.
4. Let playback continue until the loudest section has passed.
5. Note the amount of trim that was needed.
6. Set the manual **Output gain** to roughly that value.
7. Reset the current auto-trim value by turning auto-trim off and back on.
8. Leave **Auto-trim** enabled so future peaks can still be caught automatically. For turntables, though, it may be better to turn it off after setting the baseline gain, because dust clicks and pops can create instantaneous peaks much louder than the real music signal.

Example:

- If auto-trim settles at about `-6 dB`, set manual output gain to about `-6 dB`.
- Then reset the current trim and continue using the system with auto-trim still enabled.

This gives you a sensible baseline level while still protecting against occasional louder material.

---

## Practical advice

- Prefer small EQ moves first. Large boosts consume headroom quickly.
- If you boost several bands, expect to need some negative output gain.
- If one source is consistently hotter than another, reduce that source's input gain before making large output-level cuts.
- Auto-trim is a safety net, not a substitute for sensible gain staging.

---

## Symptoms and fixes

### Harsh or crunchy sound

Likely cause: clipping after EQ or gain changes.

What to do:

1. Enable auto-trim.
2. Reduce output gain if needed.
3. Replay a loud track and re-check the result.

### One source is much louder than another

Likely cause: different source output levels.

What to do:

1. Adjust the per-input gain for the louder source downward.
2. Re-check your output gain and auto-trim behavior afterwards.

### Sound becomes quieter after enabling auto-trim

Likely cause: auto-trim is correctly reducing a clipped signal.

What to do:

1. Note the trim value reached during loud playback.
2. Move that value into manual output gain.
3. Reset the current trim.
4. Leave auto-trim enabled.

---

## Related

For general recovery steps, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
