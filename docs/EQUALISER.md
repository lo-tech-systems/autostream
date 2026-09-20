# Equaliser

The Equaliser page controls the **shared output stage** - the tone and level applied to
whatever is currently playing, after all sources have been mixed.
There is no PIN gate on this page, so it stays reachable for quick adjustments while music is
playing.

> Note: This page controls the overall output. Each input also has its own three-band
> equaliser - see [Setup-Inputs](SETUP-INPUTS.md).

## Equaliser bands

Six fixed parametric bands shape the final tone:

| Band  | Centre / corner frequency | Character |
|-------|---------------------------|-----------|
| 1     | 40 Hz                     | Low shelf - overall bass weight |
| 2     | 100 Hz                    | Peak - upper bass / low-mid |
| 3     | 300 Hz                    | Peak - low-mid body |
| 4     | 1 kHz                     | Peak - midrange |
| 5     | 4 kHz                     | Peak - presence |
| 6     | 10 kHz                    | High shelf - overall treble/air |

Each band is a slider running **-12 dB to +12 dB** in 1 dB steps, labelled with its frequency
(40Hz, 100Hz, 300Hz, 1kHz, 4kHz, 10kHz) and its current value. Above the sliders, a live
frequency-response curve redraws as you move any band, so you can see the combined shape of all
six bands at once rather than reading the sliders individually.

A **Flat** button above the curve zeroes all six bands in one tap. It does not change output
gain or the auto-trim setting below.

## Output gain

Below the Equaliser card, the **Output gain** slider sets the overall level of the final mix, on
top of whatever the EQ bands are doing. It runs **-12 dB to +12 dB** in 0.5 dB steps and shows its
current value (for example "+2.5 dB" or "-4.0 dB").

Applying bass boost and other equaliser effects can overload the digital signal headroom,
particularly for modern recordings that are already produced near maximum output. The overall
gain may then need to be reduced to compensate and keep a clean signal. The automatic trim
function below can help you set this level. See
[Why clipping happens](TROUBLESHOOTING.md#why-clipping-happens) if you want the background.

## Automatically trim gain (auto-trim)

A toggle labelled **Automatically trim gain** - "Prevent clipping by adjusting output level
automatically" - watches the final signal after EQ and gain have been applied. If it detects a
sample that would clip (exceed full scale), it immediately cuts the output level by enough to
stop that overshoot happening again, then holds that cut for the rest of the session.

- The cut only ever gets larger during a session; it never eases back up on its own. It is capped
  at 10 dB of cut.
- While auto-trim is on, a status line under the toggle reads "Calculating…" until the monitor
  has reported a value, then "Auto-trim: -N dB applied" (or "unavailable" if the monitor can't be
  reached).
- Turning auto-trim off holds whatever cut has accumulated but stops it from moving further.
- Turning auto-trim back on resets the accumulated cut to 0 dB and starts fresh.

Auto-trim is a safety net for occasional loud peaks, not a substitute for setting a sensible
baseline level yourself - see the recommended workflow below.

## Recommended workflow

1. Start with the EQ bands at or near flat.
2. Turn on **Automatically trim gain**.
3. Play a loud or "hot" track - ideally one with strong bass or bright peaks - and let it run
   past its loudest section.
4. Check the auto-trim status line for how much cut was needed.
5. Set **Output gain** manually to roughly that same negative value.
6. Turn auto-trim off and back on to reset the accumulated cut back to 0 dB now that the manual
   gain covers the everyday case.
7. Leave auto-trim enabled so occasional louder peaks are still caught. For a turntable, consider
   turning it off instead once you've set the baseline gain - a stylus dust click or pop can spike
   far louder than the music itself and trigger a cut you don't actually want.

Example: if auto-trim settles at about -6 dB, set Output gain to about -6 dB, then reset auto-trim
(off, then on) and carry on with it enabled.

## Practical advice

- Make small EQ moves first. Large boosts eat into headroom quickly and make clipping more likely.
- If you've boosted several bands, expect to need some negative output gain to compensate.
- If one input is consistently louder or has a different tonal balance than the other, fix that
  at the input's own gain/EQ controls (see [Setup-Inputs](SETUP-INPUTS.md)) rather than
  compensating here every time you switch sources.
- Auto-trim reacts to peaks; it doesn't fix a persistently too-hot recording on its own - a
  negative output gain baseline does that.

## Multiple appliances

If **Display Hostname** and **Allow control of other appliances** are both enabled
([Setup > Personalisation](SETUP-PERSONALISATION.md)), a selector in the top-right of the page lets you jump to another autostream
appliance's Equaliser page and adjust it directly, the same way as on the Home page. See
[Multi-Appliance](MULTI-APPLIANCE.md) for the full behaviour and what happens if the other
appliance goes offline mid-edit.

## See also

- [Setup-Inputs](SETUP-INPUTS.md) - per-input gain and 3-band tone control.
- [Home Page](HOME-PAGE.md) - the appliance selector and day-to-day playback controls.
- [Troubleshooting](TROUBLESHOOTING.md) - general recovery steps.
