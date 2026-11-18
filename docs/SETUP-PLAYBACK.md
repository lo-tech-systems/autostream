# Setup - Playback Defaults

Open **Setup** and expand the **Playback** card. Its collapsed row shows the Auto-Start
speakers and the start volume (for example "Living Room · 45%").

Every control on this card applies immediately as you change it. There is no separate Save
button.

## Auto-Start Speakers

The speakers autostream starts when playback begins. Each is listed with the volume it starts
at. To change the set, choose the speakers you want on **Home** while something is playing, then
tap the pin above the speaker list and confirm.

Each speaker has a **Remove** button. The last speaker cannot be removed, because autostream
needs at least one to start on.

## Start volume for other speakers

A slider from 0-100% sets the volume a speaker starts at when it is not in the Auto-Start set.

## Silence detection

A single slider controls how long an input must stay quiet before autostream treats playback
as stopped. It runs from 5 to 300 seconds on a logarithmic scale, so short settings are easier
to dial in precisely than long ones.

Once playback starts, a **minimum playback hold** keeps the session running for at least a set
time (30 seconds by default) even through a brief quiet passage, so a stylus drop or a gap
between tracks does not cut it short. The hold is a config-file setting rather than a control on
this card, and it is what makes short silence-detection settings (5-10 seconds) safe, including
for automatic turntables whose start button causes a transient before the music begins. On a Turntable or Line input a single click does not start playback at
all; about a tenth of a second of sound is needed first.

This is separate from each input's own **Sensitivity** (the level below which audio counts
as silence in the first place), which is set per input under
[Setup-Inputs](SETUP-INPUTS.md#sensitivity).

## Repeat playback

**Enable repeat playback** turns on a rolling in-memory recording of the active input, sized to
the **Buffer target** below. Once the toggle is on, the drop-down offers:

- **Vinyl (33 minutes)**
- **CD (80 minutes)**

If the saved value is something else (only possible by editing the config file directly), a
third **Custom (N minutes)** entry appears showing that value, but there's no way to type a
custom number into the drop-down itself.

Underneath, a note reports what the current target actually buys you, for example "Buffer: 80
mins (256Kbps MP2)". autostream doesn't just record raw PCM at any target: it picks the
smallest-footprint codec off an internal quality ladder (PCM down through several MP2
bitrates) needed to fit the requested duration in whatever RAM is actually free at the time,
recalculating whenever the target or free memory changes. If even the lowest-bitrate tier can't
fit the requested duration in memory, the buffer instead reports fewer minutes than you asked
for, e.g. "80 minutes requested; 50 minutes at 160Kbps MP2 fit in memory": duration degrades
rather than audio quality dropping below the ladder's floor. If there isn't enough free memory
for even the shortest supported buffer, the card shows "Repeat unavailable: insufficient free
memory" instead.

Turning repeat on here only makes the feature and its **↻ Repeat Play** button available on the
Home page. It does not start recording by itself. Once you arm it there, autostream records
continuously while the source is playing. If the source then goes silent (per the silence
detection setting above), the last recording is held in memory; if repeat is armed, playback of
that recording starts immediately and loops for as long as you leave it running, until you stop
it or a new live session begins on that input. If no speaker is on for 5 minutes while it
replays, or while a record or CD plays with repeat armed, autostream stops repeat by itself: a
replay fades out, repeat is disarmed, and the recording is kept so you can arm it again. It
does this at once when the [Pause timeout](SETUP-PERSONALISATION.md#speaker-controls) turns the
last speaker off. See [Home Page](HOME-PAGE.md) for using the button itself.

## Audio processing

**Input Resampling Quality** selects how much CPU autostream's resampler is allowed to spend
on incoming audio:

- **Best (highest CPU use and best quality)**: only offered on higher-performance Raspberry Pi
  models (Pi 4/400/CM4, Pi 5/500/CM5); left out of the list entirely on smaller boards, where it
  isn't affordable.
- **Balanced (moderate CPU use)**
- **Fast (lowest CPU use, fine for most sources)**

Changing it applies immediately: playback stops and resumes automatically a few seconds later
while the pipeline restarts at the new setting.

## More Owntone Settings

A **More Owntone Settings** button opens a separate page covering AirPlay-specific behaviour
(buffered audio, per-speaker modes, output offsets); see [Setup-OwnTone](SETUP-OWNTONE.md).
Where the backend supports per-speaker timing offsets, a **Run Speaker Synchronisation** button
also appears, opening the automatic alignment tool described in [Speaker Synchronisation](SPEAKER-SYNC.md).
