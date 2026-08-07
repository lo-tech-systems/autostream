# autostream_monitor socket API

This document is the canonical external reference for the `autostream_monitor`
daemon's socket protocol, request/response shapes, and per-command behavior.

For what the daemon is, how it runs, its command-line options, and its
processing order, see [AUTOSTREAM-MONITOR.md](AUTOSTREAM-MONITOR.md).
Implementation-local invariants, concurrency notes, and code-structure details
remain documented alongside the relevant C++ code.

## Transport

The daemon listens on a Unix domain socket and speaks newline-delimited JSON.

- Default socket path: `/tmp/autostream_monitor.sock`
- Each request must be one complete JSON object followed by `\n`
- Each request receives exactly one response
- Most responses are a single JSON line
- `get_id_snapshot` is the only command that may send binary data after the JSON
  response line
- engineering dump commands (`start_output_dump`, `stop_output_dump`) can be
  driven from the Linux command line using `socat` or `nc -U`:

  ```sh
  printf '{"type":"start_output_dump","path":"/tmp/test.wav"}\n' \
    | socat - /tmp/autostream_monitor.sock

  printf '{"type":"stop_output_dump"}\n' \
    | socat - /tmp/autostream_monitor.sock
  ```

## General Response Shape

Most commands return an ack object:

```json
{"type":"ack","command":"...","ok":true}
```

Or an error:

```json
{"type":"ack","command":"...","ok":false,"error":"reason"}
```

Unknown commands return:

```json
{"type":"ack","command":"unknown","ok":false,"error":"unknown command: ..."}
```

## Data Types

### EQ band

Used by both `set_eq` and `set_output_eq`.

```json
{
  "type": "peak",
  "freq_hz": 1000.0,
  "gain_db": 2.0,
  "q": 0.707
}
```

Supported `type` values:

- `peak`
- `low_shelf`
- `high_shelf`
- `low_pass`
- `high_pass`

Validation rules:

- maximum 16 bands
- `freq_hz` must be `> 0` and `< 22050`
- `q` must be `> 0`
- `gain_db` must be in `[-12.0, +12.0]`

Notes:

- `gain_db` is ignored for `low_pass` and `high_pass`
- an empty band list clears the EQ

### Input index

Commands that target an input use 1-based indexing:

- `1`
- `2`

Any other value is rejected.

## Complete Socket API

### `list_devices`

Enumerates currently visible ALSA capture devices.

Request:

```json
{"type":"list_devices"}
```

Success response:

```json
{
  "type":"ack",
  "command":"list_devices",
  "ok":true,
  "devices":[
    {"hw":"hw:1,0","card":"USB Audio","name":"USB Audio"}
  ]
}
```

Response fields:

- `hw`
  - ALSA hardware address
- `card`
  - human-readable card name
- `name`
  - human-readable device/subdevice name

### `configure_input`

Stores configuration for one input.

Request:

```json
{
  "type":"configure_input",
  "input":1,
  "device":"hw:1,0",
  "silence_threshold_dbfs":-66.0,
  "silence_seconds":30,
  "track_change_silence_seconds":1.25,
  "minimum_playback_seconds":30
}
```

Request fields:

- `input`
  - input index, `1` or `2`
- `device`
  - ALSA device name in `hw:*` format
- `silence_threshold_dbfs`
  - silence threshold in dBFS
  - valid range: `[-120.0, 0.0]`
  - default if omitted: `-66.0`
- `silence_seconds`
  - time below threshold before the input is considered silent
  - valid range: `[1, 3600]`
  - default if omitted: `30`
- `track_change_silence_seconds`
  - minimum below-threshold gap duration that is treated as a possible track
    boundary; the same per-input amplitude threshold is reused, only the
    duration is independent
  - valid range: `[0.5, 5.0]` seconds
  - default if omitted: `1.25`
  - a runtime configuration change to this value clears any in-progress gap
    candidate but does not reset the `track_change_seq` counter
- `minimum_playback_seconds`
  - minimum playback hold: once this input starts a capture session, or once
    a repeat-feature replay sourced from this input starts, that session/
    replay owns playback for this many seconds
  - valid range: `[0, 300]`
  - default if omitted: `30`
  - `0` disables the hold entirely
  - see "Minimum playback hold" below for the exact suppression semantics

Important behavior:

- if the input is stopped, all fields are applied
- if the input is already running, every field except `device` is
  runtime-tunable, including `minimum_playback_seconds`
- changing `device` while running is rejected; the caller must stop the input
  first

Success response:

```json
{"type":"ack","command":"configure_input","input":1,"ok":true}
```

Typical errors:

- `input index must be 1 or 2`
- `device is empty`
- `device must be in ALSA hw:* format (e.g. hw:1,0)`
- `silence_threshold_dbfs must be in the range [-120.0, 0.0]`
- `silence_seconds must be in the range [1, 3600]`
- `track_change_silence_seconds must be in the range [0.5, 5.0]`
- `minimum_playback_seconds must be in the range [0, 300]`
- `stop the input before changing device`

#### Minimum playback hold

Once a source (live input or repeat-feature replay) starts playback, it owns
playback for `minimum_playback_seconds` (default 30 s, 0 disables). This
exists so a short `silence_seconds` timeout (tuned for e.g. an automatic
turntable's music-to-music gaps) does not also trip on a source's own
start-up transient: a turntable's start-button thump followed by 15-20 s of
sub-threshold spin-up rumble before the groove is reached would otherwise end
the session (and, with repeat armed, immediately replay a two-second
recording of the thump) well before real music arrives.

Two independent suppression points, both gated on elapsed time since the
session/replay started:

- **Live input session-end.** While a capture session is within its hold
  window, an elapsed-silence session-end is suppressed even though the
  debounced above-threshold state has already gone false: the session (and,
  if the repeat feature is recording, its recording) stays open through the
  quiet spell. The hold never overrides an explicit stop (`set_allow_capture`
  going false, `stop_input`, a config/device change) -- only the
  silence-timeout reason is held back.
- **Replay takeover.** While an active repeat-feature replay (or its
  fade-out) is within its hold window, a live-input transient that would
  otherwise interrupt it (crossfade to the live source) is ignored outright:
  no state change, no pending interrupt is latched. Nothing about the
  transient is stored to be replayed later; instead, for as long as that
  input keeps capturing without yet being the one actually recorded, the
  daemon re-checks roughly once a second (a bounded re-notify alongside the
  original start edge) whether it can now be admitted. Once the hold
  expires -- or the replay ends by some other route (e.g. disable/re-enable)
  while the input is still capturing -- the very next one of those checks is
  what actually starts the takeover or the recording, normally within about
  a second. Worst case, a legitimate takeover during the hold is deferred
  until the hold expires and the new source is still live.

What the hold does **not** affect:

- `is_silent` status and VU/level reporting always reflect the true
  above-threshold state, unaffected by the hold.
- Counters (wear/total hours) gate on the instantaneous `is_silent` flag, so
  a held-but-silent session does not inflate accrued time.
- Track-change detection (`track_change_silence_seconds`) runs its own,
  independent, much shorter silence window on both the live and replay
  paths and is never suppressed by the hold.
- `minimum_playback_seconds=0` reproduces pre-hold behaviour exactly on both
  suppression points.

### Silence-timeout tail trim

When a repeat-feature recording session ends because the input's own
`silence_seconds` timeout elapsed (as opposed to a manual stop, a config
change, or shutdown), the trailing silence captured while the timeout was
counting down is silence by definition and is dropped from the RAM buffer at
session close, before replay of that recording can begin. `recording.seconds`
/ `recording.bytes` and replay `duration_seconds` in status responses
reflect the trimmed length. The trim is chunk-based (whole buffer chunks
removed from the tail, with the final partial chunk truncated to its exact
byte boundary) so it is byte-exact, not merely chunk-granular.

Two different cuts can produce this trim, depending on whether the tail
offset gate (below) has a valid marker for the session:

- **Marker-based cut (the normal case, once onset has confirmed).** The
  buffer is cut back to the tail offset gate's last-sustained-run-end
  position plus a 1.0 s pad. This is what excludes lead-out crackle and a
  tonearm clunk from the recording -- see "Onset-gated recording and the
  tail offset gate" below.
- **Silence-timeout fallback cut (no valid marker).** Removes whatever
  amount of trailing below-threshold audio was actually measured for that
  session (not a fixed `silence_seconds`-sized cut), minus the same 1.0 s
  pad. In practice this only applies when onset never confirmed, in which
  case the buffer is empty anyway (nothing was ever committed) and the trim
  is a no-op either way.

Both cuts use the same 1.0 s pad so the trim never bites into the last
audible moment, whichever cut applies.

### Onset-gated recording and the tail offset gate

Further refinements on top of the tail trim above, separating the
repeat-feature SESSION (still starts on the first above-threshold transient,
pre-warming the streaming pipeline during spin-up) from what the RECORDER
actually commits to the RAM buffer, at both ends of the recording:

- **Onset gate (head).** The recorder does not commit any audio to the
  buffer until onset is confirmed: 2.5 s of continuous above-threshold
  signal, measured against the same per-input silence threshold used
  elsewhere. A mechanical start thump cannot sustain 2.5 s, so it is never
  committed; spin-up rumble that sits below the threshold does not advance
  the count either. A single below-threshold block anywhere in an otherwise-
  sustained run resets the count to zero -- the window must be unbroken. A
  CD player (or any source with no start transient) confirms onset the same
  way, roughly 2.5 s after its first note.
- **Pre-roll ring.** While onset is unconfirmed, raw audio is held in a
  rolling ~5 s ring instead of being discarded outright. Once onset confirms,
  the ring's contents are spliced into the buffer (in original order) ahead
  of ongoing live audio, so the confirmed onset's own lead-in is not lost.
  Because the ring holds at least as long as the sustain window, a recording
  whose first block is already above threshold (the CD-player case) still
  has its first notes preserved once onset confirms a couple of seconds in.
  A session that ends before onset ever confirms (a thump with no following
  music) commits nothing at all: the buffer stays empty and there is nothing
  to replay.
- **Tail offset gate (tail).** The onset gate protects the head only; left
  alone, the silence-timeout tail trim keeps everything up to and including
  any lead-out transient (run-out crackle, a tonearm clunk) since each one
  is itself above-threshold and resets the trim's own trailing-silence
  count. The tail offset gate tracks, as audio is committed to the buffer,
  the position at the end of the most recent sustained (>= 2.5 s
  continuous above-threshold, the same window and reset rule as the onset
  gate) run. At session close this position -- plus the same 1.0 s pad used
  by the tail trim -- replaces the measured-trailing-silence cut (see
  "Silence-timeout tail trim" above), so a run-out pop or clunk that cannot
  itself sustain 2.5 s is excluded from the recording, whatever the input's
  own moment-to-moment silence test made of it. The mark only exists once a
  sustained run has actually been committed, which in practice means onset
  has confirmed; a session that never reaches onset falls back to the
  silence-timeout cut, which trims nothing from the (already empty) buffer
  either way.
- **Inter-loop gap.** Since a repeat recording no longer contains its own
  start transient (onset gate) or its own trailing run-out (tail offset
  gate), consecutive replay loops would otherwise wrap directly from the
  last note back into the first with no separation. Each loop wrap inserts a
  fixed 1.5 s silence gap before resuming from the start. The gap is not
  recorded content: `replay.position_seconds` holds steady at the
  just-finished loop's `duration_seconds` for the length of the gap, then
  resets to (approximately) zero once real audio resumes; `duration_seconds`
  itself (computed once, from the recording's own size) is unaffected by the
  gap either way.

None of this affects the minimum playback hold, track-change detection, or
the memory-guard/head-truncation machinery, which all continue to operate
exactly as described above -- a session held open by the minimum-playback
hold with no onset ever reached simply commits nothing, the same as any
other pre-onset session end.

### `set_fifo`

Sets the named pipe path used for output.

Request:

```json
{"type":"set_fifo","path":"/run/autostream-pipes/autostream.fifo"}
```

Validation:

- path must not be empty
- path must be absolute
- path must not contain `..`
- the path must already exist
- the path must be a FIFO

Success response:

```json
{"type":"ack","command":"set_fifo","ok":true}
```

Typical errors:

- `path is empty`
- `path must be absolute (start with /)`
- `path must not contain ..`
- path-existence or not-a-FIFO validation errors

### `start_input`

Starts capture and processing threads for an input.

Request:

```json
{"type":"start_input","input":1}
```

Success response:

```json
{"type":"ack","command":"start_input","input":1,"ok":true}
```

Typical errors:

- `input index must be 1 or 2`
- `input is already running`
- `input stopped unexpectedly; call stop_input first`
- start-up failures from ALSA or libsamplerate setup

### `stop_input`

Stops an input and joins its worker threads.

Request:

```json
{"type":"stop_input","input":1}
```

Success response:

```json
{"type":"ack","command":"stop_input","input":1,"ok":true}
```

Typical errors:

- `input index must be 1 or 2`

### `set_allow_capture`

Controls which input is allowed to write to the shared FIFO.

Request:

```json
{"type":"set_allow_capture","input":1,"allow":true}
```

Behavior:

- only one input may capture to the FIFO at a time
- enabling capture on one input disables capture on the other input(s)
- disabling capture on an input does not stop monitoring; it only suppresses
  FIFO writes

Success response:

```json
{"type":"ack","command":"set_allow_capture","input":1,"allow":true,"ok":true}
```

Typical errors:

- `input index must be 1 or 2`

### `set_eq`

Sets per-input EQ for one input.

Request:

```json
{
  "type":"set_eq",
  "input":1,
  "bands":[
    {"type":"peak","freq_hz":100.0,"gain_db":3.0,"q":0.707}
  ]
}
```

Behavior:

- applied after sample-rate conversion
- applied at the fixed output rate of 48 kHz
- affects only the selected input

Success response:

```json
{"type":"ack","command":"set_eq","input":1,"bands_applied":1,"ok":true}
```

Typical errors:

- `input index must be 1 or 2`
- `unknown EQ band type`
- any EQ-band validation error

### `set_gain`

Sets per-input preamp gain.

Request:

```json
{"type":"set_gain","input":1,"gain_db":3.0}
```

Validation:

- `gain_db` must be in `[-24.0, +24.0]`

Behavior:

- applied in the float domain after sample-rate conversion
- applied before per-input EQ

Success response:

```json
{"type":"ack","command":"set_gain","input":1,"gain_db":3.0,"ok":true}
```

Typical errors:

- `input index must be 1 or 2`
- `gain_db must be in the range [-24.0, +24.0]`

### `set_output_eq`

Sets the shared output EQ.

Request:

```json
{
  "type":"set_output_eq",
  "bands":[
    {"type":"peak","freq_hz":1000.0,"gain_db":2.0,"q":0.707}
  ]
}
```

Behavior:

- applied after per-input gain and per-input EQ
- applied before float-to-`int16` conversion and FIFO write
- shared across all inputs
- if the band list is empty, output EQ is cleared
- if all bands are identity peak/shelf bands with `0 dB` gain, the monitor
  uses a quick path that skips filter arithmetic

Success response:

```json
{"type":"ack","command":"set_output_eq","bands_applied":1,"ok":true}
```

Typical errors:

- `unknown EQ band type`
- any EQ-band validation error

### `set_output_gain`

Sets the manual output gain applied after the output EQ.

Request:

```json
{"type":"set_output_gain","gain_db":-2.5}
```

Validation:

- `gain_db` must be in `[-10.0, +10.0]`

Behavior:

- applied after output EQ, before float-to-`int16` conversion
- shared across all inputs
- combined with any active auto-trim: `effective_output_gain_db = output_gain_db + output_auto_trim_db`
- a value of `0.0` is unity gain (default)

Success response:

```json
{
  "type":"ack",
  "command":"set_output_gain",
  "ok":true,
  "output_gain_db":-2.5,
  "output_auto_trim_db":-1.2,
  "effective_output_gain_db":-3.7
}
```

Typical errors:

- `gain_db must be in the range [-10.0, +10.0]`

### `set_output_auto_trim`

Enables or disables automatic output trimming.

Request:

```json
{"type":"set_output_auto_trim","enabled":true}
```

Behavior:

- when enabled, `apply()` monitors post-EQ/gain clipping; if a processed block
  clips (peak > 0 dBFS), the auto-trim attenuation is increased by the overshoot
  in dB so the next block avoids the same clip
- the trim is cut-only: it only accumulates downward, never boosts back
- the trim is session-scoped: it resets to `0.0 dB` on `stop_input` or on
  `set_allow_capture(true)` (input handoff)
- enabling always resets the current trim to `0.0 dB`
- disabling preserves the current trim value in `output_auto_trim_db` but stops
  the trim from being updated further
- the minimum allowed auto-trim is `-10.0 dB`

Success response:

```json
{
  "type":"ack",
  "command":"set_output_auto_trim",
  "ok":true,
  "output_auto_trim_enabled":true,
  "output_auto_trim_db":0.0,
  "effective_output_gain_db":0.0
}
```

Recommended workflow for deriving a stable manual gain baseline without losing
ongoing clip protection:

1. Set `output_gain_db` to `0.0` and enable auto-trim.
2. Let audio play through a loud representative track until the trim stabilises.
3. Read `effective_output_gain_db` from the next `get_status` response.
4. Set `output_gain_db` to that value as the new manual baseline.
5. Reset the current trim by either stopping and restarting playback, or by
   toggling auto-trim off and on again.
6. Leave auto-trim enabled so any future peaks can still be cut automatically.

### `start_output_dump`

Begins recording the final processed audio stream to a WAV file.

This is an engineering-only command intended for EQ and SRC validation directly
from the Linux command line while the service is running.  Normal clients (Python
controller, OwnTone) are unaffected.

Request:

```json
{"type":"start_output_dump","path":"/tmp/autostream-dump.wav"}
```

Or, to overwrite an existing file:

```json
{"type":"start_output_dump","path":"/tmp/autostream-dump.wav","overwrite":true}
```

Request fields:

- `path`
  - absolute path to the output WAV file
  - must not be empty, relative, or contain `..`
  - must not already exist unless `overwrite` is `true`
  - if it exists, it must be a regular file (not a directory, FIFO, etc.)
  - the parent directory must be writable
- `overwrite`
  - if `true`, an existing regular file at `path` is truncated and replaced
  - defaults to `false`

Behavior:

- the WAV file is opened immediately and a 44-byte placeholder header is written
- audio frames are tapped after all processing (SRC, per-input gain/EQ, output
  EQ, output gain, auto-trim) and after float-to-`int32` conversion — the same
  32-bit internal representation `deliver_output()` also feeds to the FIFO in
  native mode
- **the dump always records this 32-bit representation, in BOTH `--compatible`
  and native mode** — it documents the internal DSP output, not the wire. In
  `--compatible` mode the FIFO itself is narrowed to 16-bit, but the dump tap
  sits upstream of that narrowing, so the WAV file stays a 32-bit container
  and the sample RATE follows the active output descriptor: `48000` Hz / 2ch /
  32-bit in native mode, `44100` Hz / 2ch / 32-bit in `--compatible` mode (the
  internal DSP chain, including the resampler and EQ, runs at that same
  descriptor rate in both modes)
- the tap is gated by `allow_capture`: only the input that is currently allowed
  to feed the FIFO contributes frames; monitoring-only inputs are not recorded
- pre-fill frames (the initial 0.5 s buffer accumulated before the first FIFO
  write) are captured; the WAV starts from audio time zero
- recording continues across silence gaps and FIFO stalls — it stops only when
  `stop_output_dump` is called or the daemon shuts down
- a bounded in-memory ring (≈ 2.97 s) decouples the audio thread from disk I/O;
  if the ring fills (e.g. a sustained disk stall), frames are dropped and counted
  in `dropped_frames` rather than blocking audio delivery

Output format: PCM WAV, always a 32-bit integer container / 2 channels; sample
rate matches the active output descriptor (`44100` Hz with `--compatible`,
`48000` Hz otherwise) -- see the always-32-bit note above.

Success response:

```json
{"type":"ack","command":"start_output_dump","ok":true,"path":"/tmp/autostream-dump.wav"}
```

Typical errors:

- `dump already active; call stop_output_dump first`
- `path is empty`
- `path must be absolute (start with /)`
- `path must not contain ..`
- `file already exists; use "overwrite":true to replace`
- `path exists but is not a regular file`
- `parent directory is not writable: ...`
- `failed to open output file: ...`

### `set_repeat_enabled`

Global enable + codec policy for the "repeat" feature (record the streamed
audio into an in-RAM buffer, and loop it back once armed -- see
`set_repeat_armed` below). A live setter, not a debounced reload.

Request:

```json
{"type":"set_repeat_enabled","enabled":true,"codec":"auto","target_minutes":33}
```

Request fields:

- `enabled`
  - `true` to record every capture session; `false` to disable
- `codec`
  - one of `auto` (target-duration selection picks a tier from free RAM at
    each recording start -- see below), `mp2_160`, `mp2_192`, `mp2_224`,
    `mp2_256`, `mp2_320`, `mp2_384`, or `pcm` (pinned; still subject to the
    base 110 MiB availability gate and the 64 MiB floor/sliding window)
  - defaults to `auto` if omitted or empty
- `target_minutes` (optional, integer, 10..600)
  - the recording duration the `auto` codec ladder tries to GUARANTEE in
    currently-usable RAM (MemAvailable, minus whatever is currently swapped
    out, minus a 64 MiB free-RAM floor). Selection: PCM s16 if PCM's
    footprint for `target_minutes` fits usable RAM; else the highest legal
    MP2 stereo bitrate (160/192/224/256/320/384 kbps) whose footprint fits,
    never below 160 kbps. If omitted entirely, the currently-configured
    value is left unchanged (defaults to 33 minutes the first time the
    daemon is started, never reset back to 33 by a later call that simply
    doesn't mention it). Out-of-range values are clamped to [10, 600].
    `target_minutes` is a SELECTION goal only, not an admission gate or a
    hard cap: once a session starts, the sliding window still behaves
    exactly as before (bounded only by that same 64 MiB floor and the
    chosen tier's byte rate) -- a recording can
    run past `target_minutes` if RAM allows, or fall short of it under
    memory pressure (head truncation), and if even 160 kbps's target
    footprint doesn't fit, the session still starts at 160 kbps rather than
    being refused.
  - The web UI's Settings page offers a "Vinyl (33 minutes)" / "CD (80
    minutes)" choice (set via the persisted `repeat.target_minutes` setting;
    see `core/autostream_config.py`'s `RepeatConfig`). Direct config-file
    edits still accept any value in [10, 600].

Behavior:

- turning `enabled` **on** takes effect at the next capture session; a
  session already in progress when this arrives is not retroactively recorded
- turning `enabled` **off** stops any in-progress recording and frees the
  buffer immediately (a finished-but-unreplayed recording is freed too)
- changing `codec` or `target_minutes` while `enabled` stays `true` does not
  affect a recording already in progress; both are read fresh at the next
  session start. This is the raw socket-command contract: a single
  `set_repeat_enabled` call with `enabled` unchanged never itself tears down
  a session. The web UI's buffer-target dropdown gets an immediate effect on
  top of this contract by issuing two calls -- `enabled:false` then
  `enabled:true` with the new `target_minutes` -- so the `enabled:false` edge
  frees any held buffer (including hard-aborting an active replay, per the
  `enabled` **off** behavior above) and the `enabled:true` edge re-arms at
  the new target. Direct config-file edits to `target_minutes` are not
  live-applied at all; they take effect only at the next daemon start or
  reconnect resync.

Success response:

```json
{"type":"ack","command":"set_repeat_enabled","ok":true}
```

Typical errors:

- `codec must be one of auto|mp2_160|mp2_192|mp2_224|mp2_256|mp2_320|mp2_384|pcm`

- turning `enabled` **off** while replay is active hard-aborts it (no fade)
  and frees the buffer, since the feature itself is going away

### `set_repeat_armed`

Session arm/disarm for the "repeat" feature's replay path. Not persisted;
process-global (visible to all connected browsers) and reset by a daemon
restart.

Request:

```json
{"type":"set_repeat_armed","armed":true}
```

Behavior:

- `armed:true` while a finished recording is sitting idle (no capture session
  in progress) starts replay **immediately**
- `armed:true` while a capture session is still recording takes effect at
  that session's capture-stop: replay begins right away, in the same status
  update that reports the session as stopped (no snapshot ever shows
  `is_capturing:false` with `repeat.armed:true` and non-zero recorded bytes
  but `repeat.replay.active:false`)
- `armed:false` while replay is active starts a 1.5 s fade-out; once complete,
  replay stops and the recording is retained (re-armable) rather than freed
- `armed:false` at any other time is just a flag clear (nothing to interrupt)

Success response (always `"ok":true` -- there is no rejectable input beyond
the boolean itself):

```json
{"type":"ack","command":"set_repeat_armed","ok":true}
```

### `debug_fail_input` (test-only)

**Test-only. Rejected unless the daemon was launched with `--test-hooks`
(never true in production).** Arms a one-shot flag that makes the target
input's capture thread take the exact same exit path as a genuine
unrecoverable ALSA read error on its next loop iteration -- i.e. it self-stops
(`is_started:true`, `is_running:false`), exactly the state the watchdog
auto-restart loop in `AudioMonitor::run()` polls for. Everything downstream
of that point (the watchdog's teardown-then-restart sequence, the repeat
controller's `notify_input_stopped()` handling) runs completely unmodified;
only the trigger is synthetic. This lets `tools/dev/repeat_test_driver.py`
exercise the watchdog path deterministically -- unloading the ALSA loopback
kernel module does not work because the daemon's own open PCM handle pins
the module (`rmmod` fails with "module in use").

Request:

```json
{"type":"debug_fail_input","input":1}
```

Success response:

```json
{"type":"ack","command":"debug_fail_input","input":1,"ok":true}
```

Typical errors:

- `test hooks not enabled` (daemon was not launched with `--test-hooks`)
- `input index must be 1 or 2`

### `stop_output_dump`

Stops the current recording, flushes buffered data, patches the WAV header with
the final data sizes, and closes the file.  No-op if no recording is active.

Request:

```json
{"type":"stop_output_dump"}
```

Success response:

```json
{
  "type":"ack",
  "command":"stop_output_dump",
  "ok":true,
  "was_active":true,
  "frames_written":441000,
  "dropped_frames":0
}
```

Response fields:

- `was_active`
  - `true` if a recording was in progress before this call
  - `false` if no recording was active (the call was a no-op)
- `frames_written`
  - total stereo frames written to disk for the recording that just stopped
- `dropped_frames`
  - total stereo frames dropped because the ring buffer was full
  - non-zero values indicate the recording has gaps (typically caused by a disk
    or filesystem stall on the target device)

Notes:

- if the daemon crashes mid-recording, the WAV header will have zero sizes but
  the raw `s16le` audio data begins at byte offset 44 and can be recovered
- the response always has `"ok":true`; there is no failure path for `stop_output_dump`


### `set_log_level`

Changes the daemon log level at runtime.

Request:

```json
{"type":"set_log_level","level":"warning"}
```

Accepted request values:

- `fatal`
- `log`
- `warn`
- `warning`
- `info`
- `debug`
- `spam`

Success response:

```json
{"type":"ack","command":"set_log_level","ok":true,"level":"warning"}
```

Normalized response levels are:

- `warning`
- `info`
- `debug`
- `spam`

Typical errors:

- `unsupported log level`

### `get_status`

Returns a full snapshot of the monitor state.

Request:

```json
{"type":"get_status"}
```

Success response:

```json
{
  "type":"status",
  "monitor_build":"0.2.0",
  "log_level":"warning",
  "output_rate":48000,
  "output_bits":32,
  "output_channels":2,
  "output_format":"native",
  "src_quality":"medium",
  "src_source":"auto",
  "output_clip_dbfs":0.0,
  "output_gain_db":0.0,
  "output_auto_trim_enabled":true,
  "output_auto_trim_db":-3.4,
  "effective_output_gain_db":-3.4,
  "output_dump":{
    "active":false,
    "path":"",
    "frames_written":0,
    "dropped_frames":0
  },
  "fifo":{
    "stalled_seconds":0.0
  },
  "repeat":{
    "enabled":true,
    "armed":true,
    "codec":"auto",
    "target_minutes":80,
    "max_recording_seconds":20340,
    "effective_codec":"mp2_256",
    "recording":{
      "active":false,
      "seconds":812.4,
      "bytes":19496448,
      "truncated_head":false,
      "origin_input":1,
      "dropped_frames":0,
      "unavailable_reason":null
    },
    "replay":{
      "active":true,
      "position_seconds":34.2,
      "duration_seconds":812.4,
      "loop_count":0
    }
  },
  "inputs":[
    {
      "index":1,
      "level_dbfs":-42.1,
      "poll_peak_dbfs":-38.2,
      "silent":false,
      "capturing":true,
      "detected_hz":44097.3,
      "raw_peak_dbfs":-12.3,
      "effective_peak_dbfs":-9.1,
      "started":true,
      "running":true,
      "vu_history":{
        "bin_ms":100,
        "latest_seq":42,
        "bins":[
          {"seq":41,"l":-18.3,"r":-19.1},
          {"seq":42,"l":-17.2,"r":-17.8}
        ]
      }
    }
  ]
}
```

Top-level fields:

- `monitor_build`
  - build string compiled into the running `autostream_monitor` binary
  - intended to help detect a stale monitor binary after an update if the
    rebuild or redeploy failed
- `log_level`
  - current runtime log level
- `output_rate` / `output_bits` / `output_channels`
  - the wire format of the PCM stream written to the FIFO. Selected once at
    daemon startup (`--compatible`, see Command-Line Options in
    [AUTOSTREAM-MONITOR.md](AUTOSTREAM-MONITOR.md)) and
    reported here at runtime rather than assumed by the Python layer
  - same format for both FIFO writers (the live `FifoWriter` path and the
    `ReplayEngine` replay path) -- they share one runtime descriptor
    (`g_output_format`, set once in `main()` before any thread starts)
  - default (native, `--compatible` absent): `48000` / `32` / `2`; samples
    are a 32-bit left-justified container -- an s16 source occupies the top
    16 bits
  - with `--compatible`: `44100` / `16` / `2` -- both FIFO writers (live and
    replay) actually narrow the wire to match these numbers, not just
    report them
- `output_format`
  - `"native"` or `"compatible"` -- a readable label for the same choice the
    three numeric fields above encode
- `src_quality`
  - `"fast"`, `"medium"`, or `"best"` -- the sample-rate-converter tier the
    main FIFO-output converter was created with (see `--src` under
    Command-Line Options in [AUTOSTREAM-MONITOR.md](AUTOSTREAM-MONITOR.md)).
    Fixed for the process's lifetime; a
    changed tier only takes effect on the next monitor restart
- `src_source`
  - `"flag"` if `--src` selected the tier, `"auto"` if it came from the
    CPU-part auto-detect fallback
- `output_clip_dbfs`
  - maximum post-EQ, post-gain overshoot above 0 dBFS since the previous
    `get_status` call
  - `0.0` means no clipping
  - this value is reset on every `get_status` call
- `output_gain_db`
  - currently configured manual output gain
  - range `[-10.0, +10.0]`; default `0.0`
- `output_auto_trim_enabled`
  - whether auto-trim is currently active
- `output_auto_trim_db`
  - current auto-trim cut in dB; always `<= 0.0`
  - `0.0` means no trim has been applied this session
  - reported even when auto-trim is disabled
- `effective_output_gain_db`
  - `output_gain_db + output_auto_trim_db`
  - use this value as the `gain_db` argument to `set_output_gain` to make the
    auto-derived attenuation permanent
- `output_dump`
  - snapshot of the engineering output dump state
  - `active`: `true` while a `start_output_dump` recording is in progress
  - `path`: path passed to the most recent `start_output_dump` call (empty if
    never started)
  - `frames_written`: stereo frames written to disk so far (or in the last
    completed recording)
  - `dropped_frames`: stereo frames dropped because the ring buffer was full
- `fifo`
  - `stalled_seconds`: seconds the CURRENT active FIFO writer (the live
    capturing input, or ReplayEngine while it owns the pipe) has been
    continuously failing/dropping writes -- no reader attached (`ENXIO`),
    reader not draining (`EAGAIN`/poll timeout), or a broken pipe
    (`EPIPE`/`EBADF`)
  - `0.0` whenever the last write succeeded, or whenever nothing is currently
    trying to write (no input capturing and no active replay) -- this is a
    "is the downstream reader (e.g. OwnTone) actually keeping up" signal, not
    a general daemon-health signal
  - intended as an owntone-hang watchdog input for the Python side: a large,
    growing value with an active capture/replay session means bytes are not
    reaching the reader even though the monitor itself is alive and
    responding to `get_status`
- `repeat`
  - snapshot of the "repeat" feature's state (record + replay + the
    live-interrupt crossfade trigger)
  - `enabled`: current `set_repeat_enabled` policy
  - `armed`: current session-arm flag (`set_repeat_armed`); process-global,
    not persisted, reset by a daemon restart
  - `codec`: current codec policy (`auto`|`mp2_160`|`mp2_192`|`mp2_224`|
    `mp2_256`|`mp2_320`|`mp2_384`|`pcm`)
  - `target_minutes`: current target-duration goal (default 33; see
    `set_repeat_enabled` above) -- what the `auto` ladder tries to
    guarantee, not a hard cap on the sliding window
  - `max_recording_seconds`: sliding-window size in seconds, computed from
    usable RAM (MemAvailable, minus whatever is currently swapped out, minus
    a 64 MiB free-RAM floor) and the resolved codec tier's byte rate -- the
    window itself still has no fixed-duration cap (bounded only by that same
    64 MiB floor + the resolved tier's byte rate). Available whenever
    `enabled` is `true`, not just while a
    recording is active: while recording, this is the value computed when
    that session started; while enabled but idle/holding, it is computed on
    demand from a periodically-refreshed free-RAM reading, reflecting what a
    session started right now would get (using the ladder's pick for the
    *current* free RAM when `codec == "auto"`). `0` only when genuinely
    unavailable: `enabled` is `false`, or no free-RAM reading has landed yet
    (a brief window right after daemon startup or re-enabling)
  - `effective_codec`: the tier `max_recording_seconds` assumes -- the active
    session's codec while recording, else the tier a session started right
    now would resolve to (e.g. `mp2_256`, `pcm`). Empty string when the
    estimate is unavailable. The setup page renders the two together
    ("Buffer: 84 mins (256Kbps MP2)").
  - `recording.active`: `true` while a recording is in progress (`false`
    while `replay.active` is `true` -- recording and replay are never both
    active at once; recording while replaying is out of scope)
  - `recording.seconds`: approximate recorded duration (`bytes / byte_rate`
    for the resolved codec)
  - `recording.bytes`: bytes currently held in the recording buffer
  - `recording.truncated_head`: `true` once the sliding window has dropped at
    least one chunk from the head under memory pressure or the target-length
    cap; replay only ever plays the retained tail in that case
  - `recording.origin_input`: input index (`1` or `2`) that produced the
    recording; `0` if none
  - `recording.dropped_frames`: frames dropped by the recorder's encode ring
    since the current/most recent recording began (ring overrun, e.g. under
    CPU starvation); the live FIFO path is never affected by this
  - `recording.unavailable_reason`: `null` normally; `"insufficient_memory"`
    when a capture session started with `enabled:true` but free RAM was below
    the 110 MiB minimum, so no recording was started for that session;
    `"encoder_init_failed"` on the (defensive, should not occur) case where
    codec encoder construction itself fails
  - `replay.active`: `true` while the recording is looping back into the FIFO
    (including the disarm fade-out window -- see `set_repeat_armed`)
  - `replay.position_seconds` / `replay.duration_seconds`: playback position
    within the current loop and the recording's total duration
  - `replay.loop_count`: number of times playback has looped back to the
    start since replay began (`0` during the first pass)
  - while `replay.active` is `true`, the origin input's `track_change_seq` in
    the `inputs[]` array below (and its `get_id_snapshot` response) are
    served from the replay path's own tap, not the (now-silent) InputChannel

Per-input fields:

- `index`
  - input number
- `level_dbfs`
  - current raw input level
- `poll_peak_dbfs`
  - maximum raw peak seen since the previous `get_status` call
  - reset on each poll
- `silent`
  - whether silence timeout conditions currently consider the input silent
- `capturing`
  - whether this input is presently allowed and active for capture-to-FIFO
- `detected_hz`
  - estimated real input sample rate
- `raw_peak_dbfs`
  - session raw peak since input start
- `effective_peak_dbfs`
  - session peak after per-input gain/EQ, but before output EQ
- `started`
  - whether `start_input` has been called and the input has not yet been fully
    stopped/cleaned up
- `running`
  - whether the worker threads are actively running
- `track_change_seq`
  - monotonic per-input counter incremented each time a possible track boundary
    is detected; a qualifying short gap followed by resumed audio constitutes one
    event
  - resets to `0` when the input channel starts or restarts; Python baselines
    the value on capture start so a reset is not mistaken for a new boundary
  - may wrap naturally from `2^32 − 1` back to `0`; Python detects inequality
    rather than monotonic increase, so a wrap during one uninterrupted session
    still produces exactly one boundary event
  - this is a heuristic signal, not a guaranteed track-boundary count; gapless
    or noisy recordings may produce no events, while quiet passages may produce
    false ones
  - distinct from `silent` and `capturing`: those fields debounce silence for
    the configured playback stop timeout (typically 30 s); `track_change_seq`
    fires on much shorter gaps while playback remains active
  - field is absent on older monitor builds; Python defaults a missing field to `0`
- `vu_history`
  - rolling stereo peak history for driving a delayed VU meter display
  - `bin_ms`: bin duration in milliseconds (always `100`)
  - `latest_seq`: sequence number of the most recent bin (resets on channel
    restart; `0` if no bins have been produced yet)
  - `bins`: array of up to 40 bins ordered oldest-first, each containing:
    - `seq`: bin sequence number
    - `l`: peak left-channel level in dBFS for that 100 ms window
    - `r`: peak right-channel level in dBFS for that 100 ms window

### `get_id_snapshot`

Returns recent mono PCM audio for fingerprinting or identification.

Request:

```json
{"type":"get_id_snapshot","input":1}
```

Or:

```json
{"type":"get_id_snapshot","input":1,"max_seconds":10}
```

Behavior:

- `max_seconds` defaults to `20`
- values lower than `1` are clamped to `1`
- values higher than `20` are clamped to `20`
- audio format is mono `s16le` at `16000 Hz`
- the snapshot is taken from a rolling ID buffer populated via a dedicated
  `libsamplerate` (SRC_LINEAR) conversion from 48000 Hz to 16000 Hz, before
  gain and EQ

Success response:

```json
{"type":"ack","command":"get_id_snapshot","input":1,"ok":true,"format":"s16le","rate":16000,"channels":1,"frames":12345}
```

On success, the JSON line is followed immediately by raw binary PCM:

- sample format: signed 16-bit little-endian
- channels: `1`
- sample rate: `16000`
- payload bytes: `frames * 2`

The client must read exactly `frames * 2` bytes after the newline.

Typical errors:

- `input index must be 1 or 2`
- `no snapshot data available`

