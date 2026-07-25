# autostream_monitor

This document is the canonical external reference for the `autostream_monitor`
daemon's socket protocol, request/response shapes, and integration behavior.
Implementation-local invariants, concurrency notes, and code-structure details
remain documented alongside the relevant C++ code.

## Purpose

`core/monitor/autostream_monitor.cpp` is the native audio monitor daemon used by
autostream.

It is responsible for:

- enumerating ALSA capture devices
- capturing audio from up to two USB inputs
- detecting silence and measuring levels
- estimating real input sample rate and correcting drift with libsamplerate
- applying per-input EQ and gain
- applying shared output EQ
- writing a 44.1 kHz stereo PCM stream to a named FIFO for the playback backend
- exposing a local control API over a Unix domain socket
- serving short mono audio snapshots for identification/fingerprinting

It does not talk to the playback backend directly. Python remains responsible
for higher-level orchestration, UI, settings, and playback-backend control.

## Main Components

- `AudioMonitor`
  - top-level coordinator
  - owns the two `InputChannel` instances, the shared `FifoWriter`, the shared
    `OutputProcessor`, the `OutputDumpWriter`, and the `ControlServer`
- `ControlServer`
  - listens on a Unix domain socket
  - accepts newline-delimited JSON commands
  - returns exactly one response per command
- `InputChannel`
  - represents one input source
  - owns capture/process threads, ALSA state, resampler state, input gain, and
    per-input EQ
- `OutputProcessor`
  - applies the shared output-side EQ after per-input processing
  - applies manual output gain and automatic output trim after the EQ
  - tracks post-gain clipping and exposes it via `output_clip_dbfs`
- `OutputDumpWriter`
  - engineering-only tap that records the final processed audio stream to a WAV
    file on demand; controlled via the same socket API
  - completely isolated from normal FIFO delivery; uses a bounded SPSC ring so
    the audio thread never blocks on disk I/O
- `RepeatController` / `RepeatRecorder` / `ReplayEngine`
  - "repeat" feature: records the streamed audio into an in-RAM buffer while
    a capture session is active, and loops it back into the same FIFO once
    armed, until disarmed or new live audio interrupts it (crossfades out on
    interrupt)
  - `RepeatRecorder` uses the same SPSC-ring + low-priority-worker-thread
    pattern as `OutputDumpWriter`; encodes to MP2 (libtwolame) or PCM s16
    depending on free RAM. The sliding window has no fixed-duration target --
    it is bounded ONLY by a 64 MiB free-RAM floor and the codec ladder,
    buffering as much as current free RAM allows for as long as it allows it
  - `ReplayEngine` is a dedicated I/O-bound thread that decodes (libmpg123 for
    the MP2 tier) and paces playback via the reader's own consumption of the
    FIFO, looping until stopped; see `set_repeat_enabled`, `set_repeat_armed`,
    and the `repeat` status block below
- `EqChain` and `BiquadFilter`
  - implement the parametric EQ system
- `RateEstimator`
  - estimates the real capture rate so long-running playback stays in sync

## Runtime Model

- Up to two inputs can be configured and monitored at once.
- Only one input may actively write to the shared FIFO at a time.
- Each input has:
  - its own ALSA capture device
  - silence detection state
  - per-input gain
  - per-input EQ
- The final mixed output path is not a mixer. Instead, one active input is
  allowed to feed the FIFO at a time via `set_allow_capture`.
- Output EQ is shared across all inputs and is applied after per-input gain/EQ.

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

## Command-Line Options

The daemon binary supports:

```text
autostream_monitor [--socket PATH] [--log-level LEVEL] [--test-hooks]
```

- `--socket PATH`
  - override the Unix socket path
- `--log-level LEVEL`
  - accepted values: `warn`, `warning`, `log`, `fatal`, `info`, `debug`, `spam`
- `--test-hooks`
  - **test-only, never set by the production systemd unit.** Enables the
    `debug_fail_input` socket command (see below). Intended for a standalone
    test-instance daemon driven by `tools/dev/repeat_test_driver.py`, never
    the live daemon.

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
  "track_change_silence_seconds":1.25
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

Important behavior:

- if the input is stopped, all fields are applied
- if the input is already running, only silence settings are runtime-tunable
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
- `stop the input before changing device`

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
- applied at the fixed output rate of 44.1 kHz
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
  EQ, output gain, auto-trim) and after float-to-`int16` conversion — the same
  final signal written to the FIFO
- the tap is gated by `allow_capture`: only the input that is currently allowed
  to feed the FIFO contributes frames; monitoring-only inputs are not recorded
- pre-fill frames (the initial 0.5 s buffer accumulated before the first FIFO
  write) are captured; the WAV starts from audio time zero
- recording continues across silence gaps and FIFO stalls — it stops only when
  `stop_output_dump` is called or the daemon shuts down
- a bounded in-memory ring (≈ 2.97 s) decouples the audio thread from disk I/O;
  if the ring fills (e.g. a sustained disk stall), frames are dropped and counted
  in `dropped_frames` rather than blocking audio delivery

Output format: PCM WAV, 44100 Hz, 2 channels, signed 16-bit little-endian.

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
{"type":"set_repeat_enabled","enabled":true,"codec":"auto"}
```

Request fields:

- `enabled`
  - `true` to record every capture session; `false` to disable
- `codec`
  - one of `auto` (codec ladder picks a tier from free RAM at each recording
    start), `mp2_160`, `mp2_192`, `mp2_224`, or `pcm` (pinned; still subject to
    the base 110 MiB availability gate and the 64 MiB floor/sliding window)
  - defaults to `auto` if omitted or empty

Behavior:

- turning `enabled` **on** takes effect at the next capture session; a
  session already in progress when this arrives is not retroactively recorded
- turning `enabled` **off** stops any in-progress recording and frees the
  buffer immediately (a finished-but-unreplayed recording is freed too)
- changing `codec` while `enabled` stays `true` does not affect a
  recording already in progress; it is read fresh at the next session start

Success response:

```json
{"type":"ack","command":"set_repeat_enabled","ok":true}
```

Typical errors:

- `codec must be one of auto|mp2_160|mp2_192|mp2_224|pcm`

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
    "max_recording_seconds":20340,
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
  - `codec`: current codec policy (`auto`|`mp2_160`|`mp2_192`|`mp2_224`|`pcm`)
  - `max_recording_seconds`: sliding-window size in seconds, computed from free
    RAM and the resolved codec tier's byte rate -- there is no fixed-duration
    target any more (the window is bounded only by the 64 MiB free-RAM floor
    + codec ladder). Available whenever `enabled` is `true`, not just while a
    recording is active: while recording, this is the value computed when
    that session started; while enabled but idle/holding, it is computed on
    demand from a periodically-refreshed free-RAM reading, reflecting what a
    session started right now would get (using the ladder's pick for the
    *current* free RAM when `codec == "auto"`). `0` only when genuinely
    unavailable: `enabled` is `false`, or no free-RAM reading has landed yet
    (a brief window right after daemon startup or re-enabling)
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
  `libsamplerate` (SRC_LINEAR) conversion from 44100 Hz to 16000 Hz, before
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

## Processing Order

For an input that is actively feeding the FIFO, the signal path is:

1. ALSA capture
2. sample-rate conversion to `44100 Hz` stereo
3. identification snapshot tap
4. per-input gain
5. per-input EQ
6. output EQ
7. output gain (`output_gain_db + output_auto_trim_db`)
8. clip scan and auto-trim update
9. float-to-`int16` conversion
10. FIFO write

This ordering matters:

- identification snapshots are intentionally pre-gain and pre-EQ
- `effective_peak_dbfs` reflects per-input processing but not output EQ or output gain
- `output_clip_dbfs` reflects the final level after all processing, matching what
  is written to the FIFO
- auto-trim sees the real final level, so it reacts to headroom consumed by any
  combination of per-input gain, per-input EQ, output EQ, and manual output gain

## Notes And Caveats

- The protocol is intentionally small and hand-parsed rather than using a full
  JSON library.
- `configure_input` uses the wire field name `device`, not `alsa_device`.
- EQ updates are applied lazily by the audio threads; a new EQ setting may take
  effect on the next processed block rather than mid-block.
- `set_allow_capture(true)` for one input implicitly disables FIFO capture on
  the other input and resets the output auto-trim to `0.0 dB`.
- `stop_input` also resets the output auto-trim to `0.0 dB`; each new session
  starts from zero attenuation regardless of what accumulated in the previous one.
- `get_status` is a poll/reset API for peak and clip accumulators, not a pure
  read-only snapshot.
- `output_auto_trim_db` is always reported (even when auto-trim is disabled) so
  that polling clients can display the current effective gain without needing to
  track whether auto-trim is on or off.
- Shutdown: the control server must `shutdown()` its listening socket before
  `close()` — on Linux, `close()` alone does not wake a thread blocked in
  `accept()`. Without this, a SIGTERM stop hangs until systemd escalates to
  SIGKILL after its stop timeout.

### Atomics and lock-freedom

The daemon uses `std::atomic<double>` in hot paths: the `RateEstimator`'s
published ratio/rate (updated at most every 10 s) and the `_stall_since`
stall trackers written once per audio block on the process thread. On
32-bit ARMv6 these 8-byte atomics could fall back to a libatomic lock
table — a hidden lock on the audio thread. This is closed as a non-issue
by product policy: **the monitor only ships on 64-bit OS** (32-bit is
supported solely for autostream-dial, which does not include
`autostream_monitor`). Verified on aarch64 (Debian 13, g++ 14):
`std::atomic<double>::is_always_lock_free == 1` and the linked binary
carries no `libatomic` dependency. If a 32-bit monitor target is ever
reintroduced, switch these fields to integer atomics
(`std::atomic<int64_t>` milliseconds).

## Source Of Truth

For the external contract, treat this document as the primary reference.

The C++ source remains authoritative for implementation details and internal
invariants, especially around threading, handoff sequencing, and DSP state
management.

Relevant source files:

- `core/monitor/autostream_monitor.h`
- `core/monitor/autostream_monitor.cpp`

If this document and the code ever disagree about externally observable
behavior, update one of them so there is a single clear truth again rather than
leaving both versions in circulation.
