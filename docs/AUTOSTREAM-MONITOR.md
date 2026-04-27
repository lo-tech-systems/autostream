# autostream_monitor

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
    `OutputProcessor`, and the `ControlServer`
- `ControlServer`
  - listens on a Unix domain socket
  - accepts newline-delimited JSON commands
  - returns exactly one response per command
- `InputChannel`
  - represents one input source
  - owns capture/process threads, ALSA state, resampler state, input gain, and
    per-input EQ
- `OutputProcessor`
  - applies the shared output-side EQ after per-input processing and before FIFO
    write
  - also tracks post-EQ clipping
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

## Command-Line Options

The daemon binary supports:

```text
autostream_monitor [--socket PATH] [--log-level LEVEL]
```

- `--socket PATH`
  - override the Unix socket path
- `--log-level LEVEL`
  - accepted values: `warn`, `warning`, `log`, `fatal`, `info`, `debug`, `spam`

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
  "silence_seconds":30
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
{"type":"set_fifo","path":"/tmp/autostream-pipes/autostream.fifo"}
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
  "log_level":"warning",
  "output_clip_dbfs":0.0,
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
      "running":true
    }
  ]
}
```

Top-level fields:

- `log_level`
  - current runtime log level
- `output_clip_dbfs`
  - maximum post-output-EQ overshoot above 0 dBFS since the previous
    `get_status` call
  - `0.0` means no clipping
  - this value is reset on every `get_status` call

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
- audio format is mono `s16le` at `22050 Hz`
- the snapshot is taken from a rolling buffer populated from post-SRC audio
  before gain and EQ

Success response:

```json
{"type":"ack","command":"get_id_snapshot","input":1,"ok":true,"format":"s16le","rate":22050,"channels":1,"frames":12345}
```

On success, the JSON line is followed immediately by raw binary PCM:

- sample format: signed 16-bit little-endian
- channels: `1`
- sample rate: `22050`
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
7. clip scan
8. float-to-`int16` conversion
9. FIFO write

This ordering matters:

- identification snapshots are intentionally pre-gain and pre-EQ
- `effective_peak_dbfs` reflects per-input processing but not output EQ
- `output_clip_dbfs` reflects the final post-output-EQ float-domain signal

## Notes And Caveats

- The protocol is intentionally small and hand-parsed rather than using a full
  JSON library.
- `configure_input` uses the wire field name `device`, not `alsa_device`.
- EQ updates are applied lazily by the audio threads; a new EQ setting may take
  effect on the next processed block rather than mid-block.
- `set_allow_capture(true)` for one input implicitly disables FIFO capture on
  the other input.
- `get_status` is a poll/reset API for peak and clip accumulators, not a pure
  read-only snapshot.

## Source Of Truth

This document summarizes the current implementation in:

- `core/monitor/autostream_monitor.h`
- `core/monitor/autostream_monitor.cpp`

If this document and the code ever disagree, treat the code as authoritative.
