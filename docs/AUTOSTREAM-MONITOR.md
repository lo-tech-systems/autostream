# autostream_monitor

This document covers what the `autostream_monitor` daemon is, how it runs, and
how it is configured. The socket protocol, request/response shapes, and the
complete per-command reference live in
[AUTOSTREAM-MONITOR-API.md](AUTOSTREAM-MONITOR-API.md).
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
- writing a 48 kHz stereo PCM stream to a named FIFO for the playback backend
- exposing a local control API over a Unix domain socket
- serving short mono audio snapshots for identification/fingerprinting

It does not talk to the playback backend directly. Python remains responsible
for higher-level orchestration, UI, settings, and playback-backend control.

## Main Components

- `AudioMonitor`
  - top-level coordinator
  - owns the two `InputChannel` instances, the `OutputMixer` and
    `OutputStage`, the shared `FifoWriter`, the shared `OutputProcessor`,
    the `OutputDumpWriter`, and the `ControlServer`
- `ControlServer`
  - listens on a Unix domain socket
  - accepts newline-delimited JSON commands
  - returns exactly one response per command
- `InputChannel`
  - represents one input source
  - owns capture/process threads, ALSA state, resampler state, input gain, and
    per-input EQ
  - pushes its finished, resampled and per-input-processed blocks into its
    own ring in the `OutputMixer`
- `OutputMixer` / `OutputStage`
  - the single point where every source reaches the FIFO: each live input
    and the replay push their finished, gain- and EQ-adjusted blocks into
    their own ring; one thread mixes whichever rings are active, applies a
    per-source gain ramp, and writes fixed 20 ms blocks
  - clocked by whichever live input is active; falls back to the monotonic
    clock when none is, so the pipe absorbs jitter either way
  - an inactive source is neither read nor summed, and costs nothing
  - every transition is a gain ramp in the same continuous stream: a live
    input taking over from a replay is a 1.5 s crossfade heard the moment it
    is made; a disarm fade is the same 1.5 s ramp on the replay alone; a
    live session starting from idle fades in over 1 s; an input-to-input
    switch happens only once the old input has gone silent and is a ramp
    with no overlap
  - the replay never runs ahead of the output, so latency is the same
    whichever way a session began
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
    a capture session is active, and loops it back into the shared output
    stream once armed, until disarmed or new live audio interrupts it
    (crossfades out on interrupt)
  - a live interrupt of an actively-playing replay is probation-gated: the
    new audio must sustain above threshold -- 0.25 s for a line-level input,
    1.25 s for a turntable -- bounded by a 5 s wall clock, before the
    crossfade begins, so a brief transient cannot tear down a replay. A
    probation that does not sustain expires silently, leaving the replay
    untouched
  - `RepeatRecorder` uses the same SPSC-ring + low-priority-worker-thread
    pattern as `OutputDumpWriter`; encodes to MP2 (libtwolame) or PCM s16.
    The recording lives in a FIXED ARENA reserved once, when the feature is
    enabled: the codec/bitrate tier is chosen to fit a target recording
    duration (`target_minutes`, default 33) in whatever RAM is usable
    (MemAvailable, minus a 96 MiB free-RAM floor) -- PCM if it fits, else
    the highest legal MP2 bitrate (160/192/224/256/320/384 kbps) that fits,
    never below the 160 kbps floor. Below that floor, DURATION degrades instead of quality: the
    arena is capped at what usable RAM holds and the achieved capacity is
    reported truthfully (requested vs delivered). The arena is committed
    incrementally on the worker thread (one page-touched chunk at a time,
    re-checking the floor between chunks, after a boot-settle delay) and
    persists across sessions -- session start only resets cursors inside
    it. Because the daemon locks its memory at startup (see Notes And
    Caveats below), every chunk stays resident as it is touched, so the
    finished arena ends up fully resident and locked, not just reserved.
    Once full, the arena wraps: the oldest chunk is recycled in place,
    so a longer-than-capacity session always holds the most recent audio.
    Disabling the feature (or changing `target_minutes`/the pinned codec)
    frees the arena and re-plans it
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
- Only one input may capture to the FIFO at a time: `set_allow_capture`
  enabling one input disables the other.
- Each input has:
  - its own ALSA capture device
  - silence detection state
  - per-input gain
  - per-input EQ
- One output stage owns the FIFO. Each live input and the replay push their
  finished, gain- and EQ-adjusted blocks into their own ring; one thread
  mixes whichever rings are active, with a per-source gain ramp, and writes
  the result. At most two sources are ever active together, during a
  crossfade between a replay and the live input taking over from it; an
  inactive source is neither read nor summed.
- Output EQ is shared across all sources and is applied once per mixed
  block, after per-input gain and EQ.

## Thread Scheduling And Priority

The audio-critical threads run under Linux's real-time `SCHED_FIFO` policy
instead of the default best-effort scheduler, so a burst of ordinary system
load cannot preempt them for long enough to lose samples or force a
silence-fallback.

- `set_thread_realtime()` (`autostream_monitor_utils.cpp`) wraps
  `pthread_setschedparam(pthread_self(), SCHED_FIFO, ...)` for the calling
  thread. Each audio-critical thread calls it once, near the top of its own
  entry point, right after the thread starts:
  - input capture (`autostream_monitor_io.cpp`) -- `kRtPrioCapture` = 60
  - input processing (`autostream_monitor_io.cpp`) -- `kRtPrioProcess` = 58
  - replay decode (`autostream_repeat.cpp`) -- `kRtPrioReplay` = 56
  - the output stage (`autostream_output_stage.cpp`) -- `kRtPrioOutput` = 54
- Under `SCHED_FIFO`, a higher priority number preempts a lower one. Capture
  is highest because a missed ALSA period is unrecoverable -- the samples are
  simply gone -- while the output stage is lowest of the four because a late
  FIFO write still has the writer's own backlog (see the FIFO backlog note
  under Notes And Caveats) to absorb it before anything is actually lost.
- The promotion is best-effort and never fatal. It needs `CAP_SYS_NICE`,
  granted via `LimitRTPRIO=80` in the systemd unit
  (`system/systemd/autostream_monitor.service`). If `pthread_setschedparam`
  fails for any reason -- missing capability, running outside the packaged
  unit, a lower RT limit -- the thread logs a warning and continues at
  normal scheduling; nothing else about it changes.
- The kernel's real-time scheduling throttle (the default cap that reserves
  some CPU time for non-RT work even when RT threads are runnable) is left
  at whatever the host's default is. The monitor does not raise, lower, or
  otherwise touch it.
- This is a different safeguard from `mlockall` (see Notes And Caveats): RT
  priority keeps these threads from being descheduled under load, while
  `mlockall` keeps their memory from being paged out. A scheduling delay on
  the capture thread risks losing samples from the source device before the
  next ALSA period is read; a scheduling delay on the output thread risks a
  FIFO underrun on the playback side. Both threads need both protections for
  the same underlying reason: nothing else in the pipeline can recover audio
  once either one actually stalls.

## Socket API

The daemon listens on a Unix domain socket and speaks newline-delimited JSON.
The transport, general response shape, data types, and the complete per-command
reference are documented separately in
[AUTOSTREAM-MONITOR-API.md](AUTOSTREAM-MONITOR-API.md).

## Command-Line Options

The daemon binary supports:

```text
autostream_monitor [--socket PATH] [--log-level LEVEL] [--test-hooks] [--compatible] [--src LEVEL]
```

- `--socket PATH`
  - override the Unix socket path
- `--log-level LEVEL`
  - accepted values: `warn`, `warning`, `log`, `fatal`, `info`, `debug`, `spam`
- `--test-hooks`
  - **test-only, never set by the production systemd unit.** Enables the
    `debug_fail_input` socket command (see
    [AUTOSTREAM-MONITOR-API.md](AUTOSTREAM-MONITOR-API.md)). Intended for a standalone
    test-instance daemon driven by `tools/dev/repeat_test_driver.py`, never
    the live daemon.
- `--compatible`
  - output the FIFO as 44.1kHz/16-bit stereo instead of the native
    48kHz/32-bit stream, for stock (upstream) OwnTone or a pre-48k
    owntone-mini -- both have a named-pipe input fixed at 44.1kHz/16-bit and
    no way to accept a different format. Default (this flag absent) is
    native 48kHz/32-bit.
  - The daemon narrows the wire itself (not just the reported format): the
    output stage converts the mixed block to 16-bit right before the FIFO
    write, whichever source -- a live input or the replay -- produced it, so
    `--compatible` is a complete, byte-correct 44.1kHz/16-bit wire, safe to
    run against stock OwnTone or a pre-48k owntone-mini.
- `--src LEVEL`
  - sample-rate-converter quality for the main FIFO output path.
    `LEVEL` is one of `fast`, `medium`, `best`, mapping to libsamplerate's
    `SRC_SINC_FASTEST` / `SRC_SINC_MEDIUM_QUALITY` / `SRC_SINC_BEST_QUALITY`.
  - default (this flag absent): auto-detected from `/proc/cpuinfo` CPU part
    ids -- Cortex-A72/A76-class (Pi 4/5) -> `best`, everything else
    (Cortex-A53-class, unknown, unreadable) -> `medium`. The auto-detect
    default is `medium`, never `fast` -- `fast` is reachable only via an
    explicit `--src fast`.
  - an invalid `LEVEL` logs a warning and falls back to the same
    auto-detect used when the flag is absent, rather than exiting -- the
    appliance must not stay down over a bad env file. This differs from an
    unrecognised *flag*, which still exits with usage.
  - scope: only the main stereo FIFO-output converter. The internal
    track-ID/fingerprint resampler always runs at `SRC_SINC_FASTEST`
    regardless of this setting.
  - the tier is fixed for the process's lifetime at converter-creation time
    (libsamplerate has no API to re-type a converter after `src_new()`) --
    there is no runtime/adaptive tier switching. A changed tier takes
    effect the next time an input is (re)started, in practice a monitor
    restart.
  - startup logs the resolved tier and its provenance, e.g.
    `[monitor] SRC quality: medium (auto: cortex-a53)` or
    `[monitor] SRC quality: best (--src override)`. The resolved tier and
    source are also reported at runtime in `get_status`'s `src_quality` /
    `src_source` fields (see [AUTOSTREAM-MONITOR-API.md](AUTOSTREAM-MONITOR-API.md))
    so the Python layer reads them instead of assuming them.

## Processing Order

For a source contributing to the output -- a live input capturing to the
FIFO, or the replay -- the signal path is:

1. ALSA capture (replay: decode from the recording)
2. sample-rate conversion to `48000 Hz` stereo (replay is decoded at the
   same rate)
3. identification snapshot tap
4. per-input gain (replay: the origin input's gain)
5. per-input EQ (replay: the origin input's EQ)
6. mixed into the shared output stage together with any other currently
   active source, each at its own gain
7. output EQ
8. output gain (`output_gain_db + output_auto_trim_db`)
9. clip scan and auto-trim update
10. float-to-`int16` conversion
11. FIFO write

This ordering matters:

- identification snapshots are intentionally pre-gain and pre-EQ
- `effective_peak_dbfs` reflects per-input processing but not mixing, output
  EQ, or output gain
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
  `close()` - on Linux, `close()` alone does not wake a thread blocked in
  `accept()`. Without this, a SIGTERM stop hangs until systemd escalates to
  SIGKILL after its stop timeout.
- The FIFO write end requests a 1 MiB pipe buffer (`F_SETPIPE_SZ`) every
  time it is opened (including every reopen), so a short reader stall can be
  absorbed without dropping a block instead of just the kernel's default
  buffer size. The granted size is logged; if the kernel refuses the
  resize, the daemon logs a warning once and continues at the default pipe
  size rather than retrying on every open.
- Beyond the pipe itself, the writer keeps any bytes a stalled reader will
  not yet accept in a backlog (capped at 1 s of audio at the output rate)
  and delivers them ahead of the next block once the reader resumes, so only
  a stall longer than that combined headroom loses audio.
- A stream that has gone more than 1 s without a successful write is treated
  as a cold start: the output stage buffers the next 0.5 s and writes it as
  one block before resuming block-by-block writes. A transition between
  sources -- a crossfade, an input switch -- never triggers this, because
  the stream is already flowing.
- At startup the daemon calls `mlockall(MCL_CURRENT | MCL_FUTURE |
  MCL_ONFAULT)` so its memory is pinned as it is touched, rather than paged
  out under memory pressure. This requires `LimitMEMLOCK=infinity` in the
  systemd unit, since the daemon runs unprivileged. If locking fails, it
  logs a warning and continues unlocked.

### `--test-pin-src-ratio` (test-only)

Requires `--test-hooks`; rejected at startup otherwise. Pins the SRC ratio to
the nominal value published at capture start (exactly 1.0 on a loopback whose
capture rate equals the 48000 Hz output rate), disabling rate-drift
correction entirely. This makes the whole audio pipeline a pure function of
the input samples, which golden-reference byte-compare testing depends on -
without it, the `RateEstimator`'s timing-adaptive ratio makes output
non-deterministic run-to-run (first divergence roughly 0.5 s into otherwise
identical runs). Never set in production: drift correction is a core product
function.

### Test-hooks device-string relaxation

When the daemon is started with `--test-hooks`, `configure_input` accepts any
non-empty ALSA device string, not just `hw:*`. Golden-reference runs capture
from a named ALSA `file`-plugin PCM (which replays a fixed raw file into the
capture stream, making content position-locked and byte-deterministic); such
a PCM cannot be spelled with an `hw:` prefix because ALSA's resolver
intercepts `hw:*` before consulting named `pcm.*` definitions. Production
(no `--test-hooks`) keeps the strict `hw:*` validation.

### Atomics and lock-freedom

The daemon uses `std::atomic<double>` in hot paths: the `RateEstimator`'s
published ratio/rate (updated at most every 10 s) and the `_stall_since`
stall trackers written once per audio block on the process thread. On
32-bit ARMv6 these 8-byte atomics could fall back to a libatomic lock
table - a hidden lock on the audio thread. This is closed as a non-issue
by product policy: **the monitor only ships on 64-bit OS** (32-bit is
supported solely for autostream-dial, which does not include
`autostream_monitor`). Verified on aarch64 (Debian 13, g++ 14):
`std::atomic<double>::is_always_lock_free == 1` and the linked binary
carries no `libatomic` dependency. If a 32-bit monitor target is ever
reintroduced, switch these fields to integer atomics
(`std::atomic<int64_t>` milliseconds).

## Source Of Truth

For the external contract, treat this document and
[AUTOSTREAM-MONITOR-API.md](AUTOSTREAM-MONITOR-API.md) as the primary reference.

The C++ source remains authoritative for implementation details and internal
invariants, especially around threading, handoff sequencing, and DSP state
management.

Relevant source files:

- `core/monitor/autostream_monitor.h`
- `core/monitor/autostream_monitor.cpp`

If this document and the code ever disagree about externally observable
behavior, update one of them so there is a single clear truth again rather than
leaving both versions in circulation.
