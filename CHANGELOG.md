# Changelog

## Unreleased

- feat: the installer always builds the SD card health tool at a pinned
  upstream version and installs its units; `--sdmon=<method>` only enables
  the daily timer, the choice is preserved across updates, and an update
  rebuilds the tool when the pinned version changes. A check switched on
  outside the installer is no longer switched off by an update.
- feat: the audio monitor now produces one continuous output stream. Live
  inputs and the repeat replay feed a single output stage that mixes them
  with gain ramps and writes the FIFO from one place, instead of two
  writers handing the pipe over. A live input taking over from a replay is
  a 1.5 s crossfade heard the moment it is made, the replay no longer runs
  ahead of the output, and a session that starts by interrupting a replay
  has the same latency as one started from idle. The half-second pipe
  prefill now happens only when the stream starts from idle.
- feat: a live input that interrupts a repeat replay is admitted after
  0.25 s above its silence threshold when it is a line-level input, and
  after the existing 1.25 s continuous-audio check when it is a turntable;
  the monitor tells the two apart by the threshold preset the coordinator
  sends. The replay-takeover hold that ignored a live input for the first
  thirty seconds of a replay is removed, since probation covers that case.
  The recorder keeps the audio played during probation and the crossfade,
  so the recording made by such a session starts at the real onset even
  though the listener missed it.
- fix: the audio monitor keeps unwritten audio when the FIFO is full and
  sends it ahead of the next block, instead of discarding the rest of the
  block and reopening the pipe. Audio is lost only if the reader stays
  stalled for more than a second. The pipe is now requested at 1 MiB.
- feat: the audio monitor re-plans its repeat buffer 5, 10 and 15 minutes
  after start-up. The buffer is sized when it is first built, which on a
  fresh boot happens while other services are still claiming memory, so it
  could come out shorter than the configured length even though memory
  frees up shortly afterwards. Each pass now grows a short buffer to the
  configured length when memory allows, keeping its codec so a recording
  in memory is never lost, and, when nothing is recorded and the buffer
  already meets the target, rebuilds it at a higher bitrate if one now fits
  the full length. A buffer is never shrunk and its bitrate never lowered.
- fix: the audio monitor's repeat buffer is now built from memory mappings
  that are returned to the system when the buffer is torn down. Previously,
  because the monitor locks its memory, a disable and re-enable or a
  configuration change could leave a whole buffer's worth of pinned pages
  behind and rebuild a smaller buffer on top; the monitor's allocator is
  also limited to two heaps
- change: the audio monitor logs a memory line at info level every 5 minutes
  while an input is capturing and hourly when idle, and once when a capture
  session ends: resident, peak and locked size, heap in use and held by the
  allocator, malloc arenas, the repeat arena's chunks, capturing inputs,
  system available memory and swap in use. The monitor runs at warning level
  by default, so raise it to info (`set_log_level` over the control socket,
  or `--log-level info`) to see the line
- change: the web UI now prompts for an AirPlay PIN whenever the playback
  backend reports that an output is asking for a PIN, not only when the user
  has just switched it on. This matters for HomePods grouped behind an Apple
  TV, where owntone-mini now drives the group through the Apple TV and the
  PIN request can arrive when playback starts. Cancelling the prompt hides it
  until that output next asks for a PIN
- fix: the automatic default-output retry and the restart reconcile no
  longer keep re-enabling an output that is waiting for a PIN, which would
  otherwise make an Apple TV show a fresh PIN on every retry

## Version 0.6.0-beta.2

- change: the bundled owntone-mini moves to 1.3.0, so installs and updates
  rebuild it once to pick it up. Its AirPlay 2 encoder now drains its backlog
  instead of dropping audio after a stall, its pipe input buffer holds a few
  seconds of audio whatever the stream format, and it locks its own memory at
  startup like the capture daemon below
- fix: HomePods on OS 27 refused playback (403) because they now reject
  senders without an AirPlay-style User-Agent — updates set the OwnTone
  user-agent to a compatible value automatically. To use a different value,
  set it on the OwnTone setup page after updating
- fix: the audio pipe to the playback backend is now 256 KiB (up from the
  kernel default), so a brief playback stall no longer drops audio
- change: the repeat buffer now keeps 96 MiB of RAM free (up from 64 MiB),
  which may select a lower recording bitrate on 512 MB boards
- change: the capture daemon now locks its working memory so it can't be
  paged out under memory pressure

## Version 0.6.0-beta.1

- new: release-shipped settings changes are now applied automatically on
  every install and update — new defaults and one-shot fixes take effect
  without any manual step, while values you've already changed yourself
  are left alone unless a change is explicitly forced
- new: the AirPlay User-Agent string is now settable from the OwnTone setup
  page — useful when diagnosing a receiver that treats the appliance
  differently from an Apple sender. Clearing the field restores the default,
  and applying a change restarts OwnTone (requires owntone-mini 1.2.1 or
  above; hidden on other backends)
- improvement: settings that restart OwnTone now show an "Applying
  setting…" notice until the restart completes, instead of restarting
  silently in the background
- change: the Start Buffer control is now a drop-down (250 ms steps) rather
  than a slider, and the OwnTone page's card is titled "AirPlay Settings";
  saves on that page now report their status ("Saved" / "Could not apply")
- new: Speaker Synchronisation — automatic output alignment. The appliance
  plays a short tone through each selected output in turn while a companion
  page opened on your phone listens, measures the timing differences, and
  hands back per-output offsets to review and apply with one tap — so a
  TV-connected Apple TV can be lined up with other speakers automatically.
  Reached from the playback page; requires owntone-mini 1.2 or above
- new: dial touch panels — resistive and capacitive touch controllers are
  now supported, adding on-screen playback buttons alongside the rotary
  input, with the controller selectable per dial from the web UI
- new: dial displays — selectable screen types (ST7735S, ST7789, ILI9341)
  with per-dial colour-order and rotation controls, support for screen-only
  builds without rotary hardware, and an ambient-blur backdrop behind
  album art
- improvement: dial PIN recovery is now explicitly requested from the web
  UI, arms only after a power cycle, and accepts any physical input on the
  dial as proof of presence
- new: each AirPlay output's Offset control now takes effect while music is
  playing — drag the slider and that output shifts within a second or two,
  so it can also be aligned by ear. On buffered receivers the adjustment
  re-times the receiver without interrupting the audio stream (requires
  owntone-mini 1.2 or above)
- new: lossless AirPlay — with "uncompressed audio" enabled, receivers that
  support it are sent bit-exact lossless audio on the buffered transport
  instead of AAC, which is also far lighter to encode on the appliance;
  new installs have this enabled by default (requires owntone-mini 1.2.1
  or above)
- improvement: the repeat buffer now reserves its memory up front when the
  feature is enabled, at the best quality that fits the chosen duration.
  What you actually get is stated plainly (for example "80 minutes
  requested; 67 minutes at 256Kbps MP2 fit in memory"), the figure
  recalculates live when the target duration is changed, and a session
  longer than the buffer keeps the most recent audio rather than stopping
- fix: the repeat buffer's reported capacity and quality no longer drift
  between checks — the figure shown is the reserved buffer's actual size
  and bitrate, including for a held recording awaiting replay

## Version 0.5.0

- fix: the updating screen no longer briefly claims a new update is already
  100% complete (a leftover result from the previous update) — progress now
  starts at "Preparing update..." the moment an update begins, and the page
  only reports completion for an update it has actually watched run, so
  there's no window inviting a power-cycle mid-update
- fix: the platform log level chosen on the Info page now survives an
  appliance restart — previously any later settings change could silently
  revert it to the default
- fix: the first action in an already-open browser tab no longer silently
  fails after the appliance restarts — the page now refreshes its session
  transparently and retries, so buttons work first time
- improvement: when a track change is detected, the receiver now switches
  straight to the input label and the autostream logo while the new track is
  being identified, instead of continuing to show the previous track's
  title and cover until identification finishes
- fix: track cover art is now resized before being sent to AirPlay speakers,
  fixing an issue where larger covers would silently fail to display on
  Apple TV; the artwork pipeline also no longer touches disk, closing a
  narrow window where a fast track change could show the wrong cover
- fix: updating an appliance that still carried the old built-in "Turntable"
  now-playing hints file removes it, restoring the input-aware labels and
  placeholder artwork (customised hints files are always preserved)
- improvement: the wired input can now be disabled/skipped so setup can be
  completed without a wired input device connected — first-run setup gains a
  "Skip — configure later" option, Input 1 can be enabled/disabled from
  Setup, and a notice on the Home page flags when no input is configured
- improvement: pairing a Bluetooth device now automatically assigns it to a
  free input where safe, with a Setup-page prompt when both inputs are
  already in use
- fix: the Bluetooth service no longer crashes and restarts repeatedly while
  the paired device is switched off or out of range
- fix: Bluetooth input now recovers by itself when the internal audio link is
  left at incompatible settings (previously it could stay silent until a
  restart)
- improvement: warning-level logs now record when OwnTone, the monitor daemon
  connection, Bluetooth, and track identification recover from a prior
  failure, not just the failure itself
- improvement: when OwnTone denies or fails an output/setting request, the
  log now includes the HTTP status code and a snippet of the backend's
  response instead of a bare generic failure message
- improvement: stability and reliability improvements to in-app updates — the
  appliance now confirms the "updating" page is showing before it changes
  anything, puts itself back the way it was if an update fails, and skips
  rebuilding components that are already up to date, which makes most updates
  considerably faster
- improvement: stability and memory improvements for low-memory devices such
  as the Pi Zero 2 W — lower background memory use, tuned swap behaviour, and
  a longer, more reliable repeat-playback buffer
- improvement: faster start-up, by removing system services the appliance
  does not need
- improvement: the About page now shows CPU temperature, CPU load, and memory
  usage alongside the existing system information
- improvement: repeat playback now shows a "stopping" state while it winds
  down, instead of appearing to still be playing

## Version 0.5.0-beta.1

- fix: Repeat playback no longer sounds muddled during the first few seconds
  of each loop
- fix: Bluetooth input could play garbled audio after a software update or
  reboot
- fix: the onboard-Bluetooth setting is now preserved across software updates
- fix: the Setup page's Bluetooth card now shows the connected device's codec
  and sample rate
- fix: Repeat playback now produces correct audio when the output runs in the
  44.1 kHz/16-bit compatible format

## Version 0.5.0-alpha.4

- new: direct Bluetooth turntable input — pair a Bluetooth-equipped turntable and
  stream its audio straight into an input, no USB adapter needed
- new: Bluetooth card on the Setup page — enable/disable the feature, pair or
  forget a device, and see connection status, all in one place; a USB Bluetooth
  adapter is recommended, with the Pi's onboard radio available as a toggle
- new: Bluetooth Audio Buffer control — adjust how much audio is held in reserve
  to trade off dropout resistance against start-up delay
- fix: a Bluetooth device (or any device) selected on one input can no longer also
  be selected on the other input at the same time

## Version 0.5.0-alpha.2

- new: "Repeat" — buffers the current source into RAM and loops it back
  seamlessly once the source stops, with a codec ladder (MP2/PCM) sized to
  available memory
- new: live-audio interrupt crossfades out of a repeat loop the moment the
  source starts playing again
- new: Repeat controls in the web UI (Setup toggle, small repeat button on the
  Home screen)
- new: monitor now depends on `libtwolame` and `libmpg123` for repeat's
  MP2 encode/decode
- improved: `autostream_monitor.service` sets `OOMScoreAdjust=200` so the
  monitor is preferred over other processes in a worst-case OOM
- fix: Setup page's "Max buffer time" note no longer sticks at "—"
  forever until buffering actually starts — it now shows an estimate
  as soon as repeat is enabled

## Version 0.5.0-alpha.1

- new: "Enable AirPlay 2 Buffered Audio" toggle — surfaces buffered/surround
  output modes from owntone-mini end-to-end
- fix: audio FIFO moved from `/tmp` to `/run` — the daily storage-guard
  cleanup could delete an idle FIFO out from under OwnTone, silently killing
  autostart playback until a manual restart ([#15](https://github.com/lo-tech-systems/autostream/issues/15))
- fix: storage-guard no longer runs `tmpfiles --clean` when storage isn't
  actually under pressure
- fix: Owntone Setup page settings (including the new buffered-audio toggle)
  now actually autosave — a missing script injection meant every toggle on
  that page silently failed to persist

## Version 0.4.0 - 2026-07-10

- new: track identification showing current playback details on the home page
- new: multi-unit control — control other appliances from one WebUI
- new: beta support for the Autostream Dial volume control
- improved: reorganized Setup interface
- improved: updater now supports a pre-release channel
- new: experimental support for USB Wi-Fi adapters

## Version 0.3.0 - 2026-06-07

- improved: home page now live-updates and ignores brief network glitches

## Version 0.2.2 - 2026-06-05

- improved: network connection health monitoring

## Version 0.2.1 - 2026-05-10

- fix: various bug fixes
- new: factory PIN usable for 30 minutes after boot if the user-set PIN is
  forgotten

## Version 0.2.0 - 2026-05-03

- new: output equalizer
- improved: general UI improvements
- improved: update process

## Version 0.1.1 - 2026-04-25

- improved: WebUI layout, with optional dark mode
- new: optional master volume control on the home page
- improved: stylus wear tracking reorganized into a Service page
- improved: update process

## Version 0.0.4 - 2026-04-19

- new: initial release — web-based UI, C++ audio monitor with clock-drift
  compensation, AirPlay output, stylus tracking, per-input equalizer, WiFi
  hotspot recovery interface
