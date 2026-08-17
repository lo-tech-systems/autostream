# Changelog

## Unreleased

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
