# Changelog

## Unreleased

- improvement: updates, on the appliance and on the dial, are now downloaded and
  prepared in a folder that only the system can write, instead of one the
  application's own account can write, and the system checks what it reads back
  before it acts on it. An appliance or dial updating from an earlier release
  does this by itself; nothing needs doing.
- change: a factory reset of the appliance now also erases its list of authorised
  dials, so a reset appliance is as unconfigured as a new one. Before, the list
  survived and the appliance still accepted the dials it knew. After a reset,
  every dial has to be authorised again from the Dials card.
- change: a factory reset of a dial now gives it a new identity, so every
  appliance treats it as a new dial and it has to be authorised again on each one.
  Before, the dial kept the identity it was born with and stayed authorised. The
  old entry stays on each appliance's Dials list, shown as offline, until you
  switch it off there. A dial that has not been reset keeps its identity across an
  update, a reinstall and an uninstall; one that has been reset keeps its new
  identity across all three.
- improvement: the appliance and dial installers now limit the swap file to
  512 MiB. Raspberry Pi OS makes it as large as the board's RAM, up to 2 GiB, so
  a 4 GB board put a 2 GB file on its SD card. Install and update put the setting
  in place and uninstall removes it; it applies at the next reboot. With the
  default `rpi-swap` mechanism the file is the target that zram writes back to.
  The zram swap settings are left alone.
- improvement: the dial installer now applies the same base system tuning as the
  appliance installer, on a fresh install and on update, for SPI and HD dials:
  Wi-Fi power saving is turned off (a dial with it on can be slow to receive what
  the appliance sends it), swappiness is lowered and the zram writeback timer is
  masked, the unused `modemmanager` and `udisks2` packages are removed, and the
  power key is ignored. The dial uninstaller takes back the Wi-Fi and power key
  files, as the appliance uninstaller does. The Wi-Fi change takes effect after
  a reboot. The dial's display memory setting is left as it is.
- new: the appliance installer has an opt-in `--low-power` switch for low-power
  boards such as a Zero 2 W. It limits the appliance to two cores at 700 MHz
  (`maxcpus=2` on the kernel command line; `arm_freq=700`, `arm_boost=0` and
  `force_turbo=0` in `config.txt`) and takes effect after a reboot. It is off
  unless given, and once given the choice is saved and applied again by every
  `--update`, with or without the switch (an update on an appliance that has never
  used the switch leaves existing settings alone). The uninstaller removes exactly
  what the switch added; a different `maxcpus` value it replaced is not put back.
  To turn it off, remove the settings by hand and delete the `LOW_POWER` line from
  the install state.
- improvement: the dial and appliance installers now delete the downloaded package
  files (`apt-get clean`) once an install or update has succeeded, freeing space
  on a small SD card; before, a fresh install never cleaned them and an update
  kept the current ones. A dial update does this only after the new version has
  passed its check after the reboot, so a rolled-back update leaves them alone.
  Installed packages are not touched.
- improvement: after an update, an HD dial is only kept on the new version if its
  page server answers and, with a display connected, its kiosk browser is running.
  Otherwise the update is rolled back like any other failed check. A dial with no
  display connected is not held to the kiosk browser, so an update is not rolled
  back just because no screen is plugged in. SPI dials are checked as before.
- fix: a dial update no longer wipes its own install log or the dial's log history.
  The log files are now created only when missing, so the install log of an update,
  and of its automatic retries after a reboot, can be read afterwards, and a fresh
  install writes its whole log to `/var/log/autostream/dial-install.log` as well as
  to the home directory, so it is in the Download Logs bundle. The appliance
  installer also appends to its install log instead of replacing it on each run.
- fix: running the dial installer again over a dial that is already installed no
  longer resets it. The dial keeps its name, PIN, update and display settings, an
  SPI dial stays SPI and an HD dial stays HD, and `--hd` over an SPI dial turns it
  into an HD dial with its other settings kept. Before, the settings file was
  overwritten and an HD dial came back as an SPI profile with a kiosk that waited
  for a page that was never served.
- improvement: the dial uninstaller now checks before it removes anything. It must
  be run as root, refuses on an appliance or a device with no dial on it, and asks
  for confirmation. `--yes` skips the question, and is needed when there is no
  terminal to ask on.
- fix: a power cut in the middle of the package upgrade during an update no longer
  makes every automatic retry fail. The dial and appliance installers now finish
  an interrupted package run (`dpkg --configure -a`) before their first package
  command, so the retry after the next boot can complete the update.
- fix: Wi-Fi now comes back within seconds, not minutes, after a brief
  interruption of the adapter (for example when a package upgrade restarts the
  Wi-Fi authentication service). The Wi-Fi watcher used to wait for its
  five-minute retry when its first attempt found the adapter not yet available;
  it now checks every few seconds for up to a minute and reconnects as soon as
  the adapter is back.
- fix: an update no longer fails when a system package upgrade briefly drops the
  Wi-Fi. The dial and appliance installers now wait up to nine minutes for the
  network to come back before each step that downloads, and run a step again
  once if it failed because the network was gone. After a final failure the log
  says the network was not available. An unattended run that fails also no longer
  prints a message about a terminal.
- fix: the dial and appliance installers now check each sudoers file with visudo
  before it replaces the installed one. A file with a syntax error stops the
  install with a message and leaves the working file in place, where before it
  could have left sudo unusable on the whole system.
- fix: a fresh dial install now refreshes the package lists first, as the appliance
  installer does, so it no longer stops with "Unable to locate package" on a newly
  written card whose lists are empty or out of date. With no network it stops at
  that step with a plain message, before any package is touched.
- fix: uninstalling the dial software now gives the saved Wi-Fi networks back to
  NetworkManager (autoconnect on again, hotspot profile removed), the same as the
  appliance uninstaller, so a dial on Wi-Fi alone rejoins its network after the
  next reboot instead of staying offline.
- fix: the title and cover no longer drop out on a dial or the Home page every few
  minutes while a playing track is re-checked, including when the re-check finds
  nothing. A new track still clears the old one at once.
- improvement: the HD dial's pull-down and equaliser page now close by themselves
  after a minute without a touch, and when the screen goes to sleep, so the dial
  is back on the playing screen. They stay open while a finger is held on a
  slider, and while a card is showing over them.
- new: each input has a Dynamic Rate Matching switch on its Setup card, last,
  under the Level readout, off by default. Some optical (S/PDIF) USB adapters
  deliver audio at the rate of the source whatever rate the device was opened
  at, so a 44.1 kHz CD through a device opened at 48 kHz plays about 8 percent
  slow and low. With the switch on, autostream finds the real rate (32, 44.1 or
  48 kHz) within about half a second and follows it, including when the source
  changes rate later, and remembers it while the same device stays selected.
  The first half second after a rate change still plays at the old rate, and
  that stretch stays in repeat recordings. The switch applies at once and never
  interrupts playback. With it off, an input delivering a different rate raises
  a Home page banner reading "Sample Rate Mismatch: Please enable Dynamic Rate
  Matching", which opens that input's card, and the note under the switch says
  what rate is arriving. The Home card's input detail line gains Acquiring and
  Mismatch beside Locked. The estimate of an input's rate now also counts audio
  dropped when the Pi is overloaded. Existing installs are unchanged until the
  switch is turned on. The monitor's `configure_input` gains
  `dynamic_rate_matching`, and each input's status gains `negotiated_hz`,
  `rate_lock`, `relock_count`, `rate_mismatch_hz` and `dynamic_rate_matching`.
  `/api/status` gains `sample_rate_banner_text`, and `GET /api/inputs/levels`
  gains `rate_matching_note`, `sample_rate_text`, `dynamic_rate_matching`,
  `rate_mismatch_hz`, `negotiated_hz` and `monitor_supports_rate_matching`.
  The card also shows the sample rate the input is running at, with whether it
  has settled, in a live line under the Level readout. Appliances need the
  new monitor for the switch to take effect.
- new: each input now has a type, Turntable, CD or Line, chosen on its card in
  Setup (and for Input 1 at first boot) in place of the Turntable switch. The
  type names the input on the Home card, which shows a CD icon for a CD input,
  and is the default title while a track has none. An appliance that names the
  input behind what is playing now sends that name to dials, so a dial shows it
  where it used to show "Playing" for an untitled track. Dials and appliances
  both need updating for this. An input that was set as a turntable becomes
  Turntable on update and every other input becomes Line, so a CD player on an
  existing input stays on Line until you set it to CD.
- new: each input has a Sensitivity slider on its Setup card, from -70 dB to
  -30 dB, with a live Level readout beside it that updates about once a second
  while the card is open. The slider and the type apply at once and never
  interrupt playback. Choosing Turntable moves the slider to -45 dB and
  choosing CD or Line to -60 dB, but only when that changes the preset. A
  stored sensitivity is kept on update; one outside the slider's range is
  brought back inside it. The Setup page gains a levels-only route,
  `GET /api/inputs/levels`.
- improvement: a click, pop or knock on a cable no longer starts a session or
  wakes the speakers. A Turntable or Line input now needs a short run of sound
  above the sensitivity level, a few hundredths of a second added up within one
  second and not necessarily unbroken, before playback starts. A CD input
  still starts on the first sound.
- fix: with only the second input enabled, the Home card named the first
  input's type and icon. It now matches the level to its own input.
- new: dials follow changes made elsewhere. A change to the speakers, volume,
  mute, repeat, the track shown or the equaliser bands, made on one dial or in
  the appliance's web page, now shows on the other dials within a second or so
  instead of on their next poll. Appliances tell dials a change has happened
  and each dial then asks for the state itself, so a dial that misses the
  notice catches up on its regular poll. Appliances and dials both need
  updating for this. Dials gain a `POST /state-changed` route.
- fix: a dial now shows that playback has stopped within a second or so. It
  used to keep showing the appliance as playing until its next regular poll,
  up to a few seconds after the sound had gone.
- improvement: the appliance and dial installers now put in place a limit for
  core dumps, so that a crash or a crash loop cannot fill the SD card if
  dumps are being taken: each dump limited to 256 MB, all dumps together to
  256 MB, and older dumps cleared to keep 512 MB of the card free. Raspberry Pi
  OS does not include `systemd-coredump`, so nothing takes core dumps and the
  limit has no effect until that package is installed; autostream does not
  install it. Install and update put the setting in place.
- change: the HD dial's kiosk now runs WPE WebKit through its `cog` launcher,
  drawing straight to the display. It uses far less memory (about 140 MiB on a
  512 MB Pi 3 Model A+), so a 512 MB board is enough for an HD dial. The HD
  install adds `cog` and `libgles2`.
- new: an HD dial now controls an HDMI panel's brightness when the panel
  supports the monitor control channel (DDC/CI). Brightness follows the
  setting, and when the screen sleeps the panel is turned down to its minimum
  and left powered while the page shows "Touch to wake". A panel that does not
  answer keeps the page blacking out the picture. Powering the panel off while
  it sleeps is a setting, off by default, because some panels are left with
  image retention after being powered down: **Switch the panel off when
  asleep** on the dial's card in Setup, which asks you to confirm before it
  turns on. The HD install loads `i2c-dev` at boot and adds the dial's account
  to the `i2c` group; nothing new is installed.
- improvement: the HD dial reads "Playing" as the track while an appliance is
  playing but has not named the track yet (as a track changes, or at the start
  of playback), as the small screen does, instead of "Nothing playing".
- improvement: the HD dial's play and back-to-the-start buttons look pushed in
  from the press until the appliance reports the replay running from the
  start. They let go if the request is refused or unanswered, if the appliance
  stops, or if you move to another appliance.
- change: the HD dial now always shows its controls. The "Always show controls"
  switch is gone from its pull-down and from the dial's Setup card for an HD
  dial, and the controls no longer fade away. The small screen keeps its own
  setting.
- new: the HD dial's pull-down has a power button at the top right. It asks
  "Shut down?" and, once confirmed, shuts the dial down. It works only from
  the dial's own touchscreen, not from the page served on the local network.
  If the dial does not switch off within about half a minute, a card says so
  and the power button works again.
  Dials gain a `poweroff` verb in their privileged helper and a matching
  sudoers line on update.
- new: an HD dial can pair a speaker that asks for a PIN. Switching the
  speaker on opens a keypad on the dial; enter the code the device shows. The
  appliance's Home page leaves the prompt to the dial while it is doing this.
  The small screen tells you to pair in the appliance's web UI instead.
- improved: the Home page's PIN dialog pairs and switches the speaker on in
  one go, says when a code was not accepted, and asks you to wait a few
  seconds after several quick attempts. A speaker switch the appliance
  refuses now springs back on the dial at once.
- improved: the replay timer on the dial's screens now runs behind the
  appliance's reported position by the appliance's audio start buffer, so it
  matches what you hear (it was a fixed two seconds on the small screens and
  not offset on the HD page). Appliances send the buffer in the dial status;
  against an older appliance the dial keeps using two seconds. On the HD page,
  pressing Stop now stops the timer at once and it resets when playback
  stops.
- new: dials show a Starting... splash on an HDMI or DSI screen at boot and
  Shutting down... at shutdown and reboot. Existing dials gain it on their
  next update (one longer update while the boot files are rebuilt).
- new: HD dial (preview). A dial can now drive a full-size HDMI or DSI
  touchscreen. The dial serves a touch page to a kiosk browser on the same
  board: appliances and speakers on the left; artwork, replay controls, track
  and volume on the right; an equaliser page; a pull-down sheet for
  brightness, sleep and the dial's details; warnings; and a screen that
  sleeps and wakes on the first touch. Install it with
  `autostream_dial_install.sh --hd`. A 512 MB board such as a Pi 3
  Model A+ is enough.
- new: appliances now send their own maintenance and power warnings to dials:
  a stylus near or past the end of its life, a drive belt or main bearing due
  for service, and a low power-supply voltage. They page on the dial's screen
  with the appliance's name and a Dismiss button, quietly and only over the
  now-playing screen, and the appliance tells the dial when they change.
- new: the dial can use a six-band equaliser on an appliance that has one (the
  HD dial's equaliser page); the small screen keeps bass and treble.
- improvement: on the HD dial the appliances and speakers lists scroll
  separately, and a list that has more to show fades at its edge.
- new: the dial's Setup card shows Brightness and Sleep after for an HD dial
  in place of the SPI-only rows.
- improvement: the HD dial's replay row uses transport buttons and a timer in
  place of the Replay, Restart and Stop text buttons: play (or back to the
  start while a replay runs), stop, then the timer. A button that does not
  apply is greyed out. While something plays live the row holds Repeat Play
  as before. Lengths of an hour or more show hours.
- improvement: the HD dial's replay timer counts evenly, a second at a time,
  and no longer hops forwards or back as the dial reports in.
- fix: the HD dial's mute button and volume number went back to unmuted a
  moment after a press although the sound stayed muted, and the volume number
  could show an old level or another appliance's. Both now follow the
  appliance being shown, and a mute shows as soon as the dial has acted on it.
- improvement: an output in use by another autostream appliance now says
  which one (the HD dial shows "In Use by" and its name).
- improvement: the dial's outputs list marks the appliance's default output (a
  bullet on the small screen, a Default label on the HD page), and appliances
  now report it to dials.
- improvement: the HD dial's artwork sits on a blurred backdrop, as the small
  screen's does, and the picture and backdrop fade together when the track
  changes.
- improvement: appliances advertise a new dial protocol generation (v3) and
  serve a capabilities list that a dial reads in place of the discovery flags,
  so new dial features need no new discovery keys. Older dials and appliances
  keep working with each other. Protocol generations are now compared as
  numbers.
- fix: a dial whose saved poll interval is unusable now uses the default
  instead of stopping its poll loop.
- fix: the Dial name row in a dial's info (on the HD page and the small screen)
  now shows the dial's UUID while the dial has no name, as the web UI does,
  instead of "-".
- change: the dial's code is split into a core that tracks the appliances and
  views that draw the screen, so the small screen and the HD page share one
  model. No change to what the small screen does.
- change: the dial reports its screen's surface, brightness and sleep time in
  its screen settings, and can optionally serve its page on a PIN-protected
  development listener on the local network (off by default).
- docs: new HD dial guide; the dial architecture, screen and protocol
  documents describe the above.
- change: this release builds owntone-mini 1.4.3. Nothing changes in how it
  plays: its documentation and licence notices were brought up to date and
  packaging it no longer uses was removed.

## Version 0.6.1 - 2026-10-02

- fix: on a fresh install protected by a setup PIN, opening the web UI now
  asks for the PIN and continues to first-boot setup, instead of showing
  only "Authentication required".

## Version 0.6.0 - 2026-09-30

The stable release of the 0.6 series. This summarises everything since 0.5.0;
the beta sections below have the detail.

- new: Speaker Synchronisation lines up your speakers automatically, with one
  tap to apply the result.
- new: output offsets take effect while music plays, so you can align by ear.
- new: lossless AirPlay to receivers that support it, on by default for new
  installs.
- new: dial touch panels, more dial display types and on-screen playback
  buttons.
- new: SD card health monitoring, switched on from the Setup page.
- new: settings changes shipped with a release apply on update, leaving values
  you have changed alone.
- improvement: steadier playback with fewer dropouts, and a smoother handover
  between live input and repeat.
- improvement: the repeat buffer reserves its memory up front and says how much
  audio fits.
- fix: HomePods grouped behind an Apple TV start reliably, and volume reaches
  both members of a stereo pair (owntone-mini 1.4.2).
- fix: track identification no longer stalls during repeat and replay.
- change: the update rebuilds owntone-mini from source, which takes a long time
  on a Pi Zero 2 W. Leave it powered; it reboots itself.

### HomePod OS 27 and the AirPlay User-Agent

HomePods on OS 27 refuse AirPlay senders without an AirPlay-style User-Agent:
playback fails with a 403, and autostream may show a PIN prompt although no PIN
appears. Every install and update now sets the User-Agent to that of a current
iPhone, `AirPlay/950.7.1`, replacing any previous value. This has not yet been
confirmed against OS 27. If a HomePod on OS 27 still refuses to play, a user
has reported that `AirPlay/999.0.0` works
([issue #26](https://github.com/lo-tech-systems/autostream/issues/26)): set it
in Setup → AirPlay Settings → AirPlay User Agent, and OwnTone restarts on its
own. Updates reset the value, so re-enter it after each update.

## Version 0.6.0-beta.4 - 2026-09-23

- fix: track identification no longer stalls during repeat/replay playback. A
  brief transient on the replay-origin input could tear down the
  identification schedule with no replay-aware re-arm, leaving identification
  stuck on the previous track until the replay's own gap detector produced
  its next boundary. The Home page and now-playing metadata also now show
  the real "Waiting for audio" / "Analysing" state instead of a single
  "Identifying Track…" label throughout.
- fix: the installer now sets gpu_mem to 16 in the Pi firmware config for
  headless operation, and guarantees the owntone build toolchain (including
  libtool-bin) is present on every install and update rather than only the
  first, so a later rebuild cannot fail for a missing build tool.
- change: this release builds owntone-mini 1.4.1, which adds the pipe
  metadata teardown deadlock fix on top of the 1.4.0 memory-retention and
  Apple-TV group memory work.
- docs: describe the monitor's real-time thread scheduling.

## Version 0.6.0-beta.3 - 2026-09-20

- feat: the audio monitor runs its capture, input-processing, replay-decode
  and output-stage threads at real-time priority (SCHED_FIFO), so a transient
  scheduling delay can no longer drop captured samples or force silence into
  playback. Each thread falls back to normal priority if the real-time grant
  is unavailable.
- feat: the audio monitor reports playback underruns per output source and,
  per input, capture losses (recovered ALSA overruns and periods dropped when
  processing falls behind) in its status, and logs a warning when an output
  tick is scheduled more than half a second late, so audio dropouts can be
  told apart from audio lost at capture.
- change: this release builds owntone-mini 1.4.0.
- fix: disabling SD card health monitoring removes the last reading and the
  About and Setup pages stop showing SD health until it is enabled again,
  so a stale figure can never claim better health than reality.
- feat: SD card health monitoring can be switched on from the Setup page.
  The card is probed once first and monitoring is enabled only if the probe
  succeeds; the page warns that an unsupported card may stop responding and
  restart the system, and warns more strongly if that has already happened
  on this card. A wrapper around the health tool records a marker before
  every query, so a query that locks the system up is detected at the next
  boot, monitoring is switched off, and the query is never repeated on its
  own. The installer's sdmon flag now probes the card as its last step.
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
