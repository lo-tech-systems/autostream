# Info

The **Info** page is autostream's About/status screen. It's the place to check
before reporting a problem or installing an update: it shows exactly which
build of each component is running, whether the background services are
healthy, and how the appliance itself is doing (temperature, CPU, memory,
disk, SD card wear).

## Getting there

Tap **Info** in the bottom navigation bar. It opens on a hero screen with the autostream logo, the
"Powered By Lo-tech Systems" logo, and the installed **autostream** version
underneath. Below that are four rows: **System**, **Copyright**, **License**,
and **Logs**.

`Logs` is a direct link to the log viewer, useful when troubleshooting - see
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) if you need help interpreting what
you find there.

## System

Tapping **System** opens a detail panel with two cards: system information
and services. Everything on this panel loads asynchronously after the page
opens, so fields briefly read "Loading..." before they're filled in; if the
appliance can't answer, the affected fields read "Unavailable" instead.

### Build and device information

- **autostream Build** - the installed release tag (e.g. `0.6.0`).
- **Device** - the Raspberry Pi model detected at startup.
- **OS Build** - the OS name/codename from `/etc/os-release`.
- **Total Playback Time** - cumulative playback hours across both inputs,
  to one decimal place. This includes time spent replaying the in-memory
  recording during output failover (repeat playback), not just live audio.

### System status

These bars only appear when the appliance can actually read the underlying
value; if a reading isn't available, its whole row is hidden rather than
shown as zero or blank. Each bar is colour-coded healthy / warning /
critical:

| Bar | Shows | Healthy | Warning | Critical |
|-----|-------|---------|---------|----------|
| CPU Temperature | Current SoC temperature, as a percentage of 85°C (the Pi's soft-throttle point) | below 70°C | 70-78°C | above 78°C |
| CPU Load | Current busy percentage (htop-style, not a scheduler load average) | below 70% | 70-85% | above 85% |
| Memory Usage | Percentage used, plus free/total in MB | more than 96 MB free | 64-96 MB free | less than 64 MB free |
| Disk Usage | Percentage used, plus free/total in GB, for the root filesystem | below 60% | 60-80% | above 80% |
| SD Health | Manufacturer-reported endurance remaining, as a percentage | above 30% | 11-30% | 10% or below |

SD Health only appears once SD card health monitoring has been turned on and
has completed at least one successful check. See [SETUP-SYSTEM.md](SETUP-SYSTEM.md)
for how to enable it.

### Services

The Services card lists the background services autostream depends on, each
with a live systemd state:

- **Autostream** (autostream.service)
- **Audio Monitor** (autostream_monitor.service)
- **Wi-Fi Watcher** (autostream_wifi_watcher.service)
- **OwnTone** or **OwnTone Mini**, depending on which backend is installed (owntone.service)
- **Vibra Mini** (vibra-mini.service)
- **Bluetooth Service** (autostream_bluetooth.service) - only listed when the Bluetooth-input subsystem is installed
- **NGINX** (nginx.service)

Each row shows the component's build/version where one is known, followed by
its state: **OK** (unit active), **Failed** (unit not active), or
**Disabled** - the Bluetooth row alone distinguishes "installed but
switched off" (Disabled) from "installed, enabled, but not currently
running" (Failed), since systemd reports both the same way.

If a component isn't currently connected to autostream but a build number is
still known from an earlier session, its build shows `(last seen)` next to
the version.

## Copyright

The **Copyright** panel shows the autostream copyright notice, a short list
of the third-party and separately licensed components autostream ships with
(ALSA, FFmpeg, owntone-mini, vibra-mini, and other open-source libraries),
and the AirPlay/Apple trademark disclaimer.

## License

The **License** panel renders the project's `LICENSE` file. A **Copy** button
copies the full license text to the clipboard.

## Logs

The **Logs** row links straight to the log viewer, for reviewing recent
activity or pulling logs when diagnosing a problem.
