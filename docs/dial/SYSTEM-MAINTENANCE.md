# autostream dial: System Maintenance

Keeping a dial healthy day to day comes down to two things: firmware updates,
and knowing what to do if the dial's own web service stops responding.

## Firmware updates

The dial's card in the appliance's **Dials** panel (see
[Setup: Dials](../SETUP-DIALS.md)) shows its installed firmware version.

### Manual update

When a newer release is available for the dial's channel and the dial is
online, an **Update firmware** button appears on its card. Tapping it asks
you to confirm ("Start firmware update? The dial will restart."), then
starts the update. Every update ends with the dial restarting once, so
expect it to be unavailable for a minute or two at the end.

A dial that is running an older protocol version (see
[Protocol](DIAL_PROTOCOL.md#protocol-dialect-dial_proto)) is flagged
**Needs update** on its card, and the Home page shows a **Dial updates
required** banner that links to Setup, Dials. The dial keeps working in the
meantime; updating it brings it up to date.

### What an update does

An update goes through these steps. The dial keeps running its current
software until the very end, so a problem part-way through leaves it as it
was.

1. **Download.** The dial fetches the new release from GitHub.
2. **Upgrade OS.** It upgrades the operating system's packages, the same
   routine the main appliance uses, then installs any packages the new
   version needs.
3. **Install.** It builds a fresh Python environment for the new version,
   copies the new software into a holding area beside the live copy, and
   updates its services and configuration files. Before changing any of
   those it keeps a copy of the old ones.
4. **Restart and switch over.** The dial restarts. Very early in the boot,
   before its main service starts, the new software is swapped in for the
   old.
5. **Check.** The dial then checks that the new version really is running
   and healthy: the main service is up, it has not restarted itself, and it
   reports the new version. This check allows up to two minutes.
6. **Done.** When the check passes, the update is recorded as successful
   and the leftovers are cleaned up.

An update can take a long time, up to about 40 minutes on a Pi Zero 2 W,
most of it in the package upgrade, and a slow SD card makes it longer. Leave
the dial powered and let it finish.

### Seeing progress

- **On the dial's screen**, if one is fitted, an **Updating...** card shows a
  progress bar and a short label for the step (Downloading, Upgrading OS,
  Installing, Restarting). See
  [Using the Screen](USING-THE-SCREEN.md#software-update). You can still
  turn the dial's volume control while this shows.
- **On the dial's card in the appliance's Dials panel**, a progress bar and
  line of text follow the update, ending with "Updated to <version>" or a
  failure line.
- **On the dial's own web page**, `http://<dial-hostname>.local/` shows an
  updating page with a progress bar for as long as the update runs.

### If something goes wrong

**Automatic retries.** Two kinds of problem are retried without anyone
doing anything:

- If power is lost or the dial restarts part-way through an update, it picks
  the update up again at the next boot, before its main service starts,
  and carries on from the start of the install. It makes up to four
  attempts in all, counting the first. The progress shows "Retrying update
  (attempt 2 of 4)" and so on. If the fourth attempt is also interrupted,
  the update is marked failed and the dial stays on its current version.
- If the download fails because of a network problem, or a package step
  fails because the package system is locked or cannot be reached, the dial
  waits about half a minute and tries that one step once more. Any other
  failure, such as a damaged download, stops the update at once rather than
  repeating it.

A failure before the switch-over leaves the dial on its current version,
still running as normal. Nothing has been replaced yet.

**Automatic rollback.** If the new version fails its check after the
restart, or the dial restarts unexpectedly before the check finishes, the
dial puts the previous version back and restarts again. This is not retried:
a version that failed its check is not tried again until you start another
update.

The check is that the dial's services are running and have not restarted,
and that the dial reports the new version. On an HD dial it also needs the
page server to answer and, when a display is connected, the kiosk browser to
be running and not restarting. With no display connected (nothing plugged in,
or the screen off) the kiosk browser is not required, so a dial without a
screen is not rolled back for that.

What a rollback restores:

- The dial's own software.
- Its Python environment.
- Its services and configuration files (systemd services, web server and
  discovery settings, and the like) and its recorded installed version.
- On an HD dial, the kiosk service, the backlight rule and the module list
  the update installed or changed.

What a rollback does not undo:

- Operating-system packages already upgraded during the update. The
  previous dial software then runs on the upgraded system, as it does after
  any ordinary system upgrade.
- Changes to the boot configuration for the display and sensor
  connections, which are additive and safe for the older software.
- On an HD dial, the kiosk browser packages and their account, which an
  update only adds to.

After a rollback the dial's card shows a red line such as "Update to 0.7.0
failed - restored 0.6.0". If an update fails without being rolled back, it
says "Update to 0.7.0 failed - 0.6.0 kept" instead. An update that failed
while nobody was watching, for example an automatic one, shows this line
again when you next open the Dials panel, for a week afterwards.

### Automatic updates (opt-in)

Turn on **Auto-update** on the dial's card (see
[Getting Started](GETTING-STARTED.md#configuring-the-dial)). Once enabled,
the dial checks for updates every Monday at approximately 03:30, with a
randomized delay of up to 30 minutes, and installs anything newer
automatically.

Updates require an active internet connection. The dial cannot update while
it's in hotspot (Wi-Fi setup) mode.

### Update channels

Each dial has its own update channel, independent of the main appliance and
of any other dial on the network. Toggle **Pre-release updates** on the
dial's card to switch it:

- **Off (stable, default)**: only full GitHub releases.
- **On (dev)**: the most recently published release, including
  pre-releases.

The channel setting lives on the dial itself and keeps working even while
the main appliance is offline; both manual and automatic checks use it.
Switching back to stable does not downgrade an already-installed
pre-release. A later, numerically newer stable release is still offered
normally.


## SD card care

The dial runs the same storage-care routines as the main appliance:

- A daily background task cleans up its own log archives and checks the
  logrotate timer, keeping the SD card from filling up over time.
- Optional SD card health monitoring: turn it on from the appliance's Setup
  page, on the dial's own card, once its firmware advertises the capability.
  Enabling it runs a one-time guarded check first; if the card does not
  support the check or does not respond, monitoring is not turned on. Once
  running, it checks the card's remaining endurance once a day and reports
  it back on the Setup page. The dial itself has a hardware watchdog, so if
  a check against an unsupported card ever hangs the system, it restarts
  automatically rather than needing a manual power-cycle.
- The dial's own system log stays in memory rather than being written to
  the SD card, which is the same volatile-journal approach the main
  appliance uses.
- The dial's log file defaults to a quieter level (warnings and errors
  only) to reduce writes to the SD card. To see the fuller lifecycle log
  for troubleshooting, run `sudo systemctl edit autostream_dial` and add:

  ```
  [Service]
  Environment=APP_LOG_LEVEL=INFO
  ```

  then restart the service with `sudo systemctl restart autostream_dial`.

## What the installer changes on the system

Besides its own software, the dial installer, on a fresh install and on every
update, puts these operating-system settings in place. The last column says what
the uninstaller does with each.

| Setting | Effect | Uninstall |
|---|---|---|
| `/etc/rpi/swap.conf.d/99-autostream-swap.conf` | Limits the swap file to 512 MiB. Raspberry Pi OS otherwise makes the file as large as the board's RAM, up to 2 GiB, on the SD card. Only written when the system has the `rpi-swap` package, which Raspberry Pi OS Trixie does. The limit applies when swap is set up at boot, so it takes effect after a reboot; a larger file that already exists is expected to be replaced then [not yet confirmed on a device]. The zram swap settings are left as they are. | Removed |
| `/etc/systemd/journald.conf.d/99-autostream-storage.conf` | Keeps the system log in memory, with size and retention limits. | Removed |
| `/etc/systemd/coredump.conf.d/99-autostream-coredump.conf` | Limits core dumps to 256 MB in total, so a dump cannot fill the SD card. It only has an effect if `systemd-coredump` is installed, which Raspberry Pi OS does not include and the installer does not add; until then nothing takes core dumps. | Removed |
| `/etc/NetworkManager/conf.d/wifi-powersave.conf` and `/etc/NetworkManager/dispatcher.d/99-wlan-fix` | Turn Wi-Fi power saving off, as on the appliance, so the dial is quick to receive what the appliance sends it. The dispatcher script switches power saving off on each wireless interface as it comes up, and sets the transmit power of the built-in radio. Take effect after a reboot. | Removed |
| `/etc/sysctl.d/90-autostream-swappiness.conf` | Sets `vm.swappiness=20`, so compressed memory (zram) absorbs spikes instead of holding the working set. | Left in place |
| `rpi-zram-writeback.timer` | Masked. The timer writes compressed memory pages out to the SD card, which is wear for no benefit here. | Left masked |
| `modemmanager` and `udisks2` packages | Removed if present. A dial has no modem and no removable-storage workflow. | Not reinstalled |
| `/etc/systemd/logind.conf.d/90-autostream-ignore-power-key.conf` | Sets `HandlePowerKey=ignore`, so a spurious power-key event (USB devices can cause one as they enumerate) cannot shut an unattended dial down. A power button, if one is fitted, no longer powers the dial off. | Removed |

The boot configuration is a separate matter: the installer does not set
`gpu_mem` on a dial, so a display can be switched on later without reinstalling,
and it does not install the hardware watchdog service or the appliance's audio
and Bluetooth settings.

## Recovery pages

The dial's web server hosts a small set of **recovery pages** at
`http://<dial-hostname>.local/offline/`. These are served independently of
the dial's main service, so they stay reachable even when that service has
crashed, is mid-update, or is rebooting. If the dial's service is
unavailable, any request to the dial is automatically redirected here.

The recovery page offers four actions:

| Button | Effect |
|--------|--------|
| **Retry** | Refreshes the page to check whether the service has restarted. |
| **Download Logs** | Downloads a ZIP of the dial, Wi-Fi setup, install and update logs to help diagnose the problem. The install and update logs are kept across updates and reboots in `/var/log/autostream/` and rotated daily. |
| **Reboot** | Triggers a graceful reboot. The page switches to a *rebooting* holding page and waits until the dial's service returns. |
| **Factory Reset** | After a confirmation step, erases the dial's Wi-Fi credentials and settings, then reboots. Reconnect to the `autostream-dial_XXXX` hotspot afterwards to reconfigure Wi-Fi. |

### During a firmware update

While an update is in progress, the browser is automatically redirected to
an **updating** page that shows progress until the update completes. The
dial restarts as part of the update, and the updating page is kept in place
until the new version's check has finished, so allow a minute or two after
the restart before the dial's normal page returns.

## When the dial won't come back

If **Reboot** and **Retry** don't bring the service back:

1. Check the recovery page is even reachable at
   `http://<dial-hostname>.local/offline/`. If not, confirm the dial still
   has power and is on the network.
2. Use **Download Logs** from the recovery page to capture what happened
   before trying a **Factory Reset**.
3. As a last resort, **Factory Reset** clears the dial's Wi-Fi and settings
   (not its identity or hardware configuration), and starts it fresh from
   the setup hotspot.

For dial-specific problems that aren't covered by the recovery page, such as
the dial not appearing on the appliance's Setup page, volume commands not
taking effect, or the dial being unreachable at all, see
[Troubleshooting](../TROUBLESHOOTING.md).

## Removing the dial software

`autostream_dial_uninstall.sh`, run from the dial's checkout, removes the dial
software and its services. It also takes back the boot splash: it removes the
theme, the boot options and boot files the installer added (and only those),
purges the splash packages the installer itself installed, and rebuilds the
boot files. It also hands the saved Wi-Fi networks back to NetworkManager
(autoconnect on again, the setup hotspot profile removed), so a dial that only
has Wi-Fi rejoins its network after the next reboot. It is meant for a
dedicated dial.

Run it with `sudo`. It checks before it removes anything: it refuses to run
as a normal user, and it refuses on a device that is not a dial (an appliance,
or a device with no dial software on it). It then asks you to confirm, which
needs a terminal. To run it without a prompt, for example over `ssh` without
`-t` or from a script, add `--yes`:

```bash
sudo ./autostream_dial_uninstall.sh --yes
```

## Next steps

- [Getting Started](GETTING-STARTED.md): authorizing, configuring, and using
  a dial day to day.
- [Setup: Dials](../SETUP-DIALS.md): the appliance side of dial setup.
- [Build Guide](BUILD-GUIDE.md): the hardware itself.
- [HD dial](HD-DIAL.md): the kiosk service and troubleshooting for a dial with
  a full-size touchscreen.
