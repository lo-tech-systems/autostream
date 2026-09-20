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
starts the update. The dial's own service restarts automatically once the
update finishes.

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

### If an update is interrupted

If power is lost or the dial reboots mid-update, the dial resolves this at
its next boot before its main service starts, marking the update as failed
rather than leaving it stuck. Simply retry the update once the dial is back
online.

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
| **Download Logs** | Downloads a ZIP of the dial and Wi-Fi setup logs (`dial-*.log`, `autostream_wifi_watcher.log`) to help diagnose the problem. |
| **Reboot** | Triggers a graceful reboot. The page switches to a *rebooting* holding page and waits until the dial's service returns. |
| **Factory Reset** | After a confirmation step, erases the dial's Wi-Fi credentials and settings, then reboots. Reconnect to the `autostream-dial_XXXX` hotspot afterwards to reconfigure Wi-Fi. |

### During a firmware update

While an update is in progress, the browser is automatically redirected to
an **updating** page that shows progress until the update completes and the
service restarts.

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

## Next steps

- [Getting Started](GETTING-STARTED.md): authorizing, configuring, and using
  a dial day to day.
- [Setup: Dials](../SETUP-DIALS.md): the appliance side of dial setup.
- [Build Guide](BUILD-GUIDE.md): the hardware itself.
