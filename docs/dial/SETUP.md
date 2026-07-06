# autostream dial — Setup Guide

## Prerequisites

- autostream dial hardware installed and powered on (see BUILD-GUIDE.md)
- Dial has joined your home WiFi (first-boot AP mode complete)
- At least one autostream appliance on the same network

---

## Opening the Setup Page

Browse to `http://<hostname>.local/` (e.g. `http://dial-hallway.local/`) from
any device on your home network. If mDNS is unavailable, use the dial's IP
address directly.

---

## Authorizing the Dial

Before the dial can control an autostream appliance, it must be authorized from
the **autostream web interface** (not from the dial's own setup page):

1. Open the autostream web UI (e.g. `http://autostream.local/`).
2. Go to **Setup** and open the **Dials** panel.
3. The dial appears under *Discovered dials* with its identity.
4. Enter a friendly name (e.g. "Hallway") and tick **Allow control**.
5. Click **Save**.

The dial's identity is a 20-character hexadecimal value broadcast in the mDNS
TXT record — it is stable across reboots and firmware updates.

---

## Configuring Name and Step Size

On the dial's setup page (`http://<hostname>.local/`):

**Name** — A friendly display name shown in the autostream UI and mDNS
discovery. Printable ASCII; maximum 64 characters. Semicolons and pipe
characters are not permitted.

**Step** — Volume change per encoder click, 1–10%. Default: 2%.

Both settings auto-save when you leave the field (blur). If a PIN is set, you
will be prompted to enter it before changes are applied.

---

## Setting a PIN

A PIN prevents unauthorized users from changing the dial's settings. The PIN
protects: name, step size, auto-update toggle, and PIN itself.

Volume control is **not** PIN-protected — the dial still adjusts volume without
any PIN.

To set a PIN:
1. Click **Change PIN** on the setup page.
2. Leave *Current PIN* blank (no existing PIN).
3. Enter a 4–8 digit PIN in *New PIN*.
4. Click **Set PIN**.

To change the PIN: enter the current PIN, then the new PIN.

To remove the PIN: enter the current PIN, leave *New PIN* blank, click **Remove PIN**.

---

## Recovering a Lost PIN

If the PIN is forgotten, it can be reset via physical access to the dial.

The 10-minute recovery window opens automatically each time the dial service
starts (when a PIN is set). To recover:

1. **Restart the dial service** (or reboot the Pi) to open a fresh 10-minute window.
2. **Turn the dial clockwise** at least once. This physically confirms your
   presence at the device. Playback is NOT required.
3. On the autostream setup page, click **Reset lost PIN** on the dial's card.
4. Enter and confirm your new PIN.
5. Click **Save**.

The recovery window expires after 10 minutes. If it expires, restart the
service and repeat from step 2.

---

## Offline Recovery

If the dial's main service (`autostream_dial`) is unavailable — due to a crash,
an in-progress firmware update, or a reboot triggered from the setup page — the
browser shows a branded **offline recovery page** instead of an error.

The recovery page offers four actions:

| Button | Effect |
|--------|--------|
| **Retry** | Refreshes the page to check whether the service has restarted. |
| **Download Logs** | Downloads a ZIP of the dial and Wi-Fi setup logs (`dial-*.log`, `autostream_wifi_watcher.log`) to help diagnose the problem. |
| **Reboot** | Triggers a graceful reboot. The page transitions to a *rebooting* holding page and polls until the dial service returns. |
| **Factory Reset** | Shows a confirmation step, then performs a factory reset — erasing Wi-Fi credentials and dial settings — before rebooting. After reboot, reconnect to the `autostream-dial_XXXX` hotspot to reconfigure. |

### During a firmware update

While a firmware update is in progress, the browser is automatically redirected
to an **updating** page that polls the update state and shows progress. The page
redirects back to the setup page automatically once the update completes and the
service restarts.

---

## Firmware Updates

The **Firmware** card on the setup page shows the installed version and lets you
check for and install updates.

**Manual update:**
1. Click **Check for update** — the dial contacts GitHub and reports whether
   an update is available.
2. If an update is available, an **Install update** button appears. Click it
   to begin. The page polls for progress.
3. The dial service restarts automatically when the update completes.

**Automatic updates (opt-in):**
On the autostream setup page, navigate to the dial's card and enable
**Auto-update**. The dial checks for updates every Monday at ~03:30 and
installs them automatically.

Updates require an active internet connection. The dial cannot update while in
AP mode (WiFi setup).

---

## Encoder Button — Mute/Unmute

Pressing the encoder shaft (the push-button built into most KY-040 / EC11 encoders) **toggles mute on and off** for the currently selected speakers.

**What mute does:**
- Sets the volume of all selected outputs to zero.
- Does **not** stop playback or deselect speakers.
- Unmuting restores the previous volume level.

**Hardware:** the button is wired to **BCM GPIO 22** (physical pin 15). See BUILD-GUIDE.md for wiring details.

**Disabling the button:** set `"sw_gpio": null` in `/etc/autostream/autostream-dial.json` and restart `autostream_dial`. The encoder will still control volume; only the push-button function is disabled.

**Enabling the button on an existing installation:** if your hardware has the button wired but it was installed before this feature was added, add `"sw_gpio": 22` to `/etc/autostream/autostream-dial.json` and restart `autostream_dial`:

```bash
# Edit the hardware config (requires root)
sudo nano /etc/autostream/autostream-dial.json
# Add or update the "sw_gpio" key, e.g.: "sw_gpio": 22
# Then restart the service
sudo systemctl restart autostream_dial
```

---

## Local Control CLI

The `autostream-dial-control` command lets an SSH operator exercise the dial's
live volume path without a physical rotary encoder. It connects to a local
Unix-domain socket created by the running `autostream_dial` service.

**Requires root** (the socket is owned by `autostream:autostream`, mode 0660):

```bash
sudo autostream-dial-control ping
sudo autostream-dial-control version
sudo autostream-dial-control status
sudo autostream-dial-control targets
sudo autostream-dial-control nudge up
sudo autostream-dial-control nudge down
sudo autostream-dial-control nudge --delta 10
```

### Commands

| Command | Description |
|---|---|
| `ping` | Confirm the service is responding. |
| `version` | Print protocol and software versions. |
| `status` | Print live dial state: UUID, name, step size, target count, PIN recovery. |
| `targets` | List currently discovered playing appliances with live master volume. |
| `nudge up` | Queue a positive volume delta (same path as clockwise encoder turn). |
| `nudge down` | Queue a negative volume delta. |
| `nudge --delta N` | Queue an explicit delta in -100..100 (excluding 0). |

### Options

`--json` — Print the raw server response as compact JSON instead of
human-readable text. May appear before or after the subcommand.

### Discovered targets vs all appliances

`targets` lists only appliances that are **currently playing** and that the
dial has discovered via mDNS (`_autostream-playing._tcp`). It is not a list of
every autostream appliance on the LAN. An empty list means the dial currently
sees no compatible playing targets; this is a normal result when nothing is playing.

### Target master volume

For each discovered target that advertises `dial_status=v1`, `targets` fetches
the current master volume by calling `POST /api/dial/status` on that appliance.
The master volume is the rounded arithmetic mean of all currently selected
OwnTone output volumes — the same value shown on the appliance home page.

If a target cannot be reached within 1 second (per target) or 1.5 seconds
overall, or if the response is invalid, the `status_error` field explains why:

| `status_error` | Meaning |
|---|---|
| `unsupported` | Target does not advertise `dial_status=v1` |
| `unauthorized` | Target rejected the dial UUID (HTTP 403) |
| `unreachable` | Connection or network failure |
| `timeout` | No response before the per-target deadline |
| `bad_response` | Oversized, malformed, or schema-invalid response |
| `config_error` | Target could not load its configuration |
| `backend_unavailable` | Target could not read OwnTone output state |

A lookup failure does not hide the target from the list; it appears with null
volume fields and a non-null `status_error`.

### Nudge semantics

`nudge` commands return immediately after queueing the delta. The response
field `queued:true` means the delta was accepted into the dial's local queue —
not that it has been delivered to any appliance. The volume worker processes
the queue asynchronously. The response field `target_count` is advisory; the
worker takes its own fresh snapshot when it processes the delta.

A positive nudge (or `nudge up`) confirms an active PIN-recovery window,
matching a clockwise physical encoder rotation.

### Exit codes

| Exit code | Meaning |
|---|---|
| 0 | Server returned `ok:true` |
| 1 | Server returned `ok:false` |
| 2 | CLI argument or usage error |
| 3 | Socket missing, permission denied, timeout, or invalid response |

If the service is stopped, exit code 3 is returned.

### Socket path and permissions

The socket is created at `/run/autostream-dial/control.sock` with mode 0660.
The directory `/run/autostream-dial/` is created by systemd (`RuntimeDirectory`)
when the service starts and removed when it stops.

---

## LED Indicators (if fitted)

| State | LED |
|-------|-----|
| Playing target found | On (steady) |
| No playing target | Off |
| Volume at minimum or maximum | Two quick blinks |

The LED reflects whether any autostream appliance is currently announcing
playback on the network, not whether volume is changing.

---

## Troubleshooting

**Dial not visible in autostream UI:**
- Confirm both devices are on the same network segment.
- Run `avahi-browse -t _autostream-dial._tcp` on the autostream appliance to
  check mDNS visibility.
- Check `journalctl -u autostream_dial` on the Pi for startup errors.

**Volume commands not taking effect:**
- Ensure the dial is authorized in the autostream UI (Settings → Dials).
- Check that the autostream appliance is announcing playback
  (`avahi-browse -t _autostream-playing._tcp`).
- Verify the autostream service is running and OwnTone is playing.

**Setup page unreachable:**
- Check service status: `systemctl status autostream_dial`.
- Check nginx: `systemctl status nginx`.
- Verify the dial's IP with `avahi-browse -a` or your router's DHCP table.

**Forgot WiFi credentials / need to re-run setup:**
```bash
sudo systemctl start autostream_dial_wifi_watcher
```
Connect to `autostream-dial_SETUP` and enter the new credentials.

---

## Wi-Fi and USB Adapters

autostream dial uses the same Wi-Fi watcher service as the main appliance.

### USB Wi-Fi adapters

- The setup hotspot page shows networks from all detected adapters, deduplicated by SSID.
- If a network is only visible through the USB adapter, a notice explains that removing the adapter would return the dial to hotspot mode.
- On boot, dial automatically prefers a USB adapter when one is found. No configuration is needed.
- While a healthy built-in connection is active, dial adopts a newly inserted USB adapter after two stable detection passes. **Dial has no local playback, so there is no playback gating for USB adoption.**
- The built-in adapter is always used for the recovery hotspot.

### USB failure fallback

If the active USB adapter is removed or becomes unreachable:

1. Dial immediately tries the configured profile on the built-in adapter.
2. If built-in connects, the dial continues operating on built-in.
3. If built-in cannot reach the network (e.g. USB-only SSID), the recovery hotspot opens.

### mDNS during adapter transitions

When the active interface or IP address changes, the `_autostream-dial._tcp` mDNS service may briefly disappear and reappear. The main appliance's discovery registry handles transient removals; the dial reappears within a few seconds of the new interface becoming stable.

Note: there is no Network card in the dial management UI in this release. Factory reset deletes the saved Wi-Fi connection (`/etc/autostream-network.json` and `/opt/autostream/ssid`).

---

## Display Screen (if fitted)

Dials that have an optional 1.8-inch TFT display module fitted can show album
artwork for the currently playing, identified track, falling back to the
autostream logo when nothing is playing or no artwork is available.

The only setting exposed in this release is whether a screen is physically
fitted:

1. Open the main autostream Setup page and find the dial's card.
2. Unlock the card's locked settings section (enter the PIN if one is set).
3. Toggle **Has Screen Fitted**.

The toggle is read from the dial itself every time the card's settings section
is opened or unlocked — the main appliance does not store its own copy of this
setting. If the dial is offline, the card still functions for other settings;
the screen toggle simply reflects whatever was last read from the dial.

There is no offset, colour, orientation, or artwork-fit configuration in this
release — those use a fixed wiring and rendering profile chosen for the
supported hardware.

---

## Update Channels

Each dial has its own update channel setting — it is independent of the main appliance and of any other dials on the network.

### Channels

- **stable** (default) — only full GitHub releases.
- **dev** — the most recently published release, including pre-releases.

### Changing the channel

You can change the dial's update channel in two ways:

**From the dial's own Setup page:**
Open `http://<dial-hostname>.local/` in a browser, scroll to the **Device** card, and toggle **Pre-release updates**. Tap **Save**.

**From the main appliance Setup page:**
Open the main autostream Setup page, find the online dial card, and toggle **Pre-release updates** for that dial. The change is saved through the same PIN-protected configuration flow used for all other dial settings.

### Behaviour

- The setting persists locally on the dial and continues to work while the main appliance is offline.
- Manual and automatic checks both use the dial's locally configured channel.
- Switching to stable does not automatically downgrade an installed pre-release. A later numerically newer stable release will be offered normally.
