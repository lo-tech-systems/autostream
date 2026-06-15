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
| **Download Logs** | Downloads a ZIP of the dial and Wi-Fi setup logs (`dial-*.log`, `wifi_setup.log`) to help diagnose the problem. |
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
