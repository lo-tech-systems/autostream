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
3. The dial appears under *Discovered dials* with its UUID.
4. Enter a friendly name (e.g. "Hallway") and tick **Allow control**.
5. Click **Save**.

The dial's UUID is broadcast in the mDNS TXT record — it is stable across
reboots and firmware updates.

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
