# autostream dial — Setup Guide

## Prerequisites

- autostream dial hardware installed and powered on (see BUILD-GUIDE.md)
- Dial has joined your home WiFi (first-boot hotspot setup complete)
- At least one autostream appliance on the same network

---

## Where Setup Happens

The dial does **not** serve a setup page of its own. All dial configuration is
done from the **main autostream appliance's web interface**:

1. Open the autostream web UI (e.g. `http://autostream.local/`).
2. Go to **Setup** and open the **Dials** panel.

Each dial discovered on the network appears as a card in this panel, showing
its name, identity, online status, and firmware version. The panel header
summarizes the fleet (e.g. *2 authorized · 1 online*).

Browsing to the dial's own address (`http://<dial-hostname>.local/`) only
reaches its recovery pages (see *Recovery Pages* below) — there is no
browser-facing setup UI on the dial itself.

---

## Authorizing the Dial

Before the dial can control an autostream appliance, it must be authorized:

1. In the **Dials** panel, find the new dial's card — it appears under its
   identity when first discovered.
2. Tick **Allow control**.

Until the dial is authorized, the rest of its settings are hidden — **Allow
control** is the only action available on a new dial's card. Unticking it
(after a confirmation prompt) revokes the dial's access.

The dial's identity is a 20-character hexadecimal value broadcast in the mDNS
TXT record — it is stable across reboots and firmware updates.

---

## Configuring the Dial

All of the following settings live on the dial's card in the **Dials** panel.
If a PIN is set, the card's settings section is locked — click the padlock
next to **Settings** and enter the PIN to unlock it. The section re-locks
automatically when you click away from it.

**Name** — Click **Change Dial Name** to open the rename dialog. A friendly
display name shown in the autostream UI and mDNS discovery. Printable ASCII;
maximum 64 characters. Semicolons and pipe characters are not permitted.

**Step** — A slider setting the volume change per encoder click, 1–10%.
Default: 2%. Saves automatically when changed.

**Auto-update** — Toggle for weekly automatic firmware updates (see *Firmware
Updates* below). Saves automatically when changed.

**Pre-release updates** — Toggle for the dial's update channel (see *Update
Channels* below). Saves automatically when changed.

**Has Screen Fitted**, **Rotate Screen**, **Swap Red/Blue (BGR)**, **Screen
Type**, **Touch Panel** — Controls for the optional display module and its
optional touch panel (see *Display Screen* and *Touch Panel* below). Save
automatically when changed.

---

## Setting a PIN

A PIN prevents unauthorized users from changing the dial's settings. The PIN
protects: name, step size, auto-update toggle, pre-release toggle, screen
settings, and the PIN itself.

Volume control is **not** PIN-protected — the dial still adjusts volume without
any PIN.

To set a PIN, on the dial's card in the **Dials** panel:
1. Click **Change Dial PIN**.
2. Leave *Current PIN* blank (no existing PIN).
3. Enter a 4–8 digit PIN in *New PIN*.
4. Confirm.

To change the PIN: enter the current PIN, then the new PIN.

To remove the PIN: enter the current PIN and leave *New PIN* blank.

PIN attempts are rate-limited by the dial: after 5 failed attempts, further
attempts are delayed with an increasing backoff (5 seconds, doubling up to
5 minutes).

---

## Recovering a Lost PIN

If the PIN is forgotten, it can be reset — but the process now starts from
the main autostream appliance's web interface, not from the dial itself.
Physical access to the dial alone is no longer enough to reset a lost PIN;
you also need access to the appliance's web UI.

1. On the dial's card in the **Dials** panel, click **Reset Lost PIN**.
2. A dialog asks *"This feature can be used to reset a lost PIN. Continue?"*
   Confirm to request recovery. Cancelling or closing the dialog at this or
   any later point withdraws the request (see *Cancelling* below).
3. The dialog now shows: *"To reset the Dial PIN, start by power-cycling the
   Dial now. Once it restarts, you have 10 minutes to confirm you are at the
   device."* **Power-cycle the dial** — disconnect and reconnect its power,
   or switch off and on the socket/plug it's connected to. A service
   restart, a `reboot`, or a firmware update does **not** count: only an
   actual loss of power is accepted as evidence that whoever is requesting
   recovery has physical access to the device. You have 30 minutes from step
   2 to power-cycle the dial before the request expires.
4. Once the dial has restarted after a genuine power cycle, a 10-minute
   recovery window opens automatically and the dialog's message changes to
   prompt for presence. **Confirm you are at the device** with any physical
   input the dial has — touch the screen, twist the rotary control, or press
   the button. Whichever of these the dial actually has is enough; you don't
   need all of them, and playback is NOT required. The dialog polls the dial
   and unlocks the new-PIN entry as soon as one of them is detected.
5. Enter and confirm your new PIN.

A dial with none of these inputs — no rotary control, no button, and no
working touch panel — can never confirm presence, so it can never complete
PIN recovery. The autostream UI does not offer to set a PIN on such a dial in
the first place.

While waiting at step 4, the dialog shows a countdown of the time left in the
10-minute recovery window. If that window expires before presence is
confirmed, the request has been used up — go back to step 1 and request
recovery again; simply power-cycling the dial a second time does not reopen
a window on its own.

### Cancelling

Closing the recovery dialog (**Cancel**, the close control, or Escape) at any
point withdraws the outstanding request. If the dial has not yet been
power-cycled, the request is discarded and nothing arms. If the dial has
already been power-cycled and a recovery window is open, closing the dialog
does not close that window early — once opened, the 10-minute window runs to
completion (or until a new PIN is set) regardless of the dialog's state.

---

## Recovery Pages

The dial's web server hosts a small set of **recovery pages** at
`http://<dial-hostname>.local/offline/`. These are served independently of the
main dial service, so they remain reachable even when the service has crashed,
is mid-update, or is rebooting. If the dial service is unavailable, any request
to the dial is automatically redirected to the recovery page.

The recovery page offers four actions:

| Button | Effect |
|--------|--------|
| **Retry** | Refreshes the page to check whether the service has restarted. |
| **Download Logs** | Downloads a ZIP of the dial and Wi-Fi setup logs (`dial-*.log`, `autostream_wifi_watcher.log`) to help diagnose the problem. |
| **Reboot** | Triggers a graceful reboot. The page transitions to a *rebooting* holding page and polls until the dial service returns. |
| **Factory Reset** | Shows a confirmation step, then performs a factory reset — erasing Wi-Fi credentials and dial settings — before rebooting. After reboot, reconnect to the `autostream-dial_XXXX` hotspot to reconfigure. |

### During a firmware update

While a firmware update is in progress, the browser is automatically redirected
to an **updating** page that polls the update state and shows progress until
the update completes and the service restarts.

---

## Firmware Updates

The dial's card in the **Dials** panel shows the installed firmware version.

**Manual update:**
When a newer release is available for the dial's channel and the dial is
online, an **Update firmware** button appears on the card. Click it to begin;
the dial service restarts automatically when the update completes.

**Automatic updates (opt-in):**
Enable **Auto-update** on the dial's card. The dial then checks for updates
every Monday at ~03:30 (with a randomized delay of up to 30 minutes) and
installs them automatically.

Updates require an active internet connection. The dial cannot update while in
hotspot (WiFi setup) mode.

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

A nonzero nudge (`nudge up`, `nudge down`, or `nudge --delta N` with `N != 0`)
confirms an active PIN-recovery window, the same way any deliberate physical
input on the dial itself does (touch, button press, or encoder rotation in
either direction).

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
- Ensure the dial is authorized in the autostream UI (Setup → Dials).
- Check that the autostream appliance is announcing playback
  (`avahi-browse -t _autostream-playing._tcp`).
- Verify the autostream service is running and OwnTone is playing.

**Dial unreachable:**
- Check service status: `systemctl status autostream_dial`.
- Check nginx: `systemctl status nginx`.
- Verify the dial's IP with `avahi-browse -a` or your router's DHCP table.
- Try the recovery page directly: `http://<dial-hostname>.local/offline/`.

**Forgot WiFi credentials / need to re-run setup:**
```bash
sudo systemctl start autostream_dial_wifi_watcher
```
Connect to the `autostream-dial_XXXX` hotspot and enter the new credentials.

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

Note: there is no Network card in the dial management UI in this release. Factory reset deletes the dial's saved settings (`/var/lib/autostream/dial-settings.json`) and Wi-Fi connection (`/etc/autostream-network.json` and `/opt/autostream/ssid`); the hardware config and identity in `/etc/autostream/autostream-dial.json` are preserved.

---

## Display Screen (if fitted)

Dials that have an optional SPI TFT display module fitted can show album
artwork for the currently playing, identified track, falling back to the
autostream logo when nothing is playing or no artwork is available.

The shipped, hardware-validated panel is a 1.8-inch 160x128 display using the
ST7735S controller. The dial software also supports ST7735S at 128x128, ST7789
at 240x240 and 320x240, and ILI9341 at 320x240 — these four are selectable but
have **not yet been validated on real hardware**.

The screen settings live on the dial's card in the **Dials** panel:

1. Open the main autostream Setup page and find the dial's card.
2. Unlock the card's locked settings section (enter the PIN if one is set).
3. Configure the controls described below.

**Has Screen Fitted** — Whether a display module is physically connected. The
other screen controls are disabled until this is on.

**Rotate Screen** — Rotates the rendered image 180 degrees, for mounting
orientations where the panel would otherwise display upside down.

**Swap Red/Blue (BGR)** — Swaps the red and blue colour channels. Cheap panel
breakouts vary in wiring colour order; if reds and blues look swapped on the
screen, toggle this.

**Screen Type** — Selects which display profile (panel model/resolution) the
dial renders for. Changing it applies immediately to the running dial — no
restart or re-flash is needed.

**Screen Type** and **Swap Red/Blue (BGR)** only appear on dials whose
firmware advertises support for them; older dial firmware shows just **Has
Screen Fitted** and **Rotate Screen**.

All of the above toggles are read from the dial itself every time the card's
settings section is opened or unlocked — the main appliance does not store its
own copy of these settings. If the dial is offline, the card still functions
for other settings; the screen controls simply reflect whatever was last read
from the dial.

Wiring is unchanged and shared across all supported panels — the same fixed
SPI0 pin-out is used regardless of screen type (see BUILD-GUIDE.md).

### Display behavior

The display shows the autostream logo whenever:

- no `_autostream-playing._tcp` appliance is currently visible;
- track identification is disabled, not yet identified, or found no match;
- the identified track has no provider artwork URL;
- artwork fetch, decode, or render failed for any reason.

Artwork is shown only when an authorized, playing appliance reports an
`identified` track with a usable provider artwork URL. Rotary volume changes
and the mute button do not affect what the display shows.

### Artwork source selection across multiple appliances

If more than one autostream appliance is playing at once, the dial only ever
shows artwork from one of them. It polls appliances in order of how long each
has been playing (oldest first) and shows the first one that has usable
artwork; the others are not shown even if they also have artwork. This order
can change if a longer-playing appliance stops.

### Troubleshooting the display

**Screen stays on the logo even though something is playing:**
- Confirm track identification is enabled and has identified the track (check
  the appliance's own home page — the same identification state feeds the
  dial).
- Confirm the matched track actually has provider artwork; some matches have
  no artwork available.
- If another appliance has been playing longer, the dial may be showing (or
  attempting to show) artwork from that appliance instead.

**Screen stays blank (no logo, no artwork):**
- Confirm **Has Screen Fitted** is enabled for this dial.
- Check `journalctl -u autostream_dial` for `backend_open_failed` or
  `logo_unavailable` — both are non-fatal but mean the screen cannot render;
  volume control is unaffected either way.

---

## Touch Panel (if fitted)

Dials whose screen is a touch panel can control volume and mute directly on
the screen, in addition to the rotary encoder.

### Where the control lives

The **Touch Panel** selector appears on the dial's card, in the same locked
settings section as the other screen controls, but only under two
conditions:

- The dial's firmware advertises touch support at all (older dial firmware
  that predates touch simply has no **Touch Panel** row).
- **Has Screen Fitted** is on. Like **Rotate Screen**, **Swap Red/Blue
  (BGR)**, and **Screen Type**, the **Touch Panel** control greys out
  together with the rest of the screen controls when no screen is fitted —
  touch cannot work without a screen, so there is no point offering it.

Choosing **None** disables touch entirely; it is the default.

### Changing the Touch Panel setting restarts the dial

Unlike every other screen setting, changing the touch controller does
**not** take effect immediately. The other screen controls (fitted, rotate,
BGR, screen type) apply live, with no interruption. Touch is different: the
dial builds its touch driver, filter, and interaction logic once, when the
dial service starts.

To pick up the new setting without asking you to intervene, the dial
restarts its own service automatically as soon as you save a changed
**Touch Panel** choice. The restart takes roughly ten seconds. While it is
in progress, the dial's card shows a **Configuring** badge and that dial's
controls are disabled; the page polls the dial and re-enables its controls
automatically once the restart completes. You don't need to reboot or
power-cycle the dial yourself for a touch panel change to take effect.

If you save another touch panel change again within a few seconds of the
last one, the dial may not restart a second time immediately — it limits
itself to one self-restart per minute so that this setting can't be used to
knock a dial offline repeatedly. The new setting is still saved; it simply
takes effect on the next restart (including the next reboot or firmware
update) if this happens.

### How the interaction works

The touch panel does not act on the first touch. Touching anywhere on a
sleeping or idle screen only **reveals** the on-screen controls — the
volume/mute buttons are not visible, and nothing is actuated, until they
appear. Touch again (or continue holding) once the controls are showing to
actually change volume or mute.

Once revealed, the screen dims and shows the on-screen controls: three
areas divided by thin lines, a mute symbol, a minus, and a plus. The mute
symbol reflects whether audio is **currently muted** — it is not a fixed
icon, it updates to show the true mute state.

- **Tap** an area to act once: mute/unmute, step volume down, or step
  volume up.
- **Press and hold** the volume areas (minus or plus) to repeat the step
  automatically: the first repeat fires 0.4 seconds into the hold, then
  every 0.15 seconds after that for as long as the hold continues. The mute
  area does not repeat — a single tap is enough, since repeatedly toggling
  mute at speed serves no purpose.

The controls disappear automatically 4 seconds after the last touch
contact — there is no dismiss button. Every accepted tap or repeat while
holding resets that 4-second countdown, so a long hold never dismisses the
controls out from under a repeating finger. Touching again while the
controls are still showing acts immediately (no reveal-only step needed),
since the layout is already visible.

### Layout

The three areas are arranged differently depending on the screen's shape:

- On a **wide** screen (width at least 1.2x the height — for example the
  shipped 160x128 panel), the areas are three vertical columns spanning the
  full height, left to right: **mute**, **down**, **up**.
- On a **square-ish** screen (width less than 1.2x the height), **mute** is
  a band across the top spanning the full width; **down** and **up** split
  the remaining area below it, side by side.

Every boundary between areas has a small inactive margin on each side, so
an imprecise tap near a boundary lands in neither neighbouring area rather
than the wrong one.

### Hardware validation status

**No touch hardware has been validated on a physical panel in this
release.** The first target build is an ILI9341 screen paired with an
HR2046 resistive touch controller, and that combination has not yet been
confirmed working on real hardware. A capacitive (FT6206/FT6236) touch
driver also exists in the software, but no capacitive touch hardware has
been tested with it at all. Treat both as unproven until confirmed on a
physical panel — see `docs/dial/BUILD-GUIDE.md` for wiring.

---

## Update Channels

Each dial has its own update channel setting — it is independent of the main appliance and of any other dials on the network.

### Channels

- **stable** (default) — only full GitHub releases.
- **dev** — the most recently published release, including pre-releases.

### Changing the channel

Open the main autostream Setup page, find the online dial's card in the
**Dials** panel, and toggle **Pre-release updates**. The change is saved
through the same PIN-protected configuration flow used for all other dial
settings, and saves automatically when toggled.

### Behaviour

- The setting persists locally on the dial and continues to work while the main appliance is offline.
- Manual and automatic checks both use the dial's locally configured channel.
- Switching to stable does not automatically downgrade an installed pre-release. A later numerically newer stable release will be offered normally.
