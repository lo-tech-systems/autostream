# autostream dial: Getting Started

autostream dial is a physical rotary volume control for an autostream
appliance. Turn it to change volume, press it to mute. This guide covers
setting one up and using it day to day.

## Prerequisites

- autostream dial hardware built, installed, and powered on. See the
  [Build Guide](BUILD-GUIDE.md) if you haven't built one yet.
- The dial has joined your home Wi-Fi (first-boot hotspot setup complete).
- At least one autostream appliance on the same network.

## Where setup happens

The dial doesn't serve a setup page of its own. Everything is configured
from the **main autostream appliance's web interface**:

1. Open the autostream web UI, for example `http://autostream.local/`.
2. Go to **Setup** and open the **Dials** card.

Every dial the appliance has discovered shows up as a card there, with its
name, identity, online status, and firmware version. See
[Setup: Dials](../SETUP-DIALS.md) for what that card shows and for
authorizing a new dial (the step below).

Browsing to the dial's own address (`http://<dial-hostname>.local/`) only
reaches its recovery pages (see
[System Maintenance](SYSTEM-MAINTENANCE.md)). There is no setup UI served by
the dial itself.

## Authorizing the dial

Before a dial can control an appliance, it must be authorized:

1. In the **Dials** card, find the new dial. It appears under its identity
   (a 20-character hex string) when first discovered.
2. Turn on **Allow dial to control this appliance**.

Until authorized, that's the only control shown on the card. Turning the
toggle off later (after a confirmation prompt) revokes access. Full details
are in [Setup: Dials](../SETUP-DIALS.md).

## Configuring the dial

Once authorized, the dial's card expands to show its settings. If a PIN is
set, the settings section is locked: tap the padlock next to **Settings**
and enter the PIN to unlock it. It re-locks automatically as soon as you
click or tap away from it.

- **Change Dial Name**: opens a rename dialog. Printable ASCII, up to 64
  characters. Semicolons and pipe characters aren't allowed. The name is
  shown in the autostream UI and in mDNS discovery.
- **Step**: a slider setting how much volume changes per encoder click,
  1-10%. Default is 2%. Saves automatically.
- **Auto-update** and **Pre-release updates**: control automatic firmware
  updates and which release channel the dial follows. Saves automatically.
  See [System Maintenance](SYSTEM-MAINTENANCE.md) for what these do.
- **Has Screen Fitted**, **Rotate Screen**, **Swap Red/Blue (BGR)**,
  **Screen Type**, **Touch Panel**: only relevant if your dial has the
  optional display module fitted. These apply immediately, with no restart,
  except **Touch Panel**, which briefly restarts the dial service (about ten
  seconds) to pick up a new touch controller. See the
  [Build Guide](BUILD-GUIDE.md) for wiring and hardware validation status.

## Setting a PIN

A PIN stops other people changing the dial's settings from the appliance's
web UI. It protects the dial's name, step size, auto-update and channel
toggles, screen settings, and the PIN itself.

**Volume control is not PIN-protected.** The dial keeps adjusting volume
without a PIN, whether or not one is set.

To set a PIN, on the dial's card:

1. Tap **Change Dial PIN** (shown as **Set Dial PIN** if none is set yet).
2. Leave *Current PIN* blank.
3. Enter a 4-8 digit PIN in *New PIN* and confirm it.

To change the PIN, enter the current PIN, then the new one. To remove the
PIN, enter the current PIN and leave *New PIN* blank.

PIN attempts are rate-limited by the dial itself: after 5 failed attempts,
each further attempt is delayed with an increasing backoff, starting at 5
seconds and doubling up to a maximum of 5 minutes.

## Recovering a lost PIN

If you forget the PIN, it can be reset, but the process starts from the
**appliance's** web UI, not from the dial. Physical access to the dial alone
isn't enough; you also need access to the appliance's Setup page.

1. On the dial's card, tap **Reset Lost PIN**.
2. Confirm the prompt to request recovery. Closing the dialog at this or any
   later point withdraws the request.
3. The dialog asks you to **power-cycle the dial**: disconnect and reconnect
   its power, or switch the socket off and on. A service restart, a reboot,
   or a firmware update does not count, only an actual loss of power proves
   physical access. You have 30 minutes to do this before the request
   expires.
4. Once the dial restarts after a genuine power cycle, a 10-minute recovery
   window opens automatically. Confirm you're at the device with any
   physical input the dial has: touch the screen, turn the rotary control,
   or press the button. Whichever of these your dial has is enough.
5. Enter and confirm your new PIN.

A dial with none of these inputs (no rotary control, no button, and no
working touch panel) can never confirm presence, so it can never complete
PIN recovery. The appliance's UI won't offer to set a PIN on such a dial in
the first place.

If the 10-minute window expires before you confirm presence, the request is
used up: go back to step 1 and request recovery again. Power-cycling the
dial a second time on its own does not reopen a window.

Closing the recovery dialog at any point withdraws an outstanding request
that hasn't armed yet. If the dial has already been power-cycled and a
recovery window is open, closing the dialog does not close that window
early; it runs to completion (or until a new PIN is set) regardless.

## The encoder button: mute and unmute

Pressing the encoder shaft (the built-in push-button on most KY-040 / EC11
rotary encoders) toggles mute on and off for the currently selected
speakers.

- Muting sets the volume of all selected outputs to zero. It does not stop
  playback or deselect speakers.
- Unmuting restores the previous volume level.

This only works if the button is wired: see the [Build Guide](BUILD-GUIDE.md)
for wiring. If your hardware was set up before the button feature existed, add
or update the `sw_gpio` key in `/etc/autostream/autostream-dial.json` to enable
it.

## Everyday use

Once authorized and configured, using the dial day to day needs no web UI
at all:

- **Turn** the encoder to raise or lower volume on whichever autostream
  appliance is currently announcing playback on the network.
- **Press** the encoder button to mute or unmute (if wired).
- If your dial has the optional **display**, it shows album artwork for the
  currently playing, identified track, falling back to the autostream logo
  when nothing is playing or no artwork is available.
- If your dial has the optional **touch panel**, touching the screen reveals
  on-screen mute/down/up controls; touch again (or hold, to repeat) to act.
  The controls hide themselves 4 seconds after the last touch.
- If your dial has the optional **LED**, it lights steadily whenever an
  autostream appliance is announcing playback, and blinks twice when volume
  hits its minimum or maximum.

If more than one autostream appliance is playing at once, turning the dial
or pressing its button sends the volume change or mute/unmute to **all** of
them at the same time, not just one.

## Next steps

- [Setup: Dials](../SETUP-DIALS.md): the appliance side of authorizing and
  revoking a dial.
- [System Maintenance](SYSTEM-MAINTENANCE.md): firmware updates and
  recovering a dial that won't come back online.
- [Build Guide](BUILD-GUIDE.md): building or extending the hardware,
  including the optional screen, touch panel, and LED.
