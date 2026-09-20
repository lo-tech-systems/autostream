# Home Page

The Home page is served at `/` and is the main screen for day-to-day use: it shows what's
playing and lets you pick which speakers (AirPlay outputs) are active and how loud they are.

It polls the appliance in the background (`/api/status` every 1.5 s, `/api/owntone/outputs_state`
every 1.5 s) so it stays live without a manual refresh.

## Now Playing card

The card at the top of the page shows either:

- **Ready** — no audio is currently detected on the active input.
- **Now Playing** — an input is above the silence threshold.

Under the heading, an icon and label identify the source: **Turntable**, **Bluetooth**, or
**Line Level**, alongside the input's own label (for example "Input 1"). If a Bluetooth
turntable is connected it is still shown as a turntable.

If track identification is turned on for the input, the card instead shows the identified
track's title, artist and artwork once a match is found. While identification is in progress
it shows "Identifying Track…"; if nothing is found it shows "Unknown track"; if the
identification service itself is unavailable it shows "Track ID function not available".

### Input detail and VU meter

When **Display Input Detail** is enabled (Setup > Personalisation), the card also shows:

- A "Locked · NN kHz" line once the input has locked to a sample rate.
- A stereo VU meter (left/right level bars).

Both are hidden when this setting is off.

## Master Volume

A **Master Volume** slider appears inside the Now Playing card, but only when
**Show Master Volume Control** is enabled (Setup > Personalisation). It is disabled (greyed
out) whenever no output is currently selected. While active, dragging it scales the volume of
every selected output proportionally, using each output's current volume as its starting
point; it does not set every output to the same level.

## Speakers (outputs)

Below the Now Playing card, each AirPlay-capable output OwnTone can see is listed as a card
showing:

- The output's name, with a **Default** badge if it is the output configured as the default
  in [Setup-OwnTone](SETUP-OWNTONE.md).
- A state chip reading **On** or **Off**.
- An on/off toggle.
- When the output is on, a **Volume:** slider (0–100%) underneath.

Turning an output on sends its current volume to the appliance immediately; toggling it off
does the same. If the output requires a device PIN (for example a fresh Apple TV pairing), a
PIN entry dialog appears automatically — enter the code shown on the device to complete the
enable. If the appliance's CPU cannot encode another stream at the current audio quality, a
"CPU limit reached" message explains that the output could not be enabled and to disable
another output or choose a lighter audio mode.

Cards are sorted with the default output first, then alphabetically. While OwnTone is still
starting up the list shows "Waiting for owntone"; if no outputs have been discovered yet it
shows "Waiting for device discovery".

### "In Use by \<name\>"

If another appliance on the network is actively streaming to an output you have not selected
yourself, its card shows **In Use by \<name\>** (or **In Use** if the owning appliance's name
isn't known) instead of the On/Off toggle, and the toggle is disabled. This appliance cannot
also enable that output until the other one releases it. See [Multi-Appliance](MULTI-APPLIANCE.md)
for how appliances discover each other and what happens when you tap through to the appliance
that's using it.

## Repeat Play

A small pill button reading **↻ Repeat Play** (or **↻ Replay Last** when nothing is currently
playing but a buffered recording is available) appears next to the appliance name, but only
when the repeat feature is enabled. Tapping it arms or starts a repeat/replay; while a replay
is being stopped it reads **Stopping…** and the button is briefly disabled. See
[Setup-Playback](SETUP-PLAYBACK.md) for how repeat is enabled and its defaults configured.

## Appliance selector

If **Display Hostname** is enabled (Setup > Personalisation), a pill in the top-right shows
this appliance's hostname. If **Allow control of other appliances** is also enabled and other
autostream appliances are visible on the network, tapping the pill opens a dropdown to jump to
another appliance's Home or Equaliser page. See [Multi-Appliance](MULTI-APPLIANCE.md) for the
full behaviour, including what happens on a remote appliance's page and how connection loss is
handled.

## Other notices

- If no audio input is configured at all, a banner reads "No input device configured — set one
  up in Setup, or enable Bluetooth."
- Service reminder banners (stylus, belt, bearing wear) can appear above the outputs list; they
  link through to the Service page.

## See also

- [Setup-Playback](SETUP-PLAYBACK.md) — repeat/replay settings and defaults.
- [Setup-OwnTone](SETUP-OWNTONE.md) — configuring the default output and OwnTone connection.
- [Multi-Appliance](MULTI-APPLIANCE.md) — the appliance selector, jump-to-appliance behaviour,
  and cross-appliance output occupancy.
- [Equaliser](EQUALISER.md) — adjusting sound once playback is running.
- [Setup-Personalisation](SETUP-PERSONALISATION.md) — the toggles that show or hide the master volume, input detail, hostname pill, and appliance control.
