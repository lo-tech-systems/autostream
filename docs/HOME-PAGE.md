# Home Page

The Home page is the main screen for day-to-day use. It shows what's playing and lets you pick
which speakers (AirPlay outputs) are active and how loud they are. The appliance pushes each
change to the page as it happens, so it updates on its own, with no manual refresh. If the live
connection is lost, the page falls back to checking the appliance at intervals until it returns.

## Now Playing card

The card at the top of the page shows one of:

- **Ready** - no audio is currently detected on the active input.
- **Now Playing** - an input is above the silence threshold.
- **Repeat Play** - autostream is replaying the last recorded disc or record. See [Repeat playback](SETUP-PLAYBACK.md#repeat-playback).

Under the heading, an icon and label identify the source by its input type: **Turntable**, **CD**
or **Line**, alongside the input's own label (for example "Input 1 · CD"). A Bluetooth source keeps the
Bluetooth icon, with its input type as the label. You choose the type in
[Setup: Inputs](SETUP-INPUTS.md#input-type).

If [track identification](SETUP-TRACK-ID.md) is turned on, the card instead shows the identified
track's title, artist and artwork once a match is found. Track identification is a global
setting, not per input. While identification is in progress the card shows the current stage:
"Waiting for audio" before analysis starts, then "Analysing" while a sample is being checked.
The periodic re-check of a track that is already identified runs in the background: the card keeps
showing the track while it runs, and keeps it if the re-check finds nothing or fails; only a detected
track change, a new session or a replay seek clears it.
If nothing is found it shows "Unknown track"; if the identification service itself is
unavailable it shows "Track ID function not available". This works the same way during
[repeat playback](#repeat-play): identification keeps tracking the replayed recording, not
just live input.

### Input detail and VU meter

When **Display input detail** is enabled ([Setup > Personalisation](SETUP-PERSONALISATION.md)), the card also shows:

- A `Locked · 44.1 kHz` line once the input has locked to a sample rate, `Acquiring` while it is working one out, or `Mismatch · 44.1 kHz` when the input delivers a different rate than it was opened at and Dynamic Rate Matching is off. A device that delivers a rate other than 32, 44.1 or 48 kHz shows `Acquiring` for as long as it does so, and Dynamic Rate Matching does not correct it.
- Nothing for an input that is not running; the rate line appears once the input starts.
- A stereo VU meter (left/right level bars).

Both are hidden when this setting is off.

## Master Volume

A **Master Volume** slider appears inside the Now Playing card, but only when
**Show master volume control** is enabled ([Setup > Personalisation](SETUP-PERSONALISATION.md)). It is disabled (greyed
out) whenever no output is currently selected. While active, dragging it scales the volume of
every selected output proportionally, using each output's current volume as its starting
point; it does not set every output to the same level.

The Auto-Start pin sits at the right of the Master Volume heading (see
[Auto-Start speakers](#auto-start-speakers) below).

## Speakers (outputs)

Below the Now Playing card, each AirPlay-capable output OwnTone can see is listed as a card
showing:

- The output's name, with an **Auto-Start** badge if it is in the Auto-Start set (see
  [Auto-Start speakers](#auto-start-speakers) below). Auto-Start speakers are listed first, then
  the rest by name. A speaker you have hidden in [Setup-OwnTone](SETUP-OWNTONE.md) is listed
  only while it is on or in the Auto-Start set.
- A state chip reading **On** or **Off**, or **Paused** for a speaker that was paused on the
  speaker itself (see [Personalisation](SETUP-PERSONALISATION.md)). Pressing Play on that
  speaker starts it again, as does switching it off and on here.
- An on/off toggle.
- When the output is on, a **Volume:** slider (0-100%) underneath.

While autostream is starting a speaker that should be playing, its name is followed by
**(Connecting)**. A speaker you have switched off that is still ending its session shows
**(Stopping)** until it has stopped; switching it on again meanwhile is fine, and it starts
once the stop is done. An Auto-Start speaker that is not currently on the network stays in the list
with **(offline)** after its name, its volume slider is disabled, and its toggle is disabled
until a listening session is running. If an Auto-Start speaker fails to start, autostream keeps
retrying it while the music plays. A speaker that drops out while it is playing is tried
again 10 and 30 seconds later; if it is still not back it is switched off and the page says
it could not be started.

Turning an output on sends its current volume to the appliance immediately; toggling it off
does the same. If the output requires a device PIN (a fresh Apple TV pairing, for example), a
PIN entry dialog appears: enter the code shown on the device and the speaker is paired and
switched on in one go. A wrong code lets you try again; with an Apple TV the dialog says
**That PIN was not accepted. A new PIN is showing on the TV.**, so enter the new code. If the
speaker is still busy finishing something else, the dialog stays open and says **The speaker
is busy. Try the PIN again in a moment.**; the same code still works. After
several quick attempts the
dialog asks you to wait a few seconds. If an HD dial asked for the speaker, the dial shows
the keypad and this page waits for it. On an appliance running an older version the code is
accepted but the speaker stays off; switch it on again and it plays.

If a speaker does not start, a **Could not start** dialog names it and gives the likely
reason: it turned the request down, it could not be reached, it did not answer in time, or
it is not following the appliance's clock (restarting the speaker usually clears that). While
someone is entering a speaker's PIN on another page or a dial, switching it on here is
refused, so the PIN on the screen is not replaced. Another appliance's Home page shows the same dialog for a speaker on that appliance.

### Auto-Start speakers

While a listening session is running, an **Auto-Start** pin appears (in the Master Volume
heading, or above the speaker list if the master volume control is hidden). Tap it and
confirm to save the speakers that are on now, with their levels, as the set that starts with
each new session. The pin looks pressed while the speakers that are on match the saved set.
The set is also listed under [Setup - Playback](SETUP-PLAYBACK.md#auto-start-speakers).

### "In Use by \<name\>"

If another autostream appliance on the network is actively streaming to an output you have not selected
yourself, its card shows **In Use by \<name\>** (or **In Use** if the owning appliance's name
isn't known) instead of the On/Off toggle, and the toggle is disabled. This appliance cannot
also enable that output until the other one releases it. See [Multi-Appliance](MULTI-APPLIANCE.md)
for how appliances discover each other and what happens when you tap through to the appliance
that's using it.

## Repeat Play

autostream can repeat the last disc or record it played. When repeat is enabled in
[Setup - Playback](SETUP-PLAYBACK.md#repeat-playback), a **Repeat Play** button appears at the
top of the Home page. Tap it to enable replay mode (which also starts a replay if a recording
is available), and tap it again to stop repeat playback.

## Appliance selector

If **Display hostname** is enabled ([Setup > Personalisation](SETUP-PERSONALISATION.md)), a pill in the top-right shows
this appliance's hostname. If **Allow control of other appliances** is also enabled and other
autostream appliances are visible on the network, tapping the pill opens a dropdown to jump to
another appliance's Home or Equaliser page. See [Multi-Appliance](MULTI-APPLIANCE.md) for the
full behaviour, including what happens on a remote appliance's page and how connection loss is
handled.

## Other notices

Anything the appliance wants you to know appears as a warning on the Home page, in one of two
ways.

- **Red banner.** A critical fault (for example a power supply that cannot hold its voltage up,
  a CPU that is too hot, or a microSD card that is failing) shows as a red banner across the
  top of the page, as "Title: message". If there is more than one, the banner shows the first
  with "+N more"; tap it to open the whole list and tap again to fold it.
- **Warning cards.** Everything else appears as cards above the speaker list. Two show at a
  time, with a "N more" button to show the rest. A card whose message has a page to go to has
  a chevron (>) at its right edge; tap it to open that page. The cards are:
  - **Stylus, drive belt or main bearing**, per input: "Change soon" or "Service soon" as the
    hours or time run down, then "Change now" or "Service now" once overdue. They link to the
    [Service](SERVICE.md) page. When several inputs share the same message the cards are
    folded into one that names the inputs.
  - **Sample rate**: "Turn on rate matching" while an input delivers a different sample rate
    than it was opened at and Dynamic Rate Matching is off for that input. It opens that
    input on the Setup page.
  - **CPU temperature**: "Running hot" (a card) or "Too hot" (the red banner). It opens the
    System panel on the About page.
  - **microSD card**: "Replace soon" (a card) or "Replace now" (the red banner), with the same
    link. See [SD card health monitoring](SETUP-SYSTEM.md#sd-card-health-monitoring).
  - **Power supply**: "Low voltage seen" (a card) since the last restart, or "Low voltage now"
    (the red banner).
  - **Dials**: "N need updating" when a dial is running older software. It opens the Dials
    panel in Setup.
  - **Licence**: "This system is unlicensed".
  - **No input**: "Set up an input in the web UI" when no audio input is enabled. It opens
    Setup.
- The **Service** tab in the navigation bar is marked with the colour of the most severe
  Service warning, and the mark goes away when there is none.

On another appliance's page (see [Multi-Appliance](MULTI-APPLIANCE.md)) the cards show without
their links.

## See also

- [Setup-Playback](SETUP-PLAYBACK.md) - repeat/replay settings and defaults.
- [Setup-OwnTone](SETUP-OWNTONE.md) - configuring the default output and OwnTone connection.
- [Multi-Appliance](MULTI-APPLIANCE.md) - the appliance selector, jump-to-appliance behaviour,
  and cross-appliance output occupancy.
- [Equaliser](EQUALISER.md) - adjusting sound once playback is running.
- [Setup-Personalisation](SETUP-PERSONALISATION.md) - the toggles that show or hide the master volume, input detail, hostname pill, and appliance control.
