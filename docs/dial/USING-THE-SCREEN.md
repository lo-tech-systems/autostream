# autostream dial: Using the Screen

This guide covers the optional dial screen: what each page shows, what
happens when you tap it, and how the pages fit together. It doesn't cover
setup or configuration; see [Getting Started](GETTING-STARTED.md) for
that, and the [Build Guide](BUILD-GUIDE.md) for fitting the screen and
touch panel in the first place. It covers the small SPI screens. A dial
with a full-size HDMI or DSI touchscreen has its own page: see
[HD dial](HD-DIAL.md).

The screen comes in two sizes. A small (physically tiny) panel runs a
simplified "compact" layout: a plain 2x2 grid of controls with no text
labels beyond what's strictly needed. A larger panel runs the full "rich"
layout, with an appliance name, artist and track text, and a few extra
pages the compact layout doesn't have room for. Screenshots below are
marked rich or compact; where a page looks the same either way, only one is
shown.

Everything in this guide needs the touch panel to interact with. A screen
fitted without a touch panel still shows the same pages, but taps do
nothing: turn the dial's rotary control to change volume, as before.

`[ ]` marks a couple of points I couldn't confirm from the code and have
flagged rather than guessed.

## Idle screen

Nothing playing, on any autostream appliance the dial can see, shows the
plain autostream logo:

![Idle screen showing the autostream logo, a Wi-Fi status icon top left and an information badge top right](images/idle-rich.png)

*Rich idle screen: logo, Wi-Fi icon (top left), info badge (top right).*

![Idle screen on the small compact panel](images/idle-compact.png)

*Compact idle screen: the same logo, icon and badge, just tighter.*

Two small corner controls sit on every idle screen, rich or compact:

- **Top right, the "i" badge** opens the [info page](#info-page). It's
  always there, whether or not anything is playing.
- **Top left, the Wi-Fi icon** shows the dial's own network status (see
  below) and opens the [No-WiFi page](#no-wifi-and-restart) when the link
  is down.

Tapping anywhere else on the idle screen opens the replay picker, but only
if a held recording is actually available to replay; otherwise the tap
does nothing. See [Repeat and replay](#repeat-and-replay).

## Wi-Fi status icon

The Wi-Fi icon in the top-left corner has four looks:

![Wi-Fi icon showing three lit signal bars](images/idle-wifi-connected.png)

*Connected: steady bars, one lit for each notch of signal strength.*

The icon flashes when the link is down, alternating every second or so
between a dimmed grey glyph and one of two other looks, depending on what
kind of "down" it is:

![Wi-Fi icon dimmed to grey](images/idle-wifi-flash-grey.png)

*The grey half of the flash, shown either way while the link is down.*

![Wi-Fi icon in red](images/idle-wifi-flash-red.png)

*Lost connection: the flash's other half turns red. This means the dial
was connected at some point since it last started, and has since dropped
off the network.*

![Blank corner where the Wi-Fi icon would be](images/idle-wifi-flash-off.png)

*Still connecting: the flash's other half shows nothing at all, rather
than red. This means the dial hasn't connected since it started up (for
example, straight after a reboot), so dropping to red would wrongly
suggest something has gone wrong, when it may simply not have joined yet.*

The distinction matters for what a tap on the icon does. While the dial is
still connecting (grey/blank), a tap opens the No-WiFi page, but nothing
opens it for you: you have to go looking. Once the dial has been connected
and then loses the link (grey/red), the No-WiFi page opens on its own after
a few seconds of being down, without you needing to tap anything. See
[No-WiFi and Restart](#no-wifi-and-restart).

## Starting up

The very first frame the screen shows at boot, before the dial has even
finished starting its own backend:

![Starting splash reading "Starting..." on a plain dark background](images/starting-rich.png)

*Rich panel.*

![The same starting splash on the compact panel](images/starting-compact.png)

*Compact panel: identical message, smaller frame.*

This clears itself automatically once the dial's first status check
completes, replaced by the idle screen or whatever is playing.

## Now playing and touch controls

While something is playing, the appliance name, artist, track and volume
show at the top and bottom of the artwork. Artwork, artist and track shown
here are stand-ins, not a real recording:

![Now playing screen: appliance name and page dots top left, speaker icon and volume top right, artist and track above a minus / plus / mute footer](images/now-playing-rich.png)

*Rich now-playing screen. Top: page dots, appliance name, speaker icon and
volume. Bottom: minus, plus, mute.*

The top and bottom bands here are two different tap targets that happen to
both show a speaker icon, easy to mix up:

- The **top-right speaker icon and volume number** open the
  [outputs list](#per-output-control) (rich panels only, see below).
- The **bottom-right mute button** toggles mute. It always shows the same
  crossed-speaker icon; when muted, the whole button lights up solid so you
  can see the state at a glance, rather than the icon itself changing.

![The same now-playing screen with the mute button lit solid to show muted](images/now-playing-rich-muted.png)

*Muted: the mute cell (bottom right) fills solid. Nothing else changes:
the appliance is still selected and playing, just silent.*

Tapping the artwork itself (the middle of the screen, between the two
bands) hides both bands for about six seconds, so you can see the artwork
without anything overlaid. Tap anywhere on the screen to bring the bands
back before the six seconds is up.

Other taps on this screen:

- The **appliance name** (top left, next to the page dots) opens the
  [appliance selector](#appliance-selector), rich panels only.
- **Minus** and **plus** (bottom left and centre) step the volume down or
  up by the configured step size. Hold either down to repeat.

### Compact controls

On a compact panel, the now-playing screen has no text at all, just
artwork behind a 2x2 grid of controls, and even that grid starts hidden.
Tap anywhere to reveal it for about six seconds:

![Compact controls: page dots top left, mute top right, minus and plus along the bottom](images/now-playing-compact.png)

*Compact controls, revealed. Top left: page dots. Top right: mute. Bottom:
minus, plus.*

![The same compact controls with the mute cell inverted to show muted](images/now-playing-compact-muted.png)

*Muted: the top-right cell inverts to a solid light background with a dark
glyph, the same "always the same icon, the cell shows the state" rule as
the rich mute button.*

There's no appliance name and no way to open the outputs list from a
compact panel; see the notes on each of those sections below.

## Page dots

The two or three small dots next to the appliance name (or, on compact, on
their own in the top-left cell) show which of up to three pages is open,
and let you move between them:

- **Main** (now playing): the left dot.
- **Repeat**: the middle dot, only present if a held recording is
  available to arm or replay.
- **EQ**: the third dot, only present on rich and larger panels, and only
  if the currently-followed appliance supports bass/treble control. Never
  appears on compact panels at all, even if the appliance supports it.

Tapping the dots cycles to the next available page, skipping any page with
nothing to show, and wrapping back to main. Leaving the repeat or EQ page
this way brings you back to the now-playing screen with its volume overlay
showing, rather than bare artwork.

## Appliance selector

Rich panels only. Tapping the appliance name opens a list of every
appliance the dial can see and control:

![Appliance list: one row playing with a play glyph, another showing its own volume, a third with nothing playing](images/selector-rich.png)

*The currently-playing row (highlighted) shows a play glyph; other rows
show their own volume if idle, or nothing if unreachable.*

Tap a row to switch the dial's focus to that appliance. This works whether
it's currently playing or idle. Tap the X to close the list without
changing anything. The chevrons (or, on some panels, a side rail) page
through the list if there are more appliances than fit on one screen.

An appliance that has not authorised this dial is listed too, dimmed, with
**Not authorised** in place of the playing glyph or volume. Tapping that row
does not switch to it. Instead it opens a short full-screen hint, "Allow this
dial in <appliance name>'s web UI (Setup, Dials)", and going back from the
hint returns to the list. To fix it, open that appliance's web page, go to
Setup, Dials, find this dial's card and turn on **Allow dial to control this
appliance** (see [Getting Started](GETTING-STARTED.md#authorizing-the-dial)).
The row returns to normal once the appliance has accepted the dial and the
dial has next checked in with it.

The screen goes to sleep after 5 minutes with nothing playing on any
appliance the dial may control. It wakes when one of those appliances starts
playing, or when you touch it. A touch on the sleeping screen only wakes it and
never presses anything; touch again to use the control under your finger.

An appliance that has not authorised the dial no longer wakes the screen.
Playing on it does not turn a sleeping panel on, does not keep an idle panel
awake, and does not put a "Playing" view on screen. The dial does not send it
volume or mute either. An appliance that has not answered either way yet is
treated as usable until it refuses.

Compact panels have no name button and so no way to open this list: a
compact dial simply follows whichever appliance is currently reporting
playback.

## Repeat and replay

The repeat feature holds a recording so it can be replayed later. Before
one is running or held, the repeat page doesn't exist at all: the page
dots skip straight over it. Once a recording is available, it has two
layouts depending on state.

### Enable

Shown while a live source is recording, pending, or idle with repeat
switched on:

![Repeat enable screen: "Repeat Play" label with a solid dot showing it's armed](images/repeat-enable-rich.png)

*Rich: the toggle row. A solid dot means armed; a hollow ring means
disarmed. Tap the row to flip it.*

![The same enable screen on a compact panel](images/repeat-enable-compact.png)

*Compact: the same toggle spans the whole bottom row, with the dots cell
top left to back out.*

### Replaying

Shown once a held recording is running (or paused in Hold, ready to
start):

![Replaying screen: a position counter over Restart and Stop controls](images/repeat-replaying-rich.png)

*Rich: the position counter ("elapsed / total") over Restart and Stop.
Restart seeks back to the beginning; Stop fades the replay out and returns
to Hold.*

![The same replaying state on a compact panel, as a 2x2 with a restart-to-start icon and a stop square](images/repeat-replaying-compact.png)

*Compact: its own 2x2, with the position counter top right, a
restart-to-start icon bottom left, and a stop square bottom right.*

### Replay picker

From the idle screen, tapping anywhere (when a replay is actually held)
opens a picker to choose which appliance's held recording to start from
the beginning:

![Replay picker list showing two appliances and their held recording lengths](images/replay-picker-rich.png)

*Rich: the ordinary list chassis, reused. Each row shows an appliance name
and how much recording it's holding.*

![Compact replay picker: a "Replay" title over a cancel/more column and two rows](images/replay-picker-compact.png)

*Compact: its own smaller layout, with cancel (X) and "more" (next page,
wrapping) on the left, and the two visible rows on the right.*

Tapping a row starts that recording playing from the beginning straight
away and follows it on screen. On rich and larger panels the now-playing
screen shows the replay's position over the artwork for about ten seconds,
so you can see it has started, then fades it away.

## Per-output control

Rich panels only, and only for appliances that advertise support for it.
Opened by tapping the volume readout (the speaker icon and number, top
right of the now-playing, repeat or EQ page). Closing the list, or leaving
it alone until it times out, takes you back to the page you opened it
from:

![Outputs list showing two speaker names, one with a volume level shown](images/outputs-list-rich.png)

*The outputs list: a level number shows for whichever outputs are switched
on; nothing shows for ones that are off. The appliance's default output has
a bullet after its name.*

Tap a row to open that output's own detail page:

![Output detail page: the output's name and an enable dot, with minus / plus below](images/outputs-detail-rich.png)

*The output's own toggle (solid dot = on) and its own minus/plus,
independent of the appliance's master volume shown top right.*

Tap the X (where the page dots normally sit) to go back to the list, or the
row itself to switch that output on or off. Compact panels have no volume
readout to tap, so this whole feature is unreachable there.

## EQ page

Rich and larger panels only, never available on compact, even for an
appliance that supports bass/treble control. Reached by cycling the page
dots to the third page:

![EQ page: Bass and Treble bars, each with a dB reading and minus/plus steppers](images/eq-rich.png)

*Bass over Treble, each with its own reading in dB and its own minus/plus.
The master volume still shows top right, and tapping it opens the outputs
list as on the other two pages; there's no mute control on this page.*

## Info page

Reachable from the idle screen's "i" badge on every tier. Shows a handful
of read-only diagnostic fields about the dial itself: its configured name,
firmware version, IP address, Wi-Fi network and signal, free disk space,
and its SD card's remaining health, where monitoring is turned on.

![Info list showing field names and values side by side, e.g. Dial name / Firmware / IPv4](images/info-list-rich.png)

*Rich: a plain scrollable list, name and value together. Rows aren't
tappable here, there's nothing more to drill into.*

Compact shows names only, since there isn't room for both:

![Compact info list showing just the field names, e.g. Dial name / Firmware](images/info-list-compact.png)

*Compact: field names only, in the same picker-shaped rows the replay
picker uses. Tap a row to see its value.*

![Full-screen view of a single field's value, e.g. Dial name over "Kitchen dial"](images/info-value-compact.png)

*The value drill-in a compact row opens: one field, full screen.*

Values fill in within about a second of opening the page; expect to see
placeholder dashes very briefly first.

## No-WiFi and Restart

Opened by tapping the flashing Wi-Fi icon on the idle screen, or on its own
once the link has been down for a few seconds, but only if the dial has
connected at some point since it last started. If it's still connecting
for the first time, the page waits for you to tap the icon rather than
opening itself.

![No-WiFi modal with "No WiFi" over Dismiss and Restart, shown over a dimmed idle backdrop](images/nowifi-rich.png)

*Rich: a modal card over the dimmed idle screen.*

![The same page filling the whole compact panel](images/nowifi-compact.png)

*Compact: the same Dismiss/Restart layout, filling the panel instead of a
card.*

**Dismiss** closes the page without doing anything else. It stays closed
for the rest of this outage: the icon keeps flashing, and a tap on it
reopens the page if you change your mind. Reconnecting closes it
automatically and resets Dismiss for next time.

**Restart** reboots the dial. It shows "Restarting..." immediately and asks
for the reboot in the background:

![Restarting splash reading "Restarting..." on a plain dark background](images/restarting-rich.png)

*Shown from the moment you tap Restart until the reboot actually takes the
screen down. Identical on every tier.*

## SD card warning

Shown when SD card health monitoring is turned on (from the appliance's
Setup page) and the card's remaining endurance drops low. Like the No-WiFi
page, it can appear over now-playing as well as the idle screen, and looks
the same way on both tiers: a title, a body line with the remaining
percentage, and one **Dismiss** button spanning the width of the card.

**Dismiss** closes the warning without doing anything else. It stays closed
until the reading recovers or the dial restarts; if you don't tap it at
all, the page closes on its own after a minute so it never sits over
now-playing indefinitely. Either way, the current reading stays visible on
the [info page](#info-page).

## Appliance warnings

An autostream appliance can ask the dial to show a warning of its own. The
appliance sends these for maintenance and power: a stylus near or past the end
of its life, a drive belt or main bearing due for service, or a power supply
that has dipped below its voltage. They appear on the screen as a card like
the SD card warning: the appliance's name in small text on top, then a title
(for example "Input 1 stylus"), a short message (for example "Change soon,
7.5 h left"), and one button spanning the card.

These are the quietest warnings the dial shows:

- The card only opens over the now-playing screen, and only while the screen
  is awake. It never wakes a sleeping panel and never opens over a list or
  another page.
- If the dial has other warnings due (No-WiFi, SD card health), those come
  first.
- The card closes by itself if the appliance stops reporting the warning, for
  instance after you reset the counter in its Service page.

The button depends on the warning. Most say **Dismiss**, which hides the card
for a day or a week (the appliance chooses) and brings it back after that if
the cause is still there. The snooze survives a restart. A plain notice that
cannot be snoozed has an **OK** button instead, which closes the card until
the appliance reports the notice again.

Compact panels show the same card in the same layout as the SD card warning.

## Software update

When the dial updates its own software (see
[System Maintenance](SYSTEM-MAINTENANCE.md#firmware-updates)), a card
appears on the screen. It can come up over whatever is showing, including a
list, and it wakes a sleeping panel. Touching the screen does nothing while
it shows, but turning the volume control and pressing it still work as normal.

**Updating...** is the card while the update runs. It has a progress bar and,
under it, a short label for the current step: **Downloading**, **Upgrading
OS**, **Installing** or **Restarting**. The bar moves forward as the update
does. If the update is retried after an interruption, the bar starts again
from the start.

When the update reaches its restart, the card gives way to the same
**Restarting...** screen the No-WiFi page uses. The panel then goes dark while
the dial reboots, and shows **Starting...** when it comes back. While the new
version is being checked the screen carries on as normal.

Then a result card tells you how it went:

- **Updated**, with **Version <number>** under it, if the new version passed
  its check.
- **Update failed**, with **Restored <old number>** under it if the new version
  failed its check and the dial went back to the old one, or **<old number>
  kept** if the update stopped before anything was replaced.

The result card has one **Dismiss** button. If nobody dismisses it, it clears
itself after an hour, since an update can take about 40 minutes and may well
be left unattended. A result is shown once: it does not come back after
Dismiss, after it clears itself, or after the dial restarts.

If the dial has no screen, none of this applies; follow the update from the
appliance's Dials panel instead.

## Gaps I couldn't confirm from the code

- `[ ]` I couldn't confirm from the dial's own source whether a screen
  fitted without a touch panel can ever reach the repeat, EQ, outputs or
  info pages some other way (for example, automatically cycling). I've
  assumed here that all of those need a touch panel to open, since every
  route into them in the code is a tap.
- `[ ]` The EQ page is also available on a "large" physical panel tier, one
  step up from the rich panels shown here. I haven't rendered a screenshot
  for that tier specifically; the rich screenshots above should still be
  representative, just smaller than the large panel would show it.

## Next steps

- [Getting Started](GETTING-STARTED.md): setting the dial up in the first
  place, from the appliance's own web interface.
- [Build Guide](BUILD-GUIDE.md): fitting the screen and touch panel.
- [HD dial](HD-DIAL.md): a dial with a full-size touchscreen.
- [System Maintenance](SYSTEM-MAINTENANCE.md): firmware updates and
  recovering a dial that won't come back online.
