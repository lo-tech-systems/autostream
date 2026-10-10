# autostream dial: HD dial

An HD dial is an autostream dial with a full-size touchscreen instead of the
small SPI panel. It runs the same dial software as every other dial, so it
follows the same appliances, uses the same authorization and takes the same
updates. The difference is the screen: instead of drawing small frames to an
SPI display, the dial serves a web page to a kiosk browser on the same
board, and that browser fills the touchscreen.

**This is a preview.** The software is written and tested against a mock
dial and a browser, but it has not yet been run on real HD dial hardware.
Treat everything on this page about boards and panels as what we expect to
work, not what we have confirmed. If you try one, please report what you see.

## What you need

- A Raspberry Pi with enough memory to run a browser. A Pi 4 or Pi 5 is the
  expectation. A board with 1 GB of RAM or more is recommended. The kiosk has
  been started on a Pi 3 Model A+ (512 MB), where it runs but is short of
  memory and leans on swap. A Pi Zero 2 W (the board used for the small SPI
  dial) has the same 512 MB and is not a target.
- A touchscreen of about 5 inches or larger, connected by HDMI (with USB
  touch) or by the Pi's DSI connector. The page is designed at 800x480 and
  scales up to larger panels such as 1024x600 and 1280x800. It is landscape
  only: a portrait screen shows a "Turn the screen to landscape" note.
- Raspberry Pi OS Lite, 64-bit, set up as for any other dial (see the
  [Build Guide](BUILD-GUIDE.md) for the OS and Wi-Fi steps). No SPI wiring is
  needed.
- At least one autostream appliance on the same network.

A DSI panel with a backlight can be dimmed and switched off by the dial. So can
an HDMI panel that supports the monitor control channel (DDC/CI), which many do:
the dial sets its brightness and switches its backlight off when the screen
sleeps. An HDMI panel that does not answer it keeps working, but the page dims
and blacks out the picture instead and the panel's own backlight stays on.

## Installing

Run the dial installer with the `--hd` flag on a fresh install:

```
./autostream_dial_install.sh --hd
```

On top of the normal dial install this:

- installs the kiosk browser (`cage`, a minimal Wayland compositor, and
  Chromium) and a font package;
- creates an account of its own for the browser, so the browser runs apart
  from the dial's state files;
- enables the graphics driver (`vc4-kms-v3d`) in the Pi's boot
  configuration. It leaves the GPU memory split alone, because that driver
  takes its memory from the kernel's own pool;
- selects the **HD touchscreen** screen type with no touch driver (the
  browser reads the touchscreen itself);
- installs and enables the kiosk service, `autostream_dial_kiosk`, and a
  small udev rule that lets the dial control a panel's backlight;
- loads the `i2c-dev` kernel module at boot and adds the dial's service
  account to the `i2c` group, so the dial can talk to an HDMI panel's control
  channel. Nothing extra is installed, and a system without an `i2c` group
  simply skips this.

Every dial install and update, SPI or HD, also adds a boot splash. A screen
on the HDMI or DSI output shows "Starting..." while the dial boots, keeps it
until the page paints, and shows "Shutting down..." at shutdown and reboot, so
an SPI dial with a monitor attached shows it too. The dial's own small screen is
not affected. To do this the installer adds Plymouth and rebuilds the boot
files, so the first update on an existing dial takes a few minutes longer than
usual. It also quietens the console during boot; the dial's logs are unchanged.

Reboot when the installer finishes. The kiosk starts at boot and the dial
service starts its page server first. A DSI panel may need its own overlay
in the boot configuration; the installer leaves that to you, as the right
line depends on the panel.

An update does not need the flag. It reads the screen type the dial already
uses and keeps the kiosk set up. An existing SPI dial can be turned into an
HD dial by choosing **HD touchscreen** under **Screen Type** on the appliance's
Setup page, but the kiosk browser is only installed by a fresh `--hd` install,
so that choice alone shows nothing.

## Using the screen

The screen has two sides. Everything is touch; there is no keyboard, and the
mouse pointer is hidden on the dial's own screen (it stays visible when you
open the same page from a laptop).

### Appliances and speakers

The left side lists the appliances the dial can see in its top third, with
the speakers of the followed appliance below. Each list scrolls on its own.
When a list has more to show, the card at its edge fades out and the next
heading sits over it, so you can tell there is more to scroll to. Tap an
appliance to make the dial follow it. The row for the one being followed is
highlighted, and it scrolls into view when the dial changes appliance by
itself, unless you have just scrolled that list.

- An appliance that is not answering shows **Not responding** and its
  controls are disabled while it is followed.
- An appliance that has not authorised this dial shows **Not authorised**.
  Tapping it opens a short card saying to allow the dial in that appliance's
  web UI (Setup, Dials). See [Getting Started](GETTING-STARTED.md#authorizing-the-dial).
- A speaker in use by another autostream appliance is dimmed and cannot be
  switched, with **In Use by** and the other appliance's name when it is known.
- The appliance's default speaker carries a Default label, as on the appliance's
  Home page.
- Speakers have their own on/off switch and volume slider.
- Switching on a speaker that needs pairing (a new Apple TV, for example)
  makes that device show a code, and a keypad card opens on the dial. Enter
  the code and press OK; the card says Pairing while the appliance checks it,
  and closes when the speaker is paired. The code needs at least four digits,
  and the boxes grow if it is longer (up to eight). If the code is wrong the
  card says so and you can try again. After several quick attempts it asks
  you to wait a few seconds, counting down, and the keys stay greyed out until
  it is time. Cancel closes the card, and so does leaving it alone for a
  minute and a half. The appliance's Home page waits while the dial is doing
  this. Against an older appliance the card instead says **Pair in Autostream**,
  asking you to enter the code in that appliance's web UI.

### Now playing and volume

The right side shows the artwork, the track and artist, a mute button and the
master volume slider. The artwork sits on a soft, blurred copy of itself, and
the logo does the same when nothing is playing. When the track changes, the
picture and its blurred backdrop fade into the new one together (a plain
change if the screen is set to reduce motion). With nothing playing the side
shows the autostream logo and **Nothing playing**. When the appliance is
playing but has not named the track yet, as the track changes or in the first
moments of playback, the track line reads **Playing**, the same word the small
screen uses, until the title arrives.

The controls are always on show: the replay row, the track line and the volume
row stay where they are however long the screen is left alone.

### Replay row

If the followed appliance can repeat and replay, a row above the track holds
its replay controls. While something is playing live, the row holds the
**Repeat Play** switch, which arms or disarms repeat, as on the small screen.
The rest of the time it holds two transport buttons and a timer, in that
order, like the front of a tape deck:

- Once a recording is held, the first button is **play** (a triangle), which
  starts the replay from the beginning. Stop is greyed out, and the timer
  shows the recording's length, for example `0:00 / 18:20`.
- While a replay runs, the first button is **back to the start** (a bar and
  two arrows), which restarts the replay without asking, and the second is
  **stop** (a square). The timer counts the position against the length, for
  example `2:05 / 18:20`. It runs behind the appliance's reported position
  by the appliance's audio start buffer, so it matches what you hear. Press
  stop and the timer stops at once and both buttons grey out; when the
  appliance confirms the replay has ended, the row shows the held recording
  again. If the stop is refused or never confirmed, the timer picks up where
  the replay now is.
- As a replay fades out at its end, both buttons are greyed out and the timer
  stands still.
- With nothing playing and nothing held, both buttons are greyed out and the
  timer reads `-:-- / -:--`.

Play and back to the start look pushed in from the moment you press them,
because the appliance takes a few seconds to answer. They come back out when
the appliance reports the replay running from the start. They also come back
out if the request is refused or gets no answer, if the appliance stops, or if
you move to another appliance, so a button never stays down.

A greyed-out button does nothing. Lengths of an hour or more show hours, for
example 1:02:05. If repeat is turned off on the appliance, the row is not
shown.

An appliance row that holds a recording shows its length as a badge. Tapping
that row follows the appliance, and its replay row then offers play. See
[Repeat and replay](USING-THE-SCREEN.md#repeat-and-replay) for what these
mean.

### Equaliser page

If the followed appliance supports it, an equaliser icon sits beside the track
line. It opens the equaliser page for that appliance: sliders for each band
(two, Bass and Treble, on an older appliance; six on a newer one), a live
graph of the resulting response, and **Reset** to put every band back to flat.
Tap the back arrow to return.

### Pull-down settings and information

Pull the handle at the top of the screen down (or tap it) to open a sheet:

- **Brightness** slider.
- **Sleep after**: 1 min, 5 min, 15 min or Never.
- **Sleep now**, which puts the screen to sleep straight away.
- **This dial**: the dial's name, firmware version, IP address, Wi-Fi network
  and signal, free disk space and, where monitoring is on, SD card health.
- A **power button** at the top right, which shuts the dial down.

Changes apply at once and are saved by the dial.

To shut the dial down, press the power button. The dial asks **Shut down?**;
choose **Shut down** to go ahead or **Cancel** to leave things as they are.
Once you confirm, the screen reads **Shutting down...** and then the shutdown
screen takes over. Wait for the screen to go dark before taking the power
away, and unplug and replug the dial to start it again. Only the dial's own
touchscreen can do this: the page served on the local network for development
(see below) refuses it.

### Warnings

The screen shows the same warning cards as the small screen: No WiFi (with
Restart), microSD Health, and software update progress and result. They appear
in the middle of the screen over a dimmed page.

Appliances can also send warnings of their own, such as a stylus nearing the
end of its life, a drive belt or main bearing due for service, or a low
power-supply voltage. These are quieter than the dial's own warnings:

- A small badge with a count appears on that appliance's row, coloured by
  how urgent the worst warning is. Tap the badge to read the card.
- When you are following that appliance, its most urgent warning also opens
  as a card by itself.
- **Dismiss** hides a warning for a day or a week (the appliance suggests
  which) and it returns after that if the cause is still there. A notice that
  cannot be snoozed has an **OK** button instead and is put away until the
  appliance reports it again.
- An appliance warning never wakes a sleeping screen.

Resetting the counter in the appliance's Service page clears its warning.

### Sleep and waking

After the **Sleep after** time with nothing playing the screen goes black. On a
panel with a backlight (including an HDMI panel the dial controls over DDC/CI)
the dial also switches the backlight off. The screen wakes when something
starts playing, or when you touch it. An HDMI panel can take a second or two to
come back, and may briefly show its own source banner as it does. The touch
layer keeps working while the panel is off, so a touch still wakes it. A touch on a
sleeping screen only wakes it: it never presses a control, so touch again to
use what is under your finger.

### If the connection drops

If the page cannot reach the dial's service for several seconds, a bar at the
top says it is reconnecting and the controls are disabled until it recovers.

## Settings on the appliance

An HD dial's card on the appliance's **Setup** page, in the **Dials** card,
shows **Brightness** and **Sleep after** in place of the rotate, colour order,
size, layout and touch rows, which only matter to an SPI panel. They are the
same settings as in the pull-down sheet. There is no **Show dial screen**
button because an HD dial has no frame to show.

If you select **HD touchscreen** for a dial, the card reminds you that it
needs the HD kiosk install.

Everything else (name, step size, PIN, updates, authorization) is set on the
appliance as for any dial. See [Getting Started](GETTING-STARTED.md).

## Trying the page from a laptop

For development and testing, the dial can also serve its page on the local
network, so you can open it in a normal browser and drive the real dial
against real appliances. This is off by default and is intended for a trusted
home network.

1. Set a PIN on the dial (in its Setup card). The development listener signs
   in with the PIN, so it cannot be turned on without one, and it turns off if
   the PIN is cleared.
2. Turn it on by posting to the dial's own port, using the PIN (replace the
   address and PIN):

   ```
   curl -X POST http://<dial-address>:7842/configure \
     -H 'Content-Type: application/json' \
     -d '{"hd_dev_access": true, "current_pin": "1234"}'
   ```

   Send `false` the same way to turn it off. The setting is kept across
   restarts.
3. Open `http://<dial-address>:7844/` in a browser, enter the PIN and use the
   page as on the touchscreen.

Security notes:

- The listener is on port 7844 and is never advertised. It is not reachable
  through the appliance's web server.
- Every request except the sign-in page needs a session. A wrong PIN counts
  against the same per-address lockout as the dial's other PIN checks.
- Shutting the dial down and confirming that a person is at the dial are not
  possible from this page; the dial's own touchscreen is the only way to do
  either.
- Sessions last 12 hours, are kept in the dial's memory only (a restart signs
  everyone out), and at most eight are held at once.
- The connection is plain HTTP, so the PIN crosses the network unencrypted.
  Use it only on a network you trust and turn it off when you are done.
- The touchscreen itself is served only on the dial's own loopback address
  (`127.0.0.1`, port 7843) and cannot be reached from the network.

To look at the page without any dial at all, run the offline mock:

```
python3 tools/hd_mock_server.py --scenario replaying
```

and open the address it prints. `--list` shows the available scenarios.

## Troubleshooting

**The screen is black after boot.** Check that the kiosk service is running
(`systemctl status autostream_dial_kiosk`) and read its log
(`journalctl -u autostream_dial_kiosk`). The service only starts where the
installer left its marker file; if you selected the HD screen type without
installing with `--hd`, there is no kiosk. The kiosk waits for the dial's page
server, so also check `systemctl status autostream_dial`. A black screen after a
long idle is usually the dial's sleep, so touch it.

**The screen shows Starting... and stays there.** The boot has finished but the
kiosk has not painted its page yet, or has failed to start. Check
`systemctl status autostream_dial_kiosk` and
`journalctl -u autostream_dial_kiosk`.

**The page says it is reconnecting.** The browser is running but the dial
service is not answering. Restart `autostream_dial` and read its log.

**The browser shows a graphics error or is very slow.** Check that the
installer's boot changes took effect (they need a reboot) and that the board
has enough memory (1 GB or more is recommended). On a Pi 3 the browser
falls back to software rendering, which works but is slower.

**Touch does nothing, or hits the wrong place.** The browser reads the
touchscreen directly, so check the panel's own USB or DSI touch connection and
that the kiosk's account is in the `input` group.

**Brightness does nothing on an HDMI panel, or the panel never switches off.**
The dial can only control an HDMI panel that answers DDC/CI. Check that the
module is loaded (`lsmod | grep i2c_dev`), that a `/dev/i2c-*` device exists,
that the dial's account is in the `i2c` group (`id autostream`; a change of
group needs the dial service restarted, or a reboot) and that the panel's own
menu has not turned DDC/CI off. The dial logs a line naming the bus when it
finds a panel (`HD panel: DDC backlight on`). If the panel does not answer, the
page dims the picture instead, and on a panel that has no way to switch off
its backlight over DDC/CI the screen goes black but the panel's light stays
dim.

**An appliance shows Not authorised.** Allow the dial on that appliance, as for
any dial: [Getting Started](GETTING-STARTED.md#authorizing-the-dial).

## Next steps

- [Using the Screen](USING-THE-SCREEN.md): the small SPI screen, with the same
  pages in a smaller form.
- [Getting Started](GETTING-STARTED.md): setting a dial up from the appliance.
- [Build Guide](BUILD-GUIDE.md): the OS and the SPI hardware.
- [Architecture](ARCHITECTURE.md): how the HD page fits into the dial software.
