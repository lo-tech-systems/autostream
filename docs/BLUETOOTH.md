# Bluetooth Input

Some turntables have a built-in Bluetooth transmitter. If yours does, autostream can
receive audio from it directly — no USB adapter needed. The appliance takes the
Bluetooth audio and sends it on to your AirPlay speakers exactly as it would with a
wired input: drop the needle, the stream starts; stop the record, it stops.

This page explains what to expect, how to turn the feature on, and how to pair a
turntable.

---

## What this is (and isn't)

Bluetooth input is a **convenience option**, not an upgrade. Normally, autostream
receives audio through a USB adapter (like the Behringer U-PHONE UFO202) wired to your
turntable or CD player. With Bluetooth input, a turntable that has its own wireless
transmitter can send audio straight to the Pi instead — one less cable, no USB box to
find a home for.

Two things worth knowing before you switch:

* **Sound quality.** Wireless audio is always compressed to fit over the Bluetooth
  connection, and the compression happens inside the turntable itself — autostream has
  no control over it. A wired USB connection remains the best-quality option.
  Bluetooth is the convenient option. For most listening, especially through
  compact or portable speakers, the difference is minor. If you care about
  getting the absolute best sound from your records, keep the USB adapter.
* **Delay.** Bluetooth audio takes a fraction of a second longer to arrive than a
  wired connection. For music, this isn't something you'll notice — it only matters
  if you're trying to sync sound to a picture, which isn't what this feature is for.

## Supported hardware

Bluetooth input has been tested and works well on the **Raspberry Pi 3, Pi 4, and Pi
5**.

It may also work on a **Pi Zero 2 W**, but this isn't a supported configuration. The
Zero 2 W shares one antenna between Wi-Fi and Bluetooth, and running both at once
(streaming Bluetooth audio in, while sending AirPlay audio out over Wi-Fi) can make
one or the other less reliable. If reliability matters to you on a Zero 2 W, use a
**USB Bluetooth adapter** instead of the onboard radio — plugging one in avoids the
shared-antenna problem entirely, since the adapter has its own antenna.

## Turning it on

Bluetooth input is built into every autostream appliance — there's nothing to
request at install time and nothing to reboot for.

1. Open the autostream **Setup page**.
2. Find the **Bluetooth card**.
3. Press **Enable Bluetooth Services**.

That's it — the card updates to show the feature is on, ready for you to plug in an
adapter and pair a device.

## Adapters: plug in a dongle

**A USB Bluetooth adapter is strongly recommended.** Plug one into the Pi and it just
works — no setup, no reboot, nothing else to do. The Bluetooth card will show it as
the detected adapter as soon as it's plugged in.

Every Raspberry Pi model this feature supports also has a **built-in Bluetooth
radio**, but it's switched off by default because it shares its antenna with Wi-Fi —
running both at once can make either one less reliable, especially on a Pi Zero 2 W.
If you'd rather not use a dongle, you can turn the built-in radio on with the card's
**"Use onboard bluetooth device"** toggle. This restarts the appliance to take effect.

If both a USB adapter and the onboard radio are available at the same time,
autostream always uses the USB adapter.

**Our recommendation: use a USB dongle.** It's simpler, faster to turn on, and avoids
the Wi-Fi/Bluetooth trade-off entirely.

## Pairing your turntable

Pairing is done from the Setup page, either from the Bluetooth card or from an input:

1. Open the autostream **Setup page**.
2. Either press **Pair new device…** on the Bluetooth card, or choose **Bluetooth**
   from the device list on **Input 1** or **Input 2**.
3. A pairing window opens and starts scanning.
4. Put your turntable into pairing mode (check its manual — this is usually a button
   press or a switch position, and often a flashing light on the turntable).
5. Your turntable should appear in the list within a few seconds. Tap it.
6. Once pairing completes, the device is remembered and autostream assigns it to a
   free input for you — see below.

### Which input your turntable lands on

When pairing succeeds, autostream wires the Bluetooth source up to an input by
itself, so in the usual case there is nothing more to do. It never switches off or
takes over an input you are already using:

* If **Input 1 is switched off**, the turntable is assigned to Input 1, and Input 1
  is switched on.
* If **Input 1 is already in use by a wired device** and **Input 2 is free**, the
  turntable is assigned to Input 2, and Input 2 is switched on.
* If **either input is already set to Bluetooth**, nothing changes — it is already
  wired up.
* If **both inputs are in use by wired devices**, nothing is changed automatically
  and the pairing window tells you: *"Bluetooth paired — assign the Bluetooth input
  on the Setup page."* Decide which input you want to give over to Bluetooth and
  change it yourself.

The pairing window tells you which input was used, and the Setup page's input
controls update straight away — there is no need to reload the page.

If your Bluetooth source is a record player, tick the **Turntable** toggle on
whichever input it landed on — it tunes the silence detection correctly. autostream
doesn't guess this for you, so it's worth doing right after pairing.

Only one Bluetooth device can be paired at a time. If you pair a different one later,
it replaces the previous one.

## Bluetooth Audio Buffer

The Bluetooth card includes a **Bluetooth Audio Buffer** slider. This controls how
much audio autostream holds in reserve before playing it:

* A **bigger** buffer rides out small wireless glitches more smoothly, at the cost of
  a slightly longer delay before you hear the needle drop.
* A **smaller** buffer reacts faster, but is more likely to stumble if the wireless
  connection briefly hiccups.

The default works well for most setups — only adjust it if you're hearing dropouts
(try a bigger buffer) or the start-up delay bothers you (try a smaller one).

While audio is streaming, the Bluetooth card also shows the negotiated audio
format — for example "Connected - SBC 44.1 kHz" — so you can see exactly what
the turntable is sending.

## Everyday use

Once paired, there's nothing to do beyond normal use:

* Switch the turntable on — it reconnects to autostream by itself.
* Drop the needle — the stream starts automatically, just like a wired input.
* Switch the turntable off — this is treated the same as lifting the needle: the
  stream stops.

## Turning it off

The Bluetooth card's **Disable** button stops the feature. If Bluetooth audio is
playing at the time, it stops immediately. Your paired device isn't forgotten — it's
remembered, so re-enabling later picks up right where you left off without pairing
again.

## Troubleshooting

**The card shows "No adapter found."**
Plug in a USB Bluetooth adapter — it's picked up automatically, no restart needed. If
you'd rather use the Pi's built-in radio instead, turn on **"Use onboard bluetooth
device"** on the Bluetooth card (this restarts the appliance).

**Turntable doesn't show up during scanning.**
Make sure it's actually in pairing mode — many turntables only stay in this mode for
a short window (often around a minute) before giving up, so you may need to start the
scan and then immediately trigger pairing mode. Keep the turntable close to the Pi
while pairing; a wall or a lot of distance can prevent it from showing up.

**Turntable doesn't reconnect after being paired before.**
Power-cycle the turntable (off and back on). Check the Bluetooth card on the Setup
page to see whether autostream currently sees it as connected. If it still won't
reconnect, try forgetting it from the card and pairing again.

**Audio is choppy or cuts out.**
This is almost always distance or interference — move the turntable and the Pi
closer together, and keep other Wi-Fi/Bluetooth-heavy devices out of the space
between them. If you're using the Pi's built-in Bluetooth radio (rather than a USB
adapter), it shares an antenna with Wi-Fi, which can cause exactly this kind of
choppiness — switching to a USB adapter usually resolves it. Trying a bigger
**Bluetooth Audio Buffer** can also help ride out brief glitches.
