# Setup: Inputs

autostream can take audio from up to two wired inputs (**Input 1** and **Input 2**) plus one **Bluetooth** source. All three are configured from the autostream **Setup page**, each as its own card that expands into a detail panel when tapped.

This page covers the Input 1 / Input 2 cards and the Bluetooth card, including pairing a Bluetooth turntable.

---

## Input 1 and Input 2

Open the Setup page and tap **Input 1** or **Input 2**. The panel is titled **Setup Input 1** (or **Setup Input 2**).

### Enable

A toggle labelled **Enable** turns the input on or off. The rest of the card (device selection, Turntable, Gain, Equaliser) is hidden until Enable is switched on.

Input 2 starts disabled. When either input is off, its collapsed row on the Setup page shows **Not configured** (Input 1) or **Disabled** (Input 2) instead of the usual device summary.

### Input device

The **Input device** dropdown lists the capture devices autostream can currently see, normally USB sound cards and USB phono-preamp boxes plugged into the Pi. Pick the one your turntable, CD player, or other source is connected to.

A few behaviours worth knowing:

* Until you choose a device, the dropdown shows a placeholder (**- select input device -**) rather than silently defaulting to the first device in the list.
* The same physical device can't be assigned to both inputs at once: whatever is already selected on the other input is left out of this dropdown.
* If a previously saved device is no longer detected (unplugged, or the Pi rebooted without it), it still shows in the list, marked **(not currently detected)**, so the setting isn't silently lost.
* Choosing **Bluetooth** from this list opens the Bluetooth pairing window if nothing is paired yet. See [Bluetooth](#bluetooth) below.

### Turntable

The **Turntable** toggle tells autostream the source is a record player rather than a line-level device like a CD player or tape deck.

Analogue turntables will need a preamp - see [Turntable connects but the signal is too quiet](TROUBLESHOOTING.md#turntable-connects-but-the-signal-is-too-quiet).

Turning Turntable on or off changes the input's silence-detection threshold preset shown just below the toggle, for example:

> Detection threshold preset: -45 dB

Turntables pick up background noise, and this setting raises the detection level to avoid false starts. It also enables the [service tracking functions](SERVICE.md). This preset is set automatically by the toggle; it isn't something you tune by hand here. The **Silence detection** timeout itself (how long that quiet has to last before autostream stops the stream) is a shared setting across both inputs, covered in [SETUP-PLAYBACK.md](SETUP-PLAYBACK.md).

If a Bluetooth source lands on this input (see below), turn Turntable on yourself if it's a record player. autostream doesn't detect this automatically for a Bluetooth-paired device.

### Gain and Equaliser

Once an input is enabled, a second card appears underneath it with:

* **Gain**: a slider from -10 dB to +10 dB, adjusting this input's level before it reaches the shared output stage.
* **Equaliser**: three bands, **40Hz**, **Bass**, and **Treble**, each adjustable from -10 dB to +10 dB.

These apply to this input only (as opposed to the output equaliser, which affects everything downstream regardless of source). For guidance on setting gain and EQ without causing clipping, see [Equaliser](EQUALISER.md).

### Collapsed row summary

When an input is enabled, its Setup page row shows a short summary such as:

> USB Audio CODEC · Turntable · +2 dB

For a Bluetooth-assigned input, the device name and turntable/line-in flag are replaced by the Bluetooth connection state, for example:

> Bluetooth · My Turntable · 0 dB

---

## Bluetooth

Some turntables (and other sources) have a built-in Bluetooth transmitter. If yours does, autostream can receive audio from it directly, no USB adapter needed. Bluetooth audio is handled exactly like a wired input once assigned: drop the needle, the stream starts; stop the record, it stops.

### What this is, and isn't

Bluetooth input is a **convenience option**, not an upgrade over a wired connection. Normally autostream receives audio through a USB adapter (such as the Behringer U-PHONE UFO202) wired to your turntable or CD player. With Bluetooth input, a source with its own wireless transmitter can send audio straight to the Pi instead, one less cable, no USB box to find a home for.

Audio quality may be better using a dedicated USB input, since Bluetooth compresses the audio inside the transmitting device before it reaches autostream. For most listening the difference is minor.

### Turning it on

Bluetooth input is built into every autostream appliance. There's nothing to install and nothing to reboot for, just to switch on.

1. Open the Setup page and tap the **Bluetooth** card.
2. If it isn't already on, you'll see: *"Connect a Bluetooth device (such as a turntable with Bluetooth output) as an audio input."*
3. Tap **Enable Bluetooth Services**.

The card then shows **Bluetooth services: Enabled**, an **Adapter** row, and the pairing controls described below.

### Adapters: plug in a dongle

A **USB Bluetooth adapter is strongly recommended**. Plug one in and the Adapter row picks it up automatically, no setup or reboot needed.

Every Pi model this feature runs on also has a **built-in Bluetooth radio**, but it's switched off by default (it shares an antenna with Wi-Fi, and running both at once can make either less reliable). To use the built-in radio instead of a dongle, turn on **Use onboard bluetooth device** on the Bluetooth card. This edits the boot configuration and **restarts the appliance** to take effect.

If both a USB adapter and the onboard radio are available at the same time, autostream always uses the USB adapter.

### Pairing a turntable or other source

Pairing can be started two ways:

1. From the Bluetooth card: tap **Pair new device…**.
2. From an input: choose **Bluetooth** from the **Input device** dropdown on Input 1 or Input 2.

Either way, a **Pair Bluetooth Turntable** window opens and starts scanning, showing: *"Put your turntable in pairing mode. Available devices:"*.

1. Put your source into pairing mode (check its manual, this is usually a button press or switch, often with a flashing light).
2. Your device should appear in the scan list within a few seconds. Tap it.
3. Confirm with **Pair with `<device name>`?**. If something is already paired, a warning notes it will be forgotten.
4. Tap **Pair**. The window shows **Pairing…**, then a result.

### Which input your turntable lands on

Once pairing succeeds, autostream assigns the Bluetooth source to an input for you. It never switches off or takes over an input you're already using with a wired device:

* If **Input 1 is disabled**, it is assigned to Input 1, and Input 1 is enabled.
* If **Input 1 already has a device set** and **Input 2 is free** (disabled, or has no device set), it is assigned to Input 2, and Input 2 is enabled.
* If **either input is already on Bluetooth**, nothing changes, it's already wired up.
* Otherwise (both inputs are occupied by wired devices), nothing is changed automatically, and the result message tells you: *"Bluetooth paired, assign the Bluetooth input on the Setup page."* Pick which input to hand over to Bluetooth and change its **Input device** yourself.

The result panel names whichever input was used, and the Setup page's input controls update immediately, no reload needed.

If your Bluetooth source is a record player, turn on the **Turntable** toggle on whichever input it landed on. autostream doesn't set this for you.

Only one Bluetooth device can be paired at a time. Pairing a different one later forgets the previous device and replaces it.

### Bluetooth Audio Buffer

The Bluetooth card includes a **Bluetooth Audio Buffer** slider, adjustable from 100 ms to 500 ms (default 200 ms):

* Larger values ride out wireless glitches more smoothly, at the cost of a slightly longer delay before you hear the needle drop.
* Smaller values reduce that delay, but are more likely to stumble if the wireless connection briefly hiccups.

The default works well for most setups. Only change it if you're hearing dropouts (try larger) or the start-up delay bothers you (try smaller).

While a device is connected, the Bluetooth card also shows the negotiated audio format next to the device name, for example:

> My Turntable · Connected - SBC 44.1 kHz

### Everyday use

Once paired, there's nothing else to do:

* Switch the turntable on, it reconnects to autostream by itself.
* Drop the needle, the stream starts automatically, just like a wired input.
* Switch the turntable off, this is treated the same as lifting the needle: the stream stops.

### Turning it off

The Bluetooth card's **Disable** button (next to **Bluetooth services: Enabled**) turns the feature off. If Bluetooth audio is playing, it stops immediately. Your paired device isn't forgotten, re-enabling later picks up where you left off without pairing again.

To remove the paired device itself (rather than just switching Bluetooth off), tap **Forget** on the Bluetooth card.

### Troubleshooting

**Adapter row says no adapter was found.**
Plug in a USB Bluetooth adapter, it's picked up automatically, no restart needed. To use the Pi's built-in radio instead, turn on **Use onboard bluetooth device** (this restarts the appliance).

**Your device doesn't show up while scanning.**
Make sure it's actually in pairing mode; many devices only stay in this mode for a short window (often around a minute), so start the scan and then immediately put the device into pairing mode. Keep it close to the Pi while pairing; walls and distance can prevent it from appearing.

**Device doesn't reconnect after being paired before.**
Power-cycle it. Check the Bluetooth card's paired-device row to see whether autostream currently sees it as connected. If it still won't reconnect, try **Forget** and pair again.

**Audio is choppy or cuts out.**
Usually distance or interference: move the source and the Pi closer together, and keep other Wi-Fi/Bluetooth-heavy devices out of the space between them. If you're using the Pi's built-in radio rather than a USB adapter, the shared Wi-Fi/Bluetooth antenna can cause exactly this; switching to a USB adapter usually resolves it. A larger **Bluetooth Audio Buffer** can also help ride out brief glitches.

For general connectivity and access problems, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
