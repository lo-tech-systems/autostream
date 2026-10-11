# Setup: Inputs

autostream can take audio from up to two wired inputs (**Input 1** and **Input 2**) plus one **Bluetooth** source. All three are configured from the autostream **Setup page**, each as its own card that expands into a detail panel when tapped.

This page covers the Input 1 / Input 2 cards and the Bluetooth card, including pairing a Bluetooth turntable.

---

## Input 1 and Input 2

Open the Setup page and tap **Input 1** or **Input 2**. The panel is titled **Setup Input 1** (or **Setup Input 2**).

### Enable

A toggle labelled **Enable** turns the input on or off. The rest of the card (device selection, Input type, Sensitivity, Gain, Equaliser) is hidden until Enable is switched on.

Input 2 starts disabled. When either input is off, its collapsed row on the Setup page shows **Not configured** (Input 1) or **Disabled** (Input 2) instead of the usual device summary.

### Input device

The **Input device** dropdown lists the capture devices autostream can currently see, normally USB sound cards and USB phono-preamp boxes plugged into the Pi. Pick the one your turntable, CD player, or other source is connected to.

A few behaviours worth knowing:

* Until you choose a device, the dropdown shows a placeholder (**- select input device -**) rather than silently defaulting to the first device in the list.
* The same physical device can't be assigned to both inputs at once: whatever is already selected on the other input is left out of this dropdown.
* If a previously saved device is no longer detected (unplugged, or the Pi rebooted without it), it still shows in the list, marked **(not currently detected)**, so the setting isn't silently lost.
* Choosing **Bluetooth** from this list opens the Bluetooth pairing window if nothing is paired yet. See [Bluetooth](#bluetooth) below.

### Input type

The **Input type** dropdown offers **Turntable**, **CD** and **Line**. Pick the one that matches what is plugged in.

Analogue turntables will need a preamp - see [Turntable connects but the signal is too quiet](TROUBLESHOOTING.md#turntable-connects-but-the-signal-is-too-quiet).

Turntable tells autostream the source is a record player. It enables the [service tracking functions](SERVICE.md) and, when a record interrupts a repeat replay, autostream waits a little longer (about 1.25 seconds of music rather than a quarter of a second) before switching over to it. CD and Line behave the same way as each other here.

The type also decides a few things you can see:

* When autostream has no track title for what is playing, receivers and dials show the type name (**Turntable**, **CD** or **Line**) as the title. A Bluetooth source shows the type you chose, not "Bluetooth".
* While a track is untitled, the round dial (on its larger layouts) and the HD dial show the input's name where they used to show "Playing".
* The [Home page](HOME-PAGE.md) shows the matching icon and label, with a separate CD icon for a CD input.
* A CD input starts a session on the very first sound. Turntable and Line inputs need about a tenth of a second of sound above the sensitivity level, within one second, before a session starts, so a single click, pop or knock on a cable does not start playback. The sound doesn't have to be continuous. Once an input is playing, any sound above the level keeps it going.

If a Bluetooth source lands on this input (see below), choose the input type yourself. autostream doesn't detect it for a Bluetooth-paired device.

If you updated from an earlier release, an input that was set as a turntable shows as Turntable and every other input shows as Line. Nothing else changes until you change the type yourself. A CD player on an existing input is therefore treated as Line, with the click protection on, until you set it to CD.

Changing the type takes effect straight away and never interrupts playback. If autostream cannot reach its audio service at that moment, the page shows **Saved (could not apply live)** and the change takes effect once the audio service reconnects.

### Sensitivity

The **Sensitivity** slider sets the level an input has to reach before autostream counts it as playing. It runs from -70 dB to -30 dB in 1 dB steps, and its current value is shown beside the label. Further left picks up quieter audio; further right ignores more background noise.

Choosing Turntable moves the slider to -45 dB, and choosing CD or Line moves it to -60 dB, but only when the preset changes. Switching between Turntable and either of the others resets it; switching between CD and Line keeps a value you have set. Turntables pick up background noise, which is why their preset is higher.

Below the slider, the **Level** readout shows the input's current peak level in dB, refreshed about once a second while the card is open. It reads **no level** when there is nothing to show, and adds **(above threshold)** when the level is at or above the slider's value, meaning it would count as sound. The level is measured before Gain and Equaliser, so those settings don't move it. Changes to the slider are applied at once and never interrupt playback.

Under the Level readout, a **Sample rate** line shows the rate the input is running at, for example **Sample rate: 48 kHz**, and it updates as you watch. It reads **checking** for a moment while autostream works the rate out, and **not running** when the input is not running. If autostream has moved to a different rate than the one the device was opened at, it adds that in brackets, for example **Sample rate: 44.1 kHz (device opened at 48 kHz)**. While Dynamic Rate Matching is off and the source is sending a different rate, it reads, for example, **Sample rate: 48 kHz (source is sending 44.1 kHz)**.

If a very quiet passage after a long silence doesn't restart playback on a Turntable or Line input, it may need to get a little louder first. Move the Sensitivity slider to the left.

The **Silence detection** timeout itself (how long the input has to stay quiet before autostream stops the stream) is a shared setting across both inputs, covered in [SETUP-PLAYBACK.md](SETUP-PLAYBACK.md).

### Dynamic Rate Matching

Some optical (S/PDIF) USB adapters send audio at the sample rate of whatever is plugged into them, whatever rate autostream asked for. A CD player sends 44.1 kHz and a DVD player sends 48 kHz. When the two don't agree, the music plays at the wrong speed and pitch. A CD heard through an adapter that autostream opened at 48 kHz plays about 8 percent slow, and sounds low.

The **Dynamic Rate Matching** switch fixes that. It is the last item on each input's card, under the **Level** readout, and it is off by default. With it on, autostream finds out what rate the source is really sending, within about half a second of the audio arriving, and follows it. If the source changes rate later, for example when you swap a CD for a DVD, autostream follows that too.

You will usually find out you need it from the [Home page](HOME-PAGE.md). While an input is delivering a different rate than autostream expects and the switch is off, a banner reads **Sample Rate Mismatch: Please enable Dynamic Rate Matching**. Tap it to open that input's card on this page. The note under the switch then says which rate is arriving, for example "This input is delivering 44.1 kHz but the device was opened at 48 kHz." Turn the switch on, and the banner goes away once autostream has settled on the new rate.

A few things worth knowing:

* Changing the switch takes effect straight away and never interrupts playback. If autostream cannot reach its audio service at that moment, the page shows **Saved (could not apply live)** and the change takes effect once the audio service reconnects.
* For roughly the first half second after a source changes rate, the music still plays at the old rate before autostream corrects it. You may hear a brief off-pitch start. That short stretch is also kept in recordings made for repeat playback.
* autostream remembers the rate it found while the same input device stays selected, including when the input stops and starts again, so after the first time the music should start at the right pitch. It forgets the rate if you change the device or the audio service restarts.
* It recognises sources at 32, 44.1 and 48 kHz. A source at any other rate is not corrected, and if you have **Display Input Detail** on, the input's card on the Home page shows **Acquiring** for as long as it does.
* If you connect a CD player through an optical adapter, also set the input's **Input type** to CD. See [Input type](#input-type).

[Owner: this has not been tried on real adapters yet, so the page does not name any. Add a line about USB sound cards and Bluetooth sources not needing the switch only if you want one.]

### Gain and Equaliser

Once an input is enabled, a second card appears underneath it with:

* **Gain**: a slider from -10 dB to +10 dB, adjusting this input's level before it reaches the shared output stage.
* **Equaliser**: three bands, **40Hz**, **Bass**, and **Treble**, each adjustable from -10 dB to +10 dB.

These apply to this input only (as opposed to the output equaliser, which affects everything downstream regardless of source). For guidance on setting gain and EQ without causing clipping, see [Equaliser](EQUALISER.md).

### Collapsed row summary

When an input is enabled, its Setup page row shows a short summary such as:

> USB Audio CODEC · Turntable · +2 dB

> USB Audio CODEC · CD · 0 dB

For a Bluetooth-assigned input, the device name and input type are replaced by the Bluetooth connection state, for example:

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

If your Bluetooth source is a record player, set the **Input type** to Turntable on whichever input it landed on. autostream doesn't set this for you.

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
