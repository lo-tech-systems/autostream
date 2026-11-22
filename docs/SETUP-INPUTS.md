# Setup: Inputs

autostream has up to three inputs. **Input 1** and **Input 2** are wired: each takes a USB sound card or phono-preamp box plugged into the Pi. **Input 3** is **Bluetooth**: it receives a source with its own Bluetooth transmitter, such as a turntable, and leaves both wired inputs free. Each input is configured from the autostream **Setup page**, as its own card that expands into a detail panel when tapped.

This page covers the three input cards, including pairing a Bluetooth turntable on Input 3.

---

## Input 1 and Input 2

Open the Setup page and tap **Input 1** or **Input 2**. The panel is titled **Setup Input 1** (or **Setup Input 2**). Most of what follows applies to Input 3 too; the parts that are different for Bluetooth are in [Input 3 (Bluetooth)](#input-3-bluetooth).

### Enable

A toggle labelled **Enable** turns the input on or off. The rest of the card (device selection, Input type, Sensitivity, Start after, Gain, Equaliser) is hidden until Enable is switched on.

Input 2 and Input 3 start disabled. When an input is off, its collapsed row on the Setup page shows **Not configured** (Input 1) or **Disabled** (Input 2 and Input 3) instead of the usual device summary.

### Input device

The **Input device** dropdown lists the capture devices autostream can currently see, normally USB sound cards and USB phono-preamp boxes plugged into the Pi. Pick the one your turntable, CD player, or other source is connected to.

A few behaviours worth knowing:

* Until you choose a device, the dropdown shows a placeholder (**- select input device -**) rather than silently defaulting to the first device in the list.
* The same physical device can't be assigned to both inputs at once: whatever is already selected on the other input is left out of this dropdown.
* If a previously saved device is no longer detected (unplugged, or the Pi rebooted without it), it still shows in the list, marked **(not currently detected)**, so the setting isn't silently lost.
* Bluetooth isn't in this list. It has its own input, Input 3, with no device to choose.

### Input type

The **Input type** dropdown offers **Turntable**, **CD** and **Line**. Pick the one that matches what is plugged in.

Analogue turntables will need a preamp - see [Turntable connects but the signal is too quiet](TROUBLESHOOTING.md#turntable-connects-but-the-signal-is-too-quiet).

Turntable tells autostream the source is a record player. It enables the [service tracking functions](SERVICE.md) and, when a record interrupts a repeat replay, autostream waits a little longer (about 1.25 seconds of music rather than a quarter of a second) before switching over to it. CD and Line behave the same way as each other here.

The type also decides a few things you can see:

* When autostream has no track title for what is playing, receivers and dials show the type name (**Turntable**, **CD** or **Line**) as the title. A Bluetooth source shows the type you chose, not "Bluetooth".
* While a track is untitled, the round dial (on its larger layouts) and the HD dial show the input's name where they used to show "Playing".
* The [Home page](HOME-PAGE.md) shows the matching icon and label, with a separate CD icon for a CD input.
* A CD input starts a session on the very first sound. Turntable and Line inputs need a short amount of sound above the sensitivity level, within one second, before a session starts (60 milliseconds unless you change [Start after](#start-after)), so a single click, pop or knock on a cable does not start playback. The sound doesn't have to be continuous. Once an input is playing, any sound above the level keeps it going.

For a Bluetooth source on Input 3, choose the input type yourself. autostream doesn't detect it for a Bluetooth-paired device.

If you updated from an earlier release, an input that was set as a turntable shows as Turntable and every other input shows as Line. Nothing else changes until you change the type yourself. A CD player on an existing input is therefore treated as Line, with the click protection on, until you set it to CD.

Changing the type takes effect straight away and never interrupts playback. If autostream cannot reach its audio service at that moment, the page shows **Saved (could not apply live)** and the change takes effect once the audio service reconnects.

### Sensitivity

The **Sensitivity** slider sets the level an input has to reach before autostream counts it as playing. It runs from -70 dB to -30 dB in 1 dB steps, and its current value is shown beside the label. Further left picks up quieter audio; further right ignores more background noise.

Choosing Turntable moves the slider to -45 dB, and choosing CD or Line moves it to -60 dB, but only when the preset changes. Switching between Turntable and either of the others resets it; switching between CD and Line keeps a value you have set. Turntables pick up background noise, which is why their preset is higher.

Below the slider, the **Level** readout shows the input's current peak level in dB, refreshed about once a second while the card is open. It reads **no level** when there is nothing to show, and adds **(above threshold)** when the level is at or above the slider's value, meaning it would count as sound. The level is measured before Gain and Equaliser, so those settings don't move it. Changes to the slider are applied at once and never interrupt playback.

Under the Level readout and [Start after](#start-after), a **Sample rate** line shows the rate the input is running at, for example **Sample rate: 48 kHz**, and it updates as you watch. It reads **checking** for a moment while autostream works the rate out, and **not running** when the input is not running. If autostream has moved to a different rate than the one the device was opened at, it adds that in brackets, for example **Sample rate: 44.1 kHz (device opened at 48 kHz)**. While Dynamic Rate Matching is off and the source is sending a different rate, it reads, for example, **Sample rate: 48 kHz (source is sending 44.1 kHz)**.

If a very quiet passage after a long silence doesn't restart playback on a Turntable or Line input, it may need to get a little louder first. Move the Sensitivity slider to the left.

The **Silence detection** timeout itself (how long the input has to stay quiet before autostream stops the stream) is a shared setting across all inputs, covered in [SETUP-PLAYBACK.md](SETUP-PLAYBACK.md).

### Start after

**Start after** sets how much sound above the Sensitivity level a Turntable or Line input needs, within one second, before playback starts. It sits under the Level readout, with the time in the middle, **-100** and **-10** on the left, **+10** and **+100** on the right, and **Reset** beside its label. It runs from 30 to 250 milliseconds and starts at 60. Reset puts it back to 60.

A longer time ignores more clicks, pops and knocks, for example a spike from mains interference that keeps starting your speakers. A shorter time cuts less from the start of a record. The sound doesn't have to be continuous, so a quiet opening whose peaks come and go still starts. autostream measures sound in steps of about 21 milliseconds, so the time it actually waits is rounded up to the next step.

A step that would go past either end stops at the end, so **+100** at 200 gives 250. A button is greyed out only when the time is already at that end. Each input has its own value.

It isn't shown for a CD input, which starts on its very first sound.

Changing it takes effect straight away and never interrupts playback. If autostream cannot reach its audio service at that moment, the page shows **Saved (could not apply live)** and the change takes effect once the audio service reconnects.

To see what is starting playback, set **Log Level** to Debug on the **Logs** page (from **About**), wait for it to happen, then download the log bundle (see [Getting logs](TROUBLESHOOTING.md#getting-logs)) and look in `autostream_monitor.log`. Set the level back afterwards. Each start gets a line such as `[input1] Became active: -32.0 dB peak, -41.3 dB mean power, above -30.0 dB for 64 ms in 3 blocks within 430 ms (start after 60 ms)`, and a burst of sound that wasn't enough gets a **No start** line in the same form.

### Dynamic Rate Matching

Some optical (S/PDIF) USB adapters send audio at the sample rate of whatever is plugged into them, whatever rate autostream asked for. A CD player sends 44.1 kHz and a DVD player sends 48 kHz. When the two don't agree, the music plays at the wrong speed and pitch. A CD heard through an adapter that autostream opened at 48 kHz plays about 8 percent slow, and sounds low.

The **Dynamic Rate Matching** switch fixes that. It is the last item on each input's card, under the **Level** readout, and it is on by default. An appliance updated from an earlier release has it on too, unless you turned the switch off yourself. With it on, autostream finds out what rate the source is really sending, within about half a second of the audio arriving, and follows it. If the source changes rate later, for example when you swap a CD for a DVD, autostream follows that too.

You will usually find out you need it from the [Home page](HOME-PAGE.md). While an input is delivering a different rate than autostream expects and the switch is off, a banner reads **Sample Rate Mismatch: Please enable Dynamic Rate Matching**. Tap it to open that input's card on this page. The note under the switch then says which rate is arriving, for example "This input is delivering 44.1 kHz but the device was opened at 48 kHz." Turn the switch on, and the banner goes away once autostream has settled on the new rate.

A few things worth knowing:

* Changing the switch takes effect straight away and never interrupts playback. If autostream cannot reach its audio service at that moment, the page shows **Saved (could not apply live)** and the change takes effect once the audio service reconnects.
* For roughly the first half second after a source changes rate, the music still plays at the old rate before autostream corrects it. You may hear a brief off-pitch start. That short stretch is also kept in recordings made for repeat playback.
* autostream remembers the rate it found while the same input device stays selected, including when the input stops and starts again, so after the first time the music should start at the right pitch. It forgets the rate if you change the device or the audio service restarts.
* It recognises sources at 32, 44.1 and 48 kHz. A source at any other rate is not corrected, and if you have **Display input detail** on, the input's card on the Home page shows **Acquiring** for as long as it does.
* If you connect a CD player through an optical adapter, also set the input's **Input type** to CD. See [Input type](#input-type).

### Gain and Equaliser

Once an input is enabled, a second card appears underneath it with:

* **Gain**: a slider from -10 dB to +10 dB, adjusting this input's level before it reaches the shared output stage.
* **Equaliser**: three bands, **40Hz**, **Bass**, and **Treble**, each adjustable from -10 dB to +10 dB.

These apply to this input only (as opposed to the output equaliser, which affects everything downstream regardless of source). For guidance on setting gain and EQ without causing clipping, see [Equaliser](EQUALISER.md).

### Collapsed row summary

When an input is enabled, its Setup page row shows a short summary such as:

> USB Audio CODEC · Turntable · +2 dB

> USB Audio CODEC · CD · 0 dB

For Input 3, the device name is replaced by the Bluetooth device's name, or **Not Connected** while nothing is connected, for example:

> My Turntable · Turntable · 0 dB

---

## Input 3 (Bluetooth)

Some turntables (and other sources) have a built-in Bluetooth transmitter. If yours does, autostream can receive audio from it directly on Input 3, no USB adapter needed, and both wired inputs stay free for other sources. Bluetooth audio is handled exactly like a wired input: drop the needle, the stream starts; stop the record, it stops.

Open the Setup page and tap **Input 3 (Bluetooth)**. The panel is titled **Setup Input 3**. Input 3 is on every appliance with Bluetooth built in; a developer or partial install without it has no Input 3 card.

### What this is, and isn't

Bluetooth input is a **convenience option**, not an upgrade over a wired connection. Normally autostream receives audio through a USB adapter (such as the Behringer U-PHONE UFO202) wired to your turntable or CD player. With Bluetooth input, a source with its own wireless transmitter can send audio straight to the Pi instead, one less cable, no USB box to find a home for.

Audio quality may be better using a dedicated USB input, since Bluetooth compresses the audio inside the transmitting device before it reaches autostream. For most listening the difference is minor.

### Turning it on

Bluetooth input is built into every autostream appliance. There's nothing to install and nothing to reboot for, just to switch on.

1. Open the Setup page and tap **Input 3 (Bluetooth)**.
2. Turn on **Enable**. The card says what it is for: *"Connect a Bluetooth device (such as a turntable with Bluetooth output) as an audio input."*
3. autostream asks you to confirm. Tap **Enable**.

The switch is the whole of Bluetooth: turning it on starts Bluetooth on the appliance and starts Input 3. A message stays up while Bluetooth starts, which can take up to 30 seconds, and the page reloads once that's done. The card then shows an **Adapter** row, the pairing controls described below, and the same **Input type**, **Sensitivity**, **Start after**, **Dynamic Rate Matching**, **Gain** and **Equaliser** settings as a wired input. If Bluetooth can't be started, the message says so and the switch stays off.

Bluetooth uses about 40 MB of memory while it is on. On a board with 512 MB of memory, such as a Pi Zero 2 W, the card and the confirmation both say so, and that the replay buffer may hold less. Turning Bluetooth off asks first too, as any Bluetooth stream stops straight away.

Turning Bluetooth on or off restarts the inputs and sizes the replay buffer again for the memory now free. Any replay playing stops and the replay buffer is cleared. The confirmation says so before you go ahead, with how much music the buffer is holding.

While Input 3 is off, Bluetooth isn't running at all and nothing is listening for it.

### Adapters: plug in a dongle

A **USB Bluetooth adapter is strongly recommended**. Plug one in and the Adapter row picks it up automatically, no setup or reboot needed.

Every Pi model this feature runs on also has a **built-in Bluetooth radio**, but it's switched off by default (it shares an antenna with Wi-Fi, and running both at once can make either less reliable). To use the built-in radio instead of a dongle, turn on **Use onboard bluetooth device** on the Input 3 card. This edits the boot configuration and **restarts the appliance** to take effect.

If both a USB adapter and the onboard radio are available at the same time, autostream always uses the USB adapter.

On an appliance with a power board, the built-in radio can't be used at all: the board takes over the connection the radio normally uses, and Bluetooth audio through what's left breaks up too badly to listen to. The **Use onboard bluetooth device** switch is greyed out there, with a note saying so. Plug in a USB adapter instead.

On a Pi Zero 2 W without a power board the built-in radio works, but Wi-Fi and Bluetooth share one antenna, so Bluetooth audio can break up while autostream is streaming to your speakers over Wi-Fi. A USB adapter avoids that.

### Pairing a turntable or other source

On the Input 3 card, tap **Pair a device…**. The **Pair a device** screen opens: *"Put your device in pairing mode. It will appear below when autostream finds it or when it tries to connect."*

Bluetooth sources pair in one of two ways, and this one screen handles both. Some wait to be found, so autostream searches for them. Others, often the simplest players with no pairing menu at all, go looking for a speaker themselves and try to connect to it. While the screen is open autostream does both at once: it searches, and it lets itself be found under the appliance's name.

1. Put your source into pairing mode (check its manual, this is usually a button press or switch, often with a flashing light). For a player that searches by itself, this may just mean switching it on with a CD playing and nothing plugged into its headphone socket.
2. Wait for it to appear in the list. A device autostream found shows as **Found**. A device trying to connect shows as **Wants to connect**. A phone also shows a six-digit code, which should match the one on its own screen.
3. Tap your device in the list, then tap **Pair this device**. The entry shows **Pairing…**, then the screen tells you the result.

Nothing is paired until you tap it. A device that tries to connect is held in the list without playing anything until you choose it, and anything you don't choose is removed when the screen closes. If you already have a paired device, it keeps playing until you pair the new one, which then replaces it.

The screen only accepts devices while it's open and visible, and for at most five minutes. If you switch to another tab, lock your phone or close the screen, pairing stops by itself shortly afterwards. Some players fail their first attempt and try again a minute or two later, so leave the screen open while you wait.

### Input type and the other settings

A paired device plays on Input 3; pairing doesn't change any other input. If your Bluetooth source is a record player, set Input 3's **Input type** to Turntable, which also turns on [service tracking](SERVICE.md) for it. A CD player uses **CD**, and a tape deck or cassette player uses **Line**. autostream doesn't set this for you. Sensitivity, Start after, Dynamic Rate Matching, Gain and Equaliser work exactly as they do on Input 1 and Input 2.

Only one Bluetooth device can be paired at a time. Pairing a different one later forgets the previous device and replaces it.

### After the update: Bluetooth moved to Input 3

Before this release, Bluetooth borrowed Input 1 or Input 2. If yours did, the update moves it to Input 3 for you and frees the input it was on:

* Input 3 is enabled if Bluetooth was on, and keeps everything that input had for the Bluetooth source: its input type, sensitivity, Start after, Dynamic Rate Matching, gain, equaliser, and its playing hours and service counters.
* The input it was on is switched off, with no device chosen and its settings back to their defaults, ready for a wired device.
* Your paired device stays paired, so it plays on Input 3 as it did before.

Both cards say so (*"Bluetooth was moved here from Input 2 by the update."* on Input 3, and *"Bluetooth was moved to Input 3 by the update."* on the input it left) until you next change either of them.

### Bluetooth Audio Buffer

The Input 3 card includes a **Bluetooth Audio Buffer** slider, below Gain and Equaliser, adjustable from 100 ms to 500 ms (default 200 ms):

* Larger values ride out wireless glitches more smoothly, at the cost of a slightly longer delay before you hear the needle drop.
* Smaller values reduce that delay, but are more likely to stumble if the wireless connection briefly hiccups.

The default works well for most setups. Only change it if you're hearing dropouts (try larger) or the start-up delay bothers you (try smaller).

While a device is connected, the Input 3 card also shows the negotiated audio format next to the device name, for example:

> My Turntable · Connected - SBC 44.1 kHz

### Everyday use

Once paired, there's nothing else to do:

* Switch the turntable on, it reconnects to autostream by itself.
* Drop the needle, the stream starts automatically, just like a wired input.
* Switch the turntable off, this is treated the same as lifting the needle: the stream stops.

### Turning it off

Turn off **Enable** on the Input 3 card, and confirm. Bluetooth stops on the appliance, and if Bluetooth audio is playing, it stops immediately. Your paired device isn't forgotten, re-enabling later picks up where you left off without pairing again.

To remove the paired device itself (rather than just switching Bluetooth off), tap **Forget** on the Input 3 card.

### Troubleshooting

**Adapter row says no adapter was found.**
Plug in a USB Bluetooth adapter, it's picked up automatically, no restart needed. To use the Pi's built-in radio instead, turn on **Use onboard bluetooth device** (this restarts the appliance).

**Your device doesn't show up on the pairing screen.**
Make sure it's actually in pairing mode; many devices only stay in this mode for a short window (often around a minute), so open the pairing screen first and then put the device into pairing mode. Keep it close to the Pi while pairing; walls and distance can prevent it from appearing.

**Your device never sees autostream.**
autostream can only be found while the pairing screen is open, so open it first and keep it open. Some players fail their first attempt and try again on their own a minute or two later; leave the screen up until the device appears.

**Pairing stopped by itself.**
The screen has to stay open and visible for pairing to continue. Switching tabs, locking your phone or closing the screen stops it shortly afterwards, and it always stops after five minutes. Open it again to carry on.

**Your device says it's already paired but won't connect.**
It may still remember an old pairing that autostream no longer has. Open the pairing screen and let the device pair again from its side.

**Device doesn't reconnect after being paired before.**
autostream doesn't call a paired device; the device connects to autostream when it's switched on, so make sure it's on and within range. Power-cycle it. Check the paired-device row on the Input 3 card to see whether autostream currently sees it as connected. If it still won't reconnect, try **Forget** and pair again.

**Audio is choppy or cuts out.**
Usually distance or interference: move the source and the Pi closer together, and keep other Wi-Fi/Bluetooth-heavy devices out of the space between them. If you're using the Pi's built-in radio rather than a USB adapter, the shared Wi-Fi/Bluetooth antenna can cause exactly this; switching to a USB adapter usually resolves it. On an appliance with a power board the built-in radio isn't offered at all, for the same reason. A larger **Bluetooth Audio Buffer** can also help ride out brief glitches.

For general connectivity and access problems, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
