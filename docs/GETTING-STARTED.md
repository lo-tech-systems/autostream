# Getting Started

## Installation

Run the installer on a Raspberry Pi running **Raspberry Pi OS Lite (Trixie)**. Use 64-bit for autostream, unless deploying on a Pi Zero W (32-bit only).

```sh
curl -fsSL https://raw.githubusercontent.com/lo-tech-systems/autostream/main/bootstrap.sh | sudo bash
```

This downloads the latest stable release and installs everything autostream needs, including OwnTone for speaker discovery and streaming.

### OwnTone Install Options

By default, the installer builds **owntone-mini** from source. This is a lightweight build maintained by Lo-tech Systems, optimised for the Pi Zero and low-power devices.

If you prefer to use the standard packaged OwnTone build instead, pass `--owntone=full`:

```sh
curl -fsSL https://raw.githubusercontent.com/lo-tech-systems/autostream/main/bootstrap.sh | sudo bash -s -- --owntone=full
```

The default `owntone-mini` build supports AirPlay and Chromecast. Use `--owntone=full` if you need support for other protocols.

During installation you are also asked to set a PIN for the appliance. See [What the PIN does](#what-the-pin-does) below.

---

## Wi-Fi and USB Adapters

### Connecting to Wi-Fi

During first install, autostream opens a setup hotspot named **autostream_XXXX** (where XXXX is the last four hex digits of the built-in adapter's MAC address). Connect to it from your phone or laptop, then open `http://autostream.local/` and follow the on-screen steps to select your Wi-Fi network and enter the password.

The setup hotspot uses the **built-in** Wi-Fi radio and is always available as a recovery path, even if a USB adapter is in use.

### USB Wi-Fi adapters

autostream automatically uses a USB Wi-Fi adapter when one is detected:

- The setup hotspot page combines networks visible to both the built-in and USB adapters into a single, deduplicated list. A network appears once even if seen by both radios.
- If a network is only visible through the USB adapter, a notice explains that removing the adapter would return autostream to hotspot mode.
- On boot, autostream prefers a USB adapter over the built-in when one is found. No configuration is needed.
- While a healthy built-in connection is active and playback is idle, autostream will automatically move to a newly inserted USB adapter after two stable detection passes.
- The built-in adapter always remains the recovery hotspot. A USB adapter is never used for hotspot mode.

**Adapter shown in the System pane:** go to [Setup -> System](SETUP-SYSTEM.md) to see which Wi-Fi adapter is currently active and to change the Wi-Fi network.

### Changing the Wi-Fi network

1. Go to **Setup -> System -> Network -> Change Wi-Fi Network**.
2. The setup hotspot opens for up to 30 minutes.
3. Connect to the hotspot SSID and select the new network. For the first **15 minutes** autostream leaves the hotspot up and will not rejoin your old network, so you have time to connect and choose the new one, even if the old network is still in range.
4. If setup is not completed within 30 minutes, autostream reconnects to the previous network automatically.

---

## Network Access

Autostream is accessed over **HTTP** at `http://<hostname>.local/` (for example, `http://autostream.local/`). **HTTPS is not supported.** Publicly trusted certificates are not available for `.local` hostnames, and private HTTPS would require installing and trusting a local certificate authority on every phone or computer, which conflicts with autostream's zero-configuration setup and recovery design. Do not use `https://`.

The installer and updater download releases and packages over HTTPS from GitHub. This is separate from the local Web UI transport.

---

## Initial Setup

After installation, **autostream** only requires a short, one-time setup using an iPhone or iPad.

1. Connect your audio sources (turntable, CD player, etc.) and reboot the Pi.

   Inputs are optional at this stage. If nothing is connected yet, you can still
   complete setup and add an input later. See [Setup Page 2](#setup-page-2---input--defaults) below.

2. Using **Safari** on your iPhone or iPad, navigate to:

   ```
   http://autostream.local/
   ```

   Replace `autostream` with your Pi's hostname if you changed it during setup.

3. If a PIN was set during installation, the system prompts for it before showing the setup pages. See [What the PIN does](#what-the-pin-does) below.

### What the PIN does

The PIN gates the Setup pages and this two-page setup wizard. The Home page, Equaliser, Service, About and Logs pages stay open to view without a PIN; the PIN only protects configuration.

During installation you are asked to set a PIN (4-20 characters: letters, numbers and hyphens). Pressing Enter without typing one skips it, and Setup is then open to anyone on your network with no login at all. You can also set the PIN non-interactively with `--unattended PIN=1234`.

The PIN is written in plain text to the SD card's boot partition (`pin.txt`), so it can be read directly from another computer if you forget it. You can change it later from **Setup -> System** using the **Change PIN** button.

---

### Setup Page 1 - Speaker Selection

On the first setup page, choose the **Default Output**, the AirPlay / AirPlay 2 speaker that autostream should stream to.

* Pick a speaker from the dropdown list.
* If your speaker does not appear, make sure it is powered on and tap **Refresh** to rescan the network.
* Tap **Continue** when finished. If nothing is selected you are asked to choose a speaker before continuing.

You are not choosing every speaker that will ever be usable here, just the one autostream defaults to. Other speakers can be made available and selected later from the [Home page](HOME-PAGE.md).

---

### Setup Page 2 - Input & Defaults

On the second setup page:

1. Choose your connected **input device** for **Input 1** from the list.
2. Tick **Turntable** if that input is a record player (a phono pre-amp is required).
3. Choose a **default volume level**.
4. Confirm or change the appliance's **hostname**.

Input 1 is optional. If you have no input connected yet, tap **Skip - configure
later** to finish setup without one. You can set Input 1 up from the Setup page at
any time, or pair a Bluetooth source, which assigns itself to a free input
automatically (see [Setup - Inputs](SETUP-INPUTS.md)).

While no input is enabled, the Home screen shows a **"No input device configured"**
notice above the Now Playing card. It disappears as soon as you enable an input.

**Input 2** is not part of first-time setup. If you have a second input, enable it
from the **Setup page** once setup is complete.

Your **default speaker** was chosen on Setup Page 1. If no speaker is selected when a new session starts, autostream automatically switches on that default speaker at your saved default volume. It does not override a speaker you already have selected.

Tap **Finish** to complete setup.
The system will then show the autostream **Home Screen**.

---

## Home Screen Web App Mode

autostream is designed to be used from your device's home screen for an easy, app-like experience. On iOS/Safari, autostream itself shows an in-app reminder banner (once a day, and never once you have already added it) prompting you to do this.

### Add autostream to the Home Screen

1. Open autostream in **Safari**
2. Tap the **Share** button at the bottom of the screen

![Safari Share Button](safari-share.png)

3. Swipe up and select **Add to Home Screen**

![Add to Home Screen](add-to-home-screen.png)
![IOS Add to Home Screen Prompt](add-to-home-screen-2.png)

Once added, autostream behaves like a regular app, providing quick access to volume controls and speaker selection without opening Safari manually.

---

## Next steps

* [Playing your first track](FIRST-TRACK.md) - connect a source and hear it play.
* [Home Page](HOME-PAGE.md) - volume, speaker selection and Now Playing.
* [Equaliser](EQUALISER.md) - EQ bands, output gain and trim.
* Setup pages: [Inputs](SETUP-INPUTS.md), [Playback](SETUP-PLAYBACK.md), [OwnTone](SETUP-OWNTONE.md) (including AirPlay 2 buffered/surround modes), [Track Identification](SETUP-TRACK-ID.md), [Dials](SETUP-DIALS.md), [Personalisation](SETUP-PERSONALISATION.md), [System](SETUP-SYSTEM.md) (Wi-Fi, hostname, SD card health), [Factory Reset](SETUP-FACTORY-RESET.md).
* [Service](SERVICE.md) - stylus, belt and bearing wear tracking for turntable inputs.
* [Multi-Appliance Control](MULTI-APPLIANCE.md) - view and control more than one autostream from a single Home Screen app.
* [System Maintenance](SYSTEM-MAINTENANCE.md) - update channels and keeping autostream current.
* [Troubleshooting](TROUBLESHOOTING.md) - if something is not working as expected.
