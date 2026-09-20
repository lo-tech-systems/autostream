# Getting Started

## Installation

Run the installer on a Raspberry Pi running **Raspberry Pi OS Lite (Trixie)**. Use 64-bit for autostream, unless deploying on a Pi Zero W (32-bit only).

```sh
curl -fsSL https://raw.githubusercontent.com/lo-tech-systems/autostream/main/bootstrap.sh | sudo bash
```

This downloads the latest stable release and installs everything autostream needs, including OwnTone for speaker discovery and streaming.

During installation you are asked to set a PIN for the appliance. See [What the PIN does](#what-the-pin-does) below.

For install options, such as running a full OwnTone build instead of the bundled one, see [Advanced Operations](ADVANCED.md).

---

## Wi-Fi

autostream uses the Wi-Fi settings you gave the Pi, normally set with Raspberry Pi Imager when you flashed the card. USB Wi-Fi adapters are supported and used automatically when one is present.

If you later change networks (a new router, for example), or you did not set Wi-Fi up with the Imager, autostream provides a setup hotspot on boot so you can point it at the new network. See [Connecting or changing Wi-Fi](TROUBLESHOOTING.md#connecting-or-changing-wi-fi) for how to use the hotspot and switch networks later.

---

## Network Access

Connect to autostream in your browser at `http://<hostname>.local/`, for example `http://autostream.local/`. Use `http`, not `https`.

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

The PIN prevents other people on your network from changing the appliance's settings. Viewing the Home page and the other screens never needs it; only Setup does. You set it during installation and can change it later from [Setup > System](SETUP-SYSTEM.md).

For more detail, including how to recover a forgotten PIN, see [Forgotten PIN](TROUBLESHOOTING.md#forgotten-pin) and [Authentication and PIN security](TROUBLESHOOTING.md#authentication-and-pin-security) in Troubleshooting.

---

### Setup Page 1 - Speaker Selection

Pick the **Default Output**, the AirPlay speaker autostream streams to by default, and tap **Continue**. You must select a speaker to continue, so at least one has to be detected on your network. If yours does not appear, make sure it is powered on and tap **Refresh**.

You can add and switch to other speakers later from the [Home page](HOME-PAGE.md).

---

### Setup Page 2 - Input & Defaults

On the second setup page:

1. Choose your connected **input device** for **Input 1** from the list.
2. Tick **Turntable** if that input is a record player.
3. Choose a **default volume level**.
4. Confirm or change the appliance's **hostname**.

Input 1 is optional. If you have no input connected yet, tap **Skip - configure
later** to finish setup without one. You can set Input 1 up from the Setup page at
any time, or pair a Bluetooth source (see [Setup - Inputs](SETUP-INPUTS.md)).

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
