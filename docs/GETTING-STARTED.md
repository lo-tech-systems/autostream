# Getting Started

## Installation

Run the installer on a Raspberry Pi running **Raspberry Pi OS Lite (Trixie, 32-bit)**. Both the autostream host and dial are tested on 32-bit Trixie; 64-bit is untested.

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

---

## Network Access

Autostream is accessed over **HTTP** at `http://<hostname>.local/` (for example, `http://autostream.local/`). **HTTPS is not supported.** Publicly trusted certificates are not available for `.local` hostnames; private HTTPS would require installing and trusting a local certificate authority on every phone or computer, which conflicts with autostream's zero-configuration setup and recovery design. Do not use `https://`.

The installer and updater download releases and packages over HTTPS from GitHub — this is separate from the local Web UI transport.

---

## Initial Setup

After installation, **autostream** only requires a short, one-time setup using an iPhone or iPad.

1. Connect your audio sources (turntable, CD player, etc.) and reboot the Pi.

2. Using **Safari** on your iPhone or iPad, navigate to:

   ```
   http://autostream.local/
   ```

   Replace `autostream` with your Pi's hostname if you changed it during setup.

3. The system will prompt for your PIN and will then guide you through two simple setup pages.

---

### Setup Page 1 — Speaker Selection

On the first setup page, all available **AirPlay / AirPlay 2** speakers on your network should appear.

* Deselect any speakers you do not want to be available in this autostream appliance.
* Tap **Continue** when finished.

If your speakers do not appear:

* Ensure they are powered on
* Tap **Refresh** to rescan the network

![Setup Page 1 – Speaker Selection](setup-page-1.png)

---

### Setup Page 2 — Input & Defaults

On the second setup page:

1. Choose your connected **input device** from the list.
2. If you have a second input connected, enable it and select that device as well.

![Setup Page 2 – Input Selection](setup-page-2.png)

Next, choose:

* **Default speakers**
* **Default volume level**

When the system has been idle for some time, these default speakers will automatically start playing when music is detected. Any other previously selected speakers will be muted.

Tap **Done** to complete setup.
The system will then show the autostream **Home Screen**.

---

## Home Screen Web App Mode

autostream is designed to be used from your device's home screen for an easy, app-like experience.

### Add autostream to the Home Screen

1. Open autostream in **Safari**
2. Tap the **Share** button at the bottom of the screen

![Safari Share Button](safari-share.png)

3. Swipe up and select **Add to Home Screen**

![Add to Home Screen](add-to-home-screen.png)
![IOS Add to Home Screen Prompt](add-to-home-screen-2.png)

Once added, autostream behaves like a regular app — providing quick access to volume controls and speaker selection without opening Safari manually.

---

## Maintenance Tracking

**autostream** tracks stylus, belt, and bearing wear for inputs configured as turntables.

### Finding the Service page

Open the autostream Web UI and tap **Service** in the navigation. The Service page is only shown when at least one input is configured as a turntable.

### What is tracked

| Item | Basis |
|------|-------|
| Stylus | Playback hours only |
| Belt | Playback hours, calendar time, or both |
| Bearing | Playback hours, calendar time, or both |

Set a dimension to **0 / Don't track** to disable tracking for that item.

### Life values and presets

The UI offers common presets for stylus and belt life, but you can type in any positive value. Custom values are accepted and saved normally.

### During playback

Counters are updated while playback is active, so the **Service** page reflects live values including the current session.

### Warning banners and indicators

When a component is approaching or has exceeded its set life, a banner appears at the top of the Home Screen and a dot indicator appears next to the **Service** navigation item.

### Resetting counters

After servicing, tap the relevant button — **Mark Stylus Replaced**, **Mark Belt Replaced**, or **Mark Bearing Oiled** — to reset that counter to zero and clear the warning.

---

## Update Channels

autostream supports two update channels:

- **stable** — only full GitHub releases. This is the default.
- **dev** — the most recently published GitHub release, including pre-releases (alpha, beta, RC). Use this to test upcoming versions.

### Enabling the pre-release channel

1. Open the autostream **Setup page** (`/setup`).
2. Scroll to the **Updates** card.
3. Toggle **Enable pre-release updates** on.
4. Tap **Save**.

Manual checks and automatic updates both use the selected channel. The toggle is visible whether automatic updates are enabled or not.

### Switching back to stable

Toggle **Enable pre-release updates** off and save. autostream will no longer check for or install pre-releases.

**Switching to stable does not automatically downgrade an installed pre-release.** If you are already running `v1.3.0-beta.2` and switch to stable, the next offered update will be a numerically newer stable release (e.g. `v1.3.0` or later). If you need to return to a known stable build immediately, use the console reinstall route described in the Troubleshooting guide.
