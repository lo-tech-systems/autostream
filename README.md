![autostream demo](docs/autostream-vinyl-airplay-demo.gif)

# autostream

**Stream turntables and CD players to AirPlay speakers — automatically.**

**autostream** connects classic Hi-Fi gear to wireless multi-room speakers, making vinyl records and CDs play through AirPlay and AirPlay 2 speakers anywhere in your home. No apps to install. No complex configuration. Just press play.

One-line install on **Raspberry Pi OS Lite (Trixie)**:
```sh
curl -fsSL https://raw.githubusercontent.com/lo-tech-systems/autostream/main/bootstrap.sh | sudo bash
```

One-line install on **Raspberry Pi OS Lite (Trixie)** for the companion **autostream dial**:
```sh
curl -fsSL https://raw.githubusercontent.com/lo-tech-systems/autostream/main/dial_bootstrap.sh | sudo bash
```

See [GETTING-STARTED.md](docs/GETTING-STARTED.md) for full setup instructions and install options.

---

## Features

* Streams vinyl, CDs, tape decks, and other line-level sources to AirPlay speakers
* Detects audio automatically - starts and stops the stream without any interaction
* Supports HomePods and Stereo Paired HomePods, as well as third-party AirPlay and AirPlay 2 compatible speakers
* iPhone-friendly web app for volume control and speaker selection, with PIN-protected setup
* Runs entirely on your local network - no cloud services, no online accounts, no subscriptions
* Switches between two connected sources automatically (e.g. turntable and CD player)
* 6-band output equaliser and per-input 3-band equaliser
* Stylus, belt, and bearing maintenance tracking for turntable inputs
* Optional track identification — shows artist, title, album, and artwork on the Home screen; reacts to likely track changes automatically (powered by Shazam via the vibra-mini daemon; no API key required)
* Repeat — loop the last ~74 minutes of buffered audio (in-RAM) back to your speakers when the source stops
* Control multiple autostream appliances from a single iOS Home Screen application
* About > System Info page shows build versions, service health, CPU temperature, and storage status

---

## Perfect For

* Turntables
* CD Players
* Tape decks and other line-level music sources

---

## How It Works

**autostream** listens on one or two audio inputs. When sound is detected, it streams automatically to your AirPlay speakers. When the music stops, the stream stops. If you switch from vinyl to CD, **autostream** switches too.

Everything runs locally on your network — no cloud services, no online accounts, no recommendations.

---

## Network Access

Autostream is accessed over **HTTP** at `http://<hostname>.local/` (for example, `http://autostream.local/`). **HTTPS is not supported.** Publicly trusted certificates are not available for `.local` hostnames; private HTTPS would require installing and trusting a local certificate authority on every phone or computer, which conflicts with autostream's zero-configuration setup and recovery design. Do not use `https://`.

> Note: the installer and updater download releases and packages over HTTPS from GitHub — this is separate from the local Web UI transport.

---

## Platform & Requirements

* **Raspberry Pi** — Pi Zero 2W minimum for autostream; Zero W minimum for dial. 8GB+ microSD card.
* **OS** — **Raspberry Pi OS Lite (Trixie)**. Use 64-bit for autostream, unless deploying on Pi Zero W.
* **USB audio input**, for example:
  * USB turntable (e.g. Audio-Technica AT-LP60XUSBGM)
  * USB ADC for line-level or phono input (e.g. Behringer U-PHONE UFO202)
  * Optical audio adapter for CD players (e.g. Cubilux USB C Optical Audio Capture Adapter)
* **AirPlay or AirPlay 2 speakers** on the same network

Power consumption on a Pi Zero W or Zero 2W: under 2 Watts.

**autostream** automatically installs OwnTone for speaker discovery and streaming.

---

## Getting Started (autostream)

1. Flash **Raspberry Pi OS Lite (Trixie)** using Raspberry Pi Imager, boot, and SSH in.
2. Run the one-line installer above.
3. Connect one or two audio sources.
4. Reboot, then open Safari on iPhone and browse to `http://autostream.local/` (replace `autostream` with your Pi's hostname if you changed it).
5. Complete the one-time setup — it takes two screens.

From there, just drop the needle or press play. **autostream** will do the rest.

See [GETTING-STARTED.md](docs/GETTING-STARTED.md) for detailed setup instructions.

---

## Getting Started (dial)

1. Install autostream on another Raspberry Pi (sharing one Pi for autostream and dial is not supported)
2. Flash **Raspberry Pi OS Lite (Trixie)** using Raspberry Pi Imager, boot, and SSH in.
3. Run the dial one-line installer above.
4. Reboot, then continue setup from the autostream web app (Setup → Dials)

See [SETUP.md](docs/dial/SETUP.md) for detailed setup instructions and [BUILD-GUIDE.md](docs/dial/BUILD-GUIDE.md) for hardware build instructions.

---

## Developer Documentation

* [Adding a playback backend](docs/ADDING-AUDIO-BACKEND.md)
* [Adding a track-identification provider](docs/ADDING-TRACK-ID-PROVIDER.md)

---

## License

**autostream** is **source-available** and free for **personal, non-commercial use**.

See the `LICENSE` file for full terms.

---

**autostream** is Copyright (c) 2025–2026, **Lo-tech Systems Limited**. All rights reserved.
