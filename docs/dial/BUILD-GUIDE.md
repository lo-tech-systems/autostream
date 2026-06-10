# autostream dial — Build Guide

## Bill of Materials

| Qty | Component | Notes |
|-----|-----------|-------|
| 1 | Raspberry Pi Zero W | WiFi required; Zero 2W also supported |
| 1 | Rotary encoder with pushbutton | KY-040 or equivalent; EC11 series |
| 1 | UK single-gang back-box (35 mm deep) | Standard electrical back-box |
| 1 | Single-gang faceplate | Drilled/cut to expose encoder knob |
| 1 | Micro-USB power supply (5 V, 1 A min) | Slim profile preferred for in-wall fit |
| 1 | Micro-USB extension cable or adapter | To bring power out of the back-box |
| 4 | Dupont female-female jumper wires | For encoder→GPIO connection |
| — | Short M2.5 standoffs + screws | To mount Pi Zero inside back-box |

Optional:
| Qty | Component | Notes |
|-----|-----------|-------|
| 1 | Single LED (any colour, 3 mm) | Activity indicator (DR-6) |
| 1 | 330 Ω resistor | Current-limit resistor for LED |

---

## GPIO Wiring

Use BCM (Broadcom) pin numbering throughout.

| Encoder pin | Pi Zero GPIO (BCM) | Physical pin |
|-------------|-------------------|--------------|
| CLK (A)     | GPIO 17           | Pin 11       |
| DT (B)      | GPIO 27           | Pin 13       |
| SW (button) | GPIO 22 *(opt)*   | Pin 15       |
| +           | 3.3 V             | Pin 1        |
| GND         | GND               | Pin 6        |

| LED pin | Pi Zero GPIO (BCM) | Physical pin |
|---------|-------------------|--------------|
| Anode (+) via 330 Ω | GPIO 24 *(opt)* | Pin 18 |
| Cathode (−) | GND | Pin 20 |

Internal pull-ups are enabled by `gpiozero`/`lgpio` — no external resistors
needed on the encoder signal lines.

GPIO assignments can be changed in `/etc/autostream-dial/dial.json` after
install. The default values (CLK=17, DT=27) match the wiring above.

---

## Back-Box Assembly

1. Feed the power cable through the cable entry at the back of the box.
2. Mount the Pi Zero W on standoffs secured to the floor of the back-box.
3. Wire encoder to GPIO as above using Dupont jumpers. Keep leads short.
4. Drill the faceplate to accept the encoder shaft; secure the encoder nut.
5. Route the encoder leads inside the box so the faceplate closes cleanly.
6. Attach the faceplate; fit the encoder knob.

Ensure the box is not live (no mains cabling routed through it).
The Pi is powered only by low-voltage USB — no mains safety clearance required
for the Pi itself, but follow local electrical codes for in-wall installations.

---

## OS Preparation

1. Flash **Raspberry Pi OS Lite (Trixie, 32-bit)** to a microSD card using
   Raspberry Pi Imager. Use 32-bit for Pi Zero W (ARMv6); 32-bit also runs
   correctly on Zero 2W.
2. In Imager's advanced settings:
   - Set hostname (e.g. `dial-hallway`)
   - Enable SSH with your public key
   - Do **not** pre-configure WiFi — the dial's AP mode handles first-time setup
3. Insert the card, connect power, and wait ~30 seconds for first boot.
4. The dial broadcasts an access point: `autostream-dial_SETUP`

---

## First-Boot WiFi Setup

1. Connect your phone or laptop to `autostream-dial_SETUP`.
   Password: `autostream` (default; set in `/etc/hostapd/hostapd.conf` if changed).
2. A captive-portal page opens automatically (or browse to `http://192.168.4.1`).
3. Enter your home WiFi credentials and tap **Save**.
4. The dial reboots, joins your home network, and announces
   `_autostream-dial._tcp` via mDNS.

After WiFi setup, the dial is reachable at `http://dial-hallway.local` (or
whatever hostname you chose) from any device on the same network.

---

## Installing the Dial Software

The software is installed by the autostream dial installer. On a freshly
flashed Pi Zero W (after OS prep above):

```bash
# Copy the release archive to the Pi
scp autostream-dial-vX.Y.Z.tar.gz pi@dial-hallway.local:~

# SSH in and run the installer
ssh pi@dial-hallway.local
tar xzf autostream-dial-*.tar.gz
cd autostream-dial-*/
sudo bash autostream_dial_install.sh
```

The installer:
- Creates the `autostream-dial` service user
- Installs OS packages (`avahi-daemon`, `nginx`, `dnsmasq`, `gpiozero`, etc.)
- Deploys the dial Python application to `/opt/autostream/`
- Generates a UUID and writes `/etc/autostream-dial/dial.json`
- Configures systemd, nginx, logrotate, and sudoers
- Starts the `autostream-dial` service

Installation takes approximately 5 minutes on a Pi Zero W.

---

## Verifying the Installation

```bash
# Service status
systemctl status autostream_dial

# Avahi announcement
avahi-browse -t _autostream-dial._tcp

# HTTP server
curl http://localhost/configure
```

The setup page is available at `http://<hostname>.local/` from your browser.
