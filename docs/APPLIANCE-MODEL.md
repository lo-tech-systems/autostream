# Autostream Appliance Model

Autostream is designed for a **dedicated Raspberry Pi**. The installer takes
full, exclusive ownership of networking, audio, and several system subsystems.
Sharing the device with other software is unsupported and will produce
conflicts.

---

## Firmware (`/boot/firmware/config.txt`)

| Setting | Effect |
|---|---|
| `dtparam=watchdog=on` | Enables BCM hardware watchdog; `watchdog.conf` is replaced with autostream's thresholds (load, free memory). Daemon will **reboot the Pi** autonomously when thresholds are exceeded. |
| `dtoverlay=disable-bt` | Disables on-board Bluetooth, freeing the primary UART. `hciuart.service` becomes a no-op. Written on fresh installs only: the line doubles as the persistent store for the Setup page's onboard-Bluetooth toggle (removed/reinserted by `autostream_admin bt-onboard-on/off`), so updates preserve its current presence/absence rather than re-asserting the default. |

The uninstaller does **not** revert these; they persist on the SD card.

---

## Networking

Autostream assumes exclusive control of all wireless interfaces via
`autostream_wifi_watcher.service`. It installs:

- **NetworkManager conf** (`/etc/NetworkManager/conf.d/`): disables Wi-Fi
  power-saving (`wifi.powersave = 2`); enables mDNS/Avahi integration;
  installs a `99-wlan-fix` dispatcher hook applied on every interface event.
- **dnsmasq** (`autostream_dnsmasq.service`): started on demand by the Wi-Fi
  watcher to serve captive-portal DNS during hotspot/setup mode. The system
  `dnsmasq.service` is disabled.
- **Avahi** (`avahi-daemon`): publishes the Web UI as an mDNS/DNS-SD service.
  Conflicts with other Avahi consumers are untested.
- **nginx** (port 80): sole HTTP server; the default nginx site is removed and
  replaced. Any other virtual hosts will be overwritten.

The Wi-Fi watcher will activate a setup hotspot (`autostream_XXXX`) whenever
it cannot find a known network, taking over the wireless radio entirely. It also
manages switching between on-board and USB WiFi adapters.

---

## Services

Up to 15 systemd units are installed, depending on options chosen at install
time. (The dial's own units come from the separate `autostream_dial_install.sh`
on the dial device and are not counted here.) Core always-running units:

| Unit | Role |
|---|---|
| `autostream_monitor.service` | C++ audio daemon: USB capture, EQ, resampling, silence detection. Exclusive ALSA capture device owner. |
| `autostream.service` | Python coordinator and Flask Web UI (port 8080 → nginx port 80). |
| `autostream_wifi_watcher.service` | Wi-Fi lifecycle manager; starts/stops dnsmasq. |
| `vibra-mini.service` | Optional Shazam fingerprinting daemon (if track ID enabled). |
| `autostream_dial.service` | Optional GPIO rotary encoder/button daemon (if dial hardware installed). |
| `autostream_updater.timer` | Optional weekly auto-update (Monday 03:00 UTC + jitter); disabled by default. Temporarily stops the watchdog daemon during package installation. |
| `autostream_sdcardhealth.service` | Daily one-shot (if `--sdmon` enabled): runs `sdmon` against `/dev/mmcblk0`, writes remaining endurance % to `/var/lib/autostream/sdcardhealth.json`. |
| `autostream_storage_guard.service` | Daily one-shot (04:00 UTC + jitter; `Nice=10`, `IOSchedulingClass=idle`). Classifies free space into four tiers (normal ≥1 GiB/15%; warning ≥512 MiB/8%; critical ≥128 MiB/3%; emergency <128 MiB/3%) and runs escalating cleanup: logrotate → `apt autoclean` → journal vacuum → archive deletion → coredump deletion. Also enforces a **log-level ceiling** on the application via `PUT /api/log-level`: lowers to `info` at warning, `warning` at critical/emergency, and lowers to `warning` when SD card endurance < 20%. Restores the original level when conditions clear. Diagnostic levels (`debug`, `spam`) expire to `info` after 48 h; `info` expires to `warning` after 168 h regardless of disk state. Skips if playing or an update lock is held. State: `/var/lib/autostream/storage-guard.json`. |

---

## System Configuration

| Path | Change |
|---|---|
| `/etc/systemd/logind.conf.d/90-autostream-ignore-power-key.conf` | `HandlePowerKey=ignore` — suppresses USB-enumeration spurious power-key events that would otherwise shut down an unattended Pi. Disables physical power-button shutdown system-wide. |
| `/etc/systemd/journald.conf.d/99-autostream-storage.conf` | Caps journal at 128 MB / 14-day retention. |
| `/etc/sudoers.d/autostream_updater`, `autostream_admin` | Passwordless root for targeted update, reboot, and network-reconfiguration commands. |
| `/etc/logrotate.d/autostream` | Rotates `/var/log/autostream/`. |
| `/etc/cloud/cloud.cfg.d/` | Disables cloud-init management of `/etc/hosts` (if cloud-init present) to prevent it overwriting the `autostream.local` hostname entry on each boot. |
| `/etc/cloud/cloud-init.disabled` | Disables cloud-init's per-boot stage entirely (if cloud-init present). Its provisioning job is complete by the time the installer runs, and the per-boot stage costs a large fraction of every boot — including the automatic post-update reboot. Created as an empty root-owned flag file, the supported alternative to purging the package. Not reversed on uninstall. |
| `/etc/sysctl.d/90-autostream-swappiness.conf` | `vm.swappiness=20` — biases the small-RAM appliance towards zram absorbing pressure spikes rather than hosting working set. Not reversed on uninstall. |
| `rpi-zram-writeback.timer` (masked) | Masked with `systemctl mask --now`: the timer writes compressed zram pages out to microSD, which is pure card wear for this workload. Masking persists even if a later package installs the timer. Not reversed on uninstall. |
| `MALLOC_ARENA_MAX=2` | Set in the `autostream.service` and `autostream_bluetooth.service` units, capping glibc's per-thread malloc arenas on the two Python daemons. |
| Removed packages | `modemmanager` and `udisks2` are removed when present — no modem hardware and no removable-storage workflow on the appliance. Presence-guarded and best-effort; not reinstalled on uninstall. |

---

## Filesystem Layout

`/opt/autostream` (application), `/etc/autostream/` (config),
`/var/lib/autostream/` (state), `/usr/local/libexec/autostream/` (privileged
helpers), `/var/log/autostream/` (logs).

Runtime: `/tmp/autostream_monitor.sock`, `/tmp/vibra-mini.sock`,
`/run/autostream-pipes/autostream.fifo` (created at boot from
`/usr/lib/tmpfiles.d/autostream.conf`; it lives under `/run` rather than `/tmp`
because `/tmp` is subject to age-based cleanup).

---

## Known Conflicts When Sharing

| Resource | Conflict |
|---|---|
| ALSA capture | `autostream_monitor` opens USB audio devices exclusively. |
| nginx / port 80 | Installer removes the default site; other vhosts will be lost. |
| Wireless interfaces | Wi-Fi watcher assumes sole control; any external manager will fight it. |
| `dnsmasq` | System dnsmasq is disabled; autostream's instance uses its own config. |
| `watchdog` | `/etc/watchdog.conf` is replaced; thresholds may trigger spurious reboots under other workloads. |
| GPIO | Dial daemon (if installed) claims specific pins. |
| Auto-reboot | Watchdog and Wi-Fi watcher can reboot the device without warning. |

---

## Uninstaller

`sudo /opt/autostream/autostream_uninstall.sh` removes sudoers fragments, nginx
config, NetworkManager hooks, systemd drop-ins, logrotate config, dnsmasq
templates, and Avahi service records. It does **not** revert
`/boot/firmware/config.txt`. See [UNINSTALL.md](UNINSTALL.md).
