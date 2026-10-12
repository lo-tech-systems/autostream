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
| `maxcpus=2` in `cmdline.txt`; `arm_freq=700`, `arm_boost=0`, `force_turbo=0` | **Low power mode, only if you pass `--low-power` to the installer.** Limits the appliance to two cores at 700 MHz for low-power boards such as a Zero 2 W. Takes effect at the next reboot. Saved with the install choices once used, and applied again by every `--update` whether or not the switch is given; on an appliance that has never used the switch, an update leaves any such lines alone. `over_voltage` is never written or removed. If the switch was used, the uninstaller removes these settings and puts back the `config.txt` lines and the `maxcpus` value that the switch replaced. See [Advanced Operations](ADVANCED.md#low-power-mode---low-power). |

The uninstaller does **not** revert the watchdog, GPU memory and Bluetooth
settings; they persist on the SD card. It does remove the low power mode
settings, but only if the installer's `--low-power` switch was used.

---

## Networking

Autostream assumes exclusive control of all wireless interfaces via
`autostream_wifi_watcher.service`. It installs:

- **NetworkManager conf** (`/etc/NetworkManager/conf.d/`): disables Wi-Fi
  power-saving (`wifi.powersave = 2`); enables mDNS/Avahi integration;
  installs a `99-wlan-fix` dispatcher hook applied on every interface event. Dials get the power-saving file and the dispatcher hook, but not the mDNS setting.
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

Up to 16 systemd units are installed, depending on options chosen at install
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
| `autostream_sdcardhealth.service` | Daily one-shot, always installed, timer enabled only once a guarded probe of the card succeeds (`--sdmon=<method>` at install time, or the Setup page later; the method is saved and preserved by `--update`). `ExecStart` runs the `autostream_sdcardhealth` wrapper's `run` mode, which probes with `sdmon` against `/dev/mmcblk0` under a marker file and a 90 s timeout, and writes remaining endurance % to `/var/lib/autostream/sdcardhealth.json`. Enable only for cards the tool supports. |
| `autostream_sdcardhealth_boot.service` | Oneshot, always installed and enabled, runs before `timers.target` on every boot. Detects a probe that never completed before a reboot (a marker file naming the card present): records the outcome as hung and disables the health-check timer, so a card that hangs the box can do so at most once. |
| `autostream_storage_guard.service` | Daily one-shot (04:00 UTC + jitter; `Nice=10`, `IOSchedulingClass=idle`). Classifies free space into four tiers (normal ≥1 GiB/15%; warning ≥512 MiB/8%; critical ≥128 MiB/3%; emergency <128 MiB/3%) and runs escalating cleanup: logrotate → `apt autoclean` → journal vacuum → archive deletion → coredump deletion. Also enforces a **log-level ceiling** on the application via `PUT /api/log-level`: lowers to `info` at warning, `warning` at critical/emergency, and lowers to `warning` when SD card endurance < 20%. Restores the original level when conditions clear. Diagnostic levels (`debug`, `spam`) expire to `info` after 48 h; `info` expires to `warning` after 168 h regardless of disk state. Skips if playing or an update lock is held. State: `/var/lib/autostream/storage-guard.json`. |

---

## System Configuration

| Path | Change |
|---|---|
| `/etc/systemd/logind.conf.d/90-autostream-ignore-power-key.conf` | `HandlePowerKey=ignore` - suppresses USB-enumeration spurious power-key events that would otherwise shut down an unattended Pi. Disables physical power-button shutdown system-wide. Dials get the same file. |
| `/etc/systemd/journald.conf.d/99-autostream-storage.conf` | Caps journal at 128 MB / 14-day retention. |
| `/etc/systemd/coredump.conf.d/99-autostream-coredump.conf` | Limits core dumps to 256 MB each and 256 MB in total, and clears older ones to keep 512 MB of disk free. This only matters if `systemd-coredump` is installed, which Raspberry Pi OS does not include and autostream does not install: until it is, nothing takes core dumps and the limit has no effect. It is there so a dump is bounded if you install the package to investigate a crash. Dials get the same file. |
| `/etc/rpi/swap.conf.d/99-autostream-swap.conf` | Limits the swap file to 512 MiB. Raspberry Pi OS makes it as large as the board's RAM, up to 2 GiB, on the SD card. Dials get the same file. Only written when the `rpi-swap` package is present; applies at boot, so after a reboot. With the default `rpi-swap` mechanism the file is the target that zram writes back to. The zram swap settings are untouched. Removed on uninstall. |
| `/etc/sudoers.d/autostream_updater`, `autostream_admin` | Passwordless root for targeted update, reboot, and network-reconfiguration commands. |
| `/etc/logrotate.d/autostream` | Rotates `/var/log/autostream/`. |
| `/etc/cloud/cloud.cfg.d/` | Disables cloud-init management of `/etc/hosts` (if cloud-init present) to prevent it overwriting the `autostream.local` hostname entry on each boot. |
| `/etc/cloud/cloud-init.disabled` | Disables cloud-init's per-boot stage entirely (if cloud-init present). Its provisioning job is complete by the time the installer runs, and the per-boot stage costs a large fraction of every boot - including the automatic post-update reboot. Created as an empty root-owned flag file, the supported alternative to purging the package. Not reversed on uninstall. |
| `/etc/sysctl.d/90-autostream-swappiness.conf` | `vm.swappiness=20` - biases the small-RAM appliance towards zram absorbing pressure spikes rather than hosting working set. Not reversed on uninstall. Dials get the same setting. |
| `rpi-zram-writeback.timer` (masked) | Masked with `systemctl mask --now`: the timer writes compressed zram pages out to microSD, which is pure card wear for this workload. Masking persists even if a later package installs the timer. Not reversed on uninstall. Dials mask it too. |
| `MALLOC_ARENA_MAX=2` | Set in the `autostream.service` and `autostream_bluetooth.service` units, capping glibc's per-thread malloc arenas on the two Python daemons. |
| Removed packages | `modemmanager` and `udisks2` are removed when present - no modem hardware and no removable-storage workflow on the appliance. Presence-guarded and best-effort; not reinstalled on uninstall. Dials remove them too. |

---

## Filesystem Layout

`/opt/autostream` (application), `/etc/autostream/` (config),
`/var/lib/autostream/` (state), `/var/lib/autostream-update/` (staged updates,
system only), `/usr/local/libexec/autostream/` (privileged helpers),
`/var/log/autostream/` (logs).

### Where an update is kept

The application runs as an unprivileged service account that owns
`/var/lib/autostream/`, so anything kept there could be replaced by that
account. An update is run by the system, so what it runs and what it trusts
after a restart is kept somewhere else.

| Path | Owner and mode | Holds | Who can read it |
|---|---|---|---|
| `/var/lib/autostream-update/` | `root:root`, `0700` | The downloaded release (`staging/`), and a short record that an update is under way (`update-in-progress`). The list of services the installer stopped is kept here too. | The system only |
| `/var/lib/autostream/update-result.env` | root-written | The progress and last result of an update. | The Web UI and the setup pages, through the updater |
| `/var/lib/autostream/install-state.env` | root-written, `0644` | The installed version and the choices saved for the next update. | The Web UI, the storage guard and the SD card health check |

An update goes like this. The updater downloads the release into
`/var/lib/autostream-update/staging/`, writes the record beside it and starts
the installer from there. The installer reads the saved choices from
`install-state.env`, checking each value, and always installs into
`/opt/autostream`. If power is lost part-way, the boot-time retry looks only in
`/var/lib/autostream-update/`; it acts only when the record is there, and
otherwise marks the update failed and leaves the appliance as it was. The
record is removed as soon as the update has a final result. An appliance
updated from an earlier release has its staged release copied across by that
one update, and the old copy is removed once the update has succeeded.
The updater refuses to use `/var/lib/autostream-update/` unless it is a real
directory, owned by root, with mode `0700`.

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
