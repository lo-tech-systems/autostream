# Wi-Fi Watcher

`autostream_wifi_watcher` is the appliance's connectivity supervisor. It runs
continuously as root on the **system** Python (not the app venv, so setup and
recovery survive a broken venv) and owns network **policy**: NetworkManager does
the mechanics; the watcher decides which interface should carry the client, when
to host a setup hotspot, when to reset a wedged adapter, and when a reboot is the
last resort. Autoconnect is disabled on every managed Wi-Fi profile so the
watcher is the sole agent that brings a client up. It always serves the setup
page; the NGINX config routes browser traffic to the watcher or to the main
web UI by the presence of `/tmp/apmode`.

## Connectivity preference and the health model

Preference order: **wired ethernet > preferred USB Wi-Fi > onboard Wi-Fi**.
Usable ethernet wins regardless of subnet — the idle Wi-Fi client is disconnected
so there is one deterministic path and mDNS address (deferred only while playback
is active or uncertain).

A path is **healthy** when NetworkManager reports the interface connected/activated,
it holds a non-link-local RFC1918 IPv4 address (not 169.254/16), and its
interface-scoped default gateway is reachable. Health is scoped to the active
client adapter. A *soft* failure (carrier up but gateway/IPv4 not yet ready, or an
NM-disconnected-but-still-present USB) must persist **2 passes** before the path
is declared down; *hard* failures (nothing configured, NO-CARRIER, no client and
no present USB) condemn immediately. Slow to condemn, quick to forgive.

## Operating modes

`device.mode` is one of: **BOOT**, **ONLINE**, **OFFLINE_RECONNECTING**,
**HOTSPOT**, **REBOOT_PENDING**. The mode is computed by a pure classifier each
pass and applied by the loop; it is not an emergent property of scattered flags.

## Hotspot purpose table

The hotspot is a single parameterised state `HOTSPOT(purpose)`. There is no
once-per-boot AP budget — the 30-minute session lifetime is the only rate limit.
Automatic purposes are suppressed when a usable wired path is present; a
carrier-only cable does not count as usable.

| Purpose | Entry condition | Deadline | Suppressed by ethernet | Probe for saved SSID |
|---|---|---|---|---|
| FIRST_RUN | Unconfigured at boot | none (indefinite) | yes | no (nothing saved) |
| BOOT_RECOVERY | Configured, offline at boot | 30 min | yes | every pass (grace 0) |
| USB_LOSS_RECOVERY | Configured, lost client path at runtime | 30 min | yes | every pass (grace 0) |
| EXPLICIT_RECONFIGURE | User "Change Wi-Fi" | 30 min | no | after 15-min grace; rolls back to previous network at deadline |
| MANUAL | User-requested AP | 30 min | no | after 15-min grace |

A recovery hotspot probes cheaply for the saved SSID (a scan works in AP mode
without dropping the AP). When the only client radio is the AP-hosting radio,
rejoining tears the AP down — the single-radio exit edge.

## Recovery decision tree

**Recovery ladder** (one pure classifier, used identically at boot-entry, on USB
failure, and from within a recovery hotspot): ethernet > preferred USB > onboard
client > hotspot as last resort. A quarantined / no-IP-suppressed / budget-spent
onboard is not offered. The invariant: a broken USB dongle must never trap the
device in a hotspot on the only working radio — the onboard is tried as a client
before hosting a recovery AP, and climbed back to from within one.

**Dead-PHY reset ladder** (a wedged-but-present adapter, NO-CARRIER / DOWN, after a
2-pass debounce): built-in fallback → USB reset (method A rebind, then B
re-enumerate, alternating) → quarantine/back-off → guarded reboot (offline only).
Reset budget is **2 per 24 h** for the preferred client; **5 total** trips
quarantine until the adapter is stable or replaced. Reset history decays after
24 h of sustained health. The reset ladder is `transitioning`-gated so it never
overlaps a worker activation, and is left synchronous by design.

**Runtime USB adoption**: a newly stable USB spare that can see the committed SSID
is validated *before* the healthy built-in is dropped (transactional handover),
gated by playback and by a saved-SSID scan.

**Guarded reboot domains** — every request passes one shared guard (a persistent
cross-boot cap of **3 reboots per 24 h** plus an in-process throttle):
- **Gateway-down**: connected client but gateway unreachable for **30 min**.
- **Dead-PHY**: only client path dead and offline for **30 min**.
- **12-hour catch-all**: no usable non-hotspot path seen for **12 h** (suspended
  while in setup/AP mode; reset on leaving it).

## Key timers

| Timer | Value |
|---|---|
| Monitor loop interval | 15 s |
| Boot AP grace (offline → boot-window AP entry) | 60 s |
| Boot automatic-AP-entry cutoff | 15 min |
| Hotspot session lifetime | 30 min |
| User-hotspot probe grace | 15 min |
| Connectivity/USB soft-fail debounce | 2 passes |
| Gateway-down → start reconnect | 5 min |
| Reconnect attempt interval | 2 min |
| Recovery-hotspot saved-SSID scan | 30 s |
| Runtime USB-adoption scan | 5 min |
| Gateway-down / dead-PHY → reboot | 30 min |
| No usable path → catch-all reboot | 12 h |
| USB reset budget window | 24 h (2 preferred / 5 total) |
| Cross-boot reboot cap | 3 per 24 h |

## API surfaces and logging

**Captive / setup (AP clients, no token):** `GET /`, `GET|POST /setup`,
`GET /networks`, `POST /reconnect_saved`, `GET /status`, plus the OS
captive-portal probe endpoints (`/generate_204`, `/ncsi.txt`,
`/.well-known/captive-portal`, …).

**Privileged loopback control (loopback source AND per-boot token):**
`GET /version`, `GET /network_status`, `POST /network_control`
(actions: `start_setup`, `reconnect_saved`, `set_log_level`), `POST /request_ap_mode`.

**Log levels:** `fatal`, `log`, `warning`, `info` (default), `debug`, `spam`.
Only `warning` / `info` / `debug` are settable at runtime via `set_log_level`;
`debug` must carry a TTL of 60–3600 s and reverts automatically.
