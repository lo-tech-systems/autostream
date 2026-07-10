# Wi-Fi Watcher

`autostream_wifi_watcher` is the appliance's connectivity supervisor. It runs
continuously as root on the **system** Python (not the app venv, so setup and
recovery survive a broken venv) and owns network **policy**: NetworkManager does
the mechanics; the watcher decides which interface should carry the client, when
to host a setup hotspot, when to reset a wedged adapter, and when a reboot is the
last resort. Autoconnect is disabled on every managed non-AP Wi-Fi profile so the
watcher is the sole agent that brings a client up. It always serves the setup
page; the NGINX config routes browser traffic to the watcher or to the main
web UI by the presence of `/tmp/apmode`.

## Implementation map

The installed recovery component is a star topology centered on
`platform/wifi_watcher.py`. The watcher owns global `STATE`, `RECOVERY_STATE`,
locks, constants, startup, and the monitor-loop driver. Split modules are
deployed beside it, each receiving a narrow context object built once at
startup:

| Module | Responsibility |
|---|---|
| `platform/wifi_watcher.py` | Startup, constants, shared state, fact gathering, setup/AP primitives, reboot guard, loop wiring, context composition. |
| `platform/wifi_state.py` | Data-only state module: `NetworkMonitorState`, `state_lock`, and the per-concern state fragments (apply/control/log-level, mDNS, status snapshot, adoption). |
| `platform/wifi_policy.py` | Pure decision core: `Mode`, `HotspotPurpose`, `PURPOSE_TABLE`, `next_mode`, recovery ladder, BSSID roam selection. |
| `platform/wifi_loop.py` | Ordered monitor-loop phases and `step_*` handlers. |
| `platform/wifi_activation.py` | Single-slot activation worker, activation jobs/results, loop-thread success/failure tails. |
| `platform/wifi_adoption.py` | USB failure fallback, runtime USB adoption, recovery-hotspot rejoin, reconnect-saved episodes, BSSID survey/roam orchestration. |
| `platform/wifi_recovery.py` | Dead-PHY detection, reset/quarantine/no-IP ledgers, guarded reboot persistence, per-adapter recovery facts. |
| `platform/wifi_status.py` | In-memory `/network_status` schema v1 snapshot and adapter health presentation. |
| `platform/wifi_web.py` | Flask setup page, captive-portal endpoints, loopback+token control API. |
| `platform/wifi_config.py` | First-boot profile import, autoconnect migration, steady-state reconnect helper. |
| `platform/wifi_mdns.py` | Avahi hostname repair and mDNS host-record re-announce debounce. |
| `platform/wifi_nm.py` | The bounded `nmcli` client. |
| `platform/wifi_hotspot.py` | AP start/stop/rebuild/clear-stale controller; start/stop own the `/tmp/apmode` flag sequencing around AP bring-up/teardown. |
| `core/autostream_wifi_network.py` | Shared facts and command-construction primitives: network state, adapter discovery, `nmcli`/`ip` parsing, scans, dnsmasq config rendering. |

## Persistent network state

Credentials remain in NetworkManager profiles. The watcher persists only the
committed connection identity:

- `/etc/autostream-network.json`: authoritative schema v1 state with
  `connection_name` and optional `connection_uuid`.
- `/opt/autostream/ssid`: legacy compatibility mirror containing the connection
  name only, despite the historical filename.

Invalid or empty JSON falls back to the legacy mirror. The watcher lazily
resolves and persists a UUID when a legacy name-only profile is used.

## Connectivity preference and the health model

Preference order: **wired ethernet > preferred USB Wi-Fi > onboard Wi-Fi**.
Usable ethernet wins regardless of subnet — the idle Wi-Fi client is disconnected
so there is one deterministic path and mDNS address (deferred only while playback
is active or uncertain).

Wi-Fi client health means NetworkManager reports the interface
connected/activated to a non-AP profile, the interface has a non-link-local
RFC1918 IPv4 address, and its interface-scoped default gateway is reachable.
Wired health is broader: carrier plus any usable non-link-local unicast IPv4
address. A carrier-only cable is reported but does not count as a usable path.

A *soft* Wi-Fi failure (carrier up but gateway/IPv4 not yet ready, or an
NM-disconnected-but-still-present USB) must persist **2 passes** before the path
is declared down; *hard* failures (nothing configured, NO-CARRIER, no client and
no present USB) condemn immediately. Slow to condemn, quick to forgive.

## Startup sequence

On startup the watcher clears stale hotspot state, runs first-boot import if its
marker is absent, enforces `connection.autoconnect no` on managed non-AP Wi-Fi
profiles, loads persisted adapter fault state, generates the per-boot control
token, starts the activation worker, and starts the monitor loop.

## First-boot profile import

AutoStream owns the whole machine, so on the first boot after adoption the
watcher normalises saved Wi-Fi state (once, guarded by
`/var/lib/autostream/first-boot-import.done`): it imports the currently connected
Wi-Fi profile as the single managed profile, disables its autoconnect, and
**deletes every other saved non-AP Wi-Fi profile** so NetworkManager cannot race
the watcher onto a stale OS/user/installer profile. With more than one active
Wi-Fi connection it keeps the one carrying the default route; with none it
deletes nothing and lets the first-run hotspot own setup. AP/hotspot profiles are
never deleted, per-profile delete failures are tolerated, and every retained or
deleted profile is logged at INFO. The marker is removed by a factory reset
(uninstaller), so a re-adopted device imports afresh. On an already-managed
device the step is a no-op (zero or one saved profile, nothing to delete).

## Operating modes

`device.mode` is one of: **BOOT**, **ONLINE**, **OFFLINE_RECONNECTING**,
**HOTSPOT**, **REBOOT_PENDING**. The mode is computed by a pure classifier each
pass and applied by the loop; it is not an emergent property of scattered flags.

## Activation worker

Effectful joins run through one shared activation worker instead of request
threads or inline loop code. The queue is single-slot and guarded by
`STATE.transitioning`, so the watcher has at most one activation in flight.

The worker performs slow, bounded effects: dropping the AP for a single-radio
attempt, running `nmcli`, validating IPv4/health, and rebuilding the AP on
failure. The monitor loop applies the success/failure tail at the next pass:
set active client, clear timers/ledgers, leave setup mode, disconnect a previous
client when needed, and trigger Avahi verification.

Reconnect-to-saved and explicit-reconfigure rollback use a reconnect episode:
one target adapter is tried per monitor pass, and the episode advances only after
the worker result is applied.

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

**Rejoin prompt (client-count aware).** Before a drop-AP rejoin, the watcher
counts stations associated to the setup AP (`iw dev <ifname> station dump`,
surfaced as `hotspot.clients`). With **zero** stations (nobody on the portal) the
automatic rejoin proceeds as before. With a station associated — or when the
count is unknown (`iw` missing) — the watcher does **not** yank the AP; it sets
`saved_ssid_visible` on `/status`, and the setup page shows a modal offering
"Rejoin" (POST `/reconnect_saved`) or "Continue setup" (POST `/dismiss_rejoin`,
which suppresses the probe/modal for the rest of the session). The 15-minute
probe grace for user-initiated sessions still applies before any probe or modal;
headless recovery (no station) is unchanged.

## Recovery decision tree

**Recovery ladder** (one pure classifier, used identically at boot-entry, on USB
failure, and from within a recovery hotspot): ethernet > preferred USB > **one
budgeted USB reset** > onboard client > hotspot as last resort. Disabled,
quarantined, no-IP-suppressed, or onboard-failure-bound adapters are not offered
as client rungs. Activation never requires carrier: for Wi-Fi, carrier means
*associated*, and association is what activation performs, so a preferred USB
that is merely idle (autoconnect is disabled everywhere, so every adapter reads
link-down until the watcher activates it) gets a normal activation, never a
reset. When that USB is instead the *active* client and reads link-down but has
not yet accrued a debounced wedged verdict, the ladder holds
(`usb_link_down_debouncing`) rather than resetting or failing over: transient
drops are left to the reconnect machinery, and only a sustained failure —
the same debounced dead-PHY verdict the status snapshot reports as `dead_phy` —
condemns it. When the preferred USB is condemned by that wedged verdict (not
merely no-IP) — resettable, within its reset budget, not hosting the hotspot,
and not already spent this offline episode — the ladder resets and reactivates
it before onboard is tried: salvage (NM re-activation) still runs first, and on
reset success the client resumes on the same MAC/lease/IP, so failover's
client-visible churn (and the mDNS TTL wait) is avoided. The attempt counts in
the visible reset ledger and is capped at once per offline episode; a
non-resettable, budget-exhausted, quarantined, hotspot-hosting, or
already-spent wedge falls straight to onboard, and quarantine still applies per
the existing thresholds once the reset option is exhausted. The
associated-but-no-IP class is ambiguous evidence (could be router/DHCP) and
keeps its own path — the in-job implicated-failure retry and the no-IP ledger
promotion — unaffected by this rung. The invariant: a broken USB dongle must
never trap the device in a hotspot on the only working radio — the onboard is
tried as a client before hosting a recovery AP, and climbed back to from within
one.

**Dead-PHY reset ladder** (a wedged-but-present adapter, NO-CARRIER / DOWN, after a
2-pass debounce): USB reset (method A rebind, then B re-enumerate, alternating),
for a resettable target with reset budget available, → built-in fallback →
quarantine/back-off → guarded reboot (offline only) — the same reset-before-
fallback order as the primary recovery ladder above. A non-resettable,
budget-exhausted, or disabled target falls straight through to built-in
fallback instead of holding the device offline; between reset attempt windows
the ladder falls through to built-in fallback the same way rather than waiting
for the next window. Reset budget is **2 per 24 h** for the preferred client;
**5 total** trips quarantine until the adapter is stable or replaced. Reset
history decays after 24 h of sustained health. The reset ladder is
`transitioning`-gated so it never overlaps a worker activation, and is left
synchronous by design.

**Runtime USB adoption**: a newly stable USB spare that can see the committed SSID
is validated *before* the healthy built-in is dropped (transactional handover),
gated by playback and by a saved-SSID scan.

**Idle-spare wedge recovery**: the adoption saved-SSID scan distinguishes a scan
command failure from a scan that succeeds with zero rows from one that succeeds
but simply doesn't see the committed SSID. Zero rows on a present candidate means
the radio itself is wedged (a working scan always sees *some* network, even when
the saved AP is away) — a streak of **2** consecutive empty scans (about 10
minutes at the adoption scan cadence) routes the candidate through the same
`remediate_unusable_usb` primitive every other unusable-USB detector uses: a
budgeted reset while budget remains, clearing the scan rate-gate so the next
pass re-scans immediately and a recovered radio fails back through the ordinary
adoption path unmodified; quarantine once the budget is exhausted. A quarantined
adapter is excluded from adoption's candidate gate entirely — no scan, no
reset attempt — until the shared 24 h quarantine self-expires and it is
re-probed on the next stable pass, the same lifecycle every other
unusable-USB path converges on.

**USB BSSID ownership / roam**: each interface keeps its own BSSID table, so an
onboard scan can never feed a USB roam decision. Active USB clients self-scan
every 60 s (a full rescan while playback is exactly `False`, a cheap read
otherwise that keeps the table fresh without advancing or resetting the
roam-candidate streak); an opportunistic idle-onboard scan updates the onboard
table alongside it for diagnostics only. A roam candidate must clear the
existing gates (fresh, unquarantined, signal margin) **and** an absolute
signal floor (`BSSID_ROAM_MIN_SIGNAL`), and must be preferred over 3
consecutive eligible USB scans before a same-candidate confirmation scan is
even attempted; the confirmation scan re-evaluates from a fresh USB table and
only submits the roam if it still names the same candidate and still clears
policy. The 15-minute roam/activation holdoff still applies. Failure/success
accounting on a pin is scoped to the pinned interface's own table, so a
failure on one USB adapter can never quarantine entries observed by another.
At `debug` log level every scan (USB self-scan, onboard survey, activation pin
scan) logs one compact line — ifname, rescan flag, purpose, and the strongest
BSSID/signal rows for the committed SSID; `info` and above stay quiet about
scans.

**Roaming management preference**: whether the watcher pins BSSIDs, runs the
survey/roam machinery, and tracks per-BSSID quarantine described above is
gated by a global, user-facing opt-in preference (default off — unmanaged,
NM/firmware roaming). Enabling it turns on BSSID pinning, the survey/roam
loop, and per-BSSID quarantine; disabling it clears any existing pin and
resets the in-memory roam state. The adapter fault ladder — dead-PHY/wedge
detection, empty-scan remediation, no-IP backoff, budgeted resets, and the
24 h quarantine — runs identically in both modes, since it keys off link
state and scan results, not pins. The one behaviour scoped to the managed
case is the pin-implicated retry heuristic, which only fires when an
activation failure can be attributed to a stale BSSID pin.

**Persistent fault state**: the per-adapter no-IP and reset/quarantine ledgers are
persisted to `/var/lib/autostream/adapter-fault-state.json` (wall-clock
timestamps, translated back to the monotonic clock and pruned by the rolling
windows on load), so a restart — including the 12-hour catch-all reboot — does not
hand a chronically bad dongle a fresh budget.

**No-IP hold-back reset**: an idle USB spare that repeatedly associates but never
gets an IP is normally held back by the no-IP ledger. Because the dead-PHY reset
ladder only targets the *active* client, such a spare would never be reset; so
when it reaches the final hold-back the watcher spends **one** budgeted USB reset
(accounted against the normal reset budget) and clears its suppression for a fresh
adoption attempt. If that still fails, the hold-back proceeds — one reset per
hold-back episode.

**ClientFailed overlay HOLD handling / post-handover settling**: the recovery
ladder now tries a plain re-activation (scan-informed via the activation pin
step, which scans before bringing the connection up) before either a
hardware reset or an onboard demotion — cheaply distinguishing a vanished/
unrecoverable pinned AP, which recovers for free, from a genuinely wedged
radio, which fails the reactivation and falls through to the budgeted reset
on the next pass. The condemned fact that gates this (`usb_active_reactivate`
for an active preferred USB, and the wedged reactivate-first rung ahead of
`RESET_USB`) comes from the debounced connectivity verdict — a condemned
connectivity episode open on the client — not a raw connectivity flag, so a
freshly-activated, still-DHCP-settling client is never mistaken for
condemned; the accepted trade-off is that a genuinely wedged radio now
recovers one activation attempt slower (bounded by the activation timeout)
before its budgeted reset fires. The ClientFailed overlay is a pure executor
of the ladder's verdict — it submits whatever ACTIVATE_USB / RESET_USB /
ACTIVATE_ONBOARD action the ladder returns and never rewrites it. When the
ladder holds an active, carrier-up, unhealthy preferred USB that is not yet
condemned (`usb_active_no_ip`), the overlay takes no action and logs the held
decision; once the connectivity episode is condemned, the ladder's own
reactivate-first rung takes over instead of this hold. `usb_link_down_debouncing`
also holds outright (the dead-PHY debounce owns that adapter); other HOLD
reasons keep the existing onboard-fallback behaviour. Separately, for **45 s**
after the active client
identity last changed (boot detection, adoption handover, or a recovery
activation), a HARD connectivity verdict (active-client link-down, or no
active client and no recorded USB left to reconnect to) is softened to the
normal `CONNECTIVITY_DOWN_DEBOUNCE`-pass debounce instead of condemning on a
single sample — shielding a just-completed handover from one-sample races
(NM state settling, ARP `INCOMPLETE`, a coincident avahi restart) while a
genuinely dead handover still condemns within the usual debounce window.

**Manual adapter control** (loopback+token, via `/network_control`):
`disable_adapter` (a disabled adapter is never offered as a client, adopted, or
reset until re-enabled — persisted across restarts), `enable_adapter`, and
`clear_adapter` (clear an adapter's fault ledgers after replacement).

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
| BSSID survey (full rescan when idle, cheap read during playback) | 60 s |
| BSSID roam/activation holdoff | 15 min |
| Gateway-down / dead-PHY → reboot | 30 min |
| No usable path → catch-all reboot | 12 h |
| USB reset budget window | 24 h (2 preferred / 5 total) |
| Cross-boot reboot cap | 3 per 24 h |

## API surfaces and logging

**Captive / setup (AP clients, no token):** `GET /`, `GET|POST /setup`,
`GET /networks`, `POST /reconnect_saved`, `POST /dismiss_rejoin`, `GET /status`,
plus the OS captive-portal probe endpoints (`/generate_204`, `/ncsi.txt`,
`/.well-known/captive-portal`, …).

**Privileged loopback control (loopback source AND per-boot token):**
`GET /version`, `GET /network_status`, `POST /network_control`
(actions: `start_setup`, `reconnect_saved`, `set_log_level`, `disable_adapter`,
`enable_adapter`, `clear_adapter`), `POST /request_ap_mode`.
`POST /request_ap_mode` queues the compatibility `manual_ap` action internally.

**Log levels:** `fatal`, `log`, `warning`, `info` (default), `debug`, `spam`.
Only `warning` / `info` / `debug` are settable at runtime via `set_log_level`;
`debug` must carry a TTL of 60–3600 s and reverts automatically.

The watcher's runtime level follows the autostream web UI's log-level control
over this loopback API: the web UI forwards every successful level change
(and the persisted level once at its own startup) as a best-effort
`set_log_level` call, mapping `spam`/`debug` to `debug` with the maximum
`ttl_seconds` of 3600, `info` to `info`, and `warning`/`log`/`fatal` to
`warning`. A UI-set `debug` therefore still auto-reverts after the 1-hour TTL
ceiling even while the UI continues to show debug. A watcher-only restart
drops the forwarded level and falls back to `AUTOSTREAM_WIFI_LOG_LEVEL` until
the next UI change or a web-UI restart re-forwards the persisted level.

The runtime level also gates werkzeug (the watcher's HTTP server): HTTP
access logging for `/network_status` and other polling requests is only
emitted at `debug`; at `warning`/`info` those lines are suppressed. Werkzeug's
own warnings and errors always surface regardless of the runtime level.
