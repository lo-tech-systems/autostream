#!/usr/bin/python3
"""autostream_wifi_watcher.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

This module should be run continuously as root. It monitors (and logs) the network
connection status of the device.

Runtime note:
This service is intentionally executed directly via its shebang using the system
Python interpreter, rather than the autostream application venv. That keeps the
WiFi setup/recovery path available even if the venv is missing or broken, so
Flask must be installed at the system level by the installer.

== Access Point Mode ==

If the WiFi is unconfigured or remains disconnected for 1 minute after boot, it is put into
AP mode with a captive portal that enables the user to easily connect the Pi to the WiFi.

The hotspot is a single parameterised state, HOTSPOT(purpose), whose entry/exit policy is
read from one five-row purpose table (PURPOSE_TABLE) rather than a soup of booleans:

  - FIRST_RUN (unconfigured): runs indefinitely until the user configures a network or
        usable wired ethernet appears.  Nothing saved to probe for.
  - BOOT_RECOVERY (configured, offline at boot): runs for up to 30 minutes but probes for
        the saved network's return every pass and leaves as soon as it reconnects — so a
        device whose router booted slower than the Pi recovers promptly.
  - USB_LOSS_RECOVERY (configured, lost its client path at runtime): same 30-minute,
        probe-for-return policy.
  - EXPLICIT_RECONFIGURE / MANUAL (user-initiated): 30 minutes, not suppressed by ethernet.
        These probe for the saved network too, but only after a HOTSPOT_PROBE_GRACE window
        (15 min) so the watcher does not rejoin the network the user opened the portal to
        change before they have selected a new one.  EXPLICIT_RECONFIGURE still rolls back to
        the previous network at the 30-minute deadline if the user never completes setup.

There is no once-per-boot AP budget: the 30-minute session lifetime is the only rate limit,
so a recovery hotspot is available whenever the device is offline.  A failed
WiFi configuration attempt simply re-enters the hotspot.

If a wired ethernet path is usable (carrier plus a valid non-link-local IPv4 address),
automatic-purpose hotspots (FIRST_RUN / BOOT_RECOVERY / USB_LOSS_RECOVERY) are suppressed.
A carrier-only cable is reported as a fact but does not count as a usable path.  A
user-initiated hotspot (EXPLICIT_RECONFIGURE / MANUAL) is left up — it exists to connect a
new network, so ethernet appearing does not close it.

On hardware without a built-in radio, the setup hotspot uses a managed USB adapter. With multiple
USB adapters, it prefers a USB adapter that is not the active WiFi client so a second radio can keep
the setup hotspot reachable during credential retries.

== Connection Reliability ==

If the WiFi is configured and usable wired ethernet is down, the script monitors the network
health by monitoring the kernel's view of the default gateway. If this goes offline for more
than 5 minutes, the script trys to reconnect to the network periodically.

When usable wired ethernet is present it wins regardless of subnet: the watcher disconnects the
idle WiFi client and runs on ethernet to leave a single deterministic network path and mDNS
address. The only gate is playback — switching the active interface changes the
appliance IP and would break an in-flight stream, so the disconnect is deferred while playback
is active or uncertain (and while apply/setup work is in progress). If ethernet later drops, the
watcher attempts a prompt reconnect on entry to the offline-reconnecting state (no 5-minute wait).

If the gateway remains unreachable for more than 30 minutes, the script will reboot the device.
Whilst this seems aggressive, the WiFi chipset in the Pi-Zero range is not great in terms
of long periods of uptime so this is a defensive strategy. Music can't play if the device
isn't on the network anyway.

As a final safety net, if normal monitoring has not seen any usable non-hotspot WiFi or
ethernet path for 12 hours, the watcher requests a guarded NetworkDown reboot. Setup/AP mode
suspends this catch-all timer, and leaving setup/AP mode resets it.

Note that this script always serves the setup page. The associated NGINX configuration
controls which web server (this or autostream_webui.py) services requests via the presence
(or not) of /tmp/apmode.

== Module responsibility split ==

This module owns recovery *policy/orchestration*: the state machine, timers,
AP/setup transitions, apply/scan, fallback, dead-PHY recovery, and the runtime
status snapshot. It is the star-topology hub that owns STATE, state_lock, the
constants, and the logger. The Flask HTTP surface — page rendering, the app
factory build_app(), all routes, and the loopback control-token/auth surface —
lives in the deploy-together sibling wifi_web.py; this module wires the app at
startup via ``app = wifi_web.build_app(WEB_CTX)`` and drives the token
lifecycle from __main__ through the same ``WEB_CTX``. Dead-PHY recovery lives
in wifi_recovery.py and the status snapshot in wifi_status.py; each, like
wifi_web, receives a narrow context exposing only the STATE/constants/
callables it uses, and none of the split modules import wifi_watcher.

== Explicit state-machine model ==

The operating mode is an explicit ``wifi_policy.Mode`` (BOOT / ONLINE /
OFFLINE_RECONNECTING / HOTSPOT / REBOOT_PENDING), published as
``device.mode``.  All hotspot entry/exit policy is one five-row
``wifi_policy.PURPOSE_TABLE`` keyed by ``wifi_policy.HotspotPurpose``; the live
session is a ``HotspotSession`` on STATE.  The decision core is **pure** and
lives in ``platform/wifi_policy.py``: ``next_mode(state, facts)``, the
``PURPOSE_TABLE`` lookups, and ``next_recovery_action`` take values in and
return values out — no STATE mutation, no subprocess, no effects, no watcher
seam.  The loop calls those functions directly and *applies* the returned
values each pass (setting ``STATE.mode``/``STATE.hotspot`` and invoking
effects).  The
adapter-remediation overlay (``wifi_recovery.diagnose_client_failure`` and the
no-IP verdict) **emits events** (``ClientFailed`` / ``NeedReboot``); the loop
consumes them and applies the connectivity transition.  Slow transitions run
off-thread on the activation worker, gated by a load-bearing in-flight-job flag
so at most one effectful transition is in flight at a time.

A second pure classifier, ``next_recovery_action(state, recovery_facts)``, owns the
*recovery priority ladder* — Ethernet > preferred USB > onboard client >
hotspot-as-last-resort — over a per-pass ``RecoveryFacts`` snapshot built from the
shared per-adapter facts in ``wifi_recovery.adapter_recovery_facts`` (health,
carrier, reset budget, quarantine, no-IP).  It is the single source of the
client-path-vs-hotspot decision.  A wedged USB with no onboard alternative is
left to the dead-PHY reset/quarantine/reboot mechanics in ``wifi_recovery``.
The invariant it encodes: a broken USB dongle must never trap the device in a
30-minute hotspot on the only working radio — the onboard is tried as a client
before hosting a recovery AP (boot entry) and is climbed back to from within a
recovery hotspot (the exit edge).
"""

import glob
import os
import shutil
import time
import threading
import logging
import sys
import json
import urllib.request
from enum import Enum
from functools import partial
from typing import Optional
from dataclasses import dataclass, field

from autostream_sysutils import run_cmd, prime_gateway, reboot_system, get_system_hostname
import autostream_wifi_network as wifi_net

# The watcher is deployed beside its split sibling modules (wifi_status.py,
# wifi_recovery.py) in /opt/autostream.  Ensure that directory is importable
# both in production (script run directly) and under the test loader.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# Pure connectivity policy: enums, the hotspot purpose table, and the mode /
# recovery-ladder classifiers.  A standalone effect-free module; the hub and
# every context reference its names directly (`wifi_policy.<name>`).
import wifi_policy

# Multi-adapter fallback / runtime USB adoption / reconnect-saved episode
# machinery.  A standalone sibling module (imports only wifi_policy,
# wifi_recovery, wifi_activation, and the shared network helper); imported
# early so ReconnectEpisode is available for the STATE dataclass below.
import wifi_adoption

# Flask presentation/HTTP surface (page rendering, app factory, captive/setup
# routes).  Deployed beside the watcher in /opt/autostream; it takes this module
# across the seam and never imports wifi_watcher.
import wifi_web

# The single bounded nmcli client (instantiated below once the timeout constants
# exist).  Deployed beside the watcher; every nmcli invocation goes through it.
import wifi_nm

# Hotspot mechanics (start/stop/rebuild/clear-stale sequencing + flag ordering).
# Deployed beside the watcher; instantiated below once the seam is available.
import wifi_hotspot


def _self_module():
    """Return this watcher module object, for HotspotController's module seam.

    Works whether the watcher is run as a script (__main__) or loaded under an
    alias by the test harness.  Defined early so it is available at the point
    ``hotspot_controller`` is constructed.
    """
    return sys.modules.get(__name__) or sys.modules.get("__main__") or globals().get("__SELF__")


_DIAL_MODE = os.environ.get('APP_DIAL_MODE', '') == '1'
WIFI_WATCHER_VERSION = "1.0.0"

# Presentation (APP_TITLE/APP_BANNER_IMAGE/BANNER_HTML/STYLE_CSS,
# render_setup_page, render_wait_page) lives in wifi_web.py.

# File locations
LOG_FILE = "/var/log/autostream/autostream_wifi_watcher.log"
# Legacy compatibility mirror (connection NAME, not an SSID). The authoritative
# network state now lives in /etc/autostream-network.json, parsed by the helper.
CONFIGURED_SSID = wifi_net.LEGACY_SSID_PATH
NETWORK_STATE_PATH = wifi_net.NETWORK_STATE_PATH
AP_MODE_FLAG_PATH = os.environ.get('APP_APMODE_FLAG', '/tmp/apmode')
AP_PREFIX = os.environ.get('APP_AP_PREFIX', 'autostream')
DNSMASQ_SERVICE = os.environ.get('APP_DNSMASQ_SERVICE', 'autostream_dnsmasq.service')

# Runtime dnsmasq config binding.  The product-specific template
# is installed outside dnsmasq's automatic include dir; the watcher substitutes
# the resolved recovery interface and writes a runtime file the service reads.
DNSMASQ_TEMPLATE_PATH = os.environ.get(
    'APP_DNSMASQ_TEMPLATE',
    '/usr/local/share/autostream/dnsmasq/autostream-setup.conf',
)
DNSMASQ_RUNTIME_PATH = os.environ.get(
    'APP_DNSMASQ_RUNTIME',
    '/run/autostream/autostream-setup.conf',
)

# Timers (all in seconds)
NETWORK_MONITOR_INTERVAL = 15            # seconds between network checks

BOOT_AP_CUTOFF = 15 * 60                # ONLY allow *automatic* entry into AP mode within this many seconds of boot
# AP mode lifetime for configured devices (fixed, not extended by web activity)
# and the user-opened-hotspot probe grace live in wifi_policy (AP_MAX_DURATION,
# HOTSPOT_PROBE_GRACE, BOOT_AP_GRACE; they parameterise PURPOSE_TABLE).
# User-initiated hotspots (EXPLICIT_RECONFIGURE / MANUAL) suppress the
# probe-for-saved-network-return for HOTSPOT_PROBE_GRACE after entry: the user
# opened the portal to change networks and the old (saved) SSID is almost
# always still in range, so probing immediately would rejoin — and, on
# single-radio hardware, tear the hotspot down — before the user can select a
# new network.  Automatic recovery purposes (BOOT_RECOVERY / USB_LOSS_RECOVERY)
# use grace 0: they lost connectivity involuntarily and should rejoin as soon
# as the network returns.
NO_ACTIVE_PATH_REBOOT_AFTER = 12 * 60 * 60  # if no usable non-hotspot path for 12h -> reboot

GW_DOWN_RECONNECT_AFTER = 5 * 60        # gateway unreachable for this long -> start reconnect attempts
GW_DOWN_REBOOT_AFTER = 30 * 60          # gateway unreachable for this long -> reboot
RECONNECT_ATTEMPT_INTERVAL = 2 * 60     # interval between reconnect attempts (expensive join lower bound)
# Recovery-hotspot scan cadence: how often a recovery hotspot scans for the
# saved SSID's return.  Bounds the cheap scan independently of the loop tick so a
# recovery hotspot does not churn the radio/CPU on the Pi Zero every pass.
RECOVERY_SCAN_INTERVAL = 30             # seconds between saved-SSID recovery scans
# Runtime USB-adoption scan cadence: how often the idle-time adoption gate
# rescans a USB candidate that could not see the committed SSID.  Adoption is an
# optimisation on a device already healthy on the built-in, so re-scan latency
# costs nothing; the first scan for a newly stable candidate always runs
# immediately (last is None -> due), and this interval only throttles *re*-scans.
ADOPTION_SCAN_INTERVAL = 5 * 60         # seconds between saved-SSID adoption scans
# USB BSSID survey cadence: the cheap self-scan (+ opportunistic idle onboard
# scan) runs every BSSID_SURVEY_INTERVAL; the more expensive full USB rescan
# (covers bands an idle onboard radio cannot see) runs only every
# BSSID_USB_SURVEY_INTERVAL, and only while playback is idle.
BSSID_SURVEY_INTERVAL = 60
BSSID_USB_SURVEY_INTERVAL = 15 * 60
REBOOT_RATE_LIMIT_RETRY = 70 * 60       # retry a rate-limited/failed reboot after this long (exceeds the admin's 1-hour window)

# Multi-adapter failure/adoption tuning.
# Source-level connectivity_ok hysteresis: a *soft* unhealthy signal must
# persist this many consecutive passes before the path is declared down.  A
# healthy pass clears it immediately (slow to condemn, quick to forgive).  Soft
# signals: client connected with carrier up but gateway/IPv4 not ready
# (transient), and a recorded USB client NM-disconnected but still physically
# present.  HARD signals (nothing configured, no client and no present USB to
# reconnect, NO-CARRIER) bypass the debounce.
CONNECTIVITY_DOWN_DEBOUNCE = 2
USB_ADOPTION_STABLE_PASSES = 2         # consecutive passes a USB candidate must be present
# Bound async onboard-client activation failures per offline episode so a
# present-but-failing onboard (which the no-IP ledger never suppresses) eventually
# yields to the recovery hotspot.  Once this many onboard activations fail in an
# episode, gather_recovery_facts stops offering the onboard as a client rung, so
# the ladder returns ENTER_HOTSPOT.  Reset on any healthy pass.
ONBOARD_ACTIVATION_MAX_FAILURES = 2
PLAYING_STATUS_URL = os.environ.get(
    'APP_PLAYING_STATUS_URL', 'http://127.0.0.1:8080/api/playing-status'
)
PLAYING_STATUS_TIMEOUT = 2.0            # seconds
PLAYING_STATUS_WARN_THROTTLE = 5 * 60   # throttle "playing status unavailable" warnings

# After applying WiFi config, this appliance only requires *local* IPv4
# connectivity (it does not require Internet access):
#   - NetworkManager reports wlan0 connected/activated
#   - wlan0 has a non-link-local RFC1918 IPv4 address (i.e., not 169.254/16)
WAIT_FOR_CONNECTION_TIMEOUT = 45        # Seconds to wait for local IPv4 after config
WAIT_FOR_CONNECTION_INTERVAL = 2        # Poll interval for local IPv4 checks
# Enforceable per-command bounds for the worker-path nmcli subprocesses:
# run_cmd(timeout=…) SIGKILLs a hung child (rc 124), so the job's total bound is
# the deterministic sum of these plus the wait_for_connection deadline — a thread
# cannot self-interrupt in subprocess.run, so command-level timeouts are the bound.
NMCLI_ACTIVATE_TIMEOUT = WAIT_FOR_CONNECTION_TIMEOUT  # `nmcli connection up`
NMCLI_QUICK_TIMEOUT = 15                # modify / add / delete / device disconnect

# The single bounded nmcli client: every nmcli invocation passes one of the two
# timeouts above, so there is no unbounded NetworkManager code path.
nm = wifi_nm.NMClient(NMCLI_ACTIVATE_TIMEOUT, NMCLI_QUICK_TIMEOUT)

# The single source of hotspot mechanics.  Holds this module across the seam and
# drives the AP primitives (start_ap_mode / stop_ap_mode / update_apmode_flag /
# clear_apmode_flag / nm) at call time.
hotspot_controller = wifi_hotspot.HotspotController(_self_module())

# Avahi mDNS hostname monitoring
AVAHI_CHECK_INTERVAL       = 60         # seconds between avahi mDNS hostname checks
AVAHI_MISMATCH_GRACE       = 5 * 60     # grace period before acting on a hostname mismatch
AVAHI_RESTART_MIN_INTERVAL = 15 * 60    # minimum gap between avahi-daemon restarts
AVAHI_HANDOVER_RESTART_MIN_INTERVAL = 60  # minimum gap between path-change re-announcements
AVAHI_MAX_RESTART_ATTEMPTS = -1         # max avahi restarts per boot (-1 = unlimited)

# mDNS host-record re-announce on network-path changes (e.g. a USB Wi-Fi dongle
# removed while ethernet stays up).  avahi-daemon owns the `<hostname>.local`
# address records (the "system level" re-announce), and on a passive interface
# loss it cannot send goodbyes out the vanished interface nor re-announce the
# surviving record (which did not change) — so clients keep a stale answer until
# its TTL lapses.  The watcher detects when the published address set changes,
# waits for it to settle, then restarts avahi-daemon so it re-probes and
# re-announces host records (with the mDNS cache-flush bit) for the surviving
# interfaces only.
AVAHI_REANNOUNCE_DEBOUNCE  = 5          # seconds the address set must be stable before re-announcing

# Dead-PHY recovery.  A wedged-but-present USB Wi-Fi adapter
# (NO-CARRIER / state DOWN) is detected, reset via sysfs, and — only when
# genuinely offline — escalated to a guarded reboot.
DEAD_ADAPTER_DEBOUNCE      = 2            # consecutive link-down+unhealthy passes before "dead"
RESET_ATTEMPT_INTERVAL     = 60          # seconds between reset escalation steps
DEAD_ADAPTER_REBOOT_AFTER  = GW_DOWN_REBOOT_AFTER   # 30 min; reuse existing constant
USB_RESET_WINDOW           = 24 * 60 * 60  # rolling reset-budget window
USB_MAX_RESETS_PER_WINDOW  = 2           # preferred-client reset budget per window
USB_MAX_RESETS_TOTAL       = 5           # quarantine threshold until stable/reset
USB_EMERGENCY_BACKOFF      = 10 * 60     # slow retry when USB is the only path
DEAD_ADAPTER_HEALTHY_DECAY = 24 * 60 * 60  # decay reset history after sustained health
DEAD_ADAPTER_REBOOT_STAMP  = "/var/lib/autostream/dead-phy-reboot.stamp"
DEAD_ADAPTER_REBOOT_WINDOW = 24 * 60 * 60  # persistent reboot-guard window
DEAD_ADAPTER_MAX_REBOOTS_PER_WINDOW = 3   # cross-boot dead-PHY reboot cap
# Persistent per-stable-id fault state (no-IP + reset/quarantine ledgers) so a
# restart — including the 12-hour catch-all reboot — does not hand a chronically
# bad dongle a fresh budget.  Wall-clock timestamps, tolerant parsing.
ADAPTER_FAULT_STATE_PATH   = "/var/lib/autostream/adapter-fault-state.json"

# First-boot Wi-Fi profile import: a persisted marker so the one destructive
# import (retain the active profile, delete the other saved client profiles)
# runs at most once per adopted machine.  Removed by the uninstaller/factory
# reset so a re-adopted device imports afresh.
FIRST_BOOT_IMPORT_MARKER = "/var/lib/autostream/first-boot-import.done"

# Runtime log-level control.  Only these levels may be set at runtime via
# the loopback/token-protected control surface; debug must carry a TTL.
RUNTIME_LOG_LEVELS = {"warning": logging.WARNING, "info": logging.INFO, "debug": logging.DEBUG}
LOG_LEVEL_TTL_MIN = 60
LOG_LEVEL_TTL_MAX = 3600

# Control actions that touch no connectivity/AP state, so they are consumed and
# applied immediately (never deferred while transitioning, never own the pass).
_NON_DISRUPTIVE_ACTIONS = {
    "set_log_level", "clear_adapter", "disable_adapter", "enable_adapter",
}


# ** EXPLICIT STATE MODEL **
#
# The explicit model the watcher runs on — connectivity mode, hotspot purpose,
# the purpose-policy row shape, and the five-row PURPOSE_TABLE — is pure data
# plus pure classifiers (no STATE mutation, no subprocess, no effects, no
# dependency on any watcher seam) living in platform/wifi_policy.py.
# wifi_policy.next_mode() is the pure forward classifier; the loop applies its
# result by setting STATE.mode each pass, and the mode is published as
# device.mode.


@dataclass(frozen=True)
class RollbackSnapshot:
    """Rollback target for an EXPLICIT_RECONFIGURE session (mirrors rollback_* fields)."""
    connection_name: str
    connection_uuid: str
    adapter_mac: str


@dataclass
class HotspotSession:
    """The live hotspot session: purpose + entry time (+ rollback for reconfigure).

    deadline / eth_suppressible / probes_return are not stored here — they are
    looked up in wifi_policy.PURPOSE_TABLE[purpose] so policy lives in exactly
    one place.
    """
    purpose: "wifi_policy.HotspotPurpose"
    entered_at: float
    rollback: Optional[RollbackSnapshot] = None   # only EXPLICIT_RECONFIGURE


# A reconnect-saved episode: restores a saved/rollback profile across passes
# (one single-target activation job per pass, advanced on the result).  Lives
# in wifi_adoption.py; re-exported so the STATE field annotation below and
# existing `wifi_watcher.ReconnectEpisode` references keep working.
ReconnectEpisode = wifi_adoption.ReconnectEpisode


logger = logging.getLogger(__name__)


class DeduplicateFilter(logging.Filter):
    """Suppress a log record if an identical record (same logger, level, rendered
    message) was emitted within the last _WINDOW seconds.

    Each handler carries its own instance so filtering is applied independently
    per destination (stdout vs file).  Both instances stay in sync in practice
    because all handlers receive the same records in the same order.
    """

    _WINDOW = 60.0

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        # (logger_name, levelno, rendered_message) -> last emission time (monotonic)
        self._cache: dict[tuple, float] = {}

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        key = (record.name, record.levelno, msg)
        now = time.monotonic()
        with self._lock:
            last = self._cache.get(key, 0.0)
            if now - last < self._WINDOW:
                return False
            self._cache[key] = now
        return True


def _setup_logging() -> None:
    """Configure root-level logging to stdout and (if possible) a log file.

    The log level defaults to INFO and can be overridden by setting the
    AUTOSTREAM_WIFI_LOG_LEVEL environment variable (fatal/log/warning/info/
    debug/spam — matching the main autostream platform level vocabulary).
    The service keeps running even if the log file cannot be created.
    """
    _LEVEL_MAP: dict[str, int] = {
        "fatal":   logging.CRITICAL,
        "log":     logging.ERROR,
        "warning": logging.WARNING,
        "info":    logging.INFO,
        "debug":   logging.DEBUG,
        "spam":    logging.DEBUG,
    }
    env_level = os.environ.get("AUTOSTREAM_WIFI_LOG_LEVEL", "info").strip().lower()
    level = _LEVEL_MAP.get(env_level, logging.INFO)

    # Record the startup/default runtime level name for the status snapshot and
    # for reverting temporary levels.  Only the runtime-settable names are
    # carried verbatim; anything else (fatal/log/spam) reports as "info".
    STATE.default_log_level_name = env_level if env_level in RUNTIME_LOG_LEVELS else "info"

    root = logging.getLogger()
    root.setLevel(level)

    if root.handlers:
        return

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%d-%b-%y %H:%M:%S",
    )

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    stream_handler.addFilter(DeduplicateFilter())
    root.addHandler(stream_handler)

    try:
        log_dir = os.path.dirname(LOG_FILE) or "."
        os.makedirs(log_dir, exist_ok=True)
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(DeduplicateFilter())
        root.addHandler(file_handler)
    except Exception as e:
        logger.error(
            "Failed to initialise file logging (%s); continuing with stdout only.", e
        )

@dataclass
class NetworkMonitorState:
    # Link state (reported via /status and UI)
    wifistate: str = "unknown"        # "configured" / "unconfigured" / "unknown"
    wiredstate: str = "unknown"       # "connected" / "disconnected" / "unknown"
    connectivity_ok: bool = False     # "healthy" using the same validation logic as initial wifi checks
    # Consecutive *soft* unhealthy passes for the connectivity_ok down-debounce;
    # reset to 0 on any healthy pass or a hard failure.
    conn_unhealthy_checks: int = 0
    # True once the device has been ONLINE at least once this boot.  A
    # runtime connectivity loss after this must be handled by the debounced
    # runtime paths, never by re-entering the boot-recovery rung.
    been_online_this_boot: bool = False

    # Setup / AP state.  ``setup_mode`` is the "a hotspot session is active"
    # boolean read across the modules and tests; ``hotspot`` is the authoritative
    # HotspotSession.  There is no once-per-boot AP budget: the 30-minute session
    # lifetime is the rate limit.
    setup_mode: bool = False
    hotspot: "Optional[HotspotSession]" = None
    # Rejoin prompt (per hotspot session): set when the saved SSID becomes visible
    # during a session with a client associated to the AP, so the setup page can
    # offer "rejoin or keep reconfiguring" instead of the watcher silently yanking
    # the AP.  ``rejoin_dismissed`` records the user choosing to keep
    # reconfiguring, which suppresses the probe/modal for the rest of the session.
    # All three reset on session entry/exit.
    saved_ssid_visible: bool = False
    saved_ssid_name: str = ""
    rejoin_dismissed: bool = False
    # Active reconnect-saved episode (single-target-per-pass restore), or None.
    reconnect_episode: "Optional[ReconnectEpisode]" = None
    # Authoritative connectivity mode, applied by the loop each pass from the
    # pure wifi_policy.next_mode() classifier and published as device.mode.
    mode: "wifi_policy.Mode" = field(default_factory=lambda: wifi_policy.Mode.BOOT)

    # Timers (monotonic seconds)
    boot_time: Optional[float] = None
    last_active_path_seen: Optional[float] = None

    # Degradation tracking for "healthy connectivity"
    conn_down_start: Optional[float] = None
    last_reconnect_attempt: Optional[float] = None
    # Last time a recovery hotspot scanned for the saved SSID (scan gate).
    last_recovery_scan: Optional[float] = None
    # Last time runtime USB adoption scanned the candidate for the committed SSID
    # (scan gate).
    last_adoption_scan: Optional[float] = None
    # Reboot-request throttle: monotonic time before which another reboot request is
    # suppressed.  0.0 = unrestricted; float('inf') = accepted and permanent (reboot
    # issued); any other value = retry permitted after that time.
    conn_reboot_retry_after: float = 0.0

    # ---- WiFi apply workflow / wait-page status ----
    apply_in_progress: bool = False
    # idle | applying | ok | failed
    last_apply_result: str = "idle"
    # short error code/message (e.g. nmcli-failed, no-local-ip)
    last_apply_error: str = ""

    # ---- Avahi mDNS hostname monitoring ----
    avahi_hostname: Optional[str] = None
    avahi_mismatch_start: Optional[float] = None
    last_avahi_restart: Optional[float] = None
    last_avahi_handover_restart: Optional[float] = None
    avahi_restart_count: int = 0

    # ---- mDNS host-record re-announce on address-set changes ----
    # Set of (ifname, ipv4) the host currently publishes; None until first observed.
    mdns_address_set: Optional[frozenset] = None
    # Monotonic time the published address set last changed (debounce anchor).
    mdns_address_changed_at: Optional[float] = None
    # Explicit re-announce nudge from an orchestrated handover.
    mdns_reannounce_pending: bool = False

    # ---- Off-thread activation worker ----
    # Set when an activation job is in flight on the worker and cleared when its
    # result is applied at pass top.  While set, handlers that would start a
    # conflicting connectivity/AP transition hold off (one effectful transition at
    # a time); monitoring, status publishing and non-disruptive control actions
    # keep running.
    transitioning: bool = False
    # Async onboard-activation failures this offline episode (reset on a healthy
    # pass).  When it reaches ONBOARD_ACTIVATION_MAX_FAILURES the onboard is no
    # longer offered as a client rung, so the ladder falls to the hotspot.
    onboard_activation_failures: int = 0

    # ---- Multi-adapter failure / adoption ----
    using_builtin_fallback: bool = False
    active_client_ifname: str = ""
    active_client_mac: str = ""
    pending_usb_adoption_mac: Optional[str] = None
    pending_usb_adoption_checks: int = 0
    last_detected_adapter_macs: Optional[frozenset] = None

    # ---- USB BSSID ownership (roaming) ----
    bssid_table: dict = field(default_factory=dict)
    last_roam_or_activation: Optional[float] = None
    last_bssid_pin: dict = field(default_factory=dict)
    last_bssid_survey_at: Optional[float] = None
    last_bssid_usb_full_survey_at: Optional[float] = None

    # Explicit reconfiguration, rollback snapshot, and AP-session timing live on
    # the HotspotSession (STATE.hotspot).  The dead-PHY / reset / no-IP / manual-
    # disable ledgers live on RECOVERY_STATE (a wifi_recovery.RecoveryState),
    # shared with wifi_status for the status snapshot.

    # ---- Local control API ----
    pending_control_action: str = ""
    control_in_progress: bool = False
    last_control_action: str = ""
    last_control_result: str = ""
    last_control_error: str = ""

    # ---- Runtime log-level control ----
    pending_control_params: dict = field(default_factory=dict)
    temporary_log_level: str = ""
    temporary_log_level_until: Optional[float] = None
    default_log_level_name: str = "info"

    # ---- Runtime network-status snapshot ----
    network_status_snapshot: Optional[dict] = None
    network_status_updated_at: Optional[float] = None


STATE = NetworkMonitorState()

# Synchronisation primitive for shared state
state_lock = threading.Lock()

# Serialise AP start/stop transitions
ap_mode_lock = threading.Lock()

# Queued local-control action consumed by the monitor loop (manual AP requests,
# start_setup, reconnect_saved, set_log_level).
control_action_event = threading.Event()

# The per-boot control token and the loopback control/auth surface
# (init_control_token/remove_control_token, _control_authorised, the control
# routes) live in wifi_web.py.

# AP / host configuration.
# AP_IFNAME remains the compatibility default for interface-aware helper calls;
# hotspot operations resolve the adapter dynamically via resolve_hotspot_adapter():
# built-in radio when present, otherwise a USB adapter that is not the active
# client when possible (e.g. Pi 2 / multi-USB recovery hardware).
AP_IFNAME = "wlan0"
AP_CONNECTION_NAME = "Hotspot"  # default/fixed name for our AP connection


def resolve_hotspot_adapter(adapters: list, active_ifname: Optional[str] = None) -> Optional[object]:
    """Return the adapter that should host the setup hotspot, or None.

    Prefers the built-in radio so USB removal never eliminates the recovery
    path on hardware that has one. On hardware without a built-in radio
    (e.g. Pi 2), falls back to USB: the sole managed USB adapter, or with
    multiple USB adapters the first deterministic candidate that is not the
    active client. Returns None when no adapter is present.
    """
    if active_ifname is None:
        with state_lock:
            active_ifname = STATE.active_client_ifname
    builtin = wifi_net.resolve_builtin(adapters)
    if builtin is not None:
        return builtin
    usb = wifi_net.usb_candidates(adapters)
    if len(usb) == 1:
        return usb[0]
    if usb:
        for adapter in usb:
            if adapter.ifname != active_ifname:
                return adapter
        return usb[0]
    return None


def resolve_recovery_ifname() -> Optional[str]:
    """Return the interface name for the setup hotspot, or None.

    Uses resolve_hotspot_adapter() to select the interface: built-in radio
    when available, sole managed USB adapter on hardware without a built-in
    radio (e.g. Pi 2).  Returns None when no suitable adapter can be
    identified; the caller logs an error and does not start AP mode.
    """
    try:
        adapters = wifi_net.discover_adapters()
    except Exception as e:
        logger.warning("Adapter discovery failed while resolving recovery interface: %s", e)
        adapters = []
    adapter = resolve_hotspot_adapter(adapters)
    if adapter is not None:
        if adapter.is_usb:
            logger.info(
                "No built-in Wi-Fi adapter; using sole USB adapter %s as hotspot interface",
                adapter.ifname,
            )
        return adapter.ifname
    logger.warning("No suitable Wi-Fi adapter identified for recovery hotspot")
    return None

# Resolved once at startup; None disables avahi mDNS hostname monitoring.
_DBUS_SEND: Optional[str] = shutil.which("dbus-send")

# Resolved once at startup; None -> AP station count is unknown, and the rejoin
# probe treats unknown as "stations associated" (never yank the AP on missing
# information).
_IW: Optional[str] = shutil.which("iw")


def hotspot_station_count(ifname: str) -> Optional[int]:
    """Number of stations associated to the AP on *ifname*, or None if unknown.

    Uses ``iw dev <ifname> station dump`` and counts the ``Station`` records.
    Returns None when the iw binary is unavailable or the command fails; callers
    treat unknown as "assume a client is on the portal" so the AP is never torn
    down on missing information.  Bounded like every other subprocess.
    """
    if not ifname or _IW is None:
        return None
    r = run_cmd([_IW, "dev", ifname, "station", "dump"], timeout=NMCLI_QUICK_TIMEOUT)
    if r.returncode != 0:
        return None
    return sum(1 for line in r.stdout.splitlines()
               if line.strip().lower().startswith("station "))

# The Flask app is built from WEB_CTX further down, once every callable the
# routes need is defined; wifi_watcher.app stays importable there for the
# Flask-test-client tests and the __main__ app.run() startup.

# ** LOGGING **

_last_logged_values: dict[str, object] = {}
_last_throttled_log: dict[str, float] = {}


# Log de-duplication — three complementary mechanisms, one job each.
# New code should pick the one matching intent:
#   * DeduplicateFilter — transport-level; drops any record identical to one seen
#     in the last 60 s.  A blanket backstop; do not rely on it for semantics.
#   * log_on_change(key, value, ...) — semantic *transitions*; emit only when a
#     tracked value changes (state/mode flips).  Use for "X changed -> Y".
#   * log_throttled(key, msg, interval=...) — time-window *rate limit*; emit at
#     most once per `interval` seconds for a condition that stays true (avoids
#     hammering while a persistent condition holds).  Use for repeated warnings.
def log_on_change(key: str, value: object, msg: str, level: int = logging.INFO) -> None:
    """Log msg at *level* only when (key -> value) changes (semantic transition)."""
    prev = _last_logged_values.get(key, object())
    if prev != value:
        _last_logged_values[key] = value
        logger.log(level, "%s", msg)


def log_throttled(key: str, msg: str, *, interval: float,
                  level: int = logging.WARNING, now: "Optional[float]" = None) -> bool:
    """Log msg at most once per *interval* seconds per *key* (time-window throttle).

    The shared rate-limiter for a condition that stays true across passes.  Returns
    True when it logged this call.  Unlocked module state, matching log_on_change
    (best-effort; a race at most emits one extra line).
    """
    if now is None:
        now = time.monotonic()
    prev = _last_throttled_log.get(key)
    if prev is None or (now - prev) >= interval:
        _last_throttled_log[key] = now
        logger.log(level, "%s", msg)
        return True
    return False


# ** SETUP/AP MODE **

def clear_apmode_flag() -> None:
    try:
        if os.path.exists(AP_MODE_FLAG_PATH):
            logger.info("Removing stale AP flag at startup: %s", AP_MODE_FLAG_PATH)
            os.remove(AP_MODE_FLAG_PATH)
    except Exception:
        logger.warning("Failed to remove %s at startup", AP_MODE_FLAG_PATH)


def update_apmode_flag(in_setup: bool) -> None:
    """Create or remove the AP mode flag file at AP_MODE_FLAG_PATH."""
    try:
        if in_setup:
            if not os.path.exists(AP_MODE_FLAG_PATH):
                with open(AP_MODE_FLAG_PATH, "w", encoding="utf-8") as f:
                    f.write("1\n")
                logger.info("Created AP mode flag file at %s", AP_MODE_FLAG_PATH)
        else:
            if os.path.exists(AP_MODE_FLAG_PATH):
                os.remove(AP_MODE_FLAG_PATH)
                logger.info("Removed AP mode flag file at %s", AP_MODE_FLAG_PATH)
    except Exception as e:
        logger.warning("Error updating AP mode flag file %s: %s", AP_MODE_FLAG_PATH, e)


def hotspot_purpose() -> "Optional[wifi_policy.HotspotPurpose]":
    """Return the purpose of the active hotspot session, or None when not hosting."""
    with state_lock:
        return STATE.hotspot.purpose if STATE.hotspot else None


def _hotspot_blocks_eth(session) -> bool:
    """True when a user-initiated (non eth-suppressible) hotspot is active.

    EXPLICIT_RECONFIGURE / MANUAL hotspots are AP-to-connect-a-new-network and
    must not be torn down just because usable Ethernet appears.
    """
    return session is not None and not wifi_policy.PURPOSE_TABLE[session.purpose].eth_suppressible


def enter_setup_mode(purpose: "wifi_policy.HotspotPurpose", reason: str = "",
                     rollback: "Optional[RollbackSnapshot]" = None) -> None:
    """Transition into SetupMode and start the hotspot for *purpose*.

    The session lifetime/exit policy is driven entirely by
    wifi_policy.PURPOSE_TABLE[purpose]: FIRST_RUN runs indefinitely; every
    other purpose runs for wifi_policy.AP_MAX_DURATION (30 min).  There is no
    once-per-boot budget — the recovery hotspot is enterable whenever the
    device is offline.
    """
    with state_lock:
        if STATE.setup_mode:
            return
        STATE.setup_mode = True
        STATE.hotspot = HotspotSession(
            purpose=purpose, entered_at=time.monotonic(), rollback=rollback,
        )
        # Fresh session: clear any rejoin-prompt / dismissal state.
        STATE.saved_ssid_visible = False
        STATE.saved_ssid_name = ""
        STATE.rejoin_dismissed = False

    logger.info("Entering SetupMode (%s). Reason: %s", purpose.value, reason)
    # The controller brings the AP up and sets the nginx flag only when it
    # genuinely started (start_ap_mode may abort and clear setup_mode).
    hotspot_controller.start()

def leave_setup_mode(reason: str = "") -> None:
    """Transition out of SetupMode and stop AP mode, if currently active."""
    with state_lock:
        if not STATE.setup_mode:
            return
        now = time.monotonic()
        STATE.setup_mode = False
        STATE.hotspot = None
        STATE.last_active_path_seen = now
        # Session over: clear the rejoin-prompt / dismissal state and any
        # in-progress reconnect-saved episode (the session it was restoring is
        # gone).
        STATE.saved_ssid_visible = False
        STATE.saved_ssid_name = ""
        STATE.rejoin_dismissed = False
        STATE.reconnect_episode = None

    logger.info("Leaving SetupMode. Reason: %s", reason)
    # The controller tears down the AP before removing the flag so nginx does not
    # route traffic to the main webui while the setup SSID is still broadcasting.
    hotspot_controller.stop()

def get_configured_network_state() -> "wifi_net.NetworkState":
    """Return the resolved configured network state (helper-validated).

    Resolution order: valid network.json -> legacy /opt/autostream/ssid ->
    unconfigured.  Paths are taken from the watcher's (test-redirectable)
    constants so the helper and watcher agree on locations.
    """
    return wifi_net.load_network_state(
        state_path=NETWORK_STATE_PATH,
        legacy_path=CONFIGURED_SSID,
    )


def get_configured_wifi_connection_name() -> Optional[str]:
    """Return the configured *client* WiFi connection name, if any.

    The authoritative source is /etc/autostream-network.json, with the legacy
    /opt/autostream/ssid file as a compatibility fallback.  Empty means WiFi is
    unconfigured.
    """
    name = get_configured_network_state().connection_name
    return name or None


def is_wifi_configured() -> bool:
    """True if a WiFi client connection has been configured."""
    return get_configured_wifi_connection_name() is not None


def is_wifi_connected(ifname: str = AP_IFNAME) -> bool:
    """True if *ifname* is connected to a non-AP WiFi network.

    Thin policy wrapper over the interface-aware helper.
    """
    return wifi_net.is_wifi_connected(ifname)

def is_wifi_client_healthy(
    ifname: str = AP_IFNAME,
    wifi_connected: Optional[bool] = None,
) -> bool:
    """
    Interface-specific WiFi "health" using the same logic as initial validation:
    - connected to a non-AP WiFi profile on *ifname*;
    - non-link-local RFC1918 IPv4 address on *ifname*;
    - interface-specific reachable default gateway on *ifname*.

    The gateway check is now scoped to *ifname* so another adapter's route or
    Ethernet cannot make a failed Wi-Fi adapter look healthy.
    """
    if wifi_connected is None:
        wifi_connected = is_wifi_connected(ifname)

    if not wifi_connected:
        logger.debug("WiFi client health: not connected on %s", ifname)
        return False
    if not is_local_ipv4_ready(ifname):
        logger.debug("WiFi client health: no local IPv4 on %s", ifname)
        return False
    gw_ok = is_gateway_reachable(ifname)
    if not gw_ok:
        logger.debug("WiFi client health: gateway unreachable on %s", ifname)
    return gw_ok


def wired_carrier_ifnames(sys_root: str = "/sys/class/net") -> list[str]:
    """Return wired ethernet interface names that currently report carrier."""
    # Traditional + predictable ethernet names
    patterns = ("eth*", "en*")
    found: list[str] = []

    for pat in patterns:
        for path in glob.glob(os.path.join(sys_root, pat, "carrier")):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    if f.read().strip() == "1":
                        found.append(os.path.basename(os.path.dirname(path)))
            except OSError:
                # Interface disappeared or permissions issue; ignore
                continue

    return sorted(found)


def is_wired_connected() -> bool:
    """Return True if any wired (ethernet) interface has carrier."""
    return bool(wired_carrier_ifnames())


def is_wired_path_healthy(ifname: str) -> bool:
    """True when a wired interface has carrier plus a usable non-link-local IPv4."""
    return ifname in wired_carrier_ifnames() and wifi_net.interface_has_usable_ipv4(ifname)


def any_wired_path_healthy() -> bool:
    """True when any wired ethernet interface is a usable local network path."""
    return any(wifi_net.interface_has_usable_ipv4(ifname) for ifname in wired_carrier_ifnames())


def first_healthy_wired_ifname() -> Optional[str]:
    """Return the first wired carrier interface with usable IPv4, or None."""
    for ifname in wired_carrier_ifnames():
        if wifi_net.interface_has_usable_ipv4(ifname):
            return ifname
    return None


def is_gateway_reachable(ifname: str = AP_IFNAME) -> bool:
    """Interface-specific kernel gateway reachability (policy wrapper).

    Scoped to *ifname* so another adapter's route cannot mask a failed adapter.
    """
    return wifi_net.is_gateway_reachable(ifname, prime_fn=prime_gateway)


def is_local_ipv4_ready(ifname: str = AP_IFNAME) -> bool:
    """Local-only connectivity check on *ifname* (policy wrapper)."""
    return wifi_net.is_local_ipv4_ready(ifname)


def get_ap_ssid(ifname: str) -> str:
    """Generate an SSID for the AP based on the interface MAC address.

    Format: <AP_PREFIX>_XXXX where XXXX are the last four hex digits of the MAC.
    """
    try:
        with open(f"/sys/class/net/{ifname}/address", "r", encoding="utf-8") as f:
            mac = f.read().strip().replace(":", "")
    except OSError as e:
        logger.warning("Error reading MAC address for %s: %s; using default SSID", ifname, e)
        return f"{AP_PREFIX}_SETUP"
    suffix = mac[-4:].upper() if len(mac) >= 4 else "0000"
    ssid = f"{AP_PREFIX}_{suffix}"
    logger.info("Using AP SSID '%s' for interface %s", ssid, ifname)
    return ssid


# ** WIFI CONFIGURATION **

def _get_active_wifi_connection_name(ifname: str = AP_IFNAME) -> str:
    """Active connection profile name on *ifname* (policy wrapper over helper)."""
    return wifi_net.get_active_wifi_connection_name(ifname)

def _get_active_wifi_ssid(ifname: str = AP_IFNAME) -> str:
    """SSID currently in use on *ifname* (policy wrapper over helper)."""
    return wifi_net.get_active_wifi_ssid(ifname)

def _commit_network_state(conn_name: str, conn_uuid: str = "") -> None:
    """Persist a successfully validated connection to both state files.

    Writes /etc/autostream-network.json (authoritative) plus the legacy
    /opt/autostream/ssid mirror.  Resolves the NetworkManager UUID when not
    supplied so future activation/deletion can prefer ``uuid <...>``.
    """
    if not conn_uuid:
        try:
            conn_uuid = wifi_net.resolve_connection_uuid_for_name(conn_name)
        except Exception:
            conn_uuid = ""
    try:
        wifi_net.save_network_state(
            wifi_net.NetworkState(connection_name=conn_name, connection_uuid=conn_uuid),
            state_path=NETWORK_STATE_PATH,
            legacy_path=CONFIGURED_SSID,
        )
        logger.info(
            "Committed network state for connection '%s' (uuid=%s)",
            conn_name, conn_uuid or "unresolved",
        )
    except Exception as e:
        logger.error("Could not persist network state for '%s': %s", conn_name, e)
    # A new committed SSID invalidates any BSSID table entries from the previous one.
    with state_lock:
        wifi_policy.clear_bssid_table(STATE.bssid_table)


def _try_candidate_on_adapter(ssid: str, password: str, target) -> bool:
    """Create, activate and validate a candidate profile on one adapter.

    Implements the rollback-safe candidate sequence. The PSK never
    appears in logs. On success the new connection is committed (name+UUID) and
    the legacy mirror is updated; on failure only the candidate profile is
    deleted by UUID, leaving the previous committed profile untouched.
    """
    ifname = target.ifname
    con_name = wifi_net.generate_candidate_name()

    # 1-2) create + configure the uniquely named candidate.
    cmds, log_cmds = wifi_net.configure_candidate_cmds(con_name, ifname, ssid, password)
    for cmd, log_cmd in zip(cmds, log_cmds):
        r = nm.run_candidate_setup(cmd, log_cmd=log_cmd)
        if r.returncode != 0:
            logger.warning("Candidate profile setup step failed on %s", ifname)
            # Best-effort cleanup of a partially created profile by name.
            nm.delete_connection(con_name)
            return False

    # 3) obtain its UUID.
    uuid = wifi_net.get_profile_uuid(con_name)
    if not uuid:
        logger.warning("Could not resolve candidate UUID for '%s'", con_name)
        nm.delete_connection(con_name)
        return False

    # 4) clear cross-adapter restrictions EXCEPT connection.interface-name,
    #    which may remain set until the first activation succeeds.
    pre_keys = tuple(
        k for k in wifi_net.CROSS_ADAPTER_RESTRICTIONS
        if k != "connection.interface-name"
    )
    nm.clear_restrictions(uuid, pre_keys)

    # 5) activate explicitly on the target interface.
    r_up = nm.activate(uuid, con_name, ifname)
    if r_up.returncode != 0:
        logger.warning("Candidate activation failed on %s (rc=%d)", ifname, r_up.returncode)

    # 6) validate via the shared tail (net-absent short-circuit -> local IPv4 ->
    #    interface-specific gateway); the net-absent fix reaches this path too.
    ok = _validate_activation(ifname, r_up)
    logger.info("Candidate %s: validated=%s", ifname, ok)

    if not ok:
        # 9) on failure delete only the candidate; keep the previous committed profile.
        logger.warning("Candidate validation failed on %s; deleting candidate", ifname)
        nm.delete_by_uuid(uuid)
        return False

    # 7) clear connection.interface-name so the committed profile is portable.
    nm.clear_restrictions(uuid, ("connection.interface-name",))

    # 8) commit name/UUID + legacy mirror.
    _commit_network_state(con_name, uuid)
    logger.info("WiFi candidate committed on %s (ssid='%s')", ifname, ssid)
    return True


def attempt_on_targets(targets: list, attempt_fn) -> "Optional[object]":
    """Try client activation on target adapters with per-target AP handling.

    Returns the target adapter that came up (so the caller applies the session
    success tail in its own context), or None when every target failed.
    The success tail (set-active / leave-setup / verify-avahi) is NOT applied
    here — this function has two calling contexts, one of which is the worker
    thread (the apply_credentials job), and the worker must never apply a
    session success tail.  The per-target AP stop-before-attempt and
    rebuild-on-failure mechanics are the sanctioned worker-side AP writes and
    stay here unchanged.
    """
    hotspot_adapter = resolve_hotspot_adapter(wifi_net.discover_adapters())
    for target in targets:
        with state_lock:
            in_setup_now = STATE.setup_mode
        is_hotspot_target = hotspot_adapter is not None and target.ifname == hotspot_adapter.ifname
        ap_stopped_for_hotspot = False
        if in_setup_now and is_hotspot_target:
            stop_ap_mode()
            ap_stopped_for_hotspot = True

        if attempt_fn(target):
            return target

        if ap_stopped_for_hotspot:
            logger.warning(
                "Client attempt on hotspot adapter (%s) failed after AP teardown; recreating hotspot",
                target.ifname,
            )
            # The hotspot session is intact (stop_ap_mode tore down only the
            # nmcli AP, not STATE.hotspot); the controller restarts the radio side.
            hotspot_controller.rebuild()

    return None


def configure_wifi_with_nmcli(ssid: str, password: str) -> "Optional[object]":
    """Apply submitted credentials using the rollback-safe candidate sequence.

    Does NOT use ``nmcli device wifi connect`` (which would reuse/modify an
    existing profile and undermine rollback). A uniquely named candidate profile
    is created, validated, and only committed on success.

    Adapter order: USB adapters that saw the SSID first, then built-in, then
    best-effort. If a USB attempt fails and built-in saw the SSID, built-in is
    attempted once before giving up.

    Returns the adapter the credentials came up on (for the loop to apply the
    session success tail), or None when no adapter succeeded.  Runs on
    the worker thread (the apply_credentials job), so it applies no session
    tail itself.
    """
    merged, builtin_scan_known = scan_all_networks()
    adapters = wifi_net.discover_adapters()
    order = wifi_net.connection_target_order(ssid, adapters, merged, builtin_scan_known)
    if not order:
        logger.warning("No usable Wi-Fi adapter to apply credentials for '%s'", ssid)
        return None

    return attempt_on_targets(
        order,
        lambda target: _try_candidate_on_adapter(ssid, password, target),
    )


def wait_for_connection(ifname: str = AP_IFNAME, timeout: int = 20, interval: int = 2) -> bool:
    """Wait up to 'timeout' seconds for *local* IPv4 readiness on *ifname*.

    Success means NetworkManager reports the interface connected/activated with
    a non-link-local RFC1918 IPv4 address. (The ongoing health monitor uses the
    gateway heuristic separately.)
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if is_local_ipv4_ready(ifname):
            return True
        time.sleep(interval)
    logger.info("Timed out waiting %ds for local IPv4 on %s", timeout, ifname)
    return False


def _write_dnsmasq_runtime(recovery_ifname: str) -> bool:
    """Validate the recovery interface and write the runtime dnsmasq config.

    Returns True on success.  Logs WARNING and returns False on any failure so
    the caller can abort dnsmasq startup rather than starting it with a stale
    or wrong config.
    """
    # Validate against discovered adapters: must match the resolved hotspot adapter.
    resolved = resolve_recovery_ifname()
    if resolved is not None and recovery_ifname != resolved:
        logger.warning(
            "Refusing dnsmasq runtime config: %s is not the resolved hotspot adapter (%s)",
            recovery_ifname, resolved,
        )
        return False
    try:
        wifi_net.write_dnsmasq_runtime_config(
            DNSMASQ_TEMPLATE_PATH, DNSMASQ_RUNTIME_PATH, recovery_ifname,
        )
        logger.info("Wrote dnsmasq runtime config for interface %s", recovery_ifname)
        return True
    except Exception as e:
        logger.warning("dnsmasq runtime setup failed: %s", e)
        return False


def start_ap_mode() -> None:
    """Put the WiFi adapter into open AP (hotspot) mode using nmcli.

    The SSID is autostream_XXXX where XXXX are the last four hex digits of the
    adapter's MAC address. The hotspot is open (no password). The Flask app
    acts as the captive portal HTTP server; DNS/DHCP redirection is assumed to
    be handled elsewhere.
    """
    with ap_mode_lock:
        # Guard against a race where leave_setup_mode ran (from the credential-apply or the
        # ethernet-suppression path) between enter_setup_mode setting setup_mode=True and
        # this function acquiring ap_mode_lock.  In that case stop_ap_mode has already
        # run and setup_mode is False; starting AP now would leave it running unmanaged.
        with state_lock:
            if not STATE.setup_mode:
                logger.warning("start_ap_mode: setup_mode cleared before AP could start; aborting")
                return

        logger.info("Enabling AP mode for SetupMode")

        # Use the built-in radio when available; fall back to the sole managed
        # USB adapter on hardware without a built-in radio (e.g. Pi 2).  If
        # neither can be identified unambiguously, abort rather than selecting
        # an arbitrary interface.
        recovery_ifname = resolve_recovery_ifname()
        if recovery_ifname is None:
            logger.error(
                "Cannot start hotspot: no suitable Wi-Fi adapter identified "
                "(no built-in radio, no unambiguous USB adapter); aborting AP mode"
            )
            with state_lock:
                STATE.setup_mode = False
                STATE.hotspot = None
            return

        ssid = get_ap_ssid(recovery_ifname)

        # Delete any existing connection with the same name (also takes it down).
        nm.delete_connection(AP_CONNECTION_NAME)

        # Create the connection on the hotspot interface.
        logger.info(
            "Creating AP connection '%s' with SSID '%s' on %s",
            AP_CONNECTION_NAME, ssid, recovery_ifname,
        )
        r_add = nm.add_ap_connection(recovery_ifname, ssid, AP_CONNECTION_NAME)
        if r_add.returncode != 0:
            logger.error(
                "Failed to create AP connection '%s' on %s (rc=%d): %s",
                AP_CONNECTION_NAME, recovery_ifname, r_add.returncode, r_add.stderr.strip(),
            )
            with state_lock:
                STATE.setup_mode = False
                STATE.hotspot = None
            return

        # Generate the runtime dnsmasq config bound to the validated recovery
        # interface, then start the dedicated dnsmasq service that reads it.
        # Only start dnsmasq when the runtime config was written successfully;
        # starting it against a stale or missing config would serve wrong data.
        dnsmasq_ready = _write_dnsmasq_runtime(recovery_ifname)

        # Bring up the AP connection.  Checked before dnsmasq/the nginx flag are
        # touched: HotspotController.start only sets the flag while setup_mode is
        # still true, so clearing it here (mirroring the abort paths above) is
        # what keeps nginx from routing to a portal that never actually started.
        r_up = nm.activate_ap(AP_CONNECTION_NAME, recovery_ifname)
        if r_up.returncode != 0:
            logger.error(
                "Failed to activate AP connection '%s' on %s (rc=%d): %s",
                AP_CONNECTION_NAME, recovery_ifname, r_up.returncode, r_up.stderr.strip(),
            )
            with state_lock:
                STATE.setup_mode = False
                STATE.hotspot = None
            return

        if dnsmasq_ready:
            run_cmd(["systemctl", "start", DNSMASQ_SERVICE], timeout=NMCLI_QUICK_TIMEOUT)
        else:
            logger.warning("dnsmasq not started because runtime config write failed")

        # Hostname may change at runtime; construct the portal URL dynamically.
        current_host = get_system_hostname()
        logger.info("Setup portal expected at http://%s.local/setup while in AP mode", current_host)


def stop_ap_mode() -> None:
    """Tear down AP mode.

    This is primarily used when leaving SetupMode via the monitor loop.
    """
    with ap_mode_lock:
        logger.info("Disabling AP mode after leaving SetupMode")
        # Stop the dedicated dnsmasq service before removing its runtime config
        # so the service never observes a half-deleted file.
        run_cmd(["systemctl", "stop", DNSMASQ_SERVICE], timeout=NMCLI_QUICK_TIMEOUT)
        wifi_net.remove_dnsmasq_runtime_config(DNSMASQ_RUNTIME_PATH)
        nm.delete_connection(AP_CONNECTION_NAME)


def scan_all_networks() -> tuple[list[dict], bool]:
    """Live-scan every detected, managed Wi-Fi adapter and merge by exact SSID.

    Returns ``(networks, builtin_scan_known)`` where each network record carries
    ssid/signal/builtin_visible/usb_visible/adapter_macs.  No
    caching is performed; an individual adapter scan failure marks that
    adapter's visibility unknown for this response only.
    """
    adapters = wifi_net.discover_adapters()
    builtin = wifi_net.resolve_builtin(adapters)
    usb = wifi_net.usb_candidates(adapters)

    builtin_scan = wifi_net.scan_adapter(builtin) if builtin is not None else None
    builtin_scan_known = builtin_scan is not None

    usb_scans = [wifi_net.scan_adapter(a) for a in usb]
    merged = wifi_net.merge_scans(
        builtin_scan,
        usb_scans,
        builtin_mac=(builtin.permanent_mac if builtin else ""),
        usb_macs=[a.permanent_mac for a in usb],
    )
    return merged, builtin_scan_known


def submit_apply_credentials(ssid: str, pw: str) -> bool:
    """Enqueue a credential-apply job on the shared worker.

    Replaces the Flask-spawned apply thread: the /setup route calls this instead of
    starting its own thread, so the credential apply is serialised with the loop's
    activations by the transitioning gate (one effectful transition at a time — the
    unmanaged second writer is gone).  The wait-page "applying" status is set
    BEFORE the job is enqueued (not after) so a very fast worker/loop result can
    never be applied and then clobbered back to "applying" by this call; the
    worker runs configure_wifi_with_nmcli and the loop applies the ok/failed tail
    (apply_activation_result).  Returns False when the worker is busy with
    another in-flight transition (the caller keeps the user on setup to retry),
    rolling the "applying" marking back first.
    """
    with state_lock:
        if STATE.apply_in_progress:
            return False
        prev_result = STATE.last_apply_result
        prev_error = STATE.last_apply_error
        STATE.apply_in_progress = True
        STATE.last_apply_result = "applying"
        STATE.last_apply_error = ""
    # The session success tail (set-active / leave-setup / avahi) is applied by
    # apply_activation_result on the loop thread — exactly as the
    # other job kinds — so carry the leave-setup flags the shared tail reads.
    job = ActivationJob(epoch=_next_activation_epoch(), kind="apply_credentials",
                        ifname="", ssid=ssid, password=pw,
                        on_success_leaves_setup=True,
                        leave_reason="WiFi client connection succeeded")
    if not submit_activation_job(job):
        with state_lock:
            STATE.apply_in_progress = False
            STATE.last_apply_result = prev_result
            STATE.last_apply_error = prev_error
        return False
    return True

# ** TRANSACTIONAL CHANGE-WI-FI FLOW **

def _snapshot_rollback() -> "RollbackSnapshot":
    """Return the current committed profile + active adapter as a rollback target."""
    state = get_configured_network_state()
    with state_lock:
        active_mac = STATE.active_client_mac
    return RollbackSnapshot(
        connection_name=state.connection_name,
        connection_uuid=state.connection_uuid,
        adapter_mac=active_mac,
    )


def apply_log_level(level: str, ttl_seconds: Optional[int]) -> None:
    """Apply a runtime log level, optionally temporary for *ttl_seconds*.

    Without a TTL the level becomes the runtime level until the service
    restarts or another valid request changes it; the startup default
    (AUTOSTREAM_WIFI_LOG_LEVEL) is preserved for revert.
    """
    levelno = RUNTIME_LOG_LEVELS[level]
    logging.getLogger().setLevel(levelno)
    now = time.monotonic()
    with state_lock:
        if ttl_seconds:
            STATE.temporary_log_level = level
            STATE.temporary_log_level_until = now + ttl_seconds
        else:
            STATE.temporary_log_level = ""
            STATE.temporary_log_level_until = None
            STATE.default_log_level_name = level
    if ttl_seconds:
        logger.info("Runtime log level changed to %s for %ds", level, ttl_seconds)
    else:
        logger.info("Runtime log level changed to %s", level)


def revert_expired_log_level(now: Optional[float] = None) -> None:
    """Revert a temporary runtime log level once its TTL expires."""
    if now is None:
        now = time.monotonic()
    with state_lock:
        until = STATE.temporary_log_level_until
        if until is None or now < until:
            return
        default = STATE.default_log_level_name or "info"
        STATE.temporary_log_level = ""
        STATE.temporary_log_level_until = None
    logging.getLogger().setLevel(RUNTIME_LOG_LEVELS.get(default, logging.INFO))
    logger.info("Runtime log level reverted to %s", default)


def process_control_action(action: str, params: Optional[dict] = None) -> None:
    """Consume one queued control action in the monitor loop."""
    params = params or {}
    with state_lock:
        STATE.control_in_progress = True
        STATE.last_control_action = action
        STATE.last_control_error = ""
    try:
        if action == "start_setup":
            start_explicit_setup()
            result = "ok"
        elif action == "manual_ap":
            # Enter a MANUAL hotspot on a WebUI request (overrides the boot-AP
            # cutoff).  A MANUAL session is not torn down by Ethernet.  A no-op
            # when a hotspot session is already active.
            with state_lock:
                already_in_ap = STATE.setup_mode
            if not already_in_ap:
                enter_setup_mode(
                    wifi_policy.HotspotPurpose.MANUAL,
                    reason=f"manual_request: {params.get('reason') or 'UserRequest'}")
            result = "ok"
        elif action == "reconnect_saved":
            # Start an async episode (single-target restore per pass); "ok" here
            # means the episode was accepted, not that the join has completed.
            result = "ok" if start_reconnect_saved_episode("retain_hotspot") else "failed"
        elif action == "set_log_level":
            apply_log_level(params.get("level"), params.get("ttl_seconds"))
            result = "ok"
        elif action == "clear_adapter":
            wifi_recovery.clear_adapter_fault_state(RECOVERY_CTX, params.get("adapter", ""))
            result = "ok"
        elif action == "disable_adapter":
            wifi_recovery.disable_adapter(RECOVERY_CTX, params.get("adapter", ""))
            result = "ok"
        elif action == "enable_adapter":
            wifi_recovery.enable_adapter(RECOVERY_CTX, params.get("adapter", ""))
            result = "ok"
        else:
            result = "failed"
    except Exception as e:
        logger.warning("Control action '%s' raised: %s", action, e)
        result = "failed"
        with state_lock:
            STATE.last_control_error = str(e)
    with state_lock:
        STATE.control_in_progress = False
        STATE.last_control_result = result


def start_explicit_setup() -> None:
    """Begin an explicit Change-Wi-Fi reconfiguration session.

    Snapshots the current profile/adapter, disconnects the current client
    session (without deleting its profile), and enters an EXPLICIT_RECONFIGURE
    hotspot.  The 30-minute deadline, no-eth-suppression, and rollback policy all
    come from wifi_policy.PURPOSE_TABLE[EXPLICIT_RECONFIGURE].
    """
    rollback = _snapshot_rollback()
    # Disconnect the current client session without deleting its profile.
    with state_lock:
        active_ifname = STATE.active_client_ifname
    if active_ifname:
        nm.disconnect_device(active_ifname)
    logger.info("Explicit network setup starting (explicit_reconfigure)")
    enter_setup_mode(wifi_policy.HotspotPurpose.EXPLICIT_RECONFIGURE,
                     reason="explicit_reconfigure", rollback=rollback)


def start_reconnect_saved_episode(failure_tail: str = "retain_hotspot") -> bool:
    return wifi_adoption.start_reconnect_saved_episode(ADOPTION_CTX, failure_tail)


def _submit_next_reconnect_target() -> bool:
    return wifi_adoption._submit_next_reconnect_target(ADOPTION_CTX)


def _advance_reconnect_episode(result: "ActivationResult") -> None:
    wifi_adoption._advance_reconnect_episode(ADOPTION_CTX, result)


def _finish_reconnect_episode_failure() -> None:
    wifi_adoption._finish_reconnect_episode_failure(ADOPTION_CTX)


def step_reconnect_episode(pre: "PreFactsContext") -> "Verdict":
    return wifi_adoption.step_reconnect_episode(ADOPTION_CTX, pre)


def handle_reconfigure_timeout() -> None:
    """30-minute explicit-reconfiguration timeout rollback (starts an episode)."""
    logger.info("Explicit network setup timed out after %ds; restoring previous", wifi_policy.AP_MAX_DURATION)
    start_reconnect_saved_episode(failure_tail="reconfigure_timeout")



# ** MAIN NETWORK STATUS MONITORING LOOP **


def _make_health_memo():
    """Return a per-pass memo that samples client health once per (pass, ifname).

    ``is_wifi_client_healthy`` performs per-interface gateway-reachability and
    IPv4 probes (subprocess cost on the Pi Zero).  Several in-pass consumers —
    finalize_active_client_and_health, gather_recovery_facts, and
    build_network_status_snapshot — used to re-sample it independently, so two
    samples in one pass could disagree (the snapshot could contradict the
    debounced verdict it publishes).  Memoising per ifname closes that hole and
    cuts the per-tick subprocess load.  Validators outside the loop keep calling
    is_wifi_client_healthy directly (fresh) — they must not read a stale sample.
    """
    cache: dict = {}

    def memo(ifname: str = AP_IFNAME, wifi_connected: Optional[bool] = None) -> bool:
        if ifname not in cache:
            cache[ifname] = is_wifi_client_healthy(ifname, wifi_connected=wifi_connected)
        return cache[ifname]

    return memo


@dataclass(frozen=True)
class Facts:
    """One immutable per-tick snapshot of network facts.

    Gathered once at the top of each monitor pass via gather_facts() so every
    in-pass decision reads the same view of the world (no within-tick
    inconsistency) and the dominant subprocess cost on the Pi Zero (discovery,
    wired probes, address enumeration) is paid once per pass rather than per
    decision site.  Playback is intentionally NOT a field here: it is resolved
    lazily via a per-pass memoised callable (see _make_playing_status_memo)
    because it is comparatively expensive and not always needed.  ``health_memo``
    is the per-pass client-health memo: the in-pass consumers share it so
    is_wifi_client_healthy is sampled at most once per (pass, ifname).
    """
    wifi_configured: bool
    adapters: list
    wired_connected: bool
    wired_ok: bool
    active_client: Optional[object]
    addresses: dict
    taken_at: float
    health_memo: object = field(default_factory=_make_health_memo)


def gather_facts() -> "Facts":
    """Gather the single immutable Facts snapshot for one monitor pass.

    The sole caller of discover_adapters/is_wired_connected/any_wired_path_healthy/
    resolve_active_client/list_interface_addresses for the pass.  Downstream
    decisions read the returned Facts rather than re-querying these helpers.
    """
    adapters = wifi_net.discover_adapters()
    return Facts(
        wifi_configured=is_wifi_configured(),
        adapters=adapters,
        wired_connected=is_wired_connected(),
        wired_ok=any_wired_path_healthy(),
        active_client=resolve_active_client(adapters),
        addresses=wifi_net.list_interface_addresses(),
        taken_at=time.monotonic(),
    )


# The pure forward mode classifier lives in wifi_policy (it reads only plain
# state/facts fields + policy constants); the loop calls
# wifi_policy.next_mode(STATE, facts) directly.


# ** RECOVERY LADDER (recovery-ladder unification) **
#
# The recovery decision is a second pure classifier alongside next_mode:
# wifi_policy.next_recovery_action(state, recovery_facts) ->
# wifi_policy.RecoveryAction.  It lives in wifi_policy (with RecoveryFacts /
# RecoveryKind / RecoveryAction); the watcher owns only
# gather_recovery_facts(), the effectful gatherer that adapts the per-pass
# runtime facts into the plain RecoveryFacts snapshot.


def gather_recovery_facts(facts: "Facts") -> "wifi_policy.RecoveryFacts":
    """Gather the recovery-ladder snapshot from the per-pass Facts.

    Reuses Facts.adapters (single discover per pass) and derives the per-adapter
    recovery facts via the shared wifi_recovery helper so the classifier and the
    status snapshot agree exactly.
    """
    now = facts.taken_at
    adapters = facts.adapters
    by_ifname = {a.ifname: _adapter_recovery_facts(a, now, facts.health_memo)
                 for a in adapters}

    builtin = wifi_net.resolve_builtin(adapters)
    usb = wifi_net.usb_candidates(adapters)
    hotspot = resolve_hotspot_adapter(adapters)
    with state_lock:
        in_setup = STATE.setup_mode
        onboard_budget_spent = (
            STATE.onboard_activation_failures >= ONBOARD_ACTIVATION_MAX_FAILURES)

    preferred_usb = ""
    for a in usb:
        rf = by_ifname.get(a.ifname)
        if (rf is not None and rf.managed and not rf.quarantined
                and not rf.noip_suppressed and not rf.disabled):
            preferred_usb = a.ifname
            break

    # The onboard is only offered as a client rung when it is actually usable
    # (managed, not quarantined, not no-IP-suppressed) — mirroring preferred_usb.
    # This is what lets the single decider skip a demoted/quarantined onboard on
    # a USB failure instead of blindly engaging it.  The async onboard-failure
    # bound: once onboard activations have failed
    # ONBOARD_ACTIVATION_MAX_FAILURES times this episode, stop offering it so the
    # ladder falls to the recovery hotspot instead of retrying onboard forever.
    onboard_ifname = ""
    if builtin is not None and not onboard_budget_spent:
        brf = by_ifname.get(builtin.ifname)
        if (brf is not None and brf.managed and not brf.quarantined
                and not brf.noip_suppressed and not brf.disabled):
            onboard_ifname = builtin.ifname

    return wifi_policy.RecoveryFacts(
        adapters_by_ifname=by_ifname,
        onboard_ifname=onboard_ifname,
        usb_ifnames=tuple(a.ifname for a in usb),
        preferred_usb_ifname=preferred_usb,
        hotspot_ifname=(hotspot.ifname if (in_setup and hotspot is not None) else ""),
        active_ifname=facts.active_client.ifname if facts.active_client else "",
        saved_configured=facts.wifi_configured,
        wired_ok=bool(facts.wired_ok),
        taken_at=now,
    )


# The recovery-ladder enums, action type, and pure classifier live in
# wifi_policy; apply sites call wifi_policy.next_recovery_action directly.


def _make_playing_status_memo():
    """Return a closure that resolves playback at most once per pass.

    query_playing_status() performs a loopback HTTP GET, so callers that gate on
    playback share one memoised result for the pass instead of re-querying.
    """
    cache: dict = {}

    def memo() -> Optional[bool]:
        if "value" not in cache:
            cache["value"] = query_playing_status()
        return cache["value"]

    return memo


def _sleep_or_finish_monitor_pass(run_once: bool) -> bool:
    """Sleep between monitor passes, or signal one-pass tests to return."""
    if run_once:
        return True
    time.sleep(NETWORK_MONITOR_INTERVAL)
    return False


def request_guarded_reboot(now: float, reason: str, *, domain: str, target=None) -> bool:
    """Single guarded NetworkDown reboot entry point for every reboot domain.

    Applies BOTH the persistent cross-boot guard and the shared in-process
    throttle to every request, so the gateway-down and 12-hour
    catch-all domains are now counted in the same 24h reboot window as dead-PHY.
    A reboot happens only when the persistent guard permits AND the in-process
    throttle allows; an accepted reboot stamps both.  Returns True only when a
    reboot was accepted (the caller may then own the pass).

    ``domain`` is a short label for logging; ``target`` (a dead-PHY TargetAdapter)
    is recorded in the guard entry when present, else the entry carries no adapter.
    """
    now_wall = time.time()
    if not wifi_recovery.dead_phy_reboot_guard_permits(RECOVERY_CTX, now_wall):
        logger.warning("Persistent reboot guard suppresses %s reboot (%s)", domain, reason)
        return False
    with state_lock:
        retry_after = STATE.conn_reboot_retry_after
    if now < retry_after:
        if retry_after == float('inf'):
            logger.debug("%s reboot accepted; waiting for system to reboot", domain)
        else:
            logger.debug("%s reboot suppressed; will retry in %.0fs", domain, retry_after - now)
        return False
    logger.warning("%s; requesting reboot", reason)
    accepted = reboot_system("NetworkDown")
    with state_lock:
        STATE.conn_reboot_retry_after = (
            float('inf') if accepted else now + REBOOT_RATE_LIMIT_RETRY
        )
    if accepted:
        wifi_recovery.record_dead_phy_reboot_request(RECOVERY_CTX, now_wall, target)
        return True
    return False


def _request_network_down_reboot(now: float, reason: str) -> None:
    """Request a guarded NetworkDown reboot (gateway-down / 12-hour catch-all).

    Thin wrapper over request_guarded_reboot so these domains share the
    persistent cross-boot guard and the in-process throttle with dead-PHY.
    """
    request_guarded_reboot(now, reason, domain="network_down")


# ** MONITOR-LOOP HANDLER DECOMPOSITION **
#
# The monitor loop is an ordered set of handlers, each returning a Verdict over
# one of three per-pass context types (strictly more info per stage), plus a small
# driver-owned LoopState for the one value that must persist across passes.


class Verdict(Enum):
    """A handler's result: it either owned the pass or falls through."""
    OWN_PASS = "own_pass"   # transition performed; driver sleeps/returns, loop restarts
    CONTINUE = "continue"   # fall through to the next handler in the same pass


# The per-pass phase context types (PreFactsContext / FactsContext /
# HealthContext / LoopState), the fact/health derivation, and the ordered
# step_* Verdict handlers live in platform/wifi_loop.py.  The seam is narrowed
# (WP-11 style) to a LoopContext exposing only the STATE, constants and
# callables the handlers use.  The context is built once (near the end of this
# module, once every callable it needs exists); these thin wrappers pass it
# and remain network_monitor_loop's entry points, bound via functools.partial
# where a handler also needs the cross-pass LoopState.

import wifi_loop

PreFactsContext = wifi_loop.PreFactsContext
FactsContext = wifi_loop.FactsContext
HealthContext = wifi_loop.HealthContext
LoopState = wifi_loop.LoopState


def finalize_active_client_and_health(fctx: "FactsContext") -> "HealthContext":
    return wifi_loop.finalize_active_client_and_health(LOOP_CTX, fctx)


def _connectivity_failure_is_hard(facts: "Facts", active_client, prev_mac: str) -> bool:
    return wifi_loop._connectivity_failure_is_hard(facts, active_client, prev_mac)


def _debounced_connectivity(facts: "Facts", active_client, client_ok: bool,
                            prev_mac: str = "") -> bool:
    return wifi_loop._debounced_connectivity(LOOP_CTX, facts, active_client, client_ok, prev_mac)


def step_avahi_hostname(pre: "PreFactsContext", loop_state: "LoopState") -> "Verdict":
    return wifi_loop.step_avahi_hostname(LOOP_CTX, pre, loop_state)


def step_mdns_reannounce(pre: "PreFactsContext") -> "Verdict":
    return wifi_loop.step_mdns_reannounce(LOOP_CTX, pre)


def step_revert_log_level(pre: "PreFactsContext") -> "Verdict":
    return wifi_loop.step_revert_log_level(LOOP_CTX, pre)


def step_control_action(pre: "PreFactsContext") -> "Verdict":
    return wifi_loop.step_control_action(LOOP_CTX, pre)


def step_reconfigure_timeout(pre: "PreFactsContext") -> "Verdict":
    return wifi_loop.step_reconfigure_timeout(LOOP_CTX, pre)


def step_update_known_adapters(fctx: "FactsContext") -> "Verdict":
    return wifi_loop.step_update_known_adapters(LOOP_CTX, fctx)


def step_boot_client_bringup(fctx: "FactsContext") -> "Verdict":
    return wifi_loop.step_boot_client_bringup(LOOP_CTX, fctx)


def step_usb_failure_fallback(hctx: "HealthContext") -> "Verdict":
    return wifi_loop.step_usb_failure_fallback(LOOP_CTX, hctx)


def step_runtime_usb_adoption(hctx: "HealthContext") -> "Verdict":
    return wifi_loop.step_runtime_usb_adoption(LOOP_CTX, hctx)


def step_noip_holdback_reset(hctx: "HealthContext") -> "Verdict":
    return wifi_loop.step_noip_holdback_reset(LOOP_CTX, hctx)


def step_dead_phy_recovery(hctx: "HealthContext") -> "Verdict":
    return wifi_loop.step_dead_phy_recovery(LOOP_CTX, hctx)


def step_publish_state(hctx: "HealthContext") -> "Verdict":
    return wifi_loop.step_publish_state(LOOP_CTX, hctx)


def step_bssid_survey(hctx: "HealthContext") -> "Verdict":
    return wifi_loop.step_bssid_survey(LOOP_CTX, hctx)


def step_ethernet_wins(hctx: "HealthContext") -> "Verdict":
    return wifi_loop.step_ethernet_wins(LOOP_CTX, hctx)


def step_hotspot_policy(hctx: "HealthContext") -> "Verdict":
    return wifi_loop.step_hotspot_policy(LOOP_CTX, hctx)


def step_boot_ap_entry(hctx: "HealthContext") -> "Verdict":
    return wifi_loop.step_boot_ap_entry(LOOP_CTX, hctx)


def step_connection_reliability(hctx: "HealthContext") -> "Verdict":
    return wifi_loop.step_connection_reliability(LOOP_CTX, hctx)


def step_catchall_reboot(hctx: "HealthContext") -> "Verdict":
    return wifi_loop.step_catchall_reboot(LOOP_CTX, hctx)

def run_steps(steps, ctx) -> "Verdict":
    """Run *steps* in order, returning on the first OWN_PASS, else CONTINUE.

    Single uniform calling convention — ``step(ctx)`` — with no ``*extra`` channel;
    the one handler that needs the cross-pass LoopState (step_avahi_hostname) is
    bound with functools.partial at list-build time, so every entry is a plain
    ``(ctx) -> Verdict`` callable.  The internal short-circuit on OWN_PASS is
    load-bearing even for the final phase: an owning late handler must prevent the
    trailing CONTINUE handlers from running.
    """
    for step in steps:
        if step(ctx) is Verdict.OWN_PASS:
            return Verdict.OWN_PASS
    return Verdict.CONTINUE


def network_monitor_loop(run_once: bool = False):
    """Background loop to check network state and enforce the narrative rules.

    Summary of behaviour:
      - If wired ethernet is usable (carrier plus valid IPv4): never enter
            automatic AP mode; if currently in AP mode, exit it unless the user
            explicitly requested AP via /request_ap_mode.
      - If WiFi is unconfigured OR still disconnected after BOOT_AP_GRACE seconds:
            enter AP mode within the boot window (BOOT_AP_GRACE..BOOT_AP_CUTOFF).
            Unconfigured devices: AP runs indefinitely (no timeout).
            Configured devices that failed to reconnect: AP runs for AP_MAX_DURATION.
      - If WiFi is configured and usable ethernet is down:
            use the kernel's view of the default gateway as a health check.
            If unreachable for > GW_DOWN_RECONNECT_AFTER: periodically attempt reconnect.
            If unreachable for > GW_DOWN_REBOOT_AFTER: reboot.

    Reboot-timer domains:
      - Dead-PHY: 30-minute guarded reboot when genuinely offline; resets can
            still run while ethernet is attached.
      - Generic WiFi gateway-down: 30-minute guarded reboot for configured WiFi
            clients, skipped whenever usable ethernet is present.
      - Global no-active-path catch-all: 12-hour guarded reboot when no usable
            non-hotspot WiFi or ethernet path has been seen during normal
            monitoring. Setup/AP mode suspends this timer; leaving AP rebases it.
    """
    logger.info("Starting network monitor loop")

    # Record boot time on first entry
    with state_lock:
        if STATE.boot_time is None:
            STATE.boot_time = time.monotonic()
        if STATE.last_active_path_seen is None:
            STATE.last_active_path_seen = STATE.boot_time

    loop_state = LoopState()  # persists across passes (last_avahi_check)

    # Ordered handler lists.  Built once.  step_avahi_hostname also needs the
    # cross-pass loop_state; it is bound with functools.partial so run_steps keeps
    # a single uniform step(ctx) calling convention (§4.4).
    phase_a = [
        step_reconnect_episode,
        step_apply_activation_result,
        partial(step_avahi_hostname, loop_state=loop_state),
        step_mdns_reannounce,
        step_revert_log_level,
        step_control_action,
        step_reconfigure_timeout,
    ]
    phase_b_early = [
        step_update_known_adapters,
        step_boot_client_bringup,
    ]
    phase_b_late = [
        step_usb_failure_fallback,
        step_runtime_usb_adoption,
        step_noip_holdback_reset,
        step_dead_phy_recovery,
        step_publish_state,
        step_bssid_survey,
        step_ethernet_wins,
        step_hotspot_policy,
        step_boot_ap_entry,
        step_connection_reliability,
        step_catchall_reboot,
    ]

    while True:
        now = time.monotonic()
        with state_lock:
            boot_time = STATE.boot_time or now
            avahi_ok = not STATE.setup_mode and not STATE.apply_in_progress
        pre = PreFactsContext(now=now, boot_time=boot_time, avahi_ok=avahi_ok)
        if run_steps(phase_a, pre) is Verdict.OWN_PASS:
            if _sleep_or_finish_monitor_pass(run_once):
                return
            continue

        # Single immutable per-tick snapshot: one discover_adapters /
        # wired probe / address enumeration per pass; playback via the per-pass memo.
        fctx = FactsContext(pre, gather_facts(), _make_playing_status_memo())
        if run_steps(phase_b_early, fctx) is Verdict.OWN_PASS:
            if _sleep_or_finish_monitor_pass(run_once):
                return
            continue

        # Named phase boundary between B-early and B-late (never owns the pass).
        hctx = finalize_active_client_and_health(fctx)
        # Final phase: run_steps still short-circuits internally on the first
        # OWN_PASS (so the trailing CONTINUE handlers do not run after an owning
        # handler); the driver omits only the outer branch because the next line
        # sleeps regardless.
        run_steps(phase_b_late, hctx)
        if _sleep_or_finish_monitor_pass(run_once):
            return

# ** MULTI-ADAPTER FAILURE, FALLBACK, AND RUNTIME USB ADOPTION **
#
# All fallback/adoption *policy* lives here in the watcher.  The helper only
# reports facts (discovery, health, scans) and performs bounded primitives.


def query_playing_status() -> Optional[bool]:
    """Return True/False playback state, or None when uncertain.

    In Dial mode there is no local player, so playback is always treated as
    idle.  On the main appliance the watcher performs a read-only loopback GET
    to /api/playing-status with a short timeout and accepts state only when the
    response is exactly ok:true with a boolean playing.  Any failure, malformed
    body, or explicit uncertainty returns None (defer, never assume idle).
    """
    if _DIAL_MODE:
        return False
    try:
        with urllib.request.urlopen(PLAYING_STATUS_URL, timeout=PLAYING_STATUS_TIMEOUT) as resp:
            raw = resp.read()
        data = json.loads(raw)
    except Exception:
        _warn_playing_status_unavailable()
        return None
    if not isinstance(data, dict) or data.get("ok") is not True:
        _warn_playing_status_unavailable()
        return None
    playing = data.get("playing")
    if not isinstance(playing, bool):
        _warn_playing_status_unavailable()
        return None
    return playing


def _warn_playing_status_unavailable() -> None:
    """Throttled WARNING when playback status is unavailable during pending adoption."""
    with state_lock:
        pending = STATE.pending_usb_adoption_mac is not None
    if pending:
        log_throttled(
            "playing_status_unavailable",
            "Playing status unavailable while USB adoption pending; deferring",
            interval=PLAYING_STATUS_WARN_THROTTLE,
        )


import wifi_activation
import wifi_recovery

# Owns the dead-PHY / reset / no-IP / manual-disable ledgers; shared with
# wifi_status (read-only, for the status snapshot) via StatusContext.  Built
# early (ahead of the recovery seam below) because the activation context also
# needs it (client hand-over clears the no-IP hold-back marker).
RECOVERY_STATE = wifi_recovery.RecoveryState()

ActivationJob = wifi_activation.ActivationJob
ActivationResult = wifi_activation.ActivationResult


def _activation_network_absent(result) -> bool:
    return wifi_activation._activation_network_absent(result)


# ** CONFIGURED-NETWORK RECONNECT AND FIRST-BOOT IMPORT **
#
# The steady-state reconnect path and first-boot profile adoption/migration
# live in platform/wifi_config.py, which takes a ConfigContext exposing only
# the NM client, the state-file paths and the small set of watcher callables
# the helpers invoke.  The context is built once here and passed directly to
# the module's functions at every call site (production and __main__).

import wifi_config

CONFIG_CTX = wifi_config.ConfigContext(
    nm=nm,
    logger=logger,
    NETWORK_STATE_PATH=NETWORK_STATE_PATH,
    CONFIGURED_SSID=CONFIGURED_SSID,
    FIRST_BOOT_IMPORT_MARKER=FIRST_BOOT_IMPORT_MARKER,
    get_configured_network_state=get_configured_network_state,
    is_wifi_client_healthy=is_wifi_client_healthy,
    _activation_network_absent=_activation_network_absent,
    _commit_network_state=_commit_network_state,
)


def _pin_usb_bssid(ifname: str, uuid: str) -> str:
    return wifi_activation._pin_usb_bssid(ACTIVATION_CTX, ifname, uuid)


def _activate_profile_on(ifname: str, state: "wifi_net.NetworkState",
                         *, wait_for_validation: bool = True) -> bool:
    return wifi_activation._activate_profile_on(
        ACTIVATION_CTX, ifname, state, wait_for_validation=wait_for_validation)


def _validate_activation(ifname: str, activation_result,
                         *, wait_for_validation: bool = True) -> bool:
    return wifi_activation._validate_activation(
        ACTIVATION_CTX, ifname, activation_result, wait_for_validation=wait_for_validation)


def _activate_committed_on(ifname: str) -> bool:
    return wifi_activation._activate_committed_on(ACTIVATION_CTX, ifname)


# The recovery ledger hooks below are looked up by name at call time (not at
# ACTIVATION_CTX construction), so they may reference RECOVERY_CTX and
# _clear_pending_adoption even though those are defined later in this module.

def _clear_noip_failures_for_activation(stable_id) -> None:
    wifi_recovery.clear_noip_failures(RECOVERY_CTX, stable_id)


def _clear_dead_adapter_state_for_activation() -> None:
    wifi_recovery.clear_dead_adapter_state(RECOVERY_CTX)


def _record_noip_failure_for_activation(record_id, at: float) -> int:
    return wifi_recovery.record_noip_failure(RECOVERY_CTX, record_id, at)


def _clear_pending_adoption_for_activation() -> None:
    _clear_pending_adoption()


def verify_avahi_after_handover() -> None:
    """Verify the Avahi hostname and flag an mDNS host-record re-announce.

    Reuses the existing hostname verification path, then marks a re-announce as
    pending rather than restarting avahi-daemon directly.  The monitor loop owns
    the actual re-announce (see wifi_mdns.maybe_reannounce_mdns): it waits for
    the published address set to settle before restarting, so it re-announces
    only the surviving interface's address (never re-poisoning clients with the
    address that is being torn down mid-handover), and de-duplicates with the
    passive address-change detector so a single restart covers both triggers.
    """
    try:
        wifi_mdns.check_and_repair_avahi_hostname(MDNS_CTX)
        wifi_mdns.mark_mdns_reannounce_pending(MDNS_CTX, "network handover")
    except Exception as e:
        logger.warning("Avahi handover verification failed: %s", e)


# The narrowed activation seam.  Built once from the symbols defined above; the
# worker and loop-tail helpers thread this ctx instead of the whole module.
ACTIVATION_CTX = wifi_activation.ActivationContext(
    STATE=STATE,
    state_lock=state_lock,
    RECOVERY_STATE=RECOVERY_STATE,
    RECOVERY_CTX=None,  # set below once RECOVERY_CTX exists (forward reference)
    nm=nm,
    hotspot_controller=hotspot_controller,
    logger=logger,
    HotspotPurpose=wifi_policy.HotspotPurpose,
    Verdict=Verdict,
    WAIT_FOR_CONNECTION_TIMEOUT=WAIT_FOR_CONNECTION_TIMEOUT,
    WAIT_FOR_CONNECTION_INTERVAL=WAIT_FOR_CONNECTION_INTERVAL,
    configure_wifi_with_nmcli=configure_wifi_with_nmcli,
    stop_ap_mode=stop_ap_mode,
    get_configured_network_state=get_configured_network_state,
    is_wifi_client_healthy=is_wifi_client_healthy,
    wait_for_connection=wait_for_connection,
    _resolve_committed_uuid=partial(wifi_config._resolve_committed_uuid, CONFIG_CTX),
    enter_setup_mode=enter_setup_mode,
    leave_setup_mode=leave_setup_mode,
    verify_avahi_after_handover=verify_avahi_after_handover,
    clear_noip_failures=_clear_noip_failures_for_activation,
    clear_dead_adapter_state=_clear_dead_adapter_state_for_activation,
    record_noip_failure=_record_noip_failure_for_activation,
    clear_pending_adoption=_clear_pending_adoption_for_activation,
    advance_reconnect_episode=_advance_reconnect_episode,
)


def _set_active_client(adapter) -> None:
    wifi_activation._set_active_client(ACTIVATION_CTX, adapter)


def client_up_tail(adapter, *, set_builtin_fallback=None,
                   clear_noip_stable_id=None, disconnect_builtin_ifname="",
                   leave_setup_reason=None, clear_down_timers=False,
                   reset_onboard_bound=False, clear_pending_adoption=False,
                   clear_dead_adapter=False) -> None:
    wifi_activation.client_up_tail(
        ACTIVATION_CTX, adapter,
        set_builtin_fallback=set_builtin_fallback,
        clear_noip_stable_id=clear_noip_stable_id,
        disconnect_builtin_ifname=disconnect_builtin_ifname,
        leave_setup_reason=leave_setup_reason,
        clear_down_timers=clear_down_timers,
        reset_onboard_bound=reset_onboard_bound,
        clear_pending_adoption=clear_pending_adoption,
        clear_dead_adapter=clear_dead_adapter,
    )


def apply_activation_result(result: "ActivationResult", adapter: "Optional[object]" = None) -> bool:
    return wifi_activation.apply_activation_result(ACTIVATION_CTX, result, adapter)



def _next_activation_epoch() -> int:
    return wifi_activation._next_activation_epoch(ACTIVATION_CTX)


def _run_activation_job(job: "ActivationJob") -> "ActivationResult":
    return wifi_activation._run_activation_job(ACTIVATION_CTX, job)


# The worker's single-slot job queue and result slot live in wifi_activation
# (module-global: there is only ever one activation worker for the process).
# These names alias the shared queue/event objects so existing call sites and
# tests can reach them directly; _inflight_activation_epoch is exposed through
# accessor functions instead, since it is reassigned rather than mutated.
_activation_job_queue = wifi_activation._activation_job_queue
activation_result_event = wifi_activation.activation_result_event


def submit_activation_job(job: "ActivationJob") -> bool:
    return wifi_activation.submit_activation_job(ACTIVATION_CTX, job)


def _post_activation_result(result: "ActivationResult") -> None:
    wifi_activation._post_activation_result(result)


def drain_activation_result() -> "Optional[ActivationResult]":
    return wifi_activation.drain_activation_result()


def start_activation_worker() -> "threading.Thread":
    return wifi_activation.start_activation_worker(ACTIVATION_CTX)


def step_apply_activation_result(pre: "PreFactsContext") -> "Verdict":
    return wifi_activation.step_apply_activation_result(ACTIVATION_CTX, pre)


def resolve_active_client(adapters: list) -> Optional[object]:
    return wifi_adoption.resolve_active_client(adapters)


def handle_usb_failure_fallback(hctx: "HealthContext") -> bool:
    return wifi_adoption.handle_usb_failure_fallback(ADOPTION_CTX, hctx)


def apply_client_failed(event, facts: "Facts") -> bool:
    return wifi_adoption.apply_client_failed(ADOPTION_CTX, event, facts)


# Remember which permanent MACs were last seen as USB, so that an absent active
# adapter can still be classified as USB after it disappears from discovery.
# Shared with wifi_recovery via RECOVERY_CTX._known_usb_macs (single owner).
_known_usb_macs: set[str] = set()


def _submit_client_activation(action: "wifi_policy.RecoveryAction", facts: "Facts") -> bool:
    return wifi_adoption._submit_client_activation(ADOPTION_CTX, action, facts)


def _saved_network_ssid() -> str:
    return wifi_adoption._saved_network_ssid(ADOPTION_CTX)


def _saved_ssid_visible(hotspot_adapter) -> bool:
    return wifi_adoption._saved_ssid_visible(ADOPTION_CTX, hotspot_adapter)


def _rate_gated_saved_ssid_scan(adapter, last_scan_attr: str,
                                interval: float, now: float) -> Optional[bool]:
    return wifi_adoption._rate_gated_saved_ssid_scan(
        ADOPTION_CTX, adapter, last_scan_attr, interval, now)


def _attempt_recovery_reconnect(facts: "Facts") -> None:
    wifi_adoption._attempt_recovery_reconnect(ADOPTION_CTX, facts)


def handle_runtime_usb_adoption(adapters: list, wired_connected: bool,
                                playing_fn=None) -> bool:
    return wifi_adoption.handle_runtime_usb_adoption(
        ADOPTION_CTX, adapters, wired_connected, playing_fn)


def _clear_pending_adoption() -> None:
    wifi_adoption._clear_pending_adoption(ADOPTION_CTX)


def update_known_adapters(adapters: list) -> None:
    wifi_adoption.update_known_adapters(ADOPTION_CTX, adapters)


def bssid_survey_and_roam(hctx: "HealthContext") -> bool:
    return wifi_adoption.bssid_survey_and_roam(ADOPTION_CTX, hctx)


# ** DEAD-PHY RECOVERY **
#
# Detection, reset budgets, the persistent reboot guard, and the recovery
# ladder live in platform/wifi_recovery.py.  It no longer receives the whole
# watcher module: the seam is narrowed (WP-11) to a RecoveryContext (RECOVERY_CTX,
# built below) exposing only the STATE, the reset/quarantine/reboot constants and
# the policy helpers the ladder invokes.  TargetAdapter is re-exported for
# callers/tests.

TargetAdapter = wifi_recovery.TargetAdapter
INTERFACE_REAPPEAR_TIMEOUT = wifi_recovery.INTERFACE_REAPPEAR_TIMEOUT
# Adapter-remediation overlay event contract, re-exported so the loop and tests
# can reference the event shapes without importing wifi_recovery.
OverlayEvent = wifi_recovery.OverlayEvent
ClientFailed = wifi_recovery.ClientFailed
NeedReboot = wifi_recovery.NeedReboot


# Only wrappers with a genuine production caller remain: _adapter_recovery_facts
# (gather_recovery_facts + wifi_status), wait_for_interface_reappears and
# escalate_dead_adapter_recovery (the dead-PHY reset ladder /
# step_dead_phy_recovery).


def _adapter_recovery_facts(adapter, now, health_fn=None):
    # Inject the live health check (late-bound module global) so it stays patchable
    # at the watcher boundary even though RECOVERY_CTX froze its callables.
    if health_fn is None:
        health_fn = is_wifi_client_healthy
    return wifi_recovery.adapter_recovery_facts(RECOVERY_CTX, adapter, now, health_fn)


def wait_for_interface_reappears(target, timeout=INTERFACE_REAPPEAR_TIMEOUT):
    return wifi_recovery.wait_for_interface_reappears(RECOVERY_CTX, target, timeout)


def escalate_dead_adapter_recovery(adapters, wired_connected):
    return wifi_recovery.escalate_dead_adapter_recovery(RECOVERY_CTX, adapters, wired_connected)


# The narrowed recovery seam.  Built once from the symbols defined above; the
# recovery helpers thread this ctx instead of the whole module.  wait_for_-
# interface_reappears is the watcher wrapper (which re-enters wifi_recovery).
RECOVERY_CTX = wifi_recovery.RecoveryContext(
    STATE=STATE,
    state_lock=state_lock,
    logger=logger,
    RECOVERY_STATE=RECOVERY_STATE,
    AP_IFNAME=AP_IFNAME,
    USB_RESET_WINDOW=USB_RESET_WINDOW,
    USB_MAX_RESETS_TOTAL=USB_MAX_RESETS_TOTAL,
    USB_MAX_RESETS_PER_WINDOW=USB_MAX_RESETS_PER_WINDOW,
    USB_EMERGENCY_BACKOFF=USB_EMERGENCY_BACKOFF,
    RESET_ATTEMPT_INTERVAL=RESET_ATTEMPT_INTERVAL,
    RECONNECT_ATTEMPT_INTERVAL=RECONNECT_ATTEMPT_INTERVAL,
    DEAD_ADAPTER_DEBOUNCE=DEAD_ADAPTER_DEBOUNCE,
    DEAD_ADAPTER_REBOOT_AFTER=DEAD_ADAPTER_REBOOT_AFTER,
    DEAD_ADAPTER_REBOOT_WINDOW=DEAD_ADAPTER_REBOOT_WINDOW,
    DEAD_ADAPTER_MAX_REBOOTS_PER_WINDOW=DEAD_ADAPTER_MAX_REBOOTS_PER_WINDOW,
    DEAD_ADAPTER_HEALTHY_DECAY=DEAD_ADAPTER_HEALTHY_DECAY,
    DEAD_ADAPTER_REBOOT_STAMP=DEAD_ADAPTER_REBOOT_STAMP,
    ADAPTER_FAULT_STATE_PATH=ADAPTER_FAULT_STATE_PATH,
    is_wifi_client_healthy=is_wifi_client_healthy,
    client_up_tail=client_up_tail,
    _activate_committed_on=_activate_committed_on,
    wait_for_interface_reappears=wait_for_interface_reappears,
    resolve_hotspot_adapter=resolve_hotspot_adapter,
    request_guarded_reboot=request_guarded_reboot,
    _known_usb_macs=_known_usb_macs,
)
# ACTIVATION_CTX was built before RECOVERY_CTX existed (the reset/retry rung
# needs both budget-ledger access and the loop-tail callables); wire it in now.
ACTIVATION_CTX.RECOVERY_CTX = RECOVERY_CTX


# The narrowed adoption seam.  Built once from the symbols defined above; the
# fallback/adoption/reconnect-episode helpers thread this ctx instead of the
# whole module.
ADOPTION_CTX = wifi_adoption.AdoptionContext(
    STATE=STATE,
    state_lock=state_lock,
    logger=logger,
    RECOVERY_CTX=RECOVERY_CTX,
    nm=nm,
    HotspotPurpose=wifi_policy.HotspotPurpose,
    Verdict=Verdict,
    _last_logged_values=_last_logged_values,
    RECOVERY_SCAN_INTERVAL=RECOVERY_SCAN_INTERVAL,
    RECONNECT_ATTEMPT_INTERVAL=RECONNECT_ATTEMPT_INTERVAL,
    ADOPTION_SCAN_INTERVAL=ADOPTION_SCAN_INTERVAL,
    USB_ADOPTION_STABLE_PASSES=USB_ADOPTION_STABLE_PASSES,
    BSSID_SURVEY_INTERVAL=BSSID_SURVEY_INTERVAL,
    BSSID_USB_SURVEY_INTERVAL=BSSID_USB_SURVEY_INTERVAL,
    get_configured_network_state=get_configured_network_state,
    is_wifi_client_healthy=is_wifi_client_healthy,
    resolve_hotspot_adapter=resolve_hotspot_adapter,
    hotspot_station_count=hotspot_station_count,
    query_playing_status=query_playing_status,
    log_on_change=log_on_change,
    gather_recovery_facts=gather_recovery_facts,
    enter_setup_mode=enter_setup_mode,
    submit_activation_job=submit_activation_job,
    next_activation_epoch=_next_activation_epoch,
)


# ** RUNTIME NETWORK-STATUS SNAPSHOT **
#
# Snapshot construction/publishing lives in platform/wifi_status.py, which
# takes a StatusContext exposing only the STATE, the three recovery constants
# and the fact helpers the snapshot surfaces.  The context is built once here
# and passed directly to wifi_status.publish_network_status at every call site
# (step_publish_state calls it every pass).

import wifi_status

STATUS_CTX = wifi_status.StatusContext(
    STATE=STATE,
    state_lock=state_lock,
    RECOVERY_STATE=RECOVERY_STATE,
    NO_ACTIVE_PATH_REBOOT_AFTER=NO_ACTIVE_PATH_REBOOT_AFTER,
    USB_MAX_RESETS_PER_WINDOW=USB_MAX_RESETS_PER_WINDOW,
    RESET_ATTEMPT_INTERVAL=RESET_ATTEMPT_INTERVAL,
    is_wired_connected=is_wired_connected,
    any_wired_path_healthy=any_wired_path_healthy,
    is_gateway_reachable=is_gateway_reachable,
    resolve_hotspot_adapter=resolve_hotspot_adapter,
    hotspot_station_count=hotspot_station_count,
    _adapter_recovery_facts=_adapter_recovery_facts,
)


# ** AVAHI mDNS HOSTNAME MONITORING **
#
# The avahi/mDNS block (hostname-drift repair + address-set re-announce
# debounce) lives in platform/wifi_mdns.py, which takes an ``MdnsContext``
# exposing only the STATE, the constants and the callables it uses.  The
# context is built once here and passed directly to the module's functions at
# every call site (the monitor loop calls
# ``wifi_mdns.check_and_repair_avahi_hostname(MDNS_CTX)`` /
# ``wifi_mdns.maybe_reannounce_mdns(MDNS_CTX, now)`` etc.).

import wifi_mdns

MDNS_CTX = wifi_mdns.MdnsContext(
    STATE=STATE,
    state_lock=state_lock,
    NMCLI_QUICK_TIMEOUT=NMCLI_QUICK_TIMEOUT,
    AVAHI_MISMATCH_GRACE=AVAHI_MISMATCH_GRACE,
    AVAHI_RESTART_MIN_INTERVAL=AVAHI_RESTART_MIN_INTERVAL,
    AVAHI_HANDOVER_RESTART_MIN_INTERVAL=AVAHI_HANDOVER_RESTART_MIN_INTERVAL,
    AVAHI_MAX_RESTART_ATTEMPTS=AVAHI_MAX_RESTART_ATTEMPTS,
    AVAHI_REANNOUNCE_DEBOUNCE=AVAHI_REANNOUNCE_DEBOUNCE,
    _DBUS_SEND=_DBUS_SEND,
    run_cmd=run_cmd,
    logger=logger,
    log_on_change=log_on_change,
    get_system_hostname=get_system_hostname,
)


def _maybe_reset_noip_held_usb(adapters: list, now: float) -> bool:
    return wifi_recovery.maybe_reset_noip_held_usb(RECOVERY_CTX, adapters, now)


# The narrowed Flask/HTTP seam.  Built once every callable and constant the
# routes use exists; build_app() closes its handlers over this ctx and
# init_control_token()/remove_control_token() are driven from __main__.
WEB_CTX = wifi_web.WebContext(
    app_name=__name__,
    STATE=STATE,
    state_lock=state_lock,
    logger=logger,
    control_action_event=control_action_event,
    RUNTIME_LOG_LEVELS=RUNTIME_LOG_LEVELS,
    LOG_LEVEL_TTL_MIN=LOG_LEVEL_TTL_MIN,
    LOG_LEVEL_TTL_MAX=LOG_LEVEL_TTL_MAX,
    WIFI_WATCHER_VERSION=WIFI_WATCHER_VERSION,
    _DIAL_MODE=_DIAL_MODE,
    wifi_net=wifi_net,
    get_system_hostname=get_system_hostname,
    get_configured_network_state=get_configured_network_state,
    submit_apply_credentials=submit_apply_credentials,
    scan_all_networks=scan_all_networks,
)
app = wifi_web.build_app(WEB_CTX)


# The narrowed monitor-loop seam.  Built last (once every callable it needs
# exists); network_monitor_loop binds each handler to this ctx with
# functools.partial when building the ordered phase lists.
LOOP_CTX = wifi_loop.LoopContext(
    STATE=STATE,
    state_lock=state_lock,
    logger=logger,
    Verdict=Verdict,
    HotspotPurpose=wifi_policy.HotspotPurpose,
    _NON_DISRUPTIVE_ACTIONS=_NON_DISRUPTIVE_ACTIONS,
    control_action_event=control_action_event,
    nm=nm,
    AVAHI_CHECK_INTERVAL=AVAHI_CHECK_INTERVAL,
    AP_MAX_DURATION=wifi_policy.AP_MAX_DURATION,
    BOOT_AP_GRACE=wifi_policy.BOOT_AP_GRACE,
    BOOT_AP_CUTOFF=BOOT_AP_CUTOFF,
    GW_DOWN_REBOOT_AFTER=GW_DOWN_REBOOT_AFTER,
    GW_DOWN_RECONNECT_AFTER=GW_DOWN_RECONNECT_AFTER,
    RECONNECT_ATTEMPT_INTERVAL=RECONNECT_ATTEMPT_INTERVAL,
    NO_ACTIVE_PATH_REBOOT_AFTER=NO_ACTIVE_PATH_REBOOT_AFTER,
    CONNECTIVITY_DOWN_DEBOUNCE=CONNECTIVITY_DOWN_DEBOUNCE,
    AP_IFNAME=AP_IFNAME,
    check_and_repair_avahi_hostname=partial(wifi_mdns.check_and_repair_avahi_hostname, MDNS_CTX),
    maybe_reannounce_mdns=partial(wifi_mdns.maybe_reannounce_mdns, MDNS_CTX),
    revert_expired_log_level=revert_expired_log_level,
    process_control_action=process_control_action,
    handle_reconfigure_timeout=handle_reconfigure_timeout,
    log_on_change=log_on_change,
    update_known_adapters=update_known_adapters,
    gather_recovery_facts=gather_recovery_facts,
    submit_client_activation=_submit_client_activation,
    handle_usb_failure_fallback=handle_usb_failure_fallback,
    handle_runtime_usb_adoption=handle_runtime_usb_adoption,
    bssid_survey_and_roam=bssid_survey_and_roam,
    maybe_reset_noip_held_usb=_maybe_reset_noip_held_usb,
    escalate_dead_adapter_recovery=escalate_dead_adapter_recovery,
    publish_network_status=partial(wifi_status.publish_network_status, STATUS_CTX),
    hotspot_blocks_eth=_hotspot_blocks_eth,
    leave_setup_mode=leave_setup_mode,
    enter_setup_mode=enter_setup_mode,
    set_active_client=_set_active_client,
    connect_to_configured_wifi=partial(wifi_config.connect_to_configured_wifi, CONFIG_CTX),
    request_network_down_reboot=_request_network_down_reboot,
    attempt_recovery_reconnect=_attempt_recovery_reconnect,
    next_mode=wifi_policy.next_mode,
    next_recovery_action=wifi_policy.next_recovery_action,
    RecoveryKind=wifi_policy.RecoveryKind,
    PURPOSE_TABLE=wifi_policy.PURPOSE_TABLE,
)


if __name__ == "__main__":
    _setup_logging()
    logger.info("**************************************************************************")
    logger.info("autostream wifi monitor starting. Copyright (c) 2025, Lo-tech Systems Ltd.")

    # Check CPU (gated: dial sets APP_CHECK_CPU=no; autostream defaults to yes)
    if os.environ.get('APP_CHECK_CPU', 'yes') == 'yes':
        from autostream_rpi import check_cpu
        check_cpu()

    # Migrate legacy /opt/autostream/ssid into /etc/autostream-network.json when
    # needed.  The watcher (running as root) is the only writer of network.json.
    try:
        wifi_net.migrate_legacy_state(
            state_path=NETWORK_STATE_PATH,
            legacy_path=CONFIGURED_SSID,
        )
    except Exception as e:
        logger.warning("Legacy network-state migration failed: %s", e)

    # First, remove any lingering Hotspot connection and stale nginx flag that
    # would otherwise force the Pi to setup mode even though the WiFi is probably
    # OK, and connect to whatever network is configured (if it is configured).
    hotspot_controller.clear_stale()
    # First-boot adoption: import the currently connected Wi-Fi profile as the
    # single managed profile and delete other saved client profiles (marker-gated,
    # runs at most once).  Before the autoconnect sweep so it can query the active
    # connections while they are untouched.
    wifi_config.import_first_boot_wifi_profile(CONFIG_CTX)
    # Idempotently disable NM autoconnect on every managed non-AP client profile
    # (self-healing for pre-existing/installer-imported autoconnect=yes profiles),
    # so the watcher is the sole agent that brings a client up.
    try:
        wifi_config.migrate_client_profiles_autoconnect_no(CONFIG_CTX)
    except Exception as e:
        logger.warning("autoconnect=no startup migration failed: %s", e)
    # Initial client bring-up is done by the monitor loop's BOOT-window ladder rung
    # (step_boot_client_bringup) from the first pass, so a single decider ranks the
    # client paths at boot.

    # Restore the persisted per-adapter fault ledgers (no-IP + reset/quarantine)
    # so a restart does not hand a chronically bad dongle a fresh budget.
    try:
        wifi_recovery.load_adapter_fault_state(RECOVERY_CTX)
    except Exception as e:
        logger.warning("Could not load persisted adapter fault state: %s", e)

    logger.info(
        "Initial state: wifi_configured=%s, wired=%s",
        is_wifi_configured(), is_wired_connected(),
    )

    # Generate the per-boot control token before accepting any control request.
    wifi_web.init_control_token(WEB_CTX)

    # Start the off-thread activation worker; idle until a job is submitted.
    start_activation_worker()

    # Start the network monitor in a background thread
    monitor_thread = threading.Thread(target=network_monitor_loop, daemon=True)
    monitor_thread.start()

    # Ensure AP mode flag matches initial state
    update_apmode_flag(False)

    # Start the Flask app (HTTP server) on port 9080
    try:
        app.run(host="127.0.0.1", port=9080)
    finally:
        # Best-effort token removal on orderly shutdown; the next startup is
        # authoritative regardless.
        wifi_web.remove_control_token()
