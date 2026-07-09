#!/usr/bin/python3
"""autostream_wifi_watcher.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Runs continuously as root, monitoring and logging the device's network
connectivity. Executed directly via its shebang on the system Python
interpreter (not the app venv), so the WiFi setup/recovery path survives a
broken venv; Flask is installed at the system level by the installer. Always
serves the setup page — the NGINX config routes browser traffic to this
service or to the main web UI by the presence of ``/tmp/apmode``. See
``docs/WIFI-WATCHER.md`` for the full behavioural spec (AP-mode purpose
table, connection-reliability timers, reboot domains, first-boot import).

== Module map ==

This module is the star-topology hub: it owns ``STATE``/``state_lock``, the
constants, the logger, AP start/stop primitives, the credential-apply
candidate sequence, per-pass fact gathering, the monitor-loop driver, and
``__main__``. Every other concern lives in a deploy-together sibling module
that takes a narrow context exposing only the STATE/constants/callables it
needs — none of them import this module: ``wifi_state`` (data-only leaf:
``NetworkMonitorState``/``state_lock`` and the per-concern state fragments),
``wifi_policy`` (pure decision core), ``wifi_loop`` (ordered step_*
handlers), ``wifi_activation`` (off-thread worker), ``wifi_recovery``
(dead-PHY/reset/reboot-guard ledgers), ``wifi_adoption`` (USB
fallback/adoption/BSSID roam), ``wifi_config`` (configured-network reconnect,
first-boot import), ``wifi_status`` (status snapshot), ``wifi_mdns`` (avahi
repair/re-announce), ``wifi_hotspot`` (AP controller), ``wifi_nm`` (bounded
nmcli client), ``wifi_web`` (Flask surface). ``build_contexts()``, called
once at import time, constructs every context in dependency order and binds
it to a module global of the same name (``LOOP_CTX``, ``ACTIVATION_CTX``,
...).

== State machine ==

The operating mode is an explicit ``wifi_policy.Mode`` published as
``device.mode``; hotspot entry/exit policy is ``wifi_policy.PURPOSE_TABLE``.
Two pure classifiers in ``wifi_policy`` — ``next_mode`` (forward mode) and
``next_recovery_action`` (Ethernet > preferred USB > onboard > hotspot
priority ladder) — take state/facts snapshots and return decisions with no
STATE mutation, subprocess, or other effect; the loop applies each result.

== Threading model ==

One monitor-loop thread, one activation worker thread, Flask on the main
thread. ``STATE`` is guarded throughout by ``state_lock``; the ``transitioning``
flag ensures at most one effectful connectivity transition is in flight.
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

# Data-only leaf: NetworkMonitorState/state_lock, the per-concern state
# fragments (ApplyState/ControlState/LogLevelState), and the plain rollback/
# hotspot-session types.  Imports nothing else in this tree.
from wifi_state import (
    NetworkMonitorState, RollbackSnapshot, HotspotSession,
    ApplyState, ControlState, LogLevelState, MdnsState, SnapshotState,
    AdoptionState, state_lock,
)

# The watcher is deployed beside its split sibling modules (wifi_status.py,
# wifi_recovery.py) in /opt/autostream.  Ensure that directory is importable
# both in production (script run directly) and under the test loader.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# Every sibling module below is deployed flat beside the watcher in
# /opt/autostream and takes a narrow context exposing only the STATE,
# constants and callables it needs; the dependency direction is strictly
# hub-to-spoke, never the reverse.  build_contexts() (defined further down,
# called once at the bottom of this module) constructs every context in
# dependency order.

# Pure connectivity policy: enums, the hotspot purpose table, and the mode /
# recovery-ladder classifiers.  A standalone effect-free module; the hub and
# every context reference its names directly (`wifi_policy.<name>`).
import wifi_policy

# The single bounded nmcli client; every nmcli invocation goes through it.
import wifi_nm

# Dead-PHY detection, reset/quarantine/no-IP ledgers, persistence, and the
# persistent reboot guard.
import wifi_recovery

# Off-thread activation worker, job/result types, client_up_tail, and
# activation-result application.
import wifi_activation

# Multi-adapter fallback / runtime USB adoption / reconnect-saved episode
# machinery.
import wifi_adoption

# Configured-network reconnect and first-boot profile import/migration.
import wifi_config

# Runtime network-status snapshot construction/publishing.
import wifi_status

# Avahi mDNS hostname-drift repair and address-set re-announce debounce.
import wifi_mdns

# Hotspot mechanics (start/stop/rebuild/clear-stale sequencing + flag
# ordering).
import wifi_hotspot

# Flask presentation/HTTP surface (page rendering, app factory, captive/setup
# routes).
import wifi_web

# The ordered step_* monitor-loop handlers and their phase context types.
import wifi_loop


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
# Consecutive adoption scans that succeed with zero rows before a present idle
# USB candidate is treated as unusable (wedged radio) and routed through
# remediate_unusable_usb; ~10 minutes at the 5-minute adoption scan cadence.
EMPTY_SCAN_RESET_STREAK = 2
# USB BSSID survey cadence: the USB self-scan (+ opportunistic idle onboard
# scan) runs every BSSID_SURVEY_INTERVAL.  It is a full rescan (eligible for
# the proactive-roam candidate streak) only while playback is exactly False;
# otherwise it is a cheap read that keeps the table fresh without advancing
# or resetting the streak.
BSSID_SURVEY_INTERVAL = 60
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

# The single bounded nmcli client (built by build_contexts()): every nmcli
# invocation passes one of the two timeouts above, so there is no unbounded
# NetworkManager code path.
nm: "wifi_nm.NMClient" = None  # type: ignore[assignment]

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
# device.mode.  RollbackSnapshot and HotspotSession (STATE.hotspot) are
# plain data types defined in wifi_state.py.


logger = logging.getLogger(__name__)


class RepeatSuppressionFilter(logging.Filter):
    """Suppress runs of consecutively repeated messages, syslog-style.

    The first REPEAT_FREE_PASSES occurrences of a consecutive run are
    emitted; further repeats are dropped, except that a reminder (annotated
    with the suppressed count) is emitted every REPEAT_REMINDER_SECONDS.
    Any different message resets the run.  O(1) state; intervals use
    time.monotonic() so NTP clock steps cannot distort them.

    Each handler carries its own instance so filtering is applied
    independently per destination (stdout vs file).  Handlers receive the
    same LogRecord object, so a reminder's annotation is stashed on the
    record itself (``_repeat_original``) and never re-applied, keeping the
    two instances' run tracking in sync when the record propagates to both.
    """

    REPEAT_FREE_PASSES = 3
    REPEAT_REMINDER_SECONDS = 300.0

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._last_msg: Optional[str] = None
        self._run_count = 0            # consecutive occurrences of _last_msg
        self._last_emit: float = 0.0   # monotonic time _last_msg last emitted

    def filter(self, record: logging.LogRecord) -> bool:
        msg = getattr(record, "_repeat_original", record.getMessage())
        now = time.monotonic()
        with self._lock:
            if msg != self._last_msg:
                self._last_msg = msg
                self._run_count = 1
                self._last_emit = now
                return True
            self._run_count += 1
            if self._run_count <= self.REPEAT_FREE_PASSES:
                self._last_emit = now
                return True
            if now - self._last_emit >= self.REPEAT_REMINDER_SECONDS:
                if not hasattr(record, "_repeat_original"):
                    record._repeat_original = msg
                    record.msg = f"{msg} (repeated {self._run_count} times)"
                    record.args = None
                self._last_emit = now
                return True
            return False


def _apply_runtime_level(levelno: int) -> None:
    """Apply the runtime level to the root logger and gate werkzeug by it.

    Werkzeug self-configures its logger to INFO, which would bypass the
    root level for propagated records.  HTTP access lines are routine
    polling noise, so they are only enabled at debug; werkzeug's own
    warnings/errors always pass.
    """
    logging.getLogger().setLevel(levelno)
    logging.getLogger("werkzeug").setLevel(
        logging.INFO if levelno <= logging.DEBUG else logging.WARNING
    )


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
    LOG_STATE.default_log_level_name = env_level if env_level in RUNTIME_LOG_LEVELS else "info"

    root = logging.getLogger()
    _apply_runtime_level(level)

    if root.handlers:
        return

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%d-%b-%y %H:%M:%S",
    )

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    stream_handler.addFilter(RepeatSuppressionFilter())
    root.addHandler(stream_handler)

    try:
        log_dir = os.path.dirname(LOG_FILE) or "."
        os.makedirs(log_dir, exist_ok=True)
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(RepeatSuppressionFilter())
        root.addHandler(file_handler)
    except Exception as e:
        logger.error(
            "Failed to initialise file logging (%s); continuing with stdout only.", e
        )

# The shared connectivity-core state (wifi_state.NetworkMonitorState) plus the
# per-concern fragments split out of it.  All seven objects are guarded by the
# single wifi_state.state_lock; build_contexts() threads each fragment only to
# the contexts that read or write it.  The mode default is supplied here (not
# in wifi_state, which does not import wifi_policy).
STATE = NetworkMonitorState(mode=wifi_policy.Mode.BOOT)
APPLY_STATE = ApplyState()
CONTROL_STATE = ControlState()
LOG_STATE = LogLevelState()
MDNS_STATE = MdnsState()
SNAPSHOT_STATE = SnapshotState()
ADOPTION_STATE = AdoptionState()

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

class LogDedupCache:
    """The caches behind log_on_change/log_throttled — logging infrastructure,
    not watcher domain state.  Unlocked, best-effort (a race at most emits one
    extra line); every access here matches the module-global semantics this
    replaced.
    """

    def __init__(self) -> None:
        self._last_logged_values: dict = {}
        self._last_throttled_log: dict = {}

    def on_change(self, key: str, value: object, msg: str, level: int = logging.INFO) -> None:
        """Log msg at *level* only when (key -> value) changes (semantic transition)."""
        prev = self._last_logged_values.get(key, object())
        if prev != value:
            self._last_logged_values[key] = value
            logger.log(level, "%s", msg)

    def throttled(self, key: str, msg: str, *, interval: float,
                  level: int = logging.WARNING, now: "Optional[float]" = None) -> bool:
        """Log msg at most once per *interval* seconds per *key* (time-window throttle).

        The shared rate-limiter for a condition that stays true across passes.
        Returns True when it logged this call.
        """
        if now is None:
            now = time.monotonic()
        prev = self._last_throttled_log.get(key)
        if prev is None or (now - prev) >= interval:
            self._last_throttled_log[key] = now
            logger.log(level, "%s", msg)
            return True
        return False

    def reset_key(self, key: str) -> None:
        """Drop a tracked transition *key* so its next occurrence logs again,
        without emitting a spurious transition line itself.
        """
        self._last_logged_values.pop(key, None)

    def clear(self) -> None:
        """Drop every tracked key (test isolation between passes/episodes)."""
        self._last_logged_values.clear()
        self._last_throttled_log.clear()


_log_dedup = LogDedupCache()


# Log de-duplication — three complementary mechanisms, one job each.
# New code should pick the one matching intent:
#   * RepeatSuppressionFilter — transport-level; drops a message once it has
#     repeated consecutively past a small threshold.  A blanket backstop; do
#     not rely on it for semantics.
#   * log_on_change(key, value, ...) — semantic *transitions*; emit only when a
#     tracked value changes (state/mode flips).  Use for "X changed -> Y".
#   * log_throttled(key, msg, interval=...) — time-window *rate limit*; emit at
#     most once per `interval` seconds for a condition that stays true (avoids
#     hammering while a persistent condition holds).  Use for repeated warnings.
def log_on_change(key: str, value: object, msg: str, level: int = logging.INFO) -> None:
    """Log msg at *level* only when (key -> value) changes (semantic transition)."""
    _log_dedup.on_change(key, value, msg, level)


def log_throttled(key: str, msg: str, *, interval: float,
                  level: int = logging.WARNING, now: "Optional[float]" = None) -> bool:
    """Log msg at most once per *interval* seconds per *key* (time-window throttle).

    The shared rate-limiter for a condition that stays true across passes.  Returns
    True when it logged this call.
    """
    return _log_dedup.throttled(key, msg, interval=interval, level=level, now=now)


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
    # A new committed SSID invalidates any BSSID observations, the pending pin
    # record, and any in-progress roam-candidate streak from the previous one,
    # across every scanning interface.
    with state_lock:
        wifi_policy.clear_bssid_tables(ADOPTION_STATE.bssid_tables)
        ADOPTION_STATE.last_bssid_pin = {}
        ADOPTION_STATE.bssid_roam_candidate = {}


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
    ok = wifi_activation._validate_activation(ACTIVATION_CTX, ifname, r_up)
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
        if APPLY_STATE.apply_in_progress:
            return False
        prev_result = APPLY_STATE.last_apply_result
        prev_error = APPLY_STATE.last_apply_error
        APPLY_STATE.apply_in_progress = True
        APPLY_STATE.last_apply_result = "applying"
        APPLY_STATE.last_apply_error = ""
    # The session success tail (set-active / leave-setup / avahi) is applied by
    # apply_activation_result on the loop thread — exactly as the
    # other job kinds — so carry the leave-setup flags the shared tail reads.
    job = wifi_activation.ActivationJob(
        epoch=wifi_activation._next_activation_epoch(ACTIVATION_CTX), kind="apply_credentials",
        ifname="", ssid=ssid, password=pw,
        on_success_leaves_setup=True,
        leave_reason="WiFi client connection succeeded")
    if not wifi_activation.submit_activation_job(ACTIVATION_CTX, job):
        with state_lock:
            APPLY_STATE.apply_in_progress = False
            APPLY_STATE.last_apply_result = prev_result
            APPLY_STATE.last_apply_error = prev_error
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
    _apply_runtime_level(levelno)
    now = time.monotonic()
    with state_lock:
        if ttl_seconds:
            LOG_STATE.temporary_log_level = level
            LOG_STATE.temporary_log_level_until = now + ttl_seconds
        else:
            LOG_STATE.temporary_log_level = ""
            LOG_STATE.temporary_log_level_until = None
            LOG_STATE.default_log_level_name = level
    if ttl_seconds:
        logger.warning("Runtime log level changed to %s for %ds", level, ttl_seconds)
    else:
        logger.warning("Runtime log level changed to %s", level)


def revert_expired_log_level(now: Optional[float] = None) -> None:
    """Revert a temporary runtime log level once its TTL expires."""
    if now is None:
        now = time.monotonic()
    with state_lock:
        until = LOG_STATE.temporary_log_level_until
        if until is None or now < until:
            return
        default = LOG_STATE.default_log_level_name or "info"
        LOG_STATE.temporary_log_level = ""
        LOG_STATE.temporary_log_level_until = None
    _apply_runtime_level(RUNTIME_LOG_LEVELS.get(default, logging.INFO))
    logger.warning("Runtime log level reverted to %s", default)


def process_control_action(action: str, params: Optional[dict] = None) -> None:
    """Consume one queued control action in the monitor loop."""
    params = params or {}
    with state_lock:
        CONTROL_STATE.control_in_progress = True
        CONTROL_STATE.last_control_action = action
        CONTROL_STATE.last_control_error = ""
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
            result = "ok" if wifi_adoption.start_reconnect_saved_episode(
                ADOPTION_CTX, "retain_hotspot") else "failed"
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
            CONTROL_STATE.last_control_error = str(e)
    with state_lock:
        CONTROL_STATE.control_in_progress = False
        CONTROL_STATE.last_control_result = result


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


def handle_reconfigure_timeout() -> None:
    """30-minute explicit-reconfiguration timeout rollback (starts an episode)."""
    logger.info("Explicit network setup timed out after %ds; restoring previous", wifi_policy.AP_MAX_DURATION)
    wifi_adoption.start_reconnect_saved_episode(ADOPTION_CTX, failure_tail="reconfigure_timeout")



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
        active_client=wifi_adoption.resolve_active_client(adapters),
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
    by_ifname = {a.ifname: wifi_recovery.adapter_recovery_facts(RECOVERY_CTX, a, now, facts.health_memo)
                 for a in adapters}

    builtin = wifi_net.resolve_builtin(adapters)
    usb = wifi_net.usb_candidates(adapters)
    hotspot = resolve_hotspot_adapter(adapters)
    with state_lock:
        in_setup = STATE.setup_mode
        onboard_budget_spent = (
            STATE.onboard_activation_failures >= ONBOARD_ACTIVATION_MAX_FAILURES)
        failover_reset_done = set(RECOVERY_STATE.failover_reset_done)

    preferred_usb = ""
    for a in usb:
        rf = by_ifname.get(a.ifname)
        if (rf is not None and rf.managed and not rf.quarantined
                and not rf.noip_suppressed and not rf.disabled):
            preferred_usb = a.ifname
            break

    # failover_reset_spent is keyed to preferred_usb specifically (the adapter
    # whose RESET_USB rung it gates), not the active client.
    preferred_usb_rf = by_ifname.get(preferred_usb) if preferred_usb else None
    failover_reset_spent = bool(
        preferred_usb_rf is not None and preferred_usb_rf.stable_id
        and preferred_usb_rf.stable_id in failover_reset_done)

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
        failover_reset_spent=failover_reset_spent,
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
# step_* Verdict handlers live in platform/wifi_loop.py, driven through
# LOOP_CTX exposing only the STATE, constants and callables the handlers use.
# network_monitor_loop builds its ordered phase lists directly from
# wifi_loop.step_* bound to LOOP_CTX with functools.partial.


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

    loop_state = wifi_loop.LoopState()  # persists across passes (last_avahi_check)

    # Ordered handler lists.  Built once.  step_avahi_hostname also needs the
    # cross-pass loop_state; it is bound with functools.partial so run_steps keeps
    # a single uniform step(ctx) calling convention (§4.4).
    phase_a = [
        partial(wifi_adoption.step_reconnect_episode, ADOPTION_CTX),
        partial(wifi_activation.step_apply_activation_result, ACTIVATION_CTX),
        partial(wifi_loop.step_avahi_hostname, LOOP_CTX, loop_state=loop_state),
        partial(wifi_loop.step_mdns_reannounce, LOOP_CTX),
        partial(wifi_loop.step_revert_log_level, LOOP_CTX),
        partial(wifi_loop.step_control_action, LOOP_CTX),
        partial(wifi_loop.step_reconfigure_timeout, LOOP_CTX),
    ]
    phase_b_early = [
        partial(wifi_loop.step_update_known_adapters, LOOP_CTX),
        partial(wifi_loop.step_boot_client_bringup, LOOP_CTX),
    ]
    phase_b_late = [
        partial(wifi_loop.step_usb_failure_fallback, LOOP_CTX),
        partial(wifi_loop.step_runtime_usb_adoption, LOOP_CTX),
        partial(wifi_loop.step_noip_holdback_reset, LOOP_CTX),
        partial(wifi_loop.step_dead_phy_recovery, LOOP_CTX),
        partial(wifi_loop.step_publish_state, LOOP_CTX),
        partial(wifi_loop.step_bssid_survey, LOOP_CTX),
        partial(wifi_loop.step_ethernet_wins, LOOP_CTX),
        partial(wifi_loop.step_hotspot_policy, LOOP_CTX),
        partial(wifi_loop.step_boot_ap_entry, LOOP_CTX),
        partial(wifi_loop.step_connection_reliability, LOOP_CTX),
        partial(wifi_loop.step_catchall_reboot, LOOP_CTX),
    ]

    while True:
        now = time.monotonic()
        with state_lock:
            boot_time = STATE.boot_time or now
            avahi_ok = not STATE.setup_mode and not APPLY_STATE.apply_in_progress
        pre = wifi_loop.PreFactsContext(now=now, boot_time=boot_time, avahi_ok=avahi_ok)
        if run_steps(phase_a, pre) is Verdict.OWN_PASS:
            if _sleep_or_finish_monitor_pass(run_once):
                return
            continue

        # Single immutable per-tick snapshot: one discover_adapters /
        # wired probe / address enumeration per pass; playback via the per-pass memo.
        fctx = wifi_loop.FactsContext(pre, gather_facts(), _make_playing_status_memo())
        if run_steps(phase_b_early, fctx) is Verdict.OWN_PASS:
            if _sleep_or_finish_monitor_pass(run_once):
                return
            continue

        # Named phase boundary between B-early and B-late (never owns the pass).
        hctx = wifi_loop.finalize_active_client_and_health(LOOP_CTX, fctx)
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
        pending = ADOPTION_STATE.pending_usb_adoption_mac is not None
    if pending:
        log_throttled(
            "playing_status_unavailable",
            "Playing status unavailable while USB adoption pending; deferring",
            interval=PLAYING_STATUS_WARN_THROTTLE,
        )


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


def build_contexts() -> None:
    """Construct every context, in dependency order, and bind module globals.

    Called once at import time (below). Two genuine two-way dependencies exist
    between the recovery and activation/adoption seams:

    - ``RECOVERY_CTX`` needs activation-bound callables (``client_up_tail``,
      ``_activate_committed_on``) to run its reset/retry rung, while
      ``ACTIVATION_CTX`` needs the real ``RECOVERY_CTX`` object as a field.
      Broken by building ``RECOVERY_CTX`` first, with local closures for the
      two activation callables that resolve ``ACTIVATION_CTX`` at call time
      (by then this function has returned and the global is set); passing the
      already-built ``RECOVERY_CTX`` object into ``ACTIVATION_CTX`` needs no
      such trick.
    - ``ACTIVATION_CTX`` needs adoption-bound callables
      (``clear_pending_adoption``, ``advance_reconnect_episode``) that only
      exist once ``ADOPTION_CTX`` is built, and ``ADOPTION_CTX`` needs
      activation-bound callables in return. Broken the same way: local
      closures on the activation side resolve ``ADOPTION_CTX`` at call time.
    - ``RECOVERY_CTX.wait_for_interface_reappears`` is a genuine self-reference
      (it must be handed the very context it is a field of); resolved with a
      local closure that reads the ``RECOVERY_CTX`` global once this function
      has returned.
    """
    global nm, HOTSPOT_CTX, hotspot_controller, RECOVERY_STATE, CONFIG_CTX
    global ACTIVATION_CTX, RECOVERY_CTX, ADOPTION_CTX, STATUS_CTX, MDNS_CTX
    global WEB_CTX, app, LOOP_CTX

    # The single bounded nmcli client; every nmcli invocation passes one of
    # NMCLI_ACTIVATE_TIMEOUT/NMCLI_QUICK_TIMEOUT, so there is no unbounded
    # NetworkManager code path.
    nm = wifi_nm.NMClient(NMCLI_ACTIVATE_TIMEOUT, NMCLI_QUICK_TIMEOUT)

    # The single source of hotspot mechanics: start/stop/rebuild/clear-stale
    # sequencing and flag ordering, driven through a narrow HotspotContext.
    HOTSPOT_CTX = wifi_hotspot.HotspotContext(
        STATE=STATE,
        state_lock=state_lock,
        nm=nm,
        AP_CONNECTION_NAME=AP_CONNECTION_NAME,
        start_ap_mode=start_ap_mode,
        stop_ap_mode=stop_ap_mode,
        update_apmode_flag=update_apmode_flag,
        clear_apmode_flag=clear_apmode_flag,
    )
    hotspot_controller = wifi_hotspot.HotspotController(HOTSPOT_CTX)

    # Owns the dead-PHY / reset / no-IP / manual-disable ledgers; shared with
    # wifi_status (read-only, for the status snapshot) via StatusContext.
    RECOVERY_STATE = wifi_recovery.RecoveryState()

    # The steady-state reconnect path and first-boot profile adoption/
    # migration live in platform/wifi_config.py, driven through a
    # ConfigContext exposing only the NM client, the state-file paths and the
    # small set of watcher callables the helpers invoke.
    CONFIG_CTX = wifi_config.ConfigContext(
        nm=nm,
        logger=logger,
        NETWORK_STATE_PATH=NETWORK_STATE_PATH,
        CONFIGURED_SSID=CONFIGURED_SSID,
        FIRST_BOOT_IMPORT_MARKER=FIRST_BOOT_IMPORT_MARKER,
        get_configured_network_state=get_configured_network_state,
        is_wifi_client_healthy=is_wifi_client_healthy,
        _activation_network_absent=wifi_activation._activation_network_absent,
        _commit_network_state=_commit_network_state,
    )

    # Closures for the recovery<->activation cycle: RECOVERY_CTX needs these
    # activation-bound callables now, but ACTIVATION_CTX (below) is what they
    # must be bound to; each resolves the ACTIVATION_CTX global at call time.
    def client_up_tail_closure(*args, **kwargs):
        return wifi_activation.client_up_tail(ACTIVATION_CTX, *args, **kwargs)

    def activate_committed_on_closure(*args, **kwargs):
        return wifi_activation._activate_committed_on(ACTIVATION_CTX, *args, **kwargs)

    # RECOVERY_CTX.wait_for_interface_reappears is handed RECOVERY_CTX itself;
    # this closure resolves the RECOVERY_CTX global at call time, once this
    # function has returned and the global is set.
    def wait_for_interface_reappears_closure(
        target, timeout=wifi_recovery.INTERFACE_REAPPEAR_TIMEOUT,
    ):
        return wifi_recovery.wait_for_interface_reappears(RECOVERY_CTX, target, timeout)

    # Detection, reset budgets, the persistent reboot guard, and the recovery
    # ladder live in platform/wifi_recovery.py, driven through a narrow
    # RecoveryContext exposing the STATE, the reset/quarantine/reboot
    # constants and the policy helpers the ladder invokes.
    RECOVERY_CTX = wifi_recovery.RecoveryContext(
        STATE=STATE,
        state_lock=state_lock,
        logger=logger,
        RECOVERY_STATE=RECOVERY_STATE,
        ADOPTION_STATE=ADOPTION_STATE,
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
        client_up_tail=client_up_tail_closure,
        _activate_committed_on=activate_committed_on_closure,
        wait_for_interface_reappears=wait_for_interface_reappears_closure,
        resolve_hotspot_adapter=resolve_hotspot_adapter,
        request_guarded_reboot=request_guarded_reboot,
    )

    # Closures for the activation<->adoption cycle: ACTIVATION_CTX needs
    # these adoption-bound callables now, but ADOPTION_CTX (built after
    # ACTIVATION_CTX, since adoption needs activation-bound callables in
    # return) is what they must be bound to; each resolves the ADOPTION_CTX
    # global at call time.
    def clear_pending_adoption_closure() -> None:
        wifi_adoption._clear_pending_adoption(ADOPTION_CTX)

    def advance_reconnect_episode_closure(result: "wifi_activation.ActivationResult") -> None:
        wifi_adoption._advance_reconnect_episode(ADOPTION_CTX, result)

    # These three look up wifi_recovery's names by attribute at call time
    # (rather than a functools.partial captured now) so tests may patch
    # wifi_recovery.clear_noip_failures / clear_dead_adapter_state /
    # record_noip_failure and have ACTIVATION_CTX observe the patch.
    def clear_noip_failures_closure(stable_id) -> None:
        wifi_recovery.clear_noip_failures(RECOVERY_CTX, stable_id)

    def clear_dead_adapter_state_closure() -> None:
        wifi_recovery.clear_dead_adapter_state(RECOVERY_CTX)

    def record_noip_failure_closure(record_id, at: float) -> int:
        return wifi_recovery.record_noip_failure(RECOVERY_CTX, record_id, at)

    # The activation context: the worker and loop-tail helpers thread this
    # ctx through every call.
    ACTIVATION_CTX = wifi_activation.ActivationContext(
        STATE=STATE,
        APPLY_STATE=APPLY_STATE,
        ADOPTION_STATE=ADOPTION_STATE,
        state_lock=state_lock,
        RECOVERY_STATE=RECOVERY_STATE,
        RECOVERY_CTX=RECOVERY_CTX,
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
        clear_noip_failures=clear_noip_failures_closure,
        clear_dead_adapter_state=clear_dead_adapter_state_closure,
        record_noip_failure=record_noip_failure_closure,
        clear_pending_adoption=clear_pending_adoption_closure,
        advance_reconnect_episode=advance_reconnect_episode_closure,
    )

    # The adoption context: the fallback/adoption/reconnect-episode helpers
    # thread this ctx through every call.
    ADOPTION_CTX = wifi_adoption.AdoptionContext(
        STATE=STATE,
        ADOPTION_STATE=ADOPTION_STATE,
        state_lock=state_lock,
        logger=logger,
        RECOVERY_CTX=RECOVERY_CTX,
        nm=nm,
        HotspotPurpose=wifi_policy.HotspotPurpose,
        Verdict=Verdict,
        reset_log_key=_log_dedup.reset_key,
        RECOVERY_SCAN_INTERVAL=RECOVERY_SCAN_INTERVAL,
        RECONNECT_ATTEMPT_INTERVAL=RECONNECT_ATTEMPT_INTERVAL,
        ADOPTION_SCAN_INTERVAL=ADOPTION_SCAN_INTERVAL,
        USB_ADOPTION_STABLE_PASSES=USB_ADOPTION_STABLE_PASSES,
        EMPTY_SCAN_RESET_STREAK=EMPTY_SCAN_RESET_STREAK,
        BSSID_SURVEY_INTERVAL=BSSID_SURVEY_INTERVAL,
        get_configured_network_state=get_configured_network_state,
        is_wifi_client_healthy=is_wifi_client_healthy,
        resolve_hotspot_adapter=resolve_hotspot_adapter,
        hotspot_station_count=hotspot_station_count,
        query_playing_status=query_playing_status,
        log_on_change=log_on_change,
        gather_recovery_facts=gather_recovery_facts,
        enter_setup_mode=enter_setup_mode,
        submit_activation_job=partial(wifi_activation.submit_activation_job, ACTIVATION_CTX),
        next_activation_epoch=partial(wifi_activation._next_activation_epoch, ACTIVATION_CTX),
    )

    # Snapshot construction/publishing lives in platform/wifi_status.py,
    # driven through a StatusContext exposing the STATE, the three recovery
    # constants and the fact helpers the snapshot surfaces.
    STATUS_CTX = wifi_status.StatusContext(
        STATE=STATE,
        LOG_STATE=LOG_STATE,
        SNAPSHOT_STATE=SNAPSHOT_STATE,
        ADOPTION_STATE=ADOPTION_STATE,
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
        _adapter_recovery_facts=partial(wifi_recovery.adapter_recovery_facts, RECOVERY_CTX),
    )

    # The avahi/mDNS block (hostname-drift repair + address-set re-announce
    # debounce) lives in platform/wifi_mdns.py, driven through an MdnsContext
    # exposing the MDNS_STATE fragment, the constants and the callables it
    # uses.  The monitor loop calls
    # ``wifi_mdns.check_and_repair_avahi_hostname(MDNS_CTX)`` and
    # ``wifi_mdns.maybe_reannounce_mdns(MDNS_CTX, now)`` every pass via the
    # LOOP_CTX fields bound below.
    MDNS_CTX = wifi_mdns.MdnsContext(
        MDNS_STATE=MDNS_STATE,
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

    # The narrowed Flask/HTTP seam: build_app() closes its handlers over this
    # ctx and init_control_token()/remove_control_token() are driven from
    # __main__.
    WEB_CTX = wifi_web.WebContext(
        app_name=__name__,
        STATE=STATE,
        APPLY_STATE=APPLY_STATE,
        CONTROL_STATE=CONTROL_STATE,
        SNAPSHOT_STATE=SNAPSHOT_STATE,
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

    # The narrowed monitor-loop seam, built last (every callable it needs
    # already exists): network_monitor_loop binds each handler to this ctx
    # with functools.partial when building the ordered phase lists.
    LOOP_CTX = wifi_loop.LoopContext(
        STATE=STATE,
        APPLY_STATE=APPLY_STATE,
        CONTROL_STATE=CONTROL_STATE,
        RECOVERY_STATE=RECOVERY_STATE,
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
        update_known_adapters=partial(wifi_adoption.update_known_adapters, ADOPTION_CTX),
        gather_recovery_facts=gather_recovery_facts,
        submit_client_activation=partial(wifi_adoption._submit_client_activation, ADOPTION_CTX),
        handle_usb_failure_fallback=partial(wifi_adoption.handle_usb_failure_fallback, ADOPTION_CTX),
        handle_runtime_usb_adoption=partial(wifi_adoption.handle_runtime_usb_adoption, ADOPTION_CTX),
        bssid_survey_and_roam=partial(wifi_adoption.bssid_survey_and_roam, ADOPTION_CTX),
        maybe_reset_noip_held_usb=partial(wifi_recovery.maybe_reset_noip_held_usb, RECOVERY_CTX),
        escalate_dead_adapter_recovery=partial(wifi_recovery.escalate_dead_adapter_recovery, RECOVERY_CTX),
        publish_network_status=partial(wifi_status.publish_network_status, STATUS_CTX),
        hotspot_blocks_eth=_hotspot_blocks_eth,
        leave_setup_mode=leave_setup_mode,
        enter_setup_mode=enter_setup_mode,
        set_active_client=partial(wifi_activation._set_active_client, ACTIVATION_CTX),
        connect_to_configured_wifi=partial(wifi_config.connect_to_configured_wifi, CONFIG_CTX),
        request_network_down_reboot=_request_network_down_reboot,
        attempt_recovery_reconnect=partial(wifi_adoption._attempt_recovery_reconnect, ADOPTION_CTX),
        next_mode=wifi_policy.next_mode,
        next_recovery_action=wifi_policy.next_recovery_action,
        RecoveryKind=wifi_policy.RecoveryKind,
        PURPOSE_TABLE=wifi_policy.PURPOSE_TABLE,
    )


build_contexts()


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
    wifi_activation.start_activation_worker(ACTIVATION_CTX)

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
