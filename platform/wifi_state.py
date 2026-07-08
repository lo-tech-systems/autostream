#!/usr/bin/python3
"""wifi_state.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Data-only state definitions for the Autostream Wi-Fi watcher: the shared
connectivity-core ``NetworkMonitorState``, the per-concern state fragments
(``ApplyState``, ``ControlState``, ``LogLevelState``, ``MdnsState``,
``SnapshotState``), the plain rollback/hotspot-session data types, and the
single ``state_lock`` guarding all of them. A leaf module at the bottom of the
watcher's dependency graph — it imports nothing beyond the standard library
and contains no behaviour beyond dataclass defaults, so every other module can
depend on it without creating a cycle.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class RollbackSnapshot:
    """Rollback target for an EXPLICIT_RECONFIGURE session (mirrors rollback_* fields)."""
    connection_name: str
    connection_uuid: str
    adapter_mac: str


@dataclass
class HotspotSession:
    """The live hotspot session: purpose + entry time (+ rollback for reconfigure).

    ``purpose`` is a ``wifi_policy.HotspotPurpose`` value; typed ``object`` here
    so this leaf module carries no dependency on wifi_policy. deadline /
    eth_suppressible / probes_return are not stored here — they are looked up
    in wifi_policy.PURPOSE_TABLE[purpose] so policy lives in exactly one place.
    """
    purpose: object
    entered_at: float
    rollback: Optional[RollbackSnapshot] = None   # only EXPLICIT_RECONFIGURE


@dataclass
class ApplyState:
    """Credential-apply workflow / wait-page status, guarded by state_lock."""
    apply_in_progress: bool = False
    # idle | applying | ok | failed
    last_apply_result: str = "idle"
    # short error code/message (e.g. nmcli-failed, no-local-ip)
    last_apply_error: str = ""


@dataclass
class ControlState:
    """Local control API: queued action, in-flight marker, last outcome."""
    pending_control_action: str = ""
    pending_control_params: dict = field(default_factory=dict)
    control_in_progress: bool = False
    last_control_action: str = ""
    last_control_result: str = ""
    last_control_error: str = ""


@dataclass
class LogLevelState:
    """Runtime log-level control: an optional TTL-bound override plus the default."""
    temporary_log_level: str = ""
    temporary_log_level_until: Optional[float] = None
    default_log_level_name: str = "info"


@dataclass
class MdnsState:
    """Avahi hostname-drift repair and mDNS address-set re-announce debounce."""
    avahi_hostname: Optional[str] = None
    avahi_mismatch_start: Optional[float] = None
    last_avahi_restart: Optional[float] = None
    last_avahi_handover_restart: Optional[float] = None
    avahi_restart_count: int = 0
    # Set of (ifname, ipv4) the host currently publishes; None until first observed.
    mdns_address_set: Optional[frozenset] = None
    # Monotonic time the published address set last changed (debounce anchor).
    mdns_address_changed_at: Optional[float] = None
    # Explicit re-announce nudge from an orchestrated handover.
    mdns_reannounce_pending: bool = False


@dataclass
class SnapshotState:
    """The published runtime network-status snapshot."""
    network_status_snapshot: Optional[dict] = None
    network_status_updated_at: Optional[float] = None


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
    hotspot: Optional[HotspotSession] = None
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
    # A wifi_adoption.ReconnectEpisode; typed object so this leaf module carries
    # no dependency on wifi_adoption.
    reconnect_episode: Optional[object] = None
    # Authoritative connectivity mode, applied by the loop each pass from the
    # pure wifi_policy.next_mode() classifier and published as device.mode.
    # A wifi_policy.Mode value; None until the hub sets the initial value
    # right after constructing STATE, so this leaf module carries no
    # dependency on wifi_policy.
    mode: Optional[object] = None

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
    # shared with wifi_status for the status snapshot.  Apply-workflow,
    # local-control, and runtime-log-level fields live on ApplyState /
    # ControlState / LogLevelState; avahi/mDNS fields live on MdnsState; the
    # published status snapshot lives on SnapshotState — each threaded to the
    # contexts that read/write it.


# Synchronisation primitive for every fragment above.
state_lock = threading.Lock()
