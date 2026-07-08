"""Pure Wi-Fi connectivity policy for the watcher.

This module holds the watcher's *effect-free* decision core: the connectivity
``Mode`` enum, the hotspot ``HotspotPurpose`` enum and its ``PURPOSE_TABLE``
policy rows, and the pure forward-mode and recovery-ladder classifiers plus
their plain policy input types.

Nothing here reads ``STATE``, runs a subprocess, performs an effect, or depends
on any watcher context or on live ``autostream_wifi_network`` adapter
objects.  ``platform/wifi_watcher.py`` imports this module directly and adapts
its runtime facts into the plain policy inputs, so this module stays
importable and testable on its own.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


# ---- Timing policy constants -------------------------------------------------
# The hotspot lifetime and the user-opened-hotspot probe grace are policy, not
# transport, so they live with the purpose table they parameterise.  There is no
# once-per-boot AP budget: the 30-minute session lifetime is the rate limit.
AP_MAX_DURATION = 30 * 60               # AP mode lifetime for configured devices
HOTSPOT_PROBE_GRACE = 15 * 60           # user-opened hotspot delay before probing for the saved network
BOOT_AP_GRACE = 60                      # still offline after this many seconds of boot -> boot-window AP entry


class Mode(Enum):
    """The watcher's explicit connectivity operating mode."""
    BOOT = "boot"
    ONLINE = "online"
    OFFLINE_RECONNECTING = "offline_reconnecting"
    HOTSPOT = "hotspot"
    REBOOT_PENDING = "reboot_pending"


class HotspotPurpose(Enum):
    """Why the setup hotspot is up — the single key into PURPOSE_TABLE."""
    FIRST_RUN = "first_run"
    BOOT_RECOVERY = "boot_recovery"
    USB_LOSS_RECOVERY = "usb_loss_recovery"
    EXPLICIT_RECONFIGURE = "explicit_reconfigure"
    MANUAL = "manual"


@dataclass(frozen=True)
class PurposePolicy:
    """One row of PURPOSE_TABLE — pure data, no behaviour."""
    deadline_s: Optional[float]   # None = indefinite (FIRST_RUN)
    eth_suppressible: bool
    probes_return: bool
    rollback: bool
    probe_grace_s: float = 0.0    # delay after entry before probing for the saved network (user-initiated hotspots)


# The five-row purpose table: the single source of hotspot entry/exit policy.
# eth-suppressible == "automatic purpose"; user-initiated purposes
# (EXPLICIT_RECONFIGURE, MANUAL) are never torn down by Ethernet appearing.
PURPOSE_TABLE: "dict[HotspotPurpose, PurposePolicy]" = {
    HotspotPurpose.FIRST_RUN:            PurposePolicy(None,          True,  False, False, 0.0),
    HotspotPurpose.BOOT_RECOVERY:        PurposePolicy(AP_MAX_DURATION, True,  True,  False, 0.0),
    HotspotPurpose.USB_LOSS_RECOVERY:    PurposePolicy(AP_MAX_DURATION, True,  True,  False, 0.0),
    HotspotPurpose.EXPLICIT_RECONFIGURE: PurposePolicy(AP_MAX_DURATION, False, True,  True,  HOTSPOT_PROBE_GRACE),
    HotspotPurpose.MANUAL:               PurposePolicy(AP_MAX_DURATION, False, True,  False, HOTSPOT_PROBE_GRACE),
}


def next_mode(state, facts) -> "Mode":
    """The pure forward mode classifier: state + facts -> Mode.

    Pure: reads *state* fields and *facts* (needs only ``facts.wired_ok`` and
    ``facts.taken_at``) plus this module's constants; it does not mutate STATE,
    call subprocesses, run effects, or depend on the ``w`` seam.  The watcher's
    loop *applies* the returned value by setting ``STATE.mode`` each pass, and it
    is published as ``device.mode``.  Together with PURPOSE_TABLE it is the
    explicit-model decision core.

    Precedence mirrors the live loop: hotspot wins, then an accepted reboot, then
    a usable path means ONLINE, then the boot grace window means BOOT, otherwise
    the configured-but-offline device is OFFLINE_RECONNECTING.
    """
    if state.setup_mode:
        return Mode.HOTSPOT
    if state.conn_reboot_retry_after == float("inf"):
        return Mode.REBOOT_PENDING
    if bool(facts.wired_ok) or bool(state.connectivity_ok):
        return Mode.ONLINE
    boot_time = state.boot_time
    if boot_time is not None and (facts.taken_at - boot_time) < BOOT_AP_GRACE:
        return Mode.BOOT
    return Mode.OFFLINE_RECONNECTING


# ---- Recovery-ladder classifier ---------------------------------------------
# A second pure classifier alongside next_mode: next_recovery_action(state,
# recovery_facts) -> RecoveryAction.  It reads a pre-gathered immutable snapshot
# only (RecoveryFacts carries plain scalars + a dict of duck-typed per-adapter
# recovery facts — no wifi_net objects), so it lifts here unchanged.  The
# watcher's gather_recovery_facts adapts runtime facts into RecoveryFacts.


@dataclass(frozen=True)
class RecoveryFacts:
    """One immutable per-tick snapshot for the recovery-ladder classifier.

    Adapter identity is carried as ifnames (hashable, pure data); the apply layer
    re-resolves adapter objects from the live Facts.adapters when it needs them.
    ``preferred_usb_ifname`` is the first deterministic USB candidate still worth
    engaging as a client (present, managed, not quarantined, not no-IP-suppressed)
    — the "USB budget spent -> drop to onboard" rung falls out of this being "".
    """
    adapters_by_ifname: dict          # ifname -> wifi_recovery.AdapterRecoveryFacts
    onboard_ifname: str               # "" when no built-in radio
    usb_ifnames: tuple                # USB candidate ifnames, deterministic order
    preferred_usb_ifname: str         # first usable USB, else ""
    hotspot_ifname: str               # AP-hosting adapter while in setup, else ""
    active_ifname: str                # active client ifname, else ""
    saved_configured: bool            # a client profile is committed
    wired_ok: bool
    taken_at: float


class RecoveryKind(Enum):
    """The single recovery remediation the ladder selects for this pass."""
    HOLD = "hold"                      # active path fine / Ethernet / defer to dead-PHY reset
    ACTIVATE_USB = "activate_usb"      # (re)activate the committed profile on the preferred USB
    ACTIVATE_ONBOARD = "activate_onboard"  # run the client on the built-in radio (drop AP if hosting)
    ENTER_HOTSPOT = "enter_hotspot"    # last resort: no radio can carry a client


@dataclass(frozen=True)
class RecoveryAction:
    """One recovery decision — pure data returned by next_recovery_action()."""
    kind: RecoveryKind
    ifname: str = ""                              # target radio for ACTIVATE_*
    purpose: "Optional[HotspotPurpose]" = None    # for ENTER_HOTSPOT
    drop_hotspot: bool = False                    # ACTIVATE_* must tear down the AP on ifname first
    reason: str = ""


def next_recovery_action(state, facts) -> "RecoveryAction":
    """Pure recovery-ladder classifier: state + RecoveryFacts -> RecoveryAction.

    Like next_mode() this reads a pre-gathered immutable snapshot only: no STATE
    mutation, no subprocess, no effects.  It owns the single
    *client-path-vs-hotspot* priority ladder (Ethernet > preferred USB > onboard >
    hotspot-last-resort) used at boot entry, on USB failure, and at the
    recovery-hotspot probe.  The low-level USB reset/quarantine/reboot
    *mechanics* remain owned by the dead-PHY module; a wedged USB with no
    onboard alternative is deferred to it via HOLD.
    """
    by = facts.adapters_by_ifname
    active = facts.active_ifname
    active_rf = by.get(active) if active else None
    in_hotspot = bool(facts.hotspot_ifname)

    # Ethernet wins; the recovery ladder does not engage.
    if facts.wired_ok:
        return RecoveryAction(RecoveryKind.HOLD, reason="wired_ok")

    # Unconfigured: nothing to reconnect; a first-run hotspot is the only option.
    if not facts.saved_configured:
        if in_hotspot:
            return RecoveryAction(RecoveryKind.HOLD, reason="unconfigured_hotspot_up")
        return RecoveryAction(RecoveryKind.ENTER_HOTSPOT,
                              purpose=HotspotPurpose.FIRST_RUN, reason="unconfigured")

    # Active client already healthy -> nothing to recover (idle USB adoption is a
    # separate, playback-gated optimisation, not part of failure recovery).
    if active_rf is not None and active_rf.healthy and not in_hotspot:
        return RecoveryAction(RecoveryKind.HOLD, reason="active_healthy")

    preferred_usb = facts.preferred_usb_ifname
    usb_rf = by.get(preferred_usb) if preferred_usb else None
    usb_has_carrier = usb_rf is not None and usb_rf.link_down is not True
    onboard = facts.onboard_ifname

    # (1) USB is the highest-priority client path.  A usable (carrier-up) preferred
    #     USB that is not already our active client -> (re)activate it.
    if usb_has_carrier and active != preferred_usb:
        return RecoveryAction(RecoveryKind.ACTIVATE_USB, ifname=preferred_usb,
                              drop_hotspot=(preferred_usb == facts.hotspot_ifname),
                              reason="usb_preferred")
    # (1b) USB is the active client but unhealthy with carrier (associating / no-IP):
    #      hold — the no-IP ledger governs and promotes onboard once suppressed.
    if usb_has_carrier and active == preferred_usb:
        return RecoveryAction(RecoveryKind.HOLD, reason="usb_active_no_ip")

    # (2) No usable USB right now (absent / quarantined / no-IP-suppressed / wedged).
    #     Try the onboard radio as a client before any hotspot — this is the
    #     boot-entry onboard-first rule AND the exit edge from a recovery hotspot.
    if onboard and active != onboard:
        return RecoveryAction(RecoveryKind.ACTIVATE_ONBOARD, ifname=onboard,
                              drop_hotspot=(onboard == facts.hotspot_ifname),
                              reason="onboard_before_hotspot")

    # (3) A wedged/quarantined USB with no onboard alternative -> leave it to the
    #     dead-PHY reset/quarantine/reboot ladder (it owns a resettable USB PHY).
    if usb_rf is not None and not onboard:
        return RecoveryAction(RecoveryKind.HOLD, reason="usb_only_defer_reset_ladder")

    # (4) No radio can carry a client -> last-resort recovery hotspot.
    if not in_hotspot:
        return RecoveryAction(RecoveryKind.ENTER_HOTSPOT,
                              purpose=HotspotPurpose.BOOT_RECOVERY, reason="no_client_path")
    return RecoveryAction(RecoveryKind.HOLD, reason="hotspot_last_resort")


# ---- USB BSSID ownership: table maintenance + selection/roam policy --------
# Pure functions over a passed-in table dict (ADOPTION_STATE.bssid_table) — no
# STATE, no effects, consistent with this module's contract.  Units are nmcli
# SIGNAL percent (0-100) throughout.

BSSID_FRESH_SECS = 180          # max age for a selectable candidate
BSSID_EVICT_SECS = 900          # unseen entries evicted from the table
BSSID_QUARANTINE_FAILS = 3      # failures making an entry quarantinable
BSSID_QUARANTINE_SECS = 3600    # quarantine duration
ROAM_LOW_SIGNAL = 50            # "current link is weak" floor (approx -75 dBm)
ROAM_MARGIN = 12                # required candidate advantage (approx 6 dB)
ROAM_LOW_MARGIN = 6             # relaxed advantage when current <= low floor
ROAM_HOLDOFF_SECS = 900         # min gap between roams / after activation


def update_bssid_table(table: dict, rows: list, ssid: str, now: float) -> tuple:
    """Upsert *rows* matching *ssid* into *table*, then evict stale entries.

    Returns the in-use row's ``(bssid, signal)`` from *rows*, or ``("", 0)`` if
    none of the matching rows is in-use.
    """
    in_use_bssid, in_use_signal = "", 0
    for row in rows:
        if row.get("ssid") != ssid:
            continue
        bssid = row["bssid"]
        existing = table.get(bssid, {})
        table[bssid] = {
            "ssid": ssid,
            "signal": row["signal"],
            "last_seen": now,
            "fail_count": existing.get("fail_count", 0),
            "quarantined_until": existing.get("quarantined_until"),
        }
        if row.get("in_use"):
            in_use_bssid, in_use_signal = bssid, row["signal"]

    for bssid in [b for b, e in table.items() if now - e["last_seen"] > BSSID_EVICT_SECS]:
        del table[bssid]

    return in_use_bssid, in_use_signal


def record_bssid_failure(table: dict, bssid: str) -> None:
    """A pinned activation on *bssid* failed: count it toward quarantine."""
    entry = table.get(bssid)
    if entry is not None:
        entry["fail_count"] += 1


def record_bssid_success(table: dict, bssid: str, now: float) -> None:
    """A pinned activation on *bssid* succeeded: clear its count and quarantine
    other same-SSID entries that have accumulated enough failures.

    No success -> no quarantine: a whole-network outage never locks out APs.
    """
    entry = table.get(bssid)
    if entry is None:
        return
    entry["fail_count"] = 0
    ssid = entry["ssid"]
    for other_bssid, other in table.items():
        if other_bssid == bssid or other["ssid"] != ssid:
            continue
        if other["fail_count"] >= BSSID_QUARANTINE_FAILS:
            other["quarantined_until"] = now + BSSID_QUARANTINE_SECS


def select_bssid(table: dict, now: float, exclude: str = "") -> str:
    """Best selectable BSSID: fresh, not quarantined, not *exclude*.

    Ordered by (fail_count asc, signal desc); returns "" if none qualify.
    """
    candidates = []
    for bssid, entry in table.items():
        if bssid == exclude:
            continue
        if now - entry["last_seen"] > BSSID_FRESH_SECS:
            continue
        quarantined_until = entry.get("quarantined_until")
        if quarantined_until is not None and quarantined_until > now:
            continue
        candidates.append((entry["fail_count"], -entry["signal"], bssid))
    if not candidates:
        return ""
    candidates.sort()
    return candidates[0][2]


def next_roam_target(table: dict, current_bssid: str, now: float, playing,
                     last_roam_or_activation) -> str:
    """Pure roam decision: "" means hold, otherwise the target BSSID.

    Roams only when playback is exactly False (None defers), the holdoff has
    elapsed since the last roam/activation, and the best fresh, unquarantined
    candidate clears the signal margin over the current AP.
    """
    if playing is not False:
        return ""
    if last_roam_or_activation is not None and now - last_roam_or_activation < ROAM_HOLDOFF_SECS:
        return ""

    candidate = select_bssid(table, now, exclude=current_bssid)
    if not candidate:
        return ""

    current_entry = table.get(current_bssid)
    current_signal = current_entry["signal"] if current_entry else 0
    candidate_signal = table[candidate]["signal"]

    if candidate_signal >= current_signal + ROAM_MARGIN:
        return candidate
    if current_signal <= ROAM_LOW_SIGNAL and candidate_signal >= current_signal + ROAM_LOW_MARGIN:
        return candidate
    return ""


def clear_bssid_table(table: dict) -> None:
    table.clear()
