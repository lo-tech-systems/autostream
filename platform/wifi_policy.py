"""Pure Wi-Fi connectivity policy for the watcher.

This module holds the *effect-free* decision core the watcher settles on: the
connectivity ``Mode`` enum, the hotspot ``HotspotPurpose`` enum and its
``PURPOSE_TABLE`` policy rows, and (added in later work packages) the pure
forward-mode and recovery-ladder classifiers plus their plain policy input
types.

Nothing here reads ``STATE``, runs a subprocess, performs an effect, or depends
on the watcher's ``w`` seam or on live ``autostream_wifi_network`` adapter
objects.  ``platform/wifi_watcher`` re-exports these names and adapts its
runtime facts into the plain policy inputs, so this module stays importable and
testable on its own.
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


class Mode(Enum):
    """The watcher's explicit connectivity operating mode (Section 2.2)."""
    BOOT = "boot"
    ONLINE = "online"
    OFFLINE_RECONNECTING = "offline_reconnecting"
    HOTSPOT = "hotspot"
    REBOOT_PENDING = "reboot_pending"


class HotspotPurpose(Enum):
    """Why the setup hotspot is up — the single key into PURPOSE_TABLE (Section 2.3)."""
    FIRST_RUN = "first_run"
    BOOT_RECOVERY = "boot_recovery"
    USB_LOSS_RECOVERY = "usb_loss_recovery"
    EXPLICIT_RECONFIGURE = "explicit_reconfigure"
    MANUAL = "manual"


@dataclass(frozen=True)
class PurposePolicy:
    """One row of PURPOSE_TABLE (Section 2.3) — pure data, no behaviour."""
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
