"""dial_warning_text.py: the dial's warning table and the text that goes
with it.

Everything here is pure data and small pure functions: the fixed strings of
the No-WiFi, SD health and software update pages, the descriptor table
(WARNING_DESCRIPTORS), and the builder that turns one validated appliance
warning into a descriptor. The core builds its warning manager from this
table and a headless surface can render the same cards from it, so none of
it imports the display, the compositor or any drawing library.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from dial_core_state import (
    APPLIANCE_WARNING_MESSAGE_MAX, ApplianceWarning, DIAL_WARNING_ID, SEVERITY_CRITICAL,
    SEVERITY_INFO, SEVERITY_WARNING, _clean_text,
)
from dial_touch_layout import (
    GEOMETRY_NONE,
    GEOMETRY_NOWIFI,
    GEOMETRY_SDHEALTH,
    TouchZone,
)
from dial_update_watch import STATUS_SUCCESS, UpdateView
from dial_warnings import (
    ACTION_CLOSE,
    ACTION_RESTART,
    APPLIANCE_WARNING_PREFIX,
    KIND_STATUS,
    KIND_WARNING,
    WarningButton,
    WarningDescriptor,
)

# The No-WiFi page's fixed strings.
NOWIFI_WARNING_ID = "nowifi"
NOWIFI_MESSAGE_TEXT = "No WiFi"
NOWIFI_CLOSE_TEXT = "Close"
NOWIFI_RESTART_TEXT = "Restart"
# The SD card warning's fixed strings: a title at readout size and a body
# line at body size (the percent is filled in), over one Close cell.
SDHEALTH_TITLE_TEXT = "microSD Health"
SDHEALTH_BODY_TEXT = "{percent}%: Replace Soon"
SDHEALTH_BODY_TEXT_NO_PERCENT = "Replace Soon"
SDHEALTH_CLOSE_TEXT = "Close"

# The SD card warning is critical once the reading is under this.
SDHEALTH_CRITICAL_PERCENT = 3


def _sdhealth_severity_for(percent) -> str:
    if isinstance(percent, int) and percent < SDHEALTH_CRITICAL_PERCENT:
        return SEVERITY_CRITICAL
    return SEVERITY_WARNING


def _sdhealth_message_for(percent) -> str:
    if percent is None:
        return SDHEALTH_BODY_TEXT_NO_PERCENT
    return SDHEALTH_BODY_TEXT.format(percent=percent)


# The software update cards. The in-progress card's title is fixed and its
# message is a short label chosen by the update's phase (never the result
# file's long message, which is for the appliance's web page); the result
# card says how the run ended and names the version. All of it must fit on
# the smallest panel without truncation (tests render every string).
UPDATING_TEXT = "Updating..."
UPDATED_TEXT = "Updated"
UPDATE_FAILED_TEXT = "Update failed"
UPDATE_RESULT_CLOSE_TEXT = "Close"
UPDATE_PHASE_FALLBACK_TEXT = "Please wait"
UPDATE_PHASE_TEXT = {
    "download": "Downloading",
    "prepare": "Preparing",
    "packages": "Upgrading OS",
    "python": "Installing",
    "files": "Installing",
    "configure": "Installing",
    "staged": "Restarting",
    "reboot": "Restarting",
}

# How long the result card waits for someone to see it before clearing
# itself: an update can take most of an hour and is often left unattended.
# Close clears it sooner.
UPDATE_RESULT_SECONDS = 3600.0


def _update_title_for(_view) -> str:
    return UPDATING_TEXT


def _update_message_for(view) -> str:
    phase = view.phase if isinstance(view, UpdateView) else ""
    return UPDATE_PHASE_TEXT.get(phase, UPDATE_PHASE_FALLBACK_TEXT)


def _update_progress_for(view) -> "int | None":
    return view.percent if isinstance(view, UpdateView) else None


def _update_result_title_for(view) -> str:
    if isinstance(view, UpdateView) and view.status == STATUS_SUCCESS:
        return UPDATED_TEXT
    return UPDATE_FAILED_TEXT


def _update_result_message_for(view) -> str:
    if not isinstance(view, UpdateView):
        return ""
    if view.status == STATUS_SUCCESS:
        return f"Version {view.tag}" if view.tag else ""
    if view.rolled_back:
        return f"Restored {view.previous_tag}" if view.previous_tag else "Restored previous"
    return f"{view.previous_tag} kept" if view.previous_tag else "Previous kept"


def _warning_severity(_reading) -> str:
    return SEVERITY_WARNING


def _info_severity(_reading) -> str:
    return SEVERITY_INFO


# The warning for a dial older than an appliance it talks to. Its reading is
# the tuple of those appliances' names.
UPDATE_DIAL_TITLE_TEXT = "Update this dial"


def _update_dial_message_for(names) -> str:
    names = tuple(names or ())
    verb = "needs" if len(names) == 1 else "need"
    return _clean_text(f"{', '.join(names)} {verb} a newer dial", APPLIANCE_WARNING_MESSAGE_MAX)


# ---------------------------------------------------------------------------
# On-screen warnings
#
# One descriptor per warning. A warning's source (the network poller, the
# SD health reader) reports it active or cleared on the
# manager; everything else (which page, which buttons, its severity, which
# one wins when two are due) is read from its row here. Adding a warning is
# adding a row plus a source; the screen-policy table, the opener, the
# painter and the touch dispatch are all driven from this tuple.
#
# Priority: a lost link outranks a worn card (the page is the only way to
# ask for a restart), so "nowifi" carries the higher number.
#
# Warnings an appliance supplies are not rows here: each validated one is
# turned into a descriptor of the same shape by appliance_warning_descriptor()
# and registered on the manager while the appliance reports it, so a new
# appliance warning needs no change to the dial.
# ---------------------------------------------------------------------------

WARNING_DESCRIPTORS: tuple[WarningDescriptor, ...] = (
    WarningDescriptor(
        id=NOWIFI_WARNING_ID, kind=KIND_WARNING, priority=100, screen="nowifi", geometry=GEOMETRY_NOWIFI,
        title=NOWIFI_MESSAGE_TEXT, message_for=None, severity_for=_warning_severity,
        buttons=(
            WarningButton(TouchZone.NOWIFI_DISMISS, NOWIFI_CLOSE_TEXT, ACTION_CLOSE),
            WarningButton(TouchZone.NOWIFI_RESTART, NOWIFI_RESTART_TEXT, ACTION_RESTART),
        ),
    ),
    WarningDescriptor(
        id="sdhealth", kind=KIND_WARNING, priority=50, screen="sdhealth", geometry=GEOMETRY_SDHEALTH,
        title=SDHEALTH_TITLE_TEXT, message_for=_sdhealth_message_for,
        severity_for=_sdhealth_severity_for,
        buttons=(
            WarningButton(TouchZone.SDHEALTH_DISMISS, SDHEALTH_CLOSE_TEXT, ACTION_CLOSE),
        ),
    ),
    # The dial itself is older than an appliance it talks to: one warning
    # for all of them, its reading the names of the appliances that are
    # ahead of it.
    WarningDescriptor(
        id=DIAL_WARNING_ID, kind=KIND_WARNING, priority=40, screen=DIAL_WARNING_ID,
        geometry=GEOMETRY_SDHEALTH, title=UPDATE_DIAL_TITLE_TEXT,
        message_for=_update_dial_message_for, severity_for=_warning_severity,
        buttons=(
            WarningButton(TouchZone.SDHEALTH_DISMISS, SDHEALTH_CLOSE_TEXT, ACTION_CLOSE),
        ),
    ),
    # A software update in progress: above No-WiFi (the link may drop while
    # the system upgrades), no buttons (touch does nothing), shown over
    # whatever is up and waking the panel; its source clears it.
    WarningDescriptor(
        id="update", kind=KIND_STATUS, priority=200, screen="update", geometry=GEOMETRY_NONE,
        title=UPDATING_TEXT, message_for=_update_message_for, severity_for=_info_severity,
        buttons=(),
        title_for=_update_title_for, progress_for=_update_progress_for,
        interrupting=True,
    ),
    # How an update ended: one Close (the SD page's cell), clears itself
    # after UPDATE_RESULT_SECONDS.
    WarningDescriptor(
        id="update_result", kind=KIND_STATUS, priority=150, screen="update_result",
        geometry=GEOMETRY_SDHEALTH, title=UPDATED_TEXT, message_for=_update_result_message_for,
        severity_for=_info_severity,
        buttons=(
            WarningButton(TouchZone.SDHEALTH_DISMISS, UPDATE_RESULT_CLOSE_TEXT, ACTION_CLOSE),
        ),
        title_for=_update_result_title_for,
        interrupting=True, auto_clear_after_s=UPDATE_RESULT_SECONDS,
    ),
)
_WARNING_BY_ID: dict[str, WarningDescriptor] = {d.id: d for d in WARNING_DESCRIPTORS}


# ---------------------------------------------------------------------------
# Appliance-supplied warnings
#
# The dial, never the appliance, decides how an appliance warning behaves:
# it ranks below every warning of the dial's own (the band below), never
# interrupts and never wakes the panel; the appliance chooses only the text,
# a severity within the band, all from the validator's closed sets. A card
# is put away in the view that shows it; the cause is acknowledged on the
# appliance.
# ---------------------------------------------------------------------------

# The priority band for appliance warnings, all below the lowest of the
# dial's own (update_dial, 40). A more severe warning ranks higher inside it.
APPLIANCE_WARNING_PRIORITY = {
    SEVERITY_INFO: 10,
    SEVERITY_WARNING: 11,
    SEVERITY_CRITICAL: 12,
}

# The screen name every appliance warning shares: one policy row and one
# touch surface (the SD card warning's one-cell geometry), the page chosen by
# the warning id the view requests with it.
APPLIANCE_WARNING_SCREEN = "appliance_warning"

# Who the page is attributed to when the roster has no name for the appliance.
APPLIANCE_WARNING_SOURCE_FALLBACK = "Appliance"


def appliance_warning_key(appliance_id: str, warning_id: str) -> str:
    """The manager's id for one appliance's warning: the appliance's own id
    is part of it, so two appliances can use the same warning id."""
    return f"{APPLIANCE_WARNING_PREFIX}{appliance_id}:{warning_id}"


def appliance_warning_descriptor(appliance_id: str, warning: ApplianceWarning) -> WarningDescriptor:
    """The descriptor for one validated appliance warning. Its text is the
    warning's own (data, never a format template), with one Close cell."""
    message = warning.message
    return WarningDescriptor(
        id=appliance_warning_key(appliance_id, warning.id), kind=KIND_WARNING,
        priority=APPLIANCE_WARNING_PRIORITY.get(warning.severity, APPLIANCE_WARNING_PRIORITY[SEVERITY_INFO]),
        screen=APPLIANCE_WARNING_SCREEN, geometry=GEOMETRY_SDHEALTH,
        title=warning.title, message_for=lambda _reading: message,
        severity_for=lambda _reading: warning.severity,
        buttons=(WarningButton(TouchZone.SDHEALTH_DISMISS, NOWIFI_CLOSE_TEXT, ACTION_CLOSE),),
        source_name=warning.appliance_name or APPLIANCE_WARNING_SOURCE_FALLBACK,
    )
