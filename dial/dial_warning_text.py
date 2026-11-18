"""dial_warning_text.py: the dial's warning table and the text that goes
with it.

Everything here is pure data and small pure functions: the fixed strings of
the warning and update cards, the descriptor table
(WARNING_DESCRIPTORS), and the builder that turns one validated appliance
warning into a descriptor. The core builds its warning manager from this
table and a headless surface can render the same cards from it, so none of
it imports the display, the compositor or any drawing library.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from autostream_sysutils import SD_CARD_TITLE, SD_LEVEL_FAILING, SD_LEVEL_LOW, sd_card_text
from dial_appliance_warnings import (
    APPLIANCE_WARNING_MESSAGE_MAX, ApplianceWarning, DIAL_WARNING_ID, SEVERITY_CRITICAL,
    SEVERITY_INFO, SEVERITY_WARNING, clean_text,
)
from dial_update_watch import STATUS_SUCCESS, UpdateView
from dial_warnings import (
    ACTION_CLOSE,
    ACTION_NEXT,
    ACTION_RESTART,
    APPLIANCE_WARNING_PREFIX,
    KIND_STATUS,
    KIND_WARNING,
    WarningButton,
    WarningDescriptor,
)

# The labels of a card's buttons, by the action they run.
CLOSE_TEXT = "Close"
NEXT_TEXT = "Next"
RESTART_TEXT = "Restart"
BUTTON_TEXT = {ACTION_CLOSE: CLOSE_TEXT, ACTION_NEXT: NEXT_TEXT, ACTION_RESTART: RESTART_TEXT}

# The ids of the warnings and statuses the dial itself raises.
NOWIFI_WARNING_ID = "nowifi"
SDHEALTH_WARNING_ID = "sdhealth"
UPDATE_WARNING_ID = "update"
UPDATE_RESULT_WARNING_ID = "update_result"

# The No-WiFi warning's fixed title.
NOWIFI_MESSAGE_TEXT = "No WiFi"

# The SD card warning's reading is (level, percent): "low" is a warning and
# "failing" is critical; the words are the appliance's own.
def _sdhealth_severity_for(reading) -> str:
    level = reading[0] if reading else SD_LEVEL_LOW
    return SEVERITY_CRITICAL if level == SD_LEVEL_FAILING else SEVERITY_WARNING


def _sdhealth_message_for(reading) -> str:
    return sd_card_text(*reading)[1] if reading else ""


# The software update cards. The in-progress card's title is fixed and its
# message is a short label chosen by the update's phase (never the result
# file's long message, which is for the appliance's web page); the result
# card says how the run ended and names the version. All of it must fit on
# the smallest panel without truncation (tests render every string).
UPDATING_TEXT = "Updating..."
UPDATED_TEXT = "Updated"
UPDATE_FAILED_TEXT = "Update failed"
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
    return clean_text(f"{', '.join(names)} {verb} a newer dial", APPLIANCE_WARNING_MESSAGE_MAX)


# ---------------------------------------------------------------------------
# On-screen warnings
#
# One descriptor per warning or status. A source (the network poller, the
# SD health reader, the update watcher) reports it active or cleared on the
# manager; everything else (its text, its buttons, its severity) is read from
# its row here. A warning is listed on the warnings page, reached from the
# bell; a status (an update running or finished) is a screen of its own, which
# the screen-policy table names by the descriptor's `screen`.
#
# A warning's extra actions (No WiFi's Restart) are its buttons beside the
# Close every card has; the warnings card puts Close last.
#
# Warnings an appliance supplies are not rows here: each validated one is
# turned into a descriptor of the same shape by appliance_warning_descriptor()
# and registered on the manager while the appliance reports it, so a new
# appliance warning needs no change to the dial.
# ---------------------------------------------------------------------------

WARNING_DESCRIPTORS: tuple[WarningDescriptor, ...] = (
    WarningDescriptor(
        id=NOWIFI_WARNING_ID, kind=KIND_WARNING,
        title=NOWIFI_MESSAGE_TEXT, message_for=None, severity_for=_warning_severity,
        buttons=(
            WarningButton(CLOSE_TEXT, ACTION_CLOSE),
            WarningButton(RESTART_TEXT, ACTION_RESTART),
        ),
    ),
    WarningDescriptor(
        id=SDHEALTH_WARNING_ID, kind=KIND_WARNING,
        title=SD_CARD_TITLE, message_for=_sdhealth_message_for,
        severity_for=_sdhealth_severity_for,
        buttons=(WarningButton(CLOSE_TEXT, ACTION_CLOSE),),
    ),
    # The dial itself is older than an appliance it talks to: one warning
    # for all of them, its reading the names of the appliances that are
    # ahead of it.
    WarningDescriptor(
        id=DIAL_WARNING_ID, kind=KIND_WARNING, title=UPDATE_DIAL_TITLE_TEXT,
        message_for=_update_dial_message_for, severity_for=_warning_severity,
        buttons=(WarningButton(CLOSE_TEXT, ACTION_CLOSE),),
    ),
    # A software update in progress: the top status, no buttons (touch does
    # nothing), shown over whatever is up and waking the panel; its source
    # clears it.
    WarningDescriptor(
        id=UPDATE_WARNING_ID, kind=KIND_STATUS, priority=200, screen=UPDATE_WARNING_ID,
        title=UPDATING_TEXT, message_for=_update_message_for, severity_for=_info_severity,
        buttons=(),
        title_for=_update_title_for, progress_for=_update_progress_for,
        interrupting=True,
    ),
    # How an update ended: one Close, clears itself after
    # UPDATE_RESULT_SECONDS.
    WarningDescriptor(
        id=UPDATE_RESULT_WARNING_ID, kind=KIND_STATUS, priority=150, screen=UPDATE_RESULT_WARNING_ID,
        title=UPDATED_TEXT, message_for=_update_result_message_for,
        severity_for=_info_severity,
        buttons=(WarningButton(CLOSE_TEXT, ACTION_CLOSE),),
        title_for=_update_result_title_for,
        interrupting=True, auto_clear_after_s=UPDATE_RESULT_SECONDS,
    ),
)


# ---------------------------------------------------------------------------
# Appliance-supplied warnings
#
# The dial, never the appliance, decides how an appliance warning behaves:
# it never interrupts and never wakes the panel; the appliance chooses only
# the text and a severity, all from the validator's closed sets. A card
# is put away in the view that shows it; the cause is acknowledged on the
# appliance.
# ---------------------------------------------------------------------------


# Who the page is attributed to when the roster has no name for the appliance.
APPLIANCE_WARNING_SOURCE_FALLBACK = "Appliance"


def appliance_warning_key(appliance_id: str, warning_id: str) -> str:
    """The manager's id for one appliance's warning: the appliance's own id
    is part of it, so two appliances can use the same warning id."""
    return f"{APPLIANCE_WARNING_PREFIX}{appliance_id}:{warning_id}"


def appliance_warning_descriptor(appliance_id: str, warning: ApplianceWarning) -> WarningDescriptor:
    """The descriptor for one validated appliance warning. Its text is the
    warning's own (data, never a format template), with one Close button."""
    message = warning.message
    detail = warning.detail
    return WarningDescriptor(
        id=appliance_warning_key(appliance_id, warning.id), kind=KIND_WARNING,
        title=warning.title, message_for=lambda _reading: message,
        detail_for=lambda _reading: detail,
        severity_for=lambda _reading: warning.severity,
        buttons=(WarningButton(CLOSE_TEXT, ACTION_CLOSE),),
        source_name=warning.appliance_name or APPLIANCE_WARNING_SOURCE_FALLBACK,
    )
