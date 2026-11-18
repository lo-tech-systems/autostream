"""dial_display_state.py: the display's own screen state and the pure maps behind it.

One frozen record per secondary screen (what is open, its page and its
inactivity clock), and the pure maps from core rows to list rows and hint
text. The records are immutable, so the touch thread reads them lock-free.
No Pillow, no threading, no clock.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from dial_display_views import (
    DEFAULT_MARK,
    ListState,
    NEEDS_UPDATE_TEXT,
    NOT_AUTHORISED_TEXT,
    PAIR_IN_AUTOSTREAM_TEXT,
    PLAY_GLYPH,
    START_FAILURE_LINES,
    START_FAILURE_LINE_FALLBACK,
    START_FAILURE_TITLE,
    format_mmss,
)
from dial_eq_model import DERIVED_EQ_IDS
from dial_info import INFO_LABELS
from dial_touch_layout import list_layout_for
from dial_values import clamp

if TYPE_CHECKING:
    from dial_core_state import EqState, OutputRow, PickerRow, SelectorRow
    from dial_layout_metrics import LayoutMetrics


@dataclass(frozen=True)
class ListScreenState:
    """Immutable snapshot of a row-list screen's rows and paging: the
    appliance selector and the replay picker, as last built when a poll tick
    ended (_refresh_list_rows).

    rows: every row on the screen's list (SelectorRow or PickerRow), ALL
        rows across every page, not just the current one; the compositor's
        ListState (built separately, at repaint time) slices out the
        current page. The selector's are every AUTHORIZED or
        confirmed-UNAUTHORIZED identified appliance on the merged roster,
        idle or playing; the picker's are every held, authorized,
        repeat-capable appliance.
    page: the current page index. Preserved across each rebuild (clamped to
        the new row count) so an open list's page does not jump back to 0
        every ~6s poll tick; reset to 0 only when the screen is freshly
        opened (see open_selector()/_apply_screen_requests_locked()).
    opened_at: monotonic time of the open, or of the last touch activity
        while open (see _apply_touch_activity_locked) — what
        SELECTOR_TIMEOUT_SECONDS counts down from.
    """
    rows: tuple
    page: int
    opened_at: float


@dataclass(frozen=True)
class ApplianceScreenState:
    """Immutable record of the appliance-bound page that is open (the repeat
    page, the EQ page or the outputs list): which appliance it shows, the
    inactivity clock and, for the outputs list, its paging. Built once, when
    the page opens, from the last-published roster snapshot, and never
    rebuilt while it stays open: what the page shows (the repeat store's
    record, the EQ readings, the outputs rows) comes fresh from the core's
    snapshot on every repaint."""
    appliance_id: str
    service_name: str
    opened_at: float
    page: int = 0


@dataclass(frozen=True)
class InfoRow:
    """One row of the idle screen's read-only info page — see InfoState."""
    label: str
    value: str          # "-" when a source failed or has nothing to report


@dataclass(frozen=True)
class InfoState:
    """Immutable snapshot of the info page's rows and paging. rows: all seven
    fields, ALL pages (the same "every row, sliced at paint time" shape
    ListScreenState uses); page: the current page; opened_at: what
    SELECTOR_TIMEOUT_SECONDS counts down from."""
    rows: tuple[InfoRow, ...]
    page: int
    opened_at: float


# The seven info fields, shown at once and filled in within about a second
# of opening — see DialDisplay.open_info()/_gather_info().
INFO_TITLE = "Info"
INFO_PLACEHOLDER_ROWS: tuple[InfoRow, ...] = tuple(InfoRow(label=label, value="-") for label in INFO_LABELS)


@dataclass(frozen=True)
class InfoValueState:
    """The compact info page's own drill-in: which field is showing (an
    absolute index into InfoState.rows, read fresh at paint — see
    DialDisplay._display_info_value_locked, so a gather landing while the
    view is open still shows up) and the inactivity clock.

    hint: (label, text) when the view was opened from the appliance
    selector to explain an unauthorised row (see selector_pick) instead of
    showing an info field; such a view ignores index and its back returns to
    the selector."""
    index: int
    opened_at: float
    hint: "tuple[str, str] | None" = None


@dataclass(frozen=True)
class OutputDetailState:
    """The per-output page: the output it was opened for. Its row is read
    from the outputs state at every paint, so a level change or a
    disappearance shows without this being rebuilt."""
    appliance_id: str
    output_id: str
    opened_at: float


@dataclass(frozen=True)
class WarningScreenState:
    """A status page on screen: which status, and the clock every
    screen state carries. Its text is read at paint time from the
    descriptor and the manager's latest reading, so a later reading
    shows without reopening."""
    warning_id: str
    opened_at: float


@dataclass(frozen=True)
class RestartingState:
    """The "Restarting..." screen shown from a Restart tap until the reboot
    takes the panel down — or until RESTARTING_TIMEOUT_SECONDS, whichever
    comes first."""
    opened_at: float


# ---------------------------------------------------------------------------
# List-chassis paging (shared by the appliance selector and the replay
# picker, which page the same way over different row types)
# ---------------------------------------------------------------------------

def rows_per_page_for(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> int:
    return list_layout_for(width, height, metrics=metrics).rows_per_page


def clamp_page(page: int, row_count: int, rows_per_page: int) -> int:
    """Clamp *page* into [0, last page] for *row_count* rows; 0 when empty."""
    max_page = max(0, (row_count - 1) // rows_per_page) if row_count else 0
    return clamp(page, 0, max_page)


def wrap_page(page: int, row_count: int, rows_per_page: int) -> int:
    """Wrap *page* into [0, page_count) for *row_count* rows; 0 when empty
    — the compact tier's own paging rule (see _apply_screen_requests_locked):
    the picker's "more" advance loops back to page 0 after the last page
    instead of clamping there, since compact has no previous-page control of
    its own to get back with otherwise."""
    pages = max(1, -(-row_count // rows_per_page)) if row_count else 1
    return page % pages


def page_slice(rows: tuple, page: int, rows_per_page: int) -> tuple[int, tuple]:
    """(start index, the rows on *page*)."""
    start = page * rows_per_page
    return start, rows[start:start + rows_per_page]


def list_state_for(state, rows_per_page: int, placeholder: str, to_row, pressed=None, rows=None) -> ListState:
    """Build the compositor's ListState for *state*'s current page, or a
    single non-selected *placeholder* row when there are no rows. *to_row*
    maps one row of *state* to the row tuple ListState carries. *rows*
    replaces state.rows for a screen whose rows are not its own (the
    outputs list reads the core's). *pressed* is the (zone, index) pair
    from the unified pressed channel, passed through unchanged — the
    compositor resolves it against this screen's own geometry, so a zone
    from another screen simply washes nothing."""
    if rows is None and state is not None:
        rows = state.rows
    if state is None or not rows:
        return ListState(rows=((placeholder, False),), has_prev=False, has_next=False, pressed=pressed)
    start, page_rows = page_slice(rows, state.page, rows_per_page)
    return ListState(
        rows=tuple(to_row(row) for row in page_rows),
        has_prev=state.page > 0,
        has_next=start + rows_per_page < len(rows),
        pressed=pressed,
    )


def selector_list_row(row: SelectorRow) -> tuple:
    if row.needs_update:
        return (row.label, False, NEEDS_UPDATE_TEXT)
    if not row.authorized:
        return (row.label, False, NOT_AUTHORISED_TEXT)
    return (row.label, row.current, PLAY_GLYPH) if row.playing else (row.label, row.current)


def unauthorised_hint(label: str) -> tuple[str, str]:
    """The (title, text) the value view shows for a tap on an unauthorised
    selector row."""
    return NOT_AUTHORISED_TEXT, f"Allow this dial in {label}'s web UI (Setup, Dials)"


def needs_update_hint(label: str) -> tuple[str, str]:
    """The (title, text) the value view shows for a tap on a selector row
    whose appliance runs another protocol than this dial's."""
    return NEEDS_UPDATE_TEXT, f"{label} and this dial need the same software version"


def pairing_hint(label: str) -> tuple[str, str]:
    """The (title, text) the value view shows for a speaker that must be
    paired in the appliance's web UI, which the small screen cannot do."""
    return PAIR_IN_AUTOSTREAM_TEXT, f"Enter the PIN in {label}'s web UI"


def start_failure_hint(name: str, reason: str) -> tuple[str, str]:
    """The (title, text) the value view shows for a speaker that could not
    start. The name is appliance text: it is put in by replacement, never
    handed to a format call."""
    line = START_FAILURE_LINES.get(reason, START_FAILURE_LINE_FALLBACK)
    return START_FAILURE_TITLE, line.replace("{name}", name)


def picker_list_row(row: PickerRow) -> tuple:
    return (row.label, False, format_mmss(row.seconds))


_OUTPUT_ROW_MARKS = {True: DEFAULT_MARK, False: ""}


def output_list_row(row: "OutputRow") -> tuple:
    """One outputs-list row: the level rides in the same secondary-text
    slot the picker uses for durations, right-aligned by the existing row
    renderer; a disabled output shows nothing on the right. No row is ever
    "current" (no wash) and none carries the play marker — the outputs
    list has no notion of either. The default output carries the trailing
    default mark."""
    return (row.name, False, str(row.volume) if row.selected else "", _OUTPUT_ROW_MARKS[row.is_default])


def eq_loaded(eq: "EqState") -> bool:
    """Whether the EQ page has a reading it can draw: one has landed and it
    carries a band the page knows."""
    return eq.loaded and any(b.id in DERIVED_EQ_IDS for b in eq.bands)


def offerable(rows: "tuple[OutputRow, ...]") -> "tuple[OutputRow, ...]":
    """*rows* without the outputs another appliance has taken."""
    return tuple(r for r in rows if not r.remote_in_use)


def held_outputs(snapshot, state: "ApplianceScreenState | None"):
    """The core's outputs state for the appliance the outputs screen *state*
    shows, or None when the core holds none for it."""
    held = snapshot.outputs
    if state is None or held is None or held.appliance_id != state.appliance_id:
        return None
    return held


def held_eq(snapshot, state: "ApplianceScreenState | None"):
    """The core's EQ state for the appliance the EQ page *state* shows, or
    None when the core holds none for it."""
    held = snapshot.eq
    if state is None or held is None or held.appliance_id != state.appliance_id:
        return None
    return held
