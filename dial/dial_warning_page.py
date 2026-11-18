"""dial_warning_page.py: the small screen's warnings card, and the card a
status screen shows, as pure data.

The warnings page lists one bell's entries one at a time. Its state is the
entry keys the bell held when the page opened and the one on show; the
entries themselves (title, message, source) are read from the live bell at
every paint, so a reading that changes shows without reopening. Next steps
to the following entry and wraps. An entry whose cause has cleared drops
out: the page moves on to the next one that remains, and ends when none
does. A warning that appears while the page is open is not added to it.

A Card is what is painted and what a tap resolves against: the text, the
source line and the buttons as (label, action) pairs, left to right. The
same shape serves a status screen (an update running or finished), built
from its descriptor by status_card().

Pure: no drawing, no I/O, no clock (the caller passes the time).

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

from dial_warning_bell import Bell
from dial_warning_text import BUTTON_TEXT
from dial_warnings import ACTION_CLOSE, ACTION_NEXT, WarningDescriptor


@dataclass(frozen=True)
class Card:
    """One card as painted: the readout-size title, the body-size message
    under it, the source band above the title ("" for none), its severity, a
    progress percent (None for no bar) and the buttons as (label, action).
    status_id is the status a Close on this card ends, "" for a warning
    (a warning's Close only puts the card away)."""
    title: str
    message: str
    source: str
    percent: "int | None"
    buttons: tuple
    status_id: str = ""
    severity: str = ""


@dataclass(frozen=True)
class WarningsPageState:
    """keys: the bell's entry keys when the page opened, in the bell's
    order. key: the entry on show. shown: the entry last painted (None
    until the first paint), so a tap is resolved against the card the
    finger saw. opened_at: what the page's inactivity timeout counts from."""
    keys: tuple
    key: str
    shown: "str | None"
    opened_at: float

    @classmethod
    def open(cls, bell: Bell, now: float) -> "WarningsPageState | None":
        """The page for *bell*'s entries, on the first one; None when the
        bell is empty."""
        keys = tuple(e.key for e in bell.entries)
        return cls(keys=keys, key=keys[0], shown=None, opened_at=now) if keys else None

    def _remaining(self, bell: Bell) -> tuple:
        present = {e.key for e in bell.entries}
        return tuple(k for k in self.keys if k in present)

    def synced(self, bell: Bell) -> "WarningsPageState | None":
        """This page with its entry still on show: if the entry's cause has
        cleared, the next remaining one (wrapping); None when none remain."""
        remaining = self._remaining(bell)
        if not remaining:
            return None
        if self.key in remaining:
            return self
        after = self.keys[self.keys.index(self.key) + 1:] + self.keys
        return replace(self, key=next(k for k in after if k in remaining))

    def stepped(self, bell: Bell) -> "WarningsPageState | None":
        """The page on its next entry, wrapping from the last to the first."""
        page = self.synced(bell)
        if page is None:
            return None
        remaining = page._remaining(bell)
        return replace(page, key=remaining[(remaining.index(page.key) + 1) % len(remaining)])

    def painted(self) -> "WarningsPageState":
        """This page marked as showing its current entry."""
        return self if self.shown == self.key else replace(self, shown=self.key)

    def card(self, bell: Bell) -> "Card | None":
        """The card for the entry on show: None when its entry is not in the
        bell (the caller syncs first). Buttons, left to right: Next when
        more than one entry remains, the entry's extra actions, Close."""
        remaining = self._remaining(bell)
        entry = next((e for e in bell.entries if e.key == self.key), None)
        if entry is None:
            return None
        many = len(remaining) > 1
        actions = (ACTION_NEXT,) * many + tuple(entry.actions) + (ACTION_CLOSE,)
        return Card(
            title=entry.title, message=entry.message,
            source=f"{entry.source} · {remaining.index(self.key) + 1} of {len(remaining)}" if many else entry.source,
            percent=None, buttons=tuple((BUTTON_TEXT[a], a) for a in actions), severity=entry.severity,
        )

    def action_at(self, cell: int, bell: Bell) -> "str | None":
        """The action of button *cell* on the card the finger saw, or None
        when the card has moved on (its entry cleared, or the page has not
        painted the current one) or the cell is not a button."""
        if self.shown != self.key:
            return None
        card = self.card(bell)
        if card is None or not 0 <= cell < len(card.buttons):
            return None
        return card.buttons[cell][1]


def status_card(desc: WarningDescriptor, reading) -> Card:
    """The card of a status descriptor from its latest reading."""
    return Card(
        title=desc.title_text(reading),
        message=desc.message_text(reading),
        source=desc.source_name,
        percent=desc.progress(reading),
        buttons=tuple((b.label, b.action) for b in desc.buttons),
        status_id=desc.id,
        severity=desc.severity(reading),
    )
