"""Tests for dial_warning_page.py: the warnings card's pure page logic.

Covers: opening on a bell, the card text and buttons by entry count, Next
wrapping, an entry that clears (the page moves on, or ends), a tap resolved
against the card the finger saw, and the status card built from a descriptor.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

from dial_core_state import SEVERITY_WARNING  # noqa: E402
from dial_warning_bell import Bell, BellEntry  # noqa: E402
from dial_warning_page import WarningsPageState, status_card  # noqa: E402
from dial_warning_text import WARNING_BY_ID  # noqa: E402
from dial_warnings import ACTION_CLOSE, ACTION_NEXT, ACTION_RESTART  # noqa: E402


def _entry(key, source="Turntable", actions=(), title=None, message="msg"):
    return BellEntry(
        key=key, source=source, severity=SEVERITY_WARNING, title=title or key.title(),
        message=message, actions=tuple(actions))


def _bell(*keys, **kw):
    return Bell(tuple(_entry(k, **kw) for k in keys))


def _page(bell, painted=True):
    page = WarningsPageState.open(bell, 5.0)
    return page.painted() if painted else page


class TestOpen:
    def test_an_empty_bell_has_no_page(self):
        assert WarningsPageState.open(Bell(()), 0.0) is None

    def test_the_page_opens_on_the_first_entry_with_the_time(self):
        page = WarningsPageState.open(_bell("a", "b"), 7.5)
        assert (page.keys, page.key, page.opened_at) == (("a", "b"), "a", 7.5)
        assert page.shown is None


class TestCard:
    def test_one_entry_shows_close_alone_and_the_bare_source(self):
        card = _page(_bell("a")).card(_bell("a"))
        assert (card.title, card.message, card.source) == ("A", "msg", "Turntable")
        assert card.buttons == (("Close", ACTION_CLOSE),)
        assert card.status_id == "" and card.percent is None

    def test_several_entries_add_next_and_the_place(self):
        bell = _bell("a", "b", "c")
        card = _page(bell).card(bell)
        assert card.buttons == (("Next", ACTION_NEXT), ("Close", ACTION_CLOSE))
        assert card.source == "Turntable · 1 of 3"

    def test_an_extra_action_sits_between_next_and_close(self):
        bell = Bell((_entry("nowifi", source="This dial", actions=(ACTION_RESTART,)), _entry("b")))
        card = _page(bell).card(bell)
        assert [a for _, a in card.buttons] == [ACTION_NEXT, ACTION_RESTART, ACTION_CLOSE]
        assert [label for label, _ in card.buttons] == ["Next", "Restart", "Close"]

    def test_an_extra_action_alone_has_no_next(self):
        bell = Bell((_entry("nowifi", source="This dial", actions=(ACTION_RESTART,)),))
        card = _page(bell).card(bell)
        assert [a for _, a in card.buttons] == [ACTION_RESTART, ACTION_CLOSE]
        assert card.source == "This dial"

    def test_the_text_is_read_from_the_live_bell(self):
        page = _page(_bell("a"))
        assert page.card(_bell("a", message="changed")).message == "changed"

    def test_a_missing_entry_has_no_card(self):
        assert _page(_bell("a")).card(_bell("b")) is None


class TestStepping:
    def test_next_steps_and_wraps(self):
        bell = _bell("a", "b", "c")
        page = _page(bell)
        keys = []
        for _ in range(4):
            page = page.stepped(bell)
            keys.append(page.key)
        assert keys == ["b", "c", "a", "b"]

    def test_next_on_a_single_entry_stays(self):
        bell = _bell("a")
        assert _page(bell).stepped(bell).key == "a"

    def test_the_place_follows_the_page(self):
        bell = _bell("a", "b", "c")
        assert _page(bell).stepped(bell).card(bell).source.endswith("2 of 3")

    def test_stepping_does_not_mark_the_new_entry_painted(self):
        bell = _bell("a", "b")
        stepped = _page(bell).stepped(bell)
        assert stepped.shown == "a" and stepped.key == "b"
        assert stepped.painted().shown == "b"

    def test_stepping_with_nothing_left_ends_the_page(self):
        assert _page(_bell("a")).stepped(Bell(())) is None


class TestAnEntryClears:
    def test_the_current_entry_going_moves_on_to_the_next_remaining(self):
        page = _page(_bell("a", "b", "c")).stepped(_bell("a", "b", "c"))
        assert page.key == "b"
        moved = page.synced(_bell("a", "c"))
        assert moved.key == "c"

    def test_the_last_entry_going_wraps_to_the_first_remaining(self):
        bell = _bell("a", "b", "c")
        page = _page(bell).stepped(bell).stepped(bell)
        assert page.key == "c"
        assert page.synced(_bell("a", "b")).key == "a"

    def test_an_other_entry_going_keeps_the_page_and_renumbers_it(self):
        bell = _bell("a", "b", "c")
        page = _page(bell).stepped(bell).stepped(bell)
        synced = page.synced(_bell("a", "c"))
        assert synced is page
        assert synced.card(_bell("a", "c")).source.endswith("2 of 2")

    def test_down_to_one_entry_drops_next(self):
        bell = _bell("a", "b")
        card = _page(bell).card(_bell("a"))
        assert [a for _, a in card.buttons] == [ACTION_CLOSE]

    def test_every_entry_going_ends_the_page(self):
        assert _page(_bell("a", "b")).synced(Bell(())) is None

    def test_a_warning_that_appears_is_not_added(self):
        page = _page(_bell("a"))
        later = _bell("a", "z")
        assert page.stepped(later).key == "a"
        assert [a for _, a in page.card(later).buttons] == [ACTION_CLOSE]


class TestTap:
    def test_a_cell_resolves_to_the_action_painted_there(self):
        bell = Bell((_entry("nowifi", actions=(ACTION_RESTART,)), _entry("b")))
        page = _page(bell)
        assert [page.action_at(i, bell) for i in range(3)] == [ACTION_NEXT, ACTION_RESTART, ACTION_CLOSE]

    def test_a_cell_beyond_the_buttons_is_dropped(self):
        bell = _bell("a")
        assert _page(bell).action_at(1, bell) is None

    def test_a_tap_before_the_card_was_painted_is_dropped(self):
        bell = _bell("a")
        assert _page(bell, painted=False).action_at(0, bell) is None

    def test_a_tap_after_the_entry_moved_on_is_dropped_not_remapped(self):
        bell = _bell("a", "b")
        page = _page(bell).stepped(bell)  # on "b", but "a" is what is painted
        assert page.action_at(1, bell) is None

    def test_a_tap_after_the_entry_cleared_is_dropped(self):
        page = _page(_bell("a", "b"))
        assert page.action_at(1, _bell("b")) is None


class TestStatusCard:
    def test_the_result_card_has_close_and_names_its_status(self):
        card = status_card(WARNING_BY_ID["update_result"], None)
        assert card.buttons == (("Close", ACTION_CLOSE),)
        assert card.status_id == "update_result"

    def test_the_progress_card_has_no_buttons_and_a_percent(self):
        from dial_update_watch import UpdateView
        card = status_card(WARNING_BY_ID["update"], UpdateView(phase="python", percent=40))
        assert card.buttons == ()
        assert card.percent == 40

    @pytest.mark.parametrize("wid", ["update", "update_result"])
    def test_the_source_is_blank(self, wid):
        assert status_card(WARNING_BY_ID[wid], None).source == ""
