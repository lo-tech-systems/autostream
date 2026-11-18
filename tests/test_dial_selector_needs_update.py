"""tests/test_dial_selector_needs_update.py -- an appliance on another protocol
than this dial's: marked as needing an update in the selector and in the HD
body, and not drawn as offline."""
from __future__ import annotations

import dataclasses

import pytest

from dial_pool_support import Rig, aid, peer

from dial_core_state import AUTH_AUTHORIZED, AUTH_UNKNOWN, SelectorRow, selector_rows
from dial_hd_state import _appliance_block


@pytest.fixture
def rig():
    r = Rig()
    yield r
    r.close()


def test_a_mismatched_appliance_is_listed_as_needing_an_update(rig):
    rig.add("Old", peer("Old", protocol_ok=False, protocol=3, access="unknown", outputs=False))
    rig.add("Kitchen", peer("Kitchen", playing=True))
    snap = rig.fold()
    rows = {r.label: r for r in snap.selector_rows()}
    assert rows["Old"].needs_update and not rows["Old"].current and not rows["Old"].playing
    assert not rows["Kitchen"].needs_update and rows["Kitchen"].current


def test_an_unknown_appliance_on_the_same_protocol_stays_off_the_list(rig):
    rig.add("New", peer("New", access="unknown"))
    assert rig.fold().selector_rows() == ()


def test_the_row_defaults_to_not_needing_an_update():
    assert SelectorRow("a" * 20, "Kitchen", False).needs_update is False


def test_selector_rows_reads_the_protocol_status(rig):
    rig.add("Old", peer("Old", protocol_ok=False, protocol=5))
    snap = rig.fold()
    (row,) = selector_rows(snap.appliances, None, None)
    assert row.needs_update and row.appliance_id == aid("Old")


@pytest.mark.parametrize("status_error, reachable, update_needed", [
    (None, True, False),
    ("protocol", True, True),
    ("unauthorized", True, False),
    ("unreachable", False, False),
    ("unavailable", False, False),
])
def test_the_hd_row(rig, status_error, reachable, update_needed):
    rig.add("Kitchen")
    a = dataclasses.replace(rig.fold().appliance(aid("Kitchen")), status_error=status_error)
    block = _appliance_block(a, 0.0, {})
    assert (block["reachable"], block["update_needed"]) == (reachable, update_needed)


def test_the_hd_row_of_a_mismatched_appliance(rig):
    rig.add("Old", peer("Old", protocol_ok=False, protocol=3, access="unknown"))
    block = _appliance_block(rig.fold().appliance(aid("Old")), 0.0, {})
    assert block["update_needed"] and block["reachable"] and block["auth"] == AUTH_UNKNOWN


def test_the_small_screen_draws_the_marker():
    pytest.importorskip("PIL.Image", reason="Pillow not installed")
    from dial_display import NEEDS_UPDATE_TEXT, _needs_update_hint, _selector_list_row
    row = SelectorRow("a" * 20, "Old", False, authorized=False, needs_update=True)
    assert _selector_list_row(row) == ("Old", False, NEEDS_UPDATE_TEXT)
    assert _needs_update_hint("Old")[0] == NEEDS_UPDATE_TEXT == "Needs an update"
    authorised = SelectorRow("a" * 20, "Kitchen", True, authorized=True)
    assert _selector_list_row(authorised) == ("Kitchen", True)


def test_an_authorised_appliance_is_not_marked(rig):
    rig.add("Kitchen", peer("Kitchen"))
    (row,) = rig.fold().selector_rows()
    assert row.authorized and not row.needs_update
    assert rig.core.snapshot().appliance(aid("Kitchen")).auth == AUTH_AUTHORIZED
