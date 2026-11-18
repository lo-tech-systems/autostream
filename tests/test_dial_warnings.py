"""Tests for dial_warnings.py: the dial's on-screen warning framework.

Covers: the due rule (the status that is due), reading refresh, clearing an
incident, run-time registration, expiry, and the invariants the descriptor
table keeps (a warning never interrupts).
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

from dial_test_support import WARNING_BY_ID
from dial_warning_text import WARNING_DESCRIPTORS
from dial_warnings import (
    ACTION_CLOSE,
    ACTION_RESTART,
    KIND_STATUS,
    KIND_WARNING,
    WarningButton,
    WarningDescriptor,
    WarningManager,
)


class _Clock:
    """A settable fake wall clock: pass `.now` as the manager's clock=."""

    def __init__(self, t: float = 1_000_000.0) -> None:
        self.t = t

    def now(self) -> float:
        return self.t


def _severity(_reading) -> str:
    return "warning"


def _hi() -> WarningDescriptor:
    """A two-button warning: the No-WiFi shape."""
    return WarningDescriptor(
        id="hi", kind=KIND_WARNING, priority=100,
        title="Hi", message_for=None, severity_for=_severity,
        buttons=(
            WarningButton("Restart", ACTION_RESTART),
            WarningButton("Close", ACTION_CLOSE),
        ),
    )


def _lo() -> WarningDescriptor:
    """A one-button warning with a message that reads the reading: the SD
    health shape."""
    return WarningDescriptor(
        id="lo", kind=KIND_WARNING, priority=50,
        title="Lo", message_for=lambda s: f"reading {s}", severity_for=_severity,
        buttons=(WarningButton("Close", ACTION_CLOSE),),
    )


def _status(wid="st", priority=150) -> WarningDescriptor:
    return WarningDescriptor(
        id=wid, kind=KIND_STATUS, priority=priority, screen=wid,
        title="St", message_for=None, severity_for=_severity, buttons=(),
    )


def _manager(clock=None) -> WarningManager:
    return WarningManager((_hi(), _lo(), _status()), clock=clock or _Clock().now)


class TestDueStatus:
    def test_nothing_due_when_nothing_active(self):
        assert _manager().due_status() is None

    def test_a_status_is_due_when_active(self):
        m = _manager()
        m.set_active("st")
        assert m.due_status().id == "st"

    def test_a_warning_is_never_a_due_status(self):
        m = _manager()
        m.set_active("hi")
        m.set_active("lo")
        assert m.due_status() is None

    def test_the_higher_priority_status_wins_and_ties_keep_registry_order(self):
        m = WarningManager((_status("a", 10), _status("b", 20), _status("c", 20)))
        for wid in "abc":
            m.set_active(wid)
        assert m.due_status().id == "b"
        m.clear("b")
        assert m.due_status().id == "c"

    def test_clear_deactivates(self):
        m = _manager()
        m.set_active("st")
        m.clear("st")
        assert m.is_active("st") is False
        assert m.due_status() is None


class TestReading:
    def test_the_reading_refreshes_on_every_set_active(self):
        m = _manager()
        m.set_active("lo", reading=15)
        assert m.reading("lo") == 15
        m.set_active("lo", reading=2)
        assert m.reading("lo") == 2

    def test_clear_forgets_the_reading(self):
        m = _manager()
        m.set_active("lo", reading=15)
        m.clear("lo")
        assert m.reading("lo") is None


# ---------------------------------------------------------------------------
# Generic descriptor fields: defaults, active_since and expired().
# ---------------------------------------------------------------------------

def _timed(after, wid="t") -> WarningDescriptor:
    return WarningDescriptor(
        id=wid, kind=KIND_STATUS, priority=10, screen=wid, title="T",
        message_for=None, severity_for=_severity, buttons=(), auto_clear_after_s=after,
    )


class TestGenericFields:
    def test_optional_fields_default_to_the_plain_behaviour(self):
        for desc in (_hi(), _lo()):
            assert desc.title_for is None and desc.progress_for is None
            assert desc.interrupting is False and desc.auto_clear_after_s is None

    def test_set_active_reports_a_new_incident_only(self):
        manager = WarningManager([_timed(5.0)])
        assert manager.set_active("t") is True
        assert manager.set_active("t") is False
        assert manager.set_active("nope") is False
        manager.clear("t")
        assert manager.set_active("t") is True

    def test_expired_lists_only_rows_past_their_limit(self):
        clock = _Clock()
        manager = WarningManager(
            [_timed(60.0, "a"), _timed(None, "b"), _timed(10.0, "c")], clock=clock.now,
        )
        manager.set_active("a")
        manager.set_active("b")
        manager.set_active("c")
        assert manager.expired() == []
        clock.t += 10.0
        assert manager.expired() == ["c"]
        clock.t += 50.0
        assert manager.expired() == ["a", "c"]
        assert manager.expired(now=clock.t - 100.0) == []

    def test_a_refresh_keeps_the_incident_start(self):
        clock = _Clock()
        manager = WarningManager([_timed(30.0)], clock=clock.now)
        manager.set_active("t", reading=1)
        clock.t += 20.0
        manager.set_active("t", reading=2)
        clock.t += 11.0
        assert manager.expired() == ["t"]

    def test_clear_restarts_the_clock_and_inactive_rows_never_expire(self):
        clock = _Clock()
        manager = WarningManager([_timed(30.0)], clock=clock.now)
        assert manager.expired() == []
        manager.set_active("t")
        clock.t += 40.0
        manager.clear("t")
        assert manager.expired() == []
        manager.set_active("t")
        clock.t += 29.0
        assert manager.expired() == []


# ---------------------------------------------------------------------------
# Run-time registration (warnings an appliance supplies)
# ---------------------------------------------------------------------------

def _ns(appliance_id="a1", warning_id="stylus", *, buttons=True):
    return WarningDescriptor(
        id=f"appliance:{appliance_id}:{warning_id}", kind=KIND_WARNING, priority=10, title="T",
        message_for=lambda _s: "m", severity_for=_severity,
        buttons=(WarningButton("Close", ACTION_CLOSE),) if buttons else (),
    )


class TestRegistration:
    def test_a_registered_warning_joins_the_registry_and_is_never_a_due_status(self):
        manager = WarningManager([_hi()])
        manager.register(_ns())
        assert [d.id for d in manager.descriptors()] == ["hi", "appliance:a1:stylus"]
        manager.set_active("appliance:a1:stylus")
        assert manager.due_status() is None

    def test_re_registering_replaces_the_descriptor_and_keeps_the_state(self):
        manager = WarningManager([])
        manager.register(_ns())
        manager.set_active("appliance:a1:stylus", "x")
        newer = WarningDescriptor(**{**_ns().__dict__, "title": "New"})
        manager.register(newer)
        assert manager.descriptor("appliance:a1:stylus").title == "New"
        assert manager.is_active("appliance:a1:stylus")
        assert len(manager.descriptors()) == 1

    def test_unregister_ends_the_incident_and_removes_the_descriptor(self):
        manager = WarningManager([])
        manager.register(_ns())
        manager.set_active("appliance:a1:stylus")
        manager.unregister("appliance:a1:stylus")
        assert manager.descriptors() == () and manager.runtime() == ()
        assert not manager.is_active("appliance:a1:stylus")

    def test_a_reading_refresh_on_a_registered_warning_keeps_it_active(self):
        manager = WarningManager([])
        key = "appliance:a1:stylus"
        manager.register(_ns())
        manager.set_active(key, "warning")
        manager.register(_ns())
        manager.set_active(key, "critical")
        assert manager.reading(key) == "critical" and manager.is_active(key)

    def test_unregistering_an_unknown_id_is_harmless(self):
        manager = WarningManager([_hi()])
        manager.unregister("nope")
        assert [d.id for d in manager.descriptors()] == ["hi"]

    def test_runtime_reports_state_in_registry_order(self):
        clock = _Clock()
        manager = WarningManager([_hi()], clock=clock.now)
        manager.register(_ns())
        manager.set_active("appliance:a1:stylus", "sev")
        rows = manager.runtime()
        assert [r[0] for r in rows] == ["hi", "appliance:a1:stylus"]
        assert rows[0][1:] == (False, None, None)
        assert rows[1] == ("appliance:a1:stylus", True, "sev", clock.t)


# ---------------------------------------------------------------------------
# The descriptor table
# ---------------------------------------------------------------------------

class TestTheTable:
    def test_each_kind_is_one_of_the_two(self):
        assert {d.kind for d in WARNING_DESCRIPTORS} == {KIND_WARNING, KIND_STATUS}

    def test_update_and_its_result_are_status_and_the_rest_are_warnings(self):
        by_id = {d.id: d.kind for d in WARNING_DESCRIPTORS}
        assert by_id["update"] == by_id["update_result"] == KIND_STATUS
        assert by_id["nowifi"] == by_id["sdhealth"] == by_id["update_dial"] == KIND_WARNING

    def test_a_warning_never_interrupts(self):
        assert [d.id for d in WARNING_DESCRIPTORS if d.kind == KIND_WARNING and d.interrupting] == []

    def test_a_status_with_buttons_closes_with_close(self):
        for desc in WARNING_DESCRIPTORS:
            if desc.kind == KIND_STATUS:
                assert [b.action for b in desc.buttons] in ([], [ACTION_CLOSE])

    def test_every_descriptor_gives_one_of_the_three_severities(self):
        for desc in WARNING_DESCRIPTORS:
            assert desc.severity_for(None) in ("info", "warning", "critical")

    def test_the_sd_card_is_critical_only_when_failing(self):
        severity_for = WARNING_BY_ID["sdhealth"].severity_for
        assert severity_for(("failing", 8)) == "critical"
        assert severity_for(("low", 18)) == "warning"
        assert severity_for(None) == "warning"

    def test_the_sd_card_words_are_the_appliances(self):
        desc = WARNING_BY_ID["sdhealth"]
        reading = ("failing", 8)
        assert (desc.title_text(reading), desc.message_text(reading)) == (
            "microSD card", "Replace now")
        assert desc.detail_text(reading) == "8% of its life left."

    def test_the_sd_card_detail_adds_the_read_date_when_the_reading_has_one(self):
        desc = WARNING_BY_ID["sdhealth"]
        assert desc.detail_text(("low", 18, "2026-03-03T10:00:00+00:00")) == "18% of its life left. Read 3 Mar 2026."
        assert desc.detail_text(("low", 18, None)) == "18% of its life left."

    def test_a_descriptor_without_a_detail_gives_an_empty_one(self):
        assert WARNING_BY_ID["nowifi"].detail_text(None) == ""

    def test_the_dial_update_message_names_the_appliances(self):
        message_for = WARNING_BY_ID["update_dial"].message_for
        assert message_for(("Lounge",)) == "Lounge needs a newer dial"
        assert message_for(("Lounge", "Kitchen")) == "Lounge, Kitchen need a newer dial"

    def test_the_dial_update_detail_names_the_first_appliance(self):
        detail_for = WARNING_BY_ID["update_dial"].detail_for
        assert detail_for(("Lounge", "Kitchen")) == "Update it from Lounge's web UI (Setup, Dials)."
        assert detail_for(()) == ""
