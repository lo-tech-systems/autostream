"""Tests for dial_warnings.py: the dial's on-screen warning framework.

Covers: due()'s priority and eligibility rule, the two dismiss policies
(incident-scoped vs a persisted time snooze), severity refresh, clearing
an incident (and what it forgets), WarningStore's atomic write and its
never-raise degrade paths, pruning on load, and button-owner resolution.
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

from dial_touch_layout import TouchZone
from dial_warnings import (
    ACTION_DISMISS,
    ACTION_RESTART,
    WarningButton,
    WarningDescriptor,
    WarningManager,
    WarningStore,
)


class _Clock:
    """A settable fake wall clock: pass `.now` as the manager's clock=."""

    def __init__(self, t: float = 1_000_000.0) -> None:
        self.t = t

    def now(self) -> float:
        return self.t


def _hi() -> WarningDescriptor:
    """An incident-scoped, non-persisted, two-button warning: the
    No-WiFi shape."""
    return WarningDescriptor(
        id="hi", priority=100, screen="hi", geometry="hi",
        title="Hi", message_for=None,
        buttons=(
            WarningButton(TouchZone.NOWIFI_DISMISS, "Dismiss", ACTION_DISMISS),
            WarningButton(TouchZone.NOWIFI_RESTART, "Restart", ACTION_RESTART),
        ),
        persisted=False, snooze_for=None,
    )


def _lo() -> WarningDescriptor:
    """A persisted, time-snoozed, one-button warning: the SD health
    shape, a week, or a day when the severity is "critical"."""
    return WarningDescriptor(
        id="lo", priority=50, screen="lo", geometry="lo",
        title="Lo", message_for=lambda s: f"severity {s}",
        buttons=(WarningButton(TouchZone.SDHEALTH_DISMISS, "Dismiss", ACTION_DISMISS),),
        persisted=True, snooze_for=lambda s: 86400.0 if s == "critical" else 604800.0,
    )


def _manager(path=None, clock=None) -> WarningManager:
    return WarningManager((_hi(), _lo()), WarningStore(path), clock=clock or _Clock().now)


class TestDueAndPriority:
    def test_nothing_due_when_nothing_active(self):
        m = _manager()
        assert m.due() is None

    def test_set_active_makes_it_due(self):
        m = _manager()
        m.set_active("lo")
        assert m.due().id == "lo"

    def test_priority_picks_the_higher_when_both_active(self):
        m = _manager()
        m.set_active("hi")
        m.set_active("lo")
        assert m.due().id == "hi"
        m.clear("hi")
        assert m.due().id == "lo"

    def test_severity_refreshes_on_every_set_active(self):
        m = _manager()
        m.set_active("lo", severity=15)
        assert m.severity("lo") == 15
        m.set_active("lo", severity=2)
        assert m.severity("lo") == 2

    def test_clear_deactivates(self):
        m = _manager()
        m.set_active("hi")
        m.clear("hi")
        assert m.is_active("hi") is False
        assert m.due() is None


class TestDismissPolicy:
    def test_incident_dismiss_holds_until_clear(self):
        clock = _Clock()
        m = _manager(clock=clock.now)
        m.set_active("hi")
        m.dismiss("hi")
        clock.t += 10 * 365 * 86400.0
        assert m.is_snoozed("hi") is True
        m.clear("hi")
        assert m.is_snoozed("hi") is False
        m.set_active("hi")
        assert m.due().id == "hi"

    def test_incident_dismiss_is_never_persisted(self, tmp_path):
        path = str(tmp_path / "w.json")
        m = WarningManager((_hi(), _lo()), WarningStore(path))
        m.set_active("hi")
        m.dismiss("hi")
        m.flush()
        assert WarningStore(path).load() == {}

    def test_time_dismiss_snoozes_for_the_policy_duration(self):
        clock = _Clock()
        m = _manager(clock=clock.now)
        m.set_active("lo")
        m.dismiss("lo")
        assert m.is_snoozed("lo", now=clock.t + 604799) is True
        assert m.is_snoozed("lo", now=clock.t + 604800) is False

    def test_time_dismiss_uses_severity(self):
        clock = _Clock()
        m = _manager(clock=clock.now)
        m.set_active("lo", severity="critical")
        m.dismiss("lo")
        assert m.is_snoozed("lo", now=clock.t + 86399) is True
        assert m.is_snoozed("lo", now=clock.t + 86400) is False

    def test_snooze_expiry_makes_it_due_again(self):
        clock = _Clock()
        m = _manager(clock=clock.now)
        m.set_active("lo")
        m.dismiss("lo")
        assert m.due() is None
        clock.t += 604800.0 + 1
        assert m.due().id == "lo"

    def test_clear_forgets_a_time_snooze(self):
        m = _manager()
        m.set_active("lo")
        m.dismiss("lo")
        m.clear("lo")
        m.set_active("lo")
        assert m.due().id == "lo"

    def test_dismiss_of_an_inactive_warning_still_records_the_snooze(self):
        # The never-connected icon-tap page: a Dismiss lands while the
        # source has not (yet) called set_active.
        m = _manager()
        m.dismiss("hi")
        assert m.is_snoozed("hi") is True


class TestPersistence:
    def test_persistence_round_trip(self, tmp_path):
        path = str(tmp_path / "w.json")
        m = WarningManager((_hi(), _lo()), WarningStore(path))
        m.set_active("lo")
        m.dismiss("lo")
        m.flush()
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        assert set(data) == {"lo"}
        m2 = WarningManager((_hi(), _lo()), WarningStore(path))
        assert m2.is_snoozed("lo") is True

    def test_flush_writes_only_when_dirty(self, tmp_path):
        path = str(tmp_path / "w.json")
        m = WarningManager((_hi(), _lo()), WarningStore(path))
        m.set_active("lo")
        m.dismiss("lo")
        with patch.object(m._store, "save", wraps=m._store.save) as save:
            m.flush()
            m.flush()
        save.assert_called_once()

    def test_clear_marks_dirty_and_removes_the_key(self, tmp_path):
        path = str(tmp_path / "w.json")
        m = WarningManager((_hi(), _lo()), WarningStore(path))
        m.set_active("lo")
        m.dismiss("lo")
        m.flush()
        m.clear("lo")
        m.flush()
        assert json.loads(Path(path).read_text(encoding="utf-8")) == {}

    def test_missing_file_loads_empty_and_does_not_create_it(self, tmp_path):
        path = str(tmp_path / "w.json")
        m = WarningManager((_hi(), _lo()), WarningStore(path))
        assert m.due() is None
        assert not Path(path).exists()
        m.set_active("lo")
        m.dismiss("lo")
        m.flush()
        assert Path(path).exists()

    def test_first_flush_creates_the_file_atomically(self, tmp_path):
        path = str(tmp_path / "w.json")
        m = WarningManager((_hi(), _lo()), WarningStore(path))
        m.set_active("lo")
        m.dismiss("lo")
        m.flush()
        assert Path(path).exists()
        assert list(tmp_path.glob("*.tmp")) == []

    def test_corrupt_file_loads_empty(self, tmp_path):
        path = tmp_path / "w.json"
        path.write_text("not json", encoding="utf-8")
        m = WarningManager((_hi(), _lo()), WarningStore(str(path)))
        assert m.due() is None
        m.set_active("lo")
        m.dismiss("lo")
        m.flush()
        assert set(json.loads(path.read_text(encoding="utf-8"))) == {"lo"}

    def test_non_object_json_loads_empty(self, tmp_path):
        path = tmp_path / "w.json"
        path.write_text("[1, 2]", encoding="utf-8")
        assert WarningStore(str(path)).load() == {}

    def test_expired_entries_are_pruned_on_load(self, tmp_path):
        path = tmp_path / "w.json"
        now = 1_000_000.0
        path.write_text(json.dumps({"lo": now - 1}), encoding="utf-8")
        m = WarningManager((_hi(), _lo()), WarningStore(str(path)), clock=lambda: now)
        assert m.is_snoozed("lo") is False
        m.flush()
        assert json.loads(path.read_text(encoding="utf-8")) == {}

    def test_unknown_ids_are_dropped_on_load(self, tmp_path):
        path = tmp_path / "w.json"
        now = 1_000_000.0
        path.write_text(json.dumps({"gone": now + 1e6}), encoding="utf-8")
        m = WarningManager((_hi(), _lo()), WarningStore(str(path)), clock=lambda: now)
        assert m.is_snoozed("gone") is False
        assert m.due() is None

    def test_unreadable_path_degrades_to_memory(self, tmp_path):
        # A directory where the store expects a file: every load/save fails.
        m = WarningManager((_hi(), _lo()), WarningStore(str(tmp_path)))
        m.set_active("lo")
        m.dismiss("lo")
        m.flush()          # never raises
        assert m.is_snoozed("lo") is True

    def test_save_failure_logged_once(self, tmp_path, caplog):
        store = WarningStore(str(tmp_path))   # a directory: save() always fails
        with caplog.at_level(logging.DEBUG, logger="root"):
            assert store.save({"lo": 1.0}) is False
            assert store.save({"lo": 1.0}) is False
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        debugs = [r for r in caplog.records if r.levelno == logging.DEBUG]
        assert len(warnings) == 1
        assert len(debugs) >= 1


class TestButtonResolution:
    def test_button_owner_resolves_the_first_registered_owner(self):
        shared = WarningDescriptor(
            id="lo2", priority=10, screen="lo2", geometry="lo2",
            title="Lo2", message_for=None,
            buttons=(WarningButton(TouchZone.SDHEALTH_DISMISS, "Dismiss", ACTION_DISMISS),),
            persisted=False, snooze_for=None,
        )
        m = WarningManager((_lo(), shared), WarningStore(None))
        owner = m.button_owner(TouchZone.SDHEALTH_DISMISS)
        assert owner is not None
        assert owner[0].id == "lo"

    def test_descriptor_button_for(self):
        desc = _hi()
        assert desc.button_for(TouchZone.NOWIFI_DISMISS).action == ACTION_DISMISS
        assert desc.button_for(TouchZone.SDHEALTH_DISMISS) is None
