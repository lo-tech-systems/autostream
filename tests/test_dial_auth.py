"""Tests for dial_auth.py — the pure per-appliance authorization map.

Covers every row of the auth state-machine reference table: sighting
(new/same address), the two state-moving outcomes (authorized/unauthorized),
the correlation guard (mismatched or missing body appliance_id), transient
outcomes, unauthorized backoff progression, due_for_probe/force_due, 24h/64-
entry retention via prune(), and thread-safety under concurrent access.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

from dial_auth import (  # noqa: E402
    AUTH_AUTHORIZED,
    AUTH_UNAUTHORIZED,
    AUTH_UNKNOWN,
    ENTRY_RETENTION_S,
    MAX_ENTRIES,
    OUTCOME_AUTHORIZED,
    OUTCOME_TRANSIENT,
    OUTCOME_UNAUTHORIZED,
    REPROBE_BACKOFF_INITIAL_S,
    REPROBE_BACKOFF_MAX_S,
    AuthMap,
)

AID = "a" * 20
OTHER_AID = "b" * 20


@pytest.fixture
def auth_map():
    return AuthMap()


# ---------------------------------------------------------------------------
# note_sighting
# ---------------------------------------------------------------------------

class TestNoteSighting:
    def test_new_id_creates_unknown_entry(self, auth_map):
        auth_map.note_sighting(AID, "10.0.0.1", 80, 100.0)
        assert auth_map.state(AID) == AUTH_UNKNOWN

    def test_empty_id_is_ignored(self, auth_map):
        auth_map.note_sighting("", "10.0.0.1", 80, 100.0)
        assert auth_map.state("") == AUTH_UNKNOWN
        assert auth_map.states() == {}

    def test_same_address_preserves_state(self, auth_map):
        auth_map.note_sighting(AID, "10.0.0.1", 80, 100.0)
        auth_map.apply(AID, OUTCOME_AUTHORIZED, AID, 101.0)
        auth_map.note_sighting(AID, "10.0.0.1", 80, 102.0)
        assert auth_map.state(AID) == AUTH_AUTHORIZED

    def test_address_change_resets_to_unknown(self, auth_map):
        auth_map.note_sighting(AID, "10.0.0.1", 80, 100.0)
        auth_map.apply(AID, OUTCOME_AUTHORIZED, AID, 101.0)
        auth_map.note_sighting(AID, "10.0.0.2", 80, 102.0)
        assert auth_map.state(AID) == AUTH_UNKNOWN

    def test_port_change_resets_to_unknown(self, auth_map):
        auth_map.note_sighting(AID, "10.0.0.1", 80, 100.0)
        auth_map.apply(AID, OUTCOME_UNAUTHORIZED, AID, 101.0)
        auth_map.note_sighting(AID, "10.0.0.1", 81, 102.0)
        assert auth_map.state(AID) == AUTH_UNKNOWN

    def test_address_change_clears_backoff(self, auth_map):
        auth_map.note_sighting(AID, "10.0.0.1", 80, 100.0)
        auth_map.apply(AID, OUTCOME_UNAUTHORIZED, AID, 101.0)
        auth_map.note_sighting(AID, "10.0.0.2", 80, 102.0)
        # A fresh (reset) entry is due immediately regardless of the old backoff.
        assert auth_map.due_for_probe(AID, 102.0) is True

    def test_address_change_keeps_last_confirmed_as_history(self, auth_map):
        auth_map.note_sighting(AID, "10.0.0.1", 80, 100.0)
        auth_map.apply(AID, OUTCOME_AUTHORIZED, AID, 101.0)
        auth_map.note_sighting(AID, "10.0.0.2", 80, 102.0)
        entry = auth_map._entries[AID]
        assert entry.last_confirmed == 101.0

    def test_last_seen_updated_on_every_sighting(self, auth_map):
        auth_map.note_sighting(AID, "10.0.0.1", 80, 100.0)
        auth_map.note_sighting(AID, "10.0.0.1", 80, 200.0)
        assert auth_map._entries[AID].last_seen == 200.0


# ---------------------------------------------------------------------------
# state / states
# ---------------------------------------------------------------------------

class TestState:
    def test_unknown_id_never_raises(self, auth_map):
        assert auth_map.state("nonexistent" + "0" * 8) == AUTH_UNKNOWN

    def test_empty_id_is_unknown(self, auth_map):
        assert auth_map.state("") == AUTH_UNKNOWN

    def test_states_snapshot(self, auth_map):
        auth_map.note_sighting(AID, "10.0.0.1", 80, 1.0)
        auth_map.note_sighting(OTHER_AID, "10.0.0.2", 80, 1.0)
        auth_map.apply(AID, OUTCOME_AUTHORIZED, AID, 2.0)
        assert auth_map.states() == {AID: AUTH_AUTHORIZED, OTHER_AID: AUTH_UNKNOWN}


# ---------------------------------------------------------------------------
# apply(): the two state-moving outcomes and the correlation guard.
# ---------------------------------------------------------------------------

class TestApply:
    def test_authorized_outcome_moves_to_authorized(self, auth_map):
        auth_map.note_sighting(AID, "10.0.0.1", 80, 1.0)
        changed = auth_map.apply(AID, OUTCOME_AUTHORIZED, AID, 2.0)
        assert changed is True
        assert auth_map.state(AID) == AUTH_AUTHORIZED
        assert auth_map._entries[AID].last_confirmed == 2.0
        assert auth_map._entries[AID].backoff_s == 0.0

    def test_authorized_outcome_when_already_authorized_returns_false(self, auth_map):
        auth_map.apply(AID, OUTCOME_AUTHORIZED, AID, 1.0)
        changed = auth_map.apply(AID, OUTCOME_AUTHORIZED, AID, 2.0)
        assert changed is False
        assert auth_map.state(AID) == AUTH_AUTHORIZED

    def test_unauthorized_outcome_moves_to_unauthorized(self, auth_map):
        auth_map.note_sighting(AID, "10.0.0.1", 80, 1.0)
        changed = auth_map.apply(AID, OUTCOME_UNAUTHORIZED, AID, 2.0)
        assert changed is True
        assert auth_map.state(AID) == AUTH_UNAUTHORIZED
        assert auth_map._entries[AID].last_confirmed == 2.0

    def test_unauthorized_sets_initial_backoff(self, auth_map):
        auth_map.apply(AID, OUTCOME_UNAUTHORIZED, AID, 100.0)
        entry = auth_map._entries[AID]
        assert entry.backoff_s == REPROBE_BACKOFF_INITIAL_S
        assert entry.next_probe_at == 100.0 + REPROBE_BACKOFF_INITIAL_S

    def test_unauthorized_backoff_doubles_and_caps(self, auth_map):
        now = 0.0
        expected = REPROBE_BACKOFF_INITIAL_S
        auth_map.apply(AID, OUTCOME_UNAUTHORIZED, AID, now)
        assert auth_map._entries[AID].backoff_s == expected
        for _ in range(10):
            now += auth_map._entries[AID].backoff_s
            auth_map.apply(AID, OUTCOME_UNAUTHORIZED, AID, now)
            expected = min(expected * 2, REPROBE_BACKOFF_MAX_S)
            assert auth_map._entries[AID].backoff_s == expected
        assert auth_map._entries[AID].backoff_s == REPROBE_BACKOFF_MAX_S

    def test_authorized_clears_backoff_after_unauthorized(self, auth_map):
        auth_map.apply(AID, OUTCOME_UNAUTHORIZED, AID, 1.0)
        auth_map.apply(AID, OUTCOME_AUTHORIZED, AID, 2.0)
        entry = auth_map._entries[AID]
        assert entry.backoff_s == 0.0
        assert entry.next_probe_at == 0.0

    def test_transient_outcome_never_moves_state(self, auth_map):
        auth_map.note_sighting(AID, "10.0.0.1", 80, 1.0)
        changed = auth_map.apply(AID, OUTCOME_TRANSIENT, AID, 2.0)
        assert changed is False
        assert auth_map.state(AID) == AUTH_UNKNOWN

    def test_transient_outcome_does_not_demote_authorized(self, auth_map):
        auth_map.apply(AID, OUTCOME_AUTHORIZED, AID, 1.0)
        auth_map.apply(AID, OUTCOME_TRANSIENT, AID, 2.0)
        assert auth_map.state(AID) == AUTH_AUTHORIZED

    def test_none_body_id_is_a_noop(self, auth_map):
        auth_map.note_sighting(AID, "10.0.0.1", 80, 1.0)
        changed = auth_map.apply(AID, OUTCOME_AUTHORIZED, None, 2.0)
        assert changed is False
        assert auth_map.state(AID) == AUTH_UNKNOWN

    def test_mismatched_body_id_is_a_noop_for_authorized(self, auth_map):
        auth_map.note_sighting(AID, "10.0.0.1", 80, 1.0)
        changed = auth_map.apply(AID, OUTCOME_AUTHORIZED, OTHER_AID, 2.0)
        assert changed is False
        assert auth_map.state(AID) == AUTH_UNKNOWN

    def test_mismatched_body_id_is_a_noop_for_unauthorized(self, auth_map):
        auth_map.apply(AID, OUTCOME_AUTHORIZED, AID, 1.0)
        changed = auth_map.apply(AID, OUTCOME_UNAUTHORIZED, OTHER_AID, 2.0)
        assert changed is False
        assert auth_map.state(AID) == AUTH_AUTHORIZED

    def test_empty_appliance_id_is_a_noop(self, auth_map):
        changed = auth_map.apply("", OUTCOME_AUTHORIZED, "", 1.0)
        assert changed is False
        assert auth_map.states() == {}

    def test_apply_on_unseen_id_creates_the_entry_first(self, auth_map):
        # A poll result racing with prune() must still apply cleanly.
        changed = auth_map.apply(AID, OUTCOME_AUTHORIZED, AID, 1.0)
        assert changed is True
        assert auth_map.state(AID) == AUTH_AUTHORIZED


# ---------------------------------------------------------------------------
# due_for_probe / force_due
# ---------------------------------------------------------------------------

class TestDueForProbe:
    def test_absent_entry_is_due(self, auth_map):
        assert auth_map.due_for_probe(AID, 0.0) is True

    def test_unknown_entry_is_always_due(self, auth_map):
        auth_map.note_sighting(AID, "10.0.0.1", 80, 1.0)
        assert auth_map.due_for_probe(AID, 1.0) is True

    def test_authorized_entry_is_always_due(self, auth_map):
        auth_map.apply(AID, OUTCOME_AUTHORIZED, AID, 1.0)
        assert auth_map.due_for_probe(AID, 1.0) is True

    def test_unauthorized_entry_not_due_before_backoff_elapses(self, auth_map):
        auth_map.apply(AID, OUTCOME_UNAUTHORIZED, AID, 100.0)
        assert auth_map.due_for_probe(AID, 100.0 + REPROBE_BACKOFF_INITIAL_S - 1) is False

    def test_unauthorized_entry_due_once_backoff_elapses(self, auth_map):
        auth_map.apply(AID, OUTCOME_UNAUTHORIZED, AID, 100.0)
        assert auth_map.due_for_probe(AID, 100.0 + REPROBE_BACKOFF_INITIAL_S) is True

    def test_empty_id_is_always_due(self, auth_map):
        assert auth_map.due_for_probe("", 0.0) is True

    def test_force_due_one_id(self, auth_map):
        auth_map.apply(AID, OUTCOME_UNAUTHORIZED, AID, 100.0)
        assert auth_map.due_for_probe(AID, 100.0) is False
        auth_map.force_due(AID)
        assert auth_map.due_for_probe(AID, 100.0) is True

    def test_force_due_all(self, auth_map):
        auth_map.apply(AID, OUTCOME_UNAUTHORIZED, AID, 100.0)
        auth_map.apply(OTHER_AID, OUTCOME_UNAUTHORIZED, OTHER_AID, 100.0)
        auth_map.force_due()
        assert auth_map.due_for_probe(AID, 100.0) is True
        assert auth_map.due_for_probe(OTHER_AID, 100.0) is True

    def test_force_due_unknown_id_is_a_noop(self, auth_map):
        auth_map.force_due(AID)  # no entry exists — must not raise or create one
        assert auth_map.states() == {}


# ---------------------------------------------------------------------------
# prune(): 24h retention and the 64-entry cap.
# ---------------------------------------------------------------------------

class TestPrune:
    def test_drops_entries_unseen_beyond_retention(self, auth_map):
        auth_map.note_sighting(AID, "10.0.0.1", 80, 0.0)
        auth_map.prune(ENTRY_RETENTION_S + 1)
        assert auth_map.states() == {}

    def test_keeps_entries_within_retention(self, auth_map):
        auth_map.note_sighting(AID, "10.0.0.1", 80, 0.0)
        auth_map.prune(ENTRY_RETENTION_S - 1)
        assert AID in auth_map.states()

    def test_trims_to_max_entries_dropping_oldest_last_seen_first(self, auth_map):
        for i in range(MAX_ENTRIES + 5):
            aid = f"{i:020d}"
            auth_map.note_sighting(aid, "10.0.0.1", 80, float(i))
        auth_map.prune(float(MAX_ENTRIES + 5))
        states = auth_map.states()
        assert len(states) == MAX_ENTRIES
        # The 5 oldest (lowest last_seen, i.e. i=0..4) must be gone.
        for i in range(5):
            assert f"{i:020d}" not in states
        # The most recent MAX_ENTRIES must survive.
        for i in range(5, MAX_ENTRIES + 5):
            assert f"{i:020d}" in states


# ---------------------------------------------------------------------------
# reset()
# ---------------------------------------------------------------------------

class TestReset:
    def test_reset_clears_everything(self, auth_map):
        auth_map.note_sighting(AID, "10.0.0.1", 80, 1.0)
        auth_map.apply(AID, OUTCOME_AUTHORIZED, AID, 2.0)
        auth_map.reset()
        assert auth_map.states() == {}
        assert auth_map.state(AID) == AUTH_UNKNOWN


# ---------------------------------------------------------------------------
# Thread-safety: concurrent note_sighting/apply from two threads.
# ---------------------------------------------------------------------------

class TestConcurrency:
    def test_concurrent_sighting_and_apply_leaves_a_consistent_entry(self, auth_map):
        errors = []

        def sighter():
            try:
                for i in range(500):
                    auth_map.note_sighting(AID, "10.0.0.1", 80, float(i))
            except Exception as e:
                errors.append(e)

        def applier():
            try:
                for i in range(500):
                    outcome = OUTCOME_AUTHORIZED if i % 2 == 0 else OUTCOME_UNAUTHORIZED
                    auth_map.apply(AID, outcome, AID, float(i))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=sighter), threading.Thread(target=applier)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors
        # Whatever the final state is, it must be one of the three valid
        # states and reading it must never raise.
        assert auth_map.state(AID) in (AUTH_UNKNOWN, AUTH_AUTHORIZED, AUTH_UNAUTHORIZED)
