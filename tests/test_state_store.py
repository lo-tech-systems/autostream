"""tests/test_state_store.py

The state store: versions, parts, publishing in two phases, subscribers,
batches, leak detection and waiting for a change.
"""
from __future__ import annotations

import gc
import re
import sys
import threading
import time
from pathlib import Path

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_state as state
from autostream_state import Origin, SessionPart, SettingsPart, WriterTaken
from autostream_state.store import Change, StateStore


@pytest.fixture
def st():
    s = StateStore()
    s.reset_for_tests()
    return s


@pytest.fixture
def session(st):
    return st.claim("session", "test_owner")


def collect(st):
    seen: list[Change] = []
    st.subscribe(seen.append)
    return seen


class TestVersions:
    def test_a_new_store_is_at_version_zero_with_default_parts(self, st):
        snap = st.snapshot()
        assert snap.version == 0
        assert snap.session == SessionPart()
        assert dict(snap.part_versions) == {}

    def test_version_bumps_by_one_only_when_a_digest_moves(self, st, session):
        session.publish(SessionPart(True, "input1")).notify()
        assert st.snapshot().version == 1
        session.publish(SessionPart(True, "input1")).notify()
        assert st.snapshot().version == 1
        session.publish(SessionPart(True, "input2")).notify()
        assert st.snapshot().version == 2

    def test_part_versions_record_where_each_part_last_moved(self, st, session):
        settings = st.claim("settings", "test_owner")
        session.publish(SessionPart(True, "input1")).notify()
        settings.publish(SettingsPart(4)).notify()
        session.publish(SessionPart(False, None)).notify()
        assert dict(st.snapshot().part_versions) == {"session": 3, "settings": 2}

    def test_an_equal_digest_replaces_the_value_without_a_bump_or_a_change(self, st):
        monitor = st.claim("monitor", "test_owner")
        seen = collect(st)
        monitor.publish(state.MonitorRuntimeInfo("b1", "info", True, 1.0)).notify()
        monitor.publish(state.MonitorRuntimeInfo("b1", "info", True, 99.0)).notify()
        assert st.snapshot().monitor.last_seen_at == 99.0
        assert st.snapshot().version == 1
        assert len(seen) == 1

    def test_boot_is_sixteen_hex_digits_and_changes_on_reset(self, st):
        first = st.snapshot().boot
        assert re.fullmatch(r"[0-9a-f]{16}", first)
        st.reset_for_tests()
        assert st.snapshot().boot != first


class TestClaims:
    def test_a_second_owner_is_refused_and_the_same_owner_gets_the_same_handle(self, st):
        a = st.claim("session", "owner_a")
        assert st.claim("session", "owner_a") is a
        with pytest.raises(WriterTaken):
            st.claim("session", "owner_b")

    def test_claims_survive_a_reset(self, st):
        a = st.claim("session", "owner_a")
        st.reset_for_tests()
        assert st.claim("session", "owner_a") is a

    def test_an_unknown_part_is_refused(self, st):
        with pytest.raises(KeyError):
            st.claim("nonsense", "owner_a")


class TestPublish:
    def test_a_published_dict_cannot_be_mutated(self, st):
        repeat = st.claim("repeat", "test_owner")
        repeat.publish(state.RepeatPart({"enabled": True, "recording": {"active": False}})).notify()
        block = st.snapshot().repeat.block
        with pytest.raises(TypeError):
            block["enabled"] = False
        with pytest.raises(TypeError):
            block["recording"]["active"] = True

    def test_publishing_a_plain_mutable_object_is_refused(self, st, session):
        class Mutable:
            pass

        with pytest.raises(TypeError):
            session.publish(Mutable())

    def test_update_is_atomic_under_two_threads(self, st):
        settings = st.claim("settings", "test_owner")
        n = 400

        def worker():
            for _ in range(n):
                settings.update(lambda cur: SettingsPart(cur.generation + 1)).notify()

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert st.snapshot().settings.generation == 2 * n
        assert st.snapshot().version == 2 * n

    def test_tags_produce_a_change_without_a_bump(self, st, session):
        seen = collect(st)
        session.publish(SessionPart(True, "input1")).notify()
        before = st.snapshot().version
        pending = session.publish(SessionPart(True, "input1"), tags=["session"])
        assert pending.changed
        pending.notify()
        assert st.snapshot().version == before
        assert seen[-1].tags == frozenset({"session"})
        assert seen[-1].parts == frozenset()

    def test_a_change_carries_origin_and_requester(self, st, session):
        seen = collect(st)
        session.publish(SessionPart(True, "input1"), origin=Origin.USER, requester="webui").notify()
        assert seen[0].origin is Origin.USER
        assert seen[0].requester == "webui"
        assert seen[0].parts == frozenset({"session"})
        assert seen[0].version == 1
        assert seen[0].batch is False

    def test_an_unchanged_publish_has_nothing_to_notify(self, st, session):
        pending = session.publish(SessionPart())
        assert pending.changed is False
        assert pending.version == 0
        pending.notify()

    def test_publish_for_tests_swaps_without_the_owner_or_subscribers(self, st):
        seen = collect(st)
        snap = st.publish_for_tests("session", SessionPart(True, "replay"))
        assert snap.session.source == "replay"
        assert seen == []


class TestSubscribers:
    def test_subscribers_are_called_in_order(self, st, session):
        order = []
        st.subscribe(lambda c: order.append("a"))
        st.subscribe(lambda c: order.append("b"))
        session.publish(SessionPart(True, "input1")).notify()
        assert order == ["a", "b"]

    def test_a_raising_subscriber_is_swallowed_and_the_next_still_runs(self, st, session):
        def bad(change):
            raise RuntimeError("boom")

        seen = []
        st.subscribe(bad)
        st.subscribe(seen.append)
        session.publish(SessionPart(True, "input1")).notify()
        assert len(seen) == 1

    def test_notify_is_idempotent(self, st, session):
        seen = collect(st)
        pending = session.publish(SessionPart(True, "input1"))
        pending.notify()
        pending.notify()
        assert len(seen) == 1

    def test_unsubscribe_stops_delivery(self, st, session):
        seen = []
        handle = st.subscribe(seen.append)
        st.unsubscribe(handle)
        session.publish(SessionPart(True, "input1")).notify()
        assert seen == []

    def test_a_subscriber_may_subscribe_and_unsubscribe_inside_the_call(self, st, session):
        late = []
        handles = []

        def first(change):
            st.unsubscribe(handles[0])
            st.subscribe(late.append)

        handles.append(st.subscribe(first))
        session.publish(SessionPart(True, "input1")).notify()
        session.publish(SessionPart(True, "input2")).notify()
        assert len(late) == 1

    def test_subscribers_run_after_the_store_lock_is_free(self, st, session):
        free = []

        def check(change):
            got = st._lock.acquire(False)
            free.append(got)
            if got:
                st._lock.release()

        st.subscribe(check)
        session.publish(SessionPart(True, "input1")).notify()
        assert free == [True]


class TestBatch:
    def test_batch_is_returned_open_and_holds_this_threads_notifications(self, st, session):
        seen = collect(st)
        batch = st.batch()
        session.publish(SessionPart(True, "input1")).notify()
        assert seen == []
        batch.close()
        assert len(seen) == 1
        assert seen[0].batch is True
        assert seen[0].parts == frozenset({"session"})

    def test_other_threads_notifications_are_immediate(self, st, session):
        seen = collect(st)
        settings = st.claim("settings", "test_owner")
        batch = st.batch()
        t = threading.Thread(target=lambda: settings.publish(SettingsPart(1)).notify())
        t.start()
        t.join()
        assert [c.batch for c in seen] == [False]
        batch.close()

    def test_close_emits_one_change_even_with_no_parts(self, st):
        seen = collect(st)
        st.batch().close()
        assert len(seen) == 1
        assert seen[0].parts == frozenset()
        assert seen[0].batch is True

    def test_close_merges_parts_tags_and_the_latest_version(self, st, session):
        seen = collect(st)
        settings = st.claim("settings", "test_owner")
        with st.batch():
            session.publish(SessionPart(True, "input1"), tags=["session"],
                            origin=Origin.SYSTEM).notify()
            settings.publish(SettingsPart(2), origin=Origin.SYSTEM).notify()
        assert len(seen) == 1
        merged = seen[0]
        assert merged.parts == frozenset({"session", "settings"})
        assert merged.tags == frozenset({"session"})
        assert merged.version == 2
        assert merged.origin is Origin.SYSTEM

    def test_origin_and_requester_are_dropped_when_the_merged_changes_disagree(self, st, session):
        seen = collect(st)
        settings = st.claim("settings", "test_owner")
        with st.batch():
            session.publish(SessionPart(True, "input1"), origin=Origin.USER, requester="webui").notify()
            settings.publish(SettingsPart(2), origin=Origin.SYSTEM, requester="coordinator").notify()
        assert seen[0].origin is None
        assert seen[0].requester is None

    def test_close_is_idempotent(self, st, session):
        seen = collect(st)
        batch = st.batch()
        batch.close()
        batch.close()
        assert len(seen) == 1

    def test_a_second_batch_on_one_thread_raises(self, st):
        batch = st.batch()
        with pytest.raises(RuntimeError):
            st.batch()
        batch.close()
        st.batch().close()

    def test_a_closed_batch_lets_notifications_through_again(self, st, session):
        seen = collect(st)
        st.batch().close()
        session.publish(SessionPart(True, "input1")).notify()
        assert [c.batch for c in seen] == [True, False]


class TestLeaks:
    def test_a_pending_never_notified_is_reported_with_its_creation_stack(self, st, session):
        pending = session.publish(SessionPart(True, "input1"))
        gc.collect()
        leaked = st.take_leaked()
        assert len(leaked) == 1
        assert "test_a_pending_never_notified_is_reported" in leaked[0]
        pending.notify()

    def test_a_pending_dropped_without_notify_is_still_reported(self, st, session):
        session.publish(SessionPart(True, "input1"))
        gc.collect()
        assert len(st.take_leaked()) == 1

    def test_one_kept_alive_by_a_reference_cycle_is_reported_in_the_same_test(self, st, session):
        pending = session.publish(SessionPart(True, "input1"))
        pending.cycle = [pending]
        del pending
        gc.collect()
        assert len(st.take_leaked()) == 1

    def test_a_notified_pending_and_an_unchanged_one_are_not_leaks(self, st, session):
        session.publish(SessionPart(True, "input1")).notify()
        session.publish(SessionPart(True, "input1"))
        gc.collect()
        assert st.take_leaked() == []

    def test_a_pending_delivered_to_a_batch_counts_as_notified(self, st, session):
        with st.batch():
            session.publish(SessionPart(True, "input1")).notify()
        gc.collect()
        assert st.take_leaked() == []


class TestWait:
    def test_wait_returns_when_the_version_moves(self, st, session):
        result = []
        t = threading.Thread(target=lambda: result.append(st.wait_for_change(0, 5.0)))
        t.start()
        time.sleep(0.05)
        session.publish(SessionPart(True, "input1")).notify()
        t.join(5)
        assert result and result[0].version == 1

    def test_wait_returns_at_once_when_already_ahead(self, st, session):
        session.publish(SessionPart(True, "input1")).notify()
        assert st.wait_for_change(0, 0.0).version == 1

    def test_wait_times_out_with_none(self, st):
        assert st.wait_for_change(0, 0.05) is None

    def test_wait_works_after_the_lock_is_replaced_by_a_recording_lock(self, st):
        st.reset_for_tests(track_locks=True)
        session = st.claim("session", "test_owner")
        assert st.wait_for_change(0, 0.02) is None

        def later():
            time.sleep(0.05)
            session.publish(SessionPart(True, "input1")).notify()

        t = threading.Thread(target=later)
        t.start()
        snap = st.wait_for_change(0, 5.0)
        t.join()
        assert snap is not None and snap.version == 1
