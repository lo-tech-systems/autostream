"""Unit tests for autostream_debounce.Debouncer: the one shared debounce
primitive that replaced _debounce_track_id_rebuild's own ad hoc
threading.Timer/lock/global trio.
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_debounce import Debouncer, default_debouncer


class TestDebouncerTrigger:
    def test_callback_fires_after_delay(self):
        d = Debouncer()
        fired = threading.Event()
        d.trigger("k", 0.02, fired.set)
        assert fired.wait(timeout=1.0)

    def test_repeated_trigger_within_window_collapses_to_last_callback(self):
        d = Debouncer()
        calls = []
        fired = threading.Event()

        d.trigger("k", 0.2, lambda: calls.append("first"))
        d.trigger("k", 0.05, lambda: (calls.append("second"), fired.set()))

        assert fired.wait(timeout=1.0)
        # Give any (incorrectly still-pending) first timer a chance to fire.
        time.sleep(0.1)
        assert calls == ["second"]

    def test_independent_keys_do_not_interfere(self):
        d = Debouncer()
        fired_a = threading.Event()
        fired_b = threading.Event()
        d.trigger("a", 0.02, fired_a.set)
        d.trigger("b", 0.02, fired_b.set)
        assert fired_a.wait(timeout=1.0)
        assert fired_b.wait(timeout=1.0)

    def test_pending_true_before_fire_false_after(self):
        d = Debouncer()
        fired = threading.Event()
        d.trigger("k", 0.05, fired.set)
        assert d.pending("k") is True
        assert fired.wait(timeout=1.0)
        time.sleep(0.02)  # let the callback's own cleanup run
        assert d.pending("k") is False

    def test_cancel_prevents_callback(self):
        d = Debouncer()
        calls = []
        d.trigger("k", 0.05, lambda: calls.append(1))
        d.cancel("k")
        time.sleep(0.15)
        assert calls == []

    def test_cancel_unknown_key_is_a_noop(self):
        d = Debouncer()
        d.cancel("never-triggered")  # must not raise

    def test_pending_false_for_unknown_key(self):
        d = Debouncer()
        assert d.pending("nope") is False


class TestDefaultDebouncer:
    def test_returns_same_instance_across_calls(self):
        assert default_debouncer() is default_debouncer()

    def test_is_a_debouncer(self):
        assert isinstance(default_debouncer(), Debouncer)
