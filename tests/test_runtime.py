"""tests/test_runtime.py

The process-wide runtime primitives: stop and reload events, and the helper
that resets them between tests.
"""
import sys
from pathlib import Path

_CORE = str(Path(__file__).parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_runtime as runtime


def test_request_config_reload_sets_the_reload_flag():
    runtime.reload_flag.clear()
    runtime.request_config_reload()
    assert runtime.reload_flag.is_set()
    runtime.reload_flag.clear()


def test_reset_for_tests_clears_both_events():
    runtime.stop_flag.set()
    runtime.reload_flag.set()
    runtime.reset_for_tests()
    assert not runtime.stop_flag.is_set()
    assert not runtime.reload_flag.is_set()


def test_the_task_pool_accessor_returns_the_shared_pool():
    assert runtime.get_task_pool() is runtime._task_pool
