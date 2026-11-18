"""tests/test_logging_rate_limit.py

The rate limit on repeated log lines and the per-key log_every helper.
"""
import logging
import sys
import threading
from pathlib import Path

import pytest

_CORE = str(Path(__file__).parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_logging as log_setup


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record):
        self.lines.append(record.getMessage())


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def rig():
    clock = _Clock()
    handler = _Capture()
    limiter = log_setup.install_rate_limit(handler, clock=clock)
    logger = logging.getLogger("ratelimit.test")
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    yield logger, handler, limiter, clock
    logger.removeHandler(handler)


def test_first_five_pass_and_the_rest_are_dropped(rig):
    logger, handler, _, _ = rig
    for _i in range(12):
        logger.warning("same line")
    assert handler.lines == ["same line"] * 5


def test_summary_is_emitted_once_when_a_later_record_passes_after_the_window(rig):
    logger, handler, _, clock = rig
    for _i in range(12):
        logger.warning("same line")
    clock.t += 61
    logger.warning("same line")
    assert handler.lines[5:] == ["same line (repeated 7 more times in 60 s)", "same line"]
    clock.t += 1
    logger.warning("same line")
    assert len(handler.lines) == 8


def test_summary_goes_out_when_a_different_key_passes(rig):
    logger, handler, _, clock = rig
    for _i in range(7):
        logger.warning("noisy")
    clock.t += 61
    logger.warning("other")
    assert handler.lines[5:] == ["noisy (repeated 2 more times in 60 s)", "other"]


def test_keys_differ_by_logger_level_and_format_string_not_args(rig):
    logger, handler, _, _ = rig
    other = logging.getLogger("ratelimit.other")
    other.addHandler(handler)
    other.propagate = False
    try:
        for i in range(10):
            logger.warning("value %d", i)
        assert len(handler.lines) == 5
        for _i in range(10):
            logger.error("value %d", 0)
        assert len(handler.lines) == 10
        for _i in range(10):
            other.warning("value %d", 0)
        assert len(handler.lines) == 15
        for _i in range(10):
            logger.warning("another %d", 0)
        assert len(handler.lines) == 20
    finally:
        other.removeHandler(handler)


def test_critical_no_rate_limit_and_exempt_loggers_always_pass():
    clock = _Clock()
    handler = _Capture()
    log_setup.install_rate_limit(handler, clock=clock, exempt_loggers=frozenset({"ratelimit.exempt"}))
    for name, level, extra in (
        ("ratelimit.crit", logging.CRITICAL, None),
        ("ratelimit.extra", logging.WARNING, {"no_rate_limit": True}),
        ("ratelimit.exempt", logging.WARNING, None),
    ):
        lg = logging.getLogger(name)
        lg.addHandler(handler)
        lg.propagate = False
        before = len(handler.lines)
        for _i in range(20):
            lg.log(level, "flood", extra=extra)
        assert len(handler.lines) - before == 20
        lg.removeHandler(handler)


def test_debug_records_are_never_limited(rig):
    logger, handler, _, _ = rig
    for _i in range(1000):
        logger.debug("chatty")
    assert len(handler.lines) == 1000


def test_summary_is_not_itself_limited(rig):
    logger, handler, _, clock = rig
    for _i in range(6):
        logger.warning("a")
    clock.t += 61
    logger.warning("b")
    assert handler.lines.count("a (repeated 1 more times in 60 s)") == 1


def test_ended_keys_are_deleted_so_distinct_messages_stay_bounded(rig):
    logger, _, limiter, clock = rig
    for i in range(100):
        logger.warning("distinct %d" % i)
    assert len(limiter._table) == 100
    clock.t += 61
    logger.warning("fresh")
    assert list(limiter._table) == [("ratelimit.test", logging.WARNING, "fresh")]


def test_table_is_capped_and_the_oldest_key_is_evicted_with_its_drops_summarised():
    clock = _Clock()
    handler = _Capture()
    limiter = log_setup.install_rate_limit(handler, clock=clock, max_keys=3, burst=1)
    lg = logging.getLogger("ratelimit.cap")
    lg.addHandler(handler)
    lg.propagate = False
    try:
        lg.warning("k0")
        lg.warning("k0")
        lg.warning("k0")
        clock.t += 1
        lg.warning("k1")
        clock.t += 1
        lg.warning("k2")
        assert len(limiter._table) == 3
        clock.t += 1
        lg.warning("k3")
        assert len(limiter._table) == 3
        assert ("ratelimit.cap", logging.WARNING, "k0") not in limiter._table
        assert "k0 (repeated 2 more times in 60 s)" in handler.lines
    finally:
        lg.removeHandler(handler)


def test_log_every_is_independent_per_key():
    assert log_setup.log_every("a", 60.0, now=100.0) is True
    assert log_setup.log_every("a", 60.0, now=159.0) is False
    assert log_setup.log_every("b", 60.0, now=159.0) is True
    assert log_setup.log_every("a", 60.0, now=160.0) is True
    assert log_setup.log_every("a", 60.0, now=161.0) is False


def test_reset_for_tests_clears_the_log_every_timers():
    assert log_setup.log_every("r", 60.0, now=1.0) is True
    log_setup.reset_for_tests()
    assert log_setup.log_every("r", 60.0, now=2.0) is True


def test_the_filter_lock_is_not_held_while_emitting():
    clock = _Clock()

    class _Reentrant(logging.Handler):
        def __init__(self):
            super().__init__()
            self.lines = []

        def emit(self, record):
            self.lines.append(record.getMessage())
            if record.getMessage().startswith("x (repeated"):
                # A handler that logs while emitting must not deadlock.
                logging.getLogger("ratelimit.re").warning("from emit")

    handler = _Reentrant()
    log_setup.install_rate_limit(handler, clock=clock, burst=1)
    lg = logging.getLogger("ratelimit.re")
    lg.addHandler(handler)
    lg.propagate = False
    done = threading.Event()

    def run():
        try:
            lg.warning("x")
            lg.warning("x")
            clock.t += 61
            lg.warning("x")
        finally:
            done.set()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    try:
        assert done.wait(10)
        assert "x (repeated 1 more times in 60 s)" in handler.lines
        assert "from emit" in handler.lines
    finally:
        lg.removeHandler(handler)
