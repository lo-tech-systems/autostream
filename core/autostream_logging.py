"""autostream_logging.py -- logging setup and the live platform log level.

Standard library only at module level (the dial ships this module too):
the configuration helpers are imported inside the functions that need them.
"""
from __future__ import annotations

import logging
import os
import sys
import threading
import time
from typing import Callable, Hashable


_live_platform_log_level = "warning"

# Third-party libraries that are noisy at DEBUG (connection-pool churn,
# per-request lines) but rarely useful outside deep diagnostics. Pinned to
# WARNING unless the platform level is "spam".
_THIRD_PARTY_NOISY = ("urllib3", "urllib3.connectionpool", "requests")


def _pin_third_party_loggers(normalized_level: str) -> None:
    """Cap noisy third-party loggers independently of the platform level.

    Kept at WARNING even when the platform is at DEBUG, since urllib3/requests
    debug output dominates DEBUG captures without adding diagnostic value.
    Only relaxed to DEBUG at "spam", the deep-diagnostic tier.
    """
    lib_level = logging.DEBUG if normalized_level == "spam" else logging.WARNING
    for name in _THIRD_PARTY_NOISY:
        logging.getLogger(name).setLevel(lib_level)


def setup_logging(log_file: str, log_level: str) -> None:
    """Route all records through a queue to the log file and stdout."""
    global _live_platform_log_level
    from autostream_config import normalize_log_level, python_log_level_value

    normalized = normalize_log_level(log_level)
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    # Route all records through a QueueHandler so no caller thread ever
    # performs file I/O under the logging handler lock. A slow SD write
    # (e.g. during logrotate's compression pass) would otherwise block
    # whichever thread was logging while every other logging thread queued
    # on the shared handler lock -- the same structural wedge the C++
    # daemon's logger avoids. The QueueListener's single background thread
    # owns the blocking writes instead.
    import queue as _queue
    from logging.handlers import QueueHandler, QueueListener

    sink_handlers = [
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout),
    ]
    log_queue: _queue.Queue = _queue.Queue(maxsize=1000)
    queue_handler = QueueHandler(log_queue)
    # Repeated lines are limited here, on the logging thread and before the
    # queue, so a flood never reaches the file. Lifecycle lines go straight to
    # the handlers and are never dropped.
    from autostream_sysutils import LIFECYCLE_LOGGER

    install_rate_limit(
        queue_handler,
        min_level=logging.INFO,
        exempt_loggers=frozenset({LIFECYCLE_LOGGER}),
    )
    logging.basicConfig(
        level=python_log_level_value(normalized),
        format="%(asctime)s: %(message)s",
        datefmt="%d-%b-%y %H:%M:%S",
        handlers=[queue_handler],
    )
    listener = QueueListener(log_queue, *sink_handlers, respect_handler_level=False)
    listener.daemon = True
    listener.start()
    # Flush queued records on interpreter exit (best-effort; daemon thread
    # otherwise dies with the process mid-write).
    import atexit
    atexit.register(listener.stop)
    _live_platform_log_level = normalized
    _pin_third_party_loggers(normalized)


def update_live_log_level(log_level: str) -> str:
    """Apply the platform log level to the running Python process."""
    global _live_platform_log_level
    from autostream_config import normalize_log_level, python_log_level_value

    normalized = normalize_log_level(log_level)
    target_level = python_log_level_value(normalized)
    root_logger = logging.getLogger()
    root_logger.setLevel(target_level)
    for handler in root_logger.handlers:
        try:
            handler.setLevel(target_level)
        except Exception:
            pass
    _live_platform_log_level = normalized
    _pin_third_party_loggers(normalized)
    return normalized


def get_live_platform_log_level() -> str:
    """Return the current runtime platform log-level name."""
    return _live_platform_log_level


# ---------------------------------------------------------------------------
# Rate limit on repeated log lines
# ---------------------------------------------------------------------------

class RateLimitFilter(logging.Filter):
    """Limits records by (logger name, level, format string) over a window.

    Only records at ``min_level`` (INFO) and above are limited; DEBUG and the
    spam tier pass untouched, so a debug capture stays complete.
    The first ``burst`` records of a key in a window pass; the rest are counted
    and dropped. When a later record of any key passes, every key whose window
    has ended with drops gets one summary record, '<format string> (repeated N
    more times in W s)', emitted through the same handler and carrying
    ``no_rate_limit`` so it does not re-enter the filter. On the same pass every
    key whose window has ended (with or without drops) is deleted, and the
    table never holds more than ``max_keys`` keys: inserting one more evicts the
    key whose window started first (its pending drop count, if any, is
    summarised first). Records of loggers in ``exempt_loggers``, records at
    CRITICAL, and records with ``extra={"no_rate_limit": True}`` always pass.
    filter() runs on the thread that logs (Handler.handle calls it before the
    handler lock). Thread-safe: one leaf lock, never held while emitting."""

    def __init__(
        self,
        *,
        window_s: float = 60.0,
        burst: int = 5,
        min_level: int = logging.INFO,
        max_keys: int = 512,
        exempt_loggers: frozenset[str] = frozenset(),
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__()
        self._window_s = float(window_s)
        self._burst = int(burst)
        self._min_level = int(min_level)
        self._max_keys = int(max_keys)
        self._exempt = frozenset(exempt_loggers)
        self._clock = clock
        self._lock = threading.Lock()
        # key -> [window start, records passed, records dropped]
        self._table: dict[tuple, list] = {}
        self.handler: logging.Handler | None = None

    def filter(self, record: logging.LogRecord) -> bool:
        if (
            record.levelno < self._min_level
            or record.levelno >= logging.CRITICAL
            or getattr(record, "no_rate_limit", False)
            or record.name in self._exempt
        ):
            return True
        key = (record.name, record.levelno, str(record.msg))
        now = self._clock()
        summaries: list[tuple[tuple, int]] = []
        with self._lock:
            entry = self._table.get(key)
            if entry is not None and now - entry[0] < self._window_s:
                if entry[1] < self._burst:
                    entry[1] += 1
                    return True
                entry[2] += 1
                return False
            # This record passes. Close every window that has ended.
            for k in [k for k, e in self._table.items() if now - e[0] >= self._window_s]:
                dropped = self._table.pop(k)[2]
                if dropped:
                    summaries.append((k, dropped))
            while len(self._table) >= self._max_keys:
                oldest = min(self._table, key=lambda k: self._table[k][0])
                dropped = self._table.pop(oldest)[2]
                if dropped:
                    summaries.append((oldest, dropped))
            self._table[key] = [now, 1, 0]
        for k, dropped in summaries:
            self._emit_summary(k, dropped)
        return True

    def _emit_summary(self, key: tuple, dropped: int) -> None:
        name, levelno, fmt = key
        summary = logging.LogRecord(
            name, levelno, __file__, 0,
            f"{fmt} (repeated {dropped} more times in {self._window_s:g} s)",
            (), None,
        )
        summary.no_rate_limit = True
        try:
            if self.handler is not None:
                self.handler.handle(summary)
            else:
                logging.getLogger(name).handle(summary)
        except Exception:
            pass


def install_rate_limit(handler: logging.Handler, **kwargs) -> RateLimitFilter:
    """Add a RateLimitFilter to *handler* and return it."""
    limiter = RateLimitFilter(**kwargs)
    limiter.handler = handler
    handler.addFilter(limiter)
    return limiter


_every_lock = threading.Lock()
_every_last: dict[Hashable, float] = {}


def log_every(key: Hashable, seconds: float, *, now: float | None = None) -> bool:
    """True when the call site keyed *key* may log now: the first call, and
    then once each *seconds*. Independent timer per key. Leaf lock."""
    t = time.monotonic() if now is None else now
    with _every_lock:
        last = _every_last.get(key)
        if last is not None and t - last < seconds:
            return False
        _every_last[key] = t
        return True


def reset_for_tests() -> None:
    """Forget every log_every timer."""
    with _every_lock:
        _every_last.clear()
