"""autostream_logging.py -- logging setup and the live platform log level.

Standard library only at module level (the dial ships this module too):
the configuration helpers are imported inside the functions that need them.
"""
from __future__ import annotations

import logging
import os
import sys


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
    logging.basicConfig(
        level=python_log_level_value(normalized),
        format="%(asctime)s: %(message)s",
        datefmt="%d-%b-%y %H:%M:%S",
        handlers=[QueueHandler(log_queue)],
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
