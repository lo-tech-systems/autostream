"""dial_volume.py — Async volume fan-out worker.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Stage 5 stub: encoder deltas are accepted but not delivered.
  enqueue_delta() is a no-op.
  start_volume_worker() is a no-op.

Full implementation is in Stage 6 (§8.3).
"""
from __future__ import annotations


def enqueue_delta(delta: int) -> None:
    """Enqueue a volume delta for delivery to playing targets.

    Stub: no-op until Stage 6 implementation.  Volume commands will not be
    sent to appliances until the fan-out worker is implemented.
    """
    pass


def start_volume_worker(cfg, targets_fn, led) -> None:
    """Start the background volume delivery thread.

    Stub: no-op until Stage 6 implementation.
    """
    pass
