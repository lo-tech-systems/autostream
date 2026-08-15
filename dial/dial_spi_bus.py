"""dial_spi_bus.py — process-lifetime shared owner of the Raspberry Pi SPI0
bus.

Both the display backend (dial_display_adafruit.py) and the resistive
touch driver (dial_touch_drivers.py) drive SPI0, sharing the same physical
clock, MOSI and MISO lines. Bus construction and the discipline for using it
safely from more than one caller therefore live here rather than inside
either of them.

Hardware imports (board, busio) happen ONLY inside get_bus(), never at
module import time — this module must be importable on a machine with no
Adafruit stack installed at all, same discipline as dial_display_profiles.py
(pure data, no hardware import ever) and dial_display_adafruit.py (hardware
imports lazy inside open()). A display-disabled dial must never fail to
start just because this module got imported.

--------------------------------------------------------------------------
Two locks, two different jobs — do not conflate them:

1. The CONSTRUCTION lock (module-private) guards creating the single shared
   busio.SPI object. Display and touch initialise independently and could
   both call get_bus() for the first time at roughly the same moment, in
   either order — this lock makes sure exactly one busio.SPI() call happens
   and every caller (whichever arrived first or second) gets back the same
   object. It is held only around construction, never around a whole
   transaction.

2. The TRANSACTION lock, exposed via spi_transaction(), is what callers
   must hold across a WHOLE SPI transaction — e.g. the display's
   window-set-plus-pixel-write for one frame, or a future touch driver's
   baudrate-switch-plus-sample-read. It exists because Blinka's own
   busio.SPI.try_lock() is scoped to a single busio.SPI *instance* and gives
   no mutual exclusion between two independently-constructed instances —
   and in any case this module hands out one shared instance, so we are not
   relying on try_lock() for cross-user safety at all. Hold this lock for
   the whole of your operation, never just around one low-level transfer:
   grabbing and releasing it between the window-set and the pixel write (or
   between the baudrate switch and the sample read) would let another
   holder's transaction interleave with your own mid-frame/mid-sample.

BAUDRATE CONTRACT: the bus's clock configuration persists on the shared
busio.SPI object across acquisitions — nothing resets it when a transaction
lock is released. Every holder MUST (re)configure the bus for its own
transaction at the start of every acquisition, every time, and must never
assume the previous holder left it in any particular state or that it needs
to restore state for the next user.
--------------------------------------------------------------------------

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import threading

# Guards first construction of the shared bus. Distinct from
# _transaction_lock below — see module docstring.
_construction_lock = threading.Lock()

# Held by callers across a whole SPI transaction. See module docstring for
# why this exists and how it must be used.
_transaction_lock = threading.Lock()

# The shared busio.SPI object, constructed lazily on first get_bus() call.
_bus = None


def board_pin(board_module, gpio: int, *aliases: str):
    """Resolve a BCM GPIO number to whichever alias this Blinka release's
    board module exposes for it.

    Public and shared: the display backend and the touch drivers both need
    it and both already import this module, so it lives here as the single
    definition rather than being copied into each of them where the copies
    could drift apart.
    """
    names = (f"GPIO{gpio}", f"D{gpio}", *aliases)
    for name in names:
        if hasattr(board_module, name):
            return getattr(board_module, name)
    raise AttributeError(
        f"board module has no supported alias for GPIO{gpio} "
        f"(tried {', '.join(names)})"
    )


def get_bus():
    """Return the process-wide shared busio.SPI object for SPI0, constructing
    it on the first call. Every subsequent call — from the display, from a
    future touch controller, from anywhere — returns the exact same object.

    Construction is guarded by _construction_lock so two callers racing to
    initialise first (e.g. display and touch starting up in either order)
    still end up with exactly one busio.SPI() call between them.

    If construction fails, the exception propagates to the caller unchanged
    — it is not swallowed here, and a failed attempt is never cached as a
    success, so a later call can still succeed once whatever was wrong
    (missing package, busy pins, etc.) is fixed.
    """
    global _bus
    if _bus is not None:
        return _bus
    with _construction_lock:
        if _bus is not None:
            return _bus
        import board
        import busio

        bus = busio.SPI(
            clock=board_pin(board, 11, "SCLK"),
            MOSI=board_pin(board, 10, "MOSI"),
            MISO=board_pin(board, 9, "MISO"),
        )
        _bus = bus
    return _bus


def spi_transaction():
    """Return the transaction lock as a context manager:

        with dial_spi_bus.spi_transaction():
            ...whole transaction here...

    Hold it across the whole of one side's operation — see the module
    docstring for what "whole" means and why per-transfer locking is wrong.
    threading.Lock is itself a context manager, so this just hands back the
    shared lock object.
    """
    return _transaction_lock


def _reset_for_tests():
    """Test seam only: drop the singleton bus so the next get_bus() call
    constructs a fresh one. Without this, the module-level singleton would
    leak state across test cases. Not for use outside tests."""
    global _bus
    _bus = None
