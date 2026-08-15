"""dial_spi_bus.py — process-lifetime owner of the Raspberry Pi SPI buses.

The display backend (dial_display_adafruit.py) drives SPI0 and the resistive
touch driver (dial_touch_drivers.py) drives SPI1. They are separate physical
buses with separate clock, MOSI and MISO lines, so they cannot contend with
each other at all. Construction of each, and the discipline for using one
safely from more than one caller, live here rather than inside either of
them.

SPI1 is the BCM auxiliary SPI controller. It is not enabled by the stock
`dtparam=spi=on`; the dial installer adds the overlay that creates
/dev/spidev1.0. Its chip-select pin is claimed by the kernel, which is why
the touch driver drives its OWN chip select from a plain GPIO rather than
relying on a hardware CE line — see dial_touch_drivers.

Hardware imports (board, busio) happen ONLY inside get_bus(), never at
module import time — this module must be importable on a machine with no
Adafruit stack installed at all, same discipline as dial_display_profiles.py
(pure data, no hardware import ever) and dial_display_adafruit.py (hardware
imports lazy inside open()). A display-disabled dial must never fail to
start just because this module got imported.

--------------------------------------------------------------------------
Two kinds of lock, two different jobs — do not conflate them:

1. The CONSTRUCTION lock (module-private, one for all buses) guards creating
   the busio.SPI objects. Display and touch initialise independently and
   could both call get_bus() for the first time at roughly the same moment,
   in either order — this lock makes sure exactly one busio.SPI() call
   happens per bus and every caller gets back the same object for the bus it
   asked for. It is held only around construction, never around a whole
   transaction.

2. A TRANSACTION lock PER BUS, exposed via spi_transaction(spec), is what
   callers must hold across a WHOLE SPI transaction — e.g. the display's
   window-set-plus-pixel-write for one frame, or the touch driver's
   baudrate-switch-plus-sample-read. It exists because Blinka's own
   busio.SPI.try_lock() is scoped to a single busio.SPI *instance* and gives
   no mutual exclusion between two independently-constructed instances.
   Hold it for the whole of your operation, never just around one low-level
   transfer: grabbing and releasing it between the window-set and the pixel
   write (or between the baudrate switch and the sample read) would let
   another holder's transaction interleave with your own mid-frame or
   mid-sample.

   The locks are per bus and never nested, so no lock-ordering rule is
   needed between them. Display and touch now sit on different buses and so
   take different locks; the discipline is kept anyway because it is what
   makes a second user of either bus safe to add later, and because a driver
   must not assume it is the only user of its bus.

BAUDRATE CONTRACT: a bus's clock configuration persists on its busio.SPI
object across acquisitions — nothing resets it when a transaction lock is
released. Every holder MUST (re)configure the bus for its own transaction at
the start of every acquisition, every time, and must never assume the
previous holder left it in any particular state or that it needs to restore
state for the next user. This holds even on a bus with a single user today.
--------------------------------------------------------------------------

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SpiBusSpec:
    """Which physical bus, in BCM pin numbers. Pure data — no hardware
    import, so this is safe to build at module import time."""
    label: str
    clock: int
    mosi: int
    miso: int
    # Extra board-module aliases to try for each line, newest Blinka
    # releases having renamed some of them over time.
    clock_aliases: tuple = field(default=())
    mosi_aliases: tuple = field(default=())
    miso_aliases: tuple = field(default=())


# The display's bus: the main SPI0 controller, enabled by dtparam=spi=on.
DISPLAY_BUS = SpiBusSpec(
    label="SPI0",
    clock=11, mosi=10, miso=9,
    clock_aliases=("SCLK",), mosi_aliases=("MOSI",), miso_aliases=("MISO",),
)

# The touch controller's bus: the auxiliary SPI1 controller. Separate lines
# from the display, so a frame push can never delay a touch sample and no
# header pin has to carry two wires.
TOUCH_BUS = SpiBusSpec(
    label="SPI1",
    clock=21, mosi=20, miso=19,
    clock_aliases=("SCLK_1", "SCK1"),
    mosi_aliases=("MOSI_1",),
    miso_aliases=("MISO_1",),
)

_ALL_BUSES = (DISPLAY_BUS, TOUCH_BUS)

# Guards first construction of any bus. Distinct from the transaction locks
# below — see module docstring.
_construction_lock = threading.Lock()

# One transaction lock per bus, created up front (a plain threading.Lock
# needs no hardware, so there is nothing to defer).
_transaction_locks = {spec.label: threading.Lock() for spec in _ALL_BUSES}

# Constructed busio.SPI objects, keyed by bus label. Populated lazily.
_buses: dict = {}


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


def get_bus(spec: SpiBusSpec):
    """Return the process-wide busio.SPI object for one bus, constructing it
    on the first call for that bus. Every subsequent call for the same bus
    returns the exact same object.

    Construction is guarded by _construction_lock so two callers racing to
    initialise first still end up with exactly one busio.SPI() call per bus
    between them.

    If construction fails, the exception propagates to the caller unchanged
    — it is not swallowed here, and a failed attempt is never cached as a
    success, so a later call can still succeed once whatever was wrong
    (missing package, missing overlay, busy pins, etc.) is fixed.
    """
    existing = _buses.get(spec.label)
    if existing is not None:
        return existing
    with _construction_lock:
        existing = _buses.get(spec.label)
        if existing is not None:
            return existing
        import board
        import busio

        bus = busio.SPI(
            clock=board_pin(board, spec.clock, *spec.clock_aliases),
            MOSI=board_pin(board, spec.mosi, *spec.mosi_aliases),
            MISO=board_pin(board, spec.miso, *spec.miso_aliases),
        )
        _buses[spec.label] = bus
    return _buses[spec.label]


def spi_transaction(spec: SpiBusSpec):
    """Return one bus's transaction lock as a context manager:

        with dial_spi_bus.spi_transaction(dial_spi_bus.TOUCH_BUS):
            ...whole transaction here...

    Hold it across the whole of one side's operation — see the module
    docstring for what "whole" means and why per-transfer locking is wrong.
    threading.Lock is itself a context manager, so this just hands back the
    lock for the requested bus.
    """
    return _transaction_locks[spec.label]


def _reset_for_tests():
    """Test seam only: drop the constructed buses so the next get_bus() call
    builds fresh ones. Without this, the module-level singletons would leak
    state across test cases. Not for use outside tests."""
    _buses.clear()
