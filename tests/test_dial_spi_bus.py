"""Tests for dial_spi_bus.py — the process-wide owner of the two independent
SPI buses (DISPLAY_BUS on SPI0, TOUCH_BUS on SPI1).

Covers: no hardware imports at module level (a display-disabled dial must
still be able to import this module), get_bus(spec) singleton behavior per
bus (same object every call, exactly one construction even under a race,
a failed construction does not poison later calls or the other bus, lazy
per-bus construction), that the two buses are independent objects, and that
spi_transaction(spec) hands back a per-bus lock providing real mutual
exclusion within a bus while never blocking the other bus.
"""
from __future__ import annotations

import subprocess
import sys
import threading
import time
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

import dial_spi_bus


@pytest.fixture(autouse=True)
def _reset_singleton():
    dial_spi_bus._reset_for_tests()
    yield
    dial_spi_bus._reset_for_tests()


def _install_fake_hardware_modules(spi_ctor=None):
    """Inject fake board/busio modules, same shape as
    tests/test_dial_display_adafruit.py's helper of the same name.

    Includes pin aliases for both DISPLAY_BUS (GPIO9/10/11) and TOUCH_BUS
    (GPIO19/20/21) so tests can construct either or both."""
    board = types.ModuleType("board")
    for name in ("GPIO9", "GPIO10", "GPIO11", "GPIO19", "GPIO20", "GPIO21"):
        setattr(board, name, name)

    busio = types.ModuleType("busio")
    if spi_ctor is None:
        spi_ctor = MagicMock(name="SPI", side_effect=lambda **kwargs: MagicMock(name="SPI_instance"))
    busio.SPI = spi_ctor

    return {"board": board, "busio": busio}


# ---------------------------------------------------------------------------
# Module-level import discipline
# ---------------------------------------------------------------------------

class TestNoModuleLevelHardwareImports:
    def test_source_has_no_top_level_hardware_imports(self):
        source_path = Path(_DIAL) / "dial_spi_bus.py"
        text = source_path.read_text(encoding="utf-8")
        for line in text.splitlines():
            if line.startswith("import board") or line.startswith("import busio"):
                pytest.fail(f"hardware import found at module level: {line!r}")

    def test_importing_module_does_not_pull_in_hardware_modules(self):
        """Stronger than a source-text check: actually import the module in
        a fresh subprocess (without calling get_bus()) and inspect
        sys.modules afterwards — mirrors
        test_dial_display_profiles.py::TestNoHardwareImport."""
        script = (
            "import sys; "
            f"sys.path.insert(0, {_DIAL!r}); "
            "import dial_spi_bus; "
            "hw = {'board', 'busio', 'digitalio', 'adafruit_rgb_display'}; "
            "hit = hw & set(sys.modules); "
            "print(','.join(sorted(hit)))"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == ""


# ---------------------------------------------------------------------------
# get_bus() singleton behavior
# ---------------------------------------------------------------------------

class TestGetBusSingleton:
    def test_get_bus_returns_same_object_across_calls(self, monkeypatch):
        modules = _install_fake_hardware_modules()
        monkeypatch.setitem(sys.modules, "board", modules["board"])
        monkeypatch.setitem(sys.modules, "busio", modules["busio"])

        first = dial_spi_bus.get_bus(dial_spi_bus.DISPLAY_BUS)
        second = dial_spi_bus.get_bus(dial_spi_bus.DISPLAY_BUS)
        third = dial_spi_bus.get_bus(dial_spi_bus.DISPLAY_BUS)

        assert first is second is third
        modules["busio"].SPI.assert_called_once()

    def test_construction_race_produces_exactly_one_bus(self, monkeypatch):
        """Two threads calling get_bus() for the first time concurrently
        must still end up with exactly one busio.SPI() call and both must
        observe the same returned object."""
        call_count = {"n": 0}
        lock = threading.Lock()
        instance = MagicMock(name="SPI_instance")

        def slow_spi_ctor(**kwargs):
            with lock:
                call_count["n"] += 1
            # Widen the race window so both threads are inside the critical
            # section's hardware-import/construct path at the same time if
            # the construction lock did not serialize them.
            time.sleep(0.05)
            return instance

        modules = _install_fake_hardware_modules(spi_ctor=slow_spi_ctor)
        monkeypatch.setitem(sys.modules, "board", modules["board"])
        monkeypatch.setitem(sys.modules, "busio", modules["busio"])

        results = [None, None]

        def worker(i):
            results[i] = dial_spi_bus.get_bus(dial_spi_bus.DISPLAY_BUS)

        t1 = threading.Thread(target=worker, args=(0,))
        t2 = threading.Thread(target=worker, args=(1,))
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        assert call_count["n"] == 1
        assert results[0] is results[1] is instance

    def test_failed_construction_propagates_and_does_not_poison_singleton(self, monkeypatch):
        attempts = {"n": 0}

        def flaky_spi_ctor(**kwargs):
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise RuntimeError("SPI init failed")
            return MagicMock(name="SPI_instance")

        modules = _install_fake_hardware_modules(spi_ctor=flaky_spi_ctor)
        monkeypatch.setitem(sys.modules, "board", modules["board"])
        monkeypatch.setitem(sys.modules, "busio", modules["busio"])

        with pytest.raises(RuntimeError, match="SPI init failed"):
            dial_spi_bus.get_bus(dial_spi_bus.DISPLAY_BUS)

        # A later, successful call must still work — the failed attempt was
        # not cached as success.
        bus = dial_spi_bus.get_bus(dial_spi_bus.DISPLAY_BUS)
        assert bus is not None
        assert attempts["n"] == 2

    def test_get_bus_for_different_specs_returns_different_objects(self, monkeypatch):
        modules = _install_fake_hardware_modules()
        monkeypatch.setitem(sys.modules, "board", modules["board"])
        monkeypatch.setitem(sys.modules, "busio", modules["busio"])

        display = dial_spi_bus.get_bus(dial_spi_bus.DISPLAY_BUS)
        touch = dial_spi_bus.get_bus(dial_spi_bus.TOUCH_BUS)

        assert display is not touch
        assert modules["busio"].SPI.call_count == 2

    def test_each_bus_is_a_singleton_in_its_own_right(self, monkeypatch):
        modules = _install_fake_hardware_modules()
        monkeypatch.setitem(sys.modules, "board", modules["board"])
        monkeypatch.setitem(sys.modules, "busio", modules["busio"])

        display1 = dial_spi_bus.get_bus(dial_spi_bus.DISPLAY_BUS)
        touch1 = dial_spi_bus.get_bus(dial_spi_bus.TOUCH_BUS)
        display2 = dial_spi_bus.get_bus(dial_spi_bus.DISPLAY_BUS)
        touch2 = dial_spi_bus.get_bus(dial_spi_bus.TOUCH_BUS)

        assert display1 is display2
        assert touch1 is touch2
        assert modules["busio"].SPI.call_count == 2

    def test_constructing_one_bus_does_not_construct_the_other(self, monkeypatch):
        modules = _install_fake_hardware_modules()
        monkeypatch.setitem(sys.modules, "board", modules["board"])
        monkeypatch.setitem(sys.modules, "busio", modules["busio"])

        dial_spi_bus.get_bus(dial_spi_bus.DISPLAY_BUS)

        assert modules["busio"].SPI.call_count == 1
        assert dial_spi_bus._buses.get(dial_spi_bus.TOUCH_BUS.label) is None

    def test_failed_construction_of_one_bus_does_not_affect_the_other(self, monkeypatch):
        def flaky_spi_ctor(**kwargs):
            clock = kwargs.get("clock")
            if clock == "GPIO11":
                raise RuntimeError("SPI0 init failed")
            return MagicMock(name="SPI_instance")

        board = types.ModuleType("board")
        for name in ("GPIO9", "GPIO10", "GPIO11", "GPIO19", "GPIO20", "GPIO21"):
            setattr(board, name, name)
        busio = types.ModuleType("busio")
        busio.SPI = flaky_spi_ctor
        monkeypatch.setitem(sys.modules, "board", board)
        monkeypatch.setitem(sys.modules, "busio", busio)

        with pytest.raises(RuntimeError, match="SPI0 init failed"):
            dial_spi_bus.get_bus(dial_spi_bus.DISPLAY_BUS)

        touch = dial_spi_bus.get_bus(dial_spi_bus.TOUCH_BUS)
        assert touch is not None

    def test_reset_for_tests_clears_both_buses(self, monkeypatch):
        modules = _install_fake_hardware_modules()
        monkeypatch.setitem(sys.modules, "board", modules["board"])
        monkeypatch.setitem(sys.modules, "busio", modules["busio"])

        display = dial_spi_bus.get_bus(dial_spi_bus.DISPLAY_BUS)
        touch = dial_spi_bus.get_bus(dial_spi_bus.TOUCH_BUS)
        dial_spi_bus._reset_for_tests()

        new_display = dial_spi_bus.get_bus(dial_spi_bus.DISPLAY_BUS)
        new_touch = dial_spi_bus.get_bus(dial_spi_bus.TOUCH_BUS)
        assert new_display is not display
        assert new_touch is not touch


class TestSpiBusSpecPins:
    def test_display_bus_carries_spi0_pins(self):
        assert dial_spi_bus.DISPLAY_BUS.label == "SPI0"
        assert dial_spi_bus.DISPLAY_BUS.clock == 11
        assert dial_spi_bus.DISPLAY_BUS.mosi == 10
        assert dial_spi_bus.DISPLAY_BUS.miso == 9

    def test_touch_bus_carries_spi1_pins(self):
        assert dial_spi_bus.TOUCH_BUS.label == "SPI1"
        assert dial_spi_bus.TOUCH_BUS.clock == 21
        assert dial_spi_bus.TOUCH_BUS.mosi == 20
        assert dial_spi_bus.TOUCH_BUS.miso == 19


# ---------------------------------------------------------------------------
# Transaction lock
# ---------------------------------------------------------------------------

class TestSpiTransactionLock:
    def test_transaction_lock_provides_mutual_exclusion(self):
        holder_entered = threading.Event()
        release_holder = threading.Event()
        second_acquired = threading.Event()

        def holder():
            with dial_spi_bus.spi_transaction(dial_spi_bus.DISPLAY_BUS):
                holder_entered.set()
                release_holder.wait(timeout=5)

        def contender():
            holder_entered.wait(timeout=5)
            with dial_spi_bus.spi_transaction(dial_spi_bus.DISPLAY_BUS):
                second_acquired.set()

        t1 = threading.Thread(target=holder)
        t2 = threading.Thread(target=contender)
        t1.start()
        t1_entered = holder_entered.wait(timeout=5)
        assert t1_entered
        t2.start()

        # The contender must NOT be able to acquire the lock while the
        # first holder still has it.
        assert not second_acquired.wait(timeout=0.2)

        release_holder.set()
        t1.join(timeout=5)
        t2.join(timeout=5)
        assert second_acquired.is_set()

    def test_spi_transaction_returns_a_context_manager(self):
        cm = dial_spi_bus.spi_transaction(dial_spi_bus.DISPLAY_BUS)
        with cm:
            pass  # must not raise

    def test_spi_transaction_returns_different_lock_per_bus(self):
        display_lock = dial_spi_bus.spi_transaction(dial_spi_bus.DISPLAY_BUS)
        touch_lock = dial_spi_bus.spi_transaction(dial_spi_bus.TOUCH_BUS)
        assert display_lock is not touch_lock

    def test_holding_one_bus_lock_does_not_block_the_other(self):
        """The whole point of splitting into two buses: a display frame push
        holding the DISPLAY_BUS transaction lock must never delay a touch
        sample acquiring the TOUCH_BUS transaction lock, and vice versa."""
        display_holder_entered = threading.Event()
        release_display_holder = threading.Event()
        touch_acquired = threading.Event()

        def display_holder():
            with dial_spi_bus.spi_transaction(dial_spi_bus.DISPLAY_BUS):
                display_holder_entered.set()
                release_display_holder.wait(timeout=5)

        t1 = threading.Thread(target=display_holder)
        t1.start()
        assert display_holder_entered.wait(timeout=5)

        try:
            # Main thread must be able to acquire the TOUCH_BUS lock
            # immediately, without waiting for the DISPLAY_BUS holder.
            acquired = dial_spi_bus.spi_transaction(dial_spi_bus.TOUCH_BUS).acquire(timeout=0.2)
            touch_acquired.set()
            assert acquired
        finally:
            if touch_acquired.is_set():
                dial_spi_bus.spi_transaction(dial_spi_bus.TOUCH_BUS).release()
            release_display_holder.set()
            t1.join(timeout=5)

        assert touch_acquired.is_set()
