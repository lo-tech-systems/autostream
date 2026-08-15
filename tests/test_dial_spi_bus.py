"""Tests for dial_spi_bus.py — the process-wide shared SPI0 bus owner.

Covers: no hardware imports at module level (a display-disabled dial must
still be able to import this module), get_bus() singleton behavior
(same object every call, exactly one construction even under a race,
a failed construction does not poison later calls), and that the exposed
transaction lock provides real mutual exclusion.
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
    tests/test_dial_display_adafruit.py's helper of the same name."""
    board = types.ModuleType("board")
    for name in ("GPIO9", "GPIO10", "GPIO11"):
        setattr(board, name, name)

    busio = types.ModuleType("busio")
    if spi_ctor is None:
        spi_ctor = MagicMock(name="SPI", return_value=MagicMock(name="SPI_instance"))
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

        first = dial_spi_bus.get_bus()
        second = dial_spi_bus.get_bus()
        third = dial_spi_bus.get_bus()

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
            results[i] = dial_spi_bus.get_bus()

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
            dial_spi_bus.get_bus()

        # A later, successful call must still work — the failed attempt was
        # not cached as success.
        bus = dial_spi_bus.get_bus()
        assert bus is not None
        assert attempts["n"] == 2


# ---------------------------------------------------------------------------
# Transaction lock
# ---------------------------------------------------------------------------

class TestSpiTransactionLock:
    def test_transaction_lock_provides_mutual_exclusion(self):
        holder_entered = threading.Event()
        release_holder = threading.Event()
        second_acquired = threading.Event()

        def holder():
            with dial_spi_bus.spi_transaction():
                holder_entered.set()
                release_holder.wait(timeout=5)

        def contender():
            holder_entered.wait(timeout=5)
            with dial_spi_bus.spi_transaction():
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
        cm = dial_spi_bus.spi_transaction()
        with cm:
            pass  # must not raise
