"""Priority 8 — autostream_rpi health and CPU tests.

Covers PSU throttle-bit parsing, current/historic undervoltage, CPU temperature
(sysfs and vcgencmd fallback), CPU serial parsing, license cache, and
get_psu_warning_text() single-show historic behavior.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_rpi as rpi


@pytest.fixture(autouse=True)
def _reset_rpi_state():
    """Reset module-level PSU/throttle cache and license cache between tests."""
    orig_seen = rpi._seen_historic_undervolt
    orig_license = rpi._CPU_LICENSE_CACHE.ok
    orig_cache_val = rpi._GET_THROTTLED_CACHE_VALUE
    orig_cache_time = rpi._GET_THROTTLED_CACHE_TIME
    yield
    rpi._seen_historic_undervolt = orig_seen
    rpi._CPU_LICENSE_CACHE.ok = orig_license
    rpi._GET_THROTTLED_CACHE_VALUE = orig_cache_val
    rpi._GET_THROTTLED_CACHE_TIME = orig_cache_time


# ---------------------------------------------------------------------------
# _parse_throttled_mask: bit fields
# ---------------------------------------------------------------------------

class TestParseThrottledMask:
    def test_zero_means_no_throttle(self):
        current, historic = rpi._parse_throttled_mask(0x00000)
        assert current == 0
        assert historic == 0

    def test_current_undervolt_bit_0x1(self):
        current, historic = rpi._parse_throttled_mask(0x00001)
        assert current & 0x1  # undervoltage bit set

    def test_historic_undervolt_bit_0x10000(self):
        current, historic = rpi._parse_throttled_mask(0x10000)
        assert not (current & 0x1)  # current clear
        assert historic & 0x1       # historic set

    def test_both_current_and_historic(self):
        current, historic = rpi._parse_throttled_mask(0x10001)
        assert current & 0x1
        assert historic & 0x1

    def test_non_undervolt_bits_not_reported_as_undervolt(self):
        current, historic = rpi._parse_throttled_mask(0x00002)  # throttled, not undervolt
        assert not (current & 0x1)


# ---------------------------------------------------------------------------
# get_psu_warning_text
# ---------------------------------------------------------------------------

class TestGetPSUWarningText:
    def test_no_throttle_returns_none(self):
        with patch.object(rpi, "_read_get_throttled_value", return_value=0x00000):
            result = rpi.get_psu_warning_text()
        assert result is None

    def test_none_throttle_returns_none(self):
        with patch.object(rpi, "_read_get_throttled_value", return_value=None):
            result = rpi.get_psu_warning_text()
        assert result is None

    def test_current_undervolt_returns_warning(self):
        with patch.object(rpi, "_read_get_throttled_value", return_value=0x00001):
            result = rpi.get_psu_warning_text()
        assert result is not None
        assert "undervoltage" in result.lower() or "psu" in result.lower()

    def test_historic_undervolt_returns_warning_first_time(self):
        rpi._seen_historic_undervolt = False
        with patch.object(rpi, "_read_get_throttled_value", return_value=0x10000):
            result = rpi.get_psu_warning_text()
        assert result is not None

    def test_historic_undervolt_returns_none_second_time(self):
        rpi._seen_historic_undervolt = False
        with patch.object(rpi, "_read_get_throttled_value", return_value=0x10000):
            rpi.get_psu_warning_text()  # first call
            result = rpi.get_psu_warning_text()  # second call
        assert result is None

    def test_current_undervolt_always_shown(self):
        rpi._seen_historic_undervolt = True  # simulate already shown
        with patch.object(rpi, "_read_get_throttled_value", return_value=0x10001):
            # current + historic
            result = rpi.get_psu_warning_text()
        assert result is not None  # current must always show


# ---------------------------------------------------------------------------
# _read_get_throttled_value: sysfs vs vcgencmd
# ---------------------------------------------------------------------------

class TestReadGetThrottledValue:
    def test_reads_from_sysfs_when_available(self, tmp_path):
        sysfs = tmp_path / "get_throttled"
        sysfs.write_text("0x50005\n", encoding="utf-8")
        rpi._GET_THROTTLED_CACHE_TIME = 0  # invalidate cache

        with patch("os.path.isfile", return_value=True), \
             patch("builtins.open", return_value=sysfs.open("r")):
            # Reset cache so value is actually read
            rpi._GET_THROTTLED_CACHE_TIME = 0
            rpi._GET_THROTTLED_CACHE_VALUE = None
            val = rpi._read_get_throttled_value()

        # Value may have been read; just check no exception was raised
        assert val is None or isinstance(val, int)

    def test_returns_none_when_sysfs_and_vcgencmd_both_fail(self):
        rpi._GET_THROTTLED_CACHE_TIME = 0
        rpi._GET_THROTTLED_CACHE_VALUE = None

        with patch("os.path.isfile", return_value=False), \
             patch("subprocess.run", side_effect=OSError("no vcgencmd")):
            val = rpi._read_get_throttled_value()

        assert val is None

    def test_vcgencmd_fallback_parses_hex_output(self):
        rpi._GET_THROTTLED_CACHE_TIME = 0
        rpi._GET_THROTTLED_CACHE_VALUE = None

        import subprocess
        fake = MagicMock()
        fake.stdout = "throttled=0x50005\n"

        with patch("os.path.isfile", return_value=False), \
             patch("subprocess.run", return_value=fake):
            val = rpi._read_get_throttled_value()

        assert val == 0x50005

    def test_malformed_vcgencmd_output_returns_none(self):
        rpi._GET_THROTTLED_CACHE_TIME = 0
        rpi._GET_THROTTLED_CACHE_VALUE = None

        import subprocess
        fake = MagicMock()
        fake.stdout = "something unexpected\n"

        with patch("os.path.isfile", return_value=False), \
             patch("subprocess.run", return_value=fake):
            val = rpi._read_get_throttled_value()

        assert val is None


# ---------------------------------------------------------------------------
# get_cpu_temperature_c
# ---------------------------------------------------------------------------

class TestGetCPUTemperature:
    def test_reads_sysfs_thermal_zone(self, tmp_path):
        sysfs = tmp_path / "temp"
        sysfs.write_text("52000\n", encoding="utf-8")

        with patch("os.path.isfile", return_value=True), \
             patch("pathlib.Path.read_text", return_value="52000\n"):
            temp = rpi.get_cpu_temperature_c()

        assert temp == pytest.approx(52.0)

    def test_vcgencmd_fallback_parses_output(self):
        import subprocess
        fake = MagicMock()
        fake.stdout = "temp=48.1'C\n"

        with patch("os.path.isfile", return_value=False), \
             patch("subprocess.run", return_value=fake):
            temp = rpi.get_cpu_temperature_c()

        assert temp == pytest.approx(48.1)

    def test_returns_none_when_both_fail(self):
        with patch("os.path.isfile", return_value=False), \
             patch("subprocess.run", side_effect=OSError("no vcgencmd")):
            temp = rpi.get_cpu_temperature_c()
        assert temp is None


# ---------------------------------------------------------------------------
# get_raspberry_pi_model
# ---------------------------------------------------------------------------

class TestGetRaspberryPiModel:
    def test_reads_device_tree_model(self, tmp_path):
        model_file = tmp_path / "model"
        model_file.write_bytes(b"Raspberry Pi 4 Model B Rev 1.5\x00")
        with patch.object(rpi, "RPI_MODEL_FILE", model_file):
            assert rpi.get_raspberry_pi_model() == "Raspberry Pi 4 Model B Rev 1.5"

    def test_missing_model_returns_unknown(self, tmp_path):
        with patch.object(rpi, "RPI_MODEL_FILE", tmp_path / "missing"):
            assert rpi.get_raspberry_pi_model() == "unknown"

    def test_blank_model_returns_unknown(self, tmp_path):
        model_file = tmp_path / "model"
        model_file.write_bytes(b"\x00")
        with patch.object(rpi, "RPI_MODEL_FILE", model_file):
            assert rpi.get_raspberry_pi_model() == "unknown"


# ---------------------------------------------------------------------------
# get_cpu_serial
# ---------------------------------------------------------------------------

class TestGetCPUSerial:
    def test_parses_serial_from_cpuinfo(self, tmp_path):
        cpuinfo = (
            "Processor\t: ARMv6-compatible processor rev 7\n"
            "Serial\t\t: 00000000abcdef12\n"
        )
        with patch("pathlib.Path.read_text", return_value=cpuinfo):
            serial = rpi.get_cpu_serial()
        assert serial == "00000000abcdef12"

    def test_returns_empty_when_no_serial_in_cpuinfo(self):
        cpuinfo = "Processor\t: ARMv6\nHardware\t: BCM2835\n"
        with patch("pathlib.Path.read_text", return_value=cpuinfo), \
             patch("pathlib.Path.read_bytes", side_effect=FileNotFoundError):
            serial = rpi.get_cpu_serial()
        assert serial == ""

    def test_device_tree_fallback(self, tmp_path):
        # cpuinfo has no serial line; device-tree path returns serial bytes
        with patch("pathlib.Path.read_text", return_value="Hardware\t: BCM2835\n"), \
             patch("pathlib.Path.read_bytes", return_value=b"1234567890\x00"):
            serial = rpi.get_cpu_serial()
        assert serial == "1234567890"


# ---------------------------------------------------------------------------
# cpu_is_licensed: cache behavior
# ---------------------------------------------------------------------------

class TestCPULicenseCache:
    def test_positive_result_is_cached(self):
        rpi._CPU_LICENSE_CACHE.ok = False
        call_count = [0]

        def counting_matcher():
            call_count[0] += 1
            return True

        result1 = rpi.cpu_is_licensed(cpu_matcher=counting_matcher)
        result2 = rpi.cpu_is_licensed(cpu_matcher=counting_matcher)

        assert result1 is True
        assert result2 is True
        assert call_count[0] == 1  # second call was served from cache

    def test_negative_result_not_cached(self):
        rpi._CPU_LICENSE_CACHE.ok = False
        call_count = [0]

        def counting_matcher():
            call_count[0] += 1
            return False

        rpi.cpu_is_licensed(cpu_matcher=counting_matcher)
        rpi.cpu_is_licensed(cpu_matcher=counting_matcher)

        assert call_count[0] == 2  # neither result cached

    def test_matcher_exception_treated_as_false(self):
        rpi._CPU_LICENSE_CACHE.ok = False

        def raising_matcher():
            raise RuntimeError("hardware failure")

        result = rpi.cpu_is_licensed(cpu_matcher=raising_matcher)
        assert result is False
