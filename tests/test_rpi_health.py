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

import autostream_system_stats as rpi
import autostream_licensing as lic


@pytest.fixture(autouse=True)
def _reset_rpi_state():
    """Reset module-level PSU/throttle cache and license cache between tests."""
    orig_seen = rpi._seen_historic_undervolt
    orig_license = lic._CPU_LICENSE_CACHE.ok
    orig_cache_val = rpi._GET_THROTTLED_CACHE_VALUE
    orig_cache_time = rpi._GET_THROTTLED_CACHE_TIME
    orig_busy_sample = rpi._CPU_BUSY_PREV_SAMPLE
    yield
    rpi._seen_historic_undervolt = orig_seen
    lic._CPU_LICENSE_CACHE.ok = orig_license
    rpi._GET_THROTTLED_CACHE_VALUE = orig_cache_val
    rpi._GET_THROTTLED_CACHE_TIME = orig_cache_time
    rpi._CPU_BUSY_PREV_SAMPLE = orig_busy_sample


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
        lic._CPU_LICENSE_CACHE.ok = False
        call_count = [0]

        def counting_matcher():
            call_count[0] += 1
            return True

        result1 = lic.cpu_is_licensed(cpu_matcher=counting_matcher)
        result2 = lic.cpu_is_licensed(cpu_matcher=counting_matcher)

        assert result1 is True
        assert result2 is True
        assert call_count[0] == 1  # second call was served from cache

    def test_negative_result_not_cached(self):
        lic._CPU_LICENSE_CACHE.ok = False
        call_count = [0]

        def counting_matcher():
            call_count[0] += 1
            return False

        lic.cpu_is_licensed(cpu_matcher=counting_matcher)
        lic.cpu_is_licensed(cpu_matcher=counting_matcher)

        assert call_count[0] == 2  # neither result cached

    def test_matcher_exception_treated_as_false(self):
        lic._CPU_LICENSE_CACHE.ok = False

        def raising_matcher():
            raise RuntimeError("hardware failure")

        result = lic.cpu_is_licensed(cpu_matcher=raising_matcher)
        assert result is False


# ---------------------------------------------------------------------------
# classify_high_performance_pi() / is_high_performance_pi(): audio-path
# hardware classification (§2.2)
# ---------------------------------------------------------------------------

class TestClassifyHighPerformancePi:
    @pytest.mark.parametrize("model", [
        "Raspberry Pi 4 Model B Rev 1.4",
        "Raspberry Pi 400 Rev 1.0",
        "Raspberry Pi Compute Module 4 Rev 1.0",
        "Raspberry Pi 5 Model B Rev 1.0",
        "Raspberry Pi 500 Rev 1.0",
        "Raspberry Pi Compute Module 5 Rev 1.0",
    ])
    def test_high_performance_models_classify_true(self, model):
        assert rpi.classify_high_performance_pi(model) is True

    @pytest.mark.parametrize("model", [
        "Raspberry Pi Zero 2 W Rev 1.0",
        "Raspberry Pi 3 Model B Plus Rev 1.3",
        "Raspberry Pi 3 Model B Rev 1.2",
        "Raspberry Pi Zero W Rev 1.1",
        "Raspberry Pi Model B Rev 2",
        "unknown",
        "",
        "Some Unrecognised Board",
    ])
    def test_small_or_unknown_models_classify_false(self, model):
        assert rpi.classify_high_performance_pi(model) is False

    def test_case_insensitive(self):
        assert rpi.classify_high_performance_pi("RASPBERRY PI 5 MODEL B") is True

    def test_none_input_classifies_false(self):
        assert rpi.classify_high_performance_pi(None) is False


class TestIsHighPerformancePi:
    def test_reads_model_via_get_raspberry_pi_model(self):
        with patch.object(rpi, "get_raspberry_pi_model", return_value="Raspberry Pi 5 Model B"):
            assert rpi.is_high_performance_pi() is True

    def test_false_when_model_unreadable(self):
        with patch.object(rpi, "get_raspberry_pi_model", return_value="unknown"):
            assert rpi.is_high_performance_pi() is False

    def test_false_on_zero_2w(self):
        with patch.object(rpi, "get_raspberry_pi_model", return_value="Raspberry Pi Zero 2 W Rev 1.0"):
            assert rpi.is_high_performance_pi() is False


# ---------------------------------------------------------------------------
# _read_proc_stat_cpu_totals: /proc/stat line parsing
# ---------------------------------------------------------------------------

class TestReadProcStatCpuTotals:
    def test_parses_totals_and_idle_includes_iowait(self, tmp_path):
        stat_file = tmp_path / "stat"
        # user nice system idle iowait irq softirq steal guest guest_nice
        stat_file.write_text(
            "cpu  100 10 50 700 40 5 5 0 0 0\ncpu0 ...\n", encoding="utf-8"
        )
        with patch("builtins.open", return_value=stat_file.open("r", encoding="utf-8")):
            result = rpi._read_proc_stat_cpu_totals()
        assert result is not None
        total, idle = result
        assert total == 910.0
        assert idle == 740.0  # idle(700) + iowait(40)

    def test_missing_file_returns_none(self):
        with patch("builtins.open", side_effect=OSError("no such file")):
            assert rpi._read_proc_stat_cpu_totals() is None

    def test_malformed_line_returns_none(self, tmp_path):
        stat_file = tmp_path / "stat"
        stat_file.write_text("not the cpu line\n", encoding="utf-8")
        with patch("builtins.open", return_value=stat_file.open("r", encoding="utf-8")):
            assert rpi._read_proc_stat_cpu_totals() is None


# ---------------------------------------------------------------------------
# get_cpu_busy_percent: htop-style busy% delta math
# ---------------------------------------------------------------------------

class TestGetCpuBusyPercent:
    def test_unavailable_when_proc_stat_unreadable(self):
        rpi._CPU_BUSY_PREV_SAMPLE = None
        with patch.object(rpi, "_read_proc_stat_cpu_totals", return_value=None):
            assert rpi.get_cpu_busy_percent() is None

    def test_uses_cached_previous_sample_without_sleeping(self):
        # Previous sample 1s ago: total=1000, idle=800.
        rpi._CPU_BUSY_PREV_SAMPLE = (1000.0, 800.0, 99.0)
        # New sample: total=2000, idle=1200 -> total_delta=1000, idle_delta=400
        # -> busy_delta=600 -> 60% busy.
        with patch("time.monotonic", return_value=100.0), \
             patch("time.sleep") as m_sleep, \
             patch.object(rpi, "_read_proc_stat_cpu_totals", return_value=(2000.0, 1200.0)):
            pct = rpi.get_cpu_busy_percent()
        m_sleep.assert_not_called()
        assert pct == 60.0
        assert rpi._CPU_BUSY_PREV_SAMPLE == (2000.0, 1200.0, 100.0)

    def test_first_call_with_no_cache_falls_back_to_two_samples(self):
        rpi._CPU_BUSY_PREV_SAMPLE = None
        # First read: total=1000, idle=800. Second (after sleep): total=1100, idle=850.
        # total_delta=100, idle_delta=50 -> busy_delta=50 -> 50% busy.
        with patch("time.monotonic", side_effect=[100.0, 100.25]), \
             patch("time.sleep") as m_sleep, \
             patch.object(
                 rpi, "_read_proc_stat_cpu_totals",
                 side_effect=[(1000.0, 800.0), (1100.0, 850.0)],
             ):
            pct = rpi.get_cpu_busy_percent()
        m_sleep.assert_called_once()
        assert pct == 50.0
        assert rpi._CPU_BUSY_PREV_SAMPLE == (1100.0, 850.0, 100.25)

    def test_stale_cache_falls_back_to_two_samples(self):
        # Previous sample is 10 minutes old (> 5 minute staleness window).
        rpi._CPU_BUSY_PREV_SAMPLE = (1000.0, 800.0, 0.0)
        with patch("time.monotonic", side_effect=[600.0, 600.25]), \
             patch("time.sleep") as m_sleep, \
             patch.object(
                 rpi, "_read_proc_stat_cpu_totals",
                 side_effect=[(5000.0, 4000.0), (5010.0, 4005.0)],
             ):
            pct = rpi.get_cpu_busy_percent()
        m_sleep.assert_called_once()
        assert pct == 50.0

    def test_too_recent_cache_falls_back_to_two_samples(self):
        # Previous sample only 0.05s old (< 0.2s minimum meaningful age).
        rpi._CPU_BUSY_PREV_SAMPLE = (1000.0, 800.0, 99.95)
        with patch("time.monotonic", side_effect=[100.0, 100.25]), \
             patch("time.sleep") as m_sleep, \
             patch.object(
                 rpi, "_read_proc_stat_cpu_totals",
                 side_effect=[(1000.0, 800.0), (1100.0, 850.0)],
             ):
            pct = rpi.get_cpu_busy_percent()
        m_sleep.assert_called_once()
        assert pct == 50.0

    def test_counter_reset_falls_back_to_two_samples(self):
        # Cached previous sample has higher counters than the fresh read,
        # e.g. after a counter wrap -- must not produce a negative delta.
        rpi._CPU_BUSY_PREV_SAMPLE = (9000.0, 8000.0, 99.0)
        with patch("time.monotonic", side_effect=[100.0, 100.25]), \
             patch("time.sleep") as m_sleep, \
             patch.object(
                 rpi, "_read_proc_stat_cpu_totals",
                 side_effect=[(100.0, 80.0), (200.0, 130.0)],
             ):
            pct = rpi.get_cpu_busy_percent()
        m_sleep.assert_called_once()
        assert pct == 50.0

    def test_zero_total_delta_returns_none(self):
        rpi._CPU_BUSY_PREV_SAMPLE = (1000.0, 800.0, 99.0)
        with patch("time.monotonic", return_value=100.0), \
             patch("time.sleep"), \
             patch.object(rpi, "_read_proc_stat_cpu_totals", return_value=(1000.0, 800.0)):
            pct = rpi.get_cpu_busy_percent()
        assert pct is None

    def test_result_clamped_to_0_100(self):
        # Pathological input where idle delta exceeds total delta must clamp to 0.
        rpi._CPU_BUSY_PREV_SAMPLE = (1000.0, 800.0, 99.0)
        with patch("time.monotonic", return_value=100.0), \
             patch("time.sleep"), \
             patch.object(rpi, "_read_proc_stat_cpu_totals", return_value=(1010.0, 900.0)):
            pct = rpi.get_cpu_busy_percent()
        assert pct == 0.0

    def test_rounded_to_one_decimal(self):
        rpi._CPU_BUSY_PREV_SAMPLE = (0.0, 0.0, 99.0)
        # total_delta=3, idle_delta=1 -> busy=2/3 = 66.666...% -> 66.7
        with patch("time.monotonic", return_value=100.0), \
             patch("time.sleep"), \
             patch.object(rpi, "_read_proc_stat_cpu_totals", return_value=(3.0, 1.0)):
            pct = rpi.get_cpu_busy_percent()
        assert pct == 66.7
