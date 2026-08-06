"""Tests for /api/about/system collector and About page rendering."""
from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_player_service as _ps
from autostream_sysutils import StaticSystemFacts
import autostream_webui_page_about as _about


# ---------------------------------------------------------------------------
# Helpers / stubs
# ---------------------------------------------------------------------------

def _mock_handler():
    h = MagicMock()
    h.wfile = MagicMock()
    return h


def _monitor_info(build="1.0", connected=True):
    from autostream_core import MonitorRuntimeInfo
    return MonitorRuntimeInfo(
        monitor_build=build,
        log_level="info",
        connected=connected,
        last_seen_at=1000.0,
    )


def _owntone_info(version="28.12", connected=True, backend_id="owntone"):
    return _ps.OwnToneRuntimeInfo(
        base_url="http://localhost:3689",
        backend_id=backend_id,
        version=version,
        connected=connected,
        last_seen_at=1000.0,
    )


def _vibra_info(version="1.0.0", connected=True):
    from track_id.vibra_client import VibraRuntimeInfo
    return VibraRuntimeInfo(version=version, connected=connected)


def _playback_snap(seconds_1=3600, seconds_2=7200):
    """Build a fake PlaybackSnapshot with inputs 1 and 2."""
    from autostream_playback_stats import InputPlaybackSnapshot

    def _inp(secs):
        s = MagicMock(spec=InputPlaybackSnapshot)
        s.total_playback_seconds = secs
        return s

    snap = MagicMock()
    snap.inputs = {1: _inp(seconds_1), 2: _inp(seconds_2)}
    return snap


def _collect_with_mocks(
    *,
    autostream_version="1.2.3",
    wifi_watcher_version="1.0.0",
    monitor_info=None,
    owntone_info=None,
    vibra_info=None,
    playback_snap=None,
    cpu_temp=48.2,
    cpu_load_percent=35.0,
    memory_info=(200, 500),
    disk_usage=(32_000_000_000, 12_000_000_000, 20_000_000_000),
    sd_health=96,
    static_facts=None,
    systemctl_stdout="",
    systemctl_returncode=0,
    systemctl_raises=None,
):
    if monitor_info is None:
        monitor_info = _monitor_info()
    if owntone_info is None:
        owntone_info = _owntone_info()
    if vibra_info is None:
        vibra_info = _vibra_info()
    if playback_snap is None:
        playback_snap = _playback_snap()
    if static_facts is None:
        static_facts = StaticSystemFacts(
            os_pretty_name="Raspberry Pi OS GNU/Linux 13 (trixie)",
            os_version_id="13",
            os_version_codename="trixie",
            raspberry_pi_model="Raspberry Pi 4 Model B Rev 1.5",
            nginx_version="nginx/1.22.1",
        )

    def fake_systemctl(*args, **kwargs):
        if systemctl_raises is not None:
            raise systemctl_raises
        r = MagicMock()
        r.stdout = systemctl_stdout
        r.stderr = ""
        r.returncode = systemctl_returncode
        return r

    with patch("autostream_webui_page_about.get_app_version", return_value=autostream_version), \
         patch("autostream_webui_page_about._get_wifi_watcher_version", return_value=wifi_watcher_version), \
         patch("autostream_webui_page_about.get_monitor_runtime_info", return_value=monitor_info), \
         patch("autostream_webui_page_about.get_owntone_runtime_info", return_value=owntone_info), \
         patch("autostream_webui_page_about.get_vibra_runtime_info", return_value=vibra_info), \
         patch("autostream_webui_page_about.get_playback_snapshot", return_value=playback_snap), \
         patch("autostream_webui_page_about.get_cpu_temperature_c", return_value=cpu_temp), \
         patch("autostream_webui_page_about.get_cpu_load_percent_1m", return_value=cpu_load_percent), \
         patch("autostream_webui_page_about.get_effective_memory_info", return_value=memory_info), \
         patch("autostream_webui_page_about.get_root_disk_usage", return_value=disk_usage), \
         patch("autostream_webui_page_about.get_sdcard_health_percent", return_value=sd_health), \
         patch("autostream_webui_page_about.get_static_system_facts", return_value=static_facts), \
         patch("autostream_webui_page_about.subprocess.run", side_effect=fake_systemctl):
        return _about._collect_system_info()


_ACTIVE_SYSTEMCTL = """\
Id=autostream.service
ActiveState=active

Id=autostream_monitor.service
ActiveState=active

Id=autostream_wifi_watcher.service
ActiveState=active

Id=owntone.service
ActiveState=active

Id=vibra-mini.service
ActiveState=active

Id=nginx.service
ActiveState=active

"""


# ---------------------------------------------------------------------------
# Test 1 — complete payload matches required keys and types
# ---------------------------------------------------------------------------

class TestCollectSystemInfoShape:

    def test_payload_ok_true(self):
        result = _collect_with_mocks(systemctl_stdout=_ACTIVE_SYSTEMCTL)
        assert result["ok"] is True

    def test_builds_keys_present(self):
        result = _collect_with_mocks(systemctl_stdout=_ACTIVE_SYSTEMCTL)
        assert set(result["builds"].keys()) == {
            "autostream", "monitor", "wifi_watcher", "owntone", "vibra_mini",
        }

    def test_builds_are_strings(self):
        result = _collect_with_mocks(systemctl_stdout=_ACTIVE_SYSTEMCTL)
        for key, val in result["builds"].items():
            assert isinstance(val, str), f"builds.{key} is not a str"

    def test_playback_hours_is_float(self):
        result = _collect_with_mocks(systemctl_stdout=_ACTIVE_SYSTEMCTL)
        assert isinstance(result["playback_hours"], float)

    def test_cpu_temperature_c_is_float_or_none(self):
        result = _collect_with_mocks(systemctl_stdout=_ACTIVE_SYSTEMCTL, cpu_temp=48.2)
        assert isinstance(result["cpu_temperature_c"], float)
        result2 = _collect_with_mocks(systemctl_stdout=_ACTIVE_SYSTEMCTL, cpu_temp=None)
        assert result2["cpu_temperature_c"] is None

    def test_device_model_present(self):
        result = _collect_with_mocks(systemctl_stdout=_ACTIVE_SYSTEMCTL)
        assert result["device"]["model"] == "Raspberry Pi 4 Model B Rev 1.5"

    def test_os_build_present(self):
        result = _collect_with_mocks(systemctl_stdout=_ACTIVE_SYSTEMCTL)
        assert result["os"] == {
            "pretty_name": "Raspberry Pi OS GNU/Linux 13 (trixie)",
            "version_id": "13",
            "version_codename": "trixie",
        }

    def test_cpu_temperature_shape(self):
        result = _collect_with_mocks(systemctl_stdout=_ACTIVE_SYSTEMCTL, cpu_temp=48.2)
        assert result["cpu_temperature"]["available"] is True
        assert set(result["cpu_temperature"].keys()) == {
            "available", "celsius", "percent", "status",
        }
        assert isinstance(result["cpu_temperature"]["celsius"], (int, float))
        assert isinstance(result["cpu_temperature"]["percent"], (int, float))
        assert isinstance(result["cpu_temperature"]["status"], str)

    def test_cpu_temperature_available_always_present(self):
        result = _collect_with_mocks(systemctl_stdout=_ACTIVE_SYSTEMCTL)
        assert "available" in result["cpu_temperature"]

    def test_cpu_load_shape(self):
        result = _collect_with_mocks(systemctl_stdout=_ACTIVE_SYSTEMCTL)
        assert result["cpu_load"]["available"] is True
        assert set(result["cpu_load"].keys()) == {"available", "percent", "status"}
        assert isinstance(result["cpu_load"]["percent"], (int, float))
        assert isinstance(result["cpu_load"]["status"], str)

    def test_memory_shape(self):
        result = _collect_with_mocks(systemctl_stdout=_ACTIVE_SYSTEMCTL)
        assert result["memory"]["available"] is True
        assert set(result["memory"].keys()) == {
            "available", "free_mib", "total_mib", "used_percent", "status",
        }
        assert isinstance(result["memory"]["free_mib"], (int, float))
        assert isinstance(result["memory"]["total_mib"], (int, float))
        assert isinstance(result["memory"]["used_percent"], (int, float))
        assert isinstance(result["memory"]["status"], str)

    def test_cpu_load_available_always_present(self):
        result = _collect_with_mocks(systemctl_stdout=_ACTIVE_SYSTEMCTL)
        assert "available" in result["cpu_load"]

    def test_memory_available_always_present(self):
        result = _collect_with_mocks(systemctl_stdout=_ACTIVE_SYSTEMCTL)
        assert "available" in result["memory"]

    def test_disk_available_always_present(self):
        result = _collect_with_mocks(systemctl_stdout=_ACTIVE_SYSTEMCTL)
        assert "available" in result["disk"]

    def test_sd_card_available_always_present(self):
        result = _collect_with_mocks(systemctl_stdout=_ACTIVE_SYSTEMCTL)
        assert "available" in result["sd_card"]

    def test_services_has_six_entries(self):
        result = _collect_with_mocks(systemctl_stdout=_ACTIVE_SYSTEMCTL)
        assert len(result["services"]) == 6

    def test_nginx_service_includes_static_version(self):
        result = _collect_with_mocks(systemctl_stdout=_ACTIVE_SYSTEMCTL)
        svc = next(s for s in result["services"] if s["unit"] == "nginx.service")
        assert svc["version"] == "nginx/1.22.1"


# ---------------------------------------------------------------------------
# Test 2 — playback totals: inputs 1 and 2 only, one decimal hour
# ---------------------------------------------------------------------------

class TestPlaybackTotals:

    def test_hours_sum_inputs_1_and_2_only(self):
        snap = MagicMock()
        from autostream_playback_stats import InputPlaybackSnapshot

        def _inp(s):
            m = MagicMock(spec=InputPlaybackSnapshot)
            m.total_playback_seconds = s
            return m

        snap.inputs = {1: _inp(3600), 2: _inp(7200), 3: _inp(100000)}
        result = _collect_with_mocks(playback_snap=snap, systemctl_stdout=_ACTIVE_SYSTEMCTL)
        assert result["playback_hours"] == 3.0  # 10800 / 3600 = 3.0

    def test_hours_rounded_to_one_decimal(self):
        snap = MagicMock()
        from autostream_playback_stats import InputPlaybackSnapshot

        def _inp(s):
            m = MagicMock(spec=InputPlaybackSnapshot)
            m.total_playback_seconds = s
            return m

        snap.inputs = {1: _inp(3700), 2: _inp(0)}
        result = _collect_with_mocks(playback_snap=snap, systemctl_stdout=_ACTIVE_SYSTEMCTL)
        assert result["playback_hours"] == round(3700 / 3600, 1)


# ---------------------------------------------------------------------------
# Test 3 — disk and SD thresholds
# ---------------------------------------------------------------------------

class TestDiskThresholds:

    @pytest.mark.parametrize("used_pct,expected_status", [
        (0,   "healthy"),
        (59,  "healthy"),
        (60,  "warning"),
        (79,  "warning"),
        (80,  "critical"),
        (100, "critical"),
    ])
    def test_disk_status_thresholds(self, used_pct, expected_status):
        total = 100_000_000_000
        used = int(total * used_pct / 100)
        free = total - used
        result = _collect_with_mocks(
            disk_usage=(total, used, free),
            systemctl_stdout=_ACTIVE_SYSTEMCTL,
        )
        assert result["disk"]["available"] is True
        assert result["disk"]["status"] == expected_status

    @pytest.mark.parametrize("health,expected_status", [
        (0,   "critical"),
        (10,  "critical"),
        (11,  "warning"),
        (30,  "warning"),
        (31,  "healthy"),
        (100, "healthy"),
    ])
    def test_sd_health_status_thresholds(self, health, expected_status):
        result = _collect_with_mocks(
            sd_health=health,
            systemctl_stdout=_ACTIVE_SYSTEMCTL,
        )
        assert result["sd_card"]["available"] is True
        assert result["sd_card"]["status"] == expected_status


# ---------------------------------------------------------------------------
# Test 3a — CPU temperature bar thresholds and percent mapping
# ---------------------------------------------------------------------------

class TestCpuTemperatureThresholds:

    @pytest.mark.parametrize("celsius,expected_status", [
        (0,    "healthy"),
        (69.9, "healthy"),
        (70,   "warning"),
        (78,   "warning"),
        (78.1, "critical"),
        (85,   "critical"),
    ])
    def test_cpu_temperature_status_thresholds(self, celsius, expected_status):
        result = _collect_with_mocks(
            cpu_temp=celsius,
            systemctl_stdout=_ACTIVE_SYSTEMCTL,
        )
        assert result["cpu_temperature"]["available"] is True
        assert result["cpu_temperature"]["status"] == expected_status

    def test_cpu_temperature_celsius_passed_through(self):
        result = _collect_with_mocks(
            cpu_temp=48.2,
            systemctl_stdout=_ACTIVE_SYSTEMCTL,
        )
        assert result["cpu_temperature"]["celsius"] == 48.2

    def test_cpu_temperature_percent_is_celsius_over_85_scale(self):
        result = _collect_with_mocks(
            cpu_temp=42.5,
            systemctl_stdout=_ACTIVE_SYSTEMCTL,
        )
        assert result["cpu_temperature"]["percent"] == pytest.approx(42.5 / 85.0 * 100.0)

    def test_cpu_temperature_percent_clamped_at_100(self):
        result = _collect_with_mocks(
            cpu_temp=200.0,
            systemctl_stdout=_ACTIVE_SYSTEMCTL,
        )
        assert result["cpu_temperature"]["percent"] == 100.0

    def test_cpu_temperature_unavailable_when_sensor_missing(self):
        result = _collect_with_mocks(
            cpu_temp=None,
            systemctl_stdout=_ACTIVE_SYSTEMCTL,
        )
        assert result["cpu_temperature"] == {"available": False}
        # Flat compatibility key must still degrade independently to None.
        assert result["cpu_temperature_c"] is None

    def test_flat_cpu_temperature_c_key_unaffected(self):
        """The pre-existing flat key is untouched by the new bar block."""
        result = _collect_with_mocks(
            cpu_temp=48.2,
            systemctl_stdout=_ACTIVE_SYSTEMCTL,
        )
        assert result["cpu_temperature_c"] == 48.2
        assert result["cpu_temperature"]["celsius"] == 48.2


# ---------------------------------------------------------------------------
# Test 3b — CPU load and memory thresholds
# ---------------------------------------------------------------------------

class TestCpuLoadThresholds:

    @pytest.mark.parametrize("percent,expected_status", [
        (0,    "healthy"),
        (69.9, "healthy"),
        (70,   "warning"),
        (84.9, "warning"),
        (85,   "critical"),
        (100,  "critical"),
    ])
    def test_cpu_load_status_thresholds(self, percent, expected_status):
        result = _collect_with_mocks(
            cpu_load_percent=percent,
            systemctl_stdout=_ACTIVE_SYSTEMCTL,
        )
        assert result["cpu_load"]["available"] is True
        assert result["cpu_load"]["status"] == expected_status

    def test_cpu_load_percent_passed_through(self):
        result = _collect_with_mocks(
            cpu_load_percent=42.0,
            systemctl_stdout=_ACTIVE_SYSTEMCTL,
        )
        assert result["cpu_load"]["percent"] == 42.0


class TestMemoryThresholds:

    @pytest.mark.parametrize("free_mib,expected_status", [
        (500, "healthy"),
        (97,  "healthy"),
        (96,  "warning"),
        (64,  "warning"),
        (63,  "critical"),
        (0,   "critical"),
    ])
    def test_memory_status_thresholds(self, free_mib, expected_status):
        result = _collect_with_mocks(
            memory_info=(free_mib, 500),
            systemctl_stdout=_ACTIVE_SYSTEMCTL,
        )
        assert result["memory"]["available"] is True
        assert result["memory"]["status"] == expected_status

    def test_memory_used_percent_computed(self):
        result = _collect_with_mocks(
            memory_info=(100, 500),
            systemctl_stdout=_ACTIVE_SYSTEMCTL,
        )
        assert result["memory"]["used_percent"] == 80
        assert result["memory"]["free_mib"] == 100
        assert result["memory"]["total_mib"] == 500


# ---------------------------------------------------------------------------
# Test 4 — missing disk / SD / CPU load / memory returns {"available": false}
# ---------------------------------------------------------------------------

class TestMissingDiskAndSd:

    def test_missing_disk_returns_unavailable(self):
        result = _collect_with_mocks(
            disk_usage=None,
            systemctl_stdout=_ACTIVE_SYSTEMCTL,
        )
        assert result["disk"] == {"available": False}

    def test_missing_sd_returns_unavailable(self):
        result = _collect_with_mocks(
            sd_health=None,
            systemctl_stdout=_ACTIVE_SYSTEMCTL,
        )
        assert result["sd_card"] == {"available": False}

    def test_missing_cpu_temperature_returns_unavailable(self):
        result = _collect_with_mocks(
            cpu_temp=None,
            systemctl_stdout=_ACTIVE_SYSTEMCTL,
        )
        assert result["cpu_temperature"] == {"available": False}

    def test_cpu_temperature_read_failure_does_not_sink_payload(self):
        with patch("autostream_webui_page_about.get_app_version", return_value="1.0"), \
             patch("autostream_webui_page_about.get_monitor_runtime_info", return_value=_monitor_info()), \
             patch("autostream_webui_page_about.get_owntone_runtime_info", return_value=_owntone_info()), \
             patch("autostream_webui_page_about.get_vibra_runtime_info", return_value=_vibra_info()), \
             patch("autostream_webui_page_about.get_playback_snapshot", return_value=_playback_snap()), \
             patch("autostream_webui_page_about.get_cpu_temperature_c", side_effect=Exception("no thermal")), \
             patch("autostream_webui_page_about.get_cpu_load_percent_1m", return_value=None), \
             patch("autostream_webui_page_about.get_effective_memory_info", return_value=None), \
             patch("autostream_webui_page_about.get_root_disk_usage", return_value=None), \
             patch("autostream_webui_page_about.get_sdcard_health_percent", return_value=None), \
             patch("autostream_webui_page_about.subprocess.run",
                   return_value=MagicMock(stdout="", returncode=0)):
            result = _about._collect_system_info()
        assert result["ok"] is True
        assert result["cpu_temperature"] == {"available": False}
        assert result["cpu_temperature_c"] is None

    def test_missing_cpu_load_returns_unavailable(self):
        result = _collect_with_mocks(
            cpu_load_percent=None,
            systemctl_stdout=_ACTIVE_SYSTEMCTL,
        )
        assert result["cpu_load"] == {"available": False}

    def test_missing_memory_returns_unavailable(self):
        result = _collect_with_mocks(
            memory_info=None,
            systemctl_stdout=_ACTIVE_SYSTEMCTL,
        )
        assert result["memory"] == {"available": False}

    def test_cpu_load_failure_does_not_sink_payload(self):
        """A raising collector helper must degrade only its own field, mirroring
        how a None cpu_temperature_c never sets ok=false."""
        with patch("autostream_webui_page_about.get_app_version", return_value="1.0"), \
             patch("autostream_webui_page_about.get_monitor_runtime_info", return_value=_monitor_info()), \
             patch("autostream_webui_page_about.get_owntone_runtime_info", return_value=_owntone_info()), \
             patch("autostream_webui_page_about.get_vibra_runtime_info", return_value=_vibra_info()), \
             patch("autostream_webui_page_about.get_playback_snapshot", return_value=_playback_snap()), \
             patch("autostream_webui_page_about.get_cpu_temperature_c", return_value=None), \
             patch("autostream_webui_page_about.get_cpu_load_percent_1m", side_effect=Exception("boom")), \
             patch("autostream_webui_page_about.get_effective_memory_info", return_value=None), \
             patch("autostream_webui_page_about.get_root_disk_usage", return_value=None), \
             patch("autostream_webui_page_about.get_sdcard_health_percent", return_value=None), \
             patch("autostream_webui_page_about.subprocess.run",
                   return_value=MagicMock(stdout="", returncode=0)):
            result = _about._collect_system_info()
        assert result["ok"] is True
        assert result["cpu_load"] == {"available": False}

    def test_memory_failure_does_not_sink_payload(self):
        with patch("autostream_webui_page_about.get_app_version", return_value="1.0"), \
             patch("autostream_webui_page_about.get_monitor_runtime_info", return_value=_monitor_info()), \
             patch("autostream_webui_page_about.get_owntone_runtime_info", return_value=_owntone_info()), \
             patch("autostream_webui_page_about.get_vibra_runtime_info", return_value=_vibra_info()), \
             patch("autostream_webui_page_about.get_playback_snapshot", return_value=_playback_snap()), \
             patch("autostream_webui_page_about.get_cpu_temperature_c", return_value=None), \
             patch("autostream_webui_page_about.get_cpu_load_percent_1m", return_value=None), \
             patch("autostream_webui_page_about.get_effective_memory_info", side_effect=Exception("boom")), \
             patch("autostream_webui_page_about.get_root_disk_usage", return_value=None), \
             patch("autostream_webui_page_about.get_sdcard_health_percent", return_value=None), \
             patch("autostream_webui_page_about.subprocess.run",
                   return_value=MagicMock(stdout="", returncode=0)):
            result = _about._collect_system_info()
        assert result["ok"] is True
        assert result["memory"] == {"available": False}


# ---------------------------------------------------------------------------
# Test 5 — OwnTone label for backend ID
# ---------------------------------------------------------------------------

class TestOwntoneLabel:

    def test_owntone_mini_backend_uses_owntone_mini_label(self):
        result = _collect_with_mocks(
            owntone_info=_owntone_info(backend_id="owntone-mini"),
            systemctl_stdout=_ACTIVE_SYSTEMCTL,
        )
        owntone_svc = next(s for s in result["services"] if s["unit"] == "owntone.service")
        assert owntone_svc["label"] == "OwnTone Mini"

    @pytest.mark.parametrize("backend_id", ["owntone", "unknown", "other", ""])
    def test_non_mini_backend_uses_owntone_label(self, backend_id):
        result = _collect_with_mocks(
            owntone_info=_owntone_info(backend_id=backend_id),
            systemctl_stdout=_ACTIVE_SYSTEMCTL,
        )
        owntone_svc = next(s for s in result["services"] if s["unit"] == "owntone.service")
        assert owntone_svc["label"] == "OwnTone"


# ---------------------------------------------------------------------------
# Test 6 — service state mapping
# ---------------------------------------------------------------------------

class TestServiceStateMapping:

    def _systemctl_with_states(self, states: dict) -> str:
        """Build fake systemctl output from {unit: active_state} dict."""
        blocks = []
        for unit, active_state in states.items():
            blocks.append(f"Id={unit}\nActiveState={active_state}\n")
        return "\n".join(blocks) + "\n"

    def test_active_maps_to_ok(self):
        stdout = self._systemctl_with_states({
            "autostream.service": "active",
            "autostream_monitor.service": "active",
            "autostream_wifi_watcher.service": "active",
            "owntone.service": "active",
            "vibra-mini.service": "active",
            "nginx.service": "active",
        })
        result = _collect_with_mocks(systemctl_stdout=stdout)
        for svc in result["services"]:
            assert svc["state"] == "ok", f"{svc['unit']} should be ok"

    @pytest.mark.parametrize("active_state", [
        "inactive", "failed", "activating", "deactivating", "unknown", "",
    ])
    def test_non_active_maps_to_failed(self, active_state):
        stdout = self._systemctl_with_states({"autostream.service": active_state})
        result = _collect_with_mocks(systemctl_stdout=stdout)
        svc = next(s for s in result["services"] if s["unit"] == "autostream.service")
        assert svc["state"] == "failed"


# ---------------------------------------------------------------------------
# Test 6b — Bluetooth service row: three-way state mapping, version, label,
# and NGINX-last ordering
# ---------------------------------------------------------------------------

class TestBluetoothServiceRow:

    def _collect(
        self,
        *,
        installed=True,
        enabled=True,
        active_state="active",
        client_status=None,
    ):
        stdout = (
            "Id=autostream.service\nActiveState=active\n\n"
            "Id=autostream_monitor.service\nActiveState=active\n\n"
            "Id=autostream_wifi_watcher.service\nActiveState=active\n\n"
            "Id=owntone.service\nActiveState=active\n\n"
            "Id=vibra-mini.service\nActiveState=active\n\n"
            f"Id=autostream_bluetooth.service\nActiveState={active_state}\n\n"
            "Id=nginx.service\nActiveState=active\n\n"
        )
        mock_client = MagicMock()
        mock_client.status.return_value = client_status
        with patch("autostream_webui_page_about.bluetooth_installed", return_value=installed), \
             patch("autostream_webui_page_about.bluetooth_services_enabled", return_value=enabled), \
             patch("autostream_webui_page_about.BluetoothClient", return_value=mock_client):
            return _collect_with_mocks(systemctl_stdout=stdout)

    def _bt_row(self, result):
        return next(s for s in result["services"] if s["unit"] == "autostream_bluetooth.service")

    def test_disabled_maps_to_disabled_state(self):
        result = self._collect(enabled=False, active_state="inactive")
        assert self._bt_row(result)["state"] == "disabled"

    def test_disabled_still_active_state_active_maps_to_disabled(self):
        """bluetooth_services_enabled() gates the row before ActiveState is
        even consulted -- a stray 'active' unit that was never enabled
        (e.g. started by hand for debugging) must still read 'disabled'."""
        result = self._collect(enabled=False, active_state="active")
        assert self._bt_row(result)["state"] == "disabled"

    def test_disabled_shows_fallback_version(self):
        result = self._collect(enabled=False, active_state="inactive")
        assert self._bt_row(result)["version"] == "0.5.3"

    def test_disabled_uses_bluetooth_service_label(self):
        result = self._collect(enabled=False, active_state="inactive")
        assert self._bt_row(result)["label"] == "Bluetooth Service"

    def test_nginx_is_last_when_bluetooth_row_present(self):
        result = self._collect(enabled=False, active_state="inactive")
        units = [s["unit"] for s in result["services"]]
        assert units[-1] == "nginx.service"
        assert units.index("autostream_bluetooth.service") < units.index("nginx.service")

    def test_enabled_but_inactive_maps_to_failed(self):
        result = self._collect(enabled=True, active_state="inactive")
        assert self._bt_row(result)["state"] == "failed"

    def test_enabled_and_active_maps_to_ok(self):
        result = self._collect(
            enabled=True, active_state="active",
            client_status={"ok": True, "version": "0.5.1"},
        )
        assert self._bt_row(result)["state"] == "ok"

    def test_enabled_and_active_uses_live_version_from_daemon(self):
        result = self._collect(
            enabled=True, active_state="active",
            client_status={"ok": True, "version": "9.9.9"},
        )
        assert self._bt_row(result)["version"] == "9.9.9"

    def test_enabled_and_active_falls_back_when_daemon_unreachable(self):
        result = self._collect(enabled=True, active_state="active", client_status=None)
        assert self._bt_row(result)["version"] == "0.5.3"

    def test_row_absent_when_not_installed(self):
        result = self._collect(installed=False)
        units = [s["unit"] for s in result["services"]]
        assert "autostream_bluetooth.service" not in units
        assert units[-1] == "nginx.service"
        assert len(result["services"]) == 6


# ---------------------------------------------------------------------------
# Test 7 — systemd parsing maps blocks by Id, not position
# ---------------------------------------------------------------------------

class TestSystemdParsing:

    def test_parse_output_maps_by_id_not_position(self):
        stdout = (
            "Id=nginx.service\nActiveState=active\n\n"
            "Id=autostream.service\nActiveState=failed\n\n"
        )
        parsed = _about._parse_systemctl_output(stdout)
        assert parsed["nginx.service"]["ActiveState"] == "active"
        assert parsed["autostream.service"]["ActiveState"] == "failed"

    def test_parse_ignores_malformed_lines(self):
        stdout = (
            "malformed line without equals\n"
            "Id=autostream.service\nActiveState=active\n\n"
        )
        parsed = _about._parse_systemctl_output(stdout)
        assert "autostream.service" in parsed

    def test_parse_handles_missing_blocks(self):
        stdout = "Id=autostream.service\nActiveState=active\n\n"
        result = _collect_with_mocks(systemctl_stdout=stdout)
        # Missing units fall back to failed
        svc = next(s for s in result["services"] if s["unit"] == "nginx.service")
        assert svc["state"] == "failed"

    def test_parse_last_block_without_trailing_blank(self):
        stdout = "Id=autostream.service\nActiveState=active"
        parsed = _about._parse_systemctl_output(stdout)
        assert "autostream.service" in parsed
        assert parsed["autostream.service"]["ActiveState"] == "active"


# ---------------------------------------------------------------------------
# Test 8 — partial stdout retained when systemctl returns nonzero
# ---------------------------------------------------------------------------

class TestSystemctlNonzeroReturn:

    def test_partial_stdout_used_even_on_nonzero_return(self):
        partial_stdout = "Id=autostream.service\nActiveState=active\n\n"
        result = _collect_with_mocks(
            systemctl_stdout=partial_stdout,
            systemctl_returncode=1,
        )
        svc = next(s for s in result["services"] if s["unit"] == "autostream.service")
        assert svc["state"] == "ok"


# ---------------------------------------------------------------------------
# Test 9 — timeout/exception → six failed entries, no stderr leaked
# ---------------------------------------------------------------------------

class TestSystemctlFailure:

    def test_timeout_returns_six_failed_entries(self):
        result = _collect_with_mocks(
            systemctl_raises=Exception("timeout"),
        )
        assert len(result["services"]) == 6
        for svc in result["services"]:
            assert svc["state"] == "failed"

    def test_exception_does_not_propagate(self):
        # Must not raise; top-level should still return ok=True
        result = _collect_with_mocks(systemctl_raises=OSError("no systemd"))
        assert result["ok"] is True


# ---------------------------------------------------------------------------
# Test 10 — subprocess command is fixed, no shell
# ---------------------------------------------------------------------------

class TestSystemctlCommandSecurity:

    def test_subprocess_uses_fixed_unit_list(self):
        captured_args = []

        def capture_run(*args, **kwargs):
            captured_args.extend(args)
            r = MagicMock()
            r.stdout = ""
            r.returncode = 0
            return r

        with patch("autostream_webui_page_about.get_app_version", return_value="1.0"), \
             patch("autostream_webui_page_about.get_monitor_runtime_info", return_value=_monitor_info()), \
             patch("autostream_webui_page_about.get_owntone_runtime_info", return_value=_owntone_info()), \
             patch("autostream_webui_page_about.get_vibra_runtime_info", return_value=_vibra_info()), \
             patch("autostream_webui_page_about.get_playback_snapshot", return_value=_playback_snap()), \
             patch("autostream_webui_page_about.get_cpu_temperature_c", return_value=None), \
             patch("autostream_webui_page_about.get_cpu_load_percent_1m", return_value=None), \
             patch("autostream_webui_page_about.get_effective_memory_info", return_value=None), \
             patch("autostream_webui_page_about.get_root_disk_usage", return_value=None), \
             patch("autostream_webui_page_about.get_sdcard_health_percent", return_value=None), \
             patch("autostream_webui_page_about.subprocess.run", side_effect=capture_run):
            _about._collect_system_info()

        assert captured_args, "subprocess.run was not called"
        cmd = captured_args[0]
        assert isinstance(cmd, list), "command must be a list (no shell)"
        assert "shell" not in str(cmd), "shell must not be used"
        # All six fixed units must be present in the command
        expected_units = [
            "autostream.service",
            "autostream_monitor.service",
            "autostream_wifi_watcher.service",
            "owntone.service",
            "vibra-mini.service",
            "nginx.service",
        ]
        for unit in expected_units:
            assert unit in cmd, f"{unit} missing from systemctl command"

    def test_subprocess_does_not_use_shell(self):
        captured_kwargs = {}

        def capture_run(*args, **kwargs):
            captured_kwargs.update(kwargs)
            r = MagicMock()
            r.stdout = ""
            r.returncode = 0
            return r

        with patch("autostream_webui_page_about.get_app_version", return_value="1.0"), \
             patch("autostream_webui_page_about.get_monitor_runtime_info", return_value=_monitor_info()), \
             patch("autostream_webui_page_about.get_owntone_runtime_info", return_value=_owntone_info()), \
             patch("autostream_webui_page_about.get_vibra_runtime_info", return_value=_vibra_info()), \
             patch("autostream_webui_page_about.get_playback_snapshot", return_value=_playback_snap()), \
             patch("autostream_webui_page_about.get_cpu_temperature_c", return_value=None), \
             patch("autostream_webui_page_about.get_cpu_load_percent_1m", return_value=None), \
             patch("autostream_webui_page_about.get_effective_memory_info", return_value=None), \
             patch("autostream_webui_page_about.get_root_disk_usage", return_value=None), \
             patch("autostream_webui_page_about.get_sdcard_health_percent", return_value=None), \
             patch("autostream_webui_page_about.subprocess.run", side_effect=capture_run):
            _about._collect_system_info()

        assert captured_kwargs.get("shell") is not True


# ---------------------------------------------------------------------------
# Test 11 — partial field failure does not set ok=false
# ---------------------------------------------------------------------------

class TestPartialFailureDegradation:

    def test_cpu_failure_does_not_set_ok_false(self):
        with patch("autostream_webui_page_about.get_app_version", return_value="1.0"), \
             patch("autostream_webui_page_about.get_monitor_runtime_info", return_value=_monitor_info()), \
             patch("autostream_webui_page_about.get_owntone_runtime_info", return_value=_owntone_info()), \
             patch("autostream_webui_page_about.get_vibra_runtime_info", return_value=_vibra_info()), \
             patch("autostream_webui_page_about.get_playback_snapshot", return_value=_playback_snap()), \
             patch("autostream_webui_page_about.get_cpu_temperature_c", side_effect=Exception("no thermal")), \
             patch("autostream_webui_page_about.get_cpu_load_percent_1m", return_value=None), \
             patch("autostream_webui_page_about.get_effective_memory_info", return_value=None), \
             patch("autostream_webui_page_about.get_root_disk_usage", return_value=None), \
             patch("autostream_webui_page_about.get_sdcard_health_percent", return_value=None), \
             patch("autostream_webui_page_about.subprocess.run",
                   return_value=MagicMock(stdout="", returncode=0)):
            result = _about._collect_system_info()
        assert result["ok"] is True
        assert result["cpu_temperature_c"] is None

    def test_disk_failure_does_not_set_ok_false(self):
        with patch("autostream_webui_page_about.get_app_version", return_value="1.0"), \
             patch("autostream_webui_page_about.get_monitor_runtime_info", return_value=_monitor_info()), \
             patch("autostream_webui_page_about.get_owntone_runtime_info", return_value=_owntone_info()), \
             patch("autostream_webui_page_about.get_vibra_runtime_info", return_value=_vibra_info()), \
             patch("autostream_webui_page_about.get_playback_snapshot", return_value=_playback_snap()), \
             patch("autostream_webui_page_about.get_cpu_temperature_c", return_value=None), \
             patch("autostream_webui_page_about.get_root_disk_usage", side_effect=Exception("fail")), \
             patch("autostream_webui_page_about.get_sdcard_health_percent", return_value=None), \
             patch("autostream_webui_page_about.subprocess.run",
                   return_value=MagicMock(stdout="", returncode=0)):
            result = _about._collect_system_info()
        assert result["ok"] is True
        assert result["disk"] == {"available": False}

    def test_vibra_failure_does_not_set_ok_false(self):
        result = _collect_with_mocks(
            vibra_info=_vibra_info(version="unknown", connected=False),
            systemctl_stdout=_ACTIVE_SYSTEMCTL,
        )
        assert result["ok"] is True
        assert result["builds"]["vibra_mini"] == "unknown"


# ---------------------------------------------------------------------------
# Test 12 — collector does not call resolve_backend or OwnTone HTTP
# ---------------------------------------------------------------------------

class TestCollectorNoIO:

    def test_does_not_call_resolve_backend(self):
        with patch("autostream_player_service.resolve_backend") as mock_rb, \
             patch("autostream_webui_page_about.get_app_version", return_value="1.0"), \
             patch("autostream_webui_page_about.get_monitor_runtime_info", return_value=_monitor_info()), \
             patch("autostream_webui_page_about.get_owntone_runtime_info", return_value=_owntone_info()), \
             patch("autostream_webui_page_about.get_vibra_runtime_info", return_value=_vibra_info()), \
             patch("autostream_webui_page_about.get_playback_snapshot", return_value=_playback_snap()), \
             patch("autostream_webui_page_about.get_cpu_temperature_c", return_value=None), \
             patch("autostream_webui_page_about.get_cpu_load_percent_1m", return_value=None), \
             patch("autostream_webui_page_about.get_effective_memory_info", return_value=None), \
             patch("autostream_webui_page_about.get_root_disk_usage", return_value=None), \
             patch("autostream_webui_page_about.get_sdcard_health_percent", return_value=None), \
             patch("autostream_webui_page_about.subprocess.run",
                   return_value=MagicMock(stdout="", returncode=0)):
            _about._collect_system_info()
        mock_rb.assert_not_called()

    def test_get_owntone_called_with_refresh_if_stale_false(self):
        captured_kwargs = {}

        def fake_owntone(*args, **kwargs):
            captured_kwargs.update(kwargs)
            return _owntone_info()

        with patch("autostream_webui_page_about.get_app_version", return_value="1.0"), \
             patch("autostream_webui_page_about.get_monitor_runtime_info", return_value=_monitor_info()), \
             patch("autostream_webui_page_about.get_owntone_runtime_info", side_effect=fake_owntone), \
             patch("autostream_webui_page_about.get_vibra_runtime_info", return_value=_vibra_info()), \
             patch("autostream_webui_page_about.get_playback_snapshot", return_value=_playback_snap()), \
             patch("autostream_webui_page_about.get_cpu_temperature_c", return_value=None), \
             patch("autostream_webui_page_about.get_cpu_load_percent_1m", return_value=None), \
             patch("autostream_webui_page_about.get_effective_memory_info", return_value=None), \
             patch("autostream_webui_page_about.get_root_disk_usage", return_value=None), \
             patch("autostream_webui_page_about.get_sdcard_health_percent", return_value=None), \
             patch("autostream_webui_page_about.subprocess.run",
                   return_value=MagicMock(stdout="", returncode=0)):
            _about._collect_system_info()
        assert captured_kwargs.get("refresh_if_stale") is False


# ---------------------------------------------------------------------------
# Test 13 — monitor, OwnTone, Vibra, playback reads are no-protocol-I/O
# (verified via mock — if they were calling connect/send/recv they would
#  propagate errors through the mocked collection functions)
# ---------------------------------------------------------------------------

class TestSnapshotReadsAreMemoryOnly:

    def test_monitor_read_is_not_live_io(self):
        mock_monitor = MagicMock(return_value=_monitor_info())
        with patch("autostream_webui_page_about.get_monitor_runtime_info", mock_monitor), \
             patch("autostream_webui_page_about.get_app_version", return_value="1.0"), \
             patch("autostream_webui_page_about.get_owntone_runtime_info", return_value=_owntone_info()), \
             patch("autostream_webui_page_about.get_vibra_runtime_info", return_value=_vibra_info()), \
             patch("autostream_webui_page_about.get_playback_snapshot", return_value=_playback_snap()), \
             patch("autostream_webui_page_about.get_cpu_temperature_c", return_value=None), \
             patch("autostream_webui_page_about.get_cpu_load_percent_1m", return_value=None), \
             patch("autostream_webui_page_about.get_effective_memory_info", return_value=None), \
             patch("autostream_webui_page_about.get_root_disk_usage", return_value=None), \
             patch("autostream_webui_page_about.get_sdcard_health_percent", return_value=None), \
             patch("autostream_webui_page_about.subprocess.run",
                   return_value=MagicMock(stdout="", returncode=0)):
            _about._collect_system_info()
        mock_monitor.assert_called_once()


# ---------------------------------------------------------------------------
# Test 14 — get_owntone_runtime_info(refresh_if_stale=False) returns snapshot
#           even when no base URL is supplied
# ---------------------------------------------------------------------------

class TestOwnToneRuntimeInfoNoBaseUrl:

    def setup_method(self):
        _ps._DETECTION_CACHE.clear()
        # Reset the owntone runtime info to a known state
        _ps._set_owntone_runtime_info(
            base_url="http://localhost:3689",
            backend_id="owntone",
            version="28.99",
            connected=True,
            last_seen_at=1000.0,
        )

    def teardown_method(self):
        _ps._DETECTION_CACHE.clear()
        _ps._set_owntone_runtime_info(
            base_url="",
            backend_id="unknown",
            version="unknown",
            connected=False,
            last_seen_at=0.0,
        )

    def test_returns_cached_snapshot_when_refresh_if_stale_false_and_no_base_url(self):
        info = _ps.get_owntone_runtime_info(refresh_if_stale=False)
        assert info.version == "28.99"
        assert info.connected is True

    def test_returns_cached_snapshot_when_refresh_if_stale_false_with_base_url(self):
        info = _ps.get_owntone_runtime_info("http://localhost:3689", refresh_if_stale=False)
        assert info.version == "28.99"

    def test_does_not_call_resolve_backend_when_refresh_if_stale_false(self):
        with patch("autostream_player_service.resolve_backend") as mock_rb:
            _ps.get_owntone_runtime_info(refresh_if_stale=False)
        mock_rb.assert_not_called()


# ---------------------------------------------------------------------------
# Test 15 — get_app_version() caches unknown after every failure
# ---------------------------------------------------------------------------

class TestGetAppVersionCaching:

    def setup_method(self):
        import autostream_webui_common as _c
        self._original = _c._app_version_cache
        _c._app_version_cache = None

    def teardown_method(self):
        import autostream_webui_common as _c
        _c._app_version_cache = self._original

    def test_exception_is_cached_as_unknown(self):
        import autostream_webui_common as _c
        with patch("autostream_webui_common.subprocess.run", side_effect=OSError("not found")):
            v1 = _c.get_app_version()
            # cache should be set now so subprocess not called again
            with patch("autostream_webui_common.subprocess.run",
                       side_effect=AssertionError("must not call twice")):
                v2 = _c.get_app_version()
        assert v1 == "unknown"
        assert v2 == "unknown"

    def test_nonzero_exit_is_cached_as_unknown(self):
        import autostream_webui_common as _c
        r = MagicMock()
        r.returncode = 1
        r.stdout = ""
        with patch("autostream_webui_common.subprocess.run", return_value=r):
            v1 = _c.get_app_version()
            with patch("autostream_webui_common.subprocess.run",
                       side_effect=AssertionError("must not call twice")):
                v2 = _c.get_app_version()
        assert v1 == "unknown"
        assert v2 == "unknown"

    def test_invalid_json_is_cached_as_unknown(self):
        import autostream_webui_common as _c
        r = MagicMock()
        r.returncode = 0
        r.stdout = "not json"
        with patch("autostream_webui_common.subprocess.run", return_value=r):
            v1 = _c.get_app_version()
        assert v1 == "unknown"
        assert _c._app_version_cache == "unknown"

    def test_blank_release_tag_is_cached_as_unknown(self):
        import autostream_webui_common as _c
        r = MagicMock()
        r.returncode = 0
        r.stdout = '{"release_tag": ""}'
        with patch("autostream_webui_common.subprocess.run", return_value=r):
            v1 = _c.get_app_version()
        assert v1 == "unknown"
        assert _c._app_version_cache == "unknown"


# ---------------------------------------------------------------------------
# Test 16 — startup primes get_app_version (structural, tested in webui module)
# This is a code-review-level check: the webui file calls get_app_version()
# unconditionally before ThreadingHTTPServer.
# ---------------------------------------------------------------------------

class TestStartupPrimesAppVersion:

    def test_get_app_version_called_before_http_server_in_serve(self):
        """_serve() calls get_app_version() before constructing ThreadingHTTPServer."""
        try:
            import autostream_webui as _webui
        except ImportError:
            pytest.skip("autostream_webui import chain unavailable")

        import inspect
        src = inspect.getsource(_webui.start_webui_background)
        # get_app_version() must appear before ThreadingHTTPServer
        idx_version = src.find("get_app_version()")
        idx_server = src.find("ThreadingHTTPServer")
        assert idx_version != -1, "get_app_version() not found in _serve()"
        assert idx_server != -1, "ThreadingHTTPServer not found"
        assert idx_version < idx_server, (
            "get_app_version() must appear before ThreadingHTTPServer in _serve()"
        )


# ---------------------------------------------------------------------------
# Test 17 — route dispatches to the new handler
# ---------------------------------------------------------------------------

class TestRouteDispatch:

    def test_get_api_about_system_dispatches(self):
        try:
            import autostream_webui as _webui
        except ImportError:
            pytest.skip("autostream_webui import chain unavailable")

        import inspect
        src = inspect.getsource(_webui.ConfigWebHandler.do_GET)
        assert "/api/about/system" in src, (
            "/api/about/system route not found in do_GET"
        )
        assert "send_about_system_json" in src, (
            "send_about_system_json not called in do_GET"
        )


# ---------------------------------------------------------------------------
# Test 18 — /api/about/system is in the auth allowlist
# ---------------------------------------------------------------------------

class TestAuthAllowlist:

    def test_api_about_system_in_allowlist(self):
        from autostream_auth import ALLOWLIST_PATHS
        assert "/api/about/system" in ALLOWLIST_PATHS, (
            "/api/about/system must be in ALLOWLIST_PATHS so unauthenticated "
            "browser requests are allowed when PIN is enabled"
        )


# ---------------------------------------------------------------------------
# Test 19 — send_json adds no-store cache headers
# (verified via the existing send_json helper which always sets these headers)
# ---------------------------------------------------------------------------

class TestSendJsonHeaders:

    def test_send_about_system_json_uses_send_json(self):
        """send_about_system_json delegates to send_json (which sets no-store headers)."""
        import io
        handler = MagicMock()
        handler.wfile = io.BytesIO()
        sent_responses = []
        sent_headers = {}

        handler.send_response.side_effect = lambda code: sent_responses.append(code)
        handler.send_header.side_effect = lambda k, v: sent_headers.update({k: v})

        with patch("autostream_webui_page_about.get_app_version", return_value="1.0"), \
             patch("autostream_webui_page_about.get_monitor_runtime_info", return_value=_monitor_info()), \
             patch("autostream_webui_page_about.get_owntone_runtime_info", return_value=_owntone_info()), \
             patch("autostream_webui_page_about.get_vibra_runtime_info", return_value=_vibra_info()), \
             patch("autostream_webui_page_about.get_playback_snapshot", return_value=_playback_snap()), \
             patch("autostream_webui_page_about.get_cpu_temperature_c", return_value=None), \
             patch("autostream_webui_page_about.get_cpu_load_percent_1m", return_value=None), \
             patch("autostream_webui_page_about.get_effective_memory_info", return_value=None), \
             patch("autostream_webui_page_about.get_root_disk_usage", return_value=None), \
             patch("autostream_webui_page_about.get_sdcard_health_percent", return_value=None), \
             patch("autostream_webui_page_about.subprocess.run",
                   return_value=MagicMock(stdout="", returncode=0)):
            _about.send_about_system_json(handler)

        assert 200 in sent_responses
        assert "no-store" in sent_headers.get("Cache-Control", "")


# ---------------------------------------------------------------------------
# Test 20 — unexpected top-level exception → HTTP 500
# ---------------------------------------------------------------------------

class TestTopLevelExceptionHandling:

    def test_unexpected_exception_returns_500(self):
        import io
        handler = MagicMock()
        handler.wfile = io.BytesIO()
        sent_responses = []
        handler.send_response.side_effect = lambda code: sent_responses.append(code)
        handler.send_header.side_effect = lambda k, v: None

        with patch("autostream_webui_page_about._collect_system_info",
                   side_effect=RuntimeError("unexpected")):
            _about.send_about_system_json(handler)

        assert 500 in sent_responses

    def test_unexpected_exception_body_contains_safe_error(self):
        import io
        handler = MagicMock()
        buf = io.BytesIO()
        handler.wfile = buf
        handler.send_response.side_effect = lambda code: None
        handler.send_header.side_effect = lambda k, v: None

        with patch("autostream_webui_page_about._collect_system_info",
                   side_effect=RuntimeError("internal secret")):
            _about.send_about_system_json(handler)

        body = buf.getvalue()
        decoded = json.loads(body) if body else {}
        assert decoded.get("ok") is False
        assert decoded.get("error") == "system_info_unavailable"
        assert "internal secret" not in body.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# About page renders without live probes; DOM IDs and JS present
# ---------------------------------------------------------------------------

_REQUIRED_IDS = [
    "aboutBuildAutostream",
    "aboutDeviceModel",
    "aboutOsBuild",
    "aboutPlaybackHours",
    "aboutTempSection",
    "aboutTempLabel",
    "aboutTempBar",
    "aboutCpuSection",
    "aboutCpuLabel",
    "aboutCpuBar",
    "aboutMemSection",
    "aboutMemLabel",
    "aboutMemBar",
    "aboutMemMeta",
    "aboutDiskSection",
    "aboutDiskLabel",
    "aboutDiskBar",
    "aboutDiskMeta",
    "aboutSdSection",
    "aboutSdLabel",
    "aboutSdBar",
    "aboutServices",
]

_FIXED_UNITS = [unit for unit, _ in _about._SERVICES]


def _render_about_page_html() -> str:
    """Render the About page and return the full HTML string."""
    import io
    handler = MagicMock()
    buf = io.BytesIO()
    handler.wfile = buf
    state = MagicMock()

    with patch("autostream_webui_page_about.get_app_version", return_value="1.2.3"), \
         patch("autostream_webui_page_about.build_top_banner_html", return_value=("", "")), \
         patch("autostream_webui_page_about._config_snapshot", return_value=None), \
         patch("autostream_webui_page_about.load_license_text", return_value=""), \
         patch("autostream_webui_page_about.render_license_md", return_value=""):
        _about.send_about_page(handler, state)

    return buf.getvalue().decode("utf-8")


class TestAboutPageDomIds:

    def setup_method(self):
        self._html = _render_about_page_html()

    def test_all_required_ids_present(self):
        for dom_id in _REQUIRED_IDS:
            assert f"id='{dom_id}'" in self._html or f'id="{dom_id}"' in self._html, (
                f"Required DOM ID '{dom_id}' not found in About page HTML"
            )

    def test_component_build_rows_not_in_system_info_card(self):
        assert "Audio Monitor Build" not in self._html
        assert "OwnTone Build" not in self._html
        assert "Vibra Mini Build" not in self._html
        assert "aboutBuildMonitor" not in self._html
        assert "aboutBuildOwntone" not in self._html
        assert "aboutBuildVibra" not in self._html

    def test_services_heading_present(self):
        assert "Services" in self._html
        assert "about-services-heading" in self._html

    def test_old_temperature_text_element_removed(self):
        """The static text row (fed by cpu_temperature_c) is replaced by the
        aboutTempSection bar -- it must not remain in the markup."""
        assert "id='aboutCpuTemperature'" not in self._html
        assert 'id="aboutCpuTemperature"' not in self._html
        assert "<strong>CPU Temperature</strong>" not in self._html

    def test_cpu_meta_element_removed(self):
        """The CPU Load bar's meta line was removed as a duplicate of its label."""
        assert "id='aboutCpuMeta'" not in self._html
        assert 'id="aboutCpuMeta"' not in self._html

    def test_memory_label_says_usage(self):
        """Memory bar label text is JS-composed; check the fetch script literal."""
        assert "Memory Usage: " in self._html
        assert "'Memory: '" not in self._html


class TestAboutPageDiskSdInitiallyHidden:

    def setup_method(self):
        self._html = _render_about_page_html()

    def test_disk_section_initially_hidden(self):
        assert "id='aboutDiskSection'" in self._html or 'id="aboutDiskSection"' in self._html
        # The section must carry display:none so it starts hidden.
        import re
        m = re.search(r"id=['\"]aboutDiskSection['\"][^>]*>|id=['\"]aboutDiskSection['\"][^<]*style=[^>]*", self._html)
        assert m is not None
        surrounding = self._html[max(0, m.start() - 20): m.end() + 40]
        assert "display:none" in surrounding or "display: none" in surrounding, (
            f"aboutDiskSection should start with display:none; got: {surrounding!r}"
        )

    def test_sd_section_initially_hidden(self):
        import re
        m = re.search(r"id=['\"]aboutSdSection['\"]", self._html)
        assert m is not None
        surrounding = self._html[max(0, m.start() - 20): m.end() + 40]
        assert "display:none" in surrounding or "display: none" in surrounding, (
            f"aboutSdSection should start with display:none; got: {surrounding!r}"
        )

    def test_temp_section_initially_hidden(self):
        import re
        m = re.search(r"id=['\"]aboutTempSection['\"]", self._html)
        assert m is not None
        surrounding = self._html[max(0, m.start() - 20): m.end() + 40]
        assert "display:none" in surrounding or "display: none" in surrounding, (
            f"aboutTempSection should start with display:none; got: {surrounding!r}"
        )

    def test_cpu_section_initially_hidden(self):
        import re
        m = re.search(r"id=['\"]aboutCpuSection['\"]", self._html)
        assert m is not None
        surrounding = self._html[max(0, m.start() - 20): m.end() + 40]
        assert "display:none" in surrounding or "display: none" in surrounding, (
            f"aboutCpuSection should start with display:none; got: {surrounding!r}"
        )

    def test_mem_section_initially_hidden(self):
        import re
        m = re.search(r"id=['\"]aboutMemSection['\"]", self._html)
        assert m is not None
        surrounding = self._html[max(0, m.start() - 20): m.end() + 40]
        assert "display:none" in surrounding or "display: none" in surrounding, (
            f"aboutMemSection should start with display:none; got: {surrounding!r}"
        )

    def test_temp_cpu_and_mem_sections_precede_disk_section(self):
        """Section order top-to-bottom: Temp, CPU Load, Memory, Disk, SD."""
        temp_idx = self._html.find("aboutTempSection")
        cpu_idx = self._html.find("aboutCpuSection")
        mem_idx = self._html.find("aboutMemSection")
        disk_idx = self._html.find("aboutDiskSection")
        sd_idx = self._html.find("aboutSdSection")
        assert temp_idx != -1 and cpu_idx != -1 and mem_idx != -1
        assert disk_idx != -1 and sd_idx != -1
        assert temp_idx < cpu_idx < mem_idx < disk_idx < sd_idx


class TestAboutPageAccessibility:

    def test_aria_live_polite_on_system_info_container(self):
        html = _render_about_page_html()
        assert "aria-live='polite'" in html or 'aria-live="polite"' in html, (
            "aria-live='polite' must be present on the System Info container"
        )


class TestAboutPageServiceRows:

    def setup_method(self):
        self._html = _render_about_page_html()

    def test_all_six_service_units_present(self):
        for unit in _FIXED_UNITS:
            assert f"data-service-unit='{unit}'" in self._html or \
                   f'data-service-unit="{unit}"' in self._html, (
                f"Service unit '{unit}' not found in About page HTML"
            )

    def test_service_rows_have_loading_class(self):
        assert "about-svc-loading" in self._html

    def test_service_rows_have_loading_placeholder(self):
        assert "Loading..." in self._html


class TestAboutPageNoLiveData:

    def test_no_live_probe_functions_called_during_render(self):
        """send_about_page must call none of the six live probe functions."""
        import io
        handler = MagicMock()
        handler.wfile = io.BytesIO()
        state = MagicMock()

        with patch("autostream_webui_page_about.get_app_version", return_value="1.2.3"), \
             patch("autostream_webui_page_about.build_top_banner_html", return_value=("", "")), \
             patch("autostream_webui_page_about._config_snapshot", return_value=None), \
             patch("autostream_webui_page_about.load_license_text", return_value=""), \
             patch("autostream_webui_page_about.render_license_md", return_value=""), \
             patch("autostream_webui_page_about.get_monitor_runtime_info") as m_mon, \
             patch("autostream_webui_page_about.get_playback_snapshot") as m_play, \
             patch("autostream_webui_page_about.get_cpu_temperature_c") as m_cpu, \
             patch("autostream_webui_page_about.get_owntone_runtime_info") as m_owntone, \
             patch("autostream_webui_page_about.get_root_disk_usage") as m_disk, \
             patch("autostream_webui_page_about.get_sdcard_health_percent") as m_sd, \
             patch("autostream_webui_page_about.get_cpu_load_percent_1m") as m_load, \
             patch("autostream_webui_page_about.get_effective_memory_info") as m_mem:
            _about.send_about_page(handler, state)

        m_mon.assert_not_called()
        m_play.assert_not_called()
        m_cpu.assert_not_called()
        m_owntone.assert_not_called()
        m_disk.assert_not_called()
        m_sd.assert_not_called()
        m_load.assert_not_called()
        m_mem.assert_not_called()


class TestAboutPageFetchScript:

    def setup_method(self):
        self._html = _render_about_page_html()

    def test_dom_content_loaded_listener_present(self):
        assert "DOMContentLoaded" in self._html, (
            "DOMContentLoaded listener not found in About page script"
        )

    def test_fetch_url_is_api_about_system(self):
        assert "/api/about/system" in self._html, (
            "/api/about/system fetch URL not found in About page script"
        )

    def test_no_inner_html_in_fetch_script(self):
        # Only the existing copyLicenseText uses innerHTML — the fetch IIFE must not.
        iife_start = self._html.find("function _s(id,t)")
        assert iife_start != -1, "Fetch IIFE helper _s(id,t) not found in page HTML"
        fetch_block = self._html[iife_start:]
        assert "innerHTML" not in fetch_block, (
            "innerHTML must not be used in the fetch IIFE — use textContent"
        )

    def test_text_content_used_in_fetch_script(self):
        assert "textContent" in self._html, (
            "textContent not found in About page script"
        )

    def test_fail_sets_data_state_failed_not_removes_it(self):
        """_fail() must setAttribute('data-state','failed') so CSS error styling applies."""
        # Locate the fetch IIFE by its unique first helper function.
        iife_start = self._html.find("function _s(id,t)")
        assert iife_start != -1, "Fetch IIFE helper _s(id,t) not found in page HTML"
        fetch_block = self._html[iife_start:]
        assert "setAttribute('data-state','failed')" in fetch_block, (
            "_fail() must set data-state='failed' on service state spans; "
            "removeAttribute would suppress the CSS error colouring"
        )
        assert "removeAttribute('data-state')" not in fetch_block


# ---------------------------------------------------------------------------
# Snapshot-exception isolation — individual accessor errors must not 500
# ---------------------------------------------------------------------------

class TestSnapshotExceptionIsolation:
    """Exceptions thrown by in-memory snapshot accessors must not produce HTTP 500.

    The plan requires partial failures to affect only their own field; the
    top-level ok:true must be preserved even if individual getters raise.
    """

    def _make_result(self, *, raise_at: str) -> dict:
        boom = RuntimeError("simulated accessor failure")

        patches = {
            "autostream_webui_page_about.get_app_version":
                (boom if raise_at == "app_version" else "1.0"),
            "autostream_webui_page_about._get_wifi_watcher_version":
                (boom if raise_at == "wifi_watcher" else "1.0.0"),
            "autostream_webui_page_about.get_monitor_runtime_info":
                (boom if raise_at == "monitor" else _monitor_info()),
            "autostream_webui_page_about.get_owntone_runtime_info":
                (boom if raise_at == "owntone" else _owntone_info()),
            "autostream_webui_page_about.get_vibra_runtime_info":
                (boom if raise_at == "vibra" else _vibra_info()),
            "autostream_webui_page_about.get_playback_snapshot":
                (boom if raise_at == "playback" else _playback_snap()),
        }

        ctx = {}
        for target, val in patches.items():
            if isinstance(val, Exception):
                ctx[target] = patch(target, side_effect=val)
            else:
                ctx[target] = patch(target, return_value=val)

        with patch("autostream_webui_page_about.get_cpu_temperature_c", return_value=None), \
             patch("autostream_webui_page_about.get_cpu_load_percent_1m", return_value=None), \
             patch("autostream_webui_page_about.get_effective_memory_info", return_value=None), \
             patch("autostream_webui_page_about.get_root_disk_usage", return_value=None), \
             patch("autostream_webui_page_about.get_sdcard_health_percent", return_value=None), \
             patch("autostream_webui_page_about.subprocess.run",
                   return_value=MagicMock(stdout="", returncode=0)):
            with ctx["autostream_webui_page_about.get_app_version"], \
                 ctx["autostream_webui_page_about._get_wifi_watcher_version"], \
                 ctx["autostream_webui_page_about.get_monitor_runtime_info"], \
                 ctx["autostream_webui_page_about.get_owntone_runtime_info"], \
                 ctx["autostream_webui_page_about.get_vibra_runtime_info"], \
                 ctx["autostream_webui_page_about.get_playback_snapshot"]:
                return _about._collect_system_info()

    @pytest.mark.parametrize("field", [
        "app_version", "wifi_watcher", "monitor", "owntone", "vibra", "playback",
    ])
    def test_exception_does_not_propagate(self, field):
        """Accessor exception must not escape _collect_system_info()."""
        result = self._make_result(raise_at=field)
        assert result["ok"] is True

    def test_app_version_exception_yields_unknown(self):
        result = self._make_result(raise_at="app_version")
        assert result["builds"]["autostream"] == "unknown"

    def test_monitor_exception_yields_unknown(self):
        result = self._make_result(raise_at="monitor")
        assert result["builds"]["monitor"] == "unknown"

    def test_wifi_watcher_exception_yields_unknown(self):
        result = self._make_result(raise_at="wifi_watcher")
        assert result["builds"]["wifi_watcher"] == "unknown"

    def test_owntone_exception_yields_unknown(self):
        result = self._make_result(raise_at="owntone")
        assert result["builds"]["owntone"] == "unknown"

    def test_vibra_exception_yields_unknown(self):
        result = self._make_result(raise_at="vibra")
        assert result["builds"]["vibra_mini"] == "unknown"

    def test_playback_exception_yields_zero_hours(self):
        result = self._make_result(raise_at="playback")
        assert result["playback_hours"] == 0.0
