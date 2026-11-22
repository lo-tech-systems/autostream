"""tests/test_migrate_bluetooth_input3.py

The update step that moves a Bluetooth binding on input 1 or 2 to input 3
(tools/autostream_migrate.py, migrate_bluetooth_to_input3), the note it
leaves for the Setup cards and how the next write clears it, and the
installer passing the Bluetooth services' state.
"""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
for _sub in ("tools", "core"):
    _p = str(REPO_ROOT / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

_pwd_injected = "pwd" not in sys.modules
if _pwd_injected:
    sys.modules["pwd"] = MagicMock()

import autostream_migrate as m

if _pwd_injected:
    sys.modules.pop("pwd", None)

from autostream_bluetooth_client import BLUETOOTH_CAPTURE_DEVICE, BLUETOOTH_PLAYBACK_DEVICE
from autostream_config import parse_config
from autostream_settings import SettingsStore

_BT_SETTINGS = {
    "input_type": "turntable", "turntable": True, "silence_threshold": -45, "gain_db": 3.0,
    "eq_40hz_db": 1.0, "eq_100hz_db": -1.0, "eq_8khz_db": 2.0, "dynamic_rate_matching": False,
    "start_after_ms": 120, "stylus_life_hours": 500, "belt_life_hours": 1000, "belt_life_years": 2,
    "bearing_life_hours": 500, "bearing_life_years": 3,
}
_COUNTERS = {"total_playback_seconds": 3600, "stylus_seconds": 1800}


def _write(path: Path, data: dict) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def _files(tmp_path: Path, config: dict, stats: dict | None = None):
    cfg = _write(tmp_path / "autostream.json", config)
    stats_path = _write(tmp_path / "playback_stats.json", stats or {"inputs": {}})
    return cfg, stats_path


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _bt_on(index: int, **extra) -> dict:
    return {f"audio{index}": {"enabled": True, "capture_device": BLUETOOTH_CAPTURE_DEVICE,
                              **_BT_SETTINGS, **extra}}


@pytest.mark.parametrize("index", [1, 2])
def test_a_binding_moves_with_its_settings_and_counters(tmp_path, index):
    other = 3 - index
    config = {**_bt_on(index), f"audio{other}": {"enabled": True, "capture_device": "hw:1,0"}}
    stats = {"schema_version": 1, "inputs": {str(index): _COUNTERS, str(other): {"x": 1}}}
    cfg, stats_path = _files(tmp_path, config, stats)

    m.migrate_bluetooth_to_input3(cfg, stats_path, True, dry_run=False)

    raw = _read(cfg)
    assert raw[f"audio{index}"] == {"enabled": False, "capture_device": ""}
    assert raw["audio3"] == {**_BT_SETTINGS, "moved_from": index, "enabled": True}
    assert raw[f"audio{other}"] == {"enabled": True, "capture_device": "hw:1,0"}
    assert _read(stats_path)["inputs"] == {"3": _COUNTERS, str(other): {"x": 1}}

    parsed = parse_config(raw, high_perf=False)
    assert parsed.audio3_enabled is True
    assert parsed.audio3.input_type == "turntable"
    assert parsed.audio3.gain_db == 3.0
    assert parsed.audio3.start_after_ms == 120
    assert parsed.audio_enabled(index) is False
    assert parsed.audio_section(index).capture_device == ""
    assert parsed.bluetooth_moved_from == index


def test_a_second_run_writes_nothing(tmp_path):
    cfg, stats_path = _files(tmp_path, _bt_on(2), {"inputs": {"2": _COUNTERS}})
    m.migrate_bluetooth_to_input3(cfg, stats_path, True, dry_run=False)
    first = (_read(cfg), _read(stats_path))
    with patch.object(m, "_replace_json") as replace:
        m.migrate_bluetooth_to_input3(cfg, stats_path, True, dry_run=False)
    replace.assert_not_called()
    assert (_read(cfg), _read(stats_path)) == first


def test_dry_run_writes_nothing(tmp_path):
    config = _bt_on(1)
    cfg, stats_path = _files(tmp_path, config, {"inputs": {"1": _COUNTERS}})
    m.migrate_bluetooth_to_input3(cfg, stats_path, True, dry_run=True)
    assert _read(cfg) == config
    assert _read(stats_path) == {"inputs": {"1": _COUNTERS}}


@pytest.mark.parametrize("services,expected", [(True, True), (False, False)])
def test_with_no_binding_only_the_enable_follows_the_services(tmp_path, services, expected):
    config = {"audio1": {"enabled": True, "capture_device": "hw:0,0"}}
    cfg, stats_path = _files(tmp_path, config, {"inputs": {"1": _COUNTERS}})
    m.migrate_bluetooth_to_input3(cfg, stats_path, services, dry_run=False)
    raw = _read(cfg)
    assert raw["audio1"] == config["audio1"]
    assert raw["audio3"] == {"enabled": expected}
    assert _read(stats_path) == {"inputs": {"1": _COUNTERS}}


def test_without_the_services_state_the_enable_is_left_alone(tmp_path):
    config = {"audio1": {"capture_device": "hw:0,0"}, "audio3": {"enabled": True}}
    cfg, stats_path = _files(tmp_path, config)
    with patch.object(m, "_replace_json") as replace:
        m.migrate_bluetooth_to_input3(cfg, stats_path, None, dry_run=False)
    replace.assert_not_called()


def test_the_playback_side_on_a_wired_input_is_cleared_not_moved(tmp_path):
    config = {"audio2": {"enabled": True, "capture_device": BLUETOOTH_PLAYBACK_DEVICE, "gain_db": 2.0}}
    cfg, stats_path = _files(tmp_path, config)
    m.migrate_bluetooth_to_input3(cfg, stats_path, False, dry_run=False)
    raw = _read(cfg)
    assert raw["audio2"] == {"enabled": False, "capture_device": "", "gain_db": 2.0}
    assert raw["audio3"] == {"enabled": False}


def test_the_files_keep_their_mode(tmp_path):
    cfg, stats_path = _files(tmp_path, _bt_on(2), {"inputs": {"2": _COUNTERS}})
    m.migrate_bluetooth_to_input3(cfg, stats_path, True, dry_run=False)
    assert stat.S_IMODE(cfg.stat().st_mode) == 0o600
    assert stat.S_IMODE(stats_path.stat().st_mode) == 0o600


def test_an_unreadable_config_is_left_as_it_is(tmp_path):
    cfg = tmp_path / "autostream.json"
    cfg.write_text("{not json", encoding="utf-8")
    m.migrate_bluetooth_to_input3(cfg, tmp_path / "missing.json", True, dry_run=False)
    assert cfg.read_text(encoding="utf-8") == "{not json"


def test_the_entry_point_takes_the_services_state():
    with patch.object(sys, "argv", ["autostream_migrate.py", "--bluetooth-services", "on"]), \
            patch.object(m.os, "geteuid", return_value=0), \
            patch.object(m, "_AUTOSTREAM_SENTINEL") as sentinel, \
            patch.object(m, "_migrate_autostream"), \
            patch.object(m, "migrate_bluetooth_to_input3") as step:
        sentinel.exists.return_value = True
        with pytest.raises(SystemExit) as done:
            m.main()
    assert done.value.code == 0
    step.assert_called_once_with(m._NEW_CFG, m._PLAYBACK_STATS, True, dry_run=False)


def test_the_installer_passes_the_services_state():
    text = (REPO_ROOT / "autostream_install.sh").read_text(encoding="utf-8")
    assert "systemctl is-enabled --quiet autostream_bluetooth" in text
    assert 'autostream_migrate.py" --bluetooth-services "${bt_services}"' in text


# ---------------------------------------------------------------------------
# The note lasts until input 3 or the input it came from is next written
# ---------------------------------------------------------------------------

def _store(tmp_path, moved_from=2) -> SettingsStore:
    path = tmp_path / "autostream.json"
    path.write_text(json.dumps({
        "audio1": {"capture_device": "hw:0,0"},
        "audio2": {"enabled": False, "capture_device": ""},
        "audio3": {"enabled": True, "moved_from": moved_from},
    }), encoding="utf-8")
    return SettingsStore(str(path), _save_interval_seconds=9999)


@pytest.mark.parametrize("section,cleared", [("audio3", True), ("audio2", True), ("audio1", False),
                                             ("general", False)])
def test_the_note_is_cleared_by_a_write_to_either_input(tmp_path, section, cleared):
    store = _store(tmp_path)
    try:
        store.update(lambda raw: raw.setdefault(section, {}).update({"gain_db": 1.0}))
        assert (store.snapshot().bluetooth_moved_from is None) is cleared
    finally:
        store.close(save=False)


def test_a_write_that_changes_nothing_keeps_the_note(tmp_path):
    store = _store(tmp_path)
    try:
        store.update(lambda raw: raw["audio3"].update({"enabled": True}))
        assert store.snapshot().bluetooth_moved_from == 2
    finally:
        store.close(save=False)
