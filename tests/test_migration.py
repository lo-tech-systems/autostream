"""Tests for autostream_migrate.py — INI-to-JSON migration and upgrade paths.

Coverage:
- Fresh-install (no INI, no JSON) skeleton creation
- Full INI → JSON migration
- Interrupted migration recovery (config written, state absent)
- Idempotency (already migrated, re-run is safe)
- PIN preserved in state file
- Data files moved to new paths
- Hints file copied and source removed
- Dry-run produces no filesystem changes
"""

import configparser
import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

REPO_ROOT = Path(__file__).parent.parent
_tools = str(REPO_ROOT / "tools")
if _tools not in sys.path:
    sys.path.insert(0, _tools)

# pwd and grp are Unix-only; stub them before importing the migration script
# so tests run on any platform (the real calls are patched out in fixtures).
# The stub is removed from sys.modules immediately after import so that
# tarfile (imported later by test_updater_staging) doesn't pick up a MagicMock
# as its `pwd` reference and corrupt tar header assembly.
_pwd_injected = "pwd" not in sys.modules
if _pwd_injected:
    sys.modules["pwd"] = MagicMock()

import autostream_migrate as m

if _pwd_injected:
    sys.modules.pop("pwd", None)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=False)
def stub_system():
    """Stub privileged OS calls so migration can run as a non-root test user."""
    with patch.object(m, "_get_autostream_uid_gid", return_value=(65534, 65534)), \
         patch.object(m, "_ensure_dir"), \
         patch.object(m, "_set_ownership_mode"):
        yield


def _write_minimal_ini(path: Path, **extra_sections) -> Path:
    """Write a minimal but valid autostream.ini at *path* and return it."""
    cfg = configparser.ConfigParser()
    cfg["general"] = {
        "log_file": "/var/log/autostream/autostream.log",
        "silence_seconds": "30",
        "fifo_path": "/tmp/autostream-pipes/autostream.fifo",
    }
    cfg["audio1"] = {
        "capture_device": "hw:1,0",
        "silence_threshold": "-66",
        "turntable": "no",
        "gain_db": "0",
        "eq_40hz_db": "0",
        "eq_100hz_db": "0",
        "eq_8khz_db": "0",
    }
    cfg["owntone"] = {
        "base_url": "http://localhost:3689",
        "output_name": "",
        "volume_percent": "20",
    }
    for section, values in extra_sections.items():
        cfg[section] = values
    with path.open("w") as f:
        cfg.write(f)
    return path


# ---------------------------------------------------------------------------
# autostream device — _migrate_autostream
# ---------------------------------------------------------------------------

class TestAutoStreamMigration:

    def test_fresh_install_creates_skeleton_files(self, tmp_path, stub_system):
        cfg_path = tmp_path / "autostream.json"
        state_path = tmp_path / "autostream-state.json"

        with patch.multiple(m,
                _OLD_INI=tmp_path / "autostream.ini",   # absent
                _NEW_CFG=cfg_path,
                _NEW_STATE=state_path,
                _DATA_FILES=[],
                _OLD_HINTS=tmp_path / "hints.json"):
            m._migrate_autostream(dry_run=False)

        assert cfg_path.exists(), "config JSON not created on fresh install"
        assert state_path.exists(), "state JSON not created on fresh install"
        state = json.loads(state_path.read_text())
        assert "auth" in state
        assert "owntone" in state

    def test_full_migration_converts_ini(self, tmp_path, stub_system):
        old_ini = _write_minimal_ini(tmp_path / "autostream.ini")
        cfg_path = tmp_path / "autostream.json"
        state_path = tmp_path / "autostream-state.json"

        with patch.multiple(m,
                _OLD_INI=old_ini,
                _NEW_CFG=cfg_path,
                _NEW_STATE=state_path,
                _DATA_FILES=[],
                _OLD_HINTS=tmp_path / "hints.json"):
            m._migrate_autostream(dry_run=False)

        assert cfg_path.exists()
        assert state_path.exists()
        cfg = json.loads(cfg_path.read_text())
        assert "general" in cfg
        assert "audio1" in cfg
        assert "owntone" in cfg
        # INI renamed to backup, not deleted
        assert (tmp_path / "autostream.ini.pre-migration").exists()
        assert not old_ini.exists()

    def test_interrupted_migration_reconstructs_state(self, tmp_path, stub_system):
        """Config JSON written, state JSON absent — should reconstruct state from INI."""
        old_ini = _write_minimal_ini(tmp_path / "autostream.ini")
        cfg_path = tmp_path / "autostream.json"
        cfg_path.write_text("{}")            # config already written
        state_path = tmp_path / "autostream-state.json"
        assert not state_path.exists()      # state was not written — interrupted

        with patch.multiple(m,
                _OLD_INI=old_ini,
                _NEW_CFG=cfg_path,
                _NEW_STATE=state_path,
                _DATA_FILES=[],
                _OLD_HINTS=tmp_path / "hints.json"):
            m._migrate_autostream(dry_run=False)

        assert state_path.exists(), "state file not reconstructed after interrupted migration"
        state = json.loads(state_path.read_text())
        assert "auth" in state
        assert "owntone" in state

    def test_interrupted_migration_preserves_existing_config(self, tmp_path, stub_system):
        """When both INI and config JSON exist, the existing JSON is not overwritten."""
        old_ini = _write_minimal_ini(tmp_path / "autostream.ini")
        cfg_path = tmp_path / "autostream.json"
        cfg_path.write_text('{"sentinel": true}')
        state_path = tmp_path / "autostream-state.json"

        with patch.multiple(m,
                _OLD_INI=old_ini,
                _NEW_CFG=cfg_path,
                _NEW_STATE=state_path,
                _DATA_FILES=[],
                _OLD_HINTS=tmp_path / "hints.json"):
            m._migrate_autostream(dry_run=False)

        cfg = json.loads(cfg_path.read_text())
        assert cfg.get("sentinel") is True, "existing config JSON was overwritten"

    def test_already_migrated_is_noop(self, tmp_path, stub_system):
        """New JSON exists, old INI absent — function returns without changing anything."""
        cfg_path = tmp_path / "autostream.json"
        cfg_path.write_text('{"general": {"silence_seconds": 42}}')
        state_path = tmp_path / "autostream-state.json"
        state_path.write_text('{"auth": {}}')
        cfg_before = cfg_path.read_text()

        with patch.multiple(m,
                _OLD_INI=tmp_path / "autostream.ini",  # absent
                _NEW_CFG=cfg_path,
                _NEW_STATE=state_path,
                _DATA_FILES=[]):
            m._migrate_autostream(dry_run=False)

        assert cfg_path.read_text() == cfg_before

    def test_pin_preserved_in_state_file(self, tmp_path, stub_system):
        """PIN from INI [auth] section is written into the state file, not the config."""
        old_ini = _write_minimal_ini(tmp_path / "autostream.ini",
                                     auth={"pin_override": "s3cr3t"})
        cfg_path = tmp_path / "autostream.json"
        state_path = tmp_path / "autostream-state.json"

        with patch.multiple(m,
                _OLD_INI=old_ini,
                _NEW_CFG=cfg_path,
                _NEW_STATE=state_path,
                _DATA_FILES=[],
                _OLD_HINTS=tmp_path / "hints.json"):
            m._migrate_autostream(dry_run=False)

        state = json.loads(state_path.read_text())
        assert state["auth"]["pin_override"] == "s3cr3t"
        cfg = json.loads(cfg_path.read_text())
        assert "auth" not in cfg, "PIN must not appear in the config file"

    def test_data_files_moved(self, tmp_path, stub_system):
        """Data files listed in _DATA_FILES are moved from old to new paths."""
        old_ini = _write_minimal_ini(tmp_path / "autostream.ini")
        cfg_path = tmp_path / "autostream.json"
        state_path = tmp_path / "autostream-state.json"

        old_data = tmp_path / "old_data.json"
        new_data = tmp_path / "new_data.json"
        old_data.write_text('{"records": 10}')

        with patch.multiple(m,
                _OLD_INI=old_ini,
                _NEW_CFG=cfg_path,
                _NEW_STATE=state_path,
                _DATA_FILES=[("test_data", old_data, new_data)],
                _OLD_HINTS=tmp_path / "hints.json"):
            m._migrate_autostream(dry_run=False)

        assert new_data.exists()
        assert json.loads(new_data.read_text())["records"] == 10
        assert not old_data.exists()

    def test_hints_file_copied_and_source_removed(self, tmp_path, stub_system):
        """User-created hints file is copied to new location and old copy removed."""
        old_ini = _write_minimal_ini(tmp_path / "autostream.ini")
        cfg_path = tmp_path / "autostream.json"
        state_path = tmp_path / "autostream-state.json"
        old_hints = tmp_path / "old_hints.json"
        new_hints = tmp_path / "new_hints.json"
        old_hints.write_text('{"artist": {"My Band": "My Band"}}')

        with patch.multiple(m,
                _OLD_INI=old_ini,
                _NEW_CFG=cfg_path,
                _NEW_STATE=state_path,
                _DATA_FILES=[],
                _OLD_HINTS=old_hints,
                _NEW_HINTS=new_hints):
            m._migrate_autostream(dry_run=False)

        assert new_hints.exists()
        assert not old_hints.exists(), "old hints file should be removed after copy"

    def test_dry_run_writes_nothing(self, tmp_path, stub_system):
        """dry_run=True logs actions but creates no files."""
        old_ini = _write_minimal_ini(tmp_path / "autostream.ini")
        cfg_path = tmp_path / "autostream.json"
        state_path = tmp_path / "autostream-state.json"

        with patch.multiple(m,
                _OLD_INI=old_ini,
                _NEW_CFG=cfg_path,
                _NEW_STATE=state_path,
                _DATA_FILES=[],
                _OLD_HINTS=tmp_path / "hints.json"):
            m._migrate_autostream(dry_run=True)

        assert not cfg_path.exists()
        assert not state_path.exists()
