"""Dynamic Rate Matching is on unless the settings file says otherwise."""
from __future__ import annotations

import configparser
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
for _p in (REPO_ROOT / "core", REPO_ROOT / "tools"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

_pwd_injected = "pwd" not in sys.modules
if _pwd_injected:
    sys.modules["pwd"] = MagicMock()
import autostream_migrate as m
if _pwd_injected:
    sys.modules.pop("pwd", None)

import autostream_config as c
from autostream_commissioning import is_commissioning_required, required_first_boot_step


def _drm(cfg):
    return cfg.audio1.dynamic_rate_matching, cfg.audio2.dynamic_rate_matching


class TestParse:
    def test_empty_config_is_on_for_both_inputs(self):
        assert _drm(c.parse_config({})) == (True, True)

    def test_sections_without_the_key_are_on(self):
        cfg = c.parse_config({"audio1": {"capture_device": "hw:1,0"}, "audio2": {"enabled": True}})
        assert _drm(cfg) == (True, True)

    def test_absent_file_loads_as_on(self, tmp_path):
        assert _drm(c.parse_config(c.load_config(str(tmp_path / "none.json")))) == (True, True)

    @pytest.mark.parametrize("value", [True, False])
    def test_explicit_value_is_kept(self, value):
        cfg = c.parse_config({"audio1": {"dynamic_rate_matching": value},
                              "audio2": {"dynamic_rate_matching": not value}})
        assert _drm(cfg) == (value, not value)


class TestMigration:
    @pytest.fixture(autouse=True)
    def _stub(self):
        with patch.object(m, "_get_autostream_uid_gid", return_value=(65534, 65534)), \
             patch.object(m, "_ensure_dir"), patch.object(m, "_set_ownership_mode"):
            yield

    def _run(self, tmp_path, ini=None):
        cfg_path = tmp_path / "autostream.json"
        with patch.multiple(m, _OLD_INI=ini or tmp_path / "autostream.ini",
                            _NEW_CFG=cfg_path, _NEW_STATE=tmp_path / "state.json",
                            _DATA_FILES=[], _OLD_HINTS=tmp_path / "hints.json"):
            m._migrate_autostream(dry_run=False)
        return cfg_path

    def test_ini_migration_reads_as_on(self, tmp_path):
        ini = tmp_path / "autostream.ini"
        parser = configparser.ConfigParser()
        parser["audio1"] = {"capture_device": "hw:1,0"}
        with ini.open("w") as f:
            parser.write(f)
        cfg = json.loads(self._run(tmp_path, ini).read_text())
        assert "dynamic_rate_matching" not in cfg["audio1"]
        assert _drm(c.parse_config(cfg)) == (True, True)

    def test_fresh_skeleton_reads_as_on_and_still_needs_first_boot(self, tmp_path):
        cfg_path = self._run(tmp_path)
        assert _drm(c.parse_config(json.loads(cfg_path.read_text()))) == (True, True)
        state = str(tmp_path / "state.json")
        assert is_commissioning_required(str(cfg_path), state)
        assert required_first_boot_step(str(cfg_path), state) == "owntone"
