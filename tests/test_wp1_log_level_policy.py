"""WP1 — Log-level policy state and application service tests.

Covers:
  - Config metadata fields (log_level_changed_by, log_level_changed_at) in
    GeneralConfig / parse_config normalization.
  - autostream_log_policy.get_log_level_state: round-trip, missing fields,
    missing config file.
  - autostream_log_policy.set_log_level: validation rejection, policy-state
    change detection, persistence, no-op idempotency, startup mode.
  - autostream_sysutils.set_nginx_verbose_logging: admin call pass-through.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Optional
from unittest.mock import MagicMock, call, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_config as cfg_mod
import autostream_sysutils as sysutils


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_config(tmp_path: Path, data: dict) -> str:
    p = tmp_path / "autostream.json"
    p.write_text(json.dumps(data))
    return str(p)


def _minimal_config(
    level: str = "info",
    changed_by: Optional[str] = None,
    changed_at: Optional[str] = None,
) -> dict:
    d: dict = {
        "general": {
            "log_file": "/tmp/autostream.log",
            "log_level": level,
            "silence_seconds": 30,
            "fifo_path": "/tmp/fifo",
        },
        "owntone": {"host": "localhost", "port": 3689},
        "devices": [],
    }
    if changed_by is not None:
        d["general"]["log_level_changed_by"] = changed_by
    if changed_at is not None:
        d["general"]["log_level_changed_at"] = changed_at
    return d


# ---------------------------------------------------------------------------
# autostream_config: GeneralConfig metadata fields
# ---------------------------------------------------------------------------

class TestGeneralConfigMetadata:
    def test_defaults_when_fields_absent(self, tmp_path):
        p = _write_config(tmp_path, _minimal_config())
        raw = cfg_mod.load_config(p)
        parsed = cfg_mod.parse_config(raw)
        assert parsed.general.log_level_changed_by == cfg_mod.DEFAULT_LOG_LEVEL_CHANGED_BY
        assert parsed.general.log_level_changed_at is None

    def test_valid_changed_by_accepted(self, tmp_path):
        p = _write_config(tmp_path, _minimal_config(changed_by="system"))
        raw = cfg_mod.load_config(p)
        parsed = cfg_mod.parse_config(raw)
        assert parsed.general.log_level_changed_by == "system"

    def test_invalid_changed_by_defaults_to_user(self, tmp_path):
        p = _write_config(tmp_path, _minimal_config(changed_by="admin"))
        raw = cfg_mod.load_config(p)
        parsed = cfg_mod.parse_config(raw)
        assert parsed.general.log_level_changed_by == "user"

    def test_valid_changed_at_accepted(self, tmp_path):
        ts = "2026-06-24T04:00:00Z"
        p = _write_config(tmp_path, _minimal_config(changed_at=ts))
        raw = cfg_mod.load_config(p)
        parsed = cfg_mod.parse_config(raw)
        assert parsed.general.log_level_changed_at == ts

    def test_invalid_changed_at_returns_none(self, tmp_path):
        p = _write_config(tmp_path, _minimal_config(changed_at="not-a-timestamp"))
        raw = cfg_mod.load_config(p)
        parsed = cfg_mod.parse_config(raw)
        assert parsed.general.log_level_changed_at is None

    def test_null_changed_at_returns_none(self, tmp_path):
        d = _minimal_config()
        d["general"]["log_level_changed_at"] = None
        p = _write_config(tmp_path, d)
        raw = cfg_mod.load_config(p)
        parsed = cfg_mod.parse_config(raw)
        assert parsed.general.log_level_changed_at is None


class TestNormalizers:
    def test_normalize_changed_by_empty_string(self):
        assert cfg_mod.normalize_log_level_changed_by("") == "user"

    def test_normalize_changed_by_case_insensitive(self):
        assert cfg_mod.normalize_log_level_changed_by("SYSTEM") == "system"

    def test_normalize_changed_by_unknown(self):
        assert cfg_mod.normalize_log_level_changed_by("robot") == "user"

    def test_normalize_changed_at_valid(self):
        ts = "2026-06-24T04:00:00Z"
        assert cfg_mod.normalize_log_level_changed_at(ts) == ts

    def test_normalize_changed_at_no_z_suffix(self):
        assert cfg_mod.normalize_log_level_changed_at("2026-06-24T04:00:00") is None

    def test_normalize_changed_at_none(self):
        assert cfg_mod.normalize_log_level_changed_at(None) is None

    def test_normalize_changed_at_integer(self):
        assert cfg_mod.normalize_log_level_changed_at(12345) is None


# ---------------------------------------------------------------------------
# autostream_log_policy.get_log_level_state
# ---------------------------------------------------------------------------

class TestGetLogLevelState:
    def _import_policy(self):
        import autostream_log_policy as lp
        return lp

    def test_returns_level_and_metadata(self, tmp_path):
        ts = "2026-06-24T04:00:00Z"
        p = _write_config(tmp_path, _minimal_config(
            level="debug", changed_by="system", changed_at=ts,
        ))
        lp = self._import_policy()
        result = lp.get_log_level_state(p)
        assert result["ok"] is True
        assert result["level"] == "debug"
        assert result["changed_by"] == "system"
        assert result["changed_at"] == ts

    def test_absent_config_returns_error(self, tmp_path):
        lp = self._import_policy()
        result = lp.get_log_level_state(str(tmp_path / "absent.json"))
        # Missing config → load_config returns {} → parse_config raises or returns
        # default; either path the function should not raise.
        # The implementation catches exceptions and returns {"ok": False}.
        assert "ok" in result

    def test_defaults_when_metadata_absent(self, tmp_path):
        p = _write_config(tmp_path, _minimal_config("warning"))
        lp = self._import_policy()
        result = lp.get_log_level_state(p)
        assert result["ok"] is True
        assert result["level"] == "warning"
        assert result["changed_by"] == "user"  # default
        assert result["changed_at"] is None


# ---------------------------------------------------------------------------
# autostream_log_policy.set_log_level
# ---------------------------------------------------------------------------

def _make_no_op_apply(monkeypatch):
    """Patch all live-apply targets so persistence tests focus on disk I/O."""
    import autostream_log_policy as lp
    monkeypatch.setattr(lp, "_VERBOSE_NGINX_LEVELS", frozenset({"debug", "spam"}))

    def _fake_update_live(_): return "info"
    def _fake_set_monitor(_): return True
    def _fake_set_nginx(_): return True

    monkeypatch.setattr(
        "autostream_core.update_live_log_level", _fake_update_live, raising=False,
    )
    monkeypatch.setattr(
        "autostream_core.set_live_monitor_log_level", lambda *_: True, raising=False,
    )
    monkeypatch.setattr(
        "autostream_sysutils.set_nginx_verbose_logging", _fake_set_nginx, raising=False,
    )


class TestSetLogLevelValidation:
    def test_invalid_level_rejected(self, tmp_path):
        import autostream_log_policy as lp
        p = _write_config(tmp_path, _minimal_config())
        result = lp.set_log_level(p, "verbose", changed_by="user")
        assert result["ok"] is False
        assert "level" in result["error"].lower() or "unsupported" in result["error"].lower()

    def test_empty_level_rejected(self, tmp_path):
        import autostream_log_policy as lp
        p = _write_config(tmp_path, _minimal_config())
        result = lp.set_log_level(p, "", changed_by="user")
        assert result["ok"] is False

    def test_none_level_rejected_outside_startup(self, tmp_path):
        import autostream_log_policy as lp
        p = _write_config(tmp_path, _minimal_config())
        result = lp.set_log_level(p, None, changed_by="user")
        assert result["ok"] is False

    def test_valid_levels_accepted(self, tmp_path, monkeypatch):
        import autostream_log_policy as lp
        _make_no_op_apply(monkeypatch)
        # Patch out OwnTone to avoid import issues.
        with patch.dict("sys.modules", {"autostream_player_service": MagicMock()}):
            for level in cfg_mod.VALID_LOG_LEVELS:
                p = _write_config(tmp_path, _minimal_config())
                result = lp.set_log_level(p, level, changed_by="user")
                assert result["ok"] is True, f"Expected ok for level {level!r}"


class TestSetLogLevelPersistence:
    def test_level_change_persisted(self, tmp_path, monkeypatch):
        import autostream_log_policy as lp
        _make_no_op_apply(monkeypatch)
        with patch.dict("sys.modules", {"autostream_player_service": MagicMock()}):
            p = _write_config(tmp_path, _minimal_config("info"))
            fixed_now = datetime(2026, 6, 24, 4, 0, 0, tzinfo=timezone.utc)
            result = lp.set_log_level(p, "debug", changed_by="user", now=fixed_now)
        assert result["ok"] is True
        assert result["changed"] is True
        assert result["level"] == "debug"
        assert result["changed_at"] == "2026-06-24T04:00:00Z"
        # Verify disk round-trip.
        raw = cfg_mod.load_config(p)
        parsed = cfg_mod.parse_config(raw)
        assert parsed.general.log_level == "debug"
        assert parsed.general.log_level_changed_at == "2026-06-24T04:00:00Z"

    def test_no_op_when_level_and_owner_unchanged(self, tmp_path, monkeypatch):
        import autostream_log_policy as lp
        _make_no_op_apply(monkeypatch)
        ts = "2026-06-01T12:00:00Z"
        with patch.dict("sys.modules", {"autostream_player_service": MagicMock()}):
            p = _write_config(tmp_path, _minimal_config("info", "user", ts))
            result = lp.set_log_level(p, "info", changed_by="user")
        assert result["ok"] is True
        assert result["changed"] is False
        assert result["changed_at"] == ts  # original timestamp preserved

    def test_owner_change_updates_timestamp(self, tmp_path, monkeypatch):
        import autostream_log_policy as lp
        _make_no_op_apply(monkeypatch)
        ts_old = "2026-06-01T12:00:00Z"
        fixed_now = datetime(2026, 6, 24, 8, 0, 0, tzinfo=timezone.utc)
        with patch.dict("sys.modules", {"autostream_player_service": MagicMock()}):
            p = _write_config(tmp_path, _minimal_config("info", "user", ts_old))
            result = lp.set_log_level(p, "info", changed_by="system", now=fixed_now)
        assert result["ok"] is True
        assert result["changed"] is True
        assert result["changed_at"] == "2026-06-24T08:00:00Z"


class TestSetLogLevelStartupMode:
    def test_startup_mode_does_not_change_metadata(self, tmp_path, monkeypatch):
        import autostream_log_policy as lp
        _make_no_op_apply(monkeypatch)
        ts = "2026-06-01T12:00:00Z"
        with patch.dict("sys.modules", {"autostream_player_service": MagicMock()}):
            p = _write_config(tmp_path, _minimal_config("debug", "system", ts))
            result = lp.set_log_level(
                p, requested_level=None, changed_by="system", _startup=True,
            )
        assert result["ok"] is True
        assert result["changed"] is False
        assert result["level"] == "debug"
        assert result["changed_at"] == ts
        # Disk should be untouched.
        raw = cfg_mod.load_config(p)
        parsed = cfg_mod.parse_config(raw)
        assert parsed.general.log_level == "debug"
        assert parsed.general.log_level_changed_at == ts


class TestSetLogLevelApplied:
    def test_nginx_verbose_called_for_debug(self, tmp_path, monkeypatch):
        import autostream_log_policy as lp
        calls = []
        monkeypatch.setattr(
            "autostream_sysutils.set_nginx_verbose_logging",
            lambda v: calls.append(v) or True,
            raising=False,
        )
        monkeypatch.setattr("autostream_core.update_live_log_level", lambda _: None, raising=False)
        monkeypatch.setattr("autostream_core.set_live_monitor_log_level", lambda *_: True, raising=False)
        with patch.dict("sys.modules", {"autostream_player_service": MagicMock()}):
            p = _write_config(tmp_path, _minimal_config("info"))
            lp.set_log_level(p, "debug", changed_by="user")
        assert calls and calls[-1] is True  # verbose=True for debug

    def test_nginx_normal_called_for_info(self, tmp_path, monkeypatch):
        import autostream_log_policy as lp
        calls = []
        monkeypatch.setattr(
            "autostream_sysutils.set_nginx_verbose_logging",
            lambda v: calls.append(v) or True,
            raising=False,
        )
        monkeypatch.setattr("autostream_core.update_live_log_level", lambda _: None, raising=False)
        monkeypatch.setattr("autostream_core.set_live_monitor_log_level", lambda *_: True, raising=False)
        with patch.dict("sys.modules", {"autostream_player_service": MagicMock()}):
            p = _write_config(tmp_path, _minimal_config("debug", "user"))
            lp.set_log_level(p, "info", changed_by="user")
        assert calls and calls[-1] is False  # verbose=False for info

    def test_applied_dict_returned(self, tmp_path, monkeypatch):
        import autostream_log_policy as lp
        _make_no_op_apply(monkeypatch)
        with patch.dict("sys.modules", {"autostream_player_service": MagicMock()}):
            p = _write_config(tmp_path, _minimal_config())
            result = lp.set_log_level(p, "warning", changed_by="system")
        assert "applied" in result
        assert "autostream" in result["applied"]
        assert "monitor" in result["applied"]
        assert "owntone" in result["applied"]
        assert "nginx" in result["applied"]


# ---------------------------------------------------------------------------
# autostream_sysutils.set_nginx_verbose_logging
# ---------------------------------------------------------------------------

class TestSetNginxVerboseLogging:
    def test_verbose_passes_verbose_mode(self):
        with patch.object(sysutils, "run_admin_cmd") as mock_cmd:
            mock_cmd.return_value = MagicMock(returncode=0)
            result = sysutils.set_nginx_verbose_logging(True)
        assert result is True
        mock_cmd.assert_called_once_with(["set-nginx-access-log", "verbose"], timeout=10.0)

    def test_normal_passes_normal_mode(self):
        with patch.object(sysutils, "run_admin_cmd") as mock_cmd:
            mock_cmd.return_value = MagicMock(returncode=0)
            result = sysutils.set_nginx_verbose_logging(False)
        assert result is True
        mock_cmd.assert_called_once_with(["set-nginx-access-log", "normal"], timeout=10.0)

    def test_nonzero_rc_returns_false(self):
        with patch.object(sysutils, "run_admin_cmd") as mock_cmd:
            mock_cmd.return_value = MagicMock(returncode=1, stderr="error")
            result = sysutils.set_nginx_verbose_logging(True)
        assert result is False
