"""Priority 6 — autostream_dials registry tests.

Covers: missing/malformed/non-object/partially-malformed dials.json fail-closed;
write_dial_entry/remove_dial_entry preserve unrelated entries and use atomic
persistence; update_dial_sighting no-ops on unknown UUIDs, throttles writes,
recovers from malformed timestamps; _handle_line avahi event parsing.
"""
from __future__ import annotations

import json
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_dials as dials


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _redirect(tmp_path: Path):
    """Context manager that sets DIALS_PATH to a tmp file."""
    import contextlib

    @contextlib.contextmanager
    def _ctx():
        orig = dials.DIALS_PATH
        dials.DIALS_PATH = tmp_path / "dials.json"
        try:
            yield dials.DIALS_PATH
        finally:
            dials.DIALS_PATH = orig

    return _ctx()


def _write_dials(path: Path, data: object) -> None:
    if isinstance(data, (dict, list)):
        path.write_text(json.dumps(data), encoding="utf-8")
    else:
        path.write_text(str(data), encoding="utf-8")


def _av_add_dial(iface="eth0", proto="IPv4", name="My-Dial",
                 svc_type="_autostream-dial._tcp", domain="local",
                 host="dial.local", ip="192.168.1.20", port="7842",
                 txt='id=dial-uuid-1 name=Test version=v1') -> str:
    return f"=;{iface};{proto};{name};{svc_type};{domain};{host};{ip};{port};{txt}"


def _av_remove_dial(iface="eth0", proto="IPv4", name="My-Dial",
                    svc_type="_autostream-dial._tcp", domain="local") -> str:
    return f"-;{iface};{proto};{name};{svc_type};{domain}"


def _clear_scanner():
    with dials._browser._lock:
        dials._browser._by_key.clear()
        dials._browser._by_identity.clear()


# ---------------------------------------------------------------------------
# _load_dials_locked: fail-closed behaviour
# ---------------------------------------------------------------------------

class TestLoadDialsFailClosed:
    def test_missing_file_returns_empty_dict(self, tmp_path):
        with _redirect(tmp_path):
            result = dials._load_dials_locked()
        assert result == {}

    def test_malformed_json_returns_empty_dict(self, tmp_path):
        with _redirect(tmp_path) as p:
            p.write_text("not-json", encoding="utf-8")
            result = dials._load_dials_locked()
        assert result == {}

    def test_non_object_root_returns_empty_dict(self, tmp_path):
        with _redirect(tmp_path) as p:
            _write_dials(p, [1, 2, 3])
            result = dials._load_dials_locked()
        assert result == {}

    def test_valid_object_returned(self, tmp_path):
        with _redirect(tmp_path) as p:
            _write_dials(p, {"uuid-1": {"name": "Test", "authorized_at": "2026-01-01"}})
            result = dials._load_dials_locked()
        assert "uuid-1" in result

    def test_partially_malformed_entry_skipped_in_parse_entries(self, tmp_path):
        with _redirect(tmp_path) as p:
            _write_dials(p, {
                "good-uuid": {"name": "OK", "authorized_at": "2026-01-01"},
                "bad-uuid": "not-a-dict",
            })
            entries = dials.parse_dial_entries()
        uuids = [e.uuid for e in entries]
        assert "good-uuid" in uuids
        assert "bad-uuid" not in uuids


# ---------------------------------------------------------------------------
# write_dial_entry / remove_dial_entry: atomic persistence
# ---------------------------------------------------------------------------

class TestWriteRemoveDialEntry:
    def test_write_preserves_unrelated_entries(self, tmp_path):
        with _redirect(tmp_path) as p:
            _write_dials(p, {"existing": {"name": "Existing", "authorized_at": "2026-01-01"}})
            dials.write_dial_entry("new-uuid", "New Dial")
            data = json.loads(p.read_text())
        assert "existing" in data
        assert "new-uuid" in data

    def test_write_stores_name_and_authorized_at(self, tmp_path):
        with _redirect(tmp_path):
            dials.write_dial_entry("my-uuid", "Living Room")
            entries = dials.parse_dial_entries()
        found = next((e for e in entries if e.uuid == "my-uuid"), None)
        assert found is not None
        assert found.name == "Living Room"
        assert found.authorized_at

    def test_remove_preserves_unrelated_entries(self, tmp_path):
        with _redirect(tmp_path) as p:
            _write_dials(p, {
                "to-remove": {"name": "Old", "authorized_at": "2026-01-01"},
                "to-keep": {"name": "Keep", "authorized_at": "2026-01-01"},
            })
            dials.remove_dial_entry("to-remove")
            data = json.loads(p.read_text())
        assert "to-remove" not in data
        assert "to-keep" in data

    def test_remove_nonexistent_uuid_is_noop(self, tmp_path):
        with _redirect(tmp_path) as p:
            _write_dials(p, {"keep": {"name": "X", "authorized_at": "2026-01-01"}})
            dials.remove_dial_entry("nonexistent")
            data = json.loads(p.read_text())
        assert "keep" in data

    def test_is_dial_authorized_returns_true_after_write(self, tmp_path):
        with _redirect(tmp_path):
            dials.write_dial_entry("auth-uuid", "Test")
            assert dials.is_dial_authorized("auth-uuid") is True

    def test_is_dial_authorized_returns_false_for_unknown(self, tmp_path):
        with _redirect(tmp_path):
            assert dials.is_dial_authorized("unknown-uuid") is False

    def test_write_uses_atomic_persistence(self, tmp_path):
        """write_dial_entry must call atomic_write_file, not direct write."""
        with _redirect(tmp_path):
            with patch("autostream_sysutils.atomic_write_file") as mock_atomic:
                dials.write_dial_entry("uuid", "Test")
            mock_atomic.assert_called_once()


# ---------------------------------------------------------------------------
# update_dial_sighting: throttle and unknown UUID
# ---------------------------------------------------------------------------

class TestUpdateDialSighting:
    def test_unknown_uuid_is_noop(self, tmp_path):
        with _redirect(tmp_path) as p:
            _write_dials(p, {})
            with patch("autostream_sysutils.atomic_write_file") as mock_atomic:
                dials.update_dial_sighting("unknown", "Some Name")
            mock_atomic.assert_not_called()

    def test_known_uuid_updates_last_seen(self, tmp_path):
        with _redirect(tmp_path) as p:
            _write_dials(p, {"known-uuid": {"name": "X", "authorized_at": "2026-01-01"}})
            dials.update_dial_sighting("known-uuid", "New Name")
            data = json.loads(p.read_text())
        assert data["known-uuid"].get("last_seen")
        assert data["known-uuid"].get("current_name") == "New Name"

    def test_recent_last_seen_throttles_write(self, tmp_path):
        recent = (datetime.utcnow() - timedelta(seconds=10)).isoformat()
        with _redirect(tmp_path) as p:
            _write_dials(p, {"uuid": {"name": "X",
                                      "authorized_at": "2026-01-01",
                                      "last_seen": recent}})
            with patch("autostream_sysutils.atomic_write_file") as mock_atomic:
                dials.update_dial_sighting("uuid", "New")
            mock_atomic.assert_not_called()

    def test_stale_last_seen_allows_write(self, tmp_path):
        old = (datetime.utcnow() - timedelta(seconds=120)).isoformat()
        with _redirect(tmp_path) as p:
            _write_dials(p, {"uuid": {"name": "X",
                                      "authorized_at": "2026-01-01",
                                      "last_seen": old}})
            with patch("autostream_sysutils.atomic_write_file") as mock_atomic:
                dials.update_dial_sighting("uuid", "Updated")
            mock_atomic.assert_called_once()

    def test_malformed_last_seen_allows_write(self, tmp_path):
        with _redirect(tmp_path) as p:
            _write_dials(p, {"uuid": {"name": "X",
                                      "authorized_at": "2026-01-01",
                                      "last_seen": "not-a-date"}})
            with patch("autostream_sysutils.atomic_write_file") as mock_atomic:
                dials.update_dial_sighting("uuid", "Updated")
            mock_atomic.assert_called_once()


# ---------------------------------------------------------------------------
# _handle_line: avahi event parsing
# ---------------------------------------------------------------------------

class TestHandleLineDialScanner:
    def setup_method(self):
        _clear_scanner()

    def test_valid_add_event_registered(self, tmp_path):
        with _redirect(tmp_path) as p:
            _write_dials(p, {})
            with patch("autostream_dials.update_dial_sighting"):
                dials._browser._handle_line(_av_add_dial())
        assert "dial-uuid-1" in dials._browser.get_snapshot()

    def test_non_ipv4_event_ignored(self, tmp_path):
        with patch("autostream_dials.update_dial_sighting"):
            dials._browser._handle_line(_av_add_dial(proto="IPv6"))
        assert dials._browser.get_snapshot() == {}

    def test_entry_without_id_ignored(self, tmp_path):
        with patch("autostream_dials.update_dial_sighting"):
            dials._browser._handle_line(_av_add_dial(txt="name=Test version=v1"))
        assert dials._browser.get_snapshot() == {}

    def test_invalid_port_defaults_to_7842(self, tmp_path):
        with _redirect(tmp_path) as p:
            _write_dials(p, {})
            with patch("autostream_dials.update_dial_sighting"):
                dials._browser._handle_line(_av_add_dial(port="notaport"))
        sighting = dials._browser.get_snapshot().get("dial-uuid-1")
        assert sighting is not None
        assert sighting.port == 7842

    def test_pin_recovery_flag_parsed(self, tmp_path):
        with _redirect(tmp_path) as p:
            _write_dials(p, {})
            with patch("autostream_dials.update_dial_sighting"):
                dials._browser._handle_line(_av_add_dial(txt="id=uuid-pr name=X pin_recovery=1"))
        s = dials._browser.get_snapshot().get("uuid-pr")
        assert s is not None and s.pin_recovery is True

    def test_remove_event_clears_sighting(self, tmp_path):
        with _redirect(tmp_path) as p:
            _write_dials(p, {})
            with patch("autostream_dials.update_dial_sighting"):
                dials._browser._handle_line(_av_add_dial())
                dials._browser._handle_line(_av_remove_dial())
        assert "dial-uuid-1" not in dials._browser.get_snapshot()

    def test_remove_one_interface_preserves_other(self, tmp_path):
        with _redirect(tmp_path) as p:
            _write_dials(p, {})
            with patch("autostream_dials.update_dial_sighting"):
                dials._browser._handle_line(_av_add_dial(iface="eth0"))
                dials._browser._handle_line(_av_add_dial(iface="wlan0"))
                dials._browser._handle_line(_av_remove_dial(iface="eth0"))
        assert "dial-uuid-1" in dials._browser.get_snapshot()

    def test_too_few_fields_ignored(self):
        with patch("autostream_dials.update_dial_sighting"):
            dials._browser._handle_line("=;eth0;IPv4;name;_tcp;local")
        assert dials._browser.get_snapshot() == {}
