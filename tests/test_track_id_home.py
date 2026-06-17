"""Tests for WP5 — track identification state in build_home_state().

Verifies that the `track_identification` field is always present in the Home
state dict, covers all states, and that build_home_state() never calls provider
or network code to satisfy it.
"""
from __future__ import annotations

import json
import sys
import time
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_appliance_models as models
import autostream_core as core
from track_id.models import (
    STATE_DISABLED,
    STATE_WAITING,
    STATE_ANALYSING,
    STATE_IDENTIFIED,
    STATE_NOT_FOUND,
    TrackIdentificationSnapshot,
    disabled_snapshot,
    waiting_snapshot,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_cfg() -> dict:
    return {
        "general": {"silence_seconds": 30},
        "owntone": {"base_url": "http://localhost:3689"},
        "audio1": {
            "capture_device": "hw:0,0",
            "silence_threshold": -66,
            "turntable": False,
            "stylus_life_hours": 500,
            "belt_life_hours": 0,
            "bearing_life_hours": 0,
            "belt_life_years": 0,
            "bearing_life_years": 0,
            "gain_db": 0,
            "eq_40hz_db": 0,
            "eq_100hz_db": 0,
            "eq_8khz_db": 0,
        },
        "output_eq": {
            "gain_db": 0.0,
            "peq1_db": 0.0, "peq2_db": 0.0, "peq3_db": 0.0,
            "peq4_db": 0.0, "peq5_db": 0.0, "peq6_db": 0.0,
            "auto_trim_enabled": False,
        },
    }


def _make_config_file(tmp_path: Path) -> Path:
    p = tmp_path / "autostream.json"
    p.write_text(json.dumps(_minimal_cfg()), encoding="utf-8")
    return p


def _run_home(cfg_path: Path, *, ti_snapshot=None) -> dict:
    """Call build_home_state() with all external dependencies patched."""
    buf_result = MagicMock(ok=True, value="100")
    out_result = MagicMock(ok=True, outputs=[])
    playback = MagicMock()
    playback.to_public_dict.return_value = {}
    playback.stylus_banner_text = ""
    playback.belt_banner_text = ""
    playback.bearing_banner_text = ""

    snap = ti_snapshot if ti_snapshot is not None else disabled_snapshot()

    patches = [
        patch("autostream_appliance_models.get_setting", return_value=buf_result),
        patch("autostream_appliance_models.list_outputs", return_value=out_result),
        patch("autostream_appliance_models.get_monitor_levels_dbfs", return_value=[]),
        patch("autostream_appliance_models.get_playback_snapshot", return_value=playback),
        patch("autostream_appliance_models.get_appliance_id", return_value="aabbcc"),
        patch("autostream_appliance_models.get_system_hostname", return_value="test-host"),
        patch("autostream_appliance_models.get_app_version", return_value="1.0.0"),
        patch("autostream_appliance_models.get_active_track_identification_snapshot",
              return_value=snap),
    ]
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        return models.build_home_state(str(cfg_path))


# ---------------------------------------------------------------------------
# Key presence
# ---------------------------------------------------------------------------

class TestTrackIdentificationKeyPresent:

    def test_key_present_on_success(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        result = _run_home(cfg_path)
        assert "track_identification" in result

    def test_key_present_on_config_failure(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        with patch("autostream_appliance_models.locked_load_config",
                   side_effect=OSError("fail")), \
             patch("autostream_appliance_models.get_appliance_id", return_value=""), \
             patch("autostream_appliance_models.get_system_hostname", return_value=""), \
             patch("autostream_appliance_models.get_app_version", return_value=""):
            result = models.build_home_state(str(cfg_path))
        assert result["ok"] is False
        assert "track_identification" in result
        assert result["track_identification"]["state"] == STATE_DISABLED


# ---------------------------------------------------------------------------
# State values
# ---------------------------------------------------------------------------

class TestTrackIdentificationStates:

    def test_disabled_state(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        result = _run_home(cfg_path, ti_snapshot=disabled_snapshot())
        ti = result["track_identification"]
        assert ti["enabled"] is False
        assert ti["state"] == STATE_DISABLED

    def test_waiting_state(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        result = _run_home(cfg_path, ti_snapshot=waiting_snapshot())
        ti = result["track_identification"]
        assert ti["enabled"] is True
        assert ti["state"] == STATE_WAITING

    def test_analysing_state(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        snap = TrackIdentificationSnapshot(
            enabled=True,
            state=STATE_ANALYSING,
            status_text="Analysing",
            updated_at=time.time(),
        )
        result = _run_home(cfg_path, ti_snapshot=snap)
        ti = result["track_identification"]
        assert ti["state"] == STATE_ANALYSING

    def test_identified_metadata(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        snap = TrackIdentificationSnapshot(
            enabled=True,
            state=STATE_IDENTIFIED,
            status_text="Identified",
            title="Blue in Green",
            artist="Miles Davis",
            album="Kind of Blue",
            artwork_url="https://caa.example.com/art.jpg",
            confidence=0.95,
            updated_at=time.time(),
        )
        result = _run_home(cfg_path, ti_snapshot=snap)
        ti = result["track_identification"]
        assert ti["state"] == STATE_IDENTIFIED
        assert ti["title"] == "Blue in Green"
        assert ti["artist"] == "Miles Davis"
        assert ti["album"] == "Kind of Blue"
        assert ti["artwork_url"] == "https://caa.example.com/art.jpg"
        assert ti["confidence"] == pytest.approx(0.95)

    def test_not_found_state(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        snap = TrackIdentificationSnapshot(
            enabled=True,
            state=STATE_NOT_FOUND,
            status_text="Not found",
            updated_at=time.time(),
        )
        result = _run_home(cfg_path, ti_snapshot=snap)
        ti = result["track_identification"]
        assert ti["state"] == STATE_NOT_FOUND


# ---------------------------------------------------------------------------
# Public dict shape
# ---------------------------------------------------------------------------

class TestPublicDictShape:

    def test_required_keys_in_identified(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        snap = TrackIdentificationSnapshot(
            enabled=True,
            state=STATE_IDENTIFIED,
            status_text="Identified",
            title="Song",
            artist="Artist",
            updated_at=time.time(),
        )
        result = _run_home(cfg_path, ti_snapshot=snap)
        ti = result["track_identification"]
        for key in ("enabled", "state", "status_text", "title", "artist",
                    "album", "artwork_url", "provider", "error"):
            assert key in ti, f"Missing key: {key}"

    def test_no_raw_provider_payload(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        snap = TrackIdentificationSnapshot(
            enabled=True,
            state=STATE_IDENTIFIED,
            status_text="Identified",
            title="Song",
            updated_at=time.time(),
        )
        result = _run_home(cfg_path, ti_snapshot=snap)
        ti = result["track_identification"]
        # Raw provider internals must not be exposed.
        assert "external_ids" not in ti
        assert "source_detail" not in ti


# ---------------------------------------------------------------------------
# No network or provider calls in build_home_state
# ---------------------------------------------------------------------------

class TestNoProviderCallsInBuildHomeState:

    def test_identify_not_called(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        mock_svc = MagicMock()
        mock_svc.identify.side_effect = RuntimeError("should not be called")
        old_svc = core._track_id_service
        core._track_id_service = mock_svc
        try:
            result = _run_home(cfg_path)
        finally:
            core._track_id_service = old_svc

        mock_svc.identify.assert_not_called()
        assert "track_identification" in result


# ---------------------------------------------------------------------------
# In-flight recognition returns cached state without waiting
# ---------------------------------------------------------------------------

class TestInFlightState:

    def test_analysing_returned_without_block(self, tmp_path):
        cfg_path = _make_config_file(tmp_path)
        snap = TrackIdentificationSnapshot(
            enabled=True,
            state=STATE_ANALYSING,
            status_text="Analysing",
            updated_at=time.time(),
        )
        result = _run_home(cfg_path, ti_snapshot=snap)
        assert result["track_identification"]["state"] == STATE_ANALYSING
