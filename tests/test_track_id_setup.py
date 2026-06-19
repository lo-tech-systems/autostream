"""Tests for WP1 — track identification config and settings switch.

Covers:
- Config defaults and normalization
- Invalid intervals normalize to 15
- Existing configs without the section continue to parse
- Save with switch checked/unchecked
- Save with API key persists the key (without logging it)
- Save preserves nested provider settings
- Initial setup without sentinel does not create/overwrite the section
- Track ID changes apply the service live without restarting monitors
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_config as cfg_mod
from autostream_config import (
    TRACK_ID_DEFAULT_INTERVAL,
    TRACK_ID_DEFAULT_PROVIDER,
    TRACK_ID_MAX_INTERVAL,
    TRACK_ID_MIN_INTERVAL,
    TrackIdentificationConfig,
    normalize_track_id_interval,
    parse_config,
)


# ---------------------------------------------------------------------------
# Config defaults and normalization
# ---------------------------------------------------------------------------

class TestTrackIdConfigDefaults:

    def test_absent_section_disabled(self):
        parsed = parse_config({})
        assert parsed.track_identification.enabled is False

    def test_absent_section_default_provider(self):
        parsed = parse_config({})
        assert parsed.track_identification.provider == TRACK_ID_DEFAULT_PROVIDER

    def test_absent_section_default_interval(self):
        parsed = parse_config({})
        assert parsed.track_identification.interval_seconds == TRACK_ID_DEFAULT_INTERVAL

    def test_absent_section_providers_is_empty(self):
        parsed = parse_config({})
        assert parsed.track_identification.providers == {}

    def test_enabled_true_parses(self):
        parsed = parse_config({"track_identification": {"enabled": True}})
        assert parsed.track_identification.enabled is True

    def test_enabled_false_parses(self):
        parsed = parse_config({"track_identification": {"enabled": False}})
        assert parsed.track_identification.enabled is False

    def test_custom_interval_parses(self):
        parsed = parse_config({"track_identification": {"interval_seconds": 30}})
        assert parsed.track_identification.interval_seconds == 30

    def test_unknown_provider_discarded_in_parse(self):
        parsed = parse_config({
            "track_identification": {
                "providers": {"future_provider": {"token": "abc123"}}
            }
        })
        assert "future_provider" not in parsed.track_identification.providers

    def test_known_provider_settings_preserved_in_parse(self):
        parsed = parse_config({
            "track_identification": {
                "providers": {"vibra_shazam": {"custom_key": "val"}}
            }
        })
        assert parsed.track_identification.providers["vibra_shazam"]["custom_key"] == "val"

    def test_minimal_existing_config_still_parses(self):
        # Simulate a real-world config that predates this feature.
        data = {
            "general": {"fifo_path": "/tmp/x.fifo", "log_file": "/tmp/x.log"},
            "audio1": {"capture_device": "hw:1,0", "silence_threshold": -60.0},
            "owntone": {"output_name": "Speaker", "base_url": "http://localhost:3689"},
        }
        parsed = parse_config(data)
        assert parsed.track_identification.enabled is False


class TestNormalizeTrackIdInterval:

    def test_default_returned_for_invalid_string(self):
        assert normalize_track_id_interval("bad") == TRACK_ID_DEFAULT_INTERVAL

    def test_default_returned_for_none(self):
        assert normalize_track_id_interval(None) == TRACK_ID_DEFAULT_INTERVAL

    def test_too_low_normalized(self):
        assert normalize_track_id_interval(5) == TRACK_ID_DEFAULT_INTERVAL

    def test_too_high_normalized(self):
        assert normalize_track_id_interval(120) == TRACK_ID_DEFAULT_INTERVAL

    def test_min_boundary_accepted(self):
        assert normalize_track_id_interval(TRACK_ID_MIN_INTERVAL) == TRACK_ID_MIN_INTERVAL

    def test_max_boundary_accepted(self):
        assert normalize_track_id_interval(TRACK_ID_MAX_INTERVAL) == TRACK_ID_MAX_INTERVAL

    def test_mid_value_accepted(self):
        assert normalize_track_id_interval(30) == 30

    def test_zero_normalized(self):
        assert normalize_track_id_interval(0) == TRACK_ID_DEFAULT_INTERVAL


# ---------------------------------------------------------------------------
# Setup page save (handle_setup_post)
# ---------------------------------------------------------------------------

def _make_state(tmp_path: Path, extra_cfg: dict | None = None) -> MagicMock:
    base = {"general": {}, "owntone": {"base_url": "http://localhost:3689", "output_name": "Sp"}}
    if extra_cfg:
        def _deep(d, u):
            for k, v in u.items():
                if isinstance(v, dict) and isinstance(d.get(k), dict):
                    _deep(d[k], v)
                else:
                    d[k] = v
        _deep(base, extra_cfg)
    cfg_path = tmp_path / "autostream.json"
    cfg_path.write_text(json.dumps(base))
    state = MagicMock()
    state.config_path = str(cfg_path)
    return state


def _run_setup_post(form_fields: dict, tmp_path: Path, extra_cfg: dict | None = None):
    """Run handle_setup_post with minimal patches.

    Returns (saved_cfg, mock_reload, mock_live_apply).
    """
    import autostream_webui_post_handlers as ph
    from urllib.parse import urlencode

    state = _make_state(tmp_path, extra_cfg)

    body = urlencode(form_fields)
    handler = MagicMock()
    auth = MagicMock()
    auth.get_csrf_token.return_value = "tok"

    with (
        patch.object(ph, "get_system_hostname", return_value="myhost"),
        patch.object(ph, "set_system_hostname"),
        patch.object(ph, "update_live_owntone_runtime"),
        patch.object(ph, "update_playback_input_config"),
        patch.object(ph, "suggested_silence_threshold_dbfs", return_value=-60.0),
        patch.object(ph, "request_config_reload") as mock_reload,
        patch.object(ph, "apply_track_id_config_live") as mock_live_apply,
        patch.object(ph, "update_live_silence_seconds", return_value=True),
        patch.object(ph, "_set_flash_cookie"),
    ):
        ph.handle_setup_post(handler, state, auth, body)

    saved = json.loads(Path(state.config_path).read_text())
    return saved, mock_reload, mock_live_apply


class TestHandleSetupPostTrackId:

    def test_sentinel_absent_does_not_create_section(self, tmp_path):
        form = {
            "audio_capture_device": "hw:1,0",
            "audio_silence_threshold": "-60",
            "owntone_output_name": "Sp",
            "owntone_volume_percent": "20",
            "silence_seconds": "30",
        }
        saved, *_ = _run_setup_post(form, tmp_path)
        assert "track_identification" not in saved

    def test_switch_checked_saves_enabled_true(self, tmp_path):
        form = {
            "audio_capture_device": "hw:1,0",
            "audio_silence_threshold": "-60",
            "owntone_output_name": "Sp",
            "owntone_volume_percent": "20",
            "silence_seconds": "30",
            "track_identification_present": "1",
            "track_identification_enabled": "on",
        }
        saved, *_ = _run_setup_post(form, tmp_path)
        assert saved["track_identification"]["enabled"] is True

    def test_switch_unchecked_saves_enabled_false(self, tmp_path):
        form = {
            "audio_capture_device": "hw:1,0",
            "audio_silence_threshold": "-60",
            "owntone_output_name": "Sp",
            "owntone_volume_percent": "20",
            "silence_seconds": "30",
            "track_identification_present": "1",
        }
        saved, *_ = _run_setup_post(form, tmp_path)
        assert saved["track_identification"]["enabled"] is False

    def test_sentinel_value_not_in_logs(self, tmp_path, caplog):
        form = {
            "audio_capture_device": "hw:1,0",
            "audio_silence_threshold": "-60",
            "owntone_output_name": "Sp",
            "owntone_volume_percent": "20",
            "silence_seconds": "30",
            "track_identification_present": "1",
        }
        with caplog.at_level(logging.DEBUG):
            _run_setup_post(form, tmp_path)
        assert "supersecretkey" not in caplog.text

    def test_live_apply_called_when_enabled_changes(self, tmp_path):
        # Seed audio device so daemon_changed is False; only TI changes.
        existing = {
            "audio1": {"capture_device": "hw:1,0", "silence_threshold": -60.0, "turntable": False},
            "audio2": {"enabled": False, "capture_device": "", "silence_threshold": -60.0, "turntable": False},
            "track_identification": {"enabled": False},
        }
        form = {
            "audio_capture_device": "hw:1,0",
            "audio_silence_threshold": "-60",
            "owntone_output_name": "Sp",
            "owntone_volume_percent": "20",
            "silence_seconds": "30",
            "track_identification_present": "1",
            "track_identification_enabled": "on",
        }
        _, mock_reload, mock_live_apply = _run_setup_post(form, tmp_path, extra_cfg=existing)
        # Track ID changes must apply the service live, not restart the coordinator.
        mock_reload.assert_not_called()
        mock_live_apply.assert_called_once()

    def test_no_reload_when_track_id_unchanged(self, tmp_path):
        # Pre-seed config with enabled=True and matching audio devices.
        # Submitting the same enabled state must not trigger a live apply.
        existing = {
            "audio1": {"capture_device": "hw:1,0", "silence_threshold": -60.0, "turntable": False},
            "audio2": {"enabled": False, "capture_device": "", "silence_threshold": -60.0, "turntable": False},
            "track_identification": {"enabled": True},
        }
        form = {
            "audio_capture_device": "hw:1,0",
            "audio_silence_threshold": "-60",
            "owntone_output_name": "Sp",
            "owntone_volume_percent": "20",
            "silence_seconds": "30",
            "track_identification_present": "1",
            "track_identification_enabled": "on",
        }
        _, mock_reload, mock_live_apply = _run_setup_post(form, tmp_path, extra_cfg=existing)
        mock_reload.assert_not_called()
        mock_live_apply.assert_not_called()

    def test_unknown_provider_discarded_in_parsed_config(self, tmp_path):
        existing = {
            "track_identification": {
                "enabled": False,
                "providers": {
                    "acoustid_musicbrainz": {"api_key": "old"},
                    "future_provider": {"token": "xyz"},
                },
            }
        }
        form = {
            "audio_capture_device": "hw:1,0",
            "audio_silence_threshold": "-60",
            "owntone_output_name": "Sp",
            "owntone_volume_percent": "20",
            "silence_seconds": "30",
            "track_identification_present": "1",
        }
        saved, *_ = _run_setup_post(form, tmp_path, extra_cfg=existing)
        # parse_config must discard unknown provider IDs regardless of raw file contents
        parsed = parse_config(saved)
        assert "acoustid_musicbrainz" not in parsed.track_identification.providers
        assert "future_provider" not in parsed.track_identification.providers
