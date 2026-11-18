"""Tests for track-identification configuration and the settings switch.

Covers:
- Config defaults and normalization
- Invalid intervals normalize to 15
- Existing configs without the section continue to parse
- Unknown provider ids in a stored section are discarded
- The Setup card describes track-change re-identification
"""
from __future__ import annotations

import sys
from pathlib import Path
import _source_text

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_config import (
    TRACK_ID_DEFAULT_ANALYSIS_LEAD_IN_SECONDS,
    TRACK_ID_DEFAULT_PROVIDER,
    TRACK_ID_DEFAULT_REFRESH_SECONDS,
    TRACK_ID_DEFAULT_RETRY_SECONDS,
    TRACK_ID_DEFAULT_SNAPSHOT_SECONDS,
    TRACK_ID_DEFAULT_TRACK_CHANGE_SILENCE_SECONDS,
    TRACK_ID_MAX_ANALYSIS_LEAD_IN_SECONDS,
    TRACK_ID_MAX_REFRESH_SECONDS,
    TRACK_ID_MAX_RETRY_SECONDS,
    TRACK_ID_MAX_SNAPSHOT_SECONDS,
    TRACK_ID_MAX_TRACK_CHANGE_SILENCE_SECONDS,
    TRACK_ID_MIN_ANALYSIS_LEAD_IN_SECONDS,
    TRACK_ID_MIN_REFRESH_SECONDS,
    TRACK_ID_MIN_RETRY_SECONDS,
    TRACK_ID_MIN_SNAPSHOT_SECONDS,
    TRACK_ID_MIN_TRACK_CHANGE_SILENCE_SECONDS,
    TrackIdentificationConfig,
    normalize_track_id_analysis_lead_in_seconds,
    normalize_track_id_refresh_seconds,
    normalize_track_id_retry_seconds,
    normalize_track_id_snapshot_seconds,
    normalize_track_id_track_change_silence_seconds,
    parse_config,
)
import autostream_core as core


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

    def test_absent_section_default_scheduling(self):
        ti = parse_config({}).track_identification
        assert ti.analysis_lead_in_seconds == TRACK_ID_DEFAULT_ANALYSIS_LEAD_IN_SECONDS
        assert ti.snapshot_seconds == TRACK_ID_DEFAULT_SNAPSHOT_SECONDS
        assert ti.retry_seconds == TRACK_ID_DEFAULT_RETRY_SECONDS
        assert ti.refresh_seconds == TRACK_ID_DEFAULT_REFRESH_SECONDS
        assert ti.track_change_silence_seconds == TRACK_ID_DEFAULT_TRACK_CHANGE_SILENCE_SECONDS

    def test_absent_section_providers_is_empty(self):
        parsed = parse_config({})
        assert parsed.track_identification.providers == {}

    def test_enabled_true_parses(self):
        parsed = parse_config({"track_identification": {"enabled": True}})
        assert parsed.track_identification.enabled is True

    def test_enabled_false_parses(self):
        parsed = parse_config({"track_identification": {"enabled": False}})
        assert parsed.track_identification.enabled is False

    def test_custom_scheduling_parses(self):
        parsed = parse_config({"track_identification": {
            "analysis_lead_in_seconds": 5,
            "snapshot_seconds": 10,
            "retry_seconds": 10,
            "refresh_seconds": 120,
            "track_change_silence_seconds": 2.0,
        }})
        ti = parsed.track_identification
        assert ti.analysis_lead_in_seconds == 5
        assert ti.snapshot_seconds == 10
        assert ti.retry_seconds == 10
        assert ti.refresh_seconds == 120
        assert ti.track_change_silence_seconds == 2.0

    def test_interval_seconds_discarded(self):
        # interval_seconds is a removed field; it must not appear on the config.
        parsed = parse_config({"track_identification": {"interval_seconds": 30}})
        assert not hasattr(parsed.track_identification, "interval_seconds")

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
        data = {
            "general": {"fifo_path": "/tmp/x.fifo", "log_file": "/tmp/x.log"},
            "audio1": {"capture_device": "hw:1,0", "silence_threshold": -60.0},
            "owntone": {"output_name": "Speaker", "base_url": "http://localhost:3689"},
        }
        parsed = parse_config(data)
        assert parsed.track_identification.enabled is False


class TestNormalizeTrackIdScheduling:

    def test_analysis_lead_in_clamps_to_min(self):
        assert normalize_track_id_analysis_lead_in_seconds(-5) == TRACK_ID_MIN_ANALYSIS_LEAD_IN_SECONDS

    def test_analysis_lead_in_clamps_to_max(self):
        assert normalize_track_id_analysis_lead_in_seconds(999) == TRACK_ID_MAX_ANALYSIS_LEAD_IN_SECONDS

    def test_analysis_lead_in_min_boundary_accepted(self):
        assert normalize_track_id_analysis_lead_in_seconds(TRACK_ID_MIN_ANALYSIS_LEAD_IN_SECONDS) == TRACK_ID_MIN_ANALYSIS_LEAD_IN_SECONDS

    def test_analysis_lead_in_max_boundary_accepted(self):
        assert normalize_track_id_analysis_lead_in_seconds(TRACK_ID_MAX_ANALYSIS_LEAD_IN_SECONDS) == TRACK_ID_MAX_ANALYSIS_LEAD_IN_SECONDS

    def test_analysis_lead_in_invalid_uses_default(self):
        assert normalize_track_id_analysis_lead_in_seconds("bad") == TRACK_ID_DEFAULT_ANALYSIS_LEAD_IN_SECONDS

    def test_analysis_lead_in_none_uses_default(self):
        assert normalize_track_id_analysis_lead_in_seconds(None) == TRACK_ID_DEFAULT_ANALYSIS_LEAD_IN_SECONDS

    def test_snapshot_seconds_clamps_to_min(self):
        assert normalize_track_id_snapshot_seconds(1) == TRACK_ID_MIN_SNAPSHOT_SECONDS

    def test_snapshot_seconds_clamps_to_max(self):
        assert normalize_track_id_snapshot_seconds(999) == TRACK_ID_MAX_SNAPSHOT_SECONDS

    def test_snapshot_seconds_min_boundary_accepted(self):
        assert normalize_track_id_snapshot_seconds(TRACK_ID_MIN_SNAPSHOT_SECONDS) == TRACK_ID_MIN_SNAPSHOT_SECONDS

    def test_snapshot_seconds_max_boundary_accepted(self):
        assert normalize_track_id_snapshot_seconds(TRACK_ID_MAX_SNAPSHOT_SECONDS) == TRACK_ID_MAX_SNAPSHOT_SECONDS

    def test_snapshot_seconds_invalid_uses_default(self):
        assert normalize_track_id_snapshot_seconds("bad") == TRACK_ID_DEFAULT_SNAPSHOT_SECONDS

    def test_retry_seconds_clamps_to_min(self):
        assert normalize_track_id_retry_seconds(1) == TRACK_ID_MIN_RETRY_SECONDS

    def test_retry_seconds_clamps_to_max(self):
        assert normalize_track_id_retry_seconds(999) == TRACK_ID_MAX_RETRY_SECONDS

    def test_retry_seconds_min_boundary_accepted(self):
        assert normalize_track_id_retry_seconds(TRACK_ID_MIN_RETRY_SECONDS) == TRACK_ID_MIN_RETRY_SECONDS

    def test_retry_seconds_max_boundary_accepted(self):
        assert normalize_track_id_retry_seconds(TRACK_ID_MAX_RETRY_SECONDS) == TRACK_ID_MAX_RETRY_SECONDS

    def test_retry_seconds_invalid_uses_default(self):
        assert normalize_track_id_retry_seconds(None) == TRACK_ID_DEFAULT_RETRY_SECONDS

    def test_refresh_seconds_clamps_to_min(self):
        assert normalize_track_id_refresh_seconds(10) == TRACK_ID_MIN_REFRESH_SECONDS

    def test_refresh_seconds_clamps_to_max(self):
        assert normalize_track_id_refresh_seconds(9999) == TRACK_ID_MAX_REFRESH_SECONDS

    def test_refresh_seconds_min_boundary_accepted(self):
        assert normalize_track_id_refresh_seconds(TRACK_ID_MIN_REFRESH_SECONDS) == TRACK_ID_MIN_REFRESH_SECONDS

    def test_refresh_seconds_max_boundary_accepted(self):
        assert normalize_track_id_refresh_seconds(TRACK_ID_MAX_REFRESH_SECONDS) == TRACK_ID_MAX_REFRESH_SECONDS

    def test_refresh_seconds_invalid_uses_default(self):
        assert normalize_track_id_refresh_seconds("x") == TRACK_ID_DEFAULT_REFRESH_SECONDS

    def test_track_change_silence_clamps_to_min(self):
        assert normalize_track_id_track_change_silence_seconds(0.1) == TRACK_ID_MIN_TRACK_CHANGE_SILENCE_SECONDS

    def test_track_change_silence_clamps_to_max(self):
        assert normalize_track_id_track_change_silence_seconds(99.0) == TRACK_ID_MAX_TRACK_CHANGE_SILENCE_SECONDS

    def test_track_change_silence_min_boundary_accepted(self):
        assert normalize_track_id_track_change_silence_seconds(TRACK_ID_MIN_TRACK_CHANGE_SILENCE_SECONDS) == TRACK_ID_MIN_TRACK_CHANGE_SILENCE_SECONDS

    def test_track_change_silence_max_boundary_accepted(self):
        assert normalize_track_id_track_change_silence_seconds(TRACK_ID_MAX_TRACK_CHANGE_SILENCE_SECONDS) == TRACK_ID_MAX_TRACK_CHANGE_SILENCE_SECONDS

    def test_track_change_silence_nan_uses_default(self):
        assert normalize_track_id_track_change_silence_seconds(float("nan")) == TRACK_ID_DEFAULT_TRACK_CHANGE_SILENCE_SECONDS

    def test_track_change_silence_inf_uses_default(self):
        assert normalize_track_id_track_change_silence_seconds(float("inf")) == TRACK_ID_DEFAULT_TRACK_CHANGE_SILENCE_SECONDS

    def test_track_change_silence_invalid_uses_default(self):
        assert normalize_track_id_track_change_silence_seconds("bad") == TRACK_ID_DEFAULT_TRACK_CHANGE_SILENCE_SECONDS


# ---------------------------------------------------------------------------
# Parsing a stored section, and the Setup card text
# ---------------------------------------------------------------------------

class TestTrackIdStoredSection:
    def test_unknown_provider_ids_are_discarded_by_parse_config(self):
        raw = {
            "track_identification": {
                "enabled": False,
                "providers": {
                    "acoustid_musicbrainz": {"api_key": "old"},
                    "future_provider": {"token": "xyz"},
                },
            }
        }
        parsed = parse_config(raw)
        assert "acoustid_musicbrainz" not in parsed.track_identification.providers
        assert "future_provider" not in parsed.track_identification.providers

    def test_setup_page_card_describes_track_change_detection(self):
        """Setup page card text must describe the track-change / re-identification behaviour."""
        src = _source_text.module_text("webui.browser.setup")
        assert "re-identif" in src.lower() or "track change" in src.lower(),             "Setup card text should describe track-change re-identification behaviour"
