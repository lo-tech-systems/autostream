"""Tests for autostream_config.py — load_state error handling."""
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

import autostream_config as c


class TestLoadState:

    def test_missing_file_returns_empty_dict(self, tmp_path):
        """FileNotFoundError → silently returns {}."""
        result = c.load_state(str(tmp_path / "absent.json"))
        assert result == {}

    def test_valid_state_returned(self, tmp_path):
        """Valid JSON dict is returned unchanged."""
        p = tmp_path / "state.json"
        p.write_text('{"auth": {"pin_override": "abc"}}')
        result = c.load_state(str(p))
        assert result == {"auth": {"pin_override": "abc"}}

    def test_non_dict_root_returns_empty_dict(self, tmp_path):
        """JSON array at root is treated as absent (non-dict root → {})."""
        p = tmp_path / "state.json"
        p.write_text('[1, 2, 3]')
        result = c.load_state(str(p))
        assert result == {}

    def test_malformed_json_propagates(self, tmp_path):
        """JSONDecodeError is not swallowed — malformed state file surfaces the error."""
        p = tmp_path / "state.json"
        p.write_text('{bad json}')
        with pytest.raises(json.JSONDecodeError):
            c.load_state(str(p))

    def test_permission_error_propagates(self, tmp_path):
        """OSError (e.g. permission denied) is not swallowed."""
        p = tmp_path / "state.json"
        p.write_text('{}')
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            with pytest.raises(OSError):
                c.load_state(str(p))


class TestOutputsSettings:
    def parse(self, data):
        return c.parse_config(data, high_perf=False)

    def test_an_absent_section_gives_the_defaults(self):
        o = self.parse({}).outputs
        assert o.device_pause_scope == c.DEVICE_PAUSE_SCOPE_DEFAULT
        assert o.pause_off_seconds == c.PAUSE_OFF_SECONDS_DEFAULT == 300
        assert c.DEVICE_PAUSE_SCOPE_DEFAULT in c.DEVICE_PAUSE_SCOPES

    def test_the_default_scope_constant_is_the_dataclass_default(self):
        assert c.OutputsConfig().device_pause_scope == c.DEVICE_PAUSE_SCOPE_DEFAULT

    @pytest.mark.parametrize("scope", ["output", "all", "off_all"])
    def test_each_scope_is_kept(self, scope):
        assert self.parse({"outputs": {"device_pause_scope": scope}}).outputs.device_pause_scope == scope

    def test_the_retired_keep_playing_choice_reads_as_that_speaker_only(self):
        assert self.parse({"outputs": {"device_pause_scope": "ignore"}}).outputs.device_pause_scope == "output"
        assert c.DEVICE_PAUSE_SCOPE_DEFAULT == "output"

    @pytest.mark.parametrize("bad", ["", "everything", None, 3, True, ["all"]])
    def test_an_unknown_scope_is_the_default(self, bad):
        got = self.parse({"outputs": {"device_pause_scope": bad}}).outputs.device_pause_scope
        assert got == c.DEVICE_PAUSE_SCOPE_DEFAULT

    def test_the_scope_ignores_case_and_spaces(self):
        assert self.parse({"outputs": {"device_pause_scope": " All "}}).outputs.device_pause_scope == "all"

    @pytest.mark.parametrize("value,expected", [
        (60, 60), (30, 30), (3600, 3600), (5, 30), (99999, 3600), ("90", 90), (120.9, 120),
        ("soon", 300), (None, 300), (True, 300), (float("nan"), 300), (float("inf"), 300),
    ])
    def test_the_pause_timeout_is_clamped_or_defaulted(self, value, expected):
        assert self.parse({"outputs": {"pause_off_seconds": value}}).outputs.pause_off_seconds == expected

    def test_a_saved_play_guard_from_an_earlier_release_is_not_read(self):
        o = self.parse({"outputs": {"play_after_metadata_ignore_seconds": 10}}).outputs
        assert not hasattr(o, "play_after_metadata_ignore_seconds")

    def test_speaker_volume_applies_to_all_is_off_by_default(self):
        assert c.OutputsConfig().speaker_volume_applies_to_all is False
        assert self.parse({}).outputs.speaker_volume_applies_to_all is False

    @pytest.mark.parametrize("value,expected", [
        (True, True), (False, False), ("true", False), (1, False), ("yes", False), (None, False),
    ])
    def test_speaker_volume_applies_to_all_takes_only_a_json_true(self, value, expected):
        got = self.parse({"outputs": {"speaker_volume_applies_to_all": value}})
        assert got.outputs.speaker_volume_applies_to_all is expected

    def test_a_section_that_is_not_an_object_gives_the_defaults(self):
        assert self.parse({"outputs": "all"}).outputs == c.OutputsConfig()


class TestIncludeTvSetting:
    def test_it_is_empty_when_absent(self):
        assert dict(c.parse_config({}, high_perf=False).owntone.include_tv) == {}

    def test_it_keeps_only_boolean_choices_with_stripped_keys(self):
        raw = {"owntone": {"include_tv": {" 11 ": False, "12": True, "13": "no", "14": 0, "": False}}}
        assert dict(c.parse_config(raw, high_perf=False).owntone.include_tv) == {"11": False, "12": True}

    def test_a_section_that_is_not_an_object_is_empty(self):
        assert dict(c.parse_config({"owntone": {"include_tv": [1]}}, high_perf=False).owntone.include_tv) == {}
