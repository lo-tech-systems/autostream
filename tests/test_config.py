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
