"""Regression tests for the eq_8khz_db migration (WP11).

Covers the four key scenarios:
- new key only  → reads eq_8khz_db
- old key only  → falls back to eq_10khz_db
- both keys     → new key takes precedence; malformed old key is not evaluated
- new key only after migration → eq_10khz_db absent
"""
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_config import _parse_audio_input_config


def _section(**kwargs) -> dict:
    """Build a minimal audio section dict with sensible defaults."""
    defaults = {
        "capture_device": "hw:1,0",
        "silence_threshold": -66.0,
        "turntable": False,
        "stylus_life_hours": 500,
        "belt_life_hours": 0,
        "bearing_life_hours": 0,
        "belt_life_years": 0,
        "bearing_life_years": 0,
        "gain_db": 0.0,
        "eq_40hz_db": 0.0,
        "eq_100hz_db": 0.0,
    }
    defaults.update(kwargs)
    return defaults


class TestEqMigration:

    def test_new_key_only(self):
        r = _parse_audio_input_config(_section(eq_8khz_db=4.0))
        assert r.eq_8khz_db == pytest.approx(4.0)

    def test_old_key_only_fallback(self):
        r = _parse_audio_input_config(_section(eq_10khz_db=3.5))
        assert r.eq_8khz_db == pytest.approx(3.5)

    def test_both_keys_new_wins(self):
        r = _parse_audio_input_config(_section(eq_8khz_db=5.0, eq_10khz_db=2.0))
        assert r.eq_8khz_db == pytest.approx(5.0)

    def test_both_keys_malformed_old_key_is_not_evaluated(self):
        """New key present → old key (even if malformed) must not be parsed."""
        r = _parse_audio_input_config(_section(eq_8khz_db=5.0, eq_10khz_db="not_a_number"))
        assert r.eq_8khz_db == pytest.approx(5.0)

    def test_neither_key_defaults_to_zero(self):
        r = _parse_audio_input_config(_section())
        assert r.eq_8khz_db == pytest.approx(0.0)

    def test_new_key_only_after_migration(self):
        """After migration the legacy key is absent; only eq_8khz_db remains."""
        section = _section(eq_8khz_db=3.0)
        assert "eq_10khz_db" not in section
        r = _parse_audio_input_config(section)
        assert r.eq_8khz_db == pytest.approx(3.0)

    def test_old_key_malformed_without_new_key_raises(self):
        """Without the new key a malformed old value should raise ValueError."""
        with pytest.raises(ValueError):
            _parse_audio_input_config(_section(eq_10khz_db="not_a_number"))
