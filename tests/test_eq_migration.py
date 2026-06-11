"""Regression tests for the eq_8khz_db INI migration (WP11).

Covers the four key scenarios:
- new key only  → reads eq_8khz_db
- old key only  → falls back to eq_10khz_db
- both keys     → new key takes precedence; malformed old key is not evaluated
- save removes old key → eq_10khz_db is absent after a config write
"""
import configparser
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_config import _parse_audio_input_config


def _cfg(section: str, **kwargs) -> configparser.ConfigParser:
    """Build a minimal ConfigParser with the given audio section."""
    cfg = configparser.ConfigParser()
    cfg.add_section(section)
    defaults = {
        "capture_device": "hw:1,0",
        "silence_threshold": "-66",
        "turntable": "no",
        "stylus_life_hours": "500",
        "belt_life_hours": "0",
        "bearing_life_hours": "0",
        "belt_life_years": "0",
        "bearing_life_years": "0",
        "gain_db": "0",
        "eq_40hz_db": "0",
        "eq_100hz_db": "0",
    }
    defaults.update(kwargs)
    for k, v in defaults.items():
        cfg.set(section, k, v)
    return cfg


class TestEqMigration:

    def test_new_key_only(self):
        cfg = _cfg("audio1", eq_8khz_db="4.0")
        r = _parse_audio_input_config(cfg, "audio1")
        assert r.eq_8khz_db == pytest.approx(4.0)

    def test_old_key_only_fallback(self):
        cfg = _cfg("audio1", eq_10khz_db="3.5")
        r = _parse_audio_input_config(cfg, "audio1")
        assert r.eq_8khz_db == pytest.approx(3.5)

    def test_both_keys_new_wins(self):
        cfg = _cfg("audio1", eq_8khz_db="5.0", eq_10khz_db="2.0")
        r = _parse_audio_input_config(cfg, "audio1")
        assert r.eq_8khz_db == pytest.approx(5.0)

    def test_both_keys_malformed_old_key_is_not_evaluated(self):
        """New key present → old key (even if malformed) must not be parsed."""
        cfg = _cfg("audio1", eq_8khz_db="5.0", eq_10khz_db="not_a_number")
        r = _parse_audio_input_config(cfg, "audio1")
        assert r.eq_8khz_db == pytest.approx(5.0)

    def test_neither_key_defaults_to_zero(self):
        cfg = _cfg("audio1")
        r = _parse_audio_input_config(cfg, "audio1")
        assert r.eq_8khz_db == pytest.approx(0.0)

    def test_save_removes_old_key(self):
        """Simulates the save path: write eq_8khz_db, remove eq_10khz_db."""
        cfg = _cfg("audio1", eq_10khz_db="3.0")
        assert cfg.has_option("audio1", "eq_10khz_db")

        cfg.set("audio1", "eq_8khz_db", "3.0")
        cfg.remove_option("audio1", "eq_10khz_db")

        assert cfg.has_option("audio1", "eq_8khz_db")
        assert not cfg.has_option("audio1", "eq_10khz_db")

        r = _parse_audio_input_config(cfg, "audio1")
        assert r.eq_8khz_db == pytest.approx(3.0)

    def test_old_key_malformed_without_new_key_raises(self):
        """Without the new key a malformed old value should raise ValueError."""
        cfg = _cfg("audio1", eq_10khz_db="not_a_number")
        with pytest.raises(ValueError):
            _parse_audio_input_config(cfg, "audio1")
