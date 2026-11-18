"""Tests for dial_eq_model.py: the bass and treble view of the six output bands.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
for _p in (str(REPO_ROOT / "dial"), str(REPO_ROOT / "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import autostream_eq_bands as eq_bands
import dial_eq_model as m


def test_the_band_ids_come_from_the_appliance_table():
    assert m.BAND_IDS == ("peq1", "peq2", "peq3", "peq4", "peq5", "peq6")


def test_the_band_limit_is_the_appliance_clamp():
    assert m.EQ_BAND_LIMIT_DB == int(eq_bands.OUTPUT_EQ_DB_MAX) == -int(eq_bands.OUTPUT_EQ_DB_MIN)


def test_a_band_writes_its_own_field_held_to_the_band_range():
    assert m.eq_fields({"peq3": 2, "peq6": -20}) == (("peq3_db", 2.0), ("peq6_db", -12))


def test_bass_writes_the_two_lowest_bands_equally():
    assert m.eq_fields({"bass": 9}) == (("peq1_db", 6), ("peq2_db", 6))


def test_treble_writes_the_top_band_and_half_of_it_below():
    assert m.eq_fields({"treble": -4}) == (("peq6_db", -4.0), ("peq5_db", -2.0))


def test_an_unknown_control_is_refused():
    with pytest.raises(ValueError):
        m.eq_fields({"mid": 1})


@pytest.mark.parametrize("gains, expected", [
    ([0, 0, 0, 0, 0, 0], (0, 0)),
    ([3.4, 9, 9, 9, 9, -2.6], (3, -3)),
    ([12, 0, 0, 0, 0, -12], (6, -6)),
])
def test_bass_and_treble_read_the_outer_bands(gains, expected):
    assert m.bass_treble(gains) == expected
