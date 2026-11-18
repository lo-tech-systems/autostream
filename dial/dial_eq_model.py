"""dial_eq_model.py -- the equaliser as the dial addresses it.

The appliance holds six output bands (peq1 to peq6), each clamped to
+/-12 dB, and knows nothing of bass or treble. The dial adds two controls of
its own on top of them:

  * writing: bass sets the two lowest bands equally; treble sets the highest
    in full and the band below it by half, both held to +/-6 dB;
  * reading: bass is the lowest band and treble the highest, rounded to whole
    dB and held to the same range.

The two rules are not inverses: a band set by some other client shows
through its anchor band only.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from typing import Mapping

import autostream_eq_bands as eq_bands

from dial_values import clamp

# The six output band ids, lowest first.
BAND_IDS = tuple(b["key"].removesuffix("_db") for b in eq_bands.OUTPUT_PEQ_BANDS)

# The two controls every EQ capability exposes; a six-band appliance lists its
# own bands before them.
DERIVED_EQ_IDS = ("bass", "treble")

# The band range an equaliser write is held to, and the narrower one the
# bass and treble controls use.
EQ_BAND_LIMIT_DB = 12
EQ_BASS_TREBLE_LIMIT_DB = 6

# The share of a treble move that goes to the 4 kHz band; the 10 kHz band
# takes all of it.
TREBLE_SECONDARY_SCALE = 0.5


def eq_fields(gains: Mapping[str, float]) -> tuple[tuple[str, float], ...]:
    """The band fields to write for gains keyed by control id: a band id
    (peq1 to peq6) writes its own field, held to the band range; bass writes
    the two lowest bands equally and treble the highest in full and the band
    below it by half, both held to the bass and treble range. Raises
    ValueError for an id that is none of these."""
    out: list[tuple[str, float]] = []
    for band_id, raw in gains.items():
        value = float(raw)
        if band_id in BAND_IDS:
            out.append((f"{band_id}_db", clamp(value, -EQ_BAND_LIMIT_DB, EQ_BAND_LIMIT_DB)))
            continue
        held = clamp(value, -EQ_BASS_TREBLE_LIMIT_DB, EQ_BASS_TREBLE_LIMIT_DB)
        if band_id == "bass":
            out += [("peq1_db", held), ("peq2_db", held)]
        elif band_id == "treble":
            out += [("peq6_db", held), ("peq5_db", held * TREBLE_SECONDARY_SCALE)]
        else:
            raise ValueError(f"unknown equaliser control: {band_id!r}")
    return tuple(out)


def bass_treble(gains: list) -> tuple[int, int]:
    """(bass, treble): the 40 Hz and 10 kHz bands rounded to whole dB and
    held to the dial's own range."""
    def held(v):
        return clamp(int(round(v)), -EQ_BASS_TREBLE_LIMIT_DB, EQ_BASS_TREBLE_LIMIT_DB)
    return held(gains[0]), held(gains[-1])
