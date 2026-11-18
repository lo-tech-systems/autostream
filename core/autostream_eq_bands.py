"""autostream_eq_bands.py -- the fixed equaliser band tables.

A leaf module (standard library only): the band definitions sent to
autostream_monitor for the input equaliser and the output parametric
equaliser, and the table of output bands the Equaliser page labels.
"""


# Fixed output PEQ band definitions.  The stored field names (peq1_db ... peq6_db)
# are generic so the storage model can survive a future move to user-configurable
# parametrics.  This table is the single source of truth for both the band
# parameters sent to autostream_monitor and the labels shown on the Equaliser page.
OUTPUT_PEQ_BANDS: list[dict] = [
    {"key": "peq1_db", "label": "40Hz",   "type": "low_shelf",  "freq_hz":    40.0, "q": 0.5},
    {"key": "peq2_db", "label": "100Hz",  "type": "peak",       "freq_hz":   100.0, "q": 0.707},
    {"key": "peq3_db", "label": "300Hz",  "type": "peak",       "freq_hz":   300.0, "q": 0.707},
    {"key": "peq4_db", "label": "1kHz",   "type": "peak",       "freq_hz":  1000.0, "q": 0.707},
    {"key": "peq5_db", "label": "4kHz",   "type": "peak",       "freq_hz":  4000.0, "q": 0.707},
    {"key": "peq6_db", "label": "10kHz",  "type": "high_shelf", "freq_hz": 10000.0, "q": 0.5},
]


def build_monitor_eq_bands(
    eq_40hz_db: float,
    eq_100hz_db: float,
    eq_8khz_db: float,
) -> list[dict]:
    """Return the fixed three-band EQ definition expected by autostream_monitor.

    For shelf filters, the monitor currently uses the RBJ cookbook shelf
    formula wired through the generic ``q`` field. A value of ``q=0.707`` is
    equivalent to a shelf slope of ``S=1.0``.
    """
    return [
        {"type": "peak", "freq_hz": 40.0, "gain_db": float(eq_40hz_db), "q": 0.707},
        {"type": "low_shelf", "freq_hz": 100.0, "gain_db": float(eq_100hz_db), "q": 0.5},
        {"type": "high_shelf", "freq_hz": 8000.0, "gain_db": float(eq_8khz_db), "q": 0.5},
    ]


def build_output_eq_bands(
    peq1_db: float,
    peq2_db: float,
    peq3_db: float,
    peq4_db: float,
    peq5_db: float,
    peq6_db: float,
) -> list[dict]:
    """Return the six-band output EQ definition expected by autostream_monitor."""
    values = [peq1_db, peq2_db, peq3_db, peq4_db, peq5_db, peq6_db]
    return [
        {"type": b["type"], "freq_hz": b["freq_hz"], "gain_db": float(db), "q": b["q"]}
        for b, db in zip(OUTPUT_PEQ_BANDS, values)
    ]
