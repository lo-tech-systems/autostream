"""Tests for dial_display_views.py — the display's view and frame data."""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
_CORE = str(REPO_ROOT / "core")
for _p in (_DIAL, _CORE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from dial_display_views import format_mmss  # noqa: E402

# ---------------------------------------------------------------------------
# format_mmss — pure time formatting helper.
# ---------------------------------------------------------------------------

class TestFormatMmss:
    def test_zero(self):
        assert format_mmss(0) == "0:00"

    def test_under_a_minute(self):
        assert format_mmss(42) == "0:42"

    def test_exact_minute(self):
        assert format_mmss(60) == "1:00"

    def test_rounds_to_nearest_second(self):
        assert format_mmss(59.6) == "1:00"
        assert format_mmss(59.4) == "0:59"

    def test_hours_fold_into_minutes(self):
        assert format_mmss(3723) == "62:03"

    def test_negative_clamps_to_zero(self):
        assert format_mmss(-5) == "0:00"
