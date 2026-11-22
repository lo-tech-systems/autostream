"""Home page "Sample Rate Mismatch" banner and the input card's rate text.

While an input delivers a different standard rate than it was opened at and
Dynamic Rate Matching is off, the Home page shows a fixed banner that links
to that input's card on the Setup page.  The status reply carries the banner
text as a flat key; the input the banner links to is worked out by the page
from the per-input levels.  The input card's rate line (shown only with the
"Display Input Detail" preference on) says Locked, Acquiring or Mismatch.
"""
from __future__ import annotations

import contextlib
import sys
from pathlib import Path

import _source_text

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from fake_store import FakeStore
from autostream_input_status import SAMPLE_RATE_MISMATCH_BANNER_TEXT

_BANNER = "Sample Rate Mismatch: Please enable Dynamic Rate Matching"
_BANNER_OPEN = "<a id='sample-rate-warning-banner' href='/setup#input"


def _monitors(*mismatching: int):
    """Two inputs; the numbered ones report a 44.1 kHz mismatch, as the inputs
    part holds it (the banner names the lowest-numbered such input)."""
    fake = FakeStore()
    lowest = min(mismatching, default=0)
    fake.inputs(
        [fake.input_entry(n, rate_mismatch_hz=44100 if n in mismatching else 0)
         for n in (2, 1)],
        mismatch=lowest, banner=_BANNER if lowest else "")
    return contextlib.nullcontext()


# ---------------------------------------------------------------------------
# Banner text
# ---------------------------------------------------------------------------

class TestBannerText:
    def test_the_text_is_the_agreed_string(self):
        assert SAMPLE_RATE_MISMATCH_BANNER_TEXT == _BANNER


# ---------------------------------------------------------------------------
# Home page HTML
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Setup page deep link
# ---------------------------------------------------------------------------

class TestDeepLink:
    def _src(self) -> str:
        return _source_text.page_source("setup")

    def test_setup_page_script_opens_the_input_panels_for_the_hash(self):
        src = self._src()
        assert "if (location.hash === '#input' + i) openPanel('input' + i);" in src

    def test_input_panel_targets_exist(self):
        src = self._src()
        assert "cards_inputs.register_input_card(_index)" in src
        assert 'f"input{index}",' in src


# ---------------------------------------------------------------------------
# Input card rate text
# ---------------------------------------------------------------------------


