"""tests/test_state_live_start_buffer.py

The live read of the player's start buffer: it asks the in-memory cache with
the player's URL and returns what the cache says.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_state import live


def test_start_buffer_ms_passes_the_url_to_the_cache():
    with patch("autostream_start_buffer_cache.current_ms", return_value=1234) as src:
        assert live.start_buffer_ms("http://p") == 1234
    src.assert_called_once_with("http://p")
