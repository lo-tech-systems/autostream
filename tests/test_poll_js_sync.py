"""Guard: nginx/static/poll.js must stay byte-identical to POLL_JS.

The shared Poller helper is served by
nginx as a static file (nginx/static/poll.js), while POLL_JS remains the
source of truth in autostream_webui_assets.py -- mirroring the
theme.css/STYLE_CSS drift-guard convention (see test_theme_css_sync.py).
Both copies must never drift: edit POLL_JS, then regenerate the static
file from it (or vice versa) in the same change.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "core"))

from autostream_webui_assets import POLL_JS  # noqa: E402

POLL_JS_PATH = REPO_ROOT / "nginx" / "static" / "poll.js"


def test_poll_js_matches_constant():
    served = POLL_JS_PATH.read_text(encoding="utf-8")
    assert served == POLL_JS, (
        "nginx/static/poll.js has drifted from POLL_JS in "
        "autostream_webui_assets.py; the two must be byte-identical "
        "(see this test's module docstring)."
    )
