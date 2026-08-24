"""Guard: nginx/static/render_fragments.js must stay byte-identical to
RENDER_FRAGMENTS_JS.

The client-side output-card fragment renderer is served by nginx as a static file
(nginx/static/render_fragments.js), while RENDER_FRAGMENTS_JS remains the
source of truth in autostream_webui_assets.py -- mirroring the poll.js/POLL_JS
drift-guard convention (see test_poll_js_sync.py). (nginx/static/theme.css
needs no equivalent guard: it has no Python copy at all, so there is nothing
for it to drift from.) Both copies must never drift:
edit RENDER_FRAGMENTS_JS, then regenerate the static file from it (or vice
versa) in the same change.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "core"))

from autostream_webui_assets import RENDER_FRAGMENTS_JS  # noqa: E402

RENDER_FRAGMENTS_JS_PATH = REPO_ROOT / "nginx" / "static" / "render_fragments.js"


def test_render_fragments_js_matches_constant():
    served = RENDER_FRAGMENTS_JS_PATH.read_text(encoding="utf-8")
    assert served == RENDER_FRAGMENTS_JS, (
        "nginx/static/render_fragments.js has drifted from RENDER_FRAGMENTS_JS "
        "in autostream_webui_assets.py; the two must be byte-identical "
        "(see this test's module docstring)."
    )
