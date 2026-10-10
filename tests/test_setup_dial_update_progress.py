"""Setup page dial card: firmware update progress, outcome and rollback line.

JS-free source-contract checks plus card markup checks, in the style of the
other Setup page tests.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_webui_page_setup as setup

_SRC = (REPO_ROOT / "core" / "autostream_webui_page_setup.py").read_text(encoding="utf-8")


def _body(name: str) -> str:
    start = _SRC.index(f"function {name}(")
    nxt = _SRC.find("\n        function ", start + 10)
    nxt2 = _SRC.find("\n        async function ", start + 10)
    ends = [e for e in (nxt, nxt2) if e > 0]
    return _SRC[start:min(ends) if ends else len(_SRC)]


def test_started_update_is_watched_by_polling_status_endpoint():
    assert "dialWatchUpdate(card, uuid)" in _body("dialUpdateFirmware")
    watch = _body("dialWatchUpdate")
    assert "dialPollUntil(" in watch
    assert "/api/dial/update/status/" in watch


def test_poll_budget_covers_a_long_update():
    m = re.search(r"DIAL_UPDATE_BUDGET_MS = (\d+) \* (\d+) \* (\d+)", _SRC)
    assert m
    assert int(m[1]) * int(m[2]) * int(m[3]) >= 45 * 60 * 1000


def test_offline_answer_keeps_polling_as_restarting():
    watch = _body("dialWatchUpdate")
    assert "Restarting..." in watch
    assert "return false" in watch


def test_failure_wordings_present():
    text = _body("dialUpdateFailureText")
    assert "'Update to '" in text
    assert "' failed'" in text
    assert "'restored ' + prev" in text
    assert "' kept'" in text
    assert "rolled_back" in text


def test_success_and_retry_and_unknown_wordings_present():
    render = _body("dialRenderUpdateStatus")
    assert "'Updated to '" in render
    assert "Retrying update (attempt " in render
    assert "max_attempts" in render
    assert "percent" in render and "message" in render
    assert "Update status unknown" in _body("dialWatchUpdate")


def test_failure_is_rendered_as_an_error():
    render = _body("dialRenderUpdateStatus")
    assert "dialMsg(card, dialUpdateFailureText(b), false)" in render


def test_panel_open_failure_line_is_age_limited():
    fn = _body("dialShowRecentUpdateFailure")
    assert "state !== 'failed'" in fn
    assert "last_run_at" in fn
    assert "DIAL_UPDATE_STALE_MS" in fn
    assert "7 * 24 * 60 * 60 * 1000" in _SRC
    assert "dialShowRecentUpdateFailure(card); });" in _SRC


def test_card_has_progress_bar_markup_and_style():
    html = setup._dial_card_html(uuid="u1", authorized=True, online=True)
    assert "dial-update-bar" in html
    assert "dial-update-bar-fill" in html
    assert ".dial-update-bar-fill" in _SRC


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_failure_and_progress_text_behaviour():
    start = _SRC.index("function dialUpdateFailureText(")
    end = _SRC.index("function dialWatchUpdate(")
    js = _SRC[start:end].replace("{{", "{").replace("}}", "}").replace("\\u2013", "\u2013")
    script = (
        "var out=[];function dialMsg(c,t,ok){out.push([t,ok]);}"
        "function dialUpdateBar(){}\n" + js + "\n"
        "dialRenderUpdateStatus(null,{state:'failed',tag:'0.7.0',previous_tag:'0.6.0',rolled_back:true});"
        "dialRenderUpdateStatus(null,{state:'failed',tag:'0.7.0',previous_tag:'0.6.0',rolled_back:false});"
        "dialRenderUpdateStatus(null,{state:'complete',tag:'0.7.0'});"
        "dialRenderUpdateStatus(null,{state:'running',percent:40,message:'Installing',attempt:2,max_attempts:4});"
        "dialRenderUpdateStatus(null,{state:'running',phase:'reboot'});"
        "console.log(JSON.stringify(out));"
    )
    r = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    import json
    out = json.loads(r.stdout)
    assert out[0] == ["Update to 0.7.0 failed – restored 0.6.0", False]
    assert out[1] == ["Update to 0.7.0 failed – 0.6.0 kept", False]
    assert out[2] == ["Updated to 0.7.0", True]
    assert out[3] == ["Retrying update (attempt 2 of 4) - Updating... 40% - Installing", True]
    assert out[4] == ["Restarting...", True]
