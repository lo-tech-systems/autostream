"""The /auth sign-in page: what it renders and what it asks the browser to load."""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tests" / "playwright"))

from unittest.mock import MagicMock  # noqa: E402

import _page_stub  # noqa: E402
import _source_text  # noqa: E402
from autostream_auth import AuthManager  # noqa: E402
from autostream_settings import SettingsView  # noqa: E402
from autostream_webui_page_auth import send_auth_page  # noqa: E402


def _get(query: str = "", config_extra: dict | None = None, settings=True):
    handler, chunks = _page_stub._handler("/auth")
    manager = AuthManager(config_path="dummy.ini")
    with tempfile.TemporaryDirectory() as tmp:
        state = _page_stub._scratch_state(tmp, config_extra)
        if not settings:
            broken = MagicMock()
            broken.snapshot.side_effect = OSError("settings unreadable")
            state.settings = SettingsView(broken)
        send_auth_page(handler, state, manager, query)
    return b"".join(chunks).decode("utf-8"), manager, handler


def _hidden(html: str, name: str) -> str:
    return re.search(rf'<input type="hidden" id="{name}" value="([^"]*)"', html).group(1)


def test_the_nonce_in_the_page_is_the_one_just_issued():
    html, manager, handler = _get()
    nonce = _hidden(html, "nonce")
    assert nonce
    assert manager._consume_nonce(handler, nonce) is True


def test_each_visit_gets_a_fresh_nonce():
    first, _m1, _h1 = _get()
    second, _m2, _h2 = _get()
    assert _hidden(first, "nonce") != _hidden(second, "nonce")


def test_next_is_quoted_and_kept_to_a_local_path():
    html, _m, _h = _get("next=" + quote("/service?a=b c"))
    assert _hidden(html, "next") == quote("/service?a=b c", safe="/")
    html, _m, _h = _get("next=" + quote("http://elsewhere.example/"))
    assert _hidden(html, "next") == "/"


def test_the_error_banner_shows_only_after_a_failed_attempt():
    assert "Incorrect PIN" not in _get()[0]
    assert "Incorrect PIN" in _get("err=1")[0]


def test_dark_mode_follows_the_in_memory_settings():
    assert 'data-theme="dark"' in _get(config_extra={"webui": {"dark_mode": True}})[0]
    assert 'data-theme="light"' in _get(config_extra={"webui": {"dark_mode": False}})[0]


def test_a_view_whose_snapshot_raises_gives_the_light_theme():
    assert 'data-theme="light"' in _get(settings=False)[0]


def test_the_page_links_its_script_and_has_no_other_inline_script():
    html, _m, _h = _get()
    assert _source_text.linked_static(html) == [
        "theme.css", "page/banner_dismiss.js", "page/auth.js"]
    assert "<script>" not in html


def test_the_page_script_posts_the_proof_to_the_verify_route():
    script = _source_text.static_text("page/auth.js")
    assert "/api/auth/verify" in script
    assert "sha256Hex(nonce + pin)" in script
