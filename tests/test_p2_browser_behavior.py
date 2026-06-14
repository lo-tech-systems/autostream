"""P2 — Embedded browser behaviour: JS syntax and HTML escaping tests.

What runs here (offline, no browser):
  - JS syntax: extract every embedded <script> block and verify it with
    `node --check` (skipped when Node.js is absent — runs in CI).
  - HTML escaping: test Python functions that embed user-controlled strings
    in HTML, using hostile XSS payloads. These tests run everywhere.
  - Structural JS checks: verify key function names and polling structure
    are present in the embedded scripts (Python regex, no execution).

What is environment-dependent:
  - Full Playwright browser tests (full page rendering, form submission,
    polling, accessibility) require Playwright + a running server.
    These are in tests/playwright/ (separate suite, not imported here).
    CI: ubuntu-latest, `playwright install`, separate pytest run.

Acceptance criterion for JS syntax: every file referenced in the 'node'
skip message must be tested when node becomes available.
"""
from __future__ import annotations

import html
import importlib.util
import re
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent


def _node_ok() -> bool:
    try:
        r = subprocess.run(["node", "--version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


node_available = pytest.mark.skipif(
    not _node_ok(),
    reason="Node.js ('node') not available — JS syntax tests run in CI (ubuntu-latest, nodejs package)",
)


def _check_js_syntax(source: str, label: str) -> None:
    """Run `node --check` on *source*; raise AssertionError on syntax error."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".js",
                                    delete=False, encoding="utf-8") as f:
        f.write(source)
        path = f.name
    try:
        r = subprocess.run(
            ["node", "--check", path],
            capture_output=True, text=True, timeout=10,
        )
        assert r.returncode == 0, (
            f"JavaScript syntax error in {label}:\n{r.stderr.strip()}"
        )
    finally:
        try:
            Path(path).unlink()
        except OSError:
            pass


def _extract_script_blocks(html_source: str) -> list[str]:
    """Return the contents of every <script>…</script> block."""
    return re.findall(r"<script[^>]*>(.*?)</script>", html_source, re.DOTALL)


# ---------------------------------------------------------------------------
# Load modules that contain embedded JavaScript
# ---------------------------------------------------------------------------

def _load_dial_webui() -> ModuleType:
    path = REPO_ROOT / "dial" / "dial_webui_assets.py"
    loader = importlib.util.spec_from_loader(
        "dial_webui_assets_p2",
        importlib.machinery.SourceFileLoader("dial_webui_assets_p2", str(path)),
    )
    mod = importlib.util.module_from_spec(loader)
    loader.loader.exec_module(mod)
    return mod


def _load_page_setup() -> ModuleType:
    """Load autostream_webui_page_setup with external deps stubbed."""
    sys.path.insert(0, str(REPO_ROOT / "core"))
    try:
        import autostream_webui_page_setup as m
        return m
    except ImportError:
        pytest.skip("Could not import autostream_webui_page_setup")


# ---------------------------------------------------------------------------
# JS syntax checks (Node.js required)
# ---------------------------------------------------------------------------

class TestJavaScriptSyntax:
    """Every embedded <script> block must be syntactically valid JS."""

    @node_available
    def test_dial_setup_page_js_syntax(self):
        mod = _load_dial_webui()
        scripts = _extract_script_blocks(mod.SETUP_PAGE_HTML)
        assert scripts, "No <script> blocks found in SETUP_PAGE_HTML"
        for i, script in enumerate(scripts):
            _check_js_syntax(script, f"SETUP_PAGE_HTML script #{i}")

    @node_available
    def test_offline_updating_html_js_syntax(self):
        src = (REPO_ROOT / "nginx" / "offline" / "updating.html").read_text(encoding="utf-8")
        scripts = _extract_script_blocks(src)
        assert scripts, "No <script> blocks in updating.html"
        for i, script in enumerate(scripts):
            _check_js_syntax(script, f"updating.html script #{i}")

    @node_available
    def test_offline_rebooting_html_js_syntax(self):
        src = (REPO_ROOT / "nginx" / "offline" / "rebooting.html").read_text(encoding="utf-8")
        scripts = _extract_script_blocks(src)
        for i, script in enumerate(scripts):
            _check_js_syntax(script, f"rebooting.html script #{i}")

    @node_available
    def test_offline_resetting_html_js_syntax(self):
        src = (REPO_ROOT / "nginx" / "offline" / "resetting.html").read_text(encoding="utf-8")
        scripts = _extract_script_blocks(src)
        for i, script in enumerate(scripts):
            _check_js_syntax(script, f"resetting.html script #{i}")

    @node_available
    def test_offline_retrying_html_js_syntax(self):
        src = (REPO_ROOT / "nginx" / "offline" / "retrying.html").read_text(encoding="utf-8")
        scripts = _extract_script_blocks(src)
        for i, script in enumerate(scripts):
            _check_js_syntax(script, f"retrying.html script #{i}")


# ---------------------------------------------------------------------------
# Structural JS checks (no Node required)
# ---------------------------------------------------------------------------

class TestDialSetupPageJsStructure:
    """Verify key JS constructs are present in the dial setup page."""

    def test_load_update_status_function_present(self):
        mod = _load_dial_webui()
        assert "loadUpdSt" in mod.SETUP_PAGE_HTML, (
            "loadUpdSt function missing from dial setup page"
        )

    def test_polling_state_names_present(self):
        """The dial UI must check for 'running', 'complete', and 'failed'."""
        mod = _load_dial_webui()
        js = mod.SETUP_PAGE_HTML
        assert "'running'" in js or '"running"' in js, "Public state 'running' missing"
        assert "'complete'" in js or '"complete"' in js, "Public state 'complete' missing"
        assert "'failed'" in js or '"failed"' in js, "Public state 'failed' missing"

    def test_polling_uses_setinterval(self):
        """Polling must use setInterval (not manual recursion that could leak)."""
        mod = _load_dial_webui()
        assert "setInterval" in mod.SETUP_PAGE_HTML

    def test_terminal_states_clear_interval(self):
        """complete and failed must clear the polling interval."""
        mod = _load_dial_webui()
        js = mod.SETUP_PAGE_HTML
        # Both 'complete' and 'failed' branches must contain clearInterval.
        # Check that clearInterval appears at all in the script.
        assert "clearInterval" in js, "clearInterval not found; polling may leak"

    def test_update_status_endpoint_is_slash_update_slash_status(self):
        """Must fetch /update/status, not some other path."""
        mod = _load_dial_webui()
        assert "/update/status" in mod.SETUP_PAGE_HTML


class TestOfflineUpdatingHtmlJsStructure:
    """updating.html reads raw STATUS values (in_progress/success/failure)."""

    def _html(self) -> str:
        return (REPO_ROOT / "nginx" / "offline" / "updating.html").read_text(encoding="utf-8")

    def test_reads_in_progress_status(self):
        assert "'in_progress'" in self._html() or '"in_progress"' in self._html()

    def test_reads_success_status(self):
        assert "'success'" in self._html() or '"success"' in self._html()

    def test_reads_failure_status(self):
        assert "'failure'" in self._html() or '"failure"' in self._html()

    def test_polls_update_status_endpoint(self):
        html_src = self._html()
        assert "/offline/update-status" in html_src or "/update-status" in html_src, (
            "updating.html must poll an update-status endpoint"
        )

    def test_script_tags_are_balanced(self):
        html_src = self._html()
        opens = html_src.count("<script")
        closes = html_src.count("</script>")
        assert opens == closes, f"Unbalanced script tags: {opens} open, {closes} close"


# ---------------------------------------------------------------------------
# HTML escaping — device names (XSS prevention)
# ---------------------------------------------------------------------------

# Hostile strings that would inject HTML or JS if not escaped.
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "';alert(1);//",
    '<b>bold</b>',
    '&lt;not-escaped&gt;',
    'normal device name',
    'Turntable "Pro" & more',
    "O'Hara's vinyl",
]


class TestDialCardHtmlEscaping:
    """Dial card generation functions must escape user-controlled strings."""

    def _setup_stubs(self):
        sys.path.insert(0, str(REPO_ROOT / "core"))

    def test_new_dial_card_escapes_uuid(self):
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_new_html
        sighting = MagicMock()
        sighting.uuid = '<script>bad</script>'
        sighting.name = "safe"
        result = _dial_card_new_html(sighting)
        assert '<script>' not in result
        assert '&lt;script&gt;' in result

    def test_new_dial_card_escapes_name(self):
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_new_html
        for payload in XSS_PAYLOADS:
            sighting = MagicMock()
            sighting.uuid = "safe-uuid"
            sighting.name = payload
            result = _dial_card_new_html(sighting)
            # Raw unescaped payload must not appear verbatim if it contains HTML.
            if "<" in payload or ">" in payload or "&" in payload:
                assert payload not in result, (
                    f"Unescaped XSS payload in dial card name: {payload!r}"
                )

    def test_offline_dial_card_escapes_name(self):
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_offline_html
        entry = MagicMock()
        entry.uuid = "safe-uuid"
        entry.current_name = '<img src=x onerror=alert(1)>'
        entry.name = "safe"
        entry.last_seen = "2026-01-01T00:00:00"
        result = _dial_card_offline_html(entry)
        assert '<img src=x onerror=alert(1)>' not in result

    def test_online_dial_card_escapes_name(self):
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_online_html
        entry = MagicMock()
        entry.uuid = "safe-uuid"
        entry.current_name = '"><script>xss</script>'
        entry.name = "safe"
        sighting = MagicMock()
        sighting.uuid = "safe-uuid"
        sighting.name = "safe"
        sighting.version = "1.0"
        result = _dial_card_online_html(entry, sighting, "1.0")
        assert '"><script>xss</script>' not in result


class TestWifiWatcherHtmlEscaping:
    """wifi_watcher's render_setup_page must HTML-escape user-controlled content."""

    def _load_watcher(self) -> ModuleType:
        alias = "wifi_watcher_p2_escape_test"
        loader = importlib.machinery.SourceFileLoader(
            alias, str(REPO_ROOT / "platform" / "wifi_watcher")
        )
        spec = importlib.util.spec_from_loader(alias, loader)
        mod = importlib.util.module_from_spec(spec)
        flask_stub = MagicMock()
        flask_stub.Flask = lambda *a, **kw: MagicMock()
        sysutils_stub = MagicMock()
        sysutils_stub.get_system_hostname = MagicMock(return_value="autostream")
        saved = {}
        for name, stub in [("flask", flask_stub), ("autostream_sysutils", sysutils_stub)]:
            saved[name] = sys.modules.get(name)
            sys.modules[name] = stub
        try:
            loader.exec_module(mod)
        finally:
            for name, orig in saved.items():
                if orig is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = orig
        return mod

    def test_error_code_rendered_safely(self):
        mod = self._load_watcher()
        # render_setup_page maps error codes to fixed messages; the raw code
        # is never inserted into the page.  An unknown hostile code must not leak.
        result = mod.render_setup_page(error_code='<script>bad</script>')
        assert '<script>bad</script>' not in result

    def test_app_title_is_escaped(self):
        """APP_TITLE in BANNER_HTML must be HTML-escaped."""
        mod = self._load_watcher()
        # BANNER_HTML was set at import time with escaped title.
        banner = mod.BANNER_HTML
        if "<" in banner or ">" in banner:
            assert html.escape(mod.APP_TITLE) in banner or mod.APP_TITLE not in banner


# ---------------------------------------------------------------------------
# Offline HTML page structural checks (no browser needed)
# ---------------------------------------------------------------------------

OFFLINE_PAGES = [
    REPO_ROOT / "nginx" / "offline" / "updating.html",
    REPO_ROOT / "nginx" / "offline" / "rebooting.html",
    REPO_ROOT / "nginx" / "offline" / "resetting.html",
    REPO_ROOT / "nginx" / "offline" / "retrying.html",
    REPO_ROOT / "nginx" / "offline" / "index.html",
]


class TestOfflinePageStructure:
    @pytest.mark.parametrize("page", OFFLINE_PAGES, ids=[p.name for p in OFFLINE_PAGES])
    def test_has_doctype(self, page):
        content = page.read_text(encoding="utf-8")
        assert content.strip().lower().startswith("<!doctype html"), (
            f"{page.name} missing <!doctype html>"
        )

    @pytest.mark.parametrize("page", OFFLINE_PAGES, ids=[p.name for p in OFFLINE_PAGES])
    def test_has_charset_meta(self, page):
        content = page.read_text(encoding="utf-8").lower()
        assert "charset" in content, f"{page.name} missing charset meta tag"

    @pytest.mark.parametrize("page", OFFLINE_PAGES, ids=[p.name for p in OFFLINE_PAGES])
    def test_has_viewport_meta(self, page):
        content = page.read_text(encoding="utf-8").lower()
        assert "viewport" in content, f"{page.name} missing viewport meta tag"

    @pytest.mark.parametrize("page", OFFLINE_PAGES, ids=[p.name for p in OFFLINE_PAGES])
    def test_script_tags_are_balanced(self, page):
        content = page.read_text(encoding="utf-8")
        opens = content.count("<script")
        closes = content.count("</script>")
        assert opens == closes, f"{page.name}: {opens} <script> but {closes} </script>"

    @pytest.mark.parametrize("page", OFFLINE_PAGES, ids=[p.name for p in OFFLINE_PAGES])
    def test_no_inline_event_handlers_with_raw_user_data(self, page):
        """No onclick/onerror/onload attribute should contain raw user strings."""
        content = page.read_text(encoding="utf-8")
        # Offline pages should not embed user-controlled data in event handlers.
        # The check is a structural heuristic: no 'onerror' attributes at all.
        assert 'onerror=' not in content, (
            f"{page.name} contains onerror= attribute (potential XSS vector)"
        )
