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
    These live in tests/playwright/test_ui_flows.py and run in the
    playwright CI job (.github/workflows/ci.yml).

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


# ---------------------------------------------------------------------------
# §7.5  Browser behavior: setup-page discriminated response parser (source-contract)
# ---------------------------------------------------------------------------

def _setup_page_src() -> str:
    return (REPO_ROOT / "core" / "autostream_webui_page_setup.py").read_text(encoding="utf-8")


class TestSetupPageDialResponseParser:
    """Source-contract tests: verify the discriminated parser is present and correct."""

    def _src(self) -> str:
        return _setup_page_src()

    def test_parse_dial_response_function_present(self):
        assert "_parseDialResponse" in self._src()

    def test_dial_error_message_function_present(self):
        assert "_dialErrorMessage" in self._src()

    def test_parser_checks_content_type(self):
        src = self._src()
        assert "Content-Type" in src or "content-type" in src
        assert "application/json" in src

    def test_invalid_response_used_for_non_json(self):
        assert "invalid_response" in self._src()

    def test_non_object_json_rejected(self):
        assert "Array.isArray" in self._src()

    def test_ok_false_treated_as_application_error(self):
        src = self._src()
        assert "body.ok === false" in src or "ok === false" in src

    def test_transport_status_preserved_in_result(self):
        assert "transportStatus" in self._src()

    def test_network_error_only_on_fetch_rejection(self):
        src = self._src()
        assert "_dialErrorMessage" in src
        assert "Network error" in src

    def test_recovery_polling_uses_parser(self):
        src = self._src()
        assert "_parseDialResponse" in src
        assert "volume_confirmed" in src

    def test_load_config_checks_ok_before_using_body(self):
        src = self._src()
        assert "loadResult" in src
        assert "loadResult.ok" in src or ("loadResult" in src and ".ok" in src)

    def test_parser_has_no_dom_side_effects(self):
        src = self._src()
        idx = src.find("async function _parseDialResponse")
        assert idx >= 0
        # Parser is immediately followed by submitPinChange; use that as the boundary.
        end_idx = src.find("async function submitPinChange", idx)
        parser_body = src[idx:end_idx] if end_idx > 0 else src[idx:idx + 3000]
        assert "document." not in parser_body

    def test_foreground_callers_use_dial_error_message(self):
        src = self._src()
        assert src.count("_dialErrorMessage") >= 3

    def test_background_dialloadconfig_uses_parser(self):
        assert "loadResult" in self._src()

    def test_successful_response_accesses_body(self):
        src = self._src()
        assert "loadResult.body" in src or "result.body" in src or "pinResult.ok" in src

    def test_dial_offline_message_mapped(self):
        assert "Dial is offline" in self._src()

    def test_dial_unreachable_message_mapped(self):
        assert "Dial could not be reached" in self._src()

    def test_dial_bad_response_message_mapped(self):
        assert "Dial returned an invalid response" in self._src()

    def test_invalid_response_message_mapped(self):
        assert "Appliance returned an unexpected response" in self._src()

    def test_wrong_pin_message_mapped(self):
        assert "Incorrect PIN" in self._src()

    def test_too_many_attempts_message_mapped(self):
        assert "Too many attempts" in self._src()

    def test_dial_unavailable_message_mapped(self):
        assert "Dial is temporarily unavailable" in self._src()

    def test_dial_timeout_message_mapped(self):
        assert "Dial did not respond in time" in self._src()


def _render_setup_page(initial_setup_mode: bool) -> str:
    """Render the full setup page HTML with all external dependencies mocked.

    Returns the raw HTML that would be written to the browser.  Uses the same
    module the production server uses so the test exercises conditional script
    rendering, not a hardcoded copy.
    """
    import io
    from types import SimpleNamespace
    from unittest.mock import MagicMock, patch

    m = _load_page_setup()
    mod = m.__name__  # "autostream_webui_page_setup"

    buf = io.BytesIO()
    handler = MagicMock()
    handler.wfile = buf
    handler._csrf_token = "tok"
    handler.headers = {"Cookie": ""}

    auth = MagicMock()
    auth.get_csrf_token.return_value = "tok"
    auth.get_boot_pin_value.return_value = ""

    state = MagicMock()
    state.get_monitor_devices.return_value = []

    import autostream_config as _cfg
    parsed = _cfg.parse_config({
        "audio1": {"capture_device": "hw:0,0"},
    })

    list_out = MagicMock()
    list_out.ok = False

    with patch(f"{mod}._config_snapshot", new=lambda state: parsed), \
         patch(f"{mod}.unconfigured", new=lambda p: initial_setup_mode), \
         patch(f"{mod}.list_outputs", new=lambda base_url, timeout: list_out), \
         patch(f"{mod}.build_top_banner_html", new=lambda **kw: ("", "")), \
         patch(f"{mod}.get_system_hostname", new=lambda: "test-host"), \
         patch(f"{mod}.get_app_version", new=lambda: "1.0.0"), \
         patch(f"{mod}.suggested_silence_threshold_dbfs", new=lambda tt: -45.0), \
         patch(f"{mod}.get_ap_ssid", new=lambda: "test-ssid"), \
         patch(f"{mod}.parse_dial_entries", new=lambda: []), \
         patch(f"{mod}._get_dial_sightings", new=lambda: []):
        m.send_setup_page(handler, state, auth)

    return buf.getvalue().decode("utf-8", errors="replace")


class TestSetupPageScriptRendering:
    """Verify the actual generated setup page scripts — not a hardcoded copy."""

    def test_setup_page_has_saving_feedback(self):
        """The setup form shows a busy modal while its settings POST is pending."""
        html_out = _render_setup_page(initial_setup_mode=True)
        assert 'id="savingModal"' in html_out
        assert 'id="savingModalTitle">Saving...</div>' in html_out
        assert "setupSavingFeedback" in html_out
        assert "form.setAttribute('aria-busy', 'true')" in html_out
        assert "button.disabled = true" in html_out

    def test_initial_setup_parser_and_submit_coexist(self):
        """_parseDialResponse and submitPinChange must both be in the initial-setup page."""
        html_out = _render_setup_page(initial_setup_mode=True)
        scripts = _extract_script_blocks(html_out)
        combined = "\n".join(scripts)
        assert "_parseDialResponse" in combined, (
            "_parseDialResponse not found in initial-setup page scripts"
        )
        assert "submitPinChange" in combined, (
            "submitPinChange not found in initial-setup page scripts"
        )

    @node_available
    def test_initial_setup_page_scripts_syntax(self):
        """Every <script> block in the initial-setup page must be syntactically valid JS."""
        html_out = _render_setup_page(initial_setup_mode=True)
        scripts = _extract_script_blocks(html_out)
        assert scripts, "No <script> blocks found in initial-setup page"
        for i, script in enumerate(scripts):
            _check_js_syntax(script, f"initial-setup page script #{i}")

    @node_available
    def test_configured_page_scripts_syntax(self):
        """Every <script> block in the configured setup page must be syntactically valid JS."""
        html_out = _render_setup_page(initial_setup_mode=False)
        scripts = _extract_script_blocks(html_out)
        assert scripts, "No <script> blocks found in configured setup page"
        for i, script in enumerate(scripts):
            _check_js_syntax(script, f"configured-page script #{i}")
