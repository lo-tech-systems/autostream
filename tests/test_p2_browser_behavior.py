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
    """_dial_card_html must escape all user-controlled strings."""

    def _setup_stubs(self):
        sys.path.insert(0, str(REPO_ROOT / "core"))

    def test_new_dial_card_escapes_uuid(self):
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(
            uuid='<script>bad</script>', name="safe", authorized=False, online=True
        )
        assert '<script>' not in result
        assert '&lt;script&gt;' in result

    def test_new_dial_card_escapes_name(self):
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        for payload in XSS_PAYLOADS:
            result = _dial_card_html(
                uuid="safe-uuid", name=payload, authorized=False, online=True
            )
            if "<" in payload or ">" in payload or "&" in payload:
                assert payload not in result, (
                    f"Unescaped XSS payload in dial card name: {payload!r}"
                )

    def test_offline_dial_card_escapes_name(self):
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(
            uuid="safe-uuid",
            name='<img src=x onerror=alert(1)>',
            authorized=True,
            online=False,
            last_seen="2026-01-01T00:00:00",
        )
        assert '<img src=x onerror=alert(1)>' not in result

    def test_online_dial_card_escapes_name(self):
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(
            uuid="safe-uuid",
            name='"><script>xss</script>',
            authorized=True,
            online=True,
        )
        assert '"><script>xss</script>' not in result


WIFI_WEB_PATH = REPO_ROOT / "platform" / "wifi_web.py"


def _load_wifi_web(env: dict | None = None) -> ModuleType:
    """Load platform/wifi_web.py under a fresh alias with the given env.

    Presentation constants (APP_TITLE/APP_BANNER_IMAGE/BANNER_HTML) are read at
    import time, so a fresh load per env lets the banner variants be exercised.
    Requires real Flask (wifi_web binds ``from flask import request``).
    """
    try:
        import flask  # noqa: F401
    except ImportError:
        pytest.skip("flask not installed — wifi_web render tests skipped")
    import os

    env = env or {}
    saved: dict[str, str | None] = {}
    # APP_BANNER_IMAGE controls the banner branch; default it absent so the
    # no-banner variant is deterministic unless the test asks otherwise.
    keys = set(env) | {"APP_TITLE", "APP_BANNER_IMAGE"}
    for k in keys:
        saved[k] = os.environ.get(k)
        if k in env:
            os.environ[k] = env[k]
        else:
            os.environ.pop(k, None)
    try:
        alias = "wifi_web_p2_" + str(abs(hash(tuple(sorted(env.items())))))
        loader = importlib.machinery.SourceFileLoader(alias, str(WIFI_WEB_PATH))
        spec = importlib.util.spec_from_loader(alias, loader)
        mod = importlib.util.module_from_spec(spec)
        # Register under alias before exec: the dataclass decorator on
        # WebContext resolves its field annotations via sys.modules, so the
        # module must be findable by name while it executes.
        sys.modules[alias] = mod
        try:
            loader.exec_module(mod)
        finally:
            sys.modules.pop(alias, None)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return mod


class _FakeWatcher:
    """Minimal seam object for render_wait_page (w.get_system_hostname / w._DIAL_MODE)."""

    def __init__(self, dial_mode: bool, hostname: str = "autostream"):
        self._DIAL_MODE = dial_mode
        self._hostname = hostname

    def get_system_hostname(self) -> str:
        return self._hostname


def _render_wait(web: ModuleType, w, ssid: str = "", user_agent: str = "") -> str:
    """Render the wait page inside a Flask request context (needs request.headers)."""
    import flask
    app = flask.Flask(__name__)
    headers = {"User-Agent": user_agent} if user_agent else {}
    with app.test_request_context("/setup", headers=headers):
        return web.render_wait_page(w, ssid)


class TestWifiWebHtmlEscaping:
    """wifi_web's render_setup_page must HTML-escape user-controlled content."""

    def test_error_code_rendered_safely(self):
        web = _load_wifi_web()
        # render_setup_page maps error codes to fixed messages; the raw code
        # is never inserted into the page.  An unknown hostile code must not leak.
        result = web.render_setup_page(error_code='<script>bad</script>')
        assert '<script>bad</script>' not in result

    def test_app_title_is_escaped(self):
        """APP_TITLE in BANNER_HTML must be HTML-escaped."""
        web = _load_wifi_web(env={"APP_TITLE": "<b>title</b>"})
        # BANNER_HTML was set at import time with escaped title.
        banner = web.BANNER_HTML
        assert "<b>title</b>" not in banner
        assert html.escape("<b>title</b>") in banner


class TestWifiWebRender:
    """Verbatim-move proof: rendered setup/wait pages have the expected
    semantic content across the banner/error-code/show_reconnect/dial variants."""

    def test_setup_default_structure(self):
        web = _load_wifi_web()
        out = web.render_setup_page()
        assert out.startswith("<!DOCTYPE html>") or "<!DOCTYPE html>" in out[:64]
        assert "Connect to WiFi" in out
        assert 'action="/setup"' in out
        assert web.STYLE_CSS in out
        # No banner image configured -> the app-title div banner is used.
        assert '<div class="app-title">' in out
        # No error and no reconnect by default.
        assert "Connection failed." not in out
        assert "Reconnect to saved network" not in out

    def test_setup_banner_image_used_when_configured(self):
        web = _load_wifi_web(env={"APP_BANNER_IMAGE": "https://x/logo.png"})
        out = web.render_setup_page()
        assert 'class="app-banner-image"' in out
        assert "https://x/logo.png" in out

    def test_setup_show_reconnect_adds_button(self):
        web = _load_wifi_web()
        with_btn = web.render_setup_page(show_reconnect=True)
        without_btn = web.render_setup_page(show_reconnect=False)
        assert "Reconnect to saved network" in with_btn
        assert "Reconnect to saved network" not in without_btn

    def test_setup_error_code_messages(self):
        web = _load_wifi_web()
        assert "no usable local IPv4 address" in web.render_setup_page("no-local-ip")
        assert "Unable to connect to that WiFi network" in web.render_setup_page("nmcli-failed")
        assert "WiFi connection attempt failed" in web.render_setup_page("something-else")
        # The raw internal code itself never leaks into the page.
        assert "no-local-ip" not in web.render_setup_page("no-local-ip")

    def test_wait_dial_mode_appliance_instruction(self):
        web = _load_wifi_web()
        out = _render_wait(web, _FakeWatcher(dial_mode=True), ssid="MyNet")
        assert "Continue setup from an autostream appliance" in out
        assert "window.location.replace('http://" not in out
        assert "MyNet" in out

    def test_wait_non_dial_redirects_to_local(self):
        web = _load_wifi_web()
        out = _render_wait(web, _FakeWatcher(dial_mode=False, hostname="myhost"), ssid="MyNet")
        assert "myhost.local" in out
        assert "window.location.replace('http://" in out

    def test_wait_failure_redirect_in_both_modes(self):
        web = _load_wifi_web()
        for dial in (True, False):
            out = _render_wait(web, _FakeWatcher(dial_mode=dial), ssid="N")
            assert "/setup?e=" in out

    def test_wait_user_agent_browser_name(self):
        web = _load_wifi_web()
        out = _render_wait(web, _FakeWatcher(dial_mode=False), ssid="N",
                           user_agent="Mozilla/5.0 (iPhone)")
        assert "Open Safari and go to" in out

    def test_wait_ssid_escaped(self):
        web = _load_wifi_web()
        out = _render_wait(web, _FakeWatcher(dial_mode=False), ssid="<script>x</script>")
        assert "<script>x</script>" not in out


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


class TestSetupPageUpdateApplyResponseHandling:
    """Source-contract tests: the update-apply button navigates on the async
    accept response rather than the old synchronous success shape."""

    def _src(self) -> str:
        return _setup_page_src()

    def test_navigates_on_accepted(self):
        src = self._src()
        idx = src.find('fetch("/api/update/apply"')
        assert idx >= 0
        end_idx = src.find("};", idx)
        block = src[idx:end_idx] if end_idx > 0 else src[idx:idx + 800]
        assert "if(j.accepted){{" in block
        assert 'window.location.replace("/offline/updating");' in block

    def test_no_longer_branches_on_bare_ok(self):
        src = self._src()
        idx = src.find('fetch("/api/update/apply"')
        assert idx >= 0
        end_idx = src.find("};", idx)
        block = src[idx:end_idx] if end_idx > 0 else src[idx:idx + 800]
        assert "if(j.ok){{" not in block


def _render_setup_page() -> str:
    """Render the full setup page HTML with all external dependencies mocked.

    Returns the raw HTML that would be written to the browser.  Uses the same
    module the production server uses so the test exercises conditional script
    rendering, not a hardcoded copy.
    """
    import io
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

    def test_setup_page_has_no_bulk_save_form(self):
        """Configured setup page must not have a full-form POST (autosave-only mode)."""
        html_out = _render_setup_page()
        assert 'action="/setup"' not in html_out, (
            "Bulk form POST to /setup must be absent; use autosave endpoints instead"
        )
        assert 'id="savingModal"' not in html_out, (
            "Saving modal is only needed with the form POST and must be removed"
        )
        assert 'type="submit"' not in html_out or 'form=' not in html_out

    def test_owntone_button_flushes_pending(self):
        """More Owntone Settings must drain pending autosave writes before navigating."""
        html_out = _render_setup_page()
        assert "flushPendingToServer" in html_out, (
            "owntone navigation must call flushPendingToServer() before location.href"
        )
        owntone_idx = html_out.find("owntone-setup")
        flush_idx = html_out.rfind("flushPendingToServer", 0, owntone_idx)
        assert flush_idx != -1, (
            "flushPendingToServer must appear before /owntone-setup in the navigation handler"
        )

    def test_setup_page_parser_and_submit_coexist(self):
        """_parseDialResponse and submitPinChange must both be in the setup page."""
        html_out = _render_setup_page()
        scripts = _extract_script_blocks(html_out)
        combined = "\n".join(scripts)
        assert "_parseDialResponse" in combined, (
            "_parseDialResponse not found in setup page scripts"
        )
        assert "submitPinChange" in combined, (
            "submitPinChange not found in setup page scripts"
        )

    @node_available
    def test_setup_page_scripts_syntax(self):
        """Every <script> block in the setup page must be syntactically valid JS."""
        html_out = _render_setup_page()
        scripts = _extract_script_blocks(html_out)
        assert scripts, "No <script> blocks found in setup page"
        for i, script in enumerate(scripts):
            _check_js_syntax(script, f"setup page script #{i}")


# ---------------------------------------------------------------------------
# §7.6  Dial card HTML structure and in-place update JS contract
# ---------------------------------------------------------------------------

class TestDialCardHtmlStructure:
    """Structural checks on _dial_card_html output and setup page JS contract."""

    def _setup_stubs(self):
        sys.path.insert(0, str(REPO_ROOT / "core"))

    # ── _dial_card_html output ───────────────────────────────────────────────

    def test_authorized_card_has_data_authorized_true(self):
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="My Dial", authorized=True, online=True)
        assert 'data-authorized="true"' in result

    def test_unauthorized_card_has_data_authorized_false(self):
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="New Dial", authorized=False, online=False)
        assert 'data-authorized="false"' in result

    def test_online_card_has_data_online_true(self):
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="My Dial", authorized=True, online=True)
        assert 'data-online="true"' in result

    def test_offline_card_has_data_online_false(self):
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="My Dial", authorized=True, online=False)
        assert 'data-online="false"' in result

    def test_unauthorized_card_has_data_new(self):
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="", authorized=False, online=False)
        assert "data-new" in result

    def test_authorized_card_dial_config_not_hidden(self):
        """Authorized cards must have .dial-config visible (no display:none)."""
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="My Dial", authorized=True, online=True)
        # Find .dial-config section and confirm display:none is not on it
        idx = result.find("dial-config")
        assert idx >= 0, ".dial-config not found in authorized card"
        # The opening tag of .dial-config should not contain display:none
        tag_end = result.find(">", idx)
        tag = result[max(0, idx - 50):tag_end + 1]
        assert "display:none" not in tag and "display: none" not in tag

    def test_unauthorized_card_dial_config_is_hidden(self):
        """Unauthorized cards must have .dial-config hidden (display:none)."""
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="", authorized=False, online=False)
        idx = result.find("dial-config")
        assert idx >= 0, ".dial-config not found in unauthorized card"
        tag_end = result.find(">", idx)
        tag = result[max(0, idx - 50):tag_end + 1]
        assert "display:none" in tag or "display: none" in tag

    def test_dial_name_input_present_in_all_cards(self):
        """The .dial-name input must appear in both authorized and unauthorized cards."""
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        for auth in (True, False):
            result = _dial_card_html(uuid="u1", name="Test", authorized=auth, online=False)
            assert "dial-name" in result, f"dial-name missing for authorized={auth}"

    def test_allow_toggle_present_in_all_cards(self):
        """The .dial-allow toggle must appear in every card."""
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        for auth in (True, False):
            result = _dial_card_html(uuid="u1", name="Test", authorized=auth, online=False)
            assert "dial-allow" in result, f"dial-allow missing for authorized={auth}"

    # ── JS function presence in rendered page ────────────────────────────────

    def test_set_dial_authorized_function_present(self):
        src = _setup_page_src()
        assert "function setDialAuthorized" in src

    def test_refresh_dials_card_sub_function_present(self):
        src = _setup_page_src()
        assert "function refreshDialsCardSub" in src

    def test_refresh_setup_card_subs_calls_dials(self):
        src = _setup_page_src()
        assert "refreshDialsCardSub" in src

    def test_dials_card_sub_id_in_rendered_page(self):
        html_out = _render_setup_page()
        assert 'id="dials-card-sub"' in html_out

    # ── No location.reload() in authorize/revoke flows ───────────────────────

    def test_dial_toggle_allow_no_page_reload(self):
        """dialToggleAllow must not call location.reload() — it does in-place DOM updates."""
        src = _setup_page_src()
        # Find dialToggleAllow body
        start = src.find("function dialToggleAllow")
        assert start >= 0, "dialToggleAllow not found"
        # Find the next top-level function to bound the search
        next_fn = src.find("\nfunction ", start + 1)
        body = src[start:next_fn] if next_fn > 0 else src[start:start + 3000]
        assert "location.reload" not in body, (
            "dialToggleAllow must not call location.reload(); use setDialAuthorized() instead"
        )

    def test_dial_revoke_no_page_reload(self):
        """dialRevoke must not call location.reload() — it does in-place DOM updates."""
        src = _setup_page_src()
        start = src.find("function dialRevoke")
        assert start >= 0, "dialRevoke not found"
        next_fn = src.find("\nfunction ", start + 1)
        body = src[start:next_fn] if next_fn > 0 else src[start:start + 3000]
        assert "location.reload" not in body, (
            "dialRevoke must not call location.reload(); use setDialAuthorized() instead"
        )

    def test_dial_toggle_allow_calls_set_dial_authorized(self):
        src = _setup_page_src()
        start = src.find("function dialToggleAllow")
        assert start >= 0
        next_fn = src.find("\nfunction ", start + 1)
        body = src[start:next_fn] if next_fn > 0 else src[start:start + 3000]
        assert "setDialAuthorized" in body, (
            "dialToggleAllow must call setDialAuthorized() to expand the card in place"
        )

    def test_dial_revoke_calls_set_dial_authorized(self):
        src = _setup_page_src()
        start = src.find("function dialRevoke")
        assert start >= 0
        next_fn = src.find("\nfunction ", start + 1)
        body = src[start:next_fn] if next_fn > 0 else src[start:start + 3000]
        assert "setDialAuthorized" in body, (
            "dialRevoke must call setDialAuthorized() to collapse the card in place"
        )

    def test_dial_toggle_allow_calls_refresh_dials_card_sub(self):
        src = _setup_page_src()
        start = src.find("function dialToggleAllow")
        assert start >= 0
        next_fn = src.find("\nfunction ", start + 1)
        body = src[start:next_fn] if next_fn > 0 else src[start:start + 3000]
        assert "refreshDialsCardSub" in body

    def test_dial_revoke_calls_refresh_dials_card_sub(self):
        src = _setup_page_src()
        start = src.find("function dialRevoke")
        assert start >= 0
        next_fn = src.find("\nfunction ", start + 1)
        body = src[start:next_fn] if next_fn > 0 else src[start:start + 3000]
        assert "refreshDialsCardSub" in body

    # ── setDialAuthorized structure ──────────────────────────────────────────

    def test_set_dial_authorized_updates_data_authorized(self):
        src = _setup_page_src()
        start = src.find("function setDialAuthorized")
        assert start >= 0
        next_fn = src.find("\nfunction ", start + 1)
        body = src[start:next_fn] if next_fn > 0 else src[start:start + 2000]
        assert "dataset.authorized" in body

    def test_set_dial_authorized_updates_dial_config_visibility(self):
        src = _setup_page_src()
        start = src.find("function setDialAuthorized")
        assert start >= 0
        next_fn = src.find("\nfunction ", start + 1)
        body = src[start:next_fn] if next_fn > 0 else src[start:start + 2000]
        assert "dial-config" in body
        assert "display" in body

    def test_set_dial_authorized_updates_badge(self):
        # setDialAuthorized() no longer hardcodes the badge class/text -- it
        # delegates to _dialSetStatusBadge(), which owns the tri-state (+
        # Configuring) mapping. Assert the delegation, not the old inline
        # class-name literals.
        src = _setup_page_src()
        start = src.find("function setDialAuthorized")
        assert start >= 0
        next_fn = src.find("\nfunction ", start + 1)
        body = src[start:next_fn] if next_fn > 0 else src[start:start + 2000]
        assert "_dialSetStatusBadge(card," in body
        assert "dial-badge-online" not in body
        assert "dial-badge-offline" not in body
        assert "dial-badge-new" not in body

    # ── focusout guard prevents save on unauthorized cards ───────────────────

    def test_save_config_guards_unlocked_pin_before_posting(self):
        """dialSaveConfig must check _dialUnlockedPins before posting when a PIN is set."""
        src = _setup_page_src()
        # Locate the dialSaveConfig function body
        fn_idx = src.find("async function dialSaveConfig(card)")
        assert fn_idx >= 0, "dialSaveConfig not found"
        next_fn = src.find("\n        async function ", fn_idx + 1)
        body = src[fn_idx:next_fn] if next_fn > 0 else src[fn_idx:fn_idx + 1500]
        # Must check _dialUnlockedPins before attempting to POST
        assert "_dialUnlockedPins" in body, (
            "_dialUnlockedPins guard must be present in dialSaveConfig"
        )
        # The unlock check must precede the _dialPost call
        unlock_idx = body.find("_dialUnlockedPins")
        post_idx = body.find("_dialPost")
        assert unlock_idx < post_idx, (
            "_dialUnlockedPins check must appear before _dialPost in dialSaveConfig"
        )
        # The focusout handler for auto-lock must still exist
        assert "focusout" in src, "focusout handler not found"

    # ── No Revoke button in .dial-config ────────────────────────────────────

    def test_no_revoke_button_in_dial_config(self):
        """The Revoke button must not appear in .dial-config; toggle is the only revoke path."""
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="My Dial", authorized=True, online=True)
        # data-dial-action="revoke" must not appear in the config area
        assert 'data-dial-action="revoke"' not in result

    # ── Screen settings (Has Screen Fitted toggle) ───────────────────────────

    def test_screen_fitted_toggle_present_in_card(self):
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="My Dial", authorized=True, online=True)
        assert "dial-screen-fitted" in result
        assert "Has Screen Fitted" in result

    def test_screen_fitted_toggle_inside_locked_section(self):
        """The screen toggle must live inside the existing locked settings card area."""
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="My Dial", authorized=True, online=True)
        locked_idx = result.find("dial-locked-section")
        screen_idx = result.find("dial-screen-fitted")
        pin_btn_idx = result.find('data-dial-action="change-pin"')
        assert locked_idx >= 0 and screen_idx >= 0 and pin_btn_idx >= 0
        assert locked_idx < screen_idx < pin_btn_idx

    def test_dial_load_screen_settings_function_present(self):
        src = _setup_page_src()
        assert "function dialLoadScreenSettings" in src
        assert "/api/dial/screen/settings/" in src

    def test_dial_save_screen_settings_function_present(self):
        src = _setup_page_src()
        assert "function dialSaveScreenSettings" in src
        assert "/api/dial/screen/settings" in src

    def test_screen_toggle_wired_to_save_action(self):
        src = _setup_page_src()
        assert "save-screen" in src
        # The change listener passes the triggering element so a failed save
        # reverts only the checkbox the user actually changed.
        assert "dialSaveScreenSettings(card, ev.target)" in src

    def test_dial_onload_loads_screen_settings(self):
        src = _setup_page_src()
        assert "dialLoadScreenSettings" in src

    # ── Screen settings (Rotate Screen toggle) ───────────────────────────────

    def test_screen_rotate_toggle_present_in_card(self):
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="My Dial", authorized=True, online=True)
        assert "dial-screen-rotate" in result
        assert "Rotate Screen" in result

    def test_screen_rotate_toggle_inside_locked_section(self):
        """The rotate toggle must live inside the existing locked settings card area."""
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="My Dial", authorized=True, online=True)
        locked_idx = result.find("dial-locked-section")
        rotate_idx = result.find("dial-screen-rotate")
        pin_btn_idx = result.find('data-dial-action="change-pin"')
        assert locked_idx >= 0 and rotate_idx >= 0 and pin_btn_idx >= 0
        assert locked_idx < rotate_idx < pin_btn_idx

    def test_screen_rotate_toggle_after_fitted_toggle(self):
        """The rotate row must appear after the fitted row in the HTML string."""
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="My Dial", authorized=True, online=True)
        fitted_idx = result.find("dial-screen-fitted")
        rotate_idx = result.find("dial-screen-rotate")
        assert fitted_idx >= 0 and rotate_idx >= 0
        assert fitted_idx < rotate_idx

    def test_dial_sync_rotate_enabled_function_present(self):
        src = _setup_page_src()
        assert "function dialSyncScreenControlsEnabled" in src
        # The fitted condition is computed once and applied to all four
        # controls, so the greying can never drift out of step with which
        # controls are actually disabled.
        assert "var off = fittedEl.disabled || !fittedEl.checked;" in src
        assert "rotateEl.disabled = off;" in src
        assert "bgrEl.disabled = off;" in src
        assert "typeEl.disabled = off;" in src
        assert "touchEl.disabled = off;" in src
        # Old name must be gone entirely -- this was a clean rename, not an alias.
        assert "dialSyncRotateEnabled" not in src

    def test_screen_control_rows_dim_when_not_fitted(self):
        """A disabled input still renders its label at full contrast, so the
        whole row is dimmed alongside being disabled."""
        src = _setup_page_src()
        # Every screen control row carries the shared class...
        assert src.count('class="dial-screen-ctl-row"') >= 1
        assert 'dial-screen-bgr-row dial-screen-ctl-row' in src
        assert 'dial-screen-type-row dial-screen-ctl-row' in src
        assert 'dial-screen-touch-row dial-screen-ctl-row' in src
        # ...the sync function toggles the dimmed state from the same
        # condition that disables the controls...
        assert "row.classList.toggle('is-disabled', off)" in src
        # ...and the stylesheet actually dims it.
        assert ".dial-screen-ctl-row.is-disabled{opacity:0.45;}" in src

    def test_dial_cards_are_spaced_apart(self):
        """Dial cards space themselves like the setup list cards: a bottom
        margin on each card, so the first still sits flush under the header."""
        src = _setup_page_src()
        assert '<div class="dial-card-wrap">' in src
        assert ".dial-card-wrap{margin-bottom:0.62rem;}" in src

    def test_dial_sync_rotate_enabled_wired_to_change_listener(self):
        src = _setup_page_src()
        assert "dialSyncScreenControlsEnabled(card)" in src
        idx = src.find("if (action === 'save-screen')")
        assert idx >= 0
        block_end = src.find("}}", idx)
        block = src[idx:block_end]
        assert "dialSyncScreenControlsEnabled" in block

    def test_dial_sync_rotate_enabled_wired_to_unlock_and_lock(self):
        src = _setup_page_src()
        lock_idx = src.find("function _dialLockSection")
        unlock_idx = src.find("function _dialUnlockSection")
        assert lock_idx >= 0 and unlock_idx >= 0
        next_fn_after_unlock = src.find("function _updateDialLockVisibility")
        assert next_fn_after_unlock >= 0
        lock_block = src[lock_idx:unlock_idx]
        unlock_block = src[unlock_idx:next_fn_after_unlock]
        assert "dialSyncScreenControlsEnabled(card)" in lock_block
        assert "dialSyncScreenControlsEnabled(card)" in unlock_block

    # ── _dialSetStatusBadge extraction + Configuring state ────────────────────

    def test_dial_set_status_badge_helper_covers_all_four_states(self):
        src = _setup_page_src()
        idx = src.find("function _dialSetStatusBadge(card, state)")
        assert idx >= 0
        next_fn = src.find("\nfunction ", idx + 1)
        body = src[idx:next_fn] if next_fn > 0 else src[idx:idx + 2000]
        assert "online: ['dial-badge-online', 'Online']" in body
        assert "offline: ['dial-badge-offline', 'Offline']" in body
        assert "new: ['dial-badge-new', 'New']" in body
        assert "configuring: ['dial-badge-configuring', 'Configuring']" in body

    def test_set_dial_authorized_delegates_to_status_badge_helper(self):
        src = _setup_page_src()
        fn_idx = src.find("function setDialAuthorized(card, authorized)")
        assert fn_idx >= 0
        next_fn = src.find("\nfunction ", fn_idx + 1)
        body = src[fn_idx:next_fn] if next_fn > 0 else src[fn_idx:fn_idx + 2000]
        assert "_dialSetStatusBadge(card, authorized ? (online ? 'online' : 'offline') : 'new')" in body

    def test_configuring_badge_css_uses_warning_token(self):
        src = _setup_page_src()
        assert (
            ".dial-badge-configuring{background:var(--color-status-warning,#f0ad4e);color:#212529;}"
            in src
        )
        # Same token as the existing amber recovery badge -- not a new color.
        recovery_idx = src.find(".dial-badge-recovery{")
        configuring_idx = src.find(".dial-badge-configuring{")
        assert recovery_idx >= 0 and configuring_idx >= 0

    # ── dialSetCardBusy() ──────────────────────────────────────────────────────

    def test_dial_set_card_busy_queries_controls_generically(self):
        """A hand-listed selector set silently misses controls added to the
        card later, and each miss is a control left live over a device that
        is not listening. Set Dial PIN was missed exactly that way."""
        src = _setup_page_src()
        idx = src.find("function dialSetCardBusy(card, busy)")
        assert idx >= 0
        block = src[idx:idx + 2000]
        assert "querySelectorAll('input, select, button, textarea')" in block
        assert "_DIAL_BUSY_SELECTORS" not in src, "the enumerated list should be gone"

    def test_dial_set_card_busy_restores_prior_disabled_state(self):
        """Controls disabled before the operation (a locked settings section,
        screen sub-controls with no screen fitted) must stay disabled after
        it. Blanket enabling would silently unlock a locked card."""
        src = _setup_page_src()
        idx = src.find("function dialSetCardBusy(card, busy)")
        block = src[idx:idx + 2000]
        assert "busyPrevDisabled" in block
        assert "el.disabled = (el.dataset.busyPrevDisabled === '1')" in block

    def test_dial_set_card_busy_covers_the_pin_buttons(self):
        """Both PIN buttons are plain <button> elements inside the card, so
        the generic query reaches them."""
        src = _setup_page_src()
        assert 'data-dial-action="change-pin"' in src
        assert 'data-dial-action="recover-pin"' in src

    def test_dial_set_card_busy_uses_is_disabled_convention(self):
        src = _setup_page_src()
        idx = src.find("function dialSetCardBusy(card, busy)")
        next_fn = src.find("\nfunction ", idx + 1)
        body = src[idx:next_fn]
        assert "row.classList.toggle('is-disabled', busy)" in body

    def test_dial_set_card_busy_unbusy_resyncs_screen_controls_not_blanket_enable(self):
        """On un-busy the helper must re-run dialSyncScreenControlsEnabled()
        rather than unconditionally enabling every control -- otherwise a
        card whose screen isn't fitted comes back with its screen
        sub-controls wrongly enabled."""
        src = _setup_page_src()
        idx = src.find("function dialSetCardBusy(card, busy)")
        next_fn = src.find("\nfunction ", idx + 1)
        body = src[idx:next_fn]
        assert "if (!busy) {{" in body
        assert "dialSyncScreenControlsEnabled(card);" in body

    # ── _dialGet() and its call sites ─────────────────────────────────────────

    def test_dial_get_helper_defined_alongside_fetch_and_post(self):
        src = _setup_page_src()
        idx = src.find("async function _dialGet(path)")
        assert idx >= 0
        next_fn = src.find("\nfunction ", idx + 1)
        alt_next_fn = src.find("\nasync function ", idx + 1)
        candidates = [n for n in (next_fn, alt_next_fn) if n > 0]
        end = min(candidates) if candidates else idx + 500
        body = src[idx:end]
        assert "_dialFetch(path, {{cache: 'no-store'}})" in body

    def test_dial_get_call_sites_moved_off_hand_rolled_fetch(self):
        """The three former hand-rolled GET call sites (dialLoadConfig,
        dialLoadScreenSettings, the PIN-recovery poller) must go through
        _dialGet() rather than attaching X-CSRF-Token by hand."""
        src = _setup_page_src()
        assert src.count("_dialGet(") >= 3

        load_config_idx = src.find("async function dialLoadConfig(card)")
        load_config_next = src.find("async function dialLoadScreenSettings(card)", load_config_idx)
        load_config_body = src[load_config_idx:load_config_next]
        assert "_dialGet('/api/dial/configure/'" in load_config_body
        assert "headers: {{'X-CSRF-Token'" not in load_config_body

        load_screen_idx = src.find("async function dialLoadScreenSettings(card)")
        load_screen_next = src.find("async function dialSaveScreenSettings", load_screen_idx)
        load_screen_body = src[load_screen_idx:load_screen_next]
        assert "_dialGet('/api/dial/screen/settings/'" in load_screen_body
        assert "headers: {{'X-CSRF-Token'" not in load_screen_body

        recovery_poll_idx = src.find("_dialPinRecoveryTimer = setInterval")
        assert recovery_poll_idx >= 0
        recovery_poll_end = src.find("}}, 2000);", recovery_poll_idx)
        recovery_poll_body = src[recovery_poll_idx:recovery_poll_end]
        assert "_dialGet('/api/dial/pin_recovery/status/'" in recovery_poll_body
        assert "headers: {{'X-CSRF-Token'" not in recovery_poll_body

    # ── dialPollUntil() bounded poller ─────────────────────────────────────────

    def test_dial_poll_until_has_deadline_and_token_guard(self):
        src = _setup_page_src()
        idx = src.find("function dialPollUntil(intervalMs, deadlineMs, checkFn, onTimeout)")
        assert idx >= 0
        next_fn = src.find("\nasync function ", idx + 1)
        body = src[idx:next_fn] if next_fn > 0 else src[idx:idx + 2000]
        # Wall-clock deadline, not an attempt counter.
        assert "Date.now() + deadlineMs" in body
        assert "Date.now() >= deadlineAt" in body
        # Generation-token guard so a superseded/cancelled poll's in-flight
        # checkFn() promise bails instead of racing.
        assert "active !== token" in body
        # Cancellable, and never leaves a dangling interval.
        assert "return function cancel()" in body
        assert body.count("clearInterval(timerId)") >= 3

    def test_dial_save_screen_settings_sends_rotate(self):
        src = _setup_page_src()
        assert "rotate: rotateEl.checked" in src

    # ── Screen settings (BGR toggle + screen-type select) ────────────────────

    def test_screen_bgr_toggle_present_in_card(self):
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="My Dial", authorized=True, online=True)
        assert "dial-screen-bgr" in result
        assert "Swap Red/Blue (BGR)" in result
        assert 'data-dial-action="save-screen"' in result

    def test_screen_type_select_present_in_card(self):
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="My Dial", authorized=True, online=True)
        assert '<select class="dial-screen-type" data-dial-action="save-screen" disabled></select>' in result

    def test_screen_bgr_and_type_inside_locked_section_after_rotate(self):
        """Both new rows must live in the locked section, after the rotate row,
        and before the Change Dial PIN button."""
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="My Dial", authorized=True, online=True)
        locked_idx = result.find("dial-locked-section")
        rotate_idx = result.find("dial-screen-rotate")
        bgr_idx = result.find("dial-screen-bgr")
        type_idx = result.find("dial-screen-type")
        pin_btn_idx = result.find('data-dial-action="change-pin"')
        assert locked_idx >= 0 and rotate_idx >= 0 and bgr_idx >= 0 and type_idx >= 0 and pin_btn_idx >= 0
        assert locked_idx < rotate_idx < bgr_idx < type_idx < pin_btn_idx

    def test_screen_bgr_and_type_rows_hidden_by_default(self):
        """Both new rows must be hidden until the dial publishes `supported`."""
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="My Dial", authorized=True, online=True)
        bgr_row_idx = result.find("dial-screen-bgr-row")
        type_row_idx = result.find("dial-screen-type-row")
        assert bgr_row_idx >= 0 and type_row_idx >= 0
        bgr_row_tag = result[bgr_row_idx - 40:bgr_row_idx + 80]
        type_row_tag = result[type_row_idx - 40:type_row_idx + 80]
        assert "display:none" in bgr_row_tag
        assert "display:none" in type_row_tag

    def test_screen_type_select_populated_and_cleared_in_load(self):
        """dialLoadScreenSettings must clear existing options before
        repopulating -- it runs on render, authorize, and PIN unlock, so
        without a clear the options would duplicate."""
        src = _setup_page_src()
        fn_idx = src.find("async function dialLoadScreenSettings(card)")
        assert fn_idx >= 0
        next_fn = src.find("async function dialSaveScreenSettings", fn_idx)
        body = src[fn_idx:next_fn]
        assert "typeEl.innerHTML = ''" in body
        assert "j.supported" in body
        assert "localeCompare" in body

    def test_screen_caps_gate_flag_set_and_cleared(self):
        src = _setup_page_src()
        fn_idx = src.find("async function dialLoadScreenSettings(card)")
        next_fn = src.find("async function dialSaveScreenSettings", fn_idx)
        body = src[fn_idx:next_fn]
        assert "card.dataset.screenCaps = '1'" in body
        assert "delete card.dataset.screenCaps" in body

    def test_screen_save_body_gated_by_supported_caps(self):
        """The save body must include screen_type/bgr only when the
        capability gate flag is set -- an old dial 400s on an unknown field,
        which would otherwise break the existing fitted/rotate toggles."""
        src = _setup_page_src()
        fn_idx = src.find("async function dialSaveScreenSettings(card, changedEl)")
        assert fn_idx >= 0
        next_fn = src.find("async function dialUpdateFirmware", fn_idx)
        body = src[fn_idx:next_fn]
        assert "card.dataset.screenCaps === '1'" in body
        assert "screen.bgr = " in body
        assert "screen.screen_type = " in body
        # Ungated body (no caps) must remain byte-identical to the historical
        # {{fitted, rotate}} shape.
        assert "var screen = {{fitted: fittedEl.checked, rotate: rotateEl.checked}};" in body

    def test_save_blocked_until_screen_settings_loaded(self):
        """A whole-object POST built before the screen-settings GET resolves
        would omit screen_type/bgr and reset them to defaults, so the save
        must refuse until the load has populated the controls."""
        src = _setup_page_src()
        fn_idx = src.find("async function dialSaveScreenSettings(card, changedEl)")
        next_fn = src.find("async function dialUpdateFirmware", fn_idx)
        body = src[fn_idx:next_fn]
        assert "card.dataset.screenLoaded !== '1'" in body
        # The guard must sit before the body is assembled, not after.
        assert body.index("screenLoaded") < body.index("var screen = ")

        load_idx = src.find("async function dialLoadScreenSettings(card)")
        load_body = src[load_idx:src.find("async function dialSaveScreenSettings", load_idx)]
        assert "card.dataset.screenLoaded = '1'" in load_body

    def test_screen_save_reverts_via_snapshot_not_just_negation(self):
        """A <select> can't be reverted with `!checked` -- the changed
        control's previous value must be snapshotted before the POST and
        restored on both the error branch and the network-error catch."""
        src = _setup_page_src()
        fn_idx = src.find("async function dialSaveScreenSettings(card, changedEl)")
        assert fn_idx >= 0
        next_fn = src.find("async function dialUpdateFirmware", fn_idx)
        body = src[fn_idx:next_fn]
        assert "var prevValue" in body
        assert body.count("changedEl.value = prevValue") >= 1
        assert body.count("changedEl.checked = prevValue") >= 2

    def test_screen_apply_failed_error_message_mapped(self):
        src = _setup_page_src()
        idx = src.find("function _dialErrorMessage")
        assert idx >= 0
        next_fn = src.find("async function _dialFetch", idx)
        block = src[idx:next_fn]
        assert "'screen_apply_failed'" in block
        assert "Screen settings could not be applied" in block

    # ── Screen settings (Touch Panel select) ──────────────────────────────────

    def test_touch_select_present_in_card(self):
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="My Dial", authorized=True, online=True)
        assert '<select class="dial-screen-touch" data-dial-action="save-screen" disabled></select>' in result

    def test_touch_row_inside_locked_section_after_screen_type(self):
        """The touch row must live in the locked section, after the
        screen-type row, and before the Change Dial PIN button."""
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="My Dial", authorized=True, online=True)
        locked_idx = result.find("dial-locked-section")
        type_idx = result.find("dial-screen-type-row")
        touch_idx = result.find("dial-screen-touch-row")
        pin_btn_idx = result.find('data-dial-action="change-pin"')
        assert locked_idx >= 0 and type_idx >= 0 and touch_idx >= 0 and pin_btn_idx >= 0
        assert locked_idx < type_idx < touch_idx < pin_btn_idx

    def test_touch_row_hidden_by_default(self):
        """The touch row must be hidden until the dial publishes
        `supported_touch`."""
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="My Dial", authorized=True, online=True)
        touch_row_idx = result.find("dial-screen-touch-row")
        assert touch_row_idx >= 0
        touch_row_tag = result[touch_row_idx - 40:touch_row_idx + 80]
        assert "display:none" in touch_row_tag

    def test_touch_select_populated_and_cleared_in_load(self):
        """dialLoadScreenSettings must clear existing touch options before
        repopulating -- it runs on render, authorize, and PIN unlock, so
        without a clear the options would duplicate."""
        src = _setup_page_src()
        fn_idx = src.find("async function dialLoadScreenSettings(card)")
        assert fn_idx >= 0
        next_fn = src.find("async function dialSaveScreenSettings", fn_idx)
        body = src[fn_idx:next_fn]
        assert "touchEl.innerHTML = ''" in body
        assert "j.supported_touch" in body

    def test_touch_caps_gate_flag_set_and_cleared(self):
        src = _setup_page_src()
        fn_idx = src.find("async function dialLoadScreenSettings(card)")
        next_fn = src.find("async function dialSaveScreenSettings", fn_idx)
        body = src[fn_idx:next_fn]
        assert "card.dataset.touchCaps = '1'" in body
        assert "delete card.dataset.touchCaps" in body

    def test_touch_caps_gate_independent_of_screen_caps(self):
        """`supported_touch` is a SEPARATE capability array from `supported`
        -- a dial can publish screen profiles but no touch capability at
        all, so the two gate flags must be set from different response
        fields and neither must depend on the other."""
        src = _setup_page_src()
        fn_idx = src.find("async function dialLoadScreenSettings(card)")
        next_fn = src.find("async function dialSaveScreenSettings", fn_idx)
        body = src[fn_idx:next_fn]
        assert "var supported = Array.isArray(j.supported)" in body
        assert "var supportedTouch = Array.isArray(j.supported_touch)" in body
        assert "card.dataset.screenCaps = '1'" in body
        assert "card.dataset.touchCaps = '1'" in body

    def test_touch_save_body_gated_by_supported_touch_caps(self):
        """The save body must include touch_type only when the touchCaps
        gate flag is set -- an old dial 400s on an unknown field, which
        would otherwise break the existing screen controls too. This gate
        is independent of screenCaps: a dial can support screen profiles
        without supporting touch."""
        src = _setup_page_src()
        fn_idx = src.find("async function dialSaveScreenSettings(card, changedEl)")
        assert fn_idx >= 0
        next_fn = src.find("async function dialUpdateFirmware", fn_idx)
        body = src[fn_idx:next_fn]
        assert "card.dataset.touchCaps === '1'" in body
        assert "screen.touch_type = " in body
        # The touch gate must be a separate `if` from the screen gate, not
        # folded into the same condition.
        touch_gate_idx = body.find("card.dataset.touchCaps === '1'")
        screen_gate_idx = body.find("card.dataset.screenCaps === '1'")
        assert screen_gate_idx >= 0 and touch_gate_idx >= 0
        assert screen_gate_idx != touch_gate_idx

    # ── Self-restart poll after a touch-controller change ─────────────────────

    def _touch_restart_poll_body(self, src):
        idx = src.find("function dialBeginTouchRestartPoll(card, requestedTouchType)")
        assert idx >= 0
        next_fn = src.find("\nasync function ", idx + 1)
        return src[idx:next_fn] if next_fn > 0 else src[idx:idx + 3000]

    def test_save_branches_on_restarting_flag(self):
        src = _setup_page_src()
        fn_idx = src.find("async function dialSaveScreenSettings(card, changedEl)")
        assert fn_idx >= 0
        next_fn = src.find("async function dialUpdateFirmware", fn_idx)
        body = src[fn_idx:next_fn]
        assert "result.body && result.body.restarting === true" in body
        assert "dialBeginTouchRestartPoll(card, screen.touch_type)" in body

    def test_touch_restart_poll_sets_busy_and_configuring_badge_together(self):
        body = self._touch_restart_poll_body(_setup_page_src())
        assert "dialSetCardBusy(card, true)" in body
        assert "_dialSetStatusBadge(card, 'configuring')" in body
        busy_idx = body.find("dialSetCardBusy(card, true)")
        badge_idx = body.find("_dialSetStatusBadge(card, 'configuring')")
        assert busy_idx >= 0 and badge_idx >= 0

    def test_touch_restart_poll_clears_recovery_badge(self):
        body = self._touch_restart_poll_body(_setup_page_src())
        assert "_dialSetRecoveryBadge(card, false)" in body

    def test_touch_restart_poll_targets_runtime_touch_type_not_screen(self):
        """The plan's central trap: screen.touch_type is the PERSISTED value
        and flips to the new controller from the OLD, not-yet-restarted
        process, so polling it would report success instantly and verify
        nothing. Only runtime.touch_type reflects what is actually running."""
        body = self._touch_restart_poll_body(_setup_page_src())
        assert "runtime.touch_type" in body
        assert "runtime ? runtime.touch_type : null" in body
        assert "pollResult.body.screen" not in body
        assert re.search(r"\bscreen\.touch_type\b", body) is None

    def test_touch_restart_poll_uses_dial_poll_until_with_exact_interval_and_deadline(self):
        body = self._touch_restart_poll_body(_setup_page_src())
        assert "dialPollUntil(1000, 60000," in body

    def test_touch_restart_poll_unreachable_response_is_not_treated_as_error(self):
        """While the dial is down the proxy returns ok:false
        (dial_unreachable/dial_offline) -- expected, must keep polling
        silently rather than ending the poll or showing an error."""
        body = self._touch_restart_poll_body(_setup_page_src())
        assert "if (!pollResult.ok) return false;" in body

    def test_touch_restart_poll_done_condition_restores_card_and_online_badge(self):
        body = self._touch_restart_poll_body(_setup_page_src())
        assert "runtimeTouchType === requestedTouchType" in body
        assert "_DIAL_CFG_OK_DISABLED" in body and "_DIAL_CFG_OK_ENABLED" in body

    def test_touch_restart_poll_failed_runtime_value_ends_poll_with_its_own_message(self):
        """'failed' is a real outcome (the dial came back and its touch stack
        failed to open), not a timeout -- it must stop the poll immediately
        with a message distinct from the timeout message."""
        body = self._touch_restart_poll_body(_setup_page_src())
        assert "runtimeTouchType === 'failed'" in body
        idx = body.find("runtimeTouchType === 'failed'")
        end_idx = body.find("return true;", idx)
        block = body[idx:end_idx]
        assert "_DIAL_CFG_CANNOT_OPEN" in block

    def test_touch_restart_poll_timeout_restores_card_and_offline_badge(self):
        body = self._touch_restart_poll_body(_setup_page_src())
        assert "function onTimeout() {{" in body
        timeout_idx = body.find("function onTimeout() {{")
        block = body[timeout_idx:timeout_idx + 300]
        assert "_dialFinishTouchRestartPoll(card, 'offline', _DIAL_CFG_GENERIC_ERR, false);" in block

    def test_touch_restart_poll_finish_helper_restores_busy_and_sets_badge(self):
        src = _setup_page_src()
        idx = src.find("function _dialFinishTouchRestartPoll(card, badgeState, message, ok)")
        assert idx >= 0
        next_fn = src.find("\nfunction ", idx + 1)
        body = src[idx:next_fn] if next_fn > 0 else src[idx:idx + 800]
        assert "dialSetCardBusy(card, false)" in body
        assert "_dialSetStatusBadge(card, badgeState)" in body
        assert "_dialShowResultModal(_DIAL_CFG_TITLE, message)" in body

    def test_touch_outcome_messages_depend_on_outcome_and_direction(self):
        """Disabling touch is a success in its own right, and a panel that
        will not open is a wiring/type problem the user can act on -- so the
        message depends on BOTH the outcome and which way touch was going."""
        src = _setup_page_src()
        assert "var _DIAL_CFG_TITLE = 'Dial Configuration';" in src
        assert "'Touch panel configured successfully.'" in src
        assert "'Touch panel disabled.'" in src
        assert ("'Touch panel could not be opened. "
                "Please check touch panel type and wiring.'") in src
        assert "'An error was encountered applying the configuration.'" in src

    def test_disabling_touch_reports_disabled_not_configured(self):
        src = _setup_page_src()
        idx = src.find("function dialBeginTouchRestartPoll")
        block = src[idx:idx + 2500]
        # Success branch picks the disabled wording only when going to none.
        assert ("requestedTouchType === 'none' ? _DIAL_CFG_OK_DISABLED "
                ": _DIAL_CFG_OK_ENABLED") in block
        # A panel that fails to open is only a wiring hint when enabling.
        assert ("requestedTouchType === 'none' ? _DIAL_CFG_GENERIC_ERR "
                ": _DIAL_CFG_CANNOT_OPEN") in block
        # Timeout is the generic error.
        assert "_dialFinishTouchRestartPoll(card, 'offline', _DIAL_CFG_GENERIC_ERR, false)" in block

    def test_touch_restart_outcome_uses_a_single_ok_modal(self):
        """The outcome arrives up to a minute after the change, so it is
        reported in a modal rather than an inline line that is easy to miss.
        Reuses the dial PIN modals' markup and classes."""
        src = _setup_page_src()
        assert 'id="dialResultModal" class="modal-overlay"' in src
        assert 'id="dialResultModalOk"' in src
        assert 'class="btn modal-btn modal-btn-primary" id="dialResultModalOk">OK<' in src
        # Exactly one button in its footer -- OK only, no Cancel.
        start = src.find('id="dialResultModal"')
        end = src.find("</div>", src.find("modal-ft", start))
        assert src[start:end].count("<button") == 1

    def test_result_modal_ok_button_is_wired_to_close(self):
        src = _setup_page_src()
        assert "resultOk.addEventListener('click', _dialCloseResultModal)" in src
        assert "function _dialCloseResultModal()" in src

    def test_second_save_cancels_prior_touch_restart_poll(self):
        """A second save on the same card must cancel the previous poll
        rather than run two concurrently."""
        src = _setup_page_src()
        fn_idx = src.find("function dialBeginTouchRestartPoll(card, requestedTouchType)")
        assert fn_idx >= 0
        next_fn = src.find("\nasync function ", fn_idx + 1)
        body = src[fn_idx:next_fn] if next_fn > 0 else src[fn_idx:fn_idx + 3000]
        assert "_dialCancelTouchRestartPoll(card);" in body
        # The cancel must happen before a new poll is started, not after.
        cancel_idx = body.find("_dialCancelTouchRestartPoll(card);")
        new_poll_idx = body.find("var cancel = dialPollUntil(")
        assert 0 <= cancel_idx < new_poll_idx
        # And the cancel helper itself must invoke the stored cancel() and
        # clear the map entry, not just drop the reference.
        cancel_fn_idx = src.find("function _dialCancelTouchRestartPoll(card)")
        assert cancel_fn_idx >= 0
        cancel_fn_next = src.find("\nfunction ", cancel_fn_idx + 1)
        cancel_fn_body = src[cancel_fn_idx:cancel_fn_next]
        assert "cancel();" in cancel_fn_body
        assert "_dialTouchPollCancel.delete(card);" in cancel_fn_body

    def test_revoke_button_absent_in_source(self):
        """The source must not define a Revoke button element."""
        src = _setup_page_src()
        assert 'data-dial-action="revoke"' not in src

    # ── dialRevoke failure restores toggle ───────────────────────────────────

    def test_dial_revoke_failure_restores_toggle(self):
        """dialRevoke must restore .dial-allow.checked=true on server error."""
        src = _setup_page_src()
        start = src.find("function dialRevoke")
        assert start >= 0
        next_fn = src.find("\nfunction ", start + 1)
        body = src[start:next_fn] if next_fn > 0 else src[start:start + 3000]
        # Must have an else/catch branch that sets checked = true
        assert "cb.checked = true" in body or "checked = true" in body, (
            "dialRevoke must restore allow toggle to checked=true on failure"
        )

    def test_dial_revoke_catch_restores_toggle(self):
        """dialRevoke catch block must also restore .dial-allow.checked=true."""
        src = _setup_page_src()
        start = src.find("function dialRevoke")
        assert start >= 0
        next_fn = src.find("\nfunction ", start + 1)
        body = src[start:next_fn] if next_fn > 0 else src[start:start + 3000]
        # The catch block must restore the toggle — count two occurrences
        assert body.count("checked = true") >= 2, (
            "dialRevoke needs checked=true in both the else branch and the catch block"
        )

    # ── setDialAuthorized maintains data-new ────────────────────────────────

    def test_set_dial_authorized_removes_data_new_on_authorize(self):
        src = _setup_page_src()
        start = src.find("function setDialAuthorized")
        assert start >= 0
        next_fn = src.find("\nfunction ", start + 1)
        body = src[start:next_fn] if next_fn > 0 else src[start:start + 2000]
        assert "delete card.dataset.new" in body or "dataset.new" in body, (
            "setDialAuthorized must clear data-new when authorizing"
        )

    def test_set_dial_authorized_adds_data_new_on_revoke(self):
        src = _setup_page_src()
        start = src.find("function setDialAuthorized")
        assert start >= 0
        next_fn = src.find("\nfunction ", start + 1)
        body = src[start:next_fn] if next_fn > 0 else src[start:start + 2000]
        # Both delete (authorize) and set (revoke) must be present
        assert "dataset.new = 'true'" in body or 'dataset.new = "true"' in body, (
            "setDialAuthorized must set data-new='true' when revoking"
        )

    # ── Firmware update button available immediately after authorize ──────────

    def test_new_card_fw_update_btn_inside_dial_config(self):
        """Unauthorized cards with a pending update must have Update firmware in .dial-config."""
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(
            uuid="u1", name="New Dial", authorized=False, online=True,
            fw_version="1.0.0", needs_update=True,
        )
        assert "Update firmware" in result, (
            "Unauthorized card with needs_update=True must include Update firmware button "
            "inside .dial-config so it is visible immediately after in-place authorize"
        )

    def test_authorized_card_fw_update_btn_present(self):
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(
            uuid="u1", name="My Dial", authorized=True, online=True,
            fw_version="1.0.0", needs_update=True,
        )
        assert "Update firmware" in result

    def test_no_fw_update_btn_when_not_needed(self):
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(
            uuid="u1", name="My Dial", authorized=True, online=True,
            fw_version="2.0.0", needs_update=False,
        )
        assert "Update firmware" not in result

    def test_no_fw_update_btn_when_offline(self):
        self._setup_stubs()
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(
            uuid="u1", name="My Dial", authorized=True, online=False,
            fw_version="1.0.0", needs_update=True,
        )
        assert "Update firmware" not in result


# ---------------------------------------------------------------------------
# Lost-PIN recovery UX: wording covers every input type, PIN controls are
# gated on can_confirm_presence, and the recovery modal detects an expired
# window instead of waiting forever.
# ---------------------------------------------------------------------------

class TestDialPinRecoveryWording:
    """The recovery instructions must not assume a rotary control exists."""

    def _src(self) -> str:
        return _setup_page_src()

    def test_old_clockwise_instruction_removed(self):
        src = self._src()
        assert "turning the Dial clockwise" not in src
        assert "Turn the Dial clockwise" not in src

    def test_initial_instruction_mentions_power_cycle_and_window(self):
        src = self._src()
        assert "power-cycling the Dial now" in src
        assert "10 minutes" in src

    def test_active_window_instruction_covers_all_input_types(self):
        src = self._src()
        assert "touch" in src.lower()
        assert "rotary" in src.lower()
        assert "button" in src.lower()
        # The three must appear together in one instruction, not scattered.
        idx = src.find("Touch the dial's screen")
        assert idx >= 0, "new all-inputs instruction not found"
        window = src[idx:idx + 200]
        assert "rotary" in window.lower()
        assert "button" in window.lower()


class TestDialPinControlsGatedOnCanConfirmPresence:
    """A dial that can never confirm presence must not be offered a PIN lock."""

    def _src(self) -> str:
        return _setup_page_src()

    def test_dial_load_config_reads_can_confirm_presence(self):
        src = self._src()
        start = src.find("async function dialLoadConfig")
        assert start >= 0
        end = src.find("async function dialLoadScreenSettings", start)
        body = src[start:end] if end > 0 else src[start:start + 2000]
        assert "can_confirm_presence" in body
        assert "canConfirm" in body

    def test_lock_visibility_gates_pin_controls_on_can_confirm(self):
        src = self._src()
        start = src.find("function _updateDialLockVisibility")
        assert start >= 0
        end = src.find("\n        function ", start + 1)
        body = src[start:end] if end > 0 else src[start:start + 2000]
        assert "canConfirm" in body
        assert "change-pin" in body
        assert "recover-pin" in body
        assert "noConfirmMsg" in body

    def test_explanatory_message_element_in_card_html(self):
        sys.path.insert(0, str(REPO_ROOT / "core"))
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="My Dial", authorized=True, online=True)
        assert "dial-pin-no-confirm-msg" in result
        assert "could not be reset" in result

    def test_explanatory_message_toggled_by_can_confirm(self):
        src = self._src()
        start = src.find("function _updateDialLockVisibility")
        assert start >= 0
        end = src.find("\n        function ", start + 1)
        body = src[start:end] if end > 0 else src[start:start + 2000]
        assert "noConfirmMsg.style.display" in body


class TestDialPinRecoveryCountdownAndExpiry:
    """The recovery modal must show a countdown and detect an expired window
    instead of leaving the user on 'Waiting for Dial…' forever."""

    def _src(self) -> str:
        return _setup_page_src()

    def test_countdown_format_helper_present(self):
        src = self._src()
        assert "_dialFormatRemaining" in src

    def test_countdown_helper_used_during_polling(self):
        src = self._src()
        start = src.find("function openDialPinRecoveryModal")
        assert start >= 0
        end = src.find("\n        function _dialPinRecoveryTransitionToSet", start)
        body = src[start:end] if end > 0 else src[start:start + 3000]
        assert "_dialFormatRemaining" in body
        assert "recovery_remaining_ms" in body

    def test_seen_active_flag_reset_on_open(self):
        src = self._src()
        assert "_dialPinRecoverySeenActive" in src
        start = src.find("function openDialPinRecoveryModal")
        assert start >= 0
        end = src.find("\n        function _dialPinRecoveryTransitionToSet", start)
        body = src[start:end] if end > 0 else src[start:start + 3000]
        assert "_dialPinRecoverySeenActive = false" in body
        assert "_dialPinRecoverySeenActive = true" in body

    def test_expiry_stops_polling_and_shows_closed_message(self):
        src = self._src()
        start = src.find("function _dialPinRecoveryExpired")
        assert start >= 0
        end = src.find("\n        function ", start + 1)
        body = src[start:end] if end > 0 else src[start:start + 1000]
        assert "clearInterval" in body
        assert "window closed" in body.lower()

    def test_can_confirm_presence_false_short_circuits_wait(self):
        src = self._src()
        start = src.find("function _dialPinRecoveryCannotConfirm")
        assert start >= 0
        end = src.find("\n        function ", start + 1)
        body = src[start:end] if end > 0 else src[start:start + 1000]
        assert "clearInterval" in body
        start2 = src.find("function openDialPinRecoveryModal")
        end2 = src.find("\n        function _dialPinRecoveryTransitionToSet", start2)
        poll_body = src[start2:end2] if end2 > 0 else src[start2:start2 + 3000]
        assert "can_confirm_presence === false" in poll_body
        assert "_dialPinRecoveryCannotConfirm" in poll_body


class TestDialPinRecoveryTwoStepFlow:
    """Recovery is now requested first and power-cycled second: a confirm
    step arms the request, and only then does the existing power-cycle
    step (poll, confirm-presence, set-PIN) begin."""

    def _src(self) -> str:
        return _setup_page_src()

    def test_confirm_step_has_exact_wording_and_yes_no_buttons(self):
        src = self._src()
        assert "This feature can be used to reset a lost PIN. Continue?" in src
        idx = src.find("function openDialPinRecoveryModal")
        assert idx >= 0
        end = src.find("\n        async function handleDialPinRecoveryConfirmYes", idx)
        body = src[idx:end] if end > 0 else src[idx:idx + 2000]
        assert "dialPinRecoveryConfirmPanel" in body
        assert "okBtn.textContent = 'Yes'" in body
        assert "cancelBtn.textContent = 'No'" in body

    def test_yes_posts_to_arm_route_before_wait_step_begins(self):
        src = self._src()
        idx = src.find("async function handleDialPinRecoveryConfirmYes")
        assert idx >= 0
        end = src.find("\n        function _dialPinRecoveryBeginWait", idx)
        body = src[idx:end] if end > 0 else src[idx:idx + 1500]
        arm_idx = body.find("_dialPost('/api/dial/recovery/arm'")
        begin_wait_idx = body.find("_dialPinRecoveryBeginWait(card, uuid)")
        assert arm_idx >= 0, "arm route not posted from the confirm step"
        assert begin_wait_idx >= 0, "wait step never started on success"
        assert arm_idx < begin_wait_idx, "wait step must not start before the arm request completes"

    def test_failed_arm_does_not_advance_to_wait_step(self):
        src = self._src()
        idx = src.find("async function handleDialPinRecoveryConfirmYes")
        assert idx >= 0
        end = src.find("\n        function _dialPinRecoveryBeginWait", idx)
        body = src[idx:end] if end > 0 else src[idx:idx + 1500]
        else_idx = body.find("}} else {{")
        assert else_idx >= 0
        else_body = body[else_idx:]
        assert "_dialPinRecoveryBeginWait" not in else_body, (
            "a failed arm must not advance to the power-cycle step"
        )
        assert "closeDialPinRecoveryModal()" in else_body
        assert "_dialErrorMessage(result.error)" in else_body
        # The network-error branch (fetch itself rejecting) must not advance either.
        catch_idx = body.find("}} catch(e) {{")
        assert catch_idx >= 0
        catch_body = body[catch_idx:]
        assert "_dialPinRecoveryBeginWait" not in catch_body
        assert "closeDialPinRecoveryModal()" in catch_body

    def test_ok_button_dispatches_by_step(self):
        src = self._src()
        assert "if (_dialPinRecoveryStep === 'confirm')" in src
        assert "handleDialPinRecoveryConfirmYes();" in src
        assert "if (_dialPinRecoveryStep === 'set')" in src

    def test_close_posts_to_disarm_route(self):
        """Cancel/close at either step must best-effort disarm."""
        src = self._src()
        idx = src.find("function closeDialPinRecoveryModal")
        assert idx >= 0
        end = src.find("\n        async function handleDialPinRecoveryOk", idx)
        body = src[idx:end] if end > 0 else src[idx:idx + 1000]
        assert "_dialPost('/api/dial/recovery/disarm'" in body

    def test_cancel_button_reaches_close_at_both_steps(self):
        """A single Cancel/No button handles both the confirm popup and the
        power-cycle popup, so wiring it once to closeDialPinRecoveryModal
        covers cancelling either step."""
        src = self._src()
        assert "recoveryCancel.addEventListener('click', closeDialPinRecoveryModal)" in src

    def test_wait_step_still_polls_status_and_handles_confirm_presence(self):
        src = self._src()
        idx = src.find("function _dialPinRecoveryBeginWait")
        assert idx >= 0
        end = src.find("\n        function _dialPinRecoveryTransitionToSet", idx)
        body = src[idx:end] if end > 0 else src[idx:idx + 3000]
        assert "_dialGet('/api/dial/pin_recovery/status/'" in body
        assert "can_confirm_presence === false" in body
        assert "_dialPinRecoveryCannotConfirm()" in body
        assert "_dialPinRecoveryTransitionToSet()" in body

    def test_set_pin_step_still_reachable(self):
        src = self._src()
        assert "async function handleDialPinRecoveryOk" in src
        assert "/api/dial/pin_recovery/complete" in src

    def test_can_confirm_presence_suppression_still_applies(self):
        """A dial that cannot confirm presence must still not be offered
        the flow at all -- unaffected by the confirm-step addition."""
        src = self._src()
        start = src.find("function _updateDialLockVisibility")
        assert start >= 0
        end = src.find("\n        function ", start + 1)
        body = src[start:end]
        assert "recoverBtn.style.display = 'none'" in body


# ---------------------------------------------------------------------------
# §7.7  Dial card "Recovery Active" badge (pin_recovery surfaced from mDNS)
# ---------------------------------------------------------------------------

class TestDialCardRecoveryBadge:
    """The dial card must surface DialSighting.pin_recovery as a badge, and
    keep it reasonably fresh without a dedicated always-on polling loop."""

    def _src(self) -> str:
        return _setup_page_src()

    def test_badge_renders_when_pin_recovery_true(self):
        sys.path.insert(0, str(REPO_ROOT / "core"))
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(
            uuid="u1", name="My Dial", authorized=True, online=True, pin_recovery=True
        )
        assert "Recovery Active" in result

    def test_badge_absent_when_pin_recovery_false(self):
        sys.path.insert(0, str(REPO_ROOT / "core"))
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(
            uuid="u1", name="My Dial", authorized=True, online=True, pin_recovery=False
        )
        assert "Recovery Active" not in result
        assert "dial-badge-recovery" not in result

    def test_badge_defaults_to_absent(self):
        """pin_recovery defaults to False when a caller omits it."""
        sys.path.insert(0, str(REPO_ROOT / "core"))
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(uuid="u1", name="My Dial", authorized=True, online=True)
        assert "Recovery Active" not in result

    def test_badge_has_shared_and_variant_class(self):
        sys.path.insert(0, str(REPO_ROOT / "core"))
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(
            uuid="u1", name="My Dial", authorized=True, online=True, pin_recovery=True
        )
        idx = result.find("Recovery Active")
        assert idx >= 0
        tag_start = result.rfind("<span", 0, idx)
        tag = result[tag_start:idx]
        assert "dial-badge" in tag
        assert "dial-badge-recovery" in tag

    def test_badge_css_variant_defined(self):
        src = self._src()
        idx = src.find(".dial-badge-recovery")
        assert idx >= 0
        rule = src[idx:idx + 200]
        assert "background" in rule

    def test_badge_css_uses_warning_variable_not_new_hex(self):
        """Should reuse the existing danger/warning colour token rather than
        inventing a new literal colour, and stay distinct from the other
        three badge variants (accent/success/muted)."""
        src = self._src()
        idx = src.find(".dial-badge-recovery")
        assert idx >= 0
        rule = src[idx:idx + 200]
        assert "var(--color-status-warning" in rule

    def test_badge_coexists_with_online_badge(self):
        sys.path.insert(0, str(REPO_ROOT / "core"))
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(
            uuid="u1", name="My Dial", authorized=True, online=True, pin_recovery=True
        )
        assert "dial-badge-online" in result
        assert "dial-badge-recovery" in result
        assert "Online" in result
        assert "Recovery Active" in result

    def test_offline_authorized_dial_without_sighting_never_shows_badge(self):
        """An authorized-but-offline dial has no live sighting, so it cannot
        be advertising a recovery window; callers must not be able to pass
        pin_recovery=True for it in practice, and the render path itself
        must not surface the badge for an offline card."""
        sys.path.insert(0, str(REPO_ROOT / "core"))
        from autostream_webui_page_setup import _dial_card_html
        result = _dial_card_html(
            uuid="u1", name="My Dial", authorized=True, online=False, pin_recovery=False
        )
        assert "Recovery Active" not in result
        assert 'data-online="false"' in result

    def test_setup_page_loop_ties_pin_recovery_to_sighting_presence(self):
        """The card-building loop must not pass pin_recovery=True unless a
        live sighting exists (offline dials never advertise recovery)."""
        src = self._src()
        idx = src.find("_pin_recovery = bool(_sighting.pin_recovery) if _sighting is not None else False")
        assert idx >= 0
        # And it must actually be threaded into the _dial_card_html call.
        call_idx = src.find("pin_recovery=_pin_recovery", idx)
        assert call_idx >= 0

    # ── Freshness mechanism: recovery modal poller keeps the badge honest ──

    def test_recovery_badge_sync_helper_present(self):
        src = self._src()
        assert "function _dialSetRecoveryBadge" in src

    def test_recovery_poller_calls_badge_sync_helper(self):
        """Chosen freshness strategy: reuse the existing per-2s
        /api/dial/pin_recovery/status/<uuid> poll inside the recovery modal
        to add/remove the badge live, rather than adding a new polling loop."""
        src = self._src()
        start = src.find("function openDialPinRecoveryModal")
        assert start >= 0
        end = src.find("\n        function _dialPinRecoveryTransitionToSet", start)
        body = src[start:end] if end > 0 else src[start:start + 3000]
        assert "_dialSetRecoveryBadge" in body

    def test_badge_sync_runs_before_the_not_ok_early_return(self):
        """A dial that is not in a recovery window answers 404, which the
        proxy tunnels as ok:false with the dial's own active:false in the
        body. The badge must therefore be synced before the not-ok early
        return, or an expired window would leave the badge showing until
        the page is reloaded."""
        src = self._src()
        start = src.find("function openDialPinRecoveryModal")
        assert start >= 0
        end = src.find("\n        function _dialPinRecoveryTransitionToSet", start)
        body = src[start:end] if end > 0 else src[start:start + 3000]
        sync_at = body.find("_dialSetRecoveryBadge")
        guard_at = body.find("if (!pollResult.ok) return;")
        assert sync_at >= 0 and guard_at >= 0
        assert sync_at < guard_at

    def test_badge_sync_skipped_when_dial_did_not_answer(self):
        """An unreachable dial carries no boolean `active`, so the badge is
        left as-is rather than being falsely cleared by a transport error."""
        src = self._src()
        start = src.find("function openDialPinRecoveryModal")
        end = src.find("\n        function _dialPinRecoveryTransitionToSet", start)
        body = src[start:end] if end > 0 else src[start:start + 3000]
        assert "typeof body.active === 'boolean'" in body

    def test_badge_sync_helper_reads_and_writes_dial_badge_recovery_class(self):
        src = self._src()
        start = src.find("function _dialSetRecoveryBadge")
        assert start >= 0
        end = src.find("\n        function ", start + 1)
        body = src[start:end] if end > 0 else src[start:start + 1500]
        assert "dial-badge-recovery" in body

    def test_pin_reset_completion_clears_badge(self):
        """Once a PIN is successfully set the recovery window is over from
        the admin's perspective, so the badge should be cleared immediately
        rather than waiting for the next poll or page reload."""
        src = self._src()
        start = src.find("async function handleDialPinRecoveryOk")
        assert start >= 0
        end = src.find("\n        function ", start + 1)
        if end < 0:
            end = src.find("\n        async function ", start + 1)
        body = src[start:end] if end > 0 else src[start:start + 2000]
        assert "_dialSetRecoveryBadge(card, false)" in body
