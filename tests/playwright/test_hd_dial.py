"""Playwright browser tests for the HD dial page.

Two servers back the page, both on 127.0.0.1 with a free port:

  hd_real  the production HdServer (routes, hub, serialiser, headers) with a
           FakeCore fed from the HD scenario corpus; only the core is fake
  hd_mock  tools/hd_mock_server.py, the offline mock the page is developed
           against

The page is opened at the HD panel's size (800x480) with touch on, in
headless Chromium. Without Playwright or its pytest plugin the tests skip.

Requirements:
  pip install pytest-playwright && playwright install chromium

CI job: playwright in .github/workflows/ci.yml.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
for _p in (REPO_ROOT / "tests", REPO_ROOT / "tools", REPO_ROOT / "dial", REPO_ROOT / "core"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

_PLAYWRIGHT_INSTALLED = (
    importlib.util.find_spec("playwright") is not None
    and importlib.util.find_spec("pytest_playwright") is not None
)

pytestmark = pytest.mark.skipif(
    not _PLAYWRIGHT_INSTALLED,
    reason=(
        "playwright not installed — "
        "pip install pytest-playwright && playwright install chromium"
    ),
)

VIEWPORT = {"width": 800, "height": 480}


# ---------------------------------------------------------------------------
# Servers
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def hd_real():
    """The real HdServer over a FakeCore, started on a free port."""
    import dial_hd_server as hds
    import hd_scenarios
    from dial_hd_events import ChangeHub
    from hd_fake_core import FakeCore
    from hd_http_support import close_management_server, management_server

    core = FakeCore(hd_scenarios.SCENARIOS["playing_artwork"].snapshot)
    management = management_server()
    hub = ChangeHub(core)
    server = hds.HdServer(
        SimpleNamespace(), core, http_server=management, hub=hub, port=0,
        muted_fn=lambda service: False,
    )
    hub.start()
    server.start()
    yield SimpleNamespace(core=core, server=server, hub=hub, url=f"http://127.0.0.1:{server.port}")
    server.stop()
    hub.stop()
    close_management_server(management)


@pytest.fixture(scope="session")
def hd_mock():
    """The offline mock server, started on a free port."""
    from hd_mock_server import MockServer

    mock = MockServer("playing_artwork", port=0)
    mock.start()
    yield mock
    mock.stop()


@pytest.fixture(scope="session")
def hd_real_url(hd_real) -> str:
    return hd_real.url


@pytest.fixture(scope="session")
def hd_mock_url(hd_mock) -> str:
    return hd_mock.url


@pytest.fixture(params=["hd_real_url", "hd_mock_url"])
def hd_url(request) -> str:
    """Each test that takes this runs once against each server."""
    return request.getfixturevalue(request.param)


# ---------------------------------------------------------------------------
# Browser context: the HD panel's size, touch input
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def browser_context_args(browser_context_args) -> dict:
    return {**browser_context_args, "viewport": dict(VIEWPORT), "has_touch": True,
            "is_mobile": False}


class Watcher:
    """Console errors, page errors and CSP violations seen on a page."""

    def __init__(self, page) -> None:
        self.errors: list = []
        page.on("console", self._console)
        page.on("pageerror", lambda e: self.errors.append(f"pageerror: {e}"))
        page.on("requestfailed", lambda r: self.errors.append(f"requestfailed: {r.url}"))
        page.add_init_script(
            "document.addEventListener('securitypolicyviolation', function (e) {"
            " window.__csp = (window.__csp || []).concat([e.violatedDirective]); });"
        )

    def _console(self, message) -> None:
        if message.type in ("error", "warning"):
            self.errors.append(f"console.{message.type}: {message.text}")


# ---------------------------------------------------------------------------
# Smoke: the page loads cleanly and the policy holds, against both servers
# ---------------------------------------------------------------------------

class TestPageLoads:
    def test_loads_with_no_console_errors(self, page, hd_url):
        watcher = Watcher(page)
        response = page.goto(hd_url + "/", wait_until="load")
        assert response.status == 200
        assert page.title() == "autostream dial"
        assert page.locator("#app").count() == 1
        assert page.evaluate("[innerWidth, innerHeight]") == [800, 480]
        page.wait_for_timeout(300)
        assert watcher.errors == []
        assert page.evaluate("window.__csp || []") == []

    def test_page_headers_carry_the_policy(self, page, hd_url):
        response = page.goto(hd_url + "/")
        policy = response.headers["content-security-policy"]
        assert "default-src 'none'" in policy
        assert "script-src 'self'" in policy
        assert "unsafe-inline" not in policy and "unsafe-eval" not in policy
        assert response.headers["x-content-type-options"] == "nosniff"

    def test_the_policy_blocks_inline_script(self, page, hd_url):
        Watcher(page)
        page.goto(hd_url + "/")
        ran = page.evaluate(
            "() => { window.__ran = false;"
            " const s = document.createElement('script');"
            " s.textContent = 'window.__ran = true';"
            " document.body.appendChild(s);"
            " return new Promise(r => setTimeout(() => r(window.__ran), 100)); }"
        )
        assert ran is False
        assert "script-src-elem" in page.evaluate("window.__csp || []") or \
            "script-src" in page.evaluate("window.__csp || []")

    def test_the_policy_blocks_other_origins(self, page, hd_url):
        Watcher(page)
        page.goto(hd_url + "/")
        blocked = page.evaluate(
            "() => fetch('http://example.invalid/').then(() => false, () => true)"
        )
        assert blocked is True
        assert "connect-src" in page.evaluate("window.__csp || []")

    def test_state_and_first_event_reach_the_page(self, page, hd_url):
        page.goto(hd_url + "/")
        state = page.evaluate("() => fetch('/api/v1/state').then(r => r.json())")
        assert isinstance(state, dict) and state
        first = page.evaluate(
            "() => new Promise((resolve, reject) => {"
            " const es = new EventSource('/api/v1/events');"
            " es.addEventListener('state', e => { es.close(); resolve(e.data); });"
            " es.onerror = () => { es.close(); reject('stream error'); };"
            " setTimeout(() => { es.close(); reject('timeout'); }, 5000); })"
        )
        event = json.loads(first)
        assert set(state) == set(event)
