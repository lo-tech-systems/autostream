"""The HD page in the kiosk's own engine: WPE WebKit, run by cog.

Playwright's WebKit is desktop WebKit; the HD dial's kiosk is cog on WPE
WebKit, and the two differ (a vertical writing mode on a range input is one
known case). These tests drive real cog through WPEWebDriver (package
wpewebkit-webdriver) with cog's headless platform, against the production HD
server over a fake core. Without cog or WPEWebDriver every test skips.

What WPEWebDriver offers here: navigation, scripts, element clicks (delivered
as trusted mouse events), keys and screenshots. Pointer actions (drags, touch)
are accepted but reach nothing on cog's platforms, so pointer behaviour stays
with the Playwright tests and a real panel. The headless window is 800x600.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import shutil
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

COG = shutil.which("cog")
DRIVER = shutil.which("WPEWebDriver")
WINDOW = (800, 600)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Wpe:
    """One cog session over the W3C WebDriver protocol, kept to the calls the
    tests use."""

    def __init__(self, driver_url: str) -> None:
        # cog is a single-instance application on the session bus: a second
        # one with the same ID hands over to the first and exits, so each
        # session (one per xdist worker at a time) gets its own.
        app_id = f"org.autostream.wpetest.t{uuid.uuid4().hex}"
        caps = {"capabilities": {"alwaysMatch": {
            "browserName": "cog",
            "wpe:browserOptions": {"binary": COG, "args": [
                "--automation", "--platform=headless", f"--gapplication-app-id={app_id}"]},
        }}}
        reply = requests.post(f"{driver_url}/session", json=caps, timeout=30).json()["value"]
        if "sessionId" not in reply:
            raise RuntimeError(f"cog session not created: {reply}")
        self._base = f"{driver_url}/session/{reply['sessionId']}"

    def _call(self, method: str, path: str, body=None):
        reply = requests.request(method, self._base + path, json={} if body is None else body, timeout=30)
        value = reply.json().get("value")
        if reply.status_code != 200:
            raise RuntimeError(f"{method} {path}: {value}")
        return value

    def goto(self, url: str) -> None:
        self._call("POST", "/url", {"url": url})

    def js(self, script: str, *args):
        return self._call("POST", "/execute/sync", {"script": script, "args": list(args)})

    def click(self, css: str) -> None:
        """Click *css* once it is shown and enabled."""
        assert self.wait_for(
            "const e = document.querySelector(arguments[0]);"
            "return !!e && !e.disabled && e.getClientRects().length > 0 && getComputedStyle(e).visibility !== 'hidden'",
            css), f"{css} never became clickable"
        found = self._call("POST", "/element", {"using": "css selector", "value": css})
        self._call("POST", f"/element/{next(iter(found.values()))}/click")

    def screenshot_png(self) -> bytes:
        import base64
        return base64.b64decode(self._call("GET", "/screenshot"))

    def wait_for(self, script: str, *args, timeout: float = 5.0):
        """Poll *script* until it returns something truthy; return that."""
        deadline = time.monotonic() + timeout
        while True:
            value = self.js(script, *args)
            if value or time.monotonic() > deadline:
                return value
            time.sleep(0.05)

    def close(self) -> None:
        try:
            requests.delete(self._base, timeout=10)
        except requests.RequestException:
            pass


@pytest.fixture(scope="session")
def wpe_driver():
    if not (COG and DRIVER):
        pytest.skip("real WPE needs cog and WPEWebDriver: apt install cog wpewebkit-webdriver")
    port = _free_port()
    proc = subprocess.Popen([DRIVER, f"--port={port}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 10
    while True:
        try:
            if requests.get(f"{url}/status", timeout=1).json()["value"]["ready"]:
                break
        except (requests.RequestException, ValueError, KeyError):
            pass
        if time.monotonic() > deadline or proc.poll() is not None:
            proc.kill()
            pytest.skip("WPEWebDriver did not start")
        time.sleep(0.1)
    yield url
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="session")
def hd_server(wpe_driver):
    from hd_preview import HdPreview

    with HdPreview() as preview:
        yield preview


@pytest.fixture
def hd(hd_server):
    import hd_scenarios as hs

    hd_server.reset()
    hd_server.show(hs.SCENARIOS["playing_artwork"])
    return hd_server


@pytest.fixture
def wpe(wpe_driver, hd):
    """A fresh cog on the HD page, showing the dial's playing state (the title
    reads a placeholder until the first state arrives)."""
    session = Wpe(wpe_driver)
    try:
        session.goto(hd.url + "/")
        assert session.wait_for(
            "return document.getElementById('title').textContent === 'Tunnel of Love'"), "page never painted"
        yield session
    finally:
        session.close()
