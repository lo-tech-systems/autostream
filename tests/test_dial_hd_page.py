"""Static checks on the HD page's files: the content security policy the
dial's server sends (no inline script or style, nothing from another origin)
only holds if the files themselves keep to it, and appliance text must never
reach the DOM as markup."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
HD = REPO_ROOT / "dial" / "hd"
THEME = REPO_ROOT / "nginx" / "static" / "theme.css"

MARKUP_SINKS = ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function")


class _Scan(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.problems: list = []
        self.scripts: list = []
        self.stylesheets: list = []
        self._in_script = False

    def handle_starttag(self, tag, attrs) -> None:
        attrs = dict(attrs)
        for name in attrs:
            if name.startswith("on") or name == "style":
                self.problems.append(f"<{tag}> has {name}")
        if tag == "script":
            self._in_script = True
            if "src" not in attrs:
                self.problems.append("inline script")
            else:
                self.scripts.append(attrs["src"])
        if tag == "style":
            self.problems.append("style element")
        if tag == "link" and attrs.get("rel") == "stylesheet":
            self.stylesheets.append(attrs["href"])
        if tag in ("iframe", "object", "embed", "form"):
            self.problems.append(f"<{tag}>")

    def handle_data(self, data) -> None:
        if self._in_script and data.strip():
            self.problems.append("inline script body")

    def handle_endtag(self, tag) -> None:
        if tag == "script":
            self._in_script = False


def test_index_has_no_inline_script_or_style():
    scan = _Scan()
    scan.feed((HD / "index.html").read_text(encoding="utf-8"))
    assert scan.problems == []
    assert scan.scripts == ["/static/hd.js"]
    assert scan.stylesheets == ["/static/theme.css", "/static/hd.css"]


def test_index_uses_the_dark_theme():
    assert re.search(r'<html[^>]*data-theme="dark"', (HD / "index.html").read_text(encoding="utf-8"))


def test_script_never_builds_markup_from_text():
    source = (HD / "hd.js").read_text(encoding="utf-8")
    for sink in MARKUP_SINKS:
        assert sink not in source, sink


def test_script_posts_actions_through_one_helper():
    source = (HD / "hd.js").read_text(encoding="utf-8")
    assert source.count("fetch(") == 2          # the state check and post()
    assert source.count('"X-Requested-With": "autostream-hd"') == 1
    assert source.count("/api/v1/actions/") == 1


def test_stylesheets_load_nothing_else():
    # The policy is style-src 'self': an import or an external url() would be
    # blocked, so the shared theme must have none and the page's must not add any.
    for path in (THEME, HD / "hd.css"):
        css = path.read_text(encoding="utf-8")
        assert "@import" not in css, path
        for url in re.findall(r"url\(([^)]*)\)", css):
            assert url.strip("'\" ").startswith("#"), (path, url)


def test_every_request_the_script_makes_names_a_real_route():
    import sys
    for path in (REPO_ROOT / "dial", REPO_ROOT / "core"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    from dial_hd_actions import ACTIONS

    source = (HD / "hd.js").read_text(encoding="utf-8")
    sent = (
        set(re.findall(r'post\("([a-z_]+)"', source))
        | set(re.findall(r'sendDrag\([^,]+, "([a-z_]+)"', source))
        | set(re.findall(r'action: "([a-z_]+)"', source))
    )
    served = set(ACTIONS) | {"settings", "panel_wake", "panel_sleep", "panel_activity"}
    assert sent and sent <= served, sent - served
    # Every action the dial has a use for in the page is one the page can send.
    assert {"replay_start", "replay_restart", "replay_stop", "repeat_arm", "eq", "eq_reset",
            "warning_dismiss", "dial_restart", "presence"} <= sent

    routes = {"/api/v1/settings", "/api/v1/info", "/api/v1/state", "/api/v1/events",
              "/api/v1/panel/wake", "/api/v1/panel/sleep", "/api/v1/panel/activity",
              "/api/v1/actions/", "/api/v1/artwork/", "/api/v1/logo/backdrop"}
    assert set(re.findall(r'"(/api/v1/[a-z/_]*)"', source)) <= routes


def test_script_draws_the_response_curve_from_the_appliances_filters():
    source = (HD / "hd.js").read_text(encoding="utf-8")
    # The bass and treble sliders of a two-band appliance move these bands.
    assert re.search(r'bass: \[\["peq1", 1\], \["peq2", 1\]\]', source)
    assert re.search(r'treble: \[\["peq6", 1\], \["peq5", 0\.5\]\]', source)
    for kind in ("low_shelf", "high_shelf", "peak"):
        assert f'"{kind}"' in source
