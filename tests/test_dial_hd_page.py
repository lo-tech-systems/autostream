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
