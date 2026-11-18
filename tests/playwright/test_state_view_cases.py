"""Playwright test: the state_view.js functions give the case table's answers.

Every case of tests/fixtures/state_view_cases.json is run in the page, in each
engine the run selects, and the result is compared with the expectation after
sorting keys. A case whose function the module does not export fails.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from _module_stub import start_blank_server

try:
    from playwright.sync_api import Page  # type: ignore[attr-defined]
    _PLAYWRIGHT_INSTALLED = True
except ImportError:
    _PLAYWRIGHT_INSTALLED = False
    Page = object  # type: ignore[misc,assignment]

pytestmark = [
    pytest.mark.skipif(not _PLAYWRIGHT_INSTALLED, reason="playwright not installed"),
    pytest.mark.engines,
]

CASES = json.loads(
    (Path(__file__).parent.parent / "fixtures" / "state_view_cases.json").read_text(encoding="utf-8"))["cases"]

_RUN = """
async ([cases]) => {
  const view = await import('/static/shared/state_view.js');
  const sortKeys = (v) => Array.isArray(v) ? v.map(sortKeys)
    : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])])) : v;
  return cases.map((c) => {
    const fn = view[c.fn];
    if (typeof fn !== 'function') return { name: c.name, error: 'no such function ' + c.fn };
    const got = c.fn === 'startFailure' ? fn(c.view, c.seen) : fn(c.parts, c.opts);
    return { name: c.name, got: sortKeys(got === undefined ? null : got) };
  });
}
"""


@pytest.fixture(scope="module")
def blank_url():
    server, url = start_blank_server()
    try:
        yield url
    finally:
        server.shutdown()


def _sorted(v):
    if isinstance(v, list):
        return [_sorted(x) for x in v]
    if isinstance(v, dict):
        return {k: _sorted(v[k]) for k in sorted(v)}
    return v


def test_every_case_gives_its_expected_answer(page: "Page", blank_url):
    page.goto(blank_url + "/")
    results = page.evaluate(_RUN, [CASES])
    assert [r["name"] for r in results] == [c["name"] for c in CASES]
    bad = [
        (r["name"], r.get("error") or r["got"], c["expect"])
        for r, c in zip(results, CASES)
        if "error" in r or _sorted(r["got"]) != _sorted(c["expect"])
    ]
    assert not bad, "\n".join(f"{n}: got {g!r}, want {w!r}" for n, g, w in bad)
