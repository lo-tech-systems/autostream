"""Playwright tests: the shared ES modules (state_stream.js, pending.js).

Each case loads a blank page, replaces EventSource and fetch with fakes the
test drives, and runs the module under the page's clock. The fake stream is
``window.__es`` (one entry per EventSource the module opened); the fake
``fetch`` answers ``window.__reply(url)`` and records each URL in
``window.__fetches``.
"""
from __future__ import annotations

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

_FAKES = """
() => {
  window.__es = [];
  window.__fetches = [];
  window.__log = [];
  window.__state = null;
  window.__reply = () => window.__state;
  window.EventSource = class {
    constructor(url) { this.url = url; this.readyState = 0; this.l = {}; window.__es.push(this); }
    addEventListener(t, f) { (this.l[t] = this.l[t] || []).push(f); }
    close() { this.readyState = 2; this.closed = true; }
    emit(t, data) { (this.l[t] || []).forEach((f) => f({ data: JSON.stringify(data) })); }
  };
  window.fetch = async (url) => {
    window.__fetches.push(url);
    const body = JSON.parse(JSON.stringify(window.__reply(url)));
    return { ok: true, json: async () => body };
  };
}
"""

_INITIAL = {
    "boot": "b1", "version": 5, "time": 100.0,
    "parts": {"a": {"x": 1}, "c": {"y": 1}},
    "part_versions": {"a": 3, "c": 1},
}

_MAKE = """
async (initial) => {
  const { StateStream } = await import('/static/shared/state_stream.js');
  window.__s = new StateStream({
    base: '/api/v1', initial,
    onChange: (v, names, resync) => window.__log.push(['change', names, resync, v.version]),
    onAccess: (b) => window.__log.push(['access', b]),
    onUp: () => window.__log.push(['up']),
    onDown: () => window.__log.push(['down']),
    onRefused: (status, error) => window.__log.push(['refused', status, error]),
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


@pytest.fixture
def stream(page: "Page", blank_url):
    """A StateStream over the fakes, on the page's installed clock."""
    page.goto(blank_url + "/")
    page.clock.install()
    page.evaluate(_FAKES)
    page.evaluate(_MAKE, _INITIAL)
    return page


def _log(page):
    return page.evaluate("() => window.__log")


def _view(page):
    return page.evaluate("() => window.__s.view")


def _open(page):
    page.evaluate("() => window.__es[window.__es.length - 1].emit('open', {})")


def _emit(page, kind, data):
    page.evaluate("([k, d]) => window.__es[window.__es.length - 1].emit(k, d)", [kind, data])


def _state(page, **fields):
    body = dict(_INITIAL, **fields)
    page.evaluate("(b) => { window.__state = b; }", body)


class TestStateStream:
    def test_it_opens_with_the_position_of_the_state_it_holds(self, stream):
        assert stream.evaluate("() => window.__es.map((e) => e.url)") == ["/api/v1/events?since=b1-5"]

    def test_a_stream_with_no_state_asks_for_no_position(self, page, blank_url):
        page.goto(blank_url + "/")
        page.evaluate(_FAKES)
        page.evaluate(_MAKE, None)
        assert page.evaluate("() => window.__es[0].url") == "/api/v1/events"

    def test_a_change_merges_the_parts_it_carries(self, stream):
        _open(stream)
        _emit(stream, "change", {"boot": "b1", "version": 6, "resync": False, "parts": ["a"], "data": {"a": {"x": 2}}})
        v = _view(stream)
        assert v["parts"] == {"a": {"x": 2}, "c": {"y": 1}}
        assert (v["version"], v["partVersions"]) == (6, {"a": 6, "c": 1})
        assert _log(stream) == [["up"], ["change", ["a"], False, 6]]

    def test_a_resync_replaces_the_copy_from_the_state_route(self, stream):
        _open(stream)
        _state(stream, version=9, parts={"a": {"x": 7}}, part_versions={"a": 9})
        _emit(stream, "change", {"boot": "b1", "version": 9, "resync": True, "parts": ["a", "c"], "data": {}})
        v = _view(stream)
        assert v["parts"] == {"a": {"x": 7}} and v["version"] == 9 and v["partVersions"] == {"a": 9}
        assert _log(stream)[-1] == ["change", None, True, 9]
        assert stream.evaluate("() => window.__fetches") == ["/api/v1/state"]

    def test_a_state_fetch_answered_with_a_named_refusal_calls_onRefused(self, stream):
        _open(stream)
        _state(stream, ok=False, error="unknown_appliance", error_status=404)
        _emit(stream, "change", {"boot": "b1", "version": 9, "resync": True, "parts": [], "data": {}})
        assert _log(stream)[-1] == ["refused", 404, "unknown_appliance"]
        assert _view(stream)["version"] == 5

    def test_a_state_fetch_that_fails_calls_onRefused_with_status_zero(self, stream):
        _open(stream)
        stream.evaluate("() => { window.fetch = async () => { throw new TypeError('network'); }; }")
        _emit(stream, "change", {"boot": "b1", "version": 9, "resync": True, "parts": [], "data": {}})
        assert _log(stream)[-1] == ["refused", 0, "unreachable"]

    def test_an_access_event_reaches_onAccess(self, stream):
        _open(stream)
        _emit(stream, "access", {"role": "viewer"})
        assert _log(stream)[-1] == ["access", {"role": "viewer"}]

    def test_a_dropped_stream_is_down_only_after_the_grace_period(self, stream):
        _open(stream)
        _emit(stream, "error", {})
        stream.clock.run_for(4900)
        assert ["down"] not in _log(stream)
        stream.clock.run_for(200)
        assert _log(stream).count(["down"]) == 1
        assert stream.evaluate("() => window.__s.isUp()") is False

    def test_a_reconnect_within_the_grace_period_is_not_down(self, stream):
        _open(stream)
        _emit(stream, "error", {})
        stream.clock.run_for(2000)
        _open(stream)
        stream.clock.run_for(10000)
        assert _log(stream) == [["up"]]

    def test_a_refused_stream_is_down_at_once_and_opened_again_later(self, stream):
        stream.evaluate("() => { const e = window.__es[0]; e.readyState = 2; e.emit('error', {}); }")
        assert _log(stream) == [["down"]]
        stream.clock.run_for(23000)
        assert stream.evaluate("() => window.__es.length") == 1
        stream.clock.run_for(14000)
        assert stream.evaluate("() => window.__es.length") == 2

    def test_while_down_a_newer_version_in_the_same_boot_is_taken(self, stream):
        stream.evaluate("() => { const e = window.__es[0]; e.readyState = 2; e.emit('error', {}); }")
        _state(stream, version=5)
        stream.clock.run_for(2000)
        assert _log(stream) == [["down"]]
        _state(stream, version=8, parts={"a": {"x": 5}}, part_versions={"a": 8})
        stream.clock.run_for(2000)
        assert _log(stream)[-1] == ["change", None, False, 8]
        assert _view(stream)["parts"] == {"a": {"x": 5}}

    def test_while_down_a_new_boot_with_a_lower_version_replaces_the_state_whole(self, stream):
        stream.evaluate("() => { const e = window.__es[0]; e.readyState = 2; e.emit('error', {}); }")
        _state(stream, boot="b2", version=2, parts={"a": {"x": 0}}, part_versions={"a": 1})
        stream.clock.run_for(2000)
        assert _log(stream)[-1] == ["change", None, True, 2]
        v = _view(stream)
        assert (v["boot"], v["version"], v["partVersions"], v["parts"]) == ("b2", 2, {"a": 1}, {"a": {"x": 0}})

    def test_the_fallback_polls_every_two_seconds_and_stops_when_the_stream_is_up(self, stream):
        stream.evaluate("() => { const e = window.__es[0]; e.readyState = 2; e.emit('error', {}); }")
        _state(stream)
        stream.clock.run_for(6000)
        n = len(stream.evaluate("() => window.__fetches"))
        assert n >= 3
        stream.clock.run_for(30000)
        _open(stream)
        count = len(stream.evaluate("() => window.__fetches"))
        stream.clock.run_for(10000)
        assert len(stream.evaluate("() => window.__fetches")) == count
        assert _log(stream)[-1] == ["up"]

    def test_pollParts_merges_the_fast_fields_and_leaves_the_versions(self, stream):
        stream.evaluate("() => { window.__stop = window.__s.pollParts(['a'], 1000); }")
        _state(stream, parts={"a": {"x": 42}}, part_versions={"a": 99}, version=99, time=200.0)
        stream.clock.run_for(1000)
        v = _view(stream)
        assert v["parts"] == {"a": {"x": 42}, "c": {"y": 1}}
        assert (v["version"], v["partVersions"], v["time"]) == (5, {"a": 3, "c": 1}, 200.0)
        assert stream.evaluate("() => window.__fetches[0]") == "/api/v1/state?parts=a"
        assert ["change", ["a"], False, 5] in _log(stream)

    def test_pollParts_stops(self, stream):
        stream.evaluate("() => { window.__stop = window.__s.pollParts(['a'], 1000); }")
        _state(stream)
        stream.clock.run_for(2000)
        stream.evaluate("() => window.__stop()")
        count = len(stream.evaluate("() => window.__fetches"))
        stream.clock.run_for(5000)
        assert len(stream.evaluate("() => window.__fetches")) == count

    def test_close_ends_everything(self, stream):
        stream.evaluate("() => window.__s.close()")
        assert stream.evaluate("() => window.__es[0].closed") is True
        stream.clock.run_for(60000)
        assert stream.evaluate("() => window.__es.length") == 1 and _log(stream) == []

    def test_restart_opens_a_new_stream(self, stream):
        stream.evaluate("() => window.__s.restart()")
        assert stream.evaluate("() => [window.__es[0].closed, window.__es.length]") == [True, 2]


_PENDING = """
async () => {
  const { Pending } = await import('/static/shared/pending.js');
  let now = 0;
  const p = new Pending(() => now);
  const out = {};
  p.mark('u1', 40, 7);
  p.mark('u2', 60, 7);
  out.held = [p.value('u1', 10), p.value('u2', 10), p.value('u3', 10)];
  p.settle(6, false);
  out.before = [p.value('u1', 10), p.value('u2', 10)];
  p.settle(7, false);
  out.after = [p.value('u1', 10), p.value('u2', 10)];
  p.mark('u1', 40, 99);
  now = 1999; out.nearly = p.value('u1', 10);
  now = 2000; out.expired = p.value('u1', 10);
  p.mark('u1', 40, 99);
  p.mark('u2', 60, null);
  p.settle(1, true);
  out.resync = [p.value('u1', 10), p.value('u2', 10)];
  p.mark('u1', 40, null);
  p.settle(1000, false);
  out.unknownVersion = p.value('u1', 10);
  return out;
}
"""


class TestPending:
    def test_it_holds_each_unit_until_the_copy_reaches_the_reply_version(self, page: "Page", blank_url):
        page.goto(blank_url + "/")
        out = page.evaluate(_PENDING)
        assert out["held"] == [40, 60, 10]
        assert out["before"] == [40, 60]
        assert out["after"] == [10, 10]

    def test_it_lets_go_after_two_seconds(self, page: "Page", blank_url):
        page.goto(blank_url + "/")
        out = page.evaluate(_PENDING)
        assert (out["nearly"], out["expired"]) == (40, 10)

    def test_a_resync_drops_everything_and_an_unknown_version_waits_for_the_time(self, page: "Page", blank_url):
        page.goto(blank_url + "/")
        out = page.evaluate(_PENDING)
        assert out["resync"] == [10, 10]
        assert out["unknownVersion"] == 40
