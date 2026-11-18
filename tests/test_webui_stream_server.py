"""tests/test_webui_stream_server.py

The state stream and the state snapshot through a real ThreadingHTTPServer
and the route table: headers, delivery, the client cap and its refusal, the
commissioning and sign-in gates, the shape of the state body, and that other
requests are served while streams are held.
"""
from __future__ import annotations

import json
import logging
import secrets
import sys
import time
from pathlib import Path

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_logging as log_setup
import autostream_state as state
from autostream_auth import SESSION_COOKIE_NAME, Session
from stream_helpers import Publisher, RealServer, wait_for
import webui.protocol.hub as proto_hub
import webui.protocol.state as proto_state


@pytest.fixture
def server(monkeypatch):
    log_setup.reset_for_tests()
    s = RealServer(monkeypatch)
    yield s
    s.close()


@pytest.fixture
def publish(server):
    return Publisher(server.store)


def _held(server, n: int) -> list:
    clients = []
    for _ in range(n):
        c = server.connect()
        assert c.pull_until(b"retry: 2000")
        clients.append(c)
    return clients


def test_the_events_route_answers_with_a_stream_and_a_resync_event(server, publish, caplog):
    caplog.set_level(logging.DEBUG)
    publish("settings")
    c = server.connect()
    try:
        assert c.pull_until(b"event: change")
        head = c.head
        assert head.startswith("HTTP/1.1 200")
        assert "Content-Type: text/event-stream" in head
        assert "Cache-Control: no-store" in head
        assert "X-Accel-Buffering: no" in head
        assert c.body.startswith(b"retry: 2000\n\n")
        (event,) = c.events()
        assert event["resync"] is True
        assert event["version"] == server.store.snapshot().version
    finally:
        c.close()
    access = [r for r in caplog.records if "/api/v1/events" in r.getMessage() and "GET" in r.getMessage()]
    assert access and all(r.levelno == logging.DEBUG for r in access)


def test_a_publish_reaches_a_held_client_promptly(server, publish):
    c = server.connect()
    try:
        assert c.pull_until(b"retry: 2000")
        assert c.pull_until(b"event: change")       # the resync event
        c.pull(0.2)
        t0 = time.monotonic()
        publish("session")
        assert wait_for(lambda: (c.pull(0.05), len(c.events()) == 2)[1], 3.0)
        assert time.monotonic() - t0 < 1.5
        assert list(c.events()[-1]["data"]) == ["session"]
    finally:
        c.close()


def test_the_ninth_client_is_refused_and_a_freed_slot_is_taken(server, caplog):
    caplog.set_level(logging.INFO)
    held = _held(server, proto_hub.MAX_STREAMS_PER_ADDRESS)
    try:
        assert server.hub.client_count() == 8
        ninth = server.connect()
        assert ninth.pull_until(b"too_many_from_address")
        assert ninth.head.startswith("HTTP/1.1 200")
        assert "application/json" in ninth.head
        assert json.loads(ninth.body) == {
            "ok": False, "error": "too_many_from_address", "error_status": 503, "retryable": True}
        ninth.close()
        refusals = [r for r in caplog.records if "refused a client" in r.getMessage()]
        assert len(refusals) == 1
        assert refusals[0].levelno == logging.INFO
        again = server.connect()
        assert again.pull_until(b"too_many_from_address")
        again.close()
        assert len([r for r in caplog.records if "refused a client" in r.getMessage()]) == 1
        held.pop().close()
        assert wait_for(lambda: server.hub.client_count() == 7, 5.0)
        taker = server.connect()
        held.append(taker)
        assert taker.pull_until(b"retry: 2000")
        assert taker.pull_until(b"event: change")
        assert server.hub.client_count() == 8
    finally:
        for c in held:
            c.close()


def test_a_stream_request_is_served_while_commissioning(server):
    server.commissioning_required = True
    c = server.connect()
    try:
        assert c.pull_until(b"retry: 2000")
        assert c.head.startswith("HTTP/1.1 200")
        assert server.hub.client_count() == 1
    finally:
        c.close()


def test_a_request_naming_another_origin_is_refused(server):
    c = server.connect(headers={"Origin": "http://elsewhere.example"})
    try:
        assert c.pull_until(b"cross_origin")
        assert c.head.startswith("HTTP/1.1 403")
        assert server.hub.client_count() == 0
    finally:
        c.close()
    ok = server.connect(headers={"Origin": f"http://127.0.0.1:{server.port}"})
    try:
        assert ok.pull_until(b"retry: 2000")
    finally:
        ok.close()


def test_the_events_route_needs_no_sign_in(monkeypatch):
    s = RealServer(monkeypatch, pin="1234abcd")
    try:
        c = s.connect()
        assert c.pull_until(b"retry: 2000")
        assert c.head.startswith("HTTP/1.1 200")
        c.close()
    finally:
        s.close()


def test_the_state_route_needs_no_pin_when_one_is_set(monkeypatch):
    s = RealServer(monkeypatch, pin="1234abcd")
    try:
        status, body = s.get("/api/v1/state")
        assert status == 200
        assert json.loads(body)["boot"] == s.store.snapshot().boot
    finally:
        s.close()


def test_the_state_route_is_served_while_commissioning(server, publish):
    server.commissioning_required = True
    publish("settings")
    status, body = server.get("/api/v1/state")
    assert status == 200
    assert json.loads(body)["version"] == server.store.snapshot().version


def test_the_state_route_without_a_pin_returns_the_snapshot(server, publish):
    publish("settings")
    publish("session")
    status, body = server.get("/api/v1/state")
    assert status == 200
    got = json.loads(body)
    # The wall clock moves between the two builds; everything else is as held.
    expected = proto_state.state_json(server.store.snapshot(), clients=0)
    assert abs(got.pop("time") - expected.pop("time")) < 5.0
    assert got == expected
    assert len(got["boot"]) == 16 and all(ch in "0123456789abcdef" for ch in got["boot"])


def test_without_a_hub_both_routes_answer_not_found(server):
    proto_hub.install(None)
    for path in ("/api/v1/events", "/api/v1/state"):
        status, body = server.get(path)
        assert status == 200
        assert json.loads(body) == {"ok": False, "error": "not_found", "error_status": 404}


def _no_constant(name):
    raise AssertionError(f"non-finite number in the state body: {name}")


@pytest.mark.parametrize("scenario_id", ["idle", "one_output_playing_input1", "backend_unreachable"])
def test_the_state_body_has_the_shape_of_the_snapshot(scenario_id, monkeypatch):
    """The body is unstable, so its shape is checked here rather than recorded."""
    import dataclasses
    import golden_scenarios

    golden_scenarios.apply(golden_scenarios.SCENARIOS[scenario_id], monkeypatch)
    store = state.store()
    hub = proto_hub.StreamHub(store)
    body = json.loads(hub.state_body(), parse_constant=_no_constant)
    snap = store.snapshot()
    assert list(body) == ["boot", "version", "protocol", "time", "clients", "part_versions", "parts"]
    assert isinstance(body["time"], float)
    assert body["protocol"] == 4
    assert set(body["parts"]) == set(state.PART_NAMES)
    assert set(body["part_versions"]) <= set(state.PART_NAMES)
    assert body["boot"] == snap.boot
    assert isinstance(body["version"], int) and body["version"] == snap.version
    assert body["clients"] == hub.client_count() == 0
    for name, part in body["parts"].items():
        value = getattr(snap, name)
        if dataclasses.is_dataclass(value):
            assert set(part) == {f.name for f in dataclasses.fields(value)}, name


def test_other_requests_are_served_while_streams_are_held(server, monkeypatch):
    import golden_scenarios

    golden_scenarios.apply(golden_scenarios.SCENARIOS["idle"], monkeypatch)
    held = _held(server, proto_hub.MAX_STREAMS_PER_ADDRESS)
    try:
        slowest = 0.0
        for _ in range(50):
            t0 = time.monotonic()
            status, _body = server.get("/api/v1/state")
            slowest = max(slowest, time.monotonic() - t0)
            assert status == 200
        assert slowest < 0.5
    finally:
        for c in held:
            c.close()


def test_parts_returns_only_the_named_parts(server, publish):
    publish("settings")
    publish("session")
    status, body = server.get("/api/v1/state?parts=session,settings")
    assert status == 200
    got = json.loads(body)
    snap = server.store.snapshot()
    full = proto_state.state_json(snap, clients=0)
    assert list(got["parts"]) == ["session", "settings"]
    assert got["parts"] == {n: full["parts"][n] for n in ("session", "settings")}
    assert got["part_versions"] == full["part_versions"]
    assert got["protocol"] == 4 and got["version"] == snap.version


def full_appliance(server):
    return proto_state.state_json(server.store.snapshot(), clients=0)["parts"]["appliance"]


def test_an_empty_parts_returns_the_top_level_and_the_appliance(server, publish):
    publish("session")
    status, body = server.get("/api/v1/state?parts=")
    assert status == 200
    got = json.loads(body)
    assert got["parts"] == {"appliance": full_appliance(server)}
    assert set(got) == {"boot", "version", "protocol", "time", "clients", "part_versions", "parts"}


@pytest.mark.parametrize("query", ["parts=nonsense", "parts=session,nonsense", "parts=session,,settings"])
def test_an_unknown_part_is_refused(server, query):
    status, body = server.get(f"/api/v1/state?{query}")
    assert status == 400
    assert json.loads(body) == {"ok": False, "error": "unknown_part"}


def test_a_filtered_body_is_built_from_the_live_snapshot_on_each_request(server, publish, monkeypatch):
    builds = []
    real = proto_state.state_json
    monkeypatch.setattr(proto_state, "state_json",
                        lambda snap, **kw: builds.append(kw.get("parts")) or real(snap, **kw))
    publish("session")
    server.get("/api/v1/state?parts=session")
    server.get("/api/v1/state?parts=session")
    assert builds == [("session",), ("session",)]
    builds.clear()
    server.get("/api/v1/state")
    server.get("/api/v1/state")
    assert builds == [None]                              # the whole body is shared for a second


def test_the_events_route_refuses_another_protocol_number(server):
    status, body = server.get("/api/v1/events?protocol=3")
    assert status == 200
    assert json.loads(body) == {"ok": False, "error": "protocol_mismatch", "protocol": 4}
    assert server.hub.client_count() == 0


def test_a_request_header_address_gives_each_address_its_own_eight(server):
    held = []
    try:
        for n in range(2 * proto_hub.MAX_STREAMS_PER_ADDRESS):
            c = server.connect(headers={"X-Real-IP": f"10.0.0.{n // 8 + 1}"})
            held.append(c)
            assert c.pull_until(b"retry: 2000")
        assert server.hub.client_count() == 16
        ninth = server.connect(headers={"X-Real-IP": "10.0.0.1"})
        held.append(ninth)
        assert ninth.pull_until(b"too_many_from_address")
    finally:
        for c in held:
            c.close()
