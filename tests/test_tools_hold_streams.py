"""tests/test_tools_hold_streams.py

The stream load tool against a real server: it holds streams, counts what
arrives, resumes a stream the server ended without a resync, and reports a
refusal.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
for _p in (_ROOT / "core", _ROOT / "tools"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import autostream_logging as log_setup
import hold_streams
from stream_helpers import Publisher, RealServer
import webui.protocol.hub as proto_hub
import webui.protocol.stream as proto_stream


@pytest.fixture
def server(monkeypatch):
    log_setup.reset_for_tests()
    s = RealServer(monkeypatch)
    yield s
    s.close()


def test_it_counts_events_and_resumes_a_stream_the_server_ended(server, monkeypatch, capsys):
    monkeypatch.setattr(proto_stream, "MAX_AGE_S", 1.0)
    publish = Publisher(server.store)
    timer = threading.Timer(0.4, lambda: publish("session"))
    timer.start()
    try:
        code = hold_streams.main([
            "--url", f"http://127.0.0.1:{server.port}/api/v1/events",
            "--clients", "2", "--seconds", "3"])
    finally:
        timer.cancel()
    out = capsys.readouterr().out
    assert code == 0
    lines = out.strip().splitlines()
    assert len(lines) == 2
    for line in lines:
        fields = dict(f.split("=", 1) for f in line.split(": ", 1)[1].split(" ") if "=" in f)
        assert int(fields["events"]) >= 1
        assert int(fields["resyncs"]) == 1
        assert int(fields["reconnects"]) >= 1


def test_a_refused_client_is_reported_and_fails_the_run(server, capsys):
    held = [server.connect() for _ in range(proto_hub.MAX_STREAMS_PER_ADDRESS)]
    try:
        for c in held:
            assert c.pull_until(b"retry: 2000")
        code = hold_streams.main([
            "--url", f"http://127.0.0.1:{server.port}/api/v1/events",
            "--clients", "1", "--seconds", "1"])
        assert code == 1
        assert "refused" in capsys.readouterr().out
    finally:
        for c in held:
            c.close()


def test_the_address_header_gives_each_group_its_own_address():
    assert hold_streams._address(0, 0) == ""
    assert hold_streams._address(0, 8) == hold_streams._address(7, 8)
    assert hold_streams._address(7, 8) != hold_streams._address(8, 8)
    assert len({hold_streams._address(i, 8) for i in range(64)}) == 8


def test_streams_beyond_one_address_limit_are_held_with_the_address_header(server, capsys):
    url = f"http://127.0.0.1:{server.port}/api/v1/events"
    code = hold_streams.main(["--url", url, "--clients", "10", "--seconds", "1"])
    assert code == 1
    assert capsys.readouterr().out.count("refused") == 2
    code = hold_streams.main(["--url", url, "--clients", "10", "--seconds", "1",
                              "--address-header", "5"])
    assert code == 0
    assert "refused" not in capsys.readouterr().out
