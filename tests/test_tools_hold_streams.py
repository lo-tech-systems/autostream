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
from webui import stream


@pytest.fixture
def server(monkeypatch):
    log_setup.reset_for_tests()
    s = RealServer(monkeypatch)
    yield s
    s.close()


def test_it_counts_events_and_resumes_a_stream_the_server_ended(server, monkeypatch, capsys):
    monkeypatch.setattr(stream, "MAX_AGE_S", 1.0)
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
    held = [server.connect() for _ in range(stream.MAX_CLIENTS)]
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
