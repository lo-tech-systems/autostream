#!/usr/bin/env python3
"""hold_streams.py -- hold state change streams open and report on them.

Opens N streams to the appliance, holds them for a while, resumes each one
with its last event id when the server ends it, and prints per client how
many events and heartbeats arrived, how often it reconnected, the longest
silence, and how each stream ended. It is the load for the memory check (eight
streams is the server's cap) and for long soaks by hand.

    python tools/hold_streams.py [--url URL] [--clients N] [--seconds S]

The stream's body has no length and is not chunked: it ends when the server
closes the connection. The tool therefore speaks HTTP over a raw socket and
reads until the connection closes; an HTTP client library would wait for a
terminator that never comes.

Exit status is 0 when every client held a stream, 1 when one was refused or
could not connect.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import argparse
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

DEFAULT_URL = "http://localhost/api/v1/events"


@dataclass
class Report:
    client: int
    events: int = 0
    heartbeats: int = 0
    resyncs: int = 0
    reconnects: int = 0
    longest_silence: float = 0.0
    ends: list = field(default_factory=list)
    failed: bool = False

    def line(self) -> str:
        ended = ", ".join(self.ends) if self.ends else "-"
        return (f"client {self.client}: events={self.events} heartbeats={self.heartbeats} "
                f"resyncs={self.resyncs} reconnects={self.reconnects} "
                f"longest_silence={self.longest_silence:.1f}s ended=[{ended}]")


def _hold(host: str, port: int, path: str, deadline: float, report: Report) -> None:
    last_id = ""
    first = True
    while time.monotonic() < deadline:
        if not first:
            report.reconnects += 1
        first = False
        try:
            sock = socket.create_connection((host, port), timeout=5.0)
        except OSError as exc:
            report.ends.append(f"connect failed: {exc.__class__.__name__}")
            report.failed = True
            return
        try:
            lines = [f"GET {path} HTTP/1.1", f"Host: {host}:{port}", "Accept: text/event-stream"]
            if last_id:
                lines.append(f"Last-Event-ID: {last_id}")
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
            outcome = _read(sock, deadline, report)
        except OSError as exc:
            outcome = f"error: {exc.__class__.__name__}"
        finally:
            sock.close()
        if isinstance(outcome, tuple):
            outcome, last_id = outcome[0], outcome[1] or last_id
        report.ends.append(outcome)
        if outcome.startswith("refused") or outcome.startswith("error"):
            report.failed = True
            return


def _read(sock, deadline: float, report: Report):
    """Read one stream to its end. Returns (reason, last event id)."""
    buf = b""
    last_id = ""
    in_body = False
    last_rx = time.monotonic()
    head = b""
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            return ("held until the deadline", last_id)
        sock.settimeout(min(1.0, left))
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        now = time.monotonic()
        if not chunk:
            return ("closed by the server", last_id)
        report.longest_silence = max(report.longest_silence, now - last_rx)
        last_rx = now
        buf += chunk
        if not in_body:
            head, sep, buf = buf.partition(b"\r\n\r\n")
            if not sep:
                buf = head
                continue
            in_body = True
            text = head.decode("latin-1")
            status = text.split(" ", 2)[1] if " " in text else "?"
            if status != "200" or "text/event-stream" not in text.lower():
                return (f"refused (status {status}, not a stream)", last_id)
        while b"\n" in buf:
            raw, buf = buf.split(b"\n", 1)
            line = raw.decode("utf-8", "replace").rstrip("\r")
            if line.startswith(":"):
                report.heartbeats += 1
            elif line.startswith("id: "):
                last_id = line[4:]
            elif line == "event: change":
                report.events += 1
            elif line.startswith("data: ") and '"resync":true' in line:
                report.resyncs += 1


def run(url: str, clients: int, seconds: float) -> list:
    """Hold *clients* streams to *url* for *seconds*; return one Report each."""
    parts = urlsplit(url)
    host = parts.hostname or "localhost"
    port = parts.port or 80
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    deadline = time.monotonic() + seconds
    reports = [Report(i + 1) for i in range(clients)]
    threads = [
        threading.Thread(target=_hold, args=(host, port, path, deadline, r), daemon=True)
        for r in reports
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(seconds + 15.0)
    return reports


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Hold state change streams open and report.")
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--clients", type=int, default=8)
    ap.add_argument("--seconds", type=float, default=60.0)
    args = ap.parse_args(argv)
    reports = run(args.url, args.clients, args.seconds)
    for r in reports:
        print(r.line())
    return 1 if any(r.failed for r in reports) else 0


if __name__ == "__main__":
    sys.exit(main())
