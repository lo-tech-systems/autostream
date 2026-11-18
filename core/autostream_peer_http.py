"""autostream_peer_http.py -- the HTTP calls one appliance or dial makes to another.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Three small functions over the standard library: a JSON request that never
raises, the opening of an event stream, and a reader for the stream's lines.
Each call uses its own connection. The module imports nothing from the rest of
the program, so a dial can carry it unchanged.

Transport errors have three names: ``unreachable`` (the connection was refused,
timed out or reset before a reply, or the name did not resolve), ``timeout``
(the reply did not arrive in time) and ``bad_reply`` (the body is not a JSON
object, or is over the cap).
"""

from __future__ import annotations

import http.client
import json
import socket
from typing import Callable, Iterator, NamedTuple, Optional

UNREACHABLE = "unreachable"
TIMEOUT = "timeout"
BAD_REPLY = "bad_reply"

BODY_CAP = 512 * 1024
LINE_CAP = 256 * 1024

# Called with the connection's socket once it is open, and with None when the
# call has finished with it, so a caller can shut the socket from another
# thread to end a call that is blocked.
SocketTracker = Callable[[Optional[socket.socket]], None]


class SseEvent(NamedTuple):
    id: Optional[str]
    event: str          # "message" when the block names none; "ka" for a comment or a retry line
    data_text: str


class StreamError(Exception):
    """The stream broke the format: a line over the cap."""

    def __init__(self, name: str = BAD_REPLY) -> None:
        super().__init__(name)
        self.name = name


def _connect(host: str, port: int, connect_s: float, read_s: float,
             track: Optional[SocketTracker]) -> tuple[Optional[http.client.HTTPConnection], str]:
    conn = http.client.HTTPConnection(host, port, timeout=connect_s)
    try:
        conn.connect()
    except OSError:
        conn.close()
        return None, UNREACHABLE
    if conn.sock is None:
        return None, UNREACHABLE
    conn.sock.settimeout(read_s)
    if track is not None:
        track(conn.sock)
    return conn, ""


def _transport_error(exc: BaseException) -> str:
    return TIMEOUT if isinstance(exc, socket.timeout) else UNREACHABLE


def _parse_object(raw: bytes) -> Optional[dict]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def request_json(host: str, port: int, method: str, path: str, *,
                 body: Optional[dict] = None, connect_s: float = 1.0,
                 read_s: float = 2.0, cap: int = BODY_CAP,
                 track: Optional[SocketTracker] = None
                 ) -> tuple[int, Optional[dict], str]:
    """(status, parsed body or None, transport error name or ""). Never
    raises. A reply with a status and no JSON object gives the status, None and
    ``bad_reply``."""
    conn, error = _connect(host, port, connect_s, read_s, track)
    if conn is None:
        return 0, None, error
    status = 0
    try:
        headers = {"Host": f"{host}:{port}", "Accept": "application/json"}
        payload = None
        if body is not None:
            payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        status = resp.status
        raw = resp.read(cap + 1)
    except (OSError, http.client.HTTPException) as exc:
        return 0, None, _transport_error(exc)
    finally:
        if track is not None:
            track(None)
        conn.close()
    if len(raw) > cap:
        return status, None, BAD_REPLY
    parsed = _parse_object(raw)
    if parsed is None:
        return status, None, BAD_REPLY
    return status, parsed, ""


def open_events(host: str, port: int, path: str, *, last_event_id: Optional[str] = None,
                connect_s: float = 1.0, read_s: float = 25.0, cap: int = BODY_CAP,
                track: Optional[SocketTracker] = None
                ) -> tuple[Optional[http.client.HTTPResponse], int, Optional[dict], str]:
    """(response, status, refusal body, transport error name). An open event
    stream gives the response and status 200. Any other reply is a refusal:
    no response, its status and its JSON body (None when it has none). A
    transport failure gives status 0 and the error name. *read_s* bounds every
    read on the stream, so it is the longest the peer may stay silent. When a
    response is returned, *track* still holds the socket; the caller clears it
    when it closes the response."""
    conn, error = _connect(host, port, connect_s, read_s, track)
    if conn is None:
        return None, 0, None, error
    headers = {"Host": f"{host}:{port}", "Accept": "text/event-stream"}
    if last_event_id:
        headers["Last-Event-ID"] = last_event_id
    try:
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        if resp.status == 200 and (resp.getheader("Content-Type") or "").startswith("text/event-stream"):
            return resp, 200, None, ""
        status = resp.status
        raw = resp.read(cap + 1)
    except (OSError, http.client.HTTPException) as exc:
        if track is not None:
            track(None)
        conn.close()
        return None, 0, None, _transport_error(exc)
    if track is not None:
        track(None)
    conn.close()
    return None, status, (_parse_object(raw) if len(raw) <= cap else None), ""


def read_events(resp, *, line_cap: int = LINE_CAP) -> Iterator[SseEvent]:
    """The events on an open stream, until it ends. A comment line or a
    ``retry:`` line yields ``SseEvent(event="ka")`` at once, so a quiet stream
    still shows that the peer is there. A block with data yields one event at
    its blank line. Raises StreamError for a line over *line_cap*; a read
    that times out raises socket.timeout, and a reset raises OSError."""
    event_id: Optional[str] = None
    name = ""
    data: list[str] = []
    while True:
        raw = resp.readline(line_cap + 1)
        if not raw:
            return
        if len(raw) > line_cap:
            raise StreamError(BAD_REPLY)
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if not line:
            if data:
                yield SseEvent(event_id, name or "message", "\n".join(data))
            name, data = "", []
            continue
        if line.startswith(":"):
            yield SseEvent(None, "ka", "")
            continue
        field, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if field == "data":
            data.append(value)
        elif field == "event":
            name = value
        elif field == "id":
            event_id = value
        elif field == "retry":
            yield SseEvent(None, "ka", "")
