"""Helpers the Home page tests share: open the page on arranged parts, collect
page errors, and wait for the stub.

The Home page tests are written against ``_home_stub`` (the parts it serves,
``push``, ``POSTS``); these are the few steps nearly every one of them repeats.
"""
from __future__ import annotations

import re
import time

import _home_stub as stub

SHOWN = re.compile(r"\bshow\b")


def speaker(selected: bool = False, **fields) -> dict:
    """The usual one-speaker row (id ``tv``)."""
    return stub.unit("tv", fields.pop("name", "Speaker A"), selected=selected, **fields)


def outputs(*units: dict, **fields) -> dict:
    return stub.outputs_part(*units, **fields)


def open_home(page, base: str, parts: dict | None = None, *, stream: bool = True,
              wait_cards: bool = True, **render) -> None:
    """Render Home on *parts*, serve it, and load it. With *stream* the event
    stream is served (else it is refused, the page polls). With *wait_cards* it
    waits for the first speaker card (so *parts* must hold a unit with id ``tv``)."""
    parts = dict(parts or {})
    parts.setdefault("outputs", outputs(speaker()))
    stub.set_page(stub.render_home(parts=parts, **render))
    for log in (stub.POSTS, stub.POST_PATHS, stub.POST_TOKENS, stub.REPLIES):
        log.clear()
    if stream:
        stub.stream_on()
    page.goto(f"{base}/")
    if wait_cards:
        page.wait_for_selector("#output_enabled_tv", state="attached")


def wait_stream(page, ms: int = 600) -> None:
    """Wait until a stream is open on the stub and the page has acted on it."""
    wait_for(page, lambda: stub.open_streams() >= 1, "the page to open the stream", 10)
    page.wait_for_timeout(ms)


def wait_for(page, done, what: str, seconds: float = 5.0) -> None:
    deadline = time.monotonic() + seconds
    while not done() and time.monotonic() < deadline:
        page.wait_for_timeout(25)
    assert done(), f"timed out waiting for {what}"


def intents() -> list:
    """(name, args) of every intent posted so far."""
    return [(p.rsplit("/", 1)[1], b.get("args")) for p, b in zip(stub.POST_PATHS, stub.POSTS)
            if p.startswith("/api/v1/intents/")]


class Errors:
    """Console errors and page errors; a test fails if any is left at its end."""

    def __init__(self) -> None:
        self.seen: list[str] = []
        self.ignore: list[str] = []

    def left(self) -> list[str]:
        return [t for t in self.seen if not any(i in t for i in self.ignore)]


def watch_errors(page) -> Errors:
    e = Errors()
    page.on("console", lambda m: e.seen.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda x: e.seen.append(str(x)))
    return e
