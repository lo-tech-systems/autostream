"""dial_hd_session.py: the HD development listener's login sessions.

The development (LAN) listener is behind a PIN login. A login issues a
session: a token, an expiry and the PIN epoch it was issued under. Sessions
live in memory only, are capped in number, and all end when the PIN changes.

SessionStore holds them. DevListener owns the listener itself: it binds only
when asked, and closing it drops every session and ends its event streams.
The store's lock and the listener's lock are each held alone: the PIN is read
from the management server before the store is asked to adopt it.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
import re
import secrets
import threading
from collections import OrderedDict
from typing import Callable

SESSION_TTL_S = 12 * 3600
SESSION_MAX = 8
SESSION_TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")


class SessionStore:
    """The live sessions, keyed by token. Every method takes the store's own
    lock and no other."""

    def __init__(self, clock: Callable[[], float]) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._sessions: OrderedDict = OrderedDict()      # token -> (expiry, pin epoch)
        self._epoch = 0
        self._last_pin: str | None = None

    def issue(self) -> str:
        """A new session's token. The oldest session goes when the store is full."""
        token = secrets.token_hex(16)
        now = self._clock()
        with self._lock:
            self._expire_locked(now)
            while len(self._sessions) >= SESSION_MAX:
                self._sessions.popitem(last=False)
            self._sessions[token] = (now + SESSION_TTL_S, self._epoch)
        return token

    def _expire_locked(self, now: float) -> None:
        for token in [t for t, (expiry, _e) in self._sessions.items() if expiry <= now]:
            del self._sessions[token]

    def valid(self, token: "str | None") -> bool:
        """Whether *token* is a live session: issued here, not expired, and
        issued under the PIN now in force."""
        if not token or not SESSION_TOKEN_RE.match(token):
            return False
        now = self._clock()
        with self._lock:
            self._expire_locked(now)
            entry = self._sessions.get(token)
            return entry is not None and entry[1] == self._epoch

    def drop(self, token: "str | None") -> None:
        if token:
            with self._lock:
                self._sessions.pop(token, None)

    def clear(self) -> None:
        """Drop every session. The PIN epoch and the last PIN seen stay."""
        with self._lock:
            self._sessions.clear()

    def follow_pin(self, pin: str) -> bool:
        """Note the PIN now in force. When it differs from the one last seen,
        every session ends; True in that case."""
        with self._lock:
            revoked = self._last_pin is not None and pin != self._last_pin
            if revoked:
                self._epoch += 1
                self._sessions.clear()
            self._last_pin = pin
        return revoked

    def adopt_pin(self, pin: str) -> None:
        """Take *pin* as the PIN in force when none has been seen yet."""
        with self._lock:
            if self._last_pin is None:
                self._last_pin = pin


class DevListener:
    """The development listener: one HTTP server on the LAN address, run on
    its own thread while it is open.

    *make_server* builds the server for an address (and may raise OSError);
    *sessions* is cleared whenever the listener closes; *read_pin* returns
    the PIN now in force; *on_closed*, when given, is called after a listener
    that was open has closed, so its event streams wake and end."""

    def __init__(
        self, address: tuple[str, int], *, make_server: Callable[[tuple[str, int]], object],
        sessions: SessionStore, read_pin: Callable[[], str], on_closed: Callable[[], None] | None,
    ) -> None:
        self._address = address
        self._make_server = make_server
        self._sessions = sessions
        self._read_pin = read_pin
        self._on_closed = on_closed
        self._lock = threading.Lock()
        self._httpd = None
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()

    @property
    def port(self) -> int | None:
        """The bound port, or None while closed."""
        httpd = self._httpd
        return httpd.server_address[1] if httpd is not None else None

    @property
    def is_open(self) -> bool:
        return self._httpd is not None

    def start(self) -> None:
        """Bind and serve. Does nothing when already open, and leaves the
        listener closed when the port cannot be bound."""
        with self._lock:
            if self._httpd is not None:
                return
            self._stopping = threading.Event()
            try:
                httpd = self._make_server(self._address)
            except OSError as e:
                logging.warning("HD development listener not opened: %s", e)
                return
            httpd.hd_dev = True
            httpd.hd_stopping = self._stopping
            thread = threading.Thread(
                target=httpd.serve_forever, kwargs={"poll_interval": 0.2},
                daemon=True, name="dial-hd-dev",
            )
            self._httpd, self._thread = httpd, thread
            thread.start()
        self._sessions.adopt_pin(self._read_pin())
        logging.info("HD development listener open on port %d", self.port)

    def stop(self) -> None:
        """Close the listener, drop every session and end its event streams."""
        with self._lock:
            httpd, self._httpd = self._httpd, None
            thread, self._thread = self._thread, None
            self._stopping.set()
        self._sessions.clear()
        if httpd is None:
            return
        httpd.shutdown()
        if thread is not None:
            thread.join(2.0)
        httpd.server_close()
        if self._on_closed is not None:
            self._on_closed()
        logging.info("HD development listener closed")
