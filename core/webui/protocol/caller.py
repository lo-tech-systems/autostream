#!/usr/bin/env python3
"""webui/protocol/caller.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Who is asking, and what they may do. A browser is known by its session; a dial
or another appliance names itself in the request body (``dial:<id>`` or
``peer:<id>``) and is given the role the stream hub works out for it.

Contents:
  - Caller    -- the answer: kind, id, role, requester name, PIN claimant
  - Refusal   -- an HTTP refusal of the caller itself
  - identify  -- a request's caller, or the refusal
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Union

from autostream_auth import SESSION_COOKIE_NAME, parse_cookie_header
from autostream_intents import Role
from autostream_pin_pairing import REQUESTER_WEBUI
from autostream_protocol import parse_client
from webui import session_state
from webui.protocol import hub as hub_module


@dataclass(frozen=True)
class Caller:
    kind: str                       # "browser" | "dial" | "peer"
    id: str                         # "" | the dial id | the appliance id
    role: Role
    requester: str                  # "webui" | "dial:<id>" | "peer:<id>"
    reason: Optional[str]           # why the role is NONE
    pin_claimant: Optional[str]     # who may enter a speaker's PIN for this caller; None: nobody
    address: str                    # the client address behind the proxy


@dataclass(frozen=True)
class Refusal:
    """The caller itself is refused: an HTTP status, an error name, and any
    fields to send with them."""

    status: int
    error: str
    extra: dict = field(default_factory=dict)


def _csrf_token(handler, body: dict) -> str:
    return handler.headers.get("X-CSRF-Token", "") or str(body.get("csrf_token") or "")


def _browser(handler, body: dict, write: bool) -> Union[Caller, Refusal]:
    auth = session_state.AUTH
    if write and not auth.validate_csrf(handler, _csrf_token(handler, body)):
        return Refusal(403, "csrf_stale", {"csrf_token": auth.ensure_session(handler)})
    admin = auth.is_authenticated(handler.headers) or not auth.is_enabled()
    return Caller("browser", "", Role.ADMIN if admin else Role.PLAYBACK, REQUESTER_WEBUI, None,
                  REQUESTER_WEBUI, handler._get_client_ip())


def _named(handler, body: dict, client: str, configured: bool) -> Union[Caller, Refusal]:
    parsed = parse_client(client)
    if parsed is None:
        return Refusal(400, "invalid_client")
    cookies = parse_cookie_header(handler.headers.get("Cookie"))
    if cookies.get(SESSION_COOKIE_NAME):
        # A named client has no session; both at once is a confused caller.
        return Refusal(400, "invalid_client")
    hub = hub_module.current()
    if hub is None:
        return Refusal(404, "not_found")
    kind, ident = parsed
    access = hub.access(client, configured=configured)
    if kind == "dial":
        # A dial with no keypad cannot hold the claim and lock a browser out.
        claimant = client if body.get("pin_capable") is True else None
    else:
        claimant = REQUESTER_WEBUI
    return Caller(kind, ident, access.role, client, access.reason, claimant, handler._get_client_ip())


def identify(handler, body: dict, *, write: bool, configured: bool = True) -> Union[Caller, Refusal]:
    """The caller of a request whose JSON body is *body*. *write* asks for the
    CSRF check of a browser. *configured* is the appliance's live answer,
    handed on to the hub so a request never meets two."""
    client = body.get("client")
    if client is None:
        return _browser(handler, body, write)
    if not isinstance(client, str):
        return Refusal(400, "invalid_client")
    return _named(handler, body, client, configured)
