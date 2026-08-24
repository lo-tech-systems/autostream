#!/usr/bin/env python3
"""autostream_webui_routes.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Route table and dispatcher for ConfigWebHandler (autostream_webui.py).

Each request path/method can be declared as a ``Route`` row below instead
of an inline branch in do_GET/do_POST/do_PUT: ``dispatch()`` resolves the
matching row and runs its handler through the same stages the inline
if/elif chains used to apply (session/CSRF/commissioning/auth), so
behaviour is byte-for-byte identical to what it replaces. There is no
request-context object or per-caller-scheme abstraction here -- dispatch()
reuses ConfigWebHandler's/AuthManager's existing methods verbatim rather
than reimplementing them. Not every path is on the table yet; anything
not registered below still falls through to the legacy do_GET/do_POST/
do_PUT if/elif chains untouched.

Handlers are registered by *name* (a string looked up on the
``autostream_webui`` module at dispatch time), not by direct function
reference. This is deliberate: existing tests patch handlers via
``patch("autostream_webui.send_repeat_post_json")`` etc, and a module
attribute lookup at call time (rather than a reference captured once at
import time) is required for that patching to take effect -- the same
reasoning applies to AUTH/STATE/is_commissioning_required/
required_first_boot_step, which are all resolved dynamically through the
``autostream_webui`` module object rather than imported by name here.
A raw callable is also accepted for handler (and is used as-is), for
callers that don't need patch-ability (e.g. tests exercising dispatch()
directly with a mock).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional, Union
from urllib.parse import parse_qs


class AuthRequirement(Enum):
    """Per-route auth level, matching the semantics of the existing inline
    checks in ConfigWebHandler -- this codebase's two real levels of
    *login* requirement plus NONE:

    NONE  -- open to any caller; no CSRF or PIN check.
    CSRF  -- state-changing (POST/PUT) route: a valid session CSRF token is
             required, but no PIN/login. Every session (including an
             anonymous one) carries a CSRF token, so this level is
             satisfied by any visitor who has loaded a page on this
             origin. Matches AUTH.validate_csrf()'s existing behaviour.
    FULL  -- PIN authentication is required when a PIN is configured
             (AUTH.require_authenticated_if_pin_enabled()'s existing
             behaviour): pages redirect to /auth, APIs get 401. If no PIN
             is configured, behaves like NONE.
    """

    NONE = "none"
    CSRF = "csrf"
    FULL = "full"


@dataclass(frozen=True)
class Route:
    """One row of the route table.

    Exactly one of ``path`` (exact match) or ``prefix`` (startswith match)
    should be set; if both match a request, ``path`` wins (see
    ``dispatch()``'s resolution order). ``handler`` is a string name to be
    resolved dynamically against the ``autostream_webui`` module at
    dispatch time (patch-friendly -- see module docstring), or a raw
    callable used as-is.
    """

    methods: tuple
    handler: Union[str, Callable]
    auth: AuthRequirement = AuthRequirement.FULL
    path: Optional[str] = None
    prefix: Optional[str] = None
    # Caller-authentication scheme. "browser" (the default) is the full
    # stage sequence dispatch() applies: session/CSRF/commissioning/
    # FULL-auth stages, as documented on dispatch() itself.
    # The other three opt a route OUT of every one of those stages --
    # dispatch() just resolves and calls the handler, exactly mirroring the
    # early-dispatch branches these routes used to be in do_GET/do_POST
    # (before route-table dispatch even ran): "bearer" is the federation
    # API (source-IP-bound bearer tokens, its own 401s, never a browser
    # session), "dial" is the dial-device protocol endpoints (UUID/allow-
    # list auth inside the sender), "loopback_aware" is a route whose
    # handler itself distinguishes a direct-loopback caller (full access)
    # from an NGINX-proxied one (its own, usually lighter-weight, gate --
    # see the /api/playing-status and /api/log-level adapters in
    # autostream_webui.py). Non-browser handlers are always called as
    # fn(handler, STATE) -- two args, GET's calling convention -- even for
    # POST/PUT, since dispatch() does no body pre-parsing for them either
    # (that parsing is itself part of the "own logic" these routes keep;
    # see e.g. _route_post_federation's or the dial adapters' own body
    # reads in autostream_webui.py, which reproduce -- not share -- the
    # generic POST/PUT parse below since their legacy call sites ran ahead
    # of, or bypassed, one or more of its checks).
    scheme: str = "browser"
    # "page" vs "api" -- the FULL auth gate's only use of this: pages get a
    # 302 redirect to /auth on failure (AUTH.require_authenticated_if_pin_enabled's
    # redirect_path form), APIs get a 401 JSON body. This is the one place
    # the existing inline checks distinguish on *route kind*, not HTTP
    # method -- some GET routes are "api" (e.g. /api/align/status, which
    # legacy calls without redirect_path -> 401) and some are "page"
    # (e.g. /align, called with redirect_path -> 302).
    kind: str = "api"
    allow_unconfigured: bool = False
    # Bidirectional first-boot gate: the mirror image of
    # allow_unconfigured. A route with unconfigured_only=True is reachable
    # ONLY while commissioning is required -- once the appliance is
    # configured, dispatch() blocks it (GET: 302 to "/"; POST/PUT: 409
    # {"error": "already_configured"}) before the handler ever runs. This
    # reproduces do_GET's former "already configured -- redirect away from
    # first-boot pages" branch and do_POST's former commissioning-else
    # branch for /first-boot/*/continue|finish, both of which allow_
    # unconfigured alone can't express (it only ever blocks the OTHER
    # direction). Only meaningful alongside allow_unconfigured=True; every
    # route using it here sets both.
    unconfigured_only: bool = False
    # Demotes this route's access-log line to DEBUG (see log_message()'s
    # existing _POLLING_LOG_PATHS check in autostream_webui.py).
    # log_message() falls back to is_poll_log() (this module) for any
    # path not covered by that tuple.
    poll_log: bool = False
    requires_body: bool = False
    comment: str = ""

    def __post_init__(self):
        if not self.path and not self.prefix:
            raise ValueError("Route requires either path or prefix")
        if self.path and self.prefix:
            raise ValueError("Route may declare path or prefix, not both")
        if not self.methods:
            raise ValueError("Route requires at least one HTTP method")
        if self.kind not in ("page", "api"):
            raise ValueError(f"Route.kind must be 'page' or 'api', got {self.kind!r}")
        if self.scheme not in ("browser", "bearer", "dial", "loopback_aware"):
            raise ValueError(
                f"Route.scheme must be one of browser/bearer/dial/loopback_aware, got {self.scheme!r}"
            )


# Module-level table, populated by register()/@route at import time.
ROUTES: list = []


def register(route: Route) -> Route:
    """Add a Route to ROUTES, rejecting an exact duplicate (path/prefix,
    method) registration -- this is a defensive check against a copy-paste
    mistake during migration; test_route_table.py additionally scans
    ROUTES itself so a duplicate is caught at import time here AND by the
    characterisation test.
    """
    key = (route.path, route.prefix)
    for existing in ROUTES:
        if (existing.path, existing.prefix) != key:
            continue
        overlap = set(existing.methods) & set(route.methods)
        if overlap:
            raise ValueError(
                f"Duplicate route registration for {key} methods={overlap}"
            )
    ROUTES.append(route)
    return route


def route(
    *,
    path: Optional[str] = None,
    prefix: Optional[str] = None,
    methods=("GET",),
    auth: AuthRequirement = AuthRequirement.FULL,
    kind: str = "api",
    allow_unconfigured: bool = False,
    poll_log: bool = False,
    requires_body: bool = False,
    comment: str = "",
):
    """Thin decorator usable by future batches: ``@route(path="/about")``
    registers the decorated function as that route's handler (by direct
    reference, since it's defined right where it's used). Not used by this
    batch's two pilot routes -- they're registered explicitly below,
    by name, alongside their legacy call sites -- but provided now so the
    next migration batch has it available.
    """

    def deco(fn):
        register(
            Route(
                path=path,
                prefix=prefix,
                methods=tuple(methods),
                handler=fn,
                auth=auth,
                kind=kind,
                allow_unconfigured=allow_unconfigured,
                poll_log=poll_log,
                requires_body=requires_body,
                comment=comment,
            )
        )
        return fn

    return deco


def _resolve(path: str, method: str) -> Optional[Route]:
    """Exact-path match wins over prefix match."""
    prefix_hit = None
    for r in ROUTES:
        if method not in r.methods:
            continue
        if r.path is not None:
            if r.path == path:
                return r
            continue
        if r.prefix is not None and path.startswith(r.prefix):
            if prefix_hit is None:
                prefix_hit = r
    return prefix_hit


def is_poll_log(path: str, method: str) -> bool:
    """True if ``path``/``method`` resolves to a migrated route with
    ``poll_log=True`` -- consulted by ConfigWebHandler.log_message() for
    paths no longer covered by its own ``_POLLING_LOG_PATHS`` tuple once a
    polling route migrates into ROUTES (see that tuple's docstring).
    """
    r = _resolve(path, method)
    return bool(r and r.poll_log)


def _resolve_handler(route_obj: Route):
    if callable(route_obj.handler) and not isinstance(route_obj.handler, str):
        return route_obj.handler
    import autostream_webui as _webui_mod  # deferred: avoids circular import

    return getattr(_webui_mod, route_obj.handler)


def _read_and_parse_body(handler):
    """Reproduces do_POST's body-read + content-type parse (steps 2-3),
    for routes whose auth level needs the body before the handler runs
    (CSRF extraction, or the handler itself takes body_str). Returns
    (body_str, form, json_obj) or None if an error response was already
    sent (mirrors _read_post_body_bytes()'s own contract).
    """
    body_bytes = handler._read_post_body_bytes()
    if body_bytes is None:
        return None  # error already sent
    try:
        body_str = body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        handler.send_error(400, "Request body is not valid UTF-8")
        return None

    content_type = (handler.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()

    form = {}
    json_obj = None
    if body_str:
        if content_type == "application/x-www-form-urlencoded":
            form = parse_qs(body_str)
        elif content_type == "application/json":
            import json as _json

            try:
                json_obj = _json.loads(body_str)
            except _json.JSONDecodeError:
                handler.send_error(400, "Invalid JSON")
                return None
            if not isinstance(json_obj, dict):
                handler.send_error(400, "JSON object required")
                return None

    return body_str, form, json_obj


def _commissioning_redirect_get(handler, webui_mod) -> None:
    """Same redirect shape as do_GET's existing commissioning gate
    (autostream_webui.py lines ~630-636) -- no Content-Length header, to
    match that branch exactly.
    """
    step = webui_mod.required_first_boot_step(
        webui_mod.STATE.config_path, webui_mod.STATE.state_path
    )
    location = f"/first-boot/{step}" if step else "/first-boot/owntone"
    handler.send_response(302)
    handler.send_header("Location", location)
    handler.end_headers()


def _csrf_failure_response(handler, webui_mod, path: str) -> None:
    """Same three-way branch as do_POST's existing CSRF-failure handling
    (autostream_webui.py lines ~936-957): form pages get an error-flash
    redirect, /api/* paths get the stale-session-recovery shape, anything
    else gets a bare 403.
    """
    if path in ("/setup", "/owntone-setup", "/service"):
        handler._redirect_with_error_flash("Settings not saved, please try again")
    elif path.startswith("/api/"):
        fresh_csrf = webui_mod.AUTH.ensure_session(handler)
        webui_mod.send_json(
            handler, 403, {"ok": False, "error": "csrf_stale", "csrf_token": fresh_csrf}
        )
    else:
        handler.send_error(403, "CSRF validation failed")


def dispatch(handler, method: str, path: str) -> bool:
    """Look up ``path``/``method`` in ROUTES and, if found, run it through
    the per-method check pipeline, returning True.  Returns False,
    untouched, if no route matches -- the caller (do_GET/do_POST/do_PUT)
    then falls through to the legacy chain.

    Stage order mirrors the legacy chains exactly, so migrating a route
    changes no behaviour:
      GET:       [unconfigured_only gate] -> commissioning gate -> FULL
                 auth -> handler
      POST/PUT:  body read -> CSRF -> [unconfigured_only gate] ->
                 commissioning gate -> FULL auth -> handler
    (An alternative ordering would run CSRF/auth before commissioning for
    GET too; the GET divergence here is legacy-faithful on purpose, so
    moving a route onto this table cannot change its behaviour.)

    A non-"browser" scheme (see Route.scheme) skips every stage above --
    no body pre-parse, no CSRF, no commissioning gate, no FULL auth, no
    ensure_session -- and just calls the handler as fn(handler, STATE).
    """
    route_obj = _resolve(path, method)
    if route_obj is None:
        return False

    import autostream_webui as _webui_mod  # deferred: avoids circular import

    if route_obj.scheme != "browser":
        fn = _resolve_handler(route_obj)
        fn(handler, _webui_mod.STATE)
        return True

    # --- Bidirectional first-boot gate (GET): the mirror image of the
    # commissioning gate below, checked first since legacy ran this ahead
    # of even the commissioning-required branch (do_GET's former "already
    # configured -- redirect away from first-boot pages" block, which ran
    # before the elif chain these routes lived in was ever reached) ---
    if (
        method == "GET"
        and route_obj.unconfigured_only
        and not handler._commissioning_required()
    ):
        handler.send_response(302)
        handler.send_header("Location", "/")
        handler.send_header("Content-Length", "0")
        handler.end_headers()
        return True

    # --- Commissioning gate (GET only at this stage; POST/PUT gate after
    # CSRF, matching the legacy do_POST ordering) ---
    if (
        method == "GET"
        and not route_obj.allow_unconfigured
        and handler._commissioning_required()
    ):
        _commissioning_redirect_get(handler, _webui_mod)
        return True

    body_str = ""
    if method in ("POST", "PUT"):
        # do_POST/do_PUT no longer pre-read the body ahead of
        # dispatch() -- a generic pre-read would double-consume the request
        # stream for non-"browser"-scheme routes, whose adapters read the
        # body themselves (see e.g. _route_post_federation). So this is now
        # almost always a fresh read. The cache path stays for any direct
        # caller (a test, or a future addition) that pre-populates
        # ``_parsed_body`` itself. Either way, the result is (re-)stashed on
        # the transient attribute so same-request helpers that read it after
        # the fact (e.g. autostream_webui._route_post_json_obj) keep seeing
        # it, matching this attribute's original contract.
        cached = getattr(handler, "_parsed_body", None)
        if cached is not None:
            body_str, form, json_obj = cached
        else:
            parsed = _read_and_parse_body(handler)
            if parsed is None:
                return True  # error already sent
            body_str, form, json_obj = parsed
            handler._parsed_body = (body_str, form, json_obj)

    # --- Auth ---
    if route_obj.auth in (AuthRequirement.CSRF, AuthRequirement.FULL) and method in ("POST", "PUT"):
        csrf_token = handler._extract_csrf_token(form, json_obj)
        if not _webui_mod.AUTH.validate_csrf(handler, csrf_token):
            _csrf_failure_response(handler, _webui_mod, path)
            return True

    # --- Bidirectional first-boot gate (POST/PUT): after CSRF, matching
    # legacy do_POST's former commissioning-else branch for
    # /first-boot/*/continue|finish ---
    if (
        method in ("POST", "PUT")
        and route_obj.unconfigured_only
        and not handler._commissioning_required()
    ):
        _webui_mod.send_json(handler, 409, {"ok": False, "error": "already_configured"})
        return True

    # --- Commissioning gate (POST/PUT: after CSRF, per legacy ordering) ---
    if (
        method in ("POST", "PUT")
        and not route_obj.allow_unconfigured
        and handler._commissioning_required()
    ):
        _webui_mod.send_json(handler, 409, {"ok": False, "error": "appliance_unconfigured"})
        return True

    if route_obj.auth == AuthRequirement.FULL:
        redirect_path = handler.path if route_obj.kind == "page" else None
        if not _webui_mod.AUTH.require_authenticated_if_pin_enabled(
            handler, redirect_path=redirect_path
        ):
            return True

    if route_obj.requires_body and method in ("POST", "PUT") and not body_str:
        handler.send_error(400, "Missing request body")
        return True

    # --- Ensure UI session / CSRF exists (GET only) ---
    # Reproduces do_GET's unconditional `self._csrf_token =
    # AUTH.ensure_session(self)` (formerly run just after the "Gate
    # protected pages" check, for every GET reaching the page/API
    # dispatch chain, allowlisted or not) -- several page templates read
    # handler._csrf_token with no fallback, so skipping this would leave
    # first-time visitors with a blank CSRF token embedded in the page.
    if method == "GET":
        handler._csrf_token = _webui_mod.AUTH.ensure_session(handler)

    # --- Handler dispatch ---
    fn = _resolve_handler(route_obj)
    try:
        if method == "GET":
            fn(handler, _webui_mod.STATE)
        else:
            fn(handler, _webui_mod.STATE, body_str)
    finally:
        if method in ("POST", "PUT"):
            handler._parsed_body = None
    return True


# ---------------------------------------------------------------------------
# Simplest routes: one open GET page, one CSRF-protected POST API.
#
# Their legacy branches are simple single-line dispatches with no
# route-specific pre/post logic to preserve beyond what dispatch()
# already reproduces above:
#   GET  /about       -- AuthRequirement.NONE (in AUTH.ALLOWLIST_PATHS,
#                         no per-branch check in the legacy do_GET chain)
#   POST /api/repeat   -- AuthRequirement.CSRF (deliberately no PIN gate --
#                         see the comment carried over from do_POST below)
# ---------------------------------------------------------------------------

register(
    Route(
        path="/about",
        methods=("GET",),
        handler="send_about_page",
        auth=AuthRequirement.NONE,
        kind="page",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/repeat",
        methods=("POST",),
        handler="send_repeat_post_json",
        auth=AuthRequirement.CSRF,
        kind="api",
        allow_unconfigured=False,
        requires_body=True,
        comment=(
            "Deliberately NOT PIN-gated: the repeat button lives on the "
            "home page, public consumer surface (like /api/output's "
            "enable/volume controls). Arm/disarm is a playback action of "
            "the same sensitivity class as toggling an output -- "
            "requiring a PIN here would make the button 401 for any "
            "visitor who had not opened the (gated) setup pages, and "
            "silently after every autostream restart (in-memory "
            "sessions)."
        ),
    )
)


# ---------------------------------------------------------------------------
# Browser GET routes: pages and simple read-only JSON endpoints.
#
# auth/kind were derived from each route's *current* inline check in the
# legacy do_GET elif chain (now removed there), not from what "should"
# gate a page vs an API:
#   - No inline check + path in AUTH.ALLOWLIST_PATHS  -> NONE.
#   - Inline `require_authenticated_if_pin_enabled(self, redirect_path=...)`
#     -> FULL, kind="page" (302 redirect on failure).
#   - Inline `require_authenticated_if_pin_enabled(self)` (no redirect_path)
#     -> FULL, kind="api" (401 JSON on failure) -- e.g. /api/align/status,
#     already called out as the worked example in the Route.kind docstring
#     above.
#   - No inline check, path NOT in ALLOWLIST_PATHS -> FULL, kind="page".
#     do_GET's now-deleted general "Gate protected pages" check (the block
#     that used to run ahead of the whole elif chain: `if
#     AUTH.requires_auth(path) and not AUTH.is_authenticated(...):
#     redirect_to_auth(...)`) was these routes' *only* guard, and it always
#     redirects (never 401) regardless of path shape -- so "page" is the
#     faithful kind even for routes that are semantically APIs (e.g.
#     /api/owntone/outputs, /api/update/check, /api/update/status).
#
# allow_unconfigured mirrors do_GET's commissioning allowlist (now also
# removed there): a path is allow_unconfigured=True iff it started with
# one of "/first-boot/", "/owntone-restarting", "/rebooting", "/logs", or
# "/api/owntone/outputs"/"/api/owntone/outputs_state"/"/api/owntone/ready"
# (all three matched by the same "/api/owntone/outputs"/"/api/owntone/ready"
# startswith checks in that allowlist).
#
# poll_log=True is set for the polling paths migrated in this batch;
# they're removed from ConfigWebHandler._POLLING_LOG_PATHS in
# autostream_webui.py in the same commit (see is_poll_log() above, which
# log_message() now consults for any path not in that shrunk tuple).
# ---------------------------------------------------------------------------

# --- Pages -------------------------------------------------------------

register(
    Route(
        path="/",
        methods=("GET",),
        handler="_route_get_home",
        auth=AuthRequirement.NONE,
        kind="page",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/equaliser",
        methods=("GET",),
        handler="_route_get_equaliser",
        auth=AuthRequirement.NONE,
        kind="page",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/service",
        methods=("GET",),
        handler="_route_get_service",
        auth=AuthRequirement.NONE,
        kind="page",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/setup",
        methods=("GET",),
        handler="_route_get_setup",
        auth=AuthRequirement.FULL,
        kind="page",
        allow_unconfigured=False,
        comment="No inline check in legacy; guarded solely by the general requires_auth() gate.",
    )
)

register(
    Route(
        prefix="/api/setup/card/",
        methods=("GET",),
        handler="_route_get_setup_card",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
        comment=(
            "Lazy per-card detail fetch: same FULL auth + commissioning "
            "gating as /setup itself, just kind=api (401 JSON, not a "
            "redirect) on an auth failure."
        ),
    )
)

register(
    Route(
        path="/logs",
        methods=("GET",),
        handler="_route_get_logs",
        auth=AuthRequirement.NONE,
        kind="page",
        allow_unconfigured=True,
    )
)

register(
    Route(
        path="/align",
        methods=("GET",),
        handler="send_align_page",
        auth=AuthRequirement.FULL,
        kind="page",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/align/result",
        methods=("GET",),
        handler="_route_get_align_result",
        auth=AuthRequirement.FULL,
        kind="page",
        allow_unconfigured=False,
        comment=(
            "Legacy redirected with self.path (not the normalized path) so the "
            "measurement query string survives the login round-trip; "
            "dispatch()'s kind=page branch already uses handler.path, matching."
        ),
    )
)

register(
    Route(
        path="/owntone-setup",
        methods=("GET",),
        handler="_route_get_owntone_setup",
        auth=AuthRequirement.FULL,
        kind="page",
        allow_unconfigured=False,
        comment="No inline check in legacy; guarded solely by the general requires_auth() gate.",
    )
)

register(
    Route(
        path="/rebooting",
        methods=("GET",),
        handler="_route_get_rebooting",
        auth=AuthRequirement.FULL,
        kind="page",
        allow_unconfigured=True,
        comment="No inline check in legacy; guarded solely by the general requires_auth() gate.",
    )
)

register(
    Route(
        path="/owntone-restarting",
        methods=("GET",),
        handler="send_owntone_restarting_page",
        auth=AuthRequirement.FULL,
        kind="page",
        allow_unconfigured=True,
        comment="No inline check in legacy; guarded solely by the general requires_auth() gate.",
    )
)

# /first-boot/owntone and /first-boot/appliance are DELIBERATELY left in
# the legacy do_GET elif chain: do_GET has an extra branch (the "else:
# Already configured -- redirect away from first-boot pages" block, ahead
# of the elif chain) that 302-redirects these two paths to "/" once
# commissioning is no longer required. allow_unconfigured only expresses
# the *opposite* direction (block during commissioning); it can't express
# "block once no longer commissioning" too, so migrating these here would
# silently drop that redirect. Left for a later batch once dispatch() (or
# Route) grows a way to express both directions.

# --- Simple GET APIs -----------------------------------------------------

register(
    Route(
        path="/api/status",
        methods=("GET",),
        handler="send_status_json",
        auth=AuthRequirement.NONE,
        kind="api",
        allow_unconfigured=False,
        poll_log=True,
    )
)

register(
    Route(
        path="/api/owntone/outputs_state",
        methods=("GET",),
        handler="send_owntone_outputs_state_json",
        auth=AuthRequirement.NONE,
        kind="api",
        allow_unconfigured=True,
        poll_log=True,
    )
)

register(
    Route(
        path="/api/owntone/outputs",
        methods=("GET",),
        handler="send_owntone_outputs_json",
        auth=AuthRequirement.FULL,
        kind="page",
        allow_unconfigured=True,
        poll_log=True,
        comment="No inline check in legacy, and NOT in AUTH.ALLOWLIST_PATHS (unlike outputs_state) -- guarded solely by the general requires_auth() gate.",
    )
)

register(
    Route(
        path="/api/audio/status",
        methods=("GET",),
        handler="send_audio_status_json",
        auth=AuthRequirement.NONE,
        kind="api",
        allow_unconfigured=False,
        poll_log=True,
    )
)

register(
    Route(
        path="/api/about/system",
        methods=("GET",),
        handler="_route_get_about_system",
        auth=AuthRequirement.NONE,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/settings",
        methods=("GET",),
        handler="send_settings_get_json",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/output_eq/status",
        methods=("GET",),
        handler="_route_get_output_eq_status",
        auth=AuthRequirement.NONE,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/owntone/ready",
        methods=("GET",),
        handler="send_owntone_ready_json",
        auth=AuthRequirement.FULL,
        kind="page",
        allow_unconfigured=True,
        comment="No inline check in legacy; guarded solely by the general requires_auth() gate.",
    )
)

register(
    Route(
        path="/api/align/status",
        methods=("GET",),
        handler="send_align_status_json",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/network/status",
        methods=("GET",),
        handler="_route_get_network_status",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
        poll_log=True,
    )
)

register(
    Route(
        path="/api/bluetooth/status",
        methods=("GET",),
        handler="send_bluetooth_status_json",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/bluetooth/scan_results",
        methods=("GET",),
        handler="_route_get_bluetooth_scan_results",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/bluetooth/pair_status",
        methods=("GET",),
        handler="send_bluetooth_pair_status_json",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/update/check",
        methods=("GET",),
        handler="send_update_check_json",
        auth=AuthRequirement.FULL,
        kind="page",
        allow_unconfigured=False,
        comment="No inline check in legacy; guarded solely by the general requires_auth() gate.",
    )
)

register(
    Route(
        path="/api/update/status",
        methods=("GET",),
        handler="_route_get_update_status",
        auth=AuthRequirement.FULL,
        kind="page",
        allow_unconfigured=False,
        comment="No inline check in legacy; guarded solely by the general requires_auth() gate.",
    )
)


# ---------------------------------------------------------------------------
# Browser POST API routes.
#
# auth was derived from each route's *current* inline check in the legacy
# do_POST elif chain (now removed there):
#   - No inline `require_authenticated_if_pin_enabled` call -> CSRF only
#     (every POST/PUT route already gets the CSRF check ahead of the
#     commissioning gate and the per-arm code, per dispatch()'s stage
#     order -- see its docstring). This is the output/output_eq/service
#     class: /api/output, /api/output_eq/config, /api/output_eq/reset,
#     /api/service/config, /api/service/reset.
#   - Inline `require_authenticated_if_pin_enabled(self)` -> FULL. Every
#     route below that has one calls it with no redirect_path, so
#     kind="api" (401 JSON on failure, never a page redirect) throughout --
#     no POST route here is a page form post (those -- /setup,
#     /owntone-setup, first-boot -- are handled separately).
#
# allow_unconfigured mirrors do_POST's former commissioning allowlist (the
# "_post_commissioning_allowed" local, now deleted there):
#   `path.startswith("/api/owntone/") or ... or path == "/api/output" or
#    path == "/api/output_eq/reset" or path == "/api/service/reset"`
# This is a deliberate, easy-to-miss asymmetry, preserved exactly:
#   - /api/output, /api/output_eq/reset, /api/service/reset are
#     allow_unconfigured=True, but /api/output_eq/config and
#     /api/service/config (same CSRF-only auth class, same "reset vs
#     config" pairing) are NOT -- only the *reset* siblings were
#     commissioning-allowed in the legacy chain.
#   - Every /api/owntone/* POST route (output-visibility, output-mode,
#     output-offset, uncompressed-audio, buffered-audio, start-buffer,
#     grace-period) is allow_unconfigured=True despite being FULL auth --
#     the commissioning allowlist and the PIN gate are orthogonal checks in
#     both the legacy chain and dispatch()'s stage order (commissioning
#     gate before FULL auth), so this was already reachable, PIN-gated,
#     during first-boot before this migration and stays that way.
#   - /api/align/*, /api/settings*, /api/network/*, /api/bluetooth/*,
#     /api/update/apply, /api/reboot, /api/factory-reset were never in the
#     legacy allowlist -> allow_unconfigured=False (the Route default).
#
# requires_body mirrors each arm's own `if not body_str: send_error(400,
# ...)` inline check -- most of this batch had none (several senders never
# use body_str at all, e.g. the json_obj-based bluetooth/network senders,
# or the no-argument reset/save/abort/discard senders). /api/settings is
# the one exception that could not be expressed as requires_body: it
# rejected on `not isinstance(json_obj, dict)`, not on an empty body_str
# (so e.g. a form-urlencoded body was rejected too) -- that check moved
# into its adapter, _route_post_settings, instead.
#
# Adapters (in autostream_webui.py, next to the senders they wrap):
# needed wherever the sender's signature isn't already fn(handler, STATE,
# body_str) -- a json_obj-taking sender (network/bluetooth), a
# no-body sender (output_eq/reset, settings/save, align/abort,
# align/discard, bluetooth/forget), an extra-arg sender (factory-reset
# needs AUTH), or a route whose do_POST arm carried its own pre-logic
# ahead of the sender (update/apply and reboot both ran the
# _settings_save_barrier flush first; reboot's arm also called
# reboot_system() and built the response itself rather than delegating to
# a sender).
# ---------------------------------------------------------------------------

register(
    Route(
        path="/api/output",
        methods=("POST",),
        handler="handle_output_update",
        auth=AuthRequirement.CSRF,
        kind="api",
        allow_unconfigured=True,
        requires_body=True,
    )
)

register(
    Route(
        path="/api/output_eq/config",
        methods=("POST",),
        handler="send_output_eq_config_json",
        auth=AuthRequirement.CSRF,
        kind="api",
        allow_unconfigured=False,
        requires_body=True,
    )
)

register(
    Route(
        path="/api/output_eq/reset",
        methods=("POST",),
        handler="_route_post_output_eq_reset",
        auth=AuthRequirement.CSRF,
        kind="api",
        allow_unconfigured=True,
    )
)

register(
    Route(
        path="/api/service/config",
        methods=("POST",),
        handler="send_service_config_json",
        auth=AuthRequirement.CSRF,
        kind="api",
        allow_unconfigured=False,
        requires_body=True,
    )
)

register(
    Route(
        path="/api/service/reset",
        methods=("POST",),
        handler="send_service_reset_json",
        auth=AuthRequirement.CSRF,
        kind="api",
        allow_unconfigured=True,
        requires_body=True,
    )
)

register(
    Route(
        path="/api/input_eq",
        methods=("POST",),
        handler="handle_live_input_eq_update",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
        requires_body=True,
    )
)

register(
    Route(
        path="/api/input_gain",
        methods=("POST",),
        handler="handle_live_input_gain_update",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
        requires_body=True,
    )
)

register(
    Route(
        path="/api/settings",
        methods=("POST",),
        handler="_route_post_settings",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
        comment="requires_body not used: legacy rejected on `not isinstance(json_obj, dict)`, not on an empty body_str -- see adapter.",
    )
)

register(
    Route(
        path="/api/settings/hostname",
        methods=("POST",),
        handler="send_hostname_post_json",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/settings/advertisement",
        methods=("POST",),
        handler="send_advertisement_post_json",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/settings/auto-update",
        methods=("POST",),
        handler="send_auto_update_post_json",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/settings/mdns-grace-period",
        methods=("POST",),
        handler="send_settings_mdns_grace_period_json",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/settings/save",
        methods=("POST",),
        handler="_route_post_settings_save",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/owntone/grace-period",
        methods=("POST",),
        handler="send_owntone_grace_period_json",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=True,
    )
)

register(
    Route(
        path="/api/owntone/output-visibility",
        methods=("POST",),
        handler="send_owntone_output_visibility_json",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=True,
    )
)

register(
    Route(
        path="/api/owntone/output-mode",
        methods=("POST",),
        handler="send_owntone_output_mode_json",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=True,
    )
)

register(
    Route(
        path="/api/owntone/output-offset",
        methods=("POST",),
        handler="send_owntone_output_offset_json",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=True,
    )
)

register(
    Route(
        path="/api/owntone/uncompressed-audio",
        methods=("POST",),
        handler="send_owntone_uncompressed_json",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=True,
    )
)

register(
    Route(
        path="/api/owntone/buffered-audio",
        methods=("POST",),
        handler="send_owntone_buffered_audio_json",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=True,
    )
)

register(
    Route(
        path="/api/owntone/start-buffer",
        methods=("POST",),
        handler="send_owntone_start_buffer_json",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=True,
    )
)

register(
    Route(
        path="/api/align/start",
        methods=("POST",),
        handler="send_align_start_json",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/align/abort",
        methods=("POST",),
        handler="_route_post_align_abort",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/align/apply",
        methods=("POST",),
        handler="send_align_apply_json",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/align/discard",
        methods=("POST",),
        handler="_route_post_align_discard",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/network/setup",
        methods=("POST",),
        handler="_route_post_network_setup",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/network/roaming",
        methods=("POST",),
        handler="_route_post_network_roaming",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/bluetooth/scan",
        methods=("POST",),
        handler="_route_post_bluetooth_scan",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/bluetooth/pair",
        methods=("POST",),
        handler="_route_post_bluetooth_pair",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/bluetooth/forget",
        methods=("POST",),
        handler="_route_post_bluetooth_forget",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/bluetooth/services",
        methods=("POST",),
        handler="_route_post_bluetooth_services",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/bluetooth/onboard",
        methods=("POST",),
        handler="_route_post_bluetooth_onboard",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/bluetooth/buffer",
        methods=("POST",),
        handler="_route_post_bluetooth_buffer",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/update/apply",
        methods=("POST",),
        handler="_route_post_update_apply",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
        comment="Pre-logic moved from the do_POST arm: _settings_save_barrier flush before staging the update.",
    )
)

register(
    Route(
        path="/api/reboot",
        methods=("POST",),
        handler="_route_post_reboot",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
        comment="Pre-logic moved from the do_POST arm: _settings_save_barrier flush before reboot_system() (3s delay lets this response flush first).",
    )
)

register(
    Route(
        path="/api/factory-reset",
        methods=("POST",),
        handler="_route_post_factory_reset",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)


# ---------------------------------------------------------------------------
# Special-scheme and stateful routes.
#
# This section uses Route.scheme (see its docstring above) for the
# routes that were never gated by the browser session/CSRF/commissioning/
# FULL-auth pipeline in the first place: federation ("bearer"), the
# dial-device protocol endpoints ("dial"), and the two loopback-vs-proxied
# fast paths ("loopback_aware"). It also uses Route.unconfigured_only
# (see its docstring above) for the first-boot pages/posts, which need the
# opposite of allow_unconfigured's gate. Every other route below is a plain
# browser-scheme route, auth/kind/allow_unconfigured derived from its
# now-deleted legacy arm exactly as elsewhere in this table.
#
# After this batch, do_GET/do_POST/do_PUT are reduced to: normalize the
# path, try _route_dispatch(), and 404 if nothing matched -- every branch
# that used to live in their elif chains (including the dial-management
# proxy routes goal 6 called out as possibly-awkward) turned out to map
# cleanly onto the existing Route/AuthRequirement vocabulary plus this
# batch's two small extensions.
# ---------------------------------------------------------------------------

# --- Federation (bearer) ---------------------------------------------------

register(
    Route(
        prefix="/api/federation/v1",
        methods=("GET",),
        handler="_route_get_federation",
        scheme="bearer",
        comment="Auth/commissioning/body validation all stay inside _dispatch_federation, unchanged.",
    )
)

register(
    Route(
        prefix="/api/federation/v1",
        methods=("POST",),
        handler="_route_post_federation",
        scheme="bearer",
        comment=(
            "Adapter reproduces do_POST's former universal body-read (steps 2-3) "
            "up to and including the 'Invalid JSON' check, but deliberately NOT "
            "the later 'JSON object required' non-dict check (do_POST's generic "
            "step ran AFTER the federation branch returned, so federation POSTs "
            "never reached it)."
        ),
    )
)

# --- Dial-device protocol (dial) -------------------------------------------

register(
    Route(
        path="/api/dial/volume",
        methods=("POST",),
        handler="_route_post_dial_volume",
        scheme="dial",
        comment="Non-object JSON body -> 400, matching the legacy UUID-auth dial guard.",
    )
)

register(
    Route(
        path="/api/dial/mute",
        methods=("POST",),
        handler="_route_post_dial_mute",
        scheme="dial",
    )
)

register(
    Route(
        path="/api/dial/status",
        methods=("POST",),
        handler="_route_post_dial_status",
        scheme="dial",
        comment="Non-object JSON body is passed through as {} -- sender 403s on missing dial_id.",
    )
)

# --- Loopback-aware fast paths ----------------------------------------------

register(
    Route(
        path="/api/playing-status",
        methods=("GET",),
        handler="_route_get_playing_status",
        scheme="loopback_aware",
        comment=(
            "Adapter reproduces do_GET's direct-local fast path (bypasses "
            "everything) plus, for a proxied caller, the commissioning gate and "
            "the general 'gate protected pages' redirect-to-auth check it used "
            "to fall through to."
        ),
    )
)

register(
    Route(
        path="/api/log-level",
        methods=("GET",),
        handler="_route_get_log_level",
        scheme="loopback_aware",
        comment="Allowlisted (AUTH.ALLOWLIST_PATHS) so the proxied path has no auth gate, only commissioning.",
    )
)

register(
    Route(
        path="/api/log-level",
        methods=("PUT",),
        handler="_route_put_log_level",
        scheme="loopback_aware",
        comment=(
            "do_PUT never had a commissioning gate at all; adapter reproduces its "
            "own bespoke Content-Type-must-be-json 415 + CSRF-only-for-proxied "
            "logic verbatim."
        ),
    )
)

# --- Gateway (browser session surface) --------------------------------------

register(
    Route(
        path="/api/appliances",
        methods=("GET",),
        handler="_route_get_appliances_list",
        auth=AuthRequirement.NONE,
        kind="api",
        allow_unconfigured=False,
        poll_log=True,
        comment="NONE: AUTH.ALLOWLIST_PATHS covers this exact path. Blocked during commissioning (not in do_GET's commissioning allowlist).",
    )
)

register(
    Route(
        prefix="/api/appliances/",
        methods=("GET",),
        handler="_route_get_gateway_sub",
        auth=AuthRequirement.NONE,
        kind="api",
        allow_unconfigured=False,
        poll_log=True,
        comment="NONE: AUTH.ALLOWLIST_PREFIXES covers this prefix.",
    )
)

register(
    Route(
        prefix="/api/appliances/",
        methods=("POST",),
        handler="_route_post_gateway",
        auth=AuthRequirement.CSRF,
        kind="api",
        allow_unconfigured=False,
        poll_log=True,
        comment="CSRF only -- no inline PIN check in the legacy do_POST arm; per-sub-route body checks live in the adapter.",
    )
)

# --- Remote pages ------------------------------------------------------------

register(
    Route(
        prefix="/a/",
        methods=("GET",),
        handler="_route_get_remote_page",
        auth=AuthRequirement.NONE,
        kind="page",
        allow_unconfigured=False,
        comment="NONE: AUTH.ALLOWLIST_PREFIXES covers '/a/'. Blocked during commissioning (not in do_GET's commissioning allowlist).",
    )
)

# --- Auth flow ---------------------------------------------------------------

register(
    Route(
        path="/auth",
        methods=("GET",),
        handler="_route_get_auth",
        auth=AuthRequirement.NONE,
        kind="page",
        allow_unconfigured=True,
        comment=(
            "NOTE: unlike every other NONE route, legacy returned before reaching "
            "do_GET's unconditional ensure_session() call, so a first visit to "
            "/auth issued no session cookie. dispatch()'s ensure_session step runs "
            "for every browser-scheme GET, including this one, so this migration "
            "adds one extra (harmless, anonymous, already-the-norm-for-every-other-"
            "page) Set-Cookie on first load. Flagged, not fixed -- see task report."
        ),
    )
)

register(
    Route(
        path="/api/auth/verify",
        methods=("POST",),
        handler="_route_post_auth_verify",
        auth=AuthRequirement.NONE,
        kind="api",
        allow_unconfigured=True,
        requires_body=True,
        comment=(
            "NOTE: legacy read+handed off raw bytes with no UTF-8 pre-check, so a "
            "non-UTF8 body fell into handle_auth_verify's own except-Exception -> "
            "'Invalid JSON'. dispatch()'s generic body read now rejects non-UTF8 "
            "earlier with 'Request body is not valid UTF-8' instead. Narrow edge "
            "case, flagged not fixed -- see task report."
        ),
    )
)

register(
    Route(
        path="/api/pin/change",
        methods=("POST",),
        handler="_route_post_pin_change",
        auth=AuthRequirement.CSRF,
        kind="api",
        allow_unconfigured=False,
        requires_body=True,
        comment="Full-auth-if-changing-an-existing-PIN check stays inside AUTH.handle_pin_change.",
    )
)

# --- Stateful pages: setup / owntone-setup form posts -----------------------

register(
    Route(
        path="/setup",
        methods=("POST",),
        handler="_route_post_setup_form",
        auth=AuthRequirement.CSRF,
        kind="api",
        allow_unconfigured=False,
        comment=(
            "The legacy arm's 'if _is_commissioning: handle_setup_post(...)' branch "
            "was already dead code: /setup is not in do_POST's commissioning "
            "allowlist, so a commissioning-time POST was already blocked upstream "
            "(409) before ever reaching this arm -- it could only ever be reached "
            "once configured, where it unconditionally 405s. Reproduced verbatim, "
            "dead branch included (allow_unconfigured=False gives the same 409)."
        ),
    )
)

register(
    Route(
        path="/owntone-setup",
        methods=("POST",),
        handler="_route_post_owntone_setup_form",
        auth=AuthRequirement.CSRF,
        kind="api",
        allow_unconfigured=False,
        comment="Always 405s once CSRF/commissioning pass -- form POST retired in favour of autosave.",
    )
)

# --- Stateful pages: first-boot GET + POST pairs -----------------------------

register(
    Route(
        path="/first-boot/owntone",
        methods=("GET",),
        handler="_route_get_first_boot_owntone",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=True,
        unconfigured_only=True,
    )
)

register(
    Route(
        path="/first-boot/appliance",
        methods=("GET",),
        handler="_route_get_first_boot_appliance",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=True,
        unconfigured_only=True,
    )
)

register(
    Route(
        path="/first-boot/owntone/continue",
        methods=("POST",),
        handler="_route_post_first_boot_continue",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=True,
        unconfigured_only=True,
    )
)

register(
    Route(
        path="/first-boot/appliance/finish",
        methods=("POST",),
        handler="_route_post_first_boot_finish",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=True,
        unconfigured_only=True,
    )
)

# --- Logs download -----------------------------------------------------------

register(
    Route(
        path="/logs/download",
        methods=("GET",),
        handler="_route_get_logs_download",
        auth=AuthRequirement.FULL,
        kind="page",
        allow_unconfigured=True,
    )
)

# --- Dial management (browser, PIN-gated) -----------------------------------
#
# do_POST's UUID-authenticated /api/dial/{volume,mute,status} (above) are a
# different surface from these: browser-session, PIN-gated proxy endpoints
# for administering paired dials. They map cleanly onto plain FULL-auth
# browser routes, same as goal 6 hoped.

register(
    Route(
        path="/api/dial/authorize",
        methods=("POST",),
        handler="_route_post_dial_management",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/dial/revoke",
        methods=("POST",),
        handler="_route_post_dial_management",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/dial/configure",
        methods=("POST",),
        handler="_route_post_dial_management",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/dial/pin_recovery/complete",
        methods=("POST",),
        handler="_route_post_dial_management",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/dial/recovery/arm",
        methods=("POST",),
        handler="_route_post_dial_management",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        path="/api/dial/recovery/disarm",
        methods=("POST",),
        handler="_route_post_dial_management",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        prefix="/api/dial/update/",
        methods=("POST",),
        handler="_route_post_dial_update",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
        comment="Adapter 404s an empty id, reproducing the legacy len(path) > len(prefix) guard.",
    )
)

register(
    Route(
        path="/api/dial/screen/settings",
        methods=("POST",),
        handler="_route_post_dial_screen_settings",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        prefix="/api/dial/configure/",
        methods=("GET",),
        handler="_route_get_dial_configure",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        prefix="/api/dial/pin_recovery/status/",
        methods=("GET",),
        handler="_route_get_dial_pin_recovery_status",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        prefix="/api/dial/update/status/",
        methods=("GET",),
        handler="_route_get_dial_update_status",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)

register(
    Route(
        prefix="/api/dial/screen/settings/",
        methods=("GET",),
        handler="_route_get_dial_screen_settings",
        auth=AuthRequirement.FULL,
        kind="api",
        allow_unconfigured=False,
    )
)
