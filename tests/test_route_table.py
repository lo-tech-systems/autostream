"""Tests for the route table (autostream_webui_routes.py).

Four groups:
  1. Table integrity -- static checks over ROUTES itself (no duplicates,
     every handler resolvable/callable, every auth/kind value valid), plus
     expected-table literal cross-checks for every registered route's
     auth/kind/allow_unconfigured/scheme/etc, grouped by what kind of
     route each table covers (browser GET pages/APIs, browser POST APIs,
     special-scheme routes, stateful/commissioning routes).
  2. Dispatcher behaviour -- exercises dispatch() directly against
     temporary routes registered onto a scratch table, with a minimal
     mocked handler, so these tests don't depend on the two real pilot
     routes' specific semantics.
  3. Pilot-route parity -- GET /about and POST /api/repeat must behave
     identically via do_GET/do_POST as the route table intends,
     reusing the assertion style of test_webui_auth_routing.py.
"""
import io
import secrets
import sys
import time
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

try:
    from autostream_webui import ConfigWebHandler
    import autostream_webui as _webui
    import autostream_webui_routes as routes_mod
    from autostream_webui_routes import AuthRequirement, Route, dispatch, register

    _HAS_WEBUI = True
except ImportError:
    _HAS_WEBUI = False

from autostream_auth import AuthManager, Session, SESSION_COOKIE_NAME, PIN_STATUS_MISSING

_skip_no_webui = pytest.mark.skipif(
    not _HAS_WEBUI, reason="autostream_webui import chain unavailable"
)


# ---------------------------------------------------------------------------
# Shared helpers (mirrors test_webui_auth_routing.py's fixtures)
# ---------------------------------------------------------------------------

def _make_manager(pin: Optional[str] = "testpin1") -> AuthManager:
    mgr = AuthManager(config_path="dummy.ini")
    mgr._pin_loaded = True
    if pin is not None:
        mgr._pin_value = pin
        mgr._pin_status = "ok"
    else:
        mgr._pin_value = None
        mgr._pin_status = PIN_STATUS_MISSING
    return mgr


def _csrf_session(mgr: AuthManager) -> tuple:
    sess_token = secrets.token_hex(32)
    csrf_token = secrets.token_hex(32)
    mgr._sessions[sess_token] = Session(
        token=sess_token,
        expires_at=int(time.time()) + 3600,
        csrf_token=csrf_token,
        authenticated=False,
    )
    return sess_token, csrf_token


def _make_handler(path: str, method: str = "GET", sess_token: str = "",
                   csrf_token: str = "", body: bytes = b"") -> "ConfigWebHandler":
    h = ConfigWebHandler.__new__(ConfigWebHandler)
    h.path = path
    h.command = method
    h.request_version = "HTTP/1.1"
    h.headers = {
        "Cookie": f"{SESSION_COOKIE_NAME}={sess_token}" if sess_token else "",
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        "X-CSRF-Token": csrf_token,
        "X-Forwarded-For": "",
        "X-Real-IP": "",
    }
    h.client_address = ("127.0.0.1", 0)
    h.rfile = io.BytesIO(body)
    h.wfile = io.BytesIO()
    h.send_response = MagicMock()
    h.send_header = MagicMock()
    h.end_headers = MagicMock()
    h.send_error = MagicMock()
    h._pending_auth_cookie = None
    h._pending_set_cookies = []
    return h


# ---------------------------------------------------------------------------
# 1. Table integrity
# ---------------------------------------------------------------------------

@_skip_no_webui
class TestTableIntegrity:
    def test_no_duplicate_path_method(self):
        seen = {}
        for r in routes_mod.ROUTES:
            key = r.path or r.prefix
            for m in r.methods:
                dup_key = (key, r.path is not None, m)
                assert dup_key not in seen, f"duplicate route registration: {dup_key}"
                seen[dup_key] = r

    def test_all_handlers_resolvable_and_callable(self):
        for r in routes_mod.ROUTES:
            fn = routes_mod._resolve_handler(r)
            assert callable(fn), f"handler for {r.path or r.prefix} is not callable: {fn!r}"

    def test_all_auth_values_are_enum_members(self):
        for r in routes_mod.ROUTES:
            assert isinstance(r.auth, AuthRequirement)

    def test_all_kind_values_valid(self):
        for r in routes_mod.ROUTES:
            assert r.kind in ("page", "api")

    def test_every_route_has_path_xor_prefix(self):
        for r in routes_mod.ROUTES:
            assert (r.path is not None) != (r.prefix is not None)

    def test_pilot_routes_are_registered(self):
        keys = {(r.path, tuple(r.methods)) for r in routes_mod.ROUTES}
        assert ("/about", ("GET",)) in keys
        assert ("/api/repeat", ("POST",)) in keys

    def test_register_rejects_exact_duplicate(self):
        scratch = []
        with patch.object(routes_mod, "ROUTES", scratch):
            register(Route(path="/tmp-dup", methods=("GET",), handler=lambda h, s: None))
            with pytest.raises(ValueError):
                register(Route(path="/tmp-dup", methods=("GET",), handler=lambda h, s: None))


# ---------------------------------------------------------------------------
# 1b. Browser GET routes (pages + simple GET APIs) -- expected-table
#     literal cross-checking auth/allow_unconfigured/poll_log for every
#     plain GET route. Values were derived from each route's semantics in
#     AUTH.ALLOWLIST_PATHS and do_GET's commissioning allowlist -- see the
#     long comment above this route group's registrations in
#     autostream_webui_routes.py for the derivation rules.
# ---------------------------------------------------------------------------

# (path, auth, kind, allow_unconfigured, poll_log)
_BROWSER_GET_EXPECTED = [
    ("/",                          AuthRequirement.NONE, "page", False, False),
    ("/equaliser",                 AuthRequirement.NONE, "page", False, False),
    ("/service",                   AuthRequirement.NONE, "page", False, False),
    ("/setup",                     AuthRequirement.FULL, "page", False, False),
    ("/logs",                      AuthRequirement.NONE, "page", True, False),
    ("/align",                     AuthRequirement.FULL, "page", False, False),
    ("/align/result",              AuthRequirement.FULL, "page", False, False),
    ("/owntone-setup",             AuthRequirement.FULL, "page", False, False),
    ("/rebooting",                 AuthRequirement.FULL, "page", True, False),
    ("/owntone-restarting",        AuthRequirement.FULL, "page", True, False),
    # /first-boot/owntone and /first-boot/appliance are NOT migrated here --
    # see the comment above their (absent) registration in
    # autostream_webui_routes.py: do_GET's commissioning-else branch
    # redirects them to "/" once already configured, a direction
    # allow_unconfigured can't express.
    ("/api/status",                AuthRequirement.NONE, "api", False, True),
    ("/api/owntone/outputs_state", AuthRequirement.NONE, "api", True, True),
    ("/api/owntone/outputs",       AuthRequirement.FULL, "page", True, True),
    ("/api/audio/status",          AuthRequirement.NONE, "api", False, True),
    ("/api/about/system",          AuthRequirement.NONE, "api", False, False),
    ("/api/settings",              AuthRequirement.FULL, "api", False, False),
    ("/api/output_eq/status",      AuthRequirement.NONE, "api", False, False),
    ("/api/owntone/ready",         AuthRequirement.FULL, "page", True, False),
    ("/api/align/status",          AuthRequirement.FULL, "api", False, False),
    ("/api/network/status",        AuthRequirement.FULL, "api", False, True),
    ("/api/bluetooth/status",      AuthRequirement.FULL, "api", False, False),
    ("/api/bluetooth/scan_results", AuthRequirement.FULL, "api", False, False),
    ("/api/bluetooth/pair_status", AuthRequirement.FULL, "api", False, False),
    ("/api/update/check",          AuthRequirement.FULL, "page", False, False),
    ("/api/update/status",         AuthRequirement.FULL, "page", False, False),
]


@_skip_no_webui
class TestBrowserGetRouteParity:
    """Plain browser-scheme GET routes: pages and simple GET APIs."""

    _by_path = None

    @classmethod
    def setup_class(cls):
        cls._by_path = {
            (r.path, "GET"): r for r in routes_mod.ROUTES if r.path and "GET" in r.methods
        }

    @pytest.mark.parametrize(
        "path,auth,kind,allow_unconfigured,poll_log", _BROWSER_GET_EXPECTED,
        ids=[p for p, *_ in _BROWSER_GET_EXPECTED],
    )
    def test_route_matches_expected_table(self, path, auth, kind, allow_unconfigured, poll_log):
        r = self._by_path.get((path, "GET"))
        assert r is not None, f"{path} is not registered as a GET route"
        assert r.auth is auth, f"{path}: expected auth={auth}, got {r.auth}"
        assert r.kind == kind, f"{path}: expected kind={kind!r}, got {r.kind!r}"
        assert r.allow_unconfigured == allow_unconfigured, (
            f"{path}: expected allow_unconfigured={allow_unconfigured}, got {r.allow_unconfigured}"
        )
        assert r.poll_log == poll_log, f"{path}: expected poll_log={poll_log}, got {r.poll_log}"

    def test_all_expected_paths_covered(self):
        expected_paths = {p for p, *_ in _BROWSER_GET_EXPECTED}
        actual = {r.path for r in routes_mod.ROUTES if r.path in expected_paths}
        assert actual == expected_paths

    def test_polling_paths_removed_from_legacy_tuple(self):
        migrated_pollers = {
            "/api/status", "/api/audio/status", "/api/owntone/outputs_state",
            "/api/owntone/outputs", "/api/network/status",
        }
        for p in migrated_pollers:
            assert p not in _webui._POLLING_LOG_PATHS, (
                f"{p} routed with poll_log=True but is still in _POLLING_LOG_PATHS"
            )


# ---------------------------------------------------------------------------
# 1c. Browser POST API routes -- expected-table literal cross-checking
#     auth/allow_unconfigured/requires_body for every browser POST API
#     route. See the long comment above this route group's registrations
#     in autostream_webui_routes.py for the derivation rules, including the
#     deliberate output_eq/service reset-vs-config allow_unconfigured
#     asymmetry and the /api/owntone/* commissioning allowlist applying
#     despite FULL auth.
# ---------------------------------------------------------------------------

# (path, auth, allow_unconfigured, requires_body)
_BROWSER_POST_EXPECTED = [
    ("/api/output",                     AuthRequirement.CSRF, True, True),
    ("/api/output_eq/config",           AuthRequirement.CSRF, False, True),
    ("/api/output_eq/reset",            AuthRequirement.CSRF, True, False),
    ("/api/service/config",             AuthRequirement.CSRF, False, True),
    ("/api/service/reset",              AuthRequirement.CSRF, True, True),
    ("/api/input_eq",                   AuthRequirement.FULL, False, True),
    ("/api/input_gain",                 AuthRequirement.FULL, False, True),
    ("/api/settings",                   AuthRequirement.FULL, False, False),
    ("/api/settings/hostname",          AuthRequirement.FULL, False, False),
    ("/api/settings/advertisement",     AuthRequirement.FULL, False, False),
    ("/api/settings/auto-update",       AuthRequirement.FULL, False, False),
    ("/api/settings/mdns-grace-period", AuthRequirement.FULL, False, False),
    ("/api/settings/save",              AuthRequirement.FULL, False, False),
    ("/api/owntone/grace-period",       AuthRequirement.FULL, True, False),
    ("/api/owntone/output-visibility",  AuthRequirement.FULL, True, False),
    ("/api/owntone/output-mode",        AuthRequirement.FULL, True, False),
    ("/api/owntone/output-offset",      AuthRequirement.FULL, True, False),
    ("/api/owntone/uncompressed-audio", AuthRequirement.FULL, True, False),
    ("/api/owntone/buffered-audio",     AuthRequirement.FULL, True, False),
    ("/api/owntone/start-buffer",       AuthRequirement.FULL, True, False),
    ("/api/align/start",                AuthRequirement.FULL, False, False),
    ("/api/align/abort",                AuthRequirement.FULL, False, False),
    ("/api/align/apply",                AuthRequirement.FULL, False, False),
    ("/api/align/discard",              AuthRequirement.FULL, False, False),
    ("/api/network/setup",              AuthRequirement.FULL, False, False),
    ("/api/network/roaming",            AuthRequirement.FULL, False, False),
    ("/api/bluetooth/scan",             AuthRequirement.FULL, False, False),
    ("/api/bluetooth/pair",             AuthRequirement.FULL, False, False),
    ("/api/bluetooth/forget",           AuthRequirement.FULL, False, False),
    ("/api/bluetooth/services",         AuthRequirement.FULL, False, False),
    ("/api/bluetooth/onboard",          AuthRequirement.FULL, False, False),
    ("/api/bluetooth/buffer",           AuthRequirement.FULL, False, False),
    ("/api/update/apply",               AuthRequirement.FULL, False, False),
    ("/api/reboot",                     AuthRequirement.FULL, False, False),
    ("/api/factory-reset",              AuthRequirement.FULL, False, False),
]


@_skip_no_webui
class TestBrowserPostApiParity:
    """Browser-scheme POST API routes."""

    _by_path = None

    @classmethod
    def setup_class(cls):
        cls._by_path = {
            (r.path, "POST"): r for r in routes_mod.ROUTES if r.path and "POST" in r.methods
        }

    @pytest.mark.parametrize(
        "path,auth,allow_unconfigured,requires_body", _BROWSER_POST_EXPECTED,
        ids=[p for p, *_ in _BROWSER_POST_EXPECTED],
    )
    def test_route_matches_expected_table(self, path, auth, allow_unconfigured, requires_body):
        r = self._by_path.get((path, "POST"))
        assert r is not None, f"{path} is not registered as a POST route"
        assert r.auth is auth, f"{path}: expected auth={auth}, got {r.auth}"
        assert r.kind == "api", f"{path}: expected kind='api', got {r.kind!r}"
        assert r.allow_unconfigured == allow_unconfigured, (
            f"{path}: expected allow_unconfigured={allow_unconfigured}, got {r.allow_unconfigured}"
        )
        assert r.requires_body == requires_body, (
            f"{path}: expected requires_body={requires_body}, got {r.requires_body}"
        )

    def test_all_expected_paths_covered(self):
        expected_paths = {p for p, *_ in _BROWSER_POST_EXPECTED}
        actual = {r.path for r in routes_mod.ROUTES if r.path in expected_paths}
        assert actual == expected_paths


# ---------------------------------------------------------------------------
# 1d. Special-scheme routes: federation (bearer-authenticated remote-control
#     API), dial (device-authenticated smart-dial API), and loopback-aware
#     (relaxed auth when called from the appliance's own loopback address).
# ---------------------------------------------------------------------------

# (key, method, scheme) for the non-browser-scheme routes -- key is path or
# (prefix,) to disambiguate lookup.
_SPECIAL_SCHEME_EXPECTED = [
    ("/api/federation/v1", True, "GET", "bearer"),
    ("/api/federation/v1", True, "POST", "bearer"),
    ("/api/dial/volume", False, "POST", "dial"),
    ("/api/dial/mute", False, "POST", "dial"),
    ("/api/dial/status", False, "POST", "dial"),
    ("/api/playing-status", False, "GET", "loopback_aware"),
    ("/api/log-level", False, "GET", "loopback_aware"),
    ("/api/log-level", False, "PUT", "loopback_aware"),
]


@_skip_no_webui
class TestSpecialSchemeRouteParity:
    """Federation, dial, and loopback-aware routes carry a non-default
    `scheme`, which selects an alternate authentication path from the
    plain browser-session one every other route uses."""

    @pytest.mark.parametrize(
        "key,is_prefix,method,scheme", _SPECIAL_SCHEME_EXPECTED,
        ids=[f"{k}:{m}" for k, _, m, _ in _SPECIAL_SCHEME_EXPECTED],
    )
    def test_scheme_matches_expected(self, key, is_prefix, method, scheme):
        for r in routes_mod.ROUTES:
            match_key = r.prefix if is_prefix else r.path
            if match_key == key and method in r.methods:
                assert r.scheme == scheme, f"{key} {method}: expected scheme={scheme!r}, got {r.scheme!r}"
                return
        pytest.fail(f"{key} {method} is not registered")

    def test_dial_update_post_prefix_registered(self):
        matches = [r for r in routes_mod.ROUTES if r.prefix == "/api/dial/update/" and "POST" in r.methods]
        assert len(matches) == 1
        assert matches[0].auth is AuthRequirement.FULL

    def test_dial_get_prefixes_registered(self):
        expected_prefixes = {
            "/api/dial/configure/",
            "/api/dial/pin_recovery/status/",
            "/api/dial/update/status/",
            "/api/dial/screen/settings/",
        }
        actual = {
            r.prefix for r in routes_mod.ROUTES
            if r.prefix in expected_prefixes and "GET" in r.methods
        }
        assert actual == expected_prefixes

    def test_gateway_routes_registered(self):
        get_exact = routes_mod._resolve("/api/appliances", "GET")
        assert get_exact is not None and get_exact.auth is AuthRequirement.NONE
        get_sub = routes_mod._resolve("/api/appliances/aabbccdd1122334455aa/home", "GET")
        assert get_sub is not None and get_sub.auth is AuthRequirement.NONE
        post_sub = routes_mod._resolve("/api/appliances/aabbccdd1122334455aa/output", "POST")
        assert post_sub is not None and post_sub.auth is AuthRequirement.CSRF

    def test_remote_page_route_registered(self):
        r = routes_mod._resolve("/a/aabbccdd1122334455aa", "GET")
        assert r is not None
        assert r.auth is AuthRequirement.NONE
        assert r.kind == "page"
        assert r.allow_unconfigured is False


# ---------------------------------------------------------------------------
# 1e. Stateful / commissioning browser routes: auth, first-boot, and
#     logs-download pages (GET); auth verify, pin change, setup/owntone-setup
#     forms, first-boot continuation, and dial device-management actions
#     (POST). Grouped separately from the plain GET/POST tables above
#     because every route here carries commissioning-window semantics
#     (unconfigured_only) that the plain tables don't need to express.
# ---------------------------------------------------------------------------

# (path, auth, kind, allow_unconfigured, unconfigured_only)
_STATEFUL_GET_EXPECTED = [
    ("/auth",              AuthRequirement.NONE, "page", True, False),
    ("/first-boot/owntone",   AuthRequirement.FULL, "api", True, True),
    ("/first-boot/appliance", AuthRequirement.FULL, "api", True, True),
    ("/logs/download",     AuthRequirement.FULL, "page", True, False),
]

# (path, auth, allow_unconfigured, unconfigured_only)
_STATEFUL_POST_EXPECTED = [
    ("/api/auth/verify",              AuthRequirement.NONE, True, False),
    ("/api/pin/change",               AuthRequirement.CSRF, False, False),
    ("/setup",                        AuthRequirement.CSRF, False, False),
    ("/owntone-setup",                AuthRequirement.CSRF, False, False),
    ("/first-boot/owntone/continue",  AuthRequirement.FULL, True, True),
    ("/first-boot/appliance/finish",  AuthRequirement.FULL, True, True),
    ("/api/dial/authorize",           AuthRequirement.FULL, False, False),
    ("/api/dial/revoke",              AuthRequirement.FULL, False, False),
    ("/api/dial/configure",           AuthRequirement.FULL, False, False),
    ("/api/dial/pin_recovery/complete", AuthRequirement.FULL, False, False),
    ("/api/dial/recovery/arm",        AuthRequirement.FULL, False, False),
    ("/api/dial/recovery/disarm",     AuthRequirement.FULL, False, False),
    ("/api/dial/screen/settings",     AuthRequirement.FULL, False, False),
]


@_skip_no_webui
class TestStatefulRouteParity:
    _get_by_path = None
    _post_by_path = None

    @classmethod
    def setup_class(cls):
        cls._get_by_path = {r.path: r for r in routes_mod.ROUTES if r.path and "GET" in r.methods}
        cls._post_by_path = {r.path: r for r in routes_mod.ROUTES if r.path and "POST" in r.methods}

    @pytest.mark.parametrize(
        "path,auth,kind,allow_unconfigured,unconfigured_only", _STATEFUL_GET_EXPECTED,
        ids=[p for p, *_ in _STATEFUL_GET_EXPECTED],
    )
    def test_get_route_matches_expected(self, path, auth, kind, allow_unconfigured, unconfigured_only):
        r = self._get_by_path.get(path)
        assert r is not None, f"{path} is not registered as a GET route"
        assert r.auth is auth, f"{path}: expected auth={auth}, got {r.auth}"
        assert r.kind == kind, f"{path}: expected kind={kind!r}, got {r.kind!r}"
        assert r.allow_unconfigured == allow_unconfigured
        assert r.unconfigured_only == unconfigured_only

    @pytest.mark.parametrize(
        "path,auth,allow_unconfigured,unconfigured_only", _STATEFUL_POST_EXPECTED,
        ids=[p for p, *_ in _STATEFUL_POST_EXPECTED],
    )
    def test_post_route_matches_expected(self, path, auth, allow_unconfigured, unconfigured_only):
        r = self._post_by_path.get(path)
        assert r is not None, f"{path} is not registered as a POST route"
        assert r.auth is auth, f"{path}: expected auth={auth}, got {r.auth}"
        assert r.allow_unconfigured == allow_unconfigured
        assert r.unconfigured_only == unconfigured_only

    def test_setup_card_prefix_matches_setup_page_gating(self):
        """The lazy per-card detail fetch must be gated exactly like
        /setup itself -- it serves the same detail HTML /setup used to
        inline, so any weaker auth/commissioning gate would hand a caller
        page content they cannot otherwise reach. Only `kind` differs,
        deliberately: an api route 401s with JSON rather than redirecting
        a fetch() to the login page."""
        page = routes_mod._resolve("/setup", "GET")
        card = routes_mod._resolve("/api/setup/card/bluetooth", "GET")
        assert card is not None, "/api/setup/card/<key> is not registered as a GET route"
        assert card.prefix == "/api/setup/card/"
        assert card.auth is page.auth is AuthRequirement.FULL
        assert card.allow_unconfigured == page.allow_unconfigured is False
        assert card.kind == "api"

    def test_unconfigured_only_implies_allow_unconfigured(self):
        for r in routes_mod.ROUTES:
            if r.unconfigured_only:
                assert r.allow_unconfigured, (
                    f"{r.path or r.prefix}: unconfigured_only routes must also be "
                    f"allow_unconfigured (otherwise they're unreachable during "
                    f"commissioning, the only window unconfigured_only leaves open)"
                )


# ---------------------------------------------------------------------------
# 2. Dispatcher behaviour (scratch routes, mocked handler)
# ---------------------------------------------------------------------------

@_skip_no_webui
class TestDispatcherBehaviour:
    def test_unknown_path_returns_false(self):
        h = _make_handler("/no-such-route", "GET")
        h._commissioning_required = lambda: False
        with patch("autostream_webui.STATE", MagicMock()):
            assert dispatch(h, "GET", "/no-such-route-really") is False

    def test_auth_none_passes_through(self):
        stub = MagicMock()
        scratch = [Route(path="/tmp-none", methods=("GET",), handler=stub,
                          auth=AuthRequirement.NONE, kind="page")]
        h = _make_handler("/tmp-none", "GET")
        h._commissioning_required = lambda: False
        with patch.object(routes_mod, "ROUTES", scratch), \
             patch("autostream_webui.STATE", MagicMock()) as state, \
             patch("autostream_webui.AUTH", MagicMock()):
            result = dispatch(h, "GET", "/tmp-none")
        assert result is True
        stub.assert_called_once_with(h, state)

    def test_auth_full_redirects_page_when_unauthenticated(self):
        stub = MagicMock()
        scratch = [Route(path="/tmp-full-page", methods=("GET",), handler=stub,
                          auth=AuthRequirement.FULL, kind="page")]
        h = _make_handler("/tmp-full-page", "GET")
        h._commissioning_required = lambda: False
        mock_auth = MagicMock()
        mock_auth.require_authenticated_if_pin_enabled.return_value = False
        with patch.object(routes_mod, "ROUTES", scratch), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.AUTH", mock_auth):
            result = dispatch(h, "GET", "/tmp-full-page")
        assert result is True
        stub.assert_not_called()
        mock_auth.require_authenticated_if_pin_enabled.assert_called_once_with(
            h, redirect_path=h.path
        )

    def test_auth_full_401s_api_when_unauthenticated(self):
        stub = MagicMock()
        scratch = [Route(path="/tmp-full-api", methods=("GET",), handler=stub,
                          auth=AuthRequirement.FULL, kind="api")]
        h = _make_handler("/tmp-full-api", "GET")
        h._commissioning_required = lambda: False
        mock_auth = MagicMock()
        mock_auth.require_authenticated_if_pin_enabled.return_value = False
        with patch.object(routes_mod, "ROUTES", scratch), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.AUTH", mock_auth):
            result = dispatch(h, "GET", "/tmp-full-api")
        assert result is True
        stub.assert_not_called()
        mock_auth.require_authenticated_if_pin_enabled.assert_called_once_with(
            h, redirect_path=None
        )

    def test_auth_full_passes_when_authenticated(self):
        stub = MagicMock()
        scratch = [Route(path="/tmp-full-ok", methods=("GET",), handler=stub,
                          auth=AuthRequirement.FULL, kind="api")]
        h = _make_handler("/tmp-full-ok", "GET")
        h._commissioning_required = lambda: False
        mock_auth = MagicMock()
        mock_auth.require_authenticated_if_pin_enabled.return_value = True
        with patch.object(routes_mod, "ROUTES", scratch), \
             patch("autostream_webui.STATE", MagicMock()) as state, \
             patch("autostream_webui.AUTH", mock_auth):
            result = dispatch(h, "GET", "/tmp-full-ok")
        assert result is True
        stub.assert_called_once_with(h, state)

    def test_allow_unconfigured_false_blocks_during_commissioning(self):
        stub = MagicMock()
        scratch = [Route(path="/tmp-gated", methods=("GET",), handler=stub,
                          auth=AuthRequirement.NONE, kind="page",
                          allow_unconfigured=False)]
        h = _make_handler("/tmp-gated", "GET")
        h._commissioning_required = lambda: True
        with patch.object(routes_mod, "ROUTES", scratch), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.required_first_boot_step", return_value="owntone"):
            result = dispatch(h, "GET", "/tmp-gated")
        assert result is True
        stub.assert_not_called()
        h.send_response.assert_called_once_with(302)

    def test_allow_unconfigured_true_reaches_handler_during_commissioning(self):
        stub = MagicMock()
        scratch = [Route(path="/tmp-open-during-boot", methods=("GET",), handler=stub,
                          auth=AuthRequirement.NONE, kind="page",
                          allow_unconfigured=True)]
        h = _make_handler("/tmp-open-during-boot", "GET")
        h._commissioning_required = lambda: True
        with patch.object(routes_mod, "ROUTES", scratch), \
             patch("autostream_webui.STATE", MagicMock()) as state, \
             patch("autostream_webui.AUTH", MagicMock()):
            result = dispatch(h, "GET", "/tmp-open-during-boot")
        assert result is True
        stub.assert_called_once_with(h, state)

    def test_known_path_wrong_method_falls_through(self):
        stub = MagicMock()
        scratch = [Route(path="/tmp-get-only", methods=("GET",), handler=stub)]
        h = _make_handler("/tmp-get-only", "POST", body=b"{}")
        with patch.object(routes_mod, "ROUTES", scratch):
            result = dispatch(h, "POST", "/tmp-get-only")
        assert result is False
        stub.assert_not_called()


# ---------------------------------------------------------------------------
# 3. Pilot-route parity via do_GET / do_POST
# ---------------------------------------------------------------------------

@_skip_no_webui
class TestPilotRouteAboutPage:
    """GET /about: AuthRequirement.NONE, must remain open to any caller."""

    def test_about_reachable_without_session(self):
        h = _make_handler("/about", "GET")
        with patch("autostream_webui.AUTH", _make_manager()), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.send_about_page") as stub:
            h.do_GET()
        stub.assert_called_once()

    def test_about_gated_during_commissioning(self):
        h = _make_handler("/about", "GET")
        with patch("autostream_webui.AUTH", _make_manager()), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=True), \
             patch("autostream_webui.required_first_boot_step", return_value="owntone"), \
             patch("autostream_webui.send_about_page") as stub:
            h.do_GET()
        stub.assert_not_called()
        h.send_response.assert_called_once_with(302)


@_skip_no_webui
class TestPilotRouteApiRepeat:
    """POST /api/repeat: AuthRequirement.CSRF, no PIN gate (matches the
    _PUBLIC manifest in test_webui_auth_routing.py).
    """

    def test_repeat_allows_unauthenticated_with_valid_csrf(self):
        mgr = _make_manager()
        sess_token, csrf_token = _csrf_session(mgr)
        body = b'{"armed": true}'
        h = _make_handler("/api/repeat", "POST", sess_token, csrf_token, body=body)
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.send_repeat_post_json") as stub:
            h.do_POST()
        stub.assert_called_once()

    def test_repeat_rejects_missing_csrf(self):
        mgr = _make_manager()
        _csrf_session(mgr)  # session exists, but token below is wrong
        body = b'{"armed": true}'
        h = _make_handler("/api/repeat", "POST", "", "", body=body)
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.send_repeat_post_json") as stub:
            h.do_POST()
        stub.assert_not_called()

    def test_repeat_missing_body_matches_legacy_400(self):
        mgr = _make_manager()
        sess_token, csrf_token = _csrf_session(mgr)
        h = _make_handler("/api/repeat", "POST", sess_token, csrf_token, body=b"")
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=False), \
             patch("autostream_webui.send_repeat_post_json") as stub:
            h.do_POST()
        stub.assert_not_called()
        h.send_error.assert_called_once_with(400, "Missing request body")

    def test_repeat_gated_during_commissioning(self):
        mgr = _make_manager()
        sess_token, csrf_token = _csrf_session(mgr)
        body = b'{"armed": true}'
        h = _make_handler("/api/repeat", "POST", sess_token, csrf_token, body=body)
        sent = []
        with patch("autostream_webui.AUTH", mgr), \
             patch("autostream_webui.STATE", MagicMock()), \
             patch("autostream_webui.is_commissioning_required", return_value=True), \
             patch("autostream_webui.send_json", side_effect=lambda h, c, d: sent.append((c, d))), \
             patch("autostream_webui.send_repeat_post_json") as stub:
            h.do_POST()
        stub.assert_not_called()
        assert sent and sent[0][0] == 409
