"""Tests for the HD server's development listener: off by default, opened and
closed by the access setting and the PIN, a PIN login that issues an
in-memory session cookie, the shared per-IP limiter, Origin and Host checks,
and the sessions and event streams ending when access goes away."""
from __future__ import annotations

import http.client
import json
import os
import re
import socket
import sys
import time
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))

import dial_hd_events as hde
import dial_hd_server as hds
import dial_http_server as dhs
import hd_scenarios as hs
from dial_hd_events import ChangeHub
from hd_fake_core import FakeCore
from hd_http_support import (
    HEADER, close_management_server, error_of, management_server, post, raw, request,
    write_static,
)

PIN = "2468"
L = hs.LOUNGE


class Clock:
    def __init__(self):
        self.now = 5000.0

    def __call__(self):
        return self.now


def wait_until(predicate, timeout=3.0, step=0.01):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step)
    return predicate()


@pytest.fixture(autouse=True)
def fresh_limiter():
    dhs._pin_attempts.clear()
    yield
    dhs._pin_attempts.clear()


@pytest.fixture
def core():
    return FakeCore(hs.SCENARIOS["playing_artwork"].snapshot)


@pytest.fixture
def management():
    server = management_server(pin=PIN)
    yield server
    close_management_server(server)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def stack(monkeypatch, core, management, clock, tmp_path):
    monkeypatch.setattr(hde, "SSE_HEARTBEAT_S", 0.2)
    hub = ChangeHub(core)
    server = hds.HdServer(
        SimpleNamespace(), core, http_server=management, hub=hub, port=0, dev_port=0,
        static_root=write_static(tmp_path / "hd"), muted_fn=lambda s: False, clock=clock,
    )
    hub.start()
    server.start()
    yield SimpleNamespace(server=server, hub=hub, core=core, management=management, clock=clock)
    server.stop()
    hub.stop()


@pytest.fixture
def server(stack):
    return stack.server


@pytest.fixture
def dev(server):
    server.set_dev_access(True)
    assert server.dev_port
    return server


def dev_request(server, method, path, body=None, headers=None, host=None):
    port = server.dev_port
    return request(port, method, path, body, headers, host=f"127.0.0.1:{port}" if host is None else host)


def login(server, pin=PIN, **kwargs):
    return post(server.dev_port, "/login", {"pin": pin}, host=f"127.0.0.1:{server.dev_port}", **kwargs)


def cookie_of(response) -> str:
    header = response.getheader("Set-Cookie")
    return header.split(";", 1)[0]


def signed_in(server) -> str:
    response, _ = login(server)
    assert response.status == 200
    return cookie_of(response)


def api(server, path, cookie, method="GET", body=None, headers=None):
    sent = dict(headers or {})
    if cookie:
        sent["Cookie"] = cookie
    if method == "POST":
        merged = dict(HEADER)
        merged.update(sent)
        sent = merged
    return dev_request(server, method, path, body, sent)


class Sse:
    def __init__(self, port, cookie):
        self.sock = socket.socket()
        self.sock.settimeout(5)
        self.sock.connect(("127.0.0.1", port))
        lines = ["GET /api/v1/events HTTP/1.1", f"Host: 127.0.0.1:{port}", f"Cookie: {cookie}"]
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        self.buf = b""

    def read_until(self, marker: bytes, timeout=5.0) -> bool:
        deadline = time.monotonic() + timeout
        while marker not in self.buf and time.monotonic() < deadline:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                return marker in self.buf
            self.buf += chunk
        return marker in self.buf

    def closed_by_server(self, timeout=3.0) -> bool:
        deadline = time.monotonic() + timeout
        self.sock.settimeout(0.3)
        while time.monotonic() < deadline:
            try:
                if self.sock.recv(65536) == b"":
                    return True
            except socket.timeout:
                continue
            except OSError:
                return True
        return False

    def close(self):
        self.sock.close()


# ---- off by default --------------------------------------------------------


class TestOffByDefault:
    def test_no_dev_listener_exists_until_enabled(self, server):
        assert server.dev_access_enabled() is False
        assert server.dev_port is None

    def test_the_loopback_listener_does_not_serve_login(self, server):
        for method, path in (("GET", "/login"), ("POST", "/login"), ("POST", "/logout")):
            headers = HEADER if method == "POST" else None
            response, _ = request(server.port, method, path, {} if method == "POST" else None, headers)
            assert response.status in (404, 405)

    def test_the_default_bind_is_every_interface_on_port_7844(self):
        assert hds.DEV_BIND_ADDRESS == "0.0.0.0"
        assert hds.HD_DEV_PORT == 7844

    def test_stop_with_no_dev_listener_is_clean(self, server):
        server.set_dev_access(False)
        assert server.dev_port is None


class TestEnablingAndDisabling:
    def test_enabling_without_a_pin_is_refused(self, stack, caplog):
        stack.management.update_cfg(SimpleNamespace(pin="", hd_dev_access=False, display=stack.management.display_config))
        stack.server.set_dev_access(True)
        assert stack.server.dev_access_enabled() is False
        assert stack.server.dev_port is None

    def test_enabling_with_no_management_server_is_refused(self, core, tmp_path):
        server = hds.HdServer(SimpleNamespace(), core, port=0, dev_port=0, static_root=write_static(tmp_path / "x"))
        try:
            server.set_dev_access(True)
            assert server.dev_access_enabled() is False
        finally:
            server.stop()

    def test_enabling_opens_the_port_and_disabling_closes_it(self, server):
        server.set_dev_access(True)
        port = server.dev_port
        assert port and port != server.port
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            pass
        server.set_dev_access(False)
        assert server.dev_port is None
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=1)

    def test_enabling_twice_keeps_one_listener(self, server):
        server.set_dev_access(True)
        port = server.dev_port
        server.set_dev_access(True)
        assert server.dev_port == port

    def test_it_can_be_reopened_and_old_sessions_do_not_survive(self, server):
        server.set_dev_access(True)
        cookie = signed_in(server)
        assert api(server, "/api/v1/state", cookie)[0].status == 200
        server.set_dev_access(False)
        server.set_dev_access(True)
        assert api(server, "/api/v1/state", cookie)[0].status == 401

    def test_stopping_the_server_closes_it(self, server):
        server.set_dev_access(True)
        port = server.dev_port
        server.stop()
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=1)

    def test_an_unbindable_port_leaves_it_closed(self, core, management, tmp_path):
        blocker = socket.socket()
        blocker.bind(("0.0.0.0", 0))
        blocker.listen(1)
        taken = blocker.getsockname()[1]
        server = hds.HdServer(
            SimpleNamespace(), core, http_server=management, port=0, dev_port=taken,
            static_root=write_static(tmp_path / "y"),
        )
        try:
            server.set_dev_access(True)
            assert server.dev_access_enabled() is False
        finally:
            server.stop()
            blocker.close()


class TestConfigListener:
    def cfg(self, access=True, pin=PIN):
        return SimpleNamespace(hd_dev_access=access, pin=pin)

    def test_access_on_with_a_pin_opens_it(self, server):
        server.on_config(self.cfg())
        assert server.dev_access_enabled()

    def test_access_off_closes_it(self, server):
        server.on_config(self.cfg())
        server.on_config(self.cfg(access=False))
        assert not server.dev_access_enabled()

    def test_clearing_the_pin_closes_it_and_drops_sessions(self, server, stack):
        server.on_config(self.cfg())
        cookie = signed_in(server)
        server.on_config(self.cfg(pin=""))
        assert not server.dev_access_enabled()
        assert server.session_valid(cookie.split("=", 1)[1]) is False

    def test_access_on_with_no_pin_stays_closed(self, server):
        server.on_config(self.cfg(pin=""))
        assert not server.dev_access_enabled()

    def test_a_changed_pin_invalidates_sessions_and_keeps_the_listener(self, server, stack):
        server.on_config(self.cfg())
        cookie = signed_in(server)
        assert api(server, "/api/v1/state", cookie)[0].status == 200
        stack.management._cfg.pin = "1357"
        server.on_config(self.cfg(pin="1357"))
        assert server.dev_access_enabled()
        assert api(server, "/api/v1/state", cookie)[0].status == 401
        # The new PIN signs in; the old one does not.
        assert login(server, pin=PIN)[0].status == 403
        assert login(server, pin="1357")[0].status == 200

    def test_an_unchanged_pin_keeps_sessions(self, server):
        server.on_config(self.cfg())
        cookie = signed_in(server)
        server.on_config(self.cfg())
        assert api(server, "/api/v1/state", cookie)[0].status == 200

    def test_the_listener_runs_from_the_management_servers_update_cfg(self, server, stack):
        stack.management.add_cfg_listener(server.on_config)
        import copy
        new_cfg = copy.copy(stack.management._cfg)
        new_cfg.hd_dev_access = True
        stack.management.update_cfg(new_cfg)
        assert server.dev_access_enabled()
        new_cfg = copy.copy(new_cfg)
        new_cfg.hd_dev_access = False
        stack.management.update_cfg(new_cfg)
        assert not server.dev_access_enabled()


# ---- before a login --------------------------------------------------------


class TestNoSessionNoAccess:
    def test_the_index_redirects_to_login(self, dev):
        response, _ = dev_request(dev, "GET", "/")
        assert response.status == 302
        assert response.getheader("Location") == "/login"

    @pytest.mark.parametrize("path", [
        "/api/v1/state", "/api/v1/info", "/api/v1/settings", "/api/v1/artwork/" + "0" * 16,
        "/api/v1/artwork/" + "0" * 16 + "/backdrop", "/api/v1/logo/backdrop",
        "/api/v1/events", "/static/hd.js",
    ])
    def test_api_and_page_routes_are_401(self, dev, path):
        response, data = dev_request(dev, "GET", path)
        assert response.status == 401
        assert json.loads(data) == {"ok": False, "error": "login_required"}

    @pytest.mark.parametrize("path,body", [
        ("/api/v1/actions/focus", {}), ("/api/v1/actions/presence", {}),
        ("/api/v1/settings", {"brightness": 40}), ("/api/v1/panel/sleep", {}),
    ])
    def test_posts_are_401_and_change_nothing(self, dev, core, path, body):
        response, data = post(dev.dev_port, path, body, host=f"127.0.0.1:{dev.dev_port}")
        assert response.status == 401
        assert error_of(data) == "login_required"
        assert core.calls == []

    def test_a_post_without_the_header_is_403_first(self, dev):
        response, data = dev_request(dev, "POST", "/api/v1/actions/focus", {}, {})
        assert response.status == 403

    def test_the_login_page_and_its_files_are_open(self, dev):
        page, data = dev_request(dev, "GET", "/login")
        assert page.status == 200
        assert b"login.js" in data
        assert "default-src 'none'" in page.getheader("Content-Security-Policy")
        for name in hds.DEV_PUBLIC_STATIC:
            response, _ = dev_request(dev, "GET", f"/static/{name}")
            assert response.status in (200, 404), name       # 404 only when the file is absent
        assert dev_request(dev, "GET", "/static/login.js")[0].status == 200
        assert dev_request(dev, "GET", "/static/hd.css")[0].status == 200

    def test_the_page_script_is_not_among_the_open_files(self):
        assert "hd.js" not in hds.DEV_PUBLIC_STATIC
        assert "index.html" not in hds.DEV_PUBLIC_STATIC

    def test_unknown_routes_are_404_not_401(self, dev):
        assert dev_request(dev, "GET", "/nothing")[0].status == 404

    @pytest.mark.parametrize("cookie", [
        "", "hd_session=", "hd_session=abc", "hd_session=" + "0" * 32, "hd_session=" + "g" * 32,
        "other=" + "a" * 32, "hd_session=" + "a" * 5000, "hd_session=a=b; ;;", "\x01", ";;;;",
        "hd_session=" + "A" * 32,
    ])
    def test_a_missing_or_forged_cookie_is_401(self, dev, cookie):
        headers = {"Cookie": cookie} if cookie else {}
        response, _ = dev_request(dev, "GET", "/api/v1/state", None, headers)
        assert response.status == 401

    def test_a_cookie_from_another_name_is_not_accepted(self, dev):
        token = signed_in(dev).split("=", 1)[1]
        response, _ = dev_request(dev, "GET", "/api/v1/state", None, {"Cookie": "session=" + token})
        assert response.status == 401

    def test_the_token_is_found_among_other_cookies(self, dev):
        token = signed_in(dev).split("=", 1)[1]
        response, _ = dev_request(
            dev, "GET", "/api/v1/state", None, {"Cookie": f"a=1; hd_session={token}; b=2"},
        )
        assert response.status == 200


# ---- login -----------------------------------------------------------------


class TestPresenceIsLocalOnly:
    def test_a_signed_in_remote_session_cannot_confirm_presence(self, dev, management, monkeypatch):
        confirmed = []
        monkeypatch.setattr(management, "confirm_volume", lambda: confirmed.append(True))
        cookie = signed_in(dev)
        response, data = api(dev, "/api/v1/actions/presence", cookie, method="POST", body={})
        assert response.status == 403
        assert json.loads(data) == {"ok": False, "error": "local_only"}
        assert confirmed == []

    def test_a_signed_in_remote_session_cannot_shut_the_dial_down(self, dev, core):
        cookie = signed_in(dev)
        response, data = api(dev, "/api/v1/actions/dial_shutdown", cookie, method="POST", body={})
        assert response.status == 403
        assert json.loads(data) == {"ok": False, "error": "local_only"}
        assert core.calls == []

    def test_the_dials_own_listener_takes_the_shutdown(self, server, core):
        response, data = post(server.port, "/api/v1/actions/dial_shutdown", {})
        assert response.status == 200
        assert core.calls == [("request_dial_shutdown", (), {})]

    def test_other_actions_still_work_for_a_signed_in_session(self, dev, core):
        cookie = signed_in(dev)
        response, _ = api(dev, "/api/v1/actions/focus", cookie, method="POST", body={})
        assert response.status != 403


class TestLogin:
    def test_the_right_pin_sets_a_session_cookie_with_the_expected_attributes(self, dev):
        response, data = login(dev)
        assert response.status == 200
        assert json.loads(data) == {"ok": True}
        header = response.getheader("Set-Cookie")
        name, _, rest = header.partition("=")
        token, _, attributes = rest.partition(";")
        assert name == "hd_session"
        assert re.fullmatch(r"[0-9a-f]{32}", token)
        parts = [p.strip() for p in attributes.split(";")]
        assert "HttpOnly" in parts
        assert "SameSite=Strict" in parts
        assert "Path=/" in parts
        assert "Max-Age=43200" in parts
        assert not any(p.lower().startswith(("domain", "expires")) for p in parts)
        assert response.getheader("Cache-Control") == "no-store"

    def test_each_login_is_a_fresh_token(self, dev):
        assert signed_in(dev) != signed_in(dev)

    def test_the_cookie_opens_everything(self, dev, core):
        cookie = signed_in(dev)
        assert api(dev, "/", cookie)[0].status == 200
        for name in ("hd.js", "hd-tables.js", "hd-dom.js", "hd-state.js", "hd-eq.js", "hd-derive.js", "hd-requests.js", "hd-actions.js"):
            assert api(dev, "/static/" + name, cookie)[0].status == 200
        key = core.snapshot().artwork.key
        assert api(dev, "/api/v1/artwork/%s" % key, cookie)[0].status == 200
        assert api(dev, "/api/v1/artwork/%s/backdrop" % key, cookie)[0].status in (200, 404)
        assert api(dev, "/api/v1/logo/backdrop", cookie)[0].status in (200, 404)
        state = json.loads(api(dev, "/api/v1/state", cookie)[1])
        assert state["v"] == 1
        assert api(dev, "/api/v1/settings", cookie)[0].status == 200
        response, _ = api(dev, "/api/v1/actions/mute_toggle", cookie, "POST", {"appliance_id": L})
        assert response.status == 200
        assert core.calls_to("mute_toggle") == [((L,), {})]

    def test_the_same_page_and_api_as_the_loopback_listener(self, dev, server):
        cookie = signed_in(dev)
        via_dev = api(dev, "/api/v1/state", cookie)[1]
        via_loopback = request(server.port, "GET", "/api/v1/state")[1]
        assert json.loads(via_dev)["now_playing"] == json.loads(via_loopback)["now_playing"]
        assert api(dev, "/", cookie)[1] == request(server.port, "GET", "/")[1]

    def test_the_wrong_pin_is_403_and_issues_nothing(self, dev):
        response, data = login(dev, pin="0000")
        assert response.status == 403
        assert error_of(data) == "wrong_pin"
        assert response.getheader("Set-Cookie") is None

    @pytest.mark.parametrize("pin", [None, 2468, ["2468"], {"a": 1}, True, "", " 2468", "2468 ", "x" * 65])
    def test_a_pin_that_is_not_the_pin_is_403(self, dev, pin):
        response, data = login(dev, pin=pin)
        assert response.status == 403
        assert response.getheader("Set-Cookie") is None

    def test_a_missing_pin_field_is_403(self, dev):
        response, _ = post(dev.dev_port, "/login", {}, host=f"127.0.0.1:{dev.dev_port}")
        assert response.status == 403

    @pytest.mark.parametrize("body", [b"[]", b'"2468"', b"null"])
    def test_a_body_that_is_not_an_object_is_400(self, dev, body):
        response, data = post(dev.dev_port, "/login", body, host=f"127.0.0.1:{dev.dev_port}")
        assert response.status == 400
        assert response.getheader("Set-Cookie") is None

    def test_bad_json_and_an_oversized_body_are_refused(self, dev):
        host = f"127.0.0.1:{dev.dev_port}"
        assert post(dev.dev_port, "/login", b"{", host=host)[0].status == 400
        assert post(dev.dev_port, "/login", b"{" + b" " * hds.MAX_BODY + b"}", host=host)[0].status == 413

    def test_the_login_post_needs_the_custom_header(self, dev):
        response, data = dev_request(dev, "POST", "/login", {"pin": PIN}, {})
        assert response.status == 403
        assert error_of(data) == "missing_request_header"
        assert response.getheader("Set-Cookie") is None

    def test_the_pin_is_never_echoed(self, dev):
        response, data = login(dev, pin="9999")
        assert b"9999" not in data and PIN.encode() not in data

    def test_login_is_disabled_if_the_pin_was_cleared_underneath(self, dev, stack):
        stack.management._cfg.pin = ""
        response, data = login(dev, pin="")
        assert response.status == 403
        assert error_of(data) == "login_disabled"

    def test_get_login_after_a_session_is_still_the_page(self, dev):
        cookie = signed_in(dev)
        assert api(dev, "/login", cookie)[0].status == 200


class TestRateLimit:
    def test_five_wrong_pins_then_429_with_retry_after(self, dev):
        for _ in range(dhs._PIN_MAX_ATTEMPTS - 1):
            assert login(dev, pin="0000")[0].status == 403
        response, data = login(dev, pin="0000")
        assert response.status == 429
        assert int(response.getheader("Retry-After")) >= 1
        assert error_of(data) == "too_many_attempts"

    def test_the_right_pin_is_refused_while_blocked(self, dev):
        for _ in range(dhs._PIN_MAX_ATTEMPTS):
            login(dev, pin="0000")
        response, _ = login(dev, pin=PIN)
        assert response.status == 429
        assert response.getheader("Set-Cookie") is None

    def test_a_success_clears_the_count(self, dev):
        for _ in range(dhs._PIN_MAX_ATTEMPTS - 1):
            login(dev, pin="0000")
        assert login(dev)[0].status == 200
        for _ in range(dhs._PIN_MAX_ATTEMPTS - 1):
            assert login(dev, pin="0000")[0].status == 403

    def test_the_limiter_is_shared_with_the_management_server(self, dev):
        # Failures made on the management route count against the dev login.
        for _ in range(dhs._PIN_MAX_ATTEMPTS):
            dhs._pin_record_failure("127.0.0.1")
        assert login(dev)[0].status == 429
        # And the other way round.
        dhs._pin_clear_attempts("127.0.0.1")
        for _ in range(dhs._PIN_MAX_ATTEMPTS):
            login(dev, pin="0000")
        blocked, _wait = dhs._pin_check_rate_limit("127.0.0.1")
        assert blocked is True

    def test_a_guess_costs_the_same_on_either_route(self, dev):
        # Two failures on the management route and three on the login reach
        # the limit together: the fifth is the one that is blocked.
        for _ in range(2):
            dhs._pin_record_failure("127.0.0.1")
        for _ in range(2):
            assert login(dev, pin="0000")[0].status == 403
        assert login(dev, pin="0000")[0].status == 429

    def test_a_blocked_client_cannot_reach_the_api_either_way(self, dev):
        for _ in range(dhs._PIN_MAX_ATTEMPTS):
            login(dev, pin="0000")
        assert dev_request(dev, "GET", "/api/v1/state")[0].status == 401


# ---- Host and Origin -------------------------------------------------------


class TestHostAndOrigin:
    @pytest.mark.parametrize("host", ["", "evil example:%d", "127.0.0.1", "127.0.0.1:1",
                                      "127.0.0.1:%d:%d", "ex<>ample:%d", "host/x:%d", "ex ample:%d"])
    def test_a_host_without_the_dev_port_or_with_odd_characters_is_403(self, dev, host):
        host = host.replace("%d", str(dev.dev_port))
        response, _ = dev_request(dev, "GET", "/login", host=host)
        assert response.status == 403

    def test_the_loopback_port_is_not_a_dev_host(self, dev, server):
        response, _ = dev_request(dev, "GET", "/login", host=f"127.0.0.1:{server.port}")
        assert response.status == 403

    @pytest.mark.parametrize("host", ["dial.local", "192.168.1.9", "dial-1.example", "[fe80::1]"])
    def test_any_plain_name_on_the_dev_port_is_a_host(self, dev, host):
        response, _ = dev_request(dev, "GET", "/login", host=f"{host}:{dev.dev_port}")
        assert response.status == 200

    def test_the_loopback_listener_still_refuses_a_lan_name(self, server):
        response, _ = request(server.port, "GET", "/api/v1/state", host=f"dial.local:{server.port}")
        assert response.status == 403

    @pytest.mark.parametrize("origin", ["http://evil.example", "https://dial.local:%d", "null",
                                        "http://dial.local", "http://dial.local:1"])
    def test_a_mismatched_origin_is_403_on_login_and_api(self, dev, origin):
        origin = origin.replace("%d", str(dev.dev_port))
        host = f"dial.local:{dev.dev_port}"
        response, data = post(dev.dev_port, "/login", {"pin": PIN}, headers={"Origin": origin}, host=host)
        assert response.status == 403
        assert error_of(data) == "bad_origin"
        assert response.getheader("Set-Cookie") is None
        cookie = signed_in(dev)
        response, _ = request(
            dev.dev_port, "GET", "/api/v1/state", None,
            {"Cookie": cookie, "Origin": origin}, host=host,
        )
        assert response.status == 403

    def test_a_matching_origin_is_accepted(self, dev):
        host = f"dial.local:{dev.dev_port}"
        response, _ = post(
            dev.dev_port, "/login", {"pin": PIN}, headers={"Origin": f"http://{host}"}, host=host,
        )
        assert response.status == 200

    def test_a_cross_site_post_cannot_carry_the_session(self, dev, core):
        cookie = signed_in(dev)
        host = f"127.0.0.1:{dev.dev_port}"
        response, _ = request(
            dev.dev_port, "POST", "/api/v1/actions/mute_toggle", {"appliance_id": L},
            {"Cookie": cookie, "Origin": "http://evil.example", "X-Requested-With": "autostream-hd"},
            host=host,
        )
        assert response.status == 403
        response, _ = request(
            dev.dev_port, "POST", "/api/v1/actions/mute_toggle", {"appliance_id": L},
            {"Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded"}, host=host,
        )
        assert response.status == 403
        assert core.calls == []

    def test_no_cors_header_on_the_dev_listener(self, dev):
        cookie = signed_in(dev)
        for response in (login(dev)[0], api(dev, "/api/v1/state", cookie)[0], dev_request(dev, "GET", "/login")[0]):
            assert not [h for h, _ in response.getheaders() if h.lower().startswith("access-control")]


# ---- logout, expiry, the cap -----------------------------------------------


class TestSessionLifetime:
    def test_logout_drops_the_session_and_clears_the_cookie(self, dev):
        cookie = signed_in(dev)
        response, data = api(dev, "/logout", cookie, "POST", {})
        assert response.status == 200
        header = response.getheader("Set-Cookie")
        assert header.startswith("hd_session=;")
        assert "Max-Age=0" in header and "HttpOnly" in header and "SameSite=Strict" in header
        assert api(dev, "/api/v1/state", cookie)[0].status == 401

    def test_logout_needs_the_custom_header(self, dev):
        cookie = signed_in(dev)
        response, _ = dev_request(dev, "POST", "/logout", {}, {"Cookie": cookie})
        assert response.status == 403
        assert api(dev, "/api/v1/state", cookie)[0].status == 200

    def test_logout_with_no_session_is_harmless(self, dev):
        response, _ = api(dev, "/logout", "", "POST", {})
        assert response.status == 200

    def test_logout_leaves_other_sessions(self, dev):
        a, b = signed_in(dev), signed_in(dev)
        api(dev, "/logout", a, "POST", {})
        assert api(dev, "/api/v1/state", b)[0].status == 200

    def test_a_session_expires_after_twelve_hours(self, dev, stack):
        cookie = signed_in(dev)
        stack.clock.now += hds.SESSION_TTL_S - 1
        assert api(dev, "/api/v1/state", cookie)[0].status == 200
        stack.clock.now += 2
        response, data = api(dev, "/api/v1/state", cookie)
        assert response.status == 401
        assert error_of(data) == "login_required"

    def test_the_ttl_matches_the_cookie_max_age(self):
        assert hds.SESSION_TTL_S == 43200

    def test_sessions_are_capped_and_the_oldest_goes(self, dev):
        cookies = [signed_in(dev) for _ in range(hds.SESSION_MAX + 1)]
        assert api(dev, "/api/v1/state", cookies[0])[0].status == 401
        for cookie in cookies[1:]:
            assert api(dev, "/api/v1/state", cookie)[0].status == 200

    def test_expired_sessions_do_not_count_toward_the_cap(self, dev, stack):
        old = [signed_in(dev) for _ in range(hds.SESSION_MAX)]
        stack.clock.now += hds.SESSION_TTL_S + 1
        fresh = [signed_in(dev) for _ in range(hds.SESSION_MAX)]
        assert all(api(dev, "/api/v1/state", c)[0].status == 200 for c in fresh)
        assert all(api(dev, "/api/v1/state", c)[0].status == 401 for c in old)

    def test_sessions_are_held_in_memory_only(self, server, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        server.set_dev_access(True)
        signed_in(server)
        assert not [p for p in tmp_path.rglob("*") if "session" in p.name.lower()]
        source = open(hds.__file__).read()
        assert not re.search(r"(?<![A-Za-z_.])open[(]", source)
        assert "write_text" not in source and "write_bytes" not in source


# ---- event streams end with access -----------------------------------------


class TestStreams:
    def test_a_stream_with_a_session_delivers_state(self, dev):
        cookie = signed_in(dev)
        client = Sse(dev.dev_port, cookie)
        try:
            assert client.read_until(b"event: state")
            assert b"200 OK" in client.buf
        finally:
            client.close()

    def test_a_stream_without_a_session_is_refused(self, dev):
        client = Sse(dev.dev_port, "hd_session=" + "0" * 32)
        try:
            assert client.read_until(b"login_required")
            assert b"401" in client.buf.split(b"\r\n", 1)[0]
        finally:
            client.close()

    def test_switching_access_off_ends_the_stream(self, dev):
        client = Sse(dev.dev_port, signed_in(dev))
        try:
            assert client.read_until(b"event: state")
            dev.set_dev_access(False)
            assert client.closed_by_server()
        finally:
            client.close()

    def test_clearing_the_pin_ends_the_stream(self, dev):
        client = Sse(dev.dev_port, signed_in(dev))
        try:
            assert client.read_until(b"event: state")
            dev.on_config(SimpleNamespace(hd_dev_access=True, pin=""))
            assert client.closed_by_server()
        finally:
            client.close()

    def test_changing_the_pin_ends_the_stream(self, dev, stack):
        client = Sse(dev.dev_port, signed_in(dev))
        try:
            assert client.read_until(b"event: state")
            stack.management._cfg.pin = "1357"
            dev.on_config(SimpleNamespace(hd_dev_access=True, pin="1357"))
            assert client.closed_by_server()
        finally:
            client.close()

    def test_logout_ends_that_sessions_stream(self, dev):
        cookie = signed_in(dev)
        client = Sse(dev.dev_port, cookie)
        try:
            assert client.read_until(b"event: state")
            api(dev, "/logout", cookie, "POST", {})
            assert client.closed_by_server()
        finally:
            client.close()

    def test_expiry_ends_the_stream(self, dev, stack):
        client = Sse(dev.dev_port, signed_in(dev))
        try:
            assert client.read_until(b"event: state")
            stack.clock.now += hds.SESSION_TTL_S + 1
            assert client.closed_by_server()
        finally:
            client.close()

    def test_the_stream_slot_is_released(self, dev, server):
        client = Sse(dev.dev_port, signed_in(dev))
        assert client.read_until(b"event: state")
        assert server.client_count() == 1
        dev.set_dev_access(False)
        client.close()
        assert wait_until(lambda: server.client_count() == 0)

    def test_the_loopback_stream_is_unaffected_by_dev_access(self, dev, server):
        loop = socket.create_connection(("127.0.0.1", server.port), timeout=5)
        loop.sendall(f"GET /api/v1/events HTTP/1.1\r\nHost: 127.0.0.1:{server.port}\r\n\r\n".encode())
        loop.settimeout(5)
        buf = b""
        while b"event: state" not in buf:
            buf += loop.recv(65536)
        dev.set_dev_access(False)
        loop.settimeout(1.0)
        try:
            data = loop.recv(65536)
            assert data != b""                       # a ping, not a close
        except socket.timeout:
            pass
        finally:
            loop.close()


class TestLoopbackNeverAsksForALogin:
    def test_the_loopback_listener_needs_no_cookie_with_dev_access_on(self, dev, server):
        assert request(server.port, "GET", "/api/v1/state")[0].status == 200
        assert request(server.port, "GET", "/")[0].status == 200
        response, _ = post(server.port, "/api/v1/actions/focus", {})
        assert response.status == 200

    def test_the_loopback_listener_needs_no_cookie_with_dev_access_off(self, server):
        assert request(server.port, "GET", "/api/v1/state")[0].status == 200

    def test_a_dev_cookie_means_nothing_to_the_loopback_listener(self, dev, server):
        cookie = signed_in(dev)
        response, _ = request(server.port, "GET", "/api/v1/state", None, {"Cookie": cookie})
        assert response.status == 200


class TestLoginPageFiles:
    ROOT = os.path.join(os.path.dirname(__file__), "..", "dial", "hd")

    def read(self, name):
        with open(os.path.join(self.ROOT, name), encoding="utf-8") as f:
            return f.read()

    def test_the_page_has_no_inline_script_or_style(self):
        html = self.read("login.html")
        assert not re.search(r"<script(?![^>]*\bsrc=)", html)
        assert "style=" not in html
        assert not re.search(r"\son[a-z]+=", html)
        assert set(re.findall(r'(?:src|href)="([^"]+)"', html)) <= {
            "/static/theme.css", "/static/hd.css", "/static/login.js",
        }

    def test_the_script_sends_the_custom_header_and_never_builds_markup(self):
        js = self.read("login.js")
        assert '"X-Requested-With": "autostream-hd"' in js
        for forbidden in ("innerHTML", "insertAdjacentHTML", "eval(", "document.write"):
            assert forbidden not in js

    def test_every_file_the_login_page_loads_is_open_on_the_dev_listener(self):
        assert {"theme.css", "hd.css", "login.js"} <= set(hds.DEV_PUBLIC_STATIC)
        assert set(hds.DEV_PUBLIC_STATIC) <= set(hds.STATIC_FILES)
