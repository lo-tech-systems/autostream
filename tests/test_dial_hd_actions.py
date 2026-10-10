"""Tests for the HD server's action, settings, info, panel and presence
routes: a real HdServer on an ephemeral 127.0.0.1 port, a FakeCore that
records the calls, and (for settings) a real management server that is never
started."""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))

import dial_hd_actions as hda
import dial_hd_server as hds
import hd_scenarios as hs
from dial_core_state import ActionResult
from hd_http_support import (
    HEADER, close_management_server, error_of, management_server, post, raw, request,
    write_static,
)
from hd_preview import HdPreview

L = hs.LOUNGE


class FakePanel:
    def __init__(self):
        self.calls = []

    def view(self):
        return {"asleep": False}

    def touch(self):
        self.calls.append("touch")

    def wake(self):
        self.calls.append("wake")

    def sleep_now(self):
        self.calls.append("sleep")


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture(scope="module")
def preview(tmp_path_factory):
    """One server for the module, put back as new before each test. A test
    that needs a differently built server makes its own with make_server."""
    shared = HdPreview(static_root=write_static(tmp_path_factory.mktemp("hd")))
    shared.start()
    yield shared
    shared.stop()


@pytest.fixture
def fresh(preview):
    preview.restore()
    return preview


@pytest.fixture
def core(fresh):
    return fresh.core


@pytest.fixture
def management(fresh):
    return fresh.management


@pytest.fixture
def make_server(core, management, tmp_path):
    servers = []
    root = write_static(tmp_path / "hd")

    def make(**kwargs):
        kwargs.setdefault("http_server", management)
        kwargs.setdefault("static_root", root)
        kwargs.setdefault("muted_fn", lambda service: False)
        kwargs.setdefault("port", 0)
        server = hds.HdServer(SimpleNamespace(), core, **kwargs)
        server.start()
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.stop()


@pytest.fixture
def server(fresh):
    return fresh.server


def act(server, name, body=None, **kwargs):
    return post(server.port, f"/api/v1/actions/{name}", body, **kwargs)


# ---- the action table ------------------------------------------------------

GAINS = {"peq1": 3, "peq6": -2}

VALID = [
    ("focus", {"appliance_id": L}, "set_focus", (L,), {}),
    ("focus", {"appliance_id": None}, "set_focus", (None,), {}),
    ("focus", {}, "set_focus", (None,), {}),
    ("output", {"appliance_id": L, "output_id": "7", "selected": True, "volume": 30},
     "set_output", (L, "7"), {"selected": True, "volume": 30, "pin": None, "pin_entry": True}),
    ("output", {"appliance_id": L, "output_id": "7", "volume": 0},
     "set_output", (L, "7"), {"selected": None, "volume": 0, "pin": None, "pin_entry": True}),
    ("output", {"appliance_id": L, "output_id": "7", "selected": False},
     "set_output", (L, "7"), {"selected": False, "volume": None, "pin": None, "pin_entry": True}),
    ("output", {"appliance_id": L, "output_id": "7", "selected": True, "pin": "1234"},
     "set_output", (L, "7"), {"selected": True, "volume": None, "pin": "1234", "pin_entry": True}),
    ("output", {"appliance_id": L, "output_id": "7", "pin": "12345678"},
     "set_output", (L, "7"), {"selected": None, "volume": None, "pin": "12345678", "pin_entry": True}),
    ("eq", {"appliance_id": L, "gains": GAINS}, "set_eq", (L, GAINS), {}),
    ("eq_reset", {"appliance_id": L}, "reset_eq", (L,), {}),
    ("replay_start", {"appliance_id": L}, "start_replay", (L,), {}),
    ("replay_restart", {"appliance_id": L}, "restart_replay", (L,), {}),
    ("replay_stop", {"appliance_id": L}, "stop_replay", (L,), {}),
    ("repeat_arm", {"appliance_id": L, "armed": True}, "set_repeat_armed", (L, True), {}),
    ("repeat_arm", {"appliance_id": L, "armed": False}, "set_repeat_armed", (L, False), {}),
    ("volume_set", {"appliance_id": L, "level": 55}, "volume_set", (55, L), {}),
    ("volume_set", {"appliance_id": L, "level": 0}, "volume_set", (0, L), {}),
    ("volume_set", {"appliance_id": L, "level": 100}, "volume_set", (100, L), {}),
    ("volume_step", {"appliance_id": L, "delta": -3}, "volume_step", (-3, L), {}),
    ("mute_toggle", {"appliance_id": L}, "mute_toggle", (L,), {}),
    ("warning_dismiss", {"warning_id": "sdhealth"}, "dismiss_warning", ("sdhealth",), {}),
    ("warning_dismiss", {"warning_id": "appliance:" + L + ":w1"}, "dismiss_warning",
     ("appliance:" + L + ":w1",), {}),
]


class TestActionTable:
    @pytest.mark.parametrize("name,body,method,args,kwargs", VALID)
    def test_a_valid_request_calls_one_core_method(self, server, core, name, body, method, args, kwargs):
        response, data = act(server, name, body)
        assert response.status == 200
        assert json.loads(data) == {"ok": True}
        assert core.calls == [(method, args, kwargs)]

    def test_an_accepted_reply_carries_the_token_the_core_gave(self, server, core):
        core.set_result("restart_replay", ActionResult(True, token=12.5))
        response, data = act(server, "replay_restart", {"appliance_id": L})
        assert response.status == 200
        reply = json.loads(data)
        assert reply == {"ok": True, "token": 12.5}
        assert isinstance(reply["token"], float)

    def test_an_accepted_reply_with_no_token_has_no_token_key(self, server, core):
        response, data = act(server, "replay_restart", {"appliance_id": L})
        assert json.loads(data) == {"ok": True}

    def test_a_refusal_carries_no_token(self, server, core):
        core.set_result("restart_replay", ActionResult(False, "wrong_state", token=12.5))
        response, data = act(server, "replay_restart", {"appliance_id": L})
        assert response.status == 409
        assert "token" not in json.loads(data)

    def test_the_table_names_exactly_the_documented_actions(self):
        assert set(hda.ACTIONS) == {
            "focus", "output", "eq", "eq_reset", "replay_start", "replay_restart",
            "replay_stop", "repeat_arm", "volume_set", "volume_step", "mute_toggle",
            "warning_dismiss", "dial_restart", "dial_shutdown", "presence",
        }

    def test_the_valid_table_covers_every_core_calling_action(self):
        covered = {row[0] for row in VALID}
        assert covered == set(hda.ACTIONS) - {"dial_restart", "dial_shutdown", "presence"}

    @pytest.mark.parametrize("name,body,field", [
        ("focus", {"appliance_id": 5}, "appliance_id"),
        ("focus", {"appliance_id": ""}, "appliance_id"),
        ("focus", {"appliance_id": "x" * 129}, "appliance_id"),
        ("focus", {"appliance_id": ["a"]}, "appliance_id"),
        ("focus", {"appliance_id": "a\nb"}, "appliance_id"),
        ("output", {"output_id": "7"}, "appliance_id"),
        ("output", {"appliance_id": L}, "output_id"),
        ("output", {"appliance_id": L, "output_id": 7}, "output_id"),
        ("output", {"appliance_id": L, "output_id": "7", "selected": "yes"}, "selected"),
        ("output", {"appliance_id": L, "output_id": "7", "selected": 1}, "selected"),
        ("output", {"appliance_id": L, "output_id": "7", "volume": 101}, "volume"),
        ("output", {"appliance_id": L, "output_id": "7", "volume": -1}, "volume"),
        ("output", {"appliance_id": L, "output_id": "7", "volume": 5.5}, "volume"),
        ("output", {"appliance_id": L, "output_id": "7", "volume": True}, "volume"),
        ("output", {"appliance_id": L, "output_id": "7", "volume": "30"}, "volume"),
        ("output", {"appliance_id": L, "output_id": "7", "pin": "12"}, "pin"),
        ("output", {"appliance_id": L, "output_id": "7", "pin": "123456789"}, "pin"),
        ("output", {"appliance_id": L, "output_id": "7", "pin": "abcd"}, "pin"),
        ("output", {"appliance_id": L, "output_id": "7", "pin": 1234}, "pin"),
        ("output", {"appliance_id": L, "output_id": "7", "pin": "１２３４"}, "pin"),
        ("output", {"appliance_id": L, "output_id": "7", "pin": "1234\n"}, "pin"),
        ("output", {"appliance_id": L, "output_id": "7", "pin": True}, "pin"),
        ("eq", {"appliance_id": L}, "gains"),
        ("eq", {"appliance_id": L, "gains": {}}, "gains"),
        ("eq", {"appliance_id": L, "gains": []}, "gains"),
        ("eq", {"appliance_id": L, "gains": {"peq1": 25}}, "gains"),
        ("eq", {"appliance_id": L, "gains": {"peq1": -25}}, "gains"),
        ("eq", {"appliance_id": L, "gains": {"peq1": 1.5}}, "gains"),
        ("eq", {"appliance_id": L, "gains": {"peq1": "3"}}, "gains"),
        ("eq", {"appliance_id": L, "gains": {"peq1": True}}, "gains"),
        ("eq", {"appliance_id": L, "gains": {"PEQ 1": 3}}, "gains"),
        ("eq", {"appliance_id": L, "gains": {"a" * 17: 3}}, "gains"),
        ("eq", {"appliance_id": L, "gains": {f"b{i}": 0 for i in range(17)}}, "gains"),
        ("eq_reset", {}, "appliance_id"),
        ("replay_start", {}, "appliance_id"),
        ("replay_restart", {"appliance_id": None}, "appliance_id"),
        ("replay_stop", {"appliance_id": 3}, "appliance_id"),
        ("repeat_arm", {"appliance_id": L}, "armed"),
        ("repeat_arm", {"appliance_id": L, "armed": 1}, "armed"),
        ("repeat_arm", {"appliance_id": L, "armed": "true"}, "armed"),
        ("volume_set", {"appliance_id": L}, "level"),
        ("volume_set", {"appliance_id": L, "level": 101}, "level"),
        ("volume_set", {"appliance_id": L, "level": -1}, "level"),
        ("volume_set", {"appliance_id": L, "level": 50.0}, "level"),
        ("volume_set", {"appliance_id": L, "level": None}, "level"),
        ("volume_set", {"appliance_id": L, "level": 10 ** 30}, "level"),
        ("volume_step", {"appliance_id": L, "delta": 101}, "delta"),
        ("volume_step", {"appliance_id": L, "delta": -101}, "delta"),
        ("volume_step", {"delta": 1}, "appliance_id"),
        ("mute_toggle", {}, "appliance_id"),
        ("warning_dismiss", {}, "warning_id"),
        ("warning_dismiss", {"warning_id": 4}, "warning_id"),
    ])
    def test_a_bad_field_is_400_naming_it_and_calls_nothing(self, server, core, name, body, field):
        response, data = act(server, name, body)
        assert response.status == 400
        assert error_of(data) == f"invalid_{field}"
        assert core.calls == []

    def test_a_refused_pin_is_never_echoed_or_logged(self, server, core, caplog):
        caplog.set_level("DEBUG")
        response, data = act(server, "output", {"appliance_id": L, "output_id": "7", "pin": "98x7"})
        assert response.status == 400
        assert "98x7" not in str(data)
        response, data = act(server, "output", {"appliance_id": L, "output_id": "7", "pin": "98765"})
        assert response.status == 200
        assert "98765" not in str(data)
        assert "98765" not in caplog.text and "98x7" not in caplog.text

    @pytest.mark.parametrize("name", sorted(hda.ACTIONS))
    def test_an_unknown_field_is_refused_for_every_action(self, server, core, name):
        body = {"appliance_id": L, "extra": 1}
        spec = hda.ACTIONS[name][0]
        if not spec:
            body = {"extra": 1}
        response, data = act(server, name, body)
        assert response.status == 400
        assert error_of(data) == "invalid_field"
        assert core.calls == []

    @pytest.mark.parametrize("name", [
        "nothing", "FOCUS", "focus%20", "focus/", "../focus", "focus%00", "a" * 33, "focus-x", "1",
        "step_output_volume", "step_eq",
    ])
    def test_an_unknown_action_name_is_404(self, server, core, name):
        response, data = act(server, name, {})
        assert response.status == 404
        assert error_of(data) == "unknown_action"
        assert core.calls == []

    def test_a_bare_actions_path_is_404(self, server, core):
        response, data = post(server.port, "/api/v1/actions/", {})
        assert response.status == 404
        assert core.calls == []

    def test_an_empty_body_is_an_empty_object(self, server, core):
        response, _ = request(server.port, "POST", "/api/v1/actions/focus", None, HEADER)
        assert response.status == 200
        assert core.calls == [("set_focus", (None,), {})]


class TestActionRequestHardening:
    @pytest.mark.parametrize("body", [b"[]", b'"x"', b"null", b"3", b"true", b"[1,2]"])
    def test_a_body_that_is_not_an_object_is_400(self, server, core, body):
        response, data = act(server, "focus", body)
        assert response.status == 400
        assert error_of(data) == "body_must_be_object"
        assert core.calls == []

    @pytest.mark.parametrize("body", [b"{", b"{'a': 1}", b"\xff\xfe", b"{}{}", b'{"a":NaN'])
    def test_malformed_json_is_400(self, server, core, body):
        response, data = act(server, "focus", body)
        assert response.status == 400
        assert error_of(data) == "bad_json"
        assert core.calls == []

    def test_a_deeply_nested_body_is_contained(self, server, core):
        response, data = act(server, "focus", b"[" * 3000)
        assert response.status in (400, 500)
        assert core.calls == []
        again, _ = act(server, "focus", {})
        assert again.status == 200

    def test_an_oversized_body_is_413_and_never_read(self, server, core):
        response, data = act(server, "focus", b'{"appliance_id":"' + b"a" * hds.MAX_BODY + b'"}')
        assert response.status == 413
        assert error_of(data) == "body_too_large"
        assert core.calls == []

    def test_a_missing_custom_header_is_403(self, server, core):
        response, data = request(
            server.port, "POST", "/api/v1/actions/focus", {"appliance_id": L},
            {"Content-Type": "application/json"},
        )
        assert response.status == 403
        assert error_of(data) == "missing_request_header"
        assert core.calls == []

    def test_a_wrong_custom_header_value_is_403(self, server, core):
        response, _ = request(
            server.port, "POST", "/api/v1/actions/focus", {}, {"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status == 403
        assert core.calls == []

    def test_a_form_post_without_the_header_is_403(self, server, core):
        response, _ = request(
            server.port, "POST", "/api/v1/actions/mute_toggle", b"appliance_id=x",
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert response.status == 403
        assert core.calls == []

    @pytest.mark.parametrize("host", [
        "evil.example", "evil.example:%d", "127.0.0.1:1", "localhost:1", "127.0.0.2:%d", "",
        "[::1]:%d", "127.0.0.1.evil.example:%d",
    ])
    def test_a_wrong_host_is_403(self, server, core, host):
        host = host % server.port if "%d" in host else host
        response, data = act(server, "mute_toggle", {"appliance_id": L}, host=host)
        assert response.status == 403
        assert core.calls == []

    @pytest.mark.parametrize("origin", [
        "http://evil.example", "https://127.0.0.1:%d", "null", "http://127.0.0.1", "",
    ])
    def test_a_mismatched_origin_is_403(self, server, core, origin):
        origin = origin % server.port if "%d" in origin else origin
        response, data = act(
            server, "mute_toggle", {"appliance_id": L}, headers={"Origin": origin},
        )
        assert response.status == 403
        assert error_of(data) == "bad_origin"
        assert core.calls == []

    def test_a_matching_origin_is_accepted(self, server, core):
        response, _ = act(
            server, "mute_toggle", {"appliance_id": L},
            headers={"Origin": f"http://127.0.0.1:{server.port}"},
        )
        assert response.status == 200

    def test_get_on_an_action_is_405_with_allow(self, server, core):
        response, _ = request(server.port, "GET", "/api/v1/actions/focus")
        assert response.status == 405
        assert response.getheader("Allow") == "POST"
        assert core.calls == []

    def test_no_cors_header_is_ever_sent(self, server):
        response, _ = act(server, "focus", {})
        assert not [h for h, _ in response.getheaders() if h.lower().startswith("access-control")]

    def test_an_options_preflight_is_not_answered_as_allowed(self, server):
        raw_reply = raw(
            server.port,
            f"OPTIONS /api/v1/actions/focus HTTP/1.1\r\nHost: 127.0.0.1:{server.port}\r\n"
            "Origin: http://evil.example\r\nAccess-Control-Request-Method: POST\r\n\r\n".encode(),
        )
        assert b"Access-Control" not in raw_reply
        assert not raw_reply.startswith(b"HTTP/1.1 200")

    def test_a_negative_content_length_is_400(self, server, core):
        reply = raw(
            server.port,
            f"POST /api/v1/actions/focus HTTP/1.1\r\nHost: 127.0.0.1:{server.port}\r\n"
            "X-Requested-With: autostream-hd\r\nContent-Length: -5\r\n\r\n".encode(),
        )
        assert reply.startswith(b"HTTP/1.1 400")
        assert core.calls == []

    def test_chunked_encoding_without_a_length_is_411(self, server, core):
        reply = raw(
            server.port,
            f"POST /api/v1/actions/focus HTTP/1.1\r\nHost: 127.0.0.1:{server.port}\r\n"
            "X-Requested-With: autostream-hd\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".encode(),
        )
        assert reply.startswith(b"HTTP/1.1 411")
        assert core.calls == []

    def test_a_handler_that_raises_is_500_and_the_server_survives(self, server, core):
        def boom(*_a, **_k):
            raise RuntimeError("secret appliance text")

        core.mute_toggle = boom
        response, data = act(server, "mute_toggle", {"appliance_id": L})
        assert response.status == 500
        assert json.loads(data) == {"ok": False, "error": "internal_error"}
        assert b"secret" not in data
        again, _ = act(server, "focus", {})
        assert again.status == 200


DOCUMENTED_REASON_STATUS = {
    "unknown_appliance": 404, "unauthorized": 403, "no_capability": 409,
    "wrong_state": 409, "not_polling": 409, "no_record": 409, "not_focused": 409,
}


class TestRefusalMapping:
    def test_every_listed_reason_maps_to_its_status(self, server, core):
        # The expected statuses are written out above, not read from the table
        # under test; a reason the table lists but the documentation does not
        # is reported too.
        wrong = []
        for reason in sorted(set(DOCUMENTED_REASON_STATUS) | set(hds.REASON_STATUS)):
            core.set_result("mute_toggle", ActionResult(False, reason))
            response, data = act(server, "mute_toggle", {"appliance_id": L})
            want = DOCUMENTED_REASON_STATUS.get(reason)
            if response.status != want or json.loads(data) != {"ok": False, "error": reason}:
                wrong.append((reason, want, response.status, data))
        assert not wrong, f"(reason, wanted status, got status, body): {wrong}"

    def test_the_mapping_table_is_the_documented_one(self):
        assert hds.REASON_STATUS == DOCUMENTED_REASON_STATUS

    def test_an_unlisted_reason_is_409(self, server, core):
        core.set_result("mute_toggle", ActionResult(False, "something_new"))
        response, data = act(server, "mute_toggle", {"appliance_id": L})
        assert response.status == 409
        assert error_of(data) == "something_new"

    def test_a_refusal_without_a_reason_is_409_wrong_state(self, server, core):
        core.set_result("mute_toggle", ActionResult(False, None))
        response, data = act(server, "mute_toggle", {"appliance_id": L})
        assert response.status == 409
        assert error_of(data) == "wrong_state"

    def test_every_action_maps_a_refusal(self, server, core):
        wrong = []
        for name, body, method, _args, _kwargs in VALID:
            core.set_result(method, ActionResult(False, "unknown_appliance"))
            response, data = act(server, name, body)
            if response.status != 404 or error_of(data) != "unknown_appliance":
                wrong.append((name, body, response.status, data))
        assert not wrong, f"(action, body, status, reply) not a 404 unknown_appliance: {wrong}"


class TestDialRestart:
    def test_refused_while_no_warning_is_due(self, server, core):
        response, data = act(server, "dial_restart")
        assert response.status == 409
        assert error_of(data) == "wrong_state"
        assert ("request_dial_reboot", (), {}) not in core.calls

    def test_accepted_while_the_no_wifi_warning_is_due(self, server, core):
        core.warnings.set_active("nowifi")
        response, data = act(server, "dial_restart")
        assert response.status == 200
        assert ("request_dial_reboot", (), {}) in core.calls

    def test_refused_when_the_due_warning_has_no_restart_button(self, server, core):
        core.warnings.set_active("sdhealth", "critical")
        response, data = act(server, "dial_restart")
        assert response.status == 409
        assert ("request_dial_reboot", (), {}) not in core.calls

    def test_refused_when_the_no_wifi_warning_is_snoozed(self, server, core):
        core.warnings.set_active("nowifi")
        core.warnings.dismiss("nowifi")
        response, _ = act(server, "dial_restart")
        assert response.status == 409
        assert ("request_dial_reboot", (), {}) not in core.calls

    def test_refused_when_the_reboot_request_is_not_taken(self, make_server, core):
        core.reboot_result = False
        core.warnings.set_active("nowifi")
        response, data = act(make_server(), "dial_restart")
        assert response.status == 409
        assert error_of(data) == "wrong_state"

    def test_takes_no_arguments(self, server, core):
        core.warnings.set_active("nowifi")
        response, data = act(server, "dial_restart", {"now": True})
        assert response.status == 400
        assert ("request_dial_reboot", (), {}) not in core.calls


class TestDialShutdown:
    def test_accepted_calls_the_core_once(self, server, core):
        response, data = act(server, "dial_shutdown")
        assert response.status == 200
        assert json.loads(data) == {"ok": True}
        assert core.calls == [("request_dial_shutdown", (), {})]

    def test_refused_when_the_request_is_not_taken(self, make_server, core):
        core.shutdown_result = False
        response, data = act(make_server(), "dial_shutdown")
        assert response.status == 409
        assert error_of(data) == "wrong_state"

    def test_takes_no_arguments(self, server, core):
        response, data = act(server, "dial_shutdown", {"now": True})
        assert response.status == 400
        assert core.calls == []


class TestPresence:
    def test_presence_confirms_through_the_management_server(self, server, management):
        management.begin_recovery_window()
        try:
            assert management.get_runtime_status()["volume_confirmed"] is False
            response, data = act(server, "presence")
            assert response.status == 200
            assert json.loads(data) == {"ok": True}
            assert management.get_runtime_status()["volume_confirmed"] is True
        finally:
            management._recovery_window.complete()

    def test_presence_with_no_window_open_is_ignored_by_the_window(self, server, management):
        response, _ = act(server, "presence")
        assert response.status == 200
        assert management.get_runtime_status()["volume_confirmed"] is False

    def test_presence_without_a_management_server_is_409(self, make_server):
        response, data = act(make_server(http_server=None), "presence")
        assert response.status == 409
        assert error_of(data) == "wrong_state"

    def test_presence_reaches_confirm_volume(self, make_server, management):
        calls = []
        management.confirm_volume = lambda: calls.append(1)
        act(make_server(), "presence")
        assert calls == [1]

    def test_presence_takes_no_arguments(self, server):
        response, _ = act(server, "presence", {"x": 1})
        assert response.status == 400


# ---- settings --------------------------------------------------------------


@pytest.fixture
def saved():
    """Capture save_config instead of writing a file."""
    calls = []
    with patch("dial_config.save_config", side_effect=lambda cfg: calls.append(cfg)):
        yield calls


class TestSettings:
    def test_get_returns_the_management_servers_screen_report(self, server, management):
        response, data = request(server.port, "GET", "/api/v1/settings")
        assert response.status == 200
        body = json.loads(data)
        assert body == {"ok": True, "screen": management.screen_report()}
        assert response.getheader("Cache-Control") == "no-store"

    def test_post_each_key_alone(self, server, management, saved):
        for body, field, value in [
            ({"brightness": 40}, "brightness", 40),
            ({"sleep_after_s": 900}, "sleep_after_s", 900),
        ]:
            response, data = post(server.port, "/api/v1/settings", body)
            assert response.status == 200, data
            reply = json.loads(data)
            assert reply["ok"] is True
            assert reply["screen"][field] == value
            assert getattr(management.display_config, field) == value
        assert len(saved) == 2

    def test_post_both_at_once(self, server, management, saved):
        body = {"brightness": 25, "sleep_after_s": 60}
        response, data = post(server.port, "/api/v1/settings", body)
        assert response.status == 200
        display = management.display_config
        assert (display.brightness, display.sleep_after_s) == (25, 60)
        assert saved[-1].display.brightness == 25

    def test_the_other_screen_fields_are_kept(self, server, management, saved):
        before = management.display_config
        post(server.port, "/api/v1/settings", {"brightness": 33})
        after = management.display_config
        for field in ("fitted", "rotate", "screen_type", "bgr", "touch_type", "layout_size",
                      "volume_scope", "mute_scope", "poll_interval_s", "screen_size_inches"):
            assert getattr(after, field) == getattr(before, field), field

    def test_the_reply_screen_is_the_saved_report(self, server, management, saved):
        _response, data = post(server.port, "/api/v1/settings", {"brightness": 50})
        assert json.loads(data)["screen"] == management.screen_report()

    def test_the_change_reaches_config_listeners(self, server, management, saved):
        seen = []
        management.add_cfg_listener(lambda cfg: seen.append(cfg.display.brightness))
        post(server.port, "/api/v1/settings", {"brightness": 45})
        assert seen == [45]

    def test_no_pin_is_asked_even_when_one_is_set(self, make_server, saved, tmp_path):
        protected = management_server(pin="4321")
        try:
            response, _ = post(make_server(http_server=protected).port, "/api/v1/settings", {"brightness": 70})
            assert response.status == 200
        finally:
            close_management_server(protected)

    @pytest.mark.parametrize("key", [
        "fitted", "rotate", "screen_type", "bgr", "touch_type", "screen_size_inches",
        "layout_size", "volume_scope", "mute_scope", "poll_interval_s", "surface", "screen",
        "current_pin", "pin", "name", "hd_dev_access", "new_pin", "always_show_controls",
    ])
    def test_any_other_key_is_400_invalid_field_and_changes_nothing(self, server, management, saved, key):
        before = management.display_config
        response, data = post(server.port, "/api/v1/settings", {"brightness": 40, key: 1})
        assert response.status == 400
        assert error_of(data) == "invalid_field"
        assert management.display_config == before
        assert saved == []

    def test_an_empty_body_is_400(self, server, saved):
        response, data = post(server.port, "/api/v1/settings", {})
        assert response.status == 400
        assert error_of(data) == "invalid_field"
        assert saved == []

    @pytest.mark.parametrize("body,field", [
        ({"brightness": 4}, "brightness"), ({"brightness": 101}, "brightness"),
        ({"brightness": "80"}, "brightness"), ({"brightness": True}, "brightness"),
        ({"brightness": 50.5}, "brightness"), ({"brightness": None}, "brightness"),
        ({"sleep_after_s": 7}, "sleep_after_s"), ({"sleep_after_s": -1}, "sleep_after_s"),
        ({"sleep_after_s": "60"}, "sleep_after_s"), ({"sleep_after_s": False}, "sleep_after_s"),
        ({"sleep_after_s": 60.0}, "sleep_after_s"),
    ])
    def test_a_bad_value_is_400_naming_the_key(self, server, management, saved, body, field):
        response, data = post(server.port, "/api/v1/settings", body)
        assert response.status == 400
        assert error_of(data) == f"invalid_{field}"
        assert saved == []

    def test_a_good_key_beside_a_bad_one_changes_nothing(self, server, management, saved):
        before = management.display_config
        response, _ = post(server.port, "/api/v1/settings", {"brightness": 40, "sleep_after_s": 7})
        assert response.status == 400
        assert management.display_config == before

    def test_a_body_that_is_not_an_object_is_400(self, server):
        response, data = post(server.port, "/api/v1/settings", b"[1]")
        assert response.status == 400
        assert error_of(data) == "body_must_be_object"

    def test_post_needs_the_custom_header(self, server, saved):
        response, _ = request(server.port, "POST", "/api/v1/settings", {"brightness": 40}, {})
        assert response.status == 403
        assert saved == []

    def test_a_save_failure_is_500_and_leaves_the_live_config(self, server, management):
        before = management.display_config
        with patch("dial_config.save_config", side_effect=OSError("disk full")):
            response, data = post(server.port, "/api/v1/settings", {"brightness": 40})
        assert response.status == 500
        assert error_of(data) == "save_failed"
        assert management.display_config == before

    def test_an_apply_that_reports_not_ok_is_409(self, server, management):
        management.apply_screen_settings = lambda screen: (
            200, {"ok": False, "error": "screen_apply_failed", "screen": {}},
        )
        response, data = post(server.port, "/api/v1/settings", {"brightness": 40})
        assert response.status == 409
        assert json.loads(data) == {"ok": False, "error": "screen_apply_failed"}

    def test_a_restart_the_apply_asks_for_is_fired_after_the_reply(self, server, management):
        fired = []
        management.apply_screen_settings = lambda screen: (
            200, {"ok": True, "screen": {}, "restarting": True},
        )
        management.fire_touch_restart = lambda: fired.append(1)
        response, _ = post(server.port, "/api/v1/settings", {"brightness": 40})
        assert response.status == 200
        deadline = time.monotonic() + 3
        while not fired and time.monotonic() < deadline:
            time.sleep(0.01)
        assert fired == [1]

    def test_without_a_management_server_both_are_404(self, make_server):
        server = make_server(http_server=None)
        assert request(server.port, "GET", "/api/v1/settings")[0].status == 404
        assert post(server.port, "/api/v1/settings", {"brightness": 40})[0].status == 404

    def test_the_two_servers_apply_one_at_a_time(self, server, management, saved):
        inside = []
        overlap = []
        real = management._apply_screen_settings_locked

        def tracked(screen):
            inside.append(1)
            if len(inside) > 1:
                overlap.append(1)
            try:
                threading.Event().wait(0.05)
                return real(screen)
            finally:
                inside.pop()

        management._apply_screen_settings_locked = tracked
        threads = [
            threading.Thread(target=post, args=(server.port, "/api/v1/settings", {"brightness": 20 + i}))
            for i in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5)
        assert overlap == []
        assert len(saved) == 4


# ---- info ------------------------------------------------------------------


class TestInfo:
    def test_rows_come_from_the_provider_as_text_pairs(self, make_server):
        server = make_server(info_fn=lambda: (("Dial name", "Lounge dial"), ("Version", 7)))
        response, data = request(server.port, "GET", "/api/v1/info")
        assert response.status == 200
        assert json.loads(data) == {"ok": True, "rows": [["Dial name", "Lounge dial"], ["Version", "7"]]}
        assert response.getheader("Cache-Control") == "no-store"

    def test_rows_are_cached_for_ten_seconds(self, make_server):
        clock = Clock()
        calls = []

        def info():
            calls.append(1)
            return (("Calls", str(len(calls))),)

        server = make_server(info_fn=info, clock=clock)
        first = json.loads(request(server.port, "GET", "/api/v1/info")[1])
        clock.now += hds.INFO_CACHE_S - 0.5
        second = json.loads(request(server.port, "GET", "/api/v1/info")[1])
        assert first == second and len(calls) == 1
        clock.now += 1.0
        third = json.loads(request(server.port, "GET", "/api/v1/info")[1])
        assert len(calls) == 2
        assert third["rows"] == [["Calls", "2"]]

    def test_concurrent_requests_gather_once(self, make_server):
        calls = []
        gate = threading.Event()

        def slow():
            calls.append(1)
            gate.wait(2)
            return (("A", "b"),)

        server = make_server(info_fn=slow)
        results = []
        threads = [
            threading.Thread(target=lambda: results.append(request(server.port, "GET", "/api/v1/info")[0].status))
            for _ in range(3)
        ]
        for t in threads:
            t.start()
        threading.Event().wait(0.2)
        gate.set()
        for t in threads:
            t.join(5)
        assert results == [200, 200, 200]
        assert len(calls) == 1

    def test_no_provider_gives_no_rows(self, make_server):
        response, data = request(make_server().port, "GET", "/api/v1/info")
        assert response.status == 200
        assert json.loads(data) == {"ok": True, "rows": []}

    def test_a_raising_provider_is_500_and_not_cached(self, make_server):
        state = {"fail": True}

        def info():
            if state["fail"]:
                raise RuntimeError("probe failed")
            return (("A", "b"),)

        server = make_server(info_fn=info)
        assert request(server.port, "GET", "/api/v1/info")[0].status == 500
        state["fail"] = False
        response, data = request(server.port, "GET", "/api/v1/info")
        assert response.status == 200

    def test_post_is_not_allowed(self, server):
        assert post(server.port, "/api/v1/info", {})[0].status == 405


# ---- panel -----------------------------------------------------------------


class TestPanelRoutes:
    @pytest.mark.parametrize("name,call", [("wake", "wake"), ("sleep", "sleep"), ("activity", "touch")])
    def test_each_route_calls_its_panel_method(self, make_server, name, call):
        panel = FakePanel()
        server = make_server(panel=panel)
        response, data = post(server.port, f"/api/v1/panel/{name}", {})
        assert response.status == 200
        assert json.loads(data) == {"ok": True}
        assert panel.calls == [call]

    @pytest.mark.parametrize("name", ["", "reboot", "WAKE", "wake/x", "../wake", "wake%20", "a" * 40])
    def test_an_unknown_panel_route_is_404(self, make_server, name):
        panel = FakePanel()
        server = make_server(panel=panel)
        response, _ = post(server.port, f"/api/v1/panel/{name}", {})
        assert response.status == 404
        assert panel.calls == []

    def test_without_a_panel_every_route_is_404(self, make_server):
        server = make_server(panel=None)
        for name in ("wake", "sleep", "activity"):
            assert post(server.port, f"/api/v1/panel/{name}", {})[0].status == 404

    def test_a_body_is_not_needed(self, make_server):
        panel = FakePanel()
        server = make_server(panel=panel)
        response, _ = request(server.port, "POST", "/api/v1/panel/wake", None, HEADER)
        assert response.status == 200

    def test_a_hostile_body_is_refused_before_the_panel_is_touched(self, make_server):
        panel = FakePanel()
        server = make_server(panel=panel)
        assert post(server.port, "/api/v1/panel/wake", b"[1]")[0].status == 400
        assert post(server.port, "/api/v1/panel/wake", b"x" * (hds.MAX_BODY + 1))[0].status == 413
        assert panel.calls == []

    def test_a_missing_header_and_a_wrong_host_are_403(self, make_server):
        panel = FakePanel()
        server = make_server(panel=panel)
        assert request(server.port, "POST", "/api/v1/panel/wake", {}, {})[0].status == 403
        assert post(server.port, "/api/v1/panel/wake", {}, host="evil.example")[0].status == 403
        assert panel.calls == []

    def test_get_is_405(self, make_server):
        server = make_server(panel=FakePanel())
        assert request(server.port, "GET", "/api/v1/panel/wake")[0].status == 405

    def test_the_state_body_carries_the_panels_view(self, make_server):
        panel = FakePanel()
        panel.view = lambda: {"asleep": True, "backlight": "sysfs"}
        server = make_server(panel=panel)
        body = json.loads(request(server.port, "GET", "/api/v1/state")[1])
        assert body["panel"]["asleep"] is True
        assert body["panel"]["backlight"] == "sysfs"
