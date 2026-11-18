"""tests/test_protocol_intents.py

POST /api/v1/intents/<name> through a real server and the route table: the
body and origin checks, the protocol number, the unconfigured answer, who is
asking and what they may do, the exposed set, the values the route fills in
for the speaker rows, and the refusals that arrive after the reply.
"""
from __future__ import annotations

import contextlib
import dataclasses
import http.client
import json
import secrets
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_appliance_state  # noqa: F401  (binds the dials rows)
import autostream_dials as dials
import autostream_live_config as live_config
import autostream_logging as log_setup
import autostream_monitor_control  # noqa: F401  (binds the equaliser rows)
import autostream_output_intents  # noqa: F401  (binds the output rows)
import autostream_pin_pairing as pairing
import autostream_protocol
from autostream_auth import SESSION_COOKIE_NAME, Session
from autostream_intents import Intent, Origin, Reply, table
from autostream_players import ActionResult
from autostream_settings import SettingsStore
from autostream_state.outputs import START_PENDING_S, get_authority
from fake_store import FakeStore
from output_fakes import FakeBackend, group_row, row, snap
from stream_helpers import RealServer
import webui.browser.home_model as home_model
import webui.common as webui_common
import webui.protocol.hub as proto_hub
import webui.protocol.intents as route

ID = "42"
DIAL = "dial:0123456789abcdef0123"
PEER = "peer:aabbccddeeff00112233"
CONFIG = SimpleNamespace(owntone=SimpleNamespace(
    volume_percent=37, output_offsets_ms={ID: 120}, output_airplay_modes={ID: "airplay2"}))


class Env:
    def __init__(self, server) -> None:
        self.server = server
        self.verdict = dials.AUTH_AUTHORIZED

    def request(self, path, raw: bytes, headers=None, method="POST"):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=10)
        try:
            conn.request(method, path, body=raw, headers=headers or {})
            resp = conn.getresponse()
            data = resp.read()
            try:
                return resp.status, json.loads(data)
            except ValueError:
                return resp.status, data
        finally:
            conn.close()

    def post(self, name, body=None, *, headers=None, **fields):
        """POST a JSON body: a dial or peer named in *body* sends the protocol
        number; a browser gets a session and its CSRF token unless
        ``browser=False``."""
        body = dict(body or {})
        body.update(fields)
        head = {"Content-Type": "application/json"}
        if "client" in body:
            body.setdefault("protocol", autostream_protocol.PROTOCOL)
        head.update(headers or {})
        return self.request(f"/api/v1/intents/{name}", json.dumps(body).encode(), head)

    def browser(self, *, authenticated=True) -> dict:
        token, csrf = secrets.token_hex(16), secrets.token_hex(16)
        self.server.auth._sessions[token] = Session(
            token=token, expires_at=int(time.time()) + 3600, csrf_token=csrf, authenticated=authenticated)
        return {"Cookie": f"{SESSION_COOKIE_NAME}={token}", "X-CSRF-Token": csrf}


@pytest.fixture
def env(monkeypatch):
    log_setup.reset_for_tests()
    server = RealServer(monkeypatch)
    e = Env(server)
    monkeypatch.setattr(route, "_configured_memo", None)
    monkeypatch.setattr(webui_common, "_config_snapshot", lambda state: CONFIG)
    monkeypatch.setattr(proto_hub.dials, "dial_authorization", lambda uuid: e.verdict)
    server.hub._peer_control = lambda: True
    pairing.reset_for_tests() if hasattr(pairing, "reset_for_tests") else None
    yield e
    server.close()


class Spy:
    """Stands in for submit(): records the intents and replies as told."""

    def __init__(self, reply=None) -> None:
        self.intents = []
        self.reply = reply or Reply(True, None, 5, "b", {"ok": True})

    def __call__(self, intent, **kw):
        self.intents.append(intent)
        return self.reply


@pytest.fixture
def spy(monkeypatch):
    s = Spy()
    monkeypatch.setattr(route, "submit", s)
    return s


# -----------------------------------------------------------------------------
# The request itself
# -----------------------------------------------------------------------------

class TestRequest:
    def test_a_reply_has_the_five_fields(self, env, spy):
        status, body = env.post("volume.set", {"args": {"level": 20}}, headers=env.browser())
        assert status == 200
        assert set(body) == {"ok", "error", "version", "boot", "result"}
        assert body["ok"] is True and body["result"] == {"ok": True}

    def test_a_body_that_is_not_json_is_invalid_json(self, env):
        status, body = env.request("/api/v1/intents/volume.set", b"nonsense",
                                   {"Content-Type": "application/json"})
        assert (status, body["error"]) == (400, "invalid_json")

    def test_a_body_that_is_not_an_object_is_invalid_json(self, env):
        status, body = env.request("/api/v1/intents/volume.set", b"[1]",
                                   {"Content-Type": "application/json"})
        assert (status, body["error"]) == (400, "invalid_json")

    def test_another_content_type_is_invalid_json(self, env):
        status, body = env.request("/api/v1/intents/volume.set", b"{}",
                                   {"Content-Type": "text/plain"})
        assert (status, body["error"]) == (400, "invalid_json")

    def test_a_body_over_the_cap_is_body_too_large(self, env):
        big = b'{"args": {"x": "' + b"a" * 70000 + b'"}}'
        status, body = env.request("/api/v1/intents/volume.set", big,
                                   {"Content-Type": "application/json"})
        assert (status, body["error"]) == (413, "body_too_large")

    def test_another_origin_is_cross_origin(self, env, spy):
        headers = {**env.browser(), "Origin": "http://evil.example"}
        status, body = env.post("volume.set", {"args": {"level": 20}}, headers=headers)
        assert (status, body["error"]) == (403, "cross_origin")
        assert spy.intents == []

    def test_the_same_origin_is_served(self, env, spy):
        headers = {**env.browser(), "Origin": f"http://127.0.0.1:{env.server.port}"}
        assert env.post("volume.set", {"args": {"level": 20}}, headers=headers)[1]["ok"] is True

    def test_a_get_is_not_served(self, env):
        status, _ = env.request("/api/v1/intents/volume.set", b"", method="GET")
        assert status in (404, 405)

    def test_a_malformed_name_and_an_unknown_name_are_unknown_intent(self, env, spy):
        headers = env.browser()
        for name in ("nonsense", "Volume.Set", "volume.set/extra", "x" * 70):
            status, body = env.post(name, {}, headers=headers)
            assert (status, body["ok"], body["error"]) == (200, False, "unknown_intent"), name
        assert spy.intents == []

    def test_args_that_are_not_an_object_are_invalid_args(self, env, spy):
        _, body = env.post("volume.set", {"args": [1]}, headers=env.browser())
        assert body["error"] == "invalid_args"
        assert spy.intents == []

    def test_missing_args_are_an_empty_object(self, env):
        _, body = env.post("volume.set", {}, headers=env.browser())
        assert body["error"] == "invalid_args"          # the row's level is missing

    def test_rate_limited_copies_retry_after_to_the_top_level(self, env, monkeypatch):
        monkeypatch.setattr(route, "submit", Spy(Reply(
            False, "rate_limited", 5, "b", {"ok": False, "error": "rate_limited", "retry_after_s": 7})))
        _, body = env.post("output.pin.submit", {"args": {"id": ID, "pin": "1234"}}, headers=env.browser())
        assert body["error"] == "rate_limited" and body["retry_after_s"] == 7
        assert body["result"]["retry_after_s"] == 7

    def test_an_exception_in_the_intent_is_internal_error(self, env, monkeypatch):
        def boom(intent, **kw):
            raise RuntimeError("boom")

        monkeypatch.setattr(route, "submit", boom)
        status, body = env.post("volume.set", {"args": {"level": 3}}, headers=env.browser())
        assert (status, body["error"]) == (200, "internal_error")


# -----------------------------------------------------------------------------
# Protocol number, unconfigured, and the exposed set
# -----------------------------------------------------------------------------

class TestGates:
    @pytest.mark.parametrize("client", [DIAL, PEER])
    def test_a_named_client_must_send_this_protocol(self, env, spy, client):
        env.verdict = dials.AUTH_AUTHORIZED
        for extra in ({}, {"protocol": 3}, {"protocol": "4"}):
            status, body = env.request(
                "/api/v1/intents/volume.set",
                json.dumps({"client": client, "args": {"level": 5}, **extra}).encode(),
                {"Content-Type": "application/json"})
            assert (status, body) == (200, {"ok": False, "error": "protocol_mismatch", "protocol": 4})
        assert spy.intents == []

    def test_a_browser_may_leave_the_protocol_out_but_not_get_it_wrong(self, env, spy):
        headers = env.browser()
        assert env.post("volume.set", {"args": {"level": 5}}, headers=headers)[1]["ok"] is True
        assert env.post("volume.set", {"args": {"level": 5}, "protocol": 4}, headers=headers)[1]["ok"] is True
        _, body = env.post("volume.set", {"args": {"level": 5}, "protocol": 3}, headers=headers)
        assert body["error"] == "protocol_mismatch"

    @pytest.mark.parametrize("name", sorted(autostream_protocol.EXPOSED_INTENTS) + ["settings.discard", "nope"])
    def test_every_name_is_unconfigured_on_an_unconfigured_appliance(self, env, spy, name):
        env.server.commissioning_required = True
        status, body = env.post(name, {"args": {}}, headers=env.browser())
        assert (status, body["ok"], body["error"]) == (200, False, "unconfigured")
        assert spy.intents == []

    def test_a_named_client_is_unconfigured_too(self, env, spy):
        env.server.commissioning_required = True
        assert env.post("volume.set", {"client": DIAL, "args": {"level": 4}})[1]["error"] == "unconfigured"

    def test_the_configured_answer_is_remembered_for_a_second(self, env, spy, monkeypatch):
        calls = []
        real = route.commissioning.is_commissioning_required

        def counting(*a):
            calls.append(a)
            return real(*a)

        monkeypatch.setattr(route.commissioning, "is_commissioning_required", counting)
        clock = [100.0]
        monkeypatch.setattr(route.time, "monotonic", lambda: clock[0])
        headers = env.browser()
        for _ in range(3):
            env.post("volume.set", {"args": {"level": 4}}, headers=headers)
        assert len(calls) == 1
        env.server.commissioning_required = True            # not seen yet
        assert env.post("volume.set", {"args": {"level": 4}}, headers=headers)[1]["ok"] is True
        clock[0] += 1.5
        assert env.post("volume.set", {"args": {"level": 4}}, headers=headers)[1]["error"] == "unconfigured"
        assert len(calls) == 2

    def test_a_client_authorised_a_moment_ago_is_not_refused_unconfigured(self, env, spy):
        # The live answer reaches the hub; the appliance part (still empty here)
        # is never asked.
        assert env.server.store.snapshot().appliance.configured is False
        assert env.post("volume.set", {"client": DIAL, "args": {"level": 4}})[1]["ok"] is True

    @pytest.mark.parametrize("name", [
        "settings.discard", "settings.apply", "settings.save", "settings.form_apply", "first_boot.commit",
        "backend.setting.set", "align.start", "log.level.set", "input.eq.set", "input.counters.reset",
        "input.playback_config.set", "settings.service_field.set", "outputs.select_default",
        "outputs.deselect_all", "receiver.pause", "outputs.pause_off",
    ])
    def test_a_row_that_is_not_exposed_is_unknown_intent_even_for_an_admin(self, env, spy, name):
        status, body = env.post(name, {"args": {}}, headers=env.browser(authenticated=True))
        assert (status, body["ok"], body["error"]) == (200, False, "unknown_intent")
        assert spy.intents == []

    def test_the_exposed_names_are_the_table_s_exposed_rows(self):
        assert set(autostream_protocol.EXPOSED_INTENTS) == {n for n, r in table.ROWS.items() if r.exposed}


# -----------------------------------------------------------------------------
# Who is asking
# -----------------------------------------------------------------------------

class TestCallers:
    def test_a_browser_without_a_token_is_csrf_stale_with_a_fresh_one(self, env, spy):
        status, body = env.post("volume.set", {"args": {"level": 4}})
        assert (status, body["error"]) == (403, "csrf_stale")
        assert body["csrf_token"]
        assert spy.intents == []

    def test_a_token_in_the_body_is_as_good_as_the_header(self, env, spy):
        headers = env.browser()
        token = headers.pop("X-CSRF-Token")
        _, body = env.post("volume.set", {"args": {"level": 4}, "csrf_token": token}, headers=headers)
        assert body["ok"] is True

    def test_a_browser_with_no_pin_set_is_admin(self, env, spy):
        env.server.auth._pin_value = None
        env.post("dials.revoke", {"args": {"uuid": "u"}}, headers=env.browser(authenticated=False))
        assert spy.intents[0].role is table.Role.ADMIN
        assert (spy.intents[0].origin, spy.intents[0].requester) == (Origin.USER, "webui")

    def test_a_browser_that_signed_in_is_admin_and_one_that_did_not_is_playback(self, env, spy):
        env.server.auth._pin_value = "1234"
        env.server.auth._pin_status = "ok"
        env.post("volume.set", {"args": {"level": 4}}, headers=env.browser(authenticated=True))
        env.post("volume.set", {"args": {"level": 4}}, headers=env.browser(authenticated=False))
        assert [i.role for i in spy.intents] == [table.Role.ADMIN, table.Role.PLAYBACK]

    def test_an_unauthenticated_browser_with_a_pin_set_is_refused_an_admin_row(self, env):
        env.server.auth._pin_value = "1234"
        env.server.auth._pin_status = "ok"
        _, body = env.post("dials.revoke", {"args": {"uuid": "u"}}, headers=env.browser(authenticated=False))
        assert (body["ok"], body["error"]) == (False, "admin_required")

    def test_an_unauthenticated_browser_with_a_pin_set_may_use_a_playback_row(self, env, spy):
        env.server.auth._pin_value = "1234"
        env.server.auth._pin_status = "ok"
        _, body = env.post("volume.set", {"args": {"level": 4}}, headers=env.browser(authenticated=False))
        assert body["ok"] is True

    @pytest.mark.parametrize("client", [DIAL, PEER])
    def test_a_dial_and_a_peer_are_playback_and_named_by_their_requester(self, env, spy, client):
        _, body = env.post("volume.set", {"client": client, "args": {"level": 4}})
        assert body["ok"] is True
        intent = spy.intents[0]
        assert (intent.role, intent.requester, intent.origin) == (table.Role.PLAYBACK, client, Origin.USER)

    @pytest.mark.parametrize("client", [DIAL, PEER])
    def test_a_dial_and_a_peer_are_refused_an_admin_row(self, env, client):
        _, body = env.post("dials.revoke", {"client": client, "args": {"uuid": "u"}})
        assert (body["ok"], body["error"]) == (False, "admin_required")

    def test_an_unauthorised_dial_is_refused_every_row_with_its_reason(self, env, spy):
        env.verdict = dials.AUTH_NOT_AUTHORIZED
        for name in autostream_protocol.EXPOSED_INTENTS + ("settings.discard", "nope"):
            _, body = env.post(name, {"client": DIAL, "args": {}})
            assert (body["ok"], body["error"]) == (False, "dial_not_authorized"), name
        assert spy.intents == []

    def test_a_dial_that_cannot_be_checked_is_auth_unavailable(self, env, spy):
        env.verdict = dials.AUTH_UNAVAILABLE
        assert env.post("volume.set", {"client": DIAL, "args": {"level": 4}})[1]["error"] == "auth_unavailable"

    def test_a_peer_is_refused_when_control_is_off(self, env, spy):
        env.server.hub._peer_control = lambda: False
        assert env.post("volume.set", {"client": PEER, "args": {"level": 4}})[1]["error"] == "control_disabled"
        assert spy.intents == []

    @pytest.mark.parametrize("client", ["dial", "dial:xyz", "bob:0123456789abcdef0123", 7, ["dial:x"]])
    def test_a_malformed_client_is_invalid_client(self, env, spy, client):
        status, body = env.post("volume.set", {"client": client, "args": {"level": 4}})
        assert (status, body["error"]) == (400, "invalid_client")
        assert spy.intents == []

    @pytest.mark.parametrize("client", [DIAL, PEER])
    def test_a_client_together_with_a_session_cookie_is_invalid_client(self, env, spy, client):
        status, body = env.post("volume.set", {"client": client, "args": {"level": 4}},
                                headers=env.browser())
        assert (status, body["error"]) == (400, "invalid_client")
        assert spy.intents == []

    def test_a_named_client_needs_no_csrf_token(self, env, spy):
        assert env.post("volume.set", {"client": DIAL, "args": {"level": 4}})[1]["ok"] is True

    def test_the_dials_rows_refuse_a_uuid_that_is_not_text(self, env):
        _, body = env.post("dials.authorize", {"args": {"uuid": 5, "name": "Kitchen"}}, headers=env.browser())
        assert body["error"] == "invalid_args"
        _, body = env.post("dials.revoke", {"args": {"uuid": ["a"]}}, headers=env.browser())
        assert body["error"] == "invalid_args"


# -----------------------------------------------------------------------------
# The speaker rows
# -----------------------------------------------------------------------------

class TestFilledArguments:
    def test_the_configured_offset_and_mode_reach_the_intent(self, env, spy):
        env.post("outputs.set", {"args": {"id": ID, "selected": True}}, headers=env.browser())
        args = spy.intents[0].args
        assert (args["offset_ms"], args["mode"]) == (120, webui_common.config_airplay_mode_to_backend("airplay2"))

    def test_a_speaker_with_nothing_configured_gets_no_offset(self, env, spy):
        env.post("outputs.set", {"args": {"id": "other", "selected": True}}, headers=env.browser())
        assert "offset_ms" not in spy.intents[0].args

    @pytest.mark.parametrize("name", ["outputs.set", "output.pin.submit"])
    @pytest.mark.parametrize("field,value", [("offset_ms", 5), ("mode", "raop")])
    def test_a_client_offset_or_mode_is_invalid_args(self, env, spy, name, field, value):
        args = {"id": ID, "selected": True, "pin": "1234", field: value}
        if name == "outputs.set":
            args.pop("pin")
        _, body = env.post(name, {"args": args}, headers=env.browser())
        assert body["error"] == "invalid_args"
        assert spy.intents == []

    @pytest.mark.parametrize("name,args", [
        ("volume.step", {"delta": 1}), ("volume.set", {"level": 40}), ("mute.set", {"action": "mute"}),
    ])
    def test_the_default_level_comes_from_the_configuration(self, env, spy, name, args):
        for body in ({"args": args}, {"client": DIAL, "args": args}, {"client": PEER, "args": args}):
            headers = env.browser() if "client" not in body else None
            _, reply = env.post(name, body, headers=headers)
            assert reply["ok"] is True
        assert [i.args["default_level"] for i in spy.intents] == [37, 37, 37]

    @pytest.mark.parametrize("name,args", [
        ("volume.step", {"delta": 1}), ("volume.set", {"level": 40}), ("mute.set", {"action": "mute"}),
    ])
    def test_a_client_default_level_is_invalid_args(self, env, spy, name, args):
        _, body = env.post(name, {"args": {**args, "default_level": 90}}, headers=env.browser())
        assert body["error"] == "invalid_args"
        assert spy.intents == []

    def test_a_configuration_that_cannot_be_read_is_config_error(self, env, spy, monkeypatch):
        def broken(state):
            raise OSError("gone")

        monkeypatch.setattr(webui_common, "_config_snapshot", broken)
        _, body = env.post("volume.set", {"args": {"level": 4}}, headers=env.browser())
        assert body["error"] == "config_error"
        assert spy.intents == []

    def test_the_pin_claimant_is_the_page_for_a_browser_and_a_peer(self, env, spy):
        env.post("outputs.set", {"args": {"id": ID, "selected": True}}, headers=env.browser())
        env.post("outputs.set", {"client": PEER, "args": {"id": ID, "selected": True}})
        assert [i.context for i in spy.intents] == [pairing.REQUESTER_WEBUI, pairing.REQUESTER_WEBUI]

    def test_the_pin_claimant_is_a_dial_only_when_it_has_a_keypad(self, env, spy):
        env.post("outputs.set", {"client": DIAL, "pin_capable": True, "args": {"id": ID, "selected": True}})
        env.post("outputs.set", {"client": DIAL, "args": {"id": ID, "selected": True}})
        env.post("outputs.set", {"client": DIAL, "pin_capable": "yes", "args": {"id": ID, "selected": True}})
        assert [i.context for i in spy.intents] == [DIAL, None, None]

    @pytest.mark.parametrize("name,args", [
        ("volume.set", {"level": 4}),
        ("output.eq.set", {"fields": [["peq1_db", "1"]]}),
        ("output.eq.reset", {}),
    ])
    def test_the_other_rows_carry_no_context(self, env, spy, name, args):
        env.post(name, {"client": DIAL, "pin_capable": True, "args": args})
        assert spy.intents[0].context is None


# -----------------------------------------------------------------------------
# Through the real handlers
# -----------------------------------------------------------------------------

@pytest.fixture
def player(monkeypatch):
    import autostream_player_service as ps

    rec = SimpleNamespace(calls=[], answers=[], default=ActionResult(ok=True))

    def answer():
        return rec.answers.pop(0) if rec.answers else rec.default

    def update_output(base_url, out_id, **kwargs):
        rec.calls.append(("update_output", out_id, kwargs))
        return answer()

    def set_output_muted(base_url, out_id, muted, **kwargs):
        rec.calls.append(("set_output_muted", out_id, muted))
        return answer()

    monkeypatch.setattr(ps, "update_output", update_output)
    monkeypatch.setattr(ps, "set_output_muted", set_output_muted)
    monkeypatch.setattr(ps, "submit_output_pin", lambda *a, **k: answer())
    return rec


def arrange(*rows):
    FakeStore().outputs(list(rows) or [row(ID, "Kitchen")])


def err(code, message="err"):
    return ActionResult(ok=False, error_code=code, error=message)


class TestRealRows:
    def test_a_pin_prompt_claims_for_a_browser(self, env, player):
        arrange()
        player.answers.append(err("pin_required", "needs a PIN"))
        _, body = env.post("outputs.set", {"args": {"id": ID, "selected": True, "name": "Kitchen"}},
                           headers=env.browser())
        assert body["ok"] is False and body["result"]["pin_required"] is True
        assert pairing.holder(ID) == pairing.REQUESTER_WEBUI

    def test_a_pin_prompt_claims_for_a_dial_with_a_keypad(self, env, player):
        arrange()
        player.answers.append(err("pin_required", "needs a PIN"))
        _, body = env.post("outputs.set", {"client": DIAL, "pin_capable": True,
                                           "args": {"id": ID, "selected": True}})
        assert body["result"]["pin_required"] is True
        assert pairing.holder(ID) == DIAL

    def test_a_pin_prompt_claims_for_nobody_from_a_dial_without_one(self, env, player):
        arrange()
        player.answers.append(err("pin_required", "needs a PIN"))
        _, body = env.post("outputs.set", {"client": DIAL, "args": {"id": ID, "selected": True}})
        assert body["result"]["pin_required"] is True
        assert pairing.holder(ID) == ""

    def test_the_configured_offset_and_mode_reach_the_authority(self, env, player):
        arrange()
        _, body = env.post("outputs.set", {"args": {"id": ID, "selected": True, "volume": 30}},
                           headers=env.browser())
        assert body["ok"] is True
        sent = [kw for _n, _i, kw in player.calls if kw.get("enabled")]
        assert sent and sent[0].get("offset_ms") == 120

    def test_volume_set_uses_the_configured_default_level_and_reports_the_master(self, env, player):
        arrange(row(ID, "Kitchen", selected=True, volume_percent=40),
                row("43", "Lounge", selected=True, volume_percent=60))
        for headers, extra in ((env.browser(), {}), (None, {"client": DIAL}), (None, {"client": PEER})):
            _, body = env.post("volume.set", {"args": {"level": 50}, **extra}, headers=headers)
            assert body["ok"] is True and body["result"]["volume"] == 50
        assert snap().master_volume == 50

    def test_volume_set_refuses_a_level_out_of_range(self, env, player):
        arrange(row(ID, "Kitchen", selected=True, volume_percent=40))
        _, body = env.post("volume.set", {"args": {"level": 101}}, headers=env.browser())
        assert (body["ok"], body["error"]) == (False, "invalid_level")

    def test_volume_step_and_mute_work_from_every_kind_of_caller(self, env, player):
        arrange(row(ID, "Kitchen", selected=True, volume_percent=40))
        for headers, extra in ((env.browser(), {}), (None, {"client": DIAL}), (None, {"client": PEER})):
            assert env.post("volume.step", {"args": {"delta": 2}, **extra}, headers=headers)[1]["ok"] is True
            assert env.post("mute.set", {"args": {"action": "mute"}, **extra}, headers=headers)[1]["ok"] is True
            assert env.post("mute.set", {"args": {"action": "restore"}, **extra}, headers=headers)[1]["ok"] is True

    def test_the_placeholder_card_is_want_default_on_the_new_and_the_old_route(self, env, player):
        arrange(row("1", "Other"))
        get_authority().set_default_members([("", "Lounge", 30)], 30)
        placeholder = snap().default_members[0].unit_id
        assert placeholder
        _, body = env.post("outputs.set", {"args": {"id": placeholder, "selected": False}},
                           headers=env.browser())
        assert (body["ok"], body["result"]) == (True, {"ok": True})
        assert snap().silence_chosen is True
        assert player.calls == []
        old = home_model.submit_output_change(
            {"id": placeholder, "selected": True}, requester="webui", pin_requester=pairing.REQUESTER_WEBUI)
        assert old == {"ok": True}
        assert snap().silence_chosen is False

    def test_a_dials_authorize_through_the_route(self, env, monkeypatch):
        written = []
        monkeypatch.setattr(autostream_appliance_state, "write_dial_entry", lambda u, n: written.append((u, n)))
        _, body = env.post("dials.authorize", {"args": {"uuid": "d1", "name": "Kitchen"}}, headers=env.browser())
        assert body["ok"] is True and written == [("d1", "Kitchen")]


@pytest.fixture
def eq_store(tmp_path):
    path = tmp_path / "autostream.json"
    path.write_text(json.dumps({"output_eq": {}}), encoding="utf-8")
    s = SettingsStore(str(path), _save_interval_seconds=9999, _writer=MagicMock())
    live_config.bind_settings_store(s)
    yield s
    live_config.bind_settings_store(None)
    s.close(save=False)


@pytest.fixture
def monitor():
    client = MagicMock()
    for name in ("set_output_eq", "set_output_gain", "set_output_auto_trim"):
        getattr(client, name).return_value = True

    @contextlib.contextmanager
    def connected(path=None):
        yield client

    with patch("autostream_monitor_client._connected_monitor", connected):
        yield client


class TestEqualiserRows:
    def test_an_equaliser_field_from_the_page_is_saved_and_applied(self, env, eq_store, monitor):
        _, body = env.post("output.eq.set", {"args": {"fields": [["peq2_db", "3"]]}},
                           headers=env.browser())
        assert body["ok"] is True
        assert body["result"] == {"ok": True, "field": "peq2_db", "value": "3.0", "error": ""}
        assert eq_store.snapshot().output_eq.peq2_db == 3.0
        monitor.set_output_eq.assert_called_once()

    def test_a_dial_s_bass_write_is_one_merged_band_write(self, env, eq_store, monitor):
        _, body = env.post("output.eq.set", {"client": DIAL, "args": {
            "fields": [["peq1_db", 6.0], ["peq2_db", 6.0]]}})
        assert body["ok"] is True
        assert body["result"] == {"ok": True, "error": ""}
        saved = eq_store.snapshot().output_eq
        assert (saved.peq1_db, saved.peq2_db) == (6.0, 6.0)
        monitor.set_output_eq.assert_called_once()

    def test_an_equaliser_reset_zeroes_the_bands_from_the_page_and_a_dial(self, env, eq_store, monitor):
        for headers, extra in ((env.browser(), {}), (None, {"client": DIAL})):
            eq_store.update(lambda raw: raw.setdefault("output_eq", {}).update(
                {"peq1_db": 4.0, "gain_db": 2.0}))
            _, body = env.post("output.eq.reset", {"args": {}, **extra}, headers=headers)
            assert body["ok"] is True and body["result"] == {"ok": True, "error": ""}
            saved = eq_store.snapshot().output_eq
            assert [getattr(saved, f"peq{n}_db") for n in range(1, 7)] == [0.0] * 6
            assert saved.gain_db == 2.0
        monitor.set_output_gain.assert_not_called()

    def test_an_equaliser_change_without_a_store_is_refused(self, env, monitor):
        _, body = env.post("output.eq.set", {"args": {"fields": [["peq2_db", "3"]]}},
                           headers=env.browser())
        assert body["ok"] is False and body["error"] == "settings_unavailable"
        monitor.set_output_eq.assert_not_called()


# -----------------------------------------------------------------------------
# Refusals that arrive after the reply
# -----------------------------------------------------------------------------

def wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


@pytest.fixture
def slow(env, started_authority, monkeypatch):
    """A running authority whose write waits on a gate, and a short wait on
    the speaker rows so the reply goes out as pending."""
    a = started_authority
    fb = FakeBackend(a)
    fb.rows = [row(ID, "Kitchen")]
    a.start(fb)
    assert wait_for(lambda: not a._dirty)
    with a._lock:
        pass
    a.merge_for_tests(fb.rows, boot="b0")
    fb.gate = threading.Event()
    for name in ("outputs.set", "output.pin.submit", "volume.step", "volume.set", "mute.set"):
        monkeypatch.setitem(table.ROWS, name, dataclasses.replace(table.ROWS[name], wait=0.05))
    yield SimpleNamespace(a=a, fb=fb)
    fb.gate.set()


class TestLateRefusals:
    def start(self, env, slow, code, **fields):
        slow.fb.results.append(err(code, "late"))
        _, body = env.post("outputs.set", {"client": DIAL, "pin_capable": True,
                                           "args": {"id": ID, "selected": True, "volume": 30}})
        assert body["ok"] is True and body["result"] == {"ok": True, "id": ID}
        slow.fb.gate.set()

    def test_pin_required_reaches_the_unit_and_the_start_failure(self, env, slow):
        self.start(env, slow, "pin_required")
        assert wait_for(lambda: snap().start_failure is not None)
        failure = snap().start_failure
        assert failure.reason == "pin_required" and failure.requester == DIAL
        assert snap().unit(ID).availability == "password"
        assert wait_for(lambda: pairing.holder(ID) == DIAL)

    def test_pin_invalid_reaches_the_start_failure(self, env, slow):
        self.start(env, slow, "pin_invalid")
        assert wait_for(lambda: snap().start_failure is not None)
        assert snap().start_failure.reason == "pin_invalid"

    def test_encoder_capacity_reaches_the_start_failure_and_the_select_is_reverted(self, env, slow):
        self.start(env, slow, "encoder_capacity")
        assert wait_for(lambda: snap().start_failure is not None)
        assert snap().start_failure.reason == "encoder_capacity"
        assert wait_for(lambda: snap().unit(ID).selected is False)

    def test_a_player_refusal_reaches_the_start_failure(self, env, slow):
        self.start(env, slow, "request_failed")
        assert wait_for(lambda: snap().start_failure is not None)
        assert snap().start_failure.reason == "refused"

    def test_a_timeout_shows_the_unit_starting_then_timed_out(self, env, slow):
        self.start(env, slow, "timeout")
        assert wait_for(lambda: snap().unit(ID).availability == "starting")
        assert snap().start_failure is None
        slow.a._run_timers(slow.a._clock() + START_PENDING_S + 5.0)
        assert wait_for(lambda: snap().start_failure is not None)
        assert snap().start_failure.reason == "timed_out"

    def test_a_group_that_is_not_present_shows_the_unit_starting_then_failed(self, env, slow):
        slow.fb.rows = [group_row(ID, "stopped", name="Kitchen")]
        slow.a.merge_for_tests(slow.fb.rows, boot="b0")
        self.start(env, slow, "group_not_present")
        assert wait_for(lambda: snap().unit(ID).availability == "starting")
        slow.a.merge_for_tests([group_row(ID, "failed", name="Kitchen", selected=True)], boot="b0")
        assert wait_for(lambda: snap().start_failure is not None)
        assert snap().start_failure.reason == "failed"

    def test_all_outputs_failed_on_a_volume_change_is_not_in_a_part(self, env, slow):
        slow.fb.gate.set()
        slow.a.select(ID, Origin.USER, volume=40).outcome.result(timeout=5)
        slow.fb.gate = threading.Event()
        slow.fb.results.append(err("request_failed"))
        _, body = env.post("volume.set", {"client": DIAL, "args": {"level": 70}})
        assert body["ok"] is True, body
        slow.fb.gate.set()
        assert wait_for(lambda: any(c[0] == "update_output" for c in slow.fb.calls))
        time.sleep(0.2)
        assert snap().start_failure is None
