"""Auth-changed push tests: notify_dial_auth_changed and its worker.

Covers:
1.  handle_dial_authorize_post / handle_dial_revoke_post call
    notify_dial_auth_changed(uuid) after their 200 response is sent.
2.  _push_once skips silently when the uuid has no current sighting.
3.  _push_once POSTs {"appliance_id": id} to the sighting's own
    ip:port at the path it is given (/auth-changed for this push).
4.  A failed first attempt is retried once after a delay.
5.  Nothing here ever raises (connection refusal, timeout, malformed peer).
6.  notify_dial_auth_changed is a no-op when this appliance has no identity,
    and otherwise queues one /auth-changed job on the shared push worker.

The push is best-effort and advisory only (it grants nothing; it only
causes the dial to poll), so every failure mode is "log and move on".
"""
from __future__ import annotations

import json as _json
import sys
from pathlib import Path
from unittest.mock import ANY, MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_dials import DialSighting
from webui.dial.management import handle_dial_revoke_post
from webui.dial.management import handle_dial_authorize_post
from autostream_dial_push import _PUSH_RETRY_DELAY_S
from autostream_dial_push import _PUSH_TIMEOUT_S
from autostream_dial_push import notify_dial_auth_changed
from autostream_dial_push import _push_once
from autostream_dial_push import _post_push

UUID = "dial-uuid-push-1"
APPLIANCE_ID = "aaaaaaaaaaaaaaaaaaaa"


def _sighting(ip="192.168.1.50", port=7842) -> DialSighting:
    return DialSighting(uuid=UUID, name="Test Dial", version="1.0.0",
                        ip=ip, port=port, pin_recovery=False)


# ---------------------------------------------------------------------------
# Call sites: authorize / revoke write, push, then reply
# ---------------------------------------------------------------------------

def _recorder():
    calls = []

    def send_json(handler, code, body):
        calls.append(("send_json", code, dict(body)))

    return calls, send_json


def _submitted(calls_out):
    """Capture the intents the routes submit, passing them through."""
    from autostream_intents import submit as real_submit

    def spy(intent):
        calls_out.append(intent)
        return real_submit(intent)

    return spy


class TestCallSites:
    def test_authorize_pushes_after_the_write_and_replies_after_both(self):
        calls, fake_send_json = _recorder()
        with (
            patch("webui.common.send_json", side_effect=fake_send_json),
            patch("autostream_dial_push.write_dial_entry",
                  side_effect=lambda u, n: calls.append(("write", u, n))),
            patch("autostream_dial_push.validate_dial_name", return_value=True),
            patch("autostream_dial_push.notify_dial_auth_changed",
                  side_effect=lambda u: calls.append(("notify", u))),
        ):
            handle_dial_authorize_post(MagicMock(), {"uuid": UUID, "name": "Kitchen"})

        assert calls == [("write", UUID, "Kitchen"), ("notify", UUID),
                         ("send_json", 200, {"ok": True})]

    def test_revoke_pushes_after_the_removal_and_replies_after_both(self):
        calls, fake_send_json = _recorder()
        with (
            patch("webui.common.send_json", side_effect=fake_send_json),
            patch("autostream_dial_push.remove_dial_entry",
                  side_effect=lambda u: calls.append(("remove", u))),
            patch("autostream_dial_push.notify_dial_auth_changed",
                  side_effect=lambda u: calls.append(("notify", u))),
        ):
            handle_dial_revoke_post(MagicMock(), {"uuid": UUID})

        assert calls == [("remove", UUID), ("notify", UUID),
                         ("send_json", 200, {"ok": True})]

    def test_authorize_response_not_delayed_by_notify_failure(self):
        """A thread-creation (or any other) failure inside notify_dial_auth_changed
        must never turn a successful authorize into an error: the handler
        wraps the call in try/except."""
        with (
            patch("webui.common.send_json") as mock_send_json,
            patch("autostream_dial_push.write_dial_entry"),
            patch("autostream_dial_push.validate_dial_name", return_value=True),
            patch("autostream_dial_push.notify_dial_auth_changed",
                  side_effect=RuntimeError("boom")),
        ):
            handle_dial_authorize_post(MagicMock(), {"uuid": UUID, "name": "Kitchen"})

        mock_send_json.assert_called_once_with(ANY, 200, {"ok": True})

    def test_revoke_response_not_delayed_by_notify_failure(self):
        with (
            patch("webui.common.send_json") as mock_send_json,
            patch("autostream_dial_push.remove_dial_entry"),
            patch("autostream_dial_push.notify_dial_auth_changed",
                  side_effect=RuntimeError("boom")),
        ):
            handle_dial_revoke_post(MagicMock(), {"uuid": UUID})

        mock_send_json.assert_called_once_with(ANY, 200, {"ok": True})

    def test_an_invalid_name_answers_400_and_writes_and_queues_nothing(self):
        with (
            patch("webui.common.send_json") as mock_send_json,
            patch("autostream_dial_push.write_dial_entry") as write,
            patch("autostream_dial_push.notify_dial_auth_changed") as notify,
        ):
            handle_dial_authorize_post(MagicMock(), {"uuid": UUID, "name": "bad;name"})

        mock_send_json.assert_called_once_with(ANY, 400, {"ok": False, "error": "invalid_name"})
        write.assert_not_called()
        notify.assert_not_called()

    def test_the_other_refusals_keep_their_bodies(self):
        with patch("webui.common.send_json") as mock_send_json:
            handle_dial_authorize_post(MagicMock(), {"name": "Kitchen"})
            handle_dial_authorize_post(MagicMock(), {"uuid": UUID})
            handle_dial_revoke_post(MagicMock(), {"uuid": ""})
        assert [c.args[1:] for c in mock_send_json.call_args_list] == [
            (400, {"ok": False, "error": "missing_uuid"}),
            (400, {"ok": False, "error": "missing_name"}),
            (400, {"ok": False, "error": "missing_uuid"}),
        ]

    def test_a_raising_write_answers_500_and_queues_no_push(self):
        with (
            patch("webui.common.send_json") as mock_send_json,
            patch("autostream_dial_push.write_dial_entry", side_effect=OSError("read-only")),
            patch("autostream_dial_push.validate_dial_name", return_value=True),
            patch("autostream_dial_push.notify_dial_auth_changed") as notify,
        ):
            handle_dial_authorize_post(MagicMock(), {"uuid": UUID, "name": "Kitchen"})
        mock_send_json.assert_called_once_with(ANY, 500, {"ok": False, "error": "internal_error"})
        notify.assert_not_called()

    def test_a_raising_removal_answers_500_and_queues_no_push(self):
        with (
            patch("webui.common.send_json") as mock_send_json,
            patch("autostream_dial_push.remove_dial_entry", side_effect=OSError("read-only")),
            patch("autostream_dial_push.notify_dial_auth_changed") as notify,
        ):
            handle_dial_revoke_post(MagicMock(), {"uuid": UUID})
        mock_send_json.assert_called_once_with(ANY, 500, {"ok": False, "error": "internal_error"})
        notify.assert_not_called()

    def test_the_intents_are_the_users_and_carry_the_strings_unstripped(self):
        from autostream_state import Origin
        seen = []
        with (
            patch("webui.dial.management.submit", side_effect=_submitted(seen)),
            patch("webui.common.send_json"),
            patch("autostream_dial_push.write_dial_entry") as write,
            patch("autostream_dial_push.validate_dial_name", return_value=True),
            patch("autostream_dial_push.remove_dial_entry"),
            patch("autostream_dial_push.notify_dial_auth_changed"),
        ):
            handle_dial_authorize_post(MagicMock(), {"uuid": " " + UUID, "name": " Kitchen "})
            handle_dial_revoke_post(MagicMock(), {"uuid": UUID})
        assert [(i.name, i.origin, i.requester) for i in seen] == [
            ("dials.authorize", Origin.USER, "webui"),
            ("dials.revoke", Origin.USER, "webui"),
        ]
        write.assert_called_once_with(" " + UUID, " Kitchen ")


# ---------------------------------------------------------------------------
# notify_dial_auth_changed: identity gate and thread hand-off
# ---------------------------------------------------------------------------

class TestNotifyDialAuthChanged:
    def test_no_op_when_appliance_has_no_identity(self):
        with (
            patch("autostream_rpi.get_appliance_id", return_value=None),
            patch("autostream_dial_push.enqueue_push") as mock_enqueue,
        ):
            notify_dial_auth_changed(UUID)
        mock_enqueue.assert_not_called()

    def test_queues_one_auth_changed_job_when_identified(self):
        with (
            patch("autostream_rpi.get_appliance_id", return_value=APPLIANCE_ID),
            patch("autostream_dial_push.enqueue_push") as mock_enqueue,
        ):
            notify_dial_auth_changed(UUID)
        mock_enqueue.assert_called_once_with("/auth-changed", UUID, APPLIANCE_ID)


# ---------------------------------------------------------------------------
# _push_once: sighting lookup, retry
# ---------------------------------------------------------------------------

class TestPushOnce:
    def test_skips_silently_when_not_sighted(self):
        with (
            patch("autostream_dial_push.get_dial_sighting", return_value=None),
            patch("autostream_dial_push._post_push") as mock_post,
        ):
            _push_once("/auth-changed", UUID, APPLIANCE_ID)
        mock_post.assert_not_called()

    def test_single_success_does_not_retry(self):
        with (
            patch("autostream_dial_push.get_dial_sighting", return_value=_sighting()),
            patch("autostream_dial_push._post_push", return_value=True) as mock_post,
            patch("autostream_dial_push.time.sleep") as mock_sleep,
        ):
            _push_once("/auth-changed", UUID, APPLIANCE_ID)
        mock_post.assert_called_once()
        mock_sleep.assert_not_called()

    def test_failure_retries_once_after_delay(self):
        with (
            patch("autostream_dial_push.get_dial_sighting", return_value=_sighting()),
            patch("autostream_dial_push._post_push",
                  side_effect=[False, True]) as mock_post,
            patch("autostream_dial_push.time.sleep") as mock_sleep,
        ):
            _push_once("/auth-changed", UUID, APPLIANCE_ID)
        assert mock_post.call_count == 2
        mock_sleep.assert_called_once_with(_PUSH_RETRY_DELAY_S)

    def test_both_attempts_use_the_sighting_address(self):
        sighting = _sighting(ip="10.0.0.9", port=7842)
        with (
            patch("autostream_dial_push.get_dial_sighting", return_value=sighting),
            patch("autostream_dial_push._post_push",
                  side_effect=[False, False]) as mock_post,
            patch("autostream_dial_push.time.sleep"),
        ):
            _push_once("/auth-changed", UUID, APPLIANCE_ID)
        for call in mock_post.call_args_list:
            args = call[0]
            assert args[0] == "10.0.0.9"
            assert args[1] == 7842
            assert args[2] == "/auth-changed"
            assert args[3] == APPLIANCE_ID
            assert args[4] == _PUSH_TIMEOUT_S


# ---------------------------------------------------------------------------
# _post_push: wire format and failure containment
# ---------------------------------------------------------------------------

class TestPostPush:
    def test_posts_appliance_id_body_to_auth_changed_path(self):
        conn = MagicMock()
        resp = MagicMock()
        resp.status = 202
        conn.getresponse.return_value = resp

        with patch("autostream_dial_push.http.client.HTTPConnection",
                   return_value=conn):
            result = _post_push("192.168.1.50", 7842, "/auth-changed", APPLIANCE_ID,
                                        _PUSH_TIMEOUT_S)

        assert result is True
        method, path = conn.request.call_args[0][:2]
        assert method == "POST"
        assert path == "/auth-changed"
        sent_body = conn.request.call_args.kwargs.get("body")
        if sent_body is None:
            sent_body = conn.request.call_args[0][2]
        assert _json.loads(sent_body) == {"appliance_id": APPLIANCE_ID}
        headers = conn.request.call_args.kwargs.get("headers", {})
        assert headers.get("Content-Type") == "application/json"

    def test_non_2xx_status_returns_false(self):
        conn = MagicMock()
        resp = MagicMock()
        resp.status = 404
        conn.getresponse.return_value = resp

        with patch("autostream_dial_push.http.client.HTTPConnection",
                   return_value=conn):
            result = _post_push("192.168.1.50", 7842, "/auth-changed", APPLIANCE_ID,
                                        _PUSH_TIMEOUT_S)

        assert result is False

    def test_connection_refused_never_raises(self):
        with patch("autostream_dial_push.http.client.HTTPConnection",
                   side_effect=ConnectionRefusedError("refused")):
            result = _post_push("192.168.1.50", 7842, "/auth-changed", APPLIANCE_ID,
                                        _PUSH_TIMEOUT_S)
        assert result is False

    def test_timeout_never_raises(self):
        conn = MagicMock()
        conn.request.side_effect = TimeoutError("timed out")

        with patch("autostream_dial_push.http.client.HTTPConnection",
                   return_value=conn):
            result = _post_push("192.168.1.50", 7842, "/auth-changed", APPLIANCE_ID,
                                        _PUSH_TIMEOUT_S)
        assert result is False

    def test_connection_is_always_closed(self):
        conn = MagicMock()
        resp = MagicMock()
        resp.status = 202
        conn.getresponse.return_value = resp

        with patch("autostream_dial_push.http.client.HTTPConnection",
                   return_value=conn):
            _post_push("192.168.1.50", 7842, "/auth-changed", APPLIANCE_ID, _PUSH_TIMEOUT_S)

        conn.close.assert_called_once()
