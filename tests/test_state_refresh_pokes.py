"""tests/test_state_refresh_pokes.py

The places that ask the appliance-state worker to look again: a hostname
change, a PIN change, and the Service-page counter and config intents. Each
makes one live.state_refresh() call; with no worker running the call is a
no-op.
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_state import live


def _handler(host="autostream.local"):
    h = MagicMock()
    h.wfile = io.BytesIO()
    h.headers = {"Host": host}
    return h


class TestUnbound:
    def test_a_poke_with_no_worker_is_a_no_op(self):
        with patch.dict(live._bound, clear=True):
            live.state_refresh()


class TestHostname:
    def _send(self, hostname_result):
        from webui.browser import api_settings
        with patch.object(api_settings, "get_system_hostname", return_value="old"), \
             patch.object(api_settings, "set_system_hostname", **hostname_result), \
             patch.object(api_settings, "state_refresh") as poke:
            api_settings.send_hostname_post_json(
                _handler(), MagicMock(), json.dumps({"value": "new"}))
        return poke

    def test_a_changed_hostname_pokes(self):
        self._send({}).assert_called_once_with()

    def test_a_failed_change_does_not(self):
        self._send({"side_effect": OSError("denied")}).assert_not_called()


class TestPinChange:
    def test_the_route_pokes_after_the_change(self):
        from webui.browser import auth
        order = []
        with patch.object(auth.session_state, "AUTH") as session_auth, \
             patch.object(auth, "state_refresh", side_effect=lambda: order.append("poke")):
            session_auth.handle_pin_change.side_effect = lambda *a: order.append("change")
            auth._route_post_pin_change(_handler(), None, "{}")
        assert order == ["change", "poke"]


class TestServiceIntents:
    def test_a_counter_reset_that_applied_pokes(self):
        import autostream_playback_tracking as tracking
        from autostream_intents import Intent, Origin
        result = MagicMock(applied=True)
        with patch.object(tracking, "reset_input_stylus", return_value=result), \
             patch.object(tracking.live, "state_refresh") as poke, \
             patch.object(tracking.dial_warnings, "poke"):
            tracking._counters_reset(
                Intent("input.counters.reset", {"item": "stylus", "input": 1}, Origin.USER, "webui"),
                0.0)
        poke.assert_called_once_with()

    def test_a_counter_reset_that_did_not_apply_does_not(self):
        import autostream_playback_tracking as tracking
        from autostream_intents import Intent, Origin
        with patch.object(tracking, "reset_input_stylus", return_value=MagicMock(applied=False)), \
             patch.object(tracking.live, "state_refresh") as poke, \
             patch.object(tracking.dial_warnings, "poke"):
            tracking._counters_reset(
                Intent("input.counters.reset", {"item": "stylus", "input": 1}, Origin.USER, "webui"),
                0.0)
        poke.assert_not_called()

    def test_a_playback_config_change_pokes(self):
        import autostream_playback_tracking as tracking
        from autostream_intents import Intent, Origin
        with patch.object(tracking, "update_playback_input_config", return_value=True), \
             patch.object(tracking.live, "state_refresh") as poke, \
             patch.object(tracking.dial_warnings, "poke"):
            tracking._playback_config_set(
                Intent("input.playback_config.set", {"input": 1, "enabled": False},
                       Origin.USER, "webui"), 0.0)
        poke.assert_called_once_with()
