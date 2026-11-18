"""tests/test_state_live.py

The live reads that go to the monitor daemon on the caller's thread: what they
return when it is absent, what they pass on from its status, and that a raising
client is logged and answered with the fallback.
"""
from __future__ import annotations

import logging
import sys
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_monitor_client as monitor_client
from autostream_state import live


def _connected(client):
    @contextmanager
    def _cm(*args, **kwargs):
        yield client
    return _cm


def _client(status):
    client = MagicMock()
    client.get_status.return_value = status
    return client


def _with(client):
    return patch.object(monitor_client, "_connected_monitor", _connected(client))


class TestOutputEqStatus:
    def test_no_daemon_gives_none(self):
        with _with(None):
            assert live.get_live_output_eq_status() is None

    def test_an_empty_status_gives_none(self):
        with _with(_client({})):
            assert live.get_live_output_eq_status() is None

    def test_the_three_fields_are_passed_on(self):
        status = {
            "output_auto_trim_enabled": 1,
            "output_auto_trim_db": "-1.5",
            "effective_output_gain_db": -2,
            "output_rate": 48000,
        }
        with _with(_client(status)):
            assert live.get_live_output_eq_status() == {
                "output_auto_trim_enabled": True,
                "output_auto_trim_db": -1.5,
                "effective_output_gain_db": -2.0,
            }

    def test_missing_fields_take_their_defaults(self):
        with _with(_client({"output_rate": 48000})):
            assert live.get_live_output_eq_status() == {
                "output_auto_trim_enabled": False,
                "output_auto_trim_db": 0.0,
                "effective_output_gain_db": 0.0,
            }

    def test_the_socket_path_reaches_the_connection(self):
        seen = []

        @contextmanager
        def cm(path=None):
            seen.append(path)
            yield None

        with patch.object(monitor_client, "_connected_monitor", cm):
            live.get_live_output_eq_status("/run/x.sock")
        assert seen == ["/run/x.sock"]

    def test_a_raising_client_logs_one_warning_and_gives_none(self, caplog):
        client = MagicMock()
        client.get_status.side_effect = OSError("gone")
        with _with(client), caplog.at_level(logging.WARNING):
            assert live.get_live_output_eq_status() is None
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1


class TestMonitorOutputRate:
    def test_no_daemon_gives_the_fallback(self):
        with _with(None):
            assert live.get_live_monitor_output_rate() == 48000
            assert live.get_live_monitor_output_rate(fallback=44100) == 44100

    def test_an_empty_status_gives_the_fallback(self):
        with _with(_client({})):
            assert live.get_live_monitor_output_rate(fallback=44100) == 44100

    def test_the_reported_rate_is_returned_as_an_int(self):
        with _with(_client({"output_rate": 96000})):
            assert live.get_live_monitor_output_rate() == 96000
        with _with(_client({"output_rate": 44100.0})):
            assert live.get_live_monitor_output_rate() == 44100

    @pytest.mark.parametrize("rate", [True, "48000", None, 0, -1, -48000.0])
    def test_a_rate_that_is_not_a_positive_number_gives_the_fallback(self, rate):
        with _with(_client({"output_rate": rate})):
            assert live.get_live_monitor_output_rate(fallback=44100) == 44100

    def test_a_raising_client_logs_one_warning_and_gives_the_fallback(self, caplog):
        client = MagicMock()
        client.get_status.side_effect = OSError("gone")
        with _with(client), caplog.at_level(logging.WARNING):
            assert live.get_live_monitor_output_rate(fallback=44100) == 44100
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1


class TestPlayerReads:
    def test_get_setting_passes_its_arguments_and_timeout_on(self):
        with patch("autostream_player_service.get_setting", return_value="reply") as src:
            assert live.get_setting("http://p", "key", timeout=1) == "reply"
        src.assert_called_once_with("http://p", "key", timeout=1)

    def test_get_setting_default_timeout_is_the_players(self):
        with patch("autostream_player_service.get_setting") as src:
            live.get_setting("http://p", "key")
        src.assert_called_once_with("http://p", "key", timeout=3.0)

    def test_get_capabilities_passes_its_arguments_and_timeout_on(self):
        with patch("autostream_player_service.get_capabilities", return_value="caps") as src:
            assert live.get_capabilities("http://p", timeout=2) == "caps"
        src.assert_called_once_with("http://p", timeout=2)

    def test_list_outputs_passes_its_arguments_and_timeout_on(self):
        with patch("autostream_player_service.list_outputs", return_value="rows") as src:
            assert live.list_outputs("http://p", timeout=1) == "rows"
        src.assert_called_once_with("http://p", timeout=1)

    def test_get_owntone_runtime_info_passes_its_arguments_on(self):
        with patch("autostream_player_service.get_owntone_runtime_info", return_value="info") as src:
            assert live.get_owntone_runtime_info(refresh_if_stale=False) == "info"
            live.get_owntone_runtime_info("http://p", timeout=1)
        assert src.call_args_list[0].args == ("",)
        assert src.call_args_list[0].kwargs == {"timeout": 3.0, "refresh_if_stale": False}
        assert src.call_args_list[1].args == ("http://p",)
        assert src.call_args_list[1].kwargs == {"timeout": 1, "refresh_if_stale": True}

    def test_get_vibra_runtime_info_reads_the_shared_client(self):
        with patch("track_id.vibra_shazam.get_vibra_runtime_info", return_value="v") as src:
            assert live.get_vibra_runtime_info() == "v"
        src.assert_called_once_with()


class TestBoundReads:
    def test_an_unbound_name_raises(self):
        with patch.dict(live._bound, clear=True):
            with pytest.raises(live.LiveNotBound):
                live.get_align_status()
            with pytest.raises(live.LiveNotBound):
                live.get_log_level_state("c.ini")

    def test_a_bound_read_passes_its_arguments_on(self):
        calls = []
        with patch.dict(live._bound, clear=True):
            live.bind("get_align_review", lambda: calls.append("read") or ["x"], owner="m")
            live.bind("get_log_level_state", lambda *a, **k: (a, k), owner="m")
            assert live.get_align_review() == ["x"]
            assert live.get_log_level_state("c.ini", settings="s") == (("c.ini",), {"settings": "s"})
        assert calls == ["read"]

    def test_a_second_owner_raises_and_the_first_keeps_the_name(self):
        with patch.dict(live._bound, clear=True):
            live.bind("get_align_status", lambda: "first", owner="one")
            with pytest.raises(ValueError):
                live.bind("get_align_status", lambda: "second", owner="two")
            assert live.get_align_status() == "first"
            assert live.bound_owner("get_align_status") == "one"

    def test_the_same_owner_may_bind_again(self):
        with patch.dict(live._bound, clear=True):
            live.bind("get_align_status", lambda: "first", owner="one")
            live.bind("get_align_status", lambda: "second", owner="one")
            assert live.get_align_status() == "second"

    def test_an_unknown_name_cannot_be_bound(self):
        with pytest.raises(ValueError):
            live.bind("get_setting", lambda *a: None, owner="m")

    def test_every_bindable_name_is_bound_once_the_coordinator_is_imported(self):
        import autostream_core  # noqa: F401
        for name in live.BINDABLE:
            assert live.bound_owner(name) is not None, name

    def test_the_bound_reads_reach_the_replaced_function_of_their_owner(self):
        import autostream_core  # noqa: F401
        with patch("autostream_align._RUN") as run:
            run.status.return_value = {"state": "patched"}
            assert live.get_align_status() == {"state": "patched"}
        with patch("autostream_log_policy.get_log_level_state", return_value={"ok": True}):
            assert live.get_log_level_state("c.ini") == {"ok": True}


class TestPinClaimRead:
    def test_pin_claim_returns_the_holder_of_a_claim(self):
        import autostream_pin_pairing as pairing
        fresh = pairing.PairingState(clock=lambda: 100.0)
        with patch.object(pairing, "STATE", fresh):
            assert live.pin_claim("o1") == ""
            pairing.claim("o1", "dial:abc")
            assert live.pin_claim("o1") == "dial:abc"
            assert live.pin_claim("o2") == ""
