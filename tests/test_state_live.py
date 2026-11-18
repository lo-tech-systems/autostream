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
