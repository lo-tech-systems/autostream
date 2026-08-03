"""tests/test_input1_optional_startup.py

Daemon startup gating for an optional input 1 (audio1.enabled).

Covers:
  - _configure_startup_monitors skips configure/start/monitor for input 1
    when audio1.enabled is False, mirroring input 2's existing optional
    branch.
  - Input 2 still starts normally when enabled, independent of input 1.
  - The daemon can start with zero configured inputs (both disabled) and
    _configure_startup_monitors returns an empty list rather than None or
    raising.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from autostream_config import parse_config


def _cfg(data: dict):
    return parse_config(data)


def _mock_client() -> MagicMock:
    client = MagicMock()
    client.set_log_level.return_value = True
    client.configure_input.return_value = True
    client.start_input.return_value = True
    client.set_gain.return_value = True
    client.set_eq.return_value = True
    client.set_allow_capture.return_value = True
    client.stop_input.return_value = True
    return client


class TestInput1DisabledStartup:
    def test_skips_configure_and_start_for_input_1(self):
        from autostream_core import _configure_startup_monitors
        cfg = _cfg({
            "audio1": {"enabled": False},
            "owntone": {"output_name": "Kitchen"},
        })
        client = _mock_client()
        monitors = _configure_startup_monitors(client, cfg, "/tmp/autostream.fifo")

        assert monitors == []
        for call in client.configure_input.call_args_list:
            assert call.args[0] != 1
        for call in client.start_input.call_args_list:
            assert call.args[0] != 1

    def test_input_2_still_starts_when_enabled_and_input_1_disabled(self):
        from autostream_core import _configure_startup_monitors
        cfg = _cfg({
            "audio1": {"enabled": False},
            "audio2": {"enabled": True, "capture_device": "hw:1,0"},
            "owntone": {"output_name": "Kitchen"},
        })
        client = _mock_client()
        monitors = _configure_startup_monitors(client, cfg, "/tmp/autostream.fifo")

        assert monitors is not None
        assert [m.input_index for m in monitors] == [2]
        client.configure_input.assert_any_call(
            2,
            "hw:1,0",
            cfg.audio2.silence_threshold_dbfs,
            cfg.general.silence_seconds,
            cfg.track_identification.track_change_silence_seconds,
            cfg.general.minimum_playback_seconds,
        )

    def test_zero_inputs_returns_empty_list_not_none(self):
        from autostream_core import _configure_startup_monitors
        cfg = _cfg({
            "audio1": {"enabled": False},
            "owntone": {"output_name": "Kitchen"},
        })
        client = _mock_client()
        monitors = _configure_startup_monitors(client, cfg, "/tmp/autostream.fifo")
        assert monitors == []
        assert monitors is not None

    def test_input_1_enabled_by_default_still_configures(self):
        """Absent audio1.enabled defaults True -- existing single-input
        deployments behave identically to before this flag existed."""
        from autostream_core import _configure_startup_monitors
        cfg = _cfg({
            "audio1": {"capture_device": "hw:0,0"},
            "owntone": {"output_name": "Kitchen"},
        })
        client = _mock_client()
        monitors = _configure_startup_monitors(client, cfg, "/tmp/autostream.fifo")

        assert [m.input_index for m in monitors] == [1]
        client.configure_input.assert_any_call(
            1,
            "hw:0,0",
            cfg.audio1.silence_threshold_dbfs,
            cfg.general.silence_seconds,
            cfg.track_identification.track_change_silence_seconds,
            cfg.general.minimum_playback_seconds,
        )
