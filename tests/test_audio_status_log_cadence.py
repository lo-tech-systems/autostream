"""tests/test_audio_status_log_cadence.py

GET /api/audio/status logs that the outputs are unavailable at WARNING the
first time and then at most once a minute; in between it is logged at DEBUG.
The clock is injected, so no test waits.
"""
from __future__ import annotations

import io
import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_logging as log_setup
from fake_store import FakeStore
import webui.common as webui_common
import webui.browser.home_api as webui_home_api


@pytest.fixture
def clock(monkeypatch):
    """Time for log_every: a one-element list the test moves."""
    now = [1000.0]
    real = log_setup.log_every
    monkeypatch.setattr(
        log_setup, "log_every",
        lambda key, seconds, now_=None, **kw: real(key, seconds, now=now[0]))
    return now


def _call(reachable: bool):
    if reachable:
        FakeStore().outputs([])
    else:
        FakeStore().outputs_unreachable()
    handler = MagicMock()
    handler.wfile = io.BytesIO()
    cfg = SimpleNamespace(owntone=SimpleNamespace(base_url="http://localhost:3689"))
    with patch.object(webui_common, "_config_snapshot", return_value=cfg),          patch.object(webui_common, "_session_playing", return_value=False):
        webui_home_api.send_audio_status_json(handler, MagicMock())


def _levels(caplog):
    return [r.levelno for r in caplog.records if "audio/status" in r.getMessage()]


def test_first_failure_warns_repeats_inside_a_minute_do_not_and_after_a_minute_it_warns_again(
        clock, caplog):
    caplog.set_level(logging.DEBUG)

    _call(False)
    assert _levels(caplog) == [logging.WARNING]

    caplog.clear()
    clock[0] += 10.0
    _call(False)
    clock[0] += 49.0
    _call(False)
    assert _levels(caplog) == [logging.DEBUG, logging.DEBUG]

    caplog.clear()
    clock[0] += 2.0   # 61 s after the first warning
    _call(False)
    assert _levels(caplog) == [logging.WARNING]


def test_a_reachable_player_logs_nothing(clock, caplog):
    caplog.set_level(logging.DEBUG)
    _call(True)
    assert _levels(caplog) == []
