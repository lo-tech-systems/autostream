"""tests/test_audio_status_log_cadence.py

GET /api/audio/status logs a failure to list the outputs at WARNING on the
first failure and then at most once a minute; in between the failure is
logged at DEBUG. The clock is injected, so no test waits.
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
import autostream_webui_api as api


@pytest.fixture
def clock(monkeypatch):
    """Time for log_every: a one-element list the test moves."""
    now = [1000.0]
    real = log_setup.log_every
    monkeypatch.setattr(
        log_setup, "log_every",
        lambda key, seconds, now_=None, **kw: real(key, seconds, now=now[0]))
    return now


def _call(outputs_result):
    handler = MagicMock()
    handler.wfile = io.BytesIO()
    cfg = SimpleNamespace(owntone=SimpleNamespace(base_url="http://localhost:3689"))
    with patch.object(api, "_config_snapshot", return_value=cfg), \
         patch.object(api, "_session_playing", return_value=False), \
         patch.object(api, "list_outputs", **outputs_result):
        api.send_audio_status_json(handler, MagicMock())


def _levels(caplog):
    return [r.levelno for r in caplog.records if "list_outputs" in r.getMessage()]


RAISES = {"side_effect": OSError("connection refused")}
NOT_OK = {"return_value": SimpleNamespace(ok=False, message="refused", outputs=())}


@pytest.mark.parametrize("failure", [RAISES, NOT_OK], ids=["raises", "not-ok"])
def test_first_failure_warns_repeats_inside_a_minute_do_not_and_after_a_minute_it_warns_again(
        failure, clock, caplog):
    caplog.set_level(logging.DEBUG)

    _call(failure)
    assert _levels(caplog) == [logging.WARNING]

    caplog.clear()
    clock[0] += 10.0
    _call(failure)
    clock[0] += 49.0
    _call(failure)
    assert _levels(caplog) == [logging.DEBUG, logging.DEBUG]

    caplog.clear()
    clock[0] += 2.0   # 61 s after the first warning
    _call(failure)
    assert _levels(caplog) == [logging.WARNING]


def test_the_two_failure_kinds_share_one_timer(clock, caplog):
    caplog.set_level(logging.DEBUG)
    _call(RAISES)
    clock[0] += 5.0
    _call(NOT_OK)
    assert _levels(caplog) == [logging.WARNING, logging.DEBUG]
