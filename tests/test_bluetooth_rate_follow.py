"""Tests for the webui's Bluetooth rate-follow step
(core/autostream_webui.py, _rate_follow_check).

The loopback cable's rate follows the Bluetooth transport; the monitor's
capture side renegotiates only by being reopened. The rate-follow step
must request a coordinator config reload exactly when an observed
transport rate CHANGES while a Bluetooth input is configured -- and never
across transport gaps (status polls without a sample_rate), so a plain
reconnect at the same rate does not bounce the inputs.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import autostream_core as core_mod  # noqa: E402
import autostream_webui as webui_mod  # noqa: E402

STATE_SENTINEL = object()


def _patch(monkeypatch, configured: bool):
    calls = []
    monkeypatch.setattr(core_mod, "request_config_reload", lambda: calls.append(1))
    monkeypatch.setattr(
        webui_mod, "_bluetooth_input_configured", lambda state: configured,
    )
    return calls


class TestRateFollowCheck:
    def test_first_observation_records_without_reload(self, monkeypatch):
        calls = _patch(monkeypatch, configured=True)
        out = webui_mod._rate_follow_check(STATE_SENTINEL, {"sample_rate": 44100}, None)
        assert out == 44100
        assert calls == []

    def test_same_rate_across_polls_never_reloads(self, monkeypatch):
        calls = _patch(monkeypatch, configured=True)
        rate = webui_mod._rate_follow_check(STATE_SENTINEL, {"sample_rate": 44100}, 44100)
        assert rate == 44100
        assert calls == []

    def test_rate_change_triggers_reload(self, monkeypatch):
        calls = _patch(monkeypatch, configured=True)
        rate = webui_mod._rate_follow_check(STATE_SENTINEL, {"sample_rate": 48000}, 44100)
        assert rate == 48000
        assert calls == [1]

    def test_transport_gap_preserves_last_rate(self, monkeypatch):
        calls = _patch(monkeypatch, configured=True)
        # Transport dropped: no sample_rate in status. Last-seen must persist.
        rate = webui_mod._rate_follow_check(STATE_SENTINEL, {"pump_source_active": False}, 44100)
        assert rate == 44100
        # Unreachable service (None status) preserves it too.
        rate = webui_mod._rate_follow_check(STATE_SENTINEL, None, rate)
        assert rate == 44100
        # Reconnect at the SAME rate after the gap: no reload.
        rate = webui_mod._rate_follow_check(STATE_SENTINEL, {"sample_rate": 44100}, rate)
        assert rate == 44100
        assert calls == []

    def test_reconnect_at_new_rate_after_gap_reloads(self, monkeypatch):
        calls = _patch(monkeypatch, configured=True)
        rate = webui_mod._rate_follow_check(STATE_SENTINEL, None, 44100)
        rate = webui_mod._rate_follow_check(STATE_SENTINEL, {"sample_rate": 48000}, rate)
        assert rate == 48000
        assert calls == [1]

    def test_no_reload_when_no_bluetooth_input_configured(self, monkeypatch):
        calls = _patch(monkeypatch, configured=False)
        rate = webui_mod._rate_follow_check(STATE_SENTINEL, {"sample_rate": 48000}, 44100)
        assert rate == 48000   # still tracked, so a later BT input sees fresh state
        assert calls == []

    def test_bogus_rate_values_ignored(self, monkeypatch):
        calls = _patch(monkeypatch, configured=True)
        for bogus in (0, -1, True, "48000", None):
            rate = webui_mod._rate_follow_check(
                STATE_SENTINEL, {"sample_rate": bogus}, 44100,
            )
            assert rate == 44100
        assert calls == []
