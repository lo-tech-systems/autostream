"""Tests for the webui's Bluetooth lockout-healing step
(core/autostream_webui.py, _lockout_heal_check).

A sustained ``loopback_locked_out`` means the pump's capture-side peer
pinned the shared loopback cable at incompatible parameters while the pump
was absent; only the monitor reopening its capture side renegotiates the
cable. The healing step must request a coordinator config reload once the
lockout has been observed on two consecutive polls (not a single transient
one) while a Bluetooth input is configured, and must not repeat within the
cooldown window.
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


def _patch(monkeypatch, configured: bool, now: float = 1000.0):
    calls = []
    monkeypatch.setattr(core_mod, "request_config_reload", lambda: calls.append(1))
    monkeypatch.setattr(
        webui_mod, "_bluetooth_input_configured", lambda state: configured,
    )
    monkeypatch.setattr(webui_mod.time, "monotonic", lambda: now)
    return calls


class TestLockoutHealCheck:
    def test_first_lockout_poll_does_not_reload(self, monkeypatch):
        calls = _patch(monkeypatch, configured=True)
        streak, last_reload = webui_mod._lockout_heal_check(
            STATE_SENTINEL, {"loopback_locked_out": True}, 0, None,
        )
        assert streak == 1
        assert last_reload is None
        assert calls == []

    def test_second_consecutive_lockout_poll_reloads(self, monkeypatch):
        calls = _patch(monkeypatch, configured=True, now=1000.0)
        streak, last_reload = webui_mod._lockout_heal_check(
            STATE_SENTINEL, {"loopback_locked_out": True}, 1, None,
        )
        assert streak == 0  # reset after firing
        assert last_reload == 1000.0
        assert calls == [1]

    def test_clear_poll_resets_streak(self, monkeypatch):
        calls = _patch(monkeypatch, configured=True)
        streak, last_reload = webui_mod._lockout_heal_check(
            STATE_SENTINEL, {"loopback_locked_out": False}, 1, None,
        )
        assert streak == 0
        assert last_reload is None
        assert calls == []

    def test_none_status_resets_streak(self, monkeypatch):
        calls = _patch(monkeypatch, configured=True)
        streak, last_reload = webui_mod._lockout_heal_check(
            STATE_SENTINEL, None, 1, None,
        )
        assert streak == 0
        assert last_reload is None
        assert calls == []

    def test_no_reload_when_no_bluetooth_input_configured(self, monkeypatch):
        calls = _patch(monkeypatch, configured=False)
        streak, last_reload = webui_mod._lockout_heal_check(
            STATE_SENTINEL, {"loopback_locked_out": True}, 1, None,
        )
        # Streak keeps accumulating so a later-configured input sees fresh
        # state, but no reload fires without a configured input.
        assert streak == 2
        assert last_reload is None
        assert calls == []

    def test_cooldown_suppresses_second_reload(self, monkeypatch):
        calls = _patch(monkeypatch, configured=True, now=1000.0)
        streak, last_reload = webui_mod._lockout_heal_check(
            STATE_SENTINEL, {"loopback_locked_out": True}, 1, None,
        )
        assert calls == [1]
        assert last_reload == 1000.0

        # Immediately re-triggers accumulation, but the cooldown (120 s)
        # has not elapsed -- no second reload.
        monkeypatch.setattr(webui_mod.time, "monotonic", lambda: 1010.0)
        streak, last_reload = webui_mod._lockout_heal_check(
            STATE_SENTINEL, {"loopback_locked_out": True}, streak, last_reload,
        )
        streak, last_reload = webui_mod._lockout_heal_check(
            STATE_SENTINEL, {"loopback_locked_out": True}, streak, last_reload,
        )
        assert calls == [1]
        assert last_reload == 1000.0

    def test_reload_fires_again_after_cooldown_elapses(self, monkeypatch):
        calls = _patch(monkeypatch, configured=True, now=1000.0)
        streak, last_reload = webui_mod._lockout_heal_check(
            STATE_SENTINEL, {"loopback_locked_out": True}, 1, None,
        )
        assert calls == [1]

        monkeypatch.setattr(webui_mod.time, "monotonic", lambda: 1000.0 + 121.0)
        streak, last_reload = webui_mod._lockout_heal_check(
            STATE_SENTINEL, {"loopback_locked_out": True}, streak, last_reload,
        )
        streak, last_reload = webui_mod._lockout_heal_check(
            STATE_SENTINEL, {"loopback_locked_out": True}, streak, last_reload,
        )
        assert calls == [1, 1]
        assert last_reload == 1121.0
