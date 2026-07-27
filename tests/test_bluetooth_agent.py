"""Tests for the Bluetooth pairing-agent accept/reject policy
(platform/bluetooth_agent.py) — the security-relevant logic of the
autostream_bluetooth daemon.

Pure-policy tests only; no dbus/gi required (should_accept/PairingPolicy have
no D-Bus dependency at all).
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
for _p in (REPO_ROOT / "platform",):
    _s = str(_p)
    if _s not in sys.path:
        sys.path.insert(0, _s)

from bluetooth_agent import (  # noqa: E402
    KIND_AUTHORIZE,
    KIND_AUTHORIZE_SERVICE,
    KIND_CONFIRM,
    PairingPolicy,
    should_accept,
)

MAC_A = "AA:BB:CC:DD:EE:01"
MAC_B = "AA:BB:CC:DD:EE:02"


class TestShouldAcceptConfirmAndAuthorize:
    """RequestConfirmation / RequestAuthorization: accept only when a pairing
    window is open AND the MAC matches the in-flight pairing target."""

    def test_accepts_when_window_open_and_mac_matches(self):
        for kind in (KIND_CONFIRM, KIND_AUTHORIZE):
            assert should_accept(
                kind, pairing_window_open=True, pairing_target_mac=MAC_A,
                device_mac=MAC_A, trusted_mac=None,
            ) is True

    def test_rejects_when_window_closed(self):
        for kind in (KIND_CONFIRM, KIND_AUTHORIZE):
            assert should_accept(
                kind, pairing_window_open=False, pairing_target_mac=MAC_A,
                device_mac=MAC_A, trusted_mac=None,
            ) is False

    def test_rejects_when_mac_mismatches(self):
        for kind in (KIND_CONFIRM, KIND_AUTHORIZE):
            assert should_accept(
                kind, pairing_window_open=True, pairing_target_mac=MAC_A,
                device_mac=MAC_B, trusted_mac=None,
            ) is False

    def test_rejects_when_no_target_set(self):
        for kind in (KIND_CONFIRM, KIND_AUTHORIZE):
            assert should_accept(
                kind, pairing_window_open=True, pairing_target_mac=None,
                device_mac=MAC_A, trusted_mac=None,
            ) is False

    def test_trusted_device_alone_does_not_grant_confirm(self):
        """Being the already-trusted device is not enough for Confirm/Authorize
        (only AuthorizeService honours the trusted-device exception)."""
        for kind in (KIND_CONFIRM, KIND_AUTHORIZE):
            assert should_accept(
                kind, pairing_window_open=False, pairing_target_mac=None,
                device_mac=MAC_A, trusted_mac=MAC_A,
            ) is False

    def test_mac_comparison_is_case_insensitive(self):
        assert should_accept(
            KIND_CONFIRM, pairing_window_open=True, pairing_target_mac=MAC_A.lower(),
            device_mac=MAC_A.upper(), trusted_mac=None,
        ) is True


class TestShouldAcceptAuthorizeService:
    """AuthorizeService: accept for the in-flight pairing target (during the
    window) OR the already-trusted device (routine reconnect)."""

    def test_accepts_pairing_target_during_window(self):
        assert should_accept(
            KIND_AUTHORIZE_SERVICE, pairing_window_open=True, pairing_target_mac=MAC_A,
            device_mac=MAC_A, trusted_mac=None,
        ) is True

    def test_accepts_trusted_device_outside_pairing_window(self):
        assert should_accept(
            KIND_AUTHORIZE_SERVICE, pairing_window_open=False, pairing_target_mac=None,
            device_mac=MAC_A, trusted_mac=MAC_A,
        ) is True

    def test_rejects_untrusted_unrelated_device(self):
        assert should_accept(
            KIND_AUTHORIZE_SERVICE, pairing_window_open=False, pairing_target_mac=None,
            device_mac=MAC_B, trusted_mac=MAC_A,
        ) is False

    def test_rejects_when_nothing_paired_or_pairing(self):
        assert should_accept(
            KIND_AUTHORIZE_SERVICE, pairing_window_open=False, pairing_target_mac=None,
            device_mac=MAC_A, trusted_mac=None,
        ) is False

    def test_trusted_mac_case_insensitive(self):
        assert should_accept(
            KIND_AUTHORIZE_SERVICE, pairing_window_open=False, pairing_target_mac=None,
            device_mac=MAC_A.lower(), trusted_mac=MAC_A.upper(),
        ) is True


class TestShouldAcceptUnknownKind:
    def test_unknown_request_kind_rejected(self):
        assert should_accept(
            "display_passkey", pairing_window_open=True, pairing_target_mac=MAC_A,
            device_mac=MAC_A, trusted_mac=MAC_A,
        ) is False


class TestPairingPolicyWrapsLiveState:
    """PairingPolicy closes over injected callables (the real code path from
    a live BluetoothStateMachine) rather than a static snapshot."""

    def test_reflects_current_callable_values(self):
        window_open = {"value": False}
        target = {"value": None}
        trusted = {"value": None}

        policy = PairingPolicy(
            pairing_window_open=lambda: window_open["value"],
            pairing_target_mac=lambda: target["value"],
            trusted_mac=lambda: trusted["value"],
        )

        assert policy.decide(KIND_CONFIRM, MAC_A) is False

        window_open["value"] = True
        target["value"] = MAC_A
        assert policy.decide(KIND_CONFIRM, MAC_A) is True
        assert policy.decide(KIND_CONFIRM, MAC_B) is False

    def test_authorize_service_uses_trusted_callable(self):
        policy = PairingPolicy(
            pairing_window_open=lambda: False,
            pairing_target_mac=lambda: None,
            trusted_mac=lambda: MAC_A,
        )
        assert policy.decide(KIND_AUTHORIZE_SERVICE, MAC_A) is True
        assert policy.decide(KIND_AUTHORIZE_SERVICE, MAC_B) is False
