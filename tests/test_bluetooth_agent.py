"""Tests for the Bluetooth pairing-agent policy (platform/bluetooth_agent.py)
-- the security-relevant logic of the autostream_bluetooth daemon.

Pure-policy tests only; no dbus/gi required (PairingPolicy has no D-Bus
dependency at all). The table cases follow the policy's own table: which
agent methods are accepted when, and which mark a device provisional.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
for _p in (REPO_ROOT / "platform",):
    _s = str(_p)
    if _s not in sys.path:
        sys.path.insert(0, _s)

import bluetooth_agent as agent  # noqa: E402

PAIRED = "AA:BB:CC:DD:EE:01"
TAPPED = "AA:BB:CC:DD:EE:02"
PROV = "AA:BB:CC:DD:EE:03"
STRANGER = "AA:BB:CC:DD:EE:04"

A2DP = "0000110d-0000-1000-8000-00805f9b34fb"
AVRCP = "0000110e-0000-1000-8000-00805f9b34fb"
HFP = "0000111e-0000-1000-8000-00805f9b34fb"
SERIAL = "00001101-0000-1000-8000-00805f9b34fb"


class World:
    def __init__(self, window_open=False, adopting=None, paired=PAIRED, provisional=()):
        self.window_open = window_open
        self.adopting = adopting
        self.paired = paired
        self.provisional = frozenset(provisional)
        self.marked = []

    def policy(self):
        return agent.PairingPolicy(
            window_open=lambda: self.window_open,
            adopting=lambda: self.adopting,
            paired_mac=lambda: self.paired,
            provisional_macs=lambda: self.provisional,
            mark_provisional=lambda mac, passkey: self.marked.append((mac, passkey)),
        )


PAIRING_KINDS = (agent.KIND_AUTHORIZE, agent.KIND_CONFIRM)

# (world kwargs, kind, mac, passkey, expected decision, expected marks)
ROWS = [
    # Inside a window: accept and mark anything new.
    ({"window_open": True}, agent.KIND_AUTHORIZE, STRANGER, None, True, [(STRANGER, None)]),
    ({"window_open": True}, agent.KIND_CONFIRM, STRANGER, 123456, True, [(STRANGER, 123456)]),
    # The paired device re-pairing during a window: accepted, not marked.
    ({"window_open": True}, agent.KIND_AUTHORIZE, PAIRED, None, True, []),
    ({"window_open": True}, agent.KIND_CONFIRM, PAIRED, 1, True, []),
    # Outside a window: refused, nothing marked.
    ({}, agent.KIND_AUTHORIZE, STRANGER, None, False, []),
    ({}, agent.KIND_CONFIRM, PAIRED, 1, False, []),
    # During a tap: the tapped device completes its own pairing unmarked;
    # nobody else gets in.
    ({"adopting": TAPPED}, agent.KIND_CONFIRM, TAPPED, 222222, True, []),
    ({"adopting": TAPPED}, agent.KIND_AUTHORIZE, TAPPED, None, True, []),
    ({"adopting": TAPPED}, agent.KIND_AUTHORIZE, STRANGER, None, False, []),
]


@pytest.mark.parametrize("world,kind,mac,passkey,expected,marks", ROWS)
def test_pairing_requests(world, kind, mac, passkey, expected, marks):
    w = World(**world)
    assert w.policy().decide(kind, mac, passkey=passkey) is expected
    assert w.marked == marks


SERVICE_ROWS = [
    (PAIRED, A2DP, True),
    (TAPPED, A2DP, True),
    (PROV, AVRCP, True),
    (STRANGER, A2DP, False),
    (PAIRED, HFP, False),
    (PROV, SERIAL, False),
    (PAIRED, None, False),
]


@pytest.mark.parametrize("mac,uuid,expected", SERVICE_ROWS)
def test_authorize_service_audio_only_from_known_devices(mac, uuid, expected):
    w = World(adopting=TAPPED, provisional=(PROV,))
    assert w.policy().decide(agent.KIND_AUTHORIZE_SERVICE, mac, uuid=uuid) is expected
    assert w.marked == []


@pytest.mark.parametrize("kind", [
    agent.KIND_PIN_CODE, agent.KIND_PASSKEY, agent.KIND_DISPLAY_PASSKEY,
    agent.KIND_DISPLAY_PIN_CODE, "unknown_kind",
])
def test_pin_kinds_are_always_refused(kind):
    w = World(window_open=True, adopting=TAPPED)
    assert w.policy().decide(kind, TAPPED) is False
    assert w.marked == []


def test_mark_fires_once_per_accepted_request_and_never_for_the_tapped_device():
    w = World(window_open=True)
    policy = w.policy()
    policy.decide(agent.KIND_CONFIRM, STRANGER, passkey=111111)
    assert w.marked == [(STRANGER, 111111)]
    w.window_open, w.adopting = False, STRANGER
    policy.decide(agent.KIND_CONFIRM, STRANGER, passkey=111111)
    assert w.marked == [(STRANGER, 111111)]


def test_refused_requests_never_mark():
    w = World()
    for kind in PAIRING_KINDS:
        w.policy().decide(kind, STRANGER)
    assert w.marked == []


def test_macs_compare_case_insensitively():
    w = World(adopting=TAPPED.lower(), provisional=(PROV.lower(),))
    policy = w.policy()
    assert policy.decide(agent.KIND_CONFIRM, TAPPED, passkey=1) is True
    assert policy.decide(agent.KIND_AUTHORIZE_SERVICE, PROV, uuid=A2DP.upper()) is True


def test_policy_reads_live_values():
    w = World()
    policy = w.policy()
    assert policy.decide(agent.KIND_AUTHORIZE, STRANGER) is False
    w.window_open = True
    assert policy.decide(agent.KIND_AUTHORIZE, STRANGER) is True


def test_registers_as_display_yes_no():
    assert agent.AGENT_CAPABILITY == "DisplayYesNo"


def test_audio_uuid_set():
    shorts = {u[4:8] for u in agent.AUDIO_UUIDS}
    assert shorts == {"110d", "110a", "110b", "110c", "110e", "110f", "0019"}


def test_hands_free_refusal_is_named_at_info(caplog):
    w = World()
    with caplog.at_level("INFO", logger="bluetooth_agent"):
        w.policy().decide(agent.KIND_AUTHORIZE_SERVICE, PAIRED, uuid=HFP)
    assert any("hands-free" in r.getMessage() and r.levelname == "INFO" for r in caplog.records)


def test_the_policy_module_imports_nothing_from_dbus_at_module_level():
    text = (REPO_ROOT / "platform" / "bluetooth_agent.py").read_text(encoding="utf-8")
    top = text.split("def build_agent_class", 1)[0]
    assert "import dbus" not in top
