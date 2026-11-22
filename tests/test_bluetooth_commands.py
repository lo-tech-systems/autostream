"""Tests for platform/bluetooth_commands.py's op classes: AdoptDeviceOp,
RemoveDevicesOp and ReconnectProbeOp, driven against a fake BluezClient that records each async
call and lets the test fire its success/error handler manually -- no real
GLib loop or D-Bus connection involved.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
for _p in (REPO_ROOT / "platform",):
    _s = str(_p)
    if _s not in sys.path:
        sys.path.insert(0, _s)

import bluetooth_commands as cmd_mod  # noqa: E402

MAC = "AA:BB:CC:DD:EE:01"
OLD_MAC = "AA:BB:CC:DD:EE:02"


class _FakeClient:
    """Captures each async call's (mac, [trusted], on_success, on_error) so
    the test can invoke either handler on demand, exactly as the real
    dbus-python reply_handler=/error_handler= form would once a reply
    arrives on the loop."""

    def __init__(self) -> None:
        self.pair_calls: list = []
        self.trust_calls: list = []
        self.remove_calls: list = []
        self.is_connected_calls: list = []
        self.connect_calls: list = []
        self.disconnect_calls: list = []

    def pair_async(self, mac, on_success, on_error, timeout=None):
        self.pair_calls.append((mac, on_success, on_error))

    def set_trusted_async(self, mac, trusted, on_success, on_error, timeout=None):
        self.trust_calls.append((mac, trusted, on_success, on_error))

    def remove_device_async(self, mac, on_success, on_error, timeout=None):
        self.remove_calls.append((mac, on_success, on_error))

    def is_connected_async(self, mac, on_result, on_error, timeout=None):
        self.is_connected_calls.append((mac, on_result, on_error))

    def connect_async(self, mac, on_success, on_error, timeout=None):
        self.connect_calls.append((mac, on_success, on_error))

    def disconnect_async(self, mac, on_success, on_error, timeout=None):
        self.disconnect_calls.append((mac, on_success, on_error))


def _never_stale() -> bool:
    return False


def _adopt(client, entry, old_mac=OLD_MAC, stale=_never_stale):
    results: list = []
    op = cmd_mod.AdoptDeviceOp(
        client, MAC, entry, old_mac, lambda mac, ok, err: results.append((mac, ok, err)), stale
    )
    op.start()
    return results


class TestAdoptDeviceOpPairEntry:
    """A device found by scanning: pair -> trust -> connect -> remove old."""

    def test_success_path_with_old_device_removed(self):
        client = _FakeClient()
        results = _adopt(client, cmd_mod.ENTRY_PAIR)
        assert len(client.pair_calls) == 1
        client.pair_calls[0][1]()
        assert client.trust_calls[0][:2] == (MAC, True)
        client.trust_calls[0][2]()
        assert client.connect_calls[0][0] == MAC
        client.connect_calls[0][1]()
        assert client.remove_calls[0][0] == OLD_MAC
        client.remove_calls[0][1]()
        assert results == [(MAC, True, None)]

    def test_success_path_without_or_with_the_same_old_device(self):
        for old in (None, MAC):
            client = _FakeClient()
            results = _adopt(client, cmd_mod.ENTRY_PAIR, old_mac=old)
            client.pair_calls[0][1]()
            client.trust_calls[0][2]()
            client.connect_calls[0][1]()
            assert client.remove_calls == []
            assert results == [(MAC, True, None)]

    def test_pair_failure_reports_error_and_stops(self):
        client = _FakeClient()
        results = _adopt(client, cmd_mod.ENTRY_PAIR)
        client.pair_calls[0][2](Exception("org.bluez.Error.AuthenticationFailed"))
        assert results == [(MAC, False, "org.bluez.Error.AuthenticationFailed")]
        assert client.trust_calls == [] and client.connect_calls == [] and client.remove_calls == []

    def test_trust_failure_reports_error_and_stops(self):
        client = _FakeClient()
        results = _adopt(client, cmd_mod.ENTRY_PAIR)
        client.pair_calls[0][1]()
        client.trust_calls[0][3](Exception("org.bluez.Error.Failed"))
        assert results == [(MAC, False, "org.bluez.Error.Failed")]
        assert client.connect_calls == [] and client.remove_calls == []

    def test_connect_failure_fails_the_op_and_keeps_the_old_device(self):
        client = _FakeClient()
        results = _adopt(client, cmd_mod.ENTRY_PAIR)
        client.pair_calls[0][1]()
        client.trust_calls[0][2]()
        client.connect_calls[0][2](Exception("org.bluez.Error.Failed"))
        assert results == [(MAC, False, "org.bluez.Error.Failed")]
        assert client.remove_calls == []

    def test_old_device_remove_failure_still_reports_success(self):
        client = _FakeClient()
        results = _adopt(client, cmd_mod.ENTRY_PAIR)
        client.pair_calls[0][1]()
        client.trust_calls[0][2]()
        client.connect_calls[0][1]()
        client.remove_calls[0][2](Exception("org.bluez.Error.Failed"))
        assert results == [(MAC, True, None)]

    def test_stale_before_start_skips_first_call(self):
        client = _FakeClient()
        results = _adopt(client, cmd_mod.ENTRY_PAIR, stale=lambda: True)
        assert client.pair_calls == [] and results == []

    def test_stale_between_steps_stops_the_chain(self):
        client = _FakeClient()
        stale = {"value": False}
        results = _adopt(client, cmd_mod.ENTRY_PAIR, stale=lambda: stale["value"])
        client.pair_calls[0][1]()
        stale["value"] = True
        client.trust_calls[0][2]()
        assert client.connect_calls == [] and results == []

    def test_stale_before_final_report_suppresses_it(self):
        client = _FakeClient()
        stale = {"value": False}
        results = _adopt(client, cmd_mod.ENTRY_PAIR, old_mac=None, stale=lambda: stale["value"])
        client.pair_calls[0][1]()
        client.trust_calls[0][2]()
        stale["value"] = True
        client.connect_calls[0][1]()
        assert results == []


class TestAdoptDeviceOpTrustEntry:
    """A device that paired in by itself: trust -> remove old; no Pair()
    and no outgoing Connect() (it connects in on its own)."""

    def test_trusts_then_replaces_the_old_device(self):
        client = _FakeClient()
        results = _adopt(client, cmd_mod.ENTRY_TRUST)
        assert client.pair_calls == []
        assert client.trust_calls[0][:2] == (MAC, True)
        client.trust_calls[0][2]()
        assert client.connect_calls == []
        assert client.remove_calls[0][0] == OLD_MAC
        client.remove_calls[0][1]()
        assert results == [(MAC, True, None)]

    def test_trust_failure_keeps_the_old_device(self):
        client = _FakeClient()
        results = _adopt(client, cmd_mod.ENTRY_TRUST)
        client.trust_calls[0][3](Exception("org.bluez.Error.DoesNotExist"))
        assert results == [(MAC, False, "org.bluez.Error.DoesNotExist")]
        assert client.remove_calls == []

    def test_no_old_device_reports_straight_after_trust(self):
        client = _FakeClient()
        results = _adopt(client, cmd_mod.ENTRY_TRUST, old_mac=None)
        client.trust_calls[0][2]()
        assert results == [(MAC, True, None)]


class TestRemoveDevicesOp:
    def test_disconnects_before_removing_each_device_in_turn(self):
        client = _FakeClient()
        done: list = []
        cmd_mod.RemoveDevicesOp(client, [MAC, OLD_MAC], lambda: done.append(True)).start()
        assert [c[0] for c in client.disconnect_calls] == [MAC]
        assert client.remove_calls == []
        client.disconnect_calls[0][1]()
        assert [c[0] for c in client.remove_calls] == [MAC]
        client.remove_calls[0][1]()
        assert [c[0] for c in client.disconnect_calls] == [MAC, OLD_MAC]
        client.disconnect_calls[1][1]()
        client.remove_calls[1][1]()
        assert done == [True]

    def test_a_vanished_or_unconnected_device_is_tolerated(self):
        client = _FakeClient()
        done: list = []
        cmd_mod.RemoveDevicesOp(client, [MAC, OLD_MAC], lambda: done.append(True)).start()
        client.disconnect_calls[0][2](Exception("org.bluez.Error.NotConnected"))
        client.remove_calls[0][2](Exception("org.bluez.Error.Failed"))
        client.disconnect_calls[1][2](Exception("org.freedesktop.DBus.Error.UnknownObject"))
        client.remove_calls[1][1]()
        assert done == [True]

    def test_a_call_that_raises_at_once_is_tolerated(self):
        class RaisingClient(_FakeClient):
            def disconnect_async(self, mac, on_success, on_error, timeout=None):
                raise RuntimeError("bluetooth adapter not available")

            def remove_device_async(self, mac, on_success, on_error, timeout=None):
                raise RuntimeError("bluetooth adapter not available")

        done: list = []
        cmd_mod.RemoveDevicesOp(RaisingClient(), [MAC, OLD_MAC], lambda: done.append(True)).start()
        assert done == [True]

    def test_nothing_to_remove_finishes_at_once(self):
        done: list = []
        cmd_mod.RemoveDevicesOp(_FakeClient(), [], lambda: done.append(True)).start()
        assert done == [True]


class TestReconnectProbeOp:
    def test_already_connected_reports_true_without_connecting(self):
        client = _FakeClient()
        results: list = []
        op = cmd_mod.ReconnectProbeOp(
            client, MAC, lambda mac, connected: results.append((mac, connected)), _never_stale
        )
        op.start()
        assert len(client.is_connected_calls) == 1
        client.is_connected_calls[0][1](True)  # on_result

        assert results == [(MAC, True)]
        assert client.connect_calls == []

    def test_not_connected_issues_connect_and_reports_nothing_on_success(self):
        client = _FakeClient()
        results: list = []
        op = cmd_mod.ReconnectProbeOp(
            client, MAC, lambda mac, connected: results.append((mac, connected)), _never_stale
        )
        op.start()
        client.is_connected_calls[0][1](False)

        assert len(client.connect_calls) == 1
        client.connect_calls[0][1]()  # on_success

        # Mirrors reconnect_tick(): a Connect() this op issued itself is
        # never proactively reported -- the PropertiesChanged signal does
        # that job.
        assert results == []

    def test_connect_failure_including_inprogress_is_swallowed(self):
        client = _FakeClient()
        results: list = []
        op = cmd_mod.ReconnectProbeOp(
            client, MAC, lambda mac, connected: results.append((mac, connected)), _never_stale
        )
        op.start()
        client.is_connected_calls[0][1](False)
        client.connect_calls[0][2](Exception("org.bluez.Error.InProgress"))

        assert results == []

    def test_probe_error_falls_through_to_connect_attempt(self):
        client = _FakeClient()
        results: list = []
        op = cmd_mod.ReconnectProbeOp(
            client, MAC, lambda mac, connected: results.append((mac, connected)), _never_stale
        )
        op.start()
        client.is_connected_calls[0][2](Exception("org.freedesktop.DBus.Error.NoReply"))

        assert len(client.connect_calls) == 1
        assert results == []

    def test_probe_timeout_error_also_falls_through_to_connect(self):
        client = _FakeClient()
        results: list = []
        op = cmd_mod.ReconnectProbeOp(
            client, MAC, lambda mac, connected: results.append((mac, connected)), _never_stale
        )
        op.start()
        client.is_connected_calls[0][2](
            Exception("org.freedesktop.DBus.Error.NoReply: Did not receive a reply")
        )

        assert len(client.connect_calls) == 1

    def test_stale_before_start_skips_probe(self):
        client = _FakeClient()
        results: list = []
        op = cmd_mod.ReconnectProbeOp(
            client, MAC, lambda mac, connected: results.append((mac, connected)), lambda: True
        )
        op.start()
        assert client.is_connected_calls == []

    def test_stale_after_probe_skips_connect_and_report(self):
        client = _FakeClient()
        results: list = []
        stale = {"value": False}
        op = cmd_mod.ReconnectProbeOp(
            client, MAC, lambda mac, connected: results.append((mac, connected)),
            lambda: stale["value"],
        )
        op.start()
        stale["value"] = True
        client.is_connected_calls[0][1](True)  # would have reported True if fresh

        assert results == []

    def test_stale_after_probe_error_skips_connect_attempt(self):
        client = _FakeClient()
        results: list = []
        stale = {"value": False}
        op = cmd_mod.ReconnectProbeOp(
            client, MAC, lambda mac, connected: results.append((mac, connected)),
            lambda: stale["value"],
        )
        op.start()
        stale["value"] = True
        client.is_connected_calls[0][2](Exception("boom"))

        assert client.connect_calls == []
