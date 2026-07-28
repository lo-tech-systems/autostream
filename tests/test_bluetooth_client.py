"""Tests for core/autostream_bluetooth_client.py.

Covers:
  - BluetoothClient against a real Unix-domain socket server (one JSON
    request/reply per connection)
  - bluetooth_installed() / bluetooth_services_enabled() /
    bluetooth_onboard_enabled() gating helpers
  - classify_loopback_hw() / bluetooth_capture_label() relabel-hook helpers
"""
from __future__ import annotations

import json
import socket
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

from autostream_bluetooth_client import (
    BLUETOOTH_CAPTURE_DEVICE,
    BLUETOOTH_PLAYBACK_DEVICE,
    BLUETOOTH_SERVICE_VERSION,
    BluetoothClient,
    bluetooth_capture_label,
    bluetooth_installed,
    bluetooth_onboard_enabled,
    bluetooth_services_enabled,
    classify_loopback_hw,
    get_bluetooth_socket_path,
)

pytestmark = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="AF_UNIX sockets not available on this platform"
)


# ---------------------------------------------------------------------------
# Fake one-shot Unix-socket server
# ---------------------------------------------------------------------------

class _FakeBluetoothServer:
    """Accepts exactly one connection, records the request, sends one reply.

    ``reply`` may be a dict (JSON-encoded + newline), raw bytes (sent as-is,
    for malformed-response tests), or None (close without sending anything).
    """

    def __init__(self, socket_path: str, reply, *, delay: float = 0.0):
        self.socket_path = socket_path
        self.reply = reply
        self.delay = delay
        self.received: bytes = b""
        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._srv.bind(socket_path)
        self._srv.listen(1)
        self._srv.settimeout(5.0)
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> "_FakeBluetoothServer":
        self._thread.start()
        return self

    def _run(self) -> None:
        try:
            conn, _ = self._srv.accept()
        except OSError:
            return
        try:
            buf = b""
            conn.settimeout(5.0)
            while b"\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            self.received = buf
            if self.delay:
                time.sleep(self.delay)
            if self.reply is None:
                return
            try:
                if isinstance(self.reply, (bytes, bytearray)):
                    conn.sendall(self.reply)
                else:
                    conn.sendall((json.dumps(self.reply) + "\n").encode("utf-8"))
            except OSError:
                pass  # client already timed out and closed its end
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def join(self, timeout: float = 5.0) -> None:
        self._thread.join(timeout=timeout)
        try:
            self._srv.close()
        except OSError:
            pass


def _server(tmp_path: Path, reply, **kwargs) -> _FakeBluetoothServer:
    sock_path = str(tmp_path / "bluetooth.sock")
    srv = _FakeBluetoothServer(sock_path, reply, **kwargs).start()
    return srv


# ---------------------------------------------------------------------------
# Socket path resolution
# ---------------------------------------------------------------------------

class TestSocketPath:
    def test_default_path(self, monkeypatch):
        monkeypatch.delenv("AUTOSTREAM_BLUETOOTH_SOCKET", raising=False)
        assert get_bluetooth_socket_path() == "/run/autostream-bluetooth/bluetooth.sock"

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("AUTOSTREAM_BLUETOOTH_SOCKET", "/tmp/custom.sock")
        assert get_bluetooth_socket_path() == "/tmp/custom.sock"

    def test_client_uses_injected_path(self):
        c = BluetoothClient("/tmp/injected.sock")
        assert c._socket_path == "/tmp/injected.sock"


# ---------------------------------------------------------------------------
# Successful commands
# ---------------------------------------------------------------------------

class TestCommandsSucceed:
    def test_status_returns_dict(self, tmp_path):
        payload = {
            "ok": True, "adapter_present": True,
            "paired": {"mac": "AA:BB:CC:DD:EE:FF", "name": "Technics SL-1200"},
            "link": "connected", "streaming": True, "scanning": False,
        }
        srv = _server(tmp_path, payload)
        c = BluetoothClient(srv.socket_path)
        result = c.status()
        srv.join()
        assert result == payload
        sent_cmd = json.loads(srv.received.strip())
        assert sent_cmd == {"cmd": "status"}

    def test_scan_start_sends_correct_cmd(self, tmp_path):
        srv = _server(tmp_path, {"ok": True})
        c = BluetoothClient(srv.socket_path)
        result = c.scan_start()
        srv.join()
        assert result == {"ok": True}
        assert json.loads(srv.received.strip()) == {"cmd": "scan_start"}

    def test_scan_stop_sends_correct_cmd(self, tmp_path):
        srv = _server(tmp_path, {"ok": True})
        c = BluetoothClient(srv.socket_path)
        result = c.scan_stop()
        srv.join()
        assert result == {"ok": True}
        assert json.loads(srv.received.strip()) == {"cmd": "scan_stop"}

    def test_scan_results_returns_device_list(self, tmp_path):
        payload = {"ok": True, "devices": [{"mac": "11:22:33:44:55:66", "name": "TT", "rssi": -60, "paired": False}]}
        srv = _server(tmp_path, payload)
        c = BluetoothClient(srv.socket_path)
        result = c.scan_results()
        srv.join()
        assert result == payload
        assert json.loads(srv.received.strip()) == {"cmd": "scan_results"}

    def test_pair_sends_mac_field(self, tmp_path):
        srv = _server(tmp_path, {"ok": True})
        c = BluetoothClient(srv.socket_path)
        result = c.pair("AA:BB:CC:DD:EE:FF")
        srv.join()
        assert result == {"ok": True}
        assert json.loads(srv.received.strip()) == {"cmd": "pair", "mac": "AA:BB:CC:DD:EE:FF"}

    def test_pair_status_returns_state(self, tmp_path):
        payload = {"ok": True, "state": "pairing"}
        srv = _server(tmp_path, payload)
        c = BluetoothClient(srv.socket_path)
        result = c.pair_status()
        srv.join()
        assert result == payload
        assert json.loads(srv.received.strip()) == {"cmd": "pair_status"}

    def test_forget_sends_correct_cmd(self, tmp_path):
        srv = _server(tmp_path, {"ok": True})
        c = BluetoothClient(srv.socket_path)
        result = c.forget()
        srv.join()
        assert result == {"ok": True}
        assert json.loads(srv.received.strip()) == {"cmd": "forget"}

    def test_configure_sends_buffer_ms(self, tmp_path):
        srv = _server(tmp_path, {"ok": True})
        c = BluetoothClient(srv.socket_path)
        result = c.configure(250)
        srv.join()
        assert result == {"ok": True}
        assert json.loads(srv.received.strip()) == {"cmd": "configure", "buffer_ms": 250}


# ---------------------------------------------------------------------------
# Quiet failure paths
# ---------------------------------------------------------------------------

class TestQuietFailures:
    def test_socket_absent_returns_none(self, tmp_path):
        c = BluetoothClient(str(tmp_path / "does-not-exist.sock"))
        assert c.status() is None

    def test_connection_closed_without_reply_returns_none(self, tmp_path):
        srv = _server(tmp_path, None)
        c = BluetoothClient(srv.socket_path)
        result = c.status()
        srv.join()
        assert result is None

    def test_malformed_json_returns_none(self, tmp_path):
        srv = _server(tmp_path, b"not-json\n")
        c = BluetoothClient(srv.socket_path)
        result = c.status()
        srv.join()
        assert result is None

    def test_non_object_response_returns_none(self, tmp_path):
        srv = _server(tmp_path, b'["not", "an", "object"]\n')
        c = BluetoothClient(srv.socket_path)
        result = c.status()
        srv.join()
        assert result is None

    def test_timeout_returns_none(self, tmp_path):
        srv = _server(tmp_path, {"ok": True}, delay=0.5)
        c = BluetoothClient(srv.socket_path)
        c.TIMEOUT = 0.1  # instance override so the test stays fast
        result = c.status()
        srv.join()
        assert result is None

    def test_never_raises_on_repeated_calls_against_dead_socket(self, tmp_path):
        c = BluetoothClient(str(tmp_path / "gone.sock"))
        for _ in range(3):
            assert c.status() is None


# ---------------------------------------------------------------------------
# BLUETOOTH_SERVICE_VERSION — client-side fallback constant
# ---------------------------------------------------------------------------

class TestBluetoothServiceVersionConstant:
    def test_pinned_value(self):
        """Must stay in lock-step with platform/bluetooth_service.py's own
        BLUETOOTH_SERVICE_VERSION copy -- this pins the current value so an
        accidental one-sided bump is caught here rather than only surfacing
        as a stale About-page version after the daemon is upgraded."""
        assert BLUETOOTH_SERVICE_VERSION == "0.5.1"

    def test_is_a_string(self):
        assert isinstance(BLUETOOTH_SERVICE_VERSION, str)


# ---------------------------------------------------------------------------
# bluetooth_installed()
# ---------------------------------------------------------------------------

class TestBluetoothInstalled:
    def test_unit_file_present(self, tmp_path):
        unit = tmp_path / "autostream_bluetooth.service"
        unit.write_text("[Unit]\n", encoding="utf-8")
        assert bluetooth_installed(str(unit)) is True

    def test_unit_file_absent(self, tmp_path):
        assert bluetooth_installed(str(tmp_path / "nonexistent.service")) is False

    def test_env_var_override(self, tmp_path, monkeypatch):
        unit = tmp_path / "autostream_bluetooth.service"
        unit.write_text("[Unit]\n", encoding="utf-8")
        monkeypatch.setenv("AUTOSTREAM_BT_UNIT_PATH", str(unit))
        assert bluetooth_installed() is True

    def test_env_var_override_absent(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AUTOSTREAM_BT_UNIT_PATH", str(tmp_path / "gone.service"))
        assert bluetooth_installed() is False


# ---------------------------------------------------------------------------
# bluetooth_services_enabled()
# ---------------------------------------------------------------------------

class TestBluetoothServicesEnabled:
    def test_enabled_when_systemctl_returns_zero(self):
        with patch("autostream_bluetooth_client.subprocess.run",
                   return_value=MagicMock(returncode=0)) as m_run:
            assert bluetooth_services_enabled() is True
        args = m_run.call_args[0][0]
        assert args[:3] == ["systemctl", "is-enabled", "--quiet"]
        assert "autostream_bluetooth" in args

    def test_disabled_when_systemctl_returns_nonzero(self):
        with patch("autostream_bluetooth_client.subprocess.run",
                   return_value=MagicMock(returncode=1)):
            assert bluetooth_services_enabled() is False

    def test_disabled_when_systemctl_absent(self):
        with patch("autostream_bluetooth_client.subprocess.run", side_effect=OSError("no such file")):
            assert bluetooth_services_enabled() is False

    def test_disabled_on_timeout(self):
        import subprocess as _sp
        with patch("autostream_bluetooth_client.subprocess.run",
                   side_effect=_sp.TimeoutExpired(cmd="systemctl", timeout=3)):
            assert bluetooth_services_enabled() is False

    def test_custom_unit_name_used(self):
        with patch("autostream_bluetooth_client.subprocess.run",
                   return_value=MagicMock(returncode=0)) as m_run:
            bluetooth_services_enabled("custom_unit")
        assert "custom_unit" in m_run.call_args[0][0]


# ---------------------------------------------------------------------------
# bluetooth_onboard_enabled()
# ---------------------------------------------------------------------------

class TestBluetoothOnboardEnabled:
    def test_enabled_when_no_disable_line(self, tmp_path):
        cfg = tmp_path / "config.txt"
        cfg.write_text("dtparam=audio=on\n", encoding="utf-8")
        assert bluetooth_onboard_enabled(str(cfg)) is True

    def test_disabled_when_overlay_line_present(self, tmp_path):
        cfg = tmp_path / "config.txt"
        cfg.write_text("dtparam=audio=on\ndtoverlay=disable-bt\n", encoding="utf-8")
        assert bluetooth_onboard_enabled(str(cfg)) is False

    def test_disabled_when_overlay_line_has_whitespace(self, tmp_path):
        cfg = tmp_path / "config.txt"
        cfg.write_text("  dtoverlay=disable-bt  \n", encoding="utf-8")
        assert bluetooth_onboard_enabled(str(cfg)) is False

    def test_missing_file_defaults_disabled(self, tmp_path):
        assert bluetooth_onboard_enabled(str(tmp_path / "nonexistent.txt")) is False

    def test_env_var_override(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config.txt"
        cfg.write_text("dtoverlay=disable-bt\n", encoding="utf-8")
        monkeypatch.setenv("AUTOSTREAM_BOOT_CONFIG_PATH", str(cfg))
        assert bluetooth_onboard_enabled() is False


# ---------------------------------------------------------------------------
# classify_loopback_hw()
# ---------------------------------------------------------------------------

class TestClassifyLoopbackHw:
    def test_playback_side(self):
        assert classify_loopback_hw(BLUETOOTH_PLAYBACK_DEVICE) == "playback"

    def test_capture_side(self):
        assert classify_loopback_hw(BLUETOOTH_CAPTURE_DEVICE) == "capture"

    def test_case_insensitive(self):
        assert classify_loopback_hw("hw:card=asbt,dev=1") == "capture"

    def test_unrelated_hw_returns_none(self):
        assert classify_loopback_hw("hw:0,0") is None
        assert classify_loopback_hw("hw:CARD=Behringer,DEV=0") is None

    def test_empty_string_returns_none(self):
        assert classify_loopback_hw("") is None

    def test_unknown_subdevice_returns_none(self):
        assert classify_loopback_hw("hw:CARD=ASBT,DEV=2") is None


# ---------------------------------------------------------------------------
# bluetooth_capture_label()
# ---------------------------------------------------------------------------

class TestBluetoothCaptureLabel:
    def test_none_status_is_unavailable(self):
        assert bluetooth_capture_label(None) == "Bluetooth (service unavailable)"

    def test_ok_false_is_unavailable(self):
        assert bluetooth_capture_label({"ok": False}) == "Bluetooth (service unavailable)"

    def test_not_a_dict_is_unavailable(self):
        assert bluetooth_capture_label("nope") == "Bluetooth (service unavailable)"

    def test_ok_true_no_paired_is_not_paired(self):
        assert bluetooth_capture_label({"ok": True, "paired": None}) == "Bluetooth (not paired)"

    def test_ok_true_missing_paired_key_is_not_paired(self):
        assert bluetooth_capture_label({"ok": True}) == "Bluetooth (not paired)"

    def test_paired_with_name(self):
        status = {"ok": True, "paired": {"mac": "AA:BB:CC:DD:EE:FF", "name": "Technics SL-1200"}}
        assert bluetooth_capture_label(status) == "Bluetooth: Technics SL-1200"

    def test_paired_with_blank_name_falls_back(self):
        status = {"ok": True, "paired": {"mac": "AA:BB:CC:DD:EE:FF", "name": "  "}}
        assert bluetooth_capture_label(status) == "Bluetooth (not paired)"
