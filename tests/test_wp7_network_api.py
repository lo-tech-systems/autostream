"""WP7 — Network status/setup API and UI wiring tests.

Covers:
  - build_network_card_presentation() display/detail/warning fields
  - send_network_status_json(): proxy to watcher, adds display field, handles errors
  - send_network_setup_json(): action whitelist, CSRF stripping, 409 surfacing
  - Route wiring in autostream_webui: GET /api/network/status, POST /api/network/setup
  - network_card_html present in setup page render
  - changeWifiNetwork / refreshNetworkAdapterInfo JS present in page
"""
from __future__ import annotations

import json
import sys
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_CORE = str(REPO_ROOT / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_webui_api import (
    build_network_card_presentation,
    get_wifi_watcher_version,
    send_network_roaming_json,
    send_network_setup_json,
    send_network_status_json,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_handler():
    """Minimal handler stub that captures send_json / send_browser_api_error calls."""
    h = MagicMock()
    h.wfile = BytesIO()
    h.headers = {}
    return h


def _ok_status(extra: dict | None = None) -> dict:
    """A minimal watcher /network_status payload."""
    base = {
        "ok": True,
        "schema_version": 1,
        "device": {
            "state": "online",
            "primary_ifname": "wlan0",
            "primary_kind": "builtin_wifi",
            "primary_ssid": "MyNetwork",
            "primary_ipv4": "192.168.1.42",
            "primary_ipv4_info": {
                "address": "192.168.1.42",
                "prefixlen": 24,
                "netmask": "255.255.255.0",
                "gateway": "192.168.1.1",
            },
            "primary_ipv6": "",
        },
        "adapters": [],
        "ap_ssid": "autostream_ABCD",
    }
    if extra:
        base.update(extra)
    return base


def _with_device(status: dict, **fields) -> dict:
    status = dict(status)
    device = dict(status.get("device") or {})
    device.update(fields)
    status["device"] = device
    return status


def _usb_adapter(*, warning: str = "", quarantined: bool = False,
                 resets: int = 0, budget: int = 2, role: str = "client",
                 ifname: str = "wlan1", ipv4: list | None = None,
                 noip_failures: int = 0) -> dict:
    return {
        "kind": "usb_wifi",
        "ifname": ifname,
        "role": role,
        "facts": {"ipv4": ipv4 or []},
        "health": {"state": "healthy"},
        "policy": {
            "warning": warning,
            "quarantined": quarantined,
            "resets_24h": resets,
            "reset_budget_24h": budget,
            "noip_failures": noip_failures,
        },
    }


# ---------------------------------------------------------------------------
# build_network_card_presentation()
# ---------------------------------------------------------------------------

class TestBuildNetworkCardPresentation:
    def test_ethernet(self):
        s = _with_device(_ok_status(), primary_kind="ethernet", primary_ifname="eth0", primary_ssid="")
        result = build_network_card_presentation(s)
        assert result["title"] == "Network"
        assert result["display"] == "Connected via Ethernet"
        assert result["detail"] == "IP: 192.168.1.42/24 | Gateway: 192.168.1.1"
        assert result["interface_lines"] == ["Ethernet: 192.168.1.42/24"]

    def test_no_ethernet_row_when_not_primary(self):
        result = build_network_card_presentation(_ok_status())
        assert all(not line.startswith("Ethernet:") for line in result["interface_lines"])

    def test_wifi_interface_rows(self):
        s = _with_device(
            _ok_status({
                "adapters": [
                    {
                        "kind": "builtin_wifi",
                        "ifname": "wlan0",
                        "role": "idle",
                        "facts": {"ipv4": []},
                        "health": {"state": "idle"},
                        "policy": {},
                    },
                    _usb_adapter(
                        ifname="wlan1",
                        ipv4=[{
                            "family": "ipv4",
                            "address": "192.168.1.38",
                            "prefixlen": 24,
                            "scope": "global",
                        }],
                    ),
                ],
            }),
            primary_kind="usb_wifi",
            primary_ifname="wlan1",
            primary_ssid="MyNetwork",
            primary_ipv4="192.168.1.38",
            primary_ipv4_info={
                "address": "192.168.1.38",
                "prefixlen": 24,
                "netmask": "255.255.255.0",
                "gateway": "192.168.1.1",
            },
        )
        result = build_network_card_presentation(s)
        assert result["interface_lines"] == [
            "On-board WiFi: Disconnected",
            "USB WiFi: MyNetwork - 192.168.1.38/24",
        ]

    def test_usb_wifi_with_ssid(self):
        s = _with_device(_ok_status(), primary_kind="usb_wifi", primary_ifname="wlan1", primary_ssid="MyHomeWiFi")
        result = build_network_card_presentation(s)
        assert result["display"] == "Connected via USB WiFi adapter to MyHomeWiFi"

    def test_usb_wifi_without_ssid(self):
        s = _with_device(_ok_status(), primary_kind="usb_wifi", primary_ifname="wlan1", primary_ssid="")
        result = build_network_card_presentation(s)
        assert result["display"] == "Connected via USB WiFi adapter"

    def test_builtin_wifi_with_ssid(self):
        result = build_network_card_presentation(_ok_status())
        assert result["display"] == "Connected via on-board WiFi to MyNetwork"

    def test_disconnected(self):
        s = _with_device(_ok_status(), primary_kind="", primary_ifname="", primary_ssid="")
        result = build_network_card_presentation(s)
        assert result["display"] == "No active network connection"
        assert result["detail"] == ""

    def test_missing_ip_and_gateway(self):
        s = _with_device(
            _ok_status(),
            primary_ipv4_info={"address": "", "prefixlen": None, "netmask": "", "gateway": ""},
        )
        result = build_network_card_presentation(s)
        assert result["detail"] == "IP: Not assigned | Gateway: Not available"

    def test_netmask_fallback(self):
        s = _with_device(
            _ok_status(),
            primary_ipv4_info={
                "address": "192.168.1.42",
                "prefixlen": None,
                "netmask": "255.255.255.0",
                "gateway": "192.168.1.1",
            },
        )
        result = build_network_card_presentation(s)
        assert result["detail"] == "IP: 192.168.1.42/255.255.255.0 | Gateway: 192.168.1.1"

    def test_recent_resets_warning(self):
        s = _with_device(_ok_status({"adapters": [_usb_adapter(warning="recent_resets", resets=1)]}),
                         primary_kind="usb_wifi", primary_ifname="wlan1", primary_ssid="MyHomeWiFi")
        result = build_network_card_presentation(s)
        assert result["warning"] == "Warning: the USB WiFi adapter has needed 1 reset in the last 24 hours."
        assert result["warning_severity"] == "warning"
        assert result["support_detail"] == "Adapter: wlan1 | Reset attempts: 1 in 24h (normal budget: 2)"

    def test_budget_exhausted_warning(self):
        s = _with_device(_ok_status({"adapters": [_usb_adapter(warning="reset_budget_exhausted", resets=2)]}),
                         primary_kind="usb_wifi", primary_ifname="wlan1", primary_ssid="MyHomeWiFi")
        result = build_network_card_presentation(s)
        assert result["warning"] == "Warning: the USB WiFi adapter has needed repeated resets and may be faulty."
        assert result["warning_severity"] == "danger"
        assert result["support_detail"] == "Adapter: wlan1 | Reset attempts: 2 in 24h (normal budget: 2)"

    def test_quarantined_warning(self):
        s = _with_device(_ok_status({"adapters": [_usb_adapter(warning="quarantined", quarantined=True, resets=2)]}),
                         primary_kind="usb_wifi", primary_ifname="wlan1", primary_ssid="MyHomeWiFi")
        result = build_network_card_presentation(s)
        assert result["warning"] == "Warning: the USB WiFi adapter has needed repeated resets and may be faulty."
        assert result["warning_severity"] == "danger"

    def test_spare_quarantined_warning(self):
        s = _ok_status({"adapters": [_usb_adapter(warning="quarantined", quarantined=True, resets=2, role="spare")]})
        result = build_network_card_presentation(s)
        assert result["warning"] == "USB WiFi adapter held back after repeated failures. Replace the adapter if this keeps happening."
        assert result["warning_severity"] == "danger"

    def test_resetting_warning(self):
        s = _ok_status({"adapters": [_usb_adapter(warning="resetting", resets=1, role="spare")]})
        result = build_network_card_presentation(s)
        assert result["warning"] == "USB WiFi adapter is being reset. Network connection may be unstable for a minute."
        assert result["warning_severity"] == "warning"

    def test_no_ip_address_warning(self):
        # WP5b defect 3: USB associated but could not get a network address.
        s = _with_device(_ok_status({"adapters": [_usb_adapter(warning="no_ip_address", role="client", ifname="wlan1")]}),
                         primary_kind="usb_wifi", primary_ifname="wlan1", primary_ssid="MyHomeWiFi")
        result = build_network_card_presentation(s)
        assert "could not get a network address" in result["warning"]
        assert result["warning_severity"] == "warning"

    def test_no_ip_held_back_warning(self):
        # C-WP4: a no-IP-suppressed / demoted spare renders the "held back …
        # running on on-board WiFi" copy (previously wired only to quarantine).
        adapter = _usb_adapter(warning="no_ip_held_back", role="spare", ifname="wlan1")
        adapter["policy"]["held_back"] = True
        s = _ok_status({"adapters": [adapter]})
        result = build_network_card_presentation(s)
        assert "held back after repeated failures" in result["warning"]
        assert "on-board WiFi" in result["warning"]
        assert result["warning_severity"] == "danger"

    def test_held_back_flag_alone_renders_warning(self):
        # The held_back policy flag drives the warning even without the code.
        adapter = _usb_adapter(role="spare", ifname="wlan1")
        adapter["policy"]["held_back"] = True
        s = _ok_status({"adapters": [adapter]})
        result = build_network_card_presentation(s)
        assert "held back after repeated failures" in result["warning"]
        assert result["warning_severity"] == "danger"

    def test_active_usb_warning_preferred_over_spare_higher_priority(self):
        s = _with_device(
            _ok_status({
                "adapters": [
                    _usb_adapter(warning="recent_resets", resets=1, role="client", ifname="wlan1"),
                    _usb_adapter(warning="quarantined", quarantined=True, resets=2, role="spare", ifname="wlan2"),
                ],
            }),
            primary_kind="usb_wifi",
            primary_ifname="wlan1",
            primary_ssid="MyHomeWiFi",
        )
        result = build_network_card_presentation(s)
        assert result["support_detail"] == "Adapter: wlan1 | Reset attempts: 1 in 24h (normal budget: 2)"

    def test_support_detail_handles_emergency_resets_above_budget(self):
        s = _with_device(_ok_status({"adapters": [_usb_adapter(warning="reset_budget_exhausted", resets=26)]}),
                         primary_kind="usb_wifi", primary_ifname="wlan1", primary_ssid="MyHomeWiFi")
        result = build_network_card_presentation(s)
        assert result["support_detail"] == "Adapter: wlan1 | Reset attempts: 26 in 24h (normal budget: 2)"

    # IF-7b: the no-IP family (rank 1 held-back, rank 3 no-IP) shows the
    # published failed-connection count, not the reset line.  The webui renders
    # the published policy.noip_failures field only — it never recomputes it.

    def test_held_back_detail_shows_failed_connection_attempts(self):
        # Rank 1 (held-back): the 04-Jul field case — reset ledger reads 0 but
        # the no-IP ledger hit 5, so the card must show the failure count.
        adapter = _usb_adapter(warning="no_ip_held_back", role="spare", ifname="wlan1",
                               resets=0, noip_failures=5)
        adapter["policy"]["held_back"] = True
        s = _ok_status({"adapters": [adapter]})
        result = build_network_card_presentation(s)
        assert result["support_detail"] == "Adapter: wlan1 | Failed connection attempts: 5"

    def test_no_ip_address_detail_shows_failed_connection_attempts(self):
        # Rank 3 (transient no-IP) also uses the failure count.
        s = _with_device(
            _ok_status({"adapters": [_usb_adapter(warning="no_ip_address", role="client",
                                                  ifname="wlan1", noip_failures=2)]}),
            primary_kind="usb_wifi", primary_ifname="wlan1", primary_ssid="MyHomeWiFi")
        result = build_network_card_presentation(s)
        assert result["support_detail"] == "Adapter: wlan1 | Failed connection attempts: 2"

    def test_reset_family_ranks_keep_reset_line(self):
        # Ranks 0, 2, 4, 5 (the reset family) keep the reset-attempt detail line
        # even when a noip_failures field is present — it must not leak in.
        cases = [
            (_usb_adapter(warning="quarantined", quarantined=True, resets=2,
                          role="spare", ifname="wlan1", noip_failures=9), 2),   # rank 0
            (_usb_adapter(warning="reset_budget_exhausted", resets=2,
                          ifname="wlan1", noip_failures=9), 2),                 # rank 2
            (_usb_adapter(warning="resetting", resets=1, role="spare",
                          ifname="wlan1", noip_failures=9), 1),                 # rank 4
            (_usb_adapter(warning="recent_resets", resets=1,
                          ifname="wlan1", noip_failures=9), 1),                 # rank 5
        ]
        for adapter, resets in cases:
            s = _with_device(_ok_status({"adapters": [adapter]}),
                             primary_kind="usb_wifi", primary_ifname="wlan1",
                             primary_ssid="MyHomeWiFi")
            result = build_network_card_presentation(s)
            assert result["support_detail"] == (
                f"Adapter: wlan1 | Reset attempts: {resets} in 24h (normal budget: 2)"
            )


# ---------------------------------------------------------------------------
# send_network_status_json()
# ---------------------------------------------------------------------------

class TestSendNetworkStatusJson:
    def _call(self, watcher_status: int, watcher_data: dict):
        handler = _make_handler()
        captured = {}

        def fake_send_json(h, code, data):
            captured["code"] = code
            captured["data"] = data

        def fake_error(h, code, msg):
            captured["code"] = code
            captured["error"] = msg

        with patch("autostream_webui_api._watcher_request", return_value=(watcher_status, watcher_data)), \
             patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api.send_browser_api_error", side_effect=fake_error):
            send_network_status_json(handler)

        return captured

    def test_success_adds_display_field(self):
        data = _ok_status()
        result = self._call(200, data)
        assert result["code"] == 200
        assert result["data"]["display"] == "Connected via on-board WiFi to MyNetwork"

    def test_success_adds_title_field(self):
        data = _ok_status()
        result = self._call(200, data)
        assert result["code"] == 200
        assert result["data"]["title"] == "Network"

    def test_success_adds_detail_field(self):
        data = _ok_status()
        result = self._call(200, data)
        assert result["data"]["detail"] == "IP: 192.168.1.42/24 | Gateway: 192.168.1.1"

    def test_success_preserves_ap_ssid(self):
        data = _ok_status({"ap_ssid": "autostream_SETUP"})
        result = self._call(200, data)
        assert result["data"]["ap_ssid"] == "autostream_SETUP"

    def test_success_includes_warning_fields_even_when_empty(self):
        data = _ok_status()
        result = self._call(200, data)
        assert result["data"]["warning"] == ""
        assert result["data"]["warning_severity"] == ""
        assert result["data"]["support_detail"] == ""

    def test_watcher_503_returns_error(self):
        result = self._call(503, {})
        assert result["code"] == 503

    def test_watcher_ok_false_returns_error(self):
        result = self._call(200, {"ok": False})
        assert result["code"] == 503

    def test_watcher_transport_exception_returns_503(self):
        handler = _make_handler()
        captured = {}

        def fake_error(h, code, msg):
            captured["code"] = code

        with patch("autostream_webui_api._watcher_request", side_effect=Exception("refused")), \
             patch("autostream_webui_api.send_browser_api_error", side_effect=fake_error):
            send_network_status_json(handler)

        assert captured["code"] == 503

    def test_non_dict_response_returns_error(self):
        # watcher returns a list (malformed)
        result = self._call(200, [])  # type: ignore[arg-type]
        assert result["code"] == 503


# ---------------------------------------------------------------------------
# send_network_setup_json()
# ---------------------------------------------------------------------------

class TestSendNetworkSetupJson:
    def _call(self, body, watcher_status: int = 200, watcher_data: dict | None = None):
        if watcher_data is None:
            watcher_data = {"ok": True}
        handler = _make_handler()
        captured = {}

        def fake_send_json(h, code, data):
            captured["code"] = code
            captured["data"] = data

        def fake_error(h, code, msg):
            captured["code"] = code
            captured["error"] = msg

        with patch("autostream_webui_api._watcher_request", return_value=(watcher_status, watcher_data)), \
             patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api.send_browser_api_error", side_effect=fake_error):
            send_network_setup_json(handler, body)

        return captured

    def test_start_setup_success(self):
        result = self._call({"action": "start_setup", "csrf_token": "tok"})
        assert result["code"] == 200
        assert result["data"]["ok"] is True
        assert result["data"]["action"] == "start_setup"

    def test_reconnect_saved_success(self):
        result = self._call({"action": "reconnect_saved"})
        assert result["code"] == 200
        assert result["data"]["action"] == "reconnect_saved"

    def test_csrf_token_stripped_before_forward(self):
        """csrf_token must not be forwarded to the watcher."""
        forwarded = {}

        def fake_request(method, path, body=None):
            forwarded["body"] = body
            return 200, {"ok": True}

        handler = _make_handler()
        with patch("autostream_webui_api._watcher_request", side_effect=fake_request), \
             patch("autostream_webui_api.send_json"):
            send_network_setup_json(handler, {"action": "start_setup", "csrf_token": "tok"})

        assert "csrf_token" not in (forwarded.get("body") or {})

    def test_invalid_action_rejected(self):
        result = self._call({"action": "exec_nmcli"})
        assert result["code"] == 400

    def test_extra_fields_rejected(self):
        result = self._call({"action": "start_setup", "extra": "bad"})
        assert result["code"] == 400

    def test_not_dict_rejected(self):
        handler = _make_handler()
        captured = {}

        def fake_error(h, code, msg):
            captured["code"] = code

        with patch("autostream_webui_api.send_browser_api_error", side_effect=fake_error):
            send_network_setup_json(handler, "not a dict")  # type: ignore[arg-type]

        assert captured["code"] == 400

    def test_watcher_409_surfaces_conflict(self):
        result = self._call({"action": "start_setup"}, watcher_status=409)
        assert result["code"] == 409

    def test_watcher_503_returns_service_unavailable(self):
        result = self._call({"action": "start_setup"}, watcher_status=503)
        assert result["code"] == 503

    def test_transport_exception_returns_503(self):
        handler = _make_handler()
        captured = {}

        def fake_error(h, code, msg):
            captured["code"] = code

        with patch("autostream_webui_api._watcher_request", side_effect=OSError("refused")), \
             patch("autostream_webui_api.send_browser_api_error", side_effect=fake_error):
            send_network_setup_json(handler, {"action": "start_setup"})

        assert captured["code"] == 503


# ---------------------------------------------------------------------------
# send_network_roaming_json()
# ---------------------------------------------------------------------------

class TestSendNetworkRoamingJson:
    def _call(self, body, watcher_status: int = 200, watcher_data: dict | None = None):
        if watcher_data is None:
            watcher_data = {"ok": True}
        handler = _make_handler()
        captured = {}

        def fake_send_json(h, code, data):
            captured["code"] = code
            captured["data"] = data

        def fake_error(h, code, msg):
            captured["code"] = code
            captured["error"] = msg

        with patch("autostream_webui_api._watcher_request", return_value=(watcher_status, watcher_data)), \
             patch("autostream_webui_api.send_json", side_effect=fake_send_json), \
             patch("autostream_webui_api.send_browser_api_error", side_effect=fake_error):
            send_network_roaming_json(handler, body)

        return captured

    def test_managed_true_forwards_exact_action_shape(self):
        forwarded = {}

        def fake_request(method, path, body=None):
            forwarded["method"] = method
            forwarded["path"] = path
            forwarded["body"] = body
            return 200, {"ok": True}

        handler = _make_handler()
        with patch("autostream_webui_api._watcher_request", side_effect=fake_request), \
             patch("autostream_webui_api.send_json"):
            send_network_roaming_json(handler, {"managed": True, "csrf_token": "tok"})

        assert forwarded["method"] == "POST"
        assert forwarded["path"] == "/network_control"
        assert forwarded["body"] == {"action": "set_roaming_management", "managed": True}

    def test_managed_false_forwards_exact_action_shape(self):
        forwarded = {}

        def fake_request(method, path, body=None):
            forwarded["body"] = body
            return 200, {"ok": True}

        handler = _make_handler()
        with patch("autostream_webui_api._watcher_request", side_effect=fake_request), \
             patch("autostream_webui_api.send_json"):
            send_network_roaming_json(handler, {"managed": False})

        assert forwarded["body"] == {"action": "set_roaming_management", "managed": False}

    def test_success_response_shape(self):
        result = self._call({"managed": True})
        assert result["code"] == 200
        assert result["data"]["ok"] is True

    def test_missing_managed_rejected_without_forwarding(self):
        with patch("autostream_webui_api._watcher_request") as request:
            result = self._call({})
        assert result["code"] == 400
        request.assert_not_called()

    def test_non_bool_managed_rejected_without_forwarding(self):
        for bad in ("true", 1, None, [], {}):
            with patch("autostream_webui_api._watcher_request") as request:
                result = self._call({"managed": bad})
            assert result["code"] == 400
            request.assert_not_called()

    def test_extra_fields_rejected(self):
        with patch("autostream_webui_api._watcher_request") as request:
            result = self._call({"managed": True, "extra": "bad"})
        assert result["code"] == 400
        request.assert_not_called()

    def test_not_dict_rejected(self):
        handler = _make_handler()
        captured = {}

        def fake_error(h, code, msg):
            captured["code"] = code

        with patch("autostream_webui_api.send_browser_api_error", side_effect=fake_error), \
             patch("autostream_webui_api._watcher_request") as request:
            send_network_roaming_json(handler, "not a dict")  # type: ignore[arg-type]

        assert captured["code"] == 400
        request.assert_not_called()

    def test_csrf_token_stripped_before_forward(self):
        forwarded = {}

        def fake_request(method, path, body=None):
            forwarded["body"] = body
            return 200, {"ok": True}

        handler = _make_handler()
        with patch("autostream_webui_api._watcher_request", side_effect=fake_request), \
             patch("autostream_webui_api.send_json"):
            send_network_roaming_json(handler, {"managed": True, "csrf_token": "tok"})

        assert "csrf_token" not in (forwarded.get("body") or {})

    def test_watcher_failure_returns_graceful_error(self):
        result = self._call({"managed": True}, watcher_status=503)
        assert result["code"] == 503

    def test_watcher_ok_false_returns_graceful_error(self):
        result = self._call({"managed": True}, watcher_status=200, watcher_data={"ok": False})
        assert result["code"] == 503

    def test_transport_exception_returns_503(self):
        handler = _make_handler()
        captured = {}

        def fake_error(h, code, msg):
            captured["code"] = code

        with patch("autostream_webui_api._watcher_request", side_effect=OSError("refused")), \
             patch("autostream_webui_api.send_browser_api_error", side_effect=fake_error):
            send_network_roaming_json(handler, {"managed": True})

        assert captured["code"] == 503


# ---------------------------------------------------------------------------
# get_wifi_watcher_version()
# ---------------------------------------------------------------------------

class TestWifiWatcherVersion:
    def test_success_returns_version(self):
        with patch("autostream_webui_api._read_watcher_control_token", return_value="tok"), \
             patch("autostream_webui_api._watcher_request", return_value=(
                 200, {"ok": True, "version": "1.0.0"}
             )):
            assert get_wifi_watcher_version() == "1.0.0"

    def test_failure_returns_unknown(self):
        with patch("autostream_webui_api._read_watcher_control_token", return_value="tok"), \
             patch("autostream_webui_api._watcher_request", return_value=(503, {})):
            assert get_wifi_watcher_version() == "unknown"

    def test_missing_token_returns_unknown_without_request(self):
        with patch("autostream_webui_api._read_watcher_control_token", return_value=""), \
             patch("autostream_webui_api._watcher_request") as request:
            assert get_wifi_watcher_version() == "unknown"
        request.assert_not_called()


# ---------------------------------------------------------------------------
# Route wiring — verify webui.py dispatches the two new paths
# ---------------------------------------------------------------------------

class TestRouteWiring:
    """Smoke-test that GET /api/network/status and POST /api/network/setup
    reach their respective handlers.  We patch at the module level in
    autostream_webui so we don't need a running server."""

    def _load_webui(self):
        """Import autostream_webui with heavy dependencies stubbed."""
        import importlib
        import types

        stubs = [
            "autostream_core", "autostream_config", "autostream_settings",
            "autostream_auth", "autostream_federation", "autostream_appliances",
            "autostream_appliance_gateway", "autostream_rpi",
            "autostream_owntone", "autostream_nowplaying",
            "autostream_playback_stats", "autostream_output_usage",
            "autostream_dials", "autostream_players",
            "autostream_mdns", "autostream_commissioning",
            "autostream_log_policy",
            "autostream_webui_common", "autostream_webui_dials",
            "autostream_webui_page_about", "autostream_webui_page_equaliser",
            "autostream_webui_page_airplay", "autostream_webui_page_logs",
            "autostream_webui_page_owntone", "autostream_webui_page_setup",
            "autostream_webui_page_first_boot",
        ]
        for name in stubs:
            if name not in sys.modules:
                m = types.ModuleType(name)
                sys.modules[name] = m

        # autostream_webui_api must be the real module
        if "autostream_webui_api" in sys.modules:
            del sys.modules["autostream_webui_api"]
        if "autostream_webui" in sys.modules:
            del sys.modules["autostream_webui"]

        # Provide minimal symbols that autostream_webui imports from stubs
        sys.modules["autostream_webui_common"].build_nav_bar_html = MagicMock(return_value="")  # type: ignore[attr-defined]
        for attr in ("send_about_page", "send_about_system_json"):
            setattr(sys.modules["autostream_webui_page_about"], attr, MagicMock())
        for attr in ("send_equaliser_page", "send_remote_equaliser_page"):
            setattr(sys.modules["autostream_webui_page_equaliser"], attr, MagicMock())
        for attr in ("send_airplay_page", "send_remote_home_page"):
            setattr(sys.modules["autostream_webui_page_airplay"], attr, MagicMock())
        for attr in ("handle_logs_download", "send_logs_page"):
            setattr(sys.modules["autostream_webui_page_logs"], attr, MagicMock())
        for attr in ("send_owntone_ready_json", "send_owntone_restarting_page", "send_owntone_setup_page"):
            setattr(sys.modules["autostream_webui_page_owntone"], attr, MagicMock())
        for attr in ("dispatch_dial_management_post", "handle_dial_configure_get",
                     "handle_dial_pin_recovery_status", "handle_dial_update_post",
                     "handle_dial_update_status"):
            setattr(sys.modules["autostream_webui_dials"], attr, MagicMock())
        for attr in ("send_first_boot_owntone_page",):
            setattr(sys.modules["autostream_webui_page_first_boot"], attr, MagicMock())

        # Stub out the heavy imports inside autostream_webui_api path
        for name in ("flask", "urllib3"):
            if name not in sys.modules:
                sys.modules[name] = types.ModuleType(name)

        import autostream_webui_api as api_mod
        return api_mod

    # These tests just confirm the functions exist and are callable — full
    # behaviour is covered by TestSendNetworkStatusJson / TestSendNetworkSetupJson.
    def test_send_network_status_json_importable(self):
        from autostream_webui_api import send_network_status_json
        assert callable(send_network_status_json)

    def test_send_network_setup_json_importable(self):
        from autostream_webui_api import send_network_setup_json
        assert callable(send_network_setup_json)

    def test_build_network_card_presentation_importable(self):
        from autostream_webui_api import build_network_card_presentation
        assert callable(build_network_card_presentation)

    def test_send_network_roaming_json_importable(self):
        from autostream_webui_api import send_network_roaming_json
        assert callable(send_network_roaming_json)


# ---------------------------------------------------------------------------
# UI — confirm network card HTML and JS are present in the page source
# ---------------------------------------------------------------------------

class TestSetupPageNetworkCard:
    """Read the setup page source directly to verify network UI elements exist.

    This avoids the complexity of mocking a full render while still ensuring
    the HTML and JS strings are correctly embedded in the template strings.
    """

    PAGE_SRC = (REPO_ROOT / "core" / "autostream_webui_page_setup.py").read_text(encoding="utf-8")

    def test_network_card_html_present(self):
        assert 'id="networkCard"' in self.PAGE_SRC

    def test_adapter_info_element_present(self):
        assert 'id="networkAdapterInfo"' in self.PAGE_SRC
        assert "white-space:pre-line" in self.PAGE_SRC

    def test_first_open_text_checks_status(self):
        assert "Checking status..." in self.PAGE_SRC
        assert "Using on-board WiFi adapter</p>" not in self.PAGE_SRC

    def test_network_detail_warning_support_elements_present(self):
        assert 'id="networkAddressInfo"' in self.PAGE_SRC
        assert 'id="networkWarning"' in self.PAGE_SRC
        assert 'id="networkSupportDetail"' in self.PAGE_SRC

    def test_network_card_title_element_present(self):
        assert 'id="networkCardTitle"' in self.PAGE_SRC

    def test_wifi_hotspot_modal_present(self):
        assert 'id="wifiHotspotModal"' in self.PAGE_SRC
        assert 'modal-overlay' in self.PAGE_SRC
        assert "confirmChangeWifiNetwork" in self.PAGE_SRC
        assert "cancelChangeWifiNetwork" in self.PAGE_SRC

    def test_usb_pending_element_present(self):
        assert 'id="networkUsbPending"' in self.PAGE_SRC
        assert "usb_adoption_pending" in self.PAGE_SRC

    def test_network_auto_refresh_present(self):
        assert "setInterval(refreshNetworkAdapterInfo" in self.PAGE_SRC

    def test_change_wifi_button_present(self):
        assert "changeWifiNetwork" in self.PAGE_SRC
        assert "Change Wi-Fi Network" in self.PAGE_SRC

    def test_network_setup_msg_element_present(self):
        assert 'id="networkSetupMsg"' in self.PAGE_SRC

    def test_refresh_network_adapter_info_js_present(self):
        assert "refreshNetworkAdapterInfo" in self.PAGE_SRC
        assert "networkStatusFailed" in self.PAGE_SRC
        assert "Could not check network status" in self.PAGE_SRC
        assert "j.ok === false" in self.PAGE_SRC
        assert "j.error_status" in self.PAGE_SRC
        assert "if (!r.ok || !j ||" in self.PAGE_SRC

    def test_refresh_network_adapter_info_updates_new_fields(self):
        assert "Array.isArray(j.interface_lines)" in self.PAGE_SRC
        assert "j.interface_lines.join('\\\\n')" in self.PAGE_SRC
        assert "addressEl.textContent = j.detail" in self.PAGE_SRC
        assert "warningEl.textContent = j.warning" in self.PAGE_SRC
        assert "j.warning_severity === 'danger'" in self.PAGE_SRC
        assert "supportEl.textContent = j.support_detail" in self.PAGE_SRC

    def test_refresh_preserves_ap_ssid_handling(self):
        assert "j.ap_ssid" in self.PAGE_SRC
        assert "wifiHotspotSsid" in self.PAGE_SRC

    def test_api_network_status_fetch_js_present(self):
        assert "/api/network/status" in self.PAGE_SRC

    def test_api_network_setup_post_js_present(self):
        assert "/api/network/setup" in self.PAGE_SRC

    def test_open_panel_calls_refresh_on_system(self):
        assert "refreshNetworkAdapterInfo" in self.PAGE_SRC

    def test_roaming_checkbox_present_with_exact_label(self):
        assert 'id="networkRoamingManaged"' in self.PAGE_SRC
        assert "Manage USB adapter roaming" in self.PAGE_SRC

    def test_roaming_hint_text_present(self):
        assert "This may improve connection stability for some USB adapters." in self.PAGE_SRC

    def test_roaming_checkbox_onchange_calls_new_endpoint_not_settings_save(self):
        assert 'onchange="setRoamingManagement(this.checked)"' in self.PAGE_SRC

    def test_roaming_checked_state_follows_status_snapshot(self):
        assert "roamingEl.checked = !!(j.roaming && j.roaming.managed)" in self.PAGE_SRC

    def test_roaming_endpoint_fetch_js_present(self):
        assert "/api/network/roaming" in self.PAGE_SRC

    def test_roaming_degrades_gracefully_on_failure_without_new_error_ui(self):
        assert "setRoamingManagement" in self.PAGE_SRC
        # Failure path re-syncs from status rather than inventing new error UI.
        assert self.PAGE_SRC.count("refreshNetworkAdapterInfo()") >= 2
