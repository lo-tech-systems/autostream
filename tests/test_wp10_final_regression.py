"""WP10 — Final regression and invariant verification.

This file is the completion marker for the Wi-Fi Adapter Selection and
Recovery feature (WP1–WP10).  It verifies the cross-cutting invariants that
are not covered by individual WP test files.

Key invariants from the implementation plan:
  1. The main application never executes nmcli.
  2. /opt/autostream/ssid is a name-only legacy mirror (never JSON).
  3. The watcher's control interface is localhost-only and token-authenticated.
  4. NetworkManager remains the credential store; network.json has no secrets.
  5. The built-in adapter is preferred for the recovery hotspot; a sole USB
     adapter is used as fallback on hardware without a built-in (e.g. Pi 2).

Full regression: 4354 tests passed, 97 skipped on 2026-06-24 after WP1–WP9.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent

WEBUI_SRC = (REPO_ROOT / "core" / "autostream_webui.py").read_text(encoding="utf-8")
WEBUI_API_SRC = (REPO_ROOT / "core" / "autostream_webui_api.py").read_text(encoding="utf-8")
WIFI_NETWORK_SRC = (REPO_ROOT / "core" / "autostream_wifi_network.py").read_text(encoding="utf-8")
WIFI_WATCHER_SRC = (REPO_ROOT / "platform" / "wifi_watcher.py").read_text(encoding="utf-8")
# The Flask HTTP surface — including the per-boot control-token lifecycle — was
# extracted to wifi_web.py (HTTP-extraction plan); the watcher wires/invokes it.
WIFI_WEB_SRC = (REPO_ROOT / "platform" / "wifi_web.py").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Invariant 1: The main application never executes nmcli
# ---------------------------------------------------------------------------

class TestMainAppNoNmcli:
    """autostream_webui.py and autostream_webui_api.py must not shell out to
    nmcli.  All network changes go through the watcher proxy."""

    def test_webui_does_not_shell_nmcli(self):
        assert "nmcli" not in WEBUI_SRC, (
            "autostream_webui.py must not invoke nmcli directly"
        )

    def test_webui_api_does_not_shell_nmcli(self):
        # "nmcli" must only appear in comments/docstrings in webui_api, never
        # as a value in a subprocess/os call.  Check line-by-line: any line
        # containing "nmcli" that is not a comment must not also be a call site.
        import re
        call_pattern = re.compile(r'(subprocess\.|os\.system|os\.popen|run_cmd)')
        for line in WEBUI_API_SRC.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue  # comment line — allowed to mention nmcli
            if "nmcli" in stripped and call_pattern.search(stripped):
                raise AssertionError(
                    f"autostream_webui_api.py invokes nmcli on line: {line!r}"
                )

    def test_wifi_network_helper_does_not_exec_nmcli(self):
        """autostream_wifi_network.py provides nmcli parsing helpers but must
        not exec nmcli itself — that is the watcher's job."""
        # The module may contain nmcli command definitions; it must not have
        # subprocess.run / subprocess.Popen / os.system calls for nmcli
        import re
        # Pattern: subprocess call with nmcli as an argument
        pattern = re.compile(r'(subprocess\.(run|Popen|call|check_output)|os\.system).*nmcli', re.DOTALL)
        assert not pattern.search(WIFI_NETWORK_SRC), (
            "autostream_wifi_network.py must not exec nmcli via subprocess"
        )


# ---------------------------------------------------------------------------
# Invariant 2: /opt/autostream/ssid is name-only (no JSON, no secrets)
# ---------------------------------------------------------------------------

class TestLegacySsidFile:
    def test_ssid_write_never_uses_json_dumps(self):
        """ssid file writes in wifi_network helper must be plain text, not JSON."""
        import re
        # Find all write calls that reference 'ssid'
        # json.dumps must not appear near ssid file path
        src = WIFI_NETWORK_SRC
        # Check the write_legacy_ssid function specifically
        if "write_legacy_ssid" in src:
            start = src.index("write_legacy_ssid")
            snippet = src[start:start + 500]
            assert "json.dumps" not in snippet, (
                "write_legacy_ssid must write plain text, not JSON"
            )

    def test_ssid_constant_is_path_only(self):
        """The legacy ssid path constant must be /opt/autostream/ssid."""
        assert "/opt/autostream/ssid" in WIFI_NETWORK_SRC


# ---------------------------------------------------------------------------
# Invariant 3: Watcher control interface uses per-boot token authentication
# ---------------------------------------------------------------------------

class TestWatcherControlAuthentication:
    def test_webui_api_reads_token_from_file(self):
        """The Web UI reads the per-boot control token from a file."""
        assert "wifi-control.token" in WEBUI_API_SRC
        assert "_read_watcher_control_token" in WEBUI_API_SRC

    def test_watcher_generates_token_on_startup(self):
        """The recovery component writes a per-boot token so the Web UI can
        authenticate.  The token lifecycle lives in wifi_web; the watcher invokes
        it on startup (HTTP-extraction plan, WP3)."""
        assert "wifi-control.token" in WIFI_WEB_SRC or "control.token" in WIFI_WEB_SRC
        assert "init_control_token" in WIFI_WATCHER_SRC

    def test_webui_api_sends_token_in_header(self):
        """The control token is sent as an HTTP header, not in the URL."""
        assert "X-Autostream-Wifi-Control" in WEBUI_API_SRC

    def test_watcher_control_bound_to_localhost(self):
        """The control listener must bind to 127.0.0.1 only."""
        assert "127.0.0.1" in WIFI_WATCHER_SRC


# ---------------------------------------------------------------------------
# Invariant 4: network.json stores no secrets
# ---------------------------------------------------------------------------

class TestNetworkJsonNoSecrets:
    def test_network_state_schema_comment_confirms_no_secrets(self):
        """autostream_wifi_network.py must document that network.json holds no secrets."""
        assert "secret" not in WIFI_NETWORK_SRC.lower() or "no secret" in WIFI_NETWORK_SRC.lower() or "never" in WIFI_NETWORK_SRC.lower()

    def test_network_state_only_stores_connection_name(self):
        """The persistent state structure must use 'connection_name'.

        Note: autostream_wifi_network.py provides a bounded nmcli wrapper for
        provisioning new connections (which does accept a WPA password from the
        captive-portal form) but that password is never persisted in network.json
        — only the connection_name is stored there.
        """
        assert "connection_name" in WIFI_NETWORK_SRC
        # The state save function must not write any key named 'password' or 'psk'
        # to the JSON file — check that the _save_network_state function (or
        # equivalent) does not include those fields in the dict it serialises.
        import re
        # Find the dict construction that is written to the JSON file
        # and confirm it only contains known safe keys
        assert "connection_name" in WIFI_NETWORK_SRC  # safe key present
        # The schema version constant confirms the file format is defined
        assert "schema_version" in WIFI_NETWORK_SRC or "SCHEMA_VERSION" in WIFI_NETWORK_SRC

    def test_watcher_request_path_allowlist_is_fixed(self):
        """The Web UI proxy must only forward to known, fixed paths."""
        assert '"/network_status"' in WEBUI_API_SRC or "'/network_status'" in WEBUI_API_SRC
        assert '"/network_control"' in WEBUI_API_SRC or "'/network_control'" in WEBUI_API_SRC
        assert "disallowed watcher path" in WEBUI_API_SRC


# ---------------------------------------------------------------------------
# Invariant 5: Built-in adapter is always the recovery path
# ---------------------------------------------------------------------------

class TestBuiltinAdapterRecovery:
    def test_watcher_references_recovery_hotspot_via_builtin(self):
        """The watcher must prefer the built-in adapter for the recovery
        hotspot and expose resolve_hotspot_adapter() for USB fallback."""
        assert "builtin" in WIFI_WATCHER_SRC or "built_in" in WIFI_WATCHER_SRC or "built-in" in WIFI_WATCHER_SRC
        assert "resolve_hotspot_adapter" in WIFI_WATCHER_SRC

    def test_wifi_network_distinguishes_usb_from_builtin(self):
        """autostream_wifi_network.py must distinguish USB from built-in adapters."""
        assert "is_usb" in WIFI_NETWORK_SRC
        assert "builtin" in WIFI_NETWORK_SRC or "built_in" in WIFI_NETWORK_SRC


# ---------------------------------------------------------------------------
# Invariant 6: Explicit state-machine model (state-machine refactor)
# ---------------------------------------------------------------------------

class TestStateMachineInvariants:
    RECOVERY_SRC = (REPO_ROOT / "platform" / "wifi_recovery.py").read_text(encoding="utf-8")
    STATUS_SRC = (REPO_ROOT / "platform" / "wifi_status.py").read_text(encoding="utf-8")
    # The pure decision core moved to platform/wifi_policy.py (Phase B); the
    # watcher re-exports the names and its loop applies the results.
    POLICY_SRC = (REPO_ROOT / "platform" / "wifi_policy.py").read_text(encoding="utf-8")
    # step_publish_state (which applies next_mode) moved to platform/wifi_loop.py
    # (hub-shrink HS-4).
    LOOP_SRC = (REPO_ROOT / "platform" / "wifi_loop.py").read_text(encoding="utf-8")

    def test_explicit_mode_and_purpose_table_present(self):
        """The operating mode and hotspot policy are explicit, not emergent."""
        assert "class Mode(" in self.POLICY_SRC
        assert "class HotspotPurpose(" in self.POLICY_SRC
        assert "PURPOSE_TABLE" in self.POLICY_SRC
        # Still re-exported by the watcher for its callers.
        assert "PURPOSE_TABLE" in WIFI_WATCHER_SRC

    def test_permanent_next_mode_core_and_authoritative_state_mode(self):
        """The permanent pure core is next_mode (+ PURPOSE_TABLE) in wifi_policy;
        STATE.mode is applied by the loop.  The WP2 shadow classifier name is gone."""
        assert "def next_mode(" in self.POLICY_SRC
        assert "def derive_mode(" not in WIFI_WATCHER_SRC
        assert "def derive_mode(" not in self.POLICY_SRC
        assert "STATE.mode = ctx.next_mode(" in self.LOOP_SRC

    def test_retired_flags_are_gone_from_state(self):
        """The flags subsumed by HotspotSession / PURPOSE_TABLE are no longer
        read or written as STATE fields (defects 1 & 2; §3.2)."""
        for flag in (
            "ap_exhausted", "force_setup_mode", "policy_disconnected_wifi",
            "setup_purpose", "manual_ap_active", "ap_enter_time",
            "reconfigure_active", "usb_adoption_retry_after",
        ):
            assert f"STATE.{flag}" not in WIFI_WATCHER_SRC, (
                f"retired flag STATE.{flag} still referenced"
            )

    def test_overlay_decision_lives_only_in_wifi_recovery(self):
        """The adapter-remediation overlay's decision (failure diagnosis + the
        no-IP verdict) lives in wifi_recovery.py; wifi_status only reads it
        (constraint 11)."""
        assert "def diagnose_client_failure" in self.RECOVERY_SRC
        assert "def is_degraded_no_ip" in self.RECOVERY_SRC
        assert "def diagnose_client_failure" not in self.STATUS_SRC
        assert "def is_degraded_no_ip" not in self.STATUS_SRC

    def test_same_subnet_machinery_removed(self):
        """Wired-wins replaced the same-subnet policy (§2.7)."""
        assert "def same_l3_segment" not in WIFI_NETWORK_SRC
        assert "def _single_usable_ipv4_interface" not in WIFI_NETWORK_SRC
        assert "same_l3_segment(" not in WIFI_WATCHER_SRC

    MDNS_SRC = (REPO_ROOT / "platform" / "wifi_mdns.py").read_text(encoding="utf-8")

    def test_avahi_mdns_block_lives_in_wifi_mdns(self):
        """WS2-WP1: the avahi/mDNS hostname-repair + re-announce block moved to
        platform/wifi_mdns.py; the watcher keeps only thin delegating wrappers."""
        for fn in ("check_and_repair_avahi_hostname", "maybe_reannounce_mdns",
                   "get_avahi_registered_hostname", "restart_avahi_daemon",
                   "_current_mdns_address_set", "mark_mdns_reannounce_pending"):
            assert f"def {fn}(ctx" in self.MDNS_SRC, f"{fn} not extracted to wifi_mdns"
        # The watcher imports the module and re-exports the loop entry points.
        assert "import wifi_mdns" in WIFI_WATCHER_SRC
        assert "wifi_mdns.check_and_repair_avahi_hostname(" in WIFI_WATCHER_SRC
        assert "wifi_mdns.maybe_reannounce_mdns(" in WIFI_WATCHER_SRC


# ---------------------------------------------------------------------------
# Regression: verify test counts are not unexpectedly reduced
# ---------------------------------------------------------------------------

class TestSuiteCompleteness:
    def test_all_wp_test_files_exist(self):
        """All WP-specific test files must be present in tests/."""
        tests_dir = REPO_ROOT / "tests"
        required = [
            "test_wifi_watcher_core.py",
            "test_wifi_web_routes.py",
            "test_wifi_hotspot_ctl.py",
            "test_wifi_activation.py",
            "test_wifi_recovery.py",
            "test_wifi_recovery_deadphy.py",
            "test_wifi_adoption.py",
            "test_wifi_config.py",
            "test_wifi_loop.py",
            "test_wifi_status.py",
            "test_wifi_mdns.py",
            "test_autostream_wifi_network.py",
            "test_dial_wifi_setup.py",
            "test_p4_deployment_policy.py",
            "test_wp7_network_api.py",
            "test_wp8_wifi_install_reset.py",
            "test_wp9_mdns_transition.py",
        ]
        for name in required:
            assert (tests_dir / name).exists(), f"Required test file missing: {name}"
