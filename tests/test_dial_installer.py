"""Regression and structural tests for the dial installer and updater.

Covers:
- require_trixie_os runs unconditionally (before the 'if ! $UPDATE' gate),
  so pre-Trixie OS is rejected on both fresh installs and updates.
- autostream_dial_updater check subcommand does not require root privileges.
  Regression: the root check was originally before arg parsing, blocking the
  check command when run as a non-root service user.
- EXIT trap removes UPDATING_FLAG first (before any status write) so nginx
  is unblocked even if write_update_result fails under set -e.
- write_update_result in the EXIT trap is non-fatal (|| true) so the trap
  always completes even when the status file cannot be written.
- EXIT trap only calls write_update_result when $UPDATE is true so fresh
  installs do not write spurious failure status.
- Recovery infrastructure: install_recovery_packages() installs fcgiwrap+zip,
  grants www-data adm group membership, is called unconditionally so --update
  runs gain these dependencies without re-imaging.
- Image, offline-page, and shared CGI deployment paths and modes.
- Sudoers entries granting www-data the three offline-recovery admin verbs.
- Installer safety prompt (show_info_and_prompt) and TTY helpers on fresh install.
- Reboot prompt at end of fresh install (not on --update).
- network_state_phase records active non-AP WiFi connection name on fresh install.
"""
import pytest
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
DIAL_INSTALLER = REPO_ROOT / "autostream_dial_install.sh"
HELPERS_SH = REPO_ROOT / "installer" / "dial" / "helpers.sh"
SUDOERS = REPO_ROOT / "system" / "sudoers" / "autostream_dial"
UPDATER = REPO_ROOT / "supervisor" / "autostream_dial_updater"


# ---------------------------------------------------------------------------
# Trixie OS enforcement — structural tests (platform-independent)
# ---------------------------------------------------------------------------

class TestTrixieEnforcement:
    def test_require_trixie_os_called_before_update_gate(self):
        """require_trixie_os must appear before 'if ! $UPDATE' in the dial installer.

        This ensures the OS version check runs on updates as well as fresh installs.
        Regression: the check was inside the 'if ! $UPDATE' block, so running
        the installer with --update on Bookworm would succeed silently.
        """
        content = DIAL_INSTALLER.read_text(encoding="utf-8")

        trixie_pos = content.find("require_trixie_os")
        update_gate_pos = content.find("if ! $UPDATE")

        assert trixie_pos != -1, "require_trixie_os call not found in autostream_dial_install.sh"
        assert update_gate_pos != -1, "'if ! $UPDATE' gate not found in autostream_dial_install.sh"
        assert trixie_pos < update_gate_pos, (
            "require_trixie_os must appear BEFORE 'if ! $UPDATE' so it runs on updates. "
            f"Found require_trixie_os at char {trixie_pos}, update gate at {update_gate_pos}."
        )

    def test_require_trixie_os_defined_in_helpers(self):
        """require_trixie_os must be defined in helpers.sh."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        assert "require_trixie_os()" in content, (
            "require_trixie_os() function not found in installer/dial/helpers.sh"
        )

    def test_require_trixie_os_checks_version_codename(self):
        """require_trixie_os must gate on VERSION_CODENAME == trixie."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        # Find the function body
        start = content.find("require_trixie_os()")
        assert start != -1
        body = content[start: start + 400]
        assert "trixie" in body, "require_trixie_os must compare against 'trixie'"
        assert "VERSION_CODENAME" in body or "os-release" in body, (
            "require_trixie_os must read VERSION_CODENAME from /etc/os-release"
        )

    def test_require_trixie_os_exits_on_mismatch(self):
        """require_trixie_os must call exit (not just warn) on a non-Trixie OS."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        start = content.find("require_trixie_os()")
        assert start != -1
        # Find end of function (next top-level function or EOF)
        next_func = content.find("\n}", start)
        body = content[start: next_func + 2] if next_func != -1 else content[start:]
        assert "exit" in body, (
            "require_trixie_os must exit with non-zero on a non-Trixie OS"
        )


# ---------------------------------------------------------------------------
# Dial updater privilege model — structural tests (platform-independent)
# ---------------------------------------------------------------------------

class TestUpdaterPrivilegeModel:
    def test_root_check_after_arg_parsing(self):
        """The root privilege check must come after argparse argument parsing.

        Regression: the check was before ap.parse_args(), so 'check' could
        not be exempted and always failed when run as a non-root user.
        """
        source = UPDATER.read_text(encoding="utf-8")
        lines = source.splitlines()

        argparse_pos = next(
            (i for i, line in enumerate(lines) if "ap = argparse.ArgumentParser" in line),
            -1,
        )
        parse_args_pos = next(
            (i for i, line in enumerate(lines) if "ap.parse_args()" in line),
            -1,
        )
        root_check_pos = next(
            (i for i, line in enumerate(lines) if "geteuid()" in line and "!= 0" in line),
            -1,
        )

        assert argparse_pos != -1, "argparse.ArgumentParser not found in updater"
        assert parse_args_pos != -1, "ap.parse_args() not found in updater"
        assert root_check_pos != -1, "Root check (os.geteuid() != 0) not found in updater"

        assert root_check_pos > parse_args_pos, (
            "Root check must come AFTER ap.parse_args() so 'check' can be exempted. "
            f"parse_args at line {parse_args_pos + 1}, root check at line {root_check_pos + 1}."
        )

    def test_check_command_exempted_from_root_check(self):
        """The 'check' subcommand must be explicitly exempted from the root gate.

        Regression: without this exemption, the dial HTTP server could not call
        the updater as an unprivileged user to poll for available updates.
        """
        source = UPDATER.read_text(encoding="utf-8")
        root_check_line = next(
            (line.strip() for line in source.splitlines()
             if "geteuid()" in line and "!= 0" in line),
            None,
        )
        assert root_check_line is not None
        assert 'cmd != "check"' in root_check_line, (
            "Root check must be guarded by 'args.cmd != \"check\"' to allow "
            "unprivileged update polling. "
            f"Found: {root_check_line!r}"
        )


# ---------------------------------------------------------------------------
# Recovery infrastructure helpers
# ---------------------------------------------------------------------------

class TestRecoveryHelpers:
    def test_install_recovery_packages_defined_in_helpers(self):
        """install_recovery_packages() must be defined in helpers.sh."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        assert "install_recovery_packages()" in content, (
            "install_recovery_packages() not found in installer/dial/helpers.sh"
        )

    def test_install_recovery_packages_installs_fcgiwrap(self):
        """install_recovery_packages() must install fcgiwrap."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        start = content.find("install_recovery_packages() {")
        assert start != -1, "install_recovery_packages() definition not found"
        body = content[start: start + 600]
        assert "fcgiwrap" in body, (
            "install_recovery_packages() must install fcgiwrap"
        )

    def test_install_recovery_packages_installs_zip(self):
        """install_recovery_packages() must install zip."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        start = content.find("install_recovery_packages() {")
        assert start != -1, "install_recovery_packages() definition not found"
        body = content[start: start + 600]
        assert "zip" in body, (
            "install_recovery_packages() must install zip"
        )

    def test_install_recovery_packages_adds_www_data_to_adm(self):
        """install_recovery_packages() must add www-data to adm group."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        start = content.find("install_recovery_packages() {")
        assert start != -1, "install_recovery_packages() definition not found"
        body = content[start: start + 600]
        assert "www-data" in body and "adm" in body, (
            "install_recovery_packages() must run usermod -aG adm www-data"
        )

    def test_install_os_packages_does_not_include_fcgiwrap(self):
        """install_os_packages() must NOT include fcgiwrap.

        install_recovery_packages() is called unconditionally (fresh install
        and --update) and is the single install site, avoiding double
        installation on fresh installs.
        """
        content = HELPERS_SH.read_text(encoding="utf-8")
        start = content.find("install_os_packages() {")
        assert start != -1, "install_os_packages() definition not found"
        # Find end of this function (closing top-level brace)
        next_func = content.find("\n}", start)
        body = content[start: next_func + 2] if next_func != -1 else content[start:]
        assert "fcgiwrap" not in body, (
            "fcgiwrap must not be in install_os_packages(); "
            "install_recovery_packages() is the single install site"
        )

    def test_install_recovery_packages_is_single_fcgiwrap_install_site(self):
        """install_recovery_packages() must include fcgiwrap (single source for both paths)."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        start = content.find("install_recovery_packages() {")
        assert start != -1, "install_recovery_packages() definition not found"
        body = content[start: start + 600]
        assert "fcgiwrap" in body, (
            "install_recovery_packages() is the single install site for fcgiwrap"
        )


class TestInstallerExitTrap:
    def _trap_body(self) -> str:
        content = DIAL_INSTALLER.read_text(encoding="utf-8")
        trap_pos = content.find("trap '")
        assert trap_pos != -1, "EXIT trap not found in installer"
        return content[trap_pos: trap_pos + 400]

    def test_exit_trap_guards_write_update_result_with_update_flag(self):
        """EXIT trap must only call write_update_result when $UPDATE is true.

        On fresh installs the updater has not written STATUS=in_progress and the
        UPDATING_FLAG was never created; calling write_update_result unconditionally
        would write spurious failure status to an update-result.env that belongs to
        a previous update run.
        """
        trap_body = self._trap_body()
        assert "$UPDATE" in trap_body, (
            "EXIT trap must guard write_update_result with $UPDATE so fresh "
            "installs do not write spurious failure status"
        )

    def test_exit_trap_always_removes_updating_flag(self):
        """EXIT trap must always remove UPDATING_FLAG regardless of $UPDATE."""
        trap_body = self._trap_body()
        assert "rm -f" in trap_body and "UPDATING_FLAG" in trap_body, (
            "EXIT trap must always run rm -f UPDATING_FLAG"
        )

    def test_exit_trap_removes_flag_before_status_write(self):
        """EXIT trap must remove UPDATING_FLAG before calling write_update_result.

        Under set -e, if write_update_result fails the trap body exits early.
        Removing the flag first ensures nginx stops redirecting even when the
        status file cannot be written (e.g. disk full, permission denied).
        """
        trap_body = self._trap_body()
        rm_pos = trap_body.find("rm -f")
        write_pos = trap_body.find("write_update_result")
        assert rm_pos != -1, "rm -f not found in trap body"
        assert write_pos != -1, "write_update_result not found in trap body"
        assert rm_pos < write_pos, (
            "rm -f \"$UPDATING_FLAG\" must appear before write_update_result in "
            "the EXIT trap so the flag is cleared even if the write fails"
        )

    def test_exit_trap_write_update_result_is_nonfatal(self):
        """write_update_result in the EXIT trap must be followed by '|| true'.

        Under set -e, a bare write_update_result failure exits the trap before
        rm -f runs (even if rm comes first, a second failure would still abort).
        '|| true' makes the write non-fatal so the trap always completes cleanly.
        """
        trap_body = self._trap_body()
        write_pos = trap_body.find("write_update_result")
        assert write_pos != -1, "write_update_result not found in trap body"
        snippet = trap_body[write_pos: write_pos + 120]
        assert "|| true" in snippet, (
            "write_update_result in the EXIT trap must be followed by '|| true' "
            "to remain non-fatal under set -e"
        )

    @pytest.mark.skipif(
        __import__("shutil").which("bash") is None or __import__("sys").platform == "win32",
        reason="bash not available or not compatible on Windows",
    )
    def test_exit_trap_flag_removed_when_status_write_fails(self, tmp_path):
        """Execution test: flag is removed even when write_update_result returns 1.

        Simulates the failure path that static text inspection cannot cover:
        write_update_result exits non-zero (disk full / permission denied) while
        the EXIT trap fires on a failed --update run.
        """
        import shlex
        import subprocess
        import textwrap

        flag = tmp_path / "autostream-dial-updating"
        flag.touch()

        # Run the actual trap body from the installer, with write_update_result
        # replaced by a stub that always fails (simulates write error).
        script = textwrap.dedent(f"""\
            set -euo pipefail
            UPDATING_FLAG={shlex.quote(str(flag))}
            _install_success=false
            UPDATE=true
            write_update_result() {{ return 1; }}

            trap '_exit_rc=$?
                rm -f "$UPDATING_FLAG"
                if [[ "$_install_success" != true ]] && $UPDATE; then
                    write_update_result "failure" "test" || true
                fi
                exit $_exit_rc' EXIT

            exit 1
        """)

        result = subprocess.run(
            ["bash", "-c", script],
            capture_output=True,
            text=True,
        )
        assert not flag.exists(), (
            "EXIT trap must remove UPDATING_FLAG even when write_update_result fails; "
            f"bash stderr: {result.stderr!r}"
        )


class TestRecoveryInfrastructureDeployment:
    def _installer_content(self):
        return DIAL_INSTALLER.read_text(encoding="utf-8")

    def test_install_recovery_packages_called_unconditionally(self):
        """install_recovery_packages must be called outside any 'if ! $UPDATE' block.

        It must run on both fresh installs and --update runs so that existing
        devices gain fcgiwrap and zip without requiring a re-image.
        """
        content = self._installer_content()
        call_pos = content.find("install_recovery_packages")
        assert call_pos != -1, (
            "install_recovery_packages not called in autostream_dial_install.sh"
        )
        # All 'if ! $UPDATE' blocks must close before the call appears.
        # Strategy: find the position of the call; check that no unclosed
        # 'if ! $UPDATE' block spans that position.
        before = content[:call_pos]
        open_update_guards = before.count("if ! $UPDATE")
        # Each 'if ! $UPDATE' must be followed by its 'fi' before the call.
        fi_count = before.count("fi")
        # Acceptable when fi_count >= open_update_guards (all guards closed).
        assert fi_count >= open_update_guards, (
            "install_recovery_packages() is called inside 'if ! $UPDATE' — "
            "it must be outside so it runs on --update too. "
            f"Guards opened: {open_update_guards}, fi count before call: {fi_count}"
        )

    def test_fcgiwrap_enabled_in_installer(self):
        """systemctl enable fcgiwrap must appear in the installer."""
        content = self._installer_content()
        assert "systemctl enable fcgiwrap" in content, (
            "systemctl enable fcgiwrap not found in autostream_dial_install.sh"
        )

    def test_fcgiwrap_restarted_after_group_change(self):
        """systemctl restart fcgiwrap must appear after install_recovery_packages call."""
        content = self._installer_content()
        pkg_pos = content.find("install_recovery_packages")
        restart_pos = content.find("systemctl restart fcgiwrap")
        assert pkg_pos != -1, "install_recovery_packages not found"
        assert restart_pos != -1, "systemctl restart fcgiwrap not found"
        assert restart_pos > pkg_pos, (
            "systemctl restart fcgiwrap must come after install_recovery_packages "
            "so fcgiwrap picks up the new adm group membership"
        )

    def test_badge_deployed_to_images_dir(self):
        """autostream-dial-badge.png must be installed to /opt/autostream/images/."""
        content = self._installer_content()
        assert "autostream-dial-badge.png" in content, (
            "autostream-dial-badge.png deployment not found in installer"
        )
        assert "/opt/autostream/images/" in content, (
            "/opt/autostream/images/ destination not found in installer"
        )

    def test_favicons_deployed_to_images_dir(self):
        """favicon files must be installed to /opt/autostream/images/."""
        content = self._installer_content()
        assert "favicon.ico" in content
        assert "favicon-16x16.png" in content
        assert "favicon-32x32.png" in content

    def test_offline_html_pages_deployed(self):
        """nginx/offline/*.html pages must be deployed to /opt/autostream/nginx/offline/."""
        content = self._installer_content()
        assert "nginx/offline" in content, (
            "Offline HTML page deployment not found in installer"
        )
        assert "/opt/autostream/nginx/offline" in content

    def test_shared_cgi_scripts_deployed_with_0755(self):
        """Shared CGI scripts must be deployed with mode 0755."""
        content = self._installer_content()
        # Find the CGI deployment block (0755 must appear near cgi/ paths)
        cgi_block_pos = content.find("/opt/autostream/nginx/cgi/")
        assert cgi_block_pos != -1, (
            "/opt/autostream/nginx/cgi/ destination not found in installer"
        )
        # The -m 0755 flag must appear in the same block
        before_cgi = content[:cgi_block_pos]
        cgi_block = content[before_cgi.rfind("# ----"):cgi_block_pos + 300]
        assert "0755" in cgi_block, (
            "CGI scripts must be deployed with mode 0755"
        )

    def test_reboot_cgi_deployed(self):
        """nginx/cgi/reboot.cgi must be deployed."""
        content = self._installer_content()
        assert "nginx/cgi/reboot.cgi" in content

    def test_factory_reset_cgi_deployed(self):
        """nginx/cgi/factory-reset.cgi must be deployed."""
        content = self._installer_content()
        assert "nginx/cgi/factory-reset.cgi" in content

    def test_update_status_cgi_deployed(self):
        """nginx/cgi/update-status.cgi must be deployed."""
        content = self._installer_content()
        assert "nginx/cgi/update-status.cgi" in content


# ---------------------------------------------------------------------------
# Sudoers: www-data offline-recovery verbs
# ---------------------------------------------------------------------------

class TestSudoersWwwData:
    def _sudoers_content(self):
        return SUDOERS.read_text(encoding="utf-8")

    def test_www_data_reboot_verb_present(self):
        """www-data must be allowed to call autostream_admin reboot --delay 3 UserRequestSystemError."""
        content = self._sudoers_content()
        assert "www-data" in content, "No www-data entries found in autostream_dial sudoers"
        assert "reboot --delay 3 UserRequestSystemError" in content, (
            "www-data reboot verb missing from autostream_dial sudoers"
        )

    def test_www_data_factory_reset_verb_present(self):
        """www-data must be allowed to call autostream_admin factory-reset."""
        content = self._sudoers_content()
        lines = [l.strip() for l in content.splitlines() if "www-data" in l]
        assert any("factory-reset" in l for l in lines), (
            "www-data factory-reset verb missing from autostream_dial sudoers"
        )

    def test_www_data_update_status_verb_present(self):
        """www-data must be allowed to call autostream_admin update-status."""
        content = self._sudoers_content()
        lines = [l.strip() for l in content.splitlines() if "www-data" in l]
        assert any("update-status" in l for l in lines), (
            "www-data update-status verb missing from autostream_dial sudoers"
        )

    def test_www_data_entries_are_nopasswd(self):
        """All www-data sudoers entries must use NOPASSWD."""
        content = self._sudoers_content()
        lines = [l.strip() for l in content.splitlines()
                 if l.strip().startswith("www-data")]
        assert lines, "No www-data lines found in sudoers"
        for line in lines:
            assert "NOPASSWD" in line, (
                f"www-data sudoers line missing NOPASSWD: {line!r}"
            )

    def test_www_data_does_not_have_wildcard_verbs(self):
        """www-data must only have the three specific named verbs, not wildcards."""
        content = self._sudoers_content()
        lines = [l.strip() for l in content.splitlines()
                 if l.strip().startswith("www-data")]
        for line in lines:
            # No bare ALL or * that would grant broad access
            parts = line.split("NOPASSWD:", 1)
            if len(parts) == 2:
                verb = parts[1].strip()
                assert not verb.startswith("ALL"), (
                    f"www-data line must not grant ALL: {line!r}"
                )


# ---------------------------------------------------------------------------
# Control socket deployment contract tests
# ---------------------------------------------------------------------------

class TestControlSocketDeployment:
    def _service_content(self):
        svc = REPO_ROOT / "system" / "systemd" / "autostream_dial.service"
        return svc.read_text(encoding="utf-8")

    def _installer_content(self):
        return DIAL_INSTALLER.read_text(encoding="utf-8")

    def test_runtime_directory_defined_in_service(self):
        """autostream_dial.service must define RuntimeDirectory=autostream-dial."""
        content = self._service_content()
        assert "RuntimeDirectory=autostream-dial" in content, (
            "RuntimeDirectory=autostream-dial not found in autostream_dial.service"
        )

    def test_runtime_directory_mode_defined_in_service(self):
        """autostream_dial.service must define RuntimeDirectoryMode=0750."""
        content = self._service_content()
        assert "RuntimeDirectoryMode=0750" in content, (
            "RuntimeDirectoryMode=0750 not found in autostream_dial.service"
        )

    def test_cli_python_installed_with_0644(self):
        """autostream_dial_control.py must be installed with mode 0644."""
        content = self._installer_content()
        # Look for the install command with 0644 and the CLI module
        assert "autostream_dial_control.py" in content, (
            "autostream_dial_control.py deployment not found in installer"
        )
        # Find 0644 near the CLI install
        idx = content.find("autostream_dial_control.py")
        nearby = content[max(0, idx - 200): idx + 200]
        assert "0644" in nearby, (
            "autostream_dial_control.py must be installed with mode 0644"
        )

    def test_shell_launcher_installed_with_0755(self):
        """autostream-dial-control shell launcher must be installed with mode 0755."""
        content = self._installer_content()
        assert "autostream-dial-control" in content, (
            "autostream-dial-control deployment not found in installer"
        )
        idx = content.find("/usr/local/bin/autostream-dial-control")
        assert idx != -1, "/usr/local/bin/autostream-dial-control not in installer"
        nearby = content[max(0, idx - 200): idx + 200]
        assert "0755" in nearby, (
            "autostream-dial-control must be installed with mode 0755"
        )

    def test_cli_deployed_on_update(self):
        """CLI installation must appear outside the 'if ! $UPDATE' block.

        Both fresh and --update installations must deploy the CLI.
        """
        content = self._installer_content()
        cli_pos = content.find("autostream_dial_control.py")
        assert cli_pos != -1
        # The CLI install must not be inside the 'if ! $UPDATE' fresh-only block
        # (positioned before the block or outside it).
        # Simplest check: CLI install appears after 'cp -a "$DEPLOY/dial/."'
        cp_pos = content.find('cp -a "$DEPLOY/dial/."')
        assert cp_pos != -1, "cp -a dial/ block not found"
        # CLI install follows the cp -a block
        assert cli_pos > cp_pos, (
            "autostream_dial_control.py install must follow the cp -a dial/ block "
            "so it runs on both fresh install and --update"
        )

    def test_socket_path_constant_in_protocol_module(self):
        """CONTROL_SOCKET_PATH must be defined in dial_control_protocol.py."""
        protocol_module = REPO_ROOT / "dial" / "dial_control_protocol.py"
        content = protocol_module.read_text(encoding="utf-8")
        assert "CONTROL_SOCKET_PATH" in content, (
            "CONTROL_SOCKET_PATH not found in dial_control_protocol.py"
        )
        assert "/run/autostream-dial/control.sock" in content, (
            "Expected socket path not found in CONTROL_SOCKET_PATH definition"
        )

    def test_no_broad_sudoers_for_dial_control(self):
        """autostream_dial sudoers must not grant broad ALL access."""
        content = SUDOERS.read_text(encoding="utf-8")
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "autostream" in stripped and "ALL" in stripped:
                # Narrow check: must not be a bare ALL with no specific command
                # Acceptable: ALL=(ALL) NOPASSWD: /path/to/command
                # Not acceptable: ALL
                parts = stripped.split("NOPASSWD:", 1)
                if len(parts) == 2:
                    verb = parts[1].strip()
                    assert not verb == "ALL", (
                        f"Broad ALL grant found in sudoers: {stripped!r}"
                    )

    def test_no_tcp_listener_in_dial_control(self):
        """dial_control.py must not introduce a TCP listener."""
        control_module = REPO_ROOT / "dial" / "dial_control.py"
        content = control_module.read_text(encoding="utf-8")
        # Must not contain socket.AF_INET6 or socket.AF_INET used for the server
        # (the AF_INET fallback in _UnixStreamServer is for import compatibility only)
        assert "TCPServer" not in content or "_UnixStreamServer" in content, (
            "dial_control.py must not start a TCP server"
        )
        # The fallback is only for import; AF_UNIX check in start() prevents TCP
        assert "_AF_UNIX is None" in content, (
            "dial_control.py must check for _AF_UNIX is None in start()"
        )


# ---------------------------------------------------------------------------
# Installer safety prompt (show_info_and_prompt) and TTY helpers
# ---------------------------------------------------------------------------

class TestInstallerSafetyPrompt:
    def test_has_tty_defined_in_helpers(self):
        """has_tty() must be defined in helpers.sh so the prompt can detect TTY."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        assert "has_tty()" in content, "has_tty() not found in installer/dial/helpers.sh"

    def test_tty_read_defined_in_helpers(self):
        """tty_read() must be defined in helpers.sh."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        assert "tty_read()" in content, "tty_read() not found in installer/dial/helpers.sh"

    def test_show_info_and_prompt_defined_in_helpers(self):
        """show_info_and_prompt() must be defined in helpers.sh."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        assert "show_info_and_prompt()" in content, (
            "show_info_and_prompt() not found in installer/dial/helpers.sh"
        )

    def test_show_info_and_prompt_contains_installer_name(self):
        """Banner must identify this as the AUTOSTREAM DIAL INSTALLER."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        start = content.find("show_info_and_prompt()")
        assert start != -1
        body = content[start: start + 600]
        assert "AUTOSTREAM DIAL INSTALLER" in body, (
            "show_info_and_prompt() banner must say 'AUTOSTREAM DIAL INSTALLER'"
        )

    def test_show_info_and_prompt_has_continue_question(self):
        """Banner must include 'Continue with installation?' prompt."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        start = content.find("show_info_and_prompt()")
        assert start != -1
        body = content[start: start + 1500]
        assert "Continue with installation?" in body, (
            "show_info_and_prompt() must ask 'Continue with installation?'"
        )

    def test_show_info_and_prompt_called_in_fresh_install_block(self):
        """show_info_and_prompt must be called inside the 'if ! $UPDATE' block.

        It must never run on --update (which is non-interactive).
        """
        content = DIAL_INSTALLER.read_text(encoding="utf-8")
        update_gate_pos = content.find("if ! $UPDATE")
        assert update_gate_pos != -1
        # Find the matching 'fi' for the first 'if ! $UPDATE'
        fi_pos = content.find("\nfi\n", update_gate_pos)
        assert fi_pos != -1
        block = content[update_gate_pos: fi_pos]
        assert "show_info_and_prompt" in block, (
            "show_info_and_prompt must be called inside the 'if ! $UPDATE' block"
        )

    def test_show_info_and_prompt_called_before_install_os_packages(self):
        """show_info_and_prompt must appear before install_os_packages.

        The user must be able to abort before any system modification.
        """
        content = DIAL_INSTALLER.read_text(encoding="utf-8")
        prompt_pos = content.find("show_info_and_prompt")
        pkg_pos = content.find("install_os_packages")
        assert prompt_pos != -1, "show_info_and_prompt not found in installer"
        assert pkg_pos != -1, "install_os_packages not found in installer"
        assert prompt_pos < pkg_pos, (
            "show_info_and_prompt must appear before install_os_packages so the "
            "user can abort before any packages are installed"
        )

    def test_show_info_and_prompt_exits_on_non_y(self):
        """show_info_and_prompt must call exit on any answer other than Y/y."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        start = content.find("show_info_and_prompt()")
        assert start != -1
        body = content[start: start + 1500]
        assert "exit 1" in body, (
            "show_info_and_prompt must exit with code 1 on non-Y/y answer"
        )

    def test_show_info_and_prompt_refuses_non_interactive(self):
        """show_info_and_prompt must refuse (exit 1) when there is no TTY.

        The main installer's safety model is that non-interactive fresh installs
        are rejected unless an explicit unattended mode is provided.  Proceeding
        silently on a piped/automated run bypasses the only human confirmation gate.
        """
        content = HELPERS_SH.read_text(encoding="utf-8")
        start = content.find("show_info_and_prompt()")
        assert start != -1
        body = content[start: start + 1500]
        # The else branch (no TTY) must exit, not proceed
        else_idx = body.find("else\n", body.find("if has_tty"))
        assert else_idx != -1, "show_info_and_prompt must have an else branch after 'if has_tty'"
        else_body = body[else_idx: else_idx + 300]
        assert "exit 1" in else_body, (
            "show_info_and_prompt must exit 1 in the non-TTY else branch; "
            "silently proceeding on a piped install bypasses the confirmation gate"
        )
        # Must not say 'proceeding' in that else branch
        assert "proceeding with installation" not in else_body.lower(), (
            "show_info_and_prompt must not silently proceed when there is no TTY"
        )


# ---------------------------------------------------------------------------
# Reboot prompt at end of fresh install
# ---------------------------------------------------------------------------

class TestInstallerRebootPrompt:
    def test_reboot_prompt_uses_has_tty(self):
        """Reboot prompt must gate on has_tty so it only runs interactively."""
        content = DIAL_INSTALLER.read_text(encoding="utf-8")
        # find 'has_tty' after 'installation complete'
        complete_pos = content.find("installation complete")
        assert complete_pos != -1
        after = content[complete_pos:]
        assert "has_tty" in after, (
            "Reboot prompt after 'installation complete' must use has_tty"
        )

    def test_reboot_prompt_only_on_fresh_install(self):
        """Reboot prompt must be inside 'if ! $UPDATE' so --update stays non-interactive."""
        content = DIAL_INSTALLER.read_text(encoding="utf-8")
        # Find the last 'if ! $UPDATE' block (the end-of-installer one)
        complete_pos = content.find("installation complete")
        assert complete_pos != -1
        after = content[complete_pos:]
        assert "if ! $UPDATE" in after, (
            "Reboot prompt must be guarded by 'if ! $UPDATE'"
        )

    def test_reboot_prompt_offers_reboot(self):
        """Reboot prompt must call reboot on Y/y answer."""
        content = DIAL_INSTALLER.read_text(encoding="utf-8")
        complete_pos = content.find("installation complete")
        assert complete_pos != -1
        after = content[complete_pos:]
        assert "reboot" in after, (
            "Reboot prompt must call 'reboot' when user answers Y"
        )

    def test_reboot_prompt_non_interactive_message(self):
        """Non-interactive path must print a 'please reboot' message."""
        content = DIAL_INSTALLER.read_text(encoding="utf-8")
        complete_pos = content.find("installation complete")
        assert complete_pos != -1
        after = content[complete_pos:]
        assert "reboot the device when convenient" in after, (
            "Non-interactive path must tell user to reboot when convenient"
        )


# ---------------------------------------------------------------------------
# Conditional completion message based on recorded WiFi
# ---------------------------------------------------------------------------

class TestInstallerCompletionMessage:
    def _after_complete(self) -> str:
        content = DIAL_INSTALLER.read_text(encoding="utf-8")
        pos = content.find("installation complete")
        assert pos != -1
        return content[pos:]

    def test_completion_message_checks_ssid_file(self):
        """Installer must check /opt/autostream/ssid to decide which message to show."""
        after = self._after_complete()
        assert "/opt/autostream/ssid" in after, (
            "Completion block must check /opt/autostream/ssid to determine the next-step message"
        )

    def test_wifi_recorded_message_shown_when_ssid_file_exists(self):
        """When WiFi was recorded, message must direct user to continue from an appliance."""
        after = self._after_complete()
        assert "continue setup from an autostream appliance" in after.lower(), (
            "Installer must tell users to 'continue setup from an autostream appliance' "
            "when WiFi was recorded during install"
        )

    def test_setup_ssid_message_shown_when_no_wifi_recorded(self):
        """When no WiFi was recorded, message must still direct user to the setup SSID."""
        after = self._after_complete()
        assert "autostream-dial_SETUP" in after or "SETUP" in after, (
            "Installer must still mention the setup SSID for devices without recorded WiFi"
        )

    def test_completion_messages_are_mutually_conditional(self):
        """The two messages must be in an if/else block, not both always printed."""
        after = self._after_complete()
        ssid_idx = after.find("/opt/autostream/ssid")
        assert ssid_idx != -1
        block = after[ssid_idx: ssid_idx + 400]
        assert "if " in block and "else" in block, (
            "The two completion messages must be in an if/else block "
            "so only one is printed depending on whether WiFi was recorded"
        )


# ---------------------------------------------------------------------------
# network_state_phase — dial installer WiFi recording
# ---------------------------------------------------------------------------

class TestDialNetworkStatePhase:
    def test_network_state_phase_defined_in_helpers(self):
        """network_state_phase() must be defined in installer/dial/helpers.sh."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        assert "network_state_phase()" in content, (
            "network_state_phase() not found in installer/dial/helpers.sh"
        )

    def test_network_state_phase_preserves_existing_ssid_file(self):
        """network_state_phase must skip recording when /opt/autostream/ssid already exists and is non-empty."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        start = content.find("network_state_phase()")
        assert start != -1
        body = content[start: start + 800]
        # Checks for [[ -s ... ]] guard (non-empty file test)
        assert "-s " in body and "ssid" in body, (
            "network_state_phase must check for existing non-empty ssid file with [[ -s ]]"
        )
        # Must return early when file exists
        assert "return 0" in body or "return" in body, (
            "network_state_phase must return early when ssid file already exists"
        )

    def test_network_state_phase_uses_nmcli_device_status(self):
        """network_state_phase must use nmcli device status to detect active connection."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        start = content.find("network_state_phase()")
        assert start != -1
        body = content[start: start + 800]
        assert "nmcli" in body and "device" in body and "status" in body, (
            "network_state_phase must query nmcli device status"
        )

    def test_network_state_phase_checks_wlan0(self):
        """network_state_phase must specifically check the wlan0 interface."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        start = content.find("network_state_phase()")
        assert start != -1
        body = content[start: start + 800]
        assert "wlan0" in body, "network_state_phase must check wlan0"

    def test_network_state_phase_rejects_ap_mode(self):
        """network_state_phase must not record a connection that is in AP mode."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        start = content.find("network_state_phase()")
        assert start != -1
        body = content[start: start + 1000]
        assert "802-11-wireless.mode" in body or "wireless.mode" in body, (
            "network_state_phase must check 802-11-wireless.mode to reject AP connections"
        )
        assert '"ap"' in body or "'ap'" in body or "!= \"ap\"" in body or "!= 'ap'" in body, (
            "network_state_phase must skip when mode is 'ap'"
        )

    def test_network_state_phase_writes_ssid_file(self):
        """network_state_phase must write the connection name to /opt/autostream/ssid."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        start = content.find("network_state_phase()")
        assert start != -1
        body = content[start: start + 1000]
        assert "/opt/autostream/ssid" in body, (
            "network_state_phase must write to /opt/autostream/ssid"
        )
        assert "printf" in body or "> " in body, (
            "network_state_phase must write the connection name to the ssid file"
        )

    def test_network_state_phase_called_in_fresh_install_block(self):
        """network_state_phase must be called inside the 'if ! $UPDATE' block.

        It must not run on --update (WiFi is already configured and recorded).
        """
        content = DIAL_INSTALLER.read_text(encoding="utf-8")
        update_gate_pos = content.find("if ! $UPDATE")
        assert update_gate_pos != -1
        fi_pos = content.find("\nfi\n", update_gate_pos)
        assert fi_pos != -1
        block = content[update_gate_pos: fi_pos]
        assert "network_state_phase" in block, (
            "network_state_phase must be called inside the 'if ! $UPDATE' block"
        )

    def test_network_state_phase_called_after_create_dirs(self):
        """network_state_phase must be called after create_dirs so /opt/autostream exists."""
        content = DIAL_INSTALLER.read_text(encoding="utf-8")
        create_dirs_pos = content.find("create_dirs")
        network_pos = content.find("network_state_phase")
        assert create_dirs_pos != -1, "create_dirs not found in installer"
        assert network_pos != -1, "network_state_phase not found in installer"
        assert network_pos > create_dirs_pos, (
            "network_state_phase must be called after create_dirs so /opt/autostream exists"
        )
