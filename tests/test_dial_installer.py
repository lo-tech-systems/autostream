"""Regression and structural tests for the dial installer and updater.

Covers:
- require_trixie_os runs unconditionally (before the 'if ! $UPDATE' gate),
  so pre-Trixie OS is rejected on both fresh installs and updates.
- autostream_dial_updater check subcommand does not require root privileges.
  Regression: the root check was originally before arg parsing, blocking the
  check command when run as a non-root service user.
- Recovery infrastructure: install_recovery_packages() installs fcgiwrap+zip,
  grants www-data adm group membership, is called unconditionally so --update
  runs gain these dependencies without re-imaging.
- Image, offline-page, and shared CGI deployment paths and modes.
- Sudoers entries granting www-data the three offline-recovery admin verbs.
"""
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
        start = content.find("install_recovery_packages()")
        assert start != -1
        body = content[start: start + 600]
        assert "fcgiwrap" in body, (
            "install_recovery_packages() must install fcgiwrap"
        )

    def test_install_recovery_packages_installs_zip(self):
        """install_recovery_packages() must install zip."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        start = content.find("install_recovery_packages()")
        assert start != -1
        body = content[start: start + 600]
        assert "zip" in body, (
            "install_recovery_packages() must install zip"
        )

    def test_install_recovery_packages_adds_www_data_to_adm(self):
        """install_recovery_packages() must add www-data to adm group."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        start = content.find("install_recovery_packages()")
        assert start != -1
        body = content[start: start + 600]
        assert "www-data" in body and "adm" in body, (
            "install_recovery_packages() must run usermod -aG adm www-data"
        )

    def test_install_os_packages_includes_fcgiwrap(self):
        """install_os_packages() must include fcgiwrap for fresh installs."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        start = content.find("install_os_packages()")
        assert start != -1
        body = content[start: start + 500]
        assert "fcgiwrap" in body, (
            "install_os_packages() must include fcgiwrap so fresh installs get it"
        )

    def test_install_os_packages_includes_zip(self):
        """install_os_packages() must include zip for fresh installs."""
        content = HELPERS_SH.read_text(encoding="utf-8")
        start = content.find("install_os_packages()")
        assert start != -1
        body = content[start: start + 500]
        assert "zip" in body, (
            "install_os_packages() must include zip so fresh installs get it"
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
