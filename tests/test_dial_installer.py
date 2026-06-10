"""Regression tests for the dial installer and updater.

Covers:
- require_trixie_os runs unconditionally (before the 'if ! $UPDATE' gate),
  so pre-Trixie OS is rejected on both fresh installs and updates.
- autostream_dial_updater check subcommand does not require root privileges.
  Regression: the root check was originally before arg parsing, blocking the
  check command when run as a non-root service user.
"""
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
DIAL_INSTALLER = REPO_ROOT / "autostream_dial_install.sh"
HELPERS_SH = REPO_ROOT / "installer" / "dial" / "helpers.sh"
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
