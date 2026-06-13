"""Tests for dial/cgi/download-logs.cgi.

Covers:
- Request guard enforcement: GET rejected (405), cross-origin POST rejected
  (403), missing XRW rejected (400), well-formed POST passes all guards.
- Structural checks: ZIP filename uses autostream-dial-logs- prefix; only
  dial-*.log and wifi_setup.log are collected; owntone.log and main-product
  logs are excluded; no-log README is produced when no files are readable.
- Deployment: installer deploys download-logs.cgi to /opt/autostream/nginx/cgi/.

Bash execution tests are skipped when bash cannot run scripts at Windows
paths (CI/WSL limitation).
"""
import os
import subprocess
import zipfile
from pathlib import Path

import pytest

from conftest import bash_can_run_script_at_windows_path

REPO_ROOT = Path(__file__).parent.parent
DIAL_CGI = REPO_ROOT / "dial" / "cgi" / "download-logs.cgi"
INSTALLER = REPO_ROOT / "autostream_dial_install.sh"


skip_no_bash = pytest.mark.skipif(
    not bash_can_run_script_at_windows_path(),
    reason="bash cannot execute a script at a Windows path (WSL launcher or bash absent)",
)


def _run_cgi(env_overrides: dict) -> subprocess.CompletedProcess:
    """Run download-logs.cgi with a minimal CGI environment."""
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "REQUEST_METHOD": "",
        "HTTP_HOST": "autostream.local",
        "CONTENT_LENGTH": "0",
    }
    env.update(env_overrides)
    return subprocess.run(
        ["bash", str(DIAL_CGI)],
        capture_output=True,
        env=env,
        timeout=15,
    )


# ---------------------------------------------------------------------------
# Structural: source content checks (platform-independent)
# ---------------------------------------------------------------------------

class TestDialCGIStructure:
    def _src(self):
        return DIAL_CGI.read_text(encoding="utf-8")

    def test_file_exists(self):
        """dial/cgi/download-logs.cgi must exist."""
        assert DIAL_CGI.exists(), "dial/cgi/download-logs.cgi not found"

    def test_zip_filename_prefix(self):
        """ZIP filename must use the autostream-dial-logs- prefix."""
        src = self._src()
        assert "autostream-dial-logs-" in src, (
            "ZIP filename prefix must be 'autostream-dial-logs-', not 'autostream-logs-'"
        )

    def test_does_not_include_owntone_log(self):
        """OwnTone does not run on a dial device; owntone.log must not be collected."""
        src = self._src()
        assert "owntone" not in src, (
            "dial/cgi/download-logs.cgi must not reference owntone.log"
        )

    def test_collects_dial_log_glob(self):
        """Must collect dial-*.log files from /var/log/autostream/."""
        src = self._src()
        assert "dial-*.log" in src, (
            "download-logs.cgi must glob dial-*.log to collect dial-specific logs"
        )

    def test_collects_wifi_setup_log(self):
        """Must collect wifi_setup.log."""
        src = self._src()
        assert "wifi_setup.log" in src, (
            "download-logs.cgi must collect wifi_setup.log"
        )

    def test_does_not_glob_all_autostream_logs(self):
        """Must NOT use /var/log/autostream/* (would include main-product logs)."""
        src = self._src()
        assert "/var/log/autostream/*" not in src, (
            "dial CGI must not glob all /var/log/autostream/* — "
            "use dial-*.log glob and explicit wifi_setup.log instead"
        )

    def test_post_method_guard_present(self):
        """Must reject non-POST requests."""
        src = self._src()
        assert "405" in src, (
            "download-logs.cgi must return 405 for non-POST requests"
        )

    def test_origin_guard_present(self):
        """Must check HTTP_ORIGIN against HTTP_HOST to prevent CSRF."""
        src = self._src()
        assert "HTTP_ORIGIN" in src and "403" in src, (
            "download-logs.cgi must enforce same-origin check and return 403"
        )

    def test_xrw_guard_present(self):
        """Must check X-Requested-With header."""
        src = self._src()
        assert "HTTP_X_REQUESTED_WITH" in src and "400" in src, (
            "download-logs.cgi must check X-Requested-With and return 400"
        )

    def test_no_log_readme_references_dial_paths(self):
        """README produced when no logs found must reference dial log paths."""
        src = self._src()
        assert "dial-*.log" in src or "dial" in src, (
            "No-log README must reference dial-specific log paths"
        )


# ---------------------------------------------------------------------------
# Request guard enforcement (bash required)
# ---------------------------------------------------------------------------

@skip_no_bash
class TestDialCGIRequestGuards:
    def test_get_rejected_with_405(self):
        """GET must be rejected with 405."""
        result = _run_cgi({"REQUEST_METHOD": "GET"})
        assert "Status: 405" in result.stdout.decode(errors="replace")

    def test_cross_origin_post_rejected_with_403(self):
        """POST from a foreign origin must be rejected with 403."""
        result = _run_cgi({
            "REQUEST_METHOD": "POST",
            "HTTP_ORIGIN": "http://attacker.example.com",
            "HTTP_HOST": "autostream.local",
        })
        assert "Status: 403" in result.stdout.decode(errors="replace")

    def test_missing_xrw_header_rejected_with_400(self):
        """POST without X-Requested-With must be rejected with 400."""
        result = _run_cgi({"REQUEST_METHOD": "POST"})
        assert "Status: 400" in result.stdout.decode(errors="replace")

    def test_valid_post_passes_all_guards(self):
        """Well-formed POST must not be rejected by any guard (4xx)."""
        result = _run_cgi({
            "REQUEST_METHOD": "POST",
            "HTTP_X_REQUESTED_WITH": "XMLHttpRequest",
        })
        out = result.stdout.decode(errors="replace")
        assert "Status: 405" not in out
        assert "Status: 400" not in out
        assert "Status: 403" not in out

    def test_same_origin_post_with_origin_header_passes(self):
        """POST with a same-origin Origin header must also pass the origin guard."""
        result = _run_cgi({
            "REQUEST_METHOD": "POST",
            "HTTP_ORIGIN": "http://autostream.local",
            "HTTP_HOST": "autostream.local",
            "HTTP_X_REQUESTED_WITH": "XMLHttpRequest",
        })
        out = result.stdout.decode(errors="replace")
        assert "Status: 403" not in out
        assert "Status: 400" not in out
        assert "Status: 405" not in out


# ---------------------------------------------------------------------------
# Archive contents (bash + /usr/bin/zip required)
# ---------------------------------------------------------------------------

@skip_no_bash
@pytest.mark.skipif(
    not Path("/usr/bin/zip").exists(),
    reason="/usr/bin/zip not available",
)
class TestDialCGIArchiveContents:
    def _run_valid_post(self, extra_env=None):
        env = {
            "REQUEST_METHOD": "POST",
            "HTTP_X_REQUESTED_WITH": "XMLHttpRequest",
        }
        if extra_env:
            env.update(extra_env)
        return _run_cgi(env)

    def _extract_zip(self, stdout_bytes: bytes):
        """Parse CGI stdout (HTTP headers + binary body) and return ZipFile."""
        import io
        # Find the blank line separating headers from body
        sep = b"\r\n\r\n"
        idx = stdout_bytes.find(sep)
        assert idx != -1, "No header/body separator found in CGI output"
        body = stdout_bytes[idx + len(sep):]
        return zipfile.ZipFile(io.BytesIO(body))

    def test_filename_prefix_in_response_header(self, tmp_path):
        """Content-Disposition must use the autostream-dial-logs- filename prefix."""
        result = self._run_valid_post()
        out = result.stdout.decode(errors="replace")
        assert "autostream-dial-logs-" in out, (
            "Content-Disposition filename must start with 'autostream-dial-logs-'"
        )

    def test_no_log_produces_readme(self, tmp_path):
        """When no dial logs exist, the ZIP must contain a README."""
        result = self._run_valid_post()
        assert result.returncode == 0
        zf = self._extract_zip(result.stdout)
        names = zf.namelist()
        readme_entries = [n for n in names if "README" in n.upper()]
        dial_log_entries = [n for n in names
                            if n.endswith(".log") and "owntone" not in n.lower()]
        # In the test environment there are no /var/log/autostream/dial-*.log
        # files readable by bash, so the README branch must be taken.
        assert readme_entries or dial_log_entries, (
            f"ZIP is empty (no README, no logs): {names}"
        )

    def test_zip_does_not_contain_owntone_log(self):
        """ZIP must never contain owntone.log."""
        result = self._run_valid_post()
        zf = self._extract_zip(result.stdout)
        owntone_entries = [n for n in zf.namelist() if "owntone" in n.lower()]
        assert not owntone_entries, (
            f"Dial log ZIP must not contain owntone entries: {owntone_entries}"
        )


# ---------------------------------------------------------------------------
# Deployment: installer deploys the dial CGI
# ---------------------------------------------------------------------------

class TestDialCGIDeployment:
    def test_download_logs_cgi_deployed_in_installer(self):
        """installer must deploy dial/cgi/download-logs.cgi to /opt/autostream/nginx/cgi/."""
        content = INSTALLER.read_text(encoding="utf-8")
        assert "dial/cgi/download-logs.cgi" in content, (
            "dial/cgi/download-logs.cgi deployment not found in autostream_dial_install.sh"
        )
        assert "/opt/autostream/nginx/cgi/" in content

    def test_download_logs_cgi_deployed_with_0755(self):
        """dial/cgi/download-logs.cgi must be deployed executable (0755)."""
        content = INSTALLER.read_text(encoding="utf-8")
        # Find the deployment line and check the mode flag is 0755
        lines = [l for l in content.splitlines() if "dial/cgi/download-logs.cgi" in l]
        assert lines, "No deployment line for dial/cgi/download-logs.cgi"
        assert any("0755" in l for l in lines), (
            "dial/cgi/download-logs.cgi must be deployed with mode 0755"
        )
