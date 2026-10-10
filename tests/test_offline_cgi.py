"""Regression tests for offline recovery CGI method/origin/XRW enforcement.

Verifies that:
- GET is rejected with 405 (method check).
- POST with a foreign Origin is rejected with 403 (CSRF check).
- POST without X-Requested-With is rejected with 400 (XRW check).
- A well-formed same-origin POST passes all validation gates (no 4xx from guards).
- No 403 is returned for any valid POST (no PIN / credential gate).

Tests are skipped when bash cannot execute a script at a Windows-style path.
Running `bash -c :` is insufficient: the WSL launcher satisfies that probe but
fails when given a Windows path like C:\\...  We verify bash using a temporary
script file at a native path, matching how the tests actually invoke the CGIs.
"""
import subprocess
from pathlib import Path

import pytest

from conftest import bash_can_run_script_at_windows_path

REPO_ROOT = Path(__file__).parent.parent
CGI_DIR = REPO_ROOT / "nginx" / "cgi"

SCRIPTS = ["reboot.cgi", "factory-reset.cgi", "download-logs.cgi"]


skip_no_bash = pytest.mark.skipif(
    not bash_can_run_script_at_windows_path(),
    reason="bash cannot execute a script at a Windows path (WSL launcher or bash absent)",
)


def _run_cgi(script_name: str, env_overrides: dict) -> subprocess.CompletedProcess:
    """Run a CGI script with a minimal CGI environment."""
    script = CGI_DIR / script_name
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "REQUEST_METHOD": "",
        "HTTP_HOST": "autostream.local",
        "CONTENT_LENGTH": "0",
    }
    env.update(env_overrides)
    return subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=10,
    )


@skip_no_bash
@pytest.mark.parametrize("script", SCRIPTS)
def test_get_rejected_with_405(script):
    """GET requests must be rejected before any action is attempted."""
    result = _run_cgi(script, {"REQUEST_METHOD": "GET"})
    assert "Status: 405" in result.stdout


@skip_no_bash
@pytest.mark.parametrize("script", SCRIPTS)
def test_cross_origin_post_rejected_with_403(script):
    """POST from a foreign origin must be rejected (CSRF guard)."""
    result = _run_cgi(script, {
        "REQUEST_METHOD": "POST",
        "HTTP_ORIGIN": "http://attacker.example.com",
        "HTTP_HOST": "autostream.local",
    })
    assert "Status: 403" in result.stdout


@skip_no_bash
@pytest.mark.parametrize("script", SCRIPTS)
def test_missing_xrw_header_rejected_with_400(script):
    """POST without X-Requested-With must be rejected."""
    result = _run_cgi(script, {
        "REQUEST_METHOD": "POST",
        # HTTP_X_REQUESTED_WITH absent
    })
    assert "Status: 400" in result.stdout


@skip_no_bash
@pytest.mark.parametrize("script", SCRIPTS)
def test_valid_post_passes_all_validation_gates(script):
    """A well-formed POST must not be rejected by any of the validation guards.

    The action itself will fail in the test environment (no admin binary,
    no /usr/bin/zip, etc.), but the response must not contain a 400, 403,
    or 405 originating from the guard checks.

    Regression: previously a token or PIN check produced a spurious 403 that
    blocked all recovery operations from the offline page.
    """
    result = _run_cgi(script, {
        "REQUEST_METHOD": "POST",
        "HTTP_X_REQUESTED_WITH": "XMLHttpRequest",
        # No HTTP_ORIGIN: same-origin request from the offline page
    })
    assert "Status: 405" not in result.stdout
    assert "Status: 400" not in result.stdout
    assert "Status: 403" not in result.stdout


@skip_no_bash
@pytest.mark.parametrize("script", SCRIPTS)
def test_same_origin_post_with_origin_header_passes(script):
    """POST with a same-origin Origin header must also pass the origin guard."""
    result = _run_cgi(script, {
        "REQUEST_METHOD": "POST",
        "HTTP_ORIGIN": "http://autostream.local",
        "HTTP_HOST": "autostream.local",
        "HTTP_X_REQUESTED_WITH": "XMLHttpRequest",
    })
    assert "Status: 403" not in result.stdout
    assert "Status: 400" not in result.stdout
    assert "Status: 405" not in result.stdout


def _appliance_bundle(log_dir: Path, owntone_log: Path) -> set[str]:
    """Run the appliance download-logs.cgi against scratch log locations and
    return the names inside the ZIP it sends."""
    import io
    import zipfile
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "REQUEST_METHOD": "POST",
        "HTTP_HOST": "autostream.local",
        "HTTP_X_REQUESTED_WITH": "XMLHttpRequest",
        "CONTENT_LENGTH": "0",
        "AUTOSTREAM_LOG_DIR": str(log_dir),
        "AUTOSTREAM_OWNTONE_LOG": str(owntone_log),
    }
    result = subprocess.run(
        ["bash", str(CGI_DIR / "download-logs.cgi")],
        capture_output=True, env=env, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    sep = result.stdout.find(b"\r\n\r\n")
    assert sep != -1
    names = zipfile.ZipFile(io.BytesIO(result.stdout[sep + 4:])).namelist()
    return {n for n in names if not n.endswith("/")}


@skip_no_bash
@pytest.mark.skipif(not Path("/usr/bin/zip").exists(), reason="/usr/bin/zip not available")
class TestApplianceLogBundle:
    def test_autostream_logs_include_every_rotation(self, tmp_path):
        log_dir = tmp_path / "autostream"
        log_dir.mkdir()
        for name in ("autostream.log", "autostream.log.1", "autostream.log.2.gz", "autostream.log.14.gz"):
            (log_dir / name).write_bytes(b"x")
        names = _appliance_bundle(log_dir, tmp_path / "owntone.log")
        for name in ("autostream.log", "autostream.log.1", "autostream.log.2.gz", "autostream.log.14.gz"):
            assert f"autostream/{name}" in names

    def test_owntone_log_comes_with_its_three_latest_rotations(self, tmp_path):
        log_dir = tmp_path / "autostream"
        log_dir.mkdir()
        owntone = tmp_path / "owntone.log"
        owntone.write_text("current\n")
        (tmp_path / "owntone.log.1").write_text("yesterday\n")
        for n in (2, 3, 4):
            (tmp_path / f"owntone.log.{n}.gz").write_bytes(b"\x1f\x8b")
        names = _appliance_bundle(log_dir, owntone)
        for name in ("owntone.log", "owntone.log.1", "owntone.log.2.gz", "owntone.log.3.gz"):
            assert f"owntone/{name}" in names, sorted(names)
        assert "owntone/owntone.log.4.gz" not in names

    def test_no_logs_gives_a_readme(self, tmp_path):
        log_dir = tmp_path / "autostream"
        log_dir.mkdir()
        assert _appliance_bundle(log_dir, tmp_path / "owntone.log") == {"README.txt"}
