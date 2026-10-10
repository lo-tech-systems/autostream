"""Regression tests for authenticated log bundle download.

Verifies that:
- handle_logs_download() produces a valid ZIP response.
- The implementation streams from a temp file (not io.BytesIO), so peak memory
  is bounded — verified behaviourally by observing when the file is alive.
- The /logs/download route lives in the Python web UI, not in the CGI layer,
  so it is subject to the Python auth gate.
- /logs/download is not in the auth allowlist (requires auth when PIN enabled).
"""
import ast
import io
import os
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
_core = str(REPO_ROOT / "core")
if _core not in sys.path:
    sys.path.insert(0, _core)

# Modules that have heavy runtime dependencies (requests, owntone stack, …).
# Mocked via a scoped fixture so sys.modules is fully restored after this
# test module's session ends and unrelated future tests are not affected.
_HEAVY_DEPS = [
    "requests",
    "autostream_config",
    "autostream_core",
    "autostream_player_service",
    "autostream_players",
    "autostream_webui_common",
    "autostream_webui_state",
]

_ABSENT = object()  # sentinel for "key was not in sys.modules before setup"


@pytest.fixture(autouse=True, scope="module")
def _mock_heavy_deps():
    """Inject mocks for heavy deps, then restore exactly those keys on teardown.

    patch.dict is intentionally avoided: it snapshots the entire sys.modules
    dict and restores the snapshot on exit, which removes any module imported
    during the fixture's lifetime that was not present at setup time.  Manual
    teardown touches only the keys this fixture owns, leaving every other
    entry in sys.modules undisturbed.
    """
    _owned = _HEAVY_DEPS + ["autostream_webui_page_logs"]

    # Save pre-fixture state of each key we are about to touch.
    _saved = {k: sys.modules.get(k, _ABSENT) for k in _owned}

    # Install mocks and evict any cached real import of the module under test.
    for m in _HEAVY_DEPS:
        sys.modules[m] = MagicMock()
    sys.modules.pop("autostream_webui_page_logs", None)

    yield

    # Restore only the keys this fixture touched.
    for k, original in _saved.items():
        if original is _ABSENT:
            sys.modules.pop(k, None)
        else:
            sys.modules[k] = original


# ---------------------------------------------------------------------------
# Mock handler
# ---------------------------------------------------------------------------

class _MockHandler:
    """Minimal stand-in for the Python HTTP request handler."""

    def __init__(self) -> None:
        self._buf = io.BytesIO()
        self.wfile = self._buf
        self._status: int | None = None
        self._headers: list[tuple[str, str]] = []

    def send_response(self, code: int) -> None:
        self._status = code

    def send_header(self, key: str, value: str) -> None:
        self._headers.append((key, value))

    def end_headers(self) -> None:
        pass

    @property
    def response_bytes(self) -> bytes:
        return self._buf.getvalue()

    def header(self, key: str) -> str | None:
        for k, v in self._headers:
            if k.lower() == key.lower():
                return v
        return None


# ---------------------------------------------------------------------------
# Tests: handler behaviour
# ---------------------------------------------------------------------------

class TestLogsDownloadHandler:
    def test_produces_valid_zip(self) -> None:
        """Response body must be a valid ZIP file."""
        from autostream_webui_page_logs import handle_logs_download

        handler = _MockHandler()
        handle_logs_download(handler)

        data = handler.response_bytes
        assert len(data) > 0
        assert zipfile.is_zipfile(io.BytesIO(data)), "Response body is not a valid ZIP"

    def test_content_type_is_octet_stream(self) -> None:
        from autostream_webui_page_logs import handle_logs_download

        handler = _MockHandler()
        handle_logs_download(handler)

        assert handler.header("Content-Type") == "application/octet-stream"

    def test_content_length_matches_body(self) -> None:
        """Content-Length header must match the actual bytes written."""
        from autostream_webui_page_logs import handle_logs_download

        handler = _MockHandler()
        handle_logs_download(handler)

        declared = handler.header("Content-Length")
        assert declared is not None
        assert int(declared) == len(handler.response_bytes)

    def test_response_is_streamed_from_temp_file(self) -> None:
        """ZIP data must flow to wfile while the on-disk temp file still exists.

        Behavioural regression guard for the BytesIO double-buffer bug:
        - If the implementation reverted to BytesIO + getvalue(), no mkstemp
          would be called and the first assertion fails.
        - If data were written to wfile only after the temp file was deleted,
          the per-write file-alive checks would record False and the second
          assertion fails.
        - The final assertion confirms the temp file is cleaned up afterwards.
        """
        from autostream_webui_page_logs import handle_logs_download

        temp_paths: list[str] = []
        file_alive_on_write: list[bool] = []
        _orig_mkstemp = tempfile.mkstemp

        def _tracking_mkstemp(*args, **kwargs):
            fd, path = _orig_mkstemp(*args, **kwargs)
            temp_paths.append(path)
            return fd, path

        class _ObservingWfile:
            """Proxy that records whether the temp file exists on each write."""
            def __init__(self, buf: io.BytesIO) -> None:
                self._buf = buf
            def write(self, data: bytes) -> None:
                if temp_paths:
                    file_alive_on_write.append(os.path.exists(temp_paths[-1]))
                self._buf.write(data)

        handler = _MockHandler()
        handler.wfile = _ObservingWfile(handler._buf)

        with patch("autostream_webui_page_logs.tempfile.mkstemp",
                   side_effect=_tracking_mkstemp):
            handle_logs_download(handler)

        assert temp_paths, (
            "tempfile.mkstemp was never called — possible BytesIO regression"
        )
        assert file_alive_on_write, "wfile.write was never called"
        assert all(file_alive_on_write), (
            "Temp file did not exist during one or more wfile writes; "
            "data was not streamed from disk"
        )
        for path in temp_paths:
            assert not os.path.exists(path), f"Temp file not cleaned up: {path}"


# ---------------------------------------------------------------------------
# Tests: routing and auth
# ---------------------------------------------------------------------------

class TestLogsDownloadRouting:
    def test_route_exists_in_python_webui(self) -> None:
        """/logs/download must be handled by the Python web UI router.

        Migrated into the route table (autostream_webui_routes.ROUTES) --
        it's no longer a literal string in autostream_webui.py's
        do_GET, so check the table itself rather than grepping source.
        """
        import sys
        _core = str(REPO_ROOT / "core")
        if _core not in sys.path:
            sys.path.insert(0, _core)
        import autostream_webui_routes as routes_mod

        r = routes_mod._resolve("/logs/download", "GET")
        assert r is not None, "/logs/download route not found in ROUTES"

    def test_route_is_not_in_auth_allowlist(self) -> None:
        """/logs/download must NOT be in ALLOWLIST_PATHS so it requires auth.

        Regression: if /logs/download were added to the allowlist, any
        unauthenticated client could download logs without a PIN.
        """
        auth_src = (REPO_ROOT / "core" / "autostream_auth.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(auth_src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "ALLOWLIST_PATHS":
                        paths = {
                            elt.value
                            for elt in node.value.elts
                            if isinstance(elt, ast.Constant)
                        }
                        assert "/logs/download" not in paths, (
                            "/logs/download must not be in ALLOWLIST_PATHS"
                        )
                        return
        pytest.fail("ALLOWLIST_PATHS not found in autostream_auth.py")


# ---------------------------------------------------------------------------
# Tests: which files the bundle carries
# ---------------------------------------------------------------------------

class TestLogsBundleMembers:
    def _names(self, tmp_path):
        from autostream_webui_page_logs import _bundle_members
        log_dir = tmp_path / "autostream"
        return {name for _, name in _bundle_members(log_dir, tmp_path / "owntone.log")}

    def test_autostream_logs_include_every_rotation(self, tmp_path):
        log_dir = tmp_path / "autostream"
        log_dir.mkdir()
        for name in ("autostream.log", "autostream.log.1", "autostream.log.2.gz", "autostream.log.14.gz"):
            (log_dir / name).write_bytes(b"x")
        names = self._names(tmp_path)
        assert {f"autostream/{n}" for n in ("autostream.log", "autostream.log.1",
                                            "autostream.log.2.gz", "autostream.log.14.gz")} <= names

    def test_owntone_log_comes_with_its_three_latest_rotations(self, tmp_path):
        (tmp_path / "autostream").mkdir()
        (tmp_path / "owntone.log").write_text("current\n")
        (tmp_path / "owntone.log.1").write_text("yesterday\n")
        for n in (2, 3, 4):
            (tmp_path / f"owntone.log.{n}.gz").write_bytes(b"\x1f\x8b")
        names = self._names(tmp_path)
        assert {"owntone/owntone.log", "owntone/owntone.log.1",
                "owntone/owntone.log.2.gz", "owntone/owntone.log.3.gz"} <= names
        assert "owntone/owntone.log.4.gz" not in names

    def test_rotations_bundled_without_a_current_owntone_log(self, tmp_path):
        (tmp_path / "autostream").mkdir()
        (tmp_path / "owntone.log.1").write_text("yesterday\n")
        assert self._names(tmp_path) == {"owntone/owntone.log.1"}

    def test_zip_carries_the_bundle_members(self, tmp_path, monkeypatch):
        import autostream_webui_page_logs as logs
        log_dir = tmp_path / "autostream"
        log_dir.mkdir()
        (log_dir / "autostream.log").write_text("x\n")
        (tmp_path / "owntone.log.1").write_text("y\n")
        monkeypatch.setattr(logs, "BUNDLE_LOG_DIR", log_dir)
        monkeypatch.setattr(logs, "BUNDLE_OWNTONE_LOG", tmp_path / "owntone.log")
        handler = _MockHandler()
        logs.handle_logs_download(handler)
        names = set(zipfile.ZipFile(io.BytesIO(handler.response_bytes)).namelist())
        assert names == {"autostream/autostream.log", "owntone/owntone.log.1"}
