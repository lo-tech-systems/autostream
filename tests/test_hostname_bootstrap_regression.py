"""Regression tests for hostname validation and bootstrap parsing.

validate_hostname():
  Covers single-label boundaries, dot rejection, whitespace rejection, and the
  label character rules enforced by HOSTNAME_LABEL_RE.

bootstrap JSON parsing:
  The bootstrap.sh GitHub release parsing now uses Python stdlib json.load
  instead of tr/grep/cut. Tests verify correctness and demonstrate robustness
  against the formatting variations that tripped up the old approach.
"""
import importlib.util
import json
import subprocess
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
BOOTSTRAP = REPO_ROOT / "bootstrap.sh"


# ---------------------------------------------------------------------------
# Load autostream_admin (extensionless supervisor script)
# ---------------------------------------------------------------------------

def _load_admin() -> ModuleType:
    path = str(REPO_ROOT / "supervisor" / "autostream_admin")
    loader = SourceFileLoader("autostream_admin", path)
    spec = importlib.util.spec_from_loader("autostream_admin", loader)
    mod = importlib.util.module_from_spec(spec)
    if sys.platform == "win32":
        with patch.dict("sys.modules", {"fcntl": MagicMock()}):
            loader.exec_module(mod)
    else:
        loader.exec_module(mod)
    return mod


_admin = _load_admin()
validate_hostname = _admin.validate_hostname


# ---------------------------------------------------------------------------
# validate_hostname
# ---------------------------------------------------------------------------

class TestValidateHostname:
    # --- Whitespace rejection (Finding 1 fix) --------------------------------

    def test_leading_whitespace_rejected(self):
        ok, msg = validate_hostname(" foo")
        assert not ok
        assert "whitespace" in msg

    def test_trailing_whitespace_rejected(self):
        ok, msg = validate_hostname("foo ")
        assert not ok
        assert "whitespace" in msg

    def test_padded_valid_label_rejected(self):
        ok, msg = validate_hostname(" foo-bar ")
        assert not ok
        assert "whitespace" in msg

    # --- Length boundaries ---------------------------------------------------

    def test_empty_rejected(self):
        ok, msg = validate_hostname("")
        assert not ok
        assert "empty" in msg

    def test_single_char_accepted(self):
        ok, msg = validate_hostname("a")
        assert ok

    def test_max_length_63_accepted(self):
        ok, msg = validate_hostname("a" * 63)
        assert ok

    def test_length_64_rejected(self):
        ok, msg = validate_hostname("a" * 64)
        assert not ok
        assert "too long" in msg

    # --- Dot (multi-label) rejection -----------------------------------------

    def test_dot_rejected(self):
        ok, msg = validate_hostname("foo.bar")
        assert not ok
        assert "dot" in msg or "single label" in msg

    def test_fqdn_rejected(self):
        ok, msg = validate_hostname("foo.local")
        assert not ok

    def test_trailing_dot_rejected(self):
        ok, msg = validate_hostname("foo.")
        assert not ok

    # --- Character rules ------------------------------------------------------

    def test_valid_simple_name(self):
        ok, _ = validate_hostname("autostream")
        assert ok

    def test_valid_hyphen_name(self):
        ok, _ = validate_hostname("my-stream")
        assert ok

    def test_valid_alphanumeric_name(self):
        ok, _ = validate_hostname("stream42")
        assert ok

    def test_leading_hyphen_rejected(self):
        ok, msg = validate_hostname("-foo")
        assert not ok

    def test_trailing_hyphen_rejected(self):
        ok, msg = validate_hostname("foo-")
        assert not ok

    def test_underscore_rejected(self):
        ok, msg = validate_hostname("foo_bar")
        assert not ok

    def test_uppercase_accepted(self):
        # HOSTNAME_LABEL_RE uses re.IGNORECASE
        ok, _ = validate_hostname("FOO")
        assert ok

    def test_mixed_case_accepted(self):
        ok, _ = validate_hostname("MyStream")
        assert ok


# ---------------------------------------------------------------------------
# bootstrap.sh JSON parsing
# ---------------------------------------------------------------------------

_SAMPLE = {
    "tag_name": "v1.2.3",
    "tarball_url": "https://api.github.com/repos/lo-tech-systems/autostream/tarball/v1.2.3",
    "html_url": "https://github.com/lo-tech-systems/autostream/releases/tag/v1.2.3",
    "body": "Release notes here.",
}

_SNIPPET_TAG = "import json,sys; print(json.load(sys.stdin)['tag_name'])"
_SNIPPET_URL = "import json,sys; print(json.load(sys.stdin)['tarball_url'])"


def _run_snippet(snippet: str, stdin: bytes) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", snippet],
        input=stdin,
        capture_output=True,
    )


class TestBootstrapJsonParsing:
    """The Python snippet in bootstrap.sh must parse GitHub release JSON
    correctly and fail loudly on bad input, proving robustness over the
    replaced tr/grep/cut approach."""

    def test_compact_json_extracts_tag(self):
        raw = json.dumps(_SAMPLE, separators=(",", ":")).encode()
        r = _run_snippet(_SNIPPET_TAG, raw)
        assert r.returncode == 0
        assert r.stdout.strip() == b"v1.2.3"

    def test_compact_json_extracts_tarball_url(self):
        raw = json.dumps(_SAMPLE, separators=(",", ":")).encode()
        r = _run_snippet(_SNIPPET_URL, raw)
        assert r.returncode == 0
        assert r.stdout.strip() == _SAMPLE["tarball_url"].encode()

    def test_formatted_json_extracts_tag(self):
        """Pretty-printed JSON (spaces, newlines) must parse correctly —
        this was the failure mode of the old tr/grep/cut approach."""
        raw = json.dumps(_SAMPLE, indent=2).encode()
        r = _run_snippet(_SNIPPET_TAG, raw)
        assert r.returncode == 0
        assert r.stdout.strip() == b"v1.2.3"

    def test_formatted_json_extracts_tarball_url(self):
        raw = json.dumps(_SAMPLE, indent=4).encode()
        r = _run_snippet(_SNIPPET_URL, raw)
        assert r.returncode == 0
        assert r.stdout.strip() == _SAMPLE["tarball_url"].encode()

    def test_missing_tag_name_exits_nonzero(self):
        raw = json.dumps({"tarball_url": _SAMPLE["tarball_url"]}).encode()
        r = _run_snippet(_SNIPPET_TAG, raw)
        assert r.returncode != 0

    def test_missing_tarball_url_exits_nonzero(self):
        raw = json.dumps({"tag_name": _SAMPLE["tag_name"]}).encode()
        r = _run_snippet(_SNIPPET_URL, raw)
        assert r.returncode != 0

    def test_malformed_json_exits_nonzero(self):
        r = _run_snippet(_SNIPPET_TAG, b'{"tag_name": "v1" bad json}')
        assert r.returncode != 0

    def test_empty_input_exits_nonzero(self):
        r = _run_snippet(_SNIPPET_TAG, b"")
        assert r.returncode != 0

    def test_script_uses_python_json_not_grep(self):
        """Structural: bootstrap.sh must use python3/json.load; tr/grep/cut must be gone."""
        content = BOOTSTRAP.read_text(encoding="utf-8")
        assert "python3" in content
        assert "json.load" in content
        assert "grep -o" not in content
        assert "tr -d" not in content
