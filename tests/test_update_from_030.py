"""Update-path compatibility: 0.3.0 updater vs. the CURRENT tree's release shape.

Proves that the self-contained updater shipped at commit 30ae289 (before
autostream_update_support.py was factored out) can still discover, stage, and
schedule installation of a release built from HEAD.  This is the guardrail
that a real 0.3.0 device in the field will be able to update itself to
whatever we ship next.

The 0.3.0 script is loaded verbatim via `git show 30ae289:supervisor/autostream_updater`
at test time (never checked out), so this test always exercises the exact
bytes that shipped, not a hand-copied approximation.  The "new release" is a
tarball built from the CURRENT tree with `git archive`, which is byte-shape
compatible with a GitHub codeload tarball (single top-level `<prefix>/` dir).

Key facts about the 0.3.0 script established by reading it (do not assume
these match HEAD's updater — they do not):
  - cmd_check() / cmd_apply() take NO arguments (HEAD's cmd_apply(auto=...)
    does not exist at 0.3.0).
  - Discovery is GitHub `releases/latest` ONLY — no channel/prerelease concept
    at all.  A release published as a GitHub "pre-release" is invisible to it.
  - Installed tag is read from install-state.env key AUTOSTREAM_RELEASE_TAG
    via a hand-rolled _read_env_file/_read_installed_release_tag.
  - Versions are compared with a hand-rolled _version_key using regex
    ``^v?(\\d+)(?:\\.(\\d+))?(?:\\.(\\d+))?(?:[-+].*)?$``.
  - _download_file(url, dst, timeout=120) — no `ua` parameter (UA is a module
    constant baked into the request headers directly).
  - Extraction expects exactly one top-level directory in the tarball,
    containing autostream_install.sh and a system/ directory.
  - A `release_tag` file is written into the staging dir.
  - The installer is scheduled via systemd-run + flock --exclusive, with
    AUTOSTREAM_RELEASE_TAG set to the *raw* tag (e.g. "v0.4.0", not "0.4.0").
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).parent.parent
OLD_UPDATER_COMMIT = "30ae289"

# Set this to the actual tag before cutting the release that 0.3.0 devices
# must be able to discover and install.
CANDIDATE_TAG = "v0.4.0"


# ---------------------------------------------------------------------------
# Fixtures: extract the real 0.3.0 script, build a HEAD-tree release tarball
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def old_updater_source(tmp_path_factory) -> Path:
    """Extract supervisor/autostream_updater exactly as it shipped at 0.3.0."""
    out_dir = tmp_path_factory.mktemp("old_updater_src")
    src_path = out_dir / "autostream_updater_030"
    result = subprocess.run(
        ["git", "show", f"{OLD_UPDATER_COMMIT}:supervisor/autostream_updater"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=True,
    )
    src_path.write_text(result.stdout, encoding="utf-8")
    return src_path


@pytest.fixture(scope="module")
def head_release_tarball(tmp_path_factory) -> Path:
    """Build a release tarball from the CURRENT tree (HEAD), codeload-shaped.

    git archive with an explicit --prefix produces a single top-level
    directory inside the tarball, exactly like GitHub's tarball_url assets
    (owner-repo-sha/...).
    """
    out_dir = tmp_path_factory.mktemp("head_release")
    tar_path = out_dir / "release.tgz"
    subprocess.run(
        [
            "git", "archive", "--format=tar.gz",
            "--prefix=lo-tech-systems-autostream-deadbee/",
            "HEAD", "-o", str(tar_path),
        ],
        cwd=str(REPO_ROOT),
        check=True,
    )
    return tar_path


def _load_old_updater(source_path: Path, alias: str) -> ModuleType:
    """Load the extensionless 0.3.0 script, stubbing fcntl/pwd/grp on Windows.

    Mirrors tests/conftest.py::load_supervisor_script so this file also
    collects (and runs, with real behaviour skipped where platform-gated) on
    Windows, consistent with the rest of the suite's conventions.
    """
    loader = SourceFileLoader(alias, str(source_path))
    spec = importlib.util.spec_from_loader(alias, loader)
    mod = importlib.util.module_from_spec(spec)

    injected = []
    if sys.platform == "win32":
        for stub_name in ("fcntl", "pwd", "grp"):
            if stub_name not in sys.modules:
                sys.modules[stub_name] = MagicMock()
                injected.append(stub_name)
    try:
        loader.exec_module(mod)
    finally:
        for stub_name in injected:
            sys.modules.pop(stub_name, None)
    return mod


@pytest.fixture()
def old_mod(old_updater_source, tmp_path) -> ModuleType:
    mod = _load_old_updater(old_updater_source, f"updater_030_{id(tmp_path)}")
    mod.LOG_PATH = tmp_path / "update.log"
    mod.APMODE_FLAG = tmp_path / "_apmode_absent"
    mod.INSTALL_STATE_FILE = tmp_path / "install-state.env"
    mod.UPDATE_LOCK_FILE = tmp_path / "update.lock"
    mod.UPDATE_RESULT_FILE = tmp_path / "update-result.env"
    mod.STAGING_DIR = tmp_path / "staging"
    return mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_latest_release_json(tag: str, tarball_url: str, body: str = "Release notes."):
    return {
        "tag_name": tag,
        "tarball_url": tarball_url,
        "html_url": f"https://github.com/lo-tech-systems/autostream/releases/{tag}",
        "body": body,
    }


def _fake_urlopen(latest_json: dict):
    """Build a urlopen stand-in serving both API_LATEST and RELEASES_HTML.

    The 0.3.0 script hits two distinct URLs: the releases/latest API (for
    cmd_check/cmd_apply's discovery) and the plain releases HTML page (for
    _repo_exists' reachability probe). Both go through urllib.request.urlopen.
    """
    class _FakeResp:
        def __init__(self, payload: bytes):
            self._payload = payload
            self.status = 200

        def read(self):
            return self._payload

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def _urlopen(req, timeout=20):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if "releases/latest" in url:
            return _FakeResp(json.dumps(latest_json).encode("utf-8"))
        # RELEASES_HTML reachability probe — any 200 body is fine.
        return _FakeResp(b"<html></html>")

    return _urlopen


def _copy_tarball_to(src_tar: Path):
    """Old-script-compatible _download_file replacement: (url, dst, timeout)."""
    def _download(url, dst, timeout=120):
        import shutil
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(src_tar), str(dst))
    return _download


def _seed_installed_tag(mod, tag: str):
    mod.INSTALL_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    mod.INSTALL_STATE_FILE.write_text(f'AUTOSTREAM_RELEASE_TAG="{tag}"\n', encoding="utf-8")


# ---------------------------------------------------------------------------
# (a) Old _version_key ranks the candidate tag above 0.3.0; tag-format guard
# ---------------------------------------------------------------------------

class TestOldVersionKeyRanking:
    def test_candidate_ranks_above_030(self, old_mod):
        candidate = CANDIDATE_TAG.lstrip("v")
        assert old_mod._version_key(candidate) > old_mod._version_key("0.3.0")

    def test_candidate_tag_matches_old_semver_regex(self, old_mod):
        """The 0.3.0 tag-format guard: an unparseable tag silently ranks as
        (0, 0, 0, tag) and would never look newer than an installed release.
        The upcoming tag must match the old regex or 0.3.0 devices will never
        see it as an update."""
        assert old_mod._semver_re.match(CANDIDATE_TAG), (
            f"{CANDIDATE_TAG!r} does not match the 0.3.0 updater's tag regex; "
            "0.3.0 devices would never recognise it as newer."
        )


# ---------------------------------------------------------------------------
# (b) cmd_check reports an update available against a fake releases/latest
# ---------------------------------------------------------------------------

class TestOldCheckDiscoversUpdate:
    def test_check_reports_update_available(self, old_mod):
        _seed_installed_tag(old_mod, "0.3.0")
        latest = _fake_latest_release_json(
            CANDIDATE_TAG, "https://api.github.com/repos/lo-tech-systems/autostream/tarball/x"
        )
        with patch("urllib.request.urlopen", side_effect=_fake_urlopen(latest)):
            result = old_mod.cmd_check()
        assert result["ok"] is True
        assert result["installed"] == "0.3.0"
        assert result["candidate"] == CANDIDATE_TAG.lstrip("v")
        assert result["update_available"] is True


# ---------------------------------------------------------------------------
# (c) Full apply path: stage + schedule against the REAL current tree
# ---------------------------------------------------------------------------

class TestOldApplyStagesCurrentTree:
    def _run_apply(self, old_mod, tmp_path, tarball: Path):
        latest = _fake_latest_release_json(
            CANDIDATE_TAG, "https://api.github.com/repos/lo-tech-systems/autostream/tarball/x"
        )
        _seed_installed_tag(old_mod, "0.3.0")
        captured_cmd = {}

        def fake_run(cmd, timeout=60):
            captured_cmd["cmd"] = cmd
            return (0, "", "")

        with patch("urllib.request.urlopen", side_effect=_fake_urlopen(latest)), \
             patch.object(old_mod, "_download_file", side_effect=_copy_tarball_to(tarball)), \
             patch.object(old_mod, "_update_unit_active", return_value=False), \
             patch.object(old_mod, "_find_systemd_run", return_value="/usr/bin/systemd-run"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.access", return_value=True), \
             patch.object(old_mod, "_run", side_effect=fake_run):
            result = old_mod.cmd_apply()
        return result, captured_cmd.get("cmd", [])

    def test_staging_succeeds_against_real_tree(self, old_mod, tmp_path, head_release_tarball):
        result, _ = self._run_apply(old_mod, tmp_path, head_release_tarball)
        assert result["ok"] is True, result
        assert result["staged_tag"] == CANDIDATE_TAG.lstrip("v")

        repo_root = old_mod.STAGING_DIR / "src" / "lo-tech-systems-autostream-deadbee"
        installer = repo_root / "autostream_install.sh"
        assert installer.exists(), "autostream_install.sh must be present in the staged tree"
        assert installer.stat().st_mode & 0o111, "autostream_install.sh must be made executable"
        assert (repo_root / "system").is_dir(), "system/ directory must be present in the staged tree"

    def test_release_tag_file_written(self, old_mod, tmp_path, head_release_tarball):
        result, _ = self._run_apply(old_mod, tmp_path, head_release_tarball)
        assert result["ok"] is True, result
        tag_file = old_mod.STAGING_DIR / "release_tag"
        assert tag_file.exists()
        assert tag_file.read_text(encoding="utf-8").strip() == CANDIDATE_TAG

    def test_scheduled_command_shape(self, old_mod, tmp_path, head_release_tarball):
        result, cmd = self._run_apply(old_mod, tmp_path, head_release_tarball)
        assert result["ok"] is True, result
        cmd_str = " ".join(cmd)
        assert "autostream_install.sh" in cmd_str
        assert "--update" in cmd_str
        assert f"AUTOSTREAM_RELEASE_TAG={CANDIDATE_TAG}" in cmd_str


# ---------------------------------------------------------------------------
# (d) Pre-release guard: releases/latest is the ONLY discovery path
# ---------------------------------------------------------------------------

class TestOldUpdaterHasNoPrereleaseAwareness:
    def test_api_constant_is_releases_latest(self, old_mod):
        assert old_mod.API_LATEST == (
            "https://api.github.com/repos/lo-tech-systems/autostream/releases/latest"
        )

    def test_source_has_no_prerelease_or_channel_handling(self, old_updater_source):
        """Documents that the upcoming release MUST be published as a normal
        GitHub release, not a pre-release: 0.3.0's updater calls
        /releases/latest (which GitHub never returns pre-releases from) and
        has no channel/prerelease concept to fall back to. A pre-release
        would be permanently invisible to 0.3.0 devices."""
        src = old_updater_source.read_text(encoding="utf-8")
        assert "prerelease" not in src.lower()
        assert "channel" not in src.lower()
        assert "/releases/latest" in src
        # Only one discovery function exists.
        assert src.count("def _github_latest_release") == 1


# ---------------------------------------------------------------------------
# (e) Installer backward-compat guard: current autostream_install.sh does not
#     require any env var beyond what the old updater exports.
# ---------------------------------------------------------------------------

class TestInstallerBackwardCompat:
    def test_installer_present_and_executable_in_head_tarball(self, head_release_tarball):
        with tarfile.open(head_release_tarball, "r:gz") as tf:
            names = tf.getnames()
            installer_members = [
                n for n in names
                if n.endswith("/autostream_install.sh") and n.count("/") == 1
            ]
            assert installer_members, "autostream_install.sh must be at repo root in the tarball"
            info = tf.getmember(installer_members[0])
            assert info.mode & 0o111, "autostream_install.sh must be executable in the archive"

    def test_installer_only_reads_autostream_release_tag_with_safe_default(self):
        """The old updater's --setenv only ever sets AUTOSTREAM_RELEASE_TAG.
        Assert the CURRENT installer does not require any other AUTOSTREAM_*
        environment variable, and that AUTOSTREAM_RELEASE_TAG itself is read
        with a safe ${VAR:-} default (not ${VAR:?...}), so its absence does
        not hard-fail the script."""
        installer_src = (REPO_ROOT / "autostream_install.sh").read_text(encoding="utf-8")

        # detect_install_version() is the sole consumer of AUTOSTREAM_RELEASE_TAG
        # from the environment, and it uses the safe default-expansion form.
        assert '${AUTOSTREAM_RELEASE_TAG:-}' in installer_src, (
            "AUTOSTREAM_RELEASE_TAG must be read with a safe ${VAR:-} default"
        )
        # No AUTOSTREAM_* variable anywhere uses the fail-fast ${VAR:?...} form,
        # which would abort the script if the old updater didn't export it.
        import re
        fail_fast = re.findall(r"\$\{AUTOSTREAM_[A-Z_]+:\?", installer_src)
        assert not fail_fast, (
            f"installer hard-fails on absence of env var(s) {fail_fast}; "
            "the 0.3.0 updater does not export these and would break the update"
        )

        # AUTOSTREAM_DIR — the only other AUTOSTREAM_* token referenced as a
        # shell variable — is always computed from the script's own location,
        # never read from the environment, so the old updater need not set it.
        assert 'AUTOSTREAM_DIR="$(cd "$(dirname "$0")" && pwd)"' in installer_src, (
            "AUTOSTREAM_DIR must be self-computed, not required from the environment"
        )
