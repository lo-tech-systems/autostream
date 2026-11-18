"""The installer removes application files an earlier release left behind.

The copy into the install directory adds and replaces but never removes.
installer/lib/deploy_manifest.sh prunes, after the copy, by manifest: the
files the previous release shipped (recorded in .core-manifest) that this one
does not. Without a manifest (the first upgrade from a release that wrote
none) only top-level autostream_*.py modules not in the new release go.

Every removal here is made in a temporary directory standing for the install
directory; nothing touches a real system.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from conftest import bash_can_run_script_at_windows_path  # noqa: E402

REPO_ROOT = Path(__file__).parent.parent
LIB = REPO_ROOT / "installer" / "lib" / "deploy_manifest.sh"
INSTALL_SH = REPO_ROOT / "autostream_install.sh"
CORE = REPO_ROOT / "core"

bash_capable = pytest.mark.skipif(
    not bash_can_run_script_at_windows_path(),
    reason="bash cannot execute scripts at this path (MSYS2 limitation on Windows)",
)


def _shellcheck_ok() -> bool:
    try:
        return subprocess.run(
            ["shellcheck", "--version"], capture_output=True, timeout=5).returncode == 0
    except Exception:
        return False


shellcheck_available = pytest.mark.skipif(
    not _shellcheck_ok(), reason="shellcheck not installed")


def _touch(root: Path, rel: str, text: str = "x\n") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _bash(body: str) -> subprocess.CompletedProcess:
    script = (
        "set -Eeuo pipefail\n"
        'info() { echo "[INFO] $*"; }\n'
        f'source "{LIB.as_posix()}"\n{body}'
    )
    return subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, timeout=30)


def _run(body: str) -> subprocess.CompletedProcess:
    result = _bash(body)
    assert result.returncode == 0, result.stdout + result.stderr
    return result


@pytest.fixture
def trees(tmp_path):
    """A source tree for the new release and an install directory."""
    src = tmp_path / "src"
    dest = tmp_path / "dest"
    _touch(src, "core/autostream_new.py")
    _touch(src, "core/autostream_kept.py")
    _touch(src, "core/requirements.txt")
    _touch(src, "core/track_id/models.py")
    _touch(src, "core/monitor/autostream_monitor.cpp")
    _touch(src, "core/__pycache__/autostream_kept.cpython-313.pyc")
    _touch(src, "nginx/static/poll.js")
    _touch(src, "nginx/offline/offline.html")
    dest.mkdir()
    return src, dest


def _prune(src: Path, dest: Path) -> subprocess.CompletedProcess:
    return _run(f'deploy_manifest_prune "{dest.as_posix()}" "{src.as_posix()}"')


# ---------------------------------------------------------------------------
# The shipped list
# ---------------------------------------------------------------------------

@bash_capable
class TestList:
    def test_core_and_static_files_are_listed_sorted_without_compiled_files(self, trees):
        src, _dest = trees
        out = _run(f'deploy_manifest_list "{src.as_posix()}"').stdout.splitlines()
        assert out == [
            "autostream_kept.py",
            "autostream_new.py",
            "monitor/autostream_monitor.cpp",
            "nginx/static/poll.js",
            "requirements.txt",
            "track_id/models.py",
        ]

    def test_a_tree_without_core_or_static_lists_nothing(self, tmp_path):
        out = _run(f'deploy_manifest_list "{tmp_path.as_posix()}"').stdout
        assert out == ""

    def test_files_installed_beside_core_from_elsewhere_are_listed(self, tmp_path):
        for name in ("wifi_watcher.py", "wifi_state.py", "wifi_web.py", "other.py"):
            _touch(tmp_path, f"platform/{name}")
        _touch(tmp_path, "LICENSE")
        out = _run(f'deploy_manifest_list "{tmp_path.as_posix()}"').stdout.splitlines()
        assert out == ["LICENSE", "autostream_wifi_watcher", "wifi_state.py", "wifi_web.py"]

    def test_a_module_that_moved_out_of_core_is_kept_where_it_is_installed(self, trees):
        src, dest = trees
        (dest / ".core-manifest").write_text("wifi_state.py\n", encoding="utf-8")
        _touch(src, "platform/wifi_state.py")
        _touch(dest, "wifi_state.py")
        _prune(src, dest)
        assert (dest / "wifi_state.py").exists()


# ---------------------------------------------------------------------------
# First upgrade: no manifest
# ---------------------------------------------------------------------------

@bash_capable
class TestFirstUpgrade:
    def test_removes_a_planted_stale_module_and_its_compiled_copy(self, trees):
        src, dest = trees
        _touch(dest, "autostream_old.py")
        _touch(dest, "__pycache__/autostream_old.cpython-313.pyc")
        _touch(dest, "autostream_kept.py")
        _touch(dest, "__pycache__/autostream_kept.cpython-313.pyc")
        result = _prune(src, dest)
        assert not (dest / "autostream_old.py").exists()
        assert not (dest / "__pycache__" / "autostream_old.cpython-313.pyc").exists()
        assert (dest / "autostream_kept.py").exists()
        assert (dest / "__pycache__" / "autostream_kept.cpython-313.pyc").exists()
        assert "autostream_old.py" in result.stdout

    def test_keeps_everything_that_is_not_a_stale_top_level_module(self, trees):
        src, dest = trees
        _touch(dest, "autostream_old.py")
        for rel in (
            "autostream_wifi_watcher", "wifi_state.py", "LICENSE", "ssid",
            "venv/lib/site.py", "monitor/autostream_monitor", "monitor/autostream_old.py",
            "track_id/autostream_nested.py", "nginx/static/poll.js", "images/logo.png",
            "autostream_data.json",
        ):
            _touch(dest, rel)
        _prune(src, dest)
        assert not (dest / "autostream_old.py").exists()
        for rel in (
            "autostream_wifi_watcher", "wifi_state.py", "LICENSE", "ssid",
            "venv/lib/site.py", "monitor/autostream_monitor", "monitor/autostream_old.py",
            "track_id/autostream_nested.py", "nginx/static/poll.js", "images/logo.png",
            "autostream_data.json",
        ):
            assert (dest / rel).exists(), rel

    @pytest.mark.parametrize("manifest", [
        "../etc/passwd\n",
        "autostream_old.py\n\nautostream_kept.py\n",
        "autostream_old.py\n   \t\n",
        "/etc/passwd\n",
        "",
    ])
    def test_an_unusable_manifest_is_treated_as_absent(self, trees, tmp_path, manifest):
        src, dest = trees
        victim = _touch(tmp_path, "etc/passwd")
        _touch(dest, ".core-manifest", manifest)
        _touch(dest, "autostream_old.py")
        _touch(dest, "keep_me.txt")
        _prune(src, dest)
        assert victim.exists()
        assert (dest / "keep_me.txt").exists()
        assert not (dest / "autostream_old.py").exists()


# ---------------------------------------------------------------------------
# With a manifest
# ---------------------------------------------------------------------------

@bash_capable
class TestWithManifest:
    def _manifest(self, dest: Path, *paths: str) -> None:
        _touch(dest, ".core-manifest", "".join(p + "\n" for p in paths))

    def test_removes_what_the_old_release_shipped_and_this_one_does_not(self, trees):
        src, dest = trees
        self._manifest(
            dest, "autostream_kept.py", "autostream_renamed.py",
            "nginx/static/page/x.js", "nginx/static/poll.js")
        _touch(dest, "autostream_kept.py")
        _touch(dest, "autostream_renamed.py")
        _touch(dest, "__pycache__/autostream_renamed.cpython-313.pyc")
        _touch(dest, "nginx/static/page/x.js")
        _touch(dest, "nginx/static/poll.js")
        _prune(src, dest)
        assert not (dest / "autostream_renamed.py").exists()
        assert not (dest / "__pycache__").exists()
        assert not (dest / "nginx/static/page").exists()
        assert (dest / "autostream_kept.py").exists()
        assert (dest / "nginx/static/poll.js").exists()

    def test_a_file_not_in_the_old_manifest_is_kept_even_if_not_shipped(self, trees):
        src, dest = trees
        self._manifest(dest, "autostream_kept.py")
        _touch(dest, "autostream_unlisted.py")
        _touch(dest, "autostream_config.json")
        _touch(dest, "settings/state.json")
        _prune(src, dest)
        assert (dest / "autostream_unlisted.py").exists()
        assert (dest / "autostream_config.json").exists()
        assert (dest / "settings/state.json").exists()

    def test_directories_left_empty_are_removed_but_never_the_install_directory(self, trees):
        src, dest = trees
        self._manifest(dest, "pkg/sub/a.py", "pkg/sub/b.py")
        _touch(dest, "pkg/sub/a.py")
        _touch(dest, "pkg/sub/b.py")
        _touch(dest, "pkg/__pycache__/keep.cpython-313.pyc")
        _prune(src, dest)
        assert not (dest / "pkg/sub").exists()
        # pkg still holds something that was not shipped, so it stays.
        assert (dest / "pkg/__pycache__/keep.cpython-313.pyc").exists()
        assert dest.is_dir()

    def test_a_package_directory_goes_when_its_last_file_does(self, trees):
        src, dest = trees
        self._manifest(dest, "pkg/sub/a.py")
        _touch(dest, "pkg/sub/a.py")
        _touch(dest, "pkg/sub/__pycache__/a.cpython-313.pyc")
        _prune(src, dest)
        assert not (dest / "pkg").exists()
        assert dest.is_dir()

    def test_a_listed_path_that_is_already_gone_is_not_an_error(self, trees):
        src, dest = trees
        self._manifest(dest, "autostream_gone.py")
        result = _prune(src, dest)
        assert "Removing" not in result.stdout

    def test_the_prune_does_not_follow_a_manifest_entry_out_of_the_directory(
            self, trees, tmp_path):
        src, dest = trees
        victim = _touch(tmp_path, "outside.txt")
        self._manifest(dest, "../outside.txt", "autostream_gone.py")
        _touch(dest, "autostream_old.py")
        _prune(src, dest)
        assert victim.exists()
        # The manifest was unusable, so the first-upgrade rule ran instead.
        assert not (dest / "autostream_old.py").exists()


# ---------------------------------------------------------------------------
# Writing the manifest
# ---------------------------------------------------------------------------

@bash_capable
class TestWrite:
    def test_the_written_manifest_is_the_shipped_list(self, trees):
        src, dest = trees
        _run(f'deploy_manifest_write "{dest.as_posix()}" "{src.as_posix()}"')
        listed = _run(f'deploy_manifest_list "{src.as_posix()}"').stdout
        assert (dest / ".core-manifest").read_text(encoding="utf-8") == listed
        assert [p.name for p in dest.iterdir()] == [".core-manifest"]

    def test_a_second_upgrade_removes_what_the_first_one_recorded(self, trees):
        src, dest = trees
        _touch(dest, "autostream_old.py")
        _touch(dest, "autostream_kept.py")
        _prune(src, dest)
        _run(f'deploy_manifest_write "{dest.as_posix()}" "{src.as_posix()}"')
        # The next release drops a module this one shipped.
        _touch(dest, "autostream_new.py")
        (src / "core" / "autostream_new.py").unlink()
        _prune(src, dest)
        assert not (dest / "autostream_new.py").exists()
        assert (dest / "autostream_kept.py").exists()

    def test_a_failed_listing_leaves_the_old_manifest(self, trees):
        src, dest = trees
        _touch(dest, ".core-manifest", "autostream_old.py\n")
        result = _bash(
            'deploy_manifest_list() { return 1; }\n'
            f'deploy_manifest_write "{dest.as_posix()}" "{src.as_posix()}"')
        assert result.returncode != 0
        assert (dest / ".core-manifest").read_text(encoding="utf-8") == "autostream_old.py\n"
        assert [p.name for p in dest.iterdir()] == [".core-manifest"]


# ---------------------------------------------------------------------------
# Where the installer calls it
# ---------------------------------------------------------------------------

class TestInstallerOrder:
    def _configure_phase(self) -> str:
        text = INSTALL_SH.read_text(encoding="utf-8")
        start = text.index("\nconfigure_phase() {")
        return text[start:]

    def test_the_library_is_sourced(self):
        text = INSTALL_SH.read_text(encoding="utf-8")
        assert 'source "${INSTALLER_LIB}/deploy_manifest.sh"' in text

    def test_prune_follows_the_nginx_copy_and_the_manifest_is_written_last(self):
        body = self._configure_phase()
        nginx_copy = body.index('cp -a "${AUTOSTREAM_DIR}/nginx"  "${INSTALL_DIR}/"')
        prune = body.index('deploy_manifest_prune "${INSTALL_DIR}" "${AUTOSTREAM_DIR}"')
        write = body.index('deploy_manifest_write "${INSTALL_DIR}" "${AUTOSTREAM_DIR}"')
        assert nginx_copy < prune < write

    def test_the_core_copy_comes_before_the_prune(self):
        text = INSTALL_SH.read_text(encoding="utf-8")
        copy = text.index('cp -a "${AUTOSTREAM_DIR}/core/."')
        assert copy < text.index("deploy_manifest_prune ")


# ---------------------------------------------------------------------------
# Names an earlier release shipped
# ---------------------------------------------------------------------------

# Entries of core/ in the previous release, with their kind. A name reused for
# the other kind would make the copy over an existing install fail (a file
# where a directory is wanted, or the reverse), so no current entry may do so.
SHIPPED_ENTRIES: dict[str, str] = {
    **{name: "file" for name in (
        "autostream_align.py", "autostream_align_tone.py", "autostream_appliance_gateway.py",
        "autostream_appliance_identity.py", "autostream_appliance_models.py",
        "autostream_appliances.py", "autostream_artwork.py", "autostream_auth.py",
        "autostream_bluetooth_client.py", "autostream_bluetooth_facts.py",
        "autostream_bluetooth_presentation.py", "autostream_commissioning.py",
        "autostream_config.py", "autostream_core.py", "autostream_debounce.py",
        "autostream_dial_gpio.py", "autostream_dial_push.py", "autostream_dial_warnings.py",
        "autostream_dials.py", "autostream_federation.py", "autostream_licensing.py",
        "autostream_log_policy.py", "autostream_mdns.py", "autostream_mute_state.py",
        "autostream_nowplaying.py", "autostream_output_usage.py", "autostream_owntone.py",
        "autostream_owntone_mini.py", "autostream_pin_pairing.py",
        "autostream_playback_stats.py", "autostream_player_service.py",
        "autostream_players.py", "autostream_rpi.py", "autostream_runtime_state.py",
        "autostream_settings.py", "autostream_settings_schema.py",
        "autostream_start_buffer_cache.py", "autostream_system_stats.py",
        "autostream_sysutils.py", "autostream_webui.py", "autostream_webui_api.py",
        "autostream_webui_assets.py", "autostream_webui_common.py",
        "autostream_webui_components.py", "autostream_webui_dials.py",
        "autostream_webui_page_about.py", "autostream_webui_page_airplay.py",
        "autostream_webui_page_align.py", "autostream_webui_page_equaliser.py",
        "autostream_webui_page_first_boot.py", "autostream_webui_page_logs.py",
        "autostream_webui_page_owntone.py", "autostream_webui_page_rebooting.py",
        "autostream_webui_page_service.py", "autostream_webui_page_setup.py",
        "autostream_webui_post_handlers.py", "autostream_webui_routes.py",
        "autostream_webui_service_schema.py", "autostream_webui_state.py",
        "autostream_wifi_network.py", "requirements.txt",
    )},
    "track_id": "dir",
    "monitor": "dir",
}


class TestShippedNames:
    def test_the_recorded_list_has_sixty_modules(self):
        assert sum(1 for n in SHIPPED_ENTRIES if n.endswith(".py")) == 60

    @pytest.mark.parametrize("name,kind", sorted(SHIPPED_ENTRIES.items()))
    def test_no_current_entry_reuses_a_shipped_name_as_the_other_kind(self, name, kind):
        path = CORE / name
        if not path.exists():
            return
        assert path.is_dir() == (kind == "dir"), (
            f"core/{name} was a {kind} in the previous release and is now the other kind")

    def test_no_directory_is_named_like_a_shipped_module_without_its_suffix(self):
        # A package named like a shipped module would be imported in its place.
        modules = {n[:-3] for n in SHIPPED_ENTRIES if n.endswith(".py")}
        for entry in CORE.iterdir():
            if entry.is_dir() and entry.name in modules:
                pytest.fail(f"core/{entry.name}/ shadows the module of the same name")


@shellcheck_available
def test_the_library_passes_shellcheck():
    result = subprocess.run(
        ["shellcheck", str(LIB)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout
