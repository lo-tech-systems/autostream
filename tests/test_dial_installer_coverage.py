"""Dial installer coverage guards: what the dial references is what the
installer installs and owns.

Image table shared by the install and the owned-file list, the transitive
import closure of the dial code against the modules the installer copies, the
dial's mDNS template and its update-path rendering, and the sudo verbs the dial
runs against its sudoers file.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from conftest import bash_can_run_script_at_windows_path  # noqa: E402
from test_dial_installer_hd import _dry_run, _names  # noqa: E402
from test_dial_staged_install import Env  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPERS = REPO_ROOT / "installer" / "dial" / "helpers.sh"
SUDOERS = REPO_ROOT / "system" / "sudoers" / "autostream_dial"
AVAHI_TEMPLATE = REPO_ROOT / "system" / "avahi" / "autostream-dial.service"
ADMIN_HELPER = REPO_ROOT / "supervisor" / "autostream_admin"
DIAL_DIR = REPO_ROOT / "dial"
CORE_DIR = REPO_ROOT / "core"
PLATFORM_DIR = REPO_ROOT / "platform"

bash_capable = pytest.mark.skipif(
    not bash_can_run_script_at_windows_path(),
    reason="bash cannot execute scripts at this path (MSYS2 limitation on Windows)",
)

IMAGE_REF = re.compile(r"/opt/autostream/images/([A-Za-z0-9_.\-]+\.(?:png|ico|jpg|svg))")


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def _dial_sources() -> list[Path]:
    return sorted(p for p in DIAL_DIR.rglob("*.py") if "__pycache__" not in p.parts)


# ---------------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------------

def _referenced_images() -> set[str]:
    names: set[str] = set()
    for path in _dial_sources() + sorted((DIAL_DIR / "hd").glob("*")):
        if path.is_file():
            names.update(IMAGE_REF.findall(path.read_text(encoding="utf-8", errors="replace")))
    return names


@bash_capable
class TestDialImages:
    def test_the_dial_references_images(self):
        # Guards the scan below against silently matching nothing.
        assert {"autostream-logo-centred-dark.png",
                "autostream-logo-replay-dark.png"} <= _referenced_images()

    def test_every_referenced_image_is_in_the_table(self, env):
        r = env.run("dial_image_names")
        assert r.returncode == 0, r.stderr
        assert _referenced_images() <= set(r.stdout.split())

    def test_every_table_image_exists_in_the_repository(self, env):
        r = env.run("dial_image_names")
        for name in r.stdout.split():
            assert (REPO_ROOT / "images" / name).is_file(), name

    def test_install_puts_every_table_image_in_place(self, env):
        names = env.run("dial_image_names").stdout.split()
        r = env.run("install_dial_images")
        assert r.returncode == 0, r.stderr
        for name in names:
            assert (env.opt / "images" / name).is_file(), name

    def test_owned_list_names_exactly_the_installed_images(self, env):
        names = env.run("dial_image_names").stdout.split()
        owned = env.run("owned_files_list").stdout.split()
        images = sorted(p for p in owned if p.startswith("/opt/autostream/images/"))
        assert images == sorted(f"/opt/autostream/images/{n}" for n in names)

    @pytest.mark.parametrize("update", [False, True])
    def test_both_paths_run_the_image_install(self, tmp_path, update):
        r, calls = _dry_run(tmp_path, update=update)
        assert r.returncode == 0, r.stderr
        assert _names(calls).count("install_dial_images") == 1


# ---------------------------------------------------------------------------
# Transitive import closure
# ---------------------------------------------------------------------------

def _installer_module_names() -> set[str]:
    """Core and platform module names install_code_tree copies by name."""
    text = HELPERS.read_text(encoding="utf-8")
    body = text[text.index("install_code_tree() {"):]
    body = body[:body.index("\n}\n")].replace("\\\n", " ")
    names: set[str] = set()
    for loop in re.findall(r"for name in ([^;]+); do", body):
        names.update(loop.split())
    return names


def _imports(path: Path) -> set[str]:
    mods: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            mods.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            mods.add(node.module.split(".")[0])
    return mods


def _import_closure(starts: list[Path]) -> dict[str, Path]:
    """Every first-party module reachable from STARTS, name -> source file."""
    found: dict[str, Path] = {}
    todo = list(starts)
    while todo:
        for mod in _imports(todo.pop()):
            if mod in found:
                continue
            for base in (DIAL_DIR, CORE_DIR, PLATFORM_DIR):
                src = base / f"{mod}.py"
                if src.is_file():
                    found[mod] = src
                    todo.append(src)
                    break
    return found


class TestImportClosure:
    def test_installer_names_are_parsed(self):
        names = _installer_module_names()
        assert {"autostream_rpi", "autostream_artwork", "wifi_loop"} <= names

    def test_everything_the_dial_imports_is_installed(self):
        installed = _installer_module_names()
        starts = _dial_sources() + [PLATFORM_DIR / "wifi_watcher.py"]
        starts += [PLATFORM_DIR / f"{n}.py" for n in installed
                   if (PLATFORM_DIR / f"{n}.py").is_file()]
        closure = _import_closure(starts)
        assert {"autostream_sysutils", "autostream_mdns"} <= set(closure)
        missing = sorted(
            f"{mod} ({src.relative_to(REPO_ROOT).as_posix()})"
            for mod, src in closure.items()
            if src.parent != DIAL_DIR and mod not in installed
        )
        assert not missing, f"imported by the dial but not installed: {missing}"

    def test_every_installed_name_exists(self):
        for name in _installer_module_names():
            assert ((CORE_DIR / f"{name}.py").is_file()
                    or (PLATFORM_DIR / f"{name}.py").is_file()), name


# ---------------------------------------------------------------------------
# mDNS template
# ---------------------------------------------------------------------------

@bash_capable
class TestAvahiTemplate:
    def test_template_advertises_protocol_v3(self):
        text = AVAHI_TEMPLATE.read_text(encoding="utf-8")
        assert "<txt-record>dial_proto=v3</txt-record>" in text

    def test_template_has_the_placeholders_the_admin_verb_fills(self):
        text = AVAHI_TEMPLATE.read_text(encoding="utf-8")
        for token in ("__DIAL_UUID__", "__DIAL_NAME__", "__AUTOSTREAM_RELEASE_TAG__"):
            assert token in text

    @pytest.mark.parametrize("update", [False, True])
    def test_both_paths_install_then_render_the_template(self, tmp_path, update):
        r, calls = _dry_run(tmp_path, update=update)
        assert r.returncode == 0, r.stderr
        names = _names(calls)
        render = [i for i, c in enumerate(calls) if c.startswith("admin update-dial-service")]
        assert len(render) == 1
        assert names.count("deploy_avahi_template") == 1
        assert names.index("deploy_avahi_template") < render[0]

    def test_template_and_rendered_service_are_owned(self, env):
        owned = env.run("owned_files_list").stdout.split()
        assert "/usr/local/share/autostream/avahi/autostream-dial.service" in owned
        assert "/etc/avahi/services/autostream-dial.service" in owned


# ---------------------------------------------------------------------------
# Sudo verbs
# ---------------------------------------------------------------------------

VERB = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)+$")
ADMIN_RUNNERS = {"run_admin_cmd", "_sdcard_health_admin_call"}
ADMIN_CALL =re.compile(r"ADMIN_CMD,\s*[\"']([a-z][a-z0-9\-]*)[\"']")


def _sudoers_verbs(user: str = "autostream") -> set[str]:
    verbs: set[str] = set()
    for line in SUDOERS.read_text(encoding="utf-8").splitlines():
        m = re.match(rf"^{user}\s+ALL=\(root\)\s+NOPASSWD:\s+\S*/autostream_admin\s+(\S+)", line)
        if m:
            verbs.add(m.group(1))
    return verbs


def _imported_names(path: Path, module: str) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and node.module == module:
            names.update(a.name for a in node.names)
    return names


def _verbs_in_function(tree: ast.Module, name: str, seen: set[str] | None = None) -> set[str]:
    """Admin verbs a sysutils function names, following same-module calls."""
    seen = seen if seen is not None else set()
    if name in seen:
        return set()
    seen.add(name)
    funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    fn = funcs.get(name)
    if fn is None:
        return set()
    verbs: set[str] = set()
    for node in ast.walk(fn):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        first = node.args[0] if node.args else None
        if (node.func.id in ADMIN_RUNNERS and isinstance(first, ast.List) and first.elts
                and isinstance(first.elts[0], ast.Constant)
                and isinstance(first.elts[0].value, str) and VERB.match(first.elts[0].value)):
            verbs.add(first.elts[0].value)
        else:
            verbs |= _verbs_in_function(tree, node.func.id, seen)
    return verbs


def _dial_verbs() -> dict[str, str]:
    """Admin verb -> where the dial service runs it."""
    found: dict[str, str] = {}
    sysutils = ast.parse((CORE_DIR / "autostream_sysutils.py").read_text(encoding="utf-8"))
    for path in _dial_sources():
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(REPO_ROOT).as_posix()
        for verb in ADMIN_CALL.findall(text):
            found.setdefault(verb, rel)
        for fname in _imported_names(path, "autostream_sysutils"):
            for verb in _verbs_in_function(sysutils, fname):
                found.setdefault(verb, f"{rel} via {fname}")
    return found


class TestSudoVerbs:
    def test_the_scan_finds_the_known_verbs(self):
        verbs = set(_dial_verbs())
        assert {"update-dial-service", "restart-dial-service", "run-updater",
                "toggle-dial-update-timer", "sdcard-health-check"} <= verbs

    def test_every_verb_the_dial_runs_is_allowed(self):
        allowed = _sudoers_verbs()
        missing = {v: where for v, where in _dial_verbs().items() if v not in allowed}
        assert not missing, f"run by the dial but not in its sudoers: {missing}"

    def test_toggle_verb_arguments_are_both_allowed(self):
        text = SUDOERS.read_text(encoding="utf-8")
        for arg in ("enable", "disable"):
            assert re.search(rf"autostream_admin toggle-dial-update-timer {arg}$", text, re.M)

    def test_every_allowed_verb_exists_in_the_admin_helper(self):
        admin = ADMIN_HELPER.read_text(encoding="utf-8")
        for verb in _sudoers_verbs():
            assert verb in admin, verb


# ---------------------------------------------------------------------------
# Uninstaller
# ---------------------------------------------------------------------------

UNINSTALLER = REPO_ROOT / "autostream_dial_uninstall.sh"
INSTALLER = REPO_ROOT / "autostream_dial_install.sh"


def _removed_by_uninstaller() -> tuple[set[str], list[str]]:
    files: set[str] = set()
    trees: list[str] = []
    for line in UNINSTALLER.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^(?:best_effort\s+)?rm\s+(-\w+)\s+(/\S+)", line.strip())
        if not m:
            continue
        if "r" in m.group(1):
            trees.append(m.group(2).rstrip("/"))
        else:
            files.add(m.group(2))
    return files, trees


class TestUninstallerCoverage:
    # Left in place on purpose: logs are evidence, not product files.
    KEPT_PREFIXES = ("/var/log/",)

    def test_every_file_the_installer_places_is_removed(self):
        from test_dial_staged_install import _install_destinations
        files, trees = _removed_by_uninstaller()
        text = INSTALLER.read_text(encoding="utf-8") + "\n" + HELPERS.read_text(encoding="utf-8")
        checked = 0
        for src, dest in _install_destinations(text):
            if not dest.startswith("/") or dest.startswith(self.KEPT_PREFIXES):
                continue
            if dest == "/dev/null":
                continue
            if dest.endswith("/"):
                dest = dest + Path(src).name
            checked += 1
            assert dest in files or any(dest.startswith(t + "/") for t in trees), dest
        assert checked >= 15
