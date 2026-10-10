"""Dial installer, --update path: staged code tree, versioned venv, owned-file
backup and restore, the hand-off file for the boot step, the phase-aware
failure cleanup, and the delayed reboot that ends every successful update.

Functional bash round-trips against a scratch root (AUTOSTREAM_FS_ROOT) with
fake commands on PATH, plus a dry run of the whole installer with every helper
replaced by a recorder.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from conftest import bash_can_run_script_at_windows_path  # noqa: E402

bash_capable = pytest.mark.skipif(
    not bash_can_run_script_at_windows_path(),
    reason="bash cannot execute scripts at this path (MSYS2 limitation on Windows)",
)
posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="file modes and symlinks are meaningful on POSIX only"
)

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPERS = REPO_ROOT / "installer" / "dial" / "helpers.sh"
INSTALLER = REPO_ROOT / "autostream_dial_install.sh"
LOCK = REPO_ROOT / "dial" / "requirements.lock"

FAKE_PYTHON3 = r"""#!/bin/bash
echo "python3 $*" >> "$TRACE"
if [[ "$1" == "-m" && "$2" == "venv" ]]; then
    dir="${@: -1}"
    mkdir -p "$dir/bin"
    cat > "$dir/bin/python" <<EOF
#!/bin/bash
echo "venv-python $dir \$*" >> "\$TRACE"
EOF
    chmod +x "$dir/bin/python"
fi
"""

RECORDER = '#!/bin/bash\necho "$(basename "$0") $*" >> "$TRACE"\n'


def _lock_sha() -> str:
    return hashlib.sha256(LOCK.read_bytes()).hexdigest()


class Env:
    """A scratch root, fake commands and a trace file for one test."""

    def __init__(self, tmp_path: Path):
        self.tmp = tmp_path
        self.root = tmp_path / "root"
        self.opt = self.root / "opt" / "autostream"
        self.state = self.root / "var" / "lib" / "autostream"
        self.opt.mkdir(parents=True)
        self.state.mkdir(parents=True)
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.trace = tmp_path / "trace.log"
        self.trace.touch()
        self.result = self.state / "update-result.env"
        self.install_state = self.state / "install-state.env"
        self.swap = self.state / "update-swap.env"
        self.admin = tmp_path / "admin"
        self.fake("python3", FAKE_PYTHON3)
        for name in ("systemctl", "nginx", "sleep"):
            self.fake(name, RECORDER)
        self.fake_script(self.admin, RECORDER)

    def fake(self, name: str, text: str) -> None:
        self.fake_script(self.bin / name, text)

    @staticmethod
    def fake_script(path: Path, text: str) -> None:
        path.write_text(text, encoding="utf-8")
        path.chmod(0o755)

    def put(self, rel: str, text: str = "x", mode: int | None = None) -> Path:
        path = self.root / rel.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        if mode is not None:
            path.chmod(mode)
        return path

    def venv(self, name: str) -> Path:
        d = self.opt / name
        (d / "bin").mkdir(parents=True)
        py = d / "bin" / "python"
        py.write_text("#!/bin/bash\n", encoding="utf-8")
        py.chmod(0o755)
        return d

    def env(self, **extra: str) -> dict:
        e = dict(os.environ)
        e.update(
            AUTOSTREAM_FS_ROOT=self.root.as_posix(),
            UPDATE_RESULT_FILE=self.result.as_posix(),
            INSTALL_STATE_FILE=self.install_state.as_posix(),
            AUTOSTREAM_ADMIN_BIN=self.admin.as_posix(),
            APT_RETRY_DELAY="0",
            TRACE=self.trace.as_posix(),
            PATH=self.bin.as_posix() + os.pathsep + os.environ.get("PATH", ""),
        )
        e.update(extra)
        return e

    def run(self, body: str, *, update: str = "true", tag: str = "1.3.0",
            deploy: Path = REPO_ROOT, **extra: str):
        script = (
            f'set -euo pipefail; DEPLOY="{deploy.as_posix()}"; '
            f'source "{HELPERS.as_posix()}"; '
            f'UPDATE={update}; AUTOSTREAM_RELEASE_TAG={tag}\n{body}'
        )
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                              timeout=60, env=self.env(**extra))

    def calls(self) -> list[str]:
        return self.trace.read_text(encoding="utf-8").splitlines()


def _kv(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        k, _, v = line.partition("=")
        out[k] = v
    return out


VARS = ('printf "NEW_VENV=%s\\nPREVIOUS_VENV=%s\\nVENV_MIGRATE=%s\\nVENV_BUILT=%s\\n" '
        '"$NEW_VENV" "$PREVIOUS_VENV" "$VENV_MIGRATE" "$VENV_BUILT"')


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


# ---------------------------------------------------------------------------
# Staged code tree
# ---------------------------------------------------------------------------

@bash_capable
class TestStageCodeTree:
    def test_manifest_lists_every_staged_file_with_mode_and_owner(self, env):
        r = env.run("stage_code_tree")
        assert r.returncode == 0, r.stderr
        nxt = env.opt / ".next"
        lines = (nxt / "MANIFEST").read_text(encoding="utf-8").splitlines()
        rows = [ln.split("\t") for ln in lines]
        assert all(len(row) == 3 for row in rows)
        assert all(re.fullmatch(r"0[0-7]{3}", row[0]) for row in rows)
        assert all(re.fullmatch(r"[^:\s]+:[^:\s]+", row[1]) for row in rows)
        paths = [row[2] for row in rows]
        assert paths == sorted(paths)
        on_disk = sorted(
            p.relative_to(nxt).as_posix() for p in nxt.rglob("*")
            if p.is_file() and p.name != "MANIFEST"
        )
        assert paths == on_disk
        for expected in ("dial_main.py", "autostream_rpi.py", "wifi_loop.py",
                         "autostream_dial_control.py", "autostream_wifi_watcher",
                         "cgi/download-logs.cgi", "requirements.lock"):
            assert expected in paths, expected
        assert "MANIFEST" not in paths

    @posix_only
    def test_manifest_modes_match_the_files(self, env):
        env.run("stage_code_tree")
        nxt = env.opt / ".next"
        for line in (nxt / "MANIFEST").read_text(encoding="utf-8").splitlines():
            mode, _owner, path = line.split("\t")
            assert stat.S_IMODE((nxt / path).stat().st_mode) == int(mode, 8), path
        modes = {ln.split("\t")[2]: ln.split("\t")[0]
                 for ln in (nxt / "MANIFEST").read_text(encoding="utf-8").splitlines()}
        assert modes["autostream_wifi_watcher"] == "0755"
        assert modes["autostream_rpi.py"] == "0644"

    def test_nothing_live_is_touched_and_old_staging_is_discarded(self, env):
        live = env.put("opt/autostream/dial_main.py", "live version")
        env.put("opt/autostream/venv/marker", "live venv")
        (env.opt / ".next").mkdir()
        (env.opt / ".next" / "stale").write_text("old", encoding="utf-8")
        (env.opt / ".prev").mkdir()
        (env.opt / ".prev" / "old").write_text("old", encoding="utf-8")
        r = env.run("stage_code_tree")
        assert r.returncode == 0, r.stderr
        assert live.read_text(encoding="utf-8") == "live version"
        assert (env.opt / "venv" / "marker").exists()
        assert not (env.opt / ".next" / "stale").exists()
        assert not (env.opt / ".prev").exists()
        assert sorted(p.name for p in env.opt.iterdir() if p.is_file()) == ["dial_main.py"]

    def test_wifi_watcher_is_staged_with_unix_line_endings(self, env):
        env.run("stage_code_tree")
        data = (env.opt / ".next" / "autostream_wifi_watcher").read_bytes()
        assert b"\r" not in data


# ---------------------------------------------------------------------------
# Versioned venv
# ---------------------------------------------------------------------------

@bash_capable
class TestBuildVenv:
    def test_build_venv_uses_python_m_pip_not_the_console_script(self, env):
        target = env.opt / "venv.1.3.0"
        r = env.run(f'build_venv "{target.as_posix()}"')
        assert r.returncode == 0, r.stderr
        calls = env.calls()
        assert any(c.startswith("python3 -m venv --system-site-packages ") for c in calls)
        pip_calls = [c for c in calls if c.startswith("venv-python ")]
        assert len(pip_calls) == 2
        assert all(" -m pip install " in c for c in pip_calls)
        assert "-U pip" in pip_calls[0]
        assert "--require-hashes -r " in pip_calls[1]
        assert pip_calls[1].endswith("dial/requirements.lock")
        assert not (target / "bin" / "pip").exists()

    def test_falls_back_to_requirements_txt_without_a_lock(self, env, tmp_path):
        deploy = tmp_path / "deploy"
        (deploy / "dial").mkdir(parents=True)
        (deploy / "dial" / "requirements.txt").write_text("gpiozero==2.0\n", encoding="utf-8")
        r = env.run(f'build_venv "{(env.opt / "v").as_posix()}"', deploy=deploy)
        assert r.returncode == 0, r.stderr
        assert "not hash-pinned" in r.stderr
        assert any(c.endswith("-r " + (deploy / "dial" / "requirements.txt").as_posix())
                   for c in env.calls() if c.startswith("venv-python"))

    @posix_only
    def test_matching_lock_hash_reuses_the_active_venv(self, env):
        env.venv("venv.1.2.0")
        (env.opt / "venv").symlink_to("venv.1.2.0")
        env.install_state.write_text(
            f"AUTOSTREAM_RELEASE_TAG=1.2.0\nREQUIREMENTS_LOCK_SHA256={_lock_sha()}\n",
            encoding="utf-8")
        r = env.run(f"prepare_update_venv\n{VARS}")
        assert r.returncode == 0, r.stderr
        out = _kv(r.stdout.split("\n", 1)[1])
        assert out["NEW_VENV"] == "venv.1.2.0"
        assert out["PREVIOUS_VENV"] == "venv.1.2.0"
        assert (out["VENV_MIGRATE"], out["VENV_BUILT"]) == ("0", "false")
        assert not [c for c in env.calls() if c.startswith("python3")]
        assert not (env.opt / "venv.1.3.0").exists()

    @posix_only
    def test_changed_lock_hash_builds_a_versioned_venv_at_its_final_path(self, env):
        env.venv("venv.1.2.0")
        env.venv("venv.1.1.0")
        (env.opt / "venv").symlink_to("venv.1.2.0")
        env.install_state.write_text(
            "AUTOSTREAM_RELEASE_TAG=1.2.0\nREQUIREMENTS_LOCK_SHA256=0000\n", encoding="utf-8")
        r = env.run(f"prepare_update_venv\n{VARS}")
        assert r.returncode == 0, r.stderr
        out = _kv(r.stdout)
        assert out["NEW_VENV"] == "venv.1.3.0"
        assert out["PREVIOUS_VENV"] == "venv.1.2.0"
        assert (out["VENV_MIGRATE"], out["VENV_BUILT"]) == ("0", "true")
        built = env.opt / "venv.1.3.0"
        assert (built / "bin" / "python").exists()
        assert any(c.startswith("python3 -m venv") and c.endswith(built.as_posix())
                   for c in env.calls())
        # The active venv stays; the one older than it is no longer needed.
        assert (env.opt / "venv.1.2.0").exists()
        assert not (env.opt / "venv.1.1.0").exists()
        assert os.readlink(env.opt / "venv") == "venv.1.2.0"

    def test_missing_hash_in_an_old_state_file_forces_a_build(self, env):
        env.venv("venv.1.2.0")
        (env.opt / "venv").symlink_to("venv.1.2.0")
        env.install_state.write_text("AUTOSTREAM_RELEASE_TAG=1.2.0\n", encoding="utf-8")
        r = env.run(f"prepare_update_venv\n{VARS}")
        assert r.returncode == 0, r.stderr
        assert _kv(r.stdout)["VENV_BUILT"] == "true"

    def test_a_real_venv_directory_is_migrated_not_modified(self, env):
        real = env.venv("venv")
        env.install_state.write_text("AUTOSTREAM_RELEASE_TAG=0.6.0\n", encoding="utf-8")
        r = env.run(f"prepare_update_venv\n{VARS}", PREVIOUS_RELEASE_TAG="0.6.0")
        assert r.returncode == 0, r.stderr
        out = _kv(r.stdout)
        assert out["VENV_MIGRATE"] == "1"
        assert out["PREVIOUS_VENV"] == "venv.0.6.0"
        assert out["NEW_VENV"] == "venv.1.3.0"
        assert real.is_dir() and not real.is_symlink()
        assert (env.opt / "venv.1.3.0" / "bin" / "python").exists()

    def test_a_real_venv_with_unknown_previous_tag_migrates_to_venv_previous(self, env):
        env.venv("venv")
        r = env.run(f"prepare_update_venv\n{VARS}")
        assert r.returncode == 0, r.stderr
        out = _kv(r.stdout)
        assert out["PREVIOUS_VENV"] == "venv.previous"
        assert out["VENV_MIGRATE"] == "1"

    def test_a_real_venv_with_matching_hash_is_kept_in_place(self, env):
        env.venv("venv")
        env.install_state.write_text(f"REQUIREMENTS_LOCK_SHA256={_lock_sha()}\n",
                                     encoding="utf-8")
        r = env.run(f"prepare_update_venv\n{VARS}")
        assert r.returncode == 0, r.stderr
        out = _kv(r.stdout)
        assert (out["NEW_VENV"], out["PREVIOUS_VENV"]) == ("venv", "venv")
        assert (out["VENV_MIGRATE"], out["VENV_BUILT"]) == ("0", "false")

    @posix_only
    def test_a_rebuild_never_lands_on_the_active_directory(self, env):
        env.venv("venv.1.3.0")
        (env.opt / "venv").symlink_to("venv.1.3.0")
        r = env.run(f"prepare_update_venv\n{VARS}")
        assert r.returncode == 0, r.stderr
        out = _kv(r.stdout)
        assert out["NEW_VENV"] == "venv.1.3.0.1"
        assert out["PREVIOUS_VENV"] == "venv.1.3.0"
        assert (env.opt / "venv.1.3.0" / "bin" / "python").exists()

    def test_an_unsafe_tag_is_reduced_to_a_plain_directory_name(self, env):
        r = env.run(f"prepare_update_venv\n{VARS}", tag="'v1/../x y'")
        assert r.returncode == 0, r.stderr
        name = _kv(r.stdout)["NEW_VENV"]
        assert re.fullmatch(r"venv\.[A-Za-z0-9._-]+", name)
        assert "/" not in name
        assert (env.opt / name).is_dir()

    def test_install_state_records_the_lock_digest_and_keeps_sdmon_lines(self, env):
        env.install_state.write_text(
            "DIAL_UUID=x\nSDMON_METHOD=fast\nREQUIREMENTS_LOCK_SHA256=old\n", encoding="utf-8")
        env.fake("chown", "#!/bin/bash\n")
        r = env.run('VENV_LOCK_SHA256=abc123\nwrite_install_state uuid1')
        assert r.returncode == 0, r.stderr
        state = _kv(env.install_state.read_text(encoding="utf-8"))
        assert state["REQUIREMENTS_LOCK_SHA256"] == "abc123"
        assert state["SDMON_METHOD"] == "fast"
        assert state["DIAL_UUID"] == "uuid1"
        assert state["AUTOSTREAM_RELEASE_TAG"] == "1.3.0"


# ---------------------------------------------------------------------------
# Owned files outside the code tree
# ---------------------------------------------------------------------------

def _owned(env: Env) -> list[str]:
    r = env.run("owned_files_list")
    assert r.returncode == 0, r.stderr
    return r.stdout.split()


def _logical_lines(text: str) -> list[str]:
    return [ln.strip() for ln in text.replace("\\\n", " ").splitlines()]


def _install_destinations(text: str) -> list[tuple[str, str]]:
    """(source, destination) of every `install`/`ln -sf` in a script."""
    pairs = []
    for line in _logical_lines(text):
        if not re.match(r"^(install|ln -sf)\s", line):
            continue
        line = line.split("#")[0]
        toks = [t.strip('"') for t in line.split()]
        if len(toks) >= 3:
            pairs.append((toks[-2], toks[-1]))
    return pairs


@bash_capable
class TestOwnedFiles:
    # Written outside the code tree by design and not rolled back.
    NOT_OWNED = {
        "/usr/local/sbin/sdmon",
        "/dev/null",
    }

    def test_backup_list_covers_every_installer_owned_path(self, env):
        owned = set(_owned(env))
        sources = INSTALLER.read_text(encoding="utf-8") + "\n" + HELPERS.read_text(encoding="utf-8")
        seen = 0
        for src, dest in _install_destinations(sources):
            if src == "/dev/null" or dest.startswith("/var/log/") or dest in self.NOT_OWNED:
                continue
            if dest.startswith("$") or dest.startswith("${"):
                continue          # the code tree and the venv are staged, not backed up
            if dest == "/usr/local/sbin/sdmon":
                continue
            seen += 1
            if dest.endswith("/"):
                if "*" in src:
                    assert any(o.startswith(dest) for o in owned), dest
                else:
                    assert dest + Path(src).name in owned, (src, dest)
            else:
                assert dest in owned, dest
        assert seen >= 20
        # Written by other means than install(1).
        assert "/var/lib/autostream/install-state.env" in owned
        assert "/etc/avahi/services/autostream-dial.service" in owned
        assert "/etc/nginx/sites-enabled/autostream-dial" in owned

    def test_every_listed_path_is_absolute_and_unique(self, env):
        owned = _owned(env)
        assert len(owned) == len(set(owned))
        assert all(p.startswith("/") for p in owned)
        assert not any(p.startswith("/boot") for p in owned)

    @posix_only
    def test_backup_manifest_records_present_and_absent_paths(self, env):
        env.put("etc/sudoers.d/autostream_dial", "sudoers v1")
        env.put("opt/autostream/images/favicon.ico", "icon v1")
        r = env.run("backup_owned_files")
        assert r.returncode == 0, r.stderr
        prev = env.state / "update-prev"
        assert stat.S_IMODE(prev.stat().st_mode) == 0o700
        assert not (prev / "MANIFEST.tmp").exists()
        rows = [ln.split("\t") for ln in (prev / "MANIFEST").read_text().splitlines()]
        states = {path: state for state, path in rows}
        assert states["/etc/sudoers.d/autostream_dial"] == "PRESENT"
        assert states["/opt/autostream/images/favicon.ico"] == "PRESENT"
        assert states["/etc/logrotate.d/autostream-dial"] == "ABSENT"
        assert set(states) == set(_owned(env))
        saved = prev / "files" / "etc" / "sudoers.d" / "autostream_dial"
        assert saved.read_text(encoding="utf-8") == "sudoers v1"

    @posix_only
    def test_restore_round_trip_in_a_fake_root(self, env):
        unit = env.put("etc/systemd/system/autostream_dial.service", "unit v1", 0o644)
        sudo = env.put("etc/sudoers.d/autostream_dial", "sudoers v1", 0o440)
        state = env.put("var/lib/autostream/install-state.env", "AUTOSTREAM_RELEASE_TAG=1.2.0\n")
        link = env.root / "etc" / "nginx" / "sites-enabled" / "autostream-dial"
        env.put("etc/nginx/sites-available/autostream-dial", "server v1")
        link.parent.mkdir(parents=True)
        link.symlink_to("/etc/nginx/sites-available/autostream-dial")
        assert env.run("backup_owned_files").returncode == 0
        # The update changes, deletes and adds files.
        unit.write_text("unit v2", encoding="utf-8")
        sudo.unlink()
        state.write_text("AUTOSTREAM_RELEASE_TAG=1.3.0\n", encoding="utf-8")
        link.unlink()
        link.symlink_to("/elsewhere")
        added = env.put("etc/logrotate.d/autostream-dial", "added by the update")
        env.trace.write_text("", encoding="utf-8")
        r = env.run("restore_owned_files")
        assert r.returncode == 0, r.stderr
        assert unit.read_text(encoding="utf-8") == "unit v1"
        assert sudo.read_text(encoding="utf-8") == "sudoers v1"
        assert stat.S_IMODE(sudo.stat().st_mode) == 0o440
        assert state.read_text(encoding="utf-8") == "AUTOSTREAM_RELEASE_TAG=1.2.0\n"
        assert link.is_symlink() and os.readlink(link) == "/etc/nginx/sites-available/autostream-dial"
        assert not added.exists()
        assert env.calls() == ["systemctl daemon-reload", "nginx -t", "systemctl restart nginx"]

    @posix_only
    def test_restore_removes_paths_recorded_absent(self, env):
        assert env.run("backup_owned_files").returncode == 0
        added = [env.put("etc/logrotate.d/autostream-dial"),
                 env.put("usr/local/libexec/autostream/autostream_sdcardhealth"),
                 env.put("opt/autostream/nginx/cgi/download-logs.cgi")]
        assert env.run("restore_owned_files").returncode == 0
        assert not any(p.exists() for p in added)

    def test_a_failing_nginx_check_does_not_restart_nginx(self, env):
        env.put("etc/logrotate.d/autostream-dial", "v1")
        assert env.run("backup_owned_files").returncode == 0
        env.fake("nginx", '#!/bin/bash\necho "nginx $*" >> "$TRACE"\nexit 1\n')
        env.trace.write_text("", encoding="utf-8")
        r = env.run("restore_owned_files")
        assert r.returncode == 0, r.stderr
        assert env.calls() == ["systemctl daemon-reload", "nginx -t"]

    def test_restore_without_a_manifest_does_nothing(self, env):
        r = env.run("restore_owned_files")
        assert r.returncode == 0, r.stderr
        assert env.calls() == []


# ---------------------------------------------------------------------------
# Hand-off file, failure cleanup, reboot
# ---------------------------------------------------------------------------

@bash_capable
class TestSwapFile:
    @posix_only
    def test_swap_file_carries_the_contract_keys(self, env):
        r = env.run(
            'PREVIOUS_RELEASE_TAG=1.2.0; NEW_VENV=venv.1.3.0; PREVIOUS_VENV=venv.1.2.0\n'
            'VENV_MIGRATE=0; BACKUP_DIR=/var/lib/autostream/update-prev\nwrite_update_swap')
        assert r.returncode == 0, r.stderr
        assert env.swap.read_text(encoding="utf-8").splitlines() == [
            "PHASE=staged", "TAG=1.3.0", "PREVIOUS_TAG=1.2.0", "VENV=venv.1.3.0",
            "PREVIOUS_VENV=venv.1.2.0", "VENV_MIGRATE=0",
            "BACKUP_DIR=/var/lib/autostream/update-prev",
        ]
        assert stat.S_IMODE(env.swap.stat().st_mode) == 0o644
        assert list(env.state.glob("update-swap.env.tmp.*")) == []

    def test_previous_tag_prefers_the_result_file(self, env):
        env.result.write_text("STATUS=in_progress\nPREVIOUS_TAG=1.1.0\n", encoding="utf-8")
        r = env.run('PREVIOUS_RELEASE_TAG=1.2.0; NEW_VENV=v; PREVIOUS_VENV=w\nwrite_update_swap')
        assert r.returncode == 0, r.stderr
        assert _kv(env.swap.read_text(encoding="utf-8"))["PREVIOUS_TAG"] == "1.1.0"

    def test_a_migrating_swap_says_so(self, env):
        r = env.run('NEW_VENV=venv.1.3.0; PREVIOUS_VENV=venv.0.6.0; VENV_MIGRATE=1\n'
                    'write_update_swap')
        assert r.returncode == 0, r.stderr
        data = _kv(env.swap.read_text(encoding="utf-8"))
        assert data["VENV_MIGRATE"] == "1"
        assert data["PREVIOUS_VENV"] == "venv.0.6.0"


@bash_capable
class TestAbortUpdate:
    def _stage(self, env):
        (env.opt / ".next").mkdir()
        (env.opt / ".next" / "MANIFEST").write_text("", encoding="utf-8")
        built = env.venv("venv.1.3.0")
        return built

    def test_failure_before_staged_restores_backup_and_reports_the_phase(self, env):
        unit = env.put("etc/systemd/system/autostream_dial.service", "unit v1")
        env.result.write_text("STATUS=in_progress\nPREVIOUS_TAG=1.2.0\n", encoding="utf-8")
        built = self._stage(env)
        r = env.run(
            'backup_owned_files\n'
            f'echo "unit v2" > "{unit.as_posix()}"\n'
            'NEW_VENV=venv.1.3.0; VENV_BUILT=true; CURRENT_PHASE=configure\n'
            'abort_update')
        assert r.returncode == 0, r.stderr
        assert unit.read_text(encoding="utf-8") == "unit v1"
        assert not (env.opt / ".next").exists()
        assert not built.exists()
        assert not env.swap.exists()
        result = _kv(env.result.read_text(encoding="utf-8"))
        assert result["STATUS"] == "failure"
        assert result["PHASE"] == "failed"
        assert result["MESSAGE"] == "Update to 1.3.0 failed during configuration - 1.2.0 kept"

    def test_a_venv_that_was_reused_is_never_removed(self, env):
        live = env.venv("venv.1.2.0")
        r = env.run('NEW_VENV=venv.1.2.0; VENV_BUILT=false; CURRENT_PHASE=files\nabort_update')
        assert r.returncode == 0, r.stderr
        assert live.exists()

    def test_nothing_is_restored_when_no_backup_was_taken(self, env):
        unit = env.put("etc/systemd/system/autostream_dial.service", "live")
        r = env.run('CURRENT_PHASE=python\nabort_update')
        assert r.returncode == 0, r.stderr
        assert unit.read_text(encoding="utf-8") == "live"
        assert not [c for c in env.calls() if c.startswith("systemctl")]
        assert _kv(env.result.read_text(encoding="utf-8"))["PHASE"] == "failed"

    def test_failure_after_staged_leaves_the_swap_file_and_staging(self, env):
        unit = env.put("etc/systemd/system/autostream_dial.service", "unit v1")
        built = self._stage(env)
        env.result.write_text("STATUS=in_progress\nPHASE=reboot\n", encoding="utf-8")
        r = env.run(
            'backup_owned_files\n'
            f'echo "unit v2" > "{unit.as_posix()}"\n'
            'NEW_VENV=venv.1.3.0; PREVIOUS_VENV=venv.1.2.0; VENV_BUILT=true\n'
            'write_update_swap; CURRENT_PHASE=reboot\nabort_update')
        assert r.returncode == 0, r.stderr
        assert env.swap.exists()
        assert (env.opt / ".next").is_dir()
        assert built.is_dir()
        assert unit.read_text(encoding="utf-8").strip() == "unit v2"
        result = _kv(env.result.read_text(encoding="utf-8"))
        assert result["STATUS"] == "in_progress"


@bash_capable
class TestReboot:
    def test_reboot_is_requested_through_the_admin_wrapper_with_the_update_reason(self, env):
        r = env.run("schedule_update_reboot")
        assert r.returncode == 0, r.stderr
        assert env.calls() == ["admin reboot --delay 3 AutostreamUpdate"]

    def test_a_refused_reboot_is_reported_but_not_fatal(self, env):
        env.fake_script(env.admin, "#!/bin/bash\nexit 1\n")
        r = env.run("schedule_update_reboot")
        assert r.returncode == 0
        assert "reboot" in r.stderr


# ---------------------------------------------------------------------------
# The installer end to end, helpers replaced by recorders
# ---------------------------------------------------------------------------

def _dry_run(tmp_path: Path, *, update: bool, fail: str | None = None):
    env = Env(tmp_path)
    deploy = tmp_path / "deploy"
    (deploy / "installer" / "dial").mkdir(parents=True)
    (deploy / "autostream_dial_install.sh").write_bytes(INSTALLER.read_bytes())
    names = re.findall(r"^([a-z][a-z0-9_]*)\(\) \{", HELPERS.read_text(encoding="utf-8"), re.M)
    stubs = [f'source "{HELPERS.as_posix()}"']
    for name in names:
        stubs.append(f'{name}() {{ printf "%s %s\\n" {name} "$*" >> "$TRACE"; }}')
    stubs += [
        'phase() { printf "phase %s %s\\n" "$1" "$2" >> "$TRACE"; }',
        "detect_install_version() { echo 1.3.0; }",
        "generate_dial_id() { echo 0123456789abcdef0123; }",
        "has_tty() { return 1; }",
    ]
    if fail:
        stubs.append(f'{fail}() {{ printf "%s FAILED\\n" {fail} >> "$TRACE"; return 1; }}')
    (deploy / "installer" / "dial" / "helpers.sh").write_text("\n".join(stubs) + "\n",
                                                               encoding="utf-8")
    for name in ("install", "cp", "mkdir", "rm", "ln", "sed", "chown", "chmod", "reboot",
                 "flock"):
        env.fake(name, RECORDER)
    env.install_state.write_text("DIAL_UUID=abc\n", encoding="utf-8")
    args = ["bash", str(deploy / "autostream_dial_install.sh")] + (["--update"] if update else [])
    e = env.env(
        AUTOSTREAM_DIAL_LOCKED="1",
        DIAL_INSTALL_LOGFILE=(tmp_path / "install.log").as_posix(),
        HOME=tmp_path.as_posix(),
        UPDATE_PAINT_DELAY="0",
    )
    r = subprocess.run(args, capture_output=True, text=True, timeout=60, env=e)
    return r, env.calls()


def _names(calls: list[str]) -> list[str]:
    return [c.split()[0] if not c.startswith("phase ") else " ".join(c.split()[:2])
            for c in calls if c.strip()]


@bash_capable
class TestInstallerDryRun:
    def test_update_stages_swaps_nothing_and_ends_with_the_reboot(self, tmp_path):
        r, calls = _dry_run(tmp_path, update=True)
        assert r.returncode == 0, r.stderr
        names = _names(calls)

        def at(token: str) -> int:
            return names.index(token)

        assert at("prepare_update_venv") < at("backup_owned_files") < at("stage_code_tree")
        assert at("stage_code_tree") < at("write_install_state") < at("write_update_swap")
        assert at("write_update_swap") < at("phase reboot") < at("schedule_update_reboot")
        assert names.count("schedule_update_reboot") == 1
        assert [n for n in names if n != "rm"][-1] == "schedule_update_reboot"
        assert names.count("install_code_tree") == 0
        assert names.count("build_venv") == 0
        assert names.count("abort_update") == 0

    def test_update_phases_rise_monotonically_to_the_reboot(self, tmp_path):
        r, calls = _dry_run(tmp_path, update=True)
        assert r.returncode == 0, r.stderr
        phases = [c.split()[1:3] for c in calls if c.startswith("phase ")]
        assert [p[0] for p in phases] == ["prepare", "packages", "packages", "python", "files",
                                          "configure", "staged", "reboot"]
        pct = [int(p[1]) for p in phases]
        assert pct == sorted(pct)
        assert pct[-2:] == [92, 96]

    def test_update_never_restarts_the_dial_services(self, tmp_path):
        r, calls = _dry_run(tmp_path, update=True)
        assert r.returncode == 0, r.stderr
        assert not [c for c in calls if c.startswith("systemctl restart autostream_dial")]
        assert not [c for c in calls if c.startswith("systemctl") and "autostream_dial_wifi_watcher" in c
                    and " restart " in c]
        assert not [c for c in calls if c.startswith("reboot")]

    def test_no_reboot_is_requested_when_the_update_fails(self, tmp_path):
        r, calls = _dry_run(tmp_path, update=True, fail="stage_code_tree")
        assert r.returncode != 0
        names = _names(calls)
        assert "abort_update" in names
        assert "schedule_update_reboot" not in names
        assert "write_update_swap" not in names
        assert "phase reboot" not in names

    def test_a_failure_before_the_venv_build_still_runs_the_cleanup(self, tmp_path):
        r, calls = _dry_run(tmp_path, update=True, fail="system_upgrade")
        assert r.returncode != 0
        assert "abort_update" in _names(calls)
        assert "schedule_update_reboot" not in _names(calls)

    def test_fresh_install_installs_in_place_without_staging_or_reboot(self, tmp_path):
        r, calls = _dry_run(tmp_path, update=False)
        assert r.returncode == 0, r.stderr
        names = _names(calls)
        assert "install_code_tree" in names
        assert "build_venv" in names
        for absent in ("stage_code_tree", "backup_owned_files", "write_update_swap",
                       "schedule_update_reboot", "prepare_update_venv", "abort_update",
                       "phase staged", "phase reboot"):
            assert absent not in names, absent
        assert "systemctl restart autostream_dial autostream_dial_wifi_watcher" in calls
        assert not [c for c in calls if c.startswith("reboot")]
        assert "system_upgrade" not in names

    def test_fresh_install_failure_does_not_run_the_update_cleanup(self, tmp_path):
        r, calls = _dry_run(tmp_path, update=False, fail="install_code_tree")
        assert r.returncode != 0
        assert "abort_update" not in _names(calls)
