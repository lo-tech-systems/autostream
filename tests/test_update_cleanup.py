"""What an appliance update leaves behind once it has succeeded.

The downloaded release and its extracted tree (about 12 MB) and the list of
services stopped for the update stayed in the root-only directory for good.
They are removed when the update is recorded as successful, and kept when it
fails, since a retry needs them. The install state no longer records the path
of the tree the installer ran from, which nothing reads.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_dial_staged_install import REPO_ROOT, bash_capable  # noqa: E402

INSTALLER = REPO_ROOT / "autostream_install.sh"
STATE_FILES = REPO_ROOT / "installer" / "lib" / "state_files.sh"


def _function(name: str) -> str:
    m = re.search(r"^" + re.escape(name) + r"\(\) \{.*?\n\}\n", INSTALLER.read_text(encoding="utf-8"),
                  re.S | re.M)
    assert m is not None, name
    return m.group(0)


def _update_dir(tmp_path: Path) -> Path:
    d = tmp_path / "autostream-update"
    (d / "staging" / "src" / "autostream-0.7.0").mkdir(parents=True)
    (d / "staging" / "src" / "autostream-0.7.0" / "autostream_install.sh").write_text("#!/bin/bash\n")
    (d / "staging" / "release.tgz").write_bytes(b"x" * 1000)
    (d / "staging" / "release_tag").write_text("0.7.0\n")
    (d / "staging" / "retry_count").write_text("1\n")
    (d / "update-stopped-services.env").write_text("autostream\nowntone\n")
    (d / "update-in-progress").write_text("0.7.0\n")
    (d / "low-power-restore.env").write_text("# note\n")
    return d


def _bash(body: str, tmp_path: Path):
    script = f'set -Eeuo pipefail\nIFS=$\'\\n\\t\'\n{body}'
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)


@bash_capable
class TestRemoveStagedUpdate:
    def _run(self, d: Path, tmp_path: Path):
        return _bash(
            f'UPDATE_STATE_DIR="{d.as_posix()}"\nSTOPPED_SERVICES_FILE="{d.as_posix()}/update-stopped-services.env"\n'
            f'{_function("remove_staged_update")}\nremove_staged_update\necho done', tmp_path)

    def test_the_staged_release_and_the_stopped_services_list_are_removed(self, tmp_path):
        d = _update_dir(tmp_path)
        r = self._run(d, tmp_path)
        assert r.returncode == 0 and "done" in r.stdout, r.stderr
        assert not (d / "staging").exists()
        assert not (d / "update-stopped-services.env").exists()

    def test_nothing_else_in_the_directory_is_touched(self, tmp_path):
        d = _update_dir(tmp_path)
        self._run(d, tmp_path)
        assert (d / "update-in-progress").exists()
        assert (d / "low-power-restore.env").read_text() == "# note\n"

    def test_it_is_harmless_when_there_is_nothing_to_remove(self, tmp_path):
        d = tmp_path / "autostream-update"
        d.mkdir()
        r = self._run(d, tmp_path)
        assert r.returncode == 0 and "done" in r.stdout, r.stderr

    def test_a_link_called_staging_is_removed_not_followed(self, tmp_path):
        d = tmp_path / "autostream-update"
        d.mkdir()
        target = tmp_path / "elsewhere"
        target.mkdir()
        (target / "keep").write_text("keep")
        (d / "staging").symlink_to(target)
        self._run(d, tmp_path)
        assert not (d / "staging").exists() and not (d / "staging").is_symlink()
        assert (target / "keep").read_text() == "keep"

    def test_the_installer_that_runs_from_the_staged_tree_carries_on_after_it_is_removed(self, tmp_path):
        d = _update_dir(tmp_path)
        script = d / "staging" / "src" / "autostream-0.7.0" / "autostream_install.sh"
        script.write_text(
            "#!/bin/bash\n"
            f'UPDATE_STATE_DIR="{d.as_posix()}"\nSTOPPED_SERVICES_FILE="{d.as_posix()}/update-stopped-services.env"\n'
            f'{_function("remove_staged_update")}\n'
            "remove_staged_update\necho still-running\n", encoding="utf-8")
        script.chmod(0o755)
        r = subprocess.run([str(script)], capture_output=True, text=True, timeout=30)
        assert "still-running" in r.stdout, r.stderr
        assert not (d / "staging").exists()


class TestWhenItRuns:
    def _run_update(self) -> str:
        return _function("run_update")

    def test_text_check_it_follows_the_success_result_and_precedes_the_reboot(self):
        body = self._run_update()
        i = body.index('write_update_result "success"')
        j = body.index("remove_staged_update")
        assert i < j < body.index("autostream_admin reboot")

    def test_text_check_nothing_on_the_failure_path_removes_it(self):
        text = INSTALLER.read_text(encoding="utf-8")
        assert text.count("\n  remove_staged_update\n") == 1          # the one call
        on_error = _function("on_error")
        assert "remove_staged_update" not in on_error
        assert "rm -rf" not in on_error


@bash_capable
class TestInstallStateNoLongerRecordsTheTree:
    def test_the_saved_state_has_no_autostream_dir(self, tmp_path):
        state = tmp_path / "install-state.env"
        script = f'''
source "{STATE_FILES.as_posix()}"
info() {{ :; }}
STATE_FILE="{state.as_posix()}"; STAMP_DIR="{tmp_path.as_posix()}"; SCRIPT_NAME=autostream_install.sh
AUTOSTREAM_DIR=/var/lib/autostream-update/staging/src/x; INSTALL_DIR=/opt/autostream; INSTALL_MODE=install
OWNTONE_MODE=mini; SDMON_METHOD=""; SDMON_CHECK=none; SDMON_CHECK_SERIAL=""; SDMON_CHECK_AT=""
SDMON_CHECK_REASON=""; SDMON_FLAG_THIS_RUN=0; FETCH_AUTOSTREAM=0; LOW_POWER=0
{_function("detect_install_version")}
{_function("save_state")}
chown() {{ :; }}
save_state
'''
        r = _bash(script, tmp_path)
        assert r.returncode == 0, r.stderr
        text = state.read_text(encoding="utf-8")
        assert "AUTOSTREAM_DIR" not in text and "staging" not in text
        assert 'INSTALL_DIR="/opt/autostream"' in text and "OWNTONE_MODE" in text

    @pytest.mark.parametrize("tree", ["core", "supervisor", "tools", "platform"])
    def test_nothing_in_the_code_reads_the_key_back(self, tree):
        readers = []
        for path in sorted((REPO_ROOT / tree).rglob("*")):
            if path.is_file() and path.suffix in ("", ".py", ".sh") and "__pycache__" not in path.parts:
                try:
                    if "AUTOSTREAM_DIR" in path.read_text(encoding="utf-8"):
                        readers.append(path.relative_to(REPO_ROOT).as_posix())
                except UnicodeDecodeError:
                    continue
        assert readers == []
