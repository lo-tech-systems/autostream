"""The scripts a person runs directly are executable.

The documented `sudo ./autostream_uninstall.sh` fails with "command not found"
from a checkout or a release tarball when the file is not executable. The mode
that counts is the one git records, so that is what is read; where git cannot
answer (a worktree read from another system, an extracted tarball) the files
themselves are read, unless the file system keeps no modes at all (every file
looks executable), where the check says so by skipping instead of passing.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Run by name from a checkout or an extracted release: the installers and the
# uninstallers. The two bootstrap scripts are piped into bash from the web and
# run by name never.
RUN_DIRECTLY = [
    "autostream_install.sh",
    "autostream_dial_install.sh",
    "autostream_uninstall.sh",
    "autostream_dial_uninstall.sh",
]


def _git_modes() -> dict[str, str] | None:
    """Mode git records for each script, or None when git cannot say."""
    try:
        out = subprocess.run(["git", "ls-files", "-s", *RUN_DIRECTLY], cwd=str(REPO_ROOT),
                             capture_output=True, text=True, check=True)
    except (OSError, subprocess.SubprocessError):
        return None
    modes = {}
    for line in out.stdout.splitlines():
        meta, _, name = line.partition("\t")
        modes[name] = meta.split()[0]
    return modes if len(modes) == len(RUN_DIRECTLY) else None


@pytest.mark.parametrize("script", RUN_DIRECTLY)
def test_the_script_is_executable(script):
    modes = _git_modes()
    if modes is not None:
        assert modes[script] == "100755", f"{script} is tracked with mode {modes[script]}"
        return
    # No git. A file system without modes shows everything executable, so a file
    # that must not be (the licence) is the witness.
    if os.access(REPO_ROOT / "LICENSE", os.X_OK):
        pytest.skip("git cannot be asked and this file system keeps no file modes")
    assert os.access(REPO_ROOT / script, os.X_OK), f"{script} is not executable"
