"""The dial modules that were deleted must not survive an update.

The dial's update stages the new code set with a manifest and swaps it in at
boot; the swap moves every file the installed manifest lists and the new one
does not into the displaced-files directory. These tests pin that for the
modules the dial no longer has: the shipped tree does not contain them, and a
swap from a tree that does removes them from the live directory.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "tests"))
sys.path.insert(0, str(REPO_ROOT / "supervisor"))

from conftest import load_supervisor_script

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="the swap moves files with POSIX semantics"
)

RETIRED = (
    "dial_core_poll", "dial_target_status", "dial_appliance_fetch", "dial_outputs",
    "dial_eq", "dial_repeat", "dial_auth", "dial_capabilities", "dial_webui_assets",
)


def _manifest(names) -> str:
    return "".join(f"0644\troot:root\t{n}.py\n" for n in sorted(names))


def test_the_shipped_dial_tree_has_none_of_the_retired_modules():
    shipped = {p.stem for p in (REPO_ROOT / "dial").glob("*.py")}
    assert not shipped & set(RETIRED)


def test_a_swap_removes_the_retired_modules_from_the_live_directory(tmp_path):
    mod = load_supervisor_script("autostream_dial_updater", f"dial_retired_{abs(hash(str(tmp_path)))}")
    opt = tmp_path / "opt"
    mod.OPT_DIR = opt
    kept = ("dial_main", "dial_core")
    installed = list(kept) + list(RETIRED)
    for name in installed:
        (opt / f"{name}.py").parent.mkdir(parents=True, exist_ok=True)
        (opt / f"{name}.py").write_text("old", encoding="utf-8")
    (opt / ".manifest").write_text(_manifest(installed), encoding="utf-8")
    staged = opt / ".next"
    staged.mkdir()
    for name in kept:
        (staged / f"{name}.py").write_text("new", encoding="utf-8")
    (staged / "MANIFEST").write_text(_manifest(kept), encoding="utf-8")

    mod._swap_code_tree()

    live = {p.stem for p in opt.glob("*.py")}
    assert live == set(kept)
    assert all((opt / f"{n}.py").read_text(encoding="utf-8") == "new" for n in kept)
    displaced = {p.stem for p in (opt / ".prev").glob("*.py")}
    assert set(RETIRED) <= displaced
