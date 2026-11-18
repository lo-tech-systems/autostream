"""Source guards over the dial's Python modules: pyflakes finds no unused import or local, no
redefinition and no undefined name; no module calls a test hook.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pyflakes import checker, messages

GATED = (
    messages.UnusedImport,
    messages.RedefinedWhileUnused,
    messages.UnusedVariable,
    messages.UndefinedName,
    messages.UndefinedLocal,
    messages.UndefinedExport,
)
DIAL = Path(__file__).resolve().parent.parent / "dial"
MODULES = sorted(DIAL.glob("*.py"))


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.name)
def test_a_dial_module_is_lint_clean(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found = checker.Checker(tree, filename=str(path)).messages
    hits = sorted(str(m) for m in found if isinstance(m, GATED))
    assert not hits, "\n".join(hits)


def test_the_dial_has_modules():
    assert len(MODULES) > 30


def _test_hook_calls(tree):
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr.endswith("for_tests")
    ]


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.name)
def test_no_dial_module_calls_a_test_hook(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    assert not _test_hook_calls(tree), f"{path.name} calls a test hook at lines {_test_hook_calls(tree)}"
