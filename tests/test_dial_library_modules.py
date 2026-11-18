"""Source guard: the dial's small library modules stay leaves.

Each module may import only what is listed for it (plus, for a few, a named
function-level import), and none imports PIL at module level.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

DIAL = Path(__file__).resolve().parent.parent / "dial"

# module -> the non-stdlib modules it may import at module level.
ALLOWED = {
    "dial_values": set(),
    "dial_http_common": set(),
    "dial_pin_guard": set(),
    "dial_admin": set(),
    "dial_eq_model": {"autostream_eq_bands", "dial_values"},
    "dial_touch_surfaces": set(),
    "dial_display_backend": {"dial_display_profiles"},
    "dial_display_palette": set(),
    "dial_appliance_warnings": {"dial_mdns", "dial_values"},
}


def _imports(tree, *, module_level: bool):
    nodes = tree.body if module_level else list(ast.walk(tree))
    names = set()
    for node in nodes:
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


@pytest.mark.parametrize("name", sorted(ALLOWED))
def test_a_library_module_imports_only_what_it_may(name):
    tree = ast.parse((DIAL / f"{name}.py").read_text(encoding="utf-8"))
    found = {m for m in _imports(tree, module_level=True) if m not in sys.stdlib_module_names}
    assert found <= ALLOWED[name], f"{name} imports {sorted(found - ALLOWED[name])}"


@pytest.mark.parametrize("name", sorted(ALLOWED))
def test_a_library_module_does_not_import_pil_at_module_level(name):
    tree = ast.parse((DIAL / f"{name}.py").read_text(encoding="utf-8"))
    assert "PIL" not in _imports(tree, module_level=True)
