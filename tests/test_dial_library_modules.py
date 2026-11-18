"""Source guard: the dial's small library modules stay leaves.

Each module may import only what is listed for it (plus, for a few, a named
function-level import), and none imports PIL at module level.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import ast
import subprocess
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
    "dial_layout_metrics": set(),
    "dial_display_views": {"dial_touch_layout"},
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


def test_the_views_module_imports_without_pillow():
    code = (
        "import sys\n"
        "sys.modules['PIL'] = None\n"
        f"sys.path.insert(0, {str(DIAL)!r})\n"
        "import dial_display_views\n"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


# The display layers, lowest first: each may import only the display modules listed.
DISPLAY_LAYER_IMPORTS = {
    "dial_display_views": {"dial_display_palette"},
    "dial_display_draw": {"dial_display_palette", "dial_display_views"},
    "dial_display_reveal": {"dial_display_views", "dial_display_draw"},
    "dial_display_compositor": {
        "dial_display_palette", "dial_display_views", "dial_display_draw", "dial_display_reveal",
        "dial_display_render", "dial_display_image",
    },
}


@pytest.mark.parametrize("name", sorted(DISPLAY_LAYER_IMPORTS))
def test_the_display_layers_import_only_downwards(name):
    tree = ast.parse((DIAL / f"{name}.py").read_text(encoding="utf-8"))
    found = {m for m in _imports(tree, module_level=False) if m.startswith("dial_display_")}
    assert found <= DISPLAY_LAYER_IMPORTS[name], f"{name} imports {sorted(found - DISPLAY_LAYER_IMPORTS[name])}"
