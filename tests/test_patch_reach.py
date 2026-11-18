"""tests/test_patch_reach.py

A static check that every patch in the test suite reaches a lookup.

A patch of ``module.name`` only changes behaviour when some code reads
``name`` from that module at call time.  Two defects make a patch do nothing
and the test pass for the wrong reason:

  rule 1  ``name`` is never looked up in the module: no load of the name in
          its own source and no ``alias.name`` read in any core module.
  rule 2  ``name`` is defined in the module, but another core module that the
          test file also uses copied it with ``from module import name``, so
          the patch never reaches that module's copy.

Both are decided on the syntax tree alone.  Findings that exist today are held
in PATCH_RATCHET: a new finding fails, and so does an entry that no longer
occurs (delete it from PATCH_RATCHET).  Regenerate the table with
``python tests/test_patch_reach.py --print-ratchet``.
"""
from __future__ import annotations

import ast
import sys
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
CORE_DIR = TESTS_DIR.parent / "core"
_SELF = Path(__file__).name

# Modules whose attribute lookups are resolved by handler name strings kept in
# the route table, not by a literal attribute read.
_ROUTE_TABLE_MODULE = "autostream_webui_routes"
_ROUTE_TARGET_MODULE = "autostream_webui"


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _py_files(root: Path):
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" not in path.parts:
            yield path


def _module_name(root: Path, path: Path) -> str:
    """The core module a file belongs to: flat name, or `pkg.sub` for a package file."""
    rel = path.relative_to(root).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _module_names(root: Path) -> frozenset[str]:
    return frozenset(_module_name(root, p) for p in _py_files(root))


def _aliases(tree: ast.AST, modules: frozenset[str]) -> dict[str, set[str]]:
    """Local name -> core modules it may be bound to by an import in this tree."""
    out: dict[str, set[str]] = {}

    def bind(name: str, module: str) -> None:
        out.setdefault(name, set()).add(module)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname and a.name in modules:
                    bind(a.asname, a.name)
                elif not a.asname and a.name.split(".")[0] in modules:
                    bind(a.name.split(".")[0], a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for a in node.names:
                full = f"{node.module}.{a.name}"
                if full in modules:
                    bind(a.asname or a.name, full)
    return out


def _single(aliases: dict[str, set[str]], name: str) -> str | None:
    mods = aliases.get(name, ())
    return next(iter(mods)) if len(mods) == 1 else None


def _defined_names(tree: ast.Module) -> set[str]:
    """Names bound at module level (through plain statements) or via `global`."""
    names: set[str] = set()

    def targets(t: ast.AST) -> None:
        if isinstance(t, ast.Name):
            names.add(t.id)
        elif isinstance(t, (ast.Tuple, ast.List)):
            for e in t.elts:
                targets(e)

    def walk_body(body) -> None:
        for st in body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(st.name)
            elif isinstance(st, ast.Assign):
                for t in st.targets:
                    targets(t)
            elif isinstance(st, (ast.AnnAssign, ast.AugAssign)):
                targets(st.target)
            elif isinstance(st, ast.Import):
                for a in st.names:
                    names.add(a.asname or a.name.split(".")[0])
            elif isinstance(st, ast.ImportFrom):
                for a in st.names:
                    names.add(a.asname or a.name)
            elif isinstance(st, (ast.For, ast.AsyncFor)):
                targets(st.target)
                walk_body(st.body)
                walk_body(st.orelse)
            elif isinstance(st, (ast.If, ast.While)):
                walk_body(st.body)
                walk_body(st.orelse)
            elif isinstance(st, (ast.With, ast.AsyncWith)):
                walk_body(st.body)
            elif isinstance(st, ast.Try):
                walk_body(st.body)
                for h in st.handlers:
                    walk_body(h.body)
                walk_body(st.orelse)
                walk_body(st.finalbody)

    walk_body(tree.body)
    for node in ast.walk(tree):
        if isinstance(node, ast.Global):
            names.update(node.names)
    return names


# ---------------------------------------------------------------------------
# The core side: what is looked up, and what is copied
# ---------------------------------------------------------------------------

@dataclass
class CoreIndex:
    modules: frozenset[str]
    trees: dict[str, list[ast.Module]] = field(default_factory=dict)
    defined: dict[str, set[str]] = field(default_factory=dict)
    loaded: dict[str, set[str]] = field(default_factory=dict)          # Name loads in a module's own source
    attr_lookups: dict[str, set[str]] = field(default_factory=dict)    # alias.n reads and const getattr, by target module
    dynamic: set[str] = field(default_factory=set)                     # modules with a non-constant lookup
    from_imports: dict[str, list[tuple[str, str, str]]] = field(default_factory=dict)  # importer -> (source, name, local)


def _is_sys_modules_name(node: ast.AST) -> bool:
    """`sys.modules[__name__]`."""
    return (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "modules"
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "sys"
        and isinstance(node.slice, ast.Name)
        and node.slice.id == "__name__"
    )


def _is_globals_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "globals"
        and not node.args
    )


def _const_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _handler_strings(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "handler":
            s = _const_str(node.value)
            if s:
                yield s


def build_core_index(core_dir: Path) -> CoreIndex:
    modules = _module_names(core_dir)
    idx = CoreIndex(modules=modules)
    for path in _py_files(core_dir):
        mod = _module_name(core_dir, path)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        idx.trees.setdefault(mod, []).append(tree)
        idx.defined.setdefault(mod, set()).update(_defined_names(tree))
        loads = idx.loaded.setdefault(mod, set())
        aliases = _aliases(tree, modules)
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                loads.add(node.id)
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
                if isinstance(node.value, ast.Name):
                    target = _single(aliases, node.value.id)
                    if target:
                        idx.attr_lookups.setdefault(target, set()).add(node.attr)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for a in node.names:
                    idx.from_imports.setdefault(mod, []).append(
                        (node.module, a.name, a.asname or a.name)
                    )
            elif isinstance(node, ast.Call):
                _note_dynamic_lookup(idx, mod, node, aliases)
            elif isinstance(node, ast.Subscript) and _is_globals_call(node.value):
                const = _const_str(node.slice)
                if const:
                    idx.attr_lookups.setdefault(mod, set()).add(const)
                else:
                    idx.dynamic.add(mod)
        if mod == _ROUTE_TABLE_MODULE:
            idx.attr_lookups.setdefault(_ROUTE_TARGET_MODULE, set()).update(_handler_strings(tree))
    return idx


def _note_dynamic_lookup(idx: CoreIndex, mod: str, node: ast.Call, aliases) -> None:
    func = node.func
    # globals().get(expr)
    if (isinstance(func, ast.Attribute) and func.attr == "get"
            and _is_globals_call(func.value) and node.args):
        const = _const_str(node.args[0])
        if const:
            idx.attr_lookups.setdefault(mod, set()).add(const)
        else:
            idx.dynamic.add(mod)
        return
    # getattr(M, name) where M is this module or an alias of a core module
    if not (isinstance(func, ast.Name) and func.id == "getattr" and len(node.args) >= 2):
        return
    first = node.args[0]
    if _is_sys_modules_name(first):
        target = mod
    elif isinstance(first, ast.Name):
        target = _single(aliases, first.id)
    else:
        target = None
    if not target:
        return  # getattr on some other object cannot reach a module-level name
    const = _const_str(node.args[1])
    if const:
        idx.attr_lookups.setdefault(target, set()).add(const)
    elif mod != _ROUTE_TABLE_MODULE:
        # The route table resolves handler names through the strings it holds,
        # collected separately; it does not make its target dynamic.
        idx.dynamic.add(target)


# ---------------------------------------------------------------------------
# The test side: what is patched
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Patch:
    module: str
    name: str
    line: int
    create: bool


def _kw_true(node: ast.Call, key: str, value: bool) -> bool:
    for kw in node.keywords:
        if kw.arg == key and isinstance(kw.value, ast.Constant) and kw.value.value is value:
            return True
    return False


def _split_target(path: str, modules: frozenset[str], classes: set[tuple[str, str]]):
    """Resolve "pkg.mod.name[.attr]" to (module, name), or None."""
    parts = path.split(".")
    for k in range(len(parts) - 1, 0, -1):
        mod = ".".join(parts[:k])
        if mod in modules:
            rest = parts[k:]
            if len(rest) == 1:
                return mod, rest[0]
            if len(rest) == 2 and (mod, rest[0]) not in classes:
                return mod, rest[0]
            return None  # an attribute of a class or deeper: patched on an object
    return None


def _is_patch_name(func: ast.AST) -> bool:
    return (isinstance(func, ast.Name) and func.id == "patch") or (
        isinstance(func, ast.Attribute) and func.attr == "patch"
    )


def _is_patch_member(func: ast.AST, member: str) -> bool:
    return (
        isinstance(func, ast.Attribute) and func.attr == member and _is_patch_name(func.value)
    )


def _is_monkeypatch_call(func: ast.AST, member: str) -> bool:
    if not (isinstance(func, ast.Attribute) and func.attr == member):
        return False
    base = func.value
    ident = base.id if isinstance(base, ast.Name) else getattr(base, "attr", "")
    return ident in ("monkeypatch", "mp")


def collect_patches(tree: ast.AST, modules: frozenset[str], core: CoreIndex):
    aliases = _aliases(tree, modules)
    classes = {
        (m, n)
        for m, trees in core.trees.items()
        for t in trees
        for n in [c.name for c in t.body if isinstance(c, ast.ClassDef)]
    }
    out: list[Patch] = []

    def add(mod: str | None, name: str | None, node: ast.AST, create: bool = False) -> None:
        if mod and name and mod in modules:
            out.append(Patch(mod, name, node.lineno, create))

    def by_target(arg: ast.AST):
        """A module reference: an alias name, or a dotted string."""
        if isinstance(arg, ast.Name):
            return _single(aliases, arg.id)
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
            if isinstance(node.value, ast.Name):
                add(_single(aliases, node.value.id), node.attr, node)
            continue
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        create = _kw_true(node, "create", True) or _kw_true(node, "raising", False)
        if _is_patch_member(func, "object") and len(node.args) >= 2:
            add(by_target(node.args[0]), _const_str(node.args[1]), node, create)
        elif _is_patch_member(func, "multiple") and node.args:
            mod = _const_str(node.args[0])
            if mod in modules:
                for kw in node.keywords:
                    if kw.arg and kw.arg not in ("spec", "create", "spec_set", "autospec", "new_callable"):
                        add(mod, kw.arg, node, create)
        elif _is_patch_name(func) and node.args:
            target = _const_str(node.args[0])
            if target:
                hit = _split_target(target, modules, classes)
                if hit:
                    add(hit[0], hit[1], node, create)
        elif (_is_monkeypatch_call(func, "setattr") or _is_monkeypatch_call(func, "delattr")) and node.args:
            first = node.args[0]
            if len(node.args) >= 2 and not isinstance(first, ast.Constant):
                add(by_target(first), _const_str(node.args[1]), node, create)
            elif isinstance(first, ast.Constant) and _const_str(first):
                hit = _split_target(first.value, modules, classes)
                if hit:
                    add(hit[0], hit[1], node, create)
    return out, aliases


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def findings(core_dir: Path, tests_dir: Path) -> set[tuple[str, int, str, str]]:
    """Return (test file, rule, module, name) for every unreached patch."""
    core = build_core_index(core_dir)
    found: set[tuple[str, int, str, str]] = set()
    for path in _py_files(tests_dir):
        if path.name == _SELF:
            continue
        rel = path.relative_to(tests_dir).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:
            continue
        patches, aliases = collect_patches(tree, core.modules, core)
        if not patches:
            continue
        patched = {(p.module, p.name) for p in patches}
        used = {m for mods in aliases.values() for m in mods} | {p.module for p in patches}
        for p in patches:
            if p.create:
                continue
            m, n = p.module, p.name
            looked_up = (
                n in core.loaded.get(m, ())
                or n in core.attr_lookups.get(m, ())
                or m in core.dynamic
            )
            if not looked_up:
                found.add((rel, 1, m, n))
            if n in core.defined.get(m, ()):
                for x in sorted(used - {m}):
                    for src, name, local in core.from_imports.get(x, ()):
                        if (src, name) == (m, n) and local in core.loaded.get(x, ()) \
                                and (x, local) not in patched:
                            found.add((rel, 2, m, n))
    return found


# ---------------------------------------------------------------------------
# Ratchet: findings that exist today.  Shrink only.
# ---------------------------------------------------------------------------

PATCH_RATCHET: frozenset[tuple[str, int, str, str]] = frozenset({
    ('playwright/test_dial_card_surface.py', 1, 'autostream_webui_page_setup', 'suggested_silence_threshold_dbfs'),
    ('playwright/test_ui_flows.py', 1, 'autostream_webui_page_setup', 'suggested_silence_threshold_dbfs'),
    ('test_appliance_models.py', 1, 'autostream_output_usage', 'annotate_outputs'),
    ('test_appliance_models.py', 2, 'autostream_output_usage', 'annotate_outputs'),
    ('test_audio_path.py', 1, 'autostream_rpi', 'is_high_performance_pi'),
    ('test_audio_path.py', 2, 'autostream_player_service', 'save_setting'),
    ('test_audio_path.py', 2, 'autostream_rpi', 'is_high_performance_pi'),
    ('test_bluetooth_setup_ui.py', 1, 'autostream_webui_page_setup', '_set_flash_cookie'),
    ('test_bluetooth_setup_ui.py', 1, 'autostream_webui_page_setup', 'suggested_silence_threshold_dbfs'),
    ('test_browser_api_error_contract.py', 2, 'autostream_webui_api', 'send_json'),
    ('test_control_other_appliances.py', 1, 'autostream_output_usage', 'annotate_outputs'),
    ('test_control_other_appliances.py', 1, 'autostream_webui_post_handlers', 'build_top_banner_html'),
    ('test_control_other_appliances.py', 2, 'autostream_output_usage', 'annotate_outputs'),
    ('test_dial_registry.py', 1, 'autostream_sysutils', 'atomic_write_file'),
    ('test_dial_registry.py', 2, 'autostream_sysutils', 'atomic_write_file'),
    ('test_dial_warnings_provider.py', 2, 'autostream_system_stats', '_read_get_throttled_value'),
    ('test_federation_api.py', 1, 'autostream_webui_common', '_config_snapshot'),
    ('test_federation_api.py', 2, 'autostream_webui_common', '_config_snapshot'),
    ('test_monitor_daemon_recovery_log.py', 1, 'autostream_log_policy', 'apply_startup_log_level'),
    ('test_monitor_daemon_recovery_log.py', 2, 'autostream_log_policy', 'apply_startup_log_level'),
    ('test_player_service.py', 1, 'autostream_sysutils', 'atomic_write_file'),
    ('test_player_service.py', 2, 'autostream_sysutils', 'atomic_write_file'),
    ('test_process_recovery.py', 1, 'autostream_log_policy', 'apply_startup_log_level'),
    ('test_process_recovery.py', 2, 'autostream_log_policy', 'apply_startup_log_level'),
    ('test_repeat_ui_wiring.py', 1, 'autostream_webui_page_setup', '_set_flash_cookie'),
    ('test_repeat_ui_wiring.py', 1, 'autostream_webui_page_setup', 'suggested_silence_threshold_dbfs'),
    ('test_settings_cross_field_invariants.py', 1, 'autostream_webui_post_handlers', 'build_top_banner_html'),
    ('test_setup_page_golden.py', 1, 'autostream_webui_page_setup', '_set_flash_cookie'),
    ('test_setup_page_golden.py', 1, 'autostream_webui_page_setup', 'suggested_silence_threshold_dbfs'),
    ('test_setup_page_golden.py', 2, 'autostream_player_service', 'get_capabilities'),
    ('test_start_buffer_cache.py', 1, 'autostream_player_service', 'get_setting'),
    ('test_start_buffer_cache.py', 2, 'autostream_player_service', 'get_setting'),
    ('test_sysutils.py', 1, 'autostream_rpi', 'get_raspberry_pi_model'),
    ('test_sysutils.py', 2, 'autostream_rpi', 'get_raspberry_pi_model'),
    ('test_track_id_setup.py', 1, 'autostream_config', 'suggested_silence_threshold_dbfs'),
    ('test_update_apply_async.py', 1, 'autostream_webui', '_UPDATE_RESULT_FILE'),
    ('test_update_channels.py', 1, 'autostream_webui_page_setup', '_set_flash_cookie'),
    ('test_update_channels.py', 1, 'autostream_webui_page_setup', 'suggested_silence_threshold_dbfs'),
    ('test_webui_auth_routing.py', 1, 'autostream_webui_common', '_config_snapshot'),
    ('test_webui_auth_routing.py', 2, 'autostream_webui_common', '_config_snapshot'),
    ('test_webui_dial_outputs.py', 1, 'autostream_player_service', 'config_airplay_mode_to_backend'),
    ('test_webui_dial_outputs.py', 2, 'autostream_player_service', 'config_airplay_mode_to_backend'),
    ('test_webui_post_handlers.py', 1, 'autostream_appliance_models', 'submit_output_change'),
    ('test_webui_post_handlers.py', 1, 'autostream_webui_post_handlers', 'build_top_banner_html'),
    ('test_webui_post_handlers.py', 2, 'autostream_appliance_models', 'submit_output_change'),
    ('test_webui_post_handlers.py', 2, 'autostream_webui_common', 'get_app_version'),
    ('test_wp2_log_level_api.py', 1, 'autostream_log_policy', 'get_log_level_state'),
    ('test_wp2_log_level_api.py', 2, 'autostream_log_policy', 'get_log_level_state'),
    ('test_wp2_log_level_api.py', 2, 'autostream_webui_api', 'send_json'),
    ('test_wp2_settings_ownership.py', 1, 'autostream_log_policy', 'apply_startup_log_level'),
    ('test_wp2_settings_ownership.py', 1, 'autostream_settings', 'SettingsStore'),
    ('test_wp2_settings_ownership.py', 2, 'autostream_log_policy', 'apply_startup_log_level'),
    ('test_wp2_settings_ownership.py', 2, 'autostream_settings', 'SettingsStore'),
    ('test_wp3_settings_api.py', 1, 'autostream_webui_page_setup', '_set_flash_cookie'),
    ('test_wp3_settings_api.py', 1, 'autostream_webui_page_setup', 'suggested_silence_threshold_dbfs'),
    ('test_wp4c_setup_ui_wiring.py', 1, 'autostream_webui_page_setup', '_set_flash_cookie'),
    ('test_wp4c_setup_ui_wiring.py', 1, 'autostream_webui_page_setup', 'suggested_silence_threshold_dbfs'),
    ('test_wp4c_setup_ui_wiring.py', 2, 'autostream_player_service', 'get_capabilities'),
    ('test_wp5_transactions.py', 1, 'autostream_webui_page_setup', '_set_flash_cookie'),
    ('test_wp5_transactions.py', 1, 'autostream_webui_page_setup', 'suggested_silence_threshold_dbfs'),
    ('test_wp7_owntone_autosave.py', 1, 'autostream_player_service', 'get_setting'),
    ('test_wp7_owntone_autosave.py', 1, 'autostream_webui_page_owntone', 'start_owntone_restart_async'),
    ('test_wp7_owntone_autosave.py', 2, 'autostream_player_service', 'get_setting'),
    ('test_wp8b_first_boot_pages.py', 1, 'autostream_webui_page_first_boot', 'mark_configured'),
    ('test_wp8b_no_input_banner.py', 1, 'autostream_webui_page_setup', '_set_flash_cookie'),
    ('test_wp8b_no_input_banner.py', 1, 'autostream_webui_page_setup', 'suggested_silence_threshold_dbfs'),
    ('test_wp8c_routing_cutover.py', 1, 'autostream_webui_page_setup', '_set_flash_cookie'),
    ('test_wp8c_routing_cutover.py', 1, 'autostream_webui_page_setup', 'suggested_silence_threshold_dbfs'),
})


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def _tree(tmp_path: Path, core: dict[str, str], tests: dict[str, str]):
    for base, files in (("core", core), ("tests", tests)):
        for rel, text in files.items():
            p = tmp_path / base / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
    return tmp_path / "core", tmp_path / "tests"


def _run(tmp_path, core, tests):
    c, t = _tree(tmp_path, core, tests)
    return findings(c, t)


_USES_X = "def f():\n    return x + 1\n"


def test_patch_of_a_looked_up_name_is_reached(tmp_path):
    got = _run(tmp_path, {"m.py": "x = 1\n" + _USES_X},
               {"test_a.py": "from unittest.mock import patch\n"
                             "def test_a():\n    with patch('m.x', 2):\n        pass\n"})
    assert got == set()


def test_unlooked_up_name_is_rule_1(tmp_path):
    got = _run(tmp_path, {"m.py": "x = 1\ny = 2\n" + _USES_X},
               {"test_a.py": "from unittest.mock import patch\n"
                             "def test_a():\n    with patch('m.y', 2):\n        pass\n"})
    assert got == {("test_a.py", 1, "m", "y")}


def test_patch_object_and_monkeypatch_and_store_forms(tmp_path):
    tests = (
        "import m\n"
        "from unittest.mock import patch\n"
        "def test_a(monkeypatch):\n"
        "    patch.object(m, 'a')\n"
        "    monkeypatch.setattr(m, 'b', 1)\n"
        "    monkeypatch.delattr(m, 'c')\n"
        "    monkeypatch.setattr('m.d', 1)\n"
        "    m.e = 5\n"
        "    patch.multiple('m', f=1, g=2)\n"
    )
    got = _run(tmp_path, {"m.py": "x = 1\n"}, {"test_a.py": tests})
    assert got == {("test_a.py", 1, "m", n) for n in "abcdefg"}


def test_create_true_and_raising_false_are_exempt(tmp_path):
    tests = (
        "import m\n"
        "from unittest.mock import patch\n"
        "def test_a(monkeypatch):\n"
        "    patch('m.a', 1, create=True)\n"
        "    monkeypatch.setattr(m, 'b', 1, raising=False)\n"
    )
    assert _run(tmp_path, {"m.py": ""}, {"test_a.py": tests}) == set()


def test_alias_attribute_read_in_another_core_module_counts(tmp_path):
    core = {"m.py": "x = 1\n", "n.py": "import m\ndef f():\n    return m.x\n"}
    tests = "from unittest.mock import patch\ndef test_a():\n    patch('m.x', 2)\n"
    assert _run(tmp_path, core, {"test_a.py": tests}) == set()


def test_constant_getattr_on_the_module_counts(tmp_path):
    core = {"m.py": "import sys\nx = 1\ndef f():\n    return getattr(sys.modules[__name__], 'x')\n"}
    tests = "from unittest.mock import patch\ndef test_a():\n    patch('m.x', 2)\n"
    assert _run(tmp_path, core, {"test_a.py": tests}) == set()


def test_dynamic_getattr_on_the_module_exempts_it(tmp_path):
    core = {"m.py": "import sys\nx = 1\ndef f(k):\n    return getattr(sys.modules[__name__], k)\n"}
    tests = "from unittest.mock import patch\ndef test_a():\n    patch('m.x', 2)\n"
    assert _run(tmp_path, core, {"test_a.py": tests}) == set()


def test_globals_lookup_with_a_variable_exempts_the_module(tmp_path):
    core = {"m.py": "x = 1\ndef f(k):\n    return globals()[k]\n"}
    tests = "from unittest.mock import patch\ndef test_a():\n    patch('m.x', 2)\n"
    assert _run(tmp_path, core, {"test_a.py": tests}) == set()


def test_getattr_on_another_object_exempts_nothing(tmp_path):
    core = {"m.py": "x = 1\ndef f(obj, k):\n    return getattr(obj, k)\n"}
    tests = "from unittest.mock import patch\ndef test_a():\n    patch('m.x', 2)\n"
    assert _run(tmp_path, core, {"test_a.py": tests}) == {("test_a.py", 1, "m", "x")}


def test_route_handler_strings_count_as_lookups_of_the_web_module(tmp_path):
    core = {
        "autostream_webui.py": "def send_it():\n    pass\n",
        "autostream_webui_routes.py": (
            "def route(**kw):\n    pass\n"
            "route(handler='send_it')\n"
            "def resolve(mod, r):\n    import autostream_webui as w\n    return getattr(w, r.handler)\n"
        ),
    }
    tests = ("from unittest.mock import patch\n"
             "def test_a():\n    patch('autostream_webui.send_it')\n    patch('autostream_webui.other')\n")
    assert _run(tmp_path, core, {"test_a.py": tests}) == {("test_a.py", 1, "autostream_webui", "other")}


def test_class_attribute_patch_is_skipped_but_instance_attribute_is_checked(tmp_path):
    core = {"m.py": "class K:\n    def meth(self):\n        pass\nobj = object()\ndef f():\n    return obj\n"}
    tests = ("from unittest.mock import patch\n"
             "def test_a():\n    patch('m.K.meth')\n    patch('m.obj.attr')\n    patch('m.K.a.b')\n")
    assert _run(tmp_path, core, {"test_a.py": tests}) == set()


def test_rule_2_copy_made_by_from_import_is_flagged(tmp_path):
    core = {
        "m.py": "x = 1\ndef g():\n    return x\n",
        "other.py": "from m import x\ndef f():\n    return x\n",
    }
    tests = ("import other\nfrom unittest.mock import patch\n"
             "def test_a():\n    patch('m.x', 2)\n")
    got = _run(tmp_path, core, {"test_a.py": tests})
    assert ("test_a.py", 2, "m", "x") in got


def test_rule_2_is_satisfied_by_patching_the_copy_too(tmp_path):
    core = {
        "m.py": "x = 1\ndef g():\n    return x\n",
        "other.py": "from m import x\ndef f():\n    return x\n",
    }
    tests = ("import other\nfrom unittest.mock import patch\n"
             "def test_a():\n    patch('m.x', 2)\n    patch('other.x', 2)\n")
    assert _run(tmp_path, core, {"test_a.py": tests}) == set()


def test_rule_2_ignores_modules_the_test_does_not_use(tmp_path):
    core = {
        "m.py": "x = 1\n",
        "other.py": "from m import x\ndef f():\n    return x\n",
    }
    tests = "from unittest.mock import patch\ndef test_a():\n    patch('m.x', 2)\n"
    got = _run(tmp_path, core, {"test_a.py": tests})
    assert not any(f[1] == 2 for f in got)


def test_non_core_targets_are_ignored(tmp_path):
    tests = ("from unittest.mock import patch\n"
             "def test_a():\n    patch('os.getcwd')\n    patch('builtins.open')\n")
    assert _run(tmp_path, {"m.py": ""}, {"test_a.py": tests}) == set()


def test_package_module_alias_resolves(tmp_path):
    core = {"pkg/__init__.py": "", "pkg/sub.py": "x = 1\n"}
    tests = ("from pkg import sub\nfrom unittest.mock import patch\n"
             "def test_a():\n    patch.object(sub, 'x')\n")
    assert _run(tmp_path, core, {"test_a.py": tests}) == {("test_a.py", 1, "pkg.sub", "x")}


def test_the_real_tree_matches_the_ratchet():
    got = findings(CORE_DIR, TESTS_DIR)
    new = sorted(got - PATCH_RATCHET)
    stale = sorted(PATCH_RATCHET - got)
    assert not new, f"patches that reach no lookup: {new}"
    assert not stale, f"delete these from PATCH_RATCHET, they no longer occur: {stale}"


def _print_ratchet() -> None:
    print("PATCH_RATCHET: frozenset[tuple[str, int, str, str]] = frozenset({")
    for row in sorted(findings(CORE_DIR, TESTS_DIR)):
        print(f"    {row!r},")
    print("})")


if __name__ == "__main__":
    if "--print-ratchet" in sys.argv:
        _print_ratchet()
    else:
        sys.exit("usage: test_patch_reach.py --print-ratchet")
