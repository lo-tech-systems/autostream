"""tests/test_layering.py

Import layering of the application modules, checked on the syntax tree only
(no production module is imported).

Every module under core/ sits in one layer.  A module may import its own layer
or a lower one; the web layer (L3) is further limited to a named set of
modules and names; L4 may import anything.  There is no list of tolerated
violations: any violation fails.  An edge that is allowed on purpose is a row
of EXCEPTIONS, and a dynamic lookup that is allowed on purpose is a row of
DYNAMIC_LOOKUPS, each with its reason.
"""
from __future__ import annotations

import ast
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

CORE_DIR = Path(__file__).resolve().parent.parent / "core"

ORDER = ["L0", "L1a", "L1b", "L2", "L3", "L4"]

_L0 = """
align_tone appliance_identity artwork auth backend_events bluetooth_client
bluetooth_facts bluetooth_presentation commissioning config debounce dial_gpio dials eq_bands
federation licensing logging mdns monitor_client nowplaying
owntone owntone_mini pin_pairing playback_stats player_service players protocol rpi
runtime runtime_state settings settings_schema start_buffer_cache system_stats
sysutils watcher_client wifi_network
""".split()
_L2 = "align announce appliance_state appliances audio_monitor dial_push dial_warnings identification input_status live_config log_policy monitor_control output_intents output_policy output_usage playback_tracking repeat selfheal services session startup warnings".split()

LAYERS: dict[str, str] = {
    **{f"autostream_{n}": "L0" for n in _L0},
    "track_id": "L0",
    "autostream_state": "L1a",
    "autostream_intents": "L1b",
    **{f"autostream_{n}": "L2" for n in _L2},
    "webui": "L3",
    "autostream_core": "L4",
    "autostream_webui": "L4",
}

# (importer, imported) -> reason the edge is allowed although a rule forbids it.
EXCEPTIONS: dict[tuple[str, str], str] = {}

# (file, function) -> reason a web module may look a module up by a name that
# is not a constant (rule G).
DYNAMIC_LOOKUPS: dict[tuple[str, str], str] = {
    ("webui/routes.py", "_resolve_handler"): "resolves the route table's handler strings",
}

# Allowed L2-to-L2 imports (importer, imported).  Must stay acyclic.
L2_EDGES: frozenset[tuple[str, str]] = frozenset({
    ("autostream_repeat", "autostream_session"),
    ("autostream_repeat", "autostream_announce"),
    ("autostream_monitor_control", "autostream_repeat"),
    ("autostream_audio_monitor", "autostream_selfheal"),
    ("autostream_selfheal", "autostream_session"),
    ("autostream_live_config", "autostream_monitor_control"),
    ("autostream_live_config", "autostream_session"),
    ("autostream_live_config", "autostream_appliances"),
    ("autostream_live_config", "autostream_playback_tracking"),
    ("autostream_live_config", "autostream_input_status"),
    ("autostream_live_config", "autostream_identification"),
    ("autostream_identification", "autostream_audio_monitor"),
    ("autostream_startup", "autostream_audio_monitor"),
    ("autostream_startup", "autostream_monitor_control"),
    ("autostream_startup", "autostream_playback_tracking"),
    ("autostream_startup", "autostream_input_status"),
    ("autostream_services", "autostream_appliances"),
    ("autostream_services", "autostream_appliance_state"),
    ("autostream_appliance_state", "autostream_dial_push"),
    ("autostream_appliance_state", "autostream_warnings"),
    ("autostream_services", "autostream_dial_warnings"),
    ("autostream_services", "autostream_output_usage"),
    ("autostream_dial_warnings", "autostream_dial_push"),
    ("autostream_output_intents", "autostream_output_usage"),
    ("autostream_playback_tracking", "autostream_dial_warnings"),
})

# What an L3 module may import, besides the standard library, other L3 modules
# and the public names of the state and intents packages.  "*" allows the whole
# module; DENIED_FOR_WEBUI removes names from a "*".
ALLOWED_FOR_WEBUI: dict[str, frozenset[str]] = {
    "autostream_config": frozenset({"*"}),
    "autostream_settings": frozenset({"SettingsView", "as_view"}),
    "autostream_settings_schema": frozenset({"*"}),
    "autostream_auth": frozenset({"*"}),
    "autostream_commissioning": frozenset({"*"}),
    "autostream_dials": frozenset({"*"}),
    "autostream_protocol": frozenset({"*"}),
    "autostream_federation": frozenset({"*"}),
    "autostream_sysutils": frozenset({"*"}),
    "autostream_debounce": frozenset({"*"}),
    "autostream_rpi": frozenset({"*"}),
    "autostream_bluetooth_client": frozenset({"*"}),
    "autostream_logging": frozenset({"*"}),
    "autostream_eq_bands": frozenset({"OUTPUT_EQ_DB_MIN", "OUTPUT_EQ_DB_MAX", "OUTPUT_PEQ_BANDS"}),
    # Setting keys and their bounds, and two pure mappings: constants and
    # functions with no coordinator state.
    "autostream_players": frozenset({
        "SETTING_START_BUFFER_MS", "SETTING_START_BUFFER_MS_DEFAULT",
        "SETTING_START_BUFFER_MS_MIN", "SETTING_START_BUFFER_MS_MAX",
        "SETTING_START_BUFFER_MS_STEP", "SETTING_USER_AGENT",
        "SETTING_USER_AGENT_MAX_LEN", "SETTING_UNCOMPRESSED_ALAC",
        "SETTING_BUFFERED_AUDIO_ENABLED",
        "SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MIN_MINUTES",
        "SETTING_DEVICE_REMOVAL_GRACE_PERIOD_MAX_MINUTES",
        "SETTING_DEVICE_REMOVAL_GRACE_PERIOD_DEFAULT_MINUTES",
    }),
    "autostream_player_service": frozenset({
        "config_airplay_mode_to_backend", "output_supported_config_modes",
    }),
    "autostream_watcher_client": frozenset({"*"}),
    "track_id.models": frozenset({"*"}),
    "autostream_playback_stats": frozenset({
        "InputPlaybackSnapshot",
        "make_fallback_input_snapshot", "format_hours",
    }),
    "autostream_appliances": frozenset({
        "get_all_appliances", "get_appliance_sighting", "get_conflict_ids",
        "scanner_ready", "grace_remaining_ms", "ApplianceSighting",
    }),
    "autostream_pin_pairing": frozenset({"PIN_RE", "REQUESTER_WEBUI", "dial_requester"}),
    "autostream_align": frozenset({
        "parse_result_entries", "AlignArrival",
    }),
}
DENIED_FOR_WEBUI: dict[str, frozenset[str]] = {
    "autostream_config": frozenset({"load_config", "locked_load_config"}),
}
# Names of autostream_state.live an L3 module may use.
LIVE_PINNED: frozenset[str] = frozenset({
    "get_live_output_eq_status", "get_live_monitor_output_rate",
    "get_setting", "get_capabilities", "list_outputs",
    "get_owntone_runtime_info", "get_vibra_runtime_info",
    "annotate_outputs", "get_log_level_state",
    "get_align_status", "get_align_review",
    "start_buffer_ms", "pin_claim", "current_warnings", "warnings_payload", "state_refresh",
})

# Packages whose public names (from __all__) an L3 module may import.
_PUBLIC_PACKAGES = ("autostream_state", "autostream_intents")
_LIVE_MODULE = "autostream_state.live"


@dataclass(frozen=True)
class Rules:
    layers: dict = field(default_factory=lambda: LAYERS)
    exceptions: dict = field(default_factory=lambda: EXCEPTIONS)
    l2_edges: frozenset = L2_EDGES
    allowed: dict = field(default_factory=lambda: ALLOWED_FOR_WEBUI)
    denied: dict = field(default_factory=lambda: DENIED_FOR_WEBUI)
    live_pinned: frozenset = LIVE_PINNED
    dynamic_lookups: dict = field(default_factory=lambda: DYNAMIC_LOOKUPS)


RULES = Rules()


@dataclass(frozen=True)
class Edge:
    importer: str      # core module name (a package counts as one module)
    path: str          # file, relative to the core root, posix form
    module: str        # imported module, dotted
    name: str          # imported name, or "*" for a whole module
    line: int


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def module_files(root: Path) -> dict[str, list[Path]]:
    """Map each core module name to its files (a package is one module)."""
    out: dict[str, list[Path]] = {}
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root)
        if "__pycache__" in rel.parts:
            continue
        top = rel.parts[0][:-3] if len(rel.parts) == 1 else rel.parts[0]
        out.setdefault(top, []).append(path)
    return out


def _package_modules(root: Path, package: str) -> set[str]:
    pkg = root / package
    if not pkg.is_dir():
        return set()
    return {p.stem for p in pkg.glob("*.py") if p.stem != "__init__"}


def _dynamic_import_target(node: ast.Call) -> str | None:
    func = node.func
    is_dynamic = (
        (isinstance(func, ast.Attribute) and func.attr == "import_module"
         and isinstance(func.value, ast.Name) and func.value.id == "importlib")
        or (isinstance(func, ast.Name) and func.id in ("import_module", "__import__"))
    )
    if not is_dynamic or not node.args:
        return None
    arg = node.args[0]
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    return None


def scan_file(importer: str, rel: str, tree: ast.AST, packages: dict[str, set[str]],
              exported: dict[str, frozenset[str]] | None = None):
    """Return the import edges of one parsed file and the lines of its `.claim(` calls.

    A name a package lists in its ``__all__`` is that package's own public name
    even when a submodule has the same name (``from pkg import store``)."""
    exported = exported or {}
    edges: list[Edge] = []
    claims: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                edges.append(Edge(importer, rel, alias.name, "*", node.lineno))
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                continue  # relative: stays inside the package
            mod = node.module or ""
            for alias in node.names:
                top = mod.split(".")[0]
                if (mod == top and alias.name in packages.get(top, ())
                        and alias.name not in exported.get(top, ())):
                    edges.append(Edge(importer, rel, f"{mod}.{alias.name}", "*", node.lineno))
                else:
                    edges.append(Edge(importer, rel, mod, alias.name, node.lineno))
        elif isinstance(node, ast.Call):
            target = _dynamic_import_target(node)
            if target:
                edges.append(Edge(importer, rel, target, "*", node.lineno))
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "claim":
                claims.append(node.lineno)
    return edges, claims


def _is_sys_modules(node: ast.AST) -> bool:
    return (isinstance(node, ast.Attribute) and node.attr == "modules"
            and isinstance(node.value, ast.Name) and node.value.id == "sys")


def _is_constant_str(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


class _DynamicLookups(ast.NodeVisitor):
    """The places that look a module up by a name that is not a constant:
    ``importlib.import_module(x)``, ``__import__(x)``, ``sys.modules[x]`` and
    ``sys.modules.get(x)``.  Each is recorded with its enclosing function."""

    def __init__(self) -> None:
        self.found: list[tuple[str, int]] = []
        self._scope: list[str] = []

    def _visit_scope(self, node) -> None:
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _visit_scope

    def _note(self, node: ast.AST) -> None:
        self.found.append((self._scope[0] if self._scope else "<module>", node.lineno))

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        dynamic_import = (
            (isinstance(func, ast.Attribute) and func.attr == "import_module"
             and isinstance(func.value, ast.Name) and func.value.id == "importlib")
            or (isinstance(func, ast.Name) and func.id in ("import_module", "__import__"))
        )
        if dynamic_import and node.args and not _is_constant_str(node.args[0]):
            self._note(node)
        elif (isinstance(func, ast.Attribute) and func.attr == "get" and _is_sys_modules(func.value)
              and node.args and not _is_constant_str(node.args[0])):
            self._note(node)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if _is_sys_modules(node.value) and not _is_constant_str(node.slice):
            self._note(node)
        self.generic_visit(node)


def dynamic_lookups(root: Path):
    """Return (importer, path, enclosing function, line) for every non-constant
    dynamic module lookup under *root*."""
    out: list[tuple[str, str, str, int]] = []
    for importer, paths in module_files(root).items():
        for path in paths:
            visitor = _DynamicLookups()
            visitor.visit(ast.parse(path.read_text(encoding="utf-8"), filename=str(path)))
            rel = path.relative_to(root).as_posix()
            out.extend((importer, rel, func, line) for func, line in visitor.found)
    return out


def scan(root: Path):
    """Return (module names, edges, claim sites as (importer, path, line))."""
    files = module_files(root)
    packages = {name: _package_modules(root, name) for name in files if (root / name).is_dir()}
    exported = {name: _all_names(root, name) for name in packages}
    edges: list[Edge] = []
    claims: list[tuple[str, str, int]] = []
    for importer, paths in files.items():
        for path in paths:
            rel = path.relative_to(root).as_posix()
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            file_edges, file_claims = scan_file(importer, rel, tree, packages, exported)
            for e in file_edges:
                if e.module.split(".")[0] == importer:
                    continue  # a package importing itself
                edges.append(e)
            claims.extend((importer, rel, ln) for ln in file_claims)
    return set(files), edges, claims


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def _all_names(root: Path, package: str) -> frozenset[str]:
    init = root / package / "__init__.py"
    if not init.is_file():
        return frozenset()
    for node in ast.parse(init.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets
        ):
            try:
                return frozenset(ast.literal_eval(node.value))
            except ValueError:
                return frozenset()
    return frozenset()


def _l3_may_import(rules: Rules, root: Path, e: Edge) -> bool:
    mod = e.module
    top = mod.split(".")[0]
    if mod == _LIVE_MODULE:
        return e.name in rules.live_pinned
    if mod == top and top in _PUBLIC_PACKAGES:
        return e.name in _all_names(root, top)
    for key in (mod, top):
        allowed = rules.allowed.get(key)
        if allowed is None:
            continue
        denied = rules.denied.get(key, frozenset())
        if e.name == "*":
            # `import m` counts as every name of m.
            return "*" in allowed and not denied
        if e.name in denied:
            return False
        return "*" in allowed or e.name in allowed
    return False


def violations(root: Path, rules: Rules = RULES) -> set[tuple[str, str, str, str]]:
    """Return (rule letter, importer, imported module, name) for every violation."""
    modules, edges, claims = scan(root)
    unknown = sorted(m for m in modules if m not in rules.layers)
    if unknown:
        raise KeyError(f"module missing from LAYERS: {', '.join(unknown)}")
    found: set[tuple[str, str, str, str]] = set()
    for e in edges:
        top = e.module.split(".")[0]
        importer_layer = rules.layers[e.importer]
        if top == "subprocess":
            if importer_layer == "L3" and not e.path.startswith("webui/system/"):
                found.add(("D", e.importer, e.module, e.name))
        if top not in rules.layers:
            continue
        if (e.importer, top) in rules.exceptions:
            continue
        target_layer = rules.layers[top]
        up = ORDER.index(target_layer) > ORDER.index(importer_layer)
        if importer_layer != "L4" and up:
            found.add(("A", e.importer, e.module, e.name))
        if (importer_layer == "L2" and target_layer == "L2"
                and (e.importer, top) not in rules.l2_edges):
            found.add(("B", e.importer, e.module, e.name))
        if importer_layer == "L3" and target_layer != "L3" and not up:
            if not _l3_may_import(rules, root, e):
                found.add(("C", e.importer, e.module, e.name))
        if target_layer == "L3" and importer_layer not in ("L3", "L4"):
            found.add(("E", e.importer, e.module, e.name))
    for importer, _path, _line in claims:
        if rules.layers[importer] == "L3":
            found.add(("F", importer, ".claim()", "*"))
    for importer, path, func, _line in dynamic_lookups(root):
        if rules.layers[importer] == "L3" and (path, func) not in rules.dynamic_lookups:
            found.add(("G", importer, path, func))
    return found


def l2_cycle(edges) -> list[str] | None:
    graph: dict[str, set[str]] = {}
    for a, b in edges:
        graph.setdefault(a, set()).add(b)
    state: dict[str, int] = {}
    stack: list[str] = []

    def visit(n: str):
        state[n] = 1
        stack.append(n)
        for m in sorted(graph.get(n, ())):
            if state.get(m) == 1:
                return stack[stack.index(m):] + [m]
            if m not in state:
                cyc = visit(m)
                if cyc:
                    return cyc
        stack.pop()
        state[n] = 2
        return None

    for n in sorted(graph):
        if n not in state:
            cyc = visit(n)
            if cyc:
                return cyc
    return None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def _rules(layers: dict[str, str], **kw) -> Rules:
    base = dict(exceptions={}, l2_edges=frozenset(), allowed={}, denied={},
                live_pinned=frozenset(), dynamic_lookups={})
    base.update(kw)
    return Rules(layers=layers, **base)


def test_unknown_module_fails(tmp_path):
    _write(tmp_path, {"a.py": "", "b.py": ""})
    with pytest.raises(KeyError, match="b"):
        violations(tmp_path, _rules({"a": "L0"}))


def test_layers_cover_the_tree():
    modules = set(module_files(CORE_DIR))
    assert modules == set(LAYERS), (
        f"missing from LAYERS: {sorted(modules - set(LAYERS))}; "
        f"stale in LAYERS: {sorted(set(LAYERS) - modules)}"
    )


def test_rule_a_upward_import_is_flagged_and_downward_is_not(tmp_path):
    _write(tmp_path, {
        "low.py": "import high\n",
        "high.py": "import low\nfrom low import thing\n",
    })
    got = violations(tmp_path, _rules({"low": "L0", "high": "L3"}))
    assert ("A", "low", "high", "*") in got
    assert not any(v[1] == "high" and v[0] == "A" for v in got)


def test_rule_a_covers_function_local_and_dynamic_imports(tmp_path):
    _write(tmp_path, {
        "low.py": (
            "def f():\n    from high import x\n"
            "def g():\n    import importlib\n    importlib.import_module('high')\n"
            "def h():\n    __import__('high')\n"
        ),
        "high.py": "",
    })
    got = violations(tmp_path, _rules({"low": "L0", "high": "L2"}))
    assert ("A", "low", "high", "x") in got
    assert ("A", "low", "high", "*") in got


def test_l4_may_import_anything(tmp_path):
    _write(tmp_path, {"top.py": "import low\nimport mid\n", "low.py": "", "mid.py": ""})
    assert violations(tmp_path, _rules({"top": "L4", "low": "L0", "mid": "L3"})) == set()


def test_exception_allows_an_edge(tmp_path):
    _write(tmp_path, {"low.py": "import high\n", "high.py": ""})
    rules = _rules({"low": "L0", "high": "L2"}, exceptions={("low", "high"): "why"})
    assert violations(tmp_path, rules) == set()


def test_rule_b_l2_import_needs_a_listed_edge(tmp_path):
    _write(tmp_path, {"a.py": "import b\n", "b.py": "import c\n", "c.py": ""})
    rules = _rules({"a": "L2", "b": "L2", "c": "L2"}, l2_edges=frozenset({("a", "b")}))
    assert violations(tmp_path, rules) == {("B", "b", "c", "*")}


def test_l2_edges_are_acyclic():
    assert l2_cycle(L2_EDGES) is None


def test_cycle_detector_finds_a_cycle():
    assert l2_cycle({("a", "b"), ("b", "c"), ("c", "a")})
    assert l2_cycle({("a", "b"), ("b", "c")}) is None


def test_rule_c_l3_import_needs_an_allowed_name(tmp_path):
    _write(tmp_path, {
        "web.py": (
            "import os\n"
            "from cfg import load_config, other\n"
            "from sett import SettingsView, SettingsStore\n"
            "import dev\n"
            "from sibling import q\n"
        ),
        "sibling.py": "", "cfg.py": "", "sett.py": "", "dev.py": "",
    })
    rules = _rules(
        {"web": "L3", "sibling": "L3", "cfg": "L0", "sett": "L0", "dev": "L0"},
        allowed={"cfg": frozenset({"*"}), "sett": frozenset({"SettingsView"})},
        denied={"cfg": frozenset({"load_config"})},
    )
    assert violations(tmp_path, rules) == {
        ("C", "web", "cfg", "load_config"),
        ("C", "web", "sett", "SettingsStore"),
        ("C", "web", "dev", "*"),
    }


def test_rule_c_whole_module_import_counts_as_every_name(tmp_path):
    _write(tmp_path, {"web.py": "import cfg\n", "cfg.py": ""})
    rules = _rules({"web": "L3", "cfg": "L0"}, allowed={"cfg": frozenset({"*"})},
                   denied={"cfg": frozenset({"secret"})})
    assert violations(tmp_path, rules) == {("C", "web", "cfg", "*")}


def test_rule_c_public_names_of_a_package_are_allowed(tmp_path):
    _write(tmp_path, {
        "web.py": "from autostream_state import Public, Private\n",
        "autostream_state/__init__.py": "__all__ = ['Public']\n",
    })
    got = violations(tmp_path, _rules({"web": "L3", "autostream_state": "L1a"}))
    assert got == {("C", "web", "autostream_state", "Private")}


def test_rule_c_live_module_names_must_be_pinned(tmp_path):
    _write(tmp_path, {
        "web.py": "from autostream_state.live import ok, bad\n",
        "autostream_state/__init__.py": "", "autostream_state/live.py": "",
    })
    got = violations(tmp_path, _rules({"web": "L3", "autostream_state": "L1a"},
                                      live_pinned=frozenset({"ok"})))
    assert got == {("C", "web", "autostream_state.live", "bad")}


def test_rule_d_subprocess_in_an_l3_module(tmp_path):
    _write(tmp_path, {"web.py": "import subprocess\nfrom subprocess import run\n",
                      "low.py": "import subprocess\n"})
    got = violations(tmp_path, _rules({"web": "L3", "low": "L0"}))
    assert got == {("D", "web", "subprocess", "*"), ("D", "web", "subprocess", "run")}


def test_rule_e_only_l3_and_l4_import_l3(tmp_path):
    _write(tmp_path, {"mid.py": "import web\n", "top.py": "import web\n", "web.py": ""})
    got = violations(tmp_path, _rules({"mid": "L2", "top": "L4", "web": "L3"}))
    assert ("E", "mid", "web", "*") in got
    assert not any(v[1] == "top" for v in got)


def test_rule_f_claim_call_in_an_l3_module(tmp_path):
    _write(tmp_path, {"web.py": "def f(p):\n    p.claim(1)\n",
                      "low.py": "def f(p):\n    p.claim(1)\n"})
    got = violations(tmp_path, _rules({"web": "L3", "low": "L0"}))
    assert got == {("F", "web", ".claim()", "*")}


def test_package_submodule_from_import_resolves_to_the_submodule(tmp_path):
    _write(tmp_path, {
        "web.py": "from pkg import models\n",
        "pkg/__init__.py": "", "pkg/models.py": "",
    })
    rules = _rules({"web": "L3", "pkg": "L0"}, allowed={"pkg.models": frozenset({"*"})})
    assert violations(tmp_path, rules) == set()


def test_a_name_in_a_packages_all_is_not_taken_for_its_submodule(tmp_path):
    _write(tmp_path, {
        "web.py": "from autostream_state import store\n",
        "autostream_state/__init__.py": "from .store import store\n__all__ = ['store']\n",
        "autostream_state/store.py": "",
    })
    rules = _rules({"web": "L3", "autostream_state": "L1a"})
    assert violations(tmp_path, rules) == set()


def test_rule_g_non_constant_dynamic_lookups_in_an_l3_module(tmp_path):
    _write(tmp_path, {
        "web.py": (
            "import importlib\nimport sys\n"
            "def a(n):\n    return importlib.import_module(n)\n"
            "def b(n):\n    return __import__(n)\n"
            "def c(n):\n    return sys.modules[n]\n"
            "def d(n):\n    return sys.modules.get(n)\n"
            "def ok():\n    importlib.import_module('json')\n    return sys.modules['json'], sys.modules.get('json')\n"
        ),
        "low.py": "import sys\ndef f(n):\n    return sys.modules[n]\n",
    })
    layers = {"web": "L3", "low": "L0"}
    got = violations(tmp_path, _rules(layers))
    assert got == {("G", "web", "web.py", fn) for fn in "abcd"}


def test_rule_g_a_listed_function_is_allowed_and_nothing_else_in_its_file(tmp_path):
    _write(tmp_path, {
        "web.py": (
            "import sys\n"
            "def resolve(n):\n    return sys.modules[n]\n"
            "def other(n):\n    return sys.modules[n]\n"
        ),
    })
    rules = _rules({"web": "L3"}, dynamic_lookups={("web.py", "resolve"): "the one site"})
    assert violations(tmp_path, rules) == {("G", "web", "web.py", "other")}


def test_the_real_dynamic_lookup_table_has_no_stale_row():
    seen = {(path, func) for _importer, path, func, _line in dynamic_lookups(CORE_DIR)}
    assert set(DYNAMIC_LOOKUPS) <= seen


def test_the_real_tree_has_no_layering_violation():
    assert violations(CORE_DIR) == set()


def _web_identifiers() -> set[str]:
    names: set[str] = set()
    for path in sorted((CORE_DIR / "webui").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Attribute):
                names.add(node.attr)
            elif isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.ImportFrom):
                names.update(a.name for a in node.names)
    return names


def test_every_allowlisted_name_is_used():
    used = _web_identifiers()
    unused = sorted(
        (module, name)
        for module, names in ALLOWED_FOR_WEBUI.items()
        for name in names if name != "*" and name not in used
    )
    assert not unused, f"allowlisted but never used under core/webui: {unused}"
