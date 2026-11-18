"""Guard: paths and settings keys that have been removed must not come back.

A literal matches only as a whole quoted string, quote to quote, so
``"/api/output"`` does not match ``"/api/output_eq/reset"``. The test fails on
a route row that names a removed path with a removed method, and on a removed
literal quoted anywhere in the shipped code (core, dial, nginx/static,
supervisor and system). Tests and docs are exempt from the literals.

Removed modules are checked in the tests as well: an import of one, or a
patch target string that names one, fails.

The page paths ``/setup`` and ``/owntone-setup`` are still served for GET, so
only their POST rows are checked; the literals themselves are not scanned.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

import webui.routes as webui_routes

REPO_ROOT = Path(__file__).parent.parent

# Literals that must not appear quoted in shipped code.
REMOVED = (
    "/api/status",
    "/api/owntone/outputs_state",
    "/api/owntone/outputs",
    "/api/inputs/levels",
    "/api/output_eq/status",
    "/api/output",
    "/api/repeat",
    "/api/output_eq/config",
    "/api/output_eq/reset",
    "/api/input_eq",
    "/api/input_gain",
    "owntone.output_name",
    # The old gateway, federation and remote pages.
    "/api/federation/v1",
    "/api/appliances",
    "/api/audio/status",
    "webui.output_usage_poll_interval_seconds",
    "remote_home.js",
    "remote_equaliser.js",
    "home_cards.js",
    "render_fragments.js",
    "start_failure.js",
    "appliance_selector.js",
    # The dial's old protocol: its routes, the playing record and the hint
    # routes the appliance used to call on the dial.
    "/api/dial/status",
    "/api/dial/volume",
    "/api/dial/mute",
    "/api/dial/outputs",
    "/api/dial/eq",
    "/api/dial/repeat",
    "/api/dial/warnings",
    "/api/dial/capabilities",
    "_autostream-playing._tcp",
    "dial_proto",
    "/auth-changed",
    "/warnings-changed",
    "/state-changed",
    # The dial page's old appliance actions, now intents.
    "replay_start",
    "replay_restart",
    "replay_stop",
    "repeat_arm",
)

# Modules that have been removed, with what replaced them. Neither the shipped
# code nor the tests may import one or name one in a patch target.
REMOVED_MODULES = {
    "autostream_output_usage": "autostream_appliances (occupancy from the peers)",
    "autostream_federation": "the peer client library and the relay",
    "webui.peer.gateway": "webui.peer.relay",
    "webui.peer.federation": "webui.peer.relay",
    "webui.dial.api": "the client protocol",
    "autostream_announce": "autostream_session_flag",
}

# (path, method) route rows that must not exist.
REMOVED_ROUTES = (
    ("/api/status", "GET"),
    ("/api/owntone/outputs_state", "GET"),
    ("/api/owntone/outputs", "GET"),
    ("/api/inputs/levels", "GET"),
    ("/api/output_eq/status", "GET"),
    ("/api/output", "POST"),
    ("/api/repeat", "POST"),
    ("/api/output_eq/config", "POST"),
    ("/api/output_eq/reset", "POST"),
    ("/api/input_eq", "POST"),
    ("/api/input_gain", "POST"),
    ("/setup", "POST"),
    ("/owntone-setup", "POST"),
    ("/api/dial/status", "POST"),
    ("/api/dial/volume", "POST"),
    ("/api/dial/mute", "POST"),
    ("/api/dial/outputs", "POST"),
    ("/api/dial/outputs/set", "POST"),
    ("/api/dial/eq", "POST"),
    ("/api/dial/eq/set", "POST"),
    ("/api/dial/repeat", "POST"),
    ("/api/dial/repeat/arm", "POST"),
    ("/api/dial/warnings", "POST"),
    ("/api/dial/capabilities", "GET"),
)

SCAN = ("core", "dial", "nginx/static", "supervisor", "system")
SUFFIXES = {".py", ".js", ".css", ".html", ".conf", ".service", ".sh", ""}
PY_SCAN = ("core", "dial", "tests", "supervisor", "platform", "tools")


def _quoted(literal: str) -> "re.Pattern[str]":
    return re.compile(r"""(["'])%s\1""" % re.escape(literal))


def _files():
    for top in SCAN:
        for path in sorted((REPO_ROOT / top).rglob("*")):
            if (path.is_file() and path.suffix in SUFFIXES
                    and "__pycache__" not in path.parts):
                yield path


def test_no_route_row_names_a_removed_path():
    rows = {(r.path, m) for r in webui_routes.ROUTES if r.path for m in r.methods}
    assert not [row for row in REMOVED_ROUTES if row in rows]


@pytest.mark.parametrize("literal", REMOVED)
def test_no_shipped_file_quotes_a_removed_literal(literal):
    pattern = _quoted(literal)
    hits = []
    for path in _files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if pattern.search(text):
            hits.append(str(path.relative_to(REPO_ROOT)))
    assert not hits, f"{literal!r} is quoted in {hits}"


def test_a_literal_matches_only_as_a_whole_quoted_string():
    assert not _quoted("/api/output").search('"/api/output_eq/reset"')
    assert _quoted("/api/output").search("fetch('/api/output', {})")


def _module_patterns(module: str) -> "list[re.Pattern[str]]":
    name = re.escape(module)
    patterns = [
        # import X, import X as y, from X import z, from X.sub import z
        re.compile(r"^\s*(?:import|from)\s+%s(?:[.\s]|$)" % name, re.MULTILINE),
        # a quoted dotted path: a patch target or a name looked up by string
        re.compile(r"""["']%s(?:\.[\w.]*)?["']""" % name),
    ]
    if "." in module:
        package, _, leaf = module.rpartition(".")
        patterns.append(re.compile(
            r"^\s*from\s+%s\s+import\s+(?:\(\s*)?[^\n]*\b%s\b" % (re.escape(package), re.escape(leaf)),
            re.MULTILINE))
    return patterns


def _python_files():
    for top in PY_SCAN:
        for path in sorted((REPO_ROOT / top).rglob("*.py")):
            if "__pycache__" not in path.parts and path != Path(__file__):
                yield path


@pytest.mark.parametrize("module", sorted(REMOVED_MODULES))
def test_no_python_file_imports_or_patches_a_removed_module(module):
    patterns = _module_patterns(module)
    hits = []
    for path in _python_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if any(p.search(text) for p in patterns):
            hits.append(str(path.relative_to(REPO_ROOT)))
    assert not hits, f"{module} was removed; use {REMOVED_MODULES[module]}: {hits}"


def test_a_module_pattern_sees_an_import_and_a_patch_target():
    patterns = _module_patterns("webui.peer.gateway")
    assert any(p.search("import webui.peer.gateway as gw") for p in patterns)
    assert any(p.search("from webui.peer import gateway") for p in patterns)
    assert any(p.search('patch("webui.peer.gateway.send_x")') for p in patterns)
    assert not any(p.search("from webui.peer import relay") for p in patterns)
