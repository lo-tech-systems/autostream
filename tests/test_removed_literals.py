"""Guard: paths and settings keys that have been removed must not come back.

A literal matches only as a whole quoted string, quote to quote, so
``"/api/output"`` does not match ``"/api/output_eq/reset"``. The test fails on
a route row that names a removed path with a removed method, and on a removed
literal quoted anywhere in the shipped code (core, dial, nginx/static,
supervisor and system). Tests and docs are exempt.

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
)

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
)

SCAN = ("core", "dial", "nginx/static", "supervisor", "system")
SUFFIXES = {".py", ".js", ".css", ".html", ".conf", ".service", ".sh", ""}


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
