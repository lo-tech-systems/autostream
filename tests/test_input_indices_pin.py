"""tests/test_input_indices_pin.py

The input numbers come from one place (autostream_config's INPUT_INDICES,
WIRED_INPUT_INDICES and BLUETOOTH_INPUT_INDEX in Python; the page data's
input list and inputField() in the Setup scripts). Nothing else may pick
between input 1 and input 2 by hand or list the two inputs as literals, so
a new input is a new number, not a hunt for every copy.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CORE = REPO_ROOT / "core"
SETUP_SCRIPTS = sorted((REPO_ROOT / "nginx" / "static" / "page").glob("setup*.js"))

# Where the wired pair is defined.
_ALLOWED = {CORE / "autostream_config.py"}

_PY_PATTERNS = {
    "a choice between audio1 and audio2": re.compile(r"\baudio1\b[^\n]*\belse\b[^\n]*\baudio2\b"),
    "a choice between the two enables": re.compile(r"audio1_enabled\b[^\n]*\belse\b[^\n]*audio2_enabled"),
    "the two inputs as a literal pair": re.compile(r"(?:\bin|choice\(|\bfor\s+\w+\s+in)\s*\(?\s*1,\s*2\s*\)"),
}

_JS_PATTERNS = {
    "the two inputs as a literal list": re.compile(r"\[\s*1\s*,\s*2\s*\]"),
    "a choice between input 1 and input 2": re.compile(r"===\s*1\s*\?\s*'audio"),
}


def _python_sources():
    return [p for p in CORE.rglob("*.py") if "__pycache__" not in p.parts and p not in _ALLOWED]


@pytest.mark.parametrize("what", sorted(_PY_PATTERNS))
def test_python_names_no_input_pair_by_hand(what):
    pattern = _PY_PATTERNS[what]
    hits = [
        f"{path.relative_to(REPO_ROOT)}:{n}"
        for path in _python_sources()
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if pattern.search(line) and not line.lstrip().startswith("#")
    ]
    assert hits == [], f"{what}: {hits}"


@pytest.mark.parametrize("what", sorted(_JS_PATTERNS))
def test_setup_scripts_name_no_input_pair_by_hand(what):
    pattern = _JS_PATTERNS[what]
    hits = [
        f"{path.name}:{n}"
        for path in SETUP_SCRIPTS
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if pattern.search(line)
    ]
    assert hits == [], f"{what}: {hits}"


def test_the_scan_finds_the_sources():
    assert len(_python_sources()) > 50
    assert len(SETUP_SCRIPTS) >= 4
