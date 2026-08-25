"""Repo-wide guard: shipped/tracked files must not reference files or
labels that mean nothing outside this repository.

Scans every tracked file under the directories that ship or are exercised
in CI (core/, nginx/, system/, installer/, supervisor/, scripts/, tools/,
platform/, dial/, tests/) for three categories of stray reference:

  1. Paths into the gitignored docs/working/ tree (a local scratch area --
     anything under it is invisible to anyone who doesn't
     already have the same working tree, so a comment citing a path there
     is a broken/misleading reference for everyone else).
  2. Filenames of the shape "<number>-<slug>.md" (or a bare
     "design doc <number>" / "gap doc <number>" citation), which name
     documents that live in that same untracked tree.
  3. Tracking labels (``WP<n>[a-c]``, ``T<n>.<n>``, ``Batch <n>``) used
     as citations to something outside the repository rather than as
     product-facing terminology.

The list of the ~29 pre-existing ``test_wp*.py`` / ``test_p*.py`` files is
grandfathered out of the *filename* check and the identifier-content check
(they predate this guard and are named after an older, unrelated
numbering), but their contents are still scanned for docs/working paths
and numbered-doc citations, since neither of those is ever legitimate in a
shipped file regardless of age.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent

SCAN_DIRS = (
    "core", "nginx", "system", "installer", "supervisor",
    "scripts", "tools", "platform", "dial", "tests",
)

# Text-like extensions worth scanning. Binary/asset files are skipped.
TEXT_SUFFIXES = {
    ".py", ".js", ".sh", ".service", ".conf", ".ini", ".cfg", ".css",
    ".html", ".md", ".txt", ".json", ".yml", ".yaml", ".timer",
}

_WP_FILENAME_RE = re.compile(r"^test_(wp|p)\d", re.IGNORECASE)

_DOCS_WORKING_RE = re.compile(r"docs/working/\S")
_DESIGN_DOC_FILENAME_RE = re.compile(r"\b\d{1,3}-[a-zA-Z][\w\-]*\.md\b")
# Matches numbered AND unnumbered citations ("design doc 13", "the design
# doc's section 6", "gap doc", "gap 35"): a non-repository document is being
# cited either way, and the unnumbered form slipped past an earlier,
# digit-requiring version of this pattern.
_DESIGN_DOC_CITATION_RE = re.compile(
    r"\b(?:design|gap)\s+doc(?:ument)?s?\b|\bgap\s+\d+\b", re.IGNORECASE
)
_WP_ID_RE = re.compile(r"\bWP\d+[a-c]?\b")
_T_NUMBER_RE = re.compile(r"\bT[1-4]\.\d+\b")
_BATCH_ID_RE = re.compile(r"\bBatch\s+\d+\b")

# (pattern, category, always_checked_even_for_grandfathered_files)
_CHECKS = (
    (_DOCS_WORKING_RE, "docs/working/ path", True),
    (_DESIGN_DOC_FILENAME_RE, "numbered-doc filename", True),
    (_DESIGN_DOC_CITATION_RE, "numbered-doc citation", True),
    (_WP_ID_RE, "tracking label", False),
    (_T_NUMBER_RE, "tier/task identifier", False),
    (_BATCH_ID_RE, "batch identifier", False),
)


_WALK_SKIP_PARTS = {"__pycache__", ".git", ".pytest_cache", "node_modules"}


def _tracked_files():
    """Relative paths of the files to scan.

    Prefers ``git ls-files`` so local scratch files are ignored, but falls
    back to walking the scan directories when git cannot answer: the repo may
    be a worktree whose .git pointer the running git cannot resolve (a
    Windows-created worktree read from a POSIX environment), or an extracted
    release tarball with no git metadata at all. The guard must still run in
    those environments -- silently scanning nothing would turn it into a test
    that always passes.
    """
    try:
        out = subprocess.run(
            ["git", "ls-files", *SCAN_DIRS],
            cwd=str(REPO_ROOT), capture_output=True, text=True, check=True,
        )
        files = [line for line in out.stdout.splitlines() if line.strip()]
        if files:
            return files
    except (OSError, subprocess.SubprocessError):
        pass

    files = []
    for scan_dir in SCAN_DIRS:
        root = REPO_ROOT / scan_dir
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.is_file() and not (_WALK_SKIP_PARTS & set(path.parts)):
                files.append(path.relative_to(REPO_ROOT).as_posix())
    return files


def _is_grandfathered(rel_path: str) -> bool:
    name = Path(rel_path).name
    return bool(_WP_FILENAME_RE.match(name)) and rel_path.startswith("tests/")


class TestNoInternalDocReferences:
    def test_no_gitignored_or_stray_references_in_shipped_files(self):
        tracked = _tracked_files()
        assert tracked, "git ls-files returned nothing -- scan globs are wrong"

        violations = []
        this_file = Path(__file__).name

        for rel_path in tracked:
            if Path(rel_path).name == this_file:
                continue  # this guard's own docstring/patterns are not a leak
            path = REPO_ROOT / rel_path
            if path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="strict")
            except (UnicodeDecodeError, OSError):
                continue

            grandfathered = _is_grandfathered(rel_path)
            lines = text.splitlines()
            for pattern, category, always in _CHECKS:
                if grandfathered and not always:
                    continue
                for lineno, line in enumerate(lines, start=1):
                    m = pattern.search(line)
                    if m:
                        violations.append(
                            f"{rel_path}:{lineno}: {category}: {m.group(0)!r}"
                        )

        assert not violations, (
            "Stray local-only references found in tracked/shipped files "
            "(docs/working/ paths, numbered-doc filenames or citations, and "
            "WP/tier/batch identifiers must not appear outside the "
            "gitignored local tree):\n" + "\n".join(sorted(violations))
        )

    def test_grandfathered_filename_set_is_still_test_only(self):
        """Sanity check on the grandfather rule itself: every filename it
        matches must live under tests/ -- if a shipped non-test file were
        ever named test_wp*/test_p*, this would silently widen the
        exemption to a shipped path, which is not the intent."""
        for rel_path in _tracked_files():
            if _WP_FILENAME_RE.match(Path(rel_path).name):
                assert rel_path.startswith("tests/"), (
                    f"{rel_path} matches the grandfathered WP/P filename "
                    f"pattern but is not under tests/ -- narrow the pattern"
                )
