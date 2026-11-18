"""Helpers shared by the display's test files: fake backends, display builders and
frame comparisons that more than one of them use.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

Image = pytest.importorskip("PIL.Image", reason="Pillow not installed")

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
_CORE = str(REPO_ROOT / "core")
for _p in (_DIAL, _CORE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from dial_network import NetworkView


def _view(link, bars=0):
    return NetworkView(link=link, device_state="", bars=bars, updated_at=1.0)


def _fold(display):
    with display._lock:
        display._repaint_current_locked()
