"""tests/settings_fixtures.py

A settings view for tests that build a ``WebUIState`` and never write a
setting.  The view reads a fixed raw configuration, starts no save thread and
has no file behind it.

    state = WebUIState("c.json", "s.json", settings=fixed_view({"owntone": {...}}))
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path
from unittest.mock import MagicMock

_CORE = str(Path(__file__).resolve().parent.parent / "core")
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

from autostream_config import parse_config
from autostream_settings import SettingsView


class _FixedStore:
    """A read-only stand-in for the store behind a view."""

    generation = 0

    def __init__(self, raw: dict, config_path: str) -> None:
        self._raw = raw
        self.config_path = config_path

    def snapshot(self):
        return parse_config(copy.deepcopy(self._raw))

    def raw_snapshot(self) -> dict:
        return copy.deepcopy(self._raw)


def fixed_view(raw: dict | None = None, *, config_path: str = "dummy.json") -> SettingsView:
    """A view whose snapshot parses *raw* (an empty configuration by default)."""
    return SettingsView(_FixedStore(copy.deepcopy(raw) if raw else {}, config_path))


def viewed_state(raw: dict | None = None) -> MagicMock:
    """A mock web state whose settings are a fixed view of *raw*."""
    state = MagicMock()
    state.settings = fixed_view(raw)
    return state


# The settings of an appliance that shows other appliances and may control them.
CONTROLS_OTHER_APPLIANCES = {"webui": {"show_hostname_on_home": True, "control_other_appliances": True}}
