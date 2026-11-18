"""The shared source-text reader finds core modules by import name."""
from __future__ import annotations

import pytest

import _source_text


def test_core_text_contains_the_monitor_client():
    assert "class MonitorClient" in _source_text.core_text()


def test_core_sources_are_sorted_and_skip_bytecode():
    names = list(_source_text.core_sources())
    assert names == sorted(names)
    assert "autostream_core.py" in names
    assert not any("__pycache__" in n for n in names)


def test_module_text_reads_one_module():
    text = _source_text.module_text("autostream_webui_page_setup")
    assert text == _source_text.module_path("autostream_webui_page_setup").read_text(encoding="utf-8")


def test_module_text_reads_a_package_module():
    assert _source_text.module_path("track_id.models").name == "models.py"


def test_module_text_unknown_name_raises():
    with pytest.raises(KeyError):
        _source_text.module_text("autostream_no_such_module")
