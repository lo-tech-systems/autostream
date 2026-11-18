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


_PAGE = (
    "<html><head>"
    '<link rel="stylesheet" href="/static/theme.css?v=0123abcd45">'
    '<script type="application/json" id="page-data">{"a":1,"b":"x"}</script>'
    '<script src="/static/poll.js?v=0123abcd45"></script>'
    "<script>var inline_one = 1;</script>"
    "</head><body>"
    "<script src='/static/render_fragments.js'></script>"
    "<script>var inline_two = 2;</script>"
    "</body></html>"
)


def test_static_text_reads_a_served_file():
    assert "Poller" in _source_text.static_text("poll.js")


def test_linked_static_lists_scripts_and_styles_in_document_order():
    assert _source_text.linked_static(_PAGE) == [
        "theme.css", "poll.js", "render_fragments.js"]


def test_page_scripts_joins_inline_bodies_and_linked_files_in_order():
    text = _source_text.page_scripts(_PAGE)
    positions = [
        text.index("inline_one"),
        text.index(_source_text.static_text("render_fragments.js")[:40]),
        text.index("inline_two"),
    ]
    assert text.index(_source_text.static_text("poll.js")[:40]) < positions[0]
    assert positions == sorted(positions)
    assert '"a":1' not in text


def test_page_data_parses_the_island_and_defaults_to_empty():
    assert _source_text.page_data(_PAGE) == {"a": 1, "b": "x"}
    assert _source_text.page_data("<html></html>") == {}


def test_page_with_static_appends_the_linked_files_but_not_the_theme():
    text = _source_text.page_with_static(_PAGE)
    assert text.startswith(_PAGE)
    assert _source_text.static_text("poll.js")[:40] in text
    assert _source_text.static_text("render_fragments.js")[:40] in text
    assert _source_text.static_text("theme.css")[:40] not in text
