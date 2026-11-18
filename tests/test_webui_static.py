"""URLs and text of the files nginx serves under /static/."""
from __future__ import annotations

import hashlib
import json
import logging
import re
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))

import webui.static as webui_static  # noqa: E402


@pytest.fixture
def root(tmp_path, monkeypatch):
    """A scratch static root with one script, used in place of the real one."""
    (tmp_path / "page").mkdir()
    (tmp_path / "page" / "home.js").write_bytes(b"var x = 1;\n")
    monkeypatch.setattr(webui_static, "static_root", lambda: tmp_path)
    webui_static.reset_for_tests()
    yield tmp_path
    webui_static.reset_for_tests()


def test_version_is_the_first_ten_hex_digits_of_the_files_sha256(root):
    expected = hashlib.sha256(b"var x = 1;\n").hexdigest()[:10]
    assert webui_static.asset_version("page/home.js") == expected
    assert re.fullmatch(r"[0-9a-f]{10}", expected)


def test_urls_and_tags_carry_the_version(root):
    v = webui_static.asset_version("page/home.js")
    assert webui_static.static_url("page/home.js") == f"/static/page/home.js?v={v}"
    assert webui_static.script_tag("page/home.js") == f'<script src="/static/page/home.js?v={v}"></script>'
    assert webui_static.style_tag("page/home.js") == (
        f'<link rel="stylesheet" href="/static/page/home.js?v={v}">')


def test_a_changed_file_gets_a_new_version_after_the_cache_is_cleared(root):
    before = webui_static.asset_version("page/home.js")
    (root / "page" / "home.js").write_bytes(b"var x = 2;\n")
    assert webui_static.asset_version("page/home.js") == before
    webui_static.reset_for_tests()
    assert webui_static.asset_version("page/home.js") != before


def test_the_file_is_read_once_per_process(root):
    reads = []
    real = Path.read_bytes

    def counting(self):
        reads.append(self.name)
        return real(self)

    with patch.object(Path, "read_bytes", counting):
        webui_static.asset_version("page/home.js")
        webui_static.static_url("page/home.js")
        webui_static.script_tag("page/home.js")
    assert reads == ["home.js"]


def test_a_missing_file_gives_the_application_version_and_one_warning(root, caplog):
    with patch("webui.system.updates.get_app_version", return_value="9.9.9") as get_version, \
         caplog.at_level(logging.WARNING, logger=webui_static.__name__):
        assert webui_static.asset_version("page/missing.js") == "9.9.9"
        assert webui_static.static_url("page/missing.js") == "/static/page/missing.js?v=9.9.9"
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "page/missing.js" in warnings[0].getMessage()
    get_version.assert_called_once()


@pytest.mark.parametrize("rel", ["../core/autostream_core.py", "page/../../x.js", "/etc/passwd", "", "page" + chr(92) + "x.js"])
def test_paths_outside_the_static_root_are_refused(root, rel):
    for call in (webui_static.asset_version, webui_static.static_url, webui_static.script_tag, webui_static.style_tag):
        with pytest.raises(ValueError):
            call(rel)


def test_the_island_cannot_be_ended_by_its_values():
    data = {"a": "</script><script>alert(1)</script>", "b": "<!-- x -->", "c": "a&b", "d": "café"}
    out = webui_static.page_data_island(data)
    assert out.startswith('<script type="application/json" id="page-data">')
    assert out.endswith("</script>")
    inner = out[len('<script type="application/json" id="page-data">'):-len("</script>")]
    assert "<" not in inner and ">" not in inner and "&" not in inner
    assert inner.isascii()
    assert json.loads(inner) == data


def test_the_island_keeps_key_order_and_is_compact():
    inner = webui_static.page_data_island({"z": 1, "a": [1, 2]})
    assert '{"z":1,"a":[1,2]}' in inner


def test_empty_data_emits_nothing():
    assert webui_static.page_data_island({}) == ""


def test_the_installed_layout_is_preferred(tmp_path, monkeypatch):
    (tmp_path / "nginx" / "static").mkdir(parents=True)
    monkeypatch.setattr(webui_static, "__file__", str(tmp_path / "webui" / "static.py"))
    assert webui_static.static_root() == (tmp_path / "nginx" / "static").resolve()


def test_the_source_tree_is_used_when_there_is_no_installed_layout(tmp_path, monkeypatch):
    core = tmp_path / "core"
    core.mkdir()
    monkeypatch.setattr(webui_static, "__file__", str(core / "webui" / "static.py"))
    assert webui_static.static_root() == (tmp_path / "nginx" / "static").resolve()


def test_the_real_root_holds_the_shared_files():
    assert (webui_static.static_root() / "theme.css").is_file()
    assert re.fullmatch(r"[0-9a-f]{10}", webui_static.asset_version("theme.css"))
