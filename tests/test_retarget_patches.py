"""tests/test_retarget_patches.py

The patch retarget tool rewrites each reference form, changes nothing on a
second run, refuses an alias that collides, and reports through its exit
status.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_TOOLS = str(Path(__file__).resolve().parent.parent / "tools")
if _TOOLS not in sys.path:
    sys.path.insert(0, _TOOLS)

import retarget_patches as rp  # noqa: E402

MAP = "old_mod.thing -> new_mod.thing  alias=nm\nold_mod.old_name -> new_mod.new_name  alias=nm\n"
ENTRIES = rp.parse_map(MAP)


def _run(src: str, entries=ENTRIES, check=False):
    return rp.retarget_source(src.encode("utf-8"), entries, check)


def _text(src: str, entries=ENTRIES) -> str:
    return _run(src, entries).data.decode("utf-8")


def test_parse_map_skips_comments_and_blanks():
    entries = rp.parse_map("# note\n\nold_mod.thing -> new_mod.thing  alias=nm  # trailing\n")
    assert entries == [rp.Entry("old_mod", "thing", "new_mod", "thing", "nm")]


@pytest.mark.parametrize("line", ["old_mod.thing -> new_mod.thing", "thing -> x.y alias=a", "a.b => c.d alias=e"])
def test_parse_map_rejects_bad_lines(line):
    with pytest.raises(rp.ToolError):
        rp.parse_map(line)


def test_string_target_and_prefix_are_rewritten():
    src = (
        "from unittest.mock import patch\n"
        "def test_a():\n"
        "    with patch('old_mod.thing'), patch(\"old_mod.thing.attr\", 1):\n"
        "        pass\n"
    )
    out = _text(src)
    assert "patch('new_mod.thing')" in out
    assert 'patch("new_mod.thing.attr", 1)' in out
    assert "old_mod" not in out


def test_string_with_a_longer_name_is_left_alone():
    src = "x = 'old_mod.thing_extra'\n"
    result = _run(src)
    assert result.data.decode() == src
    assert result.unhandled == []


def test_attribute_through_a_module_alias_is_rewritten_and_import_added():
    src = "import os\nimport old_mod as om\n\ndef test_a():\n    om.thing = 1\n    return om.thing\n"
    out = _text(src)
    assert "nm.thing = 1" in out
    assert "return nm.thing" in out
    assert out.splitlines()[:3] == ["import os", "import old_mod as om", "import new_mod as nm"]


def test_attribute_through_a_plain_import_and_function_level_import():
    src = "def test_a():\n    import old_mod\n    return old_mod.thing\n"
    out = _text(src)
    assert "return nm.thing" in out
    assert out.startswith("import new_mod as nm\n")


def test_import_is_added_once_and_not_when_present():
    src = "import new_mod as nm\nimport old_mod\n\nold_mod.thing\nold_mod.thing\n"
    out = _text(src)
    assert out.count("import new_mod as nm") == 1
    assert out.count("nm.thing") == 2


def test_alias_equal_to_the_new_module_uses_a_plain_import():
    entries = rp.parse_map("old_mod.thing -> new_mod.thing  alias=new_mod\n")
    out = _text("import old_mod\nold_mod.thing\n", entries)
    assert out == "import old_mod\nimport new_mod\nnew_mod.thing\n"


def test_monkeypatch_and_patch_object_forms():
    src = (
        "import old_mod\n"
        "from unittest.mock import patch\n"
        "def test_a(monkeypatch):\n"
        "    monkeypatch.setattr(old_mod, 'old_name', 1)\n"
        "    monkeypatch.delattr(old_mod, \"old_name\")\n"
        "    patch.object(old_mod, 'thing')\n"
    )
    out = _text(src)
    assert "monkeypatch.setattr(nm, 'new_name', 1)" in out
    assert 'monkeypatch.delattr(nm, "new_name")' in out
    assert "patch.object(nm, 'thing')" in out


def test_from_import_single_name_is_replaced():
    out = _text("from old_mod import thing\nthing()\n")
    assert out == "from new_mod import thing\nthing()\n"


def test_from_import_renamed_keeps_the_local_binding():
    out = _text("from old_mod import old_name\nold_name()\n")
    assert out == "from new_mod import new_name as old_name\nold_name()\n"
    out = _text("from old_mod import old_name as local\nlocal()\n")
    assert out == "from new_mod import new_name as local\nlocal()\n"


def test_from_import_keeps_the_other_names():
    out = _text("from old_mod import keep, thing, other\n")
    assert out == "from old_mod import keep, other\nfrom new_mod import thing\n"


def test_from_import_in_parentheses_stays_multiline():
    src = "from old_mod import (\n    keep,\n    thing,\n)\n"
    out = _text(src)
    assert out == "from old_mod import (\n    keep,\n)\nfrom new_mod import thing\n"


def test_from_import_inside_a_function_keeps_its_indent():
    src = "def f():\n    from old_mod import keep, thing\n    return thing\n"
    out = _text(src)
    assert "    from old_mod import keep\n    from new_mod import thing\n" in out


def test_patch_multiple_follows_when_all_names_share_a_target():
    entries = rp.parse_map("old_mod.a -> new_mod.a  alias=nm\nold_mod.b -> new_mod.bb  alias=nm\n")
    src = "from unittest.mock import patch\npatch.multiple('old_mod', a=1, b=2)\n"
    result = _run(src, entries)
    assert result.data.decode() == "from unittest.mock import patch\npatch.multiple('new_mod', a=1, bb=2)\n"
    assert result.unhandled == []


def test_patch_multiple_with_an_unmapped_name_is_reported():
    entries = rp.parse_map("old_mod.a -> new_mod.a  alias=nm\n")
    src = "from unittest.mock import patch\npatch.multiple('old_mod', a=1, other=2)\n"
    result = _run(src, entries)
    assert result.data.decode() == src
    assert [line for line, _ in result.unhandled] == [2]


def test_forms_it_cannot_rewrite_are_reported_with_a_line():
    src = (
        "import old_mod\n"
        "x = getattr(old_mod, 'thing')\n"
        "y = 'see old_mod.thing for details'\n"
        "z = f'{1}old_mod.thing'\n"
    )
    result = _run(src)
    assert [line for line, _ in result.unhandled] == [2, 3, 4]


def test_second_run_makes_no_edit():
    src = (
        "import old_mod\nfrom old_mod import thing\nfrom unittest.mock import patch\n"
        "def test_a(monkeypatch):\n    patch('old_mod.thing')\n    old_mod.thing\n"
        "    monkeypatch.setattr(old_mod, 'old_name', 1)\n"
    )
    once = _run(src).data
    again = rp.retarget_source(once, ENTRIES)
    assert again.data == once
    assert sum(again.counts.values()) == 0


def test_alias_colliding_with_a_module_level_name_is_an_error():
    src = "import old_mod\nnm = 5\nold_mod.thing\n"
    with pytest.raises(rp.ToolError, match="collides"):
        _run(src)


def test_unrelated_formatting_is_untouched():
    src = "import old_mod\n\n\nx   =  [1,2 ,3]\nold_mod.thing  # keep\n"
    out = _text(src)
    assert "x   =  [1,2 ,3]" in out
    assert "nm.thing  # keep" in out


def test_non_ascii_text_before_an_edit_is_handled():
    src = "# café\nimport old_mod\nold_mod.thing\n"
    assert "nm.thing" in _text(src)


def test_check_mode_counts_and_changes_nothing():
    src = "import old_mod\nold_mod.thing\n"
    result = _run(src, check=True)
    assert result.data == src.encode()
    assert result.references[ENTRIES[0]] == 1


def _tree(tmp_path: Path, src: str) -> tuple[Path, Path]:
    (tmp_path / "t").mkdir()
    f = tmp_path / "t" / "test_x.py"
    f.write_text(src, encoding="utf-8")
    m = tmp_path / "m.map"
    m.write_text(MAP, encoding="utf-8")
    return f, m


def test_check_exit_status(tmp_path, capsys):
    f, m = _tree(tmp_path, "import old_mod\nold_mod.thing\n")
    assert rp.main(["--map", str(m), "--check", "--root", str(tmp_path / "t")]) == 1
    assert f.read_text() == "import old_mod\nold_mod.thing\n"
    f.write_text("import other\n", encoding="utf-8")
    assert rp.main(["--map", str(m), "--check", "--root", str(tmp_path / "t")]) == 0


def test_rewrite_exit_status_and_summary(tmp_path, capsys):
    f, m = _tree(tmp_path, "import old_mod\nold_mod.thing\n")
    assert rp.main(["--map", str(m), "--root", str(tmp_path / "t")]) == 0
    assert "nm.thing" in f.read_text()
    out = capsys.readouterr().out
    assert "old_mod.thing -> new_mod.thing: 1 edits in 1 files" in out
    # a reference in a form it cannot handle keeps the status at 1
    f.write_text("import old_mod\ngetattr(old_mod, 'thing')\n", encoding="utf-8")
    assert rp.main(["--map", str(m), "--root", str(tmp_path / "t")]) == 1
    assert "test_x.py:2" in capsys.readouterr().out


def test_alias_collision_exit_status(tmp_path):
    f, m = _tree(tmp_path, "import old_mod\nnm = 1\nold_mod.thing\n")
    assert rp.main(["--map", str(m), "--root", str(tmp_path / "t")]) == 2
    assert f.read_text() == "import old_mod\nnm = 1\nold_mod.thing\n"


def test_bad_map_exit_status(tmp_path):
    (tmp_path / "t").mkdir()
    m = tmp_path / "bad.map"
    m.write_text("nonsense\n", encoding="utf-8")
    assert rp.main(["--map", str(m), "--root", str(tmp_path / "t")]) == 2


SRC_OLD = "import old_mod\nold_mod.thing\n"


def _two_files(tmp_path: Path) -> tuple[Path, Path, Path]:
    f, m = _tree(tmp_path, SRC_OLD)
    other = tmp_path / "t" / "test_y.py"
    other.write_text(SRC_OLD, encoding="utf-8")
    return f, other, m


def test_only_rewrites_the_named_file_and_leaves_the_other(tmp_path):
    f, other, m = _two_files(tmp_path)
    root = str(tmp_path / "t")
    assert rp.main(["--map", str(m), "--root", root, "--only", str(f)]) == 0
    assert "nm.thing" in f.read_text()
    assert other.read_text() == SRC_OLD


def test_only_accepts_a_path_relative_to_the_root_and_repeats(tmp_path):
    f, other, m = _two_files(tmp_path)
    root = str(tmp_path / "t")
    assert rp.main(["--map", str(m), "--root", root,
                    "--only", "test_x.py", "--only", "test_y.py"]) == 0
    assert "nm.thing" in f.read_text()
    assert "nm.thing" in other.read_text()


def test_only_with_a_missing_file_exits_2_and_changes_nothing(tmp_path, capsys):
    f, other, m = _two_files(tmp_path)
    root = str(tmp_path / "t")
    assert rp.main(["--map", str(m), "--root", root, "--only", str(f),
                    "--only", str(tmp_path / "t" / "missing.py")]) == 2
    assert "missing.py" in capsys.readouterr().out
    assert f.read_text() == SRC_OLD


def test_only_with_a_file_outside_the_root_exits_2(tmp_path):
    f, other, m = _two_files(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text(SRC_OLD, encoding="utf-8")
    assert rp.main(["--map", str(m), "--root", str(tmp_path / "t"),
                    "--only", str(outside)]) == 2


def test_check_with_only_counts_only_the_named_files(tmp_path):
    f, other, m = _two_files(tmp_path)
    root = str(tmp_path / "t")
    assert rp.main(["--map", str(m), "--check", "--root", root, "--only", str(f)]) == 1
    f.write_text("import other\n", encoding="utf-8")
    # the unnamed file still holds the old target, but it is not looked at
    assert rp.main(["--map", str(m), "--check", "--root", root, "--only", str(f)]) == 0
    assert rp.main(["--map", str(m), "--check", "--root", root]) == 1
