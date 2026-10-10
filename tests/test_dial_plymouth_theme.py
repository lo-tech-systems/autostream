"""The dial's Plymouth theme: descriptor, script and the placeholder images.

Structural checks over the committed files, plus a run of the generator into
a temp directory.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import importlib.util
import re
import struct
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
THEME = REPO_ROOT / "system" / "plymouth" / "autostream-dial"
HELPERS = REPO_ROOT / "installer" / "dial" / "helpers.sh"
GENERATOR = REPO_ROOT / "tools" / "make_dial_splash.py"
INSTALLED = "/usr/share/plymouth/themes/autostream-dial"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
IMAGE_NAMES = ("starting.png", "shutting-down.png")


def _png_size(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    assert data.startswith(PNG_SIGNATURE), path.name
    return struct.unpack(">II", data[16:24])


class TestDescriptor:
    def setup_method(self):
        self.text = (THEME / "autostream-dial.plymouth").read_text(encoding="utf-8")

    def test_uses_the_script_module(self):
        assert "ModuleName=script" in self.text.splitlines()

    def test_paths_point_into_the_installed_theme_directory(self):
        assert f"ImageDir={INSTALLED}" in self.text.splitlines()
        assert f"ScriptFile={INSTALLED}/autostream-dial.script" in self.text.splitlines()

    def test_file_names_match_the_installer_table(self):
        helpers = HELPERS.read_text(encoding="utf-8")
        match = re.search(r"PLYMOUTH_THEME_FILES=\(([^)]*)\)", helpers)
        if match is None:
            pytest.skip("installer table not present yet")
        listed = match.group(1).split()
        assert sorted(listed) == sorted(
            ["autostream-dial.plymouth", "autostream-dial.script", *IMAGE_NAMES])
        for name in listed:
            assert (THEME / name).is_file(), name


class TestScript:
    def setup_method(self):
        self.text = (THEME / "autostream-dial.script").read_text(encoding="utf-8")

    def test_chooses_the_image_by_mode(self):
        assert "Plymouth.GetMode()" in self.text
        for name in IMAGE_NAMES:
            assert f'"{name}"' in self.text

    def test_names_no_other_file(self):
        assert sorted(set(re.findall(r'"([^"]+\.[a-z]+)"', self.text))) == sorted(IMAGE_NAMES)

    def test_never_upscales(self):
        assert "scale = 1;" in self.text
        assert "image_width > screen_width" in self.text
        assert "image_height > screen_height" in self.text

    def test_centres_on_both_axes(self):
        assert "SetX((screen_width - scaled_width) / 2)" in self.text
        assert "SetY((screen_height - scaled_height) / 2)" in self.text

    def test_background_matches_the_hd_page(self):
        # #0e2841 as 0..1 floats
        for call in ("SetBackgroundTopColor", "SetBackgroundBottomColor"):
            assert f"{call}(0.055, 0.157, 0.255)" in self.text


class TestImages:
    def test_png_signature_and_size(self):
        sizes = {_png_size(THEME / name) for name in IMAGE_NAMES}
        assert sizes == {(1920, 1080)}

    @pytest.mark.parametrize("name", IMAGE_NAMES)
    def test_small_enough_for_an_initramfs(self, name):
        assert (THEME / name).stat().st_size < 50 * 1024


class TestGenerator:
    def _load(self):
        spec = importlib.util.spec_from_file_location("make_dial_splash", GENERATOR)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_names_exactly_the_two_images(self):
        pytest.importorskip("PIL")
        assert sorted(self._load().IMAGES) == sorted(IMAGE_NAMES)

    def test_default_output_is_the_theme_directory(self):
        pytest.importorskip("PIL")
        assert self._load().DEFAULT_OUT == THEME

    def test_writes_images_of_the_configured_size(self, tmp_path):
        pytest.importorskip("PIL")
        module = self._load()
        written = module.generate(tmp_path)
        assert sorted(p.name for p in written) == sorted(IMAGE_NAMES)
        for path in written:
            assert _png_size(path) == module.CANVAS
