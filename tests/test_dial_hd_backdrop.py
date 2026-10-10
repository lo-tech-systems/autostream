"""Tests for the HD page's backdrop store: caching by key, replacement, a
failed render remembered, one render for concurrent requests, the logo kept
for the life of the store."""
from __future__ import annotations

import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dial"))

from dial_hd_backdrop import BackdropStore

REPO_ROOT = Path(__file__).resolve().parent.parent
LOGO = REPO_ROOT / "images" / "autostream-logo-centred-dark.png"


class Counting:
    """A renderer that counts its calls and returns a result per call."""

    def __init__(self, result=b"jpeg"):
        self.calls = []
        self.result = result

    def __call__(self, arg):
        self.calls.append(arg)
        if isinstance(self.result, Exception):
            raise self.result
        if callable(self.result):
            return self.result(arg)
        return self.result


def store(artwork=None, logo=None):
    return BackdropStore(LOGO, render_artwork=artwork or Counting(), render_logo=logo or Counting())


class TestArtwork:
    def test_the_first_request_renders_and_later_ones_reuse_it(self):
        render = Counting()
        s = store(artwork=render)
        first = s.artwork("k1", b"data")
        assert s.artwork("k1", b"data") is first
        assert render.calls == [b"data"]

    def test_a_new_key_renders_again_and_replaces_the_old(self):
        render = Counting(lambda data: b"out-" + data)
        s = store(artwork=render)
        assert s.artwork("a", b"1") == b"out-1"
        assert s.artwork("b", b"2") == b"out-2"
        assert s.artwork("a", b"1") == b"out-1"
        assert render.calls == [b"1", b"2", b"1"]

    @pytest.mark.parametrize("result", [None, RuntimeError("bad image")])
    def test_a_failed_render_is_remembered_as_none(self, result):
        render = Counting(result)
        s = store(artwork=render)
        assert s.artwork("k", b"x") is None
        assert s.artwork("k", b"x") is None
        assert len(render.calls) == 1

    def test_concurrent_requests_for_one_key_cost_one_render(self):
        release = threading.Event()
        entered = threading.Event()

        def slow(data):
            entered.set()
            release.wait(5)
            return b"done-" + data

        render = Counting(slow)
        s = store(artwork=render)
        results = {}

        def ask(name, key, data):
            results[name] = s.artwork(key, data)

        first = threading.Thread(target=ask, args=("a", "k", b"1"))
        second = threading.Thread(target=ask, args=("b", "k", b"1"))
        other = threading.Thread(target=ask, args=("c", "j", b"2"))
        first.start()
        assert entered.wait(5)
        second.start()
        other.start()
        # Nothing completes while the first render is blocked.
        second.join(0.2)
        other.join(0.2)
        assert results == {}
        release.set()
        for thread in (first, second, other):
            thread.join(5)
        assert results["a"] == results["b"] == b"done-1"
        assert results["c"] == b"done-2"
        assert render.calls == [b"1", b"2"]


class TestLogo:
    def test_it_renders_once_for_the_life_of_the_store(self):
        logo = Counting(b"logo")
        s = store(logo=logo)
        assert s.logo() == b"logo"
        s.artwork("a", b"1")
        s.artwork("b", b"2")
        assert s.logo() == b"logo"
        assert logo.calls == [str(LOGO)]

    def test_a_failing_render_stays_none(self):
        logo = Counting(RuntimeError("no logo"))
        s = store(logo=logo)
        assert s.logo() is None
        assert s.logo() is None
        assert len(logo.calls) == 1


def _png() -> bytes:
    # The corpus artwork bytes are a hand-written stub that does not decode.
    import io
    from PIL import Image
    out = io.BytesIO()
    Image.new("RGB", (64, 64), (200, 30, 30)).save(out, "PNG")
    return out.getvalue()


class TestRealRenderers:
    def test_the_artwork_is_a_jpeg(self):
        pytest.importorskip("PIL")
        data = BackdropStore(LOGO).artwork("k", _png())
        assert data is not None and data[:2] == b"\xff\xd8"

    def test_the_logo_is_a_jpeg(self):
        pytest.importorskip("PIL")
        data = BackdropStore(LOGO).logo()
        assert data is not None and data[:2] == b"\xff\xd8"

    def test_undecodable_artwork_is_none(self):
        pytest.importorskip("PIL")
        assert BackdropStore(LOGO).artwork("k", b"not an image") is None


def test_importing_the_server_and_the_store_does_not_import_pillow():
    code = (
        "import sys; sys.path[:0] = [%r, %r]\n"
        "import dial_hd_server, dial_hd_backdrop\n"
        "assert not any(m == 'PIL' or m.startswith('PIL.') for m in sys.modules), 'PIL imported'\n"
        % (str(REPO_ROOT / "dial"), str(REPO_ROOT / "core"))
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
