"""Tests for dial_display_reveal.py — the artwork-tap reveal frames."""
from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

import numpy as np
import pytest

Image = pytest.importorskip("PIL.Image", reason="Pillow not installed")
ImageChops = pytest.importorskip("PIL.ImageChops", reason="Pillow not installed")

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
_CORE = str(REPO_ROOT / "core")
for _p in (_DIAL, _CORE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import dial_display_reveal as _dr  # noqa: E402
from dial_display_views import (  # noqa: E402
    OverlayState,
    RepeatViewState,
)
from dial_display_reveal import (  # noqa: E402
    _apply_layer,
    _apply_layer_np,
    _reveal_frame,
    _reveal_frame_pillow,
)
from dial_display_compositor import (  # noqa: E402
    _compose_frame,
    _now_playing_frame,
    _repeat_frame,
    _reset_render_caches,
    _reveal_layers,
)
from dial_touch_layout import (  # noqa: E402
    layout_for,
    repeat_layout_for,
)
from dial_compositor_support import (
    _COMPACT_240,
    _LARGE_METRICS,
    _RICH_METRICS,
    _diff_bbox,
    _repeat_state,
)
from dial_compositor_support import compositor  # noqa: F401

# ---------------------------------------------------------------------------
# The artwork-tap reveal: compose(reveal_progress=p) and
# compose_repeat(reveal_progress=p) slide the overlay's own chrome off the
# panel while the artwork under it stays put, and fade the inter-band text
# as p runs from 0 (chrome in place, the ordinary frame) to 1 (chrome gone,
# the no-overlay frame). Pinned on both the rich and large tiers, which are
# the only ones the manager ever animates; the compact tier ignores the
# parameter entirely.
# ---------------------------------------------------------------------------


def _reveal_base_image(metrics):
    """A mid-grey-to-white vertical gradient, tall enough for a fade to be
    provable (a flat dark image cannot show a blend changing anything)."""
    grad = Image.linear_gradient("L").resize((metrics.width, metrics.height))
    return grad.convert("RGB")


def _reveal_overlay():
    return OverlayState(
        visible=True, artist="Artist", title="Title", album="Album", name="Kitchen",
        volume=50, dots=True, muted=True,
    )


def _plain_overlay():
    """Bands with nothing drawn on them: a pure dim, so the chrome adds no
    light of its own."""
    return OverlayState(visible=True)


def _tol(a, b, tol=2):
    """True when two same-size images agree within *tol* levels per channel."""
    if a.size != b.size:
        return False
    return all(
        abs(x - y) <= tol
        for pa, pb in zip(a.getdata(), b.getdata())
        for x, y in zip(pa, pb)
    )


def _reveal_frames(compositor, metrics, overlay, p):
    """(out, shown, bare) for one reveal progress over the gradient base."""
    w, h = metrics.width, metrics.height
    base = _reveal_base_image(metrics)
    kw = dict(rotate=False, bgr=False, is_artwork=False, metrics=metrics)
    shown = compositor.compose(base, w, h, overlay=overlay, **kw)
    bare = compositor.compose(base, w, h, overlay=None, **kw)
    out = compositor.compose(base, w, h, overlay=overlay, reveal_progress=p, **kw)
    return out, shown, bare


class TestRevealProgress:
    @pytest.mark.parametrize("metrics", [_RICH_METRICS, _LARGE_METRICS])
    @pytest.mark.parametrize("rotate,bgr", [(False, False), (True, False), (False, True), (True, True)])
    def test_zero_progress_is_byte_identical_to_shown(self, compositor, metrics, rotate, bgr):
        base = _reveal_base_image(metrics)
        overlay = _reveal_overlay()
        shown = compositor.compose(
            base, metrics.width, metrics.height, rotate=rotate, bgr=bgr, is_artwork=False,
            overlay=overlay, metrics=metrics,
        )
        zero = compositor.compose(
            base, metrics.width, metrics.height, rotate=rotate, bgr=bgr, is_artwork=False,
            overlay=overlay, metrics=metrics, reveal_progress=0.0,
        )
        assert list(zero.getdata()) == list(shown.getdata())

    @pytest.mark.parametrize("metrics", [_RICH_METRICS, _LARGE_METRICS])
    @pytest.mark.parametrize("progress", [-0.5, float("nan")])
    def test_negative_and_nan_progress_are_drawn_as_shown(self, compositor, metrics, progress):
        base = _reveal_base_image(metrics)
        overlay = _reveal_overlay()
        shown = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=overlay, metrics=metrics,
        )
        out = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=overlay, metrics=metrics, reveal_progress=progress,
        )
        assert list(out.getdata()) == list(shown.getdata())

    @pytest.mark.parametrize("metrics", [_RICH_METRICS, _LARGE_METRICS])
    @pytest.mark.parametrize("rotate,bgr", [(False, False), (True, False), (False, True), (True, True)])
    @pytest.mark.parametrize("progress", [1.0, 1.5])
    def test_full_progress_is_byte_identical_to_hidden(self, compositor, metrics, rotate, bgr, progress):
        base = _reveal_base_image(metrics)
        overlay = _reveal_overlay()
        bare = compositor.compose(
            base, metrics.width, metrics.height, rotate=rotate, bgr=bgr, is_artwork=False,
            overlay=None, metrics=metrics,
        )
        out = compositor.compose(
            base, metrics.width, metrics.height, rotate=rotate, bgr=bgr, is_artwork=False,
            overlay=overlay, metrics=metrics, reveal_progress=progress,
        )
        assert list(out.getdata()) == list(bare.getdata())
        if not rotate and not bgr:
            direct = compositor.compose(
                base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
                overlay=overlay, metrics=metrics, reveal_progress=progress,
            )
            assert direct is base

    @pytest.mark.parametrize("metrics", [_RICH_METRICS, _LARGE_METRICS])
    @pytest.mark.parametrize("p", [0.25, 0.5, 0.8])
    def test_artwork_is_stationary_under_a_sliding_band(self, compositor, metrics, p):
        w, h = metrics.width, metrics.height
        out, shown, bare = _reveal_frames(compositor, metrics, _plain_overlay(), p)
        band_h = layout_for(w, h, metrics=metrics).top_band[3]
        dy = round(p * band_h)

        # Where a band still is, the dimmed artwork is the very rows it was
        # over before the slide began, not rows carried along with the band.
        # Compared in the left-edge columns, clear of every glyph, which do
        # move with the band.
        edge = 6
        assert _tol(out.crop((0, 0, edge, band_h - dy)), shown.crop((0, 0, edge, band_h - dy)))
        assert list(out.crop((0, band_h - dy, w, band_h)).getdata()) == list(
            bare.crop((0, band_h - dy, w, band_h)).getdata()
        )
        assert _tol(
            out.crop((0, h - band_h + dy, edge, h)), shown.crop((0, h - band_h + dy, edge, h)),
        )
        assert list(out.crop((0, h - band_h, w, h - band_h + dy)).getdata()) == list(
            bare.crop((0, h - band_h, w, h - band_h + dy)).getdata()
        )

    def test_chrome_slides_by_the_offset(self, compositor):
        metrics = _RICH_METRICS
        w, h = metrics.width, metrics.height
        p = 0.5
        base = _reveal_base_image(metrics)
        overlay = _reveal_overlay()
        out, shown, bare = _reveal_frames(compositor, metrics, overlay, p)
        layout = layout_for(w, h, metrics=metrics)
        band_h = layout.top_band[3]
        dy = round(p * band_h)

        # The bottom band's divider column: white where the chrome has
        # moved to, the bare artwork in the rows it has left.
        x = layout.footer_dividers[0]
        for y in range(h - band_h + dy, h):
            assert out.getpixel((x, y)) == (255, 255, 255)
        for y in range(h - band_h, h - band_h + dy):
            assert out.getpixel((x, y)) == bare.getpixel((x, y))

        # The top band's chrome is the ordinary frame's rows [dy, band_h),
        # laid over the artwork at rows [0, band_h - dy).
        frame = _now_playing_frame(overlay, w, h, metrics)
        layers = _reveal_layers(
            frame, w, h, metrics, layout.top_band, layout.bottom_band, layout.artwork,
        )
        nx0, _, nx1, _ = layout.name
        region = base.crop((nx0, 0, nx1, band_h - dy))
        chrome = (nx0, dy, nx1, band_h)
        expected = _apply_layer(region, layers.top_add.crop(chrome), layers.top_keep.crop(chrome))
        assert _tol(out.crop((nx0, 0, nx1, band_h - dy)), expected)
        # And that region really carries name text: it differs from the
        # plain dimmed artwork there.
        plain = _reveal_frames(compositor, metrics, _plain_overlay(), p)[0]
        assert _diff_bbox(out.crop((nx0, 0, nx1, band_h - dy)), plain.crop((nx0, 0, nx1, band_h - dy))) is not None

    @pytest.mark.parametrize("metrics", [_RICH_METRICS, _LARGE_METRICS])
    @pytest.mark.parametrize("p", [0.25, 0.5, 0.8])
    def test_strip_fades_by_alpha(self, compositor, metrics, p):
        w, h = metrics.width, metrics.height
        out, shown, bare = _reveal_frames(compositor, metrics, _reveal_overlay(), p)
        layout = layout_for(w, h, metrics=metrics)
        expected = Image.blend(bare.crop(layout.artwork), shown.crop(layout.artwork), 1.0 - p)
        assert _tol(out.crop(layout.artwork), expected)
        assert _diff_bbox(out.crop(layout.title), shown.crop(layout.title)) is not None
        assert _diff_bbox(out.crop(layout.title), bare.crop(layout.title)) is not None

    def test_progress_is_ignored_on_compact(self, compositor):
        metrics = _COMPACT_240
        base = _reveal_base_image(metrics)
        overlay = _reveal_overlay()
        zero = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=overlay, metrics=metrics, reveal_progress=0.0,
        )
        half = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=overlay, metrics=metrics, reveal_progress=0.5,
        )
        assert list(zero.getdata()) == list(half.getdata())

    def test_rotate_and_bgr_apply_after_the_slide(self, compositor):
        metrics = _RICH_METRICS
        base = _reveal_base_image(metrics)
        overlay = _reveal_overlay()
        plain = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=overlay, metrics=metrics, reveal_progress=0.5,
        )
        transformed = compositor.compose(
            base, metrics.width, metrics.height, rotate=True, bgr=True, is_artwork=False,
            overlay=overlay, metrics=metrics, reveal_progress=0.5,
        )
        expected = plain.transpose(Image.ROTATE_180)
        expected = Image.merge("RGB", expected.split()[::-1])
        assert list(transformed.getdata()) == list(expected.getdata())

    @pytest.mark.parametrize("metrics", [_RICH_METRICS, _LARGE_METRICS])
    def test_layers_are_the_black_and_white_renders(self, compositor, metrics):
        w, h = metrics.width, metrics.height
        layout = layout_for(w, h, metrics=metrics)
        frame = _now_playing_frame(_reveal_overlay(), w, h, metrics)
        layers = _reveal_layers(
            frame, w, h, metrics, layout.top_band, layout.bottom_band, layout.artwork,
        )
        black = Image.new("RGB", (w, h), (0, 0, 0))
        white = Image.new("RGB", (w, h), (255, 255, 255))
        add = _compose_frame(black, w, h, frame, rotate=False, bgr=False, metrics=metrics)
        lit = _compose_frame(white, w, h, frame, rotate=False, bgr=False, metrics=metrics)
        keep = ImageChops.subtract(lit, add)
        assert layers.top_add.tobytes() == add.crop(layout.top_band).tobytes()
        assert layers.top_keep.tobytes() == keep.crop(layout.top_band).tobytes()
        assert layers.bottom_add.tobytes() == add.crop(layout.bottom_band).tobytes()
        assert layers.bottom_keep.tobytes() == keep.crop(layout.bottom_band).tobytes()
        assert layers.strip_add.tobytes() == add.crop(layout.artwork).tobytes()
        base = _reveal_base_image(metrics)
        shown = _compose_frame(base, w, h, frame, rotate=False, bgr=False, metrics=metrics)
        rebuilt = _apply_layer(base.crop(layout.artwork), layers.strip_add, layers.strip_keep)
        assert _tol(rebuilt, shown.crop(layout.artwork))
        rebuilt_top = _apply_layer(base.crop(layout.top_band), layers.top_add, layers.top_keep)
        assert _tol(rebuilt_top, shown.crop(layout.top_band))

    def test_layers_are_memoised_and_reset(self, compositor):
        metrics = _RICH_METRICS
        base = _reveal_base_image(metrics)
        _reveal_layers.cache_clear()

        def run(overlay):
            return compositor.compose(
                base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
                overlay=overlay, metrics=metrics, reveal_progress=0.4,
            )

        overlay = _reveal_overlay()
        run(overlay)
        run(overlay)
        info = _reveal_layers.cache_info()
        assert (info.hits, info.misses) == (1, 1)
        run(dataclasses.replace(overlay, volume=51))
        assert _reveal_layers.cache_info().misses == 2
        _reset_render_caches()
        assert _reveal_layers.cache_info().currsize == 0

    def test_base_image_is_not_mutated(self, compositor):
        metrics = _RICH_METRICS
        base = _reveal_base_image(metrics)
        before = base.tobytes()
        compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=_reveal_overlay(), metrics=metrics, reveal_progress=0.5,
        )
        assert base.tobytes() == before

    def test_same_inputs_same_output(self, compositor):
        metrics = _RICH_METRICS
        base = _reveal_base_image(metrics)
        overlay = _reveal_overlay()
        first = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=overlay, metrics=metrics, reveal_progress=0.37,
        )
        second = compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=overlay, metrics=metrics, reveal_progress=0.37,
        )
        assert list(first.getdata()) == list(second.getdata())

    def test_statelessness(self, compositor):
        metrics = _RICH_METRICS
        base = _reveal_base_image(metrics)
        before = dict(vars(compositor))
        compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=_reveal_overlay(), metrics=metrics, reveal_progress=0.5,
        )
        after = dict(vars(compositor))
        assert before == after == {}


def _replaying_state(**overrides) -> RepeatViewState:
    base = dict(
        name="Kitchen", layout="replaying", armed=False, line="0:42 / 3:12",
        start_enabled=True, stop_enabled=True, stop_pressed=False,
        volume=40, pressed=None,
    )
    base.update(overrides)
    return RepeatViewState(**base)


class TestRepeatRevealProgress:
    @pytest.mark.parametrize("metrics", [_RICH_METRICS, _LARGE_METRICS])
    def test_replaying_slides_and_fades_the_line(self, compositor, metrics):
        w, h = metrics.width, metrics.height
        base = _reveal_base_image(metrics)
        state = _replaying_state()
        kw = dict(rotate=False, bgr=False, base=base, metrics=metrics)
        shown = compositor.compose_repeat(w, h, state, **kw)
        bare = compositor.compose_repeat(w, h, state, controls=False, **kw)
        p = 0.5
        out = compositor.compose_repeat(w, h, state, reveal_progress=p, **kw)
        layout = repeat_layout_for(w, h, metrics=metrics)
        band_h = layout.top_band[3]
        dy = round(p * band_h)

        x = layout_for(w, h, metrics=metrics).footer_dividers[0]
        for y in range(h - band_h, h - band_h + dy):
            assert out.getpixel((x, y)) == bare.getpixel((x, y))
        assert list(out.crop((0, band_h - dy, w, band_h)).getdata()) == list(
            bare.crop((0, band_h - dy, w, band_h)).getdata()
        )
        assert _diff_bbox(out.crop(layout.line), shown.crop(layout.line)) is not None
        assert _diff_bbox(out.crop(layout.line), bare.crop(layout.line)) is not None

        assert list(compositor.compose_repeat(w, h, state, reveal_progress=0.0, **kw).getdata()) == list(
            shown.getdata()
        )
        assert list(compositor.compose_repeat(w, h, state, reveal_progress=1.0, **kw).getdata()) == list(
            bare.getdata()
        )

    def test_compact_ignores_progress(self, compositor):
        metrics = _COMPACT_240
        w, h = metrics.width, metrics.height
        base = _reveal_base_image(metrics)
        kw = dict(rotate=False, bgr=False, base=base, metrics=metrics)
        for state in (_repeat_state(), _replaying_state()):
            zero = compositor.compose_repeat(w, h, state, **kw)
            half = compositor.compose_repeat(w, h, state, reveal_progress=0.5, **kw)
            assert list(zero.getdata()) == list(half.getdata())

    def test_enable_layout_slides_its_bands_too(self, compositor):
        # The artwork shows between the bands while playing live as well
        metrics = _RICH_METRICS
        w, h = metrics.width, metrics.height
        kw = dict(rotate=False, bgr=False, base=_reveal_base_image(metrics), metrics=metrics)
        state = _repeat_state()
        shown = compositor.compose_repeat(w, h, state, **kw)
        bare = compositor.compose_repeat(w, h, state, controls=False, **kw)
        half = compositor.compose_repeat(w, h, state, reveal_progress=0.5, **kw)
        assert list(half.getdata()) not in (list(shown.getdata()), list(bare.getdata()))
        assert list(compositor.compose_repeat(w, h, state, reveal_progress=1.0, **kw).getdata()) == list(
            bare.getdata())

    def test_none_base_slides_a_chassis(self, compositor):
        metrics = _RICH_METRICS
        w, h = metrics.width, metrics.height
        state = _replaying_state()
        kw = dict(rotate=False, bgr=False, base=None, metrics=metrics)
        mid = compositor.compose_repeat(w, h, state, reveal_progress=0.5, **kw)
        assert mid.size == (w, h)
        full = compositor.compose_repeat(w, h, state, reveal_progress=1.0, **kw)
        bare = compositor.compose_repeat(w, h, state, controls=False, **kw)
        assert list(full.getdata()) == list(bare.getdata())


def _mean_abs_diff(a, b) -> float:
    pairs = [(x, y) for pa, pb in zip(a.getdata(), b.getdata()) for x, y in zip(pa, pb)]
    return sum(abs(x - y) for x, y in pairs) / len(pairs)


class TestRevealAtPanelSize:
    """A layout size composed larger than the panel builds its reveal slide
    frames at the panel's own size (compose()'s output_size)."""

    PANEL = (320, 240)

    def _main(self, compositor, p, *, output_size=PANEL, **extra):
        metrics = _LARGE_METRICS
        base = _reveal_base_image(metrics)
        return compositor.compose(
            base, metrics.width, metrics.height, rotate=False, bgr=False, is_artwork=False,
            overlay=_reveal_overlay(), metrics=metrics, reveal_progress=p,
            output_size=output_size, **extra,
        )

    @pytest.mark.parametrize("p", [0.25, 0.5, 0.8])
    def test_slide_frame_is_panel_sized_and_matches_the_shrunk_frame(self, compositor, p):
        out = self._main(compositor, p)
        assert out.size == self.PANEL
        large = self._main(compositor, p, output_size=None)
        assert large.size == (640, 480)
        # Not bit-identical: the bands move in whole panel pixels and the
        # chrome is averaged before it meets the base rather than after.
        assert _mean_abs_diff(out, large.resize(self.PANEL, Image.Resampling.BOX)) < 3.0

    @pytest.mark.parametrize("p", [0.0, 1.0])
    def test_endpoints_stay_at_the_compose_size(self, compositor, p):
        assert self._main(compositor, p).size == (640, 480)

    def test_a_frame_carrying_the_timer_line_stays_at_the_compose_size(self, compositor):
        out = self._main(compositor, 0.5, timer_text="0:07 / 3:12")
        assert out.size == (640, 480)

    @pytest.mark.parametrize("output_size", [(640, 480), (1280, 960), (800, 240)])
    def test_no_reduction_means_no_change_of_size(self, compositor, output_size):
        out = self._main(compositor, 0.5, output_size=output_size)
        assert out.tobytes() == self._main(compositor, 0.5, output_size=None).tobytes()

    def test_rotate_and_bgr_apply_after_the_shrink(self, compositor):
        plain = self._main(compositor, 0.5)
        metrics = _LARGE_METRICS
        transformed = compositor.compose(
            _reveal_base_image(metrics), metrics.width, metrics.height, rotate=True, bgr=True,
            is_artwork=False, overlay=_reveal_overlay(), metrics=metrics, reveal_progress=0.5,
            output_size=self.PANEL,
        )
        expected = Image.merge("RGB", plain.transpose(Image.ROTATE_180).split()[::-1])
        assert transformed.tobytes() == expected.tobytes()

    def test_the_base_is_shrunk_once_per_base(self, compositor):
        metrics = _LARGE_METRICS
        base = _reveal_base_image(metrics)
        before = base.tobytes()
        kw = dict(rotate=False, bgr=False, is_artwork=False, overlay=_reveal_overlay(),
                  metrics=metrics, output_size=self.PANEL)
        import dial_display_reveal

        compositor.compose(base, 640, 480, reveal_progress=0.3, **kw)
        memo = dial_display_reveal._shrunk_base_memo
        assert memo[0] is base and memo[2].size == self.PANEL
        compositor.compose(base, 640, 480, reveal_progress=0.6, **kw)
        assert dial_display_reveal._shrunk_base_memo is memo
        assert base.tobytes() == before
        _reset_render_caches()
        assert dial_display_reveal._shrunk_base_memo is None

    def test_repeat_slide_frame_is_panel_sized(self, compositor):
        metrics = _LARGE_METRICS
        kw = dict(rotate=False, bgr=False, base=_reveal_base_image(metrics), metrics=metrics)
        state = _replaying_state()
        out = compositor.compose_repeat(640, 480, state, reveal_progress=0.5, output_size=self.PANEL, **kw)
        assert out.size == self.PANEL
        large = compositor.compose_repeat(640, 480, state, reveal_progress=0.5, **kw)
        assert _mean_abs_diff(out, large.resize(self.PANEL, Image.Resampling.BOX)) < 3.0
        shown = compositor.compose_repeat(640, 480, state, output_size=self.PANEL, **kw)
        assert shown.size == (640, 480)


# ---------------------------------------------------------------------------
# The reveal's numpy compositing path against the Pillow path it replaces.
# ---------------------------------------------------------------------------


def _random_base(metrics, seed=7):
    """An artwork-like base: smooth gradients plus per-pixel noise."""
    rng = np.random.default_rng(seed)
    w, h = metrics.width, metrics.height
    yy, xx = np.mgrid[0:h, 0:w]
    smooth = (xx * 255 // max(w - 1, 1) + yy * 255 // max(h - 1, 1)) // 2
    noise = rng.integers(-40, 41, size=(h, w, 3))
    arr = np.clip(smooth[..., None] + noise, 0, 255).astype(np.uint8)
    arr[: h // 3, : w // 3] = rng.integers(0, 256, size=(h // 3, w // 3, 3), dtype=np.uint8)
    return Image.fromarray(arr, "RGB")


def _now_layers(metrics):
    w, h = metrics.width, metrics.height
    layout = layout_for(w, h, metrics=metrics)
    frame = _now_playing_frame(_reveal_overlay(), w, h, metrics)
    return _reveal_layers(frame, w, h, metrics, layout.top_band, layout.bottom_band, layout.artwork)


def _replay_layers(metrics):
    w, h = metrics.width, metrics.height
    layout = repeat_layout_for(w, h, metrics=metrics)
    strip = (0, layout.top_band[3], w, layout.bottom_band[1])
    frame = _repeat_frame(_replaying_state(), w, h, metrics)
    return _reveal_layers(frame, w, h, metrics, layout.top_band, layout.bottom_band, strip)


_LAYER_BUILDERS = {"now_playing": _now_layers, "replaying": _replay_layers}


def _max_dev(a, b):
    return int(np.abs(
        np.asarray(a, dtype=np.int16) - np.asarray(b, dtype=np.int16)
    ).max())


# The slide offset is round(progress * band height) per band, so what a
# progress value exercises depends on the panel: the band is 48 rows on the
# rich panel and 95 on the large one. Each panel/layer pair runs one
# edge value and one other: 0.02 (the smallest offset, 1 row rich and 2
# large), 0.99 (offset equals the band height on rich, so the chrome is
# skipped entirely; one row short of it on large, the last row of chrome
# left) and 0.5 on the large panel (a tie, 47.5 rows). The other values (0.25, 0.5, 0.63) give the
# strip fade a fractional opacity.
_PILLOW_PATH_CASES = [
    pytest.param(metrics, kind, p, id=f"{tier}-{kind}-{p}")
    for tier, metrics, kind, p in (
        ("rich", _RICH_METRICS, "now_playing", 0.02),
        ("rich", _RICH_METRICS, "now_playing", 0.63),
        ("rich", _RICH_METRICS, "replaying", 0.5),
        ("rich", _RICH_METRICS, "replaying", 0.99),
        ("large", _LARGE_METRICS, "now_playing", 0.5),
        ("large", _LARGE_METRICS, "now_playing", 0.02),
        ("large", _LARGE_METRICS, "replaying", 0.99),
        ("large", _LARGE_METRICS, "replaying", 0.25),
    )
]


class TestRevealNumpyPath:
    @pytest.mark.parametrize("metrics,kind,p", _PILLOW_PATH_CASES)
    def test_matches_the_pillow_path(self, compositor, metrics, kind, p):
        layers = _LAYER_BUILDERS[kind](metrics)
        assert layers.arrays is not None
        base = _random_base(metrics)
        got = np.asarray(_reveal_frame(base, layers, p))
        want = np.asarray(_reveal_frame_pillow(base, layers, p))
        assert got.shape == want.shape
        # The strip fade may differ from Pillow's float blend by a level.
        assert _max_dev(got, want) <= 1
        # The bands are bit-identical: compare every row outside the strip.
        for x0, y0, x1, y1 in (layers.top_band, layers.bottom_band):
            assert np.array_equal(got[y0:y1, x0:x1], want[y0:y1, x0:x1])

    def test_multiply_and_add_are_pillows_exactly(self):
        rng = np.random.default_rng(1)
        shape = (16, 64, 3)
        for _ in range(20):
            region = rng.integers(0, 256, size=shape, dtype=np.uint8)
            keep = rng.integers(0, 256, size=shape, dtype=np.uint8)
            add = rng.integers(0, 256, size=shape, dtype=np.uint8)
            want = _apply_layer(
                Image.fromarray(region, "RGB"), Image.fromarray(add, "RGB"),
                Image.fromarray(keep, "RGB"),
            )
            got = _apply_layer_np(
                np, region, add.astype(np.uint16), keep.astype(np.uint16),
            )
            assert np.array_equal(got.astype(np.uint8), np.asarray(want))
        # Every multiplier pair, including the extremes.
        a = np.repeat(np.arange(256, dtype=np.uint8), 256).reshape(256, 256, 1).repeat(3, 2)
        b = a.transpose(1, 0, 2).copy()
        zero = np.zeros(a.shape, dtype=np.uint16)
        want = ImageChops.multiply(Image.fromarray(a, "RGB"), Image.fromarray(b, "RGB"))
        got = _apply_layer_np(np, a, zero, b.astype(np.uint16))
        assert np.array_equal(got.astype(np.uint8), np.asarray(want))

    def test_strip_fade_arithmetic_within_a_level_of_blend(self):
        rng = np.random.default_rng(2)
        for alpha in [0.0, 0.01, 0.1, 0.25, 0.333, 0.5, 0.7, 0.9, 0.999]:
            a = rng.integers(0, 256, size=(24, 40, 3), dtype=np.uint8)
            b = rng.integers(0, 256, size=(24, 40, 3), dtype=np.uint8)
            want = Image.blend(Image.fromarray(a, "RGB"), Image.fromarray(b, "RGB"), alpha)
            a_f = a.astype(np.float32)
            got = b.astype(np.float32)
            got -= a_f
            got *= np.float32(alpha)
            got += a_f
            assert _max_dev(got.astype(np.uint8), np.asarray(want)) <= 1

    @pytest.mark.parametrize("metrics", [_RICH_METRICS, _LARGE_METRICS])
    @pytest.mark.parametrize("kind", sorted(_LAYER_BUILDERS))
    def test_active_strip_rows_cover_every_changing_row(self, metrics, kind):
        layers = _LAYER_BUILDERS[kind](metrics)
        arrays = layers.arrays
        add = np.asarray(layers.strip_add, dtype=np.int16)
        keep = np.asarray(layers.strip_keep, dtype=np.int16)
        changes = ((add != 0) | (keep != 255)).any(axis=(1, 2))
        covered = np.zeros(len(changes), dtype=bool)
        for r0, r1 in arrays.strip_runs:
            assert 0 <= r0 < r1 <= len(changes)
            covered[r0:r1] = True
        assert np.array_equal(covered, changes)
        assert changes.any()
        assert arrays.strip_add.dtype == np.uint16

    @pytest.mark.parametrize("kind", sorted(_LAYER_BUILDERS))
    def test_pass_through_strip_rows_are_bit_exact_base(self, kind):
        metrics = _RICH_METRICS
        layers = _LAYER_BUILDERS[kind](metrics)
        base = _random_base(metrics, seed=11)
        got = np.asarray(_reveal_frame(base, layers, 0.5))
        src = np.asarray(base)
        x0, y0, x1, y1 = layers.strip
        active = np.zeros(y1 - y0, dtype=bool)
        for r0, r1 in layers.arrays.strip_runs:
            active[r0:r1] = True
        # Rows the bands' slides do not reach are the ones inside the strip.
        for r in np.flatnonzero(~active):
            assert np.array_equal(got[y0 + r, x0:x1], src[y0 + r, x0:x1])

    def test_band_rows_are_all_active_by_construction(self):
        layers = _now_layers(_RICH_METRICS)
        for add, keep in ((layers.top_add, layers.top_keep), (layers.bottom_add, layers.bottom_keep)):
            a = np.asarray(add, dtype=np.int16)
            k = np.asarray(keep, dtype=np.int16)
            assert ((a != 0) | (k != 255)).any(axis=(1, 2)).all()

    def test_base_image_is_not_mutated(self):
        metrics = _RICH_METRICS
        layers = _now_layers(metrics)
        base = _random_base(metrics)
        before = base.tobytes()
        _reveal_frame(base, layers, 0.4)
        assert base.tobytes() == before

    def test_layers_are_still_a_frozen_dataclass(self):
        layers = _now_layers(_RICH_METRICS)
        with pytest.raises(dataclasses.FrozenInstanceError):
            layers.arrays = None
        assert layers == dataclasses.replace(layers, arrays=None)

    def test_numpy_failure_mid_frame_falls_back_without_raising(self, monkeypatch):
        metrics = _RICH_METRICS
        layers = _now_layers(metrics)
        base = _random_base(metrics)
        before = base.tobytes()

        def boom(*args, **kwargs):
            raise RuntimeError("simulated numpy failure")

        monkeypatch.setattr(_dr, "_apply_layer_np", boom)
        got = _reveal_frame(base, layers, 0.5)
        assert got.tobytes() == _reveal_frame_pillow(base, layers, 0.5).tobytes()
        assert base.tobytes() == before

    def test_failure_after_partial_work_still_falls_back(self, monkeypatch):
        metrics = _RICH_METRICS
        layers = _now_layers(metrics)
        base = _random_base(metrics)
        real = _dr._apply_layer_np
        calls = []

        def flaky(*args, **kwargs):
            calls.append(1)
            if len(calls) > 1:
                raise MemoryError("simulated")
            return real(*args, **kwargs)

        monkeypatch.setattr(_dr, "_apply_layer_np", flaky)
        got = _reveal_frame(base, layers, 0.5)
        assert len(calls) > 1
        assert got.tobytes() == _reveal_frame_pillow(base, layers, 0.5).tobytes()
