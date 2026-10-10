"""Tests for dial_display_windows.py — the change-region planner.

Pure array work: frames are seeded noise with rectangles re-noised, the
exact changed pixels are recomputed with numpy independently of the planner,
and the plan is judged against them (coverage, tightness, order, cost).
"""
from __future__ import annotations

import logging
import random
import sys
from pathlib import Path

import pytest

np = pytest.importorskip("numpy", reason="numpy not installed")
Image = pytest.importorskip("PIL.Image", reason="Pillow not installed")

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

import dial_display_windows as ddw
from dial_display_windows import bounding_box, frame_words, plan_windows

W, H = 320, 240


def _noise(w, h, rng):
    return rng.integers(0, 256, (h, w, 3), dtype=np.uint8)


def _frames(w, h, rects, seed=1, density=1.0):
    """(last, new) images: seeded noise, with each rect of *rects* changed
    in every channel of every selected pixel (a nonzero xor, so a changed
    pixel is guaranteed to differ); *density* selects a random fraction."""
    rng = np.random.default_rng(seed)
    last = _noise(w, h, rng)
    new = last.copy()
    for x0, y0, x1, y1 in rects:
        delta = rng.integers(1, 256, (y1 - y0, x1 - x0, 3), dtype=np.uint8)
        if density < 1.0:
            keep = rng.random((y1 - y0, x1 - x0)) >= density
            delta[keep] = 0
            delta[0, 0] = np.maximum(delta[0, 0], 1)
            delta[-1, -1] = np.maximum(delta[-1, -1], 1)
            delta[0, -1] = np.maximum(delta[0, -1], 1)
            delta[-1, 0] = np.maximum(delta[-1, 0], 1)
        new[y0:y1, x0:x1] ^= delta
    return Image.fromarray(last, "RGB"), Image.fromarray(new, "RGB")


def _exact_changed(new, last):
    return (np.asarray(new) != np.asarray(last)).any(axis=2)


def _covered(rects, w, h):
    mask = np.zeros((h, w), bool)
    for x0, y0, x1, y1 in rects:
        mask[y0:y1, x0:x1] = True
    return mask


def _plan(w, h, rects, seed=1, density=1.0):
    last, new = _frames(w, h, rects, seed, density)
    lw, nw = frame_words(last, w, h), frame_words(new, w, h)
    return plan_windows(nw, lw, w, h), nw, lw


def _overlap(a, b):
    return not (a[2] <= b[0] or b[2] <= a[0] or a[3] <= b[1] or b[3] <= a[1])


def test_identical_frames_plan_nothing():
    plan, _, _ = _plan(W, H, [])
    assert plan == []


def test_single_change_is_one_tight_window():
    plan, _, _ = _plan(W, H, [(110, 130, 210, 150)])
    assert plan == [(110, 130, 210, 150)]


def test_counter_and_volume_are_two_windows():
    plan, _, _ = _plan(W, H, [(110, 130, 210, 150), (240, 6, 310, 28)])
    assert plan == [(240, 6, 310, 28), (110, 130, 210, 150)]


def test_two_bands_are_two_windows():
    plan, _, _ = _plan(W, H, [(0, 0, W, 46), (0, 194, W, 240)])
    assert plan == [(0, 0, W, 46), (0, 194, W, 240)]


def test_same_rows_far_apart_split_by_column():
    plan, _, _ = _plan(W, H, [(4, 4, 30, 30), (290, 4, 316, 30)])
    assert plan == [(4, 4, 30, 30), (290, 4, 316, 30)]


def test_four_scattered_spots_are_four_windows():
    spots = [(10, 10, 34, 34), (280, 60, 304, 84), (20, 140, 44, 164), (270, 200, 294, 224)]
    plan, _, _ = _plan(W, H, spots)
    assert plan == sorted(spots, key=lambda r: (r[1], r[0]))


def test_close_rows_are_joined():
    plan, _, _ = _plan(W, H, [(0, 0, W, 9), (0, 10, W, 19)])
    assert plan == [(0, 0, W, 19)]
    plan, _, _ = _plan(W, H, [(0, 0, W, 8), (0, 10, W, 18)])
    assert plan == [(0, 0, W, 18)]


def test_narrow_far_apart_changes_merge_by_cost():
    plan, _, _ = _plan(W, H, [(100, 20, 110, 28), (100, 148, 110, 156)])
    assert plan == [(100, 20, 110, 156)]


def test_dense_run_is_not_column_split(monkeypatch):
    # A 60 percent changed band with a few short blanks: one rectangle at
    # the default fraction, several column segments when the fraction is
    # raised out of reach (so the dense shortcut is what merged them).
    rng = np.random.default_rng(5)
    last = _noise(W, H, rng)
    new = last.copy()
    for x0, x1 in ((0, 60), (100, 160), (200, 260)):
        new[100:110, x0:x1] ^= rng.integers(1, 256, (10, x1 - x0, 3), dtype=np.uint8)
    last_i, new_i = Image.fromarray(last, "RGB"), Image.fromarray(new, "RGB")
    lw, nw = frame_words(last_i, W, H), frame_words(new_i, W, H)
    changed_cols = 180
    assert changed_cols / 260 >= ddw.PLAN_DENSE_FRACTION
    assert plan_windows(nw, lw, W, H) == [(0, 100, 260, 110)]
    monkeypatch.setattr(ddw, "PLAN_DENSE_FRACTION", 0.99)
    monkeypatch.setattr(ddw, "WINDOW_FIXED_COST_US", 0.0)
    plan = plan_windows(nw, lw, W, H)
    assert len(plan) == 3


def test_too_many_rects_fall_back_to_bbox():
    spots = [(10 + 20 * (i % 3), 10 + 18 * i, 18 + 20 * (i % 3), 16 + 18 * i) for i in range(12)]
    last, new = _frames(W, H, spots)
    lw, nw = frame_words(last, W, H), frame_words(new, W, H)
    assert plan_windows(nw, lw, W, H) is None
    box = bounding_box(nw, lw, W, H)
    assert _covered([box], W, H)[_exact_changed(new, last)].all()
    ys, xs = np.nonzero(_exact_changed(new, last))
    assert box == (int(xs.min()), int(ys.min()), int(xs.max()) + 1, int(ys.max()) + 1)


def _cost(rect):
    return ddw.WINDOW_FIXED_COST_US + ddw.WINDOW_PIXEL_COST_US * (rect[2] - rect[0]) * (rect[3] - rect[1])


def test_plan_never_costs_more_than_bbox():
    scenarios = [
        [(110, 130, 210, 150)],
        [(110, 130, 210, 150), (240, 6, 310, 28)],
        [(0, 0, W, 46), (0, 194, W, 240)],
        [(4, 4, 30, 30), (290, 4, 316, 30)],
        [(10, 10, 34, 34), (280, 60, 304, 84), (20, 140, 44, 164), (270, 200, 294, 224)],
        [(100, 20, 110, 28), (100, 148, 110, 156)],
    ]
    for spec in scenarios:
        plan, nw, lw = _plan(W, H, spec)
        assert plan is not None
        assert sum(_cost(r) for r in plan) <= _cost(bounding_box(nw, lw, W, H))
    # A plan that is really several windows is strictly cheaper.
    plan, nw, lw = _plan(W, H, scenarios[4])
    assert sum(_cost(r) for r in plan) < _cost(bounding_box(nw, lw, W, H))


def test_windows_are_sorted_non_overlapping_and_in_bounds():
    plan, _, _ = _plan(W, H, [(270, 200, 294, 224), (10, 10, 34, 34), (280, 60, 304, 84), (20, 140, 44, 164)])
    assert plan == sorted(plan, key=lambda r: (r[1], r[0]))
    for i, a in enumerate(plan):
        assert 0 <= a[0] < a[2] <= W and 0 <= a[1] < a[3] <= H
        for b in plan[i + 1:]:
            assert not _overlap(a, b)


@pytest.mark.parametrize("width", [128, 100, 130, 131])
def test_word_widths(width):
    height = 40
    bpw = {128: 8, 100: 4, 130: 2, 131: 1}[width]
    last, _ = _frames(width, height, [])
    assert frame_words(last, width, height).bytes_per_word == bpw
    plan, _, _ = _plan(width, height, [(13, 7, 71, 19)])
    assert plan == [(13, 7, 71, 19)]


def test_property_coverage_superset():
    rnd = random.Random(2024)
    for case in range(200):
        w, h = rnd.randint(64, 320), rnd.randint(64, 240)
        rects = []
        for _ in range(rnd.randint(1, 6)):
            x0, y0 = rnd.randint(0, w - 2), rnd.randint(0, h - 2)
            x1, y1 = rnd.randint(x0 + 1, min(w, x0 + rnd.randint(1, 160))), rnd.randint(y0 + 1, min(h, y0 + rnd.randint(1, 80)))
            rects.append((x0, y0, x1, y1))
        density = 0.25 if rnd.random() < 0.4 else 1.0
        last, new = _frames(w, h, rects, seed=case, density=density)
        lw, nw = frame_words(last, w, h), frame_words(new, w, h)
        plan = plan_windows(nw, lw, w, h)
        windows = [bounding_box(nw, lw, w, h)] if plan is None else plan
        changed = _exact_changed(new, last)
        assert _covered(windows, w, h)[changed].all(), (case, windows)
        for i, a in enumerate(windows):
            assert 0 <= a[0] < a[2] <= w and 0 <= a[1] < a[3] <= h
            for b in windows[i + 1:]:
                assert not _overlap(a, b), (case, windows)
            x0, y0, x1, y1 = a
            assert changed[y0, x0:x1].any(), (case, a, "top edge")
            assert changed[y1 - 1, x0:x1].any(), (case, a, "bottom edge")
            assert changed[y0:y1, x0].any(), (case, a, "left edge")
            assert changed[y0:y1, x1 - 1].any(), (case, a, "right edge")


def test_numpy_missing_returns_none_and_logs_once(caplog, monkeypatch):
    monkeypatch.setattr(ddw, "_numpy_missing_logged", False)
    monkeypatch.setitem(sys.modules, "numpy", None)
    image = Image.new("RGB", (4, 4), (1, 2, 3))
    with caplog.at_level(logging.WARNING):
        assert frame_words(image, 4, 4) is None
        assert frame_words(image, 4, 4) is None
    assert len([r for r in caplog.records if "numpy" in r.message.lower()]) == 1


def test_unviewable_images_return_none():
    assert frame_words(Image.new("L", (4, 4)), 4, 4) is None
    assert frame_words(Image.new("RGB", (4, 4)), 5, 4) is None


def test_cost_constants_are_used(monkeypatch):
    spec = [(100, 20, 110, 28), (100, 148, 110, 156)]
    monkeypatch.setattr(ddw, "WINDOW_FIXED_COST_US", 0.0)
    plan, _, _ = _plan(W, H, spec)
    assert plan == [(100, 20, 110, 28), (100, 148, 110, 156)]
    monkeypatch.setattr(ddw, "WINDOW_FIXED_COST_US", 1e9)
    plan, _, _ = _plan(W, H, spec)
    assert plan == [(100, 20, 110, 156)]


def test_mismatched_frames_raise_for_the_caller_to_handle():
    a = frame_words(Image.new("RGB", (8, 8)), 8, 8)
    b = frame_words(Image.new("RGB", (16, 8)), 16, 8)
    with pytest.raises(ValueError):
        plan_windows(a, b, 8, 8)
