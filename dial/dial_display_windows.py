"""dial_display_windows.py — change-region planning for the dial display.

Given the finished panel frame and the one already on the panel, work out
which rectangles to write with the backend's windowed write so that every
changed pixel is sent and as little else as possible: the frames are diffed
a machine word at a time with numpy, changed rows are coalesced into runs
and each run into column segments, and the segments are merged greedily
wherever the fixed price of one more windowed write is more than the
unchanged pixels a merge would send. Pure planning: no hardware, no Pillow
beyond the image's own tobytes(), and numpy is imported lazily so a dial
without it can still import this module (frame_words() then reports it
once and returns None, and the caller keeps its numpy-free path).

Rectangles are (x0, y0, x1, y1) in panel pixels with x1/y1 exclusive, the
same convention as PIL's getbbox(); the caller converts to the panel's
inclusive address window.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
from typing import NamedTuple

Rect = tuple[int, int, int, int]  # (x0, y0, x1, y1), x1/y1 exclusive

# Cost model for one windowed write on the shipped panel: a fixed price per
# display_window() call (the driver's address-window and RAM-write
# transactions) plus a price per pixel sent. Measured at 32 MHz with a
# 4 KiB SPI transfer buffer; a larger buffer lowers the fixed price a
# little and both values are worth re-measuring after a bus change. The
# planner only ever compares costs, so a proportional error changes
# nothing.
WINDOW_FIXED_COST_US = 2000.0
WINDOW_PIXEL_COST_US = 0.75

# Changed-row runs separated by no more than this many unchanged rows are
# joined before anything is costed (a split there could never pay).
PLAN_ROW_JOIN_GAP = 2
# Changed-column segments within a run separated by no more than this many
# pixels are joined outright, for the same reason.
PLAN_COL_JOIN_GAP_PX = 8
# A row run with at least this fraction of its column span changed is one
# rectangle: splitting a dense run into segments costs planning time and
# saves nothing.
PLAN_DENSE_FRACTION = 0.5
# More candidate rectangles than this and the plan is abandoned for the
# single bounding box: the merge is quadratic in the count and a frame
# that scattered is cheaper sent whole anyway.
PLAN_MAX_RECTS = 8

_BYTES_PER_PIXEL = 3
# How many pixel columns at each side of a candidate are examined to find
# the first and last really changed column: a word of up to eight bytes
# touches at most four RGB pixels.
_EDGE_PROBE_PX = 4

# Logged at most once per process: a missing numpy is a one-time
# misconfiguration, not something worth a warning on every frame.
_numpy_missing_logged = False


class FrameWords(NamedTuple):
    """One panel frame's bytes, viewed two ways over the same buffer:
    *words*, one row of machine words per panel row (*bytes_per_word* wide),
    for whole-row comparisons in one vector op; and *raw*, one row of bytes
    per panel row, for the exact pixel-edge refinement."""

    words: object
    bytes_per_word: int
    raw: object


def frame_words(image, width: int, height: int) -> FrameWords | None:
    """The frame words of a panel-space RGB *image* of the given size: its
    bytes viewed as the widest integer word that divides a row, so a whole
    row compares in one vector op. Returns None when numpy is unavailable
    (logged once) or the image cannot be viewed that way (not RGB, not the
    stated size). The view owns a copy of the bytes, so it stays valid
    whatever later happens to the image."""
    global _numpy_missing_logged
    try:
        import numpy
    except ImportError:
        if not _numpy_missing_logged:
            logging.warning(
                "dial display: python3-numpy is not installed; falling back to "
                "whole-region window writes without change-region planning. "
                "Install python3-numpy to fix this."
            )
            _numpy_missing_logged = True
        return None
    if getattr(image, "mode", None) != "RGB" or tuple(image.size) != (width, height):
        return None
    row_bytes = width * _BYTES_PER_PIXEL
    if width <= 0 or height <= 0:
        return None
    bytes_per_word = 1
    for candidate in (8, 4, 2):
        if row_bytes % candidate == 0:
            bytes_per_word = candidate
            break
    dtype = {8: numpy.uint64, 4: numpy.uint32, 2: numpy.uint16, 1: numpy.uint8}[bytes_per_word]
    data = image.tobytes()
    if len(data) != row_bytes * height:
        return None
    words = numpy.frombuffer(data, dtype=dtype).reshape(height, row_bytes // bytes_per_word)
    raw = numpy.frombuffer(data, dtype=numpy.uint8).reshape(height, row_bytes)
    return FrameWords(words, bytes_per_word, raw)


def _cost(rect: Rect) -> float:
    return WINDOW_FIXED_COST_US + WINDOW_PIXEL_COST_US * (rect[2] - rect[0]) * (rect[3] - rect[1])


def _union(a: Rect, b: Rect) -> Rect:
    return (min(a[0], b[0]), min(a[1], b[1]), max(a[2], b[2]), max(a[3], b[3]))


def _intersects(a: Rect, b: Rect) -> bool:
    return not (a[2] <= b[0] or b[2] <= a[0] or a[3] <= b[1] or b[3] <= a[1])


def _runs(flags) -> list[list[int]]:
    """[start, end) runs of true values in the boolean vector *flags*."""
    import numpy

    padded = numpy.concatenate(([0], flags.astype(numpy.int8), [0]))
    edges = numpy.flatnonzero(numpy.diff(padded))
    return [[int(s), int(e)] for s, e in edges.reshape(-1, 2)]


def _join(runs: list[list[int]], gap: int) -> list[list[int]]:
    """*runs* with any two separated by no more than *gap* merged."""
    out: list[list[int]] = []
    for start, end in runs:
        if out and start - out[-1][1] <= gap:
            out[-1][1] = end
        else:
            out.append([start, end])
    return out


def _refine(new: FrameWords, last: FrameWords, ne, c0: int, y0: int, c1: int, y1: int, width: int) -> Rect:
    """The pixel rectangle tightly enclosing the changes inside the word
    box [c0, c1) x [y0, y1), which must contain at least one changed word.
    Rows are trimmed on the word comparison; the columns then start at the
    word boundary's pixel and are pulled in to the first and last pixel
    whose bytes really differ, so a window is never wider than the change
    by more than the rounding of a word."""
    import numpy

    bpw = new.bytes_per_word
    changed_rows = numpy.flatnonzero(ne[y0:y1, c0:c1].any(axis=1))
    if changed_rows.size:
        y1 = y0 + int(changed_rows[-1]) + 1
        y0 = y0 + int(changed_rows[0])
    x0 = (c0 * bpw) // 3
    x1 = min(width, -(-(c1 * bpw) // 3))
    rows = y1 - y0
    span = min(_EDGE_PROBE_PX, x1 - x0)
    if span > 0:
        block = new.raw[y0:y1, x0 * 3:(x0 + span) * 3] != last.raw[y0:y1, x0 * 3:(x0 + span) * 3]
        hit = numpy.flatnonzero(block.reshape(rows, span, 3).any(axis=(0, 2)))
        if hit.size:
            x0 += int(hit[0])
    span = min(_EDGE_PROBE_PX, x1 - x0)
    if span > 0:
        block = new.raw[y0:y1, (x1 - span) * 3:x1 * 3] != last.raw[y0:y1, (x1 - span) * 3:x1 * 3]
        hit = numpy.flatnonzero(block.reshape(rows, span, 3).any(axis=(0, 2)))
        if hit.size:
            x1 = x1 - span + int(hit[-1]) + 1
    return (x0, y0, x1, y1)


def bounding_box(new: FrameWords, last: FrameWords, width: int, height: int) -> Rect:
    """The single rectangle tightly enclosing every difference between the
    two frames (the whole frame if they do not differ at all, which the
    caller never asks about: plan_windows() has already said so)."""
    import numpy

    ne = new.words != last.words
    rows = numpy.flatnonzero(ne.any(axis=1))
    if not rows.size:
        return (0, 0, width, height)
    cols = numpy.flatnonzero(ne.any(axis=0))
    return _refine(new, last, ne, int(cols[0]), int(rows[0]), int(cols[-1]) + 1, int(rows[-1]) + 1, width)


def plan_windows(new: FrameWords, last: FrameWords, width: int, height: int) -> list[Rect] | None:
    """Rectangles (half-open, panel pixels, top to bottom, non-overlapping)
    whose union covers every pixel that differs between *new* and *last*
    (two frame_words() results of the same shape), chosen to minimise the
    modelled transmit cost; [] when the frames are identical; None when no
    plan is worth having (too many separate changes, or the plan would cost
    more than the single bounding box), in which case the caller sends
    bounding_box(). Over-covers by rounding, never misses: a word that
    differs marks every pixel it touches, then each rectangle is pulled in
    to its first and last really changed row and column."""
    import numpy

    if new.words.shape != last.words.shape or new.bytes_per_word != last.bytes_per_word:
        raise ValueError("frames are not comparable")
    bpw = new.bytes_per_word
    ne = new.words != last.words
    row_flags = ne.any(axis=1)
    if not row_flags.any():
        return []
    gap_words = -(-PLAN_COL_JOIN_GAP_PX * 3 // bpw)
    candidates: list[tuple[int, int, int, int]] = []  # word columns, then rows
    for y0, y1 in _join(_runs(row_flags), PLAN_ROW_JOIN_GAP):
        cols = ne[y0:y1].any(axis=0)
        idx = numpy.flatnonzero(cols)
        c0, c1 = int(idx[0]), int(idx[-1]) + 1
        if idx.size >= PLAN_DENSE_FRACTION * (c1 - c0):
            segments = [[c0, c1]]
        else:
            segments = _join([[s + c0, e + c0] for s, e in _runs(cols[c0:c1])], gap_words)
        for s0, s1 in segments:
            candidates.append((s0, y0, s1, y1))
        if len(candidates) > PLAN_MAX_RECTS:
            return None

    rects = [_refine(new, last, ne, c0, y0, c1, y1, width) for c0, y0, c1, y1 in candidates]
    whole = rects[0]
    for rect in rects[1:]:
        whole = _union(whole, rect)

    while len(rects) > 1:
        best, pair = 0.0, None
        for i in range(len(rects)):
            for j in range(i + 1, len(rects)):
                saving = _cost(rects[i]) + _cost(rects[j]) - _cost(_union(rects[i], rects[j]))
                if saving > best:
                    best, pair = saving, (i, j)
        if pair is None:
            break
        i, j = pair
        merged = _union(rects[i], rects[j])
        rects = [r for k, r in enumerate(rects) if k not in (i, j)] + [merged]

    # A union can grow into a neighbour: fold any overlapping pair into its
    # union until none remain. Unions only grow, so this terminates.
    merged_any = True
    while merged_any and len(rects) > 1:
        merged_any = False
        for i in range(len(rects)):
            for j in range(i + 1, len(rects)):
                if _intersects(rects[i], rects[j]):
                    merged = _union(rects[i], rects[j])
                    rects = [r for k, r in enumerate(rects) if k not in (i, j)] + [merged]
                    merged_any = True
                    break
            if merged_any:
                break

    rects.sort(key=lambda r: (r[1], r[0]))
    if sum(_cost(r) for r in rects) > _cost(whole):
        return None
    return rects
