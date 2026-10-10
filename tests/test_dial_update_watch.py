"""Tests for dial_update_watch.py (the update-result file reader and the
seen marker) and for the update cards' text fitting every panel size.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
_DIAL = str(REPO_ROOT / "dial")
if _DIAL not in sys.path:
    sys.path.insert(0, _DIAL)

from dial_update_watch import (  # noqa: E402
    UpdateView,
    UpdateWatcher,
    parse_update_result,
    read_seen_marker,
    read_update_result,
    write_seen_marker,
)

FULL = (
    "STATUS=failure\n"
    "PERCENT_COMPLETE=0\n"
    "MESSAGE=Update to 0.7.0 failed - restored 0.6.0\n"
    "LAST_RUN_AT=2000-01-01T01:00:00+00:00\n"
    "PHASE=rolled_back\n"
    "TAG=0.7.0\n"
    "PREVIOUS_TAG=0.6.0\n"
    "ATTEMPT=2\n"
    "MAX_ATTEMPTS=4\n"
    "ROLLED_BACK=1\n"
)


class TestParse:
    def test_parse_full_file(self):
        view = parse_update_result(FULL)
        assert view == UpdateView(
            status="failure", percent=0, message="Update to 0.7.0 failed - restored 0.6.0",
            phase="rolled_back", tag="0.7.0", previous_tag="0.6.0", attempt=2, rolled_back=True,
            last_run_at="2000-01-01T01:00:00+00:00",
        )

    def test_missing_keys_default(self):
        view = parse_update_result("STATUS=in_progress\n")
        assert view == UpdateView(status="in_progress")
        assert view.percent == 0 and view.attempt == 0 and view.rolled_back is False
        assert parse_update_result("") == UpdateView()

    def test_garbage_values_and_lines_are_tolerated(self):
        view = parse_update_result("junk\nPERCENT_COMPLETE=abc\nATTEMPT=\nROLLED_BACK=0\n#c=1\nSTATUS=success\n")
        assert (view.status, view.percent, view.attempt, view.rolled_back) == ("success", 0, 0, False)

    def test_percent_is_clamped(self):
        assert parse_update_result("PERCENT_COMPLETE=250\n").percent == 100
        assert parse_update_result("PERCENT_COMPLETE=-4\n").percent == 0

    def test_quoted_values_lose_their_quotes(self):
        assert parse_update_result('PHASE="files"\n').phase == "files"


class TestWatcher:
    def test_missing_file_is_none(self, tmp_path):
        assert read_update_result(str(tmp_path / "nope")) is None
        assert UpdateWatcher(str(tmp_path / "nope")).tick() is None

    def test_unchanged_mtime_returns_none(self, tmp_path):
        path = tmp_path / "r.env"
        path.write_text(FULL)
        watcher = UpdateWatcher(str(path))
        assert watcher.tick() == parse_update_result(FULL)
        assert watcher.tick() is None
        assert watcher.tick() is None

    def test_a_changed_file_is_read_again(self, tmp_path):
        path = tmp_path / "r.env"
        path.write_text("STATUS=in_progress\nPHASE=files\n")
        watcher = UpdateWatcher(str(path))
        assert watcher.tick().phase == "files"
        path.write_text("STATUS=in_progress\nPHASE=configure\n")
        os.utime(path, ns=(1, 2_000_000_000))
        assert watcher.tick().phase == "configure"

    def test_file_that_vanishes_then_returns_is_read_again(self, tmp_path):
        path = tmp_path / "r.env"
        path.write_text(FULL)
        watcher = UpdateWatcher(str(path))
        watcher.tick()
        path.unlink()
        assert watcher.tick() is None
        path.write_text(FULL)
        assert watcher.tick() is not None


class TestSeenMarker:
    def test_round_trip(self, tmp_path):
        path = str(tmp_path / "seen")
        assert read_seen_marker(path) == ""
        write_seen_marker("2000-01-01T01:00:00+00:00", path)
        assert read_seen_marker(path) == "2000-01-01T01:00:00+00:00"

    def test_unwritable_location_does_not_raise(self, tmp_path):
        write_seen_marker("x", str(tmp_path / "missing-dir" / "seen"))


# ---------------------------------------------------------------------------
# Text fit: every title, message and phase label of the two update cards on
# every panel size, measured with the compositor's own fit helper (the one
# that shortens text it cannot fit): none of them may be shortened.
# ---------------------------------------------------------------------------

_SIZES = [
    ("128x128 compact", 128, 128, 25.9 / 128),
    ("160x128 compact", 160, 128, 25.9 / 128),
    ("240x240 compact", 240, 240, 23.4 / 240),
    ("320x240 rich", 320, 240, 0.1778),
]


@pytest.mark.parametrize("name,width,height,mm_per_px", _SIZES, ids=[s[0] for s in _SIZES])
def test_update_card_text_fits_without_truncation(name, width, height, mm_per_px):
    pytest.importorskip("PIL.Image", reason="Pillow not installed")
    from PIL import Image, ImageDraw

    import dial_display as dd
    import dial_display_compositor as dc
    from dial_touch_layout import metrics_for, warning_layout_for

    metrics = metrics_for(width, height, mm_per_px)
    draw = ImageDraw.Draw(Image.new("RGB", (width, height)))
    readout_font = dc._load_font(metrics.font_readout)
    body_font = dc._load_font(metrics.font_body)

    def fits(text, font, avail):
        return dc._truncate_to_width(draw, text, font, avail) == text

    # The longest realistic version strings.
    tags = ("0.7.0", "0.10.12", "1.10.12")
    update_views = [
        UpdateView(status="in_progress", phase=phase, percent=50)
        for phase in list(dd.UPDATE_PHASE_TEXT) + ["verify", "never-heard-of-it", ""]
    ]
    result_views = []
    for tag in tags:
        for prev in tags:
            result_views.append(UpdateView(status="success", tag=tag, previous_tag=prev))
            result_views.append(UpdateView(status="failure", tag=tag, previous_tag=prev, rolled_back=True))
            result_views.append(UpdateView(status="failure", tag=tag, previous_tag=prev))
    result_views.append(UpdateView(status="failure"))
    result_views.append(UpdateView(status="failure", rolled_back=True))

    # The progress card has no buttons (the message row is the whole card),
    # the result card one cell; the bar leaves the width alone.
    notice = warning_layout_for(width, height, buttons=0, metrics=metrics)
    result = warning_layout_for(width, height, buttons=1, metrics=metrics)
    notice_w = (notice.message[2] - notice.message[0]) - 2 * metrics.pad
    result_w = (result.message[2] - result.message[0]) - 2 * metrics.pad
    cell_w = (result.cells[0][2] - result.cells[0][0]) - 2 * metrics.pad

    update = dd._WARNING_BY_ID["update"]
    update_result = dd._WARNING_BY_ID["update_result"]
    assert fits(dd.UPDATING_TEXT, readout_font, notice_w)
    for view in update_views:
        assert fits(update.title_for(view), readout_font, notice_w), view
        assert fits(update.message_for(view), body_font, notice_w), view
    for label in set(dd.UPDATE_PHASE_TEXT.values()) | {dd.UPDATE_PHASE_FALLBACK_TEXT}:
        assert fits(label, body_font, notice_w), label
    for text in (dd.UPDATED_TEXT, dd.UPDATE_FAILED_TEXT):
        assert fits(text, readout_font, result_w), text
    for view in result_views:
        assert fits(update_result.title_for(view), readout_font, result_w), view
        assert fits(update_result.message_for(view), body_font, result_w), view
    assert fits(dd.UPDATE_RESULT_DISMISS_TEXT, body_font, cell_w)
