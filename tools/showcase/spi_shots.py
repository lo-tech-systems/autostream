"""The small SPI dial's screens, drawn with the dial's own compositor.

Frames are built the way the display manager builds them: the cover is fitted
to the panel (the blurred-backdrop transform), then the compositor draws the
screen over it. The rich layout is a 320x240 panel and the compact layout a
240x240 one, each with the physical size the profile defaults to, so the
renderer picks the same layout it does on the real panel.

Each picture is returned at the panel's native size; the capture script also
saves it scaled up 2x with nearest-neighbour for print.
"""
from __future__ import annotations

import io
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
for _p in (str(HERE), str(REPO_ROOT / "dial"), str(REPO_ROOT / "core")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from PIL import Image  # noqa: E402

import dial_display_compositor as comp  # noqa: E402
from covers import render_cover  # noqa: E402
from dial_display_image import load_logo  # noqa: E402
from dial_display_profiles import get_profile, layout_context_for  # noqa: E402
from dial_touch_layout import CONTENT_COMPACT, metrics_for  # noqa: E402
from music import BY_KEY  # noqa: E402

LOGO = REPO_ROOT / "images" / "autostream-logo-centred-dark.png"

# variant -> display profile
VARIANTS = {"rich": "ili9341_320x240", "compact": "st7789_240x240"}


class _Cfg:
    def __init__(self, screen_type):
        self.screen_type = screen_type
        self.screen_size_inches = None
        self.layout_size = None


class Panel:
    """One panel's size and layout metrics."""

    def __init__(self, variant):
        profile = get_profile(VARIANTS[variant])
        ctx = layout_context_for(_Cfg(profile.key))
        self.variant = variant
        self.width, self.height = ctx.logical_size
        self.metrics = metrics_for(self.width, self.height, mm_per_px=ctx.mm_per_px, size_chosen=False)
        self.compact = self.metrics.content_tier == CONTENT_COMPACT
        self.compositor = comp.DialDisplayCompositor()

    def artwork_base(self, track):
        """The cover fitted to the panel, as the manager caches it."""
        return self.compositor.compose(
            render_cover(track), self.width, self.height, rotate=False, bgr=False, is_artwork=True)

    def logo_base(self):
        return load_logo(str(LOGO), self.width, self.height)


def _volume_name(name):
    return {"name": name}


def now_playing(panel, track, volume, muted=False):
    overlay = comp.OverlayState(
        visible=True, muted=muted, artist=track.artist, volume=volume, name=track.appliance,
        title=track.title, dots=True, album=track.album, eq_pages=not panel.compact)
    return panel.compositor.compose(
        panel.artwork_base(track), panel.width, panel.height, rotate=False, bgr=False,
        is_artwork=False, overlay=overlay, metrics=panel.metrics)


def idle(panel):
    return panel.compositor.compose_idle(
        panel.logo_base(), panel.width, panel.height, rotate=False, bgr=False,
        metrics=panel.metrics, wifi_bars=3)


def selector(panel):
    rows = (("Turntable", True, comp.PLAY_GLYPH), ("CD Player", False), ("Tape Deck", False))
    return panel.compositor.compose_list(
        panel.width, panel.height, comp.ListState(rows=rows), rotate=False, bgr=False,
        metrics=panel.metrics, base=panel.artwork_base(BY_KEY["folk"]))


def outputs(panel, page=0):
    rooms = (("Lounge", True, 45, True), ("Kitchen", True, 30, False), ("Dining Room", False, 25, False),
             ("Bedroom", False, 20, False), ("Study", True, 38, False), ("Patio", False, 30, False))
    chosen = rooms[page * 3:page * 3 + 3]
    rows = tuple((n, False, str(v) if on else "", comp.DEFAULT_MARK if default else "")
                 for n, on, v, default in chosen)
    return panel.compositor.compose_list(
        panel.width, panel.height, comp.ListState(rows=rows, has_prev=page > 0, has_next=page == 0),
        rotate=False, bgr=False, metrics=panel.metrics)


def output_detail(panel):
    view = comp.OutputViewState(name="Turntable", output_name="Lounge", selected=True, level=45)
    return panel.compositor.compose_output(
        panel.width, panel.height, view, rotate=False, bgr=False, metrics=panel.metrics)


def equaliser(panel):
    view = comp.EqViewState(name="Turntable", bass_db=2, treble_db=3, loaded=True, muted=False, volume=36)
    return panel.compositor.compose_eq(
        panel.width, panel.height, view, rotate=False, bgr=False, metrics=panel.metrics)


def repeat_enable(panel):
    view = comp.RepeatViewState(
        name="Turntable", layout="enable", armed=True, line="", start_enabled=False,
        stop_enabled=False, stop_pressed=False, muted=False, volume=36, eq_pages=not panel.compact)
    return panel.compositor.compose_repeat(
        panel.width, panel.height, view, rotate=False, bgr=False, metrics=panel.metrics,
        base=panel.artwork_base(BY_KEY["folk"]))


def repeat_replaying(panel):
    view = comp.RepeatViewState(
        name="Turntable", layout="replaying", armed=True, line="2:00 / 18:20", start_enabled=True,
        stop_enabled=True, stop_pressed=False, muted=False, volume=36, eq_pages=not panel.compact,
        counter_second=120)
    return panel.compositor.compose_repeat(
        panel.width, panel.height, view, rotate=False, bgr=False, metrics=panel.metrics,
        base=panel.artwork_base(BY_KEY["folk"]))


def replay_picker(panel):
    rows = (("Turntable", False, "18:42"), ("CD Player", False, "42:10"))
    return panel.compositor.compose_list(
        panel.width, panel.height, comp.ListState(rows=rows), rotate=False, bgr=False,
        metrics=panel.metrics, base=panel.artwork_base(BY_KEY["classical"]))


def screens(panel):
    """(name, image) pairs for one panel; the names are file-name stems."""
    jazz, folk, rock = BY_KEY["jazz"], BY_KEY["folk"], BY_KEY["rock"]
    out = [
        ("now-playing-jazz", now_playing(panel, jazz, 42)),
        ("now-playing-folk", now_playing(panel, folk, 36)),
        ("now-playing-rock", now_playing(panel, rock, 58)),
        ("now-playing-muted", now_playing(panel, jazz, 42, muted=True)),
        ("idle", idle(panel)),
        ("repeat-enabled", repeat_enable(panel)),
        ("replaying", repeat_replaying(panel)),
        ("replay-picker", replay_picker(panel)),
    ]
    if not panel.compact:
        out += [
            ("appliances", selector(panel)),
            ("outputs", outputs(panel)),
            ("outputs-more", outputs(panel, 1)),
            ("output-detail", output_detail(panel)),
            ("equaliser", equaliser(panel)),
        ]
    return out


def save(images, folder: Path, variant: str):
    """Write each image native and at 2x; returns the paths written."""
    written = []
    for name, image in images:
        for scale, suffix in ((1, ""), (2, "@2x")):
            shot = image if scale == 1 else image.resize(
                (image.width * scale, image.height * scale), Image.NEAREST)
            path = folder / f"spi-{name}-{variant}{suffix}.png"
            shot.save(path)
            written.append(path)
    return written


def capture(folder: Path) -> list:
    folder.mkdir(parents=True, exist_ok=True)
    written = []
    for variant in VARIANTS:
        panel = Panel(variant)
        written += save(screens(panel), folder, variant)
    return written
