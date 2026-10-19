"""The small SPI dial's screens, drawn with the dial's own compositor.

Frames are built the way the display manager builds them: the cover is fitted
to the panel (the blurred-backdrop transform), then the compositor draws the
screen over it. The rich layout is a 320x240 panel and the compact layout a
240x240 one, each with the physical size the profile defaults to, so the
renderer picks the same layout it does on the real panel.

Every screen the dial can show is drawn once per layout where it exists there.
Each picture is saved scaled up 2x with nearest-neighbour for print: the rich
layout in spi-dial/ and the compact layout in spi-dial/compact/, one file per
screen.
"""
from __future__ import annotations

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
from dial_touch_layout import CONTENT_COMPACT, list_layout_for, metrics_for  # noqa: E402
from dial_warning_text import (  # noqa: E402
    UPDATE_FAILED_TEXT, UPDATE_PHASE_TEXT, UPDATE_RESULT_DISMISS_TEXT, UPDATED_TEXT, UPDATING_TEXT)
from music import BY_KEY  # noqa: E402

LOGO = REPO_ROOT / "images" / "autostream-logo-centred-dark.png"
REPLAY_LOGO = REPO_ROOT / "images" / "autostream-logo-replay-dark.png"

# variant -> display profile
VARIANTS = {"rich": "ili9341_320x240", "compact": "st7789_240x240"}

# What the Info page reads on a showcase dial.
INFO_ROWS = (
    ("Dial name", "Lounge dial"), ("Firmware", "0.7.0"), ("IPv4", "192.168.1.42"),
    ("WiFi", "HomeNet"), ("Signal", "Strong"), ("Disk free", "21.4 GB"), ("SD health", "96%"),
)


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
        self.rows_per_page = list_layout_for(self.width, self.height, metrics=self.metrics).rows_per_page
        self.compositor = comp.DialDisplayCompositor()

    def artwork_base(self, track):
        """The cover fitted to the panel, as the manager caches it."""
        return self.compositor.compose(
            render_cover(track), self.width, self.height, rotate=False, bgr=False, is_artwork=True)

    def logo_base(self, replay=False):
        return load_logo(str(REPLAY_LOGO if replay else LOGO), self.width, self.height)

    def kw(self):
        return dict(rotate=False, bgr=False, metrics=self.metrics)


def now_playing(panel, track, volume, muted=False, controls=True, timer=None):
    overlay = comp.OverlayState(
        visible=controls, muted=muted, artist=track.artist, volume=volume, name=track.appliance,
        title=track.title, dots=True, album=track.album, eq_pages=not panel.compact)
    extra = {"timer_text": timer} if timer else {}
    return panel.compositor.compose(
        panel.artwork_base(track), panel.width, panel.height, is_artwork=False, overlay=overlay,
        **panel.kw(), **extra)


def idle(panel, replay=False, wifi_bars=3, wifi_style=comp.WIFI_SIGNAL):
    return panel.compositor.compose_idle(
        panel.logo_base(replay), panel.width, panel.height, wifi_bars=wifi_bars,
        wifi_style=wifi_style, **panel.kw())


def selector(panel, unauthorised=False):
    rows = [("Turntable", True, comp.PLAY_GLYPH), ("CD Player", False), ("Tape Deck", False)]
    if unauthorised:
        rows[2] = ("Tape Deck", False, comp.NOT_AUTHORISED_TEXT)
    return panel.compositor.compose_list(
        panel.width, panel.height, comp.ListState(rows=tuple(rows)),
        base=panel.artwork_base(BY_KEY["folk"]), **panel.kw())


def hint(panel, title, text):
    return panel.compositor.compose_info_value(
        panel.width, panel.height, comp.InfoValueView(label=title, value=text), **panel.kw())


def outputs(panel, page=0):
    rooms = (("Lounge", True, 45, True), ("Kitchen", True, 30, False), ("Dining Room", False, 25, False),
             ("Bedroom", False, 20, False), ("Study", True, 38, False), ("Patio", False, 30, False))
    per = panel.rows_per_page
    chosen = rooms[page * per:page * per + per]
    rows = tuple((n, False, str(v) if on else "", comp.DEFAULT_MARK if default else "")
                 for n, on, v, default in chosen)
    state = comp.ListState(rows=rows, has_prev=page > 0, has_next=(page + 1) * per < len(rooms))
    return panel.compositor.compose_list(
        panel.width, panel.height, state, base=panel.artwork_base(BY_KEY["folk"]), **panel.kw())


def output_detail(panel, selected=True):
    view = comp.OutputViewState(
        name="Turntable", output_name="Lounge" if selected else "Bedroom", selected=selected,
        level=45 if selected else None)
    return panel.compositor.compose_output(panel.width, panel.height, view, **panel.kw())


def equaliser(panel):
    view = comp.EqViewState(name="Turntable", bass_db=2, treble_db=3, loaded=True, muted=False, volume=36)
    return panel.compositor.compose_eq(panel.width, panel.height, view, **panel.kw())


def repeat_enable(panel, armed=True):
    view = comp.RepeatViewState(
        name="Turntable", layout="enable", armed=armed, line="", start_enabled=False,
        stop_enabled=False, stop_pressed=False, muted=False, volume=36, eq_pages=not panel.compact)
    return panel.compositor.compose_repeat(
        panel.width, panel.height, view, base=panel.artwork_base(BY_KEY["folk"]), **panel.kw())


def repeat_replaying(panel):
    view = comp.RepeatViewState(
        name="Turntable", layout="replaying", armed=True, line="2:00 / 18:20", start_enabled=True,
        stop_enabled=True, stop_pressed=False, muted=False, volume=36, eq_pages=not panel.compact,
        counter_second=120)
    return panel.compositor.compose_repeat(
        panel.width, panel.height, view, base=panel.artwork_base(BY_KEY["folk"]), **panel.kw())


def replay_picker(panel):
    rows = (("Turntable", False, "18:42"), ("CD Player", False, "42:10"))
    return panel.compositor.compose_list(
        panel.width, panel.height, comp.ListState(rows=rows),
        base=panel.artwork_base(BY_KEY["classical"]), **panel.kw())


def info_list(panel, page=0):
    per = panel.rows_per_page
    rows = INFO_ROWS[page * per:page * per + per]
    to_row = (lambda r: (r[0], False)) if panel.compact else (lambda r: (r[0], False, r[1]))
    state = comp.ListState(
        rows=tuple(to_row(r) for r in rows), has_prev=page > 0,
        has_next=(page + 1) * per < len(INFO_ROWS), title="Info", plain_background=True)
    return panel.compositor.compose_list(panel.width, panel.height, state, **panel.kw())


def warning(panel, view):
    return panel.compositor.compose_warning(
        panel.logo_base(), panel.width, panel.height, view, **panel.kw())


def nowifi(panel):
    return panel.compositor.compose_nowifi(
        panel.logo_base(), panel.width, panel.height, comp.NoWifiView(), **panel.kw())


def sdhealth(panel):
    return panel.compositor.compose_sdhealth(
        panel.logo_base(), panel.width, panel.height, comp.SdHealthView(percent=4), **panel.kw())


def updating(panel):
    return warning(panel, comp.WarningView(
        title=UPDATING_TEXT, message=UPDATE_PHASE_TEXT["packages"], percent=45))


def updated(panel):
    return warning(panel, comp.WarningView(
        title=UPDATED_TEXT, message="Version 0.7.0", buttons=(UPDATE_RESULT_DISMISS_TEXT,)))


def update_failed(panel):
    return warning(panel, comp.WarningView(
        title=UPDATE_FAILED_TEXT, message="Restored 0.6.0", buttons=(UPDATE_RESULT_DISMISS_TEXT,)))


def appliance_warning(panel, notice=False):
    return warning(panel, comp.WarningView(
        title="Stylus wear", message="Over 450 hours played",
        buttons=("OK" if notice else "Dismiss",), source="Turntable"))


def screens(panel):
    """(name, image) pairs for one panel; the names are file-name stems. On the
    compact layout the appliance list, the speakers, the equaliser and the
    replay timer are not reachable (see _main_zone_rects in dial_touch_layout),
    and the info page's single-field view exists on that layout only."""
    jazz = BY_KEY["jazz"]
    rich = not panel.compact
    out = [
        ("starting", panel.compositor.compose_starting(panel.width, panel.height, **panel.kw())),
        ("updating", updating(panel)),
        ("updated", updated(panel)),
        ("update-failed", update_failed(panel)),
        ("restarting", panel.compositor.compose_restarting(panel.width, panel.height, **panel.kw())),
        ("no-wifi", nowifi(panel)),
        ("sd-health", sdhealth(panel)),
        ("appliance-warning", appliance_warning(panel)),
        ("appliance-notice", appliance_warning(panel, notice=True)),
        ("idle", idle(panel)),
        ("idle-replay-available", idle(panel, replay=True)),
        ("idle-wifi-connecting", idle(panel, wifi_bars=0, wifi_style=comp.WIFI_GREY)),
        ("idle-wifi-lost", idle(panel, wifi_bars=0, wifi_style=comp.WIFI_RED)),
        ("now-playing", now_playing(panel, jazz, 42)),
        ("now-playing-muted", now_playing(panel, jazz, 42, muted=True)),
        ("now-playing-artwork-only", now_playing(panel, jazz, 42, controls=False)),
    ]
    if rich:
        out.append(("now-playing-replay-timer", now_playing(panel, jazz, 42, timer="2:00 / 18:20")))
    if rich:
        out += [
            ("appliances", selector(panel)),
            ("appliances-unauthorised", selector(panel, unauthorised=True)),
            ("not-authorised-hint", hint(
                panel, comp.NOT_AUTHORISED_TEXT, "Allow this dial in Tape Deck's web UI (Setup, Dials)")),
            ("pair-hint", hint(panel, comp.PAIR_IN_AUTOSTREAM_TEXT, "Enter the PIN in Turntable's web UI")),
            ("speakers", outputs(panel)),
            ("speaker-detail", output_detail(panel)),
            ("speaker-detail-off", output_detail(panel, selected=False)),
            ("equaliser", equaliser(panel)),
        ]
    out += [
        ("repeat-enable", repeat_enable(panel)),
        ("repeat-enable-off", repeat_enable(panel, armed=False)),
        ("replaying", repeat_replaying(panel)),
        ("replay-picker", replay_picker(panel)),
        ("info-list", info_list(panel)),
        ("info-list-more", info_list(panel, 1)),
    ]
    if panel.compact:
        out.append(("info-value", hint(panel, *INFO_ROWS[2])))
    return out


def save(images, folder: Path):
    """Write each image at 2x, nearest-neighbour; returns the paths written."""
    folder.mkdir(parents=True, exist_ok=True)
    written = []
    for name, image in images:
        path = folder / f"{name}.png"
        image.resize((image.width * 2, image.height * 2), Image.NEAREST).save(path, optimize=True)
        written.append(path)
    return written


def capture(folder: Path) -> list:
    """Write the rich layout to <folder>/spi-dial and the compact layout to
    <folder>/spi-dial/compact."""
    base = folder / "spi-dial"
    written = []
    for variant, target in (("rich", base), ("compact", base / "compact")):
        written += save(screens(Panel(variant)), target)
    return written
