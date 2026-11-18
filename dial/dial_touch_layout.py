"""dial_touch_layout.py — pure touch-zone geometry for the dial display.

This module computes the touch-zone rectangles (MUTE, DOWN, UP) and the
overlay band geometry for a given panel size, and answers hit-tests against
them. It has NO hardware imports and NO dependency on Pillow, the
compositor, or any I/O — it is arithmetic only, so it can be imported by
both:

  - the compositor (dial_display_compositor.py), to know where to draw the
    overlay bands, the artist text, the volume cluster and the zone glyphs,
    and
  - the touch session (dial_touch.py), to know which zone a raw touch
    coordinate landed in.

Both consumers MUST share this single source of truth for the geometry —
that is the entire reason this lives in its own module rather than being
duplicated. If the two ever disagreed about where a boundary sits, a user
could see one zone highlighted while a different zone actually responds to
the press.

COORDINATE SPACE: every function here works in COMPOSE-space — the same
(width, height) landscape space the compositor draws in, before the
rotate/BGR transforms in DialDisplayCompositor.compose() are applied. A
caller that receives raw touch coordinates from a rotated physical panel
must map them into compose-space (undo the rotation) before calling
hit_test(). This module knows nothing about rotation, panel drivers, or
physical mounting.

LAYOUT SELECTION: one band layout, used at every panel size — the layout is
aspect-independent, so there is no ratio threshold and no alternate shape to
select. The top and bottom `height // BAND_DIVISOR` rows are dimmed bands;
everything in between is left untouched. The top band splits into the NAME
zone (left — the appliance name; tap to open the appliance selector) and
the volume cluster (speaker glyph + master-volume number, right — this is
also the MUTE zone). The bottom band splits into DOWN (left half) and UP
(right half). The artist name, relocated to a centre-low line just above
the bottom band, is a non-actuating label with no touch zone of its own.
All panels in dial_display_profiles.py are mounted landscape and this
layout does not depend on their aspect ratio, so no other layout is
defined.

DEAD ZONES: every boundary between two adjacent controls carries a small
inert band (the "dead zone") on each side, so an imprecise tap near a
boundary hits neither neighbour rather than the wrong one. Two such
boundaries exist: between the NAME zone and the volume cluster (a gap of
2*margin, the same width used between DOWN and UP), and between DOWN and UP
themselves. The middle half of the panel (the rows strictly between the top
and bottom bands) is NOT a dead zone: it is the ARTWORK zone, a single tap
target covering the artist/title lines and the artwork around them — a tap
there hides the bands for a few seconds (see dial_display.hide_controls()).
The margin is 3px
at the 160x128 profile (the shipped panel) and scales with the panel's
short side using the same rule as dial_display_image._blur_radius_for —
margin = round(min(width, height) * 3 / 128) with a floor of 1px. This
keeps the dead-zone band feeling the same physical size across profiles
rather than shrinking to nothing on a big panel or ballooning on a small
one.

SURFACES: this module describes geometry for several hit-test geometries
(GEOMETRY_MAIN, GEOMETRY_LIST, GEOMETRY_REPEAT, GEOMETRY_IDLE, and others
below), never mixed. Each geometry's tappable rectangles live in one ordered table —
`zone_rects_for(geometry, width, height)` — that both `hit_test()` below
and the compositor's pressed-zone wash read, so the two can never disagree
about where a boundary sits. A few controls reach further for a finger than
they are drawn (see ZoneRect.reach): the top band's DOTS/NAME/OUTPUTS reach
down into the strip below the band, and the list rail's controls reach left
towards the rows, by 1/TOUCH_REACH_BAND_DIVISOR of a band either way. Only
hit_test() reads the reach; the wash stays on the drawn rect.

The MAIN geometry (`layout_for`, `zone_rects_for`) is the now-playing
screen: DOTS, NAME, OUTPUTS, MUTE, DOWN, UP, plus ARTWORK (the inter-band
strip, taps hide the bands) and the non-actuating artist and title labels.
DOTS is carved from the left of the NAME zone (whose x0 therefore starts
one band-height plus a 2*margin gap later than before); it opens the
repeat screen.

BELLS: the warning bell has four homes, each live only while the dial has a
warning to show (the touch state machine's one bell gate; a table lists a
bell ahead of whatever it overlaps, so it wins the overlap when live and the
neighbour keeps its tap when not). BAND_BELL sits at the right end of the
NAME zone, the band's full height and band_h * 3 / 4 wide
(band_bell_rect()), on every screen that shares the top band (main, repeat,
EQ); at the 160x128 reference that is (69, 0, 93, 32) over the name zone
(41, 0, 93, 32), and at 320x240 / 0.1778 mm per px it is (150, 0, 186, 48)
over (66, 0, 186, 48). DOTS_BELL is the right 34% of the compact playing
screen's dots quadrant, its full height (dots_bell_rect()): (76, 0, 114,
114) of the 240x240 compact quadrant (0, 0, 114, 114), (41, 0, 61, 61) of
the 128x128 one. IDLE_BELL and ARTWORK_BELL are both IdleLayout.info, the
corner square: (125, 3, 157, 35) at the 160x128 reference, (269, 6, 314, 51)
at 320x240 / 0.1778 mm per px. ARTWORK_BELL is the one entry of
GEOMETRY_ARTWORK_BELL, hit-tested alone while the artwork rests with no
controls drawn. The LIST geometry
(`list_layout_for`) is the appliance list (also reused,
unchanged, for the replay picker): LIST_ROW (one per visible row),
LIST_BACK, LIST_DOWN and LIST_UP. The REPEAT geometry
(`repeat_layout_for`) is the repeat screen: DOTS (reused,
pops back to main and reveals the main screen's volume overlay), NAME
(reused, opens the appliance selector), OUTPUTS (the volume readout, opens
the outputs list like the main screen — the repeat screen has no mute
control of its own), REPEAT_PLAY (the enable layout's arm/disarm row),
REPEAT_START, REPEAT_STOP, plus ARTWORK (the inter-band strip's remainder,
taps hide the bands while a replay runs). The IDLE geometry
(`idle_layout_for`) is the idle screen: IDLE_WIFI and
IDLE_BELL, two small corner squares listed first so they win the corners
they share with IDLE_REPLAY, which covers the whole panel below the top
band; IDLE_BELL is live only while the dial has a warning to show (see the
bell gate in dial_touch). GEOMETRY_INFO is the info page's own reading of
the LIST table with every LIST_ROW entry removed (its rows are display-only).
GEOMETRY_CARD1/2/3 are the warning and status cards' tables, one per button
count (CARD_BUTTON_0.. left to right); GEOMETRY_NONE is an empty table (the "Restarting..." screen has nothing
tappable at all). A
caller never mixes geometries — which one to hit-test against is decided
elsewhere
(dial_touch.TouchStateMachine.set_surface, which maps its own surface
strings onto these geometries many-to-one) — but `hit_test()` and
every per-geometry wrapper are pure functions of (x, y, width, height) and
are the ONLY hit-test functions any state machine calls.

REMAINDER POLICY: an active width does not always divide evenly between the
two zones sharing a split (DOWN and UP, after the dead-zone gap between
them is subtracted). _split computes each active zone's size with floor
division so all zones in a split are equal (or as equal as integer division
allows), then adds whatever pixels are left over into the LAST gap between
zones. Leftover pixels therefore always land in a dead zone, never in a
tappable rectangle. The union of the returned active zone rectangles plus
the implied dead-zone bands exactly tiles the panel with no gap and no
overlap.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from dial_layout_metrics import CONTENT_COMPACT, LayoutMetrics, metrics_for

# The volume cluster (speaker glyph + number, the MUTE zone) takes this
# fraction of the panel width at the right of the top band.
CLUSTER_WIDTH_NUMERATOR = 2
CLUSTER_WIDTH_DENOMINATOR = 5

class TouchZone(str, Enum):
    """The touch zones across both surfaces (see the module docstring's
    SURFACES paragraph). Compares equal to its own string value, so callers
    may use TouchZone.MUTE or the literal "mute" interchangeably.

    OUTPUTS, MUTE, DOWN, UP, NAME, DOTS: the main (now-playing) surface.
    DOTS opens the repeat screen; it is carved from the left of the NAME
    zone. OUTPUTS is the top-right volume-cluster readout, opening the
    outputs list; MUTE is the footer's own cell (see FOOTER_VOLUME_MUTE in
    the compositor).
    LIST_BACK, LIST_DOWN, LIST_UP, LIST_ROW: the selector/picker surface,
    also reused by the outputs list.
    REPEAT_PLAY, REPEAT_START, REPEAT_STOP: the repeat screen's own
    surface (plus DOTS and NAME, reused there from the main surface).
    OUTPUT_BACK, OUTPUT_TOGGLE, OUTPUT_UP, OUTPUT_DOWN: the per-output
    detail surface (plus NAME, reused from the main surface).
    IDLE_REPLAY: the idle-screen surface (the whole panel below the top
    band, when the idle affordance is showing).
    IDLE_BELL: the idle screen's own small top-right warning bell, live
    only while there is a warning to show (see IdleLayout.info); a tap
    opens the warnings card.
    BAND_BELL: the bell at the right end of the top band's name zone, on
    every screen that shares the top band (main, repeat, EQ).
    DOTS_BELL: the bell at the right of the compact playing screen's dots
    quadrant. ARTWORK_BELL: the bell in the corner of resting artwork (the
    same corner as IDLE_BELL), live on the hidden surface. All four bells
    are live only while the dial has a warning to show.
    IDLE_WIFI: the idle screen's own small top-left Wi-Fi status square,
    the mirror image of IDLE_BELL — a tap opens the info list (see
    GEOMETRY_INFO).
    CARD_BUTTON_0..2: a warning or status card's button cells, left to
    right; which action each runs is the card's own business.
    ARTWORK: the main surface's inter-band strip (between the top and
    bottom bands); a tap hides the bands for a few seconds.
    EQ_BASS_DOWN, EQ_BASS_UP, EQ_TREBLE_DOWN, EQ_TREBLE_UP: the EQ page's
    own surface (plus DOTS/NAME/OUTPUTS, reused from the main surface) --
    the bass and treble bars' own minus/plus steppers.
    """

    MUTE = "mute"
    DOWN = "down"
    UP = "up"
    NAME = "name"
    DOTS = "dots"
    LIST_BACK = "list_back"
    LIST_DOWN = "list_down"
    LIST_UP = "list_up"
    LIST_ROW = "list_row"
    REPEAT_PLAY = "repeat_play"
    REPEAT_START = "repeat_start"
    REPEAT_STOP = "repeat_stop"
    IDLE_REPLAY = "idle_replay"
    IDLE_BELL = "idle_bell"
    BAND_BELL = "band_bell"
    DOTS_BELL = "dots_bell"
    ARTWORK_BELL = "artwork_bell"
    OUTPUTS = "outputs"
    OUTPUT_BACK = "output_back"
    OUTPUT_TOGGLE = "output_toggle"
    OUTPUT_UP = "output_up"
    OUTPUT_DOWN = "output_down"
    ARTWORK = "artwork"
    EQ_BASS_DOWN = "eq_bass_down"
    EQ_BASS_UP = "eq_bass_up"
    EQ_TREBLE_DOWN = "eq_treble_down"
    EQ_TREBLE_UP = "eq_treble_up"
    IDLE_WIFI = "idle_wifi"
    CARD_BUTTON_0 = "card_button_0"
    CARD_BUTTON_1 = "card_button_1"
    CARD_BUTTON_2 = "card_button_2"


Rect = tuple[int, int, int, int]  # (x0, y0, x1, y1), x1/y1 exclusive

# The bell zones: live only while the dial has a warning to show (the one
# bell gate in the touch state machine).
BELL_ZONES = frozenset((
    TouchZone.IDLE_BELL, TouchZone.BAND_BELL, TouchZone.DOTS_BELL, TouchZone.ARTWORK_BELL,
))

# A card's button zones, left to right; dial_touch_wiring routes any of these to the
# display's card dispatch, which reads the index as the cell tapped.
CARD_BUTTON_ZONES = (TouchZone.CARD_BUTTON_0, TouchZone.CARD_BUTTON_1, TouchZone.CARD_BUTTON_2)


# Hit-test geometries. These name a geometry, not a screen: the touch layer
# maps its own surfaces onto them many-to-one (two surfaces share MAIN, two
# share LIST — see dial_touch.py's surface-to-geometry map).
GEOMETRY_MAIN = "main"
GEOMETRY_LIST = "list"
GEOMETRY_REPEAT = "repeat"
# The repeat screen's OWN replaying-layout geometry. Off the compact tier
# this is identical, byte for byte, to GEOMETRY_REPEAT — the large tiers
# share one row/start/stop table between the enable and replaying layouts —
# so the name is valid everywhere; only the compact tier gives the two
# repeat-screen states different rectangles (see _repeat_replay_zone_rects).
GEOMETRY_REPEAT_REPLAY = "repeat_replay"
GEOMETRY_IDLE = "idle"
GEOMETRY_OUTPUT = "output"
# The info page's own table: off the compact tier, the list table with
# every LIST_ROW entry removed, so a row press never arms, flashes or
# dispatches (rows are dead at the geometry level, not just in the
# manager); on compact the rows ARE tappable — this is the list table
# unchanged there, since the compact info page's own rows open a value view
# (see _info_zone_rects/info_row_tap).
GEOMETRY_INFO = "info"
# The compact info page's own drill-in, reached from a GEOMETRY_INFO row on
# that tier only: one entry, the whole panel, LIST_BACK — a tap anywhere
# returns to the list (close_list()'s existing back_to resolution already
# does the rest). Tier-agnostic and pure like every table here.
GEOMETRY_INFO_VALUE = "info_value"
# The EQ page's own table: rich/large only (see eq_layout_for/DialDisplay.
# _eq_available) -- DOTS/NAME/OUTPUTS reused from the main geometry, plus
# the bass/treble bar steppers.
GEOMETRY_EQ = "eq"
# A warning or status card's tables, one per button count (1, 2 or 3 cells
# under the message row), laid out by warning_layout_for() (a centred card
# off compact, the whole panel on it). The message row is display-only and
# has no entry.
GEOMETRY_CARD1 = "card1"
GEOMETRY_CARD2 = "card2"
GEOMETRY_CARD3 = "card3"
# The resting artwork's corner bell: one entry, the idle screen's own corner
# square. Hit-tested alone, ahead of the reveal-on-touch rule, while the
# artwork rests with no controls drawn (see the touch state machine).
GEOMETRY_ARTWORK_BELL = "artwork_bell"
# An empty table: the "Restarting..." screen has nothing tappable at all, and
# a surface mapped here can never arm a zone. Kept as a named geometry (not
# an absent one) so the surface map never has to fall back to MAIN.
GEOMETRY_NONE = "none"


@dataclass(frozen=True)
class ZoneRect:
    """One tappable rectangle on a geometry: the zone it resolves to, its
    rect in compose-space, and, for LIST_ROW only, the row index. Index is
    carried on the entry rather than encoded in the zone because only
    LIST_ROW ever has one, and the touch layer already reports (zone,
    index) as a pair. reach, when set, is the larger rect a touch lands in
    (always containing rect): the control takes a slightly-off finger
    without being drawn any bigger. Tables list reaching entries ahead of
    whatever they reach over, so first-match order settles the overlap."""

    zone: TouchZone
    rect: Rect
    index: int | None = None
    reach: Rect | None = None

    @property
    def touch_rect(self) -> Rect:
        """The rect hit_test() tests: reach when set, else rect."""
        return self.reach if self.reach is not None else self.rect


# How far a reaching control's touch rect extends past its drawn edge: this
# fraction (1/n) of the band height (see _band_reach and _rail_reach).
TOUCH_REACH_BAND_DIVISOR = 3


def _touch_reach_px(metrics: "LayoutMetrics") -> int:
    return metrics.band_h // TOUCH_REACH_BAND_DIVISOR


# The top-band bell's share of the band height, as a width at the right end
# of the name zone.
BAND_BELL_NUMERATOR = 3
BAND_BELL_DENOMINATOR = 4
# The compact dots quadrant's bell takes this share of the quadrant's width,
# at its right.
DOTS_BELL_WIDTH_PERCENT = 34


def band_bell_rect(name: Rect, band_h: int) -> Rect:
    """The top-band bell: the band's full height, band_h * 3 / 4 wide, at the
    right end of the name zone (it overlaps that zone; the name is drawn
    shorter while the bell is)."""
    w = band_h * BAND_BELL_NUMERATOR // BAND_BELL_DENOMINATOR
    return (max(name[0], name[2] - w), 0, name[2], band_h)


def dots_bell_rect(quadrant: Rect) -> Rect:
    """The compact playing screen's bell: the right DOTS_BELL_WIDTH_PERCENT of
    the dots quadrant, its full height."""
    x0, y0, x1, y1 = quadrant
    return (x1 - (x1 - x0) * DOTS_BELL_WIDTH_PERCENT // 100, y0, x1, y1)


def _band_reach(rect: Rect, metrics: "LayoutMetrics") -> Rect:
    """A top-band control's touch rect: its own columns, from its top down
    to the band's lower edge plus the reach, so a finger landing just under
    the band still takes the control rather than the strip below."""
    return (rect[0], rect[1], rect[2], metrics.band_h + _touch_reach_px(metrics))


def _rail_reach(rect: Rect, rail: Rect, metrics: "LayoutMetrics") -> Rect:
    """A list-rail control's touch rect: its own rows, from the drawn rail's
    left edge less the reach across to its own right edge."""
    return (rail[0] - _touch_reach_px(metrics), rect[1], rect[2], rect[3])


def zone_rects_for(
    geometry: str, width: int, height: int, metrics: "LayoutMetrics | None" = None,
) -> tuple[ZoneRect, ...]:
    """The ordered, tappable rectangles of *geometry* at this panel size —
    the single source both the hit-tests below and the compositor's
    pressed-zone wash read, so the two can never disagree about where a
    boundary sits. Order is hit-test order. Every rect here is a field of
    one of the *Layout dataclasses below; this function adds no geometry
    arithmetic of its own, only a view over them. metrics=None means
    metrics_for(width, height) — today's geometry. Raises KeyError for an
    unknown geometry (a programming error, never a runtime input)."""
    return _GEOMETRY_BUILDERS[geometry](width, height, metrics)


def _main_zone_rects(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
    if metrics is None:
        metrics = metrics_for(width, height)
    if metrics.content_tier == CONTENT_COMPACT:
        # The playing 2x2: pager dots top-left, mute top-right, minus/plus
        # along the bottom — no NAME (appliance selection is unreachable on
        # compact) and no ARTWORK strip (every cell is already a control).
        c = compact_layout_for(width, height, metrics=metrics)
        return (
            ZoneRect(TouchZone.DOTS_BELL, dots_bell_rect(c.tl)),
            ZoneRect(TouchZone.DOTS, c.tl),
            ZoneRect(TouchZone.MUTE, c.tr),
            ZoneRect(TouchZone.DOWN, c.bl),
            ZoneRect(TouchZone.UP, c.br),
        )
    layout = layout_for(width, height, metrics=metrics)
    return _top_band_rects(layout, metrics) + (
        ZoneRect(TouchZone.MUTE, layout.footer_mute),
        ZoneRect(TouchZone.DOWN, layout.footer_down),
        ZoneRect(TouchZone.UP, layout.footer_up),
        # Last: the bands' own zones above do not overlap this strip at
        # all, so the order only matters for readability, not correctness.
        ZoneRect(TouchZone.ARTWORK, layout.artwork),
    )


def _top_band_rects(layout, metrics: "LayoutMetrics") -> tuple[ZoneRect, ...]:
    """The top band's controls, shared by the main, repeat and EQ tables
    (any layout carrying dots/name/volume_cluster), each reaching below the
    band (see _band_reach). Listed first in every table so the reach wins
    over the artwork strip, repeat row or EQ steppers under it; the bell is
    listed ahead of the name it overlaps."""
    bell = band_bell_rect(layout.name, metrics.band_h)
    return (
        ZoneRect(TouchZone.BAND_BELL, bell, reach=_band_reach(bell, metrics)),
        ZoneRect(TouchZone.DOTS, layout.dots, reach=_band_reach(layout.dots, metrics)),
        ZoneRect(TouchZone.NAME, layout.name, reach=_band_reach(layout.name, metrics)),
        ZoneRect(TouchZone.OUTPUTS, layout.volume_cluster, reach=_band_reach(layout.volume_cluster, metrics)),
    )


def _list_zone_rects(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
    if metrics is None:
        metrics = metrics_for(width, height)
    if metrics.content_tier == CONTENT_COMPACT:
        # The replay picker: a title band over a 35/65 split — cancel and
        # "more" (next page, wrapping — see the manager's paging) in the
        # left column, the two visible rows in the right column. No LIST_UP:
        # compact never shows a previous-page control of its own — wrapping
        # makes one unnecessary.
        p = compact_picker_layout_for(width, height, metrics=metrics)
        return (
            ZoneRect(TouchZone.LIST_ROW, p.row0, 0),
            ZoneRect(TouchZone.LIST_ROW, p.row1, 1),
            ZoneRect(TouchZone.LIST_BACK, p.cancel),
            ZoneRect(TouchZone.LIST_DOWN, p.more),
        )
    layout = list_layout_for(width, height, metrics=metrics)
    rows = tuple(ZoneRect(TouchZone.LIST_ROW, rect, i) for i, rect in enumerate(layout.rows))
    if layout.rail is None:
        return rows + (
            ZoneRect(TouchZone.LIST_BACK, layout.back),
            ZoneRect(TouchZone.LIST_DOWN, layout.down),
            ZoneRect(TouchZone.LIST_UP, layout.up),
        )
    # On the rail, top to bottom: previous page, back/cancel, next page,
    # each reaching left over the rows' right ends (see _rail_reach), so
    # listed ahead of the rows.
    rail = layout.rail
    return (
        ZoneRect(TouchZone.LIST_UP, layout.rail_up, reach=_rail_reach(layout.rail_up, rail, metrics)),
        ZoneRect(TouchZone.LIST_BACK, layout.rail_cancel, reach=_rail_reach(layout.rail_cancel, rail, metrics)),
        ZoneRect(TouchZone.LIST_DOWN, layout.rail_down, reach=_rail_reach(layout.rail_down, rail, metrics)),
    ) + rows


def _repeat_zone_rects(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
    if metrics is None:
        metrics = metrics_for(width, height)
    if metrics.content_tier == CONTENT_COMPACT:
        # The repeat screen's enable layout: the back control (the pager
        # dots, same as opening it) top-left, the "Repeat Play" row spanning
        # the full bottom row — no separate cancel. The top-right cell is
        # absent from the table (dead): No NAME/OUTPUTS either — appliance
        # selection and the volume readout are unreachable on compact.
        c = compact_layout_for(width, height, metrics=metrics)
        return (
            ZoneRect(TouchZone.DOTS, c.tl),
            ZoneRect(TouchZone.REPEAT_PLAY, c.bottom_row),
        )
    layout = repeat_layout_for(width, height, metrics=metrics)
    return _top_band_rects(layout, metrics) + (
        ZoneRect(TouchZone.REPEAT_PLAY, layout.row),
        ZoneRect(TouchZone.REPEAT_START, layout.start),
        ZoneRect(TouchZone.REPEAT_STOP, layout.stop),
        # Last: the row above already owns most of the strip, so this only
        # catches the gaps between the row and the bands; a tap there is an
        # artwork tap, meaningful only while a replay runs (the display
        # decides, as for every zone here).
        ZoneRect(TouchZone.ARTWORK, layout.artwork),
    )


def _repeat_replay_zone_rects(
    width: int, height: int, metrics: "LayoutMetrics | None" = None,
) -> tuple[ZoneRect, ...]:
    """GEOMETRY_REPEAT_REPLAY: the repeat screen's OWN replaying-layout
    table. Off the compact tier this is _repeat_zone_rects() itself, byte
    for byte — the large tiers share one row/start/stop table between the
    enable and replaying layouts, so there is nothing of its own to
    describe there; only compact gives the replaying layout different
    rectangles, its own 2x2: back top-left, time top-right (display-only —
    absent from the table), Restart bottom-left, Stop bottom-right."""
    if metrics is None:
        metrics = metrics_for(width, height)
    if metrics.content_tier == CONTENT_COMPACT:
        c = compact_layout_for(width, height, metrics=metrics)
        return (
            ZoneRect(TouchZone.DOTS, c.tl),
            ZoneRect(TouchZone.REPEAT_START, c.bl),
            ZoneRect(TouchZone.REPEAT_STOP, c.br),
        )
    return _repeat_zone_rects(width, height, metrics=metrics)


def _idle_zone_rects(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
    # The two corner squares first: on rich they dip a few pixels below
    # the top band into IDLE_REPLAY's own rect, and on compact IDLE_REPLAY
    # is the whole panel — either way they overlap it, and hit_test's
    # first-match order is what gives each square its corner while leaving
    # IDLE_REPLAY's own published rect untouched.
    layout = idle_layout_for(width, height, metrics=metrics)
    return (
        ZoneRect(TouchZone.IDLE_WIFI, layout.wifi),
        ZoneRect(TouchZone.IDLE_BELL, layout.info),
        ZoneRect(TouchZone.IDLE_REPLAY, layout.replay),
    )


def _info_zone_rects(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
    """GEOMETRY_INFO: on the compact tier, the list table unchanged — the
    same picker-shaped rows _list_zone_rects already returns there, now
    tappable (see info_row_tap()); off compact, the list table with every
    LIST_ROW entry removed — the info page's rows are dead at the geometry
    level there, so a press anywhere on one lands in no entry at all (no
    arm, no flash, no dispatch). Either way the controls (rail or
    cancel/more) resolve exactly as they do on the list."""
    if metrics is None:
        metrics = metrics_for(width, height)
    if metrics.content_tier == CONTENT_COMPACT:
        return _list_zone_rects(width, height, metrics=metrics)
    return tuple(e for e in _list_zone_rects(width, height, metrics=metrics) if e.zone != TouchZone.LIST_ROW)


def _info_value_zone_rects(
    width: int, height: int, metrics: "LayoutMetrics | None" = None,
) -> tuple[ZoneRect, ...]:
    """GEOMETRY_INFO_VALUE: one entry, the whole panel, LIST_BACK — a tap
    anywhere on the compact info page's drill-in returns to the list.
    Tier-agnostic and pure; only the compact tier ever requests the screen
    that reads it."""
    return (ZoneRect(TouchZone.LIST_BACK, (0, 0, width, height)),)


def _output_zone_rects(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
    layout = output_layout_for(width, height, metrics=metrics)
    return (
        ZoneRect(TouchZone.OUTPUT_BACK, layout.back),
        ZoneRect(TouchZone.NAME, layout.name),
        ZoneRect(TouchZone.OUTPUT_TOGGLE, layout.row),
        ZoneRect(TouchZone.OUTPUT_DOWN, layout.down),
        ZoneRect(TouchZone.OUTPUT_UP, layout.up),
    )


def _eq_zone_rects(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
    """GEOMETRY_EQ: the top band's DOTS/NAME/OUTPUTS (reused from the main
    surface, same rects layout_for() itself gives them) plus the bass and
    treble bars' own minus/plus steppers. The caption/track area between
    each bar's two controls is non-actuating -- there is no zone for it."""
    if metrics is None:
        metrics = metrics_for(width, height)
    layout = eq_layout_for(width, height, metrics=metrics)
    return _top_band_rects(layout, metrics) + (
        ZoneRect(TouchZone.EQ_BASS_DOWN, layout.bass.down),
        ZoneRect(TouchZone.EQ_BASS_UP, layout.bass.up),
        ZoneRect(TouchZone.EQ_TREBLE_DOWN, layout.treble.down),
        ZoneRect(TouchZone.EQ_TREBLE_UP, layout.treble.up),
    )


def _card_zone_rects(buttons: int):
    """The builder of a card's table for *buttons* cells: CARD_BUTTON_0..
    left to right. The message row is display-only."""
    def build(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
        cells = warning_layout_for(width, height, buttons, metrics=metrics).cells
        return tuple(ZoneRect(zone, cell) for zone, cell in zip(CARD_BUTTON_ZONES, cells))
    return build


def _artwork_bell_zone_rects(
    width: int, height: int, metrics: "LayoutMetrics | None" = None,
) -> tuple[ZoneRect, ...]:
    """GEOMETRY_ARTWORK_BELL: the idle screen's corner square."""
    return (ZoneRect(TouchZone.ARTWORK_BELL, idle_layout_for(width, height, metrics=metrics).info),)


def _none_zone_rects(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> tuple[ZoneRect, ...]:
    """GEOMETRY_NONE: nothing is tappable."""
    return ()


_GEOMETRY_BUILDERS = {
    GEOMETRY_MAIN: _main_zone_rects,
    GEOMETRY_LIST: _list_zone_rects,
    GEOMETRY_REPEAT: _repeat_zone_rects,
    GEOMETRY_REPEAT_REPLAY: _repeat_replay_zone_rects,
    GEOMETRY_IDLE: _idle_zone_rects,
    GEOMETRY_OUTPUT: _output_zone_rects,
    GEOMETRY_INFO: _info_zone_rects,
    GEOMETRY_INFO_VALUE: _info_value_zone_rects,
    GEOMETRY_EQ: _eq_zone_rects,
    GEOMETRY_CARD1: _card_zone_rects(1),
    GEOMETRY_CARD2: _card_zone_rects(2),
    GEOMETRY_CARD3: _card_zone_rects(3),
    GEOMETRY_ARTWORK_BELL: _artwork_bell_zone_rects,
    GEOMETRY_NONE: _none_zone_rects,
}


def hit_test(
    geometry: str, x: int, y: int, width: int, height: int, metrics: "LayoutMetrics | None" = None,
    skip: "frozenset[TouchZone]" = frozenset(),
) -> "ZoneRect | None":
    """The first table entry of *geometry* whose touch rect (see
    ZoneRect.touch_rect) contains compose-space point (x, y), or None in a
    dead zone or outside the panel. Entries for zones in *skip* (controls
    the caller has switched off) are passed over, so a touch in a reach
    they would have taken falls through to whatever lies beneath. The one
    hit-test loop every per-geometry wrapper below is built from."""
    for entry in zone_rects_for(geometry, width, height, metrics=metrics):
        if entry.zone in skip:
            continue
        x0, y0, x1, y1 = entry.touch_rect
        if x0 <= x < x1 and y0 <= y < y1:
            return entry
    return None


@dataclass(frozen=True)
class OverlayLayout:
    """Full overlay geometry for one panel size — the single source of truth
    for both where the compositor dims/draws and where the touch zones sit.
    `dots`, `name`, `volume_cluster`, `down` and `up` are exactly the
    DOTS/NAME/MUTE/DOWN/UP zone rectangles the MAIN geometry holds; `artist`,
    `title`, `album` and the two band rectangles have no corresponding
    TouchZone because they never actuate. `album` is only populated on the
    content tier with room for it; elsewhere it is None and the renderer
    draws nothing there."""

    top_band: Rect        # full-width dim region, rows [0, band_h)
    bottom_band: Rect     # full-width dim region, rows [height-band_h, height)
    dots: Rect            # the two repeat-screen dots, left of the name (== DOTS zone)
    name: Rect            # appliance name, left part of top band (== NAME zone)
    artist: Rect          # centre-low text line, just above the bottom band (non-actuating)
    title: Rect           # track title line, directly above the artist line (non-actuating)
    volume_cluster: Rect  # glyph + number, right part of top band (== MUTE zone)
    down: Rect            # bottom band, left half (two-way; kept for the repeat/detail screens)
    up: Rect              # bottom band, right half (two-way; kept for the repeat/detail screens)
    divider_x: int        # x of the vertical divider centre in the bottom band (two-way split)
    album: Rect | None = None  # album line directly above the title (large tier only); None elsewhere, non-actuating
    # Three-way main footer: minus (== DOWN zone), plus (== UP zone), mute
    # (== MUTE zone) — left, middle and right thirds respectively. down/up/
    # divider_x above keep their two-way values for the repeat and output
    # detail screens, which still show only a minus/plus pair.
    footer_down: Rect | None = None      # bottom band, left third (minus, == DOWN zone)
    footer_up: Rect | None = None        # bottom band, middle third (plus, == UP zone)
    footer_mute: Rect | None = None      # bottom band, right third (== MUTE zone)
    footer_dividers: tuple[int, ...] = ()
    artwork: Rect = (0, 0, 0, 0)          # the inter-band strip (== ARTWORK zone)


@dataclass(frozen=True)
class RepeatLayout:
    """Full repeat-screen geometry for one panel size. `dots`, `name` and
    `volume_cluster` are the identical rectangles OverlayLayout uses (same
    geometry as the main screen's top band): the dots and the name label
    stay tappable here (== the DOTS/NAME zones); the volume cluster opens
    the outputs list, same as main (== the OUTPUTS zone in
    the REPEAT geometry). `row` is the full-width middle row used by the
    enable layout's "Repeat Play" toggle (== the REPEAT_PLAY zone); `line`
    shares that same rectangle for the replaying layout's centred
    "m:ss / m:ss" position text — only one of the two layouts is ever on
    screen at a time, so the two never actually compete for it. `start`/
    `stop` are exactly the DOWN/UP zone rectangles, relabelled Restart/Stop
    text glyphs for the replaying layout."""

    dots: Rect
    name: Rect
    volume_cluster: Rect
    row: Rect
    line: Rect
    start: Rect
    stop: Rect
    divider_x: int
    top_band: Rect
    bottom_band: Rect
    # The inter-band strip behind the replaying layout's line and gaps
    # (== the ARTWORK zone on this geometry off compact).
    artwork: Rect


@dataclass(frozen=True)
class OutputLayout:
    """Full per-output detail-page geometry for one panel size — the tiered
    repeat layout's own geometry, relabelled: `back` is the header's left
    chevron (== the OUTPUT_BACK zone, reusing the DOTS rect); `name` is the
    appliance name (== the NAME zone, reused from the main surface);
    `volume_cluster` is the header's speaker+digits readout, drawn but
    never hit-tested here (display-only, like the repeat screen's own);
    `row` is the full-width toggle row (== the OUTPUT_TOGGLE zone, the same
    rectangle the repeat screen's enable row uses); `down`/`up` are the
    two-way minus/plus rectangles (== the OUTPUT_DOWN/OUTPUT_UP zones,
    identical to the main surface's own two-way `down`/`up` — no per-output
    footer thirds, this page never mutes)."""

    back: Rect
    name: Rect
    volume_cluster: Rect
    row: Rect
    down: Rect
    up: Rect
    divider_x: int
    top_band: Rect
    bottom_band: Rect


def output_layout_for(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> OutputLayout:
    """Compute the per-output detail-page geometry for a *width* x *height*
    panel — the tiered repeat layout's own toggle row and two-way minus/
    plus, under the detail page's own field names."""
    if metrics is None:
        metrics = metrics_for(width, height)
    layout = layout_for(width, height, metrics=metrics)
    repeat = repeat_layout_for(width, height, metrics=metrics)
    return OutputLayout(
        back=layout.dots,
        name=layout.name,
        volume_cluster=layout.volume_cluster,
        row=repeat.row,
        down=layout.down,
        up=layout.up,
        divider_x=layout.divider_x,
        top_band=layout.top_band,
        bottom_band=layout.bottom_band,
    )


@dataclass(frozen=True)
class InfoValueLayout:
    """The compact info page's drill-in: a small label band across the top
    (the same tight height the picker's own title band uses — font_body +
    pad) and the value rect below it, inset by the usual pad on the left,
    right and bottom."""

    label: Rect    # top band, full width, font_body + pad tall
    value: Rect    # everything below the label band, inset by pad each side


def info_value_layout_for(
    width: int, height: int, metrics: "LayoutMetrics | None" = None,
) -> InfoValueLayout:
    """Compute the compact info page's drill-in geometry for a *width* x
    *height* panel: the label band is exactly as tall as the picker's own
    title band; the value rect is everything below it, inset by pad on
    three sides (the label band already sits flush at the top). Pure and
    tier-agnostic, like every layout function here — only the compact tier
    ever opens the screen that reads it. metrics=None means
    metrics_for(width, height)."""
    if metrics is None:
        metrics = metrics_for(width, height)
    band_h = metrics.font_body + metrics.pad
    pad = metrics.pad
    return InfoValueLayout(label=(0, 0, width, band_h), value=(pad, band_h, width - pad, height))


@dataclass(frozen=True)
class IdleLayout:
    """Idle-screen geometry: a single non-actuating affordance line
    (reusing the same centre-low rect the main surface's artist line
    occupies — `affordance`), the actuating rect for the whole panel
    below the top band (`replay`, == the IDLE_REPLAY zone in
    the IDLE geometry), the small top-right square (`info`, == the
    IDLE_BELL zone) that holds the warning bell and opens the warnings card
    while the dial has one to show, and its mirror image top-left (`wifi`,
    == the IDLE_WIFI zone): the Wi-Fi status glyph, the same side as `info`,
    which opens the info list."""

    affordance: Rect
    replay: Rect
    info: Rect
    wifi: Rect = (0, 0, 0, 0)


@dataclass(frozen=True)
class ListLayout:
    """Full selector-screen geometry for one panel size — the single source
    of truth for both where the compositor draws the appliance list and
    where the selector's touch zones sit. `rows` are the LIST_ROW rectangles
    for the CURRENT page, top to bottom.

    On the base tier the list's navigation lives in a bottom bar, split
    three ways: `back`, `down` and `up` are exactly the LIST_BACK/LIST_DOWN/
    LIST_UP zone rectangles of the LIST geometry, and `bar` is the
    undivided band they live in. On a wider panel the navigation instead
    moves to a right-hand rail running the full height, so the rows can use
    the freed-up width: `bar`/`back`/`down`/`up` are then None, and `rail`/
    `rail_up`/`rail_cancel`/`rail_down` (exactly the LIST_UP/LIST_BACK/
    LIST_DOWN zone rectangles) carry the same three controls stacked
    top to bottom instead of side by side. Exactly one of the two chrome
    groups is populated for a given panel; the other is all None."""

    rows: tuple[Rect, ...]   # rows_per_page rectangles, top to bottom
    row_h: int
    rows_per_page: int
    # bottom-bar chrome (base tier); None when the rail is in use.
    bar: Rect | None                 # undivided band — back|down|up live here
    back: Rect | None                # bar, left third (== LIST_BACK zone)
    down: Rect | None                # bar, middle third (== LIST_DOWN zone)
    up: Rect | None                  # bar, right third (== LIST_UP zone)
    # right-rail chrome (rich/large tiers); None on base.
    rail: Rect | None = None         # the full-height rail column
    rail_up: Rect | None = None      # previous page  (== LIST_UP zone)
    rail_cancel: Rect | None = None  # back / cancel  (== LIST_BACK zone)
    rail_down: Rect | None = None    # next page      (== LIST_DOWN zone)


@dataclass(frozen=True)
class CompactLayout:
    """The 2x2 grid every compact-tier screen is laid out on: four cells
    (tl/tr/bl/br), the two full-width rows those cells tile (top_row/
    bottom_row, used by screens that treat a row as one control rather than
    two), and the two divider-line positions between them. Which cells a
    given screen uses, and as which zones, is each geometry table's own
    business (see the compact branches of _main_zone_rects and friends,
    below) — this dataclass only describes the grid itself."""

    tl: Rect
    tr: Rect
    bl: Rect
    br: Rect
    top_row: Rect
    bottom_row: Rect
    divider_x: int
    divider_y: int


def compact_layout_for(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> CompactLayout:
    """Compute the compact-tier 2x2 grid for a *width* x *height* panel: both
    axes are split independently with the same _split(total, margin, [1, 1])
    two-way rule the base tier's own DOWN/UP footer uses, so the grid is
    built from the one existing split primitive rather than a new rule of
    its own. metrics=None means metrics_for(width, height)."""
    if metrics is None:
        metrics = metrics_for(width, height)
    m = metrics.margin
    (x0, x1), (x2, x3) = _split(width, m, [1, 1])
    (y0, y1), (y2, y3) = _split(height, m, [1, 1])
    return CompactLayout(
        tl=(x0, y0, x1, y1), tr=(x2, y0, x3, y1),
        bl=(x0, y2, x1, y3), br=(x2, y2, x3, y3),
        top_row=(0, y0, width, y1), bottom_row=(0, y2, width, height),
        divider_x=(x1 + x2) // 2, divider_y=(y1 + y2) // 2,
    )


COMPACT_PICKER_LEFT_FRACTION = 0.35  # the controls column's share of the width


@dataclass(frozen=True)
class CompactPickerLayout:
    """The compact replay picker: a title band across the top, then a 2x2
    grid whose left column (COMPACT_PICKER_LEFT_FRACTION of the width) holds
    the cancel and "more" controls and whose right column holds the two
    visible replay targets."""

    title: Rect            # full width, rows [0, title_h)
    title_divider_y: int   # the white line under the title, centred here
    cancel: Rect            # left column, upper cell  (== LIST_BACK)
    more: Rect              # left column, lower cell  (== LIST_DOWN)
    row0: Rect              # right column, upper cell (== LIST_ROW 0)
    row1: Rect              # right column, lower cell (== LIST_ROW 1)
    divider_x: int          # the column line separating the two columns
    divider_y: int          # the line between the two grid rows


def compact_picker_layout_for(
    width: int, height: int, metrics: "LayoutMetrics | None" = None,
) -> CompactPickerLayout:
    """Compute the compact-tier replay picker's geometry: a tight title
    band (the label's own line height plus half a pad above and below) over
    a two-column grid, split left/right at COMPACT_PICKER_LEFT_FRACTION of
    the width with the usual 2*margin dead gap, and top/bottom with the same
    _split(total, margin, [1, 1]) rule the rest of the compact tier uses.
    The grid starts one dead margin below the title's own divider line, so a
    tap on that line hits nothing. metrics=None means metrics_for(width,
    height)."""
    if metrics is None:
        metrics = metrics_for(width, height)
    m = metrics.margin
    title_h = metrics.font_body + metrics.pad
    grid_y0 = title_h + m
    (r0a, r0b), (r1a, r1b) = _split(height - grid_y0, m, [1, 1])
    y0, y1, y2, y3 = grid_y0 + r0a, grid_y0 + r0b, grid_y0 + r1a, grid_y0 + r1b
    divider_x = round(width * COMPACT_PICKER_LEFT_FRACTION)
    lx1, rx0 = divider_x - m, divider_x + m
    return CompactPickerLayout(
        title=(0, 0, width, title_h), title_divider_y=title_h,
        cancel=(0, y0, lx1, y1), more=(0, y2, lx1, y3),
        row0=(rx0, y0, width, y1), row1=(rx0, y2, width, y3),
        divider_x=divider_x, divider_y=(y1 + y2) // 2,
    )


# A warning or status card's share of the panel off the compact tier. On
# compact the card is the whole panel (the 2x2 grid), so neither fraction is
# read there.
CARD_WIDTH_FRACTION = 0.74
CARD_HEIGHT_FRACTION = 0.60


@dataclass(frozen=True)
class WarningLayout:
    """A warning or status card with any number of button cells: a card (the
    whole panel on compact, a centred rectangle elsewhere) split into a
    full-width message row over `cells` (left to right), with the usual
    2*margin dead gap between every pair of neighbours, a horizontal divider
    under the message row (divider_y) and a vertical divider between each
    neighbouring pair of cells (divider_xs, one fewer than the cells,
    drawn in the bottom row only). With no cells the message row is the
    whole card and there is no divider."""

    card: Rect
    message: Rect
    cells: tuple[Rect, ...]
    divider_y: "int | None"
    divider_xs: tuple[int, ...]


def warning_layout_for(
    width: int, height: int, buttons: int, metrics: "LayoutMetrics | None" = None,
) -> WarningLayout:
    """The card geometry for *buttons* cells. The card is
    CARD_WIDTH_FRACTION x CARD_HEIGHT_FRACTION of the panel, centred (the
    whole panel on compact, where it is exactly the 2x2 grid for two
    cells); its two rows and its bottom-row cells are split with the same
    _split(total, margin, weights) rule every table here uses, offset to
    the card's origin. One cell spans the whole bottom row. No buttons is a
    notice: the message row is the whole card, with no cells, no dividers
    and no horizontal divider (divider_y is None). metrics=None means
    metrics_for(width, height)."""
    if metrics is None:
        metrics = metrics_for(width, height)
    m = metrics.margin
    if metrics.content_tier == CONTENT_COMPACT:
        card_w, card_h = width, height
    else:
        card_w = round(width * CARD_WIDTH_FRACTION)
        card_h = round(height * CARD_HEIGHT_FRACTION)
    x0 = (width - card_w) // 2
    y0 = (height - card_h) // 2
    card: Rect = (x0, y0, x0 + card_w, y0 + card_h)
    count = max(0, int(buttons))
    if count == 0:
        return WarningLayout(card=card, message=card, cells=(), divider_y=None, divider_xs=())
    (r0a, r0b), (r1a, r1b) = _split(card_h, m, [1, 1])
    bands = _split(card_w, m, [1] * count)
    return WarningLayout(
        card=card,
        message=(x0, y0 + r0a, x0 + card_w, y0 + r0b),
        cells=tuple((x0 + a, y0 + r1a, x0 + b, y0 + r1b) for a, b in bands),
        divider_y=y0 + (r0b + r1a) // 2,
        divider_xs=tuple(x0 + (bands[i][1] + bands[i + 1][0]) // 2 for i in range(count - 1)),
    )


def _split(total: int, margin: int, weights: list[int]) -> list[tuple[int, int]]:
    """Partition [0, total) into len(weights) active bands separated by
    len(weights)-1 dead-zone gaps of width 2*margin, sized proportionally to
    *weights*, with any leftover pixels (from integer-division remainders)
    folded into the final gap rather than into a band.

    Returns the active band (start, end) pairs in order — the gaps
    themselves are implied by the space between consecutive returned bands
    (and are not returned, since callers only need the tappable rectangles).
    """
    n = len(weights)
    gap_width = 2 * margin
    total_zone_width = total - (n - 1) * gap_width
    weight_sum = sum(weights)

    bases = [total_zone_width * w // weight_sum for w in weights]
    remainder = total_zone_width - sum(bases)

    bands: list[tuple[int, int]] = []
    cursor = 0
    for i, base in enumerate(bases):
        start = cursor
        end = cursor + base
        bands.append((start, end))
        cursor = end
        if i < n - 1:
            gap = gap_width + (remainder if i == n - 2 else 0)
            cursor += gap
    return bands


def layout_for(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> OverlayLayout:
    """Compute the full overlay geometry for a *width* x *height* panel.

    m and band_h come from *metrics* (metrics_for(width, height) when None
    is passed — today's geometry). Bands are a plain floor-divide of the
    panel height (no dead-zone gap of their own — the artwork above and
    below them is the "gap"); the name/cluster split and the down/up split
    each carry the usual dead-zone margins. The artist line sits centre-low,
    directly above the bottom band, with no dead-zone gap of its own (it
    never actuates, so there is nothing to protect it from). See the module
    docstring for the exact arithmetic and the pinned 160x128 reference
    numbers.
    """
    if metrics is None:
        metrics = metrics_for(width, height)
    m = metrics.margin
    band_h = metrics.band_h
    top_band: Rect = (0, 0, width, band_h)
    bottom_band: Rect = (0, height - band_h, width, height)

    cluster_w = width * CLUSTER_WIDTH_NUMERATOR // CLUSTER_WIDTH_DENOMINATOR
    # Inset by m on the left and bottom so the pressed wash never touches the
    # band edge or the name area.
    volume_cluster: Rect = (width - cluster_w + m, 0, width, band_h - m)
    # DOTS is carved from the left of the name zone, square with the band
    # height, followed by the same 2m dead-zone gap the name/cluster split
    # already used — so this is a pure subdivision of the old name rect,
    # not a size change to the overall top band.
    dots_w = band_h
    dots: Rect = (m, 0, m + dots_w, band_h)
    # The gap between the name zone and cluster is 2m, the same dead-zone
    # width used between DOWN and UP. This is the same rectangle the artist
    # text occupied before it moved centre-low.
    name: Rect = (m + dots_w + 2 * m, 0, width - cluster_w - m, band_h)

    # Centre-low line, just above the bottom band — half the band height,
    # inset by m on each side. Non-actuating: no TouchZone, no dead-zone gap.
    artist_h = band_h // 2
    artist: Rect = (m, height - band_h - artist_h, width - m, height - band_h)
    # Track title sits one line directly above the artist, same height.
    title: Rect = (m, height - band_h - 2 * artist_h, width - m, height - band_h - artist_h)
    # One more line above the title, same height, where the tier has room for
    # it: the album name. None elsewhere, so the renderer draws nothing.
    album: Rect | None = (
        (m, height - band_h - 3 * artist_h, width - m, height - band_h - 2 * artist_h)
        if metrics.has_album_line else None
    )

    (dx0, dx1), (ux0, ux1) = _split(width, m, [1, 1])
    by0 = height - band_h + m
    down: Rect = (dx0, by0, dx1, height)
    up: Rect = (ux0, by0, ux1, height)
    divider_x = (dx1 + ux0) // 2

    # Three-way main footer: minus | plus | mute, left to right. Same band
    # row (by0..height) and the same dead-zone margin rule as the two-way
    # split above, just three equal thirds instead of two halves.
    (fdx0, fdx1), (fux0, fux1), (fmx0, fmx1) = _split(width, m, [1, 1, 1])
    footer_down: Rect = (fdx0, by0, fdx1, height)
    footer_up: Rect = (fux0, by0, fux1, height)
    footer_mute: Rect = (fmx0, by0, fmx1, height)
    footer_dividers = ((fdx1 + fux0) // 2, (fux1 + fmx0) // 2)

    # The inter-band strip: the whole width, rows strictly between the two
    # dimmed bands. A tap here hides them (see the ARTWORK zone) — it never
    # overlaps a real control (the bands own everything else), so it is
    # simply the panel with the bands themselves removed.
    artwork: Rect = (0, band_h, width, height - band_h)

    return OverlayLayout(
        top_band=top_band,
        bottom_band=bottom_band,
        dots=dots,
        name=name,
        artist=artist,
        title=title,
        volume_cluster=volume_cluster,
        down=down,
        up=up,
        divider_x=divider_x,
        album=album,
        footer_down=footer_down,
        footer_up=footer_up,
        footer_mute=footer_mute,
        footer_dividers=footer_dividers,
        artwork=artwork,
    )


def list_layout_for(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> ListLayout:
    """Compute the full selector-screen geometry for a *width* x *height*
    panel.

    On the base tier (metrics.list_rail is False): rows_per_page rows tiling
    [0, height - bar_h), full width, plus a bottom bar split three ways
    (back|down|up) with the usual dead-zone margins. Row height equals the
    bar height (never below 32px on any shipped profile), which is what
    makes rows_per_page exactly 3 on every base-tier profile listed in
    dial_display_profiles.py.

    On the rich/large tiers (metrics.list_rail is True): the navigation
    moves to a right-hand rail (metrics.rail_w wide) so rows tile
    [0, width - rail_w - 2*margin) instead of the full width — the same 2m
    dead gap the header's own name/cluster split and DOWN/UP split use. The
    rail itself is split three ways top to bottom, inset by margin on the
    left the same way the bottom bar is inset by margin at the top; its
    glyphs are drawn into a centred metrics.rail_glyph-side box within each
    third, not the whole zone (see _centred_box in the compositor).
    """
    if metrics is None:
        metrics = metrics_for(width, height)
    m = metrics.margin
    row_h = metrics.row_h
    rows_per_page = metrics.rows_per_page

    if not metrics.list_rail:
        bar_h = metrics.band_h
        rows = tuple((0, i * row_h, width, (i + 1) * row_h) for i in range(rows_per_page))
        (bx0, bx1), (dx0, dx1), (ux0, ux1) = _split(width, m, [1, 1, 1])
        by0 = height - bar_h + m
        return ListLayout(
            rows=rows, row_h=row_h, rows_per_page=rows_per_page,
            bar=(0, height - bar_h, width, height),
            back=(bx0, by0, bx1, height),
            down=(dx0, by0, dx1, height),
            up=(ux0, by0, ux1, height),
        )

    rail_w = metrics.rail_w
    rows_x1 = width - rail_w - 2 * m
    rows = tuple((0, i * row_h, rows_x1, (i + 1) * row_h) for i in range(rows_per_page))
    (uy0, uy1), (cy0, cy1), (dy0, dy1) = _split(height, m, [1, 1, 1])
    rx0 = width - rail_w + m
    return ListLayout(
        rows=rows, row_h=row_h, rows_per_page=rows_per_page,
        bar=None, back=None, down=None, up=None,
        rail=(width - rail_w, 0, width, height),
        rail_up=(rx0, uy0, width, uy1),
        rail_cancel=(rx0, cy0, width, cy1),
        rail_down=(rx0, dy0, width, dy1),
    )


def repeat_layout_for(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> RepeatLayout:
    """Compute the repeat-screen geometry for a *width* x *height* panel.
    `row` is a full-width strip of height 2*band_h (64px at the reference
    160x128 profile), centred vertically between the top and bottom bands
    — it exactly fills the gap between them, so the enable layout's row
    and the replaying layout's position line always tile the panel with
    no gap against either band.
    """
    if metrics is None:
        metrics = metrics_for(width, height)
    layout = layout_for(width, height, metrics=metrics)
    m = metrics.margin
    band_h = metrics.band_h
    side = band_h * 2
    cy = height // 2
    row: Rect = (m, cy - side // 2, width - m, cy + side // 2)
    return RepeatLayout(
        dots=layout.dots,
        name=layout.name,
        volume_cluster=layout.volume_cluster,
        row=row,
        line=row,
        start=layout.down,
        stop=layout.up,
        divider_x=layout.divider_x,
        top_band=layout.top_band,
        bottom_band=layout.bottom_band,
        artwork=layout.artwork,
    )


@dataclass(frozen=True)
class EqBarLayout:
    """One bar row's geometry on the EQ page (bass or treble) — a
    band-high square stepper at each end, a caption (label left, dB right)
    in the upper half of the space between them, and a track (the dB scale
    line and its marker) in the lower half."""

    row: Rect        # the whole bar row
    down: Rect       # "-" (== EQ_*_DOWN)
    up: Rect         # "+" (== EQ_*_UP)
    caption: Rect    # upper half between the controls: label left, dB right
    track: Rect      # lower half between the controls: the track line and marker
    track_x0: int
    track_x1: int
    track_y: int
    centre_x: int


@dataclass(frozen=True)
class EqLayout:
    """Full EQ-page geometry for one panel size — rich/large only. `dots`,
    `name`, `volume_cluster` and `top_band` are exactly layout_for()'s own
    rectangles (the shared top band this page reuses, unchanged); `bass`
    and `treble` are the two bar rows filling the rest of the panel."""

    dots: Rect
    name: Rect
    volume_cluster: Rect
    top_band: Rect
    bass: EqBarLayout
    treble: EqBarLayout


def eq_layout_for(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> EqLayout:
    """Compute the EQ page's geometry: the shared top band (reused from
    layout_for(), unchanged) over two equal bar rows tiling the rest of the
    panel (_split's own dead-zone gap falls between them). Each bar's own
    controls are a band-high square at each end; the space between them
    splits into an upper caption half and a lower track half."""
    if metrics is None:
        metrics = metrics_for(width, height)
    layout = layout_for(width, height, metrics=metrics)
    m, band_h, pad = metrics.margin, metrics.band_h, metrics.pad
    (a0, a1), (b0, b1) = _split(height - band_h, m, [1, 1])

    def bar(y0: int, y1: int) -> EqBarLayout:
        ctrl = band_h
        down: Rect = (m, y0, m + ctrl, y1)
        up: Rect = (width - m - ctrl, y0, width - m, y1)
        inner_x0, inner_x1 = down[2] + 2 * m, up[0] - 2 * m
        mid = (y0 + y1) // 2
        return EqBarLayout(
            row=(m, y0, width - m, y1), down=down, up=up,
            caption=(inner_x0, y0, inner_x1, mid), track=(inner_x0, mid, inner_x1, y1),
            track_x0=inner_x0 + pad, track_x1=inner_x1 - pad, track_y=(mid + y1) // 2,
            centre_x=(inner_x0 + inner_x1) // 2,
        )

    return EqLayout(
        dots=layout.dots, name=layout.name, volume_cluster=layout.volume_cluster,
        top_band=layout.top_band,
        bass=bar(band_h + a0, band_h + a1), treble=bar(band_h + b0, band_h + b1),
    )


def idle_layout_for(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> IdleLayout:
    """Compute the idle-screen geometry: the affordance line is the same
    centre-low rectangle the main surface's (non-actuating) artist line
    occupies; replay is the whole panel below the top band — or, on the
    compact tier (which has no top band of its own to exclude), the whole
    panel; info is an 8mm-floor square in the top-right corner (the
    fingertip floor wherever density is known, else a band-high square),
    reachable on every idle dial regardless of tier or replay availability;
    wifi is the identical square mirrored into the top-left corner."""
    if metrics is None:
        metrics = metrics_for(width, height)
    layout = layout_for(width, height, metrics=metrics)
    m = metrics.margin
    side = metrics.touch_min_px if metrics.touch_min_px is not None else metrics.band_h
    info: Rect = (width - m - side, m, width - m, m + side)
    wifi: Rect = (m, m, m + side, m + side)
    if metrics.content_tier == CONTENT_COMPACT:
        return IdleLayout(affordance=layout.artist, replay=(0, 0, width, height), info=info, wifi=wifi)
    return IdleLayout(affordance=layout.artist, replay=(0, layout.top_band[3], width, height), info=info, wifi=wifi)
