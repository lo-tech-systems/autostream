"""dial_display_compositor.py — stateless frame composition for the dial
display.

The manager (dial_display.py) owns all I/O: fetching artwork, decoding it,
loading the logo file, deciding what to show and when. This module owns all
pixel work once a base image is in hand — it is the single place a frame is
actually built. It has no threading, no hardware access, no persistent
state, and no lock of its own; every call is independent of every other.

Every screen (the now-playing overlay, the repeat screen, the appliance
selector, the outputs list, the per-output detail page, the idle screen) is
drawn by one pipeline, _compose_frame(): background, then dims, then any
row highlights, then a pressed-zone wash, then the header, then the body,
then the footer, then rotate/BGR. What differs between screens is
only the data — a frozen Frame descriptor made of a background choice plus
a Header/Body/Footer triple — never the drawing order. Each of the public
entry points (compose(), compose_list(), compose_repeat(), compose_output(),
compose_idle(), compose_warning(), compose_nowifi(), compose_sdhealth(), compose_restarting()) is a thin adapter that turns its own state snapshot
(OverlayState, ListState, RepeatViewState, OutputViewState, or nothing at
all) into a Frame and hands it to the pipeline. The outputs list reuses
compose_list() outright (it is just another row list); only the detail
page (compose_output()) is new.

The main screen's own footer is three-way (FOOTER_VOLUME_MUTE: minus |
plus | mute), not the two-way minus/plus (FOOTER_VOLUME) the repeat and
per-output detail screens still use — mute moved off the header (which is
never slashed on any screen any more) into its own footer cell, with a
persistent wash while muted on top of which a genuine press adds its own
momentary wash.

Two kinds of base image reach compose():
  - Artwork: the manager hands over the RAW DECODED image plus the active
    panel (width, height) and sets is_artwork=True. compose() calls
    transform_artwork_for_panel() itself, ahead of the pipeline — a
    "finished frame" is by definition already panel-fitted, so that call
    belongs here rather than in the manager.
  - Logo: the manager calls load_logo(...) itself (file I/O, and the
    failure-to-sentinel branch is manager policy) and passes the resulting
    already-panel-sized image with is_artwork=False — compose() then just
    runs it through the pipeline (or, with no visible overlay, straight
    through the rotate/BGR tail) unchanged.

overlay=None (the default) or an OverlayState with visible=False never
enters the pipeline at all: compose() returns the panel-fitted base with
only rotate/BGR applied, a strict no-op, pixel for pixel, which is what a
dial with no touch panel always sees. This also keeps the manager's
pre-rotate artwork cache exact: a call with no overlay and no rotate/bgr
returns the very same image object it was given.

A visible overlay, the repeat screen and the selector chassis are all drawn
in compose-space — the same (width, height) coordinates
dial_touch_layout.layout_for()/list_layout_for()/repeat_layout_for()
describe, and the same ones the touch session hit-tests against — before
rotate/BGR. This is the same rotate-then-BGR logic and ordering that
previously lived in dial_display.py's _apply_frame_transform, moved here
unchanged. As before, this seam is bypassed by the backend-internal
clear()/sleep() fills, which paint directly against the backend rather than
going through the manager's _display_locked()/compose() path. sleep()'s
black fill is swap-symmetric so that is harmless; clear()'s background
colour is not — an accepted cosmetic exception, limited to the fallback
background and never artwork.

The artwork-tap reveal is a paint parameter too: compose(reveal_progress=p)
and compose_repeat(reveal_progress=p) slide the overlay's own chrome (the
dim, the glyphs, the text, the washes) off the panel by p of a band's
height while the artwork underneath stays exactly where it is, and fade
the inter-band text at 1 - p; p = 0 is exactly the ordinary frame and
p = 1 exactly the no-overlay frame. The chrome is separated from the
artwork once per frame descriptor (see RevealLayers/_reveal_layers) and
memoised, so a slide frame costs a few small region operations and never
re-renders text or glyphs. The manager owns the clock; this module never
knows a frame is part of an animation.

Text rendering (artist name, volume number) never raises: every draw or
measure call goes through _draw_text_safe()/_text_size(), which swallow any
Pillow/font exception and report failure to the caller instead. The worst
case for a text failure is a frame with the glyphs but no text — never an
exception escaping the pipeline. See _load_font() for the font fallback
chain this same discipline extends to. The pipeline itself adds no blanket
exception handling: every helper it calls already degrades gracefully on
its own, and an unrecognised Body/Footer kind is a programming error, left
to raise rather than be hidden.

The album, title and artist lines (centre-low) are drawn over arbitrary
album art, so they go through _draw_text_with_halo() rather than a plain
draw.text():
a soft, Gaussian-blurred dark glow is composited behind the text before the
text itself is drawn, so it stays legible whether the artwork behind it is
light or dark. The appliance name (top-left) sits over the dimmed top band
instead, which gives it enough contrast on its own, so it is drawn plain.
The halo is drawn per element, confined to that element's own rectangle —
never as a whole-frame effect — the same discipline _draw_glyph() applies to
the list's play marker and chevrons (rendered at a higher resolution and
downsampled with LANCZOS, so small diagonal strokes read smoothly rather
than aliasing).

compose_list() builds the appliance-selector screen (a dark chassis with a
page of rows, the current one washed, and a back|down|up bar) from a
ListState snapshot, sharing
dial_touch_layout.list_layout_for()'s geometry with dial_touch.py's
selector-surface hit-test — the same single-source-of-truth discipline the
overlay's own geometry follows. Like compose(), it applies rotate/BGR last
and never raises: a font or glyph failure degrades to a plainer row, never
an exception.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import dataclasses
import functools
import logging
from dataclasses import dataclass, field

from PIL import Image, ImageChops, ImageDraw, ImageEnhance, ImageFilter, ImageFont

from dial_display_image import transform_artwork_for_panel
from dial_touch_layout import (
    CONTENT_COMPACT,
    FONT_BODY_PX_AT_REFERENCE,
    FONT_READOUT_PX_AT_REFERENCE,
    GEOMETRY_EQ,
    GEOMETRY_LIST,
    GEOMETRY_MAIN,
    GEOMETRY_NOWIFI,
    GEOMETRY_OUTPUT,
    GEOMETRY_REPEAT,
    GEOMETRY_REPEAT_REPLAY,
    GEOMETRY_SDHEALTH,
    CompactLayout,
    CompactPickerLayout,
    LayoutMetrics,
    OverlayLayout,
    Rect,
    TouchZone,
    compact_layout_for,
    compact_picker_layout_for,
    eq_layout_for,
    idle_layout_for,
    info_value_layout_for,
    layout_for,
    list_layout_for,
    metrics_for,
    nowifi_layout_for,
    repeat_layout_for,
    scale_px,
    sdhealth_layout_for,
    warning_layout_for,
    zone_rects_for,
)

# Pillow renamed the resample enum in recent versions; fall back for older
# installs, the same guard dial_display_image.py uses for its own resizes.
try:
    _LANCZOS = Image.Resampling.LANCZOS
except AttributeError:
    _LANCZOS = Image.LANCZOS

_logger = logging.getLogger(__name__)

# Overlay dim factor: the top and bottom bands are multiplied down to this
# fraction of their brightness before the glyphs/text are drawn on top, the
# same ImageEnhance.Brightness idiom dial_display_image.py uses for the
# ambient-blur backdrop (see BACKDROP_DARKEN_PERCENT there). 0.32 reads as a
# ~68% dim — dark enough that the glyphs and the pressed-zone highlight are
# unambiguous against any artwork, while the dimmed art is still faintly
# visible behind it. Set against real hardware: 0.4 left bright album art
# competing with the glyphs. The middle half of the panel is never dimmed.
OVERLAY_DIM_FACTOR = 0.32

# Glyph stroke colour and the pressed-zone highlight fill, chosen for
# contrast against the dimmed backdrop produced by OVERLAY_DIM_FACTOR. Text
# (artist name, volume number) is drawn in the same colour — see
# _draw_text_safe().
_GLYPH_RGB = (255, 255, 255)
_PRESSED_FILL_RGB = (255, 255, 255)
_PRESSED_FILL_ALPHA = 70  # out of 255 — a translucent highlight wash.

# The current-row wash on the list chassis: the same translucent white
# wash a press uses, at a fraction of the strength, drawn under any press
# so a pressed current row still reads brighter than an unpressed one.
# Alpha 21 lifts the (16,16,16) chassis to (36,36,36): visibly lighter
# than the chassis, still darker than the (48,48,48) separators, and far
# from competing with white text or the marker.
_ROW_HIGHLIGHT_RGB = (255, 255, 255)
_ROW_HIGHLIGHT_ALPHA = 21

# A persistent STATE wash on a dimmed band (currently: the mute cell while
# muted) — stronger than the row highlight above, which was tuned for the
# undimmed list chassis and all but disappears over a dimmed footer band
# under a white glyph. 96 lifts a mid-dark dimmed region clearly above its
# surroundings while still reading as lighter, not "already pressed", under
# the separate momentary press wash (_PRESSED_FILL_ALPHA) on top of it.
_MUTE_WASH_ALPHA = 96

# Divider-line colour: pure white, matching the glyph/text colour, so the
# single boundary line between DOWN and UP reads as clean structure against
# the dimmed backdrop rather than blending into it.
_DIVIDER_RGB = (255, 255, 255)

# DejaVu Sans, installed by the dial installer via fonts-dejavu-core (see
# installer/dial/helpers.sh install_image_packages()).
DEJAVU_SANS_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"

# Text/padding/divider/halo sizes, all read from LayoutMetrics — one scale
# rule (dial_touch_layout.scale_px), computed once per compose. These two
# are kept as module constants (aliases of the layout module's reference
# tuples) purely because tests import them by name; every other reference
# size lives only in dial_touch_layout now.
_ARTIST_FONT_PX_AT_REFERENCE = FONT_BODY_PX_AT_REFERENCE[0]
_VOLUME_FONT_PX_AT_REFERENCE = FONT_READOUT_PX_AT_REFERENCE[0]

_HALO_RGBA = (0, 0, 0, 255)

# Selector chassis (compose_list) — a dark background distinct from any
# artwork, so the list unambiguously reads as a different screen.
_LIST_BG_RGB = (16, 16, 16)
_LIST_SEPARATOR_RGB = (48, 48, 48)

# Small glyphs (the selector's check mark and back/down/up chevrons) are
# drawn at this multiple of their target box size on a transparent layer,
# then downsampled with LANCZOS — antialiasing applied per glyph, not to
# the whole frame. See _draw_glyph().
_GLYPH_SUPERSAMPLE = 4

# A disabled repeat-screen label (Start/Stop when the daemon state does not
# accept that action right now) is drawn in this dimmed shade of the glyph
# colour — the same OVERLAY_DIM_FACTOR the overlay's chevrons use for their
# own disabled state.
_DIMMED_GLYPH_RGB = tuple(round(c * OVERLAY_DIM_FACTOR) for c in _GLYPH_RGB)

# The appliance selector's secondary text for an appliance that has refused
# this dial. A row carrying exactly this text is drawn dimmed throughout
# (label and secondary) so it reads as unavailable next to the live rows.
NOT_AUTHORISED_TEXT = "Not authorised"

# The compact tier's muted mute-cell: a solid wash (see the main-screen
# frame builder) plus the glyph inverted to black, so "muted" reads at a
# glance on a cell too small for the large tiers' translucent wash to read
# clearly against a white glyph.
_INVERTED_GLYPH_RGB = (0, 0, 0)

# The idle screen's Wi-Fi glyph while the link is down alternates between
# all-grey (_DIMMED_GLYPH_RGB) and this alarm red — a clear "something is
# wrong" that still reads against a dimmed logo and against the white "i".
_ALARM_RGB = (226, 62, 51)

# The No-WiFi card off the compact tier: a flat dark surface, a thin
# translucent white outline, and a soft dark drop shadow offset down-right —
# sharp (rectangular) corners throughout, no rounding.
_CARD_FILL_RGB = (24, 25, 28)
_CARD_OUTLINE_RGB = (255, 255, 255)
_CARD_OUTLINE_ALPHA = 70
_CARD_SHADOW_RGB = (0, 0, 0)
_CARD_SHADOW_ALPHA = 140

# Fraction of a compact cell's own short side a cell's centred glyph box
# occupies (0.5): 57px at the 240x240 reference, 30px at 128x128. Minus/
# plus are the one exception — they are drawn straight onto the cell rect
# via the existing _draw_minus_glyph/_draw_plus_glyph, which derive their
# own reach from the rect's own size.
_COMPACT_GLYPH_FRACTION = 0.5

# A second, smaller glyph-box fraction for the replay picker's cancel and
# "more" cells only — the whole point of moving them into the picker's own
# narrower left column is that they read as secondary controls next to the
# two visible targets, not as full-size quadrant glyphs. Every other compact
# cell keeps _COMPACT_GLYPH_FRACTION.
_COMPACT_SMALL_GLYPH_FRACTION = 0.4

# The replay picker's own title-bar text.
_COMPACT_PICKER_TITLE = "Replay"

# The No-WiFi page's fixed strings and the two centred-label screens' one line
# each: the restart screen and the boot splash.
NOWIFI_MESSAGE_TEXT = "No WiFi"
NOWIFI_DISMISS_TEXT = "Dismiss"
NOWIFI_RESTART_TEXT = "Restart"
# The SD card warning's fixed strings: a title at readout size and a body
# line at body size (the percent is filled in), over one Dismiss cell.
SDHEALTH_TITLE_TEXT = "microSD Health"
SDHEALTH_BODY_TEXT = "{percent}%: Replace Soon"
SDHEALTH_BODY_TEXT_NO_PERCENT = "Replace Soon"
SDHEALTH_DISMISS_TEXT = "Dismiss"
RESTARTING_TEXT = "Restarting..."
STARTING_TEXT = "Starting..."

# How the idle screen's Wi-Fi glyph is drawn. The manager owns the link
# state and the flash clock and passes one of these per frame, so this
# module stays stateless. WIFI_SIGNAL lights wifi_bars arcs (0 = all grey,
# byte-identical to WIFI_GREY); WIFI_GREY dims every part; WIFI_RED paints
# every part in alarm red (the offline flash's alarm half); WIFI_OFF draws
# no glyph at all (the "still connecting" flash's blank half).
WIFI_SIGNAL = "signal"
WIFI_GREY = "grey"
WIFI_RED = "red"
WIFI_OFF = "off"

@dataclass(frozen=True)
class OverlayState:
    """Immutable snapshot of what the now-playing controls overlay should
    show.

    visible: when False (or when overlay is None entirely), compose() draws
        nothing and behaves exactly as it did before this feature existed —
        this is the regression guard the existing compositor tests pin.
    pressed: the TouchZone currently being pressed, or None if no zone is
        pressed. Only meaningful when visible is True. Populated by the
        display manager from its own pressed channel at compose time, not
        published directly by the touch side.
    muted: tri-state — True draws the muted glyph variant, False the
        unmuted variant, and None (unknown, e.g. nothing selected/playing)
        also draws the unmuted variant. See _draw_speaker_glyph() for the
        rationale: "unknown" defaults to the less alarming of the two
        glyphs rather than guessing a muted state that may not be true.
    artist: the now-playing artist name, or "" to draw no artist text.
        Always safe: an empty string, a too-long string (truncated with an
        ellipsis) and a font-load failure all degrade to "no artist text",
        never an exception.
    volume: the master-volume readout (0-100), or None to draw the speaker
        glyph alone with no digits — used when nothing has been observed
        yet, or when the observation is for a different target. Appended
        after muted so positional construction in existing tests/call sites
        keeps working.
    name: the appliance's display name, or "" to draw nothing and leave the
        NAME tap-zone inert. Always visible whenever a focused/controllable
        appliance is shown — never gated on how many appliances are
        authorized. Drawn top-left with a soft halo (see
        _draw_text_with_halo()), the same as the artist line. Appended last
        so positional construction in existing tests/call sites keeps
        working.
    dots: whether the two repeat-screen pager dots are drawn, left of the
        name. False leaves the NAME text's own rect untouched — the dots
        rect is a separate zone carved out of the top band (see
        dial_touch_layout.layout_for). Appended after name/title so
        existing positional construction keeps working.
    album: the now-playing album name, or "" to draw nothing. Drawn only
        where the layout provides an album rect (the content tier with
        room for it); ignored elsewhere. Appended last so existing
        positional construction keeps working.
    eq_pages: whether a third page (the EQ page) exists for the appliance
        currently shown — draws three pager dots instead of two whenever
        `dots` is also True. False (the default, byte-identical to before
        this field existed) draws the existing two-dot glyph.
    """

    visible: bool = False
    pressed: TouchZone | None = None
    muted: bool | None = None
    artist: str = ""
    volume: int | None = None
    name: str = ""
    title: str = ""
    dots: bool = False
    album: str = ""
    eq_pages: bool = False


@dataclass(frozen=True)
class ListState:
    """Immutable snapshot of what the appliance-selector screen should show
    — the compose_list() counterpart to OverlayState. Built by the display
    manager from its SelectorState (dial_display.py) on the repaint thread;
    this module has no idea what an "appliance" is, only rows to draw.

    rows: (label, checked) pairs for the CURRENT page only — at most
        ListLayout.rows_per_page entries (3 on every shipped profile).
        checked marks the row that is CURRENT — the pipeline washes that
        row before any content is drawn (see _list_frame/_list_highlight_
        rects), rather than the body renderer drawing a marker for it. A
        row may instead be a (label, checked, secondary) triple: secondary
        is drawn right-aligned when it is a plain non-empty string (the
        replay picker's buffer length, e.g. "42:10"), or, when it is the
        PLAY_GLYPH sentinel, draws the white play marker in the row's
        marker box instead of text (the appliance selector's "playing"
        mark). A 2-tuple row is byte-identical to before this field
        existed.
    has_prev: whether a previous page exists — gates whether the LIST_UP
        chevron is drawn lit (see dial_touch_layout.ListLayout.up and the
        LIST_UP -> selector_page(-1) dispatch in dial_main.py).
    has_next: whether a next page exists — gates the LIST_DOWN chevron
        (selector_page(+1)).
    pressed: the (TouchZone, index) currently being pressed, or None. index
        is only meaningful for LIST_ROW; the other zones ignore it. Mirrors
        OverlayState.pressed for the main surface.
    title: compact only — the title band's own text. None (the default)
        draws the picker's own "Replay" title, byte-identical to before this
        field existed; a non-empty string (the info page's "Info") replaces
        it. Ignored off the compact tier, where the title band does not
        exist.
    plain_background: compact only — draws a flat chassis background with
        no dimmed base image behind it, instead of the picker's own dimmed
        current base image. False (the default) is byte-identical to before
        this field existed; the info page sets it True (nothing to dim: the
        info page has no artwork/logo base of its own to show through).
    """

    rows: tuple = ()
    has_prev: bool = False
    has_next: bool = False
    pressed: tuple[TouchZone, int | None] | None = None
    title: str | None = None
    plain_background: bool = False


class _PlayGlyphSentinel:
    """Unique marker for a ListState row's secondary slot — see ListState's
    docstring. A dedicated object (rather than a string like "play") so it
    can never collide with genuine row text."""

    def __repr__(self) -> str:
        return "PLAY_GLYPH"


PLAY_GLYPH = _PlayGlyphSentinel()


@dataclass(frozen=True)
class RepeatViewState:
    """Immutable snapshot of what the repeat screen should show — the
    compose_repeat() counterpart to OverlayState/ListState. Built by the
    display manager from its repeat-store record (dial_display.py) on the
    repeat-screen compose path; this module has no idea what a daemon state
    is, only a layout name and the fields that layout draws.

    Both layouts share the same top band the main screen's now-playing
    overlay uses (dots, name, mute/volume readout — see _draw_top_band_
    content()); `name`, `muted` and `volume` feed that shared piece, drawn
    without the main screen's halo (there is no arbitrary album art behind
    it in the enable layout, and the replaying layout's own base image is
    already dimmed there — see compose_repeat()'s `base` argument).

    name: the appliance's display name.
    layout: "enable" (a live source is playing or about to; draws the
        "Repeat Play" row) or "replaying" (draws the Restart/Stop row and
        the position line, over the current artwork/logo base image).
    armed: whether the daemon will auto-start a replay on its own — read by
        the enable layout's row marker (a hollow dot when False, solid when
        True). Meaningful in either layout, but only drawn in "enable".
    muted, volume: the top band's mute/volume readout — display-only on
        this screen (no touch zone), mirroring OverlayState.muted/volume.
    line: the centre text for the "replaying" layout ("0:00 / 3:12" style);
        ignored (nothing drawn) in "enable".
    start_enabled, stop_enabled: whether the Restart/Stop label is drawn at
        full brightness (True) or dimmed (False) — "replaying" layout only.
    stop_pressed: whether Stop is drawn with a pressed wash regardless of
        an actual touch — used while a fade-out is already in flight, so
        the button visibly reads as "already actioned, no further tap
        needed" rather than merely dimmed.
    pressed: the TouchZone currently being pressed by a genuine touch, or
        None. Mirrors OverlayState.pressed/ListState.pressed.
    eq_pages: whether a third page (the EQ page) exists for this screen's
        own appliance — draws three pager dots (the second one filled)
        instead of two. Mirrors OverlayState.eq_pages.
    counter_second: the integer second `line` was built from, for the
        "replaying" layout only (None otherwise). Data for the manager,
        which records the second each pushed frame carries; never read by
        any drawing code here, so the compositor stays stateless.
    """

    name: str
    layout: str
    armed: bool
    line: str
    start_enabled: bool
    stop_enabled: bool
    stop_pressed: bool
    muted: bool | None = None
    volume: int | None = None
    pressed: "TouchZone | None" = None
    eq_pages: bool = False
    counter_second: int | None = None


@dataclass(frozen=True)
class OutputViewState:
    """Immutable snapshot of what the per-output detail page should show —
    the compose_output() counterpart to OverlayState/RepeatViewState. Built
    by the display manager from its outputs-list state (dial_display.py) on
    the repeat-screen compose path; this module has no idea what an
    "output" is beyond a name, an on/off state and a level.

    name: the appliance's display name, drawn in the NAME zone (reused from
        the main surface) with the header's own back control (an X) in
        place of the pager dots (see Header.back).
    output_name: this output's own name — the toggle row's label.
    selected: whether this output is currently enabled — the toggle row's
        dot marker (solid when True, hollow when False, the same glyph the
        repeat screen's "Repeat Play" row uses).
    level: this output's own volume (0-100), or None when disabled (no
        level to show) — drawn in the header's readout in place of the
        master-volume digits the main/repeat screens show there. There is
        no mute concept on this page (decision: disable covers it).
    pressed: the TouchZone currently being pressed, or None. Mirrors
        OverlayState.pressed/RepeatViewState.pressed.
    """

    name: str
    output_name: str
    selected: bool
    level: "int | None" = None
    pressed: "TouchZone | None" = None


@dataclass(frozen=True)
class EqViewState:
    """Immutable snapshot of what the EQ page should show — the
    compose_eq() counterpart to RepeatViewState/OutputViewState. Built by
    the display manager from its EqScreenState (dial_display.py) on the
    repeat-screen compose path; this module has no idea what a PEQ band is,
    only two optional dB values to draw as bars.

    name: the appliance's display name, drawn in the NAME zone (reused from
        the main surface).
    bass_db, treble_db: the two bars' own current values, -6..+6, or None
        while the first fetch has not yet landed (drawn as "-" with a
        dimmed, unmarked track and dimmed controls).
    loaded: whether the first fetch has landed for this screen's appliance
        — kept alongside bass_db/treble_db rather than inferred from them
        being non-None, since a fetch can legitimately land on 0 for both.
    muted, volume: the top band's mute/volume readout — display-only on
        this page (no touch zone; the encoder still steps volume), mirroring
        RepeatViewState.muted/volume.
    pressed: the TouchZone currently being pressed, or None. Mirrors
        OverlayState.pressed/RepeatViewState.pressed.
    """

    name: str
    bass_db: "int | None"
    treble_db: "int | None"
    loaded: bool
    muted: "bool | None" = None
    volume: "int | None" = None
    pressed: "TouchZone | None" = None


@dataclass(frozen=True)
class InfoValueView:
    """Immutable snapshot of what the compact info page's drill-in should
    show — the compose_info_value() counterpart to OutputViewState. The
    manager reads the tapped field fresh from its own info state at every
    paint (see DialDisplay._display_info_value_locked), so this carries
    nothing but the two strings to draw."""

    label: str   # the field's own name, drawn small in the top band
    value: str   # the field's own value, drawn large, wrapped or shrunk to fit


@dataclass(frozen=True)
class NoWifiView:
    """Immutable snapshot of what the No-WiFi page should show — nothing
    but the pressed cell, if any: the page's text is fixed and its
    geometry comes from nowifi_layout_for()."""

    pressed: "TouchZone | None" = None


@dataclass(frozen=True)
class SdHealthView:
    """Immutable snapshot of what the SD card warning should show: the
    remaining-life percent to print (None prints the body line without
    one) and the pressed cell, if any."""

    percent: "int | None" = None
    pressed: "TouchZone | None" = None


@dataclass(frozen=True)
class WarningView:
    """Immutable snapshot of a warning page: the readout-size title, the
    optional body-size message under it (empty prints the title alone,
    centred in the whole message row), the button labels left to right,
    the touch geometry whose cells they sit in (for the press wash), the
    pressed cell, if any, and the optional progress percent (None draws no
    bar; no buttons draws a notice with no cells)."""

    title: str
    message: str = ""
    buttons: tuple[str, ...] = ()
    geometry: str = GEOMETRY_SDHEALTH
    pressed: "TouchZone | None" = None
    percent: "int | None" = None


@dataclass(frozen=True)
class RevealLayers:
    """The overlay's own contribution to one screen's frame, separated from
    the artwork it is drawn over, for the artwork-tap reveal: for each of
    the top band, the bottom band and the inter-band strip, the light the
    chrome adds on its own (`*_add`) and how much of whatever is behind it
    shows through (`*_keep`, per channel, 0..255), so that a band's pixels
    are add + keep * base / 255 wherever the band sits. Built by
    _reveal_layers() from two renders of the same frame descriptor, over
    black and over white; a pure function of that descriptor, so it is
    memoised like the glyph tiles and never depends on the base image."""

    top_band: Rect
    bottom_band: Rect
    strip: Rect
    top_add: Image.Image
    top_keep: Image.Image
    bottom_add: Image.Image
    bottom_keep: Image.Image
    strip_add: Image.Image
    strip_keep: Image.Image
    # The same layers as uint16 arrays for the numpy compositing path, plus
    # the strip rows the chrome actually touches; None when numpy is not
    # available (the Pillow path is used then). Derived from the images
    # above, so excluded from equality and repr.
    arrays: "_RevealArrays | None" = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class _RevealArrays:
    """RevealLayers' layers as (rows, cols, 3) uint16 arrays, so a slide
    frame is pure arithmetic. `strip_runs` lists the half-open row ranges
    (relative to the strip) where the chrome changes anything, that is
    where add is not 0 or keep is not 255 in some column; every other
    strip row passes the base through unchanged and is never touched."""

    top_add: object
    top_keep: object
    bottom_add: object
    bottom_keep: object
    strip_add: object
    strip_keep: object
    strip_runs: tuple


# Background sources for _new_frame(): where a frame's base image comes
# from before anything is drawn on top of it.
BG_BASE = "base"          # the caller's panel-sized image (artwork or logo)
BG_CHASSIS = "chassis"    # flat _LIST_BG_RGB fill, no caller image involved

# Body kinds — the screen-specific content between the top and bottom
# bands, dispatched through _BODY_RENDERERS.
BODY_NONE = "none"
BODY_NOW_PLAYING = "now_playing"   # title + artist lines with halo
BODY_REPEAT_ROW = "repeat_row"     # "Repeat Play" label + arm dot
BODY_TOGGLE_ROW = "toggle_row"     # a label + arm dot for any on/off row (repeat, per-output)
BODY_REPEAT_LINE = "repeat_line"   # centred "m:ss / m:ss" with halo
BODY_LIST_ROWS = "list_rows"       # selector/picker rows
BODY_IDLE_BADGE = "idle_badge"     # the idle screen's own "i" information badge
# Compact-tier (2x2) bodies — see the module's compact frame builders below.
BODY_COMPACT_CONTROLS = "compact_controls"  # the playing screen: dots/mute/minus/plus
BODY_COMPACT_LIST = "compact_list"          # the replay picker's two rows + more/cancel
BODY_COMPACT_TOGGLE = "compact_toggle"      # the repeat screen's "Repeat Play" row + cancel
BODY_COMPACT_REPLAY = "compact_replay"      # the repeat screen's time line + Restart/Stop
BODY_INFO_VALUE = "info_value"              # the compact info page's own drill-in: label + wrapped value
BODY_EQ_BARS = "eq_bars"                    # the EQ page's own bass/treble bar rows
BODY_WARNING = "warning"                    # a warning page: title (+ message) row over one or more button cells, crosshair dividers
BODY_CENTRED_LABEL = "centred_label"        # one string centred on the whole panel (the "Restarting..." screen)

# The EQ bars' own +/-6 dB range — how far the marker can travel each way
# from centre_x. Duplicated (not imported) from the appliance/manager side:
# a pure compositor constant, the same number both ends independently clamp
# to.
EQ_LIMIT_DB = 6

# Footer kinds — the bottom band's content, dispatched through
# _FOOTER_RENDERERS.
FOOTER_NONE = "none"
FOOTER_VOLUME = "volume"           # minus | plus glyphs + divider (two-way: repeat, per-output detail)
FOOTER_VOLUME_MUTE = "volume_mute"  # minus | plus | mute glyphs + two dividers (main screen, three-way)
FOOTER_LABELS = "labels"           # left | right centred labels + divider
FOOTER_LIST_BAR = "list_bar"       # back | down | up chevrons
FOOTER_LIST_RAIL = "list_rail"     # up chevron | cross | down chevron on the right rail


@dataclass(frozen=True)
class Header:
    """The top band's content: appliance name, mute/volume readout, and the
    optional pager dots that switch between the main and repeat screens.
    dots_filled=None omits the dots entirely; 0 fills the left dot, 1 the
    right one. muted is carried for compatibility but no longer selects a
    slashed readout anywhere -- mute has one home, the main screen's own
    footer glyph and wash. back=True draws a left chevron into the dots
    rect instead (the per-output detail page's own back control), taking
    priority over dots_filled. dots_count (2, the default, or 3) selects
    which pager-dots glyph is drawn -- two dots for an appliance with no EQ
    page, three (the third one filled by the EQ page itself) for one that
    has it; a value other than 3 draws the existing two-dot glyph, so every
    caller that never sets it is unaffected."""

    name: str = ""
    volume: int | None = None
    muted: bool | None = None
    dots_filled: int | None = None
    dots_count: int = 2
    back: bool = False


@dataclass(frozen=True)
class Body:
    """The screen-specific content drawn between the top and bottom bands.
    Which fields are meaningful is decided entirely by `kind` — see the
    BODY_* constants and _BODY_RENDERERS."""

    kind: str = BODY_NONE
    title: str = ""        # BODY_NOW_PLAYING; also BODY_COMPACT_LIST's own title-band text (empty -> "Replay")
    artist: str = ""       # BODY_NOW_PLAYING
    armed: bool = False    # BODY_REPEAT_ROW / BODY_TOGGLE_ROW / BODY_COMPACT_TOGGLE
    label: str = ""        # BODY_REPEAT_ROW / BODY_TOGGLE_ROW / BODY_COMPACT_TOGGLE — the row's own text
    line: str = ""         # BODY_REPEAT_LINE / BODY_COMPACT_REPLAY
    rows: tuple = ()       # BODY_LIST_ROWS / BODY_COMPACT_LIST — same row tuples ListState.rows carries
    album: str = ""        # BODY_NOW_PLAYING — drawn only where the layout has an album rect
    # Compact-tier fields — see the BODY_COMPACT_* constants above.
    muted: bool = False           # BODY_COMPACT_CONTROLS: the mute cell's inverted-wash state
    dots_lit: bool = False        # BODY_COMPACT_CONTROLS: whether the pager-dots cell is tappable
    has_more: bool = False        # BODY_COMPACT_LIST: whether the "more" chevron is lit
    start_enabled: bool = True    # BODY_COMPACT_REPLAY: Restart drawn full-brightness vs dimmed
    stop_enabled: bool = True     # BODY_COMPACT_REPLAY: Stop drawn full-brightness vs dimmed
    bass_db: "int | None" = None    # BODY_EQ_BARS
    treble_db: "int | None" = None  # BODY_EQ_BARS
    wifi_bars: int = 0            # BODY_IDLE_BADGE: lit arcs on the wifi glyph (0..3) under WIFI_SIGNAL; 0 draws it all grey
    wifi_style: str = WIFI_SIGNAL # BODY_IDLE_BADGE: WIFI_SIGNAL / WIFI_GREY / WIFI_RED / WIFI_OFF — see the constants
    buttons: tuple[str, ...] = ()  # BODY_WARNING: button labels, left to right, one per layout cell
    percent: "int | None" = None   # BODY_WARNING: progress bar under the message (0..100), None for none


@dataclass(frozen=True)
class Footer:
    """The bottom band's content. Which fields are meaningful is decided
    entirely by `kind` — see the FOOTER_* constants and _FOOTER_RENDERERS."""

    kind: str = FOOTER_NONE
    left_text: str = ""            # FOOTER_LABELS
    right_text: str = ""           # FOOTER_LABELS
    left_enabled: bool = True      # FOOTER_LABELS: full brightness vs dimmed
    right_enabled: bool = True
    has_prev: bool = False         # FOOTER_LIST_BAR: lights the up chevron
    has_next: bool = False         # FOOTER_LIST_BAR: lights the down chevron


@dataclass(frozen=True)
class Frame:
    """One screen's full content, independent of panel size — everything
    _compose_frame() needs to draw it once the chrome geometry is resolved
    from layout_for()/list_layout_for()/repeat_layout_for()."""

    background: str
    dim_top: bool = False
    dim_bottom: bool = False
    # The compact tier's own dim: the whole panel (not just the top/bottom
    # bands) scaled to OVERLAY_DIM_FACTOR — "dimmed artwork behind white
    # controls" for a screen with no undimmed band left at all. Applied
    # after dim_top/dim_bottom, before any highlight/wash/pressed rect, so
    # a compact frame need never also set those two.
    dim_all: bool = False
    pressed: tuple[Rect, ...] = ()     # rects to wash, in the order they should be drawn
    highlights: tuple[Rect, ...] = ()  # rects to wash at the row-highlight strength, under any press
    washes: tuple[tuple[Rect, int], ...] = ()  # (rect, alpha) pairs for a persistent state wash, drawn after highlights and before pressed
    # A card drawn over the dimmed background before any highlight/wash/
    # pressed rect: drop shadow, flat fill, thin outline. None (the default,
    # byte-identical to before this field existed) draws nothing. The
    # No-WiFi page off the compact tier is the one user.
    card: "Rect | None" = None
    header: Header | None = None
    body: Body = Body()
    footer: Footer = Footer()


class DialDisplayCompositor:
    """Stateless frame composer — holds no attributes that change between
    calls, so a single instance can safely be shared/reused by the manager.
    """

    def compose(
        self,
        base,
        width: int,
        height: int,
        *,
        rotate: bool,
        bgr: bool,
        is_artwork: bool,
        overlay=None,
        metrics: LayoutMetrics | None = None,
        reveal_progress: float = 0.0,
        timer_text: str | None = None,
        timer_alpha: float = 1.0,
    ):
        """Build one display-ready frame from *base*.

        base: either the raw decoded artwork image (is_artwork=True) or an
            already panel-sized base such as the logo or a previously
            fitted/cached artwork frame (is_artwork=False).
        width, height: the active panel dimensions — used to fit artwork;
            ignored when is_artwork=False since the base is assumed already
            sized.
        rotate, bgr: transform toggles applied last, in that order.
        is_artwork: when True, runs transform_artwork_for_panel(base, width,
            height) first so the result is panel-fitted.
        overlay: an OverlayState, or None. None or visible=False is a strict
            no-op (existing behaviour, byte-identical). When visible, drawn
            in compose-space before rotate/bgr — see module docstring.
        metrics: a LayoutMetrics, or None meaning metrics_for(width, height)
            — today's geometry, density-unaware. Feeds the artwork blur
            radius and every overlay scale quantity.
        reveal_progress: how far the artwork-tap reveal has run, 0.0 (the
            bands in place: exactly the frame drawn before this parameter
            existed) to 1.0 (the bands gone: exactly the no-overlay frame).
            In between, the top band's chrome is slid up and the bottom
            band's down by that fraction of their height, the artwork under
            them staying put, and the album/title/artist lines fade with it
            (see _reveal_frame). A paint parameter like the
            idle screen's flash phase: the manager owns the clock. Ignored
            on the compact tier, which has no bands to slide, and whenever
            the overlay is not drawn at all. Values outside 0..1 (or NaN)
            clamp to the nearer endpoint.
        timer_text: the replay position line shown for a short while after
            a replay is started from the idle screen's picker, drawn
            centred in the artwork between the top band and the album/
            title lines, with the same halo the repeat screen's position
            line uses, over whatever else the frame shows. None (the
            default) draws nothing and leaves the frame byte-identical.
            Ignored on the compact tier, whose controls fill the panel.
        timer_alpha: the timer line's opacity, 0.0 to 1.0, for its fade
            out. A paint parameter like reveal_progress: the manager owns
            the clock.
        """
        if base is None:
            return base

        if metrics is None:
            metrics = metrics_for(width, height)

        image = base
        if is_artwork:
            image = transform_artwork_for_panel(image, width, height, blur_radius=metrics.blur_radius)

        framed = self._compose_main(image, metrics, overlay, reveal_progress)
        if timer_text and timer_alpha > 0.0 and metrics.content_tier != CONTENT_COMPACT:
            framed = _draw_timer_line(framed, timer_text, timer_alpha, metrics)
        return _finish(framed, rotate, bgr)

    @staticmethod
    def _compose_main(image, metrics: LayoutMetrics, overlay, reveal_progress: float):
        """compose()'s own frame, in compose space (before rotate/BGR).
        May return *image* itself when nothing is drawn over it, so a
        caller that draws further must not do so in place."""
        if overlay is None or not overlay.visible:
            return image

        if metrics.content_tier == CONTENT_COMPACT:
            frame = _compact_controls_frame(overlay, image.width, image.height, metrics)
            return _compose_frame(
                image, image.width, image.height, frame, rotate=False, bgr=False, metrics=metrics,
            )
        if reveal_progress >= 1.0:
            # The bands have left the panel: the same frame a hidden overlay
            # produces, through the same call.
            return image
        frame = _now_playing_frame(overlay, image.width, image.height, metrics)
        if not reveal_progress > 0.0:
            return _compose_frame(
                image, image.width, image.height, frame, rotate=False, bgr=False, metrics=metrics,
            )
        layout = layout_for(image.width, image.height, metrics=metrics)
        layers = _reveal_layers(
            frame, image.width, image.height, metrics,
            layout.top_band, layout.bottom_band, layout.artwork,
        )
        return _reveal_frame(image, layers, reveal_progress)

    def compose_list(
        self, width: int, height: int, state: ListState, *, rotate: bool, bgr: bool,
        metrics: LayoutMetrics | None = None, base=None,
    ):
        """Build one display-ready frame for the appliance-selector screen.

        Always starts from a flat dark background (_LIST_BG_RGB) — there is
        no artwork on this screen. Draws up to ListLayout.rows_per_page rows
        (label, plus a faint wash on the row `state` marks current, and the
        play marker on rows whose secondary is PLAY_GLYPH), a 1px separator
        under each row, and the bottom back|down|up bar (dimmed like
        compose()'s bottom band, with the down/up chevrons drawn at
        OVERLAY_DIM_FACTOR brightness when no next/previous page exists).
        rotate/bgr are applied last, in the same order compose() uses.

        Shares dial_touch_layout.list_layout_for()'s geometry with
        dial_touch.py's selector-surface hit-test — the single source of
        truth for where each row and bar zone sits. Never raises: a font or
        glyph failure degrades to a plainer row, matching compose()'s own
        text-failure discipline. metrics: see compose().

        *base* is used only on the compact tier — the picker's own 2x2
        screen dims the manager's current base image behind it, same as
        every other compact screen (see _compact_list_frame); every other
        tier ignores it entirely and keeps its flat chassis background,
        byte-identical to before this parameter existed.
        """
        if metrics is None:
            metrics = metrics_for(width, height)
        if metrics.content_tier == CONTENT_COMPACT:
            return _compose_frame(
                base, width, height, _compact_list_frame(state, width, height, metrics),
                rotate=rotate, bgr=bgr, metrics=metrics,
            )
        return _compose_frame(
            None, width, height, _list_frame(state, width, height, metrics),
            rotate=rotate, bgr=bgr, metrics=metrics,
        )

    def compose_repeat(
        self, width: int, height: int, state: RepeatViewState, *, rotate: bool, bgr: bool, base=None,
        metrics: LayoutMetrics | None = None, controls: bool = True, reveal_progress: float = 0.0,
    ):
        """Build one display-ready frame for the repeat screen.

        Draws the shared top band (dots, name, mute/volume readout — see
        _draw_top_band_content()) over either a flat dark background
        (_LIST_BG_RGB, the same chassis colour as compose_list()) for the
        enable layout — the "Repeat Play" row, with a hollow or solid dot
        marker depending on `state.armed` — or, for the replaying layout,
        *base* (the current artwork frame or the logo, already panel-sized;
        None falls back to the same flat background), dimmed the same way
        compose()'s overlay dims the main screen's bands, with the
        Restart/Stop labels and the centred position line drawn on top.
        rotate/bgr are applied last, in the same order compose() uses.
        Never raises: a font, glyph or base-image failure degrades to a
        plainer frame, matching compose()'s own discipline. metrics: see
        compose().

        controls=False (only ever passed by the compact tier's own manager
        path, once its controls window has lapsed — see
        DialDisplay._compact_controls_hidden()) skips the whole pipeline and
        returns *base* itself, undimmed, with only rotate/bgr applied — bare
        artwork/logo, no header/body/footer at all. A parameter, not
        attribute state, so the compositor stays stateless either way.

        reveal_progress: the artwork-tap reveal's progress, meaningful only
        for the replaying layout off the compact tier (the enable layout
        has no artwork to reveal and the compact tier no bands): between 0
        and 1 the top and bottom bands' chrome slides off and the position
        line fades, exactly as compose() does for the now-playing overlay;
        0 (the default) is the ordinary frame and 1 the same bare frame
        controls=False gives. Ignored elsewhere.
        """
        if metrics is None:
            metrics = metrics_for(width, height)
        if not controls:
            return _finish(_new_frame(base, width, height, BG_BASE), rotate, bgr)
        frame = _repeat_frame(state, width, height, metrics)
        if (
            metrics.content_tier != CONTENT_COMPACT
            and state.layout == "replaying"
            and reveal_progress > 0.0
        ):
            if reveal_progress >= 1.0:
                # The chrome has left the panel: the same bare frame
                # controls=False produces, through the same call.
                return _finish(_new_frame(base, width, height, BG_BASE), rotate, bgr)
            layout = repeat_layout_for(width, height, metrics=metrics)
            strip = (0, layout.top_band[3], width, layout.bottom_band[1])
            layers = _reveal_layers(
                frame, width, height, metrics, layout.top_band, layout.bottom_band, strip,
            )
            return _finish(_reveal_frame(base, layers, reveal_progress), rotate, bgr)
        return _compose_frame(
            base, width, height, frame, rotate=rotate, bgr=bgr, metrics=metrics,
        )

    def compose_output(
        self, width: int, height: int, state: OutputViewState, *, rotate: bool, bgr: bool,
        metrics: LayoutMetrics | None = None,
    ):
        """Build one display-ready frame for the per-output detail page.

        A thin adapter like compose_repeat(): a dark chassis background (no
        artwork here either, matching the appliance selector/replay picker
        and the repeat screen's own enable layout), the shared top band
        with a back control (an X) in place of the pager dots (Header.back) and
        this output's own level in the readout in place of the master
        volume, the toggle row (this output's own name plus its enable
        dot, through the same renderer the repeat screen's "Repeat Play"
        row uses), and the two-way minus/plus footer (FOOTER_VOLUME, the
        same one the repeat screen's replaying layout uses) stepping this
        output's own level. rotate/bgr are applied last, in the same order
        every other compose*() call uses. Never raises: a font or glyph
        failure degrades to a plainer frame, matching every other screen's
        discipline. metrics: see compose().
        """
        if metrics is None:
            metrics = metrics_for(width, height)
        return _compose_frame(
            None, width, height, _output_frame(state, width, height, metrics),
            rotate=rotate, bgr=bgr, metrics=metrics,
        )

    def compose_eq(
        self, width: int, height: int, state: "EqViewState", *, rotate: bool, bgr: bool,
        metrics: LayoutMetrics | None = None,
    ):
        """Build one display-ready frame for the EQ page: a dark chassis
        background (no artwork: the bars fill the panel below the top
        band), the shared top band with three pager dots (the third one
        filled) and the master-volume readout (the OUTPUTS zone over it
        opens the outputs list, as on the other two pages), and the
        bass/treble bar rows (see BODY_EQ_BARS/_body_eq_bars). rotate/bgr
        are applied last, in the same order every other compose*() call
        uses. Never raises: a font or glyph failure degrades to a plainer
        frame, matching every other screen's discipline. metrics: see
        compose().
        """
        if metrics is None:
            metrics = metrics_for(width, height)
        return _compose_frame(
            None, width, height, _eq_frame(state, width, height, metrics),
            rotate=rotate, bgr=bgr, metrics=metrics,
        )

    def compose_info_value(
        self, width: int, height: int, view: InfoValueView, *, rotate: bool, bgr: bool,
        metrics: LayoutMetrics | None = None,
    ):
        """Build one display-ready frame for the compact info page's own
        drill-in: a flat chassis background (no artwork here either,
        matching the info list itself), the field name small in the top
        band and its value large and centred below, wrapped or shrunk to
        fit (see _body_info_value/_fit_value_lines). rotate/bgr are applied
        last, in the same order every other compose*() call uses. Never
        raises: a font or measuring failure degrades to nothing drawn for
        that element, matching every other screen's discipline. metrics:
        see compose()."""
        if metrics is None:
            metrics = metrics_for(width, height)
        return _compose_frame(
            None, width, height, Frame(BG_CHASSIS, body=Body(BODY_INFO_VALUE, label=view.label, line=view.value)),
            rotate=rotate, bgr=bgr, metrics=metrics,
        )

    def compose_idle(
        self, base, width: int, height: int, *, rotate: bool, bgr: bool,
        metrics: LayoutMetrics | None = None, wifi_bars: int = 0, wifi_style: str = WIFI_SIGNAL,
    ):
        """Build one display-ready frame for the idle screen: *base* — the
        logo the manager chose (the plain disc, or the replay-available
        arrows-on-disc logo when a held recording can be replayed) — with no
        volume/mute controls overlay, since nothing is playing and there is
        nothing on this screen to control, plus the small "i" information
        badge in the top-right corner and the Wi-Fi status glyph in the
        top-left one (see BODY_IDLE_BADGE) on every idle frame regardless of
        which logo is showing. wifi_style picks the glyph's look: WIFI_SIGNAL
        lights wifi_bars (0..3) arcs, 0 drawing the whole glyph dimmed;
        WIFI_GREY dims every part; WIFI_RED paints every part in alarm red;
        WIFI_OFF draws no glyph at all. The manager passes the current half of
        its offline flash here (red or off against grey), so this module
        stays stateless. *base* is assumed already panel-sized (the manager's
        own logo load). rotate/bgr are applied last, in the same order
        compose() uses. Never raises beyond a None passthrough. metrics: see
        compose()."""
        if base is None:
            return base
        return _compose_frame(
            base, width, height,
            Frame(BG_BASE, body=Body(BODY_IDLE_BADGE, wifi_bars=wifi_bars, wifi_style=wifi_style)),
            rotate=rotate, bgr=bgr, metrics=metrics,
        )

    def compose_warning(
        self, base, width: int, height: int, view: WarningView, *, rotate: bool, bgr: bool,
        metrics: LayoutMetrics | None = None,
    ):
        """Build one display-ready frame for a warning page: the current
        base image (*base*, or a flat chassis when None) dimmed to
        OVERLAY_DIM_FACTOR, then, off the compact tier, a centred card
        (Frame.card: shadow, fill, outline), and on every tier the title
        (and message, if any) over the button cells with a white
        crosshair: a horizontal line under the message row and a vertical
        line between neighbouring cells (see BODY_WARNING). The pressed
        cell, if any, carries the ordinary press wash and nothing else.
        rotate/bgr last, as always. Never raises: a font failure leaves
        the dividers and card without text. metrics: see compose()."""
        if metrics is None:
            metrics = metrics_for(width, height)
        return _compose_frame(
            base, width, height, _warning_frame(view, width, height, metrics),
            rotate=rotate, bgr=bgr, metrics=metrics,
        )

    def compose_nowifi(
        self, base, width: int, height: int, view: NoWifiView, *, rotate: bool, bgr: bool,
        metrics: LayoutMetrics | None = None,
    ):
        """The No-WiFi page as a warning frame: the fixed message over
        Dismiss | Restart. Kept for existing direct callers/tests; the
        manager paints every warning through compose_warning()."""
        return self.compose_warning(
            base, width, height,
            WarningView(
                title=NOWIFI_MESSAGE_TEXT, message="",
                buttons=(NOWIFI_DISMISS_TEXT, NOWIFI_RESTART_TEXT),
                geometry=GEOMETRY_NOWIFI, pressed=view.pressed,
            ),
            rotate=rotate, bgr=bgr, metrics=metrics,
        )

    def compose_sdhealth(
        self, base, width: int, height: int, view: SdHealthView, *, rotate: bool, bgr: bool,
        metrics: LayoutMetrics | None = None,
    ):
        """The SD card warning as a warning frame: the fixed title over a
        body line carrying the percent, and one Dismiss cell. Kept for
        existing direct callers/tests."""
        line = (
            SDHEALTH_BODY_TEXT.format(percent=view.percent)
            if view.percent is not None else SDHEALTH_BODY_TEXT_NO_PERCENT
        )
        return self.compose_warning(
            base, width, height,
            WarningView(
                title=SDHEALTH_TITLE_TEXT, message=line, buttons=(SDHEALTH_DISMISS_TEXT,),
                geometry=GEOMETRY_SDHEALTH, pressed=view.pressed,
            ),
            rotate=rotate, bgr=bgr, metrics=metrics,
        )

    def compose_restarting(
        self, width: int, height: int, *, rotate: bool, bgr: bool,
        metrics: LayoutMetrics | None = None,
    ):
        """Build the "Restarting..." frame: a flat chassis fill with the
        one string centred, identical on every tier (see
        BODY_CENTRED_LABEL). Shown from a Restart tap until the reboot
        takes the panel down. Never raises: a font failure leaves the flat
        fill alone. metrics: see compose()."""
        return self._compose_centred_label(
            width, height, RESTARTING_TEXT, rotate=rotate, bgr=bgr, metrics=metrics,
        )

    def compose_starting(
        self, width: int, height: int, *, rotate: bool, bgr: bool,
        metrics: LayoutMetrics | None = None,
    ):
        """Build the "Starting..." frame: the same flat chassis and centred
        string as compose_restarting(), with the boot splash's own text.
        The manager pushes it as the very first frame after the backend
        opens at boot, before any of its threads exist, and the first poll
        replaces it with the logo or artwork. Never raises: a font failure
        leaves the flat fill alone. metrics: see compose()."""
        return self._compose_centred_label(
            width, height, STARTING_TEXT, rotate=rotate, bgr=bgr, metrics=metrics,
        )

    def _compose_centred_label(
        self, width: int, height: int, text: str, *, rotate: bool, bgr: bool,
        metrics: LayoutMetrics | None,
    ):
        """One string centred on a flat chassis fill, identical on every
        tier — the shared body of compose_restarting()/compose_starting()
        (see BODY_CENTRED_LABEL and _body_centred_label). rotate/bgr last,
        as always."""
        if metrics is None:
            metrics = metrics_for(width, height)
        return _compose_frame(
            None, width, height, Frame(BG_CHASSIS, body=Body(BODY_CENTRED_LABEL, line=text)),
            rotate=rotate, bgr=bgr, metrics=metrics,
        )


def format_mmss(seconds: float) -> str:
    """Format *seconds* as "m:ss" — used by the repeat screen's position
    line and the replay picker's row length. Hours fold into minutes (no
    separate hour field: an hour-plus recording just reads "62:03"); a
    negative input clamps to zero rather than producing a negative string.
    Pure — no I/O, no state.
    """
    total = max(0, int(round(seconds)))
    minutes, secs = divmod(total, 60)
    return f"{minutes}:{secs:02d}"


# Test-facing shims: the compositor used to compute these itself; now every
# size-dependent number comes from a LayoutMetrics (dial_touch_layout), and
# these two names delegate to it so the existing imports keep working.
_scaled_px = scale_px


def _pad_px(width: int, height: int) -> int:
    """Padding (px) between a band's edge and the text/glyph drawn inside
    it — metrics_for(width, height).pad."""
    return metrics_for(width, height).pad


@functools.lru_cache(maxsize=16)
def _load_font(size: int):
    """Load DejaVu Sans at *size*, falling back in order: the system TTF,
    Pillow's built-in default font (sized when Pillow supports it, else
    unsized), then None meaning "text disabled". Never raises. Memoised per
    size: a font object is immutable and loading it is file I/O, so loading
    once per process is the right cost.

    Statelessness note: the compositor class itself holds no attributes and
    its output is a pure function of its inputs (see TestStatelessness).
    This cache is a memoised loader of an immutable resource, keyed only by
    size — two processes, two compositor instances, or a cleared cache all
    produce identical frames, so it does not violate that in spirit. Tests
    that need a clean slate call _reset_font_cache().
    """
    try:
        return ImageFont.truetype(DEJAVU_SANS_PATH, size)
    except Exception:
        _logger.warning(
            "dial overlay: DejaVu Sans TTF unavailable at %r, falling back "
            "to Pillow's default font", DEJAVU_SANS_PATH,
        )

    try:
        return ImageFont.load_default(size=size)
    except TypeError:
        # Older Pillow: load_default() takes no size argument at all.
        try:
            return ImageFont.load_default()
        except Exception:
            pass
    except Exception:
        pass

    _logger.warning("dial overlay: Pillow's default font is unavailable; overlay text disabled")
    return None


def _reset_font_cache() -> None:
    """Clear the memoised font cache, and with it the glyph-tile and
    halo-layer caches — a font swap changes the font object identity the
    halo cache keys on, but clearing here too keeps every memo's state
    obviously consistent rather than relying on that alone. Test-only hook:
    lets a test exercise the fallback chain from a clean slate without
    restarting the process."""
    _load_font.cache_clear()
    _reset_render_caches()


def _draw_top_band_content(
    frame: Image.Image,
    *,
    dots_rect,
    dots_filled: int | None,
    name_rect,
    name_text: str,
    volume_cluster_rect,
    volume: int | None,
    muted: bool | None,
    metrics: LayoutMetrics,
    dots_count: int = 2,
) -> None:
    """Draw the top band's pager dots, appliance name and mute/volume
    readout into *frame* in place — the piece of the top band shared by the
    main screen's now-playing overlay and the repeat screen's own top band.
    The name is drawn plain: it always sits over the dimmed top band, which
    gives it enough contrast without the soft halo the artist/title lines
    need over undimmed album art.

    Caller is responsible for dimming the band (and drawing any
    pressed-zone highlight) before calling this, same discipline as every
    other draw-onto-frame helper here — text/glyphs always land on top of
    both. dots_rect=None (or dots_filled=None) omits the dots entirely —
    used when the caller's overlay snapshot says they should not be drawn.
    dots_count selects the two-dot glyph (any value other than 3) or the
    three-dot page glyph (exactly 3) — see Header.dots_count.

    *muted* is accepted for the caller's convenience but never reaches the
    readout glyph: the header speaker is never slashed on any screen — mute
    has one home, the main screen's own footer glyph and wash (see
    FOOTER_VOLUME_MUTE). The unmuted variant is always drawn here.
    """
    name_font = _load_font(metrics.font_body)
    volume_font = _load_font(metrics.font_readout)

    draw = ImageDraw.Draw(frame)
    _draw_volume_cluster(draw, volume_cluster_rect, volume, None, volume_font, metrics)
    pad = metrics.pad
    _draw_label(draw, name_rect, name_text, name_font, pad)
    if dots_rect is not None and dots_filled is not None:
        if dots_count == 3:
            _draw_glyph(frame, dots_rect, GLYPH_PAGE_DOTS, 3, dots_filled, supersample=metrics.supersample)
        else:
            _draw_glyph(frame, dots_rect, GLYPH_TWO_DOTS, dots_filled, supersample=metrics.supersample)


def _dim_rect(frame: Image.Image, rect: tuple[int, int, int, int]) -> None:
    """Dim *rect* of *frame* in place to OVERLAY_DIM_FACTOR of its original
    brightness, leaving every pixel outside the rect untouched. Used for the
    top and bottom bands only — the middle half of the panel keeps full
    artwork brightness."""
    region = frame.crop(rect)
    dimmed_region = ImageEnhance.Brightness(region).enhance(OVERLAY_DIM_FACTOR)
    frame.paste(dimmed_region, rect[:2])


def _draw_band_divider(
    draw: ImageDraw.ImageDraw, layout, metrics: LayoutMetrics, xs: "tuple[int, ...]",
) -> None:
    """Draw one or more white vertical divider lines, each spanning the
    bottom band from its top edge to its last visible row — the boundary
    between two adjacent footer controls. A two-way footer (repeat, the
    per-output detail page) passes a single x; the main screen's three-way
    footer passes both of its own."""
    line_width = metrics.divider_w
    y0 = layout.bottom_band[1]
    y1 = layout.bottom_band[3] - 1
    for x in xs:
        draw.line([(x, y0), (x, y1)], fill=_DIVIDER_RGB, width=line_width)


def _draw_bottom_band(
    frame: Image.Image, layout, metrics: LayoutMetrics, *,
    left_rect, right_rect, draw_left, draw_right,
) -> None:
    """Draw the bottom band's two controls with the white divider between
    them — the footer shared by the volume screen (minus/plus glyphs) and
    the repeat screen's replaying layout (Restart/Stop labels), the
    counterpart to the shared _draw_top_band_content() header. draw_left and
    draw_right are callables (draw, rect) that render the left and right
    control into their rect — the only part that differs between screens.
    The caller has already dimmed the band and drawn any pressed highlight;
    text/glyphs land on top. *layout* need only carry divider_x and
    bottom_band (both OverlayLayout and RepeatLayout do)."""
    draw = ImageDraw.Draw(frame)
    draw_left(draw, left_rect)
    draw_right(draw, right_rect)
    _draw_band_divider(draw, layout, metrics, (layout.divider_x,))


def _draw_wash(image: Image.Image, rect: tuple[int, int, int, int], rgb, alpha: int) -> None:
    """Alpha-composite a translucent *rgb* wash at *alpha* over *rect*.
    Built and applied at *rect*'s own size only — the same crop/composite/
    paste shape _draw_text_with_halo() and _draw_glyph() use — so nothing
    outside the rectangle is even touched by the composite. The pressed
    highlight and the list's current-row wash are both this, at different
    strengths."""
    x0, y0, x1, y1 = rect
    w, h = x1 - x0, y1 - y0
    if w <= 0 or h <= 0:
        return
    wash_layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    ImageDraw.Draw(wash_layer).rectangle([0, 0, w - 1, h - 1], fill=(*rgb, alpha))
    region = image.crop(rect).convert("RGBA")
    composited = Image.alpha_composite(region, wash_layer).convert("RGB")
    image.paste(composited, (x0, y0))


def _draw_pressed_highlight(image: Image.Image, rect: tuple[int, int, int, int]) -> None:
    """The pressed-zone wash: _draw_wash at the press strength."""
    _draw_wash(image, rect, _PRESSED_FILL_RGB, _PRESSED_FILL_ALPHA)


def _draw_row_highlight(image: Image.Image, rect: tuple[int, int, int, int]) -> None:
    """The list's current-row wash: _draw_wash at the fainter row strength."""
    _draw_wash(image, rect, _ROW_HIGHLIGHT_RGB, _ROW_HIGHLIGHT_ALPHA)


def _zone_center_and_span(rect: tuple[int, int, int, int]) -> tuple[int, int, int]:
    """Return (center_x, center_y, glyph_radius) for a zone rectangle — the
    glyph is sized from the smaller of the zone's own width/height so it
    never overflows the (possibly non-square) zone rectangle."""
    x0, y0, x1, y1 = rect
    cx = (x0 + x1) // 2
    cy = (y0 + y1) // 2
    radius = max(2, min(x1 - x0, y1 - y0) // 4)
    return cx, cy, radius


def _draw_minus_glyph(draw: ImageDraw.ImageDraw, rect: tuple[int, int, int, int], color=_GLYPH_RGB) -> None:
    cx, cy, r = _zone_center_and_span(rect)
    width = max(1, r // 3)
    draw.line([(cx - r, cy), (cx + r, cy)], fill=color, width=width)


def _draw_plus_glyph(draw: ImageDraw.ImageDraw, rect: tuple[int, int, int, int], color=_GLYPH_RGB) -> None:
    cx, cy, r = _zone_center_and_span(rect)
    stroke = max(1, r // 3)
    draw.line([(cx - r, cy), (cx + r, cy)], fill=color, width=stroke)
    draw.line([(cx, cy - r), (cx, cy + r)], fill=color, width=stroke)


def _draw_speaker_glyph(
    draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], muted: bool | None, color=_GLYPH_RGB,
) -> None:
    """Draw a simple speaker glyph: a body (rectangle + triangle "cone") plus
    sound-wave arcs when unmuted, or a diagonal slash through the body when
    muted. Sized from a square *box* (the glyph's own bounding box, not a
    zone rectangle — see _draw_volume_cluster, which lays the icon box out
    to the left of or in place of the volume digits).

    muted=True -> muted variant (slash). muted=False -> unmuted variant
    (arcs). muted=None ("unknown" — nothing selected/playing, so there is no
    real mute state to report) also draws the unmuted variant: defaulting to
    "not muted" is the less alarming reading of an unknown state and avoids
    implying a mute the user never set.
    """
    x0, y0, x1, y1 = box
    cx = (x0 + x1) // 2
    cy = (y0 + y1) // 2
    r = max(2, min(x1 - x0, y1 - y0) // 2 - 1)
    stroke = max(1, r // 4)

    # Speaker body: a small rectangle (the driver) plus a triangle (the
    # cone), both left-of-center so the wave/slash has room to the right.
    body_w = max(2, r // 2)
    body_h = max(2, r)
    body_left = cx - r
    rect_box = [body_left, cy - body_h // 2, body_left + body_w, cy + body_h // 2]
    draw.rectangle(rect_box, fill=color)
    cone_tip_x = body_left + body_w + r // 2
    draw.polygon(
        [
            (body_left + body_w, cy - body_h // 2),
            (body_left + body_w, cy + body_h // 2),
            (cone_tip_x, cy - r),
            (cone_tip_x, cy + r),
        ],
        fill=color,
    )

    if muted:
        # Centred over the speaker body, not the glyph box: the body sits
        # left of centre so the sound waves have room, and a slash centred
        # on the box reads as trailing off to the right of it. Same length
        # and angle as a box-centred slash, just shifted left so its own
        # midpoint sits over the body's.
        body_cx = (body_left + cone_tip_x) // 2
        draw.line(
            [(body_cx - r, cy - r), (body_cx + r, cy + r)],
            fill=color,
            width=stroke,
        )
    else:
        # Sound-wave arcs to the right of the cone.
        for i in range(1, 3):
            offset = i * max(1, r // 2)
            box_arc = [
                cone_tip_x - r // 3,
                cy - offset,
                cone_tip_x + offset,
                cy + offset,
            ]
            draw.arc(box_arc, start=-45, end=45, fill=color, width=stroke)


def _text_size(
    draw: ImageDraw.ImageDraw, text: str, font
) -> tuple[int, int, tuple[int, int, int, int]] | None:
    """Measure *text* rendered in *font*: returns (width, height, bbox)
    where bbox is the raw draw.textbbox((0, 0), ...) result, or None if
    measurement raised. Guarded the same way as _draw_text_safe — a None
    here must make the caller skip that text element only, never propagate
    an exception out of compose()."""
    try:
        bbox = draw.textbbox((0, 0), text, font=font)
    except Exception:
        return None
    left, top, right, bottom = bbox
    return right - left, bottom - top, bbox


def _draw_text_safe(
    draw: ImageDraw.ImageDraw, xy: tuple[int, int], text: str, font, fill=_GLYPH_RGB,
) -> bool:
    """Draw *text* at *xy* in *fill* (the glyph colour by default), guarded
    so a Pillow/font failure degrades to "no text drawn" rather than an
    exception escaping compose(). Returns True on success, False if the
    draw call raised. *fill* is overridable so a disabled repeat-screen
    label can be drawn dimmed without a separate code path."""
    try:
        draw.text(xy, text, font=font, fill=fill)
        return True
    except Exception:
        return False


def _truncate_to_width(draw: ImageDraw.ImageDraw, text: str, font, max_w: int) -> str:
    """Shorten *text* so it (plus an ASCII ellipsis when shortened) fits
    within *max_w* pixels in *font*. Returns the unmodified text when it
    already fits, the longest fitting prefix plus "..." when it needs
    shortening, or "" when nothing fits (not even one character plus the
    ellipsis). Uses the three-dot ASCII string, not U+2026, so the bitmap
    fallback font can render it too. A linear scan is fine here: artist
    strings are short and this runs at most once per repaint."""
    measured = _text_size(draw, text, font)
    if measured is not None and measured[0] <= max_w:
        return text

    for end in range(len(text) - 1, 0, -1):
        candidate = text[:end].rstrip() + "..."
        measured = _text_size(draw, candidate, font)
        if measured is not None and measured[0] <= max_w:
            return candidate
    return ""


def _fit_value_lines(
    draw: ImageDraw.ImageDraw, text: str, sizes: "tuple[int, ...]", rect: "tuple[int, int, int, int]",
) -> "tuple[tuple[str, ...], object]":
    """Fit *text* into *rect* (the compact info page's own value area — see
    InfoValueLayout.value) for the drill-in view: try each of *sizes* in
    turn, largest first — greedy word-wrap measured by _text_size, a single
    token wider than the area broken by character — and accept the first
    size whose wrapped block (line count * 1.2 * font size) fits the rect's
    height. When every size still overflows, the last size's lines are kept
    up to however many fit and the final one is ellipsized with
    _truncate_to_width, so something legible is always shown rather than
    spilling past the rect. Returns ((), None) when no size in *sizes* has a
    loadable font — the caller then draws nothing, the same
    degrade-gracefully discipline every text helper in this module follows.
    Pure: no state, no I/O beyond the *draw* measuring calls _text_size
    already makes safely."""
    max_w = rect[2] - rect[0]
    max_h = rect[3] - rect[1]

    def wrap(font) -> "tuple[str, ...]":
        def fits(s: str) -> bool:
            measured = _text_size(draw, s, font)
            return measured is not None and measured[0] <= max_w

        lines: list[str] = []
        current = ""
        for word in text.split():
            candidate = f"{current} {word}".strip()
            if fits(candidate):
                current = candidate
                continue
            if current:
                lines.append(current)
                current = ""
            if fits(word):
                current = word
                continue
            # word alone is wider than the area: break it by character.
            chunk = ""
            for ch in word:
                piece = chunk + ch
                if fits(piece) or not chunk:
                    chunk = piece
                else:
                    lines.append(chunk)
                    chunk = ch
            current = chunk
        if current:
            lines.append(current)
        return tuple(lines) if lines else (text,)

    last_lines: "tuple[str, ...]" = ()
    last_font = None
    last_size = None
    for size in sizes:
        font = _load_font(size)
        if font is None:
            continue
        lines = wrap(font)
        last_lines, last_font, last_size = lines, font, size
        line_h = size * 1.2
        if line_h > 0 and len(lines) * line_h <= max_h:
            return lines, font
    if last_font is None:
        return (), None
    line_h = last_size * 1.2
    max_lines = max(1, int(max_h // line_h)) if line_h > 0 else 1
    kept = list(last_lines[:max_lines])
    if kept:
        # The dropped remainder (if any) is folded back into the last kept
        # line before truncating it, so _truncate_to_width always has more
        # than fits and the ellipsis actually appears — a lone kept line
        # that already fit on its own would otherwise come back unchanged.
        remainder = " ".join(last_lines[max_lines:])
        tail = f"{kept[-1]} {remainder}".strip() if remainder else kept[-1]
        kept[-1] = _truncate_to_width(draw, tail, last_font, max_w)
    return tuple(kept), last_font


def _draw_volume_cluster(
    draw: ImageDraw.ImageDraw,
    rect: tuple[int, int, int, int],
    volume: int | None,
    muted: bool | None,
    font,
    metrics: LayoutMetrics,
) -> None:
    """Draw the volume readout inside *rect* (the top band's volume cluster,
    == the OUTPUTS zone on the main screen): the speaker glyph, right aligned, and — when both a
    *volume* number and a usable *font* are available — the volume digits to
    its left. *metrics* carries the panel's scale-derived padding, icon-to-
    digits gap and icon size (not the rect's own size) — all read from the
    same reference axis every other overlay dimension uses.

    volume=None or font=None draws the glyph alone, right aligned — always
    safe, since _load_font() never raises and this function never assumes a
    font is present.
    """
    pad = metrics.pad
    gap = metrics.icon_gap
    icon = metrics.icon
    cy = (rect[1] + rect[3]) // 2

    x_icon = rect[2] - pad - icon
    if volume is not None and font is not None:
        text = str(volume)
        measured = _text_size(draw, text, font)
        if measured is not None:
            text_w, text_h, bbox = measured
            left, top, _, _ = bbox
            x_text = rect[2] - pad - text_w
            if _draw_text_safe(draw, (x_text - left, cy - text_h // 2 - top), text, font):
                x_icon = x_text - gap - icon

    icon_box = (x_icon, cy - icon // 2, x_icon + icon, cy - icon // 2 + icon)
    _draw_speaker_glyph(draw, icon_box, muted)


def _draw_text_with_halo(
    frame: Image.Image,
    rect: tuple[int, int, int, int],
    text: str,
    font,
    metrics: LayoutMetrics,
    *,
    align: str = "left",
) -> None:
    """Draw *text* inside *rect* (left-aligned, or centred when
    align="center"), legible over arbitrary album art: a soft,
    Gaussian-blurred dark glow is composited behind the text before the
    text itself is drawn in the glyph colour. Used for the appliance name,
    album, title and artist lines (left-aligned) and the repeat screen's
    replaying-layout position line (centred, over its own artwork/logo base
    image) — see the module docstring's halo paragraph.

    A blank *text*, a missing *font*, truncation-to-nothing, or any Pillow
    failure while building the halo all degrade gracefully: the halo step
    is skipped/caught and the plain text still gets drawn (matching every
    other text helper's discipline of never letting a text failure escape
    compose()). The halo itself is confined strictly to *rect* — it is
    composited on a *rect*-sized layer and pasted back into *rect* only, so
    it can never bleed into a neighbouring zone.
    """
    if not text or font is None:
        return

    draw = ImageDraw.Draw(frame)
    pad = metrics.pad
    max_w = rect[2] - rect[0] - pad
    if max_w <= 0:
        return
    truncated = _truncate_to_width(draw, text, font, max_w)
    if not truncated:
        return

    measured = _text_size(draw, truncated, font)
    if measured is None:
        return
    text_w, text_h, bbox = measured
    left, top, _, _ = bbox
    cy = (rect[1] + rect[3]) // 2
    if align == "center":
        x = rect[0] + max(0, (rect[2] - rect[0] - text_w) // 2)
    else:
        x = rect[0] + pad
    y = cy - text_h // 2
    xy = (x - left, y - top)

    rect_w, rect_h = rect[2] - rect[0], rect[3] - rect[1]
    if rect_w > 0 and rect_h > 0:
        try:
            stroke = metrics.halo_stroke
            radius = metrics.halo_blur
            local_xy = (xy[0] - rect[0], xy[1] - rect[1])
            halo_layer = _halo_layer(truncated, font, local_xy, rect_w, rect_h, stroke, radius)
            region = frame.crop(rect).convert("RGBA")
            composited = Image.alpha_composite(region, halo_layer).convert("RGB")
            frame.paste(composited, (rect[0], rect[1]))
        except Exception:
            pass  # the halo is cosmetic only — fall through to plain text.

    _draw_text_safe(ImageDraw.Draw(frame), xy, truncated, font)


@functools.lru_cache(maxsize=16)
def _halo_layer(text: str, font, local_xy: tuple[int, int], w: int, h: int, stroke: int, radius: int):
    """The blurred, dark-glow layer drawn behind a piece of halo text: a
    pure function of the already-truncated text, the font object, the local
    position the text is drawn at within a (w, h) layer, the stroke width
    and the blur radius — memoised the same way _load_font() memoises a
    loaded font. Keying on the font object itself (rather than, say, its
    point size) means a font reload or a fallback to a different face is
    always a fresh key, never a stale hit.
    """
    layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    ImageDraw.Draw(layer).text(
        local_xy, text, font=font, fill=_HALO_RGBA, stroke_width=stroke, stroke_fill=_HALO_RGBA,
    )
    return layer.filter(ImageFilter.GaussianBlur(radius))


# Kinds for _draw_glyph()'s tile cache — an opaque paint callback cannot be
# hashed as a cache key, so each small glyph identifies itself by one of
# these string constants plus a tuple of hashable parameters. See
# _GLYPH_PAINTERS (below the painter functions) and _glyph_tile().
GLYPH_CHEVRON = "chevron"              # params: (direction, lit)
GLYPH_TWO_DOTS = "two_dots"            # params: (filled,) or (filled, color)
GLYPH_PAGE_DOTS = "page_dots"          # params: (count, filled) or (count, filled, color)
GLYPH_ARM_DOT = "arm_dot"              # params: (armed,)
GLYPH_PLAY = "play"                    # params: () — the selector's "playing" row marker
GLYPH_CROSS = "cross"                  # params: () — the rail's back/cancel control
GLYPH_MUTE = "mute"                    # params: () or (color,) — the main screen's footer mute cell
GLYPH_RESTART = "restart"              # params: (color,) — the compact tier's Restart control
GLYPH_STOP = "stop"                    # params: (color,) — the compact tier's Stop control
GLYPH_INFO = "info"                    # params: () — the idle screen's information badge
GLYPH_WIFI = "wifi"                    # params: (lit, color) — the idle screen's Wi-Fi status glyph

# Fraction of the idle info zone's own short side the "i" badge's box
# occupies. The painter's disc is 0.42 of that box, so 0.60 gives a disc of
# radius 0.25 of the zone — sized to read as one pair with the Wi-Fi glyph in
# the opposite corner (outer arc radius 0.33 of its zone).
_INFO_GLYPH_FRACTION = 0.60

# The "i" cut from the information badge's white disc: plain black, for
# tourist-sign contrast against the disc regardless of what the idle
# screen's own base image looks like behind it.
_INFO_GLYPH_CUT_RGB = (0, 0, 0)


@functools.lru_cache(maxsize=48)
def _glyph_tile(kind: str, params: tuple, w: int, h: int, supersample: int):
    """The downsampled RGBA tile for one small glyph at one size: a
    transparent canvas at *supersample* times (w, h) is painted by the
    kind's entry in _GLYPH_PAINTERS, then downsampled with LANCZOS. A pure
    function of its arguments, memoised the same way _load_font() memoises a
    loaded font — see that function's statelessness note. Raises on a
    Pillow failure so nothing is cached for a failed paint; the caller
    (_draw_glyph) is responsible for swallowing that.
    """
    big_w, big_h = w * supersample, h * supersample
    big = Image.new("RGBA", (big_w, big_h), (0, 0, 0, 0))
    _GLYPH_PAINTERS[kind](ImageDraw.Draw(big), big_w, big_h, *params)
    return big.resize((w, h), _LANCZOS)


def _draw_glyph(
    frame: Image.Image, rect: tuple[int, int, int, int], kind: str, *params,
    supersample: int = _GLYPH_SUPERSAMPLE,
) -> None:
    """Draw a small glyph antialiased into *rect*: *kind* plus *params*
    identifies a memoised, downsampled tile (see _glyph_tile()), rendered at
    _GLYPH_SUPERSAMPLE times *rect*'s size and downsampled with LANCZOS, then
    alpha-composited over the cropped frame region and pasted back. Used for
    the list's play marker and chevrons and the header's pager dots, whose
    diagonal strokes and curves would otherwise alias visibly at
    these small sizes — the same per-element (never whole-frame)
    antialiasing the halo helper above applies to text. Any Pillow failure,
    including one raised while painting a tile that therefore never gets
    cached, is swallowed here: a glyph that fails to render simply does not
    appear, never an exception.
    """
    x0, y0, x1, y1 = rect
    w, h = x1 - x0, y1 - y0
    if w <= 0 or h <= 0:
        return
    try:
        tile = _glyph_tile(kind, tuple(params), w, h, supersample)
        region = frame.crop(rect).convert("RGBA")
        composited = Image.alpha_composite(region, tile).convert("RGB")
        frame.paste(composited, (x0, y0))
    except Exception:
        pass


def _centred_box(rect: tuple[int, int, int, int], side: int) -> tuple[int, int, int, int]:
    """A *side*-by-*side* box centred within *rect* — used to draw a small
    glyph inside a much larger touch zone (the rail's controls, the header's
    own back control) rather than stretching it across the whole zone, so
    the glyph's own size can shrink independently of the zone's own touch
    floor."""
    x0, y0, x1, y1 = rect
    cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
    half = side // 2
    return (cx - half, cy - half, cx - half + side, cy - half + side)


def _reset_render_caches() -> None:
    """Clear the memoised glyph-tile, halo-layer and reveal-layer caches.
    Test-only hook, the same purpose _reset_font_cache() serves for the
    font cache — lets a test exercise any of them from a clean slate
    without restarting the process."""
    _glyph_tile.cache_clear()
    _halo_layer.cache_clear()
    _reveal_layers.cache_clear()


def _draw_chevron(draw: ImageDraw.ImageDraw, w: int, h: int, direction: str, lit: bool) -> None:
    """A simple two-segment chevron (back/down/up) into a (w, h) canvas —
    see _draw_glyph. *lit*=False dims it to OVERLAY_DIM_FACTOR of the glyph
    colour, matching a disabled/no-more-pages affordance."""
    stroke = max(1, min(w, h) // 7)
    color = _GLYPH_RGB if lit else tuple(round(c * OVERLAY_DIM_FACTOR) for c in _GLYPH_RGB)
    cx, cy = w / 2, h / 2
    r = min(w, h) * 0.28
    if direction == "left":
        points = [(cx + r, cy - r), (cx - r, cy), (cx + r, cy + r)]
    elif direction == "down":
        points = [(cx - r, cy - r), (cx, cy + r), (cx + r, cy - r)]
    else:  # "up"
        points = [(cx - r, cy + r), (cx, cy - r), (cx + r, cy + r)]
    draw.line(points, fill=color, width=stroke, joint="curve")


def _draw_play_glyph(draw: ImageDraw.ImageDraw, w: int, h: int) -> None:
    """A filled right-pointing triangle — the appliance selector's
    "playing" row marker. Same reach rule as _draw_chevron and
    _draw_cross_glyph (0.28 of the short side) so the list's glyphs read
    as one family; filled rather than stroked because a play mark is
    conventionally solid. Nudged right by a third of its reach so its
    centroid, not its bounding box, sits on the canvas centre — a
    box-centred triangle reads left-heavy. Rendered into a (w, h) canvas —
    see _draw_glyph."""
    r = min(w, h) * 0.28
    cx, cy = w / 2, h / 2
    s = r / 3
    draw.polygon(
        [(cx - r + s, cy - r), (cx - r + s, cy + r), (cx + r + s, cy)],
        fill=_GLYPH_RGB,
    )


def _draw_two_dots(draw: ImageDraw.ImageDraw, w: int, h: int, filled: int, color=_GLYPH_RGB) -> None:
    """Two small circles side by side, one of them (*filled*: 0 for the
    left one, 1 for the right) drawn solid and the other outlined — the
    main/repeat screen pager dots (also reused, dimmed when inert, as the
    compact tier's own repeat-quadrant glyph). Rendered into a (w, h)
    canvas — see _draw_glyph."""
    r = max(2, round(min(w, h) * 0.12))
    cy = h / 2.0
    gap = r * 3
    cx0 = w / 2.0 - gap / 2.0
    cx1 = w / 2.0 + gap / 2.0
    for i, cx in enumerate((cx0, cx1)):
        box = [cx - r, cy - r, cx + r, cy + r]
        if i == filled:
            draw.ellipse(box, fill=color)
        else:
            draw.ellipse(box, outline=color, width=max(1, r // 3))


def _draw_page_dots(draw: ImageDraw.ImageDraw, w: int, h: int, count: int, filled: int, color=_GLYPH_RGB) -> None:
    """*count* small circles evenly spaced, one of them (*filled*) drawn
    solid and the rest outlined — generalises _draw_two_dots for a page
    count other than two (currently only 3, the EQ page's own third dot);
    a smaller radius (0.10 of the short side, against two-dot's 0.12) so
    three dots still fit the same band-high box. Rendered into a (w, h)
    canvas — see _draw_glyph."""
    r = max(2, round(min(w, h) * 0.10))
    cy = h / 2.0
    gap = r * 3
    start = w / 2.0 - gap * (count - 1) / 2.0
    for i in range(count):
        cx = start + gap * i
        box = [cx - r, cy - r, cx + r, cy + r]
        if i == filled:
            draw.ellipse(box, fill=color)
        else:
            draw.ellipse(box, outline=color, width=max(1, r // 3))


def _draw_arm_dot(draw: ImageDraw.ImageDraw, w: int, h: int, armed: bool) -> None:
    """The enable layout's "Repeat Play" row marker: solid white when
    *armed* (the appliance will auto-start a replay on its own), hollow
    (outline only) when disarmed — radius 0.16 of the box. Rendered into a
    (w, h) canvas — see _draw_glyph."""
    r = max(2, round(min(w, h) * 0.16))
    cx, cy = w / 2.0, h / 2.0
    box = [cx - r, cy - r, cx + r, cy + r]
    if armed:
        draw.ellipse(box, fill=_GLYPH_RGB)
    else:
        draw.ellipse(box, outline=_GLYPH_RGB, width=max(1, r // 3))


def _draw_cross_glyph(draw: ImageDraw.ImageDraw, w: int, h: int) -> None:
    """Two diagonal strokes forming an X — the right-rail's back/cancel
    control. Same stroke width and reach rules as _draw_chevron so the
    three rail glyphs read as one family. Rendered into a (w, h) canvas —
    see _draw_glyph."""
    stroke = max(1, min(w, h) // 7)
    cx, cy = w / 2, h / 2
    r = min(w, h) * 0.28
    draw.line([(cx - r, cy - r), (cx + r, cy + r)], fill=_GLYPH_RGB, width=stroke)
    draw.line([(cx - r, cy + r), (cx + r, cy - r)], fill=_GLYPH_RGB, width=stroke)


# Fraction of the footer cell's short side the mute glyph's own bounding box
# occupies — generous, since this glyph is the cell's only content (no
# digits beside it, unlike the header's volume_cluster readout).
_MUTE_GLYPH_BOX_FRACTION = 0.56


def _draw_mute_glyph(draw: ImageDraw.ImageDraw, w: int, h: int, color=_GLYPH_RGB) -> None:
    """The main screen's own footer mute glyph: the crossed speaker, drawn
    via the same painter the header readout uses (_draw_speaker_glyph),
    always in its muted variant — this cell IS the mute control, so there
    is no unmuted state for it to distinguish. Rendered into a (w, h)
    canvas — see _draw_glyph. Integer box arithmetic throughout: Pillow's
    stroke widths must be ints, and _draw_speaker_glyph derives its own
    stroke width from this box's size. *color* lets the compact tier's
    muted cell invert it to black over its own solid white wash."""
    side = round(min(w, h) * _MUTE_GLYPH_BOX_FRACTION)
    cx, cy = w // 2, h // 2
    half = side // 2
    box = (cx - half, cy - half, cx - half + side, cy - half + side)
    _draw_speaker_glyph(draw, box, muted=True, color=color)


def _draw_restart_glyph(draw: ImageDraw.ImageDraw, w: int, h: int, color=_GLYPH_RGB) -> None:
    """The compact tier's Restart control: the conventional media-player
    "seek to start" icon ("|<<") — a vertical bar near the left edge of the
    glyph's own box, then two filled triangles beside it, both pointing
    left (apex on the left, base on the right), toward the bar. Rendered
    into a (w, h) canvas — see _draw_glyph."""
    short = min(w, h)
    r = short * 0.28
    cx, cy = w / 2, h / 2
    left = cx - r
    right = cx + r

    # The bar: a filled rectangle at the icon's own left edge.
    bar_w = max(2, round(short / 8))
    bar_h = 2 * r * 0.85
    bar_x0, bar_x1 = left, left + bar_w
    bar_y0, bar_y1 = cy - bar_h / 2, cy + bar_h / 2
    draw.rectangle([bar_x0, bar_y0, bar_x1, bar_y1], fill=color)

    # Two left-pointing triangles sharing the remaining width to the
    # icon's right edge, separated from the bar and from each other by the
    # same small gap.
    gap = max(1, bar_w / 2)
    area_x0 = bar_x1 + gap
    tri_w = (right - area_x0 - gap) / 2

    def _triangle(x0: float) -> None:
        draw.polygon(
            [(x0, cy), (x0 + tri_w, cy - bar_h / 2), (x0 + tri_w, cy + bar_h / 2)],
            fill=color,
        )

    _triangle(area_x0)
    _triangle(area_x0 + tri_w + gap)


def _draw_stop_glyph(draw: ImageDraw.ImageDraw, w: int, h: int, color=_GLYPH_RGB) -> None:
    """The compact tier's Stop control: a filled square, reach 0.28 of the
    short side (side 0.56 of it), centred — the conventional "stop" glyph.
    Rendered into a (w, h) canvas — see _draw_glyph."""
    side = min(w, h) * 0.56
    cx, cy = w / 2, h / 2
    half = side / 2
    draw.rectangle([cx - half, cy - half, cx + half, cy + half], fill=color)


def _draw_info_glyph(draw: ImageDraw.ImageDraw, w: int, h: int) -> None:
    """The idle screen's information badge: a filled white disc (radius
    0.42 of the short side) with a lowercase "i" (a dot above the centre,
    a stem from just above the centre to just below it) cut out of it in
    the dark chassis colour — tourist-sign contrast, drawn from shapes
    rather than a font so it reads identically across every font fallback.
    Rendered into a (w, h) canvas — see _draw_glyph."""
    short = min(w, h)
    cx, cy = w / 2, h / 2
    r = short * 0.42
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=_GLYPH_RGB)

    dot_r = short * 0.07
    stem_half_w = short * 0.06
    stem_top = cy - short * 0.02
    stem_bottom = cy + short * 0.2
    dot_cy = cy - short * 0.16
    draw.ellipse(
        [cx - dot_r, dot_cy - dot_r, cx + dot_r, dot_cy + dot_r], fill=_INFO_GLYPH_CUT_RGB,
    )
    draw.rectangle(
        [cx - stem_half_w, stem_top, cx + stem_half_w, stem_bottom], fill=_INFO_GLYPH_CUT_RGB,
    )


def _draw_wifi_glyph(draw: ImageDraw.ImageDraw, w: int, h: int, lit: int, color=_GLYPH_RGB) -> None:
    """The idle screen's Wi-Fi status glyph: a dot with three arcs fanning
    upward from it. The innermost *lit* arcs (0..3) and the dot are drawn in
    *color*; the rest in the dimmed glyph shade. lit=0 dims the dot as well,
    so "no link" reads as an entirely grey glyph, and the offline flash's
    red phase passes lit=3 with the alarm colour so every part turns red.

    Sized from the canvas short side S (the whole zone square, not a
    centred sub-box): outer arc radius 0.33 S, arc radii 0.42/0.71/1.00 of
    that, stroke 0.062 S, dot radius 0.78 of the stroke, dot centre at
    0.56 S from the top. The arcs span 222..318 degrees in Pillow's own
    clockwise-from-3-o'clock convention, i.e. a 96 degree fan centred
    straight up. Rendered into a (w, h) canvas — see _draw_glyph."""
    short = min(w, h)
    cx = w / 2
    dot_cy = 0.56 * short
    stroke = max(2, round(short * 0.062))
    outer_r = 0.33 * short
    dot_r = round(stroke * 0.78)
    dim = _DIMMED_GLYPH_RGB
    for i, fraction in enumerate((0.42, 0.71, 1.00)):
        r = outer_r * fraction
        arc_color = color if i < lit else dim
        draw.arc([cx - r, dot_cy - r, cx + r, dot_cy + r], start=222, end=318, fill=arc_color, width=stroke)
    dot_color = color if lit > 0 else dim
    draw.ellipse([cx - dot_r, dot_cy - dot_r, cx + dot_r, dot_cy + dot_r], fill=dot_color)


# Dispatch table for _glyph_tile()'s kinded paint step — built here, after
# every painter above is defined, and looked up by name at call time so its
# own position in the module relative to _glyph_tile()/_draw_glyph() (defined
# earlier, alongside the halo-text helper they mirror) does not matter.
_GLYPH_PAINTERS = {
    GLYPH_CHEVRON: _draw_chevron,
    GLYPH_TWO_DOTS: _draw_two_dots,
    GLYPH_PAGE_DOTS: _draw_page_dots,
    GLYPH_ARM_DOT: _draw_arm_dot,
    GLYPH_PLAY: _draw_play_glyph,
    GLYPH_CROSS: _draw_cross_glyph,
    GLYPH_MUTE: _draw_mute_glyph,
    GLYPH_RESTART: _draw_restart_glyph,
    GLYPH_STOP: _draw_stop_glyph,
    GLYPH_INFO: _draw_info_glyph,
    GLYPH_WIFI: _draw_wifi_glyph,
}


def _draw_label(
    draw: ImageDraw.ImageDraw, rect: tuple[int, int, int, int], text: str, font, pad: int,
    color=_GLYPH_RGB,
) -> None:
    """Draw *text* left-aligned inside *rect*, no halo — used on the flat
    dark repeat-screen background, where (unlike compose()'s overlay over
    arbitrary artwork) there is nothing behind the text to make illegible.
    Degrades to "no text drawn" on a blank string, a missing font,
    truncation-to-nothing, or any Pillow failure — the same discipline as
    _draw_text_with_halo()."""
    if not text or font is None:
        return
    max_w = rect[2] - rect[0] - pad
    if max_w <= 0:
        return
    truncated = _truncate_to_width(draw, text, font, max_w)
    if not truncated:
        return
    measured = _text_size(draw, truncated, font)
    if measured is None:
        return
    text_w, text_h, bbox = measured
    left, top, _, _ = bbox
    cy = (rect[1] + rect[3]) // 2
    x = rect[0] + pad
    y = cy - text_h // 2
    _draw_text_safe(draw, (x - left, y - top), truncated, font, fill=color)


def _draw_label_right(
    draw: ImageDraw.ImageDraw, rect: tuple[int, int, int, int], text: str, font, pad: int,
    color=_GLYPH_RGB,
) -> None:
    """Draw *text* right-aligned inside *rect*, no halo and no truncation —
    the right-aligned secondary-text path _body_list_rows() draws inline,
    factored out here so the EQ page's caption row (label left, dB right)
    can share it. Same degrade-gracefully discipline as _draw_label()."""
    if not text or font is None:
        return
    measured = _text_size(draw, text, font)
    if measured is None:
        return
    text_w, text_h, bbox = measured
    left, top, _, _ = bbox
    cy = (rect[1] + rect[3]) // 2
    x = rect[2] - pad - text_w
    y = cy - text_h // 2
    _draw_text_safe(draw, (x - left, y - top), text, font, fill=color)


def _draw_label_centered(
    draw: ImageDraw.ImageDraw, rect: tuple[int, int, int, int], text: str, font, color=_GLYPH_RGB,
) -> None:
    """Draw *text* centred within *rect*, no halo — same degrade-gracefully
    discipline as _draw_label()."""
    if not text or font is None:
        return
    measured = _text_size(draw, text, font)
    if measured is None:
        return
    text_w, text_h, bbox = measured
    left, top, _, _ = bbox
    cx = (rect[0] + rect[2]) // 2
    cy = (rect[1] + rect[3]) // 2
    x = cx - text_w // 2
    y = cy - text_h // 2
    _draw_text_safe(draw, (x - left, y - top), text, font, fill=color)


def _new_frame(base, width: int, height: int, background: str) -> Image.Image:
    """Return a fresh (width, height) RGB image to draw a frame into — never
    the caller's own object, so the caller's base image is never mutated by
    what happens next. background == BG_BASE tries to use *base* (a copy of
    it, resized if it is not already panel-sized); anything else, or a base
    that turns out to be unusable, falls back to the flat chassis fill."""
    if background == BG_BASE and base is not None:
        try:
            img = base.convert("RGB")
            if img.size != (width, height):
                img = img.resize((width, height))
            return img
        except Exception:
            pass
    return Image.new("RGB", (width, height), _LIST_BG_RGB)


def _finish(img: Image.Image, rotate: bool, bgr: bool) -> Image.Image:
    """Apply the rotate-then-BGR tail every screen shares, in that order.
    Returns *img* itself, unchanged, when neither flag is set."""
    if rotate:
        img = img.transpose(Image.ROTATE_180)
    if bgr:
        img = Image.merge("RGB", img.split()[::-1])
    return img


# Logged at most once per process: a missing numpy is a one-time
# environment problem, not a per-frame event.
_numpy_missing_logged = False


def _numpy_module():
    """Return the numpy module, or None (logged once) when it is missing."""
    global _numpy_missing_logged
    try:
        import numpy
    except ImportError:
        if not _numpy_missing_logged:
            _logger.warning(
                "dial display: python3-numpy is not installed; the artwork "
                "reveal falls back to slower Pillow compositing. Install "
                "python3-numpy to fix this."
            )
            _numpy_missing_logged = True
        return None
    return numpy


def _active_runs(np, add, keep) -> tuple:
    """Half-open row ranges of a layer where it is not the identity."""
    active = ((add != 0) | (keep != 255)).any(axis=(1, 2))
    padded = np.concatenate(([0], active.astype(np.int8), [0]))
    edges = np.flatnonzero(np.diff(padded))
    return tuple((int(a), int(b)) for a, b in zip(edges[::2], edges[1::2]))


def _build_reveal_arrays(layers: RevealLayers) -> "_RevealArrays | None":
    np = _numpy_module()
    if np is None:
        return None
    try:
        def arr(img):
            return np.array(img, dtype=np.uint16)

        strip_add, strip_keep = arr(layers.strip_add), arr(layers.strip_keep)
        return _RevealArrays(
            top_add=arr(layers.top_add), top_keep=arr(layers.top_keep),
            bottom_add=arr(layers.bottom_add), bottom_keep=arr(layers.bottom_keep),
            strip_add=strip_add, strip_keep=strip_keep,
            strip_runs=_active_runs(np, strip_add, strip_keep),
        )
    except Exception:
        _logger.warning("dial display: reveal layer arrays unavailable", exc_info=True)
        return None


@functools.lru_cache(maxsize=2)
def _reveal_layers(
    frame: Frame, width: int, height: int, metrics: LayoutMetrics,
    top_band: Rect, bottom_band: Rect, strip: Rect,
) -> RevealLayers:
    """Separate *frame*'s chrome from whatever base it will be drawn over,
    for the three regions the artwork-tap reveal moves or fades. Every
    drawing step in the pipeline is linear in the pixel behind it (the
    dim, every wash and glyph, the halo, antialiased text), so rendering
    the same descriptor over black and over white gives, per channel, the
    light the chrome adds on its own and how much of the base shows
    through: black render = add, white render - black render = keep. A
    pure function of its arguments, memoised the same way _glyph_tile()
    is (see _load_font()'s statelessness note): two entries, so the
    now-playing and the repeat screen's layers can both stay warm. The
    numpy forms of the layers are built here too, once per slide."""
    black = Image.new("RGB", (width, height), (0, 0, 0))
    white = Image.new("RGB", (width, height), (255, 255, 255))
    add = _compose_frame(black, width, height, frame, rotate=False, bgr=False, metrics=metrics)
    lit = _compose_frame(white, width, height, frame, rotate=False, bgr=False, metrics=metrics)
    keep = ImageChops.subtract(lit, add)
    layers = RevealLayers(
        top_band=top_band, bottom_band=bottom_band, strip=strip,
        top_add=add.crop(top_band), top_keep=keep.crop(top_band),
        bottom_add=add.crop(bottom_band), bottom_keep=keep.crop(bottom_band),
        strip_add=add.crop(strip), strip_keep=keep.crop(strip),
    )
    arrays = _build_reveal_arrays(layers)
    if arrays is not None:
        layers = dataclasses.replace(layers, arrays=arrays)
    return layers


def _apply_layer(region: Image.Image, add: Image.Image, keep: Image.Image) -> Image.Image:
    """The chrome laid over *region*: add + keep * region / 255, per
    channel. All three images are the same size."""
    return ImageChops.add(ImageChops.multiply(region, keep), add)


def _apply_layer_np(np, region, add, keep):
    """_apply_layer() on arrays, bit-identical to Pillow's multiply (the
    truncated a * b // 255) then saturating add. *region* is uint8, *add*
    and *keep* uint16 of the same shape; returns uint16 in 0..255."""
    t = region.astype(np.uint16)
    t *= keep
    # (t + 1 + (t >> 8)) >> 8 is exactly t // 255 for every t up to 255 * 255.
    t += (t >> 8) + 1
    t >>= 8
    t += add
    np.minimum(t, 255, out=t)
    return t


def _reveal_frame(base, layers: RevealLayers, progress: float) -> Image.Image:
    """One frame of the artwork-tap reveal, in compose space (before
    rotate/BGR). *progress* is strictly between 0 and 1. A fresh copy of
    *base* (never the caller's object) has the inter-band strip's chrome
    laid over it at opacity 1 - progress, so the text fades; then the top
    band's chrome is laid over the top rows shifted round(progress * band
    height) upwards and the bottom band's the same amount downwards, each
    over the artwork already at those rows, so the chrome leaves the
    panel edge while the artwork underneath never moves and shows bare
    where the chrome has gone. Reproduces the ordinary frame at 0 and the
    bare base at 1 to within rounding; the callers short-circuit both
    endpoints to the exact frames anyway.

    The normal path does the whole frame as arithmetic on one array and
    converts back once, touching only the strip rows the chrome changes;
    that keeps the per-frame cost low and, unlike Pillow's chop and blend
    calls, lets other threads run while it works. The bands are
    bit-identical to the Pillow path; the strip fade is exact too, apart
    from possible one-level float rounding differences. Without numpy, or
    if the array path fails for any reason, the same frame is built with
    Pillow instead; this never raises for either."""
    arrays = layers.arrays
    if arrays is not None:
        np = _numpy_module()
        if np is not None:
            try:
                return _reveal_frame_np(np, base, layers, arrays, progress)
            except Exception:
                _logger.warning("dial display: numpy reveal failed; using Pillow", exc_info=True)
    return _reveal_frame_pillow(base, layers, progress)


def _reveal_frame_np(np, base, layers: RevealLayers, arrays: _RevealArrays, progress: float):
    width, height = layers.strip[2], layers.bottom_band[3]
    src = _new_frame(base, width, height, BG_BASE)
    out = np.array(src, dtype=np.uint8)
    x0, y0, x1, y1 = layers.strip
    if x1 > x0 and y1 > y0 and arrays.strip_runs:
        alpha = np.float32(1.0 - progress)
        for r0, r1 in arrays.strip_runs:
            region = out[y0 + r0:y0 + r1, x0:x1]
            applied = _apply_layer_np(
                np, region, arrays.strip_add[r0:r1], arrays.strip_keep[r0:r1],
            )
            base_f = region.astype(np.float32)
            applied = applied.astype(np.float32)
            applied -= base_f
            applied *= alpha
            applied += base_f
            region[...] = applied.astype(np.uint8)
    x0, y0, x1, y1 = layers.top_band
    band_h = y1 - y0
    dy = round(progress * band_h)
    if dy < band_h:
        region = out[y0:y1 - dy, x0:x1]
        region[...] = _apply_layer_np(
            np, region, arrays.top_add[dy:band_h], arrays.top_keep[dy:band_h],
        )
    x0, y0, x1, y1 = layers.bottom_band
    band_h = y1 - y0
    dy = round(progress * band_h)
    if dy < band_h:
        region = out[y0 + dy:y1, x0:x1]
        region[...] = _apply_layer_np(
            np, region, arrays.bottom_add[:band_h - dy], arrays.bottom_keep[:band_h - dy],
        )
    return Image.fromarray(out, "RGB")


def _reveal_frame_pillow(base, layers: RevealLayers, progress: float) -> Image.Image:
    """_reveal_frame() with Pillow's own chop and blend operations."""
    width, height = layers.strip[2], layers.bottom_band[3]
    out = _new_frame(base, width, height, BG_BASE)
    x0, y0, x1, y1 = layers.strip
    if x1 > x0 and y1 > y0:
        region = out.crop(layers.strip)
        faded = Image.blend(
            region, _apply_layer(region, layers.strip_add, layers.strip_keep), 1.0 - progress,
        )
        out.paste(faded, (x0, y0))
    x0, y0, x1, y1 = layers.top_band
    band_h = y1 - y0
    dy = round(progress * band_h)
    if dy < band_h:
        region = out.crop((x0, y0, x1, y1 - dy))
        chrome = (0, dy, x1 - x0, band_h)
        out.paste(
            _apply_layer(region, layers.top_add.crop(chrome), layers.top_keep.crop(chrome)),
            (x0, y0),
        )
    x0, y0, x1, y1 = layers.bottom_band
    band_h = y1 - y0
    dy = round(progress * band_h)
    if dy < band_h:
        region = out.crop((x0, y0 + dy, x1, y1))
        chrome = (0, 0, x1 - x0, band_h - dy)
        out.paste(
            _apply_layer(region, layers.bottom_add.crop(chrome), layers.bottom_keep.crop(chrome)),
            (x0, y0 + dy),
        )
    return out


def _draw_header(img: Image.Image, layout, header: Header, metrics: LayoutMetrics) -> None:
    _draw_top_band_content(
        img,
        dots_rect=layout.dots if (header.dots_filled is not None and not header.back) else None,
        dots_filled=None if header.back else header.dots_filled,
        dots_count=header.dots_count,
        name_rect=layout.name, name_text=header.name,
        volume_cluster_rect=layout.volume_cluster,
        volume=header.volume, muted=header.muted,
        metrics=metrics,
    )
    if header.back:
        # The per-output detail page's own back control: an X, the same
        # glyph and icon-sized box the rail's own cancel control uses,
        # drawn into the same rect the pager dots would otherwise occupy —
        # the two are mutually exclusive (dots_filled is suppressed above
        # whenever back is set).
        _draw_glyph(img, _centred_box(layout.dots, metrics.icon), GLYPH_CROSS, supersample=metrics.supersample)


def _body_none(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    pass


def _body_idle_badge(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    """The idle screen's own corner glyphs, drawn regardless of which base
    image (the plain logo or the replay-available one) is showing
    underneath — see compose_idle(): the "i" information badge top-right,
    and the Wi-Fi status glyph top-left as body.wifi_style says. WIFI_SIGNAL
    lights body.wifi_bars arcs, WIFI_GREY dims every part, WIFI_RED paints
    every part in alarm red, and WIFI_OFF draws no glyph at all — the base
    shows through untouched, so the flash's blank half really is blank (no
    tile is built or cached for it). An unrecognised style is treated as
    WIFI_SIGNAL."""
    layout = idle_layout_for(metrics.width, metrics.height, metrics=metrics)
    x0, y0, x1, y1 = layout.info
    side = round(min(x1 - x0, y1 - y0) * _INFO_GLYPH_FRACTION)
    _draw_glyph(img, _centred_box(layout.info, side), GLYPH_INFO, supersample=metrics.supersample)
    style = body.wifi_style
    if style == WIFI_OFF:
        return
    if style == WIFI_RED:
        lit, color = 3, _ALARM_RGB
    elif style == WIFI_GREY:
        lit, color = 0, _GLYPH_RGB
    else:
        lit, color = max(0, min(3, int(body.wifi_bars))), _GLYPH_RGB
    _draw_glyph(img, layout.wifi, GLYPH_WIFI, lit, color, supersample=metrics.supersample)


def _body_now_playing(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    layout = layout_for(metrics.width, metrics.height, metrics=metrics)
    font = _load_font(metrics.font_body)
    if layout.album is not None:
        _draw_text_with_halo(img, layout.album, body.album, font, metrics)
    _draw_text_with_halo(img, layout.title, body.title, font, metrics)
    _draw_text_with_halo(img, layout.artist, body.artist, font, metrics)


def _draw_toggle_row(
    img: Image.Image, metrics: LayoutMetrics, row_rect: tuple[int, int, int, int], label: str, armed: bool,
    *, dot_box: int | None = None,
) -> None:
    """A label plus an on/off dot marker drawn into *row_rect* — shared by
    the repeat screen's "Repeat Play" enable row, the per-output detail
    page's own enable row (both pass repeat_layout_for(...).row) and the
    compact tier's own enable screen (which passes its bottom_row instead).

    *dot_box* sizes the arm-dot's own box, width only — its height still
    always spans the full *row_rect*, so the dot itself (drawn centred
    within that box by _draw_arm_dot) stays vertically centred on the row
    either way. None (every non-compact caller) keeps today's box: the
    row's own height, giving a square box exactly as before. The compact
    tier's own row is far taller relative to its own width than the base
    tier's row ever is, so its own caller (_body_compact_toggle) passes a
    smaller fixed width instead — the row is a single touch zone regardless
    of how big the dot itself is drawn, so shrinking it costs nothing but
    frees the width "Repeat Play" needs to fit without truncating."""
    pad = metrics.pad
    row_font = _load_font(metrics.font_body)
    draw = ImageDraw.Draw(img)
    box_w = dot_box if dot_box is not None else row_rect[3] - row_rect[1]
    dot_rect = (row_rect[2] - pad - box_w, row_rect[1], row_rect[2] - pad, row_rect[3])
    label_rect = (row_rect[0], row_rect[1], dot_rect[0] - pad, row_rect[3])
    _draw_label(draw, label_rect, label, row_font, pad)
    _draw_glyph(img, dot_rect, GLYPH_ARM_DOT, armed, supersample=metrics.supersample)


def _body_toggle_row(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    """A label plus an on/off dot marker on the shared toggle-row rect —
    the repeat screen's "Repeat Play" enable row and the per-output detail
    page's own enable row are the same layout with a different label."""
    layout = repeat_layout_for(metrics.width, metrics.height, metrics=metrics)
    _draw_toggle_row(img, metrics, layout.row, body.label, body.armed)


def _body_repeat_line(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    layout = repeat_layout_for(metrics.width, metrics.height, metrics=metrics)
    font = _load_font(metrics.font_readout)
    _draw_text_with_halo(img, layout.line, body.line, font, metrics, align="center")


def _draw_timer_line(img: Image.Image, text: str, alpha: float, metrics: LayoutMetrics) -> Image.Image:
    """The main screen's replay position line (see compose()'s timer_text):
    *text* centred at the readout size, with its halo, in the artwork
    between the top band and the first of the album/title lines, blended
    in at *alpha*. Returns a new image; *img* is never drawn on, since it
    may be the caller's cached base. Never raises: any failure returns
    *img* unchanged."""
    try:
        layout = layout_for(img.width, img.height, metrics=metrics)
        first_line = layout.album if layout.album is not None else layout.title
        rect = (first_line[0], layout.top_band[3], first_line[2], first_line[1])
        if rect[3] <= rect[1]:
            return img
        out = img.copy()
        region = out.crop(rect)
        drawn = region.copy()
        local = (0, 0, rect[2] - rect[0], rect[3] - rect[1])
        _draw_text_with_halo(drawn, local, text, _load_font(metrics.font_readout), metrics, align="center")
        if alpha < 1.0:
            drawn = Image.blend(region, drawn, max(0.0, alpha))
        out.paste(drawn, rect[:2])
        return out
    except Exception:
        return img


# The row marker's box side as a fraction of the row height. At 0.75 the
# glyph's reach (0.28 of the box each way) gives a 25 px triangle on a
# 60 px row against a 24 px body font: the marker reads at the text's own
# size rather than taller than it, as a row-height box did.
_MARKER_BOX_FRACTION = 0.75


def _row_text_color(secondary) -> tuple:
    """The text colour of a list row: dimmed when its secondary text is the
    selector's "not authorised" label, the plain glyph colour otherwise."""
    return _DIMMED_GLYPH_RGB if secondary == NOT_AUTHORISED_TEXT else _GLYPH_RGB


def _body_list_rows(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    layout = list_layout_for(metrics.width, metrics.height, metrics=metrics)
    draw = ImageDraw.Draw(img)
    row_font = _load_font(metrics.font_body)
    pad = metrics.pad

    for i, (x0, y0, x1, y1) in enumerate(layout.rows):
        draw.line([(x0, y1 - 1), (x1 - 1, y1 - 1)], fill=_LIST_SEPARATOR_RGB, width=1)
        if i >= len(body.rows):
            continue
        row = body.rows[i]
        label = row[0]
        secondary = row[2] if len(row) > 2 else ""
        row_color = _row_text_color(secondary)
        cy = (y0 + y1) // 2
        right_edge = x1 - pad

        # One marker box at the row's right, smaller than the row and in
        # the plain glyph white: the play marker when the row carries one,
        # else nothing. "Current" is not a marker: the pipeline washes the
        # current row before any content is drawn (see _list_frame).
        if secondary is PLAY_GLYPH:
            box = max(2, round(layout.row_h * _MARKER_BOX_FRACTION))
            top = y0 + (layout.row_h - box) // 2
            marker_rect = (right_edge - box, top, right_edge, top + box)
            _draw_glyph(img, marker_rect, GLYPH_PLAY, supersample=metrics.supersample)
            draw = ImageDraw.Draw(img)
            right_edge -= box

        if isinstance(secondary, str) and secondary and row_font is not None:
            measured_sec = _text_size(draw, secondary, row_font)
            if measured_sec is not None:
                sec_w, sec_h, sec_bbox = measured_sec
                sec_left, sec_top, _, _ = sec_bbox
                sec_x = right_edge - sec_w
                _draw_text_safe(
                    draw, (sec_x - sec_left, cy - sec_h // 2 - sec_top), secondary, row_font, fill=row_color,
                )
                right_edge = sec_x - pad

        if label and row_font is not None and right_edge > x0 + pad:
            text = _truncate_to_width(draw, label, row_font, right_edge - (x0 + pad))
            if text:
                measured = _text_size(draw, text, row_font)
                if measured is not None:
                    text_w, text_h, bbox = measured
                    left, top, _, _ = bbox
                    _draw_text_safe(draw, (x0 + pad - left, cy - text_h // 2 - top), text, row_font, fill=row_color)


# ---------------------------------------------------------------------------
# Compact-tier (2x2) body renderers. Every one of them draws straight onto
# the compact_layout_for() grid — the four cells plus the two divider
# lines, always drawn last so they sit on top of any glyph's own edges —
# rather than layout_for()'s band/body/footer rects, which the compact
# screens never use for drawing (only zone_rects_for() reads them, and only
# off the compact tier).
# ---------------------------------------------------------------------------


def _compact_glyph_box(rect: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """A glyph box centred within *rect*, sized at _COMPACT_GLYPH_FRACTION
    of its own short side — the compact tier's one glyph-sizing rule,
    shared by every compact cell/row except minus/plus (which are drawn
    straight onto the cell rect by the existing _draw_minus_glyph/_draw_
    plus_glyph, which derive their own reach from the rect's own size)."""
    x0, y0, x1, y1 = rect
    side = round(min(x1 - x0, y1 - y0) * _COMPACT_GLYPH_FRACTION)
    return _centred_box(rect, side)


def _compact_small_glyph_box(rect: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """A smaller glyph box than _compact_glyph_box's, sized at
    _COMPACT_SMALL_GLYPH_FRACTION of *rect*'s own short side — used only for
    the replay picker's cancel and "more" cells, which sit in a narrower
    column beside the two visible targets and read better at a size smaller
    than every other compact cell's own glyph."""
    x0, y0, x1, y1 = rect
    side = round(min(x1 - x0, y1 - y0) * _COMPACT_SMALL_GLYPH_FRACTION)
    return _centred_box(rect, side)


def _draw_compact_picker_dividers(img: Image.Image, layout: "CompactPickerLayout", metrics: LayoutMetrics) -> None:
    """The replay picker's own white divider lines, drawn last so they sit
    on top of any glyph's own edges: the line under the title band (full
    width), the line between the two grid rows (full width), and the column
    line separating the controls from the two targets — drawn only from the
    title line down to the bottom edge, since it never crosses the title
    band itself."""
    draw = ImageDraw.Draw(img)
    w = metrics.divider_w
    draw.line(
        [(0, layout.title_divider_y), (metrics.width - 1, layout.title_divider_y)], fill=_DIVIDER_RGB, width=w,
    )
    draw.line([(0, layout.divider_y), (metrics.width - 1, layout.divider_y)], fill=_DIVIDER_RGB, width=w)
    draw.line(
        [(layout.divider_x, layout.title_divider_y), (layout.divider_x, metrics.height - 1)],
        fill=_DIVIDER_RGB, width=w,
    )


def _draw_compact_dividers(
    img: Image.Image, layout: "CompactLayout", metrics: LayoutMetrics, *, vertical: str,
) -> None:
    """The compact tier's own white divider lines, drawn last so they sit
    on top of any glyph's own edges. The horizontal line at divider_y,
    spanning the full width, is always drawn; *vertical* selects how much
    of the line at divider_x is drawn: "full" (both rows — the playing 2x2
    and the repeat screen's replaying layout, now its own 2x2), "top" (the
    top row only — the repeat screen's enable layout, whose bottom row is a
    single full-width toggle strip), "bottom" (the bottom row only) or
    "none" (neither row has a vertical divider)."""
    draw = ImageDraw.Draw(img)
    w = metrics.divider_w
    draw.line([(0, layout.divider_y), (metrics.width - 1, layout.divider_y)], fill=_DIVIDER_RGB, width=w)
    if vertical == "full":
        draw.line([(layout.divider_x, 0), (layout.divider_x, metrics.height - 1)], fill=_DIVIDER_RGB, width=w)
    elif vertical == "top":
        y1 = layout.top_row[3]
        draw.line([(layout.divider_x, 0), (layout.divider_x, y1 - 1)], fill=_DIVIDER_RGB, width=w)
    elif vertical == "bottom":
        y0 = layout.bottom_row[1]
        draw.line([(layout.divider_x, y0), (layout.divider_x, metrics.height - 1)], fill=_DIVIDER_RGB, width=w)


def _body_compact_controls(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    """The compact tier's playing screen: pager dots (dimmed when there is
    no repeat record to open), mute (inverted over a solid wash while
    muted — the wash itself is a Frame.washes entry, drawn before this body
    runs), minus and plus."""
    c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
    ss = metrics.supersample
    dots_color = _GLYPH_RGB if body.dots_lit else _DIMMED_GLYPH_RGB
    _draw_glyph(img, _compact_glyph_box(c.tl), GLYPH_TWO_DOTS, 0, dots_color, supersample=ss)
    mute_color = _INVERTED_GLYPH_RGB if body.muted else _GLYPH_RGB
    _draw_glyph(img, _compact_glyph_box(c.tr), GLYPH_MUTE, mute_color, supersample=ss)
    draw = ImageDraw.Draw(img)
    _draw_minus_glyph(draw, c.bl)
    _draw_plus_glyph(draw, c.br)
    _draw_compact_dividers(img, c, metrics, vertical="full")


def _draw_compact_list_row(
    img: Image.Image, cell: tuple[int, int, int, int], row: tuple, font, pad: int,
) -> None:
    """One compact-picker row: the label centred in the cell's upper half,
    the secondary "m:ss" string (when it is a plain string — the compact
    picker never carries the appliance-selector's PLAY_GLYPH sentinel)
    centred in the lower half. A row with no secondary (the compact info
    page's own names-only rows) has no lower half to share the cell with, so
    its label is centred on the whole cell instead — the picker's own rows
    always carry "m:ss", so their placement is unchanged. No halo: the whole
    compact frame is already dimmed by Frame.dim_all, unlike the base
    tier's own artwork-backed labels."""
    x0, y0, x1, y1 = cell
    mid = (y0 + y1) // 2
    upper = (x0, y0, x1, mid)
    lower = (x0, mid, x1, y1)
    secondary = row[2] if len(row) > 2 else ""
    has_secondary = isinstance(secondary, str) and bool(secondary)
    label_rect = upper if has_secondary else cell
    draw = ImageDraw.Draw(img)
    max_w = x1 - x0 - 2 * pad
    color = _row_text_color(secondary)
    label = row[0]
    if label and font is not None and max_w > 0:
        text = _truncate_to_width(draw, label, font, max_w)
        _draw_label_centered(draw, label_rect, text, font, color)
    if has_secondary and font is not None and max_w > 0:
        text = _truncate_to_width(draw, secondary, font, max_w)
        _draw_label_centered(draw, lower, text, font, color)


def _body_compact_list(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    """The compact tier's replay picker (or, for the info page, its own
    read-only variant): a tight title bar across the top, horizontally
    centred — the picker's own "Replay" when body.title is unset, else
    body.title (the info page's "Info") — then a 35/65 split — cancel
    top-left and "more" (lit when a second page exists — the compact tier
    wraps rather than clamping, see the manager's own paging) bottom-left,
    both drawn at the picker's own smaller glyph size; the two visible rows
    (current-row highlighting is a Frame.highlights entry, drawn before this
    body runs) fill the right column."""
    p = compact_picker_layout_for(metrics.width, metrics.height, metrics=metrics)
    draw = ImageDraw.Draw(img)
    _draw_label_centered(draw, p.title, body.title or _COMPACT_PICKER_TITLE, _load_font(metrics.font_body))
    row_font = _load_font(metrics.font_body)
    pad = metrics.pad
    for cell, row in zip((p.row0, p.row1), body.rows):
        _draw_compact_list_row(img, cell, row, row_font, pad)
    ss = metrics.supersample
    _draw_glyph(img, _compact_small_glyph_box(p.cancel), GLYPH_CROSS, supersample=ss)
    _draw_glyph(img, _compact_small_glyph_box(p.more), GLYPH_CHEVRON, "down", body.has_more, supersample=ss)
    _draw_compact_picker_dividers(img, p, metrics)


def _body_compact_toggle(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    """The compact tier's repeat-enable screen: the back control (second
    dot lit) top-left, "Repeat Play" plus its arm dot spanning the full
    bottom row — no separate cancel; the top-right cell is left empty. The
    arm dot's own box is capped at metrics.icon (the same reference every
    other compact icon-sized glyph already uses) rather than the row's own
    height: that row is far taller relative to its own width than the base
    tier's row ever is, so the label needs the width back to fit "Repeat
    Play" whole (see _draw_toggle_row's own dot_box paragraph)."""
    c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
    _draw_glyph(img, _compact_glyph_box(c.tl), GLYPH_TWO_DOTS, 1, _GLYPH_RGB, supersample=metrics.supersample)
    _draw_toggle_row(img, metrics, c.bottom_row, body.label, body.armed, dot_box=metrics.icon)
    _draw_compact_dividers(img, c, metrics, vertical="top")


def _body_compact_replay(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    """The compact tier's repeat-replaying screen, its own 2x2: the back
    control (second dot lit) top-left, the position-only time (never the
    duration — the manager's own "m:ss / m:ss" line, split before " / ")
    top-right with a halo, like the base tier's own repeat line, Restart
    bottom-left and Stop bottom-right, each dimmed when its own action is
    not currently accepted."""
    c = compact_layout_for(metrics.width, metrics.height, metrics=metrics)
    ss = metrics.supersample
    _draw_glyph(img, _compact_glyph_box(c.tl), GLYPH_TWO_DOTS, 1, _GLYPH_RGB, supersample=ss)
    font = _load_font(metrics.font_readout)
    position = body.line.split(" / ", 1)[0] if body.line else body.line
    _draw_text_with_halo(img, c.tr, position, font, metrics, align="center")
    start_color = _GLYPH_RGB if body.start_enabled else _DIMMED_GLYPH_RGB
    stop_color = _GLYPH_RGB if body.stop_enabled else _DIMMED_GLYPH_RGB
    _draw_glyph(img, _compact_glyph_box(c.bl), GLYPH_RESTART, start_color, supersample=ss)
    _draw_glyph(img, _compact_glyph_box(c.br), GLYPH_STOP, stop_color, supersample=ss)
    _draw_compact_dividers(img, c, metrics, vertical="full")


def _body_info_value(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    """The compact info page's own drill-in: the field's name small in the
    top label band, its value large and centred in the rect below —
    word-wrapped (or, for one over-wide token, character-split) at
    font_readout when it does not fit on one line, shrunk to font_body when
    it still does not, and ellipsized as a last resort — see
    _fit_value_lines(). Never raises: a missing font or a measuring failure
    simply leaves that element undrawn, the same discipline every text
    helper in this module follows."""
    layout = info_value_layout_for(metrics.width, metrics.height, metrics=metrics)
    draw = ImageDraw.Draw(img)
    _draw_label_centered(draw, layout.label, body.label, _load_font(metrics.font_body))
    font_readout = _load_font(metrics.font_readout)
    font_body = _load_font(metrics.font_body)
    lines, font = _fit_value_lines(draw, body.line, (metrics.font_readout, metrics.font_body), layout.value)
    if not lines or font is None:
        return
    size = metrics.font_readout if font is font_readout else metrics.font_body
    line_h = size * 1.2
    x0, y0, x1, y1 = layout.value
    top = y0 + (y1 - y0 - len(lines) * line_h) / 2
    for i, line in enumerate(lines):
        row_rect = (x0, int(round(top + i * line_h)), x1, int(round(top + (i + 1) * line_h)))
        _draw_label_centered(draw, row_rect, line, font)


def _eq_caption_text(value: "int | None") -> str:
    """The dB caption a bar's right side shows: "-" while unloaded, else a
    signed whole-dB reading ("+2 dB", "0 dB", "-3 dB")."""
    if value is None:
        return "-"
    return f"{value:+d} dB" if value != 0 else "0 dB"


def _draw_eq_bar(img: Image.Image, bar, label: str, value: "int | None", metrics: LayoutMetrics) -> None:
    """One EQ bar row (bass or treble): the caption (label left, dB right),
    the dimmed track line with a white centre tick, a white fill from
    centre to the marker when the value is known, the marker disc itself,
    and the minus/plus controls — dimmed at the range's own limit or while
    the value has not yet loaded."""
    draw = ImageDraw.Draw(img)
    font = _load_font(metrics.font_body)
    pad = metrics.pad
    _draw_label(draw, bar.caption, label, font, pad)
    _draw_label_right(draw, bar.caption, _eq_caption_text(value), font, pad)

    w = metrics.divider_w
    draw.line([(bar.track_x0, bar.track_y), (bar.track_x1, bar.track_y)], fill=_DIMMED_GLYPH_RGB, width=w)
    draw.line(
        [(bar.centre_x, bar.track_y - 2 * w), (bar.centre_x, bar.track_y + 2 * w)], fill=_GLYPH_RGB, width=w,
    )
    if value is not None:
        marker_x = bar.centre_x + round(value * (bar.track_x1 - bar.centre_x) / EQ_LIMIT_DB)
        x0, x1 = sorted((bar.centre_x, marker_x))
        draw.line([(x0, bar.track_y), (x1, bar.track_y)], fill=_GLYPH_RGB, width=3 * w)
        r = max(3, pad // 2)
        draw.ellipse([marker_x - r, bar.track_y - r, marker_x + r, bar.track_y + r], fill=_GLYPH_RGB)

    at_min = value is not None and value <= -EQ_LIMIT_DB
    at_max = value is not None and value >= EQ_LIMIT_DB
    minus_color = _DIMMED_GLYPH_RGB if (value is None or at_min) else _GLYPH_RGB
    plus_color = _DIMMED_GLYPH_RGB if (value is None or at_max) else _GLYPH_RGB
    _draw_minus_glyph(draw, bar.down, color=minus_color)
    _draw_plus_glyph(draw, bar.up, color=plus_color)


def _body_eq_bars(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    """The EQ page's own body: the bass bar over the treble bar (see
    eq_layout_for), plus a thin white divider between the two rows at the
    midpoint of the gap between them — the band-divider colour, matching
    every other inter-row boundary in the compositor."""
    layout = eq_layout_for(metrics.width, metrics.height, metrics=metrics)
    _draw_eq_bar(img, layout.bass, "Bass", body.bass_db, metrics)
    _draw_eq_bar(img, layout.treble, "Treble", body.treble_db, metrics)
    divider_y = (layout.bass.row[3] + layout.treble.row[1]) // 2
    ImageDraw.Draw(img).line(
        [(0, divider_y), (metrics.width - 1, divider_y)], fill=_DIVIDER_RGB, width=metrics.divider_w,
    )


def _body_warning(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    """A warning page's content on every tier. With no message the title
    is centred in the whole message row at readout size; with one, the
    title takes the upper three fifths of the row and the message the
    rest at body size. Each button label is centred in its cell at body
    size. Then the crosshair: a horizontal line at divider_y across the
    card's full width, and one vertical line per gap between cells,
    spanning the bottom row only (the message row is never split). On
    the compact tier the card is the whole panel, so a two-button page
    is exactly the 2x2's own bottom-row divider pattern and a one-button
    page has no vertical line at all. A page with no cells has no
    crosshair. With body.percent set, a progress bar takes the bottom
    quarter of the message row (a dimmed track from the card's inner left
    to right edge, a white fill to the percent) and the text is laid out
    in the rest of the row."""
    layout = warning_layout_for(metrics.width, metrics.height, buttons=len(body.buttons), metrics=metrics)
    draw = ImageDraw.Draw(img)
    readout_font = _load_font(metrics.font_readout)
    body_font = _load_font(metrics.font_body)
    mx0, my0, mx1, my1 = layout.message
    w = metrics.divider_w
    if body.percent is not None:
        zone = (my1 - my0) // 4
        bar_h = max(3, 2 * w)
        bar_y0 = my1 - zone // 2 - bar_h // 2
        x0, x1 = mx0 + metrics.pad, mx1 - metrics.pad
        fill_x1 = x0 + round((x1 - x0) * max(0, min(100, body.percent)) / 100)
        draw.rectangle([x0, bar_y0, x1 - 1, bar_y0 + bar_h - 1], fill=_DIMMED_GLYPH_RGB)
        if fill_x1 > x0:
            draw.rectangle([x0, bar_y0, fill_x1 - 1, bar_y0 + bar_h - 1], fill=_GLYPH_RGB)
        my1 -= zone
    if body.line:
        split = my0 + (my1 - my0) * 3 // 5
        _draw_label_centered(draw, (mx0, my0, mx1, split), body.title, readout_font)
        _draw_label_centered(draw, (mx0, split, mx1, my1), body.line, body_font)
    else:
        _draw_label_centered(draw, (mx0, my0, mx1, my1), body.title, readout_font)
    for rect, label in zip(layout.cells, body.buttons):
        _draw_label_centered(draw, rect, label, body_font)
    if not layout.cells:
        return
    cx0, cy0, cx1, cy1 = layout.card
    draw.line([(cx0, layout.divider_y), (cx1 - 1, layout.divider_y)], fill=_DIVIDER_RGB, width=w)
    for x in layout.divider_xs:
        draw.line([(x, layout.cells[0][1]), (x, cy1 - 1)], fill=_DIVIDER_RGB, width=w)


def _body_centred_label(img: Image.Image, metrics: LayoutMetrics, body: Body) -> None:
    """One string (body.line) centred on the whole panel at the readout
    size — the "Restarting..." and "Starting..." screens."""
    draw = ImageDraw.Draw(img)
    _draw_label_centered(draw, (0, 0, metrics.width, metrics.height), body.line, _load_font(metrics.font_readout))


_BODY_RENDERERS = {
    BODY_NONE: _body_none,
    BODY_NOW_PLAYING: _body_now_playing,
    BODY_REPEAT_ROW: _body_toggle_row,
    BODY_TOGGLE_ROW: _body_toggle_row,
    BODY_REPEAT_LINE: _body_repeat_line,
    BODY_LIST_ROWS: _body_list_rows,
    BODY_IDLE_BADGE: _body_idle_badge,
    BODY_COMPACT_CONTROLS: _body_compact_controls,
    BODY_COMPACT_LIST: _body_compact_list,
    BODY_COMPACT_TOGGLE: _body_compact_toggle,
    BODY_COMPACT_REPLAY: _body_compact_replay,
    BODY_INFO_VALUE: _body_info_value,
    BODY_EQ_BARS: _body_eq_bars,
    BODY_WARNING: _body_warning,
    BODY_CENTRED_LABEL: _body_centred_label,
}


def _footer_none(img: Image.Image, layout, metrics: LayoutMetrics, footer: Footer) -> None:
    pass


def _footer_volume(img: Image.Image, layout, metrics: LayoutMetrics, footer: Footer) -> None:
    """The two-way minus/plus footer (the repeat screen's replaying layout,
    the per-output detail page). Each glyph dims to _DIMMED_GLYPH_RGB when
    its own side is disabled (Footer.left_enabled/right_enabled) — the
    detail page's own steppers when the output is not selected, matching
    the shade the disabled Restart/Stop labels already use elsewhere."""
    left_color = _GLYPH_RGB if footer.left_enabled else _DIMMED_GLYPH_RGB
    right_color = _GLYPH_RGB if footer.right_enabled else _DIMMED_GLYPH_RGB
    _draw_bottom_band(
        img, layout, metrics,
        left_rect=layout.down, right_rect=layout.up,
        draw_left=lambda d, r: _draw_minus_glyph(d, r, color=left_color),
        draw_right=lambda d, r: _draw_plus_glyph(d, r, color=right_color),
    )


def _footer_volume_mute(img: Image.Image, layout, metrics: LayoutMetrics, footer: Footer) -> None:
    """The main screen's own three-way footer: minus | plus | mute, left to
    right (the owner's chosen order — vol-/vol+ stay at today's thumb
    positions, mute moves off the header into its own cell). The mute cell
    always shows the crossed-speaker glyph (GLYPH_MUTE) — this control IS
    the mute toggle, not a state readout — and carries the persistent wash
    while muted (see _now_playing_frame's `highlights`), on top of which a
    genuine press adds the momentary wash."""
    draw = ImageDraw.Draw(img)
    _draw_minus_glyph(draw, layout.footer_down)
    _draw_plus_glyph(draw, layout.footer_up)
    _draw_glyph(img, layout.footer_mute, GLYPH_MUTE, supersample=metrics.supersample)
    draw = ImageDraw.Draw(img)  # _draw_glyph pastes into img; get a fresh Draw handle
    _draw_band_divider(draw, layout, metrics, layout.footer_dividers)


def _footer_labels(img: Image.Image, layout, metrics: LayoutMetrics, footer: Footer) -> None:
    font = _load_font(metrics.font_readout)
    left_color = _GLYPH_RGB if footer.left_enabled else _DIMMED_GLYPH_RGB
    right_color = _GLYPH_RGB if footer.right_enabled else _DIMMED_GLYPH_RGB
    _draw_bottom_band(
        img, layout, metrics,
        left_rect=layout.down, right_rect=layout.up,
        draw_left=lambda d, r: _draw_label_centered(d, r, footer.left_text, font, color=left_color),
        draw_right=lambda d, r: _draw_label_centered(d, r, footer.right_text, font, color=right_color),
    )


def _footer_list_bar(img: Image.Image, layout, metrics: LayoutMetrics, footer: Footer) -> None:
    ll = list_layout_for(metrics.width, metrics.height, metrics=metrics)
    ss = metrics.supersample
    _draw_glyph(img, ll.back, GLYPH_CHEVRON, "left", True, supersample=ss)
    _draw_glyph(img, ll.down, GLYPH_CHEVRON, "down", footer.has_next, supersample=ss)
    _draw_glyph(img, ll.up, GLYPH_CHEVRON, "up", footer.has_prev, supersample=ss)


def _footer_list_rail(img: Image.Image, layout, metrics: LayoutMetrics, footer: Footer) -> None:
    """The right-rail counterpart to _footer_list_bar(): the same three
    controls (previous page, back/cancel, next page), stacked top to bottom
    in a dimmed column at the panel's right edge instead of side by side in
    a bottom bar. A 1px separator column marks the boundary between the rows
    and the rail, in the same shade the row separators use. Each glyph is
    drawn into a centred metrics.rail_glyph-side box within its own zone,
    not the whole zone — the rail column stays a full touch target even
    though the glyph inside it is smaller."""
    ll = list_layout_for(metrics.width, metrics.height, metrics=metrics)
    _dim_rect(img, ll.rail)
    ImageDraw.Draw(img).line(
        [(ll.rail[0] - 1, 0), (ll.rail[0] - 1, ll.rail[3] - 1)], fill=_LIST_SEPARATOR_RGB, width=1,
    )
    ss = metrics.supersample
    side = metrics.rail_glyph
    _draw_glyph(img, _centred_box(ll.rail_up, side), GLYPH_CHEVRON, "up", footer.has_prev, supersample=ss)
    _draw_glyph(img, _centred_box(ll.rail_cancel, side), GLYPH_CROSS, supersample=ss)
    _draw_glyph(img, _centred_box(ll.rail_down, side), GLYPH_CHEVRON, "down", footer.has_next, supersample=ss)


_FOOTER_RENDERERS = {
    FOOTER_NONE: _footer_none,
    FOOTER_VOLUME: _footer_volume,
    FOOTER_VOLUME_MUTE: _footer_volume_mute,
    FOOTER_LABELS: _footer_labels,
    FOOTER_LIST_BAR: _footer_list_bar,
    FOOTER_LIST_RAIL: _footer_list_rail,
}


def _draw_card(img: Image.Image, rect: Rect, metrics: LayoutMetrics) -> None:
    """A sharp-cornered card: a dark translucent drop shadow offset down
    and right by the panel's pad, a flat fill, then a thin translucent
    white outline. The shadow and outline are each a _draw_wash-style
    alpha composite clipped to the panel, so nothing outside the panel is
    ever touched and the outline reads as a subtle edge rather than a hard
    line."""
    x0, y0, x1, y1 = rect
    offset = max(2, metrics.pad // 2)
    shadow = (
        min(metrics.width, x0 + offset), min(metrics.height, y0 + offset),
        min(metrics.width, x1 + offset), min(metrics.height, y1 + offset),
    )
    _draw_wash(img, shadow, _CARD_SHADOW_RGB, _CARD_SHADOW_ALPHA)
    draw = ImageDraw.Draw(img)
    draw.rectangle([x0, y0, x1 - 1, y1 - 1], fill=_CARD_FILL_RGB)
    _draw_card_outline(img, (x0, y0, x1, y1), metrics.divider_w)


def _draw_card_outline(img: Image.Image, rect: Rect, width: int) -> None:
    """The card's own thin outline, alpha-composited over its fill so it
    reads as a subtle translucent edge rather than a flat, opaque line."""
    x0, y0, x1, y1 = rect
    w, h = x1 - x0, y1 - y0
    if w <= 0 or h <= 0:
        return
    layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    ImageDraw.Draw(layer).rectangle(
        [0, 0, w - 1, h - 1], outline=(*_CARD_OUTLINE_RGB, _CARD_OUTLINE_ALPHA), width=width,
    )
    region = img.crop(rect).convert("RGBA")
    composited = Image.alpha_composite(region, layer).convert("RGB")
    img.paste(composited, (x0, y0))


def _compose_frame(
    base, width: int, height: int, frame: Frame, *, rotate: bool, bgr: bool,
    metrics: LayoutMetrics | None = None,
) -> Image.Image:
    """The one pipeline every screen frame is built from: background, dims,
    then any row highlights, pressed wash, header, body, footer, then
    rotate/BGR. *frame* carries everything screen-specific; the geometry
    itself always comes from layout_for() (plus list_layout_for()/
    repeat_layout_for() inside the renderers that need them) — never
    computed here. *metrics*=None means metrics_for(width, height) —
    today's geometry, density-unaware.

    Dimming happens before the pressed wash so a highlighted zone still
    reads brighter than its dimmed surroundings, matching the dimmed band
    it sits on; the wash happens before any content so text/glyphs always
    land on top of it. The row highlight sits under a persistent state
    wash, which itself sits under the pressed wash — a genuine touch always
    reads as an additional flash over any state already shown. Body and
    footer never overlap, so their relative order does not matter. No
    blanket exception handling here: every draw helper already degrades on
    its own (a missing font or a Pillow failure simply skips that one
    element), and an unrecognised body/footer kind is a programming error
    that should raise rather than be swallowed.
    """
    if metrics is None:
        metrics = metrics_for(width, height)
    img = _new_frame(base, width, height, frame.background)
    layout = layout_for(width, height, metrics=metrics)
    if frame.dim_top:
        _dim_rect(img, layout.top_band)
    if frame.dim_bottom:
        _dim_rect(img, layout.bottom_band)
    if frame.dim_all:
        _dim_rect(img, (0, 0, width, height))
    if frame.card is not None:
        _draw_card(img, frame.card, metrics)
    for rect in frame.highlights:
        _draw_row_highlight(img, rect)
    for rect, alpha in frame.washes:
        _draw_wash(img, rect, _PRESSED_FILL_RGB, alpha)
    for rect in frame.pressed:
        _draw_pressed_highlight(img, rect)
    if frame.header is not None:
        _draw_header(img, layout, frame.header, metrics)
    _BODY_RENDERERS[frame.body.kind](img, metrics, frame.body)
    _FOOTER_RENDERERS[frame.footer.kind](img, layout, metrics, frame.footer)
    return _finish(img, rotate, bgr)


def _zone_rect(
    geometry: str, zone: "TouchZone | None", index: "int | None", width: int, height: int,
    metrics: "LayoutMetrics | None" = None,
) -> "Rect | None":
    """The rect the touch layer would report for (zone, index) on
    *geometry*, or None when no such entry exists (a zone from another
    geometry, or a stale LIST_ROW index): nothing is washed. *metrics*
    resolves the same way zone_rects_for() resolves it, so a pressed rect
    is always looked up against the exact geometry a renderer drew — never
    a density-free approximation of it."""
    if zone is None:
        return None
    for entry in zone_rects_for(geometry, width, height, metrics=metrics):
        if entry.zone == zone and entry.index == index:
            return entry.rect
    return None


def _main_pressed_rects(
    pressed: "TouchZone | None", width: int, height: int, metrics: "LayoutMetrics | None" = None,
) -> tuple[Rect, ...]:
    """The now-playing screen's pressed-rect lookup: a stale or unrecognised
    zone (e.g. one that belongs to a different geometry) washes nothing."""
    rect = _zone_rect(GEOMETRY_MAIN, pressed, None, width, height, metrics)
    return (rect,) if rect is not None else ()


def _compact_controls_frame(overlay: OverlayState, width: int, height: int, metrics: LayoutMetrics) -> Frame:
    """The compact tier's playing screen: dimmed base behind, the mute
    cell's own solid wash when muted (before the body's inverted glyph
    draws over it — see _compose_frame's draw order), pressed resolved
    against the compact MAIN table automatically (GEOMETRY_MAIN itself
    branches on the tier)."""
    c = compact_layout_for(width, height, metrics=metrics)
    return Frame(
        background=BG_BASE,
        dim_all=True,
        pressed=_main_pressed_rects(overlay.pressed, width, height, metrics),
        washes=((c.tr, 255),) if overlay.muted else (),
        header=None,
        body=Body(BODY_COMPACT_CONTROLS, muted=bool(overlay.muted), dots_lit=overlay.dots),
        footer=Footer(FOOTER_NONE),
    )


def _now_playing_frame(overlay: OverlayState, width: int, height: int, metrics: LayoutMetrics) -> Frame:
    layout = layout_for(width, height, metrics=metrics)
    return Frame(
        background=BG_BASE,
        dim_top=True,
        dim_bottom=True,
        pressed=_main_pressed_rects(overlay.pressed, width, height, metrics),
        # The persistent mute wash: brighter than the dimmed footer band
        # while muted, independent of any genuine touch — a tap still adds
        # its own momentary wash on top (see _compose_frame's draw order).
        # A dedicated (stronger) strength from the row-highlight wash below,
        # which was tuned for the undimmed list chassis and all but
        # disappears over a dimmed footer band under a white glyph.
        washes=((layout.footer_mute, _MUTE_WASH_ALPHA),) if overlay.muted else (),
        header=Header(
            name=overlay.name, volume=overlay.volume, muted=overlay.muted,
            dots_filled=0 if overlay.dots else None,
            dots_count=3 if overlay.eq_pages else 2,
        ),
        body=Body(BODY_NOW_PLAYING, title=overlay.title, artist=overlay.artist, album=overlay.album),
        footer=Footer(FOOTER_VOLUME_MUTE),
    )


def _repeat_pressed_rects(
    state: RepeatViewState, width: int, height: int, metrics: "LayoutMetrics | None" = None,
) -> tuple[Rect, ...]:
    """The repeat screen's pressed-rect lookup: a genuine touch first, then
    the fade-out-in-flight Stop wash layered on top of it when replaying —
    same order the two highlights are drawn in today. Resolved against
    GEOMETRY_REPEAT_REPLAY, rather than GEOMETRY_REPEAT, exactly when the
    compact tier's own replaying layout is showing — the only tier/layout
    combination the two geometries actually disagree about (see
    dial_touch_layout.zone_rects_for)."""
    if metrics is None:
        metrics = metrics_for(width, height)
    replaying = state.layout == "replaying"
    geometry = GEOMETRY_REPEAT_REPLAY if (metrics.content_tier == CONTENT_COMPACT and replaying) else GEOMETRY_REPEAT
    rects = []
    rect = _zone_rect(geometry, state.pressed, None, width, height, metrics)
    if rect is not None:
        rects.append(rect)
    if replaying and state.stop_pressed:
        stop_rect = _zone_rect(geometry, TouchZone.REPEAT_STOP, None, width, height, metrics)
        if stop_rect is not None:
            rects.append(stop_rect)
    return tuple(rects)


def _compact_repeat_frame(state: RepeatViewState, width: int, height: int, metrics: LayoutMetrics) -> Frame:
    """The compact tier's repeat screen: dimmed base behind both of its own
    states (enable and replaying alike — the compact tier's own shared
    rendering discipline), no header (no NAME/OUTPUTS on compact), pressed
    resolved against
    whichever of GEOMETRY_REPEAT/GEOMETRY_REPEAT_REPLAY _repeat_pressed_
    rects picks for this state."""
    replaying = state.layout == "replaying"
    body = (
        Body(BODY_COMPACT_REPLAY, line=state.line, start_enabled=state.start_enabled, stop_enabled=state.stop_enabled)
        if replaying
        else Body(BODY_COMPACT_TOGGLE, armed=state.armed, label="Repeat Play")
    )
    return Frame(
        background=BG_BASE,
        dim_all=True,
        pressed=_repeat_pressed_rects(state, width, height, metrics),
        header=None,
        body=body,
        footer=Footer(FOOTER_NONE),
    )


def _repeat_frame(state: RepeatViewState, width: int, height: int, metrics: LayoutMetrics) -> Frame:
    if metrics.content_tier == CONTENT_COMPACT:
        return _compact_repeat_frame(state, width, height, metrics)
    replaying = state.layout == "replaying"
    if replaying:
        body = Body(BODY_REPEAT_LINE, line=state.line)
        footer = Footer(
            FOOTER_LABELS, left_text="Restart", right_text="Stop",
            left_enabled=state.start_enabled, right_enabled=state.stop_enabled,
        )
    else:
        body = Body(BODY_REPEAT_ROW, armed=state.armed, label="Repeat Play")
        footer = Footer(FOOTER_NONE)
    return Frame(
        background=BG_BASE if replaying else BG_CHASSIS,
        dim_top=True,
        dim_bottom=replaying,
        pressed=_repeat_pressed_rects(state, width, height, metrics),
        header=Header(
            name=state.name, volume=state.volume, muted=state.muted, dots_filled=1,
            dots_count=3 if state.eq_pages else 2,
        ),
        body=body,
        footer=footer,
    )


def _eq_pressed_rects(
    pressed: "TouchZone | None", width: int, height: int, metrics: "LayoutMetrics | None" = None,
) -> tuple[Rect, ...]:
    """The EQ page's pressed-rect lookup: a stale or unrecognised zone (one
    that belongs to a different geometry) washes nothing — the same
    _output_pressed_rects shape, minus the enabled/disabled gate (every EQ
    zone is always tappable once the page is open)."""
    rect = _zone_rect(GEOMETRY_EQ, pressed, None, width, height, metrics)
    return (rect,) if rect is not None else ()


def _eq_frame(state: "EqViewState", width: int, height: int, metrics: LayoutMetrics) -> Frame:
    return Frame(
        background=BG_CHASSIS,
        dim_top=True,
        pressed=_eq_pressed_rects(state.pressed, width, height, metrics),
        header=Header(
            name=state.name, volume=state.volume, muted=state.muted, dots_filled=2, dots_count=3,
        ),
        body=Body(BODY_EQ_BARS, bass_db=state.bass_db, treble_db=state.treble_db),
        footer=Footer(FOOTER_NONE),
    )


def _warning_pressed_rects(
    geometry: str, pressed: "TouchZone | None", width: int, height: int,
    metrics: "LayoutMetrics | None" = None,
) -> tuple[Rect, ...]:
    """A warning page's pressed-rect lookup against its own geometry: a
    zone from another geometry washes nothing."""
    rect = _zone_rect(geometry, pressed, None, width, height, metrics)
    return (rect,) if rect is not None else ()


def _warning_frame(view: WarningView, width: int, height: int, metrics: LayoutMetrics) -> Frame:
    """Dimmed base on every tier; the card only off compact (on compact the
    grid fills the panel and the dimmed base is the whole backdrop, the
    same convention every other compact screen follows)."""
    layout = warning_layout_for(width, height, buttons=len(view.buttons), metrics=metrics)
    compact = metrics.content_tier == CONTENT_COMPACT
    return Frame(
        background=BG_BASE,
        dim_all=True,
        card=None if compact else layout.card,
        pressed=_warning_pressed_rects(view.geometry, view.pressed, width, height, metrics),
        header=None,
        body=Body(BODY_WARNING, title=view.title, line=view.message, buttons=view.buttons, percent=view.percent),
        footer=Footer(FOOTER_NONE),
    )


def _output_pressed_rects(
    pressed: "TouchZone | None", enabled: bool, width: int, height: int,
    metrics: "LayoutMetrics | None" = None,
) -> tuple[Rect, ...]:
    """The per-output detail page's pressed-rect lookup: a stale or
    unrecognised zone (e.g. one that belongs to a different geometry)
    washes nothing, and neither does a stepper tap while the output is
    disabled — the steppers are touch-inert then, not just dimmed, so a
    tap on them neither lights nor acts."""
    if pressed in (TouchZone.OUTPUT_UP, TouchZone.OUTPUT_DOWN) and not enabled:
        return ()
    rect = _zone_rect(GEOMETRY_OUTPUT, pressed, None, width, height, metrics)
    return (rect,) if rect is not None else ()


def _output_frame(state: "OutputViewState", width: int, height: int, metrics: LayoutMetrics) -> Frame:
    return Frame(
        background=BG_CHASSIS,
        dim_top=True,
        dim_bottom=True,
        pressed=_output_pressed_rects(state.pressed, state.selected, width, height, metrics),
        header=Header(
            name=state.name, volume=state.level, muted=None, dots_filled=None, back=True,
        ),
        body=Body(BODY_TOGGLE_ROW, armed=state.selected, label=state.output_name),
        footer=Footer(FOOTER_VOLUME, left_enabled=state.selected, right_enabled=state.selected),
    )


def _list_pressed_rects(
    state: ListState, width: int, height: int, metrics: "LayoutMetrics | None" = None,
) -> tuple[Rect, ...]:
    """The selector screen's pressed-rect lookup: a stale LIST_ROW index
    (the roster shrank between paint and tap) washes nothing rather than
    raising."""
    if state.pressed is None:
        return ()
    zone, index = state.pressed
    rect = _zone_rect(GEOMETRY_LIST, zone, index, width, height, metrics)
    return (rect,) if rect is not None else ()


def _list_highlight_rects(rows: tuple, layout) -> tuple[Rect, ...]:
    """The row rects that get the current-row wash: every visible row
    whose tuple marks it current. Extra rows beyond the page are ignored,
    never indexed (the body renderer skips them from the other side)."""
    return tuple(layout.rows[i] for i, row in enumerate(rows[:len(layout.rows)]) if row[1])


def _compact_list_highlight_rects(rows: tuple, cells: tuple[Rect, Rect]) -> tuple[Rect, ...]:
    """The compact picker's own current-row wash: the same rule
    _list_highlight_rects() applies, over *cells* — the picker layout's own
    (row0, row1) rects — instead of list_layout_for()'s own row rects."""
    return tuple(cells[i] for i, row in enumerate(rows[:len(cells)]) if row[1])


def _compact_list_frame(state: ListState, width: int, height: int, metrics: LayoutMetrics) -> Frame:
    """The compact tier's replay picker (or, with state.plain_background,
    the read-only info page reusing this same layout): dimmed base behind
    (the manager's own current base image, passed through compose_list()'s
    *base*) for the picker, or a flat undimmed chassis for the info page
    (nothing to dim — it has no base image of its own); pressed and the
    current-row wash resolved against the picker's own title-band-plus-grid
    layout."""
    p = compact_picker_layout_for(width, height, metrics=metrics)
    return Frame(
        background=BG_CHASSIS if state.plain_background else BG_BASE,
        dim_all=not state.plain_background,
        pressed=_list_pressed_rects(state, width, height, metrics),
        highlights=_compact_list_highlight_rects(state.rows, (p.row0, p.row1)),
        header=None,
        body=Body(
            BODY_COMPACT_LIST, rows=state.rows, has_more=state.has_prev or state.has_next,
            title=state.title or "",
        ),
        footer=Footer(FOOTER_NONE),
    )


def _list_frame(state: ListState, width: int, height: int, metrics: LayoutMetrics) -> Frame:
    layout = list_layout_for(width, height, metrics=metrics)
    rail = layout.rail is not None
    return Frame(
        background=BG_CHASSIS,
        dim_top=False,
        dim_bottom=not rail,
        pressed=_list_pressed_rects(state, width, height, metrics),
        highlights=_list_highlight_rects(state.rows, layout),
        header=None,
        body=Body(BODY_LIST_ROWS, rows=state.rows),
        footer=Footer(
            FOOTER_LIST_RAIL if rail else FOOTER_LIST_BAR,
            has_prev=state.has_prev, has_next=state.has_next,
        ),
    )
