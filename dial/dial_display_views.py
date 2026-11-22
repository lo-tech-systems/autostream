"""dial_display_views.py -- what the display manager hands the compositor.

One immutable view state per screen (OverlayState, ListState,
RepeatViewState, OutputViewState, EqViewState, InfoValueView, WarningView),
the frame descriptor the compositor's frame builders produce (Frame: a
background choice plus Header, Body and Footer, with the washes), and the UI
strings the screens and the manager share. Everything here is plain
immutable data, with no Pillow import, so the manager, dial_main and the
tools can use it without the drawing stack.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from dataclasses import dataclass

from dial_touch_layout import Rect, TouchZone


# The appliance selector's secondary text for an appliance that has refused
# this dial. A row carrying exactly this text is drawn dimmed throughout
# (label and secondary) so it reads as unavailable next to the live rows.
NOT_AUTHORISED_TEXT = "Not authorised"
# The secondary text of a selector row for an appliance on another protocol
# than this dial's, drawn dimmed the same way.
NEEDS_UPDATE_TEXT = "Needs an update"

# The hint page's title for a speaker that has to be paired (it asks for a
# PIN) in the appliance's web UI, which the small screen cannot do.
PAIR_IN_AUTOSTREAM_TEXT = "Pair in Autostream"

# The hint page's title and lines for a speaker that could not start, by the
# reason the appliance gave. {name} is replaced by the speaker's name.
START_FAILURE_TITLE = "Could not start"
START_FAILURE_LINES = {
    "refused": "{name} turned the request down",
    "failed": "{name} did not start",
    "timed_out": "{name} did not answer in time",
    "encoder_capacity": "No capacity to stream to {name}",
    "unreachable": "{name} could not be reached",
    "no_clock": "{name} is not following the clock",
}
START_FAILURE_LINE_FALLBACK = "{name} did not start"

# A list row's trailing mark for the appliance's default output. Drawn after
# the label and never truncated; present in the DejaVu faces the dial ships.
DEFAULT_MARK = "•"


# The two centred-label screens' one line each: the restart screen and the
# boot splash.
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
class BellBadge:
    """The warning bell drawn in a corner: the worst severity among the
    entries (it picks the colour) and how many there are (the number in
    the bell)."""

    severity: str
    count: int


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
    bell: the warning bell, or None for none. In the top band (or the compact
        dots quadrant) while the controls are drawn; on a dark disc in the
        corner of the artwork while they are not.
    paused: everything playing is paused, so the mute cell shows the pause
        sign and a tap plays them all again. Muted or paused, the cell
        carries the red alert wash.
    pulse: where the alert wash is in its pulse, 0.0 (see-through) to 1.0
        (solid). A paint parameter: the manager owns the clock. The default
        draws it solid.
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
    bell: "BellBadge | None" = None
    paused: bool = False
    pulse: float = 1.0

    @property
    def alert(self) -> bool:
        """Whether the mute cell carries the alert wash: muted, or everything
        paused."""
        return bool(self.muted) or self.paused


@dataclass(frozen=True)
class ListState:
    """Immutable snapshot of what the appliance-selector screen should show
    — the compose_list() counterpart to OverlayState. Built by the display
    manager from its ListScreenState (dial_display_state.py) on the repaint thread;
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
        existed. A row may carry a fourth element, a mark: a short string
        drawn right after the label (after its ellipsis when the label is
        cut) in the label's own colour. Rows without one are drawn exactly
        as before.
    has_prev: whether a previous page exists — gates whether the LIST_UP
        chevron is drawn lit (see dial_touch_layout.ListLayout.up and the
        LIST_UP -> selector_page(-1) dispatch in dial_touch_wiring.py).
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
    content()); `name` and `volume` feed that shared piece, drawn
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
    volume: the top band's volume readout — display-only on this screen
        (no touch zone), mirroring OverlayState.volume.
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
    volume: int | None = None
    pressed: "TouchZone | None" = None
    eq_pages: bool = False
    counter_second: int | None = None
    bell: "BellBadge | None" = None


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
        switch, on or off (the same switch the repeat screen's "Repeat
        Play" uses).
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
    the display manager from its ApplianceScreenState (dial_display_state.py) on the
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
    volume: the top band's volume readout — display-only on this page (no
        touch zone; the encoder still steps volume), mirroring
        RepeatViewState.volume.
    pressed: the TouchZone currently being pressed, or None. Mirrors
        OverlayState.pressed/RepeatViewState.pressed.
    """

    name: str
    bass_db: "int | None"
    treble_db: "int | None"
    loaded: bool
    volume: "int | None" = None
    pressed: "TouchZone | None" = None
    bell: "BellBadge | None" = None


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
class WarningView:
    """Immutable snapshot of a card: the readout-size title, the optional
    body-size message under it (empty prints the title alone, centred in
    the whole message row), the button labels left to right, the index of
    the pressed cell, if any, the optional progress percent (None draws no
    bar; no buttons draws a notice with no cells) and the optional source
    (who the warning is about: a non-empty one is drawn as a band across
    the top of the message row, in white on the logo's blue with a bell in
    the severity's colour at its right end, over a rule in that colour, and the
    page's text is then fitted to the rest of the row
    rather than drawn as one line each)."""

    title: str
    message: str = ""
    buttons: tuple[str, ...] = ()
    pressed: "int | None" = None
    percent: "int | None" = None
    source: str = ""
    severity: str = ""
    detail: str = ""


# Background sources for _new_frame(): where a frame's base image comes
# from before anything is drawn on top of it.
BG_BASE = "base"          # the caller's panel-sized image (artwork or logo)
BG_CHASSIS = "chassis"    # flat LIST_BG_RGB fill, no caller image involved

# Body kinds — the screen-specific content between the top and bottom
# bands, dispatched through _BODY_RENDERERS.
BODY_NONE = "none"
BODY_NOW_PLAYING = "now_playing"   # title + artist lines with halo
BODY_TOGGLE_ROW = "toggle_row"     # a label + on/off switch on the middle row (per-output)
BODY_REPEAT_LINE = "repeat_line"   # centred "m:ss / m:ss" with halo
BODY_LIST_ROWS = "list_rows"       # selector/picker rows
BODY_IDLE_BADGE = "idle_badge"     # the idle screen's own corner glyphs: the warning bell and the Wi-Fi status
# Compact-tier (2x2) bodies — see the module's compact frame builders below.
BODY_COMPACT_CONTROLS = "compact_controls"  # the playing screen: dots/mute/minus/plus
BODY_COMPACT_LIST = "compact_list"          # the replay picker's two rows + more/cancel
BODY_COMPACT_TOGGLE = "compact_toggle"      # the repeat screen's "Repeat Play" row (lit while armed) + back
BODY_COMPACT_REPLAY = "compact_replay"      # the repeat screen's time line + Restart/Stop
BODY_INFO_VALUE = "info_value"              # the compact info page's own drill-in: label + wrapped value
BODY_EQ_BARS = "eq_bars"                    # the EQ page's own bass/treble bar rows
BODY_WARNING = "warning"                    # a warning page: title (+ message) row over one or more button cells, crosshair dividers
BODY_CENTRED_LABEL = "centred_label"        # one string centred on the whole panel (the "Restarting..." screen)

# Footer kinds — the bottom band's content, dispatched through
# _FOOTER_RENDERERS.
FOOTER_NONE = "none"
FOOTER_VOLUME = "volume"           # minus | plus glyphs + divider (two-way: repeat, per-output detail)
FOOTER_VOLUME_MUTE = "volume_mute"  # minus | plus | mute glyphs + two dividers (main screen, three-way)
FOOTER_TOGGLE = "toggle"           # a label left, its on/off switch right (the repeat screen's enable layout)
FOOTER_LABELS = "labels"           # left | right centred labels + divider
FOOTER_LIST_BAR = "list_bar"       # back | down | up chevrons
FOOTER_LIST_RAIL = "list_rail"     # up chevron | cross | down chevron on the right rail


@dataclass(frozen=True)
class Header:
    """The top band's content: appliance name, mute/volume readout, and the
    optional pager dots that switch between the main and repeat screens.
    dots_filled=None omits the dots entirely; 0 fills the left dot, 1 the
    right one. The readout speaker is never slashed: mute has one home, the
    main screen's own footer glyph and wash. back=True draws a left chevron into the dots
    rect instead (the per-output detail page's own back control), taking
    priority over dots_filled. dots_count (2, the default, or 3) selects
    which pager-dots glyph is drawn -- two dots for an appliance with no EQ
    page, three (the third one filled by the EQ page itself) for one that
    has it; a value other than 3 draws the existing two-dot glyph, so every
    caller that never sets it is unaffected."""

    name: str = ""
    volume: int | None = None
    dots_filled: int | None = None
    dots_count: int = 2
    back: bool = False
    bell: "BellBadge | None" = None


@dataclass(frozen=True)
class Body:
    """The screen-specific content drawn between the top and bottom bands.
    Which fields are meaningful is decided entirely by `kind` — see the
    BODY_* constants and _BODY_RENDERERS."""

    kind: str = BODY_NONE
    title: str = ""        # BODY_NOW_PLAYING; also BODY_COMPACT_LIST's own title-band text (empty -> "Replay")
    artist: str = ""       # BODY_NOW_PLAYING
    armed: bool = False    # BODY_TOGGLE_ROW / BODY_COMPACT_TOGGLE
    label: str = ""        # BODY_TOGGLE_ROW / BODY_COMPACT_TOGGLE — the row's own text
    line: str = ""         # BODY_REPEAT_LINE / BODY_COMPACT_REPLAY
    rows: tuple = ()       # BODY_LIST_ROWS / BODY_COMPACT_LIST — same row tuples ListState.rows carries
    album: str = ""        # BODY_NOW_PLAYING — drawn only where the layout has an album rect
    # Compact-tier fields — see the BODY_COMPACT_* constants above.
    paused: bool = False          # BODY_COMPACT_CONTROLS: the mute cell shows the pause sign
    dots_lit: bool = False        # BODY_COMPACT_CONTROLS: whether the pager-dots cell is tappable
    has_more: bool = False        # BODY_COMPACT_LIST: whether the "more" chevron is lit
    start_enabled: bool = True    # BODY_COMPACT_REPLAY: Restart drawn full-brightness vs dimmed
    stop_enabled: bool = True     # BODY_COMPACT_REPLAY: Stop drawn full-brightness vs dimmed
    bass_db: "int | None" = None    # BODY_EQ_BARS
    treble_db: "int | None" = None  # BODY_EQ_BARS
    wifi_bars: int = 0            # BODY_IDLE_BADGE: lit arcs on the wifi glyph (0..3) under WIFI_SIGNAL; 0 draws it all grey
    wifi_style: str = WIFI_SIGNAL # BODY_IDLE_BADGE: WIFI_SIGNAL / WIFI_GREY / WIFI_RED / WIFI_OFF — see the constants
    bell: "BellBadge | None" = None  # BODY_IDLE_BADGE / BODY_COMPACT_CONTROLS: the warning bell, None draws none
    buttons: tuple[str, ...] = ()  # BODY_WARNING: button labels, left to right, one per layout cell
    percent: "int | None" = None   # BODY_WARNING: progress bar under the message (0..100), None for none
    source: str = ""               # BODY_WARNING: the band above the title; non-empty fits the text to the rest of the row
    severity: str = ""             # BODY_WARNING: colours the rule under the source band
    detail: str = ""               # BODY_WARNING: the reason under the message, drawn only where it fits whole


@dataclass(frozen=True)
class Footer:
    """The bottom band's content. Which fields are meaningful is decided
    entirely by `kind` — see the FOOTER_* constants and _FOOTER_RENDERERS."""

    kind: str = FOOTER_NONE
    left_text: str = ""            # FOOTER_LABELS / FOOTER_TOGGLE (the switch's label)
    right_text: str = ""           # FOOTER_LABELS
    left_enabled: bool = True      # FOOTER_LABELS: full brightness vs dimmed
    right_enabled: bool = True
    has_prev: bool = False         # FOOTER_LIST_BAR: lights the up chevron
    has_next: bool = False         # FOOTER_LIST_BAR: lights the down chevron
    paused: bool = False           # FOOTER_VOLUME_MUTE: the mute cell shows the pause sign
    armed: bool = False            # FOOTER_TOGGLE: the switch is on


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
    washes: tuple[tuple[Rect, tuple, int], ...] = ()  # (rect, rgb, alpha) for a persistent state wash, drawn after highlights and before pressed
    header: Header | None = None
    body: Body = Body()
    footer: Footer = Footer()


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
