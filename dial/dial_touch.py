"""dial_touch.py — touch session policy and the thread that drives it.

Two classes, deliberately kept separate:

  TouchStateMachine — pure, no thread, no clock of its own (every method
  takes *now*). Consumes dial_touch_filter.TouchEvent objects plus an
  explicit "overlay actually rendered" input and produces a small ordered
  list of ACTIONS for a caller to dispatch. It owns the "is the overlay
  visible" truth — see REVEAL-THEN-ARM below.

  TouchEventSource — a thin thread wrapper with no policy of its own. It
  blocks on T_IRQ via gpiozero, drives a driver + a TouchFilter + a
  TouchStateMachine, and hands the resulting actions to injected callables.
  It does NOT import dial_volume or dial_display — a later change wires
  those in by passing their methods as the callables here. Both gpiozero and
  dial_touch_drivers are imported lazily/defensively so this module stays
  importable on a machine with neither installed.

REVEAL-ONLY FIRST TOUCH: a contact that begins while the overlay is not
visible ONLY reveals it. No zone is sampled, nothing is actuated, however
long the finger stays down — the user gets to see where the buttons are
before committing to one. Actuating on that first contact would mean
pressing a control the user could not yet see.

When the overlay is already visible at touch-down the press arms
immediately, sampling the zone at touch-down and starting the repeat clock
from touch-down — the zones were on screen before the finger landed.

PRESSED HIGHLIGHT: arming lights the pressed zone. How it clears depends on
what the zone does:

  - UP/DOWN repeat while held, so the highlight stays lit for as long as the
    finger is down and clears on release. It is showing a control that is
    genuinely still active.
  - MUTE is single-shot — it fires once and never repeats — so there is no
    ongoing state to show. It flashes for PRESSED_FLASH_S and clears itself,
    even if the finger stays down.

Either way the highlight is cleared explicitly rather than left for the next
unrelated repaint, which made a brief tap look like a stuck button.

DISMISS: ~DISMISS_S after the last *contact sample* (not the last
touch-down) the overlay is dismissed. Every accepted sample while
armed/held resets this deadline, so a long hold can never dismiss underneath
a repeating finger. The clock starts at RELEASE, or at a filter CAP (treated
as an implicit release for this purpose — no further repeats, no further
resets, straight to counting down to dismiss).

HELD VISIBLE: an external "always show controls" screen setting can hold the
overlay visible on its own, independent of any touch — see
TouchStateMachine.set_held_visible() and TouchEventSource's
get_persistent_overlay polling. While held, the overlay counts as visible
from the state machine's point of view: the next press arms immediately (the
same "already visible" path REVEAL-ONLY FIRST TOUCH describes above) and the
dismiss clock in tick() is disabled entirely, since there is no touch-driven
overlay session to time out. When the display stops holding it (screen went
to the logo, went to sleep, or the setting was turned off), the session is
forced back to hidden and a DISMISS is emitted so the touch-published
overlay snapshot is cleared too — a finger must never be able to arm against
controls that are no longer actually drawn. TouchEventSource polls the
display's persistent_overlay_shown() (injected, never imported — see the
class docstring) once per loop iteration so a transition is noticed within
one tick either way.

SURFACES: which screen is currently on the panel decides which hit-test
geometry a press is sampled against — see TouchStateMachine.set_surface()
and _GEOMETRY_FOR_SURFACE. "hidden" and "held" both map to
dial_touch_layout.GEOMETRY_MAIN: the now-playing screen, reveal-on-touch or
always-shown respectively, unchanged from HELD VISIBLE above. "selector"
and "picker" both map to GEOMETRY_LIST (the appliance-list chassis): a
press arms immediately regardless of held state (the list is either fully
on screen or not shown at all — there is no reveal-only phase for it).
"repeat" maps to GEOMETRY_REPEAT; "idle" maps to GEOMETRY_IDLE; "outputs"
maps to GEOMETRY_LIST (the outputs list reuses the same list chassis as
the selector/picker); "output" maps to GEOMETRY_OUTPUT (the per-output
detail page); "info" maps to GEOMETRY_INFO (the idle screen's read-only
info page — the list table with every row entry removed, so a row tap
lands in no zone); "eq" maps to GEOMETRY_EQ (the EQ page, rich/large only)
— all held like the selector. The map is many-to-one on purpose: which surfaces share a geometry is a policy decision (reveal
timing, what a row tap does), never a geometric one —
dial_touch_layout.py itself only ever describes its geometries, never a
surface. Every zone any of these can arm (NAME/DOTS/OUTPUTS on the main
geometry; LIST_ROW/LIST_BACK/LIST_DOWN/LIST_UP on the list geometry;
DOTS/NAME/REPEAT_PLAY/REPEAT_START/REPEAT_STOP on the repeat geometry;
OUTPUT_BACK/NAME/OUTPUT_TOGGLE/OUTPUT_UP/OUTPUT_DOWN on the output
geometry; IDLE_REPLAY on the idle geometry; DOTS/NAME/OUTPUTS/EQ_BASS_DOWN/
EQ_BASS_UP/EQ_TREBLE_DOWN/EQ_TREBLE_UP on the EQ geometry) is single-shot — it flashes
once and never repeats, and its tap is reported as ACTION_ZONE_TAP for the
caller to dispatch, EXCEPT the repeating zones (UP/DOWN's own fixed
actions, and OUTPUT_UP/OUTPUT_DOWN, reported as repeated ACTION_ZONE_TAPs
— see _REPEATING_ZONES and tick()). DOTS, NAME and OUTPUTS are each gated
by their own "is it currently tappable" flag (_dots_active/_name_active/
_outputs_active), applied unconditionally in _arm() — each gate is only
ever meaningful on the geometry its own zone actually appears in. A
surface CHANGE while a finger is
down drops the zone latch exactly as set_held_visible(False) does, because
the geometry under the finger just changed. TouchEventSource polls the
display's touch_surface() (injected; falls back to the legacy
get_persistent_overlay when that is all that is supplied, so existing
"held"/"hidden" wiring behaves byte for byte) once per loop iteration; it
accepts a 2-tuple (surface, name_active), the 3-tuple (surface,
name_active, dots_active), or the 4-tuple (surface, name_active,
dots_active, outputs_active) touch_surface() may return. Closing the repeat
screen via a DOTS tap also reveals the main screen's volume overlay on
return — see TouchStateMachine.force_overlay_visible() and
TouchEventSource._poll_surface(). "repeat_replay" is a physically-tiny-glass
variant of "repeat" (its own geometry, GEOMETRY_REPEAT_REPLAY, for the
replaying layout's own time/Restart/Stop cells): held exactly like "repeat",
and the two are treated as one set by the repeat-close reveal rule above, so
a flip between them is never mistaken for a close.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from dial_touch_filter import TouchEvent, TouchEventType
from dial_touch_layout import (
    GEOMETRY_EQ,
    GEOMETRY_IDLE,
    GEOMETRY_INFO,
    GEOMETRY_INFO_VALUE,
    GEOMETRY_LIST,
    GEOMETRY_MAIN,
    GEOMETRY_OUTPUT,
    GEOMETRY_REPEAT,
    GEOMETRY_REPEAT_REPLAY,
    LayoutMetrics,
    TouchZone,
    hit_test,
    metrics_for,
)

# Overlay auto-dismisses this long after the last contact sample / release /
# cap-stop, whichever is most recent.
DISMISS_S = 4.0

# How long a single-shot (MUTE) highlight stays lit. Long enough to read as
# deliberate feedback, short enough that it never looks like a latched
# state; each change costs one full-frame push. Repeating zones (UP/DOWN)
# ignore this and stay lit until release — see the module docstring.
PRESSED_FLASH_S = 0.25

# Mirrored here from dial_touch_filter so TouchStateMachine can run its own
# repeat clock with identical cadence to the filter's.
FIRST_REPEAT_S = 0.4
REPEAT_INTERVAL_S = 0.15

# Action kinds produced by TouchStateMachine.
ACTION_REVEAL_OVERLAY = "reveal-overlay"
ACTION_VOLUME_UP = "volume-up"
ACTION_VOLUME_DOWN = "volume-down"
ACTION_MUTE_TOGGLE = "mute-toggle"
ACTION_DISMISS_OVERLAY = "dismiss-overlay"
ACTION_SET_PRESSED_ZONE = "set-pressed-zone"
ACTION_ZONE_TAP = "zone-tap"

# The only zones that auto-repeat while held: the volume steppers (main and
# repeat screens) and the per-output volume steppers on the detail page.
# Every other zone acts once per press and flashes rather than staying lit —
# re-actuating them on a timer would be meaningless (a mute toggle, an
# open/close/page of the selector, picking a row, opening/closing the
# repeat screen, toggling an output, or tapping the idle affordance).
_REPEATING_ZONES = frozenset((
    TouchZone.UP, TouchZone.DOWN, TouchZone.OUTPUT_UP, TouchZone.OUTPUT_DOWN,
    TouchZone.EQ_BASS_DOWN, TouchZone.EQ_BASS_UP, TouchZone.EQ_TREBLE_DOWN, TouchZone.EQ_TREBLE_UP,
))

# Zones dispatched as their own fixed action kinds (volume up/down, mute
# toggle). Every other zone is reported as ACTION_ZONE_TAP with the zone
# (and row index, for LIST_ROW) for the caller to route.
_FIXED_ACTION_ZONES = frozenset((TouchZone.UP, TouchZone.DOWN, TouchZone.MUTE))

# Derived from the zone enum rather than hand-listed: a zone added to the
# enum is single-shot and zone-tap by default (the only sensible default —
# a new repeating or fixed-action zone is a deliberate decision made by
# adding it to one of the two small sets above, which need a new action
# kind wired up anyway).
_SINGLE_SHOT_ZONES = frozenset(TouchZone) - _REPEATING_ZONES
_ZONE_TAP_ZONES = frozenset(TouchZone) - _FIXED_ACTION_ZONES

_PHASE_IDLE = "idle"
_PHASE_REVEAL_PENDING = "reveal_pending"
_PHASE_ARMED = "armed"

# Surfaces set_surface()/TouchEventSource understand — see the module
# docstring's SURFACES paragraph.
SURFACE_HIDDEN = "hidden"
SURFACE_HELD = "held"
SURFACE_SELECTOR = "selector"
# The repeat, idle and picker surfaces. All three behave as
# "held" exactly like SURFACE_SELECTOR: a press arms immediately, there is
# no reveal step and no dismiss clock — see set_surface() and _arm() below.
SURFACE_REPEAT = "repeat"
SURFACE_IDLE = "idle"
SURFACE_PICKER = "picker"
# The outputs list and per-output detail surfaces. Both behave as "held"
# exactly like SURFACE_SELECTOR/SURFACE_PICKER — see set_surface() below.
SURFACE_OUTPUTS = "outputs"
SURFACE_OUTPUT = "output"
# The compact tier's own repeat-replaying surface — reported by the
# display's touch_surface() in place of SURFACE_REPEAT exactly while that
# tier's replaying layout (time/back, Restart/Stop) is the one actually
# painted; every other tier never reports it (see ScreenPolicy.
# replay_surface). Held like every other non-hidden surface — see
# set_surface() below.
SURFACE_REPEAT_REPLAY = "repeat_replay"
# The idle screen's own read-only info page: held like every other list
# surface (a press arms immediately, no reveal step). Off the compact tier
# its own geometry (GEOMETRY_INFO) carries no LIST_ROW entries at all — a
# tap on a row lands in no zone; on the compact tier the rows ARE tappable,
# opening the field's own value view below.
SURFACE_INFO = "info"
# The compact info page's own drill-in — a tapped field's own full-screen
# value. Held like every other list surface; its geometry (GEOMETRY_INFO_
# VALUE) is a single whole-panel LIST_BACK entry, so any press anywhere
# reports the same zone-tap back to the list.
SURFACE_INFO_VALUE = "info_value"
# The EQ page: rich/large only, reached via the page dots. Held like every
# other secondary surface; hit-tests use the GEOMETRY_EQ table (DOTS/NAME/
# OUTPUTS reused from the main geometry, plus the bass/treble bar steppers).
SURFACE_EQ = "eq"

# Which hit-test geometry each surface uses. Many-to-one on purpose: hidden
# and held differ only in reveal policy (not geometry); selector and picker
# differ only in what a row tap does once armed. An unrecognised surface
# string falls back to MAIN in _arm() below, matching the old default.
_GEOMETRY_FOR_SURFACE = {
    SURFACE_HIDDEN: GEOMETRY_MAIN,
    SURFACE_HELD: GEOMETRY_MAIN,
    SURFACE_SELECTOR: GEOMETRY_LIST,
    SURFACE_PICKER: GEOMETRY_LIST,
    SURFACE_REPEAT: GEOMETRY_REPEAT,
    SURFACE_REPEAT_REPLAY: GEOMETRY_REPEAT_REPLAY,
    SURFACE_IDLE: GEOMETRY_IDLE,
    SURFACE_OUTPUTS: GEOMETRY_LIST,
    SURFACE_OUTPUT: GEOMETRY_OUTPUT,
    SURFACE_INFO: GEOMETRY_INFO,
    SURFACE_INFO_VALUE: GEOMETRY_INFO_VALUE,
    SURFACE_EQ: GEOMETRY_EQ,
}

# The repeat screen's two surfaces, treated as one set by the repeat-close
# reveal rule below: a flip between them (the compact tier's own enable <->
# replaying transition) is not a close, so it must not fire the reveal —
# only leaving the set entirely (to "hidden"/"held", a genuine DOTS-tap
# close) does. Off the compact tier only SURFACE_REPEAT is ever reported, so
# this set is a strict superset of the old exact-match check.
_REPEAT_SURFACES = frozenset((SURFACE_REPEAT, SURFACE_REPEAT_REPLAY))


@dataclass(frozen=True)
class TouchAction:
    kind: str
    zone: TouchZone | None = None
    index: int | None = None


class TouchStateMachine:
    """Pure press-session policy. No thread, no clock reads — every method
    takes an explicit *now*, so tests drive it deterministically."""

    def __init__(self, width: int, height: int, metrics: "LayoutMetrics | None" = None) -> None:
        self._width = width
        self._height = height
        # Set at construction from the profile/layout size in force at
        # startup (see dial_main._build_touch_source) — None means
        # metrics_for(width, height), today's density-unaware hit-testing.
        # A live geometry change replaces all three together — see
        # set_geometry() below.
        self._metrics = metrics
        self._phase = _PHASE_IDLE
        self._overlay_visible = False
        self._contact_down = False
        self._pending_xy: tuple[int, int] | None = None
        self._armed_zone: TouchZone | None = None
        # index alongside _armed_zone — only meaningful for LIST_ROW (the
        # row index within the current page); None for every other zone.
        self._armed_index: int | None = None
        self._next_repeat_time: float | None = None
        self._dismiss_deadline: float | None = None
        self._pressed_until: float | None = None
        self._pressed_lit = False
        # True while the display is holding the overlay visible on its own
        # (always_show_controls) — see set_held_visible() below.
        self._held = False
        # Which surface is currently on the panel — see set_surface() and
        # the module docstring's SURFACES paragraph. Starts "hidden": the
        # main now-playing screen, reveal on touch.
        self._surface = SURFACE_HIDDEN
        # Whether the NAME zone is currently tappable — meaningful on BOTH
        # the main surface and the repeat surface (both open the appliance
        # selector); the selector surface itself never consults it: every
        # one of its zones is always active. See set_surface().
        self._name_active = False
        # Whether the DOTS zone is currently tappable — meaningful on BOTH
        # the main surface (opens the repeat screen) and the repeat surface
        # (pops back to main); gated the same way _name_active gates NAME.
        # See set_surface() and _arm().
        self._dots_active = False
        # Whether the OUTPUTS zone (the top-right volume-cluster readout on
        # the main surface) is currently tappable — gated the same way
        # _dots_active/_name_active gate their own zones. False when the
        # focused/reporting appliance does not advertise the capability.
        # See set_surface() and _arm().
        self._outputs_active = False

    # -- read-only state, for a compositor/UI to consult -------------------

    @property
    def overlay_visible(self) -> bool:
        return self._overlay_visible

    @property
    def held_visible(self) -> bool:
        return self._held

    @property
    def pressed_zone(self) -> TouchZone | None:
        return self._armed_zone if self._pressed_lit else None

    @property
    def pressed_index(self) -> int | None:
        """The row index alongside pressed_zone, for LIST_ROW; None for
        every other zone or when nothing is pressed."""
        return self._armed_index if self._pressed_lit else None

    @property
    def surface(self) -> str:
        return self._surface

    # -- inputs --------------------------------------------------------

    def on_filter_event(self, event, now: float) -> list[TouchAction]:
        """Feed one dial_touch_filter.TouchEvent. Returns zero or more
        actions."""
        if event.type == TouchEventType.PRESS:
            return self._on_press(event, now)
        if event.type == TouchEventType.REPEAT:
            return self._on_repeat(event, now)
        if event.type == TouchEventType.RELEASE:
            return self._on_release(now)
        if event.type == TouchEventType.CAP:
            return self._on_cap(now)
        return []

    def overlay_live(self, now: float) -> list[TouchAction]:
        """Tell the session the overlay has actually rendered. Only
        meaningful while reveal-pending; a no-op otherwise."""
        if self._phase != _PHASE_REVEAL_PENDING:
            return []
        # Reveal only. The contact that summoned the overlay never actuates,
        # whether or not the finger is still down: until this moment the
        # zones were not on screen, so acting on it would fire a control the
        # user could not see. A second, deliberate press does the work.
        self._phase = _PHASE_IDLE
        self._pending_xy = None
        self._reset_dismiss(now)
        return []

    def force_reveal_only(self) -> list[TouchAction]:
        """External force-reset: drop whatever zone was armed and stop
        repeating, without ending the whole session the way a real RELEASE
        would.

        Used when the display reports (via its non-composited-state
        Event/generation — see dial_display.DialDisplay._mark_noncomposited_
        locked) that the screen went dark (cleared or slept) underneath
        whatever was on it — the geometry an armed zone was sampled against
        may no longer correspond to anything actually drawn.

        If the finger is still down, this falls back to REVEAL_PENDING —
        the same phase a fresh touch-down against a hidden overlay starts
        in. Since a reveal never actuates, the finger resting there will
        not act on the stale geometry; a fresh, deliberate press is needed,
        which is the safe outcome when what was on screen has just been
        torn down underneath it.

        If the finger is already up, this simply returns to idle. Never
        returns any actions of its own; it only clears local state.
        """
        self._armed_zone = None
        self._armed_index = None
        self._next_repeat_time = None
        self._pressed_lit = False
        self._pressed_until = None
        if self._contact_down:
            self._phase = _PHASE_REVEAL_PENDING
        else:
            self._phase = _PHASE_IDLE
        return []

    def set_held_visible(self, held: bool, now: float) -> list[TouchAction]:
        """External sync from the display: the controls overlay is (or is
        no longer) being drawn persistently.

        held=True: the overlay counts as visible from now on, so the next
        press arms at touch-down; the dismiss clock is disabled. A finger
        already down from a reveal-only contact stays reveal-only until it
        lifts (nothing changes about that contact).

        held=False: the display has stopped drawing the overlay on its own.
        Force the session back to hidden immediately and emit a DISMISS so
        the touch snapshot is cleared too; otherwise the display would keep
        drawing the touch snapshot over the logo, or the session would arm
        a press against controls that are no longer on screen. Same latch
        handling as force_reveal_only().
        """
        if held:
            self._held = True
            self._overlay_visible = True
            self._dismiss_deadline = None
            return []
        self._held = False
        # Same latch handling as force_reveal_only(): drop whatever zone was
        # armed and stop repeating, without assuming anything about whether
        # a finger is currently down.
        was_lit = self._pressed_lit
        self._armed_zone = None
        self._armed_index = None
        self._next_repeat_time = None
        self._pressed_lit = False
        self._pressed_until = None
        was_visible = self._overlay_visible
        self._overlay_visible = False
        self._dismiss_deadline = None
        self._phase = _PHASE_REVEAL_PENDING if self._contact_down else _PHASE_IDLE
        actions: list[TouchAction] = []
        if was_lit:
            actions.append(TouchAction(ACTION_SET_PRESSED_ZONE, None))
        if was_visible:
            actions.append(TouchAction(ACTION_DISMISS_OVERLAY))
        return actions

    def set_surface(
        self, surface: str, name_active: bool, now: float, dots_active: bool = False,
        outputs_active: bool = False,
    ) -> list[TouchAction]:
        """External sync from the display: which screen is on the panel
        right now — see the module docstring's SURFACES paragraph.

        SURFACE_HIDDEN: main screen, reveal on touch (held=False).
        SURFACE_HELD: main screen with controls held visible (held=True).
        SURFACE_SELECTOR: the appliance list; hit-tests use list_zone_at,
        presses arm immediately (held=True in effect), and there is no
        dismiss clock to disable beyond what held already disables.
        SURFACE_PICKER: the replay picker — same list_zone_at hit-test
        and held behaviour as SURFACE_SELECTOR.
        SURFACE_REPEAT: the repeat screen; hit-tests use repeat_zone_at,
        held like the selector.
        SURFACE_IDLE: the idle screen; hit-tests use idle_zone_at, held
        like the selector.
        SURFACE_OUTPUTS: the outputs list; same list_zone_at hit-test and
        held behaviour as SURFACE_SELECTOR/SURFACE_PICKER.
        SURFACE_OUTPUT: the per-output detail page; hit-tests use the
        GEOMETRY_OUTPUT table, held like the selector.
        SURFACE_INFO: the idle screen's own read-only info page; hit-tests
        use the GEOMETRY_INFO table (the list table with every row entry
        removed off the compact tier; unchanged, rows tappable, on it),
        held like the selector.
        SURFACE_INFO_VALUE: the compact info page's own drill-in; hit-tests
        use the GEOMETRY_INFO_VALUE table (a single whole-panel LIST_BACK
        entry), held like the selector.

        name_active, dots_active and outputs_active are recorded either
        way — even on a same-surface call — since any of them can change on
        the main surface alone (see _effective_overlay_locked/OverlayState)
        without the surface itself changing.

        A surface CHANGE while a finger is down drops the zone latch, same
        as set_held_visible(False): the geometry under the finger just
        moved, so nothing still-armed can be trusted. The latch is dropped
        unconditionally, BEFORE delegating the held/hidden bookkeeping to
        set_held_visible() below, because set_held_visible(True) alone does
        not drop it (there is nothing to drop, ordinarily, but a surface
        change arriving mid-press is exactly the exception).
        """
        if surface == self._surface:
            self._name_active = name_active
            self._dots_active = dots_active
            self._outputs_active = outputs_active
            return []
        was_lit = self._pressed_lit
        self._armed_zone = None
        self._armed_index = None
        self._next_repeat_time = None
        self._pressed_lit = False
        self._pressed_until = None
        self._surface = surface
        self._name_active = name_active
        self._dots_active = dots_active
        self._outputs_active = outputs_active
        actions: list[TouchAction] = []
        if was_lit:
            actions.append(TouchAction(ACTION_SET_PRESSED_ZONE, None))
        actions.extend(self.set_held_visible(surface != SURFACE_HIDDEN, now))
        return actions

    def set_geometry(self, width: int, height: int, metrics) -> None:
        """Replace the hit-test size and metrics together — a live layout
        change. Plain attribute writes from the HTTP thread, read on the
        touch thread; the caller delivers the synthetic release that drops
        any press sampled against the old geometry."""
        self._width = width
        self._height = height
        self._metrics = metrics

    def force_overlay_visible(self, now: float) -> list[TouchAction]:
        """Force the overlay into the same visible state a fresh touch-down
        reveal would produce, without an actual touch triggering it.

        Used when the repeat screen closes via a DOTS tap: the surface
        change back to the main screen already forces the overlay hidden
        (see set_surface()'s set_held_visible(False) delegation, which
        fires a DISMISS the moment the repeat screen's "held" surface goes
        away) — this call, made right afterwards, brings it straight back
        so the user sees the volume controls rather than bare artwork. See
        TouchEventSource._poll_surface() for the call site and the
        module docstring's SURFACES paragraph.

        Skips resetting the dismiss deadline while the overlay is already
        held visible on its own (always_show_controls) — matching
        set_held_visible(True)'s own handling — since there is no
        touch-driven session there for a deadline to time out.
        """
        self._overlay_visible = True
        self._phase = _PHASE_IDLE
        if self._held:
            self._dismiss_deadline = None
        else:
            self._reset_dismiss(now)
        return [TouchAction(ACTION_REVEAL_OVERLAY)]

    def tick(self, now: float) -> list[TouchAction]:
        """Periodic check for repeat-due and dismiss-due, independent of any
        new filter event arriving. Callers should invoke this regularly
        (e.g. once per poll tick and once per idle-wait timeout) so repeats
        and the dismiss timeout fire even between filter events."""
        actions: list[TouchAction] = []
        if self._pressed_until is not None and now >= self._pressed_until:
            # Single-shot flash over: unlight the zone. Emitted even after a
            # release has already returned the session to idle, so a tap
            # shorter than the flash still gets its highlight cleared.
            self._pressed_until = None
            self._pressed_lit = False
            actions.append(TouchAction(ACTION_SET_PRESSED_ZONE, None))
        if self._phase == _PHASE_ARMED and self._next_repeat_time is not None:
            if now >= self._next_repeat_time:
                if self._armed_zone == TouchZone.UP:
                    actions.append(TouchAction(ACTION_VOLUME_UP))
                    self._reset_dismiss(now)
                elif self._armed_zone == TouchZone.DOWN:
                    actions.append(TouchAction(ACTION_VOLUME_DOWN))
                    self._reset_dismiss(now)
                elif self._armed_zone in _REPEATING_ZONES:
                    # A repeating zone that is not the main/repeat screen's
                    # own fixed-action UP/DOWN (currently OUTPUT_UP/
                    # OUTPUT_DOWN) has no dedicated action kind — report it
                    # as a zone tap on each repeat, same as its first arm.
                    actions.append(TouchAction(ACTION_ZONE_TAP, self._armed_zone, self._armed_index))
                    self._reset_dismiss(now)
                self._next_repeat_time += REPEAT_INTERVAL_S
        if (
            self._dismiss_deadline is not None
            and now >= self._dismiss_deadline
            and self._overlay_visible
            and not self._held
        ):
            actions.append(TouchAction(ACTION_DISMISS_OVERLAY))
            self._overlay_visible = False
            self._dismiss_deadline = None
            self._phase = _PHASE_IDLE
        return actions

    # -- internals -------------------------------------------------------

    def _on_press(self, event, now: float) -> list[TouchAction]:
        self._contact_down = True
        self._pending_xy = (event.x, event.y)
        if not self._overlay_visible:
            self._overlay_visible = True
            self._phase = _PHASE_REVEAL_PENDING
            return [TouchAction(ACTION_REVEAL_OVERLAY)]
        return self._arm(event.x, event.y, now)

    def _on_repeat(self, event, now: float) -> list[TouchAction]:
        self._contact_down = True
        self._pending_xy = (event.x, event.y)
        # Any contact sample holds the overlay open, armed or not — a finger
        # resting after a reveal-only touch must not have the zones vanish
        # from under it.
        self._reset_dismiss(now)
        return []

    def _on_release(self, now: float) -> list[TouchAction]:
        self._contact_down = False
        actions: list[TouchAction] = []
        if self._phase in (_PHASE_ARMED, _PHASE_REVEAL_PENDING):
            self._phase = _PHASE_IDLE
            self._armed_zone = None
            self._armed_index = None
            self._next_repeat_time = None
            self._reset_dismiss(now)
        # A held repeating zone stays lit until exactly here; clear it. A
        # single-shot flash may already have cleared itself, in which case
        # there is nothing to emit.
        if self._pressed_lit:
            self._pressed_lit = False
            self._pressed_until = None
            actions.append(TouchAction(ACTION_SET_PRESSED_ZONE, None))
        return actions

    def _on_cap(self, now: float) -> list[TouchAction]:
        # Implicit release: stop repeating, start the dismiss clock, same as
        # a real RELEASE — the filter guarantees no further REPEAT/RELEASE
        # will follow for this press.
        return self._on_release(now)

    def _arm(self, x: int, y: int, now: float) -> list[TouchAction]:
        geometry = _GEOMETRY_FOR_SURFACE.get(self._surface, GEOMETRY_MAIN)
        hit = hit_test(geometry, x, y, self._width, self._height, metrics=self._metrics)
        zone, index = (hit.zone, hit.index) if hit is not None else (None, None)
        # DOTS/NAME are gated by their own "is it currently tappable" flag —
        # meaningful on the main and repeat geometries only; applying the
        # gate unconditionally is equivalent since neither zone appears in
        # the list or idle tables, so the gate never sees them there.
        if zone == TouchZone.DOTS and not self._dots_active:
            zone = None
        if zone == TouchZone.NAME and not self._name_active:
            zone = None
        if zone == TouchZone.OUTPUTS and not self._outputs_active:
            zone = None
        if zone is None:
            # Landed/arrived in a dead zone — nothing to actuate; still
            # counts as a contact sample toward dismiss.
            self._phase = _PHASE_IDLE
            self._armed_zone = None
            self._armed_index = None
            self._reset_dismiss(now)
            return []
        self._phase = _PHASE_ARMED
        self._armed_zone = zone
        self._armed_index = index
        self._pressed_lit = True
        # Only a single-shot zone self-clears; a repeating one (UP/DOWN)
        # stays lit while the finger holds it, because it really is still
        # acting.
        self._pressed_until = now + PRESSED_FLASH_S if zone in _SINGLE_SHOT_ZONES else None
        self._next_repeat_time = now + FIRST_REPEAT_S
        self._reset_dismiss(now)
        # Every zone acts once, immediately, on arm — a tap must do something.
        # Holding then adds auto-repeat: the next step lands FIRST_REPEAT_S
        # later and every REPEAT_INTERVAL_S after that (see tick()), the same
        # shape as a keyboard's auto-repeat. Single-shot zones never repeat,
        # since re-actuating them at 150ms intervals would be meaningless.
        actions = [TouchAction(ACTION_SET_PRESSED_ZONE, zone, index)]
        if zone == TouchZone.MUTE:
            actions.append(TouchAction(ACTION_MUTE_TOGGLE))
        elif zone == TouchZone.UP:
            actions.append(TouchAction(ACTION_VOLUME_UP))
        elif zone == TouchZone.DOWN:
            actions.append(TouchAction(ACTION_VOLUME_DOWN))
        elif zone in _ZONE_TAP_ZONES:
            actions.append(TouchAction(ACTION_ZONE_TAP, zone, index))
        return actions

    def _reset_dismiss(self, now: float) -> None:
        self._dismiss_deadline = now + DISMISS_S


# ---------------------------------------------------------------------------
# TouchEventSource — thin thread wrapper
# ---------------------------------------------------------------------------

# T_IRQ is active-low; mirrors dial_touch_drivers._TOUCH_IRQ_GPIO (kept as
# its own constant here too so this module has no import-time dependency on
# the drivers module beyond what open_driver() itself needs).
_T_IRQ_GPIO = 26

# How often the sample loop polls the driver while T_IRQ is active.
_POLL_INTERVAL_S = 0.01

# How long wait_for_active() blocks before returning control to the loop so
# tick() gets a chance to fire the dismiss timeout even with no touch at all.
_IDLE_TICK_INTERVAL_S = 0.1


class TouchEventSource:
    """Drives driver -> filter -> state machine and dispatches the resulting
    actions through injected callables. Constructed with an already-open
    driver, filter, and state machine (dial_main.py wiring, once it exists,
    owns creating those); this class adds only the thread and the IRQ wait.
    """

    def __init__(
        self,
        driver,
        touch_filter,
        state_machine: TouchStateMachine,
        *,
        on_reveal_overlay=None,
        on_volume_up=None,
        on_volume_down=None,
        on_mute_toggle=None,
        on_dismiss_overlay=None,
        on_set_pressed_zone=None,
        on_zone_tap=None,
        on_cap=None,
        clock=None,
        irq=None,
        poll_interval_s: float = _POLL_INTERVAL_S,
        idle_tick_interval_s: float = _IDLE_TICK_INTERVAL_S,
        get_noncomposited_generation=None,
        get_persistent_overlay=None,
        get_touch_surface=None,
        consume_repeat_close_reveal=None,
        axis_signs=None,
    ) -> None:
        self._driver = driver
        self._filter = touch_filter
        self._state_machine = state_machine
        self._on_reveal_overlay = on_reveal_overlay
        self._on_volume_up = on_volume_up
        self._on_volume_down = on_volume_down
        self._on_mute_toggle = on_mute_toggle
        self._on_dismiss_overlay = on_dismiss_overlay
        # ACTION_SET_PRESSED_ZONE callback: on_set_pressed_zone(zone, index)
        # — index only ever carries a value for LIST_ROW (the row it was
        # sampled against); every other zone, and the flash-clear
        # (zone=None), pass index=None.
        self._on_set_pressed_zone = on_set_pressed_zone
        # ACTION_ZONE_TAP callback: on_zone_tap(zone, index) — NAME (opens
        # the selector) and the LIST_* zones (act on it). See dial_main.py's
        # wiring for what each zone does; this module knows nothing about
        # the display beyond dispatching the action.
        self._on_zone_tap = on_zone_tap
        self._on_cap = on_cap
        self._clock = clock or time.monotonic
        self._irq = irq
        self._poll_interval_s = poll_interval_s
        self._idle_tick_interval_s = idle_tick_interval_s
        # Injected read of dial_display.DialDisplay.noncomposited_generation
        # — kept injected (not an import) for the same reason as the other
        # callbacks: this module must not import dial_display. None disables
        # the check entirely (e.g. in tests that don't care about it).
        self._get_noncomposited_generation = get_noncomposited_generation
        # Injected read of dial_display.DialDisplay.persistent_overlay_shown
        # — kept injected (not an import) for the same reason as the
        # noncomposited getter above: this module must not import
        # dial_display. None disables the "always show controls" sync
        # entirely (e.g. in tests that don't care about it, or a dial with
        # no display stack at all).
        self._get_persistent_overlay = get_persistent_overlay
        # Injected read of dial_display.DialDisplay.touch_surface — the new
        # preferred sync (surface + name_active in one call). Takes priority
        # over get_persistent_overlay when both are supplied; None disables
        # it entirely and falls back to the legacy getter — see
        # _poll_surface(). Kept injected, never imported, for the same
        # reason as every other display-facing callback here.
        self._get_touch_surface = get_touch_surface
        # Injected read-and-clear of dial_display.DialDisplay.
        # consume_repeat_close_reveal — a one-shot flag set only when the
        # repeat screen closes via a DOTS tap (never any other way it can
        # close), consumed here right after the resulting surface change is
        # applied to reveal the main screen's volume overlay instead of
        # leaving bare artwork on screen — see _poll_surface() and
        # TouchStateMachine.force_overlay_visible(). None disables it
        # entirely (e.g. tests that don't care, or a display stand-in that
        # predates this feature).
        self._consume_repeat_close_reveal = consume_repeat_close_reveal
        self._last_held: bool | None = None
        self._last_surface: tuple[str, bool, bool, bool] | None = None
        # The profile's UNROTATED axis signs (swap, invert_x, invert_y),
        # kept so a live rotate toggle can re-derive the mapping. None when
        # the caller did not supply them (e.g. tests constructing directly).
        self._axis_signs = axis_signs
        self._last_noncomposited_gen = None
        self._thread = None
        self._stop_event = None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        import threading

        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="touch-event-source", daemon=True
        )
        self._thread.start()

    def stop(self, join_timeout: float = 1.0) -> None:
        if self._stop_event is not None:
            self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=join_timeout)

    def overlay_live(self) -> None:
        """Tell the underlying session the overlay has actually rendered.
        Safe to call from any thread; forwards to the state machine and
        dispatches any resulting actions."""
        self._dispatch(self._state_machine.overlay_live(self._clock()))

    def display_config_changed(self, rotate: bool, *, layout=None) -> None:
        """Apply a live screen-settings change that affects touch mapping.

        A 180-degree rotate is applied to the frame in software, so the
        touch axes must invert with it — otherwise every press lands
        diagonally opposite the button the user is looking at. The profile's
        own axis signs describe the UNROTATED panel, so rotate is XOR'd in,
        exactly as dial_main does when first building the filter.

        *layout*, when given, is a dial_display_profiles.LayoutContext: the
        filter is re-scaled to its logical size and the state machine
        re-geometried to it (with metrics for that size) before the
        synthetic release below, so a press straddling the change is
        dropped exactly as a rotate drops it.

        Also delivers the synthetic release that config_changed() does: the
        finger cannot carry a press across a remap, because the zone it was
        sampled against has just moved.
        """
        setter = getattr(self._filter, "set_axis_transform", None)
        if setter is not None and self._axis_signs is not None:
            swap, base_invert_x, base_invert_y = self._axis_signs
            setter(
                swap_xy=swap,
                invert_x=base_invert_x != rotate,
                invert_y=base_invert_y != rotate,
            )
        if layout is not None:
            resize = getattr(self._filter, "set_logical_size", None)
            if resize is not None:
                resize(layout.logical_width, layout.logical_height, physical_size=layout.physical_size)
            self._state_machine.set_geometry(
                layout.logical_width, layout.logical_height,
                metrics_for(
                    layout.logical_width, layout.logical_height,
                    mm_per_px=layout.mm_per_px, size_chosen=layout.size_chosen,
                ),
            )
        self.config_changed()

    def config_changed(self) -> None:
        """Tell the session a live screen settings change (e.g. screen_type,
        which changes the zone geometry a currently-armed press was sampled
        against) just landed.

        Delivers a SYNTHETIC RELEASE to the state machine and drops the zone
        latch — a still-down finger cannot resume where it left off; only a
        fresh touch-down (a real PRESS from the filter, which requires an
        actual release-then-recontact) can arm again. This is deliberately
        stricter than force_reveal_only() (used for the momentary
        clear/sleep case): a screen_type change can move zone boundaries
        outright, so resuming the old arm — or even re-sampling from the
        current position via reveal-then-arm — could land on a zone that
        means something different now. Safe to call from any thread.
        """
        now = self._clock()
        self._dispatch(
            self._state_machine.on_filter_event(TouchEvent(TouchEventType.RELEASE, 0, 0, None), now)
        )

    def _poll_noncomposited(self) -> None:
        """Check whether the display's non-composited-state generation has
        advanced since we last looked (screen cleared or slept). If so,
        force the session back to reveal-only and drop the zone latch — see
        TouchStateMachine.force_reveal_only(). A no-op when no getter was
        injected. Cheap (one int read/compare) — safe to call every loop
        iteration.
        """
        if self._get_noncomposited_generation is None:
            return
        gen = self._get_noncomposited_generation()
        if self._last_noncomposited_gen is None:
            self._last_noncomposited_gen = gen
            return
        if gen != self._last_noncomposited_gen:
            self._last_noncomposited_gen = gen
            self._dispatch(self._state_machine.force_reveal_only())

    def _poll_held_visible(self) -> None:
        """Check whether the display's "always show controls" state has
        changed since we last looked, and sync the state machine to match —
        see set_held_visible() and the module docstring's HELD VISIBLE
        paragraph. A no-op when no getter was injected. A raising getter is
        treated as False: display failure must never leave the touch side
        believing controls are held visible when they might not be drawn.
        Cheap (one bool read/compare) — safe to call every loop iteration.
        """
        if self._get_persistent_overlay is None:
            return
        try:
            held = bool(self._get_persistent_overlay())
        except Exception:
            held = False
        if held != self._last_held:
            self._last_held = held
            self._dispatch(self._state_machine.set_held_visible(held, self._clock()))

    def _poll_surface(self) -> None:
        """Sync the state machine's surface from the display each loop
        iteration — see TouchStateMachine.set_surface() and the module
        docstring's SURFACES paragraph.

        Prefers get_touch_surface (surface + name_active[+ dots_active] in
        one call) when it was supplied; a raising getter is treated as
        SURFACE_HIDDEN, same discipline as _poll_held_visible's
        raise-is-False. Falls back to _poll_held_visible entirely
        (byte-for-byte, including its own None-getter no-op) when only the
        legacy get_persistent_overlay was supplied — existing
        "held"/"hidden"-only wiring is unaffected by this method's
        existence.

        Accepts a 2-tuple (surface, name_active) — dots_active and
        outputs_active default to False — a 3-tuple (surface, name_active,
        dots_active) — outputs_active defaults to False — or the full
        4-tuple (surface, name_active, dots_active, outputs_active).
        Either way self._last_surface is kept as a 4-tuple so an
        outputs_active-only (or dots_active-only) change — main screen
        chrome appearing/disappearing with no surface or name_active
        change — still triggers a set_surface() call.

        A transition AWAY from SURFACE_REPEAT additionally consumes the
        display's one-shot repeat-close-reveal flag (see
        consume_repeat_close_reveal in __init__): when it is set — which
        only happens when the repeat screen just closed via a DOTS tap,
        never any other way — this brings the main screen's volume
        overlay straight back up after set_surface()'s own DISMISS, via
        TouchStateMachine.force_overlay_visible().
        """
        if self._get_touch_surface is None:
            self._poll_held_visible()
            return
        try:
            result = self._get_touch_surface()
        except Exception:
            result = (SURFACE_HIDDEN, False)
        if isinstance(result, tuple):
            if len(result) >= 4:
                surface, name_active, dots_active, outputs_active = (
                    result[0], result[1], result[2], result[3],
                )
            elif len(result) == 3:
                surface, name_active, dots_active = result[0], result[1], result[2]
                outputs_active = False
            else:
                surface, name_active = result
                dots_active = False
                outputs_active = False
        else:
            surface, name_active, dots_active, outputs_active = result, False, False, False
        current = (surface, bool(name_active), bool(dots_active), bool(outputs_active))
        if current != self._last_surface:
            previous_surface = self._last_surface[0] if self._last_surface is not None else None
            self._last_surface = current
            self._dispatch(self._state_machine.set_surface(
                surface, bool(name_active), self._clock(),
                dots_active=bool(dots_active), outputs_active=bool(outputs_active),
            ))
            if (
                previous_surface in _REPEAT_SURFACES and surface not in _REPEAT_SURFACES
                and self._consume_repeat_close_reveal is not None
                and self._consume_repeat_close_reveal()
            ):
                self._dispatch(self._state_machine.force_overlay_visible(self._clock()))

    # -- main loop -----------------------------------------------------

    def _make_default_irq(self):
        from gpiozero import DigitalInputDevice

        return DigitalInputDevice(_T_IRQ_GPIO, pull_up=True)

    def _run(self) -> None:
        # Close only what this thread created. An injected irq belongs to
        # whoever passed it in (tests, mostly) and closing it here would
        # release a device the owner still holds a reference to.
        owned_irq = None
        if self._irq is not None:
            irq = self._irq
        else:
            irq = owned_irq = self._make_default_irq()
        try:
            self._loop(irq)
        finally:
            if owned_irq is not None:
                # Without this the T_IRQ GPIO stays claimed for the life of
                # the process: stop() ends the thread but the pin is never
                # given back, so anything that later re-opens the touch
                # stack (a restart-free reconfigure, a test, an orderly
                # shutdown) finds it busy.
                try:
                    owned_irq.close()
                except Exception:
                    pass

    def _loop(self, irq) -> None:
        while not self._stop_event.is_set():
            self._poll_noncomposited()
            self._poll_surface()
            irq.wait_for_active(timeout=self._idle_tick_interval_s)
            if irq.is_active:
                self._sample_loop(irq)
            else:
                # Keep feeding the filter "definitely not touching" while
                # idle, not just once as the sample loop exits. The release
                # debounce needs a no-contact sample AFTER DEBOUNCE_S has
                # elapsed to complete; the single feed(None) on the way out
                # of _sample_loop only starts that timer. Without a second
                # one the filter stays mid-debounce forever, and the next
                # contact is read as the same press resuming — so no PRESS
                # is emitted, the overlay never reveals again, and once the
                # original press is older than MAX_HOLD_S every later touch
                # collapses straight to a CAP. One touch works, none after.
                now = self._clock()
                for event in self._filter.feed(None, now):
                    self._handle_filter_event(event, now)
                self._dispatch(self._state_machine.tick(now))

    def _sample_loop(self, irq) -> None:
        while irq.is_active and not self._stop_event.is_set():
            self._poll_surface()
            now = self._clock()
            raw = self._driver.read_sample()
            for event in self._filter.feed(raw, now):
                self._handle_filter_event(event, now)
            self._dispatch(self._state_machine.tick(now))
            self._stop_event.wait(self._poll_interval_s)
        # T_IRQ has gone inactive: tell the filter contact has definitely
        # ended, in case debounce/settling hadn't already caught up.
        now = self._clock()
        for event in self._filter.feed(None, now):
            self._handle_filter_event(event, now)
        self._dispatch(self._state_machine.tick(now))

    def _handle_filter_event(self, event, now: float) -> None:
        if event.type == TouchEventType.CAP and self._on_cap is not None:
            self._on_cap()
        self._dispatch(self._state_machine.on_filter_event(event, now))

    def _dispatch(self, actions) -> None:
        for action in actions:
            if action.kind == ACTION_REVEAL_OVERLAY and self._on_reveal_overlay:
                self._on_reveal_overlay()
            elif action.kind == ACTION_VOLUME_UP and self._on_volume_up:
                self._on_volume_up()
            elif action.kind == ACTION_VOLUME_DOWN and self._on_volume_down:
                self._on_volume_down()
            elif action.kind == ACTION_MUTE_TOGGLE and self._on_mute_toggle:
                self._on_mute_toggle()
            elif action.kind == ACTION_DISMISS_OVERLAY and self._on_dismiss_overlay:
                self._on_dismiss_overlay()
            elif action.kind == ACTION_SET_PRESSED_ZONE and self._on_set_pressed_zone:
                self._on_set_pressed_zone(action.zone, action.index)
            elif action.kind == ACTION_ZONE_TAP and self._on_zone_tap:
                self._on_zone_tap(action.zone, action.index)
