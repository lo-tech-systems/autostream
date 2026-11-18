"""dial_touch.py — touch session policy: TouchStateMachine. The thread that
drives it is dial_touch_source.TouchEventSource.

TouchStateMachine is pure, with no thread and no clock of its own (every
method takes *now*). It consumes dial_touch_filter.TouchEvent objects plus an
explicit "overlay actually rendered" input and produces a small ordered
list of ACTIONS for a caller to dispatch. It owns the "is the overlay
visible" truth — see REVEAL-THEN-ARM below.

REVEAL-ONLY FIRST TOUCH: a contact that begins while the overlay is not
visible ONLY reveals it (the one exception: while the dial has a warning,
the bell drawn in the corner of resting artwork, ARTWORK_BELL, is live). No zone is sampled, nothing is actuated, however
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
TouchStateMachine.set_held_visible(), driven from the display's
touch_surface(). While held, the overlay counts as visible
from the state machine's point of view: the next press arms immediately (the
same "already visible" path REVEAL-ONLY FIRST TOUCH describes above) and the
dismiss clock in tick() is disabled entirely, since there is no touch-driven
overlay session to time out. When the display stops holding it (screen went
to the logo, went to sleep, or the setting was turned off), the session is
forced back to hidden and a DISMISS is emitted so the touch-published
overlay snapshot is cleared too — a finger must never be able to arm against
controls that are no longer actually drawn. The display can also end a session itself, when an
artwork tap hides the controls it revealed: see overlay_hidden().

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
lands in no zone); "eq" maps to GEOMETRY_EQ (the EQ page, rich/large only);
"card1", "card2" and "card3" map to GEOMETRY_CARD1/2/3 (a warning or
status card with that many button cells: the warnings page picks the one
for the entry it shows, the update result card is "card1"); "update" maps
to GEOMETRY_NONE and so does "restarting" (nothing tappable, so no press
can arm anything while the reboot is pending)
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
the geometry under the finger just changed. The surface and its flags are
polled by dial_touch_source.TouchEventSource. Closing the repeat
screen via a DOTS tap also reveals the main screen's volume overlay on
return — see TouchStateMachine.force_overlay_visible() and
dial_touch_source.TouchEventSource._poll_surface(). "repeat_replay" is a physically-tiny-glass
variant of "repeat" (its own geometry, GEOMETRY_REPEAT_REPLAY, for the
replaying layout's own time/Restart/Stop cells): held exactly like "repeat",
and the two are treated as one set by the repeat-close reveal rule above, so
a flip between them is never mistaken for a close.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from dataclasses import dataclass

from dial_touch_filter import FIRST_REPEAT_S, REPEAT_INTERVAL_S, TouchEventType
from dial_touch_surfaces import (
    SURFACE_CARD1, SURFACE_CARD2, SURFACE_CARD3, SURFACE_EQ, SURFACE_HELD, SURFACE_HIDDEN, SURFACE_IDLE,
    SURFACE_INFO, SURFACE_INFO_VALUE, SURFACE_OUTPUT, SURFACE_OUTPUTS, SURFACE_PICKER, SURFACE_REPEAT,
    SURFACE_REPEAT_REPLAY, SURFACE_RESTARTING, SURFACE_SELECTOR, SURFACE_UPDATE,
)
from dial_layout_metrics import LayoutMetrics
from dial_touch_layout import (
    GEOMETRY_EQ,
    GEOMETRY_IDLE,
    GEOMETRY_INFO,
    GEOMETRY_INFO_VALUE,
    GEOMETRY_LIST,
    GEOMETRY_MAIN,
    GEOMETRY_NONE,
    GEOMETRY_ARTWORK_BELL,
    GEOMETRY_CARD1,
    GEOMETRY_CARD2,
    GEOMETRY_CARD3,
    GEOMETRY_OUTPUT,
    GEOMETRY_REPEAT,
    GEOMETRY_REPEAT_REPLAY,
    BELL_ZONES,
    TouchZone,
    hit_test,
)

# Overlay auto-dismisses this long after the last contact sample / release /
# cap-stop, whichever is most recent.
DISMISS_S = 4.0

# How long a single-shot (MUTE) highlight stays lit. Long enough to read as
# deliberate feedback, short enough that it never looks like a latched
# state; each change costs one full-frame push. Repeating zones (UP/DOWN)
# ignore this and stay lit until release — see the module docstring.
PRESSED_FLASH_S = 0.25

# Action kinds produced by TouchStateMachine.
ACTION_REVEAL_OVERLAY = "reveal-overlay"
ACTION_VOLUME_UP = "volume-up"
ACTION_VOLUME_DOWN = "volume-down"
ACTION_MUTE_TOGGLE = "mute-toggle"
ACTION_DISMISS_OVERLAY = "dismiss-overlay"
ACTION_SET_PRESSED_ZONE = "set-pressed-zone"
ACTION_ZONE_TAP = "zone-tap"
ACTION_WAKE = "wake"

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
# A contact that began while the panel was asleep: it only wakes the screen
# and does nothing more until it lifts.
_PHASE_WAKE_ONLY = "wake_only"

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
    SURFACE_CARD1: GEOMETRY_CARD1,
    SURFACE_CARD2: GEOMETRY_CARD2,
    SURFACE_CARD3: GEOMETRY_CARD3,
    SURFACE_RESTARTING: GEOMETRY_NONE,
    SURFACE_UPDATE: GEOMETRY_NONE,
}

@dataclass(frozen=True)
class TouchAction:
    kind: str
    zone: TouchZone | None = None
    index: int | None = None


class TouchStateMachine:
    """Pure press-session policy. No thread, no clock reads — every method
    takes an explicit *now*, so tests drive it deterministically."""

    def __init__(
        self, width: int, height: int, metrics: "LayoutMetrics | None" = None,
        is_asleep=None,
    ) -> None:
        self._width = width
        self._height = height
        # Set at construction from the profile/layout size in force at
        # startup (see dial_main._build_touch_source) — None means
        # metrics_for(width, height), today's density-unaware hit-testing.
        # A live geometry change replaces all three together — see
        # set_geometry() below.
        self._metrics = metrics
        # Lock-free "is the panel asleep right now" predicate, read once per
        # press (see _on_press). Default: never asleep.
        self._is_asleep = is_asleep or (lambda: False)
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
        # Whether the bell zones (BELL_ZONES) are currently live: the dial
        # has a warning to show, so a bell is drawn. One gate for every
        # bell, applied in _arm() like the three above.
        self._bell_active = False

    # -- read-only state, for a compositor/UI to consult -------------------

    @property
    def pressed_zone(self) -> TouchZone | None:
        return self._armed_zone if self._pressed_lit else None

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
        return self._drop_session()

    def overlay_hidden(self, now: float) -> list[TouchAction]:
        """External sync from the display: it has taken the touch-revealed
        overlay down itself (an artwork tap hid the controls). Held: a
        no-op, the display's own surface report drops to hidden and
        set_surface() handles it. Otherwise exactly what the dismiss clock
        firing does, at once: the overlay counts as hidden (the next press
        reveals, never actuates), the latch is dropped and a DISMISS is
        emitted so the touch-published snapshot is cleared too."""
        if self._held:
            return []
        return self._drop_session()

    def _drop_session(self) -> list[TouchAction]:
        """Force the session back to hidden: drop whatever zone was armed
        and stop repeating, without assuming anything about whether a
        finger is currently down, and emit the actions that clear a lit
        zone and the touch-published snapshot. Shared by set_held_visible()
        and overlay_hidden()."""
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
        outputs_active: bool = False, bell_active: bool = False,
    ) -> list[TouchAction]:
        """External sync from the display: which screen is on the panel
        right now — see the module docstring's SURFACES paragraph.

        SURFACE_HIDDEN: main screen, reveal on touch (held=False).
        SURFACE_HELD: main screen with controls held visible (held=True).
        SURFACE_SELECTOR: the appliance list; hit-tests use the LIST geometry,
        presses arm immediately (held=True in effect), and there is no
        dismiss clock to disable beyond what held already disables.
        SURFACE_PICKER: the replay picker — same LIST hit-test
        and held behaviour as SURFACE_SELECTOR.
        SURFACE_REPEAT: the repeat screen; hit-tests use the REPEAT geometry,
        held like the selector.
        SURFACE_IDLE: the idle screen; hit-tests use the IDLE geometry, held
        like the selector.
        SURFACE_OUTPUTS: the outputs list; same LIST hit-test and
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

        name_active, dots_active, outputs_active and bell_active are recorded
        either way — even on a same-surface call — since any of them can change on
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
            self._bell_active = bell_active
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
        self._bell_active = bell_active
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
        dial_touch_source.TouchEventSource._poll_surface() for the call site
        and the module docstring's SURFACES paragraph.

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
        if self._is_asleep():
            # The panel is dark: this contact only wakes it. Nothing is on
            # screen to press, so it must not arm, flash, step or reveal,
            # and the overlay state is left exactly as it was. The phase
            # holds the contact inert until release. A stale read costs at
            # most one wake-only or one ordinary touch, both harmless.
            self._phase = _PHASE_WAKE_ONLY
            self._armed_zone = None
            self._armed_index = None
            self._next_repeat_time = None
            return [TouchAction(ACTION_WAKE)]
        if not self._overlay_visible:
            if self._surface == SURFACE_HIDDEN and self._bell_active:
                # The one exception to reveal-only first touch: the bell
                # drawn in the corner of resting artwork is live.
                hit = hit_test(GEOMETRY_ARTWORK_BELL, event.x, event.y, self._width, self._height, metrics=self._metrics)
                if hit is not None:
                    return self._arm_zone(hit.zone, None, now)
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
        if self._phase == _PHASE_WAKE_ONLY:
            return []
        self._reset_dismiss(now)
        return []

    def _on_release(self, now: float) -> list[TouchAction]:
        self._contact_down = False
        actions: list[TouchAction] = []
        if self._phase == _PHASE_WAKE_ONLY:
            self._phase = _PHASE_IDLE
            return actions
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
        # DOTS/NAME/OUTPUTS are gated by their own "is it currently
        # tappable" flag. A switched-off one is skipped by the hit-test
        # rather than swallowing the touch, so a press in the strip its
        # reach covers below the band lands on whatever is drawn there; a
        # press on the band itself still finds nothing (nothing else
        # overlaps the band). The gates only matter where these zones
        # appear. Every bell zone shares the one bell gate.
        skip = frozenset(
            gated for gated, active in (
                (TouchZone.DOTS, self._dots_active),
                (TouchZone.NAME, self._name_active),
                (TouchZone.OUTPUTS, self._outputs_active),
            ) if not active
        ) | (frozenset() if self._bell_active else BELL_ZONES)
        hit = hit_test(geometry, x, y, self._width, self._height, metrics=self._metrics, skip=skip)
        zone, index = (hit.zone, hit.index) if hit is not None else (None, None)
        return self._arm_zone(zone, index, now)

    def _arm_zone(self, zone: "TouchZone | None", index: "int | None", now: float) -> list[TouchAction]:
        """Arm *zone* (None: a press that landed in a dead zone)."""
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
