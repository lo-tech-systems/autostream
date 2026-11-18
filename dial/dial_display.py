"""dial_display.py — the dial's screen: the view over the appliance model.

Owns the panel: threading of the repaint loop, screen policy (the table of
screens, their timeouts and what a fold that finds nothing playing does to
each), composing and transmitting frames, panel sleep and wake from
snapshots, the artwork-tap reveal slide, the replay timer line, the pressed
channel, the artwork decode and fit cache, and the touch surface the touch
source reads. It holds no appliance state of its own.

Everything about the appliances belongs to the core (dial_core.py): the
appliances as their peer clients hold them, authorization gating, focus, the
now-playing line and its artwork bytes, the repeat and outputs/EQ state, the
Wi-Fi link, SD health and update watch, and the warning manager. The core
runs on its own thread and publishes immutable snapshots. This manager
subscribes to them and its repaint thread folds each into the screen
(_apply_snapshot): a finished fold shows its artwork or logo, rows and
idle sleep; a playing appliance wakes a sleeping panel; a snapshot nothing
on screen depends on paints nothing. What the core's warning sources and
request replies mean for a screen reaches it as queued effects.

Display failure must always degrade to a no-op display; it must never affect
volume control. Backend hardware code lives in dial_display_adafruit.py;
Pillow-only image policy lives in dial_display_image.py.

Threads. The touch thread calls only the lock-free entries (section 3): plain
writes and a repaint signal, never self._lock. The repaint thread runs the loop
and its timers, folds the core's snapshots and requests, and takes self._lock
to paint. The HTTP thread calls the facade and update_config, which take the
lock. The core's thread reads a few plain-read hooks (_holds_idle_state,
_compact_tier). The lock may enclose a backend push; the lock order is in
DialDisplay.__init__.

DialDisplay is ordered by thread; its sections, in file order, are:

  1. Construction: the field table and the lock order.
  2. Lifecycle and HTTP facade.
  3. Touch-thread entries, and the plain-read helpers they share.
  4. Repaint thread: the loop and its timers.
  5. Repaint thread: request folding and the screen openers, under the lock.
  6. Painters, under the lock.
  7. Panel: backend, geometry and transmit, under the lock.
  8. Snapshot fold and effects.
  9. Warnings, idle and sleep.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import dataclasses
import functools
import io
import logging
import math
import threading
import time
from dataclasses import dataclass
from typing import Callable, NamedTuple

from PIL import Image, ImageChops

from dial_display_compositor import (
    DialDisplayCompositor,
)
from dial_display_views import (
    BellBadge,
    EqViewState,
    InfoValueView,
    ListState,
    OutputViewState,
    OverlayState,
    RepeatViewState,
    WIFI_GREY,
    WIFI_OFF,
    WIFI_RED,
    WIFI_SIGNAL,
    WarningView,
)
from dial_display_draw import _unfinish
from dial_display_controls import DEADLINE_PAD_S, ControlsReveal
from dial_display_repeat_line import RepeatLine
from dial_display_image import (
    decode_artwork,
    load_logo,
    resample_filter,
)
from dial_display_backend import (
    DEFAULT_PANEL_HEIGHT, DEFAULT_PANEL_WIDTH, DisplayBackend, NoOpBackend, backend_factory_for,
)
from dial_display_palette import TRANSITION_RGB
from dial_display_profiles import layout_context_for
from dial_display_state import (
    ApplianceScreenState,
    INFO_PLACEHOLDER_ROWS,
    INFO_TITLE,
    InfoRow,
    InfoState,
    InfoValueState,
    ListScreenState,
    OutputDetailState,
    RestartingState,
    WarningScreenState,
    clamp_page,
    eq_loaded,
    held_eq,
    held_outputs,
    list_state_for,
    needs_update_hint,
    offerable,
    output_list_row,
    page_slice,
    pairing_hint,
    picker_list_row,
    rows_per_page_for,
    selector_list_row,
    start_failure_hint,
    unauthorised_hint,
    wrap_page,
)
from dial_display_windows import bounding_box, dirty_windows, frame_words, plan_windows
from dial_core_state import (
    AUTH_UNAUTHORIZED, PIN_ERRORS, OutputRow,
    awaiting_title, title_fallback,
    eq_gain,
)
import dial_artwork
from dial_core import DialCore, CoreIO
from dial_core_effects import OutputsEffect, RepeatEffect, StartFailureEffect
from dial_mdns import appliance_display_name
from dial_network import (
    LINK_CONNECTED,
    LINK_DOWN,
)
from dial_values import clamp
from dial_warning_bell import Bell, whole_bell
from dial_warning_page import Card, WarningsPageState, status_card
from dial_warning_text import WARNING_DESCRIPTORS
from dial_touch_surfaces import (
    SURFACE_CARD1, SURFACE_CARD2, SURFACE_CARD3, SURFACE_EQ, SURFACE_HELD, SURFACE_HIDDEN, SURFACE_IDLE,
    SURFACE_INFO, SURFACE_INFO_VALUE, SURFACE_OUTPUT, SURFACE_OUTPUTS, SURFACE_PICKER, SURFACE_REPEAT,
    SURFACE_REPEAT_REPLAY, SURFACE_RESTARTING, SURFACE_SELECTOR, SurfaceState,
)
from dial_layout_metrics import (
    CONTENT_COMPACT,
    CONTENT_LARGE,
    CONTENT_RICH,
    LayoutMetrics,
    metrics_for,
)
from dial_touch_layout import (
    CARD_BUTTON_ZONES,
    TouchZone,
)
from dial_volume import (
    shown_muted,
    shown_volume,
)
from dial_warnings import (
    ACTION_CLOSE,
    ACTION_NEXT,
    ACTION_RESTART,
    KIND_STATUS,
    WarningDescriptor,
)

DEFAULT_DISPLAY_LOGO_PATH = "/opt/autostream/images/autostream-logo-centred-dark.png"
# Shown on the idle screen in place of the plain logo whenever a held
# recording can be replayed (the arrows-on-disc "replay available" logo).
DEFAULT_DISPLAY_REPLAY_LOGO_PATH = "/opt/autostream/images/autostream-logo-replay-dark.png"

DISPLAY_IDLE_SLEEP_SECONDS = 5 * 60
# How long the appliance-selector screen stays open with no touch activity
# before it closes back to the main (now-playing) screen. Refreshed by any
# touch activity while open — see _apply_touch_activity_locked. The replay
# picker uses the same timeout; the repeat screen has none of its own — see
# _check_secondary_timeout.
SELECTOR_TIMEOUT_SECONDS = 18

# The page-dots cycle order — see cycle_pages(). "main" is always available
# (the fallback every cycle lands on); "repeat" and "eq" are skipped when
# _repeat_page_available() / the snapshot's eq_available say there is nothing
# to show.
_PAGE_ORDER = ("main", "repeat", "eq")

# The idle screen's offline flash: the Wi-Fi glyph alternates grey/red,
# switching every half period (a 1 Hz cycle). The repaint loop schedules
# itself onto these boundaries (the wifi_flash timer); nothing else ticks
# for it.
WIFI_FLASH_HALF_PERIOD_S = 0.5

# The "Restarting..." screen is meant to end when the reboot takes the panel
# down. If the reboot request itself failed (nginx down, helper refused),
# fall back to main after this long so the dial is never stuck on it.
RESTARTING_TIMEOUT_SECONDS = 90.0

# The overlay an artwork tap's hide window substitutes for whatever the
# touch side has published: nothing drawn. See _effective_overlay_locked().
_HIDDEN_OVERLAY = OverlayState()

# ---------------------------------------------------------------------------
# Screen policy table
#
# One policy row per screen, read by the manager wherever the screen showing
# decides what happens: what the touch side is told, how it is painted,
# whether and when it times out, what a fold that finds nothing playing does
# to it, and what a close hands back to. Adding a screen is adding a row
# here plus its own opener and painter; nothing else in the manager should
# need to name screens.
# ---------------------------------------------------------------------------

# How a fold that finds nothing playing treats a screen.
IDLE_KEEP = "keep"                       # the screen stays; its own timeout closes it
IDLE_KEEP_WITH_FOCUS = "keep_with_focus" # kept only while an idle focus gives it something to show


@dataclass(frozen=True)
class ScreenPolicy:
    """One screen's policy — see the module note above. `open`/`paint` are
    unbound DialDisplay methods; `open` returns False to refuse the request
    and leave the current screen in place (e.g. the repeat screen with
    nothing to show for it)."""
    state_attr: str | None            # the manager attribute holding this screen's state, or None (main)
    surface: tuple[str, bool, bool, bool] | None  # (surface, name_active, dots_active, outputs_active) for touch, or None: computed (main)
    open: object                      # unbound DialDisplay method (self) -> bool
    paint: object                     # unbound DialDisplay method (self) -> None, or None: main's own paint path
    paged: bool                       # a paged list: page requests apply, rows are sliced per page
    inactivity_timeout_s: float | None
    touch_extends_timeout: bool       # touch activity re-stamps opened_at
    when_nothing_plays: str           # IDLE_KEEP | IDLE_KEEP_WITH_FOCUS
    defers_sleep: bool                # open (or requested) screen holds off the idle-sleep countdown
    close_reveals_overlay: bool       # a DOTS toggle-close arms the one-shot main-overlay reveal
    closes_on_focus_clear: bool       # a manual-focus clear pops it
    back_to: str                      # the screen a back/close request returns to
    bound_to_appliance: bool = False  # closed by the poll when its appliance stops being focused/reporting
    # A second surface tuple this screen reports, in place of `surface`,
    # while its own replaying-style layout is the one actually painted and
    # the resolved content tier gives that layout its own geometry (the
    # compact tier's repeat screen — see touch_surface() and
    # self._repeat_layout_shown). None: this screen never has one.
    replay_surface: tuple[str, bool, bool, bool] | None = None


def _defers_sleep(screen: str, request: "str | None") -> bool:
    """Whether the open screen, or the screen requested but not yet applied
    (an open_* call just ran on the touch thread), holds off the idle-sleep
    countdown. Plain reads."""
    return _policy(screen).defers_sleep or (request is not None and _policy(request).defers_sleep)


class _Signal(threading.Event):
    """The repaint thread's wake-up. `set` asks for a repaint; `poke` only
    wakes the thread so it reads the core's newest snapshot, and a wake that
    nothing but pokes caused paints nothing (the snapshot's own effects
    decide whether anything must be drawn)."""

    def __init__(self) -> None:
        super().__init__()
        self._request_lock = threading.Lock()
        self._requested = False

    def set(self) -> None:
        with self._request_lock:
            self._requested = True
            super().set()

    def poke(self) -> None:
        super().set()

    def clear(self) -> None:
        with self._request_lock:
            self._requested = False
            super().clear()

    def consume(self) -> bool:
        """Clear the signal; True when a repaint had been asked for since
        the last call."""
        with self._request_lock:
            requested, self._requested = self._requested, False
            super().clear()
        return requested


# ---------------------------------------------------------------------------
# Runtime status
# ---------------------------------------------------------------------------

@dataclass
class DisplayRuntimeStatus:
    fitted: bool
    rotate: bool
    screen_type: str
    bgr: bool
    always_show_controls: bool
    active: bool
    backend: str
    backend_loaded: bool
    showing: str
    last_error: str
    last_error_at: float | None
    display_sleeping: bool
    display_idle_seconds: int

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def _no_deadline() -> None:
    """The deadline of a timer that never schedules a wake of its own."""
    return None


class _Timer(NamedTuple):
    """One of the repaint loop's timers. *deadline* is when the loop must
    next wake for it (None: nothing scheduled); *fire* is its work on a
    timeout wake, and a truthy result asks for a repaint."""
    name: str
    deadline: Callable[[], "float | None"]
    fire: Callable[[], "bool | None"]


# Rich/large artist-row fallback text (see _effective_overlay_locked): shown
# in the artist line's own slot when the tier draws one but the focus is idle
# or pending, so there is no real artist to put there. Compact draws no
# artist row and base keeps its own, so the constant is never read there.
IDLE_ARTIST_TEXT = "Idle"


# The screens a hint on the value page may open over, by what asks for it.
_HINT_OVER_DEFAULT = ("selector", "output")
_LATE_PIN_OVER = ("outputs", "output")
_START_FAILURE_OVER = ("main", "outputs", "output")


# How each repeat-store state draws the repeat page: (layout, start_enabled,
# stop_enabled, stop_pressed). A state with no live replay draws the enable
# layout; hold, replaying and fading_out draw the Restart/Stop row, with
# Stop drawn pressed once the fade-out has begun.
_REPEAT_LAYOUTS = {
    "recording": ("enable", False, False, False),
    "pending": ("enable", False, False, False),
    "idle": ("enable", False, False, False),
    "hold": ("replaying", True, False, False),
    "replaying": ("replaying", True, True, False),
    "fading_out": ("replaying", False, True, True),
}


# The row-list screens built from a ListScreenState: the placeholder shown
# with no rows, and the mapping from a core row to a list row.
_ROW_LISTS = {
    "selector": ("No devices", selector_list_row),
    "picker": ("Nothing to replay", picker_list_row),
}


# ---------------------------------------------------------------------------
# Display manager
# ---------------------------------------------------------------------------

class DialDisplay:
    # ---------------------------------------------------------------------------
    # 1. Construction
    #
    # Thread: main.
    # Owns: every field (see the table in __init__) and the LOCK ORDER
    # ---------------------------------------------------------------------------

    def __init__(
        self,
        config,
        core: "DialCore",
        logo_path: str = DEFAULT_DISPLAY_LOGO_PATH,
        replay_logo_path: str = DEFAULT_DISPLAY_REPLAY_LOGO_PATH,
        backend_factory=NoOpBackend,
        backend_factory_builder=None,
    ) -> None:
        # FIELD TABLE. "Plain read" is a read with no lock: one reference or number,
        # atomic under the GIL, so a stale value costs at most one extra tick.
        #
        #   _lock                        the one lock; it may enclose a backend push.
        #   _config, _layout, _mm_per_px written under _lock (here, update_config on the
        #                                HTTP thread); plain reads from any thread.
        #   _backend*, _active_screen_type, _showing, _last_error*, _last_frame,
        #   _panel_words                 under _lock (repaint and HTTP threads);
        #                                _backend_open and _showing are also plain reads.
        #   _source_artwork_key, _current_rendered_image, _current_base_image
        #                                under _lock (repaint thread; HTTP via update_config).
        #   _idle_started_at, _display_sleeping
        #                                under _lock; _display_sleeping is also a plain
        #                                read (touch thread, core thread).
        #   _noncomposited_generation    bumped under _lock; plain read by the touch thread.
        #   _overlay_snapshot            written by set_overlay() under the leaf lock;
        #                                plain read.
        #   _overlay_signal              any thread.
        #   _core, _subscription, _repaint_thread, _repaint_stop_event
        #                                lifecycle: set by start() and stop().
        #   _applied, _tick_shown_level  repaint thread, under _apply_lock.
        #   _touch_activity_pending, _screen_request, _page_request, _pressed,
        #   _repeat_close_reveal, _info_value_index, _info_value_hint(_over),
        #   _output_open_id, _warnings_next, _info_gather_seq
        #                                requests: plain writes from the touch thread.
        #                                The repaint thread folds or clears them under _lock.
        #   _screen and every state attribute (_selector, _picker, _info, _info_value,
        #   _repeat_screen, _outputs, _eq, _output_detail, _restarting,
        #   _warning_screen, _warnings_page), _info_value_return, _outputs_return,
        #   _repeat_layout_shown
        #                                written under _lock: the repaint thread, the idle
        #                                tick, and the HTTP thread (update_config). The
        #                                touch entries and touch_surface() read them plain.
        #   _controls, _repeat_line      collaborators; their modules' tables say who
        #                                writes what.
        #   _get_info_rows               set once at startup by set_info_provider().
        #   _timers                      built below; run by the repaint thread.
        #
        # LOCK ORDER (binding): self._lock may enclose the SPI/backend push
        # (see _display_locked). self._overlay_snapshot_lock is a small LEAF
        # lock used only by set_overlay() to guard the write of a new
        # OverlayState snapshot; it is ALWAYS acquired standalone and is
        # NEVER acquired while self._lock is held, and self._lock is NEVER
        # acquired while it is held. Readers of the snapshot (this class and
        # the repaint thread) never take it at all — a plain attribute read
        # of self._overlay_snapshot is a single object-reference read, which
        # is atomic under the GIL, so no lock is needed to read it safely.
        # This is what keeps touch cadence off self._lock: set_overlay() is
        # the only thing the touch thread ever calls into here, and it never
        # touches self._lock — the touch thread never takes self._lock.
        self._lock = threading.Lock()
        self._config = config
        # Logical (compose) size, physical size and density per logical pixel:
        # one LayoutContext per config object (dial_display_profiles.layout_context_for()).
        self._layout = layout_context_for(config)
        # Physical pixel pitch per logical pixel, always self._layout.mm_per_px;
        # kept as its own attribute because tests and _layout_metrics() read it.
        self._mm_per_px = self._layout.mm_per_px
        self._logo_path = logo_path
        self._replay_logo_path = replay_logo_path
        self._backend_factory = backend_factory
        # Optional screen_type -> backend-factory resolver for a live screen_type
        # swap. Injected, so this module imports no concrete backend; tests that
        # never swap leave it unset.
        self._backend_factory_builder = backend_factory_builder
        # Pixel work lives in the compositor, which is stateless: one shared
        # instance is safe. This manager does the I/O (fetch, decode, load_logo).
        self._compositor = DialDisplayCompositor()

        self._backend: DisplayBackend | None = None
        self._backend_name = "noop"
        # Profile key of the backend open now ("" when none); self._config.screen_type
        # is what was requested.
        self._active_screen_type = ""
        self._backend_open = False
        self._backend_loaded = False
        self._showing = "noop"
        self._last_error = ""
        self._last_error_at: float | None = None

        # Artwork identity dedupe: only the current rendered image is kept.
        self._source_artwork_key = ""
        self._current_rendered_image = None

        # The frame last pushed to the panel (post-compose, resample, rotate, BGR),
        # kept for screenshots. Never mutated after a push; cleared whenever the
        # panel no longer shows it (disable, sleep, clear, backend swap).
        self._last_frame: Image.Image | None = None
        # The panel frame's bytes as words for the change-region planner, keyed by
        # identity to self._last_frame: (frame, words) or None. A cache, never
        # authority: when the pair no longer names self._last_frame the view is
        # rebuilt, so the places that drop self._last_frame need not know of it.
        self._panel_words = None

        # Set while the logo shows with nothing playing; cleared on activity or disable.
        self._idle_started_at: float | None = None
        self._display_sleeping = False

        self._log_limiter = dial_artwork.RateLimitedLogger()

        self._overlay_snapshot_lock = threading.Lock()
        self._overlay_snapshot = OverlayState()
        self._overlay_signal = _Signal()
        # (service, volume, muted) shown at the end of the last playing tick.
        self._tick_shown_level: tuple = (None, None, False)
        # The appliance model: it folds the appliances on its own thread and
        # publishes snapshots. While started, this view subscribes and its repaint
        # thread folds each into the screen (_apply_snapshot). The caller builds,
        # starts and stops the core.
        self._core = core
        self._core.set_io(CoreIO(
            on_artwork_error=self._record_error, log_limiter=self._log_limiter,
        ))
        self._core.set_eq_veto(self._compact_tier)
        self._core.set_idle_hold(self._holds_idle_state)
        self._subscription: int | None = None
        # The last snapshot folded into the screen, and the lock that keeps two
        # threads (the repaint thread; a test driving the core) from folding at once.
        self._applied = self._core.snapshot()
        self._apply_lock = threading.Lock()
        self._touch_activity_pending = False
        self._repaint_thread: threading.Thread | None = None
        self._repaint_stop_event = threading.Event()
        # The last base image handed to _display_locked (pre-overlay, pre-rotate/BGR):
        # logo or panel-fitted artwork. The repaint thread recomposes it against the
        # newest overlay snapshot when only the overlay changed.
        self._current_base_image = None

        # See _mark_noncomposited_locked().
        self._noncomposited_generation = 0

        # The controls windows and the reveal slide (dial_display_controls).
        self._controls = ControlsReveal()

        # ---- Screen state ------------------------------------------------
        # "main" is the now-playing screen; the other names are the keys of
        # SCREEN_POLICIES.
        self._screen = "main"
        # Last-built rows, refreshed every fold whether or not the list is open
        # (_refresh_list_rows), so opening it never waits. None until the first fold.
        self._selector: ListScreenState | None = None
        # Built once when the repeat screen opens; None while another screen shows.
        self._repeat_screen: ApplianceScreenState | None = None
        # "enable" or "replaying", stamped by _display_repeat_locked from the view
        # it just built; touch_surface() reads it for the compact tier's replay surface.
        self._repeat_layout_shown: str = "enable"
        # The replaying counter's painted-second reference and the main page's
        # replay timer line (dial_display_repeat_line).
        self._repeat_line = RepeatLine()
        # The replay picker's rows and paging, refreshed like self._selector.
        self._picker: ListScreenState | None = None
        # The info page's state: written by its opener (_open_info_locked) and by
        # _gather_info's fold-in (a short-lived daemon thread; one assignment under
        # the lock, no I/O while held).
        self._info: InfoState | None = None
        # Bumped by open_info() each time the page (re)opens; a landing gather
        # drops its result if its captured value no longer matches.
        self._info_gather_seq = 0
        # The compact info page's drill-in state, kept beside self._info (not cleared
        # when the value view opens: the view reads its rows from self._info).
        self._info_value: InfoValueState | None = None
        # The row a LIST_ROW tap on the compact info list chose, consumed by the
        # value view's opener.
        self._info_value_index: int | None = None
        # The (label, text) hint a tap on an unauthorised row asks the value view
        # to show, consumed by the opener like self._info_value_index.
        self._info_value_hint: tuple[str, str] | None = None
        # The screens the pending hint may open over; reset by _open_info_value_locked.
        self._info_value_hint_over: tuple[str, ...] = _HINT_OVER_DEFAULT
        # The screen a hint view returns to: the one it opened over.
        self._info_value_return: str = "selector"
        # Zero-arg callable -> tuple[InfoRow, ...], wired by set_info_provider()
        # after the HTTP server exists. None: _gather_info() uses the placeholders.
        self._get_info_rows = None
        # The outputs list's state (appliance, page, clock). Its rows are the
        # core's, less the outputs another appliance has taken, read at use.
        self._outputs: ApplianceScreenState | None = None
        # The EQ page's state (appliance, clock); its bands are the core's.
        self._eq: "ApplianceScreenState | None" = None

        # The per-output detail page's state.
        self._output_detail: OutputDetailState | None = None
        # The row a LIST_ROW tap on the outputs list chose, consumed by the
        # detail page's opener.
        self._output_open_id: str | None = None
        # The restarting screen's state.
        self._restarting: "RestartingState | None" = None
        # The status page on screen, if any (shared by every status row).
        self._warning_screen: "WarningScreenState | None" = None
        # The warnings card on screen, if any, and a Next tap the touch thread
        # made that the repaint thread has not yet folded in.
        self._warnings_page: "WarningsPageState | None" = None
        self._warnings_next = False
        # The (zone, index) pressed on whichever screen shows: one channel for
        # every screen, resolved at compose time against that screen's geometry.
        # index is meaningful only for LIST_ROW.
        self._pressed: "tuple[TouchZone, int | None] | None" = None
        # One-shot, touch thread only (set by cycle_pages() when a page closes via
        # a DOTS tap, read by consume_repeat_close_reveal()): tells the touch side
        # to reveal the main screen's volume overlay on return.
        self._repeat_close_reveal = False
        # The page the outputs list goes back to ("main", "repeat" or "eq"),
        # recorded by _open_outputs_locked() and kept across the per-output detail
        # page. See _back_target().
        self._outputs_return = "main"
        # Pending touch-thread requests: plain str/int writes, folded into the
        # screen state by _apply_screen_requests_locked. None: no request.
        self._screen_request: str | None = None
        self._page_request = 0

        # The repaint loop's timers, in the order they run on a timeout wake.
        # Each row's callables are methods of this display, so they look up the
        # lock and the collaborators when called.
        self._timers = (
            _Timer("secondary_timeout", _no_deadline, self._check_secondary_timeout),
            _Timer("repeat_line", self._repeat_line_deadline, self._repeat_line_fire),
            _Timer("controls_hidden", self._controls_hidden_deadline, self._controls_hidden_fire),
            _Timer("controls_shown", self._controls_shown_deadline, self._controls_shown_fire),
            _Timer("wifi_flash", self._wifi_flash_deadline, self._wifi_flashing),
            _Timer("due_status", _no_deadline, self._request_due_status),
            _Timer("reveal", self._reveal_deadline, self._reveal_fire),
            # Last: its deadline drops a timer that has run out.
            _Timer("replay_timer", self._replay_timer_next, self._replay_timer_fire),
        )

    # ---------------------------------------------------------------------------
    # 2. Lifecycle and HTTP facade
    #
    # Thread: main, HTTP (these take self._lock).
    # Owns: _config, _layout, _mm_per_px, _subscription, _repaint_thread, _get_info_rows
    # ---------------------------------------------------------------------------

    def start(self) -> None:
        with self._lock:
            if self._config.fitted:
                self._enable_locked()
        self._repaint_stop_event.clear()
        if self._subscription is None:
            self._subscription = self._core.subscribe(self._core_changed)
        try:
            self._repaint_thread = threading.Thread(
                target=self._repaint_run, daemon=True, name="dial-display-repaint",
            )
            self._repaint_thread.start()
        except Exception as e:
            logging.warning("dial display: failed to start repaint thread: %s", e)
            self._repaint_thread = None
        # Fold in whatever the core has published already.
        self._overlay_signal.poke()

    def stop(self) -> None:
        self._repaint_stop_event.set()
        # Wake the repaint thread out of its Event.wait() so it notices
        # _repaint_stop_event promptly rather than at its next timeout tick.
        self._overlay_signal.set()
        if self._subscription is not None:
            self._core.unsubscribe(self._subscription)
            self._subscription = None
        if self._repaint_thread is not None:
            try:
                self._repaint_thread.join(timeout=2)
            except RuntimeError:
                pass
        with self._lock:
            self._disable_locked()

    def get_status(self) -> dict:
        with self._lock:
            if self._idle_started_at is None:
                idle_seconds = 0
            else:
                idle_seconds = min(
                    DISPLAY_IDLE_SLEEP_SECONDS,
                    int(time.monotonic() - self._idle_started_at),
                )
            return DisplayRuntimeStatus(
                fitted=self._config.fitted,
                rotate=self._config.rotate,
                # The ACTIVE profile, not the configured one: after a failed
                # swap the configured key is the one that would not open, so
                # reporting it here would hide exactly the drift this field
                # exists to expose. Empty while no backend is open.
                screen_type=self._active_screen_type,
                bgr=self._config.bgr,
                always_show_controls=self._config.always_show_controls,
                active=self._backend_open and self._backend_name != "noop",
                backend=self._backend_name,
                backend_loaded=self._backend_loaded,
                showing=self._showing,
                last_error=self._last_error,
                last_error_at=self._last_error_at,
                display_sleeping=self._display_sleeping,
                display_idle_seconds=idle_seconds,
            ).to_dict()

    def latest_frame_png(self) -> bytes | None:
        """The frame most recently pushed to the panel, PNG-encoded as the
        viewer sees it (rotation and colour-order undone), or None when no
        frame is on the panel (never enabled, cleared, asleep). Takes
        self._lock only to snapshot the reference and the two orientation
        flags; the encode runs outside every lock. Never raises."""
        with self._lock:
            frame = self._last_frame
            rotate, bgr = self._config.rotate, self._config.bgr
        if frame is None:
            return None
        try:
            frame = _unfinish(frame, rotate, bgr)
            buf = io.BytesIO()
            frame.save(buf, format="PNG", compress_level=6)
            return buf.getvalue()
        except Exception as e:
            logging.debug("dial display: screenshot encode failed: %s", e)
            return None

    def update_config(self, config) -> dict:
        with self._lock:
            old_config = self._config
            self._config = config
            self._layout = layout_context_for(config)
            self._mm_per_px = self._layout.mm_per_px
            screen_type_changed = old_config.screen_type != config.screen_type
            # A screen_type change already drops every cache via the swap
            # branch below; screen_size_inches alone changes only density,
            # not the logical size, and the existing redisplay_changed path
            # re-pushes the still-valid cached frame for it. So this is
            # narrowed to layout_size alone — the one field that can change
            # what size every cached frame and list/zone layout was built
            # at without also being caught by one of those two paths.
            layout_changed = old_config.layout_size != config.layout_size
            if screen_type_changed:
                # Rebuild unconditionally, NOT only when fitted: a screen_type
                # change accepted while the display is off must still be in
                # force when it is later switched on. Rebuilding only under
                # `fitted` leaves the stale factory in place, and the later
                # enable sees no screen_type change to react to — so it would
                # silently open the previous profile while status and disk
                # both report the new one.
                self._rebuild_backend_factory_locked(config.screen_type)
            if config.fitted:
                if screen_type_changed and self._backend_open:
                    # Swap branch takes precedence over the rotate/bgr
                    # redisplay branch below — for this same update_config()
                    # call the two are mutually exclusive. Redisplaying a
                    # cached frame composed at the OLD backend's dimensions
                    # against the new backend would push a wrong-size frame
                    # (the backend would silently letterbox it), so the swap
                    # clears the cache instead and lets the next poll (or the
                    # logo render below) recompose at the new dims.
                    self._swap_backend_locked()
                else:
                    self._enable_locked()
                    # _enable_locked() is a no-op when the backend is already
                    # open, so a rotate/bgr/always_show_controls-only toggle
                    # needs its own path here — re-display the current frame
                    # under the new settings immediately rather than waiting
                    # for the next poll. Never runs alongside a screen_type
                    # change (see the swap branch above).
                    if layout_changed and self._backend_open and old_config.fitted:
                        # The logical size or density changed under the open
                        # backend: every cached frame was composed at the old
                        # size, and every list page and zone was laid out in
                        # it. Drop the caches, pop to main, show the logo at
                        # the new size at once, and let the next poll refetch
                        # artwork at that size.
                        self._source_artwork_key = ""
                        self._current_rendered_image = None
                        self._current_base_image = None
                        self._close_secondary_locked()
                        self._render_logo_locked()
                        self._core.request_fold()
                    else:
                        redisplay_changed = (
                            old_config.fitted and not screen_type_changed
                            and (
                                old_config.rotate != config.rotate
                                or old_config.bgr != config.bgr
                                or old_config.always_show_controls != config.always_show_controls
                                or old_config.screen_size_inches != config.screen_size_inches
                            )
                        )
                        if redisplay_changed and self._backend_open:
                            self._redisplay_current_locked()
            else:
                self._disable_locked()
        return self.get_status()

    def enable(self) -> None:
        with self._lock:
            self._enable_locked()

    def disable(self) -> None:
        with self._lock:
            self._disable_locked()

    def clear(self) -> None:
        with self._lock:
            self._clear_locked()

    def show_logo(self) -> None:
        with self._lock:
            if not (self._backend_open and self._backend is not None):
                return
            if self._showing == "logo":
                return
            self._render_logo_locked()

    def show_starting(self) -> None:
        """Paint the boot splash ("Starting...") as the panel's very first
        frame. Called once by dial_main before any display thread exists:
        opens the backend if it is not open yet (the same single backend
        start() would otherwise open — start()'s own open is then a no-op)
        without the usual logo first frame, and pushes the splash. The
        first poll replaces it: show_logo()/_show_artwork dedupe on
        "logo"/"artwork" and this marks self._showing "starting", so
        neither mistakes the splash for already showing something. A
        repaint tick before that first poll leaves it alone because no base
        image exists yet. Unfitted: a no-op. A failed backend open degrades
        exactly as start() does (backend_open_failed recorded, no-op
        display). Never raises."""
        with self._lock:
            try:
                if not self._config.fitted:
                    return
                if not self._backend_open:
                    self._enable_locked(render_logo=False)
                if not (self._backend_open and self._backend is not None):
                    return
                self._display_starting_locked()
            except Exception:
                logging.warning("dial display: boot splash failed", exc_info=True)

    def display(self, image) -> None:
        with self._lock:
            self._display_locked(image)

    def set_info_provider(self, fn) -> None:
        """Startup wiring (dial_main.py, after the HTTP server exists): a
        zero-arg callable returning an iterable of (label, value) pairs —
        dial_info.gather_dial_info, bound to this dial's own name/version.
        Plain attribute write."""
        self._get_info_rows = fn

    @property
    def core(self) -> DialCore:
        """The appliance model this view paints."""
        return self._core

    def fold_for_tests(self) -> None:
        """Test hook: fold the appliances once on this thread and fold the
        result into the screen: the core's fold, then the snapshot it ends
        in. The core's own thread and the repaint thread do the same in
        production; this is the entry for a caller that has neither running."""
        self._core.fold_once()
        self._apply_pending_snapshot()

    # ---------------------------------------------------------------------------
    # 3. Touch-thread entries
    #
    # Thread: touch.
    # Owns: _screen_request, _page_request, _touch_activity_pending, _pressed, _repeat_close_reveal,
    #        _info_value_hint(_over), _info_value_index, _output_open_id, _warnings_next, _info_gather_seq,
    #        _overlay_snapshot (leaf lock)
    #
    # The rule: an entry writes plain fields and signals the repaint thread. It never takes
    # self._lock and does no I/O, because the lock can be held across a whole SPI push and a touch
    # must never wait behind one. The repaint thread folds the requests in under the lock
    # (section 5). Calls into the core go to its own request lane.
    #
    # Exceptions, each noted where it is defined: _gather_info runs on its own worker thread (and
    # takes the lock briefly), and open_info starts it.
    # ---------------------------------------------------------------------------

    def notify_touch_activity(self) -> None:
        """Tell the display that touch activity happened right now.

        Does what a snapshot with a visible playing appliance does (see _apply_snapshot): resets the
        idle countdown and, if asleep, wakes. It resets idle, it does not disable sleep: with
        nothing playing the next fold restarts the countdown, so a user who keeps touching for
        longer than DISPLAY_IDLE_SLEEP_SECONDS still sees the panel sleep.

        Takes NO lock: this runs on the touch thread, which must never block on self._lock (it can
        be held across a whole SPI push). The idle reset and wake are applied by the repaint thread
        (_apply_touch_activity_locked). Also reopens the compact tier's controls window
        (ControlsReveal.show_compact()), a plain float write that nothing reads on other tiers."""
        self._touch_activity_pending = True
        self._controls.show_compact(time.monotonic())
        self._overlay_signal.set()

    def is_sleeping(self) -> bool:
        """True while the panel is asleep. Takes NO lock: a plain attribute
        read for the touch thread, which must never block on self._lock. A
        stale read costs at most one harmless extra tick."""
        return self._display_sleeping

    def set_overlay(self, state: OverlayState) -> None:
        """Publish a new touch-overlay snapshot and signal the repaint thread to recompose and push
        it.

        Never touches self._lock (see LOCK ORDER in __init__): the write is one leaf-lock-guarded
        assignment at touch cadence, and the compose and SPI push happen later on the repaint
        thread. A visible overlay ends an artwork-tap hide window early (hide_controls()) and opens
        the compact tier's controls window (ControlsReveal.show_compact()), both plain float writes.
        It leaves any reveal slide alone: the repaint that finds the controls back turns a running
        slide-out around, or starts the slide-in (ControlsReveal.advance())."""
        if state.visible:
            self._controls.end_hide()
            self._controls.show_compact(time.monotonic())
        with self._overlay_snapshot_lock:
            self._overlay_snapshot = state
        self._overlay_signal.set()

    def persistent_overlay_shown(self) -> bool:
        """True while the display holds the controls overlay visible on its own: the held-overlay
        predicate (_held_overlay()), the backend open and the main screen showing. Plain attribute
        reads. The touch side reads it through touch_surface() once per loop, so a finger never arms
        against controls that are not drawn; when it turns False (idle, asleep, the setting off, a
        list open, an artwork-tap hide window) the touch side drops back to reveal-on-touch within
        one loop tick.

        The compact tier ignores always_show_controls: its controls show for a few seconds after a
        touch and then fade to bare artwork (_compact_controls_hidden()). The self._showing !=
        "noop" term covers the moment right after the panel is cleared, when the snapshot's
        now_playing may still be set but nothing is on screen."""
        return (
            self._held_overlay(time.monotonic())
            and self._backend_open
            and self._screen == "main"
        )

    def touch_surface(self) -> SurfaceState:
        """(surface, name_active, dots_active, outputs_active, bell_active) for
        dial_touch.TouchStateMachine.set_surface(), polled once per touch loop by TouchEventSource.
        Plain reads only, the same discipline as persistent_overlay_shown() and
        noncomposited_generation().

        name_active: a controllable appliance is shown (the snapshot carries a now_playing),
        whatever the number of authorised appliances. outputs_active: that appliance advertises
        dial_outputs. dots_active: it has an available repeat record. bell_active: the screen draws
        a bell with something to show. "idle" is reported whenever nothing is playing, so the corner
        glyphs are reachable on every idle dial; only the idle affordance decides whether
        IDLE_REPLAY acts. While the bands slide back in the surface is already the ordinary one, so
        a tap acts on a band as it arrives.

        A secondary screen's tuple is fixed by its policy row (ScreenPolicy.surface); a row that
        asks for the outputs zone still gates it on the snapshot's outputs_available. A row with
        ScreenPolicy.replay_surface reports that tuple exactly while the compact tier's replaying
        layout is painted (self._repeat_layout_shown == "replaying").

        Two overrides come first. On the compact tier, once the controls window has lapsed
        (_compact_controls_hidden()), main and repeat report plain "hidden". The repeat screen's
        artwork-tap hide window reports "hidden" too, keeping the name, dots and outputs
        addressable: nothing is drawn to tap, so a touch brings the controls back and never actuates
        Restart, Stop or the dots."""
        snap = self._core.snapshot()
        if self._compact_controls_hidden() and self._screen in ("main", "repeat"):
            # (The corner bell is drawn only over playing artwork.)
            return SurfaceState(SURFACE_HIDDEN, False, False, False, (
                self._screen == "main" and snap.now_playing is not None and self._bell(snap).count > 0))
        if self._screen == "repeat" and self._controls.hidden(time.monotonic()):
            return SurfaceState(SURFACE_HIDDEN, True, snap.dots_active, snap.outputs_available, False)
        if self._screen == "warnings":
            # The card's surface is the one for its button count.
            card = self._warnings_card(self._bell(snap))[1]
            return SurfaceState(_card_surface(len(card.buttons) if card is not None else 1), False, False, False, False)
        policy = _policy(self._screen)
        if policy.surface is not None:
            if (
                policy.replay_surface is not None
                and self._compact_tier()
                and self._repeat_layout_shown == "replaying"
            ):
                s = policy.replay_surface
            else:
                s = policy.surface
            # The top band's bell is live on the screens that share it.
            bell = self._screen in ("repeat", "eq") and self._bell(snap).count > 0
            return SurfaceState(s[0], s[1], s[2], s[3] and snap.outputs_available, bell)
        bell = self._bell(snap).count > 0
        if snap.now_playing is None:
            return SurfaceState(SURFACE_IDLE, False, False, False, bell)
        name_active = True
        dots_active = snap.dots_active
        outputs_active = snap.outputs_available
        if self.persistent_overlay_shown():
            return SurfaceState(SURFACE_HELD, name_active, dots_active, outputs_active, bell)
        return SurfaceState(SURFACE_HIDDEN, name_active, dots_active, outputs_active, bell)

    def noncomposited_generation(self) -> int:
        """Current non-composited-state generation, bumped by _mark_noncomposited_locked() whenever
        the display clears or sleeps. The touch side polls it once per loop and, on a change, drops
        whatever overlay or zone geometry it relied on. A plain int read, no lock."""
        return self._noncomposited_generation

    def consume_repeat_close_reveal(self) -> bool:
        """Touch-thread-only read-and-clear of the one-shot flag cycle_pages() sets when a page
        closes via a DOTS tap. Setter and getter both run on the touch thread, so no lock is needed."""
        value = self._repeat_close_reveal
        self._repeat_close_reveal = False
        return value

    def hide_controls(self) -> None:
        """Touch-thread entry (an ARTWORK tap on the now-playing screen, or on the replay screen's
        artwork while a replay runs): hide the top and bottom bands for CONTROLS_HIDE_SECONDS. A
        plain float write plus a repaint signal.

        While the window holds, the overlay is not drawn whatever the touch snapshot says,
        persistent_overlay_shown() reads False and touch_surface() reports "hidden". A reveal tap
        ends the window early (set_overlay()); the loop wakes on its expiry (the controls_hidden
        timer). On the rich and large tiers the bands slide off and back (ControlsReveal.advance());
        the slide belongs to the painters and nothing is stamped here.

        A no-op off the two screens with artwork to reveal (main, and the replay screen exactly
        while a replay runs) and on the compact tier, which has no artwork zone to tap."""
        screen = self._screen
        if screen == "repeat":
            if not self._repeat_replaying_lockfree():
                return
        elif screen != "main":
            return
        if self._compact_tier():
            return
        self._controls.hide(time.monotonic())
        self._overlay_signal.set()

    def open_selector(self) -> None:
        """Touch-thread entry (dial_touch_wiring's on_zone_tap, for a NAME tap)."""
        self._screen_request = "selector"
        self._overlay_signal.set()

    def close_list(self) -> None:
        """Touch-thread entry (dial_touch_wiring's on_zone_tap, for a LIST_BACK
        tap): pop back from whichever list-chassis screen is open — to its
        policy row's back_to, or for the outputs list to the main page it
        was opened from (see _back_target())."""
        self._request_back(self._screen)

    def list_page(self, delta: int) -> None:
        """Touch-thread entry (dial_touch_wiring's on_zone_tap, for a LIST_DOWN/
        LIST_UP tap): +1 for the next page, -1 for the previous, on
        whichever list-chassis screen is open. Clamped to the valid range
        by _apply_screen_requests_locked()."""
        self._page_request += delta
        self._overlay_signal.set()

    def selector_pick(self, index: int) -> None:
        """Touch-thread entry: a LIST_ROW tap while the appliance selector is open.

        Reads the last-published ListScreenState (a plain reference read, no lock). When *index* is
        within the current page, sets manual focus to that row's appliance, playing or idle. A row
        the appliance refused, or that needs an update, sets a hint instead and leaves the selector
        open beneath it. A stale index (the row vanished between paint and tap) is treated as back:
        no focus change, no error. Either way the selector closes unless a hint is shown."""
        selector = self._selector
        if selector is not None and selector.rows:
            page_rows = self._current_page_rows(selector)
            if 0 <= index < len(page_rows):
                row = page_rows[index]
                if row.needs_update or not row.authorized:
                    # An appliance that refused this dial, or runs another
                    # protocol, cannot be controlled: no focus change, and
                    # the selector stays open underneath a short hint whose
                    # back returns here.
                    self._info_value_hint = (
                        needs_update_hint(row.label) if row.needs_update
                        else unauthorised_hint(row.label))
                    self._screen_request = "info_value"
                    self._overlay_signal.set()
                    return
                if self._core.set_focus(row.appliance_id).reason == "unauthorized":
                    # The core knows something newer than the row: the
                    # appliance has refused this dial since the page was built.
                    self._info_value_hint = unauthorised_hint(row.label)
                    self._screen_request = "info_value"
                    self._overlay_signal.set()
                    return
        self.close_list()

    def list_row_tap(self, index: int) -> None:
        """Touch-thread entry (a LIST_ROW tap): routes to whichever list screen is open: the
        appliance selector (selector_pick), the replay picker (picker_pick), the outputs list
        (outputs_row_tap) or, on the compact tier only, the info page (info_row_tap). Off compact
        the info page's rows have no LIST_ROW geometry, so this is a no-op there."""
        if self._screen == "info":
            if self._compact_tier():
                self.info_row_tap(index)
            return
        if self._screen == "picker":
            self.picker_pick(index)
        elif self._screen == "outputs":
            self.outputs_row_tap(index)
        else:
            self.selector_pick(index)

    def info_row_tap(self, index: int) -> None:
        """Touch-thread entry (a LIST_ROW tap on the compact info list): remember the tapped field's
        absolute position in InfoState.rows and request the value view, the outputs_row_tap() shape.
        A stale index is ignored and the list stays open: closing would pop past the list, since the
        info page has nothing to fall back to but main. Plain reads and writes, no lock, no I/O."""
        state = self._info
        if state is None or not state.rows:
            return
        page_rows = self._current_page_rows(state)
        if 0 <= index < len(page_rows):
            self._info_value_index = state.page * self._rows_per_page() + index
            self._screen_request = "info_value"
            self._overlay_signal.set()

    def cycle_pages(self) -> None:
        """Touch-thread entry (a DOTS tap): advance to the next available page, main -> repeat -> eq
        -> main, wrapping and skipping a page with nothing to show, so a dot never means two
        different pages.

        A true no-op (self._screen_request untouched) when starting from main, or from a screen
        outside the three-page set, and nothing is available to open. Leaving repeat or eq for main
        always fires, and arms self._repeat_close_reveal when the screen just left has
        close_reveals_overlay: the one-shot flag TouchEventSource._poll_surface() consumes to bring
        main back showing its volume overlay (dial_touch.TouchStateMachine.force_overlay_visible())."""
        current = self._screen if self._screen in _PAGE_ORDER else "main"
        leaving_page = current != "main"
        i = _PAGE_ORDER.index(current)
        for step in range(1, len(_PAGE_ORDER) + 1):
            candidate = _PAGE_ORDER[(i + step) % len(_PAGE_ORDER)]
            if candidate == "repeat" and self._repeat_page_available():
                self._screen_request = "repeat"
                self._overlay_signal.set()
                return
            if candidate == "eq" and self._core.snapshot().eq_available:
                if self._capable_target_lockfree("dial_eq") is not None:
                    self._screen_request = "eq"
                    self._overlay_signal.set()
                    return
            if candidate == "main":
                if leaving_page:
                    if _policy(self._screen).close_reveals_overlay:
                        self._repeat_close_reveal = True
                    self._screen_request = "main"
                    self._overlay_signal.set()
                return

    def repeat_toggle_tap(self) -> None:
        """Touch-thread entry (dial_touch_wiring's on_zone_tap, for a REPEAT_PLAY
        tap): toggle arm/disarm — only meaningful in the enable layout
        (a live source recording/pending, or idle with the daemon still
        enabled); a tap here while the replaying/hold layout is showing
        (no "Repeat Play" row drawn) is a no-op. Enqueues on the core's
        request lane — no lock, no I/O on this thread."""
        found = self._repeat_tap_record()
        if found is None:
            return
        screen, rec = found
        if rec.state in ("recording", "pending", "idle"):
            self._core.set_repeat_armed(screen.appliance_id, not rec.armed)
        elif rec.state == "replaying":
            # In the replaying layout this row is the position line over
            # the artwork, not a toggle: a tap on it is an artwork tap.
            self.hide_controls()

    def repeat_start_tap(self) -> None:
        """Touch-thread entry (dial_touch_wiring's on_zone_tap, for a REPEAT_START
        tap): seek to 0 — restart a running replay, or start one from
        Hold. A no-op while fading out (the appliance would refuse it with
        "fading_out" anyway) or while a live source is recording."""
        found = self._repeat_tap_record()
        if found is None:
            return
        screen, rec = found
        if rec.state in ("replaying", "hold"):
            self._core.restart_replay(screen.appliance_id)

    def repeat_stop_tap(self) -> None:
        """Touch-thread entry (dial_touch_wiring's on_zone_tap, for a REPEAT_STOP
        tap): stop a running replay (fades out, lands in Hold, disarmed).
        A no-op outside Replaying — while fading out the button is drawn
        pressed and inert, and in Hold there is nothing to stop."""
        found = self._repeat_tap_record()
        if found is None:
            return
        screen, rec = found
        if rec.state == "replaying":
            self._core.stop_replay(screen.appliance_id)

    def set_pressed(self, zone, index=None) -> None:
        """Touch-thread entry: record the zone (and, for LIST_ROW, the row
        index) currently pressed on whatever screen is showing, or None
        when nothing is. One channel for every screen: each frame builder
        resolves it against its own surface geometry at compose time, so a
        zone that does not exist on the current screen simply draws
        nothing. Lock-free: a single reference assignment plus a repaint
        signal, same discipline as notify_touch_activity()."""
        self._pressed = (zone, index) if zone is not None else None
        self._overlay_signal.set()

    def pop_secondary(self, screen: str) -> None:
        """Touch-thread entry: pop back to main if *screen* is the one
        currently open — used by the encoder and button paths so a
        physical nudge while the repeat screen is open returns to the
        volume readout on main. Lock-free request, exactly like
        close_list()."""
        if self._screen == screen:
            self._request_back(screen)

    def on_input(self, kind: str) -> None:
        """A physical input ("volume" for the encoder, "mute" for the
        button) was used. While the repeat screen is open it returns to the
        volume readout on main. Lock-free."""
        self.pop_secondary("repeat")

    def open_picker(self) -> None:
        """Touch-thread entry (dial_touch_wiring's on_zone_tap, for an IDLE_REPLAY
        tap). Refuses (plain bool read, no lock) when no replay is actually
        held — the corner glyphs are reachable on every idle dial (see
        _idle_chassis_due_locked), but a replay tap on a plain logo stays
        inert."""
        if not self._core.snapshot().idle_affordance:
            return
        self._screen_request = "picker"
        self._overlay_signal.set()

    def picker_pick(self, index: int) -> None:
        """Touch-thread entry: start replaying the tapped row's held
        recording from the beginning. A stale index (the row vanished
        between paint and tap) is treated as back, same as
        selector_pick(). The core sets a PENDING manual focus so the
        screen follows the appliance through the gap before its replay
        reaches the playing set; a rejected seek (source_active/
        no_recording, or any transport failure) clears it again when the
        core folds the reply."""
        picker = self._picker
        if picker is not None and picker.rows:
            page_rows = self._current_page_rows(picker)
            if 0 <= index < len(page_rows):
                row = page_rows[index]
                # Armed before the request goes, so a rejection the worker
                # reports at once finds the timer to drop.
                self._repeat_line.arm(row.appliance_id, time.monotonic())
                if not self._core.start_replay(row.appliance_id).accepted:
                    self._repeat_line.arm(None, time.monotonic())
        self.close_list()

    def open_info(self) -> None:
        """Touch-thread entry (the idle screen's IDLE_WIFI tap). Requests the info page and starts
        one bounded gather on its own daemon thread; the page paints at once with placeholder "-"
        values (_open_info_locked) and fills in when the gather lands (_gather_info()). Touches no
        lock and does no I/O itself: two plain writes, a signal and a thread start."""
        self._info_gather_seq += 1
        seq = self._info_gather_seq
        self._screen_request = "info"
        self._overlay_signal.set()
        threading.Thread(target=self._gather_info, args=(seq,), daemon=True, name="dial-info").start()

    def open_outputs(self) -> None:
        """Touch-thread entry (dial_touch_wiring's on_zone_tap, for an OUTPUTS
        tap): request the outputs list, which the core always holds for the
        focused appliance. Lock-free, like open_selector(); refuses (no
        request at all) when there is no focused/reporting appliance
        advertising the capability."""
        if self._capable_target_lockfree("dial_outputs") is None:
            return
        self._screen_request = "outputs"
        self._overlay_signal.set()

    def outputs_row_tap(self, index: int) -> None:
        """Touch-thread entry (a LIST_ROW tap while the outputs list is
        open): remember the tapped row's output id and request the detail
        page. A stale index (the row vanished between paint and tap) is
        treated as back, same as selector_pick()/picker_pick()."""
        state = self._outputs
        if state is not None and self._rows_of(state):
            page_rows = self._current_page_rows(state)
            if 0 <= index < len(page_rows):
                self._output_open_id = page_rows[index].id
                self._screen_request = "output"
                self._overlay_signal.set()
                return
        self.close_list()

    def output_toggle_tap(self) -> None:
        """Touch-thread entry (OUTPUT_TOGGLE): enable this output at the
        appliance's own configured default volume (the dial sends no
        volume; see send_dial_outputs_set_post_json), or disable it,
        through the core's request lane. Shows the change at once via an
        optimistic override, held until the appliance's state catches up."""
        row = self._detail_row_lockfree()
        state = self._outputs
        if row is None or state is None:
            return
        if not row.selected and row.needs_auth_key:
            # Known to need pairing, which only the appliance's web UI can
            # do: say so rather than send a request that will be refused.
            self._show_pairing_hint(state)
            return
        if self._core.set_output(state.appliance_id, row.id, selected=not row.selected).accepted:
            self._overlay_signal.set()

    def output_volume_tap(self, delta: int) -> None:
        """Touch-thread entry (OUTPUT_UP/OUTPUT_DOWN, repeating): absolute
        volume = clamp(shown level + delta) for this output only — the
        appliance has no per-output delta API, only an absolute
        apply_output_mutation. A disabled output ignores the steppers (no
        level to step from)."""
        row = self._detail_row_lockfree()
        state = self._outputs
        if row is None or state is None:
            return
        if self._core.step_output_volume(state.appliance_id, row.id, delta).accepted:
            self._overlay_signal.set()

    def eq_step(self, control: str, delta: int) -> None:
        """Touch-thread entry (an EQ_BASS_* / EQ_TREBLE_* tap, repeating): absolute clamp(shown +
        delta, -6, +6) for *control* ("bass" or "treble"), the shape of output_volume_tap(); the
        appliance clamps again. The optimistic override shows at once and the worker's
        fetch-after-set reconciles it. A no-op when the EQ page is not open."""
        state = self._eq
        if state is None:
            return
        self._core.step_eq(state.appliance_id, control, delta)
        self._overlay_signal.set()

    def open_warnings(self) -> None:
        """Touch-thread entry (dial_touch_wiring's on_zone_tap, for a bell tap):
        request the warnings card. Two plain writes and a repaint signal."""
        self._screen_request = "warnings"
        self._overlay_signal.set()

    def card_button_tap(self, zone: "TouchZone") -> None:
        """Touch-thread entry (dial_touch_wiring's on_zone_tap, for a card's button
        zones): run the action of the cell tapped on the card the finger
        saw. A tap on a card that has closed, or whose entry has moved on,
        runs nothing. Plain writes plus a repaint signal; no lock, no I/O on
        this thread."""
        cell = CARD_BUTTON_ZONES.index(zone)
        if self._screen == "warnings":
            page = self._warnings_page
            action = page.action_at(cell, self._bell()) if page is not None else None
            status_id = ""
        else:
            card = self._status_card()
            action = card.buttons[cell][1] if card is not None and cell < len(card.buttons) else None
            status_id = card.status_id if card is not None else ""
        if action == ACTION_NEXT:
            self._warnings_next = True
        elif action == ACTION_CLOSE:
            # A status ends in the core; a warning is only put away here
            # (the bell keeps counting it).
            if status_id:
                self._core.close_status(status_id)
            self._screen_request = "main"
        elif action == ACTION_RESTART:
            # Show "Restarting..." at once, then ask for the reboot.
            # request_reboot() does its I/O on its own short-lived thread
            # and is rate-gated, so a second tap inside the cooldown only
            # re-shows the screen. Never raises.
            self._screen_request = "restarting"
            self._core.request_dial_reboot()
        else:
            return
        self._overlay_signal.set()

    # ---- lock-free helpers: plain reads and a request write, from the touch thread ----

    def _back_target(self, screen: str) -> str:
        """Where a back/close from *screen* goes: the outputs list returns
        to the main page that opened it (self._outputs_return, recorded by
        _open_outputs_locked()); every other screen to its policy row's
        back_to. Lock-free plain reads."""
        if screen == "outputs":
            return self._outputs_return
        if screen == "info_value":
            view = self._info_value
            if view is not None and view.hint is not None:
                return self._info_value_return
        return _policy(screen).back_to

    def _request_back(self, screen: str) -> None:
        """Lock-free request to leave *screen* for _back_target(screen)."""
        target = self._back_target(screen)
        self._screen_request = target
        self._overlay_signal.set()

    def _rows_per_page(self) -> int:
        """Rows per list page for the active screen: the density-aware count the repaint thread
        paints with (_layout_metrics()), so the touch-thread page slice and the painted page agree.
        Safe with or without self._lock."""
        return self._layout_metrics().rows_per_page

    def _rows_of(self, state) -> tuple:
        """Every row of a list screen's *state*: its own for the selector, picker and info pages,
        the core's last fetched outputs (less those another appliance has taken) for the outputs
        list. Only the outputs list holds an ApplianceScreenState."""
        if isinstance(state, ApplianceScreenState):
            held = held_outputs(self._core.snapshot(), state)
            return offerable(held.rows) if held is not None else ()
        return state.rows

    def _current_page_rows(self, state) -> tuple:
        """The current page's slice of *state*'s rows (_rows_of()), for a ListScreenState, InfoState
        or ApplianceScreenState. Shared by the lock-free touch pick entries and the repaint-thread
        list builders so both agree on which rows are on screen. Takes no lock and writes nothing."""
        _, page_rows = page_slice(self._rows_of(state), state.page, self._rows_per_page())
        return page_rows

    def _repeat_page_available(self) -> bool:
        """Whether the repeat page has anything to show: a controllable appliance (the snapshot
        carries a now_playing) whose focused/reporting id has an available repeat record. Plain
        reads of the newest snapshot."""
        snap = self._core.snapshot()
        if snap.now_playing is None:
            return False
        appliance_id = snap.focused_id()
        if not appliance_id:
            return False
        rec = self._repeat_record(appliance_id)
        return rec is not None and rec.available

    def _repeat_record(self, appliance_id: "str | None"):
        """The repeat record of *appliance_id* as the core last folded it,
        or None. A plain read of the published snapshot."""
        entry = self._core.snapshot().appliance(appliance_id) if appliance_id else None
        return entry.repeat if entry is not None else None

    def _repeat_replaying_lockfree(self) -> bool:
        """True while the repeat screen's own appliance is replaying right
        now, read the way repeat_stop_tap() reads it (plain reference of
        self._repeat_screen, the core's published snapshot): the only repeat
        layout with artwork behind its controls to reveal."""
        screen = self._repeat_screen
        if screen is None:
            return False
        rec = self._repeat_record(screen.appliance_id)
        return rec is not None and rec.available and rec.state == "replaying"

    def _repeat_tap_record(self) -> "tuple[ApplianceScreenState, object] | None":
        """The open repeat page and the repeat-store record of its
        appliance, or None when the page is not open or the record is
        absent or unavailable. Lock-free."""
        screen = self._repeat_screen
        if screen is None:
            return None
        rec = self._repeat_record(screen.appliance_id)
        if rec is None or not rec.available:
            return None
        return screen, rec

    def _focused_entry(self, snap):
        """The roster entry of the focused/reporting appliance in *snap*, or
        None when nothing is focused or it has dropped out of the roster.
        Plain reads."""
        appliance_id = snap.focused_id()
        return snap.appliance(appliance_id) if appliance_id else None

    def _capable_target_lockfree(self, capability: str):
        """The appliance entry the outputs or EQ screens act on: the focused/
        reporting appliance when it advertises *capability* ("dial_outputs"
        or "dial_eq") and is not confirmed unauthorized; else None. Plain
        reads of the newest snapshot, like the core's focus_volume_target().
        The compact-tier veto on EQ lives in the snapshot's eq_available
        (computed once per poll tick), not here."""
        entry = self._focused_entry(self._core.snapshot())
        if entry is None or entry.auth == AUTH_UNAUTHORIZED or not getattr(entry, capability):
            return None
        return entry

    def _detail_row_lockfree(self) -> "OutputRow | None":
        """The output the detail page is open for, read from the core's last
        fetched outputs (not the optimistic override — see
        output_toggle_tap()/output_volume_tap()). Plain reads, same
        discipline as _capable_target_lockfree()."""
        detail, state = self._output_detail, self._outputs
        if detail is None or state is None:
            return None
        return next((r for r in self._rows_of(state) if r.id == detail.output_id), None)

    def _show_pairing_hint(self, state, over: tuple[str, ...] = _HINT_OVER_DEFAULT) -> None:
        """Ask for the pairing hint over the screens in *over* (by default
        the selector and a speaker's page). Lock-free."""
        self._info_value_hint = pairing_hint(appliance_display_name(state.service_name))
        self._info_value_hint_over = over
        self._screen_request = "info_value"
        self._overlay_signal.set()

    def _compact_tier(self) -> bool:
        """True while the resolved content tier is compact — the physically
        tiny 2x2 screens. Plain-arithmetic read, safe from any thread, same
        as _layout_metrics() itself."""
        return self._layout_metrics().content_tier == CONTENT_COMPACT

    def _slide_tier(self) -> bool:
        """Whether this panel animates the reveal: the tiers that draw
        bands the chrome can slide off. The base tier keeps its instant
        hide and show; the compact tier has no bands. Plain-arithmetic read, safe
        from any thread."""
        return self._layout_metrics().content_tier in (CONTENT_RICH, CONTENT_LARGE)

    def _layout_metrics(self) -> LayoutMetrics:
        """LayoutMetrics for the logical size and the density per logical pixel. Pure arithmetic on
        plain attribute reads, safe from any thread with or without self._lock. The touch thread's
        page slicing and the repaint thread's compose both read this, so they cannot disagree about
        rows per page."""
        width, height = self._logical_dims()
        return metrics_for(
            width, height, mm_per_px=self._mm_per_px, size_chosen=self._layout.size_chosen,
        )

    # ---- any thread, plain reads ----

    def _held_overlay(self, now: float) -> bool:
        """The held-visible predicate _effective_overlay_locked() applies: always-show on (off
        compact), or the compact tier's controls window open; a controllable appliance shown; the
        panel not cleared or asleep; and no artwork-tap hide window running. Plain reads, safe from
        any thread: the touch thread reaches it through persistent_overlay_shown()."""
        return (
            (
                (self._config.always_show_controls and not self._compact_tier())
                or (self._compact_tier() and not self._compact_controls_hidden())
            )
            and self._frame_controllable(self._core.snapshot())
            and not self._controls.hidden(now)
        )

    def _frame_controllable(self, snap) -> bool:
        """Whether a controllable appliance is on screen: the snapshot carries a now_playing, the
        panel is not cleared and it is not asleep. Plain reads, safe from any thread."""
        return (
            snap.now_playing is not None
            and self._showing != "noop"
            and not self._display_sleeping
        )

    def _compact_controls_hidden(self) -> bool:
        """Compact tier only: True once the controls window (ControlsReveal.show_compact()) has
        lapsed or was never opened. A freshly shown compact screen starts hidden (bare artwork);
        controls appear only after a touch or reveal. Always False off the compact tier. Plain
        reads."""
        return self._compact_tier() and self._controls.compact_hidden(time.monotonic())

    def _readout(self, service_name: str) -> "tuple[str, int | None]":
        """The top band's display-only readout for the appliance
        *service_name*: its display name and its shown volume."""
        return appliance_display_name(service_name), shown_volume(service_name)

    def _pressed_zone(self):
        """The zone the finger is down on, or None. The touch thread clears
        _pressed at any moment, so it is read once."""
        pressed = self._pressed
        return pressed[0] if pressed is not None else None

    # ---- worker thread (one per open_info call) ----

    def _gather_info(self, seq: int) -> None:
        """Worker thread (one per open_info() call, never the touch thread): call the injected
        provider and fold the result in under self._lock in one assignment, with no I/O while the
        lock is held. Never raises: a missing or failing provider yields the placeholder rows. Drops
        a stale result: the page closed and reopened (seq no longer matches) or closed outright
        (self._info is None)."""
        try:
            if self._get_info_rows is not None:
                rows = tuple(InfoRow(label=label, value=value) for label, value in self._get_info_rows())
            else:
                rows = INFO_PLACEHOLDER_ROWS
        except Exception:
            rows = INFO_PLACEHOLDER_ROWS
        with self._lock:
            state = self._info
            if state is None or seq != self._info_gather_seq:
                return
            self._info = dataclasses.replace(state, rows=rows)
        self._overlay_signal.set()

    # ---------------------------------------------------------------------------
    # 4. Repaint thread: loop and timers
    #
    # Thread: repaint.
    # Owns: _timers, _repaint_stop_event
    #
    # A dedicated thread, separate from the core's, so a touch-driven overlay update never waits
    # behind the fold cadence and never has to be dispatched from the touch thread itself. The timer
    # rows (deadline and fire methods) are lock-free: plain reads, and the one-shot clears noted on
    # each. The exception is _reveal_fire, which takes the lock for its compare-and-clear.
    # ---------------------------------------------------------------------------

    def _repaint_run(self) -> None:
        while not self._repaint_stop_event.is_set():
            # Wait no longer than the next moment something on screen must
            # change on its own (the replaying counter's next second, a
            # controls-hide window ending, the next frame of the artwork-tap
            # reveal), see _next_repaint_deadline().
            # Never longer than a second either way, so stop() and the
            # once-a-second housekeeping below are still noticed promptly
            # when nothing is scheduled.
            deadline = self._next_repaint_deadline()
            now = time.monotonic()
            timeout = 1.0 if deadline is None else clamp(deadline - now, 0.0, 1.0)
            signaled = self._overlay_signal.wait(timeout=timeout)
            if self._repaint_stop_event.is_set():
                break
            if not signaled:
                # Plain timeout — nothing to do beyond the timers' own
                # work, then go back to waiting. This periodic wake exists
                # only so stop() is noticed promptly even if no overlay
                # signal ever arrives.
                self._run_timers()
                continue
            self._repaint_once()

    def _repaint_once(self) -> None:
        """One wake of the repaint loop that something signalled."""
        # Coalesce: clear the event BEFORE doing any work. Any
        # set_overlay() call that lands after this clear() (including
        # one that lands while we are still repainting below, under
        # self._lock) leaves the event set again, so the next
        # iteration's wait() returns immediately — several rapid
        # signals that land before we get here collapse into this one
        # wake, and _display_locked() below always reads whatever the
        # NEWEST snapshot is at the moment it actually composes, not
        # whichever one triggered this particular wake.
        requested = self._overlay_signal.consume()
        # Fold in what the core has published. A wake that only the core
        # caused paints nothing unless that snapshot says something on
        # screen changed (the fold then paints, or asks for a repaint).
        self._apply_pending_snapshot()
        if not requested:
            return
        with self._lock:
            woke = self._repaint_current_locked()
        if woke:
            self._core.request_fold()

    def _run_timers(self) -> None:
        """The timeout branch: every timer's work, in row order, then one repaint request if any of
        them asked for one."""
        wake = False
        for timer in self._timers:
            if timer.fire():
                wake = True
        if wake:
            self._overlay_signal.set()

    def fire_timer_for_tests(self, name: str) -> None:
        """Test hook: run one timer's work, as the timeout branch does."""
        timer = {t.name: t for t in self._timers}[name]
        if timer.fire():
            self._overlay_signal.set()

    def _next_repaint_deadline(self) -> "float | None":
        """The earliest monotonic time something on screen must change on its own: the earliest
        deadline of the timers, in row order. None when nothing is scheduled, and the caller falls
        back to its own housekeeping cadence. Lock-free plain reads, the discipline
        _check_secondary_timeout() uses."""
        deadlines = []
        for timer in self._timers:
            due = timer.deadline()
            if due is not None:
                deadlines.append(due)
        return min(deadlines) if deadlines else None

    def _repeat_line_deadline(self) -> "float | None":
        """When the replaying counter next needs a paint: the repeat screen's line, while it is the
        screen showing. Lock-free plain reads of the core's published snapshot."""
        if self._screen == "repeat" and self._repeat_screen is not None:
            now = time.monotonic()
            return self._repeat_line.counter_due(self._repeat_record(self._repeat_screen.appliance_id), now)
        return None

    def _repeat_line_fire(self) -> bool:
        """Whether the repeat screen is due a recompose because the replaying counter's current
        second is not the one last painted. Due-ness is decided against the painted second, never
        against where in the second this wake landed, so a late wake or a status re-sync still
        paints the second owed, and a housekeeping wake with the painted second current forces no
        repaint. No HTTP call: the interpolation is local
        (dial_repeat_store.interpolated_position()) and the next fold corrects drift. False while
        the repeat screen is not showing."""
        if self._screen != "repeat":
            return False
        screen = self._repeat_screen
        if screen is None:
            return False
        now = time.monotonic()
        due = self._repeat_line.counter_due(self._repeat_record(screen.appliance_id), now)
        return due is not None and due <= now

    def _controls_hidden_deadline(self) -> "float | None":
        """When an artwork-tap hide window ends and the bands must come back."""
        return self._controls.hidden_deadline(time.monotonic())

    def _controls_hidden_fire(self) -> bool:
        """True exactly when an artwork-tap hide window (hide_controls()) has just ended, so the
        bands return without waiting for a touch or fold. One-shot: expire_hidden() resets the
        deadline to 0.0 (its "not hidden" value), so it does not re-signal every housekeeping tick.
        The repaint this wakes finds the controls back and starts the slide-in."""
        controls = self._controls
        return bool(controls.hidden_until and controls.expire_hidden(time.monotonic()))

    def _controls_shown_deadline(self) -> "float | None":
        """When a compact screen's own controls window ends and the bands
        must step aside."""
        return self._controls.shown_deadline(time.monotonic(), self._compact_tier())

    def _controls_shown_fire(self) -> bool:
        """True exactly when a compact screen's controls window (ControlsReveal.show_compact()) has
        just lapsed, so the bands step aside without waiting for a touch or fold. One-shot:
        expire_shown() resets the deadline to 0.0, the value _compact_controls_hidden() reads as
        hidden. False off the compact tier."""
        controls = self._controls
        return bool(controls.shown_until and controls.expire_shown(time.monotonic(), self._compact_tier()))

    def _wifi_flash_deadline(self) -> "float | None":
        """The idle screen's next flash boundary while it is flashing, so the
        repaint loop wakes onto it."""
        if not self._wifi_flashing():
            return None
        now = time.monotonic()
        half = WIFI_FLASH_HALF_PERIOD_S
        return (math.floor(now / half) + 1) * half + DEADLINE_PAD_S

    def _reveal_deadline(self) -> "float | None":
        """When the next frame of a reveal slide, or its settled frame, is due."""
        return self._controls.reveal_deadline(time.monotonic())

    def _reveal_fire(self) -> bool:
        """True while a reveal slide is running, and once more the moment it has ended, so the
        settled frame paints at once. The loop's wait has already been sized onto the next frame.
        One-shot at the end: the slide's start is cleared by a compare-and-clear under self._lock
        (the loop does not hold it at this point), which leaves a slide the painters stamped since
        the start was read."""
        controls = self._controls
        started = controls.started_at
        if not started:
            return False
        if controls.slide_over(started, time.monotonic()):
            with self._lock:
                controls.clear_slide_if(started)
        return True

    def _replay_timer_deadline(self, now: float) -> "float | None":
        """When the main page's replay timer line next needs a paint (_replay_timer_locked()), or
        None when no timer is on screen. Plain reads and lock-free plain writes, the same discipline
        as RepeatLine.arm(); reads the core's published snapshot."""
        if self._repeat_line.timer_id is None or self._screen != "main" or self._display_sleeping:
            return None
        return self._repeat_line.timer_deadline(now, self._repeat_record)

    def _replay_timer_next(self) -> "float | None":
        """The replay timer line's deadline at the current time."""
        return self._replay_timer_deadline(time.monotonic())

    def _replay_timer_fire(self) -> bool:
        """Whether the main page's replay timer line is due a repaint (see
        _replay_timer_deadline())."""
        now = time.monotonic()
        deadline = self._replay_timer_deadline(now)
        if deadline is not None and deadline <= now:
            self._repeat_line.timer_fired(now)
            return True
        return False

    # ---------------------------------------------------------------------------
    # 5. Repaint thread: request folding and openers
    #
    # Thread: repaint, HTTP (under self._lock).
    # Owns: _screen and every state attribute, _outputs_return, _info_value_return
    # ---------------------------------------------------------------------------

    def _apply_touch_activity_locked(self) -> bool:
        """Apply a pending touch-activity notification. Caller holds self._lock; runs on the repaint
        thread.

        Returns True when this call woke the display from sleep; the caller then asks the core for a
        fold (core.request_fold()) AFTER releasing self._lock."""
        if not self._touch_activity_pending:
            return False
        self._touch_activity_pending = False
        self._idle_started_at = None
        policy = _policy(self._screen)
        if policy.touch_extends_timeout:
            # Touch activity while this screen is open extends its own
            # inactivity timeout — see ScreenPolicy.touch_extends_timeout
            # and the _repaint_run timeout branch below.
            state = getattr(self, policy.state_attr)
            if state is not None:
                setattr(self, policy.state_attr, dataclasses.replace(state, opened_at=time.monotonic()))
        if self._display_sleeping:
            self._wake_locked()
            return True
        return False

    def _apply_screen_requests_locked(self) -> None:
        """Fold pending touch-thread requests (open_selector(), close_list(), list_page(),
        cycle_pages(), open_picker() and the rest) into self._screen and the per-screen state, via
        the screen policy table. The requested row's `open` decides whether the switch happens (it
        can refuse and leave the current screen showing); a switch clears the pressed channel; a
        pending page delta applies to the showing row when it is paged. Caller holds self._lock;
        runs on the repaint thread only."""
        previous_screen = self._screen
        request = self._screen_request
        self._screen_request = None
        delta = self._page_request
        self._page_request = 0
        if self._warnings_next:
            self._warnings_next = False
            if self._warnings_page is not None:
                self._warnings_page = self._warnings_page.stepped(self._bell())

        if request is not None:
            opened = _policy(request).open(self)
            if previous_screen in ("outputs", "output") and request in ("repeat", "eq"):
                # Back from the outputs screens to the page that opened
                # them. That page may have nothing left to show (the replay
                # was dropped, the EQ capability went away): fall back to
                # main rather than leave the list up. Either way the
                # outputs screens' own state goes with them.
                if opened:
                    self._outputs = None
                    self._output_detail = None
                    self._output_open_id = None
                else:
                    self._close_secondary_locked()

        if self._screen != previous_screen:
            # A press on a zone the new screen shares with the old one
            # (e.g. DOTS/NAME/MUTE, shared between the main and repeat
            # screens) must not carry its wash onto the screen it opens.
            self._pressed = None
            # A screen the user just opened (repeat) or was returned to
            # (main after DOTS, or after a stop — see _apply_repeat_outcome())
            # shows its own controls for a fresh window on the compact
            # tier; a no-op off it.
            self._controls.show_compact(time.monotonic())
            # A hide window and any reveal slide belong to the screen they
            # started on; a screen change abandons both rather than
            # resuming them later.
            self._controls.abandon()

        policy = _policy(self._screen)
        if delta and policy.paged:
            active = getattr(self, policy.state_attr)
            if active is not None:
                rows_per_page = self._rows_per_page()
                page_fn = wrap_page if self._compact_tier() else clamp_page
                new_page = page_fn(active.page + delta, len(self._rows_of(active)), rows_per_page)
                if new_page != active.page:
                    setattr(self, policy.state_attr, dataclasses.replace(active, page=new_page))

    def _check_secondary_timeout(self) -> None:
        """Close the screen showing after its own inactivity timeout
        (ScreenPolicy.inactivity_timeout_s; a screen with none is never closed from here). Runs as a
        timer row on the repaint thread's timeout wake, so it fires even when nothing signals a
        repaint.

        self._screen and the per-screen state are read lock-free: every write is under self._lock
        and a plain reference assignment, so a stale read costs at most one extra tick. The close
        itself is applied under the lock."""
        policy = _policy(self._screen)
        if policy.inactivity_timeout_s is None:
            return
        state = getattr(self, policy.state_attr)
        if state is None:
            return
        if time.monotonic() - state.opened_at >= policy.inactivity_timeout_s:
            if self._screen in ("outputs", "output") and self._outputs_return != "main":
                # Timing out of the outputs screens goes back to the main
                # page they were opened from, like closing the list does.
                if self._screen_request is None:
                    self._request_back("outputs")
                return
            with self._lock:
                self._close_secondary_locked()

    def _close_secondary_locked(self) -> None:
        """Pop to the main screen from any secondary screen. Caller holds self._lock. Called from
        request folding and the idle tick on the repaint thread, from sleep, disable and a backend
        swap (so a later wake never resumes on a stale secondary screen), when the focused appliance
        changes under a bound screen, and as the fallback for a stale selector_pick(), picker_pick()
        or outputs_row_tap() index.

        Every screen's state_attr is cleared from the policy table, so a screen added to the table
        is popped without a further edit."""
        self._screen = "main"
        for policy in SCREEN_POLICIES.values():
            if policy.state_attr is not None:
                setattr(self, policy.state_attr, None)
        self._output_open_id = None
        self._pressed = None
        self._overlay_signal.set()

    def _open_main_locked(self) -> bool:
        """The "main" row's opener: pop to main."""
        self._close_secondary_locked()
        return True

    def _open_list_locked(self, screen: str, keep_page_on_return: bool = False) -> bool:
        """The opener of the row-list screen *screen* ("selector" or "picker"): open, or re-open, at
        page 0 with a restarted inactivity clock, carrying over the rows last built. It does not
        clear another screen's state on a direct switch; _close_secondary_locked is the one place
        that does. With *keep_page_on_return*, a return from the unauthorised-row hint keeps the
        page the row was tapped on."""
        attr = _policy(screen).state_attr
        prev = getattr(self, attr)
        rows = prev.rows if prev is not None else ()
        page = prev.page if (keep_page_on_return and self._screen == "info_value" and prev is not None) else 0
        setattr(self, attr, ListScreenState(rows=rows, page=page, opened_at=time.monotonic()))
        self._screen = screen
        return True

    def _open_info_locked(self) -> bool:
        """The info row's opener: open at once with whatever rows the last
        gather left (or the placeholders, on a fresh open), a restarted
        inactivity clock, and page 0 — except when this is a return from
        the compact info page's own value view (self._screen ==
        "info_value"), which preserves the list's page instead of
        resetting it, so tapping back from a later page does not jump the
        list back to its first one. The actual data lands separately, from
        the daemon thread open_info() already started — see _gather_info()."""
        rows = self._info.rows if self._info is not None else INFO_PLACEHOLDER_ROWS
        page = self._info.page if (self._screen == "info_value" and self._info is not None) else 0
        self._info = InfoState(
            rows=rows, page=page, opened_at=time.monotonic(),
        )
        self._screen = "info"
        return True

    def _open_info_value_locked(self) -> bool:
        """The compact info page's own drill-in opener: refuse (the list
        stays showing) when the info list is not open or the touch-chosen
        index (self._info_value_index, set by info_row_tap()) no longer
        names a row in it — either way self._info is left untouched, since
        the view is the list's child and its own back_to returns there.

        A pending hint (self._info_value_hint, from an unauthorised selector
        row, a speaker that needs pairing or one that could not start) opens
        the view over the screen it came from instead, only while one of the
        screens the hint named (self._info_value_hint_over) is showing; that
        screen's state is left untouched."""
        hint, self._info_value_hint = self._info_value_hint, None
        over, self._info_value_hint_over = self._info_value_hint_over, _HINT_OVER_DEFAULT
        if hint is not None:
            if self._screen not in over:
                return False
            self._info_value_return = self._screen
            self._info_value = InfoValueState(index=0, opened_at=time.monotonic(), hint=hint)
            self._screen = "info_value"
            return True
        state, index = self._info, self._info_value_index
        self._info_value_index = None
        if self._screen != "info" or state is None or index is None or not (0 <= index < len(state.rows)):
            return False
        self._info_value = InfoValueState(index=index, opened_at=time.monotonic())
        self._screen = "info_value"
        return True

    def _open_repeat_locked(self) -> bool:
        """The repeat row's opener: open the page for the focused/reporting
        appliance in the newest snapshot's roster, or refuse (leaving the
        current screen in place) when there is none or it has dropped out
        of the roster. Caller holds self._lock."""
        entry = self._focused_entry(self._core.snapshot())
        if entry is None:
            return False
        screen = ApplianceScreenState(entry.appliance_id, entry.service_name, time.monotonic())
        # A fresh open re-anchors the counter: the first replaying frame
        # paints whatever second is current, never held against a value
        # painted before the screen was last closed.
        self._repeat_line.reset_counter()
        self._repeat_screen = screen
        self._screen = "repeat"
        return True

    def _open_eq_locked(self) -> bool:
        """The EQ row's opener: refuse when there is no focused/reporting
        appliance advertising the capability, or the current tier has no EQ
        page (see the snapshot's eq_available); otherwise open. The
        readings are the core's, which holds the last one while the page is
        watched, so a quick cycle away and back does not blank the bars."""
        if not self._core.snapshot().eq_available:
            return False
        entry = self._capable_target_lockfree("dial_eq")
        if entry is None:
            return False
        self._eq = ApplianceScreenState(entry.appliance_id, entry.service_name, time.monotonic())
        self._screen = "eq"
        return True

    def _open_outputs_locked(self) -> bool:
        """The outputs row's opener: refuse when there is no focused/
        reporting appliance advertising the capability (see
        _capable_target_lockfree()); otherwise open at page 0. The rows are
        the core's, which holds the last fetched list while the screen is
        watched, so a quick close/reopen does not flash back to
        "Loading"."""
        entry = self._capable_target_lockfree("dial_outputs")
        if entry is None:
            return False
        if self._screen in _PAGE_ORDER:
            # Opened from one of the three main pages: close back to it.
            # (Coming back up from the per-output detail page keeps the
            # page the list was first opened from.)
            self._outputs_return = self._screen
        elif self._screen != "output":
            self._outputs_return = "main"
        self._outputs = ApplianceScreenState(entry.appliance_id, entry.service_name, time.monotonic())
        self._screen = "outputs"
        return True

    def _open_output_locked(self) -> bool:
        """The per-output detail row's opener: refuse when the outputs
        list is not open or the touch-chosen row id (self._output_open_id,
        set by outputs_row_tap()) is no longer in its rows — either way the
        current screen (the outputs list) stays showing."""
        state, output_id = self._outputs, self._output_open_id
        self._output_open_id = None
        if output_id is None and self._screen == "info_value" and self._output_detail is not None:
            # Back from a hint that opened over this page: the page's own
            # state is still here, so show it again with a fresh clock.
            output_id = self._output_detail.output_id
        if state is None or output_id is None or not any(r.id == output_id for r in self._rows_of(state)):
            return False
        self._output_detail = OutputDetailState(
            appliance_id=state.appliance_id, output_id=output_id, opened_at=time.monotonic(),
        )
        self._screen = "output"
        return True

    def _open_status_locked(self, warning_id: str) -> bool:
        """Every status row's opener (bound per row with functools.partial
        in the policy table): refuse while the dial is restarting (that
        screen must stay until the reboot lands or times out) and while a
        higher-priority status is already up; otherwise open with a fresh
        clock. A page that is already showing this status is reopened in
        place (same screen, fresh clock). An interrupting status first pops
        whatever secondary screen is up (the warnings card included) and
        wakes a sleeping panel."""
        if self._screen == "restarting":
            return False
        warnings = self._core.warnings
        desc = warnings.descriptor(warning_id)
        if desc is None:
            return False
        showing = self._warning_screen
        showing_desc = warnings.descriptor(showing.warning_id) if showing is not None else None
        if (
            showing_desc is not None and showing.warning_id != warning_id
            and showing_desc.priority > desc.priority
            and warnings.is_active(showing.warning_id)
        ):
            return False
        if desc.interrupting:
            if self._screen != "main":
                self._close_secondary_locked()
            if self._display_sleeping:
                self._wake_locked()
                if self._screen_request == desc.screen:
                    self._screen_request = None
        self._warning_screen = WarningScreenState(warning_id=warning_id, opened_at=time.monotonic())
        self._screen = desc.screen
        return True

    def _open_warnings_locked(self) -> bool:
        """The warnings row's opener: the card of what the bell holds, on
        its first entry. Refused while the dial is restarting or a status
        page is up, and when the bell is empty."""
        if self._screen == "restarting" or self._warning_screen is not None:
            return False
        page = WarningsPageState.open(self._bell(), time.monotonic())
        if page is None:
            return False
        self._warnings_page = page
        self._screen = "warnings"
        return True

    def _open_restarting_locked(self) -> bool:
        """The restarting row's opener: always opens, and drops the warnings
        card's own state on the way (this is the one screen reached directly
        from it, and it never returns there)."""
        self._warning_screen = None
        self._warnings_page = None
        self._restarting = RestartingState(opened_at=time.monotonic())
        self._screen = "restarting"
        return True

    # ---------------------------------------------------------------------------
    # 6. Painters
    #
    # Thread: repaint, HTTP (under self._lock).
    # Owns: _current_base_image, _repeat_layout_shown, the collaborators' lock-owned fields
    # ---------------------------------------------------------------------------

    def _repaint_current_locked(self) -> bool:
        """Recompose and push the current screen, for a repaint where only the overlay or the screen
        itself changed. A no-op if the backend is closed.

        Returns True when applying pending touch activity woke the display
        (_apply_touch_activity_locked), so the caller can run the wake-pass side effects outside
        self._lock."""
        # Wake first if touch asked for it, so the backlight is on before
        # the frame is pushed rather than one repaint later.
        woke = self._apply_touch_activity_locked()
        # Fold any pending open_selector()/close_list()/list_page()
        # request into self._screen/self._selector before deciding what to
        # paint — see _apply_screen_requests_locked().
        self._apply_screen_requests_locked()
        if not (self._backend_open and self._backend is not None):
            return woke
        policy = _policy(self._screen)
        if policy.paint is not None:
            policy.paint(self)
            return woke
        # Main has no policy paint of its own — the idle chassis vs. bare
        # artwork/logo choice depends on artwork, affordance and now-
        # playing, none of which the table carries.
        if self._current_base_image is None:
            return woke
        if self._idle_chassis_due_locked():
            self._display_idle_locked()
            return woke
        self._display_locked(self._current_base_image)
        return woke

    def _idle_chassis_due_locked(self) -> bool:
        """True whenever the idle screen's own compose path (compose_idle: the corner glyphs, no
        volume/mute overlay) replaces the ordinary overlay compose: whenever nothing is playing, not
        only while the "tap to replay" affordance is due. Which base image it shows (the
        replay-available logo or the plain one) is decided by the affordance alone
        (_display_idle_locked). touch_surface()'s "idle" surface follows the same rule."""
        return self._screen == "main" and self._core.snapshot().now_playing is None

    def _display_locked(self, image) -> None:
        """Compose and write *image* to the backend: the one hand-off every frame reaches on its way
        to hardware. Caller holds self._lock.

        *image* is an already panel-sized base (logo, cached artwork or a freshly fitted frame); the
        compositor here applies only overlay, rotate and BGR, so self._current_rendered_image stays
        untransformed and a rotate or bgr toggle can re-display it without refetching. The compose
        reads the CURRENT overlay snapshot with no lock (see LOCK ORDER in __init__), so a
        fold-driven repaint landing mid-touch recomposes the overlay rather than wiping it. *image*
        is cached as self._current_base_image so the repaint thread can recompose it against a newer
        overlay later.

        Whether the overlay is held is decided in _effective_overlay_locked() from the snapshot's
        now_playing, not from *image*. While a reveal slide runs (ControlsReveal.advance()) the
        compose also receives how far it has got, from the one clock read this frame makes, so a
        repaint landing mid-slide composes under the chrome at its current position and a frame
        landing after the end draws the bare frame."""
        if not (self._backend_open and self._backend is not None):
            return
        self._current_base_image = image
        metrics = self._layout_metrics()
        now = time.monotonic()
        snapshot = self._overlay_snapshot
        steady = (snapshot.visible or self._held_overlay(now)) and not self._controls.hidden(now)
        slide_ok = (
            self._screen == "main"
            and self._slide_tier()
            and self._frame_controllable(self._core.snapshot())
        )
        animating, progress = self._controls.advance(now, steady, slide_ok)
        overlay = self._effective_overlay_locked(snapshot, now=now, animating=animating)
        timer = self._replay_timer_locked(now) if self._screen == "main" else None
        self._paint_locked(
            self._compositor.compose, image, metrics=metrics, panel_size=True,
            is_artwork=False,
            overlay=overlay,
            reveal_progress=progress,
            timer_text=timer[0] if timer else None,
            timer_alpha=timer[1] if timer else 1.0,
        )
        if timer:
            # The same reference the repeat screen's own counter advances
            # against (see _display_repeat_locked()); that screen re-anchors
            # it whenever it opens.
            self._repeat_line.frame_painted(timer[2], time.monotonic() if timer[1] < 1.0 else None)
        if animating:
            # Paced from the moment the frame has actually left, so the
            # loop's wait between slide frames is a real gap with the lock
            # released, however long the transmit took.
            self._controls.frame_sent(time.monotonic())

    def _repaint_base_locked(self, image, *, idle_ok: bool) -> None:
        """Publish a freshly chosen base image (artwork or logo) from the repaint thread without
        switching away from a secondary screen. On the main screen it composes straight to hardware:
        the idle-chassis path when *idle_ok* and nothing plays, otherwise the ordinary overlay
        compose. While a secondary screen is up it only refreshes the cached base and signals a
        repaint; the repeat, EQ and warning screens draw the base behind them, and the flat list and
        info screens ignore it. Caller holds self._lock."""
        self._current_base_image = image
        if self._screen != "main":
            self._overlay_signal.set()
            return
        if idle_ok and self._idle_chassis_due_locked():
            self._display_idle_locked()
        else:
            self._display_locked(image)

    def _show_transition_locked(self) -> None:
        """A plain dark base while the newly shown appliance's artwork or logo is fetched, so the
        previous appliance's artwork never lingers under the new name (_maybe_show_transition()
        calls this when the reporting appliance changes). Caller holds self._lock; a no-op when no
        backend is open. Drops the artwork cache so the fetch that follows always paints, and marks
        self._showing "waiting" so neither show_logo()'s nor _show_artwork()'s dedupe mistakes it
        for already showing something."""
        if not (self._backend_open and self._backend is not None):
            return
        width, height = self._logical_dims()
        self._source_artwork_key = ""
        self._current_rendered_image = None
        self._showing = "waiting"
        self._display_locked(Image.new("RGB", (width, height), TRANSITION_RGB))

    def _effective_overlay_locked(
        self, snapshot: OverlayState, now: float | None = None, animating: bool | None = None,
    ) -> OverlayState:
        """Merge now-playing state into the touch-published overlay snapshot at compose time.

        The touch side publishes only CONTROL state (visible, muted-if-known) via set_overlay(); it
        knows nothing of the track or the volume. This fills in what only the fold knows: artist,
        title, album, the optimistic volume (dial_volume.shown_volume()), the mute (shown_muted()),
        the appliance name (set whenever a controllable appliance is shown, whatever the number of
        authorised appliances), the page dots, the bell and the pressed zone (from the unified
        channel self._pressed; the snapshot's own pressed field is ignored).

        The overlay is forced visible when held (_held_overlay()): a stale visible=False snapshot,
        or a dismiss landing while held, is harmless, and the overlay stays drawn across a track
        change, when the base swaps to the placeholder logo but now_playing stays set. An
        artwork-tap hide window hides the overlay whatever the snapshot says, except while the slide
        is still drawing it on its way off (ControlsReveal.animating()). It does not check
        self._backend_open: _display_locked has already returned if the backend is closed. *now* and
        *animating* let the caller pass the one clock read and slide decision its compose was built
        on; either omitted is worked out here.

        Returns *snapshot* (carrying the bell) when it is neither visible nor held: compose() treats
        an invisible overlay as a strict no-op."""
        if now is None:
            now = time.monotonic()
        if animating is None:
            animating = self._controls.animating(now)
        held = self._held_overlay(now)
        # The reveal slide's own frames: the chrome is still on its way off
        # the panel, so the overlay is merged (the compositor slides it)
        # even though the snapshot or the hide window says hidden. Same
        # guards as held, so a cleared now-playing or a sleeping panel
        # mid-slide draws nothing.
        snap = self._core.snapshot()
        now_playing = snap.now_playing
        revealing = self._frame_controllable(snap) and animating
        # An artwork tap's hide window wins over a touch-published visible
        # snapshot: the user asked for the artwork, whichever mode the
        # controls are in. The touch side is told the same (see dial_touch_wiring's
        # ARTWORK dispatch) so its session matches.
        bell = self._bell_badge(snap)
        if self._controls.hidden(now) and not revealing:
            return _HIDDEN_OVERLAY if bell is None else dataclasses.replace(_HIDDEN_OVERLAY, bell=bell)
        if not (snapshot.visible or held or revealing):
            return snapshot if bell is None else dataclasses.replace(snapshot, bell=bell)
        artist = now_playing.artist if now_playing is not None else ""
        if now_playing is not None and self._layout_metrics().content_tier in (CONTENT_RICH, CONTENT_LARGE):
            # Rich/large only: base keeps its own artist row and compact draws
            # none. An idle or
            # pending focus (nothing actually playing) reads as idle; a
            # playing appliance with no identified title yet reads as
            # playing rather than blank. Idle wins over the no-title check;
            # a playing appliance with a real title keeps its artist
            # whatever the artwork state.
            if not now_playing.playing:
                artist = IDLE_ARTIST_TEXT
            elif awaiting_title(now_playing):
                artist = title_fallback(now_playing)
        title = now_playing.title if now_playing is not None else ""
        album = now_playing.album if now_playing is not None else ""
        name, volume = self._readout(now_playing.service_name) if now_playing is not None else ("", None)
        muted = shown_muted(now_playing.service_name) if now_playing is not None else False
        pressed = self._pressed_zone()
        # Belt and braces: dots are meaningful only on the main screen —
        # _repaint_current_locked never reaches this merge for the repeat/
        # selector/picker screens anyway (they bypass _display_locked
        # entirely), but the explicit screen check here means a stray call
        # can never show them somewhere they should not appear.
        dots = snap.dots_active and self._screen == "main"
        return dataclasses.replace(
            snapshot, visible=True, artist=artist, title=title, album=album, volume=volume, muted=muted,
            name=name, dots=dots, pressed=pressed, eq_pages=snap.eq_available, bell=bell,
        )

    def _paint_locked(self, compose, *lead, metrics=None, after=(), panel_size=False, **options) -> None:
        """Compose one screen with the compositor method *compose* and push it
        (_push_frame_locked()). The call is compose(*lead, width, height, *after, rotate, bgr,
        metrics, **options) at the logical size of *metrics* (the current layout when None). With
        *panel_size* the compositor is also told the backend's physical size, read inside the guard.
        Caller holds self._lock and has checked the backend is open. Never raises."""
        if metrics is None:
            metrics = self._layout_metrics()

        def build():
            extra = dict(options, output_size=(self._backend.width, self._backend.height)) if panel_size else options
            return compose(
                *lead, metrics.width, metrics.height, *after,
                rotate=self._config.rotate, bgr=self._config.bgr, metrics=metrics, **extra,
            )

        self._push_frame_locked(build)

    def _redisplay_current_locked(self) -> None:
        """Re-display the current frame synchronously, for a rotate or bgr change while fitted and
        open, so the new orientation shows at once."""
        if not (self._backend_open and self._backend is not None):
            return
        if self._current_rendered_image is not None:
            self._display_locked(self._current_rendered_image)
        else:
            self._render_logo_locked()

    def _render_logo_locked(self) -> None:
        width, height = self._logical_dims()
        image = load_logo(self._logo_path, width, height)
        if image is None:
            self._record_error_locked("logo_unavailable")
            self._log_limiter.log(
                logging.WARNING, "logo_unavailable",
                "dial display: logo unavailable at %s", self._logo_path,
            )
            self._clear_locked()
            return
        was_showing = self._showing
        # On the main screen this uses the idle-chassis path when a replay is
        # available (the replay-available logo, no controls overlay) and the
        # ordinary path otherwise; while a secondary screen is up it refreshes
        # the base behind that screen without switching away from it.
        self._repaint_base_locked(image, idle_ok=True)
        self._source_artwork_key = ""
        self._current_rendered_image = None
        self._showing = "logo"
        if was_showing == "artwork":
            logging.info("dial display: showing logo (no usable artwork)")

    def _display_list_locked(self) -> None:
        """Compose and push whichever list-chassis screen is open (the appliance selector, the
        replay picker, the outputs list or the read-only info page). Bypasses _display_locked(), so
        self._current_base_image survives a list visit and the frame never picks up the main
        overlay. Caller holds self._lock; the backend-open check is _repaint_current_locked's.

        Passes self._current_base_image as compose_list()'s `base` unconditionally: only the compact
        tier's picker frame draws it (dimmed); every other tier, and the info page, ignore it."""
        metrics = self._layout_metrics()
        if self._screen == "outputs":
            list_state = self._build_outputs_list_state_locked(metrics.width, metrics.height, metrics=metrics)
        elif self._screen == "info":
            list_state = self._build_info_list_state_locked(metrics.width, metrics.height, metrics=metrics)
        else:
            screen = self._screen if self._screen in _ROW_LISTS else "selector"
            list_state = self._build_row_list_state_locked(screen, metrics.width, metrics.height, metrics=metrics)
        self._paint_locked(
            self._compositor.compose_list, metrics=metrics, after=(list_state,), base=self._current_base_image,
        )

    def _build_row_list_state_locked(self, screen: str, width: int, height: int, metrics: "LayoutMetrics | None" = None) -> ListState:
        """Build the compositor's ListState for the current page of the row-list screen *screen*
        ("selector" or "picker"). Caller holds self._lock; repaint thread only. The picker's rows
        carry the buffer length in their secondary slot, formatted "m:ss". The pressed zone comes
        from the unified pressed channel (self._pressed)."""
        placeholder, to_row = _ROW_LISTS[screen]
        return list_state_for(
            getattr(self, _policy(screen).state_attr), rows_per_page_for(width, height, metrics=metrics),
            placeholder, to_row, pressed=self._pressed,
        )

    def _build_info_list_state_locked(self, width: int, height: int, metrics: "LayoutMetrics | None" = None) -> ListState:
        """Build the compositor's ListState for the info page's current page: read-only rows, all
        pages held in self._info.rows as the selector's and the picker's are in ListScreenState.
        title and plain_background mark the read-only variant: the compact tier's title band reads
        "Info", and the frame sits on the flat chassis colour, since the page has no artwork of its
        own to dim.

        Row shape is tier-aware: the compact tier's rows are names only, (label, False), since a tap
        opens the field's value view (info_row_tap(), InfoValueState); every other tier draws the
        value inline, (label, False, value)."""
        if metrics is None:
            metrics = self._layout_metrics()
        compact = metrics.content_tier == CONTENT_COMPACT
        to_row = (lambda row: (row.label, False)) if compact else (lambda row: (row.label, False, row.value))
        list_state = list_state_for(
            self._info, rows_per_page_for(width, height, metrics=metrics), "-",
            to_row, pressed=self._pressed,
        )
        return dataclasses.replace(list_state, title=INFO_TITLE, plain_background=True)

    def _row_with_optimistic_locked(self, row: "OutputRow") -> "OutputRow":
        """*row* with the core's pending optimistic override folded in when it names this row:
        paint-time only, never written back. Shared by the outputs list and the per-output detail
        view, so a toggle or volume step reads the same on both the instant it lands."""
        override = self._core.outputs_override()
        if override is not None and override[0] == row.id:
            return dataclasses.replace(row, selected=override[1], volume=override[2])
        return row

    def _build_outputs_list_state_locked(self, width: int, height: int, metrics: "LayoutMetrics | None" = None) -> ListState:
        """Build the compositor's ListState for the outputs list's current page. "Loading" until the
        first fetch has landed, "No outputs" once it has and there is nothing to show. The
        optimistic override is applied to the rows before they become row tuples, so the tap that
        set it reads back at once."""
        state = self._outputs
        held = held_outputs(self._core.snapshot(), state)
        placeholder = "Loading" if (held is None or not held.loaded) else "No outputs"
        rows = tuple(self._row_with_optimistic_locked(r) for r in offerable(held.rows)) if held is not None else ()
        return list_state_for(
            state, rows_per_page_for(width, height, metrics=metrics), placeholder,
            output_list_row, pressed=self._pressed, rows=rows,
        )

    def _display_output_locked(self) -> None:
        """Compose and push the per-output detail frame, the compose_output() counterpart to
        _display_repeat_locked(). Like the other secondary screens it bypasses _display_locked() and
        has its own dark-chassis compose path. Caller holds self._lock."""
        view = self._build_output_view_locked(time.monotonic())
        self._paint_locked(self._compositor.compose_output, after=(view,))

    def _build_output_view_locked(self, now: float) -> "OutputViewState":
        """Build the compositor's OutputViewState for the open per-output detail page, reading the
        output's row fresh from the core's outputs (through the optimistic override) at every paint.
        A detail whose row has disappeared draws a disabled placeholder rather than raising; the
        fold navigates away."""
        detail, state = self._output_detail, self._outputs
        name = appliance_display_name(state.service_name) if state is not None else ""
        pressed = self._pressed_zone()
        row = None
        if detail is not None and state is not None:
            row = next((r for r in self._rows_of(state) if r.id == detail.output_id), None)
        if row is None:
            return OutputViewState(name=name, output_name="", selected=False, level=None, pressed=pressed)
        row = self._row_with_optimistic_locked(row)
        level = row.volume if row.selected else None
        return OutputViewState(
            name=name, output_name=row.name, selected=row.selected, level=level, pressed=pressed,
        )

    def _display_info_value_locked(self) -> None:
        """Compose and push the compact info page's drill-in frame, the compose_info_value()
        counterpart to _display_output_locked(). Reads the tapped field's label and value fresh from
        self._info.rows at every paint, so a gather landing while it is open shows on the next
        repaint; an index that has fallen out of range paints a blank value rather than raising.
        Bypasses _display_locked(). Caller holds self._lock."""
        view_state = self._info_value
        if view_state is not None and view_state.hint is not None:
            view = InfoValueView(label=view_state.hint[0], value=view_state.hint[1])
        else:
            rows = self._info.rows if self._info is not None else INFO_PLACEHOLDER_ROWS
            row = rows[view_state.index] if view_state is not None and 0 <= view_state.index < len(rows) else None
            view = InfoValueView(label=row.label if row else "", value=row.value if row else "-")
        self._paint_locked(self._compositor.compose_info_value, after=(view,))

    def _display_card_locked(self) -> None:
        """Compose and push the card on screen (the warnings page, or a status page) over the
        current base image (the idle logo or the last artwork, dimmed; a flat chassis when nothing
        has been rendered). Text comes from the live bell or the status descriptor and its latest
        reading, so a fresh reading shows on the next repaint. A card whose entries have all
        cleared, or whose status has ended, closes the page instead. Bypasses _display_locked().
        Caller holds self._lock."""
        if self._screen == "warnings":
            page, card = self._warnings_card(self._bell())
            self._warnings_page = page.painted() if page is not None else None
        else:
            card = self._status_card()
        if card is None:
            self._screen_request = _policy(self._screen).back_to
            self._overlay_signal.set()
            return
        zone = self._pressed_zone()
        view = WarningView(
            title=card.title, message=card.message, buttons=tuple(label for label, _ in card.buttons),
            pressed=CARD_BUTTON_ZONES.index(zone) if zone in CARD_BUTTON_ZONES else None,
            percent=card.percent, source=card.source, severity=card.severity,
        )
        self._paint_locked(self._compositor.compose_warning, self._current_base_image, after=(view,))

    def _display_restarting_locked(self) -> None:
        """Compose and push the "Restarting..." frame. Caller holds
        self._lock."""
        self._paint_locked(self._compositor.compose_restarting)

    def _display_starting_locked(self) -> None:
        """Compose and push the "Starting..." frame and mark it as what is
        showing. Caller holds self._lock and has checked the backend is
        open. Leaves the base-image cache empty on purpose: the first poll
        must paint the logo or artwork over this, not find a stale base."""
        self._paint_locked(self._compositor.compose_starting)
        self._showing = "starting"

    def _display_repeat_locked(self) -> None:
        """Compose and push the repeat-screen frame, the compose_repeat() counterpart to
        _display_locked(). Like the other secondary screens it bypasses _display_locked() and never
        picks up the main overlay. Caller holds self._lock.

        Passes self._current_base_image as `base`: the replaying layout draws it dimmed behind the
        counter, the enable layout ignores it. Stamps self._repeat_layout_shown from the freshly
        built view, for touch_surface(), and commits the view's counter_second as the repeat line's
        painted second, the reference the counter's timer advances against (None for a layout with
        no running counter, so the next replaying frame re-anchors).

        An artwork-tap hide window hides the replaying layout's controls as it hides main's, with
        the same slide on the rich and large tiers (ControlsReveal.advance()); the counter keeps
        counting underneath. The window ends at the first paint that finds no replay running, and
        that paint does not animate, so the controls snap back. The touch surface is the ordinary
        one for the whole of a slide-in (touch_surface())."""
        now = time.monotonic()
        view = dataclasses.replace(self._build_repeat_view_locked(self._repeat_screen, now), bell=self._bell_badge())
        self._repeat_layout_shown = view.layout
        metrics = self._layout_metrics()
        # Only a running replay has artwork behind its controls to reveal:
        # a window still open when the replay stops (Restart must be
        # tappable again) or the layout changes ends at once.
        replaying = view.layout == "replaying" and view.counter_second is not None
        if self._controls.hidden(now) and not replaying:
            self._controls.end_hide()
        steady = not self._compact_controls_hidden() and not self._controls.hidden(now)
        animating, progress = self._controls.advance(now, steady, replaying and self._slide_tier())
        controls = steady or animating
        self._paint_locked(
            self._compositor.compose_repeat, metrics=metrics, after=(view,), panel_size=True,
            base=self._current_base_image, controls=controls, reveal_progress=progress,
        )
        if animating:
            self._controls.frame_sent(time.monotonic())
        # Committed whether or not the push succeeded, and whether or not
        # the line is visible: a write failure is already recorded and the
        # next second's tick repaints the whole line anyway, whereas
        # retrying the same second on every wake against a failing panel
        # would spin; and a hidden counter keeps counting, the tick
        # advancing against this reference, so it must always move.
        self._repeat_line.commit_counter(view.counter_second)

    def _build_repeat_view_locked(self, screen: "ApplianceScreenState | None", now: float) -> RepeatViewState:
        """Build the compositor's RepeatViewState from the repeat store's current record for
        *screen*: no or unavailable record, or a live source (recording, pending, idle), draws the
        enable layout (the top band plus the "Repeat Play" row); hold, replaying and fading_out draw
        the replaying layout (the Restart/Stop row and the position line). The row's dot marker
        reads `armed`, never `state`. The volume feeds the top band's readout, addressed at
        *screen*'s own appliance, since the screens can disagree about the focused appliance until
        the next fold. Caller holds self._lock (called from _display_repeat_locked)."""
        pressed = self._pressed_zone()
        # Feeds the shared top band's third page dot — see
        # OverlayState.eq_pages/_effective_overlay_locked for the identical
        # main-screen computation.
        eq_pages = self._core.snapshot().eq_available
        if screen is None:
            return RepeatViewState(
                name="", layout="enable", armed=False, line="",
                start_enabled=False, stop_enabled=False, stop_pressed=False, pressed=pressed,
                eq_pages=eq_pages,
            )
        name, volume = self._readout(screen.service_name)
        rec = self._repeat_record(screen.appliance_id)
        if rec is None or not rec.available:
            layout, start_enabled, stop_enabled, stop_pressed = _REPEAT_LAYOUTS["idle"]
        else:
            # An unlisted state reads as fading_out.
            layout, start_enabled, stop_enabled, stop_pressed = _REPEAT_LAYOUTS.get(
                rec.state, _REPEAT_LAYOUTS["fading_out"])
        line, second = "", None
        if layout == "replaying":
            # hold reads 0:00 (nothing is running for the counter-latency
            # clamp to apply to); replaying carries the counter's second,
            # which _display_repeat_locked() commits; fading_out freezes at
            # the last observed position.
            line, second = self._repeat_line.position_line(rec, now)
        return RepeatViewState(
            name=name, layout=layout, armed=rec is not None and rec.available and rec.armed, line=line,
            start_enabled=start_enabled, stop_enabled=stop_enabled, stop_pressed=stop_pressed,
            volume=volume, pressed=pressed, eq_pages=eq_pages,
            counter_second=second,
        )

    def _replay_timer_locked(self, now: float) -> "tuple[str, float, int | None] | None":
        """The main page's replay timer line right now, as (text, alpha, counter second), or None
        when none is drawn. Only for the appliance the pick was for, while it is the one shown, and
        never on the compact tier. Caller holds self._lock; repaint thread (reads the core's
        published snapshot, as _build_repeat_view_locked() does)."""
        if self._repeat_line.timer_id is None or self._compact_tier():
            return None
        return self._repeat_line.timer_line(now, self._repeat_record, self._core.snapshot().focused_id())

    def _display_eq_locked(self) -> None:
        """Compose and push the EQ-page frame, the compose_eq() counterpart to
        _display_repeat_locked(). Bypasses _display_locked() and never picks up the main overlay.
        Caller holds self._lock."""
        view = dataclasses.replace(self._build_eq_view_locked(self._eq, time.monotonic()), bell=self._bell_badge())
        self._paint_locked(self._compositor.compose_eq, after=(view,))

    def _build_eq_view_locked(self, screen: "ApplianceScreenState | None", now: float) -> EqViewState:
        """Build the compositor's EqViewState from *screen*, reading bass and treble through the
        optimistic override (_shown_eq()) so a tapped stepper moves on the same frame as the tap.
        The volume feeds the top band's readout, addressed at *screen*'s own appliance. Caller holds
        self._lock (called from _display_eq_locked)."""
        pressed = self._pressed_zone()
        if screen is None:
            return EqViewState(name="", bass_db=None, treble_db=None, loaded=False, pressed=pressed)
        name, volume = self._readout(screen.service_name)
        held = held_eq(self._core.snapshot(), screen)
        return EqViewState(
            name=name,
            bass_db=self._shown_eq(screen, "bass"),
            treble_db=self._shown_eq(screen, "treble"),
            loaded=held is not None and eq_loaded(held),
            volume=volume, pressed=pressed,
        )

    def _shown_eq(self, state: "ApplianceScreenState", control: str) -> "int | None":
        """The bass or treble value *control* should show on the page *state*: the core's pending
        optimistic override for *control* when it has not expired, else the core's last reading for
        the page's appliance (None until the first fetch lands)."""
        pairs, expires_at = self._core.eq_override()
        if pairs and expires_at > time.monotonic():
            for band_id, gain in pairs:
                if band_id == control:
                    return gain
        held = held_eq(self._core.snapshot(), state)
        return eq_gain(held.bands, control) if held is not None else None

    # ---------------------------------------------------------------------------
    # 7. Panel: backend, geometry, transmit
    #
    # Thread: repaint, HTTP (under self._lock).
    # Owns: _backend*, _active_screen_type, _showing, _last_frame, _panel_words, _last_error*,
    #        _noncomposited_generation
    # ---------------------------------------------------------------------------

    def _enable_locked(self, *, render_logo: bool = True) -> None:
        if self._backend_open:
            return
        backend = self._backend_factory()
        try:
            backend.open()
        except Exception as e:
            self._record_error_locked("backend_open_failed")
            logging.warning("dial display: backend open failed — degrading to no-op: %s", e)
            return
        self._backend = backend
        self._backend_name = getattr(backend, "name", "noop")
        self._active_screen_type = self._config.screen_type
        self._backend_open = True
        self._backend_loaded = True
        # A successful open clears any stale failure, so a successful screen_type
        # swap does not keep reporting an old error and hide drift.
        self._last_error = ""
        self._last_error_at = None
        # A newly opened panel holds nothing we know about, whatever was
        # cached before: the first push after an open is always a whole
        # frame, never a window diffed against a stale frame.
        self._last_frame = None
        logging.info(
            "dial display: backend %s open (%dx%d)",
            self._backend_name, backend.width, backend.height,
        )
        # Opening here is the awake state — reset any stale idle timer/sleep
        # flag from before this open. The logo is the normal first frame; the
        # boot splash (show_starting) opens with render_logo=False and pushes
        # its own frame instead, so the panel's first image is the splash
        # rather than a logo that the splash immediately covers.
        self._idle_started_at = None
        self._display_sleeping = False
        if render_logo:
            self._render_logo_locked()

    def _rebuild_backend_factory_locked(self, screen_type: str) -> None:
        """Rebuild self._backend_factory for *screen_type* via the injected resolver, so the next
        _enable_locked() opens the right backend. A no-op when no resolver was supplied."""
        if self._backend_factory_builder is None:
            return
        self._backend_factory = self._backend_factory_builder(screen_type)

    def _drop_backend_locked(self, during: str) -> None:
        """Close the open backend (a close that raises is logged, with
        *during* ("" or " during swap") in the message) and forget the
        panel: the backend, its name and screen type, and the cached frame
        and its source identity, which were composed at the old panel's
        dimensions and must not survive into a degraded or reopened state.
        Caller holds self._lock."""
        if self._backend_open and self._backend is not None:
            try:
                self._backend.close()
            except Exception as e:
                logging.debug("dial display: backend close raised%s: %s", during, e)
        self._backend = None
        self._backend_open = False
        self._backend_loaded = False
        self._backend_name = "noop"
        self._active_screen_type = ""
        self._showing = "noop"
        self._source_artwork_key = ""
        self._current_rendered_image = None
        self._last_frame = None

    def _swap_backend_locked(self) -> None:
        """Close the open backend and reopen via the already rebuilt factory, for a screen_type
        change while fitted and open. A failed open takes _enable_locked()'s degrade-to-noop path."""
        self._drop_backend_locked(" during swap")
        # A reopen after a screen_type swap starts on the main screen, not
        # wherever the list happened to be — the old panel's geometry is
        # gone anyway.
        self._close_secondary_locked()
        self._enable_locked()

    def _disable_locked(self) -> None:
        self._drop_backend_locked("")
        self._idle_started_at = None
        self._display_sleeping = False
        # A later re-enable starts on the main screen.
        self._close_secondary_locked()

    def _clear_locked(self) -> None:
        if self._backend_open and self._backend is not None:
            try:
                self._backend.clear()
            except Exception as e:
                logging.debug("dial display: backend clear raised: %s", e)
        self._showing = "noop"
        self._last_frame = None
        self._mark_noncomposited_locked()

    def _mark_noncomposited_locked(self) -> None:
        """Record that the display moved to a state with none of the touch overlay on screen
        (cleared or asleep), for the touch side to notice on its own schedule. Called from
        _clear_locked() and _sleep_locked() with self._lock held.

        It must not call into the touch session: any handler would want the overlay leaf lock, and
        taking that under self._lock is the mirror image of the hazard the LOCK ORDER forbids. The
        caller may also be the HTTP thread (update_config), which has no business running
        touch-session logic. So this is pure state, a generation counter the touch thread's loop
        polls (noncomposited_generation()) and reacts to on its own thread."""
        self._noncomposited_generation += 1
        # A press latched against geometry that just went dark must not
        # carry a wash into whatever comes back on screen next.
        self._pressed = None
        # Nothing is on screen for a hide window or a slide to belong to.
        self._controls.abandon()

    def _record_error_locked(self, error_id: str) -> None:
        self._last_error = error_id
        self._last_error_at = time.time()

    def _record_error(self, error_id: str) -> None:
        with self._lock:
            self._record_error_locked(error_id)

    def _active_panel_dims(self) -> tuple[int, int]:
        """The open backend's panel dimensions, or the default profile's when no backend is open.
        May be called with or without self._lock.

        The HTTP thread can swap or close the backend concurrently (update_config), so the reference
        is snapshotted into a local first. The result is advisory: a frame composed against it can
        still be superseded by a swap, which is why the size is re-checked under the lock before the
        frame is pushed (see _apply_artwork)."""
        backend = self._backend
        if self._backend_open and backend is not None:
            return backend.width, backend.height
        return DEFAULT_PANEL_WIDTH, DEFAULT_PANEL_HEIGHT

    def _logical_dims(self) -> tuple[int, int]:
        """The compose-space size every frame is built and hit-tested in: the chosen layout size
        when one is set, else the open backend's dimensions (the default profile's when none is
        open). Plain attribute reads, with or without self._lock."""
        if self._layout.size_chosen:
            return self._layout.logical_size
        return self._active_panel_dims()

    def _push_frame_locked(self, compose) -> None:
        """Compose one frame at the logical size and push it to the backend, resampling to the
        panel's physical size when the two differ, and record a write failure the same way for every
        screen. *compose* is a zero-argument callable returning the finished frame; it runs inside
        the guard so a compositor failure is handled like a backend or resample failure. Caller
        holds self._lock and has checked the backend is open. Never raises.

        The transmit is _transmit_locked(), which sends only the part that differs from the frame on
        the panel when the backend can write a window. A transmit failure drops self._last_frame,
        since the panel may hold part of the new frame and the next push must write all of it. A
        compose failure sends nothing and leaves self._last_frame as it was."""
        try:
            composed = compose()
            physical = (self._backend.width, self._backend.height)
            if composed.size != physical:
                composed = composed.resize(physical, resample_filter(composed.size, physical))
        except Exception as e:
            self._record_write_failure_locked(e)
            return
        try:
            self._transmit_locked(composed)
        except Exception as e:
            self._last_frame = None
            self._record_write_failure_locked(e)
            return
        self._last_frame = composed

    def _record_write_failure_locked(self, e: BaseException) -> None:
        self._record_error_locked("display_write_failed")
        self._log_limiter.log(
            logging.WARNING, "display_write_failed",
            "dial display: backend write failed: %s", e,
        )

    def _transmit_locked(self, composed) -> None:
        """Send *composed*, already at the panel's size and orientation, to the backend. When the
        backend can write a window, only the regions that differ from the frame on the panel are
        written: as many rectangles as the cost model says pay for themselves
        (dial_display_windows), or, if planning fails, the bounding box split in up to a few places
        (dirty_windows). An identical frame sends nothing.

        A whole-frame write is used instead whenever the backend cannot window-write, nothing is
        known to be on the panel, the frames are not comparable (size or mode), the window write
        reports it could not run, or anything in the windowed path fails: a diff or window problem
        costs the saving, never the frame. Raises only what the whole-frame display() raises; the
        caller records that."""
        backend = self._backend
        last = self._last_frame
        if (
            not getattr(backend, "supports_window_write", False)
            or not isinstance(composed, Image.Image)
            or not isinstance(last, Image.Image)
            or last.size != composed.size
            or last.mode != composed.mode
        ):
            self._panel_words = None
            backend.display(composed)
            return
        try:
            boxes, new_words = self._plan_transmit_locked(composed, last)
            if boxes is None:
                # No planner (a plan failure): the
                # bounding-box path, with its own vertical split.
                diff = ImageChops.difference(composed, last)
                bbox = diff.getbbox()
                if bbox is None:
                    return
                boxes = dirty_windows(diff, bbox)
            elif not boxes:
                self._panel_words = (composed, new_words)
                return
            written = True
            for box in boxes:
                left, upper, right, lower = box
                # The boxes are half-open on the right and bottom; the
                # panel's address window is inclusive at both corners.
                # Written top to bottom, as planned.
                if not backend.display_window(composed.crop(box), left, upper, right - 1, lower - 1):
                    written = False
                    break
            if written:
                self._panel_words = (composed, new_words)
                return
        except Exception as e:
            self._log_limiter.log(
                logging.WARNING, "display_window_failed",
                "dial display: window write failed, writing the whole frame: %s", e,
            )
        self._panel_words = None
        backend.display(composed)

    def _plan_transmit_locked(self, composed, last):
        """(boxes, new_words) for the change-region planner: *boxes* is the windows to write, top to
        bottom (empty: the frames are identical), and *new_words* the planner's view of *composed*,
        for the caller to cache once it is on the panel. (None, None) when the planner is
        unavailable, and the caller takes the bounding-box path. The previous frame's words come
        from the cache when it still names *last*, else from *last*. A planner failure is logged
        (rate-limited) and reported as unavailable. Never raises. Caller holds self._lock."""
        try:
            if composed.mode != "RGB":
                return None, None
            new_words = frame_words(composed, *composed.size)
            if new_words is None:
                return None, None
            cached = self._panel_words
            if cached is not None and cached[0] is last:
                last_words = cached[1]
            else:
                last_words = frame_words(last, *last.size)
                if last_words is None:
                    return None, None
            boxes = plan_windows(new_words, last_words, *composed.size)
            if boxes is None:
                boxes = [bounding_box(new_words, last_words, *composed.size)]
            return boxes, new_words
        except Exception as e:
            self._log_limiter.log(
                logging.WARNING, "display_plan_failed",
                "dial display: change-region planning failed, using the bounding box: %s", e,
            )
            return None, None

    # ---------------------------------------------------------------------------
    # 8. Snapshot fold and effects
    #
    # Thread: repaint (or a test driver); never holds self._lock on entry.
    # Owns: _applied, _apply_lock, _tick_shown_level, _source_artwork_key, _current_rendered_image
    #
    # The core runs its fold on its own thread and publishes immutable snapshots; this view
    # folds each into the screen on the repaint thread. The effects the core queued (what a warning
    # source, a worker result or a volume reading means for a screen) are drained here and become
    # screen requests.
    # ---------------------------------------------------------------------------

    def _core_changed(self) -> None:
        """The core's subscriber callback. Only wakes the repaint thread to read the newest
        snapshot; never paints, never blocks."""
        self._overlay_signal.poke()

    def _apply_pending_snapshot(self) -> None:
        """Fold what the core has published since the last call into the
        screen: the warning effects its housekeeping queued, then the newest
        snapshot against the one last folded. Runs on the repaint thread
        (or whoever drives the poll by hand), never with self._lock held.
        A snapshot nothing on screen depends on costs a comparison and
        paints nothing."""
        with self._apply_lock:
            self._drain_effects()
            new = self._core.snapshot()
            prev = self._applied
            if new is prev:
                return
            self._applied = new
            if self._bell(new) != self._bell(prev):
                self._overlay_signal.set()
            self._follow_screen_data(prev, new)
            self._apply_snapshot(prev, new)

    def _drain_effects(self) -> None:
        """Turn what the core queued for this view (what its warning
        sources, worker results and volume readouts mean for a screen) into
        screen requests, oldest first. Each effect goes to exactly one
        caller. Takes none of this class's locks."""
        for effect in self._core.take_effects():
            if isinstance(effect, RepeatEffect):
                self._apply_repeat_outcome(effect.appliance_id, effect.outcome)
            elif isinstance(effect, OutputsEffect):
                self._apply_outputs_outcome(effect)
            elif isinstance(effect, StartFailureEffect):
                self._apply_start_failure(effect)
            else:
                self._apply_source_effects(effect)

    def _apply_source_effects(self, effects) -> None:
        """Turn what a source did to the warnings into screen requests, in
        the order it did it: a status reported present is requested if it
        is due (waking the panel when it just began and interrupts), one
        cleared closes its page. The update run's reboot phase shows the
        restarting screen. Lock-free."""
        for change in effects.changes:
            if change.active:
                self._request_due_status(wake=change.began)
            else:
                self._close_status_request(change.warning_id)
        if effects.restarting:
            self._screen_request = "restarting"
        if effects.signal:
            self._overlay_signal.set()

    def _apply_repeat_outcome(self, appliance_id: str, outcome) -> None:
        """React to what a repeat transport result meant: a fold at once for
        an accepted replay the dial follows (and for any rejection), the
        compact tier's close of the repeat screen on the ack of its own
        Stop, and the replay timer. Lock-free."""
        if outcome.ok:
            if outcome.replay_accepted:
                # A replay the dial is following has just been accepted:
                # show it as playing until its session is folded, and fold
                # now rather than at the next interval.
                self._core.request_fold()
            if outcome.stop_acked:
                # This ok ack is for the Stop this appliance's repeat_stop_
                # tap() just sent — on the compact tier, close the repeat
                # screen back to the playing 2x2 immediately, rather than
                # waiting for it to time out or for the next poll to find
                # the appliance not playing. Off compact the repeat screen
                # simply stays. A rejected/transient Stop leaves
                # it too: only an ok ack pops it.
                if (
                    self._compact_tier() and self._screen == "repeat"
                    and self._repeat_screen is not None
                    and self._repeat_screen.appliance_id == appliance_id
                ):
                    self._screen_request = "main"
            self._overlay_signal.set()
            return

        self._core.request_fold()

        if self._repeat_line.timer_id == appliance_id:
            # The replay did not start: nothing for the timer line to show.
            self._repeat_line.arm(None, time.monotonic())
            self._overlay_signal.set()

    def _apply_outputs_outcome(self, effect: OutputsEffect) -> None:
        """React to what an output request's outcome means for the screen:
        a speaker that wants a PIN gets the pairing hint, when its own page
        is the one up (or, for a request that came after the switch's reply,
        the speaker list or any speaker's page of that appliance). Every
        other outcome needs nothing here, since the fetch after the set
        already reconciles. Lock-free."""
        if effect.outcome != "rejected" or effect.error not in PIN_ERRORS:
            return
        state, detail = self._outputs, self._output_detail
        if effect.late:
            if (
                self._screen in ("outputs", "output") and state is not None
                and state.appliance_id == effect.appliance_id
            ):
                self._show_pairing_hint(state, _LATE_PIN_OVER)
            return
        if (
            self._screen == "output" and state is not None and detail is not None
            and state.appliance_id == effect.appliance_id and detail.output_id == effect.output_id
        ):
            self._show_pairing_hint(state)

    def _apply_start_failure(self, effect: StartFailureEffect) -> None:
        """Show the notice on the value page when the screen is awake, follows
        the failure's appliance and shows the main screen or an output page.
        Lock-free, as _apply_outputs_outcome."""
        if self.is_sleeping() or effect.appliance_id != self._core.snapshot().focused_id():
            return
        self._info_value_hint = start_failure_hint(effect.name, effect.reason)
        self._info_value_hint_over = _START_FAILURE_OVER
        self._screen_request = "info_value"
        self._overlay_signal.set()

    def _close_status_request(self, warning_id: str) -> None:
        """Close the page of a status that has ended, or drop a pending
        request for it. Lock-free."""
        desc = self._core.warnings.descriptor(warning_id)
        if desc is None or not desc.screen:
            return
        if self._screen == desc.screen:
            self._screen_request = _policy(desc.screen).back_to
        elif self._screen_request == desc.screen:
            self._screen_request = None

    def _follow_screen_data(self, prev, new) -> None:
        """What a change in the core's outputs or EQ state means for the pages showing them: a
        repaint when one is up, the outputs list clamped to the page its rows still reach, and the
        per-output page sent back to the list when its output has gone. Runs on the repaint thread
        (or whoever drives the fold), never with self._lock held."""
        if new.outputs != prev.outputs:
            with self._lock:
                state = self._outputs
                held = held_outputs(new, state)
                if held is not None and held.loaded:
                    rows = offerable(held.rows)
                    page = clamp_page(state.page, len(rows), self._rows_per_page())
                    if page != state.page:
                        self._outputs = dataclasses.replace(state, page=page)
                    detail = self._output_detail
                    if (
                        detail is not None and self._screen == "output"
                        and not any(r.id == detail.output_id for r in rows)
                    ):
                        self._screen_request = "outputs"
            if state is not None:
                self._overlay_signal.set()
        if new.eq != prev.eq and self._eq is not None:
            self._overlay_signal.set()

    def _apply_snapshot(self, prev, new) -> None:
        """What a snapshot means for the screen. Anything that makes the
        panel's frame is decided here or by the repaint it asks for; the core
        never touches the panel.

        A snapshot that records a pushed auth change confirming an appliance
        wakes a sleeping panel. A snapshot with a visible playing appliance
        (not refused, with an identity; unknown auth counts) resets the idle
        clock and wakes a sleeping panel, so playback alone wakes it. A
        snapshot that ends a poll tick (a new tick count) also carries the
        tick's effects: the screens a cleared focus closes, the transition
        frame between appliances, the artwork or logo, the selector and
        picker rows, and with nothing playing the idle clock and sleep. Other
        snapshots (a focus change, a reading, a warning) change what is read,
        not what is drawn, until a repaint asks. A panel that is asleep stays
        dark: nothing here paints for it."""
        if not new.polling:
            return
        if new.auth_promotions != prev.auth_promotions:
            # A pushed auth change confirmed an appliance (playing or not)
            # while this panel may be asleep: wake it, as a touch does.
            with self._lock:
                if self._display_sleeping:
                    self._idle_started_at = None
                    self._wake_locked()
        tick = new.tick if new.ticks != prev.ticks else None
        if tick is not None and tick.focus_cleared:
            self._close_screens_for_cleared_focus()
        if new.visible_playing:
            woke = False
            with self._lock:
                self._idle_started_at = None
                if self._display_sleeping:
                    self._wake_locked()
                    woke = True
            if woke:
                self._core.request_fold()
        if tick is None:
            return
        if new.visible_playing:
            self._apply_playing_tick(tick, new)
        else:
            self._apply_idle_tick(tick, new)

    def _close_screens_for_cleared_focus(self) -> None:
        """Close the screen showing when its policy says a cleared focus
        should pop it (the repeat screen was opened for that focus)."""
        if _policy(self._screen).closes_on_focus_clear:
            with self._lock:
                self._close_secondary_locked()

    def _apply_playing_tick(self, tick, new) -> None:
        """The end of a tick with something playing: the transition frame
        when the reporting appliance changed, the artwork (or the logo when
        there is none), and the rows."""
        self._maybe_show_transition(tick.previous_reporting_id)
        self._close_bound_screen_if_unfocused()
        if new.now_playing != tick.previous_now_playing:
            self._overlay_signal.set()
        # The volume and mute the screens show are read from the volume
        # worker's store at paint time, and a poll can change them (they
        # were set from somewhere else): ask for the repaint that shows it.
        playing = new.now_playing
        service = playing.service_name if playing is not None else None
        shown = (service, shown_volume(service), shown_muted(service))
        if shown != self._tick_shown_level:
            self._tick_shown_level = shown
            self._overlay_signal.set()
        if new.artwork is not None:
            self._show_artwork(new.artwork)
        else:
            self.show_logo()
        self._refresh_list_rows(new)
        if new.idle_affordance != tick.previous_idle_affordance:
            self._overlay_signal.set()

    def _apply_idle_tick(self, tick, new) -> None:
        """The end of a tick with nothing playing anywhere: the rows, what
        the open screen does about it, the idle clock and sleep, and the
        logo. A panel asleep, asleep by now, or showing a list stays as it
        is (a list's own timeout closes it)."""
        if new.idle_affordance != tick.previous_idle_affordance:
            self._overlay_signal.set()
        self._refresh_list_rows(new)

        with self._lock:
            # Each screen's own row says what a poll finding nothing
            # playing does to it: IDLE_KEEP screens (the two list
            # screens) are left alone — their own inactivity timeout
            # closes them; IDLE_KEEP_WITH_FOCUS (repeat) closes unless
            # an idle focus keeps it meaningful. A pending request for a
            # screen that defers sleep (an open_* call just ran on the
            # touch thread, the repaint thread has not applied it yet)
            # counts as open too, so this never clobbers a list that is
            # opening this very tick.
            list_open = _defers_sleep(self._screen, self._screen_request)
            current = _policy(self._screen)
            if current.when_nothing_plays == IDLE_KEEP_WITH_FOCUS and not tick.idle_focus:
                self._close_secondary_locked()
            if not list_open:
                if self._idle_started_at is None:
                    self._idle_started_at = time.monotonic()
            else:
                # An open list counts as activity: never sleep out from
                # under it (its timeout returns to main first, after
                # which the idle-sleep clock restarts).
                self._idle_started_at = None
            if self._display_sleeping:
                # Stay dark — no repaint while asleep.
                return
            if (
                not list_open
                and time.monotonic() - self._idle_started_at >= DISPLAY_IDLE_SLEEP_SECONDS
            ):
                self._sleep_locked()
                return
        if list_open:
            return
        self._maybe_show_transition(tick.previous_reporting_id)
        self._close_bound_screen_if_unfocused()
        self.show_logo()

    def _refresh_list_rows(self, snapshot) -> None:
        """Rebuild the selector's and the replay picker's row lists from *snapshot* (selector_rows()
        and picker_rows() in dial_core_state hold the filters). Runs when a tick ends
        (_apply_snapshot), in both the playing and the idle branch, whether or not either screen is
        open, so opening one never waits for a fold. The touch thread never builds rows.

        The page is preserved (clamped to the new row count) across each rebuild; only a fresh open
        resets it to 0 (_apply_screen_requests_locked)."""
        for screen, rows in (("selector", snapshot.selector_rows()), ("picker", snapshot.picker_rows())):
            attr = _policy(screen).state_attr
            with self._lock:
                prev = getattr(self, attr)
                page, opened_at = self._carried_paging_locked(prev, len(rows))
                setattr(self, attr, ListScreenState(rows=rows, page=page, opened_at=opened_at))
                changed = prev is None or prev.rows != rows
            if changed and (self._screen == screen or self._screen_request == screen):
                # A rebuild that actually changed the rows must repaint even
                # with nothing else moving on screen — otherwise the list
                # can sit on its opening placeholder until a touch elsewhere
                # forces the next frame. Signalled outside the lock, like
                # every other _overlay_signal.set() site.
                self._overlay_signal.set()

    def _carried_paging_locked(self, prev, row_count: int) -> tuple[int, float]:
        """(page, opened_at) to keep across a row rebuild: the previous page
        clamped to the new row count, and the previous opened_at, or (0, 0.0)
        when there was no previous state. Caller holds self._lock."""
        if prev is None:
            return 0, 0.0
        return clamp_page(prev.page, row_count, self._rows_per_page()), prev.opened_at

    def _maybe_show_transition(self, previous_reporting_id: "str | None") -> None:
        """Push a brief dark transition frame (_show_transition_locked()) when the core's reporting
        appliance changed this tick directly from one appliance to a different one. Call once the
        tick's reporting id is final, in either branch of _apply_snapshot. A no-op when it is
        unchanged, cleared, or was unset: a fresh start has no stale artwork to guard against, so it
        goes straight to that appliance's own logo or artwork."""
        reporting_id = self._core.snapshot().focus.reporting_id
        if (
            reporting_id is not None
            and previous_reporting_id is not None
            and reporting_id != previous_reporting_id
        ):
            with self._lock:
                self._show_transition_locked()

    def _close_bound_screen_if_unfocused(self) -> None:
        """Pop the screen showing if its policy says it is bound to an appliance (the outputs list,
        the per-output detail page) and that appliance is no longer the focused/reporting one this
        tick. self._screen and the bound state attribute are read lock-free (a stale read costs one
        extra tick, as in _check_secondary_timeout()); the close is applied under self._lock."""
        policy = _policy(self._screen)
        if not policy.bound_to_appliance:
            return
        state = getattr(self, policy.state_attr)
        snap = self._core.snapshot()
        if state is not None and state.appliance_id != snap.focused_id():
            with self._lock:
                self._close_secondary_locked()

    def _show_artwork(self, artwork) -> None:
        """Draw the core's artwork: the picture already on screen or cached
        for this track when there is one, else decode and fit it
        (_apply_artwork)."""
        key = artwork.key
        with self._lock:
            if not (self._backend_open and self._backend is not None):
                return
            if key == self._source_artwork_key and self._showing == "artwork":
                logging.debug("dial display: unchanged artwork url reuse")
                return
            cached_reusable = (
                key == self._source_artwork_key and self._current_rendered_image is not None
            )
            if cached_reusable:
                was_showing = self._showing
                self._repaint_base_locked(self._current_rendered_image, idle_ok=False)
                self._showing = "artwork"
                if was_showing == "logo":
                    logging.info("dial display: showing artwork")
                return
        # Decoding and fitting follow in _apply_artwork().
        self._apply_artwork(artwork)

    def _apply_artwork(self, artwork) -> None:
        """Decode, fit and paint the core's artwork, or the logo when there is none. The decode and
        fit run outside the lock, so the HTTP thread can swap or close the backend underneath via
        update_config; the size re-check below, taken under the lock, is what makes that safe."""
        if artwork is None:
            self.show_logo()
            return
        key = artwork.key
        url_key = key[:12]      # the same short form _url_log_key gives the URL
        image = decode_artwork(artwork.data)
        if image is None:
            # Drop the undecodable bytes so the next poll downloads them
            # again: a truncated transfer then heals instead of repeating.
            self._core.clear_artwork(key)
            self._record_error("artwork_decode_failed")
            self._log_limiter.log(
                logging.WARNING, f"artwork_decode:{url_key}",
                "dial display: artwork decode failed (%s)", url_key,
            )
            self.show_logo()
            return

        width, height = self._logical_dims()
        # rotate/bgr are deferred to _display_locked() below (and to any
        # later cached-reuse push) — this call only produces the logical-
        # size, pre-rotate/BGR base that gets cached as
        # self._current_rendered_image.
        transformed = self._compositor.compose(
            image, width, height,
            rotate=False, bgr=False, is_artwork=True,
        )

        with self._lock:
            if not (self._backend_open and self._backend is not None):
                return
            if transformed.size != self._logical_dims():
                # A screen_type or layout_size change raced with this
                # fetch/transform, which ran outside the lock against the
                # size active at the time — composed for a (now superseded)
                # size. Drop the stale-sized frame; the next poll recomposes
                # at the now-active size.
                logging.debug(
                    "dial display: dropping frame sized for a superseded backend"
                )
                return
            was_showing = self._showing
            self._repaint_base_locked(transformed, idle_ok=False)
            self._source_artwork_key = key
            self._current_rendered_image = transformed
            self._showing = "artwork"
            self._last_error = ""
            self._last_error_at = None

        logging.info("dial display: artwork replaced (%s)", url_key)
        if was_showing == "logo":
            logging.info("dial display: showing artwork")

    # ---------------------------------------------------------------------------
    # 9. Warnings, idle and sleep
    #
    # Thread: repaint; _holds_idle_state is read on the core thread.
    # Owns: _warning_screen, _warnings_page, _idle_started_at, _display_sleeping
    # ---------------------------------------------------------------------------

    def _request_due_status(self, wake: bool = False) -> None:
        """Request the page of the due status, if any. An interrupting status is requested over a
        secondary screen (the opener pops it), over a lower-priority status page and over a pending
        request other than the restart screen's, and with wake=True into a sleeping panel (the
        opener wakes it); it is not requested again while its own page is up. Also called from the
        repaint thread's timeout branch (the due_status timer), so a status the opener refused is
        requested again. Callable with or without self._lock: plain reads and one plain request
        write, the same writes the core's source effects make."""
        desc = self._core.warnings.due_status()
        if desc is None:
            return
        if desc.interrupting:
            if self._screen in ("restarting", desc.screen) or self._screen_request == "restarting":
                return
            if self._display_sleeping and not wake:
                return
        elif self._display_sleeping or self._screen != "main" or self._screen_request is not None:
            return
        self._screen_request = desc.screen
        self._overlay_signal.set()

    def _bell(self, snap=None) -> Bell:
        """What the bell holds: the dial's own warnings and those of every
        appliance on its roster, from *snap* (the core's latest by default)."""
        return whole_bell(snap if snap is not None else self._core.snapshot(), self._core.warnings.descriptors())

    def _bell_badge(self, snap=None) -> "BellBadge | None":
        """The bell as the compositor draws it, None when it holds nothing."""
        bell = self._bell(snap)
        return BellBadge(bell.severity, bell.count) if bell.count else None

    def _warnings_card(self, bell: Bell) -> tuple:
        """(page, card) for the warnings page against *bell*: the page with
        its entry still on show, and that entry's card; (None, None) when
        there is no page or no entry of it remains."""
        page = self._warnings_page.synced(bell) if self._warnings_page is not None else None
        return page, (page.card(bell) if page is not None else None)

    def _status_card(self) -> "Card | None":
        """The card of the status page on screen, None when there is none or
        its status has ended."""
        showing = self._warning_screen
        warnings = self._core.warnings
        desc = warnings.descriptor(showing.warning_id) if showing is not None else None
        if desc is None or not warnings.is_active(desc.id):
            return None
        return status_card(desc, warnings.reading(desc.id))

    def _wifi_link(self) -> str:
        """The latest link verdict, or "unknown" before the first poll.
        Plain reference read, safe from any thread."""
        view = self._core.snapshot().network
        return view.link if view is not None else "unknown"

    def _wifi_flashing(self) -> bool:
        """True exactly while the idle screen is on screen and the link is down: the only time the
        flash is drawn and the loop has to wake for it. Lock-free plain reads (a stale read costs
        one extra repaint)."""
        return (
            self._screen == "main" and self._core.snapshot().now_playing is None
            and self._backend_open and not self._display_sleeping
            and self._wifi_link() == LINK_DOWN
        )

    @staticmethod
    def _wifi_alarm_phase(now: float) -> bool:
        """Which half of the flash *now* falls in: True is the emphasised
        half (red after a lost link, blank while still connecting), False
        the grey half."""
        return int(now // WIFI_FLASH_HALF_PERIOD_S) % 2 == 0

    def _idle_wifi_args_locked(self) -> "tuple[int, str]":
        """(wifi_bars, wifi_style) for compose_idle(): steady lit arcs while connected; while down,
        the flash's current half, grey, and on the emphasised half red (the link was lost after
        having connected since boot) or nothing (never connected yet: the dial is still connecting,
        which is not an alarm); a steady all-grey glyph while the link is ignored or unknown. Caller
        holds self._lock."""
        view = self._core.snapshot().network
        if view is None:
            return 0, WIFI_GREY
        if view.link == LINK_CONNECTED:
            return view.bars, WIFI_SIGNAL
        if view.link == LINK_DOWN:
            if not self._wifi_alarm_phase(time.monotonic()):
                return 0, WIFI_GREY
            return 0, (WIFI_RED if self._core.snapshot().wifi_ever_connected else WIFI_OFF)
        return 0, WIFI_GREY

    def _display_idle_locked(self) -> None:
        """Compose and push the idle-screen frame: the "replay available" logo whenever the idle
        affordance is due, else the plain logo stored as the current base. Either way it carries the
        Wi-Fi status glyph top-left (steady bars while connected; while down, the grey/red flash
        after a lost link or the grey/blank flash while still connecting) and the warning bell
        top-right while the bell holds anything, with no volume/mute overlay. Reached whenever
        nothing is playing (_idle_chassis_due_locked). Degrades to the plain base if the replay
        image cannot be loaded. Caller holds self._lock; a no-op if the backend is closed or nothing
        has been rendered."""
        if not (self._backend_open and self._backend is not None):
            return
        if self._current_base_image is None:
            return
        # The idle screen draws no controls; the next now-playing frame has
        # nothing comparable before it and must not slide in or out.
        self._controls.abandon_slide()
        metrics = self._layout_metrics()
        base = (
            (load_logo(self._replay_logo_path, metrics.width, metrics.height) if self._core.snapshot().idle_affordance else None)
            or self._current_base_image
        )
        wifi_bars, wifi_style = self._idle_wifi_args_locked()
        bell = self._bell_badge()
        self._paint_locked(
            self._compositor.compose_idle, base, metrics=metrics,
            wifi_bars=wifi_bars, wifi_style=wifi_style, bell=bell,
        )

    def _holds_idle_state(self, focus_cleared: bool) -> bool:
        """True when a fold finding nothing playing must leave what the core reports as it is: the
        panel is asleep, is about to sleep on this tick's idle clock, or has a list up (or being
        opened) that its own timeout closes. The same decision _apply_idle_tick acts on, taking the
        screen a cleared focus closes as already closed. Plain reads; runs on the core thread."""
        if self._display_sleeping:
            return True
        screen = self._screen
        if focus_cleared and _policy(screen).closes_on_focus_clear:
            screen = "main"
        if _defers_sleep(screen, self._screen_request):
            return True
        started = self._idle_started_at
        return started is not None and time.monotonic() - started >= DISPLAY_IDLE_SLEEP_SECONDS

    def _sleep_locked(self) -> None:
        # Pop to the main screen before the backlight goes off — the
        # appliance list must never be the last thing left on screen
        # (see also the empty-target branch in _apply_idle_tick, which is the
        # only path that can reach sleep with a fresh reason to check).
        self._close_secondary_locked()
        if self._backend_open and self._backend is not None:
            try:
                self._backend.sleep()
            except Exception as e:
                self._record_error_locked("display_sleep_failed")
                logging.debug("dial display: backend sleep raised: %s", e)
        self._display_sleeping = True
        self._showing = "sleeping"
        self._source_artwork_key = ""
        self._current_rendered_image = None
        self._last_frame = None
        logging.info("dial display: idle %ds — sleeping", DISPLAY_IDLE_SLEEP_SECONDS)
        self._mark_noncomposited_locked()

    def _wake_locked(self) -> None:
        if self._backend_open and self._backend is not None:
            try:
                self._backend.wake()
            except Exception as e:
                self._record_error_locked("display_wake_failed")
                logging.debug("dial display: backend wake raised: %s", e)
        self._display_sleeping = False
        # The cached-artwork fast path in _show_artwork and the show_logo
        # dedupe both skip rendering when _showing looks unchanged — force
        # the next render to actually paint by clearing the known artwork
        # url and setting a showing value neither path treats as "already
        # shown".
        self._showing = "waking"
        self._source_artwork_key = ""
        logging.info("dial display: activity resumed — waking")
        # A status that was popped by sleep, or became due while asleep,
        # comes straight back: the request lands before the repaint that
        # follows this wake folds its screen requests.
        self._request_due_status()


# The table itself is defined after the class body so its `open`/`paint`
# entries can name the class's own (unbound) methods directly.
SCREEN_POLICIES: dict[str, ScreenPolicy] = {
    "main": ScreenPolicy(
        state_attr=None, surface=None,
        open=DialDisplay._open_main_locked, paint=None, paged=False,
        inactivity_timeout_s=None, touch_extends_timeout=False,
        when_nothing_plays=IDLE_KEEP, defers_sleep=False,
        close_reveals_overlay=False, closes_on_focus_clear=False, back_to="main",
    ),
    "selector": ScreenPolicy(
        state_attr="_selector", surface=(SURFACE_SELECTOR, False, False, False),
        open=functools.partial(DialDisplay._open_list_locked, screen="selector", keep_page_on_return=True), paint=DialDisplay._display_list_locked, paged=True,
        inactivity_timeout_s=SELECTOR_TIMEOUT_SECONDS, touch_extends_timeout=True,
        when_nothing_plays=IDLE_KEEP, defers_sleep=True,
        close_reveals_overlay=False, closes_on_focus_clear=False, back_to="main",
    ),
    "picker": ScreenPolicy(
        state_attr="_picker", surface=(SURFACE_PICKER, False, False, False),
        open=functools.partial(DialDisplay._open_list_locked, screen="picker"), paint=DialDisplay._display_list_locked, paged=True,
        # Touch activity extends every list screen's clock.
        inactivity_timeout_s=SELECTOR_TIMEOUT_SECONDS, touch_extends_timeout=True,
        when_nothing_plays=IDLE_KEEP, defers_sleep=True,
        close_reveals_overlay=False, closes_on_focus_clear=False, back_to="main",
    ),
    "info": ScreenPolicy(
        state_attr="_info", surface=(SURFACE_INFO, False, False, False),
        open=DialDisplay._open_info_locked, paint=DialDisplay._display_list_locked, paged=True,
        inactivity_timeout_s=SELECTOR_TIMEOUT_SECONDS, touch_extends_timeout=True,
        when_nothing_plays=IDLE_KEEP, defers_sleep=True,
        close_reveals_overlay=False, closes_on_focus_clear=False, back_to="main",
    ),
    # The compact info page's own drill-in — a tapped field's own
    # full-screen value, closed by a tap anywhere (LIST_BACK) or its own
    # timeout, back to the list it opened from at the same page.
    "info_value": ScreenPolicy(
        state_attr="_info_value", surface=(SURFACE_INFO_VALUE, False, False, False),
        open=DialDisplay._open_info_value_locked, paint=DialDisplay._display_info_value_locked, paged=False,
        inactivity_timeout_s=SELECTOR_TIMEOUT_SECONDS, touch_extends_timeout=True,
        when_nothing_plays=IDLE_KEEP, defers_sleep=True,
        close_reveals_overlay=False, closes_on_focus_clear=False, back_to="info",
    ),
    "repeat": ScreenPolicy(
        state_attr="_repeat_screen", surface=(SURFACE_REPEAT, True, True, True),
        open=DialDisplay._open_repeat_locked, paint=DialDisplay._display_repeat_locked, paged=False,
        inactivity_timeout_s=None, touch_extends_timeout=False,
        when_nothing_plays=IDLE_KEEP_WITH_FOCUS, defers_sleep=False,
        close_reveals_overlay=True, closes_on_focus_clear=True, back_to="main",
        # The compact tier's own replaying layout: time/back where DOTS
        # would be, Restart/Stop in place of the enable layout's own row —
        # see GEOMETRY_REPEAT_REPLAY and touch_surface().
        replay_surface=(SURFACE_REPEAT_REPLAY, True, True, False),
    ),
    # The EQ page: a third page, reached from the same dots as the repeat
    # screen (see cycle_pages()), rich/large only. No inactivity timeout —
    # the dots (or the poll's own closes) are its only exit, same as
    # repeat.
    "eq": ScreenPolicy(
        state_attr="_eq", surface=(SURFACE_EQ, True, True, True),
        open=DialDisplay._open_eq_locked, paint=DialDisplay._display_eq_locked, paged=False,
        inactivity_timeout_s=None, touch_extends_timeout=False,
        when_nothing_plays=IDLE_KEEP_WITH_FOCUS, defers_sleep=False,
        close_reveals_overlay=True, closes_on_focus_clear=True, back_to="main",
        bound_to_appliance=True,
    ),
    "outputs": ScreenPolicy(
        state_attr="_outputs", surface=(SURFACE_OUTPUTS, False, False, False),
        open=DialDisplay._open_outputs_locked, paint=DialDisplay._display_list_locked, paged=True,
        inactivity_timeout_s=SELECTOR_TIMEOUT_SECONDS, touch_extends_timeout=True,
        when_nothing_plays=IDLE_KEEP, defers_sleep=True,
        close_reveals_overlay=False, closes_on_focus_clear=True, back_to="main",
        bound_to_appliance=True,
    ),
    "output": ScreenPolicy(
        state_attr="_output_detail", surface=(SURFACE_OUTPUT, True, False, False),
        open=DialDisplay._open_output_locked, paint=DialDisplay._display_output_locked, paged=False,
        inactivity_timeout_s=SELECTOR_TIMEOUT_SECONDS, touch_extends_timeout=True,
        when_nothing_plays=IDLE_KEEP, defers_sleep=True,
        close_reveals_overlay=False, closes_on_focus_clear=True, back_to="outputs",
        bound_to_appliance=True,
    ),
    # The warnings card: reached from the bell, one entry at a time. Closed
    # by Close, by its entries clearing or by its own timeout, and (like the
    # idle screen it sits over) it lets the panel sleep. Its touch surface
    # is the card for the entry's button count (see touch_surface()).
    "warnings": ScreenPolicy(
        state_attr="_warnings_page", surface=None,
        open=DialDisplay._open_warnings_locked, paint=DialDisplay._display_card_locked, paged=False,
        inactivity_timeout_s=SELECTOR_TIMEOUT_SECONDS, touch_extends_timeout=True,
        when_nothing_plays=IDLE_KEEP, defers_sleep=False,
        close_reveals_overlay=False, closes_on_focus_clear=False, back_to="main",
    ),
    # "Restarting...": nothing tappable; ends when the reboot takes the
    # panel down, or falls back to main after RESTARTING_TIMEOUT_SECONDS if
    # the reboot request failed.
    "restarting": ScreenPolicy(
        state_attr="_restarting", surface=(SURFACE_RESTARTING, False, False, False),
        open=DialDisplay._open_restarting_locked, paint=DialDisplay._display_restarting_locked, paged=False,
        inactivity_timeout_s=RESTARTING_TIMEOUT_SECONDS, touch_extends_timeout=False,
        when_nothing_plays=IDLE_KEEP, defers_sleep=True,
        close_reveals_overlay=False, closes_on_focus_clear=False, back_to="main",
    ),
}


def _card_surface(buttons: int) -> str:
    """The touch surface of a card with *buttons* buttons (one to three)."""
    return (SURFACE_CARD1, SURFACE_CARD2, SURFACE_CARD3)[min(3, buttons) - 1]


def _status_policy_row(desc: WarningDescriptor) -> ScreenPolicy:
    """The policy row of a status page: opened by the warning manager,
    painted from its descriptor, closed by its Close button or by its source
    clearing the condition. No inactivity timeout: a status stays until
    acted on or cleared. defers_sleep=False: the page sleeps with the normal
    idle timer like the screen it sits over, and comes back on wake if still
    due. Its touch surface is the card for its button count, or the inert
    one named after it when it has none."""
    surface = _card_surface(len(desc.buttons)) if desc.buttons else desc.screen
    return ScreenPolicy(
        state_attr="_warning_screen", surface=(surface, False, False, False),
        open=functools.partial(DialDisplay._open_status_locked, warning_id=desc.id),
        paint=DialDisplay._display_card_locked, paged=False,
        inactivity_timeout_s=None, touch_extends_timeout=False,
        when_nothing_plays=IDLE_KEEP, defers_sleep=False,
        close_reveals_overlay=False, closes_on_focus_clear=False, back_to="main",
    )


for _desc in WARNING_DESCRIPTORS:
    if _desc.kind == KIND_STATUS:
        SCREEN_POLICIES[_desc.screen] = _status_policy_row(_desc)
del _desc


def _policy(name: str) -> ScreenPolicy:
    """The policy row for screen/request name *name*. An unknown name is a
    programming error and raises KeyError — no runtime path can produce one,
    since self._screen and every screen request are only ever set to a
    table key by the entry points above."""
    return SCREEN_POLICIES[name]


def create_dial_display(cfg, core) -> DialDisplay:
    """Build the display manager for dial_main.py wiring, painting *core*
    (built, started and stopped by the caller).

    Builds the backend factory from the configured profile (cfg.display.
    screen_type) at startup, falling back to the default profile if the key
    is unresolvable; whether it is ever opened is controlled by the fitted
    flag in DialDisplay.enable()/update_config(), not by this factory
    choice. Also wires the screen_type -> factory resolver so a live
    screen_type change can rebuild and swap the backend without a restart.
    """
    return DialDisplay(
        config=cfg.display,
        backend_factory=backend_factory_for(cfg.display.screen_type),
        backend_factory_builder=backend_factory_for,
        core=core,
    )
