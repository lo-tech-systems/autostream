"""dial_display.py — Dial display manager facade.

Owns threading, fallback policy (logo vs artwork), image identity dedupe,
error handling, and the no-op path for display-disabled installs. Consumes
the mDNS display-selection helper get_display_targets() — never the volume
fan-out get_playing_targets(), which is unrelated and unaffected by display
state.

Authorization gating reads target.auth (stamped by dial_mdns from dial_auth):
a confirmed 412 (unauthorized) is skipped for display purposes; an unknown or
authorized row is polled normally. This manager is one of the writers of
dial_auth's map (via _apply_status_to_auth, from both the sequential poll and
the concurrent reconcile pass) but never the sole source of truth for it — a
push notification and the mDNS browser's own sightings write it too.

Display failure must always degrade to a no-op display; it must never affect
volume control. Backend hardware code lives in dial_display_adafruit.py;
Pillow-only image policy lives in dial_display_image.py.

This manager also feeds dial_repeat_store's per-appliance repeat/replay
belief, from the same two poll paths that feed the auth map: the sequential
artwork walk (6 s cadence for the focused/reporting appliance) and the
concurrent reconcile pass (60 s cadence, run over the merged roster —
dial_mdns.get_roster() — so idle appliances are covered too, through
enrich_targets() only; an idle row never becomes the artwork base and never
sets _now_playing). The roster and the repeat store are display-side only —
they are never read by the volume or mute resolvers.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import dataclasses
import hashlib
import logging
import os
import sys
import threading
import time
from dataclasses import dataclass

from dial_auth import (
    AUTH_AUTHORIZED,
    AUTH_UNAUTHORIZED,
    OUTCOME_AUTHORIZED,
    OUTCOME_TRANSIENT,
    OUTCOME_UNAUTHORIZED,
    auth_map,
)
from dial_display_compositor import (
    LOOP_GLYPH,
    DialDisplayCompositor,
    ListState,
    OverlayState,
    RepeatViewState,
    format_mmss,
)
from dial_display_image import (
    MAX_ARTWORK_RESPONSE_BYTES,
    decode_artwork,
    load_logo,
)
from dial_display_profiles import (
    DEFAULT_PROFILE_KEY,
    UnknownDisplayProfileError,
    get_profile,
)
from dial_mdns import appliance_display_name
from dial_mdns import get_roster as _default_get_roster
from dial_repeat import _RepeatTarget, enqueue_arm, enqueue_transport
from dial_repeat_store import parse_repeat_object, repeat_store
from dial_target_status import enrich_targets, fetch_target_status
from dial_touch_layout import TouchZone, list_layout_for
from dial_volume import (
    is_muted,
    note_master_volume_positive,
    observe_master_volume,
    select_volume_target,
    shown_volume,
)

# The artwork fetch is shared with the OwnTone metadata publisher, which also
# turns provider URLs into images. It faces the open internet, so it lives in
# one place rather than being copied here (see core/autostream_artwork.py).
# The dial deployment copies core modules alongside the dial package; in the
# repo they live in core/, which may or may not be on sys.path.
try:
    from autostream_artwork import artwork_url_eligible, fetch_artwork
except ImportError:
    _core = os.path.join(os.path.dirname(__file__), '..', 'core')
    sys.path.insert(0, os.path.abspath(_core))
    from autostream_artwork import artwork_url_eligible, fetch_artwork

DEFAULT_DISPLAY_LOGO_PATH = "/opt/autostream/images/autostream-logo-centred-dark.png"
# Shown on the idle screen in place of the plain logo whenever a held
# recording can be replayed (the arrows-on-disc "replay available" logo).
DEFAULT_DISPLAY_REPLAY_LOGO_PATH = "/opt/autostream/images/autostream-logo-replay-dark.png"

# Fallback compose dimensions for when no backend is open yet (or it just
# closed) — the default profile's landscape 160x128, matching today's only
# shipped panel.
_DEFAULT_PANEL_WIDTH = get_profile(DEFAULT_PROFILE_KEY).width
_DEFAULT_PANEL_HEIGHT = get_profile(DEFAULT_PROFILE_KEY).height

DISPLAY_POLL_INTERVAL_SECONDS = 6
DIAL_STATUS_TIMEOUT_SECONDS = 2.0
ARTWORK_FETCH_TIMEOUT_SECONDS = 2.0
DISPLAY_IDLE_SLEEP_SECONDS = 15 * 60
RECONCILE_INTERVAL_SECONDS = 60
# How long the appliance-selector screen stays open with no touch activity
# before it closes back to the main (now-playing) screen. Refreshed by any
# touch activity while open — see _apply_touch_activity_locked. The replay
# picker uses the same timeout; the repeat screen has none of its own — see
# _check_secondary_timeout.
SELECTOR_TIMEOUT_SECONDS = 18

# How long a picker-started replay's manual focus is held "pending" while
# the appliance has not yet reached the playing set — see
# set_manual_focus_pending() and the empty-targets branch of _poll_once.
FOCUS_PENDING_GRACE_S = 10.0

# The fixed inter-loop gap the appliance's replay engine inserts between
# the end of a buffer and its restart — used only to wrap the locally
# interpolated Replaying-line position between polls (see
# _interpolate_repeat_position()). Purely cosmetic: the next status poll
# always corrects any drift this produces.
_REPEAT_LOOP_GAP_S = 1.5

# The repeat screen's position counter is deliberately shown this far
# behind the true (interpolated or daemon-reported) playback position —
# there is roughly this much latency in the audio chain between a
# restart/seek landing and sound actually reaching the listener, so
# showing the raw position would read as running ahead of what is heard.
# Applied to the "replaying" layout's line only (clamped at zero — see
# _build_repeat_view_locked); the "hold" layout already reads "0:00" with
# nothing further to subtract, and the duration side of "m:ss / m:ss" is
# never touched by this.
REPEAT_COUNTER_LATENCY_S = 2.0


def _fetch_artwork(url: str, timeout: float) -> tuple[bytes | None, str]:
    """Fetch artwork for the panel, at the dial's own size ceiling."""
    return fetch_artwork(url, timeout, MAX_ARTWORK_RESPONSE_BYTES)


def _row_is_replaying(appliance_id: str, now: float) -> bool:
    """True when appliance_id's fresh repeat-store record shows it
    replaying or fading out — the appliance-selector row's loop-glyph
    marker. Pure, no lock beyond the store's own leaf lock."""
    rec = repeat_store.get(appliance_id, now)
    return rec is not None and rec.state in ("replaying", "fading_out")


def _interpolate_repeat_position(rec, now: float) -> float:
    """Local interpolation of the repeat screen's Replaying-line playback
    position between polls: advances the last observed position by elapsed
    wall time and wraps at the loop boundary (the buffer's duration plus
    the fixed inter-loop gap). No network call is added for this — the
    next status poll always corrects any drift. Never negative."""
    pos = rec.position_seconds + (now - rec.observed_at)
    dur = rec.duration_seconds
    if dur > 0:
        pos = pos % (dur + _REPEAT_LOOP_GAP_S)
        pos = min(pos, dur)
    return max(0.0, pos)


# ---------------------------------------------------------------------------
# Rate-limited logging
# ---------------------------------------------------------------------------

class _RateLimitedLogger:
    """Emits the first occurrence and every 10th consecutive repeat of a key.

    A different key resets the count so its own first occurrence is visible
    immediately, per the dial logging policy.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_key: str | None = None
        self._count = 0

    def log(self, level: int, key: str, msg: str, *args) -> None:
        with self._lock:
            if key != self._last_key:
                self._last_key = key
                self._count = 1
            else:
                self._count += 1
            should_log = self._count == 1 or self._count % 10 == 0
        if should_log:
            logging.log(level, msg, *args)


def _url_log_key(url: str) -> str:
    """Short, non-reversible identifier for a provider URL, safe at INFO/WARNING."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]


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


@dataclass(frozen=True)
class NowPlaying:
    """Now-playing state for the overlay, as last observed by the poll
    thread. Immutable — a changed poll result produces a new instance rather
    than mutating this one, which is what makes the `!=` comparison in
    _poll_once() a reliable "did anything worth repainting change" check.
    """
    service_name: str
    artist: str
    title: str          # track title, drawn on the title line above the artist
    master_volume: int | None


@dataclass(frozen=True)
class SelectorRow:
    """One row of the appliance-selector screen — see SelectorState."""
    appliance_id: str
    label: str        # appliance_display_name(service_name)
    current: bool     # this row is the focus (manual, else the reporting-from target)
    replaying: bool = False  # a fresh repeat-store record shows it replaying/fading out


@dataclass(frozen=True)
class SelectorState:
    """Immutable snapshot of the appliance-selector screen's rows and
    paging, as last built by the poll thread (_refresh_selector_rows).

    rows: every AUTHORIZED, rostered (playing), identified appliance — see
        _refresh_selector_rows for the exact filter. ALL rows across every
        page, not just the current one; the compositor's ListState (built
        separately, at repaint time) slices out the current page.
    page: the current page index. Preserved across each rebuild (clamped to
        the new row count) so an open selector's page does not jump back to
        0 every ~6s poll tick; reset to 0 only when the selector is freshly
        opened (see open_selector()/_apply_screen_requests_locked()).
    opened_at: monotonic time of the open, or of the last touch activity
        while open (see _apply_touch_activity_locked) — what
        SELECTOR_TIMEOUT_SECONDS counts down from.
    """
    rows: tuple[SelectorRow, ...]
    page: int
    opened_at: float


@dataclass(frozen=True)
class RepeatScreenState:
    """Immutable snapshot of which appliance the repeat screen is open for
    — built once, when the screen opens (_apply_screen_requests_locked),
    from the last-published roster snapshot. Never rebuilt while the
    screen stays open: the daemon-state content shown on it (armed, the
    Replaying line, ...) comes fresh from the repeat store on every
    repaint instead — see _build_repeat_view_locked."""
    appliance_id: str
    service_name: str
    ip: str
    port: int
    opened_at: float


@dataclass(frozen=True)
class PickerRow:
    """One row of the replay picker — see PickerState."""
    appliance_id: str
    service_name: str
    ip: str
    port: int
    label: str        # appliance_display_name(service_name)
    seconds: float     # recording_seconds — the held buffer's length


@dataclass(frozen=True)
class PickerState:
    """Immutable snapshot of the replay picker's rows and paging — the
    picker's counterpart to SelectorState. rows: every held, authorized, repeat-
    capable appliance, ALL pages (see _refresh_picker_rows); page: the
    current page, preserved across each rebuild the same way SelectorState
    preserves it; opened_at: what SELECTOR_TIMEOUT_SECONDS counts down
    from."""
    rows: tuple[PickerRow, ...]
    page: int
    opened_at: float


# ---------------------------------------------------------------------------
# Backend protocol
# ---------------------------------------------------------------------------

class DisplayBackend:
    name = "backend"
    # Sourced from the default profile rather than hardcoded — these were
    # previously 128/160, the transpose of the real landscape panel (see
    # dial_display_profiles.py for why the panel is 160 wide x 128 tall).
    width = _DEFAULT_PANEL_WIDTH
    height = _DEFAULT_PANEL_HEIGHT

    def open(self) -> None: ...

    def close(self) -> None: ...

    def clear(self) -> None: ...

    def display(self, image) -> None: ...

    def sleep(self) -> None: ...

    def wake(self) -> None: ...


class NoOpBackend(DisplayBackend):
    name = "noop"
    width = _DEFAULT_PANEL_WIDTH
    height = _DEFAULT_PANEL_HEIGHT

    def open(self) -> None:
        pass

    def close(self) -> None:
        pass

    def clear(self) -> None:
        pass

    def display(self, image) -> None:
        pass

    def sleep(self) -> None:
        pass

    def wake(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Display manager
# ---------------------------------------------------------------------------

class DialDisplay:
    def __init__(
        self,
        config,
        get_display_targets,
        dial_id: str,
        logo_path: str = DEFAULT_DISPLAY_LOGO_PATH,
        replay_logo_path: str = DEFAULT_DISPLAY_REPLAY_LOGO_PATH,
        backend_factory=NoOpBackend,
        backend_factory_builder=None,
        get_roster=_default_get_roster,
    ) -> None:
        self._lock = threading.Lock()
        self._config = config
        self._get_display_targets = get_display_targets
        # Merged playing+idle roster, injected like get_display_targets
        # above (default dial_mdns.get_roster, for tests). Read only by the
        # poll thread — the artwork walk and the reconcile pass — never by
        # the volume/mute resolvers.
        self._get_roster = get_roster
        self._dial_id = dial_id
        self._logo_path = logo_path
        self._replay_logo_path = replay_logo_path
        self._backend_factory = backend_factory
        # Optional screen_type -> zero-arg-backend-factory resolver, used to
        # rebuild self._backend_factory on a live screen_type swap. Left as
        # an injected callable (rather than importing a concrete backend
        # module here) so this facade stays free of hardware-specific
        # coupling; create_dial_display() supplies the real profile-driven
        # resolver, and tests that never swap can leave this unset.
        self._backend_factory_builder = backend_factory_builder
        # Pixel work (artwork fit, rotate, BGR) lives entirely in the
        # compositor; this manager does I/O (fetch, decode, load_logo) and
        # hands finished/raw bases to it. The compositor is stateless — one
        # shared instance is safe.
        self._compositor = DialDisplayCompositor()

        self._backend: DisplayBackend | None = None
        self._backend_name = "noop"
        # Profile key of the backend actually open right now ("" when none).
        # Distinct from self._config.screen_type, which is what was REQUESTED.
        self._active_screen_type = ""
        self._backend_open = False
        self._backend_loaded = False
        self._showing = "noop"
        self._last_error = ""
        self._last_error_at: float | None = None

        # Artwork identity dedupe state — only the current rendered image is
        # kept in memory; nothing persists across restart.
        self._source_artwork_url = ""
        self._current_rendered_image = None

        # Idle/sleep state — set while the display has shown the logo with no
        # playing targets on the network; cleared on any activity or disable.
        self._idle_started_at: float | None = None
        self._display_sleeping = False

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._log_limiter = _RateLimitedLogger()

        # ---- Touch overlay plumbing -----------------------------------
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
        self._overlay_snapshot_lock = threading.Lock()
        self._overlay_snapshot = OverlayState()
        self._overlay_signal = threading.Event()
        # Set by notify_touch_activity() (touch thread, lock-free); consumed
        # by the repaint thread under self._lock.
        self._touch_activity_pending = False
        self._repaint_thread: threading.Thread | None = None
        self._repaint_stop_event = threading.Event()
        # The last base image handed to _display_locked (pre-overlay,
        # pre-rotate/BGR) — logo or panel-fitted artwork. The repaint thread
        # recomposes THIS against the newest overlay snapshot when only the
        # overlay changed, so a poll-driven frame is never required just to
        # show/update/hide the overlay.
        self._current_base_image = None

        # Now-playing state for the overlay. Written only by the poll thread
        # (_poll_once), read by the repaint/poll threads under self._lock at
        # compose time and by the HTTP/touch threads lock-free — a plain
        # object-reference read, same discipline as _overlay_snapshot above.
        self._now_playing: NowPlaying | None = None
        # mDNS service name of the display's chosen artwork source, or None.
        # Read by the volume worker via current_source_service_name().
        self._source_service_name: str | None = None
        # Whether _current_base_image is artwork (True) or the logo (False).
        # Written only under self._lock (by _display_locked's is_artwork_base
        # parameter, or directly by the backend-lifecycle methods that leave
        # nothing on screen); read lock-free by persistent_overlay_shown()
        # and _effective_overlay_locked(), same discipline as the other
        # touch-overlay-plumbing fields above — a plain bool read is atomic.
        self._current_base_is_artwork = False

        # Non-composited-state notification (screen cleared or asleep) for
        # the touch side to observe — see _mark_noncomposited_locked().
        self._noncomposited_event = threading.Event()
        self._noncomposited_generation = 0

        # ---- Auth, focus and push plumbing ----------------------------
        # Poll-thread wake: replaces the plain _stop_event.wait(6) so a
        # push or a focus change can run a poll now instead of at the next
        # tick. Set from any thread; cleared by the poll thread.
        self._poll_wake = threading.Event()
        # Push queue: appliance_ids whose auth changed, per the appliance's
        # advisory POST /auth-changed. Guarded by a LEAF lock (never nested
        # with self._lock, never held across I/O); drained by the poll
        # thread. A set, so a burst of pushes for one id collapses to one
        # probe.
        self._push_lock = threading.Lock()
        self._push_pending: set[str] = set()
        # Reconcile bookkeeping (poll thread only, except for the wake-pass
        # writes from the repaint thread noted at their call sites).
        self._last_reconcile_at = 0.0
        self._reconcile_due = True          # first tick reconciles
        # The appliance_ids that were playing on the previous poll tick, so
        # the poll can notice when one stops and reconcile immediately (poll
        # thread only). See _poll_once: a shrinking playing set forces a
        # reconcile so a just-ended source's retained-recording ("hold")
        # state and now-idle authorization reach the idle screen and replay
        # picker within one tick, not at the next 60s reconcile.
        self._prev_playing_ids: set[str] = set()
        # Manual focus: appliance_id chosen by the user, or None for
        # auto-pick. Read and cleared by the poll thread; set by
        # selector_pick() below (the touch thread, via dial_main's
        # on_zone_tap dispatch for a LIST_ROW tap). Plain reference
        # read/write, same discipline as _overlay_snapshot. Never persisted.
        self._manual_focus_id: str | None = None
        # Manual-focus pending grace (a picker-started replay's focus, set
        # by set_manual_focus_pending()): (appliance_id, service_name,
        # expires_at monotonic), or None. Written by the touch thread and
        # the poll thread; plain reference assignment, same discipline as
        # _manual_focus_id itself.
        self._focus_pending: tuple[str, str, float] | None = None
        # Reporting/focused appliance_id for THIS poll tick — written only
        # by the poll thread alongside _now_playing, read lock-free by the
        # touch thread's toggle_repeat_screen()/repeat_*_tap() entries (the
        # same discipline _source_service_name already uses) so they know
        # which appliance the repeat screen would open for without needing
        # a manual focus to be set.
        self._reporting_appliance_id: str | None = None
        # Last-published merged roster (dial_mdns.get_roster()), written by
        # the poll thread every tick; read under self._lock by the repeat
        # thread when building a RepeatScreenState (_build_repeat_screen_
        # locked) — the one place outside the poll thread that needs a
        # RosterEntry's ip/port/service_name for a given appliance_id.
        self._last_roster: list = []
        # Whether the repeat screen's dots are currently tappable — the
        # main and repeat surfaces share this one gate (mirrors
        # dial_touch.TouchStateMachine's own _dots_active). Computed by the
        # poll thread each tick (_poll_once); read lock-free by
        # touch_surface() and _effective_overlay_locked().
        self._dots_active = False
        # Whether the idle screen's "tap to replay" affordance is currently
        # drawn — poll thread only (_refresh_idle_affordance); read by
        # _render_logo_locked/_display_idle_locked (under self._lock) and by
        # touch_surface() (lock-free, same discipline as _idle_started_at).
        self._idle_affordance = False

        # ---- Selector, repeat and picker screen state -------------------
        # self._screen is written under self._lock — usually by the repaint
        # thread (_apply_screen_requests_locked()/_close_secondary_locked()),
        # occasionally by the poll thread (the empty-target branch,
        # _sleep_locked) — and read lock-free elsewhere (a plain str read is
        # atomic) — same discipline as _current_base_is_artwork.
        # "main": the now-playing screen. "selector": the appliance list.
        # "repeat": the repeat screen. "picker": the replay picker.
        self._screen = "main"
        # Last-built rows, refreshed every poll tick regardless of whether
        # the selector is actually open (_refresh_selector_rows) so opening
        # it never waits on a poll; published under self._lock. None until
        # the first poll runs.
        self._selector: SelectorState | None = None
        # The repeat screen's own state — built once when it opens (see
        # RepeatScreenState); None while the main/selector/picker screen is
        # showing. Written by the repeat thread under self._lock, read
        # lock-free by the touch thread's repeat_toggle_tap()/repeat_start_
        # tap()/repeat_stop_tap() entries.
        self._repeat_screen: RepeatScreenState | None = None
        # The replay picker's own rows/paging — refreshed every poll tick
        # regardless of whether it is open, mirroring self._selector.
        self._picker: PickerState | None = None
        # The zone currently pressed on a secondary screen's own chassis
        # (the repeat screen or the idle affordance) — written by the touch
        # thread via set_secondary_pressed(), read at compose time by
        # _build_repeat_view_locked(). Plain attribute, same discipline as
        # dial_touch's own pressed-zone tracking.
        self._secondary_pressed: "TouchZone | None" = None
        # One-shot: set (by toggle_repeat_screen(), when the repeat screen
        # closes via a DOTS tap) and consumed (by TouchEventSource._poll_
        # surface(), via consume_repeat_close_reveal() below) exclusively
        # on the touch thread — both the setter and the getter run there,
        # so this needs no lock at all, unlike almost everything else this
        # class shares between threads. Tells the touch side to reveal the
        # main screen's volume overlay on return, instead of leaving bare
        # artwork on screen (item 1 of the repeat screen's touch design —
        # see toggle_repeat_screen() and dial_touch.TouchStateMachine.
        # force_overlay_visible()).
        self._repeat_close_reveal = False
        # Touch-thread requests (open_selector/close_list/list_page/
        # toggle_repeat_screen/open_picker) are flag writes only — plain
        # str/int, no lock — folded into self._screen/self._selector/
        # self._repeat_screen/self._picker by the repeat thread
        # (_apply_screen_requests_locked), the same pattern
        # _touch_activity_pending uses. None means "no pending request".
        self._screen_request: str | None = None
        self._page_request = 0

    # ---- lifecycle -------------------------------------------------------

    def start(self) -> None:
        with self._lock:
            if self._config.fitted:
                self._enable_locked()
        self._stop_event.clear()
        self._repaint_stop_event.clear()
        try:
            self._thread = threading.Thread(target=self._run, daemon=True, name="dial-display")
            self._thread.start()
        except Exception as e:
            # Must never prevent the rest of dial_main.py's startup/shutdown
            # sequence (volume control, mDNS, control socket) from running.
            logging.warning("dial display: failed to start polling thread: %s", e)
            self._thread = None
        try:
            self._repaint_thread = threading.Thread(
                target=self._repaint_run, daemon=True, name="dial-display-repaint",
            )
            self._repaint_thread.start()
        except Exception as e:
            logging.warning("dial display: failed to start repaint thread: %s", e)
            self._repaint_thread = None

    def stop(self) -> None:
        self._stop_event.set()
        self._repaint_stop_event.set()
        # Wake the repaint thread out of its Event.wait() so it notices
        # _repaint_stop_event promptly rather than at its next timeout tick.
        self._overlay_signal.set()
        # Likewise for the poll thread's _poll_wake.wait().
        self._poll_wake.set()
        if self._thread is not None:
            try:
                self._thread.join(timeout=2)
            except RuntimeError:
                # Thread.start() had not finished registering when stop() ran
                # right behind it — the daemon thread still exits on its own
                # once _stop_event is set.
                pass
        if self._repaint_thread is not None:
            try:
                self._repaint_thread.join(timeout=2)
            except RuntimeError:
                pass
        with self._lock:
            self._disable_locked()

    # ---- public facade -----------------------------------------------------

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

    def update_config(self, config) -> dict:
        with self._lock:
            old_config = self._config
            self._config = config
            screen_type_changed = old_config.screen_type != config.screen_type
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
                    redisplay_changed = (
                        old_config.fitted and not screen_type_changed
                        and (
                            old_config.rotate != config.rotate
                            or old_config.bgr != config.bgr
                            or old_config.always_show_controls != config.always_show_controls
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

    def display(self, image) -> None:
        with self._lock:
            self._display_locked(image)

    # ---- touch overlay facade ---------------------------------------------

    def notify_touch_activity(self) -> None:
        """Tell the display that touch activity happened right now.

        Mirrors the two lines _poll_once() already runs when it finds
        playing targets present (see the `if targets:` branch below):
        resets the idle countdown and, if asleep, wakes.

        Deliberate consequence: this does NOT disable idle sleep, only
        resets it. With nothing playing, the very next poll tick (up to
        DISPLAY_POLL_INTERVAL_SECONDS later) finds no targets and restarts
        the idle countdown from this moment. A user who keeps touching the
        overlay for longer than DISPLAY_IDLE_SLEEP_SECONDS while nothing
        plays will still eventually see the display sleep underneath them —
        touch resets idle, it does not disable sleep.

        Takes NO lock: this runs on the touch thread, which must never block
        on self._lock (it can be held across a whole SPI frame push, which
        would stall the very volume step the user is asking for). The actual
        idle reset and wake are applied by the repaint thread, which already
        holds self._lock when it composes — see _apply_touch_activity_locked.
        Setting the flag and signalling are both single atomic operations.
        """
        self._touch_activity_pending = True
        self._overlay_signal.set()

    def _apply_touch_activity_locked(self) -> bool:
        """Apply a pending touch-activity notification. Caller holds
        self._lock; runs on the repaint thread, not the touch thread.

        Returns True when this call actually woke the display from sleep —
        the caller uses that to run the reconcile-on-wake side effects
        (auth_map.force_due(), _poll_wake.set()) AFTER releasing self._lock,
        since those must never be reached while self._lock is held (leaf
        locks are never nested with it in either direction).
        """
        if not self._touch_activity_pending:
            return False
        self._touch_activity_pending = False
        self._idle_started_at = None
        if self._screen == "selector" and self._selector is not None:
            # Any touch activity while the selector is open extends its
            # inactivity timeout — see SELECTOR_TIMEOUT_SECONDS and the
            # _repaint_run timeout branch below.
            self._selector = dataclasses.replace(self._selector, opened_at=time.monotonic())
        if self._display_sleeping:
            self._wake_locked()
            return True
        return False

    def set_overlay(self, state: OverlayState) -> None:
        """Publish a new touch-overlay snapshot and signal the repaint
        thread to recompose/push it.

        Never touches self._lock — see the LOCK ORDER comment in __init__.
        Safe to call from the touch thread at touch cadence: the write here
        is a single leaf-lock-guarded assignment, and the actual compose +
        SPI push happens later, asynchronously, on the repaint thread.
        """
        with self._overlay_snapshot_lock:
            self._overlay_snapshot = state
        self._overlay_signal.set()

    def current_source_service_name(self) -> str | None:
        """mDNS service name of the display's chosen artwork source, or
        None when nothing is identified/playing. Plain reference read, safe
        from any thread; may lag the poll by up to one poll cycle. Used by
        dial_main's volume-target resolver (see _build_volume_targets_fn) so
        a touch/encoder press addresses whatever this dial is showing."""
        return self._source_service_name

    def persistent_overlay_shown(self) -> bool:
        """True while the display is holding the controls overlay visible
        on its own (always_show_controls on, artwork on screen, backend
        open, not asleep, and the MAIN screen is showing — never true while
        the appliance selector is open). Plain attribute reads; the touch
        thread polls this once per loop iteration (see dial_touch.
        TouchEventSource._poll_held_visible, the legacy fallback path) so a
        finger can never arm against controls that are not actually drawn —
        when this turns False (screen went to the logo, went to sleep, the
        setting was turned off, or the selector opened), the touch side is
        forced back to reveal-on-touch within one loop tick."""
        return (
            self._config.always_show_controls
            and self._current_base_is_artwork
            and self._backend_open
            and not self._display_sleeping
            and self._screen == "main"
        )

    def touch_surface(self) -> tuple[str, bool, bool]:
        """(surface, name_active, dots_active) for dial_touch.
        TouchStateMachine.set_surface() — see that module's SURFACES
        paragraph. Polled once per loop iteration by TouchEventSource; a
        plain-attribute read discipline, same as persistent_overlay_shown()
        and noncomposited_generation().

        name_active is true whenever there is a controllable appliance
        currently shown (self._now_playing is not None) — unconditional:
        the appliance name and its tap-zone are always active in that
        case, never gated on how many appliances are authorized. It is
        independent of held/hidden: by the time a second press can sample
        the NAME zone at all, the REVEAL-ONLY FIRST TOUCH rule
        (dial_touch.py) has already made the overlay visible.

        dots_active is true whenever the currently focused/reporting
        appliance has a fresh, available repeat-store record — see
        _poll_once, which computes it into self._dots_active every tick.
        "idle" is reported only while the idle affordance is drawn — a tap
        on a plain logo with nothing held stays reveal-only, as before this
        feature existed.
        """
        if self._screen == "selector":
            return ("selector", False, False)
        if self._screen == "picker":
            return ("picker", False, False)
        if self._screen == "repeat":
            # name_active is unconditionally True here: the repeat screen
            # only ever opens for a focused/reporting appliance (see
            # toggle_repeat_screen()) and closes before that appliance's
            # name could go stale (the empty-target branch of _poll_once
            # always pops the screen before clearing _now_playing), so its
            # own top-band NAME zone is always meaningful while this screen
            # is showing.
            return ("repeat", True, True)
        if self._now_playing is None:
            return ("idle" if self._idle_affordance else "hidden", False, False)
        name_active = True
        dots_active = self._dots_active
        if self.persistent_overlay_shown():
            return ("held", name_active, dots_active)
        return ("hidden", name_active, dots_active)

    def request_repaint(self) -> None:
        """Ask the repaint thread to recompose the current base against the
        latest overlay/now-playing state. Lock-free; used by the volume
        worker's on_readout_changed callback so a fresh readout appears on
        screen without waiting for the next poll or touch event."""
        self._overlay_signal.set()

    def noncomposited_generation(self) -> int:
        """Current non-composited-state generation counter.

        Bumped by _mark_noncomposited_locked() whenever the display clears
        or sleeps — the touch side polls this once per loop iteration and,
        on seeing it change, knows whatever overlay/zone geometry it was
        relying on may no longer be on screen. A plain int read — no lock
        needed, matching the read discipline used for the overlay snapshot.
        """
        return self._noncomposited_generation

    # ---- backend lifecycle (caller must hold self._lock) -------------------

    def _enable_locked(self) -> None:
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
        # A successful open clears any stale unrelated failure — today only
        # a successful artwork render did this, so a successful screen_type
        # swap would otherwise keep reporting a stale error and defeat drift
        # detection.
        self._last_error = ""
        self._last_error_at = None
        logging.info(
            "dial display: backend %s open (%dx%d)",
            self._backend_name, backend.width, backend.height,
        )
        # Rendering the logo here is the awake state — reset any stale idle
        # timer/sleep flag from before this open.
        self._idle_started_at = None
        self._display_sleeping = False
        self._render_logo_locked()

    def _rebuild_backend_factory_locked(self, screen_type: str) -> None:
        """Rebuild self._backend_factory for *screen_type* via the injected
        resolver, so the next _enable_locked() opens the right backend.

        A no-op when no resolver was supplied (see backend_factory_builder
        in __init__) — the manager simply keeps using its original factory.
        """
        if self._backend_factory_builder is None:
            return
        self._backend_factory = self._backend_factory_builder(screen_type)

    def _swap_backend_locked(self) -> None:
        """Close the currently open backend and reopen via the (already
        rebuilt) factory — used when screen_type changes while fitted and
        open. If the new backend fails to open, _enable_locked()'s existing
        degrade-to-noop path holds and runtime reflects it.
        """
        if self._backend_open and self._backend is not None:
            try:
                self._backend.close()
            except Exception as e:
                logging.debug("dial display: backend close raised during swap: %s", e)
        self._backend = None
        self._backend_open = False
        self._backend_loaded = False
        self._backend_name = "noop"
        self._active_screen_type = ""
        # Drop the cached frame and its source identity before reopening: it
        # was composed at the OLD panel's dimensions. A successful
        # _enable_locked() renders the logo (which clears these anyway), but
        # on a failed open the stale frame and URL would otherwise survive
        # into the degraded state and be reused by the next poll.
        self._showing = "noop"
        self._source_artwork_url = ""
        self._current_rendered_image = None
        self._current_base_is_artwork = False
        # A reopen after a screen_type swap starts on the main screen, not
        # wherever the list happened to be — the old panel's geometry is
        # gone anyway.
        self._close_secondary_locked()
        self._enable_locked()

    def _disable_locked(self) -> None:
        if self._backend_open and self._backend is not None:
            try:
                self._backend.close()
            except Exception as e:
                logging.debug("dial display: backend close raised: %s", e)
        self._backend = None
        self._backend_open = False
        self._backend_loaded = False
        self._backend_name = "noop"
        self._active_screen_type = ""
        self._showing = "noop"
        self._source_artwork_url = ""
        self._current_rendered_image = None
        self._idle_started_at = None
        self._display_sleeping = False
        self._current_base_is_artwork = False
        # A later re-enable starts on the main screen.
        self._close_secondary_locked()

    def _clear_locked(self) -> None:
        if self._backend_open and self._backend is not None:
            try:
                self._backend.clear()
            except Exception as e:
                logging.debug("dial display: backend clear raised: %s", e)
        self._showing = "noop"
        self._current_base_is_artwork = False
        self._mark_noncomposited_locked()

    def _sleep_locked(self) -> None:
        # Pop to the main screen before the backlight goes off — the
        # appliance list must never be the last thing left on screen
        # (see also the empty-target branch in _poll_once, which is the
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
        self._source_artwork_url = ""
        self._current_rendered_image = None
        self._current_base_is_artwork = False
        logging.info("dial display: idle %ds — sleeping", DISPLAY_IDLE_SLEEP_SECONDS)
        self._mark_noncomposited_locked()

    def _mark_noncomposited_locked(self) -> None:
        """Record that the display just moved to a state with nothing of the
        touch overlay actually on screen (cleared or asleep), for the touch
        side to notice on its own schedule.

        Called from _clear_locked()/_sleep_locked(), both of which run with
        self._lock already held. They must NOT call into the touch session
        synchronously from here: dispatching a "display went dark" action
        would need the touch session to react, and any handler for that
        would want the overlay leaf lock — taking that leaf lock while
        self._lock is held here would be the mirror image of the hazard the
        LOCK ORDER comment forbids from the touch side (leaf lock nested
        inside self._lock). A callback would also mean this thread — which
        may be the HTTP thread inside update_config(), not just the poll
        thread — ends up running touch-session logic synchronously, on a
        thread that has no business owning it.

        A threading.Event plus a monotonically increasing generation counter
        sidesteps both problems: it is pure state, set here and read there,
        with no call ever crossing from this lock into that one. The touch
        thread's own loop polls noncomposited_generation() once per
        iteration and reacts (force back to reveal-only, drop the zone
        latch) on ITS OWN thread, in ITS OWN time.
        """
        self._noncomposited_generation += 1
        self._noncomposited_event.set()

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
        self._source_artwork_url = ""
        logging.info("dial display: activity resumed — waking")

    def _record_error_locked(self, error_id: str) -> None:
        self._last_error = error_id
        self._last_error_at = time.time()

    def _record_error(self, error_id: str) -> None:
        with self._lock:
            self._record_error_locked(error_id)

    def _active_panel_dims(self) -> tuple[int, int]:
        """Return the open backend's panel dimensions, falling back to the
        default profile's dimensions when no backend is open (e.g. between
        close() and the next open()).

        May be called with or without self._lock held. The HTTP thread can
        swap or close the backend concurrently (update_config runs there), so
        the reference is snapshotted into a local before use rather than being
        dereferenced through self — otherwise a swap landing between the
        _backend_open check and the width read would raise on None.

        These dimensions are therefore advisory: a frame composed against them
        can still be superseded by a swap while it is being built. That is why
        the size is re-checked under the lock before the frame is pushed (see
        _show_artwork) — the guard, not this read, is what keeps a wrong-sized
        frame off the panel.
        """
        backend = self._backend
        if self._backend_open and backend is not None:
            return backend.width, backend.height
        return _DEFAULT_PANEL_WIDTH, _DEFAULT_PANEL_HEIGHT

    def _display_locked(self, image, is_artwork_base: bool | None = None) -> None:
        """Compose and write *image* to the backend — the single hand-off
        point every frame reaches on its way to hardware.

        *image* is treated as an already panel-sized base (logo, cached
        artwork, or a freshly artwork-fitted frame — see _show_artwork) — the
        compositor here only applies overlay/rotate/BGR, so
        self._current_rendered_image stays untransformed in the cache and a
        rotate/bgr toggle can re-display it under the new settings without
        re-fetching or re-transforming artwork.

        Every call here — poll-driven or repaint-driven — composes against
        the CURRENT overlay snapshot (read with no lock; see the LOCK ORDER
        comment in __init__), so a poll-driven repaint landing while an
        overlay is visible (e.g. a track change firing mid-touch-session)
        recomposes it back in rather than wiping it. *image* is also cached
        as self._current_base_image so the repaint thread can recompose it
        against a newer overlay snapshot later, without needing a new base
        frame from a poll.

        is_artwork_base: when not None, records whether *image* is artwork
        (True) or the logo (False) into self._current_base_is_artwork before
        composing — this is what persistent_overlay_shown() and the
        held-visible merge in _effective_overlay_locked() key off. None (the
        default) leaves the current value alone, for callers that are only
        re-composing the same base against a newer overlay/rotate/bgr
        setting (e.g. _repaint_current_locked) rather than changing what is
        actually on screen.
        """
        if not (self._backend_open and self._backend is not None):
            return
        if is_artwork_base is not None:
            self._current_base_is_artwork = is_artwork_base
        self._current_base_image = image
        width, height = self._active_panel_dims()
        overlay = self._effective_overlay_locked(self._overlay_snapshot)
        try:
            composed = self._compositor.compose(
                image, width, height,
                rotate=self._config.rotate,
                bgr=self._config.bgr,
                is_artwork=False,
                overlay=overlay,
            )
            self._backend.display(composed)
        except Exception as e:
            self._record_error_locked("display_write_failed")
            self._log_limiter.log(
                logging.WARNING, "display_write_failed",
                "dial display: backend write failed: %s", e,
            )

    def _effective_overlay_locked(self, snapshot: OverlayState) -> OverlayState:
        """Merge now-playing state into the touch-published overlay snapshot
        at compose time.

        The touch side only ever publishes CONTROL state (visible, pressed,
        muted-if-known) via set_overlay() — it has no idea what track is
        playing or what the master volume is, and must not need to, per the
        module docstring's "touch thread stays ignorant of polling" rule.
        This fills in the fields only the poll thread knows about:
          - artist: from the reporting-from target's last poll result.
          - volume: the optimistic readout for that same target (see
            dial_volume.shown_volume()), not the raw polled master_volume —
            the readout already reconciles the polled value with any
            pending delta.
          - muted: the snapshot's own value when the touch side set one
            explicitly, else the current mute belief (dial_volume.is_muted())
            — a reveal that follows a mute from the physical button or an
            earlier touch session must not show the tri-state default.
          - name: appliance_display_name() of the reporting-from target's
            service name, or "" when nothing is playing. ALWAYS populated
            whenever a controllable appliance is shown — per the low-level
            design's Q4, this is unconditional, never gated on how many
            appliances are authorized (the plan's "two or more" wording is
            explicitly withdrawn there).

        held-visible: when always_show_controls is on and artwork is on
        screen (and the display is not asleep), the overlay is forced
        visible here regardless of what the touch-published snapshot says —
        this is what makes a stale visible=False snapshot, or a dismiss
        landing while held, harmless (see dial_touch.py's HELD VISIBLE
        paragraph and set_held_visible()). Deliberately does not also check
        self._backend_open: the caller (_display_locked) already returned
        early when the backend is closed, so there is nothing left to guard
        against here.

        Returns *snapshot* unchanged when it is neither visible nor held:
        compose() already treats an invisible overlay as a strict no-op
        regardless of its other fields, so there is nothing worth merging in
        that case.
        """
        held = (
            self._config.always_show_controls and self._current_base_is_artwork
            and not self._display_sleeping
        )
        if not (snapshot.visible or held):
            return snapshot
        now_playing = self._now_playing
        artist = now_playing.artist if now_playing is not None else ""
        title = now_playing.title if now_playing is not None else ""
        name = appliance_display_name(now_playing.service_name) if now_playing is not None else ""
        volume = shown_volume(now_playing.service_name) if now_playing is not None else None
        muted = snapshot.muted if snapshot.muted is not None else is_muted()
        # Belt and braces: dots are meaningful only on the main screen —
        # _repaint_current_locked never reaches this merge for the repeat/
        # selector/picker screens anyway (they bypass _display_locked
        # entirely), but the explicit screen check here means a stray call
        # can never show them somewhere they should not appear.
        dots = self._dots_active and self._screen == "main"
        return dataclasses.replace(
            snapshot, visible=True, artist=artist, title=title, volume=volume, muted=muted, name=name,
            dots=dots,
        )

    def _redisplay_current_locked(self) -> None:
        """Re-display the current frame synchronously — used when rotate
        changes while already fitted and open, so the new orientation is
        visible immediately rather than at the next poll.
        """
        if not (self._backend_open and self._backend is not None):
            return
        if self._current_rendered_image is not None:
            self._display_locked(self._current_rendered_image, is_artwork_base=True)
        else:
            self._render_logo_locked()

    # ---- logo fallback -------------------------------------------------

    def _render_logo_locked(self) -> None:
        width, height = self._active_panel_dims()
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
        if self._idle_chassis_due_locked():
            # A replay is available: the idle screen's own compose path
            # (the replay-available logo, no volume/mute controls overlay —
            # there is nothing to control) in place of a plain logo. The
            # plain logo is still stored as the base for the fallback path.
            self._current_base_image = image
            self._current_base_is_artwork = False
            self._display_idle_locked()
        else:
            self._display_locked(image, is_artwork_base=False)
        self._source_artwork_url = ""
        self._current_rendered_image = None
        self._showing = "logo"
        if was_showing == "artwork":
            logging.info("dial display: showing logo (no usable artwork)")

    # ---- overlay repaint loop ----------------------------------------------
    #
    # A second, dedicated thread — separate from the poll thread below — so
    # a touch-driven overlay update never waits behind (or gets coalesced
    # with) the display's own 6-second poll cadence, and never has to be
    # dispatched from the touch thread itself (which never takes self._lock;
    # see the LOCK ORDER comment in __init__).

    def _repaint_run(self) -> None:
        while not self._repaint_stop_event.is_set():
            signaled = self._overlay_signal.wait(timeout=1.0)
            if self._repaint_stop_event.is_set():
                break
            if not signaled:
                # Plain timeout — nothing to do beyond the selector/picker's
                # own inactivity check and the Replaying line's once-a-
                # second tick, then go back to waiting. This periodic wake
                # exists only so stop() is noticed promptly even if no
                # overlay signal ever arrives.
                self._check_secondary_timeout()
                self._tick_repeat_line()
                continue
            # Coalesce: clear the event BEFORE doing any work. Any
            # set_overlay() call that lands after this clear() (including
            # one that lands while we are still repainting below, under
            # self._lock) leaves the event set again, so the next
            # iteration's wait() returns immediately — several rapid
            # signals that land before we get here collapse into this one
            # wake, and _display_locked() below always reads whatever the
            # NEWEST snapshot is at the moment it actually composes, not
            # whichever one triggered this particular wake.
            self._overlay_signal.clear()
            with self._lock:
                woke = self._repaint_current_locked()
            if woke:
                # Outside the lock: force_due() takes the leaf dial_auth
                # lock, which must never nest with self._lock.
                self._reconcile_due = True
                auth_map.force_due()
                self._poll_wake.set()

    def _repaint_current_locked(self) -> bool:
        """Recompose and push the current screen — used by the repaint
        thread when only the overlay or the screen itself changed (no new
        poll-driven frame). No-op if the backend is closed.

        Returns True when applying pending touch activity woke the display
        (see _apply_touch_activity_locked) — propagated to the caller so it
        can run the wake-pass side effects outside self._lock.
        """
        # Wake first if touch asked for it, so the backlight is on before
        # the frame is pushed rather than one repaint later.
        woke = self._apply_touch_activity_locked()
        # Fold any pending open_selector()/close_selector()/selector_page()
        # request into self._screen/self._selector before deciding what to
        # paint — see _apply_screen_requests_locked().
        self._apply_screen_requests_locked()
        if not (self._backend_open and self._backend is not None):
            return woke
        if self._screen == "selector":
            self._display_selector_locked()
            return woke
        if self._screen == "repeat":
            self._display_repeat_locked()
            return woke
        if self._screen == "picker":
            self._display_picker_locked()
            return woke
        if self._current_base_image is None:
            return woke
        if self._idle_chassis_due_locked():
            self._display_idle_locked()
            return woke
        self._display_locked(self._current_base_image)
        return woke

    def _idle_chassis_due_locked(self) -> bool:
        """True when the idle screen's own compose path (compose_idle, no
        volume/mute controls overlay) should be used in place of the
        ordinary overlay compose path — exactly when the "tap to replay"
        affordance is due. When nothing is playing but no affordance is
        due, the plain logo goes through the normal reveal-on-touch overlay
        path unchanged, matching the behaviour from before this screen
        existed (see touch_surface(): the touch surface itself stays
        "hidden", not "idle", in that case, so nothing here should look any
        different from it either)."""
        return self._idle_affordance and self._screen == "main" and self._now_playing is None

    # ---- appliance selector, repeat and picker screens ----------------------
    #
    # Touch-thread entry points (open_selector/close_list/list_page/
    # selector_pick/toggle_repeat_screen/repeat_*_tap/open_picker/
    # picker_pick) are flag-write-plus-signal only, exactly like
    # notify_touch_activity()/set_manual_focus() — the actual screen-state
    # change happens on the repeat thread under self._lock
    # (_apply_screen_requests_locked). Rows themselves are built ONLY on the
    # poll thread (_refresh_selector_rows/_refresh_picker_rows) — the touch
    # thread never builds rows, it only reads the last-published state.

    def open_selector(self) -> None:
        """Touch-thread entry (dial_main's on_zone_tap, for a NAME tap).
        Also forces an immediate reconcile/poll so any not-yet-confirmed
        row is checked within about one poll interval of opening, rather
        than left stale for up to 60s."""
        self._screen_request = "selector"
        self._reconcile_due = True
        auth_map.force_due()
        self._poll_wake.set()
        self._overlay_signal.set()

    def close_list(self) -> None:
        """Touch-thread entry (dial_main's on_zone_tap, for a LIST_BACK
        tap): pop back to main from whichever list-chassis screen (the
        appliance selector or the replay picker) is open."""
        self._screen_request = "main"
        self._overlay_signal.set()

    close_selector = close_list  # alias kept for existing direct callers/tests

    def list_page(self, delta: int) -> None:
        """Touch-thread entry (dial_main's on_zone_tap, for a LIST_DOWN/
        LIST_UP tap): +1 for the next page, -1 for the previous, on
        whichever list-chassis screen is open. Clamped to the valid range
        by _apply_screen_requests_locked()."""
        self._page_request += delta
        self._overlay_signal.set()

    selector_page = list_page  # alias kept for existing direct callers/tests

    def selector_pick(self, index: int) -> None:
        """Touch-thread entry: a LIST_ROW tap while the appliance selector
        is open.

        Reads the last-published SelectorState (plain reference read, no
        lock — same discipline as _overlay_snapshot). When *index* still
        falls within the CURRENT page, sets manual focus to that row's
        appliance. A stale index — the row disappeared between paint and
        tap, e.g. the appliance stopped playing — is silently treated as
        "back": no focus change, no error dialog. Either way the selector
        closes.
        """
        selector = self._selector
        if selector is not None and selector.rows:
            page_rows = self._selector_page_rows(selector)
            if 0 <= index < len(page_rows):
                self.set_manual_focus(page_rows[index].appliance_id)
        self.close_list()

    def list_row_tap(self, index: int) -> None:
        """Touch-thread entry (dial_main's on_zone_tap, for a LIST_ROW
        tap): routes to whichever list-chassis screen is actually open —
        the appliance selector (selector_pick) or the replay picker
        (picker_pick)."""
        if self._screen == "picker":
            self.picker_pick(index)
        else:
            self.selector_pick(index)

    def _selector_page_rows(self, selector: SelectorState) -> tuple[SelectorRow, ...]:
        """The CURRENT page's slice of *selector*.rows — shared by
        selector_pick() (touch thread, lock-free) and _build_list_state_
        locked() (repaint thread) so the two can never disagree about which
        rows are on screen. rows_per_page comes from dial_touch_layout, the
        same single source of truth the touch hit-test itself reads."""
        width, height = self._active_panel_dims()
        rows_per_page = list_layout_for(width, height).rows_per_page
        start = selector.page * rows_per_page
        return selector.rows[start:start + rows_per_page]

    def _picker_page_rows(self, picker: PickerState) -> tuple[PickerRow, ...]:
        """The CURRENT page's slice of *picker*.rows — the PickerState
        counterpart to _selector_page_rows()."""
        width, height = self._active_panel_dims()
        rows_per_page = list_layout_for(width, height).rows_per_page
        start = picker.page * rows_per_page
        return picker.rows[start:start + rows_per_page]

    def toggle_repeat_screen(self) -> None:
        """Touch-thread entry (dial_main's on_zone_tap, for a DOTS tap):
        open or close the repeat screen.

        Closing is unconditional, and also arms self._repeat_close_reveal
        — a one-shot flag consumed by TouchEventSource._poll_surface() to
        bring the main screen back showing its volume overlay rather than
        bare artwork (see the flag's own comment in __init__ and
        dial_touch.TouchStateMachine.force_overlay_visible()). Opening
        reads self._now_playing, self._manual_focus_id and
        self._reporting_appliance_id (all plain reference reads, same
        discipline as set_manual_focus()) and the repeat store's own leaf
        lock — it only opens when the focused/reporting appliance has a
        fresh, available record; an appliance this dial cannot see repeat
        state for has nothing to show on the repeat screen. No poll/
        reconcile is forced here: unlike open_selector()/open_picker(), the
        repeat screen's own content is entirely driven by whatever the
        repeat store already holds.
        """
        if self._screen == "repeat":
            self._repeat_close_reveal = True
            self._screen_request = "main"
            self._overlay_signal.set()
            return
        if self._now_playing is None:
            return
        appliance_id = self._manual_focus_id or self._reporting_appliance_id
        if not appliance_id:
            return
        rec = repeat_store.get(appliance_id, time.monotonic())
        if rec is None or not rec.available:
            return
        self._screen_request = "repeat"
        self._overlay_signal.set()

    def consume_repeat_close_reveal(self) -> bool:
        """Touch-thread-only read-and-clear of the one-shot flag
        toggle_repeat_screen() sets when the repeat screen closes via a
        DOTS tap. Both the setter and this getter run exclusively on the
        touch thread (see the flag's own comment in __init__), so no lock
        is needed here at all."""
        value = self._repeat_close_reveal
        self._repeat_close_reveal = False
        return value

    def repeat_toggle_tap(self) -> None:
        """Touch-thread entry (dial_main's on_zone_tap, for a REPEAT_PLAY
        tap): toggle arm/disarm — only meaningful in the enable layout
        (a live source recording/pending, or idle with the daemon still
        enabled); a tap here while the replaying/hold layout is showing
        (no "Repeat Play" row drawn) is a no-op. Enqueues on the repeat
        worker's own queue — no lock, no I/O on this thread."""
        screen = self._repeat_screen
        if screen is None:
            return
        rec = repeat_store.get(screen.appliance_id, time.monotonic())
        if rec is None or not rec.available:
            return
        if rec.state in ("recording", "pending", "idle"):
            enqueue_arm(_RepeatTarget(screen.appliance_id, screen.ip, screen.port), not rec.armed)

    def repeat_start_tap(self) -> None:
        """Touch-thread entry (dial_main's on_zone_tap, for a REPEAT_START
        tap): seek to 0 — restart a running replay, or start one from
        Hold. A no-op while fading out (the appliance would refuse it with
        "fading_out" anyway) or while a live source is recording."""
        screen = self._repeat_screen
        if screen is None:
            return
        rec = repeat_store.get(screen.appliance_id, time.monotonic())
        if rec is None or not rec.available:
            return
        if rec.state in ("replaying", "hold"):
            enqueue_transport(_RepeatTarget(screen.appliance_id, screen.ip, screen.port), "seek", 0.0)

    def repeat_stop_tap(self) -> None:
        """Touch-thread entry (dial_main's on_zone_tap, for a REPEAT_STOP
        tap): stop a running replay (fades out, lands in Hold, disarmed).
        A no-op outside Replaying — while fading out the button is drawn
        pressed and inert, and in Hold there is nothing to stop."""
        screen = self._repeat_screen
        if screen is None:
            return
        rec = repeat_store.get(screen.appliance_id, time.monotonic())
        if rec is None or not rec.available:
            return
        if rec.state == "replaying":
            enqueue_transport(_RepeatTarget(screen.appliance_id, screen.ip, screen.port), "stop", 0.0)

    def set_secondary_pressed(self, zone) -> None:
        """Touch-thread entry: record the zone currently pressed on a
        secondary screen's own chassis (the repeat screen) for the next
        repaint to draw a pressed wash. Plain attribute write plus a
        signal — same discipline as notify_touch_activity()."""
        self._secondary_pressed = zone
        self._overlay_signal.set()

    def pop_secondary(self, screen: str) -> None:
        """Touch-thread entry: pop back to main if *screen* is the one
        currently open — used by the encoder and button paths so a
        physical nudge while the repeat screen is open returns to the
        volume readout on main. Lock-free request, exactly like
        close_list()."""
        if self._screen == screen:
            self._screen_request = "main"
            self._overlay_signal.set()

    def set_manual_focus_pending(self, appliance_id: str, service_name: str) -> None:
        """Touch-thread entry (the replay picker's picker_pick()): pin the
        focus to *appliance_id* the way set_manual_focus() does, and mark
        it PENDING for FOCUS_PENDING_GRACE_S — a picker-started replay has
        not yet reached the playing set, so the ordinary "gone from the
        roster" focus-clear must not fire before it has had a chance to
        appear. See the empty-targets branch of _poll_once."""
        now = time.monotonic()
        self._manual_focus_id = appliance_id
        self._focus_pending = (appliance_id, service_name, now + FOCUS_PENDING_GRACE_S)
        self._poll_wake.set()

    def open_picker(self) -> None:
        """Touch-thread entry (dial_main's on_zone_tap, for an IDLE_REPLAY
        tap). Also forces an immediate reconcile/poll, the same as
        open_selector(), so a row that just went stale is refreshed within
        about one poll interval of opening."""
        self._screen_request = "picker"
        self._reconcile_due = True
        auth_map.force_due()
        self._poll_wake.set()
        self._overlay_signal.set()

    def picker_pick(self, index: int) -> None:
        """Touch-thread entry: start replaying the tapped row's held
        recording from the beginning. A stale index (the row vanished
        between paint and tap) is treated as back, same as
        selector_pick(). Sets a PENDING manual focus (see
        set_manual_focus_pending()) so the screen follows the appliance
        through the gap before its replay reaches the playing set; a
        rejected seek (source_active/no_recording, or any transport
        failure) clears it again in on_repeat_result()."""
        picker = self._picker
        if picker is not None and picker.rows:
            page_rows = self._picker_page_rows(picker)
            if 0 <= index < len(page_rows):
                row = page_rows[index]
                self.set_manual_focus_pending(row.appliance_id, row.service_name)
                enqueue_transport(_RepeatTarget(row.appliance_id, row.ip, row.port), "seek", 0.0)
        self.close_list()

    def _close_secondary_locked(self) -> None:
        """Pop to the main screen from any secondary screen — the
        appliance list, the repeat screen, or the replay picker. Caller
        holds self._lock. Called from the repeat thread's own request-
        folding, from sleep/disable/swap (so a later wake/reopen never
        resumes on a stale secondary screen), from the poll thread when the
        focused appliance changes while the repeat screen is open, and is
        what a stale selector_pick()/picker_pick() index falls back to."""
        self._screen = "main"
        self._selector = None
        self._repeat_screen = None
        self._picker = None
        self._secondary_pressed = None
        self._overlay_signal.set()

    _close_selector_locked = _close_secondary_locked  # alias kept for existing direct callers/tests

    def _build_repeat_screen_locked(self) -> "RepeatScreenState | None":
        """Build a RepeatScreenState for the currently focused/reporting
        appliance from the last-published roster snapshot
        (self._last_roster). Caller holds self._lock; runs on the repeat
        thread only. Returns None when there is no focus/reporting
        appliance right now, or it has since dropped out of the roster —
        either way the screen request is simply dropped and whatever was
        on screen before stays there."""
        appliance_id = self._manual_focus_id or self._reporting_appliance_id
        if not appliance_id:
            return None
        for r in self._last_roster:
            if r.appliance_id == appliance_id:
                return RepeatScreenState(
                    appliance_id=appliance_id, service_name=r.service_name,
                    ip=r.ip, port=r.port, opened_at=time.monotonic(),
                )
        return None

    def _apply_screen_requests_locked(self) -> None:
        """Fold pending open_selector()/close_list()/list_page()/
        toggle_repeat_screen()/open_picker() touch-thread requests into
        self._screen/self._selector/self._repeat_screen/self._picker.
        Caller holds self._lock; runs on the repeat thread only.
        """
        request = self._screen_request
        self._screen_request = None
        delta = self._page_request
        self._page_request = 0

        if request == "selector":
            rows = self._selector.rows if self._selector is not None else ()
            self._selector = SelectorState(rows=rows, page=0, opened_at=time.monotonic())
            self._screen = "selector"
        elif request == "picker":
            rows = self._picker.rows if self._picker is not None else ()
            self._picker = PickerState(rows=rows, page=0, opened_at=time.monotonic())
            self._screen = "picker"
        elif request == "repeat":
            screen = self._build_repeat_screen_locked()
            if screen is not None:
                self._repeat_screen = screen
                self._screen = "repeat"
        elif request == "main":
            self._close_secondary_locked()

        active = (
            self._selector if self._screen == "selector"
            else self._picker if self._screen == "picker"
            else None
        )
        if delta and active is not None:
            width, height = self._active_panel_dims()
            rows_per_page = list_layout_for(width, height).rows_per_page
            row_count = len(active.rows)
            max_page = max(0, (row_count - 1) // rows_per_page) if row_count else 0
            new_page = max(0, min(active.page + delta, max_page))
            if new_page != active.page:
                updated = dataclasses.replace(active, page=new_page)
                if self._screen == "selector":
                    self._selector = updated
                else:
                    self._picker = updated

    def _check_secondary_timeout(self) -> None:
        """Close the appliance selector or the replay picker after
        SELECTOR_TIMEOUT_SECONDS of no touch activity — called from the
        repaint thread's own 1s timeout branch, so this runs even when
        nothing else signals a repaint. The repeat screen has NO timeout
        of its own: it is the device's second screen, a user may be
        watching the Replaying line, and the dots toggle back to main at
        any time.

        self._screen/self._selector/self._picker are read lock-free here:
        all three are also written by the poll thread (_poll_once's
        empty-target branch, _sleep_locked), not only the repeat thread,
        but every write is already under self._lock and each is a plain
        reference/str assignment — the same "a stale read costs at most
        one harmless extra tick" discipline _sleeping_lockfree() documents.
        The actual close below is re-checked and applied under the lock
        regardless.
        """
        if self._screen not in ("selector", "picker"):
            return
        state = self._selector if self._screen == "selector" else self._picker
        if state is None:
            return
        if time.monotonic() - state.opened_at >= SELECTOR_TIMEOUT_SECONDS:
            with self._lock:
                self._close_secondary_locked()

    def _tick_repeat_line(self) -> None:
        """Recompose the repeat screen once a second while it is showing a
        live Replaying position, so the line visibly counts up between
        polls — called from the repeat thread's own 1s timeout branch. No
        HTTP call is added for this: the interpolation is purely local
        (see _interpolate_repeat_position()) and the next poll always
        corrects any drift. A no-op while asleep (the repeat thread does
        nothing then) or when the repeat screen is not the one on screen.
        """
        if self._screen != "repeat":
            return
        screen = self._repeat_screen
        if screen is None:
            return
        rec = repeat_store.get(screen.appliance_id, time.monotonic())
        if rec is not None and rec.state == "replaying":
            self._overlay_signal.set()

    def _refresh_selector_rows(self, targets: list, reporting_id: str | None) -> None:
        """Rebuild the selector's row list from *targets*. Runs on the poll
        thread at the end of every _poll_once, whether or not the selector
        screen is actually open right now, so opening it always shows
        fresh rows without waiting for a poll. The touch thread never
        builds rows.

        Rows: every target with a non-empty appliance_id whose auth is
        AUTHORIZED (not just "not unauthorized" — an unknown appliance is
        controllable but not yet confirmed, so it stays off the list until
        a probe confirms it). *current* marks the manual focus when one is
        set, else the reporting-from target (*reporting_id*). *replaying*
        marks a row whose fresh repeat-store record shows it replaying or
        fading out — drawn as the loop-glyph secondary marker (see
        _build_list_state_locked).

        The page is PRESERVED (clamped to the new row count) across each
        rebuild — resetting it to 0 here would make an open selector jump
        back to its first page every ~6s poll tick. It is reset to 0 only
        by a fresh open_selector() (see _apply_screen_requests_locked).
        """
        focus_id = self._manual_focus_id
        current_id = focus_id if focus_id is not None else reporting_id
        now = time.monotonic()
        rows = tuple(
            SelectorRow(
                appliance_id=t.appliance_id,
                label=appliance_display_name(t.service_name),
                current=(t.appliance_id == current_id),
                replaying=_row_is_replaying(t.appliance_id, now),
            )
            for t in targets
            if t.appliance_id and t.auth == AUTH_AUTHORIZED
        )
        with self._lock:
            prev = self._selector
            width, height = self._active_panel_dims()
            rows_per_page = list_layout_for(width, height).rows_per_page
            max_page = max(0, (len(rows) - 1) // rows_per_page) if rows else 0
            page = max(0, min(prev.page, max_page)) if prev is not None else 0
            opened_at = prev.opened_at if prev is not None else 0.0
            self._selector = SelectorState(rows=rows, page=page, opened_at=opened_at)

    def _refresh_picker_rows(self, roster: list, now: float) -> None:
        """Rebuild the replay picker's row list from *roster* — poll thread
        only, every tick regardless of whether the picker is actually open,
        mirroring _refresh_selector_rows(). Rows: every rostered,
        authorized, repeat-capable appliance currently in Hold — the only
        daemon state the picker can start a replay from. The page is
        preserved across rebuilds the same way the selector's is."""
        rows = tuple(
            PickerRow(
                appliance_id=r.appliance_id, service_name=r.service_name,
                ip=r.ip, port=r.port,
                label=appliance_display_name(r.service_name),
                seconds=rec.recording_seconds,
            )
            for r in roster
            for rec in [repeat_store.get(r.appliance_id, now)]
            if rec is not None and rec.state == "hold"
            and r.auth == AUTH_AUTHORIZED and r.repeat_capable
        )
        with self._lock:
            prev = self._picker
            width, height = self._active_panel_dims()
            rows_per_page = list_layout_for(width, height).rows_per_page
            max_page = max(0, (len(rows) - 1) // rows_per_page) if rows else 0
            page = max(0, min(prev.page, max_page)) if prev is not None else 0
            opened_at = prev.opened_at if prev is not None else 0.0
            self._picker = PickerState(rows=rows, page=page, opened_at=opened_at)

    def _refresh_idle_affordance(self, roster: list, now: float) -> None:
        """Recompute whether the idle screen's "tap to replay" affordance
        should be drawn — poll thread only, every tick regardless of
        whether anything is currently playing. True when at least one
        rostered, authorized, repeat-capable appliance is currently held (a
        retained recording with nothing else to show). A change signals
        the repeat thread so the affordance appears/disappears promptly."""
        held = repeat_store.held_ids(now)
        affordance = any(
            r.appliance_id in held and r.auth == AUTH_AUTHORIZED and r.repeat_capable
            for r in roster
        )
        if affordance != self._idle_affordance:
            self._idle_affordance = affordance
            self._overlay_signal.set()

    def _build_list_state_locked(self, width: int, height: int) -> ListState:
        """Build the compositor's ListState for the CURRENT page. Caller
        holds self._lock; runs on the repeat thread only. Live touch-press
        feedback is not wired into the selector chassis in this phase —
        pressed is always None here (compose_list still supports it, for
        the compositor's own tests). A replaying row's secondary slot
        carries the LOOP_GLYPH sentinel; every other row stays a plain
        2-tuple."""
        selector = self._selector
        if selector is None or not selector.rows:
            return ListState(rows=(("No devices", False),), has_prev=False, has_next=False)
        rows_per_page = list_layout_for(width, height).rows_per_page
        start = selector.page * rows_per_page
        page_rows = selector.rows[start:start + rows_per_page]
        return ListState(
            rows=tuple(
                (row.label, row.current, LOOP_GLYPH) if row.replaying else (row.label, row.current)
                for row in page_rows
            ),
            has_prev=selector.page > 0,
            has_next=start + rows_per_page < len(selector.rows),
        )

    def _build_picker_list_state_locked(self, width: int, height: int) -> ListState:
        """Build the compositor's ListState for the replay picker's CURRENT
        page — the PickerState counterpart to _build_list_state_locked().
        Each row's secondary slot carries the buffer length, formatted
        "m:ss"."""
        picker = self._picker
        if picker is None or not picker.rows:
            return ListState(rows=(("Nothing to replay", False),), has_prev=False, has_next=False)
        rows_per_page = list_layout_for(width, height).rows_per_page
        start = picker.page * rows_per_page
        page_rows = picker.rows[start:start + rows_per_page]
        return ListState(
            rows=tuple((row.label, False, format_mmss(row.seconds)) for row in page_rows),
            has_prev=picker.page > 0,
            has_next=start + rows_per_page < len(picker.rows),
        )

    def _display_selector_locked(self) -> None:
        """Compose and push the selector-screen frame — the compose_list()
        counterpart to _display_locked(). Bypasses _display_locked()
        entirely (that path composes the artwork/overlay screen and would
        overwrite self._current_base_image, which must survive a selector
        visit unchanged so closing it re-paints the same base). Caller
        holds self._lock.
        """
        width, height = self._active_panel_dims()
        list_state = self._build_list_state_locked(width, height)
        try:
            composed = self._compositor.compose_list(
                width, height, list_state,
                rotate=self._config.rotate, bgr=self._config.bgr,
            )
            self._backend.display(composed)
        except Exception as e:
            self._record_error_locked("display_write_failed")
            self._log_limiter.log(
                logging.WARNING, "display_write_failed",
                "dial display: backend write failed: %s", e,
            )

    def _display_picker_locked(self) -> None:
        """Compose and push the replay-picker frame — the compose_list()
        counterpart for the picker, sharing the same list chassis as the
        appliance selector. Caller holds self._lock."""
        width, height = self._active_panel_dims()
        list_state = self._build_picker_list_state_locked(width, height)
        try:
            composed = self._compositor.compose_list(
                width, height, list_state,
                rotate=self._config.rotate, bgr=self._config.bgr,
            )
            self._backend.display(composed)
        except Exception as e:
            self._record_error_locked("display_write_failed")
            self._log_limiter.log(
                logging.WARNING, "display_write_failed",
                "dial display: backend write failed: %s", e,
            )

    def _build_repeat_view_locked(self, screen: "RepeatScreenState | None", now: float) -> RepeatViewState:
        """Build the compositor's RepeatViewState from the repeat store's
        CURRENT record for *screen* — the daemon-state-to-layout mapping:
        no/unavailable record or a live source (recording/pending/idle)
        draws the enable layout (the top band, plus the "Repeat Play" row);
        hold/replaying/fading_out draw the replaying layout (the top band,
        plus the Restart/Stop row and the position line). The row's dot
        marker reads `armed`, never `state` — armed can be true while a
        live source is playing. Caller holds self._lock (called from
        _display_repeat_locked).

        muted/volume feed the top band's display-only readout — the same
        belief/reading the main screen's overlay shows (dial_volume.
        is_muted()/shown_volume()), addressed at *screen*'s own appliance
        rather than whatever the main overlay would currently show, since
        the two screens can disagree about which appliance is focused for
        as long as it takes the next poll to notice a manual focus change.
        """
        pressed = self._secondary_pressed
        if screen is None:
            return RepeatViewState(
                name="", layout="enable", armed=False, line="",
                start_enabled=False, stop_enabled=False, stop_pressed=False, pressed=pressed,
            )
        name = appliance_display_name(screen.service_name)
        muted = is_muted()
        volume = shown_volume(screen.service_name)
        rec = repeat_store.get(screen.appliance_id, now)
        if rec is None or not rec.available:
            return RepeatViewState(
                name=name, layout="enable", armed=False, line="",
                start_enabled=False, stop_enabled=False, stop_pressed=False,
                muted=muted, volume=volume, pressed=pressed,
            )
        if rec.state in ("recording", "pending", "idle"):
            return RepeatViewState(
                name=name, layout="enable", armed=rec.armed, line="",
                start_enabled=False, stop_enabled=False, stop_pressed=False,
                muted=muted, volume=volume, pressed=pressed,
            )
        if rec.state == "hold":
            # Already reads 0:00 — there is nothing running yet for the
            # counter-latency clamp (REPEAT_COUNTER_LATENCY_S) to apply to.
            line = f"0:00 / {format_mmss(rec.recording_seconds)}"
            return RepeatViewState(
                name=name, layout="replaying", armed=rec.armed, line=line,
                start_enabled=True, stop_enabled=False, stop_pressed=False,
                muted=muted, volume=volume, pressed=pressed,
            )
        if rec.state == "replaying":
            pos = _interpolate_repeat_position(rec, now)
            # The counter reads this far behind the true position — see
            # REPEAT_COUNTER_LATENCY_S — clamped at zero so a fresh
            # (re)start reads "0:00" for the first couple of seconds
            # instead of a small negative-turned-huge wrapped value.
            pos = max(0.0, pos - REPEAT_COUNTER_LATENCY_S)
            line = f"{format_mmss(pos)} / {format_mmss(rec.duration_seconds)}"
            return RepeatViewState(
                name=name, layout="replaying", armed=rec.armed, line=line,
                start_enabled=True, stop_enabled=True, stop_pressed=False,
                muted=muted, volume=volume, pressed=pressed,
            )
        # fading_out: the line freezes at the last observed position (no
        # interpolation — the fade is a fixed-length event, not a running
        # clock), Start is dimmed and inert, Stop is drawn pressed to read
        # as "already actioned" rather than merely disabled.
        line = f"{format_mmss(rec.position_seconds)} / {format_mmss(rec.duration_seconds)}"
        return RepeatViewState(
            name=name, layout="replaying", armed=rec.armed, line=line,
            start_enabled=False, stop_enabled=True, stop_pressed=True,
            muted=muted, volume=volume, pressed=pressed,
        )

    def _display_repeat_locked(self) -> None:
        """Compose and push the repeat-screen frame — the compose_repeat()
        counterpart to _display_locked(). Bypasses _display_locked()
        entirely, like _display_selector_locked(): this screen has its own
        compose path and must never pick up the main now-playing overlay.
        Passes self._current_base_image through as compose_repeat()'s
        `base` — the replaying layout draws it (dimmed) behind the
        position counter; the enable layout ignores it. Caller holds
        self._lock."""
        view = self._build_repeat_view_locked(self._repeat_screen, time.monotonic())
        width, height = self._active_panel_dims()
        try:
            composed = self._compositor.compose_repeat(
                width, height, view, base=self._current_base_image,
                rotate=self._config.rotate, bgr=self._config.bgr,
            )
            self._backend.display(composed)
        except Exception as e:
            self._record_error_locked("display_write_failed")
            self._log_limiter.log(
                logging.WARNING, "display_write_failed",
                "dial display: backend write failed: %s", e,
            )

    def _display_idle_locked(self) -> None:
        """Compose and push the idle-screen frame — the "replay available"
        logo (the arrows-on-disc image) in place of the plain logo, with no
        volume/mute controls overlay (nothing is playing, so there is
        nothing on this screen to control). Only ever reached while a replay
        is available (the idle affordance is due; see
        _idle_chassis_due_locked and its call sites in _render_logo_locked/
        _repaint_current_locked), so it always shows the replay logo,
        degrading to the plain base if the replay image cannot be loaded.
        Caller holds self._lock; a no-op if the backend is closed or nothing
        has been rendered yet."""
        if not (self._backend_open and self._backend is not None):
            return
        if self._current_base_image is None:
            return
        width, height = self._active_panel_dims()
        base = load_logo(self._replay_logo_path, width, height) or self._current_base_image
        try:
            composed = self._compositor.compose_idle(
                base, width, height,
                rotate=self._config.rotate, bgr=self._config.bgr,
            )
            self._backend.display(composed)
        except Exception as e:
            self._record_error_locked("display_write_failed")
            self._log_limiter.log(
                logging.WARNING, "display_write_failed",
                "dial display: backend write failed: %s", e,
            )

    # ---- polling loop ----------------------------------------------------

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self._poll_wake.clear()
            try:
                pushed = self._drain_push_probes()
                if not self._sleeping_lockfree() or pushed == "woke":
                    self._poll_once()
            except Exception:
                logging.debug("dial display: poll iteration raised", exc_info=True)
            # Wait from the end of this loop so slow polls never accumulate
            # into a backlog. A push, a focus change or a wake sets
            # _poll_wake to run this loop again sooner.
            self._poll_wake.wait(DISPLAY_POLL_INTERVAL_SECONDS)

    def _sleeping_lockfree(self) -> bool:
        """Plain read of self._display_sleeping — the poll thread is the
        only writer apart from the repaint thread's wake path, so a stale
        read here costs at most one harmless extra tick."""
        return self._display_sleeping

    def request_poll(self) -> None:
        """Ask the poll thread to run _poll_once now instead of waiting for
        the next tick. Lock-free."""
        self._poll_wake.set()

    def notify_auth_changed(self, appliance_id: str) -> None:
        """Record that appliance_id's auth-changed push arrived (from the
        HTTP thread). Never probes here — only enqueues and wakes the poll
        thread, which does the one permitted HTTP call while asleep."""
        with self._push_lock:
            self._push_pending.add(appliance_id)
        auth_map.force_due(appliance_id)
        self._poll_wake.set()

    def _drain_push_probes(self) -> str:
        """Probe every appliance_id the push queue holds.

        Returns "woke" when a probe confirmed a NEW authorization while
        asleep (and the screen was woken), "probed" when anything was
        probed, "" otherwise.
        """
        with self._push_lock:
            ids = set(self._push_pending)
            self._push_pending.clear()
        if not ids:
            return ""
        targets = {t.appliance_id: t for t in self._get_display_targets() if t.appliance_id}
        woke = False
        for appliance_id in ids:
            target = targets.get(appliance_id)
            if target is None or not target.dial_status:
                continue     # not rostered right now: learn on the next poll
            before = auth_map.state(appliance_id)
            self._probe_auth(target)
            after = auth_map.state(appliance_id)
            if after == AUTH_AUTHORIZED and before != AUTH_AUTHORIZED:
                with self._lock:
                    if self._display_sleeping:
                        self._idle_started_at = None      # same as _apply_touch_activity_locked
                        self._wake_locked()
                        woke = True
        return "woke" if woke else "probed"

    def _apply_status_to_auth(self, target, result: dict) -> bool:
        """Map a fetch_target_status/enrich_targets record onto the auth
        map. Only the two explicit outcomes move state; everything else
        (including a missing appliance_id) is transient."""
        err = result.get("status_error")
        if err is None:
            outcome = OUTCOME_AUTHORIZED
        elif err == "unauthorized":
            outcome = OUTCOME_UNAUTHORIZED
        else:
            outcome = OUTCOME_TRANSIENT
        return auth_map.apply(
            target.appliance_id, outcome, result.get("appliance_id"), time.monotonic(),
        )

    def _probe_auth(self, target) -> dict:
        """Fetch one target's status and apply it to the auth map. Shared
        by the push-probe path and the reconcile pass."""
        result = fetch_target_status(target, self._dial_id, timeout_seconds=DIAL_STATUS_TIMEOUT_SECONDS)
        self._apply_status_to_auth(target, result)
        return result

    def _apply_status_to_repeat(self, appliance_id: str, result: dict, now: float) -> None:
        """Feed dial_repeat_store from a fetch_target_status/enrich_targets
        record — mirrors _apply_status_to_auth's three-way split: a good
        200 updates the store from the record's repeat object (parsed
        strictly by dial_repeat_store.parse_repeat_object, so a malformed
        object degrades to "unavailable" rather than raising); a confirmed
        412 clears it (this dial's authorization for the appliance was
        revoked, so any cached repeat state is no longer this dial's to
        show); everything else (timeout, unreachable, bad_response, ...) is
        transient and leaves the record untouched — the repeat screen and
        the idle affordance must not blank mid-poll on a single bad
        response. A no-op for an identity-less
        target (dial_repeat_store.update/clear both already guard on this,
        checked again here so the intent reads at the call site)."""
        if not appliance_id:
            return
        err = result.get("status_error")
        if err is None:
            repeat_store.update(appliance_id, parse_repeat_object(result.get("repeat"), now))
        elif err == "unauthorized":
            repeat_store.clear(appliance_id)

    def _reconcile_pass(self, roster: list, visited: set[str]) -> None:
        """Concurrent fan-out over rows the sequential poll walk did not
        already fetch this tick, so an unauthorized row's re-probe backoff
        and every row's occasional re-confirmation happen without adding
        sequential latency to the artwork-selection walk.

        Runs over the MERGED roster (dial_mdns.get_roster()), not just the
        playing set: an idle appliance is reconciled here — feeding the
        auth map and the repeat store — but never gets an artwork fetch and
        never sets _now_playing (that stays exclusively the playing walk's
        job in _poll_once). After every pending row is processed,
        dial_repeat_store is pruned to the roster's current id set so a
        departed appliance's record does not linger forever.
        """
        now = time.monotonic()
        auth_map.prune(now)
        pending = [
            r for r in roster
            if r.dial_status and r.appliance_id and r.service_name not in visited
            and auth_map.due_for_probe(r.appliance_id, now)
        ]
        if pending:
            for record in enrich_targets(pending, self._dial_id):
                target = next(t for t in pending if t.service_name == record["name"])
                self._apply_status_to_auth(target, record)
                self._apply_status_to_repeat(target.appliance_id, record, now)
        repeat_store.prune({r.appliance_id for r in roster})

    def on_repeat_result(self, kind: str, appliance_id: str, status: int | None, body) -> None:
        """Callback for the repeat-transport worker (dial_repeat.py). Runs
        on the WORKER thread — never the poll/repeat/touch threads — and
        takes NO lock of this class's own (self._lock is never touched
        here; repeat_store and auth_map each guard themselves with their
        own leaf lock).

        An ok:true ack (status 200, body["ok"] truthy) folds optimistically
        into the repeat store (repeat_store.apply_ack) and wakes the repeat
        thread so the ring/buttons reflect it immediately. Every other
        outcome — a 412, a 200 ok:false, or a transient failure (no
        response, a timeout, or any other HTTP code) — never touches the
        auth map's STATE, only its due-ness (force_due plus a poll
        request), the same nudge a transient status-poll error gets
        elsewhere. A known daemon rejection of "source_active" or
        "no_recording" additionally clears the store record (the buffer is
        gone, or a live source has started again — a stale ring/row would
        otherwise linger until the next poll corrects it). Any outcome
        other than ok:true also clears a pending focus for this appliance
        (set_manual_focus_pending) — the replay did not start.
        """
        now = time.monotonic()
        if status == 200 and isinstance(body, dict) and body.get("ok"):
            repeat_store.apply_ack(appliance_id, body, now)
            self._overlay_signal.set()
            return

        auth_map.force_due(appliance_id)
        self._reconcile_due = True
        self.request_poll()

        if status == 412 or (status == 200 and isinstance(body, dict)):
            error = body.get("error") if isinstance(body, dict) else None
            if error in ("source_active", "no_recording"):
                repeat_store.clear(appliance_id)

        pending = self._focus_pending
        if pending is not None and pending[0] == appliance_id:
            self._focus_pending = None
            self._manual_focus_id = None

    def set_manual_focus(self, appliance_id: str | None) -> None:
        """Sticky manual focus: pins the display source to appliance_id
        (or clears it back to auto-pick with None). Lock-free write plus a
        poll wake so the source switch lands within milliseconds, not at
        the next tick. Never persisted."""
        self._manual_focus_id = appliance_id
        self._poll_wake.set()

    def manual_focus_id(self) -> str | None:
        return self._manual_focus_id

    def _auth_not_unauthorized(self, appliance_id: str) -> bool:
        """True unless dial_auth confirms appliance_id unauthorized. Used
        only by the pending-focus grace window (set_manual_focus_pending):
        during the gap the appliance is not rostered at all, so there is no
        target row to read .auth from — this reads the auth map directly
        instead."""
        return auth_map.state(appliance_id) != AUTH_UNAUTHORIZED

    def _update_dots_active(self, now: float) -> None:
        """Recompute whether the repeat screen's dots are currently
        tappable, from the currently focused/reporting appliance's fresh
        repeat-store record. Poll thread only; read lock-free by
        touch_surface() and _effective_overlay_locked()."""
        appliance_id = self._manual_focus_id or self._reporting_appliance_id
        rec = repeat_store.get(appliance_id, now) if appliance_id else None
        self._dots_active = rec is not None and rec.available

    def _poll_once(self) -> None:
        with self._lock:
            fitted = self._config.fitted
        if not fitted:
            self._source_service_name = None
            self._now_playing = None
            self._reporting_appliance_id = None
            self._dots_active = False
            return

        targets = self._get_display_targets()
        # A source that WAS playing and has now stopped drops out of the
        # playing set but stays advertised (idle) in the general roster with
        # a retained recording the appliance now reports as "hold". That
        # transition must reach the idle screen's replay affordance and the
        # replay picker promptly, not up to a full reconcile interval later,
        # so force an immediate reconcile whenever the playing set shrinks.
        # (Growing or unchanged sets need nothing here — the ordinary
        # cadence already covers them.) force_due() takes the leaf dial_auth
        # lock, so it is called here, before self._lock is taken below.
        playing_ids = {t.appliance_id for t in targets if t.appliance_id}
        if self._prev_playing_ids - playing_ids:
            self._reconcile_due = True
            auth_map.force_due()
        self._prev_playing_ids = playing_ids
        # The merged playing+idle roster — this is where general (idle)
        # sightings get noted into the auth map (dial_mdns.get_roster()'s
        # docstring). Computed unconditionally, whether or not anything is
        # playing, so an idle appliance's presence is tracked at every poll
        # tick, not only while something else happens to be playing. Also
        # published for the repeat thread's own use when it opens the
        # repeat screen (see _build_repeat_screen_locked) — a plain
        # reference write, read later under self._lock.
        roster = self._get_roster()
        self._last_roster = roster
        now = time.monotonic()

        # Resolve manual focus before anything else: a focused appliance
        # that is no longer rostered, or has since been confirmed
        # unauthorized, reverts silently to auto-pick — UNLESS a picker-
        # started replay is still within its pending grace window (6),
        # in which case the focus is kept and the empty-targets branch
        # below shows the appliance's name over the logo instead of the
        # ordinary idle screen.
        focus_id = self._manual_focus_id
        pending = self._focus_pending
        if pending is not None and (pending[0] != focus_id or now >= pending[2]):
            self._focus_pending = None
            pending = None
        focus_target = None
        if focus_id is not None:
            focus_target = next(
                (t for t in targets if t.appliance_id == focus_id and t.auth != AUTH_UNAUTHORIZED),
                None,
            )
            if focus_target is None:
                if pending is not None and self._auth_not_unauthorized(focus_id):
                    pass  # grace: keep the focus, appliance not rostered yet
                else:
                    self._manual_focus_id = None
                    self._focus_pending = None
                    logging.info("dial display: manual focus cleared (appliance gone or unauthorized)")
                    if self._screen == "repeat":
                        with self._lock:
                            self._close_secondary_locked()
            elif pending is not None:
                self._focus_pending = None  # sighted: converts to a normal focus

        # Any visible playing target counts as activity — including
        # unauthorized or status-erroring ones — because the mDNS
        # _autostream-playing._tcp presence alone means audio is playing
        # somewhere on the network, regardless of whether this dial's
        # display is allowed to source artwork from it.
        if targets:
            woke = False
            with self._lock:
                self._idle_started_at = None
                if self._display_sleeping:
                    self._wake_locked()
                    woke = True
            if woke:
                # Outside the lock: force_due() takes the leaf dial_auth
                # lock, which must never nest with self._lock.
                self._reconcile_due = True
                auth_map.force_due()
                self._poll_wake.set()
        else:
            # Nothing playing anywhere: there is no reporting-from target any
            # more, and a stale readout for a target that has since stopped
            # must not survive to the next time something starts playing.
            # The roster reconcile and the idle-affordance/picker refresh
            # still run here on their usual cadence — this is exactly the
            # state the idle screen and the replay picker exist for, and
            # the artwork walk below never runs in this branch to cover it
            # another way.
            self._source_service_name = None
            observe_master_volume(None, None)
            if self._reconcile_due or now - self._last_reconcile_at >= RECONCILE_INTERVAL_SECONDS:
                self._reconcile_pass(roster, set())
                self._last_reconcile_at = now
                self._reconcile_due = False
            self._refresh_idle_affordance(roster, now)
            self._refresh_picker_rows(roster, now)

            if self._focus_pending is not None:
                # A picker-started replay hasn't reached the playing set
                # yet — keep showing its name over the logo rather than
                # falling into the idle screen underneath it (the idle
                # affordance is suppressed too: _now_playing is not None
                # here, see _render_logo_locked/_display_idle_locked).
                pending = self._focus_pending
                self._now_playing = NowPlaying(pending[1], "", "", None)
                self._reporting_appliance_id = pending[0]
                self._update_dots_active(now)
                with self._lock:
                    self._close_secondary_locked()
                self.show_logo()
                return

            self._now_playing = None
            self._reporting_appliance_id = None
            self._update_dots_active(now)
            with self._lock:
                # The replay picker is the idle-state screen for choosing a
                # held recording to replay, so it MUST stay open while
                # nothing is playing — its own inactivity timeout
                # (_check_secondary_timeout), not this branch, closes it.
                # Every other secondary screen (the appliance selector, the
                # repeat screen) is meaningless with nothing playing and is
                # popped to main before the sleep decision below.
                # A pending "picker" request (open_picker just ran on the
                # touch thread, the repaint thread has not applied it yet)
                # counts as open too, so this poll never clobbers a picker
                # that is opening this very tick.
                picker_open = self._screen == "picker" or self._screen_request == "picker"
                if not picker_open:
                    self._close_secondary_locked()
                    if self._idle_started_at is None:
                        self._idle_started_at = time.monotonic()
                else:
                    # An open picker counts as activity: never sleep out from
                    # under it (its timeout returns to main first, after
                    # which the idle-sleep clock restarts).
                    self._idle_started_at = None
                if self._display_sleeping:
                    # Stay dark — no repaint while asleep.
                    return
                should_sleep = (
                    not picker_open
                    and time.monotonic() - self._idle_started_at >= DISPLAY_IDLE_SLEEP_SECONDS
                )
                if should_sleep:
                    self._sleep_locked()
                    return
            if picker_open:
                # Re-render the picker with the rows just refreshed above:
                # the on-screen PickerState was built from whatever rows
                # existed when the open request was applied, which can race
                # ahead of the reconcile that populates a just-stopped
                # source's held recording.
                self._overlay_signal.set()
                return
            self.show_logo()
            return

        selected_url = None
        selected_service = None
        selected_artist = ""
        selected_title = ""
        records: dict[str, dict] = {}
        visited: set[str] = set()
        # With a focus, it is polled first and pinned to unconditionally —
        # the walk never falls through to another appliance's artwork.
        # Without one, today's playing_since-ordered walk is unchanged.
        ordered = (
            [focus_target] + [t for t in targets if t is not focus_target]
            if focus_target is not None else targets
        )
        for target in ordered:
            is_focus = focus_target is not None and target is focus_target
            if target.auth == AUTH_UNAUTHORIZED:
                logging.debug("dial display: skip unauthorized row %s", target.service_name)
                continue
            if not target.dial_status:
                logging.debug("dial display: skip unsupported target %s", target.service_name)
                if is_focus:
                    # No status to poll, but the screen still follows the
                    # focus for its name/label; there is simply no artwork.
                    selected_service = target.service_name
                    break
                continue

            result = fetch_target_status(target, self._dial_id, timeout_seconds=DIAL_STATUS_TIMEOUT_SECONDS)
            visited.add(target.service_name)
            self._apply_status_to_auth(target, result)
            self._apply_status_to_repeat(target.appliance_id, result, time.monotonic())
            status_error = result.get("status_error")

            if is_focus and status_error == "unauthorized":
                # Revoked mid-tick: clear focus now and fall through to the
                # normal walk over the remaining targets in this same poll,
                # so the screen shows the auto-pick target immediately.
                self._manual_focus_id = None
                self._focus_pending = None
                focus_target = None
                is_focus = False
                logging.info("dial display: manual focus cleared (appliance now unauthorized)")
                if self._screen == "repeat":
                    with self._lock:
                        self._close_secondary_locked()
                continue

            if is_focus:
                # The focus target is pinned regardless of whether it has
                # identified artwork — never fall through to another
                # appliance's artwork while a focus is set.
                selected_service = target.service_name
                if not status_error:
                    records[target.service_name] = result
                    track_id = result.get("track_id")
                    if track_id and track_id.get("state") == "identified" and track_id.get("artwork_url"):
                        selected_url = track_id["artwork_url"]
                        selected_artist = track_id.get("artist", "")
                        selected_title = track_id.get("title", "")
                break

            if status_error:
                logging.debug(
                    "dial display: target %s status_error=%s", target.service_name, status_error,
                )
                continue

            records[target.service_name] = result
            track_id = result.get("track_id")
            if track_id and track_id.get("state") == "identified" and track_id.get("artwork_url"):
                selected_url = track_id["artwork_url"]
                selected_service = target.service_name
                selected_artist = track_id.get("artist", "")
                selected_title = track_id.get("title", "")
                break

        # Reporting-from target: the identified (or focused) source, else
        # the oldest playing CONTROLLABLE target (select_volume_target's
        # fallback). Only auth != unauthorized targets are offered, matching
        # the volume resolver's own filter (dial_main._build_volume_targets_fn)
        # so the poll and the worker can never disagree about who
        # volume/mute addresses.
        targets_controllable = [t for t in targets if t.auth != AUTH_UNAUTHORIZED]
        reporting = select_volume_target(targets_controllable, selected_service)
        reporting_name = reporting.service_name if reporting is not None else None
        reporting_id = reporting.appliance_id if reporting is not None else None
        self._reporting_appliance_id = reporting_id
        self._update_dots_active(time.monotonic())
        record = records.get(reporting_name) if reporting_name else None
        master_volume = record.get("master_volume") if record else None
        # Free reconciliation for the dial mute belief (dial_volume.py),
        # restricted to the REPORTING-FROM target only (not "any target
        # seen this poll" as before single-targeting): a master_volume > 0
        # on some OTHER target proves nothing about whether the one this
        # dial actually controls is muted — see the dial_volume module
        # docstring's reconciliation paragraph. master_volume == 0 is NOT
        # the mirror case — it proves nothing about the rest of the fleet —
        # so it is deliberately not checked here at all.
        if isinstance(master_volume, int) and not isinstance(master_volume, bool):
            if master_volume > 0:
                note_master_volume_positive()
            observe_master_volume(reporting_name, master_volume)
        elif reporting_name is not None:
            observe_master_volume(reporting_name, None)

        # Assigned before _show_artwork() below so a volume press landing
        # during the artwork fetch already goes to the right target.
        self._source_service_name = selected_service
        new_now_playing = (
            NowPlaying(reporting_name, selected_artist, selected_title, master_volume)
            if reporting_name is not None else None
        )
        changed = new_now_playing != self._now_playing
        self._now_playing = new_now_playing
        if changed:
            self._overlay_signal.set()

        if selected_url:
            self._show_artwork(selected_url)
        else:
            self.show_logo()

        now = time.monotonic()
        if self._reconcile_due or now - self._last_reconcile_at >= RECONCILE_INTERVAL_SECONDS:
            self._reconcile_pass(roster, visited)
            self._last_reconcile_at = now
            self._reconcile_due = False
        self._refresh_selector_rows(targets, reporting_id)
        self._refresh_idle_affordance(roster, now)
        self._refresh_picker_rows(roster, now)

    # ---- artwork selection -------------------------------------------------

    def _show_artwork(self, url: str) -> None:
        with self._lock:
            if not (self._backend_open and self._backend is not None):
                return
            if url == self._source_artwork_url and self._showing == "artwork":
                logging.debug("dial display: unchanged artwork url reuse")
                return
            cached_reusable = (
                url == self._source_artwork_url and self._current_rendered_image is not None
            )
            if cached_reusable:
                was_showing = self._showing
                self._display_locked(self._current_rendered_image, is_artwork_base=True)
                self._showing = "artwork"
                if was_showing == "logo":
                    logging.info("dial display: showing artwork")
                return

        if not artwork_url_eligible(url):
            logging.debug("dial display: unsupported artwork url candidate")
            self.show_logo()
            return

        # Fetch, decode, and transform happen outside the lock so a slow
        # network round-trip never blocks a settings change. This is the only
        # thread that changes which artwork is SELECTED, so no mid-fetch
        # cancellation is needed — but it is not the only thread touching
        # display state: the HTTP thread can swap or close the backend
        # underneath this work via update_config. The re-check below, taken
        # under the lock, is what makes that safe.
        url_key = _url_log_key(url)
        data, err = _fetch_artwork(url, ARTWORK_FETCH_TIMEOUT_SECONDS)
        if err:
            self._record_error("artwork_fetch_failed")
            self._log_limiter.log(
                logging.WARNING, f"artwork_fetch:{url_key}",
                "dial display: artwork fetch failed (%s): %s", url_key, err,
            )
            self.show_logo()
            return

        image = decode_artwork(data)
        if image is None:
            self._record_error("artwork_decode_failed")
            self._log_limiter.log(
                logging.WARNING, f"artwork_decode:{url_key}",
                "dial display: artwork decode failed (%s)", url_key,
            )
            self.show_logo()
            return

        width, height = self._active_panel_dims()
        # rotate/bgr are deferred to _display_locked() below (and to any
        # later cached-reuse push) — this call only produces the panel-
        # fitted, pre-rotate/BGR base that gets cached as
        # self._current_rendered_image.
        transformed = self._compositor.compose(
            image, width, height,
            rotate=False, bgr=False, is_artwork=True,
        )

        with self._lock:
            if not (self._backend_open and self._backend is not None):
                return
            if transformed.size != (self._backend.width, self._backend.height):
                # A screen_type swap raced with this fetch/transform, which
                # ran outside the lock against the backend that was active
                # at the time — composed for its (now superseded) dims. Drop
                # the stale-sized frame rather than letting the new backend
                # silently letterbox it; the next poll recomposes at the now
                # -active dims.
                logging.debug(
                    "dial display: dropping frame sized for a superseded backend"
                )
                return
            was_showing = self._showing
            self._display_locked(transformed, is_artwork_base=True)
            self._source_artwork_url = url
            self._current_rendered_image = transformed
            self._showing = "artwork"
            self._last_error = ""
            self._last_error_at = None

        logging.info("dial display: artwork replaced (%s)", url_key)
        if was_showing == "logo":
            logging.info("dial display: showing artwork")


def _adafruit_backend_factory_for_screen_type(screen_type: str):
    """Resolve *screen_type* to a zero-arg AdafruitDisplayBackend factory,
    falling back to the default profile if the key is unresolvable.

    dial_display_adafruit imports hardware modules only inside its open()
    method, so importing it here is safe even when no screen is fitted or
    the Adafruit package is absent — screen_type resolution itself never
    touches hardware.
    """
    from dial_display_adafruit import AdafruitDisplayBackend

    try:
        profile = get_profile(screen_type)
    except UnknownDisplayProfileError:
        profile = get_profile(DEFAULT_PROFILE_KEY)
    return lambda: AdafruitDisplayBackend(profile)


def create_dial_display(cfg, get_display_targets) -> DialDisplay:
    """Build the display manager for dial_main.py wiring.

    Builds the backend factory from the configured profile (cfg.display.
    screen_type) at startup, falling back to the default profile if the key
    is unresolvable; whether it is ever opened is controlled by the fitted
    flag in DialDisplay.enable()/update_config(), not by this factory
    choice. Also wires the screen_type -> factory resolver so a live
    screen_type change can rebuild and swap the backend without a restart.
    """
    return DialDisplay(
        config=cfg.display,
        get_display_targets=get_display_targets,
        dial_id=cfg.uuid,
        backend_factory=_adafruit_backend_factory_for_screen_type(cfg.display.screen_type),
        backend_factory_builder=_adafruit_backend_factory_for_screen_type,
    )
