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
from dial_display_compositor import DialDisplayCompositor, ListState, OverlayState
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
from dial_target_status import enrich_targets, fetch_target_status
from dial_touch_layout import list_layout_for
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
# touch activity while open — see _apply_touch_activity_locked.
SELECTOR_TIMEOUT_SECONDS = 18


def _fetch_artwork(url: str, timeout: float) -> tuple[bytes | None, str]:
    """Fetch artwork for the panel, at the dial's own size ceiling."""
    return fetch_artwork(url, timeout, MAX_ARTWORK_RESPONSE_BYTES)


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
    title: str          # kept for a future title line; unused by the overlay
    master_volume: int | None


@dataclass(frozen=True)
class SelectorRow:
    """One row of the appliance-selector screen — see SelectorState."""
    appliance_id: str
    label: str        # appliance_display_name(service_name)
    current: bool     # this row is the focus (manual, else the reporting-from target)


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
        backend_factory=NoOpBackend,
        backend_factory_builder=None,
    ) -> None:
        self._lock = threading.Lock()
        self._config = config
        self._get_display_targets = get_display_targets
        self._dial_id = dial_id
        self._logo_path = logo_path
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
        # Manual focus: appliance_id chosen by the user, or None for
        # auto-pick. Read and cleared by the poll thread; set by
        # selector_pick() below (the touch thread, via dial_main's
        # on_zone_tap dispatch for a LIST_ROW tap). Plain reference
        # read/write, same discipline as _overlay_snapshot. Never persisted.
        self._manual_focus_id: str | None = None

        # ---- Selector screen state -------------------------------------
        # self._screen is written under self._lock — usually by the repaint
        # thread (_apply_screen_requests_locked()/_close_selector_locked()),
        # occasionally by the poll thread (the empty-target branch,
        # _sleep_locked) — and read lock-free elsewhere (a plain str read is
        # atomic) — same discipline as _current_base_is_artwork.
        # "main": the now-playing screen. "selector": the appliance list.
        self._screen = "main"
        # Last-built rows, refreshed every poll tick regardless of whether
        # the selector is actually open (_refresh_selector_rows) so opening
        # it never waits on a poll; published under self._lock. None until
        # the first poll runs.
        self._selector: SelectorState | None = None
        # Touch-thread requests (open_selector/close_selector/selector_page)
        # are flag writes only — plain str/int, no lock — folded into
        # self._screen/self._selector by the repaint thread
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

    def touch_surface(self) -> tuple[str, bool]:
        """(surface, name_active) for dial_touch.TouchStateMachine.
        set_surface() — see that module's SURFACES paragraph. Polled once
        per loop iteration by TouchEventSource; a plain-attribute read
        discipline, same as persistent_overlay_shown() and
        noncomposited_generation().

        name_active is true whenever there is a controllable appliance
        currently shown (self._now_playing is not None) — unconditional,
        per the low-level design's Q4: the appliance name and its tap-zone
        are always active in that case, never gated on how many
        appliances are authorized. It is independent of held/hidden: by
        the time a second press can sample the NAME zone at all, the
        REVEAL-ONLY FIRST TOUCH rule (dial_touch.py) has already made the
        overlay visible.
        """
        if self._screen == "selector":
            return ("selector", False)
        name_active = self._now_playing is not None
        if self.persistent_overlay_shown():
            return ("held", name_active)
        return ("hidden", name_active)

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
        self._close_selector_locked()
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
        self._close_selector_locked()

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
        # (I8; see also the empty-target branch in _poll_once, which is
        # the only path that can reach sleep with a fresh reason to check).
        self._close_selector_locked()
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
        name = appliance_display_name(now_playing.service_name) if now_playing is not None else ""
        volume = shown_volume(now_playing.service_name) if now_playing is not None else None
        muted = snapshot.muted if snapshot.muted is not None else is_muted()
        return dataclasses.replace(
            snapshot, visible=True, artist=artist, volume=volume, muted=muted, name=name,
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
                # Plain timeout — nothing to do beyond the selector's own
                # inactivity check, then go back to waiting. This periodic
                # wake exists only so stop() is noticed promptly even if no
                # overlay signal ever arrives.
                self._check_selector_timeout()
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
        if self._current_base_image is None:
            return woke
        self._display_locked(self._current_base_image)
        return woke

    # ---- appliance selector screen -----------------------------------------
    #
    # Touch-thread entry points (open_selector/close_selector/selector_page/
    # selector_pick) are flag-write-plus-signal only, exactly like
    # notify_touch_activity()/set_manual_focus() — the actual screen-state
    # change happens on the repaint thread under self._lock
    # (_apply_screen_requests_locked). Rows themselves are built ONLY on the
    # poll thread (_refresh_selector_rows) — the touch thread never builds
    # rows, it only reads the last-published SelectorState.

    def open_selector(self) -> None:
        """Touch-thread entry (dial_main's on_zone_tap, for a NAME tap).
        Also forces an immediate reconcile/poll so any not-yet-confirmed
        row is checked within about one poll interval of opening, per the
        low-level design's review note (unknown rows confirmed quickly
        rather than left stale for up to 60s)."""
        self._screen_request = "selector"
        self._reconcile_due = True
        auth_map.force_due()
        self._poll_wake.set()
        self._overlay_signal.set()

    def close_selector(self) -> None:
        """Touch-thread entry (dial_main's on_zone_tap, for a LIST_BACK tap,
        or selector_pick() below)."""
        self._screen_request = "main"
        self._overlay_signal.set()

    def selector_page(self, delta: int) -> None:
        """Touch-thread entry (dial_main's on_zone_tap, for a LIST_DOWN/
        LIST_UP tap): +1 for the next page, -1 for the previous. Clamped to
        the valid range by _apply_screen_requests_locked()."""
        self._page_request += delta
        self._overlay_signal.set()

    def selector_pick(self, index: int) -> None:
        """Touch-thread entry (dial_main's on_zone_tap, for a LIST_ROW tap).

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
        self.close_selector()

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

    def _close_selector_locked(self) -> None:
        """Pop to the main screen. Caller holds self._lock. Called from the
        repaint thread's own request-folding, from sleep/disable/swap (so a
        later wake/reopen never resumes on a stale list), and is what a
        stale selector_pick() index falls back to."""
        self._screen = "main"
        self._selector = None
        self._overlay_signal.set()

    def _apply_screen_requests_locked(self) -> None:
        """Fold pending open_selector()/close_selector()/selector_page()
        touch-thread requests into self._screen/self._selector. Caller
        holds self._lock; runs on the repaint thread only.
        """
        request = self._screen_request
        self._screen_request = None
        delta = self._page_request
        self._page_request = 0

        if request == "selector":
            rows = self._selector.rows if self._selector is not None else ()
            self._selector = SelectorState(rows=rows, page=0, opened_at=time.monotonic())
            self._screen = "selector"
        elif request == "main":
            self._close_selector_locked()

        if delta and self._screen == "selector" and self._selector is not None:
            width, height = self._active_panel_dims()
            rows_per_page = list_layout_for(width, height).rows_per_page
            row_count = len(self._selector.rows)
            max_page = max(0, (row_count - 1) // rows_per_page) if row_count else 0
            new_page = max(0, min(self._selector.page + delta, max_page))
            if new_page != self._selector.page:
                self._selector = dataclasses.replace(self._selector, page=new_page)

    def _check_selector_timeout(self) -> None:
        """Close the selector after SELECTOR_TIMEOUT_SECONDS of no touch
        activity — called from the repaint thread's own 1s timeout branch,
        so this runs even when nothing else signals a repaint.

        self._screen and self._selector are read lock-free here: both are
        also written by the poll thread (_poll_once's empty-target branch,
        _sleep_locked), not only the repaint thread, but every write is
        already under self._lock and each is a plain reference/str
        assignment — the same "a stale read costs at most one harmless
        extra tick" discipline _sleeping_lockfree() documents. The actual
        close below is re-checked and applied under the lock regardless.
        """
        if self._screen != "selector":
            return
        selector = self._selector
        if selector is None:
            return
        if time.monotonic() - selector.opened_at >= SELECTOR_TIMEOUT_SECONDS:
            with self._lock:
                self._close_selector_locked()

    def _refresh_selector_rows(self, targets: list, reporting_id: str | None) -> None:
        """Rebuild the selector's row list from *targets* — see section 2.7
        of the low-level design. Runs on the poll thread at the end of
        every _poll_once, whether or not the selector screen is actually
        open right now, so opening it always shows fresh rows without
        waiting for a poll. The touch thread never builds rows.

        Rows: every target with a non-empty appliance_id whose auth is
        AUTHORIZED (not just "not unauthorized" — an unknown appliance is
        controllable but not yet confirmed, so it stays off the list until
        a probe confirms it). *current* marks the manual focus when one is
        set, else the reporting-from target (*reporting_id*).

        The page is PRESERVED (clamped to the new row count) across each
        rebuild — resetting it to 0 here would make an open selector jump
        back to its first page every ~6s poll tick. It is reset to 0 only
        by a fresh open_selector() (see _apply_screen_requests_locked).
        """
        focus_id = self._manual_focus_id
        current_id = focus_id if focus_id is not None else reporting_id
        rows = tuple(
            SelectorRow(
                appliance_id=t.appliance_id,
                label=appliance_display_name(t.service_name),
                current=(t.appliance_id == current_id),
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

    def _build_list_state_locked(self, width: int, height: int) -> ListState:
        """Build the compositor's ListState for the CURRENT page. Caller
        holds self._lock; runs on the repaint thread only. Live touch-press
        feedback is not wired into the selector chassis in this phase —
        pressed is always None here (compose_list still supports it, for
        the compositor's own tests)."""
        selector = self._selector
        if selector is None or not selector.rows:
            return ListState(rows=(("No devices", False),), has_prev=False, has_next=False)
        rows_per_page = list_layout_for(width, height).rows_per_page
        start = selector.page * rows_per_page
        page_rows = selector.rows[start:start + rows_per_page]
        return ListState(
            rows=tuple((row.label, row.current) for row in page_rows),
            has_prev=selector.page > 0,
            has_next=start + rows_per_page < len(selector.rows),
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

    def _reconcile_pass(self, targets: list, visited: set[str]) -> None:
        """Concurrent fan-out over rows the sequential poll walk did not
        already fetch this tick, so an unauthorized row's re-probe backoff
        and every row's occasional re-confirmation happen without adding
        sequential latency to the artwork-selection walk."""
        now = time.monotonic()
        auth_map.prune(now)
        pending = [
            t for t in targets
            if t.dial_status and t.appliance_id and t.service_name not in visited
            and auth_map.due_for_probe(t.appliance_id, now)
        ]
        if not pending:
            return
        for record in enrich_targets(pending, self._dial_id):
            target = next(t for t in pending if t.service_name == record["name"])
            self._apply_status_to_auth(target, record)

    def set_manual_focus(self, appliance_id: str | None) -> None:
        """Sticky manual focus: pins the display source to appliance_id
        (or clears it back to auto-pick with None). Lock-free write plus a
        poll wake so the source switch lands within milliseconds, not at
        the next tick. Never persisted."""
        self._manual_focus_id = appliance_id
        self._poll_wake.set()

    def manual_focus_id(self) -> str | None:
        return self._manual_focus_id

    def _poll_once(self) -> None:
        with self._lock:
            fitted = self._config.fitted
        if not fitted:
            self._source_service_name = None
            self._now_playing = None
            return

        targets = self._get_display_targets()

        # Resolve manual focus before anything else: a focused appliance
        # that is no longer rostered, or has since been confirmed
        # unauthorized, reverts silently to auto-pick.
        focus_id = self._manual_focus_id
        focus_target = None
        if focus_id is not None:
            focus_target = next(
                (t for t in targets if t.appliance_id == focus_id and t.auth != AUTH_UNAUTHORIZED),
                None,
            )
            if focus_target is None:
                self._manual_focus_id = None
                logging.info("dial display: manual focus cleared (appliance gone or unauthorized)")

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
            self._source_service_name = None
            self._now_playing = None
            observe_master_volume(None, None)
            with self._lock:
                # The list must never be the last thing on screen when
                # nothing is playing any more — pop to main before the
                # sleep decision below (I8).
                self._close_selector_locked()
                if self._idle_started_at is None:
                    self._idle_started_at = time.monotonic()
                if self._display_sleeping:
                    # Stay dark — no repaint while asleep.
                    return
                should_sleep = (
                    time.monotonic() - self._idle_started_at >= DISPLAY_IDLE_SLEEP_SECONDS
                )
                if should_sleep:
                    self._sleep_locked()
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
            status_error = result.get("status_error")

            if is_focus and status_error == "unauthorized":
                # Revoked mid-tick: clear focus now and fall through to the
                # normal walk over the remaining targets in this same poll,
                # so the screen shows the auto-pick target immediately.
                self._manual_focus_id = None
                focus_target = None
                is_focus = False
                logging.info("dial display: manual focus cleared (appliance now unauthorized)")
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
            self._reconcile_pass(targets, visited)
            self._last_reconcile_at = now
            self._reconcile_due = False
        self._refresh_selector_rows(targets, reporting_id)

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
