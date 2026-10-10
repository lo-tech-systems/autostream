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
enrich_targets() only; an idle row never becomes the artwork base, though a
manual focus resting on one is polled every tick and can set _now_playing
with no artwork of its own — see focus_volume_target()). The roster and the
repeat store are display-side only, read by the volume resolver only
through the display's focus accessor.

This manager also consumes the network poller's view (dial_network.py, via
on_network_view()) for the idle screen's Wi-Fi status icon and the No-WiFi
page. Both the network view and the SD health reader feed the on-screen
warning manager (dial_warnings.py) through _warning_active()/
_warning_cleared().

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import dataclasses
import functools
import hashlib
import io
import logging
import math
import os
import sys
import threading
import time
from dataclasses import dataclass

from PIL import Image, ImageChops

from dial_auth import (
    AUTH_AUTHORIZED,
    AUTH_UNAUTHORIZED,
    AUTH_UNKNOWN,
    OUTCOME_AUTHORIZED,
    OUTCOME_TRANSIENT,
    OUTCOME_UNAUTHORIZED,
    auth_map,
)
from dial_display_compositor import (
    PLAY_GLYPH,
    DialDisplayCompositor,
    EqViewState,
    InfoValueView,
    ListState,
    NOT_AUTHORISED_TEXT,
    NOWIFI_DISMISS_TEXT,
    NOWIFI_MESSAGE_TEXT,
    NOWIFI_RESTART_TEXT,
    OutputViewState,
    OverlayState,
    RepeatViewState,
    SDHEALTH_BODY_TEXT,
    SDHEALTH_BODY_TEXT_NO_PERCENT,
    SDHEALTH_DISMISS_TEXT,
    SDHEALTH_TITLE_TEXT,
    WIFI_GREY,
    WIFI_OFF,
    WIFI_RED,
    WIFI_SIGNAL,
    WarningView,
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
    layout_context_for,
)
from dial_display_windows import bounding_box, frame_words, plan_windows
from dial_eq import _EqTarget
from dial_eq import enqueue_fetch as _enqueue_eq_fetch
from dial_eq import enqueue_set as _enqueue_eq_set
from dial_mdns import PlayingTarget, appliance_display_name
from dial_mdns import get_roster as _default_get_roster
from dial_network import (
    LINK_CONNECTED,
    LINK_DOWN,
    LINK_IGNORED,
    NetworkView,
)
from dial_network import request_reboot as _request_reboot
from dial_outputs import _OutputsTarget, enqueue_fetch, enqueue_set
from dial_sdhealth import SdHealthView, is_low as _sd_is_low
from dial_repeat import _RepeatTarget, enqueue_arm, enqueue_transport
from dial_repeat_store import parse_repeat_object, repeat_store
from dial_target_status import enrich_targets, fetch_target_status
from dial_update_watch import (
    PHASE_REBOOT,
    PHASE_VERIFY,
    STATUS_FAILURE,
    STATUS_IN_PROGRESS,
    STATUS_SUCCESS,
    UPDATE_SEEN_PATH,
    UpdateView,
    UpdateWatcher,
    read_seen_marker,
    write_seen_marker,
)
from dial_touch_layout import (
    CONTENT_COMPACT,
    CONTENT_LARGE,
    CONTENT_RICH,
    GEOMETRY_NONE,
    GEOMETRY_NOWIFI,
    GEOMETRY_SDHEALTH,
    LayoutMetrics,
    TouchZone,
    list_layout_for,
    metrics_for,
)
from dial_volume import (
    forget_mute_states_except,
    observe_master_volume,
    observe_mute_state,
    select_volume_target,
    shown_muted,
    shown_volume,
)
from dial_warnings import (
    ACTION_DISMISS,
    ACTION_RESTART,
    WarningButton,
    WarningDescriptor,
    WarningManager,
    WarningStore,
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

# How often the outputs list refetches while an outputs screen is showing —
# see _tick_outputs_refresh(). The same round trip also runs once, right
# away, whenever an outputs screen opens (open_outputs()), so this cadence
# only covers staying open past that first fetch.
OUTPUTS_REFRESH_S = 2.0

# The EQ page's own bass/treble range -- both ends (this manager's eq_step
# and the appliance's own apply_eq_fields) independently clamp to it.
EQ_LIMIT_DB = 6

# The page-dots cycle order — see cycle_pages(). "main" is always available
# (the fallback every cycle lands on); "repeat" and "eq" are skipped when
# _repeat_page_available()/self._eq_available says there is nothing to show.
_PAGE_ORDER = ("main", "repeat", "eq")

# How long a picker-started replay's manual focus is held "pending" while
# the appliance has not yet reached the playing set — see
# set_manual_focus_pending() and the empty-targets branch of _poll_once.
FOCUS_PENDING_GRACE_S = 10.0

# How long a replay the appliance has just accepted may be shown as playing
# before its own playing advertisement reaches the dial (normally a few
# seconds) — see DialDisplay._with_accepted_replay().
ACCEPTED_REPLAY_GRACE_S = 20.0

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

# A status re-sync can move the locally interpolated counter back by up to
# the appliance's own status-cache age plus jitter: well under a second.
# A step back smaller than this is a re-sync artefact, and the second
# already painted is held until the clock catches up (which takes under a
# second, since the clock gains at 1 s/s); a step back of at least this
# much is a real position change (restart, loop wrap, a stalled source)
# and is shown at once. See _repeat_counter_second().
REPEAT_COUNTER_HOLD_S = 1.0

# How long an artwork tap hides the top/bottom bands for — see
# hide_controls(). Long enough to look at the artwork without the overlay
# reappearing underneath, short enough that the controls are never truly
# lost: any tap while hidden restores them at once anyway. Also the window a
# compact screen's own controls stay shown after a touch/reveal before
# fading back to bare artwork — see _show_compact_controls()/
# _compact_controls_hidden() — the same "long enough to act on, short
# enough to get out of the way" reasoning applies to both.
CONTROLS_HIDE_SECONDS = 6.0

# The artwork reveal: how long the bands' chrome takes to slide off the
# panel (the top band up, the bottom band down) while the inter-band text
# fades, before the bare artwork of the hide window shows on its own, and
# how long it takes to slide back in when the controls return. Long
# enough to read as a smooth movement at the frame rate a windowed transmit
# allows on the shipped panel (a dozen or more frames), short enough that
# the artwork is unobstructed well inside a second of the tap. Rich and
# large tiers only: the base tier keeps its instant hide and show and the
# compact tier has no bands. Between slide frames the repaint loop always
# waits at least REVEAL_FRAME_GAP_S. The gap exists so the loop actually
# sleeps, releasing self._lock and the GIL, between frames and lets the
# poll and touch threads take the lock: CPython locks are not FIFO and the
# interpreter only switches threads every sys.getswitchinterval() (5 ms), so
# a back-to-back release and reacquire would starve them. Any real sleep
# hands over, so the gap only needs to be short. On the shipped panel the
# transmit itself is the pace; on a fast or no-op backend the gap is also
# what stops the loop spinning. See _advance_reveal_locked() and
# _reveal_progress().
REVEAL_ANIMATION_S = 0.55
REVEAL_FRAME_GAP_S = 0.001

# The replay position line shown on the main page after a picker start
# (see picker_pick()): fully shown for REPLAY_TIMER_SHOW_S from the first
# frame that has a position to show, then faded out over
# REPLAY_TIMER_FADE_S, one frame every REPLAY_TIMER_FADE_GAP_S (the line
# is a small window, so the fade is cheap). A pick whose replay has
# produced nothing to show within REPLAY_TIMER_ARM_S is dropped.
REPLAY_TIMER_SHOW_S = 10.0
REPLAY_TIMER_FADE_S = 1.0
REPLAY_TIMER_FADE_GAP_S = 0.04
REPLAY_TIMER_ARM_S = 10.0


def _reveal_ease(t: float) -> float:
    """Smoothstep easing for the artwork-tap reveal: the chrome starts
    moving gently, is fastest mid-way and settles as it leaves the panel
    edge, so neither the first nor the last frame jumps at the frame rates
    the panel allows. *t* is the clamped time fraction 0..1; the result is
    monotonic in 0..1 with f(0) = 0 and f(1) = 1 exactly."""
    return t * t * (3.0 - 2.0 * t)


# The idle screen's offline flash: the Wi-Fi glyph alternates grey/red,
# switching every half period (a 1 Hz cycle). The repaint loop schedules
# itself onto these boundaries — see _next_repaint_deadline()/
# _tick_wifi_flash(); nothing else in the process ticks for it.
WIFI_FLASH_HALF_PERIOD_S = 0.5

# How many consecutive "down" polls (15 s apart) open the No-WiFi page on
# their own: three, so a brief drop that recovers within about 45 s only
# ever flashes the icon. A tap on the flashing icon opens the page at once.
NOWIFI_PROMPT_STREAK = 3

# The "Restarting..." screen is meant to end when the reboot takes the panel
# down. If the reboot request itself failed (nginx down, helper refused),
# fall back to main after this long so the dial is never stuck on it; the
# warning tick then raises the No-WiFi page again if the link is still down.
RESTARTING_TIMEOUT_SECONDS = 90.0

# How long a Dismiss of the SD card warning holds: a week, or a day once
# the reading is under SDHEALTH_CRITICAL_PERCENT. Persisted, so a restart
# does not bring the page back early; forgotten when the reading recovers.
SDHEALTH_SNOOZE_S = 7 * 86400.0
SDHEALTH_CRITICAL_PERCENT = 3
SDHEALTH_CRITICAL_SNOOZE_S = 86400.0


def _sdhealth_snooze_for(percent) -> float:
    if isinstance(percent, int) and percent < SDHEALTH_CRITICAL_PERCENT:
        return SDHEALTH_CRITICAL_SNOOZE_S
    return SDHEALTH_SNOOZE_S


def _sdhealth_message_for(percent) -> str:
    if percent is None:
        return SDHEALTH_BODY_TEXT_NO_PERCENT
    return SDHEALTH_BODY_TEXT.format(percent=percent)


# The software update cards. The in-progress card's title is fixed and its
# message is a short label chosen by the update's phase (never the result
# file's long message, which is for the appliance's web page); the result
# card says how the run ended and names the version. All of it must fit on
# the smallest panel without truncation (tests render every string).
UPDATING_TEXT = "Updating..."
UPDATED_TEXT = "Updated"
UPDATE_FAILED_TEXT = "Update failed"
UPDATE_RESULT_DISMISS_TEXT = "Dismiss"
UPDATE_PHASE_FALLBACK_TEXT = "Please wait"
UPDATE_PHASE_TEXT = {
    "download": "Downloading",
    "prepare": "Preparing",
    "packages": "Upgrading OS",
    "python": "Installing",
    "files": "Installing",
    "configure": "Installing",
    "staged": "Restarting",
    "reboot": "Restarting",
}

# How long the result card waits for someone to see it before clearing
# itself: an update can take most of an hour and is often left unattended.
# Dismiss clears it sooner.
UPDATE_RESULT_SECONDS = 3600.0


def _update_title_for(_view) -> str:
    return UPDATING_TEXT


def _update_message_for(view) -> str:
    phase = view.phase if isinstance(view, UpdateView) else ""
    return UPDATE_PHASE_TEXT.get(phase, UPDATE_PHASE_FALLBACK_TEXT)


def _update_progress_for(view) -> "int | None":
    return view.percent if isinstance(view, UpdateView) else None


def _update_result_title_for(view) -> str:
    if isinstance(view, UpdateView) and view.status == STATUS_SUCCESS:
        return UPDATED_TEXT
    return UPDATE_FAILED_TEXT


def _update_result_message_for(view) -> str:
    if not isinstance(view, UpdateView):
        return ""
    if view.status == STATUS_SUCCESS:
        return f"Version {view.tag}" if view.tag else ""
    if view.rolled_back:
        return f"Restored {view.previous_tag}" if view.previous_tag else "Restored previous"
    return f"{view.previous_tag} kept" if view.previous_tag else "Previous kept"


# ---------------------------------------------------------------------------
# On-screen warnings
#
# One descriptor per warning. A warning's source (the network poller, the
# SD health reader) calls _warning_active()/_warning_cleared() on the
# manager; everything else (which page, which buttons, what a Dismiss
# means, what survives a restart, which one wins when two are due) is read
# from its row here. Adding a warning is adding a row plus a source; the
# screen-policy table, the opener, the painter and the touch dispatch are
# all driven from this tuple.
#
# Priority: a lost link outranks a worn card (the page is the only way to
# ask for a restart), so "nowifi" carries the higher number.
#
# A future appliance-pushed notice would be one more row, for example a
# stylus-replacement reminder with a month-long persisted snooze that the
# appliance clears when the user marks the stylus replaced:
#
#   WarningDescriptor(
#       id="stylus", priority=25, screen="stylus", geometry=GEOMETRY_SDHEALTH,
#       title="Replace stylus", message_for=lambda hours: f"{hours} h played",
#       buttons=(WarningButton(TouchZone.SDHEALTH_DISMISS, "Dismiss", ACTION_DISMISS),),
#       persisted=True, snooze_for=lambda _severity: 30 * 86400.0,
#   )
#
# plus one surface-to-geometry entry in dial_touch (the surface name is
# new, the one-cell geometry is shared) and a source that calls
# _warning_active("stylus", severity=hours) / _warning_cleared("stylus").
# ---------------------------------------------------------------------------

WARNING_DESCRIPTORS: tuple[WarningDescriptor, ...] = (
    WarningDescriptor(
        id="nowifi", priority=100, screen="nowifi", geometry=GEOMETRY_NOWIFI,
        title=NOWIFI_MESSAGE_TEXT, message_for=None,
        buttons=(
            WarningButton(TouchZone.NOWIFI_DISMISS, NOWIFI_DISMISS_TEXT, ACTION_DISMISS),
            WarningButton(TouchZone.NOWIFI_RESTART, NOWIFI_RESTART_TEXT, ACTION_RESTART),
        ),
        persisted=False, snooze_for=None,
    ),
    WarningDescriptor(
        id="sdhealth", priority=50, screen="sdhealth", geometry=GEOMETRY_SDHEALTH,
        title=SDHEALTH_TITLE_TEXT, message_for=_sdhealth_message_for,
        buttons=(
            WarningButton(TouchZone.SDHEALTH_DISMISS, SDHEALTH_DISMISS_TEXT, ACTION_DISMISS),
        ),
        persisted=True, snooze_for=_sdhealth_snooze_for,
    ),
    # A software update in progress: above No-WiFi (the link may drop while
    # the system upgrades), no buttons (touch does nothing), shown over
    # whatever is up and waking the panel; its source clears it.
    WarningDescriptor(
        id="update", priority=200, screen="update", geometry=GEOMETRY_NONE,
        title=UPDATING_TEXT, message_for=_update_message_for,
        buttons=(),
        persisted=False, snooze_for=None,
        title_for=_update_title_for, progress_for=_update_progress_for,
        interrupting=True,
    ),
    # How an update ended: one Dismiss (the SD page's cell), clears itself
    # after UPDATE_RESULT_SECONDS.
    WarningDescriptor(
        id="update_result", priority=150, screen="update_result", geometry=GEOMETRY_SDHEALTH,
        title=UPDATED_TEXT, message_for=_update_result_message_for,
        buttons=(
            WarningButton(TouchZone.SDHEALTH_DISMISS, UPDATE_RESULT_DISMISS_TEXT, ACTION_DISMISS),
        ),
        persisted=False, snooze_for=None,
        title_for=_update_result_title_for,
        interrupting=True, auto_clear_after_s=UPDATE_RESULT_SECONDS,
    ),
)
_WARNING_BY_ID: dict[str, WarningDescriptor] = {d.id: d for d in WARNING_DESCRIPTORS}
_WARNING_BY_SCREEN: dict[str, WarningDescriptor] = {d.screen: d for d in WARNING_DESCRIPTORS}

# A plain dark base pushed for the moment between the display switching to
# show a different appliance and that appliance's own artwork/logo actually
# landing — see _show_transition_locked(). A step lighter than the list
# chassis (16, 16, 16) so it reads as "waiting", not as a list screen.
_TRANSITION_RGB = (32, 32, 32)

# The overlay an artwork tap's hide window substitutes for whatever the
# touch side has published: nothing drawn. See _effective_overlay_locked().
_HIDDEN_OVERLAY = OverlayState()

# Splitting one changed region into separately written windows pays only
# when the unchanged rows left out between them cost more to send than a
# further write's own fixed overhead: about 2.9 ms per windowed write
# against about 0.7 us per pixel on the shipped panel, so a gap has to be
# at least this many pixels. At most a few windows per frame; beyond that
# the single bounding box is sent as before.
_WINDOW_SPLIT_MIN_GAP_PX = 4096
_WINDOW_SPLIT_MAX_WINDOWS = 3


# ---------------------------------------------------------------------------
# Screen policy table
#
# One policy row per screen, read by the manager wherever the screen showing
# decides what happens: what the touch side is told, how it is painted,
# whether and when it times out, what the poll does to it when nothing
# plays, and what a close hands back to. Adding a screen is adding a row
# here plus its own opener and painter; nothing else in the manager should
# need to name screens.
# ---------------------------------------------------------------------------

# How the poll reacts to a screen when it finds nothing playing.
IDLE_KEEP = "keep"                       # the screen stays; its own timeout closes it
IDLE_CLOSE = "close"                     # popped to main
IDLE_KEEP_WITH_FOCUS = "keep_with_focus" # kept only while an idle focus gives it something to show


@dataclass(frozen=True)
class ScreenPolicy:
    """One screen's policy — see the module note above. `open`/`paint` are
    unbound DialDisplay methods; `open` returns False to refuse the request
    and leave the current screen in place (e.g. the repeat screen with
    nothing to show for it)."""
    name: str
    state_attr: str | None            # the manager attribute holding this screen's state, or None (main)
    surface: tuple[str, bool, bool, bool] | None  # (surface, name_active, dots_active, outputs_active) for touch, or None: computed (main)
    open: object                      # unbound DialDisplay method (self) -> bool
    paint: object                     # unbound DialDisplay method (self) -> None, or None: main's own paint path
    paged: bool                       # a paged list: page requests apply, rows are sliced per page
    inactivity_timeout_s: float | None
    touch_extends_timeout: bool       # touch activity re-stamps opened_at
    when_nothing_plays: str           # IDLE_KEEP | IDLE_CLOSE | IDLE_KEEP_WITH_FOCUS
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


# Pillow renamed these resample enums in recent versions; fall back for
# older installs, the same guard dial_display_image.py/dial_display_
# compositor.py use for their own resizes.
try:
    _RESAMPLE_BOX = Image.Resampling.BOX
    _RESAMPLE_NEAREST = Image.Resampling.NEAREST
except AttributeError:  # Pillow < 9.1
    _RESAMPLE_BOX = Image.BOX
    _RESAMPLE_NEAREST = Image.NEAREST


def _resample_filter(source: tuple[int, int], target: tuple[int, int]):
    """The Pillow filter for scaling a finished frame from its logical size
    to the panel: BOX (area averaging, cheap, exact for the integer
    reductions the layout-size table produces) whenever either axis
    shrinks; NEAREST when both grow, so a small layout previewed on a
    larger panel keeps its hard pixel edges rather than a blurred
    rendition of them."""
    if target[0] < source[0] or target[1] < source[1]:
        return _RESAMPLE_BOX
    return _RESAMPLE_NEAREST


def _fetch_artwork(url: str, timeout: float) -> tuple[bytes | None, str]:
    """Fetch artwork for the panel, at the dial's own size ceiling."""
    return fetch_artwork(url, timeout, MAX_ARTWORK_RESPONSE_BYTES)


def _dirty_windows(diff, bbox) -> list:
    """Split *bbox*, the changed region of the difference image *diff*,
    into up to _WINDOW_SPLIT_MAX_WINDOWS vertically separated windows
    wherever a run of unchanged rows at least _WINDOW_SPLIT_MIN_GAP_PX
    pixels tall lies between changed ones, each window shrunk to its own
    changed columns. Returns [bbox] whenever no split would pay or more
    windows than that would be needed. Every changed pixel lies inside
    exactly one returned window, so the caller's write is complete
    whichever way this decides. Pure; Pillow's own getbbox does the
    scanning, on strips no taller than the gap."""
    left, upper, right, lower = bbox
    width = right - left
    if width <= 0:
        return [bbox]
    gap = max(1, -(-_WINDOW_SPLIT_MIN_GAP_PX // width))
    if lower - upper < 3 * gap:
        return [bbox]
    runs = []
    y = upper
    while y < lower:
        strip_lower = min(lower, y + gap)
        strip_box = diff.crop((left, y, right, strip_lower)).getbbox()
        if strip_box is not None:
            top, bottom = y + strip_box[1], y + strip_box[3]
            if runs and runs[-1][1] == y:
                runs[-1][1] = bottom
            elif runs and y + strip_box[1] - runs[-1][1] < gap:
                runs[-1][1] = bottom
            else:
                runs.append([top, bottom])
                if len(runs) > _WINDOW_SPLIT_MAX_WINDOWS:
                    return [bbox]
        y = strip_lower
    if len(runs) < 2:
        return [bbox]
    windows = []
    for top, bottom in runs:
        box = diff.crop((left, top, right, bottom)).getbbox()
        windows.append((left + box[0], top + box[1], left + box[2], top + box[3]))
    return windows


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


def _repeat_counter_value(rec, now: float) -> float:
    """The replaying counter's unfloored value at *now*: the interpolated
    position less REPEAT_COUNTER_LATENCY_S. Deliberately not clamped: it
    runs negative for the first couple of seconds after a (re)start or a
    loop wrap, which lets the repaint deadline aim at the true moment the
    counter reaches 0:01 rather than waking a second early. Readers that
    need an integer go through DialDisplay._repeat_counter_second(), which
    clamps. The one expression the tick, the deadline and the view builder
    all share."""
    return _interpolate_repeat_position(rec, now) - REPEAT_COUNTER_LATENCY_S


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


# Rich/large artist-row fallback text (see _effective_overlay_locked): shown
# in the artist line's own slot when the tier draws one but there is no real
# artist to put there — an idle or pending focus, or a playing appliance
# with no identified title yet. Compact draws no artist row at all, and base
# keeps its own row unchanged, so neither constant is ever read there.
IDLE_ARTIST_TEXT = "Idle"
PLAYING_ARTIST_TEXT = "Playing"


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
    album: str = ""     # album name, drawn above the title where the layout has room
    # False for an idle or pending focus (an appliance is shown but nothing
    # is actually playing under it) — see the rich/large artist-row fallback
    # in _effective_overlay_locked. True (the default) for a real playback
    # walk result; also feeds the `!=` change check above, so a focused
    # appliance starting or stopping always triggers a repaint.
    playing: bool = True


@dataclass(frozen=True)
class SelectorRow:
    """One row of the appliance-selector screen — see SelectorState."""
    appliance_id: str
    label: str        # appliance_display_name(service_name)
    current: bool     # this row is the focus (manual, else the reporting-from target)
    playing: bool = False  # the appliance is playing now, live or replay
    # False for an appliance confirmed to have refused this dial: listed but
    # marked, never focused or controlled (see selector_pick).
    authorized: bool = True


@dataclass(frozen=True)
class SelectorState:
    """Immutable snapshot of the appliance-selector screen's rows and
    paging, as last built by the poll thread (_refresh_selector_rows).

    rows: every AUTHORIZED or confirmed-UNAUTHORIZED identified appliance
        on the merged roster, idle or playing — see _refresh_selector_rows
        for the exact filter. ALL
        rows across every page, not just the current one; the compositor's
        ListState (built separately, at repaint time) slices out the
        current page.
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


@dataclass(frozen=True)
class InfoRow:
    """One row of the idle screen's read-only info page — see InfoState."""
    label: str
    value: str          # "-" when a source failed or has nothing to report


@dataclass(frozen=True)
class InfoState:
    """Immutable snapshot of the info page's rows and paging. rows: all seven
    fields, ALL pages (the same "every row, sliced at paint time" shape
    PickerState/SelectorState use); page: the current page; opened_at: what
    SELECTOR_TIMEOUT_SECONDS counts down from; gather_seq: which gather
    (see DialDisplay._gather_info) this snapshot's rows belong to, so a
    stale result landing after the page closed/reopened is dropped rather
    than overwriting fresher (or placeholder) rows."""
    rows: tuple[InfoRow, ...]
    page: int
    opened_at: float
    gather_seq: int


# The seven info fields, shown at once and filled in within about a second
# of opening — see DialDisplay.open_info()/_gather_info().
INFO_TITLE = "Info"
INFO_PLACEHOLDER_ROWS: tuple[InfoRow, ...] = tuple(
    InfoRow(label=label, value="-")
    for label in ("Dial name", "Firmware", "IPv4", "WiFi", "Signal", "Disk free", "SD health")
)


@dataclass(frozen=True)
class InfoValueState:
    """The compact info page's own drill-in: which field is showing (an
    absolute index into InfoState.rows, read fresh at paint — see
    DialDisplay._display_info_value_locked, so a gather landing while the
    view is open still shows up) and the inactivity clock.

    hint: (label, text) when the view was opened from the appliance
    selector to explain an unauthorised row (see selector_pick) instead of
    showing an info field; such a view ignores index and its back returns to
    the selector."""
    index: int
    opened_at: float
    hint: "tuple[str, str] | None" = None


@dataclass(frozen=True)
class OutputRow:
    """One row of the outputs list, or the output shown on the detail page."""
    id: str
    name: str
    selected: bool
    volume: int          # 0..100, meaningful when selected


@dataclass(frozen=True)
class OutputsState:
    """The outputs list screen: which appliance it is showing, its last
    fetched rows (remote-in-use outputs already dropped by the worker's
    result parsing), paging and the inactivity clock. rows is () until the
    first fetch lands (loaded False draws the loading placeholder)."""
    appliance_id: str
    service_name: str
    ip: str
    port: int
    rows: "tuple[OutputRow, ...]"
    page: int
    opened_at: float
    loaded: bool = False


@dataclass(frozen=True)
class OutputDetailState:
    """The per-output page: the output it was opened for. Its row is read
    from the outputs state at every paint, so a level change or a
    disappearance shows without this being rebuilt."""
    appliance_id: str
    output_id: str
    opened_at: float


@dataclass(frozen=True)
class EqScreenState:
    """The EQ page: which appliance it is showing and the last fetched
    bass/treble pair. bass_db/treble_db are None until the first fetch for
    THIS appliance lands (loaded False draws "-" and dimmed controls); a
    reopen for the same appliance keeps the last known pair rather than
    blanking the bars (see _open_eq_locked)."""
    appliance_id: str
    service_name: str
    ip: str
    port: int
    opened_at: float
    bass_db: "int | None" = None
    treble_db: "int | None" = None
    loaded: bool = False


@dataclass(frozen=True)
class WarningScreenState:
    """A warning page on screen: which warning, and the clock every
    screen state carries. Its text is read at paint time from the
    descriptor and the manager's latest severity, so a later reading
    shows without reopening."""
    warning_id: str
    opened_at: float


@dataclass(frozen=True)
class RestartingState:
    """The "Restarting..." screen shown from a Restart tap until the reboot
    takes the panel down — or until RESTARTING_TIMEOUT_SECONDS, whichever
    comes first."""
    opened_at: float


# ---------------------------------------------------------------------------
# List-chassis paging (shared by the appliance selector and the replay
# picker, which page the same way over different row types)
# ---------------------------------------------------------------------------

def _rows_per_page_for(width: int, height: int, metrics: "LayoutMetrics | None" = None) -> int:
    return list_layout_for(width, height, metrics=metrics).rows_per_page


def _clamp_page(page: int, row_count: int, rows_per_page: int) -> int:
    """Clamp *page* into [0, last page] for *row_count* rows; 0 when empty."""
    max_page = max(0, (row_count - 1) // rows_per_page) if row_count else 0
    return max(0, min(page, max_page))


def _wrap_page(page: int, row_count: int, rows_per_page: int) -> int:
    """Wrap *page* into [0, page_count) for *row_count* rows; 0 when empty
    — the compact tier's own paging rule (see _apply_screen_requests_locked):
    the picker's "more" advance loops back to page 0 after the last page
    instead of clamping there, since compact has no previous-page control of
    its own to get back with otherwise."""
    pages = max(1, -(-row_count // rows_per_page)) if row_count else 1
    return page % pages


def _page_slice(rows: tuple, page: int, rows_per_page: int) -> tuple[int, tuple]:
    """(start index, the rows on *page*)."""
    start = page * rows_per_page
    return start, rows[start:start + rows_per_page]


def _list_state_for(state, rows_per_page: int, placeholder: str, to_row, pressed=None) -> ListState:
    """Build the compositor's ListState for *state*'s current page, or a
    single non-selected *placeholder* row when there are no rows. *to_row*
    maps one row of *state* to the row tuple ListState carries. *pressed*
    is the (zone, index) pair from the unified pressed channel, passed
    through unchanged — the compositor resolves it against this screen's
    own geometry, so a zone from another screen simply washes nothing."""
    if state is None or not state.rows:
        return ListState(rows=((placeholder, False),), has_prev=False, has_next=False, pressed=pressed)
    start, page_rows = _page_slice(state.rows, state.page, rows_per_page)
    return ListState(
        rows=tuple(to_row(row) for row in page_rows),
        has_prev=state.page > 0,
        has_next=start + rows_per_page < len(state.rows),
        pressed=pressed,
    )


def _selector_list_row(row: SelectorRow) -> tuple:
    if not row.authorized:
        return (row.label, False, NOT_AUTHORISED_TEXT)
    return (row.label, row.current, PLAY_GLYPH) if row.playing else (row.label, row.current)


def _unauthorised_hint(label: str) -> tuple[str, str]:
    """The (title, text) the value view shows for a tap on an unauthorised
    selector row."""
    return NOT_AUTHORISED_TEXT, f"Allow this dial in {label}'s web UI (Setup, Dials)"


def _picker_list_row(row: PickerRow) -> tuple:
    return (row.label, False, format_mmss(row.seconds))


def _output_list_row(row: "OutputRow") -> tuple:
    """One outputs-list row: the level rides in the same secondary-text
    slot the picker uses for durations, right-aligned by the existing row
    renderer; a disabled output shows nothing on the right. No row is ever
    "current" (no wash) and none carries the play marker — the outputs
    list has no notion of either."""
    return (row.name, False, str(row.volume) if row.selected else "")


def _parse_outputs_body(status, body) -> "tuple[OutputRow, ...] | None":
    """Validate and convert a POST /api/dial/outputs response body into the
    manager's own row type. None on anything malformed, non-200 or
    unreachable — transient, so the caller keeps showing the last good
    snapshot, the same discipline _apply_status_to_repeat uses for a bad
    body. An output the appliance reports as in use by another autostream
    instance is dropped entirely, matching the Home page's own filtering."""
    if status != 200 or not isinstance(body, dict) or body.get("ok") is not True:
        return None
    raw = body.get("outputs")
    if not isinstance(raw, list):
        return None
    rows = []
    for o in raw:
        if not isinstance(o, dict):
            return None
        if o.get("remote_in_use"):
            continue
        out_id, name, selected, volume = o.get("id"), o.get("name"), o.get("selected"), o.get("volume")
        if not isinstance(out_id, str) or not out_id or not isinstance(name, str):
            return None
        if not isinstance(selected, bool):
            return None
        if not isinstance(volume, int) or isinstance(volume, bool):
            return None
        rows.append(OutputRow(id=out_id, name=name, selected=selected, volume=max(0, min(100, volume))))
    return tuple(rows)


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
    # True when display_window() can write a sub-rectangle of the panel
    # in place. The manager only diffs frames against a backend that
    # says so; every other backend gets a whole-frame display() per push.
    supports_window_write = False

    def open(self) -> None: ...

    def close(self) -> None: ...

    def clear(self) -> None: ...

    def display(self, image) -> None: ...

    def display_window(self, region, x0: int, y0: int, x1: int, y1: int) -> bool:
        """Write *region*, a panel-space image exactly (x1 - x0 + 1) by
        (y1 - y0 + 1) pixels, to the panel's inclusive address window
        x0..x1, y0..y1, leaving every other pixel as it is. Returns True
        when the window was written and False when this backend cannot
        write a window right now (the caller then falls back to a whole-
        frame display()). May raise on a hardware failure, like display().
        The default cannot: it is the whole-frame-only contract."""
        return False

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
        warnings: "WarningManager | None" = None,
        update_watcher: "UpdateWatcher | None" = None,
        update_seen_path: str = UPDATE_SEEN_PATH,
    ) -> None:
        self._lock = threading.Lock()
        self._config = config
        # The logical size frames are composed/hit-tested in, the physical
        # size they are resampled to, and the density per LOGICAL pixel —
        # one LayoutContext per config object (see dial_display_profiles.
        # layout_context_for()), written only under self._lock (here and in
        # update_config). No touch-thread access.
        self._layout = layout_context_for(config)
        # Physical pixel pitch (mm/px) per LOGICAL pixel, kept as its own
        # attribute since it predates self._layout and is what tests and
        # _layout_metrics() read directly — always equal to self._layout.
        # mm_per_px.
        self._mm_per_px = self._layout.mm_per_px
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

        # The frame most recently pushed to the panel (post-compose,
        # post-resample, post-rotate/BGR) — retained for on-demand
        # screenshotting only. Never mutated after a push (a later push
        # assigns a new object), so holding the reference costs nothing.
        # Cleared whenever the panel no longer shows it (disable/sleep/
        # clear/backend swap). See latest_frame_png().
        self._last_frame: Image.Image | None = None
        # The panel frame's own bytes, viewed as words for the change-region
        # planner (see dial_display_windows), keyed by identity to the very
        # frame object self._last_frame holds: (frame, words) or None. A
        # cache, never authority: whenever the pair no longer names
        # self._last_frame the view is rebuilt from that frame, so the
        # places that drop self._last_frame need not know this exists.
        self._panel_words = None

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
        # Sticky binding to the shown playing appliance, beneath manual
        # focus: appliance_id of whichever appliance the screen is bound to
        # when no manual focus is set, or None. Poll-thread-only plain
        # attribute (like _prev_playing_ids) — written and read exclusively
        # in _poll_once(); mirrors the manual focus whenever one is set, so
        # a later focus clear releases and rebinds exactly like any other
        # release. See _poll_once's binding resolution, right beneath the
        # manual-focus resolution it always defers to.
        self._bound_appliance_id: str | None = None
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
        # Monotonic deadline until which the controls bands are hidden after
        # an artwork tap (0.0, i.e. never, until something arms it) — set by
        # the touch thread, read lock-free by the repaint loop's deadline
        # scheduling and by the overlay gates. Plain float write/read, same
        # discipline as _idle_started_at.
        self._controls_hidden_until: float = 0.0
        # Monotonic start of the artwork reveal slide (the bands' chrome
        # sliding off the panel, or back onto it), 0.0 when none is running.
        # Stamped only by _advance_reveal_locked(), under self._lock on the
        # repaint or poll thread, at the compose that first finds the
        # controls' state changed, so the first slide frame is a frame that
        # actually painted rather than a moment on the touch thread. Cleared
        # by every path that abandons the slide (a screen change, the panel
        # going dark, a screen or tier that does not animate) and, once the
        # slide is done, by the repaint thread under self._lock, only if it
        # is still the start it saw. Plain float write/read, same discipline
        # as _controls_hidden_until.
        self._reveal_started_at: float = 0.0
        # Direction of the slide the start above belongs to: False while the
        # chrome leaves, True while it returns. Written with the start, under
        # self._lock, by _advance_reveal_locked() only.
        self._reveal_sliding_in: bool = False
        # Monotonic time the last reveal frame finished being sent, so the
        # repaint loop waits at least REVEAL_FRAME_GAP_S after it with the
        # lock released. Written only under self._lock (by the two painters,
        # from the repaint and poll threads); read lock-free by the deadline
        # scheduling, where a stale value costs at most one early frame.
        self._reveal_frame_at: float = 0.0
        # Whether the last frame composed for the current screen had its
        # controls steady in place (the now-playing bands, or the repeat
        # screen's replaying chrome: True) or away (False), or None when
        # there is no comparable previous frame: nothing composed yet on this
        # screen, or the panel went dark or showed the idle screen since. The
        # reveal slide starts exactly when this flips between True and False
        # on a compose, whatever made it flip: an artwork tap in either
        # controls mode, the touch side's own dismiss or reveal, or a hide
        # window's expiry. None never starts a slide, so a screen change, a
        # wake or the first track after idle appears as it is. Written under
        # self._lock by the two painters; set to None by a screen change and
        # whenever the panel goes dark or idle.
        self._controls_last: bool | None = None
        # Compact tier only: monotonic deadline until which a compact
        # screen's own controls stay drawn, opened by a touch/reveal/screen
        # change — see _show_compact_controls()/_compact_controls_hidden().
        # Starts at 0.0 (already in the past), so a freshly shown compact
        # screen reads as hidden until the first touch, by design (compact
        # controls start hidden, never flashed on appearance). Plain float
        # write/read, same discipline as _controls_hidden_until.
        self._controls_shown_until: float = 0.0
        # Touch-thread write, worker-thread read: the appliance id a Stop
        # transport was just sent for, so on_repeat_result (worker thread)
        # can tell a Stop's own ok ack apart from a Seek's without new
        # plumbing through the repeat worker (both share the same
        # "transport" kind) — see repeat_stop_tap()/on_repeat_result(). None
        # when no stop is outstanding. Plain reference, same discipline as
        # _focus_pending.
        self._pending_repeat_stop_id: str | None = None

        # ---- Selector, repeat and picker screen state -------------------
        # self._screen is written under self._lock — usually by the repaint
        # thread (_apply_screen_requests_locked()/_close_secondary_locked()),
        # occasionally by the poll thread (the empty-target branch,
        # _sleep_locked) — and read lock-free elsewhere (a plain str read is
        # atomic) — same discipline as the other lock-free-read fields above.
        # "main": the now-playing screen. "selector": the appliance list.
        # "repeat": the repeat screen. "picker": the replay picker.
        # "nowifi"/"sdhealth": warning pages (see WARNING_DESCRIPTORS).
        # "restarting": the reboot screen.
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
        # Plain str written by _display_repeat_locked from the RepeatViewState
        # it just built ("enable" or "replaying") — read lock-free by
        # touch_surface() (with at most one repaint's staleness, the same
        # discipline _check_secondary_timeout's own lock-free reads
        # document) to decide whether the compact tier's own repeat_replay
        # surface applies. Never written or read by any other tier's own
        # touch_surface() branch.
        self._repeat_layout_shown: str = "enable"
        # The integer second the replaying counter last painted, or None
        # while no replaying line is on the panel (the screen just opened,
        # the record left "replaying", or it went unavailable). This is the
        # reference the counter advances against: a tick is due whenever
        # the second the counter should read now differs from it, wherever
        # within the second the wake landed, so a late wake or a status
        # re-sync that moved the interpolated clock can never skip a
        # second. Written only by the repaint thread under self._lock
        # (_open_repeat_locked, _display_repeat_locked) and read only by
        # the repaint thread's own tick/deadline/builder, so those reads
        # need no lock.
        self._repeat_painted_second: int | None = None
        # The replay picker's own rows/paging — refreshed every poll tick
        # regardless of whether it is open, mirroring self._selector.
        self._picker: PickerState | None = None
        # The info page's own state — written under self._lock by its
        # opener (_open_info_locked) and by _gather_info's fold-in (its own
        # short-lived daemon thread, the on_outputs_result fold-in
        # discipline: one assignment under the lock, no I/O while held).
        self._info: InfoState | None = None
        # Bumped by open_info() (touch thread, no lock — a plain int write)
        # each time the page (re)opens; a landing gather compares its own
        # captured value against this one and drops its result if they no
        # longer match (the page closed and reopened, or closed outright).
        self._info_gather_seq = 0
        # The compact info page's own drill-in state — same write/read
        # discipline as self._info, kept alongside it (not cleared when the
        # value view opens: the view is the list's child and reads its rows
        # from self._info at every paint — see _display_info_value_locked).
        self._info_value: InfoValueState | None = None
        # Touch-thread plain write: the row a LIST_ROW tap on the compact
        # info list chose, consumed by the value view's opener — the
        # self._output_open_id shape.
        self._info_value_index: int | None = None
        # Touch-thread plain write: the (label, text) hint a tap on an
        # unauthorised selector row asks the value view to show, consumed
        # by the view's opener like self._info_value_index.
        self._info_value_hint: tuple[str, str] | None = None
        # Zero-arg callable -> tuple[InfoRow, ...], wired by set_info_provider()
        # at startup (dial_main.py, after the HTTP server exists). None
        # (e.g. a NoOpDisplayStatusProvider stand-in, or before wiring runs)
        # means _gather_info() falls back to the placeholder rows.
        self._get_info_rows = None
        # The outputs list screen's own state — written under self._lock by
        # its opener and by on_outputs_result's fold (worker thread); read
        # lock-free by the touch thread's outputs_row_tap()/output_toggle_
        # tap()/output_volume_tap() entries, mirroring self._repeat_screen's
        # discipline.
        self._outputs: OutputsState | None = None
        # The per-output detail page's own state — same write/read
        # discipline as self._outputs.
        self._output_detail: OutputDetailState | None = None
        # Touch-thread plain write: the row a LIST_ROW tap on the outputs
        # list chose, consumed by the detail page's opener.
        self._output_open_id: str | None = None
        # Touch-thread plain write: an optimistic (output_id, selected,
        # volume, stamped-time) override shown immediately after a toggle or
        # volume step, before the worker's reconciling fetch lands — same
        # plain-reference discipline as self._pressed/self._overlay_snapshot.
        # Cleared once a fetch result stamped after it lands (on_outputs_
        # result) or once a stale one is superseded.
        self._outputs_optimistic: "tuple[str, bool, int | None, float] | None" = None
        # Repeat-thread-only: when an outputs screen last asked for a
        # refresh — see _tick_outputs_refresh().
        self._outputs_refresh_at: float = 0.0
        # Whether the top-right OUTPUTS zone is currently live — poll thread
        # only (_update_outputs_available); read lock-free by touch_surface().
        self._outputs_available = False
        # The EQ page's own state — same write/read discipline as
        # self._outputs: written under self._lock by its opener and by
        # on_eq_result's fold (worker thread); read lock-free by the touch
        # thread's eq_step() entry.
        self._eq: "EqScreenState | None" = None
        # Touch-thread plain write: a pending optimistic (bass, treble,
        # expires_at) override shown immediately after an eq_step() tap,
        # before the worker's reconciling fetch lands — same plain-reference
        # discipline as self._outputs_optimistic. Either element of the pair
        # may be None (only one control was just stepped); cleared once a
        # fetch result stamped after it lands (on_eq_result) or once it
        # expires.
        self._eq_optimistic: "tuple[int | None, int | None, float] | None" = None
        # Whether the EQ page is available for the currently focused/
        # reporting appliance — poll thread only (_update_eq_available);
        # read lock-free by cycle_pages()/touch_surface()/
        # _effective_overlay_locked()/_build_repeat_view_locked(). False on
        # the compact tier even when the appliance advertises dial_eq (no
        # EQ page there).
        self._eq_available = False
        # ---- Wi-Fi link state (the idle icon and the No-WiFi page) ------
        # The latest NetworkView from the network poller — written by the
        # poller's own thread in on_network_view() (a plain reference
        # assignment, no lock — the on_repeat_result discipline), read at
        # paint time under self._lock and lock-free by the repaint loop's
        # deadline scheduling. None until the first poll lands (drawn as an
        # all-grey, steady icon).
        self._network: "NetworkView | None" = None
        # Consecutive down polls; reset by any connected poll. Poller
        # thread only.
        self._wifi_down_streak = 0
        # Whether any poll since this process started has reported the link
        # connected. Poller thread only (set in on_network_view), never
        # reset — not by a later down/ignored poll and not by disable()/
        # enable() or a backend swap: it describes this boot, not the panel.
        # Read lock-free by the auto-prompt gate on the poller thread and
        # under self._lock by the idle painter. It splits a DOWN link into
        # two looks: a dial still connecting after boot (never connected
        # yet) flashes the icon grey/blank and raises no prompt, while a
        # dial that has lost a link it had flashes grey/red and raises the
        # No-WiFi page — the alarm is for a loss, not for booting.
        self._wifi_ever_connected = False
        # The restarting screen's own state, same write/read discipline as
        # self._info (opener under self._lock, cleared by
        # _close_secondary_locked via the policy table).
        self._restarting: "RestartingState | None" = None
        # ---- SD card health (the warning page and the info row) ---------
        # The latest reader view: written by the network poller's thread in
        # on_sd_health_view() (plain reference assignment, no lock), read
        # at paint time under self._lock.
        self._sd_health: "SdHealthView | None" = None
        # The incident latch: True from the first reading below the low
        # threshold until one strictly above the recover threshold, or
        # until monitoring is off. Poller thread only.
        self._sd_low = False
        # The warning page on screen, if any (the one state attribute every
        # warning row in the policy table shares), and the manager that
        # owns which warnings are active, snoozed or due. The manager is
        # injected by tests; the default reads and writes the dial's own
        # state file.
        self._warning_screen: "WarningScreenState | None" = None
        self._warnings = warnings if warnings is not None else WarningManager(
            WARNING_DESCRIPTORS, WarningStore(),
        )
        # The software update source: the result file's watcher and the
        # marker of the last finished result the screen has shown (read on
        # first use, written when a result card is raised). Repaint thread
        # only.
        self._update_watcher = update_watcher if update_watcher is not None else UpdateWatcher()
        self._update_seen_path = update_seen_path
        self._update_seen: "str | None" = None
        # The (zone, index) currently pressed on whichever screen is
        # showing — one channel for every screen, written by the touch
        # thread via set_pressed() and read at compose time by each
        # screen's own frame builder (_effective_overlay_locked,
        # _build_repeat_view_locked, _build_list_state_locked/
        # _build_picker_list_state_locked), which resolves it against its
        # own geometry. index is only meaningful for LIST_ROW; every other
        # zone carries None. Plain attribute, same discipline as
        # dial_touch's own pressed-zone tracking.
        self._pressed: "tuple[TouchZone, int | None] | None" = None
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
        # The page the outputs list goes back to when it closes: the main
        # page it was opened from ("main", "repeat" or "eq"), recorded by
        # _open_outputs_locked() and kept across the per-output detail
        # page, whose own back returns to the list. See _back_target().
        self._outputs_return = "main"
        # The replay position line shown on the main page after a replay
        # is started from the picker (see picker_pick()): the appliance it
        # is for (None: no timer), when the pick armed it, when its first
        # line was drawn (0.0: not yet; the REPLAY_TIMER_SHOW_S window
        # counts from then), and when the last fade frame left. Written by
        # the touch thread (arm) and the repaint thread (the rest); plain
        # float/str assignments, the same discipline as self._pressed.
        self._replay_timer_id: "str | None" = None
        self._replay_timer_armed_at = 0.0
        self._replay_timer_shown_at = 0.0
        self._replay_timer_frame_at = 0.0
        self._replay_timer_signal_at = 0.0  # last repaint the timer's own tick asked for
        # (appliance_id, until): a replay the appliance has just accepted,
        # shown as playing until its own advertisement arrives. Set by the
        # repeat worker's ack (on_repeat_result), cleared by the poll
        # thread (_with_accepted_replay); a plain tuple assignment either
        # way, the same discipline as self._focus_pending.
        self._accepted_replay: "tuple[str, float] | None" = None
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
        # A Dismiss inside the last tick has not been written yet.
        self._warnings.flush()
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
            if bgr:
                frame = Image.merge("RGB", frame.split()[::-1])
            if rotate:
                frame = frame.transpose(Image.ROTATE_180)
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
                        self._source_artwork_url = ""
                        self._current_rendered_image = None
                        self._current_base_image = None
                        self._close_secondary_locked()
                        self._render_logo_locked()
                        self._poll_wake.set()
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
        Also re-opens the compact tier's own controls window (see
        _show_compact_controls()) — a plain float write beside the flag
        write above, harmless on every other tier, where nothing ever reads
        it.
        """
        self._touch_activity_pending = True
        self._show_compact_controls()
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

    def set_overlay(self, state: OverlayState) -> None:
        """Publish a new touch-overlay snapshot and signal the repaint
        thread to recompose/push it.

        Never touches self._lock — see the LOCK ORDER comment in __init__.
        Safe to call from the touch thread at touch cadence: the write here
        is a single leaf-lock-guarded assignment, and the actual compose +
        SPI push happens later, asynchronously, on the repaint thread.

        A visible overlay ends an artwork-tap hide window (see
        hide_controls()) early: a normal reveal — the ordinary tap-to-show
        path, or an always-show track that just resumed showing controls —
        must not be fighting a hide window that still has time left on it.
        Plain float write, same discipline as the window's own start. Also
        opens the compact tier's own controls window (see
        _show_compact_controls()) — this is the reveal path
        (on_reveal_overlay -> set_overlay(visible=True)), so a compact
        screen's first touch after being hidden shows its controls rather
        than only ending the (irrelevant, off-compact) hide window.

        A visible overlay leaves any reveal slide alone: the repaint that
        finds the controls back turns a running slide-out around from where
        it has got, or starts the slide-in, on the rich and large tiers (see
        _advance_reveal_locked()); this method never stamps or clears the
        slide, which belongs to the painters.
        """
        if state.visible:
            self._controls_hidden_until = 0.0
            self._show_compact_controls()
        with self._overlay_snapshot_lock:
            self._overlay_snapshot = state
        self._overlay_signal.set()

    def current_source_service_name(self) -> str | None:
        """mDNS service name of the display's chosen artwork source, or
        None when nothing is identified/playing. Plain reference read, safe
        from any thread; may lag the poll by up to one poll cycle. Used by
        dial_main's volume-target resolver (see _build_volume_targets_fn) so
        a touch/encoder press addresses whatever this dial is showing — or,
        with a manual focus, the focused appliance, see
        focus_volume_target()."""
        return self._source_service_name

    def focus_volume_target(self):
        """The roster entry the volume/mute worker should address while a
        manual focus is set: that appliance, playing or idle, when it is on
        the last-published roster and not confirmed unauthorized; else None
        (no focus, or the focus is unresolved this tick), meaning "use the
        ordinary playing-set resolution". Plain reference reads of
        self._manual_focus_id and self._last_roster, safe from the worker
        thread — the same discipline current_source_service_name() uses;
        may lag the poll by one cycle."""
        focus_id = self._manual_focus_id
        if not focus_id:
            return None
        for r in self._last_roster:
            if r.appliance_id == focus_id:
                return r if r.auth != AUTH_UNAUTHORIZED else None
        return None

    def persistent_overlay_shown(self) -> bool:
        """True while the display is holding the controls overlay visible
        on its own (always_show_controls on OR the resolved content tier is
        compact, a controllable appliance shown, backend open, not asleep,
        and the MAIN screen is showing — never true while the appliance
        selector is open). The compact tier's own screens have no reveal
        step of their own regardless of the always_show_controls setting —
        every cell on a compact screen is already a control, so a
        reveal-then-arm rule would cost every action a second tap; see
        _compact_tier(). Plain attribute reads;
        the touch thread polls this once per loop iteration (see dial_touch.
        TouchEventSource._poll_held_visible, the legacy fallback path) so a
        finger can never arm against controls that are not actually drawn —
        when this turns False (screen went idle, went to sleep, the setting
        was turned off, or the selector opened), the touch side is forced
        back to reveal-on-touch within one loop tick.

        "A controllable appliance shown" is self._now_playing is not None —
        true for both real artwork and the playing-placeholder logo shown
        across a track change, false only when nothing is playing at all.
        The self._showing != "noop" term covers the moment right after the
        panel is cleared (see _clear_locked): the panel is momentarily blank
        even though self._now_playing may still be set, so nothing is
        actually on screen for the overlay to be held over until the next
        repaint recomposes a base image. An artwork tap (see hide_controls())
        also drops this to False for its own window, regardless of
        always_show_controls — the bands are hidden either way.

        On the compact tier, always_show_controls is ignored (a compact
        screen is never held permanently): instead the controls show for a
        few seconds after a touch/reveal/screen change and then fade back
        to bare artwork on their own — see _compact_controls_hidden().
        """
        return (
            (
                (self._config.always_show_controls and not self._compact_tier())
                or (self._compact_tier() and not self._compact_controls_hidden())
            )
            and self._now_playing is not None
            and self._showing != "noop"
            and self._backend_open
            and not self._display_sleeping
            and self._screen == "main"
            and not self._controls_hidden()
        )

    def _compact_tier(self) -> bool:
        """True while the resolved content tier is compact — the physically
        tiny 2x2 screens. Plain-arithmetic read, safe from any thread, same
        as _layout_metrics() itself."""
        return self._layout_metrics().content_tier == CONTENT_COMPACT

    def _compact_controls_hidden(self) -> bool:
        """Compact tier only: True once the controls window (see
        _show_compact_controls()) has lapsed, or was never opened — a
        freshly shown compact screen starts hidden (bare artwork), by
        design: controls only appear after a touch/reveal, never flashed on
        appearance. Always False off the compact tier. Plain float read,
        same discipline as _controls_hidden()."""
        return self._compact_tier() and time.monotonic() >= self._controls_shown_until

    def _show_compact_controls(self) -> None:
        """Re-open the compact tier's own controls window: plain float
        write, no lock (touch-thread safe, and also called from the repeat
        thread under self._lock on a screen change — a plain float write is
        harmless either way). Stamped by set_overlay()'s reveal path,
        notify_touch_activity() (every arm/tap/pressed-zone change) and a
        screen change (_apply_screen_requests_locked) — see the module's
        compact-controls design. A harmless no-op read/write on every other
        tier, where nothing consults it."""
        self._controls_shown_until = time.monotonic() + CONTROLS_HIDE_SECONDS

    def hide_controls(self) -> None:
        """Touch-thread entry (dial_main's on_zone_tap, for an ARTWORK
        tap on the now-playing screen, or a tap on the replay screen's own
        artwork while a replay runs): hide the top/bottom bands for
        CONTROLS_HIDE_SECONDS, so a tap on the artwork itself gives an
        unobstructed view of it. Plain float write plus a repaint signal,
        same discipline as notify_touch_activity(). While the window holds
        the overlay is not drawn whatever the touch snapshot says,
        persistent_overlay_shown() reads False and touch_surface() reports
        "hidden", so the state machine drops to reveal-on-touch; a tap
        while hidden is the ordinary reveal (on_reveal_overlay ->
        set_overlay(visible=True)), which ends the window early (see
        set_overlay()). The window's own expiry is woken by the repaint
        loop's deadline scheduling (_next_repaint_deadline/
        _tick_controls_hidden).

        On the rich and large tiers the bands do not vanish at once: the
        first repaint that finds them due to go starts a short slide (see
        _advance_reveal_locked()) in which each band's chrome leaves over
        its panel edge and the inter-band text fades, ending on exactly the
        bare frame the window then holds. The controls' return, whether the
        window lapses or a reveal ends it early, slides them back in the same
        way. The slide is the painters' own; nothing is stamped here.

        A no-op off the two screens that have artwork to reveal: the
        now-playing screen, and the replay screen exactly while a replay is
        running (its enable layout has no artwork, and a stopped replay's
        Restart control must stay visible); and on the compact tier, which
        has no artwork zone to tap."""
        screen = self._screen
        if screen == "repeat":
            if not self._repeat_replaying_lockfree():
                return
        elif screen != "main":
            return
        if self._compact_tier():
            return
        self._controls_hidden_until = time.monotonic() + CONTROLS_HIDE_SECONDS
        self._overlay_signal.set()

    def _repeat_replaying_lockfree(self) -> bool:
        """True while the repeat screen's own appliance is replaying right
        now, read the way repeat_stop_tap() reads it (plain reference of
        self._repeat_screen, the store's own leaf lock): the only repeat
        layout with artwork behind its controls to reveal."""
        screen = self._repeat_screen
        if screen is None:
            return False
        rec = repeat_store.get(screen.appliance_id, time.monotonic())
        return rec is not None and rec.available and rec.state == "replaying"

    def _controls_hidden(self, now: float | None = None) -> bool:
        """True while an artwork tap's hide window is still running. Plain
        float read, same discipline as _display_sleeping's own reads. *now*
        lets a compose pass its own single clock read through."""
        if now is None:
            now = time.monotonic()
        return now < self._controls_hidden_until

    def _slide_tier(self) -> bool:
        """Whether this panel animates the reveal: the tiers that draw
        bands the chrome can slide off. The base tier keeps its instant
        hide and show; the compact tier has no bands. Plain-arithmetic read, safe
        from any thread."""
        return self._layout_metrics().content_tier in (CONTENT_RICH, CONTENT_LARGE)

    def _reveal_animating(self, now: float) -> bool:
        """True while a reveal slide is running: a start is stamped and its
        duration has not run out, in either direction. Plain float read, safe
        from any thread. Every path that abandons the slide zeroes the
        start (see _apply_screen_requests_locked(),
        _mark_noncomposited_locked(), _advance_reveal_locked()), so the
        slide never outlives what it was sliding."""
        started = self._reveal_started_at
        return started != 0.0 and now < started + REVEAL_ANIMATION_S

    def _reveal_progress(self, now: float) -> float:
        """How far the reveal has slid the bands off the panel at *now*, 0.0
        (in place) to 1.0 (gone), eased (see _reveal_ease); 0.0 whenever no
        reveal is running, which the compositor draws as the ordinary
        frame. While the bands slide in the same position runs backwards
        (1.0 down to 0.0). Computed from the clock at compose time and never
        stored, so a compose that lands late simply draws the later position
        and one that lands after the end draws none."""
        if not self._reveal_animating(now):
            return 0.0
        e = _reveal_ease(self._reveal_fraction(now))
        return (1.0 - e) if self._reveal_sliding_in else e

    def _reveal_fraction(self, now: float) -> float:
        """The running slide's clamped time fraction 0..1 at *now*."""
        t = (now - self._reveal_started_at) / REVEAL_ANIMATION_S
        return min(1.0, max(0.0, t))

    def _advance_reveal_locked(self, now: float, steady: bool, slide_ok: bool) -> tuple[bool, float]:
        """Decide, for the frame about to be composed at *now*, whether it
        is a slide frame and how far along: (animating, progress). *steady*
        is whether the screen's controls would be drawn in place by this
        frame if no slide were running; *slide_ok* whether this screen and
        tier animate at all right now. A slide starts exactly when the
        previous frame's controls state differs from this one's: the tap
        that hid them (in either controls mode), the touch side's own
        dismiss, and the controls' return (a hide window lapsing, a reveal
        tap, the first touch) all arrive here as that one transition, the
        direction being *steady*. The start is stamped at this compose, so
        the first slide frame is the ordinary frame at progress 0 (identical
        to the last one, so nothing is transmitted) and every later frame is
        measured from a moment a frame actually painted, never from the tap
        on another thread. A change that lands mid-slide turns it around
        from where it has got: the easing is symmetric, so a slide restarted
        at the mirrored fraction continues from exactly the position last
        drawn. With no previous frame to compare (None), or where the screen
        or tier does not animate, the controls simply snap and any slide is
        dropped. Caller holds self._lock."""
        if not slide_ok:
            self._reveal_started_at = 0.0
            self._controls_last = None
            return False, 0.0
        last = self._controls_last
        if last is not None and last != steady:
            t_cur = self._reveal_fraction(now) if self._reveal_animating(now) else 1.0
            # Never 0.0, the "no slide" value.
            self._reveal_started_at = (now - (1.0 - t_cur) * REVEAL_ANIMATION_S) or 1e-9
            self._reveal_sliding_in = steady
        self._controls_last = steady
        animating = self._reveal_animating(now)
        return animating, (self._reveal_progress(now) if animating else 0.0)

    def _held_overlay_locked(self, now: float) -> bool:
        """The held-visible predicate _effective_overlay_locked() applies:
        always-show on (off compact), or the compact tier's own controls
        window open; a controllable appliance shown; the panel not cleared
        or asleep; and no artwork-tap hide window running. Caller holds
        self._lock."""
        return (
            (
                (self._config.always_show_controls and not self._compact_tier())
                or (self._compact_tier() and not self._compact_controls_hidden())
            )
            and self._now_playing is not None
            and self._showing != "noop"
            and not self._display_sleeping
            and not self._controls_hidden(now)
        )

    def touch_surface(self) -> tuple[str, bool, bool, bool]:
        """(surface, name_active, dots_active, outputs_active) for
        dial_touch.TouchStateMachine.set_surface() — see that module's
        SURFACES paragraph. Polled once per loop iteration by
        TouchEventSource; a plain-attribute read discipline, same as
        persistent_overlay_shown() and noncomposited_generation().

        outputs_active is true whenever the currently focused/reporting
        appliance advertises dial_outputs — see _poll_once, which computes
        it into self._outputs_available every tick via
        _update_outputs_available(). False whenever nothing controllable
        is shown (there is no appliance for the top-right zone to act on).

        name_active is true whenever there is a controllable appliance
        currently shown (self._now_playing is not None) — unconditional:
        the appliance name and its tap-zone are always active in that
        case, never gated on how many appliances are authorized. It is
        independent of held/hidden: by the time a second press can sample
        the NAME zone at all, the REVEAL-ONLY FIRST TOUCH rule
        (dial_touch.py) has already made the overlay visible.

        While the bands slide back in (see _advance_reveal_locked()) the
        surface is already the ordinary one: it follows the overlay state,
        not the animation, so a tap acts on a band as it arrives.

        dots_active is true whenever the currently focused/reporting
        appliance has a fresh, available repeat-store record — see
        _poll_once, which computes it into self._dots_active every tick.
        "idle" is reported whenever nothing is playing, not only while the
        idle affordance is drawn — the info page's "i" affordance must be
        reachable on every idle dial. A replay tap on a plain logo still
        stays inert (see open_picker()'s own guard); only the idle
        affordance decides whether IDLE_REPLAY actually does anything.

        Every secondary screen's surface tuple is fixed by its policy row
        (ScreenPolicy.surface) — the repeat screen's own top-band NAME zone
        is always meaningful while it is showing (it only ever opens for a
        focused/reporting appliance, and closes before that appliance's
        name could go stale — see toggle_repeat_screen() and the empty-
        target branch of _poll_once). A row whose own tuple asks for the
        outputs zone (the repeat screen's own top-right readout) still
        gates on the live self._outputs_available, same as main; a row
        that carries False there is unaffected.

        A policy row whose own ScreenPolicy.replay_surface is set reports
        that second surface tuple instead, exactly while the compact tier's
        own replaying layout is the one actually painted (self.
        _repeat_layout_shown == "replaying") — the repeat screen's own
        time/Restart/Stop cells sit on different rectangles than its enable
        layout only on that tier (see dial_touch_layout.GEOMETRY_REPEAT_
        REPLAY); every other tier paints one shared table for both states,
        so this branch is never taken there.

        Ahead of every policy row: on the compact tier, once that screen's
        own controls window has lapsed (see _compact_controls_hidden()),
        main and repeat both report plain "hidden" with nothing tappable —
        the main branch below already arrives at "hidden" on its own once
        persistent_overlay_shown() is False, but the repeat screen's surface
        is otherwise fixed by its policy row regardless of the window, so it
        needs this explicit override.

        The replay screen's own artwork-tap hide window (see
        hide_controls()) reports the main geometry's plain "hidden" as well,
        with the appliance's name and dots and the outputs readout still
        addressable: nothing is drawn to tap, so a touch brings the
        controls back and never actuates Restart, Stop or the dots.
        """
        if self._compact_controls_hidden() and self._screen in ("main", "repeat"):
            return ("hidden", False, False, False)
        if self._screen == "repeat" and self._controls_hidden():
            return ("hidden", True, self._dots_active, self._outputs_available)
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
            return (s[0], s[1], s[2], s[3] and self._outputs_available)
        if self._now_playing is None:
            return ("idle", False, False, False)
        name_active = True
        dots_active = self._dots_active
        outputs_active = self._outputs_available
        if self.persistent_overlay_shown():
            return ("held", name_active, dots_active, outputs_active)
        return ("hidden", name_active, dots_active, outputs_active)

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
        # A successful open clears any stale unrelated failure — today only
        # a successful artwork render did this, so a successful screen_type
        # swap would otherwise keep reporting a stale error and defeat drift
        # detection.
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
        self._last_frame = None
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
        self._last_frame = None
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
        self._last_frame = None
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
        # A press latched against geometry that just went dark must not
        # carry a wash into whatever comes back on screen next.
        self._pressed = None
        # Nothing is on screen for a hide window or a slide to belong to.
        self._controls_hidden_until = 0.0
        self._reveal_started_at = 0.0
        self._controls_last = None

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
        # A warning that was popped by sleep, or became due while asleep,
        # comes straight back: the request lands before the repaint that
        # follows this wake folds its screen requests.
        self._request_due_warning()

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

    def _logical_dims(self) -> tuple[int, int]:
        """The compose-space size every frame is built and hit-tested in:
        the chosen layout size when one is set, else the open backend's own
        dimensions (or the default profile's, when no backend is open) —
        exactly what _active_panel_dims() has always returned. May be
        called with or without self._lock held (plain attribute reads)."""
        if self._layout.size_chosen:
            return self._layout.logical_size
        return self._active_panel_dims()

    def _layout_metrics(self) -> LayoutMetrics:
        """LayoutMetrics for the logical size and the density per logical
        pixel. Pure arithmetic on plain attribute reads, so safe from any
        thread, with or without self._lock — the touch thread's page
        slicing and the repaint thread's compose both read this one
        function, so they can never disagree about rows per page."""
        width, height = self._logical_dims()
        return metrics_for(
            width, height, mm_per_px=self._mm_per_px, size_chosen=self._layout.size_chosen,
        )

    def _metrics_locked(self) -> LayoutMetrics:
        """The active screen's LayoutMetrics. Caller holds self._lock;
        computed once per compose, a handful of multiplications, nothing
        per pixel. A thin delegate to _layout_metrics() kept under its own
        name for its existing call sites."""
        return self._layout_metrics()

    def _push_frame_locked(self, compose) -> None:
        """Compose one frame at the logical size and push it to the
        backend, resampling to the panel's physical size first if the two
        differ — recording a write failure the same way for every screen.
        *compose* is a zero-argument callable returning the finished frame;
        it runs inside the guard so a compositor failure is handled
        identically to a backend/resample failure. Caller holds self._lock
        and has already checked the backend is open. Never raises.

        The transmit itself is delegated to _transmit_locked(), which sends
        only the part of the frame that differs from the one already on the
        panel when the backend can write a window. A transmit failure drops
        self._last_frame: the panel may then hold part of the new frame, so
        the next push must write the whole of it rather than a diff against
        a frame that is no longer what the panel shows. A compose failure
        sends nothing and leaves self._last_frame as it was."""
        try:
            composed = compose()
            physical = (self._backend.width, self._backend.height)
            if composed.size != physical:
                composed = composed.resize(physical, _resample_filter(composed.size, physical))
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
        """Send *composed*, already at the panel's size and orientation, to
        the backend, writing only the regions that differ from the frame the
        panel already shows when the backend can write a window: as many
        separate rectangles as the cost model says pay for themselves (see
        dial_display_windows), or, on a dial without numpy, the bounding
        box split in up to a few places (see _dirty_windows).

        The frame reaching here is final: rotate and colour order were
        applied by the compositor and the resample to physical size by the
        caller, and self._last_frame is kept in that same space. So the
        rectangles of the pixel difference are in panel pixels and map
        straight onto the panel's address window, with no further
        transform. An identical frame sends nothing at all. A whole-frame
        write is used instead whenever the backend cannot window-write,
        nothing is known to be on the panel, the two frames are not
        comparable (size or mode differ), the window write reports it
        could not run, or anything in the windowed path fails: a diff or
        window problem must never cost the frame, only the saving. Raises
        only what the whole-frame display() raises; the caller records
        that."""
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
                # No planner (numpy missing, or a plan failure): the
                # bounding-box path, with its own vertical split.
                diff = ImageChops.difference(composed, last)
                bbox = diff.getbbox()
                if bbox is None:
                    return
                boxes = _dirty_windows(diff, bbox)
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
        """(boxes, new_words) for the change-region planner: *boxes* is the
        list of windows to write, top to bottom (empty: the frames are
        identical), and *new_words* the planner's view of *composed* for the
        caller to cache once it is on the panel. (None, None) when the
        planner is unavailable (numpy missing, or a plan failure), in which
        case the caller takes the bounding-box path. The previous frame's
        words come from the cache when it still names *last*, else from
        *last* itself. A planner failure is logged (rate-limited) and
        reported as unavailable. Never raises. Caller holds self._lock."""
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

    def _display_locked(self, image) -> None:
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

        Whether the overlay is held over *image* is decided in
        _effective_overlay_locked() from self._now_playing, not from
        anything about *image* itself — a controllable appliance shown
        (real artwork or the playing-placeholder logo) holds the overlay;
        nothing playing does not. See persistent_overlay_shown() and
        _effective_overlay_locked() for the shared predicate.

        While a reveal slide is running (see _advance_reveal_locked()) the
        compose also receives how far it has got, from the one clock read
        this frame makes, so a poll-driven repaint landing mid-slide
        composes its fresh base under the chrome at its current position
        rather than fighting the animation, and a frame that lands after
        the end draws the bare frame, never the full bands.
        """
        if not (self._backend_open and self._backend is not None):
            return
        self._current_base_image = image
        metrics = self._metrics_locked()
        now = time.monotonic()
        snapshot = self._overlay_snapshot
        steady = (snapshot.visible or self._held_overlay_locked(now)) and not self._controls_hidden(now)
        slide_ok = (
            self._screen == "main"
            and self._slide_tier()
            and self._now_playing is not None
            and self._showing != "noop"
            and not self._display_sleeping
        )
        animating, progress = self._advance_reveal_locked(now, steady, slide_ok)
        overlay = self._effective_overlay_locked(snapshot, now=now, animating=animating)
        timer = self._replay_timer_locked(now) if self._screen == "main" else None
        self._push_frame_locked(lambda: self._compositor.compose(
            image, metrics.width, metrics.height,
            rotate=self._config.rotate,
            bgr=self._config.bgr,
            is_artwork=False,
            overlay=overlay,
            metrics=metrics,
            reveal_progress=progress,
            timer_text=timer[0] if timer else None,
            timer_alpha=timer[1] if timer else 1.0,
        ))
        if timer:
            # The same reference the repeat screen's own counter advances
            # against (see _display_repeat_locked()); that screen re-anchors
            # it whenever it opens.
            self._repeat_painted_second = timer[2]
            if timer[1] < 1.0:
                self._replay_timer_frame_at = time.monotonic()
        if animating:
            # Paced from the moment the frame has actually left, so the
            # loop's wait between slide frames is a real gap with the lock
            # released, however long the transmit took.
            self._reveal_frame_at = time.monotonic()

    def _repaint_base_locked(self, image, *, idle_ok: bool) -> None:
        """Publish a freshly chosen base image (artwork or logo) from the
        poll thread, without ever switching away from a secondary screen.

        On the main screen this composes the base straight to hardware — the
        idle-chassis path when *idle_ok* and nothing plays (the
        replay-available logo with no controls overlay), otherwise the
        ordinary overlay compose. While a secondary screen is up it only
        refreshes the cached base and signals a repaint: the repeat, EQ and
        No-WiFi screens draw the base behind them and recompose over the new
        image on the next repaint, and the flat list/info screens ignore it
        and repaint unchanged. Either way the screen the user is on stays on
        screen — fresh artwork lands behind it rather than popping it back to
        the volume screen. Caller holds self._lock.
        """
        self._current_base_image = image
        if self._screen != "main":
            self._overlay_signal.set()
            return
        if idle_ok and self._idle_chassis_due_locked():
            self._display_idle_locked()
        else:
            self._display_locked(image)

    def _show_transition_locked(self) -> None:
        """A plain dark base while the newly-shown appliance's own artwork
        or logo is fetched/rendered: the previous appliance's artwork must
        never linger on screen under the new appliance's name — see
        _maybe_show_transition(), which calls this exactly when the
        reporting-from appliance has just changed. Caller holds self._lock;
        a no-op when no backend is open. Drops the artwork cache so the
        fetch that follows always paints, and marks self._showing
        "waiting" so neither show_logo()'s nor _show_artwork()'s own
        dedupe (both compare against "logo"/"artwork") mistakes this for
        already showing something."""
        if not (self._backend_open and self._backend is not None):
            return
        width, height = self._logical_dims()
        self._source_artwork_url = ""
        self._current_rendered_image = None
        self._showing = "waiting"
        self._display_locked(Image.new("RGB", (width, height), _TRANSITION_RGB))

    def _effective_overlay_locked(
        self, snapshot: OverlayState, now: float | None = None, animating: bool | None = None,
    ) -> OverlayState:
        """Merge now-playing state into the touch-published overlay snapshot
        at compose time.

        The touch side only ever publishes CONTROL state (visible,
        muted-if-known) via set_overlay() — it has no idea what track is
        playing or what the master volume is, and must not need to, per the
        module docstring's "touch thread stays ignorant of polling" rule.
        pressed is filled from the unified pressed channel (self._pressed)
        instead — the snapshot's own pressed field, if any, is ignored; see
        set_pressed(). This fills in the fields only the poll thread knows
        about:
          - artist: from the reporting-from target's last poll result.
          - album: from the same poll result.
          - volume: the optimistic readout for that same target (see
            dial_volume.shown_volume()), not the raw polled master_volume —
            the readout already reconciles the polled value with any
            pending delta.
          - muted: the reporting-from target's last reported mute state
            (dial_volume.shown_muted()) — never the touch-published
            snapshot's own field any more; the touch side's optimistic echo
            of a press already lives in that same observation store (see
            enqueue_mute()), so there is nothing left for the snapshot's own
            value to add.
          - name: appliance_display_name() of the reporting-from target's
            service name, or "" when nothing is playing. ALWAYS populated
            whenever a controllable appliance is shown — unconditional,
            never gated on how many appliances are authorized.

        held-visible (see _held_overlay_locked()): when always_show_controls
        is on and a controllable appliance is shown (self._now_playing is
        not None — true for real artwork and for the playing-placeholder
        logo shown across a track change; false only when nothing is
        playing at all), and the display is not asleep, the overlay is
        forced visible here regardless of what the touch-published snapshot
        says — this is what makes a stale
        visible=False snapshot, or a dismiss landing while held, harmless
        (see dial_touch.py's HELD VISIBLE paragraph and set_held_visible()).
        It is also what keeps the overlay drawn across a track change: the
        base image swaps to the placeholder logo and the artist/title clear,
        but self._now_playing stays non-None throughout, so the held overlay
        is preserved rather than dropped. The self._showing != "noop" term
        mirrors persistent_overlay_shown()'s own guard against the moment
        right after the panel is cleared. An artwork-tap hide window (see
        hide_controls()) hides the overlay whatever the snapshot says,
        except while the slide is still drawing it on its way off (see
        _reveal_animating()), when it is merged regardless so the chrome can
        be slid. Deliberately does not also check self._backend_open: the
        caller (_display_locked) already returned early when the backend is
        closed, so there is nothing left to guard against here. *now* and
        *animating* let the caller pass the single clock read and slide
        decision its compose was built on; either omitted is worked out
        here.

        Returns *snapshot* unchanged when it is neither visible nor held:
        compose() already treats an invisible overlay as a strict no-op
        regardless of its other fields, so there is nothing worth merging in
        that case.
        """
        if now is None:
            now = time.monotonic()
        if animating is None:
            animating = self._reveal_animating(now)
        held = self._held_overlay_locked(now)
        # The reveal slide's own frames: the chrome is still on its way off
        # the panel, so the overlay is merged (the compositor slides it)
        # even though the snapshot or the hide window says hidden. Same
        # guards as held, so a cleared now-playing or a sleeping panel
        # mid-slide draws nothing.
        revealing = (
            self._now_playing is not None
            and self._showing != "noop"
            and not self._display_sleeping
            and animating
        )
        # An artwork tap's hide window wins over a touch-published visible
        # snapshot: the user asked for the artwork, whichever mode the
        # controls are in. The touch side is told the same (see dial_main's
        # ARTWORK dispatch) so its session matches.
        if self._controls_hidden(now) and not revealing:
            return _HIDDEN_OVERLAY
        if not (snapshot.visible or held or revealing):
            return snapshot
        now_playing = self._now_playing
        artist = now_playing.artist if now_playing is not None else ""
        if now_playing is not None and self._layout_metrics().content_tier in (CONTENT_RICH, CONTENT_LARGE):
            # Rich/large only: base keeps its artist row exactly as before,
            # byte for byte, and compact never draws one at all. An idle or
            # pending focus (nothing actually playing) reads as idle; a
            # playing appliance with no identified title yet reads as
            # playing rather than blank. Idle wins over the no-title check;
            # a playing appliance with a real title keeps its artist
            # whatever the artwork state.
            if not now_playing.playing:
                artist = IDLE_ARTIST_TEXT
            elif not now_playing.title:
                artist = PLAYING_ARTIST_TEXT
        title = now_playing.title if now_playing is not None else ""
        album = now_playing.album if now_playing is not None else ""
        name = appliance_display_name(now_playing.service_name) if now_playing is not None else ""
        volume = shown_volume(now_playing.service_name) if now_playing is not None else None
        muted = shown_muted(now_playing.service_name) if now_playing is not None else False
        pressed = self._pressed[0] if self._pressed is not None else None
        # Belt and braces: dots are meaningful only on the main screen —
        # _repaint_current_locked never reaches this merge for the repeat/
        # selector/picker screens anyway (they bypass _display_locked
        # entirely), but the explicit screen check here means a stray call
        # can never show them somewhere they should not appear.
        dots = self._dots_active and self._screen == "main"
        return dataclasses.replace(
            snapshot, visible=True, artist=artist, title=title, album=album, volume=volume, muted=muted,
            name=name, dots=dots, pressed=pressed, eq_pages=self._eq_available,
        )

    def _redisplay_current_locked(self) -> None:
        """Re-display the current frame synchronously — used when rotate
        changes while already fitted and open, so the new orientation is
        visible immediately rather than at the next poll.
        """
        if not (self._backend_open and self._backend is not None):
            return
        if self._current_rendered_image is not None:
            self._display_locked(self._current_rendered_image)
        else:
            self._render_logo_locked()

    # ---- logo fallback -------------------------------------------------

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
            # Wait no longer than the next moment something on screen must
            # change on its own (the replaying counter's next second, a
            # controls-hide window ending, the next frame of the artwork-tap
            # reveal), see _next_repaint_deadline().
            # Never longer than a second either way, so stop() and the
            # once-a-second housekeeping below are still noticed promptly
            # when nothing is scheduled.
            deadline = self._next_repaint_deadline()
            now = time.monotonic()
            timeout = 1.0 if deadline is None else max(0.0, min(1.0, deadline - now))
            signaled = self._overlay_signal.wait(timeout=timeout)
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
                self._tick_outputs_refresh()
                self._tick_controls_hidden()
                self._tick_controls_shown()
                self._tick_wifi_flash()
                self._tick_update_watch()
                self._tick_warnings()
                self._tick_controls_reveal()
                self._tick_replay_timer()
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
        """True whenever the idle screen's own compose path (compose_idle:
        the info badge, no volume/mute controls overlay) should be used in
        place of the ordinary overlay compose path — whenever nothing is
        playing, not only while the "tap to replay" affordance is due. The
        idle screen is one screen regardless of whether a replay is held,
        so the "i" affordance is reachable on every idle dial; which base
        image it shows (the replay-available logo or the plain one) is
        still decided by the affordance alone (see _display_idle_locked).
        This is the one behaviour change the info page's own idle-screen
        reach requires: a plain logo with nothing held used to fall through
        to the ordinary reveal-on-touch overlay path (a controls overlay
        over a logo that controlled nothing) — see touch_surface(), whose
        "idle" surface now follows the same rule."""
        return self._screen == "main" and self._now_playing is None

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
        tap): pop back from whichever list-chassis screen is open — to its
        policy row's back_to, or for the outputs list to the main page it
        was opened from (see _back_target())."""
        self._request_back(self._screen)

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
                return "selector"
        return _policy(screen).back_to

    def _request_back(self, screen: str) -> None:
        """Lock-free request to leave *screen* for _back_target(screen).
        Going back to the EQ page also asks the EQ worker for a fresh
        reading, as cycle_pages() does on the way in."""
        target = self._back_target(screen)
        if target == "eq":
            entry = self._eq_target_lockfree()
            if entry is not None:
                _enqueue_eq_fetch(_EqTarget(entry.appliance_id, entry.ip, entry.port))
        self._screen_request = target
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
        appliance — playing or idle; picking an idle row controls it the
        same way as picking a playing one. A stale index — the row
        disappeared between paint and tap, e.g. the appliance left the
        network — is silently treated as "back": no focus change, no error
        dialog. Either way the selector closes.
        """
        selector = self._selector
        if selector is not None and selector.rows:
            page_rows = self._current_page_rows(selector)
            if 0 <= index < len(page_rows):
                row = page_rows[index]
                if not row.authorized:
                    # An appliance that refused this dial cannot be
                    # controlled: no focus change, and the selector stays
                    # open underneath a short hint whose back returns here.
                    self._info_value_hint = _unauthorised_hint(row.label)
                    self._screen_request = "info_value"
                    self._overlay_signal.set()
                    return
                self.set_manual_focus(row.appliance_id)
        self.close_list()

    def list_row_tap(self, index: int) -> None:
        """Touch-thread entry (dial_main's on_zone_tap, for a LIST_ROW
        tap): routes to whichever list-chassis screen is actually open —
        the appliance selector (selector_pick), the replay picker
        (picker_pick), the outputs list (outputs_row_tap) or, on the
        compact tier only, the info page (info_row_tap). Off compact the
        info page's rows are dead at the geometry level (GEOMETRY_INFO
        carries no LIST_ROW entries there at all), so this stays a no-op —
        belt-and-braces only."""
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
        """Touch-thread entry (a LIST_ROW tap on the compact info list):
        remember the tapped field's absolute position in InfoState.rows and
        request the value view — the outputs_row_tap() shape. A stale
        index (the row count changed between paint and tap) is ignored and
        the list stays open, rather than falling back to "close" the way
        selector_pick()/picker_pick()/outputs_row_tap() do: closing here
        would pop past the list itself, since the info page has nothing to
        fall back to but main. Plain reads and writes, no lock, no I/O."""
        state = self._info
        if state is None or not state.rows:
            return
        page_rows = self._current_page_rows(state)
        if 0 <= index < len(page_rows):
            self._info_value_index = state.page * self._rows_per_page() + index
            self._screen_request = "info_value"
            self._overlay_signal.set()

    def _rows_per_page(self) -> int:
        """Rows per list page for the active screen — the same density-aware
        count the repaint thread paints with (_layout_metrics()), so the
        touch-thread page slice and the painted page can never disagree
        about which rows are on screen. Safe with or without self._lock."""
        return self._layout_metrics().rows_per_page

    def _current_page_rows(self, state) -> tuple:
        """The current page's slice of *state*.rows, for either a
        SelectorState or a PickerState (both carry rows and page). Shared by
        the touch-thread pick entries (lock-free) and the repaint-thread list
        builders so the two can never disagree about which rows are on
        screen; rows_per_page comes from dial_touch_layout, the same source
        the hit-test reads. Takes no lock and writes nothing."""
        _, page_rows = _page_slice(state.rows, state.page, self._rows_per_page())
        return page_rows

    def _repeat_page_available(self) -> bool:
        """Whether the repeat page has anything to show right now: a
        controllable appliance (self._now_playing is not None) whose
        focused/reporting id has a fresh, available repeat-store record.
        Reads self._now_playing, self._manual_focus_id and
        self._reporting_appliance_id (all plain reference reads, same
        discipline as set_manual_focus()) and the repeat store's own leaf
        lock — an appliance this dial cannot see repeat state for has
        nothing to show on the repeat page."""
        if self._now_playing is None:
            return False
        appliance_id = self._manual_focus_id or self._reporting_appliance_id
        if not appliance_id:
            return False
        rec = repeat_store.get(appliance_id, time.monotonic())
        return rec is not None and rec.available

    def cycle_pages(self) -> None:
        """Touch-thread entry (dial_main's on_zone_tap, for a DOTS tap):
        advance to the next available page — main -> repeat -> eq -> main,
        wrapping, and skipping a page with nothing to show (no held repeat
        record, or no EQ-capable focused/reporting appliance) so a dot
        never comes to mean two different pages. Reaching "eq" also enqueues
        a fresh fetch on the EQ worker, so its bars are at most one round
        trip away (open_outputs()'s own discipline); no poll/reconcile is
        forced for repeat (unlike open_selector()/open_picker(), its content
        is entirely driven by whatever the repeat store already holds).

        A TRUE no-op (self._screen_request left untouched) when starting
        from "main" (or a screen outside the three-page set entirely, e.g.
        the selector) and nothing is available to open — the original
        two-way toggle_repeat_screen()'s own exact behaviour, preserved so
        an appliance with neither capability keeps its byte-identical
        trace. Leaving "repeat" or "eq" for "main" (nothing further around
        the wrap), by contrast, always fires — there is a real secondary
        screen to close — and arms self._repeat_close_reveal exactly when
        the screen just left carries close_reveals_overlay (both do): the
        one-shot flag TouchEventSource._poll_surface() consumes to bring
        the main screen back showing its volume overlay rather than bare
        artwork (see the flag's own comment in __init__ and
        dial_touch.TouchStateMachine.force_overlay_visible()).
        """
        current = self._screen if self._screen in _PAGE_ORDER else "main"
        leaving_page = current != "main"
        i = _PAGE_ORDER.index(current)
        for step in range(1, len(_PAGE_ORDER) + 1):
            candidate = _PAGE_ORDER[(i + step) % len(_PAGE_ORDER)]
            if candidate == "repeat" and self._repeat_page_available():
                self._screen_request = "repeat"
                self._overlay_signal.set()
                return
            if candidate == "eq" and self._eq_available:
                target = self._eq_target_lockfree()
                if target is not None:
                    _enqueue_eq_fetch(_EqTarget(target.appliance_id, target.ip, target.port))
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

    def toggle_repeat_screen(self) -> None:
        """Alias kept for existing direct callers/tests — see
        cycle_pages(), which replaced this method's own open/close logic
        with the three-page cycle."""
        self.cycle_pages()

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
        elif rec.state == "replaying":
            # In the replaying layout this row is the position line over
            # the artwork, not a toggle: a tap on it is an artwork tap.
            self.hide_controls()

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
            # Recorded so on_repeat_result (the worker thread) can tell this
            # Stop's own ok ack apart from an unrelated Seek's — the repeat
            # worker reports both under the same "transport" kind, so kind
            # alone cannot distinguish them. See on_repeat_result().
            self._pending_repeat_stop_id = screen.appliance_id
            enqueue_transport(_RepeatTarget(screen.appliance_id, screen.ip, screen.port), "stop", 0.0)

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
        tap). Refuses (plain bool read, no lock) when no replay is actually
        held — the "i" affordance is reachable on every idle dial now (see
        _idle_chassis_due_locked), but a replay tap on a plain logo stays
        inert exactly as it was before that unification. Otherwise also
        forces an immediate reconcile/poll, the same as open_selector(), so
        a row that just went stale is refreshed within about one poll
        interval of opening."""
        if not self._idle_affordance:
            return
        self._screen_request = "picker"
        self._reconcile_due = True
        auth_map.force_due()
        self._poll_wake.set()
        self._overlay_signal.set()

    def open_info(self) -> None:
        """Touch-thread entry (dial_main's on_zone_tap, for the idle
        screen's IDLE_INFO tap). Requests the info page and starts one
        bounded gather on its own daemon thread; the page paints at once
        with placeholder "-" values (see _open_info_locked) and fills in
        within about a second once the gather lands (see _gather_info()).
        Touches no lock and does no I/O itself: two plain writes, a signal
        and a thread start."""
        self._info_gather_seq += 1
        seq = self._info_gather_seq
        self._screen_request = "info"
        self._overlay_signal.set()
        threading.Thread(target=self._gather_info, args=(seq,), daemon=True, name="dial-info").start()

    def _gather_info(self, seq: int) -> None:
        """Worker thread (one per open_info() call, never the touch
        thread): call the injected provider and fold the result in under
        self._lock in one assignment — the on_outputs_result fold-in
        discipline, no I/O while the lock is held. Never raises: a missing
        or failing provider yields the placeholder rows instead. Drops a
        stale result — the page closed and reopened (seq no longer
        matches) or closed outright (self._info is None)."""
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

    def set_info_provider(self, fn) -> None:
        """Startup wiring (dial_main.py, after the HTTP server exists): a
        zero-arg callable returning an iterable of (label, value) pairs —
        dial_info.gather_dial_info, bound to this dial's own name/version.
        Plain attribute write."""
        self._get_info_rows = fn

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
            page_rows = self._current_page_rows(picker)
            if 0 <= index < len(page_rows):
                row = page_rows[index]
                self.set_manual_focus_pending(row.appliance_id, row.service_name)
                self._arm_replay_timer(row.appliance_id)
                enqueue_transport(_RepeatTarget(row.appliance_id, row.ip, row.port), "seek", 0.0)
        self.close_list()

    def _arm_replay_timer(self, appliance_id: "str | None") -> None:
        """Touch-thread (arm) or any thread (clear, with None): start or
        drop the main page's replay position line — see compose()'s
        timer_text and _replay_timer_locked(). Lock-free plain writes; the
        id is written last so a reader never pairs a new id with stale
        times."""
        self._replay_timer_armed_at = time.monotonic()
        self._replay_timer_shown_at = 0.0
        self._replay_timer_frame_at = 0.0
        self._replay_timer_id = appliance_id

    def _outputs_target_lockfree(self):
        """The roster entry the outputs screens act on: the focused/
        reporting appliance when it advertises dial_outputs and is not
        confirmed unauthorized; else None. Plain reads, like
        focus_volume_target()."""
        appliance_id = self._manual_focus_id or self._reporting_appliance_id
        if not appliance_id:
            return None
        for r in self._last_roster:
            if r.appliance_id == appliance_id:
                return r if (r.dial_outputs and r.auth != AUTH_UNAUTHORIZED) else None
        return None

    def _eq_target_lockfree(self):
        """The roster entry the EQ page acts on: the focused/reporting
        appliance when it advertises dial_eq and is not confirmed
        unauthorized; else None. The compact-tier veto lives in
        self._eq_available (computed once per poll tick), not here — this
        mirrors _outputs_target_lockfree() exactly, tier-agnostic like every
        other *_target_lockfree() helper."""
        appliance_id = self._manual_focus_id or self._reporting_appliance_id
        if not appliance_id:
            return None
        for r in self._last_roster:
            if r.appliance_id == appliance_id:
                return r if (r.dial_eq and r.auth != AUTH_UNAUTHORIZED) else None
        return None

    def open_outputs(self) -> None:
        """Touch-thread entry (dial_main's on_zone_tap, for an OUTPUTS
        tap): request the outputs list and ask the worker for a fresh one
        straight away, so the first frame after opening is at most one
        round trip away. Lock-free, like open_selector(); refuses (no
        request at all) when there is no focused/reporting appliance
        advertising the capability."""
        entry = self._outputs_target_lockfree()
        if entry is None:
            return
        enqueue_fetch(_OutputsTarget(entry.appliance_id, entry.ip, entry.port))
        self._screen_request = "outputs"
        self._overlay_signal.set()

    def outputs_row_tap(self, index: int) -> None:
        """Touch-thread entry (a LIST_ROW tap while the outputs list is
        open): remember the tapped row's output id and request the detail
        page. A stale index (the row vanished between paint and tap) is
        treated as back, same as selector_pick()/picker_pick()."""
        state = self._outputs
        if state is not None and state.rows:
            page_rows = self._current_page_rows(state)
            if 0 <= index < len(page_rows):
                self._output_open_id = page_rows[index].id
                self._screen_request = "output"
                self._overlay_signal.set()
                return
        self.close_list()

    def _detail_row_lockfree(self) -> "OutputRow | None":
        """The output the detail page is open for, read from the last
        fetched outputs snapshot (not the optimistic override — see
        output_toggle_tap()/output_volume_tap()). Plain reads, same
        discipline as _outputs_target_lockfree()."""
        detail, state = self._output_detail, self._outputs
        if detail is None or state is None:
            return None
        return next((r for r in state.rows if r.id == detail.output_id), None)

    def _shown_output_level(self, row: "OutputRow") -> "int | None":
        """The volume *row* should currently show to a touch-thread caller
        stepping it further: the pending optimistic override's volume when
        it names this row and says selected; else row.volume when
        row.selected; else None (disabled — no level to step). Plain reads;
        safe lock-free (this is a touch-thread helper) or under self._lock
        (the paint-time callers reach the same value their own way — see
        _build_outputs_list_state_locked/_build_output_view_locked)."""
        override = self._outputs_optimistic
        if override is not None and override[0] == row.id and override[1]:
            return override[2]
        return row.volume if row.selected else None

    def output_toggle_tap(self) -> None:
        """Touch-thread entry (OUTPUT_TOGGLE): enable this output at the
        appliance's own configured default volume (the dial sends no
        volume; see send_dial_outputs_set_post_json), or disable it,
        through the outputs worker. Shows the change at once via an
        optimistic override, reconciled by the worker's own fetch-after-
        set the moment the appliance's real answer lands."""
        row = self._detail_row_lockfree()
        state = self._outputs
        if row is None or state is None:
            return
        selected = not row.selected
        self._outputs_optimistic = (row.id, selected, row.volume, time.monotonic())
        enqueue_set(
            _OutputsTarget(state.appliance_id, state.ip, state.port), row.id,
            selected=selected, volume=None,
        )
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
        shown = self._shown_output_level(row)
        if shown is None:
            return
        new = max(0, min(100, shown + delta))
        self._outputs_optimistic = (row.id, True, new, time.monotonic())
        enqueue_set(
            _OutputsTarget(state.appliance_id, state.ip, state.port), row.id,
            selected=True, volume=new,
        )
        self._overlay_signal.set()

    def _close_secondary_locked(self) -> None:
        """Pop to the main screen from any secondary screen — the
        appliance list, the repeat screen, the replay picker, the outputs
        list or the per-output detail page. Caller holds self._lock.
        Called from the repeat thread's own request-folding, from
        sleep/disable/swap (so a later wake/reopen never resumes on a
        stale secondary screen), from the poll thread when the focused
        appliance changes while a bound screen is open, and is what a
        stale selector_pick()/picker_pick()/outputs_row_tap() index falls
        back to.

        Every screen's own state_attr is cleared here, from the policy
        table itself, so a screen added to the table is popped by this
        loop without a further edit — see ScreenPolicy.state_attr."""
        self._screen = "main"
        for policy in SCREEN_POLICIES.values():
            if policy.state_attr is not None:
                setattr(self, policy.state_attr, None)
        self._output_open_id = None
        self._pressed = None
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

    def _open_main_locked(self) -> bool:
        """The "main" row's opener: pop to main. Extracted verbatim from
        the old request-folding branch so the table's `open` field can
        name it directly."""
        self._close_secondary_locked()
        return True

    def _open_selector_locked(self) -> bool:
        """The selector row's opener: open, or re-open, at page 0 with a
        restarted inactivity clock, carrying over whatever rows were last
        built. Deliberately does not clear another screen's own state on a
        direct switch (e.g. from repeat) — _close_secondary_locked is the
        one place that does. A return from the unauthorised-row hint keeps
        the page the row was tapped on."""
        rows = self._selector.rows if self._selector is not None else ()
        page = self._selector.page if (self._screen == "info_value" and self._selector is not None) else 0
        self._selector = SelectorState(rows=rows, page=page, opened_at=time.monotonic())
        self._screen = "selector"
        return True

    def _open_picker_locked(self) -> bool:
        """The picker row's opener — the replay picker's counterpart to
        _open_selector_locked."""
        rows = self._picker.rows if self._picker is not None else ()
        self._picker = PickerState(rows=rows, page=0, opened_at=time.monotonic())
        self._screen = "picker"
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
            rows=rows, page=page, opened_at=time.monotonic(), gather_seq=self._info_gather_seq,
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
        row) opens the view over the selector instead, only while the
        selector is showing; the selector's state is left untouched."""
        hint, self._info_value_hint = self._info_value_hint, None
        if hint is not None:
            if self._screen != "selector":
                return False
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
        """The repeat row's opener: build the screen, or refuse (leaving
        the current screen in place) when there is nothing to build it for
        — see _build_repeat_screen_locked."""
        screen = self._build_repeat_screen_locked()
        if screen is None:
            return False
        # A fresh open re-anchors the counter: the first replaying frame
        # paints whatever second is current, never held against a value
        # painted before the screen was last closed.
        self._repeat_painted_second = None
        self._repeat_screen = screen
        self._screen = "repeat"
        return True

    def _open_eq_locked(self) -> bool:
        """The EQ row's opener: refuse when there is no focused/reporting
        appliance advertising the capability, or the current tier has no EQ
        page (see self._eq_available); otherwise open, keeping the last
        fetched bass/treble when re-opening for the SAME appliance (so a
        quick cycle away and back does not blank the bars), resetting them
        for a different one."""
        if not self._eq_available:
            return False
        entry = self._eq_target_lockfree()
        if entry is None:
            return False
        prev = self._eq
        keep = prev is not None and prev.appliance_id == entry.appliance_id
        self._eq = EqScreenState(
            appliance_id=entry.appliance_id, service_name=entry.service_name,
            ip=entry.ip, port=entry.port, opened_at=time.monotonic(),
            bass_db=prev.bass_db if keep else None,
            treble_db=prev.treble_db if keep else None,
            loaded=keep and prev.loaded,
        )
        self._screen = "eq"
        return True

    def _open_outputs_locked(self) -> bool:
        """The outputs row's opener: refuse when there is no focused/
        reporting appliance advertising the capability (see
        _outputs_target_lockfree()); otherwise open, keeping the last
        fetched rows when re-opening for the SAME appliance (so a quick
        close/reopen does not flash back to "Loading"), resetting them for
        a different one."""
        entry = self._outputs_target_lockfree()
        if entry is None:
            return False
        if self._screen in _PAGE_ORDER:
            # Opened from one of the three main pages: close back to it.
            # (Coming back up from the per-output detail page keeps the
            # page the list was first opened from.)
            self._outputs_return = self._screen
        elif self._screen != "output":
            self._outputs_return = "main"
        prev = self._outputs
        keep = prev is not None and prev.appliance_id == entry.appliance_id
        self._outputs = OutputsState(
            appliance_id=entry.appliance_id, service_name=entry.service_name,
            ip=entry.ip, port=entry.port,
            rows=prev.rows if keep else (), page=0, opened_at=time.monotonic(),
            loaded=keep and prev.loaded,
        )
        self._screen = "outputs"
        return True

    def _open_output_locked(self) -> bool:
        """The per-output detail row's opener: refuse when the outputs
        list is not open or the touch-chosen row id (self._output_open_id,
        set by outputs_row_tap()) is no longer in its rows — either way the
        current screen (the outputs list) stays showing."""
        state, output_id = self._outputs, self._output_open_id
        self._output_open_id = None
        if state is None or output_id is None or not any(r.id == output_id for r in state.rows):
            return False
        self._output_detail = OutputDetailState(
            appliance_id=state.appliance_id, output_id=output_id, opened_at=time.monotonic(),
        )
        self._screen = "output"
        return True

    def _open_warning_locked(self, warning_id: str) -> bool:
        """Every warning row's opener (bound per row with functools.partial
        in the policy table): refuse while the dial is restarting (that
        screen must stay until the reboot lands or times out) and while a
        higher-priority warning is already up; otherwise open with a fresh
        clock. A page that is already showing this warning is reopened in
        place (same screen, fresh clock). An interrupting warning first
        pops whatever secondary screen is up and wakes a sleeping panel."""
        if self._screen == "restarting":
            return False
        desc = _WARNING_BY_ID[warning_id]
        showing = self._warning_screen
        if (
            showing is not None and showing.warning_id != warning_id
            and _WARNING_BY_ID[showing.warning_id].priority > desc.priority
            and self._warnings.is_active(showing.warning_id)
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

    def _open_restarting_locked(self) -> bool:
        """The restarting row's opener: always opens, and drops the No-WiFi
        page's own state on the way (this is the one screen reached
        directly from it, and it never returns there — the poller re-raises
        the page if the box is still up and still offline)."""
        self._warning_screen = None
        self._restarting = RestartingState(opened_at=time.monotonic())
        self._screen = "restarting"
        return True

    def _apply_screen_requests_locked(self) -> None:
        """Fold pending open_selector()/close_list()/list_page()/
        toggle_repeat_screen()/open_picker() touch-thread requests into
        self._screen and the per-screen state, via the screen policy
        table: the requested row's own `open` method decides whether the
        switch happens at all (it can refuse and leave the current screen
        showing); a switch that does happen clears the pressed channel; a
        pending page delta applies to whichever row is showing, when that
        row is paged. Caller holds self._lock; runs on the repeat thread
        only.
        """
        previous_screen = self._screen
        request = self._screen_request
        self._screen_request = None
        delta = self._page_request
        self._page_request = 0

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
            # (main after DOTS, or after a stop — see on_repeat_result())
            # shows its own controls for a fresh window on the compact
            # tier; a no-op off it.
            self._show_compact_controls()
            # A hide window and any reveal slide belong to the screen they
            # started on; a screen change abandons both rather than
            # resuming them later.
            self._controls_hidden_until = 0.0
            self._reveal_started_at = 0.0
            self._controls_last = None

        policy = _policy(self._screen)
        if delta and policy.paged:
            active = getattr(self, policy.state_attr)
            if active is not None:
                rows_per_page = self._rows_per_page()
                page_fn = _wrap_page if self._compact_tier() else _clamp_page
                new_page = page_fn(active.page + delta, len(active.rows), rows_per_page)
                if new_page != active.page:
                    setattr(self, policy.state_attr, dataclasses.replace(active, page=new_page))

    def _check_secondary_timeout(self) -> None:
        """Close the screen showing after its own inactivity timeout —
        called from the repaint thread's own 1s timeout branch, so this
        runs even when nothing else signals a repaint. A screen with no
        timeout of its own (main, repeat) is simply never closed from here
        — see ScreenPolicy.inactivity_timeout_s.

        self._screen/self._selector/self._picker are read lock-free here:
        all three are also written by the poll thread (_poll_once's
        empty-target branch, _sleep_locked), not only the repeat thread,
        but every write is already under self._lock and each is a plain
        reference/str assignment — the same "a stale read costs at most
        one harmless extra tick" discipline _sleeping_lockfree() documents.
        The actual close below is re-checked and applied under the lock
        regardless.
        """
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

    def _repeat_counter_second(self, value: float) -> int:
        """The integer second the replaying counter should read for the
        unfloored counter value *value* (see _repeat_counter_value()),
        given the second last painted. Normally floor(value), clamped at
        zero. When a status re-sync has moved the interpolated clock back
        below the painted second by less than REPEAT_COUNTER_HOLD_S, the
        painted second is held instead, so the line never steps back or
        repeats for a re-sync; a larger step back is a real change (a
        restart, the loop wrap, a stalled source) and floor(value) is
        returned so it shows at once. A hold is self-limiting: the clock
        gains on the held value at one second per second, so it lasts
        under REPEAT_COUNTER_HOLD_S. Pure: never writes the painted
        second, which only _display_repeat_locked() commits. Repaint
        thread only (reads that thread's own attribute).
        """
        current = max(0, math.floor(value))
        painted = self._repeat_painted_second
        if painted is None or current >= painted:
            return current
        if painted - value < REPEAT_COUNTER_HOLD_S:
            return painted
        return current

    def _tick_repeat_line(self) -> None:
        """Recompose the repeat screen whenever the replaying counter's
        current second is not the one last painted, so the line counts up
        between polls without skipping or repeating a value. Called from
        the repeat thread's own timeout branch (see _repaint_run), which
        sizes its wait to land just after the next second boundary; but
        due-ness is decided against the painted second, never against
        where within the second this wake landed, so a late wake, a status
        re-sync that moved the interpolated clock, or a signal repaint that
        straddled the boundary all still paint the second actually owed.
        A housekeeping wake that lands with the painted second still
        current (the wait capped at a second when something else is
        scheduled sooner, or the plain fallback timeout) is not due and
        must not force an off-boundary repaint. No HTTP call: the
        interpolation is purely local (see _interpolate_repeat_position())
        and the next poll always corrects any drift. A no-op while asleep
        or when the repeat screen is not the one on screen.
        """
        if self._screen != "repeat":
            return
        screen = self._repeat_screen
        if screen is None:
            return
        now = time.monotonic()
        due = self._repeat_counter_due(repeat_store.get(screen.appliance_id, now), now)
        if due is not None and due <= now:
            self._overlay_signal.set()

    def _repeat_counter_due(self, rec, now: float) -> "float | None":
        """When the running replay counter for repeat-store record *rec*
        next needs a paint: *now* when one is already owed (nothing painted
        yet, or the second moved under a signal repaint or a re-sync), else
        the moment the counter first passes the painted second, plus the
        small scheduling pad the other deadlines use. While a re-sync hold
        is on (value below painted) that is over a second out; the repaint
        loop's own one-second cap trims it and the tick then simply finds
        itself not due and reschedules. None when *rec* is not replaying.
        Shared by every line that shows the counter: the repeat screen and
        the main page's replay timer (see _replay_timer_deadline())."""
        if rec is None or rec.state != "replaying":
            return None
        value = _repeat_counter_value(rec, now)
        painted = self._repeat_painted_second
        if self._repeat_counter_second(value) != painted:
            return now
        return now + (painted + 1.0 - value) + 0.005

    def _replay_timer_deadline(self, now: float) -> "float | None":
        """When the main page's replay timer line next needs a paint (see
        _replay_timer_locked()), or None when there is no timer on screen.
        While armed but not yet shown, a quarter-second check for its first
        position; while shown, the counter's next second (or at once, when
        a paint is owed), then the fade's frames, then one last paint to
        clear it. A timer that has run out, or whose replay has ended, is
        dropped here as well as in _replay_timer_locked(), so it ends even
        while the main page is not painting through _display_locked() (the
        idle screen, say). No deadline is ever sooner than
        REPLAY_TIMER_FADE_GAP_S after the last one this timer signalled,
        so a paint that does not advance it can never make the loop spin.
        Plain reads and lock-free plain writes, the same discipline as
        _arm_replay_timer(); reads repeat_store's own leaf lock."""
        appliance_id = self._replay_timer_id
        if appliance_id is None or self._screen != "main" or self._display_sleeping:
            return None
        shown = self._replay_timer_shown_at
        if not shown:
            if now - self._replay_timer_armed_at >= REPLAY_TIMER_ARM_S:
                self._replay_timer_id = None
                return None
            return now + 0.25
        elapsed = now - shown
        rec = repeat_store.get(appliance_id, now)
        if elapsed >= REPLAY_TIMER_SHOW_S + REPLAY_TIMER_FADE_S or self._repeat_position_line(rec, now) is None:
            # One last paint, without the line.
            self._replay_timer_id = None
            due = now
        elif elapsed >= REPLAY_TIMER_SHOW_S:
            due = max(now, self._replay_timer_frame_at + REPLAY_TIMER_FADE_GAP_S)
        else:
            due = shown + REPLAY_TIMER_SHOW_S + 0.005
            counter_due = self._repeat_counter_due(rec, now)
            if counter_due is not None:
                due = min(due, counter_due)
        return max(due, self._replay_timer_signal_at + REPLAY_TIMER_FADE_GAP_S)

    def _tick_replay_timer(self) -> None:
        """Repaint thread's own 1s-timeout branch: signal a repaint when the
        main page's replay timer line is due one (see
        _replay_timer_deadline())."""
        now = time.monotonic()
        deadline = self._replay_timer_deadline(now)
        if deadline is not None and deadline <= now:
            self._replay_timer_signal_at = now
            self._overlay_signal.set()

    def _next_repaint_deadline(self) -> "float | None":
        """The earliest monotonic time something on screen must change on
        its own: the replaying counter's next second (now, when a paint is
        already owed, see _tick_repeat_line()), the end
        of a controls-hide window (see hide_controls()), the next frame of
        an artwork-tap reveal (see _reveal_animating()), or the offline
        flash's next half-period boundary. None when nothing
        is scheduled — the caller then falls back to its own housekeeping
        cadence. Lock-free plain reads, the same discipline
        _check_secondary_timeout() uses; reads repeat_store's own leaf lock
        with no manager lock held, as _tick_repeat_line() does.
        """
        deadlines = []
        if self._screen == "repeat" and self._repeat_screen is not None:
            now = time.monotonic()
            due = self._repeat_counter_due(repeat_store.get(self._repeat_screen.appliance_id, now), now)
            if due is not None:
                deadlines.append(due)
        if self._controls_hidden_until > time.monotonic():
            deadlines.append(self._controls_hidden_until + 0.005)
        now = time.monotonic()
        started = self._reveal_started_at
        if started:
            # A slide not yet settled: the next reveal frame a short gap
            # after the last one was sent, or at once if that moment has
            # passed, and never later than the end of the slide, so the
            # settled frame paints on time. Only the end carries the usual
            # small margin, so the settled frame's compose is sure to land
            # past it; a mid-slide frame is due exactly when its gap is
            # over, or the margin would add to every gap. Keyed on the start
            # rather than on the slide still running: the last slide frame
            # routinely finishes sending after the end, and the settled
            # frame is then due at once, not at the next unrelated wake.
            next_frame = max(now, self._reveal_frame_at + REVEAL_FRAME_GAP_S)
            end = started + REVEAL_ANIMATION_S
            deadlines.append(next_frame if next_frame < end else max(now, end + 0.005))
        if self._controls_shown_until > time.monotonic() and self._compact_tier():
            deadlines.append(self._controls_shown_until + 0.005)
        if self._wifi_flashing():
            now = time.monotonic()
            half = WIFI_FLASH_HALF_PERIOD_S
            deadlines.append((math.floor(now / half) + 1) * half + 0.005)
        timer_due = self._replay_timer_deadline(time.monotonic())
        if timer_due is not None:
            deadlines.append(timer_due)
        return min(deadlines) if deadlines else None

    def _tick_outputs_refresh(self) -> None:
        """Enqueue a fresh outputs-list fetch every OUTPUTS_REFRESH_S while
        an outputs screen is showing — called from the repeat thread's own
        1s timeout branch, the same cadence _tick_repeat_line() uses for the
        repeat screen's live position. self._screen/self._outputs are read
        lock-free here: one stale tick is harmless, the same argument
        _check_secondary_timeout() makes."""
        if self._screen not in ("outputs", "output"):
            return
        state = self._outputs
        if state is None:
            return
        now = time.monotonic()
        if now - self._outputs_refresh_at < OUTPUTS_REFRESH_S:
            return
        self._outputs_refresh_at = now
        enqueue_fetch(_OutputsTarget(state.appliance_id, state.ip, state.port))

    def _tick_controls_hidden(self) -> None:
        """Wake the repaint loop exactly when an artwork-tap hide window
        (see hide_controls()) has just ended, so the bands reappear on
        their own without waiting for an unrelated touch or poll — called
        from the repeat thread's own timeout branch, the same cadence
        _tick_repeat_line() uses. One-shot: resets the deadline to 0.0 (its
        "not hidden" value) once fired, so this does not keep re-signalling
        every housekeeping tick after expiry."""
        deadline = self._controls_hidden_until
        if deadline and time.monotonic() >= deadline:
            self._controls_hidden_until = 0.0
            # The slide is the painters' to start and end; the repaint this
            # wakes finds the controls back and slides them in.
            self._overlay_signal.set()

    def _tick_controls_reveal(self) -> None:
        """Wake the repaint loop for the next frame of a reveal slide while
        one is running, and once more the moment it has ended (its duration
        ran out) so the settled frame is painted at once rather than on the
        next unrelated signal.
        Called from the repaint thread's own timeout branch, whose wait
        _next_repaint_deadline() has already sized onto the next frame.
        One-shot at the end: resets the start to 0.0 so this does not keep
        signalling every housekeeping tick afterwards. The reset is a
        compare-and-clear under self._lock, which the repaint thread does not
        hold at this point (the loop takes it only around the repaint), so a
        slide the poll thread stamped since the start was read is left
        alone."""
        started = self._reveal_started_at
        if not started:
            return
        now = time.monotonic()
        if now >= started + REVEAL_ANIMATION_S:
            with self._lock:
                if self._reveal_started_at == started:
                    self._reveal_started_at = 0.0
        self._overlay_signal.set()

    def _tick_controls_shown(self) -> None:
        """Wake the repaint loop exactly when a compact screen's own
        controls window (see _show_compact_controls()) has just lapsed, so
        the bands step aside on their own without waiting for an unrelated
        touch or poll — called from the repeat thread's own timeout branch,
        the same cadence _tick_controls_hidden() uses. One-shot: resets the
        deadline to 0.0 once fired, the same "already in the past" value
        _compact_controls_hidden() reads as hidden, so this does not keep
        re-signalling every housekeeping tick after expiry. A no-op off the
        compact tier."""
        deadline = self._controls_shown_until
        if deadline and time.monotonic() >= deadline and self._compact_tier():
            self._controls_shown_until = 0.0
            self._overlay_signal.set()

    def _carried_paging_locked(self, prev, row_count: int) -> tuple[int, float]:
        """(page, opened_at) to keep across a row rebuild: the previous page
        clamped to the new row count, and the previous opened_at, or (0, 0.0)
        when there was no previous state. Caller holds self._lock."""
        if prev is None:
            return 0, 0.0
        return _clamp_page(prev.page, row_count, self._rows_per_page()), prev.opened_at

    def _refresh_selector_rows(self, roster: list, reporting_id: str | None) -> None:
        """Rebuild the selector's row list from the merged *roster* (idle
        and playing appliances alike). Runs on the poll thread at the end of
        every _poll_once, in both the playing-targets branch and the empty-
        targets branch, whether or not the selector screen is actually open
        right now, so opening it always shows fresh rows without waiting for
        a poll. The touch thread never builds rows.

        Rows: every roster entry with a non-empty appliance_id whose auth is
        AUTHORIZED (not just "not unauthorized" — an unknown appliance is
        controllable but not yet confirmed, so it stays off the list until
        a probe confirms it) or UNAUTHORIZED (listed, marked "not
        authorised", never current or playing — see selector_pick). *current* marks the manual focus when one is
        set, else the reporting-from appliance (*reporting_id*, the playing
        reporting target or, with nothing playing, the idle focus). *playing*
        marks a row whose appliance is in the playing set, live or replay —
        drawn as the play marker (see _build_list_state_locked).

        The page is PRESERVED (clamped to the new row count) across each
        rebuild — resetting it to 0 here would make an open selector jump
        back to its first page every ~6s poll tick. It is reset to 0 only
        by a fresh open_selector() (see _apply_screen_requests_locked).
        """
        focus_id = self._manual_focus_id
        current_id = focus_id if focus_id is not None else reporting_id
        rows = tuple(
            SelectorRow(
                appliance_id=r.appliance_id,
                label=appliance_display_name(r.service_name),
                current=(r.auth == AUTH_AUTHORIZED and r.appliance_id == current_id),
                playing=(r.auth == AUTH_AUTHORIZED and r.playing),
                authorized=(r.auth == AUTH_AUTHORIZED),
            )
            for r in roster
            if r.appliance_id and r.auth in (AUTH_AUTHORIZED, AUTH_UNAUTHORIZED)
        )
        with self._lock:
            prev = self._selector
            page, opened_at = self._carried_paging_locked(prev, len(rows))
            self._selector = SelectorState(rows=rows, page=page, opened_at=opened_at)
            changed = prev is None or prev.rows != rows
        if changed and (self._screen == "selector" or self._screen_request == "selector"):
            # A rebuild that actually changed the rows must repaint even
            # with nothing else moving on screen — otherwise the selector
            # can sit on its opening placeholder until a touch elsewhere
            # forces the next frame. Signalled outside the lock, like every
            # other _overlay_signal.set() site.
            self._overlay_signal.set()

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
            page, opened_at = self._carried_paging_locked(prev, len(rows))
            self._picker = PickerState(rows=rows, page=page, opened_at=opened_at)
            changed = prev is None or prev.rows != rows
        if changed and (self._screen == "picker" or self._screen_request == "picker"):
            self._overlay_signal.set()

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

    def _build_list_state_locked(self, width: int, height: int, metrics: "LayoutMetrics | None" = None) -> ListState:
        """Build the compositor's ListState for the appliance selector's
        CURRENT page. Caller holds self._lock; runs on the repeat thread
        only. pressed comes from the unified pressed channel (self._pressed)
        — the same one every other screen feeds from."""
        return _list_state_for(
            self._selector, _rows_per_page_for(width, height, metrics=metrics), "No devices",
            _selector_list_row, pressed=self._pressed,
        )

    def _build_picker_list_state_locked(self, width: int, height: int, metrics: "LayoutMetrics | None" = None) -> ListState:
        """Build the compositor's ListState for the replay picker's CURRENT
        page — the PickerState counterpart to _build_list_state_locked().
        Each row's secondary slot carries the buffer length, formatted
        "m:ss". pressed comes from the same unified pressed channel."""
        return _list_state_for(
            self._picker, _rows_per_page_for(width, height, metrics=metrics), "Nothing to replay",
            _picker_list_row, pressed=self._pressed,
        )

    def _build_info_list_state_locked(self, width: int, height: int, metrics: "LayoutMetrics | None" = None) -> ListState:
        """Build the compositor's ListState for the info page's CURRENT
        page — seven read-only rows, ALL pages held in self._info.rows the
        same way SelectorState/PickerState hold theirs. title/
        plain_background mark this as the read-only variant: the compact
        tier's own title band reads "Info" instead of "Replay", and the
        whole frame sits on the flat chassis colour rather than a dimmed
        base image (the info page has no artwork/logo of its own to dim).

        Row shape is tier-aware: the compact tier's own rows are names
        only, (label, False) — no value, since a tap now opens the field's
        own full-screen value view (see info_row_tap()/InfoValueState) and
        the row itself only needs to name the field; every other tier keeps
        the value drawn inline, (label, False, value), unchanged."""
        if metrics is None:
            metrics = self._layout_metrics()
        compact = metrics.content_tier == CONTENT_COMPACT
        to_row = (lambda row: (row.label, False)) if compact else (lambda row: (row.label, False, row.value))
        list_state = _list_state_for(
            self._info, _rows_per_page_for(width, height, metrics=metrics), "-",
            to_row, pressed=self._pressed,
        )
        return dataclasses.replace(list_state, title=INFO_TITLE, plain_background=True)

    def _row_with_optimistic_locked(self, row: "OutputRow") -> "OutputRow":
        """*row* with the pending optimistic override folded in when it
        names this row — paint-time only, never written back to
        self._outputs. Shared by the outputs list and the per-output
        detail view, so a toggle/volume step reads the same on both the
        instant it lands."""
        override = self._outputs_optimistic
        if override is not None and override[0] == row.id:
            return dataclasses.replace(row, selected=override[1], volume=override[2])
        return row

    def _build_outputs_list_state_locked(self, width: int, height: int, metrics: "LayoutMetrics | None" = None) -> ListState:
        """Build the compositor's ListState for the outputs list's CURRENT
        page. "Loading" while the first fetch has not landed yet (see
        OutputsState.loaded), "No outputs" once it has and there is
        nothing to show. The optimistic override is applied to the row
        list before it is turned into row tuples, so the same tap that set
        it reads back immediately without waiting for the worker's
        reconciling fetch."""
        state = self._outputs
        placeholder = "Loading" if (state is None or not state.loaded) else "No outputs"
        if state is not None and state.rows:
            state = dataclasses.replace(
                state, rows=tuple(self._row_with_optimistic_locked(r) for r in state.rows),
            )
        return _list_state_for(
            state, _rows_per_page_for(width, height, metrics=metrics), placeholder,
            _output_list_row, pressed=self._pressed,
        )

    def _build_output_view_locked(self, now: float) -> "OutputViewState":
        """Build the compositor's OutputViewState for the currently open
        per-output detail page, reading the output's row fresh from
        self._outputs (through the optimistic override) at every paint —
        see OutputDetailState's own docstring. A detail whose row has
        disappeared (a race before on_outputs_result's fold requests the
        outputs list back) draws a disabled placeholder rather than
        raising; the fold is what actually navigates away."""
        detail, state = self._output_detail, self._outputs
        name = appliance_display_name(state.service_name) if state is not None else ""
        pressed = self._pressed[0] if self._pressed is not None else None
        row = None
        if detail is not None and state is not None:
            row = next((r for r in state.rows if r.id == detail.output_id), None)
        if row is None:
            return OutputViewState(name=name, output_name="", selected=False, level=None, pressed=pressed)
        row = self._row_with_optimistic_locked(row)
        level = row.volume if row.selected else None
        return OutputViewState(
            name=name, output_name=row.name, selected=row.selected, level=level, pressed=pressed,
        )

    def _display_output_locked(self) -> None:
        """Compose and push the per-output detail page frame — the
        compose_output() counterpart to _display_repeat_locked(). Bypasses
        _display_locked() entirely: this screen has its own dark-chassis
        compose path, like the appliance selector/replay picker/outputs
        list. Caller holds self._lock."""
        view = self._build_output_view_locked(time.monotonic())
        metrics = self._metrics_locked()
        self._push_frame_locked(lambda: self._compositor.compose_output(
            metrics.width, metrics.height, view,
            rotate=self._config.rotate, bgr=self._config.bgr, metrics=metrics,
        ))

    def _display_info_value_locked(self) -> None:
        """Compose and push the compact info page's own drill-in frame —
        the compose_info_value() counterpart to _display_output_locked().
        Reads the tapped field's label/value fresh from self._info.rows at
        every paint (not a copy taken when the view opened), so a gather
        landing while it is open shows up on the next repaint — see
        InfoValueState's own docstring. An index that has since fallen out
        of range (the row count shrank while the view was open) paints a
        blank value rather than raising; the view itself is only ever
        closed by a tap-back or its own timeout, never by this. Bypasses
        _display_locked() entirely, like every other list-chassis screen's
        own compose path. Caller holds self._lock."""
        view_state = self._info_value
        if view_state is not None and view_state.hint is not None:
            view = InfoValueView(label=view_state.hint[0], value=view_state.hint[1])
        else:
            rows = self._info.rows if self._info is not None else INFO_PLACEHOLDER_ROWS
            row = rows[view_state.index] if view_state is not None and 0 <= view_state.index < len(rows) else None
            view = InfoValueView(label=row.label if row else "", value=row.value if row else "-")
        metrics = self._metrics_locked()
        self._push_frame_locked(lambda: self._compositor.compose_info_value(
            metrics.width, metrics.height, view,
            rotate=self._config.rotate, bgr=self._config.bgr, metrics=metrics,
        ))

    def _display_warning_locked(self) -> None:
        """Compose and push the warning page on screen over the current
        base image (the idle logo or the last artwork, dimmed; a flat
        chassis when nothing has been rendered yet). Text comes from the
        descriptor and the manager's latest severity, so a fresh reading
        shows on the next repaint. Bypasses _display_locked() like every
        other secondary screen. Caller holds self._lock."""
        screen = self._warning_screen
        if screen is None:
            return
        desc = _WARNING_BY_ID[screen.warning_id]
        pressed = self._pressed[0] if self._pressed is not None else None
        severity = self._warnings.severity(desc.id)
        message = desc.message_for(severity) if desc.message_for is not None else ""
        title = desc.title_for(severity) if desc.title_for is not None else desc.title
        percent = desc.progress_for(severity) if desc.progress_for is not None else None
        view = WarningView(
            title=title, message=message,
            buttons=tuple(b.label for b in desc.buttons), geometry=desc.geometry, pressed=pressed,
            percent=percent,
        )
        metrics = self._metrics_locked()
        base = self._current_base_image
        self._push_frame_locked(lambda: self._compositor.compose_warning(
            base, metrics.width, metrics.height, view,
            rotate=self._config.rotate, bgr=self._config.bgr, metrics=metrics,
        ))

    def _display_restarting_locked(self) -> None:
        """Compose and push the "Restarting..." frame. Caller holds
        self._lock."""
        metrics = self._metrics_locked()
        self._push_frame_locked(lambda: self._compositor.compose_restarting(
            metrics.width, metrics.height,
            rotate=self._config.rotate, bgr=self._config.bgr, metrics=metrics,
        ))

    def _display_starting_locked(self) -> None:
        """Compose and push the "Starting..." frame and mark it as what is
        showing. Caller holds self._lock and has checked the backend is
        open. Leaves the base-image cache empty on purpose: the first poll
        must paint the logo or artwork over this, not find a stale base."""
        metrics = self._metrics_locked()
        self._push_frame_locked(lambda: self._compositor.compose_starting(
            metrics.width, metrics.height,
            rotate=self._config.rotate, bgr=self._config.bgr, metrics=metrics,
        ))
        self._showing = "starting"

    def _display_list_locked(self) -> None:
        """Compose and push whichever list-chassis screen is open (the
        appliance selector, the replay picker, the outputs list or the
        read-only info page). Bypasses _display_locked() so self.
        _current_base_image survives a list visit unchanged and the frame
        never picks up the main now-playing overlay. Caller holds
        self._lock; the backend-open check is _repaint_current_locked's.

        Passes self._current_base_image through as compose_list()'s `base`
        unconditionally — read only by the compact tier's own picker frame
        (the current artwork/logo, dimmed behind it, same as every other
        compact screen); every other tier ignores the argument entirely and
        keeps its flat chassis background, so this is harmless off compact.
        The info page ignores it too, on every tier (plain_background=True).
        """
        metrics = self._metrics_locked()
        if self._screen == "picker":
            list_state = self._build_picker_list_state_locked(metrics.width, metrics.height, metrics=metrics)
        elif self._screen == "outputs":
            list_state = self._build_outputs_list_state_locked(metrics.width, metrics.height, metrics=metrics)
        elif self._screen == "info":
            list_state = self._build_info_list_state_locked(metrics.width, metrics.height, metrics=metrics)
        else:
            list_state = self._build_list_state_locked(metrics.width, metrics.height, metrics=metrics)
        self._push_frame_locked(lambda: self._compositor.compose_list(
            metrics.width, metrics.height, list_state, base=self._current_base_image,
            rotate=self._config.rotate, bgr=self._config.bgr, metrics=metrics,
        ))

    def _repeat_position_line(self, rec, now: float) -> "tuple[str, int | None] | None":
        """The replay position line for repeat-store record *rec* and the
        counter second it reads (None unless the replay is running), or
        None when *rec* has no replay to show (absent, unavailable, or a
        live source). hold reads 0:00; replaying reads the interpolated
        counter through _repeat_counter_second(); fading_out freezes at
        the last observed position. Shared by the repeat screen and the
        main page's replay timer line so the two always read alike."""
        if rec is None or not rec.available:
            return None
        if rec.state == "hold":
            return f"0:00 / {format_mmss(rec.recording_seconds)}", None
        if rec.state == "replaying":
            second = self._repeat_counter_second(_repeat_counter_value(rec, now))
            return f"{format_mmss(second)} / {format_mmss(rec.duration_seconds)}", second
        if rec.state == "fading_out":
            return f"{format_mmss(rec.position_seconds)} / {format_mmss(rec.duration_seconds)}", None
        return None

    def _replay_timer_locked(self, now: float) -> "tuple[str, float, int | None] | None":
        """The main page's replay timer line right now, as (text, alpha,
        counter second), or None when none is drawn. Only for the appliance
        the pick was for, and only while it is the one shown; never on the
        compact tier. The show window starts at the first frame with a
        position to show, then the line fades. The timer is dropped once it
        has faded, when its replay ends, or when a pick has shown nothing
        within REPLAY_TIMER_ARM_S. Caller holds self._lock; repaint thread
        (reads repeat_store's own leaf lock, as _build_repeat_view_locked()
        does)."""
        appliance_id = self._replay_timer_id
        if appliance_id is None or self._compact_tier():
            return None
        if appliance_id != (self._manual_focus_id or self._reporting_appliance_id):
            return None
        shown_at = self._replay_timer_shown_at
        position = self._repeat_position_line(repeat_store.get(appliance_id, now), now)
        if position is None:
            if shown_at or now - self._replay_timer_armed_at >= REPLAY_TIMER_ARM_S:
                self._replay_timer_id = None
            return None
        if not shown_at:
            shown_at = self._replay_timer_shown_at = now
        elapsed = now - shown_at
        if elapsed >= REPLAY_TIMER_SHOW_S + REPLAY_TIMER_FADE_S:
            self._replay_timer_id = None
            return None
        alpha = 1.0 if elapsed < REPLAY_TIMER_SHOW_S else 1.0 - (elapsed - REPLAY_TIMER_SHOW_S) / REPLAY_TIMER_FADE_S
        return position[0], alpha, position[1]

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
        reading the main screen's overlay shows (dial_volume.shown_muted()/
        shown_volume()), addressed at *screen*'s own appliance rather than
        whatever the main overlay would currently show, since the two
        screens can disagree about which appliance is focused for as long
        as it takes the next poll to notice a manual focus change.
        """
        pressed = self._pressed[0] if self._pressed is not None else None
        # Feeds the shared top band's third page dot — see
        # OverlayState.eq_pages/_effective_overlay_locked for the identical
        # main-screen computation.
        eq_pages = self._eq_available
        if screen is None:
            return RepeatViewState(
                name="", layout="enable", armed=False, line="",
                start_enabled=False, stop_enabled=False, stop_pressed=False, pressed=pressed,
                eq_pages=eq_pages,
            )
        name = appliance_display_name(screen.service_name)
        muted = shown_muted(screen.service_name)
        volume = shown_volume(screen.service_name)
        rec = repeat_store.get(screen.appliance_id, now)
        if rec is None or not rec.available:
            return RepeatViewState(
                name=name, layout="enable", armed=False, line="",
                start_enabled=False, stop_enabled=False, stop_pressed=False,
                muted=muted, volume=volume, pressed=pressed, eq_pages=eq_pages,
            )
        if rec.state in ("recording", "pending", "idle"):
            return RepeatViewState(
                name=name, layout="enable", armed=rec.armed, line="",
                start_enabled=False, stop_enabled=False, stop_pressed=False,
                muted=muted, volume=volume, pressed=pressed, eq_pages=eq_pages,
            )
        if rec.state == "hold":
            # Already reads 0:00 — there is nothing running yet for the
            # counter-latency clamp (REPEAT_COUNTER_LATENCY_S) to apply to.
            line, _ = self._repeat_position_line(rec, now)
            return RepeatViewState(
                name=name, layout="replaying", armed=rec.armed, line=line,
                start_enabled=True, stop_enabled=False, stop_pressed=False,
                muted=muted, volume=volume, pressed=pressed, eq_pages=eq_pages,
            )
        if rec.state == "replaying":
            # The counter reads REPEAT_COUNTER_LATENCY_S behind the true
            # position, floored (never rounded, so the displayed second
            # cannot advance before the full second has elapsed), clamped
            # at zero so a fresh (re)start reads "0:00" for the first
            # couple of seconds, and resolved against the second last
            # painted so a status re-sync that moved the clock back a
            # little never makes the line step back or repeat. All of that
            # is _repeat_counter_second(); the frame carries the integer
            # it drew so _display_repeat_locked() can commit it.
            line, second = self._repeat_position_line(rec, now)
            return RepeatViewState(
                name=name, layout="replaying", armed=rec.armed, line=line,
                start_enabled=True, stop_enabled=True, stop_pressed=False,
                muted=muted, volume=volume, pressed=pressed, eq_pages=eq_pages,
                counter_second=second,
            )
        # fading_out: the line freezes at the last observed position (no
        # interpolation — the fade is a fixed-length event, not a running
        # clock), Start is dimmed and inert, Stop is drawn pressed to read
        # as "already actioned" rather than merely disabled.
        line, _ = self._repeat_position_line(rec, now)
        return RepeatViewState(
            name=name, layout="replaying", armed=rec.armed, line=line,
            start_enabled=False, stop_enabled=True, stop_pressed=True,
            muted=muted, volume=volume, pressed=pressed, eq_pages=eq_pages,
        )

    def _display_repeat_locked(self) -> None:
        """Compose and push the repeat-screen frame — the compose_repeat()
        counterpart to _display_locked(). Bypasses _display_locked()
        entirely, like _display_list_locked(): this screen has its own
        compose path and must never pick up the main now-playing overlay.
        Passes self._current_base_image through as compose_repeat()'s
        `base` — the replaying layout draws it (dimmed) behind the
        position counter; the enable layout ignores it (the compact tier's
        own frame dims it either way — see the compositor's compact repeat
        builder). Caller holds self._lock. Stamps self._repeat_layout_shown
        from the freshly built view so touch_surface() can report the
        compact tier's own replay_surface exactly while this layout is the
        one actually on screen, and commits the view's counter_second as
        self._repeat_painted_second, the reference the counter's tick
        advances against (None for any layout without a running counter,
        so the next replaying frame re-anchors).

        An artwork-tap hide window (see hide_controls()) hides the
        replaying layout's controls the way it hides the main screen's,
        with the same slide on the rich and large tiers (see
        _advance_reveal_locked()); the counter keeps counting underneath.
        The window ends here, at the first paint that finds no replay
        running; that paint's layout does not animate, so the controls snap
        back rather than slide. While the window lapses or a reveal ends it
        early, the controls slide back in the same way.

        The touch surface is the ordinary one for the whole of a slide-in
        (see touch_surface()): taps act on the bands as they arrive."""
        now = time.monotonic()
        view = self._build_repeat_view_locked(self._repeat_screen, now)
        self._repeat_layout_shown = view.layout
        metrics = self._metrics_locked()
        # Only a running replay has artwork behind its controls to reveal:
        # a window still open when the replay stops (Restart must be
        # tappable again) or the layout changes ends at once.
        replaying = view.layout == "replaying" and view.counter_second is not None
        if self._controls_hidden(now) and not replaying:
            self._controls_hidden_until = 0.0
        steady = not self._compact_controls_hidden() and not self._controls_hidden(now)
        animating, progress = self._advance_reveal_locked(now, steady, replaying and self._slide_tier())
        controls = steady or animating
        self._push_frame_locked(lambda: self._compositor.compose_repeat(
            metrics.width, metrics.height, view, base=self._current_base_image,
            rotate=self._config.rotate, bgr=self._config.bgr, metrics=metrics,
            controls=controls, reveal_progress=progress,
        ))
        if animating:
            self._reveal_frame_at = time.monotonic()
        # Committed whether or not the push succeeded, and whether or not
        # the line is visible: a write failure is already recorded and the
        # next second's tick repaints the whole line anyway, whereas
        # retrying the same second on every wake against a failing panel
        # would spin; and a hidden counter keeps counting, the tick
        # advancing against this reference, so it must always move.
        self._repeat_painted_second = view.counter_second

    def _shown_eq(self, state: "EqScreenState", control: str) -> "int | None":
        """The bass or treble value *control* should currently show: the
        pending optimistic override's own slot for *control* when it has
        not expired and is not None, else the screen's own last-fetched
        value (None until the first fetch lands for this appliance). The
        _shown_output_level() shape, for the EQ page's pair instead of one
        output's single level."""
        override = self._eq_optimistic
        if override is not None and override[2] > time.monotonic():
            value = override[0] if control == "bass" else override[1]
            if value is not None:
                return value
        return state.bass_db if control == "bass" else state.treble_db

    def _build_eq_view_locked(self, screen: "EqScreenState | None", now: float) -> EqViewState:
        """Build the compositor's EqViewState from *screen* — reads
        bass/treble through the optimistic override (see _shown_eq()) so a
        just-tapped stepper moves on the same frame as the tap, before the
        worker's reconciling fetch lands. muted/volume feed the top band's
        display-only readout, the same reading the repeat screen's own top
        band shows, addressed at *screen*'s own appliance. Caller holds
        self._lock (called from _display_eq_locked)."""
        pressed = self._pressed[0] if self._pressed is not None else None
        if screen is None:
            return EqViewState(name="", bass_db=None, treble_db=None, loaded=False, pressed=pressed)
        name = appliance_display_name(screen.service_name)
        muted = shown_muted(screen.service_name)
        volume = shown_volume(screen.service_name)
        return EqViewState(
            name=name,
            bass_db=self._shown_eq(screen, "bass"),
            treble_db=self._shown_eq(screen, "treble"),
            loaded=screen.loaded,
            muted=muted, volume=volume, pressed=pressed,
        )

    def _display_eq_locked(self) -> None:
        """Compose and push the EQ-page frame — the compose_eq()
        counterpart to _display_repeat_locked(). Bypasses _display_locked()
        entirely: this screen has its own compose path and must never pick
        up the main now-playing overlay. Caller holds self._lock."""
        view = self._build_eq_view_locked(self._eq, time.monotonic())
        metrics = self._metrics_locked()
        self._push_frame_locked(lambda: self._compositor.compose_eq(
            metrics.width, metrics.height, view,
            rotate=self._config.rotate, bgr=self._config.bgr, metrics=metrics,
        ))

    def eq_step(self, control: str, delta: int) -> None:
        """Touch-thread entry (dial_main's on_zone_tap, for an EQ_BASS_*/
        EQ_TREBLE_* tap, repeating): absolute clamp(shown + delta, -6, +6)
        for *control* ("bass" or "treble") — the same shape as
        output_volume_tap(): the appliance clamps again defensively.
        Optimistic override shown at once; the worker's fetch-after-set
        reconciles it. A no-op when the EQ page is not open for any
        appliance."""
        state = self._eq
        if state is None:
            return
        shown = self._shown_eq(state, control)
        if shown is None:
            shown = 0
        new = max(-EQ_LIMIT_DB, min(EQ_LIMIT_DB, shown + delta))
        prev_bass = self._shown_eq(state, "bass")
        prev_treble = self._shown_eq(state, "treble")
        self._eq_optimistic = (
            new if control == "bass" else prev_bass,
            new if control == "treble" else prev_treble,
            time.monotonic() + 2.0,
        )
        _enqueue_eq_set(
            _EqTarget(state.appliance_id, state.ip, state.port), **{f"{control}_db": new},
        )
        self._overlay_signal.set()

    def on_eq_result(self, kind: str, appliance_id: str, status, body, request) -> None:
        """Worker-thread entry (dial_eq's start_eq_worker on_result
        callback): fold a "fetch" result into self._eq under self._lock — a
        "set" result is not applied here, the worker's own fetch-after-set
        does that. Mirrors on_outputs_result(). Drops a result for another
        appliance (the EQ page moved on, or closed, while the request was
        in flight) and any malformed/failed body. Clears the optimistic
        override once it has expired — the same _outputs_optimistic
        discipline on_outputs_result() follows, so a fetch that raced a
        still-fresh tap never flashes the pre-tap value back onto screen."""
        if kind != "fetch":
            return
        if not isinstance(body, dict) or not body.get("ok"):
            return
        bass, treble = body.get("bass_db"), body.get("treble_db")
        if isinstance(bass, bool) or not isinstance(bass, int):
            return
        if isinstance(treble, bool) or not isinstance(treble, int):
            return
        with self._lock:
            state = self._eq
            if state is None or state.appliance_id != appliance_id:
                return
            self._eq = dataclasses.replace(state, bass_db=bass, treble_db=treble, loaded=True)
            override = self._eq_optimistic
            if override is not None and override[2] <= time.monotonic():
                self._eq_optimistic = None
        self._overlay_signal.set()

    # ---- Wi-Fi link: the idle icon and the No-WiFi page -------------------

    # ---- On-screen warnings: the source API and the one request point ------

    def _warning_active(self, warning_id: str, severity=None) -> None:
        """A source reports its condition present (again). Lock-free, the
        on_network_view() discipline: the manager records it and the page
        is requested if it is due right now (main screen, awake, nothing
        else requested). Calling this on every poll while the condition
        holds is expected; the manager treats a repeat as a severity
        refresh. A warning that has just become active may wake a
        sleeping panel if it is interrupting; a refresh never does."""
        began = self._warnings.set_active(warning_id, severity)
        self._request_due_warning(wake=began)

    def _warning_cleared(self, warning_id: str) -> None:
        """A source reports its condition gone: the incident ends (any
        dismissal, in memory or on disk, is forgotten), an open page for
        it closes on its own and a pending request for it is dropped.
        Lock-free."""
        self._warnings.clear(warning_id)
        screen = _WARNING_BY_ID[warning_id].screen
        if self._screen == screen:
            self._screen_request = _policy(screen).back_to
        elif self._screen_request == screen:
            self._screen_request = None

    def _request_due_warning(self, wake: bool = False) -> None:
        """Request the page of the highest-priority warning that is active
        and not snoozed, if any, and only while the main screen is showing
        with nothing else requested and the panel awake (never over a
        list, the info page, another warning or the restart screen, and
        never into a sleeping panel: the wake path calls this again).
        An interrupting warning is also requested over a secondary screen
        (the opener pops it), over a lower-priority warning page and over
        a pending request other than the restart screen's, and with
        wake=True into a sleeping panel (the opener wakes it); it is not
        requested again while its own page is up. Callable with or
        without self._lock: plain reads and one plain request write, the
        same writes on_network_view() makes."""
        desc = self._warnings.due()
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

    def on_network_view(self, view: "NetworkView") -> None:
        """Callback for the network poller (dial_network.py). Runs on the
        POLLER thread, never the poll/repaint/touch threads, and takes NO
        lock of this class's own; every write here is a single attribute
        assignment, and any screen change goes through the warning
        manager's request path (see _request_due_warning) for the repaint
        thread to fold in, exactly like on_repeat_result().

        connected: the streak resets, the ever-connected latch is set and
        the No-WiFi warning is cleared (the incident is over: an open page
        closes on its own and a Dismiss is forgotten).
        down: the streak grows; at NOWIFI_PROMPT_STREAK the warning goes
        active unless the dial has never been connected since it started
        (still connecting: the icon flashes grey/blank instead and only a
        tap on it opens the page). Whether the page then opens is the
        manager's call: not while dismissed for this incident, already
        open or requested, another screen is in the way, or the panel is
        asleep (it comes back on wake).
        ignored (setup mode, reboot pending): the streak resets but the
        warning and the latch are kept; only a connected poll ends an
        incident.
        unknown (a failed read): nothing changes at all.
        Never raises."""
        try:
            self._network = view
            if view.link == LINK_CONNECTED:
                self._wifi_ever_connected = True
                self._wifi_down_streak = 0
                self._warning_cleared("nowifi")
            elif view.link == LINK_DOWN:
                self._wifi_down_streak += 1
                if self._wifi_ever_connected and self._wifi_down_streak >= NOWIFI_PROMPT_STREAK:
                    self._warning_active("nowifi")
            elif view.link == LINK_IGNORED:
                self._wifi_down_streak = 0
            self._overlay_signal.set()
        except Exception:
            logging.debug("dial display: on_network_view raised", exc_info=True)

    def _wifi_link(self) -> str:
        """The latest link verdict, or "unknown" before the first poll.
        Plain reference read, safe from any thread."""
        view = self._network
        return view.link if view is not None else "unknown"

    def _wifi_flashing(self) -> bool:
        """True exactly while the idle screen is the one on screen and the
        link is down — the only time the flash is drawn and the only time
        the repaint loop has to wake for it. Lock-free plain reads, the
        _check_secondary_timeout() discipline (a stale read costs one
        harmless extra repaint)."""
        return (
            self._screen == "main" and self._now_playing is None
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
        """(wifi_bars, wifi_style) for compose_idle(): steady lit arcs
        while connected; while down, the flash's current half — grey, and
        on the emphasised half either red (the link was lost after having
        connected since boot) or nothing at all (never connected yet: the
        dial is still connecting, which is not an alarm); and a steady
        all-grey glyph while the link is ignored or unknown. Caller holds
        self._lock."""
        view = self._network
        if view is None:
            return 0, WIFI_GREY
        if view.link == LINK_CONNECTED:
            return view.bars, WIFI_SIGNAL
        if view.link == LINK_DOWN:
            if not self._wifi_alarm_phase(time.monotonic()):
                return 0, WIFI_GREY
            return 0, (WIFI_RED if self._wifi_ever_connected else WIFI_OFF)
        return 0, WIFI_GREY

    def open_nowifi(self) -> None:
        """Touch-thread entry (dial_main's on_zone_tap, for an IDLE_WIFI
        tap): open the No-WiFi page while the link is down — the manual
        route to Restart after a Dismiss (it ignores the dismissal) and the
        only route while the dial has never connected since boot (the
        page never auto-opens in that state). Inert while connected/
        unknown (the corner square is always in the idle table; only a
        flashing icon means anything). Plain write plus a repaint signal."""
        if self._wifi_link() != LINK_DOWN:
            return
        self._screen_request = "nowifi"
        self._overlay_signal.set()

    def warning_button_tap(self, zone: "TouchZone") -> None:
        """Touch-thread entry (dial_main's on_zone_tap, for any warning
        cell): resolve *zone* against the warning on screen first (two
        one-cell warnings share a geometry, so the same zone can belong
        to either), then against the registry for a tap that lands just
        after the page closed, and run that button's action. Plain writes
        plus a repaint signal; no lock, no I/O on this thread."""
        showing = self._warning_screen
        desc = _WARNING_BY_ID.get(showing.warning_id) if showing is not None else None
        button = desc.button_for(zone) if desc is not None else None
        if button is None:
            owner = self._warnings.button_owner(zone)
            if owner is None:
                return
            desc, button = owner
        self._run_warning_action(desc, button.action)

    def _run_warning_action(self, desc: "WarningDescriptor", action: str) -> None:
        if action == ACTION_DISMISS:
            # Dismiss is the only thing that starts a snooze: the manager
            # applies the row's policy (incident-scoped or timed, and
            # persisted or not) and the page closes. The icon keeps
            # flashing for No-WiFi; a tap on it re-opens the page.
            self._warnings.dismiss(desc.id)
            self._screen_request = _policy(desc.screen).back_to
            self._overlay_signal.set()
        elif action == ACTION_RESTART:
            # Show "Restarting..." at once, then ask for the reboot.
            # request_reboot() does its I/O on its own short-lived thread
            # and is rate-gated, so a second tap inside the cooldown only
            # re-shows the screen. Never raises.
            self._screen_request = "restarting"
            self._overlay_signal.set()
            _request_reboot()

    def nowifi_dismiss_tap(self) -> None:
        """Kept for existing direct callers/tests: the No-WiFi Dismiss cell."""
        self._run_warning_action(_WARNING_BY_ID["nowifi"], ACTION_DISMISS)

    def nowifi_restart_tap(self) -> None:
        """Kept for existing direct callers/tests: the No-WiFi Restart cell."""
        self._run_warning_action(_WARNING_BY_ID["nowifi"], ACTION_RESTART)

    def _tick_wifi_flash(self) -> None:
        """Wake the repaint loop for the flash's next half-period while the
        idle screen is flashing — called from the repaint thread's own
        timeout branch (see _repaint_run), whose wait _next_repaint_
        deadline() has already sized onto the boundary."""
        if self._wifi_flashing():
            self._overlay_signal.set()

    def _tick_warnings(self) -> None:
        """Once a second from the repaint thread's own timeout branch:
        raise a warning whose snooze has just run out (or one that was
        due while a list or menu was open), and write any snooze a
        Dismiss changed since the last write. Lock-free plain reads, the
        _check_secondary_timeout() discipline; the file write runs with
        no lock held. A warning that has been up for its
        auto_clear_after_s is cleared here, through the same path a
        source's clear takes."""
        for warning_id in self._warnings.expired():
            self._warning_cleared(warning_id)
        self._request_due_warning()
        self._warnings.flush()

    # ---- Software update: the warning cards ---------------------------------

    def _tick_update_watch(self) -> None:
        """Once a second from the repaint thread's timeout branch: when the
        update result file has changed, map it onto the update cards.
        Lock-free, the on_network_view() discipline. Never raises."""
        try:
            view = self._update_watcher.tick(time.monotonic())
            if view is not None:
                self._apply_update_view(view)
        except Exception:
            logging.debug("dial display: update watch raised", exc_info=True)

    def _apply_update_view(self, view: "UpdateView") -> None:
        """A run in progress shows the progress card, except in the reboot
        phase (the existing restarting screen, without asking for a reboot:
        the updater already has) and the verify phase (the boot after the
        swap: nothing until the verdict). A finished run shows its result
        card once, recorded in the seen marker."""
        if view.status == STATUS_IN_PROGRESS:
            if view.phase == PHASE_REBOOT:
                self._warning_cleared("update")
                self._screen_request = "restarting"
                self._overlay_signal.set()
            elif view.phase != PHASE_VERIFY:
                self._warning_active("update", severity=view)
        elif view.status in (STATUS_SUCCESS, STATUS_FAILURE):
            marker = view.last_run_at or f"{view.status}-{view.tag}"
            if self._update_seen is None:
                self._update_seen = read_seen_marker(self._update_seen_path)
            if marker == self._update_seen:
                return
            self._update_seen = marker
            write_seen_marker(marker, self._update_seen_path)
            self._warning_cleared("update")
            self._warning_active("update_result", severity=view)
        self._overlay_signal.set()

    # ---- SD card health: the warning page --------------------------------

    def on_sd_health_view(self, view: "SdHealthView") -> None:
        """Callback for the SD health reader (dial_sdhealth.py). Runs on
        the network poller's thread; takes NO lock of this class's own,
        the on_network_view() discipline.

        A reading that is low (dial_sdhealth.is_low, with hysteresis)
        starts or refreshes the SD warning with the percent as its
        severity; the manager decides whether the page opens (not while
        snoozed by a Dismiss, not over another screen, not into a sleeping
        panel). A reading that is not low ends the incident: the warning
        clears, an open page closes on its own, and any snooze, including
        one saved across restarts, is forgotten. Never raises."""
        try:
            self._sd_health = view
            low = _sd_is_low(view, self._sd_low)
            self._sd_low = low
            if low:
                self._warning_active("sdhealth", severity=view.percent)
            else:
                self._warning_cleared("sdhealth")
            self._overlay_signal.set()
        except Exception:
            logging.debug("dial display: on_sd_health_view raised", exc_info=True)

    def sdhealth_dismiss_tap(self) -> None:
        """Kept for existing direct callers/tests: the SD warning's Dismiss cell."""
        self._run_warning_action(_WARNING_BY_ID["sdhealth"], ACTION_DISMISS)

    def _display_idle_locked(self) -> None:
        """Compose and push the idle-screen frame — the "replay available"
        logo (the arrows-on-disc image) whenever the idle affordance is due,
        else the plain logo already stored as the current base — either
        way with the "i" information badge and the Wi-Fi status glyph
        top-left (steady bars while connected; while down, the grey/red
        flash after a lost link or the grey/blank flash while still
        connecting) and no volume/mute controls overlay (nothing is
        playing, so there is nothing else on this screen to control).
        Reached whenever nothing is playing (see
        _idle_chassis_due_locked), not only while a replay is available;
        degrades to the plain base if the replay image cannot be loaded.
        Caller holds self._lock; a no-op if the backend is closed or nothing
        has been rendered yet."""
        if not (self._backend_open and self._backend is not None):
            return
        if self._current_base_image is None:
            return
        # The idle screen draws no controls; the next now-playing frame has
        # nothing comparable before it and must not slide in or out.
        self._controls_last = None
        self._reveal_started_at = 0.0
        metrics = self._metrics_locked()
        base = (
            (load_logo(self._replay_logo_path, metrics.width, metrics.height) if self._idle_affordance else None)
            or self._current_base_image
        )
        wifi_bars, wifi_style = self._idle_wifi_args_locked()
        self._push_frame_locked(lambda: self._compositor.compose_idle(
            base, metrics.width, metrics.height,
            rotate=self._config.rotate, bgr=self._config.bgr, metrics=metrics,
            wifi_bars=wifi_bars, wifi_style=wifi_style,
        ))

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
        roster = {r.appliance_id: r for r in self._last_roster if r.appliance_id}
        woke = False
        for appliance_id in ids:
            # Playing set first, then the last-published roster — an
            # authorization granted to an idle appliance is confirmed here
            # rather than waiting for the next reconcile pass.
            target = targets.get(appliance_id) or roster.get(appliance_id)
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
        body_id = result.get("appliance_id")
        if result.get("untyped_refusal") and not body_id:
            # An earlier-dialect refusal carries no id: correlate with the
            # id this target was resolved to.
            body_id = target.appliance_id
        elif (
            outcome == OUTCOME_AUTHORIZED and not body_id
            and not getattr(target, "typed_refusals", True)
        ):
            # Nor does an earlier-dialect success reply. Without this, an
            # appliance of that dialect that once refused the dial could
            # never be seen to accept it again.
            body_id = target.appliance_id
        changed = auth_map.apply(
            target.appliance_id, outcome, body_id, time.monotonic(),
        )
        if (
            outcome == OUTCOME_UNAUTHORIZED
            and auth_map.state(target.appliance_id) == AUTH_UNAUTHORIZED
            and auth_map.record_refusal(target.appliance_id)
        ):
            logging.warning(
                "dial display: appliance %s refused this dial; allow it in "
                "that appliance's web UI",
                appliance_display_name(target.service_name or target.name),
            )
        return changed

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
                # Stamped at apply time, not with the `now` taken before the
                # fan-out: the fetch blocks for up to its own deadline, and a
                # replay position stamped earlier than it was sampled would
                # interpolate ahead of the truth by that much.
                self._apply_status_to_repeat(target.appliance_id, record, time.monotonic())
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
            if body.get("state") == "replaying" and self._manual_focus_id == appliance_id:
                # A replay the dial is following has just been accepted:
                # show it as playing until its advertisement arrives (see
                # _with_accepted_replay()), and poll now rather than at the
                # next tick.
                self._accepted_replay = (appliance_id, now + ACCEPTED_REPLAY_GRACE_S)
                self.request_poll()
            if self._pending_repeat_stop_id == appliance_id:
                # This ok ack is for the Stop this appliance's repeat_stop_
                # tap() just sent (see that method) — on the compact tier,
                # close the repeat screen back to the playing 2x2
                # immediately, rather than waiting for it to time out or for
                # the next poll to find the appliance not playing. Off
                # compact the repeat screen simply stays, as today.
                self._pending_repeat_stop_id = None
                if (
                    self._compact_tier() and self._screen == "repeat"
                    and self._repeat_screen is not None
                    and self._repeat_screen.appliance_id == appliance_id
                ):
                    self._screen_request = "main"
            self._overlay_signal.set()
            return

        if self._pending_repeat_stop_id == appliance_id:
            # A rejected/transient Stop leaves the repeat screen as today —
            # only an ok ack pops it.
            self._pending_repeat_stop_id = None

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
        if self._replay_timer_id == appliance_id:
            # The replay did not start: nothing for the timer line to show.
            self._arm_replay_timer(None)
            self._overlay_signal.set()

    def on_outputs_result(self, kind: str, appliance_id: str, status, body, request) -> None:
        """Callback for the outputs worker (dial_outputs.py). Runs on the
        WORKER thread — never the poll/repeat/touch threads.

        A "set" outcome is not applied here at all: the worker already
        queued the reconciling fetch for the same target right after
        sending it, and that fetch's own "fetch" callback (this same
        function, called again) is what the screen actually shows — so a
        rejected mutation (in use elsewhere, a PIN required, a capacity
        limit) never needs special-casing here, it simply shows up as the
        appliance's own truth on the very next fetch.

        A "fetch" outcome folds the parsed row list into the outputs
        snapshot in one assignment, under self._lock (a leaf-lock-free
        section — this class's own lock is the only one taken here, exactly
        as _clear_focus() takes it from the poll thread). A late result for
        an appliance the screen has since moved on from is dropped. A
        malformed/unreachable result (rows is None) leaves the last good
        snapshot on screen. When the detail page is open and its output has
        disappeared from the fresh rows (gone remote-in-use, or removed),
        the screen is asked to fall back to the list.
        """
        if kind != "fetch":
            return
        rows = _parse_outputs_body(status, body)
        with self._lock:
            state = self._outputs
            if state is None or state.appliance_id != appliance_id:
                return
            if rows is None:
                return
            page = _clamp_page(state.page, len(rows), self._rows_per_page())
            self._outputs = dataclasses.replace(state, rows=rows, page=page, loaded=True)
            optimistic = self._outputs_optimistic
            if optimistic is not None and optimistic[3] <= time.monotonic():
                self._outputs_optimistic = None
            detail = self._output_detail
            if (
                detail is not None and self._screen == "output"
                and not any(r.id == detail.output_id for r in rows)
            ):
                self._screen_request = "outputs"
        self._overlay_signal.set()

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

    def _clear_focus(self, reason: str) -> None:
        """Poll thread only: drop the manual focus and any pending grace,
        and close the current screen when its policy says a focus clear
        should pop it (the repeat screen was opened for that focus)."""
        self._manual_focus_id = None
        self._focus_pending = None
        logging.info("dial display: manual focus cleared (%s)", reason)
        if _policy(self._screen).closes_on_focus_clear:
            with self._lock:
                self._close_secondary_locked()

    def _update_dots_active(self, now: float) -> None:
        """Recompute whether the page dots are currently tappable: the
        currently focused/reporting appliance has a fresh, available
        repeat-store record, OR the EQ page is available for it (see
        _update_eq_available() — call that one first each tick, since this
        reads its result). Poll thread only; read lock-free by
        touch_surface() and _effective_overlay_locked()."""
        appliance_id = self._manual_focus_id or self._reporting_appliance_id
        rec = repeat_store.get(appliance_id, now) if appliance_id else None
        self._dots_active = (rec is not None and rec.available) or self._eq_available

    def _update_outputs_available(self) -> None:
        """Recompute whether the top-right OUTPUTS zone is currently live,
        from the currently focused/reporting appliance's fresh roster row —
        poll thread only; read lock-free by touch_surface(). Mirrors
        _update_dots_active(), one tick behind the same focus/reporting
        resolution."""
        appliance_id = self._manual_focus_id or self._reporting_appliance_id
        entry = next(
            (r for r in self._last_roster if r.appliance_id == appliance_id), None,
        ) if appliance_id else None
        self._outputs_available = (
            entry is not None and entry.dial_outputs and entry.auth != AUTH_UNAUTHORIZED
        )

    def _update_eq_available(self) -> None:
        """Recompute whether the EQ page is available for the currently
        focused/reporting appliance — poll thread only; read lock-free by
        cycle_pages()/touch_surface()/_effective_overlay_locked()/
        _build_repeat_view_locked(). Mirrors _update_outputs_available(),
        with an extra veto: no EQ page exists on the compact tier even when
        the appliance itself advertises dial_eq. Call before
        _update_dots_active() each tick — the dots computation reads this
        result."""
        appliance_id = self._manual_focus_id or self._reporting_appliance_id
        entry = next(
            (r for r in self._last_roster if r.appliance_id == appliance_id), None,
        ) if appliance_id else None
        self._eq_available = (
            entry is not None and entry.dial_eq and entry.auth != AUTH_UNAUTHORIZED
            and not self._compact_tier()
        )

    def _maybe_show_transition(self, previous_reporting_id: "str | None") -> None:
        """Push a brief dark transition frame (_show_transition_locked())
        when self._reporting_appliance_id has just changed, this tick,
        directly from one appliance to a DIFFERENT one — poll thread only;
        call once the tick's own reporting id is final, in either branch of
        _poll_once (something playing, or an idle focus taking over from a
        stopped one). A no-op when it is unchanged, cleared (nothing
        playing/focused now), or was previously unset: a fresh start (boot,
        or the first appliance ever seen) has no stale artwork on screen to
        guard against, so it goes straight to that appliance's own logo/
        artwork with no transition flash first."""
        reporting_id = self._reporting_appliance_id
        if (
            reporting_id is not None
            and previous_reporting_id is not None
            and reporting_id != previous_reporting_id
        ):
            with self._lock:
                self._show_transition_locked()

    def _close_bound_screen_if_unfocused(self) -> None:
        """Poll thread: pop whichever screen is showing if its own policy
        says it is bound to an appliance (the outputs list, the per-output
        detail page) and that appliance is no longer the focused/reporting
        one this tick — an auto-pick change, a focus clear, or nothing
        playing/focused at all. self._screen and the bound state_attr are
        read lock-free here, the same "a stale read costs at most one
        harmless extra tick" discipline _check_secondary_timeout() uses;
        the close itself is re-checked and applied under self._lock."""
        policy = _policy(self._screen)
        if not policy.bound_to_appliance:
            return
        state = getattr(self, policy.state_attr)
        current_id = self._manual_focus_id or self._reporting_appliance_id
        if state is not None and state.appliance_id != current_id:
            with self._lock:
                self._close_secondary_locked()

    def _with_accepted_replay(self, targets: list, now: float) -> list:
        """*targets* (the mDNS playing set), plus the appliance whose replay
        the dial has just had accepted (see on_repeat_result()), until its
        own playing advertisement arrives. The appliance acknowledges a
        seek at once, but that advertisement only reaches the dial a few
        seconds later; in between, the replay the user just started is
        shown as playing straight away, built from its roster entry, so the
        ordinary playing path fetches its status and artwork. Only that
        gap is bridged: the window ends as soon as the advertisement is
        seen, when the dial stops following the appliance, when its repeat
        record no longer says a replay is running, or after
        ACCEPTED_REPLAY_GRACE_S, after which the playing set alone decides
        again. Poll thread only (the touch/worker side only ever sets the
        window); reads the roster published by the previous poll (the
        picker only offers rostered appliances)."""
        accepted = self._accepted_replay
        if accepted is None:
            return targets
        appliance_id, until = accepted
        rec = repeat_store.get(appliance_id, now)
        if (
            now >= until
            or self._manual_focus_id != appliance_id
            or any(t.appliance_id == appliance_id for t in targets)
            or rec is None or not rec.available or rec.state not in ("replaying", "fading_out")
        ):
            self._accepted_replay = None
            return targets
        entry = next(
            (r for r in self._last_roster if r.appliance_id == appliance_id and r.auth != AUTH_UNAUTHORIZED),
            None,
        )
        if entry is None:
            return targets
        return [*targets, PlayingTarget(
            ip=entry.ip, port=entry.port, name=entry.name, dial_api=entry.dial_api,
            audio_status=entry.audio_status, dial_status=entry.dial_status,
            dial_outputs=entry.dial_outputs, dial_eq=entry.dial_eq,
            service_name=entry.service_name, playing_since=now,
            appliance_id=entry.appliance_id, auth=entry.auth,
        )]

    def _poll_once(self) -> None:
        with self._lock:
            fitted = self._config.fitted
        if not fitted:
            self._source_service_name = None
            self._now_playing = None
            self._reporting_appliance_id = None
            self._dots_active = False
            self._outputs_available = False
            self._eq_available = False
            return

        # Captured before anything below can change it — compared against
        # this tick's own final value at _maybe_show_transition()'s two call
        # sites, one per branch (nothing playing vs. something playing).
        previous_reporting_id = self._reporting_appliance_id

        targets = self._with_accepted_replay(self._get_display_targets(), time.monotonic())
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
        # The targets this dial may act on: not confirmed unauthorized, and
        # carrying an identity (an unresolved legacy or identity-less
        # appliance cannot be addressed or tracked). Everything below that
        # wakes, binds, reports or offers a volume target works from this
        # list; the raw list still feeds the selector (via the roster) so a
        # refused appliance stays listed.
        visible_targets = [
            t for t in targets if t.auth != AUTH_UNAUTHORIZED and t.appliance_id
        ]
        stopped_ids = self._prev_playing_ids - playing_ids
        if stopped_ids:
            self._reconcile_due = True
            auth_map.force_due()
        # A refused appliance that starts playing again is re-checked at
        # once rather than at the end of its re-probe backoff: the usual way
        # to fix a refusal is to allow the dial in the appliance's web UI and
        # press play, and an appliance that pushes no auth change gives the
        # dial no other prompt to look again.
        started_refused = [
            t.appliance_id for t in targets
            if t.appliance_id not in self._prev_playing_ids and t.auth == AUTH_UNAUTHORIZED
        ]
        for appliance_id in started_refused:
            auth_map.force_due(appliance_id)
        if started_refused:
            self._reconcile_due = True
        # An appliance that has just started playing and has never answered
        # this dial (after a restart, say) is checked before anything below
        # wakes the panel for it or shows it: otherwise one that refuses the
        # dial would be shown as playing until a later poll hid it again.
        # Only for an unpinned poll (a focus or a binding is checked by the
        # walk itself, which releases it on a refusal), and in the walk's
        # own order, stopping at the first appliance that does not refuse:
        # that is the one the walk would have asked first anyway. The
        # replies are kept for the walk, which uses them instead of asking
        # again.
        first_checks: dict[str, tuple[float, dict]] = {}
        if self._manual_focus_id is None and self._bound_appliance_id is None:
            for t in visible_targets:
                if (
                    t.auth != AUTH_UNKNOWN or not t.dial_status
                    or t.appliance_id in self._prev_playing_ids
                ):
                    break
                sent_at = time.monotonic()
                result = fetch_target_status(t, self._dial_id, timeout_seconds=DIAL_STATUS_TIMEOUT_SECONDS)
                self._apply_status_to_auth(t, result)
                self._apply_status_to_repeat(t.appliance_id, result, time.monotonic())
                first_checks[t.service_name] = (sent_at, result)
                if auth_map.state(t.appliance_id) != AUTH_UNAUTHORIZED:
                    break
        if first_checks:
            visible_targets = [
                t for t in visible_targets if auth_map.state(t.appliance_id) != AUTH_UNAUTHORIZED
            ]
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

        # Resolve manual focus before anything else. focus_entry is the
        # roster entry (playing or idle); focus_target is the same
        # appliance only when it is in the playing set this tick. A focus
        # is cleared when the appliance is no longer rostered at all (or is
        # confirmed unauthorized), or when it was playing last tick and has
        # just stopped — "the show is over". A focus resting on an idle
        # appliance is otherwise kept even while something else plays: that
        # is what lets a pick control an idle device. UNLESS a picker-
        # started replay is still within its pending grace window (6), in
        # which case the focus is kept and the empty-targets branch below
        # shows the appliance's name over the logo instead of the ordinary
        # idle screen.
        focus_id = self._manual_focus_id
        pending = self._focus_pending
        if pending is not None and (pending[0] != focus_id or now >= pending[2]):
            self._focus_pending = None
            pending = None
        focus_entry = None      # the roster entry, playing or idle
        focus_target = None     # the playing-set entry, when playing
        if focus_id is not None:
            focus_entry = next(
                (r for r in roster if r.appliance_id == focus_id and r.auth != AUTH_UNAUTHORIZED),
                None,
            )
            focus_target = next(
                (t for t in visible_targets if t.appliance_id == focus_id),
                None,
            )
            if focus_entry is None:
                if pending is not None and self._auth_not_unauthorized(focus_id):
                    pass  # grace: keep the focus, appliance not rostered yet
                else:
                    self._clear_focus("appliance gone or unauthorized")
                    focus_entry = focus_target = None
            elif focus_target is None and focus_id in stopped_ids:
                self._clear_focus("appliance stopped playing")
                focus_entry = None
            elif focus_target is not None and pending is not None:
                self._focus_pending = None  # sighted: converts to a normal focus

        # An idle focus: a rostered focus with nothing playing under it.
        # The walk/artwork-selection path below runs only when this is
        # None; when it is set, one pinned status fetch replaces it (3.3),
        # and it is what the empty-targets branch shows in place of the
        # idle screen (5.2).
        idle_focus = focus_entry if (focus_entry is not None and focus_target is None) else None

        # Any visible playing target counts as activity, including
        # status-erroring ones: the mDNS _autostream-playing._tcp presence
        # alone means audio is playing on an appliance this dial can talk
        # to. A confirmed-unauthorized appliance, or one with no identity
        # after legacy resolution, does not count: the dial may not use it
        # or control it, so its playback must neither wake the panel nor
        # hold off idle sleep. (Unknown auth still counts: it is
        # controllable until a refusal says otherwise.)
        if visible_targets:
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
            # must not survive to the next time something starts playing —
            # unless a manual focus (idle, or a not-yet-rostered pending
            # replay) has something of its own to show. The roster reconcile
            # and the idle-affordance/picker/selector refresh still run here
            # on their usual cadence — this is exactly the state the idle
            # screen and the replay picker exist for, and the artwork walk
            # below never runs in this branch to cover it another way.
            self._source_service_name = None
            observe_master_volume(None, None)
            observe_mute_state(None, None)
            if self._reconcile_due or now - self._last_reconcile_at >= RECONCILE_INTERVAL_SECONDS:
                self._reconcile_pass(roster, set())
                self._last_reconcile_at = now
                self._reconcile_due = False
            self._refresh_idle_affordance(roster, now)
            self._refresh_picker_rows(roster, now)
            self._refresh_selector_rows(roster, idle_focus.appliance_id if idle_focus is not None else None)

            with self._lock:
                # Each screen's own row says what a poll finding nothing
                # playing does to it: IDLE_KEEP screens (the two list
                # screens) are left alone — their own inactivity timeout
                # closes them; IDLE_KEEP_WITH_FOCUS (repeat) closes unless
                # an idle focus keeps it meaningful. A pending request for a
                # screen that defers sleep (an open_* call just ran on the
                # touch thread, the repaint thread has not applied it yet)
                # counts as open too, so this poll never clobbers a list
                # that is opening this very tick.
                open_or_requested = [_policy(self._screen)]
                if self._screen_request is not None:
                    open_or_requested.append(_policy(self._screen_request))
                list_open = any(p.defers_sleep for p in open_or_requested)
                current = _policy(self._screen)
                if (
                    current.when_nothing_plays == IDLE_CLOSE
                    or (current.when_nothing_plays == IDLE_KEEP_WITH_FOCUS and idle_focus is None)
                ):
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
                should_sleep = (
                    not list_open
                    and time.monotonic() - self._idle_started_at >= DISPLAY_IDLE_SLEEP_SECONDS
                )
                if should_sleep:
                    self._sleep_locked()
                    return
            if list_open:
                # Re-render the list with the rows just refreshed above:
                # the on-screen state was built from whatever rows existed
                # when the open request was applied, which can race ahead
                # of the reconcile that populates a just-stopped source's
                # held recording.
                self._overlay_signal.set()
                return

            # Showing an idle appliance (a focus with nothing playing under
            # it) is not activity — the idle-sleep countdown above already
            # ran regardless of what follows here.
            if idle_focus is not None:
                result = fetch_target_status(
                    idle_focus, self._dial_id, timeout_seconds=DIAL_STATUS_TIMEOUT_SECONDS,
                )
                self._apply_status_to_auth(idle_focus, result)
                self._apply_status_to_repeat(idle_focus.appliance_id, result, time.monotonic())
                if result.get("status_error") == "unauthorized":
                    self._clear_focus("appliance now unauthorized")
                    idle_focus = None   # fall through to the plain idle screen below
                else:
                    master_volume = result.get("master_volume") if not result.get("status_error") else None
                    self._reporting_appliance_id = idle_focus.appliance_id
                    self._source_service_name = idle_focus.service_name
                    self._now_playing = NowPlaying(idle_focus.service_name, "", "", master_volume, playing=False)
                    self._update_eq_available()
                    self._update_dots_active(now)
                    self._update_outputs_available()
            if idle_focus is None:
                if self._focus_pending is not None:
                    # A picker-started replay hasn't reached the playing set
                    # yet, and its appliance is not rostered at all — keep
                    # showing its name over the logo rather than falling
                    # into the idle screen underneath it (the idle
                    # affordance is suppressed too: _now_playing is not
                    # None here, see _render_logo_locked/_display_idle_locked).
                    pending = self._focus_pending
                    self._now_playing = NowPlaying(pending[1], "", "", None, playing=False)
                    self._reporting_appliance_id = pending[0]
                    self._update_eq_available()
                    self._update_dots_active(now)
                    self._update_outputs_available()
                else:
                    self._now_playing = None
                    self._reporting_appliance_id = None
                    self._update_eq_available()
                    self._update_dots_active(now)
                    self._update_outputs_available()

            # Mirror the binding to whatever is reporting now: a manual
            # focus (idle or pending) always wins and the binding simply
            # tracks it; with none, the binding tracks the (possibly None)
            # reporting id directly, so it releases cleanly to nothing
            # playing/focused and the next tick's walk starts unpinned.
            self._bound_appliance_id = focus_id if focus_id is not None else self._reporting_appliance_id
            self._maybe_show_transition(previous_reporting_id)
            self._close_bound_screen_if_unfocused()
            self.show_logo()
            return

        selected_url = None
        selected_service = None
        selected_artist = ""
        selected_title = ""
        selected_album = ""
        records: dict[str, dict] = {}
        visited: set[str] = set(first_checks)  # already asked this tick
        # Monotonic time each mute-feeding status request was sent, so the
        # mute observation below can tell a stale reply from a fresh one. A
        # service never fetched this tick counts as sent at 0.0: still a poll
        # observation, never newer than anything a reply has settled.
        status_sent_at: dict[str, float] = {}

        if idle_focus is not None:
            # One pinned status fetch in place of the whole walk: an idle
            # focus has no artwork of its own, so selected_url/artist/title
            # stay empty, but its auth/repeat state is refreshed and its
            # visited entry stops the reconcile pass below re-probing it.
            status_sent_at[idle_focus.service_name] = time.monotonic()
            result = fetch_target_status(idle_focus, self._dial_id, timeout_seconds=DIAL_STATUS_TIMEOUT_SECONDS)
            visited.add(idle_focus.service_name)
            self._apply_status_to_auth(idle_focus, result)
            self._apply_status_to_repeat(idle_focus.appliance_id, result, time.monotonic())
            if result.get("status_error") == "unauthorized":
                self._clear_focus("appliance now unauthorized")
                idle_focus = None            # fall through to the ordinary walk this tick
            else:
                selected_service = idle_focus.service_name
                if not result.get("status_error"):
                    records[idle_focus.service_name] = result

        if idle_focus is None:
            # Automatic binding beneath manual focus, only when no manual
            # focus is set: the appliance the screen was already bound to
            # (see the mirror update after reporting resolution below and
            # in the empty-targets branch above) is pinned the same way a
            # manual focus is, so a newly-identified appliance elsewhere
            # cannot steal the screen. Released — and the walk below runs
            # unpinned — the moment the bound appliance stops, leaves the
            # roster, or is confirmed unauthorized; whatever the unpinned
            # walk then reports becomes the new binding at the end of the
            # tick.
            bound_target = None
            if focus_id is None:
                bid = self._bound_appliance_id
                if bid is not None:
                    bound_target = next(
                        (t for t in visible_targets if t.appliance_id == bid),
                        None,
                    )
                    if bound_target is None:
                        self._bound_appliance_id = None

            # With a focus (or, absent one, a binding), it is polled first
            # and pinned to unconditionally — the walk never falls through
            # to another appliance's artwork. With neither, today's
            # playing_since-ordered walk is unchanged.
            pin_target = focus_target if focus_target is not None else bound_target
            ordered = (
                [pin_target] + [t for t in visible_targets if t is not pin_target]
                if pin_target is not None else visible_targets
            )
            identified_without_art = None
            for target in ordered:
                is_focus = pin_target is not None and target is pin_target
                if target.auth == AUTH_UNAUTHORIZED:
                    logging.debug("dial display: skip unauthorized row %s", target.service_name)
                    continue
                if not target.dial_status:
                    logging.debug("dial display: skip unsupported target %s", target.service_name)
                    if is_focus:
                        # No status to poll, but the screen still follows the
                        # pinned target for its name/label; there is simply
                        # no artwork.
                        selected_service = target.service_name
                        break
                    continue

                checked = first_checks.get(target.service_name)
                if checked is not None:
                    status_sent_at[target.service_name], result = checked
                else:
                    status_sent_at[target.service_name] = time.monotonic()
                    result = fetch_target_status(target, self._dial_id, timeout_seconds=DIAL_STATUS_TIMEOUT_SECONDS)
                    self._apply_status_to_auth(target, result)
                    self._apply_status_to_repeat(target.appliance_id, result, time.monotonic())
                visited.add(target.service_name)
                status_error = result.get("status_error")

                if is_focus and status_error == "unauthorized":
                    # Revoked mid-tick: release whichever pin this was — a
                    # manual focus clears it, an automatic binding just
                    # releases — and fall through to the normal walk over
                    # the remaining targets in this same poll, so the
                    # screen shows the auto-pick target immediately.
                    if focus_target is not None:
                        self._clear_focus("appliance now unauthorized")
                        focus_target = None
                    else:
                        self._bound_appliance_id = None
                    pin_target = None
                    is_focus = False
                    continue

                if is_focus:
                    # The pinned target is shown regardless of whether it
                    # has identified artwork — never fall through to
                    # another appliance's artwork while a focus or a
                    # binding pins one.
                    selected_service = target.service_name
                    if not status_error:
                        records[target.service_name] = result
                        track_id = result.get("track_id")
                        if track_id and track_id.get("state") == "identified":
                            # A track identified without artwork still has
                            # its title and artist to show, over the logo.
                            selected_url = track_id.get("artwork_url") or None
                            selected_artist = track_id.get("artist", "")
                            selected_title = track_id.get("title", "")
                            selected_album = track_id.get("album", "")
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
                    selected_album = track_id.get("album", "")
                    break
                if track_id and track_id.get("state") == "identified" and identified_without_art is None:
                    # Artwork still wins the walk, but the first target
                    # identified without any is shown (title and artist
                    # over the logo) when no target has artwork at all.
                    identified_without_art = (target.service_name, track_id)
            else:
                if identified_without_art is not None:
                    selected_service, track_id = identified_without_art
                    selected_artist = track_id.get("artist", "")
                    selected_title = track_id.get("title", "")
                    selected_album = track_id.get("album", "")

        # Reporting-from target: the idle focus when one is pinned; else
        # the identified (or focused) source, else the oldest playing
        # CONTROLLABLE target (select_volume_target's fallback). Only
        # auth != unauthorized targets are offered, matching the volume
        # resolver's own filter (dial_main._build_volume_targets_fn) so the
        # poll and the worker can never disagree about who volume/mute
        # addresses.
        if idle_focus is not None:
            reporting = idle_focus
        else:
            reporting = select_volume_target(visible_targets, selected_service)
        reporting_name = reporting.service_name if reporting is not None else None
        reporting_id = reporting.appliance_id if reporting is not None else None
        self._reporting_appliance_id = reporting_id
        # Mirror the binding to whatever is reporting now — see the
        # empty-targets branch's identical mirror update above for the full
        # rationale. reporting_id can still be None here (e.g. every target
        # unauthorized this tick); the mirror releases to None the same way.
        self._bound_appliance_id = focus_id if focus_id is not None else reporting_id
        self._update_eq_available()
        self._update_dots_active(time.monotonic())
        self._update_outputs_available()
        self._maybe_show_transition(previous_reporting_id)
        self._close_bound_screen_if_unfocused()
        record = records.get(reporting_name) if reporting_name else None
        master_volume = record.get("master_volume") if record else None
        # Mute is recorded for EVERY target this poll actually walked, not
        # only the reporting one — a screened dial set to broadcast scope
        # "all" wants an up-to-date entry for every appliance it might fan a
        # push out to. Each target has its own entry in the observation
        # store (see dial_volume.observe_mute_state()), so this can never
        # clobber another target's flag; the glyph itself is unaffected — it
        # always reads back the reporting/bound service's own entry (see
        # shown_muted() at compose time), never another target's.
        # Whether a service's status carries the flag at all decides how a
        # missing value is treated (see the store's comment block).
        reports_mute = {
            t.service_name: getattr(t, "status_reports_mute", True) for t in visible_targets
        }
        for walked_name, walked_record in records.items():
            if walked_name == reporting_name:
                continue  # the explicit call just below covers this one
            observe_mute_state(
                walked_name, walked_record.get("muted"), requested_at=status_sent_at.get(walked_name, 0.0),
                status_reports_mute=reports_mute.get(walked_name, True),
            )
        observe_mute_state(
            reporting_name, record.get("muted") if record else None,
            requested_at=status_sent_at.get(reporting_name, 0.0),
            status_reports_mute=reports_mute.get(reporting_name, True),
        )
        forget_mute_states_except({t.service_name for t in visible_targets})
        if isinstance(master_volume, int) and not isinstance(master_volume, bool):
            observe_master_volume(reporting_name, master_volume)
        elif reporting_name is not None:
            observe_master_volume(reporting_name, None)

        # Assigned before _show_artwork() below so a volume press landing
        # during the artwork fetch already goes to the right target.
        self._source_service_name = selected_service
        new_now_playing = (
            NowPlaying(
                reporting_name, selected_artist, selected_title, master_volume, album=selected_album,
                # An idle focus reporting here (targets present elsewhere,
                # but the shown appliance itself has nothing playing) is not
                # playing, same as the empty-targets branch's own idle
                # focus above — see the rich/large artist-row fallback in
                # _effective_overlay_locked. Every other path that reaches
                # here (an identified or not-yet-identified playing target)
                # keeps the default True.
                playing=idle_focus is None,
            )
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
        self._refresh_selector_rows(roster, reporting_id)
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
                self._repaint_base_locked(self._current_rendered_image, idle_ok=False)
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
            self._source_artwork_url = url
            self._current_rendered_image = transformed
            self._showing = "artwork"
            self._last_error = ""
            self._last_error_at = None

        logging.info("dial display: artwork replaced (%s)", url_key)
        if was_showing == "logo":
            logging.info("dial display: showing artwork")


# The table itself is defined after the class body so its `open`/`paint`
# entries can name the class's own (unbound) methods directly.
SCREEN_POLICIES: dict[str, ScreenPolicy] = {
    "main": ScreenPolicy(
        name="main", state_attr=None, surface=None,
        open=DialDisplay._open_main_locked, paint=None, paged=False,
        inactivity_timeout_s=None, touch_extends_timeout=False,
        when_nothing_plays=IDLE_KEEP, defers_sleep=False,
        close_reveals_overlay=False, closes_on_focus_clear=False, back_to="main",
    ),
    "selector": ScreenPolicy(
        name="selector", state_attr="_selector", surface=("selector", False, False, False),
        open=DialDisplay._open_selector_locked, paint=DialDisplay._display_list_locked, paged=True,
        inactivity_timeout_s=SELECTOR_TIMEOUT_SECONDS, touch_extends_timeout=True,
        when_nothing_plays=IDLE_KEEP, defers_sleep=True,
        close_reveals_overlay=False, closes_on_focus_clear=False, back_to="main",
    ),
    "picker": ScreenPolicy(
        name="picker", state_attr="_picker", surface=("picker", False, False, False),
        open=DialDisplay._open_picker_locked, paint=DialDisplay._display_list_locked, paged=True,
        # touch activity extends every list screen's clock — picker now
        # matches the selector/outputs lists rather than keeping its own
        # older (never-extends) behaviour.
        inactivity_timeout_s=SELECTOR_TIMEOUT_SECONDS, touch_extends_timeout=True,
        when_nothing_plays=IDLE_KEEP, defers_sleep=True,
        close_reveals_overlay=False, closes_on_focus_clear=False, back_to="main",
    ),
    "info": ScreenPolicy(
        name="info", state_attr="_info", surface=("info", False, False, False),
        open=DialDisplay._open_info_locked, paint=DialDisplay._display_list_locked, paged=True,
        inactivity_timeout_s=SELECTOR_TIMEOUT_SECONDS, touch_extends_timeout=True,
        when_nothing_plays=IDLE_KEEP, defers_sleep=True,
        close_reveals_overlay=False, closes_on_focus_clear=False, back_to="main",
    ),
    # The compact info page's own drill-in — a tapped field's own
    # full-screen value, closed by a tap anywhere (LIST_BACK) or its own
    # timeout, back to the list it opened from at the same page.
    "info_value": ScreenPolicy(
        name="info_value", state_attr="_info_value", surface=("info_value", False, False, False),
        open=DialDisplay._open_info_value_locked, paint=DialDisplay._display_info_value_locked, paged=False,
        inactivity_timeout_s=SELECTOR_TIMEOUT_SECONDS, touch_extends_timeout=True,
        when_nothing_plays=IDLE_KEEP, defers_sleep=True,
        close_reveals_overlay=False, closes_on_focus_clear=False, back_to="info",
    ),
    "repeat": ScreenPolicy(
        name="repeat", state_attr="_repeat_screen", surface=("repeat", True, True, True),
        open=DialDisplay._open_repeat_locked, paint=DialDisplay._display_repeat_locked, paged=False,
        inactivity_timeout_s=None, touch_extends_timeout=False,
        when_nothing_plays=IDLE_KEEP_WITH_FOCUS, defers_sleep=False,
        close_reveals_overlay=True, closes_on_focus_clear=True, back_to="main",
        # The compact tier's own replaying layout: time/back where DOTS
        # would be, Restart/Stop in place of the enable layout's own row —
        # see GEOMETRY_REPEAT_REPLAY and touch_surface().
        replay_surface=("repeat_replay", True, True, False),
    ),
    # The EQ page: a third page, reached from the same dots as the repeat
    # screen (see cycle_pages()), rich/large only. No inactivity timeout —
    # the dots (or the poll's own closes) are its only exit, same as
    # repeat.
    "eq": ScreenPolicy(
        name="eq", state_attr="_eq", surface=("eq", True, True, True),
        open=DialDisplay._open_eq_locked, paint=DialDisplay._display_eq_locked, paged=False,
        inactivity_timeout_s=None, touch_extends_timeout=False,
        when_nothing_plays=IDLE_KEEP_WITH_FOCUS, defers_sleep=False,
        close_reveals_overlay=True, closes_on_focus_clear=True, back_to="main",
        bound_to_appliance=True,
    ),
    "outputs": ScreenPolicy(
        name="outputs", state_attr="_outputs", surface=("outputs", False, False, False),
        open=DialDisplay._open_outputs_locked, paint=DialDisplay._display_list_locked, paged=True,
        inactivity_timeout_s=SELECTOR_TIMEOUT_SECONDS, touch_extends_timeout=True,
        when_nothing_plays=IDLE_KEEP, defers_sleep=True,
        close_reveals_overlay=False, closes_on_focus_clear=True, back_to="main",
        bound_to_appliance=True,
    ),
    "output": ScreenPolicy(
        name="output", state_attr="_output_detail", surface=("output", True, False, False),
        open=DialDisplay._open_output_locked, paint=DialDisplay._display_output_locked, paged=False,
        inactivity_timeout_s=SELECTOR_TIMEOUT_SECONDS, touch_extends_timeout=True,
        when_nothing_plays=IDLE_KEEP, defers_sleep=True,
        close_reveals_overlay=False, closes_on_focus_clear=True, back_to="outputs",
        bound_to_appliance=True,
    ),
    # "Restarting...": nothing tappable; ends when the reboot takes the
    # panel down, or falls back to main after RESTARTING_TIMEOUT_SECONDS if
    # the reboot request failed.
    "restarting": ScreenPolicy(
        name="restarting", state_attr="_restarting", surface=("restarting", False, False, False),
        open=DialDisplay._open_restarting_locked, paint=DialDisplay._display_restarting_locked, paged=False,
        inactivity_timeout_s=RESTARTING_TIMEOUT_SECONDS, touch_extends_timeout=False,
        when_nothing_plays=IDLE_KEEP, defers_sleep=True,
        close_reveals_overlay=False, closes_on_focus_clear=False, back_to="main",
    ),
}


def _warning_policy_row(desc: WarningDescriptor) -> ScreenPolicy:
    """The policy row every warning page shares: opened by the warning
    manager (or a tap on the flashing idle icon, for No-WiFi), painted
    from its descriptor, closed by Dismiss, by its source clearing the
    condition, or by Restart (which replaces it). No inactivity timeout:
    it is an alarm, not a menu, and stays until acted on or cleared.
    defers_sleep=False: the page sleeps with the normal idle timer like
    the idle screen it sits over, and comes back on wake if still due."""
    return ScreenPolicy(
        name=desc.screen, state_attr="_warning_screen", surface=(desc.screen, False, False, False),
        open=functools.partial(DialDisplay._open_warning_locked, warning_id=desc.id),
        paint=DialDisplay._display_warning_locked, paged=False,
        inactivity_timeout_s=None, touch_extends_timeout=False,
        when_nothing_plays=IDLE_KEEP, defers_sleep=False,
        close_reveals_overlay=False, closes_on_focus_clear=False, back_to="main",
    )


for _desc in WARNING_DESCRIPTORS:
    SCREEN_POLICIES[_desc.screen] = _warning_policy_row(_desc)
del _desc


def _policy(name: str) -> ScreenPolicy:
    """The policy row for screen/request name *name*. An unknown name is a
    programming error and raises KeyError — no runtime path can produce one,
    since self._screen and every screen request are only ever set to a
    table key by the entry points above."""
    return SCREEN_POLICIES[name]


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
