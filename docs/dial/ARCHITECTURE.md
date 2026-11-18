# Dial software architecture

This page is for people working on the dial's code. It describes how the dial
service is split into a core that knows about appliances and a view that draws
the screen, which threads run, and the rules that keep them from tripping over
each other. For what the dial does as a product, see
[USING-THE-SCREEN.md](USING-THE-SCREEN.md); for what it says to appliances, see
[DIAL_PROTOCOL.md](DIAL_PROTOCOL.md).

## The split in one paragraph

The **core** (`dial/dial_core.py`) is the dial's model of the appliances it can
control. It reads them through one peer client each, decides which one the
dial is following, keeps the
now-playing line, artwork, outputs, EQ, repeat state, warnings, Wi-Fi link, SD
health and update progress, and publishes all of that as immutable snapshots.
The **view** (`dial/dial_display.py`) owns the panel. It subscribes to the
core, folds each snapshot into the screen that is up, composes frames and
pushes them to the SPI display. The view holds no appliance state of its own,
and the core imports nothing that draws. Both large classes are sectioned: each
module's docstring lists its sections, and each section names the fields it
owns and the threads that run it. An HD dial adds a second view, a web
page served by the dial, described in [The HD page is a second
view](#the-hd-page-is-a-second-view).

## Modules

Every module in `dial/` is listed, in groups.

**Core and model**

| Module | Responsibility |
|---|---|
| `dial_core.py` | `DialCore`: the model, the core thread that folds the peer clients' snapshots, the public action API, snapshots, subscriptions and the effects queue. Seven sections, listed in its docstring. |
| `dial_core_model.py` | The core's mutable record: `PublishedState` (exactly the snapshot's fields) and `CoreState` (what stays inside the core), and `snapshot_of`. |
| `dial_core_state.py` | The snapshot dataclasses and the pure decisions made over them (picker and selector rows, display order, start failure, PIN windows). No I/O, no threads, no locks, no clock reads. |
| `dial_core_focus.py` | The focus rule and the walk: which appliance the dial follows and reports volume from, decided from state. Pure. |
| `dial_core_requests.py` | What the dial asks of an appliance: the intent builders, the reply fold and settle rule, the request lane thread, and the request checks shared by the controls and the HD page's intents. |
| `dial_core_effects.py` | The effect and outcome types the core queues for the one view. |
| `dial_core_artwork.py` | `ArtworkFollower`: fetches the artwork the fold names on a short-lived thread. |
| `dial_artwork.py` | The artwork download that thread runs, with its size and time limits and a rate-limited failure log. |
| `dial_peer_view.py` | The pure mapping from an appliance's peer snapshot to the dial's own state types; its first group mirrors the browser's shared derivations. |
| `dial_repeat_store.py` | `RepeatRecord`, an appliance's repeat state at a moment. Pure. |
| `dial_eq_model.py` | The equaliser as the dial addresses it: the six bands, the bass and treble controls and their limits. |

**Warnings**

| Module | Responsibility |
|---|---|
| `dial_warning_text.py` | The warning table and its fixed strings (No-WiFi, SD health, update cards) and the builder for appliance-supplied warnings. Pure data, no drawing. |
| `dial_warnings.py` | The warning manager: registration, which status is due, and which warnings are active. A warning is told from a status (an update running or finished), which is a screen of its own. Nothing is stored: a warning counts for as long as its cause is there. |
| `dial_appliance_warnings.py` | What an appliance may say about itself (validated into closed sets) and the protocol-mismatch warnings the dial raises on its own. |
| `dial_warning_bell.py` | What a warning bell holds: the dial's own warnings, one appliance's, or the whole set, worst first. Pure. |
| `dial_warning_page.py` | The small screen's warnings card: which entry of a bell is on show, what Next does, and the card that the buttons resolve against. It also builds the card a status screen shows. Pure. |

**The SPI view**

| Module | Responsibility |
|---|---|
| `dial_display.py` | `DialDisplay`: screen policy, the repaint thread and its timers, the snapshot fold, painters, the panel's backend and transmit, sleep and wake, the pressed channel and the touch surface. Nine sections, listed in its docstring. |
| `dial_display_state.py` | The display's own screen records (one per secondary screen) and the pure maps from core rows to list rows and hints. |
| `dial_display_controls.py` | `ControlsReveal`: the controls windows and the reveal slide. |
| `dial_display_repeat_line.py` | `RepeatLine`: the replaying counter and the replay timer line. |
| `dial_display_compositor.py` | The compositor: the frame pipeline and frame builders, and `compose()`. |
| `dial_display_views.py` | What the display hands the compositor: one view state per screen and the frame descriptor. PIL-free. |
| `dial_display_render.py` | The screen renderers: bands, header, footers, card, bodies, pages. |
| `dial_display_draw.py` | Drawing primitives: fonts, text fitting, halos, labels and glyph tiles. |
| `dial_display_reveal.py` | The artwork-tap reveal frames. |
| `dial_display_windows.py` | Change-region planning: which rectangles to write for a new frame. |
| `dial_display_image.py` | Image policy: logo, artwork decode and fit, resampling, default panel size. |
| `dial_display_palette.py` | Every colour the panel paints with. Pure data. |
| `dial_display_profiles.py` | The panel profile table. Pure data. |
| `dial_display_backend.py` | The output-only backend protocol, the no-op backend and the backend factory. |
| `dial_display_adafruit.py` | The Adafruit SPI backend. |
| `dial_spi_bus.py` | The process-lifetime owner of the SPI buses the display and the resistive touch share. |

**Touch**

| Module | Responsibility |
|---|---|
| `dial_touch.py` | `TouchStateMachine`: the touch session policy. Pure, no thread. |
| `dial_touch_source.py` | `TouchEventSource`: the thread that reads the controller and drives the filter and the state machine. |
| `dial_touch_filter.py` | Sample filtering and the press lifecycle. Pure. |
| `dial_touch_layout.py` | Touch-zone geometry and the layout builders. Pure. |
| `dial_layout_metrics.py` | Physical scaling: the scale rule and `LayoutMetrics`. |
| `dial_touch_surfaces.py` | The surface names and the five-field surface state the display reports. |
| `dial_touch_wiring.py` | `TouchWiring`: what a touch does at the dial (reveal, wake, zone taps, volume and mute). The touch source calls core actions through the view's taps. |
| `dial_touch_drivers.py`, `dial_touch_controllers.py` | The controller drivers (hardware imported only on open) and the controller table. |

**HD page**

| Module | Responsibility |
|---|---|
| `dial_hd_server.py` | `HdServer`: the HD page's loopback web server, the request checks, the state body, the event stream route and the settings, info, action, intent and panel routes. |
| `dial_hd_static.py` | The page's files and pictures from one fixed table, with conditional responses. |
| `dial_hd_session.py` | The development listener and its PIN-login sessions. |
| `dial_hd_backdrop.py` | `BackdropStore`: the page's blurred backdrops, rendered on first request on the handler thread and kept in memory, one per artwork key and one for the logo. |
| `dial_hd_events.py` | `ChangeHub`: turns the core's change signals into a sequence number, builds each state body once per change and feeds the event stream. |
| `dial_hd_state.py` | `build_parts()`: the pure function that turns a core snapshot into the page's two state parts, `dial` and `focused`. |
| `dial_hd_actions.py` | The page's actions as one table onto core methods, with the argument checks: focus, volume set and step, mute, putting away a start failure, closing a status card, restart, shutdown and presence. |
| `dial/hd/hd-bell.js` | The HD page's warning bells: the dial's own in the APPLIANCES header, the card that pages through a bell's warnings, and the "Dial is healthy" card. It sits beside the page's other modules (`hd-paint.js`, `hd-actions.js` and the rest). |
| `dial_hd_panel.py` | `HdPanel`: the HD dial's sleep, wake and brightness, and the sysfs backlight writes. |
| `dial_hd_ddc.py` | The HDMI panel's backlight over DDC/CI through i2c-dev: the packet codec, panel detection, and `DdcBacklight`, which has the same interface as the sysfs backlight and applies levels on its own worker thread. |

**Servers and process**

| Module | Responsibility |
|---|---|
| `dial_main.py` | Entry point: builds the core first, then the display, workers, inputs and servers in named startup steps. Holds the headless stand-in and the volume and mute target resolvers. |
| `dial_http_server.py` | The management API the appliance uses (port 7842). |
| `dial_screen_settings.py` | `ScreenSettingsService`: the screen settings path both servers share. |
| `dial_http_common.py` | The request mechanics both servers share (body cap, read, JSON send). |
| `dial_pin_guard.py` | The PIN rule for both servers: one rate limiter and one constant-time compare. |
| `dial_recovery.py` | PIN recovery: the request file, the running marker, the arming rule and `RecoveryWindow`. |
| `dial_admin.py` | The one way the dial runs the privileged admin helper. |
| `dial_control.py`, `dial_control_protocol.py`, `autostream_dial_control.py` | The local control socket, its shared constants and the operator CLI. |
| `dial_config.py` | Configuration loading, validation and saving from one field table. |

**Workers and platform**

| Module | Responsibility |
|---|---|
| `dial_volume.py` | The volume and mute fan-out worker and the volume and mute observation stores. |
| `dial_mdns.py` | The sighted appliances as targets for the volume control and the control socket. |
| `dial_network.py` | The dial's own Wi-Fi link view and the power requests, on the network worker. |
| `dial_sdhealth.py` | The dial's own SD card health view. |
| `dial_update_watch.py` | The software update in progress, read from the update result file. |
| `dial_info.py` | The info page's rows, gathered on a short thread. |
| `dial_led.py` | The activity LED. |
| `dial_values.py` | Small pure helpers: integer checks, clamps, small-file, env-file and JSON reads. |

## Threads

| Thread | Owner | What it does |
|---|---|---|
| `dial-core` | core | Folds the peer clients' snapshots into one publish when a client signals a change (a fold asked for within 0.4 s of the last one's end waits for that gap) and at the fold interval. Once a second it also does housekeeping: the update watch, expiring warnings, and the replay position read while an appliance replays. |
| `dial-display-repaint` | view | Waits for a core snapshot or an overlay signal, folds the newest snapshot into the screen and paints. This is the only thread that composes and pushes frames. |
| `touch-event-source` | touch | Reads the touch controller and turns touches into taps. Taps call core actions (never while holding the view lock) and the view's own screen changes. |
| one per appliance | peer clients | Each holds one appliance's state from its change stream and signals the core when it moves. |
| `requests`, `volume-worker`, `network-worker` | workers | Send the screens' requests and the knob's volume and mute through the peer clients, and read the Wi-Fi link. Replies are folded by the core, which queues what they mean for the screen. |
| `dial-artwork` | core | Short-lived: downloads the focused appliance's artwork when its URL changes. |
| `dial-info` | view | Short-lived: gathers the info page's rows when the page opens. |
| mDNS browser | peer registry | Keeps the list of sighted appliances that the peer pool holds a client for. |
| HTTP server threads | control API | Serve the dial's own API. They call core actions, not the view's internals. |
| `dial-control` | control socket | Serves the local control socket. |
| `dial-reboot`, `dial-shutdown` | network worker | Short-lived: carry out a power request. |
| `dial-sdmon-probe` | management server | Short-lived: the management server's SD health probe. |
| `dial-hd`, plus one thread per connection | HD server | Accepts connections on the loopback address and serves each on a thread of its own. Every socket has a short timeout, so a stalled client holds only its own thread. |
| `dial-hd-intent` | HD server | Short-lived: each page intent runs on a thread of its own, which the handler waits on for a bounded time (the answer timeout). |
| `dial-hd-dev`, plus one thread per connection | HD server | The development listener, present only while it is switched on. |
| `hd-events` | change hub | Turns core change signals into sequence numbers. Each event stream client also has its handler thread. |
| `hd-panel` | HD panel | Runs the idle clock and the sleep and wake decisions, and writes the backlight. |
| `hd-ddc` | HD panel | Present only with a DDC backlight. Applies the newest wanted level to the panel (power on or off, brightness); the slow bus work happens here, never on a caller. |

## The interface between core and view

**Snapshots.** `core.snapshot()` returns the newest `CoreSnapshot` with a plain
reference read; no lock is taken. Every change goes through one `_publish`
step that mutates state under the core lock, builds the next snapshot with an
incremented sequence number, and wakes waiters and subscribers. A snapshot
that ends a fold carries a new `ticks` count and a `TickContext` saying
what the fold started from. That is how a view tells a finished tick from the
writes made in the middle of one, and it reacts to the finished tick only.

**Actions.** Everything that changes appliance state on the dial's behalf is a
core method: setting focus, setting an output, setting EQ, starting and
stopping replay, arming repeat, toggling mute, requesting a fold, and so on. Actions return an `ActionResult` and never touch the screen.

**Notifications.** `core.subscribe(callback)` registers a zero-argument
callback, and `core.wait_for_change(seen_seq, timeout)` blocks until something
newer than `seen_seq` exists. Several publishes before a consumer runs collapse
into one wake, and the consumer reads the newest snapshot, so a consumer that
tracks the last `seq` it saw never misses the latest state (it may skip
intermediate ones).

**Appliance changes.** Each sighted appliance is held by a peer client that
keeps its state from the appliance's change stream. A client that moves only
signals the core thread, which reads every moved client's snapshot, maps it
with `dial_peer_view` and publishes once, however many moved. The speakers
list, the equaliser, warnings and the repeat record are always held, so
nothing is asked for when a screen opens. The replay position is the one
value read on its own: every 5 s while an appliance replays, and once after an
accepted seek or stop.

**The effects queue.** Some things the core learns are not state but an event
the screen should react to once: a warning source began or cleared an incident,
the update reached its restart phase, a repeat result arrived. These are queued
as `SourceEffects` and `RepeatEffect` entries and read with `take_effects()`.
The queue is a channel for one view, not a notification mechanism. Taking is
atomic, so two takers would split the effects between them. A second consumer
should use `subscribe` or `wait_for_change` and read the snapshot. With no
view attached, only the newest `EFFECTS_BACKLOG_MAX` entries are kept.

## The HD page is a second view

An HD dial draws nothing itself. The dial serves a web page, and a kiosk
browser (WPE WebKit, started by `cog` straight on the display) on the same
board shows it (see [HD-DIAL.md](HD-DIAL.md)). That page is
a second view of the core, alongside the SPI view. It reads snapshots through a
loopback API and calls core actions. It never takes effects, and it holds no
appliance state of its own beyond a short-lived optimistic value for a control
being dragged.

**Server.** `HdServer` listens on `127.0.0.1:7843` (never through nginx and
never on a LAN address). Every request is checked before routing: the `Host`
header must name the loopback address, an `Origin` header must match it, the
request line and body are capped, and a POST must carry a custom header that a
cross-site form cannot set. No cross-origin headers are ever sent, and the page
is served under a content security policy that forbids inline script.

**State.** `build_parts()` is a pure function from a `CoreSnapshot` (plus the
dial's panel and settings, the warning descriptors and the clock readings it
is handed) to two plain dictionaries: `dial`, what the dial itself knows
(roster, focus, warnings, panel, artwork and the like), and `focused`, the
focused appliance's own parts exactly as the core folded them in. It does no
I/O, takes no lock and reads no clock, so the same input is always the same
output, and `dial` carries no reading that moves with the clock, so it changes
only when something in it does. It carries only what the page draws, with
artwork as a local key and URL rather than the appliance's address. The
deadlines in `dial` are absolute readings on the core's clock, which the body
carries as `time`, so the page estimates the dial's clock from `time` and the
time since the body arrived and never compares a deadline with its own wall
clock. The blurred backdrop behind the artwork is rendered the
first time the page asks for it. The render runs on that request's own thread
under the store's lock and nothing else.

**Change hub.** The core's subscriber callback, the config listener and the
panel all call `ChangeHub.publish()`, which only records the request and wakes
the hub thread, so a publisher is never delayed. Requests that arrive before the
hub thread runs become one sequence step. At each step, and only while a page
is connected, the hub builds the two state parts once from one core snapshot
and compares each with the step before, so any number of clients cost one
serialisation per change, and a change event carries only the parts that moved.
The event stream (server-sent events) gives each client its own handler thread,
and a client that stops reading is dropped after one write timeout, leaving the
core, the hub and the other clients unaffected. With no page open the hub builds
nothing and asks for neither outputs nor EQ.

**Actions and intents.** A POST to an action route is checked against the
action's argument spec (only the named fields, each of its type and range) and
then maps to one core method. Results map to HTTP status codes in the server, not
in the action table. Two actions mean a person at the dial's own screen,
confirming presence and shutting the dial down, and are refused with a 403 on
the development listener. A change to an appliance goes to the intents route
instead: the body names the appliance and the arguments, the core sends it on
through the peer library from a short thread of its own, which the handler waits
on for a bounded time, and the answer is the appliance's own reply. Screen settings go through the management server's own
config path, and sleep, wake and activity go to the panel.

**Panel.** `HdPanel` keeps the screen awake or asleep. Asleep, the page draws a
black shield and the first touch only wakes; where a sysfs backlight exists, or
an HDMI panel answers DDC/CI, the panel also drives that backlight (the DDC one
takes the wanted level and applies it on its own thread, keeping only the
latest, so a caller never waits on the bus). Asleep is level 0: the DDC
backlight dims the panel to its minimum and leaves it powered, and only powers
it off when the dial's `panel_power_off` setting is on, read on its worker each
time a level is applied so a change needs no restart. The idle clock starts when nothing is playing and
restarts on activity. Playback starting, or an update card, wakes
the panel; a warning, which only changes its bell, does not. The panel
never calls into the core.

**Development listener.** When the dial's `hd_dev_access` setting is on (and a
PIN is set), a second listener serves the same page and API on the LAN behind
a PIN login and an in-memory session. It is the same dispatcher, so it cannot
drift from the loopback one. PIN guessing shares the management server's
per-address limiter. It follows the config, so it opens and closes without a
restart and drops its sessions when the PIN changes.

**Trust boundary.** The loopback listener trusts every local process. The two
actions only it may take (`presence` and `dial_shutdown`) are argument-free, and
the privileged command behind the second takes no arguments either, so nothing a
caller sends reaches it. A session token for the kiosk was considered and not
adopted: the dial is a single-purpose appliance.

**Locking and threads.** The HD code follows the locking rules below. The core's
snapshot is a lock-free reference read, so a request handler never holds a core
or view lock while it reads or writes a socket. The hub's one condition and the
panel's own small lock are never held while calling out. The DDC backlight's
one condition guards only its wanted level and is never held across bus I/O;
the `panel_power_off` reader runs on its worker, outside that condition.

## Locking rules

1. The core lock is held only for in-memory work. It is never held across
   network or file I/O, a frame push or a subscriber callback.
2. The core lock and the view's locks are never nested, in either order. The
   view calls core actions outside its own lock, and the repaint thread reads
   `core.snapshot()` without a lock.
3. Subscriber callbacks run inline on the publishing thread and must only
   signal (`Event.set`, `queue.put_nowait`, `Condition.notify`). A callback
   that blocks delays that one publisher and nothing else.
4. Callbacks that the core makes into the view while folding (the EQ veto and
   the idle hold below) are plain lock-free reads, because they run on the
   core thread.

## The idle hold

When a fold finds nothing playing, the core normally clears what it reports as
now playing and the idle state that follows from it. The view registers a
predicate with `core.set_idle_hold` that can tell the core to leave things as
they are for that tick. It returns true when the panel is asleep or about to
sleep on this tick's idle clock, or when a screen is up that the view will not
redraw under (an open list, for example) and that its own timeout will close.

It exists because the view and the core each see only half of the question.
Only the core knows nothing is playing; only the view knows a list is open or
that sleep is due. Without the hold, the core would change what is reported
under a screen the user is looking at, and the view would then repaint or wake
for a change it had meant to ignore. The predicate is the same decision the
view acts on at the end of the tick, with a cleared manual focus treated as
already closed, so the two sides cannot disagree.

## Headless mode

If the display stack will not load (an incomplete install of Pillow, for
example), `dial_main.py` substitutes a headless stand-in for the display. There
is no screen, but the core is built, started and stopped by `dial_main.py` in
the same way, so the appliances are still held. That keeps volume and mute
following the appliance the dial reports from, and the warning
and update watches running. Volume control never depends on the display.

## Startup and shutdown order

`dial_main.py` builds the core first. Building it does no I/O and starts no
thread. The display, workers and inputs are then handed the core. The core
thread starts after the boot splash is on the panel and is stopped in the
`finally` block when the service exits.

## Where to add things

New appliance-derived state goes in the core and its snapshot, with the
decision logic as a pure function beside its kind: focus in
`dial_core_focus.py`, request checks in `dial_core_requests.py`, everything else
in `dial_core_state.py`. New screen
behaviour goes in the view and reads the snapshot. If a view needs to react to
a one-off event rather than a state change, add an effect rather than a second
snapshot field the view has to diff.
