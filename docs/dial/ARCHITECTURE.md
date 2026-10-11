# Dial software architecture

This page is for people working on the dial's code. It describes how the dial
service is split into a core that knows about appliances and a view that draws
the screen, which threads run, and the rules that keep them from tripping over
each other. For what the dial does as a product, see
[USING-THE-SCREEN.md](USING-THE-SCREEN.md); for what it says to appliances, see
[DIAL_PROTOCOL.md](DIAL_PROTOCOL.md).

## The split in one paragraph

The **core** (`dial/dial_core.py`) is the dial's model of the appliances it can
control. It polls them, decides which one the dial is following, keeps the
now-playing line, artwork, outputs, EQ, repeat state, warnings, Wi-Fi link, SD
health and update progress, and publishes all of that as immutable snapshots.
The **view** (`dial/dial_display.py`) owns the panel. It subscribes to the
core, folds each snapshot into the screen that is up, composes frames and
pushes them to the SPI display. The view holds no appliance state of its own,
and the core imports nothing that draws. An HD dial adds a second view, a web
page served by the dial, described in [The HD page is a second
view](#the-hd-page-is-a-second-view).

## Modules

| Module | Responsibility |
|---|---|
| `dial_core.py` | `DialCore`: the model, the poll thread, the public action API, snapshots, subscriptions and the effects queue. |
| `dial_core_state.py` | The snapshot dataclasses and the pure decisions made over them (focus resolution, walk order, volume target choice, picker rows, warning attribution). No I/O, no threads, no locks, no clock reads. |
| `dial_core_poll.py` | The poll tick's I/O steps as plain functions: status fetches, the reconcile fan-out, the artwork download, and feeding the auth map, repeat store and mute/volume observations. The network calls are injectable so a test can stub them. |
| `dial_warning_text.py` | The warning table and its fixed strings (No-WiFi, SD health, update cards) and the builder for appliance-supplied warnings. Pure data, no drawing. |
| `dial_warnings.py` | The warning manager: registration, snooze persistence, severity ordering. |
| `dial_display.py` | `DialDisplay`: the SPI view. Screen policy, the repaint thread, composing and pushing frames, panel sleep and wake, the artwork reveal slide, the pressed channel and the touch surface. |
| `dial_display_compositor.py`, `dial_display_image.py`, `dial_display_profiles.py`, `dial_display_adafruit.py` | Drawing, image policy, panel profiles and the hardware backend. |
| `dial_touch*.py` | Touch drivers, filtering and the zone layout. The touch source calls core actions through the view's taps. |
| `dial_capabilities.py` | What an appliance can do for the dial. A small registry of what appliances' capabilities replies said, and `appliance_capabilities()`, the one place every caller asks. An appliance of a generation with a capabilities endpoint is read from its reply once that has landed; every other appliance, and one whose reply has not arrived, is read from its mDNS flags. Pure data and one leaf lock. |
| `dial_appliance_fetch.py` | The reader for what an appliance says about itself (its capabilities and its warnings). One worker thread, queue and HTTP client of its own, so a slow appliance delays nothing else. Results go back to the core. |
| `dial_hd_server.py` | `HdServer`: the HD page's loopback web server, the page's static files, the state body, the held artwork, the event stream route and the settings, info, action and panel routes. Also the optional development listener. |
| `dial_hd_backdrop.py` | `BackdropStore`: the page's blurred backdrops, rendered on first request on the handler thread and kept in memory, one per artwork key and one for the logo. |
| `dial_hd_events.py` | `ChangeHub`: turns the core's change signals into a sequence number, builds each state body once per change and feeds the event stream. |
| `dial_hd_state.py` | `build_state()`: the pure function that turns a core snapshot into the page's state body. |
| `dial_hd_actions.py` | The page's actions as one table onto core methods, with the argument checks. |
| `dial_hd_panel.py` | `HdPanel`: the HD dial's sleep, wake and brightness, and the sysfs backlight writes. |
| `dial_hd_ddc.py` | The HDMI panel's backlight over DDC/CI through i2c-dev: the packet codec, panel detection, and `DdcBacklight`, which has the same interface as the sysfs backlight and applies levels on its own worker thread. |
| `dial_main.py` | Entry point. Builds the core first, then the display, workers, inputs and HTTP server. Also holds the headless stand-in for the display. |

## Threads

| Thread | Owner | What it does |
|---|---|---|
| `dial-core` | core | Polls appliances every poll interval, or sooner when asked or when an appliance pushes a change (a poll asked for within 0.4 s of the last one's end waits for that gap). Once a second it also does housekeeping: the update watch, expiring warnings, the snooze write, and refreshing watched outputs and EQ. |
| `dial-display-repaint` | view | Waits for a core snapshot or an overlay signal, folds the newest snapshot into the screen and paints. This is the only thread that composes and pushes frames. |
| `touch-event-source` | touch | Reads the touch controller and turns touches into taps. Taps call core actions (never while holding the view lock) and the view's own screen changes. |
| `volume-worker`, `eq-worker`, `outputs-worker`, `repeat-worker`, `network-worker` | workers | Do the slow appliance and system calls. Their results are handed back to the core, which folds them into state and queues what they mean for the screen. |
| mDNS browsers | roster | Keep the list of appliances and which are playing. The core reads them each tick. |
| HTTP server threads | control API | Serve the dial's own API. They call core actions, not the view's internals. |
| `appliance-fetch-worker` | appliance fetch | Reads appliances' capabilities and warnings, one at a time. Its results are handed to the core. |
| `dial-hd`, plus one thread per connection | HD server | Accepts connections on the loopback address and serves each on a thread of its own. Every socket has a short timeout, so a stalled client holds only its own thread. |
| `dial-hd-dev`, plus one thread per connection | HD server | The development listener, present only while it is switched on. |
| `hd-events` | change hub | Turns core change signals into sequence numbers, and while a page is connected keeps the followed appliance's outputs and EQ fetched. Each event stream client also has its handler thread. |
| `hd-panel` | HD panel | Runs the idle clock and the sleep and wake decisions, and writes the backlight. |
| `hd-ddc` | HD panel | Present only with a DDC backlight. Applies the newest wanted level to the panel (power on or off, brightness); the slow bus work happens here, never on a caller. |

## The interface between core and view

**Snapshots.** `core.snapshot()` returns the newest `CoreSnapshot` with a plain
reference read; no lock is taken. Every change goes through one `_publish`
step that mutates state under the core lock, builds the next snapshot with an
incremented sequence number, and wakes waiters and subscribers. A snapshot
that ends a poll tick carries a new `ticks` count and a `TickContext` saying
what the tick started from. That is how a view tells a finished tick from the
writes made in the middle of one, and it reacts to the finished tick only.

**Actions.** Everything that changes appliance state on the dial's behalf is a
core method: setting focus, setting an output, setting EQ, starting and
stopping replay, arming repeat, toggling mute, requesting a poll or reconcile,
and so on. Actions return an `ActionResult` and never touch the screen.

**Notifications.** `core.subscribe(callback)` registers a zero-argument
callback, and `core.wait_for_change(seen_seq, timeout)` blocks until something
newer than `seen_seq` exists. Several publishes before a consumer runs collapse
into one wake, and the consumer reads the newest snapshot, so a consumer that
tracks the last `seq` it saw never misses the latest state (it may skip
intermediate ones).

**Pushes from appliances.** The dial's HTTP server accepts three advisory
pushes from an appliance: `/auth-changed`, `/warnings-changed` and
`/state-changed`. Each is checked against the appliance's current sighting,
only queues the appliance id (a state push also carries what it said changed)
and wakes the core thread; nothing is fetched on the HTTP thread. The rate
limiter on the state route decides only whether the core is woken: a state
push from the appliance's sighted address always has its kinds queued, so
hints a busy sender delivers close together are not lost, and the core is
woken anyway when no tick is already due to take them. The core's
reaction is a poll, so the push brings the next status request forward and the
poll is still the truth. A state push also asks again for the speakers list
or the equaliser when the dial is watching that appliance and the kinds the
push names could have changed it (a push naming nothing asks for both); the
speakers list is left alone while this dial's own speaker request to that
appliance is still pending, and a kind the core does not recognise asks for
nothing beyond the poll. A poll woken within 0.4 s of the last one's end waits
for the gap, and hints that arrive meanwhile join that poll, so a burst of
pushes costs one poll per gap; the regular poll is not delayed. A push that is
lost or never sent costs nothing but the wait for the regular poll (and, for
the speakers list, its own periodic refresh).

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

**State.** `build_state()` is a pure function from a `CoreSnapshot` (plus the
dial's panel and settings, the warning descriptors and the clock readings it
is handed) to a plain dictionary. It does no I/O, takes no lock and reads no
clock, so the same input is always the same output. The body carries a version
and only grows: fields are added, never renamed or removed. It carries only
what the page draws, with artwork as a local key and URL rather than the
appliance's address. It also carries the core's clock reading when it was
built, at most about a second before it is sent (`now`), and the deadlines in it are absolute readings on that clock, so
the page estimates the dial's clock from `now` and the time since the body
arrived and never compares a deadline with its own wall clock. The blurred backdrop behind the artwork is rendered the
first time the page asks for it. The render runs on that request's own thread
under the store's lock and nothing else.

**Change hub.** The core's subscriber callback, the config listener and the
panel all call `ChangeHub.publish()`, which only records the request and wakes
the hub thread, so a publisher is never delayed. Requests that arrive before the
hub thread runs become one sequence step. The state body for a sequence is
built lazily by the first client that asks and cached, so any number of
clients cost one serialisation per change. A cached body is served for about
a second; one asked for after that is built again under the same sequence
(nobody is woken), so the clock reading in what a client receives is current. The event stream (server-sent
events) gives each client its own handler thread, and a client that stops
reading is dropped after one write timeout, leaving the core, the hub and the
other clients unaffected. With no page open the hub asks for neither outputs
nor EQ.

**Actions.** A POST to an action route is checked against the action's
argument spec (only the named fields, each of its type and range) and then maps
to one core method. Results map to HTTP status codes in the server, not in the
action table. Two actions mean a person at the dial's own screen, confirming
presence and shutting the dial down, and are refused with a 403 on the
development listener. Screen settings go through the management server's own config
path, and sleep, wake and activity go to the panel.

**Panel.** `HdPanel` keeps the screen awake or asleep. Asleep, the page draws a
black shield and the first touch only wakes; where a sysfs backlight exists, or
an HDMI panel answers DDC/CI, the panel also drives that backlight (the DDC one
takes the wanted level and applies it on its own thread, keeping only the
latest, so a caller never waits on the bus). Asleep is level 0: the DDC
backlight dims the panel to its minimum and leaves it powered, and only powers
it off when the dial's `panel_power_off` setting is on, read on its worker each
time a level is applied so a change needs no restart. The idle clock starts when nothing is playing and
restarts on activity. Playback starting, or a warning that interrupts, wakes
the panel; an appliance warning, which never interrupts, does not. The panel
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
   network or file I/O, a frame push, a subscriber callback, or a call into
   `auth_map`.
2. The core lock and the view's locks are never nested, in either order. The
   view calls core actions outside its own lock, and the repaint thread reads
   `core.snapshot()` without a lock.
3. Subscriber callbacks run inline on the publishing thread and must only
   signal (`Event.set`, `queue.put_nowait`, `Condition.notify`). A callback
   that blocks delays that one publisher and nothing else.
4. Callbacks that the core makes into the view while polling (the EQ veto and
   the idle hold below) are plain lock-free reads, because they run on the
   core thread.

## The idle hold

When a poll finds nothing playing, the core normally clears what it reports as
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
the same way, so the poll still runs. That keeps authorisation probes going,
volume and mute following the appliance the dial reports from, and the warning
and update watches running. Volume control never depends on the display.

## Startup and shutdown order

`dial_main.py` builds the core first. Building it does no I/O and starts no
thread. The display, workers and inputs are then handed the core. The core
thread starts after the boot splash is on the panel and is stopped in the
`finally` block when the service exits.

## Where to add things

New appliance-derived state goes in the core and its snapshot, with the
decision logic in `dial_core_state.py` as a pure function. New screen
behaviour goes in the view and reads the snapshot. If a view needs to react to
a one-off event rather than a state change, add an effect rather than a second
snapshot field the view has to diff.
