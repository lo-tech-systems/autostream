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
and the core imports nothing that draws.

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
| `dial_main.py` | Entry point. Builds the core first, then the display, workers, inputs and HTTP server. Also holds the headless stand-in for the display. |

## Threads

| Thread | Owner | What it does |
|---|---|---|
| `dial-core` | core | Polls appliances every poll interval, or sooner when asked. Once a second it also does housekeeping: the update watch, expiring warnings, the snooze write, and refreshing watched outputs and EQ. |
| `dial-display-repaint` | view | Waits for a core snapshot or an overlay signal, folds the newest snapshot into the screen and paints. This is the only thread that composes and pushes frames. |
| `touch-event-source` | touch | Reads the touch controller and turns touches into taps. Taps call core actions (never while holding the view lock) and the view's own screen changes. |
| `volume-worker`, `eq-worker`, `outputs-worker`, `repeat-worker`, `network-worker` | workers | Do the slow appliance and system calls. Their results are handed back to the core, which folds them into state and queues what they mean for the screen. |
| mDNS browsers | roster | Keep the list of appliances and which are playing. The core reads them each tick. |
| HTTP server threads | control API | Serve the dial's own API. They call core actions, not the view's internals. |

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

**The effects queue.** Some things the core learns are not state but an event
the screen should react to once: a warning source began or cleared an incident,
the update reached its restart phase, a repeat result arrived. These are queued
as `SourceEffects` and `RepeatEffect` entries and read with `take_effects()`.
The queue is a channel for one view, not a notification mechanism. Taking is
atomic, so two takers would split the effects between them. A second consumer
should use `subscribe` or `wait_for_change` and read the snapshot. With no
view attached, only the newest `EFFECTS_BACKLOG_MAX` entries are kept.

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
