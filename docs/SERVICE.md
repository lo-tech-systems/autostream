# Service

The Service page tracks turntable maintenance: stylus wear, drive
belt life, and main bearing oil life. It has no PIN and is reachable from the
bottom navigation on any autostream page.

The page is always available, but its items only do anything for inputs set
to **Turntable** in [Setup](SETUP-INPUTS.md). For an input left as Line In (or
a disabled Input 2), every card reads "Not a turntable" / "Disabled" and opens
to a message telling you to set that input to Turntable in Setup first.

## Layout

The page is a two-pane list/detail view, one row per input:

- Input 1 Stylus Tracking, Input 1 Belt Tracking, Input 1 Bearing Oil Tracking
- Input 2 Stylus Tracking, Input 2 Belt Tracking, Input 2 Bearing Oil Tracking (if Input 2 is enabled)

Tapping a row opens its detail panel; **Back** returns to the list.

## What is tracked

| Item | Legend in detail panel | Dimensions |
|------|------------------------|------------|
| Stylus | "Input N Stylus Wear Tracking" | Playback hours only |
| Drive Belt | "Drive Belt" | Playback hours, elapsed time, or both |
| Main Bearing Oil | "Main Bearing Oil" | Playback hours, elapsed time, or both |

Each dimension has its own dropdown and can be turned off independently by
selecting the "Don't track" option. For belt, the off option reads "Don't
track / Direct Drive" (a direct-drive turntable has no belt to track).

## Life values and presets

Each dimension is a fixed dropdown of presets - there is no free-text entry
in the Service page:

| Dropdown | Options |
|----------|---------|
| Stylus Life | Don't track usage, 100, 250, 500, 750, 1000 hours |
| Belt - Hours Life | Don't track / Direct Drive, 1000, 2000, 3000 hours |
| Belt - Time Life | Don't track / Direct Drive, 1-5 years |
| Bearing - Hours Life | Don't track, 200, 500, 1000, 2000 hours |
| Bearing - Time Life | Don't track, 1-5 years |

Changing a dropdown saves immediately (no Save button) and the panel's live
figures update right away.

## During playback

While a turntable input is playing, its playback time accumulates against
every dimension that is switched on for that input, so the Service page
reflects the current session as it happens - you don't need to stop playback
to see updated figures.

Two clocks run independently:

- **Total playback** covers all audible output from the input, including
  replaying a captured side from the repeat buffer.
- **Wear tracking** (stylus, belt, bearing hours) only accrues while the
  turntable is actually turning and being captured. Repeat-buffer playback of
  a previously captured recording does not add stylus, belt, or bearing
  hours, because the stylus and mechanism are not in use during replay.

## Reading a detail panel

Each active dimension shows:

- A **Life Remaining** / **Time Remaining** bar and percentage.
- **Used** (hours played against the preset) or **Age** (elapsed time since
  last service), plus **Remaining**.
- For time tracking, a **Due** date (last service date plus the selected
  number of years).
- **Last changed** (stylus) or **Last service** (belt/bearing) - the date the
  counter was last reset, or "Never".

## Warning banners and indicators

Each item has two thresholds ahead of the limit you set:

| Dimension | Warning appears when remaining is under |
|-----------|------------------------------------------|
| Stylus hours | 10 hours |
| Belt/bearing hours | 50 hours |
| Belt/bearing elapsed time | 30 days |

Below the threshold, the card and detail panel turn amber ("due soon"); once
the limit is reached, they turn red ("due now"/"Overdue").

When any tracked item on any input is in warning or overdue:

- A banner appears near the top of the Home page (one line per item -
  stylus, belt, bearing - naming the input when there's more than one
  affected). Tapping a banner opens the Service page.
- The **Service** tab in the bottom navigation is highlighted red.

## Resetting counters after servicing

Each detail panel has a reset button that clears that item's counter and
records today as the last-service date:

- Stylus: **Mark stylus changed**
- Belt: **Mark Belt Replaced**
- Bearing: **Mark Bearing Oiled**

Tapping it asks for confirmation ("Mark stylus as changed?", "Mark drive belt
as replaced?", "Mark bearing as oiled?"). Confirming resets the hours-used
counter to zero, resets the elapsed-time clock to today, and clears any
warning or overdue state for that item. The button is disabled when both of
that item's dimensions are set to "Don't track", since there is nothing to
reset.
