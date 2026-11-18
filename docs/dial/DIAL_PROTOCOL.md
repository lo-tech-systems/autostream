# autostream dial - Protocol Specification

This document describes how autostream dial devices relate to autostream appliances.
It covers appliances and dials of the same release; earlier ones are not supported.

## 1. The dial as a protocol client

A dial is a client of the appliance's client protocol, on the same footing as the
browser. For each appliance it sees, it opens one connection to that appliance's
`/api/v1/state` and `/api/v1/events`, keeps the state it receives, and sends its commands
as intents on `/api/v1/intents/<name>`. The client protocol, its parts, its change events,
its errors and its access rules are defined by the appliance's protocol documentation, not here.

- **Identity.** A dial identifies itself as `dial:<uuid>`, with the `playback` role. The
  appliance decides whether that identity may control it (the Setup page's authorise and
  revoke), and reports the result to the dial as the `access` part of its state.
- **Protocol number.** The dial advertises the protocol number it speaks as `proto`; an
  appliance advertises its own the same way. A dial whose number is lower than the
  appliance's is flagged for updating on the Setup page and in the appliance warnings.
  Neither side reads any other protocol key.
- **No other appliance routes.** A dial sends nothing to an appliance except through the
  client protocol, and an appliance sends nothing to a dial; the dial learns of every change
  from its open event stream. The Setup page's dial card talks to the dial's own HTTP API
  (section 4) through the management proxy (section 3).

The dial's own loopback-only services (the poll of its local Wi-Fi watcher at
`127.0.0.1:9080/network_status`, the offline-recovery CGI `POST 127.0.0.1/offline/reboot`
used by the Restart action, and the HD page's API on its loopback address) are dial-local
and are described in `HD-DIAL.md` and `ARCHITECTURE.md`. The only HD setting that appears
here is `hd_dev_access` (section 4).

---

## 2. mDNS service types

### `_autostream._tcp` - autostream appliance

Announced by an appliance continuously, port 80. Its TXT fields are `id`, `version`,
`control` and `proto`. A dial finds appliances by browsing this one type.

### `_autostream-dial._tcp` - dial device, always-on

Announced continuously by a dial device, port **7842** (dial HTTP server).

| TXT field | Value | Meaning |
|---|---|---|
| `id` | 20-char hex | Stable dial identity (used for authorization). A factory reset gives the dial a new one |
| `name` | string | Human-readable display name |
| `version` | e.g. `1.0.0` | Installed dial firmware version |
| `pin_recovery` | `1` | PIN recovery window active (10-minute window only) |
| `dial_sdmon` | `v1` | The dial exposes `GET`/`POST /sdcard-health` (section 4) and can run the guarded SD card health probe |
| `proto` | integer | The client protocol number the dial speaks |

**Name constraints:** dial names are restricted to printable ASCII (0x20-0x7e) excluding `;`
(avahi field separator) and `|` (config delimiter). Names containing these characters are
rejected by `autostream_admin update-dial-service`.

---

## 3. Main-appliance dial management proxy

The main autostream appliance exposes dial management routes under `/api/dial/`
(`authorize`, `revoke`, `configure`, `update/*`, `screen/*`, `sdcard-health*`,
`pin_recovery/*` and `recovery/*`) that are proxied to the individual dial's HTTP API
(port 7842). They serve the browser's Setup page; the dial itself does not call them.

### Transport status vs semantic status

Direct dial responses retain their native HTTP semantics (see section 4 below). However,
the main appliance NGINX configuration intercepts statuses `404`, `502`, `503`, and `504`
and redirects them to an offline page. When the proxy produces one of those semantic
outcomes, it **tunnels** the error through browser HTTP `200` using the canonical error
shape described in `docs/API-ERROR-CONTRACT.md`.

Clients consuming proxy responses must therefore inspect `ok`, `error`, and
`error_status` - not only the transport HTTP status - to determine the outcome:

```json
{
  "ok": false,
  "error": "dial_unreachable",
  "error_status": 502,
  "retryable": true
}
```

### Error identifiers

| `error` identifier | Meaning |
|---|---|
| `dial_offline` | Host could not find the dial UUID in the mDNS registry |
| `dial_unreachable` | Network connection to the dial failed |
| `dial_bad_response` | Dial returned an oversized, non-JSON, non-object, or redirect body |
| `not_found` | Dial was reachable but the target resource does not exist |
| `dial_unavailable` | Dial returned `503` Service Unavailable |
| `dial_timeout` | Dial returned `504` Gateway Timeout |

`dial_offline` is a **host discovery failure**. `not_found` is a **target-resource
absence** - the dial was reached, but the requested resource is not active (for example,
`GET /recovery_status` returns `{"active": false}` with HTTP `404` when no PIN recovery
window is open).

### Non-intercepted target statuses

Target statuses not intercepted by NGINX (`400`, `403`, `429`, `500`) pass through to
the browser as native HTTP responses. These represent validation errors, authorization
failures, rate limiting, and persistence failures that the browser can handle directly
using the transport status.

### Recovery arm/disarm endpoints

`POST /api/dial/recovery/arm` and `POST /api/dial/recovery/disarm` proxy to the dial's
`POST /recovery/arm` and `POST /recovery/disarm` respectively (see section 4). These are
browser dial-management routes: the main appliance
requires its own authenticated session before proxying the request - the same
`require_authenticated_if_pin_enabled` gate applied to `/api/dial/configure` and the other
dial-management routes. The dial itself does not check a PIN on either endpoint; session
authentication on the appliance side is what stands in for it. See **`POST /recovery/arm`**
under section 4 for why.

---

---

## 4. Dial HTTP API (port 7842)

### `POST /configure`

All fields optional. PIN required to change `name`, `step_percent`, `new_pin`,
`auto_update`, `update_channel`, or `hd_dev_access` if a PIN is set.

`hd_dev_access` is a strict JSON boolean (anything else is `400 invalid_hd_dev_access`).
It switches on the development listener of the HD page, which authenticates with the PIN,
so it cannot be enabled while no PIN is set: that request is `400 pin_required`. Posting
`new_pin` with an empty string, which clears the PIN, also switches it off.

PIN recovery completion: include `"pin_recovery": true` with `"new_pin"` to complete recovery
without knowing the current PIN (window must be active and volume confirmed).

`mute_all_playing`, a field never documented in this file, is retired: it is silently ignored
if a caller still posts it (unknown fields are ignored, same as any other), and it is never
present in `GET /configure`. A dial that previously had it persisted as `true` migrates that
choice once, at startup, onto `screen.mute_scope: "all"` (see `GET`/`POST /screen/settings`
below) — no client action is required.

### `GET /configure`

Returns current dial settings.

**Response:**
```json
{"step_percent": 2, "pin_set": true, "name": "My Dial", "version": "1.0.0", "auto_update": false, "update_channel": "stable", "can_confirm_presence": true, "hd_dev_access": false}
```

| Field | Type | Notes |
|---|---|---|
| `update_channel` | string | `"stable"` or `"dev"`. `stable` considers only full GitHub releases; `dev` considers the most recent release including pre-releases. PIN-gated when set via `POST /configure` (same protection as `name`, `step_percent`, `auto_update`). |
| `can_confirm_presence` | bool | Runtime truth, not config: `true` only if this dial actually constructed at least one input capable of confirming presence for PIN recovery - a working rotary encoder, a working button, or a running touch stack. `false` covers every other case, including a configured touch panel whose driver failed to construct at startup. Set once at startup after input construction finishes; a dial polled before that finishes reports `false`. |
| `hd_dev_access` | bool | Whether the HD page is also served on a LAN development listener. Off by default. PIN-gated when set via `POST /configure`, and refused while no PIN is set. An old dial does not send the field; read its absence as `false`. |

### `GET /recovery_status`

Returns 404 if no PIN recovery window is active; the body still carries
`can_confirm_presence` so a client can distinguish "no window is open" from
"this dial could never confirm presence even if a window were open":
```json
{"active": false, "can_confirm_presence": true}
```

While a window is active, `200` is returned with the full state:
```json
{"active": true, "volume_confirmed": false, "recovery_remaining_ms": 583201, "can_confirm_presence": true}
```

| Field | Type | Notes |
|---|---|---|
| `volume_confirmed` | bool | Historical field name - it means "presence confirmed", not specifically a volume change. Set `true` by any deliberate physical input on the dial: a touch anywhere on the panel, a physical button press, or the rotary encoder turned in either direction (previously only a clockwise turn, or a nudge sent over the local control socket, counted - that left touch-only, button-only, and screen-only dials unable to ever confirm presence). Once set, stays `true` for the rest of the window. |
| `recovery_remaining_ms` | int | Milliseconds left in the 10-minute recovery window, clamped at 0. `0` whenever no window is active. Lets a client show a countdown and detect expiry without polling `active` alone. |
| `can_confirm_presence` | bool | Same runtime-truth field documented under `GET /configure` above. |

### `POST /recovery/arm`

Writes a PIN-recovery request marker to persistent storage. Writing the marker does not by
itself open a recovery window - it only records that recovery has been requested. See
**Recovery arming** below for how a request is turned into an active window.

**No PIN required.** The PIN is what the caller has lost, so requiring it to reach the
endpoint that recovers it would be circular. Authority instead comes from the caller being
authenticated to the main appliance: the appliance only proxies this request (via `POST
/api/dial/recovery/arm`, see section 3) after checking its own session, and completing
recovery still requires physical presence at the dial afterwards (see **Recovery arming**).

**Request body:** none required; any body is ignored.

**Response (200):**
```json
{"ok": true}
```

Always `200 {"ok": true}`, including when the marker could not be written (for example,
read-only storage). That failure is logged on the dial, not surfaced to the caller as an
error - arming is best-effort and idempotently re-triable.

### `POST /recovery/disarm`

Deletes the PIN-recovery request marker written by `POST /recovery/arm` above, withdrawing
a request that has not yet been consumed. Called by the main appliance's proxy at `POST
/api/dial/recovery/disarm` under the same session-authentication rule as `POST
/recovery/arm`. **No PIN required**, for the same reason as `POST /recovery/arm`.

If a recovery window is already active (the request was already consumed at a prior
startup), disarming does not close that window - the window runs its own independent
10-minute course once opened; see **Recovery arming** below.

**Request body:** none required; any body is ignored.

**Response (200):**
```json
{"ok": true}
```

Same best-effort semantics as `POST /recovery/arm`: a failure to remove the marker is
logged, not surfaced as an error.

### Recovery arming

A PIN-recovery request written by `POST /recovery/arm` does not open a recovery window by
itself. The window opens only the next time the dial process starts, and only when **both**
of the following are true at that startup:

1. **An explicit request is pending** - the request marker written by `POST /recovery/arm`
   is present and has not since been disarmed.
2. **The device was genuinely power-cycled**, not merely restarted. The dial writes a
   marker file when it starts and deletes it as part of a clean shutdown; the marker
   surviving to the next startup means the previous stop did not go through the clean-
   shutdown path - most likely a power loss, or the process being killed outright. An
   ordinary `systemctl restart`, a `reboot` command, or the self-restart the dial fires
   after a firmware update or a `touch_type` change (see `POST /screen/settings`) all go
   through clean shutdown, so **none of these arm recovery** even with a request pending.

Neither condition alone is enough: a survived marker with no pending request is just an
ordinary power cycle nobody asked for, and a pending request with a clean-shutdown marker
means a restart happened before the device was ever power-cycled - the request must stay
armed for a real power cycle later, not fire on that restart. The request marker is
consumed (deleted) only in the startup where both conditions were checked together; an
unrelated clean restart between arming and power-cycling leaves the request intact for the
power cycle that eventually follows.

**Request expiry.** A pending request older than 30 minutes (measured from when `POST
/recovery/arm` wrote the marker) is not honoured. This hardware has no RTC, so the age
comparison only runs once the system clock reports itself synchronised; if synchronisation
never completes, the request is honoured anyway and the skipped age check is logged - a
dial with broken time sync and a lost PIN would otherwise be permanently unrecoverable.

This 30-minute request-expiry window is separate from, and precedes, the 10-minute
**recovery window** described under `RecoveryWindow`/`GET /recovery_status` above: the
30-minute window bounds the time between requesting recovery and actually power-cycling the
device; the 10-minute window starts only once the device has restarted with recovery armed,
and bounds the time available to confirm presence and set a new PIN.

A request found on a dial with no PIN configured is still consumed (deleted) at startup,
but never arms anything - there is nothing to recover.

### `POST /update`

Triggers a firmware update. Returns immediately:
```json
{"ok": true}
```

**Failure response (200 body):**
```json
{"ok": false, "error": "scheduler_failed"}
```

Returned when the admin command that schedules the updater run could not be started. The
update itself has not been attempted in this case.

### `GET /update/status`

```json
{
  "state": "running",
  "version": "0.6.0",
  "percent": 45,
  "message": "Installing Python packages...",
  "phase": "python",
  "tag": "0.7.0",
  "previous_tag": "0.6.0",
  "attempt": 1,
  "max_attempts": 4,
  "rolled_back": false,
  "last_run_at": "2025-01-15T14:30:00+00:00"
}
```

`state` is one of `"idle"`, `"running"`, `"complete"`, `"failed"`. `version` is the version
of the software that is running now, so during an update it stays at the old version until the
dial has restarted into the new one. The other fields describe the most recent update run
and come from the dial's update result record:

| Field | Type | Notes |
|---|---|---|
| `percent` | int | Progress, 0 to 100. Moves forward as the update passes through its phases |
| `message` | string | A human-readable status line, for example `Downloading 0.7.0...` or `Update to 0.7.0 failed - restored 0.6.0` |
| `phase` | string | Where the update is up to; see the phase names below. Empty when no update has run |
| `tag` | string | The release being installed (or that was installed) |
| `previous_tag` | string | The release that was installed before the update started |
| `attempt` | int | The attempt number, 1 for a first run. It goes up each time an interrupted update is retried at boot |
| `max_attempts` | int | The most attempts an update gets, currently 4 (the first run and three retries) |
| `rolled_back` | bool | `true` only when a new version was installed, failed its check after the restart, and the previous version was put back |
| `last_run_at` | string | When the most recent update run started or last changed state, as an ISO 8601 UTC timestamp; empty when no update has run |

Fields a record does not hold take neutral values (empty string, `0`, `false`), so an
update that has never run still gives a well-formed reply.

Phase names, in the order a normal update passes through them:

| `phase` | Meaning |
|---|---|
| `download` | Fetching the release (also shown while an interrupted update is being retried) |
| `prepare` | Checking the system and getting ready |
| `packages` | Upgrading operating-system packages and installing the packages the dial needs |
| `python` | Building the Python environment for the new version |
| `files` | Copying the new software into a holding area beside the live copy |
| `configure` | Updating services and configuration files, after saving copies of the old ones |
| `staged` | Everything is ready to be switched in at the next start |
| `reboot` | The dial is about to restart |
| `verify` | The dial has restarted into the new version and is checking that it works |
| `done` | The new version passed its check |
| `failed` | The update stopped and the previous version is still installed |
| `rolled_back` | The new version failed its check and the previous version was restored |

While the dial restarts (around the `reboot` and `verify` phases) requests to this route can
fail; a client should keep polling. Through the appliance's
proxy the reply is passed on unchanged, and a restarting dial appears as offline. See
[System Maintenance](SYSTEM-MAINTENANCE.md#firmware-updates) for what each phase does.

### `GET /update/check`

Checks GitHub for an available update on the dial's configured `update_channel`, without
staging or applying anything. Delegates to `autostream_dial_updater check` and returns its
JSON output verbatim (wrapped as HTTP `200` even on failure).

**Response (update information available):**
```json
{
  "ok": true,
  "installed": "1.0.0",
  "candidate": "1.1.0",
  "update_available": true,
  "channel": "stable",
  "release_notes": "..."
}
```

| Field | Type | Notes |
|---|---|---|
| `installed` | string | Currently installed version, or `"unknown"` if it could not be determined |
| `candidate` | string | Latest release tag on the configured channel, or `"unknown"` if none was found |
| `update_available` | bool | `true` if `candidate` is newer than `installed` |
| `channel` | string | The channel the check was performed against (`"stable"` or `"dev"`) |
| `release_notes` | string | Present only when `update_available` is `true` and notes exist |

**Failure response (200 body):**
```json
{"ok": false, "error": "GitHub API not reachable (network or HTTP error)"}
```

Also returns `{"ok": false, "error": "check_failed"}` if the underlying updater command
fails to run or produces unparseable output.

---

### `GET /screen/settings`

Returns the dial-owned effective screen settings, the catalogue of display profiles this
dial firmware supports, and current runtime status. Screen settings are owned and
persisted by the dial; the main appliance never stores a copy and always reads current
values from this endpoint.

```json
{
  "ok": true,
  "screen": {
    "fitted": false,
    "rotate": false,
    "screen_type": "st7735s_160x128",
    "bgr": false,
    "touch_type": "none",
    "always_show_controls": false,
    "screen_size_inches": null,
    "layout_size": null,
    "volume_scope": "current",
    "mute_scope": "current",
    "poll_interval_s": 6,
    "sleep_after_s": 300,
    "brightness": 80,
    "panel_power_off": false,
    "surface": "spi"
  },
  "supported": [
    {"key": "st7735s_160x128", "text": "ST7735S (128x160)", "default_inches": 1.8},
    {"key": "st7735s_128x128", "text": "ST7735S (128x128)", "default_inches": 1.44},
    {"key": "st7789_240x240", "text": "ST7789 (240x240)", "default_inches": 1.3},
    {"key": "st7789_320x240", "text": "ST7789 (240x320)", "default_inches": 2.8},
    {"key": "ili9341_320x240", "text": "ILI9341 (320x240)", "default_inches": 2.8},
    {"key": "hd_kiosk", "text": "HD touchscreen (HDMI or DSI, kiosk browser)", "default_inches": 5.0}
  ],
  "supported_touch": [
    {"key": "none", "text": "None"},
    {"key": "xpt2046", "text": "Resistive (XPT2046/HR2046)"},
    {"key": "ft6206", "text": "Capacitive (FT6206/FT6236)"}
  ],
  "layout_sizes": [
    {"key": "small", "text": "Small (160x128)"},
    {"key": "medium", "text": "Medium (320x240)"},
    {"key": "large", "text": "Large (640x480)"}
  ],
  "layout": {
    "logical_width": 160,
    "logical_height": 128,
    "physical_width": 160,
    "physical_height": 128,
    "resampled": false,
    "size_chosen": false,
    "content_tier": "base",
    "touch_short": false
  },
  "runtime": {
    "fitted": false,
    "rotate": false,
    "screen_type": "st7735s_160x128",
    "bgr": false,
    "touch_type": "none",
    "always_show_controls": false,
    "active": false,
    "backend": "noop",
    "backend_loaded": false,
    "showing": "noop",
    "last_error": "",
    "last_error_at": null,
    "display_sleeping": false,
    "display_idle_seconds": 0
  },
  "scope": {
    "volume": "all",
    "mute": "all"
  }
}
```

| Field | Type | Notes |
|---|---|---|
| `screen.fitted` | bool | Persisted screen-fitted setting |
| `screen.rotate` | bool | Persisted screen-rotation setting; `true` rotates the display 180 degrees. Optional, defaults to `false` |
| `screen.screen_type` | string | Persisted display profile key. Optional, defaults to the dial's default profile |
| `screen.bgr` | bool | Persisted colour-order swap setting. Optional, defaults to `false` |
| `screen.touch_type` | string | Persisted touch controller key. Optional, defaults to `"none"` (touch disabled). An unrecognised value is rejected outright - see **Validation** under `POST /screen/settings` below |
| `screen.always_show_controls` | bool | Persisted "always show controls" setting - keeps the now-playing/volume overlay visible rather than only on a touch. Optional, defaults to `false`. No separate capability gate: like `rotate`/`bgr`, it is always accepted and always reported |
| `screen.screen_size_inches` | number\|null | Persisted physical screen diagonal, in inches. `null` means "use the selected profile's own built-in default" (see `default_inches` under **Supported profiles** below). Optional, defaults to `null` |
| `screen.layout_size` | string\|null | Persisted logical render size: the dial composes and hit-tests every screen at this size and resamples the finished frame to the panel. `null` means "use the panel's own resolution" - today's behaviour. When present, must be one of the keys in `layout_sizes` for the current `screen_type`. Optional, defaults to `null` |
| `screen.volume_scope` | string | Which appliances a volume twist addresses while `screen.fitted` is true: `"current"` (the bound appliance) or `"all"` (every playing appliance). Optional, defaults to `"current"`. See **Scope capability gate** and **Broadcast scope** below |
| `screen.mute_scope` | string | The same choice for a mute push. Optional, defaults to `"current"` |
| `screen.poll_interval_s` | integer | How often the dial polls the appliances for their state, in whole seconds, from `2` to `6` inclusive. A lower value reacts sooner to a new track or a start/stop, at the cost of more traffic. Optional: omitted keeps the current value (`6` by default). Applies live. No capability gate |
| `screen.sleep_after_s` | integer | Idle seconds before an HD screen sleeps: one of `0` (never), `60`, `300` or `900`. Optional: omitted keeps the current value (`300` by default). Applies live. Only a dial whose `screen.surface` is `"kiosk"` acts on it; every dial stores and reports it. No capability gate |
| `screen.brightness` | integer | Backlight percentage of an HD screen while awake, from `5` to `100` inclusive. Optional: omitted keeps the current value (`80` by default). Applies live. Only a dial whose `screen.surface` is `"kiosk"` acts on it; every dial stores and reports it. No capability gate |
| `screen.panel_power_off` | boolean | Whether an HD screen's HDMI panel is also powered down over its control channel while asleep. Optional: omitted keeps the current value (`false` by default); it must be a JSON boolean. Applies live, including while the screen is asleep. With `false` a sleeping panel is dimmed to its minimum and left powered, and power-off is never sent; with `true` it is powered off when the screen sleeps and on again when it wakes, on a panel that has the power control. It is off by default because some panels are left with image retention after being powered down. Only a dial whose `screen.surface` is `"kiosk"` acts on it, and an appliance sends it only to such a dial; every dial stores and reports it. No capability gate |
| `screen.surface` | string | Where this dial's screen lives, derived from the selected profile: `"spi"` for a panel the dial drives itself, `"kiosk"` for an HD screen that shows a page the dial serves (profile `hd_kiosk`). Report only: a `screen` object sent with it, such as one fetched and posted back with a field changed, is accepted and the value is ignored. A kiosk dial has no frame, so `GET /screen/image` answers `404` and `runtime.backend` is `noop`. An old dial does not send the field; read its absence as `"spi"` |
| `scope.volume`, `scope.mute` | string | The EFFECTIVE values: the stored `screen.volume_scope`/`screen.mute_scope` while `screen.fitted` is true, otherwise always `"all"` - a dial with no screen (or one too small to select an appliance) cannot choose which appliance to address. Informational only; a client never sends either back |
| `supported` | array | Catalogue of display profiles this dial firmware supports, as `[{"key", "text", "default_inches"}, ...]` - see **Supported profiles** below |
| `supported_touch` | array | Catalogue of touch controllers this dial firmware supports, as `[{"key", "text"}, ...]`. **This is a separate capability from `supported`** - see **Touch capability gate** below |
| `layout_sizes` | array | The logical render sizes this dial can compose the *current* `screen_type` at, as `[{"key", "text"}, ...]` (e.g. `{"key": "medium", "text": "Medium (320x240)"}`). The panel's own native resolution is not listed here - a client represents it as `screen.layout_size: null`. **Its presence is the capability gate for this field** - see **Layout-size capability gate** below |
| `layout.logical_width`, `layout.logical_height` | int | The size every screen is composed and hit-tested at: the chosen `screen.layout_size`, or the panel's own resolution when none is chosen |
| `layout.physical_width`, `layout.physical_height` | int | The configured profile's panel size - the size the composed frame is resampled to before it is sent |
| `layout.resampled` | bool | `true` when the logical size differs from the physical size, i.e. the frame is scaled to the panel before it is sent |
| `layout.size_chosen` | bool | `true` when `screen.layout_size` is set, meaning the automatic small-screen fallback (see `layout.touch_short`) does not apply |
| `layout.content_tier` | string | The chrome density the logical size resolves to: `"compact"` (physically small glass - a 2x2 grid of controls, no name or readout), `"base"`, `"rich"`, or `"large"`. Informational - clients should not assume this set is closed |
| `layout.touch_short` | bool | `true` when the quarter-height control band on this glass works out below the comfortable-touch floor (a fixed 6 mm), so on-screen controls are shorter than a fingertip |
| `runtime.fitted` | bool | Effective fitted flag currently applied by the display manager |
| `runtime.rotate` | bool | Effective rotation flag currently applied by the display manager |
| `runtime.screen_type` | string | The **active** display profile key - see **Configured vs. active** below |
| `runtime.bgr` | bool | The **active** colour-order swap setting - see **Configured vs. active** below |
| `runtime.always_show_controls` | bool | The **active** "always show controls" setting; applies live, so this always matches `screen.always_show_controls` |
| `runtime.touch_type` | string | What the touch stack **actually did at startup**, set once after touch construction finishes. One of: the constructed controller key (e.g. `"xpt2046"`) when touch was built and started; `"none"` when touch was deliberately not built (disabled by config, or no screen fitted); `"failed"` when construction was attempted and raised. Polled before startup construction finishes, it reads `""` - the same early-poll caveat as `can_confirm_presence` under `GET /configure`. This is distinct from `screen.touch_type` (the persisted configuration), which changes the instant a `POST /screen/settings` saves it even though the running process has not restarted to pick it up yet |
| `runtime.active` | bool | `true` when a non-no-op display path is open |
| `runtime.backend` | string | Name of the currently active driver (e.g. `noop`, `adafruit_st7735s`) |
| `runtime.backend_loaded` | bool | `true` once backend imports and hardware open succeeded |
| `runtime.showing` | string | One of `logo`, `artwork`, or `noop` |
| `runtime.last_error` | string | Last non-fatal display/fetch/render error identifier, or `""` |
| `runtime.last_error_at` | number\|null | Unix timestamp for `last_error`, or `null` |
| `runtime.display_sleeping` | bool | `true` once the display has been idle for `display_idle_seconds` and the backend has blanked/slept it |
| `runtime.display_idle_seconds` | int | Seconds since idling began, capped at the 5-minute sleep threshold; resets to `0` while showing content |

Never returns secrets or provider artwork URLs.

**Supported profiles.** `supported` is the catalogue of display profiles this dial
firmware knows how to drive. `key` is the opaque value a client sends back in
`screen.screen_type` to select that profile; `text` is a display label for presenting the
choice to a user. `default_inches` is the profile's own built-in physical screen size, in
inches - the value a client should pre-fill a screen-size control with before the user
overrides it. **`key` and `text` are opaque to clients** - clients must not parse either
string for meaning (e.g. extracting dimensions from the label), and must render only what
the dial itself published in `supported`. `default_inches` is the one exception: it is a
plain number, not an opaque string, and is meant to be read directly. Sorting the list by
`text` for presentation is fine; inferring structure from `key`/`text` themselves is not.

**Configured vs. active.** `screen.screen_type`/`screen.bgr` are the persisted
configuration; `runtime.screen_type`/`runtime.bgr` are what the display manager currently
has open. These normally match. They can diverge when a live profile swap fails to open
the new panel - see **Apply-then-persist** under `POST /screen/settings` below - in which
case `runtime` keeps reporting the last-known-working (degraded or previous) state while
`screen` reflects what is actually persisted on disk. Clients can compare
`screen.screen_type` with `runtime.screen_type` to detect this drift. `runtime.backend`
names the driver currently active for `runtime.screen_type` (e.g. `adafruit_st7735s`,
`noop` if no panel is open).

**Capability gate.** `screen_type` and `bgr` are a single joint capability, advertised by
the presence of a non-empty `supported` array in this response. See **Capability gate**
under `POST /screen/settings` below: clients check it before ever sending
`screen.screen_type` or `screen.bgr`.

**Touch capability gate.** `supported_touch` is a **separate capability from `supported`**.
A dial can advertise display profiles in `supported` while knowing nothing at all about
touch. A client must not send
`screen.touch_type` to a dial that did not advertise a non-empty `supported_touch` array,
and must not infer touch support from the presence (or non-emptiness) of `supported` - the
two capabilities are independent and must be checked independently.

**Layout-size capability gate.** `layout_sizes` is a **separate capability from
`supported` and `supported_touch`**, gated the identical way: a client must not send
`screen.layout_size` to a dial that did not advertise a `layout_sizes` array in this
response (even an empty one - an empty array means the current `screen_type` offers no
named size, e.g. a square panel, not that the capability is absent), and must not infer
this capability from `supported`/`supported_touch`. `layout_sizes` reflects the
**currently configured** `screen_type` - a client re-fetches or reads the array returned
by `POST /screen/settings` after changing `screen_type`, rather than assuming the
previous list still applies.

**Layout report.** `layout` reports what the persisted `screen` settings resolve to: the
logical size the dial composes and hit-tests at, the physical panel size it resamples to,
and the content tier and touch-target assessment for that combination. It is informational
and computed from the **persisted** configuration, so it is meaningful even before a panel
is fitted or open - never from the open backend; compare `screen.screen_type` with
`runtime.screen_type` for what is actually open. Its presence indicates the dial publishes
this report; a client never sends any of it back. `layout.content_tier` names one of four
tiers today, but clients should not assume the set is closed. `layout.touch_short` is an
assessment against a fixed 6 mm control-band floor, and `layout.size_chosen` records
whether a deliberate layout-size choice overrides the automatic fallback to the smallest
tier. `layout.resampled` means the composed frame is scaled to the panel before it is sent.

**Scope capability gate.** `volume_scope`/`mute_scope` are **one joint capability**,
advertised by the presence of BOTH `screen.volume_scope` and `screen.mute_scope` in this
response. A client must not send either field to a dial that did not advertise both, and
must not infer this capability from `supported`, `supported_touch`, `layout_sizes`, or any
other field - it is checked independently, the same pattern every other screen capability in
this document follows. An old dial's `GET` response simply omits both fields.

**Broadcast scope.** A dial with no screen fitted (or one too small to display an appliance
selector) cannot choose which appliance a twist or a push addresses, so it addresses every
playing appliance instead of the one it would otherwise be bound to. The rule is: the
effective scope is the stored `screen.volume_scope`/`screen.mute_scope` while `screen.fitted`
is `true`, and always `"all"` otherwise (see `scope.volume`/`scope.mute` above). Under
`volume_scope` "all", the dial sends the same volume step intent to every playing
appliance; each applies it to its own master volume and its own muted-volume rule. Under
`mute_scope` "all", the dial decides one fleet-wide action from the `muted` state it holds for
every playing appliance at the moment of the push: `"mute"` when any of them is not muted (or
its state is unknown), `"restore"` only when every one of them is muted. This decision is
made once per push, not once per appliance, so the whole fleet ends up in the same state even
if it started mixed.

### `GET /screen/image`

Returns the frame currently on the panel, as a person standing at the dial would see it
(rotation and colour-order settings already applied), at the panel's own pixel size.

**Response (`200`):** `image/png` body, `Cache-Control: no-store`.

**Response (`404`)**, when nothing is currently shown (never enabled, cleared, or asleep):
```json
{"ok": false, "error": "no_frame"}
```

No PIN or token required — a read of what is already visible in the room, the same
convention as `GET /screen/settings` and the other read-only endpoints above.

### `POST /screen/settings`

Accepts the **complete** normalized screen settings object - this endpoint does not apply
partial patches. PIN behavior follows existing `POST /configure` semantics: if a dial PIN
is set, the request must include the current PIN in `current_pin`.

```json
{
  "current_pin": "1234",
  "screen": {
    "fitted": true,
    "rotate": false,
    "screen_type": "st7735s_160x128",
    "bgr": false,
    "touch_type": "xpt2046"
  }
}
```

Successful response - request changed `touch_type` from `"none"` to `"xpt2046"`, and a
restart was actually fired for it:

```json
{
  "ok": true,
  "screen": {
    "fitted": true,
    "rotate": false,
    "screen_type": "st7735s_160x128",
    "bgr": false,
    "touch_type": "xpt2046",
    "always_show_controls": false,
    "screen_size_inches": null,
    "layout_size": null,
    "volume_scope": "current",
    "mute_scope": "current",
    "poll_interval_s": 6,
    "sleep_after_s": 300,
    "brightness": 80,
    "panel_power_off": false,
    "surface": "spi"
  },
  "layout_sizes": [],
  "layout": {
    "logical_width": 160,
    "logical_height": 128,
    "physical_width": 160,
    "physical_height": 128,
    "resampled": false,
    "size_chosen": false,
    "content_tier": "base",
    "touch_short": false
  },
  "scope": {
    "volume": "all",
    "mute": "all"
  },
  "runtime": {
    "fitted": true,
    "rotate": false,
    "screen_type": "st7735s_160x128",
    "bgr": false,
    "touch_type": "none",
    "always_show_controls": false,
    "active": false,
    "backend": "noop",
    "backend_loaded": false,
    "showing": "noop",
    "last_error": "",
    "last_error_at": null,
    "display_sleeping": false,
    "display_idle_seconds": 0
  },
  "restart_required": true,
  "restarting": true
}
```

(`layout_sizes`, `layout`, and `scope` follow the same shape and gating rules as on `GET
/screen/settings` above - they are included here as they always are on every `POST
/screen/settings` response, success or `screen_apply_failed`. `supported`/`supported_touch`
are not - a client re-fetches `GET /screen/settings` for those.)

(`runtime.touch_type` in this example still reads `"none"` - the previously-running
state - because the touch controller change does not apply live; see **`restart_required`**
below. The `restarting: true` field means the dial has already begun restarting its own
service by the time this response arrives; poll `GET /screen/settings` afterwards to see
`runtime.touch_type` reflect `"xpt2046"`.)

`restart_required` reports whether **this specific POST** requires a dial service restart
before it is fully applied. `fitted`, `rotate`, `screen_type`, `bgr`, and `layout_size`
all apply live - the dial starts, stops, or swaps the current display provider internally,
and re-scales the touch stack to match, with no restart needed for any of them. `touch_type`
is the one exception: the touch stack (driver, filter,
state machine) is built once at dial process startup from the persisted controller choice,
so a `touch_type` change is saved immediately but has no live effect until the dial process
restarts. `restart_required` is `true` exactly when the request changed `touch_type` from
its previously-persisted value, and `false` otherwise. Its meaning is unchanged by the
self-restart behaviour described next - it still reports what this POST requires, not
whether a restart has been triggered.

**Self-restart on `touch_type` change.** The dial does not wait for an operator to restart
it: whenever `restart_required` is `true`, it fires its own service restart immediately
after this response has been sent, so the new `touch_type` takes effect without further
action. Measured restart time on real hardware is 8-11 seconds; the dial's HTTP API and
volume path are unavailable for that window.

To let a client show this without polling blind, a second field, `restarting`, is present
**only when a restart is actually being fired for this request**:

- `restarting: true` - present when `restart_required` is `true` and the restart was
  triggered.
- `restarting` is **absent** (not sent as `false`) whenever no restart fires for this
  request - either because `touch_type` did not change (`restart_required: false`), or
  because it did change but a self-restart already fired within the last 60 seconds and
  this one was refused. The dial allows at most one self-triggered restart per 60 seconds
  and logs a refusal at `WARNING`; the floor exists because `POST /screen/settings` is
  unauthenticated whenever no PIN is configured, and an unauthenticated, unthrottled restart
  trigger would otherwise be a denial-of-service vector. A refused restart still returns
  `restart_required: true` and `ok: true` - the setting is saved either way - but without
  `restarting`, so a client should not assume the dial is about to become unreachable.

`restarting` never appears when `restart_required` is `false` or absent (the
`screen_apply_failed` path below never sets it).

**Capability gate.** `screen_type` and `bgr` form **one joint capability**,
advertised by `GET /screen/settings` returning a non-empty `supported` array (see above).

- A client **must not** send `screen.screen_type` or `screen.bgr` to a dial that did not
  advertise a non-empty `supported` array.
- A request may omit both `screen_type` and `bgr` (they are optional and default), so a
  client that only sends `fitted`/`rotate` is accepted.

`touch_type` follows the identical rule as its **own, separate** capability - see **Touch
capability gate** above: gate on `supported_touch`, not on `supported`.

`layout_size` follows the identical rule as its **own, separate** capability - see
**Layout-size capability gate** above: gate on `layout_sizes`, not on `supported` or
`supported_touch`.

Both response shapes below also carry `layout_sizes`, `layout` (see **Layout report**
above), and `scope` for the configuration they echo: the success path reflects the
newly-saved `screen`, and the `screen_apply_failed` path reflects the still-persisted
`screen` it echoes instead.

**Validation:**

- `fitted` must be a strict JSON boolean - `0`, `1`, `"true"`, and `"false"` are rejected.
- `rotate` is optional and defaults to `false` when omitted; when present it must also be a
  strict JSON boolean.
- `bgr` is optional and defaults to `false` when omitted; when present it must also be a
  strict JSON boolean.
- `screen_type` is optional and defaults to the dial's default profile when omitted; when
  present it must be a string naming a profile key present in `supported`. An unknown
  value is rejected outright - it is never silently coerced to the default.
- `touch_type` is optional and defaults to `"none"` when omitted; when present it must be a
  string naming a controller key present in `supported_touch`. An unknown value is rejected
  outright, the same as `screen_type`.
- `always_show_controls` is optional and defaults to `false` when omitted; when present it
  must also be a strict JSON boolean. Unlike `touch_type`/`screen_type`/`layout_size`, this
  field has no capability gate - it is always accepted, the same as `rotate`/`bgr` - so an
  old appliance's whole-object POST (which never sends it) never 400s.
- `screen_size_inches` is optional and defaults to `null` when omitted (meaning "use the
  selected profile's own default"); when present it must be a JSON number (not a boolean)
  between `0.5` and `20`, or JSON `null`. Anything else is rejected outright.
- `layout_size` is optional and defaults to `null` when omitted (meaning "use the panel's
  own resolution"); when present it must be a string naming a key present in
  `layout_sizes` for the posted `screen_type`, or JSON `null`. A key not offered for that
  `screen_type` is rejected the same as an unrecognised one.
- `volume_scope` is optional and defaults to `"current"` when omitted; when present it must
  be the string `"current"` or `"all"`. Anything else is rejected outright.
- `mute_scope` follows the identical rule as `volume_scope` immediately above, independently.
- `poll_interval_s` is optional; when omitted, the dial keeps its current interval (`6`
  on a dial that has never been set). When present it must be a JSON integer (not a
  boolean, float or string) from `2` to `6` inclusive. Anything else is rejected
  outright. It has no capability gate, and an appliance screen save (which never sends
  it) leaves a configured interval unchanged.
- `sleep_after_s` is optional; when omitted, the dial keeps its current value (`300` on a
  dial that has never been set). When present it must be a JSON integer equal to `0`,
  `60`, `300` or `900`. Anything else is rejected outright. It has no capability gate,
  and an appliance screen save (which never sends it) leaves a configured value
  unchanged.
- `brightness` is optional; when omitted, the dial keeps its current value (`80` on a dial
  that has never been set). When present it must be a JSON integer (not a boolean, float
  or string) from `5` to `100` inclusive. Anything else is rejected outright. It has no
  capability gate, and an appliance screen save leaves a configured value unchanged.
- `panel_power_off` is optional; when omitted, the dial keeps its current value (`false` on a
  dial that has never been set). When present it must be a JSON boolean (not `0`/`1` or a
  string). Anything else is rejected outright. It has no capability gate, and a save that
  leaves it out leaves a configured value unchanged.
- `surface` is report only and is not accepted: it is an unknown field in a posted
  `screen` object.
- A missing or non-object `screen`, a missing `fitted` field, or any unknown field inside
  `screen` (including a `screen_type`/`bgr`/`touch_type` sent to firmware that doesn't
  support them - see the capability gates above) returns HTTP `400`:

```json
{"ok": false, "error": "invalid_screen_settings"}
```

- A wrong or missing `current_pin` when a PIN is set follows existing `POST /configure`
  PIN failure behavior (HTTP `403`/`429`).
- Persistence failures return HTTP `500`.
- A saved config whose runtime application fails for a reason unrelated to a screen_type
  change may still return `ok: true` with `runtime.last_error` populated, provided the
  display manager degraded to no-op.

**Apply-then-persist (screen_type).** Unlike the rest of `POST /configure`/`POST
/screen/settings`, a `screen_type` change is applied to the live display **before** being
written to disk, and is persisted only if the apply succeeded:

- `fitted`, `rotate`, and `bgr` can never fail to apply on their own, so a request that
  changes only these (with `screen_type` unchanged) is always persisted regardless of
  runtime outcome - this part of the ordering is unchanged from before.
- `[ ]` A request that bundles a `screen_type` change with other field changes (`fitted`,
  `rotate`, `bgr`, `touch_type`, etc.) in the same POST and hits the failure path below
  appears, from the handler, to discard the whole posted `screen` object - not just
  `screen_type` - since the on-disk config is a single write. This has not been confirmed
  against a real bundled-request test; treat mixed screen_type + other-field POSTs as
  all-or-nothing until this is verified.
- If a `screen_type` change is requested while `fitted` is true and the new panel driver
  fails to open, the response is:

```json
{
  "ok": false,
  "error": "screen_apply_failed",
  "screen": {
    "fitted": true, "rotate": false, "screen_type": "st7735s_160x128", "bgr": false,
    "touch_type": "none", "always_show_controls": false, "screen_size_inches": null,
    "layout_size": null, "volume_scope": "current", "mute_scope": "current",
    "poll_interval_s": 6, "sleep_after_s": 300, "brightness": 80, "panel_power_off": false,
    "surface": "spi"
  },
  "layout_sizes": [ "..." ],
  "layout": { "...": "..." },
  "scope": { "volume": "all", "mute": "all" },
  "runtime": { "...": "..." }
}
```

  with HTTP `200`. The `screen` object in this response echoes the **still-effective**
  (previous, on-disk) settings, not the rejected request. The on-disk configuration is
  left unchanged, so a reboot returns to the last working profile rather than booting into
  a broken panel every time.
- `restart_required` is omitted from the `screen_apply_failed` response body (it is only
  present on the `ok: true` path). `screen_type` changes themselves are always applied
  live, without a process restart, whether they succeed or fail - apply-then-persist
  gating is specific to `screen_type` and does not apply to `touch_type` (a `touch_type`
  change can never fail to "apply" in this sense, since it does nothing live at all; it is
  always persisted, and its effect is deferred to the next restart - see `restart_required`
  above).

### `GET /sdcard-health`

Reports the dial's own SD card health state, the same shape the appliance's
`autostream_sysutils.sdcard_health_state()` produces, plus whether the user has
asked for monitoring and whether a probe is currently running:

```json
{
  "ok": true,
  "state": {
    "tool_present": true, "timer_enabled": true, "method": "auto",
    "check": "passed", "serial": "...", "at": "...", "reason": "",
    "card": { "manfid": 3, "oemid": "...", "name": "...", "serial": "...", "likely_supported": true },
    "health_percent": 87, "last_sampled_at": "2026-01-01T00:00:00Z"
  },
  "requested": true,
  "probe": { "running": false, "outcome": "passed", "reason": "", "finished_at": "2026-01-01T00:00:00Z" }
}
```

`requested` reflects the dial's persisted intent (`dial-settings.json`'s
`sd_health_monitoring`); it can differ from `state.timer_enabled` when a probe
is in flight or a previous enable failed. `probe` is the same shape `POST
/sdcard-health` returns, kept for the appliance to poll after starting a
change.

### `POST /sdcard-health`

Starts (or asks the dial to stop) the guarded SD card health probe. The probe
runs on its own thread; this returns at once and the appliance polls `GET
/sdcard-health` for the outcome.

Request body:

```json
{ "enabled": true, "method": "auto", "current_pin": "1234" }
```

- `enabled` (required, boolean): true to enable monitoring, false to disable it.
- `method` (optional, default `"auto"`): one of the dial's supported probe methods.
- `current_pin` (required only when the dial has a PIN set): matches the
  PIN check on `POST /screen/settings`.

Responses:

- `200 {"ok": true, "probe": {...}}` - the change was accepted and started (or,
  for a disable, applied).
- `400 {"ok": false, "error": "invalid_json" | "body_must_be_object" | "invalid_enabled" | "invalid_method"}`
- `403 {"ok": false, "error": "wrong_pin"}` / `429` rate limit, as on `POST /screen/settings`.
- `200 {"ok": false, "error": "tool_missing"}` - the SD card health tool is not
  installed on the dial (enable only).
- `200 {"ok": false, "error": "probe_running"}` - a probe is already in flight.

---

---

## 5. Changing the protocol

The client protocol's number is raised on a change that removes or renames a field, a part
or an intent argument that clients rely on. Adding optional fields or new intents does not
need a new number. Update this document before merging a change to the dial's own HTTP API
(section 4) or to the management proxy (section 3).
