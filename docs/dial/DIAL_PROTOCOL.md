# autostream dial — Protocol Specification

This document is the authoritative spec for the wire protocol between autostream dial devices
and autostream appliances. Breaking changes require a version bump and a new capability indicator
in the mDNS TXT record.

---

## 1. mDNS Service Types

### `_autostream-playing._tcp` — autostream appliance, runtime

Announced by an autostream appliance when at least one audio capture is active.
Deleted when the last capture stops.

| TXT field | Value | Meaning |
|---|---|---|
| `version` | e.g. `1.2.3` | Installed autostream version |
| `dial_api` | `v1` | `POST /api/dial/volume` is available |
| `audio_status` | `v1` | `GET /api/audio/status` is available |
| `dial_status` | `v1` | `POST /api/dial/status` is available |

A consumer that sees neither `dial_api` nor `audio_status` treats the appliance as a legacy
instance (pre-dial support) and skips it.

`dial_status=v1` is independent of `dial_api=v1`. An older appliance may support
`dial_api=v1` without supporting `dial_status=v1`.

Port: **80** (appliance HTTP server).

### `_autostream-dial._tcp` — dial device, always-on

Announced continuously by a dial device.

| TXT field | Value | Meaning |
|---|---|---|
| `id` | 20-char hex | Stable dial identity (used for authorization) |
| `name` | string | Human-readable display name |
| `version` | e.g. `1.0.0` | Installed dial firmware version |
| `pin_recovery` | `1` | PIN recovery window active (10-minute window only) |

Port: **7842** (dial HTTP server).

**Name constraints:** dial names are restricted to printable ASCII (0x20–0x7e) excluding `;`
(avahi field separator) and `|` (config delimiter). Names containing these characters are
rejected by `autostream_admin update-dial-service`.

---

## 2. autostream HTTP API (port 80)

### `GET /api/audio/status`

Unauthenticated. Returns a fresh snapshot of currently selected OwnTone outputs and playing
state. Added to `ALLOWLIST_PATHS` — no session or CSRF token required.

**Response schema:**
```json
{
  "playing": true,
  "outputs": ["Kitchen", "Living Room"]
}
```

| Field | Type | Notes |
|---|---|---|
| `playing` | bool | `true` if any capture is active |
| `outputs` | array\|null | Selected output names; `null` means state unknown |
| `error` | string | Present only on failure: `"backend_unavailable"` |

**Semantics:**
- `playing: false, outputs: []` — normal; no conflict with this appliance.
- `playing: true, outputs: []` — startup-pending/unknown (capture is starting, OwnTone selection
  not yet established). Treat the same as `outputs: null` — retry after 1–2 s.
- `outputs: null` — OwnTone unreachable or returned an error; state unknown. Do not treat as
  "no outputs in use".

Output IDs are not included. OwnTone assigns IDs locally per host (ALSA outputs get `"0"` on
every device), making them unsuitable for cross-host comparison. Names are the stable identifier.

---

### `POST /api/dial/volume`

UUID-in-body auth. Must be routed **before** `validate_csrf()` — no session or CSRF token
required.

**Request body:**
```json
{"dial_id": "<id>", "delta": 4}
```

| Field | Type | Constraints |
|---|---|---|
| `dial_id` | string | Dial identity (20 lowercase hex chars); must be present in `dials.json` |
| `delta` | int | Volume delta in percent; clamped to [-100, 100] |

**Success response (200):**
```json
{"ok": true, "volume": 59}
```

`volume` is the new master volume level (0–100) after applying the delta.

**Partial success (200):**
```json
{"ok": true, "volume": 59, "partial": true}
```

Some outputs updated successfully; others failed. Not all outputs failed.

**Failure responses (200 body, not HTTP error):**

| `error` | Meaning |
|---|---|
| `"invalid_delta"` | `delta` missing or not an integer |
| `"backend_unavailable"` | OwnTone unreachable or returned an error |
| `"no_active_outputs"` | No outputs currently selected |
| `"all_outputs_failed"` | Every per-output update call failed |

**Authorization failure: 403** (empty body). Returned when `dial_id` is absent, empty, or
not present in `dials.json`.

---

### `POST /api/dial/mute`

UUID-in-body auth. Must be routed **before** `validate_csrf()` — no session or CSRF token
required. Same authorization check as `POST /api/dial/volume`.

Applies an **explicit** mute or restore action across all currently selected OwnTone
outputs. The appliance never infers the action from its own volumes — the dial owns the
single fleet-wide toggle decision and states it, so every appliance in a fleet performs the
same action regardless of the level it happens to be sitting at. A snapshot of pre-mute
volumes is kept so the restore action can return each output to its original level.

Both actions are idempotent: `"mute"` on an already-silent selection and `"restore"` on an
already-audible one succeed as no-ops. A command lost to a timeout therefore self-corrects
on the next press rather than leaving that appliance inverted.

**Request body:**
```json
{"dial_id": "<id>", "action": "mute"}
```

| Field | Type | Constraints |
|---|---|---|
| `dial_id` | string | Dial identity (20 lowercase hex chars); must be present in `dials.json` |
| `action` | string | Exactly `"mute"` or `"restore"`. Required; case-sensitive |

**Success response (200) — muted:**
```json
{"ok": true, "muted": true}
```

**Success response (200) — restored:**
```json
{"ok": true, "muted": false}
```

**Partial success (200):**
```json
{"ok": true, "muted": true, "partial": true}
```

Some outputs updated successfully; others failed. Not all outputs failed. (`muted` reflects
the requested action — `true` for `"mute"`, `false` for `"restore"`.)

**Failure responses (200 body, not HTTP error):**

| `error` | Meaning |
|---|---|
| `"config_error"` | Appliance configuration could not be loaded |
| `"backend_unavailable"` | OwnTone unreachable or returned an error |
| `"no_active_outputs"` | No outputs currently selected |
| `"all_outputs_failed"` | Every per-output update call failed |

**Authorization failure: 403** (empty body). Returned when `dial_id` is absent, empty, or
not present in `dials.json`. Matches `POST /api/dial/volume` behavior.

**Invalid action: 400**
```json
{"ok": false, "error": "invalid_action"}
```

Returned when `action` is absent, not a string, or not exactly `"mute"` or `"restore"`.
Authorization is checked **before** the action, so an unauthorized caller receives 403
rather than 400 even when its action is well-formed — a rejection never reveals whether the
dial is authorized.

---

### `POST /api/dial/status`

UUID-in-body auth. Must be routed **before** `validate_csrf()` — no session or CSRF token
required. Read-only; no output mutation.

Advertised via `dial_status=v1` in the `_autostream-playing._tcp` TXT record.

**Request body:**
```json
{"dial_id": "<id>"}
```

**Success response (200) — outputs selected:**
```json
{
  "ok": true,
  "playing": true,
  "master_volume": 59,
  "selected_output_count": 2,
  "track_id": {
    "enabled": true,
    "state": "identified",
    "title": "Song",
    "artist": "Artist",
    "album": "Album",
    "artwork_url": "https://provider.example/artwork/3f8a91c2.jpg",
    "updated_at": 1783170000.0,
    "last_attempt_at": 1783169990.0
  }
}
```

**Success response (200) — no outputs selected:**
```json
{"ok": true, "playing": false, "master_volume": null, "selected_output_count": 0}
```

| Field | Type | Notes |
|---|---|---|
| `playing` | bool | `true` if any capture is currently active |
| `master_volume` | int\|null | Rounded arithmetic mean of selected output volumes; `null` when none selected |
| `selected_output_count` | int | Number of currently selected outputs |
| `track_id` | object | Grouped now-playing/track-identification state for authorized dials (see below) |

`master_volume` uses the same arithmetic-mean calculation as the home-page master control
and `POST /api/dial/volume`.

This `track_id` extension is part of the pre-public dial v1 contract — it is added to the
existing `dial_status=v1` response without a new mDNS capability indicator, during the
pre-release dial development phase.

#### `track_id` object

| Field | Type | Notes |
|---|---|---|
| `enabled` | bool | Whether track identification is enabled |
| `state` | string | One of `disabled`, `waiting_for_audio`, `analysing`, `identified`, `not_found`, `error` |
| `title` | string | Empty string when unavailable |
| `artist` | string | Empty string when unavailable |
| `album` | string | Empty string when unavailable |
| `artwork_url` | string | Provider artwork URL; empty string when no artwork is available |
| `updated_at` | number\|null | Unix timestamp of the last successful identification, or `null` |
| `last_attempt_at` | number\|null | Unix timestamp of the last identification attempt, or `null` |

`artwork_url` is empty unless `state` is `identified` and the matched track has a provider
artwork URL. This includes the `disabled` example below, and `waiting_for_audio`,
`analysing`, `not_found`, and `error` states, and identified results without artwork:

```json
{
  "ok": true,
  "playing": true,
  "master_volume": 59,
  "selected_output_count": 2,
  "track_id": {
    "enabled": false,
    "state": "disabled",
    "title": "",
    "artist": "",
    "album": "",
    "artwork_url": "",
    "updated_at": null,
    "last_attempt_at": null
  }
}
```

The endpoint remains read-only: it never fetches remote artwork or mutates track
identification state on the request path.

**Application failure responses (200 body):**

| `error` | Meaning |
|---|---|
| `config_error` | Appliance configuration could not be loaded |
| `backend_unavailable` | Audio backend (OwnTone) could not provide outputs |

**Authorization failure: 403** (empty JSON object `{}`). Returned when `dial_id` is absent,
empty, or not present in `dials.json`. Matches `POST /api/dial/volume` behavior.

This `403` is **not** intercepted by the main NGINX `error_page` directive (which only
intercepts 404, 502, 503, and 504), so the dial client receives the original HTTP `403`.

---

## 3. Main-appliance Dial Management Proxy

The main autostream appliance exposes dial management routes under `/api/dial/` that
are proxied to the individual dial's HTTP API (port 7842).

### Transport status vs semantic status

Direct dial responses retain their native HTTP semantics (see section 4 below). However,
the main appliance NGINX configuration intercepts statuses `404`, `502`, `503`, and `504`
and redirects them to an offline page. When the proxy produces one of those semantic
outcomes, it **tunnels** the error through browser HTTP `200` using the canonical error
shape described in `docs/API-ERROR-CONTRACT.md`.

Clients consuming proxy responses must therefore inspect `ok`, `error`, and
`error_status` — not only the transport HTTP status — to determine the outcome:

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
absence** — the dial was reached, but the requested resource is not active (for example,
`GET /recovery_status` returns `{"active": false}` with HTTP `404` when no PIN recovery
window is open).

### Non-intercepted target statuses

Target statuses not intercepted by NGINX (`400`, `403`, `429`, `500`) pass through to
the browser as native HTTP responses. These represent validation errors, authorization
failures, rate limiting, and persistence failures that the browser can handle directly
using the transport status.

### Direct volume endpoint

`POST /api/dial/volume` is a machine-to-machine endpoint called by the dial firmware, not
by a browser dial-management flow. Its native `403` authorization response and HTTP `200`
application-failure bodies are preserved unchanged and are not subject to the tunneling
contract above.

---

## 4. Dial HTTP API (port 7842)

### `POST /configure`

All fields optional. PIN required to change `name`, `step_percent`, `new_pin`, or `auto_update` if a PIN is set.

PIN recovery completion: include `"pin_recovery": true` with `"new_pin"` to complete recovery
without knowing the current PIN (window must be active and volume confirmed).

### `GET /configure`

Returns current dial settings.

**Response:**
```json
{"step_percent": 2, "pin_set": true, "name": "My Dial", "version": "1.0.0", "auto_update": false, "update_channel": "stable", "can_confirm_presence": true}
```

| Field | Type | Notes |
|---|---|---|
| `update_channel` | string | `"stable"` or `"dev"`. `stable` considers only full GitHub releases; `dev` considers the most recent release including pre-releases. PIN-gated when set via `POST /configure` (same protection as `name`, `step_percent`, `auto_update`). |
| `can_confirm_presence` | bool | Runtime truth, not config: `true` only if this dial actually constructed at least one input capable of confirming presence for PIN recovery — a working rotary encoder, a working button, or a running touch stack. `false` covers every other case, including a configured touch panel whose driver failed to construct at startup. Set once at startup after input construction finishes; a dial polled before that finishes reports `false`. |

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
| `volume_confirmed` | bool | Historical field name — it means "presence confirmed", not specifically a volume change. Set `true` by any deliberate physical input on the dial: a touch anywhere on the panel, a physical button press, or the rotary encoder turned in either direction (previously only a clockwise turn, or a nudge sent over the local control socket, counted — that left touch-only, button-only, and screen-only dials unable to ever confirm presence). Once set, stays `true` for the rest of the window. |
| `recovery_remaining_ms` | int | Milliseconds left in the 10-minute recovery window, clamped at 0. `0` whenever no window is active. Lets a client show a countdown and detect expiry without polling `active` alone. |
| `can_confirm_presence` | bool | Same runtime-truth field documented under `GET /configure` above. |

### `POST /update`

Triggers a firmware update. Returns immediately:
```json
{"ok": true}
```

### `GET /update/status`

```json
{"state": "idle", "version": "1.0.0"}
```

`state` is one of `"idle"`, `"running"`, `"complete"`, `"failed"`.

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
    "touch_type": "none"
  },
  "supported": [
    {"key": "st7735s_160x128", "text": "ST7735S (128x160)"},
    {"key": "st7735s_128x128", "text": "ST7735S (128x128)"},
    {"key": "st7789_240x240", "text": "ST7789 (240x240)"},
    {"key": "st7789_320x240", "text": "ST7789 (240x320)"},
    {"key": "ili9341_320x240", "text": "ILI9341 (320x240)"}
  ],
  "supported_touch": [
    {"key": "none", "text": "None"},
    {"key": "xpt2046", "text": "Resistive (XPT2046/HR2046)"},
    {"key": "ft6206", "text": "Capacitive (FT6206/FT6236)"}
  ],
  "runtime": {
    "fitted": false,
    "rotate": false,
    "screen_type": "st7735s_160x128",
    "bgr": false,
    "touch_type": "",
    "active": false,
    "backend": "noop",
    "backend_loaded": false,
    "showing": "noop",
    "last_error": "",
    "last_error_at": null,
    "display_sleeping": false,
    "display_idle_seconds": 0
  }
}
```

| Field | Type | Notes |
|---|---|---|
| `screen.fitted` | bool | Persisted screen-fitted setting |
| `screen.rotate` | bool | Persisted screen-rotation setting; `true` rotates the display 180 degrees. Optional, defaults to `false` |
| `screen.screen_type` | string | Persisted display profile key. Optional, defaults to the dial's default profile |
| `screen.bgr` | bool | Persisted colour-order swap setting. Optional, defaults to `false` |
| `screen.touch_type` | string | Persisted touch controller key. Optional, defaults to `"none"` (touch disabled). An unrecognised value is rejected outright — see **Validation** under `POST /screen/settings` below |
| `supported` | array | Catalogue of display profiles this dial firmware supports, as `[{"key", "text"}, ...]` — see **Supported profiles** below |
| `supported_touch` | array | Catalogue of touch controllers this dial firmware supports, as `[{"key", "text"}, ...]`. **This is a separate capability from `supported`** — see **Touch capability gate** below |
| `runtime.fitted` | bool | Effective fitted flag currently applied by the display manager |
| `runtime.rotate` | bool | Effective rotation flag currently applied by the display manager |
| `runtime.screen_type` | string | The **active** display profile key — see **Configured vs. active** below |
| `runtime.bgr` | bool | The **active** colour-order swap setting — see **Configured vs. active** below |
| `runtime.touch_type` | string | The **active** touch controller key, or `""` when no touch stack is running (including on a dial with no touch code wired up at all) |
| `runtime.active` | bool | `true` when a non-no-op display path is open |
| `runtime.backend` | string | Name of the currently active driver (e.g. `noop`, `adafruit_st7735s`) |
| `runtime.backend_loaded` | bool | `true` once backend imports and hardware open succeeded |
| `runtime.showing` | string | One of `logo`, `artwork`, or `noop` |
| `runtime.last_error` | string | Last non-fatal display/fetch/render error identifier, or `""` |
| `runtime.last_error_at` | number\|null | Unix timestamp for `last_error`, or `null` |
| `runtime.display_sleeping` | bool | `true` once the display has been idle for `display_idle_seconds` and the backend has blanked/slept it |
| `runtime.display_idle_seconds` | int | Seconds since idling began, capped at the 15-minute sleep threshold; resets to `0` while showing content |

Never returns secrets or provider artwork URLs.

**Supported profiles.** `supported` is the catalogue of display profiles this dial
firmware knows how to drive. `key` is the opaque value a client sends back in
`screen.screen_type` to select that profile; `text` is a display label for presenting the
choice to a user. **Both `key` and `text` are opaque to clients** — clients must not parse
either string for meaning (e.g. extracting dimensions from the label), and must render
only what the dial itself published in `supported`. Sorting the list by `text` for
presentation is fine; inferring structure from its contents is not.

**Configured vs. active.** `screen.screen_type`/`screen.bgr` are the persisted
configuration; `runtime.screen_type`/`runtime.bgr` are what the display manager currently
has open. These normally match. They can diverge when a live profile swap fails to open
the new panel — see **Apply-then-persist** under `POST /screen/settings` below — in which
case `runtime` keeps reporting the last-known-working (degraded or previous) state while
`screen` reflects what is actually persisted on disk. Clients can compare
`screen.screen_type` with `runtime.screen_type` to detect this drift. `runtime.backend`
names the driver currently active for `runtime.screen_type` (e.g. `adafruit_st7735s`,
`noop` if no panel is open).

**Capability gate.** `screen_type` and `bgr` are a single joint capability, advertised by
the presence of a non-empty `supported` array in this response. See **Capability gate /
compatibility** under `POST /screen/settings` below — this is the cross-firmware-version
contract clients must follow before ever sending `screen.screen_type` or `screen.bgr`.

**Touch capability gate.** `supported_touch` is a **separate capability from `supported`**.
A dial can advertise display profiles in `supported` while knowing nothing at all about
touch — its firmware may predate touch support entirely. A client must not send
`screen.touch_type` to a dial that did not advertise a non-empty `supported_touch` array,
and must not infer touch support from the presence (or non-emptiness) of `supported` — the
two capabilities are independent and must be checked independently. Sending `touch_type` to
firmware that never advertised `supported_touch` hits the same strict field whitelist
described under **Capability gate / compatibility** below, and rejects the **entire**
request with `invalid_screen_settings` — including any otherwise-valid `fitted`/`rotate`
changes bundled in the same request.

### `POST /screen/settings`

Accepts the **complete** normalized screen settings object — this endpoint does not apply
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

Successful response:

```json
{
  "ok": true,
  "screen": {
    "fitted": true,
    "rotate": false,
    "screen_type": "st7735s_160x128",
    "bgr": false,
    "touch_type": "xpt2046"
  },
  "runtime": {
    "fitted": true,
    "rotate": false,
    "screen_type": "st7735s_160x128",
    "bgr": false,
    "touch_type": "",
    "active": false,
    "backend": "noop",
    "backend_loaded": false,
    "showing": "noop",
    "last_error": "",
    "last_error_at": null,
    "display_sleeping": false,
    "display_idle_seconds": 0
  },
  "restart_required": true
}
```

(`runtime.touch_type` in this example still reads `""` because a touch controller change
does not apply live — see **`restart_required`** below; the running process is still the
one started with the previous `touch_type`.)

`restart_required` reports whether **this specific POST** requires a dial service restart
before it is fully applied. `fitted`, `rotate`, `screen_type`, and `bgr` all apply live —
the dial starts, stops, or swaps the current display provider internally, with no restart
needed for any of them. `touch_type` is the one exception: the touch stack (driver, filter,
state machine) is built once at dial process startup from the persisted controller choice,
so a `touch_type` change is saved immediately but has no live effect — the previous touch
controller (or no touch at all) keeps running until the dial service next restarts.
`restart_required` is `true` exactly when the request changed `touch_type` from its
previously-persisted value, and `false` otherwise.

**Capability gate / compatibility.** `screen_type` and `bgr` form **one joint capability**,
advertised by `GET /screen/settings` returning a non-empty `supported` array (see above).
This is the cross-version contract between clients and dial firmware:

- A client **must not** send `screen.screen_type` or `screen.bgr` to a dial that did not
  advertise a non-empty `supported` array. Older firmware validates `screen` against a
  strict field whitelist and rejects the **entire** request with HTTP `400`
  `invalid_screen_settings` if either field is present — including otherwise-valid
  `fitted`/`rotate` changes bundled in the same request.
- Conversely, newer firmware accepts a request that omits both `screen_type` and `bgr`
  (they are optional and default), so an older client that only ever sends
  `fitted`/`rotate` keeps working unchanged against newer dials.

`touch_type` follows the identical rule as its **own, separate** capability — see **Touch
capability gate** above: gate on `supported_touch`, not on `supported`.

**Validation:**

- `fitted` must be a strict JSON boolean — `0`, `1`, `"true"`, and `"false"` are rejected.
- `rotate` is optional and defaults to `false` when omitted; when present it must also be a
  strict JSON boolean.
- `bgr` is optional and defaults to `false` when omitted; when present it must also be a
  strict JSON boolean.
- `screen_type` is optional and defaults to the dial's default profile when omitted; when
  present it must be a string naming a profile key present in `supported`. An unknown
  value is rejected outright — it is never silently coerced to the default.
- `touch_type` is optional and defaults to `"none"` when omitted; when present it must be a
  string naming a controller key present in `supported_touch`. An unknown value is rejected
  outright, the same as `screen_type`.
- A missing or non-object `screen`, a missing `fitted` field, or any unknown field inside
  `screen` (including a `screen_type`/`bgr`/`touch_type` sent to firmware that doesn't
  support them — see the capability gates above) returns HTTP `400`:
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

- `fitted`, `rotate`, and `bgr` can never fail to apply, so they are always persisted
  regardless of runtime outcome — this part of the ordering is unchanged from before.
- If a `screen_type` change is requested while `fitted` is true and the new panel driver
  fails to open, the response is:
  ```json
  {
    "ok": false,
    "error": "screen_apply_failed",
    "screen": { "fitted": true, "rotate": false, "screen_type": "st7735s_160x128", "bgr": false },
    "runtime": { "...": "..." }
  }
  ```
  with HTTP `200`. The `screen` object in this response echoes the **still-effective**
  (previous, on-disk) settings, not the rejected request. The on-disk configuration is
  left unchanged, so a reboot returns to the last working profile rather than booting into
  a broken panel every time.
- `restart_required` is omitted from the `screen_apply_failed` response body (it is only
  present on the `ok: true` path). `screen_type` changes themselves are always applied
  live, without a process restart, whether they succeed or fail — apply-then-persist
  gating is specific to `screen_type` and does not apply to `touch_type` (a `touch_type`
  change can never fail to "apply" in this sense, since it does nothing live at all; it is
  always persisted, and its effect is deferred to the next restart — see `restart_required`
  above).

---

## 5. Capability Version Table

| Capability | Endpoint | Notes |
|---|---|---|
| `dial_api=v1` | `POST /api/dial/volume` | UUID-in-body, delta-only, fire-and-forget |
| `audio_status=v1` | `GET /api/audio/status` | Output names only; no IDs |
| `dial_status=v1` | `POST /api/dial/status` | UUID-auth, read-only live master volume |

`POST /api/dial/mute` is not advertised behind its own TXT capability. It uses the same
UUID-in-body authorization as `POST /api/dial/volume` and was added to the appliance API
without a new mDNS indicator, in the same manner as the `track_id` extension to
`dial_status=v1` (see §2). A dial firmware built against this protocol version can assume
`/api/dial/mute` is present; there is no runtime way to detect its absence via mDNS.

`action` became a required field on `/api/dial/mute` after the endpoint moved from an
implicit toggle to an explicit instruction. Strictly this is a schema break under the rules
below, but it was taken without a `v2` bump: the endpoint had no deployed dial firmware
relying on the old body, and there is no mDNS indicator that could have distinguished the
two forms anyway. A dial predating the change sends no `action` and receives 400.

Breaking changes (new `v2`):
- Any change to request/response schema that removes or renames required fields.
- A change to the authorization mechanism (UUID-in-body → something else).
- A change to the path of a `v1` endpoint.

Adding optional response fields or new endpoints does **not** require a version bump.

---

## 6. Breaking-Change Policy

1. Increment the version indicator in the mDNS TXT record (`dial_api=v2`, etc.).
2. Announce the new indicator in `_autostream-playing._tcp` alongside the old one during a
   transition period so older dial firmware continues to work.
3. Update this document before merging any change to a versioned endpoint.
4. Old indicators may be removed once no deployed dial firmware references them.
