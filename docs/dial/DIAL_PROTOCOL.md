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

Toggles mute across all currently selected OwnTone outputs. A snapshot of pre-mute volumes
is kept so the restore action can return each output to its original level; the pending
action (mute or restore) survives partial failures so a retry press completes the
interrupted operation rather than toggling back too early.

**Request body:**
```json
{"dial_id": "<id>"}
```

| Field | Type | Constraints |
|---|---|---|
| `dial_id` | string | Dial identity (20 lowercase hex chars); must be present in `dials.json` |

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
the action that was in progress — `true` while muting, `false` while restoring.)

**Failure responses (200 body, not HTTP error):**

| `error` | Meaning |
|---|---|
| `"config_error"` | Appliance configuration could not be loaded |
| `"backend_unavailable"` | OwnTone unreachable or returned an error |
| `"no_active_outputs"` | No outputs currently selected |
| `"all_outputs_failed"` | Every per-output update call failed |

**Authorization failure: 403** (empty body). Returned when `dial_id` is absent, empty, or
not present in `dials.json`. Matches `POST /api/dial/volume` behavior.

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
{"step_percent": 2, "pin_set": true, "name": "Hallway Dial", "version": "1.0.0", "auto_update": false, "update_channel": "stable"}
```

| Field | Type | Notes |
|---|---|---|
| `update_channel` | string | `"stable"` or `"dev"`. `stable` considers only full GitHub releases; `dev` considers the most recent release including pre-releases. PIN-gated when set via `POST /configure` (same protection as `name`, `step_percent`, `auto_update`). |

### `GET /recovery_status`

Returns 404 if no PIN recovery window is active; otherwise:
```json
{"active": true, "volume_confirmed": false}
```

`volume_confirmed` is set on the first clockwise encoder rotation during the window.

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

Returns the dial-owned effective screen-fitted setting and current runtime status.
Screen settings are owned and persisted by the dial; the main appliance never stores a
copy and always reads current values from this endpoint.

```json
{
  "ok": true,
  "screen": {
    "fitted": false,
    "rotate": false
  },
  "runtime": {
    "fitted": false,
    "rotate": false,
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
| `runtime.fitted` | bool | Effective fitted flag currently applied by the display manager |
| `runtime.rotate` | bool | Effective rotation flag currently applied by the display manager |
| `runtime.active` | bool | `true` when a non-no-op display path is open |
| `runtime.backend` | string | Selected backend name (e.g. `noop`, `adafruit_st7735s`) |
| `runtime.backend_loaded` | bool | `true` once backend imports and hardware open succeeded |
| `runtime.showing` | string | One of `logo`, `artwork`, or `noop` |
| `runtime.last_error` | string | Last non-fatal display/fetch/render error identifier, or `""` |
| `runtime.last_error_at` | number\|null | Unix timestamp for `last_error`, or `null` |
| `runtime.display_sleeping` | bool | `true` once the display has been idle for `display_idle_seconds` and the backend has blanked/slept it |
| `runtime.display_idle_seconds` | int | Seconds since idling began, capped at the 15-minute sleep threshold; resets to `0` while showing content |

Never returns secrets or provider artwork URLs.

### `POST /screen/settings`

Accepts the **complete** normalized screen settings object — this endpoint does not apply
partial patches. PIN behavior follows existing `POST /configure` semantics: if a dial PIN
is set, the request must include the current PIN in `current_pin`.

```json
{
  "current_pin": "1234",
  "screen": {
    "fitted": true,
    "rotate": false
  }
}
```

Successful response:

```json
{
  "ok": true,
  "screen": {
    "fitted": true,
    "rotate": false
  },
  "runtime": {
    "fitted": true,
    "rotate": false,
    "active": false,
    "backend": "noop",
    "backend_loaded": false,
    "showing": "noop",
    "last_error": "",
    "last_error_at": null,
    "display_sleeping": false,
    "display_idle_seconds": 0
  },
  "restart_required": false
}
```

`restart_required` is always `false`: the dial applies the fitted and rotate settings live
by starting or stopping the current display provider internally.

**Validation:**

- `fitted` must be a strict JSON boolean — `0`, `1`, `"true"`, and `"false"` are rejected.
- `rotate` is optional and defaults to `false` when omitted; when present it must also be a
  strict JSON boolean.
- A missing or non-object `screen`, a missing `fitted` field, or any unknown field inside
  `screen` returns HTTP `400`:
  ```json
  {"ok": false, "error": "invalid_screen_settings"}
  ```
- A wrong or missing `current_pin` when a PIN is set follows existing `POST /configure`
  PIN failure behavior (HTTP `403`/`429`).
- Persistence failures return HTTP `500`.
- A saved config whose runtime application fails may still return `ok: true` with
  `runtime.last_error` populated, provided the display manager degraded to no-op.

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
