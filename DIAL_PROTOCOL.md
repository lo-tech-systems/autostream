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

A consumer that sees neither `dial_api` nor `audio_status` treats the appliance as a legacy
instance (pre-dial support) and skips it.

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
{"step_percent": 2, "pin_set": true, "name": "Hallway Dial", "version": "1.0.0", "auto_update": false}
```

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

---

## 5. `dial_api=v1` Version Table

| Version | Endpoint | Notes |
|---|---|---|
| `v1` | `POST /api/dial/volume` | UUID-in-body, delta-only, fire-and-forget |
| `v1` | `GET /api/audio/status` | Output names only; no IDs |

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
