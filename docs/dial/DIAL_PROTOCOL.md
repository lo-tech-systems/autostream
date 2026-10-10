# autostream dial - Protocol Specification

This document is the authoritative spec for the wire protocol between autostream dial devices
and autostream appliances. Breaking changes require a version bump and a new capability indicator
in the mDNS TXT record.

Out of scope: the dial's own loopback poll of its local Wi-Fi watcher (`GET
127.0.0.1:9080/network_status`, every 15 s) and its use of the local nginx offline-recovery
CGI (`POST 127.0.0.1/offline/reboot`) for the Restart action are dial-local, not part of the
appliance<->dial protocol, and are not documented here.

---

## 1. mDNS Service Types

### `_autostream-playing._tcp` - autostream appliance, runtime

Announced by an autostream appliance when at least one audio capture is active.
Deleted when the last capture stops.

| TXT field | Value | Meaning |
|---|---|---|
| `version` | e.g. `1.2.3` | Installed autostream version |
| `dial_api` | `v1` | `POST /api/dial/volume` is available |
| `audio_status` | `v1` | `GET /api/audio/status` is available |
| `dial_status` | `v1` | `POST /api/dial/status` is available |
| `dial_outputs` | `v1` | `POST /api/dial/outputs` and `POST /api/dial/outputs/set` are available |
| `dial_eq` | `v1` | `POST /api/dial/eq` and `POST /api/dial/eq/set` are available |
| `id` | 20 lowercase hex characters | This appliance's stable identity, matching the `appliance_id` returned by `POST /api/dial/status` (see below). Omitted entirely for an identity-less appliance. |

A consumer that sees neither `dial_api` nor `audio_status` treats the appliance as a legacy
instance (pre-dial support) and skips it.

`dial_status=v1` is independent of `dial_api=v1`. An older appliance may support
`dial_api=v1` without supporting `dial_status=v1`.

`id` lets a dial correlate this appliance across an `ip:port` change (a DHCP lease renewal,
a service re-register) without waiting for the next successful `POST /api/dial/status` -
the mDNS resolve alone is enough to know identity has not changed. A dial that has not been
authorized against this appliance's UUID yet has nothing to correlate and ignores the field.

Port: **80** (appliance HTTP server).

### `_autostream-dial._tcp` - dial device, always-on

Announced continuously by a dial device.

| TXT field | Value | Meaning |
|---|---|---|
| `id` | 20-char hex | Stable dial identity (used for authorization) |
| `name` | string | Human-readable display name |
| `version` | e.g. `1.0.0` | Installed dial firmware version |
| `pin_recovery` | `1` | PIN recovery window active (10-minute window only) |

Port: **7842** (dial HTTP server).

**Name constraints:** dial names are restricted to printable ASCII (0x20-0x7e) excluding `;`
(avahi field separator) and `|` (config delimiter). Names containing these characters are
rejected by `autostream_admin update-dial-service`.

### `_autostream._tcp` - autostream appliance, always-on

Announced continuously by an autostream appliance, whether or not a capture is currently
active - unlike `_autostream-playing._tcp` above, which is announced only while playing. A
dial's own second mDNS browser, started only once a screen is fitted, scans this service
type to build a roster that also covers idle appliances, so a dial can bind to (and poll
`POST /api/dial/status` and send repeat commands against) an appliance that is not
currently playing - the repeat/replay picker's "idle focus".

| TXT field | Value | Meaning |
|---|---|---|
| `id` | 20 lowercase hex characters | This appliance's stable identity, same meaning as `id` on `_autostream-playing._tcp` |
| `version` | e.g. `1.2.3` | Installed autostream version |
| `dial_api` | `v1` | Gates the sighting the same way as on `_autostream-playing._tcp` - an appliance without it is not tracked for the dial's roster |
| `dial_status` | `v1` | `POST /api/dial/status` is available |
| `dial_outputs` | `v1` | `POST /api/dial/outputs` and `POST /api/dial/outputs/set` are available |
| `dial_eq` | `v1` | `POST /api/dial/eq` and `POST /api/dial/eq/set` are available |
| `repeat` | `v1` | Repeat recording/replay is enabled on this appliance; surfaced to the dial as `repeat_capable` in its roster |

This service also carries `ui`, `federation`, and `control` TXT fields used for
appliance-to-appliance federation (see `docs/APPLIANCE-FEDERATION.md`). The dial does not
read any of these three - authorization for what a dial can do with a rostered appliance
comes entirely from the per-dial UUID check on each protocol call, never from the
peer-control setting. `audio_status` is not carried here - it is specific to
`_autostream-playing._tcp`.

Port: **80** (appliance HTTP server, same as `_autostream-playing._tcp`).

---

## 2. autostream HTTP API (port 80)

### `GET /api/audio/status`

Unauthenticated. Returns a fresh snapshot of currently selected OwnTone outputs and playing
state. Added to `ALLOWLIST_PATHS` - no session or CSRF token required.

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
- `playing: false, outputs: []` - normal; no conflict with this appliance.
- `playing: true, outputs: []` - startup-pending/unknown (capture is starting, OwnTone selection
  not yet established). Treat the same as `outputs: null` - retry after 1-2 s.
- `outputs: null` - OwnTone unreachable or returned an error; state unknown. Do not treat as
  "no outputs in use".

Output IDs are not included. OwnTone assigns IDs locally per host (ALSA outputs get `"0"` on
every device), making them unsuitable for cross-host comparison. Names are the stable identifier.

---

### `POST /api/dial/volume`

UUID-in-body auth. Must be routed **before** `validate_csrf()` - no session or CSRF token
required. A dial under broadcast scope "all" (see **Broadcast scope** under
`GET /screen/settings`) may send this same request to several appliances at once for one
twist; nothing about the request or response changes for any of them.

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
{"ok": true, "volume": 59, "muted": false}
```

`volume` is the new master volume level (0-100) after applying the delta. `muted` reports
whether the appliance holds a mute after this request - see the mute-aware behavior below.

**Partial success (200):**
```json
{"ok": true, "volume": 59, "partial": true, "muted": false}
```

Some outputs updated successfully; others failed. Not all outputs failed.

**Muted behavior:** the appliance owns its own mute state (see `POST /api/dial/mute` below),
and this is the only endpoint that steps the master volume, so the mute-aware rule lives here
for every stepper client. While the appliance holds a mute, a non-positive `delta` is a no-op
that reports the level the outputs will return to on restore (never 0):

```json
{"ok": true, "volume": 59, "muted": true}
```

A positive `delta` while muted is instead a plain restore to the remembered pre-mute levels -
no step is added on top of it - and the response reports `muted: false`, exactly like an
explicit `POST /api/dial/mute {"action": "restore"}`.

**Failure responses (200 body, not HTTP error):**

| `error` | Meaning |
|---|---|
| `"invalid_delta"` | `delta` missing or not an integer |
| `"backend_unavailable"` | OwnTone unreachable or returned an error |
| `"no_active_outputs"` | No outputs currently selected |
| `"all_outputs_failed"` | Every per-output update call failed |

**Authorization failure: 403** (empty body). Returned when `dial_id` is absent, empty, or
not present in `dials.json`. Unlike `POST /api/dial/status` below, this endpoint does not
distinguish a definitive miss from a transiently unreadable dials store - both cases are
403 here.

---

### `POST /api/dial/mute`

UUID-in-body auth. Must be routed **before** `validate_csrf()` - no session or CSRF token
required. Same authorization check as `POST /api/dial/volume`. A dial under broadcast scope
"all" may send this same request to several appliances for one push, having already decided
the single `"mute"`/`"restore"` action they all receive (see **Broadcast scope** under
`GET /screen/settings`); nothing about the request or response changes for any of them.

Applies an **explicit** mute or restore action across all currently selected OwnTone
outputs. The appliance owns its own mute state (process memory, not persisted - see below)
and never infers the action from its own output volumes - alignment zeroes volumes for its
own reasons, and a user can drag a slider to 0, and neither of those is a mute. The caller
(the dial, or the WebUI's own master-volume icon through the equivalent browser-session
route) states the absolute action that flips whatever this appliance last reported, so every
appliance in a fleet performs the same action regardless of the level it happens to be
sitting at. The remembered pre-mute levels are kept only in the appliance's own memory, so
the restore action can return each output to the level it was at (or the level most recently
set for it while muted, if a client adjusted a slider or enabled an output in the meantime -
see `master_volume` below and the per-output docs).

Both actions are idempotent: `"mute"` on an already-silent selection and `"restore"` on an
already-audible one succeed as no-ops. A command lost to a timeout therefore self-corrects
on the next press rather than leaving that appliance inverted.

**No persistence.** The mute flag and remembered levels live only in the appliance's process
memory. A restarted appliance always comes back unmuted, with whatever raw volumes OwnTone
itself kept - `master_volume` then reports 0 for a selection that was muted before the
restart, `muted` reports `false`, and a mute press mutes an already-silent selection (a
no-op) while the next restore falls back to the configured default volume for any output at
0 with nothing remembered. This is expected behavior, not a fault.

**Outputs touched while muted.** An output enabled, or whose volume is changed, while the
appliance is muted stays silent: its requested level becomes what the restore action brings
it to, rather than being applied immediately. This applies uniformly across `POST
/api/output` (the browser), `POST /api/dial/outputs/set` (the dial) and federation - muted
means silent regardless of which client last touched an output.

**Request body:**
```json
{"dial_id": "<id>", "action": "mute"}
```

| Field | Type | Constraints |
|---|---|---|
| `dial_id` | string | Dial identity (20 lowercase hex chars); must be present in `dials.json` |
| `action` | string | Exactly `"mute"` or `"restore"`. Required; case-sensitive |

**Success response (200) - muted:**
```json
{"ok": true, "muted": true}
```

**Success response (200) - restored:**
```json
{"ok": true, "muted": false}
```

**Partial success (200):**
```json
{"ok": true, "muted": true, "partial": true}
```

Some outputs updated successfully; others failed. Not all outputs failed. (`muted` reflects
the requested action - `true` for `"mute"`, `false` for `"restore"`.)

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
rather than 400 even when its action is well-formed - a rejection never reveals whether the
dial is authorized.

---

### `POST /api/dial/status`

UUID-in-body auth. Must be routed **before** `validate_csrf()` - no session or CSRF token
required. Read-only; no output mutation.

Advertised via `dial_status=v1` in the `_autostream-playing._tcp` TXT record.

**Request body:**
```json
{"dial_id": "<id>"}
```

**Success response (200) - outputs selected:**
```json
{
  "ok": true,
  "playing": true,
  "master_volume": 59,
  "selected_output_count": 2,
  "muted": false,
  "track_id": {
    "enabled": true,
    "state": "identified",
    "title": "Song",
    "artist": "Artist",
    "album": "Album",
    "artwork_url": "https://provider.example/artwork/3f8a91c2.jpg",
    "updated_at": 1783170000.0,
    "last_attempt_at": 1783169990.0
  },
  "repeat": {
    "available": true,
    "state": "hold",
    "armed": false,
    "held": true,
    "recording_seconds": 342.0,
    "replay": {
      "active": false,
      "position_seconds": 0.0,
      "duration_seconds": 0.0
    }
  }
}
```

**Success response (200) - no outputs selected:**
```json
{"ok": true, "playing": false, "master_volume": null, "selected_output_count": 0, "muted": false, "appliance_id": "a1b2c3d4e5f6a7b8c9d0"}
```

| Field | Type | Notes |
|---|---|---|
| `playing` | bool | `true` if any capture is currently active |
| `master_volume` | int\|null | Rounded arithmetic mean of selected output volumes; `null` when none selected |
| `selected_output_count` | int | Number of currently selected outputs |
| `muted` | bool | `true` while the appliance holds a mute. While `true`, `master_volume` reports the level the outputs will return to on restore, never 0 - see `POST /api/dial/mute` |
| `track_id` | object | Grouped now-playing/track-identification state for authorized dials (see below) |
| `repeat` | object | Repeat-recording/replay state (see below). Omitted entirely when the daemon has never reported it (older monitor binary, or no poll yet) |
| `appliance_id` | string\|null | This appliance's stable identity (20 lowercase hex characters), or `null` for an identity-less appliance |

`master_volume` uses the same arithmetic-mean calculation as the home-page master control
and `POST /api/dial/volume`; `muted` is an explicit flag the appliance sets and clears from
mute/restore actions, never inferred from `master_volume` being 0 (a client can drag every
output to 0 without that being a mute).

This `track_id` extension is part of the pre-public dial v1 contract - it is added to the
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
  "muted": false,
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

#### `repeat` object

| Field | Type | Notes |
|---|---|---|
| `available` | bool | Whether repeat recording is enabled in settings |
| `state` | string | One of `idle`, `recording`, `hold`, `replaying`, `fading_out` (the daemon's internal admission-window state reads as `idle` here) |
| `armed` | bool | Whether replay is armed |
| `held` | bool | `true` exactly when `state` is `hold` - a retained recording with nothing currently playing |
| `recording_seconds` | number | Length of the retained/in-progress recording, in seconds |
| `replay` | object | `active` (bool, `true` through `fading_out`), `position_seconds` (number), `duration_seconds` (number, stale when not replaying) |

`state == "hold"` is the "not currently playing" signal for the replay picker - not the
top-level `playing` flag above, which reflects the unified session tracker and is `true`
while replay is actively producing audio (through `fading_out`).

`repeat` is omitted from the response body entirely when the cached daemon status has never
reported a repeat block. A dial that has previously seen this key treats its absence as
transient (an OwnTone/monitor restart) and keeps its last known value rather than treating
the feature as gone.

**Application failure responses (200 body):**

| `error` | Meaning |
|---|---|
| `config_error` | Appliance configuration could not be loaded |
| `backend_unavailable` | Audio backend (OwnTone) could not provide outputs |
| `auth_unavailable` | The dial authorization store could not be read (transient - the dial does not demote a previously-authorized appliance on this response) |

**Authorization failure: 400** `{"ok": false, "error": "missing_dial_id"}`. Returned when
`dial_id` is absent, empty, or not a string. Checked before the dials store is ever read, so
a malformed request never touches the file.

**Authorization failure: 412** `{"ok": false, "error": "dial_not_authorized", "appliance_id": "<id>"|null}`.
Returned when `dial_id` is present but not authorized for this appliance (a definitive miss,
distinct from the transient `auth_unavailable` case above). `appliance_id` lets the dial
correlate the rejection with the appliance that issued it even if its `ip:port` has since
been reused by a different appliance on the network.

Unlike `POST /api/dial/volume` and `POST /api/dial/mute` (still `403`, see below), the status
route never returns `403` - a caller is either authorized (`200`), a definitive miss (`412`),
malformed (`400`), or the store is transiently unreadable (`200 auth_unavailable`).

`412` is not intercepted by the main NGINX `error_page` directive (which only intercepts
404, 502, 503, and 504), so the dial client receives the original HTTP `412`.

### `POST /api/dial/repeat`

UUID-in-body auth via the same authorization gate as `POST /api/dial/status` (`_dial_auth_gate`):
`400 missing_dial_id`, `412 dial_not_authorized`, `200 auth_unavailable`. Sends a
repeat-replay transport command - stop, or seek to a position. The dial only ever sends
seek `0` (used for Start); the API itself accepts any finite, non-negative position.

**Request body:**
```json
{"dial_id": "<id>", "action": "seek", "position_seconds": 0}
```

`action` is `"stop"` or `"seek"`. `position_seconds` applies only to `"seek"` (a `"stop"`
ignores it) and, when present, must be a finite, non-negative number; it defaults to `0`.

**Success response (200):**
```json
{"ok": true, "state": "replaying", "armed": true, "position_seconds": 0.0,
 "appliance_id": "a1b2c3d4e5f6a7b8c9d0"}
```

**Daemon-rejected response (200):**
```json
{"ok": false, "error": "source_active", "state": "recording", "armed": false,
 "appliance_id": "a1b2c3d4e5f6a7b8c9d0"}
```

| `error` | Meaning |
|---|---|
| `invalid_action` (`400`) | `action` is neither `"stop"` nor `"seek"` |
| `invalid_position` (`400`) | `position_seconds` is missing its default, not finite, or negative |
| `repeat_unavailable` | Repeat recording is disabled in settings |
| `no_recording` | Nothing retained to replay |
| `source_active` | A live capture (or the daemon's admission window) is in progress |
| `fading_out` | A stop is already fading out; a seek is refused until playback lands in `hold` |
| `rate_limited` | A seek arrived less than one second after the previous one - `stop` is never rate-limited and is idempotent (the daemon acks `ok:true` in every state) |
| `backend_unavailable` | The daemon is unreachable, or returned an error this appliance version does not recognise (for example an older daemon rejecting the command outright) |

This route never reads the cached repeat status from `POST /api/dial/status` - the response
is built entirely from the daemon's own transport acknowledgement, so it can never be stale
relative to the command that produced it.

### `POST /api/dial/repeat/arm`

UUID-in-body auth via the same `_dial_auth_gate` guard as `POST /api/dial/status`. Arms or
disarms repeat replay. Allowed in every daemon state - the daemon's own state machine
decides what arming means in each one (arming while recording, for example, has no visible
effect until the recording lands in `hold`).

**Request body:**
```json
{"dial_id": "<id>", "armed": true}
```

**Responses:** same shape as `POST /api/dial/repeat` above - `ok`, `state`, `armed`, and
`position_seconds` (only when `ok` is `true`), plus `appliance_id`.

| `error` | Meaning |
|---|---|
| `invalid_armed` (`400`) | `armed` is missing or not a boolean |
| `backend_unavailable` | The daemon is unreachable, or returned an error this appliance version does not recognise |

### `POST /api/dial/outputs`

UUID-in-body auth via the same `_dial_auth_gate` guard as `POST /api/dial/status`:
`400 missing_dial_id`, `412 dial_not_authorized`, `200 auth_unavailable`. Returns the
appliance's own output list -- the same filtering and remote-occupancy annotation the
setup page's output list uses. An output currently in use by another autostream instance
is left out entirely.

**Request body:**
```json
{"dial_id": "<id>"}
```

**Success response (200):**
```json
{"ok": true, "appliance_id": "a1b2c3d4e5f6a7b8c9d0", "outputs": [
  {"id": "1", "name": "Living Room", "selected": true, "volume": 42, "remote_in_use": false}
]}
```

| `error` | Meaning |
|---|---|
| `backend_unavailable` | OwnTone is unreachable or returned a failure |
| `config_error` | The appliance configuration could not be loaded |

### `POST /api/dial/outputs/set`

UUID-in-body auth via the same `_dial_auth_gate` guard. Enables, disables or changes the
volume of one output through the same mutation the setup page uses. Enabling without an
explicit `volume` applies the configured default volume; a volume change on an
already-enabled output and a disable pass through untouched.

**Request body:**
```json
{"dial_id": "<id>", "id": "1", "selected": true, "volume": 60}
```

`volume` is optional on an enable (the configured default applies); it is ignored on a
disable.

**Responses:** the underlying mutation's own result plus `appliance_id` -- `{"ok": true,
"id": "1"}` on success, or an `ok:false` dict carrying one of `output_in_use`,
`pin_required`, `encoder_capacity`, or a backend error message. The dial does not
special-case any of these; it refetches `POST /api/dial/outputs` and shows the truth.

| `error` (`400`) | Meaning |
|---|---|
| `missing_output_id` | `id` is missing or empty |
| `invalid_request_body` | `selected` is missing or not a boolean (the dial never sends `op`) |

### `POST /api/dial/eq`

UUID-in-body auth via the same `_dial_auth_gate` guard. Returns the bass and treble
values the dial's Equaliser page shows, read from the stored output EQ bands.

**Request body:**
```json
{"dial_id": "<id>"}
```

**Success response (200):**
```json
{"ok": true, "appliance_id": "a1b2c3d4e5f6a7b8c9d0", "bass_db": 2, "treble_db": -1}
```

| `error` | Meaning |
|---|---|
| `config_error` | The appliance configuration could not be loaded |

### `POST /api/dial/eq/set`

UUID-in-body auth via the same `_dial_auth_gate` guard. Sets an absolute bass and/or
treble value -- the dial computes its own clamped target (`clamp(shown + delta, -6,
+6)`) and sends the result, exactly as the per-output volume steppers do; this
appliance clamps again defensively.

Bass sets `peq1_db` (40 Hz low-shelf) and `peq2_db` (100 Hz peak) to the same value.
Treble sets `peq6_db` (10 kHz high-shelf) to the full value and `peq5_db` (4 kHz peak)
to half of it. `peq3_db`/`peq4_db` (300 Hz/1 kHz) are never touched by either field.
Both fields are saved and applied to the running monitor in a single update.

**Request body:**
```json
{"dial_id": "<id>", "bass_db": 2, "treble_db": -1}
```

At least one of `bass_db`/`treble_db` must be present; either may be sent alone.

**Success response (200):** the same shape as `POST /api/dial/eq` above -- the
read-back `bass_db`/`treble_db`, rounded and clamped to +/-6 dB, after the write.

| `error` | Meaning |
|---|---|
| `invalid_request_body` (`400`) | Neither field present, or a present field is not an integer (or is a boolean) |
| `eq_apply_failed` | The monitor daemon is unreachable; the stored config is still updated |

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

### Direct volume endpoint

`POST /api/dial/volume` is a machine-to-machine endpoint called by the dial firmware, not
by a browser dial-management flow. Its native `403` authorization response and HTTP `200`
application-failure bodies are preserved unchanged and are not subject to the tunneling
contract above.

### Recovery arm/disarm endpoints

`POST /api/dial/recovery/arm` and `POST /api/dial/recovery/disarm` proxy to the dial's
`POST /recovery/arm` and `POST /recovery/disarm` respectively (see section 4). Unlike the
direct volume endpoint above, these are browser dial-management routes: the main appliance
requires its own authenticated session before proxying the request - the same
`require_authenticated_if_pin_enabled` gate applied to `/api/dial/configure` and the other
dial-management routes. The dial itself does not check a PIN on either endpoint; session
authentication on the appliance side is what stands in for it. See **`POST /recovery/arm`**
under section 4 for why.

---

## 4. Dial HTTP API (port 7842)

### `POST /configure`

All fields optional. PIN required to change `name`, `step_percent`, `new_pin`,
`auto_update`, or `update_channel` if a PIN is set.

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
{"step_percent": 2, "pin_set": true, "name": "My Dial", "version": "1.0.0", "auto_update": false, "update_channel": "stable", "can_confirm_presence": true}
```

| Field | Type | Notes |
|---|---|---|
| `update_channel` | string | `"stable"` or `"dev"`. `stable` considers only full GitHub releases; `dev` considers the most recent release including pre-releases. PIN-gated when set via `POST /configure` (same protection as `name`, `step_percent`, `auto_update`). |
| `can_confirm_presence` | bool | Runtime truth, not config: `true` only if this dial actually constructed at least one input capable of confirming presence for PIN recovery - a working rotary encoder, a working button, or a running touch stack. `false` covers every other case, including a configured touch panel whose driver failed to construct at startup. Set once at startup after input construction finishes; a dial polled before that finishes reports `false`. |

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

### `POST /auth-changed`

Advisory, appliance-initiated notification that a given `appliance_id`'s dial authorization
may have changed. Fired by the main appliance (fire-and-forget, one retry after a short
delay on failure) immediately after its own `POST /api/dial/authorize` or `POST
/api/dial/revoke` handler responds, so an already-open dial screen or an in-flight status
poll can react without waiting for its next scheduled tick.

**No PIN required, and never authenticated** - anyone on the LAN can reach port 7842, so
this endpoint grants nothing by itself: it only causes the dial to enqueue a probe, and
only when the source IP matches a sighting the dial has already rostered for that
`appliance_id` (see `_autostream-playing._tcp`/`_autostream._tcp` above). Authorization
truth for the dial protocol routes still comes entirely from the dial's own status poll.

**Request body:**
```json
{"appliance_id": "a1b2c3d4e5f6a7b8c9d0"}
```

**Response:** always `202 {"ok": true}`, whether or not the id is known, rostered, or
rate-limited - the response must never leak that information to an unauthenticated caller.

| `error` (`400`) | Meaning |
|---|---|
| `invalid_json` | Body is not valid JSON |
| `body_must_be_object` | JSON root is not an object |
| `invalid_appliance_id` | `appliance_id` missing or not 20 lowercase hex characters |

**Rate limiting.** At most one accepted push per source IP every 2 seconds, and per
`appliance_id` every 5 seconds; a push outside these windows is still answered `202` but
never enqueued. This limits the probes a single caller (or a spoofed source) can trigger,
not the endpoint's own reachability.

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
    "touch_type": "none",
    "always_show_controls": false,
    "screen_size_inches": null,
    "layout_size": null,
    "volume_scope": "current",
    "mute_scope": "current"
  },
  "supported": [
    {"key": "st7735s_160x128", "text": "ST7735S (128x160)", "default_inches": 1.8},
    {"key": "st7735s_128x128", "text": "ST7735S (128x128)", "default_inches": 1.44},
    {"key": "st7789_240x240", "text": "ST7789 (240x240)", "default_inches": 1.3},
    {"key": "st7789_320x240", "text": "ST7789 (240x320)", "default_inches": 2.8},
    {"key": "ili9341_320x240", "text": "ILI9341 (320x240)", "default_inches": 2.8}
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
| `runtime.display_idle_seconds` | int | Seconds since idling began, capped at the 15-minute sleep threshold; resets to `0` while showing content |

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
the presence of a non-empty `supported` array in this response. See **Capability gate /
compatibility** under `POST /screen/settings` below - this is the cross-firmware-version
contract clients must follow before ever sending `screen.screen_type` or `screen.bgr`.

**Touch capability gate.** `supported_touch` is a **separate capability from `supported`**.
A dial can advertise display profiles in `supported` while knowing nothing at all about
touch - its firmware may predate touch support entirely. A client must not send
`screen.touch_type` to a dial that did not advertise a non-empty `supported_touch` array,
and must not infer touch support from the presence (or non-emptiness) of `supported` - the
two capabilities are independent and must be checked independently. Sending `touch_type` to
firmware that never advertised `supported_touch` hits the same strict field whitelist
described under **Capability gate / compatibility** below, and rejects the **entire**
request with `invalid_screen_settings` - including any otherwise-valid `fitted`/`rotate`
changes bundled in the same request.

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
`volume_scope` "all", `POST /api/dial/volume` sends the same delta to every playing
appliance; each applies the delta to its own master volume and its own muted-volume rule (see
that endpoint below) - nothing about the request or response changes. Under `mute_scope`
"all", the dial decides one fleet-wide action from a fresh `POST /api/dial/status` sweep of
every playing appliance taken at the moment of the push: `"mute"` when any of them reports
`muted: false` (or no `muted` field at all), `"restore"` only when every one of them reports
`muted: true`. This decision is made once per push, not once per appliance, so the whole
fleet ends up in the same state even if it started mixed.

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
    "mute_scope": "current"
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

**Capability gate / compatibility.** `screen_type` and `bgr` form **one joint capability**,
advertised by `GET /screen/settings` returning a non-empty `supported` array (see above).
This is the cross-version contract between clients and dial firmware:

- A client **must not** send `screen.screen_type` or `screen.bgr` to a dial that did not
  advertise a non-empty `supported` array. Older firmware validates `screen` against a
  strict field whitelist and rejects the **entire** request with HTTP `400`
  `invalid_screen_settings` if either field is present - including otherwise-valid
  `fitted`/`rotate` changes bundled in the same request.
- Conversely, newer firmware accepts a request that omits both `screen_type` and `bgr`
  (they are optional and default), so an older client that only ever sends
  `fitted`/`rotate` keeps working unchanged against newer dials.

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
      "layout_size": null, "volume_scope": "current", "mute_scope": "current"
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

---

## 5. Capability Version Table

| Capability | Endpoint | Notes |
|---|---|---|
| `dial_api=v1` | `POST /api/dial/volume` | UUID-in-body, delta-only, fire-and-forget |
| `audio_status=v1` | `GET /api/audio/status` | Output names only; no IDs |
| `dial_status=v1` | `POST /api/dial/status` | UUID-auth, read-only live master volume |
| `dial_outputs=v1` | `POST /api/dial/outputs`, `POST /api/dial/outputs/set` | UUID-auth; per-output enable and volume |
| `dial_eq=v1` | `POST /api/dial/eq`, `POST /api/dial/eq/set` | UUID-auth; bass/treble over the output EQ bands |
| `repeat=v1` | (roster only) | Advertised on `_autostream._tcp`, not `_autostream-playing._tcp` - see section 1. Gates the `repeat_capable` flag in the dial's idle-inclusive roster, not any single endpoint; a repeat command is still sent through `POST /api/dial/repeat`/`POST /api/dial/repeat/arm` above regardless of this flag, and the daemon itself rejects it (`repeat_unavailable`) if recording is disabled |

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

The `muted` field on `POST /api/dial/status` and `POST /api/dial/volume`'s response is a
later, purely additive change: the appliance moved from an implicit "master_volume 0 means
muted" convention to an explicit flag, kept in process memory (see `POST /api/dial/mute`
above). No version bump - a dial built before this change simply never reads the field, and
falls back to inferring mute from a reported 0, which is wrong for as long as the appliance
holds a mute (it now reports the pre-mute level, not 0) but self-corrects the moment either
side sends an explicit mute/restore action or the appliance stops being muted. A dial built
after this change talking to an appliance that predates it just never sees the field and
shows no lit glyph, which volume/mute presses still work through regardless (they are
explicit actions, not inferred from what the glyph shows). Appliances are expected to deploy
ahead of dials for this reason.

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
