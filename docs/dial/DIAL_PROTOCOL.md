# autostream dial - Protocol Specification

This document is the authoritative spec for the wire protocol between autostream dial devices
and autostream appliances. Breaking changes require a version bump and a new capability indicator
in the mDNS TXT record.

Out of scope: the dial's own loopback poll of its local Wi-Fi watcher (`GET
127.0.0.1:9080/network_status`, every 15 s) and its use of the local nginx offline-recovery
CGI (`POST 127.0.0.1/offline/reboot`) for the Restart action are dial-local, not part of the
appliance<->dial protocol, and are not documented here. So is the HD page's own API, which
the dial serves on its loopback address (and, if switched on, on a development listener) to
the browser on the same board; see `HD-DIAL.md` and `ARCHITECTURE.md`. The only HD setting
that appears here is `hd_dev_access` (section 4).

---

## 1. mDNS Service Types

### `_autostream-playing._tcp` - autostream appliance, runtime

Announced by an autostream appliance when at least one audio capture is active.
Deleted when the last capture stops.

| TXT field | Value | Meaning |
|---|---|---|
| `version` | e.g. `1.2.3` | Installed autostream version |
| `dial_api` | `v1` | `POST /api/dial/volume` is available |
| `dial_proto` | `v3` | The appliance speaks the third dialect (see below). Absent on older appliances |
| `audio_status` | `v1` | `GET /api/audio/status` is available |
| `dial_status` | `v1` | `POST /api/dial/status` is available |
| `dial_outputs` | `v1` | `POST /api/dial/outputs` and `POST /api/dial/outputs/set` are available |
| `dial_eq` | `v1` | `POST /api/dial/eq` and `POST /api/dial/eq/set` are available |
| `id` | 20 lowercase hex characters | This appliance's stable identity, matching the `appliance_id` returned by `POST /api/dial/status` (see below). Omitted entirely for an identity-less appliance. |

A consumer that sees neither `dial_api` nor `audio_status` treats the appliance as a legacy
instance (pre-dial support) and skips it.

`dial_status=v1` is independent of `dial_api=v1`. An older appliance may support
`dial_api=v1` without supporting `dial_status=v1`.

`dial_proto` names the protocol dialect and is separate from `dial_api`, which stays `v1` so
that older dials keep tracking and controlling the appliance. `dial_proto=v2` or later means
the appliance sends typed refusals (`412` with `dial_not_authorized` and `appliance_id`) to a
dial that itself advertises `dial_proto=v2` or later, reports `muted` in its status and volume
replies, and carries `id` on the playing record. A dial that does not advertise at least
`dial_proto=v2`, and a dial the appliance has not seen, gets the older bare `403 {}`. A
consumer that sees no `dial_proto` treats the appliance as speaking the older dialect; an old
dial ignores the key. `dial_proto=v3` adds `GET /api/dial/capabilities` (section 2), which is
the authoritative list of what the appliance supports.

The capability keys in the TXT records are frozen at the values listed above. A later version
of a capability, such as the six-band EQ (`dial_eq` version 2), is announced only by
`GET /api/dial/capabilities`, so a dial that reads only the TXT records keeps working as before.

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
| `dial_sdmon` | `v1` | The dial exposes `GET`/`POST /sdcard-health` (section 4) and can run the guarded SD card health probe |
| `dial_proto` | `v3` | The dial speaks the third dialect (see below). It includes everything `v2` means: typed refusals on every route matched to an appliance by `appliance_id`, and `muted` treated as authoritative. Absent on older dials |

Port: **7842** (dial HTTP server).

#### Protocol dialect (`dial_proto`)

`dial_proto` is how each side tells the other which dialect it speaks. It is advertised by
appliances (on both appliance records) and by dials (on `_autostream-dial._tcp`).
`dial_api=v1` and `dial_status=v1` stay on the wire unchanged, so nothing that worked before
stops working. The value is `v` followed by a generation number, and each generation includes
everything the earlier ones mean, so a check is always "at least this generation". `v2` and
`v3` are defined. Anything that is not `v` and digits, or no key at all, means the older
dialect.

What `v3` adds to `v2`, on an appliance:

- **Capabilities endpoint.** `GET /api/dial/capabilities` exists and lists every capability
  the appliance supports with its version. The TXT capability keys keep their `v1` values.
- **Output owner.** `POST /api/dial/outputs` reports `remote_owner` for an output in use by
  another appliance.
- **Six-band EQ.** `POST /api/dial/eq` and `POST /api/dial/eq/set` carry `bands`; the
  capabilities endpoint reports `dial_eq` as `2`.
- **Appliance warnings.** `POST /api/dial/warnings` lists what the appliance wants a dial to
  show (wear and power supply notices); the capabilities endpoint reports `dial_warnings`
  as `1`.
- **Speaker pairing.** `POST /api/dial/outputs` reports `pin_pending`, `needs_auth_key` and
  `pin_claim`; `POST /api/dial/outputs/set` accepts a PIN; the capabilities endpoint reports
  `dial_outputs` as `2`.

What `v3` means, on a dial: it reads `GET /api/dial/capabilities` from an appliance that
advertises `v3` and uses the reply in place of the TXT capability keys, shows the six-band EQ,
fetches `POST /api/dial/warnings` from an appliance that reports `dial_warnings`, and accepts
`POST /warnings-changed` (section 4). An appliance sends the warnings push only to a dial that
advertises `v3`. From 0.7.0 a `v3` dial also accepts `POST /state-changed` (section 4), and a
0.7.0 appliance sends it to every sighted, authorised `v3` dial. A dial built before 0.7.0
answers 404, which the appliance treats as a failed send and backs off from; nothing else
happens.

What `v2` means:

- **Typed refusals.** An appliance answers an unauthorized dial that advertises
  `dial_proto=v2` with `412` and
  `{"ok": false, "error": "dial_not_authorized", "appliance_id": "<id>"|null}` on every dial
  route: status, volume, mute, repeat, outputs and EQ.
- **Identity.** The appliance's `id` is on its playing record, and `appliance_id` is in the
  status reply, so the dial can match a refusal to the appliance that sent it.
- **`muted` is authoritative.** Status and volume replies carry `muted`, and while the
  appliance is muted its reported volume is the pre-mute level, never 0. A v2 dial trusts the
  field and does not infer mute from the volume.

Legacy behaviour, when one side does not advertise `dial_proto=v2`:

- **Refusal style follows the requesting dial.** The appliance chooses between `412` and the
  older answer from the *dial's* advertised `dial_proto`, read from the dial's own mDNS
  record. A dial that advertises `dial_proto=v2` gets the typed `412`. Any other dial, and a
  dial the appliance has not currently seen on the network (so cannot tell which dialect it
  speaks), gets `403` with an empty JSON body, `{}`. The `400 missing_dial_id` and
  `200 auth_unavailable` answers are the same for both styles. Volume and mute use the same
  check as the other routes.
- **How a v2 dial reads a refusal.** A `403` whose body is exactly `{}` with a JSON content
  type, from an appliance that does not advertise `dial_proto=v2`, is read as a refusal. A
  `403` with any other body (a proxy or CSRF rejection, for example) is not. A `403` from an
  appliance that does advertise `dial_proto=v2` is treated as transient, because that
  appliance would have sent a `412`.
- **Status without `muted`.** An older appliance's status reply has no `muted` field. A v2
  dial then goes by the mute it last sent: a later status poll that says nothing about mute
  clears that belief instead of keeping it, so the dial follows a mute made elsewhere within
  a poll. The press itself stays protected while a mute request is in flight.
- **No `id` on the playing record.** An older appliance announces its `id` only on
  `_autostream._tcp`. A v2 dial looks for an `_autostream._tcp` record at the same IP address
  and port as the playing record and uses that record's `id`. The match is weaker than an `id`
  on the playing record itself: if an address changes hands between the two lookups, a refusal
  can be attributed to the wrong appliance until the next poll corrects it. An appliance whose
  `id` cannot be found this way is not controlled by the dial and does not wake the screen.
- **Older dials with a v2 appliance.** They keep tracking and controlling the appliance, since
  it still advertises `dial_api=v1`, and they ignore the extra fields in its replies. An
  unauthorized older dial is refused with the bare `403 {}`. The appliance's web UI shows
  "Dial updates required" on the Home page and flags the dial's card on the Setup page with
  "Needs update" while the dial advertises an older `dial_proto` generation than the
  appliance does. A dial at `v2` against a `v3` appliance keeps working through the TXT
  records and is flagged the same way.
- **Capabilities with their own keys** (`dial_outputs`, `dial_eq`, `repeat`) are unaffected.
  An older appliance does not advertise them, so a dial does not offer the features.

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
| `dial_proto` | `v3` | Same meaning as on `_autostream-playing._tcp` |
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

### `GET /api/dial/capabilities`

Unauthenticated, read-only, no request body. Available when the appliance advertises
`dial_proto=v3` or later. Added to `ALLOWLIST_PATHS` - no session or CSRF token required. It
discloses only what the mDNS records already broadcast (identity, version and capability
names with versions), so a dial can read it before it is authorized.

**Response:**
```json
{
  "ok": true,
  "appliance_id": "a1b2c3d4e5f6a7b8c9d0",
  "version": "0.7.0",
  "dial_proto": 3,
  "capabilities": {
    "dial_status": 1,
    "dial_outputs": 2,
    "dial_eq": 2,
    "repeat": 1,
    "audio_status": 1,
    "dial_warnings": 1
  }
}
```

| Field | Type | Notes |
|---|---|---|
| `ok` | bool | Always `true` |
| `appliance_id` | string\|null | The same identity as `id` in the mDNS records; `null` for an identity-less appliance |
| `version` | string | The same value as `version` in the mDNS records |
| `dial_proto` | integer | The generation number of the advertised `dial_proto` |
| `capabilities` | object | Capability name to integer version. A name that is absent means the appliance does not support it |

The capabilities are those listed in section 5. The list is fixed for a given software
version, so it changes only when `version` changes. A client should ignore names it does not
know. The reply is sent with `Cache-Control: no-store`.

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

**Authorization failure.** This route uses the same gate as `POST /api/dial/status` below:
`400 missing_dial_id` when `dial_id` is absent, empty or not a string; `200 auth_unavailable`
when the dials store is transiently unreadable; and for a definitive miss, `412
dial_not_authorized` (with `appliance_id`) to a dial that advertises `dial_proto=v2`, or `403`
with an empty JSON body (`{}`) to any other dial, including one the appliance has not
currently seen. See **Protocol dialect** in section 1.

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

**Authorization failure.** Same gate and same answers as `POST /api/dial/volume` above.

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
  "input": {"index": 1, "type": "turntable", "label": "Turntable"},
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
    "latency_ms": 2250,
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
{"ok": true, "playing": false, "master_volume": null, "selected_output_count": 0, "muted": false, "input": null, "appliance_id": "a1b2c3d4e5f6a7b8c9d0"}
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
| `input` | object\|null | The input behind the current session (see below); `null` when nothing is playing. Absent from a 0.6.x appliance |

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

Once the appliance accepts a repeat seek, stop or arm request, this status reflects the
result straight away rather than on the appliance's next internal refresh: the `repeat`
object shows the new state and position, and `playing` is `true` for an accepted replay.
Starting or seeking a replay also restarts track identification, so `track_id` reads
`waiting_for_audio` until a fresh identification lands, rather than continuing to show the
track from before the seek.

#### `input` object

| Field | Type | Rule |
|---|---|---|
| `input` | object or null | Present on every `ok: true` response from 0.7.0 on; absent on `ok: false` responses and from 0.6.x appliances. `null` when no session is active. Non-null whenever `playing` is true, except within one coordinator poll (0.5 s) of a session edge, when the two may briefly disagree |
| `input.index` | int | 1 or 2. During a replay, the input the recording came from |
| `input.type` | string | One of `turntable`, `cd`, `line`, lowercase. A later release may add tokens; a dial treats an unknown token as "some input" and still uses `label` |
| `input.label` | string | Display text, used verbatim: `Turntable`, `CD`, `Line`. Never empty when the object is present |

`type` and `label` reflect the appliance's current settings, so a mid-session type change is
visible on the next poll. The object rides on `dial_status=v1` without a new capability
indicator, like `track_id`.

#### `repeat` object

| Field | Type | Notes |
|---|---|---|
| `available` | bool | Whether repeat recording is enabled in settings |
| `state` | string | One of `idle`, `recording`, `hold`, `replaying`, `fading_out` (the daemon's internal admission-window state reads as `idle` here) |
| `armed` | bool | Whether replay is armed |
| `held` | bool | `true` exactly when `state` is `hold` - a retained recording with nothing currently playing |
| `recording_seconds` | number | Length of the retained/in-progress recording, in seconds |
| `replay` | object | `active` (bool, `true` through `fading_out`), `position_seconds` (number), `duration_seconds` (number, stale when not replaying) |
| `latency_ms` | int | The appliance's audio start buffer in milliseconds: how far the audio a listener hears trails `replay.position_seconds`. A dial that shows a replay timer subtracts it so the timer matches what is heard. Optional: a dial that does not receive it assumes 2000 ms (2.0 s), and ignores a value that is not a number between 0 and 10000 |

`latency_ms` is read from a cached copy of the appliance's start buffer setting, so a status
request never waits on the audio backend. A change made in the web interface shows on the
next status poll; a change made any other way can take up to about a minute to appear.
Appliances that predate the field simply omit it.

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
distinct from the transient `auth_unavailable` case above) and the dial advertises
`dial_proto=v2`. `appliance_id` lets the dial correlate the rejection with the appliance that
issued it even if its `ip:port` has since been reused by a different appliance on the network.

**Authorization failure: 403** `{}`. The same definitive miss, for a dial that does not
advertise `dial_proto=v2` or that the appliance has not currently seen on the network (see
**Protocol dialect** in section 1). The body is exactly the two bytes `{}` with a JSON content
type.

Every dial route (status, volume, mute, repeat, outputs, EQ) answers in the same four ways: a
caller is authorized, malformed (`400`), a definitive miss (`412` or `403` as above), or the
store is transiently unreadable (`200 auth_unavailable`).

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
is still listed, with `remote_in_use` set to `true` and `remote_owner` naming that
instance.

**Request body:**
```json
{"dial_id": "<id>"}
```

**Success response (200):**
```json
{"ok": true, "appliance_id": "a1b2c3d4e5f6a7b8c9d0", "outputs": [
  {"id": "1", "name": "Living Room", "selected": true, "volume": 42,
   "remote_in_use": false, "remote_owner": "", "is_default": true,
   "pin_pending": false, "needs_auth_key": false, "pin_claim": ""}
]}
```

`remote_owner` is always present. It is the display name of the other autostream instance
using the output when `remote_in_use` is `true`, and an empty string otherwise. Appliances
from before this field existed omit it, so a reader should treat a missing value as an
empty string.

`is_default` is `true` for the appliance's configured default output and `false` for every
other. Appliances from before this field existed omit it; a reader treats a missing value as
`false`. It is informational: the default output is listed first, and a dial may mark it, but
it needs no different handling.

`pin_pending`, `needs_auth_key` and `pin_claim` describe speaker pairing. They are present
from `dial_outputs` version 2; an appliance from before that omits them, and a reader
treats a missing `pin_pending` or `needs_auth_key` as `false` and a missing `pin_claim` as
an empty string. `pin_pending` is `true` while the speaker is waiting for a PIN to be
entered. `needs_auth_key` is `true` when the speaker has never been paired and has to be
paired from a PIN before it will play. `pin_claim` names who is being asked for the PIN
right now: `webui` for the appliance's own web page, `dial:<id>` for a dial, or an empty
string when nobody is. A claim ends when the PIN is accepted or after 90 seconds. A dial
does not act on `pin_claim`; it acts on `needs_auth_key`. The appliance's 90 second claim and the 90 second window a dial allows itself for a PIN are separate constants that happen to agree; neither reads the other.

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

A speaker that has never been paired needs a PIN, shown on the speaker itself. A dial
that can ask the user for one sends `"pin_capable": true` with its requests. Without
it, the request behaves exactly as it always did. To send the PIN, use `op`:

```json
{"dial_id": "<id>", "id": "1", "op": "pin", "pin": "2718"}
```

```json
{"dial_id": "<id>", "id": "1", "op": "pin", "pin": "2718", "selected": true, "volume": 60}
```

The second form pairs the speaker and switches it on in one request; `volume` is optional
and the configured default applies when it is left out. The first form only pairs. `pin`
is a string of four to eight digits. A dial that sends `pin_capable: true`, or that
submits a PIN, is the one the appliance asks for the PIN for that speaker, and a PIN
sent without `selected` leaves the speaker switched off. At most five PINs per minute are
accepted for each speaker from each requester.

**Responses:** the underlying mutation's own result plus `appliance_id`. Success is
`{"ok": true, "id": "1"}`. Anything else is `ok:false`:

| Reply | Meaning |
|---|---|
| `pin_required: true` | The speaker needs a PIN before it can be switched on. This is a flag on the reply, not an `error` value; `error` carries a message from the player |
| `pin_invalid: true` | The PIN was sent but the speaker did not accept it. Also a flag (with a player message in `error`), and the speaker stays off |
| `error: "output_in_use"` | Another appliance is using the speaker; `owner` names it |
| `error: "encoder_capacity"` | The appliance cannot take another output right now |
| `error: "rate_limited"` | Too many PINs were sent. `retry_after_s` is a whole number of seconds, at least 1, after which a PIN may be sent again |
| `error: "invalid_pin"` | The PIN was not four to eight digits (only reachable when the appliance is called without the usual body check) |
| `error: "config_error"` | The appliance configuration could not be loaded |
| any other `error` | A message from the player backend |

A dial that does not handle one of these refetches `POST /api/dial/outputs` and shows the
truth.

| `error` (`400`) | Meaning |
|---|---|
| `missing_output_id` | `id` is missing or empty |
| `invalid_request_body` | `selected` is missing or not a boolean on a plain request, or `op` is `pin` and `pin` is not four to eight digits or `selected` is not a boolean |

An appliance that announces `dial_outputs` version 1 does not understand `op`.

### `POST /api/dial/eq`

UUID-in-body auth via the same `_dial_auth_gate` guard. Returns the bass and treble
values the dial's Equaliser page shows, read from the stored output EQ bands.

**Request body:**
```json
{"dial_id": "<id>"}
```

**Success response (200):**
```json
{"ok": true, "appliance_id": "a1b2c3d4e5f6a7b8c9d0", "bass_db": 2, "treble_db": -1,
 "bands": [
  {"id": "peq1", "frequency_hz": 40, "type": "low_shelf", "gain_db": 2.0, "min_db": -12, "max_db": 12},
  {"id": "peq2", "frequency_hz": 100, "type": "peak", "gain_db": 2.0, "min_db": -12, "max_db": 12},
  {"id": "peq3", "frequency_hz": 300, "type": "peak", "gain_db": 0.0, "min_db": -12, "max_db": 12},
  {"id": "peq4", "frequency_hz": 1000, "type": "peak", "gain_db": 0.0, "min_db": -12, "max_db": 12},
  {"id": "peq5", "frequency_hz": 4000, "type": "peak", "gain_db": -0.5, "min_db": -12, "max_db": 12},
  {"id": "peq6", "frequency_hz": 10000, "type": "high_shelf", "gain_db": -1.0, "min_db": -12, "max_db": 12}
]}
```

`bass_db` and `treble_db` are unchanged and still describe the two-control page. `bands`
lists every band the appliance's equaliser has, in frequency order. `gain_db` is the
stored gain as a decimal number (the Equaliser page can store half steps, and a band can
sit outside the +/-6 dB that `bass_db`/`treble_db` are clamped to). `min_db` and `max_db`
are the range a write to that band is clamped to. A reader that only knows `bass_db` and
`treble_db` can ignore `bands`.

| `error` | Meaning |
|---|---|
| `config_error` | The appliance configuration could not be loaded |

### `POST /api/dial/eq/set`

UUID-in-body auth via the same `_dial_auth_gate` guard. Sets an absolute bass and/or
treble value, and/or absolute gains for individual bands. The dial computes its own
clamped target (`clamp(shown + delta, -6, +6)` for bass and treble) and sends the result,
exactly as the per-output volume steppers do; this appliance clamps again defensively.

Bass sets `peq1_db` (40 Hz low-shelf) and `peq2_db` (100 Hz peak) to the same value.
Treble sets `peq6_db` (10 kHz high-shelf) to the full value and `peq5_db` (4 kHz peak)
to half of it. `peq3_db`/`peq4_db` (300 Hz/1 kHz) are never touched by either field.
Both fields are saved and applied to the running monitor in a single update.

**Request body:**
```json
{"dial_id": "<id>", "bass_db": 2, "treble_db": -1}
```

At least one of `bass_db`, `treble_db` and `bands` must be present; any may be sent
alone or together.

`bands` is an object of band id to absolute gain in dB, for example
`{"dial_id": "<id>", "bands": {"peq3": 1.5, "peq4": -2}}`. The ids are the ones the read
reply lists. A gain may be an integer or a decimal number and is clamped to that band's
`min_db`/`max_db`. Only the bands named are written; the rest keep their stored values.
When a body names the same band through both `bass_db`/`treble_db` and `bands`, the
`bands` value wins. Everything in one request is saved and applied in a single update.

**Success response (200):** the same shape as `POST /api/dial/eq` above -- the
read-back `bass_db`/`treble_db`, rounded and clamped to +/-6 dB, and every band, after
the write.

| `error` | Meaning |
|---|---|
| `invalid_request_body` (`400`) | None of the fields present; `bass_db`/`treble_db` not an integer (or a boolean); or `bands` empty, not an object, naming an unknown id, or holding a gain that is not a finite number (a boolean counts as not a number). Nothing is written |
| `eq_apply_failed` | The monitor daemon is unreachable; the stored config is still updated |

---

### `POST /api/dial/warnings`

UUID-auth, read-only. Returns the warnings the appliance wants a dial to show. Available when
the capabilities endpoint lists `dial_warnings`. It goes through the same gate as
`POST /api/dial/status`, so an unauthorized dial gets the same `400`, `412` or `403` answers
and learns nothing about the appliance's maintenance state.

**Request body:**
```json
{"dial_id": "<dial UUID>"}
```

**Success response (200):**
```json
{
  "ok": true,
  "appliance_id": "a1b2c3d4e5f6a7b8c9d0",
  "warnings": [
    {"id": "stylus_in1", "severity": "warning", "title": "Input 1 stylus",
     "message": "Change soon, 7.5 h left", "dismissal": "week"}
  ]
}
```

| Field | Type | Notes |
|---|---|---|
| `appliance_id` | string\|null | The appliance's identity; a dial ignores a reply whose id is not the one it asked |
| `warnings` | array | At most 8 entries, most urgent first. `[]` means there is nothing to report and clears whatever the dial held |
| `id` | string | 1 to 32 characters from `a-z`, `0-9`, `_` and `-`, unique in the list. Stable for a given condition, so a dial can remember that it was dismissed |
| `severity` | string | `info`, `warning` or `critical`. A condition that gets worse keeps its `id` and changes `severity` |
| `title` | string | Plain text, at most 40 characters |
| `message` | string | Plain text, at most 120 characters; may be empty |
| `dismissal` | string | How long a Dismiss should hold: `day`, `week`, or `none` (a notice with no timed return) |

Text is data: a dial strips control characters and never treats it as markup or a template.
A dial truncates anything over the limits, so an appliance should stay within them.

The warnings this appliance produces:

| `id` | `severity` | Title | Message | When |
|---|---|---|---|---|
| `stylus_in<n>` | `critical` | `<input> stylus` | Change now | The stylus life is used up |
| `stylus_in<n>` | `warning` | `<input> stylus` | Change soon, `<h>` h left | The stylus is near the end of its life |
| `belt_in<n>` | `critical` | `<input> drive belt` | Service now | The belt's hours or age limit is passed |
| `belt_in<n>` | `warning` | `<input> drive belt` | Service soon | The belt is near a limit |
| `bearing_in<n>` | `critical` | `<input> main bearing` | Service now | The bearing's hours or age limit is passed |
| `bearing_in<n>` | `warning` | `<input> main bearing` | Service soon | The bearing is near a limit |
| `psu` | `critical` | `Power supply` | Low voltage now | Undervoltage is happening now |
| `psu` | `warning` | `Power supply` | Low voltage seen earlier | Undervoltage was seen since boot |

Wear warnings appear only for enabled inputs with the item's life tracking turned on.
Resetting a counter in the appliance's Service page clears its warning.

**Failure responses:** the dial gate's answers as above, and `200 {"ok": false, "error":
"config_error"}` when the list cannot be built. A dial keeps the warnings it already holds on
any failure; only an `ok` reply with an empty list clears them.

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
by a browser dial-management flow. Its native authorization responses (`403` or `412`, see section 1) and HTTP `200`
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

### `POST /auth-changed`

Advisory, appliance-initiated notification that a given `appliance_id`'s dial authorization
may have changed. Fired by the main appliance (fire-and-forget, one retry after a short
delay on failure) immediately after its own `POST /api/dial/authorize` or `POST
/api/dial/revoke` handler responds, so an already-open dial screen or an in-flight status
poll can react without waiting for its next scheduled tick.

**No PIN required, and never authenticated** - anyone on the LAN can reach port 7842, so
this endpoint grants nothing by itself: it only causes the dial to enqueue a probe, and
only when the source IP matches a sighting the dial currently has of that `appliance_id`,
whether the appliance is playing or idle (see `_autostream-playing._tcp`/`_autostream._tcp`
above). An earlier dial matched only playing appliances, so a push from an idle appliance was
dropped and left to the dial's next scheduled check. Authorization
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

### `POST /warnings-changed`

Advisory, appliance-initiated notification that the warnings an appliance reports through
`POST /api/dial/warnings` may have changed. It has the same shape, the same lack of
authentication and the same answers as `POST /auth-changed` above: the body is
`{"appliance_id": "<id>"}`, the reply is always `202 {"ok": true}`, and the push only causes
the dial to fetch the list itself, so it grants nothing and carries no warning text.

On the dial the two push routes share one body check, one source-address check (the same
current-sighting rule as above) and one rate limiter, so an auth push and a warnings push for
one appliance inside 5 seconds drop the second; the dial's own 12 minute fetch repairs a
dropped push. A push never fetches on the dial's HTTP thread: it queues the appliance id and
the dial's core thread asks the appliance for its warnings. The dial also fetches the list
when an appliance is first seen authorised, and again on every wake, and clears an
appliance's warnings when it refuses the dial or leaves the network.

The appliance pushes to a dial only when all of these hold: the dial is in the appliance's
authorized list, the appliance currently sees it on the network, and the dial advertises
`dial_proto=v3` or later. An older dial is never contacted, and nothing is sent to an address
the appliance has not seen advertise a dial.

**When it is sent.** The appliance checks its warning set every 30 seconds, and straight away
after a maintenance counter is reset or a maintenance setting is saved in its Service page.
When the set has changed it sends one push to each eligible dial. It sends at most one such
push every 10 seconds: changes inside that window are held and sent once the window ends,
describing the set as it is then, and a change that reverses inside the window sends nothing.
The authorization and warnings pushes share one sender on the appliance, one request at a time,
with a 1 second timeout and one retry after 2 seconds. A dial still fetches the list on its own schedule, so
a missed push delays an update and loses nothing.

### `POST /state-changed`

Advisory, appliance-initiated notification that something the dial shows may have changed on
the appliance: a speaker, the volume, mute, repeat, the session or the identified track. It
lets a dial follow a change made on another dial, in the appliance's web page or by the
appliance itself within a fraction of a second, instead of at its next regular poll. It has
the same lack of authentication and the same answers as `POST /auth-changed` above, and like
the other two pushes it carries no state: the dial fetches the state itself, so it grants
nothing and a lost, repeated or late push cannot leave a dial wrong.

**Request body:**
```json
{"appliance_id": "a1b2c3d4e5f6a7b8c9d0", "changed": ["mute", "volume"]}
```

`changed` is a list of what changed. A dial treats an unknown token as some change, and an
absent or empty list as any change.

| Token | Sent when |
|---|---|
| `session` | A session started or ended, or its source changed |
| `outputs` | A speaker was enabled, disabled or paired, or its level changed |
| `volume` | The master volume changed through a dial's step |
| `mute` | The appliance muted or restored |
| `repeat` | Repeat was armed or disarmed, a replay started, was sought, stopped or ended, or the recording state changed |
| `track` | The identified track (state, title, artist, album, artwork) changed |
| `eq` | The equaliser changed |

A further token, `input`, is reserved for a change to an input's type or label and is not sent
yet.

**Response:** always `202 {"ok": true}`, with the same `400` answers as `POST /auth-changed`.
The source-address rule is the same: the push is acted on only when its source IP matches a
sighting the dial currently has of that `appliance_id`.

**Rate limiting.** This route has its own limit, apart from the other two push routes: at most
one accepted push per source IP every 0.2 seconds, and per `appliance_id` every 0.2 seconds. A
push outside the limit is still answered `202` but not acted on. The appliance already holds
its own sending to a few a second, so the limit only guards against a sender that does not.

**What the dial does.** It asks the appliance for its status at once, and refetches the
speakers or the equaliser it is currently showing for that appliance when `changed` says they
changed. Polls started by a push are paced to one every 0.4 seconds, so a burst of pushes
costs the dial a few polls a second at most.

**When it is sent.** The appliance sends a push after a change is committed, for each kind of
change in the table above. The first change is sent at once. Further changes inside the next
0.3 seconds are held and sent together, naming every kind that changed, when that window ends.
A dial whose own volume or mute request made the change is left out, because its reply already
carries the result; if another change in the same window did not come from that dial, it is
told.

**Delivery.** The push goes out on the same sender as the two pushes above, with a 1 second
timeout and no retry. A dial that did not answer with a success is skipped for 5 seconds and
tried last after that, so one unreachable dial does not delay the others. Nothing is sent to a
dial the appliance has not seen advertise, or to one that is not authorised or does not
advertise `dial_proto=v3` or later. A dial still polls on its own schedule, which repairs any
push that is lost.

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
update run by older software, or no update at all, still gives a well-formed reply.

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

## 5. Capability Version Table

| Capability | Endpoint | Notes |
|---|---|---|
| `dial_api=v1` | `POST /api/dial/volume` | UUID-in-body, delta-only, fire-and-forget |
| `audio_status=v1` | `GET /api/audio/status` | Output names only; no IDs |
| `dial_status=v1` | `POST /api/dial/status` | UUID-auth, read-only live master volume and, from 0.7.0, the `input` object |
| `dial_outputs=v1`; version 2 (JSON only) | `POST /api/dial/outputs`, `POST /api/dial/outputs/set` | UUID-auth; per-output enable and volume. Version 2, announced only by `GET /api/dial/capabilities` (the TXT key stays `v1`), adds the pairing fields, the PIN submission and `retry_after_s` |
| `dial_eq=v1`; version 2 (JSON only) | `POST /api/dial/eq`, `POST /api/dial/eq/set` | UUID-auth; version 1 is bass/treble over the output EQ bands. Version 2, announced only by `GET /api/dial/capabilities` (the TXT key stays `v1`), adds the six-band `bands` field on both routes |
| `repeat=v1` | (roster only) | Advertised on `_autostream._tcp`, not `_autostream-playing._tcp` - see section 1. Gates the `repeat_capable` flag in the dial's idle-inclusive roster, not any single endpoint; a repeat command is still sent through `POST /api/dial/repeat`/`POST /api/dial/repeat/arm` above regardless of this flag, and the daemon itself rejects it (`repeat_unavailable`) if recording is disabled |
| `dial_sdmon=v1` | `GET /sdcard-health`, `POST /sdcard-health` (dial, port 7842) | Advertised on `_autostream-dial._tcp`; gates the SD card health monitoring row on the appliance's dial card |
| `dial_warnings=v1` (JSON only) | `POST /api/dial/warnings`, and the dial's `POST /warnings-changed` | UUID-auth; appliance-authored warnings for the dial to show. Announced only by `GET /api/dial/capabilities` (version `1`), with no TXT key |
| (none) | the dial's `POST /state-changed` | Sent from 0.7.0 to every sighted, authorised dial of `dial_proto=v3` or later; no capability key. Advisory: the dial fetches the state itself |
| `dial_proto=v3` | `GET /api/dial/capabilities` | Advertised by appliances (both records) in place of `v2`; each generation includes the earlier ones. The endpoint is the authoritative capability list, with the versions in the table above. In it, `dial_eq` is `2` (six-band `bands` on the EQ routes) while the TXT key stays `dial_eq=v1` |
| `dial_proto=v2` | every dial route (typed refusals), status and volume replies (`muted`) | Advertised by appliances (both records) and by dials. Selects the refusal style, whether a dial relies on `muted`, and the dial's handling of an appliance without an `id` on its playing record; see **Protocol dialect** in section 1. `dial_api=v1` and `dial_status=v1` are unchanged alongside it |

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

The `dial_proto=v2` dialect (section 1) was introduced the same way, as a new key beside the
existing `v1` indicators rather than a bump of them. It carries the changes that an older dial
would misread (typed refusals, and `muted` being authoritative), and each side falls back to
the older behaviour when the other does not advertise it.

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
