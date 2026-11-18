# Status API

`GET /api/status` is the combined status endpoint the Web UI polls (roughly
every 1-2 seconds) to drive the Home page: current playback, input levels,
maintenance banners, repeat/session state, and track identification. This
document is the developer reference for that endpoint's shape, with a full
field-by-field reference for the `track_identification` object, which was
previously undocumented.

No PIN or CSRF token is required to read this endpoint.

---

## `GET /api/status`

**Response (200)**

```json
{
  "playing": true,
  "status_text": "Playing",
  "status_class": "playing",
  "input_levels": [ ... ],
  "playback": { ... },
  "playback_banner_text": "",
  "belt_banner_text": "",
  "bearing_banner_text": "",
  "dial_update_banner_text": "",
  "sample_rate_banner_text": "",
  "track_identification": { ... },
  "session": { "active": true, "source": "input1" },
  "repeat": { ... },
  "owntone_selfheal": { ... }
}
```

Top-level fields, briefly (this endpoint's full shape beyond
`track_identification` is out of scope for this document):

| Field | Description |
|---|---|
| `playing` | bool. Whether a playback session is currently active. Derived from `session.active`, falling back to a raw capture check if the session tracker is unavailable. |
| `status_text` | string. Home-page headline text for the overall playing/waiting state. Unrelated to `track_identification.status_text` below. |
| `status_class` | string. `"playing"` or `"waiting"`, a CSS-style hook for the same state. |
| `input_levels` | array. Per-input level/detection data. Each item has `index` (the input number), `label`, `dbfs` (the largest raw peak over the last poll window, before gain and EQ), `detected_hz`, `is_above_threshold` (debounced over the silence timeout) and `vu_history`. It also carries the sample rate fields: `detected_khz` (`detected_hz` as text such as `"44.1 kHz"`, empty when there is no rate), `negotiated_hz` (the rate the capture device was opened at, 0 while the input is not running), `rate_lock` (`"acquiring"`, `"locked"` or `"mismatch"`, or empty while the input is not running), `relock_count` (how many times the monitor has stepped the capture rate since the input started), `rate_mismatch_hz` and `rate_mismatch_khz` (the standard rate the device is delivering when it is not the one it was opened at and Dynamic Rate Matching is off, otherwise 0 and empty), `dynamic_rate_matching` (whether the setting is on for the input) and `monitor_supports_rate_matching` (false when the monitor is too old to report these fields; the sample rate fields then keep their defaults). |
| `playback` | object. Current playback snapshot (speaker, volume, etc). Each entry in `inputs` carries `input_type` (`turntable`, `cd` or `line`) and `type_label` (the matching display name). |
| `playback_banner_text`, `belt_banner_text`, `bearing_banner_text` | strings. Maintenance-tracking banner text (stylus, drive belt, main bearing), empty when nothing to show. |
| `dial_update_banner_text` | string. Text of the Home page "dial updates required" banner, empty when no dial needs an update. |
| `sample_rate_banner_text` | string. Text of the Home page sample rate banner, `"Sample Rate Mismatch: Please enable Dynamic Rate Matching"` while any input delivers a different standard sample rate than it was opened at with Dynamic Rate Matching off, empty otherwise. The text never names the input; the page links the banner to the first input in `input_levels` whose `rate_mismatch_hz` is above zero. |
| `track_identification` | object. See below. |
| `session` | object. Always present. `{"active": bool, "source": string or null}`; `source` names the actively-sourcing input (e.g. `"input1"`) or `"replay"` during a repeat replay. |
| `repeat` | object. Present only when the monitor daemon reports repeat/replay status; omitted entirely on older daemon builds. |
| `owntone_selfheal` | object. Coordinator-owned reconcile/watchdog counters; present whenever available. |

---

## `GET /api/inputs/levels`

A small, cheap answer for the Setup page's live level readout. It is built
from the coordinator's cache of the last monitor poll, so it never waits on
OwnTone or the monitor. Needs a signed-in session, like the Setup page.

```json
{
  "ok": true,
  "connected": true,
  "inputs": [
    {
      "index": 1, "enabled": true, "running": true, "dbfs": -52.3,
      "sample_rate_text": "Sample rate: 48 kHz",
      "rate_matching_note": "Follows the sample rate of the source. Turn on for an optical (S/PDIF) adapter fed by a CD or DVD player.",
      "dynamic_rate_matching": false, "rate_mismatch_hz": 0,
      "negotiated_hz": 48000, "monitor_supports_rate_matching": true
    },
    {
      "index": 2, "enabled": false, "running": false, "dbfs": null,
      "sample_rate_text": "Sample rate: not running",
      "rate_matching_note": "Follows the sample rate of the source. Turn on for an optical (S/PDIF) adapter fed by a CD or DVD player.",
      "dynamic_rate_matching": false, "rate_mismatch_hz": 0,
      "negotiated_hz": 0, "monitor_supports_rate_matching": false
    }
  ]
}
```

| Field | Description |
|---|---|
| `connected` | bool. Whether the monitor is currently connected. |
| `index` | integer. The input number, 1 or 2. Always both, in order. |
| `enabled` | bool. Whether the input is enabled in the saved settings. |
| `running` | bool. Whether the input has a running monitor. A disabled input, or one that failed to start, is not running. |
| `dbfs` | number or null. The largest raw peak over the last poll window, before gain and EQ, which is the value compared with the silence threshold. |
| `sample_rate_text` | string. The line the Setup card shows under its Level readout, for example `Sample rate: 48 kHz`. It reads `Sample rate: 44.1 kHz (device opened at 48 kHz)` when the monitor has stepped to a rate other than the one the device was opened at, `Sample rate: checking` while the rate is still being worked out, and `Sample rate: 48 kHz (source is sending 44.1 kHz)` while `rate_mismatch_hz` is above zero. It reads `Sample rate: not running` for an input that is not running and for every input while the monitor is disconnected. An older monitor that reports no rate lock gives the detected rate alone, or `not running` when there is none. |
| `rate_matching_note` | string. The help text the Setup card shows under its Dynamic Rate Matching switch, worked out from the values below. |
| `dynamic_rate_matching` | bool. Whether Dynamic Rate Matching is on for the input, as the coordinator holds it. `false` for an input that is not running. |
| `rate_mismatch_hz` | integer. The sample rate the input is delivering when that differs from the rate it was opened at and Dynamic Rate Matching has not followed it, otherwise 0. |
| `negotiated_hz` | integer. The sample rate the capture device was opened at, 0 for an input that is not running. |
| `monitor_supports_rate_matching` | bool. Whether the monitor reports the setting at all. `false` for an older monitor, and for an input that is not running. |

`dbfs` is `null` for an input that is not running, and for every input while
the monitor is disconnected, so a stale number is never shown.

---

## `track_identification`

Reflects the identification state of whichever input is currently the active
session source (live capture, or the replay origin during a repeat replay).
Sourced from `TrackIdentificationSnapshot.to_public_dict()` in
`core/track_id/models.py`. Never contains raw provider payloads, fingerprints,
or API keys.

**Response fields**

| Field | Type | Description |
|---|---|---|
| `enabled` | bool | Whether track identification is turned on in Setup. `false` for every other field's default/empty value when disabled. |
| `state` | string | One of the state values below. |
| `status_text` | string | Default UI text for `state` (see mapping below). This is the raw API value; the Web UI may derive its own on-screen wording (e.g. an input-specific "Unknown track" label) from `state` instead of displaying this string verbatim. |
| `input_index` | int or null | 1-based input number (`1` or `2`) this snapshot belongs to, or `null` when not applicable (e.g. disabled). |
| `provider` | string | Identification provider id, e.g. `"vibra_shazam"`. Empty string when no attempt has completed yet. |
| `title` | string | Identified track title. Empty until a match. |
| `artist` | string | Identified track artist. Empty until a match. |
| `album` | string | Identified album. In practice always empty: the bundled Shazam provider does not populate it. |
| `artwork_url` | string | Artwork URL as supplied by the provider (may be an external URL). Empty when no artwork is available. |
| `confidence` | float or null | Provider-reported match confidence. In practice always `null`: the bundled Shazam provider does not set it. |
| `updated_at` | float (epoch seconds) or null | When this snapshot's content was last produced. `null` before the first attempt. |
| `last_attempt_at` | float (epoch seconds) or null | When the last identification attempt was dispatched/completed. Currently always set together with `updated_at`. `null` before the first attempt. |
| `error` | string | Python exception class name (e.g. `"TrackIDRateLimitedError"`) for a runtime failure while `state` is `error`. Empty string for a non-error state, and also empty for a configuration-error `error` state (see `next_attempt_reason` for that case). |
| `next_attempt_at` | float (epoch seconds) or null | When the next identification attempt is scheduled. `null` when nothing is currently scheduled (service disabled, or an attempt is in flight, e.g. `state == "analysing"`). |
| `next_attempt_reason` | string | Short diagnostic tag for why the next attempt is scheduled the way it is, or why identification last landed where it did (see values below). Empty string alongside a `null` `next_attempt_at`. |

**`state` values and default `status_text`**

| `state` | `status_text` | Meaning |
|---|---|---|
| `disabled` | `""` | Track identification is off in Setup. |
| `waiting_for_audio` | `"Waiting for audio"` | Enabled and armed, but the analysis lead-in/snapshot window has not yet elapsed or no attempt has completed. |
| `analysing` | `"Analysing"` | An identification attempt is currently in flight and no track is identified yet (a new session or a track change). The periodic re-check of an identified track does not use this state: `identified` and its track fields are reported while it runs. |
| `identified` | `"Track identified"` | The most recent attempt matched; `title`/`artist`/`album`/`artwork_url` are populated. A periodic re-check of the identified track that finds nothing or fails leaves this state and the track in place; `last_attempt_at`, `next_attempt_at` and `next_attempt_reason` then describe the failed attempt and the scheduled retry (for example `no_match` or `rate_limit`). `error` stays empty. Only a detected track change, a new session or a replay seek clears it. |
| `not_found` | `"Listening"` | The most recent attempt completed with no match and no track was identified at the time. |
| `error` | `"Identification unavailable"` | The most recent attempt failed (provider/network/configuration error) and no track was identified at the time. |

**`next_attempt_reason` values**

Set by the coordinator's attempt scheduler (`AudioMonitor._schedule_track_id_attempt()`
in `core/autostream_core.py`) each time it arms the next attempt:

| Value | When it's set |
|---|---|
| `""` (empty) | Nothing scheduled: disabled, an attempt is currently in flight, or the input isn't actively sourcing. |
| `initial` | First attempt after capture/session start, or after re-arming for a new session source. |
| `track_change` | A track-change edge was detected on the current source. |
| `match` | The last attempt matched; this is the scheduled periodic re-identify. |
| `no_match` | The last attempt found no match, or returned no usable audio; scheduled retry. |
| `error` | The last attempt failed with a generic/configuration error; scheduled retry. |
| `upstream_rejection` | The provider's upstream rejected the request (HTTP 403/406); backing off. |
| `rate_limit` | The provider's upstream rate-limited the request; backing off, honoring a provider-supplied retry delay when given. |
| `provider_unreachable` | The provider's upstream could not be reached (network/DNS/timeout); backing off. |

`rate_limit` and `upstream_rejection` are "protected": once set, a lower-priority
reschedule request cannot pull the deadline earlier, only push it later.

**Example - identified**

```json
{
  "enabled": true,
  "state": "identified",
  "status_text": "Track identified",
  "input_index": 1,
  "provider": "vibra_shazam",
  "title": "Example Title",
  "artist": "Example Artist",
  "album": "",
  "artwork_url": "https://example.invalid/artwork.jpg",
  "confidence": null,
  "updated_at": 1700000000.0,
  "last_attempt_at": 1700000000.0,
  "error": "",
  "next_attempt_at": 1700000300.0,
  "next_attempt_reason": "match"
}
```

**Example - disabled**

```json
{
  "enabled": false,
  "state": "disabled",
  "status_text": "",
  "input_index": null,
  "provider": "",
  "title": "",
  "artist": "",
  "album": "",
  "artwork_url": "",
  "confidence": null,
  "updated_at": null,
  "last_attempt_at": null,
  "error": "",
  "next_attempt_at": null,
  "next_attempt_reason": ""
}
```

---

## `GET /api/v1/events` and `GET /api/v1/state` (unstable until the next release line)

These two routes are new and **unstable**: their shape, names and auth may
change before the next release line, and nothing outside this appliance's own
Home page should depend on them yet.

### `GET /api/v1/events`

A Server-Sent Events stream that says **which parts of the appliance state
moved**, and carries the new value of each. A client that sees a part it cares
about move reads it from the event's `data`, or fetches the route that shows
it (the Home page fetches `/api/status` and `/api/owntone/outputs_state`).
Like `GET /api/status` it needs no PIN, and it works before the appliance is
set up.

Headers: `Content-Type: text/event-stream`, `Cache-Control: no-store`. There is
no `Content-Length`; the response ends when the server closes the connection.
The first bytes of every stream are `retry: 2000` and a blank line, which sets
the browser's reconnect delay.

An event:

```
id: 3f9a0c1d2e4b5a69-1234
event: change
data: {"boot":"3f9a0c1d2e4b5a69","version":1234,"resync":false,"parts":["outputs","session"],"data":{"outputs":{...},"session":{...}}}

```

| Field | Description |
|---|---|
| `id` | `<boot>-<version>`: the 16-hex boot id of the state store and the version the event describes. A browser sends it back as `Last-Event-ID` when it reconnects. |
| `boot`, `version` | The same two values, so a client never parses the id. |
| `parts` | The parts that moved since the version the client last had, in a fixed order, never empty. The part names are `session`, `repeat`, `track`, `inputs`, `monitor`, `playback`, `health`, `settings`, `outputs`, `eq` and `devices`. |
| `resync` | `true` when the server cannot say what moved (a new client, a restart of the appliance's service, an id it does not know). `parts` is then every part, `data` is empty, and a client fetches `GET /api/v1/state`. |
| `data` | The value of each part listed in `parts`, as `GET /api/v1/state` shows it. Fields that change continuously (levels, last-seen times) are as they were when the part last moved; a client that shows them reads `GET /api/v1/state`. |

There is one event name, `change`. When nothing has happened for ten seconds
the server writes a comment line (`: ka`) to keep the connection alive; it is
not an event. Changes that follow each other within about 0.3 seconds are
folded into one event.

Some values on the Home page are not versioned and so are never announced: the
level meters, the VU history, the replay position and the unidentified track
texts, besides another appliance's use of a speaker, the dial update banner
and a dial's claim on a speaker's PIN. A client that shows them keeps polling
`/api/status` while a session or replay is live and fetches again every 15
seconds.

**Resuming.** A client names the version it last had in the `Last-Event-ID`
request header, or in a `since` query parameter (`?since=<id>`) when it
opens a new stream. The same boot and an older version gives one event naming
exactly the parts that moved since; the current version gives nothing until
the next change; a different boot, a newer version than the server has or an
id that does not parse gives a `resync` event. No event history is kept, so a
client that was away for an hour gets the same exact answer as one that was
away for a second.

**Limits.** At most 64 streams are served at once, and at most eight to one
client address. A request over a limit gets HTTP 200 with the JSON body
`{"ok": false, "error": "too_many_clients", "error_status": 503,
"retryable": true}`, or `too_many_from_address` for the per-address limit (an
event source treats any reply that is not a stream as a failed connection,
which is what a page needs to fall back to polling). A request with a
`protocol` query parameter other than the appliance's gets HTTP 200 with
`{"ok": false, "error": "protocol_mismatch", "protocol": 4}`. A stream is ended by the server after about five
minutes (each stream's limit varies by 10 percent) and the browser resumes it
with its last id. A client that stops reading is dropped after two seconds of
blocked writes. A request whose `Origin` header names another host is refused
with 403 (`cross_origin`).

The Home page uses the stream when it is available and polls as before when
it is not (the stream refused, the service restarting, an older web server in
front), trying the stream again after about 30 seconds.

### `GET /api/v1/state`

The state snapshot as it is held: `boot`, `version`, `protocol`, `clients`
(the number of open streams), `part_versions` (the version at which each part
last moved) and `parts` (every part, serialised field by field with the
internal field names). Like the stream it needs no PIN and works before the
appliance is set up. `?parts=a,b` returns only those parts, and `?parts=` none
of them; an unknown name is refused with 400 `unknown_part`. The body is
internal and will change when the parts do. Without `parts` it is built at most
once a second however many clients ask; with `parts` it is built from the live
snapshot on each request.

---

## Related files

| File | Role |
|---|---|
| `core/track_id/models.py` | `TrackIdentificationSnapshot`, state constants, `state_status_text()` |
| `core/autostream_core.py` | `AudioMonitor` attempt scheduling (`_schedule_track_id_attempt()`, `maybe_trigger_track_identification()`, `_ti_worker()`), `get_active_track_identification_snapshot()` |
| `core/webui/browser/home_api.py` | `send_status_json()` -- assembles `GET /api/status` |
| [ADDING-TRACK-ID-PROVIDER.md](ADDING-TRACK-ID-PROVIDER.md) | How the provider-neutral track-ID architecture fits together |
