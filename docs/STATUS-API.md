# Status API

The appliance's state, including track identification, is read from the
state route and the change stream described in
[CLIENT-PROTOCOL.md](CLIENT-PROTOCOL.md). This document is the developer
reference for the `track_identification` object (the `track` part of the
state carries it) and for the stream's mechanics.

No PIN or CSRF token is required to read either route.

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

## `GET /api/v1/events` and `GET /api/v1/state` (unstable until 1.0)

These two routes are **unstable**: their shape, names and auth may
change before 1.0. The Web UI, the dials and other appliances use them (see
[CLIENT-PROTOCOL.md](CLIENT-PROTOCOL.md)), and a client should expect to be updated with the appliance.

### `GET /api/v1/events`

A Server-Sent Events stream that carries the new value of each part of the
appliance state that moved. A client merges each event's `data` into the state
it holds. It needs no PIN, and it works before the appliance is set up.

Headers: `Content-Type: text/event-stream`, `Cache-Control: no-store`. There is
no `Content-Length`; the response ends when the server closes the connection.
The first bytes of every stream are `retry: 2000` and a blank line, which sets
the browser's reconnect delay.

An event:

```
id: 3f9a0c1d2e4b5a69-1234
event: change
data: {"boot":"3f9a0c1d2e4b5a69","version":1234,"resync":false,"data":{"outputs":{...},"session":{...}}}

```

| Field | Description |
|---|---|
| `id` | `<boot>-<version>`: the 16-hex boot id of the state store and the version the event describes. A browser sends it back as `Last-Event-ID` when it reconnects. |
| `boot`, `version` | The same two values, so a client never parses the id. |
| `resync` | `true` when the server cannot say what moved (a new client, a restart of the appliance's service, an id it does not know). `data` is then empty, and a client fetches `GET /api/v1/state` and takes it whole. |
| `data` | The value of each part that moved since the version the client last had, keyed by part name, as `GET /api/v1/state` shows it. It is never empty unless `resync` is true. Fields that change continuously (levels, last-seen times) are as they were when the part last moved; a client that shows them reads `GET /api/v1/state`. |

There is one event name, `change`. When nothing has happened for ten seconds
the server writes a comment line (`: ka`) to keep the connection alive; it is
not an event. Changes that follow each other within about 0.3 seconds are
folded into one event.

A client that shows the level meters or the replay position reads
`GET /api/v1/state?parts=inputs,repeat` while a session or replay is live;
those fields are not announced.

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

The browser pages use the stream when it is available and poll the state route
when it is not (the stream refused, the service restarting), trying the stream
again after about 30 seconds.

### `GET /api/v1/state`

The state snapshot as it is held: `boot`, `version`, `protocol`, `clients`
(the number of open streams), `time` (the appliance's wall clock in seconds, so
a page never compares its own clock with the appliance's), `part_versions` (the
version at which each part last moved) and `parts` (every part, serialised field by field with the
internal field names). Like the stream it needs no PIN and works before the
appliance is set up. `?parts=a,b` returns only those parts, and `?parts=` none
of them; an unknown name is refused with 400 `unknown_part`. The body is
internal and will change when the parts do. Without `parts` it is built at most
once a second however many clients ask; with `parts` it is built from the live
snapshot on each request.

---

## Another appliance's state, stream and intents

The appliances this one follows are served in the same shapes, under
`/api/v1/peers/<id>/`, so a page draws another appliance with the code that
draws this one. `<id>` is the other appliance's 20-character identity.

| Route | Reply |
|---|---|
| `GET /api/v1/peers/<id>/state` | The other appliance's state body, whole or `?parts=a,b`, as `GET /api/v1/state` shows it |
| `GET /api/v1/peers/<id>/events` | The other appliance's change stream. Its events and ids are passed on as they come, so a browser resumes against the other appliance's versions |
| `POST /api/v1/peers/<id>/intents/<name>` | The intent is sent to the other appliance as a request from this one, on behalf of the browser |

A request for an appliance this one does not follow, or may not control, is
refused with `unknown_appliance`, `bound_appliance` (the id is this
appliance's own), `control_disabled`, `appliance_conflict` or
`appliance_unconfigured`. The `peers` part of this appliance's own state lists
the appliances it follows.

---

## Related files

| File | Role |
|---|---|
| `core/track_id/models.py` | `TrackIdentificationSnapshot`, state constants, `state_status_text()` |
| `core/autostream_core.py` | `AudioMonitor` attempt scheduling (`_schedule_track_id_attempt()`, `maybe_trigger_track_identification()`, `_ti_worker()`), `get_active_track_identification_snapshot()` |
| `core/webui/protocol/state.py`, `stream.py`, `intents.py` | The state route, the change stream and `POST /api/v1/intents/<name>` |
| `core/webui/peer/relay.py` | The same three routes for another appliance |
| [ADDING-TRACK-ID-PROVIDER.md](ADDING-TRACK-ID-PROVIDER.md) | How the provider-neutral track-ID architecture fits together |
