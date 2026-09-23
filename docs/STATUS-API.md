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
| `input_levels` | array. Per-input level/detection data. |
| `playback` | object. Current playback snapshot (speaker, volume, etc). |
| `playback_banner_text`, `belt_banner_text`, `bearing_banner_text` | strings. Maintenance-tracking banner text (stylus, drive belt, main bearing), empty when nothing to show. |
| `track_identification` | object. See below. |
| `session` | object. Always present. `{"active": bool, "source": string or null}`; `source` names the actively-sourcing input (e.g. `"input1"`) or `"replay"` during a repeat replay. |
| `repeat` | object. Present only when the monitor daemon reports repeat/replay status; omitted entirely on older daemon builds. |
| `owntone_selfheal` | object. Coordinator-owned reconcile/watchdog counters; present whenever available. |

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
| `analysing` | `"Analysing"` | An identification attempt is currently in flight. |
| `identified` | `"Track identified"` | The most recent attempt matched; `title`/`artist`/`album`/`artwork_url` are populated. |
| `not_found` | `"Listening"` | The most recent attempt completed with no match. |
| `error` | `"Identification unavailable"` | The most recent attempt failed (provider/network/configuration error). |

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

## Related files

| File | Role |
|---|---|
| `core/track_id/models.py` | `TrackIdentificationSnapshot`, state constants, `state_status_text()` |
| `core/autostream_core.py` | `AudioMonitor` attempt scheduling (`_schedule_track_id_attempt()`, `maybe_trigger_track_identification()`, `_ti_worker()`), `get_active_track_identification_snapshot()` |
| `core/autostream_webui_api.py` | `send_status_json()` -- assembles `GET /api/status` |
| [ADDING-TRACK-ID-PROVIDER.md](ADDING-TRACK-ID-PROVIDER.md) | How the provider-neutral track-ID architecture fits together |
