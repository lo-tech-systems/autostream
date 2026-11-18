# Client protocol

How a client talks to an autostream appliance: read its state, follow
changes as they happen, and ask it to do things. The Web UI, the dial and
other appliances are all clients of the same three routes.

**This protocol is unstable until 1.0.** Routes, field names, part contents,
refusal names and roles may change in any release before then, and a client
should expect to be updated together with the appliance. The protocol number
(below) moves whenever a client written for an older number would stop
working, and a client must refuse to talk to an appliance that advertises a
different one.

| Route | Does |
|---|---|
| `GET /api/v1/state` | The whole state, or the parts you name, as one JSON object. |
| `GET /api/v1/events` | A stream of "these parts moved", carrying the new values. |
| `POST /api/v1/intents/<name>` | Asks the appliance to do something. |

All three are served on the appliance's web port. A request from a browser
carries a session cookie; a dial or another appliance names itself instead
(see [Who is asking](#who-is-asking)).

---

## The protocol number

The number is `4`. The appliance advertises it as `proto` in its mDNS
records, and it appears as `protocol` at the top of the state body. A client
sends it as the `protocol` query parameter when it opens the stream and as
`protocol` in the body of an intent.

A request with a different number gets HTTP 200 and no stream or action:

```json
{"ok": false, "error": "protocol_mismatch", "protocol": 4}
```

A request with no `protocol` is taken to come from a page of this appliance
and is served. A dial or another appliance must send it.

---

## State: `GET /api/v1/state`

```json
{
  "boot": "3f9a0c1d2e4b5a69",
  "version": 4812,
  "protocol": 4,
  "time": 1766000000.5,
  "clients": 3,
  "part_versions": {"outputs": 4810, "warnings": 4377},
  "parts": {"appliance": {...}, "outputs": {...}}
}
```

- `boot` names this run of the appliance's service. A new value means the
  state restarted from scratch.
- `version` counts every change to any part; `part_versions` gives the
  version at which each part last moved.
- `time` is the appliance's wall clock in seconds, so a page never compares
  its own clock with the appliance's.
- `clients` is the number of open event streams.
- `parts` holds each part under its name. The state is split into the parts
  `session`, `repeat`, `track`, `inputs`, `monitor`, `playback`, `health`,
  `settings`, `outputs`, `eq`, `devices`, `appliance`, `dials` and `warnings`.

`?parts=outputs,warnings` returns only those parts. `?parts=` (present and
empty) returns the top level and the `appliance` part only, because every
client's first question is who this is and whether it is set up. An unknown
name is refused with HTTP 400 and the error `unknown_part`.

No PIN is needed, and the route works before the appliance is set up.

Most parts are the appliance's own state, serialised field by field with
internal names, and will change when the appliance does. Four are described
here because every client reads them.

### `appliance`

| Field | Meaning |
|---|---|
| `id` | The appliance's identifier (20 lowercase hex characters), or `""` when it has none. |
| `hostname` | The name people see, without `.local`. |
| `version` | The installed release. |
| `configured` | `false` while first-boot setup is still required. |
| `pin_set` | Whether a PIN is in force. |

### `dials`

`generation` counts every authorisation or revocation of a dial. It names
no dial; a client that watches it knows to ask again whether it is allowed.

### `warnings`

`entries` is the list of things the appliance wants a person to know, most
severe first, at most 16. Each entry:

| Field | Meaning |
|---|---|
| `id` | A stable name for the item, such as `psu`, `cpu_temp`, `sd_health`, `stylus_in1`, `belt_in2`, `bearing_in1`, `sample_rate_in2`, `dial_update`, `licence` or `no_input`. The same item keeps the same id while it lasts. |
| `incident` | Reserved. Always `""` for now. |
| `severity` | `info`, `warning` or `critical`. `critical` is only for a fault in the appliance itself: the power supply, a CPU that is too hot, or a failing microSD card. |
| `kind` | `psu`, `cpu_temp`, `sd_health`, `stylus`, `belt`, `bearing`, `sample_rate`, `dial_update`, `licence` or `no_input`. Lets a client group the same item on several inputs without parsing the title. |
| `subject` | The input's label for per-input kinds, otherwise `""`. |
| `title` | At most 40 characters. |
| `message` | At most 32 characters. |
| `link` | The Web UI page that deals with it (`/service`, `/setup#input2`, `/setup#dials`, `/setup`, `/about#system`), or `null`. |

### `outputs`

Besides the speakers, `outputs` carries `master_volume` (the mean level of
the selected speakers the appliance can reach, or `null` when there are
none) and `selected_count`, so a client does not work these out for itself.

The Auto-Start set is the speakers that start playing with each session. The
part describes it in three places:

| Field | Meaning |
|---|---|
| `units[].auto_start` | `true` for a speaker in the set, including the card of a member the player does not have at the moment. |
| `default_members` | The set, in order. Each entry has `key` (stable within the set), `id` (the saved speaker id, `""` for a member saved before ids were kept), `name` (the speaker's own name when it is present, else the saved name), `volume` (the saved level), `unit_id` (the card that stands for it), `placeholder` (`true` when the player has no such speaker and `unit_id` is the placeholder card) and `pending` (`true` while the appliance still means to add it in this session). |
| `default_matches` | `true` when the selected speakers are exactly the set, each at its saved level. A muted selection that otherwise matches still counts. A client can use it to show whether the current selection is already the saved one. |

A set with one member, which is every appliance that has not saved a larger
one, reads as before: that speaker is the only `auto_start` unit.

---

## Events: `GET /api/v1/events`

A Server-Sent Events stream. Every stream begins with `retry: 2000` and a
blank line. Then each change is one event:

```
id: 3f9a0c1d2e4b5a69-4812
event: change
data: {"boot":"3f9a0c1d2e4b5a69","version":4812,"resync":false,"data":{"outputs":{...},"warnings":{...}}}
```

- `data` holds the new value of each part that moved since the version the
  client last had, keyed by part name, as `GET /api/v1/state` shows it. Values that change continuously (levels, last-seen times) are as
  they were when the part last moved; a client that shows them reads the
  state route.
- `resync` is `true` when the appliance cannot say what moved: a new client,
  a restarted appliance, or an id it does not know. `data` is then empty,
  and the client fetches `GET /api/v1/state`.

To resume, send the last id as the `Last-Event-ID` header, or as `?since=`.
The stream mechanics (keep-alive comments, the folding of changes within
0.3 s, the five-minute lifetime, the origin check) are described in the
[Status API](STATUS-API.md#get-apiv1events-and-get-apiv1state-unstable-until-the-next-release-line).

### Limits

At most 64 streams are served at once and at most 8 to one client address.
Over either limit the reply is HTTP 200 with `"error": "too_many_clients"` or
`"too_many_from_address"`, `"retryable": true`.

### Named clients and the `access` event

A dial or another appliance opens the stream as `?client=dial:<id>` or
`?client=peer:<id>`, where `<id>` is 20 lowercase hex characters. A
malformed name is refused with HTTP 400 and `invalid_client`. Such a stream
also gets an `access` event, straight after `retry:` and again whenever the
answer changes:

```
event: access
data: {"client":"dial:0123456789abcdef0123","role":"playback","reason":null}
```

| `role` | `reason` | Meaning |
|---|---|---|
| `playback` | `null` | The client may send the playback intents. |
| `none` | `unconfigured` | The appliance is not set up yet. |
| `none` | `dial_not_authorized` | A dial that has not been authorised in Setup. |
| `none` | `auth_unavailable` | The list of authorised dials could not be read. Asked again shortly. |
| `none` | `control_disabled` | Another appliance, and this one is not set to be controlled by others. |

A stream that is refused is not closed. It still carries the state, which is
how an unauthorised dial can say so on its screen.

---

## Intents: `POST /api/v1/intents/<name>`

```json
{"args": {"level": 40}, "client": "dial:0123456789abcdef0123", "protocol": 4}
```

The body is a JSON object sent as `application/json`, at most 64 KiB.
`args` is an object (it may be left out for an intent with no arguments).
`client` and `protocol` are for a dial or another appliance. A page of the
Web UI sends neither and sends its CSRF token in the `X-CSRF-Token` header.

The reply is HTTP 200 with:

```json
{"ok": true, "error": null, "version": 4813, "boot": "3f9a0c1d2e4b5a69", "result": {}}
```

`version` is the state version after the change, so a client can wait for an
event at that version to see the effect. When `error` is `rate_limited`,
`retry_after_s` is also copied to the top level.

An intent may be answered before the player has finished. The speaker rows
wait up to three seconds for the player's verdict; a refusal that comes
later, such as a speaker asking for a PIN, appears in the `outputs` part
(its `availability` and `start_failure` fields) rather than in the reply.

### The intents

| Intent | Role needed |
|---|---|
| `outputs.set`, `output.pin.submit`, `outputs.want_default`, `outputs.save_default` | playback |
| `volume.step`, `volume.set`, `mute.set` | playback |
| `output.eq.set`, `output.eq.reset` | playback |
| `repeat.arm`, `repeat.transport`, `repeat.seek` | playback |
| `dials.authorize`, `dials.revoke` | admin |

Any other name is answered `unknown_intent`. The list is also in
`core/autostream_protocol.py` as `EXPOSED_INTENTS`. The speaker rows fill in
what a client may not choose: a client that sends `offset_ms` or `mode` with
a speaker intent, or `default_level` with a volume intent, is answered
`invalid_args`.

`volume.set` takes `level` from 0 to 100 and scales the selected speakers in
proportion; a level outside that range is `invalid_level`.

`outputs.save_default` takes no arguments. It makes the speakers that are
playing now the Auto-Start set, in the order of the `outputs` part, each at
the level it returns to if muted (the start volume when that level is 0). A
speaker waiting for a PIN is not saved. The reply's `result` is
`{"ok": true, "members": [{"id": "...", "name": "...", "volume": 30}]}`. It is
refused `nothing_selected` when no speaker is playing, and
`settings_unavailable` when the appliance cannot store the change. Once saved,
`default_matches` is `true` until the selection changes.

`outputs.want_default` takes `wanted` and, optionally, `id`, the card of a
member the player does not have at the moment (`placeholder` in
`default_members`). It asks for that member to be started when it appears, or
not. Without `id` it applies to the first such card.

### Who is asking

| Caller | Identified by | Role |
|---|---|---|
| A browser | Its session cookie. | `admin` when signed in or when no PIN is set, otherwise `playback`. |
| A dial | `client: "dial:<id>"` | `playback` when authorised in Setup. |
| Another appliance | `client: "peer:<id>"` | `playback` when this appliance allows control by others. |

A browser that also names a `client` is refused `invalid_client`. A caller
without the role an intent needs is refused `admin_required`.

### Refusal names

The reply's `error` is one of the names an intent itself returns (for
example `nothing_selected` and `settings_unavailable` from
`outputs.save_default`), or one of these from the protocol layer: `not_allowed`, `admin_required`,
`unconfigured`, `dial_not_authorized`, `auth_unavailable`, `control_disabled`,
`protocol_mismatch`, `unknown_intent`, `invalid_args`, `invalid_level`,
`rate_limited`.

Some failures are not a 200 reply, because the request never became an
intent: `400 invalid_json`, `400 invalid_client`, `400 unknown_part`,
`403 cross_origin`, `403 csrf_stale` and `413 body_too_large`. Errors that are not a 200 reply are
reported as described in the [API error contract](API-ERROR-CONTRACT.md).

While the appliance is not set up, every intent is answered `unconfigured`.
