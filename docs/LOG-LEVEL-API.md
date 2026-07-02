# Log-Level API

autostream exposes two JSON endpoints for reading and writing the active log level. The same state drives the Python logger, the monitor daemon, OwnTone, and NGINX access-log verbosity.

---

## Endpoints

### `GET /api/log-level`

Returns the current log-level state. Browser callers do not need PIN authentication.

**Response (200)**

```json
{
  "ok": true,
  "level": "info",
  "changed_by": "user",
  "changed_at": "2026-06-01T14:32:00Z"
}
```

| Field | Type | Description |
|---|---|---|
| `ok` | bool | Always `true` on success |
| `level` | string | Active level: `spam`, `debug`, `info`, `warning`, `error` |
| `changed_by` | string | `"user"` or `"system"` |
| `changed_at` | string or null | UTC ISO-8601 timestamp with `Z` suffix, or `null` if never set |

---

### `PUT /api/log-level`

Sets the active log level. Accepted from two caller classes with different authentication rules.

**Request body**

```json
{ "level": "debug" }
```

Valid levels (case-insensitive): `spam`, `debug`, `info`, `warning`, `error`.

Only the `level` field is accepted. Any other field causes a 400 error.

**Response (200)**

```json
{
  "ok": true,
  "level": "debug",
  "changed_by": "user",
  "changed_at": "2026-06-01T14:32:00Z",
  "changed": true,
  "applied": {
    "monitor": true,
    "owntone": null,
    "nginx": true
  }
}
```

| Field | Description |
|---|---|
| `changed` | `true` if the persisted level actually changed, `false` if it was already set |
| `applied.monitor` | `true` if the monitor daemon runtime level was updated |
| `applied.owntone` | `true` / `false` if OwnTone was reached (null if OwnTone is not configured) |
| `applied.nginx` | `true` if the NGINX access-log mode was updated |

**Error responses**

| Status | Meaning |
|---|---|
| 400 | Invalid or missing `level`, or unknown fields in the body |
| 500 | Persistence or application failure |

---

## Authentication model

### Browser requests (CSRF-protected)

Requests that arrive via NGINX (from a user's browser) must include:

- A valid `X-CSRF-Token` header for `PUT /api/log-level`

PIN authentication is not required for `GET` or `PUT /api/log-level`. The
`changed_by` field is automatically set to `"user"` for browser-proxied writes.
Callers cannot supply or override this value.

### Direct-local requests (internal services)

A request is treated as *direct-local* (bypassing PIN auth) only when **all** of the following are true:

1. The TCP peer is a loopback address (`127.x.x.x` or `::1`)
2. No `X-Forwarded-For` header is present
3. No `X-Real-IP` header is present
4. For `PUT` requests, the `Content-Type` is `application/json`

Conditions 2 and 3 ensure NGINX-proxied browser requests (which set both headers) are never misclassified as direct-local, even though NGINX itself connects to the Python server over loopback.

The `changed_by` field is automatically set to `"system"` for direct-local requests.

### Example: curl from the appliance itself

```bash
curl -s -X PUT http://127.0.0.1:8080/api/log-level \
  -H 'Content-Type: application/json' \
  -d '{"level": "debug"}'
```

This is a direct-local request and bypasses PIN auth. It is intended for internal services (e.g. the storage guard).

---

## Partial application semantics

`set_log_level` applies the level to four targets in sequence. Failures in later targets do not roll back earlier ones.

1. **Python logger** — always succeeds (in-process)
2. **Monitor daemon** — HTTP request to the monitor control port; may fail if the monitor is restarting
3. **OwnTone** — HTTP request to the OwnTone API; may fail if OwnTone is unavailable or not configured
4. **NGINX access log** — privileged helper (`autostream_admin set-nginx-access-log`); may fail if the helper is unavailable

When `applied.monitor` or `applied.owntone` is `false`, the level has still been persisted and the Python logger has been updated. The monitor and OwnTone will pick up the persisted level on their next restart.

---

## Automatic log-level expiry

The storage guard service (`autostream_storage_guard`) applies two automatic expiry rules when it runs (daily at 04:00 by default):

| Tier | Condition | Target |
|---|---|---|
| 1 | Level is `spam` or `debug`, older than 48 h | Restore to `info` |
| 2 | Level is `info`, older than 168 h (7 days) | Restore to `warning` |

Expiry applies regardless of `changed_by`. Both user-selected verbose levels and system-applied ones are eligible. The intent is that diagnostic levels left running for many days on a constrained SD-card appliance should be retired automatically.

---

## `GET /api/playing-status`

Returns whether the appliance is currently capturing audio.

**Direct-local access:** a loopback socket peer with no `X-Forwarded-For` or
`X-Real-IP` headers may call this endpoint without a PIN, CSRF token, agent ID,
or API key. Browser and proxied requests require normal session authentication.
A plain GET without a `Content-Type` header is accepted on the direct-local path.

**Response — known state (200)**

```json
{ "ok": true, "playing": false }
```

`playing` is always a JSON boolean when `ok` is `true`.

**Response — uncertain state (200)**

When the appliance cannot determine playback state (e.g. the audio monitor has
not started, or an internal query fails):

```json
{ "ok": false, "error": "playing status unavailable" }
```

**Consumers must treat uncertain responses conservatively.** Accept playback
state only when `ok` is exactly `true` and `playing` is a JSON boolean. Any
other shape — including `ok: false`, missing fields, or a non-boolean `playing`
— must be treated as unknown (not as stopped). The wifi watcher defers optional
USB adapter handover on uncertain responses; the storage guard does not raise
the log-level ceiling.

This endpoint has a direct-local bypass: the storage guard and wifi watcher call
it over loopback to check whether audio is playing before taking potentially
disruptive actions.

---

## Related files

| File | Purpose |
|---|---|
| `core/autostream_log_policy.py` | `get_log_level_state()`, `set_log_level()` |
| `core/autostream_webui.py` | HTTP routing, `_is_direct_local()`, `do_PUT()` |
| `core/autostream_webui_api.py` | `send_log_level_get_json()`, `send_log_level_put_json()` |
| `supervisor/autostream_storage_guard` | Automatic expiry and ceiling logic |
