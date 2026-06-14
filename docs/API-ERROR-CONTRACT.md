# API Error Transport Contract

This document is the authoritative reference for how HTTP error statuses are handled at
the main autostream NGINX boundary and the autostream-dial NGINX boundary.

---

## 1. Problem: NGINX Intercepts Structured Errors

The main autostream NGINX configuration contains:

```nginx
proxy_intercept_errors on;
error_page 404 502 503 504 = @upstream_failed;
```

`@upstream_failed` returns a `302` redirect to an offline page. This means that a
structured JSON error response from Python using one of these statuses:

```
HTTP 502
Content-Type: application/json

{"ok": false, "error": "dial_unreachable"}
```

never reaches the browser. NGINX replaces it with a redirect and the browser follows
the redirect to an HTML page.

The NGINX `error_page` directive does **not** intercept `400`, `401`, `403`, `409`, `429`,
or `500`. Those statuses pass through as normal HTTP responses.

---

## 2. Transport Status vs Semantic Status

This codebase uses two distinct concepts:

| Term | Meaning |
|---|---|
| **Transport status** | The HTTP status code that actually reaches the browser |
| **Semantic status** | The application-level HTTP status that describes the error outcome |

For statuses not intercepted by NGINX, transport status and semantic status are the same.

For the four intercepted statuses (`404`, `502`, `503`, `504`), the transport status is
`200` and the `error_status` field in the JSON body carries the semantic status.

---

## 3. Interception Tables

### 3.1 Main autostream boundary (port 80)

Served through `system/nginx/autostream-nginx.conf`:

| Semantic outcome | Browser transport status | JSON requirement |
|---|---:|---|
| Success | Native success status, normally `200` | Existing success body |
| Expected semantic `400`, `401`, `403`, `409`, `429`, or `500` | Same native status | Structured JSON |
| Expected semantic `404`, `502`, `503`, or `504` | `200` | `ok:false`, stable `error`, integer `error_status` |
| Unknown application route | Native `404` | NGINX offline redirect |
| Python service unavailable | NGINX-generated redirect | Existing offline behavior |

### 3.2 autostream-dial boundary (port 7842)

Served through `system/nginx/autostream-dial-nginx.conf`:

The dial NGINX intercepts `502`, `503`, and `504`, but **not** `400`, `403`, `404`,
`429`, or `500`. Native application statuses at the dial boundary:

| Outcome | Native status |
|---|---|
| Validation failure | `400` |
| PIN / recovery authorization failure | `403` |
| Inactive recovery status | `404` |
| Rate limiting | `429` with `Retry-After` |
| Persistence failure | `500` |
| Success | `200` |

Do not convert these dial-side responses to HTTP `200`. The dial NGINX boundary is
different from the main autostream boundary.

---

## 4. Canonical Tunneled Error Shape

Expected semantic `404`, `502`, `503`, and `504` failures must use:

```json
{
  "ok": false,
  "error": "remote_timeout",
  "error_status": 504,
  "retryable": true
}
```

Rules:

- `ok` is exactly `false`.
- `error` is a stable machine-readable identifier (not a human-readable message string).
- `error_status` is the semantic HTTP status that could not be used as the browser
  transport status.
- `retryable` is included when retry behavior is meaningful; omitted otherwise.
- Endpoint-specific fields may be retained alongside the required fields.
- Do not use `status` for the semantic HTTP code (existing update APIs use `status` for
  state names such as `in_progress`).
- Do not use `http_status` (the actual browser-visible HTTP status is `200`).
- Do not expose arbitrary target-provided status values as trusted browser semantics.

Native non-intercepted errors do not need a duplicated `error_status`.

---

## 5. Shared Helper

The `send_browser_api_error()` function in `core/autostream_webui_api.py` is the single
authoritative implementation of this mapping:

```python
send_browser_api_error(
    handler,
    semantic_status: int,  # e.g. 404, 502, 503, 504
    error: str,            # stable identifier e.g. "dial_offline"
    *,
    retryable: bool | None = None,
    extra: dict | None = None,
) -> None
```

The intercepted-status set is named `_NGINX_INTERCEPTED_STATUSES` in the same module.
Tests in `tests/test_browser_api_error_contract.py` assert that this constant matches
the deployed NGINX `error_page` configuration.

Do not add a second copy of this helper. The multi-appliance feature must reuse
`send_browser_api_error()`.

---

## 6. Unknown-Route Exception

The final route-dispatch `send_error(404)` calls in `core/autostream_webui.py` **must
not** be converted to `send_browser_api_error()`. Those represent unknown URLs that
should trigger the NGINX offline-redirect behavior for the browser. Structured domain
errors and routing errors are distinct.

---

## 7. Dial Proxy Error Identifiers

The host-side dial management proxy (`core/autostream_webui_dials.py`) uses these stable
error identifiers:

| Condition | `error` identifier | Semantic status | `retryable` |
|---|---|---:|---|
| UUID not in live dial registry | `dial_offline` | `404` | `true` |
| Connection refused / network failure / timeout | `dial_unreachable` | `502` | `true` |
| Target body not valid JSON, non-object root, or oversized | `dial_bad_response` | `502` | `true` |
| Target returned a redirect (`3xx`) | `dial_bad_response` | `502` | `true` |
| Target `503` | `dial_unavailable` | `503` | `true` |
| Target `504` | `dial_timeout` | `504` | `true` |
| Management dispatcher unknown path | `not_found` | `404` | — |
| Target `404` resource not found | `not_found` (or target-provided `error`) | `404` | — |

`dial_offline` is distinct from `not_found`: `dial_offline` means the host could not
locate the dial in the mDNS registry; `not_found` means the dial was reachable but the
target resource does not exist.

A target-provided stable `error` string is preserved when normalizing intercepted target
statuses. A target-provided `error_status` is always overridden with the actual target
status.

---

## 8. Examples

### 8.1 Dial offline (UUID not in registry)

Browser receives:
```
HTTP/1.1 200 OK
Content-Type: application/json

{"ok": false, "error": "dial_offline", "error_status": 404, "retryable": true}
```

### 8.2 Target unreachable (OSError / socket timeout)

Browser receives:
```
HTTP/1.1 200 OK
Content-Type: application/json

{"ok": false, "error": "dial_unreachable", "error_status": 502, "retryable": true}
```

### 8.3 Target `404` with endpoint-specific field

Target returns `HTTP 404 {"active": false}`. Browser receives:
```
HTTP/1.1 200 OK
Content-Type: application/json

{"ok": false, "error": "not_found", "error_status": 404, "active": false}
```

### 8.4 Native `400` validation error (not intercepted)

Browser receives:
```
HTTP/1.1 400 Bad Request
Content-Type: application/json

{"ok": false, "error": "missing_uuid"}
```

### 8.5 Target `503` service unavailable

Browser receives:
```
HTTP/1.1 200 OK
Content-Type: application/json

{"ok": false, "error": "dial_unavailable", "error_status": 503, "retryable": true}
```

### 8.6 Target `504` gateway timeout

Browser receives:
```
HTTP/1.1 200 OK
Content-Type: application/json

{"ok": false, "error": "dial_timeout", "error_status": 504, "retryable": true}
```

---

## 9. Guidance for Browser Clients

Browser callers must not assume `response.ok` (i.e., transport status `200..299`) means
the operation succeeded. They must inspect the JSON body for `ok: false`.

A discriminated result parser (`_parseDialResponse`) is embedded in the setup page
JavaScript. It returns:

```javascript
{
  ok: boolean,         // true only when body is a JSON object, ok !== false, transport 200..299
  transportStatus: number,
  body: object | null,
  error: string | null // stable error identifier or "invalid_response"
}
```

Rules for browser clients:

1. Inspect `Content-Type` before calling `.json()`. A redirected HTML page has
   `text/html`, not `application/json`. Attempting to parse HTML as JSON produces a
   misleading error.
2. Catch JSON parse failures — return a controlled `invalid_response` result, not an
   uncaught exception.
3. Require a JSON object root. Arrays, strings, numbers, booleans, and `null` are not
   valid API responses.
4. Treat `body.ok === false` as an application failure even when the transport status is
   `200`.
5. Prefer the stable `error` identifier for user-facing messages. Do not expose raw HTTP
   status codes as primary error labels.
6. Network failures (rejected `fetch()` promise) remain genuine network errors and are
   caught separately from structured application errors.

---

## 10. Guidance for Proxy and Gateway Authors

When adding a new host-side proxy endpoint:

1. Use `send_browser_api_error(handler, semantic_status, error_id, ...)` for all error
   branches, not `send_json(handler, 404, ...)` or similar.
2. Use `send_json(handler, 200, {...})` only for genuine success responses.
3. Do not pass target HTTP statuses through without checking whether NGINX will intercept
   them. Use `_NGINX_INTERCEPTED_STATUSES` to decide.
4. Limit target response body sizes before JSON parsing. The dial proxy uses a 64 KiB
   limit (`_MAX_PROXY_RESPONSE_BYTES`).
5. Reject target redirects (`3xx`) before JSON parsing. No managed endpoint legitimately
   redirects.
6. Require an object JSON root from the target. Arrays and primitives are protocol
   violations.

---

## 11. Warning: Handler-Only Unit Tests Are Insufficient

Unit tests that exercise the Python handler in isolation and assert `HTTP 404` or
`HTTP 502` responses appear correct in isolation but will break in production because
NGINX intercepts those statuses.

Always pair handler tests with NGINX policy tests. The test file
`tests/test_browser_api_error_contract.py` reads both `system/nginx/autostream-nginx.conf`
and `system/nginx/autostream-nginxd.conf` and asserts that `_NGINX_INTERCEPTED_STATUSES`
matches the deployed `error_page` directive. A future NGINX policy change must force an
explicit corresponding API-contract update.

---

## 12. Related Files

| File | Role |
|---|---|
| `core/autostream_webui_api.py` | `send_browser_api_error()`, `_NGINX_INTERCEPTED_STATUSES` |
| `core/autostream_webui_dials.py` | Dial proxy using the helper |
| `system/nginx/autostream-nginx.conf` | Main NGINX `error_page` policy |
| `system/nginx/autostream-nginxd.conf` | `$from_setup` and `$safe_next` maps |
| `system/nginx/autostream-dial-nginx.conf` | Dial NGINX (different interception set) |
| `tests/test_browser_api_error_contract.py` | Helper tests, NGINX policy tests, route distinction tests |
| `tests/test_webui_dial_proxy.py` | Dial proxy contract tests |
| `DIAL_PROTOCOL.md` | Wire protocol spec including management proxy section |
