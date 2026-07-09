# Web UI Log Level — Forward to the Wi-Fi Watcher

**Status:** Complete on branch `refactor/wifi-watcher-structure`.

| WP | Commit | Suite result |
|---|---|---|
| LF-1 — Forwarding | `aafb6f6` | 5281 passed / 103 skipped |
| LF-2 — Docs + status | `6af75b4` | 5281 passed / 103 skipped |

The startup forward (decision 3) landed in `core/autostream_core.py`,
`run_autostream`, beside `apply_startup_log_level` — the sole caller of that
function.

Hardware validation checklist below remains **PENDING**.

**Context:** The watcher gained DEBUG-level BSSID scan logging (SL-1,
`35e41fb`), but its runtime log level is only reachable via its
token-protected loopback control API — the web UI's log-level control does
not touch it, so the diagnostics are unreachable without shell access.
Suite baseline entering this stage: 5365 total (5262 passed / 103 skipped on
the dev workstation; split drifts environmentally — every WP captures its
own pre-change run).

## Problem statement

Changing the log level in the autostream web UI calls
`autostream_log_policy.set_log_level(...)`, which persists the level to the
app config and applies it to the main platform (and nginx verbosity) — but
nothing forwards it to the wifi watcher. The watcher's level is set only by
`AUTOSTREAM_WIFI_LOG_LEVEL` at service start or by hand-crafted POSTs to its
control API. The web UI already maintains a bounded, token-authenticated
proxy to that API (`_watcher_request`, fixed paths including
`/network_control`), and the watcher's `/network_control` already accepts a
`set_log_level` action — the transport, auth, and receiving action all
exist; only the forwarding is missing.

## Decisions (final — do not revisit)

1. **Level mapping** (app vocabulary `fatal/log/warning/info/debug/spam` →
   watcher runtime vocabulary `warning/info/debug`):
   `spam`/`debug` → `debug`; `info` → `info`;
   `warning`/`log`/`fatal` → `warning`.
2. **Debug TTL:** the watcher's TTL rule is unchanged. Forwarded `debug`
   carries `ttl_seconds = 3600` (the watcher's maximum); the watcher
   auto-reverts to its default after an hour even if the app level remains
   debug. `info`/`warning` forward without a TTL (persistent until watcher
   restart). This preserves the never-leave-debug-on safety property.
3. **Restart drift:** forward on every successful UI/system level change AND
   once at web-UI startup (where the persisted log policy is already applied
   with `_startup=True` — find that call site by grep and forward from the
   same place). A watcher-only restart mid-session still drifts to its env
   default until the next UI change or webui restart — accepted, documented
   limitation.
4. **No UI display** of the watcher's level (explicitly decided against; do
   not add).
5. **Best-effort:** a forwarding failure (watcher down, token unreadable,
   timeout) must NEVER fail the app-level change. Log one WARNING and record
   the outcome in the response's `applied` map.

## Scope

In scope:

1. A small forwarding helper in `core/autostream_webui_api.py` using the
   existing `_watcher_request` proxy: maps the app level per decision 1 and
   POSTs `{"action": "set_log_level", "level": <mapped>, "ttl_seconds":
   3600}` (ttl only for debug) to `/network_control`.
2. Call it after every successful `set_log_level` in the log-level PUT
   handler (both `changed_by="user"` and `"system"` — forward whenever the
   app level actually changed successfully).
3. Call it once at web-UI startup after the persisted policy is applied.
4. Surface the outcome as `applied["wifi_watcher"] = bool` alongside the
   existing `applied["nginx"]` pattern (added in the handler, NOT inside
   `autostream_log_policy` — the policy module stays free of watcher
   knowledge).
5. Tests.
6. A brief `docs/WIFI-WATCHER.md` note (runtime level follows the web UI's
   level, mapped; debug auto-reverts after 1 h; watcher restart reverts to
   env default until the next change).

Out of scope — do not implement or "improve" beyond this list:

- Any change to the watcher side: `RUNTIME_LOG_LEVELS`, the TTL rule
  (60–3600, required for debug), `validate_log_level_request`, or the
  control-token mechanism are all unchanged.
- Re-arming/refreshing the debug TTL from the webui (decision 2 accepts the
  1 h revert).
- Displaying the watcher level anywhere in the UI (decision 4).
- The dial product (it has no main-webui log-level endpoint; its watcher
  keeps env-only control).
- New config keys, env vars, or constants beyond the mapping table.

No backward compatibility is required, but note the log-level PUT response
gains a key inside `applied` — update any test asserting that dict's exact
shape rather than weakening it.

## Current code pointers (verified against the branch)

- `core/autostream_webui_api.py` — the log-level PUT handler (~line 2075:
  validates fields, calls `autostream_log_policy.set_log_level(
  state.config_path, requested_level, changed_by=...)`, returns the result
  dict). The watcher proxy lives just below (~line 2113):
  `WATCHER_CONTROL_BASE` (`http://127.0.0.1:9080`),
  `WATCHER_CONTROL_TOKEN_PATH` (`/run/autostream/wifi-control.token`),
  `WATCHER_CONTROL_HEADER`, `_read_watcher_control_token()`,
  `_watcher_request(method, path, body)` with the fixed-path allowlist
  already including `/network_control`, `_WATCHER_TIMEOUT = 4.0`.
- `core/autostream_log_policy.py` — `set_log_level(config_path, level, *,
  changed_by, now, _startup)`; `VALID_LOG_LEVELS` imported from
  `autostream_config`; result dict carries `applied` (e.g.
  `applied["nginx"]`). Find the `_startup=True` caller by grep — that is the
  webui-startup application site for decision 3.
- `platform/wifi_web.py` — the receiving side (`/network_control`,
  `action == "set_log_level"` ~line 1010; `validate_log_level_request`
  clamps TTL to [60, 3600] and requires it for debug; auth =
  loopback + per-boot token header). Request body shape (from
  `tests/test_wifi_web_routes.py` ~line 501):
  `{"action": "set_log_level", "level": "debug", "ttl_seconds": 900}`.
- `platform/wifi_watcher.py` — `RUNTIME_LOG_LEVELS = {"warning", "info",
  "debug"}`; the queued control action is consumed by the monitor loop
  (`process_control_action` → `apply_log_level`). Note the action is
  *queued* (`pending_control_action`) and returns before application — the
  forward's success means "accepted", not "applied"; name the result field
  accordingly in code comments if it matters, but `applied["wifi_watcher"]`
  matching the nginx pattern is fine.
- Tests for the PUT endpoint: locate by grep (`log_level` in
  `tests/test_wp3_settings_api.py`, `tests/test_webui_post_handlers.py`,
  `tests/test_about_system_page.py` are the likely homes). The watcher-proxy
  helpers have existing tests near the network-status proxy tests
  (`tests/test_wp7_network_api.py`) — follow their mocking style
  (patch `_watcher_request` / `_read_watcher_control_token`).

## Design

New helper in `core/autostream_webui_api.py` beside the proxy:

```python
_WATCHER_LEVEL_MAP = {
    "spam": "debug", "debug": "debug",
    "info": "info",
    "warning": "warning", "log": "warning", "fatal": "warning",
}
_WATCHER_DEBUG_TTL_SECONDS = 3600

def forward_log_level_to_watcher(app_level: str) -> bool:
    """Best-effort: map and forward *app_level* to the watcher's control API.
    Returns True when the watcher accepted the request."""
```

Behaviour: map the level (unknown level → return False without a request —
cannot happen for a validated level, but stay defensive); no token readable
→ return False quietly (debug log; the watcher may simply not be running);
build the body with `ttl_seconds` ONLY for debug; POST via
`_watcher_request("POST", "/network_control", body)`; True iff HTTP 200 and
`data.get("ok") is True` (check the actual success shape of the route in
wifi_web.py and match it); any exception → WARNING log, False. Exactly one
WARNING per failed forward; no retries (the next level change or webui
restart re-forwards).

Call sites:

1. In the PUT handler, after `result.get("ok")` is confirmed and before the
   200 response: `result.setdefault("applied", {})["wifi_watcher"] =
   forward_log_level_to_watcher(<the level that was set>)`. Use the
   normalized level from the result if the policy returns it, else the
   validated request level.
2. At the webui-startup policy application site (the `_startup=True`
   caller): forward the persisted level the same way after it applies.
   Best-effort; a False return at startup is a debug-level log only (the
   watcher's token may not exist yet if it starts later — accepted).

## Testing plan

Endpoint/forwarding tests (in the PUT endpoint's existing test home; mock
`_watcher_request` / token reader per the existing proxy-test style):

1. Mapping: each app level forwards the mapped watcher level — spam→debug,
   debug→debug, info→info, warning/log/fatal→warning.
2. TTL: forwarded debug carries `ttl_seconds == 3600`; info/warning bodies
   contain no `ttl_seconds` key.
3. Best-effort: watcher request raising / returning non-200 / token missing
   → the PUT still returns 200 with the app level applied, and
   `applied["wifi_watcher"] is False`; success → True.
4. A failed app-level set (invalid level) forwards nothing.
5. Startup: the startup policy application forwards once with the persisted
   level (patch the forward helper; assert called with the mapped level).
6. Update (never weaken) any existing test asserting the exact `applied`
   dict shape.

Receiving side: NO new watcher-side tests needed (the action, validation and
TTL clamping are already covered by `tests/test_wifi_web_routes.py`); do not
modify watcher code or tests.

Verification commands:

```
python -m pytest tests/test_wp3_settings_api.py tests/test_webui_post_handlers.py tests/test_wp7_network_api.py -q   # adjust to the actual homes found
python -m pytest tests/ -q          # full gate before every commit
```

Full-suite gate: zero failures; total grows only by the tests added in that
WP.

## Work packages (one commit each, on `refactor/wifi-watcher-structure`)

### LF-1 — Forwarding

The helper, both call sites, `applied["wifi_watcher"]`, and all tests above.
Commit: `webui: forward log-level changes to the wifi watcher`

### LF-2 — Docs + status

`docs/WIFI-WATCHER.md`: one short paragraph in the runtime log-level section
(follows the web UI's level via the control API, with the mapping; debug
auto-reverts after 1 h; a watcher restart reverts to the env default until
the next change or webui restart). Update this plan's Status block to a
completion record (commits + counts). Full suite unchanged (docs-only).
Commit: `wifi: document web-UI log-level forwarding`

## Conventions (every WP)

- Run every command in the foreground (no background tasks, watchers, or
  monitors); full suite `python -m pytest tests/ -q`, timeout 600000ms.
- Code comments state behaviour and constraints only — no plan/WP/history
  references.
- Never weaken a test assertion.

## Hardware validation checklist (PENDING — add to the accumulated list)

1. Set debug in the web UI on a live appliance: watcher log shows the level
   change with TTL, BSSID scan lines appear, and the watcher reverts to its
   default after 1 h while the app stays at debug.
2. Set info/warning: watcher follows persistently (until its next restart).
3. Stop the watcher service, change the level in the UI: change succeeds,
   response carries `applied.wifi_watcher = false`, one WARNING in the webui
   log.
