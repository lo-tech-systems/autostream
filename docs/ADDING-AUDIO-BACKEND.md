# Adding A New Audio Backend

This project now supports pluggable playback back-ends instead of talking
directly to one specific OwnTone variant everywhere.

The abstraction is intentionally small:

- `core/autostream_players.py` defines the normalized backend contract.
- `core/autostream_player_service.py` resolves and caches the active backend.
- Concrete adapters such as `core/autostream_owntone.py` and
  `core/autostream_owntone_mini.py` translate between autostream's normalized
  model and a specific backend API.

This document describes how to add support for another backend.

## Overview

At runtime, the rest of autostream does not talk to backend-specific modules
directly. Instead it goes through `autostream_player_service`, which:

1. Detects which backend is available at the configured `base_url`.
2. Creates the matching backend adapter.
3. Exposes backend-neutral operations such as:
   - listing outputs
   - enabling/disabling outputs
   - setting output volume/offset
   - pushing metadata
   - reading/saving normalized settings

The Web UI and core capture/playback flow then branch only on capability flags,
not on concrete backend types.

## Files To Understand First

Read these files before implementing a new adapter:

- `core/autostream_players.py`
- `core/autostream_player_service.py`
- `core/autostream_owntone.py`
- `core/autostream_owntone_mini.py`
- `core/autostream_core.py`
- `core/autostream_webui_page_owntone.py`
- `core/autostream_webui_post_handlers.py`

The two existing OwnTone adapters are the best reference implementations:

- `autostream_owntone.py` shows a backend with a broad output API but very few
  runtime settings.
- `autostream_owntone_mini.py` shows the pared-back backend that supports extra
  normalized settings, metadata push, pipe refresh, and restart-required reporting,
  but a much less rich feature-set.

## Step 1: Create A Backend Module

Add a new module in `core/`, for example:

- `core/autostream_mybackend.py`

The module should define one concrete class implementing `PlayerBackend`, or
more commonly subclassing `OwnToneHttpBackendBase` if the backend is still
HTTP/JSON based and close enough to reuse those helpers.

Typical pattern:

```python
from autostream_players import (
    ActionResult,
    BACKEND_OWNTONE,
    BackendCapabilities,
    BackendStatus,
    DetectionResult,
    GetOutputResult,
    ListOutputsResult,
    OwnToneHttpBackendBase,
    REGISTRY,
    SaveSettingResult,
    SettingDescriptor,
    SettingValueResult,
)


class MyBackend(OwnToneHttpBackendBase):
    BACKEND_ID = "my-backend"

    @classmethod
    def backend_id_cls(cls) -> str:
        return cls.BACKEND_ID

    # implement the required methods here


REGISTRY.register(MyBackend)
```

Registration is explicit. The module must register itself with `REGISTRY`.

## Step 2: Add A Stable Backend Identifier

In `core/autostream_players.py`, add:

- a new `BACKEND_*` constant
- the backend id to `KNOWN_BACKEND_IDS`
- the backend id to `PREFERRED_DETECTION_ORDER` if it should be probed early

Detection order matters. Put more specific backends first and more generic
fallbacks later.

Example:

```python
BACKEND_MY_BACKEND = "my-backend"

KNOWN_BACKEND_IDS = (
    BACKEND_OWNTONE,
    BACKEND_OWNTONE_MINI,
    BACKEND_MY_BACKEND,
)

PREFERRED_DETECTION_ORDER = (
    BACKEND_MY_BACKEND,
    BACKEND_OWNTONE_MINI,
    BACKEND_OWNTONE,
)
```

## Step 3: Ensure The Built-In Import Path Knows About It

`create_backend()` and `detect_backend()` rely on
`ensure_builtin_backends_registered()`.

Add your module import there:

```python
import autostream_mybackend  # noqa: F401
```

Without this, your adapter will never be registered in normal startup.

## Step 4: Implement Detection Carefully

Your adapter's `detect()` method should answer one question:

"Does the target at `base_url` look like this backend?"

Keep detection:

- fast
- read-only
- specific
- log-friendly

Good detection signals:

- a backend-specific config endpoint
- a product name or version field
- a unique capability/route only that backend exposes
- a distinctive response shape

Avoid detection based only on very generic endpoints if another backend might
also satisfy them.

Return a `DetectionResult` with:

- `matched=True` when the backend is confidently identified
- a useful `detail` string for logs

## Step 5: Advertise Capabilities Honestly

`get_capabilities()` is how the rest of the app decides what UI and runtime
features can be used safely.

Set these flags conservatively:

- `can_list_outputs`
- `can_get_output`
- `can_set_output_enabled`
- `can_set_selected_outputs`
- `can_set_output_volume`
- `can_set_output_offset`
- `can_submit_output_pin`
- `can_set_output_mode`
- `can_play`
- `can_stop`
- `can_ensure_pipe_source_ready`
- `can_refresh_runtime_state`
- `can_push_metadata`
- `can_restart`
- `supports_runtime_settings`
- `supports_restart_required_reporting`

If the backend cannot do something reliably, return `False` and have the method
return an `unsupported` result instead of trying to fake support.

## Step 6: Normalize Outputs Into `OutputInfo`

The rest of autostream expects outputs to look like `OutputInfo`.

Populate these fields where possible:

- `id`
- `name`
- `type`
- `selected`
- `volume_percent`
- `offset_ms`
- `has_password`
- `requires_auth`
- `needs_auth_key`
- `available`
- `current_mode`
- `supported_modes`
- `extra`

Important conventions:

- `id` must be stable enough to persist config against it.
- `name` is user-facing and appears throughout the Web UI.
- `volume_percent` should be clamped to `0..100`.
- `offset_ms` should be `None` if the backend does not expose or support it.
- `supported_modes` should contain normalized mode ids from
  `autostream_players.py`, not backend-native strings.

If your backend is OwnTone-like, `OwnToneHttpBackendBase._normalize_output_info`
already handles the common fields.

## Step 7: Map Backend-Native Modes To Normalized Modes

Autostream uses these normalized output-mode values:

- `OUTPUT_MODE_AUTO`
- `OUTPUT_MODE_AIRPLAY1`
- `OUTPUT_MODE_AIRPLAY2`

If your backend exposes transport/protocol selection, convert to and from these
values inside the adapter.

The service layer already provides helpers for config compatibility:

- `config_airplay_mode_to_backend()`
- `backend_output_mode_to_config()`
- `output_supported_config_modes()`

Mode selection is handled inside `update_output()`, not as a separate method.
If your backend does not support mode, absorb the `mode` parameter silently
inside `update_output()`: log at `INFO` and omit the mode field from any
request payload.  Return `ok=True` so callers are not affected.
Set `can_set_output_mode=False` in `get_capabilities()` so the Web UI hides
mode controls for outputs served by this backend.

## Step 8: Support Normalized Settings Where They Make Sense

Normalized settings currently defined in `autostream_players.py`:

- `SETTING_BUFFERED_AUDIO_ENABLED`
- `SETTING_DEVICE_REMOVAL_GRACE_PERIOD`
- `SETTING_IPV6`
- `SETTING_LOG_LEVEL`
- `SETTING_PIPE_AUTOSTART`
- `SETTING_PIPE_PATH`
- `SETTING_PIPE_SAMPLE_RATE`
- `SETTING_PIPE_BITS_PER_SAMPLE`
- `SETTING_RESAMPLE_QUALITY`
- `SETTING_START_BUFFER_MS`
- `SETTING_UNCOMPRESSED_ALAC`
- `SETTING_USER_AGENT`

If your backend supports any of these, implement:

- `get_setting(key)`
- `save_setting(key, value)`
- `list_supported_settings()`

Use `SettingDescriptor` to describe:

- value type
- label
- writable status
- restart requirements
- bounds / allowed values

If a setting is unsupported, return:

- `SettingValueResult(ok=False, unsupported=True, error_code="unsupported", ...)`
- `SaveSettingResult(ok=False, unsupported=True, error_code="unsupported", ...)`

That is how the Web UI knows to hide or disable controls cleanly.

## Step 9: Declare Your Pipe Format Requirement

The monitor daemon (`autostream_monitor`) can write its FIFO in one of two
formats: `"native"` (48000 Hz / 32-bit / 2ch, the default) or `"compatible"`
(44100 Hz / 16-bit / 2ch, started with `--compatible`). Which one your
backend needs is declared through a single contract method:

```python
def required_monitor_format(self) -> Optional[str]:
    ...
```

defined on `PlayerBackend` in `core/autostream_players.py`, returning one of:

- `"native"` — the backend can consume 48000 Hz / 32-bit / 2ch.
- `"compatible"` — the backend needs (or is safest assuming) 44100 Hz /
  16-bit / 2ch.
- `None` — unknown right now, e.g. the backend is unreachable. Callers
  (`reconcile_monitor_format()` in `autostream_player_service.py`) treat
  `None` as "take no enforcement action this pass" — never as either
  concrete format.

**The default, and why.** `PlayerBackend.required_monitor_format()` is a
concrete (non-abstract) method with a default implementation of
`"compatible"`, not `"native"`. A new adapter that does not override it
inherits this default automatically. `"compatible"`'s 44.1kHz/16-bit wire
format is what a fixed, un-configurable pipe input already expects (it is
exactly the official OwnTone adapter's situation — see
`core/autostream_owntone.py`), so it is universally consumable by an unknown
backend. Defaulting to `"native"` instead would silently start feeding a
48kHz/32-bit stream to a backend that never declared it could accept one.
Only override the default if your backend actually supports (or requires)
`"native"`.

**A static answer is usually enough.** If your backend has one fixed pipe
format, a one-line override is all you need — see
`OwnToneBackend.required_monitor_format()`, which unconditionally returns
`"compatible"` because upstream OwnTone's named-pipe input is fixed and has
no settings surface to change it.

**Reference dynamic example.** If whether your backend can accept the native
format depends on the deployed backend version/build, probe for it instead
of hard-coding an answer. `OwnToneMiniBackend.required_monitor_format()` in
`core/autostream_owntone_mini.py` is the reference implementation: it reads
`SETTING_PIPE_SAMPLE_RATE` via `get_setting()` — a successful read means the
key is API-settable, so it returns `"native"`; an `unsupported` (404) result
means an older mini build predating pipe-format settings, so it returns
`"compatible"` (that build's self-healed config defaults are already
44100/16, so nothing needs pushing and nothing could be pushed anyway); a
transport failure returns `None`. It caches the definitive answers
(`"native"`/`"compatible"`, never `None`) module-level, keyed by `base_url`
rather than by instance — `resolve_backend()` in
`core/autostream_player_service.py` constructs a fresh adapter instance on
every call, so an instance attribute would never actually be reused across
calls. See the module-level comment above `_monitor_format_probe_cache` in
`autostream_owntone_mini.py` for the full rationale and TTL.

## Step 9a: The Output Resampler Quality Setting Is Optional

`SETTING_RESAMPLE_QUALITY` (`"high"` / `"standard"`) is an owntone-mini
extension, not part of the core contract: it is only meaningful for a
backend whose output stage inserts a resampler on format-mismatched output
paths and exposes a tunable quality knob for it. Most backends have no such
knob, and that is fine.

The push side (`push_resample_quality()` in
`core/autostream_player_service.py`) is capability-aware by construction, the
same way `reconcile_pipe_format_with_backend()` handles the pipe-format keys:
it calls the normalized `save_setting()` path and treats an `unsupported`
result (whatever `get_setting()`/`save_setting()` return for a key your
adapter does not recognise) as a debug-logged no-op, never a failure. A
backend that simply omits `SETTING_RESAMPLE_QUALITY` from its setting specs
(or, like `OwnToneBackend`, has no normalized-settings surface at all) is
automatically covered — **stock/full OwnTone keeps its stock resampling
behaviour regardless of the selected Audio Path tier**, and no adapter code
is needed to make that true.

If your backend does implement this key, a value save can also fail because
the deployed build predates the key (e.g. an older owntone-mini) — treat
that the same as any other unrecognised-key rejection: log it and let the
caller retry on the next reconcile pass rather than treating it as fatal
(the `set_repeat_enabled` old-binary rule).

## Step 10: Preserve Result Semantics

The result types are part of the contract. Try to follow the existing patterns:

- `ActionResult`
  - use for mutating operations
  - set `restart_required=True` when the change needs a backend restart
- `ListOutputsResult`
  - use for output enumeration
- `GetOutputResult`
  - use for single-output fetches
- `SettingValueResult`
  - use for reads
- `SaveSettingResult`
  - use for writes

All five expose a shared `.message` property — `error or error_code`, and
`error or detail or error_code` for `ActionResult`. This is what the rest of the
app reads when it surfaces a failure to the logs or the UI (for example
`autostream_webui_api.py` and `autostream_player_service.py`), so populate
`error` / `error_code` consistently on every method rather than only on the
mutating ones.

Recommended error-code conventions already used by the project:

- `unsupported`
- `request_failed`
- `http_error`
- `no_response`
- `invalid_payload`
- `missing_output_id`
- `not_found`
- `missing_pin`
- `pin_required`
- `pin_invalid`
- `not_ready`

Reuse these where possible so the rest of the app can react consistently.

## Step 11: Handle Startup And Runtime Hooks

`autostream_core.py` uses backend-neutral calls during startup and playback.
A new backend should consider these operations especially carefully:

- `ensure_pipe_source_ready()`
  - called during startup before monitors begin streaming
  - useful when the backend needs to index or discover the configured FIFO/pipe
- `refresh_runtime_state()`
  - used after reconnect/restart to re-apply transient state
- `push_metadata()`
  - extension point for roadmap metadata backends; not currently called at runtime
- `stop()` and `set_selected_outputs([])`
  - used during teardown and input handoff

If a backend does not support one of these, return `unsupported` cleanly.
Do not silently succeed unless "no-op success" is actually the correct
behavior.

## Step 12: Think About Persistence Keys

Autostream persists some speaker-specific state in config sections such as:

- `owntone_offsets`
- `owntone_airplay_modes`
- `owntone_known_outputs`

Today these sections are still named around OwnTone, but they are really
backend-output persistence stores keyed by output id.

For a new backend to work well:

- output ids should remain stable across restarts when possible
- output names should be reasonably stable for UI continuity
- a rediscovered output should ideally come back with the same id

If your backend cannot provide stable ids, plan for extra translation or a new
persistence strategy before enabling advanced per-output settings.

## Step 13: Update Installation Or Provisioning Only If Needed

If the new backend requires:

- extra packages
- a different daemon
- config-file provisioning
- systemd units
- bootstrap scripts

then update the installation path as needed, likely in:

- `autostream_install.sh`
- `system/systemd/*`
- `system/sudoers/*`
- backend-specific helper scripts if required

Keep the backend adapter itself focused on the runtime control plane. Avoid
mixing system provisioning logic into the Python backend module.

## Suggested Implementation Checklist

1. Add backend id constants and detection ordering in
   `core/autostream_players.py`.
2. Import the new module in `ensure_builtin_backends_registered()`.
3. Create `core/autostream_<name>.py`.
4. Implement `detect()`.
5. Implement `get_capabilities()`.
6. Implement output listing and output mutation methods.
7. Implement settings methods for any supported normalized settings.
8. Override `required_monitor_format()` if your backend supports `"native"`
   (statically or via a probe like `OwnToneMiniBackend`'s); otherwise the
   default `"compatible"` answer already covers it correctly.
9. Register the backend with `REGISTRY.register(...)`.
10. Verify the Web UI renders correctly when unsupported capabilities are
    returned.
11. Verify startup, reconnect, teardown, and metadata paths in
    `autostream_core.py`.

## Testing Recommendations

Minimum checks before considering a backend integration complete:

- Detection selects the new backend at the intended `base_url`.
- Detection does not falsely match an existing backend.
- `/setup` still lists available outputs correctly.
- `/owntone-setup` behaves sensibly for unsupported controls.
- The home page can enable/disable outputs and change volume.
- Startup does not regress if the backend is temporarily unavailable.
- Teardown and reconnect do not leave stale selected outputs behind.
- Unsupported features degrade gracefully instead of throwing exceptions.

## Design Notes

The current abstraction is intentionally pragmatic rather than fully generic.
It is optimized around the operations autostream already needs today.

That means:

- the "backend" API is output/playback oriented
- some legacy naming still references OwnTone
- UI routes such as `/owntone-setup` are still OwnTone-branded even though they
  now consume normalized backend services

If a future backend is substantially different, it may be better to extend the
normalized contract first rather than force a poor translation layer.

## Example Starting Point

If the new backend is:

- another OwnTone-compatible API: subclass `OwnToneHttpBackendBase`
- HTTP/JSON but not OwnTone-shaped: implement `PlayerBackend` directly, and
  copy only the helper patterns you need
- file/config driven rather than HTTP driven: implement `PlayerBackend`
  directly and keep detection/settings logic local to that module

In general, start with the smallest honest capability set, get detection and
basic output control working first, then add settings, metadata, and advanced
mode support afterwards.
