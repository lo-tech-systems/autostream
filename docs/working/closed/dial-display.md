# Autostream Dial Display Plan

**Status:** Implementation complete. WP-1 through WP-8 have all landed (see
each WP's **Status: done** note below for commit details, tests, and
verification results). This document is kept as the implementation record;
new hardware variants or v2 changes should start a fresh plan rather than
reopening this one.

## Goal

Add optional support for a 1.8-inch TFT color display module using the ST7735S
controller over SPI.  When an authorized autostream appliance is playing and
track identification has produced an artwork match, the dial displays that
album artwork.  In every other state, the dial displays the autostream logo
from `images/autostream-logo-centred-dark.png`.

If no screen is fitted, the display runtime is no-op and no logo or artwork is
shown; volume control remains unchanged.

Fallback states include:

- no `_autostream-playing._tcp` appliances visible;
- no authorized visible appliance;
- track identification disabled;
- track identification enabled but not currently identified;
- no match found;
- matched track has no artwork URL;
- artwork fetch, decode, or display render failed.

The dial remains primarily a simple volume controller: rotary input continues
to fan out to all currently playing authorized appliances.  The display chooses
one artwork source at a time.

## Decisions

- Extend the existing v1 dial API during the pre-release dial development
  phase.  Do not add a new `dial_nowplaying=v1` mDNS capability yet.
- Keep `_autostream-playing._tcp` as the runtime discovery signal.  Appliances
  appear only while playback is active and disappear when playback stops.
- Add now-playing fields to the UUID-authorized dial status response, grouped
  under a `track_id` object.
- Autostream appliances expose the provider artwork URL they already receive
  from Track ID.  The dial fetches artwork directly and treats display/artwork
  failures as non-fatal.
- Do not add an appliance-side artwork cache, nginx route, `/dial-artwork/...`
  URL space, or cache-control behavior for dial artwork in this design.
- Compare artwork source identity using **only the provider artwork URL**.
  Multiple tracks may share the same album cover; if the artwork URL is
  unchanged, keep the current rendered image in memory even if title, artist, or
  album changes.  Do not add a persistent artwork cache in v1.
- Keep Track ID snapshot ownership unchanged: existing public/home UI artwork
  fields continue to mean the provider artwork URL.
- Keep artwork fetch, decode, crop, resize, rotation, and display work on the
  dial so the appliance's real-time media path stays simple.
- Dial target display selection is ordered by oldest `playing_since`.
- Keep the existing dial GPIO stack on `gpiozero` plus `python3-lgpio`.  Do
  not migrate encoder, button, or LED handling to `RPi.GPIO`.
- Use `adafruit-circuitpython-rgb-display` as the first real ST7735S backend.
  Install it in the dial venv; keep hardware imports lazy so missing display
  dependencies never break a dial with display disabled.
- Use apt for binary/system dependencies: `python3-pil` in the image-processing
  WP, `python3-spidev` in the ST7735S hardware WP, and the existing
  `python3-lgpio`.
- Use a fixed v1 ST7735S wiring/config profile.  The browser-facing setting is
  only whether a screen is fitted.  Do not expose offsets, BGR/invert, SPI
  device selection, custom pins, idle modes, or artwork fit controls in v1.
- Persist the screen-fitted flag in the dial config object and expose it through
  the existing dial HTTP API on port `7842`.
- Surface only a screen enabled/fitted toggle on the main autostream
  Setup -> Dials page through the existing dial-management proxy.
- Use Raspberry Pi SPI0 with the fixed v1 wiring profile.  SPI1 and custom
  wiring are deferred until there is an explicit remapping design.
- Validate dial-fetched artwork URLs more strictly than general Track ID
  provider URLs: only `https://` URLs with DNS hostnames, no IP literals, no
  `.local` names, and no non-default port.  Do not resolve DNS and block
  private or internal result addresses in v1.
- Keep artwork URL validation changes local to the status serialization and dial
  display code.  Do not introduce a shared `core/autostream_artwork_urls.py`
  module in v1.

## Current Context

Existing dial behavior:

- `dial/dial_mdns.py` browses `_autostream-playing._tcp`.
- `dial/dial_volume.py` sends `POST /api/dial/volume` and
  `POST /api/dial/mute` to all discovered playing targets.
- `dial/dial_target_status.py` already enriches targets via
  `POST /api/dial/status` when the target advertises `dial_status=v1`.
  Its existing list-enrichment behavior is for local control/status
  presentation and must not become the display source-selection policy.
- Dial authorization uses the dial UUID in request JSON and the appliance
  `dials.json` allowlist.

Existing appliance behavior:

- `system/avahi/autostream-playing.service` advertises `dial_api=v1`,
  `audio_status=v1`, and `dial_status=v1`.
- `core/autostream_webui_api.py` implements `POST /api/dial/status` as a
  read-only UUID-authorized endpoint.
- Track identification state is represented by `TrackIdentificationSnapshot`
  with `enabled`, `state`, `title`, `artist`, `album`, `artwork_url`, and
  timestamps.
- Track ID currently stores provider artwork as an external URL in memory; it
  does not maintain a local artwork cache for dial use.

## Implementation Rules

Work packages are sequential.  Finish one WP with tests passing and, when this
plan is being used for implementation, commit it before starting the next.
Each WP must be small enough to review on its own and must leave the product in
a coherent state.  The full feature can still be completed in one continuous
coding session by working through the WPs in order; there is no hardware
verification stop between WPs.

For each WP:

- update the named documentation in the same commit as the behavior it
  documents;
- add or migrate tests in the same commit as the code they cover;
- run the focused tests named in the WP;
- run the broader verification baseline before declaring the WP complete;
- if new deployed files are added, update installer deployment and deployment
  guard tests in the same WP;
- do not change existing dial volume/mute behavior except where this plan
  explicitly says to do so;
- keep display-disabled installs behaviorally identical to current dial
  installs.

After completing a WP, append a short **Status: done** note to that WP section
in this plan with the commit id, files changed, tests run, documentation
updated, and installer/deployment impact.  Keep these implementation notes in
this plan, not in runtime code comments.

Completion is based on automated tests, syntax checks, mocked backend tests, and
installer/config assertions.  Do not require physical display tests, manual
hardware checks, or "pending hardware verification" notes for feature
completion.

## Logging Policy

Use concise, rate-limited logs.  Display and artwork failures must be visible
enough to diagnose, but must not flood the log while a provider image URL or a
display cable is bad.

Rate limiting is based on consecutive identical log message keys.  A message
key includes the failure class plus its stable scope, such as source URL hash,
display backend, or logo path.  Emit the first occurrence and every 10th
consecutive repeat of the same key.  Whenever a different log message key is
written through the same limiter, reset the repeat count for the new key so its
first occurrence is visible immediately.

Use `INFO` for:

- display subsystem fitted/not-fitted state at startup;
- successful display backend initialization, including backend, dimensions,
  rotation, fixed SPI wiring, and SPI clock;
- first transition from logo to artwork and first transition back to logo;
- dial artwork replacement when the provider artwork URL changes.

Use `WARNING` for:

- the first failure, and every 10th repeated failure, for artwork fetch/decode
  problems per source URL;
- display backend open failure, after which the display degrades to no-op;
- repeated display write failures, rate-limited per failure type;
- invalid screen settings that force no-op display behavior;
- artwork fetch/decode/render failures, rate-limited per source URL.

Use `DEBUG` for:

- unsupported or unauthorized display-source candidates;
- mDNS target ordering and target-selection details;
- full provider artwork URLs during fetch attempts;
- unchanged artwork URL reuse;
- non-selected target status failures;
- intermediate repeated artwork/display failures between warning intervals.

Do not log provider artwork URLs at `INFO` or `WARNING` in full.  At most log a
short hash or host plus path basename.  Do not log dial UUIDs except in
existing debug-level patterns already used elsewhere.

## Comment Policy

Comments should aid future maintenance of the final code, not narrate the
implementation journey.

Allowed comments:

- explain non-obvious invariants, such as why display failure must degrade to
  no-op and never stop volume control;
- document hardware quirks that affect correctness, such as the fixed ST7735S
  wiring profile or display-specific rotation assumptions;
- clarify security or safety constraints around direct provider artwork fetches
  from the dial;
- explain concurrency boundaries where callbacks, worker threads, and shutdown
  interact.

Avoid comments that:

- mention WP numbers, internal planning references, session history, or
  "Claude/Codex changed this";
- restate obvious assignments or control flow;
- describe code that used to exist;
- preserve debugging archaeology that belongs in git history or this plan;
- grow into large narrative blocks.

Prefer short module docstrings that state responsibility and compact comments
near the tricky code they explain.

## API Contract

### Appliance Dial Status API

Extend `POST /api/dial/status` to include a grouped `track_id` object.

Request remains:

```json
{"dial_id": "<20-char dial uuid>"}
```

Success response:

```json
{
  "ok": true,
  "playing": true,
  "master_volume": 59,
  "selected_output_count": 2,
  "track_id": {
    "enabled": true,
    "state": "identified",
    "title": "Song",
    "artist": "Artist",
    "album": "Album",
    "artwork_url": "https://provider.example/artwork/3f8a91c2.jpg",
    "updated_at": 1783170000.0,
    "last_attempt_at": 1783169990.0
  }
}
```

When track ID is disabled:

```json
{
  "ok": true,
  "playing": true,
  "master_volume": 59,
  "selected_output_count": 2,
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

When no artwork URL is available, `artwork_url` is an empty string.  This
includes `waiting_for_audio`, `analysing`, `not_found`, `error`, and identified
results without provider artwork.

Authorization failure remains native HTTP `403` with `{}`.  Application
failure responses keep the existing `POST /api/dial/status` contract:

```json
{"ok": false, "error": "config_error"}
```

```json
{"ok": false, "error": "backend_unavailable"}
```

### Dial Screen Settings API

Autostream-dial already exposes its management HTTP API on port `7842`.  Add
screen settings endpoints there, then surface them through the main appliance
dial-management proxy and Setup -> Dials UI.

Screen settings are owned and persisted by the dial.  The main autostream
appliance must not store a copy of these settings; when a user opens the Dials
page it reads the current values from the dial, and when the user saves changes
it sends the complete settings object to the dial.

`GET /screen/settings` returns the effective dial-owned screen-fitted setting
and runtime status:

```json
{
  "ok": true,
  "screen": {
    "fitted": false
  },
  "runtime": {
    "fitted": false,
    "active": false,
    "backend": "noop",
    "backend_loaded": false,
    "showing": "noop",
    "last_error": "",
    "last_error_at": null
  }
}
```

`POST /screen/settings` accepts the complete normalized screen settings object.
In v1 the complete object contains only `fitted`.  This endpoint does not apply
partial patches.  The Setup -> Dials UI should read the current settings with
`GET /screen/settings`, let the user edit the enabled/fitted toggle, then submit
the complete resulting object.

```json
{
  "current_pin": "1234",
  "screen": {
    "fitted": true
  }
}
```

Successful response:

```json
{
  "ok": true,
  "screen": {
    "fitted": true
  },
  "runtime": {
    "fitted": true,
    "active": false,
    "backend": "noop",
    "backend_loaded": false,
    "showing": "noop",
    "last_error": "",
    "last_error_at": null
  },
  "restart_required": false
}
```

The response `screen` object is the full normalized effective screen settings;
`runtime` is always the full current in-memory display status.  In WP-2, before
the real display manager exists, this status comes from a no-op display status
provider with the same response shape.  `restart_required` is `false`: the dial
applies the fitted toggle live by starting or stopping the current display
provider internally.

PIN behavior follows existing `POST /configure` semantics: if a dial PIN is
set, `POST /screen/settings` requires the current PIN in `current_pin`.
`GET /screen/settings` does not return secrets or provider artwork URLs.
Runtime fields report whether imports/GPIO/SPI/backend open and write calls
succeeded, not whether pixels appeared on glass.  The dial generally cannot
know whether a panel is physically attached or visibly working.

The Setup -> Dials "Has Screen Fitted" toggle maps to `screen.fitted`.

Validation:

- `fitted` is a JSON boolean.  Do not accept `0`, `1`, `"true"`, or `"false"`.
- Unknown fields inside `screen`, missing screen fields, missing or non-object
  `screen`, and invalid field types return HTTP `400` with
  `{"ok": false, "error": "invalid_screen_settings"}`.

Invalid settings return HTTP `400` with `invalid_screen_settings`.  Persistence
failures return HTTP `500`.  A saved config whose runtime application fails
may still return `ok: true` with `runtime.last_error` populated, provided the
failure is non-fatal and the display manager degraded to no-op.

### Main Appliance Dial Screen Proxy

The main autostream appliance exposes screen settings through the existing
authenticated dial-management API and proxies to the dial-owned API:

- `GET /api/dial/screen/settings/<uuid>` proxies to the selected dial's
  `GET /screen/settings`.
- `POST /api/dial/screen/settings` accepts
  `{"uuid": "<dial uuid>", "current_pin": "...", "screen": {"fitted": true}}`
  and proxies `{"current_pin": "...", "screen": {"fitted": true}}` to the
  selected dial's `POST /screen/settings`.

Proxy error handling follows the existing dial-management proxy: target `400`,
`403`, `429`, and `500` responses pass through natively, while target `404`,
`502`, `503`, and `504` are tunneled through HTTP `200` with `error_status`.
The Setup -> Dials UI puts screen controls inside the same locked dial card
area as existing protected dial settings.  If the dial reports `pin_set: true`,
the browser sends `current_pin` using the same unlocked-card PIN flow already
used by `/api/dial/configure`.

## Artwork URL and Dial Fetch Design

The appliance does not fetch, cache, resize, or serve artwork for the dial.
Track ID continues to store provider artwork as an external URL in the existing
snapshot, and `POST /api/dial/status` exposes that URL only to authorized dials.
There is no appliance-side artwork URL namespace, nginx route, or cache-control
contract for dial artwork.

When no provider artwork URL is available, the appliance returns
`track_id.artwork_url: ""`.  The endpoint remains read-only: it must never fetch
remote artwork on the request path.

### Dial Artwork State

Maintain artwork state inside the dial display manager:

```text
source_artwork_url
source_artwork_hash
current_rendered_image
fetched_at
last_fetch_error
```

The dial compares artwork source identity using only the provider artwork URL.
If the URL is unchanged and the previous fetch/render succeeded, reuse the
current rendered image in memory and only update metadata.  If the URL changes,
fetch and render the new artwork.  If the URL is empty or fetch/decode/render
fails, show the logo.

The first implementation keeps only the current rendered image in memory.  It
does not persist artwork across reboot or service restart, does not implement a
file cache, and does not implement provider HTTP cache semantics.

### URL Validation

Keep URL validation local in this feature.  The appliance dial-status response
may reuse the existing Track ID URL sanitization, and the dial display manager
applies its stricter fetch eligibility rules before making a network request.
Do not add a new shared `core/autostream_artwork_urls.py` module in v1, and do
not import the Track ID provider/model package directly from the dial just for
URL validation.

### Fetch and Decode Safety

The dial-side artwork fetcher must be defensive:

- use `urllib.request` from the Python standard library; do not add `requests`
  or another HTTP client dependency in v1;
- fetch only `https://` provider URLs;
- require a DNS hostname, not an IPv4 or IPv6 literal;
- reject `.local` hostnames;
- reject any explicit non-default port; only the implicit/default HTTPS port
  `443` is allowed;
- disable urllib's automatic redirect following and handle redirects explicitly;
  reject redirects unless the redirect target also satisfies the same URL
  eligibility rules; follow at most two redirects within the single fetch
  attempt, and treat a longer chain as a fetch failure;
- do not resolve DNS names to reject private, loopback, link-local, or other
  internal result addresses in v1;
- use one fetch attempt per display poll loop with
  `artwork_fetch_timeout_seconds = 2.0`;
- after fetch/decode completes, re-check the currently selected source before
  rendering: if the selected artwork URL, no-artwork state, or no-playing state
  has changed since the fetch began, discard the fetched result without
  rendering.  Polling, fetch, decode, and render run sequentially on the single
  display thread; no mid-fetch cancellation mechanism is required or expected;
- enforce `MAX_ARTWORK_RESPONSE_BYTES = 2 * 1024 * 1024` before decode by
  reading at most one sentinel byte past the limit and rejecting larger bodies;
- accept only `image/jpeg`, `image/png`, and `image/webp` content types,
  ignoring case and parameters; missing or unsupported content types are
  rejected before decode, with decoder validation still used as the final
  authority;
- decode with Pillow, passing `formats=("JPEG", "PNG", "WEBP")` when opening
  provider artwork;
- handle malformed images without crashing the dial service;
- set `MAX_DECODED_ARTWORK_PIXELS = 16_777_216` and assign it to
  `Image.MAX_IMAGE_PIXELS` once at display-module import.  `MAX_IMAGE_PIXELS`
  is a PIL process-wide global, so this limit also applies to logo decoding;
  that is acceptable and intended on the dial, which is the process's only PIL
  user.  Turn `PIL.Image.DecompressionBombWarning` into an error, and also
  reject any decoded image whose `width * height` exceeds that limit;
- reject decoded images whose estimated expanded RGBA footprint exceeds
  `64 * 1024 * 1024` bytes;
- keep failures non-fatal so volume control continues to work.

Provider artwork URLs may be logged in full at `DEBUG` while fetching.  They
must not be logged at `INFO` or `WARNING` in full; at those levels log at most a
short hash or host plus path basename.

### Image Transform

The dial performs the display transform after fetching the provider artwork URL:

- EXIF orientation corrected if supported by the decoder;
- converted to RGB;
- center-cropped to the panel aspect ratio (4:5, matching 128x160);
- the cropped image resized using a high-quality filter to the fixed 128x160
  panel dimensions;
- rendered for the fixed v1 ST7735S backend.

The first implementation should prefer simplicity and reliable decoding over
perfect visual polish.  A square album cover center-cropped to the 4:5 panel
aspect ratio and resized to 128x160 is acceptable for the fixed v1 display
profile.

The fallback logo uses a different fit policy.  The source asset is 983x575
landscape; center-cropping it to a portrait panel would reduce the wordmark to
an illegible vertical slice.  Instead, scale the logo to fit entirely within
128x160 preserving aspect ratio, then letterbox it by padding to 128x160 with
the autostream dark-mode background colour RGB `(14, 40, 65)` (`#0E2841`).
That colour is the web UI dark-theme `--color-bg` and is identical to the logo
asset's own background, so the padding is seamless.  `image_fit: center_crop`
in the fixed hardware constants applies to artwork only.

## Dial Target Selection

The dial maintains a registry of currently playing appliances from
`_autostream-playing._tcp`.

Suggested model:

```text
service_name -> {
  ip,
  port,
  name,
  playing_since,
  last_seen,
  display_row_key,
  display_authorized,
  dial_api,
  audio_status,
  dial_status
}
```

Behavior:

- When a new service appears, set `playing_since` to the local monotonic time.
  Initialize `display_authorized` to true/unknown so the target gets one status
  attempt.
- When a service changes IP/port but keeps the same service identity, preserve
  `playing_since`.  Reset `display_authorized` to true/unknown if the address or
  port changes, because it may be a different appliance instance.
- The display authorization row key is exactly
  `(service_name, ip, port)`.  `playing_since` is tied to `service_name`, but
  HTTP `403` suppression is tied to this row key so an address or port change
  automatically permits a fresh status attempt.
- When a service disappears or expires from mDNS, remove it.
- When a target returns HTTP `403` from `POST /api/dial/status`, mark
  `display_authorized` false and suppress future display-status polls for that
  row.
  The row is removed when playback stops; if the appliance later announces
  playback again, it is added and checked again from scratch.
- Select display source by sorting active targets by oldest `playing_since`,
  then by stable name/IP/port for deterministic ties.
- Query authorized/unknown targets in that order with `POST /api/dial/status`.
- Use the first target that returns `track_id.state == "identified"` with a
  non-empty provider `artwork_url`, then skip polling all later targets in that
  loop.
- If no target yields usable artwork, display the autostream logo.

The mDNS module should expose small display-selection helpers rather than
requiring the display manager to mutate the shared browser internals directly:

```python
def get_display_targets() -> list[PlayingTarget]: ...
def mark_display_target_unauthorized(target: PlayingTarget) -> None: ...
```

`get_display_targets()` returns a snapshot that includes service identity,
`playing_since`, and current authorization state, sorted by the display
selection order.  `mark_display_target_unauthorized()` marks only the matching
current `(service_name, ip, port)` row unauthorized; if the row has disappeared
or its address/port changed, the call is ignored.

The existing `PlayingTarget` dataclass carries only `ip`, `port`, `name`, and
capability flags; the mDNS service name currently exists only as the registry
key.  WP-5 extends `PlayingTarget` with `service_name`, `playing_since`, and
`display_authorized` fields so these helper signatures are implementable.
Existing `get_playing_targets()` callers and volume fan-out behavior are
unaffected by the added fields.

### Display Polling Policy

Poll only appliances currently visible in `_autostream-playing._tcp`.  Do not
poll stopped appliances, non-playing appliances, or appliances already marked
unauthorized for their current playback row.

Use one global display poll interval:

```text
display_poll_interval_seconds = 6
dial_status_timeout_seconds = 2
```

Each loop:

1. Snapshot the current mDNS playing-target table.
2. Sort rows by oldest `playing_since`, with stable name/IP/port tie-breaks.
3. Skip rows marked unauthorized.
4. Poll each remaining row with `POST /api/dial/status`, using the dial UUID
   and a short timeout, until the first usable artwork source is found.
5. If a poll returns HTTP `403`, mark only that row unauthorized and continue
   to the next row.
6. If a poll succeeds with usable provider artwork, display it and stop polling
   further rows for this loop.
7. If no usable target is found, show the logo.
8. Wait `display_poll_interval_seconds` from the end of the current loop before
   starting the next loop.

Waiting from the end of the loop prevents slow polls from accumulating into a
backlog.  Authorization suppression is intentionally simple and row-scoped:
there is no exponential backoff.  A target is retried only after its playing
mDNS row is removed and later re-added, or after its service address/port
changes.

Volume behavior remains unchanged: volume and mute continue to fan out to all
current playing targets.

### Target Status Boundary

Keep status protocol handling separate from display-source orchestration.

`dial/dial_target_status.py` owns the shared appliance status protocol:

- sending `POST /api/dial/status` with the dial UUID;
- applying HTTP timeout, response-size, content-type, and JSON validation;
- mapping HTTP `403` to `status_error == "unauthorized"`;
- validating the canonical runtime fields and, when present, the grouped
  `track_id` object;
- returning a structured single-target result.

Track ID parsing rules are deliberately small for v1:

- `track_id` may be absent; this is a valid no-artwork response.
- If `track_id` is present, it must be a JSON object.
- Required fields inside a present `track_id` are `enabled` as a JSON boolean,
  `state` as a string, and `artwork_url` as a string.
- Valid `state` values are `disabled`, `waiting_for_audio`, `analysing`,
  `identified`, `not_found`, and `error`.
- `title`, `artist`, and `album` are optional strings; absent values are exposed
  to callers as empty strings.  Non-string values are treated as schema-invalid.
- `updated_at` and `last_attempt_at` are optional numbers or `null`; absent
  values are exposed to callers as `null`.
- Unknown `track_id` fields are ignored.
- Invalid required fields or invalid known optional fields make the whole
  target status response `bad_response`.
- `state != "identified"` or an empty `artwork_url` is valid no-artwork, not
  `bad_response`.

For display artwork selection, a status response with no `track_id` object, no
`track_id.artwork_url` field, an empty `track_id.artwork_url`, or a
non-identified `track_id.state` is a valid no-artwork result.  It must not be
classified as `bad_response`; the display manager treats it as unusable artwork
and continues to show the autostream logo unless another selected target yields
usable artwork.

Extract or expose a single-target helper such as
`fetch_target_status(target, dial_id, timeout_seconds)` for reuse by both the
existing list enrichment path and the display manager.

The existing `enrich_targets()` list function remains a presentation helper for
control/status surfaces.  It may continue to poll concurrently and return
records sorted by display name/IP/port, but it should internally use the shared
single-target helper so schema validation is not duplicated.

The display manager must not call `enrich_targets()` for artwork selection.
That function's concurrent polling and name-sorted output conflict with the
display rules above.  `dial/dial_display.py` owns display policy: snapshot
visible playing rows, sort by oldest `playing_since`, skip unauthorized rows,
poll sequentially with the short display timeout, mark only the current row
unauthorized on `403`, stop after the first usable artwork source, and apply
the logo fallback display behavior.

## Dial Display Runtime

Add a display manager inside the dial service.  It should be isolated from
rotary callbacks and the volume worker.

Responsibilities:

- initialize SPI and ST7735S display hardware when configured;
- render the local fallback logo at startup;
- poll current playing targets for now-playing artwork using the shared
  single-target status helper;
- fetch provider artwork URLs with strict timeouts and size limits;
- decode and resize the fetched artwork for the panel;
- update the display only when the image identity changes;
- keep failures non-fatal so the dial remains a working volume controller.

The display manager should run in its own background thread.  It should never
block GPIO callbacks, HTTP admin handling, the local control socket, or volume
fan-out.

### Config and Runtime Ownership

Persistent screen settings live in the dial config object:

```python
@dataclass
class DialDisplayConfig:
    fitted: bool = False
```

`DialConfig` gains:

```python
display: DialDisplayConfig = field(default_factory=DialDisplayConfig)
```

`load_config()` builds the effective fitted flag from disk.  `save_config()`
persists the mutable fitted flag to `/var/lib/autostream/dial-settings.json`
alongside existing mutable dial settings.  Root-owned hardware/default config
may seed `display.fitted` from `/etc/autostream/autostream-dial.json`, but UI
changes are persisted in the mutable settings file.

The first ST7735S backend uses fixed v1 hardware constants:

```text
backend: adafruit_st7735s
width: 128
height: 160
rotation: 0
spi_bus: 0
chip_select: CE0
spi_clock_hz: 16000000
dc_gpio: 25
reset_gpio: 24
backlight_gpio: 18
image_fit: center_crop
```

These constants are not browser-configurable in v1.  Future hardware variants
can add explicit configuration once there is a concrete remapping design.
`image_fit: center_crop` governs artwork only; the fallback logo is letterboxed
per the Image Transform section.

Runtime state lives only in the display object:

```python
@dataclass
class DisplayRuntimeStatus:
    fitted: bool
    active: bool
    backend: str
    backend_loaded: bool
    showing: str
    last_error: str
    last_error_at: float | None
```

The runtime status API shape is exactly the serialized
`DisplayRuntimeStatus` shape:

- `fitted`: effective screen fitted flag from the dial-owned settings.
- `active`: true when the display manager has an active non-noop display path.
- `backend`: selected backend name.
- `backend_loaded`: true when backend imports and hardware open succeeded.
- `showing`: one of `logo`, `artwork`, or `noop`.
- `last_error`: last non-fatal display/fetch/render error identifier, or an
  empty string.
- `last_error_at`: Unix timestamp for `last_error`, or `null`.

The dial HTTP server owns HTTP handling, PIN checks, validation, and persistence:

```text
POST /screen/settings
  -> validate current_pin when a PIN is set
  -> validate and normalize complete screen settings object
  -> update cfg.display
  -> save_config(cfg)
  -> display.update_config(cfg.display)
  -> return normalized screen settings and display.get_status()
```

The display manager owns only runtime application of the desired config.  It
should expose:

```python
def get_status(self) -> dict: ...
def update_config(self, config: DialDisplayConfig) -> dict: ...
```

`update_config()` applies the fitted flag live by opening or closing the display
backend internally.  It must not write settings files directly.  Both
`get_status()` and `update_config()` return the serialized
`DisplayRuntimeStatus` dict described above; `update_config()` returns the
status as it stands after the config has been applied, so the HTTP layer can
place it directly in the `runtime` field of the response.

Before WP-6 lands, `dial_http_server.py` uses an injectable no-op display status
provider with the same `get_status()` and `update_config(config)` methods.  WP-2
adds that injection point and the default no-op provider so the screen settings
API is complete and testable before display polling, image processing, or
hardware backend work exists.  WP-8 wires the real `DialDisplay` instance into
the same interface.

### Module Layout

Use the existing dial module naming style:

```text
dial/
  dial_display.py
  dial_display_adafruit.py
  dial_display_image.py
```

`dial_display.py` is the public facade used by `dial_main.py`.  It owns
threading, fallback policy, image identity dedupe, error handling, and the
no-op path for display-disabled installs.  It exposes a small interface:

```python
class DialDisplay:
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def get_status(self) -> dict: ...
    def update_config(self, config) -> dict: ...
    def enable(self) -> None: ...
    def disable(self) -> None: ...
    def clear(self) -> None: ...
    def show_logo(self) -> None: ...
    def display(self, image) -> None: ...
```

The hardware-facing backend interface stays narrower:

```python
class DisplayBackend:
    width: int
    height: int

    def open(self) -> None: ...
    def close(self) -> None: ...
    def clear(self) -> None: ...
    def display(self, image) -> None: ...
```

`dial_display_adafruit.py` implements `AdafruitST7735SBackend` using
`adafruit_rgb_display.st7735.ST7735S`.  Imports from `board`, `busio`,
`digitalio`, and `adafruit_rgb_display` happen inside `open()`, only after the
screen is configured as fitted.  This backend owns GPIO18 backlight setup and
state: it turns the backlight on after a successful display open and off during
close/disable.  The display manager does not manipulate the backlight directly.

The first backend maps validated config to the public Adafruit constructor as:

```python
ST7735S(
    spi,
    dc,
    cs,
    rst=reset,
    width=128,
    height=160,
    baudrate=16000000,
    polarity=0,
    phase=0,
    rotation=0,
)
```

V1 uses only Raspberry Pi SPI0:

```text
SCLK=GPIO11, MOSI=GPIO10, MISO=GPIO9, CE0=GPIO8
DC=GPIO25, RESET=GPIO24, BACKLIGHT=GPIO18
```

Raspberry Pi also exposes SPI1 on GPIO21/20/19 with CE0 on GPIO18 and CE1 on
GPIO17, but those pins collide with current/default dial GPIOs (`clk_gpio: 17`
and display `backlight_gpio: 18`).  SPI1, CE1, custom chip select, custom
offsets, BGR/invert, and alternate GPIO mapping are not part of the v1 contract.

Build the SPI object with `busio.SPI(clock=board.GPIO11, MOSI=board.GPIO10,
MISO=board.GPIO9)`.  Build `cs`, `dc`, and `reset` as
`digitalio.DigitalInOut` objects for GPIO8, GPIO25, and GPIO24.  Build the
GPIO18 backlight pin inside the backend's open/close path and control it
separately from the Adafruit constructor.  If a board pin cannot be resolved,
backend open fails non-fatally and the display manager degrades to no-op.

`dial_display_image.py` owns Pillow-only helpers: logo loading, artwork
normalization, center-crop policy, RGB conversion, and fixed-size resize.
If this remains tiny it may be folded into `dial_display.py`, but backend
hardware code must stay separate from image policy.

`dial_main.py` integration should remain small:

```python
display = create_dial_display(cfg, get_display_targets, mark_display_target_unauthorized)
display.start()

try:
    ...
finally:
    display.stop()
```

The display manager consumes the display-selection helpers
(`get_display_targets()` / `mark_display_target_unauthorized()`), not the
volume fan-out `get_playing_targets()`, which remains unchanged for volume/mute.

The display object must tolerate start/open failures by logging and becoming a
no-op display.  Volume control must continue to work.

### Hardware Configuration

Extend `/etc/autostream/autostream-dial.json` with optional display fields.
Possible shape:

```json
{
  "display": {
    "fitted": true
  }
}
```

If screen settings are missing or `fitted` is false, the dial should behave
exactly as it does today.

The fixed backend constants match the supported v1 wiring profile and common
128x160 ST7735S breakout examples.  Module variants that require different
offsets, color order, inversion, chip select, or GPIO mapping are deferred until
there is a concrete need and explicit configuration design.

### Installer and Default Screen Policy

Do not add an installer prompt for display hardware in this implementation.
Fresh installs default to `screen.fitted: false`.  Updates must preserve any
existing dial-owned screen settings.  Missing screen settings are treated
exactly like `fitted: false`.

Users enable or disable the screen later from the main appliance Setup -> Dials
UI, which reads the current fitted flag from the dial and writes changes back to
the dial.  The appliance must not persist a copy of this setting.

The installer may install image/SPI/display dependencies and deploy display
assets, but it must not infer that a screen is fitted.  A fresh install may
omit the screen settings block entirely or write an explicit disabled block,
provided the effective `GET /screen/settings` response is `screen.fitted:
false`.

### Logo Asset Contract

The fallback logo source asset is:

```text
images/autostream-logo-centred-dark.png
```

The dial installer deploys it in WP-6 to:

```text
/opt/autostream/images/autostream-logo-centred-dark.png
```

The runtime display code must use that installed absolute path by default, via
a single constant or config field such as:

```python
DEFAULT_DISPLAY_LOGO_PATH = "/opt/autostream/images/autostream-logo-centred-dark.png"
```

Do not use an nginx URL, relative working-directory path, or web UI asset route
for the display fallback logo.  Tests may inject an alternate logo path, but
production runtime should not depend on the process current working directory.

The logo is rendered scale-to-fit and letterboxed with RGB `(14, 40, 65)`
(`#0E2841`) padding as defined in the Image Transform section; it is never
center-cropped.

If the logo file is missing, unreadable, or fails to decode, display startup
must remain non-fatal.  Record a rate-limited `logo_unavailable` or
`logo_decode_failed` error, clear the display if a backend is active, leave the
screen blank, and keep volume control working.

Backlight behavior:

- V1 uses fixed `backlight_gpio: 18`.
- The Adafruit backend owns backlight GPIO setup and state.
- When the screen is fitted and the backend opens, the backend turns the
  backlight on.
- When the screen is disabled or the backend is closed, the backend turns the
  backlight off.
- If backlight setup fails, log a warning and continue trying to render; display
  failure remains non-fatal.

Idle/fallback behavior:

- When no appliance is visible in `_autostream-playing._tcp`, show the logo.
- When appliances are playing but no usable artwork is available, show the logo.
- When a usable artwork URL is available, show the rendered artwork.
- Rotary volume changes and mute/button events do not affect display state.
- No blank, dim, timeout, or idle-mode behavior is part of v1.

### Dependencies

The dial dependency split is:

- WP-6 image-processing apt/system package:
  - `python3-pil`.
- Existing GPIO apt/system package:
  - `python3-lgpio` (already installed by the dial installer).
- WP-7 physical SPI/display apt/system package:
  - `python3-spidev`.
- WP-7 dial venv package:
  - `adafruit-circuitpython-rgb-display==3.14.6`, plus every transitive pip
    dependency pinned and hash-locked in `dial/requirements.lock`.

The dial venv already uses `--system-site-packages`, so Pillow, spidev, lgpio,
and any other apt-provided Python modules can be visible inside the venv while
Adafruit/Blinka packages come from pip.

Pillow is also a hard test dependency from WP-6 onward: the development/test
environment is WSL (Debian-family), where it is installed with
`sudo apt install python3-pil`, mirroring the dial's apt dependency.  The
image/decode/logo tests must actually run — they must not be silently skipped
when Pillow is missing.  Run the dial test suites under WSL where Pillow and
pytest are available.

WP-6 must install/deploy the Pillow dependency and logo asset because the
display manager owns artwork fetch/decode/resize and fallback logo rendering
before the real ST7735S backend exists.

WP-7 owns physical display enablement:

- add `python3-spidev` to the dial installer package set;
- ensure fresh installs and `--update` runs both gain any new system packages;
- add the `autostream` service user to both `gpio` and `spi` groups, allowing
  missing groups to be non-fatal on platforms where they are absent;
- enable Raspberry Pi SPI0 in the installer with
  `raspi-config nonint do_spi 0` when `raspi-config` is available; if the
  command is unavailable or fails on a non-Pi platform, log a warning and
  continue;
- state that SPI enablement and group membership may require reboot or service
  restart before hardware access works;
- keep display-disabled systems working even if SPI is unavailable.

Because `setup_venv()` prefers `dial/requirements.lock` with
`--require-hashes`, adding the Adafruit package requires regenerating/updating
the lock file with all transitive dependencies and hashes.  Updating only
`dial/requirements.txt` is not sufficient for production installs.

The target Pi-side dependency import check already passed:

```text
imports ok
board SPI: 11 10
ST7735S: <class 'adafruit_rgb_display.st7735.ST7735S'>
```

Installer changes must update:

- `dial/requirements.txt`;
- `dial/requirements.lock`;
- `installer/dial/helpers.sh`;
- user/group setup for GPIO/SPI access;
- Raspberry Pi SPI enablement or explicit documentation of the manual step;
- `autostream_dial_install.sh` image deployment, including
  `images/autostream-logo-centred-dark.png`;
- deployment guard tests.

## Work Packages

### WP-1 - Protocol and Documentation

**Scope:** documentation-only protocol contract for both now-playing status and
dial-owned screen settings APIs.

- Update `docs/dial/DIAL_PROTOCOL.md` with the extended
  `POST /api/dial/status` response.
- Document the `track_id` object and provider `artwork_url` semantics for
  authorized dials.
- Document that this extension is part of the pre-public dial v1 contract.
- Document `GET /screen/settings` and `POST /screen/settings` on the dial HTTP
  API, including PIN behavior, strict `fitted` validation, runtime status, and
  live-apply semantics.
- Document logging expectations for unauthorized/unsupported now-playing
  candidates at the protocol level only if existing dial protocol sections
  already cover similar client behavior.
- Add tests that assert the protocol doc mentions the `track_id` object,
  provider artwork URL behavior, and screen settings endpoints.

**Tests:** extend `tests/test_webui_dial_status.py` or add a focused doc
contract test if that file already owns protocol assertions.

**Commit boundary:** one docs/test commit.  No runtime code changes.

**Status: done** — `docs/dial/DIAL_PROTOCOL.md` extended with the `track_id`
object on `POST /api/dial/status` and the `GET`/`POST /screen/settings`
dial-owned endpoints. Tests added to `tests/test_webui_dial_status.py`
(`TestDialProtocolDoc`). Verification baseline (minus
`tests/test_dial_display.py`, not yet added) passed: 314 passed. No installer
or deployment impact (docs/tests only).

### WP-2 - Dial Display Config Model and Direct API

**Scope:** persistent screen settings, validation, and direct dial HTTP API on
port `7842`.  No display hardware backend is required in this WP.

- Add `DialDisplayConfig` and `display: DialDisplayConfig` to `DialConfig`.
- Load effective screen settings from `/etc/autostream/autostream-dial.json`
  defaults overlaid by `/var/lib/autostream/dial-settings.json` mutable
  settings.
- Default missing screen settings to `fitted: false`; no installer prompt is
  added for screen hardware.
- Persist mutable screen settings through existing `save_config(cfg)`.
- Add validation/normalization helpers for the v1 display field: `fitted`.
- Enforce the exact API validation contract: `fitted` must be a strict JSON
  boolean, the `screen` object must be complete, and unknown fields are rejected.
- Add `GET /screen/settings` to `dial_http_server.py`.
- Add `POST /screen/settings` with existing PIN semantics and complete-settings
  replacement behavior.  It must not accept partial patches.
- Return effective screen settings and runtime status.  Runtime status
  can come from a no-op display status provider until the display manager WP,
  but it must already use the full `DisplayRuntimeStatus` response shape.
- Add an optional display status provider/apply interface to `DialHTTPServer`.
  When the real display manager is not supplied, use the default no-op provider
  so `GET /screen/settings` and successful `POST /screen/settings` still return
  the exact full runtime status shape.
- Ensure invalid settings return HTTP `400` with
  `{"ok": false, "error": "invalid_screen_settings"}`, PIN failures preserve
  existing dial API style, and persistence failures return `500`.
- Ensure direct API responses never expose secrets or provider artwork URLs.

**Documentation:** `docs/dial/DIAL_PROTOCOL.md` updated in WP-1; update
`docs/dial/SETUP.md` only if it already documents direct dial API usage.

**Tests:** extend `tests/test_dial_config.py` and
`tests/test_dial_http_server.py`.  Cover missing screen settings defaulting to
`fitted: false`, optional explicit disabled screen settings, persisted overrides,
complete-settings replacement, validation failures, PIN-required behavior, and
the full runtime status shape.  Include tests for strict boolean validation,
missing `fitted`, missing/non-object `screen`, and unknown display fields.
Assert runtime includes `fitted`,
`active`, `backend`, `backend_loaded`, `showing`, `last_error`, and
`last_error_at`, and does not include provider artwork URLs.

**Commit boundary:** config dataclass/load/save, direct dial display API, and
tests.  No appliance proxy/UI and no display hardware dependency.

**Status: done** — Added `DialDisplayConfig`/`DialConfig.display`,
`validate_screen_settings()`/`InvalidScreenSettings` in `dial/dial_config.py`,
persisted under a `display` key in `dial-settings.json`. Added
`GET`/`POST /screen/settings` to `dial/dial_http_server.py` with a
`NoOpDisplayStatusProvider` default (injectable via `DialHTTPServer(cfg,
display_status_provider=...)`). Tests extended in `tests/test_dial_config.py`
and `tests/test_dial_http_server.py`. Verification baseline passed: 338
passed. No installer/deployment changes in this WP.

### WP-3 - Main Appliance Dial Proxy and Setup UI

**Scope:** surface each dial's screen settings on the main autostream Setup ->
Dials page through the existing dial-management proxy.  The appliance proxy
must not persist screen settings; it always reads current settings from the dial
and forwards save requests back to the dial.

- Add proxied browser API routes for dial screen settings, following existing
  dial proxy error semantics:
  - `GET /api/dial/screen/settings/<uuid>` for a dial UUID;
  - `POST /api/dial/screen/settings` with `uuid`, optional `current_pin`, and
    the complete `screen` settings object.
- Preserve existing dial proxy tunneling/native-status behavior.
- Add a Screen section to each dial card with one control:
  - Has Screen Fitted toggle.
- Keep the Dials page usable when a dial is offline or unreachable.  No
  mixed-version screen-settings UI is required; during this pre-release dial
  phase, once WP-3 lands the UI may assume managed dials implement
  `/screen/settings`.
- On every edit/open of the screen section, read current settings from the dial;
  do not use appliance-stored defaults or any installer-time display answer.
- Put screen controls inside the existing locked area of the dial card.  If the
  dial has a PIN, send `current_pin` using the same unlocked-card PIN flow used
  by current dial settings.

**Documentation:** update `docs/dial/SETUP.md` with the screen toggle behavior
and fallback/offline behavior.

**Tests:** extend `tests/test_webui_dial_proxy.py`,
`tests/test_webui_dial_status.py` only if shared routing assertions live
there, and the relevant Dials page render tests.  Cover successful proxy
GET/POST, offline/unreachable/error tunneling, screen controls in markup, and
no appliance-side persistence of screen settings.  Cover that the UI reads
screen settings back from the dial and does not rely on appliance-side stored
screen defaults.

**Commit boundary:** appliance proxy routes, Dials page UI, docs, and tests.
No display manager or hardware backend changes.

**Status: done** — Added `handle_dial_screen_settings_get/post()` proxy
handlers in `core/autostream_webui_dials.py`, wired
`GET /api/dial/screen/settings/<uuid>` and `POST /api/dial/screen/settings`
into `core/autostream_webui.py`. Added a "Has Screen Fitted" toggle inside the
existing locked settings section of the dial card in
`core/autostream_webui_page_setup.py`, with `dialLoadScreenSettings()` /
`dialSaveScreenSettings()` JS reading from and writing to the dial on
page-load, card-unlock, and toggle-change — no appliance-side persistence.
Tests extended in `tests/test_webui_dial_proxy.py` and
`tests/test_p2_browser_behavior.py`; `docs/dial/SETUP.md` updated. Verification
baseline passed: 343 passed.

### WP-4 - Dial Status API Extension

**Scope:** expose the grouped `track_id` object through the existing
UUID-authorized dial status endpoint.

- Extend `send_dial_status_post_json()` to include the grouped `track_id`
  object.
- Preserve authorization, error handling, and existing volume/playback fields.
- Keep native `403 {}` behavior.
- Extend `tests/test_webui_dial_status.py`.
- Preserve existing Track ID snapshot ownership: `TrackIdentificationSnapshot`
  continues to carry the provider artwork URL used by the public/home UI.
- Ensure `track_id.artwork_url` is empty unless Track ID has a provider
  `http://` or `https://` artwork URL.
- Ensure the endpoint remains read-only and does not perform remote artwork
  fetches on request path.

**Documentation:** update `docs/dial/DIAL_PROTOCOL.md` if WP-1 did not already
land the exact final response shape.

**Tests:** cover authorized success with identified artwork, disabled/no-match
fallback, no-artwork empty URL, provider artwork URL pass-through, and unchanged
existing error responses.

**Commit boundary:** API extension, docs if needed, and tests.

**Status: done** — Added `_dial_track_id_dict()` helper and wired it into
`send_dial_status_post_json()` in `core/autostream_webui_api.py`, sourcing
state from `get_active_track_identification_snapshot()`. `artwork_url` is
scrubbed to `""` unless `state == "identified"` and the URL has an `http(s)`
scheme (defense in depth on top of existing `TrackArtwork` validation). No
network access on the request path. Tests added in
`tests/test_webui_dial_status.py` (`TestTrackIdField`). DIAL_PROTOCOL.md
already carried the final response shape from WP-1. Verification baseline
passed: 352 passed.

### WP-5 - Dial mDNS Registry With `playing_since`

**Scope:** add stable target ordering data to the dial discovery layer.

- Extend the `PlayingTarget` dataclass with `service_name`, `playing_since`,
  and `display_authorized` fields; existing fields and callers are unchanged.
- Extend dial target tracking so each visible playing appliance has a stable
  `playing_since`.
- Preserve `playing_since` across IP/port refreshes for the same service
  identity.
- Track `is_authorized` per visible playing row for display-source polling.
  Initialize new rows to true/unknown and mark them false only after the first
  display status poll returns HTTP `403`.
- Remove entries when mDNS removes or expires them.
- Add deterministic sorting helper for display source selection.
- Add tests in `tests/test_dial_mdns.py` or a new focused test module.
- Preserve the current `get_playing_targets()` volume fan-out behavior, or
  migrate callers/tests in the same commit.

**Documentation:** update `docs/dial/SETUP.md` only if the local control/status
output surfaces `playing_since`.  Otherwise no user-facing docs.

**Tests:** cover first add, repeated resolve, IP/port change, authorization
state reset on address/port change, unauthorized marking, removal, expiry, and
deterministic sort ties.  Existing dial volume and control socket tests must
remain green.

**Commit boundary:** mDNS model/order helper plus tests.  No display backend
and no API changes.

**Status: done** — Extended `PlayingTarget` with `service_name`,
`playing_since`, `display_authorized` in `dial/dial_mdns.py`, backed by a
module-level `_target_state` registry keyed by service name (guarded by
`_state_lock`). Added `get_display_targets()` (sorted by oldest
`playing_since`, then name/ip/port) and `mark_display_target_unauthorized()`
(row-scoped to `(service_name, ip, port)`, ignored after address/port change
or removal). `get_playing_targets()`/volume fan-out unchanged. Tests added in
`tests/test_dial_mdns.py` (`TestPlayingSinceRegistry`); `tests/conftest.py`'s
`_reset_dial_mdns` fixture extended to clear the new registry between tests.
Verification baseline passed: 514 passed. No API or installer changes.

### WP-6 - Dial Display Manager

**Scope:** display policy and no-op/test backend only; no real ST7735S hardware
backend yet.

- Add `dial/dial_display.py` with a disabled/no-op implementation when screen
  settings are absent or `fitted` is false.
- Add a small backend protocol/interface and no-op backend.
- In WP-6, `fitted: true` opens the no-op/test backend, not the ST7735S backend.
  The runtime backend name remains `noop`, no Adafruit modules are imported, and
  SPI/GPIO hardware is not touched.  The fake backend exists only so the logo,
  artwork, selection, and status behavior can be tested before WP-7.
- WP-6 runtime status values with `fitted: true` are exactly: `backend` is
  `"noop"`, `backend_loaded` is `true` once the no-op backend has opened,
  `active` is `false` (it means an open non-noop display path and stays false
  until WP-7), and `showing` reports the policy state `logo` or `artwork` being
  rendered through the fake backend.  The WP-2 placeholder provider's
  `showing: "noop"` applies only until WP-6 replaces it.  WP-6 status tests
  assert these exact values.
- Consume `DialDisplayConfig` from `cfg.display`.
- Expose `get_status()` and `update_config(config)` for the dial HTTP server.
- Keep runtime state in the display manager only, matching
  `DisplayRuntimeStatus`: fitted, active, backend, backend-loaded state,
  current presentation, last error, and last-error timestamp.
- Do not write config files from the display manager; the HTTP/config layer
  owns persistence.
- Add WP-6 installer support for image processing:
  - install `python3-pil` through `installer/dial/helpers.sh`;
  - ensure both fresh install and `--update` paths gain the package;
  - deploy `images/autostream-logo-centred-dark.png` to
    `/opt/autostream/images/`.
- Add a single runtime logo path constant/default for
  `/opt/autostream/images/autostream-logo-centred-dark.png`, with test
  injection support for alternate paths.
- Do not add or depend on any appliance-side artwork cache, nginx route, or
  `/dial-artwork/...` URL.
- Keep artwork URL validation local to the dial display manager and status
  serialization.  Do not add a shared `core/autostream_artwork_urls.py` module
  in v1.
- Add direct provider artwork fetching only for eligible `https://` provider
  URLs: DNS hostname, no IP literal, not `.local`, and no explicit non-default
  port.  Do not perform DNS-resolution-based private/internal address blocking
  in v1.  Use `urllib.request` from the Python standard library and explicit
  redirect revalidation; do not add `requests`.
- Enforce artwork fetch/decode safety: one fetch attempt per display poll loop
  with a `2.0` second timeout, redirect targets revalidated against the same URL
  rules, `MAX_ARTWORK_RESPONSE_BYTES = 2 * 1024 * 1024`,
  `image/jpeg`/`image/png`/`image/webp` content-type checks, Pillow
  `formats=("JPEG", "PNG", "WEBP")` decoder validation,
  `MAX_DECODED_ARTWORK_PIXELS = 16_777_216`, a `64 * 1024 * 1024` byte
  expanded-image footprint limit, and rate-limited failures.
- Add fallback logo rendering.
- Keep missing/unreadable/invalid logo files non-fatal: record a display error,
  clear an active backend if possible, leave the screen blank, and preserve
  volume control.
- Add final artwork transform on the dial: EXIF orientation when available,
  RGB conversion, center-crop to the panel aspect ratio, resize to the fixed
  128x160 panel dimensions, and backend-specific rendering.  Render the logo
  scale-to-fit with `#0E2841` letterbox padding per the Image Transform
  section.
- Keep only the current rendered image in memory and redraw only when needed.
- Keep all display failures non-fatal; failed startup degrades to no-op.
- Implement target selection using the `playing_since` ordering from WP-5.
- Extract or expose a reusable single-target status helper from
  `dial/dial_target_status.py`, extend it to validate and return `track_id`,
  and keep `enrich_targets()` as the concurrent/name-sorted presentation path.
- Use that single-target helper from the display manager; do not call
  `enrich_targets()` for display artwork selection.
- Implement the fixed display polling policy: poll visible playing targets only,
  skip unauthorized rows, use a 2 second status timeout, wait 6 seconds from the
  end of each completed poll loop, and stop polling later targets after the
  first usable artwork source is found.
- Implement simple display fallback behavior: show artwork when usable artwork
  is available, otherwise show the logo.  Rotary or mute/button events do not
  affect display state.
- Implement rate-limited logging for target/artwork/display failures.
- Ensure `enable()`, `disable()`, `clear()`, `show_logo()`, and `display()`
  are thread-safe.
- Implement live config updates for the `fitted` flag.
- Unit-test selection/fallback behavior with fake targets and fake display
  backend.

**Documentation:** update this plan's completion note when implemented.  If a
developer-facing dial display doc exists by then, document the public
`DialDisplay` facade there.

**Tests:** add `tests/test_dial_display.py`.  Cover disabled config, no
targets, unauthorized target suppression, unsupported target, missing `track_id`
treated as no artwork, omitted artwork URL treated as no artwork, provider URL
fetch, rejection of unsupported URL schemes, IP-literal hosts,
`.local` hosts, explicit non-default ports, and unsafe redirects, oversized
response, decode failure fallback, oldest-playing target stickiness, display
polling uses the single-target status helper rather than `enrich_targets()`,
later-target skip after first usable artwork, loop delay measured from loop end,
image dedupe, logo fallback when no targets are visible, logo fallback while
playing with no artwork, backend failure degradation, and shutdown.  Extend
`tests/test_dial_target_status.py` for `track_id` validation and for
`enrich_targets()` reusing the same single-target status parsing semantics.
Add focused tests for local artwork URL validation, Pillow/logo deployment,
`python3-pil` installer coverage on fresh install and `--update`, runtime logo
path usage, missing/unreadable/invalid logo blank fallback, and the absence of
any appliance-side `/dial-artwork/...` route or nginx dependency.  Cover the
single-attempt fetch timeout and fallback to logo after fetch failure.

**Commit boundary:** display manager/no-op backend/image helpers, Pillow/logo
installer support, and tests.
No Adafruit import dependency in this WP.

**Status: done** — Added `dial/dial_display.py` (`DialDisplay` facade,
`DisplayBackend`/`NoOpBackend`, rate-limited logging, artwork URL
eligibility + fetch with explicit redirect revalidation, target
selection/polling using `get_display_targets()`/`fetch_target_status()`,
`create_dial_display()` factory) and `dial/dial_display_image.py` (Pillow
decode/transform/logo helpers, `Image.MAX_IMAGE_PIXELS`/
`DecompressionBombWarning` wiring). Extracted `fetch_target_status()` in
`dial/dial_target_status.py` as the shared single-target status helper with
`track_id` validation, reused by both `enrich_targets()` and the display
manager. Installer: added `install_image_packages()` (`python3-pil`) called
unconditionally on fresh install and `--update`, and deployed
`images/autostream-logo-centred-dark.png` to `/opt/autostream/images/`.
Tests added in `tests/test_dial_display.py`, `tests/test_dial_display_image.py`,
extended `tests/test_dial_target_status.py` and `tests/test_dial_installer.py`.
Verification baseline passed: 437 passed. Full suite: 5232 passed, 3 failed
(pre-existing `test_p1_wifi_watcher.py` failures unrelated to this feature —
file not touched by any WP-1..6 commit; failures stem from a real permission
error writing to `/var/lib/autostream` in this dev environment).

### WP-7 - ST7735S Hardware Backend

**Scope:** real display hardware backend and installer dependency support.

- Add `dial/dial_display_adafruit.py` with the real ST7735S SPI backend behind
  the display manager interface.
- Use `adafruit_rgb_display.st7735.ST7735S` and lazy imports inside backend
  open/start logic.
- Consume the already-validated `DialDisplayConfig` fitted flag and fixed v1
  hardware constants.
- Implement backend open/close when `fitted` changes.
- Implement simple fixed backlight control on GPIO18: on when the backend is
  open, off when disabled/closed.  If setup fails, log a warning and continue
  non-fatally.
- Update installer dependencies and SPI setup:
  - apt: `python3-spidev`;
  - venv: `adafruit-circuitpython-rgb-display==3.14.6` plus hash-locked
    transitive dependencies in `dial/requirements.lock`;
  - keep `python3-lgpio` and existing `gpiozero` usage;
  - add `autostream` to `gpio` and `spi` groups, tolerating a missing `spi`
    group only when the platform does not provide one;
  - enable Raspberry Pi SPI0 in the installer with
    `raspi-config nonint do_spi 0` when available, warning but continuing when
    unavailable or unsuccessful on non-Pi platforms;
  - document that SPI enablement and group membership may require reboot or
    service restart before hardware access works.
- Add syntax/import tests where hardware cannot be exercised, ensuring the
  Adafruit backend is not imported when `screen.fitted` is false.
- Preserve current dial startup when the Adafruit package is absent and
  `screen.fitted` is false.
- Do not import `board`, `busio`, `digitalio`, or `adafruit_rgb_display` at
  module import time.

**Documentation:** update `docs/dial/BUILD-GUIDE.md` or `docs/dial/SETUP.md`
with display wiring, SPI enablement, dependency notes, and display
fitted-toggle behavior.  Update `docs/dial/DIAL_PROTOCOL.md` only if API
behavior changes.

**Tests:** extend installer tests for `python3-spidev`, `gpio`/`spi` group
handling, SPI enablement or documented manual enablement, venv requirements and
lock-file entries, and `screen.fitted: false` lazy import behavior.  Add a
backend unit test with mocked Adafruit modules rather than requiring hardware.

**Commit boundary:** backend, config parsing, installer/requirements changes,
docs, and tests.

**Status: done** — Added `dial/dial_display_adafruit.py`
(`AdafruitST7735SBackend`) with hardware imports (`board`, `busio`,
`digitalio`, `adafruit_rgb_display`, `gpiozero`) lazy inside `open()` only;
`create_dial_display()` in `dial/dial_display.py` now always uses this
backend factory (fitted still gates whether `open()` is ever called).
Installer: added `install_display_hardware_packages()` (`python3-spidev`),
`add_spi_group()`, and `enable_spi0()` (via `raspi-config nonint do_spi 0`,
warning non-fatally when unavailable), all called unconditionally on fresh
install and `--update`. Regenerated `dial/requirements.lock` via
`pip-compile --generate-hashes` after adding
`adafruit-circuitpython-rgb-display==3.14.6` to `requirements.txt`, pinning
the full Blinka/Adafruit transitive chain. Documented display wiring, the
GPIO24 conflict with the optional status LED, and SPI enablement in
`docs/dial/BUILD-GUIDE.md`. Tests added in `tests/test_dial_display_adafruit.py`
(mocked hardware modules via `sys.modules` injection) and extended
`tests/test_dial_installer.py`. Verification baseline passed: 477 passed.

### WP-8 - End-to-End Dial Behavior

**Scope:** wire display manager into the dial service lifecycle.

- Wire the display manager into `dial_main.py`.
- Start it after config load and mDNS browser startup.
- Stop it cleanly on service shutdown.
- Pass the display manager/status provider into `DialHTTPServer` so
  `GET/POST /screen/settings` returns live runtime state and applies saved
  changes to the running manager.
- Verify existing volume, mute, HTTP admin, local control socket, and mDNS tests
  still pass.
- Add high-level tests for no targets, unauthorized target, no artwork, and
  oldest `playing_since` artwork selection.
- Add high-level tests for `POST /screen/settings` saving a change and applying
  it to the running display manager.
- Ensure display thread startup/shutdown does not leave background sessions
  running in tests.
- Ensure SIGTERM/SIGINT shutdown still stops mDNS browsing, control socket,
  HTTP server, display manager, and volume-visible state cleanly.

**Documentation:** update `docs/dial/SETUP.md` with the complete display
behavior: logo fallback states, artwork source ordering, and troubleshooting.

**Tests:** extend `tests/test_dial_main.py` and `tests/test_dial_control_socket.py`
only if the local control/status output changes.  Run the full dial-focused
suite plus the verification baseline.

**Commit boundary:** service wiring, final docs, and high-level tests.

**Status: done** — `dial/dial_main.py` now builds the display manager via
`create_dial_display(cfg, get_display_targets, mark_display_target_unauthorized)`,
passes it into `DialHTTPServer(cfg, display_status_provider=display)`, starts
it after `start_playing_browser()`, and stops it in the shutdown `finally`
block alongside the mDNS browser, control socket, and HTTP server. Hardened
`DialDisplay.start()`/`stop()` to never raise (thread creation/join failures
are logged and swallowed) so a display fault can never skip the rest of
startup/shutdown or affect volume control. Added high-level tests in
`tests/test_dial_main.py`: `TestEndToEndDisplaySelection` (real
`dial_mdns` + `dial_display` wiring, only the network call mocked — no
targets, unauthorized status marking, no-artwork logo fallback, oldest
`playing_since` selection) and `TestScreenSettingsLiveApply` (`POST
/screen/settings` against a real `DialHTTPServer` + real `DialDisplay`
instance, confirming the live config change is reflected by the same running
manager). Updated `docs/dial/SETUP.md` with display fallback states, artwork
source ordering across multiple appliances, and troubleshooting. Verification
baseline (all dial-focused suites) passed: 542 passed.

## Verification Baseline

Automated verification should include (`tests/test_dial_display.py` exists
from WP-6 onward; omit it when running the baseline for earlier WPs):

```text
python -m pytest tests/test_dial_config.py tests/test_dial_http_server.py tests/test_webui_dial_proxy.py tests/test_webui_dial_status.py tests/test_dial_mdns.py tests/test_dial_target_status.py tests/test_dial_display.py tests/test_dial_main.py tests/test_dial_installer.py -q -p no:cacheprovider
```

Before declaring the feature complete, run the full suite:

```text
python -m pytest -q -p no:cacheprovider
```

No physical display or Pi hardware verification is required for completion.
The implementation must be testable through automated unit tests, mocked
Adafruit modules, installer/config assertions, and syntax/import checks.

## Open Questions

- Whether the Setup -> Dials page should eventually include a software preview
  action that renders the selected logo/artwork through the same Pillow path
  without requiring physical display verification.

## Non-Goals

- No appliance-to-dial callback subscription API in the first implementation.
- No multi-artwork collage or rotation across multiple playing appliances.
- No change to volume fan-out semantics.
