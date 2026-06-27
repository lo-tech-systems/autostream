# Federation / Appliance-Discovery Defects & Remediation Plan

Status: Fixed for WP1, WP2, WP3, WP4, and WP6. WP5 deferred; existing auth behaviour unchanged.

This document records a confirmed cross-appliance switcher defect, its root
cause, and a complete remediation plan broken into independently-committable
work packages. It is written to be implementable by an agent (Claude/Codex)
without further discovery; file and function references are given throughout.

---

## 1. Symptom

After an autostream appliance fails over from wired Ethernet to USB Wi‑Fi
(observed on a Pi 2b with no on-board radio), other appliances can no longer
reach it through the home-page appliance switcher. The controlling appliance's
access log shows a repeating pattern of HTTP **429** on
`GET /api/appliances/<id>/home`, interspersed with occasional 200s:

```
"GET /api/appliances/033bff325f27e9fda222/home HTTP/1.0" 429 -
"GET /api/appliances/033bff325f27e9fda222/home HTTP/1.0" 200 -
"GET /api/appliances/033bff325f27e9fda222/home HTTP/1.0" 429 -
```

It "works generally" and only breaks after the eth→Wi‑Fi failover sequence.

## 2. Confirmed root cause

Debug logging on the controlling appliance captured the decisive evidence:

```
gateway: acquiring token for 033bff… at 10.240.1.82:80
gateway: socket timeout POST /api/federation/v1/session 10.240.1.82:80
gateway: token acquisition transport failure … remote_timeout
gateway: backoff set for 033bff…//api/federation/v1/home: 15s (step 4)
```

- The target appliance moved from its eth0 DHCP lease `10.240.1.82` to its
  Wi‑Fi address `10.240.1.131` (same /24, same L2 — verified). The cable was
  pulled, so no graceful mDNS withdrawal was sent for the eth0 record.
- A **fresh** `avahi-browse -rt _autostream._tcp` on the controller shows only
  the live `10.240.1.131` (+ IPv6). **Avahi is correct.**
- The dead `.82` survives **inside autostream's own in-process discovery
  registry** — `MdnsBrowser` in [core/autostream_mdns.py](../../../core/autostream_mdns.py).
  `avahi-browse -r` is event-driven and never re-emits resolve events for
  still-present records, so a registry entry persists until a matching `-`
  removal arrives or the subprocess restarts. The eth0 removal was missed, so
  `_by_identity[033bff…]` stayed pinned to `.82`.
- The gateway dials `sighting.ip` directly
  ([core/autostream_appliance_gateway.py](../../../core/autostream_appliance_gateway.py),
  `_remote_federation_request`, ~L314). Every federation request (including
  token acquisition) to `.82` times out, which arms per-endpoint exponential
  backoff keyed by `(appliance_id, fed_path)`
  (`_record_failure_locked`, `_BACKOFF_STEPS = (1,2,4,8,15)`). Backoff clears
  **only on a real 200** (`_coalesced_remote_get`, ~L534). The intermittent
  200s are stale-cache responses served during backoff (`_stale_response`,
  ~L478-479), so the condition never self-heals until the process restarts.

### Two coupled defects
1. **Discovery registry retains a dead address.** `MdnsBrowser._by_identity`
   keeps "most-recently-seen sighting", the dedup key excludes the IP, and
   there is no liveness re-confirmation. A single missed removal strands an
   address indefinitely.
2. **Gateway backoff has no address-change reset.** Backoff clears only on a
   200, so a peer that changed IP via failover stays blackholed even after the
   correct address becomes known.

Trigger: the Wi‑Fi watcher's eth→Wi‑Fi failover
([platform/wifi_watcher](../../../platform/wifi_watcher)) transiently dual-homes
the appliance, creating a duplicate/stale sighting that outlives the interface
it described. (The separately-tracked owntone-mini speaker-list collapse seen
in the same incident is a different bug, owned by the owntone-mini project.)

## 3. Remediation model (agreed design)

### 3.1 Single-timer TTL cache for discovery
Per address record store `{ ip, port, hostname, last_seen }`; `stale` is
**derived, not stored**.

- **Confirm** (live `=` event OR presence in a periodic dump): `last_seen = now`.
- **Stale** = "not seen in the most recent refresh cycle"
  (`last_seen < current_cycle_start`); flips on the first missed dump.
- **Remove** when **either** an explicit `-` removal arrives (immediate) **or**
  `now − last_seen > grace`.
- **Select** (per identity): return a non-stale record if any exists; if the
  only record is stale, still return it (the gateway transport path catches a
  truly-dead one); never return an expired/removed record.

This is loss-tolerant: a single missed dump on a lossy link flags a record
stale but **retains** it; the next good dump un-stales it. A dead address stops
being **selected** within one refresh cycle (~15–20 s) even though full removal
waits for the grace period. The grace period therefore governs only when a
record finally drops off the list, not failover speed.

**Mechanics:** keep the existing long-lived `avahi-browse -r` stream (low-latency
add + immediate explicit removal) AND add a periodic one-shot
`avahi-browse --no-fail -rtp <type>` dump (the `-t` terminates after the cache
is dumped) on an internal interval `R` (≈ 15–20 s) that refreshes `last_seen`.
`R` is a code constant, not user-facing. Choose `R` so `R < ` minimum grace
(60 s) comfortably.

### 3.2 Grace value: autostream-owned, core-injected
Relocate the "mDNS Grace Period" from an OwnTone-only backend setting to an
**autostream-owned general setting** (range unchanged: 1–15 min, default 2).
`autostream_core`/startup **pushes** the value (in seconds) to **both**
consumers — owntone-mini (existing mechanism) and the appliance `MdnsBrowser`
(new `set_grace_period()` setter) — at startup and on change. The browser
**never reads settings itself** (preserves the
[core/autostream_mdns.py](../../../core/autostream_mdns.py) module contract:
"must not know about … configuration files"). Dependency direction:

```
settings change ─▶ core ─▶ owntone-mini   (existing push)
                        └▶ appliance browser  (new: MdnsBrowser.set_grace_period)
```

### 3.3 Conflict redefinition (multi-homing is legitimate)
Today two `(hostname, ip)` identities for one `appliance_id` are treated as a
hard conflict and the peer is hidden
([core/autostream_appliances.py](../../../core/autostream_appliances.py),
`_parse_appliance_event`, ~L93-120; `get_appliance_sighting`, ~L209-214).
Redefine conflict to key on **hostname**: same id + same hostname + multiple
IPs = legitimate multi-homing (one identity, multiple address records); same id
+ **different hostnames** = genuine conflict (flag/hide as today). Otherwise the
transient dual-homed window re-hides the peer.

### 3.4 Gateway address-change backoff reset
When the resolved `sighting.ip` differs from the IP that armed backoff for
`(appliance_id, fed_path)`, clear backoff and retry immediately rather than
serving 429. Makes recovery near-instant once §3.1 updates the address.

### 3.5 Auth interaction (analysis — mostly reassurance)
Federation tokens are short-lived (10 min) and **bound to the requester's
source IP** ([core/autostream_federation.py](../../../core/autostream_federation.py),
`create_session`/`validate_session`, ~L30-67). The gateway caches tokens keyed
by **target `appliance_id`, never by IP**
([core/autostream_appliance_gateway.py](../../../core/autostream_appliance_gateway.py),
`_token_cache`, ~L250; `evict_gateway_token`, ~L264-267). Consequences:

- **Target changes IP** (this incident): token is bound to the controller's
  (unchanged) source IP and stored by token string, so it stays valid; only the
  address needs updating (§3.1/§3.4). **Auth does not break.**
- **Target restarts** (sessions invalidated on process restart): cached token
  401s → existing retry-once-on-401 re-acquires (`_remote_request`, ~L398-407).
- **Controller changes its own IP**: its requests arrive from a new source IP →
  401 → retry-once re-auth bound to the new IP.

Watch-items (not blockers): a controller that oscillates source IPs could
re-auth repeatedly and trip the per-source issuance rate limit (`_rate`,
`create_session`, ~L39-46) → `rate_limited`/429. Existing session and gateway
token eviction hooks are unchanged by this remediation; the 10-minute token
expiry remains the backstop.

---

## 4. Work packages

Each WP is independently committable. Recommended order WP1 → WP6. WP1 alone
would have recovered the incident once the address updates; WP1+WP2 fully close
the defect.

### WP1 — Gateway address-change backoff reset
Status: Fixed.

**Goal:** A change in a peer's resolved IP clears stale backoff immediately.

**Files:** [core/autostream_appliance_gateway.py](../../../core/autostream_appliance_gateway.py)

**Changes:**
- Record, alongside each `_backoff_state` entry (or in a parallel map keyed by
  `(appliance_id, fed_path)`), the `sighting.ip` that was current when the
  failure was recorded.
- In `_check_backoff_locked` callers (`_coalesced_remote_get` ~L476-480 and
  `_check_and_emit_backoff` ~L572-582), before honouring backoff, compare the
  *current* `sighting.ip` with the recorded IP. If different, clear the backoff
  entry (`_record_success_locked`) and proceed with a live attempt.
- Keep behaviour identical when the IP is unchanged.

**Tests:** [tests/test_appliance_gateway.py](../../../tests/test_appliance_gateway.py),
[tests/test_appliance_failure_recovery.py](../../../tests/test_appliance_failure_recovery.py),
[tests/test_remote_home.py](../../../tests/test_remote_home.py).
Add: arm backoff against IP A; resolve now returns IP B; assert backoff cleared
and a real request attempted (not 429). Assert no reset when IP is unchanged.

**Acceptance:** With a peer whose sighting flips A→B, the next poll attempts B
and does not return 429 solely because of A-era backoff.

---

### WP2 — `MdnsBrowser` single-timer TTL cache + periodic re-confirmation
Status: Fixed.

**Goal:** The in-process registry converges to Avahi ground truth even when a
removal event is missed, and tolerates lossy-link missed announcements.

**Files:** [core/autostream_mdns.py](../../../core/autostream_mdns.py)
(primary); minor selection touch in
[core/autostream_appliances.py](../../../core/autostream_appliances.py) only if the
selection rule cannot live entirely in the browser.

**Changes:**
- Extend per-five-tuple state to carry `last_seen` (monotonic). `stale` is
  derived (`last_seen < current_cycle_start`), not stored.
- Add a periodic one-shot dump task: run
  `avahi-browse --no-fail -rtp <service_type>` every `R` seconds (new module
  constant, ≈ 15–20 s), parse the same `=` lines as the stream, and refresh
  `last_seen` for present records. Define `current_cycle_start` at the start of
  each dump.
- Keep the existing streaming browse (`_browse_loop`, ~L261-345). Live `=`
  refreshes `last_seen`; live `-` removes immediately (per §3.1).
- Add a sweep (can run at the end of each dump cycle): remove any record with
  `now − last_seen > grace`; when an identity loses its **last** record, fire
  `on_remove` (final removal only — never on stale).
- Update identity promotion (`_by_identity`) selection rule: prefer a non-stale
  record; if all candidates for an identity are stale, keep/serve the
  most-recently-seen one (do not drop it until expiry). Tie-break by most recent
  `last_seen`, then deterministically (e.g. lowest IP).
- Add `set_grace_period(seconds: int)` — thread-safe setter under `_lock`;
  default to a module constant equal to the 2-minute default until WP3 injects
  the configured value. Do **not** read settings here.
- Preserve existing concurrency contract: registry mutations under `_lock`;
  callbacks invoked outside the lock; `_clear_registry` on subprocess restart
  still valid.

**Edge cases to handle:** the dump subprocess must honour the existing shutdown
path (`_shutdown_requested`, `_proc_lock`, terminate/wait) so stop() stays
clean. A live `=` arriving mid-dump must not be lost (both update `last_seen`).

**Tests:** [tests/test_mdns.py](../../../tests/test_mdns.py),
[tests/test_appliance_discovery.py](../../../tests/test_appliance_discovery.py).
Add:
- Missed-removal convergence: feed `=eth0/.82` and `=wlan0/.131`; run a dump
  that contains only `.131` (no `-` for eth0); assert `.82` becomes stale, then
  removed after grace, and `.131` is selected throughout.
- Loss tolerance: a single dump omits a live record → not removed, still served;
  next dump un-stales it.
- Multi-home selection prefers the non-stale address.
- `set_grace_period` changes expiry behaviour.

**Acceptance:** Reproduce the incident in test form — a stale dead address is no
longer selected within one dump cycle and is removed after grace, with no
process restart.

---

### WP3 — Relocate grace setting to autostream config + core injection
Status: Fixed.

**Goal:** autostream config is the source of truth; core pushes the value to
owntone-mini and the appliance browser at startup and on change.

**Files:**
- [core/autostream_config.py](../../../core/autostream_config.py) — add the field
  to the schema/defaults (seconds; default 120) parsed into `AutostreamConfig`.
- [core/autostream_players.py](../../../core/autostream_players.py) — keep the
  existing `SETTING_DEVICE_REMOVAL_GRACE_PERIOD*` constants (min 1, max 15,
  default 2 minutes) as the shared range/UI contract.
- [core/autostream_webui_api.py](../../../core/autostream_webui_api.py) —
  `send_owntone_grace_period_json` (~L1886) now writes the value to autostream
  config (via the settings store `update()`), then fans out: push to owntone-mini
  (existing `_send_owntone_native_setting_json`, ~L1805) **and** push to the
  appliance browser (`set_grace_period`). Clamp as today.
- Startup wiring — wherever the scanner is started
  ([core/autostream_webui.py](../../../core/autostream_webui.py), ~L1083-1089,
  `start_appliance_scanner`): read the configured grace from the settings store
  and call `set_grace_period`, and ensure owntone-mini receives it at startup
  (today it is only pushed on change). Prefer placing the read-and-fan-out in a
  small helper callable from both startup and the API handler.
- [core/autostream_webui_page_owntone.py](../../../core/autostream_webui_page_owntone.py)
  (~L349-366) — read the value from autostream config instead of the backend
  `get_setting`. The slider control and labels are unchanged; only the source
  moves. (Consider whether the control stays on the OwnTone page or moves to a
  general/network settings page — keep on the OwnTone page unless the UI work is
  in scope.)
- Migration — [tools/autostream_migrate.py](../../../tools/autostream_migrate.py):
  on first run after upgrade, if the autostream config key is absent, seed it
  from owntone-mini's current value if reachable, else the 2-minute default.
  Best-effort; never fatal.

**Tests:** [tests/test_settings_store.py](../../../tests/test_settings_store.py),
[tests/test_wp3_settings_api.py](../../../tests/test_wp3_settings_api.py),
[tests/test_wp7_owntone_autosave.py](../../../tests/test_wp7_owntone_autosave.py),
[tests/test_migration.py](../../../tests/test_migration.py),
[tests/test_wp6_field_writer_migration.py](../../../tests/test_wp6_field_writer_migration.py).
Add: setting persists in autostream config; POST fans out to both consumers;
startup pushes to both; value survives a simulated owntone-mini restart;
migration seeds correctly.

**Acceptance:** Changing the grace period updates autostream config, owntone-mini,
and the live browser; on reboot the browser and owntone-mini both receive the
persisted value; dial mode (no owntone backend) still configures the browser.

---

### WP4 — Conflict redefinition (multi-homing is not a conflict)
Status: Fixed.

**Goal:** A transiently dual-homed peer stays visible/selectable; genuine
identity conflicts are still detected.

**Files:** [core/autostream_appliances.py](../../../core/autostream_appliances.py)
(`_parse_appliance_event` ~L65-133, `_on_appliance_change` ~L142-156,
`_on_appliance_remove` ~L171-192, `get_appliance_sighting` ~L209-214).

**Changes:**
- Key conflict detection on **hostname**, not `(hostname, ip)`. Track per
  `appliance_id` the set of distinct **hostnames**. Conflict (hide peer) only
  when an id presents **more than one hostname**.
- Same id + same hostname + multiple IPs is normal multi-homing: record both
  addresses (this dovetails with WP2's per-address records) and resolve to a
  reachable/non-stale one.
- Ensure `_conflict_ids` cleanup still works as sightings are added/removed.

**Tests:** [tests/test_appliance_identity.py](../../../tests/test_appliance_identity.py),
[tests/test_appliance_discovery.py](../../../tests/test_appliance_discovery.py),
[tests/test_appliance_models.py](../../../tests/test_appliance_models.py).
Add: same id/hostname/two IPs → not conflicted, peer selectable; same id/two
hostnames → conflicted/hidden as before.

**Acceptance:** During a dual-homed window the peer is not hidden; genuine
two-hostname conflicts remain hidden and logged once.

---

### WP5 — Auth resilience: eviction timing + requester-IP-change
Status: Deferred — not implemented (see §3.5; existing auth behaviour unchanged).

WP5 was omitted from implementation. The code keeps the existing auth model
described in §3.5: federation tokens are source-IP-bound, target-IP changes do
not by themselves invalidate auth, and 401 responses trigger the existing
retry-once re-auth path. No eviction-timing changes or additional auth-storm
guards were implemented.

---

### WP6 — Documentation
Status: Fixed.

**Goal:** Reflect the discovery TTL model, the relocated setting, multi-homing,
and the auth behaviour; provide operator remediation guidance.

**Files:**
- [docs/APPLIANCE-FEDERATION.md](../../../docs/APPLIANCE-FEDERATION.md) — discovery
  TTL/last-seen model, multi-homing handling, conflict-by-hostname rule, and the
  source-IP-bound token behaviour across failover.
- [docs/TROUBLESHOOTING.md](../../../docs/TROUBLESHOOTING.md) — "appliance switcher
  times out / 429 after a network change" entry with the diagnostic commands
  (`avahi-browse -rt _autostream._tcp`, comparing the gateway's dialed IP via
  debug logs to the peer's current IP) and the expected self-recovery time.
- OwnTone settings docs / [docs/GETTING-STARTED.md](../../../docs/GETTING-STARTED.md)
  — note that "mDNS Grace Period" is now an autostream-owned setting that also
  drives appliance-discovery expiry (still forwarded to OwnTone).
- This file — flip Status to "In progress"/"Fixed" per WP as work lands; move to
  `docs/working/closed/` when complete (mirrors
  [docs/working/closed/wifi_watcher_defects.md](wifi_watcher_defects.md)).

**Acceptance:** Docs describe the new model and give a reproducible operator
remediation; release-consistency checks (if any reference settings) still pass.

---

## 5. Cross-cutting test impact

- New/extended unit tests: `test_mdns.py` (TTL sweep, loss tolerance, multi-home
  selection, `set_grace_period`), `test_appliance_gateway.py` (address-change
  reset), `test_appliance_identity.py`/`test_appliance_discovery.py` (conflict
  redefinition), `test_settings_store.py`/`test_wp3_settings_api.py`/
  `test_wp7_owntone_autosave.py`/`test_migration.py` (setting relocation), and
  `test_remote_home.py` (end-to-end recovery). WP5 auth scenario tests were not
  implemented because WP5 was deferred.
- Integration: a dual-home→single-home transition test asserting
  `/api/appliances/<id>/home` recovers within one dump cycle + WP1 reset, with
  no process restart.
- Watch for fixtures that assume `MdnsBrowser` resolves to a single IP per
  identity or that grace lives in the owntone backend; update accordingly.
- Release-consistency: [tests/test_p9_release_consistency.py](../../../tests/test_p9_release_consistency.py)
  and any settings/UI snapshot tests if the grace control's data source moves.

## 6. Non-goals / out of scope

- IPv6 federation transport: only IPv4 sightings are tracked and dialed today
  (`_handle_line` filters `parts[2] == "IPv4"`; gateway dials `sighting.ip`).
  Note for the backlog; not addressed here.
- The owntone-mini speaker-list collapse observed in the same incident (fixed by
  restarting owntone-mini) is owned by the owntone-mini project.
- No change to OwnTone's `device_removal_grace_period` semantics — only the
  ownership/source of the value moves.

## 7. Risks

- The periodic one-shot dump adds a lightweight recurring subprocess; bounded by
  `R` and acceptable on Pi-class hardware. Tune `R` vs. staleness.
- The sweep/selection must run under `_lock` against a snapshot and be
  **evict-only on expiry** — never blank the registry, to avoid spurious
  `appliance_offline`.
- Migration must be best-effort and non-fatal when owntone-mini is unreachable.
- Auth re-auth storms on an oscillating controller source IP remain a deferred
  watch-item from WP5; existing retry-once-on-401 behaviour is unchanged.

## 8. Related

- Trigger/background: the Wi‑Fi watcher eth→Wi‑Fi failover,
  [platform/wifi_watcher](../../../platform/wifi_watcher); see the closed
  [docs/working/closed/wifi_watcher_defects.md](wifi_watcher_defects.md).
