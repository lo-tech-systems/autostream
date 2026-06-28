# WiFi Handover & Ethernet-Disconnect — Implementation Plan

**Status:** Ready for implementation — written 2026-06-28, no work packages started

**Scope:** `platform/wifi_watcher` and `core/autostream_wifi_network.py` only. No
changes to mDNS service files, federation, or the Web UI route architecture.

---

## 0. Implementation Directive

This is an implementation plan for a coding agent (Claude Code / Codex). Complete
the work packages in order; each is one focused git commit with its tests.

Prefer the simplest route:

1. Reuse existing helpers and STATE fields; do not add new modules, classes, or
   dependency-injection layers.
2. No new third-party libraries. `ipaddress` (already imported in
   `autostream_wifi_network.py`) covers subnet maths.
3. Do not touch mDNS service types, TXT records, Avahi service files, or
   federation modules — keep the WP9 isolation tests green
   (`tests/test_wp9_mdns_transition.py`).
4. Keep WP1 and WP2 reviewable independently; do not interleave.
5. Treat unrelated worktree changes as user work; do not revert or reformat.

---

## WP1 — Visibility-driven apply/test path with per-target AP management

### Problem
When applying new WiFi credentials, `apply_wifi_async` calls
`leave_setup_mode()` up front ([wifi_watcher:1028]), tearing down the hotspot
before any adapter is tried. On two-radio hardware the user is dropped from the
hotspot the instant they hit Connect and sees a dead "connecting" page. The
saved-network path (`reconnect_saved_network`) already does this correctly with
per-target AP management; the apply path must do the same.

### Change
1. **Extract a shared helper** `attempt_on_targets(targets, attempt_fn) -> bool`
   from the existing loop in `reconnect_saved_network` ([wifi_watcher:2018-2059]).
   For each target:
   - Resolve the hotspot adapter once (`resolve_hotspot_adapter`).
   - If `STATE.setup_mode` and the target *is* the hotspot adapter: `stop_ap_mode()`
     before the attempt; on failure, rebuild it (`setup_mode=True`,
     `ap_enter_time=now`, `start_ap_mode()`, `update_apmode_flag(True)`) and
     continue to the next target.
   - If the target is **not** the hotspot adapter: attempt with the AP left up.
   - On success: `_set_active_client(target)`, `_clear_reconfigure_state()`,
     `leave_setup_mode(...)`, `verify_avahi_after_handover()`, return `True`.
   - Return `False` if all targets fail (AP is left running / rebuilt).
   `attempt_fn(target) -> bool` does the create+activate+validate(+commit) for one
   adapter and returns success.
2. **Rewire both callers onto the helper:**
   - `configure_wifi_with_nmcli` → `attempt_fn = _try_candidate_on_adapter(ssid, pw, ·)`,
     targets from `connection_target_order(...)` (unchanged, already USB-first by
     visibility).
   - `reconnect_saved_network` → `attempt_fn = activate committed profile on ·`
     (its current body), targets from its current resolution logic.
3. **Remove** the unconditional `leave_setup_mode("Applying WiFi configuration")`
   at [wifi_watcher:1028]. The helper now owns AP teardown. On total failure,
   `apply_wifi_async` keeps its existing `enter_setup_mode` + `last_apply_result =
   "failed"` behaviour (AP already up via the helper, so this is a no-op guard).

### Notes / invariants
- All radios scan while the AP is up (existing behaviour, no gating in
  `scan_all_networks`), so the visibility map is complete; no special-casing.
- Success still tears the AP down (expected captive-portal handoff). The win is
  on *failure*: the user stays on the hotspot to retry.
- Single-radio and USB-only (Pi 2) hardware: the sole target *is* the hotspot
  adapter, so the AP is torn down, tested, and rebuilt on failure — unchanged.

### Also in WP1 — multi-USB hotspot selection
Update `resolve_hotspot_adapter(adapters, active_ifname=None)`:
- Built-in present → built-in (unchanged).
- No built-in, one USB → that USB (unchanged).
- **No built-in, ≥2 USB → the USB whose ifname ≠ active client; the first
  (deterministic `usb_candidates` order) if none is active.** Replaces the old
  `return None`.
- No adapter → `None`.

`active_ifname` defaults to `STATE.active_client_ifname` when not passed (pass it
explicitly from callers/tests for determinism). Update the docstring/comment at
[wifi_watcher:436-437].

---

## WP2 — Disconnect WiFi when Ethernet is on the same subnet

### Problem
Today, when usable Ethernet wins, the WiFi client is left associated but unused
([wifi_watcher:2330]). That dual-homes the appliance and announces two mDNS A
records — the churn the re-announce work fought. When both interfaces are on the
same network, the WiFi path adds nothing and should be dropped to a single
deterministic IP.

### Change
0. **Wired-ifname helper** in `wifi_watcher`: the monitor only computes the bools
   `wired_connected`/`wired_ok` ([wifi_watcher:2231-2232]); no single Ethernet
   ifname exists. Add `first_healthy_wired_ifname() -> str | None` (the carrier
   interface from `wired_carrier_ifnames()` that also has a usable IPv4 —
   `wifi_net.interface_has_usable_ipv4`, the same predicate `any_wired_path_healthy`
   already uses), returning the first in deterministic order or `None`. This is the
   `winning_eth` source for the policy below.
1. **New fact helper** in `autostream_wifi_network.py`:
   `same_l3_segment(if_a, if_b) -> bool`. `True` only when **each** interface has
   **exactly one** usable non-link-local IPv4 (valid prefixlen) and **exactly one**
   IPv4 default gateway, the two addresses share the same `ip_network(addr/prefix)`,
   and the two gateways are equal. Any other shape — zero or multiple usable IPv4s,
   missing/invalid prefix, zero or multiple gateways — returns `False` (fail
   closed). Use `list_interface_addresses` and `default_gateway_ipv4` (both exist).
   No MAC/ARP check.
2. **Policy in the monitor loop**, inside the existing `ethernet_wins` branch
   (around [wifi_watcher:2330], after `leave_setup_mode` handling): compute
   `winning_eth = first_healthy_wired_ifname()`; if there is an active WiFi client
   (`STATE.active_client_ifname`), `winning_eth` is not `None`, and
   `same_l3_segment(active_client_ifname, winning_eth)`, **and** playback is idle
   (`query_playing_status()` is `False`), disconnect WiFi:
   `nmcli device disconnect <wlan>`, then `_set_active_client(None)`, log once.
   - **Gate, do not force:** skip while `query_playing_status()` is `True` or
     `None` (uncertain), while `apply_in_progress`, or while `setup_mode`. Defer to
     a later pass — mirror the playback gating in `handle_runtime_usb_adoption`.
   - Different subnet / different gateway → leave WiFi associated (stay
     multi-homed; no change).
3. **Reconnect on Ethernet loss — needs an explicit prompt.** `_set_active_client(None)`
   clears both `active_client_ifname` and `active_client_mac`
   ([wifi_watcher:2726-2728]). With the mac cleared and no active WiFi client,
   `handle_usb_failure_fallback` returns `False`, so the *only* remaining reconnect
   is the generic timer — `connect_to_configured_wifi()` after
   `GW_DOWN_RECONNECT_AFTER` (5 min, [wifi_watcher:144]). A multi-minute silent gap
   on cable-pull is unacceptable for an audio appliance. Close it simply: when this
   pass takes the policy-disconnect, record `STATE.policy_disconnected_wifi = True`;
   on a later pass where `not wired_ok` and that flag is set, call
   `connect_to_configured_wifi()` once and clear the flag (reuse the existing
   reconnect entrypoint — do **not** add new orchestration). Keep it a single guarded
   call, not a new state machine.

### Notes / invariants
- The committed profile is already portable (interface-name restriction cleared),
  so it reconnects on whichever radio is available.
- The active disconnect makes NetworkManager remove the address, so Avahi sends a
  proper goodbye for the withdrawn record — cleaner than the passive path.
- Do **not** add per-interface Avahi config (`allow-interfaces`); rejected as
  unnecessary complexity.

---

## Testing impact

Add to `tests/test_p1_wifi_watcher.py` unless noted.

**WP1**
- `resolve_hotspot_adapter`: built-in preferred; one USB; **≥2 USB → non-active
  USB; first when none active** (flips the old `None` assertion — find and update
  it). Add a no-adapter `None` case.
- `attempt_on_targets`: (a) non-hotspot target → AP **not** stopped, success
  commits + leaves setup; (b) hotspot target fails → AP stopped then **rebuilt**,
  device left in AP; (c) single-radio → stop/test/rebuild-on-fail; (d) total
  failure → `setup_mode` True and `last_apply_result == "failed"`.
- Test the **observable** apply/reconnect behaviour, not that the callers invoke
  `attempt_on_targets` (white-box coupling to the refactor): a non-hotspot target
  failure leaves the AP up; a hotspot target failure rebuilds the AP; success tears
  down/commits as before; an apply failure leaves the retry path reachable
  (still in `setup_mode`).
- `_run_monitor_once` isolation patches: extend if the helper is reachable from
  the monitor path.

**WP2**
- `same_l3_segment` (in `tests/test_autostream_wifi_network.py`): same net + same
  gw → True; same net + different gw → False; different net → False; missing
  IPv4/gw → False; **multiple IPv4s or multiple gateways on either interface →
  False** (ambiguity is fail-closed).
- `first_healthy_wired_ifname`: returns the carrier+usable-IPv4 interface; `None`
  when carrier exists but no usable IPv4, and when no wired carrier at all.
- Monitor policy: same-subnet + idle → WiFi disconnected once, active client
  cleared; playback active/uncertain → not disconnected; different subnet → not
  disconnected; `apply_in_progress`/`setup_mode` → skipped.
- Ethernet-loss after a policy disconnect → `policy_disconnected_wifi` flag drives
  one `connect_to_configured_wifi()` call promptly (not the 5-min timer), then the
  flag clears.

**Both:** keep `tests/test_wp9_mdns_transition.py` green (no service/TXT/federation
changes).

---

## Documentation impact

- `docs/TROUBLESHOOTING.md`: note (a) plugging Ethernet on the same subnet
  disconnects WiFi once playback is idle, single mDNS address afterward; (b) on a
  wrong WiFi key during reconfigure, the hotspot now stays up so the user can
  retry without reconnecting.
- Update the `wifi_watcher` module docstring (network-policy summary near the top)
  to state the same-subnet WiFi-disconnect policy and the multi-USB hotspot rule.
- On completion, move this plan to `docs/working/closed/`.
