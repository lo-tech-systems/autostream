# Wi-Fi Watcher — USB Reset Before Onboard Failover (+ BSSID Scan Debug Logging)

**Status:** Complete. SL-1 and RF-1 through RF-4 all landed on
`refactor/wifi-watcher-structure`, one commit per work package, full suite
green at every step. Baseline entering this stage: 5333 total (5230 passed /
103 skipped, before SL-1).

| WP | Commit | Suite after |
|---|---|---|
| SL-1 BSSID scan debug logging | `35e41fb` | 5235 passed / 103 skipped |
| RF-1 RESET_USB ladder rung (pure) | `e0cedce` | 5247 passed / 103 skipped |
| RF-2 reset-before-failover execution | `e1db617` | 5258 passed / 103 skipped |
| RF-3 dead-PHY ladder reorder | `325f96c` | 5262 passed / 103 skipped |
| RF-4 docs + regression sweep | `b24684c` | 5262 passed / 103 skipped |

RF-4 sweep: confirmed all four `next_recovery_action` consumers handle or
safely ignore `RESET_USB` — `wifi_adoption.apply_client_failed` and the
recovery-hotspot probe path (`wifi_adoption.py`), and
`wifi_loop.step_boot_client_bringup` submit it explicitly through
`_submit_client_activation`; `wifi_loop.step_boot_ap_entry` does not list
`RESET_USB` in its kind check, but by that point in the boot window the
episode reset has already been spent or the target isn't eligible (the
earlier `step_boot_client_bringup` owns the boot-window reset), so it safely
falls through to its existing "no client path" hotspot-entry branch — the
same behaviour as any other unhandled/HOLD kind, not a crash or silent drop.
Grepped docs/ and platform/ for stale rung-order prose narrating the old
"built-in fallback before reset" order: found and fixed one stale sentence in
`docs/WIFI-WATCHER.md`'s Dead-PHY reset ladder paragraph (the code comment in
`wifi_recovery.escalate_dead_adapter_recovery` was already correct from
RF-3). Confirmed `RecoveryState.failover_reset_done` is excluded from
`persist_adapter_fault_state`'s written `data` dict (only
`noip_ledgers`/`reset_ledgers`/`disabled_adapters` persist) — matches the
"not persisted, episode-scoped" comment at its declaration. No test or
production code changes were needed; only `docs/WIFI-WATCHER.md` changed
(committed) and this plan file's Status block (not committed, gitignored).
Suite count unchanged (5262/103) since the change was docs-only.

**Context:** Follow-on to the completed BSSID monitoring stage
(`docs/working/wifi-watcher-bssid-monitoring-improvements.md`, BM-1..BM-5).
Suite baseline entering this stage: 5333 total (5230 passed / 103 skipped on
the dev workstation; the pass/skip split drifts environmentally — every WP
captures its own pre-change split).

## Problem statement

### 1. Failover to onboard is more disruptive than a USB reset

When the active USB Wi-Fi client is condemned (link-down wedge), the current
order of remediation is: fail over to the built-in radio immediately, and
only reset the USB hardware later — or, for the NO-CARRIER wedge class,
**never**:

- Failing over changes the active interface, hence MAC, hence DHCP identity,
  hence (almost always) the appliance IP. Client devices suffer stale
  `<hostname>.local` answers until mDNS TTL expiry despite the watcher's
  avahi re-announce (which only helps clients that hear the multicast). The
  codebase already treats interface switching as expensive — the
  ethernet-wins path defers its Wi-Fi disconnect during playback for exactly
  this reason — but the USB failover path does not honour that principle.
- A successful USB reset resumes on the same MAC/lease/IP: zero client churn.
- Gap: after failover, the dead-PHY ladder only targets the *active* client
  (now the onboard) and the no-IP holdback reset requires accumulated no-IP
  ledger entries. A NO-CARRIER-wedged dongle produces no activation attempts
  and therefore no no-IP entries, so it is never reset — it stays dead until
  a reboot or replug ("Reset attempts: 0" while the adapter sits wedged).

Desired order for a condemned active USB with a separate healthy onboard
available: salvage (NM re-activation, unchanged) → **one budgeted hardware
reset + reactivation attempt on the USB** → onboard failover → quarantine per
the existing thresholds. Resets remain budgeted, ledgered, persisted, and
visible in the status snapshot, so a repeatedly-resetting dongle still
escalates to quarantine and the user can see the reset count.

### 2. BSSID scans are invisible at DEBUG level

Field diagnosis of roam/pin decisions requires knowing what each scan saw.
At DEBUG level the watcher should log every BSSID scan — USB self-scans,
onboard survey scans, and activation pin scans — compactly (one line per
scan).

## Scope

In scope:

1. DEBUG-level logging of every BSSID scan (survey, onboard, pin).
2. A `RESET_USB` rung in the pure recovery ladder for a **link-down
   (wedged), resettable** active/preferred USB, tried before
   `ACTIVATE_ONBOARD`, at most once per offline episode, within the existing
   reset budget/quarantine/disable gates.
3. Worker-side execution of that rung (reset → interface reappear →
   reactivate) as a single activation job.
4. The same reset-before-fallback ordering inside the dead-PHY ladder
   (reset rungs before the built-in fallback rung) so both paths agree.
5. Observability: the reset is INFO-logged with the budget position, and the
   existing snapshot reset counters cover these resets (they use the same
   ledger).
6. Tests for all of the above.

Out of scope — do not implement or "improve" beyond this list:

- Pre-failover resets for the **associated-but-no-IP** class. Ambiguous
  evidence (could be router/DHCP): that class keeps today's paths — the
  in-job implicated-failure retry (`PIN_IMPLICATE_SIGNAL`) and the no-IP
  ledger promotion. Only link-down wedges get the new rung.
- Resets for an **unplugged** adapter (not resettable — no sysfs USB paths),
  an operator-**disabled** or **quarantined** adapter, or when the reset
  budget is exhausted: all of these fail over exactly as today.
- Any change to budget sizes (`USB_MAX_RESETS_PER_WINDOW = 2`,
  `USB_MAX_RESETS_TOTAL = 5`), quarantine thresholds, ledger persistence,
  reboot guards, hotspot policy, or the no-IP holdback reset (it remains the
  idle-spare path).
- Any change to failback (runtime USB adoption) behaviour.
- New web-UI surfaces (the snapshot already exposes reset ledgers).

No backward compatibility is required: state fields, job shapes and test
expectations may change freely within scope; assertions are updated, never
weakened.

## Current code pointers (verified against the branch)

- `platform/wifi_adoption.py` — `handle_usb_failure_fallback` /
  `apply_client_failed` (the overlay consumer: ladder → submit →
  onboard-fallback branch → hotspot), `_submit_client_activation` (builds the
  recovery `ActivationJob`), `bssid_survey_and_roam` (survey scans).
- `platform/wifi_policy.py` — `next_recovery_action` ladder: rung (1)
  usable USB, (1b) HOLD `usb_active_no_ip`, (2) onboard-before-hotspot, (3)
  HOLD `usb_only_defer_reset_ladder`, (4) hotspot. `RecoveryKind` /
  `RecoveryAction` (frozen dataclass: kind, ifname, drop_hotspot, purpose,
  reason). `RecoveryFacts` carries `adapters_by_ifname` of
  `AdapterRecoveryFacts`.
- `platform/wifi_recovery.py` — `AdapterRecoveryFacts` (healthy, link_down,
  managed, quarantined, noip_suppressed, disabled…) built by
  `adapter_recovery_facts`; `build_target_adapter` (resettable_usb);
  `adapter_reset_budget_exhausted`, `record_adapter_reset`,
  `adapter_reset_ledger_snapshot` (feeds the snapshot's reset counters);
  `escalate_dead_adapter_recovery` (rung order today: setup deferral →
  built-in fallback → reset rungs → quarantine/backoff → reboot);
  `wait_for_interface_reappears`; `maybe_reset_noip_held_usb` (idle-spare
  holdback reset — unchanged); `TailSpec` + `dead_phy_recovered_via_*`
  constructors.
- `platform/wifi_activation.py` — `ActivationJob` (kind,
  ifname, drop_hotspot, records_noip, sets_builtin_fallback,
  clears_down_timers, stable_id…), `_run_activation_job` (worker),
  `_retry_after_implicated_failure` (existing in-job reset+retry precedent:
  `record_adapter_reset` → `wifi_net.reset_usb_adapter_rebind` →
  `ctx.RECOVERY_CTX.wait_for_interface_reappears` → re-run core),
  `_pin_usb_bssid` (pin scans), `apply_activation_result` (loop-side tail).
- `platform/wifi_state.py` — `NetworkMonitorState.onboard_activation_failures`
  (the per-episode counter pattern; find its reset-on-healthy site by grep —
  the new episode flag must reset at the same place). `RecoveryState`
  (wifi_recovery) holds `noip_holdback_reset_done` (the per-episode set
  pattern to copy).
- `platform/wifi_watcher.py` — `gather_recovery_facts` (builds
  `RecoveryFacts`; the place to add the new per-adapter facts), phase list in
  `network_monitor_loop`.
- Tests: `tests/test_wifi_policy.py` (pure ladder), `tests/test_wifi_adoption.py`
  (`TestUsbFailureFallback`, `TestAdapterOverlayEvents`, survey tests),
  `tests/test_wifi_recovery_deadphy.py` (dead-PHY rungs),
  `tests/test_wifi_activation.py` (worker jobs, `TestBudgetedResetRetry`
  naming may differ — locate by grep), `tests/test_wifi_status.py`
  (snapshot reset counters).

## Design

### DEBUG scan logging (SL-1)

One compact line per scan, DEBUG level, logged where the scan result lands:

- `wifi_adoption.bssid_survey_and_roam`: after the USB self-scan and after
  the onboard survey scan.
- `wifi_activation._pin_usb_bssid`: after the pin scan.

Format (single line; rows sorted by signal desc, cap at the strongest 8 to
bound volume; include the failure case):

```text
BSSID scan on wlan1 (rescan=True, pin): 3 rows for 'IoT': AA:..:FF 63*, D2:..:65 47, DA:..:F4 30
BSSID scan on wlan0 (rescan=True, survey): scan failed
```

`*` marks the in-use row. Include ifname, rescan flag, purpose
(survey/onboard/pin), row count for the committed SSID, and BSSID/signal
pairs. No new constants; use `logger.debug` via each module's existing
logger/ctx. Log volume at INFO and above is unchanged.

### RESET_USB ladder rung (RF-1)

New facts, threaded through the existing per-adapter facts:

- `AdapterRecoveryFacts` gains `resettable: bool` and `reset_budget_ok:
  bool`, computed in `adapter_recovery_facts` **for USB adapters only**
  (both default False for non-USB — no extra sysfs work for the onboard).
  `resettable` comes from `wifi_net.usb_sysfs_paths(ifname) is not None`.
  For `reset_budget_ok`, refactor the budget check to be keyed by stable
  id: extract the ledger lookup from `adapter_reset_budget_exhausted` into
  a stable-id-taking form (the reset ledgers are already keyed by stable
  id) and have the existing TargetAdapter-taking function delegate to it —
  identical semantics, no TargetAdapter construction per pass.
- `RecoveryFacts` gains `failover_reset_spent: bool` — True when the
  condemned adapter's stable id is in the new per-episode set (below).

New per-episode state: `RecoveryState.failover_reset_done: set` (stable
ids), same pattern as `noip_holdback_reset_done`. Cleared wherever
`STATE.onboard_activation_failures` resets on a healthy pass (grep for that
site and clear both together) and in `client_up_tail` when
`clear_dead_adapter` runs. Not persisted (an episode does not span reboots).

Ladder change in `wifi_policy.next_recovery_action` — insert between rung
(1b) and rung (2):

```
(1c) The preferred/active USB is wedged (link_down is True), resettable,
     budget-ok, not quarantined/suppressed/disabled, NOT currently the
     hotspot adapter (facts.hotspot_ifname != <usb> — never reset a radio
     that is hosting the recovery AP; the single-radio dead-PHY ladder owns
     that case), and the episode reset has not been spent ->
     RecoveryAction(RecoveryKind.RESET_USB, ifname=<usb>,
     reason="usb_wedged_reset_first").
```

`RecoveryKind` gains `RESET_USB`. Pure: the classifier only reads the new
facts. Rungs (2)–(4) unchanged, so once the episode reset is spent (or the
gates fail) the ladder falls through to onboard exactly as today.

### Worker execution (RF-2)

All `next_recovery_action` consumers handle `RESET_USB` **uniformly**, by
teaching `_submit_client_activation` to build the reset job for that kind —
then every consumer that submits through it gets the behaviour for free.
Enumerate the consumers by grep and verify each:

- `apply_client_failed` (the overlay): primary path — submits the reset job.
- `step_boot_client_bringup` (boot window): full parity — a dongle wedged at
  power-on gets its one reset before onboard/hotspot (clients cached the USB
  path's IP from the previous session, so recovering it preserves
  continuity). The boot handler's kind check
  (`ACTIVATE_USB / ACTIVATE_ONBOARD`) extends to include `RESET_USB`.
- The recovery-hotspot probe path: gets the behaviour through the same
  submission helper; the hosting-AP case never arises because rung (1c)
  suppresses RESET_USB when the wedged USB is the hotspot adapter.

Specifics:

- `ActivationJob` gains `reset_before: bool = False` (plus the existing
  `stable_id`). For `RESET_USB` actions the job is
  `kind="activate_committed", ifname=<usb>, reset_before=True,
  records_noip=True, clears_down_timers=True, on_success_leaves_setup=True`
  — i.e. the normal USB recovery job with a reset prefix.
- On submission (not on success), mark the stable id in
  `failover_reset_done` so a failed job cannot loop the rung.
- In `_run_activation_job`, when `reset_before` is set:
  `record_adapter_reset` → `wifi_net.reset_usb_adapter_rebind(ifname)` →
  `wait_for_interface_reappears` (resolve the possibly-renamed ifname) →
  run the normal activation core on the resolved ifname (its pin scan runs
  fresh). If the interface never reappears, the job fails; the ladder's next
  pass falls through to onboard. Reuse the exact reset/reappear sequence
  from `_retry_after_implicated_failure`; factor a small shared helper
  rather than duplicating it.
- INFO log at the reset: adapter, stable id, and budget position from the
  ledger snapshot (e.g. `resetting active USB wlan1 before onboard failover
  (reset 1 of 2 in window)`).
- The in-job implicated-failure retry must NOT stack a second reset on a
  `reset_before` job (one reset per job, ever — extend the existing
  once-per-job guard).

Timing note (accepted): a failed reset adds roughly the interface-reappear
timeout plus one activation attempt (~60–90 s) before the onboard comes up.
The connection is already dead when this runs; the trade buys IP stability
on the success path.

### Dead-PHY ladder reorder (RF-3)

In `escalate_dead_adapter_recovery`, move the built-in fallback rung to
AFTER the USB reset rungs for a **resettable target with reset budget**:
order becomes setup-deferral → reset step (existing `_perform_reset_step`
mechanics, unchanged) → built-in fallback → quarantine/backoff → guarded
reboot. A non-resettable or budget-exhausted or disabled target falls
through to the built-in fallback immediately (today's behaviour). The
escalation-to-reboot gating (`_maybe_request_dead_phy_reboot`, only when
genuinely offline) is unchanged. Between reset attempts
(`RESET_ATTEMPT_INTERVAL`) the ladder must still fall through to the
built-in fallback rather than holding the device offline waiting for the
next reset window — verify against the existing step logic and add a test.

Note the interaction: for an active recorded USB, the overlay
(`step_usb_failure_fallback`, earlier in the phase list) normally fires
before `step_dead_phy_recovery`, so RF-2 is the primary path; RF-3 covers
the cases the overlay does not own (unrecorded adapters, detection reaching
"dead" while the overlay's ladder held, single-radio recovery) and keeps
the two ladders' philosophies consistent.

### Observability (part of RF-2/RF-3)

No new counters: `record_adapter_reset` feeds the existing per-adapter reset
ledger, which `adapter_reset_ledger_snapshot` already surfaces in the status
snapshot (and it persists across restarts). Add a test asserting a
`reset_before` job's reset appears in the snapshot's reset count.

## Testing plan

Pure (`tests/test_wifi_policy.py`):

1. RESET_USB returned for a wedged, resettable, budget-ok, unspent USB with
   onboard available (proves it outranks ACTIVATE_ONBOARD).
2. Falls through to ACTIVATE_ONBOARD when: not resettable; budget spent;
   quarantined/suppressed/disabled; episode reset already spent; link not
   down (no-IP-with-carrier keeps HOLD `usb_active_no_ip`).
3. RESET_USB never returned when wired_ok or unconfigured, and never when
   the wedged USB is the hotspot adapter (`hotspot_ifname == <usb>` —
   single-radio hotspot case stays with the dead-PHY ladder).
3b. Boot window (`tests/test_wifi_loop.py`, step_boot_client_bringup): a
   wedged resettable USB at boot submits the reset job before any onboard
   activation or hotspot entry; with the episode reset spent, boot falls
   through to onboard as today.

Overlay/orchestration (`tests/test_wifi_adoption.py`):

4. ClientFailed on a wedged USB submits a reset_before job and marks the
   episode set; the same episode's next ClientFailed goes to onboard.
5. Episode set clears on a healthy pass (with `onboard_activation_failures`).
6. Unplugged (absent) USB still fails over immediately (no reset job).

Worker (`tests/test_wifi_activation.py`):

7. reset_before job: reset recorded in ledger → rebind called → reappear
   waited → activation core runs on resolved ifname; success applies the
   normal recovery tail.
8. Interface never reappears -> job fails; no second reset from the
   implicated-failure retry on the same job.
9. Snapshot reset counter reflects the reset (may live in
   `tests/test_wifi_status.py`).

Dead-PHY (`tests/test_wifi_recovery_deadphy.py`):

10. Resettable target with budget: reset rung runs before built-in fallback.
11. Non-resettable / budget-exhausted / disabled target: built-in fallback
    first (today's behaviour preserved).
12. Between reset windows the ladder falls through to built-in fallback.

Scan logging (`tests/test_wifi_adoption.py` / `test_wifi_activation.py`):

13. With caplog at DEBUG: survey scan, onboard scan, and pin scan each emit
    one line containing ifname, rescan flag and purpose; scan failure emits
    the failure form; nothing emitted at INFO.

Verification commands:

```
python -m pytest tests/test_wifi_policy.py tests/test_wifi_adoption.py tests/test_wifi_activation.py tests/test_wifi_recovery_deadphy.py -q
python -m pytest tests/ -q          # full gate before every commit
```

Full-suite gate: zero failures; total grows only by the tests added in that
WP.

## Work packages (one commit each, on `refactor/wifi-watcher-structure`)

### SL-1 — BSSID scan debug logging

The three DEBUG scan lines + failure form + tests (item 13).
Commit: `wifi: log every BSSID scan at debug level`

### RF-1 — RESET_USB ladder rung (pure)

Facts plumbing (`AdapterRecoveryFacts.resettable` / `reset_budget_ok`,
`RecoveryFacts.failover_reset_spent`, `RecoveryState.failover_reset_done` +
its two clearing sites), `RecoveryKind.RESET_USB`, ladder rung (1c), pure
tests (items 1–3). The new kind is not yet applied anywhere — apply sites
treat an unexpected kind as today's fall-through; verify none crashes on the
new enum member before committing.
Commit: `wifi: add wedged-USB reset rung to the recovery ladder`

### RF-2 — Reset-before-failover execution

`ActivationJob.reset_before`, worker reset prefix (shared helper with the
implicated-failure retry; one-reset-per-job guard), `apply_client_failed` /
other apply sites handle RESET_USB, episode marking on submission, INFO
budget log, tests (items 4–9).
Commit: `wifi: reset a wedged active USB before failing over to onboard`

### RF-3 — Dead-PHY ladder reorder

Reset rungs before built-in fallback for resettable-with-budget targets;
fall-through between reset windows; tests (items 10–12).
Commit: `wifi: prefer USB reset over builtin fallback in the dead-PHY ladder`

### RF-4 — Docs + regression sweep

Update `docs/WIFI-WATCHER.md` (failure-handling order for a condemned USB:
salvage → one budgeted reset → onboard → quarantine; scan logging note).
Full suite; grep sweep (`RESET_USB` handled at every `next_recovery_action`
consumer; no stale rung-order prose). Update this doc's Status to a
completion record (commits + counts + PENDING hardware checks).
Commit: `wifi: document reset-before-failover recovery order`

## Conventions (every WP)

- Run every command in the foreground (no background tasks, watchers, or
  monitors); full suite `python -m pytest tests/ -q`, timeout 600000ms.
- Code comments state behaviour and constraints only — no plan/WP/history
  references.
- Locking: match existing lock placement for every touched site; the new
  episode set follows `noip_holdback_reset_done`'s locking exactly.
- Never weaken a test assertion.

## Hardware validation checklist (PENDING — no Pi on the dev workstation)

Run with the accumulated UP/BM pending checks (same field session):

1. Wedge the field dongle (or unbind its driver) while it is the active
   client: confirm one reset + rejoin on the SAME IP, no onboard failover,
   reset counter incremented in the status page.
2. Wedge it twice in one episode window: confirm the second failure fails
   over to onboard (episode guard), and the dongle is later adopted back.
3. Exhaust the reset budget (2 in 24 h): confirm straight-to-onboard.
4. Unplug the dongle: confirm immediate onboard failover (no reset attempt).
5. Confirm DEBUG log level (via the control API, TTL-bound) shows the scan
   lines for survey/onboard/pin scans, and INFO stays quiet about scans.
