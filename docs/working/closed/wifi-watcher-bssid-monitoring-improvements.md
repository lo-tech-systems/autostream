# Wi-Fi Watcher — BSSID Monitoring Improvements Plan

**Status:** Complete. BM-1 through BM-5 all landed on
`refactor/wifi-watcher-structure`, one commit per work package, full suite
green at every step. Baseline entering this stage: 5207 total (before BM-1).

| WP | Commit | Suite after |
|---|---|---|
| BM-1 per-interface tables | `2edbb8c` | 5207 passed / 103 skipped |
| BM-2 floor + streak policy | `d62c03b` | 5222 passed / 103 skipped |
| BM-3 roam orchestration | `abecf8e` | 5227 passed / 103 skipped |
| BM-4 interface-scoped pinning | `a912cdc` | 5230 passed / 103 skipped |
| BM-5 docs + regression sweep | `5b11d8a` | 5230 passed / 103 skipped |

BM-5 sweep: grepped platform/, core/, tests/, docs/ for bare `bssid_table\b`,
`BSSID_USB_SURVEY_INTERVAL`, and `last_bssid_usb_full_survey_at`. The first
pattern only matched substrings of the valid `update_bssid_table` /
`clear_bssid_table` names; the latter two constant/field names are already
fully removed from the codebase (BM-3 deleted them). One stale-reading test
comment (`tests/test_wifi_adoption.py`, narrating the removed
`BSSID_USB_SURVEY_INTERVAL` gate in past tense) was reworded to a present-
tense behaviour statement. `docs/WIFI-WATCHER.md` updated: the "USB BSSID
ownership / roam" paragraph now describes per-interface tables, the
diagnostics-only onboard table, the absolute signal floor, the 3-scan
candidate streak plus same-candidate confirmation, and the single 60 s
cadence with idle full-scan; the Key Timers table collapses the old
"cheap survey" / "full USB survey" pair into one row and drops the
15-minute full-survey interval.

**Accumulated PENDING hardware checks** (no Pi hardware on the dev
workstation; none attempted) — run together with the three still-pending
UP-stage checks (pinned dual-AP activation; unbind/rebind + pinned rejoin;
forced and signal-delta roams with no roam during playback):
1. Periodic idle `rescan=True` USB scans do not drop pings.
2. No proactive roam during playback.
3. A transiently stronger AP (one scan) does not cause a roam; three
   consecutive wins do.
4. The `30 -> 47` case: candidate below the floor never roams.
5. A genuine better AP (e.g. 35 current, 65+ candidate, three scans) roams
   and stays healthy.
6. Logs explain the streak and the final decision.

**Context:** Follow-on to the completed USB BSSID ownership stage
(`docs/working/wifi_watcher_usb_handling_improvements.md`). Field testing on
the target appliance showed `nmcli dev wifi rescan` did not materially
interrupt connectivity, so more active background scanning is acceptable than
the original cautious design assumed.

## Problem statement

The current roam logic can make a one-scan, signal-only decision. Field log:

```text
BSSID roam: SSID 'IoT' DA:B3:70:14:DF:F4 (signal 30) -> D2:21:F9:9C:97:65 (signal 47)
```

The device roamed from a physically close AP to a more distant one. The
current code permits this because:

- Signals are nmcli `SIGNAL` percentages only — not distance, link
  reliability, or gateway health.
- `ROAM_LOW_SIGNAL = 50` / `ROAM_LOW_MARGIN = 6`: `30 -> 47` clears the
  relaxed low-signal arm. There is no absolute candidate floor.
- `ADOPTION_STATE.bssid_table` is a single flat table updated by scans from
  multiple interfaces; an onboard scan can overwrite signal data that later
  drives a USB roam decision.
- The confirmation scan reads the same shared table and does not require the
  candidate to be preferred over multiple scans.

The aim: make proactive roaming conservative and interface-specific.

1. A USB roam decision uses only the active USB adapter's own scan
   observations.
2. A candidate must be consistently better over multiple eligible USB scans
   (streak of 3).
3. A candidate must be strong enough in absolute terms
   (`BSSID_ROAM_MIN_SIGNAL`), not just less bad than the current AP.
4. Failure/quarantine accounting becomes interface-scoped.
5. Existing pinning, recovery-ladder, hotspot, and reboot behaviour is
   unchanged.

## Scope

In scope: per-interface BSSID tables (clean rename — the flat table is
replaced, not paralleled), USB-table-only roam decisions, the 3-scan
candidate streak, the absolute signal floor, interface-scoped
failure/quarantine, cadence change (option 1 below), tests, and a
`docs/WIFI-WATCHER.md` update.

Out of scope — do not implement or "improve" beyond the list above:

- Persisting BSSID tables across restarts (in-memory RF observations only).
- Web UI / `/network_status` exposure of the tables.
- Multi-saved-network support; band preference / 5 GHz weighting; channel
  congestion; hidden SSIDs.
- Any change to recovery-ladder ordering, hotspot policy, reboot guards, or
  no-IP reset policy.
- USB hardware resets as part of ordinary roam optimisation.
- Changing `NMClient` / command-builder / parser signatures in
  `wifi_nm.py` / `autostream_wifi_network.py` (reuse them as-is).

No backward compatibility is required: state fields, function signatures and
test expectations may change freely within scope, provided assertions are
updated rather than weakened.

## Current code pointers (verified against the branch)

- `platform/wifi_state.py` — `AdoptionState` holds `bssid_table` (flat dict,
  to be replaced), `last_roam_or_activation`, `last_bssid_pin`,
  `last_bssid_survey_at`, `last_bssid_usb_full_survey_at`. Data-only leaf:
  stdlib imports only, no behaviour. The `watcher` test fixture resets
  fragments in place generically, so new fields need no fixture changes.
- `platform/wifi_policy.py` — pure BSSID policy over a passed-in table:
  `update_bssid_table`, `record_bssid_failure`, `record_bssid_success`,
  `select_bssid`, `next_roam_target`, `clear_bssid_table`; constants
  `BSSID_FRESH_SECS`, `BSSID_EVICT_SECS`, `BSSID_QUARANTINE_FAILS`,
  `BSSID_QUARANTINE_SECS`, `ROAM_LOW_SIGNAL`, `ROAM_MARGIN`,
  `ROAM_LOW_MARGIN`, `ROAM_HOLDOFF_SECS`.
- `platform/wifi_adoption.py` — `bssid_survey_and_roam(ctx, hctx)` (survey +
  roam orchestrator), `_survey_due`, `_idle_onboard_for_survey`.
- `platform/wifi_loop.py` — `step_bssid_survey(ctx, hctx)` delegates to the
  above via `LOOP_CTX.bssid_survey_and_roam`.
- `platform/wifi_activation.py` — `_pin_usb_bssid(ctx, ifname, uuid,
  exclude="")`, success/failure accounting in `_activate_profile_on`,
  `_pin_implicates_adapter` / `_retry_after_implicated_failure`
  (reads `ADOPTION_STATE.last_bssid_pin`), `PIN_IMPLICATE_SIGNAL`.
- `platform/wifi_watcher.py` — hub. Constants `BSSID_SURVEY_INTERVAL = 60`,
  `BSSID_USB_SURVEY_INTERVAL = 15 * 60` (the latter is removed by this
  plan); `_commit_network_state` calls
  `wifi_policy.clear_bssid_table(ADOPTION_STATE.bssid_table)` on SSID
  change; `build_contexts()` threads `ADOPTION_STATE` into
  `ADOPTION_CTX` / `ACTIVATION_CTX` / `RECOVERY_CTX` / `STATUS_CTX`.
- Tests: `tests/test_wifi_policy.py` (pure policy),
  `tests/test_wifi_adoption.py` (`TestStepBssidSurvey`,
  `TestBssidSurveyAndRoam`, adoption-scan gating),
  `tests/test_wifi_activation.py` (`TestPinUsbBssid`,
  `TestBudgetedResetRetry`), `tests/test_wifi_nm.py`,
  `tests/test_autostream_wifi_network.py` (leave the last two unchanged).

## Design

### Data model

Replace `AdoptionState.bssid_table: dict` with:

```python
# wifi_state.py, AdoptionState
bssid_tables: dict = field(default_factory=dict)   # ifname -> {BSSID -> entry}
bssid_roam_candidate: dict = field(default_factory=dict)
    # {"ifname", "bssid", "count", "last_seen"} or {} when no streak
```

Per-BSSID entry shape is unchanged:
`{"ssid", "signal", "last_seen", "fail_count", "quarantined_until"}`.
Clean rename: update every reference and test in the same WP; no parallel
flat table remains. In-memory only; no persistence, no migration.

Pure accessors in `wifi_policy.py` (they operate on passed-in dicts,
consistent with the module contract):

```python
def bssid_table_for_interface(tables: dict, ifname: str) -> dict:
    return tables.setdefault(ifname, {})

def clear_bssid_tables(tables: dict) -> None:
    tables.clear()
```

`clear_bssid_table` (single-table) may remain for the per-interface tables'
internal use or be absorbed; the SSID-change site clears ALL monitoring
state: `bssid_tables`, `bssid_roam_candidate`, and `last_bssid_pin`.

### Constants — in `wifi_policy.py`, beside the existing ROAM_* group

```python
BSSID_ROAM_REQUIRED_SCANS = 3   # consecutive eligible USB scans preferring the same candidate
BSSID_ROAM_MIN_SIGNAL = 55      # absolute floor for proactive optimisation roams
```

They parameterise pure policy, so they live in the pure module (the hub
referencing them via `wifi_policy.<name>` where needed). Do NOT put them in
the hub — that would invert the dependency direction.

### Policy changes (`wifi_policy.py`, pure)

`next_roam_target` gains the absolute floor:

```python
def next_roam_target(table, current_bssid, now, playing,
                     last_roam_or_activation, *,
                     min_signal: int = BSSID_ROAM_MIN_SIGNAL) -> str
```

Behaviour: unchanged gates (playing exactly False; `ROAM_HOLDOFF_SECS`;
fresh, non-quarantined candidates; fail_count-then-signal ordering; both
margin arms) PLUS the candidate must have `signal >= min_signal`. The floor
applies to proactive optimisation roaming only — recovery/failover paths do
not call this function and are untouched.

New pure streak helper (also `wifi_policy.py`):

```python
def update_roam_streak(streak: dict, ifname: str, candidate: str, now: float) -> dict
```

Rules: empty `candidate` -> `{}` (reset). Same (ifname, bssid) as the
existing streak -> increment `count`, refresh `last_seen`. Different
candidate or interface -> new streak at `count=1`. Returns the new dict
(caller assigns it to `ADOPTION_STATE.bssid_roam_candidate` under
`state_lock`, matching existing locking of adoption state in that path).

### Survey/roam flow (`wifi_adoption.bssid_survey_and_roam`)

1. Gating unchanged (not in setup, not transitioning, active client is a
   recorded USB adapter, healthy this pass).
2. Every scan updates ONLY its own interface's table via
   `bssid_table_for_interface(ADOPTION_STATE.bssid_tables, <scanned ifname>)`:
   USB scans -> the USB table; the opportunistic idle-onboard scan -> the
   onboard table (kept for diagnostics; MUST NOT influence a USB roam).
3. Roam evaluation reads only the active USB interface's table, using the
   in-use row from the same USB scan for the current signal (unchanged
   principle).
4. Streak: no eligible USB scan this pass -> streak untouched. Eligible USB
   scan with no candidate clearing policy (including the floor) -> streak
   reset to `{}`. Candidate clears policy -> `update_roam_streak`; only when
   `count >= BSSID_ROAM_REQUIRED_SCANS` proceed to the existing fresh USB
   confirmation scan.
5. Confirmation scan updates the USB table and re-evaluates from that table
   only; submit the roam job only if the confirmed target is the SAME
   candidate and still clears policy (floor included). On submit: stamp
   `last_roam_or_activation`, reset the streak to `{}`, log, submit the
   existing `ActivationJob(kind="activate_committed", ifname=<usb>)`,
   return owning verdict — all as today.
6. Logging: streak progress at DEBUG
   (`BSSID roam candidate on wlan1: <cur> (<s>) -> <cand> (<s>) [2/3]`),
   INFO when a streak first starts and when the roam fires (include SSID,
   ifname, from/to BSSID, signals, scan count).

### Scan cadence — option 1 (conservative)

- Keep `BSSID_SURVEY_INTERVAL = 60` as the single cadence gate.
- When the survey is due and playback is exactly `False`: the USB self-scan
  runs with `rescan=True` (full scan — this is what makes a scan "eligible"
  for the streak). When playback is `True`/`None`: keep today's cheap
  `rescan=False` read (table upkeep only; never advances or resets the
  streak, since candidates from a stale list are not eligible evidence).
- Remove `BSSID_USB_SURVEY_INTERVAL` and the `last_bssid_usb_full_survey_at`
  field/gating entirely (the 60s idle full scan supersedes the 15-minute
  one). Remove the field from `AdoptionState` in the same WP.
- The idle-onboard opportunistic scan keeps its current cadence and gating,
  now writing to its own table.
- A roam therefore requires ~3 minutes of consistent idle-time preference.
  Scans stay inline on the loop thread bounded by
  `NMCLI_BSSID_SCAN_TIMEOUT` (existing precedent).

### Activation pinning interaction (`wifi_activation.py`)

- `_pin_usb_bssid`: scan the target ifname, update
  `bssid_table_for_interface(ADOPTION_STATE.bssid_tables, ifname)`, select
  from that table (the `exclude` retry parameter unchanged), record
  `last_bssid_pin` as today.
- Success/failure accounting (`record_bssid_success` / `record_bssid_failure`
  at the activation verdict) applies to the activation target's own table,
  so a pin outcome on `wlan1` can never quarantine or clear entries observed
  by `wlan0`.
- `_pin_implicates_adapter` / `_retry_after_implicated_failure` read
  `last_bssid_pin` only — unchanged.
- `_commit_network_state` (hub) switches to clearing all monitoring state
  (see Data model).

## Testing plan

Pure tests (`tests/test_wifi_policy.py`):

1. Floor: candidate below `BSSID_ROAM_MIN_SIGNAL` rejected even when a
   margin arm is satisfied (the `30 -> 47` case verbatim); at/above floor
   plus margin accepted; floor enforced on both margin arms.
2. Existing quarantine/freshness/ordering tests still pass (update call
   sites for any signature change; do not weaken).
3. `update_roam_streak`: same-candidate increment, candidate change resets
   to 1, interface change resets to 1, empty candidate resets to {}.
4. `bssid_table_for_interface` / `clear_bssid_tables` basics.

Orchestration tests (`tests/test_wifi_adoption.py`):

1. USB and onboard scans land in separate per-interface tables.
2. An onboard-only stronger candidate never triggers a USB roam.
3. Streak gating: 1 and 2 eligible scans -> no job; 3 -> job submitted;
   candidate change resets; candidate disappearance resets; below-floor
   candidate never builds a streak.
4. Playback `True`/`None`: no full USB scan, no streak progression, no roam.
5. Confirmation scan reversal -> no submission; confirmation must confirm
   the same candidate that built the streak.
6. Committed-SSID change clears tables + streak + pin record.
7. Cadence: `BSSID_USB_SURVEY_INTERVAL` gating is gone; idle survey performs
   `rescan=True` on the USB, non-idle survey performs `rescan=False`.

Activation tests (`tests/test_wifi_activation.py`):

1. `_pin_usb_bssid` selects from the target interface's table.
2. Failure accounting on `wlan1` touches only `wlan1`'s table; success
   quarantine likewise.
3. Existing implicated-failure reset tests still pass (update state shape).

Do not change `tests/test_wifi_nm.py` / `tests/test_autostream_wifi_network.py`
(no primitive signatures change).

Verification commands:

```
python -m pytest tests/test_wifi_policy.py tests/test_wifi_adoption.py tests/test_wifi_activation.py -q
python -m pytest tests/ -q          # full gate before every commit
```

Full-suite gate: zero failures; total grows only by the tests added in that
WP (baseline entering this plan: 5307 total; the pass/skip split drifts
environmentally between ~5204/103 and ~5167/140 — capture your own
pre-change split and compare like-for-like).

## Work packages (one commit each, on `refactor/wifi-watcher-structure`)

### BM-1 — Per-interface tables

`AdoptionState.bssid_table` -> `bssid_tables` (+ accessors in wifi_policy);
every reader/writer and test updated (`git grep -n "bssid_table"` must show
only the new shape afterwards); survey scans write per-interface; roam
evaluation reads the USB table only; SSID-change clearing updated
(tables + pin record; streak field arrives in BM-2).
Commit: `wifi: scope BSSID monitoring tables per interface`

### BM-2 — Floor and streak policy (pure)

`BSSID_ROAM_REQUIRED_SCANS` / `BSSID_ROAM_MIN_SIGNAL` in wifi_policy;
`next_roam_target` floor; `update_roam_streak`;
`AdoptionState.bssid_roam_candidate`; pure tests.
Commit: `wifi: add roam signal floor and candidate-streak policy`

### BM-3 — Roam orchestration

`bssid_survey_and_roam` applies the streak and same-candidate confirmation;
cadence option 1 (remove `BSSID_USB_SURVEY_INTERVAL` +
`last_bssid_usb_full_survey_at`); logging; orchestration tests.
Commit: `wifi: require a sustained candidate streak before proactive roams`

### BM-4 — Interface-scoped pinning accounting

`_pin_usb_bssid` + success/failure accounting on the target interface's
table; activation tests.
Commit: `wifi: scope BSSID pin accounting to the activation interface`

### BM-5 — Docs + regression sweep

Update `docs/WIFI-WATCHER.md` (BSSID monitoring model: per-interface tables,
streak, floor, cadence). Full-suite run; grep for stale references
(`bssid_table\b`, `BSSID_USB_SURVEY_INTERVAL`, `last_bssid_usb_full_survey_at`
must be gone from platform/ and tests/). Record hardware checks as PENDING in
this doc's Status.
Commit: `wifi: document per-interface BSSID monitoring and sweep stale references`

## Conventions (every WP)

- Run every command in the foreground (no background tasks, watchers, or
  monitors); full suite `python -m pytest tests/ -q`, timeout 600000ms.
- Code comments state behaviour and constraints only — no plan/WP/history
  references.
- All new/changed adoption-state access under `state_lock` exactly as the
  code it replaces (match existing lock placement; do not add or remove
  locking).
- Never weaken a test assertion; update call sites/shapes, keep semantics.

## Hardware validation checklist (PENDING — no Pi on the dev workstation)

To be run in one session together with the three still-pending UP-stage
checks (pinned dual-AP activation; unbind/rebind + pinned rejoin; forced and
signal-delta roams with no roam during playback):

1. Periodic idle `rescan=True` USB scans do not drop pings.
2. No proactive roam during playback.
3. A transiently stronger AP (one scan) does not cause a roam; three
   consecutive wins do.
4. The `30 -> 47` case: candidate below the floor never roams.
5. A genuine better AP (e.g. 35 current, 65+ candidate, three scans) roams
   and stays healthy.
6. Logs explain the streak and the final decision.
