# Wi-Fi Watcher Structural Refactor — Implementation Plan

**Status:** Ready for execution.
**Executor:** Claude Code (Sonnet 5), working autonomously. Everything needed is
in this document plus the source tree; do not consult git history or other
working notes for behavioural truth — the executable code is authoritative.
**Scope:** `platform/wifi_watcher` and its sibling `platform/wifi_*.py` modules,
their tests, and the installer/systemd references to them.

---

## 1. Objective

The watcher subsystem is mid-way through a decomposition from a god module into
a hub (`platform/wifi_watcher`) plus eleven spoke modules. The logic is sound;
the remaining debt is **structural**:

1. The hub keeps ~100 one-line delegation wrappers and duplicate re-exports of
   sibling names/constants, kept alive only because tests patch
   `wifi_watcher.<name>`.
2. Seven context dataclasses (`CONFIG_CTX`, `ACTIVATION_CTX`, `RECOVERY_CTX`,
   `ADOPTION_CTX`, `STATUS_CTX`, `MDNS_CTX`, `LOOP_CTX`) are wired by
   import-order side effects, including a build-then-patch cycle
   (`ACTIVATION_CTX` is built with `RECOVERY_CTX=None` and patched later).
3. `wifi_web.build_app(w)` receives the whole hub module instead of a narrowed
   context like every other spoke.
4. A single ~50-field `NetworkMonitorState` (`STATE`) is shared across seven
   modules under one lock; ownership of its fields is by convention only.
5. The hub file has no `.py` extension, forcing a fragile `SourceFileLoader`
   shim in tests and hampering tooling.
6. `tests/test_p1_wifi_watcher.py` is a 6,500-line monolith (510 tests,
   87 classes, ~1,050 `patch.object` calls) that pins the wrapper layer in
   place.

This plan removes all six problems **without changing runtime behaviour**. The
510 existing tests are the behavioural spec and safety net: every work package
must end with the full suite green.

**There is no backward-compatibility requirement.** Internal names, module
seams, re-exports, and test patch points may all be broken freely, provided the
deployed runtime contract (section 2) is preserved and tests are updated in the
same commit.

---

## 2. Invariants — things that must NOT change

These are runtime/deployment contracts, not code aesthetics:

- **Deployed filename and service units.** Installers copy the hub to
  `/opt/autostream/autostream_wifi_watcher`, and both systemd units
  (`system/systemd/autostream_wifi_watcher.service`,
  `system/systemd/autostream_dial_wifi_watcher.service`) exec that path via
  shebang. The *deployed* name stays exactly as-is; only repo-side source
  paths change.
- **Observable behaviour.** Every timer value, state transition, hotspot
  purpose rule, reboot guard, debounce, ledger, log message key, file path
  (`/tmp/apmode`, `/etc/autostream-network.json`, `/var/lib/autostream/*`,
  `/run/autostream/*`), HTTP route, JSON response shape, and the loopback
  control-token mechanism must behave identically before and after.
- **Threading model.** One monitor loop thread, one activation worker, Flask on
  the main thread, `STATE` guarded by `state_lock`, one effectful transition in
  flight at a time (the `transitioning` flag). Do not change locking
  granularity or thread ownership anywhere in this plan.
- **Sibling deployment layout.** All `platform/wifi_*.py` modules are deployed
  flat into `/opt/autostream` beside the hub; imports must remain plain
  top-level names (`import wifi_policy`), never package-relative.
- **Behavioural coverage is preserved.** Tests asserting *behaviour* may be
  relocated and their patch points repointed, but their assertions may not be
  weakened. Tests whose subject is structure this plan removes (a wrapper's
  existence, a re-export identity, the loader shim) are deleted outright — a
  net drop in raw test count is expected and fine.

---

## 3. Ground rules for the executor

- **Work on a dedicated branch.** Before WP-1, create
  `refactor/wifi-watcher-structure` from the current `main` and do all work
  there. Do not commit to `main`. Do not merge; when WP-14 is committed, stop
  and report — merging is a human decision (the branch should be merged with
  a merge commit, not squashed, to preserve the per-WP history).
- **One work package = one git commit.** Complete the WP, get the suite green,
  commit with the message given in the WP, then start the next. Do not batch
  WPs into one commit and do not leave a WP half-done across commits. Each
  commit must leave the branch in a mergeable state — if `main` moves while
  this branch is in flight, a human decides whether to merge completed WPs
  early; do not rebase or merge `main` in without being asked.
- **Run tests before the first change** to record the baseline pass/fail count
  (there should be no pre-existing failures; if there are, note them in the
  commit message of WP-1 and do not attempt to fix unrelated failures).
  - Fast loop while working: `python -m pytest tests/test_p1_wifi_watcher.py tests/test_wifi_policy.py tests/test_wifi_nm.py -q`
    (adjust file list as WP-3 splits the monolith).
  - Full gate before every commit: `python -m pytest tests/ -q`.
- **Comment discipline (important):** code comments and docstrings exist only
  to help a reviewer or future maintainer understand the code *as it now is*.
  - Never reference this plan, work-package numbers, "the refactor",
    "previously", "legacy", "moved from", or any before/after comparison.
  - When you move or rewrite code, rewrite its docstring/comments to describe
    the end state. Many existing docstrings in the hub narrate the history of
    the decomposition ("re-exported so existing references keep working",
    "WP-11 style", "the seam is narrowed") — as you touch each area, delete or
    rewrite that narration. A comment that explains a *behavioural constraint*
    (e.g. "leave_setup_mode re-acquires state_lock, so call it outside the
    lock") stays; a comment that explains *where code used to live* goes.
  - Do not add comments explaining that something was renamed or simplified.
- **When a test fails after a change,** the default assumption is that you
  broke wiring, not that the test is wrong. The only tests you may delete are
  those whose entire subject is an artifact this plan removes (a delegation
  wrapper's existence, a re-export identity check, the loader shim itself).
  A test that verified behaviour *through* a wrapper must be repointed at the
  real implementation, keeping its assertions.
- **No new abstractions that don't own real behaviour.** This plan is
  subtraction and relocation, not invention.
- Development happens on Windows; the code targets Linux. Tests are designed
  to run offline on Windows — keep it that way.

---

## 4. Architecture orientation (read before starting)

Current shape, so you know what you're looking at:

- `platform/wifi_watcher` (extensionless, ~2,570 lines): constants, logging,
  `NetworkMonitorState`/`STATE`/`state_lock`, AP start/stop primitives,
  hotspot session enter/leave, the credential-apply candidate sequence, fact
  gathering, the monitor-loop driver (`network_monitor_loop` + phase lists),
  `__main__`, and — the part this plan mostly deletes — the wrapper/re-export
  layer and the seven context constructions (roughly lines 1980–2500).
- `platform/wifi_policy.py`: pure decision core (`Mode`, `HotspotPurpose`,
  `PURPOSE_TABLE`, `next_mode`, `next_recovery_action`, BSSID selection).
  Already clean; almost nothing to do here.
- `platform/wifi_loop.py`: the ordered `step_*` handlers and phase context
  types, driven through `LoopContext`.
- `platform/wifi_recovery.py`: dead-PHY detection, reset/quarantine/no-IP
  ledgers, persistence, reboot guard (`RecoveryContext`, `RecoveryState`).
- `platform/wifi_adoption.py`: USB failover/adoption, reconnect episodes,
  BSSID roaming (`AdoptionContext`).
- `platform/wifi_activation.py`: activation worker, `ActivationJob`/`Result`,
  `client_up_tail`, result application (`ActivationContext`).
- `platform/wifi_config.py`: configured-network reconnect, first-boot import
  (`ConfigContext`).
- `platform/wifi_status.py`: status snapshot (`StatusContext`).
- `platform/wifi_mdns.py`: avahi hostname repair + re-announce (`MdnsContext`).
- `platform/wifi_hotspot.py`: `HotspotController` (takes the hub module).
- `platform/wifi_nm.py`: bounded `NMClient`.
- `platform/wifi_web.py`: Flask pages/routes/control token —
  `build_app(w)` takes the whole hub module. The only wide seam left.

Dependency direction is strictly hub→spoke: **no sibling imports
`wifi_watcher`** and this must remain true throughout.

Tests:

- `tests/test_p1_wifi_watcher.py`: the monolith. Loads the hub once per
  session via `SourceFileLoader` with `flask` and `autostream_sysutils`
  stubbed; the `watcher` fixture resets `STATE` **in place, field by field**
  (the contexts captured the `STATE` object reference at import — rebinding
  `mod.STATE` would silently desync them; preserve in-place reset until WP-9
  removes the reason for it, and document it wherever it lives).
- `tests/test_wifi_policy.py`: the model to copy — imports the spoke directly,
  duck-types state/facts, no loader shim, no hub patching.
- `tests/test_wifi_nm.py`, plus wifi-related cases scattered in
  `test_wp7_network_api.py`, `test_wp8_wifi_install_reset.py`,
  `test_wp9_mdns_transition.py`, `test_wp10_final_regression.py`,
  `test_dial_wifi_setup.py`. Leave these files where they are (out of scope
  except where a patch point you remove breaks them — then repoint the patch,
  keep the assertions).

---

## 5. Work packages

Execute strictly in order. Each WP lists goal, steps, and acceptance criteria.

### WP-1 — Rename the hub to `wifi_watcher.py`; repo hygiene

**Goal:** the hub becomes a normal Python module; deployed artifact unchanged.

Steps:
1. `git mv platform/wifi_watcher platform/wifi_watcher.py`.
2. Update every repo-side reference to the old path:
   - `autostream_install.sh` (install line copying
     `platform/wifi_watcher` → `${INSTALL_DIR}/autostream_wifi_watcher`).
   - `autostream_dial_install.sh` (same pattern →
     `/opt/autostream/autostream_wifi_watcher`).
   - `tests/test_p1_wifi_watcher.py` (`WIFI_WATCHER_PATH`).
   - Any other hits from `grep -r "platform/wifi_watcher"` — check docs only
     if they are *operative* (installer helpers); do not churn prose docs.
   - The deployed filename `/opt/autostream/autostream_wifi_watcher` and both
     systemd `ExecStart` lines are **unchanged**.
3. Remove the stale bytecode litter: delete `platform/__pycache__/` contents
   from the working tree and ensure `.gitignore` covers `__pycache__/` and
   `*.pyc` (add if missing). Check whether any are git-tracked
   (`git ls-files platform/__pycache__`) and `git rm --cached` any that are.
4. The shebang and the ability to exec the deployed copy directly must remain
   (the file keeps `#!/usr/bin/python3` and its `__main__` block).

Acceptance: full suite green; `git grep -l "platform/wifi_watcher\b"` shows no
operative references to the extensionless path.

Commit: `wifi: rename watcher source to wifi_watcher.py and clean bytecode litter`

### WP-2 — Simplify test loading of the watcher

**Goal:** replace the `SourceFileLoader` shim with a plain import; keep the
dependency stubs, centralised.

Steps:
1. In `tests/test_p1_wifi_watcher.py`, replace `_get_watcher()`'s
   loader machinery: add `platform/` (and keep `core/`) to `sys.path`, install
   the `flask` and `autostream_sysutils` stubs into `sys.modules` *only if the
   real packages are absent* (keep the existing save/restore behaviour for the
   attributes it must stub when the real module is present — or better,
   eliminate attribute mutation of real modules entirely by injecting a
   purpose-built stub module under the name before first import), then
   `import wifi_watcher`.
2. Keep loading it under a single shared module object per session (the tests
   assume shared identity), and keep the `flask_client` fixture's separate
   fresh-load-with-real-Flask path working (it may now use
   `importlib.reload`-style fresh module under an alias, still simpler than
   before because the file is importable).
3. Move the loader helper plus the `watcher` fixture (in-place `STATE` reset)
   and the activation-worker/log-level autouse fixtures into a new
   `tests/wifi_conftest` home — either `tests/conftest.py` additions or a
   `tests/_wifi_fixtures.py` imported by the wifi test files; choose whichever
   keeps non-wifi tests unaffected.
4. Add a short comment at the `watcher` fixture explaining the in-place reset
   constraint (contexts hold the `STATE` reference), phrased as a present-tense
   invariant.

Acceptance: full suite green; no `SourceFileLoader` use remains for the
watcher; real `flask`/`autostream_sysutils` modules are never attribute-mutated.

Commit: `tests: import wifi_watcher directly and centralise watcher fixtures`

### WP-3 — Split the test monolith by subject module

**Goal:** `test_p1_wifi_watcher.py` disappears; its 87 classes move, unchanged,
into per-subject files mirroring the production split.

Steps:
1. Create these files and move classes whose subject matches (judge by what
   the class exercises, not by what it patches):
   - `tests/test_wifi_watcher_core.py` — hub-owned behaviour: helpers/parsers,
     AP flag lifecycle, enter/leave setup mode, `start_ap_mode` failures,
     configured-network name resolution, facts gathering, control-action
     processing, log-level control, guarded reboot.
   - `tests/test_wifi_web_routes.py` — Flask/captive-portal/status/control
     routes, control token.
   - `tests/test_wifi_hotspot_ctl.py` — `HotspotController`, station count.
   - `tests/test_wifi_activation.py` — worker, jobs/results,
     `client_up_tail`, candidate/validate tail, apply flow.
   - `tests/test_wifi_recovery.py` — no-IP ledger, diagnosis, overlay events,
     budgeted reset/quarantine, reboot guard, fault-state persistence.
   - `tests/test_wifi_adoption.py` — USB failure fallback, runtime adoption,
     reconnect episodes, BSSID survey/roam, adoption scan gates.
   - `tests/test_wifi_config.py` — first-boot import, autoconnect migration,
     connect-to-configured, committed-UUID resolution.
   - `tests/test_wifi_loop.py` — step handlers, phase contexts, hysteresis,
     health memo, ethernet-wins, boot AP entry, connection reliability,
     catch-all reboot.
   - `tests/test_wifi_status.py` / `tests/test_wifi_mdns.py` — snapshot and
     avahi classes.
2. This WP is **mechanical**: move classes and module-level helpers they use;
   do not change assertions, patch targets, or fixtures beyond import fixes.
   Shared helpers used by several new files go into the fixtures home from
   WP-2.
3. Delete `tests/test_p1_wifi_watcher.py` once empty. Update any docstring at
   the top of each new file to state its subject in one or two lines (no
   history).

Acceptance: full suite green; total test count identical to before the WP;
no file exceeds ~1,200 lines (if one does, split it again along class lines).

Commit: `tests: split watcher test monolith into per-module files`

### WP-4 — Narrow the `wifi_web` seam to a `WebContext`

**Goal:** `wifi_web.build_app` and the control-token functions receive an
explicit context, not the hub module.

Steps:
1. Inventory every `w.<attr>` access in `wifi_web.py` (routes, page renderers,
   `_has_saved_network`, `init_control_token`, `validate_log_level_request`,
   etc.). Expect: `STATE`, `state_lock`, `logger`, `control_action_event`,
   `submit_apply_credentials`, `scan_all_networks`, constants
   (`RUNTIME_LOG_LEVELS`, `LOG_LEVEL_TTL_MIN/MAX`, `_NON_DISRUPTIVE_ACTIONS`,
   hostname/title bits), `get_configured_network_state`, and whatever else the
   grep reveals — build the exact list from the code, not this note.
2. Define `WebContext` (dataclass, same style as `LoopContext` in
   `wifi_loop.py`) carrying precisely that list. Replace `build_app(w)` with
   `build_app(ctx)`; same for `init_control_token`/`render_wait_page`/other
   `w`-taking functions.
3. In the hub, construct `WEB_CTX` beside the other contexts and pass it. The
   hub's `_self_module()` device exists mainly for this seam and for
   `HotspotController`; remove `_self_module()` usage from the web wiring
   (keep it only if `wifi_hotspot` still needs it — that seam is narrowed in
   WP-6).
4. Repoint web-route tests that patched hub attributes to patch the context
   fields or the spoke functions directly.
5. Rewrite the hub/web docstrings that describe the `w` seam so they describe
   the context seam.

Acceptance: full suite green; `wifi_web.py` contains no `w.` module-object
accesses; `grep -n "_self_module" platform/wifi_watcher.py` shows at most the
hotspot-controller use.

Commit: `wifi: narrow wifi_web seam to an explicit WebContext`

### WP-5..WP-8 — Retire the wrapper/re-export layer, seam by seam

**Goal:** delete the ~100 one-line delegators and duplicate re-exports from the
hub; call sites (production and test) use the spoke modules and contexts
directly. Four commits, smallest blast radius first.

General method per seam:
1. List the hub wrappers for the seam (they all follow the pattern
   `def name(...): return <spoke>.name(<CTX>, ...)`) and the re-exported
   names/constants.
2. Production call sites: within the hub and other spokes, call
   `<spoke>.fn(<CTX>, ...)` directly, or — where a context already carries the
   callable — leave the context field but point it at the spoke function
   bound with its context (`functools.partial(spoke.fn, SPOKE_CTX)`) instead
   of the hub wrapper. Prefer whichever produces the *fewer* indirections;
   never add a new wrapper.
3. Test call sites: repoint `watcher.<name>` uses and `patch.object(watcher,
   "<name>")` to the spoke module / context field. Where a test patched a hub
   wrapper to intercept a call made *through a context*, patch the context
   field instead (contexts are plain dataclasses; setting an attribute for the
   duration of a test is fine — restore it after, or use
   `unittest.mock.patch.object` on the context).
4. Delete the wrappers and re-exports for that seam. Delete any test whose
   only assertion was "the hub re-exports X" / "the wrapper delegates".
5. Sweep the seam's docstrings for decomposition narration and rewrite.

Seam grouping and commits:

- **WP-5** — `wifi_mdns`, `wifi_status`, `wifi_config` wrappers, plus the
  `wifi_policy` re-exports (`Mode`, `HotspotPurpose`, `PurposePolicy`,
  `PURPOSE_TABLE`, `next_mode`, `RecoveryFacts`, `RecoveryKind`,
  `RecoveryAction`, `next_recovery_action`, and the constants
  `AP_MAX_DURATION`/`HOTSPOT_PROBE_GRACE`/`BOOT_AP_GRACE` — keep exactly one
  home, `wifi_policy`, and import from it where needed).
  Commit: `wifi: retire hub wrappers for mdns/status/config and policy re-exports`
- **WP-6** — `wifi_hotspot` + AP primitives: narrow `HotspotController` to a
  `HotspotContext` (it currently takes the hub module); with WP-4 done this
  removes the last consumer of `_self_module()` — delete that function.
  Commit: `wifi: narrow HotspotController seam and drop module self-reference`
- **WP-7** — `wifi_adoption` and `wifi_activation` wrappers (the largest
  group: episodes, adoption, worker submission, `client_up_tail`,
  `apply_activation_result`, epoch/queue aliases). Note the module-level
  aliases `_activation_job_queue` / `activation_result_event` in the hub —
  tests should use `wifi_activation`'s own globals; delete the aliases.
  Commit: `wifi: retire hub wrappers for adoption and activation seams`
- **WP-8** — `wifi_recovery` wrappers and the `wifi_loop` `step_*` /
  helper wrappers. After this, `network_monitor_loop` builds its phase lists
  from `functools.partial(wifi_loop.step_x, LOOP_CTX)` directly.
  Commit: `wifi: retire hub wrappers for recovery and loop seams`

Acceptance after WP-8: the hub contains **zero** one-line delegation wrappers;
`grep -c "return wifi_" platform/wifi_watcher.py` ≈ 0 (allow genuine logic
functions); every name exists in exactly one module; suite green with the
same-or-fewer-only-by-removed-wrapper-identity-tests count.

### WP-9 — Explicit composition

**Goal:** all imports at the top of the hub; all contexts constructed in one
place, in one function, with no build-then-patch.

Steps:
1. Move the mid-file `import wifi_loop` / `wifi_activation` / `wifi_recovery`
   / `wifi_config` / `wifi_status` / `wifi_mdns` statements to the top import
   block. This becomes possible because the wrappers that forced
   definition-order interleaving are gone.
2. Create one composition function in the hub (e.g. `build_contexts()` or a
   small `Wiring` dataclass holding the seven-plus contexts and the worker
   entry points). It constructs, in explicit dependency order:
   `NMClient` → `RecoveryState` → `RECOVERY_CTX` → `ACTIVATION_CTX` (now with
   its real `RECOVERY_CTX` — the `RECOVERY_CTX=None`-then-patch step is
   deleted; break the circular need by restructuring which side holds which
   callable, e.g. pass `functools.partial`s resolved at build time) →
   `CONFIG_CTX` → `ADOPTION_CTX` → `STATUS_CTX` → `MDNS_CTX` → `WEB_CTX` →
   `HotspotContext` → `LOOP_CTX`.
   If a true cycle exists between activation and recovery callables, resolve
   it with a late-bound closure over the wiring object built *inside* the
   composition function — never by mutating a context after construction from
   module top level.
3. Module import calls the composition once and binds the results to module
   globals (production behaviour unchanged; tests keep a stable shared
   instance). Tests that need pristine wiring may call the composition
   function themselves.
4. The hub's giant module docstring: rewrite it to describe the *current*
   architecture in ~30 lines (responsibility split, threading model, state
   machine pointers). Remove all narration of how it got here.

Acceptance: suite green; no `import wifi_*` below the top import block of the
hub; no context attribute is assigned outside the composition function;
`ACTIVATION_CTX.RECOVERY_CTX = ...` post-patch is gone.

Commit: `wifi: build all module contexts in one explicit composition function`

### WP-10..WP-12 — Split `STATE` into a dedicated state module

**Goal:** create `platform/wifi_state.py`, a **data-only leaf module** at the
bottom of the dependency graph: it defines the per-concern state dataclasses,
the slimmed connectivity-core `NetworkMonitorState`, and `state_lock`. It
imports nothing from the other `wifi_*` modules and contains **no behaviour**
(no functions beyond trivial dataclass defaults). Every other module gets its
state types from here, so no spoke ever imports another spoke just for a type.
`state_lock` remains the single lock guarding all fragments — do not touch
locking granularity.

Ownership is expressed by wiring, not by file location: `build_contexts()`
constructs each fragment and threads it only to the contexts that read or
write it.

One commit per step, suite green after each:

- **WP-10** — create `wifi_state.py`; move `NetworkMonitorState` and
  `state_lock` into it verbatim (hub imports them); then extract the first
  fragments into their own dataclasses in the same file: `ApplyState`
  (`apply_in_progress`, `last_apply_result`, `last_apply_error`),
  `ControlState` (`pending_control_action`, `pending_control_params`,
  `control_in_progress`, `last_control_*`), and `LogLevelState`
  (`temporary_log_level*`, `default_log_level_name`). Thread them through the
  contexts that use them (`WebContext` reads apply/control; the hub's
  control/log-level handling writes them).
  Commit: `wifi: introduce wifi_state module and split apply/control/log-level state`
- **WP-11** — extract `MdnsState` (avahi + address-set fields) and
  `SnapshotState` (`network_status_snapshot`, `network_status_updated_at`)
  into `wifi_state.py`; thread through `MdnsContext`/`StatusContext`.
  Commit: `wifi: split mdns and status-snapshot state into wifi_state`
- **WP-12** — extract `AdoptionState` (`pending_usb_adoption_*`,
  `last_detected_adapter_macs`, `bssid_table`, `last_roam_or_activation`,
  `last_bssid_*`, `last_adoption_scan`, `using_builtin_fallback`); thread
  through `AdoptionContext` (and `StatusContext` where the snapshot reads
  adoption fields). What remains in `NetworkMonitorState` is the connectivity
  core: link/mode/hotspot-session fields, timers, debounce counters,
  `transitioning`, active-client identity, reconnect episode.
  Commit: `wifi: split adoption/roaming state into wifi_state`

Method notes for all three:
- Move fields verbatim (same names, defaults, semantics). Update every reader/
  writer — `grep -n "STATE\.<field>"` across `platform/` and `tests/` per
  field, exhaustively, before moving it.
- `wifi_state.py` must stay a leaf: if a fragment seems to need a type from
  another `wifi_*` module (e.g. `HotspotSession`, `ReconnectEpisode`), either
  move that plain data type into `wifi_state.py` too, or keep the field typed
  as `Optional[object]` — never import a spoke from `wifi_state`.
- Keep `wifi_policy` reading state duck-typed (it takes whatever object has
  the fields); do not add a `wifi_state` import there.
- Update the test `watcher` fixture to reset every fragment generically
  (iterate `dataclasses.fields` per fragment, in place — contexts hold the
  object references, so in-place reset remains mandatory; keep the
  explanatory comment). Installer note: `wifi_state.py` is a new deploy-
  together sibling — add it to the module list both install scripts copy to
  `/opt/autostream`.

### WP-13 — Replace `client_up_tail`'s flag soup with named variants

**Goal:** `wifi_activation.client_up_tail` currently takes eight orthogonal
keyword flags whose valid combinations are tribal knowledge. Replace with a
small closed set of named tail variants derived from the actual call sites.

Steps:
1. Enumerate every call site and the flag combination each passes (hub boot
   bring-up, recovery rungs, adoption, apply success, reconnect episode…).
   Expect roughly 4–6 distinct combinations.
2. Define the variants as either an enum + a per-variant parameter dataclass,
   or per-variant constructor functions returning a single `TailSpec` —
   pick the lighter one that makes each call site read as intent
   (e.g. "adopted USB client", "recovered onboard client", "credentials
   applied") rather than as a flag list.
3. Keep the tail's *behaviour* per combination byte-identical; the change is
   call-signature only. Update tests exercising `client_up_tail` combinations
   to construct the variants.

Acceptance: suite green; no call site passes more than one or two arguments
beyond the adapter and its variant.

Commit: `wifi: replace client_up_tail boolean flags with named tail variants`

### WP-14 — Final sweep

**Goal:** leave the subsystem coherent for the next maintainer.

Steps:
1. Grep all `platform/wifi_*` files and the new test files for leftover
   decomposition narration ("re-exported", "seam is narrowed", "WP-",
   "keeps working", "moved", "legacy" where it doesn't describe an actual
   runtime legacy artifact — note `/opt/autostream/ssid` genuinely *is* a
   legacy compatibility file at runtime; comments about that stay). Rewrite or
   delete.
2. Verify no sibling imports `wifi_watcher` (`git grep "import wifi_watcher"
   -- platform/` must return nothing).
3. Confirm `docs/WIFI-WATCHER.md` (the operative doc) still matches reality at
   the level it describes; fix only factual drift introduced by this plan
   (source filename, module list). Do not rewrite it wholesale.
4. Move this plan file to `docs/working/closed/`.
5. Full suite run; record the final count in the commit message.

Commit: `wifi: final comment/doc sweep after structural refactor`

---

## 6. Out of scope (do not do these)

- The service-component target architecture in
  `wifi-watcher-target-architecture-note.md` (AdapterInventory,
  ConnectionStore, etc.) — that is a later strangler phase.
- Any behaviour change, timer tuning, or new feature.
- Splitting or re-granulating `state_lock`.
- Consolidating the `test_wp*` regression files or `test_dial_wifi_setup.py`.
- Touching the installer beyond the source-path updates in WP-1.
- Converting `platform/` into a package (`__init__.py`) — deployment is flat.

## 7. Definition of done

- All 14 WPs committed individually, full suite green at every commit.
- `platform/wifi_watcher.py` contains constants, genuine hub logic (AP
  primitives, apply sequence, facts, loop driver, guarded reboot,
  `__main__`), one composition function — and no delegation wrappers, no
  re-exports, no mid-file imports, no post-construction context patching.
- `platform/wifi_state.py` is a data-only leaf module holding `state_lock`,
  the connectivity-core `NetworkMonitorState`, and the per-concern state
  fragments; it imports no other `wifi_*` module and contains no behaviour.
- Every spoke receives a narrowed context; nothing receives a module object.
- Tests live in per-subject files, import spokes directly, and patch spoke
  functions or context fields — never a hub alias.
