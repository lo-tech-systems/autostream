# Settings-Apply

Release-driven changes to on-disk settings — a new default, a renamed key,
a one-shot migration — are shipped as data instead of bespoke code. Each
release carries a JSON manifest describing the changes; a standalone engine
applies it during install and every update, converging both the AutoStream
config and the owntone-mini config toward what the release expects while
still respecting values the user has changed.

## When it runs

`tools/autostream_settings_apply.py` runs during `configure_phase`, after
services are stopped for the update (or, on a fresh install, before they
have ever started) and before OwnTone is (re)started. Both the engine and
the manifest are read straight from the release tree the installer is
already running from — nothing is deployed to the appliance separately.

## Manifest schema

```json
{
  "version": 1,
  "directives": [
    {"target": "autostream", "key": "general.fifo_path", "mode": "overwrite",
     "value": "...", "reason": "..."}
  ]
}
```

Each directive names a `target` (`autostream` or `owntone-mini`), a `key`
(dotted path for autostream; flat for owntone-mini, except
`airplay_devices.<name>.<key>`), and a `mode`:

- **ensure** — sets the value only if the key is currently absent. A no-op
  if the key exists already, even with a different value; it never
  overrides a user's choice.
- **overwrite** — sets the value unconditionally, converging it every run.
  Requires a non-empty `reason` string, since it can silently discard a
  user's change.
- **delete** — removes the key if present. For owntone-mini this is
  "remove and let the module decide": the daemon's own default-healing
  re-adds the key at its built-in default the next time it starts if that
  key is still one it manages, so `delete` effectively means "reset to the
  module's default" rather than "leave it absent forever."
- **rename** — moves a key to a new path, no-op if the source is absent.
  If the destination key already exists, the whole run fails before
  anything is written (no silent clobber of a value that already lives
  there).

`from_before` (optional) gates a directive to fire only when the
previously installed release is older than the given tag; it compares
against the tag recorded by the prior install/update. It is skipped
(never fires) on fresh installs and on installs where the prior release
tag can't be trusted (untagged/source builds).

## Validation and failure behaviour

The engine validates every manifest strictly — unknown fields, modes, or
targets are hard errors — and then validates the resulting document
against a table of known-key constraints (owntone-mini's brick-guard
ranges, autostream's clamped ranges, and similar) before writing anything.
If any manifest fails to parse, or the result of applying it would leave
either config file in an invalid state, the whole run aborts and **no
file is touched** — a bad directive in one manifest cannot leave the
target files half-updated.

## Adding a directive to a release

Add an entry to `installer/settings-directives.json`. If the value should
track a constant defined in code (as the shipped fifo-path and mDNS
grace-period entries do), pin it in
`tests/test_settings_apply.py`'s shipped-manifest test so the manifest and
the constant can never drift apart silently.

See `installer/settings-directives.example.json` for an annotated example
exercising every mode, both targets, and a `from_before` gate.
