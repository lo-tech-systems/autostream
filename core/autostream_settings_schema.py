#!/usr/bin/env python3
"""autostream_settings_schema.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Declarative settings schema table -- single source of truth for a field's
identity (section/key), type/bounds/enum shape, and which of the existing
per-field write paths' callables apply to it.

This is a **consolidation**, not a rewrite: this module holds no validation
logic of its own. Every `validate`/`live_fn`/`normalise`/`form_coerce`
callable a row carries is the exact same function object the pre-migration
code already called -- unchanged bounds, unchanged error messages, unchanged
edge-case handling. The four existing dispatch paths (POST /api/settings,
POST /api/service/config, POST /api/output_eq/config, POST /setup) each keep
owning their validator/normaliser functions in the module they always lived
in; this module is purely the shared registry those four modules populate
one row at a time, at their own import time, replacing what used to be four
separate dicts (`_SETTINGS_FIELDS`, `_SERVICE_FIELD_MAP`, the EQ module's
inline field handling, and `handle_setup_post`'s ad hoc per-field parsing).

Scope note -- what this module deliberately does NOT do:
  - It does not implement `SettingsStore.set()`/`SetOutcome`; those live in
    `autostream_settings.py`. Nothing here dispatches on `live_class`; it is
    carried on each row purely as documentation of how that field's
    live-push already happens at its existing call site(s), for
    `SettingsStore.set()` to consume.
  - It does not enforce "a field with no row cannot be read or written"
    (that is a property of the store, not the table).
    `SETTINGS_SCHEMA.get(path)` / `get_field_spec(path)` simply return
    ``None`` for an unknown path -- callers keep doing (and continue to
    do, unchanged) their own explicit "unknown field" rejection. This is
    the documented "sane" behaviour for this module: a lookup miss is data
    (``None``), not an exception, so each of the four consumers can keep
    translating "unknown" into whatever response shape it already used
    before this migration.

Three more optional slots exist, used by `SettingsStore.set()` and the
cross-field validation it runs:

  - `cross_validate` -- an atomic, commit-time invariant callable, run from
    inside ``SettingsStore.set()``'s mutator (i.e. under the store lock,
    against the raw dict about to be committed): "an atomic, race-safe
    check at commit time". Two rules exist today: cross-input
    capture-device uniqueness and the hostname-visibility cascade -- see
    the bottom of this module. Both ``send_settings_post_json`` and
    ``handle_setup_post`` call the *same* callables (via this table), so
    the setup form and the settings API enforce the same rule.
  - `mutate` -- overrides the default ``raw[section][key] = value`` write
    for the handful of fields whose on-disk shape isn't a flat
    ``section[key]`` assignment (e.g. the turntable flag, which calls
    ``set_input_mode()`` to also derive ``silence_threshold_dbfs``).
  - Wildcard/template rows: a path containing a literal ``"*"`` segment
    (e.g. ``"owntone.offsets.*"``) is a *template* row, matched by
    ``get_field_spec()`` on an exact-path miss -- see ``_split_template`` and
    the matching fallback below. ``section``/``key`` are not used for
    template rows (the caller must derive the concrete on-disk key itself,
    e.g. the output name); ``bounds``/``enum``/`validate` apply uniformly to
    every concrete instance.

Why FieldSpec carries several *different* optional "how do I turn a raw
value into a normalised one" slots (`validate`, `form_coerce`, `normalise`)
instead of one uniform slot: the four dispatch paths this table replaces
receive input in different shapes (typed JSON values vs. raw HTML-form
strings vs. Service-page JSON strings) and, today, enforce different
strictness for the *same* dotted settings path. Concretely: `handle_setup_
post` (the HTML `/setup` form) applies no bounds/enum checking at all for
several fields that `send_settings_post_json` (`POST /api/settings`, JSON)
validates strictly -- e.g. `audio1.gain_db` is plain-cast by the form path
but rejected outside [-10, 10] by the JSON path. This is a known,
pre-existing inconsistency; fixing it is deferred to once a single
`settings.set()` entry point exists to hang one shared rule off.
This migration's job is a byte-for-byte-identical consolidation of where
each path's existing logic *lives*, not a behaviour fix -- so a schema row
for a path touched by two dispatch paths with different strictness
legitimately carries two different callables (one per path) rather than
being forced onto a single `validate` that would silently change one
path's behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, FrozenSet, Optional, Tuple


class CrossFieldValidationError(ValueError):
    """Raised by a ``FieldSpec.cross_validate`` callable to atomically reject
    a write from inside ``SettingsStore.set()``'s mutator. A ``ValueError``
    subclass so existing call sites that already catch ``ValueError`` for
    validation failures keep working unchanged.
    """


# -----------------------------------------------------------------------------
# LiveClass / FieldSpec
# -----------------------------------------------------------------------------

class LiveClass(Enum):
    """How a field's write is expected to reach running state. Informational
    only in this module -- nothing here dispatches on it; each existing call
    site still decides for itself (via its own `live_fn`/inline code) whether
    and how to push a value live. Carried on each row so `SettingsStore.set()`
    has the classification already recorded rather than needing to re-derive
    it.
    """

    LIVE = "live"
    RELOAD = "reload"
    PASSIVE = "passive"


@dataclass
class FieldSpec:
    """One row of the settings schema table.

    Not every field populates every slot -- which slots are used depends on
    which of the four existing dispatch paths (or how many of them) touch
    this path today; see the module docstring for why that is legitimate
    rather than an inconsistency to paper over.

    Attributes:
      path:        Dotted settings path (``"audio1.gain_db"``), or, for the
                   Service-page maintenance fields and the /setup form's
                   sentinel-only fields, the flat field name already used
                   there (``"service_stylus_life_hours_input1"``) -- both
                   are just string keys into ``SETTINGS_SCHEMA``.
      section/key: On-disk config location, ``cfg[section][key]``.
      type:        Declared native Python type (``bool | int | float | str``),
                   informational/for characterisation tests; not itself
                   enforced by this module.
      default:     Declared default value, informational (existing load-path
                   defaulting in ``autostream_config.py`` is untouched by
                   this migration).
      bounds:      ``(min, max)`` for numeric fields, or ``None``.
      enum:        Allowed-value set for enumerated fields, or ``None``.
      live_class:  See ``LiveClass`` -- informational only, see above.
      validate:    ``Callable[[object], object]`` -- the JSON-settings-API
                   style validator: receives an already-typed value (e.g.
                   from a parsed JSON body), returns the normalised value,
                   raises ``ValueError`` with the existing message on
                   rejection. Used by ``send_settings_post_json`` (group 1)
                   and, for the output-EQ bands, by ``apply_eq_field``
                   (group 3).
      live_fn:     ``Callable[[state, value], bool]`` -- the existing
                   per-field live-push side effect used by
                   ``send_settings_post_json``. Defined in
                   ``autostream_webui_api`` (these closures depend on
                   handler-layer globals that would create an import cycle
                   if defined in this module) and passed in when the row is
                   registered.
      form_coerce: ``Callable[[str], object]`` -- the ``/setup`` HTML-form
                   style coercion: receives the raw string already extracted
                   from the submitted form (via ``fld(...)``), returns the
                   normalised value, exactly reproducing what
                   ``handle_setup_post`` did inline before this migration
                   (deliberately including the absence of bounds checking
                   where none existed -- see module docstring).
      normalise:   ``Callable[[str], object]`` -- the Service-page
                   maintenance-threshold style normaliser: receives the raw
                   string value from the JSON body, returns the normalised
                   value, raises on rejection. Used by
                   ``send_service_config_json`` (group 2).
    """

    path: str
    section: Optional[str] = None
    key: Optional[str] = None
    type: Optional[type] = None
    default: object = None
    bounds: Optional[Tuple[float, float]] = None
    enum: Optional[FrozenSet[object]] = None
    live_class: LiveClass = LiveClass.PASSIVE
    validate: Optional[Callable[[object], object]] = None
    live_fn: Optional[Callable[..., bool]] = None
    form_coerce: Optional[Callable[[object], object]] = None
    normalise: Optional[Callable[[str], object]] = None
    cross_validate: Optional[Callable[[dict, str, str, object], None]] = None
    mutate: Optional[Callable[[dict, str, str, object], None]] = None
    store: str = "settings"  # "settings" | "runtime_state"


# The shared table. Populated by autostream_webui_api (POST /api/settings,
# POST /api/service/config), autostream_appliance_models (POST
# /api/output_eq/config), and autostream_webui_post_handlers (POST /setup)
# at their own import time / call time -- see each module's own
# "settings-schema registration" section.
SETTINGS_SCHEMA: dict[str, FieldSpec] = {}


def register_field(
    path: str,
    section: Optional[str] = None,
    key: Optional[str] = None,
    validate: Optional[Callable[[object], object]] = None,
    *,
    live: Optional[Callable[..., bool]] = None,
    form_coerce: Optional[Callable[[object], object]] = None,
    normalise: Optional[Callable[[str], object]] = None,
    type: Optional[type] = None,
    bounds: Optional[Tuple[float, float]] = None,
    enum: Optional[FrozenSet[object]] = None,
    default: object = None,
    live_class: LiveClass = LiveClass.PASSIVE,
    cross_validate: Optional[Callable[[dict, str, str, object], None]] = None,
    mutate: Optional[Callable[[dict, str, str, object], None]] = None,
    store: str = "settings",
) -> FieldSpec:
    """Add (or replace) one row in SETTINGS_SCHEMA. Returns the FieldSpec so
    a caller that needs the object back (e.g. to keep a local reference) can
    use it directly instead of re-looking it up.
    """
    if store == "runtime_state" and live_class != LiveClass.PASSIVE:
        # RuntimeStateStore only ever holds PASSIVE fields; a misclassified
        # row must fail fast at registration time, not silently in
        # production.
        raise ValueError(
            f"{path!r}: runtime_state rows must be PASSIVE (got {live_class!r})"
        )
    spec = FieldSpec(
        path=path, section=section, key=key, type=type, default=default,
        bounds=bounds, enum=enum, live_class=live_class,
        validate=validate, live_fn=live, form_coerce=form_coerce, normalise=normalise,
        cross_validate=cross_validate, mutate=mutate, store=store,
    )
    SETTINGS_SCHEMA[path] = spec
    return spec


def get_field_spec(path: str) -> Optional[FieldSpec]:
    """Look up one row by path.

    Exact match first; on a miss, wildcard/template rows are checked
    (a registered path such as ``"owntone.offsets.*"`` matches any concrete
    path sharing its literal prefix/suffix, e.g. ``"owntone.offsets.abc123"``).
    Returns ``None`` for a path matching neither -- see module docstring for
    why that (rather than raising) is this module's documented "sane"
    behaviour for an unknown-path lookup.
    """
    spec = SETTINGS_SCHEMA.get(path)
    if spec is not None:
        return spec
    for template_path, template_spec in SETTINGS_SCHEMA.items():
        if "*" not in template_path:
            continue
        prefix, _, suffix = template_path.partition("*")
        if path.startswith(prefix) and path.endswith(suffix) and len(path) >= len(prefix) + len(suffix):
            return template_spec
    return None


def template_leaf(template_path: str, concrete_path: str) -> Optional[str]:
    """Return the wildcard segment *concrete_path* matched against
    *template_path* (e.g. ``template_leaf("owntone.offsets.*",
    "owntone.offsets.abc123") == "abc123"``), or ``None`` if *template_path*
    carries no ``"*"`` or *concrete_path* doesn't actually match it. Used by
    ``SettingsStore.set()`` to know which key inside the row's
    ``section``/``key`` container a template row's concrete write belongs
    under.
    """
    if "*" not in template_path:
        return None
    prefix, _, suffix = template_path.partition("*")
    if not (concrete_path.startswith(prefix) and concrete_path.endswith(suffix)):
        return None
    leaf = concrete_path[len(prefix): len(concrete_path) - len(suffix)]
    return leaf or None


# -----------------------------------------------------------------------------
# Cross-field invariants, schema-declared so both POST /api/settings and
# POST /setup enforce the same rule. Bodies are the exact logic that
# previously lived inline, once each, in send_settings_post_json's mutator
# (the duplicate-device authoritative check, the hostname-visibility
# cascade) -- relocating them here so both write paths call the one
# function does not change either rule's behaviour on the path that
# already enforced it. handle_setup_post did NOT previously call the
# duplicate-device check at all: routing it through this same callable is
# a deliberate behaviour fix, not a silent side effect -- see
# autostream_webui_post_handlers.py's own call site for the flash-error path
# this now takes.
# -----------------------------------------------------------------------------

def cross_validate_capture_device_unique(raw: dict, section: str, key: str, value: object) -> None:
    """Reject *value* if the other audio input already has this same capture
    device assigned. Runs against *raw*, the in-progress copy about to be
    committed, so it is atomic under whichever lock the caller holds while
    mutating that copy (SettingsStore._lock for the JSON API, CONFIG_IO_LOCK
    for the setup form).
    """
    normalized = str(value or "").strip()
    if not normalized:
        return
    other_section = "audio2" if section == "audio1" else "audio1"
    other_value = str((raw.get(other_section) or {}).get("capture_device") or "").strip()
    if other_value == normalized:
        raise CrossFieldValidationError(
            "That device is already assigned to the other input; choose a different device or reassign it first"
        )


def cross_validate_hostname_visibility_cascade(raw: dict, section: str, key: str, value: object) -> None:
    """Turning off 'show hostname on home' also forces 'control other
    appliances' off (one-directional: turning hostname visibility back on
    does not re-enable the dependent flag).
    """
    if not value:
        raw.setdefault("webui", {})["control_other_appliances"] = False
