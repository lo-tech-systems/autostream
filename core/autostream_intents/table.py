"""autostream_intents.table -- the intent table, its bindings and submit().

Every request to change state names a row here. submit() validates the
arguments against the row, checks the origin and the row's rate limit, calls
the handler bound to the row on the calling thread, and logs one line.
Handlers live in the modules that implement them and bind themselves at
import; this module holds data and the path, not behaviour.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Mapping, Optional

import autostream_pin_pairing as pairing
from autostream_state import Origin, store
from autostream_state.freeze import deep_freeze

from . import validate as v

LOG = logging.getLogger("autostream.intents")


class IntentNotBound(RuntimeError):
    """A row was submitted but no module has bound a handler to it."""


class HandlerTaken(RuntimeError):
    """A second owner tried to bind a row that another module already handles."""


@dataclass(frozen=True)
class Intent:
    name: str  # "outputs.set", "volume.step", ...
    args: Mapping  # validated against the row; frozen by submit
    origin: Origin
    requester: str  # "webui", "dial:<uuid>", "peer:<id>", "coordinator"
    # Route-local objects a handler needs. Never validated, never logged,
    # never kept.
    context: object = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class Reply:
    ok: bool
    error: Optional[str]  # the name the route already answers with
    version: int  # store version that shows the change
    boot: str
    result: Mapping  # intent-specific; the routes shape their replies from it


@dataclass(frozen=True)
class RateLimit:
    min_interval_s: float
    error: str = "rate_limited"
    applies: Callable[[Mapping], bool] = lambda args: True


@dataclass(frozen=True)
class Row:
    name: str
    args: Mapping[str, v.Validator]  # every allowed argument
    required: frozenset
    origins: frozenset  # ADOPTED and BACKEND never appear
    wait: float = 0.0  # default bound on a backend outcome, seconds
    limit: Optional[RateLimit] = None  # appliance-wide, one timestamp per row


@dataclass(frozen=True)
class Outcome:
    """What a handler returns."""

    ok: bool
    error: Optional[str] = None
    version: Optional[int] = None  # None: the store version after the call
    result: Mapping = field(default_factory=dict)


Handler = Callable[[Intent, float], Outcome]

_BAD_BODY = "invalid_request_body"
_PIN = v.text(error="invalid_pin", max_len=16, pattern=pairing.PIN_RE)
_MAX_REPEAT_POSITION_S = 1e7
_EQ_DB = v.number(-10, 10, error="EQ gain must be between -10 and 10 dB")


def _row(name, args, required, origins, wait=0.0, limit=None) -> Row:
    return Row(name, args, frozenset(required), frozenset(origins), wait, limit)


def _output_fields() -> dict:
    return {
        # Echoed in a PIN prompt's reply; never used to find the speaker.
        "name": v.optional(v.text(error=_BAD_BODY, max_len=256, allow_empty=True)),
        "volume": v.optional(v.integer(0, 100, error=_BAD_BODY, clamp=True)),
        "offset_ms": v.optional(v.integer(-2000, 2000, error=_BAD_BODY, clamp=True)),
        "mode": v.optional(v.text(error=_BAD_BODY, max_len=64)),
    }


def _build_rows() -> dict:
    rows = [
        _row(
            "outputs.set",
            {
                "id": v.text(error="missing_output_id", max_len=64),
                "selected": v.boolean(error=_BAD_BODY),
                **_output_fields(),
            },
            {"id", "selected"},
            {Origin.USER, Origin.SYSTEM},
            wait=3.0,
        ),
        _row(
            "output.pin.submit",
            {
                "id": v.text(error="missing_output_id", max_len=64),
                "pin": _PIN,
                "selected": v.optional(v.boolean(error=_BAD_BODY)),
                **_output_fields(),
            },
            {"id", "pin"},
            {Origin.USER},
            wait=3.0,
        ),
        _row(
            "outputs.select_default",
            {
                "name": v.text(error=_BAD_BODY, allow_empty=True),
                "volume": v.integer(0, 100, error=_BAD_BODY),
                "offset_ms": v.optional(v.integer(-2000, 2000, error=_BAD_BODY, clamp=True)),
                "mode": v.optional(v.text(error=_BAD_BODY, max_len=64)),
            },
            {"name", "volume"},
            {Origin.SESSION},
        ),
        _row("outputs.deselect_all", {}, (), {Origin.SESSION, Origin.USER, Origin.POLICY}),
        _row("receiver.pause", {"id": v.text(error="missing_output_id", max_len=32)}, {"id"}, {Origin.DEVICE}),
        _row("receiver.play", {"id": v.text(error="missing_output_id", max_len=32)}, {"id"}, {Origin.DEVICE}),
        _row("outputs.pause_off", {"id": v.text(error="missing_output_id", max_len=64)}, {"id"}, {Origin.POLICY}),
        _row(
            "volume.step",
            {
                "delta": v.integer(-100, 100, error="invalid_delta", clamp=True),
                "default_level": v.integer(0, 100, error=_BAD_BODY),
            },
            {"delta", "default_level"},
            {Origin.USER},
            wait=3.0,
        ),
        _row(
            "mute.set",
            {
                "action": v.choice("mute", "restore", error="invalid_action"),
                "default_level": v.integer(0, 100, error=_BAD_BODY),
            },
            {"action", "default_level"},
            {Origin.USER},
            wait=3.0,
        ),
        _row(
            "input.eq.set",
            {
                "input": v.choice(1, 2, error="input must be 1 or 2"),
                "eq_40hz_db": _EQ_DB,
                "eq_100hz_db": _EQ_DB,
                "eq_8khz_db": _EQ_DB,
            },
            {"input", "eq_40hz_db", "eq_100hz_db", "eq_8khz_db"},
            {Origin.USER},
        ),
        _row(
            "output.eq.set",
            {"fields": v.pairs(error=_BAD_BODY)},
            {"fields"},
            {Origin.USER},
        ),
        _row("output.eq.reset", {}, (), {Origin.USER}),
        _row(
            "repeat.arm",
            {"armed": v.boolean(error="invalid_armed")},
            {"armed"},
            {Origin.USER, Origin.SYSTEM},
        ),
        _row(
            "repeat.transport",
            {"action": v.choice("stop", error="invalid_action")},
            {"action"},
            {Origin.USER},
        ),
        _row(
            "repeat.seek",
            {"position": v.number(0, _MAX_REPEAT_POSITION_S, error="invalid_position")},
            {"position"},
            {Origin.USER},
            # One seek a second appliance-wide, whoever asks.
            limit=RateLimit(1.0),
        ),
        _row(
            "settings.apply",
            {"changes": v.pairs(error=_BAD_BODY)},
            {"changes"},
            {Origin.USER, Origin.SYSTEM},
        ),
        _row("settings.save", {}, (), {Origin.USER, Origin.SYSTEM}),
        _row(
            "settings.reload",
            {"reason": v.text(error="invalid_reason", max_len=64)},
            {"reason"},
            {Origin.USER, Origin.SYSTEM},
        ),
        _row(
            "settings.form_apply",
            {"steps": v.pairs(error=_BAD_BODY)},
            {"steps"},
            {Origin.USER},
        ),
        _row(
            "settings.advertisement",
            {
                "value": v.boolean(error="value must be a boolean"),
                "version": v.text(error="invalid_version", max_len=64),
                # The Setup form writes the configuration file and, when that
                # fails, puts this preference back.
                "rollback_to": v.optional(v.boolean(error=_BAD_BODY)),
            },
            {"value", "version"},
            {Origin.USER},
        ),
        _row(
            "settings.auto_update",
            {"value": v.boolean(error="value must be a boolean")},
            {"value"},
            {Origin.USER},
        ),
        _row(
            "backend.setting.set",
            {
                "setting": v.choice(
                    "uncompressed_audio", "buffered_audio", "start_buffer_ms", "user_agent",
                    "mdns_grace_period", "output_mode", "output_visibility", "output_offset",
                    "output_include_tv",
                    error="invalid_setting"),
                # Each setting's route has already checked its own value.
                "value": v.anything(),
                "output_id": v.optional(v.text(error="output_id required", max_len=256, allow_empty=True)),
            },
            {"setting", "value"},
            {Origin.USER, Origin.SYSTEM},
        ),
        _row(
            "input.counters.reset",
            {
                "input": v.choice(1, 2, error="Input must be 1 or 2"),
                "item": v.choice("stylus", "belt", "bearing", error="invalid_item"),
            },
            {"input", "item"},
            {Origin.USER},
        ),
        _row(
            "input.playback_config.set",
            {
                "input": v.choice(1, 2, error="Input must be 1 or 2"),
                "enabled": v.boolean(error=_BAD_BODY),
                "is_turntable": v.boolean(error=_BAD_BODY),
                "input_type": v.text(error=_BAD_BODY, max_len=64),
                "is_bluetooth": v.optional(v.boolean(error=_BAD_BODY)),
                # The life values come from the parsed configuration, and the
                # tracker normalises them.
                "stylus_life_hours": v.anything(),
                "belt_life_hours": v.optional(v.anything()),
                "belt_life_years": v.optional(v.anything()),
                "bearing_life_hours": v.optional(v.anything()),
                "bearing_life_years": v.optional(v.anything()),
            },
            {"input", "enabled", "is_turntable", "input_type", "stylus_life_hours"},
            {Origin.USER},
        ),
        _row(
            "log.level.set",
            {
                # The log policy names what it does not support.
                "level": v.anything(),
                "changed_by": v.choice("user", "system", error="Invalid changed_by value"),
            },
            {"level", "changed_by"},
            {Origin.USER, Origin.SYSTEM},
        ),
    ]
    return {row.name: row for row in rows}


ROWS: Mapping[str, Row] = _build_rows()

_NEVER_SUBMITTED = frozenset({Origin.ADOPTED, Origin.BACKEND})


class _Table:
    """The rows, their handlers and the limiter. The module keeps one."""

    def __init__(self, rows: Optional[Mapping[str, Row]] = None) -> None:
        self.rows = ROWS if rows is None else rows
        self._handlers: dict = {}
        self._owners: dict = {}
        self._limit_lock = threading.Lock()  # a leaf: a compare and a store
        self._last: dict = {}
        self._clock: Callable[[], float] = time.monotonic
        self._dirty = False

    def bind(self, name: str, handler: Handler, *, owner: str) -> None:
        if name not in self.rows:
            raise ValueError(f"no intent row named {name!r}")
        held = self._owners.get(name)
        if held is not None and held != owner:
            raise HandlerTaken(f"{name} is handled by {held}")
        self._owners[name] = owner
        self._handlers[name] = handler

    def set_clock_for_tests(self, clock: Callable[[], float]) -> None:
        self._clock = clock
        self._dirty = True

    def reset_for_tests(self) -> None:
        """Forget the limiter's timestamps and restore the clock. Bindings stay.
        Returns at once when nothing was touched."""
        if not self._dirty:
            return
        with self._limit_lock:
            self._last.clear()
        self._clock = time.monotonic
        self._dirty = False

    # ------------------------------------------------------------- submit

    def submit(self, intent: Intent, *, wait: Optional[float] = None) -> Reply:
        row = self.rows.get(intent.name)
        if row is None:
            return self._refuse(intent, "unknown_intent")
        if intent.origin in _NEVER_SUBMITTED or intent.origin not in row.origins:
            return self._refuse(intent, "origin_not_allowed")

        checked = self._check_args(row, intent.args)
        if isinstance(checked, str):
            return self._refuse(intent, checked)
        try:
            frozen_args = deep_freeze(checked)
        except TypeError:
            # A value that passes through a row unchecked ("anything") may be
            # of a type that cannot be frozen.
            return self._refuse(intent, "invalid_args")
        frozen = Intent(
            name=intent.name,
            args=frozen_args,
            origin=intent.origin,
            requester=intent.requester,
            context=intent.context,
        )

        refusal = self._take_limit(row, frozen.args)
        if refusal is not None:
            return self._refuse(intent, refusal)

        handler = self._handlers.get(row.name)
        if handler is None:
            raise IntentNotBound(row.name)

        bound = row.wait if wait is None else float(wait)
        try:
            outcome = handler(frozen, bound)
            if not isinstance(outcome, Outcome):
                raise TypeError(f"handler for {row.name} returned {type(outcome).__name__}")
        except Exception:
            LOG.exception("intent %s: handler failed", row.name)
            outcome = Outcome(ok=False, error="internal_error")

        snap = store().snapshot()
        reply = Reply(
            ok=outcome.ok,
            error=outcome.error,
            version=snap.version if outcome.version is None else outcome.version,
            boot=snap.boot,
            result=outcome.result,
        )
        self._log(intent, reply)
        return reply

    def _check_args(self, row: Row, args: object):
        """The validated arguments as a dict, or the error name."""
        if not isinstance(args, Mapping):
            return "invalid_args"
        if any(key not in row.args for key in args) or not row.required <= set(args):
            return "invalid_args"
        out = {}
        for key, validator in row.args.items():
            if key not in args:
                continue
            try:
                out[key] = validator(args[key])
            except v.Invalid as exc:
                return exc.error
        return out

    def _take_limit(self, row: Row, args: Mapping) -> Optional[str]:
        limit = row.limit
        if limit is None or not limit.applies(args):
            return None
        with self._limit_lock:
            now = self._clock()
            last = self._last.get(row.name)
            if last is not None and now - last < limit.min_interval_s:
                return limit.error
            self._last[row.name] = now
            self._dirty = True
        return None

    def _refuse(self, intent: Intent, error: str) -> Reply:
        snap = store().snapshot()
        reply = Reply(ok=False, error=error, version=snap.version, boot=snap.boot, result={})
        self._log(intent, reply)
        return reply

    def _log(self, intent: Intent, reply: Reply) -> None:
        origin = getattr(intent.origin, "value", intent.origin)
        LOG.log(
            logging.DEBUG if reply.ok else logging.INFO,
            "intent %s origin=%s requester=%s result=%s version=%d",
            intent.name,
            origin,
            intent.requester,
            "ok" if reply.ok else reply.error,
            reply.version,
        )


_table = _Table()


def bind(name: str, handler: Handler, *, owner: str) -> None:
    """Bind *handler* to row *name*. The same owner may rebind; another raises HandlerTaken."""
    _table.bind(name, handler, owner=owner)


def submit(intent: Intent, *, wait: Optional[float] = None) -> Reply:
    """Validate, check the origin and the limit, call the bound handler on
    this thread, log one line, reply. wait=None takes the row's default.
    No lock is held while the handler runs."""
    return _table.submit(intent, wait=wait)


def set_clock_for_tests(clock: Callable[[], float]) -> None:
    _table.set_clock_for_tests(clock)


def reset_for_tests() -> None:
    _table.reset_for_tests()
