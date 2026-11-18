"""autostream_monitor_control -- live commands to the audio monitor daemon.

Each function here opens a short-lived connection to autostream_monitor, sends
one command and returns the daemon's answer, so a request thread never
depends on the coordinator's own persistent connection. The repeat commands
(arm, stop, seek) are also rows of the intent table, bound at import: a
browser, a dial or a peer submits the intent and the handler here sends the
command, folds the daemon's ack into the published repeat block and tells
subscribers who asked.

The equaliser and gain values the daemon acknowledges are published as the
"eq" part of the state snapshot, after the connection to the daemon has been
closed, so a subscriber never runs while the monitor client's own lock is held.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging
from dataclasses import replace
from typing import Optional

import autostream_eq_bands as eq_bands
import autostream_monitor_client as monitor_client
import autostream_repeat
import autostream_runtime as runtime
import autostream_state
from autostream_config import CONFIG_IO_LOCK, OutputEqConfig, load_config, parse_config, save_config
from autostream_intents.table import Intent, Outcome, bind
from autostream_settings_schema import register_field

_OWNER = "autostream_monitor_control"

_eq_writer = autostream_state.store().claim("eq", _OWNER)


def set_live_repeat_enabled(
    enabled: bool,
    codec: str,
    target_minutes: Optional[int] = None,
    socket_path: Optional[str] = None,
) -> bool:
    """Push the global repeat enable/codec/target-duration policy immediately
    to autostream_monitor.

    Live setter -- must NOT trigger a coordinator reload; this
    persists no state of its own and is safe to call at any time.
    target_minutes is the target-duration goal; None means "leave whatever
    the daemon already has" (MonitorClient.set_repeat_enabled's own default
    sentinel).
    """
    with monitor_client._connected_monitor(socket_path) as client:
        if client is None:
            return False
        return client.set_repeat_enabled(bool(enabled), str(codec), target_minutes)


def set_live_repeat_armed_ack(
    armed: bool,
    socket_path: Optional[str] = None,
    *,
    requester: Optional[str] = None,
) -> Optional[dict]:
    """Arm/disarm repeat replay immediately on autostream_monitor and return
    the parsed daemon ack (None when the daemon is unreachable).

    Session arm is runtime-only: no settings write accompanies
    this call. Disarming during replay triggers the daemon's fade-out.
    *requester* names who asked, for the change this publishes.
    """
    with monitor_client._connected_monitor(socket_path) as client:
        if client is None:
            return None
        ack = client.set_repeat_armed_ack(bool(armed))
    return autostream_repeat.apply_repeat_ack(ack, requester=requester)


def set_live_repeat_armed(
    armed: bool,
    socket_path: Optional[str] = None,
) -> bool:
    """Arm/disarm repeat replay immediately on autostream_monitor.

    Session arm is runtime-only: no settings write accompanies
    this call. Disarming during replay triggers the daemon's fade-out.
    """
    ack = set_live_repeat_armed_ack(armed, socket_path)
    return bool(ack and ack.get("ok"))


def send_live_repeat_transport(
    action: str,
    position_seconds: float = 0.0,
    socket_path: Optional[str] = None,
    *,
    requester: Optional[str] = None,
) -> Optional[dict]:
    """Send a repeat-replay transport command ("stop" or "seek") to
    autostream_monitor and return the parsed daemon ack (None when the
    daemon is unreachable). *requester* names who asked, for the change this
    publishes."""
    with monitor_client._connected_monitor(socket_path) as client:
        if client is None:
            return None
        if action == "stop":
            ack = client.repeat_stop()
        else:
            ack = client.repeat_seek(position_seconds)
    return autostream_repeat.apply_repeat_ack(ack, requester=requester)


# ---------------------------------------------------------------------------
# Equaliser and gain
# ---------------------------------------------------------------------------

def _publish_input_bands(index: int, bands: tuple) -> None:
    _eq_writer.update(
        lambda cur: replace(cur, input_bands={**cur.input_bands, int(index): bands})).notify()


def _publish_input_gain(index: int, gain_db: float) -> None:
    _eq_writer.update(
        lambda cur: replace(cur, input_gain={**cur.input_gain, int(index): gain_db})).notify()


def _publish_output_bands(bands: tuple, requester: Optional[str] = None) -> None:
    _eq_writer.update(lambda cur: replace(cur, output_bands=bands), requester=requester).notify()


def _publish_output_gain(gain_db: float, requester: Optional[str] = None) -> None:
    _eq_writer.update(lambda cur: replace(cur, output_gain_db=gain_db), requester=requester).notify()


def _publish_auto_trim(enabled: bool, requester: Optional[str] = None) -> None:
    _eq_writer.update(lambda cur: replace(cur, auto_trim_enabled=enabled), requester=requester).notify()


def _input_bands(eq_40hz_db: float, eq_100hz_db: float, eq_8khz_db: float) -> tuple:
    return (float(eq_40hz_db), float(eq_100hz_db), float(eq_8khz_db))


def _output_bands(peq1_db, peq2_db, peq3_db, peq4_db, peq5_db, peq6_db) -> tuple:
    return tuple(float(v) for v in (peq1_db, peq2_db, peq3_db, peq4_db, peq5_db, peq6_db))


def _send_input_eq(client, input_index, eq_40hz_db, eq_100hz_db, eq_8khz_db) -> bool:
    return client.set_eq(
        input_index,
        eq_bands.build_monitor_eq_bands(eq_40hz_db, eq_100hz_db, eq_8khz_db),
    )


def _send_output_eq(client, peq1_db, peq2_db, peq3_db, peq4_db, peq5_db, peq6_db) -> bool:
    return client.set_output_eq(
        eq_bands.build_output_eq_bands(peq1_db, peq2_db, peq3_db, peq4_db, peq5_db, peq6_db)
    )


def apply_input_eq(
    client: "monitor_client.MonitorClient",
    input_index: int,
    eq_40hz_db: float,
    eq_100hz_db: float,
    eq_8khz_db: float,
) -> bool:
    """Push one input's EQ settings to autostream_monitor; published when acked."""
    ok = _send_input_eq(client, input_index, eq_40hz_db, eq_100hz_db, eq_8khz_db)
    if ok:
        _publish_input_bands(input_index, _input_bands(eq_40hz_db, eq_100hz_db, eq_8khz_db))
    return ok


def apply_input_gain(
    client: "monitor_client.MonitorClient",
    input_index: int,
    gain_db: float,
) -> bool:
    """Push one input's gain setting to autostream_monitor; published when acked."""
    ok = client.set_gain(input_index, float(gain_db))
    if ok:
        _publish_input_gain(input_index, float(gain_db))
    return ok


def set_live_input_eq(
    input_index: int,
    eq_40hz_db: float,
    eq_100hz_db: float,
    eq_8khz_db: float,
    socket_path: Optional[str] = None,
) -> bool:
    """Apply one input's EQ immediately to the running autostream_monitor.

    Uses a short-lived monitor connection so the Web UI can update EQ live
    without depending on the coordinator loop's persistent client.
    Also updates any matching in-process AudioMonitor cache so reconnect replay
    continues to use the most recent live values until the INI is saved.
    """
    with monitor_client._connected_monitor(socket_path) as client:
        if client is None:
            return False
        ok = _send_input_eq(client, input_index, eq_40hz_db, eq_100hz_db, eq_8khz_db)
    if ok:
        with runtime._monitors_lock:
            for mon in runtime.all_monitors:
                if mon.input_index == input_index:
                    mon.eq_40hz_db = float(eq_40hz_db)
                    mon.eq_100hz_db = float(eq_100hz_db)
                    mon.eq_8khz_db = float(eq_8khz_db)
        _publish_input_bands(input_index, _input_bands(eq_40hz_db, eq_100hz_db, eq_8khz_db))
    return ok


def set_live_input_gain(
    input_index: int,
    gain_db: float,
    socket_path: Optional[str] = None,
) -> bool:
    """Apply one input's gain immediately to the running autostream_monitor."""
    with monitor_client._connected_monitor(socket_path) as client:
        if client is None:
            return False
        ok = client.set_gain(input_index, float(gain_db))
    if ok:
        with runtime._monitors_lock:
            for mon in runtime.all_monitors:
                if mon.input_index == input_index:
                    mon.gain_db = float(gain_db)
        _publish_input_gain(input_index, float(gain_db))
    return ok


def apply_output_eq(
    client: "monitor_client.MonitorClient",
    peq1_db: float,
    peq2_db: float,
    peq3_db: float,
    peq4_db: float,
    peq5_db: float,
    peq6_db: float,
) -> bool:
    """Push shared output EQ bands to autostream_monitor; published when acked."""
    ok = _send_output_eq(client, peq1_db, peq2_db, peq3_db, peq4_db, peq5_db, peq6_db)
    if ok:
        _publish_output_bands(_output_bands(peq1_db, peq2_db, peq3_db, peq4_db, peq5_db, peq6_db))
    return ok


def apply_output_gain(client: "monitor_client.MonitorClient", gain_db: float) -> bool:
    """Push shared output gain to autostream_monitor; published when acked."""
    ok = client.set_output_gain(float(gain_db))
    if ok:
        _publish_output_gain(float(gain_db))
    return ok


def apply_output_auto_trim(client: "monitor_client.MonitorClient", enabled: bool) -> bool:
    """Push shared output auto-trim enable state to autostream_monitor; published when acked."""
    ok = client.set_output_auto_trim(bool(enabled))
    if ok:
        _publish_auto_trim(bool(enabled))
    return ok


def _apply_output_eq_config(
    client: "monitor_client.MonitorClient",
    output_eq: OutputEqConfig,
) -> bool:
    """Push all persisted [output_eq] settings to the running monitor daemon.

    Applies gain, EQ bands, and auto-trim in one call.  Used during both
    initial startup and reconnect resync so the daemon always reflects the INI.
    """
    if not apply_output_gain(client, output_eq.gain_db):
        return False
    if not apply_output_eq(
        client,
        output_eq.peq1_db,
        output_eq.peq2_db,
        output_eq.peq3_db,
        output_eq.peq4_db,
        output_eq.peq5_db,
        output_eq.peq6_db,
    ):
        return False
    if not apply_output_auto_trim(client, output_eq.auto_trim_enabled):
        return False
    return True


def set_live_output_eq(
    peq1_db: float,
    peq2_db: float,
    peq3_db: float,
    peq4_db: float,
    peq5_db: float,
    peq6_db: float,
    socket_path: Optional[str] = None,
    *,
    requester: Optional[str] = None,
) -> bool:
    """Apply shared output EQ immediately to the running autostream_monitor.
    *requester* names who asked, for the change this publishes."""
    with monitor_client._connected_monitor(socket_path) as client:
        if client is None:
            return False
        ok = _send_output_eq(client, peq1_db, peq2_db, peq3_db, peq4_db, peq5_db, peq6_db)
    if ok:
        _publish_output_bands(
            _output_bands(peq1_db, peq2_db, peq3_db, peq4_db, peq5_db, peq6_db), requester)
    return ok


def set_live_output_gain(
    gain_db: float,
    socket_path: Optional[str] = None,
    *,
    requester: Optional[str] = None,
) -> bool:
    """Apply shared output gain immediately to the running autostream_monitor."""
    with monitor_client._connected_monitor(socket_path) as client:
        if client is None:
            return False
        ok = client.set_output_gain(float(gain_db))
    if ok:
        _publish_output_gain(float(gain_db), requester)
    return ok


def set_live_output_auto_trim(
    enabled: bool,
    socket_path: Optional[str] = None,
    *,
    requester: Optional[str] = None,
) -> bool:
    """Apply shared output auto-trim enable state immediately to the running monitor."""
    with monitor_client._connected_monitor(socket_path) as client:
        if client is None:
            return False
        ok = client.set_output_auto_trim(bool(enabled))
    if ok:
        _publish_auto_trim(bool(enabled), requester)
    return ok


# ---------------------------------------------------------------------------
# Output equaliser changes: saved, then applied to the daemon
# ---------------------------------------------------------------------------

_OUTPUT_EQ_DB_FIELDS = frozenset({
    "gain_db", "peq1_db", "peq2_db", "peq3_db", "peq4_db", "peq5_db", "peq6_db",
})
_OUTPUT_EQ_BAND_FIELDS = frozenset({
    "peq1_db", "peq2_db", "peq3_db", "peq4_db", "peq5_db", "peq6_db",
})
_OUTPUT_EQ_BOOL_FIELDS = frozenset({"auto_trim_enabled"})
_OUTPUT_EQ_ALL_FIELDS = _OUTPUT_EQ_DB_FIELDS | _OUTPUT_EQ_BOOL_FIELDS


def _clamp_output_eq_db(value_raw: object) -> float:
    """Coerce+clamp one output_eq dB-valued field: non-numeric input raises
    "Value must be numeric"; any numeric input is silently clamped to
    [OUTPUT_EQ_DB_MIN, OUTPUT_EQ_DB_MAX] rather than rejected.
    """
    try:
        value = float(value_raw)
    except ValueError:
        raise ValueError("Value must be numeric")
    return max(eq_bands.OUTPUT_EQ_DB_MIN, min(eq_bands.OUTPUT_EQ_DB_MAX, value))


def _normalize_output_eq_bool(value_raw: object) -> bool:
    """Coerce one output_eq bool-valued field (currently just
    auto_trim_enabled): "true", "1" or "yes", in any case.
    """
    return value_raw.lower() in ("true", "1", "yes")


for _eq_field in _OUTPUT_EQ_DB_FIELDS:
    register_field(f"output_eq.{_eq_field}", "output_eq", _eq_field, _clamp_output_eq_db)
for _eq_field in _OUTPUT_EQ_BOOL_FIELDS:
    register_field(f"output_eq.{_eq_field}", "output_eq", _eq_field, _normalize_output_eq_bool)


def apply_eq_field(
    config_path: str,
    field: str,
    value_raw: str,
    *,
    settings=None,
    requester: Optional[str] = None,
) -> tuple[bool, str, str]:
    """Save and apply one output EQ field.

    Returns (ok, normalised_str, error_message).
    Raises ValueError for unknown fields or non-numeric dB values.

    When *settings* is a SettingsStore instance, it is used as the sole
    persistence mechanism (store -> background disk write). The config_path
    is only used as a fallback when no store is available.

    Dials are told when a band changes (the eq part moves); they show the
    bands, not the output gain or auto-trim. *requester* names who asked, so
    that dial is left out of the hint.
    """
    from autostream_settings import SettingsStore as _SettingsStore
    _store = settings if isinstance(settings, _SettingsStore) else None

    if field not in _OUTPUT_EQ_ALL_FIELDS:
        raise ValueError(f"Unknown field: {field!r}")

    from autostream_settings_schema import SETTINGS_SCHEMA
    _spec = SETTINGS_SCHEMA[f"output_eq.{field}"]

    if field in _OUTPUT_EQ_BOOL_FIELDS:
        normalised_bool = _spec.validate(value_raw)
        normalised_str = "true" if normalised_bool else "false"
        try:
            if _store is not None:
                _store.update(lambda raw: raw.setdefault("output_eq", {}).update({field: normalised_bool}))
            else:
                with CONFIG_IO_LOCK:
                    cfg = load_config(config_path)
                    cfg.setdefault("output_eq", {})[field] = normalised_bool
                    save_config(config_path, cfg)
            set_live_output_auto_trim(normalised_bool, requester=requester)
        except Exception as e:
            logging.exception("apply_eq_field: save failed")
            return False, normalised_str, str(e)
        return True, normalised_str, ""

    value = _spec.validate(value_raw)
    normalised_str = f"{value:.1f}"

    try:
        if _store is not None:
            pre_snap = _store.snapshot()
            _store.update(lambda raw: raw.setdefault("output_eq", {}).update({field: value}))
            oeq = pre_snap.output_eq
        else:
            with CONFIG_IO_LOCK:
                cfg = load_config(config_path)
                p = parse_config(cfg)
                cfg.setdefault("output_eq", {})[field] = value
                save_config(config_path, cfg)
            oeq = p.output_eq

        if field == "gain_db":
            set_live_output_gain(value, requester=requester)
        else:
            band_vals = {b: float(getattr(oeq, b)) for b in _OUTPUT_EQ_BAND_FIELDS}
            band_vals[field] = value
            set_live_output_eq(
                band_vals["peq1_db"],
                band_vals["peq2_db"],
                band_vals["peq3_db"],
                band_vals["peq4_db"],
                band_vals["peq5_db"],
                band_vals["peq6_db"],
                requester=requester,
            )
    except Exception as e:
        logging.exception("apply_eq_field: save failed")
        return False, normalised_str, str(e)

    return True, normalised_str, ""


def apply_eq_fields(
    config_path: str,
    values: dict,
    *,
    settings=None,
    requester: Optional[str] = None,
) -> tuple:
    """Save and apply several output EQ band fields in one update: one store
    write, one live apply of the merged six bands -- unlike calling
    apply_eq_field() once per field, this never re-applies live or re-writes
    the store more than once for a single dial tap that moves two bands at
    once. Each field in *values* is validated through the same schema
    apply_eq_field() uses; a field absent from *values* keeps its currently
    stored value untouched (peq3/peq4 are never in *values* -- the dial never
    writes them).

    When *settings* is a SettingsStore instance, it is used as the sole
    persistence mechanism, same as apply_eq_field().

    Returns (ok, error_message).
    """
    from autostream_settings import SettingsStore as _SettingsStore
    _store = settings if isinstance(settings, _SettingsStore) else None

    from autostream_settings_schema import SETTINGS_SCHEMA
    normalised: dict = {}
    for field, value_raw in values.items():
        if field not in _OUTPUT_EQ_BAND_FIELDS:
            raise ValueError(f"Unknown field: {field!r}")
        normalised[field] = SETTINGS_SCHEMA[f"output_eq.{field}"].validate(value_raw)

    try:
        if _store is not None:
            pre_snap = _store.snapshot()
            _store.update(lambda raw: raw.setdefault("output_eq", {}).update(normalised))
            oeq = pre_snap.output_eq
        else:
            with CONFIG_IO_LOCK:
                cfg = load_config(config_path)
                p = parse_config(cfg)
                cfg.setdefault("output_eq", {}).update(normalised)
                save_config(config_path, cfg)
            oeq = p.output_eq

        band_vals = {b: float(getattr(oeq, b)) for b in _OUTPUT_EQ_BAND_FIELDS}
        band_vals.update(normalised)
        set_live_output_eq(
            band_vals["peq1_db"], band_vals["peq2_db"], band_vals["peq3_db"],
            band_vals["peq4_db"], band_vals["peq5_db"], band_vals["peq6_db"],
            requester=requester,
        )
    except Exception as e:
        logging.exception("apply_eq_fields: save failed")
        return False, str(e)

    return True, ""


def apply_eq_reset(
    config_path: str,
    *,
    settings=None,
    requester: Optional[str] = None,
) -> tuple[bool, str]:
    """Zero all EQ band fields (peq1-peq6). Does not change output gain or auto-trim.

    When *settings* is a SettingsStore instance, uses it for atomic persistence.
    """
    from autostream_settings import SettingsStore as _SettingsStore
    _store = settings if isinstance(settings, _SettingsStore) else None

    try:
        if _store is not None:
            def _zero(raw: dict) -> None:
                eq = raw.setdefault("output_eq", {})
                for f in _OUTPUT_EQ_BAND_FIELDS:
                    eq[f] = 0.0
            _store.update(_zero)
        else:
            with CONFIG_IO_LOCK:
                cfg = load_config(config_path)
                eq = cfg.setdefault("output_eq", {})
                for f in _OUTPUT_EQ_BAND_FIELDS:
                    eq[f] = 0.0
                save_config(config_path, cfg)
        set_live_output_eq(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, requester=requester)
    except Exception as e:
        logging.exception("apply_eq_reset: reset failed")
        return False, str(e)
    return True, ""


# ---------------------------------------------------------------------------
# Intent handlers
# ---------------------------------------------------------------------------

def _ack_outcome(ack: Optional[dict]) -> Outcome:
    """The outcome of a command: ok when the daemon accepted it. The ack
    itself (None when the daemon could not be reached) is in the result for
    the route to map to its reply."""
    accepted = isinstance(ack, dict) and bool(ack.get("ok"))
    error = None
    if not accepted:
        error = ack.get("error") if isinstance(ack, dict) else None
        if not isinstance(error, str) or not error:
            error = "backend_unavailable"
    return Outcome(ok=accepted, error=error, result={"ack": ack})


def _repeat_arm(intent: Intent, wait: float) -> Outcome:
    ack = set_live_repeat_armed_ack(intent.args["armed"], requester=intent.requester)
    return _ack_outcome(ack)


def _repeat_stop(intent: Intent, wait: float) -> Outcome:
    ack = send_live_repeat_transport("stop", requester=intent.requester)
    return _ack_outcome(ack)


def _repeat_seek(intent: Intent, wait: float) -> Outcome:
    ack = send_live_repeat_transport(
        "seek", float(intent.args["position"]), requester=intent.requester)
    return _ack_outcome(ack)


def _input_eq_set(intent: Intent, wait: float) -> Outcome:
    """Store the three bands of one input, then apply them to the running
    daemon. *context* is the request's state, whose settings store is written."""
    from autostream_settings import SettingsStore

    args = intent.args
    index = args["input"]
    bands = {key: float(args[key]) for key in ("eq_40hz_db", "eq_100hz_db", "eq_8khz_db")}
    settings = getattr(intent.context, "settings", None)
    if isinstance(settings, SettingsStore):
        section = f"audio{index}"
        try:
            def _mutate(raw: dict) -> None:
                raw.setdefault(section, {}).update(bands)
            settings.update(_mutate)
        except Exception:
            logging.warning("input.eq.set: store write failed", exc_info=True)
    ok = set_live_input_eq(
        input_index=index,
        eq_40hz_db=bands["eq_40hz_db"],
        eq_100hz_db=bands["eq_100hz_db"],
        eq_8khz_db=bands["eq_8khz_db"],
    )
    return Outcome(ok=ok, error=None if ok else "Could not update live EQ")


def _output_eq_set(intent: Intent, wait: float) -> Outcome:
    """Save and apply output equaliser fields. One field is the Equaliser
    page's (or a peer's) request, its value a string; several are a dial's
    band write, applied together. *context* is the request's state."""
    state = intent.context
    settings = getattr(state, "settings", None)
    config_path = getattr(state, "config_path", None)
    fields = intent.args["fields"]
    try:
        if len(fields) == 1:
            field, value_raw = fields[0]
            ok, normalised, error = apply_eq_field(
                config_path, field, value_raw, settings=settings, requester=intent.requester)
            return Outcome(ok=ok, error=error or None,
                           result={"ok": ok, "field": field, "value": normalised, "error": error})
        ok, error = apply_eq_fields(
            config_path, dict(fields), settings=settings, requester=intent.requester)
    except ValueError as exc:
        return Outcome(ok=False, error=str(exc), result={"invalid": str(exc)})
    return Outcome(ok=ok, error=error or None, result={"ok": ok, "error": error})


def _output_eq_reset(intent: Intent, wait: float) -> Outcome:
    state = intent.context
    ok, error = apply_eq_reset(
        getattr(state, "config_path", None), settings=getattr(state, "settings", None),
        requester=intent.requester)
    return Outcome(ok=ok, error=error or None, result={"ok": ok, "error": error})


bind("input.eq.set", _input_eq_set, owner=_OWNER)
bind("output.eq.set", _output_eq_set, owner=_OWNER)
bind("output.eq.reset", _output_eq_reset, owner=_OWNER)
bind("repeat.arm", _repeat_arm, owner=_OWNER)
bind("repeat.transport", _repeat_stop, owner=_OWNER)
bind("repeat.seek", _repeat_seek, owner=_OWNER)
