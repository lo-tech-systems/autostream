"""autostream_output_intents -- handlers for requests to change an output.

Binds the output rows of the intent table at import. A browser, a dial or a
peer asks for a speaker to be switched on or off, for its volume to change, or
for a PIN to be tried; the handler here turns that into a call on the output
authority, waits a bounded time for the player's answer, and shapes the
result the routes send back.

The authority has already updated the desired state (and told every
subscriber) by the time the handler waits, so the speaker list reflects the
request at once; the wait is only for the player's verdict. A wait that
expires replies as "pending": the request was accepted and the authority
records the real outcome when it comes.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import logging

import autostream_mute_state as mute_state
import autostream_output_usage as output_usage
import autostream_pin_pairing as pairing
from autostream_intents.table import Intent, Outcome, bind
from autostream_state import Origin, store
from autostream_state.outputs import WriteOutcome, get_authority, wait_outcome

_OWNER = "autostream_output_intents"
_DEFAULT_VOLUME = 50


def _first(outcomes: tuple) -> WriteOutcome:
    return outcomes[0] if outcomes else WriteOutcome(ok=True)


def _failure(out_id: str, outcome: WriteOutcome) -> dict:
    return {"ok": False, "id": out_id, "error": outcome.error}


def _enable(intent: Intent, wait: float, out_id: str, user: bool) -> dict:
    """Switch a speaker on, or change the volume of one that is on."""
    args = intent.args
    unit = store().snapshot().outputs.unit(out_id)
    if unit is None:
        return {"ok": False, "id": out_id, "error": "unknown_output"}
    already_on = unit.selected
    if unit.name and not already_on:
        # Only a speaker that is not already ours can be taken from someone
        # else; a volume change on a speaker that is on is always allowed.
        try:
            usage = output_usage.usage_for_output(unit.name)
            if usage is not None:
                return {"ok": False, "id": out_id, "error": "output_in_use", "owner": usage.owner_name}
        except Exception:
            logging.debug("outputs.set: usage check failed for %s", unit.name)

    volume = args.get("volume")
    volume = _DEFAULT_VOLUME if volume is None else volume
    cause = Origin.USER if user else Origin.SYSTEM
    authority = get_authority()

    if already_on and user and mute_state.is_muted():
        # A deliberate volume change on a speaker while muted is the unmute:
        # it sounds at the level just chosen, not the remembered one.
        mute_state.end_mute()
    elif already_on and mute_state.remember_level(out_id, volume):
        # Not the user (the coordinator): the level it returns to moves, the
        # speaker stays silent.
        return {"ok": True, "id": out_id}

    if already_on:
        applied = authority.set_volume(out_id, volume, cause, requester=intent.requester)
    else:
        applied = authority.select(
            out_id, cause, volume=volume, offset_ms=args.get("offset_ms"),
            mode=args.get("mode"), requester=intent.requester,
        )
    if applied.refused is not None:
        return {"ok": False, "id": out_id, "error": applied.refused}

    outcome = _first(wait_outcome(applied, wait))
    if not outcome.ok:
        if outcome.error_code == "pin_required":
            # The speaker was not switched on; whoever asked can be sent its PIN.
            requester = intent.context
            if requester:
                pairing.claim(out_id, requester)
            return {
                "ok": False,
                "pin_required": True,
                "id": out_id,
                "output_name": str(args.get("name") or ""),
                "error": outcome.error,
            }
        if outcome.error_code == "encoder_capacity":
            return {"ok": False, "id": out_id, "error": "encoder_capacity"}
        return {"ok": False, "id": out_id, "error": outcome.error, "pin_invalid": False}

    if not already_on and mute_state.remember_level(out_id, volume):
        # It joined a muted appliance: it sounds only when the mute ends, at
        # the level just asked for.
        silenced = authority.set_volume(out_id, 0, Origin.SYSTEM, requester=intent.requester)
        quiet = _first(wait_outcome(silenced, wait))
        if not quiet.ok:
            logging.warning(
                "outputs.set: could not silence newly-enabled output %s under mute: %s",
                out_id, quiet.error,
            )
    return {"ok": True, "id": out_id}


def _disable(intent: Intent, wait: float, out_id: str, user: bool) -> dict:
    cause = Origin.USER if user else Origin.SYSTEM
    applied = get_authority().deselect(out_id, cause, requester=intent.requester)
    if applied.refused is not None:
        return {"ok": False, "id": out_id, "error": applied.refused}
    outcome = _first(wait_outcome(applied, wait))
    if not outcome.ok:
        return _failure(out_id, outcome)
    mute_state.forget_output(out_id)
    return {"ok": True, "id": out_id}


def _outputs_set(intent: Intent, wait: float) -> Outcome:
    user = intent.origin == Origin.USER
    out_id = intent.args["id"]
    if intent.args["selected"]:
        result = _enable(intent, wait, out_id, user)
    else:
        result = _disable(intent, wait, out_id, user)
    return Outcome(ok=bool(result.get("ok")), error=result.get("error"), result=result)


def _output_pin_submit(intent: Intent, wait: float) -> Outcome:
    user = intent.origin == Origin.USER
    args = intent.args
    out_id = args["id"]
    allowed, retry_after = pairing.note_attempt(intent.context or pairing.REQUESTER_WEBUI, out_id)
    if not allowed:
        result = {"ok": False, "error": "rate_limited", "retry_after_s": retry_after, "id": out_id}
        return Outcome(ok=False, error="rate_limited", result=result)
    applied = get_authority().submit_pin(out_id, args["pin"], requester=intent.requester)
    outcome = _first(wait_outcome(applied, wait))
    if not outcome.ok and outcome.error_code == "pin_invalid":
        result = {"ok": False, "id": out_id, "pin_invalid": True, "error": outcome.error}
    elif not outcome.ok:
        result = _failure(out_id, outcome)
    else:
        pairing.release(out_id)
        if args.get("selected"):
            result = _enable(intent, wait, out_id, user)
        else:
            result = {"ok": True, "id": out_id}
    return Outcome(ok=bool(result.get("ok")), error=result.get("error"), result=result)


def _deselect_all(intent: Intent, wait: float) -> Outcome:
    """Switch every speaker off (the session edges, and the shutdown)."""
    applied = get_authority().deselect_all(intent.origin, requester=intent.requester)
    outcome = _first(wait_outcome(applied, wait))
    if outcome.ok:
        if not outcome.pending:
            logging.info("OwnTone outputs cleared (%s).", intent.origin.value)
        return Outcome(ok=True)
    logging.warning("OwnTone stop/disable request failed: %s", outcome.error or "unknown error")
    return Outcome(ok=False, error=outcome.error or "failed", result={"message": outcome.error})


def _select_default(intent: Intent, wait: float) -> Outcome:
    """Switch the configured default speaker on. The error names the reason
    it was not: no_default, not_found, pin_pending, in_use, pin_required, or
    the player's own text in the result."""
    args = intent.args
    name = args["name"].strip()
    if not name:
        return Outcome(ok=False, error="no_default")
    unit = store().snapshot().outputs.unit_by_name(name)
    if unit is None:
        return Outcome(ok=False, error="not_found")
    if unit.availability == "password" or (unit.reported is not None and unit.reported.needs_auth_key):
        # The player deselected it pending pairing; asking again would make
        # the speaker prompt for a PIN on every retry.
        return Outcome(ok=False, error="pin_pending")
    try:
        output_usage.refresh_now("default-output-auto-select", timeout=1.5)
        usage = output_usage.usage_for_output(name)
        if usage is not None:
            return Outcome(ok=False, error="in_use", result={"owner": usage.owner_name})
    except Exception:
        logging.debug("outputs.select_default: usage check failed", exc_info=True)
    applied = get_authority().select(
        unit.id, Origin.SESSION, volume=args["volume"], offset_ms=args.get("offset_ms"),
        mode=args.get("mode"), requester=intent.requester,
    )
    if applied.refused is not None:
        return Outcome(ok=False, error=applied.refused)
    outcome = _first(wait_outcome(applied, wait))
    if not outcome.ok:
        if outcome.error_code == "pin_required":
            return Outcome(ok=False, error="pin_required")
        return Outcome(ok=False, error="failed", result={"message": outcome.error})
    logging.info("No outputs selected; auto-enabled default output '%s'.", name)
    return Outcome(ok=True)


bind("outputs.set", _outputs_set, owner=_OWNER)
bind("output.pin.submit", _output_pin_submit, owner=_OWNER)
bind("outputs.select_default", _select_default, owner=_OWNER)
bind("outputs.deselect_all", _deselect_all, owner=_OWNER)
