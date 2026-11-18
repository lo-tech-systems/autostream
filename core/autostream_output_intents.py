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

import autostream_output_usage as output_usage
import autostream_pin_pairing as pairing
from autostream_intents.table import Intent, Outcome, bind
from autostream_state import Origin, store
from autostream_state.outputs import WriteOutcome, get_authority, set_pin_claim_handler, wait_outcome

_OWNER = "autostream_output_intents"


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
    authority = get_authority()
    volume = authority.start_volume() if volume is None else volume
    cause = Origin.USER if user else Origin.SYSTEM

    # The authority holds the mute: a deliberate volume change on a muted
    # speaker is its unmute (it sounds at the level just chosen); any other
    # caller only moves the level it returns to; a speaker that joins a muted
    # selection comes on silent.
    if already_on:
        applied = authority.set_volume(out_id, volume, cause, requester=intent.requester)
    else:
        applied = authority.select(
            out_id, cause, volume=volume, offset_ms=args.get("offset_ms"),
            mode=args.get("mode"), requester=intent.requester, claimant=intent.context,
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
                get_authority().republish()
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

    return {"ok": True, "id": out_id}


def _disable(intent: Intent, wait: float, out_id: str, user: bool) -> dict:
    cause = Origin.USER if user else Origin.SYSTEM
    applied = get_authority().deselect(out_id, cause, requester=intent.requester)
    if applied.refused is not None:
        return {"ok": False, "id": out_id, "error": applied.refused}
    outcome = _first(wait_outcome(applied, wait))
    if not outcome.ok:
        return _failure(out_id, outcome)
    return {"ok": True, "id": out_id}


def _outputs_set(intent: Intent, wait: float) -> Outcome:
    user = intent.origin == Origin.USER
    out_id = intent.args["id"]
    member = store().snapshot().outputs.placeholder_member(out_id)
    if member is not None:
        # A set member's card while the player has no row for it: the tap is
        # a choice for the session, with nothing to send yet.
        get_authority().want_default(bool(intent.args["selected"]), member.key)
        return Outcome(ok=True, result={"ok": True})
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
        get_authority().republish()
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


def _want_default(intent: Intent, wait: float) -> Outcome:
    """The user's tap on a default speaker's card while the player has no
    row for it. The choice is kept for the session; the speaker starts once
    it appears. Without an id it is the first such card."""
    wanted = bool(intent.args["wanted"])
    part = store().snapshot().outputs
    card = intent.args.get("id")
    if card:
        member = part.placeholder_member(card)
    else:
        member = next((m for m in part.default_members if m.placeholder), None)
    if member is not None:
        get_authority().want_default(wanted, member.key)
    return Outcome(ok=True, result={"ok": True})


def _select_default(intent: Intent, wait: float) -> Outcome:
    """Switch one speaker of the Auto-Start set on, named by its member key.
    The error names the reason it was not: no_default, not_found, pin_pending,
    in_use, pin_required, or the player's own text in the result."""
    args = intent.args
    part = store().snapshot().outputs
    member = next((m for m in part.default_members if m.key == args["key"]), None)
    if member is None:
        return Outcome(ok=False, error="no_default")
    unit = None if member.placeholder else part.unit(member.unit_id)
    if unit is None or unit.offline:
        return Outcome(ok=False, error="not_found")
    name = unit.name
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


def _step_levels(intent: Intent, wait: float, applied) -> dict:
    """The reply body of a volume step or a restore from mute."""
    outcomes = wait_outcome(applied, wait) if applied.outcome is not None else ()
    master = applied.master
    if applied.restored:
        body: dict = {"ok": True, "muted": False}
    elif applied.muted:
        return {"ok": True, "volume": master, "muted": True}
    else:
        body = {"ok": True, "volume": master, "muted": False}
    if any(o.pending for o in outcomes):
        return {"ok": True, "volume": master, "muted": store().snapshot().outputs.muted_all}
    failed = sum(1 for o in outcomes if not o.ok)
    for o in outcomes:
        if not o.ok:
            logging.warning("volume.step: update_output: %s", o.error)
    if outcomes and failed == len(outcomes):
        body = {"ok": False, "error": "all_outputs_failed"}
        if applied.restored:
            body["volume"] = None
        return body
    if failed:
        if applied.restored:
            body["partial"] = True
        else:
            body = {"ok": True, "volume": master, "partial": True, "muted": False}
    if applied.restored:
        body["volume"] = master
    return body


def _refusal(applied) -> dict:
    return {"ok": False, "error": "backend_unavailable" if applied.refused == "not_connected" else applied.refused}


def _volume_step(intent: Intent, wait: float) -> Outcome:
    """Move the volume of every selected speaker together. While muted, a
    step down changes nothing and a step up is a plain restore."""
    args = intent.args
    applied = get_authority().step_volume(
        args["delta"], Origin.USER, default_level=args["default_level"], requester=intent.requester,
    )
    result = _refusal(applied) if applied.refused is not None else _step_levels(intent, wait, applied)
    return Outcome(ok=bool(result.get("ok")), error=result.get("error"), result=result)


def _volume_set(intent: Intent, wait: float) -> Outcome:
    """Bring the volume of every selected speaker to a level together,
    keeping their proportions. A set above 0 while muted is a restore."""
    args = intent.args
    applied = get_authority().set_master(
        args["level"], Origin.USER, default_level=args["default_level"], requester=intent.requester,
    )
    result = _refusal(applied) if applied.refused is not None else _step_levels(intent, wait, applied)
    return Outcome(ok=bool(result.get("ok")), error=result.get("error"), result=result)


def _mute_set(intent: Intent, wait: float) -> Outcome:
    """Mute every selected speaker, or restore them to their remembered
    levels. Both are idempotent."""
    args = intent.args
    authority = get_authority()
    if args["action"] == "mute":
        applied = authority.mute_all(Origin.USER, requester=intent.requester)
        muted = True
    else:
        applied = authority.unmute_all(
            Origin.USER, default_level=args["default_level"], requester=intent.requester,
        )
        muted = False
    if applied.refused is not None:
        result = _refusal(applied)
    else:
        outcomes = wait_outcome(applied, wait) if applied.outcome is not None else ()
        failed = 0
        for o in outcomes:
            if not o.ok:
                failed += 1
                logging.warning("mute.set: update_output: %s", o.error)
        if any(o.pending for o in outcomes):
            result = {"ok": True, "muted": store().snapshot().outputs.muted_all}
        elif outcomes and failed == len(outcomes):
            result = {"ok": False, "error": "all_outputs_failed"}
        elif failed:
            result = {"ok": True, "muted": muted, "partial": True}
        else:
            result = {"ok": True, "muted": muted}
    return Outcome(ok=bool(result.get("ok")), error=result.get("error"), result=result)


def _claim_late_pin(unit_id: str, claimant: str) -> None:
    pairing.claim(unit_id, claimant)
    get_authority().republish()


set_pin_claim_handler(_claim_late_pin)

bind("outputs.set", _outputs_set, owner=_OWNER)
bind("output.pin.submit", _output_pin_submit, owner=_OWNER)
bind("outputs.select_default", _select_default, owner=_OWNER)
bind("outputs.want_default", _want_default, owner=_OWNER)
bind("outputs.deselect_all", _deselect_all, owner=_OWNER)
bind("volume.step", _volume_step, owner=_OWNER)
bind("volume.set", _volume_set, owner=_OWNER)
bind("mute.set", _mute_set, owner=_OWNER)
