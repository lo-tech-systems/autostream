"""autostream_output_policy -- what a Pause or Play pressed on a speaker does.

A receiver command (Pause, Play) arrives from the player's event channel as
a device event. The output authority hands each one to this policy on its
worker thread, and the policy turns it into an intent: mute that speaker,
mute every playing speaker, or turn every speaker off, as the device pause
setting says. A Play undoes what its Pause did.

Every Pause that mutes also starts the pause timeout. When it runs out with
no Play, the speakers that Pause muted and that are still muted are turned
off (deselected; the player is never stopped). A Play, or anything that ends
a speaker's mute in the meantime, takes that speaker out of it.

A Play that arrives soon after autostream wrote now-playing metadata to the
player is ignored: an Apple TV answers new artwork with a Play.

The policy owns no lock. Its state is confined to the authority's worker
thread, where the hooks run, and what it calls takes its own short locks.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Optional

import autostream_runtime as runtime
from autostream_backend_events import DeviceEvent
from autostream_config import (
    DEVICE_PAUSE_ALL,
    DEVICE_PAUSE_OFF_ALL,
    DEVICE_PAUSE_OUTPUT,
    OutputsConfig,
)
from autostream_intents.table import Intent, Outcome, bind, submit
from autostream_state import Origin, OutputsPart
from autostream_state.outputs import get_authority

LOG = logging.getLogger("autostream.output_policy")

_OWNER = "autostream_output_policy"
_REQUESTER = "policy"


@dataclass
class PauseEntry:
    """One speaker's Pause that is waiting for its Play or its timeout."""
    unit_id: str
    name: str                        # the speaker's name, for logs
    by: str                          # the device the Pause came from, for logs
    at: float                        # worker clock
    select_seq: int                  # the unit's selection when paused; another one ends the entry
    muted: dict                      # unit id -> mute token of the mute this Pause made
    since_token: int                 # the mute counter after the first Pause
    off_at: Optional[float] = None   # when the speakers it muted are turned off


@dataclass(frozen=True)
class EventContext:
    """Intent.context of the receiver rows. Never logged."""
    outputs: OutputsPart
    now: float
    received: float                  # DeviceEvent.received: the play guard compares this
    member_id: Optional[str]
    speaker_name: Optional[str]


def _requester(unit_id: str) -> str:
    return f"device:{unit_id}"


def _names(outputs: OutputsPart, unit_ids) -> str:
    names = []
    for uid in unit_ids:
        unit = outputs.unit(uid)
        names.append(unit.name if unit is not None and unit.name else uid)
    return ", ".join(names) if names else "nothing"


class OutputPolicy:
    def __init__(self) -> None:
        self._settings: Callable[[], OutputsConfig] = OutputsConfig
        self._entries: dict = {}
        self._touched = False

    def bind_settings(self, fn: Callable[[], OutputsConfig]) -> None:
        self._touched = True
        self._settings = fn

    def reset_for_tests(self) -> None:
        """Forget every entry and the bound settings. Returns at once when
        nothing was touched."""
        if not self._touched:
            return
        self._entries.clear()
        self._settings = OutputsConfig
        self._touched = False

    def paused_units(self) -> tuple:
        return tuple(self._entries)

    # -- the authority's hooks (worker thread, no lock held) -------------------

    def on_device_event(self, ev: DeviceEvent, outputs: OutputsPart, now: float) -> None:
        if ev.kind != "receiver_command":
            # A device volume has already ended the unit's mute in the
            # authority; a later Play finds its token gone.
            return
        name = {"paus": "receiver.pause", "play": "receiver.play"}.get(ev.verb)
        who = ev.speaker_name or ev.speaker_id
        if name is None:
            LOG.info(
                "receiver command %s from %s (%s): no action",
                ev.verb, who, ev.member_id or ev.speaker_id,
            )
            return
        self._touched = True
        ctx = EventContext(outputs, now, ev.received, ev.member_id, ev.speaker_name)
        submit(Intent(name, {"id": ev.speaker_id}, Origin.DEVICE, _requester(ev.speaker_id), context=ctx))

    def on_timer(self, now: float, outputs: OutputsPart) -> None:
        if not self._entries:
            return
        for entry in list(self._entries.values()):
            if self._stale(entry, outputs):
                self._entries.pop(entry.unit_id, None)
                continue
            if entry.off_at is not None and entry.off_at <= now:
                self._entries.pop(entry.unit_id, None)
                self._turn_off(entry, outputs)

    def next_deadline(self) -> Optional[float]:
        due = [e.off_at for e in self._entries.values() if e.off_at is not None]
        return min(due) if due else None

    def on_session(self, active: bool) -> None:
        if not active:
            self._entries.clear()

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _stale(entry: PauseEntry, outputs: OutputsPart) -> bool:
        """The unit is gone, off, or was switched off and on again since."""
        unit = outputs.unit(entry.unit_id)
        if unit is None or not unit.selected:
            return True
        marks = get_authority().unit_marks(entry.unit_id)
        return marks is None or marks.select_seq != entry.select_seq

    @staticmethod
    def _still_muted(entry: PauseEntry, outputs: OutputsPart) -> list:
        """The speakers this Pause muted that are muted still: the set a
        Play from its speaker would restore."""
        authority = get_authority()
        found = []
        for uid, token in entry.muted.items():
            marks = authority.unit_marks(uid)
            if marks is not None and marks.mute_token == token:
                found.append(uid)
        for unit in outputs.units:
            if unit.id in found or not unit.selected or not unit.muted:
                continue
            marks = authority.unit_marks(unit.id)
            if marks is not None and marks.mute_joined and marks.mute_token > entry.since_token:
                found.append(unit.id)
        return found

    def _turn_off(self, entry: PauseEntry, outputs: OutputsPart) -> None:
        muted = self._still_muted(entry, outputs)
        if not muted:
            LOG.info("pause from %s: nothing it muted is still muted; nothing turned off", entry.name)
            return
        for uid in muted:
            submit(Intent("outputs.pause_off", {"id": uid}, Origin.POLICY, _REQUESTER))
        LOG.info("pause from %s lasted too long: %s turned off", entry.name, _names(outputs, muted))

    # -- the intent handlers -------------------------------------------------

    def pause(self, intent: Intent, wait: float) -> Outcome:
        ctx: EventContext = intent.context
        uid = intent.args["id"]
        who = ctx.speaker_name or uid
        by = ctx.member_id or uid
        settings = self._settings()
        scope = settings.device_pause_scope
        unit = ctx.outputs.unit(uid)
        if unit is None:
            LOG.info("receiver pause from %s: no such speaker", who)
            return Outcome(ok=False, error="unknown_output")
        if not unit.selected:
            LOG.info("receiver pause from %s: that speaker is not on", who)
            return Outcome(ok=False, error="not_selected")
        authority = get_authority()
        if scope == DEVICE_PAUSE_OFF_ALL:
            self._entries.clear()
            reply = submit(Intent("outputs.deselect_all", {}, Origin.POLICY, _REQUESTER))
            LOG.info("receiver pause from %s (%s): every speaker turned off", who, by)
            return Outcome(ok=reply.ok, error=reply.error, result={"action": "off_all"})
        if scope == DEVICE_PAUSE_OUTPUT:
            applied = authority.mute(uid, Origin.DEVICE, requester=intent.requester)
        elif scope == DEVICE_PAUSE_ALL:
            applied = authority.mute_all(Origin.DEVICE, requester=intent.requester)
        else:
            LOG.info("receiver pause from %s: unknown scope %r", who, scope)
            return Outcome(ok=False, error="invalid_scope")
        if applied.refused is not None:
            LOG.info("receiver pause from %s: not muted (%s)", who, applied.refused)
            return Outcome(ok=False, error=applied.refused)
        entry = self._entries.get(uid)
        if entry is None:
            marks = authority.unit_marks(uid)
            entry = PauseEntry(
                unit_id=uid, name=who, by=by, at=ctx.now,
                select_seq=marks.select_seq if marks is not None else 0,
                muted={}, since_token=applied.token_at,
                off_at=ctx.now + settings.pause_off_seconds,
            )
            self._entries[uid] = entry
        entry.muted.update(dict(applied.mute_tokens))
        LOG.info(
            "receiver pause from %s (%s): %s muted", who, by,
            _names(ctx.outputs, [u for u, _ in applied.mute_tokens]),
        )
        return Outcome(ok=True, result={"action": "muted", "muted": [u for u, _ in applied.mute_tokens]})

    def play(self, intent: Intent, wait: float) -> Outcome:
        ctx: EventContext = intent.context
        uid = intent.args["id"]
        who = ctx.speaker_name or uid
        entry = self._entries.get(uid)
        if entry is None:
            LOG.info("receiver play from %s: nothing paused", who)
            return Outcome(ok=True, result={"action": "none"})
        settings = self._settings()
        last = runtime.last_metadata_push()
        guard = settings.play_after_metadata_ignore_seconds
        if last is not None and guard > 0 and ctx.received - last < guard:
            LOG.info("ignored unsolicited play from %s after a metadata push", who)
            return Outcome(ok=False, error="ignored_after_metadata")
        if self._stale(entry, ctx.outputs):
            self._entries.pop(uid, None)
            LOG.info("receiver play from %s: that pause is over; nothing to undo", who)
            return Outcome(ok=True, result={"action": "none"})
        authority = get_authority()
        restored = self._still_muted(entry, ctx.outputs)
        for muted_id, token in entry.muted.items():
            authority.unmute(
                muted_id, Origin.DEVICE, default_level=0,
                requester=intent.requester, only_token=token,
            )
        authority.unmute_joined(
            entry.since_token, Origin.DEVICE, default_level=0, requester=intent.requester,
        )
        self._entries.pop(uid, None)
        LOG.info("receiver play from %s: %s restored", who, _names(ctx.outputs, restored))
        return Outcome(ok=True, result={"action": "restored"})


def _pause_off(intent: Intent, wait: float) -> Outcome:
    """Switch one speaker off because a Pause on it has lasted too long."""
    applied = get_authority().deselect(intent.args["id"], Origin.POLICY, requester=intent.requester)
    return Outcome(ok=applied.refused is None, error=applied.refused)


_policy = OutputPolicy()


def get_policy() -> OutputPolicy:
    return _policy


bind("receiver.pause", lambda intent, wait: _policy.pause(intent, wait), owner=_OWNER)
bind("receiver.play", lambda intent, wait: _policy.play(intent, wait), owner=_OWNER)
bind("outputs.pause_off", _pause_off, owner=_OWNER)
