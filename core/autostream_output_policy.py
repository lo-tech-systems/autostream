"""autostream_output_policy -- what a Pause or Play pressed on a speaker does.

A receiver command (Pause, Play, or the play/pause toggle an Apple TV sends
from its now-playing screen) arrives from the player's event channel as a
device event. The output authority hands each one to this policy on its
worker thread, and the policy turns it into intents.

A speaker that pauses itself stops playing whatever autostream does, and
its own Play does not start it again. So a Pause always holds that speaker:
the player sends it no audio until the hold ends. The device pause setting
says what happens to the other playing speakers: nothing, muted, or
switched off. A speaker the player cannot hold is muted instead. A Play on
the held speaker ends the hold, which restarts it at the live position, and
unmutes the speakers its Pause muted; speakers it switched off stay off. A
Play from a speaker that is not paused is ignored: an Apple TV sends one
when its own screens change.

Every Pause also starts the pause timeout. When it runs out with no Play,
the held speaker and the speakers that Pause muted and that are still muted
are turned off (deselected; the player is never stopped). A hold the player
ends itself (its session ended or was restarted) counts as the Play for the
speakers it muted. Switching the paused speaker off ends its Pause and
leaves the others as they are.

The policy owns no lock. Its state is confined to the authority's worker
thread, where the hooks run, and what it calls takes its own short locks.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Optional

from autostream_backend_events import DeviceEvent
from autostream_config import (
    DEVICE_PAUSE_ALL,
    DEVICE_PAUSE_OFF_ALL,
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
    since_token: Optional[int]       # the mute counter after the first mute; None: it muted nothing
    off_at: Optional[float] = None   # when the speakers it paused or muted are turned off
    held: bool = False               # the speaker itself is held, not muted


@dataclass(frozen=True)
class EventContext:
    """Intent.context of the receiver rows. Never logged."""
    outputs: OutputsPart
    now: float
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
        who = ev.speaker_name or ev.speaker_id
        verb = ev.verb
        if verb == "plps":
            verb = "play" if self._paused(ev.speaker_id, outputs) else "paus"
            LOG.info("receiver toggle from %s: taken as %s", who, "play" if verb == "play" else "pause")
        name = {"paus": "receiver.pause", "play": "receiver.play"}.get(verb)
        if name is None:
            LOG.info(
                "receiver command %s from %s (%s): no action",
                ev.verb, who, ev.member_id or ev.speaker_id,
            )
            return
        self._touched = True
        ctx = EventContext(outputs, now, ev.member_id, ev.speaker_name)
        submit(Intent(name, {"id": ev.speaker_id}, Origin.DEVICE, _requester(ev.speaker_id), context=ctx))

    def on_timer(self, now: float, outputs: OutputsPart) -> None:
        if not self._entries:
            return
        for entry in list(self._entries.values()):
            if self._stale(entry, outputs):
                self._entries.pop(entry.unit_id, None)
                continue
            if entry.held and not self._unit_held(entry.unit_id, outputs):
                # The player ended the hold itself: the speaker plays again,
                # so the speakers its Pause muted play again too.
                self._entries.pop(entry.unit_id, None)
                restored = self._restore_others(entry, outputs, _REQUESTER)
                LOG.info("hold of %s ended by the player: %s restored", entry.name, _names(outputs, restored))
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
    def _unit_held(unit_id: str, outputs: OutputsPart) -> bool:
        unit = outputs.unit(unit_id)
        return unit is not None and unit.held

    def _paused(self, unit_id: str, outputs: OutputsPart) -> bool:
        """The speaker's own Pause is in force: it is held, or the mute its
        Pause made is still the one it has. What a toggle from it means."""
        if self._unit_held(unit_id, outputs):
            return True
        entry = self._entries.get(unit_id)
        if entry is None or entry.held or unit_id not in entry.muted:
            return False
        marks = get_authority().unit_marks(unit_id)
        return marks is not None and marks.mute_token == entry.muted[unit_id]

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
        if entry.since_token is None:
            return found
        for unit in outputs.units:
            if unit.id in found or not unit.selected or not unit.muted:
                continue
            marks = authority.unit_marks(unit.id)
            if marks is not None and marks.mute_joined and marks.mute_token > entry.since_token:
                found.append(unit.id)
        return found

    def _restore_others(self, entry: PauseEntry, outputs: OutputsPart, requester: str) -> list:
        """Unmute what this Pause muted that is muted still. The speakers it
        switched off stay off."""
        authority = get_authority()
        restored = self._still_muted(entry, outputs)
        for muted_id, token in entry.muted.items():
            authority.unmute(muted_id, Origin.DEVICE, default_level=0, requester=requester, only_token=token)
        if entry.since_token is not None:
            authority.unmute_joined(entry.since_token, Origin.DEVICE, default_level=0, requester=requester)
        return restored

    def _turn_off(self, entry: PauseEntry, outputs: OutputsPart) -> None:
        off = self._still_muted(entry, outputs)
        if entry.held and self._unit_held(entry.unit_id, outputs) and entry.unit_id not in off:
            off.insert(0, entry.unit_id)
        if not off:
            LOG.info("pause from %s: nothing it paused or muted is still so; nothing turned off", entry.name)
            return
        for uid in off:
            submit(Intent("outputs.pause_off", {"id": uid}, Origin.POLICY, _REQUESTER))
        LOG.info("pause from %s lasted too long: %s turned off", entry.name, _names(outputs, off))

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
        if self._paused(uid, ctx.outputs):
            LOG.info("receiver pause from %s: already paused", who)
            return Outcome(ok=True, result={"action": "none"})
        authority = get_authority()
        tokens: dict = {}
        since_token: Optional[int] = None
        applied = authority.hold(uid, Origin.DEVICE, requester=intent.requester)
        held = applied.refused is None
        if not held:
            if applied.refused != "not_holdable":
                LOG.info("receiver pause from %s: not held (%s)", who, applied.refused)
                return Outcome(ok=False, error=applied.refused)
            # A speaker the player cannot hold is muted instead
            muted = authority.mute(uid, Origin.DEVICE, requester=intent.requester)
            if muted.refused is not None:
                LOG.info("receiver pause from %s: cannot be held, and not muted (%s)", who, muted.refused)
                return Outcome(ok=False, error=muted.refused)
            tokens.update(dict(muted.mute_tokens))
            since_token = muted.token_at
        others = "nothing else changed"
        if scope == DEVICE_PAUSE_ALL:
            muted_all = authority.mute_all(Origin.DEVICE, requester=intent.requester, except_id=uid)
            if muted_all.refused is None:
                tokens.update(dict(muted_all.mute_tokens))
                if since_token is None:
                    since_token = muted_all.token_at
                others = _names(ctx.outputs, [u for u, _ in muted_all.mute_tokens]) + " muted"
        elif scope == DEVICE_PAUSE_OFF_ALL:
            off = [u.id for u in ctx.outputs.units if u.selected and u.id != uid]
            if authority.deselect_others(uid, Origin.POLICY, requester=_REQUESTER).refused is None:
                others = _names(ctx.outputs, off) + " turned off"
        marks = authority.unit_marks(uid)
        entry = PauseEntry(
            unit_id=uid, name=who, by=by, at=ctx.now,
            select_seq=marks.select_seq if marks is not None else 0,
            muted=tokens, since_token=since_token,
            off_at=ctx.now + settings.pause_off_seconds, held=held,
        )
        self._entries[uid] = entry
        LOG.info(
            "receiver pause from %s (%s): %s %s; %s", who, by, who,
            "held" if held else "muted (it cannot be held)", others,
        )
        return Outcome(ok=True, result={"action": "held" if held else "muted", "muted": list(tokens)})

    def play(self, intent: Intent, wait: float) -> Outcome:
        ctx: EventContext = intent.context
        uid = intent.args["id"]
        who = ctx.speaker_name or uid
        authority = get_authority()
        entry = self._entries.get(uid)
        if entry is None:
            if self._unit_held(uid, ctx.outputs):
                # Held with no Pause on record (autostream restarted since):
                # there is nothing else to restore.
                authority.resume(uid, Origin.DEVICE, requester=intent.requester)
                LOG.info("receiver play from %s: hold ended", who)
                return Outcome(ok=True, result={"action": "resumed"})
            LOG.info("receiver play from %s: not paused; ignored", who)
            return Outcome(ok=True, result={"action": "none"})
        if self._stale(entry, ctx.outputs):
            self._entries.pop(uid, None)
            LOG.info("receiver play from %s: that pause is over; nothing to undo", who)
            return Outcome(ok=True, result={"action": "none"})
        self._entries.pop(uid, None)
        if entry.held:
            authority.resume(uid, Origin.DEVICE, requester=intent.requester)
        restored = self._restore_others(entry, ctx.outputs, intent.requester)
        LOG.info(
            "receiver play from %s: %s%s restored", who,
            "hold ended, " if entry.held else "", _names(ctx.outputs, restored),
        )
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
