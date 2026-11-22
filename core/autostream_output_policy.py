"""autostream_output_policy -- what a Pause or Play pressed on a speaker does.

A receiver command (Pause, Play, or the play/pause toggle an Apple TV sends
from its now-playing screen) arrives from the player's event channel as a
device event. The output authority hands each one to this policy on its
worker thread, and the policy turns it into intents.

A speaker that pauses itself stops playing whatever autostream does, and
its own Play does not start it again. So a Pause always holds that speaker:
the player sends it no audio until the hold ends. A speaker the player
cannot hold is muted instead. The device pause setting says whether the
other playing speakers pause too: each is held, or muted when it cannot be
held (one already muted is left as it is). A Pause from a speaker that is
still starting (switched on here and not playing yet, or playing for under
START_PAUSE_S) pauses it alone: an Apple TV whose TV is off pauses itself as
soon as it is started, which is not a person's Pause. A Play on any speaker that Pause
held or muted ends every hold it made, which restarts those speakers at the
live position, and unmutes the speakers it muted. A Play from a speaker
that is not paused is ignored: an Apple TV sends one when its own screens
change.

Every Pause also starts the pause timeout. When it runs out with no Play,
the speakers that Pause held and that are still held, and those it muted
that are still muted, are turned off (deselected; the player is never
stopped). A hold it made that ends any other way counts as its Play: the
player ended it (its session ended or was restarted), or a client resumed
the speaker (the outputs.resume intent). Switching a speaker it held off
takes that speaker out of the Pause; when that is the speaker the Pause
came from, the others it held stay paused together, and with none left the
Pause ends and the speakers it muted stay as they are.

A turn of a paused or muted speaker's own volume knob arrives as a wake:
the player does not report the level of a silent speaker. A wake on a
paused speaker is its Play; on a speaker that is only muted it unmutes that
speaker alone; on any other it does nothing.

The policy owns no lock. Its state is confined to the authority's worker
thread, where the hooks run, and what it calls takes its own short locks.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace
from typing import Callable, Optional

import autostream_repeat_idle as repeat_idle
from autostream_backend_events import DeviceEvent
from autostream_config import (
    DEVICE_PAUSE_ALL,
    OutputsConfig,
)
from autostream_intents.table import Intent, Outcome, bind, submit
from autostream_state import Origin, OutputsPart
from autostream_state.outputs import get_authority

LOG = logging.getLogger("autostream.output_policy")

_OWNER = "autostream_output_policy"
_REQUESTER = "policy"
# A Pause from a speaker that started playing less than this long ago pauses
# that speaker alone, whatever the device pause setting says
START_PAUSE_S = 5.0


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
    others_held: dict = field(default_factory=dict)  # unit id -> select_seq of the others it held


@dataclass(frozen=True)
class EventContext:
    """Intent.context of the receiver rows. Never logged."""
    outputs: OutputsPart
    now: float
    member_id: Optional[str]
    speaker_name: Optional[str]
    protocol: Optional[str] = None   # where a receiver command came from; for logs


def _requester(unit_id: str) -> str:
    return f"device:{unit_id}"


def _starting(unit, marks, now: float) -> bool:
    """Whether a speaker switched on here is still starting: not playing yet,
    or playing for less than START_PAUSE_S. One found already playing is not."""
    if unit.connecting:
        return True
    played = marks.first_played_at if marks is not None else None
    return played is not None and now - played < START_PAUSE_S


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
            # A device volume is the authority's business: it never ends a
            # mute; a muted speaker's knob arrives as a wake.
            return
        who = ev.speaker_name or ev.speaker_id
        verb = ev.verb
        if verb == "plps":
            verb = "play" if self._paused(ev.speaker_id, outputs) else "paus"
            LOG.info("receiver toggle from %s: taken as %s", who, "play" if verb == "play" else "pause")
        name = {"paus": "receiver.pause", "play": "receiver.play", "wake": "receiver.wake"}.get(verb)
        if name is None:
            LOG.info(
                "receiver command %s from %s (%s): no action",
                ev.verb, who, ev.member_id or ev.speaker_id,
            )
            return
        self._touched = True
        ctx = EventContext(outputs, now, ev.member_id, ev.speaker_name, protocol=ev.protocol)
        submit(Intent(name, {"id": ev.speaker_id}, Origin.DEVICE, _requester(ev.speaker_id), context=ctx))

    def on_timer(self, now: float, outputs: OutputsPart) -> None:
        if not self._entries:
            return
        for entry in list(self._entries.values()):
            entry = self._settle(entry, outputs)
            if entry is None:
                continue
            ended = self._hold_ended(entry, outputs)
            if ended is not None:
                # A hold this Pause made ended without a Play (the player
                # ended it, or a client resumed the speaker): that speaker
                # plays again, so everything the Pause held or muted does too.
                self._entries.pop(entry.unit_id, None)
                restored = self._resume_all(entry, outputs, _REQUESTER, except_id=ended)
                name = entry.name if ended == entry.unit_id else _names(outputs, [ended])
                LOG.info("hold of %s ended: %s restored", name, _names(outputs, restored))
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

    def _entry_for(self, unit_id: str) -> Optional[PauseEntry]:
        """The Pause that paused this speaker: its own, or a Pause on another
        speaker that held or muted it too."""
        entry = self._entries.get(unit_id)
        if entry is not None:
            return entry
        for other in self._entries.values():
            if unit_id in other.others_held or unit_id in other.muted:
                return other
        return None

    def _paused(self, unit_id: str, outputs: OutputsPart) -> bool:
        """A Pause is in force on the speaker: it is held, or the mute a Pause
        made is still the one it has. What a toggle from it means."""
        if self._unit_held(unit_id, outputs):
            return True
        entry = self._entry_for(unit_id)
        if entry is None or unit_id not in entry.muted:
            return False
        marks = get_authority().unit_marks(unit_id)
        return marks is not None and marks.mute_token == entry.muted[unit_id]

    @staticmethod
    def _in_pause(unit_id: str, select_seq: int, outputs: OutputsPart) -> bool:
        """The speaker is still on with the selection it was paused with."""
        unit = outputs.unit(unit_id)
        if unit is None or not unit.selected:
            return False
        marks = get_authority().unit_marks(unit_id)
        return marks is not None and marks.select_seq == select_seq

    def _settle(self, entry: PauseEntry, outputs: OutputsPart) -> Optional[PauseEntry]:
        """Take the speakers switched off since out of a Pause. When the
        speaker it came from is one of them, the others it held stay paused
        together under one of them; with none left the Pause ends. Returns
        the entry as it now stands, or None."""
        for uid, seq in list(entry.others_held.items()):
            if not self._in_pause(uid, seq, outputs):
                del entry.others_held[uid]
        if not self._stale(entry, outputs):
            return entry
        self._entries.pop(entry.unit_id, None)
        if not entry.others_held:
            return None
        lead, seq = next(iter(entry.others_held.items()))
        others = {uid: s for uid, s in entry.others_held.items() if uid != lead}
        entry = replace(entry, unit_id=lead, name=_names(outputs, [lead]), select_seq=seq,
                        held=True, others_held=others)
        self._entries[lead] = entry
        return entry

    def _held_members(self, entry: PauseEntry, outputs: OutputsPart) -> list:
        """The speakers this Pause held that are held still."""
        ids = ([entry.unit_id] if entry.held else []) + list(entry.others_held)
        return [uid for uid in ids if self._unit_held(uid, outputs)]

    def _hold_ended(self, entry: PauseEntry, outputs: OutputsPart) -> Optional[str]:
        """A speaker whose hold this Pause made has ended while it stayed on."""
        ids = ([entry.unit_id] if entry.held else []) + list(entry.others_held)
        for uid in ids:
            if not self._unit_held(uid, outputs):
                return uid
        return None

    def _resume_all(self, entry: PauseEntry, outputs: OutputsPart, requester: str,
                    except_id: Optional[str] = None) -> list:
        """End every hold this Pause made and unmute what it muted. Returns
        the speakers brought back, other than the held *except_id*, for the
        log."""
        authority = get_authority()
        resumed = []
        for uid in self._held_members(entry, outputs):
            authority.resume(uid, Origin.DEVICE, requester=requester)
            if uid != except_id:
                resumed.append(uid)
        return resumed + self._restore_others(entry, outputs, requester)

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
        off += [uid for uid in self._held_members(entry, outputs) if uid not in off]
        if not off:
            LOG.info("pause from %s: nothing it paused or muted is still so; nothing turned off", entry.name)
            return
        for uid in off:
            submit(Intent("outputs.pause_off", {"id": uid}, Origin.POLICY, _REQUESTER))
        LOG.info("pause from %s lasted too long: %s turned off", entry.name, _names(outputs, off))
        # If that left no speaker on, repeat is stopped at the next check
        # rather than after the usual wait
        repeat_idle.nudge()

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
        others_held: dict = {}
        marks = authority.unit_marks(uid)
        if scope == DEVICE_PAUSE_ALL and _starting(unit, marks, ctx.now):
            # Not a person's Pause: an Apple TV whose TV is off pauses itself
            # as soon as it is started, so the others play on
            others = "nothing else paused, as it paused while starting"
        elif scope == DEVICE_PAUSE_ALL:
            others_held, others_muted, others_token = self._pause_others(uid, ctx.outputs, intent.requester)
            tokens.update(others_muted)
            if since_token is None:
                since_token = others_token
            parts = []
            if others_held:
                parts.append(_names(ctx.outputs, others_held) + " held")
            if others_muted:
                parts.append(_names(ctx.outputs, others_muted) + " muted")
            others = ", ".join(parts) or others
        entry = PauseEntry(
            unit_id=uid, name=who, by=by, at=ctx.now,
            select_seq=marks.select_seq if marks is not None else 0,
            muted=tokens, since_token=since_token,
            off_at=ctx.now + settings.pause_off_seconds, held=held,
            others_held=others_held,
        )
        self._entries[uid] = entry
        LOG.info(
            "receiver pause from %s (%s): %s %s; %s", who, by, who,
            "held" if held else "muted (it cannot be held)", others,
        )
        return Outcome(ok=True, result={
            "action": "held" if held else "muted", "muted": list(tokens), "held": list(others_held),
        })

    @staticmethod
    def _pause_others(uid: str, outputs: OutputsPart, requester: str) -> tuple:
        """Pause every other speaker that is on and playing: hold it, or mute
        it when it cannot be held. One that is held or muted already is left
        as it is: a hold of a muted speaker would end its mute when resumed.
        Returns (unit id -> select_seq of those held, unit id -> mute token
        of those muted, the mute counter after the first mute or None)."""
        authority = get_authority()
        held: dict = {}
        muted: dict = {}
        token_at: Optional[int] = None
        for unit in outputs.units:
            if unit.id == uid or not unit.selected or unit.held or unit.muted:
                continue
            applied = authority.hold(unit.id, Origin.DEVICE, requester=requester)
            if applied.refused is None:
                marks = authority.unit_marks(unit.id)
                held[unit.id] = marks.select_seq if marks is not None else 0
                continue
            if applied.refused != "not_holdable":
                LOG.info("pause of %s: not held (%s)", _names(outputs, [unit.id]), applied.refused)
                continue
            result = authority.mute(unit.id, Origin.DEVICE, requester=requester)
            if result.refused is None and result.mute_tokens:
                muted.update(dict(result.mute_tokens))
                if token_at is None:
                    token_at = result.token_at
        return held, muted, token_at

    def play(self, intent: Intent, wait: float) -> Outcome:
        ctx: EventContext = intent.context
        uid = intent.args["id"]
        who = ctx.speaker_name or uid
        authority = get_authority()
        entry = self._entry_for(uid)
        if entry is None:
            if self._unit_held(uid, ctx.outputs):
                # Held with no Pause on record (autostream restarted since):
                # there is nothing else to restore.
                authority.resume(uid, Origin.DEVICE, requester=intent.requester)
                LOG.info("receiver play from %s: hold ended", who)
                return Outcome(ok=True, result={"action": "resumed"})
            LOG.info("receiver play from %s: not paused; ignored", who)
            return Outcome(ok=True, result={"action": "none"})
        entry = self._settle(entry, ctx.outputs)
        if entry is None:
            LOG.info("receiver play from %s: that pause is over; nothing to undo", who)
            return Outcome(ok=True, result={"action": "none"})
        self._entries.pop(entry.unit_id, None)
        was_held = self._unit_held(uid, ctx.outputs)
        restored = self._resume_all(entry, ctx.outputs, intent.requester, except_id=uid)
        LOG.info(
            "receiver play from %s: %s%s restored", who,
            "hold ended, " if was_held else "", _names(ctx.outputs, restored),
        )
        return Outcome(ok=True, result={"action": "restored"})

    def wake(self, intent: Intent, wait: float) -> Outcome:
        """A paused or muted speaker's own knob was turned. On a paused one
        it is its Play: the speaker resumes at its own level and what the
        Pause held or muted is restored. On a speaker that is only muted it unmutes
        that speaker alone, at its own level."""
        ctx: EventContext = intent.context
        uid = intent.args["id"]
        who = ctx.speaker_name or uid
        via = ctx.protocol or "?"
        unit = ctx.outputs.unit(uid)
        if unit is None:
            LOG.info("receiver wake from %s: no such speaker", who)
            return Outcome(ok=False, error="unknown_output")
        if self._paused(uid, ctx.outputs):
            LOG.info("receiver wake from %s (%s): taken as its play", who, via)
            return self.play(intent, wait)
        if unit.muted:
            get_authority().unmute(uid, Origin.DEVICE, default_level=0, requester=intent.requester)
            LOG.info("receiver wake from %s (%s): unmuted", who, via)
            return Outcome(ok=True, result={"action": "unmuted"})
        LOG.info("receiver wake from %s (%s): not paused or muted; ignored", who, via)
        return Outcome(ok=True, result={"action": "none"})


def _pause_off(intent: Intent, wait: float) -> Outcome:
    """Switch one speaker off because a Pause on it has lasted too long."""
    applied = get_authority().deselect(intent.args["id"], Origin.POLICY, requester=intent.requester)
    return Outcome(ok=applied.refused is None, error=applied.refused)


_policy = OutputPolicy()


def get_policy() -> OutputPolicy:
    return _policy


bind("receiver.pause", lambda intent, wait: _policy.pause(intent, wait), owner=_OWNER)
bind("receiver.play", lambda intent, wait: _policy.play(intent, wait), owner=_OWNER)
bind("receiver.wake", lambda intent, wait: _policy.wake(intent, wait), owner=_OWNER)
bind("outputs.pause_off", _pause_off, owner=_OWNER)
