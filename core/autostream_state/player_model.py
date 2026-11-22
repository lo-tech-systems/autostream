"""autostream_state.player_model -- what a player's rows can be taken to say.

What the output authority may conclude from a player, by what the player
reports. Two things vary between players, independently:

  session_rows    the rows carry a session object (owntone-mini), so a row
                  says whether a speaker is starting, playing or failed; a
                  player without one (upstream OwnTone) says only whether a
                  speaker is selected
  outcome_events  the player answers a speaker request at once and reports
                  how the start went as an output_state event (owntone-mini
                  with its event channel up); it then also retries a lost
                  speaker once itself

Each question the authority asks of a row is answered here, so the authority
asks it by name instead of testing a flag. Pure: no lock, no clock, no units.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from autostream_players import OutputInfo


class PendingStart(Enum):
    """What a row says of a start the authority is waiting for, when it has
    not shown its result."""
    WAIT = "wait"          # still starting
    NO_WAIT = "no_wait"    # taken with nothing playing: it starts with the playback
    FAILED = "failed"      # over, and the speaker is off: it did not start


def taking_audio(row: OutputInfo) -> bool:
    """The row's speaker takes the audio: its session is connected or
    streaming, or the row has no session (a player that says only whether
    a speaker is selected)."""
    return row.session_state in ("", "connected", "streaming")


@dataclass(frozen=True)
class PlayerModel:
    session_rows: bool = False
    outcome_events: bool = False

    @property
    def authority_retries_loss(self) -> bool:
        """A speaker lost while it played is retried by the authority: the
        player shows the loss but does not retry it itself."""
        return self.session_rows and not self.outcome_events

    @property
    def follows_hold(self) -> bool:
        """The rows say whether a speaker is held."""
        return self.session_rows

    @property
    def reselects_an_off_row(self) -> bool:
        """A wanted speaker whose row reads off is selected again. Without
        session rows an off row may be the player's own deselect (a device
        pause, a failed start), which is followed instead."""
        return self.session_rows

    @property
    def off_means_between_retries(self) -> bool:
        """A wanted speaker, off after a start of the authority's that is to
        be retried, has failed: the player cannot report it otherwise."""
        return not self.session_rows

    def availability(self, row: OutputInfo, selected: bool) -> str:
        if not self.session_rows:
            return "password" if (row.needs_auth_key or row.pin_pending) else "ok"
        state = row.session_state
        if state in ("streaming", "connected"):
            return "ok"
        if state in ("startup", "connecting"):
            return "starting"
        if state == "stopping":
            # Still ending its session: wanted again, it starts once that is done
            return "starting" if selected else "ok"
        if state == "failed":
            return "failed"
        if state == "password":
            return "password"
        return "starting" if selected else "ok"

    def connecting(self, row: OutputInfo) -> bool:
        """A wanted speaker is not playing yet."""
        if self.session_rows:
            return row.session_state != "streaming"
        return not row.selected

    def streaming(self, row: OutputInfo) -> bool:
        """The speaker plays, for the last-played-at record."""
        if self.session_rows:
            return row.session_state in ("streaming", "connected")
        return row.selected

    def result_shown(self, row: OutputInfo, availability: str) -> bool:
        """A start has shown how it went."""
        if self.session_rows:
            return row.session_state in ("streaming", "connected", "failed", "password")
        return row.selected or availability == "password"

    def pending_start(self, row: OutputInfo) -> PendingStart:
        """A start being waited for whose result the row does not show."""
        if self.outcome_events and row.selected and row.session_state == "stopped":
            return PendingStart.NO_WAIT
        if not self.session_rows and not row.selected:
            # The player answers a read only after the start it was busy with
            # has ended, so a speaker still off now did not start
            return PendingStart.FAILED
        return PendingStart.WAIT
