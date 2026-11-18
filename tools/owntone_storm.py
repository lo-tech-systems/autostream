#!/usr/bin/env python3
"""owntone_storm.py -- drive owntone-mini with bursts of speaker requests and judge it.

Talks to owntone-mini directly, over its JSON API and its event channel, with
many requests at once, and checks that every request is answered in time, that
every start and stop ends, and that the daemon logged no bug and did not grow.
It uses only the Python standard library and imports nothing from autostream,
so it can be copied to a host on its own.

    python3 tools/owntone_storm.py SCENARIO --speakers "NAME,NAME,..."
        [--base http://localhost:3689] [--socket PATH|none]
        [--repeat N] [--seed N] [--poll-hz 5]
        [--fifo PATH] [--rate HZ] [--bits 16|32] [--no-tone]
        [--firewall NAME=IP ...] [--firewall-tool auto|iptables|nft]
        [--pin-speaker NAME] [--pair NAME] [--pair-members 2]
        [--duration-s 600] [--settle-s 3] [--teardown-drop]
        [--put-p99-ms 200] [--put-max-ms 1000] [--get-p99-ms 200]
        [--stop-bound-s 2.0] [--start-bound-s 90] [--rss-growth-mib 10]
        [--log journal|PATH] [--unit owntone] [--asan-glob GLOB]
        [--expect-log NAME=COUNT ...] [--log-pattern NAME=REGEX ...]
        [--report FILE.json] [--dry-run]

Speakers are named by their row name or row id in ``GET /api/outputs``.
--pair names a stereo pair's row; --pair-members is how many sessions it
has, which is how many times each per-session log line appears for it.

Scenarios:

  S1  With the tone playing, select every named speaker in one burst (one
      thread each, released together), wait until each one is streaming, has
      failed or wants a PIN, then deselect them all in one burst and wait for
      each one that was connected or streaming to read stopped. A stop that
      lands while its speaker is still connecting waits for the start, so it
      is judged against the start bound. Repeated --repeat times.
  S2  S1 with four readers, each reading the speaker list twenty times a
      second.
  S6  S1 plus one speaker that cannot be reached (--firewall) and one that
      wants a PIN (--pin-speaker). The first must end failed, with the reason
      unreachable or timeout once rows carry reasons; the second must want a
      PIN, with the reason pin_required once rows carry reasons.
  S7  S1 while four threads keep selecting the firewalled speaker
      (--firewall). Where a select blocks the request until the speaker
      answers, each of those holds one of the daemon's four HTTP workers, so
      the burst shows whether other requests wait behind a dead speaker.
  S3  Each speaker on a thread of its own: select it, then deselect it 0,
      50, 200, 800 or 2000 ms later (in a seeded random order), --repeat
      times. Every stop of a connected or streaming speaker must read
      stopped within --stop-bound-s, one made while connecting within
      --start-bound-s, and no speaker may be left with a session. With
      --no-tone it can run against a daemon that is already playing.
  S4  Every speaker (and --pair, when given) streaming; each on its own
      thread is deselected and selected again 0, 50, 200, 1000 or 3000 ms
      later, --repeat times. Every cycle must end streaming, and with
      output_state events stopped must come before the next connecting.
  S9  S1, with hold and muted set true and false in a seeded random order
      100 ms after each select. Every reply must be 204, or 409
      not_holdable for a hold, and each speaker that streams must end with
      the hold and mute its last accepted requests asked for.
  S15 --pair and the --speakers streaming; the pair's hold is turned on
      and off every 1 to 4 s for --duration-s. Each hold must show in the
      row, each hold of an anchored pair must log one pause per member,
      and no speaker may fail.
  S16 Select --pair and set its hold 0, 50 or 200 ms later, --repeat
      times. Each member must log its pause after its anchor was accepted.
  S17 Hold --pair, deselect it, and select it again 1 or 5 s later,
      --repeat times. The stop must read stopped within --stop-bound-s and
      the pair must stream again. Run it twice: once as the daemon
      normally runs, and once with the daemon started with
      OWNTONE_STORM_DROP_TEARDOWN_ANSWERS=1 (a storm-debug build) and
      --teardown-drop given, when every member's stop must log that its
      TEARDOWN went unanswered.
  S18 Select the --firewall speaker, firewall it once it streams, set its
      volume and deselect it within a second, then lift the firewall,
      --repeat times. The stop must read stopped, never failed, within
      --stop-bound-s.
  S19 Hold --pair, then end its hold and hold it again 0, 20 or 100 ms
      later; the row must read held. Then end, start and end the hold
      within 100 ms: each member must log exactly one resume flush and one
      accepted anchor. Both, --repeat times.
  S20 Hold --pair, then select the first --speakers speaker on the same
      line. It must stream and log its anchor point reached, while the
      pair stays held and logs no resume flush. --repeat times.

Log lines are counted with these patterns (NAME: what it matches), which
--log-pattern NAME=REGEX replaces or adds to; a group named "name" in a
pattern captures the speaker's name:

  pause            Paused '...' in place after N ms
  teardown_timeout No answer to TEARDOWN from '...'
  leader_kept      ... both members advertise our group ...
  resume_flush     ...: Sending FLUSHBUFFERED (resume) to '...'
  anchor           SETRATEANCHORTIME accepted by '...' after N ms
  anchor_reached   Anchor point reached for '...'

The resume flush is a debug line, so S19 needs the daemon's AirPlay log at
debug level. --expect-log NAME=COUNT checks a pattern's count over the whole
run, COUNT being N, >=N or <=N.

Checks made for every scenario: the 99th percentile and the longest speaker
PUT; every start reaching an end state within --start-bound-s; every stop of
a connected or streaming speaker reading stopped within --stop-bound-s; no
gap in the event channel's message numbers and no dropped connection; the
99th percentile of the speaker list reads; no "Bug!" line in the daemon's
log; no new sanitiser report; the daemon's peak memory (VmHWM) growing by no
more than --rss-growth-mib. Daemons that answer a select only once the
speaker has started need --put-p99-ms and --put-max-ms raised to the start
and stop bounds (4000 is usual).

Speaker states come from the event channel's output_state events when the
daemon offers them, and otherwise from reading the list --poll-hz times a
second. The tone is a 440 Hz sine at -20 dBFS written into the pipe at its
own pace; the rate and sample size are read from the daemon's settings unless
given. With --no-tone nothing is written to the pipe and the speakers play
whatever already feeds it.

The firewall drops all traffic to and from each --firewall address while the
scenario runs and is removed afterwards, also on Ctrl-C. It uses iptables
when that is installed and nft otherwise (Raspberry Pi OS Lite has only
nft; an iptables there is the nft-backed one). --dry-run prints the rules
and the plan and touches nothing.

Run it on the host the daemon runs on, as root (the event channel admits
only root, the daemon's user and autostream's user, and the firewall needs
root), with autostream stopped so the storm owns the speaker selection, and
with the audio monitor stopped too when the tone is used. Never run it on an
appliance whose monitor is holding a buffered CD.

Every speaker the scenario touched is deselected at the end, whatever
happened. Random orders and delays come from --seed; a run without one
picks a seed and prints it, so the run can be repeated.

Exit status is 0 when every check passed, 1 when one failed, and 2 for a
setup error (a speaker not found, the daemon or its event channel not
answering, the pipe not open, the firewall not installed) or an interrupt.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import argparse
import array
import bisect
import errno
import glob
import json
import math
import os
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from dataclasses import field as dc_field

DEFAULT_BASE = "http://localhost:3689"
DEFAULT_FIFO = "/run/autostream-pipes/autostream.fifo"
DEFAULT_ASAN_GLOB = "/var/log/owntone-asan*"
SCENARIOS = ("S1", "S2", "S3", "S4", "S6", "S7", "S9", "S15", "S16", "S17", "S18", "S19", "S20")
PAIR_SCENARIOS = ("S15", "S16", "S17", "S19", "S20")
ROUND_SCENARIOS = ("S1", "S2", "S6", "S7", "S9")

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_SETUP = 2

# Row states after normalising: older daemons say "startup" for connecting.
STARTING = ("connecting", "connected")
SESSION = ("connected", "streaming")
END_STATES = ("streaming", "failed", "password")
LIVE_STATES = ("connecting", "connected", "streaming", "stopping")

STOP_DELAYS_MS = (0, 50, 200, 800, 2000)
RESELECT_DELAYS_MS = (0, 50, 200, 1000, 3000)
HOLD_DELAYS_MS = (0, 50, 200)
REHOLD_DELAYS_MS = (0, 20, 100)
RESELECT_AFTER_S = (1.0, 5.0)
FIELD_DELAY_S = 0.1
HOLD_EVERY_S = (1.0, 4.0)

LOG_PATTERNS = {
    "pause": r"Paused '(?P<name>.+?)' in place after",
    "teardown_timeout": r"No answer to TEARDOWN from '(?P<name>.+?)' in",
    "leader_kept": r"both members advertise our group",
    "resume_flush": r"Sending FLUSHBUFFERED \(resume\) to '(?P<name>.+)'\s*$",
    "anchor": r"SETRATEANCHORTIME accepted by '(?P<name>.+?)' after \d+ ms",
    "anchor_reached": r"Anchor point reached for '(?P<name>.+?)':",
}

FIREWALLED_REASONS = ("unreachable", "timeout")
PIN_REASONS = ("pin_required",)

TONE_HZ = 440
TONE_DBFS = -20.0
CHUNK_MS = 20

BUSY_WORKERS = 4
READERS = 4
READER_HZ = 20.0
PING_S = 10.0
HELLO_TIMEOUT_S = 5.0
SLACK_S = 1.0
NFT_TABLE = "owntone_storm"


class SetupError(Exception):
    """The scenario could not be set up; nothing was judged."""


def percentile(values, p: float):
    """The nearest-rank *p*th percentile of *values*, or None when empty."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(p / 100.0 * len(ordered)))
    return ordered[rank - 1]


def normalise_state(state) -> str:
    if not state:
        return "stopped"
    return "connecting" if state == "startup" else str(state)


def state_at(transitions, t: float):
    """The state a row was in at time *t*, from its (time, state) changes."""
    state = None
    for when, s in transitions:
        if when > t:
            break
        state = s
    return state


def delay_plan(rng: random.Random, delays, count: int) -> list:
    """*count* delays taken from *delays* in shuffled rounds, so each one is
    used about equally often, in an order fixed by *rng*'s seed."""
    plan: list = []
    while len(plan) < count:
        block = list(delays)
        rng.shuffle(block)
        plan.extend(block)
    return plan[:count]


def field_reply_ok(fields: dict, status, body) -> bool:
    """A hold or mute request is answered 204, or 409 not_holdable for a
    hold the speaker cannot take now (while connecting or stopping)."""
    if status == 204:
        return True
    return (status == 409 and "hold" in fields and isinstance(body, dict)
            and body.get("error") == "not_holdable")


def stop_precedes_connect(transitions, after: float) -> bool:
    """Whether, from *after*, the row read stopped before it next read
    connecting (a restart that skips its stop is the fault)."""
    stopped = False
    for when, state in transitions:
        if when < after:
            continue
        if state == "stopped":
            stopped = True
        elif state == "connecting":
            return stopped
    return True


def _sleep_until(deadline: float) -> None:
    left = deadline - time.monotonic()
    if left > 0:
        time.sleep(left)


def row_state(row) -> str:
    return normalise_state(((row or {}).get("session") or {}).get("state"))


def row_held(row) -> bool:
    return ((row or {}).get("session") or {}).get("held") is True


def row_muted(row) -> bool:
    return (row or {}).get("muted") is True


def row_idle(row) -> bool:
    """Not selected and with no session starting, playing or stopping."""
    return not row.get("selected") and row_state(row) not in LIVE_STATES


def expected_flags(replies) -> tuple:
    """(held, muted) as the last accepted hold and mute requests among
    *replies*, (request, status) pairs, left them; False when none was."""
    held = muted = False
    for fields, status in replies:
        if status != 204:
            continue
        if "hold" in fields:
            held = bool(fields["hold"])
        if "muted" in fields:
            muted = bool(fields["muted"])
    return held, muted


def once_per_member(per_speaker: dict, members: int) -> bool:
    """Exactly one line for each of *members* speakers. Lines whose pattern
    names no speaker are only counted."""
    total = sum(per_speaker.values())
    if set(per_speaker) <= {""}:
        return total == members
    return total == members and all(n == 1 for n in per_speaker.values())


def pause_after_anchor(sequence, members: int) -> tuple:
    """From (pattern, speaker) lines in order: whether each of *members*
    speakers logged one pause, after its own accepted anchor. (ok, detail)."""
    anchored: set = set()
    paused: dict = {}
    for kind, who in sequence:
        if kind == "anchor":
            anchored.add(who)
        elif kind == "pause":
            if who not in anchored:
                return False, f"{who or 'a member'} paused before its anchor was accepted"
            paused[who] = paused.get(who, 0) + 1
    if not once_per_member(paused, members):
        return False, f"pause lines per member: {paused or 'none'}"
    return True, ""


# --- log lines -----------------------------------------------------------------

class LogPatterns:
    """The named log patterns, compiled. A group called "name" captures the
    speaker a line is about."""

    def __init__(self, overrides=None):
        table = dict(LOG_PATTERNS)
        for value in overrides or []:
            name, sep, regex = value.partition("=")
            if not sep or not name or not regex:
                raise SetupError(f"--log-pattern wants NAME=REGEX, not {value!r}")
            table[name] = regex
        try:
            self.compiled = {name: re.compile(regex) for name, regex in table.items()}
        except re.error as exc:
            raise SetupError(f"--log-pattern: {exc}") from exc

    def count(self, lines) -> dict:
        """How many lines match each pattern."""
        counts = {name: 0 for name in self.compiled}
        for line in lines:
            for name, rx in self.compiled.items():
                if rx.search(line):
                    counts[name] += 1
        return counts

    def per_speaker(self, lines, name: str) -> dict:
        """How many lines match pattern *name*, per speaker named in them."""
        rx = self.compiled[name]
        out: dict = {}
        for line in lines:
            m = rx.search(line)
            if m:
                who = m.groupdict().get("name") or ""
                out[who] = out.get(who, 0) + 1
        return out

    def sequence(self, lines, names) -> list:
        """(pattern, speaker) for each line matching one of *names*, in order."""
        out = []
        for line in lines:
            for name in names:
                m = self.compiled[name].search(line)
                if m:
                    out.append((name, m.groupdict().get("name") or ""))
                    break
        return out


def parse_expectations(values) -> list:
    """--expect-log NAME=COUNT, COUNT being N, >=N or <=N, as (name, op, n)."""
    out = []
    for value in values or []:
        # NAME=3, NAME=>=3 and NAME>=3 are all accepted
        m = re.fullmatch(r"([^=<>]+)(=?)(>=|<=)?(\d+)", value.strip())
        if not m or not (m.group(2) or m.group(3)):
            raise SetupError(f"--expect-log wants NAME=COUNT, NAME=>=COUNT or NAME=<=COUNT, not {value!r}")
        out.append((m.group(1).strip(), m.group(3) or "==", int(m.group(4))))
    return out


def check_log_counts(counts: dict, expectations) -> list:
    """(check name, ok, detail) for each expectation against *counts*."""
    out = []
    for name, op, n in expectations:
        got = counts.get(name)
        if got is None:
            out.append((f"log {name} {op} {n}", False, "no such pattern"))
            continue
        ok = got == n if op == "==" else (got >= n if op == ">=" else got <= n)
        out.append((f"log {name} {op} {n}", ok, f"{got} line(s)"))
    return out


# --- judging -----------------------------------------------------------------

@dataclass
class Outcome:
    ok: bool
    state: str | None = None
    elapsed: float | None = None
    detail: str = ""
    needed: bool = True


def judge_start(transitions, sent: float, bound_s: float, replied=None, read_after_reply=None) -> Outcome:
    """Judge one select from the row's state changes.

    The start has ended at the first change after *sent* to streaming,
    failed or password, or to stopped once a connecting state was seen (a
    select made while nothing plays only probes the speaker). When the
    states come from polling and the daemon answers a select only once the
    start is over, *replied* is when the answer came and *read_after_reply*
    the first read after it: an end state in that read ends the start at the
    reply, which covers a start too quick for the poller to see."""
    started = False
    for when, state in transitions:
        if when < sent:
            continue
        if state in STARTING:
            started = True
        if state in END_STATES or (state == "stopped" and started):
            elapsed = when - sent
            return Outcome(elapsed <= bound_s, state, elapsed,
                           "" if elapsed <= bound_s else f"ended after {elapsed:.1f} s")
    if replied is not None and read_after_reply is not None:
        state = state_at(transitions, read_after_reply)
        if state in END_STATES or state == "stopped":
            elapsed = replied - sent
            return Outcome(elapsed <= bound_s, state, elapsed,
                           "" if elapsed <= bound_s else f"ended after {elapsed:.1f} s")
    return Outcome(False, state_at(transitions, math.inf), None, "no end state seen")


def judge_stop(transitions, sent: float, stop_bound_s: float, start_bound_s: float, prior=None) -> Outcome:
    """Judge one deselect from the row's state changes.

    A speaker that was connected or streaming must read stopped within the
    stop bound. One that was still connecting finishes its start first, so
    it must read stopped within the start bound. Any other speaker had
    nothing to stop."""
    if prior is None:
        prior = state_at(transitions, sent)
    if prior in SESSION:
        bound, what = stop_bound_s, "stop"
    elif prior == "connecting":
        bound, what = start_bound_s, "stop while connecting"
    else:
        return Outcome(True, prior, None, "nothing to stop", needed=False)
    for when, state in transitions:
        if when < sent:
            continue
        if state == "stopped":
            elapsed = when - sent
            return Outcome(elapsed <= bound, state, elapsed,
                           what if elapsed <= bound else f"{what} took {elapsed:.1f} s")
        if state == "failed":
            return Outcome(False, state, when - sent, f"{what} ended failed, not stopped")
    return Outcome(False, state_at(transitions, math.inf), None, f"{what}: stopped not seen")


# --- state sources -------------------------------------------------------------

class Timeline:
    """Per row, the state changes seen as (monotonic time, state), and the
    row's latest fields."""

    def __init__(self):
        self._lock = threading.Lock()
        self._changes: dict[str, list] = {}
        self._last: dict[str, dict] = {}

    def record(self, row_id: str, state, t: float | None = None, **fields) -> bool:
        t = time.monotonic() if t is None else t
        state = normalise_state(state)
        with self._lock:
            last = self._last.setdefault(row_id, {})
            last.update({k: v for k, v in fields.items() if v is not None})
            changes = self._changes.setdefault(row_id, [])
            if changes and changes[-1][1] == state:
                return False
            changes.append((t, state))
            last["state"] = state
            return True

    def transitions(self, row_id: str) -> list:
        with self._lock:
            return list(self._changes.get(row_id, ()))

    def last(self, row_id: str) -> dict:
        with self._lock:
            return dict(self._last.get(row_id, {}))


class SeqCounter:
    """Checks that the server's message numbers count up from 1 on each
    connection without a gap."""

    def __init__(self):
        self.expected = 1
        self.connections = 0
        self.gaps: list[str] = []

    def new_connection(self) -> None:
        self.connections += 1
        self.expected = 1

    def see(self, seq) -> None:
        if not isinstance(seq, int):
            return
        if seq != self.expected:
            self.gaps.append(f"connection {self.connections}: expected {self.expected}, got {seq}")
        self.expected = seq + 1


class Events:
    """A client of the daemon's event channel on a thread of its own: keeps
    every message with the time it arrived, the server's capabilities, the
    message-number check and, from output_state events, a timeline per row.
    A dropped connection is counted and opened again."""

    def __init__(self, path: str | None = None, connect=None, client: str = "owntone-storm",
                 ping_s: float = PING_S):
        self._connect = connect or (lambda: self._unix(path))
        self.client = client
        self.ping_s = ping_s
        self.messages: list = []
        self.capabilities: list = []
        self.errors: list = []
        self.drops = 0
        self.seq = SeqCounter()
        self.timeline = Timeline()
        self._sock = None
        self._buf = b""
        self._send_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    @staticmethod
    def _unix(path):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(path)
        return sock

    def start(self) -> None:
        try:
            self._open()
        except (OSError, EOFError, ValueError) as exc:
            raise SetupError(f"event channel: {exc}") from exc
        self._thread = threading.Thread(target=self._loop, name="storm-events", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._send({"type": "goodbye"})
        except OSError:
            pass
        if self._thread:
            self._thread.join(3.0)
        self._close()

    def has(self, capability: str) -> bool:
        return capability in self.capabilities

    def _open(self) -> None:
        self._sock = self._connect()
        self._buf = b""
        self.seq.new_connection()
        self._send({"type": "hello", "protocol": 1, "client": self.client})
        line = self._line(HELLO_TIMEOUT_S)
        if line is None:
            raise EOFError("no hello from the server")
        msg = json.loads(line)
        self._handle(msg, time.monotonic())
        if msg.get("type") != "hello":
            raise ValueError(f"the server answered {msg.get('type')} {msg.get('code', '')}".strip())

    def _close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _send(self, obj) -> None:
        sock = self._sock
        if sock is None:
            return
        with self._send_lock:
            sock.sendall(json.dumps(obj, separators=(",", ":")).encode("utf-8") + b"\n")

    def _line(self, timeout: float):
        """The next line, None on timeout; EOFError when the server closed."""
        end = time.monotonic() + timeout
        while b"\n" not in self._buf:
            left = end - time.monotonic()
            if left <= 0:
                return None
            self._sock.settimeout(min(left, 0.5))
            try:
                data = self._sock.recv(65536)
            except socket.timeout:
                continue
            except ConnectionResetError:
                data = b""
            if not data:
                raise EOFError("the server closed the connection")
            self._buf += data
        line, _, self._buf = self._buf.partition(b"\n")
        return line.decode("utf-8", "replace")

    def _loop(self) -> None:
        next_ping = time.monotonic() + self.ping_s
        while not self._stop.is_set():
            try:
                line = self._line(0.5)
                if line:
                    self._handle(json.loads(line), time.monotonic())
                if time.monotonic() >= next_ping:
                    self._send({"type": "ping", "t": int(time.time())})
                    next_ping = time.monotonic() + self.ping_s
            except ValueError:
                continue
            except (EOFError, OSError):
                if self._stop.is_set():
                    return
                self.drops += 1
                self._close()
                self._reopen()
                next_ping = time.monotonic() + self.ping_s

    def _reopen(self) -> None:
        while not self._stop.is_set():
            try:
                self._open()
                return
            except (OSError, EOFError, ValueError):
                self._close()
                self._stop.wait(1.0)

    def _handle(self, msg: dict, t: float) -> None:
        self.seq.see(msg.get("seq"))
        self.messages.append((t, msg))
        kind = msg.get("type")
        if kind == "hello":
            self.capabilities = list(msg.get("capabilities") or [])
        elif kind == "error":
            self.errors.append(f"{msg.get('code')}: {msg.get('text', '')}")
        elif kind == "event" and msg.get("kind") == "output_state":
            speaker = msg.get("speaker") or {}
            row_id = str(speaker.get("id", ""))
            if row_id:
                self.timeline.record(row_id, msg.get("state"), t, reason=msg.get("reason"),
                                     pin_pending=msg.get("pin_pending"), selected=msg.get("selected"),
                                     held=msg.get("held"), muted=msg.get("muted"))


class Api:
    """The daemon's JSON API. Every request is recorded as (kind, status,
    milliseconds); status is the HTTP code, or "timeout" or "error"."""

    def __init__(self, base: str = DEFAULT_BASE, timeout: float = 10.0):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.samples: list = []
        self._lock = threading.Lock()

    def request(self, kind: str, method: str, path: str, body=None):
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        started = time.monotonic()
        status, payload = "error", None
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status, payload = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, payload = exc.code, exc.read()
        except (TimeoutError, socket.timeout):
            status = "timeout"
        except urllib.error.URLError as exc:
            status = "timeout" if isinstance(exc.reason, (TimeoutError, socket.timeout)) else "error"
        except OSError:
            status = "error"
        ms = (time.monotonic() - started) * 1000.0
        with self._lock:
            self.samples.append((kind, status, ms))
        parsed = None
        if payload:
            try:
                parsed = json.loads(payload.decode("utf-8"))
            except ValueError:
                parsed = None
        return status, parsed

    def get_outputs(self, kind: str = "get"):
        status, body = self.request(kind, "GET", "/api/outputs")
        if status == 200 and isinstance(body, dict):
            return body.get("outputs") or []
        return None

    def put_output(self, row_id: str, fields: dict, kind: str = "put"):
        return self.request(kind, "PUT", f"/api/outputs/{row_id}", fields)[0]

    def put_fields(self, row_id: str, fields: dict, kind: str = "field"):
        """A speaker PUT whose reply body matters: (status, parsed body)."""
        return self.request(kind, "PUT", f"/api/outputs/{row_id}", fields)

    def get_row(self, row_id: str, kind: str = "check"):
        outputs = self.get_outputs(kind=kind)
        if outputs is None:
            return None
        return next((r for r in outputs if str(r.get("id")) == str(row_id)), None)

    def put_set(self, ids, kind: str = "put"):
        return self.request(kind, "PUT", "/api/outputs/set", {"outputs": [str(i) for i in ids]})[0]

    def put_update(self, kind: str = "update"):
        return self.request(kind, "PUT", "/api/update")[0]

    def config(self):
        status, body = self.request("config", "GET", "/api/config")
        return body if status == 200 and isinstance(body, dict) else None

    def setting(self, category: str, option: str):
        status, body = self.request("config", "GET", f"/api/settings/{category}/{option}")
        return body.get("value") if status == 200 and isinstance(body, dict) else None

    def latencies(self, *kinds) -> list:
        with self._lock:
            return [ms for k, _, ms in self.samples if k in kinds]

    def summary(self) -> dict:
        with self._lock:
            samples = list(self.samples)
        out = {}
        for kind in sorted({k for k, _, _ in samples}):
            ms = [m for k, _, m in samples if k == kind]
            statuses: dict = {}
            for k, s, _ in samples:
                if k == kind:
                    statuses[str(s)] = statuses.get(str(s), 0) + 1
            out[kind] = {"count": len(ms), "p50_ms": round(percentile(ms, 50), 1),
                         "p99_ms": round(percentile(ms, 99), 1), "max_ms": round(max(ms), 1),
                         "statuses": statuses}
        return out


class Poller:
    """Reads the speaker list *hz* times a second, turning each row's
    session.state into a timeline of changes, and counts reads in which a
    watched row was missing."""

    def __init__(self, api: Api, hz: float = 5.0):
        self.api = api
        self.hz = hz
        self.timeline = Timeline()
        self.reads: list = []
        self.missing: dict[str, int] = {}
        self._watched: set = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def watch(self, ids) -> None:
        self._watched = set(ids)

    def ingest(self, outputs, t: float | None = None) -> None:
        t = time.monotonic() if t is None else t
        seen = set()
        for row in outputs:
            row_id = str(row.get("id", ""))
            seen.add(row_id)
            session = row.get("session") or {}
            self.timeline.record(row_id, session.get("state"), t, reason=session.get("failure"),
                                 pin_pending=row.get("pin_pending"), selected=row.get("selected"),
                                 name=row.get("name"), held=session.get("held"), muted=row.get("muted"))
        with self._lock:
            for row_id in self._watched - seen:
                self.missing[row_id] = self.missing.get(row_id, 0) + 1
            self.reads.append(t)

    def read_after(self, t: float):
        """The time of the first read that began after *t*, or None."""
        with self._lock:
            i = bisect.bisect_right(self.reads, t)
            return self.reads[i] if i < len(self.reads) else None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="storm-poller", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(self.api.timeout + 2.0)

    def _loop(self) -> None:
        period = 1.0 / self.hz
        while not self._stop.is_set():
            began = time.monotonic()
            outputs = self.api.get_outputs()
            if outputs is not None:
                self.ingest(outputs, began)
            self._stop.wait(max(0.0, period - (time.monotonic() - began)))


# --- load ------------------------------------------------------------------------

def chunk_frames(rate: int) -> int:
    return rate * CHUNK_MS // 1000


def tone_second(rate: int, bits: int) -> bytes:
    """One second of a 440 Hz stereo sine at -20 dBFS as signed little-endian
    samples. A whole number of cycles fits in a second, so it repeats without
    a click."""
    if bits not in (16, 32):
        raise ValueError(f"unsupported sample size {bits}")
    peak = (2 ** (bits - 1) - 1) * 10 ** (TONE_DBFS / 20.0)
    samples = array.array("h" if bits == 16 else "i")
    step = 2.0 * math.pi * TONE_HZ / rate
    for n in range(rate):
        v = int(round(peak * math.sin(step * n)))
        samples.append(v)
        samples.append(v)
    if sys.byteorder == "big":
        samples.byteswap()
    return samples.tobytes()


def tone_chunks(rate: int, bits: int):
    """Endless 20 ms chunks of the tone."""
    second = tone_second(rate, bits)
    size = chunk_frames(rate) * 2 * bits // 8
    while True:
        for i in range(0, len(second), size):
            yield second[i:i + size]


class Tone:
    """Writes the tone into the pipe at real-time pace on a thread. Closing
    the pipe ends the daemon's pipe session."""

    def __init__(self, path: str, rate: int, bits: int, open_wait_s: float = 5.0):
        self.path = path
        self.rate = rate
        self.bits = bits
        self.open_wait_s = open_wait_s
        self._fd = None
        self._stop = threading.Event()
        self._thread = None
        self.short_writes = 0

    def start(self) -> None:
        end = time.monotonic() + self.open_wait_s
        while True:
            try:
                self._fd = os.open(self.path, os.O_WRONLY | os.O_NONBLOCK)
                break
            except OSError as exc:
                if exc.errno != errno.ENXIO or time.monotonic() >= end:
                    raise SetupError(f"pipe {self.path}: {exc}") from exc
                time.sleep(0.2)
        os.set_blocking(self._fd, True)
        self._thread = threading.Thread(target=self._loop, name="storm-tone", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(2.0)
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None

    def _loop(self) -> None:
        deadline = time.monotonic()
        for chunk in tone_chunks(self.rate, self.bits):
            if self._stop.is_set():
                return
            try:
                os.write(self._fd, chunk)
            except OSError:
                self.short_writes += 1
                return
            deadline += CHUNK_MS / 1000.0
            delay = deadline - time.monotonic()
            if delay > 0:
                self._stop.wait(delay)
            elif delay < -1.0:
                deadline = time.monotonic()


class Firewall:
    """Drops all traffic to and from the given addresses while in use.
    Rules are added in order and removed in reverse, also when the block
    is left by an exception or Ctrl-C."""

    def __init__(self, addresses, tool: str = "auto", dry_run: bool = False,
                 run=subprocess.run, which=None, euid=None, out=print):
        self.addresses = list(addresses)
        self.dry_run = dry_run
        self._run = run
        self._out = out
        euid = os.geteuid() if euid is None else euid
        self._prefix = [] if euid == 0 else ["sudo", "-n"]
        if tool == "auto":
            # A user's PATH often lacks the sbin directories the tools live in.
            which = which or (lambda name: shutil.which(
                name, path=os.pathsep.join([os.environ.get("PATH", ""), "/usr/sbin", "/sbin"])))
            tool = "iptables" if which("iptables") else "nft"
        self.tool = tool
        self._added: list = []

    def add_commands(self) -> list:
        cmds = []
        if self.tool == "iptables":
            for ip in self.addresses:
                exe = "ip6tables" if ":" in ip else "iptables"
                cmds.append([exe, "-I", "OUTPUT", "-d", ip, "-j", "DROP"])
                cmds.append([exe, "-I", "INPUT", "-s", ip, "-j", "DROP"])
        else:
            cmds.append(["nft", "add", "table", "inet", NFT_TABLE])
            cmds.append(["nft", "add", "chain", "inet", NFT_TABLE, "out",
                         "{ type filter hook output priority 0 ; }"])
            cmds.append(["nft", "add", "chain", "inet", NFT_TABLE, "in",
                         "{ type filter hook input priority 0 ; }"])
            for ip in self.addresses:
                family = "ip6" if ":" in ip else "ip"
                cmds.append(["nft", "add", "rule", "inet", NFT_TABLE, "out", family, "daddr", ip, "drop"])
                cmds.append(["nft", "add", "rule", "inet", NFT_TABLE, "in", family, "saddr", ip, "drop"])
        return [self._prefix + c for c in cmds]

    def remove_commands(self, added=None) -> list:
        added = self.add_commands() if added is None else added
        if self.tool == "iptables":
            return [[("-D" if a == "-I" else a) for a in c] for c in reversed(added)]
        return [self._prefix + ["nft", "delete", "table", "inet", NFT_TABLE]] if added else []

    def __enter__(self):
        for cmd in self.add_commands():
            if self.dry_run:
                self._out("would run: " + " ".join(cmd))
                continue
            result = self._run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                self._remove()
                raise SetupError(f"firewall: {' '.join(cmd)} failed: {(result.stderr or '').strip()}")
            self._added.append(cmd)
        return self

    def __exit__(self, *exc):
        self._remove()
        return False

    def _remove(self) -> None:
        if self.dry_run:
            for cmd in self.remove_commands():
                self._out("would run: " + " ".join(cmd))
            return
        for cmd in self.remove_commands(self._added):
            result = self._run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                self._out(f"firewall: could not remove a rule: {' '.join(cmd)}")
        self._added = []


class Busy:
    """Keeps selecting one speaker from four threads at once. Against a
    speaker that cannot be reached, each select is a start that runs until
    the speaker gives up."""

    def __init__(self, api: Api, row_id: str, workers: int = BUSY_WORKERS):
        self.api = api
        self.row_id = row_id
        self.workers = workers
        self._stop = threading.Event()
        self._threads: list = []

    def start(self) -> None:
        for i in range(self.workers):
            t = threading.Thread(target=self._loop, name=f"storm-busy-{i}", daemon=True)
            self._threads.append(t)
            t.start()

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(self.api.timeout + 2.0)

    def _loop(self) -> None:
        while not self._stop.is_set():
            began = time.monotonic()
            self.api.put_output(self.row_id, {"selected": True}, kind="busy")
            if time.monotonic() - began < 0.2:
                self._stop.wait(0.2)


class Readers:
    """Readers of the speaker list, each at *hz*."""

    def __init__(self, api: Api, count: int = READERS, hz: float = READER_HZ):
        self.api = api
        self.count = count
        self.hz = hz
        self._stop = threading.Event()
        self._threads: list = []

    def start(self) -> None:
        for i in range(self.count):
            t = threading.Thread(target=self._loop, name=f"storm-reader-{i}", daemon=True)
            self._threads.append(t)
            t.start()

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(self.api.timeout + 2.0)

    def _loop(self) -> None:
        period = 1.0 / self.hz
        while not self._stop.is_set():
            began = time.monotonic()
            self.api.get_outputs()
            self._stop.wait(max(0.0, period - (time.monotonic() - began)))


# --- the daemon's health -------------------------------------------------------------

def find_pid(name: str = "owntone", proc: str = "/proc"):
    for comm in glob.glob(os.path.join(proc, "[0-9]*", "comm")):
        try:
            with open(comm, encoding="utf-8") as f:
                if f.read().strip() == name:
                    return int(os.path.basename(os.path.dirname(comm)))
        except (OSError, ValueError):
            continue
    return None


def read_memory(pid: int, proc: str = "/proc") -> dict:
    """VmHWM and VmRSS of *pid* in KiB."""
    out = {}
    try:
        with open(os.path.join(proc, str(pid), "status"), encoding="utf-8") as f:
            for line in f:
                key, _, rest = line.partition(":")
                if key in ("VmHWM", "VmRSS"):
                    out[key] = int(rest.split()[0])
    except (OSError, ValueError, IndexError):
        pass
    return out


BUG_MARK = "Bug!"
SANITISER_MARKS = ("AddressSanitizer", "LeakSanitizer", "runtime error:")


class Probe:
    """The daemon's memory over the run, and what it logged."""

    def __init__(self, log: str = "journal", unit: str = "owntone", asan_glob: str = DEFAULT_ASAN_GLOB,
                 proc: str = "/proc", run=subprocess.run, process: str = "owntone"):
        self.log = log
        self.unit = unit
        self.asan_glob = asan_glob
        self.proc = proc
        self.process = process
        self._run = run
        self.memory: list = []
        self.started_at = None
        self.pid = None
        self._log_offset = 0
        self._watch_offset = 0
        self._cursor = None
        self._sanitiser_before: dict = {}

    def begin(self) -> None:
        self.started_at = time.time()
        self.pid = find_pid(self.process, self.proc)
        if self.log != "journal":
            try:
                self._log_offset = os.path.getsize(self.log)
            except OSError:
                self._log_offset = 0
            self._watch_offset = self._log_offset
        self._sanitiser_before = self._sanitiser_files()
        self.sample("start")

    def sample(self, label: str) -> None:
        if self.pid is None:
            return
        mem = read_memory(self.pid, self.proc)
        if mem:
            self.memory.append({"at": label, **mem})

    def hwm_growth_mib(self):
        hwm = [m["VmHWM"] for m in self.memory if "VmHWM" in m]
        if len(hwm) < 2:
            return None
        return (max(hwm) - hwm[0]) / 1024.0

    def log_lines(self):
        """The daemon's log since the start as (lines, error)."""
        if self.log == "journal":
            cmd = ["journalctl", "-u", self.unit, "-o", "cat", "--no-pager",
                   "--since", f"@{int(self.started_at or 0)}"]
            try:
                result = self._run(cmd, capture_output=True, text=True)
            except OSError as exc:
                return [], f"journalctl: {exc}"
            err = result.stderr or ""
            if result.returncode != 0 or "insufficient permissions" in err or "No journal files were opened" in err:
                return [], f"journal not readable: {err.strip() or result.returncode}"
            return result.stdout.splitlines(), None
        try:
            with open(self.log, encoding="utf-8", errors="replace") as f:
                f.seek(self._log_offset)
                return f.read().splitlines(), None
        except OSError as exc:
            return [], f"log not readable: {exc}"

    def new_log_lines(self):
        """The daemon's log lines since the last call (since the start on
        the first), as (lines, error). A partly written last line is left
        for the next call."""
        if self.log == "journal":
            cmd = ["journalctl", "-u", self.unit, "-o", "cat", "--no-pager", "-q", "--show-cursor"]
            cmd += (["--after-cursor", self._cursor] if self._cursor
                    else ["--since", f"@{int(self.started_at or 0)}"])
            try:
                result = self._run(cmd, capture_output=True, text=True)
            except OSError as exc:
                return [], f"journalctl: {exc}"
            if result.returncode != 0:
                return [], f"journal not readable: {(result.stderr or '').strip() or result.returncode}"
            lines = result.stdout.splitlines()
            if lines and lines[-1].startswith("-- cursor: "):
                self._cursor = lines.pop()[len("-- cursor: "):]
            return lines, None
        try:
            with open(self.log, "rb") as f:
                f.seek(self._watch_offset)
                data = f.read()
        except OSError as exc:
            return [], f"log not readable: {exc}"
        end = data.rfind(b"\n") + 1
        self._watch_offset += end
        return data[:end].decode("utf-8", "replace").splitlines(), None

    def _sanitiser_files(self) -> dict:
        out = {}
        for path in glob.glob(self.asan_glob):
            try:
                out[path] = os.path.getsize(path)
            except OSError:
                pass
        return out

    def new_sanitiser_files(self) -> list:
        """Sanitiser logs that appeared or grew since the start."""
        now = self._sanitiser_files()
        return sorted(p for p, size in now.items() if size > self._sanitiser_before.get(p, -1))


# --- the verdict ---------------------------------------------------------------------

class Verdict:
    """Named checks; a check whose ok is None was not made and fails nothing."""

    def __init__(self, out=print):
        self.checks: list = []
        self._out = out

    def add(self, name: str, ok, detail: str = "") -> None:
        self.checks.append((name, ok, detail))

    @property
    def ok(self) -> bool:
        return all(ok is not False for _, ok, _ in self.checks)

    def show(self) -> None:
        for name, ok, detail in self.checks:
            word = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
            self._out(f"{word} {name}" + (f": {detail}" if detail else ""))

    def report(self, **extra) -> dict:
        return {"ok": self.ok,
                "checks": [{"name": n, "ok": ok, "detail": d} for n, ok, d in self.checks],
                **extra}

    def write(self, path: str, **extra) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.report(**extra), f, indent=2, sort_keys=True)
            f.write("\n")


class Tally:
    """Per named check, how many times it was made and what failed, from
    any thread; each becomes one line of the verdict."""

    def __init__(self):
        self._lock = threading.Lock()
        self._checks: dict = {}

    def add(self, name: str, ok: bool, detail: str = "") -> None:
        with self._lock:
            made, failed = self._checks.setdefault(name, [0, []])
            self._checks[name][0] = made + 1
            if not ok:
                failed.append(detail)

    def items(self) -> list:
        """(name, ok, detail) per check, in the order first made."""
        with self._lock:
            return [(name, not failed, "; ".join(failed[:5]) if failed else f"{made} made")
                    for name, (made, failed) in self._checks.items()]


# --- the scenario ------------------------------------------------------------------

@dataclass
class Speaker:
    row_id: str
    name: str
    role: str = "burst"
    ip: str | None = None


@dataclass
class Op:
    speaker: Speaker
    selected: bool
    sent: float = 0.0
    replied: float | None = None
    status: object = None
    prior: str | None = None
    outcome: Outcome | None = None
    fields: list = dc_field(default_factory=list)   # (request, status) of S9's hold and mute PUTs


def resolve(outputs, wanted: str):
    key = wanted.strip()
    for row in outputs:
        if str(row.get("id")) == key:
            return row
    for row in outputs:
        if str(row.get("name", "")).casefold() == key.casefold():
            return row
    return None


def parse_firewall(values) -> list:
    out = []
    for value in values or []:
        name, sep, ip = value.rpartition("=")
        if not sep or not name or not ip:
            raise SetupError(f"--firewall wants NAME=IP, not {value!r}")
        out.append((name, ip))
    return out


def requirement_error(args, firewall) -> str | None:
    """What the scenario needs and was not given, or None."""
    scenario = args.scenario
    if scenario in ("S6", "S7", "S18") and not firewall:
        return f"{scenario} needs --firewall NAME=IP"
    if scenario == "S6" and not args.pin_speaker:
        return "S6 needs --pin-speaker NAME"
    if scenario in PAIR_SCENARIOS and not args.pair:
        return f"{scenario} needs --pair NAME"
    if scenario in ("S15", "S20") and not [n for n in (args.speakers or "").split(",") if n.strip()]:
        return f"{scenario} needs a speaker in --speakers to play beside the pair"
    if scenario == "S18" and len(firewall) != 1:
        return "S18 takes exactly one --firewall NAME=IP"
    return None


class Storm:
    """Runs one scenario and judges it. The parts are passed in so a test
    can replace the daemon, the pipe and the firewall."""

    def __init__(self, args, api: Api, events: Events | None, poller: Poller, probe: Probe,
                 tone: Tone | None, firewall: Firewall | None, out=print):
        self.args = args
        self.api = api
        self.events = events
        self.poller = poller
        self.probe = probe
        self.tone = tone
        self.firewall = firewall
        self.out = out
        self.verdict = Verdict(out)
        self.speakers: list = []
        self.starts: list = []
        self.stops: list = []
        if args.seed is None:
            args.seed = random.SystemRandom().randrange(1 << 31)
        self.rng = random.Random(args.seed)
        self.tally = Tally()
        self.patterns = None
        self.expectations: list = []
        self.log_counts: dict = {}
        self.pair = None
        self._ops_lock = threading.Lock()
        self._busy = None
        self._readers = None

    # Which source the timelines come from: events when the daemon reports
    # each speaker's state, otherwise the poller.
    def _event_driven(self) -> bool:
        return self.events is not None and self.events.has("output_state")

    def _timeline(self) -> Timeline:
        return self.events.timeline if self._event_driven() else self.poller.timeline

    def run(self) -> int:
        code = EXIT_OK
        stack = []
        try:
            self._setup(stack)
            self.out(f"scenario {self.args.scenario}, seed {self.args.seed}")
            if self.args.scenario in ROUND_SCENARIOS:
                for i in range(self.args.repeat):
                    self._round([s for s in self.speakers if s.role != "busy"])
                    self.probe.sample(f"repeat {i + 1}")
            else:
                getattr(self, f"_run_{self.args.scenario.lower()}")()
        except SetupError as exc:
            self.out(f"setup: {exc}")
            code = EXIT_SETUP
        except KeyboardInterrupt:
            self.out("interrupted")
            code = EXIT_SETUP
        finally:
            self._cleanup(stack)
        if code != EXIT_OK:
            return code
        self.probe.sample("end")
        self._judge()
        self.verdict.show()
        if self.args.report:
            self.verdict.write(self.args.report, **self._report_extra())
        return EXIT_OK if self.verdict.ok else EXIT_FAIL

    def _setup(self, stack: list) -> None:
        outputs = self.api.get_outputs(kind="setup")
        if outputs is None:
            raise SetupError(f"no speaker list from {self.api.base}")
        names = [n for n in (self.args.speakers or "").split(",") if n.strip()]
        firewall = parse_firewall(self.args.firewall)
        problem = requirement_error(self.args, firewall)
        if problem:
            raise SetupError(problem)
        self.patterns = LogPatterns(self.args.log_pattern)
        self.expectations = parse_expectations(self.args.expect_log)
        wanted = [(n, "burst", None) for n in names]
        fw_role = "busy" if self.args.scenario == "S7" else "firewalled"
        wanted += [(n, fw_role, ip) for n, ip in firewall]
        if self.args.scenario == "S6":
            wanted.append((self.args.pin_speaker, "pin", None))
        if self.args.pair:
            wanted.append((self.args.pair, "pair", None))
        # A speaker named twice takes its last role: a firewalled or PIN
        # speaker also listed in --speakers is not selected as a plain one.
        chosen: dict[str, Speaker] = {}
        for name, role, ip in wanted:
            row = resolve(outputs, name)
            if row is None:
                known = ", ".join(str(r.get("name")) for r in outputs)
                raise SetupError(f"no speaker {name!r} (known: {known})")
            row_id = str(row["id"])
            chosen[row_id] = Speaker(row_id, str(row.get("name", row_id)), role, ip)
        self.speakers = list(chosen.values())
        self.pair = next((s for s in self.speakers if s.role == "pair"), None)
        if not any(s.role != "busy" for s in self.speakers):
            raise SetupError("no speakers to select (--speakers)")
        self.poller.ingest(outputs)
        self.poller.watch([s.row_id for s in self.speakers])
        self.probe.begin()
        if self.events is not None:
            self.events.start()
            stack.append(self.events.stop)
        self.poller.start()
        stack.append(self.poller.stop)
        stack.append(self._deselect_all)
        self._settle_selected(outputs)
        # S18 raises its firewall only while it means to, once per cycle
        if self.firewall is not None and self.args.scenario != "S18":
            self.firewall.__enter__()
            stack.append(lambda: self.firewall.__exit__(None, None, None))
        if self.tone is not None:
            self.tone.start()
            stack.append(self.tone.stop)
            time.sleep(self.args.tone_settle_s)
        if self.args.scenario == "S2":
            self._readers = Readers(self.api)
            self._readers.start()
            stack.append(self._readers.stop)
        if self.args.scenario == "S7":
            busy = next(s for s in self.speakers if s.role == "busy")
            self._busy = Busy(self.api, busy.row_id)
            self._busy.start()
            stack.append(self._busy.stop)
            time.sleep(1.0)

    def _settle_selected(self, outputs) -> None:
        """Deselect any of our speakers that is already selected, so every
        round starts from stopped."""
        ids = {s.row_id for s in self.speakers}
        busy = [str(r["id"]) for r in outputs if str(r.get("id")) in ids and r.get("selected")]
        for row_id in busy:
            self.api.put_output(row_id, {"selected": False}, kind="setup")
        end = time.monotonic() + self.args.start_bound_s
        while busy and time.monotonic() < end:
            if all(self.poller.timeline.last(r).get("state") in ("stopped", "failed", "password", None)
                   for r in busy):
                return
            time.sleep(0.1)

    def _cleanup(self, stack: list) -> None:
        while stack:
            step = stack.pop()
            try:
                step()
            except Exception as exc:  # noqa: BLE001 - every cleanup step must get its turn
                self.out(f"cleanup: {exc}")

    def _deselect_all(self) -> None:
        threads = [threading.Thread(target=self.api.put_output,
                                    args=(s.row_id, {"selected": False}, "cleanup"), daemon=True)
                   for s in self.speakers]
        for t in threads:
            t.start()
        for t in threads:
            t.join(self.api.timeout + 2.0)

    def _send(self, speaker: Speaker, selected: bool, op: Op | None = None) -> Op:
        """One select or deselect, noting when it left and the state the row
        was in then."""
        op = op or Op(speaker, selected)
        op.sent = time.monotonic()
        op.prior = state_at(self._timeline().transitions(speaker.row_id), op.sent)
        op.status = self.api.put_output(speaker.row_id, {"selected": selected})
        if isinstance(op.status, int):
            op.replied = time.monotonic()
        return op

    def _burst(self, speakers, selected: bool) -> list:
        ops = [Op(s, selected) for s in speakers]
        self.rng.shuffle(ops)
        # S9's hold and mute requests are ordered here, so the seed fixes them
        orders = {}
        if selected and self.args.scenario == "S9":
            orders = {id(op): self._field_order() for op in ops}
        barrier = threading.Barrier(len(ops))
        extra: list = []

        def send(op: Op) -> None:
            barrier.wait()
            if id(op) in orders:
                # 100 ms after the select left, whether or not it has been answered
                t = threading.Timer(FIELD_DELAY_S, self._put_fields_in_turn, args=(op, orders[id(op)]))
                t.daemon = True
                extra.append(t)
                t.start()
            self._send(op.speaker, selected, op)

        threads = [threading.Thread(target=send, args=(op,), daemon=True) for op in ops]
        for t in threads:
            t.start()
        for t in threads:
            t.join(self.api.timeout + 2.0)
        for t in extra:
            t.join(4 * self.api.timeout + 2.0)
        return ops

    # --- hold and mute requests ---

    def _field_order(self) -> list:
        order = [{"hold": True}, {"hold": False}, {"muted": True}, {"muted": False}]
        self.rng.shuffle(order)
        return order

    def _put_field(self, speaker: Speaker, fields: dict):
        """A hold, mute or level request; its reply is checked and returned
        as (status, body)."""
        status, body = self.api.put_fields(speaker.row_id, fields)
        if "hold" in fields or "muted" in fields:
            error = body.get("error", "") if isinstance(body, dict) else ""
            self.tally.add("hold and mute replies were 204 or not_holdable", field_reply_ok(fields, status, body),
                           f"{speaker.name} {fields}: {status} {error}".strip())
        return status, body

    def _put_fields_in_turn(self, op: Op, order) -> None:
        for fields in order:
            status, _ = self._put_field(op.speaker, fields)
            op.fields.append((fields, status))

    def _hold(self, speaker: Speaker, held: bool):
        return self._put_field(speaker, {"hold": held})

    def _check_flags(self, op: Op) -> None:
        """A speaker that streams ends with the hold and mute its last
        accepted requests asked for."""
        held, muted = expected_flags(op.fields)
        row = self._wait_row(op.speaker, lambda r: row_held(r) == held and row_muted(r) == muted,
                             self.args.settle_s)
        if row is None:
            last = self.api.get_row(op.speaker.row_id) or {}
            detail = (f"{op.speaker.name}: wanted held {held} muted {muted}, "
                      f"read held {row_held(last)} muted {row_muted(last)}")
        else:
            detail = ""
        self.tally.add("the final row agreed with the last request", row is not None, detail)

    # --- helpers for the scenarios that drive one speaker at a time ---

    def _plain(self) -> list:
        return [s for s in self.speakers if s.role == "burst"]

    def _rng_for(self, what: str) -> random.Random:
        return random.Random(f"{self.args.seed}:{what}")

    def _record(self, starts=(), stops=()) -> None:
        with self._ops_lock:
            self.starts.extend(starts)
            self.stops.extend(stops)

    def _start_wait(self, speaker: Speaker) -> Op:
        op = self._send(speaker, True)
        self._wait([op])
        self._record(starts=[op])
        return op

    def _stop_wait(self, speaker: Speaker) -> Op:
        op = self._send(speaker, False)
        self._wait([op])
        self._record(stops=[op])
        return op

    def _select_then(self, speaker: Speaker, delay_s: float, then):
        """Select *speaker* and call *then* *delay_s* after the select left,
        while it may still be waiting for its answer. Returns (op, what
        *then* returned)."""
        op = Op(speaker, True)
        t = threading.Thread(target=self._send, args=(speaker, True, op), daemon=True)
        began = time.monotonic()
        t.start()
        _sleep_until(began + delay_s)
        result = then()
        t.join(self.api.timeout + 2.0)
        return op, result

    def _wait_row(self, speaker: Speaker, test, timeout: float):
        """The row once *test* holds for it, read ten times a second for
        up to *timeout*; None when it never did."""
        end = time.monotonic() + timeout
        while True:
            row = self.api.get_row(speaker.row_id)
            if row is not None and test(row):
                return row
            if time.monotonic() >= end:
                return None
            time.sleep(0.1)

    def _new_lines(self) -> list:
        lines, err = self.probe.new_log_lines()
        if err:
            self.tally.add("the daemon's log was readable", False, err)
        return lines

    def _parallel(self, fn, speakers) -> None:
        def run(s):
            try:
                fn(s)
            except Exception as exc:  # noqa: BLE001 - a thread's failure is a failed check
                self.tally.add("every speaker's cycles ran to the end", False, f"{s.name}: {exc!r}")

        threads = [threading.Thread(target=run, args=(s,), daemon=True, name=f"storm-{s.row_id}")
                   for s in speakers]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    # --- the scenarios that are not rounds of S1 ---

    def _run_s3(self) -> None:
        def cycles(s: Speaker) -> None:
            for delay in delay_plan(self._rng_for(s.row_id), STOP_DELAYS_MS, self.args.repeat):
                start = self._send(s, True)
                _sleep_until(start.sent + delay / 1000.0)
                stop = self._send(s, False)
                self._wait([stop])
                self._record(stops=[stop])
            row = self._wait_row(s, row_idle, self.args.start_bound_s)
            last = row or self.api.get_row(s.row_id) or {}
            self.tally.add("no speaker was left with a session", row is not None,
                           f"{s.name} reads {row_state(last)}, selected {bool(last.get('selected'))}")

        self._parallel(cycles, self._plain())

    def _run_s4(self) -> None:
        speakers = self._plain() + ([self.pair] if self.pair else [])
        first = self._burst(speakers, True)
        self._wait(first)
        self._record(starts=first)

        def cycles(s: Speaker) -> None:
            for delay in delay_plan(self._rng_for(s.row_id), RESELECT_DELAYS_MS, self.args.repeat):
                stop = self._send(s, False)
                _sleep_until(stop.sent + delay / 1000.0)
                start = self._start_wait(s)
                self.tally.add("every cycle ended streaming", start.outcome.state == "streaming",
                               f"{s.name} after {delay} ms: {start.outcome.state} {start.outcome.detail}".strip())
                if self._event_driven() and stop.prior in SESSION:
                    self.tally.add("stopped came before the next connecting",
                                   stop_precedes_connect(self._timeline().transitions(s.row_id), stop.sent),
                                   f"{s.name} after {delay} ms")

        self._parallel(cycles, speakers)

    def _run_s15(self) -> None:
        pair, members = self.pair, self.args.pair_members
        everyone = self._plain() + [pair]
        first = self._burst(everyone, True)
        self._wait(first)
        self._record(starts=first)
        began = time.monotonic()
        rng = self._rng_for("hold")
        end = began + self.args.duration_s
        held, anchored = False, True
        self._new_lines()
        while time.monotonic() < end:
            want = not held
            status, _ = self._hold(pair, want)
            time.sleep(rng.uniform(*HOLD_EVERY_S))
            row = self.api.get_row(pair.row_id)
            counts = self.patterns.count(self._new_lines())
            if status != 204:
                continue
            self.tally.add("each hold showed in the row", row is not None and row_held(row) == want,
                           f"asked held {want}, read {row_held(row) if row else 'no row'}")
            held = want
            if want and anchored:
                self.tally.add("one pause per member for each hold of an anchored pair",
                               counts["pause"] == members, f"{counts['pause']} pause line(s)")
            if not want:
                # The next hold is of an anchored pair once every member's
                # anchor was accepted again
                anchored = counts["anchor"] >= members
        for s in everyone:
            failed = [w for w, st in self._timeline().transitions(s.row_id) if w >= began and st == "failed"]
            self.tally.add("no speaker failed", not failed, f"{s.name} failed {len(failed)}x")

    def _run_s16(self) -> None:
        pair, members = self.pair, self.args.pair_members
        for delay in delay_plan(self._rng_for("hold"), HOLD_DELAYS_MS, self.args.repeat):
            self._new_lines()
            op, (status, _) = self._select_then(pair, delay / 1000.0, lambda: self._hold(pair, True))
            self._wait([op])
            self._record(starts=[op])
            time.sleep(self.args.settle_s)
            lines = self._new_lines()
            if status == 204 and op.outcome.state == "streaming":
                ok, detail = pause_after_anchor(self.patterns.sequence(lines, ("anchor", "pause")), members)
                self.tally.add("each member paused after its anchor was accepted", ok,
                               f"hold {delay} ms after the select: {detail}")
            self._stop_wait(pair)

    def _run_s17(self) -> None:
        pair, members = self.pair, self.args.pair_members
        self._start_wait(pair)
        for after in delay_plan(self._rng_for("reselect"), RESELECT_AFTER_S, self.args.repeat):
            self._hold(pair, True)
            self._wait_row(pair, row_held, self.args.settle_s)
            self._new_lines()
            stop = self._send(pair, False)
            self._wait([stop])
            self._record(stops=[stop])
            _sleep_until(stop.sent + after)
            start = self._start_wait(pair)
            self.tally.add("the pair streamed again", start.outcome.state == "streaming",
                           f"selected {after:.0f} s after the stop: {start.outcome.state}")
            if self.args.teardown_drop:
                n = self.patterns.count(self._new_lines())["teardown_timeout"]
                self.tally.add("each member's TEARDOWN went unanswered", n == members, f"{n} line(s)")

    def _run_s18(self) -> None:
        s = next(sp for sp in self.speakers if sp.role == "firewalled")
        rng = self._rng_for("volume")
        for _ in range(self.args.repeat):
            start = self._start_wait(s)
            if start.outcome.state != "streaming":
                self.tally.add("the speaker streamed before each firewall", False, str(start.outcome.state))
                continue
            with self.firewall:
                level = {"volume": rng.randint(20, 60)}
                # The level request may wait for the speaker that no longer answers
                t = threading.Thread(target=self._put_field, args=(s, level), daemon=True)
                t.start()
                time.sleep(rng.uniform(0.0, 1.0))
                stop = self._send(s, False)
                self._wait([stop])
                self._record(stops=[stop])
                t.join(self.api.timeout + 2.0)
            time.sleep(self.args.settle_s)

    def _run_s19(self) -> None:
        pair, members = self.pair, self.args.pair_members
        settle = self.args.settle_s
        self._start_wait(pair)
        self._hold(pair, True)
        self._wait_row(pair, row_held, settle)
        rng = self._rng_for("rehold")
        for delay in delay_plan(rng, REHOLD_DELAYS_MS, self.args.repeat):
            began = time.monotonic()
            self._hold(pair, False)
            _sleep_until(began + delay / 1000.0)
            self._hold(pair, True)
            row = self._wait_row(pair, row_held, settle)
            self.tally.add("the row read held after an end and a new hold", row is not None,
                           f"hold {delay} ms after the end")
            time.sleep(settle)

            self._new_lines()
            first, second = sorted(rng.uniform(0.0, 0.1) for _ in range(2))
            began = time.monotonic()
            self._hold(pair, False)
            _sleep_until(began + first)
            self._hold(pair, True)
            _sleep_until(began + second)
            self._hold(pair, False)
            time.sleep(settle)
            lines = self._new_lines()
            flushes = self.patterns.per_speaker(lines, "resume_flush")
            anchors = self.patterns.per_speaker(lines, "anchor")
            self.tally.add("an end, a hold and an end made one resume flush and one anchor per member",
                           once_per_member(flushes, members) and once_per_member(anchors, members),
                           f"resume flushes {flushes or 'none'}, anchors {anchors or 'none'}")
            row = self.api.get_row(pair.row_id)
            self.tally.add("the row read not held after the last end", row is not None and not row_held(row))

            self._hold(pair, True)
            self._wait_row(pair, row_held, settle)
            time.sleep(settle)

    def _run_s20(self) -> None:
        pair, newcomer = self.pair, self._plain()[0]
        settle = self.args.settle_s
        self._start_wait(pair)
        for _ in range(self.args.repeat):
            self._hold(pair, True)
            self._wait_row(pair, row_held, settle)
            time.sleep(settle)
            self._new_lines()
            start = self._start_wait(newcomer)
            self.tally.add("the newcomer streamed", start.outcome.state == "streaming", str(start.outcome.state))
            time.sleep(settle)
            lines = self._new_lines()
            reached = self.patterns.per_speaker(lines, "anchor_reached")
            n = reached.get(newcomer.name, 0) + reached.get("", 0)
            self.tally.add("the newcomer logged its anchor point reached", n >= 1, f"{reached or 'none'}")
            flushes = sum(self.patterns.per_speaker(lines, "resume_flush").values())
            row = self.api.get_row(pair.row_id)
            self.tally.add("the paused pair stayed paused", row is not None and row_held(row) and not flushes,
                           f"held {row_held(row) if row else 'no row'}, {flushes} resume flush(es)")
            self._stop_wait(newcomer)
            self._hold(pair, False)
            self._wait_row(pair, lambda r: not row_held(r), settle)
            time.sleep(settle)

    def _judge_op(self, op: Op) -> Outcome:
        transitions = self._timeline().transitions(op.speaker.row_id)
        if op.selected:
            read = None
            if not self._event_driven() and op.replied is not None:
                read = self.poller.read_after(op.replied)
            return judge_start(transitions, op.sent, self.args.start_bound_s, op.replied, read)
        return judge_stop(transitions, op.sent, self.args.stop_bound_s, self.args.start_bound_s, op.prior)

    def _bound(self, op: Op) -> float:
        if not op.selected and op.prior in SESSION:
            return self.args.stop_bound_s
        return self.args.start_bound_s

    def _wait(self, ops: list) -> None:
        """Judge each request as soon as its outcome is known, or once its
        bound has passed."""
        pending = list(ops)
        while pending:
            now = time.monotonic()
            still = []
            for op in pending:
                outcome = self._judge_op(op)
                if outcome.ok or (outcome.elapsed is not None) or not outcome.needed:
                    op.outcome = outcome
                elif now > op.sent + self._bound(op) + SLACK_S:
                    op.outcome = outcome
                else:
                    still.append(op)
            pending = still
            if pending:
                time.sleep(0.05)

    def _round(self, speakers) -> None:
        starts = self._burst(speakers, True)
        self._wait(starts)
        self.starts.extend(starts)
        if self.args.scenario == "S9":
            for op in starts:
                if op.outcome.state == "streaming":
                    self._check_flags(op)
        stops = self._burst(speakers, False)
        self._wait(stops)
        self.stops.extend(stops)

    def _judge(self) -> None:
        a, v = self.args, self.verdict
        put = self.api.latencies("put", "field")
        p99, top = percentile(put, 99), (max(put) if put else None)
        v.add("PUT p99", None if p99 is None else p99 <= a.put_p99_ms,
              "" if p99 is None else f"{p99:.0f} ms (limit {a.put_p99_ms:.0f})")
        v.add("PUT max", None if top is None else top <= a.put_max_ms,
              "" if top is None else f"{top:.0f} ms (limit {a.put_max_ms:.0f})")
        get = self.api.latencies("get")
        g99 = percentile(get, 99)
        v.add("GET p99", None if g99 is None else g99 <= a.get_p99_ms,
              "" if g99 is None else f"{g99:.0f} ms over {len(get)} reads (limit {a.get_p99_ms:.0f})")

        late = [f"{op.speaker.name}: {op.outcome.detail}" for op in self.starts if not op.outcome.ok]
        v.add("every start ended in time", not late, "; ".join(late[:5]) or f"{len(self.starts)} starts")
        judged = [op for op in self.stops if op.outcome.needed]
        bad = [f"{op.speaker.name}: {op.outcome.detail}" for op in judged if not op.outcome.ok]
        v.add("every stop read stopped in time", not bad, "; ".join(bad[:5]) or f"{len(judged)} stops")

        if a.scenario == "S6":
            self._expect("firewalled", "failed", FIREWALLED_REASONS, "the firewalled speaker failed")
            self._expect("pin", "password", PIN_REASONS, "the PIN speaker asked for a PIN")
        for name, ok, detail in self.tally.items():
            v.add(name, ok, detail)
        if a.scenario == "S4" and not self._event_driven():
            v.add("stopped came before the next connecting", None, "needs output_state events")

        missing = {sid: n for sid, n in self.poller.missing.items() if n}
        v.add("every speaker listed in every read", not missing,
              ", ".join(f"{self._name(sid)} missing {n}x" for sid, n in missing.items()))

        if self.events is None:
            v.add("event channel message numbers", None, "no event channel")
        else:
            gaps = self.events.seq.gaps
            v.add("event channel message numbers", not gaps, "; ".join(gaps[:3]))
            v.add("event channel stayed connected", self.events.drops == 0 and not self.events.errors,
                  "; ".join(self.events.errors[:3]) or (f"{self.events.drops} drops" if self.events.drops else ""))

        lines, err = self.probe.log_lines()
        bugs = [ln for ln in lines if BUG_MARK in ln]
        v.add("no Bug! line", False if err else not bugs, err or "; ".join(bugs[:3]))
        reports = self.probe.new_sanitiser_files() + [ln for ln in lines
                                                      if any(m in ln for m in SANITISER_MARKS)]
        v.add("no sanitiser report", not reports, "; ".join(reports[:3]))
        self.log_counts = self.patterns.count(lines)
        for name, ok, detail in check_log_counts(self.log_counts, self.expectations):
            v.add(name, False if err else ok, err or detail)
        growth = self.probe.hwm_growth_mib()
        v.add("VmHWM growth", None if growth is None else growth <= a.rss_growth_mib,
              "daemon not found on this host" if growth is None
              else f"{growth:.1f} MiB (limit {a.rss_growth_mib:.0f})")

    def _expect(self, role: str, state: str, reasons, name: str) -> None:
        wrong = []
        for op in self.starts:
            if op.speaker.role != role:
                continue
            last = self._timeline().last(op.speaker.row_id)
            got = op.outcome.state
            ok = got == state or (state == "password" and last.get("pin_pending"))
            reason = last.get("reason")
            if ok and reason not in (None, "", "none") and reason not in reasons:
                ok = False
            if not ok:
                wrong.append(f"{op.speaker.name}: {got} ({reason or 'no reason'})")
        self.verdict.add(name, not wrong, "; ".join(wrong[:3]))

    def _name(self, row_id: str) -> str:
        return next((s.name for s in self.speakers if s.row_id == row_id), row_id)

    def _report_extra(self) -> dict:
        def ops(items):
            return [{"speaker": op.speaker.name, "role": op.speaker.role, "status": str(op.status),
                     "state": op.outcome.state if op.outcome else None,
                     "elapsed_s": None if not op.outcome or op.outcome.elapsed is None
                     else round(op.outcome.elapsed, 3)} for op in items]
        return {"scenario": self.args.scenario, "repeat": self.args.repeat, "seed": self.args.seed,
                "event_driven": self._event_driven(),
                "capabilities": self.events.capabilities if self.events else [],
                "latency": self.api.summary(), "memory": self.probe.memory, "log_counts": self.log_counts,
                "starts": ops(self.starts), "stops": ops(self.stops)}


# --- command line -------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Drive owntone-mini with bursts of speaker requests and judge it.")
    ap.add_argument("scenario", choices=SCENARIOS)
    ap.add_argument("--base", default=DEFAULT_BASE)
    ap.add_argument("--socket", default=None, help="event channel path, or 'none'; default from /api/config")
    ap.add_argument("--speakers", default="", help="comma-separated speaker names or ids")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--poll-hz", type=float, default=5.0)
    ap.add_argument("--fifo", default=DEFAULT_FIFO)
    ap.add_argument("--rate", type=int, default=None, help="default: the daemon's pipe_sample_rate")
    ap.add_argument("--bits", type=int, choices=(16, 32), default=None,
                    help="default: the daemon's pipe_bits_per_sample")
    ap.add_argument("--no-tone", action="store_true")
    ap.add_argument("--tone-settle-s", type=float, default=3.0)
    ap.add_argument("--firewall", action="append", default=[], metavar="NAME=IP")
    ap.add_argument("--firewall-tool", choices=("auto", "iptables", "nft"), default="auto")
    ap.add_argument("--pin-speaker", default=None)
    ap.add_argument("--pair", default=None, help="a stereo pair's row name or id")
    ap.add_argument("--pair-members", type=int, default=2)
    ap.add_argument("--duration-s", type=float, default=600.0, help="how long S15 runs")
    ap.add_argument("--settle-s", type=float, default=3.0,
                    help="how long a hold, resume or join is given before its log lines are counted")
    ap.add_argument("--teardown-drop", action="store_true",
                    help="S17: the daemon ignores every TEARDOWN answer")
    ap.add_argument("--put-p99-ms", type=float, default=200.0)
    ap.add_argument("--put-max-ms", type=float, default=1000.0)
    ap.add_argument("--get-p99-ms", type=float, default=200.0)
    ap.add_argument("--stop-bound-s", type=float, default=2.0)
    ap.add_argument("--start-bound-s", type=float, default=90.0)
    ap.add_argument("--rss-growth-mib", type=float, default=10.0)
    ap.add_argument("--log", default="journal", help="'journal' or a log file path")
    ap.add_argument("--unit", default="owntone")
    ap.add_argument("--asan-glob", default=DEFAULT_ASAN_GLOB)
    ap.add_argument("--expect-log", action="append", default=[], metavar="NAME=COUNT")
    ap.add_argument("--log-pattern", action="append", default=[], metavar="NAME=REGEX")
    ap.add_argument("--report", default=None, metavar="FILE.json")
    ap.add_argument("--dry-run", action="store_true")
    return ap


def dry_run(args, out=print) -> int:
    try:
        firewall = parse_firewall(args.firewall)
    except SetupError as exc:
        out(f"setup: {exc}")
        return EXIT_SETUP
    try:
        problem = requirement_error(args, firewall)
        patterns = LogPatterns(args.log_pattern)
        expectations = parse_expectations(args.expect_log)
    except SetupError as exc:
        problem = str(exc)
    if problem:
        out(f"setup: {problem}")
        return EXIT_SETUP
    if args.scenario == "S15":
        out(f"scenario S15 for {args.duration_s:.0f} s against {args.base}")
    else:
        out(f"scenario {args.scenario}, {args.repeat} round(s) against {args.base}")
    out(f"speakers: {args.speakers or '(none given)'}")
    if args.pair:
        out(f"pair: {args.pair} ({args.pair_members} members)")
    if args.pin_speaker:
        out(f"PIN speaker: {args.pin_speaker}")
    if args.scenario == "S17":
        out("TEARDOWN answers: " + ("dropped by the daemon" if args.teardown_drop else "as the daemon gets them"))
    for name, op, n in expectations:
        out(f"expect log {name} {op} {n}: {patterns.compiled[name].pattern if name in patterns.compiled else '(no such pattern)'}")
    for name, ip in firewall:
        out(f"firewalled: {name} at {ip}" + (" (kept busy by four selects)" if args.scenario == "S7" else ""))
    out("tone: off" if args.no_tone else
        f"tone: {args.fifo} at {args.rate or 'the daemon'}'s rate, {args.bits or 'the daemon'}'s sample size")
    if args.scenario == "S2":
        out(f"readers: {READERS} at {READER_HZ:.0f} Hz")
    if firewall:
        with Firewall([ip for _, ip in firewall], args.firewall_tool, dry_run=True, out=out):
            pass
    return EXIT_OK


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.dry_run:
        return dry_run(args)

    def on_term(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, on_term)
    api = Api(args.base)
    config = api.config()
    if config is None:
        print(f"setup: no answer from {args.base}/api/config")
        return EXIT_SETUP
    events = None
    if args.socket != "none":
        path = args.socket or config.get("event_socket")
        if not path:
            print("setup: the daemon has no event channel (use --socket none to poll only)")
            return EXIT_SETUP
        events = Events(path)
    tone = None
    if not args.no_tone:
        rate = args.rate or api.setting("player", "pipe_sample_rate") or 44100
        bits = args.bits or api.setting("player", "pipe_bits_per_sample") or 16
        tone = Tone(args.fifo, int(rate), int(bits))
    try:
        firewall = parse_firewall(args.firewall)
    except SetupError as exc:
        print(f"setup: {exc}")
        return EXIT_SETUP
    fw = Firewall([ip for _, ip in firewall], args.firewall_tool) if firewall else None
    storm = Storm(args, api, events, Poller(api, args.poll_hz),
                  Probe(args.log, args.unit, args.asan_glob), tone, fw)
    return storm.run()


if __name__ == "__main__":
    sys.exit(main())
