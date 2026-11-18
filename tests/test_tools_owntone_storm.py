"""tests/test_tools_owntone_storm.py

The owntone-mini storm script: its judging, its state sources, the tone, the
firewall rules, the daemon health checks, and whole runs against a small
fake daemon on 127.0.0.1.
"""
from __future__ import annotations

import json
import random
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(_ROOT / "tools"))

import owntone_storm as storm


# --- a fake daemon -------------------------------------------------------------

class FakeDaemon:
    """Rows that step through startup and streaming on a select and to
    stopped on a deselect, *delay_s* apart. A row in *stuck* never gets past
    startup."""

    def __init__(self, names, delay_s=0.05, stuck=(), slow_get_s=0.0):
        self.rows = {str(100 + i): {"id": str(100 + i), "name": n, "selected": False,
                                    "pin_pending": False,
                                    "session": {"state": "stopped", "failure": "none"}}
                     for i, n in enumerate(names)}
        self.delay_s = delay_s
        self.stuck = set(stuck)
        self.slow_get_s = slow_get_s
        self.puts = []
        self.gen = {row_id: 0 for row_id in self.rows}
        self.lock = threading.Lock()
        daemon = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, code, body=None):
                data = b"" if body is None else json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path == "/slow":
                    time.sleep(1.0)
                    return self._reply(200, {})
                if self.path != "/api/outputs":
                    return self._reply(404)
                if daemon.slow_get_s:
                    time.sleep(daemon.slow_get_s)
                with daemon.lock:
                    self._reply(200, {"outputs": json.loads(json.dumps(list(daemon.rows.values())))})

            def do_PUT(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                row_id = self.path.rsplit("/", 1)[-1]
                with daemon.lock:
                    row = daemon.rows.get(row_id)
                    if row is None:
                        return self._reply(400)
                    daemon.puts.append((row_id, body))
                    if "selected" in body:
                        daemon._select(row_id, bool(body["selected"]))
                    reply = daemon._fields(row_id, body)
                if reply:
                    return self._reply(*reply)
                self._reply(204)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def id_of(self, name):
        return next(r["id"] for r in self.rows.values() if r["name"] == name)

    def _set(self, row_id, state, gen=None):
        """Move a row on; a step planned before a later select or deselect
        of the row is dropped."""
        with self.lock:
            if gen is not None and gen != self.gen[row_id]:
                return False
            self.rows[row_id]["session"]["state"] = state
        return True

    def _later(self, row_id, state):
        t = threading.Timer(self.delay_s, self._set, args=(row_id, state, self.gen[row_id]))
        t.daemon = True
        t.start()

    def _fields(self, row_id, body):
        """Fields other than selected: (status, body) to refuse, or None."""
        return None

    def _select(self, row_id, on):
        row = self.rows[row_id]
        self.gen[row_id] += 1
        row["selected"] = on
        if on:
            row["session"]["state"] = "startup"
            if row_id not in self.stuck:
                self._later(row_id, "streaming")
        elif row["session"]["state"] in ("startup", "connected", "streaming"):
            self._later(row_id, "stopped")

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class HoldingDaemon(FakeDaemon):
    """A FakeDaemon whose speakers take hold, muted and volume, and which
    writes the log lines the storm counts. The *pair* row has two members.
    A hold is refused with 409 not_holdable until the speaker streams. An
    ended hold resumes over *window_s*: one resume flush at once, one
    accepted anchor at the end, and a hold or end inside the window only
    changes what the speaker is left in. With *rehold_window* False every
    end resumes at once, as a daemon without that window would."""

    def __init__(self, names, log, pair=None, window_s=0.2, rehold_window=True,
                 drop_teardown=False, **kw):
        super().__init__(names, **kw)
        self.log = Path(log)
        self.pair = pair
        self.window_s = window_s
        self.rehold_window = rehold_window
        self.drop_teardown = drop_teardown
        self.resuming = {}
        for row in self.rows.values():
            row["muted"] = False
            row["volume"] = 50
            row["session"]["held"] = False

    def members(self, row_id):
        name = self.rows[row_id]["name"]
        return [name, f"{name} (2)"] if name == self.pair else [name]

    def write(self, row_id, *templates):
        with self.log.open("a") as f:
            for template in templates:
                for m in self.members(row_id):
                    f.write(template.format(m) + "\n")

    def anchor(self, row_id):
        self.write(row_id, "SETRATEANCHORTIME accepted by '{}' after 40 ms",
                   "SETRATEANCHORTIME accepted by '{}': stats")

    def _set(self, row_id, state, gen=None):
        # The anchor lines are written under the lock with the state, so a
        # hold accepted once the row streams always logs after them
        with self.lock:
            if gen is not None and gen != self.gen[row_id]:
                return False
            self.rows[row_id]["session"]["state"] = state
            if state == "streaming":
                self.anchor(row_id)
                self.write(row_id, "Anchor point reached for '{}': delivering from seq 1, rtptime 2")
        return True

    def _select(self, row_id, on):
        session = self.rows[row_id]["session"]
        if not on and session["state"] == "streaming":
            if session["held"] and self.drop_teardown:
                self.write(row_id, "No answer to TEARDOWN from '{}' in 1500 ms, closing")
            session["held"] = False
            self.rows[row_id]["muted"] = False
            self.resuming.pop(row_id, None)
        super()._select(row_id, on)

    def _fields(self, row_id, body):
        row = self.rows[row_id]
        session = row["session"]
        if "muted" in body:
            row["muted"] = bool(body["muted"])
        if "volume" in body:
            row["volume"] = body["volume"]
        if "hold" not in body:
            return None
        want = bool(body["hold"])
        if row_id in self.resuming:
            self.resuming[row_id] = want
            session["held"] = want
            return None
        if want and session["state"] != "streaming":
            return 409, {"error": "not_holdable"}
        if want and not session["held"]:
            session["held"] = True
            self.write(row_id, "Paused '{}' in place after 90 ms")
        elif not want and session["held"]:
            session["held"] = False
            self.write(row_id, "send: Sending FLUSHBUFFERED (resume) to '{}'")
            if self.rehold_window:
                self.resuming[row_id] = False
                t = threading.Timer(self.window_s, self._resumed, args=(row_id,))
                t.daemon = True
                t.start()
            else:
                self.anchor(row_id)
        return None

    def _resumed(self, row_id):
        with self.lock:
            if self.resuming.pop(row_id, None) is None:
                return
        self.anchor(row_id)


@pytest.fixture
def daemon_factory():
    made = []

    def make(*a, holding=False, **kw):
        d = (HoldingDaemon if holding else FakeDaemon)(*a, **kw)
        made.append(d)
        return d

    yield make
    for d in made:
        d.close()


class FakeFirewall:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        self.calls.append("enter")
        return self

    def __exit__(self, *exc):
        self.calls.append("exit")
        return False


class FakeTone:
    def __init__(self):
        self.calls = []

    def start(self):
        self.calls.append("start")

    def stop(self):
        self.calls.append("stop")


def _args(tmp_path, base, *extra):
    log = tmp_path / "owntone.log"
    if not log.exists():
        log.write_text("before the run Bug! not ours\n")
    argv = ["S1", "--base", base, "--socket", "none", "--no-tone",
            "--log", str(log), "--asan-glob", str(tmp_path / "asan*"),
            "--report", str(tmp_path / "report.json"),
            "--start-bound-s", "2", "--stop-bound-s", "1", "--poll-hz", "50",
            "--tone-settle-s", "0", *extra]
    return storm.build_parser().parse_args(argv)


def _storm(args, tone=None, firewall=None, out=None):
    api = storm.Api(args.base, timeout=2.0)
    probe = storm.Probe(args.log, args.unit, args.asan_glob, process="no-such-process-for-storm")
    return storm.Storm(args, api, None, storm.Poller(api, args.poll_hz), probe, tone, firewall,
                       out=out or (lambda *_: None))


# --- pure parts ------------------------------------------------------------------

def test_percentile_is_nearest_rank():
    assert storm.percentile([], 99) is None
    assert storm.percentile([5], 99) == 5
    values = list(range(1, 101))
    assert storm.percentile(values, 50) == 50
    assert storm.percentile(values, 99) == 99
    assert storm.percentile(values, 100) == 100
    assert storm.percentile([3, 1, 2], 50) == 2
    assert storm.percentile([1, 2, 3, 4], 99) == 4


def test_a_seq_gap_is_counted_and_seq_restarts_with_each_connection():
    seq = storm.SeqCounter()
    seq.new_connection()
    for n in (1, 2, 3, 5, 6):
        seq.see(n)
    assert len(seq.gaps) == 1
    assert "expected 4, got 5" in seq.gaps[0]
    seq.new_connection()
    for n in (1, 2):
        seq.see(n)
    seq.see(None)
    assert len(seq.gaps) == 1
    assert seq.connections == 2
    seq.new_connection()
    seq.see(2)
    assert len(seq.gaps) == 2


def test_events_keep_a_timeline_per_row():
    client, server = socket.socketpair()
    connections = iter([client])
    events = storm.Events(connect=lambda: next(connections), ping_s=0.2)

    def serve():
        buf = b""
        while b"\n" not in buf:
            buf += server.recv(4096)
        hello = json.loads(buf.split(b"\n", 1)[0])
        assert hello == {"type": "hello", "protocol": 1, "client": "owntone-storm"}
        msgs = [
            {"type": "hello", "seq": 1, "capabilities": ["changed", "output_state"]},
            {"type": "event", "seq": 2, "kind": "output_state", "speaker": {"id": "7"},
             "state": "connecting", "reason": "none"},
            {"type": "changed", "seq": 3, "what": "outputs"},
            {"type": "event", "seq": 4, "kind": "output_state", "speaker": {"id": "8"},
             "state": "connecting"},
            {"type": "event", "seq": 5, "kind": "output_state", "speaker": {"id": "7"},
             "state": "streaming", "selected": True},
            {"type": "event", "seq": 7, "kind": "output_state", "speaker": {"id": "8"},
             "state": "failed", "reason": "unreachable", "selected": False},
            {"type": "event", "seq": 8, "kind": "device_volume", "speaker": {"id": "7"}},
        ]
        server.sendall(b"".join(json.dumps(m).encode() + b"\n" for m in msgs))

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    events.start()
    try:
        deadline = time.monotonic() + 3
        while len(events.messages) < 7 and time.monotonic() < deadline:
            time.sleep(0.02)
        assert events.has("output_state")
        assert [s for _, s in events.timeline.transitions("7")] == ["connecting", "streaming"]
        assert [s for _, s in events.timeline.transitions("8")] == ["connecting", "failed"]
        assert events.timeline.last("8")["reason"] == "unreachable"
        assert events.timeline.last("7")["selected"] is True
        assert len(events.seq.gaps) == 1
        # The client pings on its own.
        server.settimeout(2)
        assert b'"type":"ping"' in server.recv(4096)
    finally:
        events.stop()
        server.close()


def test_an_event_channel_that_refuses_the_hello_is_a_setup_error():
    client, server = socket.socketpair()
    server.sendall(b'{"type":"error","seq":1,"code":"not_allowed","text":"no"}\n')
    events = storm.Events(connect=lambda: client)
    with pytest.raises(storm.SetupError, match="not_allowed"):
        events.start()
    server.close()


def test_the_poller_turns_row_states_into_transitions():
    poller = storm.Poller(api=None)
    poller.watch(["1", "2"])

    def row(i, state, **kw):
        return {"id": i, "name": f"n{i}", "session": {"state": state, "failure": "none"}, **kw}

    poller.ingest([row("1", "stopped"), row("2", "stopped")], 1.0)
    poller.ingest([row("1", "startup"), row("2", "stopped")], 1.2)
    poller.ingest([row("1", "startup")], 1.4)
    poller.ingest([row("1", "streaming", selected=True), {"id": "2"}], 1.6)
    assert poller.timeline.transitions("1") == [(1.0, "stopped"), (1.2, "connecting"), (1.6, "streaming")]
    assert poller.timeline.transitions("2") == [(1.0, "stopped")]
    assert poller.timeline.last("1")["selected"] is True
    assert poller.missing == {"2": 1}
    assert poller.read_after(1.2) == 1.4
    assert poller.read_after(1.6) is None


def test_start_and_stop_bounds_are_judged_from_a_timeline():
    tl = [(0.0, "stopped"), (10.1, "connecting"), (10.5, "connected"), (11.0, "streaming"),
          (20.4, "stopped")]
    start = storm.judge_start(tl, 10.0, 90)
    assert start.ok and start.state == "streaming" and start.elapsed == pytest.approx(1.0)
    assert not storm.judge_start(tl, 10.0, 0.5).ok
    stop = storm.judge_stop(tl, 20.0, 2.0, 90)
    assert stop.ok and stop.needed and stop.elapsed == pytest.approx(0.4)
    assert not storm.judge_stop(tl, 20.0, 0.2, 90).ok
    # Nothing to stop when the speaker never got a session.
    assert not storm.judge_stop([(0.0, "failed")], 5.0, 2.0, 90).needed
    # A stop that ends failed is not a stop.
    assert not storm.judge_stop([(0.0, "streaming"), (5.5, "failed")], 5.0, 2.0, 90).ok
    # A probe while nothing plays ends at stopped once connecting was seen.
    probe = storm.judge_start([(0.0, "stopped"), (1.1, "connecting"), (1.3, "stopped")], 1.0, 90)
    assert probe.ok and probe.state == "stopped"
    # No end state yet.
    assert storm.judge_start([(0.0, "stopped"), (1.1, "connecting")], 1.0, 90).elapsed is None
    # A start too quick for the poller ends at the reply when the first read
    # after it shows an end state.
    quick = storm.judge_start([(0.0, "password")], 1.0, 90, replied=1.5, read_after_reply=1.7)
    assert quick.ok and quick.state == "password" and quick.elapsed == pytest.approx(0.5)
    assert not storm.judge_start([(0.0, "failed")], 1.0, 0.2, replied=1.5, read_after_reply=1.7).ok
    # Without a read after the reply, the reply alone proves nothing.
    assert storm.judge_start([(0.0, "failed")], 1.0, 90, replied=1.5).elapsed is None


def test_a_stop_during_connecting_is_judged_by_the_start_bound():
    tl = [(0.0, "stopped"), (1.0, "connecting"), (9.0, "stopped")]
    slow = storm.judge_stop(tl, 2.0, 2.0, 90)
    assert slow.ok and slow.needed and slow.elapsed == pytest.approx(7.0)
    assert not storm.judge_stop(tl, 2.0, 2.0, 5).ok
    assert not storm.judge_stop([(0.0, "streaming")], 2.0, 2.0, 90).ok


@pytest.mark.parametrize("rate,bits,frames", [(44100, 16, 882), (48000, 32, 960)])
def test_a_tone_chunk_is_twenty_milliseconds_of_frames(rate, bits, frames):
    import array
    assert storm.chunk_frames(rate) == frames
    chunks = storm.tone_chunks(rate, bits)
    first = [next(chunks) for _ in range(51)]
    assert all(len(c) == frames * 2 * bits // 8 for c in first)
    # Fifty chunks are one second, and the tone repeats from there.
    assert first[50] == first[0]
    samples = array.array("h" if bits == 16 else "i")
    samples.frombytes(b"".join(first[:50]))
    full = 2 ** (bits - 1) - 1
    assert max(samples) == pytest.approx(full * 0.1, rel=0.01)
    assert samples[0::2] == samples[1::2]


def test_firewall_rules_are_added_and_removed_in_order():
    ran = []

    def run(cmd, **kw):
        ran.append(cmd)
        return SimpleNamespace(returncode=0, stderr="")

    fw = storm.Firewall(["192.0.2.7"], "iptables", run=run, euid=1000)
    with pytest.raises(RuntimeError):
        with fw:
            assert len(ran) == 2
            raise RuntimeError("scenario failed")
    assert ran == [
        ["sudo", "-n", "iptables", "-I", "OUTPUT", "-d", "192.0.2.7", "-j", "DROP"],
        ["sudo", "-n", "iptables", "-I", "INPUT", "-s", "192.0.2.7", "-j", "DROP"],
        ["sudo", "-n", "iptables", "-D", "INPUT", "-s", "192.0.2.7", "-j", "DROP"],
        ["sudo", "-n", "iptables", "-D", "OUTPUT", "-d", "192.0.2.7", "-j", "DROP"],
    ]

    ran.clear()
    fw = storm.Firewall(["192.0.2.7"], "auto", run=run, which=lambda name: None, euid=0)
    assert fw.tool == "nft"
    with fw:
        pass
    assert ran[0] == ["nft", "add", "table", "inet", storm.NFT_TABLE]
    assert ["nft", "add", "rule", "inet", storm.NFT_TABLE, "out", "ip", "daddr", "192.0.2.7", "drop"] in ran
    assert ["nft", "add", "rule", "inet", storm.NFT_TABLE, "in", "ip", "saddr", "192.0.2.7", "drop"] in ran
    assert ran[-1] == ["nft", "delete", "table", "inet", storm.NFT_TABLE]

    # A rule that cannot be added takes back the ones that were, and is a
    # setup error.
    ran.clear()

    def fail_second(cmd, **kw):
        ran.append(cmd)
        return SimpleNamespace(returncode=1 if len(ran) == 2 else 0, stderr="denied")

    fw = storm.Firewall(["192.0.2.7"], "iptables", run=fail_second, euid=0)
    with pytest.raises(storm.SetupError, match="denied"):
        fw.__enter__()
    assert ran[-1] == ["iptables", "-D", "OUTPUT", "-d", "192.0.2.7", "-j", "DROP"]

    # A dry run prints and runs nothing.
    printed = []
    with storm.Firewall(["192.0.2.7"], "nft", dry_run=True, run=None, euid=0, out=printed.append):
        pass
    assert printed[0].startswith("would run: nft add table")
    assert printed[-1] == f"would run: nft delete table inet {storm.NFT_TABLE}"


def test_the_api_records_status_and_latency(daemon_factory):
    d = daemon_factory(["A"])
    api = storm.Api(d.base, timeout=0.3)
    assert api.put_output(d.id_of("A"), {"selected": True}) == 204
    assert api.put_output("999", {"selected": True}) == 400
    assert [r["name"] for r in api.get_outputs()] == ["A"]
    assert api.request("slow", "GET", "/slow")[0] == "timeout"
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        free = s.getsockname()[1]
    assert storm.Api(f"http://127.0.0.1:{free}").get_outputs() is None
    kinds = [(k, s) for k, s, _ in api.samples]
    assert kinds == [("put", 204), ("put", 400), ("get", 200), ("slow", "timeout")]
    assert all(ms >= 0 for _, _, ms in api.samples)
    assert api.samples[-1][2] >= 250
    summary = api.summary()
    assert summary["put"]["count"] == 2 and summary["put"]["statuses"] == {"204": 1, "400": 1}
    assert d.puts[0] == (d.id_of("A"), {"selected": True})


# --- whole runs ------------------------------------------------------------------

def test_a_clean_run_passes_and_writes_a_report(daemon_factory, tmp_path):
    d = daemon_factory(["Speaker A", "Speaker B", "Speaker C"])
    args = _args(tmp_path, d.base, "--speakers", "Speaker A,speaker b," + d.id_of("Speaker C"), "--repeat", "2",
                 "--put-p99-ms", "1000", "--put-max-ms", "2000", "--get-p99-ms", "1000")
    lines = []
    code = _storm(args, out=lines.append).run()
    assert code == storm.EXIT_OK, lines
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["ok"] is True
    assert len(report["starts"]) == 6 and all(s["state"] == "streaming" for s in report["starts"])
    assert len(report["stops"]) == 6 and all(s["state"] == "stopped" for s in report["stops"])
    names = {c["name"]: c["ok"] for c in report["checks"]}
    assert names["VmHWM growth"] is None
    assert names["event channel message numbers"] is None
    assert names["no Bug! line"] is True
    assert any(line.startswith("SKIP VmHWM growth") for line in lines)


def test_a_bug_line_or_a_sanitiser_log_fails_the_run(daemon_factory, tmp_path):
    d = daemon_factory(["Speaker A"], delay_s=0.3)
    args = _args(tmp_path, d.base, "--speakers", "Speaker A",
                 "--put-p99-ms", "1000", "--put-max-ms", "2000", "--get-p99-ms", "1000")
    log = Path(args.log)

    def misbehave():
        time.sleep(0.15)
        with log.open("a") as f:
            f.write("player: Bug! Output callback queue is full (96)\n")
        (tmp_path / "asan.1234").write_text("==1234==ERROR: AddressSanitizer: heap-use-after-free\n")

    t = threading.Thread(target=misbehave)
    t.start()
    lines = []
    code = _storm(args, out=lines.append).run()
    t.join()
    assert code == storm.EXIT_FAIL
    assert any(ln.startswith("FAIL no Bug! line") and "queue is full" in ln for ln in lines)
    assert any(ln.startswith("FAIL no sanitiser report") and "asan.1234" in ln for ln in lines)
    # The line written before the run is not counted.
    assert not any("not ours" in ln for ln in lines)


def test_cleanup_runs_after_a_failed_check(daemon_factory, tmp_path):
    d = daemon_factory(["Speaker A", "Speaker B"], stuck=("101",))
    args = _args(tmp_path, d.base, "--speakers", "Speaker A,Speaker B", "--start-bound-s", "0.4",
                 "--put-p99-ms", "1000", "--put-max-ms", "2000", "--get-p99-ms", "1000")
    tone, fw, lines = FakeTone(), FakeFirewall(), []
    code = _storm(args, tone=tone, firewall=fw, out=lines.append).run()
    assert code == storm.EXIT_FAIL
    assert any(ln.startswith("FAIL every start ended in time") and "Speaker B" in ln for ln in lines)
    assert tone.calls == ["start", "stop"]
    assert fw.calls == ["enter", "exit"]
    assert not any(r["selected"] for r in d.rows.values())
    assert sum(1 for _, body in d.puts if body == {"selected": False}) >= 4


def test_cleanup_runs_after_an_interrupt(daemon_factory, tmp_path, monkeypatch):
    d = daemon_factory(["Speaker A"])
    args = _args(tmp_path, d.base, "--speakers", "Speaker A")
    tone, fw = FakeTone(), FakeFirewall()
    s = _storm(args, tone=tone, firewall=fw)

    def interrupted(speakers):
        storm.Api.put_output(s.api, speakers[0].row_id, {"selected": True})
        raise KeyboardInterrupt

    monkeypatch.setattr(s, "_round", interrupted)
    assert s.run() == storm.EXIT_SETUP
    assert tone.calls == ["start", "stop"] and fw.calls == ["enter", "exit"]
    assert d.rows[d.id_of("Speaker A")]["selected"] is False


def test_an_unknown_speaker_or_a_missing_option_is_a_setup_error(daemon_factory, tmp_path):
    d = daemon_factory(["Speaker A"])
    lines = []
    assert _storm(_args(tmp_path, d.base, "--speakers", "Speaker Z"), out=lines.append).run() == storm.EXIT_SETUP
    assert "no speaker 'Speaker Z'" in lines[0] and "Speaker A" in lines[0]
    args = _args(tmp_path, d.base, "--speakers", "Speaker A")
    args.scenario = "S7"
    lines.clear()
    assert _storm(args, out=lines.append).run() == storm.EXIT_SETUP
    assert "needs --firewall" in lines[0]
    assert storm.dry_run(storm.build_parser().parse_args(["S6", "--firewall", "A=192.0.2.1"]),
                         out=lambda *_: None) == storm.EXIT_SETUP


def test_s7_keeps_the_firewalled_speaker_busy_and_out_of_the_burst(daemon_factory, tmp_path):
    d = daemon_factory(["Speaker A", "Speaker D"], stuck=("101",))
    args = _args(tmp_path, d.base, "--speakers", "Speaker A,Speaker D", "--firewall", "Speaker D=192.0.2.9",
                 "--put-p99-ms", "1000", "--put-max-ms", "2000", "--get-p99-ms", "1000")
    args.scenario = "S7"
    code = _storm(args, firewall=FakeFirewall()).run()
    assert code == storm.EXIT_OK
    report = json.loads((tmp_path / "report.json").read_text())
    assert [s["speaker"] for s in report["starts"]] == ["Speaker A"]
    assert report["latency"]["busy"]["count"] >= 4
    assert d.rows["101"]["selected"] is False


def test_s6_expects_a_failure_and_a_pin(daemon_factory, tmp_path):
    d = daemon_factory(["Speaker A", "Speaker D", "Receiver P"])

    def select(row_id, on, _orig=d._select):
        row = d.rows[row_id]
        if on and row["name"] == "Speaker D":
            row["selected"], row["session"] = False, {"state": "failed", "failure": "unreachable"}
        elif on and row["name"] == "Receiver P":
            row["selected"], row["pin_pending"] = False, True
            row["session"] = {"state": "password", "failure": "pin_required"}
        else:
            _orig(row_id, on)

    d._select = select
    args = _args(tmp_path, d.base, "--speakers", "Speaker A", "--firewall", "Speaker D=192.0.2.9",
                 "--pin-speaker", "Receiver P",
                 "--put-p99-ms", "1000", "--put-max-ms", "2000", "--get-p99-ms", "1000")
    args.scenario = "S6"
    lines = []
    assert _storm(args, firewall=FakeFirewall(), out=lines.append).run() == storm.EXIT_OK, lines
    assert "PASS the firewalled speaker failed" in lines
    assert "PASS the PIN speaker asked for a PIN" in lines


# --- stops, holds and pauses -------------------------------------------------------

def test_log_counts_are_matched_per_pattern(daemon_factory, tmp_path):
    patterns = storm.LogPatterns()
    lines = [
        "SETRATEANCHORTIME accepted by 'Study' after 40 ms",
        "SETRATEANCHORTIME accepted by 'Study': stats",
        "SETRATEANCHORTIME accepted by 'Study (2)' after 52 ms",
        "Paused 'Study' in place after 90 ms",
        "Paused 'Study (2)' in place after 120 ms",
        "seq: Sending FLUSHBUFFERED (resume) to 'Jo's HomePod'",
        "seq: Sending FLUSHBUFFERED to 'Study'",
        "No answer to TEARDOWN from 'Study' in 1500 ms, closing",
        "Stereo group 'Study': both members advertise our group, keeping 'Study' as its leader",
        "Anchor point reached for 'Kitchen': delivering from seq 1, rtptime 2",
    ]
    counts = patterns.count(lines)
    assert counts == {"pause": 2, "teardown_timeout": 1, "leader_kept": 1, "resume_flush": 1,
                      "anchor": 2, "anchor_reached": 1}
    assert patterns.per_speaker(lines, "anchor") == {"Study": 1, "Study (2)": 1}
    assert patterns.per_speaker(lines, "resume_flush") == {"Jo's HomePod": 1}
    assert patterns.sequence(lines, ("anchor", "pause")) == [
        ("anchor", "Study"), ("anchor", "Study (2)"), ("pause", "Study"), ("pause", "Study (2)")]

    # A pattern can be replaced or added; one without a name group counts lines.
    custom = storm.LogPatterns(["pause=Held '.+'", "mine=Ending the hold"])
    assert custom.count(["Held 'A'", "Ending the hold of 'A'", "Paused 'A' in place after 1 ms"]) \
        == {**{k: 0 for k in storm.LOG_PATTERNS}, "pause": 1, "mine": 1}
    assert custom.per_speaker(["Held 'A'"], "pause") == {"": 1}
    for bad in (["pause"], ["=x"], ["x=("]):
        with pytest.raises(storm.SetupError):
            storm.LogPatterns(bad)

    expectations = storm.parse_expectations(["pause=2", "anchor=>=3", "resume_flush<=0", "mine>=1"])
    assert expectations == [("pause", "==", 2), ("anchor", ">=", 3), ("resume_flush", "<=", 0), ("mine", ">=", 1)]
    for bad in ("pause", "pause=x", "pause3", "=3"):
        with pytest.raises(storm.SetupError):
            storm.parse_expectations([bad])
    checks = storm.check_log_counts(counts, expectations)
    assert [(name, ok) for name, ok, _ in checks] == [
        ("log pause == 2", True), ("log anchor >= 3", False), ("log resume_flush <= 0", False),
        ("log mine >= 1", False)]
    assert checks[1][2] == "2 line(s)" and checks[3][2] == "no such pattern"

    # Over a whole run, against the log file, counting only what the run logged.
    d = daemon_factory(["Speaker A"], holding=True, log=tmp_path / "owntone.log")
    args = _args(tmp_path, d.base, "--speakers", "Speaker A", "--repeat", "2",
                 "--expect-log", "anchor_reached=2", "--expect-log", "pause<=0", "--expect-log", "anchor=3",
                 "--put-p99-ms", "1000", "--put-max-ms", "2000", "--get-p99-ms", "1000")
    out = []
    assert _storm(args, out=out.append).run() == storm.EXIT_FAIL
    assert "PASS log anchor_reached == 2: 2 line(s)" in out
    assert "PASS log pause <= 0: 0 line(s)" in out
    assert "FAIL log anchor == 3: 2 line(s)" in out
    assert json.loads((tmp_path / "report.json").read_text())["log_counts"]["anchor_reached"] == 2


def test_the_log_is_read_on_from_where_it_was_left(tmp_path):
    log = tmp_path / "owntone.log"
    log.write_text("old line\n")
    probe = storm.Probe(str(log), process="no-such-process-for-storm")
    probe.begin()
    with log.open("a") as f:
        f.write("one\ntwo\nhalf")
    assert probe.new_log_lines() == (["one", "two"], None)
    with log.open("a") as f:
        f.write(" a line\n")
    assert probe.new_log_lines() == (["half a line"], None)
    assert probe.new_log_lines() == ([], None)

    ran = []

    def run(cmd, **kw):
        ran.append(cmd)
        return SimpleNamespace(returncode=0, stdout=f"x\ny\n-- cursor: c{len(ran)}\n", stderr="")

    probe = storm.Probe("journal", "owntone", run=run, process="no-such-process-for-storm")
    probe.begin()
    assert probe.new_log_lines() == (["x", "y"], None)
    assert probe.new_log_lines() == (["x", "y"], None)
    assert "--since" in ran[0] and "--after-cursor" not in ran[0]
    assert ran[1][-2:] == ["--after-cursor", "c1"]


def test_a_hold_request_reply_of_409_not_holdable_is_accepted(daemon_factory, tmp_path):
    assert storm.field_reply_ok({"hold": True}, 204, None)
    assert storm.field_reply_ok({"muted": False}, 204, None)
    assert storm.field_reply_ok({"hold": True}, 409, {"error": "not_holdable"})
    assert not storm.field_reply_ok({"muted": True}, 409, {"error": "not_holdable"})
    assert not storm.field_reply_ok({"hold": True}, 409, {"error": "reselect_required"})
    assert not storm.field_reply_ok({"hold": True}, 400, None)
    assert not storm.field_reply_ok({"hold": True}, "timeout", None)
    assert storm.expected_flags([({"hold": True}, 204), ({"muted": True}, 204),
                                 ({"hold": False}, 409), ({"muted": False}, 400)]) == (True, True)
    assert storm.expected_flags([({"hold": True}, 409)]) == (False, False)

    # S9 against a daemon that refuses a hold while the speaker connects: the
    # hold sent 100 ms after the select meets "connecting" and is refused.
    d = daemon_factory(["Speaker A", "Speaker B"], holding=True, log=tmp_path / "owntone.log", delay_s=0.3)
    args = _args(tmp_path, d.base, "--speakers", "Speaker A,Speaker B", "--repeat", "2", "--seed", "3",
                 "--settle-s", "1", "--put-p99-ms", "1000", "--put-max-ms", "2000", "--get-p99-ms", "1000")
    args.scenario = "S9"
    out = []
    assert _storm(args, out=out.append).run() == storm.EXIT_OK, out
    assert "PASS hold and mute replies were 204 or not_holdable: 16 made" in out
    assert "PASS the final row agreed with the last request: 4 made" in out
    refused = [body for _, body in d.puts if body.get("hold") is True]
    assert len(refused) == 4

    # A muted request refused outright fails the run.
    d = daemon_factory(["Speaker A"], holding=True, log=tmp_path / "owntone.log")
    d._fields = lambda row_id, body: (400, None) if "muted" in body else None
    args = _args(tmp_path, d.base, "--speakers", "Speaker A", "--settle-s", "0.3",
                 "--put-p99-ms", "1000", "--put-max-ms", "2000", "--get-p99-ms", "1000")
    args.scenario = "S9"
    out = []
    assert _storm(args, out=out.append).run() == storm.EXIT_FAIL
    assert any(ln.startswith("FAIL hold and mute replies") and "400" in ln for ln in out)


def test_random_delays_repeat_with_a_seed(daemon_factory, tmp_path):
    plan = storm.delay_plan(random.Random("7:101"), storm.STOP_DELAYS_MS, 12)
    assert plan == storm.delay_plan(random.Random("7:101"), storm.STOP_DELAYS_MS, 12)
    assert plan != storm.delay_plan(random.Random("8:101"), storm.STOP_DELAYS_MS, 12)
    # Each delay is used once in every round of five.
    assert sorted(plan[:5]) == sorted(storm.STOP_DELAYS_MS) == sorted(plan[5:10])
    assert len(plan) == 12 and set(plan[10:]) <= set(storm.STOP_DELAYS_MS)

    # A run with a seed sends the same hold and mute order again; a run
    # without one picks a seed and says which.
    def s9_order(seed):
        d = daemon_factory(["Speaker A", "Speaker B"], holding=True, log=tmp_path / "owntone.log", delay_s=0.02)
        args = _args(tmp_path, d.base, "--speakers", "Speaker A,Speaker B", "--settle-s", "0.3",
                     "--put-p99-ms", "1000", "--put-max-ms", "2000", "--get-p99-ms", "1000",
                     *(["--seed", str(seed)] if seed is not None else []))
        args.scenario = "S9"
        out = []
        _storm(args, out=out.append).run()
        return [(d.rows[r]["name"], body) for r, body in d.puts if "selected" not in body], out, args.seed

    def by_speaker(order, name):
        return [body for n, body in order if n == name]

    first, _, _ = s9_order(11)
    again, _, _ = s9_order(11)
    for name in ("Speaker A", "Speaker B"):
        assert by_speaker(first, name) == by_speaker(again, name)
    _, out, picked = s9_order(None)
    assert isinstance(picked, int) and f"scenario S9, seed {picked}" in out


def test_the_false_true_false_cycle_counts_one_resume_and_one_anchor(daemon_factory, tmp_path):
    assert storm.once_per_member({"Pair": 1, "Pair (2)": 1}, 2)
    assert not storm.once_per_member({"Pair": 2}, 2)
    assert not storm.once_per_member({"Pair": 1, "Pair (2)": 2}, 2)
    assert storm.once_per_member({"": 2}, 2) and not storm.once_per_member({}, 2)

    def run(rehold_window):
        log = tmp_path / f"owntone-{rehold_window}.log"
        d = daemon_factory(["Pair", "Kitchen"], holding=True, log=log, pair="Pair",
                           rehold_window=rehold_window, window_s=0.25)
        args = _args(tmp_path, d.base, "--pair", "Pair", "--repeat", "2", "--settle-s", "0.5", "--log", str(log),
                     "--put-p99-ms", "1000", "--put-max-ms", "2000", "--get-p99-ms", "1000")
        args.scenario = "S19"
        out = []
        return _storm(args, out=out.append).run(), out

    code, out = run(True)
    assert code == storm.EXIT_OK, out
    assert "PASS an end, a hold and an end made one resume flush and one anchor per member: 2 made" in out
    assert "PASS the row read held after an end and a new hold: 2 made" in out

    # A daemon that resumes on every end flushes twice in the cycle.
    code, out = run(False)
    assert code == storm.EXIT_FAIL
    line = next(ln for ln in out if "one resume flush and one anchor per member" in ln)
    assert line.startswith("FAIL") and "'Pair': 2" in line


def test_order_checks_for_pauses_and_restarts():
    seq = [("anchor", "P"), ("anchor", "P (2)"), ("pause", "P"), ("pause", "P (2)")]
    assert storm.pause_after_anchor(seq, 2) == (True, "")
    ok, detail = storm.pause_after_anchor([("pause", "P"), ("anchor", "P")], 1)
    assert not ok and "before its anchor" in detail
    ok, detail = storm.pause_after_anchor([("anchor", "P"), ("anchor", "P (2)"), ("pause", "P")], 2)
    assert not ok and "pause lines per member" in detail
    tl = [(0.0, "streaming"), (1.0, "stopping"), (1.5, "stopped"), (2.0, "connecting"), (3.0, "streaming")]
    assert storm.stop_precedes_connect(tl, 0.5)
    assert not storm.stop_precedes_connect([(0.0, "streaming"), (2.0, "connecting")], 0.5)
    assert storm.stop_precedes_connect([(0.0, "streaming")], 0.5)


@pytest.fixture
def quick(monkeypatch):
    monkeypatch.setattr(storm, "STOP_DELAYS_MS", (0, 30))
    monkeypatch.setattr(storm, "RESELECT_DELAYS_MS", (0, 30))
    monkeypatch.setattr(storm, "RESELECT_AFTER_S", (0.1, 0.2))
    monkeypatch.setattr(storm, "HOLD_EVERY_S", (0.25, 0.35))


@pytest.mark.parametrize("scenario,extra", [
    ("S3", ["--speakers", "Speaker A,Kitchen", "--repeat", "4"]),
    ("S4", ["--speakers", "Speaker A", "--pair", "Pair", "--repeat", "4"]),
    ("S15", ["--speakers", "Kitchen", "--pair", "Pair", "--duration-s", "2"]),
    ("S16", ["--pair", "Pair", "--repeat", "3"]),
    ("S17", ["--pair", "Pair", "--repeat", "2", "--teardown-drop"]),
    ("S18", ["--firewall", "Speaker A=192.0.2.9", "--repeat", "2"]),
    ("S20", ["--speakers", "Kitchen", "--pair", "Pair", "--repeat", "2"]),
])
def test_each_scenario_passes_against_a_daemon_that_behaves(daemon_factory, tmp_path, quick, scenario, extra):
    log = tmp_path / "owntone.log"
    d = daemon_factory(["Speaker A", "Kitchen", "Pair"], holding=True, log=log, pair="Pair", window_s=0.1,
                       drop_teardown=True)
    args = _args(tmp_path, d.base, *extra, "--settle-s", "0.4", "--seed", "5",
                 "--put-p99-ms", "1000", "--put-max-ms", "2000", "--get-p99-ms", "1000")
    args.scenario = scenario
    fw, out = FakeFirewall(), []
    assert _storm(args, firewall=fw, out=out.append).run() == storm.EXIT_OK, out
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["seed"] == 5
    assert not any(r["selected"] for r in d.rows.values())
    made = {c["name"] for c in report["checks"]}
    expected = {
        "S3": {"no speaker was left with a session"},
        "S4": {"every cycle ended streaming"},
        "S15": {"each hold showed in the row", "one pause per member for each hold of an anchored pair",
                "no speaker failed"},
        "S16": {"each member paused after its anchor was accepted"},
        "S17": {"the pair streamed again", "each member's TEARDOWN went unanswered"},
        "S18": set(),
        "S20": {"the newcomer streamed", "the newcomer logged its anchor point reached",
                "the paused pair stayed paused"},
    }[scenario]
    assert expected <= made
    if scenario == "S3":
        assert len(report["stops"]) == 8
    if scenario == "S4":
        skipped = next(c for c in report["checks"] if c["name"] == "stopped came before the next connecting")
        assert skipped["ok"] is None
    if scenario == "S18":
        assert fw.calls == ["enter", "exit", "enter", "exit"]
        assert len(report["stops"]) == 2 and all(s["state"] == "stopped" for s in report["stops"])
        assert sum(1 for _, body in d.puts if "volume" in body) == 2


def test_the_new_scenarios_say_what_they_need():
    def dry(*argv):
        lines = []
        code = storm.dry_run(storm.build_parser().parse_args([*argv, "--dry-run"]), out=lines.append)
        return code, lines

    for scenario in ("S15", "S16", "S17", "S19", "S20"):
        code, lines = dry(scenario, "--speakers", "A")
        assert code == storm.EXIT_SETUP and "needs --pair" in lines[0]
    code, lines = dry("S20", "--pair", "P")
    assert code == storm.EXIT_SETUP and "needs a speaker" in lines[0]
    code, lines = dry("S18", "--speakers", "A")
    assert code == storm.EXIT_SETUP and "needs --firewall" in lines[0]
    code, lines = dry("S18", "--firewall", "A=192.0.2.1", "--firewall", "B=192.0.2.2")
    assert code == storm.EXIT_SETUP and "exactly one" in lines[0]
    code, lines = dry("S19", "--pair", "P", "--expect-log", "bogus")
    assert code == storm.EXIT_SETUP and "--expect-log" in lines[0]
    code, lines = dry("S17", "--pair", "P", "--teardown-drop", "--expect-log", "teardown_timeout=>=2")
    assert code == storm.EXIT_OK
    assert "TEARDOWN answers: dropped by the daemon" in lines
    assert any(ln.startswith("expect log teardown_timeout >= 2: No answer to TEARDOWN") for ln in lines)
