"""tests/test_tools_owntone_storm.py

The owntone-mini storm script: its judging, its state sources, the tone, the
firewall rules, the daemon health checks, and whole runs against a small
fake daemon on 127.0.0.1.
"""
from __future__ import annotations

import json
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
                self._reply(204)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def id_of(self, name):
        return next(r["id"] for r in self.rows.values() if r["name"] == name)

    def _set(self, row_id, state):
        with self.lock:
            self.rows[row_id]["session"]["state"] = state

    def _later(self, row_id, state):
        t = threading.Timer(self.delay_s, self._set, args=(row_id, state))
        t.daemon = True
        t.start()

    def _select(self, row_id, on):
        row = self.rows[row_id]
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


@pytest.fixture
def daemon_factory():
    made = []

    def make(*a, **kw):
        d = FakeDaemon(*a, **kw)
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
