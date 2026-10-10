#!/usr/bin/env python3
"""Show the HD dial's page in a chosen state, for iterating on it on a laptop
with no dial.

It starts the dial's real HD server over a fake core (the same set-up the
browser tests use) and puts it into one of the scenarios of tests/hd_scenarios.py.
Open the printed address in a browser. One scenario is current at a time: the
one named on the command line, or each step of a script in turn. Pressing
replay in the page moves to the replaying scenario, and stop back to the
playing one; sleep and the pull-down settings work, and settings changed in
the page stick until the preview stops (nothing is written to disk).

    python3 tools/hd_page_preview.py [--port 8080] [--scenario replaying]
                                     [--script tests/hd_scripts/journey.json] [--list]

A script is a JSON list of [delay_seconds, scenario] steps, each played that
long after the one before. The server listens on the loopback address only,
as it does on the dial. It needs the dial's Python dependencies, as the tests
do; no display or hardware is used.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (REPO_ROOT / "tests", REPO_ROOT / "dial", REPO_ROOT / "core"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import hd_scenarios  # noqa: E402
from hd_preview import DEFAULT_SCENARIO, HdPreview  # noqa: E402

DEFAULT_PORT = 8080

# The core call behind an action that leads somewhere, and the scenario the
# page is taken to when it is made.
ACTION_LEADS = {
    "start_replay": "replaying",
    "restart_replay": "replaying",
    "stop_replay": "playing_artwork",
}


def load_script(path) -> list:
    """A script as [(delay_s, scenario), ...]; raises ValueError when a step
    is malformed or names an unknown scenario."""
    try:
        steps = json.loads(Path(path).read_text(encoding="utf-8"))
    except ValueError as e:
        raise ValueError(f"script is not JSON: {e}") from None
    if not isinstance(steps, list):
        raise ValueError("script is not a list of steps")
    out = []
    for step in steps:
        try:
            delay, name = step
            delay = float(delay)
        except (TypeError, ValueError):
            raise ValueError(f"bad script step: {step!r}") from None
        if name not in hd_scenarios.SCENARIOS or delay < 0:
            raise ValueError(f"bad script step: {step!r}")
        out.append((delay, name))
    return out


def action_hook(preview, log, leads=ACTION_LEADS):
    """The fake core's on_call: log each accepted action (never its PIN) and
    take the page to the scenario the action leads to."""
    def on_call(method, args, kwargs) -> None:
        shown = {key: value for key, value in kwargs.items() if key != "pin"}
        log(f"action {method} {args!r} {shown!r}")
        if method in leads:
            show(preview, leads[method], log)
    return on_call


def show(preview, name, log) -> None:
    preview.show(hd_scenarios.SCENARIOS[name])
    log(f"scenario -> {name}")


def play_script(preview, script, stop, log) -> None:
    for delay, name in script:
        if stop.wait(delay):
            return
        show(preview, name, log)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="The HD dial page in a chosen state, offline.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--scenario", default=DEFAULT_SCENARIO)
    parser.add_argument("--script", help="JSON list of [delay_s, scenario] steps")
    parser.add_argument("--list", action="store_true", help="print the scenario names and exit")
    args = parser.parse_args(argv)
    if args.list:
        print("\n".join(hd_scenarios.SCENARIO_NAMES))
        return 0
    log = lambda text: print(text, flush=True)  # noqa: E731
    try:
        if args.scenario not in hd_scenarios.SCENARIOS:
            raise ValueError(f"unknown scenario {args.scenario!r}")
        script = load_script(args.script) if args.script else []
        preview = HdPreview(port=args.port)
    except (ValueError, OSError) as e:
        print(f"hd_page_preview: {e}", file=sys.stderr)
        return 2
    stop = threading.Event()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, lambda *_: stop.set())
    preview.core.on_call = action_hook(preview, log)
    preview.show(hd_scenarios.SCENARIOS[args.scenario])
    preview.start()
    player = threading.Thread(target=play_script, args=(preview, script, stop, log), daemon=True)
    player.start()
    log(f"HD page on {preview.url}/  scenario={args.scenario}")
    stop.wait()
    player.join(timeout=3)
    preview.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
