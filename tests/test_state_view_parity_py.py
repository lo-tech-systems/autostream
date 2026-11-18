"""tests/test_state_view_parity_py.py

The dial works out what it shows with dial_peer_view, the Python twin of the
browser's nginx/static/shared/state_view.js. Both run one table of cases
(tests/fixtures/state_view_cases.json). IMPLEMENTED names the derivations the
dial implements and how each Python result is put into the case's shape. A
case for any other derivation is skipped by name; a case for one of these
that the Python side does not pass fails.
"""
from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
for _p in (_ROOT / "dial", _ROOT / "core"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import dial_peer_view as pv  # noqa: E402

CASES = json.loads((Path(__file__).parent / "fixtures" / "state_view_cases.json").read_text(encoding="utf-8"))["cases"]


def _speaker_rows(case):
    rows = pv.speaker_rows(case["parts"], include_offline=bool((case.get("opts") or {}).get("includeOffline")))
    return [{
        "id": r.id, "name": r.name, "on": r.on, "volume": r.volume, "chip": r.chip,
        "autoStart": r.auto_start, "inUseBy": r.in_use_by, "inUseId": r.in_use_id,
        "connecting": r.connecting, "offline": r.offline, "disabled": r.disabled,
        "pinPending": r.pin_pending, "pinClaim": r.pin_claim,
    } for r in rows]


def _start_failure(case):
    view, seen = case["view"], case.get("seen")
    show, new = pv.start_failure_decision(
        view["boot"], view["time"], view["parts"],
        None if seen is None else (seen["boot"], seen["seq"], seen["first"]))
    return {"show": show, "seen": {"boot": new[0], "seq": new[1], "first": new[2]}}


IMPLEMENTED = {
    "playing": lambda c: pv.playing(c["parts"]),
    "activeInput": lambda c: pv.active_input(c["parts"]),
    "speakerRows": _speaker_rows,
    "masterVolume": lambda c: pv.master_volume(c["parts"]),
    "startFailure": _start_failure,
    "repeatControls": lambda c: dataclasses.asdict(pv.repeat_controls(c["parts"])),
}


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_case(case):
    run = IMPLEMENTED.get(case["fn"])
    if run is None:
        pytest.skip(f"{case['fn']} is not a dial derivation")
    assert run(case) == case["expect"]


def test_every_implemented_derivation_has_cases():
    named = {c["fn"] for c in CASES}
    assert set(IMPLEMENTED) <= named
