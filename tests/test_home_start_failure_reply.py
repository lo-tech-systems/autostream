"""The failed start the Home page may be told of."""
from __future__ import annotations

import pytest

from autostream_state import store
from fake_store import FakeStore
import webui.browser.home_model as webui_home_model

CLOCK = 5000.0


@pytest.fixture(autouse=False)
def fake(monkeypatch):
    store().reset_for_tests(boot="test-boot")
    from autostream_state.outputs import get_authority
    get_authority().reset_for_tests()
    monkeypatch.setattr(webui_home_model, "_wall", lambda: CLOCK)
    return FakeStore()


def _rows():
    return [FakeStore.output_row("1001", "Speaker A"), FakeStore.output_row("1002", "Speaker B")]


def _reply(snap):
    return {"start_failure": webui_home_model.start_failure_reply(snap)}


def test_the_part_has_no_failure_when_no_start_has_failed(fake):
    snap = fake.outputs(_rows())
    assert snap.outputs.start_failure is None


def test_the_key_carries_the_failure_the_boot_and_its_age(fake):
    snap = fake.outputs(_rows(), start_failure={
        "unit_id": "1002", "reason": "refused", "requester": "webui", "at": CLOCK - 4.9})
    assert _reply(snap)["start_failure"] == {
        "seq": 1, "boot": "test-boot", "unit_id": "1002", "name": "Speaker B",
        "reason": "refused", "requester": "webui", "age_s": 4}


def test_the_requester_is_null_for_the_coordinator(fake):
    snap = fake.outputs(_rows(), start_failure={"unit_id": "1001", "reason": "failed", "at": CLOCK})
    f = _reply(snap)["start_failure"]
    assert f["requester"] is None and f["age_s"] == 0


def test_a_failure_stamped_in_the_future_has_age_zero(fake):
    snap = fake.outputs(_rows(), start_failure={"unit_id": "1001", "reason": "failed", "at": CLOCK + 60})
    assert _reply(snap)["start_failure"]["age_s"] == 0


def test_the_age_follows_the_clock(fake, monkeypatch):
    snap = fake.outputs(_rows(), start_failure={"unit_id": "1001", "reason": "timed_out", "at": CLOCK})
    monkeypatch.setattr(webui_home_model, "_wall", lambda: CLOCK + 125)
    assert _reply(snap)["start_failure"]["age_s"] == 125
