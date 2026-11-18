"""tests/test_dial_artwork_fetch.py -- artwork on its own short-lived thread: a
slow download holds neither the core nor a request, and the result for a URL
no longer followed is dropped."""
from __future__ import annotations

import threading

import pytest

from dial_pool_support import Rig, aid, peer, track, unit

from dial_core_state import artwork_key

URL1 = "https://provider.example/one.jpg"
URL2 = "https://provider.example/two.jpg"


@pytest.fixture
def rig():
    r = Rig()
    yield r
    r.close()


class SlowFetch:
    """An artwork fetch held per URL until released."""

    def __init__(self) -> None:
        self.gates: dict = {}
        self.started: list = []

    def __call__(self, url, timeout):
        self.started.append(url)
        self.gates.setdefault(url, threading.Event()).wait(10)
        return url.encode(), ""

    def release(self, url) -> None:
        self.gates.setdefault(url, threading.Event()).set()


def test_a_slow_artwork_fetch_does_not_delay_a_queued_speaker_request(rig):
    slow = SlowFetch()
    rig.io.fetch_artwork = slow
    client = rig.add("Kitchen", peer("Kitchen", playing=True, track_entry=track(url=URL1), units=[unit()]))
    rig.fold()
    assert rig.wait(lambda: slow.started == [URL1])
    assert rig.core.set_output(aid("Kitchen"), "u1", selected=True).accepted
    assert rig.wait(lambda: client.sent(), timeout=2.0)
    assert rig.core.snapshot().artwork is None
    slow.release(URL1)
    assert rig.wait(lambda: rig.core.snapshot().artwork is not None)
    assert rig.core.snapshot().artwork.key == artwork_key(URL1)


def test_the_fold_does_not_wait_for_the_artwork(rig):
    slow = SlowFetch()
    rig.io.fetch_artwork = slow
    rig.add("Kitchen", peer("Kitchen", playing=True, track_entry=track(url=URL1)))
    rig.fold()
    rig.fold()
    assert rig.core.snapshot().ticks == 2
    slow.release(URL1)


def test_a_stale_urls_result_is_dropped(rig):
    slow = SlowFetch()
    rig.io.fetch_artwork = slow
    rig.add("Kitchen", peer("Kitchen", playing=True, track_entry=track(url=URL1)))
    rig.fold()
    assert rig.wait(lambda: URL1 in slow.started)
    rig.set("Kitchen", peer("Kitchen", playing=True, track_entry=track(title="Next", url=URL2), seq=2))
    rig.fold()
    assert rig.wait(lambda: URL2 in slow.started)
    slow.release(URL2)
    assert rig.wait(lambda: rig.core.snapshot().artwork is not None)
    slow.release(URL1)
    # The first download finishing late changes nothing.
    rig.wait(lambda: False, timeout=0.2)
    assert rig.core.snapshot().artwork.key == artwork_key(URL2)


def test_a_track_without_artwork_releases_the_held_copy(rig):
    rig.add("Kitchen", peer("Kitchen", playing=True, track_entry=track(url=URL1)))
    rig.fold()
    assert rig.wait(lambda: rig.core.snapshot().artwork is not None)
    rig.set("Kitchen", peer("Kitchen", playing=True, track_entry=track(url=""), seq=2))
    rig.fold()
    assert rig.core.snapshot().artwork is None


def test_the_same_url_is_fetched_once(rig):
    rig.add("Kitchen", peer("Kitchen", playing=True, track_entry=track(url=URL1)))
    rig.fold()
    assert rig.wait(lambda: rig.core.snapshot().artwork is not None)
    rig.fold()
    rig.fold()
    assert rig.io.fetch_artwork.call_count == 1


def test_a_failed_fetch_is_tried_again_by_a_later_fold(rig):
    rig.io.fetch_artwork.return_value = (None, "boom")
    rig.add("Kitchen", peer("Kitchen", playing=True, track_entry=track(url=URL1)))
    rig.fold()
    assert rig.wait(lambda: rig.core._artwork.url is None)
    rig.io.fetch_artwork.return_value = (b"jpeg", "")
    rig.fold()
    assert rig.wait(lambda: rig.core.snapshot().artwork is not None)
