"""The HD page under real WPE WebKit (cog), the kiosk's own engine.

See conftest.py for how cog is driven and what it can and cannot be asked to
do. These tests cover what only the real engine can show: the page's modules
load and run, it follows the dial live, a press reaches the core, and the EQ
band sliders stand upright although WPE ignores a vertical writing mode on a
range input.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import io
import time
from pathlib import Path

import hd_scenarios as hs

HD_DIR = Path(__file__).resolve().parent.parent.parent / "dial" / "hd"

ERROR_HOOK = """window.__errors = [];
addEventListener('error', e => __errors.push(String(e.message || e.type)));
addEventListener('unhandledrejection', e => __errors.push('rejection: ' + String(e.reason)));
return true;"""


def test_the_page_paints_the_scenario(wpe):
    assert wpe.js("return document.getElementById('title').textContent") == "Tunnel of Love"


def test_every_page_module_loads(wpe):
    loaded = set(wpe.js(
        "return performance.getEntriesByType('resource').map(r => r.name.split('/').pop())"))
    modules = {p.name for p in HD_DIR.glob("hd*.js")}
    assert modules <= loaded, f"not loaded under WPE: {sorted(modules - loaded)}"


def test_the_page_follows_the_dial_live(wpe, hd):
    hd.show(hs.SCENARIOS["nothing_playing"])
    assert wpe.wait_for("return document.getElementById('title').textContent === 'Nothing playing'")
    hd.show(hs.SCENARIOS["playing_artwork"])
    assert wpe.wait_for("return document.getElementById('title').textContent === 'Tunnel of Love'")


def test_a_mute_press_reaches_the_core(wpe, hd):
    wpe.click("#mute")
    # The page shows muted at once, before its request reaches the core.
    assert wpe.wait_for("return document.getElementById('mute').getAttribute('aria-pressed') === 'true'")
    deadline = time.monotonic() + 5
    while not hd.core.calls_to("mute_toggle") and time.monotonic() < deadline:
        time.sleep(0.05)
    assert hd.core.calls_to("mute_toggle")


def test_eq_band_sliders_stand_upright(wpe):
    wpe.click("#eq-open")
    boxes = wpe.wait_for("""
        const s = [...document.querySelectorAll('.hd-band-slider')]
            .map(e => e.getBoundingClientRect()).filter(b => b.width > 0 && b.height > 0);
        return s.length ? s.map(b => [Math.round(b.width), Math.round(b.height)]) : null;""")
    assert boxes, "no EQ band slider shown"
    for width, height in boxes:
        assert height > 2 * width, f"band slider {width}x{height} is not upright"


def test_use_raises_no_script_errors(wpe, hd):
    wpe.js(ERROR_HOOK)
    for name in ("replaying", "nothing_playing", "eq_two", "playing_artwork"):
        hd.show(hs.SCENARIOS[name])
    wpe.click("#eq-open")
    wpe.wait_for("return document.querySelectorAll('.hd-band-slider').length")
    assert wpe.js("return window.__errors") == []


def test_a_screenshot_is_a_whole_painted_frame(wpe):
    from PIL import Image

    image = Image.open(io.BytesIO(wpe.screenshot_png()))
    assert image.size == (800, 600)
    lo, hi = image.convert("L").getextrema()
    assert hi - lo > 64, "frame is blank"
