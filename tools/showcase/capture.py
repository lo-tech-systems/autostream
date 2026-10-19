#!/usr/bin/env python3
"""Capture the product screenshots: the HD dial page at two panel sizes and the
small SPI dial's screens, all from invented music and generated covers.

    python tools/showcase/capture.py [OUT_DIR] [--engine webkit|chromium]
                                     [--only hd|spi] [--scenario NAME ...]

The HD page is the dial's real page served by its real server over a fake core
(as tools/hd_page_preview.py does) and driven in Playwright at 800x480 and
1024x600; files are named hd-<scenario>-<width>x<height>.png. The SPI screens
come from the dial's own compositor (see spi_shots.py) and are named
spi-<screen>-<variant>.png, native size, with an @2x copy for print.

Needs the dial's Python dependencies, Pillow and Playwright with the chosen
engine installed. The default engine is WebKit, the one the kiosk runs on.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))

import showcase_scenarios as ss  # noqa: E402  (also sets up the import paths)
import spi_shots  # noqa: E402

SIZES = ((800, 480), (1024, 600))
# The default folder is the gitignored working area under docs.
DEFAULT_OUT = REPO_ROOT / "docs" / "working" / "showcase-shots"

# What the pull-down's "This dial" list shows, as on a real installation; the
# preview serves FakePanel.INFO_ROWS, so it is replaced here.
INFO_ROWS = (
    ("Dial name", "Lounge dial"), ("Firmware", "0.7.0"), ("IPv4", "192.168.1.42"),
    ("WiFi", "HomeNet"), ("Signal", "Strong"), ("Disk free", "21.4 GB"), ("SD health", "96%"),
)
PULLDOWN_BASE = "now-playing-jazz"
PULLDOWN_NAME = "pulldown"

SETTLED_JS = """() => {
    const o = id => getComputedStyle(document.getElementById(id)).opacity;
    return o('art') === '1' && o('backdrop') === '1' && o('art-prev') === '0'
        && o('backdrop-prev') === '0' && !document.querySelector('.loading')
        && document.getElementById('art').complete;
}"""


def capture_hd(out: Path, engine: str, only: "set | None") -> list:
    from hd_preview import FakePanel, HdPreview
    from playwright.sync_api import sync_playwright

    written = []
    FakePanel.INFO_ROWS = INFO_ROWS
    chosen = [(s, a) for s, a in ss.scenarios() if not only or s.name in only]
    # The pull-down is the jazz now-playing page with the panel opened.
    chosen += [(s, "pulldown") for s, a in ss.scenarios()
               if s.name == PULLDOWN_BASE and (not only or PULLDOWN_NAME in only)]
    with HdPreview() as preview, sync_playwright() as p:
        browser = getattr(p, engine).launch()
        for width, height in SIZES:
            context = browser.new_context(viewport={"width": width, "height": height}, has_touch=True)
            page = context.new_page()
            for scenario, action in chosen:
                preview.reset()
                preview.show(scenario)
                page.goto(preview.url + "/")
                page.wait_for_function("document.getElementById('title').textContent !== ''")
                page.wait_for_function(SETTLED_JS, timeout=10000)
                page.evaluate("document.fonts.ready")
                if action == "eq":
                    page.locator("#eq-open").click()
                    page.wait_for_function(
                        "() => document.getElementById('eq').getBoundingClientRect().left === 0")
                elif action == "pulldown":
                    page.locator("#handle").click()
                    page.wait_for_function(
                        "() => document.getElementById('sheet').getBoundingClientRect().top === 0")
                    page.wait_for_function(
                        "() => document.querySelectorAll('#info .info-row').length === 7")
                elif action == "scroll-speakers":
                    page.evaluate("() => { const l = document.getElementById('speakers-list');"
                                  " l.scrollTop = l.scrollHeight; }")
                page.wait_for_timeout(600)
                name = PULLDOWN_NAME if action == "pulldown" else scenario.name
                path = out / f"hd-{name}-{width}x{height}.png"
                page.screenshot(path=str(path))
                written.append(path)
                print(path, flush=True)
            context.close()
        browser.close()
    return written


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Capture the showcase screenshots.")
    parser.add_argument("out", nargs="?", default=str(DEFAULT_OUT), help="output folder")
    parser.add_argument("--engine", choices=("webkit", "chromium"), default="webkit")
    parser.add_argument("--only", choices=("hd", "spi"), help="capture just one of the two")
    parser.add_argument("--scenario", action="append", help="an HD scenario to capture (repeatable)")
    args = parser.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    if args.only != "spi":
        capture_hd(out, args.engine, set(args.scenario or ()))
    if args.only != "hd":
        for path in spi_shots.capture(out):
            print(path, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
