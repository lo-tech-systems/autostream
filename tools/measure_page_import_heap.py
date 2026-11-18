#!/usr/bin/env python3
"""measure_page_import_heap.py

How much heap importing the page-producing modules holds.

Run with the appliance's own Python, from the install directory, so the
modules and the interpreter are the ones that serve the pages:

    cd /opt/autostream && /opt/autostream/venv/bin/python /path/to/measure_page_import_heap.py

Imports the shared page helpers first (outside the measurement, since every
page imports them), then starts tracemalloc and imports the page modules,
and prints:

    label,traced_kB,peak_kB,modules

traced_kB is what stays allocated after the imports, peak_kB the most held
at any point during them.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import argparse
import importlib
import os
import sys
import tracemalloc

PAGE_MODULES = (
    "webui.assets",
    "webui.common",
    "webui.components",
    "autostream_auth",
    "webui.browser.about",
    "webui.browser.home",
    "webui.browser.align",
    "webui.browser.equaliser",
    "webui.browser.first_boot",
    "webui.browser.logs",
    "webui.browser.owntone",
    "webui.browser.rebooting",
    "webui.browser.service",
    "webui.browser.setup.page",
)


def measure(modules=PAGE_MODULES) -> tuple[float, float]:
    """Return (traced_kB, peak_kB) for importing *modules*."""
    importlib.import_module("webui.common")
    tracemalloc.start()
    try:
        for name in modules:
            importlib.import_module(name)
        current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return current / 1024.0, peak / 1024.0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[2])
    parser.add_argument("--label", default="page-import", help="first column of the output line")
    parser.add_argument("--core", default=os.getcwd(),
                        help="directory holding the modules (default: the current directory)")
    args = parser.parse_args(argv)
    if "," in args.label or any(c.isspace() for c in args.label):
        parser.error("label must not contain commas or white space")
    sys.path.insert(0, args.core)
    traced, peak = measure()
    print(f"{args.label},{traced:.0f},{peak:.0f},{len(PAGE_MODULES)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
