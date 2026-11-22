"""tests/test_setup_card_registry.py

The Setup page's card registry: importing the page module fills it with the
nine cards, in the order they appear on the page (Input 3 is registered on
every appliance and shown only where Bluetooth is installed).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

CORE = Path(__file__).resolve().parent.parent / "core"

EXPECTED = [
    ("input1", "Input 1"),
    ("input2", "Input 2"),
    ("input3", "Input 3 (Bluetooth)"),
    ("playback", "Playback"),
    ("track-id", "Track Identification"),
    ("dials", "Dials"),
    ("customise", "Personalisation"),
    ("system", "System"),
    ("factory-reset", "Factory Reset"),
]


def test_the_page_module_registers_the_nine_cards_in_page_order():
    import webui.browser.setup.page  # noqa: F401  (registers the cards)
    from webui.browser.setup import context

    assert [(c.key, c.title) for c in context.CARDS] == EXPECTED


def test_importing_only_the_page_module_gives_a_full_registry():
    code = (
        "import sys; sys.path.insert(0, %r)\n"
        "import webui.browser.setup.page\n"
        "from webui.browser.setup import context\n"
        "print([c.key for c in context.CARDS])\n" % str(CORE)
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str([key for key, _title in EXPECTED])
