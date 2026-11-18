"""dial_display_backend.py -- the output-only display backend protocol.

The protocol every panel backend implements, the no-op backend for a dial
without a panel, and the factory that resolves a screen type to the
hardware backend. It lives apart from the display manager so the hardware
module need not import the manager.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from typing import Callable

from dial_display_profiles import DEFAULT_PROFILE_KEY, get_profile, get_profile_or_default

# Fallback compose dimensions for when no backend is open yet (or it just
# closed) — the default profile's landscape 160x128, matching today's only
# shipped panel.
DEFAULT_PANEL_WIDTH = get_profile(DEFAULT_PROFILE_KEY).width
DEFAULT_PANEL_HEIGHT = get_profile(DEFAULT_PROFILE_KEY).height


class DisplayBackend:
    name = "backend"
    # Sourced from the default profile rather than hardcoded — these were
    # previously 128/160, the transpose of the real landscape panel (see
    # dial_display_profiles.py for why the panel is 160 wide x 128 tall).
    width = DEFAULT_PANEL_WIDTH
    height = DEFAULT_PANEL_HEIGHT
    # True when display_window() can write a sub-rectangle of the panel
    # in place. The manager only diffs frames against a backend that
    # says so; every other backend gets a whole-frame display() per push.
    supports_window_write = False

    def open(self) -> None: ...

    def close(self) -> None: ...

    def clear(self) -> None: ...

    def display(self, image) -> None: ...

    def display_window(self, region, x0: int, y0: int, x1: int, y1: int) -> bool:
        """Write *region*, a panel-space image exactly (x1 - x0 + 1) by
        (y1 - y0 + 1) pixels, to the panel's inclusive address window
        x0..x1, y0..y1, leaving every other pixel as it is. Returns True
        when the window was written and False when this backend cannot
        write a window right now (the caller then falls back to a whole-
        frame display()). May raise on a hardware failure, like display().
        The default cannot: it is the whole-frame-only contract."""
        return False

    def sleep(self) -> None: ...

    def wake(self) -> None: ...


class NoOpBackend(DisplayBackend):
    name = "noop"
    width = DEFAULT_PANEL_WIDTH
    height = DEFAULT_PANEL_HEIGHT

    def open(self) -> None:
        pass

    def close(self) -> None:
        pass

    def clear(self) -> None:
        pass

    def display(self, image) -> None:
        pass

    def sleep(self) -> None:
        pass

    def wake(self) -> None:
        pass


def backend_factory_for(screen_type: str) -> Callable[[], DisplayBackend]:
    """Resolve *screen_type* to a zero-arg AdafruitDisplayBackend factory,
    falling back to the default profile if the key is unresolvable.

    dial_display_adafruit imports hardware modules only inside its open()
    method, so importing it here is safe even when no screen is fitted or
    the Adafruit package is absent — screen_type resolution itself never
    touches hardware.
    """
    from dial_display_adafruit import AdafruitDisplayBackend

    profile = get_profile_or_default(screen_type)
    return lambda: AdafruitDisplayBackend(profile)
