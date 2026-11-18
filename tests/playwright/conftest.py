"""Browser selection for the Playwright tests.

pytest-playwright's --browser (repeatable) runs a test once per engine. The
default is Chromium only. The pointer-driven HD page classes carry the
`engines` marker; under any other engine only those run, so
`pytest tests/playwright -m engines --browser chromium --browser webkit`
checks them on both. An engine that cannot be launched here (not installed, or
missing system libraries) skips its tests with the reason instead of erroring.
"""
from __future__ import annotations

import subprocess
import sys

import pytest

_LAUNCH_CHECK = (
    "import sys\n"
    "from playwright.sync_api import sync_playwright\n"
    "with sync_playwright() as p:\n"
    "    getattr(p, sys.argv[1]).launch().close()\n"
)

_launchable: dict[str, str | None] = {}


@pytest.fixture(scope="session", autouse=True)
def _state_store_in_test_mode():
    """Put the state store in test mode before any module fixture runs.

    The page stubs are served from module-scoped fixtures, which set up before
    the per-test store reset, and they arrange the parts they render through
    the store's test-only writer.
    """
    from pathlib import Path

    core = str(Path(__file__).resolve().parents[2] / "core")
    if core not in sys.path:
        sys.path.insert(0, core)
    import autostream_state

    autostream_state.store().reset_for_tests()


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "engines: pointer-driven HD page tests that also run under every --browser engine"
    )


def _why_not_launchable(name: str) -> str | None:
    """None if the engine launches, else a one-line reason (checked once per engine)."""
    if name not in _launchable:
        try:
            done = subprocess.run(
                [sys.executable, "-c", _LAUNCH_CHECK, name],
                capture_output=True, text=True, timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            _launchable[name] = f"{name} could not be started ({exc.__class__.__name__}): playwright install {name}"
        else:
            if done.returncode == 0:
                _launchable[name] = None
            else:
                text = done.stderr
                missing = [ln.strip("║ \n") for ln in text.splitlines() if ".so" in ln]
                if "Executable doesn't exist" in text:
                    _launchable[name] = f"{name} not installed: playwright install {name}"
                elif missing:
                    _launchable[name] = (
                        f"{name} cannot launch, {len(missing)} system libraries missing "
                        f"(first: {missing[0]}): playwright install-deps {name}"
                    )
                else:
                    last = next((ln for ln in reversed(text.splitlines()) if ln.strip()), "launch failed")
                    _launchable[name] = f"{name} cannot launch: {last.strip()}"
    return _launchable[name]


def _engine(item) -> str:
    callspec = getattr(item, "callspec", None)
    return callspec.params.get("browser_name", "chromium") if callspec else "chromium"


def pytest_collection_modifyitems(config, items):
    kept, dropped = [], []
    for item in items:
        if _engine(item) != "chromium" and item.get_closest_marker("engines") is None:
            dropped.append(item)
        else:
            kept.append(item)
    if dropped:
        config.hook.pytest_deselected(items=dropped)
        items[:] = kept
    for item in items:
        callspec = getattr(item, "callspec", None)
        if callspec is None or "browser_name" not in callspec.params:
            continue
        name = callspec.params["browser_name"]
        reason = _why_not_launchable(name)
        if reason:
            item.add_marker(pytest.mark.skip(reason=reason))
