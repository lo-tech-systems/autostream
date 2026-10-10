"""Session-scoped test configuration.

Registers stubs for optional native dependencies that are declared in
core/requirements.txt but may not be installed in the test environment.
Also provides autouse fixtures that reset module-level mutable globals so
that tests pass in any collection order.
"""
import importlib.util
import os
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# requests stub — only when the real package is absent
# ---------------------------------------------------------------------------

try:
    import requests as _requests_real  # noqa: F401
except ImportError:
    # Real package not installed: provide a stub that is safe for both normal
    # use (return-value mocking) and exception-path tests.  The exception
    # classes must inherit from BaseException so that `except requests.Foo`
    # clauses work correctly in the production code under test.
    _stub = MagicMock()
    _stub.RequestException = type("RequestException", (IOError,), {})
    _stub.ConnectionError = type("ConnectionError", (_stub.RequestException,), {})
    _stub.Timeout = type("Timeout", (_stub.RequestException,), {})
    _stub.HTTPError = type("HTTPError", (_stub.RequestException,), {})
    sys.modules.setdefault("requests", _stub)


# ---------------------------------------------------------------------------
# Helpers for loading extensionless supervisor scripts
# ---------------------------------------------------------------------------

def load_supervisor_script(name: str, unique_alias: str | None = None) -> ModuleType:
    """Load an extensionless supervisor script by name.

    Loads the file as a module under *unique_alias* (defaults to *name*) so
    that multiple callers can load the same script under different names without
    collisions in sys.modules.  Platform stubs (fcntl, pwd, grp) are injected
    on Windows where the POSIX headers are unavailable, and removed afterwards
    so that subsequent imports in other tests are not affected.
    """
    repo_root = Path(__file__).parent.parent
    path = repo_root / "supervisor" / name
    alias = unique_alias or name

    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader(alias, str(path))
    spec = importlib.util.spec_from_loader(alias, loader)
    mod = importlib.util.module_from_spec(spec)

    _injected: list[str] = []
    if sys.platform == "win32":
        for stub_name in ("fcntl", "pwd", "grp"):
            if stub_name not in sys.modules:
                sys.modules[stub_name] = MagicMock()
                _injected.append(stub_name)

    try:
        loader.exec_module(mod)
    finally:
        for stub_name in _injected:
            sys.modules.pop(stub_name, None)

    return mod


# ---------------------------------------------------------------------------
# Bash capability detection (shared with test_offline_cgi)
# ---------------------------------------------------------------------------

def bash_can_run_script_at_windows_path() -> bool:
    """Return True only if bash can execute a script file at a Windows-style path.

    Running `bash -c :` is insufficient on Windows: the WSL launcher satisfies
    that probe but cannot consume Windows paths of the form C:\\...  We write a
    temporary no-op script and execute it the same way the CGI tests do.
    """
    import subprocess
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sh", delete=False
        ) as tmp:
            tmp.write("exit 0\n")
            tmp_path = tmp.name
        try:
            result = subprocess.run(
                ["bash", tmp_path],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Autouse fixtures — reset mutable module globals between tests
# ---------------------------------------------------------------------------

def _mod(name: str) -> ModuleType | None:
    """Return the already-imported module or None without triggering an import."""
    return sys.modules.get(name)


@pytest.fixture(autouse=True)
def _hermetic_playing_announcement(monkeypatch):
    """Keep the LAN playing announcement inert for every test.

    The coordinator's poll cycle syncs the _autostream-playing._tcp
    announcement from the session state each iteration, and starts a
    60-second reconcile thread once per process. Tests that drive
    run_autostream()/the poll cycle with mock monitors would therefore
    invoke the real avahi service-file helpers (a sudo autostream_admin
    subprocess per transition) and leave a real daemon thread running for
    the rest of the pytest session. Stub both at the autostream_core
    import site; tests that assert on the announcement itself re-patch
    these names inside the test, which nests over this seal.

    autostream_core is imported here (not looked up lazily) because many
    coordinator tests import it inside the test body, after fixture setup.
    """
    repo_core = str(Path(__file__).parent.parent / "core")
    if repo_core not in sys.path:
        sys.path.insert(0, repo_core)
    try:
        import autostream_core as m
    except Exception:
        yield
        return
    monkeypatch.setattr(m, "write_avahi_playing_service", lambda version, appliance_id=None: True)
    monkeypatch.setattr(m, "remove_avahi_playing_service", lambda: True)
    monkeypatch.setattr(m, "_start_playing_reconciliation", lambda version: None)
    m._playing_announced = False
    yield
    m._playing_announced = False
    m._playing_version = None
    m._reconcile_started = False


@pytest.fixture(autouse=True)
def _reset_player_state():
    """Save/restore player backend registry; clear detection cache after each test."""
    m = _mod("autostream_players")
    saved_registry = dict(m.REGISTRY._backend_classes) if m is not None else None
    yield
    m = _mod("autostream_players")
    if m is not None:
        m.REGISTRY._backend_classes.clear()
        if saved_registry is not None:
            m.REGISTRY._backend_classes.update(saved_registry)
    ps = _mod("autostream_player_service")
    if ps is not None:
        ps._DETECTION_CACHE.clear()


@pytest.fixture(autouse=True)
def _reset_dial_mdns():
    """Clear dial mDNS discovery maps after each test."""
    yield
    m = _mod("dial_mdns")
    if m is not None:
        browser = getattr(m, "_browser", None)
        if browser is not None:
            with browser._lock:
                browser._by_key.clear()
                browser._by_identity.clear()
        state_lock = getattr(m, "_state_lock", None)
        if state_lock is not None:
            with state_lock:
                m._target_state.clear()
        general_browser = getattr(m, "_general_browser", None)
        if general_browser is not None:
            with general_browser._lock:
                general_browser._by_key.clear()
                general_browser._by_identity.clear()
        general_lock = getattr(m, "_general_lock", None)
        if general_lock is not None:
            with general_lock:
                m._general_svc.clear()
                m._general_conflicts.clear()


@pytest.fixture(autouse=True)
def _reset_dial_auth():
    """Clear the dial auth map's module singleton after each test."""
    yield
    m = _mod("dial_auth")
    if m is not None:
        m.auth_map.reset()


@pytest.fixture(autouse=True)
def _reset_dial_volume_fail_counts():
    """Clear dial volume sender failure counters after each test."""
    yield
    m = _mod("dial_volume")
    if m is not None:
        m._fail_counts.clear()


@pytest.fixture(autouse=True)
def _reset_dial_pin_attempts():
    """Clear dial PIN rate-limiting map after each test."""
    yield
    m = _mod("dial_http_server")
    if m is not None:
        m._pin_attempts.clear()


@pytest.fixture(autouse=True)
def _reset_core_monitors():
    """Clear the core audio-monitor list and save/restore _playback_tracker after each test."""
    m = _mod("autostream_core")
    saved_tracker = m._playback_tracker if m is not None else None
    yield
    m = _mod("autostream_core")
    if m is not None:
        m.all_monitors.clear()
        m._playback_tracker = saved_tracker


@pytest.fixture(autouse=True)
def _reset_webui_api_fail_counts():
    """Reset web-UI API failure counters after each test."""
    yield
    m = _mod("autostream_webui_api")
    if m is not None:
        m._audio_status_fail_count = 0


@pytest.fixture(autouse=True)
def _reset_mute_state():
    """Unmute and forget remembered levels after each test: the mute state is
    process-wide, and a test that ends muted would otherwise turn a later
    test's volume step into a restore of the remembered levels."""
    yield
    m = _mod("autostream_mute_state")
    if m is not None:
        m.reset_for_tests()


@pytest.fixture(autouse=True)
def _reset_dial_repeat_store():
    """Clear the dial repeat store's module singleton after each test."""
    yield
    m = _mod("dial_repeat_store")
    if m is not None:
        with m.repeat_store._lock:
            m.repeat_store._records.clear()


@pytest.fixture(autouse=True)
def _reset_dial_seek_rate_limit():
    """Reset the dial repeat-seek rate-limit timer after each test."""
    yield
    m = _mod("autostream_webui_api")
    if m is not None:
        m._dial_seek_last = 0.0


@pytest.fixture(autouse=True)
def _reset_dial_repeat_worker():
    """Reset the dial repeat-transport worker's module state after each
    test — a fresh queue (so a leftover enqueued item from one test can
    never be drained by the next) and cleared cfg/on_result (so a stray
    worker thread from an earlier test can never call into another test's
    callback)."""
    yield
    m = _mod("dial_repeat")
    if m is not None:
        import queue as _queue_mod
        m._queue = _queue_mod.SimpleQueue()
        m._cfg = None
        m._on_result = None


@pytest.fixture(autouse=True)
def _reset_dial_mute_observation_store():
    """Clear the dial volume module's mute observation store (entries,
    settled times and in-flight marks) after each test, so a mark or settled
    time left by one test can never make a later test's poll observation
    get ignored."""
    yield
    m = _mod("dial_volume")
    if m is not None:
        m.observe_mute_state(None, None)
