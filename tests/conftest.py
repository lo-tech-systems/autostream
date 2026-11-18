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


def pytest_configure(config):
    # The tests build scratch trees that stand for what root creates, and the
    # code under test refuses state a group can write. Root's services run
    # under umask 022, but a login on Raspberry Pi OS defaults to 002, which
    # would leave every scratch directory group-writable. Fix it for the run.
    os.umask(0o022)


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
# The output authority never starts threads under test
# ---------------------------------------------------------------------------
# Set once, when this module is imported: no fixture, so no per-test cost. A
# test that runs the process bootstrap gets an authority that writes inline;
# the started_authority fixture turns threads on for one test.

_CORE_DIR = str(Path(__file__).resolve().parent.parent / "core")
if _CORE_DIR not in sys.path:
    sys.path.insert(0, _CORE_DIR)
import autostream_state.outputs as _outputs_module  # noqa: E402

_outputs_module._threads_allowed = False

# Every intent handler is bound when its module is imported, and the process
# imports them all at start. Importing the coordinator once here binds them for
# every test, whichever files run first.
import autostream_core  # noqa: E402,F401


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

    # The scripts import the shared support module from their own directory
    # when installed; give them the same view of the source tree.
    if str(path.parent) not in sys.path:
        sys.path.insert(0, str(path.parent))

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

    # The scripts expect their root-only update directory to belong to root.
    # A test runs as an ordinary user, so the user running it stands in.
    if hasattr(mod, "UPDATE_STATE_UID") and hasattr(os, "getuid"):
        mod.UPDATE_STATE_UID = os.getuid()

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
def _hermetic_session_flag(monkeypatch, tmp_path):
    """Point the playback-session flag at a scratch file for every test.

    The coordinator's poll cycle syncs the flag from the session state each
    iteration. Tests that drive run_autostream()/the poll cycle with mock
    monitors would otherwise create and remove the real flag under
    /run/autostream-pipes. Tests that assert on the flag itself patch the
    path again inside the test, which nests over this one.
    """
    repo_core = str(Path(__file__).parent.parent / "core")
    if repo_core not in sys.path:
        sys.path.insert(0, repo_core)
    try:
        import autostream_session_flag as session_flag
    except Exception:
        yield
        return
    monkeypatch.setattr(session_flag, "SESSION_FLAG_PATH", tmp_path / "session-active")
    session_flag.reset_for_tests()
    yield
    session_flag.reset_for_tests()


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
        ps._CONFIDENT.clear()
        ps._KEPT_LOGGED.clear()


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
    m = _mod("dial_pin_guard")
    if m is not None:
        m.reset_for_tests()


@pytest.fixture(autouse=True)
def _reset_runtime():
    """Return the process-wide runtime state (monitor list, playback tracker,
    identification service and gate, stop and reload events) to its start-up
    values after each test."""
    yield
    m = _mod("autostream_runtime")
    if m is not None:
        m.reset_for_tests()


@pytest.fixture(autouse=True)
def _reset_log_every():
    """Forget the per-key log timers after each test."""
    yield
    m = _mod("autostream_logging")
    if m is not None:
        m.reset_for_tests()


@pytest.fixture(autouse=True)
def _reset_owntone_mute_emulation():
    """Forget the levels the upstream OwnTone mute emulation keeps."""
    yield
    m = _mod("autostream_owntone")
    if m is not None:
        m.reset_mute_emulation_for_tests()


@pytest.fixture(autouse=True)
def _reset_audio_status_fail_count():
    """Reset the audio-status failure counter after each test."""
    yield
    m = _mod("webui.browser.home_api")
    if m is not None:
        m._audio_status_fail_count = 0



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


@pytest.fixture(autouse=True)
def _reset_pin_pairing():
    """Clear the pairing claims and PIN attempt counts around every test."""
    m = _mod("autostream_pin_pairing")
    if m is not None:
        m.STATE.reset()
    yield
    m = _mod("autostream_pin_pairing")
    if m is not None:
        m.STATE.reset()


@pytest.fixture(autouse=True)
def _reset_state_store():
    """Give every test a fresh state store, and fail the test that leaves a
    publish un-notified.

    A writer that publishes and forgets to call notify() on the result leaves
    subscribers uninformed, which no assertion of the test would notice. The
    store keeps a record of every such publish in test mode, whether the
    result is still alive or already collected, so no collection is forced
    here: on a full run a collection after every test costs more than the
    tests themselves.
    """
    repo_core = str(Path(__file__).parent.parent / "core")
    if repo_core not in sys.path:
        sys.path.insert(0, repo_core)
    import autostream_state

    autostream_state.store().reset_for_tests()
    intents_table = _mod("autostream_intents.table")
    if intents_table is not None:
        intents_table.reset_for_tests()
    _outputs_module.get_authority().reset_for_tests()
    # A player as the current owntone-mini presents itself: it starts a
    # speaker at the level it is enabled with. A test of an older player
    # says otherwise.
    _outputs_module.get_authority().assume_start_volume_for_tests()
    live_config = _mod("autostream_live_config")
    if live_config is not None:
        live_config.reset_output_settings_for_tests()
    output_policy = _mod("autostream_output_policy")
    if output_policy is not None:
        output_policy.get_policy().reset_for_tests()
    yield
    leaked = autostream_state.store().take_leaked()
    if leaked:
        pytest.fail(
            "state: %d publish(es) never notified; created at:\n%s"
            % (len(leaked), "\n---\n".join(leaked)),
            pytrace=False,
        )


@pytest.fixture
def started_authority(monkeypatch):
    """The output authority with its threads running, for the one test that
    asks. The threads are stopped afterwards, and the authority reset by the
    store fixture."""
    monkeypatch.setattr(_outputs_module, "_threads_allowed", True)
    authority = _outputs_module.get_authority()
    yield authority
    authority.stop(timeout=5.0)


@pytest.fixture
def fake_store():
    """Put parts into the process state store without their owners."""
    from fake_store import FakeStore
    return FakeStore()

