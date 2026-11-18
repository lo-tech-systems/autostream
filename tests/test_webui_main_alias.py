"""Regression: running autostream_webui.py as a script starts the coordinator
with the web server of the package, and registers no module of its own name.

On the appliance the entry file is the process entrypoint, so it executes as
__main__. The web code lives in the webui package and keeps its shared state
(STATE, AUTH) in webui.session_state, always imported by that name, so there
is no second copy of anything to alias. This test executes the real file with
run_name="__main__" (exactly the appliance's execution mode) in a subprocess,
with run_autostream replaced so that nothing is started, and checks what the
entry hands it.
"""

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

DRIVER = r"""
import sys, runpy

# Import the REAL autostream_core (heavy but side-effect-free at import
# time) and replace only run_autostream, so the __main__ block's
# run_autostream() call lands in our probe instead of starting the
# appliance.
import autostream_core

def run_autostream(config_path, start_webui=None, **kwargs):
    server = sys.modules.get("webui.server")
    print("SERVER_LOADED:", server is not None)
    print("STARTS_SERVER:", start_webui is getattr(server, "start_server", None))
    print("CONFIG_PATH:", config_path)
    print("NO_ENTRY_ALIAS:", "autostream_webui" not in sys.modules)

autostream_core.run_autostream = run_autostream

sys.argv = ["autostream_webui.py", "/tmp/nonexistent-config.json"]
runpy.run_path(sys.argv[0], run_name="__main__")
"""


def test_script_execution_starts_the_package_server():
    result = subprocess.run(
        [sys.executable, "-c", DRIVER],
        cwd=str(REPO_ROOT / "core"),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    out = result.stdout
    assert "SERVER_LOADED: True" in out, out + result.stderr[-500:]
    assert "STARTS_SERVER: True" in out, out
    assert "CONFIG_PATH: /tmp/nonexistent-config.json" in out, out
    assert "NO_ENTRY_ALIAS: True" in out, out


def test_wrong_argument_count_prints_usage():
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "core" / "autostream_webui.py")],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 1
    assert "Usage:" in result.stdout
