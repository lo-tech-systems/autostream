"""Regression: running autostream_webui.py as a script must alias itself
into sys.modules as "autostream_webui".

On the appliance the webui file is the process entrypoint, so it executes
as __main__. autostream_webui_routes.dispatch() resolves AUTH/STATE and
handlers via `import autostream_webui` at request time; without the alias
that import loads a SECOND copy of the module whose AUTH/STATE globals are
never set, and every dispatched request crashes with AUTH=None (observed
live on-appliance — the entire UI redirected to the nginx offline page
while all services showed active). Tests import the module by name, so
only this script-execution test can catch it.

The test executes the real file with run_name="__main__" (exactly the
appliance's execution mode) in a subprocess, with autostream_core stubbed
so run_autostream() never actually starts anything; the stub then checks
the alias identity from inside the running "process".
"""

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

DRIVER = r"""
import sys, runpy

# Import the REAL autostream_core (heavy but side-effect-free at import
# time) and replace only run_autostream, so the webui module body's other
# `from autostream_core import ...` names all resolve; the __main__ block's
# run_autostream() call then lands in our probe instead of starting the
# appliance.
import autostream_core

def run_autostream(config_path, start_webui=None, **kwargs):
    alias = sys.modules.get("autostream_webui")
    main_mod = sys.modules.get("__main__")
    print("ALIAS_PRESENT:", alias is not None)
    print("ALIAS_IS_MAIN:", alias is main_mod)
    # The routes dispatcher resolves attributes off this module object; the
    # names it needs must exist on the aliased module (still None until
    # start_webui_background runs, but present).
    print("HAS_AUTH_ATTR:", hasattr(alias, "AUTH"))

autostream_core.run_autostream = run_autostream

sys.argv = ["autostream_webui.py", "/tmp/nonexistent-config.json"]
runpy.run_path(sys.argv[0], run_name="__main__")
"""


def test_script_execution_aliases_module_name():
    result = subprocess.run(
        [sys.executable, "-c", DRIVER],
        cwd=str(REPO_ROOT / "core"),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    out = result.stdout
    assert "ALIAS_PRESENT: True" in out, out + result.stderr[-500:]
    assert "ALIAS_IS_MAIN: True" in out, out
    assert "HAS_AUTH_ATTR: True" in out, out
