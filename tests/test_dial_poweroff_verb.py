"""poweroff verb: supervisor/autostream_admin and its sudoers grant.

A zero-argument verb with a literal command that lets a dial power itself
off a few seconds after it is asked (the HD page's Shut down button). Covers:
  - the verb is declared as a subparser and dispatches to schedule_poweroff()
  - the power-off is scheduled on a transient timer, so the caller's reply
    goes out first, and the command is a literal
  - the sudoers grant is present, NOPASSWD, exact-verb and unwildcarded
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "tests"))
from conftest import load_supervisor_script

m = load_supervisor_script("autostream_admin", "admin_dial_poweroff")

_REPO_ROOT = Path(__file__).parent.parent
_ADMIN_SCRIPT = _REPO_ROOT / "supervisor" / "autostream_admin"
_SUDOERS_DIAL = _REPO_ROOT / "system" / "sudoers" / "autostream_dial"


class TestVerbDeclaredAndDispatched:
    def test_verb_parses(self):
        assert m.parse_args(["poweroff"]).command == "poweroff"

    def test_verb_takes_no_arguments(self):
        with pytest.raises(SystemExit):
            m.parse_args(["poweroff", "extra-arg"])

    @pytest.mark.parametrize("scheduled,code", [(True, 0), (False, 1)])
    def test_dispatches_to_schedule_poweroff(self, scheduled, code):
        with patch("os.geteuid", return_value=0, create=True), \
             patch.object(m, "schedule_poweroff", return_value=scheduled) as mock_fn:
            rc = m.main(["poweroff"])
        mock_fn.assert_called_once_with()
        assert rc == code


class TestSchedulePoweroff:
    def _run(self, *, systemd_run="/usr/bin/systemd-run", bin_exists=True, rc=0):
        binary = Path(__file__) if bin_exists else Path("/nonexistent/poweroff")
        with patch.object(m, "find_systemd_run", return_value=systemd_run), \
             patch.object(m, "POWEROFF_BIN", binary), \
             patch.object(m, "run_cmd", return_value=(rc, "", "boom")) as run:
            ok = m.schedule_poweroff()
        return ok, run, binary

    def test_success_schedules_a_delayed_literal_command(self):
        ok, run, binary = self._run()
        assert ok is True
        cmd = run.call_args[0][0]
        assert cmd[0] == "/usr/bin/systemd-run"
        assert f"--on-active={m.POWEROFF_DELAY_SECONDS}" in cmd
        assert cmd[-2:] == ["--", str(binary)]
        assert m.POWEROFF_DELAY_SECONDS > 0

    def test_a_failed_schedule_is_false(self):
        ok, _, _binary = self._run(rc=1)
        assert ok is False

    def test_no_systemd_run_is_false(self):
        ok, run, _binary = self._run(systemd_run=None)
        assert ok is False
        run.assert_not_called()

    def test_no_poweroff_binary_is_false(self):
        ok, run, _binary = self._run(bin_exists=False)
        assert ok is False
        run.assert_not_called()

    # Guards the sudoers grant: the verb must take nothing from its caller.
    def test_the_function_takes_no_arguments_and_never_reads_the_namespace(self):
        tree = ast.parse(_ADMIN_SCRIPT.read_text(encoding="utf-8"))
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "schedule_poweroff")
        assert fn.args.args == [] and fn.args.vararg is None and fn.args.kwarg is None
        assert "args" not in {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}


class TestSudoersGrant:
    LINE = (
        "autostream ALL=(root) NOPASSWD: "
        "/usr/local/libexec/autostream/autostream_admin poweroff"
    )

    def test_the_grant_line_is_present_verbatim_and_alone(self):
        lines = [ln.strip() for ln in _SUDOERS_DIAL.read_text(encoding="utf-8").splitlines()]
        assert self.LINE in lines
        assert len([ln for ln in lines if ln.endswith(" poweroff") and not ln.startswith("#")]) == 1

    def test_the_grant_has_no_wildcard(self):
        for ln in _SUDOERS_DIAL.read_text(encoding="utf-8").splitlines():
            if "poweroff" in ln and not ln.strip().startswith("#"):
                assert "*" not in ln
