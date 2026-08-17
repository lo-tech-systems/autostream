"""restart-dial-service verb — supervisor/autostream_admin and its sudoers grant.

A zero-argument, hardcoded-unit verb that lets a dial restart its own
systemd unit. Covers:
  - the verb is declared as a subparser and dispatches to restart_dial_service()
  - the systemd unit name is a literal in the source, never built from argv
  - the sudoers grant is present, NOPASSWD, exact-verb, and unwildcarded
  - the sudoers file's own verb-count comment stays truthful
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "tests"))
from conftest import load_supervisor_script

m = load_supervisor_script("autostream_admin", "admin_dial_restart")

_REPO_ROOT = Path(__file__).parent.parent
_ADMIN_SCRIPT = _REPO_ROOT / "supervisor" / "autostream_admin"
_SUDOERS_DIAL = _REPO_ROOT / "system" / "sudoers" / "autostream_dial"


# ---------------------------------------------------------------------------
# Verb declared and dispatched
# ---------------------------------------------------------------------------

class TestVerbDeclaredAndDispatched:
    def test_verb_parses(self):
        args = m.parse_args(["restart-dial-service"])
        assert args.command == "restart-dial-service"

    def test_verb_takes_no_arguments(self):
        with pytest.raises(SystemExit):
            m.parse_args(["restart-dial-service", "extra-arg"])

    def test_dispatches_to_restart_dial_service(self):
        with patch("os.geteuid", return_value=0, create=True), \
             patch.object(m, "restart_dial_service", return_value=True) as mock_fn:
            rc = m.main(["restart-dial-service"])
        mock_fn.assert_called_once_with()
        assert rc == 0

    def test_failure_returns_exit_code_1(self):
        with patch("os.geteuid", return_value=0, create=True), \
             patch.object(m, "restart_dial_service", return_value=False):
            rc = m.main(["restart-dial-service"])
        assert rc == 1


# ---------------------------------------------------------------------------
# restart_dial_service() behaviour
# ---------------------------------------------------------------------------

class TestRestartDialServiceBehaviour:
    def test_success_returns_true(self):
        with patch.object(m, "find_systemctl", return_value="/bin/systemctl"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = ""
            mock_run.return_value.stderr = ""
            result = m.restart_dial_service()
        assert result is True

    def test_failure_returns_false_and_logs_rc_and_stderr(self):
        with patch.object(m, "find_systemctl", return_value="/bin/systemctl"), \
             patch("subprocess.run") as mock_run, \
             patch.object(m, "log") as mock_log:
            mock_run.return_value.returncode = 1
            mock_run.return_value.stdout = ""
            mock_run.return_value.stderr = "unit not found"
            result = m.restart_dial_service()
        assert result is False
        error_calls = [c for c in mock_log.call_args_list if c.args[0] == "ERROR"]
        assert error_calls, "a failure must log at ERROR"
        msg = error_calls[-1].args[1]
        assert "rc=1" in msg
        assert "unit not found" in msg

    def test_no_systemctl_returns_false(self):
        with patch.object(m, "find_systemctl", return_value=None):
            result = m.restart_dial_service()
        assert result is False

    def test_call_uses_the_literal_unit_name(self):
        with patch.object(m, "find_systemctl", return_value="/bin/systemctl"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = ""
            mock_run.return_value.stderr = ""
            m.restart_dial_service()
        cmd = mock_run.call_args[0][0]
        assert cmd == ["/bin/systemctl", "restart", "autostream_dial"]

    def test_call_is_bounded_by_a_timeout(self):
        with patch.object(m, "find_systemctl", return_value="/bin/systemctl"), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = ""
            mock_run.return_value.stderr = ""
            m.restart_dial_service()
        _, kwargs = mock_run.call_args
        assert kwargs.get("timeout"), "systemctl restart call must be bounded by a timeout"
        assert kwargs["timeout"] == m._RESTART_DIAL_TIMEOUT_SECONDS

    def test_timeout_expiry_returns_false(self):
        import subprocess as _subprocess
        with patch.object(m, "find_systemctl", return_value="/bin/systemctl"), \
             patch("subprocess.run",
                   side_effect=_subprocess.TimeoutExpired(cmd="systemctl", timeout=30.0)):
            result = m.restart_dial_service()
        assert result is False

    def test_success_logs_info(self):
        with patch.object(m, "find_systemctl", return_value="/bin/systemctl"), \
             patch("subprocess.run") as mock_run, \
             patch.object(m, "log") as mock_log:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = ""
            mock_run.return_value.stderr = ""
            m.restart_dial_service()
        info_calls = [c for c in mock_log.call_args_list if c.args[0] == "INFO"]
        assert any("restart-dial-service" in c.args[1] for c in info_calls)


# ---------------------------------------------------------------------------
# Unit name is a hardcoded literal, never derived from argv
# ---------------------------------------------------------------------------

class TestUnitNameIsLiteral:
    """The plan requires the unit name to be an in-function literal string,
    never built from caller-supplied argv, so a compromised/careless caller
    cannot redirect the restart to an arbitrary unit (privilege escalation).
    """

    def _find_function(self, tree: ast.Module, name: str) -> ast.FunctionDef:
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == name:
                return node
        raise AssertionError(f"function {name!r} not found in AST")

    def test_restart_dial_service_takes_no_arguments(self):
        tree = ast.parse(_ADMIN_SCRIPT.read_text(encoding="utf-8"))
        fn = self._find_function(tree, "restart_dial_service")
        assert fn.args.args == [], "restart_dial_service must take zero arguments"
        assert fn.args.vararg is None
        assert fn.args.kwarg is None

    def test_systemctl_restart_call_uses_a_string_constant_unit_name(self):
        """Walk the function body for the subprocess.run/Popen call list argument
        and assert its unit-name element is an ast.Constant (a literal), not a
        Name, Attribute, or f-string built from args."""
        tree = ast.parse(_ADMIN_SCRIPT.read_text(encoding="utf-8"))
        fn = self._find_function(tree, "restart_dial_service")

        found_list = None
        for node in ast.walk(fn):
            if isinstance(node, ast.List) and len(node.elts) == 3:
                # Expect [<systemctl>, "restart", "<unit>"]
                second = node.elts[1]
                if isinstance(second, ast.Constant) and second.value == "restart":
                    found_list = node
                    break
        assert found_list is not None, "could not locate the systemctl restart argv list"
        unit_arg = found_list.elts[2]
        assert isinstance(unit_arg, ast.Constant), (
            "the unit name argument must be a literal constant, not derived from argv"
        )
        assert unit_arg.value == "autostream_dial"

    def test_no_args_namespace_referenced_in_function_body(self):
        """restart_dial_service() must never touch an argparse Namespace (the
        'args' parameter every other verb function takes), since that is the
        only channel through which caller input could reach it."""
        tree = ast.parse(_ADMIN_SCRIPT.read_text(encoding="utf-8"))
        fn = self._find_function(tree, "restart_dial_service")
        names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
        assert "args" not in names

    def test_literal_string_autostream_dial_present_in_source(self):
        text = _ADMIN_SCRIPT.read_text(encoding="utf-8")
        assert '"autostream_dial"' in text


# ---------------------------------------------------------------------------
# sudoers grant: exact, NOPASSWD, unwildcarded, single verb
# ---------------------------------------------------------------------------

class TestSudoersGrant:
    EXPECTED_LINE = (
        "autostream ALL=(root) NOPASSWD: "
        "/usr/local/libexec/autostream/autostream_admin restart-dial-service"
    )

    def test_sudoers_file_exists(self):
        assert _SUDOERS_DIAL.exists()

    def test_grant_line_present_verbatim(self):
        text = _SUDOERS_DIAL.read_text(encoding="utf-8")
        lines = [ln.strip() for ln in text.splitlines()]
        assert self.EXPECTED_LINE in lines

    def test_grant_is_nopasswd(self):
        text = _SUDOERS_DIAL.read_text(encoding="utf-8")
        for line in text.splitlines():
            if "restart-dial-service" in line and not line.strip().startswith("#"):
                assert "NOPASSWD:" in line
                return
        pytest.fail("restart-dial-service grant line not found")

    def test_grant_has_no_wildcard(self):
        text = _SUDOERS_DIAL.read_text(encoding="utf-8")
        for line in text.splitlines():
            if "restart-dial-service" in line and not line.strip().startswith("#"):
                assert "*" not in line
                return
        pytest.fail("restart-dial-service grant line not found")

    def test_grant_names_exactly_this_verb_and_no_others(self):
        """The grant line must end at the verb itself — no trailing tokens that
        would broaden it beyond exactly `restart-dial-service`."""
        text = _SUDOERS_DIAL.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if "restart-dial-service" in stripped and not stripped.startswith("#"):
                assert stripped.endswith("restart-dial-service")
                return
        pytest.fail("restart-dial-service grant line not found")

    def test_only_one_restart_dial_service_grant_line(self):
        text = _SUDOERS_DIAL.read_text(encoding="utf-8")
        matches = [
            ln for ln in text.splitlines()
            if "restart-dial-service" in ln and not ln.strip().startswith("#")
        ]
        assert len(matches) == 1


# ---------------------------------------------------------------------------
# sudoers header comment stays truthful about the verb count
# ---------------------------------------------------------------------------

class TestSudoersHeaderCommentAccuracy:
    def test_header_no_longer_claims_four_verbs(self):
        text = _SUDOERS_DIAL.read_text(encoding="utf-8")
        header = "\n".join(text.splitlines()[:6])
        assert "Four verbs only" not in header

    def test_header_verb_count_matches_actual_autostream_user_grants(self):
        """Extract the count word from the header comment (e.g. 'Five verbs
        only') and assert it matches the number of non-comment grant lines
        for the `autostream` user — the same user the header describes."""
        text = _SUDOERS_DIAL.read_text(encoding="utf-8")
        header_match = re.search(r"(\w+) verbs only", text)
        assert header_match, "header must state a verb count (e.g. 'Five verbs only')"

        word_to_number = {
            "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
            "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
        }
        claimed = word_to_number.get(header_match.group(1).lower())
        assert claimed is not None, f"unrecognised count word: {header_match.group(1)!r}"

        actual = sum(
            1 for ln in text.splitlines()
            if ln.strip().startswith("autostream ALL=(root) NOPASSWD:")
        )
        assert claimed == actual, (
            f"header claims {claimed} verbs but {actual} autostream grant lines exist"
        )
