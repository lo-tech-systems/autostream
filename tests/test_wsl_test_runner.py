"""Regression tests for the local WSL test runner."""

from pathlib import Path


REPO_ROOT = Path(__file__).parent.parent
WSL_RUNNER = REPO_ROOT / "scripts" / "run_wsl_tests.sh"


def test_dependency_probe_checks_every_required_python_package():
    source = WSL_RUNNER.read_text(encoding="utf-8")

    assert 'python3 -c "import pytest, flask, requests"' in source
    assert (
        "python3 -m pip install --user --break-system-packages --quiet "
        "pytest flask requests"
    ) in source
