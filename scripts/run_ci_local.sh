#!/usr/bin/env bash
# Run the CI test gate locally, the way .github/workflows/ci.yml runs it.
#
# The workflow file is the single source of truth: the Python version is
# parsed out of it, the dependency set is CI's own requirements file, and
# the pytest invocation is CI's verbatim — so this script cannot drift from
# CI without failing loudly.
#
# Usage (from WSL or any Linux shell, repo root):
#   scripts/run_ci_local.sh          # offline suite (CI job: offline-tests)
#   scripts/run_ci_local.sh --env    # + environment-dependent suite
#                                    #   (CI job: wsl-tests, via
#                                    #    scripts/run_wsl_tests.sh)
#
# Interpreter provisioning uses uv (installed per-user on first run, no
# sudo), which downloads the exact CPython CI uses regardless of what the
# distribution ships.
set -euo pipefail

cd "$(dirname "$0")/.."

WORKFLOW=.github/workflows/ci.yml
PYVER=$(grep -m1 'python-version:' "$WORKFLOW" | sed 's/.*"\(.*\)".*/\1/')
if [ -z "$PYVER" ]; then
  echo "ERROR: could not parse python-version from $WORKFLOW" >&2
  exit 1
fi
echo "CI python version (from $WORKFLOW): $PYVER"

if ! command -v uv >/dev/null 2>&1 && [ -x "$HOME/.local/bin/uv" ]; then
  export PATH="$HOME/.local/bin:$PATH"
fi
if ! command -v uv >/dev/null 2>&1; then
  echo "Installing uv (per-user, no sudo)..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi

# The venv lives on the native Linux filesystem, not under the repo: when
# the repo sits on a Windows mount, putting site-packages there makes every
# import cross the filesystem boundary and multiplies suite time ~5x.
VENV="$HOME/.cache/autostream-ci-venv-$PYVER"
if [ ! -x "$VENV/bin/python" ] || ! "$VENV/bin/python" -c "import sys; raise SystemExit(0 if sys.version_info[:2] == tuple(map(int, '$PYVER'.split('.'))) else 1)"; then
  echo "Creating $VENV with CPython $PYVER..."
  rm -rf "$VENV"
  uv venv --python "$PYVER" "$VENV"
fi
uv pip install --python "$VENV/bin/python" -q -r tests/requirements-ci.txt

echo "Interpreter: $("$VENV/bin/python" --version)"

# CI job "offline-tests", command verbatim.
"$VENV/bin/python" -m pytest tests/ -q --ignore=tests/playwright --timeout=60

if [ "${1:-}" = "--env" ]; then
  # CI job "wsl-tests". The script manages its own tool checks; run it under
  # the CI-matched interpreter.
  PATH="$(pwd)/$VENV/bin:$PATH" bash scripts/run_wsl_tests.sh
fi

echo "CI-local gate passed (python $PYVER)."
