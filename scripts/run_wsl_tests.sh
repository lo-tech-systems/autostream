#!/usr/bin/env bash
# Run the environment-dependent test suite inside WSL.
#
# This unlocks the ~116 tests that are skipped on Windows because they require
# Linux system calls or tools:
#   - Unix sockets (AF_UNIX)           test_dial_control_socket, test_track_id_vibra_shazam
#   - os.mkfifo                        test_player_service
#   - fcntl / sys.platform == "linux"  test_p7_concurrency, test_p0_config_ownership, test_sysutils
#   - g++ / build-essential            test_p8_native_monitor, test_native_monitor
#   - shellcheck                       test_installer_ownership
#   - nginx                            test_dial_nginx_config (validity check)
#   - bash (native Linux path)         test_offline_cgi, test_dial_cgi_logs, test_p0_update_schema
#
# NOTE — WSL vs full Linux CI differences:
#   systemd tests (test_p4_deployment_policy::TestLinuxServiceValidation) fail in
#   standard WSL2 because systemd-analyze requires systemd to be running.
#   These tests do pass in the GitHub Actions ubuntu-latest runner.
#   To enable systemd in WSL2: https://learn.microsoft.com/en-us/windows/wsl/systemd
#
# One-time tool setup (run once with your password):
#   wsl -- sudo apt-get install -y g++ shellcheck nginx nodejs build-essential
#
# Usage (from repo root on Windows):
#   wsl -- bash scripts/run_wsl_tests.sh
#   wsl -- bash scripts/run_wsl_tests.sh tests/test_p8_native_monitor.py

set -euo pipefail

# ── Python deps (no sudo needed) ────────────────────────────────────────────
export PATH="$HOME/.local/bin:$PATH"

if ! python3 -c "import pytest, flask, requests" &>/dev/null; then
    echo "Installing Python test dependencies..."
    python3 -m pip install --user --break-system-packages --quiet pytest flask requests
fi

# ── Warn about missing optional system tools ─────────────────────────────────
MISSING_TOOLS=()
for tool in g++ shellcheck nginx; do
    command -v "$tool" &>/dev/null || MISSING_TOOLS+=("$tool")
done

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
    echo ""
    echo "NOTE: Some optional system tools are absent — related tests will skip:"
    for t in "${MISSING_TOOLS[@]}"; do
        echo "  missing: $t"
    done
    echo ""
    echo "To install (run once with your password):"
    echo "  wsl -- sudo apt-get install -y g++ shellcheck nginx nodejs build-essential"
    echo ""
fi

# ── Warn about systemd (WSL2 without systemd mode) ──────────────────────────
if ! systemd-analyze --version &>/dev/null 2>&1 || \
   ! systemctl is-system-running &>/dev/null 2>&1; then
    echo ""
    echo "NOTE: systemd is not running — test_p4_deployment_policy::TestLinuxServiceValidation"
    echo "      will fail (not skip). These tests pass in CI (ubuntu-latest has systemd)."
    echo "      To enable: add [boot] systemd=true to /etc/wsl.conf and restart WSL."
    echo ""
fi

# ── Resolve repo root as a Linux path ───────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

TARGETS="${*:-tests/}"

echo "=== WSL test suite: $REPO_ROOT ==="
echo "=== Targets: $TARGETS ==="
echo ""

exec python3 -m pytest $TARGETS -q --ignore=tests/playwright --timeout=60
