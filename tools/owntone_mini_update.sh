#!/usr/bin/env bash
#
# tools/owntone_mini_update.sh
#
# Updates JUST the owntone-mini component of an existing autostream
# installation on a remote appliance, over SSH. Intended for testing new
# owntone-mini builds without running a full autostream install/update.
#
# Mirrors install_owntone_mini_from_source() in installer/lib/owntone.sh,
# but targets a remote host via SSH and lets you pick the source branch.
#
# Usage:
#   tools/owntone_mini_update.sh [--branch BRANCH] [--user USER] HOST
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
# www.lo-tech.co.uk/autostream • GitHub.com/lo-tech-systems/autostream
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

set -euo pipefail

#############################################
# Logging
#############################################
info()  { echo "[INFO] $*"; }
warn()  { echo "[WARN] $*"; }
error() { echo "[ERROR] $*" >&2; }

#############################################
# Defaults
#############################################
BRANCH="minimal"
SSH_USER="pi"
HOST=""

OWNTONE_REPO="https://github.com/lo-tech-systems/owntone-mini.git"

#############################################
# Usage
#############################################
usage() {
  cat <<EOF
Usage: $(basename "$0") [--branch BRANCH] [--user USER] HOST

Rebuilds and reinstalls owntone-mini from source on a remote autostream
appliance, over SSH. Only the owntone binary/service is touched; nothing
else on the appliance is modified. /etc/owntone.conf and
/etc/owntone-settings.json are left untouched.

Arguments:
  HOST                    Hostname or IP of the appliance (required).

Options:
  --branch BRANCH         owntone-mini branch to build (default: minimal).
                           Use this to test an unreleased branch.
  --user USER             SSH user on the appliance (default: pi).
  --help, -h              Show this help.

Examples:
  $(basename "$0") autostream.local
  $(basename "$0") --branch feature/foo --user pi 192.168.1.50

Note:
  The remote build (autoreconf/configure/make) can take around 10 minutes
  on a Raspberry Pi.

  If --branch is not "minimal", a future full autostream update will
  rebuild owntone-mini from the "minimal" branch and revert this test
  build.
EOF
}

#############################################
# Argument parsing
#############################################
while [[ $# -gt 0 ]]; do
  case "$1" in
    --branch)
      BRANCH="${2:-}"
      if [[ -z "${BRANCH}" ]]; then
        error "--branch requires a value"
        exit 1
      fi
      shift 2
      ;;
    --user)
      SSH_USER="${2:-}"
      if [[ -z "${SSH_USER}" ]]; then
        error "--user requires a value"
        exit 1
      fi
      shift 2
      ;;
    --help|-h)
      usage; exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      error "Unknown option: $1"
      usage
      exit 1
      ;;
    *)
      if [[ -n "${HOST}" ]]; then
        error "Unexpected extra argument: $1"
        usage
        exit 1
      fi
      HOST="$1"
      shift
      ;;
  esac
done

if [[ -z "${HOST}" ]]; then
  error "HOST is required."
  usage
  exit 1
fi

if [[ "${BRANCH}" != "minimal" ]]; then
  warn "Building non-default branch '${BRANCH}'. A future full autostream" \
       "update will rebuild owntone-mini from 'minimal' and revert this test build."
fi

info "Target appliance: ${SSH_USER}@${HOST}"
info "owntone-mini branch: ${BRANCH}"
info "This can take around 10 minutes to build on a Raspberry Pi..."

#############################################
# Remote build script
#############################################
# Runs on the appliance under sudo. Uses `set -e` so a failed build step
# aborts immediately; an EXIT trap always fires afterwards (whether the
# script finished normally or was aborted by `set -e`), cleans up the
# tmpdir, and — if the build didn't reach BUILD_OK=1 — restarts the
# existing owntone binary and reports the failure clearly, so the service
# is never left stopped silently.
read -r -d '' REMOTE_SCRIPT <<EOF || true
set -e
BRANCH="${BRANCH}"
OWNTONE_REPO="${OWNTONE_REPO}"
TMPDIR_BUILD=""
BUILD_OK=0

on_exit() {
  status=\$?
  if [ -n "\${TMPDIR_BUILD}" ] && [ -d "\${TMPDIR_BUILD}" ]; then
    rm -rf "\${TMPDIR_BUILD}"
  fi
  if [ "\${BUILD_OK}" -ne 1 ]; then
    echo "[REMOTE][ERROR] owntone-mini build/install failed (exit \${status}). Restarting existing owntone..." >&2
    systemctl daemon-reload || true
    systemctl restart owntone || true
    exit 1
  fi
}
trap on_exit EXIT

echo "[REMOTE] Stopping owntone.service..."
systemctl stop owntone || true

TMPDIR_BUILD="\$(mktemp -d)"
echo "[REMOTE] Building in \${TMPDIR_BUILD}..."

cd "\${TMPDIR_BUILD}"
echo "[REMOTE] Cloning \${OWNTONE_REPO} (branch \${BRANCH})..."
git clone --branch "\${BRANCH}" --single-branch "\${OWNTONE_REPO}" owntone-mini
cd owntone-mini
echo "[REMOTE] autoreconf..."
autoreconf -i
echo "[REMOTE] configure..."
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-install-user --enable-chromecast
echo "[REMOTE] make (-j2)..."
make -j2
echo "[REMOTE] make install..."
make install

BUILD_OK=1
echo "[REMOTE] Build succeeded. Reloading systemd and restarting owntone..."
systemctl daemon-reload
systemctl restart owntone
EOF

# Quote the remote script safely for embedding as a single argument to
# `sudo bash -c`, regardless of its contents (printf %q handles any
# embedded quotes correctly).
REMOTE_SCRIPT_QUOTED="$(printf '%q' "${REMOTE_SCRIPT}")"

if ! ssh -t "${SSH_USER}@${HOST}" "sudo bash -c ${REMOTE_SCRIPT_QUOTED}"; then
  error "Remote build/update failed. See remote output above for details."
  exit 1
fi

#############################################
# Verify
#############################################
info "Verifying owntone service and reported version on ${HOST}..."

SERVICE_STATE="$(ssh "${SSH_USER}@${HOST}" "systemctl is-active owntone" || true)"
info "owntone.service is-active: ${SERVICE_STATE}"

if [[ "${SERVICE_STATE}" != "active" ]]; then
  warn "owntone.service is not active after the update; check the remote logs (journalctl -u owntone)."
fi

CONFIG_JSON="$(ssh "${SSH_USER}@${HOST}" "curl -fsS http://localhost:3689/api/config" || true)"
if [[ -z "${CONFIG_JSON}" ]]; then
  warn "Could not fetch http://localhost:3689/api/config from ${HOST}; owntone may still be starting up."
else
  VERSION="$(printf '%s' "${CONFIG_JSON}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('version','?'))" 2>/dev/null || echo "?")"
  PRODUCT_NAME="$(printf '%s' "${CONFIG_JSON}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('product_name','?'))" 2>/dev/null || echo "?")"
  info "Reported product_name: ${PRODUCT_NAME}"
  info "Reported version: ${VERSION}"
fi

if [[ "${BRANCH}" != "minimal" ]]; then
  warn "Built from non-default branch '${BRANCH}'. A future full autostream" \
       "update will rebuild owntone-mini from 'minimal' and revert this test build."
fi

info "Done."
