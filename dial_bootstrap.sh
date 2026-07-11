#!/usr/bin/env bash
#
# dial_bootstrap.sh
#
# Downloads the latest autostream release from GitHub and runs the dial installer.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/lo-tech-systems/autostream/main/dial_bootstrap.sh | sudo bash
#
# Any arguments are forwarded to autostream_dial_install.sh.
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
# www.lo-tech.co.uk/autostream • GitHub.com/lo-tech-systems/autostream
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

set -Eeuo pipefail

# ---- Constants (kept consistent with autostream_dial_updater) ----------------
readonly REPO_OWNER="lo-tech-systems"
readonly REPO_NAME="autostream"
readonly API_LATEST="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"
readonly UA="autostream-dial-updater/1.0 (+https://github.com/${REPO_OWNER}/${REPO_NAME})"

# Staging layout mirrors autostream_dial_updater exactly:
#   ${STAGING_DIR}/release.tgz   — downloaded tarball
#   ${STAGING_DIR}/src/          — extraction root
readonly STAGING_DIR="/var/lib/autostream/update-staging"

# ---- Helpers ----------------------------------------------------------------
info()  { echo "[INFO] $*"; }
error() { echo "[ERROR] $*" >&2; }

# ---- Preflight --------------------------------------------------------------
if [[ ${EUID} -ne 0 ]]; then
  error "This script must be run as root (e.g. curl ... | sudo bash)"
  exit 1
fi

# ---- Resolve latest release -------------------------------------------------
info "Querying GitHub for the latest autostream release..."
release_json=$(curl -fsSL \
  -H "Accept: application/json" \
  -H "User-Agent: ${UA}" \
  "${API_LATEST}")

# Parse tag_name and tarball_url using Python stdlib JSON — robust against
# whitespace and escaping variations in the API response.
AUTOSTREAM_RELEASE_TAG=$(printf '%s' "${release_json}" | python3 -c "import json,sys; print(json.load(sys.stdin)['tag_name'])")
tarball_url=$(printf '%s'           "${release_json}" | python3 -c "import json,sys; print(json.load(sys.stdin)['tarball_url'])")

if [[ -z "${AUTOSTREAM_RELEASE_TAG}" || -z "${tarball_url}" ]]; then
  error "Could not parse latest release from GitHub API response."
  exit 1
fi

info "Latest release: ${AUTOSTREAM_RELEASE_TAG}"

# ---- Stage release ----------------------------------------------------------
# Remove any previous staging directory so stale extracts do not accumulate —
# consistent with the cleanup autostream_dial_updater performs before each
# apply run.
if [[ -d "${STAGING_DIR}" ]]; then
  rm -rf "${STAGING_DIR}"
fi
mkdir -p "${STAGING_DIR}"
chmod 0700 "${STAGING_DIR}"

tar_path="${STAGING_DIR}/release.tgz"
info "Downloading release tarball..."
curl -fsSL -L \
  -H "User-Agent: ${UA}" \
  -H "Accept: application/vnd.github+json" \
  "${tarball_url}" \
  -o "${tar_path}"

extract_dir="${STAGING_DIR}/src"
mkdir -p "${extract_dir}"
info "Extracting release..."
tar -xzf "${tar_path}" -C "${extract_dir}"

# GitHub tarballs contain a single top-level directory.
repo_root=$(find "${extract_dir}" -mindepth 1 -maxdepth 1 -type d | head -1)
if [[ -z "${repo_root}" ]]; then
  error "No top-level directory found in extracted release."
  exit 1
fi

installer="${repo_root}/autostream_dial_install.sh"
if [[ ! -f "${installer}" ]]; then
  error "autostream_dial_install.sh not found in extracted release at ${repo_root}."
  exit 1
fi
chmod 0755 "${installer}"

# ---- Hand off to installer --------------------------------------------------
# Export AUTOSTREAM_RELEASE_TAG so detect_install_version() in the installer
# records it in install-state.env — the same mechanism used by
# autostream_dial_updater, which passes the tag via systemd-run
# --setenv=AUTOSTREAM_RELEASE_TAG=<tag>.
export AUTOSTREAM_RELEASE_TAG

info "Starting dial installer for release ${AUTOSTREAM_RELEASE_TAG}..."
exec bash "${installer}" "$@"
