#!/usr/bin/env bash
#
# bootstrap.sh
#
# Downloads the latest autostream release from GitHub and runs the installer.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/lo-tech-systems/autostream/main/bootstrap.sh | sudo bash
#
# Any arguments are forwarded to autostream_install.sh, for example:
#   curl -fsSL .../bootstrap.sh | sudo bash -s -- --unattended PIN=1234
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
# www.lo-tech.co.uk/autostream • GitHub.com/lo-tech-systems/autostream
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

set -Eeuo pipefail

# ---- Constants (kept consistent with autostream_updater) --------------------
readonly REPO_OWNER="lo-tech-systems"
readonly REPO_NAME="autostream"
readonly API_LATEST="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"
readonly UA="autostream-updater/1.0 (+https://github.com/${REPO_OWNER}/${REPO_NAME})"

# Staging layout mirrors autostream_updater exactly:
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

# Ensure git is present — the installer requires it for building owntone-mini.
if ! command -v git >/dev/null 2>&1; then
  info "git not found — installing..."
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git
fi

# ---- Resolve latest release -------------------------------------------------
info "Querying GitHub for the latest autostream release..."
release_json=$(curl -fsSL \
  -H "Accept: application/json" \
  -H "User-Agent: ${UA}" \
  "${API_LATEST}")

# Parse tag_name and tarball_url without jq.
# Compact whitespace first so "key":"value" matching is reliable.
release_compact=$(printf '%s' "${release_json}" | tr -d ' \t')
AUTOSTREAM_RELEASE_TAG=$(printf '%s' "${release_compact}" | grep -o '"tag_name":"[^"]*"' | cut -d'"' -f4)
tarball_url=$(printf '%s'          "${release_compact}" | grep -o '"tarball_url":"[^"]*"' | cut -d'"' -f4)

if [[ -z "${AUTOSTREAM_RELEASE_TAG}" || -z "${tarball_url}" ]]; then
  error "Could not parse latest release from GitHub API response."
  exit 1
fi

info "Latest release: ${AUTOSTREAM_RELEASE_TAG}"

# ---- Stage release ----------------------------------------------------------
# Remove any previous staging directory so stale extracts do not accumulate —
# consistent with the cleanup autostream_updater performs before each apply run.
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

installer="${repo_root}/autostream_install.sh"
if [[ ! -f "${installer}" ]]; then
  error "autostream_install.sh not found in extracted release at ${repo_root}."
  exit 1
fi
chmod 0755 "${installer}"

# ---- Hand off to installer --------------------------------------------------
# Export AUTOSTREAM_RELEASE_TAG so detect_install_version() in the installer
# records it in install-state.env — the same mechanism used by
# autostream_updater, which passes the tag via systemd-run
# --setenv=AUTOSTREAM_RELEASE_TAG=<tag>.
export AUTOSTREAM_RELEASE_TAG

info "Starting installer for release ${AUTOSTREAM_RELEASE_TAG}..."
exec bash "${installer}" "$@"
