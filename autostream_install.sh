#!/usr/bin/env bash
#
# autostream_install.sh
#
# Deployment script for autostream on Raspberry Pi OS Lite (Trixie).
# This installer is intentionally defensive and verbose.
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
# www.lo-tech.co.uk/autostream • GitHub.com/lo-tech-systems/autostream
#
# IMPORTANT
# - This script is for Raspberry Pi OS (Trixie) ONLY.
# - Run this on a dedicated Raspberry Pi that will be a single-purpose autostream device.
# - It will install packages, enable services, and modify system configuration.
#
# Modes:
#   (default)  First-time installation.
#   --update   Update an existing installation, reusing prior install choices.
#              This must be the only flag passed.
#
# Options:
# --unattended PIN=1234
#   Skips Continue Y/N prompt and sets the PIN to the value specified.
#   Falls back to attended mode if PIN is not specified.
#
# --sdmon=[auto|sandisk|adata|transcend|micron|swissbit|2step]
#   Enable sdmon (SD Card Monitoring) with the specified method.
#   IMPORTANT: This should only be used with supported cards, generally
#              industrial-grade cards from those manufacturers, for example
#              the Sandisk SDSDQAF3-008G-I. sdmon may cause consumer-grade
#              cards to go offline.
#
# --fetch-autostream
#   Clone or update the Autostream repository from GitHub.
#
# --help, -h
#   Show usage information and exit.
#
# --owntone=[mini|full|skip]
#   Select how OwnTone should be provisioned:
#     mini (default): build and install OwnTone from the lo-tech-systems source
#                     repository without modifying /etc/owntone.conf
#     full: install packaged OwnTone from the public repository
#     skip: do not install or build OwnTone; only reuse an existing installation
#           and update /etc/owntone.conf when present
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

set -Eeuo pipefail
IFS=$'\n\t'

#############################################
# Source libraries
#############################################
INSTALLER_LIB="$(cd "$(dirname "$0")/installer/lib" && pwd)"
# shellcheck source=installer/lib/helpers.sh
source "${INSTALLER_LIB}/helpers.sh"
# shellcheck source=installer/lib/owntone.sh
source "${INSTALLER_LIB}/owntone.sh"
# shellcheck source=installer/lib/vibra.sh
source "${INSTALLER_LIB}/vibra.sh"
# shellcheck source=installer/lib/hardware.sh
source "${INSTALLER_LIB}/hardware.sh"

#############################################
# Globals
#############################################
SCRIPT_NAME="$(basename "${0}")"
ORIG_USER="${SUDO_USER:-$(id -un)}"
ORIG_HOME="$(getent passwd "${ORIG_USER}" | cut -d: -f6)"

AUTOSTREAM_DIR="$(cd "$(dirname "$0")" && pwd)"

INSTALL_DIR="/opt/autostream"
APP_LOG_DIR="/var/log/autostream"

# When invoked interactively via sudo (fresh install/manual run) the log goes
# beside the calling user's home directory so they can easily find it.
# When invoked by a systemd unit (update) there is no SUDO_USER, so we log to
# the standard application log directory instead.
if [[ -n "${SUDO_USER:-}" ]]; then
  LOGFILE="${ORIG_HOME}/autostream_install.log"
else
  LOGFILE="${APP_LOG_DIR}/autostream_install.log"
fi
STAMP_DIR="/var/lib/autostream"          # root-only stamp/admin area
LIBEXEC_DIR="/usr/local/libexec/autostream"

STATE_FILE="${STAMP_DIR}/install-state.env"
UPDATE_RESULT_FILE="${STAMP_DIR}/update-result.env"

PIN_REGEX='^[A-Za-z0-9-]{4,20}$'

# Installer flags — defaults; overridden by saved state then CLI args
INSTALL_MODE="install"           # install | update
UNATTENDED=0
PIN_VALUE=""
SDMON_METHOD=""
FETCH_AUTOSTREAM=0
OWNTONE_MODE="mini"
PROMPT_REBOOT_ON_EXIT=0
CURRENT_PHASE=""
UPDATE_RUN_AT=""

#############################################
# Usage
#############################################
usage() {
  cat <<EOF
Usage: sudo ./${SCRIPT_NAME} [--unattended PIN=1234] [--sdmon[=<method>]] [--owntone=<mini|full|skip>] [--fetch-autostream]
       sudo ./${SCRIPT_NAME} --update

Modes:
  (default)               First-time install.
  --update                Update an existing installation using the choices
                          saved in ${STATE_FILE}. This must be the only flag.

Options:
  --unattended PIN=1234   Run non-interactively and set the PIN.
                          If PIN is omitted/invalid, falls back to attended mode.

  --sdmon[=<method>]      Enable sdmon (SD Card Monitoring); bare --sdmon uses auto.
                          auto | sandisk | adata | transcend | micron | swissbit | 2step

  --owntone=MODE          OwnTone provisioning mode:
                          mini = build/install lo-tech OwnTone from source (default)
                                 without editing /etc/owntone.conf
                          full = install packaged OwnTone
                          skip = do not install/build OwnTone, but update /etc/owntone.conf when present

  --fetch-autostream      Clone/update the autostream GitHub repository.
  --help, -h              Show this help.

Examples:
  sudo ./${SCRIPT_NAME}
  sudo ./${SCRIPT_NAME} --unattended PIN=1234
  sudo ./${SCRIPT_NAME} --unattended PIN=abcd-1234 --sdmon=sandisk
  sudo ./${SCRIPT_NAME} --owntone=full
  sudo ./${SCRIPT_NAME} --update

EOF
}

#############################################
# Argument validation helpers
#############################################
is_valid_sdmon_method() {
  case "$1" in
    auto|sandisk|adata|transcend|micron|swissbit|2step) return 0 ;;
    *) return 1 ;;
  esac
}

is_valid_owntone_mode() {
  case "$1" in
    mini|full|skip) return 0 ;;
    *) return 1 ;;
  esac
}

detect_install_version() {
  local raw=""

  # A source fetch installs origin/main rather than the release tarball that
  # launched the installer, so do not record that release's tag. FETCH_AUTOSTREAM
  # persists in install-state.env; restrict this override to fresh installs so a
  # later release update records its actual tag.
  if [[ "${INSTALL_MODE:-install}" == "install" && "${FETCH_AUTOSTREAM:-0}" -eq 1 ]]; then
    raw="test"
  elif [[ -n "${AUTOSTREAM_RELEASE_TAG:-}" ]]; then
    raw="${AUTOSTREAM_RELEASE_TAG}"
  fi

  raw="${raw#refs/tags/}"
  raw="${raw#v}"
  printf '%s\n' "${raw:-unknown}"
}

#############################################
# Argument parsing
#############################################
parse_args() {
  local _unattended_seen=0
  local _update_seen=0
  local _non_update_arg_seen=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --update)
        INSTALL_MODE="update"
        _update_seen=1
        shift
        ;;
      --unattended)
        _non_update_arg_seen=1
        _unattended_seen=1
        UNATTENDED=1
        if [[ $# -ge 2 && "$2" == PIN=* ]]; then
          PIN_VALUE="${2#PIN=}"
          shift 2
        else
          PIN_VALUE=""
          UNATTENDED=0
          shift
        fi
        ;;
      --sdmon)
        _non_update_arg_seen=1
        SDMON_METHOD="auto"
        shift
        ;;
      --sdmon=*)
        _non_update_arg_seen=1
        SDMON_METHOD="${1#--sdmon=}"
        if ! is_valid_sdmon_method "${SDMON_METHOD}"; then
          error "Invalid --sdmon method: ${SDMON_METHOD}"
          usage; exit 2
        fi
        shift
        ;;
      --owntone=*)
        _non_update_arg_seen=1
        OWNTONE_MODE="${1#--owntone=}"
        if ! is_valid_owntone_mode "${OWNTONE_MODE}"; then
          error "Invalid --owntone mode: ${OWNTONE_MODE}"
          usage; exit 2
        fi
        shift
        ;;
      --owntone)
        _non_update_arg_seen=1
        [[ $# -ge 2 ]] || { error "--owntone requires a value"; exit 2; }
        OWNTONE_MODE="$2"
        if ! is_valid_owntone_mode "${OWNTONE_MODE}"; then
          error "Invalid --owntone mode: ${OWNTONE_MODE}"
          usage; exit 2
        fi
        shift 2
        ;;
      --fetch-autostream)
        _non_update_arg_seen=1
        FETCH_AUTOSTREAM=1
        shift
        ;;
      --help|-h)
        usage; exit 0
        ;;
      *)
        error "Unknown argument: $1"
        usage; exit 2
        ;;
    esac
  done

  if [[ ${_update_seen} -eq 1 && ${_non_update_arg_seen} -eq 1 ]]; then
    error "--update must be the only flag."
    usage
    exit 2
  fi

  # Only validate PIN against UNATTENDED when --unattended was present on this
  # invocation.  If UNATTENDED=1 was loaded from saved state (update mode) but
  # --unattended was not passed this run, we must not clear it.
  if [[ ${_unattended_seen} -eq 1 && ${UNATTENDED} -eq 1 ]]; then
    if [[ -z "${PIN_VALUE}" || ! "${PIN_VALUE}" =~ ${PIN_REGEX} ]]; then
      warn "--unattended supplied but PIN is missing/invalid; falling back to attended mode."
      UNATTENDED=0
      PIN_VALUE=""
    fi
  fi
}

#############################################
# Install state persistence
#############################################
save_state() {
  local release_tag
  release_tag="$(detect_install_version)"
  mkdir -p "${STAMP_DIR}"
  cat > "${STATE_FILE}" <<EOF
# autostream install state — written by ${SCRIPT_NAME}
# Do not edit manually.
AUTOSTREAM_PRODUCT=autostream
AUTOSTREAM_RELEASE_TAG="${release_tag}"
INSTALL_TIMESTAMP="$(date -Is)"
INSTALL_DIR="${INSTALL_DIR}"
AUTOSTREAM_DIR="${AUTOSTREAM_DIR}"
OWNTONE_MODE="${OWNTONE_MODE}"
SDMON_METHOD="${SDMON_METHOD}"
FETCH_AUTOSTREAM="${FETCH_AUTOSTREAM}"
EOF
  chmod 0644 "${STATE_FILE}"
  chown root:root "${STATE_FILE}"
  info "Saved install state to ${STATE_FILE}"
}

load_state() {
  if [[ ! -f "${STATE_FILE}" ]]; then
    error "No saved install state found at ${STATE_FILE}."
    error "Cannot run --update without a prior installation."
    error "Run without --update to perform a first-time install."
    exit 1
  fi
  info "Loading saved install state from ${STATE_FILE}"

  # Parse KEY=VALUE pairs explicitly rather than using 'source'.
  # 'source' executes the file as shell code; a compromised or malformed
  # state file could run arbitrary commands as root during an update.
  # Only the specific keys required are accepted; all others are ignored.
  #
  # AUTOSTREAM_DIR and AUTOSTREAM_RELEASE_TAG are intentionally excluded:
  #   AUTOSTREAM_DIR         — always the staged release tree (this script's
  #                            own directory), not the original install path.
  #   AUTOSTREAM_RELEASE_TAG — exported by the supervisor via --setenv and
  #                            carries the NEW tag; the state file records the
  #                            OLD installed tag and must not overwrite it.
  local _key _val _line
  while IFS= read -r _line || [[ -n "${_line}" ]]; do
    # Skip blank lines and comments.
    [[ -n "${_line}" && "${_line}" != \#* ]] || continue
    # Skip lines with no '='.
    [[ "${_line}" == *=* ]] || continue

    _key="${_line%%=*}"
    _val="${_line#*=}"

    # Strip surrounding double or single quotes written by save_state's heredoc.
    if [[ ${#_val} -ge 2 ]]; then
      if [[ "${_val:0:1}" == '"' && "${_val: -1}" == '"' ]]; then
        _val="${_val:1:${#_val}-2}"
      elif [[ "${_val:0:1}" == "'" && "${_val: -1}" == "'" ]]; then
        _val="${_val:1:${#_val}-2}"
      fi
    fi

    case "${_key}" in
      OWNTONE_MODE)     OWNTONE_MODE="${_val}"     ;;
      SDMON_METHOD)     SDMON_METHOD="${_val}"      ;;
      FETCH_AUTOSTREAM) FETCH_AUTOSTREAM="${_val}"  ;;
      INSTALL_DIR)      INSTALL_DIR="${_val}"       ;;
    esac
  done < "${STATE_FILE}"

  info "Update mode: using staged release at ${AUTOSTREAM_DIR}"
}

write_update_result() {
  local status="$1"
  local message="$2"
  local percent="${3:-}"
  local run_at="${UPDATE_RUN_AT:-$(date -Is)}"
  local tmp

  mkdir -p "${STAMP_DIR}"
  tmp="$(mktemp)"
  cat > "${tmp}" <<EOF
LAST_RUN_AT="${run_at}"
STATUS="${status}"
MESSAGE="${message}"
PERCENT_COMPLETE="${percent}"
EOF
  install -m 0600 -o root -g root "${tmp}" "${UPDATE_RESULT_FILE}"
  rm -f "${tmp}"
}

update_progress() {
  # Write a progress update only when running in update mode.
  [[ "${INSTALL_MODE}" == "update" ]] || return 0
  write_update_result "in_progress" "$1" "$2"
}


#############################################
# Error and exit traps
#############################################
on_error() {
  local exit_code=$?
  local line_no=${BASH_LINENO[0]:-?}
  if [[ "${INSTALL_MODE}" == "update" ]]; then
    if [[ -n "${CURRENT_PHASE}" ]]; then
      write_update_result "failure" "Failed at ${CURRENT_PHASE} stage"
    else
      write_update_result "failure" "Update failed"
    fi
  fi
  error "Installation failed (exit ${exit_code}) at line ${line_no}."
  open_log_prompt "Check ${LOGFILE} for details."
  exit "${exit_code}"
}
trap on_error ERR

on_exit() {
  local exit_code=$?
  # Remove the nginx redirect flag written by the boot-time retry service.
  # This runs on both success and failure paths (trap on EXIT).
  rm -f /tmp/autostream-updating || true
  if [[ ${PROMPT_REBOOT_ON_EXIT} -ne 1 ]]; then
    exit "${exit_code}"
  fi
  if [[ ${exit_code} -eq 0 ]]; then
    info "Installer completed successfully."
    if has_tty; then
      echo
      tty_read "Reboot now to complete setup? (Y/N) " rb || true
      case "${rb:-N}" in
        Y|y) info "Rebooting..."; reboot ;;
        *)   info "Reboot skipped. It's recommended to reboot soon." ;;
      esac
    else
      info "Non-interactive session detected; not prompting for reboot."
      info "Please reboot the device when convenient."
    fi
  fi
}
trap on_exit EXIT

#############################################
# Preflight checks
#############################################
check_network_manager() {
  if ! command -v nmcli >/dev/null 2>&1; then
    error "nmcli not found. This application requires NetworkManager. Aborting."
    exit 1
  fi
  if ! systemctl is-active --quiet NetworkManager; then
    error "NetworkManager service is not active. Aborting."
    exit 1
  fi
  if ! nmcli -t -f RUNNING general status 2>/dev/null | grep -qx running; then
    error "NetworkManager is installed but not managing networking."
    error "Please disable other network managers (e.g. dhcpcd, ifupdown). Aborting."
    exit 1
  fi
}

require_rpi_os_trixie() {
  local codename
  codename="$(. /etc/os-release 2>/dev/null && echo "${VERSION_CODENAME:-}")"

  if [[ "${codename}" != "trixie" ]]; then
    warn "Detected VERSION_CODENAME='${codename:-unknown}'."
    warn "This installer is intended ONLY for Raspberry Pi OS (Trixie)."
    warn "Continuing on other OS versions may break the system."

    if has_tty; then
      echo
      tty_read "Type 'TRIXIE' to continue anyway, or anything else to abort: " confirm || true
      if [[ "${confirm}" != "TRIXIE" ]]; then
        error "Aborting."; exit 1
      fi
    else
      error "Non-interactive session detected; refusing to override OS safety check."
      exit 1
    fi
  fi
}

show_warnings_and_prompt() {
  cat <<EOF

=============================================================================
AUTOSTREAM INSTALLER
=============================================================================
This script will:
- Install OS packages (nginx, watchdog, dnsmasq, build tools, etc.)
- Provision OwnTone according to the selected mode (mini by default)
- Build and install vibra-mini ${VIBRA_VERSION} for optional track identification
- Enable/disable systemd services
- Create system users/groups and modify permissions
- Modify /boot/firmware/config.txt to enable the hardware watchdog and disable Bluetooth
- Configure nginx, logrotate, NetworkManager hooks, and autostream services

WARNING:
- Use ONLY on a dedicated Raspberry Pi running Raspberry Pi OS Lite (Trixie).
- Ideally, run this on a clean image (otherwise, ensure you have a backup).
- Do NOT run on machines containing important data or multi-purpose systems.

A full activity log will be written to ~/autostream_install.log
Note: the log is overwritten on each run.
=============================================================================
EOF

  if has_tty; then
    if [[ ${UNATTENDED} -eq 1 && -n "${PIN_VALUE}" ]]; then
      info "--unattended supplied with PIN; skipping interactive confirmation."
      return 0
    fi
    tty_read "Continue with installation? (Y/N) " ans || true
    case "${ans:-N}" in
      Y|y) info "Continuing..." ;;
      *) error "Aborted by user."; exit 1 ;;
    esac
  else
    if [[ ${UNATTENDED} -eq 1 && -n "${PIN_VALUE}" ]]; then
      info "Non-interactive session; --unattended supplied, continuing."
    else
      error "Non-interactive session detected. Refusing to proceed without a valid unattended PIN."
      error "Re-run with: sudo ./${SCRIPT_NAME} --unattended PIN=<4-20 chars A-Z a-z 0-9 hyphen>"
      exit 1
    fi
  fi
}

#############################################
# PIN management
#############################################
set_pin_file() {
  local pin="$1"
  if [[ -d /boot/firmware ]]; then
    echo "${pin}" > /boot/firmware/pin.txt
    chmod 0644 /boot/firmware/pin.txt || true
    info "Wrote PIN to /boot/firmware/pin.txt"
  elif [[ -d /boot ]]; then
    echo "${pin}" > /boot/pin.txt
    chmod 0644 /boot/pin.txt || true
    info "Wrote PIN to /boot/pin.txt"
  else
    warn "Could not find /boot or /boot/firmware; PIN not saved."
  fi
}

prompt_for_pin() {
  local pin=""

  if ! has_tty; then
    warn "Non-interactive session: cannot prompt for PIN."
    warn "The web UI will be accessible without authentication until a PIN is set."
    warn "To set a PIN, create /boot/firmware/pin.txt (or /boot/pin.txt) containing"
    warn "a 4-20 character string (A-Z a-z 0-9 and hyphens), then restart autostream."
    warn "Or re-run the installer with: sudo ./${SCRIPT_NAME} --unattended PIN=<your-pin>"
    return 0
  fi

  while true; do
    echo
    tty_read "Enter a setup PIN (4-20 chars; A-Z a-z 0-9 and hyphen only, Enter to skip): " pin || true
    if [[ -z "${pin}" ]]; then
      warn "No PIN set. The web UI will be accessible without authentication."
      warn "You can set a PIN later by creating /boot/firmware/pin.txt (or /boot/pin.txt)."
      return 0
    fi
    if [[ "${pin}" =~ ${PIN_REGEX} ]]; then
      break
    fi
    warn "Invalid PIN. Must match: ${PIN_REGEX}"
  done

  set_pin_file "${pin}"
}

handle_pin() {
  # install: prompt or use unattended PIN
  # update:  skip unless --unattended PIN=... explicitly provided on this run
  if [[ "${INSTALL_MODE}" == "update" ]]; then
    if [[ ${UNATTENDED} -eq 1 && -n "${PIN_VALUE}" ]]; then
      info "Update mode: overwriting PIN from --unattended flag"
      set_pin_file "${PIN_VALUE}"
    else
      info "Update mode: skipping PIN prompt (re-run with --unattended PIN=... to change)"
    fi
    return 0
  fi

  if [[ ${UNATTENDED} -eq 1 && -n "${PIN_VALUE}" ]]; then
    info "Unattended mode: setting PIN from command line"
    set_pin_file "${PIN_VALUE}"
  else
    prompt_for_pin
  fi
}

#############################################
# Install phases
#############################################

# bootstrap_phase: first-time-only setup — users, groups, directories, base packages.
bootstrap_phase() {
  info "=== Phase: bootstrap ==="

  info "Creating directories"
  mkdir -p "${AUTOSTREAM_DIR}" || true
  mkdir -p "${INSTALL_DIR}" "${APP_LOG_DIR}"
  mkdir -p "${STAMP_DIR}"
  mkdir -p /etc/autostream
  mkdir -p "${LIBEXEC_DIR}"

  info "Updating apt metadata"
  DEBIAN_FRONTEND=noninteractive apt-get update

  apt_install curl gpg ca-certificates

  # Note: Flask is installed at system level because autostream_wifi_watcher
  # runs directly via its shebang as a boot/recovery path and must not depend
  # on the application venv being present.
  apt_install git build-essential libffi-dev pkg-config fq \
    libasound2-dev libsamplerate0-dev libtwolame-dev libmpg123-dev \
    python3-dev python3-venv python3-pip python3-flask

  apt_install nginx watchdog dnsmasq fcgiwrap avahi-daemon avahi-utils

  apt_install --soft python3-requests

  # Track identification: Vibra/Shazam daemon build dependencies.
  apt_install libfftw3-dev libcurl4-openssl-dev libjson-c-dev cmake

  # Create user and group before applying ownership — chown fails if the user
  # does not yet exist and set -e aborts the install.
  ensure_group autostream
  ensure_user autostream autostream
  ensure_user_in_group autostream netdev
  ensure_user_in_group autostream audio
  # video group required to allow autostream to query PSU status via vcgencmd
  ensure_user_in_group autostream video

  # Apply directory ownership now that the user exists.
  chown autostream:autostream "${STAMP_DIR}"
  chmod 0750 "${STAMP_DIR}"

  chown autostream:autostream /etc/autostream
  chmod 0755 /etc/autostream

  chown root:root "${LIBEXEC_DIR}"
  chmod 0755 "${LIBEXEC_DIR}"
}

# system_upgrade_phase: refresh installed OS packages during update.
system_upgrade_phase() {
  CURRENT_PHASE="system upgrade"
  info "=== Phase: system upgrade ==="
  write_update_result "in_progress" "Refreshing package lists..." 20
  info "Updating apt metadata"
  DEBIAN_FRONTEND=noninteractive apt-get update
  write_update_result "in_progress" "Upgrading system packages (this may take several minutes)..." 22
  info "Upgrading installed system packages"
  NEEDRESTART_MODE=l DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
}

# fetch_phase: clone/update the autostream source repo (install only).
fetch_phase() {
  CURRENT_PHASE="fetch"
  info "=== Phase: fetch ==="

  if [[ "${INSTALL_MODE}" == "update" ]]; then
    info "Update mode: skipping autostream GitHub fetch"
    if [[ ! -d "${AUTOSTREAM_DIR}/system" ]]; then
      error "autostream files not found at ${AUTOSTREAM_DIR}."
      error "The update service should provide the application files before running --update."
      exit 1
    fi
    return 0
  fi

  if [[ ${FETCH_AUTOSTREAM} -eq 1 ]]; then
    info "Fetching autostream repository from GitHub"
    git_clone_or_update https://github.com/lo-tech-systems/autostream.git "${AUTOSTREAM_DIR}"
  else
    info "Skipping autostream GitHub fetch (use --fetch-autostream to enable)"
  fi

  if [[ ! -d "${AUTOSTREAM_DIR}/system" ]]; then
    error "autostream files not found at ${AUTOSTREAM_DIR}."
    error "Either pre-populate this directory or re-run with --fetch-autostream."
    exit 1
  fi
}

# sdmon_phase: build and install sdmon binary (install and update).
sdmon_phase() {
  CURRENT_PHASE="sdmon"
  info "=== Phase: sdmon ==="

  if [[ -z "${SDMON_METHOD}" ]]; then
    info "sdmon not enabled (use --sdmon=<method> to enable)"
    return 0
  fi

  update_progress "Installing sdmon..." 38
  info "Installing sdmon (method: ${SDMON_METHOD})"
  if [[ ! -x "/usr/local/sbin/sdmon" ]]; then
    local tmpdir
    tmpdir="$(mktemp -d)"
    git clone https://github.com/Ognian/sdmon.git "${tmpdir}/sdmon"
    make -C "${tmpdir}/sdmon/src"
    install -m 0755 "${tmpdir}/sdmon/src/sdmon" "/usr/local/sbin/sdmon"
    rm -rf "${tmpdir}"
  else
    info "sdmon binary already present at /usr/local/sbin/sdmon"
  fi
}

# deploy_phase: copy app files, build monitor binary, set up venv (install and update).
deploy_phase() {
  CURRENT_PHASE="deploy"
  info "=== Phase: deploy ==="
  update_progress "Deploying application files..." 40

  info "Deploying autostream files to ${INSTALL_DIR}"
  # Remove stale dependency lockfiles before copying — an old requirements.lock
  # can survive repo upgrades and reinstall packages no longer in the project.
  rm -f "${INSTALL_DIR}/requirements.lock"
  cp -a "${AUTOSTREAM_DIR}/core/."     "${INSTALL_DIR}/"
  install -m 0755 -o root -g root \
      "${AUTOSTREAM_DIR}/platform/wifi_watcher.py" "${INSTALL_DIR}/autostream_wifi_watcher"
  sed -i 's/\r$//' "${INSTALL_DIR}/autostream_wifi_watcher"
  # wifi_watcher's split sibling modules (imported beside it from /opt/autostream).
  cp    "${AUTOSTREAM_DIR}/platform/wifi_state.py"    "${INSTALL_DIR}/"
  cp    "${AUTOSTREAM_DIR}/platform/wifi_status.py"   "${INSTALL_DIR}/"
  cp    "${AUTOSTREAM_DIR}/platform/wifi_recovery.py" "${INSTALL_DIR}/"
  cp    "${AUTOSTREAM_DIR}/platform/wifi_policy.py"   "${INSTALL_DIR}/"
  cp    "${AUTOSTREAM_DIR}/platform/wifi_mdns.py"     "${INSTALL_DIR}/"
  cp    "${AUTOSTREAM_DIR}/platform/wifi_nm.py"       "${INSTALL_DIR}/"
  cp    "${AUTOSTREAM_DIR}/platform/wifi_hotspot.py"  "${INSTALL_DIR}/"
  cp    "${AUTOSTREAM_DIR}/platform/wifi_config.py"   "${INSTALL_DIR}/"
  cp    "${AUTOSTREAM_DIR}/platform/wifi_activation.py" "${INSTALL_DIR}/"
  cp    "${AUTOSTREAM_DIR}/platform/wifi_adoption.py"  "${INSTALL_DIR}/"
  cp    "${AUTOSTREAM_DIR}/platform/wifi_loop.py"      "${INSTALL_DIR}/"
  # wifi_web.py owns the Flask presentation/HTTP surface; deploy it root-owned
  # 0644 so the recovery web server has a complete, missing-import-free module set.
  install -m 0644 -o root -g root \
      "${AUTOSTREAM_DIR}/platform/wifi_web.py" "${INSTALL_DIR}/wifi_web.py"
  cp -a "${AUTOSTREAM_DIR}/LICENSE" "${INSTALL_DIR}/"
  # Only deploy the bundled hints file when neither the new location nor the old
  # (to-be-migrated) location exists.  This prevents the repo defaults from
  # overwriting a user-customized file that migration will later copy into place.
  if [[ -f "${AUTOSTREAM_DIR}/nowplaying_hints.json" && \
        ! -f /etc/autostream/nowplaying_hints.json && \
        ! -f /opt/autostream/nowplaying_hints.json ]]; then
    install -m 0644 -o root -g root \
        "${AUTOSTREAM_DIR}/nowplaying_hints.json" /etc/autostream/nowplaying_hints.json
  fi

  update_progress "Building autostream_monitor..." 50
  info "Building autostream_monitor"
  mkdir -p "${INSTALL_DIR}/monitor"
  g++ -std=c++17 -O2 \
    -o "${INSTALL_DIR}/monitor/autostream_monitor" \
    "${INSTALL_DIR}/monitor/autostream_monitor.cpp" \
    "${INSTALL_DIR}/monitor/autostream_monitor_dsp.cpp" \
    "${INSTALL_DIR}/monitor/autostream_monitor_io.cpp" \
    "${INSTALL_DIR}/monitor/autostream_monitor_utils.cpp" \
    "${INSTALL_DIR}/monitor/autostream_repeat.cpp" \
    -lasound -lsamplerate -lpthread -latomic -ltwolame -lmpg123
  chmod 0755 "${INSTALL_DIR}/monitor/autostream_monitor"

  update_progress "Building vibra-mini..." 55
  if [[ "${INSTALL_MODE}" == "install" ]]; then
    install_vibra_from_source
  else
    update_vibra_from_source
  fi

  info "Installing supervisor and helper scripts"
  install_text_linux "${AUTOSTREAM_DIR}/supervisor/autostream_update_support.py"  "${LIBEXEC_DIR}/autostream_update_support.py"  0644 root root
  install_text_linux "${AUTOSTREAM_DIR}/supervisor/autostream_updater"            "${LIBEXEC_DIR}/autostream_updater"            0755 root root
  install_text_linux "${AUTOSTREAM_DIR}/supervisor/autostream_admin"              "${LIBEXEC_DIR}/autostream_admin"              0755 root root
  install_text_linux "${AUTOSTREAM_DIR}/supervisor/autostream_update_retry"       "${LIBEXEC_DIR}/autostream_update_retry"       0755 root root
  install_text_linux "${AUTOSTREAM_DIR}/supervisor/autostream_storage_guard"      "${LIBEXEC_DIR}/autostream_storage_guard"      0755 root root
  install_text_linux "${AUTOSTREAM_DIR}/tools/autostream_migrate.py"              "${LIBEXEC_DIR}/autostream_migrate.py"         0755 root root

  update_progress "Updating Python packages..." 57
  info "Creating/updating Python virtual environment"
  if [[ ! -d "${INSTALL_DIR}/venv" ]]; then
    PIP_CACHE_DIR=/tmp/pip-cache python3 -m venv --system-site-packages "${INSTALL_DIR}/venv"
  fi
  PIP_CACHE_DIR=/tmp/pip-cache PIP_ROOT_USER_ACTION=ignore "${INSTALL_DIR}/venv/bin/pip" install -U pip

  if [[ -f "${INSTALL_DIR}/requirements.lock" ]]; then
    info "Installing Python dependencies from requirements.lock (hash-checked)"
    PIP_CACHE_DIR=/tmp/pip-cache PIP_ROOT_USER_ACTION=ignore \
      "${INSTALL_DIR}/venv/bin/pip" install --require-hashes -r "${INSTALL_DIR}/requirements.lock"
  else
    warn "requirements.lock not found; installing from requirements.txt (not hash-pinned)"
    PIP_CACHE_DIR=/tmp/pip-cache PIP_ROOT_USER_ACTION=ignore \
      "${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"
  fi
}

# configure_phase: apply/refresh all managed system configs (install and update).
configure_phase() {
  CURRENT_PHASE="configure"
  info "=== Phase: configure ==="
  update_progress "Applying configuration..." 62

  info "Configuring permissions and policy"
  install -m 0440 -o root -g root "${AUTOSTREAM_DIR}/system/sudoers/autostream_updater" /etc/sudoers.d/autostream_updater
  install -m 0440 -o root -g root "${AUTOSTREAM_DIR}/system/sudoers/autostream_admin"   /etc/sudoers.d/autostream_admin
  validate_sudoers

  info "Running config layout migration (idempotent)"
  python3 "${LIBEXEC_DIR}/autostream_migrate.py"

  # Must be in place before OwnTone is provisioned and (re)started below, so
  # that the FIFO it watches already exists.
  info "Configuring the audio FIFO runtime directory"
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/tmpfiles.d/autostream.conf" /usr/lib/tmpfiles.d/autostream.conf
  systemd-tmpfiles --create /usr/lib/tmpfiles.d/autostream.conf || warn "Could not create /run/autostream-pipes now; it will be created on next boot"

  provision_owntone "${INSTALL_MODE}"
  update_progress "Configuring system services..." 78

  # nginx
  info "Configuring nginx"
  cp -a "${AUTOSTREAM_DIR}/nginx"  "${INSTALL_DIR}/"
  cp -a "${AUTOSTREAM_DIR}/images" "${INSTALL_DIR}/"
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/nginx/autostream-nginx.conf"          /etc/nginx/sites-available/autostream-nginx.conf
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/nginx/autostream-nginxd.conf"         /etc/nginx/conf.d/autostream-nginxd.conf
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/nginx/99-autostream-access-log.conf"  /etc/nginx/conf.d/99-autostream-access-log.conf

  if [[ -e /etc/nginx/sites-enabled/default ]]; then
    rm -f /etc/nginx/sites-enabled/default
  fi
  ln -sf /etc/nginx/sites-available/autostream-nginx.conf /etc/nginx/sites-enabled/autostream-nginx.conf
  nginx -t
  systemctl enable nginx

  # journald storage drop-in (fixed appliance bounds; does not restrict log severity)
  mkdir -p /etc/systemd/journald.conf.d
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/journald/99-autostream-storage.conf" \
    /etc/systemd/journald.conf.d/99-autostream-storage.conf
  systemctl restart systemd-journald || warn "systemctl restart systemd-journald failed"

  # logind drop-in: suppress power-key events so USB enumeration cannot shut down the appliance
  mkdir -p /etc/systemd/logind.conf.d
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/logind/90-autostream-ignore-power-key.conf" \
    /etc/systemd/logind.conf.d/90-autostream-ignore-power-key.conf
  systemctl restart systemd-logind || warn "systemctl restart systemd-logind failed"

  # logrotate
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/logrotate/autostream" /etc/logrotate.d/autostream

  # dnsmasq — install the captive-portal config as a root-owned TEMPLATE outside
  # dnsmasq's automatic include directory.  The watcher substitutes the resolved
  # built-in recovery interface into a runtime file under /run/autostream and the
  # dedicated service reads only that runtime file.  Remove the obsolete
  # /etc/dnsmasq.d/ copy so a manually started system dnsmasq cannot read a
  # placeholder-bearing or stale config.
  mkdir -p /usr/local/share/autostream/dnsmasq
  install -m 0644 -o root -g root \
      "${AUTOSTREAM_DIR}/system/dnsmasq/autostream-setup.conf" \
      /usr/local/share/autostream/dnsmasq/autostream-setup.conf
  rm -f /etc/dnsmasq.d/autostream-setup.conf
  systemctl disable dnsmasq || true

  # NetworkManager
  install -m 0755 -o root -g root \
      "${AUTOSTREAM_DIR}/system/NetworkManager/99-wlan-fix" \
      /etc/NetworkManager/dispatcher.d/99-wlan-fix
  install -m 0644 -o root -g root \
      "${AUTOSTREAM_DIR}/system/NetworkManager/mdns.conf" \
      /etc/NetworkManager/conf.d/mdns.conf
  install -m 0644 -o root -g root \
      "${AUTOSTREAM_DIR}/system/NetworkManager/wifi-powersave.conf" \
      /etc/NetworkManager/conf.d/wifi-powersave.conf

  # cloud-init
  configure_cloud_init

  # Firmware / watchdog
  update_pi_firmware_config
  cp -a "${AUTOSTREAM_DIR}/system/watchdog/watchdog.conf" /etc/watchdog.conf
  systemctl enable watchdog

  # Permissions pass
  permissions_pass

  # Create stable appliance identity fallback only when no valid CPU serial is
  # available and the file does not yet exist.  On hardware with a readable serial,
  # the runtime derives the identity from a hash and the file is not needed.
  info "Ensuring appliance identity"
  python3 - <<'PYEOF'
import hashlib, os, re, secrets
from pathlib import Path

def _get_cpu_serial():
    try:
        text = Path('/proc/cpuinfo').read_text(encoding='utf-8', errors='ignore')
        for ln in text.splitlines():
            if ln.strip().lower().startswith('serial'):
                parts = ln.split(':', 1)
                if len(parts) == 2 and parts[1].strip():
                    return parts[1].strip()
    except Exception:
        pass
    try:
        raw = Path('/proc/device-tree/serial-number').read_bytes()
        if raw:
            return raw.replace(b'\x00', b'').decode('utf-8', errors='ignore').strip()
    except Exception:
        pass
    return ''

serial = _get_cpu_serial().strip().lower()
fallback_path = Path('/var/lib/autostream/appliance-id')

if re.match(r'^[0-9a-f]+$', serial) and serial:
    print('appliance-id: CPU serial available; fallback file not needed')
elif fallback_path.exists():
    print(f'appliance-id: fallback file already exists; preserving')
else:
    new_id = secrets.token_hex(10)
    tmp = fallback_path.with_suffix('.tmp')
    tmp.write_text(new_id, encoding='utf-8')
    os.chmod(tmp, 0o644)
    os.chown(tmp, 0, 0)
    tmp.replace(fallback_path)
    print(f'appliance-id: created fallback identity at {fallback_path}')
PYEOF
}

configure_cloud_init() {
  info "Disabling cloud-init /etc/hosts management"
  local user_data="/boot/firmware/user-data"

  if [[ ! -f "${user_data}" ]]; then
    warn "cloud-init user-data not found at ${user_data}"
    return 0
  fi

  if grep -q '^manage_etc_hosts:' "${user_data}"; then
    sed -i 's/^manage_etc_hosts:.*/manage_etc_hosts: false/' "${user_data}"
  else
    printf "\nmanage_etc_hosts: false\n" >> "${user_data}"
  fi

  if grep -q '^preserve_hostname:' "${user_data}"; then
    sed -i 's/^preserve_hostname:.*/preserve_hostname: true/' "${user_data}"
  else
    printf "preserve_hostname: true\n" >> "${user_data}"
  fi

  if command -v cloud-init >/dev/null 2>&1; then
    info "Resetting cloud-init state to apply updated user-data"
    cloud-init clean --logs || true
  fi
}

permissions_pass() {
  info "Setting ownership and permissions"

  # Reclaim the entire application tree as root:root.  Existing installations
  # may have subdirectories (nginx/, images/, monitor/, venv/) still owned by
  # the service account from older installers; a recursive pass fixes them all.
  chown -R root:root "${INSTALL_DIR}"
  chmod 0755 "${INSTALL_DIR}"
  chown -R autostream:autostream "${APP_LOG_DIR}"
  chmod 0755 "${APP_LOG_DIR}"

  find "${INSTALL_DIR}" -maxdepth 1 -type f -name "*.sh" -exec chmod 0755 {} + 2>/dev/null || true
  chmod 0755 "${INSTALL_DIR}/nginx/cgi"/*.cgi  2>/dev/null || true
  chmod 0644 "${INSTALL_DIR}/nginx/offline"/*.html 2>/dev/null || true

  # The Wi-Fi recovery watcher and its dedicated helper are one inseparable
  # root-owned recovery component. Enforce root:root and a non-writable mode so
  # the unprivileged autostream/www-data accounts cannot modify either file.
  chown root:root "${INSTALL_DIR}/autostream_wifi_watcher"
  chmod 0755 "${INSTALL_DIR}/autostream_wifi_watcher"
  if [[ -f "${INSTALL_DIR}/autostream_wifi_network.py" ]]; then
    chown root:root "${INSTALL_DIR}/autostream_wifi_network.py"
    chmod 0644 "${INSTALL_DIR}/autostream_wifi_network.py"
  fi

  if [[ -f "${INSTALL_DIR}/ssid" ]]; then
    chown root:root "${INSTALL_DIR}/ssid"
    chmod 0644 "${INSTALL_DIR}/ssid"
  fi

  # Enforce root:root 0644 on the persistent network-state file when present.
  # The installer never creates it; the watcher writes it on migration/commit.
  if [[ -f /etc/autostream-network.json ]]; then
    chown root:root /etc/autostream-network.json
    chmod 0644 /etc/autostream-network.json
  fi

  # Create dial authorization store if absent (under /var/lib/autostream/).
  # Runs on both fresh install and --update; the ! -f guard preserves existing authorizations.
  if [[ ! -f "${STAMP_DIR}/dials.json" ]]; then
    echo '{}' > "${STAMP_DIR}/dials.json"
    chown autostream:autostream "${STAMP_DIR}/dials.json"
    chmod 0600 "${STAMP_DIR}/dials.json"
  fi
}

# services_phase: install and enable/reload systemd units (install and update).
services_phase() {
  CURRENT_PHASE="services"
  info "=== Phase: services ==="
  update_progress "Restarting services..." 80

  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream_update_retry.service" /etc/systemd/system/
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream_dnsmasq.service"       /etc/systemd/system/
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream_monitor.service"       /etc/systemd/system/
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/vibra-mini.service"              /etc/systemd/system/

  if [[ -n "${SDMON_METHOD}" ]]; then
    install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream_sdcardhealth.service" /etc/systemd/system/
    install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream_sdcardhealth.timer"   /etc/systemd/system/
  else
    info "Skipping sdmon systemd units (use --sdmon=<method> to enable)"
  fi

  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream.service"              /etc/systemd/system/
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream_wifi_watcher.service" /etc/systemd/system/
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream_updater.service"      /etc/systemd/system/
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream_updater.timer"        /etc/systemd/system/
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream_storage_guard.service" /etc/systemd/system/
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream_storage_guard.timer"   /etc/systemd/system/

  systemctl daemon-reload

  if [[ -n "${SDMON_METHOD}" ]]; then
    patch_sdmon_service_method "${SDMON_METHOD}"
    systemctl daemon-reload
    systemctl enable autostream_sdcardhealth.timer
  fi

  systemctl enable autostream_update_retry.service
  systemctl enable autostream_monitor.service
  systemctl enable vibra-mini.service
  systemctl enable autostream.service
  systemctl enable autostream_wifi_watcher.service
  systemctl enable --now autostream_storage_guard.timer

  if [[ "${INSTALL_MODE}" == "update" ]]; then
    info "Restarting affected services"
    systemctl restart autostream_monitor.service || true
    systemctl restart vibra-mini.service         || true
    systemctl restart autostream.service         || true
    systemctl restart autostream_wifi_watcher.service || true
    systemctl reload  nginx                      || true
  fi
}

# _wifi_profile_mode: print the NetworkManager Wi-Fi mode for a profile.
_wifi_profile_mode() {
  local uuid="$1" name="${2:-}" ident=()
  if [[ -n "${uuid}" ]]; then
    ident=(uuid "${uuid}")
  else
    ident=("${name}")
  fi
  nmcli -t -f 802-11-wireless.mode connection show "${ident[@]}" 2>/dev/null \
    | awk -F: '{print tolower($2)}' | head -n1
}

# _record_wifi_connection_state: persist the chosen NM connection identity.
_record_wifi_connection_state() {
  local wifi_conn="$1" wifi_uuid="${2:-}"

  printf "%s\n" "${wifi_conn}" > "${INSTALL_DIR}/ssid"
  AUTOSTREAM_WIFI_CONN_NAME="${wifi_conn}" \
  AUTOSTREAM_WIFI_CONN_UUID="${wifi_uuid}" \
    python3 - <<'PYEOF'
import json
import os
from pathlib import Path

payload = {
    "schema_version": 1,
    "connection_name": os.environ["AUTOSTREAM_WIFI_CONN_NAME"],
    "connection_uuid": os.environ.get("AUTOSTREAM_WIFI_CONN_UUID", ""),
}
Path("/etc/autostream-network.json").write_text(
    json.dumps(payload, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PYEOF
  chown root:root "${INSTALL_DIR}/ssid" /etc/autostream-network.json
  chmod 0644 "${INSTALL_DIR}/ssid" /etc/autostream-network.json
}

# _network_state_configured: true if JSON state already commits a connection.
_network_state_configured() {
  python3 - <<'PYEOF'
import json
import sys
from pathlib import Path

try:
    data = json.loads(Path("/etc/autostream-network.json").read_text(encoding="utf-8"))
except Exception:
    sys.exit(1)
sys.exit(0 if isinstance(data, dict) and bool(str(data.get("connection_name", "")).strip()) else 1)
PYEOF
}

# _select_active_wifi_connection: prefer the currently active non-AP Wi-Fi.
_select_active_wifi_connection() {
  local default_dev wifi_devices dev conn uuid mode
  default_dev="$(ip route show default 2>/dev/null | awk '/dev/{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1)"
  wifi_devices="$(
    nmcli -t -f DEVICE,TYPE,STATE device status 2>/dev/null \
      | awk -F: -v prefer="${default_dev}" '
          NF>=3 && $2=="wifi" && ($3=="connected" || $3=="activated") {
            if ($1==prefer) { preferred=$1 }
            else { others[++n]=$1 }
          }
          END {
            if (preferred!="") print preferred
            for (i=1; i<=n; i++) print others[i]
          }
        '
  )"

  while IFS= read -r dev; do
    [[ -z "${dev}" ]] && continue
    conn="$(nmcli -g GENERAL.CONNECTION device show "${dev}" 2>/dev/null | head -n1)"
    uuid="$(nmcli -g GENERAL.CON-UUID device show "${dev}" 2>/dev/null | head -n1)"
    [[ -z "${conn}" || "${conn}" == "--" ]] && continue
    mode="$(_wifi_profile_mode "${uuid}" "${conn}")"
    if [[ "${mode}" != "ap" ]]; then
      printf "%s\t%s\n" "${conn}" "${uuid}"
      return 0
    fi
    info "Wi-Fi connection '${conn}' is AP mode; skipping" >&2
  done <<< "${wifi_devices}"

  return 1
}

# _select_saved_wifi_connection: import a unique saved infrastructure profile.
#
# D-WP3 trace (Phase D, client profiles autoconnect=no): this selection runs only
# at fresh install (network_state_phase short-circuits once network.json/ssid is
# recorded), on profiles that PRE-EXIST the install and are therefore still
# autoconnect=yes, so the best-autoconnect-priority path below is unaffected. The
# watcher's autoconnect=no migration (D-WP2) runs later, at boot, after selection
# has already recorded a default. A user who manually set autoconnect=no on their
# one profile before install is still imported by the suitable_count==1 fallback
# (which does not require autoconnect=yes), so no widening is needed — the fallback
# already covers the lone autoconnect=no case.
_select_saved_wifi_connection() {
  local uuid type name mode autoconnect priority
  local best_auto_name="" best_auto_uuid="" best_auto_priority=-2147483648 best_auto_count=0
  local only_name="" only_uuid="" suitable_count=0

  while IFS=: read -r uuid type; do
    [[ -z "${uuid}" ]] && continue
    [[ "${type}" == "802-11-wireless" || "${type}" == "wifi" ]] || continue

    name="$(nmcli -g connection.id connection show uuid "${uuid}" 2>/dev/null | head -n1)"
    [[ -z "${name}" || "${name}" == "Hotspot" ]] && continue
    mode="$(_wifi_profile_mode "${uuid}" "${name}")"
    if [[ "${mode}" == "ap" ]]; then
      info "Saved Wi-Fi connection '${name}' is AP mode; skipping" >&2
      continue
    fi

    suitable_count=$((suitable_count + 1))
    only_name="${name}"
    only_uuid="${uuid}"

    autoconnect="$(nmcli -g connection.autoconnect connection show uuid "${uuid}" 2>/dev/null | head -n1 | tr '[:upper:]' '[:lower:]')"
    priority="$(nmcli -g connection.autoconnect-priority connection show uuid "${uuid}" 2>/dev/null | head -n1)"
    [[ "${priority}" =~ ^-?[0-9]+$ ]] || priority=0
    if [[ "${autoconnect}" == "yes" ]]; then
      if (( priority > best_auto_priority )); then
        best_auto_name="${name}"
        best_auto_uuid="${uuid}"
        best_auto_priority="${priority}"
        best_auto_count=1
      elif (( priority == best_auto_priority )); then
        best_auto_count=$((best_auto_count + 1))
      fi
    fi
  done < <(nmcli -t -f UUID,TYPE connection show 2>/dev/null)

  if (( best_auto_count == 1 )); then
    printf "%s\t%s\n" "${best_auto_name}" "${best_auto_uuid}"
    return 0
  fi
  if (( best_auto_count > 1 )); then
    info "Multiple saved autoconnect Wi-Fi profiles share priority ${best_auto_priority}; not recording a default" >&2
    return 1
  fi
  if (( suitable_count == 1 )); then
    printf "%s\t%s\n" "${only_name}" "${only_uuid}"
    return 0
  fi
  if (( suitable_count > 1 )); then
    info "Multiple saved Wi-Fi profiles found and none is a unique autoconnect default; not recording a default" >&2
  fi
  return 1
}

# network_state_phase: record current or saved WiFi connection (install only).
network_state_phase() {
  info "=== Phase: network state ==="
  info "Recording current network connection (if applicable)"

  if [[ -s "${INSTALL_DIR}/ssid" ]]; then
    info "WiFi connection already recorded at ${INSTALL_DIR}/ssid"
    return 0
  fi
  if _network_state_configured; then
    info "WiFi connection already recorded at /etc/autostream-network.json"
    return 0
  fi

  local selected wifi_conn wifi_uuid source
  selected="$(_select_active_wifi_connection || true)"
  source="active"
  if [[ -z "${selected}" ]]; then
    selected="$(_select_saved_wifi_connection || true)"
    source="saved"
  fi

  if [[ -n "${selected}" ]]; then
    wifi_conn="${selected%%$'\t'*}"
    wifi_uuid="${selected#*$'\t'}"
    if [[ "${wifi_uuid}" == "${wifi_conn}" ]]; then
      wifi_uuid=""
    fi
    _record_wifi_connection_state "${wifi_conn}" "${wifi_uuid}"
    info "Recorded ${source} WiFi connection '${wifi_conn}' to ${INSTALL_DIR}/ssid and /etc/autostream-network.json"
  else
    info "No active or uniquely selectable saved WiFi client connection detected; hotspot mode will be used if wired connection is not detected"
  fi
}

#############################################
# Watchdog safety
#############################################

# stop_watchdog_if_ram_monitored
#
# If the system watchdog service is enabled AND /etc/watchdog.conf has
# min-memory set to a non-zero value, stop the watchdog before the
# install/update begins.
#
# Why: the watchdog daemon will force-reboot the system if free RAM drops
# below the configured threshold.  apt upgrades, g++ compilation, and pip
# installs can all cause transient memory pressure that exceeds a tight
# min-memory limit, causing a spurious mid-update reboot.  Stopping the
# watchdog for the duration of the script is safe because the hardware
# watchdog timer is reset during graceful stops and the OS remains running.
stop_watchdog_if_ram_monitored() {
  # Nothing to do if the watchdog unit is not present or not enabled.
  if ! systemctl is-enabled watchdog &>/dev/null; then
    return 0
  fi

  # Parse the last uncommented min-memory line from /etc/watchdog.conf.
  # A value of 0 means the RAM check is disabled; anything else is active.
  local conf="/etc/watchdog.conf"
  local min_mem=""
  if [[ -f "${conf}" ]]; then
    min_mem="$(grep -E '^\s*min-memory\s*=' "${conf}" 2>/dev/null \
               | tail -n1 \
               | sed 's/[^=]*=\s*//' \
               | tr -d '[:space:]')" || true
  fi

  if [[ -z "${min_mem}" || "${min_mem}" == "0" ]]; then
    return 0
  fi

  info "Watchdog RAM monitoring is active (min-memory = ${min_mem} pages);" \
       "stopping watchdog service to prevent a spurious reboot during update"
  systemctl stop watchdog || true
}

#############################################
# Orchestration
#############################################
run_install() {
  info ">>> Starting first-time installation <<<"
  PROMPT_REBOOT_ON_EXIT=1

  stop_watchdog_if_ram_monitored
  check_network_manager
  show_warnings_and_prompt
  require_rpi_os_trixie
  handle_pin

  info "Setting working directory to original user's home: ${ORIG_HOME}"
  cd "${ORIG_HOME}"

  bootstrap_phase
  fetch_phase
  sdmon_phase
  deploy_phase
  configure_phase
  network_state_phase
  services_phase
  save_state

  info "Installation complete."
}

run_update() {
  info ">>> Starting update of existing installation <<<"
  PROMPT_REBOOT_ON_EXIT=0
  UPDATE_RUN_AT="$(date -Is)"
  CURRENT_PHASE="preflight"
  write_update_result "in_progress" "Starting update" 0

  stop_watchdog_if_ram_monitored
  check_network_manager

  system_upgrade_phase

  info "Setting working directory to original user's home: ${ORIG_HOME}"
  cd "${ORIG_HOME}"

  fetch_phase
  sdmon_phase
  deploy_phase
  configure_phase
  services_phase

  CURRENT_PHASE="state save"
  save_state
  CURRENT_PHASE="complete"
  write_update_result "success" "Update complete" 100

  info "Update complete. Scheduling reboot..."
  /usr/local/libexec/autostream/autostream_admin reboot --delay 3 AutostreamUpdate || true
}

#############################################
# Main
#############################################
main() {
  require_sudo
  parse_args "$@"
  init_logging

  if [[ "${INSTALL_MODE}" == "update" ]]; then
    load_state
    info "Loaded saved update config: OWNTONE_MODE=${OWNTONE_MODE} SDMON_METHOD=${SDMON_METHOD:-none}"
    run_update
  else
    run_install
  fi
}

main "$@"
