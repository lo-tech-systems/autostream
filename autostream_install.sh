#!/usr/bin/env bash
#
# autostream_install.sh
#
# Deployment script for autostream on Raspberry Pi OS Lite (Trixie).
# This installer is intentionally defensive and verbose.
#
# Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.
# www.lo-tech.co.uk/autostream • GitHub.com/lo-tech-systems/autostream
#
# IMPORTANT
# - This script is for Raspberry Pi OS (Trixie) ONLY.
# - Run this on a dedicated Raspberry Pi that will be a single-purpose autostream device.
# - It will install packages, enable services, and modify system configuration.
#
# Options:
# --yes
# Skips Continue Y/N prompt. User must still enter the PIN.
#
# --fetch-autostream
# Clone or update the Autostream repository from GitHub.
#
# --owntone-apt-ref <ref>
# Git ref, tag, or commit used to fetch Owntone APT repository metadata.
#
# --owntone-key-fpr <fingerprint>
# Expected GPG key fingerprint for the Owntone APT repository signing key.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

set -Eeuo pipefail
IFS=$'\n\t'

#############################################
# Globals
#############################################
SCRIPT_NAME="$(basename "${0}")"
ORIG_USER="${SUDO_USER:-$(id -un)}"
ORIG_HOME="$(getent passwd "${ORIG_USER}" | cut -d: -f6)"
LOGFILE="${ORIG_HOME}/autostream_install.log"

AUTOSTREAM_DIR="${ORIG_HOME}/autostream"
INSTALL_DIR="/opt/autostream"
APP_LOG_DIR="/var/log/autostream"

PIN_REGEX='^[A-Za-z0-9-]{4,20}$'

# Installer flags
AUTO_YES=0
OWNTONE_APT_REF="refs/heads/master"  # Prefer pinning to a commit or tag for release builds
OWNTONE_KEY_FPR=""                   # Optional: set expected Owntone repo key fingerprint to verify
FETCH_AUTOSTREAM=0                   # Only fetch autostream repo when explicitly requested

usage() {
  cat <<EOF
Usage: sudo ./${SCRIPT_NAME} [--yes] [--owntone-apt-ref <ref>] [--owntone-key-fpr <fingerprint>]

  --yes                  Run non-interactively (or skip confirmation prompts).
  --owntone-apt-ref REF  GitHub ref/commit for Owntone APT metadata (default: ${OWNTONE_APT_REF}).
  --owntone-key-fpr FPR  Expected Owntone repo key fingerprint (optional hardening).
  --fetch-autostream     Clone/update the autostream GitHub repository.
  --help, -h             Show this help.

Examples:
  sudo ./${SCRIPT_NAME}
  sudo ./${SCRIPT_NAME} --yes
  sudo ./${SCRIPT_NAME} --owntone-apt-ref <commit-sha> --owntone-key-fpr "ABCD ..."

EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --yes)
        AUTO_YES=1
        shift
        ;;
      --owntone-apt-ref)
        [[ $# -ge 2 ]] || { error "--owntone-apt-ref requires a value"; exit 2; }
        OWNTONE_APT_REF="$2"
        shift 2
        ;;
      --owntone-key-fpr)
        [[ $# -ge 2 ]] || { error "--owntone-key-fpr requires a value"; exit 2; }
        OWNTONE_KEY_FPR="$2"
        shift 2
        ;;
      --fetch-autostream)
        FETCH_AUTOSTREAM=1
        shift
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        error "Unknown argument: $1"
        usage
        exit 2
        ;;
    esac
  done
}

#############################################
# Logging + error handling
#############################################
init_logging() {
  # Overwrite existing log file
  mkdir -p "${ORIG_HOME}" || true
  : > "${LOGFILE}"
  chmod 0644 "${LOGFILE}" || true

  # Tee all output to log
  exec > >(tee -a "${LOGFILE}") 2>&1

  echo "[INFO] ${SCRIPT_NAME} starting at $(date -Is)"
  echo "[INFO] Running as: $(id -un) (uid=$(id -u)); original user: ${ORIG_USER}; original home: ${ORIG_HOME}"
  echo "[INFO] Log file: ${LOGFILE}"
}

info()  { echo "[INFO] $*"; }
warn()  { echo "[WARN] $*"; }
error() { echo "[ERROR] $*"; }

has_tty() {
  # Prefer the controlling terminal if present. This works even when stdin/stdout
  # are redirected (common over SSH or when logging/capturing output).
  [[ -r /dev/tty && -w /dev/tty ]]
}

tty_read() {
  # Usage: tty_read "Prompt" varname
  local prompt="$1" __var="$2"
  IFS= read -r -p "${prompt}" "${__var}" < /dev/tty
}

open_log_prompt() {
  # Offer to open the log with less (or pager) when interactive.
  local reason="$1"
  warn "${reason}"

  if has_tty; then
    echo
    tty_read "Open the log now? (Y/N) " ans || true
    case "${ans:-N}" in
      Y|y)
        ${PAGER:-less} "${LOGFILE}" || true
        ;;
      *)
        info "Log not opened. You can view it later: ${LOGFILE}"
        ;;
    esac
  else
    info "Non-interactive session; log available at: ${LOGFILE}"
  fi
}

on_error() {
  local exit_code=$?
  local line_no=${BASH_LINENO[0]:-?}
  error "Installation failed (exit ${exit_code}) at line ${line_no}."
  open_log_prompt "Check ${LOGFILE} for details."
  exit "${exit_code}"
}
trap on_error ERR

on_exit() {
  local exit_code=$?
  if [[ ${exit_code} -eq 0 ]]; then
    info "Installer completed successfully."
    if has_tty; then
      echo
      tty_read "Reboot now to complete setup? (Y/N) " rb || true
      case "${rb:-N}" in
        Y|y)
          info "Rebooting..."
          reboot
          ;;
        *)
          info "Reboot skipped. It's recommended to reboot soon."
          ;;
      esac
    else
      info "Non-interactive session detected; not prompting for reboot."
      info "Please reboot the device when convenient."
    fi
  fi
}
trap on_exit EXIT

#############################################
# Helpers
#############################################
require_sudo() {
  if [[ ${EUID} -ne 0 ]]; then
    echo "This script must be run as root (e.g., sudo ./${SCRIPT_NAME})."
    exit 1
  fi
}

validate_sudoers() {
  # Validate sudoers syntax to avoid bricking sudo access
  if ! command -v visudo >/dev/null 2>&1; then
    warn "visudo not found; cannot validate sudoers syntax."
    return 0
  fi

  # Validate main sudoers file
  if ! visudo -cf /etc/sudoers; then
    error "sudoers validation failed for /etc/sudoers"
    exit 1
  fi

  # Validate each fragment we installed
  local f
  for f in /etc/sudoers.d/autostream*; do
    [[ -e "$f" ]] || continue
    if ! visudo -cf "$f"; then
      error "sudoers validation failed for ${f}"
      exit 1
    fi
  done
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
        error "Aborting."
        exit 1
      fi
    else
      error "Non-interactive session detected; refusing to override OS safety check."
      exit 1
    fi
  fi
}

show_warnings_and_prompt() {
  cat <<'EOF'

=============================================================================
AUTOSTREAM INSTALLER
=============================================================================
This script will:
- Install OS packages (nginx, ffmpeg, owntone, watchdog, dnsmasq, etc.)
- Enable/disable systemd services
- Create system users/groups and modify permissions
- Modify /boot/firmware/config.txt to enable the hardware watchdog
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
    if [[ ${AUTO_YES} -eq 1 ]]; then
      info "--yes supplied; skipping interactive confirmation."
      return 0
    fi

    tty_read "Continue with installation? (Y/N) " ans || true
    case "${ans:-N}" in
      Y|y) info "Continuing..." ;;
      *) error "Aborted by user."; exit 1 ;;
    esac
  else
    if [[ ${AUTO_YES} -eq 1 ]]; then
      info "Non-interactive session; --yes supplied, continuing."
    else
      error "Non-interactive session detected. Refusing to proceed without --yes."
      error "Re-run with: sudo ./${SCRIPT_NAME} --yes"
      exit 1
    fi
  fi
}

prompt_for_pin() {
  local pin=""

  if ! has_tty; then
    warn "Non-interactive session: cannot prompt for PIN."
    warn "You can set the PIN later by creating /boot/pin.txt (or /boot/firmware/pin.txt)."
    return 0
  fi

  while true; do
    echo
    tty_read "Enter a setup PIN (4-20 chars; A-Z a-z 0-9 and hyphen only): " pin || true
    if [[ "${pin}" =~ ${PIN_REGEX} ]]; then
      break
    fi
    warn "Invalid PIN. Must match: ${PIN_REGEX}"
  done

  # Save to /boot for first-run configuration
  if [[ -d /boot/firmware ]]; then
    echo "${pin}" > /boot/firmware/pin.txt
  elif [[ -d /boot ]]; then
    echo "${pin}" > /boot/pin.txt
  else
    warn "Could not find /boot or /boot/firmware; PIN not saved."
  fi
}

apt_install() {
  local soft_fail=0
  if [[ "$1" == "--soft" ]]; then
    soft_fail=1
    shift
  fi

  local pkgs=("$@")
  [[ ${#pkgs[@]} -eq 0 ]] && return 0

  info "Installing packages: ${pkgs[*]}"

  if ! DEBIAN_FRONTEND=noninteractive \
       apt-get install -y --no-install-recommends "${pkgs[@]}"; then
    if (( soft_fail )); then
      warn "apt_install soft-failed for packages: ${pkgs[*]}"
      return 0
    else
      error "apt_install failed for packages: ${pkgs[*]}"
      return 1
    fi
  fi
}

apt_install_() {
  local pkgs=("$@")
  if [[ ${#pkgs[@]} -eq 0 ]]; then
    return 0
  fi
  info "Installing packages: ${pkgs[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${pkgs[@]}"
}

ensure_group() {
  local group="$1"
  if getent group "${group}" >/dev/null; then
    info "Group '${group}' already exists."
  else
    info "Creating group '${group}'"
    groupadd "${group}"
  fi
}

ensure_user() {
  local user="$1"
  local group="$2"

  if id -u "${user}" >/dev/null 2>&1; then
    info "User '${user}' already exists."
  else
    info "Creating system user '${user}'"
    useradd --system --no-create-home --shell /usr/sbin/nologin -g "${group}" "${user}"
  fi
}

ensure_user_in_group() {
  local user="$1"
  local group="$2"

  if ! getent group "${group}" >/dev/null 2>&1; then
    warn "Group '${group}' not found; cannot add '${user}' to it."
    return 0
  fi

  if id -nG "${user}" 2>/dev/null | tr ' ' '\n' | grep -qx "${group}"; then
    info "User '${user}' is already a member of '${group}'."
    return 0
  fi

  info "Adding user '${user}' to group '${group}'"
  usermod -aG "${group}" "${user}"
}

git_clone_or_update() {
  local repo_url="$1"
  local dest_dir="$2"

  if [[ -d "${dest_dir}/.git" ]]; then
    info "Updating ${dest_dir}"
    git -C "${dest_dir}" fetch --all --prune
    git -C "${dest_dir}" reset --hard origin/master
  else
    info "Cloning ${repo_url} into ${dest_dir}"
    rm -rf "${dest_dir}" || true
    git clone "${repo_url}" "${dest_dir}"
  fi
}


update_pi_firmware_config() {
  # updates /boot/firmware/config.txt to enable the hardware watchdog and disable Bluetooth
  local cfg="/boot/firmware/config.txt"
  if [[ ! -f "${cfg}" ]]; then
    warn "${cfg} not found; skipping firmware settings update."
    return 0
  fi
  info "Updating firmware settings in ${cfg}"

  local tmp
  tmp="$(mktemp)"

  if grep -qE '^\s*\[all\]\s*$' "${cfg}"; then
    awk '
      BEGIN { inserted=0 }
      # Drop any existing watchdog param regardless of value
      /^[[:space:]]*dtparam=watchdog[[:space:]]*=.*$/ { next }
      # Drop any existing disable-bt overlay line (with or without extra params)
      /^[[:space:]]*dtoverlay=disable-bt([[:space:]]*|,.*)$/ { next }

      {
        print
        if (!inserted && $0 ~ /^[[:space:]]*\[all\][[:space:]]*$/) {
          print "dtparam=watchdog=on"
          print "dtoverlay=disable-bt"
          inserted=1
        }
      }
    ' "${cfg}" > "${tmp}"
  else
    {
      echo "[all]"
      echo "dtparam=watchdog=on"
      echo "dtoverlay=disable-bt"
      echo
      # Also clean conflicting lines from the rest of the file
      awk '
        /^[[:space:]]*dtparam=watchdog[[:space:]]*=.*$/ { next }
        /^[[:space:]]*dtoverlay=disable-bt([[:space:]]*|,.*)$/ { next }
        { print }
      ' "${cfg}"
    } > "${tmp}"
  fi

  install -m "$(stat -c %a "${cfg}")" \
          -o "$(stat -c %u "${cfg}")" \
          -g "$(stat -c %g "${cfg}")" \
          "${tmp}" "${cfg}"
  rm -f "${tmp}"
}


#############################################
# Main
#############################################
main() {
  parse_args "$@"
  require_sudo
  init_logging

  show_warnings_and_prompt
  require_rpi_os_trixie
  prompt_for_pin

  info "Setting working directory to original user's home: ${ORIG_HOME}"
  cd "${ORIG_HOME}"

  info "Creating directories"
  mkdir -p "${AUTOSTREAM_DIR}" || true
  mkdir -p "${INSTALL_DIR}" "${APP_LOG_DIR}"

  info "Updating apt metadata"
  DEBIAN_FRONTEND=noninteractive apt-get update -y

  # Base prerequisites
  apt_install curl gpg ca-certificates

  # Add owntone apt repo (idempotent)
  info "Configuring Owntone APT repository"
  curl -fsSL "https://raw.githubusercontent.com/owntone/owntone-apt/${OWNTONE_APT_REF}/repo/rpi/owntone.gpg" \
    | gpg --dearmor \
    | tee /usr/share/keyrings/owntone-archive-keyring.gpg >/dev/null

  if [[ -n "${OWNTONE_KEY_FPR}" ]]; then
    info "Verifying Owntone APT key fingerprint"
    # Normalize expected fingerprint: remove spaces
    local_expected="$(echo "${OWNTONE_KEY_FPR}" | tr -d '[:space:]')"
    local_actual="$(gpg --show-keys --with-colons /usr/share/keyrings/owntone-archive-keyring.gpg | awk -F: '$1=="fpr"{print $10; exit}')"
    if [[ -z "${local_actual}" || "${local_actual}" != "${local_expected}" ]]; then
      error "Owntone APT key fingerprint mismatch. Expected: ${local_expected}; got: ${local_actual:-<none>}"
      exit 1
    fi
  else
    warn "OWNTONE_KEY_FPR not set; skipping Owntone APT key fingerprint verification."
  fi

  curl -fsSL \
    -o /etc/apt/sources.list.d/owntone.list \
    "https://raw.githubusercontent.com/owntone/owntone-apt/${OWNTONE_APT_REF}/repo/rpi/owntone-trixie.list"

  DEBIAN_FRONTEND=noninteractive apt-get update -y

  # Platform libraries
  apt_install git build-essential libffi-dev pkg-config jq fq acl \
    libportaudio2 portaudio19-dev python3-dev python3-venv python3-pip

  # Platform services
  apt_install watchdog dnsmasq fcgiwrap

  # Application services
  apt_install nginx ffmpeg owntone
  systemctl enable owntone

  # Python libraries. Anything that fails will be installed by pip later hence can ignore
  # failures. It just saves compiling e.g. numpy, which takes hours on a Pi Zero.
  # There doesn't seem to be a python3-sounddevice on trixie, so we install it via pip later.
  apt_install --soft python3-requests
  apt_install --soft python3-numpy
  apt_install --soft python3-flask
  apt_install --soft python3-flask-sqlalchemy
  apt_install --soft python3-yaml
  apt_install --soft python3-cffi

  # sdmon
  info "Installing sdmon"
  if [[ ! -x "${INSTALL_DIR}/sdmon" ]]; then
    tmpdir="$(mktemp -d)"
    git clone https://github.com/Ognian/sdmon.git "${tmpdir}/sdmon"
    make -C "${tmpdir}/sdmon/src"
    install -m 0755 "${tmpdir}/sdmon/src/sdmon" "${INSTALL_DIR}/sdmon"
    rm -rf "${tmpdir}"
  fi

  # Create autostream user and groups
  ensure_group autostream
  ensure_user autostream autostream
  ensure_user_in_group autostream netdev
  ensure_user_in_group autostream audio

  # Download/update autostream (optional)
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

  ###########################################
  # Permissions + policy
  ###########################################
  info "Configuring permissions and policy"

  mkdir -p /etc/polkit-1/rules.d
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/polkit/50-autostream-hostname.rules" /etc/polkit-1/rules.d/50-autostream-hostname.rules

  install -m 0440 -o root -g root "${AUTOSTREAM_DIR}/system/sudoers/autostream_updater" /etc/sudoers.d/autostream_updater
  install -m 0440 -o root -g root "${AUTOSTREAM_DIR}/system/sudoers/autostream_owntone_restart" /etc/sudoers.d/autostream_owntone_restart
  validate_sudoers

  # Install directory ownership
  mkdir -p "${INSTALL_DIR}"
  chown -R autostream:autostream "${INSTALL_DIR}"
  chmod 0755 "${INSTALL_DIR}"

  # Owntone config dir - owned by root, but allow autostream user via ACL
  info "Creating owntone.conf"
  mkdir -p "${INSTALL_DIR}/owntone"
  if [[ -f /etc/owntone.conf ]]; then
    install /etc/owntone.conf "${INSTALL_DIR}/owntone/owntone.conf"
  else
    warn "/etc/owntone.conf not found; owntone.conf was not staged"
  fi

  ###########################################
  # systemd override for owntone
  ###########################################
  info "Applying owntone systemd override"
  mkdir -p /etc/systemd/system/owntone.service.d
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/owntone_override.conf" /etc/systemd/system/owntone.service.d/owntone_override.conf
  systemctl daemon-reload
  systemctl restart owntone

  ###########################################
  # Copy in files
  ###########################################
  info "Deploying autostream files to ${INSTALL_DIR}"
  cp -a "${AUTOSTREAM_DIR}/core/." "${INSTALL_DIR}/"
  cp -a "${AUTOSTREAM_DIR}/license/." "${INSTALL_DIR}/"
  cp -a "${AUTOSTREAM_DIR}/version" "${INSTALL_DIR}/"


  # Record current WiFi connection (if any)
  info "Recording current network connection (if applicable)"

  # Capture the active WiFi client connection name (if present)
  if [[ ! -s "${INSTALL_DIR}/ssid" ]]; then
    wifi_conn="$(
      nmcli -t -f DEVICE,TYPE,STATE,CONNECTION device status 2>/dev/null \
        | awk -F: '$1=="wlan0" && $2=="wifi" && ($3=="connected" || $3=="activated") && $4!="" {print $4; exit}'
    )"

    if [[ -n "${wifi_conn}" ]]; then
      # Ensure we are not recording the hotspot/AP connection
      wifi_mode="$(
        nmcli -t -f 802-11-wireless.mode connection show "${wifi_conn}" 2>/dev/null \
          | awk -F: '{print tolower($2)}' | head -n1
      )"
      if [[ "${wifi_mode}" != "ap" ]]; then
        printf "%s\n" "${wifi_conn}" > "${INSTALL_DIR}/ssid"
        info "Recorded WiFi connection '${wifi_conn}' to ${INSTALL_DIR}/ssid"
      else
        info "Current WiFi connection '${wifi_conn}' is AP mode; not recording"
      fi
    else
      info "No active WiFi connection detected on wlan0; Hotspot mode will be used if wired connection is not detected"
    fi
  else
    info "WiFi connection already recorded at ${INSTALL_DIR}/ssid"
  fi

  # systemd services (install explicit units to avoid clobbering unrelated files)
  info "Installing systemd units"
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream_dnsmasq.service" /etc/systemd/system/
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream_rebooter.path" /etc/systemd/system/
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream_rebooter.service" /etc/systemd/system/
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream_sdcardhealth.service" /etc/systemd/system/
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream_sdcardhealth.timer" /etc/systemd/system/
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream.service" /etc/systemd/system/
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream_wifi_watcher.service" /etc/systemd/system/

  systemctl daemon-reload
  systemctl enable autostream_rebooter.path
  systemctl enable autostream_sdcardhealth.timer
  systemctl enable autostream.service
  systemctl enable autostream_wifi_watcher.service

  # nginx
  info "Configuring nginx"
  cp -a "${AUTOSTREAM_DIR}/nginx"  "${INSTALL_DIR}/"
  cp -a "${AUTOSTREAM_DIR}/images" "${INSTALL_DIR}/"
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/nginx/autostream-nginx.conf"  /etc/nginx/sites-available/autostream-nginx.conf
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/nginx/autostream-nginxd.conf" /etc/nginx/conf.d/autostream-nginxd.conf

  if [[ -e /etc/nginx/sites-enabled/default ]]; then
    rm -f /etc/nginx/sites-enabled/default
  fi
  ln -sf /etc/nginx/sites-available/autostream-nginx.conf /etc/nginx/sites-enabled/autostream-nginx.conf

  nginx -t
  systemctl enable nginx

  # logrotate
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/logrotate/autostream" /etc/logrotate.d/autostream

  # dnsmasq
  cp -a "${AUTOSTREAM_DIR}/system/dnsmasq/autostream-setup.conf" /etc/dnsmasq.d/
  systemctl disable dnsmasq || true

  # NetworkManager
  cp -a "${AUTOSTREAM_DIR}/system/NetworkManager/99-wlan-fix" /etc/NetworkManager/dispatcher.d/
  cp -a "${AUTOSTREAM_DIR}/system/NetworkManager/mdns.conf" /etc/NetworkManager/conf.d/
  cp -a "${AUTOSTREAM_DIR}/system/NetworkManager/wifi-powersave.conf" /etc/NetworkManager/conf.d/

  ###########################################
  # Watchdog and firmware settings
  ###########################################
  update_pi_firmware_config
  cp -a "${AUTOSTREAM_DIR}/system/watchdog/watchdog.conf" /etc/watchdog.conf
  systemctl enable watchdog
  # no need to disable bluetooth services as it is disabled in the firmware config

  ###########################################
  # Python venv
  ###########################################
  info "Setting permissions to enable autostream to create Python venv"
  chown autostream:autostream "${INSTALL_DIR}"

  info "Creating Python virtual environment"
  if [[ ! -d "${INSTALL_DIR}/venv" ]]; then
    sudo -u autostream PIP_CACHE_DIR=/tmp/pip-cache python3 -m venv --system-site-packages "${INSTALL_DIR}/venv"
  fi

  sudo -u autostream PIP_CACHE_DIR=/tmp/pip-cache "${INSTALL_DIR}/venv/bin/pip" install -U pip

  if [[ -f "${INSTALL_DIR}/requirements.lock" ]]; then
    info "Installing Python dependencies from requirements.lock (hash-checked)"
    sudo -u autostream PIP_CACHE_DIR=/tmp/pip-cache "${INSTALL_DIR}/venv/bin/pip" install --require-hashes -r "${INSTALL_DIR}/requirements.lock"
  else
    warn "requirements.lock not found; installing from requirements.txt (not hash-pinned)"
    sudo -u autostream PIP_CACHE_DIR=/tmp/pip-cache "${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"
  fi

  ###########################################
  # Permissions
  ###########################################
  info "Setting ownership and permissions"

  # 1) Normalize ownership for the whole install tree (we'll restore exceptions below)
  chown -R autostream:autostream "${INSTALL_DIR}"
  chown -R autostream:autostream "${APP_LOG_DIR}"

  # 2) Base directory expectations
  chown root:root "${INSTALL_DIR}"
  chmod 0755 "${INSTALL_DIR}"

  # 3) Log directory
  chmod 0750 "${APP_LOG_DIR}"

  # 4) Executables / scripts
  # Top-level installer/runtime scripts shipped in INSTALL_DIR
  find "${INSTALL_DIR}" -maxdepth 1 -type f -name "*.sh" -exec chmod 0755 {} + 2>/dev/null || true
  chown root:root "${INSTALL_DIR}/autostream_rebooter.sh"

  # Nginx CGI scripts should be executable
  chmod 0755 "${INSTALL_DIR}/nginx/cgi"/*.cgi 2>/dev/null || true

  # Offline html should be world-readable
  chmod 0644 "${INSTALL_DIR}/nginx/offline"/*.html 2>/dev/null || true

  # 5) Exceptions that must remain root-owned (restore after the bulk chown)
  # Owntone config hardening: root-owned + restrictive perms + ACL access for autostream
  if [[ -d "${INSTALL_DIR}/owntone" ]]; then
    chown -R root:root "${INSTALL_DIR}/owntone"
    chmod 0750 "${INSTALL_DIR}/owntone"
    setfacl -m u:autostream:rwx "${INSTALL_DIR}/owntone" 2>/dev/null || true
    setfacl -m d:u:autostream:rwx "${INSTALL_DIR}/owntone" 2>/dev/null || true
    # Allow autostream read/write access to owntone.conf if present
    if [[ -f "${INSTALL_DIR}/owntone/owntone.conf" ]]; then
      setfacl -m u:autostream:rw "${INSTALL_DIR}/owntone/owntone.conf" 2>/dev/null || true
    fi
  fi

  # SSID file: root-owned and readable
  if [[ -f "${INSTALL_DIR}/ssid" ]]; then
    chown root:root "${INSTALL_DIR}/ssid"
    chmod 0644 "${INSTALL_DIR}/ssid"
  fi

  # sdmon helper: keep root-owned + executable (if present)
  if [[ -f "${INSTALL_DIR}/sdmon" ]]; then
    chown root:root "${INSTALL_DIR}/sdmon"
    chmod 0755 "${INSTALL_DIR}/sdmon"
  fi

  # Reboot script - prevent autostream from modifying this
  if [[ -f "${INSTALL_DIR}/autostream_rebooter.sh" ]]; then
    chown root:root "${INSTALL_DIR}/autostream_rebooter.sh"
    chmod 0755 "${INSTALL_DIR}/autostream_rebooter.sh"
  fi

  # autostream directory owned by autostream
  chown autostream:autostream "${INSTALL_DIR}"

  info "Install script completed."
}

main "$@"
