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
# Options:
# --unattended PIN=1234
# Skips Continue Y/N prompt and sets the PIN to the value specified.
# Falls back to attended mode if PIN is not specified.
#
# --sdmon=[auto|sandisk|adata|transcend|micron|swissbit|2step]
# Enable sdmon (SD Card Monitoring) with the specified method.
# IMPORTANT: This should only be used with supported cards, generally
#            industrial-grade cards from those manufacturers, for example
#            the Sandisk SDSDQAF3-008G-I. sdmon may cause consumer-grade
#            cards to go offline.
#
# --fetch-autostream
# Clone or update the Autostream repository from GitHub.
#
# --owntone=[mini|full|skip]
# Select how OwnTone should be provisioned:
#   mini (default): build and install OwnTone from the lo-tech-systems source
#                   repository without modifying /etc/owntone.conf
#   full: install packaged OwnTone from the public repository
#   skip: do not install or build OwnTone; only reuse an existing installation
#         and update /etc/owntone.conf when present
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

AUTOSTREAM_DIR="$(cd "$(dirname "$0")" && pwd)"
#AUTOSTREAM_DIR="${ORIG_HOME}/autostream"

INSTALL_DIR="/opt/autostream"
APP_LOG_DIR="/var/log/autostream"
STAMP_DIR="/var/lib/autostream"          # root-only stamp/admin binaries
LIBEXEC_DIR="/usr/local/libexec/autostream"  # root-owned helper scripts

PIN_REGEX='^[A-Za-z0-9-]{4,20}$'

# Installer flags
UNATTENDED=0
PIN_VALUE=""

SDMON_METHOD=""                  # e.g. auto|sandisk|adata|transcend|micron|swissbit|2step

FETCH_AUTOSTREAM=0                   # Only fetch autostream repo when explicitly requested
PROMPT_REBOOT_ON_EXIT=0              # Enabled only after a real install run starts
OWNTONE_MODE="mini"                  # mini=lo-tech source build, full=packaged, skip=reuse existing install

usage() {
  cat <<EOF
Usage: sudo ./${SCRIPT_NAME} [--unattended PIN=1234] [--sdmon[=<method>]] [--owntone=<mini|full|skip>] [--fetch-autostream]

  --unattended PIN=1234      Run non-interactively (or skip confirmation prompts) and set the PIN.
                             If PIN is omitted/invalid, the installer falls back to attended mode.

  --sdmon[=<method>]         Enable sdmon (SD Card Monitoring); bare --sdmon uses auto.
                             auto | sandisk | adata | transcend | micron | swissbit | 2step

  --owntone=MODE             OwnTone provisioning mode:
                             mini = build/install lo-tech OwnTone from source (default)
                                    without editing /etc/owntone.conf
                             full = install packaged OwnTone
                             skip = do not install/build OwnTone, but update /etc/owntone.conf when present
  --fetch-autostream         Clone/update the autostream GitHub repository.
  --help, -h                 Show this help.

Examples:
  sudo ./${SCRIPT_NAME}
  sudo ./${SCRIPT_NAME} --unattended PIN=1234
  sudo ./${SCRIPT_NAME} --unattended PIN=abcd-1234 --sdmon=sandisk
  sudo ./${SCRIPT_NAME} --owntone=full
  sudo ./${SCRIPT_NAME} --owntone=skip

EOF
}

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

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --unattended)
        UNATTENDED=1
        # Expect a following arg like PIN=1234
        if [[ $# -ge 2 && "$2" == PIN=* ]]; then
          PIN_VALUE="${2#PIN=}"
          shift 2
        else
          # Narrative says: fall back to attended mode if PIN not specified.
          PIN_VALUE=""
          UNATTENDED=0
          shift
        fi
        ;;
      --sdmon)
        SDMON_METHOD="auto"
        shift
        ;;
      --sdmon=*)
        SDMON_METHOD="${1#--sdmon=}"
        if ! is_valid_sdmon_method "${SDMON_METHOD}"; then
          error "Invalid --sdmon method: ${SDMON_METHOD}"
          usage
          exit 2
        fi
        shift
        ;;
      --owntone=*)
        OWNTONE_MODE="${1#--owntone=}"
        if ! is_valid_owntone_mode "${OWNTONE_MODE}"; then
          error "Invalid --owntone mode: ${OWNTONE_MODE}"
          usage
          exit 2
        fi
        shift
        ;;
      --owntone)
        [[ $# -ge 2 ]] || { error "--owntone requires a value"; exit 2; }
        OWNTONE_MODE="$2"
        if ! is_valid_owntone_mode "${OWNTONE_MODE}"; then
          error "Invalid --owntone mode: ${OWNTONE_MODE}"
          usage
          exit 2
        fi
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

  # If --unattended provided with a PIN, validate it here. If invalid, revert to attended.
  if [[ ${UNATTENDED} -eq 1 ]]; then
    if [[ -z "${PIN_VALUE}" || ! "${PIN_VALUE}" =~ ${PIN_REGEX} ]]; then
      warn "--unattended supplied but PIN is missing/invalid; falling back to attended mode."
      UNATTENDED=0
      PIN_VALUE=""
    fi
  fi
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
  if [[ ${PROMPT_REBOOT_ON_EXIT} -ne 1 ]]; then
    exit "${exit_code}"
  fi
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
- Install OS packages (nginx, watchdog, dnsmasq, build tools, etc.) and build
  OwnTone Mini by default
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

  if id -nG "${user}" 2>/dev/null | tr ' ' '
' | grep -qx "${group}"; then
    info "User '${user}' is already a member of '${group}'."
    return 0
  fi

  info "Adding user '${user}' to group '${group}'"
  usermod -aG "${group}" "${user}"
}

install_text_linux() {
  # Install a text file and normalize line endings to LF (strip CR).
  # Usage: install_text_linux <src> <dest> <mode> [owner] [group]
  local src="$1" dest="$2" mode="$3" owner="${4:-root}" group="${5:-root}"

  if [[ ! -f "$src" ]]; then
    error "Missing required file: $src"
    return 1
  fi

  install -m "$mode" -o "$owner" -g "$group" "$src" "$dest"

  # Convert CRLF -> LF in-place (remove trailing carriage return)
  sed -i 's/\r$//' "$dest" || true
}

install_bin() {
  # Install an executable file (binary or script). Does not modify contents.
  # Usage: install_bin <src> <dest> <mode> [owner] [group]
  local src="$1" dest="$2" mode="$3" owner="${4:-root}" group="${5:-root}"

  if [[ ! -e "${src}" ]]; then
    error "Missing required file: ${src}"
    return 1
  fi

  install -m "${mode}" -o "${owner}" -g "${group}" "${src}" "${dest}"
}

git_clone_or_update() {
  local repo_url="$1"
  local dest_dir="$2"

  if [[ -d "${dest_dir}/.git" ]]; then
    info "Updating ${dest_dir}"
    git -C "${dest_dir}" fetch --all --prune
    git -C "${dest_dir}" reset --hard origin/main
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

patch_sdmon_service_method() {
  # Inject the requested sdmon method into ExecStart before the /dev node.
  # The -a flag is only valid for the 2step method.
  local method="$1"
  local svc="/etc/systemd/system/autostream_sdcardhealth.service"

  [[ -f "${svc}" ]] || { warn "sdmon service not found at ${svc}; cannot patch method"; return 0; }

  local method_args="-m ${method}"
  if [[ "${method}" == "2step" ]]; then
    method_args="${method_args} -a"
  fi

  if grep -qE "^ExecStart=.*\\bsdmon\\b" "${svc}"; then
    info "Patching ${svc} to set sdmon method: ${method}"
    # Remove any existing -m/-a flags and then insert the requested method before the /dev node.
    sed -i -E \
      "/^ExecStart=.*\\bsdmon\\b/ {
        s/[[:space:]]-m[[:space:]]+[A-Za-z0-9_-]+//g
        s/[[:space:]]-a//g
        s#(\\bsdmon\\b[^\n]*)([[:space:]]+/dev/)#\\1 ${method_args}\\2#
      }" \
      "${svc}"
  else
    warn "No ExecStart line referencing sdmon found in ${svc}; cannot patch method"
  fi
}

configure_owntone_apt_repo() {
  info "Configuring Owntone APT repository"
  curl -fsSL "https://raw.githubusercontent.com/owntone/owntone-apt/refs/heads/master/repo/rpi/owntone.gpg" \
    | gpg --dearmor \
    | tee /usr/share/keyrings/owntone-archive-keyring.gpg >/dev/null

  curl -fsSL \
    -o /etc/apt/sources.list.d/owntone.list \
    "https://raw.githubusercontent.com/owntone/owntone-apt/refs/heads/master/repo/rpi/owntone-trixie.list"

  DEBIAN_FRONTEND=noninteractive apt-get update
}

install_packaged_owntone() {
  configure_owntone_apt_repo
  apt_install owntone
  systemctl enable owntone
}

remove_owntone_apt_repo() {
  local removed=0
  if [[ -f /etc/apt/sources.list.d/owntone.list ]]; then
    rm -f /etc/apt/sources.list.d/owntone.list
    removed=1
  fi
  if [[ -f /usr/share/keyrings/owntone-archive-keyring.gpg ]]; then
    rm -f /usr/share/keyrings/owntone-archive-keyring.gpg
    removed=1
  fi
  if [[ ${removed} -eq 1 ]]; then
    info "Removed OwnTone APT repository configuration"
    DEBIAN_FRONTEND=noninteractive apt-get update
  fi
}

install_owntone_mini_from_source() {
  info "Installing OwnTone Mini from lo-tech-systems source repository"
  apt_install nginx autotools-dev autoconf automake libtool gettext gawk \
    gperf bison flex libconfuse-dev libunistring-dev libsqlite3-dev \
    libavcodec-dev libavformat-dev libavfilter-dev libswscale-dev libavutil-dev \
    libxml2-dev libgcrypt20-dev libavahi-client-dev zlib1g-dev \
    libevent-dev libplist-dev libsodium-dev libjson-c-dev libwebsockets-dev \
    libcurl4-openssl-dev libprotobuf-c-dev libgnutls28-dev

  if dpkg -s owntone >/dev/null 2>&1; then
    info "Removing packaged OwnTone before source install"
    systemctl stop owntone || true
    DEBIAN_FRONTEND=noninteractive apt-get remove -y owntone
    remove_owntone_apt_repo
  else
    remove_owntone_apt_repo
  fi

  local tmpdir
  tmpdir="$(mktemp -d)"
  git clone --branch minimal --single-branch https://github.com/lo-tech-systems/owntone-server.git "${tmpdir}/owntone-server"
  (
    cd "${tmpdir}/owntone-server"
    autoreconf -i
    ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-install-user --enable-chromecast
    make -j2
    make install
  )
  rm -rf "${tmpdir}"

  systemctl daemon-reload
  systemctl enable avahi-daemon
  systemctl enable owntone
  systemctl start owntone
}

#############################################
# Main
#############################################
main() {
  parse_args "$@"
  PROMPT_REBOOT_ON_EXIT=1
  require_sudo
  init_logging

# --- NetworkManager / nmcli hard requirement ---
if ! command -v nmcli >/dev/null 2>&1; then
  echo "ERROR: nmcli not found."
  echo "This application requires NetworkManager. Aborting."
  exit 1
fi

# Ensure NetworkManager is running and managing networking
if ! systemctl is-active --quiet NetworkManager; then
  echo "ERROR: NetworkManager service is not active."
  echo "This application requires NetworkManager to manage networking. Aborting."
  exit 1
fi

# Ensure NetworkManager is actually in control (not ifupdown, dhcpcd, etc.)
if ! nmcli -t -f RUNNING general status 2>/dev/null | grep -qx running; then
  echo "ERROR: NetworkManager is installed but not managing networking."
  echo "Please disable other network managers (e.g. dhcpcd, ifupdown)."
  echo "Aborting."
  exit 1
fi
# --- end NetworkManager guard ---

  show_warnings_and_prompt
  require_rpi_os_trixie

  if [[ ${UNATTENDED} -eq 1 && -n "${PIN_VALUE}" ]]; then
    info "Unattended mode: setting PIN from command line"
    set_pin_file "${PIN_VALUE}"
  else
    prompt_for_pin
  fi

  info "Setting working directory to original user's home: ${ORIG_HOME}"
  cd "${ORIG_HOME}"

  info "Creating directories"
  mkdir -p "${AUTOSTREAM_DIR}" || true
  mkdir -p "${INSTALL_DIR}" "${APP_LOG_DIR}"

  # Root-only stamps/admin directory
  mkdir -p "${STAMP_DIR}"
  chown root:root "${STAMP_DIR}"
  chmod 0700 "${STAMP_DIR}"

  # Root-owned libexec helpers
  mkdir -p "${LIBEXEC_DIR}"
  chown root:root "${LIBEXEC_DIR}"
  chmod 0755 "${LIBEXEC_DIR}"

  info "Updating apt metadata"
  DEBIAN_FRONTEND=noninteractive apt-get update

  # Base prerequisites
  apt_install curl gpg ca-certificates

  # Platform libraries
  # Note - Flask is intentionally installed at the system level because
  # autostream_wifi_watcher runs directly via its shebang as a boot/recovery
  # path and should not depend on the application venv being present/healthy.
  apt_install git build-essential libffi-dev pkg-config fq \
    libasound2-dev libsamplerate0-dev python3-dev python3-venv python3-pip python3-flask

  # Platform services
  apt_install nginx watchdog dnsmasq fcgiwrap avahi-daemon avahi-utils

  # Application services
  if [[ "${OWNTONE_MODE}" == "skip" ]]; then
    info "Skipping OwnTone install/build; reusing existing system OwnTone"
  elif [[ "${OWNTONE_MODE}" == "mini" ]]; then
    install_owntone_mini_from_source
  else
    install_packaged_owntone
  fi

  # Python libraries. Anything that fails will be installed by pip later, so
  # failures here are non-fatal; this mainly speeds up the venv install.
  apt_install --soft python3-requests

  # sdmon (only when enabled)
  if [[ -n "${SDMON_METHOD}" ]]; then
    info "Installing sdmon (method: ${SDMON_METHOD})"
    if [[ ! -x "/usr/local/sbin/sdmon" ]]; then
      tmpdir="$(mktemp -d)"
      git clone https://github.com/Ognian/sdmon.git "${tmpdir}/sdmon"
      make -C "${tmpdir}/sdmon/src"
      install -m 0755 "${tmpdir}/sdmon/src/sdmon" "/usr/local/sbin/sdmon"
      rm -rf "${tmpdir}"
    fi
  else
    info "sdmon not enabled (use --sdmon=<method> to enable)"
  fi

  # Create autostream user and groups
  ensure_group autostream
  ensure_user autostream autostream
  ensure_user_in_group autostream netdev
  ensure_user_in_group autostream audio
  # video group required to allow autostream to query PSU status via vcgencmd
  ensure_user_in_group autostream video

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

  install -m 0440 -o root -g root "${AUTOSTREAM_DIR}/system/sudoers/autostream_updater" /etc/sudoers.d/autostream_updater
  install -m 0440 -o root -g root "${AUTOSTREAM_DIR}/system/sudoers/autostream_admin" /etc/sudoers.d/autostream_admin
  validate_sudoers

  # Install directory ownership
  mkdir -p "${INSTALL_DIR}"
  chown -R autostream:autostream "${INSTALL_DIR}"
  chmod 0755 "${INSTALL_DIR}"

  if [[ "${OWNTONE_MODE}" == "mini" ]]; then
    info "Skipping /etc/owntone.conf update for --owntone=mini"
  elif [[ "${OWNTONE_MODE}" == "skip" && ! -f /etc/owntone.conf ]]; then
    warn "--owntone=skip is set and /etc/owntone.conf is missing; skipping OwnTone config update."
  else
    info "Configuring /etc/owntone.conf for autostream pipe playback"
    python3 - /etc/owntone.conf <<'PYOWNTONE'
from pathlib import Path
import re
import sys

conf = Path(sys.argv[1])
if conf.exists():
    text = conf.read_text(encoding="utf-8")
else:
    text = ""

line = 'directories = { "/tmp/autostream-pipes" }'
lib = re.search(r'(?ms)^\s*library\s*\{.*?^\s*\}', text)
if lib:
    block = lib.group(0)
    if re.search(r'(?m)^\s*directories\s*=\s*\{[^}]*\}', block):
        block = re.sub(
            r'(?m)^(\s*)directories\s*=\s*\{[^}]*\}\s*$',
            r'\1' + line,
            block,
            count=1,
        )
    else:
        open_brace = block.find('{')
        first_newline = block.find('\n', open_brace)
        if first_newline != -1:
            block = block[:first_newline + 1] + '\t' + line + '\n' + block[first_newline + 1:]
        else:
            block = block.rstrip() + '\n\t' + line + '\n}'
    text = text[:lib.start()] + block + text[lib.end():]
else:
    if text and not text.endswith('\n'):
        text += '\n'
    if text:
        text += '\n'
    text += 'library {\n\t' + line + '\n}\n'

conf.write_text(text, encoding="utf-8")
PYOWNTONE
  fi

  ###########################################
  # Copy in files
  ###########################################
  info "Deploying autostream files to ${INSTALL_DIR}"
  # Remove stale dependency lockfiles from previous installs before copying the
  # new tree.  Otherwise an old requirements.lock can survive repo upgrades and
  # keep reinstalling packages that are no longer part of the project.
  rm -f "${INSTALL_DIR}/requirements.lock"
  cp -a "${AUTOSTREAM_DIR}/core/." "${INSTALL_DIR}/"
  cp -a "${AUTOSTREAM_DIR}/LICENSE" "${INSTALL_DIR}/"
  cp -a "${AUTOSTREAM_DIR}/version" "${INSTALL_DIR}/"
  chmod +x "${INSTALL_DIR}/autostream_wifi_watcher"
  if [[ -f "${AUTOSTREAM_DIR}/nowplaying_hints.json" ]]; then
    cp -a "${AUTOSTREAM_DIR}/nowplaying_hints.json" "${INSTALL_DIR}/nowplaying_hints.json"
  fi

  ###########################################
  # Build autostream_monitor
  ###########################################
  info "Building autostream_monitor"
  mkdir -p "${INSTALL_DIR}/monitor"
  g++ -std=c++17 -O2 \
    -o "${INSTALL_DIR}/monitor/autostream_monitor" \
    "${INSTALL_DIR}/monitor/autostream_monitor.cpp" \
    -lasound -lsamplerate -lpthread
  chmod 0755 "${INSTALL_DIR}/monitor/autostream_monitor"

  # Keep autostream FIFO in a dedicated subdirectory to avoid scanning unrelated
  # transient files under /tmp.
  if [[ -f "${INSTALL_DIR}/autostream.ini" ]]; then
    sed -i -E 's|^[[:space:]]*fifo_path[[:space:]]*=.*$|fifo_path = /tmp/autostream-pipes/autostream.fifo|' "${INSTALL_DIR}/autostream.ini"
  fi

  ###########################################
  # Supervisor + helper binaries/scripts
  ###########################################
  info "Installing supervisor and helper scripts"

  # 1) Create /var/lib/autostream (root 0700) for stamps
  mkdir -p "${STAMP_DIR}"

  # 2) Use /usr/local/libexec/autostream for helper scripts
  install_text_linux "${AUTOSTREAM_DIR}/supervisor/autostream_updater" "${LIBEXEC_DIR}/autostream_updater" 0755 root root
  install_text_linux "${AUTOSTREAM_DIR}/supervisor/autostream_admin" "${LIBEXEC_DIR}/autostream_admin" 0755 root root

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
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream_monitor.service" /etc/systemd/system/

  if [[ -n "${SDMON_METHOD}" ]]; then
    install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream_sdcardhealth.service" /etc/systemd/system/
    install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream_sdcardhealth.timer" /etc/systemd/system/
  else
    info "Skipping sdmon systemd units (use --sdmon=<method> to enable)"
  fi

  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream.service" /etc/systemd/system/
  install -m 0644 -o root -g root "${AUTOSTREAM_DIR}/system/systemd/autostream_wifi_watcher.service" /etc/systemd/system/

  systemctl daemon-reload

  if [[ -n "${SDMON_METHOD}" ]]; then
    patch_sdmon_service_method "${SDMON_METHOD}"
    systemctl daemon-reload
    systemctl enable autostream_sdcardhealth.timer
  fi
 
  systemctl enable autostream_monitor.service
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
  # Cloud-init hostname / /etc/hosts control
  ###########################################
  info "Disabling cloud-init /etc/hosts management in user-data"

  USER_DATA="/boot/firmware/user-data"

  if [ -f "$USER_DATA" ]; then
    # If manage_etc_hosts already exists, replace it
    if grep -q '^manage_etc_hosts:' "$USER_DATA"; then
      sed -i 's/^manage_etc_hosts:.*/manage_etc_hosts: false/' "$USER_DATA"
    else
      # Otherwise append it
      printf "\nmanage_etc_hosts: false\n" >> "$USER_DATA"
    fi

    # Preserve hostnames (prevents cloud-init from overwriting /etc/hosts)
    if grep -q '^preserve_hostname:' "$USER_DATA"; then
      sed -i 's/^preserve_hostname:.*/preserve_hostname: true/' "$USER_DATA"
    else
      printf "preserve_hostname: true\n" >> "$USER_DATA"
    fi
  else
    warn "cloud-init user-data not found at $USER_DATA"
  fi

  # Ensure cloud-init re-reads user-data even if it already ran
  if command -v cloud-init >/dev/null 2>&1; then
    info "Resetting cloud-init state to apply updated user-data"
    cloud-init clean --logs || true
  fi

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
  chmod 0755 "${INSTALL_DIR}"

  # 3) Log directory
  chmod 0755 "${APP_LOG_DIR}"

  # 4) Executables / scripts
  # Top-level installer/runtime scripts shipped in INSTALL_DIR
  find "${INSTALL_DIR}" -maxdepth 1 -type f -name "*.sh" -exec chmod 0755 {} + 2>/dev/null || true

  # Nginx CGI scripts should be executable
  chmod 0755 "${INSTALL_DIR}/nginx/cgi"/*.cgi 2>/dev/null || true

  # Offline html should be world-readable
  chmod 0644 "${INSTALL_DIR}/nginx/offline"/*.html 2>/dev/null || true

  # 5) Exceptions that must remain root-owned (restore after the bulk chown)
  # SSID file: root-owned and readable
  if [[ -f "${INSTALL_DIR}/ssid" ]]; then
    chown root:root "${INSTALL_DIR}/ssid"
    chmod 0644 "${INSTALL_DIR}/ssid"
  fi

  # autostream directory owned by autostream
  chown autostream:autostream "${INSTALL_DIR}"

  info "Install script completed."
}

main "$@"
