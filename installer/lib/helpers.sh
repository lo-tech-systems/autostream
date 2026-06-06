#!/usr/bin/env bash
#
# installer/lib/helpers.sh
#
# Common helpers: logging, TTY, apt, file ops, user/group management, git.
# Sourced by autostream_install.sh; not executed directly.
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

#############################################
# Logging
#############################################
info()  { echo "[INFO] $*"; }
warn()  { echo "[WARN] $*"; }
error() { echo "[ERROR] $*"; }

init_logging() {
  mkdir -p "$(dirname "${LOGFILE}")" || true
  : > "${LOGFILE}"
  chmod 0644 "${LOGFILE}" || true
  exec > >(tee -a "${LOGFILE}") 2>&1
  echo "[INFO] ${SCRIPT_NAME} starting at $(date -Is)"
  echo "[INFO] Running as: $(id -un) (uid=$(id -u)); original user: ${ORIG_USER}; original home: ${ORIG_HOME}"
  echo "[INFO] Log file: ${LOGFILE}"
}

#############################################
# TTY helpers
#############################################
has_tty() {
  [[ -r /dev/tty && -w /dev/tty ]]
}

tty_read() {
  local prompt="$1" __var="$2"
  IFS= read -r -p "${prompt}" "${__var}" < /dev/tty
}

open_log_prompt() {
  local reason="$1"
  warn "${reason}"
  if has_tty; then
    echo
    tty_read "Open the log now? (Y/N) " ans || true
    case "${ans:-N}" in
      Y|y) ${PAGER:-less} "${LOGFILE}" || true ;;
      *)   info "Log not opened. You can view it later: ${LOGFILE}" ;;
    esac
  else
    info "Non-interactive session; log available at: ${LOGFILE}"
  fi
}

#############################################
# Privilege check
#############################################
require_sudo() {
  if [[ ${EUID} -ne 0 ]]; then
    echo "This script must be run as root (e.g., sudo ./${SCRIPT_NAME})."
    exit 1
  fi
}

#############################################
# Sudoers validation
#############################################
validate_sudoers() {
  if ! command -v visudo >/dev/null 2>&1; then
    warn "visudo not found; cannot validate sudoers syntax."
    return 0
  fi
  if ! visudo -cf /etc/sudoers; then
    error "sudoers validation failed for /etc/sudoers"
    exit 1
  fi
  local f
  for f in /etc/sudoers.d/autostream*; do
    [[ -e "$f" ]] || continue
    if ! visudo -cf "$f"; then
      error "sudoers validation failed for ${f}"
      exit 1
    fi
  done
}

#############################################
# Package management
#############################################
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

#############################################
# User and group management
#############################################
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
  local user="$1" group="$2"
  if id -u "${user}" >/dev/null 2>&1; then
    info "User '${user}' already exists."
  else
    info "Creating system user '${user}'"
    useradd --system --no-create-home --shell /usr/sbin/nologin -g "${group}" "${user}"
  fi
}

ensure_user_in_group() {
  local user="$1" group="$2"
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

#############################################
# File installation helpers
#############################################
install_text_linux() {
  # Install a text file and normalize line endings to LF (strip CR).
  # Usage: install_text_linux <src> <dest> <mode> [owner] [group]
  local src="$1" dest="$2" mode="$3" owner="${4:-root}" group="${5:-root}"

  if [[ ! -f "$src" ]]; then
    error "Missing required file: $src"
    return 1
  fi

  install -m "$mode" -o "$owner" -g "$group" "$src" "$dest"
  sed -i 's/\r$//' "$dest" || true
}


#############################################
# Git helpers
#############################################

# Clone a repo to dest_dir (fresh).  Removes dest_dir first if it exists but
# is not a git repo, so the caller always gets a clean clone.
git_clone() {
  local repo_url="$1" dest_dir="$2"
  info "Cloning ${repo_url} into ${dest_dir}"
  rm -rf "${dest_dir}" || true
  git clone "${repo_url}" "${dest_dir}"
}

# Update an existing git repo to origin/main via fetch + reset.
# Requires dest_dir to already be a git repo; errors otherwise.
git_update() {
  local dest_dir="$1"
  if [[ ! -d "${dest_dir}/.git" ]]; then
    error "git_update: '${dest_dir}' is not a git repository"
    return 1
  fi
  info "Updating git repository at ${dest_dir}"
  git -C "${dest_dir}" fetch --all --prune
  git -C "${dest_dir}" reset --hard origin/main
}

# Clone or update: used during install when --fetch-autostream is set.
# On update runs, prefer git_update directly so the mode is explicit.
git_clone_or_update() {
  local repo_url="$1" dest_dir="$2"
  if [[ -d "${dest_dir}/.git" ]]; then
    git_update "${dest_dir}"
  else
    git_clone "${repo_url}" "${dest_dir}"
  fi
}
