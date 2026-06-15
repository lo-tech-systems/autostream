#!/usr/bin/env bash
#
# autostream_uninstall.sh
#
# Quick-and-dirty uninstaller for autostream on Raspberry Pi OS.
# This removes the main autostream installation and attempts to remove
# OwnTone, but intentionally does not try to reverse every shared system
# change made by the installer.

set -u
set -o pipefail

SCRIPT_NAME="$(basename "$0")"

info()  { echo "[INFO] $*"; }
warn()  { echo "[WARN] $*"; }
error() { echo "[ERROR] $*"; }

require_sudo() {
  if [[ ${EUID} -ne 0 ]]; then
    error "This script must be run as root (e.g. sudo ./${SCRIPT_NAME})."
    exit 1
  fi
}

has_tty() {
  [[ -r /dev/tty && -w /dev/tty ]]
}

prompt_continue() {
  cat <<'EOF'

=============================================================================
AUTOSTREAM UNINSTALLER
=============================================================================
This script uninstalls autostream and OwnTone, but it is intentionally
incomplete. It will leave some fragments and shared system components behind.

It does NOT try to undo every change to shared system files.
Use this only if you understand that some cleanup may still need to be done
manually afterward.
=============================================================================
EOF

  if has_tty; then
    local ans
    read -r -p "Continue with uninstall? (Y/N) " ans < /dev/tty || true
    case "${ans:-N}" in
      Y|y) ;;
      *) error "Aborted by user."; exit 1 ;;
    esac
  else
    error "Interactive confirmation requires a TTY."
    exit 1
  fi
}

stop_and_disable_service() {
  local svc="$1"
  if systemctl list-unit-files "${svc}" >/dev/null 2>&1; then
    info "Stopping ${svc}"
    systemctl stop "${svc}" >/dev/null 2>&1 || warn "Could not stop ${svc}"
    info "Disabling ${svc}"
    systemctl disable "${svc}" >/dev/null 2>&1 || warn "Could not disable ${svc}"
  else
    info "Service ${svc} not present; skipping"
  fi
}

remove_path() {
  local path="$1"
  if [[ -e "${path}" || -L "${path}" ]]; then
    info "Removing ${path}"
    rm -rf "${path}" || warn "Failed to remove ${path}"
  else
    info "Path ${path} not present; skipping"
  fi
}

apt_remove_owntone() {
  if command -v apt-get >/dev/null 2>&1; then
    info "Attempting to remove packaged OwnTone"
    DEBIAN_FRONTEND=noninteractive apt-get remove -y owntone >/dev/null 2>&1 \
      || warn "apt remove owntone failed or owntone was not installed as a package"
  else
    warn "apt-get not found; skipping packaged OwnTone removal"
  fi
}

prompt_reboot() {
  if ! has_tty; then
    info "Please reboot the device when convenient."
    return 0
  fi

  local ans
  echo
  read -r -p "Reboot now? (Y/N) " ans < /dev/tty || true
  case "${ans:-N}" in
    Y|y)
      info "Rebooting..."
      reboot
      ;;
    *)
      info "Reboot skipped. A reboot is recommended."
      ;;
  esac
}

main() {
  require_sudo
  prompt_continue

  info "Stopping services"
  stop_and_disable_service autostream_update_retry.service
  stop_and_disable_service autostream_updater.timer
  stop_and_disable_service autostream_updater.service
  stop_and_disable_service autostream.service
  stop_and_disable_service autostream_monitor.service
  stop_and_disable_service autostream_wifi_watcher.service
  stop_and_disable_service autostream_sdcardhealth.timer
  stop_and_disable_service autostream_sdcardhealth.service
  stop_and_disable_service autostream_dnsmasq.service
  stop_and_disable_service owntone.service
  stop_and_disable_service nginx.service

  info "Removing autostream application files"
  remove_path /opt/autostream
  remove_path /var/log/autostream
  remove_path /var/lib/autostream
  remove_path /usr/local/libexec/autostream

  apt_remove_owntone

  info "Removing possible OwnTone Mini files"
  remove_path /usr/sbin/owntone
  remove_path /etc/systemd/system/owntone.service
  remove_path /etc/systemd/system/owntone.service.d
  remove_path /etc/owntone-settings.json
  remove_path /etc/owntone.conf
  remove_path /etc/apt/sources.list.d/owntone.list
  remove_path /usr/share/keyrings/owntone-archive-keyring.gpg

  info "Removing autostream nginx configuration"
  remove_path /etc/nginx/sites-enabled/autostream-nginx.conf
  remove_path /etc/nginx/sites-available/autostream-nginx.conf
  remove_path /etc/nginx/conf.d/autostream-nginxd.conf

  info "Removing autostream systemd units"
  remove_path /etc/systemd/system/autostream_update_retry.service
  remove_path /etc/systemd/system/autostream_updater.service
  remove_path /etc/systemd/system/autostream_updater.timer
  remove_path /etc/systemd/system/autostream.service
  remove_path /etc/systemd/system/autostream_monitor.service
  remove_path /etc/systemd/system/autostream_wifi_watcher.service
  remove_path /etc/systemd/system/autostream_dnsmasq.service
  remove_path /etc/systemd/system/autostream_sdcardhealth.service
  remove_path /etc/systemd/system/autostream_sdcardhealth.timer

  info "Removing autostream sudoers snippets"
  remove_path /etc/sudoers.d/autostream_updater
  remove_path /etc/sudoers.d/autostream_admin

  info "Removing other autostream-managed files we can identify confidently"
  remove_path /etc/avahi/services/autostream.service
  remove_path /etc/logrotate.d/autostream
  remove_path /etc/dnsmasq.d/autostream-setup.conf
  remove_path /etc/NetworkManager/dispatcher.d/99-wlan-fix
  remove_path /etc/NetworkManager/conf.d/mdns.conf
  remove_path /etc/NetworkManager/conf.d/wifi-powersave.conf

  info "Reloading systemd manager configuration"
  systemctl daemon-reload || warn "systemctl daemon-reload failed"

  info "Uninstall complete. Some fragments may still remain."
  prompt_reboot
}

main "$@"
