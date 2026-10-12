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

# Bluetooth input subsystem removal (installer/lib/bluetooth.sh). Sourced
# from the checkout the uninstaller is run from -- if this is a standalone
# copy without that library, removal just falls back to leaving the
# Bluetooth-specific files/units in place (they are also covered
# individually below where identifiable). The subsystem is always present
# (installed unconditionally, disabled), so removal is always attempted.
INSTALLER_LIB_DIR="$(cd "$(dirname "$0")/installer/lib" 2>/dev/null && pwd || true)"
if [[ -n "${INSTALLER_LIB_DIR}" && -f "${INSTALLER_LIB_DIR}/hardware.sh" && -f "${INSTALLER_LIB_DIR}/bluetooth.sh" ]]; then
  # shellcheck source=installer/lib/hardware.sh
  source "${INSTALLER_LIB_DIR}/hardware.sh"
  # shellcheck source=installer/lib/bluetooth.sh
  source "${INSTALLER_LIB_DIR}/bluetooth.sh"
fi

# apt_remove_guarded (installer/lib/apt.sh) removes a package only when apt
# says nothing else would go with it. Without the library nothing is removed.
if [[ -n "${INSTALLER_LIB_DIR}" && -f "${INSTALLER_LIB_DIR}/apt.sh" ]]; then
  # shellcheck source=installer/lib/apt.sh
  source "${INSTALLER_LIB_DIR}/apt.sh"
else
  apt_remove_guarded() {
    warn "installer/lib/apt.sh is unavailable; leaving $* installed."
    return 1
  }
fi

# restore_wifi_profiles (installer/lib/wifi_restore.sh) is shared with the dial
# uninstaller. Without the library the profiles stay as the wifi watcher left
# them, which is said plainly rather than skipped silently.
if [[ -n "${INSTALLER_LIB_DIR}" && -f "${INSTALLER_LIB_DIR}/wifi_restore.sh" ]]; then
  # shellcheck source=installer/lib/wifi_restore.sh
  source "${INSTALLER_LIB_DIR}/wifi_restore.sh"
else
  restore_wifi_profiles() {
    warn "installer/lib/wifi_restore.sh is unavailable; Wi-Fi profiles keep autoconnect disabled."
    warn "Re-enable each with: nmcli connection modify <name> connection.autoconnect yes"
  }
fi

# remove_bluetooth_if_enabled: call remove_bluetooth_stack (disable/remove
# the unit, module config, bluez fragment). Apt packages are kept, matching
# this uninstaller's existing light-touch stance. Must run before
# /var/lib/autostream is removed below.
remove_bluetooth_if_enabled() {
  if ! command -v remove_bluetooth_stack >/dev/null 2>&1; then
    warn "installer/lib/bluetooth.sh is unavailable; the Bluetooth unit/module"
    warn "config/bluez fragment will need to be removed manually."
    return 0
  fi
  info "Removing Bluetooth input subsystem"
  remove_bluetooth_stack
}

# revert_low_power_if_used: take back the low power mode settings (maxcpus=2,
# arm_freq=700, arm_boost=0, force_turbo=0) only if the install state records
# that the installer's --low-power switch was used; a device that never had the
# switch keeps whatever its boot files say. Must run before /var/lib/autostream
# is removed below, because that is where the record lives.
revert_low_power_if_used() {
  local state="${INSTALL_STATE_FILE:-/var/lib/autostream/install-state.env}" saved
  # The file is in the service account's directory: read it without following a link.
  [[ -f "${state}" && ! -L "${state}" ]] || return 0
  saved="$(dd if="${state}" iflag=nofollow,nonblock bs=65536 count=1 status=none 2>/dev/null || true)"
  grep -qE '^LOW_POWER="?1"?[[:space:]]*$' <<< "${saved}" || return 0
  if ! command -v remove_low_power_settings >/dev/null 2>&1; then
    warn "installer/lib/hardware.sh is unavailable; remove maxcpus=2 from cmdline.txt and"
    warn "arm_freq=700, arm_boost=0 and force_turbo=0 from config.txt by hand."
    return 0
  fi
  info "Removing low power mode settings"
  remove_low_power_settings
  info "The previous CPU limits return at the next reboot."
}

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
    apt_remove_guarded remove owntone >/dev/null 2>&1 \
      || warn "apt remove owntone failed, was refused, or owntone was not installed as a package"
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
  stop_and_disable_service autostream_storage_guard.timer
  stop_and_disable_service autostream_storage_guard.service
  stop_and_disable_service autostream_log_policy.timer
  stop_and_disable_service autostream_log_policy.service
  stop_and_disable_service autostream_sdcardhealth.timer
  stop_and_disable_service autostream_sdcardhealth.service
  stop_and_disable_service autostream_sdcardhealth_boot.service
  stop_and_disable_service autostream_dnsmasq.service
  stop_and_disable_service autostream_bluetooth.service
  stop_and_disable_service owntone.service
  stop_and_disable_service nginx.service

  restore_wifi_profiles
  revert_low_power_if_used
  remove_bluetooth_if_enabled

  info "Removing autostream application files"
  remove_path /opt/autostream
  remove_path /etc/autostream
  remove_path /var/log/autostream
  remove_path /var/lib/autostream
  remove_path /var/lib/autostream-update
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
  remove_path /etc/nginx/conf.d/99-autostream-access-log.conf

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
  remove_path /etc/systemd/system/autostream_sdcardhealth_boot.service
  remove_path /etc/systemd/system/autostream_storage_guard.service
  remove_path /etc/systemd/system/autostream_storage_guard.timer
  remove_path /etc/systemd/system/autostream_log_policy.service
  remove_path /etc/systemd/system/autostream_log_policy.timer
  remove_path /etc/systemd/system/autostream_bluetooth.service

  info "Removing autostream sudoers snippets"
  remove_path /etc/sudoers.d/autostream_updater
  remove_path /etc/sudoers.d/autostream_admin

  info "Removing other autostream-managed files we can identify confidently"
  remove_path /usr/local/libexec/autostream/autostream_sdcardhealth
  remove_path /var/lib/autostream/sdcardhealth-status.json
  remove_path /var/lib/autostream/sdcardhealth.json
  remove_path /var/lib/autostream/sdcardhealth.inflight
  remove_path /usr/local/sbin/sdmon
  remove_path /usr/lib/tmpfiles.d/autostream.conf
  remove_path /run/autostream-pipes
  remove_path /etc/avahi/services/autostream.service
  remove_path /etc/logrotate.d/autostream
  remove_path /etc/dnsmasq.d/autostream-setup.conf
  remove_path /etc/autostream-network.json
  remove_path /boot/firmware/pin.txt
  remove_path /boot/pin.txt
  remove_path /usr/local/share/autostream/dnsmasq/autostream-setup.conf
  remove_path /run/autostream/autostream-setup.conf
  remove_path /etc/NetworkManager/dispatcher.d/99-wlan-fix
  remove_path /etc/NetworkManager/conf.d/mdns.conf
  remove_path /etc/NetworkManager/conf.d/wifi-powersave.conf
  remove_path /etc/systemd/journald.conf.d/99-autostream-storage.conf
  remove_path /etc/systemd/journald.conf.d/zz-autostream-diag-persistent.conf
  remove_path /var/lib/autostream/journald-persistent.applied
  systemctl restart systemd-journald || warn "systemctl restart systemd-journald failed"
  remove_path /etc/systemd/coredump.conf.d/99-autostream-coredump.conf
  remove_path /etc/rpi/swap.conf.d/99-autostream-swap.conf
  remove_path /etc/systemd/logind.conf.d/90-autostream-ignore-power-key.conf
  systemctl restart systemd-logind || warn "systemctl restart systemd-logind failed"

  # Bluetooth input subsystem leftovers, as a fallback in case
  # remove_bluetooth_if_enabled (above) could not source installer/lib/bluetooth.sh.
  # Idempotent no-ops if remove_bluetooth_stack already removed them.
  remove_path /etc/modules-load.d/autostream-bluetooth.conf
  remove_path /etc/modprobe.d/autostream-bluetooth.conf
  remove_path /etc/bluetooth/main.conf.d/autostream.conf

  info "Reloading systemd manager configuration"
  systemctl daemon-reload || warn "systemctl daemon-reload failed"

  info "Uninstall complete. Some fragments may still remain."
  prompt_reboot
}

main "$@"
