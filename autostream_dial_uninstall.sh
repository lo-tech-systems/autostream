#!/usr/bin/env bash
# autostream_dial_uninstall.sh — Removes all autostream dial components.
#
# Usage:
#   sudo ./autostream_dial_uninstall.sh          # asks for confirmation
#   sudo ./autostream_dial_uninstall.sh --yes    # no prompt (scripted use)
#
# Must run as root, and only on a dial install: it refuses an appliance or a
# device with no dial on it. Without --yes it needs a terminal to ask on.
#
# Co-installation (autostream + dial on the same device) is not supported.
# This uninstaller assumes a dial-only device and removes /opt/autostream/.
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/installer/dial/helpers.sh"
# The Wi-Fi handback is the appliance uninstaller's own function; it reports
# through info and warn.
info() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*"; }
# shellcheck source=installer/lib/wifi_restore.sh
source "$SCRIPT_DIR/installer/lib/wifi_restore.sh"

ASSUME_YES=false
for _arg in "$@"; do
    case "${_arg}" in
        --yes|-y) ASSUME_YES=true ;;
        *) echo "Usage: $(basename "$0") [--yes]" >&2; exit 2 ;;
    esac
done
require_root_user "$(basename "$0")"
require_dial_install
confirm_dial_uninstall "${ASSUME_YES}"

# From here the uninstall must reach the end. The checks above are the only
# reason to stop; once units and files start to go, stopping half way leaves a
# dial that the checks would no longer let anyone finish removing. A step that
# cannot be done is reported and counted, and the rest carries on.
failed=0
best_effort() {
    "$@" || {
        warn "Could not complete: $*"
        failed=$((failed + 1))
    }
}

# Remove a service account. The account may be missing already (nothing to do)
# or still in use by a running process (it stays, and the owner is told).
remove_account() {
    local name="$1" rc=0
    userdel "${name}" 2>/dev/null || rc=$?
    case "${rc}" in
        0|6) ;;
        *)
            warn "Could not remove the ${name} account (userdel exit ${rc}); a process may still be running as it. Run 'userdel ${name}' once it has stopped."
            failed=$((failed + 1))
            ;;
    esac
}

# One unit at a time, so that a unit that is not installed cannot keep the
# others in the list from being stopped.
for unit in \
    autostream_dial \
    autostream_dial_wifi_watcher \
    autostream_dial_dnsmasq \
    autostream_dial_updater.timer \
    autostream_dial_update_recover \
    autostream_storage_guard.timer \
    autostream_sdcardhealth.timer \
    autostream_sdcardhealth_boot; do
    systemctl disable --now "${unit}" 2>/dev/null || true
done
systemctl stop autostream_dial_dnsmasq 2>/dev/null || true
# HD dial only; each step does nothing on an SPI dial.
systemctl disable --now autostream_dial_kiosk 2>/dev/null || true

# The Wi-Fi watcher, now stopped, keeps every client profile on autoconnect
# off; give them back to NetworkManager before anything is removed so a
# Wi-Fi-only dial rejoins its network after the next boot.
restore_wifi_profiles

best_effort rm -f /etc/systemd/system/autostream_dial.service
best_effort rm -f /etc/systemd/system/autostream_dial_wifi_watcher.service
best_effort rm -f /etc/systemd/system/autostream_dial_dnsmasq.service
best_effort rm -f /etc/systemd/system/autostream_dial_updater.service
best_effort rm -f /etc/systemd/system/autostream_dial_updater.timer
best_effort rm -f /etc/systemd/system/autostream_dial_update_recover.service
best_effort rm -f /etc/systemd/system/autostream_storage_guard.service
best_effort rm -f /etc/systemd/system/autostream_storage_guard.timer
best_effort rm -f /etc/systemd/system/autostream_sdcardhealth.service
best_effort rm -f /etc/systemd/system/autostream_sdcardhealth.timer
best_effort rm -f /etc/systemd/system/autostream_sdcardhealth_boot.service
best_effort rm -f /etc/systemd/system/autostream_dial_kiosk.service

# Take back the boot splash while its state file (under /var/lib/autostream,
# removed below) still says what was added. This also removes the splash's
# systemd drop-in, so the reload that follows covers it.
best_effort revert_plymouth
best_effort systemctl daemon-reload

best_effort rm -f /etc/nginx/sites-enabled/autostream-dial
best_effort rm -f /etc/nginx/sites-available/autostream-dial
nginx -s reload 2>/dev/null || true

best_effort rm -f /etc/avahi/services/autostream-dial.service
best_effort rm -f /etc/dnsmasq.d/autostream-dial-setup.conf
best_effort rm -f /etc/sudoers.d/autostream_dial
best_effort rm -f /etc/logrotate.d/autostream-dial
best_effort rm -f /etc/udev/rules.d/99-autostream-backlight.rules
best_effort rm -f /etc/modules-load.d/autostream-dial-i2c.conf
udevadm control --reload 2>/dev/null || true

# Restore system dnsmasq (masked during install)
systemctl unmask dnsmasq.service 2>/dev/null || true

best_effort rm -f /etc/systemd/journald.conf.d/99-autostream-storage.conf
best_effort rm -f /etc/systemd/coredump.conf.d/99-autostream-coredump.conf
best_effort rm -f /etc/rpi/swap.conf.d/99-autostream-swap.conf
systemctl restart systemd-journald 2>/dev/null || true

# Wi-Fi power saving and the power key, as the appliance uninstaller takes them
# back. The swappiness setting, the masked zram writeback timer and the removed
# modemmanager and udisks2 packages are left as they are, also as there.
best_effort rm -f /etc/NetworkManager/dispatcher.d/99-wlan-fix
best_effort rm -f /etc/NetworkManager/conf.d/wifi-powersave.conf
best_effort rm -f /etc/systemd/logind.conf.d/90-autostream-ignore-power-key.conf
# Signalled, not restarted: a restart would drop the login session this runs in.
systemctl kill --kill-whom=main --signal=HUP systemd-logind.service 2>/dev/null || true
best_effort rm -f /usr/local/sbin/sdmon
best_effort rm -f /usr/local/bin/autostream-dial-control

# Shared admin infrastructure — safe to remove on dial-only device
best_effort rm -rf /usr/local/libexec/autostream
best_effort rm -rf /usr/local/share/autostream

best_effort rm -rf /opt/autostream         # dial-only device; no autostream appliance present
best_effort rm -f /etc/autostream-network.json
# A dial that has been factory reset keeps its identity salt through an
# uninstall. Removing it would put the dial back on the identity it had before
# the reset, and so back on every appliance that still lists that identity.
# The salt is in /etc/autostream, which only root can write, so everything else
# in that directory is removed and the directory stays. Each entry is removed on
# its own, so one that cannot be removed does not keep the others.
dial_etc="$(_fs_root)/etc/autostream"
if [[ -f "${dial_etc}/dial-id-salt" && ! -L "${dial_etc}/dial-id-salt" ]]; then
    best_effort find "${dial_etc}" -mindepth 1 -maxdepth 1 ! -name dial-id-salt \
        -exec rm -rf -- {} +
    salt_kept=true
else
    best_effort rm -rf /etc/autostream
    salt_kept=false
fi
best_effort rm -rf /var/lib/autostream
best_effort rm -rf /var/lib/autostream-update
rm -f  /run/autostream/autostream-dial-setup.conf 2>/dev/null || true

remove_account autostream
remove_account autostream-kiosk
best_effort rm -rf /var/lib/autostream-kiosk
if $salt_kept; then
    echo "Kept the dial identity salt in /etc/autostream so a reinstall does not"
    echo "give this dial back the identity it had before its factory reset."
fi
if (( failed > 0 )); then
    warn "${failed} step(s) could not be completed (see the warnings above); the rest of the dial has been removed."
    exit 1
fi
echo "autostream dial uninstalled."
