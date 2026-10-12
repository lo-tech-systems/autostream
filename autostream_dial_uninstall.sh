#!/usr/bin/env bash
# autostream_dial_uninstall.sh — Removes all autostream dial components.
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

systemctl disable --now \
    autostream_dial \
    autostream_dial_wifi_watcher \
    autostream_dial_dnsmasq \
    autostream_dial_updater.timer \
    autostream_dial_update_recover \
    autostream_storage_guard.timer \
    autostream_sdcardhealth.timer \
    autostream_sdcardhealth_boot \
    2>/dev/null || true
systemctl stop autostream_dial_dnsmasq 2>/dev/null || true
# HD dial only; each step does nothing on an SPI dial.
systemctl disable --now autostream_dial_kiosk 2>/dev/null || true

# The Wi-Fi watcher, now stopped, keeps every client profile on autoconnect
# off; give them back to NetworkManager before anything is removed so a
# Wi-Fi-only dial rejoins its network after the next boot.
restore_wifi_profiles

rm -f /etc/systemd/system/autostream_dial.service
rm -f /etc/systemd/system/autostream_dial_wifi_watcher.service
rm -f /etc/systemd/system/autostream_dial_dnsmasq.service
rm -f /etc/systemd/system/autostream_dial_updater.service
rm -f /etc/systemd/system/autostream_dial_updater.timer
rm -f /etc/systemd/system/autostream_dial_update_recover.service
rm -f /etc/systemd/system/autostream_storage_guard.service
rm -f /etc/systemd/system/autostream_storage_guard.timer
rm -f /etc/systemd/system/autostream_sdcardhealth.service
rm -f /etc/systemd/system/autostream_sdcardhealth.timer
rm -f /etc/systemd/system/autostream_sdcardhealth_boot.service
rm -f /etc/systemd/system/autostream_dial_kiosk.service

# Take back the boot splash while its state file (under /var/lib/autostream,
# removed below) still says what was added. This also removes the splash's
# systemd drop-in, so the reload that follows covers it.
revert_plymouth
systemctl daemon-reload

rm -f /etc/nginx/sites-enabled/autostream-dial
rm -f /etc/nginx/sites-available/autostream-dial
nginx -s reload 2>/dev/null || true

rm -f /etc/avahi/services/autostream-dial.service
rm -f /etc/dnsmasq.d/autostream-dial-setup.conf
rm -f /etc/sudoers.d/autostream_dial
rm -f /etc/logrotate.d/autostream-dial
rm -f /etc/udev/rules.d/99-autostream-backlight.rules
rm -f /etc/modules-load.d/autostream-dial-i2c.conf
udevadm control --reload 2>/dev/null || true

# Restore system dnsmasq (masked during install)
systemctl unmask dnsmasq.service 2>/dev/null || true

rm -f /etc/systemd/journald.conf.d/99-autostream-storage.conf
rm -f /etc/systemd/coredump.conf.d/99-autostream-coredump.conf
systemctl restart systemd-journald 2>/dev/null || true
rm -f /usr/local/sbin/sdmon
rm -f /usr/local/bin/autostream-dial-control

# Shared admin infrastructure — safe to remove on dial-only device
rm -rf /usr/local/libexec/autostream
rm -rf /usr/local/share/autostream

rm -rf /opt/autostream         # dial-only device; no autostream appliance present
rm -rf /etc/autostream
rm -f  /etc/autostream-network.json
rm -rf /var/lib/autostream
rm -f  /run/autostream/autostream-dial-setup.conf 2>/dev/null || true

userdel autostream 2>/dev/null || true
userdel autostream-kiosk 2>/dev/null || true
rm -rf /var/lib/autostream-kiosk
echo "autostream dial uninstalled."
