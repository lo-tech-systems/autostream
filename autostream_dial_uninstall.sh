#!/usr/bin/env bash
# autostream_dial_uninstall.sh — Removes all autostream dial components.
#
# Co-installation (autostream + dial on the same device) is not supported.
# This uninstaller assumes a dial-only device and removes /opt/autostream/.
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

set -euo pipefail

systemctl disable --now \
    autostream_dial \
    autostream_dial_wifi_watcher \
    autostream_dial_dnsmasq \
    autostream_dial_updater.timer \
    autostream_dial_update_recover \
    2>/dev/null || true
systemctl stop autostream_dial_dnsmasq 2>/dev/null || true

rm -f /etc/systemd/system/autostream_dial.service
rm -f /etc/systemd/system/autostream_dial_wifi_watcher.service
rm -f /etc/systemd/system/autostream_dial_dnsmasq.service
rm -f /etc/systemd/system/autostream_dial_updater.service
rm -f /etc/systemd/system/autostream_dial_updater.timer
rm -f /etc/systemd/system/autostream_dial_update_recover.service
systemctl daemon-reload

rm -f /etc/nginx/sites-enabled/autostream-dial
rm -f /etc/nginx/sites-available/autostream-dial
nginx -s reload 2>/dev/null || true

rm -f /etc/avahi/services/autostream-dial.service
rm -f /etc/dnsmasq.d/autostream-dial-setup.conf
rm -f /etc/sudoers.d/autostream_dial
rm -f /etc/logrotate.d/autostream-dial

# Restore system dnsmasq (masked during install)
systemctl unmask dnsmasq.service 2>/dev/null || true

# Shared admin infrastructure — safe to remove on dial-only device
rm -rf /usr/local/libexec/autostream
rm -rf /usr/local/share/autostream

rm -rf /opt/autostream         # dial-only device; no autostream appliance present
rm -rf /etc/autostream
rm -rf /var/lib/autostream

userdel autostream 2>/dev/null || true
echo "autostream dial uninstalled."
