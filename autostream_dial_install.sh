#!/usr/bin/env bash
# autostream_dial_install.sh — Installer for autostream dial.
#
# Usage:
#   ./autostream_dial_install.sh           # fresh install
#   ./autostream_dial_install.sh --update  # in-place update (run by autostream_dial_updater)
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY="$SCRIPT_DIR"
source "$DEPLOY/installer/dial/helpers.sh"

UPDATE=false
[[ "${1:-}" == "--update" ]] && UPDATE=true

# AUTOSTREAM_RELEASE_TAG is injected by systemd-run --setenv on --update runs.
# On fresh install it is typically unset; detect_install_version() falls back to "unknown".
AUTOSTREAM_RELEASE_TAG="$(detect_install_version)"

# ---- Logging ----------------------------------------------------------------
# On --update: log dir already exists (created on initial install); redirect immediately.
# On fresh unattended install: log dir is created by create_dirs below; start in HOME,
# then redirect to persistent path once create_dirs + init_service_dirs have run.
if $UPDATE; then
    LOGFILE=/var/log/autostream/dial-install.log
else
    LOGFILE="${HOME:-/root}/autostream_dial_install.log"
fi
exec > >(tee -a "$LOGFILE") 2>&1
echo "=== autostream dial install $(date -Iseconds) ==="

# ---- Flock: serialise concurrent installer invocations ----------------------
# When launched by autostream_dial_updater the wrapper sets AUTOSTREAM_DIAL_LOCKED=1
# and 'flock --exclusive' holds update.lock for this process's entire lifetime.
# Opening the same file here and blocking on it would deadlock.
# Use the explicit env marker — not $UPDATE — so a direct '--update' invocation
# (e.g. manual recovery) still acquires its own blocking flock and is safe.
if [[ "${AUTOSTREAM_DIAL_LOCKED:-0}" != "1" ]]; then
    LOCK_FD=9
    eval "exec ${LOCK_FD}>/run/autostream-dial-update.lock" 2>/dev/null || \
        exec 9>/tmp/autostream-dial-update.lock
    flock ${LOCK_FD}
fi
# LOCK_PATH in autostream_dial_updater must match /run/autostream-dial-update.lock exactly.

# ---- Exit trap ---------------------------------------------------------------
# The UPDATING_FLAG (/tmp/autostream-dial-updating) was created by the updater
# immediately before scheduling this installer. Remove it on every exit so that
# nginx stops redirecting requests to /offline/updating after this process ends.
UPDATING_FLAG=/tmp/autostream-dial-updating
_install_success=false
trap '_exit_rc=$?
    rm -f "$UPDATING_FLAG"
    if [[ "$_install_success" != true ]] && $UPDATE; then
        write_update_result "failure" "Installer exited unexpectedly at line $LINENO" || true
    fi
    exit $_exit_rc' EXIT

# ---- OS version check (fresh install and update) ----------------------------
require_trixie_os

# ---- Fresh-install only steps -----------------------------------------------
if ! $UPDATE; then
    show_info_and_prompt
    check_pi_model
    install_os_packages
    create_dirs
    create_service_user       # user must exist before init_service_dirs
    init_service_dirs         # chown settings/; create initial log files
    add_gpio_group
    disable_system_dnsmasq
    network_state_phase       # record existing WiFi so wifi_watcher can reconnect
    # Redirect to persistent log now that /var/log/autostream/ and log files exist.
    if [[ ! -t 1 ]]; then
        LOGFILE=/var/log/autostream/dial-install.log
        exec > >(tee -a "$LOGFILE") 2>&1
    fi
fi

# ---- Deploy Python files ----------------------------------------------------
install -m 0644 "$DEPLOY/core/autostream_rpi.py"      /opt/autostream/autostream_rpi.py
install -m 0644 "$DEPLOY/core/autostream_sysutils.py" /opt/autostream/autostream_sysutils.py
install -m 0644 "$DEPLOY/core/autostream_mdns.py"     /opt/autostream/autostream_mdns.py
# Dedicated Wi-Fi recovery helper — deployed alongside the watcher (root:root
# 0644) so the recovery executable's import resolves on every install/update.
install -m 0644 -o root -g root "$DEPLOY/core/autostream_wifi_network.py" \
    /opt/autostream/autostream_wifi_network.py
cp -a "$DEPLOY/dial/."     /opt/autostream/
install -m 0644 "$DEPLOY/dial/autostream_dial_control.py" \
    /opt/autostream/autostream_dial_control.py
install -m 0755 "$DEPLOY/dial/autostream-dial-control" \
    /usr/local/bin/autostream-dial-control
install -m 0755 "$DEPLOY/platform/wifi_watcher" /opt/autostream/autostream_wifi_watcher

deploy_admin
deploy_avahi_template
setup_venv   # pip install gpiozero into /opt/autostream/venv

# ---- Recovery infrastructure (fresh install and --update) -------------------
# install_recovery_packages() installs fcgiwrap+zip and grants www-data adm
# group membership so the CGI log-download endpoint can read dial logs.
# Called unconditionally so --update runs gain these dependencies without
# requiring a re-image.
install_recovery_packages

# ---- Deploy images ----------------------------------------------------------
mkdir -p /opt/autostream/images
install -m 0644 "$DEPLOY/images/autostream-dial-badge.png" /opt/autostream/images/
install -m 0644 "$DEPLOY/images/favicon.ico"               /opt/autostream/images/
install -m 0644 "$DEPLOY/images/favicon-16x16.png"         /opt/autostream/images/
install -m 0644 "$DEPLOY/images/favicon-32x32.png"         /opt/autostream/images/

# ---- Deploy offline recovery pages ------------------------------------------
mkdir -p /opt/autostream/nginx/offline
install -m 0644 "$DEPLOY"/nginx/offline/*.html /opt/autostream/nginx/offline/

# ---- Deploy shared CGI scripts ----------------------------------------------
mkdir -p /opt/autostream/nginx/cgi
install -m 0755 "$DEPLOY/nginx/cgi/reboot.cgi"        /opt/autostream/nginx/cgi/
install -m 0755 "$DEPLOY/nginx/cgi/factory-reset.cgi" /opt/autostream/nginx/cgi/
install -m 0755 "$DEPLOY/nginx/cgi/update-status.cgi" /opt/autostream/nginx/cgi/
install -m 0755 "$DEPLOY/dial/cgi/download-logs.cgi"  /opt/autostream/nginx/cgi/

# Enable and restart fcgiwrap so the worker picks up the new adm group membership.
systemctl enable fcgiwrap
systemctl restart fcgiwrap

# ---- Identity and config handling -------------------------------------------
if ! $UPDATE; then
    DIAL_UUID=$(generate_dial_id)
    if [[ -z "$DIAL_UUID" ]]; then
        echo "ERROR: Unable to derive Dial identity (no CPU serial and fallback creation failed)." >&2
        exit 1
    fi
    write_dial_hw_config "$DIAL_UUID"
    write_dial_settings
else
    # On --update, ensure user, dirs, and permissions are current-layout before
    # reading the UUID (handles first-time install of a fresh release).
    create_service_user
    create_dirs
    init_service_dirs

    # Parse without source — never execute env file contents.
    DIAL_UUID=$(grep '^DIAL_UUID=' \
        /var/lib/autostream/install-state.env 2>/dev/null | cut -d= -f2-)
    if [[ -z "$DIAL_UUID" ]]; then
        echo "ERROR: DIAL_UUID not found in /var/lib/autostream/install-state.env" >&2
        exit 1
    fi
fi

# ---- systemd ----------------------------------------------------------------
install -m 0644 "$DEPLOY"/system/systemd/autostream_dial.service                  /etc/systemd/system/
install -m 0644 "$DEPLOY"/system/systemd/autostream_dial_wifi_watcher.service     /etc/systemd/system/
install -m 0644 "$DEPLOY"/system/systemd/autostream_dial_dnsmasq.service          /etc/systemd/system/
install -m 0644 "$DEPLOY"/system/systemd/autostream_dial_updater.service          /etc/systemd/system/
install -m 0644 "$DEPLOY"/system/systemd/autostream_dial_updater.timer            /etc/systemd/system/
install -m 0644 "$DEPLOY"/system/systemd/autostream_dial_update_recover.service   /etc/systemd/system/
systemctl daemon-reload
systemctl enable autostream_dial autostream_dial_wifi_watcher autostream_dial_update_recover
# autostream_dial_updater.timer is not enabled by default; users opt in via the Setup page.

# ---- nginx ------------------------------------------------------------------
rm -f /etc/nginx/sites-enabled/default
install -m 0644 "$DEPLOY/system/nginx/autostream-dial-nginx.conf" \
    /etc/nginx/sites-available/autostream-dial
ln -sf /etc/nginx/sites-available/autostream-dial /etc/nginx/sites-enabled/autostream-dial
nginx -t && nginx -s reload   # validate config before applying; abort on error

# ---- avahi service file -----------------------------------------------------
# Read name from settings JSON on update; blank string on fresh install.
DIAL_NAME=""
if $UPDATE; then
    DIAL_NAME=$(python3 -c "
import json, sys
try:
    d = json.load(open('/var/lib/autostream/dial-settings.json'))
    print(d.get('name', ''))
except Exception:
    pass
" 2>/dev/null || true)
fi
# Use admin verb — handles XML escaping, avoids unsafe sed substitution.
# Blank name falls back to UUID so the avahi TXT record is never empty.
/usr/local/libexec/autostream/autostream_admin \
    update-dial-service "${AUTOSTREAM_RELEASE_TAG}" "${DIAL_UUID}" "${DIAL_NAME:-${DIAL_UUID}}"

# ---- dnsmasq, sudoers, logrotate --------------------------------------------
install -m 0644 "$DEPLOY/system/dnsmasq/autostream-dial-setup.conf" \
    /etc/dnsmasq.d/autostream-dial-setup.conf
install -m 0440 "$DEPLOY/system/sudoers/autostream_dial" \
    /etc/sudoers.d/autostream_dial
install -m 0644 "$DEPLOY/system/logrotate/autostream-dial" \
    /etc/logrotate.d/autostream-dial

write_install_state "$DIAL_UUID"

# ---- Initialize update-result.env on fresh install only ---------------------
# On --update the file already contains STATUS=in_progress written by the updater;
# do not overwrite.
if ! $UPDATE; then
    printf 'STATUS=\nMESSAGE=\n' > /var/lib/autostream/update-result.env
    chown root:autostream /var/lib/autostream/update-result.env
    chmod 0644 /var/lib/autostream/update-result.env
fi

# ---- Start / restart services -----------------------------------------------
systemctl restart autostream_dial autostream_dial_wifi_watcher

# write_update_result only on --update: fresh install leaves status=idle (no update occurred).
# Set _install_success AFTER the write — if write_update_result fails, the EXIT trap fires
# and writes "failure", which is correct.
# PERCENT_COMPLETE=100 signals the updating.html page to start its restart-and-redirect flow.
$UPDATE && write_update_result "success" "Installed ${AUTOSTREAM_RELEASE_TAG}" 100
_install_success=true   # disarm EXIT trap only after status is safely written

echo "autostream dial installation complete."
if ! $UPDATE; then
    if [[ -s /opt/autostream/ssid ]]; then
        echo "WiFi connection recorded. After reboot, continue setup from an autostream appliance."
    else
        echo "Connect to 'autostream-dial_SETUP' WiFi to complete setup."
    fi
    if has_tty; then
        echo ""
        tty_read "Reboot now to complete setup? (Y/N) " _rb || true
        case "${_rb:-N}" in
            Y|y) echo "Rebooting..."; reboot ;;
            *) echo "Reboot skipped. Please reboot the device when convenient." ;;
        esac
    else
        echo "Non-interactive session; please reboot the device when convenient."
    fi
fi
