#!/usr/bin/env bash
# autostream_dial_install.sh — Installer for autostream dial.
#
# Usage:
#   ./autostream_dial_install.sh           # fresh install
#   ./autostream_dial_install.sh --update  # in-place update (run by autostream_dial_updater)
#   ./autostream_dial_install.sh --hd      # install of an HD (kiosk browser) dial
#
# Run over a dial that is already installed, a plain or --hd run is a reinstall
# that keeps the dial's name, PIN and settings and its display profile (no
# --update needed to repair a dial): an SPI dial stays SPI and an HD dial stays
# HD. --hd over an SPI dial converts it to HD, keeping its other settings. To
# turn an HD dial back into an SPI one, change its screen type from the
# appliance's Setup page rather than reinstalling.
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY="$SCRIPT_DIR"
source "$DEPLOY/installer/dial/helpers.sh"

UPDATE=false
HD=false
REINSTALL=false
for _arg in "$@"; do
    case "${_arg}" in
        --update) UPDATE=true ;;
        --hd) HD=true ;;
    esac
done
# An HD dial is chosen at install time; an update reads the profile the dial
# already runs (detect_hd_install) and ignores the flag.
if $UPDATE; then HD=false; fi

# AUTOSTREAM_RELEASE_TAG is injected by systemd-run --setenv on --update runs.
# On fresh install it is typically unset; detect_install_version() falls back to "unknown".
AUTOSTREAM_RELEASE_TAG="$(detect_install_version)"
# The release installed before this run, read before anything rewrites
# install-state.env.
PREVIOUS_RELEASE_TAG="$(_installed_release_tag)"

# ---- Logging ----------------------------------------------------------------
# The log is appended to, never replaced, so the output of earlier runs and of
# an update's boot-time retries stays in it; logrotate keeps it bounded.
# On --update the log directory already exists (created by the initial install)
# and the output goes to the persistent log alone. A fresh install also writes
# to a log in the user's home, where it is easy to find; the persistent copy is
# prepared first so the whole run lands in /var/log/autostream/ and so in the
# support log bundle.
INSTALL_LOG="${DIAL_INSTALL_LOGFILE:-/var/log/autostream/dial-install.log}"
if $UPDATE; then
    LOGFILES=("$INSTALL_LOG")
else
    LOGFILES=("${HOME:-/root}/autostream_dial_install.log")
    if prepare_install_log "$INSTALL_LOG"; then
        LOGFILES+=("$INSTALL_LOG")
    fi
fi
exec > >(tee -a "${LOGFILES[@]}") 2>&1
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
# An --update that stops before the staged hand-off is written discards what it
# staged, restores the files it owns outside the code tree and reports the
# failed phase (abort_update); the running software was never touched, and no
# reboot follows. Once the hand-off exists the boot step owns the outcome.
UPDATING_FLAG=/tmp/autostream-dial-updating
_install_success=false
trap '_exit_rc=$?
    rm -f "$UPDATING_FLAG"
    if [[ "$_install_success" != true ]] && $UPDATE; then
        abort_update || true
    fi
    exit $_exit_rc' EXIT

# ---- OS version check (fresh install and update) ----------------------------
require_trixie_os

# ---- Prepare (update only; a fresh install does its own setup below) --------
# User, directories and permissions are brought to the current layout first,
# so every later step finds what it expects (handles first-time install of a
# fresh release).
phase prepare 5 "Preparing..."
if $UPDATE; then
    create_service_user
    create_dirs
    init_service_dirs
    detect_hd_install
fi

# ---- Fresh-install only steps -----------------------------------------------
if ! $UPDATE; then
    # Over an existing install the settings and display profile are kept (the
    # writers below leave them in place) and a plain run keeps an HD dial HD.
    detect_existing_dial_install
    if $REINSTALL; then detect_hd_install; fi
    show_info_and_prompt
    check_pi_model
    # An --update does both of these in system_upgrade; a fresh install does them
    # here, ahead of its first apt command.
    recover_interrupted_packages
    refresh_package_lists
    install_os_packages
    create_dirs
    create_service_user       # user must exist before init_service_dirs
    init_service_dirs         # chown settings/; create initial log files
    add_gpio_group
    disable_system_dnsmasq
    network_state_phase       # record existing WiFi so wifi_watcher can reconnect
fi

# ---- Packages (fresh install and --update) ----------------------------------
# --update upgrades the installed system packages first, as the appliance
# installer does; the per-feature installs follow on both paths.
# install_recovery_packages() installs fcgiwrap+zip and grants www-data adm
# group membership so the CGI log-download endpoint can read dial logs.
# Called unconditionally so --update runs gain these dependencies without
# requiring a re-image. The same holds for the image, display-hardware and
# sdmon installs; the venv build packages (Python.h + gcc for sdist-only deps,
# sysv-ipc on armv7l) must precede both the pip step and the sdmon build.
if $UPDATE; then
    phase packages 10 "Upgrading system packages (this may take several minutes)..."
    system_upgrade
fi
phase packages 10 "Installing packages..."
install_recovery_packages
install_image_packages
install_display_hardware_packages
# The boot splash is installed on every dial, so a monitor plugged into any
# dial shows it; an SPI panel is unaffected.
install_plymouth_packages
# The kiosk browser and its account exist on an HD dial only.
if $HD; then
    install_kiosk_packages
    create_kiosk_user
fi
install_venv_build_packages
# The binary is always present so SD card health monitoring can be switched on
# later from the appliance's Setup page without a rebuild; only the wrapper's
# enable verb ever starts the timer.
install_sdmon

# ---- Python environment (fresh install and --update) ------------------------
phase python 45 "Installing Python packages..."
if $UPDATE; then
    # Reuse the current venv when the requirements are unchanged, otherwise
    # build venv.<tag> beside it; the running dial keeps its own venv.
    prepare_update_venv
else
    VENV_LOCK_SHA256="$(requirements_lock_sha256)"
    build_venv "$(_opt_dir)/venv"
fi

# ---- Files (fresh install and --update) -------------------------------------
phase files 70 "Copying files..."
# ---- Deploy Python files ----------------------------------------------------
# --update stages the whole code set in /opt/autostream/.next after saving every
# file this installer owns outside the tree; nothing the running dial has
# imported changes before the reboot, when the boot step switches it in. A fresh
# install has no running dial and installs in place.
if $UPDATE; then
    backup_owned_files
    stage_code_tree
else
    install_code_tree "$(_opt_dir)"
fi
install -m 0755 "$DEPLOY/dial/autostream-dial-control" \
    /usr/local/bin/autostream-dial-control

deploy_admin
deploy_avahi_template

# ---- Deploy images ----------------------------------------------------------
install_dial_images

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

# ---- Configuration ----------------------------------------------------------
phase configure 80 "Configuring..."

# ---- Display hardware (fresh install and --update) ---------------------------
# SPI enablement and group membership may require a reboot or service restart
# before hardware access works. I2C is enabled unconditionally alongside SPI
# so a capacitive touch panel can be fitted later without re-running the
# installer — see enable_i2c()'s comment for why this is free when idle.
add_spi_group
enable_spi0
enable_spi1
set_spidev_bufsiz
enable_i2c
if $HD; then
    configure_hd_boot
fi

# ---- Boot splash (fresh install and --update) --------------------------------
# Unconditional and idempotent, like disable_cloud_init below: dials installed
# before this existed gain the splash on their next --update, and the initramfs
# is rebuilt only when something changed.
configure_plymouth

# ---- Boot-time trim (fresh install and --update) ----------------------------
# One call on the unconditional path rather than inside the fresh-only block
# above: the flag file is idempotent, and dials installed before this existed
# must gain the faster boot on their next --update without a re-image — the
# same reasoning as install_recovery_packages/install_image_packages.
disable_cloud_init

# ---- Identity and config handling -------------------------------------------
if ! $UPDATE; then
    DIAL_UUID=$(generate_dial_id)
    if [[ -z "$DIAL_UUID" ]]; then
        echo "ERROR: Unable to derive Dial identity (no CPU serial and fallback creation failed)." >&2
        exit 1
    fi
    write_dial_hw_config "$DIAL_UUID"
    write_dial_settings
    if $HD; then
        write_hd_display_config
    fi
else
    # Parse without source — never execute env file contents.
    DIAL_UUID=$(grep '^DIAL_UUID=' \
        "${INSTALL_STATE_FILE:-/var/lib/autostream/install-state.env}" 2>/dev/null | cut -d= -f2-)
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
# Shared storage-care units, identical to the appliance's. The storage
# guard script detects the dial install itself; the SD health units run
# the same wrapper the appliance uses.
install -m 0644 "$DEPLOY"/system/systemd/autostream_storage_guard.service         /etc/systemd/system/
install -m 0644 "$DEPLOY"/system/systemd/autostream_storage_guard.timer           /etc/systemd/system/
install -m 0644 "$DEPLOY"/system/systemd/autostream_sdcardhealth.service          /etc/systemd/system/
install -m 0644 "$DEPLOY"/system/systemd/autostream_sdcardhealth.timer            /etc/systemd/system/
install -m 0644 "$DEPLOY"/system/systemd/autostream_sdcardhealth_boot.service     /etc/systemd/system/
systemctl daemon-reload
systemctl enable autostream_dial autostream_dial_wifi_watcher autostream_dial_update_recover
# autostream_dial_updater.timer is not enabled by default; users opt in via the Setup page.
systemctl enable --now autostream_storage_guard.timer
# The boot-check unit only acts on a marker left by a probe that never
# completed, so it is always enabled; the health timer itself is enabled
# only by the wrapper's enable verb (from the Setup page) and its state is
# left alone here so an update never switches monitoring on or off.
systemctl enable autostream_sdcardhealth_boot.service

# The kiosk unit is enabled on an HD dial only. Its start marker is what makes
# it run, so a dial that stopped being an HD dial has it switched off here.
if $HD; then
    write_hd_marker
    deploy_kiosk_unit
else
    retire_hd_kiosk
fi

# ---- nginx ------------------------------------------------------------------
rm -f /etc/nginx/sites-enabled/default
install -m 0644 "$DEPLOY/system/nginx/autostream-dial-nginx.conf" \
    /etc/nginx/sites-available/autostream-dial
ln -sf /etc/nginx/sites-available/autostream-dial /etc/nginx/sites-enabled/autostream-dial
nginx -t
systemctl enable nginx
systemctl restart nginx

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
"$(_admin_bin)" \
    update-dial-service "${AUTOSTREAM_RELEASE_TAG}" "${DIAL_UUID}" "${DIAL_NAME:-${DIAL_UUID}}"

# ---- dnsmasq, sudoers, logrotate --------------------------------------------
# Install the captive-portal config as a root-owned TEMPLATE outside dnsmasq's
# automatic include directory.  The watcher substitutes the resolved built-in
# recovery interface into a runtime file under /run/autostream and the dedicated
# dnsmasq service reads only that runtime file.  Remove the obsolete
# /etc/dnsmasq.d/ copy so a manually started system dnsmasq cannot read it.
mkdir -p /usr/local/share/autostream/dnsmasq
install -m 0644 -o root -g root "$DEPLOY/system/dnsmasq/autostream-dial-setup.conf" \
    /usr/local/share/autostream/dnsmasq/autostream-dial-setup.conf
rm -f /etc/dnsmasq.d/autostream-dial-setup.conf
# The sudoers file is checked before it replaces the installed one: a broken
# drop-in stops sudo working on the whole system.
install_sudoers_file "$DEPLOY/system/sudoers/autostream_dial" \
    /etc/sudoers.d/autostream_dial
install -m 0644 "$DEPLOY/system/logrotate/autostream-dial" \
    /etc/logrotate.d/autostream-dial

# journald storage drop-in, shared with the appliance: volatile at rest with
# size/retention/rate-limit bounds.
mkdir -p /etc/systemd/journald.conf.d
install -m 0644 -o root -g root "$DEPLOY/system/journald/99-autostream-storage.conf" \
    /etc/systemd/journald.conf.d/99-autostream-storage.conf
systemctl restart systemd-journald || echo "WARNING: systemctl restart systemd-journald failed" >&2

# systemd-coredump storage bounds, shared with the appliance: cap how much
# disk core dumps may use. Read on every dump, so nothing is restarted.
mkdir -p /etc/systemd/coredump.conf.d
install -m 0644 -o root -g root "$DEPLOY/system/coredump/99-autostream-coredump.conf" \
    /etc/systemd/coredump.conf.d/99-autostream-coredump.conf

# Swap file limit, shared with the appliance: rpi-swap sizes the file from RAM,
# so a 4 GB board would put 2 GB on the SD card. Takes effect at the next boot.
install_swap_limit "$DEPLOY/system/rpi-swap/99-autostream-swap.conf"

write_install_state "$DIAL_UUID"

# ---- Initialize update-result.env on fresh install only ---------------------
# On --update the file already contains STATUS=in_progress written by the updater;
# do not overwrite.
if ! $UPDATE; then
    _result_file="${UPDATE_RESULT_FILE:-/var/lib/autostream/update-result.env}"
    printf 'STATUS=\nMESSAGE=\n' > "$_result_file"
    chown root:autostream "$_result_file"
    chmod 0644 "$_result_file"
fi

# ---- Finish -----------------------------------------------------------------
# An --update never restarts the dial services here: the running processes keep
# the code and venv they loaded, and the reboot below brings the new version up
# through the boot step. The dial's own units are not touched in the meantime.
if $UPDATE; then
    phase staged 92 "Finishing..."
    write_update_swap
    phase reboot 96 "Restarting..."
    # Let the running dial's next status poll paint "Restarting..." first.
    sleep "${UPDATE_PAINT_DELAY:-2}"
    _install_success=true   # the hand-off is complete; the boot step owns the outcome
    echo "autostream dial update staged; rebooting to switch to ${AUTOSTREAM_RELEASE_TAG}."
    # Same verb and reason as the appliance's update; a clean shutdown, so PIN
    # recovery is not armed.
    schedule_update_reboot
else
    systemctl restart autostream_dial autostream_dial_wifi_watcher
    _install_success=true
    # Everything has succeeded; free the space the downloaded packages took.
    # (An update does this once the boot step has verified it, not here.)
    clean_package_cache
    echo "autostream dial installation complete."
fi
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
