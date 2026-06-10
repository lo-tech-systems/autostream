#!/usr/bin/env bash
#
# installer/dial/helpers.sh
#
# Helper functions for autostream_dial_install.sh.
# Sourced by the installer; not executed directly.
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

detect_install_version() {
    # Same contract as autostream_install.sh: strip refs/tags/ and v prefix.
    # Falls back to "unknown" (not "dev") when AUTOSTREAM_RELEASE_TAG is unset
    # so the result is obviously non-production.
    local raw="${AUTOSTREAM_RELEASE_TAG:-}"
    raw="${raw#refs/tags/}"
    raw="${raw#v}"
    printf '%s\n' "${raw:-unknown}"
}

install_os_packages() {
    # Flask is system Python (outside venv) — see wifi_watcher source comment line 13.
    apt-get install -y --no-install-recommends \
        avahi-daemon avahi-utils nginx dnsmasq curl \
        python3-venv python3-flask python3-lgpio
}

create_dirs() {
    mkdir -p /opt/autostream
    mkdir -p /etc/autostream-dial
    mkdir -p /var/lib/autostream-dial
    mkdir -p /var/lib/autostream-dial/settings   # service-user-writable subdirectory
    mkdir -p /var/log/autostream
    mkdir -p /usr/local/libexec/autostream
    mkdir -p /usr/local/share/autostream/avahi
    # Note: settings/ ownership is set in init_service_dirs(), called after create_service_user()
}

create_service_user() {
    id autostream-dial &>/dev/null && return
    useradd --system --no-create-home --shell /usr/sbin/nologin autostream-dial
}

init_service_dirs() {
    # Called AFTER create_service_user() so the user exists when chown runs.
    # settings/ is owned by service user so save_config() can write without privilege.
    chown autostream-dial:autostream-dial /var/lib/autostream-dial/settings
    chmod 0700 /var/lib/autostream-dial/settings
    # Create initial log files with correct owner/mode before logrotate's first rotation.
    install -m 0640 -o root -g adm /dev/null /var/log/autostream/dial-install.log
    install -m 0640 -o root -g adm /dev/null /var/log/autostream/dial-update.log
    install -m 0640 -o root -g adm /dev/null /var/log/autostream/wifi_setup.log
}

add_gpio_group() {
    usermod -aG gpio autostream-dial 2>/dev/null || true
}

disable_system_dnsmasq() {
    systemctl disable --now dnsmasq.service 2>/dev/null || true
    systemctl mask dnsmasq.service
}

generate_uuid() {
    python3 -c "import uuid; print(uuid.uuid4())"
}

write_dial_hw_config() {
    # Hardware + identity config — root-owned, service user can read, never writes it.
    local uuid="$1"
    python3 - "$uuid" <<'PYEOF'
import json, sys
uuid = sys.argv[1]
with open('/etc/autostream-dial/dial.json', 'w') as f:
    json.dump({
        "clk_gpio": 17,
        "dt_gpio":  27,
        "sw_gpio":  None,
        "led_gpio": None,
        "port":     7842,
        "uuid":     uuid
    }, f, indent=2)
PYEOF
    chown root:autostream-dial /etc/autostream-dial/dial.json
    chmod 0640 /etc/autostream-dial/dial.json
}

write_dial_settings() {
    # Runtime-mutable settings inside the service-user-owned settings/ subdirectory.
    python3 -c "
import json, os
path = '/var/lib/autostream-dial/settings/dial-settings.json'
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, 'w') as f:
    json.dump({'step_percent': 2, 'name': '', 'pin': '', 'auto_update': False}, f, indent=2)
"
    chown autostream-dial:autostream-dial /var/lib/autostream-dial/settings/dial-settings.json
}

check_pi_model() {
    local model
    model=$(tr -d '\0' < /proc/device-tree/model 2>/dev/null || true)
    if [[ "$model" != *"Raspberry Pi Zero"* ]]; then
        echo "WARNING: expected Pi Zero, got: ${model:-unknown}" >&2
    fi
}

require_trixie_os() {
    local codename
    codename="$(. /etc/os-release 2>/dev/null && printf '%s' "${VERSION_CODENAME:-}")"
    if [[ "${codename}" != "trixie" ]]; then
        echo "ERROR: Raspberry Pi OS Trixie is required (detected: ${codename:-unknown})." >&2
        echo "ERROR: Bookworm installations require re-imaging; unattended OS upgrades are not supported." >&2
        exit 1
    fi
}

setup_venv() {
    # --system-site-packages: exposes apt-installed python3-lgpio to the venv.
    python3 -m venv --system-site-packages /opt/autostream/venv
    /opt/autostream/venv/bin/pip install --quiet -U pip
    # Prefer hash-locked requirements for reproducible builds.  Fall back to
    # pinned requirements.txt with a warning.
    if [[ -f "$DEPLOY/dial/requirements.lock" ]]; then
        /opt/autostream/venv/bin/pip install --quiet \
            --require-hashes -r "$DEPLOY/dial/requirements.lock"
    else
        echo "WARNING: requirements.lock not found; installing from requirements.txt (not hash-pinned)" >&2
        /opt/autostream/venv/bin/pip install --quiet \
            -r "$DEPLOY/dial/requirements.txt"
    fi
}

write_update_result() {
    local status="$1" message="$2"
    printf 'STATUS=%s\nMESSAGE=%s\n' "$status" "$message" \
        > /var/lib/autostream-dial/update-result.env
}

deploy_admin() {
    install -m 0755 -o root -g root \
        "$DEPLOY/supervisor/autostream_admin" \
        /usr/local/libexec/autostream/autostream_admin
    install -m 0755 -o root -g root \
        "$DEPLOY/supervisor/autostream_dial_updater" \
        /usr/local/libexec/autostream/autostream_dial_updater
}

deploy_avahi_template() {
    install -D -m 0644 -o root -g root \
        "$DEPLOY/system/avahi/autostream-dial.service" \
        /usr/local/share/autostream/avahi/autostream-dial.service
}

write_install_state() {
    local uuid="$1"
    # root-owned 0644: root writes, all can read (including autostream-dial for UUID fallback).
    cat > /var/lib/autostream-dial/install-state.env <<EOF
AUTOSTREAM_PRODUCT=autostream-dial
DIAL_UUID=${uuid}
AUTOSTREAM_RELEASE_TAG=${AUTOSTREAM_RELEASE_TAG}
EOF
    chown root:root /var/lib/autostream-dial/install-state.env
    chmod 0644 /var/lib/autostream-dial/install-state.env
}
