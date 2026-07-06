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
    # Offline-recovery packages are omitted here; install_recovery_packages() is
    # the single install site, called unconditionally for both fresh and update paths.
    apt-get install -y --no-install-recommends \
        avahi-daemon avahi-utils nginx dnsmasq curl \
        python3-venv python3-flask python3-lgpio
}

install_image_packages() {
    # python3-pil is apt-provided (not pip) so it is visible in the dial venv
    # via --system-site-packages. Called unconditionally on fresh install and
    # --update so existing installs gain it without requiring a re-image.
    apt-get install -y --no-install-recommends python3-pil
}

install_recovery_packages() {
    # Install offline-recovery dependencies idempotently.
    # Called unconditionally (fresh install and --update) so that upgraded
    # devices gain fcgiwrap and zip without requiring a re-image, and fresh
    # installs are covered by a single code path.
    apt-get install -y --no-install-recommends fcgiwrap zip
    # Dial logs are root:adm 0640; www-data needs adm membership to read them
    # for the CGI log-download endpoint.
    usermod -aG adm www-data
}

create_dirs() {
    mkdir -p /opt/autostream
    mkdir -p /etc/autostream
    mkdir -p /var/lib/autostream
    mkdir -p /var/log/autostream
    mkdir -p /usr/local/libexec/autostream
    mkdir -p /usr/local/share/autostream/avahi
    # Ownership is applied in init_service_dirs(), called after create_service_user()
}

create_service_user() {
    id autostream &>/dev/null && return
    useradd --system --no-create-home --shell /usr/sbin/nologin autostream
}

init_service_dirs() {
    # Called AFTER create_service_user() so the user exists when chown runs.
    # /etc/autostream/ is root-owned so the service cannot rename autostream-dial.json.
    chown root:root /etc/autostream
    chmod 0755 /etc/autostream
    chown autostream:autostream /var/lib/autostream
    chmod 0750 /var/lib/autostream
    # Create initial log files with correct owner/mode before logrotate's first rotation.
    install -m 0640 -o autostream -g adm /dev/null /var/log/autostream/autostream-dial.log
    install -m 0640 -o root -g adm /dev/null /var/log/autostream/dial-install.log
    install -m 0640 -o root -g adm /dev/null /var/log/autostream/dial-update.log
    install -m 0640 -o root -g adm /dev/null /var/log/autostream/autostream_wifi_watcher.log
}

add_gpio_group() {
    usermod -aG gpio autostream 2>/dev/null || true
}

install_display_hardware_packages() {
    # python3-spidev is apt-provided; the ST7735S backend needs SPI0 access.
    # Called unconditionally on fresh install and --update so existing dials
    # gain SPI support without requiring a re-image.
    apt-get install -y --no-install-recommends python3-spidev
}

add_spi_group() {
    # Some platforms/images do not define an spi group; that is non-fatal —
    # display hardware simply cannot be used until one is provisioned.
    usermod -aG spi autostream 2>/dev/null || true
}

enable_spi0() {
    # Enables Raspberry Pi SPI0 for the ST7735S display backend. Non-fatal on
    # non-Pi platforms or when raspi-config is unavailable; display-disabled
    # installs must keep working regardless.
    if command -v raspi-config >/dev/null 2>&1; then
        raspi-config nonint do_spi 0 \
            || echo "WARNING: raspi-config could not enable SPI0 — enable it manually if a screen is fitted" >&2
    else
        echo "WARNING: raspi-config not found — enable Raspberry Pi SPI0 manually if a screen is fitted" >&2
    fi
}

disable_system_dnsmasq() {
    systemctl disable --now dnsmasq.service 2>/dev/null || true
    systemctl mask dnsmasq.service
}

generate_dial_id() {
    # Derive the Dial identity from the CPU serial (SHA-256 hash, 20 hex chars)
    # or create and store a cryptographically secure random fallback identity.
    # Prints exactly 20 lowercase hexadecimal characters and exits non-zero on failure.
    python3 - <<'PYEOF'
import hashlib, os, re, secrets, sys
from pathlib import Path

def _get_cpu_serial():
    try:
        text = Path('/proc/cpuinfo').read_text(encoding='utf-8', errors='ignore')
        for ln in text.splitlines():
            if ln.strip().lower().startswith('serial'):
                parts = ln.split(':', 1)
                if len(parts) == 2 and parts[1].strip():
                    return parts[1].strip()
    except Exception:
        pass
    try:
        raw = Path('/proc/device-tree/serial-number').read_bytes()
        if raw:
            return raw.replace(b'\x00', b'').decode('utf-8', errors='ignore').strip()
    except Exception:
        pass
    return ''

serial = _get_cpu_serial().strip().lower()
if re.match(r'^[0-9a-f]+$', serial) and serial:
    digest = hashlib.sha256(('autostream-dial-v1:' + serial).encode('utf-8')).hexdigest()
    print(digest[:20])
    sys.exit(0)

fallback_path = Path('/var/lib/autostream/dial-id')
if fallback_path.exists():
    raw = fallback_path.read_text(encoding='utf-8').strip()
    if len(raw) == 20 and re.match(r'^[0-9a-f]+$', raw):
        print(raw)
        sys.exit(0)

# Create a new cryptographically secure fallback identity.
new_id = secrets.token_hex(10)
tmp = fallback_path.with_suffix('.tmp')
tmp.write_text(new_id, encoding='utf-8')
os.chmod(tmp, 0o644)
os.chown(tmp, 0, 0)
tmp.replace(fallback_path)
print(new_id)
sys.exit(0)
PYEOF
}

write_dial_hw_config() {
    # Hardware + identity config — root-owned, service user can read, never writes it.
    local uuid="$1"
    python3 - "$uuid" <<'PYEOF'
import json, sys
uuid = sys.argv[1]
with open('/etc/autostream/autostream-dial.json', 'w') as f:
    json.dump({
        "clk_gpio": 17,
        "dt_gpio":  27,
        "sw_gpio":  22,
        "led_gpio": None,
        "port":     7842,
        "uuid":     uuid
    }, f, indent=2)
PYEOF
    chown root:autostream /etc/autostream/autostream-dial.json
    chmod 0640 /etc/autostream/autostream-dial.json
}

write_dial_settings() {
    # Runtime-mutable settings owned by the service user.
    python3 -c "
import json, os
path = '/var/lib/autostream/dial-settings.json'
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, 'w') as f:
    json.dump({'step_percent': 2, 'name': '', 'pin': '', 'auto_update': False, 'update_channel': 'stable'}, f, indent=2)
"
    chown autostream:autostream /var/lib/autostream/dial-settings.json
}

has_tty() {
    [[ -r /dev/tty && -w /dev/tty ]]
}

tty_read() {
    local prompt="$1" __var="$2"
    IFS= read -r -p "${prompt}" "${__var}" < /dev/tty
}

show_info_and_prompt() {
    cat <<'EOF'

=============================================================================
AUTOSTREAM DIAL INSTALLER
=============================================================================
This script will:
- Install OS packages (nginx, dnsmasq, avahi, Python dependencies, etc.)
- Deploy dial firmware and configuration files
- Enable systemd services for dial, wifi watcher, and auto-update
- Create system users/groups and modify permissions
- Configure nginx, logrotate, dnsmasq, and avahi for dial operation

WARNING:
- Use ONLY on a dedicated Raspberry Pi Zero running Raspberry Pi OS Lite (Trixie).
- Use on a clean image only.
- Do NOT run on machines containing important data or multi-purpose systems.

A full activity log will be written to ~/autostream_dial_install.log
=============================================================================
EOF

    if has_tty; then
        local ans
        tty_read "Continue with installation? (Y/N) " ans || true
        case "${ans:-N}" in
            Y|y) echo "Continuing..." ;;
            *) echo "ERROR: Aborted by user." >&2; exit 1 ;;
        esac
    else
        echo "ERROR: Non-interactive session detected. Cannot prompt for confirmation." >&2
        echo "ERROR: Re-run interactively via a TTY (e.g. sudo ./autostream_dial_install.sh)." >&2
        exit 1
    fi
}

# _wifi_profile_mode: print the NetworkManager Wi-Fi mode for a profile.
_wifi_profile_mode() {
    local uuid="$1" name="${2:-}" ident=()
    if [[ -n "${uuid}" ]]; then
        ident=(uuid "${uuid}")
    else
        ident=("${name}")
    fi
    nmcli -t -f 802-11-wireless.mode connection show "${ident[@]}" 2>/dev/null \
        | awk -F: '{print tolower($2)}' | head -n1
}

# _record_wifi_connection_state: persist the chosen NM connection identity.
_record_wifi_connection_state() {
    local wifi_conn="$1" wifi_uuid="${2:-}" ssid_file="/opt/autostream/ssid"

    printf "%s\n" "${wifi_conn}" > "${ssid_file}"
    AUTOSTREAM_WIFI_CONN_NAME="${wifi_conn}" \
    AUTOSTREAM_WIFI_CONN_UUID="${wifi_uuid}" \
        python3 - <<'PYEOF'
import json
import os
from pathlib import Path

payload = {
    "schema_version": 1,
    "connection_name": os.environ["AUTOSTREAM_WIFI_CONN_NAME"],
    "connection_uuid": os.environ.get("AUTOSTREAM_WIFI_CONN_UUID", ""),
}
Path("/etc/autostream-network.json").write_text(
    json.dumps(payload, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PYEOF
    chown root:root "${ssid_file}" /etc/autostream-network.json
    chmod 0644 "${ssid_file}" /etc/autostream-network.json
}

# _network_state_configured: true if JSON state already commits a connection.
_network_state_configured() {
    python3 - <<'PYEOF'
import json
import sys
from pathlib import Path

try:
    data = json.loads(Path("/etc/autostream-network.json").read_text(encoding="utf-8"))
except Exception:
    sys.exit(1)
sys.exit(0 if isinstance(data, dict) and bool(str(data.get("connection_name", "")).strip()) else 1)
PYEOF
}

# _select_active_wifi_connection: prefer the currently active non-AP Wi-Fi.
_select_active_wifi_connection() {
    local default_dev wifi_devices dev conn uuid mode
    default_dev="$(ip route show default 2>/dev/null | awk '/dev/{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1)"
    wifi_devices="$(
        nmcli -t -f DEVICE,TYPE,STATE device status 2>/dev/null \
            | awk -F: -v prefer="${default_dev}" '
                NF>=3 && $2=="wifi" && ($3=="connected" || $3=="activated") {
                  if ($1==prefer) { preferred=$1 }
                  else { others[++n]=$1 }
                }
                END {
                  if (preferred!="") print preferred
                  for (i=1; i<=n; i++) print others[i]
                }
              '
    )"

    while IFS= read -r dev; do
        [[ -z "${dev}" ]] && continue
        conn="$(nmcli -g GENERAL.CONNECTION device show "${dev}" 2>/dev/null | head -n1)"
        uuid="$(nmcli -g GENERAL.CON-UUID device show "${dev}" 2>/dev/null | head -n1)"
        [[ -z "${conn}" || "${conn}" == "--" ]] && continue
        mode="$(_wifi_profile_mode "${uuid}" "${conn}")"
        if [[ "${mode}" != "ap" ]]; then
            printf "%s\t%s\n" "${conn}" "${uuid}"
            return 0
        fi
        echo "Wi-Fi connection '${conn}' is AP mode; skipping" >&2
    done <<< "${wifi_devices}"

    return 1
}

# _select_saved_wifi_connection: import a unique saved infrastructure profile.
#
# D-WP3 trace (Phase D, client profiles autoconnect=no): this selection runs only
# at fresh install on profiles that PRE-EXIST the install (still autoconnect=yes),
# so the best-autoconnect-priority path is unaffected; the watcher's autoconnect=no
# migration (D-WP2) runs later, at boot, after a default has been recorded. A lone
# manually-set autoconnect=no profile is still imported by the suitable_count==1
# fallback (which does not require autoconnect=yes) — no widening needed.
_select_saved_wifi_connection() {
    local uuid type name mode autoconnect priority
    local best_auto_name="" best_auto_uuid="" best_auto_priority=-2147483648 best_auto_count=0
    local only_name="" only_uuid="" suitable_count=0

    while IFS=: read -r uuid type; do
        [[ -z "${uuid}" ]] && continue
        [[ "${type}" == "802-11-wireless" || "${type}" == "wifi" ]] || continue

        name="$(nmcli -g connection.id connection show uuid "${uuid}" 2>/dev/null | head -n1)"
        [[ -z "${name}" || "${name}" == "Hotspot" ]] && continue
        mode="$(_wifi_profile_mode "${uuid}" "${name}")"
        if [[ "${mode}" == "ap" ]]; then
            echo "Saved Wi-Fi connection '${name}' is AP mode; skipping" >&2
            continue
        fi

        suitable_count=$((suitable_count + 1))
        only_name="${name}"
        only_uuid="${uuid}"

        autoconnect="$(nmcli -g connection.autoconnect connection show uuid "${uuid}" 2>/dev/null | head -n1 | tr '[:upper:]' '[:lower:]')"
        priority="$(nmcli -g connection.autoconnect-priority connection show uuid "${uuid}" 2>/dev/null | head -n1)"
        [[ "${priority}" =~ ^-?[0-9]+$ ]] || priority=0
        if [[ "${autoconnect}" == "yes" ]]; then
            if (( priority > best_auto_priority )); then
                best_auto_name="${name}"
                best_auto_uuid="${uuid}"
                best_auto_priority="${priority}"
                best_auto_count=1
            elif (( priority == best_auto_priority )); then
                best_auto_count=$((best_auto_count + 1))
            fi
        fi
    done < <(nmcli -t -f UUID,TYPE connection show 2>/dev/null)

    if (( best_auto_count == 1 )); then
        printf "%s\t%s\n" "${best_auto_name}" "${best_auto_uuid}"
        return 0
    fi
    if (( best_auto_count > 1 )); then
        echo "Multiple saved autoconnect Wi-Fi profiles share priority ${best_auto_priority}; not recording a default" >&2
        return 1
    fi
    if (( suitable_count == 1 )); then
        printf "%s\t%s\n" "${only_name}" "${only_uuid}"
        return 0
    fi
    if (( suitable_count > 1 )); then
        echo "Multiple saved Wi-Fi profiles found and none is a unique autoconnect default; not recording a default" >&2
    fi
    return 1
}

# network_state_phase: record current or saved WiFi client connection (fresh install only).
# Mirrors the same function in autostream_install.sh.
# Preserves an existing /opt/autostream/ssid if non-empty.
network_state_phase() {
    local ssid_file="/opt/autostream/ssid"

    if [[ -s "${ssid_file}" ]]; then
        echo "WiFi connection already recorded at ${ssid_file}"
        return 0
    fi
    if _network_state_configured; then
        echo "WiFi connection already recorded at /etc/autostream-network.json"
        return 0
    fi

    local selected wifi_conn wifi_uuid source
    selected="$(_select_active_wifi_connection || true)"
    source="active"
    if [[ -z "${selected}" ]]; then
        selected="$(_select_saved_wifi_connection || true)"
        source="saved"
    fi

    if [[ -n "${selected}" ]]; then
        wifi_conn="${selected%%$'\t'*}"
        wifi_uuid="${selected#*$'\t'}"
        if [[ "${wifi_uuid}" == "${wifi_conn}" ]]; then
            wifi_uuid=""
        fi
        _record_wifi_connection_state "${wifi_conn}" "${wifi_uuid}"
        echo "Recorded ${source} WiFi connection '${wifi_conn}' to ${ssid_file} and /etc/autostream-network.json"
    else
        echo "No active or uniquely selectable saved WiFi client connection detected; hotspot mode will be used if wired connection is not detected"
    fi
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
    # Write the canonical update-result.env schema shared with autostream_admin
    # update-status and the offline/updating.html page.
    # Usage: write_update_result STATUS MESSAGE [PERCENT_COMPLETE]
    local status="$1" message="$2" percent="${3:-0}"
    local last_run_at
    last_run_at="$(date -u '+%Y-%m-%dT%H:%M:%S+00:00')"
    printf 'STATUS=%s\nPERCENT_COMPLETE=%s\nMESSAGE=%s\nLAST_RUN_AT=%s\n' \
        "$status" "$percent" "$message" "$last_run_at" \
        > /var/lib/autostream/update-result.env
}

deploy_admin() {
    install -m 0644 -o root -g root \
        "$DEPLOY/supervisor/autostream_update_support.py" \
        /usr/local/libexec/autostream/autostream_update_support.py
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
    # root-owned 0644: root writes, all can read (including autostream for UUID fallback).
    cat > /var/lib/autostream/install-state.env <<EOF
AUTOSTREAM_PRODUCT=autostream-dial
DIAL_UUID=${uuid}
AUTOSTREAM_RELEASE_TAG=${AUTOSTREAM_RELEASE_TAG}
EOF
    chown root:root /var/lib/autostream/install-state.env
    chmod 0644 /var/lib/autostream/install-state.env
}
