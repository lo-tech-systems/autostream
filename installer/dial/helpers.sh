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
    # Flask is system Python (outside venv) — see the runtime note in
    # platform/wifi_watcher.py's module docstring.
    # Offline-recovery packages are omitted here; install_recovery_packages() is
    # the single install site, called unconditionally for both fresh and update paths.
    # Venv build dependencies are likewise omitted; install_venv_build_packages()
    # owns those and runs on both paths because setup_venv() does too.
    apt_step apt-get install -y --no-install-recommends \
        avahi-daemon avahi-utils nginx dnsmasq curl \
        python3-venv python3-flask python3-lgpio
}

install_image_packages() {
    # python3-pil is apt-provided (not pip) so it is visible in the dial venv
    # via --system-site-packages. fonts-dejavu-core supplies the DejaVu Sans
    # TTF the now-playing overlay renders artist/volume text with; it lives
    # here (rather than install_os_packages()) because it is only needed by
    # the display stack, same lifecycle as python3-pil. Called unconditionally
    # on fresh install and --update so existing installs gain both without
    # requiring a re-image.
    apt_step apt-get install -y --no-install-recommends python3-pil fonts-dejavu-core
}

install_recovery_packages() {
    # Install offline-recovery dependencies idempotently.
    # Called unconditionally (fresh install and --update) so that upgraded
    # devices gain fcgiwrap and zip without requiring a re-image, and fresh
    # installs are covered by a single code path.
    apt_step apt-get install -y --no-install-recommends fcgiwrap zip
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
    # python3-spidev is apt-provided; the SPI display backend needs SPI0 access.
    # python3-smbus is apt-provided; a capacitive (I2C) touch panel backend
    # (e.g. FT6206/FT6236) needs it.
    # python3-numpy is apt-provided and REQUIRED, not optional: the pinned
    # adafruit_rgb_display driver converts every frame to RGB565 inside
    # Display.image(), and without numpy it falls back to a pure-Python
    # per-pixel loop that takes hundreds of milliseconds to well over a
    # second per frame (measured on a Pi 2B) — the display is unusably slow
    # without it. All three are installed here so the venv sees them via
    # --system-site-packages, the same mechanism as python3-pil/python3-spidev.
    # Called unconditionally on fresh install and --update so existing dials
    # gain SPI/I2C/fast-display support without requiring a re-image.
    apt_step apt-get install -y --no-install-recommends python3-spidev python3-smbus python3-numpy
}

add_spi_group() {
    # Some platforms/images do not define an spi group; that is non-fatal —
    # display hardware simply cannot be used until one is provisioned.
    usermod -aG spi autostream 2>/dev/null || true
}

enable_spi0() {
    # Enables Raspberry Pi SPI0 for the SPI display backend. Non-fatal on
    # non-Pi platforms or when raspi-config is unavailable; display-disabled
    # installs must keep working regardless.
    if command -v raspi-config >/dev/null 2>&1; then
        raspi-config nonint do_spi 0 \
            || echo "WARNING: raspi-config could not enable SPI0 — enable it manually if a screen is fitted" >&2
    else
        echo "WARNING: raspi-config not found — enable Raspberry Pi SPI0 manually if a screen is fitted" >&2
    fi
}

enable_spi1() {
    # Enables the Raspberry Pi auxiliary SPI1 controller, which the resistive
    # touch driver uses. raspi-config has no knob for SPI1 (do_spi covers SPI0
    # only), so this appends the overlay to config.txt directly.
    #
    # cs0_pin=12 parks the overlay's chip select on a pin the dial does not
    # use, and must not be dropped. The overlay's default is GPIO18 — the
    # display backlight — and GPIO16 is where the touch driver's own chip
    # select lives (see dial_touch_drivers._TOUCH_CS_GPIO). The kernel claims
    # whichever pin the overlay names, so it has to be neither of those.
    #
    # Called unconditionally, like enable_i2c: the overlay costs nothing with
    # no panel attached, and this avoids re-running the installer when a
    # resistive panel is fitted later. Takes effect on the next boot.
    local cfg="${1:-/boot/firmware/config.txt}"
    local line="dtoverlay=spi1-1cs,cs0_pin=12"

    if [[ ! -f "${cfg}" ]]; then
        echo "WARNING: ${cfg} not found — enable SPI1 manually if a resistive touch panel is fitted" >&2
        return 0
    fi
    # Rewrite rather than skip. An existing spi1 overlay may name a stale
    # chip-select pin from an earlier layout, which would silently collide
    # with the touch chip select and leave touch dead with no obvious cause.
    # A dial must end up on the documented pin numbering after any install or
    # update, not merely be left with whatever it happened to have.
    if grep -qE '^[[:space:]]*dtoverlay=spi1(-[0-9]cs)?([[:space:]]*|,.*)$' "${cfg}"; then
        if grep -qxF "${line}" "${cfg}"; then
            return 0
        fi
        sed -i -E "/^[[:space:]]*dtoverlay=spi1(-[0-9]cs)?([[:space:]]*|,.*)\$/d" "${cfg}" \
            || { echo "WARNING: could not rewrite the SPI1 overlay in ${cfg}" >&2; return 0; }
    fi
    printf '%s\n' "${line}" >> "${cfg}" \
        || echo "WARNING: could not append SPI1 overlay to ${cfg} — enable it manually if a resistive touch panel is fitted" >&2
}

set_spidev_bufsiz() {
    # Raises the kernel's per-transfer spidev limit so a display window goes
    # out in a few large SPI transfers instead of one ioctl per 4096 bytes.
    # The dial reads the live limit at startup and sizes its own writes to
    # match (dial_spi_bus._configure_spi_chunk_size), so this is safe on an
    # update: until the reboot applies it the dial keeps using 4096.
    #
    # spidev.bufsiz goes on the kernel command line rather than in
    # modprobe.d: spidev loads from the initramfs, which never sees a
    # modprobe.d change without a rebuild, while the command line reaches it
    # either way. cmdline.txt must stay a single line, so any existing
    # spidev.bufsiz token is replaced in place rather than appended again.
    # Called unconditionally; costs nothing with no panel. Takes effect on
    # the next boot.
    local cmdline="${1:-/boot/firmware/cmdline.txt}"
    local token="spidev.bufsiz=65536"

    if [[ ! -f "${cmdline}" ]]; then
        echo "WARNING: ${cmdline} not found — add ${token} to the kernel command line manually" >&2
        return 0
    fi
    if grep -qE "(^|[[:space:]])${token}([[:space:]]|\$)" "${cmdline}"; then
        return 0
    fi
    if grep -qE '(^|[[:space:]])spidev\.bufsiz=[^[:space:]]*' "${cmdline}"; then
        sed -i -E "1 s/(^|[[:space:]])spidev\.bufsiz=[^[:space:]]*/\1${token}/" "${cmdline}" \
            || echo "WARNING: could not update spidev.bufsiz in ${cmdline}" >&2
        return 0
    fi
    sed -i -E "1 s/[[:space:]]*\$/ ${token}/" "${cmdline}" \
        || echo "WARNING: could not add ${token} to ${cmdline}" >&2
}

enable_i2c() {
    # Enables Raspberry Pi I2C for a future capacitive (FT6206/FT6236) touch
    # panel backend. Called unconditionally: enabling I2C with nothing
    # attached costs nothing — the bus idles on the fixed pull-ups, no
    # polling, no interrupts, no measurable boot cost — and GPIO2/3 are not
    # used by the dial. This avoids re-running the installer when a
    # capacitive panel is later fitted. Non-fatal on non-Pi platforms or
    # when raspi-config is unavailable; installs must keep working regardless.
    if command -v raspi-config >/dev/null 2>&1; then
        raspi-config nonint do_i2c 0 \
            || echo "WARNING: raspi-config could not enable I2C — enable it manually if a capacitive touch panel is fitted" >&2
    else
        echo "WARNING: raspi-config not found — enable Raspberry Pi I2C manually if a capacitive touch panel is fitted" >&2
    fi
}

disable_system_dnsmasq() {
    systemctl disable --now dnsmasq.service 2>/dev/null || true
    systemctl mask dnsmasq.service
}

disable_cloud_init() {
    # cloud-init's per-boot stage costs a large fraction of every dial boot
    # and its provisioning job is finished by the time this installer runs.
    # The supported way to stop the per-boot run without purging the package
    # is an empty, root-owned /etc/cloud/cloud-init.disabled flag file: it is
    # reversible and survives package updates. Idempotent, so it runs on fresh
    # installs and on every --update alike (existing dials pick it up on their
    # next update). Only created when cloud-init is actually installed; a
    # failure warns and continues — a slower boot must never fail an install.
    if dpkg -s cloud-init >/dev/null 2>&1; then
        echo "Disabling cloud-init per-boot runs"
        { mkdir -p /etc/cloud && install -m 0644 -o root -g root /dev/null /etc/cloud/cloud-init.disabled; } \
            || echo "WARNING: could not create /etc/cloud/cloud-init.disabled — cloud-init will keep running at boot" >&2
    else
        echo "cloud-init not installed; skipping disable flag."
    fi
}

install_sdmon() {
    # Build and install the sdmon binary at the pinned revision, the same
    # revision the appliance installer builds, so both products probe the
    # card with identical code. The binary is always installed; whether
    # the health timer ever runs is decided later by the wrapper's enable
    # verb, which only enables after a guarded probe has passed. A build
    # failure warns and continues: the dial must install without it.
    local ref="8a70aed673f4b319972b3a2cfac043e3b171653a"
    local marker="/var/lib/autostream/sdmon-version"
    if [[ -x /usr/local/sbin/sdmon && -f "${marker}" && "$(cat "${marker}")" == "${ref}" ]]; then
        echo "sdmon binary already at ${ref}"
        return 0
    fi
    # gcc comes from install_venv_build_packages(); make is only needed here.
    apt_step apt-get install -y --no-install-recommends make
    local tmpdir
    tmpdir="$(mktemp -d)"
    if curl -fsSL "https://github.com/Ognian/sdmon/archive/${ref}.tar.gz" \
            | tar -xz -C "${tmpdir}" \
       && make -s -C "${tmpdir}/sdmon-${ref}/src"; then
        install -m 0755 -o root -g root "${tmpdir}/sdmon-${ref}/src/sdmon" /usr/local/sbin/sdmon
        printf '%s\n' "${ref}" > "${marker}"
        chmod 0644 "${marker}"
    else
        if [[ -x /usr/local/sbin/sdmon ]]; then
            echo "WARNING: sdmon build failed; keeping the existing binary" >&2
        else
            echo "WARNING: sdmon build failed and no binary is installed; SD card health monitoring cannot be enabled" >&2
        fi
    fi
    rm -rf "${tmpdir}"
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
    json.dump({'step_percent': 2, 'name': '', 'pin': '', 'auto_update': False, 'update_channel': 'stable', 'sd_health_monitoring': False}, f, indent=2)
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
# Client-profiles-autoconnect=no trace: this selection runs only
# at fresh install on profiles that PRE-EXIST the install (still autoconnect=yes),
# so the best-autoconnect-priority path is unaffected; the watcher's autoconnect=no
# migration runs later, at boot, after a default has been recorded. A lone
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

install_venv_build_packages() {
    # Headers and a compiler for source builds in setup_venv().
    # adafruit-circuitpython-rgb-display pulls in sysv-ipc (via adafruit-blinka),
    # which publishes no armv7l wheel — on 32-bit images pip compiles it from the
    # sdist, and without Python.h the pip step fails and aborts the whole install.
    # python3-dev transitively supplies libc6-dev, so gcc needs no build-essential.
    # Called unconditionally (fresh install and --update) because setup_venv() is:
    # dials installed from a 32-bit image before this existed must acquire it on
    # their next update, or that update's pip step fails the same way.
    apt_step apt-get install -y --no-install-recommends python3-dev gcc
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

# Keys the update result file may carry beyond STATUS, PERCENT_COMPLETE,
# MESSAGE and LAST_RUN_AT, in the order they are written.
UPDATE_RESULT_KEYS=(PHASE TAG PREVIOUS_TAG ATTEMPT MAX_ATTEMPTS ROLLED_BACK TRANSIENT_RETRY)

_update_result_file() {
    printf '%s\n' "${UPDATE_RESULT_FILE:-/var/lib/autostream/update-result.env}"
}

_update_result_value() {
    # Print the value of KEY in the result file; empty when absent.
    local file line
    file="$(_update_result_file)"
    [[ -r "${file}" ]] || return 0
    while IFS= read -r line || [[ -n "${line}" ]]; do
        if [[ "${line%%=*}" == "$1" && "${line}" == *=* ]]; then
            printf '%s\n' "${line#*=}"
            return 0
        fi
    done < "${file}"
    return 0
}

_installed_release_tag() {
    # Release tag recorded by the previous install; empty when unknown.
    local state="${INSTALL_STATE_FILE:-/var/lib/autostream/install-state.env}"
    [[ -r "${state}" ]] || return 0
    grep '^AUTOSTREAM_RELEASE_TAG=' "${state}" 2>/dev/null | head -n 1 | cut -d= -f2- || true
}

write_update_result() {
    # Write the canonical update-result.env schema shared with autostream_admin
    # update-status and the offline/updating.html page.
    # Usage: write_update_result STATUS MESSAGE [PERCENT_COMPLETE] [KEY=VALUE ...]
    # Optional KEY=VALUE pairs set UPDATE_RESULT_KEYS entries; an empty value
    # removes the key. Entries already in the file and not named here are kept
    # (read-modify-write), so a phase write never drops the tag or attempt.
    # The file stays 0644 so the dial's own processes can read it.
    local status="$1" message="$2" percent="${3:-0}"
    shift $(( $# < 3 ? $# : 3 ))
    local file tmp last_run_at key arg value line
    local -A kv=()
    file="$(_update_result_file)"
    message="${message//$'\n'/ }"
    if [[ -r "${file}" ]]; then
        while IFS= read -r line || [[ -n "${line}" ]]; do
            [[ "${line}" == *=* && -n "${line#*=}" ]] || continue
            for key in "${UPDATE_RESULT_KEYS[@]}"; do
                if [[ "${line%%=*}" == "${key}" ]]; then
                    kv["${key}"]="${line#*=}"
                fi
            done
        done < "${file}"
    fi
    for arg in "$@"; do
        key="${arg%%=*}"
        value="${arg#*=}"
        value="${value//$'\n'/ }"
        if [[ -z "${value}" ]]; then
            unset "kv[${key}]"
        else
            kv["${key}"]="${value}"
        fi
    done
    last_run_at="$(date -u '+%Y-%m-%dT%H:%M:%S+00:00')"
    tmp="${file}.tmp.$$"
    {
        printf 'STATUS=%s\nPERCENT_COMPLETE=%s\nMESSAGE=%s\nLAST_RUN_AT=%s\n' \
            "${status}" "${percent}" "${message}" "${last_run_at}"
        for key in "${UPDATE_RESULT_KEYS[@]}"; do
            if [[ -n "${kv[${key}]+set}" ]]; then
                printf '%s=%s\n' "${key}" "${kv[${key}]}"
            fi
        done
    } > "${tmp}"
    chmod 0644 "${tmp}"
    if [[ -e "${file}" ]]; then
        chown --reference="${file}" "${tmp}" 2>/dev/null || true
    fi
    mv -f "${tmp}" "${file}"
}

phase() {
    # Enter an update phase: remember it for the failure message and, on
    # --update runs, record it in the result file.
    # Usage: phase NAME PERCENT_COMPLETE MESSAGE
    # The first phase write of a run also fills PREVIOUS_TAG, ATTEMPT and
    # MAX_ATTEMPTS when the updater that started the run did not write them.
    CURRENT_PHASE="$1"
    CURRENT_PERCENT="$2"
    CURRENT_MESSAGE="$3"
    [[ "${UPDATE:-false}" == true ]] || return 0
    local -a extras=("PHASE=$1" "TAG=${AUTOSTREAM_RELEASE_TAG:-}")
    local previous
    if [[ -z "$(_update_result_value PREVIOUS_TAG)" ]]; then
        previous="$(_installed_release_tag)"
        if [[ -n "${previous}" ]]; then
            extras+=("PREVIOUS_TAG=${previous}")
        fi
    fi
    if [[ -z "$(_update_result_value ATTEMPT)" ]]; then
        extras+=("ATTEMPT=1")
    fi
    if [[ -z "$(_update_result_value MAX_ATTEMPTS)" ]]; then
        extras+=("MAX_ATTEMPTS=4")
    fi
    write_update_result "in_progress" "$3" "$2" "${extras[@]}"
}

update_failure_message() {
    # Failure text for the phase that was running when the installer stopped.
    local previous step
    previous="$(_update_result_value PREVIOUS_TAG)"
    [[ -n "${previous}" ]] || previous="$(_installed_release_tag)"
    case "${CURRENT_PHASE:-}" in
        prepare)   step="preparation" ;;
        packages)  step="package installation" ;;
        python)    step="Python setup" ;;
        files)     step="file installation" ;;
        configure) step="configuration" ;;
        *)         step="setup" ;;
    esac
    printf 'Update to %s failed during %s - %s kept' \
        "${AUTOSTREAM_RELEASE_TAG:-unknown}" "${step}" \
        "${previous:-previous version}"
}

# Output patterns that mark an apt failure as transient (lock held, or the
# network failed mid-fetch). Anything else fails at once.
APT_TRANSIENT_PATTERN='Could not get lock|Unable to acquire the dpkg frontend lock|Failed to fetch|Temporary failure resolving|Connection timed out'

apt_step() {
    # Run an apt command; retry it once, after a pause, when it fails with
    # status 100 and its output shows a lock or fetch failure. A second
    # failure, or any other failure, is returned to the caller.
    local out rc
    out="$(mktemp)"
    if "$@" 2>&1 | tee "${out}"; then
        rc="${PIPESTATUS[0]}"
    else
        rc="${PIPESTATUS[0]}"
    fi
    if (( rc == 0 )); then
        rm -f "${out}"
        return 0
    fi
    if (( rc != 100 )) || ! grep -qE "${APT_TRANSIENT_PATTERN}" "${out}"; then
        rm -f "${out}"
        return "${rc}"
    fi
    rm -f "${out}"
    echo "Package step failed, retrying in ${APT_RETRY_DELAY:-30}s: $*" >&2
    if [[ "${UPDATE:-false}" == true ]]; then
        write_update_result "in_progress" "Package step failed, retrying..." \
            "${CURRENT_PERCENT:-0}" "TRANSIENT_RETRY=1" || true
    fi
    sleep "${APT_RETRY_DELAY:-30}"
    rc=0
    "$@" || rc=$?
    if (( rc == 0 )) && [[ "${UPDATE:-false}" == true && -n "${CURRENT_MESSAGE:-}" ]]; then
        write_update_result "in_progress" "${CURRENT_MESSAGE}" \
            "${CURRENT_PERCENT:-0}" || true
    fi
    return "${rc}"
}

system_upgrade() {
    # Refresh the package index and upgrade installed packages, as the
    # appliance installer does; needrestart is told only to list, never to
    # restart services mid-install. Then trim the downloaded package cache,
    # since the card is small.
    apt_step apt-get update
    apt_step env NEEDRESTART_MODE=l DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
    apt-get autoclean -y
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
    # Shared storage-care scripts: the same storage guard and SD card
    # health wrapper the appliance runs. The guard detects a dial install
    # from install-state.env and skips the appliance-only steps itself.
    install -m 0755 -o root -g root \
        "$DEPLOY/supervisor/autostream_storage_guard" \
        /usr/local/libexec/autostream/autostream_storage_guard
    install -m 0755 -o root -g root \
        "$DEPLOY/supervisor/autostream_sdcardhealth" \
        /usr/local/libexec/autostream/autostream_sdcardhealth
    sed -i 's/\r$//' /usr/local/libexec/autostream/autostream_storage_guard \
                     /usr/local/libexec/autostream/autostream_sdcardhealth
}

deploy_avahi_template() {
    install -D -m 0644 -o root -g root \
        "$DEPLOY/system/avahi/autostream-dial.service" \
        /usr/local/share/autostream/avahi/autostream-dial.service
}

write_install_state() {
    local uuid="$1"
    local path=/var/lib/autostream/install-state.env
    # The SD card health wrapper records its method and last outcome in
    # this file. Carry those lines over so an update keeps monitoring
    # enabled with the method the user chose.
    local sdmon_lines=""
    if [[ -f "${path}" ]]; then
        sdmon_lines="$(grep -E '^SDMON_[A-Z_]+=' "${path}" 2>/dev/null || true)"
    fi
    # root-owned 0644: root writes, all can read (including autostream for UUID fallback).
    {
        cat <<EOF
AUTOSTREAM_PRODUCT=autostream-dial
DIAL_UUID=${uuid}
AUTOSTREAM_RELEASE_TAG=${AUTOSTREAM_RELEASE_TAG}
EOF
        [[ -n "${sdmon_lines}" ]] && printf '%s\n' "${sdmon_lines}"
    } > "${path}"
    chown root:root "${path}"
    chmod 0644 "${path}"
}
