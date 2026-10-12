#!/usr/bin/env bash
#
# installer/dial/helpers.sh
#
# Helper functions for autostream_dial_install.sh.
# Sourced by the installer; not executed directly.
#
# Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

# install_sudoers_file, shared with the appliance installer.
# shellcheck source=../lib/sudoers.sh
source "${BASH_SOURCE[0]%/*}/../lib/sudoers.sh"
# recover_interrupted_packages, shared with the appliance installer.
# shellcheck source=../lib/apt.sh
source "${BASH_SOURCE[0]%/*}/../lib/apt.sh"
# install_swap_limit, shared with the appliance installer.
# shellcheck source=../lib/swap.sh
source "${BASH_SOURCE[0]%/*}/../lib/swap.sh"
# Wi-Fi power saving, swap behaviour, unneeded packages and the power key,
# shared with the appliance installer.
# shellcheck source=../lib/system_tuning.sh
source "${BASH_SOURCE[0]%/*}/../lib/system_tuning.sh"
# Replacing config.txt and cmdline.txt by rename, shared with the appliance
# installer.
# shellcheck source=../lib/boot_files.sh
source "${BASH_SOURCE[0]%/*}/../lib/boot_files.sh"
# Writing a state file without following a link, shared with the appliance
# installer.
# shellcheck source=../lib/state_files.sh
source "${BASH_SOURCE[0]%/*}/../lib/state_files.sh"
# The root-only directory an update stages into, shared with the appliance
# installer.
# shellcheck source=../lib/update_state.sh
source "${BASH_SOURCE[0]%/*}/../lib/update_state.sh"

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
    # owns those and runs on both paths because build_venv() does too.
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
    # installs are covered by a single code path. iw is here too: the Wi-Fi
    # watcher counts the stations on the setup hotspot with it, and the
    # NetworkManager dispatcher script (99-wlan-fix) uses it to turn Wi-Fi power
    # saving off and set the transmit power.
    apt_step apt-get install -y --no-install-recommends fcgiwrap zip iw
    # Dial logs are root:adm 0640; www-data needs adm membership to read them
    # for the CGI log-download endpoint.
    usermod -aG adm www-data
}

create_dirs() {
    mkdir -p /opt/autostream
    mkdir -p /etc/autostream
    mkdir -p /var/lib/autostream
    ensure_update_state_dir "$(_update_dir)" || {
        echo "ERROR: could not prepare $(_update_dir)." >&2
        return 1
    }
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
    # Create the log files with the right owner and mode before logrotate's
    # first rotation. A file that is already there is kept: install(1) over it
    # would replace it, wiping the dial's log history on every update along with
    # the log the running installer is writing to. Owner and mode are corrected
    # in place instead.
    local logdir f
    logdir="$(_fs_root)/var/log/autostream"
    [[ -e "${logdir}/autostream-dial.log" ]] || \
        install -m 0640 -o autostream -g adm /dev/null "${logdir}/autostream-dial.log"
    chown autostream:adm "${logdir}/autostream-dial.log"
    chmod 0640 "${logdir}/autostream-dial.log"
    for f in dial-install.log dial-update.log autostream_wifi_watcher.log; do
        [[ -e "${logdir}/${f}" ]] || install -m 0640 -o root -g adm /dev/null "${logdir}/${f}"
        chown root:adm "${logdir}/${f}"
        chmod 0640 "${logdir}/${f}"
    done
}

prepare_install_log() {
    # The persistent install log, ready before a fresh install writes its first
    # line: the directory and the file are created if absent, an existing file
    # is kept and appended to, and it is root:adm 0640 like the other dial logs,
    # which puts the whole run in the support log bundle. Fails (so the caller
    # logs to the user's home alone) when the file cannot be prepared.
    # Usage: prepare_install_log FILE
    local file="$1"
    mkdir -p "$(dirname "${file}")" || return 1
    [[ -e "${file}" ]] || install -m 0640 -o root -g adm /dev/null "${file}" || return 1
    chown root:adm "${file}" 2>/dev/null || true
    chmod 0640 "${file}" 2>/dev/null || true
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
    # A dial that has been factory reset also has a salt file; the salt is mixed
    # into the hash so the same board is a different device. The installer
    # never creates or changes the salt, and a salt file that is not exactly 32
    # lowercase hex characters, or that is not a root-owned regular file in a
    # root-owned directory, stops the install rather than guessing.
    # Prints exactly 20 lowercase hexadecimal characters and exits non-zero on failure.
    python3 - "$(_fs_root)" <<'PYEOF'
import hashlib, os, re, secrets, stat, sys
from pathlib import Path

root = sys.argv[1]
state = Path(root + '/var/lib/autostream')

def _get_cpu_serial():
    try:
        text = Path(root + '/proc/cpuinfo').read_text(encoding='utf-8', errors='ignore')
        for ln in text.splitlines():
            if ln.strip().lower().startswith('serial'):
                parts = ln.split(':', 1)
                if len(parts) == 2 and parts[1].strip():
                    return parts[1].strip()
    except Exception:
        pass
    try:
        raw = Path(root + '/proc/device-tree/serial-number').read_bytes()
        if raw:
            return raw.replace(b'\x00', b'').decode('utf-8', errors='ignore').strip()
    except Exception:
        pass
    return ''

# The salt lives where only root can write: a regular file (never a link) owned
# by the user running this, in a directory only that user can change.
salt = None
salt_path = Path(root + '/etc/autostream/dial-id-salt')

def _read_salt(path):
    me = os.geteuid()
    d = os.lstat(str(path.parent))
    if not stat.S_ISDIR(d.st_mode) or d.st_uid != me or d.st_mode & 0o022:
        raise ValueError('directory')
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != me or st.st_mode & 0o022:
            raise ValueError('file')
        return os.read(fd, 4096).decode('utf-8', errors='replace').strip()
    finally:
        os.close(fd)

if os.path.lexists(str(salt_path)):
    try:
        salt = _read_salt(salt_path)
    except Exception:
        salt = ''
    if not re.fullmatch(r'[0-9a-f]{32}', salt):
        print('ERROR: ' + str(salt_path) + ' does not hold a valid salt', file=sys.stderr)
        sys.exit(1)

serial = _get_cpu_serial().strip().lower()
if re.match(r'^[0-9a-f]+$', serial) and serial:
    base, from_serial = serial, True
else:
    from_serial = False
    fallback_path = state / 'dial-id'
    base = ''
    if fallback_path.exists():
        raw = fallback_path.read_text(encoding='utf-8').strip()
        if len(raw) == 20 and re.match(r'^[0-9a-f]+$', raw):
            base = raw
    if not base:
        # Create a new cryptographically secure fallback identity.
        base = secrets.token_hex(10)
        # The directory belongs to the service account, so the file is made
        # under a name nothing can already hold, mode and owner are set on
        # the open file, and the rename replaces whatever is at the final name.
        tmp = state / ('.dial-id.' + secrets.token_hex(8))
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o644)
            os.write(fd, base.encode('utf-8'))
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            os.unlink(str(tmp))
            raise
        os.close(fd)
        try:
            os.rename(str(tmp), str(fallback_path))
        except BaseException:
            os.unlink(str(tmp))
            raise

if salt is not None:
    text = 'autostream-dial-v1:' + base + ':' + salt
    print(hashlib.sha256(text.encode('utf-8')).hexdigest()[:20])
elif from_serial:
    print(hashlib.sha256(('autostream-dial-v1:' + base).encode('utf-8')).hexdigest()[:20])
else:
    print(base)
sys.exit(0)
PYEOF
}

write_dial_hw_config() {
    # Hardware + identity config — root-owned, service user can read, never writes it.
    # Run over an existing install it keeps the pins and the display profile
    # already in the file and refreshes only the identity.
    local uuid="$1" path
    path="$(_fs_root)/etc/autostream/autostream-dial.json"
    python3 - "$uuid" "$path" <<'PYEOF'
import json, sys
uuid, path = sys.argv[1], sys.argv[2]
cfg = None
try:
    with open(path, encoding='utf-8') as f:
        loaded = json.load(f)
    if isinstance(loaded, dict):
        cfg = loaded
except (OSError, ValueError):
    pass
if cfg is None:
    cfg = {
        "clk_gpio": 17,
        "dt_gpio":  27,
        "sw_gpio":  22,
        "led_gpio": None,
        "port":     7842,
        "uuid":     uuid
    }
cfg["uuid"] = uuid
with open(path, 'w') as f:
    json.dump(cfg, f, indent=2)
PYEOF
    chown root:autostream "${path}"
    chmod 0640 "${path}"
}

write_dial_settings() {
    # Runtime-mutable settings owned by the service user; a file already there
    # (the installer run over an existing install) is kept as it is.
    local path
    path="$(_state_dir)/dial-settings.json"
    python3 -c "
import json, os, sys
path = sys.argv[1]
defaults = {'step_percent': 2, 'name': '', 'pin': '', 'auto_update': False, 'update_channel': 'stable', 'sd_health_monitoring': False}
try:
    with open(path, encoding='utf-8') as f:
        keep = isinstance(json.load(f), dict)
except (OSError, ValueError):
    keep = False
if not keep:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(defaults, f, indent=2)
" "${path}"
    chown autostream:autostream "${path}"
    chmod 0600 "${path}"
}

detect_existing_dial_install() {
    # A fresh-install run over a dial that is already installed, or part
    # installed. Sets REINSTALL, which keeps the dial's settings and display
    # profile in place (write_dial_settings, write_dial_hw_config) and lets a
    # plain run keep an HD dial HD (detect_hd_install).
    REINSTALL=false
    if [[ "$(_install_state_value AUTOSTREAM_PRODUCT)" == autostream-dial \
          || -e "$(_fs_root)/etc/autostream/autostream-dial.json" \
          || -e "$(_state_dir)/dial-settings.json" ]]; then
        REINSTALL=true
    fi
}

# ---- HD dial (kiosk browser) -------------------------------------------------
#
# Everything below runs only when HD=true, which a fresh install gets from
# --hd and an --update from detect_hd_install(). An SPI dial runs none of the
# install steps; its only contact is retire_hd_kiosk(), which does nothing
# unless an earlier HD install left state behind.
KIOSK_USER="autostream-kiosk"
KIOSK_HOME="/var/lib/autostream-kiosk"
KIOSK_UNIT="autostream_dial_kiosk.service"
I2C_MODULES_FILE="autostream-dial-i2c.conf"

_hd_marker() { printf '%s\n' "$(_state_dir)/hd-kiosk"; }

detect_hd_install() {
    # --update: decide whether this dial is an HD (kiosk) dial from the display
    # profile it already runs, so an update keeps the kiosk set-up without any
    # flag. The mutable settings file's screen_type wins over the hardware
    # file's, as the dial's own config loader does. When the profile cannot be
    # read at all the marker an earlier HD install left decides, so a damaged
    # settings file never switches the kiosk off. Sets HD; never clears it.
    local verdict
    verdict="$(python3 - "$DEPLOY/dial" \
        "$(_fs_root)/etc/autostream/autostream-dial.json" \
        "$(_state_dir)/dial-settings.json" <<'PYEOF' 2>/dev/null || true
import json, sys
sys.path.insert(0, sys.argv[1])
try:
    from dial_display_profiles import DISPLAY_PROFILES
except Exception:
    print("unknown")
    sys.exit(0)

key = None
for path in (sys.argv[2], sys.argv[3]):
    try:
        with open(path, encoding="utf-8") as f:
            display = json.load(f).get("display")
    except Exception:
        continue
    if isinstance(display, dict) and isinstance(display.get("screen_type"), str):
        key = display["screen_type"]
profile = DISPLAY_PROFILES.get(key) if key else None
if profile is None:
    print("unknown")
else:
    print("kiosk" if profile.surface == "kiosk" else "spi")
PYEOF
    )"
    case "${verdict}" in
        kiosk) HD=true ;;
        spi) ;;
        *) if [[ -e "$(_hd_marker)" ]]; then HD=true; fi ;;
    esac
}

install_kiosk_packages() {
    # cog is the WPE WebKit launcher that draws the page straight to the
    # display (it pulls in the WebKit libraries); libgles2 is the GL library
    # its GLES renderer loads. Installed with the package manager's default
    # recommends, as it was proven.
    apt_step apt-get install -y cog libgles2 fonts-dejavu-core
}

create_kiosk_user() {
    # The browser's own account: no login shell, a home that holds only its
    # profile, and the groups it needs for the GPU and the touch panel. The
    # dial service additionally joins video to drive a sysfs backlight and
    # i2c to reach an HDMI panel's DDC bus.
    if ! id "${KIOSK_USER}" &>/dev/null; then
        useradd --system --create-home --home-dir "${KIOSK_HOME}" \
            --shell /usr/sbin/nologin "${KIOSK_USER}"
    fi
    local grp
    for grp in video input render; do
        usermod -aG "${grp}" "${KIOSK_USER}" 2>/dev/null || true
    done
    usermod -aG video autostream 2>/dev/null || true
    if getent group i2c >/dev/null 2>&1; then
        usermod -aG i2c autostream 2>/dev/null || true
    else
        echo "No i2c group on this system: an HDMI panel's backlight cannot be controlled over DDC."
    fi
    chown "${KIOSK_USER}:${KIOSK_USER}" "${KIOSK_HOME}"
    chmod 0750 "${KIOSK_HOME}"
}

_boot_config_append() {
    # Append LINE to config.txt where it applies to every board: plainly when
    # the file has no section headers or its last header is [all], otherwise
    # under a new [all] header, so the line can never land inside a trailing
    # conditional section such as [pi4] or [cm4].
    # Usage: _boot_config_append CONFIG_FILE LINE
    local cfg="$1" line="$2" last
    last="$(grep -E '^[[:space:]]*\[' "${cfg}" | tail -n 1 | tr -d '[:space:]' || true)"
    {
        if [[ -s "${cfg}" && -n "$(tail -c 1 "${cfg}")" ]]; then
            printf '\n'
        fi
        if [[ -n "${last}" && "${last}" != "[all]" ]]; then
            printf '[all]\n'
        fi
        printf '%s\n' "${line}"
    } >> "${cfg}" \
        || echo "WARNING: could not append ${line} to ${cfg} — set it manually" >&2
}

_boot_config_in_all() {
    # Succeeds when a line matching the extended regex PATTERN sits in the
    # unconditional part of config.txt (before any header, or under [all]).
    # Usage: _boot_config_in_all CONFIG_FILE PATTERN
    awk -v pat="$2" '
        /^[[:space:]]*\[/ { s = $0; gsub(/[[:space:]]/, "", s); cond = (s != "[all]") }
        !cond && $0 ~ pat { found = 1 }
        END { exit !found }' "$1"
}

write_boot_config_line() {
    # Make the unconditional part of config.txt (before any section header, or
    # under [all]) carry exactly one KEY=VALUE line for KEY: the first such
    # line is rewritten and extra copies dropped, otherwise the line is
    # appended where it applies to every board (see _boot_config_append). Lines
    # inside conditional sections are left alone. For single-valued keys such
    # as gpu_mem; overlays use ensure_boot_overlay. Non-fatal, like the other
    # boot-config helpers.
    # Usage: write_boot_config_line KEY VALUE [CONFIG_FILE]
    local key="$1" value="$2" cfg="${3:-/boot/firmware/config.txt}"
    local line="${key}=${value}" tmp
    if [[ ! -f "${cfg}" ]]; then
        echo "WARNING: ${cfg} not found — set ${line} in the boot config manually" >&2
        return 0
    fi
    if _boot_config_in_all "${cfg}" "^[[:space:]]*${key}="; then
        tmp="$(boot_file_stage "${cfg}")" \
            || { echo "WARNING: could not rewrite ${key} in ${cfg}" >&2; return 0; }
        awk -v pat="^[[:space:]]*${key}=" -v line="${line}" '
            /^[[:space:]]*\[/ { s = $0; gsub(/[[:space:]]/, "", s); cond = (s != "[all]") }
            !cond && $0 ~ pat { if (!done) { print line; done = 1 } next }
            { print }' "${cfg}" > "${tmp}" || { boot_file_discard "${tmp}"; return 0; }
        if cmp -s "${tmp}" "${cfg}"; then
            boot_file_discard "${tmp}"
        else
            boot_file_commit "${tmp}" "${cfg}" \
                || echo "WARNING: could not rewrite ${key} in ${cfg}" >&2
        fi
        return 0
    fi
    _boot_config_append "${cfg}" "${line}"
}

ensure_boot_overlay() {
    # Enable dtoverlay=NAME for every board unless an overlay of that name
    # (with or without parameters) is already enabled in the unconditional part
    # of config.txt; otherwise append it where it applies to every board.
    # Usage: ensure_boot_overlay NAME [CONFIG_FILE]
    local name="$1" cfg="${2:-/boot/firmware/config.txt}"
    if [[ ! -f "${cfg}" ]]; then
        echo "WARNING: ${cfg} not found — enable dtoverlay=${name} manually" >&2
        return 0
    fi
    if _boot_config_in_all "${cfg}" "^[[:space:]]*dtoverlay=${name}([[:space:]]*$|,)"; then
        return 0
    fi
    _boot_config_append "${cfg}" "dtoverlay=${name}"
}

configure_hd_boot() {
    # The kiosk browser needs the KMS graphics driver. Its graphics memory
    # comes from the kernel CMA pool, so gpu_mem is left as the system has it.
    # A DSI panel's own overlay is left to the owner.
    # Takes effect on the next boot.
    local cfg="${1:-/boot/firmware/config.txt}"
    ensure_boot_overlay vc4-kms-v3d "${cfg}"
}

# ---- Boot splash -------------------------------------------------------------
# A themed Plymouth splash on every dial: "Starting..." at boot and "Shutting
# down..." at shutdown and reboot on an HDMI or DSI screen. An SPI panel is
# driven from user space and is unaffected. Everything here is OS-level and
# idempotent; what the installer added is recorded in a state file so the
# uninstaller can take back exactly that.
#
# Every step helper returns 10 when it changed something and 0 when the
# system was already as wanted, so the initramfs is rebuilt only when needed.

PLYMOUTH_THEME="autostream-dial"
PLYMOUTH_THEME_FILES=(autostream-dial.plymouth autostream-dial.script starting.png shutting-down.png)
PLYMOUTH_PACKAGES=(plymouth plymouth-themes initramfs-tools)
# Order matters: the I2C bus module must load before the graphics driver.
PLYMOUTH_INITRAMFS_MODULES=(i2c_bcm2835 vc4)
PLYMOUTH_CMDLINE_TOKENS=(quiet splash plymouth.ignore-serial-consoles loglevel=3
    logo.nologo vt.global_cursor_default=0 consoleblank=0 systemd.show_status=0
    rd.systemd.show_status=0)
PLYMOUTH_DEVICE_TIMEOUT=20

_plymouth_state() { printf '%s\n' "$(_state_dir)/plymouth.state"; }
_plymouth_theme_dir() { printf '%s\n' "$(_fs_root)/usr/share/plymouth/themes/${PLYMOUTH_THEME}"; }
_plymouth_conf() { printf '%s\n' "$(_fs_root)/etc/plymouth/plymouthd.conf"; }
_plymouth_dropin() {
    printf '%s\n' "$(_fs_root)/etc/systemd/system/plymouth-quit.service.d/retain-splash.conf"
}

_ere_escape() {
    # Escape the characters that are special in an extended regex.
    printf '%s' "$1" | sed -E 's/[][^.$*+?(){}|\\]/\\&/g'
}

_plymouth_state_get() {
    # Print the value recorded for KEY, empty when there is none.
    local file
    file="$(_plymouth_state)"
    [[ -f "${file}" ]] || return 0
    sed -n "s/^$1=//p" "${file}" | tail -n 1
}

_plymouth_state_set() {
    # Record KEY=VALUE, replacing any earlier line for KEY.
    # Usage: _plymouth_state_set KEY VALUE
    local file tmp
    file="$(_plymouth_state)"
    mkdir -p "$(dirname "${file}")"
    tmp="$(mktemp)"
    if [[ -f "${file}" ]]; then
        grep -v "^$1=" "${file}" > "${tmp}" || true
    fi
    printf '%s=%s\n' "$1" "$2" >> "${tmp}"
    cat "${tmp}" > "${file}"
    rm -f "${tmp}"
}

_plymouth_state_add() {
    # Merge WORDs into the space-separated list recorded for KEY, so a re-run
    # never loses an earlier record.
    # Usage: _plymouth_state_add KEY WORD...
    local key="$1"
    shift
    (( $# > 0 )) || return 0
    local -a words=()
    read -r -a words <<< "$(_plymouth_state_get "${key}")"
    words+=("$@")
    _plymouth_state_set "${key}" "$(printf '%s\n' "${words[@]}" | sort -u | paste -sd' ' -)"
}

install_plymouth_packages() {
    # Plymouth, its script-plugin theme package and initramfs-tools. Those not
    # fully installed beforehand are recorded so the uninstaller purges only
    # what this installer brought in (a package left in the config-files state
    # does not count as installed).
    local pkg status
    local -a missing=()
    for pkg in "${PLYMOUTH_PACKAGES[@]}"; do
        status="$(dpkg-query -W -f='${db:Status-Status}' "${pkg}" 2>/dev/null || true)"
        [[ "${status}" == installed ]] || missing+=("${pkg}")
    done
    apt_step apt-get install -y --no-install-recommends "${PLYMOUTH_PACKAGES[@]}"
    if (( ${#missing[@]} > 0 )); then
        _plymouth_state_add packages_installed "${missing[@]}"
    fi
}

ensure_initramfs_modules() {
    # Make the initramfs module list carry PLYMOUTH_INITRAMFS_MODULES as whole
    # lines in that order, keeping every other line. Modules already present
    # are moved into order but not recorded as added.
    # Usage: ensure_initramfs_modules [MODULES_FILE]
    local file="${1:-$(_fs_root)/etc/initramfs-tools/modules}"
    local mod line prev=0 in_order=true tmp
    local -a absent=()
    for mod in "${PLYMOUTH_INITRAMFS_MODULES[@]}"; do
        line=""
        if [[ -f "${file}" ]]; then
            line="$(grep -nxF -- "${mod}" "${file}" | head -n 1 | cut -d: -f1 || true)"
        fi
        if [[ -z "${line}" ]]; then
            absent+=("${mod}")
            in_order=false
        elif (( line <= prev )); then
            in_order=false
        else
            prev="${line}"
        fi
    done
    if ${in_order}; then
        return 0
    fi
    mkdir -p "$(dirname "${file}")"
    tmp="$(mktemp)"
    if [[ -f "${file}" ]]; then
        grep -vxF -f <(printf '%s\n' "${PLYMOUTH_INITRAMFS_MODULES[@]}") "${file}" > "${tmp}" || true
    fi
    printf '%s\n' "${PLYMOUTH_INITRAMFS_MODULES[@]}" >> "${tmp}"
    if ! cat "${tmp}" > "${file}"; then
        echo "WARNING: could not update ${file} — add ${PLYMOUTH_INITRAMFS_MODULES[*]} to it manually" >&2
        rm -f "${tmp}"
        return 0
    fi
    rm -f "${tmp}"
    _plymouth_state_add modules_added "${absent[@]}"
    return 10
}

set_plymouth_device_timeout() {
    # Give plymouthd a bounded wait for a display device: on a dial with no
    # screen on the graphics driver it then gives up quickly instead of
    # holding the boot. The original file is kept once for the uninstaller.
    # Usage: set_plymouth_device_timeout [PLYMOUTHD_CONF]
    local file="${1:-$(_plymouth_conf)}"
    local line="DeviceTimeout=${PLYMOUTH_DEVICE_TIMEOUT}" tmp
    if [[ -f "${file}" ]] && awk -v line="${line}" '
            /^[[:space:]]*\[/ { s = $0; gsub(/[[:space:]]/, "", s); cur = s }
            cur == "[Daemon]" && $0 == line { found = 1 }
            END { exit !found }' "${file}"; then
        return 0
    fi
    if [[ -z "$(_plymouth_state_get plymouthd_conf)" ]]; then
        if [[ -f "${file}" ]]; then
            cp -p "${file}" "$(_state_dir)/plymouthd.conf.orig" \
                && _plymouth_state_set plymouthd_conf backup
        else
            _plymouth_state_set plymouthd_conf created
        fi
    fi
    mkdir -p "$(dirname "${file}")"
    tmp="$(mktemp)"
    if [[ -f "${file}" ]]; then
        cat "${file}" > "${tmp}"
    fi
    awk -v line="${line}" '
        /^[[:space:]]*DeviceTimeout=/ { next }
        { print }
        /^[[:space:]]*\[Daemon\][[:space:]]*$/ && !done { print line; done = 1 }
        END { if (!done) { print "[Daemon]"; print line } }' "${tmp}" > "${tmp}.new" \
        && cat "${tmp}.new" > "${file}" \
        || echo "WARNING: could not set ${line} in ${file}" >&2
    rm -f "${tmp}" "${tmp}.new"
    return 10
}

ensure_cmdline_tokens() {
    # Append the splash and quiet-boot tokens to the single kernel command
    # line. A key=value token counts as present whatever its value, so an
    # owner's own setting is left alone; only tokens added here are recorded.
    # Usage: ensure_cmdline_tokens [CMDLINE_FILE]
    local file="${1:-$(_fs_root)/boot/firmware/cmdline.txt}"
    local token pattern
    local -a added=()
    if [[ ! -f "${file}" ]]; then
        echo "WARNING: ${file} not found — add ${PLYMOUTH_CMDLINE_TOKENS[*]} to the kernel command line manually" >&2
        return 0
    fi
    for token in "${PLYMOUTH_CMDLINE_TOKENS[@]}"; do
        if [[ "${token}" == *=* ]]; then
            pattern="(^|[[:space:]])$(_ere_escape "${token%%=*}")="
        else
            pattern="(^|[[:space:]])$(_ere_escape "${token}")([[:space:]]|\$)"
        fi
        if grep -qE "${pattern}" "${file}"; then
            continue
        fi
        if sed -i -E "1 s/[[:space:]]*\$/ ${token}/" "${file}"; then
            added+=("${token}")
        else
            echo "WARNING: could not add ${token} to ${file}" >&2
        fi
    done
    if (( ${#added[@]} == 0 )); then
        return 0
    fi
    _plymouth_state_add cmdline_added "${added[@]}"
    return 10
}

remove_boot_config_line() {
    # Delete every KEY=... line from the unconditional part of config.txt
    # (before any section header, or under [all]); lines inside conditional
    # sections are left alone. The counterpart of write_boot_config_line.
    # Usage: remove_boot_config_line KEY [CONFIG_FILE]
    local key="$1" cfg="${2:-/boot/firmware/config.txt}" tmp
    [[ -f "${cfg}" ]] || return 0
    tmp="$(boot_file_stage "${cfg}")" \
        || { echo "WARNING: could not remove ${key} from ${cfg}" >&2; return 0; }
    awk -v pat="^[[:space:]]*${key}=" '
        /^[[:space:]]*\[/ { s = $0; gsub(/[[:space:]]/, "", s); cond = (s != "[all]") }
        !cond && $0 ~ pat { next }
        { print }' "${cfg}" > "${tmp}" || { boot_file_discard "${tmp}"; return 0; }
    if cmp -s "${tmp}" "${cfg}"; then
        boot_file_discard "${tmp}"
    else
        boot_file_commit "${tmp}" "${cfg}" \
            || echo "WARNING: could not remove ${key} from ${cfg}" >&2
    fi
}

set_disable_splash() {
    # Turn off the firmware's rainbow square. A different existing value is
    # the firmware default being undone, not an owner preference, so it is
    # rewritten; only an key_was_absent key is recorded as added.
    # Usage: set_disable_splash [CONFIG_FILE]
    local cfg="${1:-$(_fs_root)/boot/firmware/config.txt}"
    local before key_was_absent=false
    if [[ ! -f "${cfg}" ]]; then
        echo "WARNING: ${cfg} not found — set disable_splash=1 in the boot config manually" >&2
        return 0
    fi
    _boot_config_in_all "${cfg}" '^[[:space:]]*disable_splash=' || key_was_absent=true
    before="$(mktemp)"
    cat "${cfg}" > "${before}"
    write_boot_config_line disable_splash 1 "${cfg}"
    if cmp -s "${before}" "${cfg}"; then
        rm -f "${before}"
        return 0
    fi
    rm -f "${before}"
    if ${key_was_absent}; then
        _plymouth_state_add config_added disable_splash=1
    fi
    return 10
}

write_retain_splash_dropin() {
    # Quit Plymouth with its last frame retained, so the screen keeps the
    # splash until the kiosk browser paints over it.
    local path tmp
    path="$(_plymouth_dropin)"
    tmp="$(mktemp)"
    cat > "${tmp}" <<'DROPIN'
[Service]
ExecStart=
ExecStart=-/usr/bin/plymouth quit --retain-splash
DROPIN
    _plymouth_state_set dropin 1
    if [[ -f "${path}" ]] && cmp -s "${tmp}" "${path}"; then
        rm -f "${tmp}"
        return 0
    fi
    mkdir -p "$(dirname "${path}")"
    if ! install -m 0644 "${tmp}" "${path}"; then
        echo "WARNING: could not write ${path}" >&2
    fi
    rm -f "${tmp}"
    return 10
}

install_plymouth_theme() {
    # Install the theme files from the checkout, replacing only those that
    # differ.
    local dir name src changed=false
    local -a own=()
    [[ "${EUID:-$(id -u)}" -eq 0 ]] && own=(-o root -g root)
    dir="$(_plymouth_theme_dir)"
    mkdir -p "${dir}"
    for name in "${PLYMOUTH_THEME_FILES[@]}"; do
        src="${DEPLOY}/system/plymouth/${PLYMOUTH_THEME}/${name}"
        if [[ -f "${dir}/${name}" ]] && cmp -s "${src}" "${dir}/${name}"; then
            continue
        fi
        if install -m 0644 ${own[@]+"${own[@]}"} "${src}" "${dir}/${name}"; then
            changed=true
        else
            echo "WARNING: could not install ${name} into ${dir}" >&2
        fi
    done
    _plymouth_state_set theme "${PLYMOUTH_THEME}"
    if ${changed}; then
        return 10
    fi
    return 0
}

apply_plymouth_theme() {
    # Make the theme the default and rebuild the initramfs of the running
    # kernel when something changed, or when the last rebuild was for another
    # kernel. A failure warns and leaves the previous initramfs in place, so
    # the dial still boots; the next run retries.
    # Usage: apply_plymouth_theme CHANGED   (true or false)
    local changed="${1:-false}" current kernel
    if ! command -v plymouth-set-default-theme >/dev/null 2>&1; then
        echo "WARNING: plymouth-set-default-theme not found — the boot splash is not applied" >&2
        return 0
    fi
    current="$(plymouth-set-default-theme 2>/dev/null || true)"
    if [[ "${current}" != "${PLYMOUTH_THEME}" ]]; then
        if ! plymouth-set-default-theme "${PLYMOUTH_THEME}"; then
            echo "WARNING: could not set the ${PLYMOUTH_THEME} boot theme" >&2
            return 0
        fi
        changed=true
    fi
    kernel="$(uname -r)"
    if [[ "${changed}" != true && "$(_plymouth_state_get initramfs_kernel)" == "${kernel}" ]]; then
        return 0
    fi
    if ! command -v update-initramfs >/dev/null 2>&1; then
        echo "WARNING: update-initramfs not found — the boot splash needs an initramfs rebuild" >&2
        return 0
    fi
    phase configure 82 "Configuring the boot splash (this may take a few minutes)..."
    if update-initramfs -u -k "${kernel}"; then
        _plymouth_state_set initramfs_kernel "${kernel}"
    else
        echo "WARNING: could not rebuild the initramfs for ${kernel}" >&2
    fi
    return 0
}

configure_plymouth() {
    # Every boot-splash step in order, then one theme apply and rebuild when
    # any of them changed something. Step status 10 means "changed".
    local changed=false rc step
    for step in ensure_initramfs_modules set_plymouth_device_timeout \
                ensure_cmdline_tokens set_disable_splash \
                write_retain_splash_dropin install_plymouth_theme; do
        rc=0
        "${step}" || rc=$?
        if (( rc == 10 )); then
            changed=true
        fi
    done
    apply_plymouth_theme "${changed}"
}

revert_plymouth() {
    # Undo exactly what the boot splash steps recorded in the state file, in
    # reverse of how it was set up, then remove the state file. Every step
    # tolerates "already gone", and a dial with no state file (installed
    # before the splash existed, or already reverted) is left alone.
    local state value word mod token pkg conf orig cfg cmdline modules tmp
    local -a words=() pkgs=()
    state="$(_plymouth_state)"
    [[ -f "${state}" ]] || return 0
    conf="$(_plymouth_conf)"
    orig="$(_state_dir)/plymouthd.conf.orig"
    cfg="$(_fs_root)/boot/firmware/config.txt"
    cmdline="$(_fs_root)/boot/firmware/cmdline.txt"
    modules="$(_fs_root)/etc/initramfs-tools/modules"

    if [[ "$(_plymouth_state_get dropin)" == 1 ]]; then
        rm -f "$(_plymouth_dropin)"
        rmdir --ignore-fail-on-non-empty "$(dirname "$(_plymouth_dropin)")" 2>/dev/null || true
    fi

    value="$(_plymouth_state_get plymouthd_conf)"
    case "${value}" in
        backup) [[ -f "${orig}" ]] && { cp -p "${orig}" "${conf}" || true; } ;;
        created) rm -f "${conf}" ;;
        "") ;;
        *) [[ -f "${conf}" ]] && { sed -i "/^[[:space:]]*DeviceTimeout=${PLYMOUTH_DEVICE_TIMEOUT}\$/d" "${conf}" || true; } ;;
    esac

    read -r -a words <<< "$(_plymouth_state_get modules_added)"
    if [[ -f "${modules}" ]]; then
        for mod in ${words[@]+"${words[@]}"}; do
            tmp="$(mktemp)"
            grep -vxF -- "${mod}" "${modules}" > "${tmp}" || true
            cat "${tmp}" > "${modules}" || true
            rm -f "${tmp}"
        done
    fi

    read -r -a words <<< "$(_plymouth_state_get cmdline_added)"
    if [[ -f "${cmdline}" && ${#words[@]} -gt 0 ]]; then
        for token in "${words[@]}"; do
            sed -i -E "s/(^|[[:space:]])$(_ere_escape "${token}")([[:space:]]|\$)/\1\2/g" "${cmdline}" || true
        done
        sed -i -E '1 s/[[:space:]]+/ /g; 1 s/^ //; 1 s/ $//' "${cmdline}" || true
    fi

    read -r -a words <<< "$(_plymouth_state_get config_added)"
    for word in ${words[@]+"${words[@]}"}; do
        if [[ "${word}" == disable_splash=1 ]]; then
            remove_boot_config_line disable_splash "${cfg}"
        fi
    done

    rm -rf "$(_plymouth_theme_dir)"
    if command -v plymouth-set-default-theme >/dev/null 2>&1 \
            && [[ "$(plymouth-set-default-theme 2>/dev/null || true)" == "${PLYMOUTH_THEME}" ]]; then
        plymouth-set-default-theme -r || true
    fi

    read -r -a pkgs <<< "$(_plymouth_state_get packages_installed)"
    if (( ${#pkgs[@]} > 0 )); then
        apt-get purge -y "${pkgs[@]}" || true
    fi

    if command -v update-initramfs >/dev/null 2>&1; then
        update-initramfs -u -k "$(uname -r)" || true
    fi

    rm -f "${state}" "${orig}"
}

write_hd_display_config() {
    # An --hd install: the hardware file's display block selects the HD
    # profile with no SPI panel and no touch driver, so the dial runs headless
    # and serves the page. Keeps the file's owner and mode and any other
    # display settings already in the block. A display block in the dial's own
    # settings file overrides the hardware file's, so one left by an earlier
    # SPI set-up is switched to the HD profile too.
    python3 - "$(_fs_root)/etc/autostream/autostream-dial.json" \
        "$(_state_dir)/dial-settings.json" <<'PYEOF'
import json, sys
hd = {'fitted': True, 'screen_type': 'hd_kiosk', 'touch_type': 'none'}
path = sys.argv[1]
with open(path, encoding='utf-8') as f:
    cfg = json.load(f)
display = cfg.get('display')
cfg['display'] = {**display, **hd} if isinstance(display, dict) else dict(hd)
with open(path, 'w', encoding='utf-8') as f:
    json.dump(cfg, f, indent=2)
try:
    with open(sys.argv[2], encoding='utf-8') as f:
        settings = json.load(f)
except (OSError, ValueError):
    settings = None
if isinstance(settings, dict) and isinstance(settings.get('display'), dict):
    settings['display'].update(hd)
    with open(sys.argv[2], 'w', encoding='utf-8') as f:
        json.dump(settings, f, indent=2)
PYEOF
}

write_hd_marker() {
    # The kiosk unit's start condition; see the unit's header.
    install -m 0644 -o root -g root /dev/null "$(_hd_marker)"
}

deploy_kiosk_unit() {
    # The unit is enabled, not started: the kiosk comes up on the reboot that
    # ends every install and update. The udev rule is applied to a backlight
    # already present so a fresh install needs no extra reboot for it, and
    # i2c-dev (the HDMI panel's DDC bus) is loaded now as well as at boot.
    local root
    root="$(_fs_root)"
    install -m 0644 -o root -g root "$DEPLOY/system/systemd/${KIOSK_UNIT}" \
        "${root}/etc/systemd/system/${KIOSK_UNIT}"
    install -D -m 0644 -o root -g root "$DEPLOY/system/udev/99-autostream-backlight.rules" \
        "${root}/etc/udev/rules.d/99-autostream-backlight.rules"
    install -D -m 0644 -o root -g root "$DEPLOY/system/modules-load.d/${I2C_MODULES_FILE}" \
        "${root}/etc/modules-load.d/${I2C_MODULES_FILE}"
    modprobe i2c-dev 2>/dev/null || true
    udevadm control --reload 2>/dev/null || true
    udevadm trigger --subsystem-match=backlight --action=add 2>/dev/null || true
    systemctl daemon-reload
    systemctl enable "${KIOSK_UNIT}"
}

retire_hd_kiosk() {
    # An SPI dial that was once an HD dial (its profile was changed, then it
    # updated): switch the kiosk off. Nothing happens on a dial that never was.
    local root marker
    root="$(_fs_root)"
    marker="$(_hd_marker)"
    if [[ -e "${marker}" || -e "${root}/etc/systemd/system/${KIOSK_UNIT}" ]]; then
        systemctl disable --now "${KIOSK_UNIT}" 2>/dev/null || true
        rm -f "${marker}"
    fi
}

has_tty() {
    # /dev/tty is readable and writable even when the process has no
    # controlling terminal (a service, cron, ssh without -t), so the check
    # that counts is whether it can be opened.
    [[ -r /dev/tty && -w /dev/tty ]] && { : < /dev/tty; } 2>/dev/null
}

tty_read() {
    local prompt="$1" __var="$2"
    IFS= read -r -p "${prompt}" "${__var}" < /dev/tty
}

# ---- Uninstaller guards -------------------------------------------------------
# The dial uninstaller deletes shared paths (/opt/autostream, /var/lib/autostream,
# /usr/local/libexec/autostream and the service user), so it checks who is
# running it, what it is running on and, unless told not to ask, whether the
# owner means it. Wording follows the appliance uninstaller.

require_root_user() {
    # Usage: require_root_user SCRIPT_NAME
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "[ERROR] This script must be run as root (e.g. sudo ./${1:-autostream_dial_uninstall.sh})." >&2
        exit 1
    fi
}

require_dial_install() {
    # Proceed only on a dial install. The installer's state file names the
    # product; where it is absent (an install that stopped before writing it)
    # the dial's own hardware file or service unit shows a dial was started.
    local product root
    product="$(_install_state_value AUTOSTREAM_PRODUCT)"
    root="$(_fs_root)"
    case "${product}" in
        autostream-dial) return 0 ;;
        "")
            if [[ -e "${root}/etc/autostream/autostream-dial.json" \
                  || -e "${root}/etc/systemd/system/autostream_dial.service" ]]; then
                return 0
            fi
            echo "[ERROR] No autostream dial installation found on this device; nothing was removed." >&2
            exit 1
            ;;
        *)
            echo "[ERROR] This device is an autostream installation of another kind (${product}), not a dial." >&2
            echo "[ERROR] This script would remove files the appliance shares; nothing was removed." >&2
            echo "[ERROR] Use autostream_uninstall.sh to remove an appliance." >&2
            exit 1
            ;;
    esac
}

confirm_dial_uninstall() {
    # Usage: confirm_dial_uninstall ASSUME_YES (true when --yes was given)
    cat <<'EOF'

=============================================================================
AUTOSTREAM DIAL UNINSTALLER
=============================================================================
This script removes the autostream dial software from this device, including
the dial's name, PIN and settings, and its identity files. Installed packages
and boot configuration are not undone.
=============================================================================
EOF
    if [[ "${1:-false}" == true ]]; then
        echo "[INFO] --yes given; continuing without confirmation."
        return 0
    fi
    if ! has_tty; then
        echo "[ERROR] Interactive confirmation requires a TTY (or pass --yes to continue without one)." >&2
        exit 1
    fi
    local ans
    tty_read "Continue with uninstall? (Y/N) " ans || true
    case "${ans:-N}" in
        Y|y) ;;
        *) echo "[ERROR] Aborted by user." >&2; exit 1 ;;
    esac
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
- Install a boot and shutdown splash (shown on an HDMI or DSI screen)

WARNING:
- Use ONLY on a dedicated Raspberry Pi running Raspberry Pi OS Lite (Trixie).
- Use on a clean image only.
- Do NOT run on machines containing important data or multi-purpose systems.

A full activity log will be written to ~/autostream_dial_install.log and
/var/log/autostream/dial-install.log
=============================================================================
EOF
    [[ "${HD:-false}" == true ]] && echo "HD dial: also installs the kiosk browser (cog) and its service."
    [[ "${REINSTALL:-false}" == true ]] && echo "An existing dial installation was found: its name, PIN and settings are kept."

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
    # The Zero expectation is for the SPI dial; an HD dial runs on a larger Pi.
    [[ "${HD:-false}" == true ]] && return 0
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
    # Headers and a compiler for source builds in build_venv().
    # adafruit-circuitpython-rgb-display pulls in sysv-ipc (via adafruit-blinka),
    # which publishes no armv7l wheel — on 32-bit images pip compiles it from the
    # sdist, and without Python.h the pip step fails and aborts the whole install.
    # python3-dev transitively supplies libc6-dev, so gcc needs no build-essential.
    # Called unconditionally (fresh install and --update) because build_venv() is:
    # dials installed from a 32-bit image before this existed must acquire it on
    # their next update, or that update's pip step fails the same way.
    apt_step apt-get install -y --no-install-recommends python3-dev gcc
}

# ---- Update staging: paths and on-disk contract ------------------------------
#
# An --update never touches the running code tree or venv. The new version is
# staged beside them and a root oneshot at the next boot (before the dial
# service starts) swaps it in. Everything that oneshot consumes is here.
#
# Under /opt/autostream (all on one filesystem, so every switch is a rename):
#   .next/           the complete new flat code set, plus .next/MANIFEST
#   .next/MANIFEST   one line per file, tab separated: MODE, OWNER:GROUP, PATH
#                    (PATH relative to the tree root, e.g.
#                    0644<TAB>root:root<TAB>dial_main.py); directories are
#                    implied by the paths and made on demand
#   .prev/           files displaced by the previous swap (removed when the
#                    next update starts)
#   .manifest        manifest of the installed set (written by the swap)
#   venv.<tag>/      one real venv per installed version, built at its final
#                    path; `venv` is a symlink to the active one. The first
#                    update of an older install finds a real `venv` directory.
#
# Under /var/lib/autostream-update, which only root can write (the service
# account owns /var/lib/autostream and could replace anything the boot step
# is about to act on if it were kept there):
#   update-in-progress  marker written when the update starts, holding the
#                    release tag. The boot step acts on the hand-off below, or
#                    retries an interrupted run, only while it is there. It is
#                    removed once the update has a final result.
#   update-prev/     backup of every file this installer owns outside the tree
#     MANIFEST       one line per path, tab separated: PRESENT or ABSENT, then
#                    the absolute path. ABSENT means the file did not exist
#                    before the update, so a restore removes it. The manifest
#                    is written last, so a partial backup is never restored.
#     files/<path>   the saved copy of each PRESENT path (cp -a)
#   update-swap.env  KEY=VALUE hand-off to the boot step, written once
#                    everything above is complete:
#     PHASE          staged
#     TAG            release being installed
#     PREVIOUS_TAG   release installed before (may be empty)
#     VENV           venv directory name the new version runs from
#     PREVIOUS_VENV  directory name the previous version's venv has after the
#                    swap
#     VENV_MIGRATE   1 when the live `venv` is a real directory that must be
#                    renamed to PREVIOUS_VENV before the symlink is made;
#                    0 otherwise. When VENV is `venv` (a real directory kept
#                    because its requirements are unchanged) there is
#                    nothing to switch.
#
# AUTOSTREAM_FS_ROOT prefixes every path (tests use a scratch root);
# AUTOSTREAM_OPT_DIR, AUTOSTREAM_STATE_DIR and AUTOSTREAM_UPDATE_DIR override the
# three directories individually; AUTOSTREAM_ADMIN_BIN overrides the admin wrapper.
_fs_root()   { local r="${AUTOSTREAM_FS_ROOT:-}"; printf '%s\n' "${r%/}"; }
_opt_dir()   { printf '%s\n' "${AUTOSTREAM_OPT_DIR:-$(_fs_root)/opt/autostream}"; }
_state_dir() { printf '%s\n' "${AUTOSTREAM_STATE_DIR:-$(_fs_root)/var/lib/autostream}"; }
# The root-only directory the staged release and the boot hand-off live in.
_update_dir() { printf '%s\n' "${AUTOSTREAM_UPDATE_DIR:-$(_fs_root)/var/lib/autostream-update}"; }
_admin_bin() {
    printf '%s\n' "${AUTOSTREAM_ADMIN_BIN:-$(_fs_root)/usr/local/libexec/autostream/autostream_admin}"
}

dial_image_names() {
    # The images the dial installs under /opt/autostream/images, one per line:
    # the single list behind both the install and the owned-file backup, so a
    # file one of them knows about cannot be missing from the other.
    printf '%s\n' autostream-dial-badge.png favicon.ico favicon-16x16.png \
                  favicon-32x32.png autostream-logo-centred-dark.png \
                  autostream-logo-replay-dark.png
}

install_dial_images() {
    # Install every image from dial_image_names into the images directory.
    local dir name
    dir="$(_opt_dir)/images"
    mkdir -p "${dir}"
    for name in $(dial_image_names); do
        install -m 0644 "$DEPLOY/images/${name}" "${dir}/"
    done
}

install_code_tree() {
    # Install every code file the dial runs from /opt/autostream into DEST:
    # the shared core modules, the wifi_* siblings, the dial package, the
    # control CLI module and the wifi watcher.
    # Usage: install_code_tree DEST
    local dest="$1" name
    local -a own=()
    [[ "${EUID:-$(id -u)}" -eq 0 ]] && own=(-o root -g root)
    mkdir -p "${dest}"
    # autostream_rpi.py is a re-export shim over the four modules its concerns
    # were split into; it imports all four at import time, so a dial-only
    # install must deploy them alongside it or dial_main's
    # setup_rotary_encoder/setup_button import (and wifi_watcher's check_cpu
    # import) fails at startup. dial_display imports the shared artwork fetch
    # from autostream_artwork; without it the dial cannot start. The Wi-Fi
    # recovery helper is deployed alongside the watcher so the recovery
    # executable's import resolves on every install/update.
    for name in autostream_rpi autostream_system_stats autostream_appliance_identity \
                autostream_licensing autostream_dial_gpio autostream_sysutils \
                autostream_mdns autostream_artwork autostream_wifi_network; do
        install -m 0644 ${own[@]+"${own[@]}"} "$DEPLOY/core/${name}.py" "${dest}/${name}.py"
    done
    # wifi_watcher's split sibling modules (imported beside it).
    for name in wifi_state wifi_status wifi_recovery wifi_policy wifi_mdns wifi_nm \
                wifi_hotspot wifi_config wifi_activation wifi_adoption wifi_loop wifi_web; do
        install -m 0644 ${own[@]+"${own[@]}"} "$DEPLOY/platform/${name}.py" "${dest}/${name}.py"
    done
    cp -a --no-preserve=ownership "$DEPLOY/dial/." "${dest}/"
    find "${dest}" -name __pycache__ -type d -prune -exec rm -rf {} +
    [[ ${#own[@]} -eq 0 ]] || chown -R root:root "${dest}"
    install -m 0644 ${own[@]+"${own[@]}"} "$DEPLOY/dial/autostream_dial_control.py" \
        "${dest}/autostream_dial_control.py"
    # The HD page shares the appliance WebUI's stylesheet and serves it from
    # beside the page files, so it travels with the staged code set.
    mkdir -p "${dest}/hd"
    install -m 0644 ${own[@]+"${own[@]}"} "$DEPLOY/nginx/static/theme.css" "${dest}/hd/theme.css"
    install -m 0755 ${own[@]+"${own[@]}"} "$DEPLOY/platform/wifi_watcher.py" \
        "${dest}/autostream_wifi_watcher"
    sed -i 's/\r$//' "${dest}/autostream_wifi_watcher"
}

write_code_manifest() {
    # List every regular file under DIR (bytecode and the manifest itself
    # excluded) as MODE<TAB>OWNER:GROUP<TAB>RELATIVE_PATH, sorted by path.
    # Usage: write_code_manifest DIR OUTFILE
    local dir="$1" out="$2" tmp
    tmp="${out}.tmp.$$"
    ( cd "${dir}" && find . -type f ! -path './MANIFEST*' ! -path '*/__pycache__/*' \
        ! -name '*.pyc' -printf '0%m\t%u:%g\t%P\n' ) \
        | LC_ALL=C sort -t $'\t' -k3 > "${tmp}"
    mv -f "${tmp}" "${out}"
}

stage_code_tree() {
    # Build the new code set in .next with its manifest. Nothing the running
    # dial has imported or will import lazily is touched.
    local opt
    opt="$(_opt_dir)"
    rm -rf "${opt}/.next" "${opt}/.prev"
    install_code_tree "${opt}/.next"
    write_code_manifest "${opt}/.next" "${opt}/.next/MANIFEST"
}

requirements_lock_sha256() {
    # Digest of the file the venv is built from.
    local file="$DEPLOY/dial/requirements.lock"
    [[ -f "${file}" ]] || file="$DEPLOY/dial/requirements.txt"
    sha256sum "${file}" | cut -d' ' -f1
}

_install_state_value() {
    # Value of KEY in install-state.env; empty when absent.
    local state="${INSTALL_STATE_FILE:-/var/lib/autostream/install-state.env}"
    [[ -r "${state}" ]] || return 0
    grep -m 1 "^$1=" "${state}" 2>/dev/null | cut -d= -f2- || true
}

_sanitise_tag() {
    printf '%s\n' "${1//[^A-Za-z0-9._-]/_}"
}

build_venv() {
    # Create a venv at DIR and install the dial's Python requirements into it.
    # pip runs as `python -m pip`, never the console script, so nothing depends
    # on the directory name baked into a script shebang.
    # --system-site-packages: exposes apt-installed python3-lgpio to the venv.
    # Usage: build_venv DIR
    local dir="$1" py
    py="${dir}/bin/python"
    python3 -m venv --system-site-packages "${dir}"
    "${py}" -m pip install --quiet -U pip
    # Prefer hash-locked requirements for reproducible builds.  Fall back to
    # pinned requirements.txt with a warning.
    if [[ -f "$DEPLOY/dial/requirements.lock" ]]; then
        "${py}" -m pip install --quiet \
            --require-hashes -r "$DEPLOY/dial/requirements.lock"
    else
        echo "WARNING: requirements.lock not found; installing from requirements.txt (not hash-pinned)" >&2
        "${py}" -m pip install --quiet \
            -r "$DEPLOY/dial/requirements.txt"
    fi
}

prepare_update_venv() {
    # Decide which venv the new version runs from, building one when needed.
    # Sets NEW_VENV, PREVIOUS_VENV, VENV_MIGRATE, VENV_BUILT and
    # VENV_LOCK_SHA256 (read by write_install_state).
    # The current venv is reused when the requirements digest recorded by the
    # last install matches; otherwise a new venv.<tag> is built at its final
    # path beside it. Venvs older than the active one cannot be rolled back
    # to any more, so they are removed first to make room on a small card.
    local opt venv current="" name candidate migrate_name="" prev_tag recorded
    opt="$(_opt_dir)"
    venv="${opt}/venv"
    VENV_BUILT=false
    VENV_MIGRATE=0
    VENV_LOCK_SHA256="$(requirements_lock_sha256)"
    if [[ -L "${venv}" ]]; then
        current="$(basename "$(readlink "${venv}")")"
    elif [[ -d "${venv}" ]]; then
        current="venv"
    fi
    recorded="$(_install_state_value REQUIREMENTS_LOCK_SHA256)"
    if [[ -n "${current}" && -x "${venv}/bin/python" && -n "${recorded}" \
          && "${recorded}" == "${VENV_LOCK_SHA256}" ]]; then
        echo "Python requirements unchanged; reusing ${current}"
        NEW_VENV="${current}"
        PREVIOUS_VENV="${current}"
        return 0
    fi
    for candidate in "${opt}"/venv.*; do
        [[ -e "${candidate}" || -L "${candidate}" ]] || continue
        [[ "$(basename "${candidate}")" == "${current}" ]] && continue
        rm -rf "${candidate}"
    done
    PREVIOUS_VENV="${current}"
    if [[ "${current}" == "venv" ]]; then
        prev_tag="$(_update_result_value PREVIOUS_TAG)"
        [[ -n "${prev_tag}" ]] || prev_tag="${PREVIOUS_RELEASE_TAG:-}"
        prev_tag="$(_sanitise_tag "${prev_tag}")"
        migrate_name="venv.${prev_tag:-previous}"
        PREVIOUS_VENV="${migrate_name}"
        VENV_MIGRATE=1
    fi
    name="venv.$(_sanitise_tag "${AUTOSTREAM_RELEASE_TAG:-unknown}")"
    while [[ "${name}" == "${current}" || "${name}" == "${migrate_name}" ]]; do
        name="${name}.1"
    done
    NEW_VENV="${name}"
    VENV_BUILT=true
    build_venv "${opt}/${name}"
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
    [[ -r "${file}" && ! -L "${file}" ]] || return 0
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
    [[ -r "${state}" && ! -L "${state}" ]] || return 0
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
    local file last_run_at key arg value line owner=""
    local -A kv=()
    file="$(_update_result_file)"
    message="${message//$'\n'/ }"
    if [[ -r "${file}" && ! -L "${file}" ]]; then
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
    # An existing result file keeps its owner.
    if [[ -f "${file}" && ! -L "${file}" ]]; then
        owner="$(stat -c '%u:%g' -- "${file}" 2>/dev/null || true)"
    fi
    {
        printf 'STATUS=%s\nPERCENT_COMPLETE=%s\nMESSAGE=%s\nLAST_RUN_AT=%s\n' \
            "${status}" "${percent}" "${message}" "${last_run_at}"
        for key in "${UPDATE_RESULT_KEYS[@]}"; do
            if [[ -n "${kv[${key}]+set}" ]]; then
                printf '%s=%s\n' "${key}" "${kv[${key}]}"
            fi
        done
    } | write_state_file "${file}" 0644 "${owner}"
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
        staged|reboot) step="finishing" ;;
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

refresh_package_lists() {
    # Fetch the current package lists, as the appliance installer does before
    # it installs anything: a freshly written card can carry lists that are
    # empty or out of date, and an install against them stops at "Unable to
    # locate package" or a 404. Runs once per install or update, ahead of the
    # first package step. When the lists cannot be fetched (no network) the
    # installer stops here, before a package has been touched.
    if ! apt_step apt-get update; then
        echo "ERROR: could not refresh the package lists; check the network connection and run the installer again." >&2
        return 1
    fi
}

system_upgrade() {
    # Refresh the package index and upgrade installed packages, as the
    # appliance installer does; needrestart is told only to list, never to
    # restart services mid-install. Then trim the downloaded package cache,
    # since the card is small.
    # The first apt command of an update: finish any interrupted package run
    # first, or the upgrade below is refused for it.
    recover_interrupted_packages
    refresh_package_lists
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

owned_files_list() {
    # Every file this installer writes outside the code tree and the venv,
    # one absolute path per line. The restore after a failed run (or a failed
    # first boot) covers exactly these. Not listed on purpose: boot
    # configuration (additive, idempotent and tolerated by older software),
    # the boot splash (theme, drop-in, module list, plymouthd.conf and its
    # state file: OS-level like the boot configuration), installed packages,
    # the sdmon binary, the cloud-init flag and group memberships.
    local opt unit name
    opt="/opt/autostream"
    for name in autostream_admin autostream_dial_updater autostream_update_support.py \
                autostream_storage_guard autostream_sdcardhealth; do
        printf '%s\n' "/usr/local/libexec/autostream/${name}"
    done
    printf '%s\n' /usr/local/bin/autostream-dial-control
    for unit in autostream_dial.service autostream_dial_wifi_watcher.service \
                autostream_dial_dnsmasq.service autostream_dial_updater.service \
                autostream_dial_updater.timer autostream_dial_update_recover.service \
                autostream_storage_guard.service autostream_storage_guard.timer \
                autostream_sdcardhealth.service autostream_sdcardhealth.timer \
                autostream_sdcardhealth_boot.service; do
        printf '%s\n' "/etc/systemd/system/${unit}"
    done
    printf '%s\n' /etc/nginx/sites-available/autostream-dial \
                  /etc/nginx/sites-enabled/autostream-dial \
                  /usr/local/share/autostream/avahi/autostream-dial.service \
                  /etc/avahi/services/autostream-dial.service \
                  /usr/local/share/autostream/dnsmasq/autostream-dial-setup.conf \
                  /etc/sudoers.d/autostream_dial \
                  /etc/logrotate.d/autostream-dial \
                  /etc/systemd/journald.conf.d/99-autostream-storage.conf \
                  /etc/systemd/coredump.conf.d/99-autostream-coredump.conf \
                  /etc/rpi/swap.conf.d/99-autostream-swap.conf \
                  /etc/NetworkManager/dispatcher.d/99-wlan-fix \
                  /etc/NetworkManager/conf.d/wifi-powersave.conf \
                  /etc/sysctl.d/90-autostream-swappiness.conf \
                  /etc/systemd/logind.conf.d/90-autostream-ignore-power-key.conf \
                  /var/lib/autostream/install-state.env
    for name in $(dial_image_names); do
        printf '%s\n' "${opt}/images/${name}"
    done
    # Offline pages are listed from the incoming release so a page it adds
    # is recorded as absent; one an older release shipped and this one drops
    # stays in place either way.
    for name in "$DEPLOY"/nginx/offline/*.html; do
        [[ -e "${name}" ]] || continue
        printf '%s\n' "${opt}/nginx/offline/$(basename "${name}")"
    done
    for name in reboot.cgi factory-reset.cgi update-status.cgi download-logs.cgi; do
        printf '%s\n' "${opt}/nginx/cgi/${name}"
    done
    # An HD dial also owns its kiosk unit, backlight rule, i2c module file and
    # start marker.
    if [[ "${HD:-false}" == true ]]; then
        printf '%s\n' "/etc/systemd/system/${KIOSK_UNIT}" \
                      /etc/udev/rules.d/99-autostream-backlight.rules \
                      "/etc/modules-load.d/${I2C_MODULES_FILE}" \
                      /var/lib/autostream/hd-kiosk
    fi
}

backup_owned_files() {
    # Save every owned file into update-prev with a manifest; a path that does
    # not exist yet is recorded ABSENT so a restore removes what the update
    # adds. The directory is rebuilt from scratch and the manifest is moved
    # into place last.
    local root dir path
    root="$(_fs_root)"
    BACKUP_DIR="$(_update_dir)/update-prev"
    dir="${BACKUP_DIR}"
    BACKUP_TAKEN=false
    rm -rf "${dir}"
    mkdir -p "${dir}/files"
    chmod 0700 "${dir}"
    : > "${dir}/MANIFEST.tmp"
    while IFS= read -r path; do
        if [[ -e "${root}${path}" || -L "${root}${path}" ]]; then
            mkdir -p "${dir}/files$(dirname "${path}")"
            cp -a "${root}${path}" "${dir}/files${path}"
            printf 'PRESENT\t%s\n' "${path}" >> "${dir}/MANIFEST.tmp"
        else
            printf 'ABSENT\t%s\n' "${path}" >> "${dir}/MANIFEST.tmp"
        fi
    done < <(owned_files_list)
    mv -f "${dir}/MANIFEST.tmp" "${dir}/MANIFEST"
    BACKUP_TAKEN=true
}

restore_owned_files() {
    # Put back every file recorded by backup_owned_files, remove those
    # recorded ABSENT, then make systemd and nginx pick the restored files up.
    # Best effort: one failed copy does not stop the rest.
    # Usage: restore_owned_files [BACKUP_DIR]
    local dir root state path
    dir="${1:-${BACKUP_DIR:-$(_update_dir)/update-prev}}"
    root="$(_fs_root)"
    [[ -f "${dir}/MANIFEST" ]] || return 0
    while IFS=$'\t' read -r state path; do
        [[ -n "${path}" ]] || continue
        case "${state}" in
            PRESENT)
                mkdir -p "$(dirname "${root}${path}")" || true
                cp -a --remove-destination "${dir}/files${path}" "${root}${path}" \
                    || echo "WARNING: could not restore ${path}" >&2
                ;;
            ABSENT)
                rm -f "${root}${path}" || true
                ;;
        esac
    done < "${dir}/MANIFEST"
    systemctl daemon-reload || true
    if nginx -t; then
        systemctl restart nginx || true
    fi
    return 0
}

write_update_swap() {
    # Hand the staged update to the boot step (contract above). Reads TAG,
    # previous tag and the venv decision from the installer's variables.
    local file tmp previous
    previous="$(_update_result_value PREVIOUS_TAG)"
    previous="${previous:-${PREVIOUS_RELEASE_TAG:-}}"
    file="$(_update_dir)/update-swap.env"
    tmp="${file}.tmp.$$"
    {
        printf 'PHASE=staged\n'
        printf 'TAG=%s\n' "${AUTOSTREAM_RELEASE_TAG:-}"
        printf 'PREVIOUS_TAG=%s\n' "${previous}"
        printf 'VENV=%s\n' "${NEW_VENV:-}"
        printf 'PREVIOUS_VENV=%s\n' "${PREVIOUS_VENV:-}"
        printf 'VENV_MIGRATE=%s\n' "${VENV_MIGRATE:-0}"
    } > "${tmp}"
    chmod 0644 "${tmp}"
    mv -f "${tmp}" "${file}"
    UPDATE_STAGED=true
}

mark_update_in_progress() {
    # Record, where only root can write, that this update is under way. The
    # boot step retries an interrupted run, or completes a hand-off, only while
    # this is there. Written for any release tag; removed by abort_update and
    # by the boot step once the update has a final result.
    printf '%s\n' "${AUTOSTREAM_RELEASE_TAG:-unknown}" \
        | write_state_file "$(_update_dir)/update-in-progress" 0600
}

clear_update_in_progress() {
    rm -f -- "$(_update_dir)/update-in-progress" || true
}

abort_update() {
    # Run by the EXIT trap when an --update did not finish. Before the swap
    # file exists the running software was never touched: discard what was
    # staged, restore the owned files if the backup completed and report the
    # failure. After it, leave everything for the boot step.
    local opt
    if [[ "${UPDATE_STAGED:-false}" == true ]]; then
        echo "Update interrupted after staging; the boot step completes it." >&2
        return 0
    fi
    opt="$(_opt_dir)"
    rm -rf "${opt}/.next"
    if [[ "${VENV_BUILT:-false}" == true && -n "${NEW_VENV:-}" ]]; then
        rm -rf "${opt}/${NEW_VENV}"
    fi
    if [[ "${BACKUP_TAKEN:-false}" == true ]]; then
        restore_owned_files || true
    fi
    write_update_result "failure" "$(update_failure_message)" 0 PHASE=failed || true
    clear_update_in_progress
}

schedule_update_reboot() {
    # Same delayed reboot, with the same reason, as the appliance's update.
    "$(_admin_bin)" reboot --delay 3 AutostreamUpdate || \
        echo "WARNING: could not schedule the reboot; please reboot the device" >&2
}

write_install_state() {
    local uuid="$1"
    local path="${INSTALL_STATE_FILE:-/var/lib/autostream/install-state.env}"
    # The SD card health wrapper records its method and last outcome in
    # this file. Carry those lines over so an update keeps monitoring
    # enabled with the method the user chose.
    local sdmon_lines=""
    if [[ -f "${path}" ]]; then
        sdmon_lines="$(grep -E '^SDMON_[A-Z_]+=' "${path}" 2>/dev/null || true)"
    fi
    # root-owned 0644: root writes, all can read (including autostream for UUID fallback).
    # Written beside the old file and renamed over it: the directory belongs
    # to the service account.
    {
        cat <<EOF
AUTOSTREAM_PRODUCT=autostream-dial
DIAL_UUID=${uuid}
AUTOSTREAM_RELEASE_TAG=${AUTOSTREAM_RELEASE_TAG}
EOF
        # Digest of the requirements the venv was built from; the next update
        # reuses the venv when it still matches.
        [[ -z "${VENV_LOCK_SHA256:-}" ]] || printf 'REQUIREMENTS_LOCK_SHA256=%s\n' "${VENV_LOCK_SHA256}"
        if [[ -n "${sdmon_lines}" ]]; then printf '%s\n' "${sdmon_lines}"; fi
    } | write_state_file "${path}" 0644 root:root
}
