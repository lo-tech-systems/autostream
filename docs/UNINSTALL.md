# Uninstalling autostream

The supported way to remove autostream from a Raspberry Pi is to re-image the SD card.

That is the recommendation because the installer changes system packages, service
configuration, nginx configuration, sudoers policy, NetworkManager files, watchdog
settings, and some shared system files. A simple uninstall script cannot reliably
put the machine back into its exact pre-install state.

If you want a clean machine again, re-image the card.

## Quick uninstall script

This repository also includes a best-effort uninstall script:

```bash
sudo ./autostream_uninstall.sh
```

This script is intentionally limited. It is useful if you want to remove the main
autostream application and most of the clearly autostream-owned service files, but
it should not be treated as a full system rollback.

## What the script does

`autostream_uninstall.sh` currently:

- Shows a warning and asks for confirmation before continuing.
- Stops and disables these services when present:
  `autostream.service`, `autostream_monitor.service`,
  `autostream_wifi_watcher.service`, `autostream_storage_guard.timer`,
  `autostream_storage_guard.service`, `autostream_sdcardhealth.service`,
  `autostream_sdcardhealth.timer`, `autostream_dnsmasq.service`,
  `owntone.service`, and `nginx.service`.
- Removes the main application directories:
  `/opt/autostream`, `/var/log/autostream`, `/var/lib/autostream`,
  and `/usr/local/libexec/autostream`.
- Attempts to remove packaged OwnTone with `apt-get remove -y owntone`.
- Removes a few possible OwnTone(-mini) files if present:
  `/usr/sbin/owntone`, `/etc/systemd/system/owntone.service`,
  `/etc/owntone-settings.json`, `/etc/owntone.conf`,
  `/etc/apt/sources.list.d/owntone.list`,
  and `/usr/share/keyrings/owntone-archive-keyring.gpg`.
- Removes the autostream nginx config files:
  `/etc/nginx/sites-enabled/autostream-nginx.conf`,
  `/etc/nginx/sites-available/autostream-nginx.conf`,
  `/etc/nginx/conf.d/autostream-nginxd.conf`,
  and `/etc/nginx/conf.d/99-autostream-access-log.conf`.
- Removes the systemd unit files created by the installer for autostream.
- Removes the sudoers snippets created by the installer.
- Removes the journald storage drop-in
  (`/etc/systemd/journald.conf.d/99-autostream-storage.conf`) and restarts
  `systemd-journald` to apply the removal.
- Removes a few other installer-managed files we can identify confidently, such as
  the autostream logrotate file, the autostream dnsmasq snippet, and the
  NetworkManager files copied by the installer.
- Runs `systemctl daemon-reload` and prompts for reboot.

## What the script does not do

The uninstall script does not try to fully reverse the installer.

In particular, it does not attempt to:

- Remove all packages that may have been installed as dependencies for autostream.
- Restore the previous nginx site layout.
- Re-enable services that may have been disabled during install.
- Reconstruct previous versions of shared config files.
- Undo changes to firmware or boot configuration.
- Undo cloud-init changes.
- Guarantee removal of every OwnTone-related artifact.
- Guarantee that the system is returned to a known-good non-autostream state.

Some examples of changes that are deliberately not reversed:

- `/boot/firmware/config.txt`
- `/boot/firmware/user-data`
- Any generic packages that may also be useful to other software on the system

## Before you run it

Make sure you understand the trade-off:

- The script is convenient for partial cleanup.
- Re-imaging the SD card is the safer and more complete option.

If the Raspberry Pi was set up as a dedicated autostream appliance, re-imaging is
usually the better choice.

## Running the script

From the repository root:

```bash
sudo ./autostream_uninstall.sh
```

The script requires root privileges and an interactive terminal. It will ask for
confirmation before making changes, and it will offer a reboot prompt at the end.

## After running it

Expect to do some manual cleanup if you are trying to reuse the machine.

At minimum, review:

- `systemctl list-unit-files | grep -E 'autostream|owntone'`
- `/etc/nginx/`
- `/etc/NetworkManager/`
- `/boot/firmware/config.txt`
- `/boot/firmware/user-data`

If you want a predictable clean slate, re-image the SD card instead of relying on
manual cleanup.
