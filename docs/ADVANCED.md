# Advanced Operations

Options for people who want to change how autostream is installed or which
streaming backend it runs. Most users never need anything here.

## Install options

The one-line installer accepts flags after `-s --`. For example, to choose the
OwnTone backend:

```sh
curl -fsSL https://raw.githubusercontent.com/lo-tech-systems/autostream/main/bootstrap.sh | sudo bash -s -- --owntone=full
```

### OwnTone backend (`--owntone=`)

By default the installer builds **owntone-mini** from source, a lightweight
build maintained by Lo-tech Systems and tuned for the Pi Zero and other
low-power devices. It streams to AirPlay and AirPlay 2 speakers.

- `--owntone=full` installs the standard packaged OwnTone build instead. Use
  this if you need streaming protocols the bundled build does not carry, such
  as Chromecast. See [Running autostream with full OwnTone](FULL-OWNTONE.md)
  for what the installer sets up and what you maintain yourself.
- `--owntone=skip` leaves OwnTone alone, for a machine where you manage it
  yourself.

### Low power mode (`--low-power`)

For low-power boards such as a Pi Zero 2 W, `--low-power` limits the appliance
to two cores at 700 MHz to lower its power draw. It is off
unless you ask for it. It writes four settings:

- `maxcpus=2` on the kernel command line in `/boot/firmware/cmdline.txt` (added
  once, and the file stays a single line; the first change keeps a copy of the
  original as `cmdline.txt.autostream-bak`);
- `arm_freq=700`, `arm_boost=0` and `force_turbo=0` under `[all]` in
  `/boot/firmware/config.txt`.

It does not set `over_voltage`, and never removes an `over_voltage` line that is
already there.

```sh
curl -fsSL https://raw.githubusercontent.com/lo-tech-systems/autostream/main/bootstrap.sh | sudo bash -s -- --low-power
```

The settings take effect at the next reboot. Reduced to two cores at 700 MHz,
the appliance has less headroom than at full speed [how this affects behaviour on
boards other than a Zero 2 W has not been measured], so use it only where the
power or heat budget needs it.

The choice is saved with the other install choices, so the automatic updater
applies it again on each update while it is on. An update run by hand can switch
it on too (`sudo ./autostream_install.sh --update --low-power`). An update
without the switch leaves whatever is already in the two files alone, so an
appliance that already has these settings keeps them. The uninstaller removes
exactly these settings, and only if the switch was used.

There is no switch to turn it off again. To turn it off, remove `maxcpus=2` from
`cmdline.txt` and the three lines from `config.txt` by hand, and delete the
`LOW_POWER=` line from `/var/lib/autostream/install-state.env`, then reboot.

### Unattended install

Set the appliance PIN without the interactive prompt by passing it on the
install command:

```sh
curl -fsSL https://raw.githubusercontent.com/lo-tech-systems/autostream/main/bootstrap.sh | sudo bash -s -- --unattended PIN=1234
```

## API reference

autostream exposes local interfaces for integration and diagnostics. These are developer
references, not needed for normal use:

- [Monitor socket API](AUTOSTREAM-MONITOR-API.md) - the audio monitor's control and status interface.
- [Log level API](LOG-LEVEL-API.md) - reading and setting log verbosity at runtime.
- [API error contract](API-ERROR-CONTRACT.md) - how the web interface reports errors.
- [Status API](STATUS-API.md) - the combined `/api/status` endpoint, including track identification.

## See also

- [Getting Started](GETTING-STARTED.md) - the normal install and setup.
- [Running autostream with full OwnTone](FULL-OWNTONE.md) - the full OwnTone backend.
- [System Maintenance](SYSTEM-MAINTENANCE.md) - updates and channels.
