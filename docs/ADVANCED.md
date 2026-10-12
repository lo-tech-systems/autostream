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
  once, or changed in place if there is a `maxcpus` setting with another value
  already, and the file stays a single line; the first change keeps a copy of the
  original as `cmdline.txt.autostream-bak`);
- `arm_freq=700`, `arm_boost=0` and `force_turbo=0` under `[all]` in
  `/boot/firmware/config.txt`.

It does not set `over_voltage`, and never removes an `over_voltage` line that is
already there.

```sh
curl -fsSL https://raw.githubusercontent.com/lo-tech-systems/autostream/main/bootstrap.sh | sudo bash -s -- --low-power
```

The settings take effect at the next reboot. Reduced to two cores at 700 MHz,
the appliance has less headroom than at full speed, so use it only where the
power or heat budget needs it.

The switch belongs to the appliance installer. The dial installer has no low
power mode.

Once the switch has been used, the choice is saved with the other install
choices and stays saved. Every later update, the automatic updater's and one run
by hand, applies it again whether or not the switch is given, so settings you
have removed from the two files come back. An update run by hand can switch it
on too (`sudo ./autostream_install.sh --update --low-power`). On an appliance
that has never used the switch, an update leaves whatever is already in the two
files alone, so an appliance that already has these settings by hand keeps them.

The uninstaller removes these settings, and only if the switch was used. It also
puts back what the switch replaced when it was first used: an `arm_freq`,
`arm_boost` or `force_turbo` line that was in `config.txt` outside any section, or
under `[all]`, returns to the part of the file it came from, and a `maxcpus` value
other than 2 on the kernel command line returns in place of `maxcpus=2`. A line
in any other section of `config.txt` is never touched. An appliance that first used
the switch under an earlier release made no such note, and only loses the added
settings. The backup
`cmdline.txt.autostream-bak` is left in place.

There is no switch to turn it off again. To turn it off, remove `maxcpus=2` from
`cmdline.txt` and the three lines from `config.txt` by hand, and delete the
`LOW_POWER=` line from `/var/lib/autostream/install-state.env`, then reboot.
Without the last step the next update puts the settings back.

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
