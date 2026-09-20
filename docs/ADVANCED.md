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

## See also

- [Getting Started](GETTING-STARTED.md) - the normal install and setup.
- [Running autostream with full OwnTone](FULL-OWNTONE.md) - the full OwnTone backend.
- [System Maintenance](SYSTEM-MAINTENANCE.md) - updates and channels.
