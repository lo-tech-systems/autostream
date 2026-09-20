# System & Updates

This is the Setup panel for the appliance's hostname, how long it remembers other
appliances and speakers that have gone quiet, SD card wear monitoring, and software
updates.

## Reaching the page

Open **Setup** and expand the **System** card, which opens the **System & Updates** panel.

## Hostname

The card shows the current hostname and a **Change Hostname** button. Tapping it opens a
dialog pre-filled with the current value; entering a new one and confirming applies it
immediately (letters, numbers and hyphens only - anything else is rejected with an inline
error). There's no reboot involved, but if you reach this appliance at
`<hostname>.local`, you'll need to browse to the new address afterwards.

## Grace Period

A slider from 1 to 15 minutes (default 2) sets how long autostream keeps remembering an
appliance or speaker that has gone quiet before it gives up on it. This covers both other
autostream appliances that have dropped off the network and AirPlay speakers that have
stopped responding: a shorter setting notices a gone-quiet device sooner, a longer one
rides out brief network blips without dropping it too early.

## SD card health monitoring

Underneath, a status line reports one of:

- **Tool not installed** - the health-check tool isn't present on this appliance.
- **Not monitored** - the tool is installed but monitoring hasn't been turned on (or a
  scheduled check hasn't completed yet).
- **Monitored, NN % endurance remaining, last checked <when>** - monitoring is on and a
  reading has been recorded.

A second line shows what's known about the card itself (name and manufacturer, and whether
it's a manufacturer likely to be supported), and readings are only ever shown while
monitoring is switched on - the moment you turn it off, the percentage and last-checked
detail disappear, they aren't just left stale on screen.

### Turning it on

Pick a method from the drop-down - **auto**, or a specific card vendor (**sandisk**,
**adata**, **transcend**, **micron**, **swissbit**, **2step**, **innodisk**) if you know
your card's make - then press **Enable**. This runs a one-off probe first, using a
manufacturer-specific command to read the card's wear level, before a confirmation dialog
that warns:

> Querying the card's health uses a manufacturer command that may cause unsupported cards
> to become unresponsive. If the card stops responding, the system will restart
> automatically.

(If a previous check on this card already caused a hang, the warning instead says the
function has previously hung the system and the card may not be supported.) Monitoring is
only switched on if that probe passes; an unsupported or hung card is left with monitoring
off. Once enabled, the method drop-down locks and the button changes to **Disable**, which
asks for a plain confirmation before turning scheduled monitoring off again.

## Updates

The same panel also has an **Updates** card (Check / Install / Reboot, automatic updates,
and a pre-release channel toggle). It's covered in depth in
[System Maintenance](SYSTEM-MAINTENANCE.md) - this page only notes that it lives here.
