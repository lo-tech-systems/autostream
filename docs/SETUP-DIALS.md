# Dials (Setup)

This page covers the **Dials** card on the main autostream Setup page: the
appliance side of setting up an [autostream dial](dial/GETTING-STARTED.md), a
separate rotary volume-control accessory.

For everything you do on the dial side (naming it, setting a PIN, the
encoder button, everyday use), see
[autostream dial: Getting Started](dial/GETTING-STARTED.md). This page only
covers what you see and do on the **appliance's** Setup page.

## Reaching the card

Open the autostream web UI and go to **Setup**. The **Dials** card lists
every dial the appliance has found. Its summary line shows a quick count,
for example *2 authorized · 1 online* or *No dials* when none have been
seen.

## What each dial's card shows

Every dial discovered on the network, authorized or not, gets its own card:

- **Name** (or the dial's identity if it has none yet) as the card title.
- A status badge: **New** (seen but not yet authorized), **Online**, or
  **Offline**.
- **Firmware** version, shown next to the title only while the dial is
  authorized and online.
- **Last seen**, shown for an authorized dial that is currently offline.
- **UUID**: a 20-character hexadecimal identity broadcast in the dial's mDNS
  record. It stays the same across reboots and firmware updates, so it's a
  reliable way to tell two dials apart if neither has a name yet.

A brand new, unauthorized dial's card shows only its status and the **Allow
dial to control this appliance** toggle. Its settings are hidden until it is
authorized.

## Authorizing a dial

Before a dial can control this appliance, it must be authorized:

1. Find the dial's card in the **Dials** panel.
2. Turn on **Allow dial to control this appliance**.

That's it. Once authorized, the card's full settings section appears
(covered in [Getting Started](dial/GETTING-STARTED.md)), and the dial can
start adjusting volume on this appliance as soon as it is playing something.

## Revoking a dial

Turn **Allow dial to control this appliance** off. A confirmation prompt
("Remove authorization for this dial?") appears first. Confirming removes
the dial's access; the card falls back to its unauthorized state. Cancelling
leaves the toggle on and nothing changes.

## Next steps

- [autostream dial: Getting Started](dial/GETTING-STARTED.md): configuring a
  newly authorized dial, setting a PIN, the encoder button, and everyday use.
- [autostream dial: System Maintenance](dial/SYSTEM-MAINTENANCE.md): firmware
  updates and recovering an unresponsive dial.
- [autostream dial: Build Guide](dial/BUILD-GUIDE.md): building the hardware.
