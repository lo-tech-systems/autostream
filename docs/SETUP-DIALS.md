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
- A **Needs update** badge while the dial is online and on a different release
  from the appliance, and a **Recovery Active** badge while a lost-PIN recovery
  window is open.
- **Firmware** version, shown next to the title only while the dial is
  authorized and online.
- **Last seen**, shown for an authorized dial that is currently offline.
- **UUID**: a unique identity code so you can tell two dials apart, even
  before either has a name. It stays the same across reboots and firmware
  updates, and changes only if the dial is factory reset.
- **SD card health monitoring**, on dials whose firmware supports it: the
  same enable/disable control as the System page, with the dial's last
  reading.

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

## Keeping dials and the appliance on the same release

Update the appliance and its dials together: every appliance and every dial must be on 0.8. A dial that is older than the appliance shows a **Needs update** badge on its card in the Dials panel, along with an **Update firmware** button, and the Home page shows a "Dials" warning card saying how many need updating. Such a dial cannot control the appliance until it is updated.

## Dial settings and the lock

If a PIN is set on a dial, the **Settings** section of its card is locked. Tap the padlock and enter the dial's PIN to unlock it. The card stays unlocked while you use its controls and the dialogs they open. It locks again when you tap the padlock, leave the Dials panel with Back, or the page is hidden. Without a PIN the section is always unlocked. See [Getting Started](dial/GETTING-STARTED.md#setting-a-pin).

## Revoking a dial

Turn **Allow dial to control this appliance** off. A confirmation prompt
("Remove authorization for this dial?") appears first. Confirming removes
the dial's access; the card falls back to its unauthorized state. Cancelling
leaves the toggle on and nothing changes.

## After the appliance is factory reset

A factory reset of the appliance erases its list of authorised dials. Every dial
shows as **New** again and has to be authorised as above.

## A dial that has been factory reset

A factory reset gives a dial a new UUID, so this appliance treats it as a new
dial: it appears with the **New** badge, and you authorise it as above. The
dial's old entry stays in the list, shown as **Offline** with the time it was
last seen. To remove it, turn off **Allow dial to control this appliance** on
that card and confirm.

## Next steps

- [autostream dial: Getting Started](dial/GETTING-STARTED.md): configuring a
  newly authorized dial, setting a PIN, the encoder button, and everyday use.
- [autostream dial: System Maintenance](dial/SYSTEM-MAINTENANCE.md): firmware
  updates and recovering an unresponsive dial.
- [autostream dial: Build Guide](dial/BUILD-GUIDE.md): building the hardware.
