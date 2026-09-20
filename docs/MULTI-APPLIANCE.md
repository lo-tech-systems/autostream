# Multi-Appliance

If you have more than one autostream appliance on the same network, you can view and
control another appliance's Home page from the one you're standing in front of, without
walking over to it or opening a second browser tab by hand.

## How it works

Every autostream appliance can discover other autostream appliances on the same LAN
automatically (no setup needed beyond each appliance having power and network). When
another appliance is discovered, it becomes available in the appliance selector pill on
your Home page (see below).

Selecting another appliance doesn't move your phone or browser to that appliance's
address. Your browser stays talking to the appliance it's bound to (the one whose address
you loaded), and that appliance relays your requests to the remote one and relays the
remote one's state back. This is why the address bar never changes, even while you're
looking at and controlling a different appliance.

## Turning it on

Multi-appliance control is configured in **Setup > Personalisation** - see
[Setup-Personalisation](SETUP-PERSONALISATION.md) for the full settings card. Two
switches matter here:

- **Display Hostname** - shows this appliance's hostname as a pill in the top-right of
  the Home page. This has to be on before the next switch can do anything.
- **Allow control of other appliances** - lets you use the pill to jump to and control
  other appliances. This switch is disabled (greyed out) until Display Hostname is
  switched on.

With both on, and at least one other autostream appliance visible on the network, the
pill becomes a dropdown.

## The selector pill

The pill in the top-right of the Home page shows the current appliance's hostname. Tap
it to open a dropdown listing:

- Your own (bound) appliance, shown first in bold.
- Every other discovered autostream appliance, listed by hostname below a divider.

If no other appliances are visible, the dropdown shows "No other appliances". The list
refreshes automatically every 15 seconds, and again as soon as you open it, so a newly
discovered or newly offline appliance shows up without a page reload.

Tapping any entry takes you to that appliance's Home page (or Equaliser page, if that's
where you tapped the pill from) in remote-control mode.

## Jumping to an appliance from an output card

If another appliance is already using one of your outputs (see the "In Use by" card
described in [Home Page](HOME-PAGE.md)), and **Allow control of other appliances** is
on, tapping anywhere on that output's card - other than its toggle or volume slider -
takes you straight to the appliance that's using it, the same as picking it from the
selector dropdown. This is a shortcut to the appliance you'd likely want to check on
without hunting for its hostname in the list first.

## Getting back to your own appliance

While you're viewing a remote appliance, the autostream logo at the top of the page
always links back to your own (bound) appliance's Home page. You can also pick your own
appliance's name from the selector dropdown.

## What you can control remotely

While controlling a remote appliance, the bottom navigation only lets you switch between
its **Home** and **Equaliser** pages. **Service**, **Setup**, and **Info** are disabled
in this mode - those apply to the appliance you're physically at, not the one you're
remote-controlling, so you return to your own appliance (via the logo or the selector)
to reach them.

On the remote appliance's Home page you can:

- Turn its outputs on or off and adjust their volume.
- Adjust its Master Volume, if it has that control enabled.
- Open its Equaliser page and change its EQ bands.

You cannot change its Setup, Service, or other configuration remotely.

## Discovery requirements

- Both appliances must be on the same LAN - discovery relies on mDNS (Bonjour-style
  local network discovery) and does not cross routers or separate networks.
- Each appliance needs its own unique hostname. Two appliances that end up reporting the
  same identity under different hostnames are treated as a conflict and the affected
  appliance is left out of the selector rather than risking cross-talk.

## Opting out

**Allow control of this from other appliances** (also in Setup > Personalisation)
controls whether this appliance announces itself to others at all. Turn it off and this
appliance stops appearing in other appliances' selector dropdowns and output-card
shortcuts - it becomes invisible to multi-appliance control network-wide, even though
its own **Allow control of other appliances** switch (if on) still lets it browse and
control others.

## Recovery when a remote appliance goes offline

If a remote appliance you're controlling stops responding (network drop, reboot, power
loss), autostream's automatic polling detects the failure after a few consecutive
attempts and returns you to your own appliance's Home page with a message explaining
that the remote appliance is unavailable. You don't need to do anything else - reopen
the selector once the other appliance is back to reconnect to it.

## See also

- [Home Page](HOME-PAGE.md) - the appliance selector pill and the "In Use by" output
  card that this feature builds on.
- [Setup-Personalisation](SETUP-PERSONALISATION.md) - where both switches live, and the
  rest of the Personalisation settings card.
