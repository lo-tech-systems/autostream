# Personalisation

This card holds the appearance and multi-appliance-visibility switches for the Home page
and the rest of the web UI.

## Reaching the page

Open **Setup** and expand the **Personalisation** card.

## The switches

- **Display Hostname** - shows this appliance's hostname as a pill in the top-right of the
  Home page. Turning this on is also the prerequisite for using the appliance selector
  described below.
- **Allow control of other appliances** - lets you use that hostname pill to jump to and
  control other autostream appliances discovered on the network. This switch is disabled
  (greyed out) until **Display Hostname** is switched on, and turning **Display Hostname**
  off turns this behaviour off with it.
- **Allow control of this from other appliances** - controls whether this appliance
  announces itself for discovery at all. Turn it off and this appliance stops appearing in
  other appliances' selectors, even if its own **Allow control of other appliances** switch
  is on and it can still browse and control others.

  See [Multi-Appliance](MULTI-APPLIANCE.md) for the full behaviour of these two switches,
  including the selector pill, remote-control mode, and discovery requirements.

- **Show Master Volume Control** - shows a Master Volume slider on the Home page's Now
  Playing card, which scales the volume of every selected output at once. On by default;
  turning it off hides the slider entirely rather than showing it disabled. See
  [Home Page](HOME-PAGE.md) for how the slider behaves.
- **Display Input Detail** - shows the locked sample-rate line and the stereo VU meter on
  the Home page's Now Playing card. Off by default. See [Home Page](HOME-PAGE.md) for
  details.
- **Dark Mode** - switches the web UI to a dark colour theme. Applies immediately across
  the whole app.

## Gaps

- [gap: whether "Display Input Detail" and "Show Master Volume Control" have any effect
  outside the Home page (for example the Equaliser page) was not checked here - only their
  documented Home-page behaviour is covered]
