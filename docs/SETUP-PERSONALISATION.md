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
- **When Pause is pressed on a speaker** - what happens to the other speakers when someone
  presses Pause on a HomePod, or on an Apple TV remote. The speaker itself always pauses: an
  Apple TV or HomePod stops by itself when its own Pause is pressed, so autostream holds it
  and shows it as **Paused**. Pressing Play on it starts it again, at the point the music has
  reached (a record or CD keeps playing while it is paused). The choices are:
  - **Only that speaker pauses** (the default) - the other speakers carry on.
  - **Mute the other speakers too** - the other playing speakers are muted, and Play on the
    paused speaker unmutes them.
  - **Turn the other speakers off too** - the other speakers are switched off and stay off
    until you turn them on again.

  Switching a paused speaker off and on again also starts it, and on a small-screen dial a
  tap on the speaker in its speaker list does the same as Play. A stereo pair, or an Apple TV
  with its HomePods, counts as one speaker. A paused speaker, and any speakers its Pause
  muted, are turned off if the Pause lasts longer than a set time (five minutes unless
  changed in the configuration file); the page states the current time under the setting. A
  speaker that cannot be held this way is muted instead, and Play unmutes it. Some speakers
  do not tell the appliance about their own Pause at all (the Edifier MS50A, for example),
  so the setting does nothing for them. This needs owntone-mini 1.6 or above, which this
  release installs, and its event channel, which is on unless the player could not open it.
  Without them the setting is greyed out and its help text says which is missing.
- **Volume changes made at any speaker apply to all playing speakers** - off by
  default. When on, turning the volume up or down on a speaker itself (its
  buttons, knob or app, or an Apple TV remote) moves the other playing speakers
  too, each in proportion to its own level, so they all reach silent together.
  Muted speakers stay muted. A stereo pair, or an Apple TV with its HomePods,
  counts as one speaker. Needs owntone-mini 1.6 or above and its event channel;
  the switch is greyed out without them, and a volume change at a speaker then
  applies to that speaker only.
