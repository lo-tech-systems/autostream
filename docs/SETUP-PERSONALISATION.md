# Personalisation

This page holds the appearance, multi-appliance and speaker-control settings for the Home
page and the rest of the web UI. It has three cards: **Display**, **Appliance control** and
**Speaker controls**. Each setting's name is on the left and its switch or choice on the
right, and every change is saved as soon as you make it.

## Reaching the page

Open **Setup** and expand **Personalisation**.

## Display

- **Display hostname** - shows this appliance's hostname as a pill in the top-right of the
  Home page. Turning this on is also the prerequisite for using the appliance selector
  described under Appliance control.
- **Show master volume control** - shows a Master Volume slider on the Home page's Now
  Playing card, which scales the volume of every selected output at once. On by default;
  turning it off hides the slider entirely rather than showing it disabled. See
  [Home Page](HOME-PAGE.md) for how the slider behaves.
- **Display input detail** - shows the locked sample-rate line and the stereo VU meter on
  the Home page's Now Playing card. Off by default. See [Home Page](HOME-PAGE.md) for
  details.
- **Dark mode** - switches the web UI to a dark colour theme. Applies immediately across
  the whole app.

## Appliance control

- **Allow control of other appliances** - lets you use the hostname pill to jump to and
  control other autostream appliances discovered on the network. This switch is greyed out
  until **Display hostname** is switched on, and turning **Display hostname** off turns this
  behaviour off with it.
- **Allow control of this from other appliances** - controls whether this appliance
  announces itself for discovery at all. Turn it off and this appliance stops appearing in
  other appliances' selectors, even if its own **Allow control of other appliances** switch
  is on and it can still browse and control others.

See [Multi-Appliance](MULTI-APPLIANCE.md) for the full behaviour of these two switches,
including the selector pill, remote-control mode, and discovery requirements.

## Speaker controls

These settings are about what happens when someone presses Pause or turns the volume on a
speaker itself: a HomePod, a speaker's own buttons, knob or app, or an Apple TV remote. A
stereo pair, or an Apple TV with its HomePods, counts as one speaker.

- **Pause all speakers when pause is pressed on a speaker** - off by default.
  - The speaker you pressed Pause on always pauses. An Apple TV or HomePod stops by itself
    when its own Pause is pressed, so autostream holds it and shows it as **Paused**.
    Pressing Play on it starts it again, at the point the music has reached (a record or CD
    keeps playing while it is paused).
  - With this off, only that speaker pauses and the others carry on.
  - With it on, the other playing speakers are muted too, and Play on the paused speaker
    brings them all back.

  Switching a paused speaker off and on again also starts it, and on a small-screen dial a
  tap on the speaker in its speaker list does the same as Play. A speaker that streams in
  real time, or an AirPlay 1 speaker, is held by silencing it: it keeps receiving audio, so
  it stays in time, and Play brings its sound back at once, at its own level. Turning a
  paused speaker's own volume knob starts it again too, and Play on a paused speaker that
  was also muted unmutes it. A speaker that cannot be held this way is muted instead, and
  Play unmutes it. Some speakers do not tell the appliance about their own Pause at all (the
  Edifier MS50A, for example), so the setting does nothing for them.
- **Stop paused speakers after** - 1, 3, 5 or 10 minutes, 5 by default. A paused speaker,
  and any speakers its Pause muted, are turned off once the Pause has lasted this long. This
  applies whether or not **Pause all speakers** is on. A time set by hand in the
  configuration file that is not one of these shows as the nearest choice, and stays as it
  is until you pick one.
- **Apply volume changes made at any speaker to all playing speakers** - off by default.
  When on, turning the volume up or down on a speaker itself moves the other playing
  speakers too, each in proportion to its own level, so they all reach silent together.
  Muted and paused speakers stay so, and their levels move with the others, so they come
  back in proportion. A paused or muted speaker is never the one that moves the others:
  turning its knob starts or unmutes that speaker alone.

These settings need owntone-mini 1.6 or above, which this release installs, and its event
channel, which is on unless the player could not open it. Without them the three settings
are greyed out, and a line under the card's title says which is missing. A volume change at
a speaker then applies to that speaker only.
