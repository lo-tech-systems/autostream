# Setup - Track Identification

Open **Setup** and expand the **Track Identification** card. Its collapsed row shows **On** or
**Off**.

## Enabling it

**Track identification** is a single toggle, off by default. Turning it on tells autostream to
identify what's currently playing so it can show a real title/artist/artwork instead of just an
input label. The card explains, in its own words, exactly what this involves:

> A compact frequency fingerprint is derived from a short audio sample and sent to Apple's
> Shazam using vibra-mini. No raw audio leaves the device. The use of this feature requires
> internet access and may be subject to third-party terms of service.

There is only one identification provider (Shazam, via the bundled vibra-mini daemon). The
card has no provider picker.

## What actually leaves the device

A fingerprint derived from a short audio sample is sent to Shazam, not the raw audio itself.
This means:

- Track identification requires the appliance to have internet access. If it can't reach
  Shazam, identification will fail or be unavailable.
- Using it is subject to Shazam's own third-party terms of service.

When identification is off, the three sliders below are shown greyed out and disabled: nothing
is analysed or sent anywhere.

## Lead-in before analysis

Once a track change is detected, autostream ignores audio for this many seconds before starting
analysis (0-30s). Higher values help avoid an unnecessary online check on the transient at the
very start of a track, and help first-time identification succeed.

## Re-identify period

While no track change is detected, autostream periodically re-identifies the current track
anyway, on this interval (1-15 minutes, shown rounded to the nearest minute). This is aimed at
continuous or noisy records where a track boundary might never trigger a silence gap on its
own. Lower values catch changes faster but mean autostream checks online more often.

## Track-change detection

A silence gap of this length (1.00-3.00 seconds) is what autostream uses to decide a track has
changed, which in turn triggers automatic re-identification.
