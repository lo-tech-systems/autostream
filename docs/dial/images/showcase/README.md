# Showcase pictures

Pictures of the dials for the website and print. The music and the cover art
in them are invented: the artists, albums and tracks are made up and the
covers are drawn by `tools/showcase`, so no real artists or artwork appear.
Appliances are named for their input (Turntable, CD Player, Tape Deck) and
speakers for their rooms.

## hd-dial

The HD dial's page at 1024x600.

- `now-playing-jazz-1024x600.png`: now playing, with the speaker list.
- `appliances-1024x600.png`: the appliance list, with a turntable playing and a CD player idle.
- `equaliser-six-band-1024x600.png`: the six-band equaliser page.
- `pulldown-1024x600.png`: the pull-down panel open, with screen settings and the dial's details.

## spi-dial

The small SPI dial's screens in the rich layout (320x240), drawn by the dial's
own display code and scaled up two times. The same screens in the compact
layout (240x240) are in `compact/` under the same names, apart from the ones
that layout cannot reach: the appliance list, the speakers, the equaliser and
the replay timer.

Start-up and system screens:

- `starting.png`: the "Starting..." splash shown at boot.
- `restarting.png`: "Restarting..." after a Restart tap.
- `updating.png`: a software update in progress, with its step and progress bar.
- `updated.png`: the update finished, showing the new version.
- `update-failed.png`: the update failed and the previous version was restored.
- `no-wifi.png`: the No WiFi card, with Dismiss and Restart.
- `sd-health.png`: the microSD health warning.
- `appliance-warning.png`: a warning from an appliance (the stylus reminder), with Dismiss.
- `appliance-notice.png`: the same kind of card as a notice that is put away with OK.

Idle:

- `idle.png`: nothing playing, with the Wi-Fi signal and the information badge.
- `idle-replay-available.png`: idle with the replay logo, offered when a recording can be replayed.
- `idle-wifi-connecting.png`: the Wi-Fi icon dimmed while the dial connects.
- `idle-wifi-lost.png`: the Wi-Fi icon in red after the link is lost.

Now playing:

- `now-playing.png`: now playing with the controls shown.
- `now-playing-muted.png`: the same, muted.
- `now-playing-artwork-only.png`: the cover alone, with the controls hidden.
- `now-playing-replay-timer.png`: the replay position shown briefly over the cover (rich layout only).

Appliances and speakers (rich layout only):

- `appliances.png`: the appliance list, with the playing one marked.
- `appliances-unauthorised.png`: an appliance this dial is not yet allowed to control.
- `not-authorised-hint.png`: what a tap on that appliance explains.
- `pair-hint.png`: the hint for a speaker that must be paired in the appliance's web page.
- `speakers.png`: the speakers list, with levels and the default marked.
- `speaker-detail.png`: one speaker, on, with its level and the volume controls.
- `speaker-detail-off.png`: one speaker, off.
- `equaliser.png`: the bass and treble equaliser.

Repeat Play and replay:

- `repeat-enable.png`: the Repeat Play switch, on.
- `repeat-enable-off.png`: the Repeat Play switch, off.
- `replaying.png`: replaying a held recording, with Restart and Stop.
- `replay-picker.png`: choosing which appliance's recording to replay.

Information:

- `info-list.png`: the dial's information list, first page.
- `info-list-more.png`: the second page of the list.
- `info-value.png`: one field shown full screen (compact layout only; the rich list shows values inline).

## Regenerating

From the repository root, with the dial's Python dependencies, Pillow,
Playwright and the WebKit engine installed:

    python tools/showcase/capture.py --docs

This rewrites every picture here: the four HD pages and all the SPI screens.
To capture into another folder instead, give it as the argument; that run
also writes the 800x480 HD pages. See `tools/showcase/README.md` for the
options.
