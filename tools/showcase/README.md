# Showcase screenshots

Reproducible product pictures of the dials, drawn from invented music and
generated cover art. Nothing here is collected by the test suite.

- `music.py`: the invented tracks (artist, album, title, genre, cover style
  and seed). Edit this to change the music.
- `covers.py`: draws a 600x600 cover per album with Pillow, deterministically
  from the track's seed, in DejaVu type (the face the dial's renderer uses).
  `python tools/showcase/covers.py OUT_DIR` writes the covers on their own.
- `showcase_scenarios.py`: scenarios for the HD page in the same form as
  `tests/hd_scenarios.py`, reusing its helpers, with the invented tracks and
  covers. Appliances are named for their input (Turntable, CD Player, Tape
  Deck) and speakers for their rooms.
- `spi_shots.py`: every screen of the small SPI dial, drawn by the dial's own
  compositor for a 320x240 panel (rich layout) and a 240x240 panel (compact
  layout), where the screen exists on that layout. Edit `screens()` to add or
  change one.
- `capture.py`: runs it all.

## Regenerating

From the repository root, with the dial's Python dependencies, Pillow,
Playwright and the WebKit engine installed:

    python tools/showcase/capture.py [OUT_DIR | --docs] [--engine webkit|chromium]
                                     [--only hd|spi] [--scenario NAME ...]

The default folder is `build/showcase-shots`, which git ignores. HD pictures go to `hd-dial/<scenario>-<width>x<height>.png` at 800x480
and 1024x600; SPI pictures go to `spi-dial/<screen>.png` (rich layout) and
`spi-dial/compact/<screen>.png`, scaled up two times with nearest-neighbour.

`--docs` writes the published set into docs/dial/images/showcase instead:
the HD pictures listed in `DOCS_HD` at 1024x600, and every SPI screen.

WebKit is the default because the kiosk browser is WebKit-based. On a drive
that is slow for many small files (a mounted Windows disk under WSL), copy the
repository to a native folder first and run from there.
