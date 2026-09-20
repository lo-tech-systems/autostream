# Owntone Setup

This page holds the AirPlay settings that don't fit on the main Setup page:
buffered audio, per-speaker AirPlay modes (including Apple TV surround), and
per-speaker output offsets.

## Reaching the page

Open **Setup**, expand the **Playback** card, and tap **More Owntone
Settings**. This opens `/owntone-setup`.

If your backend supports [output offsets](#output-offsets), the same card
also shows a **Run Speaker Synchronisation** button, which opens the
automatic alignment tool described in [SPEAKER-SYNC.md](SPEAKER-SYNC.md).

## AirPlay Settings

At the top of the page is an **AirPlay Settings** card:

- **Enable AirPlay 2 Buffered Audio** — a toggle. Turning it on unlocks the
  buffered and surround modes on every speaker's mode drop-down below (see
  [Enabling buffered audio](#enabling-buffered-audio)). Turning it off hides
  those modes again; any speaker that was using one falls back to Auto.
- **Use uncompressed audio** — a toggle for ALAC compression on the AirPlay
  stream.
- **Start Buffer (ms)** — a drop-down controlling how much audio is queued
  before playback starts on the buffered transport.
- **AirPlay User Agent** — a free-text field overriding the User-Agent
  string AirPlay advertises. Changing it restarts OwnTone; clearing it
  restores the backend's own default.

Each of these controls is only shown, or only enabled, when the backend
exposes it. If a control can't be read from the backend at all it's left
out; if it's read but unsupported, it's shown disabled with a note
explaining why. This whole page's live controls — mode, offset, and the
settings above — only take full effect against the bundled owntone-mini
engine. Running full/stock OwnTone instead disables most of them; see
[FULL-OWNTONE.md](FULL-OWNTONE.md) for what still works there.

## Speaker rows

Below AirPlay Settings, every known speaker gets its own row:

- **Show in autostream** — a toggle that hides or shows the speaker
  elsewhere in the app. Hidden speakers still keep their saved mode and
  offset.
- **Mode** — a drop-down (see [AirPlay modes](#airplay-modes) below).
- **Offset** — a slider (see [Output offsets](#output-offsets) below), shown
  only when the backend supports it.

If a speaker isn't currently discovered, its row still appears (from saved
state) but shows: "Speaker not currently discovered. Saved mode will be
applied when it reappears." Any mode you choose while it's away is saved
and pushed to it automatically the next time autostream sees it.

If the backend exposes only Auto for a speaker, its row shows: "Only Auto
mode is currently exposed by this backend. Additional protocols will
appear here when supported."

## AirPlay modes

### Enabling buffered audio

Most speakers only ever need **Auto**. The buffered and surround modes are
extra choices that only appear once **Enable AirPlay 2 Buffered Audio** (in
the AirPlay Settings card above) is switched on. Turn it on first if you
don't see them.

### The standard modes

With buffered audio off, or on a speaker that doesn't support it, the mode
drop-down offers:

- **Auto** — let the backend choose the best available transport.
- **AirPlay** — force classic AirPlay 1 (RAOP).
- **AirPlay 2** — force standard AirPlay 2.

With buffered audio on, two more choices appear:

- **AirPlay 2 (buffered)**
- **AirPlay 2 (buffered lossless)**

### The two surround modes (Apple TV only)

Two further modes can appear once buffered audio is on, but **only for a
standalone Apple TV connected to a 5.1-capable system**. They never appear
for a HomePod, a stereo-paired HomePod, or HomePods grouped behind an Apple
TV, and there's no way to select them for anything but a lone Apple TV.

- **AirPlay 2 (stereo for 5.1 systems)** — in plain terms, a 2.1 layout.
  Your stereo signal plays on the front-left and front-right channels, and
  a blend of left and right goes to the subwoofer (LFE). The centre and
  rear channels stay silent. The stream sent to the Apple TV is still a
  full 5.1 stream; the unused channels just carry silence. Use this when
  you want clean stereo-plus-bass through a 5.1 system rather than a
  synthesised surround effect.
- **AirPlay 2 (5.1 upmix)** — spreads the stereo signal across all six
  channels using a steering filter that derives centre, rear, and a
  band-limited subwoofer feed from the source. This is a synthetic
  surround effect, not a true discrete mix, and it costs noticeably more
  processing power than the stereo mode above.

A mode drop-down is only editable when the backend can accept mode changes
for that speaker; otherwise the page shows the current mode as fixed text
alongside the notes above.

## Output offsets

Where supported, each speaker row has an **Offset** slider running from
-2000 ms to +2000 ms in 10 ms steps, with a **Reset** button that sets it
back to 0. This shifts that speaker's audio earlier or later relative to
the others, for correcting small timing mismatches between speakers (for
example one lagging behind the rest in a multi-room group).

Offsets are applied live as you drag the slider (debounced briefly so it
doesn't fire on every pixel of movement). The same offset values are what
[Speaker Synchronisation](SPEAKER-SYNC.md) measures and writes
automatically if you'd rather not set them by ear — run that first, then
fine-tune here if needed.

## Gaps

- [gap: the exact mechanism/benefit of "Use uncompressed audio", "Start
  Buffer", and "AirPlay User Agent" beyond their on-page labels was not
  investigated in the audio pipeline code; only their UI behaviour is
  documented here]
