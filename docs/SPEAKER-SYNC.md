# Speaker Synchronisation

Speaker Synchronisation measures how far out of step your speakers are from each other
and works out timing adjustments to bring them back into line.

## What it does

The tool plays a short test tone through each speaker you select, one at a time. You
hold your phone near your speakers while this happens; a measurement page on your phone
listens for each tone and times when it actually arrives. Once every speaker has been
measured, autostream compares the arrival times and proposes a timing offset for each
speaker (relative to whichever one you chose as the reference) that would bring them
back into step.

Nothing is changed until you review the proposed offsets and choose to apply them.

This needs owntone-mini 1.2 or above, which supports per-output playback offsets. If
your backend doesn't support that, the Setup page won't show the **Run Speaker
Synchronisation** button, and the Speaker Synchronisation page explains that calibration
is unavailable rather than offering controls that couldn't do anything.

## When to use it

Use it whenever two or more of your AirPlay speakers are noticeably out of time with
each other - for example, sound from a TV-connected Apple TV arriving audibly ahead of
or behind other speakers playing the same source in another room, or any group of
speakers where one consistently lags the rest. Running the tool measures the actual gap
and sets numbers you'd otherwise have to guess by ear.

You need at least two outputs selected to run a measurement: one to act as the
reference and at least one other to be measured against it.

## How to run it

1. Open **Setup**, expand the **Playback** card, and tap **Run Speaker
   Synchronisation**.
2. Under **Select the outputs to calibrate**, switch on every speaker you want
   included. The first one you switch on becomes the reference (marked with a
   **Reference** chip) - the others are adjusted to match it, not the other way round.
3. Set the **Calibration volume** the test tones will play at.
4. Tap **Start**. autostream opens a link to a measurement page hosted at
   lo-tech.co.uk (a secure page is needed for microphone access, which your phone's
   browser only allows over HTTPS). Open that link on your phone and hold it near your
   speakers.
5. autostream plays the test tone through each selected speaker in turn while the page
   shows which speaker is currently playing and which cycle it's on. You can tap
   **Abort** at any time to cancel the run.
6. When the phone has measured every speaker, it sends the timing results straight back
   to your appliance over your own network (not to lo-tech.co.uk) and the Speaker
   Synchronisation page shows a review table.

Tap **Privacy** on the page for a fuller explanation of what the measurement page can
and can't see.

## What to expect from the results

The review table lists, for each speaker: the measured delta, the measurement spread,
its current offset, and the proposed new offset. A spread over 40 ms is flagged as a
noisy measurement - if you see that, it's worth re-running rather than trusting the
number as-is.

From here you can:

- **Apply** - writes the proposed offsets to the outputs immediately. They take effect
  right away; there's nothing further to save.
- **Re-run** - discards this result without changing anything, so you can measure again
  (for example after moving the phone somewhere with less background noise).

Proposed offsets are clamped to a maximum of ±2000 ms either way.

After applying, you can jump straight to **Open Output Settings** to fine-tune any
offset by hand, or **Run Alignment Again** to repeat the whole process. See
[Setup-OwnTone](SETUP-OWNTONE.md) for how the per-output offset sliders work if you want
to nudge a value afterwards rather than re-running the whole measurement.

## See also

- [Setup-OwnTone](SETUP-OWNTONE.md) - the per-output offset sliders that Speaker
  Synchronisation reads from and writes to, and how to adjust them by hand.
