# Playing your first track

This assumes you have completed [Initial Setup](GETTING-STARTED.md#initial-setup): Input 1 is connected and enabled, and a default speaker is chosen.

## 1. Connect a source

Plug your turntable, CD player, or other line-level source into the input you configured as **Input 1** (or **Input 2**, if you have set up a second input from the [Setup page](SETUP-INPUTS.md)).

## 2. Start playback at the source

Press play on the turntable or CD player itself. There is no play button in autostream: each input is monitored continuously, and autostream watches its audio level against a silence threshold.

## 3. autostream starts streaming automatically

As soon as the input's level rises above the silence threshold, autostream treats this as the start of a listening session and begins streaming to your default speaker. There is no manual "start" step in the Web UI: the session starts itself as soon as it detects real audio. A brief quiet passage will not cut it short; see [Silence detection](SETUP-PLAYBACK.md#silence-detection) for the minimum hold that keeps a session running.

## 4. Choose your speakers

Your default speaker (chosen during [Setup Page 1](GETTING-STARTED.md#setup-page-1---speaker-selection)) is switched on automatically if nothing else is already selected. Open the [Home page](HOME-PAGE.md) at any time to:

- See which speaker(s) are currently playing (shown as **On**/**Off** on each speaker card).
- Turn on a different speaker, or more than one.
- Adjust the volume.

## 5. Sound plays

Once a speaker is on and the session has started, audio streams to it continuously for as long as the source keeps producing sound.

## 6. Playback stops on silence

When you stop the source (or the record/CD finishes), autostream waits for a period of continuous silence (30 seconds by default) before ending the session and switching outputs off again. There is no manual "stop" button either: silence itself ends the session. You can adjust how long autostream waits before treating a source as silent, per input, from [Setup -> Inputs](SETUP-INPUTS.md) or the playback defaults in [Setup -> Playback](SETUP-PLAYBACK.md).

## Next steps

* [Home Page](HOME-PAGE.md) - volume, speaker selection and Now Playing details.
* [Setup - Inputs](SETUP-INPUTS.md) - configuring inputs, turntable mode and detection sensitivity.
