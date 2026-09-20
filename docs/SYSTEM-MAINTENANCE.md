# System Maintenance

Practical guidance for keeping an autostream appliance healthy over time:
software updates, update channels, and what to do when you want the
appliance gone.

For the exact controls, see the [Setup > System > Updates](SETUP-SYSTEM.md#updates) card.
For the fields this section reports on, see [Info](INFO.md).

## Software updates

autostream can check for, download, and install its own updates. Everything
here happens from the **Updates** card on the Setup page, which has three
buttons - **Check**, **Install**, **Reboot** - plus the two toggles covered
below.

### Checking for an update manually

Tap **Check**. autostream contacts GitHub for the latest release on the
currently selected channel:

- If nothing newer is available, the card reports "No updates available."
- If an update is found, the card reports "Update available: `<version>`"
  and the button relabels to **Info** - tap it to see the release notes.
  **Install** becomes available at the same time.

### Installing an update

Tap **Install**. autostream saves your current settings, then starts the
update in the background and switches you to a progress page. The updater
downloads the release, stops the affected services (audio playback stops for
the duration), and restarts `autostream` automatically once it's done - a
full reboot isn't required for the update itself. If a previous update is
still in progress, or appears to have stalled, the Updates card shows that
state instead of letting you start a new one.

If an update fails or seems to hang, see the "Update problems" section of
[TROUBLESHOOTING.md](TROUBLESHOOTING.md).

### Automatic updates

The **Automatic updates** toggle turns on a weekly check-and-install: once
enabled, autostream looks for a new release roughly once a week and installs
it automatically if one is available on the selected channel. It's off by
default. An automatic update skips itself (quietly, trying again the
following week) if playback is active at the time, so it won't interrupt
whatever's playing.

Automatic and manual updates always use the same channel - whichever is
selected below.

### Update channels

There are two channels:

- **Stable** (default) - only full GitHub releases.
- **Dev / pre-release** - the most recently published GitHub release,
  including alpha, beta, and release-candidate builds. Use this to try
  upcoming versions early.

The **Enable pre-release updates** toggle switches between them. It's
independent of the Automatic updates toggle - you can leave automatic
updates off and still use pre-release checks manually, or run both together.
Flipping this toggle discards any update candidate a previous **Check**
already found, since it may no longer apply once the channel changes.

**Switching back to stable does not downgrade an already-installed
pre-release.** If you're running a pre-release build and switch to stable,
the next update offered will be the next numerically newer *stable* release,
whenever one ships - not the last stable version before you switched. To
force your way back onto a specific known-good build immediately, use the
console reinstall path described in
[TROUBLESHOOTING.md](TROUBLESHOOTING.md).

The Setup page's System card summary line always shows the current state at
a glance, e.g. "Auto-update: On" or "Auto-update: On - Pre-release channel".

## Uninstalling

If you want autostream off the device entirely - or want to reuse the SD
card - see [UNINSTALL.md](UNINSTALL.md). Re-imaging the card is the
supported, complete option; a best-effort uninstall script is also provided
for partial cleanup.
