# Running AutoStream With Full OwnTone

AutoStream normally bundles owntone-mini, a stripped-down build tuned for
this project. It can instead run against a full, packaged OwnTone install
(`--owntone=full` / `--owntone=skip` at install time). This document covers
what the installer sets up automatically, what you're expected to
maintain yourself, and what doesn't work in this configuration.

## What the installer configures

On every install and update, the installer edits `/etc/owntone.conf`'s
`library { }` block so its `directories` line points at AutoStream's pipe
directory (`/run/autostream-pipes`), creating the `library` block if
none exists. This is the one setting AutoStream depends on and it is
applied idempotently — safe to run repeatedly, and it only touches the
`directories` line, leaving the rest of the block alone.

This edit is skipped when OwnTone is running in owntone-mini mode (mini
manages its own settings file, not `owntone.conf`), and skipped for
`--owntone=skip` if `/etc/owntone.conf` doesn't exist yet.

## What AutoStream expects

- A reachable OwnTone JSON API at the configured `base_url`/port
  (default `http://localhost:3689`).
- `/run/autostream-pipes` present in OwnTone's library directories, as
  configured above, so it picks up AutoStream's playback pipe.

## What is not managed

Every other `/etc/owntone.conf` setting — ports, library scan behaviour,
AirPlay device names, audio backends, and so on — is yours to configure
and maintain; the installer never touches them. See upstream OwnTone's
own documentation for the full set of `owntone.conf` options.

## Capability note

Full OwnTone's JSON API does not expose the same settings surface as
owntone-mini's, so the OwnTone setup page's live settings controls do not
function against full OwnTone. Depending on the control, it is either
omitted from the page entirely or rendered inactive with a note saying the
backend does not expose it — but none of them can change full OwnTone's
settings. Speaker selection, volume, and playback control work normally;
they use the standard OwnTone API.
