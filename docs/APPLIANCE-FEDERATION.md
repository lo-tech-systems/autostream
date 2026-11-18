# Multi-Appliance Control

This document describes how one autostream appliance shows and controls another:
the mDNS advertisement schema, appliance identity format, the relay routes,
versioning rules, architecture boundaries, and HTTP-only threat-model
limitations.

---

## Architecture Overview

Multi-appliance control uses a **bound-appliance relay** pattern. The browser and
iOS Home Screen application are permanently bound to the appliance from which they
were launched. Every appliance follows the others it sees on the network: it reads
each one's state, keeps it current from the other's change stream, and sends the
other's controls as intents. When the user selects another appliance, the browser
reads and controls it through the bound appliance's relay routes, with the same
page code and the same message shapes it uses for the bound appliance itself.

Key boundaries:

| Layer | Responsibility |
|---|---|
| Shared mDNS transport (`autostream_mdns.py`) | Raw Avahi event parsing; no policy |
| Peer registry (`autostream_peer_registry.py`) | `_autostream._tcp` event handling; in-memory registry of sightings |
| Peer client (`autostream_peer_client.py`) | One live copy of another appliance: state, change stream, intents |
| Appliance follower (`autostream_appliances.py`) | One client per sighting; the `peers` state part; occupancy; resolving an appliance id |
| Relay (`webui/peer/relay.py`) | The browser-facing routes for another appliance |

The browser never navigates to another appliance and never receives its cookies,
CSRF tokens, IP address, or direct URL.

---

## mDNS Advertisement Schema

Each autostream appliance that has discovery enabled announces itself on the local
LAN as an `_autostream._tcp` Avahi service. The service file is written by
`autostream_admin write-appliance-service`.

### Service record

| Field | Value |
|---|---|
| Service type | `_autostream._tcp` |
| Port | 80 (HTTP) |
| Host | The appliance's mDNS hostname (e.g. `living-room.local`) |

### TXT records

| Key | Example value | Description |
|---|---|---|
| `id` | `a1b2c3d4e5f6a7b8c9d0` | Appliance identity (see below) |
| `version` | `0.8.0` | Installed autostream version string |
| `control` | `on` | Whether other appliances may control this one |
| `proto` | `4` | The client protocol version the appliance speaks |

A missing or malformed `id` TXT record causes the sighting to be ignored. An
appliance that speaks a different protocol version is listed but not followed
until its version matches.

### Registry refresh and expiry

Peer appliances keep an in-process mDNS registry on top of Avahi. Each resolved
address record is tracked with a `last_seen` timestamp. Autostream keeps the
long-lived Avahi event stream for low-latency adds and explicit removals, and also
runs a periodic one-shot `avahi-browse --no-fail -r -t -p _autostream._tcp` dump
to re-confirm records when an event was missed.

A record is considered stale when it was not seen in the most recent refresh
cycle. Stale records remain in the registry until the configured mDNS grace period
expires, but selection prefers a non-stale address for the same appliance identity.
This means an appliance that moves from one interface or IP address to another is
usually dialed at the live address after one refresh cycle; the grace period only
controls when the old address is finally removed.

The **mDNS Grace Period** setting lives in Setup -> System and is owned by
autostream's general configuration. Core startup injects the configured value
into the appliance discovery browser and also forwards the same value to
OwnTone/owntone-mini for its native device-removal setting.

---

## Appliance Identity

Each autostream derives a stable, non-secret 20-character lowercase hexadecimal
identity string.

**Derivation:**

1. Read the Raspberry Pi CPU serial from `/proc/cpuinfo`.
2. Normalize the serial (strip whitespace, lowercase, left-pad to 16 chars with zeros).
3. Compute `HMAC-SHA256(key=b"autostream-appliance-id-v1", msg=serial.encode())`.
4. Take the first 10 bytes (80 bits) of the digest and hex-encode them.

**Persistent fallback:**

When the CPU serial is unavailable (non-Pi hardware, `/proc/cpuinfo` absent), the
installer creates a random fallback at `/var/lib/autostream/appliance-id`. The
fallback is created once during install, preserved across software updates and factory
resets, and removed only by a full uninstall. The runtime reads the file but never
creates or repairs it.

**Properties:**

* Always exactly 20 lowercase hex characters.
* The raw CPU serial is never stored, logged, or transmitted.
* The identity is process-lifetime cached after the first read.
* The same identity and same hostname may appear on multiple IP addresses during
  normal multi-homing or adapter failover.
* The same identity with multiple hostnames is treated as a genuine conflict; the
  peer is suppressed and a warning is logged.

---

## The Relay Routes

The relay serves another appliance in the shapes the appliance's own routes use,
so a page that draws this appliance draws another one with the same code. `<id>` is
the other appliance's 20-character identity.

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/peers/<id>/state` | The other appliance's state, whole or by part (`?parts=`) |
| `GET` | `/api/v1/peers/<id>/events` | Its change stream, passed on as it comes, with its own event ids |
| `POST` | `/api/v1/peers/<id>/intents/<name>` | One of its controls, sent as an intent |

The state and the stream carry the other appliance's versions, so a browser that
reconnects resumes against them. The pages `/a/<id>/` and `/a/<id>/equaliser`
show the Home and Equaliser pages for that appliance.

The `peers` part of this appliance's own state lists the appliances it follows
(identity, hostname, version, whether it can be reached, whether it may be
controlled) and is what the appliance selector shows.

### Refusals

| Code | Meaning |
|---|---|
| `unknown_appliance` | Unknown appliance id, or one that is not followed |
| `bound_appliance` | The id is this appliance's own; use its own routes |
| `control_disabled` | The other appliance does not allow control by other appliances |
| `appliance_conflict` | The id is announced under several hostnames |
| `appliance_unconfigured` | The other appliance is reachable but not set up yet |

A transport failure while following an appliance is retried with a growing delay
(1, 2, 4, 8, 15, then 30 seconds) for as long as it lasts, and the appliance is
shown as unreachable meanwhile.

---

## Versioning and Compatibility

* The protocol version is advertised as `proto=<n>` in the TXT record, and an
  appliance on another version is not followed.
* The `version` TXT key carries the human-readable autostream release string for
  display in the selector UI; it does not affect protocol compatibility.

---

## HTTP-Only Threat Model

autostream uses plain HTTP. This is intentional: publicly trusted TLS certificates
are not available for `.local` hostnames, and distributing a private CA to every
phone would conflict with autostream's zero-configuration design.

**What this means for the relay:**

* The relay routes are open to the LAN, as the appliance's own state route is. An
  intent sent through them identifies the browser by the token the page carries,
  and is refused when the other appliance does not allow control.
* A passive observer on the same LAN can read what the appliances exchange.

**Appropriate use:**

The protocol is designed for a trusted home LAN. It is not appropriate for use over
untrusted networks, the Internet, or networks where other tenants may be present.

The same limitations already apply to the local session cookie and PIN nonce
mechanism - see the **Authentication and PIN security** section in
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) for the full threat-model description.

---

## Manual Verification Steps

The following checks require two physical autostream appliances on the same LAN and
an iPhone or iPad.

### Two-appliance acceptance checklist

- [ ] Both appliances are reachable at their own `http://<hostname>.local/` addresses.
- [ ] `avahi-browse _autostream._tcp -t -r` on each appliance shows the other's
      `id`, `proto`, `control`, and `version` TXT records.
- [ ] The appliance selector pill appears on the Home page when both are online.
- [ ] Selecting the remote appliance shows the remote appliance's hostname in the pill.
- [ ] Volume changes on the Home page apply to the remote appliance.
- [ ] Opening the Equaliser page while remote shows the remote appliance's EQ bands
      and allows saving changes.
- [ ] Selecting the bound appliance by name returns to normal local control.
- [ ] Powering off the remote appliance triggers an automatic return to the bound
      appliance within 15 seconds.
- [ ] Disabling "Show this autostream to other appliances" on one appliance removes it
      from the other's selector within the next discovery refresh.

### iOS Safari and Home Screen mode checklist

- [ ] In Safari, navigate to `http://<hostname>.local/`.
- [ ] Use **Share → Add to Home Screen** to install the PWA.
- [ ] Launch the PWA from the Home Screen; confirm it opens at the bound appliance's
      URL (not the remote appliance's URL even if a remote was previously selected).
- [ ] Select a remote appliance; confirm the URL bar (if visible in Safari) does not
      change to the remote hostname.
- [ ] Tap the selector pill; confirm the dropdown renders correctly on an iPhone-size
      viewport.
- [ ] With a remote appliance selected, rotate the device; confirm the selector and
      controls reflow correctly.
- [ ] With a remote appliance selected, background the PWA for 30+ seconds, then
      resume; confirm the remote appliance state is re-fetched.

If hardware is unavailable, record that these checks were not performed and complete
all automated verification instead.

---

## Cross-Appliance Output Usage

When multiple appliances share the same AirPlay speakers, autostream shows which
outputs are in use by a neighbouring appliance so the user does not inadvertently
take over a speaker that is already playing.

### How it works

Each appliance follows the others it sees (see the architecture above). From the
state it holds for each one, it works out which speakers that appliance is
playing: an appliance counts while it is reachable and has a playback session,
and each speaker it has switched on, that the player reports and that is not
waiting for a PIN, is in use. When two appliances report one speaker name, the
first by hostname wins.

The result is handed to the output authority, which marks each speaker with the
appliance using it. The Home page shows "In Use by &lt;hostname&gt;" on that
speaker's card.

Speaker names are **not** placed in mDNS TXT records; they are read from the other
appliance's state over HTTP.

### Event-driven, best-effort

The occupancy follows the other appliances' change streams, so a change shows as
soon as the other appliance reports it. If Wi-Fi is lost or the other appliance
crashes, the appliance is shown as unreachable after its stream falls silent and
its speakers are released.

### Navigation shortcut

When *Allow control of other appliances* is enabled (Setup → Personalisation), an
output card that shows "In Use by &lt;hostname&gt;" becomes tappable. Tapping anywhere
on the card (except the toggle switch or volume slider) navigates directly to that
appliance's Home page - equivalent to selecting it from the appliance
selector dropdown. The card remains visually greyed-out; only the status pill gains
a green outline to indicate the remote ownership.

### Constraints

- Locally selected outputs are never marked as occupied regardless of remote reports.
- The occupancy is held in memory and read from there on every browser-facing request
  path; no remote HTTP is performed during a toggle or page load.

---

## Wi-Fi adapter changes and mDNS

When an autostream appliance switches its active Wi-Fi interface (for example, adopting a USB adapter or falling back to built-in after USB loss), Avahi publishes over the new interface. The mDNS service types, TXT record schema, and appliance identity are unchanged; only the source address of the announcement changes.

Discovery registries on peer appliances track each address record and select a
non-stale address for the appliance identity. When an adapter change produces a
remove event followed by an add event with a new IP:

- The old sighting is removed or allowed to expire after the mDNS grace period.
- Requests to a peer automatically use the updated address after the next discovery poll.
- A brief gap (typically one to a few seconds) may occur between the remove and add events. The peer appliance's UI shows the remote as offline during this window.
- If a graceful remove event is missed, the periodic dump marks the old address
  stale after one refresh cycle and selection moves to the live address.

`dnsmasq` is used only during the setup hotspot (captive portal DHCP/DNS). It is not involved in normal mDNS service announcements.
