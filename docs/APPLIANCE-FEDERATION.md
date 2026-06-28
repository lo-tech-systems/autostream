# Appliance Federation Protocol

This document describes the protocol used by autostream multi-appliance control:
the mDNS advertisement schema, appliance identity format, federation API, token
lifecycle, versioning rules, architecture boundaries, and HTTP-only threat-model
limitations.

---

## Architecture Overview

Multi-appliance control uses a **bound-appliance gateway** pattern. The browser and
iOS Home Screen application are permanently bound to the appliance from which they
were launched. When the user selects a remote appliance, the bound appliance's server
makes server-to-server requests to the remote appliance's federation API and relays
the result.

Key boundaries:

| Layer | Responsibility |
|---|---|
| Shared mDNS transport (`autostream_mdns.py`) | Raw Avahi event parsing; no policy |
| Appliance discovery adapter (`autostream_appliances.py`) | `_autostream._tcp` event handling; in-memory registry |
| Bound-appliance gateway (`autostream_appliance_gateway.py`) | Token acquisition, request forwarding, error normalization |
| Browser-facing gateway API (`/api/appliances/<id>/…`) | Thin proxy; returns browser-contract JSON |
| Target federation API (`/api/federation/v1/…`) | Reads and mutates local state; validates bearer tokens |

The browser never navigates to a remote appliance and never receives the remote
appliance's cookies, CSRF tokens, federation tokens, IP address, or direct URL.

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
| `ui` | `v1` | Web UI API version |
| `federation` | `v1` | Federation API version |
| `version` | `0.4.1` | Installed autostream version string |

A missing or malformed `id` TXT record causes the sighting to be ignored. A missing
`federation` key is treated as incompatible (the peer is listed in the selector but
the gateway will reject federation attempts with `remote_bad_response`).

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
  peer is suppressed with `appliance_conflicted` and a log warning.

---

## Federation API

### Version

Current version: **v1**

All federation endpoints are under `/api/federation/v1/`. The version is fixed in
the URL path. A gateway will not attempt federation with a peer that does not
advertise `federation=v1` in its TXT record.

### Token acquisition

Before making any federation request, the gateway acquires a short-lived bearer token
from the target:

```
POST /api/federation/v1/session
Content-Type: application/json
Body: {}

Response 200:
{
  "ok": true,
  "token": "<40-char hex string>",
  "expires_in": 600,
  "federation_version": 1
}
```

The token is issued per source IP and stored in memory on the target appliance. It
expires after **600 seconds (10 minutes)** and is evicted on service restart.

**Rate limit:** 5 successful issuances per 60-second rolling window per source IP.
The target returns HTTP 429 with a `retry_after` field when the limit is exceeded.

All subsequent federation requests include:

```
Authorization: Bearer <token>
```

### Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/federation/v1/session` | Acquire bearer token |
| `GET` | `/api/federation/v1/home` | Read Home state (volume, outputs, play state) |
| `POST` | `/api/federation/v1/output` | Toggle or select an AirPlay output |
| `GET` | `/api/federation/v1/equaliser` | Read Equaliser state (bands, gain) |
| `POST` | `/api/federation/v1/equaliser/config` | Apply one EQ band or gain field |
| `POST` | `/api/federation/v1/equaliser/reset` | Zero all EQ fields |
| `GET` | `/api/federation/v1/equaliser/status` | Read live auto-trim state |

The **session** response (`POST /api/federation/v1/session`) includes `"federation_version": 1`
and `"expires_in": 600`. The gateway validates that both values match these exact constants
and rejects the response (returning `remote_bad_response`) if they do not. Other federation
endpoints do not include `federation_version` in their responses.

### Error codes returned by the target

| Code | Meaning |
|---|---|
| `appliance_unconfigured` | Target has no speakers configured yet |
| `appliance_identity_unavailable` | Target has no stable identity |

### Error codes produced by the gateway (browser-contract)

| Code | Source | Meaning |
|---|---|---|
| `not_found` | Gateway | Unknown appliance ID |
| `appliance_conflicted` | Gateway | Appliance ID has multiple conflicting identities |
| `appliance_offline` | Gateway | No sighting in the local registry |
| `appliance_unconfigured` | Gateway (relayed) | Target not ready |
| `appliance_identity_unavailable` | Gateway (relayed) | Target identity unavailable |
| `remote_timeout` | Gateway | Target did not respond within timeout |
| `remote_bad_response` | Gateway | Target response malformed or version mismatch |
| `remote_backoff` | Gateway | Token rate-limit hit; includes `retry_after` field |

---

## Token Lifecycle

```
Gateway                          Target
  │  POST /api/federation/v1/session  │
  │ ────────────────────────────────► │  issues 160-bit hex token
  │ ◄────────────────────────────────  bound to gateway IP, TTL 600 s
  │                                   │
  │  GET /api/federation/v1/home      │
  │  Authorization: Bearer <token>    │
  │ ────────────────────────────────► │  validates: token exists, not expired,
  │ ◄────────────────────────────────  source IP matches
  │                                   │
  │  (token expires after 600 s)      │
  │  (gateway evicts on error / 401)  │
  │  POST /api/federation/v1/session  │
  │ ────────────────────────────────► │  re-issues
```

* Tokens are in-memory only. All sessions are lost when `autostream.service` restarts.
* The gateway evicts its cached token and re-acquires on any 401 response.
* The target enforces strict IP binding: a token issued to `192.168.1.10` cannot be
  used from `192.168.1.11`.
* Gateway token cache entries are keyed by target appliance identity, not by the
  target's IP address. If the target appliance changes IP but the gateway's source
  IP is unchanged, the existing token remains valid and the gateway only needs the
  refreshed discovery address. If the target restarts or the gateway source IP
  changes, the next 401 response triggers the existing retry-once re-auth path.

---

## Versioning and Compatibility

* The federation version is advertised as `federation=v1` in the TXT record.
* Future protocol changes that are not backwards-compatible will increment the version
  (e.g. `federation=v2`) and use a new URL path (`/api/federation/v2/…`).
* A gateway that discovers a peer advertising only `federation=v2` will not attempt v1
  federation and will return `remote_bad_response` to the browser.
* The `version` TXT key carries the human-readable autostream release string for
  display in the selector UI; it does not affect protocol compatibility.

---

## HTTP-Only Threat Model

autostream uses plain HTTP. This is intentional: publicly trusted TLS certificates
are not available for `.local` hostnames, and distributing a private CA to every
phone would conflict with autostream's zero-configuration design.

**What this means for the federation token:**

* The bearer token is transmitted in plaintext over the LAN.
* A passive observer on the same LAN can capture the token and replay it before it
  expires (TTL 10 minutes).
* The IP binding provides no meaningful protection against an on-path attacker.
* **The federation token does not upgrade the existing LAN threat model.** It
  provides the same level of protection as the existing session cookie: it restricts
  casual cross-origin use but offers no cryptographic confidentiality.

**Appropriate use:**

The protocol is designed for a trusted home LAN. It is not appropriate for use over
untrusted networks, the Internet, or networks where other tenants may be present.

The same limitations already apply to the local session cookie and PIN nonce
mechanism — see the **Authentication and PIN security** section in
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) for the full threat-model description.

---

## Manual Verification Steps

The following checks require two physical autostream appliances on the same LAN and
an iPhone or iPad.

### Two-appliance acceptance checklist

- [ ] Both appliances are reachable at their own `http://<hostname>.local/` addresses.
- [ ] `avahi-browse _autostream._tcp -t -r` on each appliance shows the other's
      `id`, `federation=v1`, `ui=v1`, and `version` TXT records.
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
      resume; confirm polling resumes and the remote appliance state is re-fetched.

If hardware is unavailable, record that these checks were not performed and complete
all automated verification instead.

---

## Cross-Appliance Output Usage

When multiple appliances share the same AirPlay speakers, autostream shows which
outputs are in use by a neighbouring appliance so the user does not inadvertently
take over a speaker that is already playing.

### How it works

Each autostream appliance that is currently playing announces itself on the LAN as
an `_autostream-playing._tcp` Avahi service. The appliance includes
`dial_api=v1 audio_status=v1` TXT keys in this announcement.

A background poller on each appliance browses `_autostream-playing._tcp`, queries
`GET /api/audio/status` from each discovered neighbour, and populates a local
in-memory occupancy cache.

The occupancy cache drives the Home page UI and prevents automatic or user-initiated
enablement of an output that is actively used by a neighbour.

Output names are **not** placed in mDNS TXT records; they are fetched over HTTP only.

### TTL-based, best-effort

The cache is TTL-based, not a distributed lock. Occupancy entries expire
automatically. If Wi-Fi is lost or the remote appliance crashes without sending a
goodbye packet, stale entries persist until their TTL elapses (at most a few seconds
longer than twice the poll interval).

There is no push or subscription mechanism; the poller is purely pull-based.

### Poll interval

The poll interval defaults to 3 seconds. A shorter interval reduces the time a
stale occupied state is shown; a longer interval reduces LAN traffic.

### Constraints

- Only appliances announcing `dial_api=v1` **and** `audio_status=v1` are polled.
- At most 4 neighbours are queried concurrently.
- Locally selected outputs are never marked as occupied regardless of remote reports.
- The occupancy check is cache-only on all browser-facing request paths; no remote
  HTTP is performed during a toggle or page load.

---

## Wi-Fi adapter changes and mDNS

When an autostream appliance switches its active Wi-Fi interface (for example, adopting a USB adapter or falling back to built-in after USB loss), Avahi publishes over the new interface. The mDNS service types, TXT record schema, and appliance identity are unchanged; only the source address of the announcement changes.

Discovery registries on peer appliances track each address record and select a
non-stale address for the appliance identity. When an adapter change produces a
remove event followed by an add event with a new IP:

- The old sighting is removed or allowed to expire after the mDNS grace period.
- HTTP requests to a peer automatically use the updated address after the next discovery poll.
- A brief gap (typically one to a few seconds) may occur between the remove and add events. The peer appliance's UI shows the remote as offline during this window.
- If a graceful remove event is missed, the periodic dump marks the old address
  stale after one refresh cycle and selection moves to the live address.
- Gateway backoff recorded against the old IP is cleared when the resolved
  sighting changes to a new IP, so stale-address failures do not keep returning
  429 once discovery has refreshed.

`dnsmasq` is used only during the setup hotspot (captive portal DHCP/DNS). It is not involved in normal mDNS service announcements.
