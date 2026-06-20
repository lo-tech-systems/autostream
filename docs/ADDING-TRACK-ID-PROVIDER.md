# Adding A Track-Identification Provider

Autostream's track-identification code is provider-abstracted, but it is not a
dynamically loaded plugin system. Vibra/Shazam (`vibra_shazam`) is currently the
only supported provider, and the Setup page only enables or disables track
identification.

Adding another provider requires coordinated source, configuration, dependency,
test, and documentation changes. A provider picker can then be added to the
Setup page if users should be able to switch between the supported providers.

## Architecture

The provider-neutral path consists of:

- `core/track_id/provider.py`, which defines the `TrackIdentifier` protocol;
- `core/track_id/models.py`, which defines normalized results and public state;
- `core/track_id/service.py`, which handles caching, logging, and provider
  invocation;
- `core/track_id/registry.py`, which constructs one of the built-in providers;
- `core/autostream_core.py`, which selects the configured provider, schedules
  recognition, and passes provider settings into the service.

Provider-specific response objects and errors must not leak into the Home API
or Web UI. Providers return `TrackIdentificationResult`; the rest of Autostream
consumes normalized snapshots.

The configuration shape already reserves a provider identifier and nested
provider settings:

```json
{
  "track_identification": {
    "enabled": true,
    "provider": "vibra_shazam",
    "providers": {
      "vibra_shazam": {}
    }
  }
}
```

This schema makes provider selection possible, but selection is not currently
exposed in the Setup page.

## Adding A Provider

1. Add a module under `core/track_id/` containing a class that satisfies
   `TrackIdentifier`.
2. Give it a stable `provider_id`.
3. Return only normalized `TrackIdentificationResult` values. Return
   `matched=False` for a valid no-match response and raise an exception for
   dependency, configuration, transport, or upstream failures.
4. Implement `fingerprint_pcm()`. Return a stable fingerprint string when the
   service can use it as a cache key, or `None` when fingerprinting is internal
   to the provider.
5. If the provider can identify from a fingerprint without repeating work, it
   may also implement `identify_from_fingerprint()`. The service detects this
   optional method at runtime.
6. Add the provider to `core/track_id/registry.py`. Despite its name, this is
   currently an explicit built-in factory, not a discovery or registration
   mechanism.
7. Add the identifier to `TRACK_ID_KNOWN_PROVIDERS` in
   `core/autostream_config.py`. Settings for identifiers outside this allowlist
   are discarded while parsing configuration.
8. Add any required packages, helper services, files, permissions, and upgrade
   behavior to the installer.
9. Add focused provider tests plus service, configuration, and integration
   coverage.
10. Update user documentation with the provider's network, privacy,
    credentials, catalog, rate-limit, and troubleshooting requirements.

## Provider Selection In The Setup Page

The current Setup page only submits the enabled flag and preserves the existing
provider value. To let users switch providers:

- render a selector from an explicit list of supported providers;
- validate submitted identifiers rather than accepting arbitrary form values;
- save the selected `track_identification.provider`;
- render and save provider-specific settings without exposing secrets in logs
  or unrelated page output;
- rebuild the live track-identification service when the provider or its
  settings change;
- define what the UI shows when a configured provider is unavailable.

Do not expose a provider in the selector until its runtime dependencies and
installer support are available on the target appliance.

## Current Coupling To Review

`core/track_id/service.py` currently caps snapshots at 20 seconds because that
is the Vibra protocol limit. A provider needing a different limit should not
silently inherit that assumption. Move the limit into provider capabilities or
introduce another provider-neutral constraint before relying on longer windows.

The capture pipeline supplies raw mono `s16le` PCM and a sample rate. A new
provider should perform any resampling or encoding behind its adapter unless a
provider-neutral preprocessing contract is deliberately introduced.

## Completion Checklist

- The provider can be built from its configured identifier.
- Unknown or unavailable providers disable identification without crashing
  Autostream.
- No-match, matched, rate-limited, rejected, and transport-failure behavior is
  covered.
- Provider secrets and raw upstream payloads are absent from logs and public
  state.
- Existing Vibra/Shazam behavior remains unchanged.
- Setup selection, if implemented, persists and applies without restarting the
  coordinator process.
- Installation and upgrade paths provision every required dependency.
