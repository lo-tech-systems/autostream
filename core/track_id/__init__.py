"""track_id — provider-abstracted track identification package for autostream.

Public surface:
  models.py    — normalized dataclasses
  provider.py  — TrackIdentifier protocol
  registry.py  — built-in provider lookup
  service.py   — TrackIdentificationService (used by autostream_core)

Vibra/Shazam is currently the only supported provider. Adding another provider
requires source changes; this package is not a dynamically loaded plugin system.
"""
