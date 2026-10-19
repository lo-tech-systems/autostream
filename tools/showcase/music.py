"""The invented music the showcase shots are drawn from.

Every artist, album and title here is made up for the shots. Change a track
here and the artwork, the scenarios and both capture paths follow. The seed
drives that track's generated cover (see covers.py); the style picks the
cover's look.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Track:
    key: str          # short id used in scenario and file names
    artist: str
    album: str
    title: str
    genre: str
    style: str        # cover style, one of covers.STYLES
    seed: int         # makes the cover the same on every run
    appliance: str    # the input the record or disc is playing from


TRACKS = (
    Track("jazz", "Teodor Brandvold Trio", "Quiet Ferries", "Low Tide Waltz",
          "Jazz trio", "blocks", 11, "Turntable"),
    Track("folk", "Odalys Penhallow", "Gorse Season", "The Long Way to Marazion",
          "Folk singer-songwriter", "botanical", 23, "Turntable"),
    Track("rock", "Hollis Brake", "Second Gear Sunrise", "Fortune on the Interstate",
          "1970s rock band", "sunburst", 37, "Turntable"),
    Track("classical", "Halloran-Vesk Quartet", "Late Quartets, Vol. 2", "Andante sostenuto",
          "Classical chamber ensemble", "engraved", 41, "CD Player"),
    Track("soul", "Lyle Fontaine & The Ninth Street Four", "Rent Party at Midnight",
          "Slow Dance in the Kitchen", "Soul", "halftone", 53, "Turntable"),
    Track("electronic", "Pale Halogen", "Calder Interchange", "Night Bus to Calder",
          "Electronic", "grid", 67, "CD Player"),
    Track("ambient", "Hushfield", "Winter Orchard Recordings", "Frost on the Vines",
          "Ambient", "haze", 79, "Tape Deck"),
)

BY_KEY = {track.key: track for track in TRACKS}

# The appliances are named for their input; the speakers for their rooms.
APPLIANCE_NAMES = ("Turntable", "CD Player", "Tape Deck", "Tuner")
ROOMS = ("Lounge", "Kitchen", "Dining Room", "Bedroom", "Study", "Patio")
