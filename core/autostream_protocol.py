"""autostream_protocol.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The client protocol's number and the shape of a client's name. This module
imports nothing from the rest of the program, so a client can carry a copy of
it and the appliance, the web pages and the dial agree on the same values.

The number is advertised as ``proto`` in the appliance's mDNS records, sent
by clients as ``protocol`` and checked by the appliance on the event stream
and on intents. It moves when a client written for the old number would no
longer work.
"""

from __future__ import annotations

import re
from typing import Optional

PROTOCOL = 4

# The intents a client may send to POST /api/v1/intents/<name>. Any other name
# is answered unknown_intent.
EXPOSED_INTENTS = (
    "outputs.set", "output.pin.submit", "outputs.want_default",
    "volume.step", "volume.set", "mute.set",
    "output.eq.set", "output.eq.reset",
    "repeat.arm", "repeat.transport", "repeat.seek",
    "dials.authorize", "dials.revoke",
)

# A dial's id and an appliance's id are both 20 lowercase hex characters.
APPLIANCE_ID_RE = re.compile(r"[0-9a-f]{20}")
CLIENT_RE = re.compile(r"(dial|peer):([0-9a-f]{20})")


def parse_client(text: str) -> Optional[tuple[str, str]]:
    """(kind, id) for a client name such as ``dial:<id>`` or ``peer:<id>``,
    or None when *text* is not one."""
    if not isinstance(text, str):
        return None
    m = CLIENT_RE.fullmatch(text)
    return (m.group(1), m.group(2)) if m else None
