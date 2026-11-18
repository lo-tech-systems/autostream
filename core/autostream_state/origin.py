"""autostream_state.origin -- who caused a change."""
from __future__ import annotations

from enum import Enum


class Origin(str, Enum):
    """Who caused a change."""

    USER = "user"
    SYSTEM = "system"
    SESSION = "session"
    POLICY = "policy"
    DEVICE = "device"
    ADOPTED = "adopted"
    BACKEND = "backend"
