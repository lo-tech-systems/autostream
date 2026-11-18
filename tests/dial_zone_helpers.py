"""Point hit-tests over the touch geometries, for tests: thin views over
dial_touch_layout.hit_test and zone_rects_for."""
from __future__ import annotations

from dial_touch_layout import (
    BELL_ZONES,
    GEOMETRY_IDLE,
    GEOMETRY_LIST,
    GEOMETRY_MAIN,
    GEOMETRY_REPEAT,
    TouchZone,
    hit_test,
    zone_rects_for,
)


def zones_for(width: int, height: int) -> dict:
    """The active rectangle of each MAIN-geometry zone (bells skipped), in
    table order."""
    return {
        entry.zone: entry.rect
        for entry in zone_rects_for(GEOMETRY_MAIN, width, height)
        if entry.zone not in BELL_ZONES
    }


def zone_at(x: int, y: int, width: int, height: int) -> TouchZone | None:
    hit = hit_test(GEOMETRY_MAIN, x, y, width, height, skip=BELL_ZONES)
    return hit.zone if hit is not None else None


def list_zone_at(x: int, y: int, width: int, height: int) -> tuple[TouchZone, int | None] | None:
    hit = hit_test(GEOMETRY_LIST, x, y, width, height)
    return (hit.zone, hit.index) if hit is not None else None


def repeat_zone_at(x: int, y: int, width: int, height: int) -> TouchZone | None:
    hit = hit_test(GEOMETRY_REPEAT, x, y, width, height, skip=BELL_ZONES)
    return hit.zone if hit is not None else None


def idle_zone_at(x: int, y: int, width: int, height: int) -> TouchZone | None:
    hit = hit_test(GEOMETRY_IDLE, x, y, width, height)
    return hit.zone if hit is not None else None
