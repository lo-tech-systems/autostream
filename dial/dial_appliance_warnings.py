"""dial_appliance_warnings.py -- what an appliance may say about itself, and
the protocol-mismatch warnings the dial raises on its own.

An appliance can supply warnings (an id, a severity, a title and a message)
in its reply. The reply is untrusted text from the LAN, so
appliance_warning_entries is the one entry point and returns only data:
strings drawn from closed sets, or stripped and length-capped text.
protocol_warning and newer_appliance_names build the warnings the dial raises
itself when an appliance speaks a different protocol number. Pure: no I/O, no
clock, no threads.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, replace

from dial_mdns import appliance_display_name
from dial_values import is_int


# ---- appliance-supplied warnings ------------------------------------------
#
# The protocol is plain HTTP, so any host on the LAN can answer in an
# appliance's place: everything in a warnings reply is untrusted text.
# appliance_warning_entries is the one entry point. It only ever returns
# data (strings drawn from closed sets, or stripped and length-capped text);
# nothing it returns is a format template, a path, a command or a link.

# At most this many warnings are kept per appliance; the rest are dropped.
APPLIANCE_WARNINGS_MAX = 16
# Longest title and message kept, in characters; longer ones are truncated.
APPLIANCE_WARNING_TITLE_MAX = 40
APPLIANCE_WARNING_MESSAGE_MAX = 120
# Longest detail kept. The appliance's own detail is shorter than this, as its
# message is shorter than the message limit above; neither cap says how long
# the appliance's text is.
APPLIANCE_WARNING_DETAIL_MAX = 120
# A warning id is short and plain, so it is safe to use as a key.
APPLIANCE_WARNING_ID_RE = re.compile(r"[a-z0-9_-]{1,32}")

SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"
APPLIANCE_WARNING_SEVERITIES = (SEVERITY_INFO, SEVERITY_WARNING, SEVERITY_CRITICAL)
# An unknown or missing severity reads as the mildest.
APPLIANCE_WARNING_DEFAULT_SEVERITY = SEVERITY_INFO


@dataclass(frozen=True)
class ApplianceWarning:
    """One warning an appliance supplies, after validation. The dial sets
    everything about how it behaves (priority, no interruption, no wake);
    the appliance supplies only these fields."""
    id: str                 # [a-z0-9_-]{1,32}, unique within its appliance
    severity: str           # one of APPLIANCE_WARNING_SEVERITIES
    title: str              # non-empty, at most APPLIANCE_WARNING_TITLE_MAX characters
    message: str            # at most APPLIANCE_WARNING_MESSAGE_MAX characters
    appliance_name: str = ""  # the roster's display name, set by the core
    detail: str = ""        # the reason, at most APPLIANCE_WARNING_DETAIL_MAX characters; "" for none


def clean_text(value, limit: int) -> str:
    """*value* as plain display text of at most *limit* characters, or ""
    for anything that is not a string. Control, format (which includes the
    bidirectional overrides and isolates), surrogate, private-use and
    unassigned characters are removed, except that white-space controls and
    line separators become a space; runs of spaces collapse, the ends are
    trimmed, and the result is Unicode NFC."""
    if not isinstance(value, str):
        return ""
    value = value[:limit * 4]
    out = []
    for ch in value:
        category = unicodedata.category(ch)
        if category in ("Zl", "Zp") or (category == "Cc" and ch.isspace()):
            out.append(" ")
        elif category in ("Cc", "Cf", "Cs", "Co", "Cn"):
            continue
        else:
            out.append(ch)
    text = unicodedata.normalize("NFC", "".join(out))
    text = re.sub(r" {2,}", " ", text).strip()
    return text[:limit].rstrip()


def _enum_or_default(value, allowed: tuple, default: str) -> str:
    if isinstance(value, str):
        value = value.strip().lower()
        if value in allowed:
            return value
    return default


# The ids of the warnings a dial raises for an appliance that speaks a
# different protocol number: the appliance is older (a warning about it, on
# its row), or the dial is (one warning about this dial).
PROTOCOL_WARNING_ID = "update_appliance"
DIAL_WARNING_ID = "update_dial"
_PROTOCOL_WARNING_MESSAGE = "Its software is older than this dial's. Update it from its web UI."


def _entry_protocol(entry, own_protocol: int) -> "int | None":
    """The protocol number of a rostered appliance with an identity
    (entry.dial_proto_version: the hello's when it has been read, else the
    one its record advertises) when it differs from *own_protocol*; None
    when they agree or the appliance has not said one."""
    if not getattr(entry, "appliance_id", ""):
        return None
    protocol = getattr(entry, "dial_proto_version", 0)
    if not is_int(protocol) or protocol <= 0 or protocol == own_protocol:
        return None
    return protocol


def _entry_name(entry) -> str:
    service_name = getattr(entry, "service_name", "")
    return appliance_display_name(service_name) if isinstance(service_name, str) else ""


def protocol_warning(entry, own_protocol: int) -> ApplianceWarning | None:
    """"Update <appliance>" for a rostered appliance whose protocol number is
    lower than *own_protocol*; None when it agrees, is higher (that is the
    dial's own warning, see newer_appliance_names) or has not said one.
    Severity "warning". Access is not asked: a mismatch opens no stream, so
    it is never learned. Pure."""
    protocol = _entry_protocol(entry, own_protocol)
    if protocol is None or protocol > own_protocol:
        return None
    name = _entry_name(entry)
    return ApplianceWarning(
        id=PROTOCOL_WARNING_ID, severity=SEVERITY_WARNING,
        title=clean_text("Update " + name, APPLIANCE_WARNING_TITLE_MAX) or "Update appliance",
        message=_PROTOCOL_WARNING_MESSAGE, appliance_name=name,
    )


def newer_appliance_names(roster, own_protocol: int) -> tuple[str, ...]:
    """The names of the rostered appliances whose protocol number is higher
    than *own_protocol*, in roster order: the reading of the dial's own
    "Update this dial" warning. Pure."""
    return tuple(
        _entry_name(r) for r in roster
        if (_entry_protocol(r, own_protocol) or 0) > own_protocol
    )


def appliance_warning_entries(entries, limit: int) -> tuple[ApplianceWarning, ...]:
    """The usable warnings among *entries*, at most *limit* of them: an entry
    that is not an object, has an invalid or repeated id, or has no title once
    cleaned is dropped; over-long text is truncated; severity falls back
    to its default. At most four times *limit* entries are
    examined. Never raises."""
    try:
        out: list[ApplianceWarning] = []
        seen: set[str] = set()
        for entry in list(entries)[:4 * limit]:
            if len(out) >= limit:
                break
            if not isinstance(entry, dict):
                continue
            warning_id = entry.get("id")
            if (
                not isinstance(warning_id, str)
                or APPLIANCE_WARNING_ID_RE.fullmatch(warning_id) is None
                or warning_id in seen
            ):
                continue
            title = clean_text(entry.get("title"), APPLIANCE_WARNING_TITLE_MAX)
            if not title:
                continue
            seen.add(warning_id)
            out.append(ApplianceWarning(
                id=warning_id,
                severity=_enum_or_default(
                    entry.get("severity"), APPLIANCE_WARNING_SEVERITIES,
                    APPLIANCE_WARNING_DEFAULT_SEVERITY,
                ),
                title=title,
                message=clean_text(entry.get("message"), APPLIANCE_WARNING_MESSAGE_MAX),
                detail=clean_text(entry.get("detail"), APPLIANCE_WARNING_DETAIL_MAX),
            ))
        return tuple(out)
    except Exception:
        return ()


def attribute_appliance_warnings(warnings, name: str) -> tuple[ApplianceWarning, ...]:
    """*warnings* carrying *name* (the roster's display name) as their
    source, whatever the appliance said about itself."""
    return tuple(replace(w, appliance_name=name) for w in warnings)
