"""webui/browser/home_model.py -- the output change helper the output routes
share.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

from typing import Optional

from autostream_intents import Intent, submit
from autostream_state import Origin


def submit_output_change(
    body: dict,
    *,
    requester: str,
    pin_requester: Optional[str],
    offset_ms: Optional[int] = None,
    mode: Optional[str] = None,
    origin: Origin = Origin.USER,
) -> dict:
    """Switch a speaker on or off, change its volume, or submit its PIN, and
    return the reply body the output routes send.

    *body* is {"id", "selected"[, "volume"]}, or {"id", "op": "pin", "pin"[,
    "selected", "volume"]}; *offset_ms* and *mode* come from the per-output
    configuration, never from the browser. *requester* names the caller for
    the intent path ("webui", "dial:<uuid>", "peer"); *pin_requester* is the
    identity that can enter a PIN for the speaker (None when the caller
    cannot). A pin op that also carries "selected" switches the speaker on
    straight after the PIN is accepted.
    """
    out_id = str(body.get("id") or "").strip()
    if not out_id:
        return {"ok": False, "error": "Missing output id"}
    op = str(body.get("op") or "").strip().lower()
    args: dict = {"id": out_id}
    name = body.get("name")
    if name:
        args["name"] = str(name)[:256]
    if op == "pin":
        args["pin"] = body.get("pin")
        if "selected" in body:
            args["selected"] = bool(body.get("selected"))
        row = "output.pin.submit"
    else:
        args["selected"] = bool(body.get("selected", False))
        row = "outputs.set"
    if args.get("selected"):
        if body.get("volume") is not None:
            # Without a level the output is started at the configured start volume.
            args["volume"] = max(0, min(100, int(body["volume"])))
        if offset_ms is not None:
            args["offset_ms"] = offset_ms
        if mode:
            args["mode"] = mode
    reply = submit(Intent(row, args, origin, requester, context=pin_requester))
    if reply.result:
        return dict(reply.result)
    return {"ok": False, "error": reply.error, "id": out_id}
