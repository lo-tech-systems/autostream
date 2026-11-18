#!/usr/bin/env python3
"""autostream_auth.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Lightweight, HTTP-only authentication for the Autostream WebUI.

Design goals
- Optional: enabled only when a valid PIN file exists on the boot partition.
- Simple: protects all routes except a small allowlist.
- "App-like" friendly: intended for iOS Add-to-Home-Screen usage.
- Stateless-ish: short-lived nonce for login proof + 24h session cookie.

Threat model note
- This is NOT a replacement for HTTPS. It is meant to prevent casual/accidental access
  on a local home network. With HTTP, a capable on-LAN attacker can still sniff/hijack.

Flow
1) If PIN.TXT exists (and is valid), unauthenticated requests to protected routes
   are redirected to /auth?next=<path>.
   A user-configured PIN override takes precedence over the boot-partition
   PIN. If the override is present but malformed (bad characters, wrong
   length, or unreadable), the factory boot-partition PIN is used instead
   when one is valid; only if no valid PIN exists anywhere does auth become
   disabled.
2) GET /auth renders a PIN entry page.
3) Client computes proof = SHA256(nonce + PIN) and POSTs JSON to /api/auth/verify.
4) Server recomputes and compares; if OK, issues a random session cookie (24h).

The module is intentionally self-contained and avoids dependencies beyond stdlib.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import urllib.parse
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import logging
from autostream_config import read_pin_override, write_pin_override, STATE_PATH
LOG = logging.getLogger(__name__)

# ----------------------------
# Configuration
# ----------------------------

PIN_FILENAME = "pin.txt"
# Raspberry Pi OS variants commonly mount the FAT boot partition here.
PIN_PATH_CANDIDATES = (
    f"/boot/{PIN_FILENAME}",
    f"/boot/firmware/{PIN_FILENAME}",
)

PIN_REGEX = re.compile(r"^[A-Za-z0-9-]{4,20}$")
PIN_REJECT_HEADER = "X-Autostream-Auth-Reason"

# Pin configuration status values (stringy on purpose; no new deps)
PIN_STATUS_OK = "ok"
PIN_STATUS_MISSING = "missing"
PIN_STATUS_INVALID = "invalid"
PIN_STATUS_UNREADABLE = "unreadable"

# Cookie names
SESSION_COOKIE_NAME = "autostream_session"

# Lifetimes
SESSION_TTL_SECONDS = 24 * 60 * 60
NONCE_TTL_SECONDS = 60

# Brute-force throttling (best-effort; in-memory)
MAX_FAILED_ATTEMPTS = 5
MAX_NONCES_PER_CLIENT = 8
BACKOFF_BASE_SECONDS = 5
BACKOFF_MAX_SECONDS = 5 * 60

# Routes not requiring authentication
ALLOWLIST_PATHS = {
    "/",
    "/about",
    "/api/about/system",
    "/equaliser",
    "/logs",
    "/service",
    "/auth",
    "/api/status",
    "/api/auth/verify",
    "/api/log-level",
    "/api/owntone/outputs_state",
    "/api/output_eq/config",
    "/api/output_eq/status",
    "/api/service/reset",
    "/api/service/config",
    "/api/audio/status",
    "/api/dial/capabilities",
    "/api/appliances",
}

# Path prefixes exempt from authentication (dynamic segments).
# Implement prefix matching rather than adding literal remote IDs to the allowlist.
ALLOWLIST_PREFIXES = (
    "/api/appliances/",
    "/a/",
)

# Static asset extensions that must never trigger an auth redirect.
# If these reach Python (nginx misconfiguration or missing file), the correct
# response is a 404 — not a redirect to /auth, which would overwrite the
# per-client nonce and lock the user out of PIN-protected pages.
_STATIC_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".css", ".js", ".woff", ".woff2", ".ttf",
})


# ----------------------------
# Helpers
# ----------------------------


def _now() -> int:
    return int(time.time())


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def safe_next_path(raw_next: str) -> str:
    """Allow only relative paths on this host."""
    if not raw_next:
        return "/"
    # Decode once (query param)
    nxt = urllib.parse.unquote(raw_next)
    # Must be a path that starts with /
    if not nxt.startswith("/"):
        return "/"
    # Prevent scheme/host tricks like //evil.com
    if nxt.startswith("//"):
        return "/"
    # Basic normalize
    return nxt

FLASH_COOKIE_NAME: str = "autostream_flash"

def parse_cookie_header(cookie_header: Optional[str]) -> Dict[str, str]:
    if not cookie_header:
        return {}
    out: Dict[str, str] = {}
    parts = cookie_header.split(";")
    for part in parts:
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ----------------------------
# State
# ----------------------------


@dataclass
class Session:
    token: str
    expires_at: int
    csrf_token: str
    authenticated: bool = True


@dataclass
class Nonce:
    value: str
    expires_at: int


class AuthManager:
    """Holds auth state (sessions/nonces) and provides handler helpers."""

    def __init__(
        self,
        config_path: str,
        state_path: str = STATE_PATH,
    ) -> None:
        self._config_path = config_path
        self._state_path = state_path

        # Lock protecting _sessions, _nonces, and _attempts.
        # RLock allows _gc() to be called while the lock is already held.
        self._lock = threading.RLock()

        # In-memory state
        self._sessions: Dict[str, Session] = {}
        # client_key → {nonce_value → Nonce}; multiple outstanding nonces per client
        self._nonces: Dict[str, Dict[str, Nonce]] = {}
        self._attempts: Dict[str, tuple[int, float]] = {}  # client_key -> (fails, blocked_until_epoch)

        # PIN cache
        self._pin_value: Optional[str] = None
        self._pin_mtime: Optional[float] = None
        self._pin_path: Optional[str] = None
        self._pin_source: Optional[str] = None
        self._pin_status: str = PIN_STATUS_MISSING
        # Explicit flag so the cache sentinel is not conflated with the status value.
        # Once True, the PIN is not re-read from disk (process restart required to
        # pick up external PIN file changes).
        self._pin_loaded: bool = False

    # ------------------------
    # PIN
    # ------------------------

    def get_pin_status(self) -> str:
        return self._pin_status

    def _read_pin_file(self) -> Tuple[Optional[str], Optional[str], Optional[float], str]:
        """Return (pin, path, mtime, status). Pin is first non-empty line stripped."""
        for path in PIN_PATH_CANDIDATES:
            try:
                st = os.stat(path)
            except FileNotFoundError:
                continue
            except OSError:
                # Exists maybe, but can't stat reliably
                return None, path, None, PIN_STATUS_UNREADABLE

            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        candidate = line.strip()
                        if candidate:
                            return candidate, path, st.st_mtime, PIN_STATUS_OK
                # File exists but had no non-empty line
                return None, path, st.st_mtime, PIN_STATUS_INVALID
            except OSError:
                return None, path, st.st_mtime, PIN_STATUS_UNREADABLE

        # No candidate paths existed
        return None, None, None, PIN_STATUS_MISSING

    def _read_pin_override(self) -> Tuple[Optional[str], Optional[str], Optional[float], str, bool]:
        """Return (pin, path, mtime, status, present) for config override."""
        try:
            pin, present = read_pin_override(self._state_path)
        except (OSError, ValueError):
            return None, self._state_path, None, PIN_STATUS_UNREADABLE, True

        if not present:
            return None, self._state_path, None, PIN_STATUS_MISSING, False

        try:
            st = os.stat(self._state_path)
            mtime = st.st_mtime
        except OSError:
            mtime = None

        return pin, self._state_path, mtime, PIN_STATUS_OK, True


    def get_pin_if_enabled(self) -> Optional[str]:
        """Return the configured PIN, or None if missing/invalid/unreadable.

        The result is cached for the process lifetime. A process restart is
        required to pick up external PIN file changes (e.g. adding/removing
        pin.txt from the boot partition, or editing pin_override in the INI).
        """
        if self._pin_loaded:
            if self._pin_status == PIN_STATUS_OK:
                LOG.debug(
                    "PIN cache hit: using cached PIN from %s source=%s (mtime=%s)",
                    self._pin_path,
                    self._pin_source,
                    self._pin_mtime,
                )
            else:
                LOG.debug(
                    "PIN cache hit: status=%s source=%s path=%r",
                    self._pin_status,
                    self._pin_source,
                    self._pin_path,
                )
            return self._pin_value

        pin, path, mtime, status, present = self._read_pin_override()
        source = "config"
        if present:
            LOG.debug(
                "PIN read result: pin_len=%s path=%r mtime=%r status=%s source=%s",
                len(pin) if pin else None,
                path,
                mtime,
                status,
                source,
            )
            if not pin or not PIN_REGEX.match(pin):
                # Config override is present but malformed (bad characters,
                # wrong length, or the state file could not be read). A
                # corrupt/typo'd override must not silently strip PIN
                # protection from the appliance, so fall back to the factory
                # (boot-partition) PIN when one is available and valid.
                # The PIN value itself is never logged, only presence/status.
                LOG.warning(
                    "Config PIN override is present but invalid; "
                    "falling back to the factory PIN if available. "
                    "path=%r status=%s pin_len=%s",
                    path,
                    status,
                    len(pin) if pin else None,
                )
                override_path, override_mtime, override_status = path, mtime, status
                boot_pin, boot_path, boot_mtime, boot_status = self._read_pin_file()
                if boot_pin and PIN_REGEX.match(boot_pin):
                    pin, path, mtime, status = boot_pin, boot_path, boot_mtime, boot_status
                    source = "boot"
                    LOG.warning(
                        "Using the factory PIN in place of the malformed config override."
                    )
                else:
                    # No usable factory PIN either. Report the override's own
                    # status/path (e.g. invalid/unreadable) rather than the
                    # factory read's, since the override is the reason the
                    # appliance has no PIN — this keeps the reported status
                    # meaningful instead of introducing a new combined state.
                    pin, path, mtime, status = None, override_path, override_mtime, override_status
        else:
            pin, path, mtime, status = self._read_pin_file()
            source = "boot"
            LOG.debug(
                "PIN read result: pin_len=%s path=%r mtime=%r status=%s source=%s",
                len(pin) if pin else None,
                path,
                mtime,
                status,
                source,
            )

        # Valid PIN
        if pin and PIN_REGEX.match(pin):
            self._pin_value = pin
            self._pin_path = path
            self._pin_mtime = mtime
            self._pin_source = source
            self._pin_status = PIN_STATUS_OK
            self._pin_loaded = True
            LOG.info(
                "Valid PIN loaded from %s source=%s (mtime=%s)",
                path,
                source,
                mtime,
            )
            return pin

        # No usable PIN anywhere (override missing/malformed with no valid
        # factory fallback, or factory PIN itself missing/invalid). Auth
        # is disabled in this state (see is_enabled/requires_auth) rather
        # than locking the appliance down.
        self._pin_value = None
        self._pin_path = path
        self._pin_mtime = mtime
        self._pin_source = source
        self._pin_loaded = True

        # Distinguish invalid vs missing vs unreadable
        if status == PIN_STATUS_OK:
            # status OK here means we read a non-empty line but regex failed
            self._pin_status = PIN_STATUS_INVALID
            LOG.warning(
                "PIN file read OK but PIN is invalid (regex mismatch): pin_len=%s from %s",
                len(pin) if pin else None,
                path,
            )
        else:
            self._pin_status = status
            LOG.warning(
                "PIN unavailable: status=%s path=%s",
                status,
                path,
            )

        return None

    def get_boot_pin_value(self) -> Optional[str]:
        """Return the current PIN from the boot partition only, or None if absent/invalid.

        Reads directly from /boot/firmware/pin.txt or /boot/pin.txt (the
        PIN_PATH_CANDIDATES list). Does not consult the config-file override
        and does not use the internal cache.

        Used for display (e.g. the factory reset confirmation modal) and as
        the emergency authentication fallback during the early-uptime window
        when a user-configured PIN is in effect.
        The returned value has already been validated against PIN_REGEX.
        """
        pin, _path, _mtime, status = self._read_pin_file()
        if status == PIN_STATUS_OK and pin and PIN_REGEX.match(pin):
            return pin
        return None

    def set_pin(self, new_pin: str) -> tuple[int, dict]:
        """
        Set or replace the configured PIN.

        Rules:
          - new_pin must match PIN_REGEX
          - writes the new PIN override to the main INI
          - updates in-memory cache on success
          - invalidates all active sessions so a compromised session cannot
            persist after a PIN change

        Returns:
          (status_code, payload_dict)
        """
        new_pin = (new_pin or "").strip()

        if not PIN_REGEX.match(new_pin):
            return 400, {
                "ok": False,
                "error": "PIN must be 4-20 characters using letters, numbers, or hyphens",
                "pin_status": self.get_pin_status(),
            }

        try:
            write_pin_override(self._state_path, new_pin)

            try:
                st = os.stat(self._state_path)
                mtime = st.st_mtime
            except OSError:
                mtime = None

            self._pin_value = new_pin
            self._pin_path = self._state_path
            self._pin_mtime = mtime
            self._pin_source = "config"
            self._pin_status = PIN_STATUS_OK
            self._pin_loaded = True

            # Revoke all active sessions so that anyone who held a session
            # under the old PIN must re-authenticate with the new one.
            with self._lock:
                self._sessions.clear()

            LOG.info(
                "PIN updated at %s source=%s (pin_len=%s, mtime=%r); all sessions invalidated",
                self._state_path,
                self._pin_source,
                len(new_pin),
                mtime,
            )

            return 200, {
                "ok": True,
                "pin_status": self._pin_status,
                "path": self._state_path,
                "source": self._pin_source,
            }

        except (OSError, ValueError) as e:
            LOG.warning("Failed to update PIN override at %s: %s", self._state_path, e)
            return 500, {
                "ok": False,
                "error": "Failed to write PIN",
                "pin_status": self.get_pin_status(),
                "detail": str(e),
            }


    def is_enabled(self) -> bool:
        return self.get_pin_if_enabled() is not None


    # ------------------------
    # Auth decisions
    # ------------------------

    def requires_auth(self, path: str) -> bool:
        # If no PIN is configured, auth is disabled — all paths are open.
        if self.get_pin_if_enabled() is None:
            return False
        if path in ALLOWLIST_PATHS:
            return False
        for prefix in ALLOWLIST_PREFIXES:
            if path.startswith(prefix):
                return False
        # Static assets must never trigger an auth redirect. If they reach
        # Python (e.g. nginx misconfiguration, missing file), the correct
        # outcome is a 404 — not a /auth redirect that would overwrite the
        # per-client nonce and lock the user out.
        _, ext = os.path.splitext(path)
        if ext.lower() in _STATIC_EXTENSIONS:
            return False
        return True

    def is_authenticated(self, headers) -> bool:
        self._gc()  # opportunistic expiry

        cookie = parse_cookie_header(headers.get("Cookie"))
        token = cookie.get(SESSION_COOKIE_NAME)
        if not token:
            return False
        with self._lock:
            sess = self._sessions.get(token)
            if not sess:
                return False
            if sess.expires_at <= _now():
                self._sessions.pop(token, None)
                return False
        return sess.authenticated

    def require_authenticated_if_pin_enabled(
        self, handler, *, redirect_path: Optional[str] = None
    ) -> bool:
        """Return True if the request may proceed.

        When a PIN is configured and the session is not authenticated:
        - If redirect_path is given, redirect to /auth?next=<redirect_path> (form pages).
        - Otherwise send a 401 JSON response (API endpoints).
        Returns False after sending a response; callers must return immediately.
        """
        if self.get_pin_if_enabled() is None:
            return True
        if self.is_authenticated(handler.headers):
            return True
        if redirect_path:
            self.redirect_to_auth(handler, next_path=redirect_path)
        else:
            self._send_json(handler, 401, {"ok": False, "error": "Authentication required"})
        return False

    # ------------------------
    # CSRF & UI Sessions
    # ------------------------

    def ensure_session(self, handler) -> str:
        """Ensure a session exists. Returns the CSRF token."""
        cookie = parse_cookie_header(handler.headers.get("Cookie"))
        token = cookie.get(SESSION_COOKIE_NAME)

        # Generate new credentials before the lock — avoid holding it during crypto.
        new_token = _b64url(secrets.token_bytes(32))
        new_csrf = _b64url(secrets.token_bytes(32))
        new_sess: Optional[Session] = None

        with self._lock:
            sess: Optional[Session] = None
            if token:
                sess = self._sessions.get(token)
                if sess and sess.expires_at <= _now():
                    self._sessions.pop(token, None)
                    sess = None

            if not sess:
                sess = Session(
                    token=new_token,
                    expires_at=_now() + SESSION_TTL_SECONDS,
                    csrf_token=new_csrf,
                    authenticated=False,
                )
                self._sessions[new_token] = sess
                new_sess = sess

        if new_sess is not None:
            self._set_session_cookie(handler, new_sess)

        return sess.csrf_token  # type: ignore[union-attr]

    def validate_csrf(self, handler, token_from_body: Optional[str] = None) -> bool:
        """Validate CSRF token from header (X-CSRF-Token) or body."""
        cookie = parse_cookie_header(handler.headers.get("Cookie"))
        token = cookie.get(SESSION_COOKIE_NAME)
        if not token:
            return False

        with self._lock:
            sess = self._sessions.get(token)
            if not sess or sess.expires_at <= _now():
                return False
            expected = sess.csrf_token

        # Constant-time comparison outside the lock
        got = handler.headers.get("X-CSRF-Token")
        if not got and token_from_body:
            got = token_from_body
        return bool(got and constant_time_eq(got, expected))

    def get_csrf_token(self, headers) -> str | None:
        """Return CSRF token for current session, if any."""
        cookie = parse_cookie_header(headers.get("Cookie"))
        token = cookie.get(SESSION_COOKIE_NAME)
        if not token:
            return None
        with self._lock:
            sess = self._sessions.get(token)
            if not sess or sess.expires_at <= _now():
                return None
            return sess.csrf_token

    # ------------------------
    # Rate limiting
    # ------------------------

    def _rate_limit_check(self, handler) -> tuple[bool, int]:
        """Returns (blocked, retry_after_seconds)."""
        key = self._client_key(handler)
        with self._lock:
            fails, blocked_until = self._attempts.get(key, (0, 0.0))
        now = time.time()
        if blocked_until and blocked_until > now:
            return True, int(blocked_until - now) + 1
        return False, 0

    def _rate_limit_fail(self, handler) -> None:
        key = self._client_key(handler)
        now = time.time()
        with self._lock:
            fails, blocked_until = self._attempts.get(key, (0, 0.0))
            fails += 1
            if fails >= MAX_FAILED_ATTEMPTS:
                exp = min(fails - MAX_FAILED_ATTEMPTS, 6)
                delay = min(BACKOFF_BASE_SECONDS * (2 ** exp), BACKOFF_MAX_SECONDS)
                blocked_until = now + delay
            self._attempts[key] = (fails, blocked_until)

    def _rate_limit_success(self, handler) -> None:
        key = self._client_key(handler)
        with self._lock:
            self._attempts.pop(key, None)

    # ------------------------
    # Nonce + verify
    # ------------------------

    def _client_key(self, handler) -> str:
        # Best-effort partitioning for rate-limiting and nonce association.
        # Prefer proxy-provided client IP if present (e.g. nginx).
        xff = handler.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        ip = (handler.headers.get("X-Real-IP", "") or "").strip()
        if ip:
            return ip
        return getattr(handler, "client_address", ("", 0))[0] or ""

    def issue_nonce(self, handler) -> str:
        key = self._client_key(handler)
        # Generate token before the lock to avoid holding it during crypto.
        value = _b64url(secrets.token_bytes(18))
        now = _now()
        new_nonce = Nonce(value=value, expires_at=now + NONCE_TTL_SECONDS)
        with self._lock:
            bucket = self._nonces.setdefault(key, {})
            # Prune expired entries first
            for v in list(bucket):
                if bucket[v].expires_at <= now:
                    del bucket[v]
            # Cap at MAX_NONCES_PER_CLIENT: remove the oldest when full
            while len(bucket) >= MAX_NONCES_PER_CLIENT:
                oldest = min(bucket, key=lambda v: bucket[v].expires_at)
                del bucket[oldest]
            bucket[value] = new_nonce
        return value

    def _consume_nonce(self, handler, nonce_value: str) -> bool:
        key = self._client_key(handler)
        now = _now()
        with self._lock:
            bucket = self._nonces.get(key)
            if not bucket:
                return False
            n = bucket.get(nonce_value)
            if not n:
                return False
            del bucket[nonce_value]
            if not bucket:
                del self._nonces[key]
            expired = n.expires_at <= now
        return not expired

    def _compute_proof(self, nonce: str, pin: str) -> str:
        # Proof = SHA256(nonce + pin) in hex
        digest = hashlib.sha256((nonce + pin).encode("utf-8")).hexdigest()
        return digest

    def _uptime_seconds(self) -> Optional[float]:
        """Return system uptime in seconds, or None if unavailable (non-Linux)."""
        try:
            with open("/proc/uptime", "r", encoding="ascii") as f:
                return float(f.read().split()[0])
        except Exception:
            return None

    # ------------------------
    # Session cookie
    # ------------------------

    def _new_session(self) -> Session:
        token = _b64url(secrets.token_bytes(32))
        csrf = _b64url(secrets.token_bytes(32))
        return Session(token=token, expires_at=_now() + SESSION_TTL_SECONDS, csrf_token=csrf)

    def _set_session_cookie(self, handler, session: Session) -> None:
        # We set a pending attribute to be flushed in ConfigWebHandler.end_headers
        # to ensure proper HTTP protocol order (status line first).
        # Lax, not Strict: cross-site top-level navigations must carry the
        # session (the alignment measurement page hands results back via a
        # plain GET from another origin; Strict would force a fresh login on
        # every handoff). Cross-site POSTs still get no cookie under Lax,
        # and every state-changing endpoint requires the CSRF token anyway.
        cookie = (
            f"{SESSION_COOKIE_NAME}={session.token}; "
            f"Max-Age={SESSION_TTL_SECONDS}; Path=/; HttpOnly; SameSite=Lax"
        )
        handler._pending_auth_cookie = cookie

    # ------------------------
    # Rendering / handlers
    # ------------------------

    def redirect_to_auth(self, handler, next_path: str) -> None:
        nxt = urllib.parse.quote(safe_next_path(next_path), safe="/")
        handler.send_response(302)
        handler.send_header("Location", f"/auth?next={nxt}")
        handler.send_header("Content-Length", "0")
        handler.end_headers()

    def handle_auth_verify(self, handler, body_bytes: bytes) -> None:
        """POST /api/auth/verify

        Expected JSON:
          {"nonce":"...","proof":"...","next":"/setup"}
        """
        if self.get_pin_if_enabled() is None:
            payload = {
                "ok": False,
                "error": "PIN not enabled",
                "error_code": "pin_unconfigured",
                "pin_status": self._pin_status,
            }
            # manual send so we can attach the header:
            data = json.dumps(payload).encode("utf-8")
            handler.send_response(403)
            handler.send_header(PIN_REJECT_HEADER, "pin_unconfigured")
            handler.send_header("Content-Type", "application/json; charset=utf-8")
            handler.send_header("Content-Length", str(len(data)))
            handler.end_headers()
            handler.wfile.write(data)
            return

        try:
            data = json.loads(body_bytes.decode("utf-8", errors="strict"))
        except Exception:
            self._send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
            return

        nonce = str(data.get("nonce") or "")
        proof = str(data.get("proof") or "")
        next_path = safe_next_path(str(data.get("next") or "/"))

        if not nonce or not proof:
            self._send_json(handler, 400, {"ok": False, "error": "Missing fields"})
            return

        blocked, retry_after = self._rate_limit_check(handler)
        if blocked:
            self._send_json(handler, 429, {"ok": False, "error": "rate_limited", "retry_after": retry_after})
            return

        if not self._consume_nonce(handler, nonce):
            self._send_json(handler, 400, {"ok": False, "error": "Invalid/expired nonce"})
            return

        pin = self.get_pin_if_enabled()
        if pin is None:
            self._send_json(handler, 500, {"ok": False, "error": "Internal error"})
            return

        accepted = constant_time_eq(proof, self._compute_proof(nonce, pin))

        # If a user-configured PIN is in use, also accept the factory boot-partition
        # PIN for the first 30 minutes of uptime (recovery / forgotten-PIN window).
        # Outside that window the user PIN is required exclusively.
        if not accepted and self._pin_source == "config":
            uptime = self._uptime_seconds()
            if uptime is not None and uptime < 30 * 60:
                boot_pin = self.get_boot_pin_value()
                if boot_pin:
                    accepted = constant_time_eq(proof, self._compute_proof(nonce, boot_pin))
                    if accepted:
                        LOG.info(
                            "Auth accepted via factory PIN during early-uptime window "
                            "(uptime=%.0fs < 1800s)",
                            uptime,
                        )

        if not accepted:
            self._rate_limit_fail(handler)
            self._send_json(handler, 401, {"ok": False, "error": "Incorrect PIN"})
            return

        self._rate_limit_success(handler)
        session = self._new_session()
        with self._lock:
            self._sessions[session.token] = session

        handler.send_response(200)
        self._set_session_cookie(handler, session)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        payload = json.dumps({"ok": True, "next": next_path}).encode("utf-8")
        handler.send_header("Content-Length", str(len(payload)))
        handler.end_headers()
        handler.wfile.write(payload)

    def handle_pin_change(self, handler, body_bytes: bytes) -> None:
        """POST /api/pin/change

        Expected JSON:
          {"new_pin": "...", "new_pin_check": "..."}

        If a PIN already exists, this requires an authenticated session plus a
        valid CSRF token (enforced by the router before this method is called).
        If no PIN exists yet, this endpoint also serves as the initial PIN
        creation flow from the setup page, using the CSRF-protected UI session.

        The new PIN is sent in plaintext, which is acceptable given the
        existing HTTP-only threat model: a passive on-LAN attacker can already
        sniff session cookies.
        """
        current_pin = self.get_pin_if_enabled()

        # When changing an existing PIN, require a fully authenticated session.
        # CSRF alone is not sufficient because unauthenticated sessions also
        # carry a CSRF token.
        if current_pin is not None and not self.is_authenticated(handler.headers):
            self._send_json(handler, 401, {"ok": False, "error": "Authentication required"})
            return

        try:
            data = json.loads(body_bytes.decode("utf-8", errors="strict"))
        except Exception:
            self._send_json(handler, 400, {"ok": False, "error": "Invalid JSON"})
            return

        new_pin = str(data.get("new_pin") or "").strip()
        new_pin_check = str(data.get("new_pin_check") or "").strip()

        if not new_pin or not new_pin_check:
            self._send_json(handler, 400, {"ok": False, "error": "Missing fields"})
            return

        if not constant_time_eq(new_pin, new_pin_check):
            self._send_json(handler, 400, {"ok": False, "error": "Values did not match"})
            return

        status, payload = self.set_pin(new_pin)
        if status != 200:
            self._send_json(handler, status, payload)
            return

        # The old authenticated session set was revoked by set_pin(). Mint a
        # fresh authenticated session for this client so the UI can stay on the
        # current page without bouncing through /auth, which in turn helps
        # avoid iOS credential-save heuristics. This also upgrades the current
        # setup-page flow from "no PIN" to "PIN enabled" seamlessly.
        session = self._new_session()
        with self._lock:
            self._sessions[session.token] = session

        handler.send_response(200)
        self._set_session_cookie(handler, session)
        response_payload = dict(payload)
        response_payload["reauthenticated"] = True
        payload_bytes = json.dumps(response_payload).encode("utf-8")
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(payload_bytes)))
        handler.end_headers()
        handler.wfile.write(payload_bytes)

    # ------------------------
    # Internal utilities
    # ------------------------

    def _gc(self) -> None:
        now = _now()
        with self._lock:
            # Sessions
            for k in list(self._sessions):
                if self._sessions[k].expires_at <= now:
                    del self._sessions[k]
            # Nonces (nested buckets)
            for ck in list(self._nonces):
                bucket = self._nonces[ck]
                for v in list(bucket):
                    if bucket[v].expires_at <= now:
                        del bucket[v]
                if not bucket:
                    del self._nonces[ck]

    def _send_json(self, handler, status: int, obj: dict) -> None:
        payload = json.dumps(obj).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(payload)))
        handler.end_headers()
        handler.wfile.write(payload)
