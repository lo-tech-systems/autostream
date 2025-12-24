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
import time
import urllib.parse
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import logging
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
NONCE_COOKIE_NAME = "autostream_nonce"  # short-lived helper; not strictly required

# Lifetimes
SESSION_TTL_SECONDS = 24 * 60 * 60
NONCE_TTL_SECONDS = 60

# Brute-force throttling (best-effort; in-memory)
MAX_FAILED_ATTEMPTS = 5
BACKOFF_BASE_SECONDS = 5
BACKOFF_MAX_SECONDS = 5 * 60

# Routes
ALLOWLIST_PATHS = {"/", "/about", "/auth", "/api/status", "/api/auth/verify"}


# ----------------------------
# Helpers
# ----------------------------


def _now() -> int:
    return int(time.time())


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _safe_next_path(raw_next: str) -> str:
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


@dataclass
class Nonce:
    value: str
    expires_at: int


class AuthManager:
    """Holds auth state (sessions/nonces) and provides handler helpers."""

    def __init__(
        self,
        style_css: str = "",
        banner_html: str = "",
        title: str = "Autostream",
    ) -> None:
        self.style_css = style_css
        self.banner_html = banner_html
        self.title = title

        # In-memory state
        self._sessions: Dict[str, Session] = {}
        self._nonces: Dict[str, Nonce] = {}
        self._attempts: Dict[str, tuple[int, float]] = {}  # client_key -> (fails, blocked_until_epoch)

        # PIN cache
        self._pin_value: Optional[str] = None
        self._pin_mtime: Optional[float] = None
        self._pin_path: Optional[str] = None

        self._pin_status: str = PIN_STATUS_MISSING

    # ------------------------
    # PIN
    # ------------------------

    def get_pin_status(self) -> str:
        return self._pin_status

    def _read_pin_file(self) -> Tuple[Optional[str], Optional[str], Optional[float], str]:
        """Return (pin, path, mtime, status). Pin is first non-empty line stripped."""
        saw_any_candidate = False

        for path in PIN_PATH_CANDIDATES:
            try:
                st = os.stat(path)
            except FileNotFoundError:
                continue
            except OSError:
                # Exists maybe, but can't stat reliably
                return None, path, None, PIN_STATUS_UNREADABLE

            saw_any_candidate = True
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


    def get_pin_if_enabled(self) -> Optional[str]:
        """Return the configured PIN, or None if missing/invalid/unreadable."""
        pin, path, mtime, status = self._read_pin_file()

        LOG.debug(
            "PIN read result: pin=%r path=%r mtime=%r status=%s",
            pin,
            path,
            mtime,
            status,
        )

        # Cache hit (only meaningful when we previously had a valid pin)
        if (
            path
            and mtime
            and self._pin_path == path
            and self._pin_mtime == mtime
            and self._pin_value is not None
        ):
            self._pin_status = PIN_STATUS_OK
            LOG.debug(
                "PIN cache hit: using cached PIN from %s (mtime=%s)",
                path,
                mtime,
            )
            return self._pin_value

        # Valid PIN
        if pin and PIN_REGEX.match(pin):
            self._pin_value = pin
            self._pin_path = path
            self._pin_mtime = mtime
            self._pin_status = PIN_STATUS_OK
            LOG.info(
                "Valid PIN loaded from %s (mtime=%s)",
                path,
                mtime,
            )
            return pin

        # Unconfigured PIN (lockdown)
        self._pin_value = None
        self._pin_path = path
        self._pin_mtime = mtime

        # Distinguish invalid vs missing vs unreadable
        if status == PIN_STATUS_OK:
            # status OK here means we read a non-empty line but regex failed
            self._pin_status = PIN_STATUS_INVALID
            LOG.warning(
                "PIN file read OK but PIN is invalid (regex mismatch): %r from %s",
                pin,
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


    def is_enabled(self) -> bool:
        return self.get_pin_if_enabled() is not None


    # ------------------------
    # Auth decisions
    # ------------------------

    def _reject_unconfigured(self, handler) -> None:
        handler.send_response(403)
        handler.send_header(PIN_REJECT_HEADER, "pin_unconfigured")
        handler.send_header("Content-Type", "text/plain; charset=utf-8")
        body = f"Authentication PIN is not configured ({self._pin_status}).\n".encode("utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)


    def requires_auth(self, path: str) -> bool:
        # If PIN is not configured, reject/lockdown applies to everything.
        if self.get_pin_if_enabled() is None:
            return True
        if path in ALLOWLIST_PATHS:
            return False
        return True

    def is_authenticated(self, headers) -> bool:
        # cleanup opportunistically
        self._gc()

        cookie = parse_cookie_header(headers.get("Cookie"))
        token = cookie.get(SESSION_COOKIE_NAME)
        if not token:
            return False
        sess = self._sessions.get(token)
        if not sess:
            return False
        if sess.expires_at <= _now():
            self._sessions.pop(token, None)
            return False
        
        # If a PIN is required, we only count as authenticated if the session
        # was created via a successful PIN verification. 
        # For now, all sessions in self._sessions are 'authenticated' because 
        # they are only created in handle_auth_verify.
        # But we want to support 'unauthenticated' sessions for CSRF when PIN is off.
        return getattr(sess, 'authenticated', True)

    # ------------------------
    # CSRF & UI Sessions
    # ------------------------

    def ensure_session(self, handler) -> str:
        """Ensure a session exists. Returns the CSRF token."""
        cookie = parse_cookie_header(handler.headers.get("Cookie"))
        token = cookie.get(SESSION_COOKIE_NAME)
        
        sess = None
        if token:
            sess = self._sessions.get(token)
            if sess and sess.expires_at <= _now():
                self._sessions.pop(token, None)
                sess = None

        if not sess:
            # Create a new 'unauthenticated' session (still provides CSRF)
            token = _b64url(secrets.token_bytes(32))
            csrf = _b64url(secrets.token_bytes(32))
            sess = Session(token=token, expires_at=_now() + SESSION_TTL_SECONDS, csrf_token=csrf)
            # Tag it so is_authenticated knows it's just a UI session
            setattr(sess, 'authenticated', False) 
            self._sessions[token] = sess
            self._set_session_cookie(handler, sess)

        return sess.csrf_token

    def validate_csrf(self, handler, token_from_body: Optional[str] = None) -> bool:
        """Validate CSRF token from header (X-CSRF-Token) or body."""
        cookie = parse_cookie_header(handler.headers.get("Cookie"))
        token = cookie.get(SESSION_COOKIE_NAME)
        if not token:
            return False
        
        sess = self._sessions.get(token)
        if not sess or sess.expires_at <= _now():
            return False
        
        expected = sess.csrf_token
        # Check header first
        got = handler.headers.get("X-CSRF-Token")
        if not got and token_from_body:
            got = token_from_body
            
        if got and constant_time_eq(got, expected):
            return True
        return False

    def get_csrf_token(self, headers) -> str | None:
        """Return CSRF token for current session, if any."""
        cookie = parse_cookie_header(headers.get("Cookie"))
        token = cookie.get(SESSION_COOKIE_NAME)
        if not token:
            return None
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
        fails, blocked_until = self._attempts.get(key, (0, 0.0))
        now = time.time()
        if blocked_until and blocked_until > now:
            return True, int(blocked_until - now) + 1
        return False, 0

    def _rate_limit_fail(self, handler) -> None:
        key = self._client_key(handler)
        fails, blocked_until = self._attempts.get(key, (0, 0.0))
        fails += 1
        # After MAX_FAILED_ATTEMPTS, apply exponential backoff.
        if fails >= MAX_FAILED_ATTEMPTS:
            exp = min(fails - MAX_FAILED_ATTEMPTS, 6)
            delay = min(BACKOFF_BASE_SECONDS * (2 ** exp), BACKOFF_MAX_SECONDS)
            blocked_until = time.time() + delay
        self._attempts[key] = (fails, blocked_until)

    def _rate_limit_success(self, handler) -> None:
        key = self._client_key(handler)
        self._attempts.pop(key, None)

    # ------------------------
    # Nonce + verify
    # ------------------------

    def _client_key(self, handler) -> str:
        # Best-effort partitioning; avoids global nonce reuse.
        # Prefer proxy-provided client IP if present (e.g. nginx).
        xff = handler.headers.get("X-Forwarded-For", "")
        if xff:
            ip = xff.split(",")[0].strip()
        else:
            ip = (handler.headers.get("X-Real-IP", "") or "").strip()
        if not ip:
            ip = getattr(handler, "client_address", ("", 0))[0] or ""
        ua = handler.headers.get("User-Agent", "")
        return hashlib.sha256(f"{ip}|{ua}".encode("utf-8")).hexdigest()

    def _issue_nonce(self, handler) -> str:
        key = self._client_key(handler)
        value = _b64url(secrets.token_bytes(18))
        self._nonces[key] = Nonce(value=value, expires_at=_now() + NONCE_TTL_SECONDS)
        return value

    def _get_nonce(self, handler) -> Optional[str]:
        key = self._client_key(handler)
        n = self._nonces.get(key)
        if not n:
            return None
        if n.expires_at <= _now():
            self._nonces.pop(key, None)
            return None
        return n.value

    def _consume_nonce(self, handler, expected: str) -> bool:
        key = self._client_key(handler)
        n = self._nonces.get(key)
        if not n:
            return False
        if n.expires_at <= _now():
            self._nonces.pop(key, None)
            return False
        ok = constant_time_eq(n.value, expected)
        # Consume regardless to prevent replay
        self._nonces.pop(key, None)
        return ok

    def _compute_proof(self, nonce: str, pin: str) -> str:
        # Proof = SHA256(nonce + pin) in hex
        digest = hashlib.sha256((nonce + pin).encode("utf-8")).hexdigest()
        return digest

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
        cookie = (
            f"{SESSION_COOKIE_NAME}={session.token}; "
            f"Max-Age={SESSION_TTL_SECONDS}; Path=/; HttpOnly; SameSite=Strict"
        )
        if (handler.headers.get("X-Forwarded-Proto", "").lower() == "https"):
            cookie += "; Secure"
        handler._pending_auth_cookie = cookie

    # ------------------------
    # Rendering / handlers
    # ------------------------

    def redirect_to_auth(self, handler, next_path: str) -> None:
        if self.get_pin_if_enabled() is None:
            self._reject_unconfigured(handler)
            return
        nxt = urllib.parse.quote(_safe_next_path(next_path), safe="/")
        handler.send_response(302)
        handler.send_header("Location", f"/auth?next={nxt}")
        handler.send_header("Content-Length", "0")
        handler.end_headers()

    def handle_auth_get(self, handler, query: str) -> None:
        if self.get_pin_if_enabled() is None:
            self._reject_unconfigured(handler)
            return

        qs = urllib.parse.parse_qs(query or "", keep_blank_values=True)
        next_path = _safe_next_path((qs.get("next") or ["/"])[0])
        err = (qs.get("err") or [""])[0]

        nonce = self._issue_nonce(handler)

        html = self._render_auth_page(next_path=next_path, nonce=nonce, error=bool(err))
        body = html.encode("utf-8")

        handler.send_response(200)
        handler.send_header("Content-Type", "text/html; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    def handle_auth_verify(self, handler, body_bytes: bytes) -> None:
        """POST /api/auth/verify

        Expected JSON:
          {"nonce":"...","proof":"...","next":"/setup"}
        """
        if self.get_pin_if_enabled() is None:
            payload = {
                "ok": False,
                "error": "PIN not enabled",          # keep existing string
                "error_code": "pin_unconfigured",    # new, optional
                "pin_status": self._pin_status,      # new, optional
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
        next_path = _safe_next_path(str(data.get("next") or "/"))

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
        assert pin is not None
        expected = self._compute_proof(nonce, pin)

        if not constant_time_eq(proof, expected):
            self._rate_limit_fail(handler)
            # Do not set cookie; frontend will show error
            # JP Note - this should probably be return 403
            self._send_json(handler, 401, {"ok": False, "error": "Incorrect PIN"})
            return

        self._rate_limit_success(handler)
        session = self._new_session()
        self._sessions[session.token] = session

        handler.send_response(200)
        self._set_session_cookie(handler, session)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        payload = json.dumps({"ok": True, "next": next_path}).encode("utf-8")
        handler.send_header("Content-Length", str(len(payload)))
        handler.end_headers()
        handler.wfile.write(payload)

    # ------------------------
    # Internal utilities
    # ------------------------

    def _gc(self) -> None:
        now = _now()
        # Sessions
        for k, s in list(self._sessions.items()):
            if s.expires_at <= now:
                self._sessions.pop(k, None)
        # Nonces
        for k, n in list(self._nonces.items()):
            if n.expires_at <= now:
                self._nonces.pop(k, None)

    def _send_json(self, handler, status: int, obj: dict) -> None:
        payload = json.dumps(obj).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(payload)))
        handler.end_headers()
        handler.wfile.write(payload)

    def _render_auth_page(self, next_path: str, nonce: str, error: bool) -> str:
        # Reuse existing banner styles if provided.
        # If error: show a red fixed banner with "Incorrect PIN".
        err_banner = ""
        if error:
            err_banner = (
                "<div id='license-banner'>Incorrect PIN</div>"
                "<div id='license-banner-spacer'></div>"
            )

        # Minimal page that matches the existing Autostream look by using injected CSS.
        # Uses WebCrypto SHA-256 to compute proof without sending the PIN in plaintext.
        return f"""
            <!doctype html>
            <html lang=\"en\">
            <head>
            <meta charset=\"utf-8\" />
            <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
            <title>{self.title} • Authentication</title>
            <style>
            {self.style_css}
            </style>
            </head>
            <body>
            <div class=\"container\">
                {err_banner}
                {self.banner_html}
                <h1>Setup</h1>
                <a href="/"
                    style="display:inline-block;padding:0.6rem 1.2rem;font-size:1rem;font-weight:600;
                            background:#6c757d;color:#fff;text-decoration:none;border-radius:999px;
                            box-shadow:0 2px 6px rgba(0,0,0,0.05);">
                    ← Back
                </a>
                <p>Enter the device PIN. This may be on a label attached to the device.</p>

                <div class=\"card\">
                <form id=\"auth-form\" autocomplete=\"off\">
                    <label for=\"pin\">PIN</label>
                    <input id=\"pin\" name=\"pin\" type=\"password\" inputmode=\"text\" autocapitalize=\"off\" autocomplete=\"off\" spellcheck=\"false\" required />
                    <div style=\"height: 10px\"></div>
                    <button class=\"btn\" type=\"submit\">Continue</button>
                    <input type=\"hidden\" id=\"next\" value=\"{urllib.parse.quote(next_path, safe='/')}\" />
                    <input type=\"hidden\" id=\"nonce\" value=\"{nonce}\" />
                </form>
                </div>
            </div>

            <script>
            // SHA-256 helper.
            // Prefer WebCrypto when available, but fall back to a small JS implementation
            // because many browsers (notably iOS Safari / standalone mode) do not expose
            // crypto.subtle on plain HTTP origins.
            function _rotr(x, n) {{ return (x >>> n) | (x << (32 - n)); }}
            function _toHex32(x) {{ return (x >>> 0).toString(16).padStart(8, '0'); }}

            function sha256HexFallback(msg) {{
            // Minimal SHA-256 implementation (Uint8Array in, hex out).
            const K = new Uint32Array([
                0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
                0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
                0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
                0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
                0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
                0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
                0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
                0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
            ]);

            // Encode as UTF-8 bytes
            const bytes = new TextEncoder().encode(msg);
            const bitLenHi = Math.floor((bytes.length * 8) / 0x100000000);
            const bitLenLo = (bytes.length * 8) >>> 0;

            // Padding: 0x80, then zeros, then 64-bit length
            const withOne = bytes.length + 1;
            const padLen = (withOne % 64 <= 56) ? (56 - (withOne % 64)) : (56 + (64 - (withOne % 64)));
            const totalLen = bytes.length + 1 + padLen + 8;
            const buf = new Uint8Array(totalLen);
            buf.set(bytes, 0);
            buf[bytes.length] = 0x80;
            // length (big-endian)
            const dv = new DataView(buf.buffer);
            dv.setUint32(totalLen - 8, bitLenHi);
            dv.setUint32(totalLen - 4, bitLenLo);

            // Initial hash values
            let h0=0x6a09e667, h1=0xbb67ae85, h2=0x3c6ef372, h3=0xa54ff53a;
            let h4=0x510e527f, h5=0x9b05688c, h6=0x1f83d9ab, h7=0x5be0cd19;

            const W = new Uint32Array(64);
            for (let i = 0; i < buf.length; i += 64) {{
                for (let t = 0; t < 16; t++) {{
                W[t] = dv.getUint32(i + t*4);
                }}
                for (let t = 16; t < 64; t++) {{
                const s0 = (_rotr(W[t-15],7) ^ _rotr(W[t-15],18) ^ (W[t-15] >>> 3)) >>> 0;
                const s1 = (_rotr(W[t-2],17) ^ _rotr(W[t-2],19) ^ (W[t-2] >>> 10)) >>> 0;
                W[t] = (W[t-16] + s0 + W[t-7] + s1) >>> 0;
                }}

                let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
                for (let t = 0; t < 64; t++) {{
                const S1 = (_rotr(e,6) ^ _rotr(e,11) ^ _rotr(e,25)) >>> 0;
                const ch = ((e & f) ^ (~e & g)) >>> 0;
                const temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
                const S0 = (_rotr(a,2) ^ _rotr(a,13) ^ _rotr(a,22)) >>> 0;
                const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
                const temp2 = (S0 + maj) >>> 0;
                h=g; g=f; f=e; e=(d + temp1) >>> 0;
                d=c; c=b; b=a; a=(temp1 + temp2) >>> 0;
                }}

                h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
                h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
            }}

            return _toHex32(h0)+_toHex32(h1)+_toHex32(h2)+_toHex32(h3)+_toHex32(h4)+_toHex32(h5)+_toHex32(h6)+_toHex32(h7);
            }}

            async function sha256Hex(s) {{
            // WebCrypto path (fast) when available
            if (window.crypto && crypto.subtle && window.isSecureContext) {{
                const enc = new TextEncoder();
                const buf = await crypto.subtle.digest('SHA-256', enc.encode(s));
                const arr = Array.from(new Uint8Array(buf));
                return arr.map(b => b.toString(16).padStart(2,'0')).join('');
            }}
            // Fallback path (works on HTTP)
            return sha256HexFallback(s);
            }}

            document.getElementById('auth-form').addEventListener('submit', async (e) => {{
            e.preventDefault();

            const pin = (document.getElementById('pin').value || '').trim();
            const nextPath = decodeURIComponent(document.getElementById('next').value || '%2F');
            const nonce = document.getElementById('nonce').value || '';

            // Client-side input validation to match server rules.
            const re = /^[A-Za-z0-9-]{{4,20}}$/;
            if (!re.test(pin)) {{
                // Mirror server error banner style by reloading with err=1.
                window.location.href = '/auth?next=' + encodeURIComponent(nextPath) + '&err=1';
                return;
            }}

            const proof = await sha256Hex(nonce + pin);

            const res = await fetch('/api/auth/verify', {{
                method: 'POST',
                credentials: 'same-origin',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{nonce: nonce, proof: proof, next: nextPath}})
            }});

            if (res.ok) {{
                const j = await res.json();
                window.location.href = (j && j.next) ? j.next : nextPath;
                return;
            }}

            // Incorrect PIN (or any auth failure): reload with error banner.
            window.location.href = '/auth?next=' + encodeURIComponent(nextPath) + '&err=1';
            }});
            </script>
            </body>
            </html>
        """

