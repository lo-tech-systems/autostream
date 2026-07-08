#!/usr/bin/python3
"""wifi_web.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Flask HTTP surface for the Autostream Wi-Fi watcher.
This module owns:

  * presentation — the setup/captive-portal page rendering (render_setup_page,
    render_wait_page) plus APP_TITLE/APP_BANNER_IMAGE/BANNER_HTML/STYLE_CSS;
  * the Flask app factory ``build_app(ctx)`` and all routes — the captive-portal/
    setup surface and the privileged loopback control surface;
  * the loopback control/auth surface — the per-boot control token lifecycle
    (init_control_token/remove_control_token), loopback+token authorisation
    (_control_authorised, hmac.compare_digest), and request-shape validation.

Routes only *validate, authenticate, and queue/trigger* via a :class:`WebContext`;
all policy/orchestration (apply/scan, AP/setup transitions, the monitor loop's
action consumption) stays in wifi_watcher.

Runtime note:
Like its sibling recovery modules (wifi_status.py, wifi_recovery.py) this runs
on the system Python, not the app venv.  It imports only the standard library
and ``flask``; it never imports an Autostream application module.  Functions
that need watcher state receive a :class:`WebContext` as their first argument
and read its constants/helpers through it — a narrow view of the watcher
exposing only the state objects (STATE plus the apply/control fragments),
state_lock, the logger, and the constants/callables the routes use.
"""
from __future__ import annotations

import hmac
import html
import json
import logging
import os
import secrets
import tempfile
from dataclasses import dataclass
from typing import Callable, Optional

from flask import Flask, request, jsonify, redirect, url_for, make_response


@dataclass
class WebContext:
    """Narrow view of the watcher that the Flask HTTP surface depends on.

    Constructed once by the watcher and passed to ``build_app()``,
    ``init_control_token()``, and the route helpers; nothing else of the
    watcher is reachable from this module.
    """

    app_name: str
    STATE: object
    APPLY_STATE: object
    CONTROL_STATE: object
    state_lock: object
    logger: logging.Logger
    control_action_event: object
    RUNTIME_LOG_LEVELS: dict
    LOG_LEVEL_TTL_MIN: int
    LOG_LEVEL_TTL_MAX: int
    WIFI_WATCHER_VERSION: str
    _DIAL_MODE: bool
    wifi_net: object
    get_system_hostname: Callable
    get_configured_network_state: Callable
    submit_apply_credentials: Callable
    scan_all_networks: Callable


# Per-boot control token.  Generated at startup; the normal Web
# UI reads the token file and supplies it as an X-Autostream-Wifi-Control header
# on direct-localhost requests.  Never sent to the browser or logged.  This is
# the single source of truth for the loopback control surface (the watcher calls
# init_control_token(ctx)/remove_control_token() at startup/shutdown).
CONTROL_TOKEN_DIR = os.environ.get('APP_RUN_DIR', '/run/autostream')
CONTROL_TOKEN_PATH = os.environ.get(
    'APP_WIFI_CONTROL_TOKEN', '/run/autostream/wifi-control.token'
)
CONTROL_TOKEN_HEADER = "X-Autostream-Wifi-Control"
_control_token: str = ""

APP_TITLE = os.environ.get('APP_TITLE', 'autostream')
APP_BANNER_IMAGE = os.environ.get('APP_BANNER_IMAGE', '').strip()

if APP_BANNER_IMAGE:
    BANNER_HTML = (
        f'<img src="{html.escape(APP_BANNER_IMAGE, quote=True)}" '
        f'alt="{html.escape(APP_TITLE, quote=True)}" class="app-banner-image">'
    )
else:
    BANNER_HTML = f'<div class="app-title">{html.escape(APP_TITLE)}</div>'

STYLE_CSS = """
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; padding: 0; background: #f5f5f5; color: #333; }
.container { max-width: 420px; margin: 2rem auto; padding: 1rem 1.5rem; background: #fff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,.1); }
.app-title { font-size: 1.2rem; font-weight: 700; color: #555; margin: 0 0 1rem 0; padding-bottom: 0.5rem; border-bottom: 1px solid #e0e0e0; }
.app-banner-image { max-height: 48px; width: auto; display: block; margin: 0 0 0.75rem 0; }
h1 { font-size: 1.4rem; margin: 0.5rem 0 1rem 0; }
label { display: block; margin-top: 0.75rem; font-size: 0.85rem; font-weight: 600; color: #555; }
input, select { display: block; width: 100%; padding: 0.55rem 0.75rem; margin-top: 0.25rem; border: 1px solid #ccc; border-radius: 8px; font-size: 1rem; background: #fff; color: #333; }
input:focus, select:focus { outline: 2px solid #0070f3; border-color: transparent; }
.pill-btn { display: inline-block; padding: 0.55rem 1.25rem; background: #0070f3; color: #fff; border: none; border-radius: 8px; font-size: 1rem; cursor: pointer; }
.pill-btn.small { padding: 0.4rem 0.75rem; font-size: 0.85rem; background: #6c757d; }
.pill-btn:disabled { opacity: 0.55; cursor: default; }
.alert { margin: 0.75rem 0; padding: 0.75rem 1rem; background: #fff0f0; border: 1px solid #f5c6cb; border-radius: 8px; color: #721c24; font-size: 0.9rem; }
.hint { font-size: 0.8rem; color: #777; margin-top: 0.25rem; }
.status { font-size: 0.8rem; text-align: center; color: #666; margin-top: 0.5rem; }
.row { display: flex; align-items: stretch; gap: 0.5rem; }
.row .grow { flex: 1 1 auto; min-width: 0; }
.row input, .row button { margin-top: 0.25rem; }
.masked { -webkit-text-security: disc; text-security: disc; }
"""


def render_setup_page(error_code: str = "", show_reconnect: bool = False) -> str:
    """Return the HTML for the WiFi setup page (styled like autostream_webui.py),
    while trying hard to avoid iOS credential-save prompts.
    Includes iOS-friendly focus handling (avoid auto-focus in key field).

    ``show_reconnect`` adds a "Reconnect to saved network" action; it must be
    False during first-run unconfigured setup (no saved network exists).
    """
    reconnect_html = ""
    if show_reconnect:
        reconnect_html = """
        <hr>
        <div class="hint">Already configured before? You can return to your
        previous network without re-entering its key.</div>
        <button id="reconnect-btn" class="pill-btn small" type="button"
                onclick="reconnectSaved()">Reconnect to saved network</button>
        <div class="status" id="reconnect-status"></div>
        """

    # Map internal error codes to a user-friendly message
    msg = ""
    if error_code:
        if error_code == "no-local-ip":
            msg = (
                "WiFi connected but no usable local IPv4 address was obtained. "
                "Check DHCP is enabled on the network or try another."
            )
        elif error_code == "nmcli-failed":
            msg = "Unable to connect to that WiFi network. Check the key and try again."
        else:
            msg = "WiFi connection attempt failed. Please try again."

    alert_html = ""
    if msg:
        alert_html = f"""
        <div class="alert">
          <strong>Connection failed.</strong><br>
          {html.escape(msg)}
        </div>
        """

    return f"""<!DOCTYPE html>
        <html>
        <head>
        <meta charset="utf-8">
        <title>Network Setup</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
        <style>{STYLE_CSS}</style>
        <style>
          /* Mask text input like a password field without using type=password (iOS prompt heuristic) */
          .masked {{
            -webkit-text-security: disc; /* Safari/iOS */
            text-security: disc;         /* non-standard fallback */
          }}
          /* Put key field + eye button on one line */
          .row {{
            display: flex;
            align-items: stretch;
            gap: 0.5rem;
          }}
          .row .grow {{
            flex: 1 1 auto;
            min-width: 0; /* important: allows the input to shrink instead of overflowing */
          }}
          .row input,
          .row button {{
            margin-top: 0.25rem; /* match the existing input top margin from STYLE_CSS */
          }}
          .status {{
            font-size: 0.8rem;     /* smaller text */
            text-align: center;   /* center horizontally */
            color: #666;          /* optional: softer “status” look */
            margin-top: 0.5rem;   /* optional spacing from controls */
          }}
          #toggle-mask svg {{
            position: relative;
            top: 1px;        /* nudges the eye icon down a bit */
            display: block;  /* removes baseline alignment quirks */
          }}
          /* Rejoin prompt modal */
          .modal-overlay {{
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.55);
            display: none;               /* toggled to flex by JS */
            align-items: center;
            justify-content: center;
            padding: 1rem;
            z-index: 1000;
          }}
          .modal-box {{
            background: #fff;
            color: #222;
            border-radius: 12px;
            padding: 1.25rem;
            max-width: 22rem;
            width: 100%;
            text-align: center;
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.3);
          }}
          .modal-box h2 {{ margin-top: 0; font-size: 1.1rem; }}
          .modal-box button {{ margin-top: 0.5rem; }}
        </style>
        <script>
            let _didInitialFocus = false;

            async function fetchStatus() {{
                try {{
                    const resp = await fetch('/status', {{ cache: 'no-store' }});
                    if (!resp.ok) return;
                    const data = await resp.json();
                    const el = document.getElementById('status');
                    if (el) el.textContent =
                        'WiFi: ' + data.wifistate + ', ' +
                        'Wired: ' + data.wiredstate + ', ' +
                        'Gateway reachable: ' + data.gateway_reachable + ', ' +
                        'SetupMode: ' + data.SetupMode;
                    updateRejoinModal(data);
                }} catch (e) {{}}
            }}

            // Once the user chooses "continue setup", stop showing the modal for
            // this page even if a status poll races the server flag update.
            let _rejoinDismissedLocal = false;

            function updateRejoinModal(data) {{
                const modal = document.getElementById('rejoin-modal');
                if (!modal) return;
                if (data && data.saved_ssid_visible && !_rejoinDismissedLocal) {{
                    const nameEl = document.getElementById('rejoin-ssid');
                    if (nameEl) nameEl.textContent = data.saved_ssid || 'your saved network';
                    modal.style.display = 'flex';
                }} else {{
                    modal.style.display = 'none';
                }}
            }}

            async function rejoinNow() {{
                const modal = document.getElementById('rejoin-modal');
                if (modal) modal.style.display = 'none';
                try {{
                    await fetch('/reconnect_saved', {{ method: 'POST', cache: 'no-store' }});
                }} catch (e) {{}}
            }}

            async function dismissRejoin() {{
                _rejoinDismissedLocal = true;
                const modal = document.getElementById('rejoin-modal');
                if (modal) modal.style.display = 'none';
                try {{
                    await fetch('/dismiss_rejoin', {{ method: 'POST', cache: 'no-store' }});
                }} catch (e) {{}}
            }}

            function focusSsidSelectSoon() {{
                if (_didInitialFocus) return;

                const select = document.getElementById('ssid-select');
                const key = document.getElementById('key-field');
                if (!select) return;

                // If the user has already interacted, don't steal focus.
                const ae = document.activeElement;
                const userIsTyping = (ae && (ae === key || ae === select));

                if (!userIsTyping) {{
                    setTimeout(() => {{
                    try {{ select.focus(); }} catch (e) {{}}
                    }}, 250); // iOS captive portal is happier with a slight delay
                }}

                _didInitialFocus = true;
            }}

            // Latest merged network list + built-in scan state for warning logic.
            let _networks = [];
            let _builtinScanKnown = false;

            function updateUsbOnlyWarning() {{
                const warn = document.getElementById('usb-only-warning');
                const select = document.getElementById('ssid-select');
                if (!warn || !select) return;
                const ssid = select.value;
                let show = false;
                if (ssid && _builtinScanKnown) {{
                    const rec = _networks.find(n => (n.ssid || '') === ssid);
                    // Show only for a KNOWN USB-only network: built-in scan
                    // succeeded, built-in did not see it, USB did.
                    if (rec && rec.builtin_visible === false && rec.usb_visible === true) {{
                        show = true;
                    }}
                }}
                warn.style.display = show ? 'block' : 'none';
            }}

            async function fetchNetworks() {{
                try {{
                    const resp = await fetch('/networks', {{ cache: 'no-store' }});
                    if (!resp.ok) return;
                    const data = await resp.json();
                    // New shape: {{networks:[...], builtin_scan_known:bool}}.
                    const list = Array.isArray(data) ? data : (data.networks || []);
                    _networks = list;
                    _builtinScanKnown = Array.isArray(data) ? false : !!data.builtin_scan_known;

                    const select = document.getElementById('ssid-select');
                    if (!select) return;

                    const current = select.value;
                    select.innerHTML = '';

                    const ph = document.createElement('option');
                    ph.value = '';
                    ph.textContent = 'Select a WiFi network…';
                    select.appendChild(ph);

                    for (const n of list) {{
                        const opt = document.createElement('option');
                        opt.value = n.ssid || '';
                        const sig = (typeof n.signal === 'number') ? (' (' + n.signal + '%)') : '';
                        opt.textContent = (n.ssid || '(hidden)') + sig;
                        select.appendChild(opt);
                    }}

                    if (current) select.value = current;
                    updateUsbOnlyWarning();

                    // After first successful population, guide focus to the SSID dropdown (iOS).
                    focusSsidSelectSoon();
                }} catch (e) {{}}
            }}

            function armKeyField() {{
                const key = document.getElementById('key-field');
                if (!key) return;

                // iOS often auto-focuses the first "fillable" input; readonly prevents that.
                // Allow editing as soon as the user interacts.
                const enable = () => key.removeAttribute('readonly');

                key.addEventListener('pointerdown', enable, {{ once: true }});
                key.addEventListener('focus', enable, {{ once: true }});

                // Also enable when user selects an SSID (common flow)
                const select = document.getElementById('ssid-select');
                if (select) {{
                    select.addEventListener('change', () => {{
                    enable();
                    updateUsbOnlyWarning();
                    // Only nudge focus to key if they picked a real SSID
                    if (select.value) setTimeout(() => {{ try {{ key.focus(); }} catch (e) {{}} }}, 100);
                    }});
                }}
            }}

            function installHandlers() {{
                const form = document.getElementById('wifi-form');
                if (!form) return;

                // Optional: allow user to briefly reveal/mask the key
                const toggle = document.getElementById('toggle-mask');
                const key = document.getElementById('key-field');
                const eyeOpen = document.getElementById('eye-open');
                const eyeClosed = document.getElementById('eye-closed');

                form.addEventListener('submit', async (ev) => {{
                    ev.preventDefault();

                    const btn = document.getElementById('connect-btn');
                    const status = document.getElementById('status');
                    if (btn) btn.disabled = true;
                    if (status) status.textContent = 'Submitting WiFi settings…';

                    const ssid = document.getElementById('ssid-select')?.value || '';
                    const k = document.getElementById('key-field')?.value || '';

                    try {{
                        // Send the server the expected parameter names without exposing them in the DOM.
                        const body = new URLSearchParams();
                        body.set('ssid', ssid);
                        body.set('password', k);

                        const resp = await fetch('/setup', {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
                            body: body.toString(),
                            cache: 'no-store',
                            credentials: 'same-origin',
                    }});

                    const html = await resp.text();
                    document.open();
                    document.write(html);
                    document.close();
                    }} catch (e) {{

                    if (status) status.textContent = 'Submit failed. Please try again.';
                    if (btn) btn.disabled = false;
                    }}
                }});

                if (toggle && key) {{
                    toggle.addEventListener('click', () => {{
                        const masked = key.classList.toggle('masked');

                        // Keep icons in sync with mask state:
                        // masked=true  -> show "eye-open" (can reveal)
                        // masked=false -> show "eye-closed" (currently visible)
                        if (eyeOpen && eyeClosed) {{
                            eyeOpen.style.display = masked ? 'inline' : 'none';
                            eyeClosed.style.display = masked ? 'none' : 'inline';
                        }}

                        // Update a11y label
                        toggle.setAttribute('aria-label', masked ? 'Show password' : 'Hide password');
                    }});
                }}
            }}

            async function reconnectSaved() {{
                const btn = document.getElementById('reconnect-btn');
                const st = document.getElementById('reconnect-status');
                if (btn) btn.disabled = true;
                if (st) st.textContent = 'Reconnecting to your saved network…';
                try {{
                    await fetch('/reconnect_saved', {{ method: 'POST', cache: 'no-store' }});
                    if (st) st.textContent =
                        'Reconnecting. You may lose this setup network shortly.';
                }} catch (e) {{
                    if (st) st.textContent = 'Request failed. Please try again.';
                    if (btn) btn.disabled = false;
                }}
            }}

            window.addEventListener('load', () => {{
                // Ensure key field won't be auto-focused by iOS, and only becomes editable on interaction.
                armKeyField();

                fetchNetworks();
                fetchStatus();
                installHandlers();
                setInterval(fetchNetworks, 5000);
                setInterval(fetchStatus, 2000);

                // Extra nudge: if iOS still tries to focus something, move focus away from key.
                // (No-op on most browsers.)
                focusSsidSelectSoon();
            }});
        </script>
        </head>

        <body>
        <div class="container">
            <div class="banner">
            {BANNER_HTML}
            </div>

            <h1>Connect to WiFi</h1>

            {alert_html}

            <p>Select your WiFi network and enter the key (leave blank for open networks).</p>

            <!-- Use innocuous field names + non-password input to reduce iOS save-password heuristics -->
            <form id="wifi-form" method="post" action="/setup" autocomplete="off" novalidate>
            <label for="ssid-select">WiFi Network (SSID)</label>
            <select id="ssid-select" name="s" autocomplete="off">
                <option value="">Scanning…</option>
            </select>

            <div id="usb-only-warning" class="alert" style="display:none;">
              This network is currently available only with the USB Wi-Fi
              adapter. If removed, {html.escape(APP_TITLE)} will revert to
              hotspot setup mode.
            </div>

            <label for="key-field">WiFi Passphrase/Password</label>
            <div class="row">
                <div class="grow">
                <input
                    id="key-field"
                    type="text"
                    name="k"
                    class="masked"
                    readonly
                    autocomplete="off"
                    autocapitalize="off"
                    autocorrect="off"
                    spellcheck="false"
                    inputmode="text"
                    placeholder="(leave blank for open networks)"
                />
                </div>
                <button id="toggle-mask"
                        class="pill-btn small"
                        type="button"
                        aria-label="Show password"
                        title="Show / hide">
                    <svg id="eye-open" xmlns="http://www.w3.org/2000/svg" width="18" height="18"
                        viewBox="0 0 24 24" fill="none" stroke="currentColor"
                        stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                        <circle cx="12" cy="12" r="3"/>
                    </svg>
                    <svg id="eye-closed" xmlns="http://www.w3.org/2000/svg" width="18" height="18"
                        viewBox="0 0 24 24" fill="none" stroke="currentColor"
                        stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                        style="display:none;">
                        <path d="M17.94 17.94A10.94 10.94 0 0 1 12 20c-7 0-11-8-11-8
                                a21.82 21.82 0 0 1 5.06-6.94"/>
                        <path d="M1 1l22 22"/>
                        <path d="M9.53 9.53A3 3 0 0 0 12 15
                                a3 3 0 0 0 2.47-5.47"/>
                    </svg>
                </button>
            </div>
            <br>
            <div class="hint">
                You may need to reconnect to your normal WiFi after pressing Connect.
            </div>
            <br>
            <button id="connect-btn" class="pill-btn" type="submit">Connect</button>
            </form>
            <br>
            <div class="status" id="status">Status: unknown</div>
            {reconnect_html}
        </div>

        <div id="rejoin-modal" class="modal-overlay" role="dialog" aria-modal="true">
          <div class="modal-box">
            <h2>Your network is available again</h2>
            <p>Your network <strong id="rejoin-ssid"></strong> is back in range.
               Rejoin it, or continue setting up a different network?</p>
            <button class="pill-btn" type="button" onclick="rejoinNow()">Rejoin</button>
            <button class="pill-btn small" type="button"
                    onclick="dismissRejoin()">Continue setup</button>
          </div>
        </div>
        </body>
        </html>
        """


def render_wait_page(ctx, selected_ssid: str = "") -> str:
    """Wait page shown immediately after submit."""
    ua = (request.headers.get("User-Agent") or "").lower()

    if "iphone" in ua or "ipad" in ua or "ipod" in ua:
        browser_name = "Safari"
    elif "android" in ua:
        browser_name = "Chrome"
    elif "windows" in ua:
        browser_name = "Browser"
    else:
        browser_name = "Browser"

    ssid_safe = html.escape(selected_ssid or "")
    # Hostname may change at runtime (e.g. user renames device); re-read when rendering.
    host_safe = html.escape(ctx.get_system_hostname())

    # Dial mode: after joining, the user continues setup from an autostream appliance,
    # not from the dial's own web page.  Non-dial mode: redirect to the appliance web UI.
    if ctx._DIAL_MODE:
        next_step_html = "<p>Continue setup from an autostream appliance.</p>"
        success_js = "/* dial: remain on this page — user continues from an appliance */"
    else:
        next_step_html = (
            f"<p>Open {browser_name} and go to "
            f"<code>{host_safe}.local</code> to continue setup.</p>"
        )
        success_js = (
            f"window.location.replace('http://{host_safe}.local/?t=' + Date.now());"
        )

    return f"""<!DOCTYPE html>
        <html>
        <head>
        <meta charset="utf-8">
        <title>Joining network…</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
        <style>{STYLE_CSS}</style>
        <script>
            async function poll() {{
            try {{
                const r = await fetch('/status', {{ cache: 'no-store' }});
                if (!r.ok) return;
                const s = await r.json();

                // Once apply is finished:
                if (!s.apply_in_progress) {{
                // If we're back in SetupMode, the join failed -> go back to setup
                if (s.SetupMode || s.last_apply_result === 'failed') {{
                    const e = encodeURIComponent(s.last_apply_error || 'failed');
                    window.location.replace('/setup?e=' + e + '&t=' + Date.now());
                    return;
                }}

                // Success path
                {success_js}
                return;
                }}
            }} catch (e) {{}}
            }}

            setInterval(poll, 1200);
            window.addEventListener('load', poll);
        </script>

        </head>

        <body>
        <div class="container">
            {BANNER_HTML}

            <h1>Joining network…</h1>

            <p>Attempting to join the network <code>{ssid_safe}</code>.</p>

            {next_step_html}
        </div>
        </body>
        </html>
        """


# ---------------------------------------------------------------------------
# Captive-portal / setup HTTP surface
# ---------------------------------------------------------------------------

def _captive_response(html: str):
    resp = make_response(html, 200)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp

CAPTIVE_LANDING = """<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <meta http-equiv="refresh" content="0; url=/setup">
    <title>Wi-Fi setup</title>
  </head>
  <body>
    <p>Redirecting to setup…</p>
    <p><a href="/setup">Open setup</a></p>
  </body>
</html>
"""


def _has_saved_network(ctx) -> bool:
    """True if a committed or rollback connection exists."""
    if ctx.get_configured_network_state().is_configured:
        return True
    with ctx.state_lock:
        session = ctx.STATE.hotspot
    return bool(session is not None and session.rollback is not None
                and session.rollback.connection_name)


# ---------------------------------------------------------------------------
# Local control / auth surface (loopback + per-boot token)
# ---------------------------------------------------------------------------

def _atomic_write(path: str, data: str, mode: int = 0o644) -> None:
    """Atomically write *data* to *path* with *mode* (stdlib-only).

    Creates a temp file in the same directory, flushes, fsyncs, sets mode, then
    ``os.replace`` over the destination.  Equivalent to the watcher helper's
    atomic write; inlined here so wifi_web stays self-contained on the
    system-Python recovery path (it imports no Autostream module).
    """
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def init_control_token(ctx) -> str:
    """Generate the per-boot control token and write it root:autostream 0640.

    The runtime dir is created root:autostream 0750 when needed.  Replacement at
    each startup is authoritative.  Returns the token (also stored in module
    state).  Never logged.
    """
    global _control_token
    _control_token = secrets.token_urlsafe(32)
    try:
        os.makedirs(CONTROL_TOKEN_DIR, exist_ok=True)
        try:
            os.chmod(CONTROL_TOKEN_DIR, 0o750)
        except OSError:
            pass
        _atomic_write(CONTROL_TOKEN_PATH, _control_token + "\n", mode=0o640)
        # Best-effort group ownership so the unprivileged Web UI can read it.
        try:
            import grp
            gid = grp.getgrnam("autostream").gr_gid
            os.chown(CONTROL_TOKEN_PATH, 0, gid)
            os.chown(CONTROL_TOKEN_DIR, 0, gid)
        except (KeyError, OSError, ImportError):
            pass
    except Exception as e:
        ctx.logger.error("Failed to write control token file: %s", e)
    return _control_token


def remove_control_token() -> None:
    try:
        os.unlink(CONTROL_TOKEN_PATH)
    except OSError:
        pass


def _is_loopback_remote() -> bool:
    return (request.remote_addr or "") in ("127.0.0.1", "127.0.1.1", "::1")


def _control_authorised() -> bool:
    """Require BOTH a loopback source AND a matching per-boot token header.

    Loopback alone is insufficient: during AP mode nginx proxies external
    captive-portal clients to the watcher, so Flask may see loopback.  Tokens are
    compared with hmac.compare_digest.
    """
    if not _is_loopback_remote():
        return False
    supplied = request.headers.get(CONTROL_TOKEN_HEADER, "")
    if not supplied or not _control_token:
        return False
    return hmac.compare_digest(supplied, _control_token)


def validate_log_level_request(ctx, level, ttl) -> tuple[str, Optional[int]]:
    """Validate a set_log_level request.

    Returns ``(error, clamped_ttl)``; *error* is "" when valid.  ``debug``
    requires a TTL; provided TTLs must be numeric and are clamped to
    [LOG_LEVEL_TTL_MIN, LOG_LEVEL_TTL_MAX].
    """
    if level not in ctx.RUNTIME_LOG_LEVELS:
        return "invalid_level", None
    if ttl is None:
        if level == "debug":
            return "ttl_required_for_debug", None
        return "", None
    if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or ttl <= 0:
        return "invalid_ttl", None
    clamped = int(max(ctx.LOG_LEVEL_TTL_MIN, min(ctx.LOG_LEVEL_TTL_MAX, ttl)))
    return "", clamped


def build_app(ctx) -> Flask:
    """Build the watcher's Flask app and register the captive-portal/setup routes.

    Handlers close over a :class:`WebContext` and read/queue through it:
    ``ctx.STATE``, ``ctx.state_lock``, ``ctx.submit_apply_credentials``,
    ``ctx.scan_all_networks``, ``ctx.control_action_event``, ``ctx.logger``.
    Endpoint (handler) names are preserved so ``url_for`` keeps resolving.
    """
    app = Flask(ctx.app_name)

    @app.route("/", methods=["GET"])
    def index():
        """Redirect root to the /setup page."""
        return redirect(url_for("setup"))

    @app.errorhandler(404)
    def page_not_found(_):
        return _captive_response(CAPTIVE_LANDING)

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if request.method == "POST":
            # Accept both the “real” names and your innocuous names
            ssid = (request.form.get("ssid") or request.form.get("s") or "").strip()
            pw = request.form.get("password") or request.form.get("k") or ""

            if not ssid:
                ctx.logger.warning("WiFi configuration POST received without SSID")
                return _captive_response(render_setup_page())

            # Enqueue the apply on the shared activation worker instead of
            # spawning a Flask thread, so it is serialised with the loop's
            # activations (no unmanaged second writer).  submit_apply_credentials
            # sets apply_in_progress + "applying" on accept.
            if not ctx.submit_apply_credentials(ssid, pw):
                ctx.logger.info("Apply already in progress / worker busy; showing wait page again")
            return _captive_response(render_wait_page(ctx, ssid))

        # GET: show the setup form (include last failure, if any)
        with ctx.state_lock:
            e = (request.args.get("e") or "").strip()
            if not e and ctx.APPLY_STATE.last_apply_result == "failed":
                e = ctx.APPLY_STATE.last_apply_error or "failed"

        ctx.logger.info("User requested /setup (error: %s)", e)

        # Offer "Reconnect to saved network" only when a saved network exists —
        # never during first-run unconfigured setup.
        show_reconnect = _has_saved_network(ctx)
        return _captive_response(render_setup_page(e, show_reconnect=show_reconnect))

    @app.route("/networks", methods=["GET"])
    def networks():
        """Return merged, deduplicated networks seen by all detected adapters.

        Response shape:
            {"networks": [{ssid, signal, builtin_visible, usb_visible,
                           adapter_macs}, ...], "builtin_scan_known": bool}
        """
        nets, builtin_scan_known = ctx.scan_all_networks()
        return jsonify({"networks": nets, "builtin_scan_known": builtin_scan_known})

    @app.route("/reconnect_saved", methods=["POST"])
    def reconnect_saved():
        """Narrowly handled captive-page action: reconnect to the saved network.

        Available to AP clients (not loopback) but strictly limited to reconnecting
        an existing committed/rollback profile — it does NOT expose the general
        network-control API.  Queues the work for the monitor loop; the browser may
        lose AP connectivity, so success does not depend on a final acknowledgement.
        """
        if not _has_saved_network(ctx):
            return jsonify({"ok": False, "error": "no_saved_network"}), 409
        with ctx.state_lock:
            if ctx.APPLY_STATE.apply_in_progress:
                return jsonify({"ok": False, "error": "apply_in_progress"}), 409
            if ctx.CONTROL_STATE.pending_control_action or ctx.CONTROL_STATE.control_in_progress:
                return jsonify({"ok": False, "error": "busy"}), 409
            ctx.CONTROL_STATE.pending_control_action = "reconnect_saved"
            ctx.control_action_event.set()
        ctx.logger.info("Captive-page reconnect_saved queued")
        return jsonify({"ok": True, "queued": True})

    @app.route("/dismiss_rejoin", methods=["POST"])
    def dismiss_rejoin():
        """Captive-page action: keep reconfiguring instead of rejoining the saved
        network for the rest of this setup session.

        Captive-accessible like /reconnect_saved (AP clients, no token) — it is
        strictly less powerful, only *suppressing* the automatic rejoin for one
        session; the flag resets when the session ends.
        """
        with ctx.state_lock:
            ctx.STATE.rejoin_dismissed = True
            ctx.STATE.saved_ssid_visible = False
        ctx.logger.info("Captive-page rejoin dismissed for this session")
        return jsonify({"ok": True})

    @app.route("/status", methods=["GET"])
    def status():
        """Return a simple JSON status including SetupMode and link states."""
        with ctx.state_lock:
            wifistate = ctx.STATE.wifistate
            wiredstate = ctx.STATE.wiredstate
            gateway_reachable = ctx.STATE.connectivity_ok
            SetupMode = ctx.STATE.setup_mode
            aip = ctx.APPLY_STATE.apply_in_progress
            lar = ctx.APPLY_STATE.last_apply_result
            lae = ctx.APPLY_STATE.last_apply_error
            saved_ssid_visible = bool(ctx.STATE.saved_ssid_visible)
            saved_ssid = ctx.STATE.saved_ssid_name

        return jsonify(
            {
                "wifistate": wifistate,
                "wiredstate": wiredstate,
                "gateway_reachable": gateway_reachable,
                "SetupMode": SetupMode,
                "apply_in_progress": aip,
                "last_apply_result": lar,
                "last_apply_error": lae,
                # Rejoin prompt: the saved network is visible again while a client
                # is on the setup AP; the page offers rejoin vs keep-reconfiguring.
                "saved_ssid_visible": saved_ssid_visible,
                "saved_ssid": saved_ssid,
            }
        )

    # iOS / Apple captive probes
    @app.route("/hotspot-detect.html", methods=["GET"])
    @app.route("/library/test/success.html", methods=["GET"])
    def apple_captive_probe():
        ctx.logger.debug("Captive portal probe (Apple): %s", request.path)
        return _captive_response(CAPTIVE_LANDING)

    # Android / Chrome probes
    @app.route("/generate_204", methods=["GET"])
    @app.route("/gen_204", methods=["GET"])
    def android_probe():
        ctx.logger.debug("Captive portal probe (Android): %s", request.path)
        return _captive_response(CAPTIVE_LANDING)

    # Windows NCSI probe
    @app.route("/ncsi.txt", methods=["GET"])
    @app.route("/connecttest.txt", methods=["GET"])
    def windows_probe():
        ctx.logger.debug("Captive portal probe (Windows): %s", request.path)
        return _captive_response(CAPTIVE_LANDING)

    @app.route("/.well-known/captive-portal", methods=["GET"])
    def captive_portal_api():
        """
        RFC 8910 Captive Portal API endpoint (DHCP option 114 points here).
        iOS/macOS expect application/captive+json and typically respect no-store.
        """
        # Use whatever host the client used (often 192.168.4.1 via DNS hijack / proxy)
        base = (request.host_url or "http://192.168.4.1/").rstrip("/")

        payload = {
            "captive": True,
            "user-portal-url": f"{base}/setup",
        }

        resp = make_response(json.dumps(payload), 200)
        resp.headers["Content-Type"] = "application/captive+json; charset=utf-8"
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        return resp

    # ** LOCAL CONTROL API **
    # Privileged loopback surface: every route requires loopback AND the
    # per-boot token (_control_authorised); handlers only validate/authenticate
    # and queue/trigger — all policy consumption stays in the watcher.

    @app.route("/version", methods=["GET"])
    def version():
        if not _control_authorised():
            return jsonify({"ok": False, "error": "forbidden"}), 403
        return jsonify({
            "ok": True,
            "component": "wifi_watcher",
            "version": ctx.WIFI_WATCHER_VERSION,
        })

    @app.route("/network_status", methods=["GET"])
    def network_status():
        if not _control_authorised():
            return jsonify({"ok": False, "error": "forbidden"}), 403
        with ctx.state_lock:
            snapshot = ctx.STATE.network_status_snapshot
        if not snapshot:
            return jsonify({
                "ok": True,
                "schema_version": ctx.wifi_net.NETWORK_STATUS_SCHEMA_VERSION,
                "device": {"state": "unknown"},
                "stale": True,
            })
        return jsonify(snapshot)

    @app.route("/network_control", methods=["POST"])
    def network_control():
        """Queue a disruptive network action; never execute it in the request thread.

        Validates/authenticates, stores one pending action under the state lock,
        signals the monitor loop, and returns a queued response before any interface
        is disconnected.  Rejects unknown actions/fields and a second conflicting
        action while one is pending or in progress.
        """
        if not _control_authorised():
            ctx.logger.warning("Rejected /network_control (unauthenticated/non-loopback)")
            return jsonify({"ok": False, "error": "forbidden"}), 403

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"ok": False, "error": "invalid_body"}), 400
        action = payload.get("action")
        keys = set(payload.keys())

        # Per-action field validation.  start_setup/reconnect_saved accept
        # only {"action"}; set_log_level accepts {"action","level","ttl_seconds?"};
        # the adapter actions accept {"action","adapter"} (a non-empty stable-id).
        params: dict = {}
        if action in ("start_setup", "reconnect_saved"):
            if keys != {"action"}:
                return jsonify({"ok": False, "error": "invalid_action"}), 400
        elif action == "set_log_level":
            if not keys <= {"action", "level", "ttl_seconds"}:
                return jsonify({"ok": False, "error": "invalid_action"}), 400
            level = payload.get("level")
            ttl = payload.get("ttl_seconds", None)
            error, clamped = validate_log_level_request(ctx, level, ttl)
            if error:
                ctx.logger.warning("Rejected set_log_level request: %s", error)
                return jsonify({"ok": False, "error": error}), 400
            params = {"level": level, "ttl_seconds": clamped}
        elif action in ("clear_adapter", "disable_adapter", "enable_adapter"):
            if keys != {"action", "adapter"}:
                return jsonify({"ok": False, "error": "invalid_action"}), 400
            adapter = payload.get("adapter")
            if not isinstance(adapter, str) or not adapter.strip():
                return jsonify({"ok": False, "error": "invalid_adapter"}), 400
            params = {"adapter": adapter.strip()}
        else:
            return jsonify({"ok": False, "error": "invalid_action"}), 400

        with ctx.state_lock:
            if ctx.CONTROL_STATE.pending_control_action or ctx.CONTROL_STATE.control_in_progress:
                return jsonify({"ok": False, "error": "busy"}), 409
            ctx.CONTROL_STATE.pending_control_action = action
            ctx.CONTROL_STATE.pending_control_params = params
            ctx.control_action_event.set()

        ctx.logger.info("Queued network control action: %s", action)
        return jsonify({"ok": True, "queued": True, "action": action})

    @app.route("/request_ap_mode", methods=["POST"])
    def request_ap_mode():
        """Allow the normal (non-setup) WebUI to request AP/setup mode.

        Retained for compatibility but now requires both a loopback source and the
        per-boot control token, so no unauthenticated privileged loopback-only route
        remains behind nginx.  Queues a ``manual_ap`` control action on the shared
        control channel — so it defers while a transition is in flight and adopts
        the channel's busy semantics — instead of the legacy dedicated event.
        """
        if not _control_authorised():
            ctx.logger.warning("Rejected /request_ap_mode (unauthenticated/non-loopback)")
            return jsonify({"ok": False, "error": "forbidden"}), 403

        reason = ""
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            reason = str(payload.get("reason", "")).strip()
        if not reason:
            reason = (request.form.get("reason") or "").strip()

        # There is no once-per-boot AP budget: a MANUAL hotspot is enterable
        # whenever requested; the 30-minute session lifetime is the only rate
        # limit.  Reject with 409 only when another control action is already
        # pending or in progress (the caller retries once the channel is free).
        with ctx.state_lock:
            if ctx.CONTROL_STATE.pending_control_action or ctx.CONTROL_STATE.control_in_progress:
                return jsonify({"ok": False, "error": "busy"}), 409
            ctx.CONTROL_STATE.pending_control_action = "manual_ap"
            ctx.CONTROL_STATE.pending_control_params = {"reason": reason}
            ctx.control_action_event.set()

        ctx.logger.info("AP mode requested via /request_ap_mode (reason='%s')", reason or "UserRequest")
        return jsonify({"ok": True, "queued": True, "action": "manual_ap"})

    return app
