#!/usr/bin/python3
"""wifi_web.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Flask presentation surface for the Autostream Wi-Fi watcher (HTTP-extraction
plan, WP1).  This module owns the setup/captive-portal page rendering; later
work packages add the Flask app factory, the captive/setup routes, and the
loopback control/auth surface.

Runtime note:
Like its sibling recovery modules (wifi_status.py, wifi_recovery.py) this runs
on the system Python, not the app venv.  It imports only the standard library
and ``flask``; it never imports an Autostream application module.  Functions
that need watcher state receive the watcher module ``w`` as their first
argument and read its constants/helpers through it (the star-topology seam).
"""
from __future__ import annotations

import html
import os

from flask import request

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
        </style>
        <script>
            let _didInitialFocus = false;

            async function fetchStatus() {{
                try {{
                    const resp = await fetch('/status', {{ cache: 'no-store' }});
                    if (!resp.ok) return;
                    const data = await resp.json();
                    const el = document.getElementById('status');
                    if (!el) return;
                    el.textContent =
                        'WiFi: ' + data.wifistate + ', ' +
                        'Wired: ' + data.wiredstate + ', ' +
                        'Gateway reachable: ' + data.gateway_reachable + ', ' +
                        'SetupMode: ' + data.SetupMode;
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
        </body>
        </html>
        """


def render_wait_page(w, selected_ssid: str = "") -> str:
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
    host_safe = html.escape(w.get_system_hostname())

    # Dial mode: after joining, the user continues setup from an autostream appliance,
    # not from the dial's own web page.  Non-dial mode: redirect to the appliance web UI.
    if w._DIAL_MODE:
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
