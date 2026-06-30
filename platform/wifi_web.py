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
import json
import os
import threading

from flask import Flask, request, jsonify, redirect, url_for, make_response

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


def _has_saved_network(w) -> bool:
    """True if a committed or rollback connection exists (Section 11.5)."""
    if w.get_configured_network_state().is_configured:
        return True
    with w.state_lock:
        return bool(w.STATE.rollback_connection_name)


def build_app(w) -> Flask:
    """Build the watcher's Flask app and register the captive-portal/setup routes.

    Handlers close over the watcher module ``w`` (the star-topology hub) and
    read/queue through it: ``w.STATE``, ``w.state_lock``, ``w.apply_wifi_async``,
    ``w.scan_all_networks``, ``w.control_action_event``, ``w.logger``.  Endpoint
    (handler) names are preserved so ``url_for`` keeps resolving.
    """
    app = Flask(w.__name__)

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
                w.logger.warning("WiFi configuration POST received without SSID")
                return _captive_response(render_setup_page())

            with w.state_lock:
                if w.STATE.apply_in_progress:
                    w.logger.info("Apply already in progress; showing wait page again")
                    return _captive_response(render_wait_page(w, ssid))
                    #return render_wait_page(ssid)
                w.STATE.apply_in_progress = True
                w.STATE.last_apply_result = "applying"
                w.STATE.last_apply_error = ""

            # IMPORTANT: return wait page first, then reconfigure in background
            t = threading.Thread(target=w.apply_wifi_async, args=(ssid, pw), daemon=True)
            t.start()
            return _captive_response(render_wait_page(w, ssid))

        # GET: show the setup form (include last failure, if any)
        with w.state_lock:
            e = (request.args.get("e") or "").strip()
            if not e and w.STATE.last_apply_result == "failed":
                e = w.STATE.last_apply_error or "failed"

        w.logger.info("User requested /setup (error: %s)", e)

        # Offer "Reconnect to saved network" only when a saved network exists —
        # never during first-run unconfigured setup (Section 11.5).
        show_reconnect = _has_saved_network(w)
        return _captive_response(render_setup_page(e, show_reconnect=show_reconnect))

    @app.route("/networks", methods=["GET"])
    def networks():
        """Return merged, deduplicated networks seen by all detected adapters.

        Response shape (Section 6.2):
            {"networks": [{ssid, signal, builtin_visible, usb_visible,
                           adapter_macs}, ...], "builtin_scan_known": bool}
        """
        nets, builtin_scan_known = w.scan_all_networks()
        return jsonify({"networks": nets, "builtin_scan_known": builtin_scan_known})

    @app.route("/reconnect_saved", methods=["POST"])
    def reconnect_saved():
        """Narrowly handled captive-page action: reconnect to the saved network.

        Available to AP clients (not loopback) but strictly limited to reconnecting
        an existing committed/rollback profile — it does NOT expose the general
        network-control API.  Queues the work for the monitor loop; the browser may
        lose AP connectivity, so success does not depend on a final acknowledgement.
        """
        if not _has_saved_network(w):
            return jsonify({"ok": False, "error": "no_saved_network"}), 409
        with w.state_lock:
            if w.STATE.apply_in_progress:
                return jsonify({"ok": False, "error": "apply_in_progress"}), 409
            if w.STATE.pending_control_action or w.STATE.control_in_progress:
                return jsonify({"ok": False, "error": "busy"}), 409
            w.STATE.pending_control_action = "reconnect_saved"
            w.control_action_event.set()
        w.logger.info("Captive-page reconnect_saved queued")
        return jsonify({"ok": True, "queued": True})

    @app.route("/status", methods=["GET"])
    def status():
        """Return a simple JSON status including SetupMode and link states."""
        with w.state_lock:
            wifistate = w.STATE.wifistate
            wiredstate = w.STATE.wiredstate
            gateway_reachable = w.STATE.connectivity_ok
            SetupMode = w.STATE.setup_mode
            aip = w.STATE.apply_in_progress
            lar = w.STATE.last_apply_result
            lae = w.STATE.last_apply_error

        return jsonify(
            {
                "wifistate": wifistate,
                "wiredstate": wiredstate,
                "gateway_reachable": gateway_reachable,
                "SetupMode": SetupMode,
                "apply_in_progress": aip,
                "last_apply_result": lar,
                "last_apply_error": lae,
            }
        )

    # iOS / Apple captive probes
    @app.route("/hotspot-detect.html", methods=["GET"])
    @app.route("/library/test/success.html", methods=["GET"])
    def apple_captive_probe():
        w.logger.debug("Captive portal probe (Apple): %s", request.path)
        return _captive_response(CAPTIVE_LANDING)

    # Android / Chrome probes
    @app.route("/generate_204", methods=["GET"])
    @app.route("/gen_204", methods=["GET"])
    def android_probe():
        w.logger.debug("Captive portal probe (Android): %s", request.path)
        return _captive_response(CAPTIVE_LANDING)

    # Windows NCSI probe
    @app.route("/ncsi.txt", methods=["GET"])
    @app.route("/connecttest.txt", methods=["GET"])
    def windows_probe():
        w.logger.debug("Captive portal probe (Windows): %s", request.path)
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

    # The watcher's still-resident control routes (version/network_status/
    # network_control/request_ap_mode) register themselves onto this same app
    # object via module-level @app.route decorators as the watcher finishes
    # loading.  They move into this factory in WP3.
    return app
