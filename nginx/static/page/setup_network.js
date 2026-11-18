        // -- Network adapter status and Change Wi-Fi -----------------
        function _networkStatusFailed() {
          var titleEl = document.getElementById('networkCardTitle');
          var adapterEl = document.getElementById('networkAdapterInfo');
          var addressEl = document.getElementById('networkAddressInfo');
          var warningEl = document.getElementById('networkWarning');
          var supportEl = document.getElementById('networkSupportDetail');
          if (titleEl) titleEl.textContent = 'Network';
          if (adapterEl) {
            adapterEl.textContent = 'Could not check network status';
            adapterEl.style.display = '';
          }
          if (addressEl) addressEl.style.display = 'none';
          if (warningEl) warningEl.style.display = 'none';
          if (supportEl) supportEl.style.display = 'none';
        }
        // Success-path DOM apply, shared by the manual one-shot refresh
        // (refreshNetworkAdapterInfo(), used by direct call sites) and the
        // activeOnly Poller below (_networkAdapterInfoPoller) so
        // there's exactly one fetch per tick either way, not two.
        function _applyNetworkStatus(j) {
          if (!j || j.ok === false || j.error || j.error_status) {
            _networkStatusFailed();
            return;
          }
          var adapterEl = document.getElementById('networkAdapterInfo');
          var addressEl = document.getElementById('networkAddressInfo');
          var warningEl = document.getElementById('networkWarning');
          var supportEl = document.getElementById('networkSupportDetail');
          var titleEl = document.getElementById('networkCardTitle');
          var pendingEl = document.getElementById('networkUsbPending');
          var roamingEl = document.getElementById('networkRoamingManaged');
          if (titleEl) titleEl.textContent = j.title || 'Network';
          if (adapterEl) {
            if (Array.isArray(j.interface_lines) && j.interface_lines.length) {
              adapterEl.textContent = j.interface_lines.join('\n');
              adapterEl.style.display = '';
            } else if (j.display) {
              adapterEl.textContent = j.display;
              adapterEl.style.display = '';
            } else {
              adapterEl.style.display = 'none';
            }
          }
          if (addressEl) {
            if (Array.isArray(j.interface_lines) && j.interface_lines.length) {
              addressEl.style.display = 'none';
            } else if (j.detail) {
              addressEl.textContent = j.detail;
              addressEl.style.display = '';
            } else {
              addressEl.style.display = 'none';
            }
          }
          if (warningEl) {
            if (j.warning) {
              warningEl.textContent = j.warning;
              warningEl.style.color = (j.warning_severity === 'danger')
                ? 'var(--color-status-danger,#c00)'
                : 'var(--color-status-warning,#b26b00)';
              warningEl.style.display = '';
            } else {
              warningEl.style.display = 'none';
            }
          }
          if (supportEl) {
            if (j.support_detail) {
              supportEl.textContent = j.support_detail;
              supportEl.style.display = '';
            } else {
              supportEl.style.display = 'none';
            }
          }
          if (pendingEl) pendingEl.style.display = j.usb_adoption_pending ? '' : 'none';
          if (roamingEl) roamingEl.checked = !!(j.roaming && j.roaming.managed);
          if (j.ap_ssid) {
            var ssidEl = document.getElementById('wifiHotspotSsid');
            if (ssidEl) ssidEl.textContent = j.ap_ssid;
          }
        }
        async function refreshNetworkAdapterInfo() {
          try {
            var r = await fetch('/api/network/status', {
              credentials: 'same-origin',
              cache: 'no-store',
              headers: { 'X-CSRF-Token': (window.__CSRF || '') }
            });
            var j = await r.json().catch(function() { return null; });
            if (!r.ok) { _networkStatusFailed(); return; }
            _applyNetworkStatus(j);
          } catch (e) { _networkStatusFailed(); }
        }
        refreshNetworkAdapterInfo();
        // Avoids an unconditional `setInterval` that would keep polling
        // every 5s even with the tab backgrounded or the System panel
        // closed. Poller's activeOnly mode ties the poll's lifetime to
        // the panel being open (started/stopped by openPanel()/
        // closePanel()) and its built-in visibility gating pauses it
        // whenever the tab is hidden.
        var _networkAdapterInfoPoller = Poller({
          url: '/api/network/status',
          intervalMs: 5000,
          activeOnly: true,
          fetchOptions: {
            credentials: 'same-origin',
            headers: { 'X-CSRF-Token': (window.__CSRF || '') },
          },
          onData: _applyNetworkStatus,
          onError: _networkStatusFailed,
        });

        async function setRoamingManagement(managed) {
          try {
            var r = await fetch('/api/network/roaming', {
              method: 'POST',
              credentials: 'same-origin',
              headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': (window.__CSRF || '')
              },
              body: JSON.stringify({ managed: managed, csrf_token: (window.__CSRF || '') })
            });
            var j = await r.json().catch(function() { return {}; });
            if (!r.ok || !j || j.ok !== true) {
              refreshNetworkAdapterInfo();
            }
          } catch (e) {
            refreshNetworkAdapterInfo();
          }
        }

        function changeWifiNetwork() {
          var modal = document.getElementById('wifiHotspotModal');
          if (modal) modal.classList.add('show');
        }

        function cancelChangeWifiNetwork() {
          var modal = document.getElementById('wifiHotspotModal');
          if (modal) modal.classList.remove('show');
        }

        async function confirmChangeWifiNetwork() {
          var modal = document.getElementById('wifiHotspotModal');
          if (modal) modal.classList.remove('show');
          var btn = document.querySelector('#networkCard .pill-btn');
          var msg = document.getElementById('networkSetupMsg');
          if (btn) btn.disabled = true;
          if (msg) { msg.textContent = 'Starting setup hotspot\u2026'; msg.style.color = ''; }
          try {
            var r = await fetch('/api/network/setup', {
              method: 'POST',
              credentials: 'same-origin',
              headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': (window.__CSRF || '')
              },
              body: JSON.stringify({ action: 'start_setup', csrf_token: (window.__CSRF || '') })
            });
            var j = await r.json().catch(function() { return {}; });
            if (r.ok && j && j.ok) {
              if (msg) { msg.textContent = 'Hotspot starting. Connect to the \u201cautostream-setup\u201d network to complete setup.'; msg.style.color = ''; }
            } else if (r.status === 409) {
              if (msg) { msg.textContent = 'A network change is already in progress.'; msg.style.color = 'var(--color-error,#c00)'; }
              if (btn) btn.disabled = false;
            } else {
              if (msg) { msg.textContent = 'Could not start setup. Please try again.'; msg.style.color = 'var(--color-error,#c00)'; }
              if (btn) btn.disabled = false;
            }
          } catch (e) {
            if (msg) { msg.textContent = 'Network error. Please try again.'; msg.style.color = 'var(--color-error,#c00)'; }
            if (btn) btn.disabled = false;
          }
        }
