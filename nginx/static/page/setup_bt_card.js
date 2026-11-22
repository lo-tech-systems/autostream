var pageData = (function () {
  try { return JSON.parse(document.getElementById('page-data').textContent); }
  catch (e) { return {}; }
})();
        var btServicesEnabled = pageData.bt_services_enabled;
        var btOnboardEnabled = pageData.bt_onboard_enabled;
        if (typeof btPaired === 'undefined') var btPaired = pageData.bt_paired;
        if (typeof _btLinkState === 'undefined') var _btLinkState = pageData.bt_link_state;
        window._btLastStatus = pageData.bt_status;
        window._btUiText = pageData.bt_ui_text;

        // Cross-input exclusivity over the wired inputs' device selects (input
        // 3 has none): a device chosen on one is not offered on another.
        function refreshExclusivityOptions() {
          var selects = Array.prototype.slice.call(
            document.querySelectorAll('select[data-input-index]'));
          selects.forEach(function(self) {
            var taken = selects
              .filter(function(other) { return other !== self && other.value; })
              .map(function(other) { return other.value; });
            Array.prototype.forEach.call(self.options, function(opt) {
              var conflict = opt.value !== self.value && taken.indexOf(opt.value) !== -1;
              opt.disabled = conflict;
              opt.hidden = conflict;
            });
          });
        }

        function syncInputExclusivity(changedIndex, value) {
          refreshExclusivityOptions();
        }

        // Input 3's Enable switch is the Bluetooth services switch. The
        // switch stays disabled (busy) while the services change, then the
        // page reloads; if they cannot be changed it goes back.
        function btServicesToggle(el) {
          var enable = !!el.checked;
          if (!enable && !window.confirm('Disable Bluetooth? Any active Bluetooth stream will stop immediately.')) {
            el.checked = true;
            return;
          }
          el.disabled = true;
          settingsTransact('/api/bluetooth/services', {action: enable ? 'enable' : 'disable'}, {
            onSuccess: function() { window.location.reload(); },
            onError: function() { el.checked = !enable; el.disabled = false; }
          });
        }

        function btOnboardToggleChanged(checked) {
          if (!window.confirm('Changing this restarts the appliance. Continue?')) {
            var t = document.getElementById('btOnboardToggle');
            if (t) t.checked = !checked;
            return;
          }
          settingsTransact('/api/bluetooth/onboard', {enabled: checked}, {
            onSuccess: function(d) {
              if (d && d.reboot_required) { window.location.href = '/rebooting'; }
            },
            onError: function() {
              var t = document.getElementById('btOnboardToggle');
              if (t) t.checked = !checked;
            }
          });
        }

        var _btBufferTimer = null;
        function btBufferInput(value) {
          var lbl = document.getElementById('btBufferVal');
          if (lbl) lbl.textContent = value + ' ms';
          if (_btBufferTimer) clearTimeout(_btBufferTimer);
          _btBufferTimer = setTimeout(function() {
            settingsTransact('/api/bluetooth/buffer', {buffer_ms: parseInt(value, 10)});
          }, 500);
        }

        // -- SD card health monitoring row (shares this card) --------------
        var sdHealthState = pageData.sd_health;

        function showSdHealthModal() {
          var msg = document.getElementById('sdHealthModalMsg');
          if (msg) {
            msg.textContent = (sdHealthState && sdHealthState.check === 'hung')
              ? 'This function has previously resulted in a system hang and the card may not be supported. Do you wish to continue?'
              : "Querying the card's health uses a manufacturer command that may cause unsupported cards to become unresponsive. If the card stops responding, the system will restart automatically. Continue?";
          }
          var m = document.getElementById('sdHealthModal');
          if (m) m.classList.add('show');
        }

        function hideSdHealthModal() {
          var m = document.getElementById('sdHealthModal');
          if (m) m.classList.remove('show');
        }

        function confirmSdHealthEnable() {
          hideSdHealthModal();
          var sel = document.getElementById('sdHealthMethod');
          var method = sel ? sel.value : 'auto';
          var btn = document.getElementById('sdHealthActionBtn');
          var prevLabel = btn ? btn.textContent : '';
          if (btn) { btn.disabled = true; btn.textContent = 'Checking card\u2026'; }
          settingsTransact('/api/sdcard-health/enable', {method: method}, {
            onSuccess: function() { window.location.reload(); },
            onError: function(d) {
              if (btn) { btn.disabled = false; btn.textContent = prevLabel; }
              var msg = (d && d.reason) ? d.reason
                : (d && d.error === 'hung') ? 'A query of this card did not complete and locked the system up; the card may not be supported.'
                : (d && d.error === 'tool_missing') ? 'The SD card health tool is not installed.'
                : 'The card health check failed.';
              showInfoModal('SD Card Health', msg);
            }
          });
        }

        function sdHealthDisable() {
          if (!window.confirm('Stop monitoring this card\'s health?')) return;
          var btn = document.getElementById('sdHealthActionBtn');
          var prevLabel = btn ? btn.textContent : '';
          if (btn) { btn.disabled = true; btn.textContent = 'Disabling\u2026'; }
          settingsTransact('/api/sdcard-health/disable', {}, {
            onSuccess: function() { window.location.reload(); },
            onError: function() { if (btn) { btn.disabled = false; btn.textContent = prevLabel; } }
          });
        }

        function _btApplyStatus(body) {
          if (!body) return;
          btServicesEnabled = !!body.services_enabled;
          btOnboardEnabled = !!body.onboard_enabled;
          var daemon = body.daemon || null;
          window._btLastStatus = daemon;
          var ui = body.ui || null;
          window._btUiText = (ui && ui.bt_input_text) || 'Not Connected';
          btPaired = !!(daemon && daemon.paired);
          _btLinkState = (daemon && daemon.link) || 'disconnected';
          var adapterPresent = !!(daemon && daemon.adapter_present);

          var adapterRow = document.getElementById('btAdapterRow');
          if (adapterRow) {
            var kind = daemon && daemon.adapter_kind;
            var noAdapter = body.onboard_refused
              ? 'No Bluetooth adapter found \u2014 plug in a USB adapter.'
              : 'No Bluetooth adapter found \u2014 plug in a USB adapter, or enable the onboard device below.';
            var text = !adapterPresent
              ? noAdapter
              : (kind === 'usb' ? 'USB adapter' : (kind === 'onboard' ? 'Onboard' : 'Detected'));
            adapterRow.textContent = 'Adapter: ' + text;
          }
          var onboardToggle = document.getElementById('btOnboardToggle');
          if (onboardToggle) {
            onboardToggle.checked = btOnboardEnabled;
            // Where the board refuses the onboard radio it can only be turned off.
            onboardToggle.disabled = !btServicesEnabled || (!!body.onboard_refused && !btOnboardEnabled);
          }
          var gatedRow = document.getElementById('btAdapterGatedRow');
          if (gatedRow) {
            gatedRow.style.opacity = adapterPresent ? '' : '0.4';
            gatedRow.style.pointerEvents = adapterPresent ? '' : 'none';
          }
          var pairedRow = document.getElementById('btPairedRow');
          if (pairedRow) pairedRow.textContent = (ui && ui.paired_text) || 'No device paired';
          var forgetBtn = document.getElementById('btnBtForget');
          if (forgetBtn) forgetBtn.style.display = btPaired ? '' : 'none';

          // Input 3's summary carries the Bluetooth device or connection state.
          if (typeof refreshInputCardSubs === 'function') refreshInputCardSubs();
        }

        async function _btRefreshLinkStatus() {
          var res, body = null;
          try {
            res = await fetch('/api/bluetooth/status', {
              cache: 'no-store',
              headers: {'X-CSRF-Token': window.__CSRF || ''}
            });
            body = await res.json();
          } catch (e) {
            return;
          }
          if (!body || body.ok !== true) return;
          _btApplyStatus(body);
        }

        document.addEventListener('DOMContentLoaded', function() {
          refreshExclusivityOptions();
        });
        // Avoids an unconditional `setInterval` that would keep polling
        // every 5s even with the tab backgrounded or the Bluetooth panel
        // closed. Poller's activeOnly mode ties the poll's lifetime to the
        // panel being open (started/stopped by openPanel()/closePanel())
        // and its built-in visibility gating pauses it whenever the tab
        // is hidden.
        var _btStatusPoller = Poller({
          url: '/api/bluetooth/status',
          intervalMs: 5000,
          activeOnly: true,
          fetchOptions: {headers: {'X-CSRF-Token': window.__CSRF || ''}},
          onData: function(body) {
            if (!body || body.ok !== true) return;
            _btApplyStatus(body);
          },
        });
        // Input level readout: one poller serves every input card and runs
        // only while one of them is open. The "above threshold" mark is the
        // last sample compared with the slider here, so it follows the slider
        // without waiting for the next poll.
        var _inputLevelLast = {};
        // The inputs as the readout wants them, from the inputs and monitor
        // parts: no level unless the monitor is connected, and the texts the
        // page was given for an input that is absent.
        function _inputLevelsFromState(body){
          const parts = (body && body.parts) || {};
          const entries = (parts.inputs && parts.inputs.entries) || [];
          const connected = !!(parts.monitor && parts.monitor.connected);
          const missing = pageData.missing_rate_texts || ['', ''];
          return {inputs: SETUP_INPUT_INDICES.map(function(i){
            const e = entries.find(function(x){ return x && x.index === i; });
            const lv = e && e.level;
            return {
              index: i,
              dbfs: (connected && lv && typeof lv.dbfs === 'number') ? lv.dbfs : null,
              sample_rate_text: e ? e.sample_rate_text : missing[1],
              rate_matching_note: e ? e.rate_note : missing[0],
            };
          })};
        }
        function _applyInputLevelMark(inputIndex){
          const el = document.getElementById('audio' + inputIndex + '_level_val');
          if (!el) return;
          const dbfs = _inputLevelLast[inputIndex];
          if (!Number.isFinite(dbfs)) { el.textContent = 'no level'; return; }
          const slider = document.getElementById(inputField(inputIndex, 'silence_threshold'));
          const above = slider ? dbfs >= Number(slider.value) : false;
          el.textContent = Math.round(dbfs) + ' dB' + (above ? ' (above threshold)' : '');
        }
        function _applyInputLevels(body){
          const inputs = (body && Array.isArray(body.inputs)) ? body.inputs : [];
          SETUP_INPUT_INDICES.forEach(function(i){
            const item = inputs.find(function(x){ return x && x.index === i; });
            _inputLevelLast[i] = (item && typeof item.dbfs === 'number') ? item.dbfs : NaN;
            _applyInputLevelMark(i);
            const rate = document.getElementById('audio' + i + '_sample_rate');
            if (rate && item && typeof item.sample_rate_text === 'string') rate.textContent = item.sample_rate_text;
            const note = document.getElementById('audio' + i + '_rate_matching_note');
            if (note && item && typeof item.rate_matching_note === 'string') note.textContent = item.rate_matching_note;
          });
        }
        var _inputLevelPoller = Poller({
          url: '/api/v1/state?parts=inputs,monitor',
          intervalMs: 1000,
          activeOnly: true,
          fetchOptions: {headers: {'X-CSRF-Token': window.__CSRF || ''}},
          onData: function(body){ _applyInputLevels(_inputLevelsFromState(body)); },
        });
